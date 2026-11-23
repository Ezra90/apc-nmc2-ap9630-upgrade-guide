"""APC NMC2 (AP9630/AP9631 hw05) Staged Upgrade & Verification Helper.

Architectural Context:
    Upgrading legacy APC Network Management Card 2 (NMC2 / hw05) units across major
    firmware generations (v5.x -> v6.6.4 -> v6.9.6 -> v7.0.8 -> v7.1.2) requires
    strict single-binary-at-a-time transfers (bootmon -> reboot -> aos -> reboot -> sumx)
    with version verification gates after every reboot. Combining uploads or skipping
    verification risks stranding the card in boot monitor mode or mismatched AOS/APP state.

Purpose:
    Provides a self-contained CLI utility for probing open management ports, executing
    verified binary FTP/SCP single-file uploads with automatic reboot tracking, running
    interactive Telnet or OpenSSH CLI commands (including forced default password resets),
    and backing up config.ini over FTP or legacy SCP.

Design Choices:
    - Uses native OpenSSH (ssh.exe / scp.exe -O) with SSH_ASKPASS instead of Paramiko
      because Paramiko 5.x dropped SHA-1 ssh-rsa host key verification, which APC NMC2
      cryptlib SSH servers still offer on v6.6.4 through v7.1.2.
    - Passes credentials via an ephemeral SSH_ASKPASS helper backed by an environment
      variable so passwords never appear in command-line arguments and the temporary
      helper is always deleted in a finally block.
    - Forces legacy SCP protocol (-O) because APC NMC2 does not implement an SFTP
      subsystem, whereas OpenSSH 9.x defaults scp to SFTP.

Constraints / Trade-offs:
    - Uses Python's stdlib telnetlib for v5.x cards prior to SSH enablement (compatible
      with Python <= 3.12; Python 3.13+ users should use SSH once on v6.6.4+ or install
      telnetlib3).
    - APC NMC2 only permits one concurrent SSH/SCP session; callers should allow a brief
      cooldown (3-5 seconds) between closing an SSH shell and starting an SCP transfer.
"""

from __future__ import annotations

import argparse
import ftplib
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple

try:
    import telnetlib  # type: ignore[import-not-found]
except ImportError:
    telnetlib = None  # Python 3.13+ removed stdlib telnetlib


# APC NMC2 (cryptlib SSH daemon on v6.6.4-v7.1.2) advertises ssh-rsa host keys and
# older KEX/cipher suites disabled by default in modern OpenSSH 9.x clients.
SSH_COMPAT_OPTS: List[str] = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=" + ("NUL" if os.name == "nt" else "/dev/null"),
    "-o", "HostKeyAlgorithms=+ssh-rsa",
    "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
    "-o", "KexAlgorithms=+diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1",
    "-o", "Ciphers=+aes128-cbc,aes256-cbc,3des-cbc",
    "-o", "ConnectTimeout=15",
]


def probe_management_ports(
    host: str,
    ports: Sequence[int] = (21, 22, 23, 80, 443),
    timeout: float = 1.5,
) -> Dict[int, Tuple[bool, str]]:
    """Checks TCP reachability and captures initial service banners for NMC2 ports."""
    results: Dict[int, Tuple[bool, str]] = {}
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                banner = ""
                if port in (21, 22, 23):
                    sock.settimeout(1.2)
                    try:
                        banner = repr(sock.recv(512))
                    except OSError:
                        banner = "b''"
                results[port] = (True, banner)
        except OSError as exc:
            results[port] = (False, str(exc))
    return results


def wait_for_card_reboot(
    host: str,
    check_ports: Sequence[int] = (21, 22, 23),
    min_down_wait: int = 10,
    max_wait: int = 240,
) -> Tuple[int, bytes]:
    """Waits for the card to drop offline after a flash/reboot and return with a live banner."""
    start_time = time.time()
    went_down = False

    # Wait up to 30 seconds to observe the management interface actually go offline so
    # we never mistake the pre-reboot daemon for a completed reboot.
    while time.time() - start_time < max(min_down_wait, 30):
        any_open = False
        for port in check_ports:
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    any_open = True
                    break
            except OSError:
                pass
        if not any_open:
            went_down = True
            print(f"  [reboot] Card offline at +{time.time() - start_time:.1f}s")
            break
        time.sleep(1.0)

    if not went_down:
        print("  [reboot] Warning: card did not drop within 30s; continuing port poll...")

    print(f"  [reboot] Waiting for card to return on ports {tuple(check_ports)}...")
    while time.time() - start_time < max_wait:
        for port in check_ports:
            try:
                with socket.create_connection((host, port), timeout=2.0) as sock:
                    banner = b""
                    sock.settimeout(2.5)
                    try:
                        banner = sock.recv(512)
                    except OSError:
                        pass
                    if banner or port not in (21, 22):
                        print(f"  [reboot] Port {port} UP at +{time.time() - start_time:.1f}s | banner={banner!r}")
                        return port, banner
            except OSError:
                pass
        time.sleep(2.5)

    raise TimeoutError(f"Card at {host} did not return on ports {check_ports} within {max_wait}s")


def ftp_upload_single_binary(
    host: str,
    local_path: str,
    username: str = "apc",
    password: str = "apc",
    wait_ports: Sequence[int] = (22, 21, 23),
) -> Tuple[int, bytes]:
    """Uploads a single .bin payload via binary FTP, validates byte count and 226 reply, and awaits reboot."""
    if not os.path.isfile(local_path):
        raise FileNotFoundError(f"Firmware binary not found: {local_path}")

    filename = os.path.basename(local_path)
    expected_size = os.path.getsize(local_path)
    print(f"=== FTP BINARY PUT: {filename} ({expected_size} bytes) -> {host} ===")

    ftp = ftplib.FTP()
    ftp.connect(host, 21, timeout=15)
    print(f"  Pre-upload banner: {ftp.getwelcome()}")
    ftp.login(username, password)
    ftp.set_pasv(True)

    bytes_sent = [0]

    def track_progress(chunk: bytes) -> None:
        bytes_sent[0] += len(chunk)

    t0 = time.time()
    with open(local_path, "rb") as handle:
        # storbinary issues TYPE I (binary mode) automatically before STOR.
        response = ftp.storbinary(f"STOR {filename}", handle, blocksize=8192, callback=track_progress)
    elapsed = time.time() - t0
    print(f"  Transfer finished in {elapsed:.1f}s | sent={bytes_sent[0]}/{expected_size} bytes | reply: {response}")

    if bytes_sent[0] != expected_size:
        raise RuntimeError(f"Incomplete transfer: sent {bytes_sent[0]} of {expected_size} bytes")
    if not response.startswith("226"):
        raise RuntimeError(f"Unexpected FTP STOR reply (expected 226): {response}")

    # APC NMC2 initiates flash commit and reboot immediately after QUIT (or right after 226).
    try:
        print(f"  FTP QUIT: {ftp.quit()}")
    except Exception as exc:
        print(f"  FTP QUIT closed during reboot (expected): {exc}")
        try:
            ftp.close()
        except Exception:
            pass

    port_up, banner = wait_for_card_reboot(host, check_ports=wait_ports, min_down_wait=10, max_wait=240)
    time.sleep(5)
    return port_up, banner


def ftp_backup_config(host: str, local_path: str, username: str = "apc", password: str = "apc") -> None:
    """Downloads config.ini over FTP prior to firmware upgrades."""
    os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
    ftp = ftplib.FTP()
    ftp.connect(host, 21, timeout=10)
    ftp.login(username, password)
    ftp.set_pasv(True)
    with open(local_path, "wb") as handle:
        ftp.retrbinary("RETR config.ini", handle.write)
    ftp.quit()
    print(f"Saved FTP config.ini backup -> {local_path} ({os.path.getsize(local_path)} bytes)")


def run_telnet_commands(
    host: str,
    commands: Sequence[str],
    username: str = "apc",
    password: str = "apc",
    timeout: int = 8,
) -> None:
    """Executes interactive CLI commands over Telnet (for v5.x cards prior to SSH enablement)."""
    if telnetlib is None:
        raise RuntimeError("Python stdlib telnetlib is unavailable on Python 3.13+; use SSH on v6.6.4+.")

    tn = telnetlib.Telnet(host, 23, timeout=timeout)

    def read_until_any(tokens: Sequence[bytes], wait: float = 6.0) -> bytes:
        deadline = time.time() + wait
        buffer = b""
        while time.time() < deadline:
            try:
                chunk = tn.read_very_eager()
                if chunk:
                    buffer += chunk
                    for token in tokens:
                        if token in buffer:
                            return buffer
            except EOFError:
                break
            time.sleep(0.1)
        return buffer

    read_until_any([b"User Name", b"Username"])
    tn.write(username.encode("utf-8") + b"\r\n")
    read_until_any([b"Password"])
    tn.write(password.encode("utf-8") + b"\r\n")
    login_banner = read_until_any([b"apc>", b"New Password"], wait=8.0)
    print(login_banner.decode("latin1", errors="replace"))
    if b"apc>" not in login_banner:
        tn.close()
        raise RuntimeError("Failed to reach apc> prompt over Telnet.")

    for command in commands:
        tn.write(command.encode("utf-8") + b"\r\n")
        if command.strip().lower() == "reboot":
            reply = read_until_any([b"YES", b"apc>", b"Rebooting"], wait=5.0)
            if b"YES" in reply:
                tn.write(b"YES\r\n")
                reply += read_until_any([b"Rebooting", b"apc>"], wait=4.0)
        else:
            reply = read_until_any([b"apc>"], wait=6.0)
        print(f"=== {command} ===")
        print(reply.decode("latin1", errors="replace"))

    try:
        tn.write(b"bye\r\n")
        tn.close()
    except OSError:
        pass


def _create_ephemeral_askpass(password: str) -> Tuple[str, Dict[str, str]]:
    """Creates a temporary SSH_ASKPASS script reading password from an environment variable."""
    suffix = ".cmd" if os.name == "nt" else ".sh"
    fd, script_path = tempfile.mkstemp(suffix=suffix)
    if os.name == "nt":
        payload = f'@"{sys.executable}" -c "import os; print(os.environ[\'APC_SSH_PW\'])"\r\n'
    else:
        payload = f'#!/bin/sh\n"{sys.executable}" -c "import os; print(os.environ[\'APC_SSH_PW\'])"\n'
    os.write(fd, payload.encode("ascii"))
    os.close(fd)
    if os.name != "nt":
        os.chmod(script_path, 0o700)

    env = os.environ.copy()
    env["APC_SSH_PW"] = password
    env["SSH_ASKPASS"] = script_path
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["DISPLAY"] = "1"
    return script_path, env


def run_ssh_commands(
    host: str,
    commands: Sequence[str],
    username: str = "apc",
    password: str = "apc",
    new_password: Optional[str] = None,
) -> None:
    """Executes interactive CLI commands via native OpenSSH with legacy ssh-rsa compatibility."""
    askpass_path, env = _create_ephemeral_askpass(password)
    ssh_bin = "ssh.exe" if os.name == "nt" else "ssh"
    try:
        proc = subprocess.Popen(
            [ssh_bin] + SSH_COMPAT_OPTS + ["-tt", f"{username}@{host}"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            bufsize=0,
        )
        assert proc.stdin is not None and proc.stdout is not None

        byte_queue: "queue.Queue[bytes]" = queue.Queue()

        def stream_reader() -> None:
            while True:
                ch = proc.stdout.read(1)  # type: ignore[union-attr]
                if not ch:
                    break
                byte_queue.put(ch)

        threading.Thread(target=stream_reader, daemon=True).start()

        def read_until_any(tokens: Sequence[bytes], wait: float = 12.0) -> bytes:
            deadline = time.time() + wait
            buf = b""
            while time.time() < deadline:
                try:
                    buf += byte_queue.get(timeout=0.1)
                    while not byte_queue.empty():
                        buf += byte_queue.get_nowait()
                    lower_buf = buf.lower()
                    for token in tokens:
                        if token.lower() in lower_buf:
                            return buf
                except queue.Empty:
                    if proc.poll() is not None:
                        break
            return buf

        banner = read_until_any(
            [b"apc>", b"new password", b"permission denied", b"connection closed"],
            wait=15.0,
        )
        print(banner.decode("latin1", errors="replace"))

        if b"new password" in banner.lower():
            if not new_password:
                proc.terminate()
                raise RuntimeError("NMC2 forced a password change; re-run with --new-pwd.")
            proc.stdin.write(new_password.encode("utf-8") + b"\r")
            proc.stdin.flush()
            confirm = read_until_any([b"confirm", b"re-enter", b"apc>", b"error"], wait=10.0)
            print(confirm.decode("latin1", errors="replace"))
            if b"apc>" not in confirm.lower():
                proc.stdin.write(new_password.encode("utf-8") + b"\r")
                proc.stdin.flush()
                done = read_until_any([b"apc>", b"error"], wait=10.0)
                print(done.decode("latin1", errors="replace"))
        elif b"apc>" not in banner:
            proc.terminate()
            raise RuntimeError("Did not reach apc> prompt over SSH.")

        for command in commands:
            proc.stdin.write(command.encode("utf-8") + b"\r")
            proc.stdin.flush()
            if command.strip().lower() == "reboot":
                reply = read_until_any([b"yes", b"apc>", b"rebooting"], wait=6.0)
                if b"yes" in reply.lower():
                    proc.stdin.write(b"YES\r")
                    proc.stdin.flush()
                    reply += read_until_any([b"rebooting", b"connection", b"apc>"], wait=6.0)
            else:
                reply = read_until_any([b"apc>"], wait=10.0)
            print(f"=== {command} ===")
            print(reply.decode("latin1", errors="replace"))

        try:
            proc.stdin.write(b"bye\r")
            proc.stdin.flush()
            time.sleep(0.5)
        except OSError:
            pass
        proc.terminate()
    finally:
        if os.path.exists(askpass_path):
            os.remove(askpass_path)


def scp_download_config(host: str, local_path: str, username: str = "apc", password: str = "apc") -> None:
    """Downloads config.ini over legacy SCP (-O) after hardening disables FTP."""
    os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
    askpass_path, env = _create_ephemeral_askpass(password)
    scp_bin = "scp.exe" if os.name == "nt" else "scp"
    try:
        # Remote filename MUST be 'config.ini' without a leading slash; '/config.ini'
        # produces 'apc-scp: file open error' on NMC2.
        result = subprocess.run(
            [scp_bin, "-O"] + SSH_COMPAT_OPTS + [f"{username}@{host}:config.ini", local_path],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        # NMC2 occasionally closes the SCP channel early at EOF after transferring the
        # entire generated config.ini; verify file presence and header rather than rc alone.
        if os.path.isfile(local_path) and os.path.getsize(local_path) > 1024:
            print(f"Saved SCP config.ini backup -> {local_path} ({os.path.getsize(local_path)} bytes)")
            return
        raise RuntimeError(f"SCP backup failed (rc={result.returncode}): {result.stderr.strip()}")
    finally:
        if os.path.exists(askpass_path):
            os.remove(askpass_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="APC NMC2 (AP9630 hw05) Staged Upgrade Helper")
    sub = parser.add_subparsers(dest="action", required=True)

    p_probe = sub.add_parser("probe", help="Probe TCP ports 21, 22, 23, 80, 443 and banners")
    p_probe.add_argument("host")

    p_fbak = sub.add_parser("ftp-backup", help="Backup config.ini over FTP")
    p_fbak.add_argument("host")
    p_fbak.add_argument("local_path")
    p_fbak.add_argument("--user", default="apc")
    p_fbak.add_argument("--pwd", default="apc")

    p_fput = sub.add_parser("ftp-put", help="Upload a single .bin via binary FTP and await reboot")
    p_fput.add_argument("host")
    p_fput.add_argument("file")
    p_fput.add_argument("--user", default="apc")
    p_fput.add_argument("--pwd", default="apc")
    p_fput.add_argument("--wait-ports", default="22,21,23")

    p_tel = sub.add_parser("telnet", help="Run interactive Telnet CLI commands (v5.x)")
    p_tel.add_argument("host")
    p_tel.add_argument("--user", default="apc")
    p_tel.add_argument("--pwd", default="apc")
    p_tel.add_argument("cmds", nargs="+")

    p_ssh = sub.add_parser("ssh", help="Run interactive OpenSSH CLI commands (v6.6.4+)")
    p_ssh.add_argument("host")
    p_ssh.add_argument("--user", default="apc")
    p_ssh.add_argument("--pwd", default="apc")
    p_ssh.add_argument("--new-pwd", default=None)
    p_ssh.add_argument("cmds", nargs="+")

    p_sbak = sub.add_parser("scp-backup", help="Backup config.ini over legacy SCP (-O)")
    p_sbak.add_argument("host")
    p_sbak.add_argument("local_path")
    p_sbak.add_argument("--user", default="apc")
    p_sbak.add_argument("--pwd", default="apc")

    args = parser.parse_args()
    if args.action == "probe":
        for port, (is_open, detail) in probe_management_ports(args.host).items():
            print(f"  {args.host}:{port:<3} -> {'OPEN' if is_open else 'closed'} {detail}")
    elif args.action == "ftp-backup":
        ftp_backup_config(args.host, args.local_path, args.user, args.pwd)
    elif args.action == "ftp-put":
        ports = tuple(int(x) for x in args.wait_ports.split(","))
        ftp_upload_single_binary(args.host, args.file, args.user, args.pwd, wait_ports=ports)
    elif args.action == "telnet":
        run_telnet_commands(args.host, args.cmds, args.user, args.pwd)
    elif args.action == "ssh":
        run_ssh_commands(args.host, args.cmds, args.user, args.pwd, new_password=args.new_pwd)
    elif args.action == "scp-backup":
        scp_download_config(args.host, args.local_path, args.user, args.pwd)


if __name__ == "__main__":
    main()
