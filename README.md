# APC NMC2 (AP9630 / AP9631 `hw05`) Safe Firmware Upgrade & Hardening Guide

A field-tested, step-by-step runbook for safely upgrading legacy **APC Network Management Card 2 (NMC2 — `AP9630` / `AP9631`, Hardware Revision `05`)** cards from ancient **`v5.1.3` (2010)** firmware up to **`v7.1.2` (TLStorm-patched, TLS 1.2, SSHv2, SNMPv3)** — plus hardening and troubleshooting lessons learned the hard way.

> **Hardware Compatibility Warning — Read First**
> This guide and all firmware files apply **strictly to NMC2 (`hw05` — `AP9630` / `AP9631` / `AP9635`) Smart-UPS (`sumx`)** cards.
> **Never** flash `apc_hw05_*` binaries onto an older **NMC1 (`hw02` — `AP9617` / `AP9619`)** card or a Symmetra (`sy`) / PDU (`rpdu`) application card. Always verify `Hardware Revision: 05` and `Application Module: sumx` in `about` first.
>
> *Note on UPS firmware:* On legacy Smart-UPS models (e.g., SUA-series Smart-UPS 1500 RM), the UPS microcontroller firmware itself is not network-upgradeable. Only the SmartSlot NMC2 card firmware is upgraded here.

---

## 1. Verified Staged Firmware Packages (`apc_hw05` / `sumx`)

Jumping directly from `v5.x` (`bootmon v1.0.1`) to `v7.x` (`bootmon v1.0.9`) frequently bricks or strands NMC2 cards. Stepping cleanly through four verified Schneider Electric-signed releases avoids flash/config corruption.

Every installer below has been verified for both **SHA-1 integrity** and a **Valid Windows Authenticode signature from Schneider Electric**. All four signed installers are mirrored under [**GitHub Releases (`v1.0.0`)**](https://github.com/Ezra90/apc-nmc2-ap9630-upgrade-guide/releases/tag/v1.0.0) in case upstream mirrors go offline, alongside their original **Archive.org** source references:

| Stage | Target Version | Boot Monitor | Package Filename | Verified SHA-1 | Authenticode Signer | Mirrors |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Stage 1** | `v6.6.4` | `v1.0.8` | `apc_hw05_aos664_sumx664_bootmon108.exe` | `0ab24997839accd88006ceb9a411dca60206dc4d` | `Schneider Electric` (FR) | [GitHub Release](https://github.com/Ezra90/apc-nmc2-ap9630-upgrade-guide/releases/download/v1.0.0/apc_hw05_aos664_sumx664_bootmon108.exe) · [Archive.org](https://archive.org/download/ups-network-management-card-2-ap9630ap9631-firmware/apc_hw05_aos664_sumx664_bootmon108.exe) |
| **Stage 2** | `v6.9.6` | `v1.0.9` | `apc_hw05_aos696_sumx696_bootmon109.exe` | `651df26e0bced4defaea5e4a991a8b6a855630d2` | `Schneider Electric USA Inc.` | [GitHub Release](https://github.com/Ezra90/apc-nmc2-ap9630-upgrade-guide/releases/download/v1.0.0/apc_hw05_aos696_sumx696_bootmon109.exe) · [Archive.org](https://archive.org/download/apc_hw05_aos696_sumx696_bootmon109/apc_hw05_aos696_sumx696_bootmon109.exe) |
| **Stage 3** | `v7.0.8` | `v1.0.9` | `apc_hw05_aos708_sumx708_bootmon109.exe` | `d2fdd803daa320d2b064e8915ab1a264135d2851` | `SCHNEIDER ELECTRIC USA, INC.` | [GitHub Release](https://github.com/Ezra90/apc-nmc2-ap9630-upgrade-guide/releases/download/v1.0.0/apc_hw05_aos708_sumx708_bootmon109.exe) · [Archive.org](https://archive.org/download/ups-network-management-card-2-ap9630ap9631-firmware/apc_hw05_aos708_sumx708_bootmon109.exe) |
| **Stage 4** | `v7.1.2` | `v1.0.9` | `apc_hw05_aos712_sumx712_bootmon109.exe` | `f6a740dcb8bae14b8f2ab5405b98d2715ec205a1` | `SCHNEIDER ELECTRIC USA, INC.` | [GitHub Release](https://github.com/Ezra90/apc-nmc2-ap9630-upgrade-guide/releases/download/v1.0.0/apc_hw05_aos712_sumx712_bootmon109.exe) · [Archive.org](https://archive.org/download/ups-network-management-card-2-ap9630ap9631-firmware/apc_hw05_aos712_sumx712_bootmon109.exe) |
| **Optional Stage 5** | `v7.2.2` (`SFSUMX722`) | `v1.0.9` | Final NMC2 release | *(Verify Authenticode)* | Schneider Electric | [SE.com AP9630 Page](https://www.se.com/us/en/product/AP9630/apc-ups-network-management-card-2/) (Software & Firmware tab) |
| *Legacy Fallback* | `v5.1.6` | `v1.0.2` | `apc_hw05_aos516_sumx516_bootmon102.exe` | `720eba2d11dff1e14c3443be8227864554980214` | *Unsigned 2010 PE — fallback only* | [Archive.org](https://archive.org/download/ups-network-management-card-2-ap9630ap9631-firmware/apc_hw05_aos516_sumx516_bootmon102.exe) |

### Extracted `.bin` Payload Reference

> **Quirk:** In Stage 1 (`v6.6.4`), `.bin` files extract to the archive root. In Stages 2–4 (`v6.9.6`–`v7.1.2`), `.bin` files extract inside a `Bins\` subfolder. `apc_hw05_bootmon_109.bin` is byte-identical across Stages 2–4 (`sha256:891b2a88385a3bda...`) and only needs to be flashed once.

| Stage | `bootmon` | `aos` | `sumx` |
| :--- | :--- | :--- | :--- |
| **v6.6.4** | `apc_hw05_bootmon_108.bin` (262,144 B) | `apc_hw05_aos_664.bin` (3,069,184 B) | `apc_hw05_sumx_664.bin` (3,032,116 B) |
| **v6.9.6** | `Bins\apc_hw05_bootmon_109.bin` (262,144 B) | `Bins\apc_hw05_aos_696.bin` (3,137,536 B) | `Bins\apc_hw05_sumx_696.bin` (3,018,116 B) |
| **v7.0.8** | *(already `v1.0.9`)* | `Bins\apc_hw05_aos_708.bin` (3,127,808 B) | `Bins\apc_hw05_sumx_708.bin` (3,023,396 B) |
| **v7.1.2** | *(already `v1.0.9`)* | `Bins\apc_hw05_aos_712.bin` (3,130,624 B) | `Bins\apc_hw05_sumx_712.bin` (3,026,804 B) |

### Automated Download, Verification & Extraction (Windows)

Run [`scripts/download_and_verify.ps1`](scripts/download_and_verify.ps1) to fetch all four installers, verify SHA-1 and Schneider Electric Authenticode signatures, and extract the `.bin` files safely using 7-Zip (without executing any `.exe`):

```powershell
.\scripts\download_and_verify.ps1 -OutputDir C:\apc-fw
```

---

## 2. Golden Rules Before Flashing

1. **Direct Layer-2 LAN Access:** Run the upgrade from a laptop/workstation on the same Layer-2 VLAN as the UPS (not behind Docker NAT) so ARP recovery (`arp -s` + `ping -l 113`) and IPv6 link-local work if needed.
2. **Verify Hardware & Back Up `config.ini` First:** Confirm `Model Number: AP9630` (or `AP9631`), `Hardware Revision: 05`, and `Name: sumx`, then save `config.ini` via FTP.
3. **One `.bin` at a Time — Strictly in Order:**
   - Upload **`bootmon`** (binary FTP) → wait for reboot → verify version in `about`
   - Upload **`aos`** (binary FTP) → wait for reboot → verify FTP banner shows the new AOS version
   - Upload **`sumx`** (binary FTP) → wait for reboot → verify `about` shows matching AOS + SUMX and `Stat: ... A+`
   - **Abort immediately** if any verification gate fails.
4. **Set Temporary Static IPv4 Before Crossing `v5.x → v6.x`:** This is the single most important safeguard (see Section 3).
5. **Enable SSH & HTTPS on `v6.6.4` Before Crossing to `v6.9.6+`:** Later releases tighten FTP/Telnet defaults and may force changing the default `apc`/`apc` password.
6. **Harden Only After Reaching Final Firmware (`v7.1.2` / `v7.2.2`):** Keep upgrades smooth first, lock down protocols and credentials last.

---

## 3. Step-by-Step Upgrade Procedure (`v5.1.3` → `v7.1.2`)

Replace `<UPS_IP>` (e.g., `192.168.1.50`) and `<GATEWAY_IP>` (e.g., `192.168.1.1`) with your bench network values.

### Step 0 — Identify Card & Back Up `config.ini`

```powershell
python scripts/apc_nmc2_tool.py probe <UPS_IP>
python scripts/apc_nmc2_tool.py ftp-backup <UPS_IP> backups\card_v5.1.3_config.ini
python scripts/apc_nmc2_tool.py telnet <UPS_IP> about boot tcpip
```

Verify in the output:
- `Model Number: AP9630` (or `AP9631`)
- `Hardware Revision: 05`
- `Application Module: sumx`

### Step 1 — Set Temporary Static IPv4 Safeguard (Prevents `v5 → v6` DHCP Dropout!)

When crossing from `v5.1.3` to `v6.6.4`, cards configured for `BootMode=DHCP Only` frequently lose their IPv4 address after `aos_664.bin` reboots because the `v5 → v6` config migration can re-enable `DHCPRequireCookie` (Option 43 `1APC`). Setting a temporary **manual static IPv4** before flashing completely avoids this failure mode:

```powershell
python scripts/apc_nmc2_tool.py telnet <UPS_IP> `
    "tcpip -i <UPS_IP> -s 255.255.255.0 -g <GATEWAY_IP>" `
    "boot -b manual" `
    "reboot"
```

Wait ~25 seconds and verify `Boot Mode: manual` and `Manual Settings: enabled`:

```powershell
python scripts/apc_nmc2_tool.py telnet <UPS_IP> tcpip boot
```

### Step 2 — Stage 1: Upgrade to `v6.6.4` (`bootmon v1.0.8`)

```powershell
# 2a. Boot Monitor v1.0.8 (~25s reboot)
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage1_v6.6.4\apc_hw05_bootmon_108.bin --wait-ports 21,23
python scripts/apc_nmc2_tool.py telnet <UPS_IP> about
# GATE: Confirm "APC Boot Monitor: v1.0.8" (Application Module showing bootmon / Stat A- is normal until sumx is flashed)

# 2b. AOS v6.6.4 (~60-90s flash + reboot)
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage1_v6.6.4\apc_hw05_aos_664.bin --wait-ports 21,23
python scripts/apc_nmc2_tool.py probe <UPS_IP>
# GATE: Confirm port 21 banner reports "AOS v6.6.4"

# 2c. SUMX v6.6.4 (~20s reboot)
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage1_v6.6.4\apc_hw05_sumx_664.bin --wait-ports 21,23
python scripts/apc_nmc2_tool.py telnet <UPS_IP> about boot
# GATE: Confirm bootmon v1.0.8, aos v6.6.4, sumx v6.6.4, Stat: P+ N4+ N6+ A+
```

### Step 3 — Enable SSH & HTTPS (TLS 1.2) on `v6.6.4` Before Crossing to `v6.9.6+`

```powershell
python scripts/apc_nmc2_tool.py telnet <UPS_IP> "console -s enable" "web -s enable -mp TLS1.2" "reboot"
```

> **Wait ~90 seconds on first boot:** Generating the RSA SSH host key and self-signed HTTPS certificate on the NMC2 CPU takes 60–95 seconds.

Verify SSH login works before proceeding:

```powershell
python scripts/apc_nmc2_tool.py probe <UPS_IP>
python scripts/apc_nmc2_tool.py ssh <UPS_IP> about console web ftp
```

### Step 4 — Stage 2: Upgrade to `v6.9.6` (`bootmon v1.0.9`)

```powershell
# 4a. Boot Monitor v1.0.9
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage2_v6.9.6\Bins\apc_hw05_bootmon_109.bin
python scripts/apc_nmc2_tool.py ssh <UPS_IP> about
# GATE: Confirm "APC Boot Monitor: v1.0.9"

# 4b. AOS v6.9.6
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage2_v6.9.6\Bins\apc_hw05_aos_696.bin
python scripts/apc_nmc2_tool.py probe <UPS_IP>
# GATE: Confirm banner "AOS v6.9.6"

# 4c. SUMX v6.9.6
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage2_v6.9.6\Bins\apc_hw05_sumx_696.bin
python scripts/apc_nmc2_tool.py ssh <UPS_IP> about
# GATE: Confirm bootmon v1.0.9, aos v6.9.6, sumx v6.9.6, Stat: A+
```

### Step 5 — Stage 3: Upgrade to `v7.0.8`

`bootmon` is already `v1.0.9` — do not re-flash it.

```powershell
# 5a. AOS v7.0.8
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage3_v7.0.8\Bins\apc_hw05_aos_708.bin
python scripts/apc_nmc2_tool.py probe <UPS_IP>
# GATE: Confirm banner "AOS v7.0.8"

# 5b. SUMX v7.0.8
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage3_v7.0.8\Bins\apc_hw05_sumx_708.bin
python scripts/apc_nmc2_tool.py ssh <UPS_IP> about
# GATE: Confirm bootmon v1.0.9, aos v7.0.8, sumx v7.0.8, Stat: A+
```

### Step 6 — Stage 4: Upgrade to `v7.1.2` (TLStorm Patched)

```powershell
# 6a. AOS v7.1.2
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage4_v7.1.2\Bins\apc_hw05_aos_712.bin
python scripts/apc_nmc2_tool.py probe <UPS_IP>
# GATE: Confirm banner "AOS v7.1.2"

# 6b. SUMX v7.1.2
python scripts/apc_nmc2_tool.py ftp-put <UPS_IP> C:\apc-fw\stage4_v7.1.2\Bins\apc_hw05_sumx_712.bin
python scripts/apc_nmc2_tool.py ssh <UPS_IP> about
# GATE: Confirm bootmon v1.0.9, aos v7.1.2, sumx v7.1.2, Stat: A+
```

---

## 4. Post-Upgrade Hardening (`v7.1.2+`)

Once `v7.1.2` (or optional `v7.2.2`) is verified with `Stat: P+ N4+ N6+ A+`, lock down all insecure protocols, configure **SNMPv3 (`SHA` + `AES`)**, restore **DHCP (`DHCPRequireCookie=disabled`)**, configure NTP, and rotate the default `apc`/`apc` credentials.

> **Important CLI Quirks:**
> - **SNMPv1 disable must be separate commands:** Combining `snmp -S disable -a1 disable ...` returns `E102: Parameter Error` on NMC2. Issue `-S disable` and each `-a[1-4] disable` separately.
> - **SNMPv3 passphrase length:** APC NMC2 requires **15 to 32 ASCII characters** for both Auth (`-a1`) and Privacy (`-c1`) passphrases. Avoid shell/YAML metacharacters (`$`, `"`, `'`, `\`, spaces).

```powershell
python scripts/apc_nmc2_tool.py ssh <UPS_IP> `
    "snmp -S disable" `
    "snmp -a1 disable" `
    "snmp -a2 disable" `
    "snmp -a3 disable" `
    "snmp -a4 disable" `
    "snmpv3 -S enable -u1 nutmon -ap1 sha -pp1 aes -a1 <SNMPV3_AUTH_15_TO_32_CHARS> -c1 <SNMPV3_PRIV_15_TO_32_CHARS>" `
    "snmpv3 -au1 nutmon -ac1 enable -n1 0.0.0.0" `
    "console -t disable -s enable" `
    "web -h disable -s enable -mp TLS1.2" `
    "ftp -S disable" `
    "boot -b dhcp -c disable" `
    "date -z +10:00" `
    "ntp -p pool.ntp.org -s time.cloudflare.com -e enable" `
    "ntp -u" `
    "user -n apc -cp apc -pw <STRONG_ADMIN_PASSWORD>" `
    "reboot"
```

### Final Verification & Encrypted Backup

Wait ~35 seconds after reboot, then confirm:
1. Ports `21` (FTP), `23` (Telnet), and `80` (HTTP) are **closed**.
2. Ports `22` (SSH) and `443` (HTTPS TLS 1.2) are **open**.
3. SSH works with `<STRONG_ADMIN_PASSWORD>` and shows `SNMPv1: Disabled`, `SNMPv3: Enabled`, `Boot Mode: dhcp`, `DHCP Cookie: disabled`.
4. Save the final hardened `config.ini` over SCP (wait 5 seconds after closing SSH — NMC2 allows only one SSH/SCP session at a time):

```powershell
python scripts/apc_nmc2_tool.py probe <UPS_IP>
python scripts/apc_nmc2_tool.py ssh <UPS_IP> --pwd "<STRONG_ADMIN_PASSWORD>" about boot snmp snmpv3 console web ftp ntp date
Start-Sleep -Seconds 5
python scripts/apc_nmc2_tool.py scp-backup <UPS_IP> backups\card_v7.1.2_hardened_config.ini --pwd "<STRONG_ADMIN_PASSWORD>"
```

### Example NUT (`snmp-ups`) Configuration for SNMPv3

```ini
[ups_main]
    driver = snmp-ups
    port = <UPS_IP>
    desc = "APC Smart-UPS (AP9630 SNMPv3)"
    mibs = apcc
    snmp_version = v3
    secLevel = authPriv
    secName = nutmon
    authProtocol = SHA
    authPassword = <SNMPV3_AUTH_15_TO_32_CHARS>
    privProtocol = AES
    privPassword = <SNMPV3_PRIV_15_TO_32_CHARS>
    pollfreq = 15
```

---

## 5. Troubleshooting & Field-Tested Gotchas

### 1. Card Loses IPv4 After Flashing `aos_664.bin` (Link UP, No ARP/Ping)
- **Cause:** Upgrading from `v5.x` → `v6.x` while in DHCP mode can reset `DHCPRequireCookie` to `enabled`. If your DHCP server does not supply Option 43 `1APC` (`01:04:31:41:50:43`), the card ignores every DHCP offer and holds `0.0.0.0`.
- **Prevention:** Set temporary `boot -b manual` static IPv4 before flashing `aos_664.bin` (Step 1 above).
- **Layer-2 Recovery (`arp -s` + 113-byte ping):** On an elevated Windows Command Prompt (Administrator) on the same Layer-2 VLAN, **explicitly bind your wired NIC's IP** (critical if Hyper-V, VirtualBox, or Wi-Fi adapters exist):
  ```cmd
  arp -s <DESIRED_UPS_IP> 00-c0-b7-xx-xx-xx <LAPTOP_WIRED_LAN_IP>
  ping <DESIRED_UPS_IP> -l 113 -n 4
  ```
  Wait 10–15 seconds and probe FTP port 21 (`AOS v6.6.4`) or Telnet port 23. Alternatively, test IPv6 link-local derived from the card's MAC (`fe80::2c0:b7ff:fexx:xxxx%<InterfaceIndex>`).

### 2. Modern OpenSSH / Paramiko Refuses to Connect (`no matching host key type found. Their offer: ssh-rsa`)
- **Cause:** APC NMC2's embedded `SSH-2.0-cryptlib` daemon offers `ssh-rsa` host keys even on `v7.1.2`. OpenSSH 8.8+ disables `ssh-rsa` by default, and Paramiko 5.0+ removed SHA-1 RSA verification altogether.
- **Fix:** Use native OpenSSH with compatibility flags:
  ```powershell
  ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa apc@<UPS_IP>
  ```

### 3. `scp` Fails with SFTP Error or `apc-scp: file open error` or `Connection closed`
- **Three distinct APC NMC2 SCP quirks:**
  1. **Use `scp -O`:** OpenSSH 9.x defaults `scp` to SFTP, which NMC2 does not implement. Pass `-O` to force legacy SCP protocol.
  2. **No leading slash:** Request `apc@<UPS_IP>:config.ini`, **not** `:/config.ini` (which fails with `apc-scp: file open error`).
  3. **Single concurrent SSH/SCP session:** NMC2 allows only one active SSH/SCP session at a time. Wait 3–5 seconds after closing an `ssh` session before running `scp`.

### 4. `snmp -S disable -a1 disable` Returns `E102: Parameter Error`
- **Cause:** NMC2's `snmp` CLI parser rejects combining `-S` with `-a[n]` flags in one command.
- **Fix:** Run `snmp -S disable`, then `snmp -a1 disable` through `snmp -a4 disable` as separate commands.

### 5. Serial Console Gotchas (Cable Type & Prolific Code 10)
- **Wrong port:** The UPS chassis **DB9** and **USB-B** ports talk to the UPS microcontroller (PowerChute/NUT), **not** the AP9630 card. The AP9630 serial console is the tiny **2.5 mm TRS jack** on the card faceplate (APC cable `940-0299A`, **9600 baud, 8N1, no flow control**).
- **Windows 11 Prolific PL2303 Code 10:** Older Prolific USB-to-serial adapters (`VID_067B&PID_2303&REV_0300`, PL2303HXA) fail to start (`CM_PROB_FAILED_START`, Code 10) under Windows Prolific drivers `3.4.x+`. Use an FTDI/CH340/PL2303GC adapter (or legacy `3.3.2.102` driver) if serial recovery is strictly required.

### 6. Slow Uploads (~50s per 3 MB `.bin`) & 10 Mbps Half-Duplex Link
- **Cause:** Older AP9630 PHY chips sometimes auto-negotiate `10 Half_Duplex` with modern gigabit switches.
- **Behavior:** Completely safe for upgrades — a 3.1 MB `.bin` takes ~48–50 seconds to upload, followed by ~60–70 seconds of flash erase/write + reboot for `aos`, and ~17–25 seconds for `bootmon`/`sumx`. Do not interrupt power during flash commit.

### 7. OpenSSL 3.x `UNSAFE_LEGACY_RENEGOTIATION_DISABLED` on HTTPS
- **Cause:** Python/OpenSSL 3.x enforces RFC 5746 secure renegotiation strictly, whereas NMC2's embedded TLS 1.2 stack omits the extension on some handshakes. Modern Chromium/Edge/Firefox browsers connect cleanly to `https://<UPS_IP>` after accepting the self-signed certificate.

---

## Disclaimer

Firmware binaries are copyright Schneider Electric / APC. This repository documents verified official checksums, Authenticode validation, safe upgrade procedures, and troubleshooting practices for maintaining legacy hardware. Always back up `config.ini` and verify hardware revision (`hw05`) before flashing.
