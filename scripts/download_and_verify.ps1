<#
.SYNOPSIS
    Downloads, cryptographically verifies, and extracts APC NMC2 (AP9630/AP9631 hw05)
    Smart-UPS (sumx) staged firmware packages without executing the installer binaries.

.DESCRIPTION
    Architectural Context:
        Legacy APC Network Management Card 2 (NMC2 / hardware revision hw05) units running
        v5.x firmware cannot jump directly to v7.x without risking configuration resets,
        boot monitor mismatches, or bricked flash partitions. Schneider Electric retired
        many intermediate archives from public product pages, leaving administrators to
        source historical releases from community mirrors such as archive.org.

    Purpose:
        Automates retrieval of the four verified staged firmware installers (v6.6.4,
        v6.9.6, v7.0.8, v7.1.2), enforces both SHA-1 integrity verification and Windows
        Authenticode code-signing validation (requiring a valid Schneider Electric
        signature), and extracts the raw .bin payloads using 7-Zip so no third-party
        or archived executable is ever run directly.

    Design Choices:
        - Uses curl.exe for reliable HTTP redirect handling against archive.org.
        - Validates both cryptographic hash (SHA-1) and Authenticode signer subject
          before extraction; aborts immediately on any mismatch.
        - Extracts via 7-Zip (7z.exe) to avoid executing self-extracting PE binaries.

    Constraints / Trade-offs:
        - Windows-only for Authenticode verification (Get-AuthenticodeSignature).
        - Requires 7-Zip installed at standard Program Files paths or on PATH.
        - Legacy v5.1.6 (bootmon 1.0.2) is intentionally excluded from default downloads
          because it is an unsigned 2010 PE; enable -IncludeLegacy516 only if a v5.1.3
          card strictly refuses bootmon 1.0.8 directly.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDir = "C:\apc-fw",

    [Parameter()]
    [ValidateSet('GitHubFirst', 'ArchiveOrgFirst')]
    [string]$SourceOrder = 'GitHubFirst',

    [Parameter()]
    [switch]$IncludeLegacy516
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$githubReleaseBase = 'https://github.com/Ezra90/apc-nmc2-ap9630-upgrade-guide/releases/download/v1.0.0'

function Resolve-SevenZipPath {
    $candidates = @(
        (Get-Command '7z.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue),
        'C:\Program Files\7-Zip\7z.exe',
        'C:\Program Files (x86)\7-Zip\7z.exe'
    ) | Where-Object { $_ -and (Test-Path $_) }

    if (-not $candidates) {
        throw "7-Zip (7z.exe) not found. Install 7-Zip from https://www.7-zip.org/ before running this script."
    }
    return $candidates[0]
}

$sevenZip = Resolve-SevenZipPath
$downloadsDir = Join-Path $OutputDir 'downloads'
New-Item -ItemType Directory -Force -Path $downloadsDir | Out-Null

$packages = @(
    [PSCustomObject]@{
        Stage        = 'stage1_v6.6.4'
        FileName     = 'apc_hw05_aos664_sumx664_bootmon108.exe'
        GitHubUrl    = "$githubReleaseBase/apc_hw05_aos664_sumx664_bootmon108.exe"
        ArchiveUrl   = 'https://archive.org/download/ups-network-management-card-2-ap9630ap9631-firmware/apc_hw05_aos664_sumx664_bootmon108.exe'
        ExpectedSha1 = '0ab24997839accd88006ceb9a411dca60206dc4d'
        RequireSig   = $true
    },
    [PSCustomObject]@{
        Stage        = 'stage2_v6.9.6'
        FileName     = 'apc_hw05_aos696_sumx696_bootmon109.exe'
        GitHubUrl    = "$githubReleaseBase/apc_hw05_aos696_sumx696_bootmon109.exe"
        ArchiveUrl   = 'https://archive.org/download/apc_hw05_aos696_sumx696_bootmon109/apc_hw05_aos696_sumx696_bootmon109.exe'
        ExpectedSha1 = '651df26e0bced4defaea5e4a991a8b6a855630d2'
        RequireSig   = $true
    },
    [PSCustomObject]@{
        Stage        = 'stage3_v7.0.8'
        FileName     = 'apc_hw05_aos708_sumx708_bootmon109.exe'
        GitHubUrl    = "$githubReleaseBase/apc_hw05_aos708_sumx708_bootmon109.exe"
        ArchiveUrl   = 'https://archive.org/download/ups-network-management-card-2-ap9630ap9631-firmware/apc_hw05_aos708_sumx708_bootmon109.exe'
        ExpectedSha1 = 'd2fdd803daa320d2b064e8915ab1a264135d2851'
        RequireSig   = $true
    },
    [PSCustomObject]@{
        Stage        = 'stage4_v7.1.2'
        FileName     = 'apc_hw05_aos712_sumx712_bootmon109.exe'
        GitHubUrl    = "$githubReleaseBase/apc_hw05_aos712_sumx712_bootmon109.exe"
        ArchiveUrl   = 'https://archive.org/download/ups-network-management-card-2-ap9630ap9631-firmware/apc_hw05_aos712_sumx712_bootmon109.exe'
        ExpectedSha1 = 'f6a740dcb8bae14b8f2ab5405b98d2715ec205a1'
        RequireSig   = $true
    }
)

if ($IncludeLegacy516) {
    $packages += [PSCustomObject]@{
        Stage        = 'legacy_v5.1.6'
        FileName     = 'apc_hw05_aos516_sumx516_bootmon102.exe'
        GitHubUrl    = $null
        ArchiveUrl   = 'https://archive.org/download/ups-network-management-card-2-ap9630ap9631-firmware/apc_hw05_aos516_sumx516_bootmon102.exe'
        ExpectedSha1 = '720eba2d11dff1e14c3443be8227864554980214'
        RequireSig   = $false
    }
}

foreach ($pkg in $packages) {
    $exePath = Join-Path $downloadsDir $pkg.FileName
    $extractDir = Join-Path $OutputDir $pkg.Stage

    Write-Host "`n=== [$($pkg.Stage)] $($pkg.FileName) ===" -ForegroundColor Cyan
    if (-not (Test-Path $exePath)) {
        $urls = if ($SourceOrder -eq 'GitHubFirst') {
            @($pkg.GitHubUrl, $pkg.ArchiveUrl)
        } else {
            @($pkg.ArchiveUrl, $pkg.GitHubUrl)
        }
        $urls = $urls | Where-Object { $_ }

        $downloaded = $false
        foreach ($url in $urls) {
            Write-Host "  Fetching from: $url"
            & curl.exe -fsSL --retry 2 --retry-delay 2 -o $exePath $url
            if ($LASTEXITCODE -eq 0 -and (Test-Path $exePath)) {
                $downloaded = $true
                break
            }
            Write-Warning "  Download failed from $url; trying next mirror..."
            if (Test-Path $exePath) { Remove-Item $exePath -Force }
        }
        if (-not $downloaded) {
            throw "All download mirrors failed for $($pkg.FileName)"
        }
    } else {
        Write-Host "  Already downloaded; verifying existing file..."
    }

    $actualSha1 = (Get-FileHash -Path $exePath -Algorithm SHA1).Hash.ToLowerInvariant()
    if ($actualSha1 -ne $pkg.ExpectedSha1.ToLowerInvariant()) {
        throw "SHA-1 mismatch for $($pkg.FileName)! Expected $($pkg.ExpectedSha1), got $actualSha1"
    }
    Write-Host "  SHA-1 Verified : $actualSha1" -ForegroundColor Green

    $sig = Get-AuthenticodeSignature -FilePath $exePath
    $signerSubject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'UNSIGNED' }
    Write-Host "  Authenticode   : $($sig.Status) | $signerSubject"

    if ($pkg.RequireSig) {
        if ($sig.Status -ne 'Valid' -or $signerSubject -notmatch 'Schneider Electric') {
            throw "Authenticode verification failed for $($pkg.FileName): Status=$($sig.Status), Signer=$signerSubject"
        }
    }

    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    & $sevenZip x $exePath "-o$extractDir" -y | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "7-Zip extraction failed for $($pkg.FileName)"
    }

    $bins = Get-ChildItem -Path $extractDir -Recurse -Filter '*.bin' | Sort-Object Name
    foreach ($bin in $bins) {
        $sha256 = (Get-FileHash -Path $bin.FullName -Algorithm SHA256).Hash.ToLowerInvariant().Substring(0, 16)
        Write-Host ("  Extracted      : {0,-30} ({1,10} bytes, sha256:{2}...)" -f $bin.Name, $bin.Length, $sha256)
    }
}

Write-Host "`nAll packages verified and extracted to $OutputDir." -ForegroundColor Green
