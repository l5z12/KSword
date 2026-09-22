<#
.SYNOPSIS
    Send the built Qt main program, language packs, and hvm_ctl to the test machine.

.DESCRIPTION
    Deploy-KswordDriverToVm.ps1 handles only the driver and KswordCLI. The GUI side has historically
    been deployed manually via command-line, leading to repeated mistakes and uncertainty about
    whether the deployment actually occurred. This script exists solely to fix those steps.

    Three pitfalls, all encountered in practice:

    1) Copy-VMFile requires the Guest Service Interface. On this local target machine, it returns 0x80070015
       (Device not ready), so a PowerShell Direct fallback path is mandatory; do not rely solely on Copy-VMFile.

    2) Expand-Archive -Force aborts the entire operation if the gui\KswordARK.sys file in the guest is
       **currently being loaded by the kernel** during extraction. This causes all 80+ other files to fail to
       land, while the command only reports an error for that single file. Therefore, first extract to a staging
       directory, then copy files one by one. If a file cannot be copied but its hash already matches, skip it.

    3) If the ABI changes, the GUI and driver must be updated together. Inserting a field into the query-response structure causes the
       old GUI to misalign every field after the insertion point when reading the new driver, without raising an error on the interface;
       it only displays numbers that look familiar but are shifted by one position. Therefore, this script defaults to verifying that the
       driver on the guest is built from the same source as the local build; if they differ, GUI deployment is rejected.

.EXAMPLE
    .\Deploy-KswordGuiToVm.ps1

.EXAMPLE
    .\Deploy-KswordGuiToVm.ps1 -SkipDriverMatchCheck
#>
[CmdletBinding()]
param(
    [string] $VMName = 'KSword-HVM-Target',
    [string] $GuestUser = 'felix',
    [string] $GuestPassword = 'password',
    [string] $GuestGuiDir = 'C:\ksword\gui',
    [string] $GuestToolDir = 'C:\ksword',
    # Bytes per chunk. If too large, PowerShell Direct serialization slows down significantly or fails,
    # 4 MiB is the stable magnitude confirmed by local testing.
    [int]    $ChunkBytes = 4MB,
    # ABI validation is enabled by default (see item 3 above). Only disable it when explicitly pushing an incompatible combination.
    # Turn it off only then.
    [switch] $SkipDriverMatchCheck
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$releaseDir = Join-Path $repo 'artifacts/bin\x64\Release'

$credential = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

$vm = Get-VM -Name $VMName -ErrorAction Stop
if ($vm.State -ne 'Running') { throw "Virtual machine is not in Running state ($($vm.State)). Start-VM first." }

# Files to deploy: Ksword5.1.exe and both language packs must be deployed together; new entries are ineffective with an old exe,
# If a new exe is paired with old terms, it falls back to the default Chinese in the source code, and English interfaces will not show these changes.
$payload = @(
    [pscustomobject]@{ Local = Join-Path $releaseDir 'Ksword5.1.exe';            Remote = Join-Path $GuestGuiDir  'Ksword5.1.exe' }
    [pscustomobject]@{ Local = Join-Path $releaseDir 'languages\zh-CN.json';     Remote = Join-Path $GuestGuiDir  'languages\zh-CN.json' }
    [pscustomobject]@{ Local = Join-Path $releaseDir 'languages\en-US.json';     Remote = Join-Path $GuestGuiDir  'languages\en-US.json' }
    [pscustomobject]@{ Local = Join-Path $repo 'tools\hvm_ctl\hvm_ctl.exe';      Remote = Join-Path $GuestToolDir 'hvm_ctl.exe' }
)

$missing = $payload | Where-Object { -not (Test-Path $_.Local) }
if ($missing) { throw "Missing local files: $(($missing.Local) -join ', ')" }

# ---------------------------------------------------------------------------
# 0. ABI compatibility check
# ---------------------------------------------------------------------------
if (-not $SkipDriverMatchCheck) {
    Write-Host "`n--- 0. Are the driver and GUI from the same source ---" -ForegroundColor Cyan
    $localSys = Join-Path $releaseDir 'KswordARK.sys'
    if (-not (Test-Path $localSys)) { throw "Local $localSys is missing; build the driver first." }
    $localSysHash = (Get-FileHash $localSys -Algorithm SHA256).Hash
    $guestSysHash = Invoke-Command -VMName $VMName -Credential $credential -ScriptBlock {
        $path = 'C:\Windows\System32\drivers\KswordARK.sys'
        if (Test-Path $path) { (Get-FileHash $path -Algorithm SHA256).Hash } else { $null }
    }
    if ($null -eq $guestSysHash) {
        throw 'No driver installed on the guest. Run Deploy-KswordDriverToVm.ps1 first.'
    }
    if ($guestSysHash -ne $localSysHash) {
        Write-Host "  Local : $localSysHash" -ForegroundColor Yellow
        Write-Host "  guest: $guestSysHash" -ForegroundColor Yellow
        throw ('The driver installed on the guest is not the local version. Once the protocol structure changes, the old driver cannot configure the new GUI ' +
               '(or vice versa) will silently misread fields without reporting errors on the UI. First run ' +
               'Deploy-KswordDriverToVm.ps1, or explicitly skip with -SkipDriverMatchCheck.')
    }
    Write-Host '  [OK]   The driver installed on the guest is this locally built version' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 1. Package
# ---------------------------------------------------------------------------
Write-Host "`n--- 1. Packaging ---" -ForegroundColor Cyan
$stage = Join-Path ([IO.Path]::GetTempPath()) ('ksword-gui-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
    $index = 0
    foreach ($item in $payload) {
        # The archive uses flat sequential naming without paths. The target path is passed separately with the manifest.
        # This way, the guest side does not need to understand any directory structure, preventing path traversal during extraction.
        $index += 1
        Copy-Item $item.Local (Join-Path $stage ('{0:d2}.bin' -f $index)) -Force
    }
    $manifest = @()
    $index = 0
    foreach ($item in $payload) {
        $index += 1
        $manifest += [pscustomobject]@{
            Name   = ('{0:d2}.bin' -f $index)
            Remote = $item.Remote
            Sha256 = (Get-FileHash $item.Local -Algorithm SHA256).Hash
            Bytes  = (Get-Item $item.Local).Length
        }
    }
    $manifest | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $stage 'manifest.json') -Encoding UTF8

    $zip = Join-Path ([IO.Path]::GetTempPath()) ('ksword-gui-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.zip')
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal -Force
    $zipBytes = [IO.File]::ReadAllBytes($zip)
    Write-Host ('  {0}  files -> {1:N1} MiB  compressed archive' -f $payload.Count, ($zipBytes.Length / 1MB))

    # -----------------------------------------------------------------------
    # 2. Transfer to guest in chunks
    # -----------------------------------------------------------------------
    Write-Host "`n--- 2. Transfer (PowerShell Direct, Chunked) ---" -ForegroundColor Cyan
    $session = New-PSSession -VMName $VMName -Credential $credential
    try {
        $guestZip = Invoke-Command -Session $session -ScriptBlock {
            $path = Join-Path $env:TEMP ('ksword-gui-' + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.zip')
            if (Test-Path $path) { Remove-Item $path -Force }
            $path
        }
        $offset = 0
        $chunkIndex = 0
        $chunkCount = [Math]::Ceiling($zipBytes.Length / $ChunkBytes)
        while ($offset -lt $zipBytes.Length) {
            $size = [Math]::Min($ChunkBytes, $zipBytes.Length - $offset)
            $chunk = New-Object byte[] $size
            [Array]::Copy($zipBytes, $offset, $chunk, 0, $size)
            $b64 = [Convert]::ToBase64String($chunk)
            Invoke-Command -Session $session -ScriptBlock {
                param($data, $target)
                $bytes = [Convert]::FromBase64String($data)
                $fs = [IO.File]::Open($target, [IO.FileMode]::Append, [IO.FileAccess]::Write)
                try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Dispose() }
            } -ArgumentList $b64, $guestZip
            $offset += $size
            $chunkIndex += 1
            Write-Host ('  Block {0}/{1}  {2:N1} / {3:N1} MiB' -f $chunkIndex, $chunkCount, ($offset / 1MB), ($zipBytes.Length / 1MB))
        }

        # Verify the full package hash after transfer. The hardest failure to detect in chunked transfer is a missing block: decompression often
        # The operation might succeed, but the deployed file is corrupted.
        $localZipHash = (Get-FileHash $zip -Algorithm SHA256).Hash
        $guestZipHash = Invoke-Command -Session $session -ScriptBlock {
            param($path) (Get-FileHash $path -Algorithm SHA256).Hash
        } -ArgumentList $guestZip
        if ($localZipHash -ne $guestZipHash) {
            throw "Hash mismatch after archive transfer (local $localZipHash / guest $guestZipHash)."
        }
        Write-Host '  [OK]   Package hash matches' -ForegroundColor Green

        # -------------------------------------------------------------------
        # 3. Extract and deploy one by one in the guest
        # -------------------------------------------------------------------
        Write-Host "`n--- 3. Placement ---" -ForegroundColor Cyan
        $results = Invoke-Command -Session $session -ScriptBlock {
            param($zipPath)
            $out = @()
            $stageDir = Join-Path $env:TEMP ('ksword-gui-stage-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
            try {
                # Extract to staging directory; never use -Force to overwrite the target directory directly, as the target may contain files currently being loaded by the kernel, which would abort the entire extraction.
                # Files being loaded by the kernel would abort the entire extraction.
                Expand-Archive -Path $zipPath -DestinationPath $stageDir -Force
                $manifest = Get-Content (Join-Path $stageDir 'manifest.json') -Raw | ConvertFrom-Json
                foreach ($entry in $manifest) {
                    $source = Join-Path $stageDir $entry.Name
                    $parent = Split-Path $entry.Remote
                    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
                    $status = 'copied'
                    $note = ''
                    try {
                        Copy-Item $source $entry.Remote -Force -ErrorAction Stop
                    } catch {
                        # Copy failed. If the target already contains identical content, skipping the push makes no difference.
                        if ((Test-Path $entry.Remote) -and
                            (Get-FileHash $entry.Remote -Algorithm SHA256).Hash -eq $entry.Sha256) {
                            $status = 'locked-but-identical'
                            $note = 'File is in use, but content is already the target content'
                        } else {
                            $status = 'FAILED'
                            $note = $_.Exception.Message
                        }
                    }
                    $actual = if (Test-Path $entry.Remote) {
                        (Get-FileHash $entry.Remote -Algorithm SHA256).Hash
                    } else { $null }
                    $out += [pscustomobject]@{
                        Remote   = $entry.Remote
                        Status   = $status
                        Match    = ($actual -eq $entry.Sha256)
                        Expected = $entry.Sha256
                        Actual   = $actual
                        Note     = $note
                    }
                }
            } finally {
                Remove-Item $stageDir -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            }
            $out
        } -ArgumentList $guestZip

        $failed = @()
        foreach ($row in $results) {
            if ($row.Match) {
                Write-Host ('  [OK]   {0}  ({1})' -f $row.Remote, $row.Status) -ForegroundColor Green
            } else {
                Write-Host ('  [FAIL] {0}  {1} {2}' -f $row.Remote, $row.Status, $row.Note) -ForegroundColor Red
                Write-Host ('         Expecting {0}' -f $row.Expected) -ForegroundColor Red
                Write-Host ('         Actual {0}' -f $row.Actual) -ForegroundColor Red
                $failed += $row
            }
        }
        if ($failed.Count -gt 0) {
            throw "$($failed.Count) files failed to deploy."
        }
        Write-Host "`nAll components in place, hash verification passed one by one." -ForegroundColor Green
        Write-Host 'The GUI in the guest is C:\ksword\gui\Ksword5.1.exe, and the command-line tool is C:\ksword\hvm_ctl.exe.'
    } finally {
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }
} finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    if ($zip -and (Test-Path $zip)) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
}
