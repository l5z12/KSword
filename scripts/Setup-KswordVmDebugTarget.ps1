<#
.SYNOPSIS
    Configure a VMware VM as a KSword license test machine: enable test signing + network kernel debugging (KDNET).

.DESCRIPTION
    Modify only this VM's boot configuration (BCD); do not touch the host, install anything, or load drivers.
    Ensure before execution:
      1. This VM has already been snapshotted;
      2. Secure Boot is disabled in the virtual machine firmware: if enabled, testsigning would be
         silently ignored, creating the false impression of "command success" while the driver fails to load.

    Changes require a reboot to take effect. After reboot, a "Test Mode" watermark will appear in the bottom-right corner of the desktop.

.PARAMETER HostIp
    Address of the host machine on the VMware virtual network segment. NAT (VMnet8) defaults to 192.168.80.1.

.PARAMETER Port
    KDNET port. The host firewall must allow inbound UDP traffic on this port.

.PARAMETER Key
    KDNET key, four segments separated by dots. Both sides must match exactly.

.PARAMETER Revert
    Revert: disable debugging and test signing to restore normal boot.

.EXAMPLE
    # In the virtual machine, run as Administrator:
    powershell -ExecutionPolicy Bypass -File .\Setup-KswordVmDebugTarget.ps1

.EXAMPLE
    # Revoke
    powershell -ExecutionPolicy Bypass -File .\Setup-KswordVmDebugTarget.ps1 -Revert
#>
[CmdletBinding()]
param(
    [string] $HostIp = '192.168.80.1',
    [int]    $Port   = 50000,
    [string] $Key    = 'ksw.ark.dbg.1',
    [switch] $Revert
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Must run as administrator.'
    }
}

function Get-SecureBootState {
    # On non-UEFI machines, Confirm-SecureBootUEFI throws an exception; this case is equivalent to 'not enabled'.
    try { return [bool](Confirm-SecureBootUEFI) } catch { return $false }
}

Assert-Admin

Write-Host "=== KSword Test Target Configuration ===" -ForegroundColor Cyan
Write-Host "Computer Name : $env:COMPUTERNAME"
Write-Host "System     : $((Get-CimInstance Win32_OperatingSystem).Caption) build $((Get-CimInstance Win32_OperatingSystem).BuildNumber)"

if ($Revert) {
    Write-Host "`n--- Revoke Mode ---" -ForegroundColor Yellow
    bcdedit /debug off
    bcdedit /set testsigning off
    Write-Host "`nDebugging and test signing have been disabled. Changes take effect after a restart." -ForegroundColor Yellow
    bcdedit /enum "{current}" | Select-String 'testsigning|debug'
    return
}

# ---------------------------------------------------------------------------
# 1) Secure Boot must be disabled.
# ---------------------------------------------------------------------------
$secureBoot = Get-SecureBootState
Write-Host "`nSecure Boot : $secureBoot" -NoNewline
if ($secureBoot) {
    Write-Host "  <-- Must turn off first" -ForegroundColor Red
    throw 'Secure Boot is on: bcdedit /set testsigning on will be silently ignored. Please disable Secure Boot in the VM firmware first (VMware: VM Settings → Options → Advanced → uncheck "Enable Secure Boot"), then rerun this script.'
}
Write-Host "  OK" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2) Backup current startup items (the second line of defense beyond snapshots).
#    The Desktop may not exist when running as SYSTEM (via scheduled task with elevated privileges); fall back to Windows\Temp.
# ---------------------------------------------------------------------------
$desktop = [Environment]::GetFolderPath('Desktop')
$backupDir = if ($desktop -and (Test-Path $desktop)) { $desktop } else { Join-Path $env:SystemRoot 'Temp' }
$backup = Join-Path $backupDir 'bcd-before-ksword.txt'
bcdedit /enum "{current}" | Out-File -FilePath $backup -Encoding utf8
bcdedit /dbgsettings   | Out-File -FilePath $backup -Encoding utf8 -Append
Write-Host "Backed up current boot entries to $backup"

# ---------------------------------------------------------------------------
# 3) Network kernel debugging (KDNET)
#    e1000e = Intel 82574L, which is in the list of NICs supported by KDNET.
# ---------------------------------------------------------------------------
Write-Host "`n--- Configuring KDNET ---" -ForegroundColor Cyan
Write-Host "hostip=$HostIp port=$Port key=$Key"
& bcdedit /dbgsettings net "hostip:$HostIp" "port:$Port" "key:$Key"
if ($LASTEXITCODE -ne 0) { throw "bcdedit /dbgsettings failed, exit code $LASTEXITCODE" }

& bcdedit /debug on
if ($LASTEXITCODE -ne 0) { throw "bcdedit /debug on failed, exit code $LASTEXITCODE" }

# ---------------------------------------------------------------------------
# 4) Test signing — allows drivers signed by CN=KswordARK Test Signing Certificate to load
# ---------------------------------------------------------------------------
Write-Host "`n--- Enabling test signing ---" -ForegroundColor Cyan
& bcdedit /set testsigning on
if ($LASTEXITCODE -ne 0) { throw "bcdedit /set testsigning on failed, exit code $LASTEXITCODE" }

# ---------------------------------------------------------------------------
# 5) Read-back confirmation — do not rely solely on the message "The operation completed successfully."
# ---------------------------------------------------------------------------
Write-Host "`n--- Readback Confirmation ---" -ForegroundColor Cyan
$dbg = (bcdedit /dbgsettings | Out-String)
$cur = (bcdedit /enum "{current}" | Out-String)

Write-Host $dbg.Trim()

$checks = @(
    @{ Name = 'debugtype=NET'; Ok = $dbg -match '(?im)^\s*debugtype\s+NET' }
    @{ Name = "hostip=$HostIp"; Ok = $dbg -match [regex]::Escape($HostIp) }
    @{ Name = "port=$Port";     Ok = $dbg -match "(?im)^\s*port\s+$Port" }
    @{ Name = 'key is set';      Ok = $dbg -match [regex]::Escape($Key) }
    @{ Name = 'debug=Yes';      Ok = $cur -match '(?im)^\s*debug\s+Yes' }
    @{ Name = 'testsigning=Yes';Ok = $cur -match '(?im)^\s*testsigning\s+Yes' }
)

Write-Host ""
$bad = 0
foreach ($c in $checks) {
    if ($c.Ok) { Write-Host ("  [OK]   " + $c.Name) -ForegroundColor Green }
    else       { Write-Host ("  [FAIL] " + $c.Name) -ForegroundColor Red; $bad++ }
}

if ($bad -gt 0) {
    throw "$bad item readback validation failed -- do not treat as configuration success."
}

Write-Host "`n All ready. Now restarting the virtual machine: " -ForegroundColor Yellow
Write-Host "    shutdown /r /t 0"
Write-Host "`nAfter reboot, you should see the 'Test Mode' watermark in the bottom-right corner of the desktop. Connection command on the host side: " -ForegroundColor Yellow
Write-Host "    windbg.exe -k net:port=$Port,key=$Key"
