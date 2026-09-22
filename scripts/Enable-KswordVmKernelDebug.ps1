<#
.SYNOPSIS
    Attach a serial (named pipe) kernel debugger to the KSword test VM to locate hangs without dumps.

.DESCRIPTION
    Must run as **Administrator**.

    Why it is needed: In nested virtualization, START_RESIDENT causes the guest to hang with
    **multiple cores spinning at high IRQL and all interrupts disabled**. This failure:
      * No BSOD — no code can reach KeBugCheckEx;
      * No dump written — same as above.
      * Even the clock watchdog (CLOCK_WATCHDOG_TIMEOUT 0x101) fails to run.
      * Note: Post-event status read cannot detect it—the system had no exit point at the moment of hang.
    The only way to see where each of the four cores is halted is via the kernel debugger.

    Why use serial port named pipes instead of KDNET:
    Named pipes use Hyper-V's own serial port emulation, **bypassing the host's network driver stack**. Previously used
    KDNET-over-VMware-NAT has crashed the host machine twice; that path traverses the host kernel's vmnet driver.
    This entry has no such risk.

    **Break-in requires an NMI. Serial break-in depends on the target responding to serial interrupts, but when hung, interrupts
    are disabled, so pressing Ctrl+Break has no effect. Hyper-V's `Debug-VM -InjectNonMaskableInterrupt` injects a non-maskable
    interrupt that reaches the target even when all interrupts are disabled. This command is printed at the end of the script.

    Changes to the guest (all contained within this one-time isolated test VM; the host remains unaffected):
      1. Add a virtual serial port COM1, mapped to a named pipe on the host.
      2. bcdedit /dbgsettings serial debugport:1 baudrate:115200
      3. bcdedit /set {current} debug on
      4. Restart to apply changes. Before modification, export a BCD backup
    and create a checkpoint; after each change, re-read and validate.

    **Does not automatically attach a debugger—that is an interactive operation; commands must be executed manually by you.

.PARAMETER Disable
    Reverse operation: disable guest debugging and remove serial port mapping.

.EXAMPLE
    .\Enable-KswordVmKernelDebug.ps1
    .\Enable-KswordVmKernelDebug.ps1 -Disable
#>
[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [string] $PipeName      = 'KSword-HVM-Target-kd',
    [switch] $Disable
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$pipePath = "\\.\pipe\$PipeName"
$cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

function Show-Check {
    param([string] $Name, [bool] $Ok, [string] $Detail = '')
    if ($Ok) { Write-Host ("  [OK]   {0}{1}" -f $Name, $(if ($Detail) { "  $Detail" })) -ForegroundColor Green }
    else     { Write-Host ("  [FAIL] {0}{1}" -f $Name, $(if ($Detail) { "  $Detail" })) -ForegroundColor Red }
    return [bool]$Ok
}

function Wait-GuestReady {
    param([int] $TimeoutSeconds = 300)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Invoke-Command -VMName $VMName -Credential $cred `
                        -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            return $true
        } catch { Start-Sleep -Seconds 5 }
    }
    return $false
}

$vm = Get-VM -Name $VMName -ErrorAction Stop
Write-Host ("Virtual machine {0}  status {1}" -f $vm.Name, $vm.State) -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Create a fallback before modifying the boot configuration.
# ---------------------------------------------------------------------------
if (-not $Disable) {
    Write-Host "`n--- 1. Fallback before modifying boot configuration ---" -ForegroundColor Cyan
    if ($vm.State -eq 'Running') {
        $stamp = 'before-kdebug-' + (Get-Date -Format 'MMdd-HHmmss')
        Checkpoint-VM -Name $VMName -SnapshotName $stamp
        Show-Check "Checkpoint '$stamp'" $true | Out-Null
    } else {
        Write-Host "  Virtual machine is not running, skipping checkpoint" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# 2. Serial port mapping (requires VM shutdown)
# ---------------------------------------------------------------------------
Write-Host "`n--- 2. Virtual Serial Port COM1 ---" -ForegroundColor Cyan
$vm = Get-VM -Name $VMName
if ($vm.State -ne 'Off') {
    Write-Host "  Set-VMComPort requires the virtual machine to be in a powered-off state, performing graceful shutdown..." -ForegroundColor Yellow
    Stop-VM -Name $VMName -Force:$false -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Date) -lt $deadline -and (Get-VM -Name $VMName).State -ne 'Off') {
        Start-Sleep -Seconds 5
    }
    if ((Get-VM -Name $VMName).State -ne 'Off') {
        # A hung guest cannot be shut down. Do not automatically force power off here; confirm and decide manually.
        throw @"
The virtual machine did not shut down within 5 minutes (it may still be hung).
Forced power-off will lose the current memory context, so it is not executed automatically. After confirming that it is safe to discard, run manually:
  Stop-VM -Name '$VMName' -TurnOff -Force
Then re-run this script.
"@
    }
}

if ($Disable) {
    Set-VMComPort -VMName $VMName -Number 1 -Path $null
    Show-Check 'COM1 mapping removed' ((Get-VMComPort -VMName $VMName -Number 1).Path -in @($null, '')) | Out-Null
} else {
    Set-VMComPort -VMName $VMName -Number 1 -Path $pipePath
    $now = (Get-VMComPort -VMName $VMName -Number 1).Path
    Show-Check 'COM1 -> Named Pipe' ($now -eq $pipePath) $now | Out-Null
}

Write-Host "`n--- 3. Start and wait for guest to be ready ---" -ForegroundColor Cyan
Start-VM -Name $VMName -ErrorAction SilentlyContinue | Out-Null
if (-not (Wait-GuestReady)) { throw 'guest did not respond to PowerShell Direct within 5 minutes.' }
Show-Check 'guest is ready' $true | Out-Null

# ---------------------------------------------------------------------------
# 4. Boot configuration within the guest
# ---------------------------------------------------------------------------
Write-Host "`n--- 4. guest boot configuration ---" -ForegroundColor Cyan
$result = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    param($off)
    $out = [ordered]@{}

    # First, export a BCD backup. Modifying boot configuration has no 'undo' button; the backup is the only fallback.
    $backup = "C:\ksword\bcd-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').bcd"
    New-Item -ItemType Directory -Force -Path 'C:\ksword' | Out-Null
    $out.Backup = (& bcdedit.exe /export $backup 2>&1 | Out-String).Trim()
    $out.BackupPath = $backup

    if ($off) {
        $out.Debug = (& bcdedit.exe /set '{current}' debug off 2>&1 | Out-String).Trim()
    } else {
        # debugport:1 corresponds to the previously mapped COM1; baud rate has no practical meaning for named pipes.
        # Both ends must match; hardcoding 115200 avoids mismatches.
        $out.DbgSettings = (& bcdedit.exe /dbgsettings serial debugport:1 baudrate:115200 2>&1 | Out-String).Trim()
        $out.Debug = (& bcdedit.exe /set '{current}' debug on 2>&1 | Out-String).Trim()
    }

    # Readback verification: a successful command return does not guarantee the configuration was actually written.
    $out.CurrentEnum = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
    $out.DbgEnum     = (& bcdedit.exe /enum '{dbgsettings}' 2>&1 | Out-String)
    $out.DebugOn     = [bool]($out.CurrentEnum -match '(?im)^\s*debug\s+Yes')
    $out.SerialSet   = [bool]($out.DbgEnum -match '(?im)^\s*debugtype\s+Serial')
    $out.PortSet     = [bool]($out.DbgEnum -match '(?im)^\s*debugport\s+1')
    $out
} -ArgumentList ([bool]$Disable)

Write-Host ("  BCD backup: {0}" -f $result.BackupPath)
if ($Disable) {
    Show-Check 'debug is disabled' (-not $result.DebugOn) | Out-Null
} else {
    $ok = $true
    $ok = (Show-Check 'debug = Yes'        $result.DebugOn)   -and $ok
    $ok = (Show-Check 'debugtype = Serial' $result.SerialSet) -and $ok
    $ok = (Show-Check 'debugport = 1'      $result.PortSet)   -and $ok
    if (-not $ok) {
        Write-Host "`n{dbgsettings} Original text:`n$($result.DbgEnum)" -ForegroundColor Yellow
        throw 'Boot configuration readback failed — do not treat as configuration success.'
    }
}

# ---------------------------------------------------------------------------
# 5. Restart to apply configuration
# ---------------------------------------------------------------------------
Write-Host "`n--- 5. Restart guest ---" -ForegroundColor Cyan
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    Start-Process -FilePath 'shutdown.exe' -ArgumentList @('/r', '/t', '0') -NoNewWindow
} -ErrorAction SilentlyContinue
Start-Sleep -Seconds 15
if (-not (Wait-GuestReady)) { throw 'Guest did not respond within 5 minutes after reboot.' }
Show-Check 'guest has restarted and is ready' $true | Out-Null

if ($Disable) {
    Write-Host "`nDebugging is disabled, serial port mapping has been removed." -ForegroundColor Green
    return
}

# ---------------------------------------------------------------------------
Write-Host "`n=== How to use ===" -ForegroundColor Cyan
$kd = @(
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    "C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $kd) { $kd = 'kd.exe (not found, WDK/Debugging Tools required)' }

Write-Host @"

1) Connect the debugger (**connect before running the test**, otherwise you won't be able to connect after a hang):

     & "$kd" -k com:pipe,port=$pipePath,resets=0,reconnect

   The parameter is `resets=0,reconnect`, **not** `resync` — the latter only works for real serial ports,
   It will be judged as an invalid parameter on the named pipe ("COM parameters: resync is not a valid parameter",
   Win32 error 0n87). Tested and encountered.

   After connecting, first `g` to let the guest continue running; do not stop at the initial breakpoint.

2) Open another window to run the resident hypervisor test target with readback and resume execution as appropriate:

     .\scripts\Invoke-KswordAutomatedAcceptance.ps1 -Stage resident

3) **After a hang, inject via NMI** — this is the critical step:

     Debug-VM -Name '$VMName' -InjectNonMaskableInterrupt

   Why Ctrl+Break cannot be used: serial break-in requires the target to respond to serial interrupts, but when frozen
   Interrupts on all four cores are disabled; pressing keys yields no response. NMI is **unmaskable** and can be delivered.

4) After breaking in, first check these three items:

     !running -it        What each core is currently running (-it includes stack)
     ~*k                 Call stacks for all processors
     !irql               IRQL on each core — expect to see spin on IPI_LEVEL

   What we are looking for is: which core has not reached the rendezvous point, and which wait loop the other cores are stuck in.

Fallback method when debugger is not connected: also inject NMI; guest will trigger NMI_HARDWARE_FAILURE (0x80)
Blue screen and write C:\Windows\MEMORY.DMP. The information is less than real-time debugging, but it's better than nothing.

Disable debugging: .\scripts\Enable-KswordVmKernelDebug.ps1 -Disable
"@ -ForegroundColor Yellow
