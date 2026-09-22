<#
.SYNOPSIS
    Connect to the kernel debugger on the test machine, automatically load symbols, and set breakpoints for the resident path.

.DESCRIPTION
    Previous rounds wasted significant time manually typing kd commands, and breakpoints must be set **before the system hangs**.
    After a hang, neither NMI nor Ctrl+C can be entered (kd reports 'transport connection lost'), so the path of 'run the test
    first then figure out how to break in' does not exist. This script performs the entire preparation sequence in one go.

    What it does:
      1. Locate kd.exe;
      2. Verify that the named pipe mapping and driver symbol files actually exist.
      3. Start kd using -c "$$><scripts\kd-ksword-resident.txt" to automatically
         load symbols, self-check symbols, set breakpoints, and then 'g' to continue.

    kd will **take over the current console**, so run it in a dedicated window.

.PARAMETER ScriptFile
    The kd script to execute. Defaults to scripts\kd-ksword-resident.txt.

.PARAMETER NoAutoScript
    Connect only; do not execute any scripts. For manual exploration.

.EXAMPLE
    .\Start-KswordVmDebugger.ps1
    .\Start-KswordVmDebugger.ps1 -NoAutoScript
#>
[CmdletBinding()]
param(
    [string] $VMName     = 'KSword-HVM-Target',
    [string] $PipeName   = 'KSword-HVM-Target-kd',
    [string] $ScriptFile,
    [switch] $NoAutoScript
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

# --- kd.exe -----------------------------------------------------------------
$kd = @(
    "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    "C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $kd) { throw 'Cannot find kd.exe (WDK or Debugging Tools for Windows is required).' }
Write-Host ("kd     : {0}" -f $kd) -ForegroundColor DarkGray

# --- Precondition check: Fail now rather than connect and miss breakpoints.
$pdb = Join-Path $repo 'artifacts/bin\x64\Release\KswordARKDriver\KswordARK.pdb'
$sys = Join-Path $repo 'artifacts/bin\x64\Release\KswordARK.sys'
if (-not (Test-Path $pdb)) { throw "Missing driver symbols: $pdb" }
if (-not (Test-Path $sys)) { throw "Missing driver artifacts: $sys" }
$pdbTime = (Get-Item $pdb).LastWriteTime
$sysTime = (Get-Item $sys).LastWriteTime
Write-Host ("Symbol   : {0} ({1})" -f $pdb, $pdbTime) -ForegroundColor DarkGray
if ([math]::Abs(($pdbTime - $sysTime).TotalMinutes) -gt 5) {
    # When symbols and binaries are out of sync, breakpoints land at incorrect addresses — such failures appear as
    # "Breakpoint not hit" is easily misread as "code path not executed".
    Write-Host ("  [Warning] .pdb and .sys timestamps differ by {0:N1} minutes; they may not be from the same build." -f
        ($pdbTime - $sysTime).TotalMinutes) -ForegroundColor Yellow
    Write-Host "         When symbols do not match, breakpoints will be set at incorrect addresses, manifesting as 'misses'; do not misinterpret this as 'code was not reached'." -ForegroundColor Yellow
}

# Named pipe mapping
try {
    $com = Get-VMComPort -VMName $VMName -Number 1 -ErrorAction Stop
    $want = "\\.\pipe\$PipeName"
    if ($com.Path -ne $want) {
        throw "COM1 is currently mapped to '$($com.Path)', not '$want'. Run Enable-KswordVmKernelDebug.ps1 first."
    }
    Write-Host ("Pipeline : {0}" -f $com.Path) -ForegroundColor DarkGray
} catch [Microsoft.HyperV.PowerShell.VirtualizationException] {
    throw "Failed to query COM1 (requires administrator): $($_.Exception.Message)"
}

# --- Assemble command line -------------------------------------------------------------
$conn = "com:pipe,port=\\.\pipe\$PipeName,resets=0,reconnect"
# Parameters are resets=0,reconnect — **not** resync. The latter only works for real serial ports.
# Invalid parameters on the named pipe (Win32 error 0x87). This has been encountered in practice.

# -b: Request break-in upon connection.
# Without it, a kd connection established during the **boot phase** will follow the target indefinitely without ever obtaining the kd> prompt,
# However, the -c script only executes at the first prompt — resulting in 'connected but no breakpoints set'.
# The script produces no output. In practice, the previous prompt appeared only because it was an active break-in connection.
$kdArgs = @('-b', '-k', $conn)
if (-not $NoAutoScript) {
    if (-not $ScriptFile) { $ScriptFile = Join-Path $PSScriptRoot 'kd-ksword-resident.txt' }
    if (-not (Test-Path $ScriptFile)) { throw "Cannot find kd script: $ScriptFile" }
    # Must use $$< (line-by-line execution); **do not** use $$><.
    # $$>< replaces all newlines in the file with semicolons to form a single command, while .sympath+ follows
    # The semicolon acts as a path separator, causing it to consume all subsequent commands as paths and corrupting the symbol path.
    # A bunch of "Error: ... attempts to access 'bu KswordARK!...' failed".
    # Note: Cannot set a single breakpoint. Verified by experience.
    $kdArgs += @('-c', "`$`$<$ScriptFile")
    Write-Host ("Script : {0}" -f $ScriptFile) -ForegroundColor DarkGray
}

Write-Host @"

--- Start kd first, then launch the virtual machine ---

Hyper-V's named pipe serial port only handshakes at the moment the virtual machine **initializes the COM port**. The guest is already running
Connect later; kd will remain stuck at "no_debuggee / Waiting to reconnect" and cannot connect.
After the previous kd disconnect, the virtual machine also needs to be restarted to reconnect.

So: keep this window open, then execute in another administrator window

    Restart-VM -Name '$VMName' -Force

kd will automatically attach during the boot process. (When the guest is healthy, -Force only skips confirmation, it does not force a power-off.)

--- The order after connecting (must not be reversed) ---

The script uses **delayed breakpoints** bu: the driver service is start= demand, so it is not yet loaded when connecting the debugger,
Normal bp will fail to set due to unresolved symbols. bu will suspend and wait for the module to load before resolving.
So bl showing "u" (unresolved) at this time is **normal**, not an error.

After resuming execution, switch to another window and follow this order:

  1) .\scripts\Deploy-KswordDriverToVm.ps1
     When the driver is loaded, kd will break once due to sxe ld:KswordARK.sys. After breaking, type:
         .reload /f KswordARK.sys
         bl                      <- breakpoint should become resolved (no longer u)
         g

  2) .\scripts\Invoke-KswordAutomatedAcceptance.ps1 -Stage resident

Check up to which step [1][2][3][4] has reached, and whether GuestResume / VmExitEntry has been hit.
Paste all output from the kd window back.

"@ -ForegroundColor Cyan

& $kd @kdArgs
