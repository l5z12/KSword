<#
.SYNOPSIS
    Change the test VM's vCPU count to the specified value and redeploy the
    driver to bisect whether a hang is caused by multi-processor rendezvous.

.DESCRIPTION
    Must run as **Administrator**.

    Why this experiment: START_RESIDENT hangs the guest on 4 vCPU, and the hang is so
    **severe that NMI cannot even reach the debugger (kd reports 'Retry sending the same data
    packet' / 'transport connection seems lost'), making post-mortem debugging impossible.

    With only 1 processor, **there is no rendezvous barrier to cause a deadlock**:
      * Resident success -> The issue is confirmed in the multi-processor merge logic, narrowing the search scope to a single function;
      * Still hangs -> the issue lies in the construction of 'current context becomes guest' or the VMRESUME exit
                     loop. Reducing the scope by half helps; single-core hangs are far easier to debug than four-core hangs.

    What the script does (re-read and verify at each step):
      1. Optional: Save the current (possibly hung) memory state as a checkpoint
         — this is the only remaining evidence; forced power-off will destroy it.
      2) Force power-off (a hung guest cannot shut down gracefully);
      3. Modify vCPU count;
      4. Start and wait for the guest to be ready;
      5. Call Deploy-KswordDriverToVm.ps1 to reload the driver (the driver service
         is set to start=demand, so it won't load automatically after reboot).

    The script does **not** run resident — that step is manually executed by you after confirming the debugger is ready.

.PARAMETER Count
    Target vCPU count. Default is 1. Use -Count 4 to restore the original.

.PARAMETER PreserveHungState
    Save the current memory state as a checkpoint before power-off. Enabled by default; skip with -PreserveHungState:$false if not needed.

.EXAMPLE
    .\Invoke-KswordVmCpuBisect.ps1 # Reduce to 1 core and redeploy
    .\Invoke-KswordVmCpuBisect.ps1 -Count 4 # Restore to 4 cores
#>
[CmdletBinding()]
param(
    [string] $VMName            = 'KSword-HVM-Target',
    [ValidateRange(1, 64)]
    [int]    $Count             = 1,
    [bool]   $PreserveHungState = $true,
    [string] $GuestUser         = 'felix',
    [string] $GuestPassword     = 'password'
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

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
$before = (Get-VMProcessor -VMName $VMName).Count
Write-Host ("VM {0}  status {1}  current {2} vCPU  ->  target {3} vCPU" -f
    $vm.Name, $vm.State, $before, $Count) -ForegroundColor Cyan

if ($before -eq $Count -and $vm.State -eq 'Running') {
    Write-Host "  Already at target core count and running; only redeploying driver." -ForegroundColor Yellow
} else {
    # ---- 1. Preserve current state --------------------------------------------------------
    if ($vm.State -ne 'Off' -and $PreserveHungState) {
        Write-Host "`n--- 1. Save current memory context ---" -ForegroundColor Cyan
        $snap = 'hung-' + (Get-Date -Format 'MMdd-HHmmss')
        try {
            Checkpoint-VM -Name $VMName -SnapshotName $snap
            Show-Check "Checkpoint '$snap'" $true 'Forced power-off will destroy the memory state; this is the only remaining evidence' | Out-Null
        } catch {
            # Frozen guests sometimes cannot even create checkpoints. This should not block the entire experiment.
            Write-Host ("  [Skip] Checkpoint failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }

    # ---- 2. Power off ------------------------------------------------------------
    if ($vm.State -ne 'Off') {
        Write-Host "`n--- 2. Force Power Off ---" -ForegroundColor Cyan
        Write-Host "  A hung guest cannot be gracefully shut down, only TurnOff." -ForegroundColor Yellow
        Stop-VM -Name $VMName -TurnOff -Force
        $deadline = (Get-Date).AddMinutes(3)
        while ((Get-Date) -lt $deadline -and (Get-VM -Name $VMName).State -ne 'Off') {
            Start-Sleep -Seconds 3
        }
        if (-not (Show-Check 'Powered Off' ((Get-VM -Name $VMName).State -eq 'Off'))) {
            throw 'The virtual machine failed to shut down.'
        }
    }

    # ---- 3. Change Core Count -------------------------------------------------------
    Write-Host "`n--- 3. Set vCPU count ---" -ForegroundColor Cyan
    Set-VMProcessor -VMName $VMName -Count $Count
    $now = (Get-VMProcessor -VMName $VMName).Count
    if (-not (Show-Check "vCPU = $Count" ($now -eq $Count) "Actual $now")) {
        throw 'vCPU count readback mismatch.'
    }
    # The nested virtualization switch is per-VM; changing the core count should not affect it — but still re-read once,
    # Because once disabled, all subsequent VMX operations will fail in an unintelligible manner.
    $nested = (Get-VMProcessor -VMName $VMName).ExposeVirtualizationExtensions
    if (-not (Show-Check 'Nested virtualization is still enabled' ([bool]$nested))) {
        throw 'Nested virtualization is disabled —— Set-VMProcessor -ExposeVirtualizationExtensions $true'
    }

    # ---- 4. Start ------------------------------------------------------------
    Write-Host "`n--- 4. Start and wait for ready ---" -ForegroundColor Cyan
    Start-VM -Name $VMName
    if (-not (Wait-GuestReady)) { throw 'guest did not respond to PowerShell Direct within 5 minutes.' }
    Show-Check 'guest is ready' $true | Out-Null
}

# ---- 5. Redeploy driver --------------------------------------------------------
Write-Host "`n--- 5. Reload driver ---" -ForegroundColor Cyan
Write-Host "  The driver service is start=demand, so it will not load automatically after a restart." -ForegroundColor DarkGray
& (Join-Path $PSScriptRoot 'Deploy-KswordDriverToVm.ps1') -VMName $VMName `
    -GuestUser $GuestUser -GuestPassword $GuestPassword | Out-Host

Write-Host "`n=== Next ===" -ForegroundColor Cyan
Write-Host @"

**Set breakpoints before running the resident hypervisor** — this hang prevents even NMIs from entering the debugger
(kd reports transport connection lost), so it is impossible to reconnect afterwards.
But the debugger is fully available before the hang, so setting breakpoints in advance lets you see exactly how far it gets.

1) Attach debugger:

     & "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe" -k com:pipe,port=\\.\pipe\KSword-HVM-Target-kd,resets=0,reconnect

2) After breaking in, first load our symbols (otherwise the stack will only show KswordARK+0x1234):

     .symfix+ C:\symbols
     .sympath+ C:\Users\Felix\CLionProjects\KSword\artifacts/bin\x64\Release\KswordARKDriver
     .reload /f KswordARK.sys
     x KswordARK!KswordARKHvmResident*

   The last command to verify if symbols are truly loaded — if symbols cannot be listed, do not proceed further,
   The breakpoints derived from the bisect will not be hit.

3) Set a breakpoint on the resident path. **Start from the outermost layer**, first confirm whether it entered:

     bp KswordARK!KswordARKHvmResidentStart
     bp KswordARK!KswordARKHvmResidentStartCurrent
     bp KswordARK!KswordARKHvmConfigureResidentVmcsFromAsm
     bl

4) g resume, run in another window:

     .\scripts\Invoke-KswordAutomatedAcceptance.ps1 -Stage resident

5) Each time a breakpoint is hit, record which one it is, then g to continue. **The last breakpoint hit is the upper bound of the hang** —
   After reaching it, if there is no further hit, it indicates that the wedge occurred between it and the next breakpoint.
   Gradually refine the breakpoints inward, bisecting down to the specific few lines.

Note: When a breakpoint is hit on IPI_LEVEL, the entire machine will freeze in the debugger, which is normal.

After completion, restore to 4 cores: .\scripts\Invoke-KswordVmCpuBisect.ps1 -Count 4
"@ -ForegroundColor Yellow
