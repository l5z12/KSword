<#
.SYNOPSIS
    On-site analysis when the test machine becomes unresponsive. Read-only; do not modify any state.

.DESCRIPTION
    Must run as **Administrator**. It can run in a separate window without interrupting the currently executing test script.

    Black screen + unresponsiveness has three completely different causes with opposite remediation steps, so determine the type before acting:

      Paused-Critical: Host disk full; Hyper-V actively paused the VM. **This is not a crash.**
                       After freeing space, Resume-VM restores it in place; do not rollback or power off.
      Running + no heartbeat: guest kernel hang or writing crash dump. Dump
                       **may take minutes; power loss during this period will corrupt the dump.
      Off / Saved: Already stopped.

    The script only reads status; any recovery actions are executed manually by you after confirmation.
#>
[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [int]    $ProbeSeconds  = 25
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$vm = Get-VM -Name $VMName -ErrorAction Stop
Write-Host "=== Virtual Machine ===" -ForegroundColor Cyan
Write-Host ("  Status      : {0}" -f $vm.State) -ForegroundColor $(
    if ("$($vm.State)" -match 'Critical') { 'Red' } elseif ($vm.State -eq 'Running') { 'Yellow' } else { 'White' })
Write-Host ("  Status    : {0}" -f $vm.Status)
Write-Host ("  Runtime   : {0}" -f $vm.Uptime)
Write-Host ("  Memory Allocation : {0} MB" -f [math]::Round($vm.MemoryAssigned / 1MB))
Write-Host ("  CPU Usage: {0}%" -f $vm.CPUUsage)

Write-Host "`n=== CPU Sampling (determining if idle or working) ===" -ForegroundColor Cyan
$samples = @()
for ($i = 0; $i -lt 5; $i++) {
    $samples += (Get-VM -Name $VMName).CPUUsage
    Start-Sleep -Milliseconds 800
}
Write-Host ("  Five samples: {0}" -f ($samples -join ', '))
if (($samples | Measure-Object -Maximum).Maximum -eq 0) {
    Write-Host "  All zeros — no instructions are executing" -ForegroundColor Red
} else {
    Write-Host "  Non-zero — code is indeed running (writing dumps, or a core is spinning)" -ForegroundColor Yellow
}

Write-Host "`n=== Integration Service ===" -ForegroundColor Cyan
# Do not filter by -Name: component names vary across versions and languages; hardcoding names will cause errors.
# 'No integration service found with the given name' indicates an error in the query method, not the VM's state.
try {
    Get-VMIntegrationService -VMName $VMName -ErrorAction Stop |
        Select-Object Name, Enabled, PrimaryStatusDescription |
        Format-Table -AutoSize
} catch { Write-Host "  Query failed: $($_.Exception.Message)" -ForegroundColor Yellow }

Write-Host "=== PowerShell Direct Liveness Probe (Decisive Criterion) ===" -ForegroundColor Cyan
# This is the only check that distinguishes between "the guest OS is alive but the console is black" and "the kernel has hung."
# It uses VMBus, so it does not depend on the network or the display.
$psDirect = 'UNKNOWN'
try {
    $cred = New-Object System.Management.Automation.PSCredential(
        $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))
    $job = Start-Job -ScriptBlock {
        param($n, $u, $p)
        $c = New-Object System.Management.Automation.PSCredential(
            $u, (ConvertTo-SecureString $p -AsPlainText -Force))
        Invoke-Command -VMName $n -Credential $c -ScriptBlock {
            "$env:COMPUTERNAME|$([Environment]::TickCount64)"
        }
    } -ArgumentList $VMName, $GuestUser, $GuestPassword
    if (Wait-Job $job -Timeout $ProbeSeconds) {
        $r = Receive-Job $job -ErrorAction SilentlyContinue
        if ($r) { $psDirect = 'ALIVE'; Write-Host ("  Response: {0}" -f $r) -ForegroundColor Green }
        else    { $psDirect = 'ERROR'; Write-Host "  Connected but no return value" -ForegroundColor Yellow }
    } else {
        $psDirect = 'TIMEOUT'
        Write-Host ("  No response within {0} seconds" -f $ProbeSeconds) -ForegroundColor Red
    }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
} catch {
    $psDirect = 'ERROR'
    Write-Host ("  Liveness probe failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

Write-Host "`n=== Host Disk ===" -ForegroundColor Cyan
$root = [IO.Path]::GetPathRoot($vm.Path)
Get-PSDrive -PSProvider FileSystem |
    Where-Object { $null -ne $_.Used } |
    Select-Object Name,
        @{ n = 'Used GB'; e = { [math]::Round($_.Used / 1GB, 1) } },
        @{ n = 'Remaining GB'; e = { [math]::Round($_.Free / 1GB, 2) } } |
    Format-Table -AutoSize
Write-Host ("  Virtual machine is resident at {0}" -f $root)

Write-Host "=== Checkpoint ===" -ForegroundColor Cyan
Get-VMSnapshot -VMName $VMName | Sort-Object CreationTime |
    Format-Table Name, CreationTime -AutoSize

# ---------------------------------------------------------------------------
Write-Host "=== Judgment ===" -ForegroundColor Cyan
if ("$($vm.State)" -match 'Critical' -or "$($vm.Status)" -match 'Critical|critical') {
    Write-Host @"
  [Host disk full, not a crash]
  Hyper-V actively suspends the virtual machine when the dynamic VHDX cannot continue to grow. Nothing happens inside the guest.

  Remediation (in order, do not rollback, do not power off):
    1. .\scripts\Clear-KswordVmCheckpoints.ps1 -KeepLast 0 -Confirm
    2. Resume-VM -Name '$VMName'
  After resumption, the guest continues from where it was paused, and the previous resident results remain valid.
"@ -ForegroundColor Yellow
}
elseif ($vm.State -eq 'Running' -and $psDirect -eq 'ALIVE') {
    Write-Host @"
  [guest OS is still alive]
  PowerShell Direct responds, indicating the kernel has not hung — the black screen is merely a symptom of the console/display.
  Common causes: After VMLAUNCH, the guest continues running in VMX non-root mode, but the graphics stack or
  The session was interrupted; it may also be that the VMConnect window itself needs to reconnect.

  Remediation:
    1. Read status directly, do not rollback:
       .\scripts\Invoke-KswordAutomatedAcceptance.ps1 -Stage status
       Each processor line tells you whether VMLAUNCH actually succeeded (check the GUEST_LAUNCHED bit).
    2. Close and reopen the VMConnect window to check if the black screen is just a display issue.
"@ -ForegroundColor Green
}
elseif ($vm.State -eq 'Running') {
    Write-Host @"
  [Still running but may be hung or writing a dump]
  Deployment script has enabled kernel dump (CrashDumpEnabled=2, AutoReboot=1). If a blue screen occurs,
  guest will first write the dump to C:\Windows\MEMORY.DMP and then automatically reboot —— 8 GiB memory
  Kernel dumps typically take a few minutes; black screen and no heartbeat are normal during this period.

  **Powering off during this period will corrupt the dump**, and that dump is the only evidence explaining what happened after VMLAUNCH.

  Remediation:
    1. Wait another 5-10 minutes, then rerun this script to check if Uptime has reset to zero (reset to zero = system has rebooted, dump has been written)
    2. Only consider rollback if it remains stuck and CPU usage is 0:
       Restore-VMCheckpoint -VMName '$VMName' -Name '<before-resident-*>' -Confirm:`$false
       Note: rolling back will discard dumps.
"@ -ForegroundColor Yellow
}
else {
    Write-Host ("  The virtual machine is in {0} and not running." -f $vm.State)
}
