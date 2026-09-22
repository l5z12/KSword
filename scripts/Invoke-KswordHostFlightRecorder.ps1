<#
.SYNOPSIS
    Record Hyper-V nested virtualization counters on the **host**; after three calibration
    segments, run START_RESIDENT to answer whether VM entry actually sends the CPU to L2.

.DESCRIPTION
    Must run as **Administrator** (required for PowerShell Direct).

    Why recording must happen on the host side: once the guest hangs, nothing can be read. The driver side has zero DbgPrint, zero registry
    writes, and per-CPU lines and event rings reside in non-paged pool, which vanish immediately upon hard reset; furthermore, a hang prevents
    even NMI and Ctrl+C from entering the debugger. Therefore, **evidence must be sent outside the guest at the exact moment the hang occurs**.
    Hyper-V's per-virtual-processor counters reside on the host; the guest cannot affect them even if it crashes.

    Three calibration segments; the order cannot be omitted:

      1. Baseline: Idle the virtual machine and record the resting values of all counters.
      2. Calibration: Send 1 LAUNCH_TEST_GUEST. It is known to produce exactly 1 nested
                   entry and 1 VM exit. If the counter does not jump, its meaning differs from our
                   assumption, all subsequent readings are untrustworthy, and the experiment is invalid.
      3. Observation: Send START_RESIDENT and continue sampling until the VM disconnects or times out.

    Segment 2 is the foundation of the entire experiment. Skipping it is equivalent to drawing conclusions
    based on an unverified criterion. This investigation line has failed three times due to "uncalibrated
    criteria": the GUEST_LAUNCHED bit was contaminated by the previous experiment, lastVmInstructionError
    has three sources of 0, and RESIDENT_STARTING is cleared at all three exit points.

.PARAMETER SkipResident
    Performs only baseline and calibration; does not send START_RESIDENT. Used to verify counter semantics independently.

.EXAMPLE
    .\Invoke-KswordHostFlightRecorder.ps1
    .\Invoke-KswordHostFlightRecorder.ps1 -SkipResident
#>
[CmdletBinding()]
param(
    [string] $VMName          = 'KSword-HVM-Target',
    [string] $GuestUser       = 'felix',
    [string] $GuestPassword   = 'password',
    [int]    $BaselineSeconds = 20,
    [int]    $ObserveSeconds  = 90,
    [double] $SampleInterval  = 1,
    [string] $OutDir,
    [switch] $SkipResident
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$repo = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $repo 'docs\next\logs' }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csv   = Join-Path $OutDir "flight-$stamp.csv"
$json  = Join-Path $OutDir "flight-$stamp.json"

$cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

# --- Counters: use only what actually exists on this machine; silently skip missing ones --------------------------------
# Hard-coding a list and assuming its existence is another form of 'uncalibrated criterion'. Here we retrieve it from -ListSet instead.
$wanted = @(
    # --- Totals and ownership ---
    'Nested VM Entries/sec',
    'Total Intercepts/sec',
    '% Guest Run Time',
    '% Hypervisor Run Time',
    # --- Three categories excluded by actual measurement (keep for comparison, do not delete) ---
    # Measured: Among 100,000 interceptions per second in the observation segment, these three types combined account for fewer than 6.
    'MSR Accesses/sec',
    'Hypercalls/sec',
    'Nested Page Fault Intercepts/sec',
    # --- Intercepting and emulating each VMX instruction individually ---
    # When Hyper-V acts as L0, it traps and emulates every VMX instruction executed by L1 (without performing VMCS shadowing)
    # This is especially true for VMREAD/VMWRITE during shadowing). The previous round failed to reach a conclusion because
    # Only sampled three categories: MSR, hypercall, and page faults, while the actual storm lies outside these.
    'Total Virtualization Instructions Emulated/sec',
    'VMREAD Emulation Intercepts/sec',
    'VMWRITE Emulation Intercepts/sec',
    'VMPTRLD Emulation Intercepts/sec',
    'VMCLEAR Emulation Intercepts/sec',
    'VMXON Emulation Intercepts/sec',
    'VMXOFF Emulation Intercepts/sec',
    'InvEpt Single Context Emulation Intercepts/sec',
    'InvEpt All Context Emulation Intercepts/sec',
    # --- Fallback: categorize remaining intercepts.
    'Emulated Instructions/sec',
    'Page Fault Intercepts/sec',
    'Memory Intercept Messages/sec',
    'IO Intercept Messages/sec',
    'Other Intercepts/sec'
)
$instance = "$VMName" + ':Hv VP 0'
$set = Get-Counter -ListSet 'Hyper-V Hypervisor Virtual Processor' -ErrorAction Stop
$paths = @()
foreach ($w in $wanted) {
    $p = $set.PathsWithInstances | Where-Object { $_ -like "*($instance)\$w" } | Select-Object -First 1
    if ($p) { $paths += $p } else { Write-Host ("  [Skip] The local machine does not have counter '$w'") -ForegroundColor Yellow }
}
if ($paths.Count -eq 0) { throw "No counters found for '$instance'. Is the virtual machine running? Changing the number of vCPUs will change the instance name." }

Write-Host ("=== Host Flight Recorder ===") -ForegroundColor Cyan
Write-Host ("Instance : {0}" -f $instance)
Write-Host ("Counter: {0} items" -f $paths.Count)
Write-Host ("Output : {0}" -f $csv) -ForegroundColor DarkGray

$samples = New-Object System.Collections.ArrayList
$marks   = New-Object System.Collections.ArrayList

function Add-Sample {
    param([string] $Phase)
    try {
        $s = Get-Counter -Counter $paths -ErrorAction Stop
        $row = [ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); phase = $Phase }
        foreach ($v in $s.CounterSamples) {
            # Spaces and percent signs in counter names are problematic in CSVs; take the last segment and normalize.
            $name = ($v.Path -split '\\')[-1] -replace '[^A-Za-z0-9]', '_'
            $row[$name] = [math]::Round($v.CookedValue, 2)
        }
        [void]$samples.Add([pscustomobject]$row)
        return $row
    } catch {
        [void]$samples.Add([pscustomobject]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); phase = $Phase; error = "$($_.Exception.Message)" })
        return $null
    }
}

function Invoke-HvmCtl {
    param([string] $Command)
    try {
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
            param($c)
            $o = 'C:\ksword\fr_out.txt'
            Remove-Item $o -ErrorAction SilentlyContinue
            $p = Start-Process -FilePath 'C:\ksword\hvm_ctl.exe' -ArgumentList @('--json', $c) `
                     -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o `
                     -RedirectStandardError 'C:\ksword\fr_err.txt'
            $t = ''
            if (Test-Path $o) { $t = [IO.File]::ReadAllText($o) }
            [ordered]@{ Exit = $p.ExitCode; Out = $t }
        } -ArgumentList $Command
    } catch { return $null }
}

function Get-Field { param($Row, [string] $Like)
    if (-not $Row) { return $null }
    $k = $Row.Keys | Where-Object { $_ -like $Like } | Select-Object -First 1
    if ($k) { return $Row[$k] } else { return $null }
}

function Get-HvmJson {
    param([string] $Command)
    $r = Invoke-HvmCtl $Command
    if (-not $r -or -not $r.Out) { return $null }
    try { return ($r.Out | ConvertFrom-Json) } catch { return $null }
}

# ---------------------------------------------------------------------------
# Self-healing of preconditions.
#
# The consequence of skipping this step was tested once: the driver carried over FAULTED state from the previous round and was never prepared,
# Thus, launch-test-guest and START_RESIDENT are both rejected at the pre-check gate (UNSUPPORTED_CPU /
# STATUS_NOT_SUPPORTED, so the counter naturally doesn't increment and the machine doesn't hang — the entire experiment appears to have "completed".
# However, it detects nothing and can easily be misinterpreted as 'hung and not reproducible'.
#
# Uses the same chain as Invoke-KswordHvmControl.ps1:
#   FAULTED/ROLLBACK_REQUIRED -> reset-fault
#   No RESOURCES_READY -> prepare (skip if present; re-running prepare will result in a FAULTED state).
#   If SELF_TEST_PASSED is missing -> self-test failure.
# ---------------------------------------------------------------------------
function Initialize-HvmPrereq {
    Write-Host "`n--- 0. Prerequisite Self-Healing ---" -ForegroundColor Cyan
    $st = Get-HvmJson 'status'
    if (-not $st) {
        throw 'hvm_ctl status failed to get result —— driver likely not loaded. Run Deploy-KswordDriverToVm.ps1 first.'
    }
    $names = @($st.stateNames)
    Write-Host ("  Current status: {0}" -f ($names -join ' '))

    if (($names -contains 'FAULTED') -or ($names -contains 'ROLLBACK_REQUIRED')) {
        $r = Get-HvmJson 'reset-fault'
        Write-Host ("  reset-fault -> {0}" -f $(if ($r) { $r.statusName } else { 'No Response' }))
        if ($r) { $names = @($r.newStateNames) }
    }
    if ($names -notcontains 'RESOURCES_READY') {
        $r = Get-HvmJson 'prepare'
        Write-Host ("  prepare -> {0}" -f $(if ($r) { $r.statusName } else { 'No response' }))
        if ($r) { $names = @($r.newStateNames) }
    } else {
        Write-Host "  prepare skip (RESOURCES_READY is set)" -ForegroundColor DarkGray
    }
    if ($names -notcontains 'SELF_TEST_PASSED') {
        $r = Get-HvmJson 'self-test'
        Write-Host ("  self-test -> {0}" -f $(if ($r) { $r.statusName } else { 'No response' }))
        if ($r) { $names = @($r.newStateNames) }
    } else {
        Write-Host "  self-test skipped (SELF_TEST_PASSED is set)" -ForegroundColor DarkGray
    }

    $ok = ($names -contains 'RESOURCES_READY') -and
          ($names -contains 'SELF_TEST_PASSED') -and
          ($names -notcontains 'FAULTED')
    if (-not $ok) {
        throw ("Preconditions not met, the experiment will not measure anything. Current state: {0}" -f ($names -join ' '))
    }
    Write-Host ("  [OK] Prerequisites met: {0}" -f ($names -join ' ')) -ForegroundColor Green
}

Initialize-HvmPrereq

# --- 1. Baseline ----------------------------------------------------------------
Write-Host "`n--- 1. Baseline (VM idle for $BaselineSeconds seconds) ---" -ForegroundColor Cyan
$t0 = Get-Date
while (((Get-Date) - $t0).TotalSeconds -lt $BaselineSeconds) {
    $r = Add-Sample 'baseline'
    Start-Sleep -Seconds $SampleInterval
}
$baseNested = ($samples | Where-Object { $_.phase -eq 'baseline' } |
    ForEach-Object { Get-Field $_.PSObject.Properties['nested_vm_entries_sec'].Value '*' } ) 2>$null
$baseAvg = ($samples | Where-Object { $_.phase -eq 'baseline' -and $_.PSObject.Properties['nested_vm_entries_sec'] } |
    Measure-Object -Property nested_vm_entries_sec -Average).Average
Write-Host ("  Nested VM Entries/sec Idle Mean = {0:N2}" -f $baseAvg)

# --- 2. Calibration (this section is foundational and cannot be skipped)------------------------------------------
Write-Host "`n--- 2. Calibration: Send one LAUNCH_TEST_GUEST ---" -ForegroundColor Cyan
Write-Host "  It is known to produce exactly 1 nested entry. Counter does not jump => criterion is unreliable, experiment discarded." -ForegroundColor DarkGray
[void]$marks.Add([ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); mark = 'launch-test-guest:before' })
$calib = Invoke-HvmCtl 'launch-test-guest'
if ($calib) { Write-Host ("  Exit code {0}" -f $calib.Exit) }
for ($i = 0; $i -lt 8; $i++) { $r = Add-Sample 'calibrate'; Start-Sleep -Seconds $SampleInterval }
$calAvg = ($samples | Where-Object { $_.phase -eq 'calibrate' -and $_.PSObject.Properties['nested_vm_entries_sec'] } |
    Measure-Object -Property nested_vm_entries_sec -Maximum).Maximum
Write-Host ("  Nested VM Entries/sec Calibrated Peak = {0:N2} (Baseline {1:N2})" -f $calAvg, $baseAvg)
$calibrated = ($null -ne $calAvg -and $null -ne $baseAvg -and $calAvg -gt $baseAvg)
if ($calibrated) {
    Write-Host "  [OK] The counter responds to the nested entry; the criterion is available." -ForegroundColor Green
} else {
    Write-Host "  [Warning] The counter shows no obvious jump. Subsequent readings **cannot be used as a conclusion**, only as a reference." -ForegroundColor Yellow
}

if ($SkipResident) {
    Write-Host "`nPress -SkipResident to exit without sending START_RESIDENT." -ForegroundColor Yellow
} else {
    # --- 3. Observation -------------------------------------------------------
    Write-Host "`n--- 3. Observation: Send START_RESIDENT ---" -ForegroundColor Cyan
    Write-Host "  guest may hang here. Sampling is on the host and unaffected." -ForegroundColor DarkGray
    [void]$marks.Add([ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); mark = 'resident:before' })

    # Do not wait for it to return; this call never returns if the system hangs.
    $job = Start-Job -ScriptBlock {
        param($n, $u, $p)
        $c = New-Object System.Management.Automation.PSCredential(
            $u, (ConvertTo-SecureString $p -AsPlainText -Force))
        Invoke-Command -VMName $n -Credential $c -ScriptBlock {
            $o = 'C:\ksword\fr_res.txt'
            Remove-Item $o -ErrorAction SilentlyContinue
            $pp = Start-Process -FilePath 'C:\ksword\hvm_ctl.exe' -ArgumentList @('--json','resident') `
                      -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o `
                      -RedirectStandardError 'C:\ksword\fr_res_err.txt'
            $t = ''
            if (Test-Path $o) { $t = [IO.File]::ReadAllText($o) }
            [ordered]@{ Exit = $pp.ExitCode; Out = $t }
        }
    } -ArgumentList $VMName, $GuestUser, $GuestPassword

    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $ObserveSeconds) {
        $r = Add-Sample 'observe'
        if ($r -and $r['nested_vm_entries_sec'] -ne $null) {
            Write-Host ("  t+{0,3:N0}s  nestedEntries={1,10:N1}  intercepts={2,10:N1}  guest%={3,6:N1}  hv%={4,6:N1}" -f `
                ((Get-Date) - $t0).TotalSeconds, $r['nested_vm_entries_sec'],
                $r['total_intercepts_sec'], $r['__guest_run_time'], $r['__hypervisor_run_time'])
        }
        Start-Sleep -Seconds $SampleInterval
    }
    if ($job.State -eq 'Completed') {
        $res = Receive-Job $job -ErrorAction SilentlyContinue
        Write-Host ("`n  resident returned: exit code {0}" -f $res.Exit)
        if ($res.Out) { Write-Host "  $($res.Out)" }
    } else {
        Write-Host "`n  resident call did not return (guest is likely hung)." -ForegroundColor Yellow
    }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    [void]$marks.Add([ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); mark = 'observe:end' })
}

# --- Disk Write and Interpretation --------------------------------------------------------------
$samples | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
$flightRecord = [ordered]@{
    schema     = 'ksword.hostflight/1'
    vmName     = $VMName
    instance   = $instance
    counters   = $paths
    calibrated = $calibrated
    baselineNestedEntriesAvg = $baseAvg
    calibrationNestedEntriesMax = $calAvg
    marks      = $marks
    csv        = $csv
}
# JSON must be BOM-free; see the note at the end of the file.
[IO.File]::WriteAllText(
    $json,
    ($flightRecord | ConvertTo-Json -Depth 8),
    (New-Object Text.UTF8Encoding($false)))

$obs = @($samples | Where-Object { $_.phase -eq 'observe' -and $_.PSObject.Properties['nested_vm_entries_sec'] })
Write-Host "`n=== Judgment ===" -ForegroundColor Cyan
if (-not $calibrated) {
    Write-Host "  Calibration failed - the following interpretation is for reference only and cannot be used as a conclusion." -ForegroundColor Yellow
}
if ($obs.Count -eq 0) {
    Write-Host "  No valid samples in the observation segment."
} else {
    $ne = ($obs | Measure-Object -Property nested_vm_entries_sec -Average).Average
    $ti = ($obs | Measure-Object -Property total_intercepts_sec -Average).Average
    $gt = ($obs | Measure-Object -Property __guest_run_time -Average).Average
    $ht = ($obs | Measure-Object -Property __hypervisor_run_time -Average).Average
    Write-Host ("  Observation segment mean: nestedEntries={0:N1}  intercepts={1:N1}  guest%={2:N1}  hv%={3:N1}" -f $ne, $ti, $gt, $ht)

    # Directly list the counters that increased the most in the observation segment — 'Which category accounts for the 100,000 interceptions?'
    # This issue must be answered by readings, not guesses. The previous round failed completely because only three categories were sampled.
    $cols = $samples[0].PSObject.Properties.Name | Where-Object { $_ -notin @('utc','phase','error') }
    $rank = foreach ($c in $cols) {
        $b = ($samples | Where-Object { $_.phase -eq 'baseline' -and $null -ne $_.$c } |
              Measure-Object -Property $c -Average).Average
        $o = ($obs | Where-Object { $null -ne $_.$c } | Measure-Object -Property $c -Average).Average
        if ($null -eq $o) { continue }
        [pscustomobject]@{ counter = $c; baseline = [math]::Round(($b), 1); observe = [math]::Round($o, 1); delta = [math]::Round($o - $b, 1) }
    }
    Write-Host "`n  Observation segment relative baseline increase ranking (top 8):" -ForegroundColor Cyan
    $rank | Sort-Object delta -Descending | Select-Object -First 8 |
        Format-Table counter, baseline, observe, delta -AutoSize | Out-Host
    if ($ne -gt ($baseAvg + 1)) {
        Write-Host "  => VM entry **continues to succeed**, exit continues to be processed, but the guest makes zero progress." -ForegroundColor Yellow
        Write-Host "     Next, look at the breakdown: MSR Accesses/sec off the charts = synthetic MSR storm;" -ForegroundColor DarkGray
        Write-Host "     Excessive Hypercalls/sec = hypercall storm;" -ForegroundColor DarkGray
        Write-Host "     Excessive Nested Page Fault Intercepts/sec = shadow EPT thrashing." -ForegroundColor DarkGray
    } elseif ($ti -lt 1 -and $gt -gt 50) {
        Write-Host "  => CPU is idling in L1's **VMX root** (L1's root still counts as guest time from L0's perspective)." -ForegroundColor Yellow
    } elseif ($ht -gt $gt) {
        Write-Host "  => Stuck on the **L0 side**." -ForegroundColor Yellow
    } else {
        Write-Host "  =>  Falls into no gear, paste the CSV for manual interpretation." -ForegroundColor Yellow
    }
}
Write-Host ("`nCSV  : {0}" -f $csv)
Write-Host ("JSON : {0}" -f $json)
