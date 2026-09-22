<#
.SYNOPSIS
    Run all required tests for this round with a single command and generate a merged report. Designed for unattended execution.

.DESCRIPTION
    This script itself performs no new test logic; it schedules existing stages in dependency order, clears
    state between each stage, and automatically collects evidence upon failure. It exists separately
    because the most common issue in unattended runs is not "a single stage failing," but rather:

      * The previous item leaves the machine in a dirty state; each subsequent item tests a different machine.
      * Note: A mid-run BSOD + auto-restart goes undetected by the script, causing all subsequent checks to report 'pass'.
      * Discovered after completion that the driver in the guest was not the one just built.

    Thus, sequence verification, status checks, hash verification, and crash forensics are all handled here, not left for human memory.

    **Order is intentional; do not change it arbitrarily.
      1. Offline assertion + tool compilation — fail here first to avoid touching the VM, saving the most resources.
      2. Deploy + SHA256 verification — only then can subsequent readings be attributed.
      3. probe-platform — Read-only; calibrate CET, KVA shadow, and GS base.
      4. probe-flags —— Send requests only, expect all to be rejected, do not change state.
      5. self-test —— VMXON/VMXOFF only
      6. launch-guest — a one-time controlled guest with an explosion radius of a single 4KiB stack
      7. resident + stop — Verify residency liveness after the initiating process (HOST_CR3 and CR3 restoration).
      8. soak: Long-duration stress test to verify StateFlags remain stable after full interlocked operations.
      9. view-probe / view-effect — Separate views: installed and **actually effective**
     10. probe-xonly — Will exit virtualization, so place it last

    3 and 4 precede 5 because they are read-only: if this driver version has issues, obtaining platform readings first is
    more useful than crashing the machine. 9 is placed last because it is designed to cause the resident component to exit.

.PARAMETER SoakMs
    Soak duration. **Hard upper limit on the driver side is 30 seconds** (KSWORD_ARK_HVM_SOAK_MAX_MILLISECONDS);
    values larger than this are silently clamped to 30000—the soakElapsedMilliseconds in the report reflects the
    actual duration. Thus, the default is set to 30000, avoiding an unachievable number.

.PARAMETER SkipOffline
    Skip section 1. Use only when the offline suite has just been run.

.EXAMPLE
    .\Invoke-KswordUnattendedSuite.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName  = 'KSword-HVM-Target',
    [ValidateRange(1, 30000)]   # Hard limit for the driver; values exceeding this are silently dropped.
    [int]    $SoakMs  = 30000,
    [switch] $SkipOffline
)

$ErrorActionPreference = 'Stop'
$repo   = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repo 'docs\next\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'

$sysPath = Join-Path $repo 'artifacts/bin\x64\Release\KswordARK.sys'
$record  = [ordered]@{
    schema      = 'ksword-unattended-suite/1'
    startedUtc  = (Get-Date).ToUniversalTime().ToString('o')
    vmName      = $VMName
    soakMs      = $SoakMs
    driverSha256 = $null
    stages      = [System.Collections.ArrayList]::new()
    verdict     = 'NOT_RUN'
    notes       = [System.Collections.ArrayList]::new()
}
$resultPath = Join-Path $logDir "unattended-$stamp.json"

function Save-Record {
    $record.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
    # JSON must be BOM-free; see the note at the end of the file.
    [IO.File]::WriteAllText(
        $resultPath,
        ($record | ConvertTo-Json -Depth 14),
        (New-Object Text.UTF8Encoding($false)))
}

function Add-Stage {
    param([string] $Name, [string] $Outcome, [string] $Note, $Data)
    $e = [ordered]@{
        name = $Name
        utc  = (Get-Date).ToUniversalTime().ToString('o')
        outcome = $Outcome
    }
    if ($Note) { $e.note = $Note }
    if ($null -ne $Data) { $e.data = $Data }
    [void]$record.stages.Add($e)
    $color = switch ($Outcome) { 'PASS' { 'Green' } 'SKIP' { 'DarkGray' } 'BLOCKED' { 'Yellow' } default { 'Red' } }
    Write-Host ("[{0,-7}] {1}{2}" -f $Outcome, $Name, $(if ($Note) { "  — $Note" })) -ForegroundColor $color
    Save-Record
}

# Crash forensics: **Run only when the guest truly crashes**.
#
# A single failure does not mean the guest crashed. We tested this once: the guest ran successfully in one attempt, and the driver returned normally,
# This is an hvm_ctl.exe AV when returning to user mode, with exit code 0xC0000005 bubbling up — that's a tool-side issue, unrelated to the guest.
# The incident is unrelated to the guest. Attempting to retrieve the dump will only return a **dump from several hours ago**.
# Then it presents a completely self-consistent yet entirely false narrative.
#
# Use the control script's recorded 'alive' steps as the criterion: if it matches the boot-time state and returns OK, it indicates no reboot occurred.
function Test-GuestActuallyCrashed {
    param($StageData)
    if ($null -eq $StageData -or $null -eq $StageData.steps) { return $true }
    $alive = @($StageData.steps | Where-Object { $_.name -like 'alive:*' })
    if ($alive.Count -eq 0) { return $true }      # Liveness not tested; conservative forensics.
    # Consider the guest to have failed only if an alive check reports FAIL.
    return [bool](@($alive | Where-Object { $_.outcome -ne 'OK' }).Count -gt 0)
}

function Invoke-CrashForensics {
    param([string] $AfterStage)
    Write-Host "`nSomething went wrong, starting automatic forensics..." -ForegroundColor Yellow
    try {
        & (Join-Path $PSScriptRoot 'Get-KswordVmBugcheck.ps1') -VMName $VMName 2>&1 |
            Tee-Object -Variable out | Out-Host
        $newest = Get-ChildItem $logDir -Filter 'bugcheck-*.json' |
                  Sort-Object -Property { $_.LastWriteTime } -Descending |
                  Select-Object -First 1
        if ($newest) {
            [void]$record.notes.Add("Crash forensics (after $AfterStage): $($newest.FullName)")
        }
    } catch {
        [void]$record.notes.Add("Crash forensics failed: $($_.Exception.Message)")
    }
}

# Run a stage and return $true/$false. On failure, attach the log written by the control script to the report.
function Invoke-Stage {
    param([string] $Stage, [string] $Why, [int] $Soak = 0)

    Write-Host "`n=== $Stage ===  $Why" -ForegroundColor Cyan
    $before = Get-ChildItem $logDir -Filter 'hvm-autotest-*.json' -ErrorAction SilentlyContinue
    $beforeNames = @($before | ForEach-Object { $_.Name })

    # splat must use a **hash table**, not an array.
    #
    # Array splatting passes arguments **by position**: `@('-Stage','resident')` will pass the string "-Stage" as a positional argument.
    # It is bound to the first positional parameter (which happens to be $Stage), so it reports
    # "The argument '-Stage' does not belong to the set ..." ——
    # Looks like a typo in the stage name, but it's actually a parameter passing error. This has consumed an entire test run in practice.
    # Only hash table splatting passes arguments by name.
    $stageArgs = @{ Stage = $Stage; VMName = $VMName }
    if ($Soak -gt 0) { $stageArgs['SoakMs'] = $Soak }

    $global:LASTEXITCODE = $null
    & (Join-Path $PSScriptRoot 'Invoke-KswordHvmControl.ps1') @stageArgs | Out-Host
    $code = $LASTEXITCODE
    if ($null -eq $code) {
        # When binding fails or the script throws an exception, $LASTEXITCODE is not set. Treat this as a failure.
        # Instead of letting the `$code -eq 0` comparison silently evaluate to false with error messages pointing elsewhere.
        Add-Stage $Stage 'FAIL' "Call did not return an exit code (likely parameter binding failure) — $Why"
        return $false
    }

    # Import the machine log just written by the control script so the report is self-contained.
    $data = $null
    $after = Get-ChildItem $logDir -Filter 'hvm-autotest-*.json' -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -notin $beforeNames } |
             Sort-Object -Property { $_.LastWriteTime } -Descending |
             Select-Object -First 1
    if ($after) {
        try { $data = Get-Content $after.FullName -Raw | ConvertFrom-Json } catch { }
    }

    if ($code -eq 0) {
        Add-Stage $Stage 'PASS' $Why $data
        return $true
    }
    if ($code -eq 4) {
        # Not applicable to this machine: the hardware capabilities required by the criteria are not provided, so there is nothing to fix.
        #
        # The reason for separating from 3 is not wording: dragging the overall verdict to downgrade in 3 is **correct** because someone should fix it;
        # 4 If also downgraded, the suite will always be marked PARTIAL for this entire class of hardware, and reports that never turn green with
        # No report equivalence — the next time a real issue occurs, no one will pay extra attention to that line.
        #
        # It also **does not count as passed**: this item measured nothing; the reason for not measuring is outside our scope.
        Add-Stage $Stage 'NOT_APPLICABLE' "This issue cannot be reproduced on the local machine —— $Why" $data
        [void]$record.notes.Add("$Stage Not applicable on local machine: the hardware capabilities required by the criteria do not exist; this is not a matter of being unprepared.")
        return $true
    }
    if ($code -eq 3) {
        # Skipped: Completed but lacks discriminative power. **Not a pass**, but should not interrupt the entire round --
        # Subsequent items are unrelated. Mark as BLOCKED to downgrade the overall verdict, then continue.
        Add-Stage $Stage 'BLOCKED' "Skipped (ran but no test detected) — $Why" $data
        [void]$record.notes.Add("$Stage Skipped: This item did not test anything this time, so it does not count as passed.")
        $script:anyBlocked = $true
        return $true
    }
    Add-Stage $Stage 'FAIL' "Exit code $code — $Why" $data
    return $false
}

$anyBlocked = $false

# ---------------------------------------------------------------------------
Write-Host "=== KSword Unattended Suite ===" -ForegroundColor Cyan
Write-Host "Log -> $resultPath`n"

try {
    # --- 0. Driver hash: Record it first so all subsequent readings can be identified as belonging to a specific binary.
    if (-not (Test-Path $sysPath)) {
        Add-Stage 'Pre: Driver Exists' 'FAIL' "Cannot find $sysPath — Build first"
        $record.verdict = 'FAIL'
        exit 1
    }
    $record.driverSha256 = (Get-FileHash $sysPath -Algorithm SHA256).Hash
    Add-Stage 'Pre: Driver Hash' 'PASS' $record.driverSha256

    $sig = Get-AuthenticodeSignature $sysPath
    if ($sig.Status -eq 'NotSigned') {
        Add-Stage 'Pre: Driver Signed' 'FAIL' 'Unsigned, sending to guest will only result in sc start 577'
        $record.verdict = 'FAIL'
        exit 1
    }
    Add-Stage 'Pre: Driver Signed' 'PASS' "$($sig.Status)"

    # --- 0b. Free up disk space first ---
    #
    # This round's risky stage creates 5 checkpoints, plus one for the deployment itself, each consuming approximately 8 GiB.
    # In unattended mode, a full disk is misleading: checkpoint failure → VM enters Paused-Critical.
    # → Looks like a hang. Better to clear it before starting than to crash halfway through.
    # clean-install: Never delete (it is the only fallback to return to a clean system).
    $freeGb = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
    Write-Host "`n=== Disk ===  C: $freeGb GB remaining" -ForegroundColor Cyan
    if ($freeGb -lt 80) {
        try {
            & (Join-Path $PSScriptRoot 'Clear-KswordVmCheckpoints.ps1') `
                -VMName $VMName -KeepLast 0 -Confirm | Out-Host
            $freeGb = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
            Add-Stage 'Pre: Checkpoint Cleanup' 'PASS' "Remaining $freeGb GB after cleanup (clean-install reserved)"
        } catch {
            Add-Stage 'Pre: Checkpoint Cleanup' 'BLOCKED' $_.Exception.Message
        }
    } else {
        Add-Stage 'Pre: Checkpoint Cleanup' 'SKIP' "Remaining $freeGb GB, sufficient"
    }
    if ($freeGb -lt 50) {
        [void]$record.notes.Add(
            "Only $freeGb GB of disk space remains; 5 checkpoints likely won't fit —— if it fails midway, first check if the disk is full.")
    }

    # --- 1. Offline: Avoid touching the VM; failing here early saves the most resources ---
    if ($SkipOffline) {
        Add-Stage 'Offline Assertion + Tool' 'SKIP' 'Skip with -SkipOffline'
    } else {
        Write-Host "`n=== Offline Assertion + Tool Compilation ===" -ForegroundColor Cyan
        & (Join-Path $PSScriptRoot 'Invoke-KswordAutomatedAcceptance.ps1') -OfflineOnly | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Add-Stage 'Offline Assertion + Tool' 'FAIL' "Exit Code $LASTEXITCODE"
            $record.verdict = 'FAIL'
            exit 1
        }
        Add-Stage 'Offline Assertion + Tools' 'PASS' '4000 Assertions + Two /MT Tools'
    }

    # --- 2. Deployment (scripts internally compare host and guest SHA256) ---
    Write-Host "`n=== Deployment ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'Deploy-KswordDriverToVm.ps1') -VMName $VMName | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Add-Stage 'Deploy + Hash Verification' 'FAIL' "Exit code $LASTEXITCODE --- Prerequisites or hash mismatch, subsequent stages will not run"
        $record.verdict = 'FAIL'
        exit 1
    }
    Add-Stage 'Deploy + Hash Verification' 'PASS' 'On the guest, it is exactly the freshly built version'

    # --- Steps 3..9 in dependency order ---
    $plan = @(
        @{ S = 'probe-platform'; W = 'Read-only: CET / KVA shadow / GS base calibration';            Soak = 0 }
        @{ S = 'self-test';      W = 'VMXON/VMXOFF';                                      Soak = 0 }
        # probe-flags is placed **after** self-test: driver pre-checks occur before all capability gates.
        # Without prepare+self-test, the capability gate is never queried, so the test would pass by default.
        @{ S = 'probe-flags';    W = 'Negative: Whether ENFORCE and capability flags are rejected at the places they should be rejected';      Soak = 0 }
        @{ S = 'launch-guest';   W = 'One-time controlled guest: VMCS construction + EPTP + VMLAUNCH';     Soak = 0 }
        @{ S = 'resident';       W = 'Resident hypervisor survives the initiating process (HOST_CR3 + CR3 restoration when leaving virtualization)';  Soak = 0 }
        # Nested end-to-end, scheduled after resident and before soak.
        #
        # Previously, this entire line could only be run manually, so nothing it verified was ever re-verified in regression.
        # — while the most expensive path in nested virtualization (where an MSR exit is dispatched to us but no one services it)
        # The symptom is a **silent hang**, not an error. A validation run with no one watching equals no validation.
        @{ S = 'nested';         W = 'L2 end-to-end: vmcs02 merge + shadow EPT + MSR bitmap routing';  Soak = 0 }
        @{ S = 'soak';           W = "Long-distance run $SoakMs ms (driver limit 30000): StateFlags full interlocked remains stable"; Soak = $SoakMs }
        # View attribution probes emit VIEW_OP_ADD only once and do not enter VMX, so they are placed before the two levels that may exit virtualization.
        @{ S = 'view-probe';     W = 'Attribution during separated view installation: Rejection occurs at that specific door of denial';      Soak = 0 }
        # End-to-end effectiveness criterion. It starts and stops the resident component itself and is the **only** one that truly triggers an EPTP switch exit.
        # This is a level in the path, so it runs before probe-xonly — probe-xonly is designed to exit virtualization.
        # Running it first means the next level starts on a machine where the resident component has just been removed.
        @{ S = 'view-effect';    W = 'CLOAK is truly effective: kernel reads are redirected to shadow and the resident hypervisor remains active';   Soak = 0 }
        @{ S = 'probe-xonly';    W = 'EPT permissions are still enforced (leaving virtualization is by design, so placed last)';    Soak = 0 }
    )

    $anyFail = $false
    foreach ($p in $plan) {
        if (-not (Invoke-Stage $p.S $p.W $p.Soak)) {
            $anyFail = $true
            # Stop on first failure: Continuing in a dirty state would cause subsequent items to test a different machine.
            [void]$record.notes.Add("Stop after failure in $($p.S) — do not continue on a dirty state.")
            $lastStage = $record.stages[$record.stages.Count - 1]
            if (Test-GuestActuallyCrashed $lastStage.data) {
                Invoke-CrashForensics $p.S
            } else {
                [void]$record.notes.Add(
                    "guest survives throughout without rebooting —— this is a failure on the **tool or script side**," +
                    "Not a guest crash. No dump was taken (what would be retrieved is an old one).")
                Write-Host "`nguest did not crash (all alive checks OK and no reboot) — do not collect dump." -ForegroundColor Yellow
            }
            break
        }
        # Trim each segment to keep only the most recent checkpoint.
        #
        # Each stage's plan includes its own self-test, so a full round generates about a dozen checkpoints.
        # Each is about 8 GiB — with current free space, it will inevitably fill the disk, and the symptom of a full disk (the VM hangs
        # Paused-Critical appears to be hung. Keeping one is sufficient to roll back to the previous state.
        try {
            & (Join-Path $PSScriptRoot 'Clear-KswordVmCheckpoints.ps1') `
                -VMName $VMName -KeepLast 1 -Confirm | Out-Null
        } catch { }
    }

    # Three-state overall verdict. PARTIAL is not 'basically passed'; it means 'some items were not tested' — listed separately.
    # Otherwise, it is treated as a green light.
    $record.verdict = if ($anyFail) { 'FAIL' }
                      elseif ($anyBlocked) { 'PARTIAL' }
                      else { 'PASS' }
}
catch {
    $record.verdict = 'ERROR'
    [void]$record.notes.Add("Suite exception: $($_.Exception.Message)")
    Write-Host "`nSuite exception: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # No matter how it exits, clean up the resident component completely; leaving it will cause the next deployment to collide.
    # The misleading error message 'CPUID does not show VMX'.
    try {
        & (Join-Path $PSScriptRoot 'Invoke-KswordHvmControl.ps1') `
            -Stage stop -VMName $VMName -SkipCheckpoint 2>&1 | Out-Null
    } catch { }

    Save-Record
    Write-Host ""
    Write-Host ("================ Unattended Suite Final Verdict: {0} ================" -f $record.verdict) `
        -ForegroundColor $(switch ($record.verdict) {
            'PASS' { 'Green' } 'PARTIAL' { 'Yellow' } default { 'Red' } })
    if ($record.verdict -eq 'PARTIAL') {
        Write-Host "  PARTIAL is not 'Basic Pass' -- some projects ran but nothing was tested." -ForegroundColor Yellow
    }
    foreach ($n in $record.notes) { Write-Host "  · $n" -ForegroundColor Yellow }
    Write-Host "  Report : $resultPath" -ForegroundColor Cyan
    Write-Host "  Driver : $($record.driverSha256)" -ForegroundColor DarkGray
    exit $(switch ($record.verdict) { 'PASS' { 0 } 'PARTIAL' { 3 } default { 1 } })
}
