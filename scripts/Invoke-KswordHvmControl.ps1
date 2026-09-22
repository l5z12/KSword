<#
.SYNOPSIS
    Automatically advance the KSword HVM lifecycle on a Hyper-V test machine: read the status first, decide the next action, take
    a checkpoint before entering VMX, and verify the VM is still alive afterward; output machine-readable JSON records throughout.

.DESCRIPTION
    Must run as **Administrator**.

    The key difference from the previous version is: **this version checks the status first to decide the action**, rather than unconditionally sending commands in sequence.

      * Repeating PREPARE sets the state to FAULTED. When already ready, the driver returns
        STATUS_ALREADY_REGISTERED, which is an NT_ERROR and triggers the `StateFlags |=
        FAULTED` branch in hvm_runtime.c; FAULTED then causes START_RESIDENT to be rejected
        by hvm_resident.c with STATUS_INVALID_DEVICE_STATE. Thus, an operation that appears
        idempotent like "running prepare again" blocks the subsequent flow.
        This script first checks status; if RESOURCES_READY is set, it skips prepare.

      * If FAULTED or ROLLBACK_REQUIRED is seen, reset-fault first before proceeding.

      * The set of flags for each command is provided by hvm_ctl.exe according to the allowedFlags table in hvm_runtime.c.
        SELF_TEST, START_RESIDENT, SOAK, and RESET_FAULT all require the FORCE bit; without it, the result is always
        CONFIRMATION_REQUIRED. That status code *looks* like a security policy is disabled, but it is actually unrelated
        to security policies (the default value on the security policy side is 0x3fbff, which already allows this).

    The levels are intentional; do not skip steps:

      prepare: allocates per-processor resources, **does not enter VMX**. Failure is only a resource issue and will not cause a BSOD.
      self-test: Executes VMXON followed by VMXOFF on each processor. The first execution enters VMX root mode but does not remain resident.
                 In a nested environment, this is the crucial step: it establishes whether VMXON can run in L1.
      resident: VMM resident on all processors with EPT enabled. The system runs continuously in VMX non-root mode thereafter.
      soak: Run for a bounded duration then stop to prove stability under normal system activity.

.PARAMETER Stage
    safe = status + necessary reset-fault/prepare + self-test
    (default, non-resident); prepare = only up to prepare
    self-test = run only self-test (preconditions are auto-satisfied
    if missing) resident = proceed to resident mode and run stop
    soak soak = proceed to resident mode and perform bounded soak
    full = soak + stop + teardown; clear all state after completion
    status / stop / teardown / reset-fault = single commands

.PARAMETER ResultPath
    Path where JSON records are persisted. Defaults to docs\next\logs\hvm-autotest-<timestamp>.json.

.PARAMETER SkipCheckpoint
    Skip pre-VMX checkpoints. **Not recommended**; use only immediately after applying a checkpoint.

.EXAMPLE
    .\Invoke-KswordHvmControl.ps1
    .\Invoke-KswordHvmControl.ps1 -Stage soak -SoakMs 5000
#>
[CmdletBinding()]
param(
    [ValidateSet('safe', 'status', 'prepare', 'self-test', 'launch-guest',
                 'resident', 'probe-platform', 'probe-flags', 'probe-xonly',
                 'view-probe', 'view-effect', 'nested',
                 'soak', 'stop', 'teardown', 'reset-fault', 'full')]
    [string] $Stage         = 'safe',
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [int]    $SoakMs        = 2000,
    # This script retains a few before-* checkpoints it creates. Each consumes approximately 8 GiB of memory image +
    # A differencing disk; keeping too many will exhaust the system disk. Manual baselines (clean-install) are exempt.
    [int]    $KeepCheckpoints = 2,
    [string] $ResultPath,
    [switch] $SkipCheckpoint
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$repo = Split-Path $PSScriptRoot -Parent
$tool = Join-Path $repo 'tools\hvm_ctl\hvm_ctl.exe'
if (-not (Test-Path $tool)) { throw "Missing $tool (run scripts\Build-KswordHvmTools.ps1 first)" }

if (-not $ResultPath) {
    $logDir = Join-Path $repo 'docs\next\logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
    $ResultPath = Join-Path $logDir ('hvm-autotest-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
}

$cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

# The entire record. Each step appends to it, and the record is persisted even if the script throws an exception mid-execution (see the finally block at the end).
$record = [ordered]@{
    schema      = 'ksword.hvm.autotest/1'
    startedUtc  = (Get-Date).ToUniversalTime().ToString('o')
    vmName      = $VMName
    stage       = $Stage
    host        = [ordered]@{
        computer = $env:COMPUTERNAME
        os       = (Get-CimInstance Win32_OperatingSystem).Caption
        build    = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    }
    steps       = New-Object System.Collections.ArrayList
    checkpoints = New-Object System.Collections.ArrayList
    verdict     = 'NOT_RUN'
    notes       = New-Object System.Collections.ArrayList
}

function Add-Step {
    param([string] $Name, [string] $Outcome, $Data, [string] $Note)
    $entry = [ordered]@{
        name    = $Name
        utc     = (Get-Date).ToUniversalTime().ToString('o')
        outcome = $Outcome
    }
    if ($null -ne $Data) { $entry.data = $Data }
    if ($Note)           { $entry.note = $Note }
    [void]$record.steps.Add($entry)
    $color = switch ($Outcome) { 'OK' { 'Green' } 'SKIP' { 'DarkGray' } 'BLOCKED' { 'Yellow' } default { 'Red' } }
    Write-Host ("  [{0,-7}] {1}{2}" -f $Outcome, $Name, $(if ($Note) { "  — $Note" })) -ForegroundColor $color
}

function Save-Record {
    $record.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
    # JSON must be BOM-free; see the note at the end of the file.
    [IO.File]::WriteAllText(
        $ResultPath,
        ($record | ConvertTo-Json -Depth 12),
        (New-Object Text.UTF8Encoding($false)))
}

function Invoke-Guest {
    # Parameter name cannot be $Args—that is a PowerShell automatic variable that causes -ArgumentList to receive an empty value.
    param([scriptblock] $Script, [object[]] $ScriptArgs)
    if ($null -eq $ScriptArgs -or $ScriptArgs.Count -eq 0) {
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script
    } else {
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script -ArgumentList $ScriptArgs
    }
}

function Test-GuestAlive {
    param([int] $TimeoutSeconds = 120)
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

# Guest boot time. Used to distinguish between 'alive' and 'crashed but self-recovered'.
#
# Just checking "whether it can respond" is insufficient: the deployment script sets AutoReboot to 1 (to obtain dumps),
# So if a BSOD + auto-reboot recovers within the 120-second window of Test-GuestAlive,
# Exactly like 'never crashed' — alive: OK. Among a night's worth of PASS results, this might be the only one mixed in.
function Get-GuestBootTime {
    try {
        $t = Invoke-Command -VMName $VMName -Credential $cred -ErrorAction Stop `
                 -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
        return [datetime]$t
    } catch { return $null }
}

# Check if a crash occurred: a change in boot time indicates a reboot. Then distinguish between BSOD and silent reset via event logs.
function Get-GuestCrashEvidence {
    param($BootBefore)

    $bootAfter = Get-GuestBootTime
    if ($null -eq $BootBefore -or $null -eq $bootAfter) { return $null }
    if ([math]::Abs(($bootAfter - $BootBefore).TotalSeconds) -lt 2) { return $null }

    $code = $null
    try {
        $code = Invoke-Command -VMName $VMName -Credential $cred -ErrorAction Stop -ScriptBlock {
            $e = Get-WinEvent -FilterHashtable @{
                     LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41
                 } -MaxEvents 1 -ErrorAction SilentlyContinue
            if (-not $e) { return $null }
            $x = [xml]$e.ToXml()
            ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'BugcheckCode' }).'#text'
        }
    } catch { }

    if ($null -ne $code -and [int]$code -ne 0) {
        return "This stage **caused a BSOD and rebooted** bugcheck=0x$('{0:X}' -f [int]$code) (boot time $BootBefore -> $bootAfter)"
    }
    return "This phase **restarted but without a bugcheck code** — silent reset (typical fingerprint of triple fault), boot moment $BootBefore -> $bootAfter"
}

function New-Guard {
    param([string] $Label)
    if ($SkipCheckpoint) { Add-Step "checkpoint:$Label" 'SKIP' $null 'Skip by -SkipCheckpoint'; return $null }

    # Each checkpoint must store a full memory image (8 GiB locally) plus a differencing disk for tiered testing.
    # Each round produces one or two. Without cleanup, the system drive will quickly fill up, manifesting as
    # "Checkpoint operation failed ... insufficient disk space (0x80070070)",
    # At that point, the script was already halfway through, making it appear as if an HVM issue occurred.
    # Therefore, before creating each checkpoint, prune the ones created by this script itself (those with names starting with 'before-').
    # Keep only the most recent $KeepCheckpoints. **Never touch manual baselines like clean-install.**
    try {
        $mine = @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop |
                  Where-Object { $_.Name -like 'before-*' } |
                  Sort-Object CreationTime -Descending)
        if ($mine.Count -gt $KeepCheckpoints) {
            foreach ($old in $mine[$KeepCheckpoints..($mine.Count - 1)]) {
                Remove-VMSnapshot -VMName $VMName -Name $old.Name -Confirm:$false
                Add-Step "prune:$($old.Name)" 'OK' $null 'Automatically prune old checkpoints to reclaim disk space'
            }
            # Merging is asynchronous; without waiting, the next Checkpoint-VM may still encounter insufficient space.
            $deadline = (Get-Date).AddMinutes(15)
            while ((Get-Date) -lt $deadline -and
                   (Get-VM -Name $VMName).Status -match 'Merg|合并') {
                Start-Sleep -Seconds 10
            }
        }
    } catch {
        [void]$record.notes.Add("Checkpoint pruning failed (does not affect subsequent operations): $($_.Exception.Message)")
    }

    $name = "before-$Label-" + (Get-Date -Format 'MMdd-HHmmss')
    try {
        Checkpoint-VM -Name $VMName -SnapshotName $name
    } catch {
        # Insufficient space is a recoverable operational issue, not an HVM failure. Report separately and provide the cleanup command.
        Add-Step "checkpoint:$Label" 'FAIL' $null $_.Exception.Message
        if ("$($_.Exception.Message)" -match '0x80070070|磁盘空间不足|not enough space') {
            [void]$record.notes.Add('Checkpoint failure is due to insufficient disk space, unrelated to HVM. Cleanup: .\scripts\Clear-KswordVmCheckpoints.ps1 -Confirm')
        }
        throw
    }
    [void]$record.checkpoints.Add($name)
    Add-Step "checkpoint:$Label" 'OK' $name
    return $name
}

# ---------------------------------------------------------------------------
# hvm_ctl.exe invocation and JSON parsing.
#
# Native exe stdout is swallowed when passing through PowerShell Direct, so redirect within the guest.
# Re-read the file. This is not for safety; directly using `& exe | Out-String` yields an empty string.
# Looks like "command produced no output".
# ---------------------------------------------------------------------------
function Invoke-HvmCtl {
    param([string] $Command, [int] $Arg = 0)

    $raw = Invoke-Guest {
        param($cmdName, $cmdArg)
        $o = 'C:\ksword\hvm_out.txt'
        $e = 'C:\ksword\hvm_err.txt'
        Remove-Item $o, $e -ErrorAction SilentlyContinue
        $argList = @('--json', $cmdName)
        if ($cmdArg -gt 0) { $argList += "$cmdArg" }
        $p = Start-Process -FilePath 'C:\ksword\hvm_ctl.exe' -ArgumentList $argList `
                 -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
        # Use ReadAllText instead of Get-Content -Raw because it **can never return null**:
        #   * `Get-Content -Raw` outputs zero objects when reading a truly empty file;
        #   * `[string]$( zero objects )` evaluates to $null, not '' (verified empirically,
        #     Assuming [string] casting ensures safety is incorrect);
        #   * That $null crossing the PowerShell Direct serialization boundary becomes an **empty**
        #     PSCustomObject** is **true** in `if ($x)` (any non-null object is true).
        #     However, no string method exists; downstream calls to .Trim() will throw.
        #     "does not contain a method named 'Trim'"。
        # Observed this issue twice; the second occurrence happened exactly on the branch where resident returns a non-zero value.
        # The most critical failure response was lost. ReadAllText returns '' for an empty file, breaking the chain at the source.
        $outText = ''
        $errText = ''
        if (Test-Path $o) { $outText = [IO.File]::ReadAllText($o) }
        if (Test-Path $e) { $errText = [IO.File]::ReadAllText($e) }
        [ordered]@{
            Exit = $p.ExitCode
            Out  = $outText
            Err  = $errText
        }
    } -ScriptArgs @($Command, $Arg)

    $stdout = ConvertTo-Text $raw.Out
    $stderr = ConvertTo-Text $raw.Err

    $parsed = $null
    if ($stdout) {
        try { $parsed = $stdout | ConvertFrom-Json } catch { $parsed = $null }
    }
    return [ordered]@{
        Exit   = $raw.Exit
        Json   = $parsed
        Stdout = $stdout
        Stderr = $stderr
    }
}

# Safely convert data returned via PowerShell Direct into a string.
# Reading an empty file returns $null, but after serialization it becomes an empty PSCustomObject — which evaluates to true when non-null.
# However, there are no string methods. Anything used as text must pass through here first.
function ConvertTo-Text {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    $s = "$Value"
    # The stringified result of an empty PSCustomObject is either an empty string or the type name, neither of which represents actual content.
    if ($s -eq '' -or $s -eq 'System.Management.Automation.PSCustomObject') { return '' }
    return $s
}

# Check if the state bit name appears in the status/control result.
function Test-StateBit {
    param($StateNames, [string] $Bit)
    if ($null -eq $StateNames) { return $false }
    return [bool]($StateNames -contains $Bit)
}

$exitCode = 0
try {
    $vm = Get-VM -Name $VMName -ErrorAction Stop
    $nested = (Get-VMProcessor -VMName $VMName).ExposeVirtualizationExtensions
    $record.vm = [ordered]@{
        state = "$($vm.State)"; vcpu = $vm.ProcessorCount; nested = [bool]$nested
    }
    Write-Host ("=== KSword HVM Automation: {0} ===" -f $Stage) -ForegroundColor Cyan
    Write-Host ("VM {0} {1} {2} vCPU nested={3}" -f $vm.Name, $vm.State, $vm.ProcessorCount, $nested)
    Write-Host ("Record -> {0}`n" -f $ResultPath) -ForegroundColor DarkGray

    if ($vm.State -ne 'Running') { throw "Virtual machine is not in Running state ($($vm.State)). Start-VM first." }
    if (-not $nested) { throw 'Nested virtualization is not enabled —— after shutdown, run Set-VMProcessor -ExposeVirtualizationExtensions $true' }

    # ---- Send tool (send every time to ensure running the freshly compiled version) ------------------------
    Invoke-Guest { New-Item -ItemType Directory -Force -Path 'C:\ksword' | Out-Null } | Out-Null
    try {
        Copy-VMFile -Name $VMName -SourcePath $tool -DestinationPath 'C:\ksword\hvm_ctl.exe' `
                    -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    } catch {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($tool))
        Invoke-Guest {
            param($d, $t)
            [IO.File]::WriteAllBytes($t, [Convert]::FromBase64String($d))
        } -ScriptArgs @($b64, 'C:\ksword\hvm_ctl.exe')
    }
    Add-Step 'deploy:hvm_ctl' 'OK' ((Get-Item $tool).Length)

    # ---- Step 1 is always a read-only status --------------------------------------------
    $st = Invoke-HvmCtl 'status'
    if ($st.Exit -ne 0 -or $null -eq $st.Json) {
        Add-Step 'status' 'FAIL' $st.Stderr 'Device query failed - driver may not be loaded'
        $record.verdict = 'BLOCKED'
        [void]$record.notes.Add('hvm_ctl status failed to get result, subsequent operations did not run. First run Deploy-KswordDriverToVm.ps1.')
        $exitCode = 1
        return
    }
    Add-Step 'status' 'OK' $st.Json
    $names = $st.Json.stateNames
    Write-Host ("  Status bits: {0}" -f ($names -join ' ')) -ForegroundColor DarkGray

    if ($Stage -eq 'status') { $record.verdict = 'OK'; return }

    # ---- Single-command mode ------------------------------------------------------
    if ($Stage -in @('stop', 'teardown', 'reset-fault')) {
        $r = Invoke-HvmCtl $Stage
        Add-Step $Stage $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json
        $record.verdict = if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }
        $exitCode = $r.Exit
        return
    }

    # ---- Precondition self-healing: clear FAULTED first; only prepare if not ready ----------------------
    if ((Test-StateBit $names 'FAULTED') -or (Test-StateBit $names 'ROLLBACK_REQUIRED')) {
        $r = Invoke-HvmCtl 'reset-fault'
        Add-Step 'reset-fault' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json `
                 'If the status contains FAULTED/ROLLBACK_REQUIRED, clear it first, otherwise the resident hypervisor will definitely be rejected'
        if ($r.Exit -ne 0) { $record.verdict = 'FAIL'; $exitCode = $r.Exit; return }
        $names = $r.Json.newStateNames
    }

    # Since the backend can only be selected in PREPARE, the choice of 'which backend at this level' determines which prepare verb to use.
    #
    # view-effect requires EPTP switching (it is the only one that truly traverses that exit path at the first level).
    # view-probe requires **private EPT** for a completely different reason: it verifies that the rejection occurs at the specific gate where the rejection happens.
    # When multi-core and private EPT are not armed, the multi-core security gate triggers first and returns the same result as the capability gate.
    # Status code — the probe can only report an empty pass honestly, causing the entire suite to always be marked as PARTIAL.
    $requiredArm =
        switch ($Stage) {
            'view-effect' { @{ Verb = 'prepare-eptpsw';   Feature = 'EPTP_SWITCH_ARMED'; Why = 'EPTP switch backend' } }
            'view-probe'  { @{ Verb = 'prepare-localept'; Feature = 'LOCAL_EPT_ARMED';   Why = 'Per-processor private EPT' } }
            default       { $null }
        }
    $prepareVerb = if ($requiredArm) { $requiredArm.Verb } else { 'prepare' }

    if ((Test-StateBit $names 'RESOURCES_READY') -and $requiredArm) {
        # Already prepared, but possibly with a different backend.
        # Skipping prepare directly causes this level to silently run to completion on the wrong backend and report success.
        # This is the most expensive class of errors on this line. Unpack first, then rebuild with the required backend.
        $armed = Invoke-HvmCtl 'status'
        $isArmed = ($armed.Json.featureNames -contains $requiredArm.Feature)
        if (-not $isArmed) {
            $r = Invoke-HvmCtl 'teardown'
            Add-Step 'teardown' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json `
                     "Prepared but not armed $($requiredArm.Why); remove it first, otherwise this level will be tested on the wrong backend"
            if ($r.Exit -ne 0) { $record.verdict = 'FAIL'; $exitCode = $r.Exit; return }
            $names = @()
        }
    }

    if (Test-StateBit $names 'RESOURCES_READY') {
        Add-Step 'prepare' 'SKIP' $null 'RESOURCES_READY is set; repeating prepare will return ALREADY_PREPARED and set the state to FAULTED'
    } else {
        $r = Invoke-HvmCtl $prepareVerb
        Add-Step $prepareVerb $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json
        if ($r.Exit -ne 0) {
            $record.verdict = 'FAIL'
            [void]$record.notes.Add("prepare returned $($r.Json.statusName) (lastStatus=$($r.Json.lastStatus))")
            $exitCode = $r.Exit
            return
        }
        $names = $r.Json.newStateNames
    }
    if ($Stage -eq 'prepare') { $record.verdict = 'OK'; return }

    # --- Actually enters VMX level: checkpoint -> execute -> liveness confirmation
    $plan = switch ($Stage) {
        'safe'      { @('self-test') }
        'self-test' { @('self-test') }
        # launch-test-guest is the missing tier between self-test and resident:
        # self-test only performs VMXON/VMXOFF; it does not write VMCS, install EPTP, or execute VMLAUNCH.
        # This level actually writes VMCS, actually installs EPTP, and actually performs VMLAUNCH into a guest that only executes VMCALL.
        # guest, the blast radius is a 4KiB guest stack. It answers whether L0 recognizes us.
        # VMCS construction, which is a part never touched by self-test.
        'launch-guest' { @('self-test', 'launch-test-guest') }
        'resident'  { @('self-test', 'resident', 'stop') }
        # Platform probes are purely read-only: they do not enter VMX, modify any execution paths, allocate resources, or acquire locks.
        # Thus, it is neither added to the risky list nor requires a self-test to precede it.
        'probe-platform' { @('probe-platform') }
        # Negative probes require a self-test.
        #
        # Driver pre-checks (RESOURCES_READY | EPT_READY | SELF_TEST_PASSED all present)
        # Placed **before all capability gates**: if not complete, return NOT_PREPARED immediately. At that point, whether the capability gate exists
        # Allowing this issue to go unasked results in the test case being **skipped** entirely — reporting success without performing any checks.
        # Therefore, the order is not optional; it determines whether this group of tests can obtain results.
        'probe-flags' { @('self-test', 'probe-flags') }
        # The probe manages its own resident start/stop; do not start it on its behalf here.
        # This follows a strict driver invariant: the rule table is immutable during resident operation because the exit path scans it without a lock,
        # Therefore, the order must be: install rules → start resident → read → stop resident → clear rules.
        # That page belongs to the tool process and must remain alive until the resident hypervisor starts, so the entire operation must stay in one process.
        'probe-xonly' { @('self-test', 'probe-xonly') }
        # View installation attribution probe: sends VIEW_OP_ADD only once; it is installed and immediately uninstalled.
        # It does not require self-test (does not enter VMX), but requires EPT_READY, which is provided by the preceding step:
        # prepare guarantee; the self-test is only included to maintain consistency with prerequisites of other probes.
        'view-probe'  { @('self-test', 'view-probe') }
        # End-to-end validity criteria. The probe **itself** manages resident start/stop — for the same reason as probe-xonly:
        # The view table cannot change during resident operation, so the order must be: install view -> start resident mode -> read -> stop -> uninstall view,
        # That page belongs to the tool process and must remain alive until the resident hypervisor starts, so the entire operation must stay in one process.
        'view-effect' { @('self-test', 'view-effect') }
        # Nested end-to-end test. It must start the resident hypervisor itself **with the nested-dispatch bit set**, so use
        # resident-nested instead of resident — the latter's resident VMX instructions are still trapped.
        # #UD: the probe will stop at the VMXON step.
        #
        # The L2 probe program consists of two RDMSR instructions: the first is cleared in L1's bitmap and must be allowed; the second
        # Must exit. The criterion is in hvm_ctl (reason 31, stopped at +12, dispatched to L1), and the consequence of failing to roll back is L1 reading stale data.
        # Here we only check its exit code. The cleanup stop cannot be omitted: the resident process will outlive the one that launched it.
        # nested-ad verifies accessed/dirty: L1 requests it via the EPT12 pointer, which must be accepted.
        # When truly maintaining state and returning to L1's own tables upon pausing at L2, the consequence of failing to return is that L1 reads back
        # All zeros; jump to the pages the guest actually wrote to—no reads on that path will change.
        # Only this test case is visible.
        # nested-selfvirt-all follows nested-probe-all: the former verifies that we can host a hypervisor that performs the same actions as ourselves.
        # A self-written L1"; the latter verifies that we can host something that does the same thing we do.
        # hypervisor: Captures state, redirects guest RIP to its own next instruction, and executes VMLAUNCH.
        # It becomes its own guest and repeatedly enters and exits through VMRESUME. A real hypervisor
        # This is what our resident path and VMware's VMM do: treat segments, CR3, and page tables with full seriousness.
        'nested'    { @('self-test', 'resident-nested', 'nested-probe-all',
                        'nested-selfvirt-all', 'nested-ad', 'stop') }
        'soak'      { @('self-test', 'soak') }
        'full'      { @('self-test', 'soak', 'stop', 'teardown') }
        default     { @() }
    }

    # Only increment, never decrement: if any step is skipped, set to true; at the end, use this to mark this section as PARTIAL instead of OK.
    $anyBlocked = $false
    # Similarly, it only increases and never decreases, but the meaning differs: this machine cannot query it, so there is nothing to fix.
    $anyNotApplicable = $false

    foreach ($step in $plan) {
        # probe-xonly starts a resident instance itself, so it is as dangerous as resident/soak.
        # A checkpoint must be taken first.
        # probe-flags is also risky: its use cases 2/3 send START_RESIDENT with FORCE.
        # If the target machine supports #VE, that path **actually starts the resident hypervisor**, but the tool has no matching
        # Note: Taking a checkpoint on this path is the cheapest insurance.
        # view-effect spawns its own resident thread and **forces an actual EPT access**.
        # This is the only level-one case on this path that triggers an EPTP switch exit, so a checkpoint is mandatory.
        # view-probe only sends requests and does not enter VMX, so it is not considered risky.
        # resident-nested is as dangerous as resident, and even more so: its resident mode allows the guest to...
        # Executes VMX instructions, causing the probe to enter and exit L2 once.
        $risky = $step -in @('self-test', 'launch-test-guest', 'resident',
                             'resident-nested', 'nested-probe-all',
                             'nested-selfvirt-all', 'nested-ad',
                             'soak', 'probe-flags', 'probe-xonly', 'view-effect')
        $snap = $null
        $bootBefore = $null
        if ($risky) {
            $snap = New-Guard $step
            # Record boot time for later comparison — 'responsive' does not equal 'never crashed'.
            $bootBefore = Get-GuestBootTime
        }

        $arg = if ($step -eq 'soak') { $SoakMs } else { 0 }
        $r = Invoke-HvmCtl $step $arg

        if ($risky) {
            if (Test-GuestAlive) {
                $crash = Get-GuestCrashEvidence $bootBefore
                if ($crash) {
                    Add-Step "alive:$step" 'FAIL' $null $crash
                    $record.verdict = 'FAIL'
                    [void]$record.notes.Add($crash)
                    [void]$record.notes.Add("Dump forensics: .\scripts\Get-KswordVmBugcheck.ps1")
                    [void]$record.notes.Add("Rollback: Restore-VMCheckpoint -VMName '$VMName' -Name '$snap' -Confirm:`$false")
                    $exitCode = 1
                    return
                }
                Add-Step "alive:$step" 'OK' $null 'The virtual machine is still responsive and has not been restarted'
            } else {
                Add-Step "alive:$step" 'FAIL' "$((Get-VM -Name $VMName).State)" 'Virtual machine disconnected, likely blue screen'
                $record.verdict = 'FAIL'
                [void]$record.notes.Add("Lost response at $step stage. Rollback: Restore-VMCheckpoint -VMName '$VMName' -Name '$snap' -Confirm:`$false")
                [void]$record.notes.Add('Dump should be in guest C:\Windows\MEMORY.DMP (kernel dump was enabled in advance by deployment script)')
                $exitCode = 1
                return
            }
        }

        if ($r.Exit -eq 0) {
            Add-Step $step 'OK' $r.Json
        } elseif ($r.Exit -eq 4) {
            # Exit code 4 = **this machine cannot query this issue**, which is distinct from 3.
            #
            # 3 means 'not ready this time': there is something to fix; without fixing it, the test won't detect it, so the entire segment must be deferred.
            # Check for PARTIAL until someone fixes it. 4 means "nothing to fix"—the capability required by the check is not available on this
            # Hardware does not provide it (e.g., nested guests lacking the Monitor Trap Flag), private
            # EPT can never be armed; multi-core safety gates will trigger first).
            #
            # Treating case 4 as BLOCKED would cause the suite to always be marked PARTIAL for this entire class of machines.
            # And a report that never turns green is equivalent to no report: the extra line added when a real issue occurs next time
            # No one will look at it again. So we record NOT_APPLICABLE, add it to notes, and do NOT set
            # anyBlocked。
            Add-Step $step 'NOT_APPLICABLE' $r.Json `
                'This machine cannot answer this question: the hardware capability required by the criterion does not exist, and it is not that it is not ready this time'
            [void]$record.notes.Add("$step Not applicable on local machine — the capabilities required by the criteria are not provided by this hardware.")
            # Propagate up; do not let this segment print as PASS.
            #
            # Do not set anyBlocked (it should not drag the overall verdict to PARTIAL), but absolutely must not allow
            # verdict is OK — this item **detected nothing**, so printing it as passed is the repository's standard.
            # Note: The recurring pitfall is interpreting 'ran without crashing' as 'detected something'.
            $anyNotApplicable = $true
        } elseif ($r.Exit -eq 3) {
            # Exit code 3 = probe 'completed but detected nothing' — prerequisites not established or calibration incomplete.
            # It is neither pass nor fail: mark as BLOCKED and continue, but **do not** interpret it as a pass.
            Add-Step $step 'BLOCKED' $r.Json `
                'Probe skipped: completed but lacks discriminative power (prerequisites not established or calibration incomplete), does not count as passed'
            [void]$record.notes.Add("$step Skipped -- This item did not test anything this time.")
            # Record this in a **sticky** flag that can be set but never cleared; do not change verdict here.
            #
            # The previous version used `if ($record.verdict -eq 'OK') { ... = 'PARTIAL' }`,
            # At this moment, the verdict is still the initial value 'NOT_RUN' (line 99), **that condition never holds**;
            # Immediately after, the plan loop unconditionally writes 'OK', so BLOCKED is silently upgraded to PASS.
            # Measured on 2026-09-07: On a 2 vCPU configuration, the multicore gate prevents view-effect from installing a view; the tool accurately
            # Report "unable to detect if effective" and exit with code 3, yet the suite prints this section as [PASS].
            $anyBlocked = $true
        } else {
            # Log the response first before doing anything else. The previous version formatted the note here first,
            # After Add-Step, when result formatting throws an exception, the entire failure response is lost.
            # However, the response upon failure is the only valuable piece of information.
            $sn = if ($r.Json) { "$($r.Json.statusName)" } else { 'NO_JSON' }
            # Record capability missing and code failure separately: the former is BLOCKED, the latter is FAIL.
            $blockedStatuses = @('UNSUPPORTED_CPU', 'FIRMWARE_DISABLED', 'HYPERVISOR_CONFLICT',
                                 'NESTED_UNSUPPORTED', 'EVMCS_UNSUPPORTED', 'PARTIAL_IMPLEMENTATION')
            $outcome = if ($blockedStatuses -contains $sn) { 'BLOCKED' } else { 'FAIL' }
            $note = (ConvertTo-Text $r.Stderr).Trim()
            Add-Step $step $outcome $r.Json $note
            $record.verdict = $outcome
            $ls = if ($r.Json) { "$($r.Json.lastStatus)" } else { '?' }
            [void]$record.notes.Add("$step returns $sn (lastStatus=$ls); subsequent levels will not be executed.")

            # LIFECYCLE_GUARD_FAILED indicates a failure of KswordARKHvmArmUnloadGuard.
            # Among its three failure branches, the only one not yet excluded compares
            # DriverObject->DriverUnload compared to the original value captured at registration. Thus, here we directly...
            # Read back the driver's own DriverObject — the current value being 0 settles the matter immediately.
            # No longer need to infer.
            if ($sn -eq 'LIFECYCLE_GUARD_FAILED') {
                try {
                    $doRaw = Invoke-Guest {
                        $o = 'C:\ksword\drvobj.txt'
                        Remove-Item $o -ErrorAction SilentlyContinue
                        if (-not (Test-Path 'C:\ksword\KswordCLI.exe')) { return '' }
                        $p = Start-Process -FilePath 'C:\ksword\KswordCLI.exe' `
                                 -ArgumentList @('kernel', 'query-driver-object', '--driver', 'KswordARK') `
                                 -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o `
                                 -RedirectStandardError 'C:\ksword\drvobj_err.txt'
                        if (Test-Path $o) { [IO.File]::ReadAllText($o) } else { "(No output, exit code $($p.ExitCode))" }
                    }
                    $doText = ConvertTo-Text $doRaw
                    if ($doText) {
                        $record.driverObject = $doText
                        Write-Host "`n--- KswordARK's DriverObject (current value)---" -ForegroundColor Cyan
                        Write-Host $doText
                        $unload = ([regex]::Match($doText, 'driverUnload=(0x[0-9A-Fa-f]+)')).Groups[1].Value
                        if ($unload) {
                            [void]$record.notes.Add("Current DriverObject->DriverUnload = $unload (a non-0 value was captured during registration; otherwise EnableResidentLifecycle would return early)")
                        }
                    }
                } catch { [void]$record.notes.Add('DriverObject query failed') }
            }
            if ($r.Stdout) { [void]$record.notes.Add("Original stdout: $((ConvertTo-Text $r.Stdout).Trim())") }
            $exitCode = $r.Exit
            return
        }
    }

    # If any step is skipped, this segment is not OK.
    # 「Finished without crashing」and「Found something」are two different things; printing the former as the latter is exactly the shape of repeated losses in this repository.
    #
    # Three states, not two: PARTIAL means "there is something to fix", NOT_APPLICABLE means "this machine is not applicable"
    # No output or nothing to fix. Neither is OK, but only the former should prompt manual intervention.
    if ($anyBlocked) {
        $record.verdict = 'PARTIAL'
    } elseif ($anyNotApplicable) {
        $record.verdict = 'NOT_APPLICABLE'
        $exitCode = 4
    } else {
        $record.verdict = 'OK'
    }
}
catch {
    $record.verdict = 'ERROR'
    [void]$record.notes.Add("Script exception: $($_.Exception.Message)")
    Write-Host "`nScript exception: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
finally {
    # Regardless of how the exit occurs, read and persist the final state once — this record is especially critical when an exception occurs mid-process.
    # Before cleanup, ensure the resident hypervisor will not be left running.
    #
    # A resident component survives the process that launched it (by design and verified), so a failed plan mid-execution
    # Returning directly leaves the resident component lingering; the next deployment will encounter a highly misleading issue.
    # Error: CPUID does not show VMX — because our CPUID handler intentionally clears that bit by design.
    # The error points to 'nested virtualization not enabled', but the actual cause is leftover state from the previous round. Learned this the hard way.
    try {
        $pre = Invoke-HvmCtl 'status'
        if ($pre.Json -and $pre.Json.residentProcessorCount -gt 0) {
            Write-Host "`nCleanup: resident hypervisor still running (residentProcessorCount=$($pre.Json.residentProcessorCount)), stopping it" -ForegroundColor Yellow
            $cleanup = Invoke-HvmCtl 'stop'
            Add-Step 'cleanup:stop' $(if ($cleanup.Exit -eq 0) { 'OK' } else { 'FAIL' }) $cleanup.Json `
                'Exit before reaching stop in the plan, perform a backup here'
        }
    } catch { [void]$record.notes.Add('Final shutdown check failed (virtual machine may be disconnected)') }

    try {
        $final = Invoke-HvmCtl 'status'
        if ($final.Json) {
            $record.finalStatus = $final.Json
            # Exit telemetry is printed directly to the console. This is currently the only exit observation surface that does not go through the serial port:
            # The kernel debugger's reporting channel is itself port I/O, which is precisely the phenomenon under investigation.
            $j = $final.Json
            if ($null -ne $j.vmExitCount) {
                Write-Host ""
                Write-Host "--- Exit Telemetry ---" -ForegroundColor Cyan
                Write-Host ("  count={0}  reason={1}  instrLen={2}" -f
                    $j.vmExitCount, $j.lastExitReason, $j.lastExitInstructionLength)
                Write-Host ("  qualification={0}  guestRip={1}  guestRsp={2}" -f
                    $j.lastExitQualification, $j.lastGuestRip, $j.lastGuestRsp)
                if ($j.lastExitReason -eq 30) {
                    # SDM Table 28-5: bits31:16 port number, bit3 direction (1=IN), bits2:0 width.
                    $qs = "$($j.lastExitQualification)"
                    if ($qs.StartsWith('0x')) { $qs = $qs.Substring(2) }
                    $q = [Convert]::ToUInt64($qs, 16)
                    $port = [int](($q -shr 16) -band 0xFFFF)
                    $dir  = if ((($q -shr 3) -band 1) -eq 1) { 'IN' } else { 'OUT' }
                    $size = @(1,2,0,4,0,0,0,0)[[int]($q -band 0x7)]
                    Write-Host ("  >>> I/O Exit: {0} port 0x{1:X4} ({1}) {2} bytes" -f
                        $dir, $port, $size) -ForegroundColor Green
                }
            }
        }
        # Driver event loop.
        #
        # This section previously referenced an **uninitialized** $ev, so driverEvents is never written to.
        # Looks like forensic code but is actually dead code. Now actually performing the collection.
        # The event ring showed 97% loss in measurements: every exit emits an event unconditionally, but the ring has only 1024 slots,
        # Therefore, it can only serve as supplementary evidence, not as a criterion.
        $ev = Invoke-Guest {
            $o = 'C:\ksword\hvm_events.txt'
            Remove-Item $o -ErrorAction SilentlyContinue
            if (-not (Test-Path 'C:\ksword\KswordCLI.exe')) { return '' }
            $p = Start-Process -FilePath 'C:\ksword\KswordCLI.exe' `
                     -ArgumentList @('r0', 'hvm-events', '--max-rows', '64') `
                     -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o `
                     -RedirectStandardError 'C:\ksword\hvm_events_err.txt'
            if (Test-Path $o) { [IO.File]::ReadAllText($o) }
            else { "(No output, exit code $($p.ExitCode))" }
        }
        $evText = ConvertTo-Text $ev
        if ($evText) {
            $record.driverEvents = $evText
            if ($record.verdict -ne 'OK') {
                Write-Host "`n--- Driver Event Ring (high packet loss, for clues only)---" -ForegroundColor Cyan
                Write-Host $evText
            }
        }
    } catch { [void]$record.notes.Add('Event ring query failed') }

    try { $record.checkpointsNow = @(Get-VMSnapshot -VMName $VMName | ForEach-Object { $_.Name }) } catch { }

    # Skipped tests must have their own exit code.
    #
    # Otherwise, the caller (unattended suite) sees 0 and records PASS, while that item actually tested nothing.
    # This is the most expensive class of error on this line: a report that looks entirely green.
    if ($record.verdict -eq 'PARTIAL' -and $exitCode -eq 0) { $exitCode = 3 }

    Save-Record
    Write-Host ("`nVerdict: {0}" -f $record.verdict) -ForegroundColor $(
        switch ($record.verdict) { 'OK' { 'Green' } 'PARTIAL' { 'Yellow' } 'BLOCKED' { 'Yellow' } default { 'Red' } })
    foreach ($n in $record.notes) { Write-Host "  · $n" -ForegroundColor Yellow }
    Write-Host ("Record written to {0}" -f $ResultPath) -ForegroundColor Cyan

    # Placing exit in finally: a return in the try block will terminate the script directly, so writing it after finally is ineffective.
    # The statement will never execute, causing the exit code to always be 0, which would make CI treat failures as successes.
    exit $exitCode
}
