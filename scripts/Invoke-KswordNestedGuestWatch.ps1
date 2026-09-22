<#
.SYNOPSIS
    Launch a resident with nested dispatch in the test machine to capture a baseline. Then, when you create a virtual
    machine using a **third-party hypervisor** inside the guest, output the difference between the two status snapshots.

.DESCRIPTION
    Must run as Administrator on the host.

    This script solves a very specific problem: while `hvm_ctl status` already provides the evidence,
    it outputs over thirty fields plus an exit histogram. However, the question 'Is a third-party
    hypervisor running beneath us?' only cares about the deltas of **nine exit reasons** and **three
    **counters**. Comparing two massive output blocks by eye is slow and prone to missing details.

    Reading method (the numbers below correspond to KSW_VMX_EXIT_* in hvm_nested.c):

      27 VMXON: Whether the other side actually uses VT-x. **Zero is zero**,
                   meaning it never reached this path—either it used a different backend (such
                   as Hyper-V platform APIs) or it errored out and exited earlier. In this case,
                   checking our counters is meaningless; first, examine the other side's logs.
      21 VMPTRLD loaded several vmcs12 structures. At least one per vCPU per virtual machine.
      23/25 VMREAD/VMWRITE
                   Note: It configures VMCS. A large count is normal (hundreds to thousands); the **distribution** is
                   more useful than the total: VMWRITE without VMLAUNCH indicates an abandoned configuration halfway.
      20/24 VMLAUNCH/VMRESUME
                   Actual number of entry attempts.
      26 VMXOFF: The peer actively exited VMX — typically indicating it has given up.

    Combined with three counters:

      nestedL2LaunchRefusedCount: The number of times we **refused** entry.
                                   Successful entry count = (20 + 24 increment) - (this increment).
                                   The driver lacks a global counter for "successfully entered" states, so this calculation
                                   is used; thus, the reported value is an **inferred estimate, not a direct reading**.
      nestedVmcs12EvictionCount: Number of vmcs12 pool evictions. It should increase only
                                   when the peer vCPU count exceeds the pool depth (8); any other increase is anomalous.
      nestedFuseTripCount: Fuse trip; repeated exits at the same RIP without progress.
                                   Non-zero indicates we have stalled an L2 guest in place.

    There is also lastVmInstructionError. When VMLAUNCH/VMRESUME
    fails, it is the **only** field indicating the reason for failure.

.PARAMETER WaitSeconds
    Observation window after the baseline. The status is sampled every PollSeconds seconds and stored in the
    record, so if the guest BSODs or hangs mid-process, **the last successful sample serves as the crash dump**.
    Press any key in an interactive console to exit the window early.

.PARAMETER Mode
    nested = start resident-nested (default); hidehv =
    start resident-nested-hidehv: additionally hide the
              hypervisor identity from the guest's user-mode CPUID.

    The first blocking reading observed on the physical machine is not a capability check but an identity check: VMware
    Workstation 17.6 uses CPUID to detect that the outer layer is Hyper-V and requests WHP; if WHP is unavailable, it
    refuses to start any VM before loading them ([msg.vmx.nestedHyperV]). hidehv addresses exactly this issue.

    Two resident instances in different modes cannot be distinguished by status flags. Therefore, the rule here is: if the resident is
    already running and you specify a mode, stop it first and then restart it in the requested mode — better to stop once extra than to
    have a measurement complete in a mode different from what you assumed and report success. Use -SkipBringUp to disable this behavior.

.PARAMETER SkipBringUp
    Do not touch lifecycle; only collect baseline + observation + delta. Use this when already running.

.PARAMETER StopWhenDone
    Stop the resident hypervisor after observation ends. By default, **leave it running** so observation can continue.

.PARAMETER SelfTest
    Do not connect to the VM; iterate through the combined status of the two groups to check differences and interpretations, confirming this logic itself is correct.
    It executes after the observation window; if it crashes during actual execution, the wait is wasted, so verify offline first.

.EXAMPLE
    .\Invoke-KswordNestedGuestWatch.ps1 -SelfTest
    .\Invoke-KswordNestedGuestWatch.ps1
    .\Invoke-KswordNestedGuestWatch.ps1 -WaitSeconds 600 -StopWhenDone
#>
[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [ValidateSet('nested','hidehv')]
    [string] $Mode          = 'nested',
    [int]    $WaitSeconds   = 300,
    [int]    $PollSeconds   = 10,
    [string] $ResultPath,
    [switch] $SkipBringUp,
    [switch] $StopWhenDone,
    [switch] $SelfTest
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path $PSScriptRoot -Parent
$tool = Join-Path $repo 'tools\hvm_ctl\hvm_ctl.exe'

if (-not $ResultPath) {
    $logDir = Join-Path $repo 'docs\next\logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
    $ResultPath = Join-Path $logDir ('hvm-guestwatch-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
}

$record = [ordered]@{
    schema     = 'ksword.hvm.guestwatch/1'
    startedUtc = (Get-Date).ToUniversalTime().ToString('o')
    vmName     = $VMName
    steps      = New-Object System.Collections.ArrayList
    samples    = New-Object System.Collections.ArrayList
    baseline   = $null
    final      = $null
    delta      = $null
    verdict    = 'NOT_RUN'
    notes      = New-Object System.Collections.ArrayList
}

function Add-Step {
    param([string] $Name, [string] $Outcome, $Data, [string] $Note)
    $entry = [ordered]@{
        name = $Name; utc = (Get-Date).ToUniversalTime().ToString('o'); outcome = $Outcome
    }
    if ($null -ne $Data) { $entry.data = $Data }
    if ($Note)           { $entry.note = $Note }
    [void]$record.steps.Add($entry)
    $color = switch ($Outcome) { 'OK' { 'Green' } 'SKIP' { 'DarkGray' } 'BLOCKED' { 'Yellow' } default { 'Red' } }
    Write-Host ("  [{0,-7}] {1}{2}" -f $Outcome, $Name, $(if ($Note) { "  — $Note" })) -ForegroundColor $color
}

function Save-Record {
    $record.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
    [IO.File]::WriteAllText(
        $ResultPath,
        ($record | ConvertTo-Json -Depth 12),
        (New-Object Text.UTF8Encoding($false)))
}

function Invoke-Guest {
    param([scriptblock] $Script, [object[]] $ScriptArgs)
    if ($null -eq $ScriptArgs -or $ScriptArgs.Count -eq 0) {
        Invoke-Command -VMName $VMName -Credential $script:cred -ScriptBlock $Script
    } else {
        Invoke-Command -VMName $VMName -Credential $script:cred -ScriptBlock $Script -ArgumentList $ScriptArgs
    }
}

# Reading an empty file returns $null, which becomes an **empty** string when crossing the PowerShell Direct serialization boundary.
# PSCustomObject** — it evaluates to true in the if condition but has no string methods. All objects used as text pass through here first.
function ConvertTo-Text {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    $s = "$Value"
    if ($s -eq '' -or $s -eq 'System.Management.Automation.PSCustomObject') { return '' }
    return $s
}

function Invoke-HvmCtl {
    param([string] $Command)
    $raw = Invoke-Guest {
        param($cmdName)
        $o = 'C:\ksword\hvm_out.txt'
        $e = 'C:\ksword\hvm_err.txt'
        Remove-Item $o, $e -ErrorAction SilentlyContinue
        $p = Start-Process -FilePath 'C:\ksword\hvm_ctl.exe' -ArgumentList @('--json', $cmdName) `
                 -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
        $outText = ''
        $errText = ''
        if (Test-Path $o) { $outText = [IO.File]::ReadAllText($o) }
        if (Test-Path $e) { $errText = [IO.File]::ReadAllText($e) }
        [ordered]@{ Exit = $p.ExitCode; Out = $outText; Err = $errText }
    } -ScriptArgs @($Command)

    $stdout = ConvertTo-Text $raw.Out
    $parsed = $null
    if ($stdout) { try { $parsed = $stdout | ConvertFrom-Json } catch { $parsed = $null } }
    return [ordered]@{ Exit = $raw.Exit; Json = $parsed; Stdout = $stdout; Stderr = (ConvertTo-Text $raw.Err) }
}

function Test-StateBit {
    param($StateNames, [string] $Bit)
    if ($null -eq $StateNames) { return $false }
    return [bool]($StateNames -contains $Bit)
}

function Get-GuestBootTime {
    try {
        $t = Invoke-Command -VMName $VMName -Credential $script:cred -ErrorAction Stop `
                 -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
        return [datetime]$t
    } catch { return $null }
}

# ---------------------------------------------------------------------------
# Exit reason
# ---------------------------------------------------------------------------
# ID to name mapping. Must align with ExitReasonName in tools\hvm_ctl\hvm_ctl.c and hvm_nested.c.
# KSW_VMX_EXIT_* are the same set; only listing those relevant on this line. Any change here must be synchronized across all three sides.
$reasonNames = @{
    0='EXCEPTION_OR_NMI'; 1='EXTERNAL_INTERRUPT'; 2='TRIPLE_FAULT'; 7='INTERRUPT_WINDOW'
    9='TASK_SWITCH'; 10='CPUID'; 12='HLT'; 13='INVD'; 14='INVLPG'; 15='RDPMC'; 16='RDTSC'
    18='VMCALL'; 19='VMCLEAR'; 20='VMLAUNCH'; 21='VMPTRLD'; 22='VMPTRST'; 23='VMREAD'
    24='VMRESUME'; 25='VMWRITE'; 26='VMXOFF'; 27='VMXON'; 28='MOV_CR'; 29='MOV_DR'
    30='IO_INSTRUCTION'; 31='RDMSR'; 32='WRMSR'; 33='VM_ENTRY_FAILURE_GUEST_STATE'
    34='VM_ENTRY_FAILURE_MSR_LOADING'; 37='MONITOR_TRAP_FLAG'; 48='EPT_VIOLATION'
    49='EPT_MISCONFIGURATION'; 50='INVEPT'; 51='RDTSCP'; 52='VMX_PREEMPTION_TIMER'
    53='INVVPID'; 54='WBINVD'; 55='XSETBV'; 58='INVPCID'; 59='VMFUNC'
}
# The family of reasons that only appears when another hypervisor is running beneath us.
$vmxReasons = @(19, 20, 21, 22, 23, 24, 25, 26, 27, 50, 53)

function Get-ReasonName {
    param([int] $Reason)
    if ($reasonNames.ContainsKey($Reason)) { return $reasonNames[$Reason] }
    return 'See SDM Appendix C'
}

# exitReasonCount: Only emit non-zero items; keys are stringified reason IDs. Missing key = zero.
function Get-ReasonMap {
    param($Json)
    $map = @{}
    if ($null -eq $Json -or $null -eq $Json.exitReasonCount) { return $map }
    foreach ($p in $Json.exitReasonCount.PSObject.Properties) {
        $map[[int]$p.Name] = [uint64]$p.Value
    }
    return $map
}

function Get-ReasonDelta {
    param($Before, $After, [int] $Reason)
    $b = 0; $a = 0
    if ($Before.ContainsKey($Reason)) { $b = $Before[$Reason] }
    if ($After.ContainsKey($Reason))  { $a = $After[$Reason] }
    return [int64]$a - [int64]$b
}

# ---------------------------------------------------------------------------
# Difference calculation and interpretation. The function is extracted for two reasons: it is the only part of the entire flow involving arithmetic, and it is only called
# This runs only after the observation window ends. If a crash occurs during actual execution, waiting becomes futile, so offline verification is required.
# ---------------------------------------------------------------------------
function Show-Delta {
    param($Base, $Final)

    $bMap = Get-ReasonMap $Base
    $fMap = Get-ReasonMap $Final

    $d = [ordered]@{
        vmExitCount = [int64]$Final.vmExitCount - [int64]$Base.vmExitCount
        refused     = [int64]$Final.nestedL2LaunchRefusedCount - [int64]$Base.nestedL2LaunchRefusedCount
        evicted     = [int64]$Final.nestedVmcs12EvictionCount - [int64]$Base.nestedVmcs12EvictionCount
        fuseTrips   = [int64]$Final.nestedFuseTripCount - [int64]$Base.nestedFuseTripCount
        lastVmInstructionError = $Final.lastVmInstructionError
        reasons     = [ordered]@{}
        verdict     = 'NOT_RUN'
    }
    foreach ($r in (@($bMap.Keys) + @($fMap.Keys) | Sort-Object -Unique)) {
        $delta = Get-ReasonDelta $bMap $fMap ([int]$r)
        if ($delta -ne 0) { $d.reasons["$r"] = $delta }
    }

    $vmxon   = Get-ReasonDelta $bMap $fMap 27
    $vmptrld = Get-ReasonDelta $bMap $fMap 21
    $vmwrite = Get-ReasonDelta $bMap $fMap 25
    $vmread  = Get-ReasonDelta $bMap $fMap 23
    $vmxoff  = Get-ReasonDelta $bMap $fMap 26
    $entries = (Get-ReasonDelta $bMap $fMap 20) + (Get-ReasonDelta $bMap $fMap 24)

    Write-Host ''
    Write-Host '=== Difference ===' -ForegroundColor Cyan
    Write-Host ("  Total Exit      : +{0}" -f $d.vmExitCount)
    Write-Host ("  Refuse L2 start: +{0}" -f $d.refused)   -ForegroundColor $(if ($d.refused   -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Host ("  vmcs12  eviction : +{0}" -f $d.evicted)   -ForegroundColor $(if ($d.evicted   -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Host ("  Fuse Trip Count : +{0}" -f $d.fuseTrips) -ForegroundColor $(if ($d.fuseTrips -gt 0) { 'Red'    } else { 'Gray' })
    Write-Host ("  Last instruction error: {0}" -f $d.lastVmInstructionError)

    Write-Host ''
    Write-Host '  --- VMX instruction class exit (only occurs if another hypervisor is running beneath us) ---'
    $anyVmx = $false
    foreach ($r in $vmxReasons) {
        $delta = Get-ReasonDelta $bMap $fMap $r
        if ($delta -eq 0) { continue }
        $anyVmx = $true
        Write-Host ("    +{0,-10} reason={1,-3} {2}" -f $delta, $r, (Get-ReasonName $r)) -ForegroundColor Green
    }
    if (-not $anyVmx) { Write-Host '    None found' -ForegroundColor DarkGray }

    Write-Host ''
    Write-Host '  --- Incremental for other exit reasons ---'
    # Materialize objects with real properties first, then sort. When Sort-Object uses a script block to retrieve keys, the keys must be comparable.
    # Items that are **silently kept in original order** and returned as-is appear sorted but are not.
    $others = @()
    foreach ($k in $d.reasons.Keys) {
        if ([int]$k -in $vmxReasons) { continue }
        $others += [pscustomobject]@{
            Reason = [int]$k; Delta = [int64]$d.reasons[$k]; Name = (Get-ReasonName ([int]$k))
        }
    }
    if ($others.Count -eq 0) {
        Write-Host '    <No changes>' -ForegroundColor DarkGray
    } else {
        foreach ($o in ($others | Sort-Object -Property Delta -Descending)) {
            Write-Host ("    +{0,-10} reason={1,-3} {2}" -f $o.Delta, $o.Reason, $o.Name)
        }
    }

    Write-Host ''
    Write-Host '=== Judgment ===' -ForegroundColor Cyan
    if ($vmxon -eq 0) {
        $d.verdict = 'NO_VMXON'
        Write-Host '  VMXON increment is 0 —— the hypervisor inside the guest **did not take the VT-x path**.' -ForegroundColor Yellow
        Write-Host '  There are no readable values on our side. First confirm if it is truly started,' -ForegroundColor Yellow
        Write-Host '  And which backend it selected (if using the Hyper-V platform API, VMX instructions are never touched).' -ForegroundColor Yellow
    } elseif ($entries -eq 0) {
        $d.verdict = 'VMXON_BUT_NO_ENTRY'
        Write-Host ("  VMXON +{0}, VMPTRLD +{1}, VMWRITE +{2}, VMREAD +{3}, but **no single entry attempt**." -f `
            $vmxon, $vmptrld, $vmwrite, $vmread) -ForegroundColor Yellow
        Write-Host '  It entered VMX, started configuring VMCS, then gave up. Most likely we didn''t permit some capability bit ——' -ForegroundColor Yellow
        Write-Host '  If the nested hypervisor reads capability MSRs and finds a missing feature, it exits on its own. Inspect the capability allowlist next.' -ForegroundColor Yellow
    } elseif ($d.refused -ge $entries) {
        $d.verdict = 'ALL_ENTRIES_REFUSED'
        Write-Host ("  Attempting {0} times, we rejected {1} times — **All rejected**." -f $entries, $d.refused) -ForegroundColor Red
        Write-Host ("  Last instruction error {0}. Rejection reason is in the driver's L2 startup validation." -f $d.lastVmInstructionError) -ForegroundColor Red
    } else {
        $d.verdict = 'L2_ENTERED'
        Write-Host ("  Attempting {0} times, rejected {1} times ⇒ **Calculated successful entry {2} times**." -f `
            $entries, $d.refused, ($entries - $d.refused)) -ForegroundColor Green
        Write-Host '  (There is no global counter for "successfully entered" in the driver; this is derived by subtraction, not a direct read.)' -ForegroundColor DarkGray
        if ($d.fuseTrips -gt 0) {
            $d.verdict = 'L2_ENTERED_BUT_STUCK'
            Write-Host ("  But fuse trip +{0} — L2 is stuck at the same RIP and not advancing." -f $d.fuseTrips) -ForegroundColor Red
        }
        if ($vmxoff -gt 0) {
            Write-Host ("  VMXOFF +{0} --- The peer voluntarily exited VMX." -f $vmxoff) -ForegroundColor Yellow
        }
    }
    return $d
}

# ---------------------------------------------------------------------------
# Offline self-check: Synthesize four typical scenarios to verify that difference arithmetic and judgment branches are correct.
# ---------------------------------------------------------------------------
function New-FakeStatus {
    param([hashtable] $Reasons, [int] $Refused = 0, [int] $Evicted = 0, [int] $Fuse = 0,
          [int] $Exits = 0, [int] $LastErr = 0)
    $rc = [pscustomobject]@{}
    foreach ($k in $Reasons.Keys) { $rc | Add-Member -NotePropertyName "$k" -NotePropertyValue $Reasons[$k] }
    return [pscustomobject]@{
        generation                 = 1
        vmExitCount                = $Exits
        nestedL2LaunchRefusedCount = $Refused
        nestedVmcs12EvictionCount  = $Evicted
        nestedFuseTripCount        = $Fuse
        lastVmInstructionError     = $LastErr
        exitReasonCount            = $rc
    }
}

function Invoke-SelfTest {
    $cases = @(
        @{ Name='VT-x not touched';       Expect='NO_VMXON'
           B=(New-FakeStatus @{10=100; 31=50} 0 0 0 1000)
           F=(New-FakeStatus @{10=400; 31=90} 0 0 0 4000) }
        @{ Name='Entered VMX but not L2'; Expect='VMXON_BUT_NO_ENTRY'
           B=(New-FakeStatus @{10=100} 0 0 0 1000)
           F=(New-FakeStatus @{10=120; 27=1; 21=2; 25=900; 23=300; 26=1} 0 0 0 2400) }
        @{ Name='All Rejected';           Expect='ALL_ENTRIES_REFUSED'
           B=(New-FakeStatus @{10=100} 0 0 0 1000)
           F=(New-FakeStatus @{10=120; 27=1; 21=2; 25=900; 20=4} 4 0 0 2100 7) }
        @{ Name='Entered but stuck';     Expect='L2_ENTERED_BUT_STUCK'
           B=(New-FakeStatus @{10=100} 0 0 0 1000)
           F=(New-FakeStatus @{10=120; 27=1; 21=2; 25=900; 20=4; 24=600} 1 0 3 9000) }
        @{ Name='Entered';           Expect='L2_ENTERED'
           B=(New-FakeStatus @{10=100} 2 1 0 1000)
           F=(New-FakeStatus @{10=120; 27=1; 21=2; 25=900; 20=4; 24=600} 2 1 0 9000) }
    )
    $failed = 0
    foreach ($c in $cases) {
        Write-Host ''
        Write-Host ("######## Self-check case: {0} (expected {1}) ########" -f $c.Name, $c.Expect) -ForegroundColor Magenta
        $got = Show-Delta $c.B $c.F
        if ($got.verdict -eq $c.Expect) {
            Write-Host ("  [OK]   Determine {0}" -f $got.verdict) -ForegroundColor Green
        } else {
            Write-Host ("  [FAIL] Verdict {0}, expected {1}" -f $got.verdict, $c.Expect) -ForegroundColor Red
            $failed++
        }
    }
    # Note: The non-zero baseline case also verifies that 'counters are cumulative during the residency period': rejecting 2->2 must result in +0.
    Write-Host ''
    if ($failed -eq 0) {
        Write-Host ("Self-check {0}/{0} passed" -f $cases.Count) -ForegroundColor Green
        return 0
    }
    Write-Host ("Self-check {0} examples failed" -f $failed) -ForegroundColor Red
    return 1
}

if ($SelfTest) { exit (Invoke-SelfTest) }

# ---------------------------------------------------------------------------
Import-Module Hyper-V -ErrorAction Stop
if (-not (Test-Path $tool)) { throw "Missing $tool (run scripts\Build-KswordHvmTools.ps1 first)" }
$script:cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

$exitCode = 0
try {
    $vm = Get-VM -Name $VMName -ErrorAction Stop
    $nestedExposed = (Get-VMProcessor -VMName $VMName).ExposeVirtualizationExtensions
    $record.vm = [ordered]@{
        state = "$($vm.State)"; vcpu = $vm.ProcessorCount; nested = [bool]$nestedExposed
    }
    Write-Host '=== KSword Nested Guest Observation ===' -ForegroundColor Cyan
    Write-Host ("VM {0} {1} {2} vCPU nested={3}" -f $vm.Name, $vm.State, $vm.ProcessorCount, $nestedExposed)
    Write-Host ("Record -> {0}`n" -f $ResultPath) -ForegroundColor DarkGray

    if ($vm.State -ne 'Running') { throw "Virtual machine is not in Running state ($($vm.State)). Start-VM first." }
    if (-not $nestedExposed) { throw 'Nested virtualization is not enabled —— after shutdown, run Set-VMProcessor -ExposeVirtualizationExtensions $true' }

    $bootBefore = Get-GuestBootTime

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

    # ---- Lifecycle: Only supplement until 'resident with nested dispatch is running' ---------------------------
    $st = Invoke-HvmCtl 'status'
    if ($st.Exit -ne 0 -or $null -eq $st.Json) {
        Add-Step 'status' 'FAIL' $st.Stderr 'Device query failed - driver may not be loaded'
        $record.verdict = 'BLOCKED'
        [void]$record.notes.Add('hvm_ctl status failed to get result. First run Deploy-KswordDriverToVm.ps1.')
        $exitCode = 1
        return
    }
    $names = $st.Json.stateNames
    Add-Step 'status:before-bringup' 'OK' $null ("Status bit " + ($names -join ' '))

    if ($SkipBringUp) {
        Add-Step 'bring-up' 'SKIP' $null 'Skip with -SkipBringUp; observe only, do not modify lifecycle'
        if (-not (Test-StateBit $names 'RESIDENT_ACTIVE')) {
            [void]$record.notes.Add('The resident hypervisor is not running, and -SkipBringUp does not start it — there can be no nested readback in this round.')
        }
    } else {
        if ((Test-StateBit $names 'FAULTED') -or (Test-StateBit $names 'ROLLBACK_REQUIRED')) {
            $r = Invoke-HvmCtl 'reset-fault'
            Add-Step 'reset-fault' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json `
                     'Status contains FAULTED/ROLLBACK_REQUIRED; if resident is not cleared, it will be rejected'
            if ($r.Exit -ne 0) { $record.verdict = 'FAIL'; $exitCode = $r.Exit; return }
            $names = $r.Json.newStateNames
        }
        if (Test-StateBit $names 'RESOURCES_READY') {
            Add-Step 'prepare' 'SKIP' $null 'RESOURCES_READY is set; repeating prepare will set the state to FAULTED'
        } else {
            $r = Invoke-HvmCtl 'prepare'
            Add-Step 'prepare' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json
            if ($r.Exit -ne 0) { $record.verdict = 'FAIL'; $exitCode = $r.Exit; return }
            $names = $r.Json.newStateNames
        }
        # SELF_TEST_PASSED is required; missing it results in NOT_PREPARED (0xC00000A3) and is handled accordingly.
        # Mark the state as FAULTED — that state name reads like "not prepared," yet prepare was clearly
        # Just returned 0; a mismatch between the two readings would lead in a completely wrong direction. Adding this layer is not for safety.
        if (-not (Test-StateBit $names 'SELF_TEST_PASSED')) {
            $r = Invoke-HvmCtl 'self-test'
            Add-Step 'self-test' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json `
                     'Per-processor VMXON/VMXOFF; resident hypervisor prerequisites'
            if ($r.Exit -ne 0) { $record.verdict = 'FAIL'; $exitCode = $r.Exit; return }
            $names = $r.Json.newStateNames
        } else {
            Add-Step 'self-test' 'SKIP' $null 'SELF_TEST_PASSED set'
        }

        # Setting RESIDENT_ACTIVE does not equal it being the mode we want: a normal resident start
        # Resident mode traps VMX instructions with #UD, while nested and hidehv resident modes are identical in their state bits.
        # The same applies here: reusing a resident hypervisor of unknown origin runs the entire measurement in an unknown mode.
        if (Test-StateBit $names 'RESIDENT_ACTIVE') {
            $r = Invoke-HvmCtl 'stop'
            Add-Step 'stop' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json `
                     'Resident hypervisor is already running but mode is unknown (status bits cannot distinguish nested / hidehv); stop it first and restart according to the mode required for this round'
            if ($r.Exit -ne 0) { $record.verdict = 'FAIL'; $exitCode = $r.Exit; return }
        }
        $residentVerb = if ($Mode -eq 'hidehv') { 'resident-nested-hidehv' } else { 'resident-nested' }
        $r = Invoke-HvmCtl $residentVerb
        Add-Step $residentVerb $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json `
                 'All processors enter VMX resident mode, and allow the guest to execute VMX instructions'
        if ($r.Exit -ne 0) {
            $record.verdict = 'FAIL'
            [void]$record.notes.Add("$residentVerb readback $($r.Json.statusName)")
            $exitCode = $r.Exit
            return
        }
    }

    # After becoming resident, immediately read the guest user-mode CPUID. This is the only direct criterion for hidehv.
    # The mode cannot be determined from the status bits; these two values are the ones VMware uses to determine the outer identity.
    $cv = Invoke-HvmCtl 'cpuid-view'
    if ($null -ne $cv.Json) {
        $record.cpuidView = $cv.Json
        $hidden = [bool]$cv.Json.hidden
        $note = "hypervisor bit={0}  vendor=`"{1}`"" -f $cv.Json.hypervisorPresent, $cv.Json.hvVendor
        if ($Mode -eq 'hidehv' -and -not $hidden) {
            Add-Step 'cpuid-view' 'FAIL' $cv.Json ("Hidden but visible in user mode: " + $note)
            [void]$record.notes.Add('hidehv did not take effect — even if VMware fails to start afterward, it is not a nested virtualization capability issue.')
        } elseif ($Mode -eq 'hidehv') {
            Add-Step 'cpuid-view' 'OK' $cv.Json ("Hidden effect: " + $note)
        } else {
            Add-Step 'cpuid-view' 'OK' $cv.Json $note
        }
    } else {
        Add-Step 'cpuid-view' 'BLOCKED' $null 'Readback failed; unable to confirm the identity seen by the guest in this round'
    }

    # ---- Baseline -------------------------------------------------------------------
    $base = Invoke-HvmCtl 'status'
    if ($base.Exit -ne 0 -or $null -eq $base.Json) {
        Add-Step 'baseline' 'FAIL' $base.Stderr; $record.verdict = 'FAIL'; $exitCode = 1; return
    }
    $record.baseline = $base.Json
    Add-Step 'baseline' 'OK' $null ("vmExitCount={0} Deny={1} Evict={2} Melt={3}" -f `
        $base.Json.vmExitCount, $base.Json.nestedL2LaunchRefusedCount,
        $base.Json.nestedVmcs12EvictionCount, $base.Json.nestedFuseTripCount)

    # ---- Observation Window ----------------------------------------------------------
    Write-Host ''
    Write-Host '>>> Now go into the guest and launch a VM inside the third-party hypervisor.' -ForegroundColor Yellow
    Write-Host (">>> Window for {0} seconds, sample every {1} seconds; press any key to exit early." -f $WaitSeconds, $PollSeconds) -ForegroundColor Yellow
    Write-Host ''

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    $lastAlive = $true
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $PollSeconds
        $poll = $null
        try { $poll = Invoke-HvmCtl 'status' } catch { $poll = $null }
        if ($null -eq $poll -or $null -eq $poll.Json) {
            # The guest did not respond. **This itself is a reading** — the last successful sample is the flight record.
            $lastAlive = $false
            Add-Step 'poll' 'BLOCKED' $null 'Guest did not respond; last sample is the final context'
            break
        }
        [void]$record.samples.Add([ordered]@{
            utc     = (Get-Date).ToUniversalTime().ToString('o')
            exits   = $poll.Json.vmExitCount
            refused = $poll.Json.nestedL2LaunchRefusedCount
            evicted = $poll.Json.nestedVmcs12EvictionCount
            fuse    = $poll.Json.nestedFuseTripCount
            lastErr = $poll.Json.lastVmInstructionError
            reasons = $poll.Json.exitReasonCount
        })
        $vmxSeen = 0L
        $m = Get-ReasonMap $poll.Json
        foreach ($r in $vmxReasons) { if ($m.ContainsKey($r)) { $vmxSeen += [int64]$m[$r] } }
        Write-Host ("  Sampling exits={0} VMX instruction class={1} Rejected={2} Meltdown={3}" -f `
            $poll.Json.vmExitCount, $vmxSeen,
            $poll.Json.nestedL2LaunchRefusedCount, $poll.Json.nestedFuseTripCount) -ForegroundColor DarkGray

        $keyed = $false
        try { $keyed = [Console]::KeyAvailable } catch { $keyed = $false }
        if ($keyed) { try { [void][Console]::ReadKey($true) } catch { }; break }
    }

    # ---- Final State ----------------------------------------------------------------
    if (-not $lastAlive) {
        $bootAfter = Get-GuestBootTime
        if ($null -eq $bootAfter) {
            Add-Step 'final' 'BLOCKED' $null 'Guest still unresponsive -- hung or rebooting'
            $record.verdict = 'GUEST_UNRESPONSIVE'
        } elseif ($null -ne $bootBefore -and [math]::Abs(($bootAfter - $bootBefore).TotalSeconds) -ge 2) {
            Add-Step 'final' 'FAIL' $null "Guest rebooted ($bootBefore -> $bootAfter); counter cleared, difference meaningless"
            $record.verdict = 'GUEST_REBOOTED'
        } else {
            Add-Step 'final' 'BLOCKED' $null 'Guest disconnected mid-flight but did not restart —— the scene is the last entry in samples'
            $record.verdict = 'GUEST_UNRESPONSIVE'
        }
        $exitCode = 1
        return
    }

    $fin = Invoke-HvmCtl 'status'
    if ($fin.Exit -ne 0 -or $null -eq $fin.Json) {
        Add-Step 'final' 'FAIL' $fin.Stderr; $record.verdict = 'FAIL'; $exitCode = 1; return
    }
    $record.final = $fin.Json

    # A change in generation indicates the resource was torn down and prepared again in between; the counter belongs to a different lifecycle.
    if ($fin.Json.generation -ne $base.Json.generation) {
        Add-Step 'final' 'BLOCKED' $null ("generation {0} -> {1}: Resources were rebuilt mid-process, difference is not comparable" -f `
            $base.Json.generation, $fin.Json.generation)
        $record.verdict = 'GENERATION_CHANGED'
        $exitCode = 1
        return
    }
    Add-Step 'final' 'OK' $null

    $record.delta = Show-Delta $base.Json $fin.Json
    $record.verdict = $record.delta.verdict

    if ($StopWhenDone) {
        $r = Invoke-HvmCtl 'stop'
        Add-Step 'stop' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json
    } else {
        Add-Step 'stop' 'SKIP' $null 'Default: do not stop resident hypervisor; add -StopWhenDone or run hvm_ctl stop separately to stop'
    }
}
catch {
    $record.verdict = 'ERROR'
    [void]$record.notes.Add("$($_.Exception.Message)")
    Write-Host ("!! $($_.Exception.Message)") -ForegroundColor Red
    $exitCode = 1
}
finally {
    Save-Record
    Write-Host ''
    Write-Host ("Determine {0} record {1}" -f $record.verdict, $ResultPath) -ForegroundColor Cyan
}

exit $exitCode
