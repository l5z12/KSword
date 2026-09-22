<#
.SYNOPSIS
    On a dedicated CI machine with test signing enabled, traverse KswordARK driver functionality and treat system crashes as failures.

.DESCRIPTION
    This script iterates through driver_functional_ci/driver_test_plan.json to run each apps/cli driver test case.
    Before each step, it writes the current test case being executed to disk logs using WriteThrough, ensuring that
    even if the machine bugchecks immediately, the exact failing test case can be identified after reboot.

    Crash criteria take three evidence sources: new kernel dump, BugCheck(1001) in System log, and
    Kernel-Power (41)/EventLog (6008), and LastBootUpTime inconsistent with the baseline.

    RepositoryRoot: Repository root directory; if empty, derived from the script location.
    1. Any IOCTL in the plan that matches dangerous patterns (writing to kernel/physical memory, modifying PatchGuard coverage
       areas, performing DKOM unlinking, forcibly unloading drivers, altering HWID/clock/power settings, or configuring BSOD
       paths) is statically blocked by plan_gate.py and added to the excluded list; no CI mode will ever issue these requests.
    2. Every bounded write in the probe layer uses targetGuard. At runtime, require the target to be a process, file, or registry
       key created by the harness itself. Abort the entire run immediately if it falls outside that scope; never target system objects;
    3. The guarded layer is disabled by default; once explicitly enabled, the current run is marked as
       attributionWeakened. Crashes are attributed to harness-attributable rather than driver defects,
       and this flag persists across reboots, overriding PatchGuard's delayed crash time window.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File drivers/ark\tests\DriverFunctionalMatrix.ps1

.EXAMPLE
    # The previous crash has been manually resolved; resume execution after unblocking.
    ... -AcknowledgePreviousCrash
#>

[CmdletBinding()]
param(
    # RepositoryRoot: Repository root directory; derived from script location if empty.
    [string]$RepositoryRoot,

    # PlanPath: Functional matrix plan file.
    [string]$PlanPath,

    # BinaryDir: Directory containing KswordARK.sys and KswordCLI.exe.
    [string]$BinaryDir,

    # StateRoot: directory for preserving state across runs and reboots; must be outside the workspace.
    [string]$StateRoot,

    # ArtifactRoot: Output directory for logs and judgment results of this run.
    [string]$ArtifactRoot,

    # ServiceName: Kernel service name of the driver under test.
    [string]$ServiceName = 'KswordARK',

    # Mode: Run executes the full matrix; Verify performs only crash forensics and judgment; SelfTest checks only the harness logic itself.
    [ValidateSet('Run', 'Verify', 'SelfTest')]
    [string]$Mode = 'Run',

    # CaseFilter: Executes only cases whose IDs match this regex, used for locating a single regression.
    [string]$CaseFilter,

    # IncludeGuarded: Execute guarded layer test cases; -AcknowledgeGuardedRisk must be provided simultaneously.
    [switch]$IncludeGuarded,

    # AcknowledgeGuardedRisk: Confirm acceptance of self-harm risks and attribution downgrade in the guarded layer.
    [switch]$AcknowledgeGuardedRisk,

    # ConfigureCrashDump: allows the script to configure the machine to retain kernel dumps; if not provided, only validation is performed.
    [switch]$ConfigureCrashDump,

    # AcknowledgePreviousCrash: The previous crash has been manually identified, removing the block on this run.
    [switch]$AcknowledgePreviousCrash,

    # SkipDriverLoad: The driver has already been loaded by the operator; the script will not create or start the service.
    [switch]$SkipDriverLoad,

    # FailOnSkippedProbe: Treat skipped probe-level test cases due to missing variables as failures.
    [switch]$FailOnSkippedProbe
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# $PSScriptRoot may be empty during parameter default value evaluation on some hosts; resolve it once inside the script body.
$script:ScriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

$script:ExitPass = 0
$script:ExitCaseFailure = 1
$script:ExitCrash = 2
$script:ExitPreflight = 3

$script:Journal = $null
$script:SpawnedPids = New-Object System.Collections.Generic.HashSet[int]
$script:GuardedExecuted = $false

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "[driver-matrix] $Message"
}

function Get-UtcStamp {
    return (Get-Date).ToUniversalTime().ToString('o')
}

function Open-Journal {
    <#
      Open crash-survival execution logs. Input is the log file path; the process uses WriteThrough to open the
      FileStream so each record is flushed to disk before returning; the return value is the writer handle.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::Read,
        4096,
        [System.IO.FileOptions]::WriteThrough)
    return [pscustomobject]@{ Stream = $stream; Path = $Path }
}

function Write-Journal {
    <#
      Append a JSONL record and force it to disk. The input is the record object; the process serializes it, writes it, and
      calls Flush(true) to flush the file system cache. The return value is empty. Crash attribution relies entirely on this.
    #>
    param([Parameter(Mandatory)][hashtable]$Record)

    if ($null -eq $script:Journal) { return }
    $Record['utc'] = Get-UtcStamp
    $line = ($Record | ConvertTo-Json -Compress -Depth 6) + "`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($line)
    $script:Journal.Stream.Write($bytes, 0, $bytes.Length)
    $script:Journal.Stream.Flush($true)
}

function Close-Journal {
    if ($null -ne $script:Journal) {
        $script:Journal.Stream.Dispose()
        $script:Journal = $null
    }
}

function Read-JournalRecords {
    <#
      Read a historical log. Input is a path; the process deserializes line by line and skips truncated
      trailing lines (the last line may be incomplete during a crash); the return value is an array of records.
    #>
    param([Parameter(Mandatory)][string]$Path)

    # Wrapping with a comma is necessary: PowerShell would otherwise downgrade an empty array return value to $null.
    if (-not (Test-Path -LiteralPath $Path)) { return , @() }
    $records = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $records += ($line | ConvertFrom-Json) } catch { }
    }
    return , $records
}

# ---------------------------------------------------------------------------
# Pre-check
# ---------------------------------------------------------------------------

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-TestSigningEnabled {
    <#
      Check if the machine is in test signing mode. Input: none; Process: reads current boot entry output from
      bcdedit; Return value: boolean. If not enabled, the driver cannot load, making this CI meaningless.
    #>
    $output = & bcdedit.exe /enum '{current}' 2>&1 | Out-String
    return ($output -match '(?im)^\s*testsigning\s+Yes\s*$')
}

function Assert-CrashDumpConfigured {
    <#
      Validate (and optionally correct) kernel dump configuration. Input indicates whether modifications are allowed. The process reads
      the CrashControl registry key and writes kernel dump configuration if necessary. The return value is a configuration summary.
      The dump must be available; otherwise, there is no evidence for attribution after a crash.
    #>
    param([switch]$AllowConfigure)

    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $readDword = {
        param($Source, $Name)
        if ($Source.PSObject.Properties.Name -contains $Name) { return [int]$Source.$Name }
        return 0
    }
    $control = Get-ItemProperty -Path $key
    if ($AllowConfigure) {
        Set-ItemProperty -Path $key -Name 'CrashDumpEnabled' -Value 2 -Type DWord
        Set-ItemProperty -Path $key -Name 'AlwaysKeepMemoryDump' -Value 1 -Type DWord
        Set-ItemProperty -Path $key -Name 'AutoReboot' -Value 1 -Type DWord
        $control = Get-ItemProperty -Path $key
    }
    if ((& $readDword $control 'CrashDumpEnabled') -eq 0) {
        throw 'Kernel dump is not enabled (CrashControl\CrashDumpEnabled = 0). Crashes will have no evidence; please add -ConfigureCrashDump or enable it manually.'
    }
    return [ordered]@{
        crashDumpEnabled     = (& $readDword $control 'CrashDumpEnabled')
        autoReboot           = (& $readDword $control 'AutoReboot')
        alwaysKeepMemoryDump = (& $readDword $control 'AlwaysKeepMemoryDump')
    }
}

# ---------------------------------------------------------------------------
# Crash evidence
# ---------------------------------------------------------------------------

function Get-MinidumpInventory {
    <#
      List current kernel dump files. Input: none; Process: enumerate the Minidump directory and MEMORY.DMP.
      Return value: An ordered dictionary mapping 'path -> last write time' for baseline comparison.
    #>
    $inventory = [ordered]@{}
    $minidumpDir = Join-Path $env:SystemRoot 'Minidump'
    if (Test-Path -LiteralPath $minidumpDir) {
        foreach ($file in Get-ChildItem -LiteralPath $minidumpDir -Filter '*.dmp' -File -ErrorAction SilentlyContinue) {
            $inventory[$file.FullName] = $file.LastWriteTimeUtc.ToString('o')
        }
    }
    $memoryDump = Join-Path $env:SystemRoot 'MEMORY.DMP'
    if (Test-Path -LiteralPath $memoryDump) {
        $inventory[$memoryDump] = (Get-Item -LiteralPath $memoryDump).LastWriteTimeUtc.ToString('o')
    }
    return $inventory
}

function Get-CrashBaseline {
    <#
      Collect the crash determination baseline. Input: none. Process: records the current dump manifest, the last boot time, and
      the latest record number in the System log. Return value: a baseline object used to calculate increments after execution.
    #>
    $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    $lastRecord = 0
    try {
        $newest = Get-WinEvent -LogName 'System' -MaxEvents 1 -ErrorAction Stop
        $lastRecord = [int64]$newest.RecordId
    } catch { }
    return [pscustomobject]@{
        dumps          = Get-MinidumpInventory
        lastBootUpTime = $lastBoot
        systemRecordId = $lastRecord
        capturedAtUtc  = Get-UtcStamp
    }
}

function Get-CrashEvidence {
    <#
      Compare against baseline to provide crash evidence. Input is the baseline; the process compares dump inventories
      and boot times, and queries three event types: BugCheck(1001), Kernel-Power(41), and EventLog(6008).
      Return value includes the crashed flag and all evidence details.
    #>
    param([Parameter(Mandatory)]$Baseline)

    $current = Get-MinidumpInventory
    $newDumps = @()
    foreach ($path in $current.Keys) {
        if (-not $Baseline.dumps.Contains($path) -or $Baseline.dumps[$path] -ne $current[$path]) {
            $newDumps += $path
        }
    }

    $rebooted = $false
    $lastBoot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    if ($lastBoot -ne $Baseline.lastBootUpTime) { $rebooted = $true }

    $events = @()
    $since = [datetime]::Parse($Baseline.capturedAtUtc).ToUniversalTime().AddMinutes(-1)
    foreach ($spec in @(
            @{ Provider = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001 },
            @{ Provider = 'Microsoft-Windows-Kernel-Power'; Id = 41 },
            @{ Provider = 'EventLog'; Id = 6008 })) {
        try {
            $found = Get-WinEvent -FilterHashtable @{
                LogName      = 'System'
                ProviderName = $spec.Provider
                Id           = $spec.Id
                StartTime    = $since
            } -ErrorAction Stop
        } catch {
            continue
        }
        foreach ($entry in $found) {
            $events += [ordered]@{
                provider = $spec.Provider
                id       = $spec.Id
                timeUtc  = $entry.TimeCreated.ToUniversalTime().ToString('o')
                message  = ($entry.Message -replace '\s+', ' ').Trim()
            }
        }
    }

    return [pscustomobject]@{
        crashed        = (($newDumps.Count -gt 0) -or $rebooted -or ($events.Count -gt 0))
        newDumps       = $newDumps
        unexpectedBoot = $rebooted
        events         = $events
        lastBootUpTime = $lastBoot
    }
}

# ---------------------------------------------------------------------------
# Previous run crash block.
# ---------------------------------------------------------------------------

function Get-PreviousRunState {
    param([Parameter(Mandatory)][string]$StateRoot)
    $path = Join-Path $StateRoot 'last-run.json'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Resolve-InFlightCase {
    <#
      Infer the test case executing at the crash from the log. Input is an array of log records; the
      process finds the last 'case-begin' without a matching 'case-end'; returns that record or $null.
    #>
    param([Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][array]$Records)

    $pending = $null
    if ($null -eq $Records) { return $null }
    foreach ($record in $Records) {
        if ($record.event -eq 'case-begin') { $pending = $record }
        elseif ($record.event -eq 'case-end' -and $null -ne $pending -and $record.case -eq $pending.case) { $pending = $null }
    }
    return $pending
}

function Assert-NoUnresolvedPreviousCrash {
    <#
      Prevent starting a new run on top of an unlocated crash. Input is the state directory and whether it has been manually acknowledged.
      The process checks if the previous run left unclosed logs accompanied by crash evidence;
      Returns empty; on hit, throws and requires -AcknowledgePreviousCrash.
    #>
    param(
        [Parameter(Mandatory)][string]$StateRoot,
        [switch]$Acknowledged
    )

    $previous = Get-PreviousRunState -StateRoot $StateRoot
    if ($null -eq $previous) { return }
    if ($previous.verdict -ne 'incomplete' -and -not $previous.crash.crashed) { return }

    $journalPath = Join-Path $StateRoot 'journal.jsonl'
    $inFlight = Resolve-InFlightCase -Records (Read-JournalRecords -Path $journalPath)
    $caseText = if ($null -ne $inFlight) { $inFlight.case } else { '<Unknown>' }

    if ($Acknowledged) {
        Write-Warning "Previous run $($previous.runId) did not end normally (interrupted at test case $caseText), continuing with -AcknowledgePreviousCrash."
        return
    }
    throw ("Previous run $($previous.runId) did not end normally, interrupted at test case $caseText." +
        "First locate the crash using $journalPath and the kernel dump, then add -AcknowledgePreviousCrash to rerun after handling it.")
}

# ---------------------------------------------------------------------------
# Driver service
# ---------------------------------------------------------------------------

function Install-DriverService {
    <#
      Create and start the kernel service for the driver under test. Inputs are the service name and .sys
      path. Remove remnants with the same name, then run sc create/start. Return no value; throw on failure.
    #>
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$DriverPath
    )

    Uninstall-DriverService -ServiceName $ServiceName -Quiet
    Write-Step "Create kernel service $ServiceName -> $DriverPath"
    $create = & sc.exe create $ServiceName type= kernel start= demand binPath= $DriverPath 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "sc create failed: $create" }
    $start = & sc.exe start $ServiceName 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        Uninstall-DriverService -ServiceName $ServiceName -Quiet
        throw ("sc start failed: $start" + [Environment]::NewLine +
            '577 usually means the .sys lacks a test signature or the certificate is absent from LocalMachine\Root and TrustedPublisher.')
    }
}

function Uninstall-DriverService {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [switch]$Quiet
    )
    if (-not $Quiet) { Write-Step "Stop and remove kernel service $ServiceName" }
    & sc.exe stop $ServiceName 2>&1 | Out-Null
    & sc.exe delete $ServiceName 2>&1 | Out-Null
}

function Test-DriverDeviceAlive {
    <#
      Probe whether the driver control device is still available. Input is the CLI path; the process sends a minimal
      read-only registry query; the return value is a boolean used to detect driver inactivity between use cases.
    #>
    param([Parameter(Mandatory)][string]$CliPath)

    $result = Invoke-CliStep -CliPath $CliPath -Arguments @('r0', 'ioctl-registry', '--max-entries', '1') -TimeoutSeconds 30
    return ($result.exitCode -eq 0)
}

# ---------------------------------------------------------------------------
# Test case execution
# ---------------------------------------------------------------------------

function Invoke-CliStep {
    <#
      Execute a single apps/cli call. Inputs are the CLI path, argument array, and timeout in seconds. The process
      redirects stdout/stderr to temporary files and terminates the process upon timeout. The return value includes the
      exit code, elapsed time, timeout status, whether the process failed to exit after the timeout, and the output tail.
    #>
    param(
        [Parameter(Mandatory)][string]$CliPath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $stdout = [System.IO.Path]::GetTempFileName()
    $stderr = [System.IO.Path]::GetTempFileName()
    $timedOut = $false
    $unkillable = $false
    $exitCode = $null
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $process = Start-Process -FilePath $CliPath -ArgumentList $Arguments -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            # Windows PowerShell 5.1's Process.Kill lacks a bool overload, so it falls back to taskkill to terminate the process tree.
            try { $process.Kill() } catch { }
            & taskkill.exe /T /F /PID $process.Id 2>&1 | Out-Null
            # If a suspended IOCTL lacks a cancellable routine, the process will remain stuck in kernel mode and cannot exit.
            if (-not $process.WaitForExit(30000)) { $unkillable = $true }
        }
        if (-not $unkillable) { $exitCode = $process.ExitCode }
    } finally {
        $watch.Stop()
    }

    $outText = if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue } else { '' }
    $errText = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue } else { '' }
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue

    return [pscustomobject]@{
        exitCode    = $exitCode
        timedOut    = $timedOut
        unkillable  = $unkillable
        elapsedMs   = [int]$watch.ElapsedMilliseconds
        stdout      = if ($null -eq $outText) { '' } else { $outText }
        stderr      = if ($null -eq $errText) { '' } else { $errText }
    }
}

function Test-FaultExitCode {
    <#
      Check if the exit code indicates an abnormal termination in user mode. Input is the exit code; the process checks if it falls
      within the NTSTATUS error range (above 0xC0000000); the return value is a boolean. R3 crashes are also considered defects.
    #>
    param($ExitCode)
    if ($null -eq $ExitCode) { return $false }
    # Native process exit codes are signed Int32; reinterpret them bitwise as DWORD to compare against NTSTATUS ranges.
    $value = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$ExitCode), 0)
    return ($value -ge [uint32]3221225472)
}

function Expand-PlanArguments {
    <#
      Replace placeholders in the steps with actual values for this run. Input consists of a parameter array and a variable dictionary.
      The processing performs whole-string replacement token by token; undefined variables return $null.
      Returns the replaced argument array or $null (indicating this test case should be skipped).
    #>
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][hashtable]$Variables
    )

    $expanded = @()
    foreach ($token in $Arguments) {
        $value = $token
        foreach ($match in [regex]::Matches($token, '\{([A-Za-z0-9_.]+)\}')) {
            $name = $match.Groups[1].Value
            if (-not $Variables.ContainsKey($name) -or [string]::IsNullOrEmpty([string]$Variables[$name])) {
                return $null
            }
            $value = $value.Replace($match.Value, [string]$Variables[$name])
        }
        $expanded += $value
    }
    return , $expanded
}

function Assert-TargetGuard {
    <#
      Runtime fallback: Ensure bounded writes target only the harness's own objects.
      Input consists of the guard name, expanded arguments, and execution context; the process checks pid, --path,
      ----key, and --new-name values according to the guard type; returns empty, or throws on out-of-bounds access.
      This layer is the second line of defense against 'reckless hands'; it still blocks even if static access control fails.
    #>
    param(
        [Parameter(Mandatory)][string]$Guard,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][hashtable]$Context
    )

    for ($index = 0; $index -lt $Arguments.Count - 1; $index++) {
        $name = $Arguments[$index]
        $value = $Arguments[$index + 1]
        switch ($Guard) {
            'harness-owned-process' {
                if ($name -eq '--pid') {
                    $candidate = 0
                    if (-not [int]::TryParse($value, [ref]$candidate) -or -not $script:SpawnedPids.Contains($candidate)) {
                        throw "targetGuard violation: $name $value is not a process launched in this run, execution denied."
                    }
                }
            }
            'harness-owned-path' {
                if ($name -eq '--path') {
                    $normalized = ($value -replace '^\\\?\?\\', '')
                    if (-not $normalized.StartsWith($Context.TempDir, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw "targetGuard violation: $name $value is not within the temporary directory for this run, execution denied."
                    }
                }
            }
            'harness-owned-registry-key' {
                if ($name -eq '--key') {
                    if (-not $value.StartsWith($Context.RegistryTestRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                        throw "targetGuard violation: $name $value is not within the test keys for this run, execution denied."
                    }
                }
                if ($name -eq '--new-name' -and ($value -match '[\\/]')) {
                    throw "targetGuard violation: --new-name $value must be a leaf name and cannot contain path separators."
                }
            }
            default { throw "Unknown targetGuard: $Guard" }
        }
    }
}

function Invoke-PlanCase {
    <#
      Execute a single test case. Inputs are the test case definition, runtime context, and variable dictionary; the
      process expands parameters, performs targetGuard validation, executes all steps in order, and always runs cleanup.
      The return value is the result record for this test case. Log begin/end entries are written by the caller.
    #>
    param(
        [Parameter(Mandatory)]$Case,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][hashtable]$Variables
    )

    $steps = @()
    $status = 'passed'
    $failureReason = ''

    foreach ($rawStep in $Case.steps) {
        $arguments = Expand-PlanArguments -Arguments ([string[]]$rawStep) -Variables $Variables
        if ($null -eq $arguments) {
            return [ordered]@{
                case = $Case.id; tier = $Case.tier; status = 'skipped'
                reason = 'Missing required runtime variables'; steps = $steps
            }
        }
        if ($Case.PSObject.Properties.Name -contains 'targetGuard') {
            Assert-TargetGuard -Guard $Case.targetGuard -Arguments $arguments -Context $Context
        }

        $result = Invoke-CliStep -CliPath $Context.CliPath -Arguments $arguments -TimeoutSeconds $Case.timeoutSeconds
        $stepRecord = [ordered]@{
            arguments = ($arguments -join ' ')
            exitCode  = $result.exitCode
            elapsedMs = $result.elapsedMs
            timedOut  = $result.timedOut
            stdoutTail = (($result.stdout -split "`r?`n") | Select-Object -Last 12) -join "`n"
            stderrTail = (($result.stderr -split "`r?`n") | Select-Object -Last 12) -join "`n"
        }
        $steps += $stepRecord

        if ($result.unkillable) {
            $status = 'failed'
            $failureReason = 'pended-request-not-cancelled: Process still cannot exit after timeout, indicating a flaw in the driver''s cancellation path.'
            break
        }
        if ($Case.expect -eq 'timeout') {
            if (-not $result.timedOut) {
                $status = 'failed'
                $failureReason = "This test case expects the request to hang, but the process returned directly with exit code $($result.exitCode)."
                break
            }
            continue
        }
        if ($result.timedOut) {
            $status = 'failed'
            $failureReason = "Step timeout ($($Case.timeoutSeconds)s): possibly driver deadlock or response budget exceeded."
            break
        }
        if (Test-FaultExitCode -ExitCode $result.exitCode) {
            $status = 'failed'
            $failureReason = "apps/cli terminated abnormally, exit code 0x{0:X8}: crashed while parsing driver response in R3." -f ([System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$result.exitCode), 0))
            break
        }
        if ($Case.expect -eq 'success' -and $result.exitCode -ne 0) {
            $status = 'failed'
            $failureReason = "This test case requires success, but actual exit code is $($result.exitCode)."
            break
        }
    }

    if ($Case.PSObject.Properties.Name -contains 'cleanup') {
        foreach ($rawStep in $Case.cleanup) {
            $arguments = Expand-PlanArguments -Arguments ([string[]]$rawStep) -Variables $Variables
            if ($null -eq $arguments) { continue }
            try {
                if ($Case.PSObject.Properties.Name -contains 'targetGuard') {
                    Assert-TargetGuard -Guard $Case.targetGuard -Arguments $arguments -Context $Context
                }
                Invoke-CliStep -CliPath $Context.CliPath -Arguments $arguments -TimeoutSeconds 60 | Out-Null
            } catch {
                Write-Warning "Cleanup step for test case $($Case.id) failed: $($_.Exception.Message)"
            }
        }
    }

    return [ordered]@{
        case = $Case.id; tier = $Case.tier; status = $status
        reason = $failureReason; steps = $steps
    }
}

# ---------------------------------------------------------------------------
# Runtime variable discovery
# ---------------------------------------------------------------------------

function Start-SacrificialProcess {
    <#
      Launches a one-time target process. Input is a label; the handler starts a long-running idle cmd.exe and
      registers its PID in SpawnedPids (targetGuard only recognizes this table); returns the process object.
    #>
    param([Parameter(Mandatory)][string]$Label)

    $process = Start-Process -FilePath $env:ComSpec `
        -ArgumentList '/c', 'ping -n 900 127.0.0.1 > nul' `
        -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 400
    $process.Refresh()
    [void]$script:SpawnedPids.Add($process.Id)
    Write-Step "Launched test target process $Label with PID=$($process.Id)"
    return $process
}

function Stop-SacrificialProcess {
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return }
    & taskkill.exe /T /F /PID $ProcessId 2>&1 | Out-Null
}

function Resolve-RuntimeVariables {
    <#
      Constructs all runtime variables required for the scheduled task. The input is the execution context; the process launches the target process, resolves
      the main module base address and main thread, retrieves a self-owned handle from the handle enumeration output, and prepares temporary files and a
      dedicated registry key. The return value is a variable dictionary with missing fields left empty, causing related test cases to be marked as skipped.
    #>
    param([Parameter(Mandatory)][hashtable]$Context)

    $variables = @{}
    $variables['self.pid'] = $PID
    $variables['driver.serviceName'] = $Context.ServiceName
    $variables['temp.dirWin32'] = $Context.TempDir
    $variables['system.kernel32Win32'] = (Join-Path $env:SystemRoot 'System32\kernel32.dll')
    $variables['system.kernel32Nt'] = '\??\' + (Join-Path $env:SystemRoot 'System32\kernel32.dll')
    $variables['registry.softwareKeyNt'] = '\REGISTRY\MACHINE\SOFTWARE'
    $variables['registry.currentVersionKeyNt'] = '\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $variables['registry.testKeyNt'] = $Context.RegistryTestKey
    $variables['registry.testKeyRenamedLeaf'] = $Context.RegistryTestRenamedLeaf
    $variables['registry.testKeyRenamedNt'] = $Context.RegistryTestRenamedKey

    $probeFile = Join-Path $Context.TempDir 'probe.bin'
    $mutableFile = Join-Path $Context.TempDir 'mutable.bin'
    $deletableFile = Join-Path $Context.TempDir 'deletable.bin'
    $regValueFile = Join-Path $Context.TempDir 'regvalue.bin'
    [System.IO.File]::WriteAllBytes($probeFile, [byte[]](1..64))
    [System.IO.File]::WriteAllBytes($mutableFile, [byte[]](1..64))
    [System.IO.File]::WriteAllBytes($deletableFile, [byte[]](1..64))
    [System.IO.File]::WriteAllBytes($regValueFile, [System.Text.Encoding]::Unicode.GetBytes("KswordARK-CI`0"))
    $variables['temp.probeFileNt'] = '\??\' + $probeFile
    $variables['temp.mutableFileNt'] = '\??\' + $mutableFile
    $variables['temp.deletableFileNt'] = '\??\' + $deletableFile
    $variables['temp.regValueFile'] = $regValueFile

    $target = Start-SacrificialProcess -Label 'Evidence'
    $variables['target.pid'] = $target.Id
    try {
        $variables['target.imageBase'] = '0x' + $target.MainModule.BaseAddress.ToInt64().ToString('X')
    } catch {
        Write-Warning "Failed to read the base address of the target process's main module: $($_.Exception.Message)"
    }
    try {
        $variables['target.tid'] = ($target.Threads | Select-Object -First 1).Id
    } catch {
        Write-Warning "Failed to read the target process thread list: $($_.Exception.Message)"
    }

    $handleProbe = Invoke-CliStep -CliPath $Context.CliPath `
        -Arguments @('handle', 'enum', '--pid', "$PID", '--limit', '32') -TimeoutSeconds 120
    $handleMatch = [regex]::Match($handleProbe.stdout, 'handle=0x([0-9a-fA-F]+)')
    if ($handleMatch.Success) {
        $variables['self.handle'] = '0x' + $handleMatch.Groups[1].Value
    } else {
        Write-Warning 'Failed to parse self-owned handle from handle enum output; related test cases will be skipped.'
    }

    $window = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
    if ($null -ne $window) {
        $variables['window.hwnd'] = '0x' + $window.MainWindowHandle.ToInt64().ToString('X')
    }

    foreach ($pair in @{
            'profile.v4Blob'        = 'KSWORD_CI_PROFILE_V4_BLOB'
            'callback.rulesBlob'    = 'KSWORD_CI_CALLBACK_RULES_BLOB'
            'redirect.rulesBlob'    = 'KSWORD_CI_REDIRECT_RULES_BLOB'
            'network.rulesBlob'     = 'KSWORD_CI_NETWORK_RULES_BLOB'
            'mutation.targetKind'   = 'KSWORD_CI_MUTATION_TARGET_KIND'
            'mutation.address'      = 'KSWORD_CI_MUTATION_ADDRESS'
            'mutation.beforeHex'    = 'KSWORD_CI_MUTATION_BEFORE_HEX'
            'mutation.afterHex'     = 'KSWORD_CI_MUTATION_AFTER_HEX'
            'mutation.transactionId' = 'KSWORD_CI_MUTATION_TRANSACTION_ID'
        }.GetEnumerator()) {
        $value = [Environment]::GetEnvironmentVariable($pair.Value)
        if (-not [string]::IsNullOrWhiteSpace($value)) { $variables[$pair.Key] = $value }
    }

    return $variables
}

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

function Invoke-Matrix {
    <#
      Execute the full functional matrix. Inputs are the parsed plan and runtime context; the process executes test
      cases in plan order, periodically probes driver liveness, and logs every step to a crash-survivable log.
      Return value is the result array.
    #>
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][hashtable]$Variables
    )

    $results = @()
    $index = 0
    foreach ($case in $Plan.cases) {
        if ($CaseFilter -and ($case.id -notmatch $CaseFilter)) { continue }
        if ($case.tier -eq 'guarded' -and -not $IncludeGuarded) {
            $results += [ordered]@{ case = $case.id; tier = $case.tier; status = 'skipped'; reason = 'guarded layer not executed by default'; steps = @() }
            continue
        }

        # Lifecycle test cases target one-time processes: a new process is spawned after the target terminates to avoid cross-contamination.
        $stepText = ($case.steps | ForEach-Object { $_ -join ' ' }) -join ' '
        if ($stepText -like '*{lifecycle.pid}*') {
            if (-not $Variables.ContainsKey('lifecycle.pid') -or -not $Variables['lifecycle.pid']) {
                $lifecycle = Start-SacrificialProcess -Label 'Lifecycle'
                $Variables['lifecycle.pid'] = $lifecycle.Id
            }
        }

        $index++
        Write-Step "[$index] $($case.id) ($($case.tier))"
        Write-Journal @{ event = 'case-begin'; case = $case.id; tier = $case.tier; ioctls = $case.ioctls }
        if ($case.tier -eq 'guarded') { $script:GuardedExecuted = $true }

        $result = Invoke-PlanCase -Case $case -Context $Context -Variables $Variables
        Write-Journal @{ event = 'case-end'; case = $case.id; status = $result.status; reason = $result.reason }
        $results += $result

        if ($result.status -eq 'failed') {
            Write-Warning "Test case $($case.id) failed: $($result.reason)"
        }
        # After the target process is terminated, subsequent lifecycle cases require a new target.
        if ($case.id -eq 'process.terminate') { $Variables['lifecycle.pid'] = $null }

        if (($index % 10) -eq 0) {
            if (-not (Test-DriverDeviceAlive -CliPath $Context.CliPath)) {
                Write-Journal @{ event = 'device-lost'; afterCase = $case.id }
                throw "The driver control device no longer responds after case $($case.id), terminating this round."
            }
        }
    }
    return $results
}

function Resolve-Attribution {
    <#
      Classify the crash. Inputs are crash evidence, execution logs, and the previous run's state. The process determines attribution by checking "which test case
      was running at the time of the crash" and "whether guarded mode was enabled in the current or previous run". The return value is the attribution string.
      driver-defect indicates a planned safe operation that crashed the machine, representing a genuine driver defect.
    #>
    param(
        [Parameter(Mandatory)]$Crash,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][array]$Records,
        $PreviousState
    )

    if (-not $Crash.crashed) { return 'none' }
    $inFlight = Resolve-InFlightCase -Records $Records
    if ($null -ne $inFlight -and $inFlight.tier -eq 'guarded') { return 'harness-attributable' }
    if ($script:GuardedExecuted) { return 'possibly-self-inflicted-this-run' }
    if ($null -ne $PreviousState -and $PreviousState.PSObject.Properties.Name -contains 'guardedExecuted' `
            -and $PreviousState.guardedExecuted `
            -and $PreviousState.crash.lastBootUpTime -eq $Crash.lastBootUpTime) {
        # PatchGuard checks are triggered with a delay: if guarded was run in the same boot, the crash cannot be attributed to this round.
        return 'possibly-self-inflicted-previous-run'
    }
    return 'driver-defect'
}

function Invoke-SelfTest {
    <#
      Self-check harness security and attribution logic. Input is the plan path; the process uses synthetic inputs to verify that
      targetGuard blocks out-of-bounds targets, placeholder expansion skips on missing variables, crash attribution distinguishes
      between guarded and probe modes, and the plan is re-verified to ensure no dangerous IOCTLs are embedded in the probe layer.
      Returns the exit code. This mode does not load the driver and does not require administrator privileges or a test signature.
    #>
    param([Parameter(Mandatory)][string]$PlanPath)

    $failures = @()
    function Assert-True {
        param([bool]$Condition, [string]$Message)
        if (-not $Condition) { $script:SelfTestFailures += $Message }
    }
    $script:SelfTestFailures = @()

    $context = @{
        CliPath = 'unused'; ServiceName = 'KswordARK'
        TempDir = 'C:\Temp\KswordArkDriverCI-selftest'
        RegistryTestRoot = '\REGISTRY\MACHINE\SOFTWARE\KswordARKDriverCI'
        RegistryTestKey = '\REGISTRY\MACHINE\SOFTWARE\KswordARKDriverCI\run-selftest'
        RegistryTestRenamedLeaf = 'run-selftest-renamed'
        RegistryTestRenamedKey = '\REGISTRY\MACHINE\SOFTWARE\KswordARKDriverCI\run-selftest-renamed'
    }

    # 1. The process guard only recognizes PIDs spawned in the current run.
    [void]$script:SpawnedPids.Add(424242)
    $blocked = $false
    try { Assert-TargetGuard -Guard 'harness-owned-process' -Arguments @('process', 'terminate', '--pid', '4') -Context $context }
    catch { $blocked = $true }
    Assert-True $blocked 'targetGuard failed to block the termination request targeting a system process (PID 4).'

    $allowed = $true
    try { Assert-TargetGuard -Guard 'harness-owned-process' -Arguments @('process', 'terminate', '--pid', '424242') -Context $context }
    catch { $allowed = $false }
    Assert-True $allowed 'targetGuard incorrectly blocked the process it itself launched.'
    [void]$script:SpawnedPids.Remove(424242)

    # 2. The path guard only recognizes the temporary directory of the current run; NT prefixes must also be recognized.
    $blocked = $false
    try { Assert-TargetGuard -Guard 'harness-owned-path' -Arguments @('file', 'delete-path', '--path', '\??\C:\Windows\System32\ntoskrnl.exe') -Context $context }
    catch { $blocked = $true }
    Assert-True $blocked 'targetGuard failed to block the deletion request targeting the system directory.'

    $allowed = $true
    try { Assert-TargetGuard -Guard 'harness-owned-path' -Arguments @('file', 'delete-path', '--path', ('\??\' + $context.TempDir + '\deletable.bin')) -Context $context }
    catch { $allowed = $false }
    Assert-True $allowed 'targetGuard incorrectly blocked the temporary file for this run.'

    # 3. The registry guard only recognizes dedicated test keys.
    $blocked = $false
    try { Assert-TargetGuard -Guard 'harness-owned-registry-key' -Arguments @('registry', 'delete-key', '--key', '\REGISTRY\MACHINE\SYSTEM\CurrentControlSet') -Context $context }
    catch { $blocked = $true }
    Assert-True $blocked 'targetGuard failed to block the delete request targeting CurrentControlSet.'

    # 4. When placeholders are missing, the test case should be skipped rather than issuing a partial command.
    $expanded = Expand-PlanArguments -Arguments @('process', 'detail', '--pid', '{target.pid}') -Variables @{}
    Assert-True ($null -eq $expanded) 'Placeholder expansion did not return $null when the variable is missing.'
    $expanded = Expand-PlanArguments -Arguments @('process', 'detail', '--pid', '{target.pid}') -Variables @{ 'target.pid' = 1234 }
    Assert-True (($expanded -join ' ') -eq 'process detail --pid 1234') 'Placeholder expansion result is incorrect.'

    # 5. Exceptional exit codes must be recognized as R3 crashes.
    Assert-True (Test-FaultExitCode -ExitCode -1073741819) 'Failed to recognize 0xC0000005 as an abnormal termination.'
    Assert-True (-not (Test-FaultExitCode -ExitCode 3)) 'Misidentified a normal non-zero exit code as an abnormal termination.'

    # 6. Crash attribution: crashes in guarded cases are self-inflicted by the harness; only crashes in probe cases indicate driver defects.
    $crash = [pscustomobject]@{ crashed = $true; lastBootUpTime = 'b1' }
    $guardedRecords = @(
        [pscustomobject]@{ event = 'case-begin'; case = 'guarded.x'; tier = 'guarded' })
    $script:GuardedExecuted = $true
    Assert-True ((Resolve-Attribution -Crash $crash -Records $guardedRecords -PreviousState $null) -eq 'harness-attributable') `
        'Crashes during guarded test case execution were not attributed to harness-attributable.'
    $script:GuardedExecuted = $false
    $probeRecords = @(
        [pscustomobject]@{ event = 'case-begin'; case = 'probe.x'; tier = 'probe' })
    Assert-True ((Resolve-Attribution -Crash $crash -Records $probeRecords -PreviousState $null) -eq 'driver-defect') `
        'Crashes during probe test case execution are not attributed to driver-defect.'
    $previous = [pscustomobject]@{ guardedExecuted = $true; crash = [pscustomobject]@{ lastBootUpTime = 'b1' } }
    Assert-True ((Resolve-Attribution -Crash $crash -Records $probeRecords -PreviousState $previous) -eq 'possibly-self-inflicted-previous-run') `
        'A guarded case ran earlier in this boot, but crash attribution was not downgraded for the PatchGuard delayed-trigger window.'
    Assert-True ((Resolve-Attribution -Crash ([pscustomobject]@{ crashed = $false; lastBootUpTime = 'b1' }) -Records $probeRecords -PreviousState $null) -eq 'none') `
        'When not crashed, the attribution should not be a value other than none.'

    # 7. In-flight test cases at the time of a crash must be reconstructible from partial logs.
    $records = @(
        [pscustomobject]@{ event = 'case-begin'; case = 'a'; tier = 'probe' },
        [pscustomobject]@{ event = 'case-end'; case = 'a'; status = 'passed' },
        [pscustomobject]@{ event = 'case-begin'; case = 'b'; tier = 'probe' })
    $inFlight = Resolve-InFlightCase -Records $records
    Assert-True ($null -ne $inFlight -and $inFlight.case -eq 'b') 'Failed to restore the in-flight test case from the log at the time of the crash.'

    # 8. A new round must be blocked if the previous crash was not located; it can only proceed after confirmation.
    $selfTestState = Join-Path ([System.IO.Path]::GetTempPath()) ("KswordArkDriverCI-selftest-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $selfTestState -Force | Out-Null
    try {
        '{"event":"case-begin","case":"memory.read-phys","tier":"probe"}' |
            Set-Content -LiteralPath (Join-Path $selfTestState 'journal.jsonl') -Encoding UTF8
        '{"runId":"selftest","verdict":"incomplete","guardedExecuted":false,"crash":{"crashed":false,"lastBootUpTime":"b1"}}' |
            Set-Content -LiteralPath (Join-Path $selfTestState 'last-run.json') -Encoding UTF8

        $blocked = $false
        try { Assert-NoUnresolvedPreviousCrash -StateRoot $selfTestState } catch { $blocked = $true }
        Assert-True $blocked 'When unclosed logs from the previous round remain, the new run is not blocked.'

        $released = $true
        try { Assert-NoUnresolvedPreviousCrash -StateRoot $selfTestState -Acknowledged } catch { $released = $false }
        Assert-True $released '-AcknowledgePreviousCrash failed to unblock.'

        '{"runId":"selftest","verdict":"passed","guardedExecuted":false,"crash":{"crashed":false,"lastBootUpTime":"b1"}}' |
            Set-Content -LiteralPath (Join-Path $selfTestState 'last-run.json') -Encoding UTF8
        $released = $true
        try { Assert-NoUnresolvedPreviousCrash -StateRoot $selfTestState } catch { $released = $false }
        Assert-True $released 'A new run should not be blocked when the previous one ended normally.'
    } finally {
        Remove-Item -LiteralPath $selfTestState -Recurse -Force -ErrorAction SilentlyContinue
    }

    # 9. Self-verification of the plan: The probe layer must not include IOCTLs that match dangerous patterns.
    $plan = Get-Content -LiteralPath $PlanPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $patterns = @($plan.policy.mustExcludePatterns)
    foreach ($case in $plan.cases) {
        foreach ($ioctl in $case.ioctls) {
            foreach ($pattern in $patterns) {
                if ($ioctl -match $pattern) {
                    $script:SelfTestFailures += "Test case $($case.id) references an $ioctl that matches a dangerous pattern."
                }
            }
        }
    }

    $failures = $script:SelfTestFailures
    foreach ($message in $failures) { Write-Host "  SELFTEST FAIL $message" }
    if ($failures.Count -gt 0) {
        Write-Host "harness self-check failed: $($failures.Count) items."
        return $script:ExitCaseFailure
    }
    Write-Host 'harness self-check passed: targetGuard, placeholders, exit code judgment, crash attribution, and schedule review all meet expectations.'
    return $script:ExitPass
}

function Main {
    if (-not $RepositoryRoot) {
        $RepositoryRoot = (Resolve-Path (Join-Path $script:ScriptDirectory '..\..')).Path
    }
    if (-not $StateRoot) {
        $StateRoot = Join-Path $env:ProgramData 'KswordARK\driver-functional-ci'
    }
    if (-not $PlanPath) {
        $PlanPath = Join-Path $RepositoryRoot 'tools\driver_functional_ci\driver_test_plan.json'
    }
    if (-not $BinaryDir) {
        $BinaryDir = Join-Path $RepositoryRoot 'artifacts/bin\x64\Release'
    }
    if (-not $ArtifactRoot) {
        $ArtifactRoot = Join-Path $RepositoryRoot 'artifacts\driver-functional-ci'
    }
    if (-not (Test-Path -LiteralPath $ArtifactRoot)) {
        New-Item -ItemType Directory -Path $ArtifactRoot -Force | Out-Null
    }

    # Self-test does not load the driver and requires no admin privileges or test signing, so it is routed before all environment checks.
    if ($Mode -eq 'SelfTest') {
        return (Invoke-SelfTest -PlanPath $PlanPath)
    }
    if (-not (Test-Path -LiteralPath $StateRoot)) {
        New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    }

    $runId = [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $previousState = Get-PreviousRunState -StateRoot $StateRoot
    $journalPath = Join-Path $StateRoot 'journal.jsonl'
    $verdictPath = Join-Path $ArtifactRoot 'verdict.json'

    if ($Mode -eq 'Verify') {
        $records = Read-JournalRecords -Path $journalPath
        $inFlight = Resolve-InFlightCase -Records $records
        $verdict = [ordered]@{
            runId = $runId; mode = 'Verify'
            previousRunId = if ($null -ne $previousState) { $previousState.runId } else { $null }
            inFlightCase = if ($null -ne $inFlight) { $inFlight.case } else { $null }
            previousVerdict = if ($null -ne $previousState) { $previousState.verdict } else { $null }
        }
        $verdict | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $verdictPath -Encoding UTF8
        Write-Step "Verify mode completed, results available at $verdictPath"
        if ($null -ne $previousState -and $previousState.verdict -eq 'incomplete') { return $script:ExitCrash }
        return $script:ExitPass
    }

    if (-not (Test-Administrator)) {
        throw 'Must run as administrator: loading kernel drivers and reading crash evidence both require administrator privileges.'
    }
    if (-not (Test-TestSigningEnabled)) {
        throw 'Current machine does not have test signing mode enabled (run bcdedit /set testsigning on and restart), cannot load test-signed driver.'
    }
    if ($IncludeGuarded -and -not $AcknowledgeGuardedRisk) {
        throw '-IncludeGuarded must be used with -AcknowledgeGuardedRisk: the guarded layer will downgrade crash attribution to harness-attributable.'
    }
    Assert-NoUnresolvedPreviousCrash -StateRoot $StateRoot -Acknowledged:$AcknowledgePreviousCrash

    $cliPath = Join-Path $BinaryDir 'KswordCLI.exe'
    $driverPath = Join-Path $BinaryDir 'KswordARK.sys'
    foreach ($required in @($PlanPath, $cliPath, $driverPath)) {
        if (-not (Test-Path -LiteralPath $required)) { throw "Missing required file: $required" }
    }
    $dumpConfig = Assert-CrashDumpConfigured -AllowConfigure:$ConfigureCrashDump

    $plan = Get-Content -LiteralPath $PlanPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($plan.schemaVersion -ne 1) {
        throw "Unrecognized plan schemaVersion=$($plan.schemaVersion), please synchronize and update this runner."
    }
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "KswordArkDriverCI-$runId"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    $context = @{
        CliPath                 = $cliPath
        ServiceName             = $ServiceName
        TempDir                 = $tempDir
        RegistryTestRoot        = '\REGISTRY\MACHINE\SOFTWARE\KswordARKDriverCI'
        RegistryTestKey         = "\REGISTRY\MACHINE\SOFTWARE\KswordARKDriverCI\run-$runId"
        RegistryTestRenamedLeaf = "run-$runId-renamed"
        RegistryTestRenamedKey  = "\REGISTRY\MACHINE\SOFTWARE\KswordARKDriverCI\run-$runId-renamed"
    }

    $baseline = Get-CrashBaseline
    $script:Journal = Open-Journal -Path $journalPath
    Write-Journal @{
        event = 'run-begin'; runId = $runId; plan = $PlanPath
        includeGuarded = [bool]$IncludeGuarded; lastBootUpTime = $baseline.lastBootUpTime
        driver = $driverPath; cli = $cliPath
    }

    $state = [ordered]@{
        runId = $runId; startedUtc = Get-UtcStamp; verdict = 'incomplete'
        guardedExecuted = $false; crash = @{ crashed = $false; lastBootUpTime = $baseline.lastBootUpTime }
    }
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $StateRoot 'last-run.json') -Encoding UTF8

    $results = @()
    $runError = $null
    try {
        if (-not $SkipDriverLoad) {
            Install-DriverService -ServiceName $ServiceName -DriverPath $driverPath
        }
        if (-not (Test-DriverDeviceAlive -CliPath $cliPath)) {
            throw 'Driver is loaded but control device is unavailable; apps/cli cannot open \\.\KswordARKLog.'
        }
        $variables = Resolve-RuntimeVariables -Context $context
        $results = Invoke-Matrix -Plan $plan -Context $context -Variables $variables
    } catch {
        $runError = $_.Exception.Message
        Write-Warning "Execution interrupted in this round: $runError"
    } finally {
        foreach ($spawned in @($script:SpawnedPids)) { Stop-SacrificialProcess -ProcessId $spawned }
        if (-not $SkipDriverLoad) { Uninstall-DriverService -ServiceName $ServiceName }
        Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'HKLM:\SOFTWARE\KswordARKDriverCI' -Recurse -Force -ErrorAction SilentlyContinue
    }

    $crash = Get-CrashEvidence -Baseline $baseline
    Write-Journal @{ event = 'run-end'; runId = $runId; crashed = $crash.crashed }
    Close-Journal

    $records = Read-JournalRecords -Path $journalPath
    $attribution = Resolve-Attribution -Crash $crash -Records $records -PreviousState $previousState

    $failed = @($results | Where-Object { $_.status -eq 'failed' })
    $skipped = @($results | Where-Object { $_.status -eq 'skipped' })
    $skippedProbe = @($skipped | Where-Object { $_.tier -eq 'probe' })
    $passed = @($results | Where-Object { $_.status -eq 'passed' })

    $exitCode = $script:ExitPass
    $verdictName = 'passed'
    if ($crash.crashed) {
        $exitCode = $script:ExitCrash
        $verdictName = "crashed:$attribution"
    } elseif ($null -ne $runError) {
        $exitCode = $script:ExitCaseFailure
        $verdictName = 'aborted'
    } elseif ($failed.Count -gt 0) {
        $exitCode = $script:ExitCaseFailure
        $verdictName = 'failed'
    } elseif ($FailOnSkippedProbe -and $skippedProbe.Count -gt 0) {
        $exitCode = $script:ExitCaseFailure
        $verdictName = 'failed:skipped-probe'
    }

    $verdict = [ordered]@{
        runId               = $runId
        verdict             = $verdictName
        attribution         = $attribution
        attributionWeakened = [bool]$script:GuardedExecuted
        crash               = $crash
        dumpConfiguration   = $dumpConfig
        abortReason         = $runError
        counts              = [ordered]@{
            total = $results.Count; passed = $passed.Count; failed = $failed.Count
            skipped = $skipped.Count; skippedProbe = $skippedProbe.Count
        }
        results             = $results
        journal             = $journalPath
    }
    $verdict | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $verdictPath -Encoding UTF8

    $state['verdict'] = $verdictName
    $state['guardedExecuted'] = [bool]$script:GuardedExecuted
    $state['crash'] = @{ crashed = $crash.crashed; lastBootUpTime = $crash.lastBootUpTime }
    $state['finishedUtc'] = Get-UtcStamp
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $StateRoot 'last-run.json') -Encoding UTF8

    Write-Host ''
    Write-Host "Result: $verdictName (Passed $($passed.Count) / Failed $($failed.Count) / Skipped $($skipped.Count))"
    if ($crash.crashed) {
        $inFlight = Resolve-InFlightCase -Records $records
        Write-Host "System crash evidence: $($crash.newDumps.Count) dumps, $($crash.events.Count) events, unexpected reboot=$($crash.unexpectedBoot)"
        Write-Host "Executing at crash: $(if ($null -ne $inFlight) { $inFlight.case } else { '<No test case is executing>' })"
        Write-Host "Attribution: $attribution"
    }
    foreach ($item in $failed) { Write-Host "  FAIL $($item.case): $($item.reason)" }
    Write-Host "Verdict file: $verdictPath"
    return $exitCode
}

try {
    $mainResult = Main
    # Main should return only the exit code; if a function leaks objects to the pipeline, take the last value as a fallback.
    if ($mainResult -is [array]) { $mainResult = $mainResult[-1] }
    exit ([int]$mainResult)
} catch {
    Close-Journal
    # Cannot use Write-Error here: ErrorActionPreference=Stop causes it to throw itself.
    # The script exits with code 1 instead of the precheck-specific exit code.
    $Host.UI.WriteErrorLine("[driver-matrix] $($_.Exception.Message)")
    exit $script:ExitPreflight
}
