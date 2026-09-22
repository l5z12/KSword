<#
.SYNOPSIS
    Automated acceptance for KSword in a single command: offline assertion suite + real driver verification
    in nested VMs, producing a machine-readable JSON and a Markdown report ready for acceptance records.

.DESCRIPTION
    Split into three segments, each capable of failing independently without blocking the subsequent parts.

      1. Offline (no VM required, no driver required): Build and run
         KswordARKLightTests. It calls the **production code itself** in
         shared/evidence and shared/driver, not a copy of the logic placed in tests.
         Parse 'N/N checks passed' per suite; any inequality results in FAIL.

      2. Build tools: hvm_probe.exe / hvm_ctl.exe
         (statically linked with /MT; no CRT needed in guest).

      3. On-machine (requires a Hyper-V test machine + loaded driver): Invoke
         Invoke-KswordHvmControl.ps1 to advance the HVM lifecycle and collect its JSON.

    **The semantic distinction is intentional; do not merge.

      PASS Actual run passed with execution evidence. FAIL
      Code or logic failure. BLOCKED Missing hardware
      capability, permissions, signature environment, or
               real samples — not a code issue, but **cannot** be
      recorded as passed. NOT_RUN Not executed.

    The script **will not** modify the host's security configuration, reboot the host, enable Verifier, install
    drivers on the host, or upload any data. The only side effects it causes on the virtual machine are taking
    checkpoints and issuing IOCTLs inside the guest, both of which occur within that isolated, one-time test machine.

.PARAMETER OfflineOnly
    Run only segments 1 and 2. Use this when no VM is available; mark the on-machine portion as NOT_RUN instead of FAIL.

.PARAMETER Stage
    Level passed to Invoke-KswordHvmControl.ps1. Default is safe (up to self-test, not
    resident). To run resident/soak tests, explicitly specify resident, soak, or full.

.EXAMPLE
    .\Invoke-KswordAutomatedAcceptance.ps1
    .\Invoke-KswordAutomatedAcceptance.ps1 -OfflineOnly
    .\Invoke-KswordAutomatedAcceptance.ps1 -Stage soak -SoakMs 5000
#>
[CmdletBinding()]
param(
    [switch] $OfflineOnly,
    # This group must match the ValidateSet in Invoke-KswordHvmControl.ps1 —
    # Two enumerations are two representations of the same contract; changing one and forgetting the other results in the top layer directly rejecting the parameter.
    # Error messages point to 'value not in set' but don't indicate which side is missing. I've encountered this once in practice.
    [ValidateSet('safe', 'status', 'prepare', 'self-test', 'launch-guest',
                 'resident', 'probe-platform', 'probe-flags', 'probe-xonly',
                 'view-probe', 'view-effect',
                 'soak', 'full')]
    [string] $Stage   = 'safe',
    [string] $VMName  = 'KSword-HVM-Target',
    [int]    $SoakMs  = 2000,
    [switch] $SkipBuild
)

$ErrorActionPreference = 'Stop'
$repo   = Split-Path $PSScriptRoot -Parent
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$logDir = Join-Path $repo 'docs\next\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }

$manifestPath = Join-Path $PSScriptRoot 'ksword-expected-suites.json'

$report = [ordered]@{
    schema     = 'ksword.acceptance.autotest/1'
    startedUtc = (Get-Date).ToUniversalTime().ToString('o')
    machine    = [ordered]@{
        computer = $env:COMPUTERNAME
        os       = (Get-CimInstance Win32_OperatingSystem).Caption
        build    = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        cpu      = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    }
    phases     = [ordered]@{}
}

function Resolve-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found, unable to locate MSBuild' }
    $p = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" |
         Select-Object -First 1
    if (-not $p) { throw 'MSBuild.exe not found' }
    return $p
}

# ---------------------------------------------------------------------------
# Phase 1: Offline assertion suite
# ---------------------------------------------------------------------------
Write-Host "=== 1. Offline Assertion Suite (invokes production code itself) ===" -ForegroundColor Cyan
$offline = [ordered]@{ verdict = 'NOT_RUN' }
try {
    $proj = Join-Path $repo 'tests\native\ark_light\KswordARKLightTests.vcxproj'
    $exe  = Join-Path $repo 'tests\native\ark_light\x64\Release\KswordARKLightTests.exe'

    if (-not $SkipBuild) {
        $msb = Resolve-MSBuild
        $buildLog = Join-Path $logDir "autotest-build-$stamp.txt"
        & $msb $proj /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo `
            2>&1 | Tee-Object -FilePath $buildLog | Out-Null
        $offline.buildExit = $LASTEXITCODE
        $offline.buildLog  = $buildLog
        if ($LASTEXITCODE -ne 0) { throw "Build failed, exit code $LASTEXITCODE (see $buildLog)" }
        Write-Host "  [OK]   Build passed" -ForegroundColor Green
    } else {
        $offline.buildExit = 'skipped'
        Write-Host "  [Skip] Reuse existing artifacts with -SkipBuild" -ForegroundColor DarkGray
    }

    if (-not (Test-Path $exe)) { throw "No test artifact $exe" }

    $runLog = Join-Path $logDir "autotest-run-$stamp.txt"
    $raw = & $exe 2>&1 | Out-String
    $offline.runExit = $LASTEXITCODE
    $raw | Set-Content -Path $runLog -Encoding UTF8
    $offline.runLog = $runLog

    # Parse each suite for "<name>: <passed>/<total> checks passed".
    # Checking the exit code alone is insufficient: the exit code is also 0 when an entire suite is not linked in.
    # This is exactly the hole we need to patch (HvmEptSwitchTests was never compiled before).
    $suites = @()
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^\s*(.+?):\s*(\d+)/(\d+)\s+checks passed\s*$') {
            $suites += [pscustomobject]@{
                suite  = $Matches[1].Trim()
                passed = [int]$Matches[2]
                total  = [int]$Matches[3]
            }
        }
    }
    $offline.suites      = $suites
    $offline.suiteCount  = $suites.Count
    $offline.assertions  = ($suites | Measure-Object -Property total  -Sum).Sum
    $offline.passed      = ($suites | Measure-Object -Property passed -Sum).Sum
    $incomplete = @($suites | Where-Object { $_.passed -ne $_.total })

    # For the manifest verification. Checking only for "FAIL" lines fails to detect that **the entire suite was not linked in**:
    # In that case, the test process still exits with code 0 and prints "All passed", but none of the assertions are executed.
    # HvmEptSwitchTests were silently absent for an entire round like this.
    $missing  = @()
    $shrunk   = @()
    $unlisted = @()
    if (Test-Path $manifestPath) {
        $manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $offline.manifest = $manifestPath
        foreach ($want in $manifest.suites) {
            $got = $suites | Where-Object { $_.suite -eq $want.name } | Select-Object -First 1
            if (-not $got) {
                $missing += $want.name
            } elseif ($got.total -lt $want.minAssertions) {
                $shrunk += [pscustomobject]@{ suite = $want.name; now = $got.total; expected = $want.minAssertions }
            }
        }
        $known = @($manifest.suites | ForEach-Object { $_.name })
        $unlisted = @($suites | Where-Object { $known -notcontains $_.suite } | ForEach-Object { $_.suite })
    } else {
        $offline.manifest = "Missing: $manifestPath (unable to verify package completeness)"
    }
    $offline.missingSuites = $missing
    $offline.shrunkSuites  = $shrunk
    $offline.unlistedSuites = $unlisted

    if ($offline.runExit -eq 0 -and $suites.Count -gt 0 -and $incomplete.Count -eq 0 -and
        $missing.Count -eq 0 -and $shrunk.Count -eq 0) {
        $offline.verdict = 'PASS'
        Write-Host ("  [PASS] {0} suites, {1} assertions all passed" -f $suites.Count, $offline.assertions) -ForegroundColor Green
    } else {
        $offline.verdict = 'FAIL'
        $offline.failingSuites = $incomplete
        Write-Host ("  [FAIL] Exit code {0}; {1} suite(s) not fully passed" -f $offline.runExit, $incomplete.Count) -ForegroundColor Red
        foreach ($s in $incomplete) { Write-Host ("         {0}: {1}/{2}" -f $s.suite, $s.passed, $s.total) -ForegroundColor Red }
        foreach ($m in $missing)    { Write-Host ("         Package missing (never linked in?): {0}" -f $m) -ForegroundColor Red }
        foreach ($s in $shrunk)     { Write-Host ("         Assertion count decreased: {0} now {1} items, was {2} items at registration" -f $s.suite, $s.now, $s.expected) -ForegroundColor Red }
    }
    foreach ($u in $unlisted) {
        # Adding new suites is good, but if the manifest isn't updated, no one will notice when they disappear next time.
        Write-Host ("         [Reminder] New suite not in the manifest: {0} — remember to update ksword-expected-suites.json" -f $u) -ForegroundColor Yellow
    }
    foreach ($s in $suites) { Write-Host ("         {0,-24} {1,5}/{2}" -f $s.suite, $s.passed, $s.total) -ForegroundColor DarkGray }
}
catch {
    $offline.verdict = 'FAIL'
    $offline.error = "$($_.Exception.Message)"
    Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
}
$report.phases.offline = $offline

# ---------------------------------------------------------------------------
# Phase 2: Guest tools
# ---------------------------------------------------------------------------
Write-Host "`n=== 2. guest tool compilation ===" -ForegroundColor Cyan
$tools = [ordered]@{ verdict = 'NOT_RUN' }
try {
    & (Join-Path $PSScriptRoot 'Build-KswordHvmTools.ps1') | Out-Host
    $tools.verdict = 'PASS'
    $tools.artifacts = @(
        (Join-Path $repo 'tools\hvm_probe\hvm_probe.exe'),
        (Join-Path $repo 'tools\hvm_ctl\hvm_ctl.exe')
    ) | Where-Object { Test-Path $_ } | ForEach-Object {
        [pscustomobject]@{ path = $_; bytes = (Get-Item $_).Length }
    }
}
catch {
    $tools.verdict = 'FAIL'
    $tools.error = "$($_.Exception.Message)"
    Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
}
$report.phases.tools = $tools

# ---------------------------------------------------------------------------
# Phase 3: On-machine (nested VM + real driver)
# ---------------------------------------------------------------------------
Write-Host "`n=== 3. On-machine verification (nested Hyper-V test target) ===" -ForegroundColor Cyan
$onMachine = [ordered]@{ verdict = 'NOT_RUN' }
if ($OfflineOnly) {
    $onMachine.reason = 'Skip with -OfflineOnly. Mark as NOT_RUN on-machine, do not record PASS or FAIL.'
    Write-Host "  [NOT_RUN] $($onMachine.reason)" -ForegroundColor DarkGray
} elseif ($tools.verdict -ne 'PASS') {
    $onMachine.reason = 'hvm_ctl.exe was not compiled, so the machine-side component cannot run.'
    Write-Host "  [NOT_RUN] $($onMachine.reason)" -ForegroundColor DarkGray
} else {
    try {
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        if ($vm.State -ne 'Running') {
            $onMachine.verdict = 'BLOCKED'
            $onMachine.reason = "Virtual machine $VMName is in state $($vm.State), not started."
            Write-Host "  [BLOCKED] $($onMachine.reason)" -ForegroundColor Yellow
        } else {
            $hvmJson = Join-Path $logDir "hvm-autotest-$stamp.json"
            & (Join-Path $PSScriptRoot 'Invoke-KswordHvmControl.ps1') `
                -Stage $Stage -VMName $VMName -SoakMs $SoakMs -ResultPath $hvmJson | Out-Host
            $hvmExit = $LASTEXITCODE
            $onMachine.controlExit = $hvmExit
            $onMachine.resultPath  = $hvmJson
            if (Test-Path $hvmJson) {
                $detail = Get-Content $hvmJson -Raw -Encoding UTF8 | ConvertFrom-Json
                $onMachine.detail  = $detail
                $onMachine.verdict = switch ($detail.verdict) {
                    'OK'      { 'PASS' }
                    'BLOCKED' { 'BLOCKED' }
                    'NOT_RUN' { 'NOT_RUN' }
                    default   { 'FAIL' }
                }
            } else {
                $onMachine.verdict = 'FAIL'
                $onMachine.reason = 'The HVM control script did not produce a JSON record.'
            }
        }
    }
    catch {
        # VM not existing and an error occurring inside the VM are different: the former is a missing environment (BLOCKED),
        # The latter is the failure. This branch is only reached when Get-VM throws an exception, which belongs to the former case.
        $onMachine.verdict = 'BLOCKED'
        $onMachine.reason = "$($_.Exception.Message)"
        Write-Host "  [BLOCKED] $($onMachine.reason)" -ForegroundColor Yellow
    }
}
$report.phases.onMachine = $onMachine

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
$report.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
$verdicts = @($offline.verdict, $tools.verdict, $onMachine.verdict)
$report.verdict =
    if ($verdicts -contains 'FAIL')       { 'FAIL' }
    elseif ($verdicts -contains 'BLOCKED') { 'BLOCKED' }
    elseif ($verdicts -contains 'NOT_RUN') { 'PARTIAL' }
    else                                   { 'PASS' }

$jsonPath = Join-Path $logDir "acceptance-autotest-$stamp.json"
# JSON must be BOM-free; see the note at the end of the file.
[IO.File]::WriteAllText(
    $jsonPath,
    ($report | ConvertTo-Json -Depth 14),
    (New-Object Text.UTF8Encoding($false)))

$mdPath = Join-Path $logDir "acceptance-autotest-$stamp.md"
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# KSword Automated Acceptance Record")
[void]$md.AppendLine()
[void]$md.AppendLine("Time (UTC): $($report.startedUtc) → $($report.finishedUtc)")
[void]$md.AppendLine("Machine: $($report.machine.os) build $($report.machine.build)")
[void]$md.AppendLine("CPU: $($report.machine.cpu)")
[void]$md.AppendLine()
[void]$md.AppendLine("**Overall Verdict: $($report.verdict)**")
[void]$md.AppendLine()
[void]$md.AppendLine("| Segment | Judgment | Description |")
[void]$md.AppendLine("|---|---|---|")
[void]$md.AppendLine("| Offline Assertion Suite | $($offline.verdict) | $($offline.suiteCount) suites / $($offline.assertions) assertions |")
[void]$md.AppendLine("| guest tools | $($tools.verdict) | hvm_probe + hvm_ctl, /MT static linking |")
[void]$md.AppendLine("| On-Machine Verification | $($onMachine.verdict) | $(if ($onMachine.reason) { $onMachine.reason } else { "Level $Stage" }) |")
[void]$md.AppendLine()
if ($offline.suites) {
    [void]$md.AppendLine("## Offline Package Details")
    [void]$md.AppendLine()
    [void]$md.AppendLine("| Package | Passed | Total |")
    [void]$md.AppendLine("|---|---:|---:|")
    foreach ($s in $offline.suites) { [void]$md.AppendLine("| $($s.suite) | $($s.passed) | $($s.total) |") }
    [void]$md.AppendLine()
}
if ($onMachine.detail) {
    [void]$md.AppendLine("## On-machine steps")
    [void]$md.AppendLine()
    [void]$md.AppendLine("| Step | Result | Description |")
    [void]$md.AppendLine("|---|---|---|")
    foreach ($s in $onMachine.detail.steps) { [void]$md.AppendLine("| $($s.name) | $($s.outcome) | $($s.note) |") }
    [void]$md.AppendLine()
    if ($onMachine.detail.notes) {
        [void]$md.AppendLine("### Remarks")
        [void]$md.AppendLine()
        foreach ($n in $onMachine.detail.notes) { [void]$md.AppendLine("- $n") }
        [void]$md.AppendLine()
    }
}
[void]$md.AppendLine("---")
[void]$md.AppendLine()
[void]$md.AppendLine("BLOCKED indicates missing capability/permission/sample, **not equivalent to passing**; NOT_RUN indicates this section was not executed this time.")
[void]$md.AppendLine("Original JSON: ``$(Split-Path $jsonPath -Leaf)``")
$md.ToString() | Set-Content -Path $mdPath -Encoding UTF8

Write-Host "`n================ Total Verdict: $($report.verdict) ================" -ForegroundColor $(
    switch ($report.verdict) { 'PASS' { 'Green' } 'BLOCKED' { 'Yellow' } 'PARTIAL' { 'Yellow' } default { 'Red' } })
Write-Host "  JSON     : $jsonPath"
Write-Host "  Markdown : $mdPath"

exit $(if ($report.verdict -eq 'FAIL') { 1 } else { 0 })
