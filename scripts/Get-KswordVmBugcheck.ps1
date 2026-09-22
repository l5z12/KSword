<#
.SYNOPSIS
    Blue screen forensics: retrieve the guest's bugcheck code and minidump to the host for direct analysis.

.DESCRIPTION
    When hung, nothing can be read inside the guest; only host counters are available. **A BSOD is different**
    — it leaves a bugcheck code and a dump. This script walks that entire evidence chain in one go:

      1. If the VM is not running, start it and wait for PowerShell Direct to recover.
      2. Read guest crash configuration (CrashDumpEnabled / AutoReboot / DumpPath);
      3. Read BugCheck records from the System event log (WER-SystemErrorReporting
         1001 and Kernel-Power 41; the latter's XML directly contains BugcheckCode);
      4) Copy the latest minidump to the host docs/next/logs/ using PSSession;
      5. Run !analyze -v directly on the host using kd -z and save the output to disk.

    Read-only evidence collection: do not change any guest settings, do not reboot, and do not modify VM configuration (except for necessary boot).

.NOTES
    Crash dumps failing to write is normal, not a script bug: CrashDumpEnabled might be 0, or the page file is
    smaller than the minimum dump size. The script will **explicitly report which case it is**, rather than
    vaguely saying "dump not found"—that vagueness is exactly what has caused repeated wasted time on this line.
#>

[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [int]    $WaitSeconds   = 300,
    # Collect evidence only; do not run kd (e.g., debugger not installed on host).
    [switch] $SkipAnalyze
)

$ErrorActionPreference = 'Stop'
$repo   = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repo 'docs\next\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$NL     = [Environment]::NewLine

function Write-Head { param([string] $T) Write-Host ''; Write-Host "=== $T ===" -ForegroundColor Cyan }

# --- 1. VM Status ---------------------------------------------------------
Write-Head 'Virtual Machine Status'
$vm = Get-VM -Name $VMName -ErrorAction Stop
Write-Host ('{0}  state={1}  uptime={2}' -f $vm.Name, $vm.State, $vm.Uptime)

if ($vm.State -ne 'Running') {
    Write-Host "Virtual machine is not running ($($vm.State)), starting..." -ForegroundColor Yellow
    if ($vm.State -eq 'Paused') { Resume-VM -Name $VMName } else { Start-VM -Name $VMName }
}

$cred = New-Object System.Management.Automation.PSCredential(
            $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

Write-Host "Waiting for PowerShell Direct (up to $WaitSeconds seconds)..."
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$session  = $null
while ((Get-Date) -lt $deadline) {
    try {
        $session = New-PSSession -VMName $VMName -Credential $cred -ErrorAction Stop
        break
    } catch { Start-Sleep -Seconds 5 }
}
if (-not $session) {
    Write-Host 'PowerShell Direct has not started. The guest is likely stuck on the blue screen (AutoReboot is off).' -ForegroundColor Red
    Write-Host 'Open vmconnect to check the bugcheck code on the screen, or pull the power to reboot:' -ForegroundColor Yellow
    Write-Host "  Stop-VM -Name '$VMName' -TurnOff -Force; Start-VM -Name '$VMName'"
    exit 2
}

$report = [ordered]@{
    vm        = $VMName
    stampUtc  = (Get-Date).ToUniversalTime().ToString('o')
    crashCfg  = $null
    bugchecks = @()
    dumps     = @()
    copied    = $null
    analyzed  = $null
}

# --- 2. Crash dump configuration -------------------------------------------------------
Write-Head 'guest crash dump configuration'
$report.crashCfg = Invoke-Command -Session $session -ScriptBlock {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue |
              Select-Object -First 1 -ExpandProperty AllocatedBaseSize
    [ordered]@{
        # 0=No dump, 1=Full, 2=Kernel, 3=Small (minidump), 7=Automatic
        CrashDumpEnabled = $p.CrashDumpEnabled
        AutoReboot       = $p.AutoReboot
        DumpFile         = $p.DumpFile
        MinidumpDir      = $p.MinidumpDir
        PagefileMB       = $pf
    }
}
foreach ($kv in $report.crashCfg.GetEnumerator()) {
    Write-Host ('  {0,-17}: {1}' -f $kv.Key, $kv.Value)
}
if ($report.crashCfg.CrashDumpEnabled -eq 0) {
    Write-Host '  ** CrashDumpEnabled = 0: This machine does not write dumps at all.**' -ForegroundColor Red
    Write-Host '     The bugcheck code still appears in the event log; keep reading.' -ForegroundColor Yellow
}

# --- 3. BugCheck in Event Log ---------------------------------------------
Write-Head 'Event Log: BugCheck'
$report.bugchecks = @(Invoke-Command -Session $session -ScriptBlock {
    $out = @()
    # 1001 / WER-SystemErrorReporting: The message contains the complete bugcheck parameter string.
    try {
        $out += Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
                    Id = 1001
                } -MaxEvents 5 -ErrorAction Stop |
                ForEach-Object {
                    [ordered]@{ time = $_.TimeCreated.ToString('o'); id = 1001; text = $_.Message }
                }
    } catch { }
    # 41 / Kernel-Power: Abnormal shutdown; the XML directly contains BugcheckCode.
    try {
        $out += Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ProviderName = 'Microsoft-Windows-Kernel-Power'
                    Id = 41
                } -MaxEvents 5 -ErrorAction Stop |
                ForEach-Object {
                    $x  = [xml]$_.ToXml()
                    $d  = $x.Event.EventData.Data
                    $bc = ($d | Where-Object { $_.Name -eq 'BugcheckCode' }).'#text'
                    $p1 = ($d | Where-Object { $_.Name -eq 'BugcheckParameter1' }).'#text'
                    $p2 = ($d | Where-Object { $_.Name -eq 'BugcheckParameter2' }).'#text'
                    $p3 = ($d | Where-Object { $_.Name -eq 'BugcheckParameter3' }).'#text'
                    $p4 = ($d | Where-Object { $_.Name -eq 'BugcheckParameter4' }).'#text'
                    [ordered]@{
                        time = $_.TimeCreated.ToString('o')
                        id   = 41
                        text = ('BugcheckCode={0} (0x{0:X})  P1={1} P2={2} P3={3} P4={4}' -f
                                    [int]$bc, $p1, $p2, $p3, $p4)
                    }
                }
    } catch { }
    $out
})
if ($report.bugchecks.Count -eq 0) {
    Write-Host '  (No bugcheck event found — either it didn''t crash, or the logs haven''t been written to disk yet)' -ForegroundColor Yellow
} else {
    foreach ($b in $report.bugchecks) {
        Write-Host ('  [{0}] id={1}' -f $b.time, $b.id) -ForegroundColor Green
        foreach ($line in (($b.text -split "`r?`n") | Select-Object -First 5)) {
            if ($line.Trim()) { Write-Host "     $($line.Trim())" }
        }
    }
}

# --- 4. Retrieve dump -------------------------------------------------------------
Write-Head 'Dump File'
$report.dumps = @(Invoke-Command -Session $session -ScriptBlock {
    $r = @()
    foreach ($d in @('C:\Windows\Minidump', 'C:\Windows')) {
        if (Test-Path $d) {
            $r += Get-ChildItem -Path $d -Filter '*.dmp' -File -ErrorAction SilentlyContinue |
                  ForEach-Object {
                      [ordered]@{
                          path = $_.FullName
                          mb   = [math]::Round($_.Length / 1MB, 2)
                          utc  = $_.LastWriteTimeUtc.ToString('o')
                      }
                  }
        }
    }
    $r
})
if ($report.dumps.Count -eq 0) {
    Write-Host '  (guest has no .dmp)' -ForegroundColor Yellow
} else {
    foreach ($d in $report.dumps) { Write-Host ('  {0}  {1} MB  {2}' -f $d.path, $d.mb, $d.utc) }
    # Use a script block for sorting, not `Sort-Object utc`.
    #
    # These records arrive via PowerShell Direct as **hash tables**, and Sort-Object sorts by
    # *Property name* binding — hash tables do not expose keys as properties, so the key for each item is $null,
    # Sorting degrades to stable sort and returns the first element as-is. In practice, this caused retrieval of dumps from several hours ago,
    # Analysis reveals the previous bugcheck code, which appears to indicate the same bug has occurred again.
    # `{ $_.utc }` uses member access, which is valid on hash tables.
    $newest = $report.dumps | Sort-Object -Property { $_.utc } -Descending |
              Select-Object -First 1
    $local  = Join-Path $logDir ("bugcheck-$stamp-" + (Split-Path $newest.path -Leaf))
    Write-Host "  Retrieving the latest one: $($newest.path)" -ForegroundColor Green
    Copy-Item -FromSession $session -Path $newest.path -Destination $local -Force
    $report.copied = $local
    Write-Host ('  -> {0}  ({1:N2} MB)' -f $local, ((Get-Item $local).Length / 1MB))
}

Remove-PSSession $session

# --- 5. Direct analysis -----------------------------------------------------------
if ($report.copied -and -not $SkipAnalyze) {
    Write-Head 'kd !analyze -v'
    $kd = @(
        'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe',
        'C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $kd) {
        Write-Host '  kd.exe not found, skipping analysis. Dump is already on the host.' -ForegroundColor Yellow
    } else {
        $sym = 'srv*C:\symbols*https://msdl.microsoft.com/download/symbols;' +
               (Join-Path $repo 'artifacts/bin\x64\Release\KswordARKDriver')
        $out = Join-Path $logDir "bugcheck-$stamp-analyze.txt"
        # Commands are chained with semicolons; 'q' exits at the end; -logo writes all output to disk.
        & $kd -z $report.copied -y $sym -logo $out -c '!analyze -v; lm m Ksword*; kb; q' 2>&1 | Out-Null
        $report.analyzed = $out
        if (Test-Path $out) {
            Write-Host "  Full output: $out" -ForegroundColor Cyan
            $lines = [IO.File]::ReadAllLines($out)
            foreach ($pat in @('Bugcheck code', 'BugCheck ', 'PROCESS_NAME', 'MODULE_NAME',
                               'IMAGE_NAME', 'FAILURE_BUCKET_ID', 'Probably caused by')) {
                $m = $lines | Select-String -SimpleMatch $pat | Select-Object -First 1
                if ($m) { Write-Host ('  {0}' -f $m.Line.Trim()) -ForegroundColor Green }
            }

            # Cross-verification: The analyzed bugcheck code must match the latest entry in the event log.
            #
            # This is the final safeguard against 'analyzing an old dump'. An outdated dump will provide a
            # A story that is internally consistent yet completely wrong — the code, stack, and bucket of the previous crash
            # All pieces are present, looking like the same bug happened again, while the real one this time was never seen.
            # In practice, encountered a case where sorting degradation retrieved dumps from several hours ago.
            $analyzedCode = ($lines | Select-String -Pattern '^BUGCHECK_CODE:\s*([0-9a-fA-F]+)' |
                             Select-Object -First 1)
            $eventCode = $null
            foreach ($b in $report.bugchecks) {
                if ($b.text -match 'bugcheck was:\s*0x([0-9a-fA-F]+)') { $eventCode = $Matches[1]; break }
                if ($b.text -match 'BugcheckCode=\d+\s*\(0x([0-9a-fA-F]+)\)') { $eventCode = $Matches[1]; break }
            }
            if ($analyzedCode -and $eventCode) {
                $a = ([int]("0x" + $analyzedCode.Matches[0].Groups[1].Value))
                $e = ([int]("0x" + $eventCode))
                if ($a -ne $e) {
                    Write-Host ''
                    Write-Host ("  ** Analyzing the wrong dump ** The latest event log entry is 0x{0:X}," -f $e) -ForegroundColor Red
                    Write-Host ("     But this dump shows 0x{0:X}. The stack and bucket below belong to the **previous** crash," -f $a) -ForegroundColor Red
                    Write-Host '     Do not attribute this to the current run. Manually select the .dmp file corresponding to the time and rerun.' -ForegroundColor Red
                    [void]($report.GetEnumerator())
                    $report.analyzed = "$out (MISMATCH: event=0x$('{0:X}' -f $e) dump=0x$('{0:X}' -f $a))"
                } else {
                    Write-Host ("  [OK]   Consistent with event log: 0x{0:X}" -f $e) -ForegroundColor Green
                }
            }
        }
    }
}

$jsonPath = Join-Path $logDir "bugcheck-$stamp.json"
# JSON must be BOM-free; see the note at the end of the file.
[IO.File]::WriteAllText(
    $jsonPath,
    ($report | ConvertTo-Json -Depth 8),
    (New-Object Text.UTF8Encoding($false)))
Write-Host ''
Write-Host "Record written to $jsonPath" -ForegroundColor Cyan
