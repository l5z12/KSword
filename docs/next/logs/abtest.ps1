# Host-side A/B: Under identical idle conditions, compare the two resident modes: 'hidden mode off' vs. 'hidden mode on'.
#
# 12:42:55: The 0xA incident occurred when the machine was idle, no user was logged in, and VMware was not running; our frames were absent from the stack.
# This round answers only one question: **Will hidden mode crash the machine**? Thus, the two phases differ by only that one bit,
# Everything else remains identical, with the host handling timing and liveness checks—the guest may crash while the host continues.
param([int] $PhaseSeconds = 300)

$ErrorActionPreference = 'Continue'
$VMName = 'KSword-HVM-Target'
$cred = New-Object System.Management.Automation.PSCredential(
    'felix', (ConvertTo-SecureString 'password' -AsPlainText -Force))

function Note($s) {
    $line = ('[{0:HH:mm:ss}] {1}' -f (Get-Date), $s)
    Write-Host $line
    [IO.File]::AppendAllText('C:\Users\Felix\CLionProjects\KSword\docs\next\logs\abtest.log', $line + [Environment]::NewLine)
}

function GuestBoot {
    try {
        return [datetime](Invoke-Command -VMName $VMName -Credential $cred -ErrorAction Stop -ScriptBlock {
            (Get-CimInstance Win32_OperatingSystem).LastBootUpTime })
    } catch { return $null }
}

function Ctl($verb) {
    try {
        return Invoke-Command -VMName $VMName -Credential $cred -ErrorAction Stop -ScriptBlock {
            param($v)
            $o = 'C:\ksword\abo.txt'
            $p = Start-Process 'C:\ksword\hvm_ctl.exe' -ArgumentList @('--json', $v) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError 'C:\ksword\abe.txt'
            @{ Exit = $p.ExitCode; Out = [IO.File]::ReadAllText($o) }
        } -ArgumentList $verb
    } catch { return $null }
}

function RunPhase($name, $verb) {
    Note ('--- ' + $name + ' ---')
    $boot0 = GuestBoot
    Note ('  Boot time ' + $boot0)

    $r = Ctl 'status'
    $st = $null
    if ($r) { try { $st = $r.Out | ConvertFrom-Json } catch { } }
    if ($st -and ($st.stateNames -contains 'RESIDENT_ACTIVE')) { $null = Ctl 'stop' }
    $r = Ctl 'status'
    if ($r) { try { $st = $r.Out | ConvertFrom-Json } catch { } }
    if ($st -and (($st.stateNames -contains 'FAULTED') -or ($st.stateNames -contains 'ROLLBACK_REQUIRED'))) { $null = Ctl 'reset-fault' }
    if ($st -and -not ($st.stateNames -contains 'RESOURCES_READY')) { $null = Ctl 'prepare' }
    $r = Ctl 'status'
    if ($r) { try { $st = $r.Out | ConvertFrom-Json } catch { } }
    if ($st -and -not ($st.stateNames -contains 'SELF_TEST_PASSED')) { $null = Ctl 'self-test' }

    $r = Ctl $verb
    if ($null -eq $r -or $r.Exit -ne 0) { Note ('  ' + $verb + '  failed to start, exit=' + $(if ($r) { $r.Exit } else { 'N/A' })); return 'BRINGUP_FAILED' }
    Note ('  ' + $verb + '  started')
    $cv = Ctl 'cpuid-view'
    if ($cv) { Note ('  cpuid-view ' + $cv.Out.Trim()) }

    $deadline = (Get-Date).AddSeconds($PhaseSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 20
        $b = GuestBoot
        if ($null -eq $b) { Note '  **Guest does not respond**'; return 'UNRESPONSIVE' }
        if ([math]::Abs(($b - $boot0).TotalSeconds) -ge 2) { Note ('  **Guest has rebooted** ' + $boot0 + ' -> ' + $b); return 'REBOOTED' }
    }
    Note ('  ' + $PhaseSeconds + '  seconds passed without restart or disconnection')
    return 'SURVIVED'
}

[IO.File]::WriteAllText('C:\Users\Felix\CLionProjects\KSword\docs\next\logs\abtest.log', '')
Note '=== A/B Start ==='
$a = RunPhase 'Phase A: No hidden (resident-nested)' 'resident-nested'
Note ('Phase A result ' + $a)
$b = RunPhase 'Phase B: Enable hidden (resident-nested-hidehv)' 'resident-nested-hidehv'
Note ('Phase B result ' + $b)
$null = Ctl 'stop'
Note ('=== Done A=' + $a + ' B=' + $b + ' ===')
