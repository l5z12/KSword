# R-1 injection validation for shared image pages.
#
# This is the only truly challenging scenario for CR3 scope checks. Previous rounds of target pages were process-private: the probe page is
# VirtualAlloc'd, hvm_target's .text is mapped only by itself. System DLLs (ntdll, ...)
# kernel32 code pages are mapped to the same guest physical page by every process—the view is attached to that physical page,
# Visible across the entire machine; without comparing CR3, any process executing on that page will be hijacked to run the payload.
#
# Three criteria:
#   A The target process's marker changed — the payload ran on it.
#   B The marker for the **control process** remains unchanged — the scope is effective. This is the key point of this round: running two simultaneously
#     Identical targets: inject into only one; the other must remain completely unharmed.
#   The heartbeats of both C processes continue to advance; neither is damaged.
param([string] $VMName = 'KSword-HVM-Target')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$cred = New-Object System.Management.Automation.PSCredential(
    'felix', (ConvertTo-SecureString 'password' -AsPlainText -Force))
$repo = 'C:\Users\Felix\CLionProjects\KSword'

function Guest([scriptblock] $s, $a) {
    if ($null -eq $a) { Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $s }
    else { Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $s -ArgumentList $a }
}
function Ctl([string[]] $a) {
    Guest { param($x)
        $o = & 'C:\ksword\hvm_ctl.exe' @x 2>&1 | Out-String
        [pscustomobject]@{ exit = $LASTEXITCODE; text = $o }
    } (,$a)
}
function Push-Tool([string] $src, [string] $dst) {
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($src))
    Guest { param($d,$t)
        New-Item -ItemType Directory -Force -Path (Split-Path $t) | Out-Null
        [IO.File]::WriteAllBytes($t, [Convert]::FromBase64String($d))
    } @($b64,$dst)
}

Write-Output "=== 0. Injection ==="
Guest { Get-Process -Name 'hvm_target' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
Push-Tool (Join-Path $repo 'tools\hvm_ctl\hvm_ctl.exe') 'C:\ksword\hvm_ctl.exe'
Push-Tool (Join-Path $repo 'tools\hvm_target\hvm_target.exe') 'C:\ksword\hvm_target.exe'

Write-Output "`n=== 1. Clean Starting Point ==="
foreach ($v in @('inject-release-all','proc-release-all','stop','teardown','reset-fault')) {
    $null = Ctl @($v)
}
Write-Output "  Reset complete"

Write-Output "`n=== 2. Launch two identical test targets ==="
$pair = Guest {
    $r = @()
    foreach ($tag in @('A','B')) {
        $log = "C:\ksword\target-shared-$tag.log"
        if (Test-Path $log) { Remove-Item $log -Force }
        $p = Start-Process -FilePath 'C:\ksword\hvm_target.exe' `
            -RedirectStandardOutput $log -PassThru -WindowStyle Hidden
        $r += [pscustomobject]@{ tag = $tag; pid = $p.Id; log = $log }
    }
    Start-Sleep -Seconds 2
    foreach ($e in $r) {
        $x = Get-Content $e.log
        $e | Add-Member -NotePropertyName loop -NotePropertyValue `
            ((($x | Where-Object { $_ -like 'loop *' } | Select-Object -First 1) -replace '^loop 0x',''))
        $e | Add-Member -NotePropertyName marker -NotePropertyValue `
            ((($x | Where-Object { $_ -like 'marker *' } | Select-Object -First 1) -replace '^marker 0x',''))
    }
    $r
}
foreach ($e in $pair) {
    Write-Output "  Test target $($e.tag): pid=$($e.pid) loop=0x$($e.loop) marker=0x$($e.marker)"
}
$targetA = $pair | Where-Object { $_.tag -eq 'A' }
$targetB = $pair | Where-Object { $_.tag -eq 'B' }
# The .text section of the same exe is the **same guest physical page** (image section sharing) in both instances.
# If the loop linear addresses on both sides are identical, it is the result of ASLR re-mapping only once per startup, which is exactly what we want.
Write-Output "  Both loop linear addresses are the same: $($targetA.loop -eq $targetB.loop)"

Write-Output "`n=== 3. Prerequisites ==="
$null = Ctl @('cr-track-cr3-on')
$r = Ctl @('prepare-eptpsw'); Write-Output "  prepare-eptpsw exit=$($r.exit)"
if ($r.exit -ne 0) { Write-Output $r.text; exit 1 }

Write-Output "`n=== 4. Inject only into test target A ==="
$r = Ctl @('inject-test', "$($targetA.pid)", $targetA.loop, $targetA.marker)
Write-Output "  inject-test(A) exit=$($r.exit)`n$($r.text)"
if ($r.exit -ne 0) { Write-Output "Installation failed, aborting"; exit 1 }

Write-Output "`n=== 5. Start resident hypervisor, observe for 15 seconds ==="
$null = Ctl @('self-test')
$r = Ctl @('resident'); Write-Output "  resident exit=$($r.exit)"
if ($r.exit -ne 0) { Write-Output $r.text; exit 1 }
Start-Sleep -Seconds 15

$obs = Guest { param($pa, $la, $pb, $lb)
    function Snap($p, $l) {
        $lines = @(Get-Content $l -ErrorAction SilentlyContinue)
        $ticks = @($lines | Where-Object { $_ -like 'tick *' })
        [pscustomobject]@{
            alive  = [bool](Get-Process -Id $p -ErrorAction SilentlyContinue)
            last   = ($ticks | Select-Object -Last 1)
            marked = @($ticks | Where-Object { $_ -notlike '*marker 00000000*' }).Count
        }
    }
    [pscustomobject]@{ a = (Snap $pa $la); b = (Snap $pb $lb) }
} @($targetA.pid, $targetA.log, $targetB.pid, $targetB.log)

Write-Output "  A(target)  alive=$($obs.a.alive)  heartbeat=$($obs.a.last)  marked non-zero lines=$($obs.a.marked)"
Write-Output "  B(Reference)  Alive=$($obs.b.alive)  Heartbeat=$($obs.b.last)  Marked Non-zero Lines=$($obs.b.marked)"
$r = Ctl @('--json','inject-query'); Write-Output "  inject-query: $($r.text)"

Write-Output "`n=== 6. Wait another 6 seconds to confirm neither side has been damaged ==="
Start-Sleep -Seconds 6
$obs2 = Guest { param($pa, $la, $pb, $lb)
    function Snap($p, $l) {
        $lines = @(Get-Content $l -ErrorAction SilentlyContinue)
        $ticks = @($lines | Where-Object { $_ -like 'tick *' })
        [pscustomobject]@{
            alive = [bool](Get-Process -Id $p -ErrorAction SilentlyContinue)
            last  = ($ticks | Select-Object -Last 1)
        }
    }
    [pscustomobject]@{ a = (Snap $pa $la); b = (Snap $pb $lb) }
} @($targetA.pid, $targetA.log, $targetB.pid, $targetB.log)
Write-Output "  A alive=$($obs2.a.alive) heartbeat=$($obs2.a.last)"
Write-Output "  B Alive=$($obs2.b.alive) Heartbeat=$($obs2.b.last)"

function TickNo($s) { if ($s -match '^tick (\d+)') { [int]$matches[1] } else { -1 } }
$aAdv = (TickNo $obs2.a.last) -gt (TickNo $obs.a.last)
$bAdv = (TickNo $obs2.b.last) -gt (TickNo $obs.b.last)
Write-Output "`n>>> A payload execution : $(if ($obs.a.marked -gt 0) { 'PASS' } else { 'FAIL (target marker is always 0)' })"
Write-Output ">>> B not affected   : $(if ($obs.b.marked -eq 0) { 'PASS (control marker always 0)' } else { "FAIL (control also executed payload, $($obs.b.marked) non-zero lines)" })"
Write-Output ">>> C both sides intact: $(if ($obs2.a.alive -and $obs2.b.alive -and $aAdv -and $bAdv) { 'PASS' } else { "FAIL (A alive=$($obs2.a.alive) A advanced=$aAdv B alive=$($obs2.b.alive) B advanced=$bAdv)" })"

Write-Output "`n=== 7. Cleanup ==="
$null = Ctl @('stop'); $null = Ctl @('inject-release-all'); $null = Ctl @('teardown')
Guest { Get-Process -Name 'hvm_target' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue }
Write-Output "  Done"
