# Run in the guest: take two snapshots of the L2 reading and subtract them.
#
# Why take the delta: These counters are cumulative from power-on, while the port I/O during the few dozen seconds of POST
# EPT violations account for the vast majority. The cumulative value answers 'what this machine has done in total', not 'what it is doing now'.
# What '— the same error has already caused me to export three error diagnostics'.
#
# Two supporting rules:
#   1. The event ring returns only 64 lines per iteration; pagination is required, otherwise the desired line silently disappears from the window.
#   2. When a key is missing in the second snapshot, mark it as (missing) instead of treating it as 0 — do not interpret "read failure" as 0.
#      Once reported a non-existent success.
param([int] $Seconds = 60)

function Run($a) {
    $o = 'C:\ksword\ro.txt'
    $e = 'C:\ksword\re.txt'
    $p = Start-Process 'C:\ksword\hvm_ctl.exe' -ArgumentList $a -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $o -RedirectStandardError $e
    if (Test-Path $o) { return [IO.File]::ReadAllText($o) }
    return ''
}

function ReadRing($count) {
    $h = (Run @('--json', 'events', '0')) | ConvertFrom-Json
    $newest = [int64]$h.newestSequence
    $cur = [Math]::Max(0, $newest - $count)
    $all = @()
    while ($cur -lt $newest) {
        $j = (Run @('--json', 'events', "$cur")) | ConvertFrom-Json
        $rows = @($j.rows)
        if ($rows.Count -eq 0) { break }
        $all += $rows
        $cur = [int64]$rows[-1].sequence
    }
    return $all
}

# Compress a single snapshot into a 'key -> value' hash table.
#
# The key must include the core number written by the driver itself, i.e., `access` (= ApicId) in the line, not
# `processor` (the core where the event ring record was published). The first version grouped by `processor`, so two cores
# Counters are written to the same key, causing later writes to overwrite earlier ones; the delta contains a negative increment like -21,208.
# A monotonically increasing counter cannot decrease; a negative value indicates a corrupted signature.
function Snapshot($rows) {
    $m = @{}
    foreach ($r in $rows) {
        $rid = [int]$r.ruleId
        $cpu = "Core $($r.access)"
        if ($rid -eq 251) {
            # 0xFB: Exit reason histogram.
            $m["Exit reason $($r.exitReason) $cpu"] = [uint64]$r.qualification
            $m["L2 total exit $cpu"] = [uint64]$r.guestPhysicalAddress
            $m["vmcs12pin $cpu"] = [uint64]$r.guestLinearAddress
        }
        elseif ($rid -eq 247) {
            # 0xF7: External interrupt and injection.
            $m["External Interrupt $cpu"] = [uint64]$r.qualification
            $m["Inject $cpu"] = [uint64]$r.guestPhysicalAddress
        }
        elseif ($rid -eq 227) {
            # Event delivery aborted on exit with 0xE3: observed / we re-inject / handed to L1 for re-injection.
            # Note: The sum of re-injection and reflection must equal the count seen; the difference represents interrupts that were never injected.
            $m["Abort delivery - encountered $cpu"] = [uint64]$r.qualification
            $m["Abort delivery - retry $cpu"] = [uint64]$r.guestPhysicalAddress
            $m["Abort delivery - reflect $cpu"] = [uint64]$r.guestLinearAddress
            $m["Injected retired $cpu"] = [uint64]$r.guestRip
        }
        elseif ($rid -eq 245) {
            # 0xF5: Device count by port range
            $dev = @('Keyboard 60/64', 'IDE Slave 170', 'IDE Master 1F0', 'VGA 3B0-3DF', 'Serial 3F8-3FF',
                     'Timer 40-43', 'CMOS70/71', 'Other Ports')
            $m["Port $($dev[[int]$r.exitReason]) $cpu"] = [uint64]$r.qualification
        }
        elseif ($rid -eq 250) {
            # 0xFA. Field order copied sequentially from the location in hvm_exit.c where this line is published:
            # qualification=injection request / guestPhysicalAddress=injection /
            # guestLinearAddress = count of exits with IF set / guestRip = count of exits with IF cleared /
            # exitReason: vmcs12 exit control.
            # In the first version, the last three fields were mapped incorrectly, causing '0 on every IF exit' to be misinterpreted as the conclusion.
            # Actually exactly the opposite. **Field mappings must be copied from the publish point; do not guess based on field names.**
            $m["Injection request $cpu"] = [uint64]$r.qualification
            $m["Inject $cpu(FA)"] = [uint64]$r.guestPhysicalAddress
            $m["IF=1 Exit $cpu"] = [uint64]$r.guestLinearAddress
            $m["IF=0 Exit $cpu"] = [uint64]$r.guestRip
            $m["vmcs12exit $cpu"] = [uint64]$r.exitReason
        }
    }
    return $m
}

$a = Snapshot (ReadRing 1600)
Write-Output ("First snapshot " + $a.Count + " keys")
Start-Sleep -Seconds $Seconds
$b = Snapshot (ReadRing 1600)
Write-Output ("Second snapshot " + $b.Count + " keys, interval ${Seconds}s")
Write-Output ''

$keys = @($a.Keys) + @($b.Keys) | Sort-Object -Unique
foreach ($k in $keys) {
    $has1 = $a.ContainsKey($k)
    $has2 = $b.ContainsKey($k)
    if (-not $has1 -or -not $has2) {
        Write-Output ("  {0,-28} {1,18} -> {2,18}   (missing, not participating in delta)" -f $k,
            $(if ($has1) { $a[$k] } else { '(Missing)' }),
            $(if ($has2) { $b[$k] } else { '(Missing)' }))
        continue
    }
    $d = [int64]$b[$k] - [int64]$a[$k]
    $mark = ''
    if ($d -ne 0) { $mark = '  <<<' }
    Write-Output ("  {0,-28} {1,18} -> {2,18}   Incremental {3}{4}" -f $k, $a[$k], $b[$k], $d, $mark)
}
