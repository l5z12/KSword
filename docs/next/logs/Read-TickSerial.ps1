# Decode tickprobe serial logs and provide a time-series summary.
#
# Why decoding is required: VMware's virtual UART stops at a **5-bit word length** (Line Control Register) after BIOS.
# For 0), so each transmitted byte retains only its lower 5 bits. The file appears to contain a bunch of control characters, but the data
# Nothing was lost: '0'..'9' (30h..39h) masked to 10h..19h, 'A'..'F' (41h..46h) masked to
# 0x01..0x06, two non-overlapping segments; CR/LF are naturally < 0x20 and unaffected. Thus, unambiguous restoration is possible.
#
# The probe later sets LCR to 8-bit word length on its own, but **the already recorded logs still rely on this section for restoration**.
# Keeping it is cheaper than "re-running": that takes ten-plus minutes and a reboot.
#
# Line format: SPIN(8) TICK(8) OWN(8) PIT(4) IRR(2) ISR(2) SIRR(2) SISR(2) RTC(2),
# Fixed width, CRLF line endings.
param(
    [string] $Path = 'C:\vmware\probe-serial.log'
)

$fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite)
$raw = New-Object byte[] $fs.Length
[void]$fs.Read($raw, 0, $raw.Length)
$fs.Close()

# Both encodings must be recognized: the probe now sets LCR to 8-bit word length, so subsequent bytes are normal ASCII.
# Logs recorded before that point are masked to the lower 5 bits. Since the two value ranges do not overlap, the same decoder can handle both.
# Can be read simultaneously; no need for readers to know the log version beforehand.
$sb = New-Object Text.StringBuilder
foreach ($b in $raw) {
    if (($b -ge 0x30 -and $b -le 0x39) -or ($b -ge 0x41 -and $b -le 0x46)) {
        [void]$sb.Append([char]$b)                       # 8-bit word length, pass-through
    }
    elseif ($b -ge 0x10 -and $b -le 0x19) { [void]$sb.Append([char](0x30 + ($b - 0x10))) }
    elseif ($b -ge 0x01 -and $b -le 0x06) { [void]$sb.Append([char](0x41 + ($b - 0x01))) }
    elseif ($b -eq 0x0D -or $b -eq 0x0A) { [void]$sb.Append([char]$b) }
    else { [void]$sb.Append('?') }   # Bytes that cannot be restored are explicitly marked; do not silently discard them.
}

$lines = @($sb.ToString() -split "`r`n" | Where-Object { $_.Length -eq 38 })
$bad = @($sb.ToString() -split "`r`n" | Where-Object { $_.Length -ne 38 -and $_.Length -gt 0 })
Write-Output ("Full line = {0}   Lines not 38 wide = {1}   Lines containing ? = {2}" -f `
    $lines.Count, $bad.Count, @($lines | Where-Object { $_.Contains('?') }).Count)

function Field($s, $off, $len) { return $s.Substring($off, $len) }

$rows = foreach ($s in $lines) {
    [PSCustomObject]@{
        SPIN = Field $s 0 8
        TICK = Field $s 8 8
        OWN  = Field $s 16 8
        PIT  = Field $s 24 4
        IRR  = Field $s 28 2
        ISR  = Field $s 30 2
        SIRR = Field $s 32 2
        SISR = Field $s 34 2
        RTC  = Field $s 36 2
    }
}

function Show($r, $tag) {
    Write-Output ("  {0,-6} SPIN={1} TICK={2} OWN={3} PIT={4} IRR={5} ISR={6} SIRR={7} SISR={8} RTC={9}" -f `
        $tag, $r.SPIN, $r.TICK, $r.OWN, $r.PIT, $r.IRR, $r.ISR, $r.SIRR, $r.SISR, $r.RTC)
}

Write-Output '=== Start and End ==='
Show $rows[0] 'First'
Show $rows[[int]($rows.Count/2)] 'middle'
Show $rows[-1] 'Tail'

Write-Output '=== Values taken by each field (all criteria are here) ==='
foreach ($f in 'TICK', 'OWN', 'IRR', 'ISR', 'SIRR', 'SISR') {
    $u = @($rows | ForEach-Object { $_.$f } | Select-Object -Unique)
    Write-Output ("  {0,-5} total {1,5} distinct values: {2}" -f $f, $u.Count,
        (($u | Select-Object -First 10) -join ' '))
}
foreach ($f in 'PIT', 'RTC') {
    $u = @($rows | ForEach-Object { $_.$f } | Select-Object -Unique)
    Write-Output ("  {0,-5} total {1,5} distinct values (first 10): {2}" -f $f, $u.Count,
        (($u | Select-Object -First 10) -join ' '))
}

# RTC uses BCD seconds, cycling 0..59. Its progression indicates that VMware's virtual time is advancing.
# This is unrelated to whether the PIT raises an interrupt — they are two independent clocks; only by examining them separately can we determine which segment is faulty.
$rtcChanges = 0
for ($i = 1; $i -lt $rows.Count; $i++) {
    if ($rows[$i].RTC -ne $rows[$i-1].RTC) { $rtcChanges++ }
}
Write-Output ("=== RTC second change count = {0} (time series covers {1} rows)" -f $rtcChanges, $rows.Count)

$pitChanges = 0
for ($i = 1; $i -lt $rows.Count; $i++) {
    if ($rows[$i].PIT -ne $rows[$i-1].PIT) { $pitChanges++ }
}
Write-Output ("=== PIT count changes = {0}" -f $pitChanges)
