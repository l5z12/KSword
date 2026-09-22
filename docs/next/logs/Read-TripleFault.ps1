# Host side: Retrieve and read the lines containing the triple fault context from the target machine's event ring.
#
# Read only 0xD3 (the three descriptor tables loaded in vmcs02 at that time and the per-field mask against vmcs12) and
# 0xD2 (how many times L1 wrote to the IDTR base address and what the last value was). These two lines must be viewed together:
# Looking at 0xD3's "IDTR base = 0" alone cannot distinguish between "L1 never wrote" and "we lost it",
# Linux's IDT is at 0xFFFFFE0000000000; the lower 32 bits are all zeros, so both interpretations yield the same value.
#
# Ring once returns only 64 lines, requiring pagination; if the line isn't found, output "(no such line)" instead of treating it as zero.
param(
    [string] $VMName = 'KSword-HVM-Target',
    [int]    $Depth  = 4000
)

$ErrorActionPreference = 'Stop'
$cred = New-Object PSCredential('felix',
    (ConvertTo-SecureString 'password' -AsPlainText -Force))
$s = New-PSSession -VMName $VMName -Credential $cred

$rows = Invoke-Command -Session $s -ArgumentList $Depth -ScriptBlock {
    param($depth)

    function Run($a) {
        $o = 'C:\ksword\tfo.txt'
        $e = 'C:\ksword\tfe.txt'
        Start-Process 'C:\ksword\hvm_ctl.exe' -ArgumentList $a -NoNewWindow -Wait `
            -RedirectStandardOutput $o -RedirectStandardError $e | Out-Null
        if (Test-Path $o) { return [IO.File]::ReadAllText($o) }
        return ''
    }

    $h = (Run @('--json', 'events', '0')) | ConvertFrom-Json
    $newest = [int64]$h.newestSequence
    $cur = [Math]::Max(0, $newest - $depth)
    $all = @()
    while ($cur -lt $newest) {
        $j = (Run @('--json', 'events', "$cur")) | ConvertFrom-Json
        $r = @($j.rows)
        if ($r.Count -eq 0) { break }
        $all += $r
        $cur = [int64]$r[-1].sequence
    }
    return ($all | Where-Object {
        $_.ruleId -in @(201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211) })
}

Remove-PSSession $s

$desc = @($rows | Where-Object { $_.ruleId -eq 211 })
$idtw = @($rows | Where-Object { $_.ruleId -eq 210 })
$copy = @($rows | Where-Object { $_.ruleId -eq 209 })

if ($desc.Count -eq 0) { Write-Output '0xD3 (descriptor-table state): (this line is absent)' }
foreach ($r in $desc) {
    $lim = [uint64]$r.guestRip
    Write-Output ''
    Write-Output ("0xD3 Descriptor Context  Core{0}  Sequence {1}" -f $r.access, $r.sequence)
    Write-Output ("  IDTR Base Address = 0x{0:X16}  Limit = 0x{1:X4}" -f `
        ([uint64]$r.qualification), ($lim -band 0xFFFF))
    Write-Output ("  GDTR Base = 0x{0:X16}  Limit = 0x{1:X4}" -f `
        ([uint64]$r.guestPhysicalAddress), (($lim -shr 16) -band 0xFFFF))
    Write-Output ("  TR   Base = 0x{0:X16}  Limit = 0x{1:X8}  AR = 0x{2:X}" -f `
        ([uint64]$r.guestLinearAddress), (($lim -shr 32) -band 0xFFFFFFFFL), ([uint32]$r.status))
    Write-Output ("  Inconsistent mask with vmcs12 = 0x{0:X} (0 = field-by-field consistent)" -f ([uint64]$r.exitReason))
}

if ($idtw.Count -eq 0) { Write-Output ''; Write-Output '0xD2 (IDTR base address write record): (this line is missing)' }
foreach ($r in $idtw) {
    Write-Output ''
    Write-Output ("0xD2 IDTR base address write record  Core{0}  Sequence {1}" -f $r.access, $r.sequence)
    Write-Output ("  L1 VMWRITE count to 0x6818 = {0}" -f ([uint64]$r.guestLinearAddress))
    Write-Output ("  Last written value          = 0x{0:X16}" -f ([uint64]$r.qualification))
    Write-Output ("  Values in vmcs02 at triple fault = 0x{0:X16}" -f ([uint64]$r.guestPhysicalAddress))
    Write-Output ("  The vmcs12 region at that time = 0x{0:X}" -f ([uint64]$r.guestRip))
}

if ($copy.Count -eq 0) { Write-Output ''; Write-Output '0xD1 (copy loop endpoints): (this line is missing)' }
foreach ($r in $copy) {
    $nz = [uint64]$r.guestLinearAddress
    $cn = [uint64]$r.guestRip
    $wc = [uint64]$r.exitReason
    Write-Output ''
    Write-Output ("0xD1 IDTR base address copy both ends  core{0}  sequence {1}" -f $r.access, $r.sequence)
    Write-Output ("  Number of saves (vmcs02→vmcs12) = {0}   Non-zero count = {1}   Last saved value = 0x{2:X16}" -f `
        ($cn -shr 32), ($nz -shr 32), ([uint64]$r.qualification))
    Write-Output ("  Number of loads (vmcs12→vmcs02) = {0}   Non-zero count = {1}   Last loaded value = 0x{2:X16}" -f `
        ($cn -band 0xFFFFFFFFL), ($nz -band 0xFFFFFFFFL), ([uint64]$r.guestPhysicalAddress))
    # exitReason is only 32 bits; the two comparison counters each occupy 16 bits. The first version packed them as 32/32.
    # The upper half is directly truncated, resulting in a constant zero false read.
    Write-Output ("  Reference: L1 writes IDTR limit {0} times, writes GDTR base {1} times" -f `
        (($wc -shr 16) -band 0xFFFF), ($wc -band 0xFFFF))
}

# The IDTR base address for each vmcs12 region. This set is not gated by the triple fault and is always readable.
$perRegion = @($rows | Where-Object { $_.ruleId -eq 208 })
if ($perRegion.Count -eq 0) { Write-Output ''; Write-Output '0xD0 (IDTR base address per region): (this line is absent)' }
foreach ($r in ($perRegion | Sort-Object { [int64]$_.sequence } | Select-Object -Last 8)) {
    Write-Output ''
    Write-Output ("0xD0 Region IDTR Base  Core{0}  Region{1}  vmcs12=0x{2:X}  Sequence {3}" -f `
        $r.access, [uint64]$r.exitReason, ([uint64]$r.guestRip), $r.sequence)
    Write-Output ("  Current base address = 0x{0:X16}" -f ([uint64]$r.qualification))
    Write-Output ("  Reset count = {0}   RIP at reset = 0x{1:X}   Exit reason at reset = {2}" -f `
        ([uint64]$r.guestLinearAddress), ([uint64]$r.guestPhysicalAddress), ([uint32]$r.status))
}

# Breakdown of zeroing count: Did our load clear it, or did L2 reload the IDT?
$blame = @($rows | Where-Object { $_.ruleId -eq 207 })
if ($blame.Count -eq 0) { Write-Output ''; Write-Output '0xCF (Reset Attribution): (This line is absent)' }
foreach ($r in ($blame | Sort-Object { [int64]$_.sequence } | Select-Object -Last 4)) {
    Write-Output ''
    Write-Output ("0xCF Zeroed Attribution  Core{0}  Region{1}  vmcs12=0x{2:X}  Sequence {3}" -f `
        $r.access, (([uint64]$r.exitReason) -band 0xFF), ([uint64]$r.guestRip), $r.sequence)
    Write-Output ("  The area has been installed with IDT base address {0} times" -f ((([uint64]$r.exitReason) -shr 8)))
    Write-Output ("  Total zero count = {0}" -f ([uint32]$r.status))
    Write-Output ("    Among them we load the erased = {0}" -f ([uint64]$r.guestPhysicalAddress))
    Write-Output ("    Among them, L2 self-reloaded = {0}" -f ([uint64]$r.guestLinearAddress))
    Write-Output ("  Last loaded value = 0x{0:X16}" -f ([uint64]$r.qualification))
}

# The context we cleared: the state of the backup storage at that time.
foreach ($r in (@($rows | Where-Object { $_.ruleId -eq 206 }) |
                Sort-Object { [int64]$_.sequence } | Select-Object -Last 2)) {
    $p = [uint64]$r.guestRip
    Write-Output ''
    Write-Output ("0xCE The time we wiped  Core{0}  Sequence {1}" -f $r.access, $r.sequence)
    Write-Output ("  L2 RIP about to enter = 0x{0:X}" -f ([uint64]$r.qualification))
    Write-Output ("  The vmcs12 region at that time = 0x{0:X}   Region header = 0x{1:X}   Write sequence number = {2}" -f `
        ([uint64]$r.guestPhysicalAddress), ([uint64]$r.guestLinearAddress), ([uint32]$r.exitReason))
    Write-Output ("  At that time: page store failed {0}   restore miss {1}   restore rejected field {2}   pool eviction {3}   last stored {4} entries" -f `
        ($p -shr 48), (($p -shr 32) -band 0xFFFF), (($p -shr 16) -band 0xFFFF), ($p -band 0xFFFF), ([uint32]$r.status))
}

# Health status of the backup storage itself (cumulative), never released before.
foreach ($r in (@($rows | Where-Object { $_.ruleId -eq 205 }) |
                Sort-Object { [int64]$_.sequence } | Select-Object -Last 2)) {
    $q = [uint64]$r.qualification
    $l = [uint64]$r.guestLinearAddress
    $g = [uint64]$r.guestRip
    Write-Output ''
    Write-Output ("0xCD Backup storage health  Core{0}  Sequence {1}" -f $r.access, $r.sequence)
    Write-Output ("  Page: Success {0}   Failed {1}   Skipped {2}   Last wrote {3} entries" -f `
        ($q -shr 32), ($q -band 0xFFFFFFFFL), ([uint64]$r.guestPhysicalAddress), ([uint32]$r.status))
    Write-Output ("  Restore: success {0}   Missed {1}   Rejected fields {2}   Pool eviction {3}   Entries in last header {4}" -f `
        ($l -shr 32), ($l -band 0xFFFFFFFFL), ($g -shr 32), ($g -band 0xFFFFFFFFL), ([uint32]$r.exitReason))
}

# The shape of a triple fault: 64-bit mode + IDTR base address 0 + limit 0x0FFF.
# Counting status alone is useless (Linux typically passes through); the key is whether injection is present.
foreach ($r in (@($rows | Where-Object { $_.ruleId -eq 204 }) |
                Sort-Object { [int64]$_.sequence } | Select-Object -Last 2)) {
    Write-Output ''
    Write-Output ("0xCC 64-bit IDT base address is 0, entering core{0}, sequence {1}" -f $r.access, $r.sequence)
    Write-Output ("  Entered {0} times, {1} with injection" -f `
        ([uint64]$r.qualification), ([uint64]$r.guestPhysicalAddress))
    Write-Output ("  Last injected: RIP = 0x{0:X}   vmcs12 = 0x{1:X}" -f `
        ([uint64]$r.guestLinearAddress), ([uint64]$r.guestRip))
    Write-Output ("    Injection Info = 0x{0:X8}   RFLAGS = 0x{1:X}" -f `
        ([uint32]$r.exitReason), ([uint32]$r.status))
}

# What each field stores in the three locations: working copy / pool slot / region page.
foreach ($r in (@($rows | Where-Object { $_.ruleId -eq 203 }) |
                Sort-Object { [int64]$_.sequence } | Select-Object -Last 2)) {
    Write-Output ''
    Write-Output ("0xCB IDTR base address in three stores  Core{0}  Sequence {1} (this is the {2} time entering this way)" -f `
        $r.access, $r.sequence, ([uint32]$r.status))
    Write-Output ("  Working copy vmcs12 = 0x{0:X16}" -f ([uint64]$r.qualification))
    Write-Output ("  Pool Slot          = 0x{0:X16}" -f ([uint64]$r.guestPhysicalAddress))
    Write-Output ("  Region Page        = 0x{0:X16} (with {1} entries in page)" -f `
        ([uint64]$r.guestLinearAddress), ([uint32]$r.exitReason))
    Write-Output ("  This region = 0x{0:X}" -f ([uint64]$r.guestRip))
}

# The moment the 64-bit L2 discards the IDT base address.
foreach ($r in (@($rows | Where-Object { $_.ruleId -eq 202 }) |
                Sort-Object { [int64]$_.sequence } | Select-Object -Last 2)) {
    $g = [uint64]$r.guestRip
    Write-Output ''
    Write-Output ("0xCA 64-bit L2 self-dropped IDT base address  Core{0}  Sequence {1}" -f $r.access, $r.sequence)
    Write-Output ("  Occurred {0} times   Last exit RIP = 0x{1:X}   Exit reason = {2}" -f `
        ([uint64]$r.guestLinearAddress), ([uint64]$r.qualification), ([uint32]$r.exitReason))
    Write-Output ("  Upon entry, we installed 0x{0:X16}" -f ([uint64]$r.guestPhysicalAddress))
    Write-Output ("  At that time IDTR limit = 0x{0:X}   CS.AR = 0x{1:X}" -f `
        ($g -band 0xFFFFFFFFL), ($g -shr 32))
}

# The upward jump: the base address returned upon exit was not one we wrote, meaning L2 executed LIDT.
foreach ($r in (@($rows | Where-Object { $_.ruleId -eq 201 }) |
                Sort-Object { [int64]$_.sequence } | Select-Object -Last 2)) {
    Write-Output ''
    Write-Output ("0xC9 L2 Install IDT base address manually  Core{0}  Sequence {1}" -f $r.access, $r.sequence)
    Write-Output ("  Occurred {0} times   Last value = 0x{1:X16}" -f `
        ([uint32]$r.status), ([uint64]$r.qualification))
    Write-Output ("  Last exit RIP = 0x{0:X}   Reason = {1}   Region = 0x{2:X}" -f `
        ([uint64]$r.guestPhysicalAddress), ([uint32]$r.exitReason), ([uint64]$r.guestLinearAddress))
    Write-Output ("  When the issue occurred upon entry, the last value stored by this core to this region was 0x{0:X16}" -f `
        ([uint64]$r.guestRip))
}
