<#
.SYNOPSIS
    Clean up accumulated checkpoints on the KSword test machine to reclaim disk space.

.DESCRIPTION
    Must run as **Administrator**.

    Each checkpoint saves a full memory image (8 GiB native) plus a differencing disk. Tiered
    testing generates one to two per round, quickly filling the system drive—manifesting as
    `Checkpoint operation failed ... Not enough disk space (0x80070070)`.

    **By default, this is a dry run that deletes nothing. Only add -Confirm after reviewing the list to confirm it is correct before actually deleting.

    Retention rules (both must apply):
      * Names in -Keep are always retained; by default, 'clean-install' is retained. That is the only
        baseline with a 'clean system + pre-configured prerequisites'; deleting it requires a reinstall.
      * Keep the most recent -KeepLast (default 2) snapshots in reverse chronological order.

    Deletion is **asynchronous**: Hyper-V merges the differencing disk back to the parent disk in the background.
    The script waits for the merge to complete; otherwise, you will not see the space freed immediately.

.PARAMETER Confirm
    Actually perform the deletion. Without this switch, only the list of items to be deleted is printed.

.PARAMETER KeepLast
    Retain a few recent ones in addition to the whitelist. Default is 2.

.PARAMETER Keep
    Checkpoints that are never deleted. Default is 'clean-install'.

.EXAMPLE
    .\Clear-KswordVmCheckpoints.ps1 # Dry run: list only.
    .\Clear-KswordVmCheckpoints.ps1 -Confirm # Actual deletion.
    .\Clear-KswordVmCheckpoints.ps1 -KeepLast 0 -Confirm
#>
[CmdletBinding()]
param(
    [string]   $VMName   = 'KSword-HVM-Target',
    [int]      $KeepLast = 2,
    [string[]] $Keep     = @('clean-install'),
    [switch]   $Confirm
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

function Get-FreeGb {
    param([string] $Path)
    $root = [IO.Path]::GetPathRoot($Path)
    $d = Get-PSDrive -Name $root.TrimEnd(':\') -ErrorAction SilentlyContinue
    if ($d) { return [math]::Round($d.Free / 1GB, 2) }
    return $null
}

$vm = Get-VM -Name $VMName -ErrorAction Stop
$vmPath = $vm.Path
$freeBefore = Get-FreeGb $vmPath
Write-Host ("Virtual Machine {0}  Status {1}  Path {2}" -f $vm.Name, $vm.State, $vmPath)
Write-Host ("Remaining {0} GB on the volume" -f $freeBefore) -ForegroundColor $(
    if ($freeBefore -lt 5) { 'Red' } elseif ($freeBefore -lt 20) { 'Yellow' } else { 'Green' })

$all = @(Get-VMSnapshot -VMName $VMName | Sort-Object CreationTime)
if ($all.Count -eq 0) { Write-Host "`nNo checkpoints." -ForegroundColor Green; return }

Write-Host "`nAll checkpoints (in chronological order):" -ForegroundColor Cyan
$all | Format-Table Name, SnapshotType, CreationTime -AutoSize

# Keep: those on the list + the most recent KeepLast entries.
$keepByName = @($all | Where-Object { $Keep -contains $_.Name })
$keepRecent = @($all | Sort-Object CreationTime -Descending | Select-Object -First ([math]::Max($KeepLast, 0)))
$keepNames  = @(($keepByName + $keepRecent) | ForEach-Object { $_.Name } | Sort-Object -Unique)
$doomed     = @($all | Where-Object { $keepNames -notcontains $_.Name })

Write-Host "Keep: " -ForegroundColor Green
foreach ($n in $keepNames) {
    $why = if ($Keep -contains $n) { '(Whitelist)' } else { '(One of the last {0})' -f $KeepLast }
    Write-Host ("  {0} {1}" -f $n, $why) -ForegroundColor Green
}

if ($doomed.Count -eq 0) {
    Write-Host "`nNo checkpoints to delete. To free up space, reduce -KeepLast." -ForegroundColor Yellow
    return
}

Write-Host "`nDeleting $($doomed.Count) :" -ForegroundColor Yellow
foreach ($s in $doomed) { Write-Host ("  {0}   {1}" -f $s.Name, $s.CreationTime) -ForegroundColor Yellow }

if (-not $Confirm) {
    Write-Host "`n[Rehearsal] Nothing has been deleted. Add -Confirm after verifying the manifest to execute:" -ForegroundColor Cyan
    Write-Host "  .\scripts\Clear-KswordVmCheckpoints.ps1 -Confirm"
    return
}

foreach ($s in $doomed) {
    Write-Host ("Deleting {0} ..." -f $s.Name) -NoNewline
    Remove-VMSnapshot -VMName $VMName -Name $s.Name -Confirm:$false
    Write-Host "  Submitted" -ForegroundColor Green
}

# Hyper-V deletion is asynchronous: differencing disks merge back to the parent disk in the background; space is only reclaimed after the merge completes.
# Without waiting, you might see "deleted but space unchanged" and mistakenly assume the deletion failed.
Write-Host "`nWaiting for background merge to complete..." -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes(30)
while ((Get-Date) -lt $deadline) {
    $merging = @(Get-VM -Name $VMName | Where-Object { $_.Status -match 'Merg|合并' })
    if ($merging.Count -eq 0) { break }
    Write-Host ("  Still merging: {0}" -f (Get-VM -Name $VMName).Status)
    Start-Sleep -Seconds 15
}

$freeAfter = Get-FreeGb $vmPath
Write-Host ("`nRemaining space {0} GB -> {1} GB (reclaiming approximately {2} GB)" -f
    $freeBefore, $freeAfter, [math]::Round($freeAfter - $freeBefore, 2)) -ForegroundColor Green
Write-Host "`nRemaining checkpoints:" -ForegroundColor Cyan
Get-VMSnapshot -VMName $VMName | Sort-Object CreationTime | Format-Table Name, CreationTime -AutoSize
