# Read the tail of the serial port file in the target machine. Since VMware keeps it open, we must open it with shared access to read.
#
# If the read length increases between two reads, the guest is still running; if it stays constant, it has stopped. This is more reliable than checking the screen:
# The default boot item starts X, resulting in a completely black screen where it is impossible to determine the status.
param(
    [string] $VMName = 'KSword-HVM-Target',
    [string] $SerialLog = 'C:\vmware\hltprobe.log',
    [int]    $Lines = 20,
    # Wait this many seconds before reading again; use length difference to determine if still running. 0 = read only once.
    [int]    $AgainAfter = 0
)

$ErrorActionPreference = 'Stop'
$cred = New-Object PSCredential('felix',
    (ConvertTo-SecureString 'password' -AsPlainText -Force))
$s = New-PSSession -VMName $VMName -Credential $cred

$block = {
    param($log, $lines)
    if (-not (Test-Path $log)) { return @{ Size = -1; Tail = '(Serial file does not exist)' } }
    $fs = New-Object IO.FileStream($log, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $b = New-Object byte[] $fs.Length
        [void]$fs.Read($b, 0, $b.Length)
    } finally { $fs.Dispose() }
    $txt = -join ($b | ForEach-Object {
        if ($_ -ge 32 -and $_ -lt 127) { [char]$_ }
        elseif ($_ -eq 10) { "`n" }
        elseif ($_ -eq 13) { '' }
        else { '.' }
    })
    return @{
        Size = $b.Length
        Tail = (($txt -split "`n" | Select-Object -Last $lines) -join "`n")
    }
}

$a = Invoke-Command -Session $s -ArgumentList $SerialLog, $Lines -ScriptBlock $block
Write-Output ("Serial port {0} bytes" -f $a.Size)
Write-Output $a.Tail
if ($AgainAfter -gt 0) {
    Start-Sleep -Seconds $AgainAfter
    $b = Invoke-Command -Session $s -ArgumentList $SerialLog, $Lines -ScriptBlock $block
    Write-Output ''
    Write-Output ("{0} seconds later: {1} bytes (increment {2})" -f `
        $AgainAfter, $b.Size, ($b.Size - $a.Size))
    if ($b.Size -ne $a.Size) { Write-Output $b.Tail }
}
Remove-PSSession $s
