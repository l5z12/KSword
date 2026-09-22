# Reboot TinyCore using a text console and serial logs to retrieve the kernel's own output.
#
# Why this path: Every conclusion so far about "where it stopped" has been inferred from VMCS fields —
# Exit reason, RIP, and descriptor tables show that L2 stopped at the HLT at 0xFFFFFFFF81C721CA,
# It cannot tell me what Linux thinks happened. The default menu item "Boot TinyCorePure64" also requires
# Starting X results in a solid 1024x768 black screen, making even kernel prints invisible.
#
# Both modifications apply only to boot parameters, leaving the virtual machine hardware configuration unchanged:
#   1. Select the third option "Boot Core (command line only)" without starting X;
#   2. Press TAB to enter the edit line, append console=ttyS0,115200n8 to make the kernel print to the serial port simultaneously.
# The serial port was already configured (serial0.fileName = C:\vmware\hltprobe.log) by the probe from the previous round.
param(
    [string] $VMName = 'KSword-HVM-Target',
    [string] $SerialLog = 'C:\vmware\hltprobe.log',
    [int]    $WaitSeconds = 120,
    # Additional kernel parameters to append, e.g., 'nosmp'. Only lowercase letters and digits are allowed; uppercase requires the Shift key.
    [string] $Append = ''
)

$ErrorActionPreference = 'Stop'
# Hyper-V PowerShell Direct requires a nonempty local machine name.
$env:COMPUTERNAME = [Environment]::MachineName
$vncScript = Join-Path $PSScriptRoot 'Get-VmwareVnc.ps1'
$cred = New-Object PSCredential('felix',
    (ConvertTo-SecureString 'password' -AsPlainText -Force))
$s = New-PSSession -VMName $VMName -Credential $cred

# Note: The serial port is appended to; clear it first, otherwise you will read bytes from the previous probe run.
Invoke-Command -Session $s -ArgumentList $SerialLog -ScriptBlock {
    param($log)
    # Keep the virtual CPU execution layer alive while VMware destroys its VM.
    # Stopping residency first can leave vmrun waiting indefinitely (recorded 4x2).
    # If teardown fails, retain the state for diagnosis and restart HVM-target.
    $vmxPath = 'C:\Users\felix\Documents\Virtual Machines\' +
               'Other Linux 6.x kernel 64-bit\Other Linux 6.x kernel 64-bit.vmx'
    $vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    $ctl = 'C:\ksword\hvm_ctl.exe'

    if (@(Get-Process -Name 'vmware-vmx' -ErrorAction SilentlyContinue).Count -gt 0) {
        # Retain the handle to the process started by this script to prevent the object returned by Start-Process from losing its ExitCode after termination.
        $stopInfo = New-Object Diagnostics.ProcessStartInfo
        $stopInfo.FileName = $vmrun
        $stopInfo.Arguments = "-T ws stop `"$vmxPath`" hard"
        $stopInfo.UseShellExecute = $false
        $stopInfo.CreateNoWindow = $true
        $stopping = New-Object Diagnostics.Process
        $stopping.StartInfo = $stopInfo
        try {
            if (-not $stopping.Start()) { throw 'Failed to start vmrun stop' }
            if (-not $stopping.WaitForExit(30000)) {
                $stopping.Kill()
                throw 'vmrun stop timeout; retain Windows, VMware, and resident state for inspection'
            }
            if ($stopping.ExitCode -ne 0) { throw "vmrun stop failed: $($stopping.ExitCode)" }
        } finally {
            $stopping.Dispose()
        }
    }
    $waited = 0
    while (@(Get-Process -Name 'vmware-vmx' -ErrorAction SilentlyContinue).Count -gt 0 -and
           $waited -lt 30) {
        Start-Sleep -Seconds 1
        $waited++
    }
    if (@(Get-Process -Name 'vmware-vmx' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'VMware guest not stopped, prohibiting restart of resident hypervisor or overwriting serial port logs'
    }
    # Reclaim a revoked page only after all VMware vCPUs have disappeared.
    & $ctl --json nested-page-remove | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'EPT replacement reclamation failed; do not stop residency' }
    $stop = Start-Process $ctl -ArgumentList 'stop' -WindowStyle Hidden -Wait -PassThru
    $state = (& $ctl --json status) | ConvertFrom-Json
    if ($stop.ExitCode -ne 0 -or $null -eq $state.residentProcessorCount -or
        $state.residentProcessorCount -ne 0 -or
        $state.stateNames -contains 'ROLLBACK_REQUIRED') {
        throw 'Resident hypervisor not fully stopped, preserve current VMware and Windows state, prohibit further teardown'
    }
    Get-Process -Name 'vmware' -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    # Must be running and must be the version with the hidden hypervisor; otherwise, VMware's identity gate will directly reject it.
    $state = (& $ctl --json status) | ConvertFrom-Json
    if ($state.featureNames -notcontains 'EPTP_SWITCH_ARMED') {
        foreach ($command in @('teardown', 'prepare-eptpsw', 'self-test')) {
            & $ctl $command | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "$command failed" }
        }
    }
    & $ctl resident-nested-hidehv | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Nested resident startup failed' }
    $state = (& $ctl --json status) | ConvertFrom-Json
    $view = (& $ctl --json cpuid-view) | ConvertFrom-Json
    if ($null -eq $state.residentProcessorCount -or $state.residentProcessorCount -le 0 -or
        $state.featureNames -notcontains 'EPTP_SWITCH_ARMED' -or -not $view.hidden) {
        throw 'Nested resident hypervisor or EPTP page-switching backend not active'
    }
    & sc.exe stop vmx86 | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe start vmx86 | Out-Null
    Start-Sleep -Seconds 2
    if (Test-Path $log) { Remove-Item $log -Force }
    $vmx = 'C:\Users\felix\Documents\Virtual Machines\' +
           'Other Linux 6.x kernel 64-bit\Other Linux 6.x kernel 64-bit.vmx'
    Start-Process -FilePath 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' `
        -ArgumentList @('-T', 'ws', 'start', "`"$vmx`"") -WindowStyle Hidden
    Start-Sleep -Seconds 40
    "vmware-vmx = " + @(Get-Process -Name 'vmware-vmx' -ErrorAction SilentlyContinue).Count
}

# X11 keysym: printable ASCII characters use their own codes, while arrow keys and TAB use the 0xFF range.
$down = 0xFF54
$tab = 0xFF09
$enter = 0xFF0D
# ignore_loglevel: The menu provides loglevel=3, which only prints up to KERN_ERR, exactly enough to determine where it stopped.
# Filter out that entire section. Appending it to the end is sufficient; there is no need to modify the preceding parameters.
$text = ' console=ttyS0,115200n8 ignore_loglevel'
if ($Append) { $text += ' ' + $Append }
# Uppercase letters require Shift (bit 0x10000); otherwise ttyS0 becomes ttys0 — see VNC script.
$keys = @($down, $down, $tab) +
        ($text.ToCharArray() | ForEach-Object {
            $c = [int][char]$_
            if (($_ -cge 'A' -and $_ -cle 'Z') -or
                '~!@#$%^&*()_+{}|:"<>?'.Contains([string]$_)) {
                $c -bor 0x10000
            } else { $c }
        }) +
        @($enter)

Invoke-Command -Session $s -FilePath $vncScript `
    -ArgumentList '127.0.0.1', 5900, 'C:\vmware\shot-serialboot.png', $keys, 90

Start-Sleep -Seconds $WaitSeconds

Invoke-Command -Session $s -FilePath $vncScript `
    -ArgumentList '127.0.0.1', 5900, 'C:\vmware\shot-serialafter.png'

$out = Invoke-Command -Session $s -ArgumentList $SerialLog -ScriptBlock {
    param($log)
    if (-not (Test-Path $log)) { return '(Serial file does not exist)' }
    # vmware-vmx keeps this file open; ReadAllBytes will be denied; must open with shared read access.
    $fs = New-Object IO.FileStream($log, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $b = New-Object byte[] $fs.Length
        [void]$fs.Read($b, 0, $b.Length)
    } finally { $fs.Dispose() }
    "Serial port has $($b.Length) bytes`n" +
        (-join ($b | ForEach-Object {
            if ($_ -ge 32 -and $_ -lt 127) { [char]$_ }
            elseif ($_ -eq 10) { "`n" }
            elseif ($_ -eq 13) { '' }
            else { '.' }
        }))
}
Remove-PSSession $s
Write-Output $out
