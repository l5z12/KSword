<#
.SYNOPSIS
    Configure the KSword Hyper-V test VM (with OS installed) to load test-signed drivers and ensure VT-x ownership belongs to KSword HVM.

.DESCRIPTION
    Must run as **Administrator** (both Hyper-V cmdlets and PowerShell Direct require this).

    Perform four steps, reading back and validating after each step; abort immediately if any step fails instead of continuing.

      1. Shutdown → Disable Secure Boot (prerequisite for testsigning) → Create baseline checkpoint
      2. Boot → via PowerShell Direct inside the guest:
           - bcdedit /set testsigning on: Allows loading of test-signed drivers.
           - bcdedit /set hypervisorlaunchtype off prevents the guest's own hypervisor from starting.
           - Disable VBS and HVCI (Memory Integrity); otherwise, they will steal VT-x.
      3. Restart guest
      4. After reboot, verify each item by re-reading and report whether the KSword HVM can obtain VT-x.

    Why the last two items in Step 2 are hard requirements: This VM is L1, and KSword's HVM requires VMXON within L1.
    If the guest's own Hyper-V / VBS / HVCI is active, VT-x will be occupied by them
    first, causing KSword HVM to report 'Hypervisor already exists' and refuse to start.

.PARAMETER VMName
    VM name.

.PARAMETER GuestCredential
    Administrator credentials inside the guest. If not provided, prompts interactively.

.PARAMETER GrantHyperVAccess
    Additionally, adds the current user to the local Hyper-V Administrators group so that non-privileged
    sessions can manage VMs (requires logout and re-login to take effect). This is not done by default.

.EXAMPLE
    .\Configure-KswordHyperVGuest.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName = 'KSword-HVM-Target',
    [System.Management.Automation.PSCredential] $GuestCredential,
    [switch] $GrantHyperVAccess
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Must run as administrator (Hyper-V cmdlets and PowerShell Direct both require elevation).'
    }
}

function Show-Check {
    param([string] $Name, [bool] $Ok)
    if ($Ok) { Write-Host ("  [OK]   " + $Name) -ForegroundColor Green }
    else     { Write-Host ("  [FAIL] " + $Name) -ForegroundColor Red }
    return [bool]$Ok
}

Assert-Admin
Import-Module Hyper-V -ErrorAction Stop

$vm = Get-VM -Name $VMName -ErrorAction Stop
Write-Host "=== $VMName ===" -ForegroundColor Cyan
Write-Host ("  Status {0}  Generation {1}  {2} vCPU  {3:N0} MB" -f `
    $vm.State, $vm.Generation, $vm.ProcessorCount, ($vm.MemoryAssigned / 1MB))

# Nested virtualization is the entire point here; first confirm it is still present.
$proc = Get-VMProcessor -VMName $VMName
if (-not $proc.ExposeVirtualizationExtensions) {
    throw 'This virtual machine does not expose VT-x/EPT. Shut it down first and then run: Set-VMProcessor -VMName ' +
          $VMName + ' -ExposeVirtualizationExtensions $true'
}
Write-Host "  Nested virtualization: VT-x/EPT exposed" -ForegroundColor Green

if (-not $GuestCredential) {
    Write-Host "`nPlease enter administrator credentials inside the guest (username can be specified as .\<username>)" -ForegroundColor Yellow
    $GuestCredential = Get-Credential -Message "guest administrator credentials"
}

# ---------------------------------------------------------------------------
# 1) Shutdown → Disable Secure Boot → Create baseline checkpoint
# ---------------------------------------------------------------------------
Write-Host "`n--- 1. Disable Secure Boot and create a baseline checkpoint ---" -ForegroundColor Cyan

if ((Get-VM -Name $VMName).State -ne 'Off') {
    Write-Host "  Shutting down..."
    Stop-VM -Name $VMName -Force
    while ((Get-VM -Name $VMName).State -ne 'Off') { Start-Sleep -Seconds 2 }
}
Write-Host "  Machine is powered off"

Set-VMFirmware -VMName $VMName -EnableSecureBoot Off
$fw = Get-VMFirmware -VMName $VMName
if (-not (Show-Check 'Secure Boot is disabled' ($fw.SecureBoot -eq 'Off'))) {
    throw 'Secure Boot is not disabled —— continuing will cause testsigning to be silently ignored, aborting.'
}

$snapName = 'clean-install'
if (-not (Get-VMSnapshot -VMName $VMName -Name $snapName -ErrorAction SilentlyContinue)) {
    Checkpoint-VM -Name $VMName -SnapshotName $snapName
    Write-Host "  Created checkpoint '$snapName'"
} else {
    Write-Host "  Checkpoint '$snapName' already exists, skipping"
}

# ---------------------------------------------------------------------------
# 2) Power on and wait for PowerShell Direct to become available
# ---------------------------------------------------------------------------
Write-Host "`n--- 2. Boot and configure guest ---" -ForegroundColor Cyan
Start-VM -Name $VMName
Write-Host "  Waiting for PowerShell Direct to be ready (up to 10 minutes)..."

$deadline = (Get-Date).AddMinutes(10)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $null = Invoke-Command -VMName $VMName -Credential $GuestCredential `
                    -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        $ready = $true
        break
    } catch { Start-Sleep -Seconds 10 }
}
if (-not $ready) { throw 'PowerShell Direct has been unable to connect. Ensure the guest is logged into the desktop and credentials are correct.' }
Write-Host "  PowerShell Direct is ready" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Modify configuration inside the guest. These changes apply only to this one-time test VM.
# ---------------------------------------------------------------------------
$applied = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $out = [ordered]@{}
    $out.Computer = $env:COMPUTERNAME
    $os = Get-CimInstance Win32_OperatingSystem
    $out.Os = "$($os.Caption) build $($os.BuildNumber)"

    # Backup current boot entry; a second line of defense beyond checkpoints
    $backup = Join-Path $env:SystemRoot 'Temp\bcd-before-ksword.txt'
    & bcdedit.exe '/enum' '{current}' | Out-File $backup -Encoding utf8
    $out.Backup = $backup

    # Test signing: Allows drivers signed by CN=KswordARK Test Signing Certificate to load.
    & bcdedit.exe '/set' 'testsigning' 'on'  | Out-Null
    # Prevent the guest's own hypervisor from starting; otherwise, VT-x will be occupied by it first.
    & bcdedit.exe '/set' 'hypervisorlaunchtype' 'off' | Out-Null

    # Disable VBS and HVCI. The UI path is 'Core Isolation → Memory Integrity', but here we write directly to the registry.
    $dgRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $dgHvci = Join-Path $dgRoot 'Scenarios\HypervisorEnforcedCodeIntegrity'
    New-Item -Path $dgRoot -Force | Out-Null
    New-Item -Path $dgHvci -Force | Out-Null
    New-ItemProperty -Path $dgRoot -Name 'EnableVirtualizationBasedSecurity' `
        -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $dgHvci -Name 'Enabled' `
        -PropertyType DWord -Value 0 -Force | Out-Null

    $out.Dbg = (& bcdedit.exe '/enum' '{current}' | Out-String)
    $out
}

Write-Host "  guest : $($applied.Computer)  $($applied.Os)"
Write-Host "  Boot entries backed up to $($applied.Backup)"

# ---------------------------------------------------------------------------
# 3) Restart guest
# ---------------------------------------------------------------------------
Write-Host "`n--- 3. Restart the guest to apply the configuration ---" -ForegroundColor Cyan
Invoke-Command -VMName $VMName -Credential $GuestCredential `
    -ScriptBlock { Restart-Computer -Force } -ErrorAction SilentlyContinue
Start-Sleep -Seconds 20

$deadline = (Get-Date).AddMinutes(10)
$back = $false
while ((Get-Date) -lt $deadline) {
    try {
        $null = Invoke-Command -VMName $VMName -Credential $GuestCredential `
                    -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
        $back = $true
        break
    } catch { Start-Sleep -Seconds 10 }
}
if (-not $back) { throw 'PowerShell Direct did not return after reboot. Check the guest status in Hyper-V Manager.' }
Write-Host "  guest has been restarted and returned to a controllable state" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 4) Readback verification — do not rely solely on "no command errors"
# ---------------------------------------------------------------------------
Write-Host "`n--- 4. Readback Verification ---" -ForegroundColor Cyan

$state = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $cur = (& bcdedit.exe '/enum' '{current}' | Out-String)
    $dg  = Get-CimInstance -ClassName Win32_DeviceGuard `
             -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    $cs  = Get-CimInstance Win32_ComputerSystem
    [ordered]@{
        TestSigning       = [bool]($cur -match '(?im)^\s*testsigning\s+Yes')
        HypervisorOff     = [bool]($cur -match '(?im)^\s*hypervisorlaunchtype\s+Off')
        VbsStatus         = if ($dg) { [int]$dg.VirtualizationBasedSecurityStatus } else { -1 }
        VbsRunningSvc     = if ($dg) { @($dg.SecurityServicesRunning) -join ',' } else { '' }
        HypervisorPresent = [bool]$cs.HypervisorPresent
        VmxInCpuid        = $null
        Raw               = $cur
    }
}

$allOk = $true
$allOk = (Show-Check 'testsigning = Yes'                     $state.TestSigning)       -and $allOk
$allOk = (Show-Check 'hypervisorlaunchtype = Off'            $state.HypervisorOff)     -and $allOk
$allOk = (Show-Check 'VBS is disabled (status 0)' ($state.VbsStatus -eq 0)) -and $allOk

Write-Host ""
Write-Host ("  VBS Status Code            : {0}  (0=Off 1=Configured but not running 2=Running)" -f $state.VbsStatus)
Write-Host ("  Running security services    : {0}" -f $(if ($state.VbsRunningSvc) { $state.VbsRunningSvc } else { '(None)' }))
Write-Host ("  HypervisorPresent     : {0}   <- This is CPUID.1:ECX[31], reporting" -f $state.HypervisorPresent)
Write-Host  "                                     'I have a hypervisor above me.' This is an L1 virtual machine,"
Write-Host  "                                     The above is L0 Hyper-V, so it must be True,"
Write-Host  "                                     **NOT** a fault. It is about whether there is anything inside the 'guest' competing for VT-x"
Write-Host  "                                     are two different things; the latter is determined by the three items above."
Write-Host  ""
Write-Host "  Whether VMXON is possible depends on CPUID.1:ECX[5]; test it inside the guest using tools\hvm_probe\hvm_probe.exe." -ForegroundColor Yellow

if ($GrantHyperVAccess) {
    Write-Host "`n--- Attach: Add current user to Hyper-V Administrators ---" -ForegroundColor Cyan
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    try {
        Add-LocalGroupMember -SID 'S-1-5-32-578' -Member $me -ErrorAction Stop
        Write-Host "  Added to $me.**Requires logout and re-login to take effect.**" -ForegroundColor Yellow
    } catch {
        if ("$($_.Exception.Message)" -match '已经|already') { Write-Host "  Already a member" }
        else { Write-Warning "  Join failed: $($_.Exception.Message)" }
    }
}

if (-not $allOk) {
    throw 'Readback validation failed -- do not treat this as successful configuration. Items marked [FAIL] above need to be addressed.'
}

Write-Host @"

All ready. This L1 virtual machine is now:
  * Can load KswordARK.sys with test signatures
  * VT-x/EPT is passed through from Hyper-V, and there is no other hypervisor preempting inside the guest

Next step (deploy the driver into the guest):
    Copy-VMFile -Name '$VMName' -SourcePath '<Repository>\artifacts/bin\x64\Release\KswordARK.sys' ``
                -DestinationPath 'C:\ksword\KswordARK.sys' -CreateFullPath -FileSource Host

Rollback:
    Restore-VMCheckpoint -VMName '$VMName' -Name '$snapName' -Confirm:`$false
"@ -ForegroundColor Yellow
