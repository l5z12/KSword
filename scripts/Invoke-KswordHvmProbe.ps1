<#
.SYNOPSIS
    Send the CPUID probe to the Hyper-V test machine and run it to determine whether KSword HVM can execute VMXON in this L1.

.DESCRIPTION
    Requires administrator privileges (both Copy-VMFile and PowerShell Direct require it), unless the current user is already...
    Hyper-V Administrators group and logged in again.

    Why this probe is needed: Win32_ComputerSystem.HypervisorPresent reads CPUID.1:ECX[31], which only indicates
    'I have a hypervisor above me'. This bit is always 1 in any VM, so using it to determine if 'something inside
    the guest is contending for VT-x' is incorrect. The true criterion is CPUID.1:ECX[5] (whether VMX is visible).

    The probe's check items correspond one-to-one with the decision chain in hvm_evmcs.c within the driver,
    allowing us to predict where KswordARKHvmEvmcsDiscover will stop and why without loading the driver.

.EXAMPLE
    .\Invoke-KswordHvmProbe.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName = 'KSword-HVM-Target',
    [System.Management.Automation.PSCredential] $GuestCredential,
    [string] $ProbePath = (Join-Path $PSScriptRoot '..\tools\hvm_probe\hvm_probe.exe')
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$ProbePath = (Resolve-Path $ProbePath).Path
if (-not (Test-Path $ProbePath)) { throw "Probe does not exist: $ProbePath (compile tools\hvm_probe\hvm_probe.c first)" }

$vm = Get-VM -Name $VMName -ErrorAction Stop
if ($vm.State -ne 'Running') { throw "Virtual machine is not in Running state (current $($vm.State)). Start-VM first." }

if (-not $GuestCredential) {
    $GuestCredential = Get-Credential -Message "guest administrator credentials"
}

# Copy-VMFile depends on the 'Guest Service Interface' integration service, which is disabled by default.
$svc = Get-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
if ($svc -and -not $svc.Enabled) {
    Write-Host "Enabling guest service interface (required for Copy-VMFile)..."
    Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface'
    Start-Sleep -Seconds 3
}

$dest = 'C:\ksword\hvm_probe.exe'
Write-Host "Copy probe to guest: $dest"
try {
    Copy-VMFile -Name $VMName -SourcePath $ProbePath -DestinationPath $dest `
                -CreateFullPath -FileSource Host -Force -ErrorAction Stop
} catch {
    # Fall back to PowerShell Direct for byte transfer when integration services are unavailable; slower but does not depend on guest services.
    Write-Warning "Copy-VMFile failed ($($_.Exception.Message)), switching to PowerShell Direct for transfer."
    $bytes = [IO.File]::ReadAllBytes($ProbePath)
    $b64 = [Convert]::ToBase64String($bytes)
    Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
        param($data, $target)
        New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
        [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String($data))
    } -ArgumentList $b64, $dest
}

Write-Host "`nRunning the probe inside the guest: `n"
Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    param($exe)
    & $exe
} -ArgumentList $dest
