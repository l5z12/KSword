<#
.SYNOPSIS
    Create a Hyper-V test machine for KSword HVM/EPT HOOK development and configure it according to nested virtualization requirements.

.DESCRIPTION
    Must run as **Administrator**, and the host must have the Hyper-V role enabled.

    Nested virtualization requires more than one switch. Every item below is mandatory; missing any one prevents KSword HVM
    from executing VMXON or causes incorrect behavior. The script configures all of them and reads each back for verification:

      * ExposeVirtualizationExtensions = $true — Pass VT-x/EPT through to the L1 guest.
        Can only be set when the VM is **powered off**.
      * Dynamic memory must be disabled — Hyper-V explicitly states that nested virtualization is unavailable when dynamic memory is enabled.
      * MAC spoofing enabled: The source MAC of L2 guest packets differs from the L1 NIC;
        without this, the virtual switch drops them, leaving the L2 guest with no network.
      * Set checkpoints (snapshots) to Standard type and disable automatic checkpoints by default —
        production checkpoints rely on VSS inside the guest and conflict with the running hypervisor.
      * Generation 2 VMs — UEFI-based; required for Windows 11.

    What the script does **not** do: does not install an OS, does not modify host security
    configurations, and does not touch Secure Boot (disable it after OS installation per output prompts).

.PARAMETER VMName
    VM name.

.PARAMETER Path
    Directory for storing the virtual machine and virtual disk.

.PARAMETER IsoPath
    Windows installation ISO.

.PARAMETER MemoryGB
    Fixed memory size (do not use dynamic memory).

.PARAMETER CpuCount
    Number of virtual processors.

.PARAMETER DiskGB
    Virtual disk size (dynamic expansion).

.PARAMETER SwitchName
    Virtual switch to connect to. If empty, automatically select the first External switch; if none exist, select the Default Switch.

.EXAMPLE
    .\New-KswordHyperVTarget.ps1 -IsoPath 'D:\Users\felix\Downloads\Windows11_InsiderPreview_Client_x64_en-us_22621.iso'
#>
[CmdletBinding()]
param(
    [string] $VMName     = 'KSword-HVM-Target',
    [string] $Path       = 'C:\Hyper-V',
    [Parameter(Mandatory)][string] $IsoPath,
    [int]    $MemoryGB   = 8,
    [int]    $CpuCount   = 4,
    [int]    $DiskGB     = 80,
    [string] $SwitchName = ''
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Must run as administrator.'
    }
}

Assert-Admin

if (-not (Get-Module -ListAvailable Hyper-V)) {
    throw @'
The Hyper-V role is not installed. Run as administrator first:

    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All

Then restart and run this script again.
'@
}
Import-Module Hyper-V -ErrorAction Stop

if (-not (Test-Path -LiteralPath $IsoPath)) { throw "ISO not found: $IsoPath" }
if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    throw "Virtual machine '$VMName' already exists. To rebuild, please delete it manually first; the script will not delete it for you."
}

# ---------------------------------------------------------------------------
# Virtual switch
# ---------------------------------------------------------------------------
if (-not $SwitchName) {
    $sw = Get-VMSwitch -ErrorAction SilentlyContinue |
          Sort-Object @{ e = { switch ($_.SwitchType) { 'External' { 0 } 'Internal' { 1 } default { 2 } } } } |
          Select-Object -First 1
    if (-not $sw) {
        throw @'
The host has no virtual switches. Create one first in Hyper-V Manager (Virtual Switch Manager →
External → Bind to your physical network adapter), or:

    New-VMSwitch -Name 'External' -NetAdapterName '<Your network adapter name>' -AllowManagementOS $true
'@
    }
    $SwitchName = $sw.Name
}
Write-Host "Virtual Switch : $SwitchName" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# create machine
# ---------------------------------------------------------------------------
$vhdDir = Join-Path $Path 'Virtual Hard Disks'
New-Item -ItemType Directory -Force -Path $vhdDir | Out-Null
$vhdPath = Join-Path $vhdDir "$VMName.vhdx"
if (Test-Path -LiteralPath $vhdPath) { throw "Virtual disk already exists: $vhdPath" }

Write-Host "`nCreating virtual machine $VMName ..." -ForegroundColor Cyan
$vm = New-VM -Name $VMName -Generation 2 -Path $Path `
             -MemoryStartupBytes ($MemoryGB * 1GB) `
             -NewVHDPath $vhdPath -NewVHDSizeBytes ($DiskGB * 1GB) `
             -SwitchName $SwitchName

# --- Three hard requirements for nested virtualization -------------------------------------------------
# 1) Dynamic memory must be disabled. Hyper-V requires that virtualization extensions cannot be exposed while dynamic memory is enabled.
Set-VMMemory  -VMName $VMName -DynamicMemoryEnabled $false -StartupBytes ($MemoryGB * 1GB)
# 2) Pass through VT-x/EPT. Can only be set when the VM is powered off.
Set-VMProcessor -VMName $VMName -Count $CpuCount -ExposeVirtualizationExtensions $true
# 3) If the L2 guest's source MAC differs from the L1 NIC's MAC, packets will be dropped by the virtual switch unless MAC spoofing is enabled.
Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -MacAddressSpoofing On

# --- Checkpoint: Standard type ---------------------------------------------------------
# Production checkpoints rely on VSS inside the guest, which conflicts with a running hypervisor; use Standard type here.
# Disable automatic checkpoints (otherwise one is generated on every startup, which is cumbersome during experiments).
Set-VM -Name $VMName -CheckpointType Standard -AutomaticCheckpointsEnabled $false
Set-VM -Name $VMName -AutomaticStopAction ShutDown

# --- Firmware: ISO boot priority -----------------------------------------------------
$dvd = Add-VMDvdDrive -VMName $VMName -Path $IsoPath -Passthru
Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd

# --- vTPM: Required for Windows 11 Installation Check -----------------------------------------
# Unlike VMware, Hyper-V's vTPM does not encrypt the entire VM configuration in this case.
# This prevents the situation where forgetting the password makes the data permanently inaccessible.
try {
    $hgs = Get-HgsGuardian -Name 'UntrustedGuardian' -ErrorAction SilentlyContinue
    if (-not $hgs) { $hgs = New-HgsGuardian -Name 'UntrustedGuardian' -GenerateCertificates }
    $kp = New-HgsKeyProtector -Owner $hgs -AllowUntrustedRoot
    Set-VMKeyProtector -VMName $VMName -KeyProtector $kp.RawData
    Enable-VMTPM -VMName $VMName
    $tpmOk = $true
} catch {
    $tpmOk = $false
    Write-Warning "vTPM configuration failed ($($_.Exception.Message)). Windows 11 installer may reject; use Shift+F10 → regedit to bypass the check, or manually configure vTPM."
}

# ---------------------------------------------------------------------------
# Read-back verification — do not rely solely on 'no command errors'.
# ---------------------------------------------------------------------------
Write-Host "`n--- Readback Verification ---" -ForegroundColor Cyan
$p  = Get-VMProcessor -VMName $VMName
$m  = Get-VMMemory    -VMName $VMName
$na = Get-VMNetworkAdapter -VMName $VMName
$fw = Get-VMFirmware  -VMName $VMName
$v  = Get-VM -Name $VMName

$checks = @(
    @{ N = 'Generation 2 Virtual Machine (UEFI)';       O = ($v.Generation -eq 2) }
    @{ N = 'Nested virtualization has exposed VT-x/EPT';   O = ($p.ExposeVirtualizationExtensions -eq $true) }
    @{ N = "Virtual Processor = $CpuCount";      O = ($p.Count -eq $CpuCount) }
    @{ N = 'Dynamic Memory is disabled (nesting required)';   O = ($m.DynamicMemoryEnabled -eq $false) }
    @{ N = "Fixed memory = $MemoryGB GB";     O = ($m.Startup -eq ($MemoryGB * 1GB)) }
    @{ N = 'MAC spoofing enabled (required for L2 networking)'; O = ($na.MacAddressSpoofing -eq 'On') }
    @{ N = 'Checkpoint is Standard';              O = ($v.CheckpointType -eq 'Standard') }
    @{ N = 'Automatic checkpoints are disabled';            O = ($v.AutomaticCheckpointsEnabled -eq $false) }
    @{ N = 'ISO mounted and set as primary boot device';   O = ($fw.BootOrder[0].Device -is [Microsoft.HyperV.PowerShell.DvdDrive]) }
    @{ N = 'vTPM Enabled';                 O = $tpmOk }
)
$bad = 0
foreach ($c in $checks) {
    if ($c.O) { Write-Host ("  [OK]   " + $c.N) -ForegroundColor Green }
    else      { Write-Host ("  [FAIL] " + $c.N) -ForegroundColor Red; $bad++ }
}
if ($bad -gt 0) { throw "$bad items readback validation failed — do not treat as creation success." }

Write-Host @"

Virtual machine is ready: $VMName
  Position    : $Path
  Disk    : $vhdPath  ($DiskGB GB Dynamic Expansion)
  Memory : $MemoryGB GB Fixed
  Processor : $CpuCount  VT-x/EPT exposed

Next:
  1. Start and install OS: Start-VM -Name '$VMName'
                     Then connect in Hyper-V Manager (or vmconnect localhost '$VMName')
  2. After installing the system, **shutdown**, disable Secure Boot (prerequisite for testsigning):
         Set-VMFirmware -VMName '$VMName' -EnableSecureBoot Off
  3. Take baseline snapshot:
         Checkpoint-VM -Name '$VMName' -SnapshotName 'clean-install'
  4. Enable test signing inside the guest, and **confirm that the guest's own VBS/Memory Integrity is turned off** —
     Otherwise, Hyper-V in the guest will seize VT-x, and KSword HVM cannot VMXON:
         bcdedit /set testsigning on
         bcdedit /set hypervisorlaunchtype off
     (Memory integrity is separately configured in Settings → Privacy & security → Windows Security → Device security →
       Disable in Kernel Isolation, then restart)
"@ -ForegroundColor Yellow
