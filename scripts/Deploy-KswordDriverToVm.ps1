<#
.SYNOPSIS
    Deploy the KswordARK driver to a Hyper-V test VM and query the HVM capability status.

.DESCRIPTION
    Must run as **Administrator** (both Hyper-V cmdlets and PowerShell Direct require this).

    Order is intentional:

      1. First verify the guest prerequisites (testsigning / VMX visible / no other hypervisor competing for VT-x) — if
         prerequisites are not met, do not load the driver; otherwise, only an incomprehensible failure will be returned.
      2) Open the guest kernel dump (in case of a BSOD, this dump is a real sample with a
         clear source, suitable for the C module; without it, a BSOD leaves only a stop code).
      3. **Take a checkpoint before loading.** This is a hypervisor driver; an error on the VMXON path causes a BSOD.
      4. Copy files → Create service → Start → Check device → Run hvm-status.

    Verify by re-reading at every step; abort if preconditions fail rather than forcing execution forward.

    The script **does not start HVM** (no VMXON); it only loads the driver and reads capability
    status. VMXON is a separate step performed only after confirming the capability report is normal.

.PARAMETER VMName
    VM name.

.PARAMETER GuestCredential
    Administrator credentials inside the guest. If not provided, prompts interactively.

.PARAMETER SkipCheckpoint
    Skip pre-load checkpoints. **Not recommended**; use only if you just created a checkpoint.

.EXAMPLE
    .\Deploy-KswordDriverToVm.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName = 'KSword-HVM-Target',
    [System.Management.Automation.PSCredential] $GuestCredential,
    # This is a one-time isolated test machine; default credentials are hardcoded by convention to remain consistent with other scripts in the same directory.
    # Avoids having to manually re-enter the password every time the deployment is re-run.
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    # This script retains a few before-driver-load-* checkpoints (including this newly created one).
    # Each image is about 8 GiB with a differencing disk; keeping too many will exhaust the system drive.
    [int]    $KeepCheckpoints = 2,
    [switch] $SkipCheckpoint
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$repo    = Split-Path $PSScriptRoot -Parent
$sysPath = Join-Path $repo 'artifacts/bin\x64\Release\KswordARK.sys'
$cliPath = Join-Path $repo 'artifacts/bin\x64\Release\KswordCLI.exe'
$prbPath = Join-Path $repo 'tools\hvm_probe\hvm_probe.exe'

foreach ($p in @($sysPath, $cliPath)) {
    if (-not (Test-Path $p)) { throw "Missing artifact: $p" }
}

# ---------------------------------------------------------------------------
# Before deployment, verify on the host that the .sys file has a signature.
#
# Even if the guest has testsigning enabled, it **does not** allow unsigned drivers: the kernel still requires the .sys file to have at least
# a test signature; without it, `sc start` returns 577. The message for 577 says the digital signature cannot be verified,
# Looks like a certificate trust issue, but it might just be that the code wasn't signed at all—the remediation steps differ completely.
#
# Common sources of unsigned builds: constructing with /p:KswordArkSkipAutoVariantSign=true. That property simultaneously
# Disabled both the test signing and variant signing targets in the vcxproj (both targets have the same Condition).
# Since both SkipAutoVariantSign and SkipAutoTestSign are checked, "just skipping variant signing" is not the case.
# This intuition is incorrect.
#
# Check only, do not auto-sign: signing requires certificate handling and is a separate step.
# ---------------------------------------------------------------------------
$sysSig = Get-AuthenticodeSignature $sysPath
if ($sysSig.Status -eq 'NotSigned') {
    throw @"
$sysPath is unsigned, sending it to the guest will only result in sc start 577.
First, complete the signature (without modifying host security configuration):
  .\scripts\Sign-KswordArkDriverTest.ps1 -DriverPath '$sysPath' -SkipMachineTrust
The exit code 1 from `signtool verify /pa` at the end of this script is expected — that's because the host does not trust the self-signed root,
It is unrelated to whether the guest can load. As long as "Successfully signed" is seen.
"@
}
Write-Host ("Driver signature (host side): {0} / {1}" -f $sysSig.Status, $sysSig.SignerCertificate.Subject) -ForegroundColor DarkGray

function Show-Check {
    param([string] $Name, [bool] $Ok, [string] $Detail = '')
    if ($Ok) { Write-Host ("  [OK]   " + $Name + $(if ($Detail) { "  $Detail" })) -ForegroundColor Green }
    else     { Write-Host ("  [FAIL] " + $Name + $(if ($Detail) { "  $Detail" })) -ForegroundColor Red }
    return [bool]$Ok
}

# Send a local file to the guest. Copy-VMFile requires the guest service interface; fall back if unavailable.
# PowerShell Direct sends base64 (slow, but no dependency on integration services).
function Send-ToGuest {
    param([string] $Local, [string] $Remote)
    try {
        Copy-VMFile -Name $VMName -SourcePath $Local -DestinationPath $Remote `
                    -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    } catch {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Local))
        Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
            param($data, $target)
            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String($data))
        } -ArgumentList $b64, $Remote
    }
}

$vm = Get-VM -Name $VMName -ErrorAction Stop
if ($vm.State -ne 'Running') { throw "Virtual machine is not in Running state ($($vm.State)). Start-VM first." }
if (-not (Get-VMProcessor -VMName $VMName).ExposeVirtualizationExtensions) {
    throw 'Nested virtualization is not enabled —— after shutdown, run Set-VMProcessor -ExposeVirtualizationExtensions $true'
}
if (-not $GuestCredential) {
    $GuestCredential = New-Object System.Management.Automation.PSCredential(
        $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))
}

# ---------------------------------------------------------------------------
# 1. Prerequisite check: Do not load if it fails.
# ---------------------------------------------------------------------------
Write-Host "`n--- 1. guest prerequisite check ---" -ForegroundColor Cyan
$pre = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $cur = (& bcdedit.exe '/enum' '{current}' | Out-String)
    $dg  = Get-CimInstance -ClassName Win32_DeviceGuard `
             -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    [ordered]@{
        TestSigning   = [bool]($cur -match '(?im)^\s*testsigning\s+Yes')
        HypervisorOff = [bool]($cur -match '(?im)^\s*hypervisorlaunchtype\s+Off')
        # Bring back the observed value. The check item name is "hypervisorlaunchtype = Off",
        # Reading only the [FAIL] line would incorrectly imply 'it is Off and this counts as a failure', which is the exact opposite.
        HypervisorRaw = $(
            if ($cur -match '(?im)^\s*hypervisorlaunchtype\s+(\S+)') { $Matches[1] }
            else { '(This line is not in bcdedit — equivalent to the default value Auto)' })
        VbsStatus     = if ($dg) { [int]$dg.VirtualizationBasedSecurityStatus } else { -1 }
        Build         = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    }
}
$ok = $true
$ok = (Show-Check 'testsigning = Yes'          $pre.TestSigning)          -and $ok
$ok = (Show-Check 'hypervisorlaunchtype = Off' $pre.HypervisorOff `
            "Actually read: $($pre.HypervisorRaw)")                            -and $ok
$ok = (Show-Check 'VBS is disabled' ($pre.VbsStatus -eq 0) "Status code $($pre.VbsStatus)") -and $ok
if (-not $ok) {
    $hint = ''
    if (-not $pre.HypervisorOff) {
        # Most common cause: Hyper-V/VBS/WSL2, etc., are enabled in the guest.
        # Or BCD may have reverted to defaults after a forced power-off. If it is not Off, our driver
        # It will run **under two layers of hypervisor**, so readings from the entire run cannot be attributed.
        $hint = @"

hypervisorlaunchtype is currently "$($pre.HypervisorRaw)", which needs to be Off.
In the guest (as administrator), revert the changes, then restart the guest:
  bcdedit /set hypervisorlaunchtype off
Or directly run .\scripts\Configure-KswordHyperVGuest.ps1 (it will handle testsigning and VBS together).
"@
    }
    throw "Prerequisites not met — driver not loaded. $hint"
}

# Check if VMX is truly visible: use a probe instead of HypervisorPresent (which reads whether there is a hypervisor 'above').
if (Test-Path $prbPath) {
    Write-Host "`n  CPUID probe (whether VMX is passed through): "
    Send-ToGuest $prbPath 'C:\ksword\hvm_probe.exe'
    # The probe outputs UTF-8 using SetConsoleOutputCP(CP_UTF8). Direct `& exe | Out-String`
    # This causes PowerShell to decode using the guest's OEM code page, turning Chinese characters into mojibake like σÅ»τö¿
    # Looks like encoding corruption, but is actually a wrong decoding method. Redirect to a file and read back using UTF-8.
    $probe = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
        $o = 'C:\ksword\probe_out.txt'
        Remove-Item $o -ErrorAction SilentlyContinue
        $p = Start-Process -FilePath 'C:\ksword\hvm_probe.exe' -NoNewWindow -Wait -PassThru `
                 -RedirectStandardOutput $o -RedirectStandardError 'C:\ksword\probe_err.txt'
        if (Test-Path $o) {
            [IO.File]::ReadAllText($o, [Text.Encoding]::UTF8)
        } else {
            "(No output, exit code $($p.ExitCode))"
        }
    }
    $vmxOk = [bool]($probe -match 'VMX')
    ($probe -split "`n" | Where-Object { $_ -match '\[OK \]|\[NO \]' }) | ForEach-Object { Write-Host "   $_" }
    if ($probe -match '\[NO \].*ECX\[5\]') {
        # There are two completely different causes for 'VMX not visible'; the error message must distinguish them, otherwise it will mislead users.
        # Perform a round of troubleshooting on the host's nested virtualization settings.
        #
        # Our resident hypervisor **by design** clears CPUID.1:ECX[5].
        # (hvm_exit.c CPUID handling: clears VMX bits when Nested.Enabled is false).
        # Therefore, the combination of 'VMX cannot see it, but eVMCS/nested feature leaves are readable' is not
        # that nested virtualization is disabled. On the contrary, the previous run's resident hypervisor is still running.
        $nestedLeavesOk = ($probe -match '\[OK \].*eVMCS') -or
                          ($probe -match '\[OK \].*0x4000000A')
        if ($nestedLeavesOk) {
            throw @'
CPUID does not show VMX, but the nested feature leaf can be read back — these two observations have only one explanation:
**The resident hypervisor from the previous round is still running; it cleared the VMX bit as designed.**

Stop it first before deploying:
  .\scripts\Invoke-KswordHvmControl.ps1 -Stage stop

(The resident hypervisor outlives the process that launched it, so if a round fails and exits midway, it will not stop itself.)
'@
        }
        throw 'VMX not visible in CPUID, and nested feature leaf also unreadable -- nested virtualization not enabled, driver not loaded.'
    }
}

# ---------------------------------------------------------------------------
# 2. Open the guest kernel dump.
# ---------------------------------------------------------------------------
Write-Host "`n--- 2. Open guest kernel dump ---" -ForegroundColor Cyan
$dump = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $cc = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    # 2 = Kernel memory dump. Sufficient for C modules and much smaller than a full dump.
    Set-ItemProperty -Path $cc -Name CrashDumpEnabled -Value 2 -Type DWord
    Set-ItemProperty -Path $cc -Name AutoReboot       -Value 1 -Type DWord
    Set-ItemProperty -Path $cc -Name LogEvent         -Value 1 -Type DWord
    $now = Get-ItemProperty -Path $cc
    [ordered]@{ Enabled = [int]$now.CrashDumpEnabled; File = $now.DumpFile; Auto = [int]$now.AutoReboot }
}
Show-Check 'Kernel dump enabled (CrashDumpEnabled=2)' ($dump.Enabled -eq 2) "-> $($dump.File)" | Out-Null

# ---------------------------------------------------------------------------
# 3. Pre-load checkpoint
# ---------------------------------------------------------------------------
if (-not $SkipCheckpoint) {
    Write-Host "`n--- 3. Pre-loading Checkpoint ---" -ForegroundColor Cyan
    <#
      Trim old checkpoints created by self before creating a new one.

      This section belongs here; the cost of omitting it was paid on 2026-09-08: deploying the driver ten times in one night accumulated
      ten 'before-driver-load-*' snapshots, each consuming approximately 8 GiB of memory image plus a differencing disk, filling the
      system disk to 0% and causing Hyper-V to pause the virtual machine in PausedCritical state. The symptom is **the deployment
      command hangs without returning**—because it is waiting for a machine that is already frozen, not because any step is slow.

      Relying on the caller to remember adding -SkipCheckpoint is not a robust defense: forgetting is the norm, and the cost of forgetting is a
      complete system hang. Invoke-KswordHvmControl.ps1 already performed this truncation before creation; this script follows the same approach.
    #>
    try {
        $mine = @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop |
                  Where-Object { $_.Name -like 'before-driver-load-*' } |
                  Sort-Object CreationTime -Descending)
        if ($mine.Count -ge $KeepCheckpoints) {
            foreach ($old in $mine[($KeepCheckpoints - 1)..($mine.Count - 1)]) {
                Remove-VMSnapshot -VMName $VMName -Name $old.Name -Confirm:$false
                Write-Host "  Trimmed old checkpoint '$($old.Name)'" -ForegroundColor DarkGray
            }
            # Merge is asynchronous: even if we don't wait for it to finish, the next Checkpoint-VM may still hit out-of-space.
            $deadline = (Get-Date).AddMinutes(15)
            while ((Get-Date) -lt $deadline -and
                   (Get-VM -Name $VMName).Status -match 'Merg|合并') {
                Start-Sleep -Seconds 10
            }
        }
    } catch {
        Write-Host "  Checkpoint pruning failed (deployment unaffected): $($_.Exception.Message)" -ForegroundColor Yellow
    }
    $stamp = 'before-driver-load-' + (Get-Date -Format 'MMdd-HHmm')
    try {
        Checkpoint-VM -Name $VMName -SnapshotName $stamp
    } catch {
        # Insufficient space is a recoverable operational issue unrelated to the driver. Report separately and provide the cleanup command.
        if ("$($_.Exception.Message)" -match '0x80070070|磁盘空间不足|not enough space') {
            throw "Failed to create checkpoint: insufficient disk space, unrelated to driver. Cleanup: .\scripts\Clear-KswordVmCheckpoints.ps1 -Confirm"
        }
        throw
    }
    Write-Host "  Created '$stamp'" -ForegroundColor Green
    Write-Host "  Rollback: Restore-VMCheckpoint -VMName '$VMName' -Name '$stamp' -Confirm:`$false"
} else {
    Write-Host "`n--- 3. Checkpoint skipped (-SkipCheckpoint) ---" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 4. Send files, create service, and start
# ---------------------------------------------------------------------------
Write-Host "`n--- 4. Deploy and load driver ---" -ForegroundColor Cyan

# **Unload before copying.** Reversing this order causes redeployment to encounter
# "The process cannot access the file ... because it is being used by another
# process" — The loaded driver image is held by the kernel; it cannot be overwritten as long as the service is running.
# .sys. The file does not exist during the first deployment, so this ordering issue only manifests on the second deployment.
$unload = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $before = (& sc.exe query KswordARK 2>&1 | Out-String)
    $wasPresent = ($before -notmatch '1060')     # 1060 = Service does not exist.
    if ($wasPresent) {
        & sc.exe stop   KswordARK 2>&1 | Out-Null
        & sc.exe delete KswordARK 2>&1 | Out-Null
        Start-Sleep -Seconds 2
    }
    $after = (& sc.exe query KswordARK 2>&1 | Out-String)
    [ordered]@{
        WasPresent = [bool]$wasPresent
        StillThere = [bool]($after -notmatch '1060')
    }
}
if ($unload.WasPresent) {
    Show-Check 'Old driver unloaded (before copy)' (-not $unload.StillThere) | Out-Null
    if ($unload.StillThere) {
        throw 'Old driver is still running, cannot overwrite .sys. There may be unreleased handles; restart the guest and try again.'
    }
} else {
    Write-Host "  [OK]   No previously registered KswordARK service found" -ForegroundColor Green
}

Send-ToGuest $sysPath 'C:\Windows\System32\drivers\KswordARK.sys'
Send-ToGuest $cliPath 'C:\ksword\KswordCLI.exe'
Write-Host "  File delivered"

# Immediately compare hashes upon delivery.
#
# Before this point, **no link** in the entire script chain can guarantee that the guest is running the just-built version.
# Driver: Copy-VMFile silently fails, or PowerShell Direct chunked transfer truncates when falling back...
# The old service was not fully unloaded while the image was still held by the kernel — all three scenarios cause the next reading to fall on
# A driver of unknown version; this has already cost two rounds of attribution.
#
# The printed hash has a second use: it allows verifying which version was run in that round against the machine record.
$hostHash = (Get-FileHash $sysPath -Algorithm SHA256).Hash
$guestHash = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    (Get-FileHash 'C:\Windows\System32\drivers\KswordARK.sys' -Algorithm SHA256).Hash
}
Write-Host ("  Host SHA256 : {0}" -f $hostHash) -ForegroundColor DarkGray
Write-Host ("  guest SHA256: {0}" -f $guestHash) -ForegroundColor DarkGray
if ($hostHash -ne $guestHash) {
    throw @"
The driver sent into the guest is not the same as the one on the host — any readback in this round is unattributable, aborted.
  Host: $hostHash
  guest: $guestHash
Common causes: Old driver was not actually unloaded (image still held by kernel, overwrite silently discarded).
Action: Restart the guest and rerun this script.
"@
}
Write-Host "  [OK]   Hashes match, this is the freshly built version on the guest" -ForegroundColor Green

$load = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    $out = [ordered]@{}
    $sig = Get-AuthenticodeSignature 'C:\Windows\System32\drivers\KswordARK.sys'
    $out.SigStatus = "$($sig.Status)"
    $out.Signer    = "$($sig.SignerCertificate.Subject)"

    # If it exists, stop then delete to ensure the loaded file is the one just delivered.
    & sc.exe stop   KswordARK 2>&1 | Out-Null
    & sc.exe delete KswordARK 2>&1 | Out-Null
    Start-Sleep -Seconds 1

    $create = (& sc.exe create KswordARK type= kernel start= demand `
                  binPath= 'C:\Windows\System32\drivers\KswordARK.sys' 2>&1 | Out-String)
    $out.Create = $create.Trim()

    $start = (& sc.exe start KswordARK 2>&1 | Out-String)
    $out.Start = $start.Trim()
    $out.StartExit = $LASTEXITCODE

    $q = (& sc.exe query KswordARK 2>&1 | Out-String)
    $out.Query = $q.Trim()
    $out.Running = [bool]($q -match 'RUNNING')

    # The device's existence confirms that DriverEntry completed and created the symbolic link.
    # Must use CreateFileW: .NET's [IO.File]::Open directly rejects device objects during type checking.
    # ("FileStream was asked to open a device that was not a file"), that error message
    # Indicates the host script used the wrong API; this is unrelated to whether the device exists. The previous version reported this exact issue.
    # Fake FAIL.
    $out.DeviceOpen = $false
    try {
        Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KswDev {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
    public static int Probe(string path) {
        // GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|WRITE, OPEN_EXISTING
        IntPtr h = CreateFileW(path, 0xC0000000u, 3u, IntPtr.Zero, 3u, 0x80u, IntPtr.Zero);
        if (h == new IntPtr(-1)) { return Marshal.GetLastWin32Error(); }
        CloseHandle(h);
        return 0;
    }
}
'@ -ErrorAction SilentlyContinue | Out-Null
        $win32 = [KswDev]::Probe('\\.\KswordARKLog')
        $out.DeviceOpen = ($win32 -eq 0)
        if ($win32 -ne 0) {
            # 2 = device name does not exist; 5 = exists but access is denied. The two meanings are completely different.
            $out.DeviceError = "win32=$win32"
        }
    } catch { $out.DeviceError = "$($_.Exception.Message)" }
    $out
}

Write-Host ("  Driver Signature: {0} / {1}" -f $load.SigStatus, $load.Signer)
Write-Host ("  sc create: {0}" -f ($load.Create -replace '\s+', ' '))
Write-Host ("  sc start : {0}" -f ($load.Start  -replace '\s+', ' '))
$loaded = Show-Check 'Service is RUNNING' $load.Running
$dev    = Show-Check 'Device \\.\KswordARKLog can be opened' $load.DeviceOpen $load.DeviceError

if (-not $loaded) {
    Write-Host "`nsc query Original text: `n$($load.Query)" -ForegroundColor Yellow
    throw 'Driver failed to enter RUNNING state — do not treat this as a successful load. The output from the sc start command above is the primary clue.'
}

# ---------------------------------------------------------------------------
# 5. Query HVM capability status (**do not VMXON**)
# ---------------------------------------------------------------------------
Write-Host "`n--- 5. HVM capability status (read-only; does not start HVM)---" -ForegroundColor Cyan
$status = Invoke-Command -VMName $VMName -Credential $GuestCredential -ScriptBlock {
    & 'C:\ksword\KswordCLI.exe' r0 hvm-status 2>&1 | Out-String
}
Write-Host $status

Write-Host @"
Driver loaded, HVM **not yet started** (no VMXON).

The next step is a separate step, to be performed only after confirming that the capabilities report above is normal:
  * Launch HVM from the kernel page of the Qt main program, or
  * Start using the corresponding IOCTL

Rollback on error:
  Get-VMSnapshot -VMName '$VMName' | Select-Object Name,CreationTime
  Restore-VMCheckpoint -VMName '$VMName' -Name '<CheckpointName>' -Confirm:`$false

In case of a blue screen, the dump is in guest's $($dump.File), retrieve it:
  Copy-VMFile reverse is unavailable; use PowerShell Direct to read, or share it out within the guest.
"@ -ForegroundColor Yellow
