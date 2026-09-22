# Host-side one-step execution: install the freshly built driver into the target VM, reboot to make it resident, launch TinyCore, press Enter, and capture the screenshot.
#
# Why make this a script: this section has six steps; missing just one yields a reading that looks like the phenomenon under test
#   1. The service ImagePath points to System32\drivers; copying only to C:\ksword causes the old driver to remain loaded and running.
#   2. Must run 'sc stop' before overwriting; otherwise, the copy is rejected but the script continues.
#   3. vmx86 does not restart; VMware still uses the original capability values cached at boot time.
#   4. VMware starts via PowerShell Direct (session 0), with the window on an invisible desktop,
#      Screen capture must be retrieved via VNC only;
#   5. The isolinux menu requires pressing Enter, and key presses can only be routed via VNC;
#   6. Record the hash of the built artifact separately for verification; matching hashes on both ends only prove faithful transmission.
param(
    [string] $VMName = 'KSword-HVM-Target',
    [string] $DriverPath = 'C:\Users\Felix\CLionProjects\KSword\Ksword5.1\x64\Release\KswordARK.sys',
    [string] $ShotDir,
    [switch] $SkipDriver
)

$ErrorActionPreference = 'Stop'
$vncScript = Join-Path $PSScriptRoot 'Get-VmwareVnc.ps1'
$built = (Get-FileHash $DriverPath -Algorithm SHA256).Hash
Write-Output "Build output sha256 = $built"

$cred = New-Object PSCredential('felix',
    (ConvertTo-SecureString 'password' -AsPlainText -Force))
$s = New-PSSession -VMName $VMName -Credential $cred

Invoke-Command -Session $s -ScriptBlock {
    # Verify that every processor has left resident mode before shutting down VMware. Driver updates may restart the test guest.
    & 'C:\ksword\hvm_ctl.exe' stop | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Resident hypervisor stop failed, prohibit removing VMware' }
    $state = (& 'C:\ksword\hvm_ctl.exe' --json status) | ConvertFrom-Json
    if ($null -eq $state.residentProcessorCount -or $state.residentProcessorCount -ne 0 -or
        $state.stateNames -contains 'ROLLBACK_REQUIRED') {
        throw 'Resident hypervisor still has active processors or pending rollback state, keep Windows running and stop deployment'
    }
    Get-Process -Name 'vmware', 'vmware-vmx' -ErrorAction SilentlyContinue |
        Stop-Process -Force
    Start-Sleep -Seconds 3
}

if (-not $SkipDriver) {
    # If it cannot stop, reboot the guest.
    #
    # In practice, this unload gets stuck in StopPending (the driver refuses to unload when it cannot be stopped), after which
    # Overwrites the file in System32\drivers that will inevitably report 'File in use', while the script throws there,
    # Leaves a partially completed deployment. A one-minute reboot is cheaper than manual intervention each time and avoids carrying over
    # Running the old driver downward is safe — the latter receives a reading that looks normal but actually measures the previous version.
    $stopped = Invoke-Command -Session $s -ScriptBlock {
        Start-Process 'C:\ksword\hvm_ctl.exe' -ArgumentList 'stop' -NoNewWindow -Wait | Out-Null
        & sc.exe stop KswordARK | Out-Null
        $n = 0
        while ((Get-Service KswordARK).Status -ne 'Stopped' -and $n -lt 30) {
            Start-Sleep -Milliseconds 500; $n++
        }
        Write-Output ("Driver stop status: " + (Get-Service KswordARK).Status)
        return ((Get-Service KswordARK).Status -eq 'Stopped')
    }
    if (-not ($stopped | Select-Object -Last 1)) {
        Write-Output 'Uninstall incomplete, reboot guest'
        Remove-PSSession $s
        Restart-VM -Name $VMName -Force -Confirm:$false
        Start-Sleep -Seconds 45
        $tries = 0
        while ($tries -lt 24) {
            $s = New-PSSession -VMName $VMName -Credential $cred -ErrorAction SilentlyContinue
            if ($s) { break }
            Start-Sleep -Seconds 10
            $tries++
        }
        if (-not $s) { throw 'Cannot connect to PowerShell Direct after the guest reboots' }
        Write-Output 'Guest has rebooted and reconnected'
    }
    Copy-Item -ToSession $s -Path $DriverPath -Destination 'C:\ksword\KswordARK.sys' -Force
    Invoke-Command -Session $s -ArgumentList $built -ScriptBlock {
        param($built)
        # Overwrites the file pointed to by the **service ImagePath**, not some assumed path.
        #
        # Real-world issue encountered: after the GUI starts, it re-registers the service to its own bundled version.
        # (C:\ksword\gui\KswordARK.sys, date is six days older than the current build). Deployment script
        # Still writing to System32\drivers, still verifying the hash there, still ensuring both ends match—
        # And it loads a different copy. Subsequently, all readings describe the driver from six days ago.
        # And no errors occur anywhere.
        $imagePath = (Get-ItemProperty `
            'HKLM:\SYSTEM\CurrentControlSet\Services\KswordARK' -Name ImagePath).ImagePath
        $target = $imagePath -replace '^\\\?\?\\', ''
        if ($target -notmatch '^[A-Za-z]:\\') {
            $target = Join-Path $env:SystemRoot ($target -replace '^\\?SystemRoot\\?', '')
        }
        [IO.File]::Copy('C:\ksword\KswordARK.sys', $target, $true)
        # Synchronize the other copy as well to avoid loading the old version if someone later points ImagePath back to it.
        $other = 'C:\Windows\System32\drivers\KswordARK.sys'
        if ($target -ne $other) { [IO.File]::Copy('C:\ksword\KswordARK.sys', $other, $true) }
        $h = (Get-FileHash $target -Algorithm SHA256).Hash
        if ($h -ne $built) { throw "The hash of $target pointed to by ImagePath is $h, which does not match the build output" }
        "Service ImagePath = $target"
        "This file sha256 = $h (consistent with build output)"
        & sc.exe start KswordARK | Out-Null
        Start-Sleep -Seconds 2
        "Driver started: " + (Get-Service KswordARK).Status
    }
}

Invoke-Command -Session $s -ScriptBlock {
    function Run($a) {
        $o = 'C:\ksword\ro.txt'
        $p = Start-Process 'C:\ksword\hvm_ctl.exe' -ArgumentList $a -NoNewWindow `
                -Wait -PassThru -RedirectStandardOutput $o
        return @{ Exit = $p.ExitCode; Out = [IO.File]::ReadAllText($o) }
    }
    # The criterion is the hidden bit of cpuid-view, not the state bits.
    #
    # The status bits for `resident-nested` and `resident-nested-hidehv` are **exactly the same**; both are
    # INITIALIZED … RESIDENT_ACTIVE RESIDENT_NESTED. Judge based on RESIDENT_ACTIVE
    # "Skip if already running" will reuse the non-hidden version when another (e.g., GUI menu) has started it;
    # However, VMware's identity gate precedes the capability gate: as soon as CPUID sees Microsoft Hv, it triggers.
    # "VMware Workstation and Hyper-V are not compatible"; it won't even read the capability MSR.
    # Real-world pitfall: status bits were all normal, yet VMware failed to start.
    # Must use prepare-eptpsw, not prepare.
    #
    # The difference between the two is ENABLE_EPTP_SWITCH. This machine has multiple cores and lacks the Monitor Trap Flag,
    # The private EPT path is **permanently unarmable** (view-probe will correctly return NOT_APPLICABLE),
    # Therefore, the CLOAK view here can only rely on EPTP switching backends. A resident instance started with a standard prepare,
    # Status bits are all normal and VMware runs as expected, yet `view-effect` returns "view installation failed"—
    # This means the virtualization line is advancing, yet EPT functionality remains disabled with no readings ever reported.
    #
    # Furthermore, the old implementation skips prepare when RESOURCES_READY is set, so once a machine has been used normally...
    # prepare was started previously, and subsequent deployments reuse that instance, so this bit can never be added. The check must look at...
    # The EPTP_SWITCH_ARMED capability bit itself is not equivalent to RESOURCES_READY.
    $st = (Run @('--json', 'status')).Out | ConvertFrom-Json
    $armed = ($st.featureNames -contains 'EPTP_SWITCH_ARMED')
    $hidden = $false
    if ($st.stateNames -contains 'RESIDENT_ACTIVE') {
        try { $hidden = ((Run @('--json', 'cpuid-view')).Out | ConvertFrom-Json).hidden } catch { }
    }
    if (-not ($hidden -and $armed)) {
        if ($st.stateNames -contains 'RESIDENT_ACTIVE') {
            Write-Output ("Resident but not meeting requirements (hidden=$hidden EPTP switch armed=$armed), stopping and restarting")
            $r = Run @('stop')
            if ($r.Exit -ne 0) { throw "stop exit code $($r.Exit)" }
        }
        if (-not $armed) {
            # Resources that have already been prepared must be torn down first; otherwise, prepare-eptpsw will be treated as a duplicate prepare.
            $r = Run @('teardown')
            if ($r.Exit -ne 0) { throw "teardown exit code $($r.Exit)" }
        }
        foreach ($cmd in 'prepare-eptpsw', 'self-test', 'resident-nested-hidehv') {
            $r = Run @($cmd)
            if ($r.Exit -ne 0) { throw "$cmd exit code $($r.Exit)" }
        }
    }
    $st = (Run @('--json', 'status')).Out | ConvertFrom-Json
    $view = (Run @('--json', 'cpuid-view')).Out | ConvertFrom-Json
    if (-not $view.hidden) {
        throw "Resident hypervisor started but cpuid-view's hidden is still false; VMware will refuse to start"
    }
    "Status bits = " + ($st.stateNames -join ' ')
    "cpuid-view hidden = " + $view.hidden + " (VMware's identity gate looks at this)"
    # EPT criteria are independent of the virtualization path; print this on every deployment.
    # Without this bit, the CLOAK view cannot be installed on this machine, while all other readings remain unchanged.
    if (-not ($st.featureNames -contains 'EPTP_SWITCH_ARMED')) {
        throw "EPTP_SWITCH_ARMED not set: EPT view cannot be installed on this machine"
    }
    "EPTP_SWITCH_ARMED = True (criterion for EPT view; without it, view-effect will readback as 'not installed')"
    # vmx86 restart: VMware queries MSR capabilities only once when this driver is running.
    & sc.exe stop vmx86 | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe start vmx86 | Out-Null
    "vmx86 = " + (Get-Service vmx86).Status

    $vmx = 'C:\Users\felix\Documents\Virtual Machines\Other Linux 6.x kernel 64-bit\Other Linux 6.x kernel 64-bit.vmx'
    Start-Process -FilePath 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe' `
        -ArgumentList @('-T', 'ws', 'start', "`"$vmx`"") -NoNewWindow
    Start-Sleep -Seconds 40
    "vmware-vmx = " + @(Get-Process -Name 'vmware-vmx' -ErrorAction SilentlyContinue).Count
}

# isolinux menu: Enter (X11 keysym 0xFF0D). The menu also times out and boots automatically.
# But that requires waiting 60 seconds, and the fact that the countdown is running itself is the criterion that the clock is connected; pressing a key is faster.
Invoke-Command -Session $s -FilePath $vncScript `
    -ArgumentList '127.0.0.1', 5900, 'C:\vmware\shot-menu.png', @(65293)

Start-Sleep -Seconds 75
Invoke-Command -Session $s -FilePath $vncScript `
    -ArgumentList '127.0.0.1', 5900, 'C:\vmware\shot-boot.png'

if ($ShotDir) {
    foreach ($f in 'shot-menu.png', 'shot-boot.png') {
        Copy-Item -FromSession $s -Path "C:\vmware\$f" -Destination (Join-Path $ShotDir $f) -Force
    }
    Write-Output ("Screenshot retrieved " + $ShotDir)
}
Remove-PSSession $s
