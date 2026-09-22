<#
.SYNOPSIS
    Diagnose the loaded KswordARK driver: verify if the device is actually openable, if CLI communication works, and check HVM capability status.

.DESCRIPTION
    Must run as **Administrator**.

    Two differences from the previous version (in the previous version, I used the wrong method for both, not a driver issue):

      * Device inspection now uses **CreateFileW**. .NET's [IO.File]::Open cannot open device
        objects; it throws "FileStream was asked to open a device that was not a file".
        That error indicates the host script used the wrong API, not that \\.\KswordARKLog does not exist.

      * Redirect native exe output to a file within the guest, then read it back.
        When `& exe | Out-String` passes through PowerShell Direct, the native process's stdout/stderr
        are swallowed, resulting in blank output—this does not mean the command produced no output.

.PARAMETER GuestPassword
    Guest administrator password. This is a one-time isolated test VM; the default value is hardcoded by convention to avoid repeated prompts.

.EXAMPLE
    .\Test-KswordDriverInVm.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [string[]] $CliCommands = @('r0 hvm-status', 'r0 capabilities', 'help')
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

function Invoke-Guest {
    # Note: The parameter name cannot be $Args—that is a PowerShell automatic variable and would conflict with the built-in.
    # The behavior is that -ArgumentList receives a null value and reports 'argument is null or empty'.
    param([scriptblock] $Script, [object[]] $ScriptArgs)
    if ($null -eq $ScriptArgs -or $ScriptArgs.Count -eq 0) {
        # -ArgumentList does not accept empty arrays, so omit this parameter when there are no arguments.
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script
    } else {
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script -ArgumentList $ScriptArgs
    }
}

Write-Host "=== 1. Services and Devices ===" -ForegroundColor Cyan

$svc = Invoke-Guest {
    $q = (& sc.exe query KswordARK 2>&1 | Out-String)
    $c = (& sc.exe qc    KswordARK 2>&1 | Out-String)
    [ordered]@{ Running = [bool]($q -match 'RUNNING'); Query = $q.Trim(); Config = $c.Trim() }
}
Write-Host ("  Service RUNNING : {0}" -f $svc.Running)

# Use CreateFileW to open the device. This is the only correct approach — the device object is not a file.
# .NET file APIs will directly reject based on type checking, regardless of whether the device exists.
$dev = Invoke-Guest {
    $sig = @'
using System;
using System.Runtime.InteropServices;
public static class Dev {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);
    public static string Probe(string path) {
        // GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|WRITE, OPEN_EXISTING
        IntPtr h = CreateFileW(path, 0xC0000000u, 3u, IntPtr.Zero, 3u, 0x80u, IntPtr.Zero);
        if (h == new IntPtr(-1)) {
            return "FAIL win32=" + Marshal.GetLastWin32Error();
        }
        CloseHandle(h);
        return "OK";
    }
}
'@
    Add-Type -TypeDefinition $sig -Language CSharp | Out-Null
    [ordered]@{
        Log = [Dev]::Probe('\\.\KswordARKLog')
    }
}
Write-Host ("  \\.\KswordARKLog : {0}" -f $dev.Log)
if ($dev.Log -ne 'OK') {
    Write-Host "  (win32=2 means the device name does not exist; win32=5 means it exists but access is denied -- the two meanings are completely different)" -ForegroundColor Yellow
}

Write-Host "`n=== 1b. CLI Runtime ===" -ForegroundColor Cyan
# KswordCLI.exe uses a dynamically linked CRT (as shown by dumpbin, it depends on MSVCP140 / VCRUNTIME140 /
# VCRUNTIME140_1.dll), and a fresh Windows installation lacks the VC++ runtime. The symptom of missing it is that the process
# The process fails to start entirely with exit code 0xC0000135 (STATUS_DLL_NOT_FOUND), and both stdout/stderr are empty —
# Looks like 'no command output', but actually the exe failed to start.
$crtNames = @('MSVCP140.dll', 'VCRUNTIME140.dll', 'VCRUNTIME140_1.dll')

foreach ($dll in $crtNames) {
    # Directly take the copy from the host's System32 — it is the exact same file installed by the VC++ redistributable.
    # Version matches the local compiler. Place it in the same directory as the exe: the application directory is searched before System32.
    $src = Join-Path $env:SystemRoot ('System32\' + $dll)
    if (-not (Test-Path $src)) { Write-Host "  [FAIL]  $dll not found on the host" -ForegroundColor Red; continue }
    $already = Invoke-Guest { param($n) Test-Path "C:\ksword\$n" } -ScriptArgs @($dll)
    if ($already) { Write-Host "  [OK]   $dll is already in the guest" -ForegroundColor Green; continue }
    try {
        Copy-VMFile -Name $VMName -SourcePath $src -DestinationPath "C:\ksword\$dll" `
                    -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    } catch {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($src))
        Invoke-Guest {
            param($data, $target)
            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            [IO.File]::WriteAllBytes($target, [Convert]::FromBase64String($data))
        } -ScriptArgs @($b64, "C:\ksword\$dll")
    }
    Write-Host ("  [OK]   Sent {0} (Host System32)" -f $dll) -ForegroundColor Green
}

Write-Host "`n=== 2. CLI Communication ===" -ForegroundColor Cyan
Write-Host "  (Native exe output is redirected to a file within the guest and then read back to avoid being swallowed by PowerShell Direct)"

foreach ($cmd in $CliCommands) {
    Write-Host "`n  --- KswordCLI.exe $cmd ---" -ForegroundColor Cyan
    $r = Invoke-Guest {
        param($arguments)
        $exe = 'C:\ksword\KswordCLI.exe'
        if (-not (Test-Path $exe)) { return [ordered]@{ Missing = $true } }
        $o = 'C:\ksword\out.txt'
        $e = 'C:\ksword\err.txt'
        Remove-Item $o, $e -ErrorAction SilentlyContinue
        $split = $arguments -split ' '
        $p = Start-Process -FilePath $exe -ArgumentList $split -NoNewWindow -Wait -PassThru `
                 -RedirectStandardOutput $o -RedirectStandardError $e
        [ordered]@{
            Missing = $false
            Exit    = $p.ExitCode
            Out     = if (Test-Path $o) { Get-Content $o -Raw -Encoding UTF8 } else { '' }
            Err     = if (Test-Path $e) { Get-Content $e -Raw -Encoding UTF8 } else { '' }
        }
    } -ScriptArgs @($cmd)

    if ($r.Missing) { Write-Host "  CLI not found at C:\ksword\KswordCLI.exe" -ForegroundColor Red; continue }
    Write-Host ("  Exit code: {0}" -f $r.Exit)
    if ($r.Out) { Write-Host "  --- stdout ---"; Write-Host $r.Out }
    if ($r.Err) { Write-Host "  --- stderr ---" -ForegroundColor Yellow; Write-Host $r.Err }
    if (-not $r.Out -and -not $r.Err) { Write-Host "  (Both streams are empty)" -ForegroundColor Yellow }
}

Write-Host "`n=== 3. Driver-side event logs (if any) ===" -ForegroundColor Cyan
$evt = Invoke-Guest {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddMinutes(-30) } `
        -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match 'Ksword|KswordARK' } |
      Select-Object -First 10 TimeCreated, Id, LevelDisplayName,
                    @{ n = 'Msg'; e = { ($_.Message -split "`n")[0] } }
}
if ($evt) { $evt | Format-Table -AutoSize } else { Write-Host "  (No Ksword-related system events in the last 30 minutes)" }
