<#
.SYNOPSIS
    Compile two dependency-free small tools for the test machine: hvm_probe.exe and hvm_ctl.exe.

.DESCRIPTION
    Both use /MT for static CRT linking. This is not a style issue: a fresh Windows installation
    lacks VC++ redistributables, so dynamically linked EXEs fail to start in the guest with exit code
    0xC0000135 (STATUS_DLL_NOT_FOUND) and empty stdout/stderr—appearing as 'no command output' when
    the process never actually ran. Static linking eliminates the need to deploy the entire DLL set.

    /W4 /WX: These two tools send IOCTLs directly to the kernel; warnings here leave no room for 'later'.

.EXAMPLE
    .\Build-KswordHvmTools.ps1
#>
[CmdletBinding()]
param(
    [string] $VcVars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

if (-not (Test-Path $VcVars)) {
    # Change the installation method to change the path; use vswhere to locate it instead of guessing.
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $root = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($root) { $VcVars = Join-Path $root 'VC\Auxiliary\Build\vcvars64.bat' }
    }
}
if (-not (Test-Path $VcVars)) { throw "vcvars64.bat not found (tried $VcVars)" }

$targets = @(
    [pscustomobject]@{ Name = 'hvm_probe';    Dir = (Join-Path $repo 'tools\hvm_probe')    ; Libs = '' },
    [pscustomobject]@{ Name = 'hvm_ctl';      Dir = (Join-Path $repo 'tools\hvm_ctl')      ; Libs = '' },
    # hvm_target is the target for R-1 process handling: reports its main loop address and sends heartbeats to enable 'freeze effect'.
    # The three outcomes 'End of Effect', 'Wrong Page Selected with No Effect', and 'No Effect' are distinguishable externally. It does not touch the driver.
    # Just a regular process being handled.
    [pscustomobject]@{ Name = 'hvm_target';   Dir = (Join-Path $repo 'tools\hvm_target')   ; Libs = '' },
    # attest_probe runs on the **host**, not injected into the guest — it reads the runtime signed by the secure kernel.
    # Driver reports exist only on machines with VBS enabled, but the target machine requires VBS to be disabled.
    # Using /MT together is solely to maintain consistency with the other two, allowing the binary to run immediately after copying to another machine.
    # wintrust.lib: Computes Authenticode PE image hash (CryptCATAdminCalcHashFromFileHandle2).
    # The ImageHash in the report is this hash, **not** the file flat hash — it has been byte-mapped for afd.sys.
    [pscustomobject]@{ Name = 'attest_probe'; Dir = (Join-Path $repo 'tools\attest_probe') ; Libs = 'psapi.lib wintrust.lib' },
    # hvm_probe_dll is evidence of R-1 **DLL** injection: writes a file containing the PID when loaded.
    # It is a DLL, so use /LD instead of producing an EXE.
    [pscustomobject]@{ Name = 'hvm_probe_dll'; Dir = (Join-Path $repo 'tools\hvm_probe_dll'); Libs = ''; Dll = $true }
)

$failed = 0
foreach ($t in $targets) {
    $src = Join-Path $t.Dir ($t.Name + '.c')
    if (-not (Test-Path $src)) { Write-Host "  [Skipped] No $src" -ForegroundColor Yellow; continue }
    # DLL targets produce .dll; others produce .exe; /LD also changes the entry point and linking method.
    $isDll = [bool]$t.Dll
    $ext = if ($isDll) { '.dll' } else { '.exe' }
    $exe = Join-Path $t.Dir ($t.Name + $ext)
    $obj = Join-Path $t.Dir ($t.Name + '.obj')
    $ldFlag = if ($isDll) { '/LD' } else { '' }

    $cmd = "`"$VcVars`" >nul 2>&1 && cd /d `"$($t.Dir)`" && cl /nologo /W4 /WX /O2 /MT $ldFlag $($t.Name).c /Fe:$($t.Name)$ext /Fo:$($t.Name).obj $($t.Libs)"
    $out = cmd /c $cmd 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) {
        Write-Host "  [FAIL] $($t.Name)" -ForegroundColor Red
        Write-Host $out
        $failed++
        continue
    }
    Remove-Item $obj -ErrorAction SilentlyContinue
    $size = (Get-Item $exe).Length
    Write-Host ("  [OK]   {0,-10} {1,8:N0}  bytes  {2}" -f $t.Name, $size, $exe) -ForegroundColor Green
}

if ($failed -gt 0) { throw "$failed tools failed to compile" }
Write-Host "`nBoth tools are statically linked with /MT, so no additional VC++ runtime libraries are needed when deployed to the guest." -ForegroundColor Cyan
