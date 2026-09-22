# Preparing a release

[简体中文](zh-CN/releasing.md) · [Documentation index](README.md)

Run commands from the repository root. A release archive must contain a complete
`Release/` directory. Select a known reference archive explicitly; do not assume
another contributor has a particular developer's previous package.

## Build the binaries

Use [the development guide](development.md) and `python tools/dev.py doctor
--target desktop` to discover MSBuild, Qt, and Qt MSBuild. Set `$msbuild`,
`$env:KSWORD_QT_DIR`, and `$qtMsBuild` to those paths. Prefer repository-local
dependencies when present; do not encode workstation paths in project files.

Build the desktop, Launcher, Taskbar, HUD, and API monitor in Release/x64 before
copying their outputs into the package:

```powershell
$projects = @(
    'apps/desktop/KswordDesktop.vcxproj',
    'apps/launcher/Launcher.vcxproj',
    'apps/taskbar/Taskbar.vcxproj',
    'apps/hud/KswordHUD.vcxproj',
    'integrations/api_monitor/APIMonitor_x64.vcxproj'
)
foreach ($project in $projects) {
    & $msbuild $project /t:Build /p:Configuration=Release /p:Platform=x64 "/p:QtMsBuild=$qtMsBuild" /m:1 /v:minimal
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $project" }
}
```

The desktop project also builds the DWM ordering DLL through its project reference.
Include a current ARKLight executable; its full link requires the embedded driver.
If the current machine cannot build the WDK driver, packaging may reuse the
existing unsigned `KswordARK.sys`, `KswordARK.pdb`, and `KswordARKDriver.inf` from
`artifacts/bin/x64/Release/`. Explicitly record that reuse and the artifact identities;
do not describe it as a freshly built driver.

## Internal linker and WDK recovery

For desktop MSVC `LNK1000`, `IMAGE::BuildImage`, or `.iobj` internal errors, first
perform **one** clean rebuild with WPO/LTCG disabled only for that invocation.
Do not switch to LLVM, `amd64/MSBuild.exe`, another TargetName, or automatically
upgrade/downgrade MSVC. The established local helper, when installed, is:

```powershell
& "$env:USERPROFILE/.codex/skills/ksword-build-check/scripts/Invoke-KSwordBuildCheck.ps1" `
  -RepositoryRoot (Get-Location).Path -Action Rebuild -DisableWholeProgramOptimization
```

The helper is not a repository prerequisite. Its temporary props must not become
project settings. Success requires `BUILD_RESULT=SUCCESS`, `EXIT_CODE=0`, and a
nonempty `artifacts/bin/x64/Release/Ksword5.1.exe`. Use `-VerifyArtifactOnly` afterward;
an immediate normal Build invalidates the WPO-disabled incremental state. Consider
VS servicing or a parallel v143 installation only if this recovery also fails.
See [the detailed recovery record](../.claude/memory/ksword-build-recovery.md).

If the driver linked successfully but WDK selected an ARM64 validator or stalled
without children, record the exact MSBuild PID and command line. Confirm the
updated `.sys` identity and that no `cl.exe`, `link.exe`, `ApiValidator.exe`, or
`aitstatic.exe` child is active before stopping that specific stalled MSBuild.
An interrupted Build is not a successful full build. Validate the linked driver
separately with the installed **x64** WDK validator:

```powershell
$solutionDir = (Resolve-Path 'Ksword5.1').Path + '\'
# Set $apiValidatorX64 to Windows Kits/10/bin/<installed-WDK-version>/x64.
& $msbuild 'drivers/ark/KswordARKDriver.vcxproj' /t:ApiValidator `
  /p:Configuration=Release /p:Platform=x64 "/p:SolutionDir=$solutionDir" `
  "/p:ApiValidator_ApiExtractorExePath=$apiValidatorX64" /m:1 /v:minimal
```

`Driver is 'Universal'.` establishes this independent API/architecture check.
Report compilation/linking, validation, INF/CAT generation, signing, and actual
loading separately. If failure preceded linking, fix that failure first.

## Assemble the package

Choose a new staging directory under `dist/`, such as
`dist/KswordARK-release-work/`. Refuse to overwrite an existing staging directory
until its contents have been inspected. Extract the reference archive there;
it must produce `Release/`. Preserve the complete Qt layout: `platforms`, `styles`,
`imageformats`, `iconengines`, `generic`, `networkinformation`, `tls`, `translations`,
and `qtadvanceddocking.dll`.

Overlay current files from `artifacts/bin/x64/Release/`:

| Destination under `Release/` | Required contents |
| --- | --- |
| Root | `Ksword5.1.exe`, `Launcher.exe`, `KswordARKLight.exe`, `Taskbar.exe`, `KswordHUD.exe`, `APIMonitor_x64.dll`, `APIMonitor_x64.pdb`, `KswordDwmZOrder.dll`, `KswordARK.sys`, `KswordARK.pdb`, `KswordARKDriver.inf` |
| `profiles/` | `ark_dyndata_pack_v4.json.qz`, `launcher_support_manifest.json`, `registry_optimization_items.json.qz`, complete `registry_optimization_assets/` |
| `languages/` | Replace the old directory with the current language directory, including `zh-CN.json` and `en-US.json` |
| `drivers/ark/` | Another copy of `KswordARK.sys` and `KswordARKDriver.inf` |

Copy root `LICENSE` and `COMMUNITY_COVENANT.md`. Under `licenses/third_party/`,
include these vendored texts without modification:

| Source under `third_party/` | Packaged name |
| --- | --- |
| `systeminformer_dyn/LICENSE.txt` | `systeminformer-LICENSE.txt` |
| `systeminformer_dyn/NOTICE.md` | `systeminformer-NOTICE.md` |
| `easy_hwid_spoofer/LICENSE.txt` | `easy-hwid-spoofer-LICENSE.txt` |
| `easy_hwid_spoofer/NOTICE.md` | `easy-hwid-spoofer-NOTICE.md` |
| `fltk/LICENSE.txt` | `fltk-LICENSE.txt` |
| `qt_advanced_docking_system/LICENSE.txt` | `qt-advanced-docking-system-LICENSE.txt` |
| `zstd/LICENSE.txt` | `zstd-LICENSE.txt` |

The registry optimization build emits the compressed `.json.qz` file and removes
the uncompressed copy; stage and check the compressed output. Refresh optional
shipped tools and runtime scripts when present, including `TaskmgrHijack.ps1`
copied by the desktop project from `scripts/runtime/`.

## Archive and verify

Use 7-Zip from PATH or an explicit installation path. Choose a new archive name
under `dist/` with the release date and version/feature description. Run from the
staging directory so the archive root is exactly `Release/`:

```powershell
$seven = (Get-Command 7z.exe -ErrorAction Stop).Source
$archive = Join-Path (Get-Location) 'dist/KSword-release.7z' # Choose a unique name.
if (Test-Path -LiteralPath $archive) { throw 'Choose a new archive filename.' }
Push-Location 'dist/KswordARK-release-work'
try {
    & $seven a -t7z -mx=9 -mmt=on $archive 'Release'
    if ($LASTEXITCODE -ne 0) { throw 'Archive creation failed.' }
} finally { Pop-Location }
& $seven t $archive
if ($LASTEXITCODE -ne 0) { throw 'Archive verification failed.' }
& $seven l $archive
```

Require `Everything is Ok`, then verify each file in the tables above, plus
`Release/platforms/qwindows.dll` and
`Release/profiles/registry_optimization_assets/Config/Data.zip`. Compare staged
binary hashes with the chosen build outputs; archive integrity alone does not
prove that fresh binaries were packaged. The application reads its license and
loads `KswordDwmZOrder.dll` alongside the executable. Never package the enclosing
`dist/KswordARK-release-work/` directory as an extra archive root.
