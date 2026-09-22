# Building a contribution

[简体中文](zh-CN/development.md)

[Contribution guide](../CONTRIBUTING.md) · [中文贡献指南](zh-CN/contributing.md) · [Code map](maintenance.md)

Start with a project or an offline test, not the entire solution. Desktop UI and
CLI contributions can be built without the private release profile corpus or a
loaded kernel driver.

## Choose the smallest build

| Work | Prerequisites | Command from the repository root |
| --- | --- | --- |
| Source checks | Git, Python 3.12+, PowerShell 7 (`pwsh`) | `python tools/check.py` |
| Client, CLI parser, and filesystem tests | Windows, MSVC v143, Windows SDK | `python tools/dev.py test` |
| CLI executable and every help route | Same as native tests | `python tools/dev.py test --target cli` |
| ETW configuration tests | Native prerequisites + Qt 6.9.3 MSVC x64 (QtCore) | `python tools/dev.py test --target monitor-tests` |
| Full desktop executable | Native prerequisites + Qt 6.9.3 MSVC x64, SVG, Qt MSBuild | `python tools/dev.py build --target desktop` |
| Driver or driver-embedding editions | WDK and the component's driver/signing inputs | Follow component build and acceptance notes; not part of the starter command. |

Use `uv run --python 3.12 python` in place of `python` if using uv. The scripts
reuse the invoking interpreter, including Python steps launched by MSBuild.
CI can continue calling Python directly.

The native baseline is Visual Studio 2022 (Community or Build Tools), the
**Desktop development with C++** workload, the **MSVC v143 x64/x86 build tools**,
and a **Windows SDK**. The starter targets do not need WDK, administrator rights,
a signing certificate, or a driver loaded. Defaults are Release/x64, matching CI.

`Directory.Build.props` selects the 64-bit MSVC host tools for direct MSBuild,
IDE, and CI builds. The desktop's whole-program optimization can exhaust the
32-bit linker's address space. Host architecture is independent of the target
platform: Win32 targets still produce 32-bit binaries, and the selected toolset
remains unchanged. An explicit `PreferredToolArchitecture` override takes precedence.

## Discover and test

```powershell
uv run --python 3.12 python tools/dev.py doctor
uv run --python 3.12 python tools/dev.py test
```

`doctor` reports paths and missing inputs; MSBuild verifies the actual installed
toolset and SDK during the build. MSBuild discovery uses `MSBUILD_PATH`, PATH,
then Visual Studio's `vswhere`. For side-by-side installations, select one
explicitly with `--msbuild '<path-to-MSBuild.exe>'`. The script never installs
software, changes user environment variables, edits project files, signs an
artifact, or loads a driver.

`test` builds before running and stops on a build/test failure. It checks that
the expected artifact exists and is nonempty, so an unsuccessful build cannot
silently run an older test executable. Build/test output remains visible in the
terminal. Use `--dry-run` to inspect commands without compiling or executing tests.

Use `--target client-tests`, `cli-tests`, or `fs-tests` for a focused native test;
`--config Debug` selects a debug build. An explicitly installed alternate toolset
can be selected with `--toolset v145`; this does not change the project's v143
default or prove compatibility with the CI baseline.

## Qt desktop setup

Install the Qt **6.9.3 / MSVC 2022 64-bit** kit with **Core, GUI, Network, Widgets, and SVG**.
The MinGW kit cannot link these MSVC projects. Install Qt VS Tools' MSBuild
integration or use the standalone **3.5.0** MSBuild archive used in
[the CI workflow](../.github/workflows/ci.yml). Point to the directory containing
`qt.props`, `qt.targets`, and `qt_defaults.props`, not its parent directory.

If you need the standalone integration, these are the same download/extraction
steps as CI, scoped to the ignored repository dependency directory:

```powershell
New-Item -ItemType Directory -Force .deps | Out-Null
Invoke-WebRequest 'https://download.qt.io/official_releases/vsaddin/3.5.0/qt-vsaddin-msbuild-3.5.0.zip' -OutFile .deps/qt-msbuild.zip
Expand-Archive .deps/qt-msbuild.zip -DestinationPath .deps/QtVsTools -Force
$qtTargets = Get-ChildItem .deps/QtVsTools -Filter qt.targets -Recurse -File | Select-Object -First 1
if (!$qtTargets) { throw 'Qt MSBuild archive did not contain qt.targets.' }
$env:KSWORD_QT_MSBUILD = $qtTargets.Directory.FullName
```

Set `KSWORD_QT_DIR` to your installed kit, or pass `--qt-dir` explicitly:

```powershell
$env:KSWORD_QT_DIR = 'C:/Qt/6.9.3/msvc2022_64' # Replace with your installation.
uv run --python 3.12 python tools/dev.py doctor --target desktop
uv run --python 3.12 python tools/dev.py test --target monitor-tests
uv run --python 3.12 python tools/dev.py build --target desktop
```

Qt discovery also recognizes `QT_ROOT_DIR`, `QTDIR`, and the repository-local
`.deps/Qt/6.9.3/msvc2022_64`. Qt MSBuild discovery recognizes
`KSWORD_QT_MSBUILD`, `QtMsBuild`, `.deps/QtVsTools/msbuild`, and `.deps/QtVsTools`.
Explicit arguments take priority; a misspelled override is reported rather than
silently replaced with another installation. Debug Qt tests require debug Qt DLLs
and import libraries as well.

The desktop and CLI outputs are `artifacts/bin/x64/<configuration>/Ksword5.1.exe`
and `KswordCLI.exe`. Native test outputs are under their project directory's
`x64/<configuration>/`. The runner adds Qt's `bin` directory only to the child
environment when needed. It does not launch the desktop automatically.

## What a public checkout does not contain

- The reviewed release DynData profile corpus and registry optimization assets
  are generated separately. Their absence produces build warnings or unavailable
  features, not a requirement to create fake supported-kernel data.
- The desktop build does not require a driver binary. Without a compatible driver
  and profiles, R0 features remain unavailable. Test offline behavior first.
- Launcher consumes a generated support matrix. CI uses empty build-only fixtures;
  those fixtures are not a supported release matrix.
- ARKLight embeds `KswordARK.sys` as a resource. A full link/package therefore
  requires that driver artifact; successful C++ compilation alone is not a
  completed ARKLight build. Installer/release packaging also requires its payloads.

No private corpus or release signing key is needed for the starter test, CLI,
ETW configuration, or desktop compilation workflows above. Report feature
limitations when sharing a development binary.

## Troubleshooting and review evidence

| Symptom | Next step |
| --- | --- |
| MSBuild not found | Install the C++ workload, or use `--msbuild`; avoid assuming an edition-specific Visual Studio path. |
| MSB8020 / toolset unavailable | Install v143 in Visual Studio Installer, or explicitly select an already installed supported alternate toolset. |
| Windows SDK missing | Install the SDK component through Visual Studio Installer; rerun the same target. |
| Qt integration missing | Pass the actual directory containing `qt.targets` with `--qt-msbuild`. |
| Qt DLL missing at test startup | Verify the MSVC x64 kit and configuration; use `dev.py test` so the child receives Qt's DLL path. |
| Source/project audit misses a new file | Add it to Git, its consuming project, and the matching filters file. |
| Driver post-link validation or MSVC internal linker failure | Record the exact command and first error; follow [the recovery notes](../.claude/memory/ksword-build-recovery.md). Do not change compiler families or report a partial build as success. |

Before a PR, run `python tools/check.py` and the checks for affected behavior.
Include commands, results, and any unavailable runtime test environment. A local
v145 build, source audit, or offline regression does not substitute for CI's
v143 build or live driver/VM acceptance.
