# Repository layout

[简体中文](zh-CN/repository-layout.md) · [Coding style](coding-style.md) · [Code map](maintenance.md)

Start at `KSword.sln` for the Windows applications, or use `tools/dev.py` to build
one contributor-facing target. Source directories describe responsibilities;
product versions and CPU architectures belong in build configuration.

| Location | Responsibility |
| --- | --- |
| `apps/desktop/` | Qt desktop application; each dock has its own module |
| `apps/cli/` | Command-line frontend |
| `apps/ark_light/` | Native lightweight frontend |
| `apps/launcher/`, `apps/setup/` | Startup compatibility and installation |
| `apps/taskbar/`, `apps/hud/`, `apps/uac_desktop/` | Companion applications |
| `drivers/ark/` | Kernel implementation and driver-specific tests |
| `integrations/` | API monitor, DWM agent, and Cheat Engine integration |
| `shared/ark_client/` | Driver transport and domain clients shared by frontends |
| `shared/driver/` | Authoritative R0/R3 wire declarations |
| `shared/evidence/` | Frontend-independent evidence processing |
| `shared/platform/` | Reusable platform utilities; some modules also require Qt Core |
| `tests/native/` | Small native regression executables, grouped by subject |
| `tools/`, `scripts/` | Source checks, development utilities, and operational scripts |
| `build/msbuild/` | Shared build configuration |
| `third_party/` | Vendored dependencies and attribution |
| `docs/`, `docs/zh-CN/` | English guides and corresponding Chinese copies |
| `docs/archive/`, `archive/` | Historical documentation and source snapshots |
| `artifacts/` | Ignored build outputs, audit reports, and local experiments |

## File and directory names

- First-party source folders use lowercase `snake_case`: `process_dock`,
  `ark_client`, and `api_monitor`. Use a domain name rather than `misc2`, a
  product version, or a developer's initials.
- C++ type and module files use PascalCase: `ProcessSnapshot.h`,
  `ProcessSnapshot.cpp`. Responsibility splits use `Type.Responsibility.cpp`
  and private support headers use `Type.Support.h`.
- C driver modules use lowercase `snake_case`: `ioctl_registry.c` and
  `ioctl_registry.h`. Keep a header and its implementation together.
- Keep conventional entry and build filenames such as `main.cpp`, `pch.h`,
  `resource.h`, `CMakeLists.txt`, `README.md`, and `AGENTS.md`.
- Python files use `snake_case.py`; public PowerShell commands retain
  `Verb-Noun.ps1`. Documentation uses descriptive `kebab-case.md` names.
- Preserve vendor filenames, original-language research records, resource
  identifiers, and filenames consumed by installed applications. A source
  folder rename must not silently rename an executable, DLL, protocol, or
  resource URL.

New source files must appear in every consuming `.vcxproj` and `.filters`.
Run `uv run --python 3.12 python tools/project_filters.py --write` after editing
project inputs. It keeps header/implementation pairs together, mirrors physical
folders, and groups shared inputs by repository path. `tools/check.py` rejects
filter drift. Use exact filename case even on Windows. Update source includes, resource
manifests, CI path filters, scripts, and both guide languages together.

## Build outputs

Applications and drivers share `artifacts/bin/<platform>/<configuration>/`,
including `artifacts/bin/x64/Release/`. Native test binaries
use their test project's ignored `x64/Release/` directory. Intermediate output,
local SDK installations, signing keys, and `.vcxproj.user` settings must not be
committed. Keep the root for the solution, repository policies, and automatic
MSBuild configuration.
