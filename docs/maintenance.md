# Maintaining KSword

[简体中文](zh-CN/maintenance.md)

KSword is a set of Windows C/C++ applications sharing a driver protocol, a
user-mode driver client, and reusable analysis code. Start with the boundary
that owns the behavior you are changing, then build its consumers.

New contributors can start with the [first-PR guide](../CONTRIBUTING.md) and
[developer setup](development.md). `tools/dev.py test` builds and runs the native
starter tests without Qt or WDK; the build guide lists the additional desktop inputs.

## Where code belongs

| Responsibility | Location | Boundary |
| --- | --- | --- |
| Wire structs, versioning, IOCTL numbers | `shared/driver/` | The only definition consumed by both R0 and R3. |
| Device access, request/response validation | `shared/ark_client/` | UI code calls this client rather than issuing KswordARK IOCTLs. |
| Driver routing and common validation | `drivers/ark/src/dispatch/` | Register handlers in `ioctl_registry.c`; keep business logic out of the dispatcher. |
| Kernel feature implementation | `drivers/ark/src/features/<module>/` | Each module owns its handlers and capability requirements. |
| Reusable evidence and decision logic | `shared/evidence/` | Keep acquisition and window state separate from analysis. |
| Full desktop presentation | `apps/desktop/*_dock/`, `ui/` | Own display state, user intent, asynchronous lifecycle, and navigation. |
| Lightweight presentation and orchestration | `apps/ark_light/features/`, `core/`, `ui/` | Preserve the Win32 edition's independence from Qt. |
| Command-line entry points | `apps/cli/` | Keep command parsing, built-in help, and `docs/zh-CN/cli.md` synchronized. |
| Startup and distribution | `apps/launcher/`, `apps/setup/` | Keep support-manifest and embedded-payload validation at the application boundary. |
| Development checks and CI impact selection | `tools/check.py`, `tools/ci_changes.py` | Local runs and CI share executable rules. |

Read [the shared memory index](../.claude/memory/MEMORY.md) and its relevant
topic before changing a feature. For UI work, also read
[UI architecture](../.claude/memory/ksword-ui-architecture.md). These notes
record constraints that are not apparent from a single source file.

## Desktop window modules

`MainWindow.h` is the window's public Qt API and state owner. It forward-declares
Dock types where possible; implementation files include the Dock headers they
actually use. `MainWindow.cpp` contains construction, shutdown, and startup
progress. Add feature behavior to its owning unit rather than growing that file.

| Responsibility | Implementation (`apps/desktop/`) |
| --- | --- |
| Dock creation, lazy loading, layout persistence | `MainWindow.Docking.cpp`, `MainWindow.DockTabs.cpp` |
| Page navigation and crash-dump entry points | `MainWindow.Navigation.cpp` |
| Theme application and application QSS blocks | `MainWindow.Appearance.cpp`, `MainWindow.StyleSheet.cpp` |
| Image loading, generation checks, background rendering | `MainWindow.Background.cpp`, `MainWindow.BackgroundSupport.h` |
| Native window events, backdrop, z-order | `MainWindow.NativeFrame.cpp` |
| Title bar, menus, command launching | `MainWindow.TitleBar.cpp`, `MainWindow.Menus.cpp`, `MainWindow.Commands.cpp` |
| Qt event filters and delegates | `MainWindow.WidgetBehavior.cpp` |
| Privilege presentation and Win32 token operations | `MainWindow.Privileges.cpp`, `MainWindow.Win32Privileges.cpp` |
| Driver-service UI and SCM worker operations | `MainWindow.DriverService.cpp`, `MainWindow.DriverServiceBackend.cpp` |
| Bugcheck diagnostics and KVM integration | `MainWindow.Bugcheck.cpp`, `MainWindow.Kvm.cpp` |

`MainWindow.*Support.h` files are private implementation contracts in
`ksword::ui::main_window`. They expose helpers needed by multiple window units;
other features should use the public window API or their own service interface.
Keep the service-operation latch in its single backend definition. Preserve the
notification shutdown barrier, worker completion guards, and background-image
generation checks when changing asynchronous code.

## File, process, and monitor modules

The Dock classes still own Qt state and asynchronous lifetimes. Their `.cpp`
entry files contain construction and destruction; named implementation files
own the corresponding operations. Private `*.Support.h` contracts are local
to each feature, in `ksword::ui::file_dock`, `process_dock`, or `monitor_dock`.
Do not include these private headers from unrelated features.

| Feature | Where to change behavior |
| --- | --- |
| File browsing | `FileDock.Navigation.cpp`, `Models`, `Recovery`, `ContextMenu`, `Transfer`, `Deletion`, `Unlock`, `Security`, and `Oplocks` |
| File properties | `FileDetailDialog.h` declares the dialog; `FileDetailDialog.*.cpp` separates lifecycle, lazy pages, metadata editing, transactions, security, hashing, and storage. |
| File backend helpers | `FileDock.*Support.cpp` owns path, recovery, integrity, deletion, transfer, and access operations. |
| Process acquisition and display | `ProcessDock.Acquisition.cpp`, `Refresh`, `TableModel`, `TableData`, `DisplayOrder`, and `ActivityHistory` |
| Process actions | `ProcessDock.ActionDispatch.cpp`, `DriverControl`, `HvmActions`, `Termination`, `ProcessControl`, and `CreateProcess` |
| Process activity widgets | `ProcessActivityChartWidget.*` and `ProcessActivityTimelineSlider.*` own painting, scale calculation, and interaction. |
| WMI monitoring | `MonitorDock.WmiDiscovery.cpp`, `WmiCapture`, `WmiExport`, and `WmiUi` |
| ETW monitoring | `MonitorDock.EtwSession.cpp`, `EtwCapture`, `EtwDelivery`, `EtwArchive`, `EtwDecoding`, and `EtwExport` |
| ETW decoding helpers | `MonitorDock.Schema.cpp`, `PropertyDecoding`, `EventMeaning`, `EventFields`, and `ArchiveCodec` |
| ETW filter UI | `MonitorDock.FilterUi.cpp`, `FilterCompile`, `FilterApply`, `FilterStorage`, and `FilterImportExport` |
| ETW filter document format | `EtwFilterConfig.h/.cpp`: QtCore-only models, stable field metadata, parsing, and serialization |

The file report preference and ETW schema cache each retain one definition,
rather than creating state per translation unit. Oplock records stay private to
`FileDock.Oplocks.cpp`; their handle cleanup remains with their owner. The
process activity copy template remains in the private header because multiple
translation units instantiate it.

ETW configuration parsing receives explicit pre/post provider and action
catalogs. It constructs a candidate and assigns the output only after validating
the complete document. Import and export share one serializer; the widget layer
captures values and handles dialogs, file persistence, and capture state.
`KswordMonitorTests` covers versions, invalid input without partial commits,
stage-specific catalogs, and every field/string-mode round trip without creating
a window or starting a capture:

```powershell
# KSWORD_QT_DIR must name the Qt installation used for the application.
msbuild tests/native/monitor/KswordMonitorTests.vcxproj /p:Configuration=Release /p:Platform=x64
$env:PATH = (Join-Path $env:KSWORD_QT_DIR 'bin') + ';' + $env:PATH
./tests/native/monitor/x64/Release/KswordMonitorTests.exe
```

## CLI modules

`KswordCLI.cpp` owns console setup and the exception boundary. Command handlers
live in `CliProcess.cpp`, `CliMemory.cpp`, `CliFile.cpp`, and other domain files.
`CliArguments.h/.cpp` owns numeric, named-argument, PID-list, and hex parsing.
`CliIo.cpp` delegates transport and handle ownership to `ArkDriverClient`.
`CliOutput.cpp` owns common output formatting. `CliSupport.h` is an internal
contract between these units, not a second public driver API.

`CliHelp.cpp` holds command metadata and the family registry used by dispatch.
When adding a family, register its handler there. When changing commands or
arguments, update the built-in metadata and `docs/cli.md` (regenerate with `tools/generate_cli_docs.py`) and
  `docs/zh-CN/cli.md` together.
`KswordCliTests` covers parser bounds, invalid bytes, named arguments, and PID
lists; `tools/test_cli_help.py` executes every declared family/command help route
and its alias against the built executable. An optional `--baseline` executable
compares existing help output byte for byte.

```powershell
msbuild tests/native/cli/KswordCliTests.vcxproj /p:Configuration=Release /p:Platform=x64
./tests/native/cli/x64/Release/KswordCliTests.exe
uv run --python 3.12 python tools/test_cli_help.py --exe artifacts/bin/x64/Release/KswordCLI.exe
```

## Driver-client modules

`ArkDriverClient.h` remains the public operation API. `ArkDriverClient.cpp` owns
device transport, handle lifetime, and notification synchronization. Process
control, thread control, enumeration, security, injection, and firmware operations
have separate `ArkDriver*.cpp` implementations. Audit acquisition is divided by
network, storage, security, Win32k, device, platform, I8042, object, and DynData
responsibility.

`ArkDriverTypes.h` is a compatibility umbrella. New code that only needs a result
type can include its domain header, such as `ArkDriverProcessTypes.h` or
`ArkDriverIoTypes.h`. These headers hold R3 models; wire layouts still belong
exclusively to `shared/driver/`.

Shared internal response policy lives in three headers:

- `ArkDriverResponseSupport.h`: bounded fixed-field strings and explicit error
  classifiers. Missing IOCTLs, legacy invalid-parameter compatibility, and protocol
  version mismatches have different policies; do not collapse them.
- `ArkDriverAuditSupport.h`: fixed response validation and variable-row parsing.
  Bound counts and allocations by available bytes and require a complete stride.
- `ArkDriverNetworkSupport.h`: metadata validation and completeness decisions.
  Inventory permits documented partial snapshots; endpoints discard failed rows.

`KswordArkClientTests` exercises these contracts without Qt, elevation, or a loaded
driver, including protected-page string boundaries, malformed responses,
oversized counts, partial results, and real Windows handle ownership:

```powershell
msbuild tests/native/ark_client/KswordArkClientTests.vcxproj /p:Configuration=Release /p:Platform=x64
./tests/native/ark_client/x64/Release/KswordArkClientTests.exe
```

The CI source-integrity job builds and runs this target on Windows. Compiling the
application and its other consumers is still required when moving implementations
or changing public headers.

## Source checks

From the repository root, with Git and Python 3.12 or newer:

```powershell
python tools/check.py
```

An equivalent local command when using uv is:

```powershell
uv run --python 3.12 python tools/check.py
```

No Python packages, Qt installation, administrator privileges, or loaded driver
are required for these checks. Each check runs even if an earlier one fails;
the final exit code is nonzero if any check failed. IOCTL findings are written
to `artifacts/ioctl-audit.md`, including when the IOCTL policy check fails.

To list checks or run a focused subset:

```powershell
python tools/check.py --list
python tools/check.py --check projects --check tool-tests
python tools/check.py --check i18n --check theme
```

The default set validates tracked JSON, MSBuild source/filter membership,
English comment prose in C/C++, Python, and XML, tooling regression tests,
language packs, kernel knowledge, the HVM command
catalog and private EPT invariants, theme tokens, and IOCTL access policy.
It does not compile C/C++, run VM acceptance, or establish driver loadability.
The CI workflow retains the separate MSVC arithmetic tests and native builds.

The JSON and project checks use Git's tracked-file inventory. Add new source
files to Git before running them. They read working-tree content, so edits to
tracked files do not need to be committed or staged for validation.

## Adding or moving a source file

1. Select its owning module from the table above. Keep protocol definitions in
   `shared/driver/`, and move independently testable decisions out of UI callbacks.
2. Add the file to every consuming `.vcxproj` and the corresponding
   `.vcxproj.filters`. Match item types exactly: a `QtMoc` header must not appear
   as `ClInclude` in the filters file. Preserve existing filter organization.
3. Add the file to Git, then run `python tools/check.py --check projects`.
4. If a consumer gains a dependency on another directory, update
   `PROJECT_INPUTS` in `tools/ci_changes.py` and add a regression case in
   `tools/tests/test_ci_changes.py`.
5. Build the affected native projects, run their tests, and then run the full
   source checks before review.

`tools/project_audit.py` checks every tracked `.vcxproj`, including projects
outside the main solution. It detects missing/stale filter entries, duplicate
source items, incorrect item types, untracked or wrongly cased input paths,
and deleted source inputs. Dynamic MSBuild items are left to MSBuild. The only
literal generated-input exceptions are the two installer payload resource files
produced by `GenerateKswordSetupPayload`.

This is not an MSBuild evaluator or an orphan-file detector: it cannot decide
which project should own a source file that no project references. Review that
ownership explicitly. It also does not prove that a translation unit compiles.

## Refactoring a large feature

Use a behavior-preserving slice with a named input and result. For example,
`shared/evidence/MemoryTamperCrossView.cpp` is consumed by both the desktop
project and `tests/native/ark_light/MemoryTamperCrossViewTests.cpp`; this is an
existing home for analysis that should be testable without opening a window
or talking to a driver.

Before extracting code, identify which layer owns handles, buffers, cancellation,
and callback lifetimes. Keep those owners explicit. Preserve process creation
time alongside PID, generation checks for asynchronous results, bounded buffer
validation, and capability checks. Splitting a function must not weaken those
contracts or change a wire layout.

Move one cohesive responsibility, update callers and project entries together,
and test observable results and error paths. Avoid scattering a large file
across `.inc` fragments: that changes file size without establishing a module
boundary. Protocol changes, presentation changes, and behavior changes should
be independently reviewable where possible.

Useful native regression targets include:

| Changed behavior | Existing validation |
| --- | --- |
| Evidence, parsing, pure Light policies | `tests/native/ark_light/KswordARKLightTests.vcxproj` and its executable |
| NTFS run-list decoding | `tests/native/fs_decode/KswordFsDecodeTests.vcxproj` and its executable |
| Driver-client response policy and handle ownership | `tests/native/ark_client/KswordArkClientTests.vcxproj` and its executable |
| DWM ordering/loading | Projects in `tests/native/dwm_z_order/` |
| HVM control arithmetic | `tools/hvm_unit_tests/hvm_unit_tests.c` (compiled and run in CI) |
| Driver functionality or kernel reads | [Driver test guide](../drivers/ark/tests/README.md) |

Build with the repository's supported MSVC/Qt/WDK setup. See
[Building](../README.md#building) and
[build recovery notes](../.claude/memory/ksword-build-recovery.md).
Report compilation, static validation, signing, loading, and VM acceptance as
separate results.

## Maintaining CI selection

Both `ci.yml` and `driver-ci.yml` call `tools/ci_changes.py`; directory mappings
and history fallback behavior are maintained there. The selector treats manual
runs, failed/cancelled/incomplete history, API errors, and unavailable Git bases
as a request to build all projects. A push can use a smaller diff only when the
previous successful workflow built that push's exact `before` commit. PRs use
the merge base with the target branch.

Renames include both paths, and Git filenames are read using NUL separators.
Root MSBuild settings trigger all consumers, including the driver. Regression
tests cover these cases, the shipped `TaskmgrHijack.ps1` script, vendored driver
inputs, and application dependencies.

Source integrity runs even for changes that do not select a native build.
Do not replace failing audits with report-only steps or bless all current
findings with a baseline. Fix drift or document an exact, justified exception.
