# Tests

[简体中文](../docs/zh-CN/testing.md) · [Build guide](../docs/development.md)

Run source checks with `uv run --python 3.12 python tools/check.py`. On Windows,
run the three starter native suites with `uv run --python 3.12 python tools/dev.py
test`. They require MSVC and a Windows SDK, but no Qt, WDK, administrator privileges,
or loaded driver.

| Project under `native/` | Coverage | Runner target |
| --- | --- | --- |
| `KswordArkClientTests` | Driver response bounds, partial results, handle ownership | `client-tests` |
| `KswordCliTests` | Numeric and hexadecimal argument parsing | `cli-tests` |
| `KswordFsDecodeTests` | Malformed NTFS run lists | `fs-tests` |
| `KswordMonitorTests` | ETW configuration validation and round trips; QtCore required | `monitor-tests` |
| `KswordARKLightTests` | Offline evidence, cross-view, snapshots, DDMA plans, and other analysis helpers | Build its `.vcxproj` with MSBuild, then run the output |

Use `python tools/dev.py test --target <target>` for individual runner targets.
The runner builds before executing tests and stops on failures. ARKLight's
offline test project does not embed or load the driver:

```powershell
# Run from a Visual Studio developer shell with MSBuild available.
MSBuild tests/native/ark_light/KswordARKLightTests.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 /m:1
if ($LASTEXITCODE -ne 0) { throw 'Test build failed.' }
& ./tests/native/ark_light/x64/Release/KswordARKLightTests.exe
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
```

Python tool tests stay in `tools/tests/` near the tools they exercise. Component
tests such as `tests/native/dwm_z_order/` stay with that component's standalone build.
`python tools/dev.py test --target cli` builds the CLI and exercises every declared
help route; it does not execute the corresponding system operations.

Add behavior tests at the narrowest boundary that reproduces a bug. Register new
native sources in both project and filters files. Test outputs belong under each
project's ignored `x64/<configuration>/`. Live driver, VM, and signing acceptance
remain separate; successful offline tests do not establish hardware support.
