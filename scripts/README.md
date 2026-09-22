# Repository scripts

[简体中文](../docs/zh-CN/scripts.md) · [Documentation](../docs/README.md)

For ordinary contributions, start with `python tools/dev.py doctor` and
`python tools/dev.py test`. They discover dependencies without modifying the
machine. Python source checks and generators remain in `tools/`.

| Location | Purpose |
| --- | --- |
| `setup/Setup-QtPaths.ps1` | Optional persistent Qt/Visual Studio setup; can write user environment variables, local `Directory.Build.props`, and project settings. Review `-WhatIf` first. |
| `runtime/TaskmgrHijack.ps1` | Task Manager integration helper distributed beside the desktop executable. The desktop project copies it; changing its source path must preserve the deployed basename. |
| `legacy/Auto-Qmoc.ps1` | Historical MOC helper retained for reference. Normal builds use Qt MSBuild; this script is not part of the supported contributor build. |
| `Build-*.ps1`, `Invoke-*.ps1` | Component builds and acceptance workflows. Read each script's help and required environment before running it. Some invoke or change a live driver/system. |

From the repository root, preview optional Qt setup without persistent edits:

```powershell
./scripts/setup/Setup-QtPaths.ps1 -WhatIf -NoUserEnvironment -NoDirectoryBuildProps -SkipProjectFilePatch
```

Keep setup, shipped runtime helpers, and legacy scripts in their respective
directories. Resolve repository paths from the script location so invocation
from another working directory remains valid. Put generated logs in `artifacts/`.
