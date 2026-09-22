# 仓库脚本

[English](../../scripts/README.md) · [文档目录](index.md)

一般贡献先运行 `python tools/dev.py doctor` 和 `python tools/dev.py test`，
它们只发现依赖，不修改机器配置。Python 检查与生成器位于 `tools/`。

| 位置 | 用途 |
| --- | --- |
| `scripts/setup/Setup-QtPaths.ps1` | 可选的 Qt/Visual Studio 持久化配置；可能写用户环境变量、根目录本地 `Directory.Build.props` 和项目设置。先用 `-WhatIf` 检查。 |
| `scripts/runtime/TaskmgrHijack.ps1` | 随桌面程序发布的任务管理器集成脚本，由主项目复制；移动源码时保留发布文件名。 |
| `scripts/legacy/Auto-Qmoc.ps1` | 保留供参考的历史 MOC 脚本；常规构建使用 Qt MSBuild，不依赖此脚本。 |
| `scripts/Build-*.ps1`、`scripts/Invoke-*.ps1` | 组件构建与验收流程；先读各脚本帮助与环境要求，部分会操作真实驱动或系统。 |

从根目录预览可选 Qt 设置，不执行持久化改动：

```powershell
./scripts/setup/Setup-QtPaths.ps1 -WhatIf -NoUserEnvironment -NoDirectoryBuildProps -SkipProjectFilePatch
```

环境设置、随程序发布的脚本、历史脚本分别放入对应目录。通过脚本位置解析仓库路径，
避免依赖调用者工作目录。生成日志放入 `artifacts/`。
