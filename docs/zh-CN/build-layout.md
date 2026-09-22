# 构建配置目录

[English](../../build/README.md) · [构建指南](development.md)

`build/msbuild/Ksword.Output.props` 定义统一 Release 输出目录
`artifacts/bin/x64/Release/`，相对 props 自身位置解析，所有消费项目都指向同一个目录。

`Directory.Build.targets` 保留在仓库根目录，因为 MSBuild 会沿父目录自动寻找该名称。
本地、已忽略的 `Directory.Build.props` 可存机器专属 Qt 路径，不能提交该文件，也不能
把个人绝对路径写进共享默认配置。

应用与驱动组件保留各自根目录和项目文件。原生回归项目放在 `tests/native/`；移动时同步
项目与 filters 中的源码路径、构建 runner、CI 和验收脚本。依赖下载放 `.deps/`，
构建/测试报告放 `artifacts/`，发行暂存与归档放 `dist/`，这些目录均已忽略。

项目成员变化后运行 `python tools/check.py --check projects`，再构建受影响消费者。
源码审计检查源码和 filters 条目，真正的 imports 及构建属性仍由 MSBuild 求值验证。
