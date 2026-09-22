# 参与 KSword

[English](../../CONTRIBUTING.md) · [构建指南](development.md) · [模块地图](maintenance.md)

欢迎提交可复现的问题、文档修正、翻译、回归测试和代码。参与 CLI、开发工具或离线
分析测试不需要内核测试机。Issue 和 PR 都可以使用中文或英文。

## 第一个 PR

1. 选择一个具体问题，搜索已有 Issue 和 PR。小修复、文档和测试可以直接提交 PR；
   新子系统或协议变更建议先在 Issue 中讨论方案，避免投入后才发现方向不一致。
2. Fork 仓库，克隆自己的分支仓库，再创建描述问题的工作分支：

   ```powershell
   git clone https://github.com/YOUR-USERNAME/KSword.git
   cd KSword
   git switch -c fix/describe-the-problem
   ```

3. 先运行与 CI 共用的源码检查，只需要 Git 和 Python 3.12+：

   ```powershell
   uv run --python 3.12 python tools/check.py
   ```

   已安装 Python 3.12+ 时也可直接执行 `python tools/check.py`，不需要额外 Python 包。
4. 从[模块地图](maintenance.md)找到负责该行为的代码。围绕一个问题修改，为行为变更
   增加有意义的回归测试，优先复用离线测试。
5. 新文件先加入 Git，同时更新每个消费者的 `.vcxproj` 和 `.vcxproj.filters`。
   源码检查读取已跟踪文件的工作区内容，未跟踪文件还不在审计范围内。
6. 向仓库默认分支提交 PR，说明原问题、修改后的行为、测试命令与结果，以及没有条件
   验证的部分。日志应包含工具集和第一条错误，不要只有 MSBuild 最后的失败摘要。

## 不依赖 Qt / WDK 的起点

Windows 上安装 Visual Studio 2022 Community 或 Build Tools，选择“使用 C++ 的桌面开发”、
MSVC v143 x64/x86 工具集和 Windows SDK，然后运行：

```powershell
uv run --python 3.12 python tools/dev.py doctor
uv run --python 3.12 python tools/dev.py test
```

默认构建并执行驱动客户端响应解析、CLI 参数解析、文件系统解码三组测试，使用
Release/x64；不需要 Qt、WDK、管理员权限、签名证书或已加载驱动。

| 想修改的内容 | 入口 | 验证命令（可加 `uv run --python 3.12` 前缀） |
| --- | --- | --- |
| 开发工具 | `tools/`、`tools/tests/` | `python tools/check.py --check tool-tests --check projects` |
| CLI 参数 | `apps/cli/CliArguments.cpp` | `python tools/dev.py test --target cli-tests` |
| CLI 命令与帮助 | `apps/cli/Cli*.cpp`、`CliHelp.cpp` | `python tools/dev.py test --target cli`，再做命令相关验证 |
| 文件系统异常输入 | `file_dock/NtfsRunListDecode.cpp` | `python tools/dev.py test --target fs-tests` |
| 驱动响应边界 | `ArkDriverClient/*Support.h` | `python tools/dev.py test --target client-tests` |
| ETW 配置格式 | `monitor_dock/EtwFilterConfig.*` | `python tools/dev.py test --target monitor-tests`，需要 QtCore |
| 翻译/UI 文案 | `languages/` 与相应 UI 模块 | `python tools/check.py --check i18n`，UI 修改还需主程序构建 |

表内 `file_dock/`、`ArkDriverClient/`、`monitor_dock/`、`languages/` 均位于
`apps/desktop/`。CLI 帮助测试只验证帮助路由，不代表驱动操作已实机验收。

`dev.py` 优先使用显式 `--msbuild` / `MSBUILD_PATH`，再查 PATH 和 `vswhere`。
`doctor` 负责发现依赖，实际工具集/SDK 由 MSBuild 在构建时验证。可用 `--dry-run`
查看将要执行的命令；脚本不会安装软件、改用户环境、改项目文件、签名或加载驱动。
本机只有已安装的 v145 时可显式传 `--toolset v145`，但这不替代 CI 的 v143 验证。

## Qt 与公开源码的边界

主程序使用 Qt 6.9.3 MSVC 2022 64-bit，需 Core、GUI、Network、Widgets、SVG 和 Qt MSBuild 集成；
不能换成 MinGW kit。完整安装/发现步骤见[构建指南](development.md#qt-desktop-setup)。
设置 `KSWORD_QT_DIR`、`KSWORD_QT_MSBUILD` 后：

```powershell
uv run --python 3.12 python tools/dev.py doctor --target desktop
uv run --python 3.12 python tools/dev.py test --target monitor-tests
uv run --python 3.12 python tools/dev.py build --target desktop
```

开发命令会把当前 Python 解释器传给 MSBuild，因此 uv 环境可直接使用；CI 仍可用
普通 Python。Qt 的 DLL 搜索路径只添加到子进程环境。主程序不会自动启动。

公开 checkout 没有维护者审核过的发布用 DynData 语料和部分注册表优化资源；这些
缺失会产生构建提示或功能不可用，不妨碍上述入门测试、CLI 和主程序编译。
不要伪造支持矩阵。Launcher 需要生成的矩阵；ARKLight 会嵌入 `KswordARK.sys`，
因此完整构建需要驱动产物。编译成功、链接成功、签名和实机加载必须分开报告。

## 便于审阅的修改

遵循[代码风格](coding-style.md)：类型使用 PascalCase，函数和变量使用 camelCase，
常量使用 kPascalCase。脚本帮助、诊断、提示和进度也使用英文；保留必须精确匹配的
本地化输入模式和 Unicode 测试样例。

代码注释使用英文，便于社区贡献者理解实现。保留技术标识符、字面量示例与第三方声明。
非英文字面量示例放在行内反引号中，其说明使用英文。
UI 字符串和英文/中文文档仍保持双语。
`python tools/check.py --check comments` 检查第一方 C/C++、Python、XML 注释与
Python 文档字符串。其他语言的注释在 PR 中人工审阅；该检查不判断技术含义是否正确，
也不会自动翻译内容。

- 一个 PR 聚焦一个问题，避免混入无关格式化、生成的二进制、个人路径和发布资源。
- 重构应说明职责边界与保留的行为；不要把大规模移动和无关功能修改混在一起。
- 新贡献者可以在自己的 PR 中更新项目和 filters，不需要为了构建或准备这些修改
  先找某个“owner”批准。发现并行 PR 涉及同一模块时在 Issue/PR 中协调。
- 协议只放 `shared/driver/`；驱动 handler 通过 `ioctl_registry.c` 注册；用户态
  KswordARK 访问只经过 `ArkDriverClient`，Dock UI 不直接调用其 `DeviceIoControl`。
- 私有字段来自验证过的 DynData/runtime capability；不得硬编码新偏移。
  新 IOCTL 正确填写 `RequiredCapability`，无依赖时才用 `KSWORD_ARK_IOCTL_CAPABILITY_NONE`。
  保留字段来源展示、身份复核、边界校验、异步生命周期和系统修改确认。
- System Informer 只作为 vendored DynData 数据源，不搬入 KPH 对象/通信/session token 系统。
  PPL 操作保留 `KSW_CAP_PROCESS_PROTECTION_PATCH` 门禁和现有确认信息。
- CLI 命令、别名或参数变更同步 `CliHelp.cpp`，通过 `tools/generate_cli_docs.py`
  重新生成 `docs/cli.md`，并更新 `docs/zh-CN/cli.md`。
- 主要公开指南以英文为主，提供中文副本，并在同一 PR 同步。两种语言互链，新增配对登记
  `docs/catalog.json`，目录与原始语言研究记录见[文档目录](index.md)。
  `python tools/check.py` 同时验证文档配对、本地链接及 CLI 文档时效。
- 用户可见文案同时定点更新 `zh-CN.json` 和 `en-US.json`；禁止整包 JSON 重写。
  修改 UI 主题或异步逻辑前查看[共享项目记忆](../../.claude/memory/MEMORY.md)中的相关主题。

## 许可与社区

项目按 [LICENSE](../../LICENSE) 发布，当前为 KSword Community Source License 1.6。
提交代码即表示你有权提交，并同意该贡献随项目按对应许可证约束处理。
第三方代码保留原许可与署名。本指南不更改项目许可证。

讨论遵守[社区公约](../../COMMUNITY_COVENANT.md)；它是社区约定，不是额外的软件许可限制。
