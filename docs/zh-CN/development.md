# 构建贡献代码

[English](../development.md) · [贡献指南](contributing.md) · [模块地图](maintenance.md)

先构建一个项目或离线测试，不必先构建整个解决方案。CLI 和主程序编译不需要
维护者的私有发布语料库，也不需要加载内核驱动。

## 选择最小构建

| 工作 | 依赖 | 仓库根目录命令 |
| --- | --- | --- |
| 源码检查 | Git、Python 3.12+ | `python tools/check.py` |
| 客户端、CLI 参数、文件系统测试 | Windows、MSVC v143、Windows SDK | `python tools/dev.py test` |
| CLI 及全部帮助路由 | 同上 | `python tools/dev.py test --target cli` |
| ETW 配置测试 | 上述依赖 + Qt 6.9.3 MSVC x64 的 QtCore | `python tools/dev.py test --target monitor-tests` |
| 主程序 | 上述原生依赖 + Qt Core/GUI/Network/Widgets/SVG、Qt MSBuild | `python tools/dev.py build --target desktop` |
| 驱动及嵌入驱动的发行版 | WDK、相关驱动/签名输入 | 按组件的构建和验收说明执行，不属于入门命令 |

使用 uv 时将 `python` 换为 `uv run --python 3.12 python`。脚本复用当前解释器，
包括由 MSBuild 调用的 Python 步骤；CI 仍可直接使用 Python。
原生基线为 Visual Studio 2022 Community 或 Build Tools，“使用 C++ 的桌面开发”、
MSVC v143 x64/x86 工具集与 Windows SDK。默认 Release/x64，与 CI 一致。
入门测试不需要 Qt、WDK、管理员权限、签名证书或已加载驱动。

## 发现依赖并测试

```powershell
uv run --python 3.12 python tools/dev.py doctor
uv run --python 3.12 python tools/dev.py test
```

`doctor` 报告路径与缺失输入，实际工具集和 SDK 在 MSBuild 构建时验证。
发现顺序为 `MSBUILD_PATH`、PATH、Visual Studio 的 `vswhere`；并存安装可通过
`--msbuild '<MSBuild.exe 路径>'` 显式选择。脚本不安装软件、不改用户环境、
不改工程文件、不签名、不加载驱动。

`test` 先构建再执行，构建或测试失败立即停止，并要求产物存在且非空，避免失败后
运行旧测试程序。终端保留完整输出；`--dry-run` 只显示命令，不编译或执行测试。
用 `--target client-tests`、`cli-tests`、`fs-tests` 缩小范围，`--config Debug`
选择调试构建。已安装的其它工具集可显式用 `--toolset v145`，但不会改变工程/CI
的 v143 默认值，也不能用该结果替代 CI 基线验证。

## Qt 配置

安装 Qt 6.9.3 MSVC 2022 64-bit kit，包含 Core、GUI、Network、Widgets、SVG。
MinGW kit 无法链接这些 MSVC 工程。Qt MSBuild 可来自 Qt VS Tools，或
[CI](../../.github/workflows/ci.yml) 使用的 3.5.0 独立归档。
目标目录必须直接包含 `qt.props`、`qt.targets` 和 `qt_defaults.props`。

```powershell
New-Item -ItemType Directory -Force .deps | Out-Null
Invoke-WebRequest 'https://download.qt.io/official_releases/vsaddin/3.5.0/qt-vsaddin-msbuild-3.5.0.zip' -OutFile .deps/qt-msbuild.zip
Expand-Archive .deps/qt-msbuild.zip -DestinationPath .deps/QtVsTools -Force
$qtTargets = Get-ChildItem .deps/QtVsTools -Filter qt.targets -Recurse -File | Select-Object -First 1
if (!$qtTargets) { throw 'Qt MSBuild archive did not contain qt.targets.' }
$env:KSWORD_QT_MSBUILD = $qtTargets.Directory.FullName
$env:KSWORD_QT_DIR = 'C:/Qt/6.9.3/msvc2022_64' # 改为自己的安装目录。
uv run --python 3.12 python tools/dev.py doctor --target desktop
uv run --python 3.12 python tools/dev.py test --target monitor-tests
uv run --python 3.12 python tools/dev.py build --target desktop
```

Qt 也可通过 `--qt-dir`、`QT_ROOT_DIR`、`QTDIR` 或 `.deps/Qt/6.9.3/msvc2022_64`
发现。Qt MSBuild 也支持 `--qt-msbuild`、`QtMsBuild`、`.deps/QtVsTools/msbuild`
和 `.deps/QtVsTools`。显式参数优先；错误路径会报告，不会悄悄选择另一个安装。
Debug 测试需要对应 Debug Qt DLL 和导入库。

主程序/CLI 产物在 `artifacts/bin/x64/<configuration>/`，原生测试在各自
`tests/native/<project>/x64/<configuration>/`。Qt 的 bin 只加入子进程 PATH，
不会自动启动主程序。

## 公开 checkout 不含的输入

- 发布用 DynData 语料与注册表优化资源另行生成；缺失会产生构建提示或不可用功能。
  不要伪造已支持的内核矩阵。
- 主程序构建不依赖驱动二进制；没有兼容驱动/profile 时 R0 功能不可用。
- Launcher 消费生成的支持矩阵，CI 的空构建 fixture 不是有效的发布支持矩阵。
- ARKLight 把 `KswordARK.sys` 嵌入资源，完整链接/打包需要该产物；仅 C++ 编译成功
  不等于完整构建成功。安装器和发行打包也需要各自载荷。

上述入门测试、CLI、ETW 配置测试、主程序编译均不需要私有语料或发布签名私钥。
分享开发版时应说明其功能限制。

## 排障与 PR 证据

| 症状 | 处理 |
| --- | --- |
| 找不到 MSBuild | 安装 C++ 工作负载或传 `--msbuild`，不要假定特定 VS edition 路径 |
| MSB8020 | 安装 v143，或显式选择已安装的支持工具集 |
| 缺少 SDK | 在 VS Installer 中安装 Windows SDK，重跑同一目标 |
| 找不到 Qt 集成 | `--qt-msbuild` 指向实际含 `qt.targets` 的目录 |
| 测试缺少 Qt DLL | 检查 MSVC x64 kit 与 Debug/Release 配置，使用 dev.py 传入子进程路径 |
| 新文件未审计 | 加入 Git、消费者工程与 filters |
| 驱动后置验证/链接器内部错误 | 记录原命令与第一条错误，按[恢复说明](../../.claude/memory/ksword-build-recovery.md)处理，不用部分成功冒充整体通过 |

PR 前执行 `python tools/check.py` 和受影响行为的检查。报告命令、结果及无法进行的
运行时验收。本机 v145、源码检查或离线测试均不替代 CI v143 或驱动/VM 实机验收。
