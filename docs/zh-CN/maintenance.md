# 维护 KSword

[English](../maintenance.md) · [贡献指南](contributing.md) · [构建指南](development.md)

KSword 是共享驱动协议、用户态客户端和分析代码的多个 Windows C/C++ 程序。
先找到行为所属边界，再构建其消费者。`tools/dev.py test` 运行不依赖 Qt/WDK 的入门测试。

## 代码归属

| 职责 | 位置 | 边界 |
| --- | --- | --- |
| wire 结构、版本、IOCTL 编号 | `shared/driver/` | R0/R3 唯一定义 |
| 设备访问和响应校验 | `shared/ark_client/` | UI 调用客户端，不直接发 KswordARK IOCTL |
| 路由与公共校验 | `drivers/ark/src/dispatch/` | handler 在 `ioctl_registry.c` 注册，dispatcher 不放业务 switch |
| 内核功能 | `drivers/ark/src/features/<module>/` | 模块拥有 handler 与能力要求 |
| 可复用证据/判定逻辑 | `shared/evidence/` | 采集与窗口状态和分析逻辑分开 |
| 完整桌面 UI | `apps/desktop/*_dock/`、`ui/` | 展示、意图、异步生命周期和导航 |
| 轻量 UI/编排 | `apps/ark_light/features/`、`core/`、`ui/` | 保持 Win32 版独立于 Qt |
| CLI | `apps/cli/` | 参数、内置帮助、中英文 CLI 文档同步 |
| 启动/发行 | `apps/launcher/`、`apps/setup/` | 在边界验证支持清单和嵌入载荷 |
| 原生测试 | `tests/native/` | 可独立构建的回归工程 |
| 共用构建配置 | `build/msbuild/` | 根 `Directory.Build.targets` 仍由 MSBuild 自动发现 |
| 源码检查/CI 范围 | `tools/check.py`、`tools/ci_changes.py` | 本机和 CI 共用执行规则 |

修改功能前读[共享记忆索引](../../.claude/memory/MEMORY.md)相关主题。
UI 修改还需读[主题架构](../../.claude/memory/ksword-ui-architecture.md)。

## MainWindow

`MainWindow.h` 是 Qt API 和状态所有者，尽量前置声明 Dock；实现文件只包含所需头。
`MainWindow.cpp` 保留构造、退出和启动进度，其余行为进入对应单元：

| 职责 | 实现（主程序目录内） |
| --- | --- |
| Dock 创建、懒加载、布局 | `MainWindow.Docking.cpp`、`DockTabs` |
| 页面/转储导航 | `MainWindow.Navigation.cpp` |
| 主题/QSS | `MainWindow.Appearance.cpp`、`StyleSheet` |
| 背景图和代数检查 | `MainWindow.Background.cpp`、`BackgroundSupport.h` |
| 原生事件、背景、Z-order | `MainWindow.NativeFrame.cpp` |
| 标题栏、菜单、命令 | `MainWindow.TitleBar.cpp`、`Menus`、`Commands` |
| Qt 事件过滤/委托 | `MainWindow.WidgetBehavior.cpp` |
| 权限展示/令牌操作 | `MainWindow.Privileges.cpp`、`Win32Privileges` |
| 驱动服务 ui/后台 SCM | `MainWindow.DriverService.cpp`、`DriverServiceBackend` |
| Bugcheck/KVM | `MainWindow.Bugcheck.cpp`、`Kvm` |

`MainWindow.*Support.h` 是 `ksword::ui::main_window` 下的私有跨单元合同。
其它功能应使用公开 API 或自己的服务接口。服务操作互锁只有后台单元一份定义；
异步修改必须保留通知关闭屏障、worker 完成保护和背景图代数检查。

## File、Process、Monitor 模块

Dock 类继续拥有 Qt 状态和异步生命周期；入口 cpp 放生命周期，命名实现文件分担操作。
私有 `*.Support.h` 分别在 `ksword::ui::file_dock`、`process_dock`、`monitor_dock`，
不应被无关功能引用。

| 模块 | 对应实现 |
| --- | --- |
| 文件浏览 | `FileDock.Navigation`、`Models`、`Recovery`、`ContextMenu`、`Transfer`、`Deletion`、`Unlock`、`Security`、`Oplocks` |
| 文件属性 | `FileDetailDialog.h` 声明；`FileDetailDialog.*.cpp` 分离生命周期、懒页面、元数据、事务、安全、哈希、存储 |
| 文件后台帮助函数 | `FileDock.*Support.cpp` 分离路径、恢复、完整性、删除、传输、访问 |
| 进程采集/展示 | `ProcessDock.Acquisition`、`Refresh`、`TableModel`、`TableData`、`DisplayOrder`、`ActivityHistory` |
| 进程动作 | `ProcessDock.ActionDispatch`、`DriverControl`、`HvmActions`、`Termination`、`ProcessControl`、`CreateProcess` |
| 活动图控件 | `ProcessActivityChartWidget.*`、`ProcessActivityTimelineSlider.*` |
| WMI | `MonitorDock.WmiDiscovery`、`WmiCapture`、`WmiExport`、`WmiUi` |
| ETW | `MonitorDock.EtwSession`、`EtwCapture`、`EtwDelivery`、`EtwArchive`、`EtwDecoding`、`EtwExport` |
| ETW 解码帮助函数 | `MonitorDock.Schema`、`PropertyDecoding`、`EventMeaning`、`EventFields`、`ArchiveCodec` |
| ETW 筛选 UI | `MonitorDock.FilterUi`、`FilterCompile`、`FilterApply`、`FilterStorage`、`FilterImportExport` |
| ETW 配置格式 | `EtwFilterConfig.h/.cpp`，只依赖 QtCore 的模型、字段、解析和序列化 |

表中省略扩展名的实现均为 `.cpp`。报告展示偏好与 ETW schema cache 各只有一个定义。
Oplock 记录与句柄清理在 `FileDock.Oplocks.cpp`；活动字段复制模板在私有头中，供多个单元实例化。

ETW 解析显式接收前/后置 provider/action 选项，完整验证候选模型后才提交输出。
导入/导出共用一个 serializer；UI 只捕获值、处理对话框、文件持久化和采集状态。
`KswordMonitorTests` 覆盖版本、失败不提交、阶段选项和所有字段/模式往返，不开窗口或采集：

```powershell
uv run --python 3.12 python tools/dev.py test --target monitor-tests
```

## CLI

`KswordCLI.cpp` 保留控制台和异常边界；各 `Cli<领域>.cpp` 拥有命令处理。
`CliArguments` 拥有数值、命名参数、PID 列表和十六进制解析；`CliIo` 将传输/句柄交给
ArkDriverClient；`CliOutput` 统一输出。`CliSupport.h` 是内部合同，不是第二套驱动 API。

`CliHelp.cpp` 的 family registry 同时供帮助与分发使用。新增族在此注册 handler。
命令/参数变化同步 help、[英文 CLI 参考](../cli.md)和[中文 CLI 指南](cli.md)。
英文命令参考由 `tools/generate_cli_docs.py` 生成。
`KswordCliTests` 覆盖解析边界；`tools/test_cli_help.py` 执行所有帮助和别名，
可用 `--baseline` 对已有输出逐字节比较。

```powershell
uv run --python 3.12 python tools/dev.py test --target cli-tests
uv run --python 3.12 python tools/dev.py test --target cli
```

## 驱动客户端

`ArkDriverClient.h` 保留公开 API，`ArkDriverClient.cpp` 负责传输、句柄与通知同步。
进程、线程、枚举、安全、注入和固件有独立实现；审计按 network/storage/security/
Win32k/device/platform/I8042/object/DynData 分离。

`ArkDriverTypes.h` 是兼容聚合入口；仅需某类结果时包含领域类型头，例如
`ArkDriverProcessTypes.h` 或 `ArkDriverIoTypes.h`。它们是 R3 模型，wire 定义仍只在 shared/driver。

- `ArkDriverResponseSupport.h`：有界固定字符串与错误分类。缺少 IOCTL、旧版 invalid-parameter
  兼容和版本不匹配的策略不同，不能合并。
- `ArkDriverAuditSupport.h`：固定头和变长行解析。按实际字节数约束计数/分配，要求完整 stride。
- `ArkDriverNetworkSupport.h`：元数据与完整性；inventory 允许文档化 partial，endpoint 丢弃失败行。

`KswordArkClientTests` 覆盖保护页字符串边界、畸形响应、过大计数、partial 与真实句柄所有权，
不依赖 Qt、提权或驱动。CI 运行测试；移动实现或公开头仍需构建其它消费者。

## 源码检查与文件迁移

```powershell
uv run --python 3.12 python tools/check.py
uv run --python 3.12 python tools/check.py --list
uv run --python 3.12 python tools/check.py --check projects --check tool-tests
```

检查只需 Git/Python 3.12+ 标准库，逐项执行，即使前项失败也保留其它结果；任一失败最终非零。
范围包含 JSON、project/filters、C/C++/Python/XML 英文注释、工具回归、语言包、内核知识、HVM catalog/EPT、主题、
IOCTL 访问策略及维护文档。IOCTL 报告保存在 `artifacts/ioctl-audit.md`，失败也保留。
这些检查不编译 C/C++，也不证明驱动签名/加载或 VM 验收。

1. 选定所属模块，把可独立测试的判定从 UI 回调中提取。
2. 更新所有消费者的 `.vcxproj` / `.filters`，类型必须对应；QtMoc 不能在 filters 写成 ClInclude。
3. 新文件加入 Git，移动/删除登记旧路径删除，再运行 projects 检查。
4. 新增目录依赖更新 `tools/ci_changes.py` 的 `PROJECT_INPUTS` 和回归测试。
5. 构建、运行相关测试，最后执行全部源码检查。

审计覆盖所有已跟踪 vcxproj，包括不在主解决方案中的工程；检查重复、遗漏、大小写、类型、
跟踪状态和已删源文件。动态 MSBuild 项留给 MSBuild 求值；唯一 literal generated 例外是
安装器 GenerateKswordSetupPayload 生成的两个资源文件。审计不能判定一个从未注册的源文件
应该属于哪个工程，也不证明某翻译单元可编译。

## 重构与 CI 范围

按有输入/结果的完整职责拆分，而不是拆成 `.inc` 碎片。先确认句柄、缓冲区、取消和回调
生命周期的所有者；保留 PID 对应创建时间、异步 generation、有界解析和 capability 检查。
`shared/evidence/MemoryTamperCrossView.cpp` 同时被桌面与 Light 测试使用，是可复用分析的例子。

回归入口包括 `tests/native/` 下的 evidence/client/CLI/fs/monitor 工程、
`tests/native/dwm_z_order/`、`tools/hvm_unit_tests/`，以及[驱动测试指南](../../drivers/ark/tests/README.md)。
编译、静态验证、签名、加载、VM 验收要分别报告。

`ci.yml` 和 `driver-ci.yml` 共用 `tools/ci_changes.py`。手动运行、失败/取消/未完成历史、
API 错误或缺少 Git 基线均全量构建；push 只有上一成功工作流确实构建该 push 的 before
提交才缩小范围，PR 使用 merge base。重命名包含新旧路径，Git 路径用 NUL 分隔读取。
共用 MSBuild 设置触发所有消费者，包括驱动。Source integrity 不随 native 选择而跳过；
不能用只报告不失败或宽泛白名单掩盖漂移。
