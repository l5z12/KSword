# Ksword UI 表格—详情页面分类

## 审查范围

本报告只审查 `artifacts/bin/Ksword5.1` 用户态 Qt UI。判定依据是源码中的控件创建、表格/树选择信号和详情文本更新链路，不涉及业务逻辑、驱动行为或运行时截图。

页面只有同时满足以下条件，才列入“严格命中”：

1. 下方控件是项目自有 `CodeEditorWidget`。
2. 上方存在表格或树，并连接当前行/当前项选择信号。
3. 详情文本由当前选中行/当前选中项生成。
4. 页面主体是单一的“表格/树 → 下方详情”结构。

`QTextEdit`、`QPlainTextEdit`、日志框、整次快照、第二张表、多个 Tab、左右多模块分栏和只用于启用按钮/填充表单的选中状态，均不满足严格命中。

## 严格命中（23 个页面）

下表中的“页面构建”指向表格/树与 `CodeEditorWidget` 的创建位置，“选中联动”指向当前项信号或详情更新位置。

| 模块 | 页面 | 页面构建 | 选中联动 |
| --- | --- | --- | --- |
| DriverDock | 驱动完整性 | [`DriverDock.Integrity.cpp:457`](../../apps/desktop/driver_dock/DriverDock.Integrity.cpp#L457) | [`DriverDock.Ui.cpp:1103`](../../apps/desktop/driver_dock/DriverDock.Ui.cpp#L1103) |
| HardwareDock | 设备管理器 | [`HardwareDeviceManagerPage.cpp:977`](../../apps/desktop/hardware_dock/HardwareDeviceManagerPage.cpp#L977) | [`HardwareDeviceManagerPage.cpp:1062`](../../apps/desktop/hardware_dock/HardwareDeviceManagerPage.cpp#L1062) |
| HardwareDock | R0 证据 | [`HardwareR0EvidencePage.cpp:1045`](../../apps/desktop/hardware_dock/HardwareR0EvidencePage.cpp#L1045) | [`HardwareR0EvidencePage.cpp:1128`](../../apps/desktop/hardware_dock/HardwareR0EvidencePage.cpp#L1128) |
| MemoryDock | 内核可执行页 | [`MemoryDock.KernelExecutableMemory.cpp:463`](../../apps/desktop/memory_dock/MemoryDock.KernelExecutableMemory.cpp#L463) | [`MemoryDock.UiWireAndStatus.cpp:1386`](../../apps/desktop/memory_dock/MemoryDock.UiWireAndStatus.cpp#L1386) |
| MemoryDock | 内核内存证据 | [`MemoryDock.KernelMemoryEvidence.cpp:503`](../../apps/desktop/memory_dock/MemoryDock.KernelMemoryEvidence.cpp#L503) | [`MemoryDock.UiWireAndStatus.cpp:1420`](../../apps/desktop/memory_dock/MemoryDock.UiWireAndStatus.cpp#L1420) |
| MemoryDock | 进程内存证据 | [`MemoryDock.ProcessMemoryEvidence.cpp:455`](../../apps/desktop/memory_dock/MemoryDock.ProcessMemoryEvidence.cpp#L455) | [`MemoryDock.UiWireAndStatus.cpp:1497`](../../apps/desktop/memory_dock/MemoryDock.UiWireAndStatus.cpp#L1497) |
| MemoryDock | PTE / VA 翻译 | [`MemoryDock.ProcessPteTranslate.cpp:308`](../../apps/desktop/memory_dock/MemoryDock.ProcessPteTranslate.cpp#L308) | [`MemoryDock.UiWireAndStatus.cpp:1451`](../../apps/desktop/memory_dock/MemoryDock.UiWireAndStatus.cpp#L1451) |
| KernelDock | I/O Timer | [`KernelIoTimerTab.cpp:169`](../../apps/desktop/kernel_dock/KernelIoTimerTab.cpp#L169) | [`KernelIoTimerTab.cpp:203`](../../apps/desktop/kernel_dock/KernelIoTimerTab.cpp#L203) |
| KernelDock | Named Pipe | [`KernelNamedPipeTab.cpp:163`](../../apps/desktop/kernel_dock/KernelNamedPipeTab.cpp#L163) | [`KernelNamedPipeTab.cpp:223`](../../apps/desktop/kernel_dock/KernelNamedPipeTab.cpp#L223) |
| KernelDock | 对象目录深度枚举 | [`KernelObjectDirectoryDeepTab.cpp:277`](../../apps/desktop/kernel_dock/KernelObjectDirectoryDeepTab.cpp#L277) | [`KernelObjectDirectoryDeepTab.cpp:312`](../../apps/desktop/kernel_dock/KernelObjectDirectoryDeepTab.cpp#L312) |
| KernelDock | 对象类型矩阵 | [`KernelObjectTypeMatrixTab.cpp:192`](../../apps/desktop/kernel_dock/KernelObjectTypeMatrixTab.cpp#L192) | [`KernelObjectTypeMatrixTab.cpp:233`](../../apps/desktop/kernel_dock/KernelObjectTypeMatrixTab.cpp#L233) |
| KernelDock | 线程审计 | [`KernelThreadAuditTab.cpp:181`](../../apps/desktop/kernel_dock/KernelThreadAuditTab.cpp#L181) | [`KernelThreadAuditTab.cpp:203`](../../apps/desktop/kernel_dock/KernelThreadAuditTab.cpp#L203) |
| KernelDock | CID Cross-View | [`KernelDockCidTab.cpp:205`](../../apps/desktop/kernel_dock/KernelDockCidTab.cpp#L205) | [`KernelDockCidTab.cpp:259`](../../apps/desktop/kernel_dock/KernelDockCidTab.cpp#L259) |
| KernelDock | SSDT | [`KernelDock.Ssdt.cpp:190`](../../apps/desktop/kernel_dock/KernelDock.Ssdt.cpp#L190) | [`KernelDock.Ssdt.cpp:238`](../../apps/desktop/kernel_dock/KernelDock.Ssdt.cpp#L238) |
| KernelDock | Atom 表 | [`KernelDock.cpp:1009`](../../apps/desktop/kernel_dock/KernelDock.cpp#L1009) | [`KernelDock.cpp:1051`](../../apps/desktop/kernel_dock/KernelDock.cpp#L1051) |
| KernelDock | NtQuery 历史结果 | [`KernelDock.cpp:1086`](../../apps/desktop/kernel_dock/KernelDock.cpp#L1086) | [`KernelDock.cpp:1121`](../../apps/desktop/kernel_dock/KernelDock.cpp#L1121) |
| KernelDock | ShadowSSDT | [`KernelDock.KernelHooks.cpp:1773`](../../apps/desktop/kernel_dock/KernelDock.KernelHooks.cpp#L1773) | [`KernelDock.KernelHooks.cpp:1802`](../../apps/desktop/kernel_dock/KernelDock.KernelHooks.cpp#L1802) |
| KernelDock | Inline Hook | [`KernelDock.KernelHooks.cpp:1861`](../../apps/desktop/kernel_dock/KernelDock.KernelHooks.cpp#L1861) | [`KernelDock.KernelHooks.cpp:1897`](../../apps/desktop/kernel_dock/KernelDock.KernelHooks.cpp#L1897) |
| KernelDock | IAT/EAT | [`KernelDock.KernelHooks.cpp:1952`](../../apps/desktop/kernel_dock/KernelDock.KernelHooks.cpp#L1952) | [`KernelDock.KernelHooks.cpp:1984`](../../apps/desktop/kernel_dock/KernelDock.KernelHooks.cpp#L1984) |
| KernelDock | Timer/DPC | [`KernelDock.KernelHooks.cpp:2024`](../../apps/desktop/kernel_dock/KernelDock.KernelHooks.cpp#L2024) | [`KernelDock.KernelHooks.cpp:2045`](../../apps/desktop/kernel_dock/KernelDock.KernelHooks.cpp#L2045) |
| MonitorDock | ARK 风险中心 | [`MonitorDock.ArkRiskCenter.cpp:780`](../../apps/desktop/monitor_dock/MonitorDock.ArkRiskCenter.cpp#L780) | [`MonitorDock.ArkRiskCenter.cpp:813`](../../apps/desktop/monitor_dock/MonitorDock.ArkRiskCenter.cpp#L813) |
| NetworkDock | 防火墙规则管理 | [`NetworkFirewallPage.cpp:2663`](../../apps/desktop/network_dock/NetworkFirewallPage.cpp#L2663) | [`NetworkFirewallPage.cpp:2771`](../../apps/desktop/network_dock/NetworkFirewallPage.cpp#L2771) |
| ProcessDock | 进程详情线程审查 | [`ProcessDetailWindow.BaseAndUi.cpp:3222`](../../apps/desktop/process_dock/ProcessDetailWindow.BaseAndUi.cpp#L3222) | [`ProcessDetailWindow.BaseAndUi.cpp:3267`](../../apps/desktop/process_dock/ProcessDetailWindow.BaseAndUi.cpp#L3267) |

### 严格命中的共同证据

- 每个页面都在表格/树下创建 `CodeEditorWidget`，并设置为只读详情展示。
- 选择信号读取 `currentRow()`、`currentItem()` 或缓存索引，随后调用 `setText`、`setLocalizedText` 或等价详情生成函数。
- 页面主体只有一个结果表/树和其对应详情区。页面工具栏中的刷新、过滤、导出或状态控件不改变该主体判定。

## 可疑对象（11 个多模块页面）

这些页面具备自有 `CodeEditorWidget` 和选中项详情联动，但同时包含多个表格、树、Tab 或左右分栏，无法按单一“表格/树 → 下方详情”主体严格命中，保留人工复核状态。

| 页面 | 参考位置 | 复核原因 |
| --- | --- | --- |
| DriverDock 驱动概览 | [`DriverDock.Ui.cpp:419`](../../apps/desktop/driver_dock/DriverDock.Ui.cpp#L419) | 概览页包含多个数据区，详情编辑器不构成唯一的下方详情主体。 |
| Kernel 对象命名空间 | [`KernelDock.cpp:902`](../../apps/desktop/kernel_dock/KernelDock.cpp#L902) | 对象树、属性表和详情编辑器并列。 |
| Kernel 驱动状态/能力矩阵 | [`KernelDock.DriverStatus.cpp:1284`](../../apps/desktop/kernel_dock/KernelDock.DriverStatus.cpp#L1284) | 状态表、能力矩阵等多个模块共同组成页面。 |
| DynData 总览/Profile | [`KernelDock.DynData.cpp:3300`](../../apps/desktop/kernel_dock/KernelDock.DynData.cpp#L3300) | 总览与 Profile 分区/Tab 同时存在。 |
| 回调枚举 | [`KernelDock.CallbackEnum.cpp:2144`](../../apps/desktop/kernel_dock/KernelDock.CallbackEnum.cpp#L2144) | 回调结果、动作/审计区域同时存在。 |
| IPC/ALPC | [`KernelDockIpcTab.cpp:361`](../../apps/desktop/kernel_dock/KernelDockIpcTab.cpp#L361) | IPC 多个子页和 ALPC 详情模块并列。 |
| 进程 Cross-View | [`ProcessDock.CrossView.cpp:447`](../../apps/desktop/process_dock/ProcessDock.CrossView.cpp#L447) | Cross-View 包含多个视图和状态/详情分区。 |
| 注册表优化 | [`RegistryOptimizationPage.cpp:1288`](../../apps/desktop/registry_dock/RegistryOptimizationPage.cpp#L1288) | 项目表、动作/审计模块并列。 |
| 服务详情 | [`ServiceDock.Ui.cpp:224`](../../apps/desktop/service_dock/ServiceDock.Ui.cpp#L224) | 服务属性、依赖和审计等多个 Tab/详情区。 |
| WindowDock GUI/Session | [`WindowDock.cpp:3261`](../../apps/desktop/window_dock/WindowDock.cpp#L3261) | GUI、Session、显示等多个摘要编辑器和视图。 |
| OtherDock 窗口树与预览 | [`OtherDock.cpp:3171`](../../apps/desktop/other_dock/OtherDock.cpp#L3171) | 窗口树旁有多个预览/摘要模块，非单一下方详情。 |

## 按新口径排除

- HTTPS 解析：[`NetworkDock.HttpsAnalyze.cpp:640`](../../apps/desktop/network_dock/NetworkDock.HttpsAnalyze.cpp#L640) 下方是 `QPlainTextEdit` 日志，内容不是当前表格行详情。
- Descriptor Table、HVM、VBS、SLAT/IOMMU：使用 `QTextEdit` 或展示整次快照。
- 文件安全描述符 ACE：虽然存在 `CodeEditorWidget`，但展示整体 Owner/Group/DACL/SACL，没有 ACE 当前行联动。
- Boot Editor：下方主要是编辑表单和 `QPlainTextEdit` 原始输出。
- Handle Object Type：下方是 `QTreeWidget`，不属于项目自有文本框组件。
- NetworkAudit、系统内存审计、应用控制、磁盘监控、下载任务：详情是整体说明、日志或第二张表。

## 结果

按本口径，目标页面为上述 23 个严格命中页面；11 个可疑对象只进入人工复核清单，其余页面不进入目标集合。Qt 平台插件启动错误与本次 UI 分类无关，未纳入审查结论。
