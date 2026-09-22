---
name: ksword-ui-architecture
description: KSword 主程序 ui/主题架构要点（theme.h token 体系、全局样式块链路、WindowChrome、透明背景与毛玻璃、Dock 懒加载）
metadata:
  type: project
---

KSword 主程序位于 `artifacts/bin/Ksword5.1`（Qt 6.9.3 Widgets + Qt Advanced Docking System，MSVC vcxproj 构建）。

主窗口实现已按职责拆分：`MainWindow.cpp` 保留生命周期；主题入口在 `MainWindow.Appearance.cpp`，全局样式块与 marker 在 `MainWindow.StyleSheet.cpp`，背景图在 `MainWindow.Background.cpp` 与私有 `MainWindow.BackgroundSupport.h`，原生背景/窗口消息在 `MainWindow.NativeFrame.cpp`，Dock 惰性加载在 `MainWindow.Docking.cpp`。跨单元 helper 位于 `ksword::ui::main_window`；后续查找以函数名为准，本文旧 `MainWindow.cpp` 指代上述主窗口模块。完整职责地图见 `docs/maintenance.md`。

## UI 主题架构

- `Theme.h`（KswordTheme 命名空间）：design-token 中心。中性表面色（Window/Surface/SurfaceAlt/SurfaceMuted/Border）由 RGB 偏移从种子色派生；强调色 PrimaryBlueColor 可由用户自定义；提供 EnsureTextContrast 等 WCAG 对比度工具。
- `Theme.h` 的颜色访问器分两族，名字只差一个词，用错编译器和 Qt 都不报错：**动态** token（`surfaceHex()`、`textPrimaryHex()`、`PrimaryBlueHex` 等，共 14 个）返回 `palette(base)` 这类样式表角色，Qt 每次重绘重新求值，天然跟随主题；**静态** token（`*ColorHex()`）在调用瞬间固化成 `#RRGGBB`。
- `palette(...)` 是 QSS 专有扩展，**只有样式表能解析**。写进 QLabel/QTextEdit 富文本（走 QTextDocument 的 CSS 解析器）、`QColor` 字符串构造、`setForeground`/`QPen` 等绘制路径，或通过环境变量传给插件进程，都会被**静默丢弃**——声明整条失效、元素退回继承色，没有任何警告。这类误用已经犯过 5 次（HardwareDock 的 CPU 详情单元格、GlobalUiSearch 的结果副标题、NotificationCardManager、PluginHost）。上述场景一律改用 `*ColorHex()`。
- 构建期有门禁：`tools/theme_token_audit.py`（vcxproj Target `AuditKswordThemeTokens`，`BeforeTargets="ClCompile"`）。token 清单从 theme.h 现场解析，新增 token 自动纳入；语句定界会跳过字符串字面量，否则内联 CSS 里的 `padding-right:18px;` 会把语句在 HTML 标签前截断而漏检。脚本自带 `--self-test`，对照 `tools/theme_token_audit_fixture/` 双向校验（标记行必须报出、未标记行不得报出），构建时先自测再扫源码。跳过用 `/p:KswordSkipThemeTokenAudit=true`。
- 语义状态色（信息/成功/警告/错误/空闲）没有对应的 palette 角色，统一走 `ui/ThemeStatusRole`：控件用 `ks::ui::applyStatusRole()` 只记状态，颜色由全局样式块的 `QLabel[ksword_status_role="..."]` 规则下发。控件因此不持有自己的 styleSheet，也就不必再依赖 `ThemeColorRemap` 的存量字符串扫描（该扫描按旧值建映射，撞色时只能整组跳过）。属性名用下划线：驼峰会被 i18n 审计当成待翻译文本。
- `SurfaceMuted` 和 `TextDisabled` 没有动态版本，且不该硬造：QSS 的 `palette()` 选不到 disabled group，剩余空闲角色（light/bright-text/shadow）都会被 QStyle 用于原生控件的立体边框绘制。用到它们的页面必须自己具备重建入口（`changeEvent` 处理 `ApplicationPaletteChange`，或每次显示时重新生成样式）。
- 纯图标按钮的几何同样由 `Theme.h` 收口：紧凑工具栏使用 `applyCompactIconButtonMetrics`（28px 按钮 / 16px 图标），独立或强调动作使用 `applyStandardIconButtonMetrics`（32px / 18px）；页面不得继续新增 30/34/36px 的临时组合。
- `mainWindow::applyAppearanceSettings`：主题应用唯一入口，设置 QApplication palette + 调用 `applyGlobalApplicationStyleBlocks`（带 marker 的 QSS 块替换机制，marker 常量在 MainWindow.cpp 顶部匿名命名空间）。
- 全局 QSS 块顺序：BaseControl（`ui/GlobalUiBaseStyle.cpp`）→ Tooltip → ContextMenu → ControlContrast → ComboBox，依次追加到 app stylesheet，基线块在最前，局部样式可覆盖。
- `QComboBox` 弹出列表是独立 `Qt::Popup` 顶层窗口。禁止在 Popup 的 `Show`/`Resize` 事件内同步调用 `setMask`、`setStyleSheet` 或其它可能 repolish 子树的操作：Qt 此时可能仍在 `QWidgetPrivate::showChildren` 中遍历内部子对象，重入修改会留下悬空 child。Popup palette/QSS 必须用零延时 queued 更新并做幂等去重；圆角只保留 QSS 绘制，不再修改原生窗口 mask。
- `ui/GlobalDialogTheme.cpp`：QApplication 事件过滤器给所有 QDialog 补主题（palette + 追加 QSS）；QMessageBox 由 `ui/ThemedMessageBox` 专管。
- `ui/WindowChrome.cpp`：事件过滤器对所有原生标题栏顶层窗口用 DwmSetWindowAttribute 染色（IMMERSIVE_DARK_MODE=20、BORDER=34、CAPTION=35、TEXT=36），主题切换时 `refreshAllWindowChrome()`。
- 大型独立窗口的初始尺寸和最低尺寸统一调用 `ks::ui::applyResponsiveWindowGeometry`，以父窗口所在屏幕的 `availableGeometry` 为边界；不要再直接写 1000px 以上的硬 `setMinimumSize`，否则高 DPI、小屏或远程桌面会把窗口撑出工作区。
- 独立窗口中的懒加载 `QTabWidget` 必须隔离页面动态 `minimumSizeHint`：页面栈使用零最小尺寸和 `QSizePolicy::Ignored`，顶层窗口只保留响应式最低尺寸，禁止用 `maximumWidth` 对抗内容传播。纵向表单页应放入 `QScrollArea`，使切页和异步控件挂载不改变用户当前窗口尺寸，同时保留自由拖大和最大化能力。
- 主窗口是 FramelessWindowHint + 自绘 `framework/CustomTitleBar`；其余子窗口全是原生标题栏。

**全局基线样式只允许颜色/边框，禁止 min-height/padding 等几何属性**——app 级几何会穿透局部样式破坏紧凑布局（曾导致主窗口标题栏按钮被撑高、最大化后标题文字上偏）。

## 透明背景与毛玻璃（MainWindow.cpp）

配置项：`backgroundTransparencyEnabled`（总开关）+ `backgroundTranslucencyMaterial`（auto/mica/desktop）。

- 总开关需要 `WA_TranslucentBackground`，**必须在原生窗口创建前设置**，因此改动只能重启生效；材质选项可运行时切换。
- **DWM 云母（DWMWA_SYSTEMBACKDROP_TYPE）与 `WA_TranslucentBackground` 互斥**：云母要求窗口不透明、由 DWM 在其背后合成，遇到分层透明窗口会回退成系统浅色 fallback 底，表现为整窗发白。已改用 `SetWindowCompositionAttribute` + `ACCENT_ENABLE_ACRYLICBLURBEHIND`（Win10 1803+/Win11 通用），配置值仍叫 `mica` 仅为兼容旧配置。
- 毛玻璃生效时着色由系统随模糊合成，根容器必须画完全透明；未生效（旧系统/调用失败）才回退自绘半透明着色层保证文字可读——由 `applyMainWindowBackdropMaterial` 的返回值驱动。
- Acrylic 不会自动跟随窗口移动重采样，失焦后还会降级为静态回退色：`scheduleWindowBackdropRefresh()` 在 move/resize/WindowStateChange/ActivationChange 时重新下发组合特性，40ms 节流合并。
- 首次外观应用早于原生窗口创建，组合特性会被句柄守卫跳过，因此 `showEvent` 必须补调一次 `refreshWindowBackdropMaterial()`。
- **Dock 内容透明不能只看背景图**：`enableDockContentTransparency = 背景图就绪 || 窗口透明`，否则 DockManager 与各 Dock 的不透明表面会盖住底层，只剩菜单栏可见。KernelDock 会自绘实底，三处决策统一走 `shouldRenderTransparentDockContent()`。

## Dock 懒加载机制

- `ensureDockContentInitialized` 按 `ks_lazy_key` 创建真实 widget（成员指针 m_processWidget 等允许为 null，占位页 `createDockPlaceholderWidget`）。
- 跨 Dock 打开独立详情窗口时，只用 `ensureDockContentInitialized` 创建内部控制器和窗口管理状态；不要对其所属 Dock 调用 `raise()`、`setVisible(true)` 或 `setAsCurrentTab()`，否则会无条件改变用户当前标签。进程详情入口遵循此规则，`ProcessDock` 仍负责 identity 校验、窗口复用和详情页导航。
- 主功能 Dock 一律 `DockWidgetClosable=false`（Tab 无关闭按钮）。曾实现过"Tab 关闭按钮=卸载内容"（CustomCloseHandling + unloadDockContent），最终整体撤销（23251d80）；若再有此需求注意：welcome 无懒加载工厂，kernel↔driver 有共享自驱动页 `attachKswordSelfDriverPage`，卸载会悬空。
- 跨 Dock 的进程详情入口仍可调用 `ensureDockContentInitialized(m_dockProcess)` 来复用 `ProcessDock` 的详情窗口管理与 identity 校验，但不得随后 `raise()` 或 `setVisible(true)` 激活进程 Dock；`ProcessDetailWindow` 是独立顶层窗口，打开它时应保留用户当前页签。

## 启动单实例与权限切换

- `AppearanceSettings::preventMultipleInstances` 默认为 `true`，对应 JSON 字段 `prevent_multiple_instances`；只限制普通启动，关闭后新进程不再查找或激活旧主窗口。
- Admin、SYSTEM、UIAccess 等权限切换重启必须携带 `--ksword-privilege-restart`，保证默认开启防多开时仍能启动接管实例。使用 `CreateProcessWithTokenW` / `CreateProcessAsUserW` 时不能把 `lpCommandLine` 留空，应通过 `argumentsWithPrivilegeRestartMarker` 组装命令行并保留当前参数。
- 权限接管不能只绕过单实例检查：旧实例启动新实例成功后必须进入正常关闭流程，新实例应复用 `--ksword-crash-restart-wait-pid <PID>` 的同路径/直接父进程校验并等待旧实例退出，再继续主程序初始化，避免两个实例同时读写设置或争用 R0 服务。透传当前参数时先替换可能遗留的旧 wait PID。

## 通用表格交互

- 周期性后台刷新（例如进程监视采样）不得注册为全局 `kPro` 任务；否则每轮采样都会进入“当前任务”和顶部进度通知。`kPro` 只用于有明确开始/结束、需要用户感知的有限操作，常驻监视状态应留在页面状态标签与诊断日志中。
- 把系统枚举放进工作线程仍不足以保证主界面流畅：结果回到 UI 线程后，`QTableWidgetItem`、`QTreeWidgetItem` 与文件图标解析也可能形成长时间事件循环占用。启动项页把单阶段排序留在工作线程，每个枚举器完成后按固定顺序发布独立结果批次；UI 必须等上一批用零间隔单次 `QTimer`（目标 7ms、最多 24 单元）分时落表完成后再累计下一批，先填当前分类，未完成视图保持禁用，且只有“后端全部结束 + 阶段队列清空”才能结束同一刷新任务。后台枚举进度通过 UI 无关的稳定阶段枚举回调上报，翻译文案必须先在 UI 线程取得，不能从工作线程并发读取 `LanguageManager`。
- 周期采集的缺失证据或查询失败若使用 `Warn`，必须按规范化错误集合做状态变化去重：首次出现或错误集合改变时记录一次，连续相同采样只更新页面状态；错误清除后再复发才允许重新通知。否则默认 Warn 通知阈值会把固定失败放大成通知卡和日志风暴。
- `ui/TableInteractionSupport.cpp` 通过应用级事件过滤器统一接入 `QTableView/QTableWidget`；表头点击排序由 `ui/TableHeaderSortingSupport.*` 负责。
- `VisibleTableWidget` 与 `TableActionTableView` 共用嵌入式 `TableActionBar`，两者默认都提供冻结、暂停、快照和差异比对的完整条；窄小或纯展示表格可用 `setTableActionBarMode(..., Compact/None)` 降级或禁用。通用表格搜索入口只显示图标按钮，点击后把范围切到当前表格并激活标题栏搜索框，不在表格操作条内重复放置输入框。操作条会同时出现在 Dock 和普通 `QDialog` 中，因此按钮、快照滚动区等几何/字体样式必须由操作条自身用 palette 角色封装；不能继承宿主弹窗的 `themedButtonStyle`，否则弹窗中的 padding/粗体会把同一套按钮放大并挤压固定高度操作条。
- 普通 `QTableView/QTableWidget` 的横纵表头由 `TableInteractionSupport` 强制应用同一套 palette 基线，页面不要再用蓝色粗体等局部表头 QSS 制造层级差异；十六进制编辑器等确实需要专业表头语义的控件须在设置局部样式前调用 `setPreserveCustomTableHeaderStyle(table, true)` 显式声明例外。
- 线程表的“线程亲和性”右键入口（全局枚举、Ksword5.1 进程详情、KswordARKLight 进程详情）统一以 `shared/ThreadAffinityR3.h` 的 CPU Set/Group R3 API 实现。Ksword5.1 使用与进程 CPU 亲和性相同的 `QWidgetAction` 处理器矩阵；Light 保留原生子菜单。操作前必须核验 TID、所属 PID 和线程创建时间，R0-only/hidden 行不可走 R3 入口。
- 未显式开启 Qt 持续排序的 `QTableWidget` 使用“一次点击、一次排序”，不改变 `sortingEnabled`。这样后续 `setRowCount/setItem` 批量或分批填充不会因实时搬行而写错列组。
- 手动排序后遇到增删行、模型重置或单元格更新会撤销排序箭头，不自动重排半成品数据。具有帧序、加载序、采集序等固定行序语义的表格调用 `setTableHeaderClickSortingEnabled(table, false)`。
- 进程表使用 `QSortFilterProxyModel` 与友好分组专用排序；点击表头时首次为升序、同列再次为降序。父子树状视图点表头后保持“进程友好视图”未勾选，只把内部投影切成没有父子关系的普通扁平枚举并交给代理排序；用户再次切换友好视图复选框时退出该临时扁平模式。搜索结果与历史快照同样走代理原生排序。
- 进程友好视图不得维护独立的列比较 `switch`：数值列必须与普通列表共用 `processNumericSortValue`，非数值列复用 `formatColumnText` 的实际展示值。资源/工作量数值列的单元格染色统一由 `processUsageHighlightValue` 按同列幅值归一化，未采集值不染色，PID/会话 ID/优先级/布尔状态等非占用数值不进入染色。否则“专用 GPU 内存”等后续追加列会出现排序箭头变但行序不变，且单元格没有强度染色的漂移。
- 句柄页等大型 `QTreeWidget` 结果必须先建立轻量摘要节点，展开分支时每批最多创建 300 个明细节点，并用末尾“继续加载”节点追加下一批。摘要始终保持业务配置顺序，表头排序只重排各摘要下已加载的明细；占位节点和“继续加载”节点固定在分支末尾。进程图标等异步资源只为已创建的明细解析，回填必须同时校验树重建代次，并允许同一源记录出现在多个规则分支。
- `ui/DetailLayoutHost` 复用既有 `QSplitter` 时，必须确认表格与详情控件位于两个不同的 splitter 直接子面板；只判断“同属某个 splitter 祖先”会把整个页面面板误认成详情区，折叠后只剩箭头。页面仍在构造、详情面板尚未加入 splitter 时，统一布局接管应延迟到下一轮事件循环重试。
- 行内详情不得向现有 `QTableWidget/QTreeWidget` 插入合成业务行或子节点，否则页面原有的行号到缓存映射、排序和右键逻辑会整体漂移。统一详情布局只在视图层扩展源行高度并覆盖只读文本框，以 `QPersistentModelIndex` 跟踪源项；大型树的 SVG 状态图标更新必须合并频繁的 `rowsInserted`，并按固定批次让出事件循环。
- 行内详情展开后发生排序时，必须在模型的 `layoutAboutToBeChanged` 阶段清理详情：`QPersistentModelIndex` 会在布局完成后跟随数据项，但 `QHeaderView` 行高仍绑定排序前逻辑行；等 `layoutChanged` 后再恢复会留下旧行空白并裁剪新行编辑器。

## Taskbar AppBar 重启

- Taskbar 的设置重启与显示器变化重启统一走 PID 感知的接替路径：旧实例启动携带 `--restart-after-pid <oldPid>` 的同程序，新实例在创建窗口、AppBar 或后台采样线程前用 `OpenProcess(SYNCHRONIZE)` / `WaitForSingleObject` 等待旧实例真正退出。禁止用固定延时近似旧进程退出，否则同步线程清理和 AppBar 注销可能与新实例重叠。

## 踩坑记录

- 构建带 **i18n 审计钩子**：源码中任何"可提取"字符串字面量（中文日志、英文句子、无路径分隔的头文件名、甚至 `GetProcAddress` 的函数名）都必须在两个语言包的 `source_translations` 有条目，否则构建直接失败。QSS 选择器行要与 `{` 写在同一字符串片段内才会被审计排除。
- 语言包**只能定点编辑**：用脚本 json.load/dump 会重排键序与缩进，产生 5 万行无意义 diff。
- 约 1374 处散落 `setStyleSheet` 分布在 136 个文件（多带 `!important`），未来渐进收敛到全局基线。
- 构建产物被运行中的 exe 占用会导致 `LNK1104`；`vctip.exe` 残留会导致 obj `Permission denied`。

## 仓库规范（详见 AGENTS.md）

- 新增源码必须同步 `.vcxproj` 和 `.vcxproj.filters`。
- 用户可见文本必须同步 `languages/zh-CN.json` 与 `en-US.json`，并通过 `tools/i18n_language_pack.py audit`。
