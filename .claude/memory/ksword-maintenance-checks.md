# 可维护性与源码检查

- 公开指南使用英文与 `docs/zh-CN/` 中文副本，入口 `docs/README.md` / `docs/zh-CN/index.md`；配对登记 `docs/catalog.json`。`tools/docs_audit.py` 检查配对互链与本地链接，`tools/generate_cli_docs.py --check` 检查英文 CLI 参考与唯一 help 注册元数据一致。中文 CLI 保留人工操作说明，同步更新。
- 原生回归项目位于 `tests/native/`，共享输出 props 位于 `build/msbuild/`；根 `Directory.Build.targets` 因 MSBuild 自动发现机制保留。Qt 设置脚本位于 `scripts/setup/`，随程序发布的 Taskmgr 脚本位于 `scripts/runtime/`，旧 MOC helper 位于 `scripts/legacy/`。生成 PDF/报告/日志放 `artifacts/`，文档图片放 `docs/assets/`。移动路径时同步 CI、runner、项目 imports、验收入口和文档，不重写历史执行日志。

- 面向社区的入口为 `CONTRIBUTING.md`（英文）、`docs/zh-CN/contributing.md`（中文）、`docs/development.md`（构建路径）；README 两种语言链接这些入口。不要恢复个人 VS 路径或临时“找 owner 批准才能构建”的贡献规则。
- `tools/dev.py doctor/build/test` 只发现依赖并调用现有 MSBuild 项目，不安装依赖、不改用户环境、不加载/签名驱动。默认 v143/Release/x64，v145 只允许显式选择；Qt 依赖仅对应 Qt 目标。默认 tests 是 client/CLI/fs 三组离线测试，CI 也直接用 `python tools/dev.py test`。
- 开发脚本复用 `sys.executable` 给主程序构建期 Python 检查，uv 本地调用不需要包装脚本。环境覆盖和 PATH 仅进入子进程。新增开发目标同步更新 `tools/dev.py`、贡献/构建指南和对应 CI 验证；原生构建失败不得执行旧测试 exe。

- `MainWindow.cpp` 只保留构造、析构、关闭和启动进度；Dock、导航、主题、背景、原生窗口、权限、驱动服务分别位于 `MainWindow.<职责>.cpp`。私有跨单元接口在 `MainWindow.*Support.h`，命名空间 `ksword::ui::main_window`。服务操作互锁仍只有 `MainWindow.DriverServiceBackend.cpp` 一份定义，窗口析构仍等待 R0 通知租约释放。
- `ArkDriverClient.cpp` 只负责设备传输、句柄和通知同步；进程/线程/固件/注入等实现独立。原大型审计文件拆成 Network/Storage/Security/Win32k/Device/Platform/I8042/Object/DynData 单元。所有消费者项目与 filters 必须同时加入新增实现。
- `ArkDriverTypes.h` 保留兼容聚合入口，215 个原声明按职责分到 18 个类型头；只需要 IoResult/DriverHandle 的代码可直接包含 `ArkDriverIoTypes.h`。这不是协议迁移，wire 定义继续只放 `shared/driver/`。
- 响应共用逻辑在 `ArkDriverResponseSupport.h`、`ArkDriverAuditSupport.h`、`ArkDriverNetworkSupport.h`。三种 unsupported 判定的错误集合不同，不能合并语义；网络 inventory 与 endpoint 的 partial 保留策略也不同。变长行 reserve 必须先按真实缓冲容量约束，拒绝 0/短 stride。
- `KswordArkClientTests` 是不加载驱动的原生 MSVC 回归项目，覆盖 guard-page 字符串读取、审计边界、计数与 stride、网络 partial/header 和 Win32 句柄所有权。CI source-integrity 无条件构建运行。源码 Python 检查不能替代它。
- i18n 扫描跳过 `#include` 的头文件名（含续行），但不跳过包含可见文案的宏定义。不要把新增头文件名塞进语言包。

- `FileDock`、`ProcessDock`、`MonitorDock` 按职责拆到同目录命名 `.cpp`；入口保留生命周期。私有 `*.Support.h` 分别使用 `ksword::ui::file_dock`、`process_dock`、`monitor_dock`。不要跨功能依赖这些私有合同；具体映射见 `docs/maintenance.md`。
- `FileDetailDialog.h` 声明文件属性对话框，`FileDetailDialog.*.cpp` 分别实现元数据、事务、哈希、安全与存储等。Oplock 记录定义只在 `FileDock.Oplocks.cpp`，报告展示偏好只有 `FileDock.ViewSupport.cpp` 一份定义。
- 进程活动图与滑块分别在 `ProcessActivityChartWidget.*`、`ProcessActivityTimelineSlider.*`。动态字段复制模板必须保留在 `ProcessDock.Support.h`，多个翻译单元都会实例化。
- ETW schema cache 和锁只有 `MonitorDock.Schema.cpp` 一份定义。`EtwFilterConfig.h/.cpp` 只依赖 QtCore：模型、字段元数据、JSON 校验和序列化不读取 UI。解析时显式传入前后置 Provider/Action 选项，完整校验后才提交输出。配置导出复用同一序列化路径。
- `KswordMonitorTests` 仅需 QtCore，不启动窗口、驱动或 ETW，覆盖版本、失败不提交、阶段选项以及所有字段/匹配模式往返。CI usermode 构建运行，独立修改该测试也必须触发该 job。
- CLI 按命令族拆到 `Cli*.cpp`；`CliHelp.cpp` 的 family registry 同时负责 help 与 dispatch；`CliArguments` 拒绝负数/溢出和非法十六进制字符；设备 IO 复用 ArkDriverClient。命令修改同步内置元数据、生成的 `docs/cli.md` 与 `docs/zh-CN/cli.md`。
- `KswordCliTests` 覆盖参数解析；`tools/test_cli_help.py` 执行所有元数据声明的 help/别名路由，可用 `--baseline` 比较已有命令输出。CI 仍使用原生 Python；本次本地 Python 操作使用 uv。

- 本机/CI 共用 `tools/check.py`，Python 3.12+，仅标准库；CI 保持直接调用 Python。本机可以使用 `uv run --python 3.12 python tools/check.py`。
- `--list` 查看门禁；`--check <name>` 可重复。所有选中的检查均会执行，最终任一失败即非零退出，避免首个失败遮住其它回归。
- `tools/project_audit.py` 检查所有 Git 跟踪的 `.vcxproj` 的源码输入与 `.filters` 一致性：类型、重复项、精确大小写、Git 跟踪状态与文件存在性。不是 MSBuild 求值器，也不判断完全未注册文件的归属。新增源码先 `git add` 再审计。
- 唯一显式生成文件例外是安装器 `GenerateKswordSetupPayload` 生成的 `PayloadResources.h/.rc`；不要把整个 generated 目录或现有差异加入宽泛白名单。
- 两个构建工作流共用 `tools/ci_changes.py`；调整消费者依赖时更新 `PROJECT_INPUTS` 和 `tools/tests/test_ci_changes.py`。Root props/targets/solution 必须触发驱动与所有用户态消费者。
- CI 历史不明确则全量构建；push 只有上一成功运行的 `head_sha` 等于该 push 的 `before` 才能缩小范围。重命名读取新旧两个路径，文件清单统一使用 `git ... -z`，避免中文路径转义与空白分割。
- `Source integrity` 不再按 native build 的 `any` 过滤，文档/驱动独立变更同样执行源码门禁；IOCTL 审计保留 `--fail-on-risk`，报告输出到 `artifacts/ioctl-audit.md`。
- 维护说明与渐进拆分建议见 `docs/maintenance.md`。这些门禁不能替代 native build、驱动签名、加载或 VM 验收。

- First-party source comments and Python docstrings use English. Preserve technical identifiers, numeric constraints, literal examples, and safety invariants. User-facing text and bilingual guides retain their separate language rules; never translate vendored license or attribution text as part of a comment cleanup. For bulk comment edits, verify executable tokens/ASTs and non-comment bytes against the pre-edit source, then run the normal checks and relevant native tests. Some sources have mixed line endings; do not normalize entire files during translation.
- `tools/check.py --check comments` checks tracked first-party C/C++, Python, and XML comments/docstrings for Chinese prose. It skips runtime strings and vendored directories; inline literal examples can use backticks. The standard-library-only check has lexer regression tests in `tools/tests/test_comment_language_audit.py`. Review other source languages manually and assess technical accuracy separately.
- When translating adjacent comments, preserve the boundary between a trailing field annotation and the following field's standalone explanation. Joining them can silently attach a safety invariant to the wrong field even when executable tokens remain identical. Keep bit tables and assembly examples on their original rows, and review negation, stopped/running prerequisites, inclusive bounds, and ring-buffer wraparound terminology explicitly.

- First-party naming follows `docs/coding-style.md` and its Chinese copy: PascalCase types, camelCase functions/variables/parameters (including const/defaulted parameters), kPascalCase constants/enumerators, and trailing underscores for private members. `.clang-tidy` records the policy; use the actual compilation database and review changes before applying them.
- Preserve external names at both declarations and references: SDK/WDK imports such as `IoDriverObjectType`, `MmSectionObjectType`, opaque `HWND__`, FLTK forward declarations, `.def` exports, and every assembly `PROC`/`EXTERN`/`PUBLIC` symbol. A Clang-only pass can miss `offsetof`/`FIELD_OFFSET`, SAL, WDF macros, pragma section names, namespace aliases, and uninstantiated template references. MSVC compilation plus linking is required.
- Check case-folding collisions explicitly. A PascalCase helper can become hidden by an existing camelCase variable; a newly prefixed local constant can hide an existing kPascalCase global. Give helpers descriptive names and qualify adapters when ADL finds a newly matching underlying API. Consolidate duplicate private compatibility wrappers after updating all consumers.
- `script-language` checks first-party scripts and workflow code. Exact non-English input patterns, persisted compatibility values, Unicode fixtures, and bilingual generated content are documented in `tools/script_language_exceptions.json`; diagnostics and comments remain English. Local Python work uses uv; CI may use raw Python.
- `tools/tests/test_hvm_local_ept_gate.py` verifies both private-root operand rejection and failure when a resident function has no recognized INVEPT call. This prevents a future symbol rename from making the safety gate pass without inspecting any calls.


## Repository layout and path validation

- The active solution is `KSword.sln`. Applications are under `apps/`, the driver
  under `drivers/ark/`, and adapters under `integrations/`. Shared R3 transport
  is `shared/ark_client/`; reusable platform utilities are `shared/platform/`.
  Some platform modules need Qt Core; do not assume the whole directory is Qt-free.
- Native tests use `tests/native/{ark_client,ark_light,cli,dwm_z_order,fs_decode,monitor}`.
  `build/msbuild/Ksword.Output.props` gives applications/drivers one output root,
  `artifacts/bin/<platform>/<configuration>/`, independent of SolutionDir.
- `tools/layout_audit.py` enforces root boundaries, snake_case source directories,
  PascalCase C++ module filenames, snake_case C driver filenames, case-folding
  uniqueness, and exclusion of local IDE/build state. Vendor/runtime asset names
  retain their required spelling. ADS and FLTK headers preserve upstream bytes.
- `.vcxproj.filters` files are generated by `tools/project_filters.py --write`.
  Add inputs to every consuming project, then regenerate filters; do not hand-edit
  virtual folders. Filters keep header/implementation pairs together and show
  shared dependencies by repository path. `tools/check.py` detects drift.
- Preserve resource URLs, output binary names, exported symbols and language packs
  during path-only refactors. Review RC filenames and development fallback strings,
  Python pathlib chains, PowerShell script-root depth, CI filters, and CMake source
  exports; successful C++ compilation alone does not validate these references.
- The default source checks also run `driver-plan`, `driver-safe-read`, and
  `driver-harness`. PowerShell 7 (`pwsh`) is required for the latter two;
  the harness runs only `SelfTest`, without driver loading. Keep all source-name
  expectations in `SafeReadRegression.ps1` synchronized during symbol renames.
- The functional-plan gate reuses `tools/cli_catalog.py` and reads `CliHelp.cpp`,
  like the docs generator and help-route tests. Do not restore a separate regex
  over the CLI entry point. Script root traversal must account for `drivers/ark/tests/`.
- WDK builds force-include `warning.h`, which defines C macros including `leave`.
  A standalone compiler invocation without this header can miss name collisions:
  the window-band runtime callback uses `leaveCriticalSection` for this reason.
- `Directory.Build.props` selects x64 host tools before C++ tool-path evaluation.
  Direct CI builds previously used `HostX86/x64/link.exe` and failed with C1002
  during LTCG, even when the automatic HostX64 retry finished code generation.
  Keep the host choice shared across IDE, direct MSBuild, and contributor commands;
  it does not change the MSVC toolset, target platform, or optimization settings.
- Retired desktop/qmake scaffolding is text under `archive/desktop/`; taskbar
  snapshots remain under `archive/taskbar/`. Local old build trees were moved to
  ignored `artifacts/legacy-layout/`. Do not use those trees as source dependencies.
