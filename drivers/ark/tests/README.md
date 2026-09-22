# 驱动功能矩阵 CI

在开启测试签名的专用机器上加载 `KswordARK.sys`，按计划遍历驱动功能，**系统崩溃即判失败**。

| 文件 | 作用 |
| --- | --- |
| `tools/driver_functional_ci/driver_test_plan.json` | 功能矩阵计划：185 个已注册 IOCTL 的逐条处置 |
| `tools/driver_functional_ci/plan_gate.py` | 静态门禁：计划与 IOCTL 注册表必须一致，危险操作必须被排除 |
| `drivers/ark/tests/DriverFunctionalMatrix.ps1` | 测试机上的执行器：加载驱动、跑用例、采集崩溃证据、给出归因 |
| `.github/workflows/driver-functional-ci.yml` | 两段式工作流：普通 runner 跑门禁，自托管测试机跑矩阵 |

## 为什么崩溃可以被判为驱动缺陷

驱动本身提供了大量「写内核内存」「摘链 EPROCESS」「强卸驱动」「改 HWID/时钟」这类操作。
拿它们去打自己的机器，崩溃只能说明测试输入危险，不能说明驱动有缺陷——尤其是命中
PatchGuard 覆盖区时，bugcheck 还会**延迟数分钟到数小时**才触发，足以污染后续的运行。

所以本 CI 用三层把「自伤」和「缺陷」分开：

1. **静态排除。** `plan_gate.py` 用 `policy.mustExcludePatterns` 逐个匹配已注册 IOCTL，
   命中危险模式的一律必须落在 `excluded`，否则门禁直接失败。当前 185 个 IOCTL 里有 33 个
   命中危险模式，全部被排除；新增的危险 IOCTL 会因为模式匹配被自动拦下，除非在
   `policy.patternWaivers` 里显式写明豁免理由。
2. **运行时目标校验。** probe 层允许的有界写操作（删文件、打完整性标签、建/改/删注册表键、
   挂起与终止进程）全部带 `targetGuard`，执行前逐个检查 `--pid` / `--path` / `--key`
   的实际取值：PID 必须是本次运行自己拉起的一次性进程，路径必须在本次运行的临时目录里，
   注册表键必须在本次运行的专属子键下。越界立即中止整轮，不会打到系统对象上。
3. **归因降级。** `guarded` 层默认不执行。一旦显式打开，本轮会被标记
   `attributionWeakened`，崩溃归因为 `harness-attributable`；而且这个标记会随
   `last-run.json` 保留到下次重启，所以**同一次启动内跑过 guarded 之后**，即使崩溃发生在
   下一轮的 probe 用例上，也只会归因为 `possibly-self-inflicted-previous-run`，
   不会误报成驱动缺陷。

因此只有 `attribution == driver-defect` 才表示：计划内的安全操作把机器打崩了。

## 覆盖口径

```
185 已注册 IOCTL = 134 计划执行 + 51 排除
```

排除的 51 项里，33 项是上面说的安全排除，18 项是 `no-cli-path`——KswordCLI 还没有对应
子命令，harness 触发不到。这 18 项是**覆盖缺口而不是安全排除**，受 `policy.gapBudget`
约束：缺口只能减少不能增加，想加新缺口必须显式上调预算并说明原因。

用例分 `probe`（默认执行）和 `guarded`（需要 `-IncludeGuarded -AcknowledgeGuardedRisk`）。
判定口径分三种：`success` 要求退出码为 0；`graceful` 允许非零退出（`unsupported`、
`partial`、`truncated`、budget 都是有效的运行态结果），但进程不得异常终止；
`timeout` 用于故意让请求挂起的用例，超时被结束算通过，**进程无法退出则判定驱动取消路径有缺陷**。

## 崩溃判据

运行前采基线，运行后取三路证据，任意一路命中即判崩溃：

- `%SystemRoot%\Minidump\*.dmp` 与 `MEMORY.DMP` 的新增或更新；
- System 日志的 `WER-SystemErrorReporting(1001)`、`Kernel-Power(41)`、`EventLog(6008)`；
- `Win32_OperatingSystem.LastBootUpTime` 与基线不一致（意外重启）。

崩溃时正在跑哪个用例，靠 `%ProgramData%\KswordARK\driver-functional-ci\journal.jsonl`。
该日志用 `FileOptions.WriteThrough` 打开并逐条 `Flush($true)`，每条记录在命令发出**之前**
就已经穿透文件系统缓存落盘，所以机器当场 bugcheck 也能还原现场。

如果机器崩到把 job 直接带走，下一轮运行的预检会读到未闭合的日志并**拒绝启动**，
提示中断在哪个用例上。人工定位完成后加 `-AcknowledgePreviousCrash`（或用
`workflow_dispatch` 的同名输入）解除阻塞。

## 测试机准备

1. 装好 VS 2022 生成工具与 WDK（要能构建 `KswordARKDriver.vcxproj`）。
2. 开测试签名并重启：

```bash
bcdedit /set testsigning on
```

3. 开内核转储。工作流会带 `-ConfigureCrashDump` 自动配置，也可以手工设置
   `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl` 的 `CrashDumpEnabled=2`、
   `AlwaysKeepMemoryDump=1`、`AutoReboot=1`。
4. 以**管理员**身份安装 GitHub 自托管 runner，打上标签
   `self-hosted, windows, x64, ksword-driver-testmode`。
5. 在仓库变量里设置 `KSWORD_DRIVER_TESTMODE_RUNNER=true`，push/PR 才会自动排队；
   不设置时只有 `workflow_dispatch` 会触发矩阵作业（避免 job 永远挂在等待 runner）。

这台机器应当是可随时重装的一次性环境：矩阵会加载未正式签名的内核驱动，并按计划改动
临时文件与专属注册表键。

## 本机手动运行

```bash
powershell -ExecutionPolicy Bypass -File drivers/ark\tests\DriverFunctionalMatrix.ps1
```

常用参数：`-Mode SelfTest` 只自检 harness 自身逻辑（不加载驱动、不需要管理员，可在任意机器上跑）；
`-Mode Verify` 只做崩溃取证；`-CaseFilter '^memory\.'` 定位单条回归；
`-SkipDriverLoad` 复用已经加载好的驱动。

退出码：`0` 通过，`1` 有失败用例或中途中止，`2` 观察到系统崩溃，`3` 预检未过。

## 新增 IOCTL 时要做什么

在 `shared/driver/` 加协议、在 `ioctl_registry.c` 登记之后，`plan_gate.py` 会立刻失败并点名
新 IOCTL。补上其中一项：

- 能安全执行：在 `cases` 里加一条用例，写清 `ioctls`、`steps`、`expect`、`timeoutSeconds`；
  涉及有界写操作的必须带 `targetGuard`，并且只能打在 harness 自建对象上。
- 不能安全执行：在 `excluded` 里加一条，写明 `reason` 与 `detail`（说明为什么 CI 不能执行它）。
- 还没有 CLI 入口：按 `no-cli-path` 排除，但缺口预算不允许增长，需要同时补 CLI 子命令
  或显式上调 `policy.gapBudget`。
