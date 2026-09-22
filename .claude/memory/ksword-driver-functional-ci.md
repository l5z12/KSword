---
name: ksword-driver-functional-ci
description: 驱动功能矩阵 CI 的覆盖口径、危险操作排除策略与崩溃归因边界
metadata:
  type: project
---

# 驱动功能矩阵 CI

- 入口三件套：`tools/driver_functional_ci/driver_test_plan.json`（计划）、
  `tools/driver_functional_ci/plan_gate.py`（静态门禁）、
  `drivers/ark/tests/DriverFunctionalMatrix.ps1`（测试机执行器）。
  工作流 `.github/workflows/driver-functional-ci.yml` 分两段：普通 runner 跑门禁 + harness 自检，
  自托管测试签名机跑真实矩阵。完整说明见 `drivers/ark/tests/README.md`。
- 覆盖是**强制闭合**的：185 个已注册 IOCTL 必须在计划里被「执行」或「排除」恰好一次。
  新增/改名 IOCTL 而没有同步计划，`plan_gate.py` 会直接点名失败。当前口径是
  134 执行 + 51 排除（33 项安全排除 + 18 项 `no-cli-path` 缺口）。
- 「崩溃即失败」只有在排除了自伤操作后才成立。驱动自带写内核/物理内存、DKOM 摘链、
  强卸驱动、改 HWID/时钟/电源、配置蓝屏路径等能力，用它们打自己的机器崩溃说明不了任何问题。
  策略靠 `policy.mustExcludePatterns` 做**模式匹配**而不是硬编码名单，新增的危险 IOCTL
  会被自动拦下，要放行必须在 `policy.patternWaivers` 写明理由。
- **PatchGuard 的 bugcheck 是延迟触发的**，可能在危险操作之后几分钟到几小时才炸。所以归因
  不能只看「崩溃时在跑哪个用例」：`last-run.json` 会把 `guardedExecuted` 与 `lastBootUpTime`
  一起留到下次运行，同一次启动内跑过 guarded，后续崩溃一律降级为
  `possibly-self-inflicted-previous-run`。只有 `driver-defect` 才是真缺陷。
- probe 层允许的有界写操作全部带 `targetGuard`，运行时逐个校验 `--pid` / `--path` / `--key`：
  PID 必须是本次运行自己 spawn 的一次性进程，路径必须在本次运行临时目录内，注册表键必须在
  专属子键下。这是静态门禁失效时的第二道防线，越界直接中止整轮。
- 崩溃现场靠 `%ProgramData%\KswordARK\driver-functional-ci\journal.jsonl`：用
  `FileOptions.WriteThrough` 打开并逐条 `Flush($true)`，在命令发出**之前**就落盘。
  机器被打崩导致 job 消失时，下一轮预检会读到未闭合日志并拒绝启动，必须人工定位后加
  `-AcknowledgePreviousCrash` 解除。
- 判定口径要容忍降级结果：`unsupported`、`partial`、`truncated`、budget 都是有效运行态结果，
  所以默认 `expect: graceful` 只要求进程不异常终止；只有自诊断类用例才要求退出码为 0。
  另有 `expect: timeout` 专门验证挂起请求的 IRP 取消路径——进程超时后仍无法退出就是驱动缺陷。
- harness 自身的安全逻辑可在任意机器验证：`DriverFunctionalMatrix.ps1 -Mode SelfTest`
  不加载驱动、不需要管理员，覆盖 targetGuard、占位符展开、异常退出码判定、崩溃归因与
  上一轮崩溃阻塞，普通 CI 每次都跑。
