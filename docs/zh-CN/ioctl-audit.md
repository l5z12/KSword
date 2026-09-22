# IOCTL 一致性与访问策略审计

[English](../ioctl-audit.md) · [文档目录](index.md)

`tools/ioctl_audit/ksword_ioctl_audit.py` 只读取源码，不构建或执行驱动，也不修改 handler。
它对比共享 IOCTL 定义与 `drivers/ark/src/dispatch/ioctl_registry.c`。

检查包括 CTL_CODE 解析、缺失/多余注册、名称与功能号重复、METHOD_BUFFERED 约定、
修改型名称使用 FILE_ANY_ACCESS、查询型名称要求写权限以及明显的 handler 命名偏差。
这是静态策略检查，不是运行时授权正确性的证明。

## 运行

```powershell
uv run --python 3.12 python tools/check.py --check ioctl
uv run --python 3.12 python tools/ioctl_audit/ksword_ioctl_audit.py --repo-root . --format json --out artifacts/ioctl-audit.json --fail-on-risk
```

发现 HIGH 风险时 `--fail-on-risk` 返回 2。CI 必须保留失败门禁，只生成报告不能执行策略。
当前结果以运行命令为准，[旧基线](../research/ioctl-audit-baseline.zh-CN.md)不是当前扫描状态。

## 规则与报告

`tools/ioctl_audit/ioctl_audit_rules.json` 包含完整名称的 `allowedAnyAccess` 例外、
`mutatingKeywords`、`queryKeywords`、`ignoredHeaders` 和解释性 `notes`。
例外必须说明具体理由与补偿控制，不能把所有当前发现整体加入白名单。

JSON 报告包含 `schemaVersion`、UTC `generatedAt`、`repoRoot`、`inputs` 中的头文件/注册表、
实际 `rules`、`summary`、解析出的 `ioctls` / `registry` 与 `findings`。
每个 IOCTL 包含名称、device/function/method/access 表达式与数值、计算的 `control_code`、
源码位置、注册和 handler、注册行号以及命中的修改/查询关键词。
每个 finding 包含 `severity`（HIGH/MEDIUM/LOW）、稳定 `category`、相关 `name`、
可读 `message` 与结构化 `details`。

新增操作时保持共享定义与注册表一致。破坏性操作、pending 状态与策略变更需检查访问权限，
并确认用户态句柄请求相应权限。只读操作也可能为了限制敏感地址泄露而要求写访问；
应说明该边界，不能仅凭 access bit 推断 handler 会修改系统。
