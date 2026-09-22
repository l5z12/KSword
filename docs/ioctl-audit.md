# IOCTL consistency and access-policy audit

[简体中文](zh-CN/ioctl-audit.md) · [Documentation index](README.md)

`tools/ioctl_audit/ksword_ioctl_audit.py` reads repository source. It neither builds
nor executes driver code and does not modify handlers. It compares shared IOCTL
definitions with `drivers/ark/src/dispatch/ioctl_registry.c`.

It checks CTL_CODE parsing; missing/extra registrations; duplicate names/function
IDs; method agreement with the project's METHOD_BUFFERED convention; mutating names
using FILE_ANY_ACCESS; query names requiring write access; and conspicuous handler
name mismatches. These are static policy checks, not proof of runtime authorization.

## Run

```powershell
uv run --python 3.12 python tools/check.py --check ioctl
uv run --python 3.12 python tools/ioctl_audit/ksword_ioctl_audit.py --repo-root . --format json --out artifacts/ioctl-audit.json --fail-on-risk
```

`--fail-on-risk` returns 2 for HIGH findings. Keep it in CI; generating a report
without failing does not enforce the policy. Current results come from the command
above, not the [historical baseline](research/ioctl-audit-baseline.zh-CN.md).

## Rules and report

`tools/ioctl_audit/ioctl_audit_rules.json` contains full-name `allowedAnyAccess`
exceptions, `mutatingKeywords`, `queryKeywords`, `ignoredHeaders`, and explanatory
`notes`. Exceptions need a specific reason and compensating controls; do not
allowlist every current finding.

The JSON report includes `schemaVersion`, UTC `generatedAt`, `repoRoot`, scanned
headers/registry in `inputs`, effective `rules`, `summary`, parsed `ioctls`, parsed
`registry`, and `findings`. Each IOCTL records its name, device/function/method/access
expressions and values, computed `control_code`, source/line, registration/handler,
registry line, and matched mutating/query keywords. Each finding includes
`severity` (HIGH/MEDIUM/LOW), stable `category`, affected `name`, human-readable
`message`, and structured `details`.

For a new operation, keep shared definitions and registry entries in agreement.
Review access requirements for destructive operations and changes to pending or
policy state, and verify user-mode handles request the necessary access. A
read-only operation may intentionally require write access to restrict disclosure
of sensitive addresses; document that boundary instead of inferring mutation from
the access bit alone.
