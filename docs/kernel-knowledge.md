# Kernel knowledge and topic evidence

[简体中文](zh-CN/kernel-knowledge.md) · [Documentation index](README.md)

The Kernel Dock's knowledge page presents 71 Windows kernel topics in 12
categories, based on the [knowledge plan](research/kernel-knowledge-plan.zh-CN.md).
Each topic has two complementary parts: a complete bilingual explanation in the
language packs, and a fixed-ID R3 → R0 snapshot that verifies related business
IOCTL registrations. Users can navigate to those features to collect their actual results.

A registered entry does not prove that the current machine returned every private
field. Preserve `unsupported`, `partial`, `truncated`, `budget`, and `unavailable`
when symbols, privileges, hardware, subsystems, or query budgets are insufficient.

## Page behavior

- Search titles, summaries, bodies, and stable topic IDs across the catalog.
- Navigate between articles, copy Markdown, and open Microsoft Learn references.
- Collect evidence in a worker through `DriverClient::queryResearchTopic`: PID/TID,
  RequestorMode, IRQL, processor group/CPU, exact system time, QPC, WDF/WDM device
  relationships, and metadata for the topic's business IOCTLs.
- Reject invalid protocol versions, fixed-header lengths, returned byte counts,
  flags, reserved fields, row counts/types, statuses, and unterminated strings.
- Carry a generation with asynchronous results so changing topics or destroying
  the page cannot display an old result in a new context.
- Open related pages only through allowlisted `routeId` values. Navigation never
  simulates action-button clicks or initiates a mutation; destination pages keep
  their own initial read-only loading lifecycle.

## Protocol and ownership

`shared/driver/KswordArkResearchIoctl.h` is the only shared ABI. Its version is
`KSWORD_ARK_RESEARCH_PROTOCOL_VERSION`; IDs 1–71 must have exactly the catalog's order.
`IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC` uses `METHOD_BUFFERED`, zero input flags and
reserved fields, and a bounded row budget. The response includes kernel-object and
handler addresses. It intentionally requires a read/write device handle, restricting
the evidence to Administrators/SYSTEM despite the control device's World read access.
That access requirement is a gate, not a statement that the handler modifies the system.

The handler reads request context and the central registry. It does not call other
handlers, scan, or mutate. Each topic maps to 1–4 real business IOCTLs, verified
through `kswordArkLookupIoctlEntry` for name, function, method, access, capability
mask, and registration. The snapshot proves this request reached R0 and reports
current registrations; it does not replace each business operation's input checks,
scan budget, DynData validation, cross-view comparison, or response.

| Owner | Responsibility |
| --- | --- |
| `kernel_dock/KernelKnowledgeCatalog.*` | Categories, IDs, implementation states, references, and allowlisted routes |
| `kernel_dock/KernelKnowledgeTab.*` | Search, filtering, navigation, Markdown, themes/languages, asynchronous evidence dialogs |
| `languages/{en-US,zh-CN}.json` | Visible titles, summaries, bodies, and evidence text; edit individual keys only |
| `drivers/ark/src/features/research/research_topic_ioctl.c` | R0 snapshot and business-entry mapping |
| `ArkDriverClient/ArkDriverResearch.cpp` | Typed R3 wrapper and strict parsing; no direct device access from the page |
| `KernelDock::openKnowledgeRoute` | Allowlisted navigation |

UI and client paths above are under `apps/desktop/`. Body keys are
`kernel.knowledge.topic.<topic_id>.title`, `.summary`, and `.body`.
Bodies must cover, in order: object relationships; lifecycle; public/private
boundaries; read-only observation; version/privilege/IRQL constraints; correct and
incorrect handling; KSword field interpretation; and what the evidence cannot prove.
The English pack uses the corresponding eight English headings.

## Constraints and extension

The handler must not scan, write, repair, detach, unload, or switch state. Copy
input before acquiring the output buffer. Bound output by the caller budget,
protocol limit, and actual WDF buffer. Pair WDM top-device references with
`ObDereferenceObject`; do not directly dereference PDB-private structures here.
Label private conclusions with their PDB/DynData/runtime-inference source.
External links are limited to `https://learn.microsoft.com`.

When adding or changing a topic, update the unique snake_case ID, category,
availability, route, shared numeric ID, R0 mapping, and both language packs
together. Keep their ordering identical. Map only IOCTLs already in the main
driver's registry; independent devices' control codes are not main-driver evidence.
Register new sources in every consuming project and filters file.

```powershell
uv run --python 3.12 python tools/check.py --check i18n --check knowledge --check ioctl
```

The validator checks catalog/order/count agreement; available status and routes;
business IOCTL registration and mapping counts; duplicate mappings; project
membership; client-only access; bilingual keys and eight-part bodies; relationship
diagrams; and incomplete markers in the plan. CI also builds the desktop and driver.
Compilation is not driver-load acceptance or proof of complete results on every
Windows/hardware combination. Runtime validation belongs on isolated test machines.
