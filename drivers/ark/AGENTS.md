# Driver development notes

[简体中文](../../docs/zh-CN/driver-agent-notes.md) · [Repository rules](../../AGENTS.md)

Every driver statement must have an English comment. New code must build with
warnings treated as errors. Explicitly resolve conversion, value-category, and
format warnings. Prefer files below 1,000 lines; split larger modules into
coherent `.c`/`.h` units, never stacked `.inc` files.

R0/R3 IOCTL constants and input/output structures belong only in `shared/driver/`.
Do not duplicate wire declarations in driver-private headers or frontend code.

- `drivers/ark/src/dispatch/ioctl_registry.c/.h` registers handlers only.
- `drivers/ark/src/dispatch/ioctl_validation.c/.h` owns common WDF buffer and
  access validation.
- `drivers/ark/src/dispatch/ioctl_dispatch.c` performs registry lookup, handler
  invocation, common logging, and request completion; keep business logic out.
- `drivers/ark/src/features/<module>/<module>_ioctl.c` contains the module's
  handlers. Put the underlying query/action implementation beside them.

Register every new `.c`/`.h` in `KswordARKDriver.vcxproj` and its `.filters`.
Preserve third-party LICENSE/NOTICE files and use repository-relative paths.

When adding or deleting an IOCTL, update
`tools/driver_functional_ci/driver_test_plan.json`. Add a safe executable test or
explain its exclusion. The plan gate identifies every uncovered IOCTL; see
[driver tests](tests/README.md).
