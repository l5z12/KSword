# Contributing to KSword

[简体中文](docs/zh-CN/contributing.md) · [Build guide](docs/development.md) · [Code map](docs/maintenance.md)

Contributions can be a reproducible bug report, a documentation correction, a
translation, a regression test, or a code change. You do not need a kernel testing
machine to contribute to the CLI, source tools, or offline analysis tests.
Issues and pull requests may be written in English or Chinese.

## Your first contribution

1. Pick one observable problem. Search existing issues and pull requests for
   related work. A small fix or test can go straight to a PR; discuss a new
   subsystem or protocol change in an issue before investing in its implementation.
2. Fork the repository, clone your fork, and create a descriptive branch:

   ```powershell
   git clone https://github.com/YOUR-USERNAME/KSword.git
   cd KSword
   git switch -c fix/describe-the-problem
   ```

3. Run the source checks with Python 3.12+ and PowerShell 7 (`pwsh` on PATH):

   ```powershell
   uv run --python 3.12 python tools/check.py
   ```

   If you already have Python 3.12+, `python tools/check.py` is equivalent. No
   Python packages are needed. Native builds use Windows; see the
   [prerequisite table](docs/development.md#choose-the-smallest-build) before
   installing Qt or WDK.
4. Find the owning module in the [code map](docs/maintenance.md). Keep a change
   focused on that responsibility. Add a regression case for changed behavior;
   use existing offline tests when possible.
5. Add new files to Git and to every consuming `.vcxproj` and `.vcxproj.filters`.
   Run the relevant tests and source checks. The checks inspect tracked
   working-tree files, so untracked additions are not yet part of the audit.
6. Open a pull request against the repository's default branch. Explain the
   problem, resulting behavior, and how you tested it. List anything you could
   not test. Build logs should identify the command, toolset, and first failure,
   rather than only showing the final MSBuild summary.

## Small contributions with useful feedback

| If you want to work on… | Start here | Validate with… |
| --- | --- | --- |
| Contributor tools or build selection | `tools/`, `tools/tests/` | `python tools/check.py --check tool-tests --check projects` |
| CLI argument handling | `apps/cli/CliArguments.cpp`, `tests/native/cli/` | `python tools/dev.py test --target cli-tests` |
| CLI commands and help | `apps/cli/Cli*.cpp`, `CliHelp.cpp` | `python tools/dev.py test --target cli` plus command-specific tests |
| Malformed filesystem input | `file_dock/NtfsRunListDecode.cpp`, `tests/native/fs_decode/` | `python tools/dev.py test --target fs-tests` |
| Driver response validation | `ArkDriverClient/*Support.h`, `tests/native/ark_client/` | `python tools/dev.py test --target client-tests` |
| ETW configuration files | `monitor_dock/EtwFilterConfig.*`, `tests/native/monitor/` | `python tools/dev.py test --target monitor-tests` (QtCore) |
| Translations or UI text | `apps/desktop/languages/`, owning UI module | `python tools/check.py --check i18n`; build the desktop for UI changes |

The `file_dock/`, `ArkDriverClient/`, and `monitor_dock/` paths above are under
`apps/desktop/`. All commands can be prefixed with `uv run --python 3.12`.
Passing CLI help tests verifies help routes, not live driver operations. Do not
claim runtime acceptance from a successful build.

## Reviewable changes

Public guides use English with a Chinese copy. Update both languages in the same
PR, keep reciprocal links, and register new pairs in `docs/catalog.json`. See the
[documentation index](docs/README.md) for the layout and original-language research
references. `python tools/check.py` checks paired guides, local links, and generated
CLI documentation alongside source integrity.

Keep unrelated formatting, generated binaries, local paths, and release assets
out of a PR. Follow the [coding style](docs/coding-style.md). Use names that describe the
operation and document ownership or invariants that are not apparent from the
code; avoid comments that repeat each statement.

Write code comments in English so contributors can follow the implementation.
Preserve technical identifiers, literal examples, and third-party notices. Put
non-English literal examples in inline backticks, with the explanation in English.
UI strings and English/Chinese documentation remain bilingual.
Script help, diagnostics, prompts, and progress messages use English too; retain
exact localized input patterns and Unicode test fixtures where required.
`python tools/check.py --check comments` checks first-party C/C++, Python, and XML
comments and Python docstrings. Review comments in other languages as part of the
PR; this check does not assess technical accuracy or translate text.

For a refactor, explain the new responsibility boundary and which behavior is
preserved. Avoid combining a large move with unrelated behavior changes. When a
review identifies a regression, add a targeted test before fixing it where the
behavior can be exercised independently.

New contributors can update project/filter entries in their own PR. There is no
separate owner approval required to build a project or prepare those edits. If
another PR touches the same feature, coordinate in the issue or PR and resolve
conflicts using the current module layout.

## Boundaries to preserve

- Define wire protocols only in `shared/driver/`, including DynData and capability
  structures. Register new driver IOCTL handlers in
  `drivers/ark/src/dispatch/ioctl_registry.c`; implement the feature under
  `src/features/<module>/`.
- User-mode code accesses KswordARK through `ArkDriverClient`. Dock UI must not
  issue raw KswordARK `DeviceIoControl` calls.
- Private kernel fields come from validated DynData/runtime capabilities, never
  new hardcoded offsets. Set the registry entry's `RequiredCapability` to the
  appropriate `KSW_CAP_*`; use `KSWORD_ARK_IOCTL_CAPABILITY_NONE` only when no
  capability is needed. Preserve field provenance and capability failures in UI.
- Keep System Informer integration limited to the vendored DynData source;
  do not import its KPH object system, communication layer, or session tokens.
- Preserve identity checks, buffer bounds, cancellation, callback lifetimes,
  and confirmations around system-changing operations. PPL changes still require
  `KSW_CAP_PROCESS_PROTECTION_PATCH` and the existing confirmation details.
- CLI command, alias, and parameter changes must update `CliHelp.cpp` and
  `docs/cli.md` (regenerate with `tools/generate_cli_docs.py`) and
  `docs/zh-CN/cli.md` together.
- Edit language packs at the affected keys only. Update both `zh-CN.json` and
  `en-US.json` for visible text changes; never rewrite whole packs with a JSON
  serializer. Run the i18n audit.

Before changing UI themes or asynchronous behavior, read the relevant entries in
[the shared project notes](.claude/memory/MEMORY.md). Those notes are available to
human contributors as well as coding agents; [maintenance.md](docs/maintenance.md)
is the public starting point.

## License and community

The project is distributed under [LICENSE](LICENSE), currently the KSword
Community Source License 1.6. Submit only material you have the right to
contribute, under the project's contribution terms. Preserve third-party license
texts and attribution. This guide does not change the project's license.

Discussion follows the [Community Covenant](COMMUNITY_COVENANT.md). It is a
community agreement, not an additional software license restriction.
