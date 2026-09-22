# KSword agent notes

[简体中文](docs/zh-CN/agent-notes.md) · [Contributing](CONTRIBUTING.md) · [Code map](docs/maintenance.md)

## Read before working

Read both the agent's available personal/user memory or conversation summary and
[the shared memory index](.claude/memory/MEMORY.md), then relevant linked topics.
The `.claude/memory/` directory is shared by all agents and developers. Missing
personal memory does not excuse skipping shared memory.

Before changing desktop UI, themes, or window backgrounds, read
[UI architecture](.claude/memory/ksword-ui-architecture.md). Record reusable
discoveries in the appropriate shared topic. Use repository-relative paths in
instructions and documentation, not a developer's machine-specific checkout.

## Code and documentation boundaries

- Follow `docs/coding-style.md`: PascalCase types, camelCase functions and
  variables, kPascalCase constants, and English script help and diagnostics.
  Preserve externally mandated names, wire contracts, and localized input patterns.
- Write first-party code comments in English. Preserve technical identifiers,
  literal examples, third-party notices, and the meaning of safety invariants.
  User-visible strings and bilingual documentation follow their own language rules.
- Define R0/R3 wire protocols only in `shared/driver/`.
- Register IOCTL handlers in `drivers/ark/src/dispatch/ioctl_registry.c`;
  do not add business switches to `ioctl_dispatch.c`.
- Access the KswordARK device through `shared/ark_client/`;
  Dock UI must not call KswordARK `DeviceIoControl` directly.
- Update every consuming `.vcxproj` and `.vcxproj.filters` for new source files.
- For CLI command, alias, or parameter changes, update built-in help metadata,
  regenerate `docs/cli.md` with `tools/generate_cli_docs.py`, and update
  `docs/zh-CN/cli.md` in the same change.
- Use English for primary public documentation, with a Chinese copy under
  `docs/zh-CN/`. Keep both versions current and register guide pairs in
  `docs/catalog.json`. Preserve original-language research records.
- Edit language packs only at affected keys. Never rewrite `languages/*.json`
  wholesale with `json.load`/`json.dump` or another serializer.
- Changes to visible desktop text must update both
  `apps/desktop/languages/zh-CN.json` and `en-US.json`, and pass
  `python tools/check.py --check i18n`.
- Preserve third-party license texts and attribution.

Run `python tools/check.py` and relevant native tests; local Python commands may
use `uv run --python 3.12 python`. CI may invoke Python directly. See the
[build guide](docs/development.md) for prerequisites and explicit toolset choices.

## Releases and build recovery

Read [the release procedure](docs/releasing.md) before packaging. Keep a complete
`Release/` archive layout, refresh the required binaries, include licenses and
profiles, and verify archive integrity and contents. Record any reused driver.

For `LNK1000`, `IMAGE::BuildImage`, or `.iobj` internal linker failures, follow
[the recovery notes](.claude/memory/ksword-build-recovery.md): one clean rebuild
with temporary WPO/LTCG disablement, no automatic compiler/toolset switching, and
artifact-only verification afterward. A post-link WDK validator pass is separate
from a complete build, signing, and loading. Stop only the positively identified
stalled MSBuild process after establishing it has no active compiler/linker/
validator children.

## Launcher report intake

Validate an extracted report read-only before committing it to the corpus:

```powershell
uv run --python 3.12 python tools/pdb_offset_generator/launcher_report_intake.py $reportDir
# Continue only when valid=true.
uv run --python 3.12 python tools/pdb_offset_generator/launcher_report_intake.py $reportDir --corpus-root $corpusRoot --commit
```

The intake validates SHA256 and PE/RSDS identity, downloads exact PDBs, and
generates NTOS/NTKRLA57 offsets; collection-only modules retain PE/PDB only.
Wine, non-amd64, missing-RSDS, or checksum-mismatched reports must not enter the
official matrix. After import, run `ksword_profile_release_sync.py` to regenerate
the single release matrix `ark_dyndata_pack_v4.json`, then
`apps/launcher/tools/generate_support_manifest.py`. Confirm the PDB GUID/Age is unique
and `complete=true`, and build Launcher Release. Repeated imports should report
`existing`.
