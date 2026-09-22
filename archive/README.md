# Historical source snapshots

[简体中文](../docs/zh-CN/source-archive.md) · [Current layout](../docs/repository-layout.md)

These files preserve old experiments and superseded build descriptions. They
are not supported build entry points. The active solution is `KSword.sln` at
the repository root; use `tools/dev.py` for individual targets.

- `desktop/`: retired unused Qt form scaffolding and Win32/qmake build descriptions,
  stored as text so IDEs and source checks cannot mistake them for active projects.
- `taskbar/`: historical taskbar source snapshots, retained for reference.

Do not add current implementations here. Place new work in its owning module and
use Git history for ordinary backups.
