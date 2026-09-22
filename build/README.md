# Build configuration

[简体中文](../docs/zh-CN/build-layout.md) · [Build guide](../docs/development.md)

`msbuild/Ksword.Output.props` defines the shared Release output directory,
`artifacts/bin/x64/Release/`. Its path is resolved relative to this props file, so each
consumer imports the same location regardless of its project directory.

`Directory.Build.props` and `Directory.Build.targets` stay at the repository root
because MSBuild discovers them while walking parent directories. The shared props
selects 64-bit host tools and imports the optional, ignored
`Directory.Build.local.props` for workstation-specific Qt paths. The Qt setup
helper writes only that local file. Keep personal paths out of tracked defaults.
If an older checkout has generated Qt settings in `Directory.Build.props`, move
that local file to `Directory.Build.local.props` before updating the checkout.

Application and driver components retain their own root directories and project
files. Native regression projects live in `tests/native/`; changing their location
requires updating project/filter source paths, build runners, CI, and acceptance
scripts. Developer dependency downloads belong in `.deps/`, build/test reports in
`artifacts/`, and release staging and packages in `dist/`. These are ignored.

Run `python tools/check.py --check projects` after changing project membership,
then build the affected consumers. The source audit checks source/filter entries;
only MSBuild evaluates imports and resolves the effective build properties.
