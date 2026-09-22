# Coding style

[简体中文](zh-CN/coding-style.md) · [Contributing](../CONTRIBUTING.md)

KSword uses one naming convention for first-party C and C++ identifiers. Prefer
names that explain the domain and operation; casing alone does not make a name
useful. Avoid type prefixes such as `dw`, `lp`, `psz`, or `b` on new variables.

| Identifier | Convention | Example |
| --- | --- | --- |
| Class, struct, union, enum, type alias | PascalCase | `ProcessSnapshot` |
| Function, method | camelCase | `readProcessSnapshot` |
| Variable, parameter, public data member | camelCase | `processId` |
| Private data member | camelCase with a trailing underscore | `deviceHandle_` |
| Constant, enumerator | kPascalCase | `kMaximumEntries`, `State::kReady` |
| Namespace | lowercase; underscores between words if needed | `ksword::evidence` |
| Preprocessor macro | UPPER_SNAKE_CASE | `KSWORD_ENABLE_TRACE` |

Use ordinary words for acronyms inside new names: `readIoctl`, `processId`, and
`parseJson`. Do not encode ownership or nullability only in a prefix: make the
type and interface contract express them. Constructors and destructors retain
their class name, and operators retain C++ syntax. Parameters use camelCase even when
they are `const` or have a default argument.

## Compatibility boundaries

Names imposed by another interface keep that interface's spelling. This includes
Windows/WDK declarations and callbacks, Qt overrides and automatic connection
slots, exported entry points, assembly linkage, third-party interfaces, and
published wire declarations in `shared/driver/`. Preserve serialized keys,
command names, protocol constants, symbol lookup strings, and resource IDs.
These are contracts, not examples for naming new private implementation code.

Renames must include declarations, definitions, call sites, tests, and relevant
documentation. Check string-based dispatch and code generators explicitly.
Never apply a global text replacement to a common identifier: the same spelling
can name unrelated declarations or a Windows structure member.

## Tooling

The root `.clang-tidy` config records the naming policy using
`readability-identifier-naming`. Run Clang-Tidy against a compilation database
for the actual target, with its Windows SDK, WDK, Qt, defines, and includes.
Inspect proposed replacements before applying them; a parse failure is not a
successful audit. Review collisions with local names and existing constants,
macro arguments (`FIELD_OFFSET`, SAL, WDF), assembly `PROC` symbols, imported
variables, and third-party forward declarations. A source rename alone cannot
verify these boundaries. Clang is an analysis tool here: normal builds still use the
explicit MSVC toolset described in the [build guide](development.md).

After a rename, build every affected consumer and run its native tests, then run
`uv run --python 3.12 python tools/check.py`. A spelling change can still break
linkage or Qt dispatch even when a source-only check passes.

## Script language

First-party scripts use English for comments, help, diagnostics, progress,
prompts, and generated developer reports. Python follows PEP 8 naming;
PowerShell public commands keep its `Verb-Noun` convention. Script naming does
not inherit C++ casing rules.

Keep exact non-English text where it is input data: localized Windows output
patterns, Unicode regression fixtures, bilingual documentation content, and
existing persisted schema values. Explain the exception in English. Do not
translate a regular expression that must recognize Chinese Windows output or
silently migrate a stored value while translating a diagnostic.

`python tools/check.py --check script-language` checks scripts and workflow code.
`tools/script_language_exceptions.json` lists exact literal-data lines and their
reasons. It is not a baseline for untranslated messages. New diagnostics must be
English even when the same script contains a justified input-pattern exception.

## File and folder names

Use the [repository layout](repository-layout.md) rules: PascalCase C++ modules,
snake_case C modules and source folders, with conventional entry filenames.
