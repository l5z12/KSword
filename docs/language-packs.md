# Language packs

[简体中文](zh-CN/language-packs.md) · [Documentation index](README.md)

The desktop loads UTF-8 JSON packs from `languages/` beside the executable and
also probes `apps/desktop/languages/` in development. Adding or updating a
pack needs no recompilation; restart to discover a file added after startup.
The `ui_language` setting defaults to `system`. Settings, the native splash,
first-run flow, startup dialogs, and standard QMessageBox buttons use the same
resolved language.

## Format

One JSON file describes one language. Its identity comes from `id`, not its filename:

```json
{
  "schema": "ksword-language-pack",
  "format_version": 1,
  "id": "en-US",
  "name": "English (United States)",
  "native_name": "English",
  "author": "KSword Team",
  "text_direction": "ltr",
  "fallback": "zh-CN",
  "translations": { "menu.settings": "Settings" },
  "context_translations": { "process.menu.copy_cell": "Copy cell" }
}
```

- `schema` is `ksword-language-pack`; the current `format_version` is `1`.
- `id` uses a BCP 47-style identifier such as `en-US`, `zh-CN`, or `ja-JP`.
- `name` is the English name; `native_name` is the name in that language.
- `text_direction` is `ltr` or `rtl`, defaulting to `ltr`.
- Optional `fallback` names another pack for missing keys. Cycles are cut off.
- Translation keys and values must be strings. `translations` uses stable semantic
  IDs, not source text. `context_translations` identifies the particular control,
  column, menu, or drawing location and is read through `LanguageManager::contextText`.
  The same source text in different contexts needs different keys.
- `source_translations` is retained only for old pack compatibility and is no
  longer used at runtime. Do not use it for global replacement of controls, log
  levels, table data, or protocol fields.

Packs are limited to 32 MiB. Invalid JSON, incomplete metadata, and non-string
translations cause a pack to be ignored. For duplicate IDs, the highest-priority
search location wins.

## Selection and fallback

For `system`, an empty setting, or an unknown regional language, resolve in order:

1. Exact region, such as `pt-BR`.
2. Base language (`pt`), then a validated regional variant of that base.
3. `en-US`.
4. The product fallback, `zh-CN`.

Releases must include English and Chinese. Only a custom or damaged installation
missing both uses the first validated pack to keep the UI usable. Pack selection
is distinct from resolving a missing key through that pack's `fallback` chain.

## Adding a language or text

1. Copy `en-US.json` and change the filename and metadata.
2. Translate values in `translations` and `context_translations`; preserve keys.
3. Untranslated keys can temporarily be absent and use the fallback pack.
4. Put the pack in the source `languages/` directory; the build copies it to output.
5. Select it in Settings and inspect menus, Dock titles, and the settings page.

For new UI text, add the same stable key to both English and Chinese and bind the
actual location with `bindText`, `bindToolTip`, `bindPlaceholder`, `bindSuffix`,
`bindTab`, `bindTabToolTip`, `bindComboBoxItem`, `bindWindowTitle`, or `contextText`.
Preserve the historical Chinese source fallback. Fallback text in code is for a
missing/damaged pack, not a substitute for a translation entry.

Translate complete strings at their original location. Never substitute pieces
of translated strings globally: this can corrupt a language name or reinterpret
a `Debug` log level. Language names should have independent keys such as
`language.name.zh-CN`.

## Validation

Edit existing packs at individual keys; do not serialize the entire file again.
The audit extracts user-visible C++/UI text and checks both languages for keys,
placeholders, and line breaks. Legacy `source_translations` does not establish
correctness.

```powershell
uv run --python 3.12 python tools/check.py --check i18n
```

`tools/i18n_language_pack.py sync` produces a source-string report and does not
rewrite packs. Release builds run the audit before compilation. The temporary
diagnostic option `/p:KswordSkipI18nAudit=true` must not be used for submission
validation. Enter translations deliberately; do not batch-replace source strings
or automatically rewrite UI packs.
