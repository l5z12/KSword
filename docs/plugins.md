# Standalone plugin protocol (v1)

[简体中文](zh-CN/plugins.md) · [Documentation index](README.md)

A plugin is an independent program under `plugin/<plugin-id>/`, not a DLL loaded
into KSword. The GUI reads its manifest, verifies that the entry point stays inside
the plugin directory, and starts it directly with QProcess. It does not route through
KswordCLI or load Python, ONNX Runtime, models, or plugin code into the host process.
Only install trusted plugins: process separation isolates crashes and dependencies,
but a local executable still runs with the current user's privileges.

## Discovery and distribution

```text
plugin/file-analysis/
  plugin.json
  scanner.exe
  scanner.py
  requirements.txt
  Pefile_General_T1.onnx
  features.json
  LICENSE.txt
  NOTICE
```

Search roots in order: `KSWORD_PLUGIN_ROOT`; `plugin/` in the working directory;
then `plugin/` beside the executable and in up to six parent directories.
First-time marketplace installation uses `KSWORD_PLUGIN_ROOT`, or creates
`plugin/` beside the executable, and installs into `<install_directory>`.
Existing roots retain the discovery order above.

Release packages do not bundle third-party plugin payloads. Do not copy models,
Python dependencies, plugin executables, or the plugin directory into Release,
Qt resources, DLLs, or the driver. Marketplace installation happens separately
after the user accepts the plugin's license.

## Manifest

`plugin.json` is a UTF-8 JSON object of at most 64 KiB. Additional plugin-owned
fields are allowed. The host requires or interprets these fields:

| Field | Contract |
| --- | --- |
| `ksword_plugin_api` | String `"1"` |
| `id` | Matches directory name; lowercase ASCII letters, digits, hyphens; at most 64 characters |
| `name`, `version`, `description` | User-visible metadata |
| `plugin_type` | Optional `command` (default), `tab`, or `hybrid` |
| `runtime` | `python` or `executable` |
| `entrypoint` | Relative file inside the plugin; no absolute path or `.`/`..` segments |
| `default_command` | Default subcommand, without path traversal |
| `targets` | Command: `file`, `process`, and/or `network`; tab: only `tab`; hybrid: `tab` and at least one command target |
| `visualization` | Optional `scan-table` configuration |
| `tab` | Required for a tab plugin; title, ready event, and startup timeout |

Python runtime discovery tries `KSWORD_PLUGIN_PYTHON`, `python.exe`, then
`py.exe -3`. Declare dependencies in `requirements.txt`; do not require an embedded
host interpreter. Marketplace releases should provide a runnable executable entry
point. Python sources may accompany it; external Python is mainly a development
option or an explicit plugin dependency.

## Command invocation and GUI routes

```text
python.exe <entrypoint> --ksword-plugin scan -- <plugin-arguments...>
<entrypoint> --ksword-plugin <default-command> -- <plugin-arguments...>
```

The host passes arguments after `--` unchanged, including plugin `--help`.
Command-mode plugins are noninteractive: no stdin prompt, GUI, or human banner on
stdout. GUI menus are generated from the manifest as **Plugins → plugin name**:

- File manager: one selected regular file; `--target-kind file --path <selected-file>`.
- Process details: the Plugins page; `--target-kind process --pid <pid> --path <image-path> --process-name <name>`.
- Network monitoring: the control bar; `--target-kind network`. The plugin captures
  traffic itself; the host does not feed packets through stdin.
- Plugin manager: rescan, read manifest details, open directories, and install from the marketplace.

Treat process arguments as context, never as kernel addresses or command payloads.
Missing manifests, entry points, or runtimes produce explicit GUI diagnostics.

## Scan visualization

The host renders standard JSON Lines events using manifest metadata rather than
knowing a plugin's proprietary result fields:

```json
{
  "visualization": {
    "type": "scan-table",
    "title": "File scan",
    "start_event": "scan_started",
    "result_event": "file_result",
    "complete_event": "scan_complete",
    "total_field": "total_files",
    "columns": [
      { "field": "result", "label": "Verdict", "format": "badge", "values": {
        "safe": { "label": "Safe", "tone": "success" },
        "malware": { "label": "Malware", "tone": "danger" },
        "error": { "label": "Error", "tone": "warning" }
      } },
      { "field": "probability", "label": "Probability", "format": "percent" },
      { "field": "path", "label": "Path", "format": "path" },
      { "field": "message", "label": "Details", "format": "text" }
    ],
    "summary": [
      { "field": "total", "label": "Total", "format": "integer" },
      { "field": "safe", "label": "Safe", "format": "integer" },
      { "field": "malware", "label": "Malware", "format": "integer" },
      { "field": "errors", "label": "Errors", "format": "integer" }
    ]
  }
}
```

V1 supports only `scan-table`. Titles are limited to 96 characters, columns to
1–8 entries, and optional summary items to 8. Field/event names begin with an
ASCII letter or underscore and contain only letters, digits, underscore, dot,
and hyphen, with a 64-character limit. The start event supplies `total_field`;
each result adds a row and advances progress; the complete event supplies summary values.

Formats are `text`, `path` (with a full tooltip), `percent` (values in [-1,1] are
multiplied by 100), `integer`, `number`, and `badge`. Badges require a `values`
map to a label and a tone from `success`, `danger`, `warning`, `info`, or `muted`.
The host does not hardcode values such as `safe` or `malware`.

Each event must have the right `protocol`, `plugin_id`, and `event`. Parsing is
incremental. Invalid JSON, protocol/ID mismatches, an error event, or a missing
declared completion event fail the run and appear in Diagnostics. stderr goes
only to diagnostics. Display is limited to 10,000 rows and an unterminated stdout
line to 1 MiB. Users can cancel a running plugin. Without visualization metadata,
the plugin still runs with generic output and diagnostics.

## Native tab plugins

A tab embeds a native child window from an independent process in the host's
Plugins page. The host creates a container, launches the process, verifies a
handshake, and resizes the child; it never loads plugin code.

```json
{
  "ksword_plugin_api": "1",
  "id": "example-tab",
  "name": "Example Tab",
  "version": "1.0.0",
  "description": "An independent tab process.",
  "plugin_type": "tab",
  "runtime": "executable",
  "entrypoint": "ExampleTab.exe",
  "default_command": "tab",
  "targets": ["tab"],
  "tab": { "title": "Example", "ready_event": "tab_ready", "startup_timeout_ms": 15000 }
}
```

A hybrid retains command targets alongside `tab`, with optional `tab.command`
overriding `default_command` for tab launch:

```text
<entrypoint> --ksword-plugin <tab.command-or-default_command> -- --parent-hwnd <decimal-HWND> --host-pid <PID>
```

Verify that the parent belongs to `--host-pid` and create a direct
`WS_CHILD | WS_VISIBLE` child. Send a UTF-8 JSON Lines handshake:

```json
{"protocol":"ksword-plugin/1","plugin_id":"example-tab","event":"tab_ready","hwnd":"123456"}
```

Use a decimal string for HWND to avoid floating-point precision loss. The host
checks `IsWindow`, process ownership, `GetParent`, and `WS_CHILD`. Wrong ownership,
indirect parenting, protocol mismatch, a stdout line over 1 MiB, or timeout rejects
embedding and terminates the plugin. A plugin exit/crash leaves the host running
and provides diagnostics and Retry.

Tab plugins cannot declare `scan-table`. `tab.title` is at most 96 characters;
`ready_event` follows the event-name rules; optional `startup_timeout_ms` is
1000–60000 milliseconds. Recreate the top-level Plugins page or restart to discover
installed/updated tabs.

## Startup theme snapshot

Independent processes cannot inherit Qt palettes/QSS. Plugins may read these
optional startup environment variables; ignoring them does not prevent launch:

| Variable | Value |
| --- | --- |
| `KSWORD_PLUGIN_STYLE_API` | `1` |
| `KSWORD_PLUGIN_THEME` | `dark` or `light` |
| `KSWORD_PLUGIN_COLOR_WINDOW` | Top-level background, `#RRGGBB` |
| `KSWORD_PLUGIN_COLOR_SURFACE` / `SURFACE_ALT` | Main/alternate content background |
| `KSWORD_PLUGIN_COLOR_TEXT_PRIMARY` / `TEXT_SECONDARY` | Primary/secondary text |
| `KSWORD_PLUGIN_COLOR_BORDER` | Border color |
| `KSWORD_PLUGIN_COLOR_ACCENT` / `ON_ACCENT` | Accent and text on accent |

Abbreviated names in the table retain the `KSWORD_PLUGIN_COLOR_` prefix. All color
values use `#RRGGBB`. No particular UI framework is required. Reopen or retry after
a host theme change to obtain a fresh snapshot.

## Marketplace and results

The manager asynchronously reads the public `KSwordDEV/Plugins` catalog. Its root
has `ksword_plugin_marketplace_api: "1"`. Entries require `id`, `name`, `version`,
`description`, `targets`, `install_directory`, `archive_url`, `sha256`, `license_name`,
and `license_url`. Download/license URLs must use HTTPS on `raw.githubusercontent.com`;
the ZIP needs a 64-digit SHA-256.

Installation first downloads and displays the entire license. Only after explicit
acceptance does it request the ZIP. A checksum mismatch prevents extraction/writing.
After verification, it extracts with Windows PowerShell Expand-Archive into a
staging directory under the plugin root, rechecks the manifest, directory, ID, and
entry point, then replaces the same-ID installation. Failure preserves the old
version and cleans staging. Installed plugins are rescanned after success. ZIPs do
not go into Downloads or the KSword installer. Acceptance is not persisted: each
install/update requires reading and accepting the license again.

Each stdout line contains at least:

```json
{"protocol":"ksword-plugin/1","plugin_id":"example","event":"ready"}
```

The recommended sequence is `ready`, `scan_started`, zero or more `file_result`,
then `scan_complete`. Errors use `event: "error"` with stable `code` and `message`.
Exit 0 means complete, 64 means argument error, 2 means target/environment unavailable;
other nonzero values are plugin-defined and displayed by the host. Results are
never trusted as instructions for R0 operations. A system-changing plugin command
must expose its own explicit operation and policy.

Preserve original LICENSE and NOTICE files at each third-party plugin root and
reference them in its manifest. Ship its models, feature data, dependencies, and
licenses in `KSwordDEV/Plugins`, not this repository or the KSword installer.
`ARK/PYAS-Scanner` is the reference implementation and retains its original
interactive interface alongside this JSON Lines entry point.
