#!/usr/bin/env python3
"""
Ksword win32k PDB deep directory generator.

Purpose:
- Reads public types, enums, and public symbols from the local win32k / win32kbase / win32kfull PDB cache;
- Prepares a publishable offline fact library for R0 read-only auditing of windows, GUI threads, hotkeys, hooks, and Desktop/Session;
- Explicitly record the capability gap when public PDBs lack private structures: tagWND, tagTHREADINFO, tagQ, tagHOOK, tagHOTKEY, tagTIMER, tagEVENTHOOK.

Boundary:
- Read-only PDB file: no symbol downloading, no driver access, no program execution.
- The section:offset in public symbols is not the final RVA; R0 must combine it with the loaded PE section table and perform PDB/PE identity validation before use.
- When there are no private structure fields, output only missingPrivateTypes without fabricating offsets.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

# Reuse the TPI parser from the ntos generator to avoid duplicating a fragile PDB text parsing logic.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ksword_ntos_pdb_deep_offsets import (  # noqa: E402
    build_flat_rows,
    build_type_info,
    extract_type_fields,
    parse_summary,
    run_pdbutil,
    split_type_records,
)

DEFAULT_LLVM_PDBUTIL = r"D:\Software\VS\VC\Tools\Llvm\x64\bin\llvm-pdbutil.exe"
DEFAULT_OUTPUT_DIR = r"D:\Temp\ksword_pdb_deep_offsets"
DEFAULT_REPO_JSON = str(
    Path(__file__).resolve().parents[2]
    / "apps/desktop/profiles/pdb_deep_offsets/win32k_gui_public_7bd3_a8a6_2d74_deep_offsets.json"
)

DEFAULT_PDBS = [
    r"E:\KswordPDB\PDB\pdb-cache\amd64\win32k.pdb\7BD3B4D17A3C35551C4972B31B8155361\win32k.pdb",
    r"E:\KswordPDB\PDB\pdb-cache\amd64\win32kbase.pdb\A8A69A7FD22B0D044A322341F88A665F1\win32kbase.pdb",
    r"E:\KswordPDB\PDB\pdb-cache\amd64\win32kfull.pdb\2D745AB4CE6186F2D19839B96062ED851\win32kfull.pdb",
]

# P0 GUI private type list: If these types are missing, tagWND/tagQ/Hook/Hotkey runtime reads cannot be declared available.
PRIVATE_GUI_TYPES = [
    "tagWND",
    "tagTHREADINFO",
    "tagQ",
    "tagHOOK",
    "tagHOTKEY",
    "tagTIMER",
    "tagEVENTHOOK",
    "DESKTOPINFO",
    "tagDESKTOP",
    "tagWINDOWSTATION",
]

# These keywords are used to filter structures and enums related to GUI auditing from public types in the PDB.
TYPE_KEYWORDS = [
    "wnd",
    "window",
    "desktop",
    "station",
    "threadinfo",
    "hook",
    "hotkey",
    "timer",
    "input",
    "queue",
    "qmsg",
    "pointer",
    "cursor",
    "caret",
    "clipboard",
    "menu",
    "composition",
    "dwm",
    "monitor",
    "display",
    "dxgk",
    "gdi",
    "user",
]

# Public symbol classification keywords: used to group symbols such as NtUser/NtGdi/xxx/tagWND/Hotkey/Hook.
SYMBOL_GROUP_KEYWORDS: list[tuple[str, list[str]]] = [
    ("window_timer", ["timer", "settimer", "killtimer", "validatetimercallback"]),
    ("event_hook", ["winevent", "eventhook", "wineventhook", "gpeventhooks"]),
    (
        "message_hook",
        [
            "setwindowshook",
            "unhookwindowshook",
            "freehook",
            "gethmodtableindex",
            "callhook",
            "messagehook",
            "hookproc",
            "aatomsysloaded",
            "catomsystableentries",
        ],
    ),
    ("hotkey_hook", ["hotkey", "hook", "unhook", "setwindowshook"]),
    ("window_object", ["tagwnd", "window", "hwnd", "foreground", "focus", "capture", "caret"]),
    ("gui_thread_queue", ["tagthreadinfo", "inputqueue", "thread", "queue", "qmsg"]),
    ("desktop_session", ["desktop", "windowstation", "session", "silo"]),
    ("clipboard_message", ["clipboard", "message", "postmessage", "sendmessage"]),
    ("gdi_display", ["ntgdi", "dxg", "dddi", "display", "monitor", "composition", "dwm"]),
    ("ntuser_api", ["ntuser", "xxx"]),
]

# Runtime detail fields:
# - requiredPrivateTypes: The private GUI layout required before safely reading object fields.
# - usefulPublicSymbolGroups indicates the function/symbol attribution evidence that public PDBs can at least provide;
# - This structure is used to generate runtimeDetailCatalog so that the UI and audit scripts do not only display scattered summaries.
RUNTIME_DETAIL_DOMAINS: dict[str, dict[str, Any]] = {
    "window_detail": {
        "displayName": "Window detail / tagWND",
        "requiredPrivateTypes": ["tagWND", "tagTHREADINFO", "tagQ"],
        "usefulPublicSymbolGroups": ["window_object", "gui_thread_queue", "ntuser_api"],
        "intendedUse": "Expand single HWND details, window cross-view, and focus/capture/caret attribution.",
    },
    "gui_thread_detail": {
        "displayName": "GUI thread / tagTHREADINFO + tagQ",
        "requiredPrivateTypes": ["tagTHREADINFO", "tagQ"],
        "usefulPublicSymbolGroups": ["gui_thread_queue", "window_object", "ntuser_api"],
        "intendedUse": "Expand the GUI thread table, input queue, and active window relationships.",
    },
    "hotkey_detail": {
        "displayName": "Hotkey table / tagHOTKEY",
        "requiredPrivateTypes": ["tagHOTKEY", "tagWND", "tagTHREADINFO"],
        "usefulPublicSymbolGroups": ["hotkey_hook", "window_object", "gui_thread_queue"],
        "intendedUse": "Expand the hotkey object, window, and thread ownership fields in the hotkey table.",
    },
    "hook_detail": {
        "displayName": "Hook chain / tagHOOK",
        "requiredPrivateTypes": ["tagHOOK", "tagTHREADINFO", "DESKTOPINFO"],
        "usefulPublicSymbolGroups": ["message_hook", "gui_thread_queue", "desktop_session"],
        "intendedUse": "Expand Hook chain, process address, target thread, and desktop ownership fields.",
    },
    "timer_detail": {
        "displayName": "Window timer / tagTIMER",
        "requiredPrivateTypes": ["tagTIMER", "tagTHREADINFO", "tagWND"],
        "usefulPublicSymbolGroups": ["window_timer", "gui_thread_queue", "window_object", "ntuser_api"],
        "intendedUse": "Expand window timer object, interval, flags, callback, window, and thread affiliation fields.",
    },
    "event_hook_detail": {
        "displayName": "WinEvent hook / tagEVENTHOOK",
        "requiredPrivateTypes": ["tagEVENTHOOK", "tagTHREADINFO"],
        "usefulPublicSymbolGroups": ["event_hook", "hotkey_hook", "gui_thread_queue"],
        "intendedUse": "Expand WinEvent Hook chain, event scope, callback, module, and target thread affiliation fields.",
    },
    "desktop_session_detail": {
        "displayName": "Desktop / WindowStation / Session",
        "requiredPrivateTypes": ["tagDESKTOP", "tagWINDOWSTATION"],
        "usefulPublicSymbolGroups": ["desktop_session", "window_object", "ntuser_api"],
        "intendedUse": "Expand desktop, window station, and Session readiness auditing.",
    },
}

# If a private PDB becomes available, these aliases will map fields directly to the win32k offset structure names in shared/driver.
WIN32K_FIELD_ALIASES: dict[tuple[str, str], str] = {
    ("tagWND", "pti"): "tagWndThreadInfo",
    ("tagWND", "spwndParent"): "tagWndParent",
    ("tagWND", "spwndOwner"): "tagWndOwner",
    ("tagWND", "style"): "tagWndStyle",
    ("tagWND", "ExStyle"): "tagWndExStyle",
    ("tagWND", "rcWindow"): "tagWndRect",
    ("tagWND", "rcClient"): "tagWndClientRect",
    ("tagWND", "pcls"): "tagWndClass",
    ("tagWND", "strName"): "tagWndTitle",
    ("tagTHREADINFO", "pq"): "tagThreadInfoQueue",
    ("tagTHREADINFO", "rpdesk"): "tagThreadInfoDesktop",
    ("tagTHREADINFO", "aphkStart"): "tagThreadInfoHookArray",
    ("tagTHREADINFO", "pDeskInfo"): "tagThreadInfoDesktopInfo",
    ("tagTHREADINFO", "pdi"): "tagThreadInfoDesktopInfo",
    ("DESKTOPINFO", "aphkStart"): "desktopInfoHookArray",
    ("tagDESKTOPINFO", "aphkStart"): "desktopInfoHookArray",
    ("tagQ", "spwndActive"): "tagQActiveWindow",
    ("tagQ", "spwndFocus"): "tagQFocusWindow",
    ("tagQ", "spwndCapture"): "tagQCaptureWindow",
    ("tagQ", "spwndCaret"): "tagQCaretWindow",
    ("tagHOOK", "phkNext"): "tagHookNext",
    ("tagHOOK", "head"): "tagHookHandleHeader",
    ("tagHOOK", "pti"): "tagHookOwnerThreadInfo",
    ("tagHOOK", "rpdesk"): "tagHookDesktop",
    ("tagHOOK", "iHook"): "tagHookType",
    ("tagHOOK", "offPfn"): "tagHookProcedure",
    ("tagHOOK", "flags"): "tagHookFlags",
    ("tagHOOK", "ihmod"): "tagHookModuleId",
    ("tagHOOK", "ptiHooked"): "tagHookTargetThreadInfo",
    ("tagHOTKEY", "phkNext"): "hotkeyNext",
    ("tagHOTKEY", "pti"): "hotkeyThreadInfo",
    ("tagHOTKEY", "spwnd"): "hotkeyWindow",
    ("tagHOTKEY", "fsModifiers"): "hotkeyModifiers",
    ("tagHOTKEY", "vk"): "hotkeyVirtualKey",
    ("tagHOTKEY", "id"): "hotkeyId",
    ("tagTIMER", "pti"): "timerPrimaryThreadInfo",
    ("tagTIMER", "pfn"): "timerCallback",
    ("tagTIMER", "cmsCountdown"): "timerCountdown",
    ("tagTIMER", "cmsTolerance"): "timerTolerance",
    ("tagTIMER", "flags"): "timerFlags",
    ("tagTIMER", "cmsRate"): "timerInterval",
    ("tagTIMER", "spwnd"): "timerWindow",
    ("tagTIMER", "nID"): "timerId",
    ("tagTIMER", "ptiCreator"): "timerAlternateThreadInfo",
    ("tagTIMER", "leHash"): "timerHashListEntry",
    ("tagTIMER", "dwTime"): "timerTimestamp",
    ("tagEVENTHOOK", "hEventHook"): "eventHookHandle",
    ("tagEVENTHOOK", "pti"): "eventHookOwnerThreadInfo",
    ("tagEVENTHOOK", "phkNext"): "eventHookNext",
    ("tagEVENTHOOK", "eventMin"): "eventHookEventMin",
    ("tagEVENTHOOK", "eventMax"): "eventHookEventMax",
    ("tagEVENTHOOK", "dwFlags"): "eventHookFlags",
    ("tagEVENTHOOK", "idProcess"): "eventHookTargetProcessId",
    ("tagEVENTHOOK", "idThread"): "eventHookTargetThreadId",
    ("tagEVENTHOOK", "offPfn"): "eventHookCallbackOffset",
    ("tagEVENTHOOK", "atomMod"): "eventHookModuleAtom",
    ("tagEVENTHOOK", "timeLast"): "eventHookTimestamp",
}

# Stable aliases mapping public symbol names to Ksword runtime project names. Section:offset still requires combination with
# Precise PE identity conversion: do not treat public PDB records directly as RVAs.
WIN32K_PUBLIC_SYMBOL_ALIASES: dict[str, str] = {
    "aatomSysLoaded": "messageHookModuleAtomTable",
    "catomSysTableEntries": "messageHookModuleAtomCount",
}

# The version layout actually used by the current Win32 message hook enumerator. This stores the Windows version and
# PE/PDB identity and RVA, used for offline auditing, matrix expansion, and pre-release comparison. At runtime, perform precise checks first.
# PE identity matching; if missing, selects the most recent table entry not exceeding the current system version based on windowsVersion.
VALIDATED_MESSAGE_HOOK_PROFILES: list[dict[str, Any]] = [
    {
        "profileId": "message_hook_a8a6_2d74_v1",
        "source": "validated_disassembly",
        "windowsVersion": {
            "major": 10,
            "minor": 0,
            "build": 19041,
            "revision": 6456,
            "text": "10.0.19041.6456",
        },
        "moduleIdentities": {
            "win32kbase.sys": {
                "timeDateStamp": 0x8FC48444,
                "timeDateStampHex": "0x8FC48444",
                "imageSize": 0x002D6000,
                "imageSizeHex": "0x002D6000",
                "pdbName": "win32kbase.pdb",
                "pdbGuid": "A8A69A7F-D22B-0D04-4A32-2341F88A665F",
                "pdbAge": 1,
                "pdbGuidAge": "A8A69A7FD22B0D044A322341F88A665F1",
            },
            "win32kfull.sys": {
                "timeDateStamp": 0x83C73BE4,
                "timeDateStampHex": "0x83C73BE4",
                "imageSize": 0x003B4000,
                "imageSizeHex": "0x003B4000",
                "pdbName": "win32kfull.pdb",
                "pdbGuid": "2D745AB4-CE61-86F2-D198-39B96062ED85",
                "pdbAge": 1,
                "pdbGuidAge": "2D745AB4CE6186F2D19839B96062ED851",
            },
        },
        "hookTypeRange": {
            "minimum": -1,
            "maximum": 14,
            "arrayIndexExpression": "hookType + 1",
            "arrayElementCount": 16,
        },
        "layouts": {
            "tagHOOK": {
                "size": 0x60,
                "sizeHex": "0x60",
                "fields": {
                    "handle": {"offset": 0x00, "offsetHex": "0x00"},
                    "ownerThreadInfo": {"offset": 0x10, "offsetHex": "0x10"},
                    "desktopObject": {"offset": 0x18, "offsetHex": "0x18"},
                    "nextHook": {"offset": 0x28, "offsetHex": "0x28"},
                    "hookType": {"offset": 0x30, "offsetHex": "0x30"},
                    "procedureOffset": {"offset": 0x38, "offsetHex": "0x38"},
                    "flags": {"offset": 0x40, "offsetHex": "0x40"},
                    "moduleId": {"offset": 0x44, "offsetHex": "0x44"},
                    "targetThreadInfo": {"offset": 0x48, "offsetHex": "0x48"},
                },
            },
            "tagTHREADINFO": {
                "fields": {
                    "desktopInfo": {"offset": 0x1D0, "offsetHex": "0x1D0"},
                    "aphkStart": {"offset": 0x390, "offsetHex": "0x390"},
                },
            },
            "DESKTOPINFO": {
                "fields": {
                    "aphkStart": {"offset": 0x28, "offsetHex": "0x28"},
                },
            },
        },
        "moduleAtomTable": {
            "moduleName": "win32kfull.sys",
            "tableSymbol": "aatomSysLoaded",
            "tableRva": 0x003391D0,
            "tableRvaHex": "0x003391D0",
            "countSymbol": "catomSysTableEntries",
            "countRva": 0x00339310,
            "countRvaHex": "0x00339310",
        },
        "disassemblyEvidence": [
            {"symbol": "NtUserSetWindowsHookEx", "rva": 0x0001FB00, "rvaHex": "0x0001FB00", "coreRva": 0x0001FC48, "coreRvaHex": "0x0001FC48"},
            {"symbol": "FreeHook", "rva": 0x0001FF90, "rvaHex": "0x0001FF90"},
            {"symbol": "GetHmodTableIndex", "rva": 0x000203EC, "rvaHex": "0x000203EC"},
        ],
    },
]

PUBLIC_HEADER_RE = re.compile(r"^\s*(?P<record>\d+)\s+\|\s+S_PUB32\s+\[size\s*=\s*(?P<size>\d+)\]\s+`(?P<name>[^`]+)`")
PUBLIC_DETAIL_RE = re.compile(r"flags\s*=\s*(?P<flags>[^,]+),\s*addr\s*=\s*(?P<section>[0-9A-Fa-f]+):(?P<offset>[0-9A-Fa-f]+)")
RECORD_COUNT_RE = re.compile(r"Showing\s+([0-9,]+)\s+records")


def parse_record_count(text: str) -> int:
    """Parse 'Showing N records' from llvm-pdbutil output."""
    match = RECORD_COUNT_RE.search(text)
    if not match:
        return -1
    return int(match.group(1).replace(",", ""))


def classify_text(text: str, fallback: str) -> str:
    """Coarsely group type names or symbol names for GUI audit purposes."""
    lowered = text.lower()
    for group_name, keywords in SYMBOL_GROUP_KEYWORDS:
        if any(keyword in lowered for keyword in keywords):
            return group_name
    return fallback


def is_interesting_type(type_name: str) -> bool:
    """Determine if a public type is worth entering the win32k GUI fact library."""
    lowered = type_name.lower()
    return any(keyword in lowered for keyword in TYPE_KEYWORDS)


def resolve_public_symbol_alias(symbol_name: str) -> str:
    """Parses stable aliases for plain or MSVC-decorated public symbols."""
    direct_alias = WIN32K_PUBLIC_SYMBOL_ALIASES.get(symbol_name)
    if direct_alias:
        return direct_alias
    lowered = symbol_name.lower()
    for source_name, alias_name in WIN32K_PUBLIC_SYMBOL_ALIASES.items():
        if source_name.lower() in lowered:
            return alias_name
    return ""


def apply_win32k_aliases(target: dict[str, Any]) -> None:
    """Add Ksword win32k offset aliases for future private PDB fields."""
    type_name = str(target.get("typeName", ""))
    for field_entry in target.get("fields", []):
        if not isinstance(field_entry, dict):
            continue
        alias = WIN32K_FIELD_ALIASES.get((type_name, str(field_entry.get("name", ""))))
        if alias:
            field_entry["kswordItemName"] = alias


def parse_public_symbols(publics_text: str, module_name: str) -> list[dict[str, Any]]:
    """Parse public symbols and retain only GUI audit-related names."""
    rows: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    for line in publics_text.splitlines():
        header = PUBLIC_HEADER_RE.match(line)
        if header:
            if pending is not None:
                rows.append(pending)
            pending = {
                "moduleName": module_name,
                "record": int(header.group("record")),
                "recordSize": int(header.group("size")),
                "name": header.group("name"),
                "kswordItemName": resolve_public_symbol_alias(header.group("name")),
                "group": classify_text(header.group("name"), "other_public"),
                "flags": "",
                "section": "",
                "offset": 0,
                "offsetHex": "",
                "sectionOffset": "",
            }
            continue
        if pending is not None:
            detail = PUBLIC_DETAIL_RE.search(line)
            if detail:
                pending["flags"] = detail.group("flags").strip()
                pending["section"] = detail.group("section")
                pending["offset"] = int(detail.group("offset"), 10)
                pending["offsetHex"] = f"0x{pending['offset']:08X}"
                pending["sectionOffset"] = f"{pending['section']}:{int(detail.group('offset'), 10):08d}"
    if pending is not None:
        rows.append(pending)

    filtered = []
    for row in rows:
        name = str(row.get("name", ""))
        lowered = name.lower()
        if row.get("group") != "other_public" or "ntuser" in lowered or "ntgdi" in lowered or "tagwnd" in lowered:
            filtered.append(row)
    filtered.sort(key=lambda item: (str(item.get("group", "")), str(item.get("name", ""))))
    return filtered


def extract_module_catalog(pdbutil_path: str, pdb_path: Path, cache_dir: Path) -> dict[str, Any]:
    """Extract type, enumeration, and public symbol directories for a single win32k-family PDB."""
    module_name = pdb_path.name
    started = time.time()
    summary_text = run_pdbutil(pdbutil_path, pdb_path, "-summary", timeout=120)
    summary = parse_summary(summary_text, pdb_path)

    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_stem = f"{module_name}_{str(summary.get('pdbGuid', '')).replace('-', '').lower()}_age{summary.get('pdbAge', 0)}"
    types_cache = cache_dir / f"{cache_stem}_types.txt"
    publics_cache = cache_dir / f"{cache_stem}_publics.txt"

    if types_cache.exists():
        types_text = types_cache.read_text(encoding="utf-8", errors="replace")
    else:
        types_text = run_pdbutil(pdbutil_path, pdb_path, "-types", timeout=900)
        types_cache.write_text(types_text, encoding="utf-8")

    if publics_cache.exists():
        publics_text = publics_cache.read_text(encoding="utf-8", errors="replace")
    else:
        publics_text = run_pdbutil(pdbutil_path, pdb_path, "-publics", timeout=900)
        publics_cache.write_text(publics_text, encoding="utf-8")

    records = split_type_records(types_text)
    type_infos = build_type_info(records)
    selected_names = sorted({info.name for info in type_infos.values() if info.name and not info.forward_ref and is_interesting_type(info.name)})

    targets: list[dict[str, Any]] = []
    selected_but_missing_fields: list[str] = []
    for type_name in selected_names:
        group_name = classify_text(type_name, "public_gui_type")
        extracted = extract_type_fields(type_name, group_name, type_infos, records)
        if extracted is None:
            selected_but_missing_fields.append(type_name)
            continue
        extracted["moduleName"] = module_name
        apply_win32k_aliases(extracted)
        targets.append(extracted)

    private_present = sorted({name for name in PRIVATE_GUI_TYPES if any(info.name == name and not info.forward_ref for info in type_infos.values())})
    private_missing = [name for name in PRIVATE_GUI_TYPES if name not in private_present]
    flat_rows = build_flat_rows(targets)
    for row in flat_rows:
        row["moduleName"] = module_name
    alias_rows = [row for row in flat_rows if row.get("kswordItemName")]
    public_symbols = parse_public_symbols(publics_text, module_name)
    public_alias_symbols = [symbol for symbol in public_symbols if symbol.get("kswordItemName")]

    public_groups: dict[str, int] = {}
    for symbol in public_symbols:
        public_groups[str(symbol.get("group", ""))] = public_groups.get(str(symbol.get("group", "")), 0) + 1

    return {
        "moduleName": module_name,
        "source": summary,
        "stats": {
            "typeRecordCount": len(records),
            "reportedTypeRecordCount": parse_record_count(types_text),
            "selectedTypeCount": len(targets),
            "selectedTypeWithoutFieldListCount": len(selected_but_missing_fields),
            "fieldCount": len(flat_rows),
            "enumValueCount": sum(int(target.get("enumValueCount", 0) or 0) for target in targets),
            "kswordAliasFieldCount": len(alias_rows),
            "publicSymbolCount": len(public_symbols),
            "kswordAliasPublicSymbolCount": len(public_alias_symbols),
            "publicSymbolGroupCounts": public_groups,
            "elapsedSeconds": round(time.time() - started, 3),
        },
        "privateTypeReadiness": {
            "ready": len(private_missing) == 0,
            "presentPrivateTypes": private_present,
            "missingPrivateTypes": private_missing,
            "reason": "private_win32k_types_available" if not private_missing else "public_pdb_does_not_expose_required_gui_private_types",
        },
        "targets": targets,
        "flatFields": flat_rows,
        "kswordAliasFields": alias_rows,
        "kswordAliasPublicSymbols": public_alias_symbols,
        "publicSymbols": public_symbols,
        "selectedTypesWithoutFieldList": selected_but_missing_fields,
        "notes": [
            "The section:offset of publicSymbols needs to be converted using the target PE section table and cannot be directly treated as a runtime RVA.",
            "privateTypeReadiness.ready is false, tagWND/tagTHREADINFO/tagQ/tagHOOK/tagHOTKEY/tagTIMER/tagEVENTHOOK field readback cannot be enabled.",
        ],
    }


def write_combined_csv(path: Path, modules: list[dict[str, Any]]) -> None:
    """Write all modules' flatFields into a single CSV for manual review."""
    rows: list[dict[str, Any]] = []
    for module in modules:
        for row in module.get("flatFields", []):
            if isinstance(row, dict):
                rows.append(row)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "moduleName",
        "group",
        "typeName",
        "typeSize",
        "fieldName",
        "qualifiedName",
        "offset",
        "offsetHex",
        "fieldType",
        "typeId",
        "kswordItemName",
        "runtimeItemId",
        "runtimeItemIdHex",
        "collisionAttempt",
        "bitBaseType",
        "bitOffset",
        "bitSize",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def collect_runtime_public_symbol_examples(
    modules: list[dict[str, Any]],
    group_names: list[str],
    max_examples_per_group: int = 5,
) -> dict[str, list[dict[str, Any]]]:
    """Collect public symbol examples available for runtime details by symbol group.

    Inputs:
    - modules: the win32k-family module catalog returned by extract_module_catalog;
    - group_names: groups of public symbols of interest to the runtime domain;
    - max_examples_per_group: Maximum number of examples to retain per group.
    Processing:
    - Iterate through each module's publicSymbols;
    - Retain only fields required for audit display, such as name, moduleName, sectionOffset, and flags.
    - Limit the number of examples per group to prevent the JSON from being infinitely expanded by public symbol examples.
    Returns:
    - dict[groupName] -> list of examples; groups without evidence return an empty list
    """
    examples_by_group: dict[str, list[dict[str, Any]]] = {group_name: [] for group_name in group_names}
    wanted_groups = set(group_names)
    for module in modules:
        module_name = str(module.get("moduleName", ""))
        for symbol in module.get("publicSymbols", []):
            if not isinstance(symbol, dict):
                continue
            group_name = str(symbol.get("group", ""))
            if group_name not in wanted_groups:
                continue
            group_examples = examples_by_group.setdefault(group_name, [])
            if len(group_examples) >= max_examples_per_group:
                continue
            group_examples.append({
                "moduleName": module_name,
                "name": symbol.get("name", ""),
                "sectionOffset": symbol.get("sectionOffset", ""),
                "flags": symbol.get("flags", ""),
            })
    return examples_by_group


def build_runtime_detail_catalog(modules: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate the win32k runtime details domain readiness directory.

    Inputs:
    - modules: directories for all win32k, win32kbase, and win32kfull modules.
    Processing:
    - Summarize private GUI types present per module, missing types, and public symbol group counts.
    - Check if the window/gui-thread/hotkey/hook/event-hook/desktop domains have field read conditions based on RUNTIME_DETAIL_DOMAINS;
    - Provides group counts and representative symbols for symbols available in public PDBs, to display detailed content in the UI details page.
    Returns:
    - JSON-serializable directory; when ready=false, blockedBy explicitly indicates missing private layout.
    """
    present_private_types: set[str] = set()
    missing_by_module: dict[str, list[str]] = {}
    public_group_counts: dict[str, int] = {}
    field_counts_by_private_type: dict[str, int] = {type_name: 0 for type_name in PRIVATE_GUI_TYPES}

    for module in modules:
        module_name = str(module.get("moduleName", ""))
        readiness = module.get("privateTypeReadiness", {})
        if isinstance(readiness, dict):
            for type_name in readiness.get("presentPrivateTypes", []):
                present_private_types.add(str(type_name))
            missing_types = [
                str(type_name)
                for type_name in readiness.get("missingPrivateTypes", [])
            ] if isinstance(readiness.get("missingPrivateTypes", []), list) else []
            if missing_types:
                missing_by_module[module_name] = missing_types

        stats = module.get("stats", {})
        if isinstance(stats, dict) and isinstance(stats.get("publicSymbolGroupCounts", {}), dict):
            for group_name, count_value in stats["publicSymbolGroupCounts"].items():
                try:
                    public_group_counts[str(group_name)] = public_group_counts.get(str(group_name), 0) + int(count_value)
                except (TypeError, ValueError):
                    continue

        for target in module.get("targets", []):
            if not isinstance(target, dict):
                continue
            type_name = str(target.get("typeName", ""))
            if type_name in field_counts_by_private_type:
                field_counts_by_private_type[type_name] += int(target.get("fieldCount", 0) or 0)

    domains: dict[str, dict[str, Any]] = {}
    ready_domain_count = 0
    for domain_id, domain_definition in RUNTIME_DETAIL_DOMAINS.items():
        required_types = [str(item) for item in domain_definition.get("requiredPrivateTypes", [])]
        symbol_groups = [str(item) for item in domain_definition.get("usefulPublicSymbolGroups", [])]
        missing_types = [type_name for type_name in required_types if type_name not in present_private_types]
        ready = not missing_types
        if ready:
            ready_domain_count += 1

        public_examples = collect_runtime_public_symbol_examples(modules, symbol_groups)
        concrete_field_count = sum(field_counts_by_private_type.get(type_name, 0) for type_name in required_types)
        domain_group_counts = {
            group_name: public_group_counts.get(group_name, 0)
            for group_name in symbol_groups
        }
        domains[domain_id] = {
            "displayName": domain_definition.get("displayName", domain_id),
            "ready": ready,
            "requiredPrivateTypes": required_types,
            "presentPrivateTypes": [type_name for type_name in required_types if type_name in present_private_types],
            "missingPrivateTypes": missing_types,
            "concreteFieldCount": concrete_field_count,
            "publicSymbolGroups": domain_group_counts,
            "publicSymbolExamples": public_examples,
            "publicEvidenceAvailable": any(count > 0 for count in domain_group_counts.values()),
            "blockedBy": ""
            if ready
            else "missing private win32k GUI layout types: " + ", ".join(missing_types),
            "intendedUse": domain_definition.get("intendedUse", ""),
        }

    return {
        "schemaVersion": 1,
        "ready": ready_domain_count == len(RUNTIME_DETAIL_DOMAINS),
        "readyDomainCount": ready_domain_count,
        "blockedDomainCount": len(RUNTIME_DETAIL_DOMAINS) - ready_domain_count,
        "presentPrivateTypes": sorted(present_private_types),
        "missingPrivateTypesByModule": missing_by_module,
        "publicSymbolGroupCounts": public_group_counts,
        "domains": domains,
        "notes": [
            "ready=false does not mean public PDBs are valueless; public symbol examples can still be used for UI attribution and audit explanation.",
            "Only when all requiredPrivateTypes exist can R0 promote the corresponding runtime detail fields from readiness to field read.",
        ],
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Extract win32k-family public PDB GUI audit catalogs.")
    parser.add_argument("--llvm-pdbutil", default=DEFAULT_LLVM_PDBUTIL, help="llvm-pdbutil executable path")
    parser.add_argument("--pdb", action="append", default=[], help="win32k-family PDB path; can be repeated")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="directory for JSON/CSV output")
    parser.add_argument("--json-name", default="win32k_gui_public_deep_offsets.json", help="JSON output file name")
    parser.add_argument("--csv-name", default="win32k_gui_public_deep_offsets.csv", help="CSV output file name")
    parser.add_argument("--repo-json", default=DEFAULT_REPO_JSON, help="optional repository JSON output path")
    parser.add_argument("--cache-dir", default=r"D:\Temp\ksword_pdb_deep_offsets\win32k_cache", help="raw pdbutil cache directory")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Main entry: Generate win32k-family deep/public catalog JSON."""
    args = parse_args(argv)
    pdbutil_path = str(Path(args.llvm_pdbutil))
    if not Path(pdbutil_path).exists():
        print(f"llvm-pdbutil not found: {pdbutil_path}", file=sys.stderr)
        return 2

    pdb_paths = [Path(item) for item in (args.pdb or DEFAULT_PDBS)]
    missing_paths = [str(path) for path in pdb_paths if not path.exists()]
    if missing_paths:
        print("PDB not found: " + "; ".join(missing_paths), file=sys.stderr)
        return 2

    started = time.time()
    cache_dir = Path(args.cache_dir)
    modules = [extract_module_catalog(pdbutil_path, pdb_path, cache_dir) for pdb_path in pdb_paths]
    all_fields = sum(int(module.get("stats", {}).get("fieldCount", 0) or 0) for module in modules)
    all_aliases = sum(int(module.get("stats", {}).get("kswordAliasFieldCount", 0) or 0) for module in modules)
    all_symbols = sum(int(module.get("stats", {}).get("publicSymbolCount", 0) or 0) for module in modules)
    missing_private: dict[str, list[str]] = {}
    for module in modules:
        readiness = module.get("privateTypeReadiness", {})
        if isinstance(readiness, dict) and not readiness.get("ready", False):
            missing_private[str(module.get("moduleName", ""))] = list(readiness.get("missingPrivateTypes", []))
    runtime_detail_catalog = build_runtime_detail_catalog(modules)

    result = {
        "schemaVersion": 1,
        "kind": "KswordWin32kDeepOffsetLibrary",
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "generator": "tools/pdb_offset_generator/ksword_win32k_pdb_deep_offsets.py",
        "stats": {
            "moduleCount": len(modules),
            "fieldCount": all_fields,
            "kswordAliasFieldCount": all_aliases,
            "publicSymbolCount": all_symbols,
            "privateTypeReady": not missing_private,
            "elapsedSeconds": round(time.time() - started, 3),
        },
        "missingPrivateTypesByModule": missing_private,
        "runtimeDetailCatalog": runtime_detail_catalog,
        "runtimeProfileSelectionPolicy": {
            "exactMatch": "win32kbase/win32kfull TimeDateStamp+SizeOfImage pair",
            "missingExactMatch": "nearest previous windowsVersion from the same layout domain",
            "futureProfilesRejected": True,
            "peTimestampOrdering": False,
            "reason": "Modern Windows PE timestamps may be reproducible-build hashes and are not chronological.",
        },
        "validatedMessageHookProfiles": VALIDATED_MESSAGE_HOOK_PROFILES,
        "modules": modules,
        "notes": [
            "Current public win32kbase/win32kfull PDB may report Has Types=true, but TPI dump is actually 0 records; this library will record it faithfully.",
            "tagWND/tagTHREADINFO/tagQ/tagHOOK/tagHOTKEY/tagTIMER/tagEVENTHOOK private structures missing, R0 runtime detail IOCTL can only report readiness, cannot read object fields.",
            "publicSymbols can be used for function symbol extraction and UI attribution; structure field reading still requires private PDB or other verified profile.",
        ],
    }

    output_dir = Path(args.output_dir)
    json_path = output_dir / args.json_name
    csv_path = output_dir / args.csv_name
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_combined_csv(csv_path, modules)

    repo_json = str(args.repo_json).strip()
    if repo_json:
        repo_path = Path(repo_json)
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        repo_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"json={json_path}")
    print(f"csv={csv_path}")
    if repo_json:
        print(f"repoJson={repo_json}")
    print(f"modules={len(modules)} fields={all_fields} aliases={all_aliases} publicSymbols={all_symbols} privateTypeReady={not missing_private}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
