#!/usr/bin/env python3
"""
Ksword DynData pack / deep-offset coverage audit script.

Purpose:
- Read-only check of the ark_dyndata_pack_v4.json bundled with the main GUI;
- Read-only check the ntoskrnl / win32k deep offset libraries in profiles/pdb_deep_offsets;
- Verify whether the 'deep alias' field has been included in the v4 pack's items;
- Record whether the win32k public PDB already contains private GUI layout tags such as tagWND/tagTHREADINFO.
- Output JSON report to help confirm the program does not depend on E: drive PDB cache before release.

Boundary:
- Does not parse PDBs, access drivers, compile, or modify profile packs.
- Reads only JSON files within the repository and writes the audit report to the user-specified location.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROFILE_ROOT = REPO_ROOT / 'apps/desktop/profiles'
DEFAULT_PACK_PATH = DEFAULT_PROFILE_ROOT / "ark_dyndata_pack_v4.json"
DEFAULT_MANIFEST_PATH = DEFAULT_PROFILE_ROOT / "ark_dyndata_manifest.json"
DEFAULT_OUTPUT_PATH = Path(r"D:\Temp\ksword_pdb_deep_offsets\ksword_dyndata_pack_deep_audit.json")
SYMBOL_CACHE_KEY_RE = re.compile(r"^(?P<guid>[0-9A-Fa-f]{32})(?P<age>[0-9A-Fa-f]+)$")
FILENAME_AGE_RE = re.compile(r"_age(?P<age>\d+)_deep_offsets\.json$", re.IGNORECASE)


PROCESS_DETAIL_REQUIRED = [
    "EpUniqueProcessId",
    "EpActiveProcessLinks",
    "EpThreadListHead",
    "EpImageFileName",
    "EpToken",
    "EpObjectTable",
    "EpSectionObject",
    "EpProtection",
    "EpSignatureLevel",
    "EpSectionSignatureLevel",
]

THREAD_DETAIL_REQUIRED = [
    "EtCid",
    "EtThreadListEntry",
    "EtStartAddress",
    "EtWin32StartAddress",
    "KtProcess",
    "KtInitialStack",
    "KtStackLimit",
    "KtStackBase",
    "KtKernelStack",
    "KtReadOperationCount",
    "KtWriteOperationCount",
    "KtOtherOperationCount",
    "KtReadTransferCount",
    "KtWriteTransferCount",
    "KtOtherTransferCount",
]

MODULE_DRIVER_REQUIRED = [
    "KldrInLoadOrderLinks",
    "KldrDllBase",
    "KldrSizeOfImage",
    "KldrFullDllName",
    "KldrBaseDllName",
    "DoDriverStart",
    "DoDriverSize",
    "DoDriverSection",
    "DoMajorFunction",
    "DoDriverUnload",
]

TOKEN_INTEGRITY_REQUIRED = [
    "EpToken",
    "TokUserAndGroupCount",
    "TokUserAndGroups",
    "TokIntegrityLevelIndex",
    "TokMandatoryPolicy",
]


@dataclass(frozen=True)
class PackProfileView:
    """Save a normalized view of a pack profile."""

    profile: dict[str, Any]
    field_names: set[str]
    item_names: set[str]


@dataclass(frozen=True)
class PackProfileMatch:
    """Save matching evidence between a deep library and a pack profile."""

    profile: dict[str, Any]
    match_method: str
    identity_strict: bool
    matched_age: int | None
    identity_notes: tuple[str, ...]


def read_json(path: Path) -> dict[str, Any]:
    """Read JSON file.

    Inputs:
    - path: target JSON path.
    Processing:
    - Reads and parses the object using UTF-8.
    Returns:
    - dict JSON object; raises ValueError if format is invalid.
    """
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"JSON root is not an object: {path}")
    return data


def normalize_guid(value: Any) -> str:
    """Normalize PDB GUID string.

    Inputs:
    - value: The GUID field within the JSON.
    Processing:
    - Remove braces and hyphens, then convert to lowercase.
    Returns:
    - 32-bit hexadecimal text suitable for comparison.
    """
    text = str(value or "").strip().strip("{}")
    return text.replace("-", "").lower()


def optional_int(value: Any) -> int | None:
    """Safely convert JSON numeric fields to int."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def symbol_cache_age_from_path(path_text: str, source_guid: str) -> int | None:
    """Parse GUID and Age from the parent directory of the PDB symbol-cache path.

    Inputs:
    - path_text：deep source.pdbPath；
    - source_guid: Normalized GUID.
    Processing:
    - Check if the parent directory is a 32-character hex GUID followed by a hex age.
    - GUID must match source_guid.
    Returns:
    - The symbol-cache age of the matched entry; otherwise None.
    """
    if not path_text or not source_guid:
        return None
    key_text = Path(path_text).parent.name.strip()
    match = SYMBOL_CACHE_KEY_RE.match(key_text)
    if not match or match.group("guid").lower() != source_guid:
        return None
    try:
        return int(match.group("age"), 16)
    except ValueError:
        return None


def filename_age(deep_path: Path) -> int | None:
    """Parse the age from the _ageN_ segment in the deep JSON filename."""
    match = FILENAME_AGE_RE.search(deep_path.name)
    if not match:
        return None
    return optional_int(match.group("age"))


def add_age_candidate(output: list[dict[str, Any]], method: str, age_value: int | None) -> None:
    """Append deduplicated age candidates.

    Inputs:
    - output: candidate list
    - method: candidate source
    - age_value: candidate age.
    Processing:
    - Ignore None/negative values;
    - For the same age, retain only the first source to ensure priority stability.
    Returns:
    - No return value; directly modifies `output`.
    """
    if age_value is None or age_value < 0:
        return
    for candidate in output:
        if candidate["age"] == age_value:
            return
    output.append({"method": method, "age": age_value})


def deep_identity(deep_library: dict[str, Any], deep_path: Path) -> dict[str, Any]:
    """Extract multi-source PDB identities from the deep library.

    Inputs:
    - deep_library：deep-offset JSON；
    - deep_path: deep JSON path.
    Processing:
    - Runtime matching prioritizes source.pdbAge / symbolCacheAge / the parent directory GUID+Age of pdbPath.
    - Retain pdbSummaryAge and filename age for diagnostics.
    Returns:
    - Dictionary containing guid, ageCandidates, and diagnostic fields.
    """
    source = deep_library.get("source", {})
    if not isinstance(source, dict):
        source = {}
    source_guid = normalize_guid(source.get("pdbGuid"))
    candidates: list[dict[str, Any]] = []
    add_age_candidate(candidates, "source.pdbAge", optional_int(source.get("pdbAge")))
    add_age_candidate(candidates, "source.symbolCacheAge", optional_int(source.get("symbolCacheAge")))
    add_age_candidate(candidates, "source.pdbPath.symbolCacheKey", symbol_cache_age_from_path(str(source.get("pdbPath", "")), source_guid))
    add_age_candidate(candidates, "filename.age", filename_age(deep_path))
    add_age_candidate(candidates, "source.pdbSummaryAge", optional_int(source.get("pdbSummaryAge")))
    return {
        "pdbGuid": source.get("pdbGuid", ""),
        "normalizedPdbGuid": source_guid,
        "pdbAge": optional_int(source.get("pdbAge")),
        "pdbSummaryAge": optional_int(source.get("pdbSummaryAge")),
        "symbolCacheAge": optional_int(source.get("symbolCacheAge")),
        "filenameAge": filename_age(deep_path),
        "identitySource": source.get("identitySource", ""),
        "ageCandidates": candidates,
    }


def deep_library_paths(manifest: dict[str, Any], manifest_path: Path) -> list[Path]:
    """Parse deep-offset library paths from the manifest.

    Inputs:
    - manifest: ark_dyndata_manifest.json object.
    - manifest_path: Path to the manifest file, used for resolving relative paths.
    Processing:
    - Read deepOffsetLibraries[].path.
    Returns:
    - List of actual JSON paths within the repository.
    """
    output: list[Path] = []
    manifest_dir = manifest_path.parent
    for entry in manifest.get("deepOffsetLibraries", []):
        if not isinstance(entry, dict):
            continue
        relative_path = str(entry.get("path", "")).strip()
        if not relative_path:
            continue
        candidate = (manifest_dir.parent / relative_path).resolve()
        if not candidate.exists():
            candidate = (REPO_ROOT / relative_path).resolve()
        output.append(candidate)
    if output:
        return output

    # Earlier release manifests predate deepOffsetLibraries. The deep JSON
    # files are still shipped beside the pack, so discover that canonical
    # profile directory instead of reporting a false missing-library failure.
    deep_directory = manifest_path.parent / "pdb_deep_offsets"
    if not deep_directory.is_dir():
        return []
    return sorted(deep_directory.glob("*_deep_offsets.json"), key=lambda path: path.name.lower())


def build_profile_view(profile: dict[str, Any]) -> PackProfileView:
    """Convert the compact pack profile into an auditable set.

    Inputs:
    - profile: A profile entry within the pack.
    Processing:
    - Directly extracts names from v4 items.
    Returns:
    - PackProfileView, used for override checks.
    """
    item_names: set[str] = set()
    for item in profile.get("items", []):
        if isinstance(item, dict) and str(item.get("name", "")).strip():
            item_names.add(str(item["name"]).strip())

    return PackProfileView(profile=profile, field_names=set(), item_names=item_names)


def find_matching_profiles(pack: dict[str, Any], deep_library: dict[str, Any], deep_path: Path) -> list[PackProfileMatch]:
    """Find pack profiles matching the deep library PDB identity.

    Inputs:
    - pack: ark_dyndata_pack_v4.json object.
    - deep_library: A single deep-offset JSON object.
    Processing:
    - Prioritize using deep source.pdbGuid/pdbAge;
    - Also compatible with source.symbolCacheAge, parent directory GUID+Age of pdbPath, and filename age.
    - Only GUID + candidate age hit counts as strict identity.
    Returns:
    - Matches profile lists and matching evidence.
    """
    identity = deep_identity(deep_library, deep_path)
    source_guid = str(identity.get("normalizedPdbGuid", ""))
    age_candidates = [
        (str(candidate.get("method", "")), optional_int(candidate.get("age")))
        for candidate in identity.get("ageCandidates", [])
        if isinstance(candidate, dict)
    ]

    profiles = [profile for profile in pack.get("profiles", []) if isinstance(profile, dict)]
    matches: list[PackProfileMatch] = []
    seen_ids: set[int] = set()
    for method, source_age_int in age_candidates:
        if source_age_int is None:
            continue
        for profile in profiles:
            if source_guid and normalize_guid(profile.get("pdbGuid")) != source_guid:
                continue
            profile_age = optional_int(profile.get("pdbAge"))
            if profile_age != source_age_int:
                continue
            profile_id = id(profile)
            if profile_id in seen_ids:
                continue
            seen_ids.add(profile_id)
            notes: list[str] = []
            if identity.get("pdbSummaryAge") is not None and identity.get("pdbSummaryAge") != source_age_int:
                notes.append(
                    f"llvm-pdbutil summary age {identity.get('pdbSummaryAge')} differs from matched runtime age {source_age_int}."
                )
            matches.append(PackProfileMatch(
                profile=profile,
                match_method=method,
                identity_strict=True,
                matched_age=source_age_int,
                identity_notes=tuple(notes),
            ))
    if matches:
        return matches

    # Fall back to GUID-only diagnostics when there is no strict match: this does not prove safe runtime matching.
    # But helps locate age source differences in the pack/deep library.
    for profile in pack.get("profiles", []):
        if not isinstance(profile, dict):
            continue
        if source_guid and normalize_guid(profile.get("pdbGuid")) != source_guid:
            continue
        profile_age = optional_int(profile.get("pdbAge"))
        candidate_text = ", ".join(
            f"{method}={age}" for method, age in age_candidates if age is not None
        )
        matches.append(PackProfileMatch(
            profile=profile,
            match_method="guidOnlyAgeMismatch",
            identity_strict=False,
            matched_age=profile_age,
            identity_notes=(f"profile age {profile_age} did not match any deep age candidate: {candidate_text}",),
        ))
    return matches


def required_status(view: PackProfileView, required_names: list[str]) -> dict[str, Any]:
    """Check if a set of required runtime detail fields are present.

    Inputs:
    - view: Normalized view of the pack profile.
    - required_names: Field names required for the functionality.
    Processing:
    - Accepts fields only from v4 items.
    Returns:
    - present/missing/ready ternary state.
    """
    present: list[str] = []
    missing: list[str] = []
    combined = view.field_names | view.item_names
    for name in required_names:
        if name in combined:
            present.append(name)
        else:
            missing.append(name)
    return {
        "ready": not missing,
        "present": present,
        "missing": missing,
    }


def audit_deep_library(pack: dict[str, Any], deep_path: Path, deep_library: dict[str, Any]) -> dict[str, Any]:
    """Audit the coverage relationship between a deep-offset library and the pack.

    Inputs:
    - pack: publish pack.
    - deep_path: deep JSON path.
    - deep_library: the deep JSON object.
    Processing:
    - Count whether aliases match fields/items in the profile.
    - Check the ready status of key fields in process/thread/module details.
    Returns:
    - JSON-serializable audit results.
    """
    alias_rows = [
        row for row in deep_library.get("kswordAliasFields", [])
        if isinstance(row, dict) and str(row.get("kswordItemName", "")).strip()
    ]
    alias_names = sorted({str(row["kswordItemName"]).strip() for row in alias_rows})
    identity = deep_identity(deep_library, deep_path)
    matching_profiles = find_matching_profiles(pack, deep_library, deep_path)

    profile_reports: list[dict[str, Any]] = []
    for profile_match in matching_profiles:
        profile = profile_match.profile
        view = build_profile_view(profile)
        combined_names = view.field_names | view.item_names
        missing_aliases = [name for name in alias_names if name not in combined_names]
        profile_reports.append({
            "profileName": profile.get("profileName", ""),
            "pdbGuid": profile.get("pdbGuid", ""),
            "pdbAge": profile.get("pdbAge", 0),
            "matchMethod": profile_match.match_method,
            "identityStrict": profile_match.identity_strict,
            "matchedAge": profile_match.matched_age,
            "identityNotes": list(profile_match.identity_notes),
            "fieldCount": len(view.field_names),
            "itemCount": len(view.item_names),
            "aliasCount": len(alias_names),
            "presentAliasCount": len(alias_names) - len(missing_aliases),
            "missingAliases": missing_aliases,
            "processDetail": required_status(view, PROCESS_DETAIL_REQUIRED),
            "threadDetail": required_status(view, THREAD_DETAIL_REQUIRED),
            "moduleDriverDetail": required_status(view, MODULE_DRIVER_REQUIRED),
            "tokenIntegrity": required_status(view, TOKEN_INTEGRITY_REQUIRED),
        })

    return {
        "path": str(deep_path),
        "schemaVersion": deep_library.get("schemaVersion"),
        "kind": deep_library.get("kind"),
        "stats": deep_library.get("stats", {}),
        "source": deep_library.get("source", {}),
        "deepIdentity": identity,
        "aliasCount": len(alias_names),
        "aliases": alias_names,
        "matchingProfileCount": len(profile_reports),
        "profiles": profile_reports,
    }


def audit_win32k_deep_library(deep_path: Path, deep_library: dict[str, Any]) -> dict[str, Any]:
    """Audit the availability of the win32k public deep library within the repository.

    Inputs:
    - deep_path: path to the win32k deep-offset JSON
    - deep_library: the parsed JSON object.
    Processing:
    - Aggregate PDB identity, field count, and public symbol count for each win32k* PDB module.
    - Aggregate missing status for private GUI types such as tagWND, tagTHREADINFO, and tagHOOK.
    - Do not match with ntoskrnl dyn-data pack, as the current win32k public library is bypass audit data.
    Returns:
    - JSON-serializable win32k audit results; privateTypeReady=false indicates that runtime object introspection still requires a private layout source.
    """
    stats = deep_library.get("stats", {})
    if not isinstance(stats, dict):
        stats = {}

    missing_by_module = deep_library.get("missingPrivateTypesByModule", {})
    if not isinstance(missing_by_module, dict):
        missing_by_module = {}

    modules: list[dict[str, Any]] = []
    for module in deep_library.get("modules", []):
        if not isinstance(module, dict):
            continue
        source = module.get("source", {})
        if not isinstance(source, dict):
            source = {}
        module_stats = module.get("stats", {})
        if not isinstance(module_stats, dict):
            module_stats = {}
        readiness = module.get("privateTypeReadiness", {})
        if not isinstance(readiness, dict):
            readiness = {}

        module_name = str(module.get("moduleName") or source.get("pdbName") or "").strip()
        modules.append({
            "moduleName": module_name,
            "pdbGuid": source.get("pdbGuid", ""),
            "pdbAge": optional_int(source.get("pdbAge")),
            "pdbSummaryAge": optional_int(source.get("pdbSummaryAge")),
            "symbolCacheAge": optional_int(source.get("symbolCacheAge")),
            "fieldCount": optional_int(module_stats.get("fieldCount")) or 0,
            "enumValueCount": optional_int(module_stats.get("enumValueCount")) or 0,
            "publicSymbolCount": optional_int(module_stats.get("publicSymbolCount")) or 0,
            "privateTypeReady": bool(readiness.get("ready")),
            "missingPrivateTypes": list(readiness.get("missingPrivateTypes", []))
            if isinstance(readiness.get("missingPrivateTypes", []), list)
            else list(missing_by_module.get(module_name, []))
            if isinstance(missing_by_module.get(module_name, []), list)
            else [],
        })

    missing_private_types = sorted({
        str(type_name)
        for type_list in missing_by_module.values()
        if isinstance(type_list, list)
        for type_name in type_list
    })
    private_type_ready = bool(stats.get("privateTypeReady"))
    runtime_catalog = deep_library.get("runtimeDetailCatalog", {})
    if not isinstance(runtime_catalog, dict):
        runtime_catalog = {}

    runtime_domains: list[dict[str, Any]] = []
    domains_object = runtime_catalog.get("domains", {})
    if isinstance(domains_object, dict):
        for domain_id, domain_value in domains_object.items():
            if not isinstance(domain_value, dict):
                continue
            runtime_domains.append({
                "domainId": str(domain_id),
                "displayName": domain_value.get("displayName", str(domain_id)),
                "ready": bool(domain_value.get("ready")),
                "requiredPrivateTypes": list(domain_value.get("requiredPrivateTypes", []))
                if isinstance(domain_value.get("requiredPrivateTypes", []), list)
                else [],
                "missingPrivateTypes": list(domain_value.get("missingPrivateTypes", []))
                if isinstance(domain_value.get("missingPrivateTypes", []), list)
                else [],
                "concreteFieldCount": optional_int(domain_value.get("concreteFieldCount")) or 0,
                "publicEvidenceAvailable": bool(domain_value.get("publicEvidenceAvailable")),
                "publicSymbolGroups": domain_value.get("publicSymbolGroups", {})
                if isinstance(domain_value.get("publicSymbolGroups", {}), dict)
                else {},
                "blockedBy": domain_value.get("blockedBy", ""),
                "intendedUse": domain_value.get("intendedUse", ""),
            })

    runtime_domains.sort(key=lambda item: str(item.get("domainId", "")))
    ready_domain_count = sum(1 for item in runtime_domains if item.get("ready"))
    blocked_domain_count = len(runtime_domains) - ready_domain_count

    return {
        "path": str(deep_path),
        "schemaVersion": deep_library.get("schemaVersion"),
        "kind": deep_library.get("kind"),
        "stats": stats,
        "moduleCount": len(modules),
        "modules": modules,
        "privateTypeReady": private_type_ready,
        "runtimeDetailReady": bool(runtime_catalog.get("ready")) if runtime_catalog else private_type_ready,
        "runtimeDetailCatalogPresent": bool(runtime_catalog),
        "runtimeReadyDomainCount": (optional_int(runtime_catalog.get("readyDomainCount")) or ready_domain_count)
        if runtime_catalog else ready_domain_count,
        "runtimeBlockedDomainCount": (optional_int(runtime_catalog.get("blockedDomainCount")) or blocked_domain_count)
        if runtime_catalog else blocked_domain_count,
        "runtimeDomains": runtime_domains,
        "missingPrivateTypes": missing_private_types,
        "missingPrivateTypesByModule": missing_by_module,
        "runtimeDetailBlockedBy": ""
        if (bool(runtime_catalog.get("ready")) if runtime_catalog else private_type_ready)
        else "public win32k PDB cache does not expose private GUI object layouts such as tagWND/tagTHREADINFO.",
    }


def build_report(pack_path: Path, manifest_path: Path) -> dict[str, Any]:
    """Build the complete audit report.

    Inputs:
    - pack_path：ark_dyndata_pack_v4.json。
    - manifest_path：ark_dyndata_manifest.json。
    Processing:
    - Read pack, manifest, and deep libraries;
    - Aggregates errors, warnings, and the coverage status for each deep library.
    Returns:
    - JSON report object.
    """
    pack = read_json(pack_path)
    manifest = read_json(manifest_path)
    deep_paths = deep_library_paths(manifest, manifest_path)

    errors: list[str] = []
    warnings: list[str] = []
    incomplete: list[str] = []
    libraries: list[dict[str, Any]] = []

    if int(pack.get("packVersion", 0) or 0) != 4:
        errors.append("ark_dyndata_pack_v4.json packVersion must be 4.")
    if "fieldDictionary" in pack:
        errors.append("v4 pack must not contain fieldDictionary.")
    legacy_keys = {"fields", "legacyItems", "callbackItems", "typedItems"}
    legacy_key_profile_count = sum(
        any(key in profile for key in legacy_keys)
        for profile in pack.get("profiles", [])
        if isinstance(profile, dict)
    )
    if legacy_key_profile_count:
        errors.append(f"{legacy_key_profile_count} v4 profiles contain legacy offset mirrors.")
    if not deep_paths:
        errors.append("manifest has no deepOffsetLibraries entries.")

    for deep_path in deep_paths:
        if not deep_path.exists():
            errors.append(f"deep-offset library missing: {deep_path}")
            continue
        deep_library = read_json(deep_path)
        deep_kind = str(deep_library.get("kind", "")).strip()
        if deep_kind == "KswordWin32kDeepOffsetLibrary":
            library_report = audit_win32k_deep_library(deep_path, deep_library)
            libraries.append(library_report)
            if not library_report["privateTypeReady"]:
                incomplete.append(
                    f"{deep_path.name} has public win32k symbols, but private GUI layout types are absent; "
                    "tagWND/tagTHREADINFO runtime detail remains unavailable."
                )
            if int(library_report.get("stats", {}).get("publicSymbolCount", 0) or 0) == 0:
                warnings.append(f"{deep_path.name} contains no public win32k symbols.")
            continue

        if deep_kind and deep_kind != "KswordNtosDeepOffsetLibrary":
            warnings.append(f"unknown deep-offset library kind {deep_kind}: {deep_path.name}")

        library_report = audit_deep_library(pack, deep_path, deep_library)
        libraries.append(library_report)
        if library_report["matchingProfileCount"] == 0:
            warnings.append(f"no pack profile matches deep library identity: {deep_path.name}")
            continue
        for profile_report in library_report["profiles"]:
            if profile_report["missingAliases"]:
                warnings.append(
                    f"{profile_report['profileName']} misses "
                    f"{len(profile_report['missingAliases'])} deep aliases."
                )
            if not profile_report["processDetail"]["ready"]:
                warnings.append(f"{profile_report['profileName']} process detail required fields are incomplete.")
            if not profile_report["threadDetail"]["ready"]:
                warnings.append(f"{profile_report['profileName']} thread detail required fields are incomplete.")

    return {
        "schemaVersion": 1,
        "kind": "KswordDynDataPackDeepAudit",
        "packPath": str(pack_path),
        "manifestPath": str(manifest_path),
        "packVersion": pack.get("packVersion"),
        "profileCount": len(pack.get("profiles", [])) if isinstance(pack.get("profiles"), list) else 0,
        "legacyKeyProfileCount": legacy_key_profile_count,
        "deepLibraryCount": len(libraries),
        "libraries": libraries,
        "errors": errors,
        "warnings": warnings,
        "incomplete": incomplete,
        "ok": not errors,
        "notes": [
            "This audit proves repository JSON coverage only; it does not prove the loaded driver consumed the pack.",
            "ntoskrnl deep libraries cannot provide win32k tagWND/tagTHREADINFO fields; win32k private layout data is still required for full window runtime detail.",
        ],
    }


def main() -> int:
    """Command-line entry point.

    Inputs:
    - Parameters: --pack, --manifest, --output.
    Processing:
    - Builds the report and writes it to JSON.
    Returns:
    - 0 indicates audit file write; returns 2 when errors exist.
    """
    parser = argparse.ArgumentParser(description="Audit Ksword DynData pack coverage against deep-offset libraries.")
    parser.add_argument("--pack", default=str(DEFAULT_PACK_PATH), help="Path to ark_dyndata_pack_v4.json.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST_PATH), help="Path to ark_dyndata_manifest.json.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="JSON report output path.")
    args = parser.parse_args()

    report = build_report(Path(args.pack), Path(args.manifest))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"ok={report['ok']}")
    print(f"profileCount={report['profileCount']}")
    print(f"legacyKeyProfileCount={report['legacyKeyProfileCount']}")
    print(f"deepLibraryCount={report['deepLibraryCount']}")
    print(f"errors={len(report['errors'])}")
    print(f"warnings={len(report['warnings'])}")
    print(f"incomplete={len(report['incomplete'])}")
    print(f"output={output_path}")
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
