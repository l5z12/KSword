#!/usr/bin/env python3
"""Generate the apps/launcher identity index from the published DynData v4 pack."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any


REQUIRED_PROFILE_KEYS = (
    "moduleClassId",
    "machine",
    "timeDateStamp",
    "sizeOfImage",
    "pdbName",
    "pdbGuid",
    "pdbAge",
)

# These fields are optional capabilities in the current DynData diagnostics; their absence should not mark the entire kernel profile as unavailable.
# Marked as unavailable. Other missing fields will still cause the apps/launcher to report that this identity requires developer attention.
OPTIONAL_MISSING_FIELDS = {
    "_EPROCESS->NumberOfLockedPages",
    "_HANDLE_TABLE->HandleCount",
    "_UNLOADED_DRIVERS->Name",
    "_UNLOADED_DRIVERS->StartAddress",
    "_UNLOADED_DRIVERS->EndAddress",
    "_UNLOADED_DRIVERS->CurrentTime",
}

# The CI v4 profile lacks the traditional v3 field table; safe publishing requires only read-only traversal of the two global fields.
# If Next, DriverName, and entry size are all present, it can be safely published as a complete identity.
CI_MODULE_CLASS_ID = 65
CI_REQUIRED_V4_ITEM_IDS = {1201, 1202, 1203, 1204, 1209}


def load_object(path: Path) -> dict[str, Any]:
    """Read the JSON object: input is the file path, output is the top-level dictionary; terminate the build immediately on format errors."""
    with path.open("r", encoding="utf-8-sig") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def validate_source(source: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Validate the manually written module directory; takes an input source object and outputs a module map indexed by classId."""
    if source.get("schemaVersion") != 1:
        raise ValueError("support_manifest_source.json schemaVersion must be 1")
    modules = source.get("modules")
    if not isinstance(modules, list) or len(modules) != 12:
        raise ValueError("the apps/launcher catalog must contain exactly 12 v4 module classes")
    indexed: dict[int, dict[str, Any]] = {}
    for module in modules:
        if not isinstance(module, dict):
            raise ValueError("every module entry must be an object")
        class_id = module.get("classId")
        names = module.get("fileNames")
        if not isinstance(class_id, int) or class_id in indexed:
            raise ValueError(f"invalid or duplicate module classId: {class_id!r}")
        if not isinstance(names, list) or not names or not all(isinstance(name, str) and name for name in names):
            raise ValueError(f"module {class_id} must contain fileNames")
        compatibility_required = module.get("compatibilityRequired")
        collection_only = module.get("collectionOnly")
        if not isinstance(compatibility_required, bool) or not isinstance(collection_only, bool):
            raise ValueError(f"module {class_id} must declare compatibilityRequired and collectionOnly")
        if compatibility_required and collection_only:
            raise ValueError(f"module {class_id} cannot be compatibilityRequired and collectionOnly")
        indexed[class_id] = module
    expected_class_ids = {0, 1, 2, 16, 17, 18, 32, 33, 34, 48, 64, 65}
    if set(indexed) != expected_class_ids:
        raise ValueError("module classIds do not match the shared DynData v4 class IDs")
    if not indexed[0]["compatibilityRequired"] or not indexed[1]["compatibilityRequired"]:
        raise ValueError("NTOS and NTKRLA57 must remain compatibility-required")
    return indexed


def profile_is_complete(profile: dict[str, Any]) -> bool:
    """Check if the v4 profile is complete and output the integrity marker used by the Launcher."""
    if int(profile.get("moduleClassId", -1)) == CI_MODULE_CLASS_ID:
        items = profile.get("items", [])
        if not isinstance(items, list):
            return False
        item_ids = {
            int(item["itemId"])
            for item in items
            if isinstance(item, dict) and isinstance(item.get("itemId"), int)
        }
        return CI_REQUIRED_V4_ITEM_IDS.issubset(item_ids)

    missing_fields = profile.get("missingFields", [])
    missing_globals = profile.get("missingGlobals", [])
    # coveragePercent is the mathematical coverage of all fields and cannot be used alone to determine core availability.
    # The current profile may only be missing optional handle count or driver unload history fields.
    return not missing_globals and all(field in OPTIONAL_MISSING_FIELDS for field in missing_fields)


def normalize_guid(value: str) -> str:
    """Normalize PDB GUID format: input may include hyphens or braces; output is 32 uppercase hex digits."""
    normalized = re.sub(r"[-{}\s]", "", value).upper()
    if not re.fullmatch(r"[0-9A-F]{32}", normalized):
        raise ValueError(f"invalid PDB GUID: {value!r}")
    return normalized


def compact_profile(profile: dict[str, Any]) -> dict[str, Any]:
    """Discard the offset array, retaining only PE/PDB identity and coverage status; input is the original profile, output is a lightweight record."""
    missing = [key for key in REQUIRED_PROFILE_KEYS if key not in profile]
    if missing:
        raise ValueError(f"profile {profile.get('profileName', '<unnamed>')} misses {missing}")
    return {
        "moduleClassId": int(profile["moduleClassId"]),
        "machine": int(profile["machine"]),
        "timeDateStamp": int(profile["timeDateStamp"]),
        "sizeOfImage": int(profile["sizeOfImage"]),
        "pdbName": str(profile["pdbName"]),
        "pdbGuid": normalize_guid(str(profile["pdbGuid"])),
        "pdbAge": int(profile["pdbAge"]),
        "complete": profile_is_complete(profile),
        "coveragePercent": float(profile.get("coveragePercent", 0.0)),
        "profileName": str(profile.get("profileName", "")),
    }


def identity_key(profile: dict[str, Any]) -> tuple[Any, ...]:
    """Generates stable deduplicated keys; accepts a lightweight profile as input and outputs a tuple covering all matching fields."""
    return tuple(profile[key] for key in REQUIRED_PROFILE_KEYS)


def generate(source: dict[str, Any], pack: dict[str, Any]) -> dict[str, Any]:
    """Merge directories with the published v4 matrix and output the apps/launcher manifest."""
    modules_by_id = validate_source(source)
    if int(pack.get("packVersion", 0)) != 4 or not isinstance(pack.get("profiles"), list):
        raise ValueError("apps/launcher support manifest requires a v4 profile pack")

    deduplicated: dict[tuple[Any, ...], dict[str, Any]] = {}
    for raw_profile in pack["profiles"]:
        if not isinstance(raw_profile, dict):
            raise ValueError("every profile must be an object")
        profile = compact_profile(raw_profile)
        if profile["moduleClassId"] not in modules_by_id:
            raise ValueError(f"unknown moduleClassId in profile pack: {profile['moduleClassId']}")
        key = identity_key(profile)
        previous = deduplicated.get(key)
        if previous is None or (profile["complete"] and not previous["complete"]):
            deduplicated[key] = profile

    profiles = sorted(
        deduplicated.values(),
        key=lambda item: (
            item["moduleClassId"],
            item["pdbName"].lower(),
            item["pdbGuid"],
            item["pdbAge"],
        ),
    )
    output_modules: list[dict[str, Any]] = []
    for class_id in sorted(modules_by_id):
        module = dict(modules_by_id[class_id])
        rows = [profile for profile in profiles if profile["moduleClassId"] == class_id]
        complete_count = sum(1 for profile in rows if profile["complete"])
        if not rows:
            status = "unpublished"
        elif complete_count == len(rows):
            status = "complete"
        else:
            status = "partial"
        module["publishedProfileCount"] = len(rows)
        module["completeProfileCount"] = complete_count
        module["coverageStatus"] = status
        output_modules.append(module)

    return {
        "schemaVersion": 1,
        "generatedUtc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "product": source.get("product", "KswordARK"),
        "osPolicy": source["osPolicy"],
        "modules": output_modules,
        "profiles": profiles,
    }


def validate_output(output: dict[str, Any]) -> None:
    """Perform strict structural validation without third-party libraries; input/output objects throw exceptions on failure."""
    if set(output) != {"schemaVersion", "generatedUtc", "product", "osPolicy", "modules", "profiles"}:
        raise ValueError("generated manifest contains unexpected top-level keys")
    if output["schemaVersion"] != 1 or len(output["modules"]) != 12:
        raise ValueError("generated manifest has an invalid schema or module count")
    for profile in output["profiles"]:
        for key in REQUIRED_PROFILE_KEYS + ("complete", "coveragePercent", "profileName"):
            if key not in profile:
                raise ValueError(f"generated profile misses {key}")


def main() -> int:
    """Parse command-line arguments and atomically write the manifest; input script parameters, output process exit code."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--pack", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()

    output = generate(load_object(args.source), load_object(args.pack))
    validate_output(output)
    if not args.validate_only:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(output, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        temporary.replace(args.output)
        print(f"Generated {args.output} with {len(output['profiles'])} identities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
