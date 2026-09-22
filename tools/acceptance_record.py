#!/usr/bin/env python3
"""Update the execution record in docs/next/KSword_Acceptance_Results_Template.json item by item.

This is a maintenance tool for deliverable Section 9 "Itemized Result Records". It is not part of the product
runtime and is not read by the UI. It only modifies explicitly numbered entries, leaving all other items unchanged.

Usage:
    uv run --python 3.12 python tools/acceptance_record.py set F-03 \
        --implementation implemented --verification PASS \
        --path shared/evidence/ObjectIdentity.cpp \
        --env E0 --exec "Build+Run KswordARKLightTests.exe -> F 92/92" \
        --evidence docs/next/logs/lighttests-run.txt

    uv run --python 3.12 python tools/acceptance_record.py show F-03
    uv run --python 3.12 python tools/acceptance_record.py summary
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECORD = os.path.join(REPO_ROOT, "docs", "next", "KSword_Acceptance_Results_Template.json")

# Keep the existing record schema; expose English names at the CLI boundary.
IMPLEMENTATION_STATES = {
    "not-started": "未开始",
    "in-progress": "开发中",
    "implemented": "已实现",
}
VERIFICATION_STATES = ("NOT_RUN", "PASS", "FAIL", "BLOCKED")
APPLICABILITY_STATES = ("required", "not_applicable")


def load() -> dict:
    with io.open(RECORD, encoding="utf-8") as handle:
        return json.load(handle)


def save(document: dict) -> None:
    with io.open(RECORD, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def find(document: dict, item_id: str) -> dict:
    for item in document["acceptance_items"]:
        if item["id"] == item_id:
            return item
    raise SystemExit("unknown acceptance id: %s" % item_id)


def cmd_set(args: argparse.Namespace) -> int:
    document = load()
    item = find(document, args.id)

    if args.implementation:
        item["implementation_status"] = implementation_value(args.implementation)
    if args.verification:
        if args.verification not in VERIFICATION_STATES:
            raise SystemExit("verification must be one of %s" % (VERIFICATION_STATES,))
        item["verification_status"] = args.verification
    if args.applicability:
        if args.applicability not in APPLICABILITY_STATES:
            raise SystemExit("applicability must be one of %s" % (APPLICABILITY_STATES,))
        item["applicability"] = args.applicability

    for path in args.path or []:
        if path not in item["implementation_paths"]:
            item["implementation_paths"].append(path)
    for env in args.env or []:
        if env not in item["environments"]:
            item["environments"].append(env)
    for execution in args.exec or []:
        if execution not in item["executions"]:
            item["executions"].append(execution)
    for evidence in args.evidence or []:
        if evidence not in item["evidence_paths"]:
            item["evidence_paths"].append(evidence)
    for issue in args.issue or []:
        if issue not in item["known_issues"]:
            item["known_issues"].append(issue)

    if args.blocking is not None:
        item["blocking_reason"] = args.blocking or None
    if args.notes is not None:
        item["notes"] = args.notes

    # PASS status requires at least one actual execution record; otherwise, the record is invalid.
    if item["verification_status"] == "PASS" and not item["executions"]:
        raise SystemExit("%s cannot be PASS without at least one execution record" % args.id)
    if item["verification_status"] == "BLOCKED" and not item["blocking_reason"]:
        raise SystemExit("%s cannot be BLOCKED without a blocking_reason" % args.id)

    save(document)
    print("updated %s: impl=%s verify=%s" %
          (args.id, implementation_label(item["implementation_status"]), item["verification_status"]))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    item = find(load(), args.id)
    print(json.dumps(item, ensure_ascii=False, indent=2))
    return 0


def implementation_value(value: str) -> str:
    """Accept English CLI values and legacy aliases without migrating records."""
    if value in IMPLEMENTATION_STATES:
        return IMPLEMENTATION_STATES[value]
    if value in IMPLEMENTATION_STATES.values():
        return value
    raise SystemExit("implementation must be one of %s" % ", ".join(IMPLEMENTATION_STATES))


def implementation_label(value: str) -> str:
    return next((label for label, stored in IMPLEMENTATION_STATES.items() if stored == value), value)


def cmd_summary(_args: argparse.Namespace) -> int:
    document = load()
    by_phase: dict[str, dict[str, int]] = {}
    for item in document["acceptance_items"]:
        phase = item.get("phase", "?")
        bucket = by_phase.setdefault(phase, {})
        key = item["verification_status"]
        bucket[key] = bucket.get(key, 0) + 1
    total = len(document["acceptance_items"])
    print("total acceptance items: %d" % total)
    for phase in sorted(by_phase):
        parts = ", ".join("%s=%d" % (k, v) for k, v in sorted(by_phase[phase].items()))
        print("  %s: %s" % (phase, parts))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    setter = sub.add_parser("set", help="update one acceptance item")
    setter.add_argument("id")
    setter.add_argument("--implementation", metavar="STATE",
                        help="not-started, in-progress, or implemented (legacy aliases accepted)")
    setter.add_argument("--verification")
    setter.add_argument("--applicability")
    setter.add_argument("--path", action="append")
    setter.add_argument("--env", action="append")
    setter.add_argument("--exec", action="append")
    setter.add_argument("--evidence", action="append")
    setter.add_argument("--issue", action="append")
    setter.add_argument("--blocking")
    setter.add_argument("--notes")
    setter.set_defaults(func=cmd_set)

    shower = sub.add_parser("show", help="print one acceptance item")
    shower.add_argument("id")
    shower.set_defaults(func=cmd_show)

    summary = sub.add_parser("summary", help="count verification states per phase")
    summary.set_defaults(func=cmd_summary)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
