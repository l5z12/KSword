#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static gate for the KswordARK driver functional matrix plan.

Input: repository root directory and ``driver_test_plan.json``. The process reuses the parser from
``tools/ioctl_audit/ksword_ioctl_audit.py`` to read the ``shared/driver`` protocol header and the central registry,
then validates the plan item by item: each registered IOCTL must be either 'executed' or 'excluded' exactly once.
IOCTLs triggered in dangerous mode must be on the exclusion list; every apps/cli subcommand and variable placeholder referenced by a
test case must actually exist. The return value is the process exit code, where 0 indicates the plan matches the driver's current state.

This gate does not require a driver test machine and can run on standard Windows/Linux runners; it ensures that
the plan actually executed by ``DriverFunctionalMatrix.ps1`` does not silently drift as the driver evolves.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cli_catalog import read_catalog

TIERS = {"probe", "guarded"}
EXPECTATIONS = {"success", "graceful", "timeout"}
REASON_RE = re.compile(r"^[a-z][a-z0-9-]*$")
PLACEHOLDER_RE = re.compile(r"\{([A-Za-z0-9_.]+)\}")
GAP_REASON = "no-cli-path"


def load_auditor(root: Path):
    """Load the existing IOCTL audit script to reuse its header and registry parsing implementations.

    Input: repository root directory. The process loads modules by path without modifying the state of any loaded module.
    Returns the module object for the caller to read IOCTL definitions and registry entries.
    """

    path = root / "tools" / "ioctl_audit" / "ksword_ioctl_audit.py"
    spec = importlib.util.spec_from_file_location("ksword_ioctl_audit", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load IOCTL audit module: {path}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses(slots=True) checks sys.modules; the module name must be registered before dynamic loading.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def registered_ioctls(root: Path, prefix: str) -> set[str]:
    """Returns the set of registered IOCTL short names from the central registry.

    Input is the repository root directory and protocol prefix. The process parses shared protocol
    headers, then intersects with rows in `ioctl_registry.c`, retaining only entries present in both.
    Return value is a set of short names with prefixes removed.
    """

    auditor = load_auditor(root)
    rules = auditor.load_rules(root)
    headers = auditor.discover_headers(root, rules)
    definitions, _ = auditor.parse_ioctl_defs(headers, root)
    table = {entry.name for entry in auditor.parse_registry(root)}
    return {d.name[len(prefix):] for d in definitions if d.name in table}


def cli_commands(root: Path) -> tuple[set[tuple[str, str]], dict[str, set[str]]]:
    """Parse apps/cli built-in help metadata to obtain the command table and 'Backed by' mapping.

    Reuse the documentation/help-test parser without compiling or executing the CLI.
    Return value: A set of (family, subcommand) pairs, plus a reverse mapping from short IOCTL names to command families.
    """

    _, catalog = read_catalog(root / "apps/cli/CliHelp.cpp")
    commands: set[tuple[str, str]] = set()
    backed: dict[str, set[str]] = {}
    for command in catalog:
        commands.add((command.family, command.name))
        for name in re.findall(r"IOCTL_KSWORD_ARK_[A-Z0-9_]+", command.notes):
            backed.setdefault(name[len("IOCTL_KSWORD_ARK_"):], set()).add(command.family)
    return commands, backed


def fail(errors: list[str], message: str) -> None:
    """Record a gate failure reason.

    Input: error list and description text. Processing: only appends; no deduplication or sorting.
    Returns empty; the caller outputs all errors after completing all checks.
    """

    errors.append(message)


def check_structure(plan: dict[str, Any], errors: list[str]) -> None:
    """Validate structural constraints of the plan file itself.

    Input is a parsed plan and error accumulation list. The processing checks ID uniqueness,
    tier/expect enums, step shapes, cleanup shapes, and exclusion reason code formats. Returns void.
    """

    seen: set[str] = set()
    for case in plan["cases"]:
        cid = case.get("id", "")
        if not cid:
            fail(errors, "There are test cases missing an id.")
            continue
        if cid in seen:
            fail(errors, f"Test case ID duplicate: {cid}")
        seen.add(cid)
        if case.get("tier") not in TIERS:
            fail(errors, f"{cid}: tier must be one of {sorted(TIERS)}.")
        if case.get("expect") not in EXPECTATIONS:
            fail(errors, f"{cid}: expect must be one of {sorted(EXPECTATIONS)}.")
        timeout = case.get("timeoutSeconds")
        if not isinstance(timeout, int) or timeout <= 0:
            fail(errors, f"{cid}: timeoutSeconds must be a positive integer.")
        steps = case.get("steps")
        if not isinstance(steps, list) or not steps:
            fail(errors, f"{cid}: steps must be a non-empty array.")
            continue
        for group in ("steps", "cleanup"):
            for step in case.get(group, []):
                if not isinstance(step, list) or not step or not all(isinstance(x, str) for x in step):
                    fail(errors, f"{cid}: {group} contains an invalid step {step!r}.")

    for row in plan["excluded"]:
        name = row.get("ioctl", "")
        reason = row.get("reason", "")
        if not REASON_RE.match(reason or ""):
            fail(errors, f"{name}: exclusion reason code {reason!r} must be kebab-case.")
        if not row.get("detail"):
            fail(errors, f"{name}: Exclusion items must specify a detail explaining why CI cannot execute them.")


def check_coverage(plan: dict[str, Any], registered: set[str], errors: list[str]) -> dict[str, Any]:
    """Verify that the plan fully and mutually exclusively covers registered IOCTLs.

    Input: plan, set of registry short names, and error list. Process: aggregate execution and exclusion sets,
    check gaps, out-of-bounds names, and duplicate classifications. Return: statistical dictionary for reporting.
    """

    covered: dict[str, list[str]] = {}
    for case in plan["cases"]:
        for name in case["ioctls"]:
            covered.setdefault(name, []).append(case["id"])
    excluded = {row["ioctl"]: row for row in plan["excluded"]}

    for name in sorted(set(covered) & set(excluded)):
        fail(errors, f"{name}: Appears in both test cases and exclusion list; classification must be unique.")

    unknown = sorted((set(covered) | set(excluded)) - registered)
    for name in unknown:
        fail(errors, f"{name}: Plan references an unregistered IOCTL, possibly a leftover after renaming or deletion.")

    missing = sorted(registered - set(covered) - set(excluded))
    for name in missing:
        fail(errors, f"{name}: New IOCTL not included in the functional matrix plan; please add a test case or specify the exclusion reason.")

    return {
        "registered": len(registered),
        "covered": len(set(covered) & registered),
        "excluded": len(set(excluded) & registered),
        "missing": missing,
        "unknown": unknown,
        "coveredMap": covered,
        "excludedMap": excluded,
    }


def check_danger_policy(plan: dict[str, Any], registered: set[str], stats: dict[str, Any],
                        errors: list[str]) -> list[str]:
    """Enforce the 'no meddling' static defense line.

    Input is the plan, registry set, coverage stats, and error list. The process matches registered IOCTLs
    against mustExcludePatterns one by one; any hit must be in the exclusion list. Any necessary exceptions
    must be documented in patternWaivers. Returns the list of IOCTLs that hit dangerous patterns.
    """

    policy = plan["policy"]
    patterns = [re.compile(p) for p in policy["mustExcludePatterns"]]
    waivers = policy.get("patternWaivers", {})
    dangerous: list[str] = []
    for name in sorted(registered):
        if not any(p.search(name) for p in patterns):
            continue
        dangerous.append(name)
        if name in stats["excludedMap"]:
            continue
        reason = waivers.get(name)
        if not reason:
            fail(
                errors,
                f"{name}: Hit dangerous operation mode but was scheduled for execution."
                f"Crashes from such IOCTLs are attributed to test inputs rather than driver defects and must be excluded,"
                f"or specify the waiver reason in policy.patternWaivers.",
            )
        else:
            cases = ", ".join(stats["coveredMap"].get(name, []))
            print(f"  [waiver] {name}: {reason} (Test Case: {cases})")
    return dangerous


def check_gap_budget(plan: dict[str, Any], stats: dict[str, Any], errors: list[str]) -> dict[str, int]:
    """Check if coverage gaps exceed the budget.

    Input is the plan, coverage statistics, and error list. The process counts excluded items by reason code and
    compares gaps like ``no-cli-path`` (which are gaps rather than security exclusions) against policy.gapBudget.
    Return value is a mapping from reason codes to counts.
    """

    counts: dict[str, int] = {}
    for row in stats["excludedMap"].values():
        counts[row["reason"]] = counts.get(row["reason"], 0) + 1
    for reason, budget in plan["policy"].get("gapBudget", {}).items():
        actual = counts.get(reason, 0)
        if actual > budget:
            fail(
                errors,
                f"Excluded reasons {reason} has {actual} items, exceeding budget {budget}."
                f"New gaps must first be addressed by adding a CLI entry point, or explicitly increase the budget and explain the reason.",
            )
    return counts


def check_commands(plan: dict[str, Any], root: Path, errors: list[str]) -> None:
    """Verify that each step corresponds to an existing apps/cli subcommand.

    Inputs are the plan, repository root, and error list. The process compares CLI built-in help metadata
    and performs reverse validation on items declared as no-cli-path. The return value is empty.
    """

    commands, backed = cli_commands(root)
    families = {family for family, _ in commands}
    for case in plan["cases"]:
        for group in ("steps", "cleanup"):
            for step in case.get(group, []):
                family = step[0]
                sub = step[1] if len(step) > 1 and not step[1].startswith("--") else ""
                if family not in families:
                    fail(errors, f"{case['id']}: Command family {family!r} is not in apps/cli help metadata.")
                elif (family, sub) not in commands:
                    fail(errors, f"{case['id']}: apps/cli has no subcommand {family} {sub!r}.")

    for name, row in ((r["ioctl"], r) for r in plan["excluded"]):
        if row["reason"] != GAP_REASON:
            continue
        if name in backed:
            fail(
                errors,
                f"{name}: Marked as {GAP_REASON}, but apps/cli help metadata declares "
                f"{sorted(backed[name])} command family is supported by it, should be changed to executable test case.",
            )


def check_variables(plan: dict[str, Any], errors: list[str]) -> None:
    """Verify that placeholders and 'requires' are both defined in 'variables'.

    Input is a plan and error list. The process scans all `{var}` placeholders and `requires`
    declarations in the step text, compares them one-by-one with the `variables` dictionary,
    and requires that `requires` covers all non-constant placeholders. Returns empty.
    """

    declared = set(plan["variables"])
    for case in plan["cases"]:
        used: set[str] = set()
        for group in ("steps", "cleanup"):
            for step in case.get(group, []):
                for token in step:
                    used.update(PLACEHOLDER_RE.findall(token))
        for name in sorted(used - declared):
            fail(errors, f"{case['id']}: Used undeclared variable {{{name}}}.")
        for name in case.get("requires", []):
            if name not in declared:
                fail(errors, f"{case['id']}: requires referencing an undeclared variable {name}.")
            if name not in used:
                fail(errors, f"{case['id']}: requires {name} to be declared, but it is not used in the steps.")

    guards = set(plan["policy"]["targetGuards"])
    for case in plan["cases"]:
        guard = case.get("targetGuard")
        if guard is None:
            continue
        if guard not in guards:
            fail(errors, f"{case['id']}: targetGuard {guard!r} is not defined in policy.targetGuards.")


def render_report(plan: dict[str, Any], stats: dict[str, Any], counts: dict[str, int],
                  dangerous: list[str]) -> str:
    """Generate human-readable coverage reports.

    Input includes the plan, coverage statistics, reason code counts, and a list of hazardous pattern hits. The processing step performs only text concatenation.
    Return value is Markdown text, intended for CI to upload as an artifact.
    """

    probe = [c for c in plan["cases"] if c["tier"] == "probe"]
    guarded = [c for c in plan["cases"] if c["tier"] == "guarded"]
    lines = [
        "# KswordARK driver functional matrix coverage report",
        "",
        f"- Registered IOCTLs: {stats['registered']}",
        f"- Plan execution: {stats['covered']}",
        f"- Plan excluded: {stats['excluded']}",
        f"- Total test cases: {len(plan['cases'])} (probe {len(probe)} / guarded {len(guarded)})",
        f"- Dangerous operations excluded: {len(dangerous)}",
        "",
        "## Exclusion Cause Distribution",
        "",
        "| Reason | Count |",
        "| --- | ---: |",
    ]
    for reason in sorted(counts):
        lines.append(f"| {reason} | {counts[reason]} |")
    lines += ["", "## Exclusion Details", "", "| IOCTL | Reason | Description |", "| --- | --- | --- |"]
    for row in sorted(plan["excluded"], key=lambda r: (r["reason"], r["ioctl"])):
        lines.append(f"| {row['ioctl']} | {row['reason']} | {row['detail']} |")
    lines.append("")
    return "\n".join(lines)


def force_utf8_output() -> None:
    """Switch standard output/error to UTF-8.

    No input. If the stream supports reconfigure, rewrite the encoding; otherwise, silently skip on failure.
    Return value is null. GitHub's Windows runner defaults Python to cp1252; directly printing
    Chinese diagnostics throws UnicodeEncodeError, causing passed gates to be misjudged as failures.
    """

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse command-line arguments.

    Input is a parameter list or None. The process only declares options without accessing files.
    Return value: argparse namespace.
    """

    parser = argparse.ArgumentParser(description="KswordARK driver functional matrix plan gate")
    parser.add_argument("--repo-root", default=".", help="Repository root directory")
    parser.add_argument("--plan", default=None, help="Path to the plan file; defaults to the repository's built-in plan")
    parser.add_argument("--out", default=None, help="Optional Markdown override report output path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Gate entry.

    Input is command-line arguments. The process sequentially executes structure, coverage, dangerous policy, gap budget, and command/variable
    checks, then generates reports as needed. The return value is an exit code; a non-zero value indicates the plan requires correction.
    """

    force_utf8_output()
    args = parse_args(argv)
    root = Path(args.repo_root).resolve()
    plan_path = Path(args.plan) if args.plan else root / "tools" / "driver_functional_ci" / "driver_test_plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8-sig"))

    errors: list[str] = []
    registered = registered_ioctls(root, plan["ioctlPrefix"])

    check_structure(plan, errors)
    stats = check_coverage(plan, registered, errors)
    dangerous = check_danger_policy(plan, registered, stats, errors)
    counts = check_gap_budget(plan, stats, errors)
    check_commands(plan, root, errors)
    check_variables(plan, errors)

    report = render_report(plan, stats, counts, dangerous)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8", newline="\n")

    print(f"registered={stats['registered']} covered={stats['covered']} excluded={stats['excluded']} "
          f"cases={len(plan['cases'])} dangerous={len(dangerous)}")
    if errors:
        print("")
        print("Driver functional matrix plan gate check failed:")
        for message in errors:
            print(f"  - {message}")
        return 1
    print("The driver function matrix plan is consistent with the current IOCTL registry.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
