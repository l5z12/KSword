"""Run the repository's portable source checks with the same commands as CI.

Usage: python tools/check.py [--check NAME ...]
The checks need Git and Python, but do not build or load the Windows driver.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from project_audit import git_files


ROOT = Path(__file__).resolve().parents[1]
CHECKS = {
    "docs": ["tools/docs_audit.py"],
    "cli-docs": ["tools/generate_cli_docs.py", "--check"],
    "projects": ["tools/project_audit.py"],
    "layout": ["tools/layout_audit.py"],
    "filters": ["tools/project_filters.py"],
    "comments": ["tools/comment_language_audit.py"],
    "script-language": ["tools/script_language_audit.py"],
    "tool-tests": ["-m", "unittest", "discover", "-s", "tools/tests", "-v"],
    "i18n-tests": ["-m", "unittest", "discover", "-s", "tools", "-p", "test_i18n_language_pack.py", "-v"],
    "i18n": [
        "tools/i18n_language_pack.py", "audit", "--source-root", "apps/desktop",
        "--zh-pack", "apps/desktop/languages/zh-CN.json",
        "--en-pack", "apps/desktop/languages/en-US.json",
    ],
    "knowledge": ["tools/validate_kernel_knowledge.py"],
    # hvm_ctl is no longer a GUI build dependency, so its catalog needs an
    # explicit gate. The EPT audit pins the private, per-processor hierarchy.
    "hvm-catalog": ["tools/hvm_ctl/audit_catalog.py"],
    "hvm-ept": ["tools/hvm_local_ept_gate.py"],
    "theme-tests": ["tools/theme_token_audit.py", "--self-test"],
    "theme": ["tools/theme_token_audit.py", "--source-root", "apps/desktop"],
    # Keep --fail-on-risk: producing a report alone does not gate regressions.
    "ioctl": [
        "tools/ioctl_audit/ksword_ioctl_audit.py", "--repo-root", ".",
        "--format", "markdown", "--out", "artifacts/ioctl-audit.md", "--fail-on-risk",
    ],
}


def validate_json(root: Path) -> int:
    paths = git_files(root, "*.json")
    failures = []
    for name in paths:
        try:
            with (root / name).open(encoding="utf-8-sig") as stream:
                json.load(stream)
        except (OSError, ValueError) as error:
            failures.append(f"{name}: {error}")
    for failure in failures:
        print(failure)
    print(f"Validated {len(paths)} tracked JSON files; {len(failures)} failed.")
    return int(bool(failures))


def run_checks(names: list[str], root: Path = ROOT) -> int:
    results = []
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    for name in names:
        print(f"\n--- {name} ---", flush=True)
        start = time.monotonic()
        try:
            if name == "json":
                code = validate_json(root)
            else:
                # Reuse the invoking interpreter (including a local uv environment).
                code = subprocess.run([sys.executable, *CHECKS[name]], cwd=root, env=env).returncode
        except (OSError, subprocess.SubprocessError) as error:
            print(f"Could not run {name}: {error}", flush=True)
            code = 1
        results.append((name, code, time.monotonic() - start))
    print("\nSource check results:", flush=True)
    for name, code, elapsed in results:
        print(f"  {'PASS' if code == 0 else 'FAIL'} {name} ({elapsed:.1f}s)", flush=True)
    return int(any(code != 0 for _, code, _ in results))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choices = ["json", *CHECKS]
    parser.add_argument("--check", action="append", choices=choices, help="run only named checks; repeatable")
    parser.add_argument("--list", action="store_true", help="list available checks without running them")
    args = parser.parse_args()
    if args.list:
        print("\n".join(choices))
        return 0
    return run_checks(list(dict.fromkeys(args.check or choices)))


if __name__ == "__main__":
    raise SystemExit(main())
