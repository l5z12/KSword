#!/usr/bin/env python3
"""Exercise every registered CLI help route without opening the driver."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

from cli_catalog import read_catalog


def invoke(executable: Path, arguments: list[str]) -> tuple[int, bytes, bytes]:
    result = subprocess.run([str(executable), *arguments], capture_output=True, timeout=15)
    return result.returncode, result.stdout, result.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, help="Optional pre-refactor executable for output comparison")
    args = parser.parse_args()
    executable = args.exe.resolve()
    catalog, registered = read_catalog(Path(__file__).resolve().parents[1] / "apps/cli/CliHelp.cpp")
    families = [name for name, _ in catalog]
    commands = [(command.family, command.name) for command in registered]

    checked = 0
    for family in families:
        first = invoke(executable, ["help", family])
        alias = invoke(executable, [family, "help"])
        if first[0] or first != alias or not first[1]:
            raise RuntimeError(f"Family help failed or differs by spelling: {family}")
        if args.baseline and family != "ddma":
            if first != invoke(args.baseline.resolve(), ["help", family]):
                raise RuntimeError(f"Family help changed from baseline: {family}")
        checked += 2

    for family, command in commands:
        if not command:
            continue
        first = invoke(executable, ["help", family, command])
        alias = invoke(executable, [family, command, "--help"])
        if first[0] or first != alias or not first[1]:
            raise RuntimeError(f"Command help failed or differs by spelling: {family} {command}")
        if args.baseline and family != "ddma":
            if first != invoke(args.baseline.resolve(), ["help", family, command]):
                raise RuntimeError(f"Command help changed from baseline: {family} {command}")
        checked += 2

    for arguments in (["help", "__unknown__"], ["help", "process", "__unknown__"]):
        if invoke(executable, arguments)[0] != 1:
            raise RuntimeError(f"Unknown help target must fail: {arguments}")
    print(f"CLI help passed: {len(families)} families, {len(commands)} commands, {checked} help routes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
