"""Discover prerequisites and build/test a small, contributor-facing target.

Uses only Python's standard library. Run with --help for explicit path overrides.
No package installation, driver loading, signing, or machine configuration occurs.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Target:
    project: str
    artifact: str
    qt: bool = False
    qt_msbuild: bool = False
    test: bool = False


TARGETS = {
    "client-tests": Target("tests/native/ark_client/KswordArkClientTests.vcxproj",
                           "tests/native/ark_client/x64/{config}/KswordArkClientTests.exe", test=True),
    "cli-tests": Target("tests/native/cli/KswordCliTests.vcxproj",
                        "tests/native/cli/x64/{config}/KswordCliTests.exe", test=True),
    "fs-tests": Target("tests/native/fs_decode/KswordFsDecodeTests.vcxproj",
                       "tests/native/fs_decode/x64/{config}/KswordFsDecodeTests.exe", test=True),
    "monitor-tests": Target("tests/native/monitor/KswordMonitorTests.vcxproj",
                            "tests/native/monitor/x64/{config}/KswordMonitorTests.exe", qt=True, test=True),
    "cli": Target("apps/cli/KswordCLI.vcxproj", "artifacts/bin/x64/{config}/KswordCLI.exe"),
    "desktop": Target("apps/desktop/KswordDesktop.vcxproj",
                      "artifacts/bin/x64/{config}/Ksword5.1.exe", qt=True, qt_msbuild=True),
}
CORE_TESTS = ("client-tests", "cli-tests", "fs-tests")


def selected_targets(name: str) -> list[Target]:
    return [TARGETS[key] for key in (CORE_TESTS if name == "tests" else (name,))]


def find_msbuild(explicit: str | None, env: dict[str, str]) -> Path | None:
    env = {key.upper(): value for key, value in env.items()}
    # An explicit override must not silently fall back to a different installation.
    if override := explicit or env.get("MSBUILD_PATH"):
        return Path(override).expanduser().resolve()
    if on_path := shutil.which("MSBuild.exe"):
        return Path(on_path)
    vswhere = Path(env.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
    if vswhere.is_file():
        result = subprocess.run(
            [str(vswhere), "-latest", "-products", "*", "-requires",
             "Microsoft.Component.MSBuild", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
             "-find", "MSBuild/Current/Bin/MSBuild.exe", "-utf8"],
            capture_output=True, text=True, encoding="utf-8", check=True,
        )
        for line in result.stdout.splitlines():
            if Path(line.strip()).is_file():
                return Path(line.strip())
    return None


def find_directory(explicit: str | None, env: dict[str, str], names: tuple[str, ...],
                   candidates: tuple[Path, ...], marker: str) -> Path | None:
    env = {key.upper(): value for key, value in env.items()}
    for value in (explicit, *(env.get(name.upper()) for name in names)):
        if value:
            return Path(value).expanduser().resolve()
    return next((path for path in candidates if (path / marker).is_file()), None)


@dataclass(frozen=True)
class Environment:
    msbuild: Path | None
    qt: Path | None
    qt_msbuild: Path | None


def discover(args: argparse.Namespace, env: dict[str, str], root: Path = ROOT) -> Environment:
    return Environment(
        find_msbuild(args.msbuild, env),
        find_directory(args.qt_dir, env, ("KSWORD_QT_DIR", "QT_ROOT_DIR", "QTDIR"),
                       (root / ".deps/Qt/6.9.3/msvc2022_64",), "bin/qmake.exe"),
        find_directory(args.qt_msbuild, env, ("KSWORD_QT_MSBUILD", "QtMsBuild"),
                       (root / ".deps/QtVsTools/msbuild", root / ".deps/QtVsTools"), "qt.targets"),
    )


def prerequisite_errors(targets: list[Target], found: Environment, config: str,
                        platform: str = sys.platform) -> list[str]:
    errors = []
    if platform != "win32":
        errors.append("Native targets require Windows. Source checks: python tools/check.py")
    if found.msbuild is None or not found.msbuild.is_file():
        errors.append("MSBuild/C++ tools not found. Install VS 2022 Desktop development with C++ "
                      "(v143 and a Windows SDK), or pass --msbuild PATH.")
    if any(target.qt for target in targets):
        suffix = "d" if config == "Debug" else ""
        required = ("bin/qmake.exe", f"bin/Qt6Core{suffix}.dll", f"lib/Qt6Core{suffix}.lib", "include/QtCore/qglobal.h")
        for name in required:
            if found.qt is None or not (found.qt / name).is_file():
                errors.append(f"Qt MSVC x64 installation missing {name}. Pass --qt-dir PATH (CI uses Qt 6.9.3).")
        if any(target.qt_msbuild for target in targets):
            for name in ("bin/windeployqt.exe", *(f"lib/Qt6{module}{suffix}.lib" for module in ("Gui", "Network", "Widgets", "Svg"))):
                if found.qt is None or not (found.qt / name).is_file():
                    errors.append(f"Desktop Qt installation missing {name}. Include Qt GUI, Network, Widgets, and SVG.")
    if any(target.qt_msbuild for target in targets):
        for name in ("qt.props", "qt.targets", "qt_defaults.props"):
            if found.qt_msbuild is None or not (found.qt_msbuild / name).is_file():
                errors.append(f"Qt MSBuild missing {name}. Pass --qt-msbuild PATH to the extracted integration files.")
    return errors


def build_command(target: Target, args: argparse.Namespace, found: Environment) -> list[str]:
    command = [str(found.msbuild or "MSBuild.exe"), target.project, "/t:Build",
               f"/p:Configuration={args.config}", "/p:Platform=x64", f"/p:PlatformToolset={args.toolset}",
               "/p:PreferredToolArchitecture=x64", "/m:1", "/v:minimal", "/nologo"]
    if target.qt_msbuild:
        command.extend([f"/p:QtMsBuild={found.qt_msbuild or '<QtMsBuild>'}", "/p:KswordArkSkipAutoTestSign=true"])
        # MSBuild uses the exact invoking interpreter, including a uv environment.
        for name in ("KswordI18nPythonExe", "KswordThemeTokenPythonExe", "KswordProfilePythonExe"):
            command.append(f"/p:{name}={sys.executable}")
    return command


def run(command: list[str], env: dict[str, str], dry_run: bool) -> None:
    print("\n> " + subprocess.list2cmdline(command), flush=True)
    if not dry_run:
        subprocess.run(command, cwd=ROOT, env=env, check=True)


def execute(args: argparse.Namespace, found: Environment, env: dict[str, str]) -> None:
    targets = selected_targets(args.target)
    child_env = {**env, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    if any(target.qt for target in targets) and found.qt:
        child_env.update(KSWORD_QT_DIR=str(found.qt), QTDIR=str(found.qt))
        child_env["PATH"] = str(found.qt / "bin") + os.pathsep + child_env.get("PATH", "")
    for target in targets:
        run(build_command(target, args, found), child_env, args.dry_run)
        artifact = ROOT / target.artifact.format(config=args.config)
        if not args.dry_run and (not artifact.is_file() or artifact.stat().st_size == 0):
            raise RuntimeError(f"Build reported success but the expected artifact is missing or empty: {artifact}")
        if args.action == "test":
            if target.test:
                run([str(artifact)], child_env, args.dry_run)
            else:  # The only non-test executable accepted here is the CLI help surface.
                run([sys.executable, "tools/test_cli_help.py", "--exe", str(artifact)], child_env, args.dry_run)
    if not args.dry_run:
        print(f"\nPASS: {args.action} {args.target} ({args.config}, x64, {args.toolset})")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("doctor", "build", "test"))
    parser.add_argument("--target", choices=("tests", *TARGETS), default="tests",
                        help="tests = driver-client, CLI parser, and filesystem decoder tests (no Qt/WDK)")
    parser.add_argument("--config", choices=("Debug", "Release"), default="Release")
    parser.add_argument("--toolset", choices=("v143", "v145"), default="v143",
                        help="explicit compiler choice; default matches CI (never auto-upgraded)")
    parser.add_argument("--msbuild", help="MSBuild.exe path; otherwise PATH, then vswhere")
    parser.add_argument("--qt-dir", help="Qt MSVC x64 install prefix; otherwise environment or .deps")
    parser.add_argument("--qt-msbuild", help="directory containing qt.props and qt.targets")
    parser.add_argument("--dry-run", action="store_true", help="print commands even if prerequisites are missing; do not build or run tests")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = argument_parser()
    args = parser.parse_args(argv)
    if args.action == "test" and args.target == "desktop":
        parser.error("desktop has no automated UI acceptance test; use build --target desktop")
    try:
        found = discover(args, dict(os.environ))
        print(f"Repository: {ROOT}\nPython: {sys.executable}\nMSBuild: {found.msbuild or 'not found'}")
        print(f"Toolset: {args.toolset} (must be installed); configuration: {args.config}/x64")
        if any(target.qt for target in selected_targets(args.target)):
            print(f"Qt: {found.qt or 'not found'}\nQt MSBuild: {found.qt_msbuild or 'not needed for QtCore tests'}")
        errors = prerequisite_errors(selected_targets(args.target), found, args.config)
        for error in errors:
            print(f"MISSING: {error}")
        if args.action == "doctor":
            if not errors:
                print("Discovery passed. MSBuild verifies the installed toolset and SDK when building.")
            return int(bool(errors))
        if errors and not args.dry_run:
            return 1
        execute(args, found, dict(os.environ))
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
