"""Shared CI impact detection. Unproven history always selects a full build."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import subprocess


PROJECT_INPUTS = {
    "usermode": (
        "apps/desktop/", "apps/launcher/", "apps/taskbar/", "apps/hud/", "integrations/api_monitor/",
        "apps/cli/", "tests/native/fs_decode/", "tests/native/monitor/", "integrations/dwm_z_order/", "apps/uac_desktop/",
        "tests/native/dwm_z_order/",
    ),
    "setup": (
        "apps/setup/", "apps/desktop/", "apps/launcher/", "apps/taskbar/", "apps/hud/",
        "integrations/api_monitor/", "apps/cli/", "drivers/ark/", "apps/ark_light/",
        "integrations/dwm_z_order/", "apps/uac_desktop/",
    ),
    "arklight": (
        "apps/ark_light/", "tests/native/ark_light/", "drivers/ark/",
        "shared/ark_client/", "apps/desktop/Resource/",
        "shared/platform/",
    ),
    "ce_plugin": (
        "integrations/cheat_engine_plugin/", "shared/ark_client/",
        "shared/platform/string/",
    ),
    "ce_launcher": (
        "integrations/cheat_engine_launcher/", "shared/ark_client/",
        "shared/platform/string/",
    ),
    "driver": ("drivers/ark/", "shared/driver/", "third_party/systeminformer_dyn/"),
}


def is_build_metadata(path: str) -> bool:
    name = PurePosixPath(path).name
    return name.startswith("Directory.Build.") or name.endswith((".props", ".targets", ".sln"))


def affected_projects(paths: list[str] | None) -> dict[str, bool]:
    """None means unknown impact; an empty list means a proven empty diff."""
    result = {project: paths is None for project in PROJECT_INPUTS}
    for path in paths or []:
        common = path.startswith(("tools/", "scripts/", "shared/", "third_party/", ".deps/", ".github/workflows/"))
        for project, prefixes in PROJECT_INPUTS.items():
            affected = path.startswith(prefixes) or is_build_metadata(path)
            if project == "driver":
                affected |= path.startswith(("tools/ci_changes.py", "tools/tests/", ".github/workflows/driver-ci.yml"))
            else:
                affected |= common
            result[project] |= affected
    result["any"] = any(value for key, value in result.items() if key != "driver")
    return result


def command(*args: str) -> str:
    return subprocess.check_output(args, encoding="utf-8", errors="strict", timeout=90)


def previous_run_allows_diff(run: dict, event: str, before: str) -> bool:
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return False
    # A newer successful run, rerun, or delayed push must not hide unbuilt inputs.
    return event != "push" or bool(before and run.get("head_sha") == before)


def changed_paths(workflow: str, env: dict[str, str]) -> list[str] | None:
    """Query CI evidence before computing a NUL-delimited, rename-safe Git diff."""
    event = env.get("EVENT_NAME", "")
    if event == "workflow_dispatch" or event not in {"push", "pull_request"}:
        return None
    try:
        response = json.loads(command(
            "gh", "api", "--method", "GET",
            f"/repos/{env['GITHUB_REPOSITORY']}/actions/workflows/{workflow}/runs",
            "-f", f"branch={env['RUN_BRANCH']}", "-f", "per_page=20",
        ))
        runs = [run for run in response["workflow_runs"] if str(run["id"]) != env["GITHUB_RUN_ID"]]
        previous = runs[0] if runs else {}
        before = env.get("EVENT_BEFORE", "")
        if not previous_run_allows_diff(previous, event, before):
            print("Previous run does not prove a successful baseline; selecting all projects.")
            return None
        head = env["EVENT_SHA"]
        if event == "pull_request":
            base_ref = env["BASE_REF"]
            command("git", "fetch", "--no-tags", "origin", base_ref, "--depth=1")
            base = command("git", "merge-base", f"origin/{base_ref}", head).strip()
        else:
            if not before or set(before) == {"0"}:
                return None
            command("git", "cat-file", "-e", f"{before}^{{commit}}")
            base = before
        # --no-renames includes both the old and new paths of a moved input.
        raw = command("git", "diff", "--no-renames", "--name-only", "-z", base, head, "--")
        return [path for path in raw.split("\0") if path]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        print(f"Cannot establish change scope ({error}); selecting all projects.")
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", choices=("ci.yml", "driver-ci.yml"), required=True)
    args = parser.parse_args()
    paths = changed_paths(args.workflow, dict(os.environ))
    result = affected_projects(paths)
    print("Changed paths: " + ("<all>" if paths is None else repr(paths)))
    output = "".join(f"{name}={str(value).lower()}\n" for name, value in result.items())
    print(output, end="")
    if destination := os.environ.get("GITHUB_OUTPUT"):
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
