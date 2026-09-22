"""Build selection must never skip inputs whose previous build is unproven."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_changes


class ImpactTests(unittest.TestCase):
    def test_unknown_and_empty_diff_are_different(self):
        self.assertTrue(all(ci_changes.affected_projects(None).values()))
        self.assertFalse(any(ci_changes.affected_projects([]).values()))

    def test_documentation_does_not_request_native_builds(self):
        self.assertFalse(any(ci_changes.affected_projects(["docs/maintenance.md"]).values()))

    def test_shipping_script_triggers_both_consumers(self):
        affected = ci_changes.affected_projects(["scripts/runtime/TaskmgrHijack.ps1"])
        self.assertTrue(affected["usermode"])
        self.assertTrue(affected["setup"])
        self.assertFalse(affected["driver"])

    def test_root_build_settings_trigger_every_consumer(self):
        for path in ("Directory.Build.targets", "build/msbuild/Ksword.Output.props", "KSword.sln"):
            with self.subTest(path=path):
                self.assertTrue(all(ci_changes.affected_projects([path]).values()))

    def test_driver_vendored_inputs_are_not_skipped(self):
        for name in ("kphdyn.c", "kphdyn.h", "ksw_si_dynconfig.h"):
            self.assertTrue(ci_changes.affected_projects(["third_party/systeminformer_dyn/" + name])["driver"])

    def test_driver_change_builds_embedded_consumers(self):
        affected = ci_changes.affected_projects(["drivers/ark/src/driver.c"])
        for name in ("driver", "setup", "arklight", "any"):
            self.assertTrue(affected[name], name)

    def test_shared_protocol_builds_all_consumers(self):
        self.assertTrue(all(ci_changes.affected_projects(["shared/driver/protocol.h"]).values()))

    def test_uac_helper_and_arklight_library_dependencies(self):
        for name in ("usermode", "setup"):
            self.assertTrue(ci_changes.affected_projects(["apps/uac_desktop/uacdesk.cpp"])[name])
        self.assertTrue(ci_changes.affected_projects(["shared/platform/service/Service.cpp"])["arklight"])

    def test_classifier_change_rechecks_driver_and_usermode(self):
        self.assertTrue(all(ci_changes.affected_projects(["tools/ci_changes.py"]).values()))

    def test_monitor_test_change_runs_qt_test_consumer(self):
        affected = ci_changes.affected_projects(["tests/native/monitor/KswordMonitorTests.cpp"])
        self.assertTrue(affected["usermode"])
        self.assertTrue(affected["any"])
        self.assertFalse(affected["driver"])

    def test_relocated_desktop_and_dwm_tests_trigger_their_consumers(self):
        desktop = ci_changes.affected_projects(["apps/desktop/process_dock/ProcessDock.cpp"])
        self.assertTrue(desktop["usermode"])
        self.assertTrue(desktop["setup"])
        tests = ci_changes.affected_projects(["tests/native/dwm_z_order/RuntimeTests.cpp"])
        self.assertTrue(tests["usermode"])
        self.assertFalse(tests["driver"])


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.env = {
            "EVENT_NAME": "push", "EVENT_BEFORE": "a" * 40, "EVENT_SHA": "b" * 40,
            "GITHUB_REPOSITORY": "owner/repo", "RUN_BRANCH": "main", "GITHUB_RUN_ID": "20",
            "BASE_REF": "main",
        }
        self.previous = {"id": 19, "status": "completed", "conclusion": "success", "head_sha": "a" * 40}

    def response(self, previous=None):
        return json.dumps({"workflow_runs": [{"id": 20}, self.previous if previous is None else previous]})

    def test_failed_cancelled_pending_or_missing_runs_force_full_build(self):
        for run in ({}, {**self.previous, "conclusion": "failure"},
                    {**self.previous, "conclusion": "cancelled"},
                    {**self.previous, "status": "in_progress"}):
            with self.subTest(run=run), patch.object(ci_changes, "command", return_value=self.response(run)):
                self.assertIsNone(ci_changes.changed_paths("ci.yml", self.env))

    def test_success_from_wrong_push_commit_is_not_a_baseline(self):
        with patch.object(ci_changes, "command", return_value=self.response({**self.previous, "head_sha": "c" * 40})):
            self.assertIsNone(ci_changes.changed_paths("ci.yml", self.env))

    def test_api_failure_or_invalid_response_forces_full_build(self):
        for error in (OSError("offline"), subprocess.CalledProcessError(1, "gh")):
            with patch.object(ci_changes, "command", side_effect=error):
                self.assertIsNone(ci_changes.changed_paths("ci.yml", self.env))
        for response in ("not json", "{}", '{"workflow_runs": null}'):
            with patch.object(ci_changes, "command", return_value=response):
                self.assertIsNone(ci_changes.changed_paths("ci.yml", self.env))

    def test_manual_run_does_not_query_history(self):
        with patch.object(ci_changes, "command") as command:
            self.assertIsNone(ci_changes.changed_paths("ci.yml", {**self.env, "EVENT_NAME": "workflow_dispatch"}))
            command.assert_not_called()

    def test_verified_push_preserves_unicode_and_whitespace_in_paths(self):
        paths = ["artifacts/bin/中文 文件.cpp", " leading space.json", 'a"b.json', "with\nnewline.json"]
        with patch.object(ci_changes, "command", side_effect=[self.response(), "", "\0".join(paths) + "\0"]) as command:
            self.assertEqual(paths, ci_changes.changed_paths("ci.yml", self.env))
            self.assertIn("--no-renames", command.call_args.args)
            self.assertIn("-z", command.call_args.args)

    def test_unavailable_push_base_forces_full_build(self):
        with patch.object(ci_changes, "command", side_effect=[self.response(), subprocess.CalledProcessError(1, "git")]):
            self.assertIsNone(ci_changes.changed_paths("ci.yml", self.env))

    def test_pr_uses_merge_base_and_does_not_require_push_before(self):
        with patch.object(ci_changes, "command", side_effect=[self.response(), "", "merge-base\n", "apps/launcher/main.cpp\0"]) as command:
            paths = ci_changes.changed_paths("ci.yml", {**self.env, "EVENT_NAME": "pull_request", "EVENT_BEFORE": ""})
            self.assertEqual(["apps/launcher/main.cpp"], paths)
            self.assertIn("merge-base", command.call_args.args)

    def test_git_rename_includes_both_project_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(root), "-c", "commit.gpgsign=false",
                     "-c", f"core.hooksPath={root / 'disabled-hooks'}", *args],
                    stderr=subprocess.STDOUT,
                )
            git("init", "-q")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            (root / "apps/launcher").mkdir(parents=True)
            (root / "apps/uac_desktop").mkdir()
            (root / "apps/launcher/source.cpp").write_text("unchanged", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "baseline")
            git("mv", "apps/launcher/source.cpp", "apps/uac_desktop/source.cpp")
            git("commit", "-qm", "move")
            raw = ci_changes.command("git", "-C", str(root), "diff", "--no-renames", "--name-only", "-z", "HEAD~1", "HEAD", "--")
            self.assertEqual({"apps/launcher/source.cpp", "apps/uac_desktop/source.cpp"}, set(raw.rstrip("\0").split("\0")))


if __name__ == "__main__":
    unittest.main()
