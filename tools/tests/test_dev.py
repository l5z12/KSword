"""Contributor commands must fail clearly and never run stale test binaries."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import dev


class DeveloperCommandTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ksword contributor ")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.msbuild = self.root / "VS with spaces/MSBuild.exe"
        self.msbuild.parent.mkdir()
        self.msbuild.touch()
        self.found = dev.Environment(self.msbuild, None, None)
        self.args = dev.argument_parser().parse_args(["test", "--target", "cli-tests"])

    def artifact(self, name="cli-tests"):
        path = self.root / dev.TARGETS[name].artifact.format(config="Release")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"test fixture")
        return path

    def test_core_tests_do_not_require_qt_or_wdk(self):
        self.assertEqual([], dev.prerequisite_errors(dev.selected_targets("tests"), self.found, "Release", "win32"))
        self.assertTrue(all(target.test and not target.qt for target in dev.selected_targets("tests")))

    def test_missing_msbuild_and_non_windows_have_actionable_errors(self):
        errors = dev.prerequisite_errors(dev.selected_targets("tests"), dev.Environment(None, None, None), "Release", "linux")
        self.assertTrue(any("tools/check.py" in error for error in errors))
        self.assertTrue(any("--msbuild" in error for error in errors))

    def test_explicit_invalid_msbuild_does_not_fall_back(self):
        missing = self.root / "missing.exe"
        with patch.object(dev.shutil, "which") as which:
            self.assertEqual(missing, dev.find_msbuild(str(missing), {}))
            which.assert_not_called()

    def test_directory_override_wins_over_a_valid_fallback(self):
        candidate = self.root / "qt"
        candidate.mkdir()
        (candidate / "qt.targets").touch()
        override = self.root / "typo"
        self.assertEqual(override, dev.find_directory(str(override), {}, (), (candidate,), "qt.targets"))
        self.assertEqual(candidate, dev.find_directory(None, {}, (), (candidate,), "qt.targets"))

    def test_monitor_needs_qtcore_but_not_qt_msbuild(self):
        errors = dev.prerequisite_errors(dev.selected_targets("monitor-tests"), self.found, "Debug", "win32")
        self.assertTrue(any("Qt6Cored.dll" in error for error in errors))
        self.assertFalse(any("qt.targets" in error for error in errors))

    def test_windows_environment_names_are_case_insensitive(self):
        path = self.root / "Qt integration"
        self.assertEqual(path, dev.find_directory(None, {"QTMSBUILD": str(path)}, ("QtMsBuild",), (), "qt.targets"))
        with patch.object(dev.shutil, "which") as which:
            self.assertEqual(self.msbuild, dev.find_msbuild(None, {"msbuild_path": str(self.msbuild)}))
            which.assert_not_called()

    def test_vswhere_uses_the_actual_program_files_location(self):
        vswhere = self.root / "Microsoft Visual Studio/Installer/vswhere.exe"
        vswhere.parent.mkdir(parents=True)
        vswhere.touch()
        result = subprocess.CompletedProcess([], 0, stdout=str(self.msbuild) + "\n")
        with patch.object(dev.shutil, "which", return_value=None), patch.object(dev.subprocess, "run", return_value=result) as run:
            self.assertEqual(self.msbuild, dev.find_msbuild(None, {"PROGRAMFILES(X86)": str(self.root)}))
            self.assertEqual(str(vswhere), run.call_args.args[0][0])

    def test_desktop_reuses_python_and_does_not_enable_signing(self):
        command = dev.build_command(dev.TARGETS["desktop"], self.args, self.found)
        self.assertEqual(str(self.msbuild), command[0])
        self.assertIn(f"/p:KswordI18nPythonExe={sys.executable}", command)
        self.assertIn("/p:KswordArkSkipAutoTestSign=true", command)
        self.assertIn("/p:PlatformToolset=v143", command)
        self.assertIn("/p:PreferredToolArchitecture=x64", command)

    def test_failed_build_never_runs_an_old_executable(self):
        self.artifact()
        with patch.object(dev, "ROOT", self.root), patch.object(dev.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "MSBuild")) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                dev.execute(self.args, self.found, {})
            self.assertEqual(1, run.call_count)

    def test_success_without_an_artifact_is_rejected(self):
        with patch.object(dev, "ROOT", self.root), patch.object(dev.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "missing or empty"):
                dev.execute(self.args, self.found, {})
            self.assertEqual(1, run.call_count)

    def test_success_with_empty_artifact_is_rejected(self):
        self.artifact().write_bytes(b"")
        with patch.object(dev, "ROOT", self.root), patch.object(dev.subprocess, "run"):
            with self.assertRaisesRegex(RuntimeError, "missing or empty"):
                dev.execute(self.args, self.found, {})

    def test_qt_test_environment_is_child_local_and_commands_preserve_spaces(self):
        self.args.target = "monitor-tests"
        artifact = self.artifact("monitor-tests")
        found = dev.Environment(self.msbuild, self.root / "Qt with spaces", None)
        original = {"PATH": "original", "KSWORD_QT_DIR": "another"}
        with patch.object(dev, "ROOT", self.root), patch.object(dev.subprocess, "run") as run:
            dev.execute(self.args, found, original)
            self.assertEqual([str(artifact)], run.call_args.args[0])
            self.assertEqual(self.root, run.call_args.kwargs["cwd"])
            self.assertTrue(run.call_args.kwargs["check"])
            self.assertEqual(str(found.qt), run.call_args.kwargs["env"]["KSWORD_QT_DIR"])
        self.assertEqual({"PATH": "original", "KSWORD_QT_DIR": "another"}, original)

    def test_dry_run_neither_builds_nor_runs_tests(self):
        self.args.dry_run = True
        with patch.object(dev.subprocess, "run") as run:
            dev.execute(self.args, self.found, {})
            run.assert_not_called()

    def test_cli_test_uses_help_only(self):
        self.args.target = "cli"
        artifact = self.artifact("cli")
        with patch.object(dev, "ROOT", self.root), patch.object(dev.subprocess, "run") as run:
            dev.execute(self.args, self.found, {})
            self.assertEqual([sys.executable, "tools/test_cli_help.py", "--exe", str(artifact)], run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
