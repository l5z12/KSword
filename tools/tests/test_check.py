import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check


class CheckRunnerTests(unittest.TestCase):
    def test_failure_does_not_skip_other_checks_or_return_success(self):
        output = io.StringIO()
        with patch.object(check.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 2), subprocess.CompletedProcess([], 0)]) as run:
            with contextlib.redirect_stdout(output):
                self.assertEqual(1, check.run_checks(["theme", "hvm-ept"]))
        self.assertEqual(2, run.call_count)
        self.assertIn("FAIL theme", output.getvalue())
        self.assertIn("PASS hvm-ept", output.getvalue())
        self.assertEqual(sys.executable, run.call_args.args[0][0])

    def test_cannot_launch_check_is_a_failure(self):
        with patch.object(check.subprocess, "run", side_effect=OSError("cannot launch")):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, check.run_checks(["theme"]))

    def test_json_scan_uses_git_paths_and_reports_all_invalid_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            for name, contents in (("中文 文件.json", '\ufeff{"ok": true}'), ("bad.json", "["), ("also bad.json", "{")):
                (root / name).write_text(contents, encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True, capture_output=True)
            (root / "untracked.json").write_text("not JSON", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(1, check.validate_json(root))
            self.assertIn("bad.json:", output.getvalue())
            self.assertIn("also bad.json:", output.getvalue())
            self.assertIn("3 tracked JSON files; 2 failed", output.getvalue())
            self.assertNotIn("untracked.json", output.getvalue())


if __name__ == "__main__":
    unittest.main()
