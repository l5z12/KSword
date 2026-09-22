from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from driver_functional_ci.plan_gate import cli_commands


class DriverPlanCatalogTests(unittest.TestCase):
    def test_reads_split_help_registry_and_preserves_ioctl_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / "apps/cli"
            cli.mkdir(parents=True)
            (cli / "KswordCLI.cpp").write_text("// Dispatch only.\n", encoding="utf-8")
            (cli / "CliHelp.cpp").write_text(r'''
constexpr FamilyHelp kFamilyHelps[] = {
    { L"file", L"Files" },
};
constexpr CommandHelp kCommandHelps[] = {
    { L"file", L"read", L"file read", L"Read \"bytes\"", L"", L"Backed by IOCTL_KSWORD_ARK_READ_FILE." },
};
''', encoding="utf-8")
            commands, backed = cli_commands(root)
            self.assertEqual({("file", "read")}, commands)
            self.assertEqual({"READ_FILE": {"file"}}, backed)

    def test_missing_registry_fails_instead_of_returning_empty_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cli = root / "apps/cli"
            cli.mkdir(parents=True)
            (cli / "CliHelp.cpp").write_text("// No metadata.\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Missing literal help registry"):
                cli_commands(root)


if __name__ == "__main__":
    unittest.main()
