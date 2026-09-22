import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import project_audit


class ProjectAuditTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "App").mkdir()
        (self.root / "App/main.cpp").write_text("", encoding="utf-8")
        self.tracked = {"App/main.cpp"}

    def write_project(self, project_items, filter_items=None):
        prefix = '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>'
        suffix = '</ItemGroup></Project>'
        (self.root / "App/App.vcxproj").write_text(prefix + project_items + suffix, encoding="utf-8")
        if filter_items is not None:
            (self.root / "App/App.vcxproj.filters").write_text(prefix + filter_items + suffix, encoding="utf-8")

    def audit(self):
        return project_audit.audit_project(self.root, "App/App.vcxproj", self.tracked)

    def test_matching_items_and_windows_path_separators(self):
        self.write_project('<ClCompile Include=".\\main.cpp"/>', '<ClCompile Include="main.cpp"/>')
        self.assertEqual([], self.audit())

    def test_missing_filters_is_reported(self):
        self.write_project('<ClCompile Include="main.cpp"/>')
        self.assertIn("missing .filters", self.audit()[0])

    def test_wrong_qt_item_type_and_missing_entry_are_reported(self):
        self.write_project('<QtMoc Include="main.cpp"/>', '<ClInclude Include="main.cpp"/>')
        errors = self.audit()
        self.assertTrue(any("missing QtMoc" in error for error in errors))
        self.assertTrue(any("wrong item type" in error for error in errors))

    def test_duplicate_items_are_reported(self):
        item = '<ClCompile Include="main.cpp"/>'
        self.write_project(item, item * 2)
        self.assertTrue(any("duplicate ClCompile" in error for error in self.audit()))

    def test_nested_source_items_in_project_metadata_are_rejected(self):
        self.write_project(
            '<ProjectReference Include="Library.vcxproj"><Project>{GUID}'
            '<ItemGroup><ClCompile Include="main.cpp"/></ItemGroup>'
            '</Project></ProjectReference>', '')
        self.assertTrue(any("nested XML" in error for error in self.audit()))

    def test_untracked_and_wrong_case_inputs_are_reported(self):
        for name in ("untracked.cpp", "Main.cpp"):
            with self.subTest(name=name):
                item = f'<ClCompile Include="{name}"/>'
                self.write_project(item, item)
                self.assertTrue(any("not tracked" in error for error in self.audit()))

    def test_deleted_tracked_source_is_reported(self):
        item = '<ClCompile Include="main.cpp"/>'
        self.write_project(item, item)
        (self.root / "App/main.cpp").unlink()
        self.assertTrue(any("missing input" in error for error in self.audit()))

    def test_properties_are_left_to_msbuild(self):
        item = '<ClCompile Include="$(GeneratedDir)\\file.cpp"/>'
        self.write_project(item, item)
        self.assertEqual([], self.audit())

    def test_known_generated_input_is_allowed_but_not_arbitrary_generated_files(self):
        for name, allowed in (("PayloadResources.h", True), ("unknown.h", False)):
            item = f'<ClInclude Include="../apps/setup/generated/{name}"/>'
            self.write_project(item, item)
            self.assertEqual(allowed, not self.audit())

    def test_malformed_xml_is_an_actionable_failure(self):
        self.write_project('<ClCompile', '')
        self.assertTrue(self.audit())

    def test_empty_repository_is_not_a_passing_audit(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(["No tracked MSBuild projects found."], project_audit.audit(self.root))


if __name__ == "__main__":
    unittest.main()
