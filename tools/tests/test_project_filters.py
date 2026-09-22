"""Verify stable project filters without flattening shared modules."""

from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from project_filters import filter_name, render


class ProjectFilterTests(unittest.TestCase):
    def test_shared_inputs_use_repository_paths(self):
        self.assertEqual("shared\\ark_client", filter_name("apps/desktop/App.vcxproj", "..\\..\\shared\\ark_client\\Client.h"))
        self.assertEqual("process_dock", filter_name("apps/desktop/App.vcxproj", "process_dock\\ProcessDock.cpp"))

    def test_pairs_stay_together_with_stable_unique_parent_filters(self):
        source = '<Project><ItemGroup><ClInclude Include="feature/nested/Record.h"/><ClCompile Include="feature/nested/Record.cpp"/><ProjectReference Include="Other.vcxproj"/></ItemGroup></Project>'
        result = render("apps/example/App.vcxproj", source)
        self.assertEqual(result, render("apps/example/App.vcxproj", source))
        elements = list(ET.fromstring(result).iter())
        identifiers = [element.text for element in elements if element.tag.endswith("}UniqueIdentifier")]
        self.assertEqual(2, len(set(identifiers)))
        self.assertNotIn("{00000000-0000-0000-0000-000000000000}", identifiers)
        memberships = [element.text for element in elements if element.tag.endswith("}Filter") and not element.attrib]
        self.assertEqual(["feature\\nested", "feature\\nested"], memberships)
        self.assertNotIn("Other.vcxproj", result)

    def test_generated_inputs_are_named_without_evaluating_msbuild(self):
        self.assertEqual("generated", filter_name("apps/example/App.vcxproj", "$(IntDir)Generated.h"))


if __name__ == "__main__":
    unittest.main()
