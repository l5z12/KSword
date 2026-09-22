"""Catch path portability and local-build-state regressions before CI builds."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from layout_audit import audit_paths


class LayoutTests(unittest.TestCase):
    def test_case_collision_is_rejected_on_every_platform(self):
        errors = audit_paths(["shared/model/Record.h", "shared/model/record.h"])
        self.assertTrue(any("collision" in error for error in errors))

    def test_local_state_and_accidental_root_outputs_are_rejected(self):
        errors = audit_paths(["apps/desktop/App.vcxproj.user", "build.log", "artifacts/result.json"])
        self.assertEqual(3, len(errors))

    def test_source_conventions_keep_vendor_and_entry_names(self):
        self.assertEqual([], audit_paths([
            "KSword.sln", "apps/desktop/main.cpp", "shared/model/Record.Support.h",
            "apps/setup/fltk/FL/fl_draw.H", "drivers/ark/src/dispatch/ioctl_registry.c",
        ]))
        self.assertEqual(2, len(audit_paths(["apps/desktop/ProcessDock/process_view.cpp"])))

    def test_c_driver_modules_use_snake_case(self):
        self.assertEqual([], audit_paths(["drivers/ark/src/generated/ascii_font_8x12.h"]))
        self.assertEqual(2, len(audit_paths(["drivers/ark/src/Generated/AsciiFont.h"])))


if __name__ == "__main__":
    unittest.main()
