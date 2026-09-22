"""Protect the resident EPT checker against stale names and shared-root regressions."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hvm_local_ept_gate as gate


class ResidentEptGateTests(unittest.TestCase):
    def check_body(self, body: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.c").write_text(
                "void\nrestoreTransient(void)\n{\n" + body + "\n}\n",
                encoding="utf-8",
            )
            with patch.object(gate, "HVM", root), patch.object(
                gate, "CHECKED_FUNCTIONS",
                [("fixture.c", "restoreTransient", [gate.ALLOWED_OPERAND])],
            ):
                return gate.check_invept_operands()

    def test_transient_hierarchy_is_required(self):
        valid = (
            "kswordArkHvmAsmInveptSingle(transient->eptPointer != 0ULL "
            "? transient->eptPointer : runtime->eptPointer);"
        )
        self.assertEqual(self.check_body(valid), [])
        invalid = "kswordArkHvmAsmInveptSingle(runtime->eptPointer);"
        self.assertTrue(any("whitelist" in issue for issue in self.check_body(invalid)))

    def test_renamed_or_removed_call_cannot_silently_pass(self):
        issues = self.check_body("unknownInvept(runtime->eptPointer);")
        self.assertTrue(any("no recognized INVEPT call" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
