from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import acceptance_record


class AcceptanceStateTests(unittest.TestCase):
    def test_english_states_preserve_legacy_storage(self):
        for label, stored in acceptance_record.IMPLEMENTATION_STATES.items():
            self.assertEqual(stored, acceptance_record.implementation_value(label))
            self.assertEqual(stored, acceptance_record.implementation_value(stored))
            self.assertEqual(label, acceptance_record.implementation_label(stored))

    def test_invalid_state_reports_english_choices(self):
        with self.assertRaisesRegex(SystemExit, 'not-started, in-progress, implemented'):
            acceptance_record.implementation_value('invalid')


if __name__ == '__main__':
    unittest.main()
