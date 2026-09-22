import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import script_language_audit as audit


class ScriptLanguageTests(unittest.TestCase):
    def test_only_exact_explained_literal_lines_are_exempt(self):
        literal = "$pattern = 'localized-input'"
        # Construct a non-English fixture without introducing another literal exception.
        non_english = chr(0x4E2D) + chr(0x6587)
        literal = literal.replace('localized-input', non_english)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            manifest = {'test.ps1': {'reason': 'Localized input pattern', 'lines': [literal]}}
            (root / 'tools/script_language_exceptions.json').write_text(json.dumps(manifest))
            (root / 'test.ps1').write_text(literal + '\nWrite-Host "' + non_english + '"', encoding='utf-8')
            with patch.object(audit, 'git_files', return_value=['test.ps1']):
                self.assertEqual(['test.ps1:2: use English; document exact input/fixture literals separately'], audit.audit(root))
            manifest['test.ps1']['reason'] = ''
            (root / 'tools/script_language_exceptions.json').write_text(json.dumps(manifest))
            with patch.object(audit, 'git_files', return_value=['test.ps1']):
                self.assertEqual(2, len(audit.audit(root)))

    def test_workflow_code_is_checked_but_bilingual_issue_forms_are_not_scripts(self):
        self.assertTrue(audit.script_path('.github/workflows/build.yml'))
        self.assertTrue(audit.script_path('tools/check.py'))
        self.assertFalse(audit.script_path('.github/ISSUE_TEMPLATE/bug_report.yml'))
        self.assertFalse(audit.script_path('third_party/tool.py'))


if __name__ == '__main__':
    unittest.main()
