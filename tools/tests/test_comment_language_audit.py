from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import comment_language_audit as audit


class CommentLanguageAuditTests(unittest.TestCase):
    def test_literal_examples_do_not_exempt_surrounding_prose(self):
        self.assertFalse(audit.has_chinese_prose('For example, `中文` must round-trip.'))
        self.assertTrue(audit.has_chinese_prose('中文 explanation of `中文`.'))
        self.assertTrue(audit.has_chinese_prose('```中文```'))

    def test_cpp_runtime_literals_and_digit_separators_are_not_comments(self):
        source = ('auto text = u8"中文 // text";\n'
                  'auto raw = LR"tag(中文 " /* text */)tag";\n'
                  "auto quote = '\\''; auto size = 10'000; // 中文\n"
                  '/* 中文\ncontinued */\n')
        self.assertEqual(
            [(3, '// 中文'), (4, '/* 中文\ncontinued */')],
            list(audit.comments(Path('test.cpp'), source)),
        )

    def test_cpp_continued_comment_keeps_the_next_line(self):
        source = '// English \\\n中文\nconst char* text = "中文";\n'
        self.assertEqual([(1, '// English \\\n中文')], list(audit.comments(Path('test.h'), source)))

    def test_python_distinguishes_docstrings_from_runtime_strings(self):
        source = ('"""中文 module"""\n'
                  'message = "中文 # literal"\n'
                  '# 中文 comment\n'
                  'async def example():\n'
                  '    """中文 function"""\n'
                  '    return "中文"\n')
        self.assertEqual(
            [(1, '中文 module'), (3, '# 中文 comment'), (5, '中文 function')],
            sorted(audit.comments(Path('test.py'), source)),
        )

    def test_xml_text_and_attributes_are_not_comments(self):
        source = '<item title="中文">中文<![CDATA[<!-- 中文 -->]]></item>\n<!-- 中文 -->'
        self.assertEqual([(2, ' 中文 ')], list(audit.comments(Path('test.qrc'), source)))

    def test_audit_skips_vendored_code_and_reports_bad_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test.cpp').write_text('// 中文\n', encoding='utf-8')
            (root / 'broken.py').write_text('"""中文', encoding='utf-8')
            names = ['test.cpp', 'broken.py', 'third_party/not-present.cpp', 'guide.md']
            with patch.object(audit, 'git_files', return_value=names):
                errors = audit.audit(root)
            self.assertEqual(2, len(errors))
            self.assertIn('test.cpp:1:', errors[0])
            self.assertIn('broken.py: cannot inspect comments:', errors[1])


if __name__ == '__main__':
    unittest.main()
