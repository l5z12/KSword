from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cli_catalog import read_catalog

FAMILY = '    { L"file", L"Files" },'
COMMAND = r'    { L"file", L"read", L"file read", L"Read \"bytes\"", L"--path C:\\file", L"" },'


def source(family=FAMILY, commands=COMMAND):
    return f'constexpr FamilyHelp kFamilyHelps[] = {{\n{family}\n}};\nconstexpr CommandHelp kCommandHelps[] = {{\n{commands}\n}};\n'


class CatalogTests(unittest.TestCase):
    def parse(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'help.cpp'
            path.write_text(text, encoding='utf-8')
            return read_catalog(path)

    def test_escaped_literals_preserve_help_text(self):
        families, commands = self.parse(source())
        self.assertEqual([('file', 'Files')], families)
        self.assertEqual('Read "bytes"', commands[0].summary)
        self.assertEqual('--path C:\\file', commands[0].options)

    def test_duplicate_commands_and_families_are_errors(self):
        for text in (source(commands=COMMAND + '\n' + COMMAND), source(family=FAMILY + '\n' + FAMILY)):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'duplicate'):
                self.parse(text)

    def test_unregistered_family_and_nonliteral_rows_are_errors(self):
        with self.assertRaisesRegex(ValueError, 'without a family'):
            self.parse(source(family=FAMILY.replace('file', 'disk')))
        with self.assertRaisesRegex(ValueError, 'six literal'):
            self.parse(source(commands=COMMAND.replace('L"file"', 'SomeConstant')))
        with self.assertRaisesRegex(ValueError, 'Missing literal'):
            self.parse('')


if __name__ == "__main__":
    unittest.main()
