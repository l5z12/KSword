import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from docs_audit import audit, local_links


class DocumentationTests(unittest.TestCase):
    def test_external_fragments_and_fenced_examples_are_not_file_targets(self):
        text = '''[Web](https://example.com) [Anchor](#heading)
```md
[Example](missing.md)
```
<a href="guide.md#part">Guide</a> ![Image](assets/space%20name.png)
'''
        self.assertEqual(["assets/space name.png", "guide.md"], list(local_links(text)))

    def test_missing_translation_broken_link_and_escape_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "docs/catalog.json").write_text(json.dumps([{"en": "README.md", "zh": "docs/zh.md"}]))
            (root / "README.md").write_text('[中文](docs/zh.md) [Broken](missing.md) [Escape](../outside.md)')
            errors = audit(root)
            self.assertTrue(any('Missing zh guide' in error for error in errors))
            self.assertTrue(any('missing local target: missing.md' in error for error in errors))
            self.assertTrue(any('escapes repository' in error for error in errors))
            (root / "README.md").write_text('[中文](docs/zh.md)')
            (root / "docs/zh.md").write_text('[English](../README.md)')
            self.assertEqual([], audit(root))
            (root / "docs/zh.md").write_text('Missing reciprocal link')
            self.assertIn('missing link to README.md', audit(root)[0])


if __name__ == "__main__":
    unittest.main()
