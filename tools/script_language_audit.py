"""Require English in first-party scripts, with explicit literal-data exceptions."""

from __future__ import annotations

import json
from pathlib import Path
import re

from project_audit import git_files

ROOT = Path(__file__).resolve().parents[1]
SUFFIXES = {'.py', '.ps1', '.psm1', '.sh', '.bat', '.cmd', '.lua'}
HAN = re.compile(r'[\u3400-\u9fff\U00020000-\U0002ffff]')
VENDORED = ('third_party/', 'apps/setup/fltk/', 'apps/desktop/include/ads/')


def script_path(name: str) -> bool:
    return not name.startswith(VENDORED) and (
        Path(name).suffix in SUFFIXES
        or name.startswith('.github/workflows/') and Path(name).suffix in {'.yml', '.yaml'}
    )


def audit(root: Path = ROOT) -> list[str]:
    exceptions = json.loads((root / 'tools/script_language_exceptions.json').read_text(encoding='utf-8'))
    errors = []
    for name in git_files(root):
        if not script_path(name):
            continue
        try:
            text = (root / name).read_text(encoding='utf-8-sig')
        except (OSError, UnicodeError) as error:
            errors.append(f'{name}: cannot inspect script: {error}')
            continue
        allowed = exceptions.get(name, {})
        for line_number, line in enumerate(text.splitlines(), 1):
            if not HAN.search(line):
                continue
            if line.strip() in allowed.get('lines', []) and allowed.get('reason', '').strip():
                continue
            errors.append(f'{name}:{line_number}: use English; document exact input/fixture literals separately')
    return errors


def main() -> int:
    errors = audit()
    for error in errors:
        print(error)
    print(f'Script language audit: {len(errors)} issue(s).')
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())
