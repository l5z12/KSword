"""Check registered bilingual guides and their local file links (no network)."""

import json
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def local_links(text: str):
    """Read inline Markdown and HTML links outside fenced code blocks.

    Fragment anchors are left to the renderer; this audit checks file targets.
    Reference-style links must use explicit inline links in registered guides.
    """
    text = re.sub(r"(?ms)^\s*(`{3,}|~{3,})[^\n]*\n.*?^\s*\1\s*$", "", text)
    targets = re.findall(r"\]\((<[^>]+>|[^\s)]+)(?:\s+\"[^\"]*\")?\)", text)
    targets += re.findall(r'(?:href|src)\s*=\s*[\"\']([^\"\']+)[\"\']', text, re.I)
    for target in targets:
        parsed = urlsplit(target.strip("<>"))
        if not parsed.scheme and not parsed.netloc and parsed.path:
            yield unquote(parsed.path)


def audit(root: Path) -> list[str]:
    errors = []
    pairs = json.loads((root / "docs/catalog.json").read_text(encoding="utf-8"))
    seen = set()
    for pair in pairs:
        for language, other in (("en", "zh"), ("zh", "en")):
            name = pair[language]
            path = root / name
            if name in seen:
                errors.append(f"Duplicate guide registration: {name}")
            seen.add(name)
            if not path.is_file():
                errors.append(f"Missing {language} guide: {name}")
                continue
            resolved = [(path.parent / link).resolve() for link in local_links(path.read_text(encoding="utf-8-sig"))]
            if (root / pair[other]).resolve() not in resolved:
                errors.append(f"{name}: missing link to {pair[other]}")
            for target in resolved:
                if not target.is_relative_to(root.resolve()):
                    errors.append(f"{name}: link escapes repository: {target}")
                elif not target.exists():
                    errors.append(f"{name}: missing local target: {target.relative_to(root.resolve()).as_posix()}")
    return errors


def main() -> int:
    try:
        errors = audit(ROOT)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Invalid documentation catalog: {error}")
        return 1
    for error in errors:
        print(error)
    print(f"Documentation audit: {len(errors)} error(s).")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
