#!/usr/bin/env python3
"""Audit KSword theme colour tokens for use outside Qt Style Sheets.

Theme.h exposes two families of colour accessors:

* dynamic tokens return a Qt Style Sheet palette role such as ``palette(base)``;
  Qt re-resolves them on every repaint, so they follow theme changes for free;
* static tokens (``*ColorHex()``) return a concrete ``#RRGGBB`` at call time.

Only a style sheet can resolve ``palette(...)``.  It is a QSS-only extension:
QTextDocument's CSS parser (rich text on QLabel/QTextEdit), QColor's string
constructor and any consumer in another process all fail to parse it, and they
fail *silently* -- the declaration is dropped and the element keeps its
inherited colour.  Nothing warns at compile time, and the two accessor families
differ by a single word, so the mistake is easy to make and hard to see.

This audit fails the build when a dynamic token reaches one of those consumers.
The token list is parsed out of Theme.h, so new tokens are covered automatically.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SOURCE_SUFFIXES = {".cpp", ".h", ".hpp", ".cc", ".cxx"}
SKIPPED_DIRS = {"x64", "debug", "release", "backup", "moc", ".git"}
SKIPPED_FILE_PREFIXES = ("moc_", "qrc_", "ui_")

# Two ways to write dynamic tokens in Theme.h.
DYNAMIC_FUNCTION_RE = re.compile(
    r"inline QString ([A-Za-z_]\w*)\(\)\s*\{\s*return QStringLiteral\(\"palette\("
)
DYNAMIC_CONSTANT_RE = re.compile(
    r"inline const QString ([A-Za-z_]\w*)\s*=\s*QStringLiteral\(\"palette\("
)

# Contexts that consume dynamic tokens are forbidden. Each entry must specify 'how to fix' rather than just stating 'not allowed'.
# Mark in regression samples indicating 'this line should be reported'; only the line-end format is recognized, not mentions within the body.
EXPECT_MARK_RE = re.compile(r"//\s*KSWORD_AUDIT_EXPECT\s*$")

FORBIDDEN_CONTEXTS = (
    (
        re.compile(r"\bQColor\s*\("),
        "QColor's string constructor cannot parse palette(...), resulting in an invalid color",
    ),
    (
        re.compile(r"\bQ(?:Pen|Brush)\s*\("),
        "QPen/QBrush require real colors, palette(...) is not a color value",
    ),
    (
        re.compile(r"\.set(?:Foreground|Background)\s*\("),
        "QTextCharFormat/QTableWidgetItem follow the draw path, do not parse palette(...)",
    ),
    (
        re.compile(r"<(?:div|span|td|tr|p|font|b|i|h[1-6]|html|body)\b[^>]*style\s*="),
        "QLabel/QTextEdit rich text is parsed by QTextDocument, does not recognize palette(...)",
    ),
    (
        re.compile(r"\bsetHtml\s*\("),
        "setHtml goes through QTextDocument, does not recognize palette(...)",
    ),
    (
        re.compile(r"environment\.insert\s*\(|\bsetEnvironment\s*\("),
        "Cross-process parameter passing: The peer does not have this process's stylesheet and cannot parse palette(...)",
    ),
)


@dataclass
class Violation:
    path: Path
    line: int
    token: str
    reason: str
    snippet: str


def parse_dynamic_tokens(theme_header: Path) -> set[str]:
    text = theme_header.read_text(encoding="utf-8", errors="replace")
    tokens = set(DYNAMIC_FUNCTION_RE.findall(text))
    tokens |= set(DYNAMIC_CONSTANT_RE.findall(text))
    return tokens


def iter_source_files(source_root: Path):
    for path in sorted(source_root.rglob("*")):
        if path.suffix.lower() not in SOURCE_SUFFIXES or not path.is_file():
            continue
        if any(part.lower() in SKIPPED_DIRS for part in path.parts):
            continue
        if path.name.startswith(SKIPPED_FILE_PREFIXES):
            continue
        yield path


def build_code_mask(text: str) -> bytearray:
    """Mark which offsets are real code rather than literal or comment text.

    Statement boundaries must ignore punctuation inside string literals.  Inline
    CSS is the case that matters: a rich-text snippet whose style attribute reads
    padding-right:18px; carries a semicolon *inside* the literal, and treating it
    as a boundary truncates the statement right before the HTML tag -- exactly the
    context this audit needs to see.
    """
    mask = bytearray(len(text))
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        if character == "/" and index + 1 < length and text[index + 1] == "/":
            while index < length and text[index] != chr(10):
                index += 1
            continue
        if character == "/" and index + 1 < length and text[index + 1] == "*":
            index += 2
            while index + 1 < length and not (text[index] == "*" and text[index + 1] == "/"):
                index += 1
            index += 2
            continue
        if character == chr(34) or character == chr(39):
            quote = character
            index += 1
            while index < length:
                if text[index] == chr(92):
                    index += 2
                    continue
                if text[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        mask[index] = 1
        index += 1
    return mask


def statement_range(text: str, index: int, code_mask: bytearray) -> tuple[int, int]:
    """Bound the statement containing `index`.

    Style sheets are routinely built across a dozen lines, so a fixed line
    window either misses the consumer or drags in unrelated code.  Statement
    boundaries (`;`, `{`, `}`) track how the value is actually used -- but only
    when they appear in code; see build_code_mask for why.
    """
    start = index
    while start > 0 and not (text[start - 1] in ";{}" and code_mask[start - 1]):
        start -= 1
    end = index
    while end < len(text) and not (text[end] in ";{}" and code_mask[end]):
        end += 1
    return start, end


def audit_file(path: Path, tokens: set[str]) -> list[Violation]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if "ksword_theme::" not in text:
        return []
    violations: list[Violation] = []
    code_mask = build_code_mask(text)
    pattern = re.compile(r"ksword_theme::(" + "|".join(sorted(tokens)) + r")\b")
    for match in pattern.finditer(text):
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_text = text[line_start : text.find("\n", match.start())].strip()
        if line_text.startswith("//"):
            continue
        start, end = statement_range(text, match.start(), code_mask)
        statement = text[start:end]
        for context_re, reason in FORBIDDEN_CONTEXTS:
            if context_re.search(statement):
                violations.append(
                    Violation(
                        path=path,
                        line=text.count("\n", 0, match.start()) + 1,
                        token=match.group(1),
                        reason=reason,
                        snippet=line_text[:110],
                    )
                )
                break
    return violations


def run_self_test(fixture_root: Path, tokens: set[str]) -> int:
    """Check the rules against the committed fixture.

    A passing audit proves nothing on its own -- it also passes when the rules
    have quietly stopped matching.  The fixture pins both directions: every
    marked line must be reported, and nothing else may be.
    """
    expected: set[tuple[str, int]] = set()
    actual: set[tuple[str, int]] = set()
    for path in iter_source_files(fixture_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            if EXPECT_MARK_RE.search(line):
                expected.add((path.name, number))
        for item in audit_file(path, tokens):
            actual.add((item.path.name, item.line))

    missed = sorted(expected - actual)
    spurious = sorted(actual - expected)
    if not missed and not spurious:
        print(f"theme token audit self-test passed: {len(expected)} marked cases")
        return 0
    print("theme token audit self-test failed", file=sys.stderr)
    for name, number in missed:
        print(f"  - {name}:{number}: marked as a violation but the rules did not catch it", file=sys.stderr)
    for name, number in spurious:
        print(f"  - {name}:{number}: reported but not marked -- rule is over-matching", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--theme-header", type=Path)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the rules against tools/theme_token_audit_fixture instead of the source tree",
    )
    arguments = parser.parse_args()

    default_header = Path(__file__).resolve().parent.parent / 'apps/desktop/Theme.h'
    source_root: Path = arguments.source_root
    theme_header: Path = arguments.theme_header or (
        (source_root / "Theme.h") if source_root is not None else default_header
    )
    if source_root is None and not arguments.self_test:
        print("theme token audit: --source-root is required unless --self-test is given", file=sys.stderr)
        return 2
    if not theme_header.is_file():
        print(f"theme token audit: theme header not found: {theme_header}", file=sys.stderr)
        return 2

    tokens = parse_dynamic_tokens(theme_header)
    if not tokens:
        print(f"theme token audit: no dynamic tokens parsed from {theme_header}", file=sys.stderr)
        return 2

    if arguments.self_test:
        fixture_root = Path(__file__).resolve().parent / "theme_token_audit_fixture"
        if not fixture_root.is_dir():
            print(f"theme token audit: fixture not found: {fixture_root}", file=sys.stderr)
            return 2
        return run_self_test(fixture_root, tokens)

    violations: list[Violation] = []
    scanned = 0
    for path in iter_source_files(source_root):
        scanned += 1
        violations.extend(audit_file(path, tokens))

    if not violations:
        print(
            f"theme token audit passed: {len(tokens)} dynamic tokens, {scanned} source files"
        )
        return 0

    print("theme token audit failed: dynamic palette tokens used outside style sheets", file=sys.stderr)
    for item in violations:
        location = item.path.as_posix()
        print(f"  - {location}:{item.line}: {item.token} -- {item.reason}", file=sys.stderr)
        print(f"      {item.snippet}", file=sys.stderr)
    print(
        "  fix: use the matching *ColorHex() accessor, which returns a concrete #RRGGBB",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
