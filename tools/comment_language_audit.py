"""Reject Chinese prose in first-party C/C++, Python, and XML comments.

This portable check skips runtime strings and vendored sources. It is a language
regression check, not a substitute for reviewing the meaning of comments.
"""

from __future__ import annotations

import ast
import io
from pathlib import Path
import re
import tokenize
from xml.parsers import expat

from project_audit import git_files


ROOT = Path(__file__).resolve().parents[1]
VENDORED = ("third_party/", "apps/setup/fltk/", "apps/desktop/include/ads/")
CPP_SUFFIXES = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".inc", ".inl", ".rc", ".yar"}
XML_SUFFIXES = {".vcxproj", ".filters", ".props", ".targets", ".qrc", ".ui", ".svg", ".xml", ".manifest"}
HAN = re.compile(r"[\u3400-\u9fff\U00020000-\U0002ffff]")
# Consume strings and numeric digit separators before looking for comments.
# Raw strings may contain quotes, newlines, and apparent comment delimiters.
CPP_TOKENS = re.compile(
    r'R"(?P<delimiter>[^\s()\\]{0,16})\([\s\S]*?\)(?P=delimiter)"'
    r'|"(?:\\[\s\S]|[^"\\])*"'
    r"|\b[0-9][A-Za-z0-9_'.]*"
    r"|'(?:\\[\s\S]|[^'\\\r\n])*'"
    r"|(?P<comment>/\*[\s\S]*?\*/|//(?:\\\r?\n|[^\r\n])*)"
)


def comments(path: Path, text: str):
    """Yield (line number, comment/docstring text) without runtime literals."""
    if path.suffix in CPP_SUFFIXES:
        line, previous = 1, 0
        for match in CPP_TOKENS.finditer(text):
            if match["comment"] is not None:
                line += text.count("\n", previous, match.start())
                previous = match.start()
                yield line, match["comment"]
    elif path.suffix in XML_SUFFIXES:
        parser = expat.ParserCreate()
        found = []
        parser.CommentHandler = lambda comment: found.append((parser.CurrentLineNumber, comment))
        parser.Parse(text, True)
        yield from found
    elif path.suffix == ".py":
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                yield token.start[0], token.string
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                docstring = ast.get_docstring(node, clean=False)
                if docstring is not None:
                    yield node.body[0].lineno, docstring


def has_chinese_prose(comment: str) -> bool:
    """Allow inline literal examples in backticks; check the surrounding prose."""
    prose = re.sub(r"(?<!`)`[^`\r\n]+`(?!`)", "", comment)
    return bool(HAN.search(prose))


def audit(root: Path = ROOT) -> list[str]:
    errors = []
    for name in git_files(root):
        path = Path(name)
        if name.startswith(VENDORED) or path.suffix not in CPP_SUFFIXES | XML_SUFFIXES | {".py"}:
            continue
        try:
            text = (root / path).read_text(encoding="utf-8-sig")
            # Most files need no tokenization at all.
            if not HAN.search(text):
                continue
            for line, comment in comments(path, text):
                if has_chinese_prose(comment):
                    errors.append(f"{name}:{line}: write comment prose in English")
        except (OSError, UnicodeError, SyntaxError, tokenize.TokenError, expat.ExpatError) as error:
            errors.append(f"{name}: cannot inspect comments: {error}")
    return errors


def main() -> int:
    errors = audit()
    for error in errors:
        print(error)
    print(f"Comment language audit: {len(errors)} issue(s).")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
