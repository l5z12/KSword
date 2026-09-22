"""Read the literal CLI help registry without compiling or opening a device."""

from dataclasses import dataclass
import ast
from pathlib import Path
import re


@dataclass(frozen=True)
class Command:
    family: str
    name: str
    syntax: str
    summary: str
    options: str
    notes: str


LITERAL = r'L"((?:\\.|[^"\\])*)"'


def read_catalog(path: Path) -> tuple[list[tuple[str, str]], list[Command]]:
    source = path.read_text(encoding="utf-8-sig")
    def block(name: str) -> str:
        match = re.search(r'constexpr \w+ ' + name + r'\[\]\s*=\s*\{(.*?)\n\s*\};', source, re.S)
        if not match:
            raise ValueError(f"Missing literal help registry: {name}")
        return match[1]
    def strings(row: str) -> list[str]:
        return [ast.literal_eval('"' + value + '"') for value in re.findall(LITERAL, row)]
    families = []
    for row in block("kFamilyHelps").splitlines():
        if not row.strip():
            continue
        values = strings(row)
        if len(values) != 2:
            raise ValueError(f"Expected a literal family registration: {row}")
        families.append(tuple(values))
    commands = []
    for row in block("kCommandHelps").splitlines():
        if not row.strip():
            continue
        values = strings(row)
        if len(values) != 6:
            raise ValueError(f"Expected six literal command fields: {row}")
        commands.append(Command(*values))
    names = [name for name, _ in families]
    keys = [(command.family, command.name) for command in commands]
    if not names or not keys or len(set(names)) != len(names) or len(set(keys)) != len(keys):
        raise ValueError("Empty or duplicate CLI help registrations")
    if unknown := {command.family for command in commands} - set(names):
        raise ValueError(f"Commands without a family: {sorted(unknown)}")
    return families, commands
