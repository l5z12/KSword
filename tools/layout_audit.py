"""Keep tracked source paths portable and the repository root intentional."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
import re

from project_audit import git_files


ROOT = Path(__file__).resolve().parents[1]
ROOT_DIRECTORIES = {
    ".cert", ".claude", ".github", "apps", "archive", "build", "docs",
    "drivers", "integrations", "scripts", "shared", "tests", "third_party", "tools",
}
ROOT_FILES = {
    ".clang-tidy", ".editorconfig", ".gitattributes", ".gitignore", "AGENTS.md",
    "COMMUNITY_COVENANT.md", "CONTRIBUTING.md", "Directory.Build.targets",
    "KSword.sln", "LICENSE", "README.md",
}
CPP_ROOTS = ("apps/", "integrations/", "shared/", "tests/native/")
VENDORED = ("apps/setup/fltk/", "apps/desktop/include/ads/")
CONVENTIONAL_CPP_NAMES = {
    "main.cpp", "dllmain.cpp", "pch.cpp", "pch.h", "stdafx.cpp", "stdafx.h",
    "framework.h", "resource.h",
}
SOURCE_SUFFIXES = {".cpp", ".cc", ".cxx", ".h", ".hpp", ".inl"}


def audit_paths(paths: list[str]) -> list[str]:
    errors = []
    seen = {}
    for name in sorted(paths):
        path = PurePosixPath(name)
        if name.casefold() in seen:
            errors.append(f"Case-insensitive path collision: {seen[name.casefold()]} and {name}")
        seen[name.casefold()] = name
        if len(path.parts) == 1:
            if name not in ROOT_FILES:
                errors.append(f"Unexpected root file: {name}; place it in its owning directory")
        elif path.parts[0] not in ROOT_DIRECTORIES:
            errors.append(f"Unexpected root directory: {name}")
        if name.endswith((".vcxproj.user", ".cbt")) or path.name == ".qmake.stash":
            errors.append(f"Local build or IDE state must not be tracked: {name}")
        if name.startswith("drivers/") and path.suffix in {".c", ".h", ".asm"}:
            if any(not re.fullmatch(r"[a-z][a-z0-9_]*", part) for part in path.parts[:-1]):
                errors.append(f"Driver source directories must use snake_case: {name}")
            if not re.fullmatch(r"[a-z][a-z0-9_]*", path.stem):
                errors.append(f"C driver module filenames must use snake_case: {name}")
        if not name.startswith(CPP_ROOTS) or name.startswith(VENDORED) or path.suffix not in SOURCE_SUFFIXES:
            continue
        if any(not re.fullmatch(r"[a-z][a-z0-9_]*", part) for part in path.parts[:-1]):
            errors.append(f"First-party source directories must use snake_case: {name}")
        if path.name not in CONVENTIONAL_CPP_NAMES and not re.fullmatch(r"[A-Z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)*", path.stem):
            errors.append(f"C++ module filenames must use PascalCase: {name}")
    return errors


def main() -> int:
    errors = audit_paths(git_files(ROOT))
    for error in errors:
        print(error)
    print(f"Repository layout audit: {len(errors)} error(s).")
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
