"""Generate Visual Studio filters from project inputs and physical directories."""

from __future__ import annotations

import argparse
from pathlib import Path
import posixpath
import uuid
import xml.etree.ElementTree as ET

from project_audit import SOURCE_TYPES, git_files


ROOT = Path(__file__).resolve().parents[1]
NAMESPACE = "http://schemas.microsoft.com/developer/msbuild/2003"
ITEM_TYPES = SOURCE_TYPES | {"None", "Image", "Text", "Natvis", "CustomBuild"}
ET.register_namespace("", NAMESPACE)


def tag(name: str) -> str:
    return f"{{{NAMESPACE}}}{name}"


def filter_name(project: str, include: str) -> str:
    """Mirror local folders; identify shared inputs by repository-relative path."""
    path = include.replace("\\", "/")
    if any(marker in path for marker in ("$(", "%(", "@(", "*", "?")):
        return "generated"
    directory = posixpath.dirname(posixpath.normpath(path))
    if path.startswith("../"):
        target = posixpath.normpath(posixpath.join(posixpath.dirname(project), path))
        directory = posixpath.dirname(target) or "repository"
    return directory.replace("/", "\\")


def render(project: str, source: str) -> str:
    items = []
    for group in ET.fromstring(source):
        if group.tag.rsplit("}", 1)[-1] != "ItemGroup":
            continue
        for item in group:
            kind = item.tag.rsplit("}", 1)[-1]
            include = item.get("Include")
            if kind in ITEM_TYPES and include:
                items.append((kind, include, filter_name(project, include)))

    filters = set()
    for _, _, name in items:
        while name:
            filters.add(name)
            name = name.rpartition("\\")[0]

    result = ET.Element(tag("Project"), {"ToolsVersion": "4.0"})
    if filters:
        definitions = ET.SubElement(result, tag("ItemGroup"))
        for name in sorted(filters):
            definition = ET.SubElement(definitions, tag("Filter"), {"Include": name})
            identifier = uuid.uuid5(uuid.NAMESPACE_URL, f"ksword/filter/{project}/{name}")
            ET.SubElement(definition, tag("UniqueIdentifier")).text = "{" + str(identifier).upper() + "}"
    entries = ET.SubElement(result, tag("ItemGroup"))
    for kind, include, name in sorted(items, key=lambda item: (item[2], item[1], item[0])):
        entry = ET.SubElement(entries, tag(kind), {"Include": include})
        if name:
            ET.SubElement(entry, tag("Filter")).text = name
    ET.indent(result, space="  ")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(result, encoding="unicode") + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="update filters; default checks for drift")
    args = parser.parse_args()
    stale = []
    projects = git_files(ROOT, "*.vcxproj")
    for project in projects:
        source = ROOT / project
        target = Path(str(source) + ".filters")
        expected = render(project, source.read_text(encoding="utf-8-sig"))
        current = target.read_text(encoding="utf-8-sig") if target.is_file() else ""
        if current == expected:
            continue
        stale.append(project)
        if args.write:
            target.write_text(expected, encoding="utf-8", newline="\n")
        else:
            print(f"Stale filters: {project}; run python tools/project_filters.py --write")
    print(f"Checked {len(projects)} project filters; {len(stale)} {'updated' if args.write else 'stale'}.")
    return int(bool(stale) and not args.write)


if __name__ == "__main__":
    raise SystemExit(main())
