"""Build gate for the C command catalog consumed by the hvm_ctl probe CLI.

hvm_ctl is a functional test probe, not a release artifact: the main program neither compiles this directory nor bundles its
command help text into language packs. Therefore, this check only verifies the directory's internal consistency (unique
command names and a dispatch branch for each command), without asserting that corresponding entries exist in the GUI language
pack—since that assertion presupposes the directory is consumed by the main program, a dependency that has been removed.
"""
import json
from pathlib import Path
import re


def main():
    here = Path(__file__).resolve().parent
    source = (here / "HvmCommandCatalog.c").read_text(encoding="utf-8-sig")
    catalog = source.split("kGCommands[] = {", 1)[1].split("\n};", 1)[0]
    literal = r'"(?:\\.|[^"\\])*"'
    records = re.findall(r"^\s*\{\s*(" + literal + r"),\s*(" + literal + r"),\s*(" +
                         literal + r"),\s*(" + literal + r"),\s*(kHvm\w+),", catalog, re.M)
    assert records, "No command definitions"
    names = [json.loads(r[0]) for r in records]
    assert len(set(names)) == len(names), "Duplicate command name"
    strings = {json.loads(s) for r in records for s in r[1:4]}
    strings.update(json.loads(s) for s in re.findall(r"\{\s*(" + literal + r"),\s*kHvm\w+,", catalog))
    engine = (here / "HvmCommandEngine.c").read_text(encoding="utf-8-sig")
    handlers = set(re.findall(r"case (kHvm\w+):", engine))
    handlers.update(re.findall(r"spec->handler == (kHvm\w+)", engine))
    assert not ({r[4] for r in records} - handlers), "Command has no dispatch handler"
    print(f"HVM_CATALOG_AUDIT=PASS commands={len(records)} texts={len(strings)}")


if __name__ == "__main__":
    main()
