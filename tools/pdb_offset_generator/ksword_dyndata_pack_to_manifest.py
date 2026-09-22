"""Extracts a profile from the v4 pack JSON and outputs a plain-text manifest for ksword_dyndata_v4_blob.

Purpose: When the target machine has only the driver and KswordCLI, this downloads the PDB profile into the
driver. Since pack JSON parsing is currently only available in the GUI (Qt JSON), on machines without a GUI,
fields like `_EPROCESS.VadRoot` that come solely from the PDB profile will remain "Unavailable". This looks like
"this build lacks an offset table", but actually means "the offset table is in the package, just not applied".

This step performs **JSON-to-text conversion only**, touching no binary layout bytes: packing is
handled by `ksword_dyndata_v4_blob.cpp` using structures from the product headers. Manually copying
the layout will inevitably drift from the headers, and such drift will go undetected without errors.

Usage:
  python ksword_dyndata_pack_to_manifest.py --pack <pack.json> --pdb-guid <32hex>
         [--pdb-age N] [--image-base 0x...] [--output manifest.txt]
"""

import argparse
import io
import json
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pack", required=True)
    parser.add_argument("--pdb-guid", required=True,
                        help="32-bit hexadecimal, no hyphens; see PE's RSDS record")
    parser.add_argument("--pdb-age", type=int, default=None)
    parser.add_argument("--image-base", default="0",
                        help="The actual load base address of this module on the target machine; 0 means not declared")
    parser.add_argument("--flags", type=int, default=0)
    parser.add_argument("--output", default="-")
    args = parser.parse_args()

    wanted = args.pdb_guid.upper().replace("-", "")
    with io.open(args.pack, encoding="utf-8") as handle:
        pack = json.load(handle)

    hit = None
    for profile in pack.get("profiles", []):
        guid = str(profile.get("pdbGuid", "")).upper().replace("-", "")
        if guid != wanted:
            continue
        if args.pdb_age is not None and int(profile.get("pdbAge", -1)) != args.pdb_age:
            continue
        hit = profile
        break

    if hit is None:
        # Explicitly report "no profile in pack" rather than falling back to a similar build—that is precisely what this feature has always refused to do.
        sys.stderr.write("no profile in pack for pdbGuid=%s age=%s\n"
                         % (wanted, args.pdb_age))
        return 3

    image_base = int(args.image_base, 0)
    lines = []
    lines.append("# generated from %s" % args.pack)
    lines.append("profile %s" % hit.get("profileName", ""))
    lines.append("pdbName %s" % hit.get("pdbName", ""))
    lines.append("pdbGuid %s" % wanted)
    lines.append("pdbAge %d" % int(hit.get("pdbAge", 0)))
    lines.append("moduleName %s" % ("ntoskrnl.exe" if int(hit.get("moduleClassId", 0)) == 0
                                    else hit.get("pdbName", "")))
    lines.append("machine %d" % int(hit.get("machine", 0)))
    lines.append("timeDateStamp %d" % int(hit.get("timeDateStamp", 0)))
    lines.append("sizeOfImage %d" % int(hit.get("sizeOfImage", 0)))
    lines.append("imageBase %d" % image_base)
    lines.append("classId %d" % int(hit.get("moduleClassId", 0)))
    lines.append("flags %d" % args.flags)

    for group in hit.get("capabilityGroups", []):
        lines.append("group %d %d %d %d %s" % (
            int(group.get("groupId", 0)), int(group.get("flags", 0)),
            int(group.get("requiredItemCount", 0)), int(group.get("optionalItemCount", 0)),
            group.get("groupName", "")))

    for item in hit.get("items", []):
        lines.append("item %d %d %d %d %d %d %d %d %d %d" % (
            int(item.get("itemId", 0)), int(item.get("itemKind", 0)),
            int(item.get("flags", 0)), int(item.get("capabilityGroupId", 0)),
            int(item.get("valueLow", 0)), int(item.get("valueHigh", 0)),
            int(item.get("aux0", 0)), int(item.get("aux1", 0)),
            int(item.get("aux2", 0)), int(item.get("aux3", 0))))

    # Legacy (v1) field. `fields` contains [dictionary index, offset] pairs, but the **driver recognizes field IDs**,
    # These are not the same: dictionary indices come from the fieldDictionary's order, while field IDs are hardcoded in the protocol.
    # KSW_DYN_FIELD_ID_*. Therefore, look up the itemId by name in v4 items.
    # If an ID cannot be found, discard the entry rather than using the index as an ID; otherwise, the offset would be written to the wrong field.
    id_by_name = {}
    for item in hit.get("items", []):
        name = item.get("name")
        if name:
            id_by_name[name] = int(item.get("itemId", 0))

    dictionary = pack.get("fieldDictionary", [])
    emitted = 0
    unmapped = []
    for entry in hit.get("fields", []):
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        index, offset = int(entry[0]), int(entry[1])
        if index < 0 or index >= len(dictionary):
            continue
        name = dictionary[index]
        field_id = id_by_name.get(name)
        if field_id is None:
            unmapped.append(name)
            continue
        lines.append("field %d %d" % (field_id, offset))
        emitted += 1

    if unmapped:
        sys.stderr.write("note: %d legacy fields have no v4 itemId and were skipped: %s\n"
                         % (len(unmapped), ", ".join(sorted(unmapped)[:8])))

    text = "\n".join(lines) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        with io.open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        sys.stderr.write("wrote %s: %d v4 items, %d groups, %d legacy fields\n"
                         % (args.output, len(hit.get("items", [])),
                            len(hit.get("capabilityGroups", [])), emitted))
    return 0


if __name__ == "__main__":
    sys.exit(main())
