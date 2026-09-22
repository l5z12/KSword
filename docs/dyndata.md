# Adding a DynData-backed feature

[简体中文](zh-CN/dyndata.md) · [Documentation index](README.md)

Keep field IDs, PDB profiles, R0 capabilities, R3 presentation, and consumers in
agreement when adding a feature that depends on private structure offsets. A
missing exact profile must disable the feature instead of making the driver guess.

## Define the capability

Identify the structure, field, and consumer, such as `_EPROCESS.Token` or
`_TOKEN.UserAndGroups`. Separate required fields from optional diagnostics:
missing required fields disable the operation; optional fields affect detail only.
Append an appropriate `KSW_CAP_*` capability in `shared/driver/`. Do not reuse an
unrelated bit. Append field IDs without renumbering existing entries.

## Update shared and R0 definitions

In `shared/driver/KswordArkDynDataIoctl.h`, append `KSW_DYN_FIELD_ID_*`, update
`KSW_DYN_FIELD_ID_MAX`, and increase `KSW_DYN_PROFILE_MAX_FIELDS`,
`KSW_DYN_PROFILE_EX_MAX_ITEMS`, or `KSW_DYN_V4_MAX_ITEMS_PER_MODULE` if necessary.
Document the new fields' source, purpose, and compatibility.

| File | Required update |
| --- | --- |
| `drivers/ark/include/ark/ark_dyndata.h` | Add offset members to `KswDynKernelOffsets` or the owning module structure, with matching source members. |
| `src/features/dyndata/dyndata_loader.c` | Initialize to `KSW_DYN_OFFSET_UNAVAILABLE`; add field-ID to offset/source pointer mappings. |
| `src/features/dyndata/dyndata_validate.c` | Add the `g_KswordDynFieldBindings` descriptor and source lookup; compute capabilities from required fields in `kswordArkDynDataComputeCapabilities`. |

The two `src/` paths above are relative to `drivers/ark/`.

## Update profile tools and R3

Under `tools/pdb_offset_generator/`, update:

- `ksword_pdb_profile_generator.py`: `FIELD_MAP` maps profile names to PDB types/members.
- `ksword_ntos_pdb_deep_offsets.py`: `KSWORD_ITEM_ALIASES` provides audit aliases.
- `ksword_profile_release_sync.py`: `KNOWN_FIELD_IDS` maps names to shared IDs.
- Any relevant field-coverage audit.

Confirm generated fields appear in `ark_dyndata_pack_v4.json` items. Releases use
the v4 matrix, not v1/v2/v3 matrices or loose profiles. Updating only the driver
must leave the operation disabled when the profile lacks its required fields.

Update `apps/desktop/kernel_dock/` capability labels, short/full PDB field
names, and unavailable-feature explanations. Add device operations through
`ArkDriverClient`; Dock code must not issue KswordARK `DeviceIoControl` directly.

## Consume private fields

1. Obtain `kswordArkDynDataSnapshot` and use that snapshot consistently.
2. Check the capability and every required offset.
3. For writes, prefer `KSW_DYN_FIELD_SOURCE_PDB_PROFILE`; never substitute guessed
   or old static offsets.
4. Bound object-derived pointers, indices, and lengths.
5. Guard private-memory access with `__try/__except` and the applicable safe-read
   helpers; exception handling does not replace ownership or range checks.
6. Verify lifetime before replacing a pointer. Prefer in-place updates; do not
   point private structures at stack storage or temporary pool allocations.
7. Return an explicit failing `NTSTATUS` instead of silently claiming success.

## Validate

- Build the driver and affected user-mode consumers, including Qt after shared-header changes.
- Validate the generated pack with release sync.
- Verify present/source/capability information in KernelDock.
- Check that absent or mismatched profiles disable the feature with an explanatory error.
- Distinguish API success, API failure followed by a private-offset path, and
  private-offset validation failure in runtime evidence.
