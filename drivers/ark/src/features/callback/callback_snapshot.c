/*++

Module Name:

    callback_snapshot.c

Abstract:

    Builds stable callback-row identities and an ordered enumeration snapshot hash.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"

#define KSWORD_ARK_CALLBACK_FNV64_OFFSET 14695981039346656037ULL
#define KSWORD_ARK_CALLBACK_FNV64_PRIME 1099511628211ULL

static ULONG64
KswordArkCallbackEnumHashBytes(
    _In_ ULONG64 initialHash,
    _In_reads_bytes_(byteCount) const VOID* bytes,
    _In_ SIZE_T byteCount
    )
/*++

Routine Description:

    Incrementally compute the hash of a byte sequence using the FNV-1a 64 algorithm with fixed parameters. This function only
    processes data already read into the controlled buffer and does not directly dereference unverified kernel addresses.

Arguments:

    InitialHash - Hash state of the previous data segment.
    Bytes - The byte sequence participating in the hash for this operation.
    ByteCount - Length of the byte sequence.

Return Value:

    Return value: Updated hash value; empty input preserves the original value.

--*/
{
    // Convert read-only input to a byte-by-byte view to avoid relying on structure field types.
    const UCHAR* currentByte = (const UCHAR*)bytes;
    // Continue calculation from the state passed by the caller to combine multiple stable fields.
    ULONG64 hashValue = initialHash;
    // Use explicit indexing to prevent the kernel compiler from introducing undefined pointer strides.
    SIZE_T index = 0U;

    // Null input is excluded from hashing and must not be dereferenced.
    if (bytes == NULL) {
        return hashValue;
    }

    // Perform standard FNV-1a updates in the original byte order as defined by the protocol.
    for (index = 0U; index < byteCount; ++index) {
        hashValue ^= (ULONG64)currentByte[index];
        hashValue *= KSWORD_ARK_CALLBACK_FNV64_PRIME;
    }

    // Returns: The incremental state to be used for the next field.
    return hashValue;
}

static ULONG64
kswordArkCallbackEnumBuildIdentityHash(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry
    )
/*++

Routine Description:

    Generate an identity hash from the stable semantic fields of the callback line. Page location, enumeration generation, and the identity
    hash itself are excluded from the input, so the same registration entry maintains a consistent identity across different pages.

Arguments:

    Entry - Callback row that has been filled and verified via read.

Return Value:

    Returns a non-zero stable identity hash; returns zero for invalid input.

--*/
{
    // normalize fieldFlags separately to exclude derived flags written by this function and the finalization phase.
    ULONG stableFieldFlags = 0UL;
    // All callback lines use the same public FNV-1a initial state.
    ULONG64 hashValue = KSWORD_ARK_CALLBACK_FNV64_OFFSET;

    // Calling convention requires valid lines; defensive check prevents null pointer dereference in exception paths.
    if (Entry == NULL) {
        return 0ULL;
    }

    // Derived hash fields must not reverse-influence identity, otherwise repeated enumeration cannot be stably compared.
    stableFieldFlags = Entry->fieldFlags &
        ~(KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH |
          KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION);
    // This local macro unifies field address and field width to prevent length drift across different call sites.
#define KSWORD_ARK_CALLBACK_HASH_FIELD(FieldName) \
    hashValue = KswordArkCallbackEnumHashBytes( \
        hashValue, \
        &Entry->FieldName, \
        sizeof(Entry->FieldName))

    // Base category, source, and query status determine the semantic identity of a row.
    KSWORD_ARK_CALLBACK_HASH_FIELD(callbackClass);
    KSWORD_ARK_CALLBACK_HASH_FIELD(source);
    KSWORD_ARK_CALLBACK_HASH_FIELD(status);
    // Use field flags excluding derived bits to preserve validity differences in other data.
    hashValue = KswordArkCallbackEnumHashBytes(
        hashValue,
        &stableFieldFlags,
        sizeof(stableFieldFlags));
    // Operation, object, and underlying status fields participate in identity differentiation.
    KSWORD_ARK_CALLBACK_HASH_FIELD(operationMask);
    KSWORD_ARK_CALLBACK_HASH_FIELD(objectTypeMask);
    KSWORD_ARK_CALLBACK_HASH_FIELD(lastStatus);
    // Address, context, and original storage values distinguish concurrent registrations.
    KSWORD_ARK_CALLBACK_HASH_FIELD(callbackAddress);
    KSWORD_ARK_CALLBACK_HASH_FIELD(contextAddress);
    KSWORD_ARK_CALLBACK_HASH_FIELD(registrationAddress);
    KSWORD_ARK_CALLBACK_HASH_FIELD(rawStorageValue);
    // Trust, removal policy, and module ownership determine the security semantics of this entry.
    KSWORD_ARK_CALLBACK_HASH_FIELD(trustFlags);
    KSWORD_ARK_CALLBACK_HASH_FIELD(removeBehavior);
    KSWORD_ARK_CALLBACK_HASH_FIELD(moduleBase);
    KSWORD_ARK_CALLBACK_HASH_FIELD(moduleSize);
    KSWORD_ARK_CALLBACK_HASH_FIELD(ownerRangeState);
    KSWORD_ARK_CALLBACK_HASH_FIELD(registrationType);
    // Name and altitude distinguish entries with different registration metadata at the same address.
    KSWORD_ARK_CALLBACK_HASH_FIELD(name);
    KSWORD_ARK_CALLBACK_HASH_FIELD(altitude);

    // Macro is valid only within this function to prevent polluting subsequent driver source code.
#undef KSWORD_ARK_CALLBACK_HASH_FIELD

    // The protocol uses zero to indicate 'not provided', so map the theoretical zero hash to one.
    return (hashValue != 0ULL) ? hashValue : 1ULL;
}

static BOOLEAN
kswordArkCallbackEnumRemoveRequestMatchesEntry(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST* requestPacket,
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry
    )
/*++

Routine Description:

    Compares every Object Callback row-identity field carried by the EX request.
    identityHash additionally covers field flags, context, registration type,
    module identity, name, and altitude, so an address-only match is impossible.

--*/
{
    if (requestPacket == NULL || entry == NULL) {
        return FALSE;
    }

    return entry->callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT &&
        requestPacket->callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT &&
        entry->source == requestPacket->source &&
        entry->callbackAddress == requestPacket->callbackAddress &&
        entry->registrationAddress == requestPacket->registrationAddress &&
        entry->rawStorageValue == requestPacket->rawStorageValue &&
        entry->operationMask == requestPacket->operationMask &&
        entry->objectTypeMask == requestPacket->objectTypeMask &&
        entry->trustFlags == requestPacket->trustFlags &&
        entry->removeBehavior == requestPacket->removeBehavior &&
        entry->identityHash == requestPacket->identityHash;
}

VOID
kswordArkCallbackEnumSnapshotBegin(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    initialize the snapshot aggregation state for a complete callback enumeration.

Arguments:

    Builder: The enumeration builder used by the current IOCTL request.

Return Value:

    No return value.

--*/
{
    // Without a builder, no snapshot state can be written.
    if (builder == NULL) {
        return;
    }

    // Row count starts at zero, using the protocol-fixed FNV-1a initial value.
    builder->snapshotRowCount = 0UL;
    builder->snapshotHash = KSWORD_ARK_CALLBACK_FNV64_OFFSET;
    // No pending page rows are currently waiting to be committed.
    builder->pendingEntry = NULL;
}

VOID
kswordArkCallbackEnumSnapshotCommitPending(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Submit each row after the enumerator completes field filling for that row: generate the identity hash and
    merge the identity into the full snapshot hash by global row order. Only rows actually returned by the
    current page write back to the identity field, but all logical rows participate in snapshot aggregation.

Arguments:

    Builder: The enumeration builder used by the current IOCTL request.

Return Value:

    No return value.

--*/
{
    // Save the current pending row and clear it immediately after submission.
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;
    // A non-zero identity hash indicates it has been computed.
    ULONG64 identityHash = 0ULL;
    // Global row order participates in snapshot hashing to prevent identical row sets from being misidentified as the same snapshot due to different ordering.
    ULONG rowIndex = 0UL;

    // Keep the builder state unchanged when there are no pending entries.
    if (builder == NULL || builder->pendingEntry == NULL) {
        return;
    }

    // The enumerator has finished populating all stable fields for this row.
    entry = builder->pendingEntry;
    // Calculate the identity first, then write to the protocol row and snapshot aggregator.
    identityHash = kswordArkCallbackEnumBuildIdentityHash(entry);
    entry->identityHash = identityHash;
    entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH;

    // EX removal captures the unique, fully reconstructed row while all rows
    // still participate in the same ordered snapshot hash used by R3.
    if (builder->removeMatchRequest != NULL &&
        kswordArkCallbackEnumRemoveRequestMatchesEntry(builder->removeMatchRequest, entry)) {
        builder->removeMatchedFieldFlags = entry->fieldFlags;
        builder->removeMatchedRegistrationAddress = entry->registrationAddress;
        builder->removeMatchCount += 1UL;
    }

    // Use the row count before commit as the zero-based global row index.
    rowIndex = builder->snapshotRowCount;
    // Mix in the row index first, then the identity, to clearly distinguish duplicate rows from reordered rows.
    builder->snapshotHash = KswordArkCallbackEnumHashBytes(
        builder->snapshotHash,
        &rowIndex,
        sizeof(rowIndex));
    builder->snapshotHash = KswordArkCallbackEnumHashBytes(
        builder->snapshotHash,
        &identityHash,
        sizeof(identityHash));
    // The row has fully entered the snapshot; increment the total row count and release the pending submission slot.
    builder->snapshotRowCount += 1UL;
    builder->pendingEntry = NULL;
}

VOID
kswordArkCallbackEnumSnapshotFinalize(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Submit the last row, close the complete snapshot hash, and write the
    unified enumeration generation to all return rows on the current page.

Arguments:

    Builder: The enumeration builder used by the current IOCTL request.

Return Value:

    No return value.

--*/
{
    // Iterate return rows of the current page to publish a unified generation.
    ULONG entryIndex = 0UL;

    // Without a builder, there are no snapshots requiring finalization.
    if (builder == NULL) {
        return;
    }

    // ReserveEntry only commits the previous line upon the next reservation, so the trailing line must be committed here.
    kswordArkCallbackEnumSnapshotCommitPending(builder);
    // Incorporate the final total row count into the hash to distinguish snapshots with the same prefix but different lengths.
    builder->snapshotHash = KswordArkCallbackEnumHashBytes(
        builder->snapshotHash,
        &builder->snapshotRowCount,
        sizeof(builder->snapshotRowCount));
    // A zero value is reserved in the shared protocol to mean 'invalid hash', so it is normalized to one.
    if (builder->snapshotHash == 0ULL) {
        builder->snapshotHash = 1ULL;
    }

    // Each row on the current page carries the same generation number, facilitating R3 detection of cross-page mixing.
    for (entryIndex = 0UL; entryIndex < builder->returnedCount; ++entryIndex) {
        builder->entries[entryIndex].enumerationGeneration = builder->snapshotHash;
        builder->entries[entryIndex].fieldFlags |=
            KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH;
    }

    // Only declare hash fields valid to R3 after all snapshot calculations are complete.
    builder->flags |=
        KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID |
        KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID;
}
