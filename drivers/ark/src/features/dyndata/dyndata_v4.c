/*++

Module Name:

    dyndata_v4.c

Abstract:

    DynData v4 multi-module PDB profile storage and validation.

Environment:

    Kernel-mode Driver Framework

--*/

#include "dyndata_v4_internal.h"
#include "ark/ark_push_lock.h"
#include "../../platform/kernel_module_identity.h"

#include <ntstrsafe.h>

#define KSW_DYN_V4_STATE_POOL_TAG 'sDvK'

typedef PVOID
(NTAPI* KswDynV4ExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

typedef struct KswDynV4ModuleMatch
{
    ULONG classId;
    const KswKernelModuleNameMatch* names;
    ULONG nameCount;
} KswDynV4ModuleMatch;

EX_PUSH_LOCK gKswordDynDataV4Lock;
KswDynV4State gKswordDynDataV4State;

static PVOID
kswordArkDynDataV4AllocateStateBuffer(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate nonpaged temporary storage for v4 apply state. This avoids placing
    the large per-module item cache on the small kernel stack.

Arguments:

    BufferBytes - Number of bytes required by the caller.

Return Value:

    Nonpaged allocation on success; NULL on zero length or allocation failure.

--*/
{
    static volatile LONG allocatorResolved = 0;
    static KswDynV4ExAllocatePooL2Fn exAllocatePool2Fn = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&allocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        exAllocatePool2Fn = (KswDynV4ExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }

    if (exAllocatePool2Fn != NULL) {
        return exAllocatePool2Fn(POOL_FLAG_NON_PAGED, bufferBytes, KSW_DYN_V4_STATE_POOL_TAG);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_DYN_V4_STATE_POOL_TAG);
#pragma warning(pop)
}

static const KswKernelModuleNameMatch kGKswordDynV4NtosNames[] = {
    { "ntoskrnl.exe", KSW_DYN_PROFILE_CLASS_NTOSKRNL },
    { "ntkrnlmp.exe", KSW_DYN_PROFILE_CLASS_NTOSKRNL }
};

static const KswKernelModuleNameMatch kGKswordDynV4Ntkrla57Names[] = {
    { "ntkrla57.exe", KSW_DYN_PROFILE_CLASS_NTKRLA57 }
};

static const KswKernelModuleNameMatch kGKswordDynV4LxcoreNames[] = {
    { "lxcore.sys", KSW_DYN_PROFILE_CLASS_LXCORE }
};

static const KswKernelModuleNameMatch kGKswordDynV4Win32kNames[] = {
    { "win32k.sys", KSW_DYN_PROFILE_CLASS_WIN32K }
};

static const KswKernelModuleNameMatch kGKswordDynV4Win32kbaseNames[] = {
    { "win32kbase.sys", KSW_DYN_PROFILE_CLASS_WIN32KBASE }
};

static const KswKernelModuleNameMatch kGKswordDynV4Win32kfullNames[] = {
    { "win32kfull.sys", KSW_DYN_PROFILE_CLASS_WIN32KFULL }
};

static const KswKernelModuleNameMatch kGKswordDynV4TcpipNames[] = {
    { "tcpip.sys", KSW_DYN_PROFILE_CLASS_TCPIP }
};

static const KswKernelModuleNameMatch kGKswordDynV4NdisNames[] = {
    { "ndis.sys", KSW_DYN_PROFILE_CLASS_NDIS }
};

static const KswKernelModuleNameMatch kGKswordDynV4NetioNames[] = {
    { "netio.sys", KSW_DYN_PROFILE_CLASS_NETIO }
};

static const KswKernelModuleNameMatch kGKswordDynV4FltMgrNames[] = {
    { "fltMgr.sys", KSW_DYN_PROFILE_CLASS_FLTMGR }
};

static const KswKernelModuleNameMatch kGKswordDynV4FvevolNames[] = {
    { "fvevol.sys", KSW_DYN_PROFILE_CLASS_FVEVOL }
};

static const KswKernelModuleNameMatch kGKswordDynV4CiNames[] = {
    { "ci.dll", KSW_DYN_PROFILE_CLASS_CI },
    { "ci.sys", KSW_DYN_PROFILE_CLASS_CI }
};

static const KswDynV4ModuleMatch kGKswordDynV4ModuleMatches[] = {
    { KSW_DYN_PROFILE_CLASS_NTOSKRNL, kGKswordDynV4NtosNames, RTL_NUMBER_OF(kGKswordDynV4NtosNames) },
    { KSW_DYN_PROFILE_CLASS_NTKRLA57, kGKswordDynV4Ntkrla57Names, RTL_NUMBER_OF(kGKswordDynV4Ntkrla57Names) },
    { KSW_DYN_PROFILE_CLASS_LXCORE, kGKswordDynV4LxcoreNames, RTL_NUMBER_OF(kGKswordDynV4LxcoreNames) },
    { KSW_DYN_PROFILE_CLASS_WIN32K, kGKswordDynV4Win32kNames, RTL_NUMBER_OF(kGKswordDynV4Win32kNames) },
    { KSW_DYN_PROFILE_CLASS_WIN32KBASE, kGKswordDynV4Win32kbaseNames, RTL_NUMBER_OF(kGKswordDynV4Win32kbaseNames) },
    { KSW_DYN_PROFILE_CLASS_WIN32KFULL, kGKswordDynV4Win32kfullNames, RTL_NUMBER_OF(kGKswordDynV4Win32kfullNames) },
    { KSW_DYN_PROFILE_CLASS_TCPIP, kGKswordDynV4TcpipNames, RTL_NUMBER_OF(kGKswordDynV4TcpipNames) },
    { KSW_DYN_PROFILE_CLASS_NDIS, kGKswordDynV4NdisNames, RTL_NUMBER_OF(kGKswordDynV4NdisNames) },
    { KSW_DYN_PROFILE_CLASS_NETIO, kGKswordDynV4NetioNames, RTL_NUMBER_OF(kGKswordDynV4NetioNames) },
    { KSW_DYN_PROFILE_CLASS_FLTMGR, kGKswordDynV4FltMgrNames, RTL_NUMBER_OF(kGKswordDynV4FltMgrNames) },
    { KSW_DYN_PROFILE_CLASS_FVEVOL, kGKswordDynV4FvevolNames, RTL_NUMBER_OF(kGKswordDynV4FvevolNames) },
    { KSW_DYN_PROFILE_CLASS_CI, kGKswordDynV4CiNames, RTL_NUMBER_OF(kGKswordDynV4CiNames) }
};

static VOID
kswordArkDynDataV4SetMessage(
    _Out_writes_(KSW_DYN_REASON_CHARS) WCHAR* destination,
    _In_z_ PCWSTR message
    )
/*++

Routine Description:

    Store a bounded v4 response message for user-mode diagnostics.

Arguments:

    Destination - Fixed WCHAR message buffer in a response packet.
    Message - NUL-terminated diagnostic message.

Return Value:

    None.

--*/
{
    if (destination == NULL) {
        return;
    }

    destination[0] = L'\0';
    if (message == NULL) {
        return;
    }

    (VOID)RtlStringCchCopyW(destination, KSW_DYN_REASON_CHARS, message);
    destination[KSW_DYN_REASON_CHARS - 1U] = L'\0';
}

static CHAR
kswordArkDynDataV4LowerAnsi(
    _In_ CHAR character
    )
/*++

Routine Description:

    Convert one ASCII character to lowercase for bounded module-name matching.

Arguments:

    Character - Input character.

Return Value:

    Lowercase ASCII character when applicable; otherwise the original byte.

--*/
{
    if (character >= 'A' && character <= 'Z') {
        return (CHAR)(character + ('a' - 'A'));
    }

    return character;
}

static BOOLEAN
kswordArkDynDataV4WideEqualsInsensitive(
    _In_reads_(leftChars) const WCHAR* leftText,
    _In_ ULONG leftChars,
    _In_reads_(rightChars) const WCHAR* rightText,
    _In_ ULONG rightChars
    )
/*++

Routine Description:

    Compare two bounded shared WCHAR names without trusting trailing bytes.

Arguments:

    LeftText - First WCHAR buffer.
    LeftChars - Maximum readable WCHARs in LeftText.
    RightText - Second WCHAR buffer.
    RightChars - Maximum readable WCHARs in RightText.

Return Value:

    TRUE when both strings terminate at the same point and match ignoring ASCII
    case; FALSE otherwise.

--*/
{
    ULONG index = 0UL;
    ULONG limit = 0UL;

    if (leftText == NULL || rightText == NULL || leftChars == 0UL || rightChars == 0UL) {
        return FALSE;
    }

    limit = (leftChars < rightChars) ? leftChars : rightChars;
    for (index = 0UL; index < limit; ++index) {
        WCHAR leftCharacter = leftText[index];
        WCHAR rightCharacter = rightText[index];

        if (leftCharacter == L'\0' || rightCharacter == L'\0') {
            return (leftCharacter == rightCharacter) ? TRUE : FALSE;
        }
        if (leftCharacter > 0x7f || rightCharacter > 0x7f) {
            return FALSE;
        }
        if (kswordArkDynDataV4LowerAnsi((CHAR)leftCharacter) != kswordArkDynDataV4LowerAnsi((CHAR)rightCharacter)) {
            return FALSE;
        }
    }

    return FALSE;
}

static BOOLEAN
kswordArkDynDataV4WideMatchesAnsi(
    _In_reads_(wideChars) const WCHAR* wideText,
    _In_ ULONG wideChars,
    _In_z_ PCSTR ansiText
    )
/*++

Routine Description:

    Compare a fixed shared WCHAR module name with an ANSI basename constant.

Arguments:

    WideText - Shared WCHAR buffer to compare.
    WideChars - Maximum readable WCHARs in WideText.
    AnsiText - NUL-terminated ASCII module basename.

Return Value:

    TRUE when the names are equal ignoring ASCII case.

--*/
{
    ULONG index = 0UL;

    if (wideText == NULL || wideChars == 0UL || ansiText == NULL) {
        return FALSE;
    }

    for (index = 0UL; index < wideChars; ++index) {
        const WCHAR kWideCharacter = wideText[index];
        const CHAR kAnsiCharacter = ansiText[index];

        if (kAnsiCharacter == '\0') {
            return (kWideCharacter == L'\0') ? TRUE : FALSE;
        }
        if (kWideCharacter == L'\0' || kWideCharacter > 0x7f) {
            return FALSE;
        }
        if (kswordArkDynDataV4LowerAnsi((CHAR)kWideCharacter) != kswordArkDynDataV4LowerAnsi(kAnsiCharacter)) {
            return FALSE;
        }
    }

    return (ansiText[index] == '\0') ? TRUE : FALSE;
}

static const KswDynV4ModuleMatch*
kswordArkDynDataV4FindModuleMatch(
    _In_ ULONG classId
    )
/*++

Routine Description:

    Resolve a stable v4 module class id into the accepted loaded-module names.

Arguments:

    ClassId - KSW_DYN_PROFILE_CLASS_* value from the v4 request.

Return Value:

    Pointer to a static match row when supported; NULL otherwise.

--*/
{
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(kGKswordDynV4ModuleMatches); ++index) {
        if (kGKswordDynV4ModuleMatches[index].classId == classId) {
            return &kGKswordDynV4ModuleMatches[index];
        }
    }

    return NULL;
}

static LONG
kswordArkDynDataV4FindModuleSlot(
    _In_ ULONG classId
    )
/*++

Routine Description:

    Resolve a module class id into a stable compact v4 state slot.

Arguments:

    ClassId - KSW_DYN_PROFILE_CLASS_* value.

Return Value:

    Zero-based slot index when supported; -1 when unsupported.

--*/
{
    ULONG index = 0UL;

    for (index = 0UL; index < RTL_NUMBER_OF(kGKswordDynV4ModuleMatches); ++index) {
        if (kGKswordDynV4ModuleMatches[index].classId == classId) {
            return (LONG)index;
        }
    }

    return -1L;
}

// Forward declaration: the module state snapshot requires reusing the strict image identity comparison below.
static BOOLEAN
kswordArkDynDataV4ImageIdentityMatches(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* currentIdentity,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* requestedIdentity
    );

ULONG
kswordArkDynDataV4BuildModuleStatusSnapshot(
    _Out_writes_opt_(entryCapacity) KSW_DYN_V4_MODULE_STATUS_ENTRY* entries,
    _In_ ULONG entryCapacity,
    _Out_ ULONG* totalCountOut
    )
/*++

Routine Description:

    Query every currently loaded module class supported by DynData v4 and merge
    an already accepted profile row when its immutable image identity still
    matches. Note: ci.dll without an applied profile also returns an identity. R3 must select precise entries
    from the v4 pack; do not guess versions or iterate through submissions with many incorrect profiles.

Return Value:

    Number of rows copied to Entries. TotalCountOut receives all loaded matches.

--*/
{
    ULONG matchIndex = 0UL;
    ULONG copiedCount = 0UL;
    ULONG totalCount = 0UL;

    if (totalCountOut == NULL) {
        return 0UL;
    }
    *totalCountOut = 0UL;

    for (matchIndex = 0UL;
         matchIndex < RTL_NUMBER_OF(kGKswordDynV4ModuleMatches);
         ++matchIndex) {
        const KswDynV4ModuleMatch* moduleMatch =
            &kGKswordDynV4ModuleMatches[matchIndex];
        KSW_DYN_MODULE_IDENTITY_PACKET currentIdentity;
        KSW_DYN_V4_MODULE_STATUS_ENTRY publicEntry;
        const LONG kModuleSlot =
            kswordArkDynDataV4FindModuleSlot(moduleMatch->classId);
        NTSTATUS identityStatus = STATUS_SUCCESS;

        RtlZeroMemory(&currentIdentity, sizeof(currentIdentity));
        RtlZeroMemory(&publicEntry, sizeof(publicEntry));
        identityStatus = kswordArkQueryKernelModuleIdentity(
            moduleMatch->names,
            moduleMatch->nameCount,
            &currentIdentity);
        if (!NT_SUCCESS(identityStatus) || currentIdentity.present == 0UL) {
            continue;
        }

        // The current match table index is also a public stable slot; do not directly
        // convert the theoretical -1 moduleSlot to ULONG before exposing it to R3.
        publicEntry.moduleIndex = matchIndex;
        publicEntry.statusFlags = KSW_DYN_V4_STATUS_FLAG_IDENTITY_MATCHED;
        publicEntry.module.image = currentIdentity;
        if (kModuleSlot >= 0L &&
            (ULONG)kModuleSlot < KSW_DYN_V4_MAX_MODULES) {
            kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
            if (gKswordDynDataV4State.modules[kModuleSlot].occupied &&
                kswordArkDynDataV4ImageIdentityMatches(
                    &currentIdentity,
                    &gKswordDynDataV4State.modules[kModuleSlot]
                        .publicEntry.module.image)) {
                publicEntry =
                    gKswordDynDataV4State.modules[kModuleSlot].publicEntry;
            }
            kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);
        }

        totalCount += 1UL;
        if (entries != NULL && copiedCount < entryCapacity) {
            entries[copiedCount] = publicEntry;
            copiedCount += 1UL;
        }
    }

    *totalCountOut = totalCount;
    return copiedCount;
}

static BOOLEAN
kswordArkDynDataV4ModuleNameAllowed(
    _In_ const KswDynV4ModuleMatch* match,
    _In_reads_(KSW_DYN_MODULE_NAME_CHARS) const WCHAR* moduleName
    )
/*++

Routine Description:

    Check that the request names one of the basenames owned by its class id.

Arguments:

    Match - Static class-to-name mapping.
    ModuleName - Request module basename.

Return Value:

    TRUE when the basename belongs to the class mapping.

--*/
{
    ULONG index = 0UL;

    if (match == NULL || moduleName == NULL) {
        return FALSE;
    }

    for (index = 0UL; index < match->nameCount; ++index) {
        if (kswordArkDynDataV4WideMatchesAnsi(moduleName, KSW_DYN_MODULE_NAME_CHARS, match->names[index].fileName)) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
kswordArkDynDataV4ImageIdentityMatches(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* currentIdentity,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* requestedIdentity
    )
/*++

Routine Description:

    Compare the loaded-image tuple that makes a v4 module profile safe to store.

Arguments:

    CurrentIdentity - Identity read from the loaded kernel module list.
    RequestedIdentity - Identity supplied by the v4 PDB profile request.

Return Value:

    TRUE when class, machine, timestamp, size, and basename all match.

--*/
{
    if (currentIdentity == NULL || requestedIdentity == NULL) {
        return FALSE;
    }
    if (currentIdentity->present == 0UL || requestedIdentity->present == 0UL) {
        return FALSE;
    }
    if (currentIdentity->classId != requestedIdentity->classId ||
        currentIdentity->machine != requestedIdentity->machine ||
        currentIdentity->timeDateStamp != requestedIdentity->timeDateStamp ||
        currentIdentity->sizeOfImage != requestedIdentity->sizeOfImage) {
        return FALSE;
    }

    return kswordArkDynDataV4WideEqualsInsensitive(
        currentIdentity->moduleName,
        KSW_DYN_MODULE_NAME_CHARS,
        requestedIdentity->moduleName,
        KSW_DYN_MODULE_NAME_CHARS);
}

static BOOLEAN
kswordArkDynDataV4ItemKindSupported(
    _In_ ULONG itemKind
    )
/*++

Routine Description:

    Check whether one v4 item kind is understood by this R0 storage layer.

Arguments:

    ItemKind - KSW_DYN_V4_ITEM_KIND_* value.

Return Value:

    TRUE for supported v4 item kinds; FALSE for unknown kinds.

--*/
{
    return itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET ||
        itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA ||
        itemKind == KSW_DYN_V4_ITEM_KIND_FUNCTION_RVA ||
        itemKind == KSW_DYN_V4_ITEM_KIND_ENUM_VALUE ||
        itemKind == KSW_DYN_V4_ITEM_KIND_TYPE_SIZE ||
        itemKind == KSW_DYN_V4_ITEM_KIND_BIT_FIELD ||
        itemKind == KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL;
}

static BOOLEAN
kswordArkDynDataV4ItemValueValid(
    _In_ const KSW_DYN_V4_ITEM_PACKET* item,
    _In_ ULONG sizeOfImage
    )
/*++

Routine Description:

    Apply kind-specific range checks that do not require business consumers.

Arguments:

    Item - One compact v4 item.
    SizeOfImage - Loaded image size for RVA range checks.

Return Value:

    TRUE when the item is self-consistent and safe to store.

--*/
{
    if (item == NULL) {
        return FALSE;
    }

    switch (item->itemKind) {
    case KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET:
        return (item->valueLow != KSW_DYN_OFFSET_UNAVAILABLE);
    case KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA:
    case KSW_DYN_V4_ITEM_KIND_FUNCTION_RVA:
    case KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL:
        return (item->valueLow != 0UL && item->valueLow < sizeOfImage);
    case KSW_DYN_V4_ITEM_KIND_ENUM_VALUE:
        return (item->aux0 == 1UL || item->aux0 == 2UL || item->aux0 == 4UL || item->aux0 == 8UL);
    case KSW_DYN_V4_ITEM_KIND_TYPE_SIZE:
        return (item->valueLow != 0UL);
    case KSW_DYN_V4_ITEM_KIND_BIT_FIELD:
        if (!(item->aux2 == 1UL || item->aux2 == 2UL || item->aux2 == 4UL || item->aux2 == 8UL)) {
            return FALSE;
        }
        if (item->aux1 == 0UL || item->aux1 > 64UL || item->aux0 >= 64UL) {
            return FALSE;
        }
        return (item->aux0 + item->aux1) <= (item->aux2 * 8UL);
    default:
        return FALSE;
    }
}

static LONG
kswordArkDynDataV4FindGroupIndex(
    _In_reads_(groupCount) const KSW_DYN_V4_CAPABILITY_GROUP_PACKET* groups,
    _In_ ULONG groupCount,
    _In_ ULONG groupId
    )
/*++

Routine Description:

    Locate one capability group id in a bounded request group array.

Arguments:

    Groups - Fixed request group array.
    GroupCount - Number of active rows in Groups.
    GroupId - Capability group id to locate.

Return Value:

    Zero-based group index when found; -1 when missing.

--*/
{
    ULONG index = 0UL;

    if (groups == NULL) {
        return -1L;
    }

    for (index = 0UL; index < groupCount; ++index) {
        if (groups[index].groupId == groupId) {
            return (LONG)index;
        }
    }

    return -1L;
}

static BOOLEAN
kswordArkDynDataV4ItemDuplicate(
    _In_reads_(itemCount) const KSW_DYN_V4_ITEM_PACKET* items,
    _In_ ULONG itemCount,
    _In_ ULONG currentIndex
    )
/*++

Routine Description:

    Detect duplicate item ids inside one module profile request.

Arguments:

    Items - Variable request item array.
    ItemCount - Number of item rows.
    CurrentIndex - Index whose itemId is being checked.

Return Value:

    TRUE when an earlier item uses the same nonzero item id.

--*/
{
    ULONG index = 0UL;
    ULONG itemId = 0UL;

    if (items == NULL || currentIndex >= itemCount) {
        return TRUE;
    }

    itemId = items[currentIndex].itemId;
    for (index = 0UL; index < currentIndex; ++index) {
        if (items[index].itemId == itemId) {
            return TRUE;
        }
    }

    return FALSE;
}

static VOID
kswordArkDynDataV4AppendMissing(
    _Inout_ KswDynV4State* state,
    _In_ ULONG moduleClassId,
    _In_ ULONG groupId,
    _In_ ULONG missingKind,
    _In_ ULONG missingCount,
    _In_z_ PCSTR reason
    )
/*++

Routine Description:

    Append a bounded missing-summary row for R3 diagnostics.

Arguments:

    State - Mutable v4 state.
    ModuleClassId - Module class that owns the missing summary.
    GroupId - Capability group whose count is short.
    MissingKind - Required or optional missing category.
    MissingCount - Number of absent items summarized by this row.
    Reason - ASCII reason text.

Return Value:

    None.

--*/
{
    KSW_DYN_V4_MISSING_ITEM_ENTRY* entry = NULL;

    if (state == NULL || missingCount == 0UL || state->missingCount >= KSW_DYN_V4_MAX_MISSING_SUMMARY) {
        return;
    }

    entry = &state->missing[state->missingCount];
    RtlZeroMemory(entry, sizeof(*entry));
    entry->moduleClassId = moduleClassId;
    entry->itemId = missingCount;
    entry->capabilityGroupId = groupId;
    entry->missingKind = missingKind;
    (VOID)RtlStringCchCopyA(entry->itemName, KSW_DYN_V4_ITEM_NAME_CHARS, "summary-count");
    (VOID)RtlStringCchCopyA(entry->reason, KSW_DYN_V4_MISSING_REASON_CHARS, reason);
    state->missingCount += 1UL;
}

VOID
kswordArkDynDataV4Initialize(
    VOID
    )
/*++

Routine Description:

    initialize the independent v4 profile state lock and clear cached modules.

Arguments:

    None.

Return Value:

    None.

--*/
{
    ExInitializePushLock(&gKswordDynDataV4Lock);
    kswordArkAcquirePushLockExclusive(&gKswordDynDataV4Lock);
    RtlZeroMemory(&gKswordDynDataV4State, sizeof(gKswordDynDataV4State));
    kswordArkReleasePushLockExclusive(&gKswordDynDataV4Lock);
}

VOID
kswordArkDynDataV4Uninitialize(
    VOID
    )
/*++

Routine Description:

    Clear cached v4 module profile state during DynData shutdown.

Arguments:

    None.

Return Value:

    None.

--*/
{
    kswordArkAcquirePushLockExclusive(&gKswordDynDataV4Lock);
    RtlZeroMemory(&gKswordDynDataV4State, sizeof(gKswordDynDataV4State));
    kswordArkReleasePushLockExclusive(&gKswordDynDataV4Lock);
}

NTSTATUS
kswordArkDynDataV4SnapshotFltMgrMinifilterLayout(
    _Out_ KswDynV4FltmgrMinifilterLayout* layoutOut
    )
/*++

Routine Description:

    Copy the PDB-derived _FLT_FILTER.Operations offset for the currently loaded
    fltMgr.sys image. Note: Only accept v4 items that have passed module PE/PDB identity verification
    to avoid using private structure offsets from other system versions for the current Filter object.

Return Value:

    STATUS_SUCCESS when item 1101 is available and valid; otherwise
    STATUS_NOT_SUPPORTED.

--*/
{
    ULONG moduleIndex = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (layoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layoutOut, sizeof(*layoutOut));

    kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
    for (moduleIndex = 0UL; moduleIndex < KSW_DYN_V4_MAX_MODULES; ++moduleIndex) {
        KswDynV4ModuleState* moduleState = &gKswordDynDataV4State.modules[moduleIndex];
        ULONG itemIndex = 0UL;

        if (!moduleState->occupied ||
            moduleState->publicEntry.module.image.classId != KSW_DYN_PROFILE_CLASS_FLTMGR ||
            moduleState->storedItemCount > KSW_DYN_V4_MAX_ITEMS_PER_MODULE) {
            continue;
        }

        for (itemIndex = 0UL; itemIndex < moduleState->storedItemCount; ++itemIndex) {
            const KSW_DYN_V4_ITEM_PACKET* item = &moduleState->items[itemIndex];
            if (item->itemId == KSW_DYN_V4_ITEM_ID_FLT_FILTER_OPERATIONS &&
                item->itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET &&
                item->valueLow != 0UL &&
                item->valueLow <= KSW_DYN_PROFILE_OFFSET_MAX) {
                layoutOut->fltFilterOperations = item->valueLow;
                status = STATUS_SUCCESS;
                break;
            }
        }
        break;
    }
    kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);
    return status;
}

NTSTATUS
kswordArkDynDataV4SnapshotTimerDpcLayout(
    _Out_ KswDynV4TimerDpcLayout* layoutOut
    )
/*++

Routine Description:

    Copy the complete ntoskrnl Timer/DPC layout from the accepted v4 profile.
    The global push lock is held only while fixed scalar values are copied.

Return Value:

    STATUS_SUCCESS when all required Timer/DPC item IDs are present with their
    expected kinds; STATUS_NOT_SUPPORTED otherwise.

--*/
{
    KswDynV4ModuleState* moduleState = NULL;
    ULONG index = 0UL;
    ULONG foundCount = 0UL;

    if (layoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layoutOut, sizeof(*layoutOut));

    kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
    moduleState = &gKswordDynDataV4State.modules[0];
    if (!moduleState->occupied ||
        moduleState->publicEntry.module.image.classId != KSW_DYN_PROFILE_CLASS_NTOSKRNL ||
        moduleState->storedItemCount > KSW_DYN_V4_MAX_ITEMS_PER_MODULE) {
        kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);
        return STATUS_NOT_SUPPORTED;
    }

    for (index = 0UL; index < moduleState->storedItemCount; ++index) {
        const KSW_DYN_V4_ITEM_PACKET* item = &moduleState->items[index];
        ULONG* destination = NULL;
        ULONG expectedKind = KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET;

        switch (item->itemId) {
        case KSW_DYN_V4_ITEM_ID_KPRCB_TIMER_TABLE: destination = &layoutOut->kprcbTimerTable; break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TIMER_ENTRIES: destination = &layoutOut->timerTableTimerEntries; break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_ENTRY: destination = &layoutOut->timerTableEntryEntry; break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_LIST_ENTRY: destination = &layoutOut->timerTimerListEntry; break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_DUE_TIME: destination = &layoutOut->timerDueTime; break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_DPC: destination = &layoutOut->timerDpc; break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_TYPE: destination = &layoutOut->timerType; break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_PERIOD: destination = &layoutOut->timerPeriod; break;
        case KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_ROUTINE: destination = &layoutOut->dpcDeferredRoutine; break;
        case KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_CONTEXT: destination = &layoutOut->dpcDeferredContext; break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TYPE_SIZE:
            destination = &layoutOut->timerTableTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_TYPE_SIZE:
            destination = &layoutOut->timerTableEntryTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            break;
        case KSW_DYN_V4_ITEM_ID_KTIMER_TYPE_SIZE:
            destination = &layoutOut->timerTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            break;
        case KSW_DYN_V4_ITEM_ID_KDPC_TYPE_SIZE:
            destination = &layoutOut->dpcTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            break;
        default:
            break;
        }

        if (destination != NULL && item->itemKind == expectedKind) {
            *destination = item->valueLow;
            foundCount += 1UL;
        }
    }
    kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);

    // The v4 timer contract contains fourteen consumed layout values.  The
    // reserved Lock/Time IDs are intentionally absent from new profiles.
    return (foundCount == 14UL) ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

NTSTATUS
kswordArkDynDataV4SnapshotActiveExWorkerField(
    _Out_ KswDynV4BitFieldLayout* fieldOut
    )
/*++

Routine Description:

    Copy the accepted _ETHREAD.ActiveExWorker bit-field layout from the current
    ntoskrnl v4 profile without exposing the global v4 state to thread code.

Return Value:

    STATUS_SUCCESS when item 1001 is present and valid; otherwise a validation
    or capability status.

--*/
{
    KswDynV4ModuleState* moduleState = NULL;
    ULONG index = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (fieldOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(fieldOut, sizeof(*fieldOut));

    kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
    moduleState = &gKswordDynDataV4State.modules[0];
    if (moduleState->occupied &&
        moduleState->publicEntry.module.image.classId == KSW_DYN_PROFILE_CLASS_NTOSKRNL &&
        moduleState->storedItemCount <= KSW_DYN_V4_MAX_ITEMS_PER_MODULE) {
        for (index = 0UL; index < moduleState->storedItemCount; ++index) {
            const KSW_DYN_V4_ITEM_PACKET* item = &moduleState->items[index];
            if (item->itemId != KSW_DYN_V4_ITEM_ID_ETH_ACTIVE_EX_WORKER ||
                item->itemKind != KSW_DYN_V4_ITEM_KIND_BIT_FIELD) {
                continue;
            }

            fieldOut->offset = item->valueLow;
            fieldOut->bitOffset = item->aux0;
            fieldOut->bitCount = item->aux1;
            fieldOut->storageBytes = item->aux2;
            if ((fieldOut->storageBytes == 1UL ||
                 fieldOut->storageBytes == 2UL ||
                 fieldOut->storageBytes == 4UL ||
                 fieldOut->storageBytes == 8UL) &&
                fieldOut->bitCount != 0UL &&
                fieldOut->bitCount <= 64UL &&
                fieldOut->bitOffset + fieldOut->bitCount <= fieldOut->storageBytes * 8UL) {
                status = STATUS_SUCCESS;
            }
            else {
                status = STATUS_DATA_ERROR;
            }
            break;
        }
    }
    kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);

    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(fieldOut, sizeof(*fieldOut));
    }
    return status;
}

NTSTATUS
kswordArkDynDataV4SnapshotWorkQueueLayout(
    _Out_ KswDynV4WorkQueueLayout* layoutOut
    )
/*++

Routine Description:

    Copy the complete, identity-matched ntoskrnl work-queue layout. Every item
    is required; consumers never substitute fixed offsets or scan for globals.

Return Value:

    STATUS_SUCCESS only when all twenty-three PDB-derived items are present with the
    expected kinds. Missing or malformed descriptors fail closed.

--*/
{
    KswDynV4ModuleState* moduleState = NULL;
    ULONG itemIndex = 0UL;
    ULONG foundMask = 0UL;

    if (layoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layoutOut, sizeof(*layoutOut));

    kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
    moduleState = &gKswordDynDataV4State.modules[0];
    if (!moduleState->occupied ||
        moduleState->publicEntry.module.image.classId != KSW_DYN_PROFILE_CLASS_NTOSKRNL ||
        moduleState->storedItemCount > KSW_DYN_V4_MAX_ITEMS_PER_MODULE) {
        kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);
        return STATUS_NOT_SUPPORTED;
    }

    layoutOut->moduleBase = moduleState->publicEntry.module.image.imageBase;
    layoutOut->moduleSize = moduleState->publicEntry.module.image.sizeOfImage;
    for (itemIndex = 0UL; itemIndex < moduleState->storedItemCount; ++itemIndex) {
        const KSW_DYN_V4_ITEM_PACKET* item = &moduleState->items[itemIndex];
        ULONG* destination = NULL;
        ULONG expectedKind = KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET;
        ULONG bit = 0UL;

        if (item->capabilityGroupId != KSW_DYN_V4_CAPABILITY_GROUP_WORK_QUEUE ||
            item->valueHigh != 0UL ||
            item->aux1 != 0UL ||
            item->aux2 != 0UL ||
            item->aux3 != 0UL) {
            continue;
        }
        switch (item->itemId) {
        case KSW_DYN_V4_ITEM_ID_WQ_PSP_SYSTEM_PARTITION:
            destination = &layoutOut->pspSystemPartitionRva;
            expectedKind = KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA;
            bit = 0x00000001UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EXP_BUILTIN_PRIORITIES:
            destination = &layoutOut->expBuiltinPrioritiesRva;
            expectedKind = KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA;
            bit = 0x00000002UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_EX_PARTITION:
            destination = &layoutOut->epartitionExPartition;
            bit = 0x00000004UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_WORK_QUEUES:
            destination = &layoutOut->exPartitionWorkQueues;
            bit = 0x00000008UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_WORK_PRI_QUEUE:
            destination = &layoutOut->exWorkQueueWorkPriQueue;
            bit = 0x00000010UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_QUEUE_INDEX:
            destination = &layoutOut->exWorkQueueQueueIndex;
            bit = 0x00000020UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_ENTRY_LIST_HEAD:
            destination = &layoutOut->kpriQueueEntryListHead;
            bit = 0x00000040UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_THREAD_LIST_HEAD:
            destination = &layoutOut->kpriQueueThreadListHead;
            bit = 0x00000080UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE:
            destination = &layoutOut->kthreadQueue;
            bit = 0x00000100UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE_LIST_ENTRY:
            destination = &layoutOut->kthreadQueueListEntry;
            bit = 0x00000200UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_LIST:
            destination = &layoutOut->workItemList;
            bit = 0x00000400UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_ROUTINE:
            destination = &layoutOut->workItemRoutine;
            bit = 0x00000800UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_PARAMETER:
            destination = &layoutOut->workItemParameter;
            bit = 0x00001000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EX_POOL_UNTRUSTED:
            destination = &layoutOut->exPoolUntrusted;
            expectedKind = KSW_DYN_V4_ITEM_KIND_ENUM_VALUE;
            bit = 0x00002000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_TYPE_SIZE:
            destination = &layoutOut->epartitionTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            bit = 0x00004000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_TYPE_SIZE:
            destination = &layoutOut->exPartitionTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            bit = 0x00008000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_TYPE_SIZE:
            destination = &layoutOut->exWorkQueueTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            bit = 0x00010000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_TYPE_SIZE:
            destination = &layoutOut->kpriQueueTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            bit = 0x00020000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_TYPE_SIZE:
            destination = &layoutOut->kthreadTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            bit = 0x00040000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_TYPE_SIZE:
            destination = &layoutOut->workItemTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            bit = 0x00080000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_START_ADDRESS:
            destination = &layoutOut->ethreadStartAddress;
            bit = 0x00100000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TYPE_SIZE:
            destination = &layoutOut->ethreadTypeSize;
            expectedKind = KSW_DYN_V4_ITEM_KIND_TYPE_SIZE;
            bit = 0x00200000UL;
            break;
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TCB:
            destination = &layoutOut->ethreadTcb;
            bit = 0x00400000UL;
            break;
        default:
            break;
        }

        if (destination != NULL &&
            item->itemKind == expectedKind &&
            (foundMask & bit) == 0UL &&
            ((expectedKind == KSW_DYN_V4_ITEM_KIND_ENUM_VALUE &&
              item->aux0 == sizeof(ULONG)) ||
             (expectedKind != KSW_DYN_V4_ITEM_KIND_ENUM_VALUE &&
              item->aux0 == 0UL))) {
            *destination = item->valueLow;
            foundMask |= bit;
        }
    }
    kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);

    if (foundMask != 0x007FFFFFUL ||
        layoutOut->moduleBase == 0ULL ||
        layoutOut->moduleSize == 0UL) {
        RtlZeroMemory(layoutOut, sizeof(*layoutOut));
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDynDataV4SnapshotCiKernelHashLayout(
    _Out_ KswDynV4CiKernelHashLayout* layoutOut
    )
/*++

Routine Description:

    Copy the identity-matched CI kernel hash list globals and entry layout into
    one scalar snapshot. Note: The caller does not directly access v4 global
    state, nor does it traverse the CI list while holding the DynData lock.

Return Value:

    STATUS_SUCCESS when every required CI hash item is present and bounded;
    STATUS_NOT_SUPPORTED when the CI profile or required item is absent.

--*/
{
    ULONG moduleIndex = 0UL;
    ULONG itemIndex = 0UL;
    ULONG requiredFoundMask = 0UL;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (layoutOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    layoutOut->entryTimeDateStamp = KSW_DYN_OFFSET_UNAVAILABLE;
    layoutOut->entryLoadStatus = KSW_DYN_OFFSET_UNAVAILABLE;
    layoutOut->entryImageBase = KSW_DYN_OFFSET_UNAVAILABLE;
    layoutOut->entryImageSize = KSW_DYN_OFFSET_UNAVAILABLE;

    kswordArkAcquirePushLockShared(&gKswordDynDataV4Lock);
    for (moduleIndex = 0UL; moduleIndex < KSW_DYN_V4_MAX_MODULES; ++moduleIndex) {
        const KswDynV4ModuleState* moduleState =
            &gKswordDynDataV4State.modules[moduleIndex];

        if (!moduleState->occupied ||
            moduleState->publicEntry.module.image.classId != KSW_DYN_PROFILE_CLASS_CI ||
            moduleState->storedItemCount > KSW_DYN_V4_MAX_ITEMS_PER_MODULE) {
            continue;
        }

        layoutOut->moduleBase = moduleState->publicEntry.module.image.imageBase;
        layoutOut->moduleSize = moduleState->publicEntry.module.image.sizeOfImage;
        for (itemIndex = 0UL; itemIndex < moduleState->storedItemCount; ++itemIndex) {
            const KSW_DYN_V4_ITEM_PACKET* item = &moduleState->items[itemIndex];

            switch (item->itemId) {
            case KSW_DYN_V4_ITEM_ID_CI_KERNEL_HASH_BUCKET_LIST:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA) {
                    layoutOut->kernelHashBucketListRva = item->valueLow;
                    requiredFoundMask |= 0x00000001UL;
                }
                break;
            case KSW_DYN_V4_ITEM_ID_CI_HASH_CACHE_LOCK:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA) {
                    layoutOut->hashCacheLockRva = item->valueLow;
                    requiredFoundMask |= 0x00000002UL;
                }
                break;
            case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_NEXT:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET) {
                    layoutOut->entryNext = item->valueLow;
                    requiredFoundMask |= 0x00000004UL;
                }
                break;
            case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_DRIVER_NAME:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET) {
                    layoutOut->entryDriverName = item->valueLow;
                    requiredFoundMask |= 0x00000008UL;
                }
                break;
            case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TIME_DATE_STAMP:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET) {
                    layoutOut->entryTimeDateStamp = item->valueLow;
                }
                break;
            case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_LOAD_STATUS:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET) {
                    layoutOut->entryLoadStatus = item->valueLow;
                }
                break;
            case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_BASE:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET) {
                    layoutOut->entryImageBase = item->valueLow;
                }
                break;
            case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_SIZE:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET) {
                    layoutOut->entryImageSize = item->valueLow;
                }
                break;
            case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TYPE_SIZE:
                if (item->itemKind == KSW_DYN_V4_ITEM_KIND_TYPE_SIZE) {
                    layoutOut->entryTypeSize = item->valueLow;
                    requiredFoundMask |= 0x00000040UL;
                }
                break;
            default:
                break;
            }
        }
        break;
    }
    kswordArkReleasePushLockShared(&gKswordDynDataV4Lock);

    // All required fields must be present, and each access range must fall within the structure size reported by the PDB.
    if (requiredFoundMask == 0x0000004FUL &&
        layoutOut->moduleBase != 0ULL &&
        layoutOut->moduleSize != 0UL &&
        layoutOut->kernelHashBucketListRva != 0UL &&
        layoutOut->hashCacheLockRva != 0UL &&
        layoutOut->moduleSize >= sizeof(PVOID) &&
        layoutOut->kernelHashBucketListRva <=
            layoutOut->moduleSize - sizeof(PVOID) &&
        layoutOut->moduleSize >= sizeof(ERESOURCE) &&
        layoutOut->hashCacheLockRva <=
            layoutOut->moduleSize - sizeof(ERESOURCE) &&
        layoutOut->moduleBase <=
            (~0ULL - layoutOut->kernelHashBucketListRva) &&
        layoutOut->moduleBase <=
            (~0ULL - layoutOut->hashCacheLockRva) &&
        layoutOut->entryTypeSize >= sizeof(UNICODE_STRING) &&
        layoutOut->entryTypeSize <= 4096UL &&
        layoutOut->entryNext <= layoutOut->entryTypeSize - sizeof(PVOID) &&
        layoutOut->entryDriverName <= layoutOut->entryTypeSize - sizeof(UNICODE_STRING) &&
        (layoutOut->entryTimeDateStamp == KSW_DYN_OFFSET_UNAVAILABLE ||
            layoutOut->entryTimeDateStamp <= layoutOut->entryTypeSize - sizeof(ULONG)) &&
        (layoutOut->entryLoadStatus == KSW_DYN_OFFSET_UNAVAILABLE ||
            layoutOut->entryLoadStatus <= layoutOut->entryTypeSize - sizeof(NTSTATUS)) &&
        (layoutOut->entryImageBase == KSW_DYN_OFFSET_UNAVAILABLE ||
            layoutOut->entryImageBase <= layoutOut->entryTypeSize - sizeof(PVOID)) &&
        (layoutOut->entryImageSize == KSW_DYN_OFFSET_UNAVAILABLE ||
            layoutOut->entryImageSize <= layoutOut->entryTypeSize - sizeof(ULONG))) {
        status = STATUS_SUCCESS;
    }

    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(layoutOut, sizeof(*layoutOut));
    }
    return status;
}

NTSTATUS
kswordArkDynDataV4ApplyProfile(
    _In_reads_bytes_(inputBufferLength) const KSW_APPLY_DYN_PROFILE_V4_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSW_APPLY_DYN_PROFILE_V4_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Validate and store one v4 module profile without wiring items to consumers.

Arguments:

    Request - METHOD_BUFFERED v4 module profile request.
    InputBufferLength - Total input bytes supplied by WDF.
    Response - Fixed v4 apply response.
    OutputBufferLength - Writable response byte count.
    BytesWrittenOut - Receives response bytes written.

Return Value:

    STATUS_SUCCESS on accepted storage; validation status when rejected.

--*/
{
    const KswDynV4ModuleMatch* moduleMatch = NULL;
    KSW_DYN_MODULE_IDENTITY_PACKET currentIdentity;
    KswDynV4ModuleState* moduleState = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    size_t requiredBytes = 0U;
    LONG moduleSlot = -1L;
    ULONG groupPresentRequired[KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE] = { 0 };
    ULONG groupPresentOptional[KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE] = { 0 };
    ULONG index = 0UL;
    ULONG rejectedCount = 0UL;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (response == NULL || outputBufferLength < sizeof(KSW_APPLY_DYN_PROFILE_V4_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(response, outputBufferLength);
    response->size = sizeof(*response);
    response->version = KSW_DYN_V4_PROTOCOL_VERSION;
    response->status = STATUS_UNSUCCESSFUL;
    kswordArkDynDataV4SetMessage(response->message, L"DynData v4 apply did not run.");
    *bytesWrittenOut = sizeof(*response);

    if (request == NULL || inputBufferLength < KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE) {
        status = STATUS_BUFFER_TOO_SMALL;
        response->status = status;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 request header is too small.");
        return status;
    }
    if (request->version != KSW_DYN_V4_PROTOCOL_VERSION) {
        status = STATUS_REVISION_MISMATCH;
        response->status = status;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 protocol version mismatch.");
        return status;
    }
    if (request->itemCount == 0UL || request->itemCount > KSW_DYN_V4_MAX_ITEMS_PER_MODULE ||
        request->capabilityGroupCount == 0UL ||
        request->capabilityGroupCount > KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE) {
        status = STATUS_INVALID_PARAMETER;
        response->status = status;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 request counts are invalid.");
        return status;
    }
    if ((request->itemCount - 1UL) >
        ((MAXSIZE_T - KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE) / sizeof(KSW_DYN_V4_ITEM_PACKET))) {
        status = STATUS_INTEGER_OVERFLOW;
        response->status = status;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 request size overflow.");
        return status;
    }

    requiredBytes = KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE +
        ((size_t)request->itemCount * sizeof(KSW_DYN_V4_ITEM_PACKET));
    if ((size_t)request->size < requiredBytes || inputBufferLength < requiredBytes) {
        status = STATUS_BUFFER_TOO_SMALL;
        response->status = status;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 request does not contain all items.");
        return status;
    }

    moduleMatch = kswordArkDynDataV4FindModuleMatch(request->module.image.classId);
    if (moduleMatch == NULL ||
        !kswordArkDynDataV4ModuleNameAllowed(moduleMatch, request->module.image.moduleName)) {
        status = STATUS_NOT_SUPPORTED;
        response->status = status;
        response->statusFlags = KSW_DYN_V4_STATUS_FLAG_IDENTITY_REJECTED;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 module class or name is unsupported.");
        return status;
    }
    moduleSlot = kswordArkDynDataV4FindModuleSlot(request->module.image.classId);
    if (moduleSlot < 0L) {
        status = STATUS_NOT_SUPPORTED;
        response->status = status;
        response->statusFlags = KSW_DYN_V4_STATUS_FLAG_IDENTITY_REJECTED;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 module class has no storage slot.");
        return status;
    }

    status = kswordArkQueryKernelModuleIdentity(moduleMatch->names, moduleMatch->nameCount, &currentIdentity);
    if (!NT_SUCCESS(status)) {
        response->status = status;
        response->statusFlags = KSW_DYN_V4_STATUS_FLAG_IDENTITY_REJECTED;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 target module is absent or unreadable.");
        return status;
    }
    if (!kswordArkDynDataV4ImageIdentityMatches(&currentIdentity, &request->module.image)) {
        status = STATUS_NOT_SUPPORTED;
        response->status = status;
        response->statusFlags = KSW_DYN_V4_STATUS_FLAG_IDENTITY_REJECTED;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 module identity mismatch.");
        return status;
    }

    moduleState = (KswDynV4ModuleState*)kswordArkDynDataV4AllocateStateBuffer(sizeof(*moduleState));
    if (moduleState == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        response->status = status;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 could not allocate module state storage.");
        return status;
    }

    RtlZeroMemory(moduleState, sizeof(*moduleState));
    moduleState->occupied = TRUE;
    moduleState->publicEntry.moduleIndex = (ULONG)moduleSlot;
    moduleState->publicEntry.module = request->module;
    moduleState->publicEntry.module.image.imageBase = currentIdentity.imageBase;
    moduleState->publicEntry.itemCount = request->itemCount;
    moduleState->publicEntry.capabilityGroupCount = request->capabilityGroupCount;
    moduleState->publicEntry.statusFlags = KSW_DYN_V4_STATUS_FLAG_IDENTITY_MATCHED;

    for (index = 0UL; index < request->capabilityGroupCount; ++index) {
        moduleState->groups[index].publicEntry.moduleClassId = request->module.image.classId;
        moduleState->groups[index].publicEntry.groupId = request->capabilityGroups[index].groupId;
        moduleState->groups[index].publicEntry.requiredItemCount = request->capabilityGroups[index].requiredItemCount;
        moduleState->groups[index].publicEntry.optionalItemCount = request->capabilityGroups[index].optionalItemCount;
        RtlCopyMemory(
            moduleState->groups[index].publicEntry.groupName,
            request->capabilityGroups[index].groupName,
            sizeof(moduleState->groups[index].publicEntry.groupName));
        moduleState->groups[index].publicEntry.groupName[KSW_DYN_V4_CAPABILITY_NAME_CHARS - 1U] = '\0';
        response->requiredItemCount += request->capabilityGroups[index].requiredItemCount;
        response->optionalItemCount += request->capabilityGroups[index].optionalItemCount;
    }

    for (index = 0UL; index < request->itemCount; ++index) {
        const KSW_DYN_V4_ITEM_PACKET* item = &request->items[index];
        LONG groupIndex = -1L;
        ULONG groupSlot = 0UL;

        if (item->itemId == 0UL ||
            !kswordArkDynDataV4ItemKindSupported(item->itemKind) ||
            !kswordArkDynDataV4ItemValueValid(item, currentIdentity.sizeOfImage) ||
            kswordArkDynDataV4ItemDuplicate(request->items, request->itemCount, index)) {
            rejectedCount += 1UL;
            continue;
        }

        groupIndex = kswordArkDynDataV4FindGroupIndex(
            request->capabilityGroups,
            request->capabilityGroupCount,
            item->capabilityGroupId);
        if (groupIndex < 0L) {
            rejectedCount += 1UL;
            continue;
        }

        groupSlot = (ULONG)groupIndex;
        response->appliedItemCount += 1UL;
        moduleState->items[moduleState->storedItemCount] = *item;
        moduleState->storedItemCount += 1UL;
        if ((item->flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0UL) {
            groupPresentRequired[groupSlot] += 1UL;
            response->presentRequiredItemCount += 1UL;
        }
        else {
            groupPresentOptional[groupSlot] += 1UL;
            response->presentOptionalItemCount += 1UL;
        }
    }

    response->rejectedItemCount = rejectedCount;
    if (rejectedCount != 0UL || response->appliedItemCount == 0UL) {
        status = STATUS_INVALID_PARAMETER;
        response->status = status;
        response->statusFlags = KSW_DYN_V4_STATUS_FLAG_VALIDATION_FAILED;
        kswordArkDynDataV4SetMessage(response->message, L"DynData v4 profile contained invalid items; active v4 state was left unchanged.");
        ExFreePoolWithTag(moduleState, KSW_DYN_V4_STATE_POOL_TAG);
        return status;
    }

    for (index = 0UL; index < request->capabilityGroupCount; ++index) {
        KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY* group = &moduleState->groups[index].publicEntry;
        group->presentRequiredItemCount = groupPresentRequired[index];
        group->presentOptionalItemCount = groupPresentOptional[index];
        if (group->presentRequiredItemCount >= group->requiredItemCount) {
            group->statusFlags |= KSW_DYN_V4_STATUS_FLAG_REQUIRED_COMPLETE;
            group->statusFlags |= KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED;
            moduleState->publicEntry.activeCapabilityGroupCount += 1UL;
        }
        else {
            moduleState->publicEntry.missingRequiredItemCount += group->requiredItemCount - group->presentRequiredItemCount;
        }
        if (group->presentOptionalItemCount < group->optionalItemCount) {
            group->statusFlags |= KSW_DYN_V4_STATUS_FLAG_OPTIONAL_DEGRADED;
            moduleState->publicEntry.missingOptionalItemCount += group->optionalItemCount - group->presentOptionalItemCount;
        }
    }

    if (moduleState->publicEntry.missingRequiredItemCount == 0UL) {
        moduleState->publicEntry.statusFlags |= KSW_DYN_V4_STATUS_FLAG_REQUIRED_COMPLETE;
        moduleState->publicEntry.statusFlags |= KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED;
    }
    else {
        moduleState->publicEntry.statusFlags |= KSW_DYN_V4_STATUS_FLAG_VALIDATION_FAILED;
    }
    if (moduleState->publicEntry.missingOptionalItemCount != 0UL) {
        moduleState->publicEntry.statusFlags |= KSW_DYN_V4_STATUS_FLAG_OPTIONAL_DEGRADED;
    }

    kswordArkAcquirePushLockExclusive(&gKswordDynDataV4Lock);
    RtlCopyMemory(&gKswordDynDataV4State.modules[(ULONG)moduleSlot], moduleState, sizeof(*moduleState));
    gKswordDynDataV4State.missingCount = 0UL;
    for (index = 0UL; index < KSW_DYN_V4_MAX_MODULES; ++index) {
        const KswDynV4ModuleState* storedModule = &gKswordDynDataV4State.modules[index];

        if (!storedModule->occupied) {
            continue;
        }
        if (storedModule->publicEntry.missingRequiredItemCount != 0UL) {
            kswordArkDynDataV4AppendMissing(
                &gKswordDynDataV4State,
                storedModule->publicEntry.module.image.classId,
                0UL,
                KSW_DYN_V4_MISSING_KIND_REQUIRED,
                storedModule->publicEntry.missingRequiredItemCount,
                "required items absent from applied profile");
        }
        if (storedModule->publicEntry.missingOptionalItemCount != 0UL) {
            kswordArkDynDataV4AppendMissing(
                &gKswordDynDataV4State,
                storedModule->publicEntry.module.image.classId,
                0UL,
                KSW_DYN_V4_MISSING_KIND_OPTIONAL,
                storedModule->publicEntry.missingOptionalItemCount,
                "optional items absent from applied profile");
        }
    }
    kswordArkReleasePushLockExclusive(&gKswordDynDataV4Lock);

    response->status = STATUS_SUCCESS;
    response->statusFlags = moduleState->publicEntry.statusFlags;
    response->activeCapabilityGroupCount = moduleState->publicEntry.activeCapabilityGroupCount;
    response->missingRequiredItemCount = moduleState->publicEntry.missingRequiredItemCount;
    response->missingOptionalItemCount = moduleState->publicEntry.missingOptionalItemCount;
    response->module = moduleState->publicEntry.module;
    ExFreePoolWithTag(moduleState, KSW_DYN_V4_STATE_POOL_TAG);
    kswordArkDynDataV4SetMessage(response->message, L"DynData v4 module profile accepted for safe storage.");
    return STATUS_SUCCESS;
}
