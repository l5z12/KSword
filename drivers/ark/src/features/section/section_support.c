/*++

Module Name:

    section_support.c

Abstract:

    Shared Section/ControlArea helper routines for Phase-7 queries.

    ControlArea mapping walks run under EX_SPIN_LOCK at DISPATCH_LEVEL.  Two
    containment tools stop working there: MmCopyMemory requires APC_LEVEL or
    below, and __try/__except cannot catch an invalid kernel dereference — the
    fault bugchecks instead of raising.  Everything that can be validated is
    therefore validated before the lock is taken, and the walk itself only
    touches memory that MmIsAddressValid confirms is resident.

Environment:

    Kernel-mode Driver Framework

--*/

#include "section_support.h"
#include "../../platform/kernel_object_probe.h"

#define KSW_SECTION_MAPPING_HARD_WALK_LIMIT 4096UL

/*
 * EPROCESS is an opaque structure; the offset of UniqueProcessId varies by version. Note:
 * PsGetProcessId reads internal object data, so probe a conservative
 * length covering a range rather than just the first pointer.
 */
#define KSW_SECTION_EPROCESS_PROBE_BYTES 0x800U

typedef struct MmvadShort
{
    union KswMmvadShortNodeUnion
    {
        struct KswMmvadShortNodeFields
        {
            struct MmvadShort* nextVad;
            PVOID extraCreateInfo;
        } nodeFields;
        RTL_BALANCED_NODE vadNode;
    } nodeUnion;
    ULONG startingVpn;
    ULONG endingVpn;
#ifdef _WIN64
    UCHAR startingVpnHigh;
    UCHAR endingVpnHigh;
    UCHAR commitChargeHigh;
    union KswMmvadShortHigherUnion
    {
        UCHAR spareNT64VadUChar;
        struct KswMmvadShortHigherFields
        {
            UCHAR endingVpnHigher : 4;
            UCHAR commitChargeHigher : 4;
        } higherFields;
    } higherUnion;
#endif
    LONG referenceCount;
    EX_PUSH_LOCK pushLock;
    ULONG longFlags;
    ULONG longFlags1;
#ifdef _WIN64
    union KswMmvadShortU5
    {
        ULONG_PTR eventListULongPtr;
        UCHAR startingVpnHigher : 4;
    } u5;
#else
    PVOID EventList;
#endif
} MmvadShort, *PmmvadShort;

typedef struct Mmvad
{
    MmvadShort core;
    ULONG longFlags2;
    PVOID subsection;
    PVOID firstPrototypePte;
    PVOID lastContiguousPte;
    LIST_ENTRY viewLinks;
    union KswMmvadProcessUnion
    {
        PEPROCESS vadsProcess;
        UCHAR viewMapType : 3;
    } processUnion;
} MMVAD, *PMMVAD;

typedef NTSTATUS
(NTAPI* KswPsReferenceProcessFilePointerFn)(
    _In_ PEPROCESS process,
    _Outptr_ PFILE_OBJECT* fileObject
    );

static BOOLEAN
kswordArkSectionMappingWalkIsSafe(
    _In_ PVOID controlArea,
    _In_ const KswDynState* dynState,
    _Outptr_ PEX_SPIN_LOCK* lockOut,
    _Outptr_ PLIST_ENTRY* listHeadOut
    )
/*++

Routine Description:

    Perform all possible validations before raising IRQL. Note: offsets must come from available DynData; the
    lock and list head must reside entirely in resident memory; the list head and its two adjacent nodes must
    be mutually consistent via fault-tolerant reads. If any condition fails, refuse to enter the spin lock.

Return Value:

    TRUE indicates it is safe to acquire the spin lock and traverse.

--*/
{
    PEX_SPIN_LOCK lock = NULL;
    PLIST_ENTRY listHead = NULL;

    if (lockOut == NULL || listHeadOut == NULL) {
        return FALSE;
    }
    *lockOut = NULL;
    *listHeadOut = NULL;
    if (controlArea == NULL || dynState == NULL ||
        !kswordArkSectionIsOffsetPresent(dynState->kernel.mmControlAreaListHead) ||
        !kswordArkSectionIsOffsetPresent(dynState->kernel.mmControlAreaLock)) {
        return FALSE;
    }
    lock = (PEX_SPIN_LOCK)((PUCHAR)controlArea + dynState->kernel.mmControlAreaLock);
    listHead = (PLIST_ENTRY)((PUCHAR)controlArea + dynState->kernel.mmControlAreaListHead);
    if (!kswordArkKernelProbeRangeIsResident(lock, sizeof(*lock)) ||
        !kswordArkKernelProbeRangeIsResident(listHead, sizeof(*listHead)) ||
        !kswordArkKernelProbeListHeadIsSane((ULONG_PTR)listHead)) {
        return FALSE;
    }
    *lockOut = lock;
    *listHeadOut = listHead;
    return TRUE;
}

static BOOLEAN
kswordArkSectionMappingNodeIsUsable(
    _In_ PLIST_ENTRY link,
    _Outptr_ PMMVAD* vadOut
    )
/*++

Routine Description:

    Iterate and validate nodes within the lock. Note: Both the linked list node and its host MMVAD must be resident;
    otherwise, stop traversal immediately—currently at DISPATCH_LEVEL, a dereference error would cause a BSOD.

Return Value:

    TRUE indicates this node can be safely read.

--*/
{
    PMMVAD vad = NULL;

    if (vadOut == NULL) {
        return FALSE;
    }
    *vadOut = NULL;
    if (!kswordArkKernelProbeRangeIsResident(link, sizeof(*link))) {
        return FALSE;
    }
    vad = CONTAINING_RECORD(link, MMVAD, viewLinks);
    if (!kswordArkKernelProbeRangeIsResident(vad, sizeof(*vad))) {
        return FALSE;
    }
    *vadOut = vad;
    return TRUE;
}

BOOLEAN
kswordArkSectionIsOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Check if DynData offset is available. Note: Section/ControlArea are private
    structures; any missing field must fail closed, not guessed based on Windows build.

Arguments:

    Offset - Field offset in DynData.

Return Value:

    TRUE indicates the offset is available; FALSE indicates the field is unavailable.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

ULONG
kswordArkSectionNormalizeOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert the offset diagnostic value. Note: R3 displays only the offset and does
    not use the offset as a credential for subsequent kernel object operations.

Arguments:

    Offset - Original DynData offset.

Return Value:

    May display the offset, or KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE.

--*/
{
    if (!kswordArkSectionIsOffsetPresent(offset)) {
        return KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
    }

    return offset;
}

VOID
kswordArkSectionPrepareOffsets(
    _Inout_ KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE* response,
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Copy Section-related DynData diagnostic fields to the response packet. Note: These fields help the UI
    display whether the current profile satisfies Phase-7 and do not participate in object references.

Arguments:

    Response - Writable response packet.
    DynState - Snapshot of DynData.

Return Value:

    None. This function has no return value.

--*/
{
    if (response == NULL || dynState == NULL) {
        return;
    }

    response->dynDataCapabilityMask = dynState->capabilityMask;
    response->epSectionObjectOffset = kswordArkSectionNormalizeOffset(dynState->kernel.epSectionObject);
    response->mmSectionControlAreaOffset = kswordArkSectionNormalizeOffset(dynState->kernel.mmSectionControlArea);
    response->mmControlAreaListHeadOffset = kswordArkSectionNormalizeOffset(dynState->kernel.mmControlAreaListHead);
    response->mmControlAreaLockOffset = kswordArkSectionNormalizeOffset(dynState->kernel.mmControlAreaLock);
}

BOOLEAN
kswordArkSectionHasRequiredDynData(
    _In_ const KswDynState* dynState
    )
/*++

Routine Description:

    Check Section/ControlArea query capabilities. Note: This requires full KSW_CAP_SECTION_CONTROL_AREA
    to avoid reading only the SectionObject and erroneously entering the mapping enumeration.

Arguments:

    DynState - Snapshot of DynData.

Return Value:

    TRUE indicates capability is satisfied; FALSE indicates it is not queryable.

--*/
{
    if (dynState == NULL) {
        return FALSE;
    }

    return ((dynState->capabilityMask & KSW_CAP_SECTION_CONTROL_AREA) == KSW_CAP_SECTION_CONTROL_AREA) ? TRUE : FALSE;
}

NTSTATUS
kswordArkSectionReferenceProcessImageControlArea(
    _In_ PEPROCESS processObject,
    _Outptr_result_maybenull_ PFILE_OBJECT* fileObjectOut,
    _Outptr_result_maybenull_ PVOID* controlAreaOut
    )
/*++

Routine Description:

    Resolve the process image ControlArea without EPROCESS.SectionObject or
    SECTION.ControlArea offsets.  PsReferenceProcessFilePointer supplies a
    referenced FILE_OBJECT, whose public SectionObjectPointer projection owns
    the image ControlArea pointer.  The caller releases FileObjectOut.

--*/
{
    UNICODE_STRING routineName;
    KswPsReferenceProcessFilePointerFn referenceFile = NULL;
    PFILE_OBJECT fileObject = NULL;
    PSECTION_OBJECT_POINTERS sectionPointers = NULL;
    PVOID controlArea = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || fileObjectOut == NULL || controlAreaOut == NULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileObjectOut = NULL;
    *controlAreaOut = NULL;
    RtlInitUnicodeString(&routineName, L"PsReferenceProcessFilePointer");
    referenceFile = (KswPsReferenceProcessFilePointerFn)
        MmGetSystemRoutineAddress(&routineName);
    if (referenceFile == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    status = referenceFile(processObject, &fileObject);
    if (!NT_SUCCESS(status) || fileObject == NULL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    __try {
        sectionPointers = fileObject->SectionObjectPointer;
        if (sectionPointers != NULL) {
            controlArea = sectionPointers->ImageSectionObject;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status) || controlArea == NULL) {
        ObDereferenceObject(fileObject);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    *fileObjectOut = fileObject;
    *controlAreaOut = controlArea;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkSectionReadPointerField(
    _In_ PVOID object,
    _In_ ULONG offset,
    _Outptr_result_maybenull_ PVOID* pointerOut
    )
/*++

Routine Description:

    Safely read pointer fields. Note: All private field reads must be wrapped in
    SEH; return an error code if the target process exits or the field is invalid.

Arguments:

    Object - Structure base address.
    Offset - Field offset.
    PointerOut - Output pointer.

Return Value:

    STATUS_SUCCESS or an exceptional NTSTATUS.

--*/
{
    PVOID pointerValue = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (object == NULL || pointerOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkSectionIsOffsetPresent(offset)) {
        return STATUS_NOT_SUPPORTED;
    }

    __try {
        RtlCopyMemory(&pointerValue, (PUCHAR)object + offset, sizeof(pointerValue));
        *pointerOut = pointerValue;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
}

static PVOID
kswordArkSectionVadStartAddress(
    _In_ PMMVAD vad
    )
/*++

Routine Description:

    Calculate the VAD start address using the MiGetVadStartAddress formula from System Informer. Note:
    LA57 high bits are absorbed by MmvadShort.u5.StartingVpnHigher; do not guess based on system version.

Arguments:

    Vad: MMVAD in the ControlArea linked list.

Return Value:

    VAD starting virtual address.

--*/
{
#ifdef _WIN64
    ULONG_PTR higher = vad->core.u5.startingVpnHigher;
    ULONG_PTR high = vad->core.startingVpnHigh;
    ULONG_PTR low = vad->core.startingVpn;
    return (PVOID)((low | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
#else
    return (PVOID)((ULONG_PTR)Vad->Core.StartingVpn << PAGE_SHIFT);
#endif
}

static PVOID
kswordArkSectionVadEndAddress(
    _In_ PMMVAD vad
    )
/*++

Routine Description:

    Calculate the VAD end address using the MiGetVadEndAddress formula from System Informer. Note:
    Returns the boundary of the page immediately following the interval end, facilitating UI display of the mapping range.

Arguments:

    Vad: MMVAD in the ControlArea linked list.

Return Value:

    VAD ending virtual address.

--*/
{
#ifdef _WIN64
    ULONG_PTR higher = vad->core.higherUnion.higherFields.endingVpnHigher;
    ULONG_PTR high = vad->core.endingVpnHigh;
    ULONG_PTR low = vad->core.endingVpn;
    return (PVOID)(((low + 1) | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
#else
    return (PVOID)(((ULONG_PTR)Vad->Core.EndingVpn + 1) << PAGE_SHIFT);
#endif
}

NTSTATUS
kswordArkSectionReadProcessSectionObject(
    _In_ PEPROCESS processObject,
    _In_ const KswDynState* dynState,
    _Outptr_result_maybenull_ PVOID* sectionObjectOut
    )
/*++

Routine Description:

    Read the target process's main image SectionObject from EPROCESS.SectionObject. Note: Only EPROCESS objects
    resolved via PID are accepted here; arbitrary EPROCESS or Section addresses passed from R3 are rejected.

Arguments:

    ProcessObject: Referenced target EPROCESS.
    DynState - Snapshot of DynData.
    SectionObjectOut - receives the SectionObject pointer.

Return Value:

    STATUS_SUCCESS or read error.

--*/
{
    if (processObject == NULL || dynState == NULL || sectionObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *sectionObjectOut = NULL;
    return kswordArkSectionReadPointerField(processObject, dynState->kernel.epSectionObject, sectionObjectOut);
}

NTSTATUS
kswordArkSectionReadControlArea(
    _In_ PVOID sectionObject,
    _In_ const KswDynState* dynState,
    _Outptr_result_maybenull_ PVOID* controlAreaOut,
    _Out_ BOOLEAN* remoteUnsupportedOut
    )
/*++

Routine Description:

    Read ControlArea from SectionObject. Note: Remote mappings with the lower two bits set as markers are
    considered unsupported per System Informer logic, and the status is explicitly returned to the UI.

Arguments:

    SectionObject: Current pointer to EPROCESS.SectionObject.
    DynState - Snapshot of DynData.
    ControlAreaOut - Receives ControlArea.
    RemoteUnsupportedOut: Indicates whether the low-order flag signifies remote mapping unsupported.

Return Value:

    STATUS_SUCCESS, STATUS_NOT_SUPPORTED, or a read error.

--*/
{
    PVOID rawControlArea = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (controlAreaOut != NULL) {
        *controlAreaOut = NULL;
    }
    if (remoteUnsupportedOut != NULL) {
        *remoteUnsupportedOut = FALSE;
    }
    if (sectionObject == NULL || dynState == NULL || controlAreaOut == NULL || remoteUnsupportedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkSectionReadPointerField(sectionObject, dynState->kernel.mmSectionControlArea, &rawControlArea);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (((ULONG_PTR)rawControlArea & 3ULL) != 0ULL) {
        *remoteUnsupportedOut = TRUE;
        rawControlArea = (PVOID)((ULONG_PTR)rawControlArea & ~3ULL);
        *controlAreaOut = rawControlArea;
        return STATUS_NOT_SUPPORTED;
    }

    *controlAreaOut = rawControlArea;
    return (rawControlArea != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
kswordArkSectionEnumerateMappings(
    _In_ PVOID controlArea,
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE* response,
    _In_ size_t entryCapacity
    )
/*++

Routine Description:

    enumerate the ControlArea mapping list. Note: Logic follows the core model of System Informer:
    Hold the MmControlAreaLock shared spin lock, traverse MmControlAreaListHead, and
    reverse-engineer the process PID and start/end addresses from MMVAD.ViewLinks.

Arguments:

    ControlArea: Pointer to the already-read ControlArea.
    DynState - Snapshot of DynData.
    Response - Writable response packet.
    EntryCapacity - Output mapping entry capacity.

Return Value:

    STATUS_SUCCESS or list/lock/read error.

--*/
{
    PEX_SPIN_LOCK lock = NULL;
    PLIST_ENTRY listHead = NULL;
    PLIST_ENTRY link = NULL;
    KIRQL oldIrql = 0;
    BOOLEAN lockHeld = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    ULONG walked = 0UL;

    if (controlArea == NULL || dynState == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: All checks that can be completed at low IRQL must occur before acquiring the lock. */
    if (!kswordArkSectionMappingWalkIsSafe(
            controlArea,
            dynState,
            &lock,
            &listHead)) {
        return STATUS_NOT_SUPPORTED;
    }

    oldIrql = ExAcquireSpinLockShared(lock);
    lockHeld = TRUE;

    for (link = listHead->Flink; link != listHead; link = link->Flink) {
        PMMVAD vad = NULL;

        /* Note: A cyclic but self-consistent linked list causes DISPATCH_LEVEL traversal to never return. */
        if (walked >= KSW_SECTION_MAPPING_HARD_WALK_LIMIT) {
            response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_MAPPING_TRUNCATED;
            break;
        }
        walked += 1UL;
        if (!kswordArkSectionMappingNodeIsUsable(link, &vad)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (response->totalCount != MAXULONG) {
            response->totalCount += 1UL;
        }

        if ((size_t)response->returnedCount < entryCapacity) {
            KSWORD_ARK_SECTION_MAPPING_ENTRY* entry = &response->mappings[response->returnedCount];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->viewMapType = (ULONG)vad->processUnion.viewMapType;
            if (vad->processUnion.viewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS) {
                PEPROCESS mappedProcess = (PEPROCESS)((ULONG_PTR)vad->processUnion.vadsProcess & ~(ULONG_PTR)KSWORD_ARK_SECTION_MAP_TYPE_PROCESS);
                if (kswordArkKernelProbeRangeIsResident(
                        mappedProcess,
                        KSW_SECTION_EPROCESS_PROBE_BYTES)) {
                    entry->processId = HandleToULong(PsGetProcessId(mappedProcess));
                }
            }
            entry->startVa = (ULONG64)(ULONG_PTR)kswordArkSectionVadStartAddress(vad);
            entry->endVa = (ULONG64)(ULONG_PTR)kswordArkSectionVadEndAddress(vad);
            response->returnedCount += 1UL;
        }

        if (!kswordArkKernelProbeRangeIsResident(link->Flink, sizeof(*link)) ||
            link->Flink->Blink != link) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    if (lockHeld) {
        ExReleaseSpinLockShared(lock, oldIrql);
        lockHeld = FALSE;
    }

    if (NT_SUCCESS(status)) {
        response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_MAPPING_LIST_PRESENT;
        if (response->returnedCount < response->totalCount) {
            response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_MAPPING_TRUNCATED;
        }
    }

    return status;
}

NTSTATUS
kswordArkSectionEnumerateFileControlAreaMappings(
    _In_ PVOID controlArea,
    _In_ ULONG sectionKind,
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE* response,
    _In_ size_t entryCapacity
    )
/*++

Routine Description:

    Enumerates the mapping list in the file's Data/Image ControlArea. Note: FileObject's
    SECTION_OBJECT_POINTERS directly provides ControlArea, so MmSectionControlArea
    offset is no longer used; only MmControlAreaListHead and Lock are reused.

Arguments:

    ControlArea in FileObject->SectionObjectPointer's Data/Image ControlArea.
    SectionKind - current ControlArea type, Data or Image.
    DynState - Snapshot of DynData, providing ControlArea list and lock offset.
    Response - Writable file-mapped response packet.
    EntryCapacity - Maximum output entry capacity.

Return Value:

    STATUS_SUCCESS or list/lock access error.

--*/
{
    PEX_SPIN_LOCK lock = NULL;
    PLIST_ENTRY listHead = NULL;
    PLIST_ENTRY link = NULL;
    KIRQL oldIrql = 0;
    BOOLEAN lockHeld = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    ULONG walked = 0UL;

    if (controlArea == NULL || dynState == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Note: All checks that can be completed at low IRQL must occur before acquiring the lock. */
    if (!kswordArkSectionMappingWalkIsSafe(
            controlArea,
            dynState,
            &lock,
            &listHead)) {
        return STATUS_NOT_SUPPORTED;
    }

    oldIrql = ExAcquireSpinLockShared(lock);
    lockHeld = TRUE;

    for (link = listHead->Flink; link != listHead; link = link->Flink) {
        PMMVAD vad = NULL;

        /* Note: A cyclic but self-consistent linked list causes DISPATCH_LEVEL traversal to never return. */
        if (walked >= KSW_SECTION_MAPPING_HARD_WALK_LIMIT) {
            response->fieldFlags |=
                KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_TRUNCATED;
            break;
        }
        walked += 1UL;
        if (!kswordArkSectionMappingNodeIsUsable(link, &vad)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (response->totalCount != MAXULONG) {
            response->totalCount += 1UL;
        }

        if ((size_t)response->returnedCount < entryCapacity) {
            KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY* entry = &response->mappings[response->returnedCount];
            RtlZeroMemory(entry, sizeof(*entry));
            entry->sectionKind = sectionKind;
            entry->viewMapType = (ULONG)vad->processUnion.viewMapType;
            entry->controlAreaAddress = (ULONG64)(ULONG_PTR)controlArea;
            if (vad->processUnion.viewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS) {
                PEPROCESS mappedProcess = (PEPROCESS)((ULONG_PTR)vad->processUnion.vadsProcess & ~(ULONG_PTR)KSWORD_ARK_SECTION_MAP_TYPE_PROCESS);
                if (kswordArkKernelProbeRangeIsResident(
                        mappedProcess,
                        KSW_SECTION_EPROCESS_PROBE_BYTES)) {
                    entry->processId = HandleToULong(PsGetProcessId(mappedProcess));
                    if (response->mappedProcessCount != MAXULONG) {
                        response->mappedProcessCount += 1UL;
                    }
                    if (sectionKind == KSWORD_ARK_FILE_SECTION_KIND_DATA &&
                        response->dataMappedProcessCount != MAXULONG) {
                        response->dataMappedProcessCount += 1UL;
                    }
                    if (sectionKind == KSWORD_ARK_FILE_SECTION_KIND_IMAGE &&
                        response->imageMappedProcessCount != MAXULONG) {
                        response->imageMappedProcessCount += 1UL;
                    }
                }
            }
            entry->startVa = (ULONG64)(ULONG_PTR)kswordArkSectionVadStartAddress(vad);
            entry->endVa = (ULONG64)(ULONG_PTR)kswordArkSectionVadEndAddress(vad);
            response->returnedCount += 1UL;
        }

        if (!kswordArkKernelProbeRangeIsResident(link->Flink, sizeof(*link)) ||
            link->Flink->Blink != link) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
    }

    if (lockHeld) {
        ExReleaseSpinLockShared(lock, oldIrql);
        lockHeld = FALSE;
    }

    if (NT_SUCCESS(status)) {
        response->fieldFlags |= KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_LIST_PRESENT;
        if (response->returnedCount < response->totalCount) {
            response->fieldFlags |= KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_TRUNCATED;
        }
    }

    return status;
}
