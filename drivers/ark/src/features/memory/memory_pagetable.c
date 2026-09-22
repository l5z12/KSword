/*++

Module Name:

    memory_pagetable.c

Abstract:

    x64 virtual-to-physical translation and page-table query helpers.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#if defined(_M_AMD64) || defined(_M_X64)
#include <intrin.h>
#endif

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000DL)
#endif

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID process,
    _Out_ PVOID apcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID apcState
    );

// x64 page table entry size is fixed at 8 bytes per level.
#define KSWORD_ARK_PAGE_TABLE_ENTRY_BYTES 8ULL

// x64 four-level paging uses a 9-bit index.
#define KSWORD_ARK_PAGE_TABLE_INDEX_MASK 0x1FFULL

// The lower 12 bits of CR3 are control bits; the physical base address must be page-aligned.
#define KSWORD_ARK_PAGE_TABLE_CR3_ADDRESS_MASK 0x000FFFFFFFFFF000ULL

// For standard 4KB PTEs, the PFN bit range is 12..51.
#define KSWORD_ARK_PAGE_TABLE_4KB_ADDRESS_MASK 0x000FFFFFFFFFF000ULL

// The physical base address bit range for 2MB large page PDEs is 21..51.
#define KSWORD_ARK_PAGE_TABLE_2MB_ADDRESS_MASK 0x000FFFFFFFE00000ULL

// The physical base address bit range for 1GB large page PDPTEs is 30..51.
#define KSWORD_ARK_PAGE_TABLE_1GB_ADDRESS_MASK 0x000FFFFFC0000000ULL

// When IA32_EFER.NXE is enabled, bit63 indicates NX; otherwise, the original bit is displayed without reading EFER.
#define KSWORD_ARK_PAGE_TABLE_NX_BIT 0x8000000000000000ULL

// CR4.LA57 indicates 5-level paging; the current protocol only defines 4 levels: PML4/PDPTE/PDE/PTE.
#define KSWORD_ARK_X64_CR4_LA57_BIT 0x0000000000001000ULL

// Page table entry Present bit.
#define KSWORD_ARK_PAGE_TABLE_PRESENT_BIT 0x0000000000000001ULL

// PS bit in PDE/PDPTE; the same bit in PTE is interpreted per PAT. This module uses it only in upper-level entries to detect large pages.
#define KSWORD_ARK_PAGE_TABLE_LARGE_BIT 0x0000000000000080ULL

typedef struct KswordArkPageTableWalkContext
{
    ULONG processId;
    ULONG64 virtualAddress;
    ULONG64 cr3PhysicalAddress;
    PEPROCESS processObject;
} KswordArkPageTableWalkContext;

static BOOLEAN
kswordArkPageTableIsCanonicalAddress(
    _In_ ULONG64 virtualAddress
    )
/*++

Routine Description:

    Check if the x64 virtual address is a 48-bit canonical address. Note: The current implementation does not assume LA57 five-level
    paging; unknown platforms or five-level paging environments are conservatively returned as NOT_SUPPORTED by the upper layer.

Arguments:

    VirtualAddress - Virtual address to be checked.

Return Value:

    TRUE indicates the address satisfies the 48-bit canonical rule; FALSE indicates an invalid address.

--*/
{
    ULONG64 signExtension = virtualAddress & 0xFFFF000000000000ULL;
    BOOLEAN signBitSet = ((virtualAddress & 0x0000800000000000ULL) != 0ULL) ? TRUE : FALSE;

    if (signBitSet) {
        return signExtension == 0xFFFF000000000000ULL;
    }
    return signExtension == 0ULL;
}

static ULONG
kswordArkPageTableExtractIndex(
    _In_ ULONG64 virtualAddress,
    _In_ ULONG shift
    )
/*++

Routine Description:

    Extract the page table index for a specified level. Note: x64 uses 4-level paging with
    9 bits per level; passing 39/30/21/12 yields the PML4/PDPT/PD/PT index respectively.

Arguments:

    VirtualAddress - Virtual address to be parsed.
    Shift - Number of right-shift bits.

Return Value:

    0.Page table index in the range 0..511.

--*/
{
    return (ULONG)((virtualAddress >> shift) & KSWORD_ARK_PAGE_TABLE_INDEX_MASK);
}

static ULONG
kswordArkPageTableDecodeEntryFlags(
    _In_ ULONG64 entryValue,
    _In_ BOOLEAN largePageEntry
    )
/*++

Routine Description:

    Convert raw x64 page table entry bits to shared protocol flags. Note: The function
    parses only common bits, not software-reserved bits. LargePageEntry is passed by the
    caller at the appropriate level to prevent misreporting PTE PAT bits as large pages.

Arguments:

    EntryValue - Original page table entry value.
    LargePageEntry - TRUE indicates the entry originates from PDPTE/PDE and the PS bit indicates a large page.

Return Value:

    Combination of KSWORD_ARK_PAGE_TABLE_FLAG_*.

--*/
{
    ULONG flags = 0UL;

    if ((entryValue & 0x1ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT;
    }
    if ((entryValue & 0x2ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE;
    }
    if ((entryValue & 0x4ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_USER;
    }
    if ((entryValue & 0x8ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_WRITE_THROUGH;
    }
    if ((entryValue & 0x10ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_CACHE_DISABLE;
    }
    if ((entryValue & 0x20ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_ACCESSED;
    }
    if ((entryValue & 0x40ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_DIRTY;
    }
    if (largePageEntry && (entryValue & KSWORD_ARK_PAGE_TABLE_LARGE_BIT) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE;
    }
    if ((entryValue & 0x100ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL;
    }
    if ((entryValue & KSWORD_ARK_PAGE_TABLE_NX_BIT) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_NX;
    }

    return flags;
}

static ULONG
kswordArkPageTableMergeEffectiveFlags(
    _In_ ULONG pml4eFlags,
    _In_ ULONG pdpteFlags,
    _In_ ULONG pdeFlags,
    _In_ ULONG pteFlags,
    _In_ ULONG levelCount
    )
/*++

Routine Description:

    Merge page table layer permissions into the final display flags. Note: Present/Writable/User require all
    participating layers to allow it to be valid; NX takes effect if any layer sets it; other diagnostic bits are
    preserved and displayed via OR to facilitate R3 viewing accessed/dirty/global information simultaneously.

Arguments:

    Pml4eFlags - PML4E flags。
    PdpteFlags - PDPTE flags。
    PdeFlags - PDE flags。
    PteFlags - PTE flags; may be 0 for large pages.
    LevelCount: Number of levels involved in the merge; 2 for 1GB, 3 for 2MB, 4 for 4KB.

Return Value:

    Merged KSWORD_ARK_PAGE_TABLE_FLAG_* bitmap.

--*/
{
    ULONG flags = pml4eFlags | pdpteFlags | pdeFlags | pteFlags;
    ULONG requiredMask = pml4eFlags;

    if (levelCount >= 2UL) {
        requiredMask &= pdpteFlags;
    }
    if (levelCount >= 3UL) {
        requiredMask &= pdeFlags;
    }
    if (levelCount >= 4UL) {
        requiredMask &= pteFlags;
    }

    if ((requiredMask & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) == 0UL) {
        flags &= ~KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT;
    }
    if ((requiredMask & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) == 0UL) {
        flags &= ~KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE;
    }
    if ((requiredMask & KSWORD_ARK_PAGE_TABLE_FLAG_USER) == 0UL) {
        flags &= ~KSWORD_ARK_PAGE_TABLE_FLAG_USER;
    }
    if ((pml4eFlags | pdpteFlags | pdeFlags | pteFlags) & KSWORD_ARK_PAGE_TABLE_FLAG_NX) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_NX;
    }

    return flags;
}

static NTSTATUS
kswordArkPageTableReadPhysicalU64(
    _In_ ULONG64 physicalAddress,
    _Out_ ULONG64* valueOut
    )
/*++

Routine Description:

    Read a 64-bit page table entry from a physical address. Note: The page table walker reads only 8-byte entries via the
    MmCopyMemory physical path with exception wrapping, avoiding direct mapping or dereferencing of untrusted addresses.

Arguments:

    PhysicalAddress - Physical address of the page table entry.
    ValueOut - Receives the original 64-bit value read.

Return Value:

    STATUS_SUCCESS indicates a complete 8-byte read; otherwise returns MmCopyMemory or an exception status.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T bytesCopied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (valueOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *valueOut = 0ULL;

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.PhysicalAddress.QuadPart = (LONGLONG)physicalAddress;

    __try {
        status = MmCopyMemory(
            valueOut,
            copyAddress,
            sizeof(*valueOut),
            MM_COPY_MEMORY_PHYSICAL,
            &bytesCopied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        bytesCopied = 0U;
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (bytesCopied != sizeof(*valueOut)) {
        return STATUS_PARTIAL_COPY;
    }
    return STATUS_SUCCESS;
}

static VOID
kswordArkPageTableInitInfo(
    _Out_ KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* info,
    _In_ ULONG processId,
    _In_ ULONG64 virtualAddress
    )
/*++

Routine Description:

    initialize the page table query response structure. Note: All hierarchy states are initially set to unresolved; the
    caller subsequently fills in original items, physical addresses, indices, and final VA->PA results layer by layer.

Arguments:

    Info: output page table info structure.
    ProcessId: Target PID; 0 indicates the current process context.
    VirtualAddress - Virtual address to be parsed.

Return Value:

    None. The function only writes to Info.

--*/
{
    RtlZeroMemory(info, sizeof(*info));
    info->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    info->size = sizeof(*info);
    info->processId = processId;
    info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_UNAVAILABLE;
    info->lookupStatus = STATUS_SUCCESS;
    info->walkStatus = STATUS_NOT_SUPPORTED;
    info->source = KSWORD_ARK_MEMORY_SOURCE_R0_PAGE_TABLE_WALK;
    info->largePageType = KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE;
    info->pageSize = 0UL;
    info->resolved = 0UL;
    info->virtualAddress = virtualAddress;
    info->pml4Index = kswordArkPageTableExtractIndex(virtualAddress, 39U);
    info->pdptIndex = kswordArkPageTableExtractIndex(virtualAddress, 30U);
    info->pdIndex = kswordArkPageTableExtractIndex(virtualAddress, 21U);
    info->ptIndex = kswordArkPageTableExtractIndex(virtualAddress, 12U);
}

static NTSTATUS
kswordArkPageTableAttachAndReadCr3(
    _Inout_ KswordArkPageTableWalkContext* context
    )
/*++

Routine Description:

    Read CR3 in the target process context. Note: Windows does not expose a stable offset for EPROCESS DirectoryTableBase;
    this module avoids hardcoding version-specific offsets by reading CR3 after calling KeStackAttachProcess.

Arguments:

    Context: walker context; ProcessObject must already be referenced.

Return Value:

    STATUS_SUCCESS indicates Cr3PhysicalAddress is populated; unknown architectures return STATUS_NOT_SUPPORTED.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    BOOLEAN attached = FALSE;
    unsigned __int64 cr3Value = 0ULL;
    unsigned __int64 cr4Value = 0ULL;

    if (context == NULL || context->processObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    cr4Value = __readcr4();
    if ((cr4Value & KSWORD_ARK_X64_CR4_LA57_BIT) != 0ULL) {
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(attachState, sizeof(attachState));
    __try {
        KeStackAttachProcess((PVOID)context->processObject, attachState);
        attached = TRUE;
        cr3Value = __readcr3();
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (attached) {
            KeUnstackDetachProcess(attachState);
            attached = FALSE;
        }
        return GetExceptionCode();
    }

    context->cr3PhysicalAddress =
        ((ULONG64)cr3Value) & KSWORD_ARK_PAGE_TABLE_CR3_ADDRESS_MASK;
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Context);
    return STATUS_NOT_SUPPORTED;
#endif
}

static VOID
kswordArkPageTableFinalizeInfo(
    _Inout_ KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* info
    )
/*++

Routine Description:

    Populate the derived display fields for the page table query. Note: This function calculates confidence,
    protection, and NX/write/user/global/large scalars based solely on the flags/status obtained by the
    read-only walker, avoiding redundant interpretation of underlying bits by R3 for common columns.

Arguments:

    Info: page table query result structure.

Return Value:

    None. The function only writes to Info.

--*/
{
    ULONG protection = 0UL;

    if (info == NULL) {
        return;
    }
    if ((info->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_PRESENT |
            KSWORD_ARK_MEMORY_PROTECTION_READ;
    }
    if ((info->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_WRITE;
        info->writeFlag = 1UL;
    }
    if ((info->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_NX;
        info->nxFlag = 1UL;
    }
    else if ((info->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_EXECUTE;
    }
    if ((info->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_USER) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_USER;
        info->userFlag = 1UL;
    }
    if ((info->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_GLOBAL;
        info->globalFlag = 1UL;
    }
    if ((info->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE) != 0UL ||
        info->largePageType != KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_LARGE;
        info->largePageFlag = 1UL;
    }
    info->protection = protection;

    if (info->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK && info->resolved != 0UL) {
        info->confidence = KSWORD_ARK_PAGE_TABLE_CONFIDENCE_HIGH;
    }
    else if (info->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT) {
        info->confidence = KSWORD_ARK_PAGE_TABLE_CONFIDENCE_LOW;
    }
    else if (info->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_UNAVAILABLE) {
        info->confidence = KSWORD_ARK_PAGE_TABLE_CONFIDENCE_UNKNOWN;
    }
    else {
        info->confidence = KSWORD_ARK_PAGE_TABLE_CONFIDENCE_MEDIUM;
    }
}

static NTSTATUS
kswordArkPageTableResolveProcess(
    _In_ ULONG processId,
    _Outptr_ PEPROCESS* processObjectOut
    )
/*++

Routine Description:

    Get the target process object for page table resolution. Note: If ProcessId is 0, use the current process
    and explicitly call ObReferenceObject; otherwise, obtain the reference via PsLookupProcessByProcessId.

Arguments:

    ProcessId - Target PID; 0 indicates the current process.
    ProcessObjectOut: Receives the EPROCESS reference that the caller must release.

Return Value:

    STATUS_SUCCESS or process lookup failure status.

--*/
{
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processObjectOut = NULL;

    if (processId == 0UL) {
        processObject = PsGetCurrentProcess();
        ObReferenceObject(processObject);
        *processObjectOut = processObject;
        return STATUS_SUCCESS;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *processObjectOut = processObject;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkPageTableWalk(
    _Inout_ KswordArkPageTableWalkContext* context,
    _Out_ KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* info
    )
/*++

Routine Description:

    Perform read-only traversal of the 4-level page table. Note: The function reads PML4E/PDPTE/PDE/PTE layer by
    layer; it stops immediately and returns available information upon encountering a not-present entry. When a
    1GB or 2MB large page is encountered, the final physical address is calculated using the large page offset.

Arguments:

    Context - Parsing context, containing the target process and virtual address.
    Info: output page table info structure.

Return Value:

    STATUS_SUCCESS indicates traversal logic is complete; not-present is also indicated via Info->queryStatus.

--*/
{
    ULONG64 nextTablePhysical = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (context == NULL || info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_IRQL_REJECTED;
        info->walkStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_SUCCESS;
    }
    if (!kswordArkPageTableIsCanonicalAddress(context->virtualAddress)) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_INVALID_ADDRESS;
        info->walkStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    status = kswordArkPageTableAttachAndReadCr3(context);
    if (!NT_SUCCESS(status)) {
        info->queryStatus =
            (status == STATUS_NOT_SUPPORTED) ?
            KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_SUPPORTED :
            KSWORD_ARK_MEMORY_TRANSLATE_STATUS_READ_FAILED;
        info->walkStatus = status;
        return STATUS_SUCCESS;
    }

    info->cr3PhysicalAddress = context->cr3PhysicalAddress;
    info->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PAGE_TABLE_PRESENT;

    info->pml4ePhysicalAddress =
        context->cr3PhysicalAddress +
        ((ULONG64)info->pml4Index * KSWORD_ARK_PAGE_TABLE_ENTRY_BYTES);
    status = kswordArkPageTableReadPhysicalU64(
        info->pml4ePhysicalAddress,
        &info->pml4eValue);
    info->pml4eFlags = kswordArkPageTableDecodeEntryFlags(info->pml4eValue, FALSE);
    info->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PML4E_PRESENT;
    if (!NT_SUCCESS(status)) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_READ_FAILED;
        info->walkStatus = status;
        return STATUS_SUCCESS;
    }
    if ((info->pml4eValue & KSWORD_ARK_PAGE_TABLE_PRESENT_BIT) == 0ULL) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT;
        info->walkStatus = STATUS_NO_MEMORY;
        return STATUS_SUCCESS;
    }

    nextTablePhysical = info->pml4eValue & KSWORD_ARK_PAGE_TABLE_4KB_ADDRESS_MASK;
    info->pdptePhysicalAddress =
        nextTablePhysical +
        ((ULONG64)info->pdptIndex * KSWORD_ARK_PAGE_TABLE_ENTRY_BYTES);
    status = kswordArkPageTableReadPhysicalU64(
        info->pdptePhysicalAddress,
        &info->pdpteValue);
    info->pdpteFlags = kswordArkPageTableDecodeEntryFlags(info->pdpteValue, TRUE);
    info->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PDPTE_PRESENT;
    if (!NT_SUCCESS(status)) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_READ_FAILED;
        info->walkStatus = status;
        return STATUS_SUCCESS;
    }
    if ((info->pdpteValue & KSWORD_ARK_PAGE_TABLE_PRESENT_BIT) == 0ULL) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT;
        info->walkStatus = STATUS_NO_MEMORY;
        return STATUS_SUCCESS;
    }
    if ((info->pdpteValue & KSWORD_ARK_PAGE_TABLE_LARGE_BIT) != 0ULL) {
        info->largePageType = KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_1GB;
        info->pageSize = KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_1GB;
        info->physicalAddress =
            (info->pdpteValue & KSWORD_ARK_PAGE_TABLE_1GB_ADDRESS_MASK) |
            (context->virtualAddress & (KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_1GB - 1ULL));
        info->effectiveFlags = kswordArkPageTableMergeEffectiveFlags(
            info->pml4eFlags,
            info->pdpteFlags,
            0UL,
            0UL,
            2UL);
        info->resolved = 1UL;
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK;
        info->walkStatus = STATUS_SUCCESS;
        info->fieldFlags |=
            KSWORD_ARK_MEMORY_FIELD_PHYSICAL_ADDRESS_PRESENT |
            KSWORD_ARK_MEMORY_FIELD_LARGE_PAGE_1GB |
            KSWORD_ARK_MEMORY_FIELD_PAGE_TABLE_WALK_COMPLETE;
        return STATUS_SUCCESS;
    }

    nextTablePhysical = info->pdpteValue & KSWORD_ARK_PAGE_TABLE_4KB_ADDRESS_MASK;
    info->pdePhysicalAddress =
        nextTablePhysical +
        ((ULONG64)info->pdIndex * KSWORD_ARK_PAGE_TABLE_ENTRY_BYTES);
    status = kswordArkPageTableReadPhysicalU64(
        info->pdePhysicalAddress,
        &info->pdeValue);
    info->pdeFlags = kswordArkPageTableDecodeEntryFlags(info->pdeValue, TRUE);
    info->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PDE_PRESENT;
    if (!NT_SUCCESS(status)) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_READ_FAILED;
        info->walkStatus = status;
        return STATUS_SUCCESS;
    }
    if ((info->pdeValue & KSWORD_ARK_PAGE_TABLE_PRESENT_BIT) == 0ULL) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT;
        info->walkStatus = STATUS_NO_MEMORY;
        return STATUS_SUCCESS;
    }
    if ((info->pdeValue & KSWORD_ARK_PAGE_TABLE_LARGE_BIT) != 0ULL) {
        info->largePageType = KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_2MB;
        info->pageSize = KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_2MB;
        info->physicalAddress =
            (info->pdeValue & KSWORD_ARK_PAGE_TABLE_2MB_ADDRESS_MASK) |
            (context->virtualAddress & (KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_2MB - 1ULL));
        info->effectiveFlags = kswordArkPageTableMergeEffectiveFlags(
            info->pml4eFlags,
            info->pdpteFlags,
            info->pdeFlags,
            0UL,
            3UL);
        info->resolved = 1UL;
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK;
        info->walkStatus = STATUS_SUCCESS;
        info->fieldFlags |=
            KSWORD_ARK_MEMORY_FIELD_PHYSICAL_ADDRESS_PRESENT |
            KSWORD_ARK_MEMORY_FIELD_LARGE_PAGE_2MB |
            KSWORD_ARK_MEMORY_FIELD_PAGE_TABLE_WALK_COMPLETE;
        return STATUS_SUCCESS;
    }

    nextTablePhysical = info->pdeValue & KSWORD_ARK_PAGE_TABLE_4KB_ADDRESS_MASK;
    info->ptePhysicalAddress =
        nextTablePhysical +
        ((ULONG64)info->ptIndex * KSWORD_ARK_PAGE_TABLE_ENTRY_BYTES);
    status = kswordArkPageTableReadPhysicalU64(
        info->ptePhysicalAddress,
        &info->pteValue);
    info->pteFlags = kswordArkPageTableDecodeEntryFlags(info->pteValue, FALSE);
    info->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PTE_PRESENT;
    if (!NT_SUCCESS(status)) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_READ_FAILED;
        info->walkStatus = status;
        return STATUS_SUCCESS;
    }
    if ((info->pteValue & KSWORD_ARK_PAGE_TABLE_PRESENT_BIT) == 0ULL) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT;
        info->walkStatus = STATUS_NO_MEMORY;
        return STATUS_SUCCESS;
    }

    info->largePageType = KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE;
    info->pageSize = KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_4KB;
    info->physicalAddress =
        (info->pteValue & KSWORD_ARK_PAGE_TABLE_4KB_ADDRESS_MASK) |
        (context->virtualAddress & (KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_4KB - 1ULL));
    info->effectiveFlags = kswordArkPageTableMergeEffectiveFlags(
        info->pml4eFlags,
        info->pdpteFlags,
        info->pdeFlags,
        info->pteFlags,
        4UL);
    info->resolved = 1UL;
    info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK;
    info->walkStatus = STATUS_SUCCESS;
    info->fieldFlags |=
        KSWORD_ARK_MEMORY_FIELD_PHYSICAL_ADDRESS_PRESENT |
        KSWORD_ARK_MEMORY_FIELD_PAGE_TABLE_WALK_COMPLETE;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkPageTableQueryCommon(
    _Out_ KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* info,
    _In_ ULONG processId,
    _In_ ULONG64 virtualAddress
    )
/*++

Routine Description:

    Common entry point for page table queries. Note: The function is responsible for initializing the response, referencing the target
    process, executing a read-only walker, and releasing objects; the outer IOCTL or exported function only needs to handle the buffer.

Arguments:

    Info: output page table info structure.
    ProcessId - Target PID; 0 indicates the current process.
    VirtualAddress - Virtual address to be parsed.

Return Value:

    STATUS_SUCCESS indicates Info is valid; failure typically occurs only with invalid parameters.

--*/
{
    KswordArkPageTableWalkContext context;
    NTSTATUS status = STATUS_SUCCESS;

    if (info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    kswordArkPageTableInitInfo(info, processId, virtualAddress);
    RtlZeroMemory(&context, sizeof(context));
    context.processId = processId;
    context.virtualAddress = virtualAddress;

    status = kswordArkPageTableResolveProcess(processId, &context.processObject);
    info->lookupStatus = status;
    if (!NT_SUCCESS(status)) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_PROCESS_LOOKUP_FAILED;
        info->walkStatus = STATUS_NOT_FOUND;
        kswordArkPageTableFinalizeInfo(info);
        return STATUS_SUCCESS;
    }

    status = kswordArkPageTableWalk(&context, info);
    ObDereferenceObject(context.processObject);
    context.processObject = NULL;

    if (!NT_SUCCESS(status)) {
        info->queryStatus = KSWORD_ARK_MEMORY_TRANSLATE_STATUS_READ_FAILED;
        info->walkStatus = status;
    }
    kswordArkPageTableFinalizeInfo(info);

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverTranslateVirtualAddress(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Resolve the target process virtual address to a physical address. Note: This interface returns a complete page
    table information structure, but R3 can only use the physicalAddress/pageSize/resolved fields as the VA->PA result.

Arguments:

    OutputBuffer - Fixed response buffer.
    OutputBufferLength - Length of the response buffer.
    Request - Query request containing PID and VA.
    BytesWrittenOut - Response bytes received.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; parsing details are in response->info.

--*/
{
    KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE* response = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->flags != 0UL || request->reserved != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE*)outputBuffer;

    status = kswordArkPageTableQueryCommon(
        &response->info,
        request->processId,
        request->virtualAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverQueryPageTableEntry(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query PML4E/PDPTE/PDE/PTE information corresponding to the target virtual address. Note: The
    interface reads the page table only and modifies no PTE/PDE. For large pages, it does not fabricate
    non-existent lower-level PTEs but informs the R3 presentation layer via largePageType and pageSize.

Arguments:

    OutputBuffer - Fixed response buffer.
    OutputBufferLength - Length of the response buffer.
    Request - Query request containing PID and VA.
    BytesWrittenOut - Response bytes received.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; parsing details are in response->info.

--*/
{
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE* response = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->flags != 0UL || request->reserved != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE*)outputBuffer;

    status = kswordArkPageTableQueryCommon(
        &response->info,
        request->processId,
        request->virtualAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
