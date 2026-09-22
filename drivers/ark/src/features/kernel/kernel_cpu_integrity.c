/*++
Module Name:
    kernel_cpu_integrity.c
Abstract:
    Read-only per-CPU descriptor/MSR/control-register evidence collection for
    DriverDock integrity diagnostics.
Environment:
    Kernel-mode Driver Framework
--*/
#include "kernel_cpu_integrity.h"
#include "kernel_idt_baseline.h"
#include "kernel_idt_consistency.h"
#include "kernel_image_section_map.h"
#include <intrin.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#define KSW_CPU_INTEGRITY_MSR_EFER 0xC0000080UL
#define KSW_CPU_INTEGRITY_MSR_LSTAR 0xC0000082UL
#define KSW_CPU_INTEGRITY_MSR_SYSENTER_EIP 0x00000176UL
#define KSW_CPU_INTEGRITY_CR0_WP 0x0000000000010000ULL
#define KSW_CPU_INTEGRITY_CR4_SMEP 0x0000000000100000ULL
#define KSW_CPU_INTEGRITY_CR4_SMAP 0x0000000000200000ULL
#define KSW_CPU_INTEGRITY_EFER_NXE 0x0000000000000800ULL
#define KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES 16UL
#define KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES 8UL
#define KSW_CPU_INTEGRITY_MAX_GDT_ENTRIES 256UL
#define KSW_DRIVER_INTEGRITY_LOADED_MODULE_LIMIT 512UL
#ifndef ALL_PROCESSOR_GROUPS
#define ALL_PROCESSOR_GROUPS 0xFFFFU
#endif
#if defined(_M_AMD64) || defined(_M_X64)
extern void _sgdt(void*);
#pragma intrinsic(_sgdt)
#define KswordARKCpuStoreGdtr _sgdt
#else
#define KswordARKCpuStoreGdtr(_Destination) UNREFERENCED_PARAMETER(_Destination)
#endif
#pragma pack(push, 1)
typedef struct KswCpuIntegrityDescriptorRegister
{
    USHORT limit;
    ULONG_PTR base;
} KswCpuIntegrityDescriptorRegister, *PkswCpuIntegrityDescriptorRegister;
typedef struct KswCpuIntegrityIdtEntrY64
{
    USHORT offsetLow;
    USHORT selector;
    USHORT istAndType;
    USHORT offsetMiddle;
    ULONG offsetHigh;
    ULONG reserved;
} KswCpuIntegrityIdtEntrY64, *PkswCpuIntegrityIdtEntrY64;
#pragma pack(pop)
typedef struct KswCpuIntegritySample
{
    ULONG group;
    ULONG number;
    ULONG captured;
    ULONGLONG cr0;
    ULONGLONG cr4;
    ULONGLONG efer;
    ULONGLONG lstar;
    ULONGLONG sysenterEip;
    KswCpuIntegrityDescriptorRegister idtr;
    KswCpuIntegrityDescriptorRegister gdtr;
} KswCpuIntegritySample, *PkswCpuIntegritySample;
static VOID
kswordArkCpuIntegrityFormatDetail(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_z_ PCWSTR formatText,
    ...
    )
/*++
Routine Description:
    Format a bounded wide detail string for CPU evidence rows.
Arguments:
    Destination - Fixed output buffer.
    DestinationChars - Output capacity in WCHARs.
    FormatText - printf-style wide format.
    ... - Formatting arguments.
Return Value:
    None. Invalid output is ignored.
--*/
{
    va_list arguments;
    if (destination == NULL || destinationChars == 0UL || formatText == NULL) {
        return;
    }
    destination[0] = L'\0';
    va_start(arguments, formatText);
    (VOID)RtlStringCbVPrintfW(destination, (SIZE_T)destinationChars * sizeof(WCHAR), formatText, arguments);
    va_end(arguments);
    destination[destinationChars - 1UL] = L'\0';
}
VOID
kswordArkDriverIntegrityCopyWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    )
/*++
Routine Description:
    Copy a NUL-terminated wide string into a fixed protocol buffer.
Arguments:
    Destination - Fixed output buffer.
    DestinationChars - Output capacity in WCHARs.
    Source - Optional source string.
Return Value:
    None. Output is terminated when a buffer is supplied.
--*/
{
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL) {
        return;
    }
    (VOID)RtlStringCchCopyNW(destination, destinationChars, source, destinationChars - 1UL);
    destination[destinationChars - 1UL] = L'\0';
}
const KswHookSystemModuleEntry*
kswordArkDriverIntegrityFindModuleForAddress(
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONGLONG address
    )
/*++
Routine Description:
    Resolve a kernel virtual address to a loaded module snapshot row.
Arguments:
    ModuleInfo - Optional SystemModuleInformation snapshot.
    Address - Address to classify.
Return Value:
    Owning module row or NULL.
--*/
{
    if (address == 0ULL || address > (ULONGLONG)((ULONG_PTR)~((ULONG_PTR)0U))) {
        return NULL;
    }
    return kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)address);
}
BOOLEAN
kswordArkDriverIntegrityIsCoreKernelModule(
    _In_opt_ const KswHookSystemModuleEntry* moduleEntry
    )
/*++
Routine Description:
    Decide whether a module is one of the normal ntoskrnl/HAL entry owners.
Arguments:
    ModuleEntry - Optional loaded-module snapshot row.
Return Value:
    TRUE for nt kernel or HAL style filenames; otherwise FALSE.
--*/
{
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;
    if (moduleEntry == NULL) {
        return FALSE;
    }
    kswordArkHookGetModuleFileName(moduleEntry, &fileName, &fileNameBytes);
    return kswordArkHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "ntoskrnl.exe") ||
        kswordArkHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "ntkrnlmp.exe") ||
        kswordArkHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "ntkrnlpa.exe") ||
        kswordArkHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "ntkrpamp.exe") ||
        kswordArkHookBoundedAnsiEqualsInsensitive(fileName, fileNameBytes, "hal.dll");
}
KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*
kswordArkDriverIntegrityAddEvidence(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ ULONG evidenceClass,
    _In_ ULONGLONG objectAddress,
    _In_ ULONGLONG targetAddress,
    _In_ ULONG riskFlags,
    _In_ ULONG sourceMask,
    _In_ ULONG confidence,
    _In_ ULONG processorGroup,
    _In_ ULONG processorNumber,
    _In_ ULONG vector,
    _In_opt_ const KswHookSystemModuleEntry* ownerModule,
    _In_opt_z_ PCWSTR detailText
    )
/*++
Routine Description:
    Append one variable evidence row and preserve total count on truncation.
Arguments:
    Builder - Response builder state.
    EvidenceClass - Evidence class identifier.
    ObjectAddress - Object or field address under inspection.
    TargetAddress - Observed target address.
    RiskFlags - Risk bits for the row.
    SourceMask - Evidence source mask for the row.
    Confidence - 0..100 row confidence.
    ProcessorGroup - CPU group or ULONG_MAX for non-CPU rows.
    ProcessorNumber - CPU number or ULONG_MAX for non-CPU rows.
    Vector - IDT vector or ULONG_MAX for non-vector rows.
    OwnerModule - Optional owner module for TargetAddress.
    DetailText - Optional detail string.
Return Value:
    Pointer to the appended row, or NULL when validation/capacity rejected it.
--*/
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* response = NULL;
    KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
    if (builder == NULL || builder->response == NULL) {
        return NULL;
    }
    response = builder->response;
    response->totalCount += 1UL;
    response->sourceMask |= sourceMask;
    response->flags |= riskFlags;
    if ((builder->rowLimit != 0UL && response->returnedCount >= builder->rowLimit) || response->returnedCount >= builder->capacity) {
        response->flags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED;
        return NULL;
    }
    row = &response->entries[response->returnedCount];
    RtlZeroMemory(row, sizeof(*row));
    row->evidenceClass = evidenceClass;
    row->riskFlags = riskFlags;
    row->sourceMask = sourceMask;
    row->confidence = confidence;
    row->processorGroup = processorGroup;
    row->processorNumber = processorNumber;
    row->vector = vector;
    row->objectAddress = objectAddress;
    row->targetAddress = targetAddress;
    if (ownerModule != NULL) {
        const UCHAR* fileName = NULL;
        ULONG fileNameBytes = 0UL;
        row->ownerModuleBase = (ULONGLONG)(ULONG_PTR)ownerModule->imageBase;
        row->ownerModuleSize = ownerModule->imageSize;
        kswordArkHookGetModuleFileName(ownerModule, &fileName, &fileNameBytes);
        kswordArkHookCopyBoundedAnsiToWide(fileName, fileNameBytes, row->ownerModule, KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS);
    }
    kswordArkDriverIntegrityCopyWide(row->detail, KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS, detailText);
    response->returnedCount += 1UL;
    return row;
}
BOOLEAN
kswordArkDriverIntegrityOffsetPresent(
    _In_ ULONG offset
    )
/*++
Routine Description:
    Test whether a DynData offset is usable for read-only field access.
Arguments:
    Offset - Offset value from the active DynData snapshot.
Return Value:
    TRUE when the offset is not a sentinel.
--*/
{
    return offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL;
}
static BOOLEAN
kswordArkDriverIntegrityReadLoadedModuleRecord(
    _In_ ULONGLONG entryAddress,
    _In_ const KswDynKernelOffsets* offsets,
    _Out_ KswDriverIntegrityLdrTarget* record
    )
/*++
Routine Description:
    Read one KLDR entry using only DynData offsets and guarded memory copies.
Arguments:
    EntryAddress - Address of the KLDR_DATA_TABLE_ENTRY candidate.
    Offsets - Active DynData kernel offsets.
    Record - Receives the selected KLDR fields and a bounded basename.
Return Value:
    TRUE when the required fields were copied.
--*/
{
    UNICODE_STRING baseName;
    WCHAR baseNameBuffer[KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS] = { 0 };
    ULONG baseNameChars = 0UL;
    if (record == NULL || offsets == NULL || entryAddress == 0ULL) {
        return FALSE;
    }
    if (!kswordArkDriverIntegrityOffsetPresent(offsets->kldrInLoadOrderLinks) ||
        !kswordArkDriverIntegrityOffsetPresent(offsets->kldrDllBase) ||
        !kswordArkDriverIntegrityOffsetPresent(offsets->kldrSizeOfImage)) {
        return FALSE;
    }
    RtlZeroMemory(record, sizeof(*record));
    record->available = TRUE;
    record->entryAddress = entryAddress;
    record->linkAddress = entryAddress + (ULONGLONG)offsets->kldrInLoadOrderLinks;
    if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(entryAddress + (ULONGLONG)offsets->kldrDllBase), &record->dllBase, sizeof(record->dllBase)) ||
        !kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(entryAddress + (ULONGLONG)offsets->kldrSizeOfImage), &record->sizeOfImage, sizeof(record->sizeOfImage))) {
        return FALSE;
    }
    if (kswordArkDriverIntegrityOffsetPresent(offsets->kldrBaseDllName) &&
        kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(entryAddress + (ULONGLONG)offsets->kldrBaseDllName), &baseName, sizeof(baseName)) &&
        baseName.Buffer != NULL &&
        baseName.Length != 0U) {
        baseNameChars = (ULONG)(baseName.Length / sizeof(WCHAR));
        if (baseNameChars >= RTL_NUMBER_OF(baseNameBuffer)) {
            baseNameChars = RTL_NUMBER_OF(baseNameBuffer) - 1UL;
        }
        if (baseNameChars != 0UL &&
            kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)baseName.Buffer, baseNameBuffer, (SIZE_T)baseNameChars * sizeof(WCHAR))) {
            baseNameBuffer[baseNameChars] = L'\0';
            baseName.Buffer = baseNameBuffer;
            baseName.Length = (USHORT)(baseNameChars * sizeof(WCHAR));
            baseName.MaximumLength = baseName.Length;
            kswordArkDriverIntegrityCopyWide(record->baseDllName, RTL_NUMBER_OF(record->baseDllName), baseNameBuffer);
        }
    }
    return TRUE;
}
ULONGLONG
kswordArkDriverIntegrityNtosAddressFromRva(
    _In_ const KswDynState* dynState,
    _In_ ULONG rva,
    _In_ SIZE_T probeBytes
    )
/*++
Routine Description:
    Convert a DynData ntoskrnl RVA to a readable kernel VA.
Arguments:
    DynState - Active DynData snapshot.
    Rva - Global RVA from the PDB profile.
    ProbeBytes - Optional bytes that must fit inside the image.
Return Value:
    Kernel VA, or zero when DynData is inactive/untrusted/unreadable.
--*/
{
    UCHAR probe[sizeof(LIST_ENTRY)] = { 0 };
    ULONGLONG address = 0ULL;
    if (dynState == NULL || !dynState->initialized || !dynState->ntosActive ||
        dynState->ntoskrnl.imageBase == 0ULL || dynState->ntoskrnl.sizeOfImage == 0UL ||
        !kswordArkDriverIntegrityOffsetPresent(rva)) {
        return 0ULL;
    }
    if (rva >= dynState->ntoskrnl.sizeOfImage ||
        probeBytes > sizeof(probe) ||
        (probeBytes != 0U && ((ULONGLONG)rva + (ULONGLONG)probeBytes) > (ULONGLONG)dynState->ntoskrnl.sizeOfImage) ||
        dynState->ntoskrnl.imageBase > (((ULONGLONG)~0ULL) - (ULONGLONG)rva)) {
        return 0ULL;
    }
    address = dynState->ntoskrnl.imageBase + (ULONGLONG)rva;
    if (probeBytes != 0U &&
        !kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)address, probe, probeBytes)) {
        return 0ULL;
    }
    return address;
}
NTSTATUS
kswordArkDriverIntegrityFindLoadedModule(
    _In_ const KswDynState* dynState,
    _In_ ULONGLONG driverStart,
    _Out_ KswDriverIntegrityLdrTarget* targetOut
    )
/*++
Routine Description:
    Walk PsLoadedModuleList read-only with DynData KLDR offsets and find the target image.
Arguments:
    DynState - Query-time DynData snapshot.
    DriverStart - DriverObject->DriverStart or requested module base.
    TargetOut - Receives the matched target or list-head evidence.
Return Value:
    STATUS_SUCCESS when a target row is found, STATUS_NOT_FOUND for a valid
    walk without a target match, or an explanatory status for unavailable data.
--*/
{
    ULONGLONG listHead = 0ULL;
    LIST_ENTRY headLinks;
    ULONGLONG currentLink = 0ULL;
    ULONG visited = 0UL;
    if (targetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(targetOut, sizeof(*targetOut));
    if (dynState == NULL ||
        !dynState->initialized ||
        !dynState->ntosActive ||
        (dynState->capabilityMask & KSW_CAP_KERNEL_MODULE_LIST_FIELDS) == 0ULL ||
        !kswordArkDriverIntegrityOffsetPresent(dynState->kernelGlobals.psLoadedModuleList)) {
        return STATUS_NOT_SUPPORTED;
    }
    listHead = kswordArkDriverIntegrityNtosAddressFromRva(dynState, dynState->kernelGlobals.psLoadedModuleList, sizeof(LIST_ENTRY));
    if (listHead == 0ULL) {
        return STATUS_NOT_FOUND;
    }
    if (!kswordArkDriverIntegrityOffsetPresent(dynState->kernel.kldrInLoadOrderLinks) ||
        !kswordArkDriverIntegrityOffsetPresent(dynState->kernel.kldrDllBase) ||
        !kswordArkDriverIntegrityOffsetPresent(dynState->kernel.kldrSizeOfImage)) {
        return STATUS_NOT_SUPPORTED;
    }
    RtlZeroMemory(&headLinks, sizeof(headLinks));
    if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)listHead, &headLinks, sizeof(headLinks))) {
        return STATUS_ACCESS_VIOLATION;
    }
    targetOut->available = TRUE;
    targetOut->listHeadAddress = listHead;
    currentLink = (ULONGLONG)(ULONG_PTR)headLinks.Flink;
    while (currentLink != 0ULL && currentLink != listHead && visited < KSW_DRIVER_INTEGRITY_LOADED_MODULE_LIMIT) {
        KswDriverIntegrityLdrTarget record;
        ULONGLONG entryAddress = 0ULL;
        LIST_ENTRY links;
        if (currentLink < (ULONGLONG)dynState->kernel.kldrInLoadOrderLinks) {
            return STATUS_ACCESS_VIOLATION;
        }
        entryAddress = currentLink - (ULONGLONG)dynState->kernel.kldrInLoadOrderLinks;
        RtlZeroMemory(&record, sizeof(record));
        RtlZeroMemory(&links, sizeof(links));
        if (!kswordArkDriverIntegrityReadLoadedModuleRecord(entryAddress, &dynState->kernel, &record)) {
            return STATUS_PARTIAL_COPY;
        }
        record.listHeadAddress = listHead;
        if (driverStart != 0ULL &&
            record.sizeOfImage != 0UL &&
            record.dllBase <= (((ULONGLONG)~0ULL) - (ULONGLONG)record.sizeOfImage) &&
            driverStart >= record.dllBase &&
            driverStart < (record.dllBase + (ULONGLONG)record.sizeOfImage)) {
            record.found = TRUE;
            RtlCopyMemory(targetOut, &record, sizeof(*targetOut));
            return STATUS_SUCCESS;
        }
        if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)currentLink, &links, sizeof(links))) {
            return STATUS_PARTIAL_COPY;
        }
        currentLink = (ULONGLONG)(ULONG_PTR)links.Flink;
        ++visited;
    }
    return (visited >= KSW_DRIVER_INTEGRITY_LOADED_MODULE_LIMIT) ? STATUS_MORE_ENTRIES : STATUS_NOT_FOUND;
}
static ULONGLONG
kswordArkCpuIntegrityIdtHandler(
    _In_ const KswCpuIntegrityIdtEntrY64* entry
    )
/*++
Routine Description:
    Decode one x64 IDT gate handler address from copied descriptor bytes.
Arguments:
    Entry - Copied IDT gate descriptor.
Return Value:
    Handler virtual address, or zero for invalid input.
--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONGLONG high = 0ULL;
    ULONGLONG middle = 0ULL;
    ULONGLONG low = 0ULL;
    if (entry == NULL) {
        return 0ULL;
    }
    low = (ULONGLONG)entry->offsetLow;
    middle = ((ULONGLONG)entry->offsetMiddle) << 16;
    high = ((ULONGLONG)entry->offsetHigh) << 32;
    return high | middle | low;
#else
    UNREFERENCED_PARAMETER(Entry);
    return 0ULL;
#endif
}

static BOOLEAN
kswordArkCpuIntegrityGdtDescriptorIsWide(
    _In_ ULONG type,
    _In_ BOOLEAN userSegment
    )
/*++
Routine Description:
    Decide whether one long-mode GDT system descriptor consumes two slots.
Arguments:
    Type - Four-bit architectural descriptor type.
    UserSegment - TRUE when the S bit marks a code/data descriptor.
Return Value:
    TRUE for LDT/TSS/call/interrupt/trap system descriptors; FALSE otherwise.
--*/
{
    if (userSegment) {
        return FALSE;
    }
    return type == 0x2UL || type == 0x9UL || type == 0xBUL ||
        type == 0xCUL || type == 0xEUL || type == 0xFUL;
}

static VOID
kswordArkCpuIntegrityPopulateDescriptorFields(
    _Inout_opt_ KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row,
    _In_ ULONG selector,
    _In_ ULONG type,
    _In_ ULONG dpl,
    _In_ ULONG flags,
    _In_ ULONG descriptorSize,
    _In_ ULONGLONG tableBase,
    _In_ ULONG tableLimit,
    _In_ ULONGLONG base,
    _In_ ULONGLONG limit,
    _In_ ULONGLONG rawLow,
    _In_ ULONGLONG rawHigh
    )
/*++
Routine Description:
    Fill the append-only v3 descriptor columns on one evidence row.
Arguments:
    Row - Row returned by the bounded evidence builder.
    Selector - IDT code selector or GDT selector.
    Type - Architectural gate/segment type.
    Dpl - descriptor privilege level.
    Flags - KSWORD_ARK_DESCRIPTOR_FLAG_* bits.
    DescriptorSize - descriptor byte width.
    TableBase - IDTR/GDTR base captured on the target CPU.
    TableLimit - IDTR/GDTR limit captured on the target CPU.
    Base - Handler or segment base decoded from the descriptor.
    Limit - Effective segment limit; zero for IDT gates.
    RawLow - First eight descriptor bytes.
    RawHigh - Second eight descriptor bytes when present.
Return Value:
    None.
--*/
{
    if (row == NULL) {
        return;
    }
    row->fieldMask |= KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DESCRIPTOR;
    row->descriptorSelector = selector;
    row->descriptorType = type;
    row->descriptorDpl = dpl;
    row->descriptorFlags = flags;
    row->descriptorSize = descriptorSize;
    row->descriptorTableBase = tableBase;
    row->descriptorTableLimit = tableLimit;
    row->descriptorBase = base;
    row->descriptorLimit = limit;
    row->descriptorRawLow = rawLow;
    row->descriptorRawHigh = rawHigh;
}
static VOID
kswordArkCpuIntegrityCaptureCurrent(
    _Inout_ KswCpuIntegritySample* sample
    )
/*++
Routine Description:
    Capture only read-only CPU state on the current processor.
Arguments:
    Sample - Per-CPU sample to populate.
Return Value:
    None. Unsupported architectures mark Captured as zero.
--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    if (sample == NULL) {
        return;
    }
    sample->cr0 = __readcr0();
    sample->cr4 = __readcr4();
    sample->efer = __readmsr(KSW_CPU_INTEGRITY_MSR_EFER);
    sample->lstar = __readmsr(KSW_CPU_INTEGRITY_MSR_LSTAR);
    sample->sysenterEip = __readmsr(KSW_CPU_INTEGRITY_MSR_SYSENTER_EIP);
    __sidt(&sample->idtr);
    KswordARKCpuStoreGdtr(&sample->gdtr);
    sample->captured = 1UL;
#else
    UNREFERENCED_PARAMETER(Sample);
#endif
}
static VOID
kswordArkCpuIntegrityEmitControlRows(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ const KswCpuIntegritySample* sample,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_opt_ const KswIdtConsistencyView* consistencyView
    )
/*++
Routine Description:
    Emit CR0/CR4/EFER/LSTAR/SYSENTER and descriptor-table summary rows.
Arguments:
    Builder - Response builder.
    Sample - Captured CPU state.
    ModuleInfo - Optional module snapshot for MSR owner attribution.
    ConsistencyView - Optional cross-CPU IDTR view used to score the table row.
Return Value:
    None. Rows are appended to Builder.
--*/
{
    ULONG consistencyRisk = 0UL;
    ULONG tableRisk = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    ULONG lstarSection = KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
    ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    ULONG lstarRisk = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    ULONG sysenterRisk = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
    const KswHookSystemModuleEntry* lstarOwner = NULL;
    const KswHookSystemModuleEntry* sysenterOwner = NULL;
    if (builder == NULL || sample == NULL || sample->captured == 0UL) {
        return;
    }
    if ((sample->cr0 & KSW_CPU_INTEGRITY_CR0_WP) == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED;
    }
    if ((sample->cr4 & KSW_CPU_INTEGRITY_CR4_SMEP) == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED;
    }
    if ((sample->cr4 & KSW_CPU_INTEGRITY_CR4_SMAP) == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED;
    }
    if ((sample->efer & KSW_CPU_INTEGRITY_EFER_NXE) == 0ULL) {
        riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED;
    }
    kswordArkCpuIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"CR0=0x%llX CR4=0x%llX EFER=0x%llX; WP/SMEP/SMAP/NXE read-only state.", sample->cr0, sample->cr4, sample->efer);
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL, 0ULL, 0ULL, riskFlags,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR, 90UL, sample->group, sample->number, ~0UL, NULL, detail);
    lstarOwner = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, sample->lstar);
    sysenterOwner = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, sample->sysenterEip);
    if (lstarOwner == NULL) {
        lstarRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
    }
    else {
        if (!kswordArkDriverIntegrityIsCoreKernelModule(lstarOwner)) {
            lstarRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER;
        }
        // The syscall entry point must also fall within the executable section of the owning module.
        lstarSection = kswordArkImageClassifyAddress(lstarOwner, sample->lstar, NULL, 0UL, NULL);
        if (lstarSection == KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE ||
            lstarSection == KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS) {
            lstarRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC;
        }
    }
    if (sample->sysenterEip != 0ULL) {
        if (sysenterOwner == NULL) {
            sysenterRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
        }
        else if (!kswordArkDriverIntegrityIsCoreKernelModule(sysenterOwner)) {
            sysenterRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER;
        }
    }
    kswordArkCpuIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail), L"MSR_LSTAR=0x%llX; SYSENTER_EIP=0x%llX.", sample->lstar, sample->sysenterEip);
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY, 0ULL, sample->lstar,
        lstarRisk,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, 90UL, sample->group, sample->number, ~0UL, lstarOwner, detail);
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY, 0ULL, sample->sysenterEip,
        sysenterRisk,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, 70UL, sample->group, sample->number, ~0UL, sysenterOwner, L"SYSENTER_EIP captured read-only; x64 systems may leave this path unused.");
    // The descriptor table summary row now includes the cross-CPU consistency and startup baseline judgment results.
    consistencyRisk = kswordArkIdtConsistencyClassify(consistencyView, sample->group, sample->number);
    if ((consistencyRisk & KSW_IDT_CONSISTENCY_RISK_DIVERGED) != 0UL) {
        tableRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_DIVERGED;
    }
    if ((consistencyRisk & KSW_IDT_CONSISTENCY_RISK_RELOCATED) != 0UL) {
        tableRisk |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_RELOCATED;
    }
    kswordArkCpuIntegrityFormatDetail(detail, RTL_NUMBER_OF(detail),
        L"IDTR base=0x%llX limit=0x%04X; GDTR base=0x%llX limit=0x%04X; majority IDT base=0x%llX limit=0x%04lX on %lu/%lu CPU.",
        (ULONGLONG)sample->idtr.base, sample->idtr.limit, (ULONGLONG)sample->gdtr.base, sample->gdtr.limit,
        (consistencyView != NULL) ? consistencyView->majorityBase : 0ULL,
        (consistencyView != NULL) ? consistencyView->majorityLimit : 0UL,
        (consistencyView != NULL) ? consistencyView->majorityCount : 0UL,
        (consistencyView != NULL) ? consistencyView->cpuCount : 0UL);
    kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE, (ULONGLONG)sample->idtr.base,
        (ULONGLONG)sample->gdtr.base, tableRisk,
        KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT, 90UL, sample->group, sample->number, ~0UL, NULL, detail);
}
static VOID
kswordArkCpuIntegrityEmitIdtRows(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ const KswCpuIntegritySample* sample,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG maxVectors
    )
/*++
Routine Description:
    Read copied IDT entries and emit handler owner evidence rows.
Arguments:
    Builder - Response builder.
    Sample - Captured descriptor state for one CPU.
    ModuleInfo - Optional module snapshot for owner attribution.
    MaxVectors - Maximum vectors to emit for this CPU.
Return Value:
    None. IDT rows are appended to Builder.
--*/
{
    ULONG vector = 0UL;
    ULONG vectorCount = 0UL;
    if (builder == NULL || sample == NULL || sample->captured == 0UL || sample->idtr.base == 0U) {
        return;
    }
    vectorCount = ((ULONG)sample->idtr.limit + 1UL) / KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES;
    if (vectorCount > 256UL) {
        vectorCount = 256UL;
    }
    if (maxVectors != 0UL && vectorCount > maxVectors) {
        vectorCount = maxVectors;
    }
    for (vector = 0UL; vector < vectorCount; ++vector) {
        KswCpuIntegrityIdtEntrY64 entry;
        KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
        ULONGLONG entryAddress = (ULONGLONG)sample->idtr.base + ((ULONGLONG)vector * KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES);
        ULONGLONG handler = 0ULL;
        ULONGLONG rawLow = 0ULL;
        ULONGLONG rawHigh = 0ULL;
        ULONGLONG baselineTableBase = 0ULL;
        ULONGLONG baselineHandler = 0ULL;
        ULONGLONG baselineRawLow = 0ULL;
        ULONGLONG baselineRawHigh = 0ULL;
        ULONG baselineTableLimit = 0UL;
        ULONG baselineGeneration = 0UL;
        BOOLEAN baselineAvailable = FALSE;
        ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
        ULONG descriptorFlags = 0UL;
        ULONG descriptorType = 0UL;
        ULONG descriptorDpl = 0UL;
        const KswHookSystemModuleEntry* owner = NULL;
        ULONG sectionResult = KSW_IMAGE_SECTION_RESULT_UNKNOWN;
        WCHAR sectionName[KSW_IMAGE_SECTION_NAME_CHARS] = { 0 };
        WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };
        RtlZeroMemory(&entry, sizeof(entry));
        if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)entryAddress, &entry, sizeof(entry))) {
            riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED;
            row = kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER, entryAddress, 0ULL, riskFlags,
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT, 35UL, sample->group, sample->number, vector, NULL, L"IDT entry read failed.");
            kswordArkCpuIntegrityPopulateDescriptorFields(
                row, 0UL, 0UL, 0UL, KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED,
                KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES, (ULONGLONG)sample->idtr.base,
                sample->idtr.limit, 0ULL, 0ULL, 0ULL, 0ULL);
            continue;
        }
        RtlCopyMemory(&rawLow, &entry, sizeof(rawLow));
        RtlCopyMemory(&rawHigh, (const UCHAR*)&entry + sizeof(rawLow), sizeof(rawHigh));
        handler = kswordArkCpuIntegrityIdtHandler(&entry);
        descriptorType = ((ULONG)entry.istAndType >> 8) & 0xFUL;
        descriptorDpl = ((ULONG)entry.istAndType >> 13) & 0x3UL;
        if ((entry.istAndType & 0x8000U) != 0U) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT;
        }
        if ((descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT) == 0UL ||
            entry.selector == 0U || handler == 0ULL ||
            (descriptorType != 0xEUL && descriptorType != 0xFUL) || entry.reserved != 0UL) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID;
        }
        owner = kswordArkDriverIntegrityFindModuleForAddress(moduleInfo, handler);
        if (owner == NULL) {
            riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED;
        }
        else {
            if (!kswordArkDriverIntegrityIsCoreKernelModule(owner)) {
                riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER;
            }
            // Being within an image range is not enough; the handler must reside in an executable section of that module.
            sectionResult = kswordArkImageClassifyAddress(
                owner, handler, sectionName, RTL_NUMBER_OF(sectionName), NULL);
            if (sectionResult == KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE ||
                sectionResult == KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS) {
                riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC;
            }
        }
        baselineAvailable = kswordArkIdtBaselineQuery(
            (USHORT)sample->group,
            (UCHAR)sample->number,
            (UCHAR)vector,
            &baselineTableBase,
            &baselineTableLimit,
            NULL,
            &baselineRawLow,
            &baselineRawHigh,
            &baselineHandler,
            &baselineGeneration);
        if (baselineAvailable &&
            (baselineRawLow != rawLow ||
             baselineRawHigh != rawHigh)) {
            riskFlags |=
                KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_BASELINE_CHANGED;
        }
        kswordArkCpuIntegrityFormatDetail(
            detail,
            RTL_NUMBER_OF(detail),
            L"IDT[%lu] gate=0x%llX handler=0x%llX selector=0x%04X attr=0x%04X; section=%ls(%lu); baseline=%ls handler=0x%llX generation=%lu.",
            vector,
            entryAddress,
            handler,
            entry.selector,
            entry.istAndType,
            (sectionName[0] != L'\0') ? sectionName : L"n/a",
            sectionResult,
            baselineAvailable ? L"available" : L"unavailable",
            baselineHandler,
            baselineGeneration);
        row = kswordArkDriverIntegrityAddEvidence(builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER, entryAddress, handler, riskFlags,
            KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT | KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE, 85UL, sample->group, sample->number, vector, owner, detail);
        kswordArkCpuIntegrityPopulateDescriptorFields(
            row, entry.selector, descriptorType, descriptorDpl, descriptorFlags,
            KSW_CPU_INTEGRITY_IDT_ENTRY_BYTES, (ULONGLONG)sample->idtr.base,
            sample->idtr.limit, handler, 0ULL, rawLow, rawHigh);
        if (row != NULL && baselineAvailable) {
            row->fieldMask |=
                KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DESCRIPTOR_BASELINE;
            row->baselineDescriptorFlags =
                KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE;
            if (baselineTableBase == (ULONGLONG)sample->idtr.base &&
                baselineTableLimit == sample->idtr.limit) {
                row->baselineDescriptorFlags |=
                    KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_SAME_TABLE;
            }
            if (baselineRawLow != rawLow ||
                baselineRawHigh != rawHigh) {
                row->baselineDescriptorFlags |=
                    KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_DIFFERS;
            }
            row->baselineGeneration = baselineGeneration;
            row->baselineDescriptorBase = baselineHandler;
            row->baselineDescriptorRawLow = baselineRawLow;
            row->baselineDescriptorRawHigh = baselineRawHigh;
        }
    }
}

static VOID
kswordArkCpuIntegrityEmitGdtRows(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_ const KswCpuIntegritySample* sample
    )
/*++
Routine Description:
    Decode a bounded copy of each GDT slot and emit structured v3 evidence.
Arguments:
    Builder - Response builder.
    Sample - Captured GDTR state for one CPU.
Return Value:
    None. Every row remains read-only diagnostic evidence.
--*/
{
    ULONG slot = 0UL;
    ULONG slotCount = 0UL;
    if (builder == NULL || sample == NULL || sample->captured == 0UL || sample->gdtr.base == 0U) {
        return;
    }
    slotCount = ((ULONG)sample->gdtr.limit + 1UL) / KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES;
    if (slotCount > KSW_CPU_INTEGRITY_MAX_GDT_ENTRIES) {
        builder->response->flags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED;
        slotCount = KSW_CPU_INTEGRITY_MAX_GDT_ENTRIES;
    }
    for (slot = 0UL; slot < slotCount; ++slot) {
        KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = NULL;
        const ULONGLONG kEntryAddress =
            (ULONGLONG)sample->gdtr.base + ((ULONGLONG)slot * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES);
        ULONGLONG rawLow = 0ULL;
        ULONGLONG rawHigh = 0ULL;
        ULONGLONG base = 0ULL;
        ULONGLONG limit = 0ULL;
        ULONG descriptorType = 0UL;
        ULONG descriptorDpl = 0UL;
        ULONG descriptorFlags = 0UL;
        ULONG descriptorSize = KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES;
        ULONG riskFlags = KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE;
        BOOLEAN userSegment = FALSE;
        BOOLEAN wideDescriptor = FALSE;
        WCHAR detail[KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS] = { 0 };

        if (!kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)kEntryAddress, &rawLow, sizeof(rawLow))) {
            row = kswordArkDriverIntegrityAddEvidence(
                builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR,
                kEntryAddress, 0ULL, KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED,
                KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT, 35UL, sample->group,
                sample->number, slot, NULL, L"GDT descriptor read failed.");
            kswordArkCpuIntegrityPopulateDescriptorFields(
                row, slot * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES, 0UL, 0UL,
                KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED, descriptorSize,
                (ULONGLONG)sample->gdtr.base, sample->gdtr.limit,
                0ULL, 0ULL, 0ULL, 0ULL);
            continue;
        }

        descriptorType = (ULONG)((rawLow >> 40) & 0xFULL);
        userSegment = ((rawLow >> 44) & 0x1ULL) != 0ULL ? TRUE : FALSE;
        descriptorDpl = (ULONG)((rawLow >> 45) & 0x3ULL);
        if (((rawLow >> 47) & 0x1ULL) != 0ULL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT;
        }
        if (((rawLow >> 55) & 0x1ULL) != 0ULL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_GRANULARITY_PAGE;
        }
        if (userSegment) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_USER_SEGMENT;
        }
        if (((rawLow >> 53) & 0x1ULL) != 0ULL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_LONG_MODE;
        }
        if (((rawLow >> 54) & 0x1ULL) != 0ULL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_DEFAULT_BIG;
        }
        if (!userSegment && descriptorType == 0x9UL) {
            descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_AVAILABLE;
        }

        base = ((rawLow >> 16) & 0xFFFFFFULL) | (((rawLow >> 56) & 0xFFULL) << 24);
        limit = (rawLow & 0xFFFFULL) | (((rawLow >> 48) & 0xFULL) << 16);
        wideDescriptor = kswordArkCpuIntegrityGdtDescriptorIsWide(descriptorType, userSegment);
        if (wideDescriptor) {
            descriptorSize = 2UL * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES;
            if (slot + 1UL >= slotCount ||
                !kswordArkHookReadMemorySafe((const VOID*)(ULONG_PTR)(kEntryAddress + KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES), &rawHigh, sizeof(rawHigh))) {
                riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED |
                    KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID;
                descriptorFlags |= KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED;
            }
            else {
                base |= (rawHigh & 0xFFFFFFFFULL) << 32;
                if ((rawHigh >> 32) != 0ULL) {
                    riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID;
                }
            }
        }
        if ((descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_GRANULARITY_PAGE) != 0UL) {
            limit = (limit << 12) | 0xFFFULL;
        }
        if ((descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT) != 0UL) {
            if (descriptorType == 0UL ||
                (userSegment &&
                 (descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_LONG_MODE) != 0UL &&
                 (descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_DEFAULT_BIG) != 0UL)) {
                riskFlags |= KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID;
            }
        }

        kswordArkCpuIntegrityFormatDetail(
            detail, RTL_NUMBER_OF(detail),
            L"GDT selector=0x%04lX entry=0x%llX base=0x%llX limit=0x%llX type=0x%lX DPL=%lu flags=0x%lX size=%lu.",
            slot * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES, kEntryAddress, base, limit,
            descriptorType, descriptorDpl, descriptorFlags, descriptorSize);
        row = kswordArkDriverIntegrityAddEvidence(
            builder, KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR,
            kEntryAddress, base, riskFlags, KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT,
            riskFlags == 0UL ? 90UL : 55UL, sample->group, sample->number,
            slot, NULL, detail);
        kswordArkCpuIntegrityPopulateDescriptorFields(
            row, slot * KSW_CPU_INTEGRITY_GDT_ENTRY_BYTES, descriptorType,
            descriptorDpl, descriptorFlags, descriptorSize,
            (ULONGLONG)sample->gdtr.base, sample->gdtr.limit,
            base, limit, rawLow, rawHigh);
        if (wideDescriptor && slot + 1UL < slotCount) {
            // IA-32e system descriptors consume two adjacent GDT slots. The
            // upper half is raw continuation data, not an independent entry.
            ++slot;
        }
    }
}
NTSTATUS
kswordArkCpuIntegrityCollect(
    _Inout_ KswDriverIntegrityBuilder* builder,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG flags,
    _In_ ULONG maxIdtVectorsPerCpu,
    _Out_ ULONG* cpuCountOut
    )
/*++
Routine Description:
    Sequentially switch to each active processor and collect read-only CPU entry evidence.
Arguments:
    Builder - Response builder.
    ModuleInfo - Optional module snapshot for owner attribution.
    Flags - Query flags controlling IDT expansion.
    MaxIdtVectorsPerCpu - Per-CPU IDT vector cap; zero selects protocol default.
    CpuCountOut - Receives number of active processors visited or attempted.
Return Value:
    STATUS_SUCCESS when at least the current architecture supports sampling.
--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    ULONG groupCount = 0UL;
    ULONG groupIndex = 0UL;
    ULONG totalCpus = 0UL;
    ULONG allActiveCount = 0UL;
    KswIdtConsistencyView* consistencyView = NULL;
    if (builder == NULL || cpuCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *cpuCountOut = 0UL;
    // Perform an initial read-only full-system IDTR sampling so that subsequent evidence rows for each CPU can reference the majority conclusion.
    // Collection failure does not affect other evidence; consistencyView should remain NULL.
    (VOID)kswordArkIdtConsistencyCollect(&consistencyView);
    if (maxIdtVectorsPerCpu == 0UL || maxIdtVectorsPerCpu > KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS) {
        maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS;
    }
    groupCount = KeQueryActiveGroupCount();
    allActiveCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (groupIndex = 0UL; groupIndex < groupCount; ++groupIndex) {
        ULONG activeInGroup = KeQueryActiveProcessorCountEx((USHORT)groupIndex);
        ULONG visitedInGroup = 0UL;
        ULONG globalIndex = 0UL;
        for (globalIndex = 0UL; globalIndex < allActiveCount && visitedInGroup < activeInGroup; ++globalIndex) {
            GROUP_AFFINITY targetAffinity;
            GROUP_AFFINITY previousAffinity;
            PROCESSOR_NUMBER processorNumber;
            KswCpuIntegritySample sample;
            KAFFINITY bit = 0U;
            RtlZeroMemory(&processorNumber, sizeof(processorNumber));
            if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(globalIndex, &processorNumber))) {
                break;
            }
            if (processorNumber.Group != (USHORT)groupIndex) {
                continue;
            }
            if (processorNumber.Number >= (sizeof(KAFFINITY) * 8UL)) {
                break;
            }
            bit = ((KAFFINITY)1) << processorNumber.Number;
            RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
            RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
            RtlZeroMemory(&sample, sizeof(sample));
            targetAffinity.Group = (USHORT)groupIndex;
            targetAffinity.Mask = bit;
            KeSetSystemGroupAffinityThread(&targetAffinity, &previousAffinity);
            sample.group = groupIndex;
            sample.number = processorNumber.Number;
            kswordArkCpuIntegrityCaptureCurrent(&sample);
            KeRevertToUserGroupAffinityThread(&previousAffinity);
            visitedInGroup += 1UL;
            totalCpus += 1UL;
            kswordArkCpuIntegrityEmitControlRows(builder, &sample, moduleInfo, consistencyView);
            if ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES) != 0UL) {
                kswordArkCpuIntegrityEmitIdtRows(builder, &sample, moduleInfo, maxIdtVectorsPerCpu);
            }
            if ((flags & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_GDT_ENTRIES) != 0UL) {
                kswordArkCpuIntegrityEmitGdtRows(builder, &sample);
            }
        }
    }
    *cpuCountOut = totalCpus;
    // The consistency view is valid only for this collection period; release its non-paged pool.
    kswordArkIdtConsistencyRelease(consistencyView);
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Builder);
    UNREFERENCED_PARAMETER(ModuleInfo);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(MaxIdtVectorsPerCpu);
    if (CpuCountOut != NULL) {
        *CpuCountOut = 0UL;
    }
    return STATUS_NOT_SUPPORTED;
#endif
}
