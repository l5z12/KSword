/*++

Module Name:

    slat_iommu_audit.c

Abstract:

    Read-only Intel EPT / AMD NPT cross-view probes and IOMMU firmware/runtime
    evidence.  A clean result is not proof that an outer hypervisor has no
    execute-only SLAT hook: the outer EPT/NPT tables are intentionally opaque
    to the guest.  The response keeps this boundary explicit.

--*/

#include <ntifs.h>
#include <acpitabl.h>
#include <intrin.h>

#include "ark/ark_driver.h"

/* ntddk also defines the member name as a HALDISPATCH macro wrapper. */
#ifdef HalGetCachedAcpiTable
#undef HalGetCachedAcpiTable
#endif

C_ASSERT(sizeof(KSWORD_ARK_SLAT_PROBE_ROW) == 96U);
C_ASSERT(sizeof(KSWORD_ARK_IOMMU_ROW) == 80U);
C_ASSERT(sizeof(KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST) == 16U);
C_ASSERT(sizeof(KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE) == 6848U);

#define KSW_SLAT_PROBE_BYTES 32UL
#define KSW_SLAT_TIMING_SAMPLES 64UL
#define KSW_IA32_FEATURE_CONTROL 0x3AUL
#define KSW_IA32_VMX_PROCBASED_CTLS2 0x48BUL
#define KSW_IA32_VMX_EPT_VPID_CAP 0x48CUL
#define KSW_AMD_EFER 0xC0000080UL
#define KSW_AMD_VM_CR 0xC0010114UL
#define KSW_VTD_MMIO_BYTES 0x1000UL
#define KSW_AMD_IOMMU_MMIO_BYTES 0x3000UL

typedef NTSTATUS
(*KswIoGetIommuInterfaceFn)(
    _In_ ULONG version,
    _Out_ PDMA_IOMMU_INTERFACE interfaceOut
    );

typedef NTSTATUS
(*KswIoGetIommuInterfaceExFn)(
    _In_ ULONG version,
    _In_ ULONGLONG flags,
    _Out_ PDMA_IOMMU_INTERFACE_EX interfaceOut
    );

typedef struct KswSlatProbeTarget
{
    PCWSTR wideName;
    PCSTR ansiName;
} KswSlatProbeTarget;

static const KswSlatProbeTarget kGKswordSlatProbeTargets[] = {
    { L"KeBugCheckEx", "KeBugCheckEx" },
    { L"IoCreateDevice", "IoCreateDevice" },
    { L"PsLookupProcessByProcessId", "PsLookupProcessByProcessId" },
    { L"MmCopyMemory", "MmCopyMemory" },
    { L"MmMapIoSpace", "MmMapIoSpace" },
    { L"ObReferenceObjectByHandle", "ObReferenceObjectByHandle" },
    { L"ZwOpenFile", "ZwOpenFile" },
    { L"KeQueryPerformanceCounter", "KeQueryPerformanceCounter" }
};

static pHalGetAcpiTable
kswordArkSlatResolveAcpiGetter(
    VOID
    )
{
    UNICODE_STRING routineName;
    pHalGetAcpiTable routine = NULL;

    RtlInitUnicodeString(&routineName, L"HalGetCachedAcpiTable");
    routine = (pHalGetAcpiTable)MmGetSystemRoutineAddress(&routineName);
    if (routine != NULL) {
        return routine;
    }
    if (HALDISPATCH != NULL &&
        HALDISPATCH->Version >= HAL_DISPATCH_VERSION) {
        return HALDISPATCH->HalGetCachedAcpiTable;
    }
    return NULL;
}

static VOID
kswordArkSlatCopyAscii(
    _Out_writes_(destinationChars) CHAR* destination,
    _In_ ULONG destinationChars,
    _In_reads_bytes_(sourceBytes) const CHAR* source,
    _In_ ULONG sourceBytes
    )
{
    ULONG copyBytes = 0UL;

    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    RtlZeroMemory(destination, destinationChars);
    if (source == NULL || sourceBytes == 0UL) {
        return;
    }
    copyBytes = min(sourceBytes, destinationChars - 1UL);
    RtlCopyMemory(destination, source, copyBytes);
}

static ULONG
kswordArkSlatAsciiLength(
    _In_z_ const CHAR* text
    )
{
    ULONG length = 0UL;

    if (text == NULL) {
        return 0UL;
    }
    while (text[length] != '\0' && length < 1024UL) {
        ++length;
    }
    return length;
}

static ULONGLONG
kswordArkSlatHashBytes(
    _In_reads_bytes_(bytes) const UCHAR* buffer,
    _In_ ULONG bytes
    )
{
    ULONGLONG hash = 1469598103934665603ULL;
    ULONG index = 0UL;

    if (buffer == NULL) {
        return 0ULL;
    }
    for (index = 0UL; index < bytes; ++index) {
        hash ^= (ULONGLONG)buffer[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static BOOLEAN
kswordArkSlatBufferEqual(
    _In_reads_bytes_(bytes) const UCHAR* left,
    _In_reads_bytes_(bytes) const UCHAR* right,
    _In_ ULONG bytes
    )
{
    return RtlCompareMemory(left, right, bytes) == bytes ? TRUE : FALSE;
}

static NTSTATUS
kswordArkSlatReadVirtual(
    _In_ const VOID* address,
    _Out_writes_bytes_(bytes) UCHAR* buffer,
    _In_ ULONG bytes
    )
{
    if (address == NULL || buffer == NULL || bytes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        RtlCopyMemory(buffer, address, bytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkSlatReadPhysical(
    _In_ PHYSICAL_ADDRESS physicalAddress,
    _Out_writes_bytes_(bytes) UCHAR* buffer,
    _In_ ULONG bytes
    )
{
    MM_COPY_ADDRESS source;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (buffer == NULL || bytes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&source, sizeof(source));
    source.PhysicalAddress = physicalAddress;
    status = MmCopyMemory(
        buffer,
        source,
        bytes,
        MM_COPY_MEMORY_PHYSICAL,
        &copied);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return copied == bytes ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

static VOID
kswordArkSlatRunAliasProbes(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
    ULONG targetIndex = 0UL;

    if (response == NULL) {
        return;
    }
    response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_ALIAS_PROBES;
    for (targetIndex = 0UL;
         targetIndex < RTL_NUMBER_OF(kGKswordSlatProbeTargets) &&
         response->probeCount < KSWORD_ARK_SLAT_IOMMU_MAX_PROBES;
         ++targetIndex) {
        const KswSlatProbeTarget* target =
            &kGKswordSlatProbeTargets[targetIndex];
        KSWORD_ARK_SLAT_PROBE_ROW* row =
            &response->probes[response->probeCount++];
        UNICODE_STRING routineName;
        PVOID routineAddress = NULL;
        PHYSICAL_ADDRESS physicalAddress;
        UCHAR virtualFirst[KSW_SLAT_PROBE_BYTES] = { 0 };
        UCHAR virtualSecond[KSW_SLAT_PROBE_BYTES] = { 0 };
        UCHAR physicalFirst[KSW_SLAT_PROBE_BYTES] = { 0 };
        UCHAR physicalSecond[KSW_SLAT_PROBE_BYTES] = { 0 };
        ULONG bytes = KSW_SLAT_PROBE_BYTES;
        ULONG pageRemaining = 0UL;
        NTSTATUS virtualStatus = STATUS_SUCCESS;
        NTSTATUS physicalStatus = STATUS_SUCCESS;

        RtlZeroMemory(row, sizeof(*row));
        row->status = STATUS_NOT_FOUND;
        kswordArkSlatCopyAscii(
            row->name,
            RTL_NUMBER_OF(row->name),
            target->ansiName,
            kswordArkSlatAsciiLength(target->ansiName));
        RtlInitUnicodeString(&routineName, target->wideName);
        routineAddress = MmGetSystemRoutineAddress(&routineName);
        if (routineAddress == NULL) {
            continue;
        }
        row->virtualAddress = (ULONGLONG)(ULONG_PTR)routineAddress;
        pageRemaining = PAGE_SIZE -
            ((ULONG)(ULONG_PTR)routineAddress & (PAGE_SIZE - 1UL));
        if (bytes > pageRemaining) {
            bytes = pageRemaining;
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_PAGE_BOUNDARY;
        }
        if (bytes == 0UL) {
            row->status = STATUS_INVALID_ADDRESS;
            continue;
        }
        virtualStatus = kswordArkSlatReadVirtual(
            routineAddress,
            virtualFirst,
            bytes);
        if (!NT_SUCCESS(virtualStatus)) {
            row->status = virtualStatus;
            continue;
        }
        KeMemoryBarrier();
        virtualStatus = kswordArkSlatReadVirtual(
            routineAddress,
            virtualSecond,
            bytes);
        if (!NT_SUCCESS(virtualStatus)) {
            row->status = virtualStatus;
            continue;
        }
        row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_VIRTUAL_READ;
        if (!kswordArkSlatBufferEqual(virtualFirst, virtualSecond, bytes)) {
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_VIRTUAL_UNSTABLE;
            ++response->unstableCount;
            response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_UNSTABLE;
        }

        physicalAddress = MmGetPhysicalAddress(routineAddress);
        row->physicalAddress = (ULONGLONG)physicalAddress.QuadPart;
        physicalStatus = kswordArkSlatReadPhysical(
            physicalAddress,
            physicalFirst,
            bytes);
        if (!NT_SUCCESS(physicalStatus)) {
            row->status = physicalStatus;
            row->virtualHash = kswordArkSlatHashBytes(virtualFirst, bytes);
            row->bytesCompared = bytes;
            continue;
        }
        KeMemoryBarrier();
        physicalStatus = kswordArkSlatReadPhysical(
            physicalAddress,
            physicalSecond,
            bytes);
        if (!NT_SUCCESS(physicalStatus)) {
            row->status = physicalStatus;
            row->virtualHash = kswordArkSlatHashBytes(virtualFirst, bytes);
            row->bytesCompared = bytes;
            continue;
        }
        row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_PHYSICAL_READ;
        response->featureFlags |=
            KSWORD_ARK_SLAT_IOMMU_FEATURE_PHYSICAL_ALIAS;
        if (!kswordArkSlatBufferEqual(physicalFirst, physicalSecond, bytes)) {
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_PHYSICAL_UNSTABLE;
            ++response->unstableCount;
            response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_UNSTABLE;
        }
        row->virtualHash = kswordArkSlatHashBytes(virtualSecond, bytes);
        row->physicalHash = kswordArkSlatHashBytes(physicalSecond, bytes);
        row->bytesCompared = bytes;
        if (kswordArkSlatBufferEqual(virtualSecond, physicalSecond, bytes)) {
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MATCH;
        }
        else {
            row->flags |= KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MISMATCH;
            ++response->mismatchCount;
            response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_MISMATCH;
        }
        row->status = STATUS_SUCCESS;
    }
}

static VOID
kswordArkSlatSortTiming(
    _Inout_updates_(count) ULONGLONG* values,
    _In_ ULONG count
    )
{
    ULONG index = 0UL;

    for (index = 1UL; index < count; ++index) {
        ULONGLONG value = values[index];
        ULONG cursor = index;
        while (cursor > 0UL && values[cursor - 1UL] > value) {
            values[cursor] = values[cursor - 1UL];
            --cursor;
        }
        values[cursor] = value;
    }
}

static VOID
kswordArkSlatMeasureCpuid(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
#if defined(_M_AMD64) || defined(_M_IX86)
    ULONGLONG samples[KSW_SLAT_TIMING_SAMPLES] = { 0 };
    ULONG index = 0UL;
    int registers[4] = { 0 };

    if (response == NULL) {
        return;
    }
    for (index = 0UL; index < KSW_SLAT_TIMING_SAMPLES; ++index) {
        ULONGLONG before = __rdtsc();
        __cpuidex(registers, 0, 0);
        samples[index] = __rdtsc() - before;
    }
    kswordArkSlatSortTiming(samples, KSW_SLAT_TIMING_SAMPLES);
    response->cpuidCyclesMinimum = samples[0];
    response->cpuidCyclesMedian = samples[KSW_SLAT_TIMING_SAMPLES / 2UL];
    response->cpuidCyclesMaximum = samples[KSW_SLAT_TIMING_SAMPLES - 1UL];
    if (response->cpuidCyclesMedian != 0ULL &&
        response->cpuidCyclesMaximum >
            response->cpuidCyclesMedian * 8ULL) {
        response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_TIMING_VARIANCE;
    }
#else
    UNREFERENCED_PARAMETER(Response);
#endif
}

static VOID
kswordArkSlatQueryCpu(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
#if defined(_M_AMD64) || defined(_M_IX86)
    int registers[4] = { 0 };
    CHAR vendor[13] = { 0 };
    CHAR hypervisorVendor[13] = { 0 };
    ULONG leaf1Ecx = 0UL;

    if (response == NULL) {
        return;
    }
    response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_CPUID;
    __cpuidex(registers, 0, 0);
    response->cpuidMaxBasic = (ULONG)registers[0];
    RtlCopyMemory(vendor + 0, &registers[1], sizeof(ULONG));
    RtlCopyMemory(vendor + 4, &registers[3], sizeof(ULONG));
    RtlCopyMemory(vendor + 8, &registers[2], sizeof(ULONG));
    kswordArkSlatCopyAscii(
        response->cpuVendor,
        RTL_NUMBER_OF(response->cpuVendor),
        vendor,
        12UL);

    __cpuidex(registers, (int)0x80000000UL, 0);
    response->cpuidMaxExtended = (ULONG)registers[0];
    __cpuidex(registers, 1, 0);
    leaf1Ecx = (ULONG)registers[2];
    if ((leaf1Ecx & (1UL << 31)) != 0UL) {
        response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_HYPERVISOR;
        response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_HYPERVISOR_OPAQUE;
        __cpuidex(registers, (int)0x40000000UL, 0);
        response->cpuidMaxHypervisor = (ULONG)registers[0];
        RtlCopyMemory(hypervisorVendor + 0, &registers[1], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 4, &registers[2], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 8, &registers[3], sizeof(ULONG));
        kswordArkSlatCopyAscii(
            response->hypervisorVendor,
            RTL_NUMBER_OF(response->hypervisorVendor),
            hypervisorVendor,
            12UL);
        if (response->cpuidMaxHypervisor < 0x40000000UL ||
            hypervisorVendor[0] == '\0') {
            response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT;
        }
    }

    if (RtlCompareMemory(vendor, "GenuineIntel", 12UL) == 12UL) {
        ULONGLONG secondaryControls = 0ULL;
        response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_INTEL;
        if ((leaf1Ecx & (1UL << 5)) != 0UL) {
            response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_VMX;
            __try {
                response->vmxFeatureControl =
                    __readmsr(KSW_IA32_FEATURE_CONTROL);
                secondaryControls =
                    __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
                response->vmxEptVpidCapabilities =
                    __readmsr(KSW_IA32_VMX_EPT_VPID_CAP);
                response->fieldFlags |=
                    KSWORD_ARK_SLAT_IOMMU_FIELD_VIRTUALIZATION_MSR;
                if (((secondaryControls >> 32) & (1ULL << 1)) != 0ULL &&
                    (response->vmxEptVpidCapabilities & (1ULL << 6)) != 0ULL) {
                    response->featureFlags |=
                        KSWORD_ARK_SLAT_IOMMU_FEATURE_EPT;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                /* Nested or filtered VMX MSRs may be intentionally opaque. */
            }
        }
    }
    else if (RtlCompareMemory(vendor, "AuthenticAMD", 12UL) == 12UL) {
        response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_AMD;
        if (response->cpuidMaxExtended >= 0x80000001UL) {
            __cpuidex(registers, (int)0x80000001UL, 0);
            if (((ULONG)registers[2] & (1UL << 2)) != 0UL) {
                response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_SVM;
            }
        }
        if (response->cpuidMaxExtended >= 0x8000000AUL) {
            __cpuidex(registers, (int)0x8000000AUL, 0);
            if (((ULONG)registers[3] & 0x1UL) != 0UL) {
                response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_NPT;
            }
        }
        else if ((response->featureFlags &
            KSWORD_ARK_SLAT_IOMMU_FEATURE_SVM) != 0ULL) {
            response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT;
        }
        __try {
            response->amdEfer = __readmsr(KSW_AMD_EFER);
            response->amdVmCr = __readmsr(KSW_AMD_VM_CR);
            response->fieldFlags |=
                KSWORD_ARK_SLAT_IOMMU_FIELD_VIRTUALIZATION_MSR;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* A parent VMM may filter SVM MSRs while preserving CPUID data. */
        }
    }
    else {
        response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT;
    }
    kswordArkSlatMeasureCpuid(response);
#else
    UNREFERENCED_PARAMETER(Response);
#endif
}

static BOOLEAN
kswordArkSlatAcpiChecksumValid(
    _In_ const DESCRIPTION_HEADER* header,
    _In_ ULONG minimumLength
    )
{
    ULONG index = 0UL;
    UCHAR checksum = 0U;

    if (header == NULL) {
        return FALSE;
    }
    __try {
        if (header->Length < minimumLength || header->Length > (1024UL * 1024UL)) {
            return FALSE;
        }
        for (index = 0UL; index < header->Length; ++index) {
            checksum = (UCHAR)(checksum + ((const UCHAR*)header)[index]);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return checksum == 0U ? TRUE : FALSE;
}

static KSWORD_ARK_IOMMU_ROW*
kswordArkSlatAppendIommuRow(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
    KSWORD_ARK_IOMMU_ROW* row = NULL;

    if (response == NULL) {
        return NULL;
    }
    if (response->iommuRowCount >= KSWORD_ARK_SLAT_IOMMU_MAX_ROWS) {
        response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_TRUNCATED;
        return NULL;
    }
    row = &response->iommuRows[response->iommuRowCount++];
    RtlZeroMemory(row, sizeof(*row));
    row->status = STATUS_SUCCESS;
    return row;
}

static ULONG
kswordArkSlatCountDeviceScopes(
    _In_reads_bytes_(bytes) const UCHAR* buffer,
    _In_ ULONG bytes,
    _Out_ BOOLEAN* malformedOut,
    _Out_opt_ ULONG* firstDeviceIdOut
    )
{
    ULONG count = 0UL;
    ULONG offset = 0UL;

    if (malformedOut == NULL) {
        return 0UL;
    }
    *malformedOut = FALSE;
    if (firstDeviceIdOut != NULL) {
        *firstDeviceIdOut = 0UL;
    }
    while (offset < bytes) {
        const DEVICESCOPE* scope = NULL;
        if (bytes - offset < DEVICE_SCOPE_MIN_SIZE) {
            *malformedOut = TRUE;
            break;
        }
        scope = (const DEVICESCOPE*)(buffer + offset);
        if (scope->Length < DEVICE_SCOPE_MIN_SIZE || scope->Length > bytes - offset) {
            *malformedOut = TRUE;
            break;
        }
        if (((scope->Length - FIELD_OFFSET(DEVICESCOPE, PCIPath)) %
             sizeof(scope->PCIPath[0])) != 0U) {
            *malformedOut = TRUE;
            break;
        }
        if (count == 0UL && firstDeviceIdOut != NULL) {
            *firstDeviceIdOut =
                ((ULONG)scope->StartBusNumber << 8) |
                ((ULONG)scope->PCIPath[0].Device << 3) |
                (ULONG)scope->PCIPath[0].Function;
        }
        ++count;
        offset += scope->Length;
    }
    return count;
}

static NTSTATUS
kswordArkSlatReadVtdMmio(
    _In_ ULONGLONG baseAddress,
    _Inout_ KSWORD_ARK_IOMMU_ROW* row,
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
    PHYSICAL_ADDRESS physicalAddress;
    PVOID mapping = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (row == NULL || response == NULL || baseAddress == 0ULL ||
        (baseAddress & (PAGE_SIZE - 1ULL)) != 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    physicalAddress.QuadPart = (LONGLONG)baseAddress;
    mapping = MmMapIoSpaceEx(
        physicalAddress,
        KSW_VTD_MMIO_BYTES,
        PAGE_READONLY | PAGE_NOCACHE);
    if (mapping == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __try {
        row->capability = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x08));
        row->extendedCapability = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x10));
        row->statusRegister = (ULONGLONG)READ_REGISTER_ULONG(
            (volatile ULONG*)((PUCHAR)mapping + 0x1C));
        row->rootTableAddress = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x20));
        row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_MMIO_READ;
        response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_MMIO;
        if ((row->statusRegister & (1ULL << 31)) != 0ULL) {
            row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION;
            response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_TRANSLATION;
        }
        else {
            response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_TRANSLATION_DISABLED;
        }
        if ((row->statusRegister & (1ULL << 25)) != 0ULL) {
            row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_INTERRUPT_REMAP;
            response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_INTERRUPT_REMAP;
        }
        if ((row->statusRegister & (1ULL << 30)) != 0ULL &&
            (row->rootTableAddress & 0x000FFFFFFFFFF000ULL) != 0ULL) {
            row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_ROOT_TABLE_VALID;
        }
        else if ((row->flags & KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION) != 0UL) {
            response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_ROOT_TABLE_UNAVAILABLE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    MmUnmapIoSpace(mapping, KSW_VTD_MMIO_BYTES);
    return status;
}

static NTSTATUS
kswordArkSlatReadAmdIommuMmio(
    _In_ ULONGLONG baseAddress,
    _Inout_ KSWORD_ARK_IOMMU_ROW* row,
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
    PHYSICAL_ADDRESS physicalAddress;
    PVOID mapping = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (row == NULL || response == NULL || baseAddress == 0ULL ||
        (baseAddress & (PAGE_SIZE - 1ULL)) != 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    physicalAddress.QuadPart = (LONGLONG)baseAddress;
    mapping = MmMapIoSpaceEx(
        physicalAddress,
        KSW_AMD_IOMMU_MMIO_BYTES,
        PAGE_READONLY | PAGE_NOCACHE);
    if (mapping == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    __try {
        row->rootTableAddress = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x00));
        row->capability = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x18));
        row->extendedCapability = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x30));
        row->statusRegister = READ_REGISTER_ULONG64(
            (volatile ULONG64*)((PUCHAR)mapping + 0x2020));
        row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_MMIO_READ;
        response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_MMIO;
        if ((row->capability & 0x1ULL) != 0ULL) {
            row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION;
        }
        else {
            response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_TRANSLATION_DISABLED;
        }
        if ((row->rootTableAddress & 0x000FFFFFFFFFF000ULL) != 0ULL) {
            row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_ROOT_TABLE_VALID;
        }
        else if ((row->flags & KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION) != 0UL) {
            response->riskFlags |=
                KSWORD_ARK_SLAT_IOMMU_RISK_ROOT_TABLE_UNAVAILABLE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    MmUnmapIoSpace(mapping, KSW_AMD_IOMMU_MMIO_BYTES);
    return status;
}

static NTSTATUS
kswordArkSlatParseDmar(
    _In_ BOOLEAN includeMmio,
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
    const DMAR* dmar = NULL;
    const UCHAR* cursor = NULL;
    const UCHAR* end = NULL;
    pHalGetAcpiTable getAcpiTable = NULL;

    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    getAcpiTable = kswordArkSlatResolveAcpiGetter();
    if (getAcpiTable == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    dmar = (const DMAR*)getAcpiTable(
        DMAR_SIGNATURE,
        NULL,
        NULL);
    if (dmar == NULL) {
        return STATUS_NOT_FOUND;
    }
    response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_DMAR;
    response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_DMAR;
    if (!kswordArkSlatAcpiChecksumValid(
            &dmar->Header,
            FIELD_OFFSET(DMAR, DMARTables))) {
        response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_CHECKSUM;
    }
    __try {
        response->dmarFlags = dmar->Flags;
        response->dmarHostAddressWidth = dmar->HostAddressWidth;
        if ((dmar->Flags & DMAR_FLAG_DMA_CTRL_PLATFORM_OPT_IN) != 0U) {
            response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_DMA_GUARD_OPT_IN;
        }
        cursor = (const UCHAR*)dmar + FIELD_OFFSET(DMAR, DMARTables);
        end = (const UCHAR*)dmar + dmar->Header.Length;
        while (cursor < end) {
            const DMARTABLE* table = NULL;
            KSWORD_ARK_IOMMU_ROW* row = NULL;
            BOOLEAN malformed = FALSE;
            ULONG fixedBytes = sizeof(USHORT) * 2UL;

            if ((ULONG_PTR)(end - cursor) < sizeof(USHORT) * 2UL) {
                response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
                ++response->malformedRowCount;
                break;
            }
            table = (const DMARTABLE*)cursor;
            if (table->Length < sizeof(USHORT) * 2UL ||
                table->Length > (ULONG_PTR)(end - cursor)) {
                response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
                ++response->malformedRowCount;
                break;
            }
            row = kswordArkSlatAppendIommuRow(response);
            if (row == NULL) {
                break;
            }
            switch (table->Type) {
            case DMAR_DRHD:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_DRHD;
                fixedBytes = DMAR_DRHD_MIN_SIZE;
                if (table->Length >= fixedBytes) {
                    row->firmwareFlags = table->Drhd.Flags;
                    row->flags = (table->Drhd.Flags & DRHD_INCLUDE_ALL) != 0U
                        ? KSWORD_ARK_IOMMU_ROW_FLAG_INCLUDE_ALL
                        : 0UL;
                    row->segment = table->Drhd.SegmentNumber;
                    row->baseAddress = table->Drhd.BaseAddress;
                    row->scopeCount = kswordArkSlatCountDeviceScopes(
                        cursor + fixedBytes,
                        table->Length - fixedBytes,
                        &malformed,
                        &row->deviceId);
                    if (includeMmio != FALSE) {
                        row->status = kswordArkSlatReadVtdMmio(
                            row->baseAddress,
                            row,
                            response);
                        if (!NT_SUCCESS(row->status)) {
                            response->riskFlags |=
                                KSWORD_ARK_SLAT_IOMMU_RISK_MMIO_UNREADABLE;
                        }
                    }
                }
                else {
                    malformed = TRUE;
                }
                break;
            case DMAR_RMRR:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_RMRR;
                fixedBytes = 24UL;
                if (table->Length >= fixedBytes) {
                    row->flags |=
                        KSWORD_ARK_IOMMU_ROW_FLAG_RESERVED_MEMORY;
                    row->segment = table->Rmrr.SegmentNumber;
                    row->baseAddress = table->Rmrr.RegionBaseAddress;
                    row->limitAddress = table->Rmrr.RegionLimitAddress;
                    row->scopeCount = kswordArkSlatCountDeviceScopes(
                        cursor + fixedBytes,
                        table->Length - fixedBytes,
                        &malformed,
                        &row->deviceId);
                    ++response->reservedMemoryCount;
                    response->riskFlags |=
                        KSWORD_ARK_SLAT_IOMMU_RISK_RESERVED_MEMORY_PRESENT;
                }
                else {
                    malformed = TRUE;
                }
                break;
            case DMAR_ATSR:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_ATSR;
                fixedBytes = 8UL;
                if (table->Length >= fixedBytes) {
                    row->segment = table->Atsr.SegmentNumber;
                    row->firmwareFlags = table->Atsr.Flags;
                    row->scopeCount = kswordArkSlatCountDeviceScopes(
                        cursor + fixedBytes,
                        table->Length - fixedBytes,
                        &malformed,
                        &row->deviceId);
                }
                else {
                    malformed = TRUE;
                }
                break;
            case DMAR_RHSA:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_RHSA;
                if (table->Length >= sizeof(RHSA)) {
                    const RHSA* rhsa = (const RHSA*)cursor;
                    row->baseAddress = rhsa->RegisterBaseAddress;
                    row->segment = rhsa->ProximityDomain;
                }
                else {
                    malformed = TRUE;
                }
                break;
            case DMAR_ANDD:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_ANDD;
                break;
            case DMAR_SATC:
                row->type = KSWORD_ARK_IOMMU_ROW_INTEL_SATC;
                fixedBytes = 8UL;
                if (table->Length >= fixedBytes) {
                    row->firmwareFlags = table->Satc.Flags;
                    row->segment = table->Satc.SegmentNumber;
                    row->scopeCount = kswordArkSlatCountDeviceScopes(
                        cursor + fixedBytes,
                        table->Length - fixedBytes,
                        &malformed,
                        &row->deviceId);
                }
                else {
                    malformed = TRUE;
                }
                break;
            default:
                row->type = KSWORD_ARK_IOMMU_ROW_UNKNOWN;
                break;
            }
            if (malformed != FALSE) {
                row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_MALFORMED;
                row->status = STATUS_DATA_ERROR;
                ++response->malformedRowCount;
                response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
            }
            cursor += table->Length;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkSlatParseIvrs(
    _In_ BOOLEAN includeMmio,
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
    const IVRS* ivrs = NULL;
    const UCHAR* cursor = NULL;
    const UCHAR* end = NULL;
    pHalGetAcpiTable getAcpiTable = NULL;

    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    getAcpiTable = kswordArkSlatResolveAcpiGetter();
    if (getAcpiTable == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    ivrs = (const IVRS*)getAcpiTable(
        IVRS_SIGNATURE,
        NULL,
        NULL);
    if (ivrs == NULL) {
        return STATUS_NOT_FOUND;
    }
    response->fieldFlags |= KSWORD_ARK_SLAT_IOMMU_FIELD_IVRS;
    response->featureFlags |= KSWORD_ARK_SLAT_IOMMU_FEATURE_IVRS;
    if (!kswordArkSlatAcpiChecksumValid(
            &ivrs->Header,
            FIELD_OFFSET(IVRS, DefinitionBlocks))) {
        response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_CHECKSUM;
    }
    __try {
        response->ivrsInfo = ivrs->IVInfo.AsUINT32;
        if (ivrs->IVInfo.DmaGuardOptIn != 0U) {
            response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_DMA_GUARD_OPT_IN;
        }
        cursor = (const UCHAR*)ivrs + FIELD_OFFSET(IVRS, DefinitionBlocks);
        end = (const UCHAR*)ivrs + ivrs->Header.Length;
        while (cursor < end) {
            const IVRS_BLOCK_HEADER* header = NULL;
            KSWORD_ARK_IOMMU_ROW* row = NULL;
            BOOLEAN malformed = FALSE;

            if ((ULONG_PTR)(end - cursor) < sizeof(IVRS_BLOCK_HEADER)) {
                ++response->malformedRowCount;
                response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
                break;
            }
            header = (const IVRS_BLOCK_HEADER*)cursor;
            if (header->Length < sizeof(IVRS_BLOCK_HEADER) ||
                header->Length > (ULONG_PTR)(end - cursor)) {
                ++response->malformedRowCount;
                response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
                break;
            }
            row = kswordArkSlatAppendIommuRow(response);
            if (row == NULL) {
                break;
            }
            row->firmwareFlags = header->Flags;
            switch (header->Type) {
            case IommuDefinitionBlockTypeIvhd:
            case IommuDefinitionBlockType11Ivhd:
            case IommuDefinitionBlockType40Ivhd:
                row->type = KSWORD_ARK_IOMMU_ROW_AMD_IVHD;
                if (header->Length >= 24UL) {
                    const IVHD_BLOCK* ivhd = (const IVHD_BLOCK*)cursor;
                    row->deviceId = ivhd->DeviceId;
                    row->segment = ivhd->PciSegment;
                    row->baseAddress = ivhd->IommuBaseAddress;
                    if (includeMmio != FALSE) {
                        row->status = kswordArkSlatReadAmdIommuMmio(
                            row->baseAddress,
                            row,
                            response);
                        if (!NT_SUCCESS(row->status)) {
                            response->riskFlags |=
                                KSWORD_ARK_SLAT_IOMMU_RISK_MMIO_UNREADABLE;
                        }
                    }
                }
                else {
                    malformed = TRUE;
                }
                break;
            case IommuDefinitionBlockTypeIvmdAll:
            case IommuDefinitionBlockTypeIvmdSpecified:
            case IommuDefinitionBlockTypeIvmdRange:
                row->type = KSWORD_ARK_IOMMU_ROW_AMD_IVMD;
                if (header->Length >= sizeof(IVMD_BLOCK)) {
                    const IVMD_BLOCK* ivmd = (const IVMD_BLOCK*)cursor;
                    row->flags |=
                        KSWORD_ARK_IOMMU_ROW_FLAG_RESERVED_MEMORY;
                    row->deviceId = ivmd->u1.DeviceId;
                    row->endDeviceId = ivmd->u2.EndDeviceId;
                    row->baseAddress = ivmd->StartAddress;
                    row->limitAddress = ivmd->MemoryBlockLength == 0ULL
                        ? ivmd->StartAddress
                        : ivmd->StartAddress + ivmd->MemoryBlockLength - 1ULL;
                    ++response->reservedMemoryCount;
                    response->riskFlags |=
                        KSWORD_ARK_SLAT_IOMMU_RISK_RESERVED_MEMORY_PRESENT;
                }
                else {
                    malformed = TRUE;
                }
                break;
            default:
                row->type = KSWORD_ARK_IOMMU_ROW_UNKNOWN;
                break;
            }
            if (malformed != FALSE) {
                row->flags |= KSWORD_ARK_IOMMU_ROW_FLAG_MALFORMED;
                row->status = STATUS_DATA_ERROR;
                ++response->malformedRowCount;
                response->riskFlags |=
                    KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
            }
            cursor += header->Length;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->riskFlags |= KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED;
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

static VOID
kswordArkSlatQueryIommuInterfaces(
    _Inout_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
    UNICODE_STRING routineName;
    KswIoGetIommuInterfaceFn getInterface = NULL;
    KswIoGetIommuInterfaceExFn getInterfaceEx = NULL;
    DMA_IOMMU_INTERFACE interfaceValue;
    DMA_IOMMU_INTERFACE_EX interfaceExValue;
    ULONG version = 0UL;

    if (response == NULL) {
        return;
    }
    response->iommuInterfaceStatus = STATUS_PROCEDURE_NOT_FOUND;
    response->iommuInterfaceExStatus = STATUS_PROCEDURE_NOT_FOUND;
    RtlInitUnicodeString(&routineName, L"IoGetIommuInterface");
    getInterface = (KswIoGetIommuInterfaceFn)
        MmGetSystemRoutineAddress(&routineName);
    if (getInterface != NULL) {
        response->featureFlags |=
            KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EXPORT;
        response->fieldFlags |=
            KSWORD_ARK_SLAT_IOMMU_FIELD_IOMMU_INTERFACE;
        RtlZeroMemory(&interfaceValue, sizeof(interfaceValue));
        response->iommuInterfaceStatus = getInterface(
            DMA_IOMMU_INTERFACE_VERSION,
            &interfaceValue);
        if (NT_SUCCESS(response->iommuInterfaceStatus)) {
            response->iommuInterfaceVersion = interfaceValue.Version;
            response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE;
        }
    }

    RtlInitUnicodeString(&routineName, L"IoGetIommuInterfaceEx");
    getInterfaceEx = (KswIoGetIommuInterfaceExFn)
        MmGetSystemRoutineAddress(&routineName);
    if (getInterfaceEx == NULL) {
        return;
    }
    response->featureFlags |=
        KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EX_EXPORT;
    response->fieldFlags |=
        KSWORD_ARK_SLAT_IOMMU_FIELD_IOMMU_INTERFACE;
    for (version = DMA_IOMMU_INTERFACE_EX_VERSION_MAX;
         version >= DMA_IOMMU_INTERFACE_EX_VERSION_MIN;
         --version) {
        RtlZeroMemory(&interfaceExValue, sizeof(interfaceExValue));
        response->iommuInterfaceExStatus = getInterfaceEx(
            version,
            0ULL,
            &interfaceExValue);
        if (NT_SUCCESS(response->iommuInterfaceExStatus)) {
            response->iommuInterfaceExVersion = interfaceExValue.Version;
            response->featureFlags |=
                KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE_EX;
            break;
        }
        if (version == DMA_IOMMU_INTERFACE_EX_VERSION_MIN) {
            break;
        }
    }
}

NTSTATUS
kswordArkSlatIommuAuditQuery(
    _In_ const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_REQUEST* request,
    _Out_ KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE* response
    )
{
    BOOLEAN includeMmio = FALSE;

    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_SLAT_IOMMU_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = STATUS_SUCCESS;
    response->dmarStatus = STATUS_NOT_FOUND;
    response->ivrsStatus = STATUS_NOT_FOUND;
    response->iommuInterfaceStatus = STATUS_PROCEDURE_NOT_FOUND;
    response->iommuInterfaceExStatus = STATUS_PROCEDURE_NOT_FOUND;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->queryStatus = STATUS_INVALID_DEVICE_STATE;
        return response->queryStatus;
    }
    if (request->size != sizeof(*request) ||
        request->version != KSWORD_ARK_SLAT_IOMMU_AUDIT_PROTOCOL_VERSION ||
        (request->flags & ~KSWORD_ARK_SLAT_IOMMU_QUERY_FLAG_INCLUDE_MMIO) != 0UL) {
        response->queryStatus = STATUS_INVALID_PARAMETER;
        return response->queryStatus;
    }
    includeMmio = (request->flags &
        KSWORD_ARK_SLAT_IOMMU_QUERY_FLAG_INCLUDE_MMIO) != 0UL;
    response->queryFlags = request->flags;

    kswordArkSlatQueryCpu(response);
    kswordArkSlatQueryIommuInterfaces(response);
    response->dmarStatus = kswordArkSlatParseDmar(includeMmio, response);
    response->ivrsStatus = kswordArkSlatParseIvrs(includeMmio, response);
    kswordArkSlatRunAliasProbes(response);
    return STATUS_SUCCESS;
}
