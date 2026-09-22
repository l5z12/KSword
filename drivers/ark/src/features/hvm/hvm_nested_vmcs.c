/*++

Module Name:

    hvm_nested_vmcs.c

Abstract:

    Implements bounded vmcs12 field storage and fail-closed vmcs02 validation.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_vmcs.h"
#include "hvm_vmcs.h"
#if defined(_M_AMD64)
#include <intrin.h>
#endif

/* Name Intel VM-entry invalid-control-fields error seven. */
#define KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS 7UL

/* Native VMCS layout is implementation-specific. Never decode its page bytes. */
NTSTATUS kswordArkHvmNestedVmcsImportCleared(
    ULONGLONG physicalAddress,
    KswHvmVmcS12State* destination,
    const ULONG* supportedFields,
    ULONG* discoveredFields,
    ULONG* fieldCount)
{
#if defined(_M_AMD64)
    unsigned __int64 original = ~0ULL;
    unsigned __int64 source = physicalAddress;
    SIZE_T value = 0;
    SIZE_T originalError = 0;
    ULONG slot;
    NTSTATUS status = STATUS_HV_OPERATION_FAILED;
    BOOLEAN loaded = FALSE;
    UCHAR cleared;
    UCHAR restored = 0;

    if (destination == NULL || fieldCount == NULL || physicalAddress == 0 ||
        (physicalAddress & 0xFFFULL) != 0 ||
        (supportedFields == NULL && discoveredFields == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *fieldCount = 0;
    __vmx_vmptrst(&original);
    if (original == source) {
        return STATUS_INVALID_PARAMETER;
    }
    /* The caller admits only inactive VMCSs. VMCLEAR also validates the PA. */
    if (__vmx_vmclear(&source) != 0) {
        return STATUS_HV_OPERATION_FAILED;
    }
    if (__vmx_vmptrld(&source) == 0) {
        loaded = TRUE;
        kswordArkHvmNestedVmcsInitialize(destination, NULL);
        destination->current = TRUE;
        destination->physicalAddress = physicalAddress;
        if (discoveredFields != NULL) {
            RtlZeroMemory(discoveredFields, 64 * sizeof(ULONG));
        }
        /* Unsupported-field discovery itself changes VM_INSTRUCTION_ERROR. */
        if (kswordArkHvmVmcsFieldLoad(0x4400, &originalError) == 0) {
            status = STATUS_SUCCESS;
            for (slot = 0; slot < KSW_HVM_VMCS12_SLOT_COUNT; ++slot) {
                const ULONG kEncoding = ((slot / 512) << 13) |
                    (((slot % 512) / 128) << 10) | ((slot % 128) << 1);
                if (supportedFields != NULL &&
                    (supportedFields[slot / 32] & (1UL << (slot % 32))) == 0) {
                    continue;
                }
                if (kEncoding == 0x4400) {
                    value = originalError;
                } else if (kswordArkHvmVmcsFieldLoad(kEncoding, &value) != 0) {
                    if (supportedFields != NULL) {
                        status = STATUS_HV_OPERATION_FAILED;
                        break;
                    }
                    continue;
                }
                destination->fields[slot] = (ULONGLONG)value;
                if (discoveredFields != NULL) {
                    discoveredFields[slot / 32] |= 1UL << (slot % 32);
                }
                ++*fieldCount;
            }
            destination->instructionError = (ULONG)originalError;
            destination->writeSerial = 1;
            /* No guessed launch state: admission requires a clear boundary. */
            destination->launched = FALSE;
        }
    }
    cleared = loaded ? __vmx_vmclear(&source) : 0;
    if (original != ~0ULL) {
        restored = __vmx_vmptrld(&original);
    }
    if (cleared != 0 || restored != 0) {
        /* A foreign/current or still-active VMCS cannot escape this helper. */
        KeBugCheckEx(0x20001, 0x4E564D43, physicalAddress, cleared, restored);
    }
    return status;
#else
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Destination);
    UNREFERENCED_PARAMETER(SupportedFields);
    UNREFERENCED_PARAMETER(DiscoveredFields);
    UNREFERENCED_PARAMETER(FieldCount);
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS kswordArkHvmNestedVmcsNativeSelfTest(
    KswHvmCpuResource* cpu,
    KswHvmVmcS12State* scratch)
{
#if defined(_M_AMD64)
    static const ULONG kFields[] = {0x0802, 0x4004, 0x2010, 0x681E};
    static const ULONGLONG kValues[] = {
        0x28ULL, 0xA5010080ULL, 0x1122334455667788ULL, 0xFFFF800012345678ULL};
    unsigned __int64 source = (ULONGLONG)cpu->vmcs02Physical.QuadPart;
    unsigned __int64 anchor = (ULONGLONG)cpu->vmcsPhysical.QuadPart;
    unsigned __int64 current = ~0ULL;
    ULONG count = 0, index;
    ULONGLONG readback = 0;
    NTSTATUS status = STATUS_HV_OPERATION_FAILED;
    cpu->nativeVmcsFieldCount = 0;
    RtlZeroMemory(cpu->nativeVmcsFields, sizeof(cpu->nativeVmcsFields));
    /*
     * Say which step failed, not merely that one did.
     *
     * Four of the exits below return the same status, so a failure reported
     * only as STATUS_HV_OPERATION_FAILED on four processors leaves no way to
     * tell "vmcs02 would not load" from "this processor answered a capability
     * question differently than the test assumed". The site is published in the
     * per-processor row, which already carries VMX instruction results, and is
     * cleared on success.
     */
    cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_LOAD_SOURCE;
    if (__vmx_vmclear(&source) != 0 || __vmx_vmptrld(&source) != 0) {
        goto Cleanup;
    }
    cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_STORE_FIELDS;
    for (index = 0; index < RTL_NUMBER_OF(kFields); ++index) {
        if (kswordArkHvmVmcsFieldStore(kFields[index], (SIZE_T)kValues[index]) != 0) {
            goto Cleanup;
        }
    }
    cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_SWITCH_ANCHOR;
    if (__vmx_vmclear(&source) != 0 || __vmx_vmclear(&anchor) != 0 ||
        __vmx_vmptrld(&anchor) != 0) {
        goto Cleanup;
    }
    /* Each condition gets its own site: they fail for unrelated reasons. */
    cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_IMPORT;
    status = kswordArkHvmNestedVmcsImportCleared(
        source, scratch, NULL, cpu->nativeVmcsFields, &count);
    __vmx_vmptrst(&current);
    if (!NT_SUCCESS(status)) { goto Cleanup; }
    status = STATUS_DATA_ERROR;
    if (current != anchor) {
        cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_IMPORT_ANCHOR;
        goto Cleanup;
    }
    if (count == 0) {
        cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_IMPORT_EMPTY;
        goto Cleanup;
    }
    if (scratch->launched) {
        cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_IMPORT_LAUNCHED;
        goto Cleanup;
    }
    /*
     * The error slot and the summary must agree.
     *
     * This used to compare against a value read from vmcs02 before the import
     * cleared it, which is not a property anything guarantees: VM-instruction
     * error is live state the processor rewrites, VMCLEAR resets it, and the
     * import deliberately reloads the VMCS. Comparing across that boundary
     * failed on all four processors and was testing the wrong thing.
     *
     * What the importer actually promises is internal: enumerating the fields
     * issues VMREADs that themselves set VM-instruction error, so it snapshots
     * the value on entry and substitutes that snapshot when it reaches the error
     * field rather than reading it again. If that substitution were dropped the
     * slot would hold whatever the last probe produced, so requiring the slot and
     * the summary to match is exactly the check that catches it.
     */
    if (!NT_SUCCESS(kswordArkHvmNestedVmcs12Read(scratch, 0x4400, &readback)) ||
        readback != (ULONGLONG)scratch->instructionError) {
        cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_IMPORT_ERRORFIELD;
        goto Cleanup;
    }
    cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_IMPORT_FIELDS;
    for (index = 0; index < RTL_NUMBER_OF(kFields); ++index) {
        if (!NT_SUCCESS(kswordArkHvmNestedVmcs12Read(scratch, kFields[index], &readback)) ||
            readback != kValues[index]) {
            goto Cleanup;
        }
    }
    cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_IMPORT_STEADY;
    /* The steady-state importer reads only fields this CPU actually supports. */
    status = kswordArkHvmNestedVmcsImportCleared(
        source, scratch, cpu->nativeVmcsFields, NULL, &count);
    __vmx_vmptrst(&current);
    if (NT_SUCCESS(status) && current == anchor) {
        cpu->nativeVmcsFieldCount = count;
    } else {
        status = STATUS_DATA_ERROR;
    }
Cleanup:
    if (__vmx_vmclear(&source) != 0 || __vmx_vmclear(&anchor) != 0) {
        cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_CLEANUP;
        status = STATUS_HV_OPERATION_FAILED;
    }
    if (!NT_SUCCESS(status)) {
        cpu->nativeVmcsFieldCount = 0;
    } else {
        /* Nothing to attribute once the whole sequence has passed. */
        cpu->row.vmxInstructionResult = KSW_HVM_NATIVE_SITE_NONE;
    }
    return status;
#else
    UNREFERENCED_PARAMETER(Cpu);
    UNREFERENCED_PARAMETER(Scratch);
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
kswordArkHvmNestedVmcsInitialize(
    _Out_ KswHvmVmcS12State* vmcs12,
    _Out_ KswHvmVmcS02State* vmcs02
    )
{
    /* initialize a supplied vmcs12 state. */
    if (vmcs12 != NULL) {
        /* Clear every bounded vmcs12 field and identity. */
        RtlZeroMemory(vmcs12, sizeof(*vmcs12));
    }
    /* initialize a supplied vmcs02 merge state. */
    if (vmcs02 != NULL) {
        /* Clear every merge and active-state marker. */
        RtlZeroMemory(vmcs02, sizeof(*vmcs02));
        /* Publish explicit partial implementation status. */
        vmcs02->lastStatus = STATUS_NOT_IMPLEMENTED;
    }
}

/*
 * Decompose one VMCS field encoding.
 *
 * Returns FALSE for an encoding this model does not address, which is what
 * makes the architectural "unsupported component" answer honest rather than a
 * stand-in for running out of room.
 */
static BOOLEAN
kswordArkHvmNestedVmcs12Decompose(
    _In_ ULONG encoding,
    _Out_ ULONG* slot,
    _Out_ ULONG* width,
    _Out_ BOOLEAN* highHalf
    )
{
    const ULONG kIndex = (encoding >> 1) & 0x1FFUL;
    const ULONG kType = (encoding >> 10) & 0x3UL;
    const ULONG kWidth = (encoding >> 13) & 0x3UL;
    const BOOLEAN kHigh = ((encoding & 0x1UL) != 0UL);

    *slot = 0UL;
    *width = 0UL;
    *highHalf = FALSE;
    /* Reject bits above the encoding Intel defines. */
    if ((encoding & ~0x00007FFFUL) != 0UL) {
        /* Report an encoding outside the model. */
        return FALSE;
    }
    /* Reject an index this bounded model does not address. */
    if (kIndex >= KSW_HVM_VMCS12_INDEX_COUNT) {
        /* Report an encoding outside the model. */
        return FALSE;
    }
    /*
     * The high half exists only for 64-bit fields.
     *
     * Width one is the 64-bit class; every other class is a single storage
     * unit, so an access-type bit set on one is a malformed encoding rather
     * than a request for its upper half.
     */
    if (kHigh && kWidth != 1UL) {
        /* Report an encoding outside the model. */
        return FALSE;
    }
    /* Width is part of the identity, not a hint - see the header. */
    *slot =
        (kWidth * KSW_HVM_VMCS12_TYPE_COUNT * KSW_HVM_VMCS12_INDEX_COUNT) +
        (kType * KSW_HVM_VMCS12_INDEX_COUNT) +
        kIndex;
    *width = kWidth;
    *highHalf = kHigh;
    /* Report a complete decomposition. */
    return TRUE;
}

/* Narrow one stored value to the width its encoding declares. */
static ULONGLONG
kswordArkHvmNestedVmcs12Narrow(
    _In_ ULONGLONG value,
    _In_ ULONG width
    )
{
    /* Select the sixteen-bit field class. */
    if (width == 0UL) {
        /* Return only the bits a sixteen-bit field holds. */
        return value & 0xFFFFULL;
    }
    /* Select the thirty-two-bit field class. */
    if (width == 2UL) {
        /* Return only the bits a thirty-two-bit field holds. */
        return value & 0xFFFFFFFFULL;
    }
    /* Return the full value for the 64-bit and natural-width classes. */
    return value;
}

NTSTATUS
kswordArkHvmNestedVmcs12Write(
    _Inout_ KswHvmVmcS12State* vmcs12,
    _In_ ULONG encoding,
    _In_ ULONGLONG value
    )
{
    ULONG slot = 0UL;
    ULONG width = 0UL;
    BOOLEAN high = FALSE;

    /* Require one current vmcs12 before touching its storage. */
    if (vmcs12 == NULL || !vmcs12->current) {
        /* Return the exact nested-state contract failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Reject an encoding this model does not address. */
    if (!kswordArkHvmNestedVmcs12Decompose(
            encoding,
            &slot,
            &width,
            &high)) {
        /* Return the exact unsupported-component failure. */
        return STATUS_NOT_FOUND;
    }
    if (high) {
        /* Replace only the upper half the access type names. */
        vmcs12->fields[slot] =
            (vmcs12->fields[slot] & 0xFFFFFFFFULL) |
            ((value & 0xFFFFFFFFULL) << 32);
    } else {
        vmcs12->fields[slot] =
            kswordArkHvmNestedVmcs12Narrow(value, width);
    }
    /* Mark the copy changed, so the backing store knows it has work to do. */
    vmcs12->writeSerial += 1UL;
    /* Complete the field write successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmNestedVmcs12Read(
    _In_ const KswHvmVmcS12State* vmcs12,
    _In_ ULONG encoding,
    _Out_ ULONGLONG* value
    )
{
    ULONG slot = 0UL;
    ULONG width = 0UL;
    BOOLEAN high = FALSE;

    /* Require one current vmcs12 and a fixed output. */
    if (vmcs12 == NULL || value == NULL || !vmcs12->current) {
        /* Return the exact nested-state contract failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    *value = 0ULL;
    /* Reject an encoding this model does not address. */
    if (!kswordArkHvmNestedVmcs12Decompose(
            encoding,
            &slot,
            &width,
            &high)) {
        /* Return the exact unsupported-component failure. */
        return STATUS_NOT_FOUND;
    }
    /*
     * A field never written reads as zero rather than failing.
     *
     * That is the architectural shape: whether a component is supported is a
     * property of its encoding, not of whether anyone has written it yet.
     * Failing on an unwritten field would make VMREAD-before-VMWRITE - which
     * L1 is entitled to do - look like an unsupported component.
     */
    *value = high
        ? ((vmcs12->fields[slot] >> 32) & 0xFFFFFFFFULL)
        : kswordArkHvmNestedVmcs12Narrow(vmcs12->fields[slot], width);
    /* Complete the field read successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmNestedVmcs02Prepare(
    _In_ const KswHvmVmcS12State* vmcs12,
    _In_ ULONGLONG composedEptPointer,
    _Out_ KswHvmVmcS02State* vmcs02
    )
{
    /* Validate fixed merge-state pointers. */
    if (vmcs12 == NULL ||
        vmcs02 == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Clear stale merge state before evaluating prerequisites. */
    RtlZeroMemory(vmcs02, sizeof(*vmcs02));
    /* Require one current vmcs12 before merge validation. */
    if (!vmcs12->current) {
        /* Publish the exact invalid nested state. */
        vmcs02->lastStatus =
            STATUS_INVALID_DEVICE_STATE;
        /* Publish Intel invalid-control-fields evidence. */
        vmcs02->instructionError =
            KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
        /* Return the exact invalid nested state. */
        return vmcs02->lastStatus;
    }
    /* Require a fully composed L1-on-L0 EPT pointer before L2 entry. */
    if (composedEptPointer == 0ULL) {
        /* Publish explicit partial shadow-EPT status. */
        vmcs02->lastStatus = STATUS_NOT_IMPLEMENTED;
        /* Publish Intel invalid-control-fields evidence. */
        vmcs02->instructionError =
            KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
        /* Return without claiming vmcs02 readiness. */
        return vmcs02->lastStatus;
    }
    /*
     * Control/guest merge and exit reflection remain deliberately incomplete.
     * Preserve the composed EPT identity but do not publish an active vmcs02.
     */
    vmcs02->eptPointer = composedEptPointer;
    /* Publish explicit partial merge status. */
    vmcs02->lastStatus = STATUS_NOT_IMPLEMENTED;
    /* Publish Intel invalid-control-fields evidence. */
    vmcs02->instructionError =
        KSW_HVM_VMX_ERROR_INVALID_CONTROL_FIELDS;
    /* Return without claiming L2 active state. */
    return vmcs02->lastStatus;
}
