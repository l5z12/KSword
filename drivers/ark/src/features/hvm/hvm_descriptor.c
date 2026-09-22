/* Preserve descriptor-table registers across native and nested continuations. */
#include "hvm_descriptor.h"
#include "hvm_event.h"

/* Match the packed ten-byte operands consumed by the assembly helper. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, gdtr) == 0);
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, idtr) == 10);

BOOLEAN
kswordArkHvmCaptureGuestDescriptorTables(
    _Out_ KswHvmSegmentSnapshot* snapshot
    )
{
    /* Keep partial reads private until every VMREAD has succeeded. */
    SIZE_T gdtBase = 0U, gdtLimit = 0U, idtBase = 0U, idtLimit = 0U;

    /* Refuse a missing destination without changing the VMCS. */
    if (snapshot == NULL) {
        /* Report that no restorable state was captured. */
        return FALSE;
    }
    /* Capture guest state, not the host tables currently loaded by VM-exit. */
    if (kswordArkHvmVmcsFieldLoad(0x6816UL, &gdtBase) != 0U ||
        kswordArkHvmVmcsFieldLoad(0x4810UL, &gdtLimit) != 0U ||
        kswordArkHvmVmcsFieldLoad(0x6818UL, &idtBase) != 0U ||
        kswordArkHvmVmcsFieldLoad(0x4812UL, &idtLimit) != 0U ||
        gdtLimit > MAXUSHORT || idtLimit > MAXUSHORT) {
        /* Fail before VMXOFF rather than install an incomplete snapshot. */
        return FALSE;
    }
    /* Selector slots are unused by this table-only snapshot. */
    RtlZeroMemory(snapshot, sizeof(*snapshot));
    /* Publish the exact guest GDT base. */
    snapshot->gdtr.base = (ULONGLONG)gdtBase;
    /* Publish the validated sixteen-bit GDT limit. */
    snapshot->gdtr.limit = (USHORT)gdtLimit;
    /* Publish the exact guest IDT base. */
    snapshot->idtr.base = (ULONGLONG)idtBase;
    /* Publish the validated sixteen-bit IDT limit. */
    snapshot->idtr.limit = (USHORT)idtLimit;
    /* Report a complete snapshot that can survive VMCLEAR. */
    return TRUE;
}

#if defined(_M_AMD64)
/* Preserve the three observations in the existing lifecycle evidence format. */
static BOOLEAN
kswordArkHvmRecordDescriptorRestore(
    _In_ const KswHvmDescriptorTable* expected,
    _In_ const KswHvmDescriptorTable* before,
    _In_ const KswHvmDescriptorTable* after,
    _In_ ULONG tag,
    _In_ ULONG stage
    )
{
    /* Compare both architectural components, not just the base. */
    const BOOLEAN kMatched = expected->base == after->base &&
        expected->limit == after->limit;
    /* initialize the fixed-size lifecycle diagnostic row. */
    KSWORD_ARK_HVM_EVENT_ROW row = { 0 };
    /* Attribute each readback to the exact Windows processor identity. */
    PROCESSOR_NUMBER processor = { 0 };

    /* Distinguish these diagnostics from guest memory accesses. */
    row.type = KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE;
    /* The ring supplies timestamps but does not infer processor identity. */
    (void)KeGetCurrentProcessorNumberEx(&processor);
    /* Preserve the processor group instead of assuming group zero. */
    row.processorGroup = processor.Group;
    /* Preserve the processor number within that group. */
    row.processorNumber = processor.Number;
    /* Use the four-byte GDTR or IDTR tag. */
    row.ruleId = tag;
    /* Identify resident stop, one-shot return, or nested-probe return. */
    row.exitReason = stage;
    /* Retain the expected base in the diagnostic payload. */
    row.guestPhysicalAddress = expected->base;
    /* Retain the hardware base read after restoration. */
    row.guestLinearAddress = after->base;
    /* Retain the preceding base to expose private-host-IDT leakage. */
    row.guestRip = before->base;
    /* Pack expected and restored limits into separate sixteen-bit lanes. */
    row.qualification = (ULONGLONG)expected->limit |
        ((ULONGLONG)after->limit << 16);
    /* Retain the preceding limit, normally 0xFFFF after VM-exit. */
    row.access = (ULONG)before->limit;
    /* Publish failure unless the complete hardware readback matches. */
    row.status = kMatched ? STATUS_SUCCESS : STATUS_HV_OPERATION_FAILED;
    /* The allocation-free ring supplies the sequence and QPC timestamp. */
    kswordArkHvmEventPublish(&row);
    /* Refuse an incomplete restoration at the continuation boundary. */
    return kMatched;
}
#endif

BOOLEAN
kswordArkHvmRestoreDescriptorTables(
    _In_ const KswHvmSegmentSnapshot* snapshot,
    _In_ ULONG stage
    )
{
#if defined(_M_AMD64)
    /* Keep both observations on the current processor's stack. */
    KswHvmSegmentSnapshot before = { 0 }, after = { 0 };
    /* Verify both tables without short-circuiting the second evidence row. */
    BOOLEAN gdtMatched = FALSE, idtMatched = FALSE;

    /* Refuse a missing snapshot before privileged instructions run. */
    if (snapshot == NULL) {
        /* Report an unusable continuation. */
        return FALSE;
    }
    /* Observe the VM-exit host tables before replacing them. */
    KswordARKHvmCaptureSegments(&before);
    /* VMXOFF does not undo host table loads or their 0xFFFF limits. */
    KswordARKHvmAsmRestoreDescriptorTables(snapshot);
    /* Verify actual hardware state before the caller enables interrupts. */
    KswordARKHvmCaptureSegments(&after);
    /* Retain GDT verification independently of the IDT result. */
    gdtMatched = kswordArkHvmRecordDescriptorRestore(&snapshot->gdtr,
        &before.gdtr, &after.gdtr, 0x47445452UL, stage);
    /* Retain IDT verification independently of the GDT result. */
    idtMatched = kswordArkHvmRecordDescriptorRestore(&snapshot->idtr,
        &before.idtr, &after.idtr, 0x49445452UL, stage);
    /* Only a complete restoration permits the continuation. */
    return gdtMatched && idtMatched;
#else
    /* This VMX-specific continuation has no non-amd64 implementation. */
    UNREFERENCED_PARAMETER(Snapshot);
    /* Consume the diagnostic stage without claiming success. */
    UNREFERENCED_PARAMETER(Stage);
    /* Refuse unverifiable architectural state. */
    return FALSE;
#endif
}
