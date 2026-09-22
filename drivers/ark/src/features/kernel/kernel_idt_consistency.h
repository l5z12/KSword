#pragma once

//
// kernel_idt_consistency.h
//
// Cross-CPU IDTR consistency view. Read-only collection of IDTRs from each logical processor to identify
// the 'majority' table, flagging processors that deviate from the majority or the boot-time baseline.
// Used to detect table switching (lidt takeover) on individual cores and full table relocation tampering.
//

#include "ark/ark_driver.h"

EXTERN_C_START

// This processor's IDTR differs from the majority of processors.
#define KSW_IDT_CONSISTENCY_RISK_DIVERGED 0x00000001UL
// This processor's IDTR is inconsistent with the baseline captured at driver startup.
#define KSW_IDT_CONSISTENCY_RISK_RELOCATED 0x00000002UL

// IDTR sample for a single processor.
typedef struct KswIdtConsistencyCpu
{
    ULONG group;
    ULONG number;
    ULONG captured;
    ULONG limit;
    ULONGLONG base;
    ULONGLONG baselineBase;
    ULONG baselineLimit;
    ULONG baselineAvailable;
} KswIdtConsistencyCpu, *PkswIdtConsistencyCpu;

// Result of a full-system collection. Cpus is a variable-length array with length CpuCount.
typedef struct KswIdtConsistencyView
{
    ULONG cpuCount;
    ULONG capturedCount;
    ULONG majorityCount;
    ULONG majorityLimit;
    ULONG divergedCount;
    ULONG relocatedCount;
    ULONGLONG majorityBase;
    KswIdtConsistencyCpu cpus[1];
} KswIdtConsistencyView, *PkswIdtConsistencyView;

NTSTATUS
kswordArkIdtConsistencyCollect(
    _Outptr_result_maybenull_ KswIdtConsistencyView** viewOut
    );

VOID
kswordArkIdtConsistencyRelease(
    _In_opt_ KswIdtConsistencyView* view
    );

ULONG
kswordArkIdtConsistencyClassify(
    _In_opt_ const KswIdtConsistencyView* view,
    _In_ ULONG processorGroup,
    _In_ ULONG processorNumber
    );

EXTERN_C_END
