#pragma once

#include "hvm_vmcs.h"

/* Identify the continuation whose descriptor tables are being restored. */
#define KSW_HVM_DESCRIPTOR_RESIDENT 1UL
#define KSW_HVM_DESCRIPTOR_ONESHOT 2UL
#define KSW_HVM_DESCRIPTOR_PROBE 3UL

EXTERN_C_START

/* Capture the current guest's tables before VMCLEAR destroys their source. */
BOOLEAN kswordArkHvmCaptureGuestDescriptorTables(
    _Out_ KswHvmSegmentSnapshot* snapshot);

/* Restore bases and limits, then verify SGDT/SIDT and publish both readbacks. */
BOOLEAN kswordArkHvmRestoreDescriptorTables(
    _In_ const KswHvmSegmentSnapshot* snapshot,
    _In_ ULONG stage);

/* Load GDTR and IDTR without modifying selectors or descriptor memory. */
VOID KswordARKHvmAsmRestoreDescriptorTables(
    _In_ const KswHvmSegmentSnapshot* snapshot);

EXTERN_C_END
