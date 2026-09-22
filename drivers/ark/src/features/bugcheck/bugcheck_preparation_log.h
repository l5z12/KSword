#pragma once

#include <ntddk.h>

// Write the completed PASSIVE_LEVEL BGP preparation state to a fixed text
// report under the Windows temporary directory. No bugcheck callback calls it.
NTSTATUS
kswordArkBugcheckWritePreparationLog(
    _In_ NTSTATUS bgpInitializeStatus,
    _In_ NTSTATUS panelInitializeStatus,
    _In_ NTSTATUS callbackRegistrationStatus
    );
