#pragma once

#include "ark/ark_driver.h"
#include "driver/KswordArkHvmIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkHvmInitialize(
    VOID
    );

NTSTATUS
kswordArkHvmEnableResidentLifecycle(
    _In_ PDRIVER_OBJECT driverObject
    );

VOID
kswordArkHvmUninitialize(
    VOID
    );

NTSTATUS
kswordArkHvmQuery(
    _Out_ KSWORD_ARK_QUERY_HVM_RESPONSE* response
    );

/*
 * Read-only platform probe: read a few registers that determine whether virtualization exit can return to user mode.
 * Does not enter VMX, does not modify any state, does not allocate, and does not lock. Each field has its own valid bit.
 */
NTSTATUS
kswordArkHvmPlatformProbe(
    _Out_ KSWORD_ARK_HVM_PLATFORM_RESPONSE* response
    );

NTSTATUS
kswordArkHvmControl(
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* request,
    _Out_ KSWORD_ARK_CONTROL_HVM_RESPONSE* response
    );

NTSTATUS
kswordArkHvmEptRuleControl(
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* response
    );

NTSTATUS
kswordArkHvmEventControl(
    _In_ const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* response
    );

EXTERN_C_END
