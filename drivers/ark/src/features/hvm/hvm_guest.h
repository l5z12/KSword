#pragma once

#include "ark/ark_driver.h"
#include "hvm_vmcs.h"

struct KswHvmRuntime;

typedef struct KswHvmGuestLaunchInput
{
    USHORT processorGroup;
    UCHAR processorNumber;
    UCHAR nestedLaunch;
    PHYSICAL_ADDRESS vmxonPhysical;
    PHYSICAL_ADDRESS vmcsPhysical;
    ULONGLONG vmxBasic;
    ULONGLONG cr0Fixed0;
    ULONGLONG cr0Fixed1;
    ULONGLONG cr4Fixed0;
    ULONGLONG cr4Fixed1;
    ULONGLONG eptPointer;
    struct KswHvmRuntime* runtime;
    LONG expectedPowerTransitionGeneration;
} KswHvmGuestLaunchInput;

typedef struct KswHvmGuestLaunchResult
{
    NTSTATUS status;
    UCHAR vmxInstructionResult;
    UCHAR vmcsLoaded;
    UCHAR guestLaunched;
    UCHAR vmExitHandled;
    ULONG vmInstructionError;
    KswHvmVmexitTelemetry exit;
} KswHvmGuestLaunchResult;

EXTERN_C_START

NTSTATUS
kswordArkHvmLaunchControlledGuest(
    _In_ const KswHvmGuestLaunchInput* input,
    _Out_ KswHvmGuestLaunchResult* result
    );

PVOID
KswordARKHvmVmExitDispatch(
    VOID
    );

UCHAR
KswordARKHvmAsmLaunch(
    _Inout_ PVOID context
    );

EXTERN_C_END
