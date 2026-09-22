/*++

Module Name:

    alpc_runtime_fallback.c

Abstract:

    No-profile ALPC basic-information fallback.  Instead of interpreting the
    private ALPC_PORT layout, it resolves the stable ZwAlpcQueryInformation
    export and queries information class zero while attached to the owning
    process.  Unsupported kernels fail closed without publishing guessed data.

Environment:

    Kernel mode, PASSIVE_LEVEL read-only query paths.

--*/

#include "alpc_runtime_fallback.h"

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef NTSTATUS
(NTAPI* KswZwAlpcQueryInformationFn)(
    _In_ HANDLE portHandle,
    _In_ ULONG portInformationClass,
    _Out_writes_bytes_(length) PVOID portInformation,
    _In_ ULONG length,
    _Out_opt_ PULONG returnLength
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

static KswZwAlpcQueryInformationFn
KswordARKAlpcResolveQueryInformation(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwAlpcQueryInformation");
    return (KswZwAlpcQueryInformationFn)MmGetSystemRoutineAddress(
        &routineName);
}

NTSTATUS
kswordArkAlpcQueryRuntimeBasicInfo(
    _In_ PEPROCESS processObject,
    _In_ ULONG64 handleValue,
    _Out_ KswAlpcRuntimeBasicInfo* basicInfoOut
    )
{
    KswZwAlpcQueryInformationFn queryInformation = NULL;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    ULONG returnLength = 0UL;
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || handleValue == 0ULL ||
        basicInfoOut == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(basicInfoOut, sizeof(*basicInfoOut));
    queryInformation = KswordARKAlpcResolveQueryInformation();
    if (queryInformation == NULL) {
        return STATUS_NOT_SUPPORTED;
    }

    RtlZeroMemory(attachState, sizeof(attachState));
    __try {
        KeStackAttachProcess((PVOID)processObject, attachState);
        attached = TRUE;
        status = queryInformation(
            (HANDLE)(ULONG_PTR)handleValue,
            0UL,
            basicInfoOut,
            sizeof(*basicInfoOut),
            &returnLength);
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (attached) {
            KeUnstackDetachProcess(attachState);
            attached = FALSE;
        }
    }
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(basicInfoOut, sizeof(*basicInfoOut));
        return status;
    }
    if (returnLength != 0UL && returnLength < sizeof(*basicInfoOut)) {
        RtlZeroMemory(basicInfoOut, sizeof(*basicInfoOut));
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    return STATUS_SUCCESS;
}
