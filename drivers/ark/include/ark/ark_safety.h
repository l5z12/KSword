#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkSafetyIoctl.h"

EXTERN_C_START

typedef struct KswordArkSafetyContext
{
    ULONG operation;
    ULONG targetProcessId;
    ULONG contextFlags;
    PCWSTR targetText;
    USHORT targetTextChars;
} KswordArkSafetyContext, *PkswordArkSafetyContext;

VOID
kswordArkSafetyInitialize(
    VOID
    );

NTSTATUS
kswordArkSafetyEvaluate(
    _In_opt_ WDFDEVICE device,
    _In_ const KswordArkSafetyContext* context
    );

NTSTATUS
kswordArkSafetyQueryPolicy(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkSafetySetPolicy(
    _In_ const KSWORD_ARK_SET_SAFETY_POLICY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END
