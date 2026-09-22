#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkProcessProtectIoctl.h"

EXTERN_C_START

/*
 * kswordArkProcessProtectInitialize
 * Inputs:
 * - Device is the control device used to write protection hits to the R3 log channel.
 * Processing:
 * - Allocate and publish the host state for the protection configuration snapshot. Must be called before
 *   kswordArkCallbackInitialize to ensure that once a handle callback is attached, it can read the initialized state.
 * Return behavior:
 * - Returns STATUS_INSUFFICIENT_RESOURCES on allocation failure; protection
 *   capabilities are disabled, but other driver functions load normally.
 */
NTSTATUS
kswordArkProcessProtectInitialize(
    _In_ WDFDEVICE device
    );

/*
 * kswordArkProcessProtectUninitialize
 * Processing:
 * - Release the configuration snapshot. The caller must first unregister object callbacks
 *   (kswordArkCallbackUninitialize); otherwise, in-flight pre-callbacks may access freed memory.
 */
VOID
kswordArkProcessProtectUninitialize(
    VOID
    );

/*
 * kswordArkProcessProtectNoteObjectCallbackState
 * Inputs:
 * - Registered indicates whether ObRegisterCallbacks is currently in a registered state.
 * - RegisterStatus is the original NTSTATUS of the most recent registration attempt;
 * Processing:
 * - Filled in by the object callback module during registration/unregistration, enabling R3 to
 *   distinguish between 'no rules configured' and 'handle callbacks failed to attach on this machine'.
 */
VOID
kswordArkProcessProtectNoteObjectCallbackState(
    _In_ BOOLEAN registered,
    _In_ NTSTATUS registerStatus
    );

/*
 * kswordArkProcessProtectFilterHandleOperation
 * Inputs:
 * - TargetIsThreadObject distinguishes whether the opened object is a process or a thread.
 * - TargetProcess is the target process (or its host process if the object is a thread); may be NULL.
 * - TargetImagePath and InitiatorImagePath are image paths already resolved by the caller and may be empty
 *   strings. Reusing them avoids repeated calls to SeLocateProcessImageName on the hot path for handles.
 * - DesiredAccess is the access mask requested from the object manager; bits are trimmed in-place upon hitting protection.
 * Processing:
 * - Sequentially checks the global switch, trusted whitelist, and rule table; if a match is found, removes
 *   dangerous bits from DesiredAccess and accumulates statistics with the 'last interception' snapshot.
 * Return behavior:
 * - Returns TRUE if at least one privilege was actually removed; FALSE if no match was found or no changes were needed.
 */
BOOLEAN
kswordArkProcessProtectFilterHandleOperation(
    _In_ BOOLEAN targetIsThreadObject,
    _In_opt_ PEPROCESS targetProcess,
    _In_opt_z_ PCWSTR targetImagePath,
    _In_opt_z_ PCWSTR initiatorImagePath,
    _Inout_ ACCESS_MASK* desiredAccess
    );

/*
 * kswordArkProcessProtectNotifyProcessCreate
 * Inputs:
 * - ProcessObject / ProcessId refer to the newly created process;
 * - ImageFileName is the NT path of the image provided by the create notification, which may be NULL.
 * Processing:
 * - Called by the process creation callback. When a rule with kernelProtection is matched, PP/PPL flags are set before the
 *   process starts executing. This is the only opportunity to ensure protection persists after the target process restarts.
 * Return behavior:
 * No return value; on failure, only increment the counter and write a log, never blocking process creation.
 */
VOID
kswordArkProcessProtectNotifyProcessCreate(
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_opt_ PCUNICODE_STRING imageFileName
    );

/*
 * kswordArkProcessProtectNotifyProcessExit
 * Processing:
 * - Called by process exit notifications to remove the PID from the self-healing ledger.
 */
VOID
kswordArkProcessProtectNotifyProcessExit(
    _In_ ULONG processId
    );

/*
 * kswordArkProcessProtectIoctlSetConfig
 * Processing:
 * - Validate and replace the protection configuration as a whole. The configuration is replaced entirely in one shot, without incremental merging.
 */
NTSTATUS
kswordArkProcessProtectIoctlSetConfig(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    );

/*
 * kswordArkProcessProtectIoctlQueryState
 * Processing:
 * - Re-read current configuration, capability status, and statistical counters for R3 display and verification.
 */
NTSTATUS
kswordArkProcessProtectIoctlQueryState(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    );

EXTERN_C_END
