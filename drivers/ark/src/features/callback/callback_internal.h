#pragma once

#include <fltKernel.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "ark/ark_callback.h"
#include "ark/ark_log.h"

#define KSWORD_ARK_CALLBACK_TAG_RUNTIME 'rCbK'
#define KSWORD_ARK_CALLBACK_TAG_SNAPSHOT 'sCbK'
#define KSWORD_ARK_CALLBACK_TAG_PENDING 'pCbK'
#define KSWORD_ARK_CALLBACK_TAG_EXTERNAL 'xCbK'

typedef struct KswordArkCallbackMonitorSlot
{
    volatile LONG64 commitSequence;
    KSWORD_ARK_CALLBACK_MONITOR_EVENT event;
} KswordArkCallbackMonitorSlot;

#define KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY 0x00000001UL
#define KSWORD_ARK_CALLBACK_REGISTERED_PROCESS 0x00000002UL
#define KSWORD_ARK_CALLBACK_REGISTERED_THREAD 0x00000004UL
#define KSWORD_ARK_CALLBACK_REGISTERED_IMAGE 0x00000008UL
#define KSWORD_ARK_CALLBACK_REGISTERED_OBJECT 0x00000010UL
#define KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER 0x00000020UL

typedef struct KswordArkCallbackRuleSnapshot KswordArkCallbackRuleSnapshot;
typedef struct KswordArkPendingDecision KswordArkPendingDecision;

typedef struct KswordArkCallbackMatchResult
{
    BOOLEAN matched;
    ULONG callbackType;
    ULONG ruleOperationMask;
    ULONG action;
    ULONG matchMode;
    ULONG askTimeoutMs;
    ULONG askDefaultDecision;
    ULONG groupId;
    ULONG ruleId;
    ULONG groupPriority;
    ULONG rulePriority;
    WCHAR groupName[KSWORD_ARK_CALLBACK_EVENT_MAX_NAME_CHARS];
    WCHAR ruleName[KSWORD_ARK_CALLBACK_EVENT_MAX_NAME_CHARS];
    WCHAR ruleInitiatorPattern[KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS];
    WCHAR ruleTargetPattern[KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS];
} KswordArkCallbackMatchResult;

typedef struct KswordArkCallbackEventInput
{
    ULONG callbackType;
    ULONG operationType;
    ULONG originatingPid;
    ULONG originatingTid;
    ULONG sessionId;
    ULONG pathUnavailable;
    UNICODE_STRING initiatorPath;
    UNICODE_STRING targetPath;
    KswordArkCallbackMatchResult match;
} KswordArkCallbackEventInput;

typedef struct KswordArkRuntimeRule
{
    ULONG groupId;
    ULONG ruleId;
    ULONG groupPriority;
    ULONG rulePriority;
    ULONG callbackType;
    ULONG operationMask;
    ULONG action;
    ULONG matchMode;
    ULONG askTimeoutMs;
    ULONG askDefaultDecision;
    UNICODE_STRING initiatorPattern;
    UNICODE_STRING targetPattern;
    UNICODE_STRING groupName;
    UNICODE_STRING ruleName;
} KswordArkRuntimeRule;

typedef struct KswordArkCallbackRuleSnapshot
{
    EX_RUNDOWN_REF rundownRef;
    ULONG globalFlags;
    ULONG groupCount;
    ULONG ruleCount;
    ULONG activeRuleCount;
    ULONG stringPoolBytes;
    ULONG bucketStart[KSWORD_ARK_CALLBACK_TYPE_MINIFILTER + 1];
    ULONG bucketCount[KSWORD_ARK_CALLBACK_TYPE_MINIFILTER + 1];
    ULONG64 ruleVersion;
    LARGE_INTEGER appliedAtUtc100ns;
    KswordArkRuntimeRule rules[1];
} KswordArkCallbackRuleSnapshot;

typedef struct KswordArkCallbackRuntime
{
    WDFDEVICE device;
    WDFQUEUE waitQueue;

    EX_PUSH_LOCK snapshotLock;
    KswordArkCallbackRuleSnapshot* activeSnapshot;

    EX_PUSH_LOCK pendingLock;
    LIST_ENTRY pendingDecisionList;
    volatile LONG pendingDecisionCount;
    // Reject creating new wait items after unloading begins to ensure existing waiters are drained before deregistering callbacks.
    volatile LONG stopping;
    volatile LONG64 eventSequence;

    LARGE_INTEGER registryCookie;
    PVOID obRegistrationHandle;
    PFLT_FILTER miniFilterHandle;
    BOOLEAN miniFilterStarted;
    NTSTATUS miniFilterRegisterStatus;
    NTSTATUS miniFilterStartStatus;
    EX_PUSH_LOCK miniFilterBypassPidLock;
    ULONG miniFilterBypassPidCount;
    ULONG miniFilterBypassPids[KSWORD_ARK_MINIFILTER_BYPASS_PID_MAX_COUNT];
    ULONG registeredCallbacksMask;
    // Telemetry ring uses try-lock for serialized publishing; in case of contention, prefer counting drops over blocking kernel callbacks.
    volatile LONG monitorWriterLock;
    volatile LONG monitorCategoryMask;
    volatile LONG64 monitorLatestSequence;
    volatile LONG64 monitorDroppedCount;
    NTSTATUS monitorLastStatus;
    KswordArkCallbackMonitorSlot monitorSlots[KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY];
    // The original registration status for each callback type. After a degraded start, R3 uses this to explain why
    // a capability is missing, rather than presenting only a vague conclusion like 'Driver online but incomplete'.
    NTSTATUS waitQueueStatus;
    NTSTATUS registryRegisterStatus;
    NTSTATUS processRegisterStatus;
    NTSTATUS threadRegisterStatus;
    NTSTATUS imageRegisterStatus;
    NTSTATUS objectRegisterStatus;
    BOOLEAN initialized;
} KswordArkCallbackRuntime;

typedef struct KswordArkPendingDecision
{
    LIST_ENTRY link;
    LONG refCount;
    volatile LONG answered;
    KSWORD_ARK_GUID128 eventGuid;
    KEVENT decisionEvent;
    ULONG finalDecision;
    ULONG defaultDecision;
    ULONG callbackType;
    ULONG operationType;
    ULONG originatingPid;
    ULONG originatingTid;
    ULONG sessionId;
    ULONG pathUnavailable;
    ULONG timeoutMs;
    LARGE_INTEGER createdAtUtc100ns;
    LARGE_INTEGER deadlineUtc100ns;
    KswordArkCallbackMatchResult match;
    WCHAR initiatorPath[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS];
    WCHAR targetPath[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS];
} KswordArkPendingDecision;

typedef struct KswordArkCallbackEnumBuilder
{
    // Entries points to the actual output array for the current page; its capacity is limited by the METHOD_BUFFERED length.
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entries;
    ULONG entryCapacity;
    // StartIndex and the counter together project the full logical enumeration onto the current page.
    ULONG startIndex;
    ULONG totalCount;
    ULONG returnedCount;
    // Flags and LastStatus aggregate the status of the current page and the full snapshot.
    ULONG flags;
    NTSTATUS lastStatus;
    // SnapshotRowCount and SnapshotHash cover all logical lines, not just the current page.
    ULONG snapshotRowCount;
    ULONG64 snapshotHash;
    // PendingEntry: identity hash is computed lazily after the caller fills one row.
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* pendingEntry;
    // Rows outside the paging range are constructed in ScratchEntry so they can still participate in snapshot hashing.
    KSWORD_ARK_CALLBACK_ENUM_ENTRY scratchEntry;
    // EX Object Callback unregistration matches one original enumeration row during the full snapshot aggregation phase.
    const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST* removeMatchRequest;
    ULONG removeMatchedFieldFlags;
    ULONG64 removeMatchedRegistrationAddress;
    ULONG removeMatchCount;
} KswordArkCallbackEnumBuilder;

typedef struct KswordArkCallbackModuleEntry
{
    HANDLE section;
    PVOID mappedBase;
    PVOID imageBase;
    ULONG imageSize;
    ULONG flags;
    USHORT loadOrderIndex;
    USHORT initOrderIndex;
    USHORT loadCount;
    USHORT offsetToFileName;
    UCHAR fullPathName[256];
} KswordArkCallbackModuleEntry;

typedef struct KswordArkCallbackModuleInformation
{
    ULONG numberOfModules;
    KswordArkCallbackModuleEntry modules[1];
} KswordArkCallbackModuleInformation;

typedef struct KswordArkCallbackModuleCache
{
    KswordArkCallbackModuleInformation* moduleInfo;
    ULONG moduleInfoBytes;
} KswordArkCallbackModuleCache;

EXTERN_C_START

KswordArkCallbackRuntime*
kswordArkCallbackGetRuntime(
    VOID
    );

VOID
kswordArkCallbackLogFrame(
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    );

VOID
kswordArkCallbackLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    );

// The initialization phase must use the explicit runtime version: the global runtime is only published after all five
// types of callbacks are registered. Using global lookup would cause the entire startup-phase log to be discarded.
VOID
kswordArkCallbackLogFrameForRuntime(
    _In_opt_ KswordArkCallbackRuntime* runtime,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    );

VOID
kswordArkCallbackLogFormatForRuntime(
    _In_opt_ KswordArkCallbackRuntime* runtime,
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    );

VOID
kswordArkGetSystemTimeUtc100ns(
    _Out_ LARGE_INTEGER* utcOut
    );

VOID
kswordArkCopyUnicodeToFixedBuffer(
    _In_opt_ PCUNICODE_STRING sourceText,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars
    );

VOID
kswordArkCopyWideStringToFixedBuffer(
    _In_opt_z_ PCWSTR sourceText,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars
    );

BOOLEAN
kswordArkResolveProcessImagePath(
    _In_opt_ PEPROCESS processObject,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars,
    _Out_opt_ BOOLEAN* pathUnavailableOut
    );

ULONG
kswordArkGetProcessSessionIdSafe(
    _In_opt_ PEPROCESS processObject
    );

BOOLEAN
kswordArkGuidEquals(
    _In_ const KSWORD_ARK_GUID128* leftGuid,
    _In_ const KSWORD_ARK_GUID128* rightGuid
    );

PVOID
kswordArkAllocateNonPaged(
    _In_ SIZE_T bytes,
    _In_ ULONG poolTag
    );

VOID
kswordArkCallbackEnumCopyWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    );

VOID
kswordArkCallbackEnumCopyUnicode(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_ PCUNICODE_STRING source
    );

VOID
kswordArkCallbackEnumInitModuleCache(
    _Out_ KswordArkCallbackModuleCache* moduleCache
    );

VOID
kswordArkCallbackEnumFreeModuleCache(
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    );

_Must_inspect_result_
NTSTATUS
kswordArkCallbackEnumEnsureModuleCache(
    _Inout_ KswordArkCallbackModuleCache* moduleCache
    );

_Must_inspect_result_
NTSTATUS
kswordArkCallbackEnumResolveModuleByAddressCached(
    _Inout_opt_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 callbackAddress,
    _Out_writes_(modulePathChars) PWCHAR modulePath,
    _In_ ULONG modulePathChars,
    _Out_opt_ ULONG64* moduleBaseOut,
    _Out_opt_ ULONG* moduleSizeOut
    );

BOOLEAN
kswordArkCallbackEnumIsKernelModuleAddress(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _In_ ULONG64 candidateAddress
    );

BOOLEAN
kswordArkCallbackEnumReadMemory(
    _In_ const VOID* sourceAddress,
    _Out_writes_bytes_(bytesToRead) VOID* destinationBuffer,
    _In_ SIZE_T bytesToRead
    );

KSWORD_ARK_CALLBACK_ENUM_ENTRY*
kswordArkCallbackEnumReserveEntry(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackEnumSnapshotBegin(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackEnumSnapshotCommitPending(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackEnumSnapshotFinalize(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

VOID
kswordArkCallbackEnumFinalizeModuleCached(
    _Inout_ KswordArkCallbackModuleCache* moduleCache,
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry
    );

VOID
kswordArkCallbackEnumAddUnsupportedRow(
    _Inout_ KswordArkCallbackEnumBuilder* builder,
    _In_ ULONG callbackClass,
    _In_opt_z_ PCWSTR nameText,
    _In_opt_z_ PCWSTR detailText
    );

VOID
kswordArkCallbackEnumAddMinifilters(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

NTSTATUS
kswordArkMinifilterQueryFirstCallbackOwner(
    _In_ PFLT_FILTER filterObject,
    _Out_writes_(modulePathChars) PWCHAR modulePath,
    _In_ ULONG modulePathChars,
    _Out_opt_ ULONG64* moduleBaseOut,
    _Out_opt_ ULONG* moduleSizeOut
    );

VOID
kswordArkCallbackEnumAddPrivateCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    );

_Must_inspect_result_
NTSTATUS
kswordArkCallbackEnumRevalidateObjectRemoveRequest(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST* requestPacket,
    _In_ BOOLEAN requireGenerationMatch,
    _Out_ BOOLEAN* matchPresentOut,
    _Out_opt_ ULONG* matchedFieldFlagsOut,
    _Out_opt_ ULONG64* matchedRegistrationAddressOut,
    _Out_opt_ ULONG64* currentGenerationOut
    );

VOID
kswordArkGuidGenerate(
    _Out_ KSWORD_ARK_GUID128* guidOut
    );

NTSTATUS
kswordArkCallbackBuildSnapshotFromBlob(
    _In_reads_bytes_(blobBytes) const VOID* blobData,
    _In_ size_t blobBytes,
    _Outptr_ KswordArkCallbackRuleSnapshot** snapshotOut
    );

VOID
kswordArkCallbackFreeSnapshot(
    _In_opt_ KswordArkCallbackRuleSnapshot* snapshot
    );

NTSTATUS
kswordArkCallbackSwapSnapshot(
    _In_ KswordArkCallbackRuleSnapshot* newSnapshot
    );

VOID
kswordArkCallbackQueryRuntimeState(
    _Out_ KSWORD_ARK_CALLBACK_RUNTIME_STATE* runtimeStateOut
    );

NTSTATUS
kswordArkCallbackMatchRule(
    _In_ ULONG callbackType,
    _In_ ULONG operationType,
    _In_opt_ PCUNICODE_STRING initiatorPath,
    _In_opt_ PCUNICODE_STRING targetPath,
    _Out_ KswordArkCallbackMatchResult* matchResultOut
    );

NTSTATUS
kswordArkCallbackSetMinifilterBypassPids(
    _In_reads_opt_(pidCount) const ULONG* processIds,
    _In_ ULONG pidCount
    );

NTSTATUS
kswordArkCallbackQueryMinifilterBypassPids(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

BOOLEAN
kswordArkCallbackIsMinifilterBypassPid(
    _In_ ULONG processId
    );

NTSTATUS
kswordArkCallbackWaiterInitialize(
    _In_ KswordArkCallbackRuntime* runtime
    );

VOID
kswordArkCallbackWaiterUninitialize(
    _In_ KswordArkCallbackRuntime* runtime
    );

NTSTATUS
kswordArkCallbackIoctlWaitEventInternal(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackIoctlAnswerEventInternal(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    );

NTSTATUS
kswordArkCallbackCancelAllPendingInternal(
    VOID
    );

NTSTATUS
kswordArkCallbackCancelAllPendingForRuntime(
    _In_ KswordArkCallbackRuntime* runtime
    );

NTSTATUS
kswordArkCallbackAskUserDecision(
    _In_ const KswordArkCallbackEventInput* eventInput,
    _Out_ ULONG* decisionOut
    );

ULONG
kswordArkCallbackGetWaitingRequestCount(
    VOID
    );

ULONG
kswordArkCallbackGetPendingDecisionCount(
    VOID
    );

NTSTATUS
kswordArkRegistryCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    );

VOID
kswordArkRegistryCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    );

NTSTATUS
kswordArkProcessCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    );

VOID
kswordArkProcessCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    );

NTSTATUS
kswordArkThreadCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    );

VOID
kswordArkThreadCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    );

NTSTATUS
kswordArkImageCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    );

VOID
kswordArkImageCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    );

NTSTATUS
kswordArkObjectCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    );

VOID
kswordArkObjectCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    );

VOID
kswordArkMinifilterCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    );

VOID
kswordArkMinifilterCallbackUpdateState(
    _In_opt_ PFLT_FILTER filterHandle,
    _In_ NTSTATUS registerStatus,
    _In_ NTSTATUS startStatus,
    _In_ BOOLEAN started
    );

FLT_PREOP_CALLBACK_STATUS
FLTAPI
kswordArkMinifilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Outptr_result_maybenull_ PVOID* completionContext
    );

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
kswordArkMinifilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_opt_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags
    );

FLT_PREOP_CALLBACK_STATUS
kswordArkMinifilterApplyRule(
    _In_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ ULONG operationType
    );

EXTERN_C_END
