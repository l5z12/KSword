/*++

Module Name:

    wsl_silo_query.c

Abstract:

    Phase-13 WSL/Pico and Silo read-only diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#include <ntimage.h>

#define KSWORD_ARK_WSL_SYSTEM_MODULE_INFORMATION_CLASS 11UL
#define KSWORD_ARK_WSL_OFFSET_UNAVAILABLE KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE
#define KSWORD_ARK_WSL_PROCESS_SUBSYSTEM_INFORMATION 75UL
#define KSWORD_ARK_WSL_THREAD_SUBSYSTEM_INFORMATION 38UL

#define KSWORD_ARK_WSL_SILO_ROUTINE_GET_IDENTIFIER       0x00000001UL
#define KSWORD_ARK_WSL_SILO_ROUTINE_GET_EFFECTIVE_SERVER 0x00000002UL
#define KSWORD_ARK_WSL_SILO_ROUTINE_IS_HOST              0x00000004UL
#define KSWORD_ARK_WSL_SILO_ROUTINE_GET_SERVICE_SESSION  0x00000008UL
#define KSWORD_ARK_WSL_SILO_ROUTINE_GET_ACTIVE_CONSOLE   0x00000010UL
#define KSWORD_ARK_WSL_SILO_ROUTINE_GET_CONTAINER_ID     0x00000020UL

typedef BOOLEAN(NTAPI* KswordLxpThreadGetCurrentFn)(
    _Outptr_ PVOID* picoContextOut
    );

typedef ULONG(NTAPI* KswordPsGetSiloIdentifierFn)(
    _In_opt_ PVOID silo
    );

typedef PVOID(NTAPI* KswordPsGetEffectiveServerSiloFn)(
    _In_opt_ PVOID silo
    );

typedef BOOLEAN(NTAPI* KswordPsIsHostSiloFn)(
    _In_opt_ PVOID silo
    );

typedef ULONG(NTAPI* KswordPsGetServerSiloSessionFn)(
    _In_opt_ PVOID silo
    );

typedef GUID*(NTAPI* KswordPsGetSiloContainerIdFn)(
    _In_ PVOID silo
    );

typedef NTSTATUS(NTAPI* KswordZwQueryInformationProcessFn)(
    _In_ HANDLE processHandle,
    _In_ ULONG processInformationClass,
    _Out_writes_bytes_(processInformationLength) PVOID processInformation,
    _In_ ULONG processInformationLength,
    _Out_opt_ PULONG returnLength
    );

typedef NTSTATUS(NTAPI* KswordZwQueryInformationThreadFn)(
    _In_ HANDLE threadHandle,
    _In_ ULONG threadInformationClass,
    _Out_writes_bytes_(threadInformationLength) PVOID threadInformation,
    _In_ ULONG threadInformationLength,
    _Out_opt_ PULONG returnLength
    );

typedef struct KswordWslSystemModuleEntry
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
} KswordWslSystemModuleEntry, *PkswordWslSystemModuleEntry;

typedef struct KswordWslSystemModuleInformation
{
    ULONG numberOfModules;
    KswordWslSystemModuleEntry modules[1];
} KswordWslSystemModuleInformation, *PkswordWslSystemModuleInformation;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupThreadByThreadId(
    _In_ HANDLE threadId,
    _Outptr_ PETHREAD* thread
    );

NTKERNELAPI
HANDLE
PsGetThreadId(
    _In_ PETHREAD thread
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID object,
    _In_ ULONG handleAttributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Out_ PHANDLE handle
    );

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_ PCCH routineName
    );

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#endif

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION (0x0800)
#endif

static BOOLEAN
kswordArkWslOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Check if the lxcore DynData offset is available. Note: Both 0xffff
    and Ksword's own unavailable sentinel are treated as unreadable.

Arguments:

    Offset - DynData offset.

Return Value:

    TRUE indicates the value can be used for pointer dereferencing.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static ULONG
kswordArkWslNormalizeOffset(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Convert internal offset sentinel to shared protocol sentinel. Note: R3 only needs to
    check KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; do not expose internal 0xffff details.

Arguments:

    Offset: Original offset.

Return Value:

    Valid offset or unavailable sentinel.

--*/
{
    return kswordArkWslOffsetPresent(offset) ? offset : KSWORD_ARK_WSL_OFFSET_UNAVAILABLE;
}

static CHAR
kswordArkWslAsciiLower(
    _In_ CHAR character
    )
{
    if (character >= 'A' && character <= 'Z') {
        return (CHAR)(character + ('a' - 'A'));
    }
    return character;
}

static BOOLEAN
kswordArkWslModuleNameEquals(
    _In_reads_bytes_(leftBytes) const UCHAR* leftText,
    _In_ ULONG leftBytes,
    _In_z_ PCSTR rightText
    )
/*++

Routine Description:

    Compare bounded ANSI module names in SystemModuleInformation. Note: Module name buffers
    are not guaranteed to be null-terminated; compare byte-by-byte up to the length limit.

Arguments:

    LeftText - bounded ANSI text.
    LeftBytes: Number of readable bytes.
    RightText: Target module name.

Return Value:

    TRUE indicates case-insensitive matching.

--*/
{
    ULONG index = 0UL;

    if (leftText == NULL || leftBytes == 0UL || rightText == NULL) {
        return FALSE;
    }

    for (index = 0UL; index < leftBytes; ++index) {
        CHAR leftCharacter = (CHAR)leftText[index];
        CHAR rightCharacter = rightText[index];

        if (rightCharacter == '\0') {
            return (leftCharacter == '\0') ? TRUE : FALSE;
        }
        if (leftCharacter == '\0') {
            return FALSE;
        }
        if (kswordArkWslAsciiLower(leftCharacter) != kswordArkWslAsciiLower(rightCharacter)) {
            return FALSE;
        }
    }

    return (rightText[index] == '\0') ? TRUE : FALSE;
}

static PVOID
kswordArkWslAllocate(
    _In_ SIZE_T bytes
    )
{
    if (bytes == 0U) {
        return NULL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bytes, 'wLsK');
#pragma warning(pop)
}

static PVOID
kswordArkWslFindExportedRoutine(
    _In_z_ PCSTR moduleName,
    _In_z_ PCSTR routineName
    )
/*++

Routine Description:

    Search for exported functions in the loaded module list. Note: This follows the
    KphGetRoutineAddress approach from System Informer but uses SystemModuleInformation to
    avoid relying on private symbols like PsLoadedModuleList or PsLoadedModuleResource.

Arguments:

    ModuleName - Target module name, e.g., lxcore.sys.
    RoutineName: The exported function name, e.g., LxpThreadGetCurrent.

Return Value:

    Export address or NULL.

--*/
{
    PkswordWslSystemModuleInformation moduleInfo = NULL;
    ULONG requiredBytes = 0UL;
    ULONG queryBytes = 0UL;
    ULONG index = 0UL;
    PVOID routineAddress = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    status = ZwQuerySystemInformation(
        KSWORD_ARK_WSL_SYSTEM_MODULE_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes == 0UL) {
        return NULL;
    }

    queryBytes = requiredBytes + (64UL * 1024UL);
    moduleInfo = (PkswordWslSystemModuleInformation)kswordArkWslAllocate(queryBytes);
    if (moduleInfo == NULL) {
        return NULL;
    }

    status = ZwQuerySystemInformation(
        KSWORD_ARK_WSL_SYSTEM_MODULE_INFORMATION_CLASS,
        moduleInfo,
        queryBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, 'wLsK');
        return NULL;
    }

    for (index = 0UL; index < moduleInfo->numberOfModules; ++index) {
        const KswordWslSystemModuleEntry* entry = &moduleInfo->modules[index];
        const UCHAR* fileName = entry->fullPathName;
        ULONG fileNameBytes = sizeof(entry->fullPathName);

        if (entry->offsetToFileName < sizeof(entry->fullPathName)) {
            fileName = entry->fullPathName + entry->offsetToFileName;
            fileNameBytes = (ULONG)(sizeof(entry->fullPathName) - entry->offsetToFileName);
        }

        if (!kswordArkWslModuleNameEquals(fileName, fileNameBytes, moduleName)) {
            continue;
        }

        __try {
            routineAddress = RtlFindExportedRoutineByName(entry->imageBase, routineName);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            routineAddress = NULL;
        }
        break;
    }

    ExFreePoolWithTag(moduleInfo, 'wLsK');
    return routineAddress;
}

static KswordZwQueryInformationProcessFn
kswordArkWslResolveZwQueryInformationProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
    return (KswordZwQueryInformationProcessFn)MmGetSystemRoutineAddress(&routineName);
}

static KswordZwQueryInformationThreadFn
kswordArkWslResolveZwQueryInformationThread(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwQueryInformationThread");
    return (KswordZwQueryInformationThreadFn)MmGetSystemRoutineAddress(&routineName);
}

static ULONG
kswordArkWslResolveSiloRoutineMask(
    VOID
    )
/*++

Routine Description:

    Dynamically resolve the availability of public Silo export functions. Note: Phase-13 v1 only displays
    availability without registering a silo monitor to avoid introducing additional lifecycle complexity.

Arguments:

    None.

Return Value:

    Bitmap for KSWORD_ARK_WSL_SILO_ROUTINE_*.

--*/
{
    ULONG mask = 0UL;
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"PsGetSiloIdentifier");
    if (MmGetSystemRoutineAddress(&routineName) != NULL) {
        mask |= KSWORD_ARK_WSL_SILO_ROUTINE_GET_IDENTIFIER;
    }
    RtlInitUnicodeString(&routineName, L"PsGetEffectiveServerSilo");
    if (MmGetSystemRoutineAddress(&routineName) != NULL) {
        mask |= KSWORD_ARK_WSL_SILO_ROUTINE_GET_EFFECTIVE_SERVER;
    }
    RtlInitUnicodeString(&routineName, L"PsIsHostSilo");
    if (MmGetSystemRoutineAddress(&routineName) != NULL) {
        mask |= KSWORD_ARK_WSL_SILO_ROUTINE_IS_HOST;
    }
    RtlInitUnicodeString(&routineName, L"PsGetServerSiloServiceSessionId");
    if (MmGetSystemRoutineAddress(&routineName) != NULL) {
        mask |= KSWORD_ARK_WSL_SILO_ROUTINE_GET_SERVICE_SESSION;
    }
    RtlInitUnicodeString(&routineName, L"PsGetServerSiloActiveConsoleId");
    if (MmGetSystemRoutineAddress(&routineName) != NULL) {
        mask |= KSWORD_ARK_WSL_SILO_ROUTINE_GET_ACTIVE_CONSOLE;
    }
    RtlInitUnicodeString(&routineName, L"PsGetSiloContainerId");
    if (MmGetSystemRoutineAddress(&routineName) != NULL) {
        mask |= KSWORD_ARK_WSL_SILO_ROUTINE_GET_CONTAINER_ID;
    }

    return mask;
}

static NTSTATUS
kswordArkWslQueryProcessSubsystem(
    _In_ PEPROCESS processObject,
    _Out_ ULONG* subsystemOut
    )
/*++

Routine Description:

    Query the target process subsystem type. Note: On older Windows versions that do not
    support this info class, treat it as Win32, consistent with System Informer behavior.

Arguments:

    ProcessObject - Target EPROCESS.
    SubsystemOut - Receives the subsystem type.

Return Value:

    STATUS_SUCCESS or underlying open/query status.

--*/
{
    KswordZwQueryInformationProcessFn zwQueryInformationProcess = NULL;
    HANDLE processHandle = NULL;
    ULONG subsystemType = KSWORD_ARK_WSL_SUBSYSTEM_UNKNOWN;
    NTSTATUS status = STATUS_SUCCESS;

    if (processObject == NULL || subsystemOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *subsystemOut = KSWORD_ARK_WSL_SUBSYSTEM_UNKNOWN;
    zwQueryInformationProcess = kswordArkWslResolveZwQueryInformationProcess();
    if (zwQueryInformationProcess == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode,
        &processHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = zwQueryInformationProcess(
        processHandle,
        KSWORD_ARK_WSL_PROCESS_SUBSYSTEM_INFORMATION,
        &subsystemType,
        sizeof(subsystemType),
        NULL);
    ZwClose(processHandle);

    if (status == STATUS_INVALID_INFO_CLASS) {
        subsystemType = KSWORD_ARK_WSL_SUBSYSTEM_WIN32;
        status = STATUS_SUCCESS;
    }
    if (NT_SUCCESS(status)) {
        *subsystemOut = subsystemType;
    }

    return status;
}

static NTSTATUS
kswordArkWslQueryThreadSubsystem(
    _In_ PETHREAD threadObject,
    _Out_ ULONG* subsystemOut
    )
/*++

Routine Description:

    Query the subsystem type of the target thread. Note: This field distinguishes WSL/Pico threads
    from standard Win32 threads; on failure, do not attempt to read lxcore private structures.

Arguments:

    ThreadObject - target ETHREAD.
    SubsystemOut - Receives the subsystem type.

Return Value:

    STATUS_SUCCESS or underlying open/query status.

--*/
{
    KswordZwQueryInformationThreadFn zwQueryInformationThread = NULL;
    HANDLE threadHandle = NULL;
    ULONG subsystemType = KSWORD_ARK_WSL_SUBSYSTEM_UNKNOWN;
    NTSTATUS status = STATUS_SUCCESS;

    if (threadObject == NULL || subsystemOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *subsystemOut = KSWORD_ARK_WSL_SUBSYSTEM_UNKNOWN;
    zwQueryInformationThread = kswordArkWslResolveZwQueryInformationThread();
    if (zwQueryInformationThread == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = ObOpenObjectByPointer(
        threadObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_QUERY_LIMITED_INFORMATION,
        *PsThreadType,
        KernelMode,
        &threadHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = zwQueryInformationThread(
        threadHandle,
        KSWORD_ARK_WSL_THREAD_SUBSYSTEM_INFORMATION,
        &subsystemType,
        sizeof(subsystemType),
        NULL);
    ZwClose(threadHandle);

    if (status == STATUS_INVALID_INFO_CLASS) {
        subsystemType = KSWORD_ARK_WSL_SUBSYSTEM_WIN32;
        status = STATUS_SUCCESS;
    }
    if (NT_SUCCESS(status)) {
        *subsystemOut = subsystemType;
    }

    return status;
}

static NTSTATUS
kswordArkWslReadLinuxIdsFromCurrentThread(
    _In_ const KswDynLxcoreOffsets* offsets,
    _Out_ ULONG* linuxPidOut,
    _Out_ ULONG* linuxTidOut
    )
/*++

Routine Description:

    Read Linux PID/TID from the current thread's lxcore pico context. Note: System Informer
    uses APCs to return to the original thread context for any thread; this first version
    reads only within the current thread context to avoid cross-thread APC lifecycle risks.

Arguments:

    Offsets - lxcore DynData offsets。
    LinuxPidOut - Receives Linux PID.
    LinuxTidOut - Receives Linux TID.

Return Value:

    STATUS_SUCCESS or read failure status.

--*/
{
    KswordLxpThreadGetCurrentFn lxpThreadGetCurrent = NULL;
    PVOID picoContext = NULL;
    PVOID value = NULL;
    ULONG linuxPid = 0UL;
    ULONG linuxTid = 0UL;

    if (offsets == NULL || linuxPidOut == NULL || linuxTidOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *linuxPidOut = 0UL;
    *linuxTidOut = 0UL;
    if (!kswordArkWslOffsetPresent(offsets->lxPicoProc) ||
        !kswordArkWslOffsetPresent(offsets->lxPicoProcInfo) ||
        !kswordArkWslOffsetPresent(offsets->lxPicoProcInfoPid) ||
        !kswordArkWslOffsetPresent(offsets->lxPicoThrdInfo) ||
        !kswordArkWslOffsetPresent(offsets->lxPicoThrdInfoTid)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    lxpThreadGetCurrent =
        (KswordLxpThreadGetCurrentFn)kswordArkWslFindExportedRoutine(
            "lxcore.sys",
            "LxpThreadGetCurrent");
    if (lxpThreadGetCurrent == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    __try {
        if (!lxpThreadGetCurrent(&picoContext) || picoContext == NULL) {
            return STATUS_NOT_FOUND;
        }

        value = *(PVOID*)((PUCHAR)picoContext + offsets->lxPicoThrdInfo);
        linuxTid = *(ULONG*)((PUCHAR)value + offsets->lxPicoThrdInfoTid);

        value = *(PVOID*)((PUCHAR)picoContext + offsets->lxPicoProc);
        value = *(PVOID*)((PUCHAR)value + offsets->lxPicoProcInfo);
        linuxPid = *(ULONG*)((PUCHAR)value + offsets->lxPicoProcInfoPid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *linuxPidOut = linuxPid;
    *linuxTidOut = linuxTid;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverQueryWslSilo(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_WSL_SILO_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query WSL/Pico and Silo basic diagnostic information. Note: lxcore load/match status comes from
    DynData; Linux PID/TID first version is only resolved when the request thread is the current thread.

Arguments:

    OutputBuffer - Response buffer.
    OutputBufferLength - Response length.
    Request - Query request.
    BytesWrittenOut - receives sizeof(response).

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; details are provided via queryStatus and individual NTSTATUS returns.

--*/
{
    KSWORD_ARK_QUERY_WSL_SILO_RESPONSE* response = NULL;
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    PETHREAD threadObject = NULL;
    ULONG requestFlags = 0UL;
    ULONG processSubsystem = KSWORD_ARK_WSL_SUBSYSTEM_UNKNOWN;
    ULONG threadSubsystem = KSWORD_ARK_WSL_SUBSYSTEM_UNKNOWN;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_WSL_SILO_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&dynState, sizeof(dynState));

    response = (KSWORD_ARK_QUERY_WSL_SILO_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_WSL_SILO_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->queryStatus = KSWORD_ARK_WSL_QUERY_STATUS_UNAVAILABLE;
    response->processLookupStatus = STATUS_NOT_SUPPORTED;
    response->threadLookupStatus = STATUS_NOT_SUPPORTED;
    response->processSubsystemStatus = STATUS_NOT_SUPPORTED;
    response->threadSubsystemStatus = STATUS_NOT_SUPPORTED;
    response->linuxPidStatus = STATUS_NOT_SUPPORTED;
    response->linuxTidStatus = STATUS_NOT_SUPPORTED;
    response->siloStatus = STATUS_NOT_SUPPORTED;
    response->processId = request->processId;
    response->threadId = request->threadId;
    response->processSubsystemType = KSWORD_ARK_WSL_SUBSYSTEM_UNKNOWN;
    response->threadSubsystemType = KSWORD_ARK_WSL_SUBSYSTEM_UNKNOWN;

    kswordArkDynDataSnapshot(&dynState);
    response->dynDataCapabilityMask = dynState.capabilityMask;
    response->lxcore = dynState.lxcore;
    response->lxPicoProcOffset = kswordArkWslNormalizeOffset(dynState.lxcoreOffsets.lxPicoProc);
    response->lxPicoProcInfoOffset = kswordArkWslNormalizeOffset(dynState.lxcoreOffsets.lxPicoProcInfo);
    response->lxPicoProcInfoPidOffset = kswordArkWslNormalizeOffset(dynState.lxcoreOffsets.lxPicoProcInfoPid);
    response->lxPicoThrdInfoOffset = kswordArkWslNormalizeOffset(dynState.lxcoreOffsets.lxPicoThrdInfo);
    response->lxPicoThrdInfoTidOffset = kswordArkWslNormalizeOffset(dynState.lxcoreOffsets.lxPicoThrdInfoTid);

    if (dynState.lxcore.present != 0UL) {
        response->fieldFlags |= KSWORD_ARK_WSL_FIELD_LXCORE_PRESENT;
    }
    if (dynState.lxcoreActive &&
        (dynState.capabilityMask & KSW_CAP_WSL_LXCORE_FIELDS) != 0ULL) {
        response->fieldFlags |= KSWORD_ARK_WSL_FIELD_LXCORE_DYNDATA_ACTIVE;
    }

    requestFlags = (request->flags == 0UL) ? KSWORD_ARK_WSL_QUERY_FLAG_INCLUDE_ALL : request->flags;

    if ((requestFlags & KSWORD_ARK_WSL_QUERY_FLAG_INCLUDE_SILO) != 0UL) {
        response->siloRoutinesMask = kswordArkWslResolveSiloRoutineMask();
        response->siloStatus = (response->siloRoutinesMask != 0UL) ? STATUS_SUCCESS : STATUS_PROCEDURE_NOT_FOUND;
        if (response->siloRoutinesMask != 0UL) {
            response->fieldFlags |= KSWORD_ARK_WSL_FIELD_SILO_ROUTINES_PRESENT;
        }
    }

    if ((requestFlags & KSWORD_ARK_WSL_QUERY_FLAG_INCLUDE_PROCESS) != 0UL &&
        request->processId != 0UL) {
        status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
        response->processLookupStatus = status;
        if (NT_SUCCESS(status)) {
            status = kswordArkWslQueryProcessSubsystem(processObject, &processSubsystem);
            response->processSubsystemStatus = status;
            if (NT_SUCCESS(status)) {
                response->processSubsystemType = processSubsystem;
                response->fieldFlags |= KSWORD_ARK_WSL_FIELD_PROCESS_SUBSYSTEM_PRESENT;
            }
        }
    }

    if ((requestFlags & KSWORD_ARK_WSL_QUERY_FLAG_INCLUDE_THREAD) != 0UL &&
        request->threadId != 0UL) {
        status = PsLookupThreadByThreadId(ULongToHandle(request->threadId), &threadObject);
        response->threadLookupStatus = status;
        if (NT_SUCCESS(status)) {
            status = kswordArkWslQueryThreadSubsystem(threadObject, &threadSubsystem);
            response->threadSubsystemStatus = status;
            if (NT_SUCCESS(status)) {
                response->threadSubsystemType = threadSubsystem;
                response->fieldFlags |= KSWORD_ARK_WSL_FIELD_THREAD_SUBSYSTEM_PRESENT;
            }

            if (PsGetThreadId(threadObject) == PsGetCurrentThreadId()) {
                response->fieldFlags |= KSWORD_ARK_WSL_FIELD_CURRENT_THREAD_CONTEXT;
                if ((response->fieldFlags & KSWORD_ARK_WSL_FIELD_LXCORE_DYNDATA_ACTIVE) != 0UL &&
                    threadSubsystem == KSWORD_ARK_WSL_SUBSYSTEM_WSL) {
                    ULONG linuxPid = 0UL;
                    ULONG linuxTid = 0UL;
                    status = kswordArkWslReadLinuxIdsFromCurrentThread(
                        &dynState.lxcoreOffsets,
                        &linuxPid,
                        &linuxTid);
                    response->linuxPidStatus = status;
                    response->linuxTidStatus = status;
                    if (NT_SUCCESS(status)) {
                        response->linuxProcessId = linuxPid;
                        response->linuxThreadId = linuxTid;
                        response->fieldFlags |=
                            KSWORD_ARK_WSL_FIELD_LINUX_PID_PRESENT |
                            KSWORD_ARK_WSL_FIELD_LINUX_TID_PRESENT;
                    }
                }
            }
            else {
                response->linuxPidStatus = STATUS_NOT_SUPPORTED;
                response->linuxTidStatus = STATUS_NOT_SUPPORTED;
            }
        }
    }

    if (threadObject != NULL) {
        ObDereferenceObject(threadObject);
    }
    if (processObject != NULL) {
        ObDereferenceObject(processObject);
    }

    if ((response->fieldFlags & KSWORD_ARK_WSL_FIELD_LXCORE_PRESENT) == 0UL) {
        response->queryStatus = KSWORD_ARK_WSL_QUERY_STATUS_WSL_NOT_LOADED;
    }
    else if ((response->fieldFlags & KSWORD_ARK_WSL_FIELD_LXCORE_DYNDATA_ACTIVE) == 0UL) {
        // Public subsystem and silo projections remain useful without lxcore
        // private offsets.  Report a real partial result instead of making the
        // complete feature look unavailable merely because Linux IDs cannot
        // be decoded on this build.
        response->queryStatus =
            (response->fieldFlags &
                (KSWORD_ARK_WSL_FIELD_PROCESS_SUBSYSTEM_PRESENT |
                 KSWORD_ARK_WSL_FIELD_THREAD_SUBSYSTEM_PRESENT |
                 KSWORD_ARK_WSL_FIELD_SILO_ROUTINES_PRESENT)) != 0UL
            ? KSWORD_ARK_WSL_QUERY_STATUS_PARTIAL
            : KSWORD_ARK_WSL_QUERY_STATUS_DYNDATA_MISSING;
    }
    else if ((response->fieldFlags & (KSWORD_ARK_WSL_FIELD_LINUX_PID_PRESENT | KSWORD_ARK_WSL_FIELD_LINUX_TID_PRESENT)) != 0UL) {
        response->queryStatus = KSWORD_ARK_WSL_QUERY_STATUS_OK;
    }
    else if ((request->threadId != 0UL) &&
        (response->fieldFlags & KSWORD_ARK_WSL_FIELD_CURRENT_THREAD_CONTEXT) == 0UL) {
        response->queryStatus = KSWORD_ARK_WSL_QUERY_STATUS_NOT_CURRENT_THREAD;
    }
    else if (processSubsystem != KSWORD_ARK_WSL_SUBSYSTEM_WSL &&
        threadSubsystem != KSWORD_ARK_WSL_SUBSYSTEM_WSL) {
        response->queryStatus = KSWORD_ARK_WSL_QUERY_STATUS_NOT_WSL_SUBSYSTEM;
    }
    else {
        response->queryStatus = KSWORD_ARK_WSL_QUERY_STATUS_PARTIAL;
    }

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
