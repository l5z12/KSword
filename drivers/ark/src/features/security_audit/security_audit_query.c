/*++
Module Name:
    security_audit_query.c
Abstract:
    Read-only Security/CI/VBS/SKCI/Hyper-V/AppControl posture queries.
Environment:
    Kernel-mode Driver Framework
--*/
#include "ark/ark_driver.h"
#include "security_audit_internal.h"
#include <ntstrsafe.h>
#if defined(_M_IX86) || defined(_M_X64)
#include <intrin.h>
#endif
#define KSWORD_ARK_SECURITY_AUDIT_SYSTEM_MODULE_INFORMATION 11UL
#define KSWORD_ARK_SECURITY_AUDIT_SYSTEM_CODEINTEGRITY_INFORMATION 103UL
#define KSWORD_ARK_SECURITY_AUDIT_SYSTEM_SECUREBOOT_INFORMATION 145UL
#define KSWORD_ARK_SECURITY_AUDIT_POOL_TAG 'aSsK'
typedef struct KswordSecurityAuditSystemCodeintegrityInformation
{
    ULONG length;
    ULONG codeIntegrityOptions;
} KswordSecurityAuditSystemCodeintegrityInformation;
typedef struct KswordSecurityAuditSystemSecurebootInformation
{
    BOOLEAN secureBootEnabled;
    BOOLEAN secureBootCapable;
} KswordSecurityAuditSystemSecurebootInformation;
typedef struct KswordSecurityAuditSystemModuleEntry
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
} KswordSecurityAuditSystemModuleEntry, *PkswordSecurityAuditSystemModuleEntry;
typedef struct KswordSecurityAuditSystemModuleInformation
{
    ULONG numberOfModules;
    KswordSecurityAuditSystemModuleEntry modules[1];
} KswordSecurityAuditSystemModuleInformation, *PkswordSecurityAuditSystemModuleInformation;
typedef UCHAR KswordSecurityAuditSeSigningLevel;
typedef KswordSecurityAuditSeSigningLevel* PkswordSecurityAuditSeSigningLevel;
typedef NTSTATUS
(NTAPI* KswordSecurityAuditSeGetCachedSigningLevelFn)(
    _In_ PFILE_OBJECT fileObject,
    _Out_ PULONG flags,
    _Out_ PkswordSecurityAuditSeSigningLevel signingLevel,
    _Out_writes_bytes_to_opt_(*thumbprintSize, *thumbprintSize) PUCHAR thumbprint,
    _Inout_opt_ PULONG thumbprintSize,
    _Out_opt_ PULONG thumbprintAlgorithm
    );
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );
static volatile LONG gKswordSecurityAuditSigningResolverDone = 0;
static KswordSecurityAuditSeGetCachedSigningLevelFn gKswordSecurityAuditSeGetCachedSigningLevel = NULL;
static PVOID
kswordSecurityAuditAllocate(
    _In_ SIZE_T bytes
    )
/*++
Routine Description:
    Allocate nonpaged temporary memory for bounded security audit snapshots.
Arguments:
    Bytes - Requested byte count.
Return Value:
    Nonpaged pool pointer, or NULL on allocation failure.
--*/
{
    if (bytes == 0U) {
        return NULL;
    }
#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bytes, KSWORD_ARK_SECURITY_AUDIT_POOL_TAG);
#pragma warning(pop)
}
static VOID
kswordSecurityAuditFree(
    _In_opt_ PVOID buffer
    )
/*++
Routine Description:
    Free a buffer allocated by kswordSecurityAuditAllocate.
Arguments:
    Buffer - Optional pool pointer.
Return Value:
    None. The function only releases memory when Buffer is non-NULL.
--*/
{
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, KSWORD_ARK_SECURITY_AUDIT_POOL_TAG);
    }
}
static CHAR
kswordSecurityAuditAsciiLower(
    _In_ CHAR character
    )
/*++
Routine Description:
    Convert one ASCII character to lowercase without locale dependencies.
Arguments:
    Character - Input character.
Return Value:
    Lowercase ASCII character, or the original value for non-uppercase bytes.
--*/
{
    if (character >= 'A' && character <= 'Z') {
        return (CHAR)(character + ('a' - 'A'));
    }
    return character;
}
static ULONG
kswordSecurityAuditBoundedAnsiLength(
    _In_reads_bytes_(maximumBytes) const UCHAR* text,
    _In_ ULONG maximumBytes
    )
/*++
Routine Description:
    Measure a bounded ANSI string from SystemModuleInformation.
Arguments:
    Text - Bounded ANSI text buffer.
    MaximumBytes - Maximum readable byte count.
Return Value:
    Number of bytes before NUL or MaximumBytes.
--*/
{
    ULONG index = 0UL;
    if (text == NULL || maximumBytes == 0UL) {
        return 0UL;
    }
    for (index = 0UL; index < maximumBytes; ++index) {
        if (text[index] == 0U) {
            break;
        }
    }
    return index;
}
static BOOLEAN
kswordSecurityAuditBoundedAnsiEquals(
    _In_reads_bytes_(leftBytes) const UCHAR* leftText,
    _In_ ULONG leftBytes,
    _In_z_ PCSTR rightText
    )
/*++
Routine Description:
    Compare a bounded module basename with a NUL-terminated ASCII name.
Arguments:
    LeftText - Bounded ANSI text from SystemModuleInformation.
    LeftBytes - Maximum readable bytes for LeftText.
    RightText - Expected module basename.
Return Value:
    TRUE when the bounded left string equals RightText case-insensitively.
--*/
{
    ULONG index = 0UL;
    if (leftText == NULL || leftBytes == 0UL || rightText == NULL) {
        return FALSE;
    }
    for (index = 0UL; index < leftBytes; ++index) {
        const CHAR kLeftCharacter = (CHAR)leftText[index];
        const CHAR kRightCharacter = rightText[index];
        if (kRightCharacter == '\0') {
            return (kLeftCharacter == '\0') ? TRUE : FALSE;
        }
        if (kLeftCharacter == '\0') {
            return FALSE;
        }
        if (kswordSecurityAuditAsciiLower(kLeftCharacter) != kswordSecurityAuditAsciiLower(kRightCharacter)) {
            return FALSE;
        }
    }
    return (rightText[index] == '\0') ? TRUE : FALSE;
}
static const UCHAR*
kswordSecurityAuditModuleFileName(
    _In_ const KswordSecurityAuditSystemModuleEntry* moduleEntry,
    _Out_ ULONG* fileNameBytesOut
    )
/*++
Routine Description:
    Return the bounded filename portion of a SystemModuleInformation row.
Arguments:
    ModuleEntry - Module row supplied by the kernel.
    FileNameBytesOut - Receives the readable byte count for the returned pointer.
Return Value:
    Pointer into ModuleEntry->FullPathName; never points outside the fixed array.
--*/
{
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;
    if (fileNameBytesOut != NULL) {
        *fileNameBytesOut = 0UL;
    }
    if (moduleEntry == NULL || fileNameBytesOut == NULL) {
        return NULL;
    }
    fileName = moduleEntry->fullPathName;
    fileNameBytes = sizeof(moduleEntry->fullPathName);
    if (moduleEntry->offsetToFileName < sizeof(moduleEntry->fullPathName)) {
        fileName = moduleEntry->fullPathName + moduleEntry->offsetToFileName;
        fileNameBytes = (ULONG)(sizeof(moduleEntry->fullPathName) - moduleEntry->offsetToFileName);
    }
    *fileNameBytesOut = fileNameBytes;
    return fileName;
}
static VOID
kswordSecurityAuditCopyAnsiNameToWide(
    _Out_writes_(destinationChars) PWSTR destination,
    _In_ USHORT destinationChars,
    _In_reads_bytes_(sourceBytes) const UCHAR* source,
    _In_ ULONG sourceBytes
    )
/*++
Routine Description:
    Copy a bounded ANSI module name to a fixed WCHAR protocol field.
Arguments:
    Destination - Fixed WCHAR output field.
    DestinationChars - Capacity of Destination in WCHARs.
    Source - Bounded ANSI source text.
    SourceBytes - Maximum readable bytes in Source.
Return Value:
    None. The destination is always NUL-terminated when capacity is nonzero.
--*/
{
    USHORT index = 0U;
    USHORT maxCopy = 0U;
    if (destination == NULL || destinationChars == 0U) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL || sourceBytes == 0UL) {
        return;
    }
    maxCopy = (USHORT)((sourceBytes < (ULONG)(destinationChars - 1U)) ? sourceBytes : (ULONG)(destinationChars - 1U));
    for (index = 0U; index < maxCopy; ++index) {
        const UCHAR kSourceByte = source[index];
        if (kSourceByte == 0U) {
            break;
        }
        destination[index] = (WCHAR)kSourceByte;
    }
    destination[index] = L'\0';
}
static ULONG
kswordSecurityAuditHashAnsiPath(
    _In_reads_bytes_(sourceBytes) const UCHAR* source,
    _In_ ULONG sourceBytes
    )
/*++
Routine Description:
    Compute a bounded FNV-1a hash for a module path without returning full paths.
Arguments:
    Source - Bounded ANSI source path.
    SourceBytes - Maximum readable bytes in Source.
Return Value:
    32-bit hash value; zero when Source is absent.
--*/
{
    ULONG hashValue = 2166136261UL;
    ULONG index = 0UL;
    if (source == NULL || sourceBytes == 0UL) {
        return 0UL;
    }
    for (index = 0UL; index < sourceBytes; ++index) {
        UCHAR sourceByte = source[index];
        if (sourceByte == 0U) {
            break;
        }
        if (sourceByte >= 'A' && sourceByte <= 'Z') {
            sourceByte = (UCHAR)(sourceByte + ('a' - 'A'));
        }
        hashValue ^= (ULONG)sourceByte;
        hashValue *= 16777619UL;
    }
    return hashValue;
}
static NTSTATUS
kswordSecurityAuditQueryModuleSnapshot(
    _Outptr_result_bytebuffer_(*snapshotBytesOut) PkswordSecurityAuditSystemModuleInformation* snapshotOut,
    _Out_ ULONG* snapshotBytesOut
    )
/*++
Routine Description:
    Query SystemModuleInformation into a bounded nonpaged snapshot.
Arguments:
    SnapshotOut - Receives the allocated module snapshot.
    SnapshotBytesOut - Receives the allocated byte count.
Return Value:
    STATUS_SUCCESS with a snapshot, or the query/allocation failure status.
--*/
{
    PkswordSecurityAuditSystemModuleInformation snapshot = NULL;
    ULONG requiredBytes = 0UL;
    ULONG queryBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    if (snapshotOut == NULL || snapshotBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *snapshotOut = NULL;
    *snapshotBytesOut = 0UL;
    status = ZwQuerySystemInformation(
        KSWORD_ARK_SECURITY_AUDIT_SYSTEM_MODULE_INFORMATION,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }
    queryBytes = requiredBytes + (64UL * 1024UL);
    snapshot = (PkswordSecurityAuditSystemModuleInformation)kswordSecurityAuditAllocate(queryBytes);
    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = ZwQuerySystemInformation(
        KSWORD_ARK_SECURITY_AUDIT_SYSTEM_MODULE_INFORMATION,
        snapshot,
        queryBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        kswordSecurityAuditFree(snapshot);
        return status;
    }
    *snapshotOut = snapshot;
    *snapshotBytesOut = queryBytes;
    return STATUS_SUCCESS;
}
static const KswordSecurityAuditSystemModuleEntry*
kswordSecurityAuditFindModuleByName(
    _In_opt_ const KswordSecurityAuditSystemModuleInformation* snapshot,
    _In_z_ PCSTR moduleName
    )
/*++
Routine Description:
    Find a loaded module by basename in a SystemModuleInformation snapshot.
Arguments:
    Snapshot - Optional module snapshot.
    ModuleName - Expected module basename, for example ci.dll or vmbus.sys.
Return Value:
    Matching module row, or NULL when absent.
--*/
{
    ULONG index = 0UL;
    if (snapshot == NULL || moduleName == NULL) {
        return NULL;
    }
    for (index = 0UL; index < snapshot->numberOfModules; ++index) {
        const KswordSecurityAuditSystemModuleEntry* entry = &snapshot->modules[index];
        ULONG fileNameBytes = 0UL;
        const UCHAR* fileName = kswordSecurityAuditModuleFileName(entry, &fileNameBytes);
        if (kswordSecurityAuditBoundedAnsiEquals(fileName, fileNameBytes, moduleName)) {
            return entry;
        }
    }
    return NULL;
}
static ULONG
kswordSecurityAuditModuleState(
    _In_opt_ const KswordSecurityAuditSystemModuleInformation* snapshot,
    _In_z_ PCSTR moduleName
    )
/*++
Routine Description:
    Convert module-list presence into a protocol state value.
Arguments:
    Snapshot - Optional module snapshot.
    ModuleName - Module basename to search.
    PRESENT when loaded, ABSENT when the snapshot exists but no row matches.
--*/
{
    if (snapshot == NULL) {
        return KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
    }
    return (kswordSecurityAuditFindModuleByName(snapshot, moduleName) != NULL) ?
        KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT :
        KSWORD_ARK_SECURITY_AUDIT_STATE_ABSENT;
}
static KswordSecurityAuditSeGetCachedSigningLevelFn
kswordSecurityAuditResolveSigningLevelRoutine(
    VOID
    )
/*++
Routine Description:
    Resolve SeGetCachedSigningLevel dynamically for optional read-only trust rows.
Arguments:
    None.
    Function pointer when exported; NULL when unavailable.
--*/
{
    if (InterlockedCompareExchange(&gKswordSecurityAuditSigningResolverDone, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"SeGetCachedSigningLevel");
        gKswordSecurityAuditSeGetCachedSigningLevel =
            (KswordSecurityAuditSeGetCachedSigningLevelFn)MmGetSystemRoutineAddress(&routineName);
    }
    return gKswordSecurityAuditSeGetCachedSigningLevel;
}
static NTSTATUS
kswordSecurityAuditOpenModulePath(
    _In_reads_bytes_(pathBytes) const UCHAR* pathText,
    _In_ ULONG pathBytes,
    _Out_ HANDLE* fileHandleOut
    )
/*++
Routine Description:
    Open a loaded-module path for metadata-only cached signing level lookup.
Arguments:
    PathText - Bounded ANSI module path from SystemModuleInformation.
    PathBytes - Maximum readable bytes in PathText.
    FileHandleOut - Receives a kernel file handle on success.
    ZwCreateFile status or conversion failure status.
--*/
{
    ANSI_STRING ansiPath;
    UNICODE_STRING unicodePath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    ULONG pathLength = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    if (fileHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileHandleOut = NULL;
    if (pathText == NULL || pathBytes == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    pathLength = kswordSecurityAuditBoundedAnsiLength(pathText, pathBytes);
    if (pathLength == 0UL || pathLength > 255UL) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    RtlZeroMemory(&ansiPath, sizeof(ansiPath));
    ansiPath.Buffer = (PCHAR)pathText;
    ansiPath.Length = (USHORT)pathLength;
    ansiPath.MaximumLength = (USHORT)pathLength;
    RtlZeroMemory(&unicodePath, sizeof(unicodePath));
    status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        fileHandleOut,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0U);
    RtlFreeUnicodeString(&unicodePath);
    return status;
}
static NTSTATUS
kswordSecurityAuditQueryModuleSigningLevel(
    _In_ const KswordSecurityAuditSystemModuleEntry* moduleEntry,
    _Out_ ULONG* signingLevelOut,
    _Out_ ULONG* signingFlagsOut
    )
/*++
Routine Description:
    Query cached signing level for one loaded module by opening its image path read-only.
Arguments:
    ModuleEntry - Loaded module row.
    SigningLevelOut - Receives the signing level value.
    SigningFlagsOut - Receives signing flags returned by the kernel cache.
    STATUS_SUCCESS when signing level was obtained; otherwise a non-mutating failure status.
--*/
{
    KswordSecurityAuditSeGetCachedSigningLevelFn signingRoutine = NULL;
    KswordSecurityAuditSeSigningLevel signingLevel = KSWORD_ARK_SIGNING_LEVEL_UNCHECKED;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    UCHAR thumbprint[KSWORD_ARK_TRUST_THUMBPRINT_MAX_BYTES] = { 0 };
    ULONG thumbprintSize = sizeof(thumbprint);
    ULONG thumbprintAlgorithm = 0UL;
    ULONG signingFlags = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    if (signingLevelOut == NULL || signingFlagsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *signingLevelOut = KSWORD_ARK_SIGNING_LEVEL_UNCHECKED;
    *signingFlagsOut = 0UL;
    if (moduleEntry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    signingRoutine = kswordSecurityAuditResolveSigningLevelRoutine();
    if (signingRoutine == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = kswordSecurityAuditOpenModulePath(
        moduleEntry->fullPathName,
        sizeof(moduleEntry->fullPathName),
        &fileHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ObReferenceObjectByHandle(
        fileHandle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&fileObject,
        NULL);
    if (NT_SUCCESS(status)) {
        status = signingRoutine(
            fileObject,
            &signingFlags,
            &signingLevel,
            thumbprint,
            &thumbprintSize,
            &thumbprintAlgorithm);
        ObDereferenceObject(fileObject);
    }
    ZwClose(fileHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    *signingLevelOut = (ULONG)signingLevel;
    *signingFlagsOut = signingFlags;
    return STATUS_SUCCESS;
}
static BOOLEAN
kswordSecurityAuditReadBooleanRoutineAddress(
    _In_z_ PCWSTR nameText,
    _Out_ ULONG* valueOut
    )
/*++
Routine Description:
    Resolve and read an exported BOOLEAN variable when the kernel exposes it.
Arguments:
    NameText - Exported symbol name.
    ValueOut - Receives 0 or 1 when the symbol is readable.
    TRUE when a value was read; FALSE when the export is unavailable.
--*/
{
    UNICODE_STRING routineName;
    volatile BOOLEAN* valuePointer = NULL;
    if (nameText == NULL || valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0UL;
    RtlInitUnicodeString(&routineName, nameText);
    valuePointer = (volatile BOOLEAN*)MmGetSystemRoutineAddress(&routineName);
    if (valuePointer == NULL) {
        return FALSE;
    }
    *valueOut = (*valuePointer != FALSE) ? 1UL : 0UL;
    return TRUE;
}
static VOID
kswordSecurityAuditFillCpuidHypervisor(
    _Inout_ KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE* response
    )
/*++
Routine Description:
    Use CPUID on x86/x64 to detect hypervisor presence and vendor string.
Arguments:
    Response - Hyper-V summary response to update.
    None. Non-x86 architectures are left unavailable by design.
--*/
{
#if defined(_M_IX86) || defined(_M_X64)
    int cpuInfo[4] = { 0, 0, 0, 0 };
    CHAR vendorText[13] = { 0 };
    ULONG index = 0UL;
    if (response == NULL) {
        return;
    }
    __cpuid(cpuInfo, 1);
    response->hypervisorPresent = ((cpuInfo[2] & 0x80000000) != 0) ?
        KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT :
        KSWORD_ARK_SECURITY_AUDIT_STATE_ABSENT;
    response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_CPUID;
    if (response->hypervisorPresent == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT) {
        __cpuid(cpuInfo, 0x40000000);
        RtlCopyMemory(&vendorText[0], &cpuInfo[1], sizeof(int));
        RtlCopyMemory(&vendorText[4], &cpuInfo[2], sizeof(int));
        RtlCopyMemory(&vendorText[8], &cpuInfo[3], sizeof(int));
        vendorText[12] = '\0';
        for (index = 0UL; index < (KSWORD_ARK_SECURITY_AUDIT_VENDOR_CHARS - 1U) && vendorText[index] != '\0'; ++index) {
            response->hypervisorVendor[index] = (WCHAR)vendorText[index];
        }
        response->hypervisorVendor[index] = L'\0';
    }
#else
    if (Response != NULL) {
        Response->hypervisorPresent = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
    }
#endif
}
NTSTATUS
kswordArkSecurityAuditQuerySecurityStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Query CI/VBS/Secure Kernel/SKCI/test-signing/debug posture through read-only sources.
Arguments:
    OutputBuffer - METHOD_BUFFERED output memory.
    OutputBufferLength - Output buffer byte count.
    BytesWrittenOut - Receives the fixed response size.
    STATUS_SUCCESS when the response was populated; buffer/IRQL errors otherwise.
--*/
{
    KSWORD_ARK_QUERY_SECURITY_STATUS_RESPONSE* response = NULL;
    KswordSecurityAuditSystemCodeintegrityInformation ciInformation;
    KswordSecurityAuditSystemSecurebootInformation secureBootInformation;
    PkswordSecurityAuditSystemModuleInformation moduleSnapshot = NULL;
    ULONG moduleSnapshotBytes = 0UL;
    ULONG kdEnabled = 0UL;
    ULONG kdNotPresent = 0UL;
    NTSTATUS moduleStatus = STATUS_SUCCESS;
    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_SECURITY_STATUS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_SECURITY_STATUS_RESPONSE*)outputBuffer;
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = STATUS_SUCCESS;
    response->ciModuleLoaded = KSWORD_ARK_SECURITY_AUDIT_STATE_UNKNOWN;
    response->secureKernelModuleLoaded = KSWORD_ARK_SECURITY_AUDIT_STATE_UNKNOWN;
    response->skciModuleLoaded = KSWORD_ARK_SECURITY_AUDIT_STATE_UNKNOWN;
    response->debuggerStatus = STATUS_NOT_SUPPORTED;
    RtlZeroMemory(&ciInformation, sizeof(ciInformation));
    ciInformation.length = sizeof(ciInformation);
    response->codeIntegrityStatus = ZwQuerySystemInformation(
        KSWORD_ARK_SECURITY_AUDIT_SYSTEM_CODEINTEGRITY_INFORMATION,
        &ciInformation,
        sizeof(ciInformation),
        NULL);
    if (NT_SUCCESS(response->codeIntegrityStatus)) {
        response->codeIntegrityOptions = ciInformation.codeIntegrityOptions;
        response->ciEnabled = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_ENABLED) != 0UL) ? 1UL : 0UL;
        response->umciEnabled = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_UMCI_ENABLED) != 0UL) ? 1UL : 0UL;
        response->hvciKmciEnabled = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0UL) ? 1UL : 0UL;
        response->hvciAuditMode = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE) != 0UL) ? 1UL : 0UL;
        response->hvciStrictMode = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE) != 0UL) ? 1UL : 0UL;
        response->hvciIumEnabled = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) != 0UL) ? 1UL : 0UL;
        response->testSigningEnabled = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_TESTSIGN) != 0UL) ? 1UL : 0UL;
        response->ciDebugModeEnabled = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) != 0UL) ? 1UL : 0UL;
        response->testBuild = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_TEST_BUILD) != 0UL) ? 1UL : 0UL;
        response->flightBuild = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_FLIGHT_BUILD) != 0UL) ? 1UL : 0UL;
        response->flightingEnabled = ((ciInformation.codeIntegrityOptions & KSWORD_ARK_CODEINTEGRITY_OPTION_FLIGHTING_ENABLED) != 0UL) ? 1UL : 0UL;
        response->fieldFlags |= KSWORD_ARK_SECURITY_STATUS_FIELD_CI_OPTIONS | KSWORD_ARK_SECURITY_STATUS_FIELD_CI_FLAGS | KSWORD_ARK_SECURITY_STATUS_FIELD_VBS_HVCI;
        response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_SYSTEM_QUERY;
    }
    RtlZeroMemory(&secureBootInformation, sizeof(secureBootInformation));
    response->secureBootStatus = ZwQuerySystemInformation(
        KSWORD_ARK_SECURITY_AUDIT_SYSTEM_SECUREBOOT_INFORMATION,
        &secureBootInformation,
        sizeof(secureBootInformation),
        NULL);
    if (NT_SUCCESS(response->secureBootStatus)) {
        response->secureBootEnabled = (secureBootInformation.secureBootEnabled != FALSE) ? 1UL : 0UL;
        response->secureBootCapable = (secureBootInformation.secureBootCapable != FALSE) ? 1UL : 0UL;
        response->fieldFlags |= KSWORD_ARK_SECURITY_STATUS_FIELD_SECURE_BOOT;
        response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_SYSTEM_QUERY;
    }
    if (kswordSecurityAuditReadBooleanRoutineAddress(L"KdDebuggerEnabled", &kdEnabled) &&
        kswordSecurityAuditReadBooleanRoutineAddress(L"KdDebuggerNotPresent", &kdNotPresent)) {
        response->kernelDebuggerEnabled = kdEnabled;
        response->kernelDebuggerNotPresent = kdNotPresent;
        response->debuggerStatus = STATUS_SUCCESS;
        response->fieldFlags |= KSWORD_ARK_SECURITY_STATUS_FIELD_KD_FLAGS;
        response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_EXPORT;
    }
    moduleStatus = kswordSecurityAuditQueryModuleSnapshot(&moduleSnapshot, &moduleSnapshotBytes);
    response->moduleQueryStatus = moduleStatus;
    if (NT_SUCCESS(moduleStatus)) {
        response->ciModuleLoaded = kswordSecurityAuditModuleState(moduleSnapshot, "ci.dll");
        if (response->ciModuleLoaded == KSWORD_ARK_SECURITY_AUDIT_STATE_ABSENT) {
            response->ciModuleLoaded = kswordSecurityAuditModuleState(moduleSnapshot, "ci.sys");
        }
        response->secureKernelModuleLoaded = kswordSecurityAuditModuleState(moduleSnapshot, "securekernel.exe");
        response->skciModuleLoaded = kswordSecurityAuditModuleState(moduleSnapshot, "skci.dll");
        if (response->skciModuleLoaded == KSWORD_ARK_SECURITY_AUDIT_STATE_ABSENT) {
            response->skciModuleLoaded = kswordSecurityAuditModuleState(moduleSnapshot, "skci.sys");
        }
        response->vbsPresent = (response->secureKernelModuleLoaded == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT ||
            response->skciModuleLoaded == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT ||
            response->hvciKmciEnabled != 0UL ||
            response->hvciIumEnabled != 0UL) ? 1UL : 0UL;
        response->fieldFlags |= KSWORD_ARK_SECURITY_STATUS_FIELD_CI_MODULE | KSWORD_ARK_SECURITY_STATUS_FIELD_SECUREKERNEL | KSWORD_ARK_SECURITY_STATUS_FIELD_SKCI;
        response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_MODULE_LIST;
    }
    kswordSecurityAuditFree(moduleSnapshot);
    UNREFERENCED_PARAMETER(moduleSnapshotBytes);
    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
NTSTATUS
kswordArkSecurityAuditQueryDriverTrustView(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Build a bounded loaded-driver trust cross-view from module list and signing cache.
Arguments:
    OutputBuffer - METHOD_BUFFERED output memory.
    OutputBufferLength - Output buffer byte count.
    Request - Optional caller request; NULL selects default row count and flags.
    BytesWrittenOut - Receives the actual response byte count.
    STATUS_SUCCESS with a possibly degraded response, or a buffer/IRQL error.
--*/
{
    KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE* response = NULL;
    PkswordSecurityAuditSystemModuleInformation moduleSnapshot = NULL;
    ULONG moduleSnapshotBytes = 0UL;
    ULONG requestFlags = KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_DEFAULT;
    ULONG maxEntries = KSWORD_ARK_SECURITY_AUDIT_DEFAULT_DRIVER_ROWS;
    ULONG writableEntries = 0UL;
    ULONG index = 0UL;
    size_t minimumBytes = FIELD_OFFSET(KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE, entries);
    NTSTATUS status = STATUS_SUCCESS;
    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < minimumBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (request != NULL) {
        requestFlags = (request->flags == 0UL) ? KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_DEFAULT : request->flags;
        maxEntries = (request->maxEntries == 0UL) ? KSWORD_ARK_SECURITY_AUDIT_DEFAULT_DRIVER_ROWS : request->maxEntries;
    }
    if ((requestFlags & ~KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_INCLUDE_SIGNING_LEVEL) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (maxEntries > KSWORD_ARK_SECURITY_AUDIT_MAX_DRIVER_ROWS) {
        maxEntries = KSWORD_ARK_SECURITY_AUDIT_MAX_DRIVER_ROWS;
    }
    writableEntries = (ULONG)((outputBufferLength - minimumBytes) / sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY));
    if (writableEntries > maxEntries) {
        writableEntries = maxEntries;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE*)outputBuffer;
    response->size = (ULONG)minimumBytes;
    response->version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = STATUS_SUCCESS;
    response->maxEntriesAccepted = maxEntries;
    response->signingResolverStatus = (kswordSecurityAuditResolveSigningLevelRoutine() != NULL) ? STATUS_SUCCESS : STATUS_PROCEDURE_NOT_FOUND;
    status = kswordSecurityAuditQueryModuleSnapshot(&moduleSnapshot, &moduleSnapshotBytes);
    response->moduleQueryStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = status;
        *bytesWrittenOut = minimumBytes;
        return STATUS_SUCCESS;
    }
    response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_MODULE_LIST;
    response->totalModuleCount = moduleSnapshot->numberOfModules;
    response->truncated = (moduleSnapshot->numberOfModules > writableEntries) ? 1UL : 0UL;
    for (index = 0UL; index < moduleSnapshot->numberOfModules && response->entryCount < writableEntries; ++index) {
        const KswordSecurityAuditSystemModuleEntry* moduleEntry = &moduleSnapshot->modules[index];
        KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY* outputEntry = &response->entries[response->entryCount];
        ULONG fileNameBytes = 0UL;
        const UCHAR* fileName = kswordSecurityAuditModuleFileName(moduleEntry, &fileNameBytes);
        outputEntry->size = sizeof(*outputEntry);
        outputEntry->sourceMask = KSWORD_ARK_SECURITY_AUDIT_SOURCE_MODULE_LIST;
        outputEntry->sourceCount = 1UL;
        outputEntry->imageBase = (ULONG64)(ULONG_PTR)moduleEntry->imageBase;
        outputEntry->imageSize = moduleEntry->imageSize;
        outputEntry->signingLevel = KSWORD_ARK_SIGNING_LEVEL_UNCHECKED;
        outputEntry->signingStatus = STATUS_NOT_SUPPORTED;
        outputEntry->fieldFlags |= KSWORD_ARK_DRIVER_TRUST_FLAG_SYSTEM_MODULE_PRESENT;
        if (moduleEntry->imageBase == NULL || moduleEntry->imageSize == 0UL) {
            outputEntry->conflictFlags |= KSWORD_ARK_DRIVER_TRUST_CONFLICT_EMPTY_IMAGE_RANGE;
        }
        if (kswordSecurityAuditBoundedAnsiLength(moduleEntry->fullPathName, sizeof(moduleEntry->fullPathName)) == 0UL) {
            outputEntry->conflictFlags |= KSWORD_ARK_DRIVER_TRUST_CONFLICT_PATH_UNAVAILABLE;
        }
        else {
            outputEntry->pathHash = kswordSecurityAuditHashAnsiPath(moduleEntry->fullPathName, sizeof(moduleEntry->fullPathName));
            outputEntry->fieldFlags |= KSWORD_ARK_DRIVER_TRUST_FLAG_PATH_HASH_PRESENT;
        }
        kswordSecurityAuditCopyAnsiNameToWide(
            outputEntry->moduleName,
            KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS,
            fileName,
            fileNameBytes);
        if (outputEntry->moduleName[0] != L'\0') {
            outputEntry->fieldFlags |= KSWORD_ARK_DRIVER_TRUST_FLAG_NAME_PRESENT;
        }
        if ((requestFlags & KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_INCLUDE_SIGNING_LEVEL) != 0UL) {
            outputEntry->signingStatus = kswordSecurityAuditQueryModuleSigningLevel(
                moduleEntry,
                &outputEntry->signingLevel,
                &outputEntry->signingLevelFlags);
            if (NT_SUCCESS(outputEntry->signingStatus)) {
                outputEntry->fieldFlags |= KSWORD_ARK_DRIVER_TRUST_FLAG_SIGNING_PRESENT;
                outputEntry->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_SIGNING_CACHE;
                outputEntry->sourceCount += 1UL;
                if (outputEntry->signingLevel == KSWORD_ARK_SIGNING_LEVEL_UNCHECKED ||
                    outputEntry->signingLevel == KSWORD_ARK_SIGNING_LEVEL_UNSIGNED) {
                    outputEntry->conflictFlags |= KSWORD_ARK_DRIVER_TRUST_CONFLICT_UNSIGNED_OR_UNKNOWN;
                }
            }
            else {
                outputEntry->conflictFlags |= KSWORD_ARK_DRIVER_TRUST_CONFLICT_SIGNING_UNAVAILABLE;
            }
        }
        response->entryCount += 1UL;
    }
    response->fieldFlags = KSWORD_ARK_DRIVER_TRUST_FLAG_SYSTEM_MODULE_PRESENT;
    if ((requestFlags & KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_INCLUDE_SIGNING_LEVEL) != 0UL) {
        response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_SIGNING_CACHE;
    }
    response->size = (ULONG)(minimumBytes + ((size_t)response->entryCount * sizeof(KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY)));
    *bytesWrittenOut = response->size;
    kswordSecurityAuditFree(moduleSnapshot);
    UNREFERENCED_PARAMETER(moduleSnapshotBytes);
    return STATUS_SUCCESS;
}
NTSTATUS
kswordArkSecurityAuditQueryHyperVSummary(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Query read-only Hyper-V availability and module-backed status skeleton.
Arguments:
    OutputBuffer - METHOD_BUFFERED output memory.
    OutputBufferLength - Output buffer byte count.
    BytesWrittenOut - Receives the fixed response size.
    STATUS_SUCCESS when the response was populated; buffer/IRQL errors otherwise.
--*/
{
    KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE* response = NULL;
    PkswordSecurityAuditSystemModuleInformation moduleSnapshot = NULL;
    ULONG moduleSnapshotBytes = 0UL;
    NTSTATUS moduleStatus = STATUS_SUCCESS;
    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE*)outputBuffer;
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = STATUS_SUCCESS;
    response->hypervisorPresent = KSWORD_ARK_SECURITY_AUDIT_STATE_UNKNOWN;
    response->rootPartitionStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
    kswordSecurityAuditFillCpuidHypervisor(response);
    moduleStatus = kswordSecurityAuditQueryModuleSnapshot(&moduleSnapshot, &moduleSnapshotBytes);
    response->moduleQueryStatus = moduleStatus;
    if (NT_SUCCESS(moduleStatus)) {
        response->vmbusStatus = kswordSecurityAuditModuleState(moduleSnapshot, "vmbus.sys");
        response->vSwitchStatus = kswordSecurityAuditModuleState(moduleSnapshot, "vmswitch.sys");
        response->vPciStatus = kswordSecurityAuditModuleState(moduleSnapshot, "vpci.sys");
        response->hvSocketStatus = kswordSecurityAuditModuleState(moduleSnapshot, "hvsocket.sys");
        response->winHvStatus = kswordSecurityAuditModuleState(moduleSnapshot, "winhv.sys");
        response->winHvRuntimeStatus = kswordSecurityAuditModuleState(moduleSnapshot, "winhvr.sys");
        response->hvLoaderStatus = kswordSecurityAuditModuleState(moduleSnapshot, "hvloader.sys");
        response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_MODULE_LIST;
    }
    else {
        response->vmbusStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->vSwitchStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->vPciStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->hvSocketStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->winHvStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->winHvRuntimeStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->hvLoaderStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
    }
    response->fieldFlags = 0xFFFFFFFFUL;
    *bytesWrittenOut = sizeof(*response);
    kswordSecurityAuditFree(moduleSnapshot);
    UNREFERENCED_PARAMETER(moduleSnapshotBytes);
    return STATUS_SUCCESS;
}
NTSTATUS
kswordArkSecurityAuditQueryAppControlStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Query AppID/AppLocker/mssecflt presence and callback-owner skeleton read-only.
Arguments:
    OutputBuffer - METHOD_BUFFERED output memory.
    OutputBufferLength - Output buffer byte count.
    BytesWrittenOut - Receives the fixed response size.
    STATUS_SUCCESS when the response was populated; buffer/IRQL errors otherwise.
--*/
{
    KSWORD_ARK_QUERY_APP_CONTROL_STATUS_RESPONSE* response = NULL;
    PkswordSecurityAuditSystemModuleInformation moduleSnapshot = NULL;
    ULONG moduleSnapshotBytes = 0UL;
    NTSTATUS moduleStatus = STATUS_SUCCESS;
    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_APP_CONTROL_STATUS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_APP_CONTROL_STATUS_RESPONSE*)outputBuffer;
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION;
    response->queryStatus = STATUS_SUCCESS;
    response->appidPolicyStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
    moduleStatus = kswordSecurityAuditQueryModuleSnapshot(&moduleSnapshot, &moduleSnapshotBytes);
    response->moduleQueryStatus = moduleStatus;
    if (NT_SUCCESS(moduleStatus)) {
        response->appidStatus = kswordSecurityAuditModuleState(moduleSnapshot, "appid.sys");
        response->appLockerFilterStatus = kswordSecurityAuditModuleState(moduleSnapshot, "applockerfltr.sys");
        response->mssecfltStatus = kswordSecurityAuditModuleState(moduleSnapshot, "mssecflt.sys");
        response->ahcacheStatus = kswordSecurityAuditModuleState(moduleSnapshot, "ahcache.sys");
        response->bamStatus = kswordSecurityAuditModuleState(moduleSnapshot, "bam.sys");
        response->appLockerCallbackOwnerStatus = response->appLockerFilterStatus;
        response->mssecfltCallbackOwnerStatus = response->mssecfltStatus;
        if (response->appLockerFilterStatus == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT) {
            kswordSecurityAuditCopyAnsiNameToWide(
                response->appLockerOwnerModule,
                KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS,
                (const UCHAR*)"applockerfltr.sys",
                sizeof("applockerfltr.sys"));
        }
        if (response->mssecfltStatus == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT) {
            kswordSecurityAuditCopyAnsiNameToWide(
                response->mssecfltOwnerModule,
                KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS,
                (const UCHAR*)"mssecflt.sys",
                sizeof("mssecflt.sys"));
        }
        response->sourceMask |= KSWORD_ARK_SECURITY_AUDIT_SOURCE_MODULE_LIST;
    }
    else {
        response->appidStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->appLockerFilterStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->appLockerCallbackOwnerStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->mssecfltStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->mssecfltCallbackOwnerStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->ahcacheStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
        response->bamStatus = KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE;
    }
    response->fieldFlags = 0xFFFFFFFFUL;
    *bytesWrittenOut = sizeof(*response);
    kswordSecurityAuditFree(moduleSnapshot);
    UNREFERENCED_PARAMETER(moduleSnapshotBytes);
    return STATUS_SUCCESS;
}
