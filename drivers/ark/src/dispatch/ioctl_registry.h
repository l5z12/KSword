#pragma once

#include <ntddk.h>
#include <wdf.h>

EXTERN_C_START

// Describes one isolated IOCTL implementation. The handler receives the WDF
// device/request, raw input/output byte counts, and writes the completion size.
typedef NTSTATUS
(*KswordArkIoctlHandler)(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

// Registry row consumed by ioctl_dispatch.c. Name is for trace/log text, while
// RequiredCapability stores a KSW_CAP_* dependency used for Phase 1 fail-closed
// gating before dispatching private-offset features.
typedef struct KswordArkIoctlEntry
{
    ULONG ioControlCode;
    KswordArkIoctlHandler handler;
    const char* name;
    ULONG64 requiredCapability;
    ULONG flags;
} KswordArkIoctlEntry;

#define KSWORD_ARK_IOCTL_FLAG_NONE 0x00000000UL
// Note: Set this bit for high-frequency query-type IOCTLs; the dispatch layer logs completion only on failure or rejection.
#define KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS 0x00000001UL
// Optional best-effort IOCTLs may set this bit; both success and failure completions skip the general R0 log.
#define KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION 0x00000002UL
// Only for scan-type IOCTLs: If the process exits after the snapshot, STATUS_INVALID_CID is returned; the dispatch layer does not log this as an error.
#define KSWORD_ARK_IOCTL_FLAG_QUIET_INVALID_CID 0x00000004UL
#define KSWORD_ARK_IOCTL_CAPABILITY_NONE 0ULL

_Must_inspect_result_
const KswordArkIoctlEntry*
kswordArkLookupIoctlEntry(
    _In_ ULONG ioControlCode
    );

ULONG
kswordArkGetRegisteredIoctlCount(
    VOID
    );

ULONG
kswordArkGetDuplicateIoctlCount(
    VOID
    );

// Note: Return registry entries by stable index for read-only diagnostic IOCTLs.
_Must_inspect_result_
const KswordArkIoctlEntry*
kswordArkGetIoctlEntryByIndex(
    _In_ ULONG index
    );

EXTERN_C_END
