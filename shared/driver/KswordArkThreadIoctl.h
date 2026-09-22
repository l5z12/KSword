#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkThreadIoctl.h
// Purpose:
// - Define R3/R0 thread extension enumeration protocol.
// - The basic thread list can still be provided by R3 NtQuerySystemInformation;
// - KTHREAD stack boundaries and I/O counters are supplemented by this protocol according to the DynData capability.
// ============================================================

#define KSWORD_ARK_THREAD_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_ENUM_THREAD 0x80B
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_CROSSVIEW 0x837UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_DETAIL 0x83DUL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_RUNTIME_FIELDS 0x83FUL
#define KSWORD_ARK_IOCTL_FUNCTION_TERMINATE_THREAD 0x84FUL
#define KSWORD_ARK_IOCTL_FUNCTION_SET_THREAD_SUSPENDED 0x850UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_DRIVER_THREAD 0x851UL

#define IOCTL_KSWORD_ARK_ENUM_THREAD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ENUM_THREAD, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_CROSSVIEW, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

// Thread runtime detail protocol:
// - Input: Accepts only TID and optional PID filtering; R0 performs PsLookupThreadByThreadId internally.
// - Processing: Read-only sampling of Cid, linked list, start address, stack, and I/O count based on ETHREAD/KTHREAD PDB offset.
// - Output: fixed response packet, directly renderable into human-readable details by R3.
#define IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_DETAIL, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_RUNTIME_FIELDS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

// Specify the thread termination protocol:
// - Input: TID, associated PID, and thread exit status; R0 references objects solely by ID;
// - Processing: Verify that the ETHREAD still belongs to the requesting PID before terminating the specified thread.
// - Output: none; completion status is determined by the success or failure of DeviceIoControl and driver logs.
#define IOCTL_KSWORD_ARK_TERMINATE_THREAD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_TERMINATE_THREAD, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

typedef struct _KSWORD_ARK_TERMINATE_THREAD_REQUEST
{
    unsigned long threadId;
    unsigned long processId;
    long exitStatus;
    unsigned long reserved;
} KSWORD_ARK_TERMINATE_THREAD_REQUEST;

// Thread suspend/resume protocol specification:
// - Input: TID, owning PID, and action; R0 re-references ETHREAD and verifies ownership.
// - action: KSWORD_ARK_THREAD_SUSPEND_ACTION_SUSPEND or RESUME;
// - Output: None; the driver logs the suspend count before the operation.
#define IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_THREAD_SUSPENDED, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_THREAD_SUSPEND_ACTION_SUSPEND 1UL
#define KSWORD_ARK_THREAD_SUSPEND_ACTION_RESUME  2UL

typedef struct _KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST
{
    unsigned long threadId;
    unsigned long processId;
    unsigned long action;
    unsigned long reserved;
} KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST;

// Driver/System thread control protocol:
// - Accept only system threads with PID 4; R0 reads the actual start address and creation time itself;
// - Before executing dangerous actions, TID + StartAddress + CreateTime100ns must match precisely.
// - Reject requests where the ntoskrnl first module, current WDF driver instance, current IOCTL execution thread, or identity do not match;
// - terminate/suspend must carry UI_CONFIRMED; resume, as a recovery action, can be executed directly.
#define IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONTROL_DRIVER_THREAD, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND   1UL
#define KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME    2UL
#define KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE 3UL

#define KSWORD_ARK_DRIVER_THREAD_CONTROL_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_VALID_MASK \
    KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED

// terminateMethod is effective only during ACTION_TERMINATE. All backends are experimental:
// - PspTerminateThreadByPointer: undocumented; terminates the thread via the ETHREAD pointer.
// - Zw/NtTerminateThread: Request thread termination based on a kernel handle;
// - Normal APC: Call PsTerminateSystemThread on the target system thread at PASSIVE_LEVEL.
// - Special -> Normal APC: Special Kernel APC only queues the next segment at APC_LEVEL; the
//   final call to PsTerminateSystemThread is made by the Normal Kernel APC at PASSIVE_LEVEL.
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE                   0UL
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER         1UL
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT               2UL
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC             3UL
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC  4UL

typedef struct _KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long threadId;
    unsigned long action;
    unsigned long flags;
    unsigned long terminateMethod;
    unsigned long long expectedStartAddress;
    unsigned long long expectedCreateTime100ns;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST;

// Thread runtime field sample request:
// - Input: threadId to locate the ETHREAD; processId is for optional consistency context display only;
// - Processing: items are shared with the process protocol; do not accept object addresses passed from R3.
// - Return: Shared KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE.
typedef struct _KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long threadId;
    unsigned long processId;
    unsigned long itemCount;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long reserved2;
    KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST items[1];
} KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST;

#define KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_STACK    0x00000001UL
#define KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_IO       0x00000002UL
#define KSWORD_ARK_ENUM_THREAD_FLAG_SCAN_CID_TABLE   0x00000004UL
#define KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE 0x00000008UL
#define KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_STACK | \
     KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_IO | \
     KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE)

#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK 0x00000001UL
#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST 0x00000002UL
#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE   0x00000004UL
#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START      0x00000008UL
#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK | \
     KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST | \
     KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE | \
     KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START)

#define KSWORD_ARK_THREAD_FLAG_KERNEL_ENUMERATED                0x00000001UL
#define KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST   0x00000002UL
#define KSWORD_ARK_THREAD_FLAG_OWNER_PROCESS_HIDDEN             0x00000004UL
#define KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER                  0x00000008UL

#define KSWORD_ARK_THREAD_FIELD_INITIAL_STACK_PRESENT          0x00000001UL
#define KSWORD_ARK_THREAD_FIELD_STACK_LIMIT_PRESENT            0x00000002UL
#define KSWORD_ARK_THREAD_FIELD_STACK_BASE_PRESENT             0x00000004UL
#define KSWORD_ARK_THREAD_FIELD_KERNEL_STACK_PRESENT           0x00000008UL
#define KSWORD_ARK_THREAD_FIELD_READ_OPERATION_COUNT_PRESENT   0x00000010UL
#define KSWORD_ARK_THREAD_FIELD_WRITE_OPERATION_COUNT_PRESENT  0x00000020UL
#define KSWORD_ARK_THREAD_FIELD_OTHER_OPERATION_COUNT_PRESENT  0x00000040UL
#define KSWORD_ARK_THREAD_FIELD_READ_TRANSFER_COUNT_PRESENT    0x00000080UL
#define KSWORD_ARK_THREAD_FIELD_WRITE_TRANSFER_COUNT_PRESENT   0x00000100UL
#define KSWORD_ARK_THREAD_FIELD_OTHER_TRANSFER_COUNT_PRESENT   0x00000200UL
#define KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT       0x00000400UL

#define KSWORD_ARK_THREAD_R0_STATUS_UNAVAILABLE     0UL
#define KSWORD_ARK_THREAD_R0_STATUS_OK              1UL
#define KSWORD_ARK_THREAD_R0_STATUS_PARTIAL         2UL
#define KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING 3UL
#define KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED     4UL

#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IDENTITY 0x00000001UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_LISTS    0x00000002UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_START    0x00000004UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_STACK    0x00000008UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IO       0x00000010UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IDENTITY | \
     KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_LISTS | \
     KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_START | \
     KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_STACK | \
     KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IO)

#define KSWORD_ARK_THREAD_DETAIL_FIELD_PUBLIC_IDENTITY       0x00000001UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_OBJECT_ADDRESS        0x00000002UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_ETHREAD_CID           0x00000004UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_THREAD_LIST_ENTRY     0x00000008UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS         0x00000010UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS   0x00000020UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_KTHREAD_PROCESS       0x00000040UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_STACK_LIMITS          0x00000080UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_IO_COUNTERS           0x00000100UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_OFFSET_SOURCES        0x00000200UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_KERNEL_GLOBALS        0x00000400UL

typedef struct _KSWORD_ARK_THREAD_DETAIL_OFFSETS
{
    unsigned long etCid;
    unsigned long etThreadListEntry;
    unsigned long etStartAddress;
    unsigned long etWin32StartAddress;
    unsigned long ktProcess;
    unsigned long ktInitialStack;
    unsigned long ktStackLimit;
    unsigned long ktStackBase;
    unsigned long ktKernelStack;
    unsigned long ktReadOperationCount;
    unsigned long ktWriteOperationCount;
    unsigned long ktOtherOperationCount;
    unsigned long ktReadTransferCount;
    unsigned long ktWriteTransferCount;
    unsigned long ktOtherTransferCount;
} KSWORD_ARK_THREAD_DETAIL_OFFSETS;

// Thread detail offset source packet:
// - Input: R0 current KswDynState.KernelSources;
// - Processing: Corresponds one-to-one with the offsets fields, recording System Informer/PDB profile/runtime pattern.
// - Return: The structure itself has no return value; it is provided solely for R3 to interpret the thread field source.
typedef struct _KSWORD_ARK_THREAD_DETAIL_SOURCES
{
    unsigned long etCid;
    unsigned long etThreadListEntry;
    unsigned long etStartAddress;
    unsigned long etWin32StartAddress;
    unsigned long ktProcess;
    unsigned long ktInitialStack;
    unsigned long ktStackLimit;
    unsigned long ktStackBase;
    unsigned long ktKernelStack;
    unsigned long ktReadOperationCount;
    unsigned long ktWriteOperationCount;
    unsigned long ktOtherOperationCount;
    unsigned long ktReadTransferCount;
    unsigned long ktWriteTransferCount;
    unsigned long ktOtherTransferCount;
} KSWORD_ARK_THREAD_DETAIL_SOURCES;

typedef struct _KSWORD_ARK_THREAD_DETAIL_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long threadId;
    unsigned long processId;
} KSWORD_ARK_THREAD_DETAIL_REQUEST;

typedef struct _KSWORD_ARK_THREAD_DETAIL_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long threadId;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long requestedFlags;
    long lastStatus;
    unsigned long reserved;
    unsigned long long dynDataCapabilityMask;
    unsigned long long missingCapabilityMask;
    unsigned long long threadObjectAddress;
    unsigned long long processObjectAddress;
    unsigned long long cidUniqueProcess;
    unsigned long long cidUniqueThread;
    unsigned long long threadListEntryFlink;
    unsigned long long threadListEntryBlink;
    unsigned long long startAddress;
    unsigned long long win32StartAddress;
    unsigned long long kthreadProcessObject;
    unsigned long long initialStack;
    unsigned long long stackLimit;
    unsigned long long stackBase;
    unsigned long long kernelStack;
    unsigned long long readOperationCount;
    unsigned long long writeOperationCount;
    unsigned long long otherOperationCount;
    unsigned long long readTransferCount;
    unsigned long long writeTransferCount;
    unsigned long long otherTransferCount;
    KSWORD_ARK_THREAD_DETAIL_OFFSETS offsets;
    KSWORD_ARK_THREAD_DETAIL_SOURCES sources;
    KSWORD_ARK_RUNTIME_KERNEL_GLOBALS kernelGlobals;
    wchar_t detail[KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS];
} KSWORD_ARK_THREAD_DETAIL_RESPONSE;

typedef struct _KSWORD_ARK_ENUM_THREAD_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_ENUM_THREAD_REQUEST;

typedef struct _KSWORD_ARK_THREAD_ENTRY
{
    unsigned long threadId;
    unsigned long processId;
    unsigned long flags;
    unsigned long fieldFlags;
    unsigned long r0Status;
    unsigned long stackFieldSource;
    unsigned long ioFieldSource;
    unsigned long reserved;
    unsigned long long initialStack;
    unsigned long long stackLimit;
    unsigned long long stackBase;
    unsigned long long kernelStack;
    unsigned long long readOperationCount;
    unsigned long long writeOperationCount;
    unsigned long long otherOperationCount;
    unsigned long long readTransferCount;
    unsigned long long writeTransferCount;
    unsigned long long otherTransferCount;
    unsigned long ktInitialStackOffset;
    unsigned long ktStackLimitOffset;
    unsigned long ktStackBaseOffset;
    unsigned long ktKernelStackOffset;
    unsigned long ktReadOperationCountOffset;
    unsigned long ktWriteOperationCountOffset;
    unsigned long ktOtherOperationCountOffset;
    unsigned long ktReadTransferCountOffset;
    unsigned long ktWriteTransferCountOffset;
    unsigned long ktOtherTransferCountOffset;
    unsigned long long dynDataCapabilityMask;
} KSWORD_ARK_THREAD_ENTRY;

typedef struct _KSWORD_ARK_ENUM_THREAD_RESPONSE
{
    unsigned long version;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    KSWORD_ARK_THREAD_ENTRY entries[1];
} KSWORD_ARK_ENUM_THREAD_RESPONSE;

typedef struct _KSWORD_ARK_THREAD_CROSSVIEW_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long processId;
    unsigned long startTid;
    unsigned long endTid;
    unsigned long maxNodes;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_THREAD_CROSSVIEW_REQUEST;

typedef struct _KSWORD_ARK_THREAD_CROSSVIEW_ROW
{
    unsigned long long objectAddress;
    unsigned long long processObjectAddress;
    unsigned long long startAddress;
    unsigned long processId;
    unsigned long threadId;
    unsigned long sourceMask;
    unsigned long anomalyFlags;
    unsigned long long dynDataCapabilityMask;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    long lastStatus;
    unsigned long confidence;
    char imageName[16];
    char detail[KSWORD_ARK_CROSSVIEW_DETAIL_CHARS];
    unsigned long publicThreadId;
    unsigned long threadListThreadId;
    unsigned long cidTableThreadId;
    unsigned long publicProcessId;
    unsigned long threadListProcessId;
    unsigned long cidTableProcessId;
    long publicWalkStatus;
    long threadListStatus;
    long cidTableStatus;
    long startAddressStatus;
    unsigned long detailStatus;
    unsigned long denoiseFlags;
} KSWORD_ARK_THREAD_CROSSVIEW_ROW;

typedef struct _KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long reserved;
    unsigned long long dynDataCapabilityMask;
    unsigned long long missingCapabilityMask;
    long lastStatus;
    unsigned long reserved2;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    KSWORD_ARK_THREAD_CROSSVIEW_ROW entries[1];
} KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE;
