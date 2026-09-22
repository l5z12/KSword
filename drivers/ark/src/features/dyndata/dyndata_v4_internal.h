#pragma once

#include "ark/ark_dyndata.h"

EXTERN_C_START

// Per-capability-group v4 state. The public row is stored directly so query
// IOCTLs can copy stable coverage counters without recomputing them.
typedef struct KswDynV4GroupState
{
    KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY publicEntry;
} KswDynV4GroupState;

// Per-loaded-module v4 profile state. Occupied marks whether a module profile
// has passed identity validation, StoredItemCount bounds Items, PublicEntry is
// the module status returned to R3, Groups holds derived capability coverage,
// and Items preserves the accepted compact PDB facts for future consumers.
typedef struct KswDynV4ModuleState
{
    BOOLEAN occupied;
    ULONG storedItemCount;
    KSW_DYN_V4_MODULE_STATUS_ENTRY publicEntry;
    KswDynV4GroupState groups[KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE];
    KSW_DYN_V4_ITEM_PACKET items[KSW_DYN_V4_MAX_ITEMS_PER_MODULE];
} KswDynV4ModuleState;

// Global v4 state. Modules is indexed by the compact v4 module-slot mapping,
// Missing stores bounded required/optional diagnostics, and MissingCount bounds
// the number of valid Missing rows.
typedef struct KswDynV4State
{
    KswDynV4ModuleState modules[KSW_DYN_V4_MAX_MODULES];
    KSW_DYN_V4_MISSING_ITEM_ENTRY missing[KSW_DYN_V4_MAX_MISSING_SUMMARY];
    ULONG missingCount;
} KswDynV4State;

extern EX_PUSH_LOCK gKswordDynDataV4Lock;
extern KswDynV4State gKswordDynDataV4State;

// Timer/DPC consumers only receive completed one-time layout snapshots and do not directly hold the v4 global lock.
typedef struct KswDynV4TimerDpcLayout
{
    ULONG kprcbTimerTable;
    ULONG timerTableTimerEntries;
    ULONG timerTableEntryLock;
    ULONG timerTableEntryEntry;
    ULONG timerTableEntryTime;
    ULONG timerTimerListEntry;
    ULONG timerDueTime;
    ULONG timerDpc;
    ULONG timerType;
    ULONG timerPeriod;
    ULONG dpcDeferredRoutine;
    ULONG dpcDeferredContext;
    ULONG timerTableTypeSize;
    ULONG timerTableEntryTypeSize;
    ULONG timerTypeSize;
    ULONG dpcTypeSize;
} KswDynV4TimerDpcLayout;

// Minifilter callback enumeration only consumes _FLT_FILTER.Operations and does not directly hold the v4 state lock.
typedef struct KswDynV4FltmgrMinifilterLayout
{
    ULONG fltFilterOperations;
} KswDynV4FltmgrMinifilterLayout;

// Bit-field consumers use a fixed snapshot; Offset is the object memory offset, while
// BitOffset/BitCount describe the bit range within the integer width of StorageBytes.
typedef struct KswDynV4BitFieldLayout
{
    ULONG offset;
    ULONG bitOffset;
    ULONG bitCount;
    ULONG storageBytes;
} KswDynV4BitFieldLayout;

// CI hash cache consumers receive only a one-time snapshot layout after identity verification is complete.
// Global field stores the RVA relative to the current image base of ci.dll/ci.sys.
typedef struct KswDynV4CiKernelHashLayout
{
    ULONGLONG moduleBase;
    ULONG moduleSize;
    ULONG kernelHashBucketListRva;
    ULONG hashCacheLockRva;
    ULONG entryNext;
    ULONG entryDriverName;
    ULONG entryTimeDateStamp;
    ULONG entryLoadStatus;
    ULONG entryImageBase;
    ULONG entryImageSize;
    ULONG entryTypeSize;
} KswDynV4CiKernelHashLayout;

// Ex worker queue consumers only receive the complete layout matching the current ntoskrnl PE/PDB identity.
// Global field is the current image RVA; all other fields are PDB structure offsets, type sizes, or enumeration values.
typedef struct KswDynV4WorkQueueLayout
{
    ULONGLONG moduleBase;
    ULONG moduleSize;
    ULONG pspSystemPartitionRva;
    ULONG expBuiltinPrioritiesRva;
    ULONG epartitionExPartition;
    ULONG exPartitionWorkQueues;
    ULONG exWorkQueueWorkPriQueue;
    ULONG exWorkQueueQueueIndex;
    ULONG kpriQueueEntryListHead;
    ULONG kpriQueueThreadListHead;
    ULONG kthreadQueue;
    ULONG kthreadQueueListEntry;
    ULONG ethreadTcb;
    ULONG ethreadStartAddress;
    ULONG workItemList;
    ULONG workItemRoutine;
    ULONG workItemParameter;
    ULONG exPoolUntrusted;
    ULONG epartitionTypeSize;
    ULONG exPartitionTypeSize;
    ULONG exWorkQueueTypeSize;
    ULONG kpriQueueTypeSize;
    ULONG kthreadTypeSize;
    ULONG ethreadTypeSize;
    ULONG workItemTypeSize;
    ULONG runtimeFlags;
    ULONG runtimePriorityIndexes[3];
} KswDynV4WorkQueueLayout;

#define KSW_DYN_V4_WORK_QUEUE_RUNTIME_SIGNATURE 0x00000001UL
#define KSW_DYN_V4_WORK_QUEUE_RUNTIME_ITEMS     0x00000002UL
#define KSW_DYN_V4_WORK_QUEUE_RUNTIME_THREADS   0x00000004UL

NTSTATUS
kswordArkDynDataV4SnapshotTimerDpcLayout(
    _Out_ KswDynV4TimerDpcLayout* layoutOut
    );

// Get the offset of _FLT_FILTER.Operations that exactly matches the current identity of fltMgr.sys.
NTSTATUS
kswordArkDynDataV4SnapshotFltMgrMinifilterLayout(
    _Out_ KswDynV4FltmgrMinifilterLayout* layoutOut
    );

// Thread consumer obtains the precise PDB bit-field layout of _ETHREAD.ActiveExWorker.
NTSTATUS
kswordArkDynDataV4SnapshotActiveExWorkerField(
    _Out_ KswDynV4BitFieldLayout* fieldOut
    );

// Retrieve the read-only kernel hash cache layout that exactly matches the current ci.dll/ci.sys identity.
NTSTATUS
kswordArkDynDataV4SnapshotCiKernelHashLayout(
    _Out_ KswDynV4CiKernelHashLayout* layoutOut
    );

// Obtain the Ex work queue layout described by the precise ntoskrnl PDB; if any required item is missing, it is not supported.
NTSTATUS
kswordArkDynDataV4SnapshotWorkQueueLayout(
    _Out_ KswDynV4WorkQueueLayout* layoutOut
    );

// enumerate currently loaded modules supported by v4 and their applied profile statuses.
ULONG
kswordArkDynDataV4BuildModuleStatusSnapshot(
    _Out_writes_opt_(entryCapacity) KSW_DYN_V4_MODULE_STATUS_ENTRY* entries,
    _In_ ULONG entryCapacity,
    _Out_ ULONG* totalCountOut
    );

EXTERN_C_END
