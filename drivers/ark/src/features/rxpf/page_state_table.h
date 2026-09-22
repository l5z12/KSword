#pragma once

#include <ntddk.h>

#include "driver/KswordArkRxPfIoctl.h"

EXTERN_C_START

#define KSW_RXPF_PAGE_TABLE_CAPACITY 64UL
#define KSW_RXPF_PAGE_TABLE_MASK (KSW_RXPF_PAGE_TABLE_CAPACITY - 1UL)
#define KSW_RXPF_PAGE_TOMBSTONE 1ULL

typedef struct KswRxpfPageRecord
{
    volatile LONG state;
    volatile LONG emulationEnabled;
    ULONG targetKind;
    ULONG flags;
    volatile ULONG generation;
    volatile LONG referenceCount;
    volatile LONG lastStatus;
    volatile ULONG lastFailureReason;
    ULONG originalProtection;
    ULONG currentProtection;
    ULONG writableAliasProtection;
    ULONG lastWriteOffset;
    ULONG lastWriteLength;
    DECLSPEC_ALIGN(8) volatile LONG64 recordId;
    DECLSPEC_ALIGN(8) volatile LONG64 pageBase;
    ULONGLONG writableAlias;
    ULONGLONG pfn;
    ULONGLONG ownerImageBase;
    PMDL mdl;
    PVOID originalMapping;
    PVOID backup;
    PVOID currentContent;
    BOOLEAN ownsMdlPages;
    BOOLEAN pagesLockedByProbe;
    BOOLEAN mappingIsAlias;
    UCHAR reservedBoolean;
    UCHAR lastWriteBytes[KSWORD_ARK_RXPF_MAX_WRITE_BYTES];
    DECLSPEC_ALIGN(8) volatile LONG64 faultCount;
    DECLSPEC_ALIGN(8) volatile LONG64 emulatedCount;
    DECLSPEC_ALIGN(8) volatile LONG64 unsupportedCount;
} KswRxpfPageRecord, *PkswRxpfPageRecord;

typedef struct KswRxpfPageTable
{
    EX_PUSH_LOCK controlLock;
    volatile LONG accepting;
    volatile LONG registeredCount;
    volatile LONG enabledCount;
    volatile LONG64 nextRecordId;
    KswRxpfPageRecord slots[KSW_RXPF_PAGE_TABLE_CAPACITY];
} KswRxpfPageTable, *PkswRxpfPageTable;

VOID
kswRxpfPageTableInitialize(
    _Out_ PkswRxpfPageTable table
    );

VOID
kswRxpfPageTableStopAccepting(
    _Inout_ PkswRxpfPageTable table
    );

VOID
kswRxpfPageTableAcquireExclusive(
    _Inout_ PkswRxpfPageTable table
    );

VOID
kswRxpfPageTableReleaseExclusive(
    _Inout_ PkswRxpfPageTable table
    );

_Must_inspect_result_
NTSTATUS
kswRxpfPageTableInsertLocked(
    _Inout_ PkswRxpfPageTable table,
    _In_ const KswRxpfPageRecord* source,
    _Outptr_ PkswRxpfPageRecord* recordOut
    );

_Must_inspect_result_
PkswRxpfPageRecord
kswRxpfPageTableFindByIdLocked(
    _In_ PkswRxpfPageTable table,
    _In_ ULONGLONG recordId
    );

_Must_inspect_result_
PkswRxpfPageRecord
kswRxpfPageTableLookupFault(
    _In_ PkswRxpfPageTable table,
    _In_ ULONGLONG pageBase
    );

VOID
kswRxpfPageTableBeginRemoveLocked(
    _Inout_ PkswRxpfPageTable table,
    _Inout_ PkswRxpfPageRecord record
    );

VOID
kswRxpfPageTableClearRemovedLocked(
    _Inout_ PkswRxpfPageTable table,
    _Inout_ PkswRxpfPageRecord record
    );

EXTERN_C_END
