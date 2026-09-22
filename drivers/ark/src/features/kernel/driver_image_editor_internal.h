#pragma once

#include <ntifs.h>

#include "ark/ark_driver.h"
#include "driver_integrity.h"

// Note: The transaction table limit restricts the number of held DriverObject references to prevent unbounded kernel pool growth.
#define KSW_DRIVER_IMAGE_RECORD_LIMIT 128UL
// Note: Module chain traversal uses a fixed budget to prevent infinite loops on corruption or cycles.
#define KSW_DRIVER_IMAGE_LIST_WALK_LIMIT 4096UL

// Note: Runtime description saves identity-matched ntoskrnl, KLDR offsets, and two exact export addresses.
typedef struct KswDriverImageRuntime
{
    KswDynState dynState;
    PLIST_ENTRY listHead;
    PERESOURCE listResource;
    ULONG layoutFlags;
    BOOLEAN resourceAcquired;
    BOOLEAN resourceExclusive;
    UCHAR reserved0[2];
} KswDriverImageRuntime, *PkswDriverImageRuntime;

// Note: The link view describes only the observation protected by PsLoadedModuleResource once.
typedef struct KswDriverImageLinkView
{
    BOOLEAN loaderAvailable;
    BOOLEAN inList;
    BOOLEAN selfLinked;
    BOOLEAN malformed;
    ULONGLONG entryAddress;
    ULONGLONG linkAddress;
    ULONGLONG dllBase;
    ULONG sizeOfImage;
    ULONG reserved0;
    PLIST_ENTRY flink;
    PLIST_ENTRY blink;
} KswDriverImageLinkView, *PkswDriverImageLinkView;

// Note: Each target record retains immutable original values, the last applied values, and the original list neighbors.
typedef struct KswDriverImageRecord
{
    BOOLEAN inUse;
    BOOLEAN linkManaged;
    BOOLEAN linkOwned;
    BOOLEAN linkConflict;
    ULONG generation;
    ULONG originalFieldMask;
    ULONG managedFieldMask;
    ULONG ownedFieldMask;
    ULONG conflictFieldMask;
    ULONGLONG targetModuleBase;
    PDRIVER_OBJECT driverObject;
    PVOID loaderEntry;
    PLIST_ENTRY loaderLink;
    PLIST_ENTRY originalLinkFlink;
    PLIST_ENTRY originalLinkBlink;
    KSWORD_ARK_DRIVER_IMAGE_VALUES originalValues;
    KSWORD_ARK_DRIVER_IMAGE_VALUES appliedValues;
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KswDriverImageRecord, *PkswDriverImageRecord;

// Note: The global transaction table uses FAST_MUTEX to serialize record generation and multi-field rollback.
typedef struct KswDriverImageState
{
    FAST_MUTEX lock;
    volatile LONG initialized;
    BOOLEAN shuttingDown;
    UCHAR reserved0[3];
    ULONG generation;
    PDRIVER_OBJECT selfDriverObject;
    KswDriverImageRecord records[KSW_DRIVER_IMAGE_RECORD_LIMIT];
} KswDriverImageState, *PkswDriverImageState;

// Note: The response context aggregates action results and locked snapshots for transmission to a unified serializer.
typedef struct KswDriverImageResponseContext
{
    const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request;
    const KswDriverImageRecord* record;
    const KswDriverImageRuntime* runtime;
    NTSTATUS lastStatus;
    NTSTATUS loaderStatus;
    ULONG changedFieldMask;
    BOOLEAN recordPresent;
    BOOLEAN linkChanged;
    BOOLEAN restoredOriginalPosition;
    BOOLEAN restoredListTail;
} KswDriverImageResponseContext, *PkswDriverImageResponseContext;

// Note: The parser accepts only the exact export chain head and resource locks currently exported by ntoskrnl.
NTSTATUS
kswordArkDriverImageResolveRuntime(
    _Out_ KswDriverImageRuntime* runtime
    );

// Note: The caller acquires shared or exclusive resources after entering the critical section at PASSIVE/APC_LEVEL.
NTSTATUS
kswordArkDriverImageAcquireRuntime(
    _Inout_ KswDriverImageRuntime* runtime,
    _In_ BOOLEAN exclusive
    );

// Note: Release function must strictly pair with AcquireRuntime and restore standard kernel APC.
VOID
kswordArkDriverImageReleaseRuntime(
    _Inout_ KswDriverImageRuntime* runtime
    );

// Note: On the first transaction, locate the KLDR entry by exact DllBase and verify the current chain state.
NTSTATUS
kswordArkDriverImageLocateLoaderLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _In_ ULONGLONG driverStart,
    _Out_ KswDriverImageLinkView* view
    );

// Note: An existing transaction uses the saved loader/link addresses to refresh member relationships and KLDR values.
NTSTATUS
kswordArkDriverImageInspectRecordLinkLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _In_ const KswDriverImageRecord* record,
    _Out_ KswDriverImageLinkView* view
    );

// Note: Require exact expected Flink/Blink values before unlinking; upon success, self-link the target node.
NTSTATUS
kswordArkDriverImageHideLinkLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _In_ PLIST_ENTRY expectedFlink,
    _In_ PLIST_ENTRY expectedBlink,
    _Out_ BOOLEAN* changed
    );

// Note: Restore and reinsert the original neighbor first; if the original neighbor disappears, insert at the end of the chain under the same resource lock.
NTSTATUS
kswordArkDriverImageRestoreLinkLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _Out_ BOOLEAN* changed,
    _Out_ BOOLEAN* originalPosition
    );

// Note: Field reads are always atomic samples; KLDR fields additionally require holding the actual module resources.
NTSTATUS
kswordArkDriverImageReadValuesLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _In_ const KswDriverImageRecord* record,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_VALUES* values,
    _Out_ ULONG* availableFieldMask
    );

// Note: Multi-field application uses per-field CAS; a mid-operation failure rolls back written fields via reverse CAS.
NTSTATUS
kswordArkDriverImageApplyFieldsLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _In_ ULONG fieldMask,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* expectedValues,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_VALUES* desiredValues,
    _Out_ ULONG* changedFieldMask,
    _Out_ ULONG* rollbackConflictMask
    );

// Note: Restore a field with CAS to its immutable original value only if it still equals this transaction's applied value.
NTSTATUS
kswordArkDriverImageRestoreFieldsLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _In_ ULONG fieldMask,
    _Out_ ULONG* changedFieldMask,
    _Out_ ULONG* failedFieldMask
    );

// Note: Refreshes only observation and updates ownership/conflict bits without overwriting any current third-party values.
NTSTATUS
kswordArkDriverImageRefreshFieldsLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _Out_ BOOLEAN* stateChanged
    );

// Note: Protocol names must be terminated within the fixed array to prevent RtlInitUnicodeString buffer overruns.
BOOLEAN
kswordArkDriverImageHasTerminatedName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* driverName
    );

// Note: Driver object names are compared case-insensitively per Object Manager conventions.
BOOLEAN
kswordArkDriverImageNamesEqual(
    _In_z_ const WCHAR* left,
    _In_z_ const WCHAR* right
    );

// Note: The target can be resolved by object name or initial module base address; the action also verifies the exact object address.
NTSTATUS
kswordArkDriverImageResolveTarget(
    _In_ const KSWORD_ARK_DRIVER_IMAGE_REQUEST* request,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut,
    _Out_writes_(nameChars) PWCHAR canonicalNameOut,
    _In_ ULONG nameChars,
    _Out_ ULONGLONG* targetModuleBaseOut
    );

// Note: Runtime open performs unified precise export resolution, critical section handling, and shared/exclusive resource acquisition.
NTSTATUS
kswordArkDriverImageOpenRuntime(
    _Out_ KswDriverImageRuntime* runtime,
    _In_ BOOLEAN exclusive
    );

// Note: Record the first time KLDR is needed, bind the loader entry using the frozen module base address, and save the link identity.
NTSTATUS
kswordArkDriverImageAttachLoaderLocked(
    _In_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _Out_ BOOLEAN* stateChanged
    );

// Note: Refresh fields and chain ownership; Runtime may be missing, in which case KLDR/link conservatively enters a conflict state.
NTSTATUS
kswordArkDriverImageRefreshRecordLocked(
    _In_opt_ const KswDriverImageRuntime* runtime,
    _Inout_ KswDriverImageRecord* record,
    _Out_ BOOLEAN* stateChanged
    );

// Note: The unified response serializer only observes locked records and resource-protected chains, without performing writes.
VOID
kswordArkDriverImageFillResponseLocked(
    _In_ const KswDriverImageState* state,
    _In_ const KswDriverImageResponseContext* context,
    _Out_ KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    );
