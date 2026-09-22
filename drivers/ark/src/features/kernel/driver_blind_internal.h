#pragma once

#include "ark/ark_driver.h"

/* Note: Store up to 32 DriverObject states, uniquely identified by module base address, simultaneously. */
#define KSW_DRIVER_COMMUNICATION_RECORD_LIMIT 32UL
/* Note: This feature covers only the five communication entry points; it does not touch lifecycle or FastIo. */
#define KSW_DRIVER_COMMUNICATION_SLOT_COUNT 5UL

/* Note: A fixed slot maps the protocol mask to the public IRP major index. */
typedef struct KswDriverCommunicationSlot
{
    ULONG mask;
    UCHAR majorFunction;
} KswDriverCommunicationSlot, *PkswDriverCommunicationSlot;

/* Note: a record stores the complete target identity and original entry required for a reversible replacement. */
typedef struct KswDriverCommunicationRecord
{
    BOOLEAN inUse;
    UCHAR padding[3];
    ULONG generation;
    /* Note: Contains only slots where this feature's actual CAS installation is present and can still be safely rolled back. */
    ULONG ownedMask;
    /* Note: Represents the set of currently pointing to kernel reject in the five target slots. */
    ULONG activeMask;
    /* Note: Permanently latch slots observing foreign/ABA; do not clear before deletion. */
    ULONG conflictMask;
    /* Note: Latch the slot domain where this feature was successfully installed and still requires ABA monitoring. */
    ULONG installedMask;
    /* Note: Use the immutable module base address supplied by the request as the record key after resolution and validation. */
    ULONGLONG targetModuleBase;
    PDRIVER_OBJECT driverObject;
    PDRIVER_DISPATCH originalDispatch[KSW_DRIVER_COMMUNICATION_SLOT_COUNT];
    WCHAR canonicalName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KswDriverCommunicationRecord, *PkswDriverCommunicationRecord;

/* Note: Global state is accessed only in PASSIVE_LEVEL control paths and during driver unloading. */
typedef struct KswDriverCommunicationState
{
    FAST_MUTEX lock;
    volatile LONG initialized;
    BOOLEAN shuttingDown;
    UCHAR padding[3];
    ULONG generation;
    PDRIVER_OBJECT selfDriverObject;
    PDRIVER_DISPATCH rejectDispatch;
    KswDriverCommunicationRecord records[KSW_DRIVER_COMMUNICATION_RECORD_LIMIT];
} KswDriverCommunicationState, *PkswDriverCommunicationState;

/* Note: The action backend accesses the state core only through these internal symbols. */
extern const KswDriverCommunicationSlot
kGKswordArkDriverCommunicationSlots[KSW_DRIVER_COMMUNICATION_SLOT_COUNT];
extern KswDriverCommunicationState
gKswordArkDriverCommunicationState;

PDRIVER_DISPATCH
kswordArkDriverCommunicationReadDispatch(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ UCHAR majorFunction
    );

PDRIVER_DISPATCH
kswordArkDriverCommunicationCompareExchangeDispatch(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ UCHAR majorFunction,
    _In_ PDRIVER_DISPATCH exchange,
    _In_ PDRIVER_DISPATCH expected
    );

VOID
kswordArkDriverCommunicationAdvanceGenerationLocked(
    _Inout_opt_ KswDriverCommunicationRecord* record
    );

KswDriverCommunicationRecord*
kswordArkDriverCommunicationFindRecordLocked(
    _In_ ULONGLONG targetModuleBase
    );

KswDriverCommunicationRecord*
kswordArkDriverCommunicationAllocateRecordLocked(
    VOID
    );

VOID
kswordArkDriverCommunicationRefreshRecordLocked(
    _Inout_ KswDriverCommunicationRecord* record
    );

VOID
kswordArkDriverCommunicationFillResponse(
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response,
    _In_ ULONG action,
    _In_ NTSTATUS status,
    _In_ ULONG changedMask,
    _In_opt_ const KswDriverCommunicationRecord* record,
    _In_opt_ PDRIVER_OBJECT driverObject,
    _In_opt_z_ const WCHAR* canonicalName
    );

NTSTATUS
kswordArkDriverCommunicationValidateTarget(
    _In_ PDRIVER_OBJECT driverObject,
    _In_z_ const WCHAR* canonicalName
    );

NTSTATUS
kswordArkDriverCommunicationQuery(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    );

NTSTATUS
kswordArkDriverCommunicationBlind(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    );

NTSTATUS
kswordArkDriverCommunicationRestore(
    _In_ const KSWORD_ARK_DRIVER_COMMUNICATION_REQUEST* request,
    _Out_ KSWORD_ARK_DRIVER_COMMUNICATION_RESPONSE* response
    );
