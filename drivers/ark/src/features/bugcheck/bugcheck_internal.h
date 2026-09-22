#pragma once

#include "ark/ark_bugcheck.h"

#define KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT 512UL
#define KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS 64UL
#define KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT 1024UL
#define KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS 16UL
#define KSWORD_ARK_BUGCHECK_FAULT_TEXT_CHARS 64UL
#define KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS 192UL
#define KSWORD_ARK_BUGCHECK_DRAW_MILLISECONDS 10000ULL

#define KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN 0UL
#define KSWORD_ARK_BUGCHECK_MODULE_OURS 1UL
#define KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT 2UL
#define KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY 3UL

#define KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE 0UL
#define KSWORD_ARK_BUGCHECK_CONFIDENCE_LOW 1UL
#define KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM 2UL
#define KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH 3UL

#define KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_NONE 0UL
#define KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CONTEXT 1UL
#define KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CRITICAL 2UL

#define KSWORD_ARK_VMWARE_VENDOR_ID 0x15AD
#define KSWORD_ARK_PCI_BAR_COUNT 6UL

typedef struct KswordArkBugcheckModuleEntry
{
    volatile LONG sequence;
    ULONG_PTR base;
    ULONG size;
    ULONG classification;
    CHAR name[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS];
} KswordArkBugcheckModuleEntry, *PkswordArkBugcheckModuleEntry;

typedef struct KswordArkBugcheckProcessEntry
{
    volatile LONG sequence;
    PVOID object;
    ULONG_PTR processId;
    BOOLEAN exiting;
    UCHAR reserved[3];
    CHAR name[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS];
} KswordArkBugcheckProcessEntry, *PkswordArkBugcheckProcessEntry;

typedef struct KswordArkBugcheckDiagnostics
{
    volatile LONG captured;
    ULONG bugCheckCode;
    ULONG_PTR parameter1;
    ULONG_PTR parameter2;
    ULONG_PTR parameter3;
    ULONG_PTR parameter4;
    ULONG_PTR faultAddress;
    ULONG faultParameter;
    CHAR faultMeaning[KSWORD_ARK_BUGCHECK_FAULT_TEXT_CHARS];
    ULONG lastReason;
    ULONG lastDumpType;
    ULONG dumpBufferLength;
    ULONG64 dumpOffset;
    ULONG irql;
    ULONG cpu;
    LARGE_INTEGER perfCounter;
    ULONG_PTR processObject;
    ULONG_PTR processId;
    ULONG processSource;
    CHAR processName[KSWORD_ARK_BUGCHECK_PROCESS_NAME_CHARS];
    ULONG_PTR candidateAddress;
    ULONG_PTR candidateModuleBase;
    ULONG_PTR candidateModuleOffset;
    ULONG candidateModuleSize;
    ULONG candidateParameter;
    ULONG candidateClass;
    ULONG candidateConfidence;
    CHAR candidateModule[KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS];
    CHAR candidateSource[KSWORD_ARK_BUGCHECK_FAULT_TEXT_CHARS];
} KswordArkBugcheckDiagnostics, *PkswordArkBugcheckDiagnostics;

typedef struct KswordArkSvgaContext
{
    BOOLEAN found;
    BOOLEAN mapped;
    BOOLEAN fifoMapped;
    ULONG bus;
    ULONG device;
    ULONG function;
    USHORT vendorId;
    USHORT deviceId;
    ULONG ioBase;
    PHYSICAL_ADDRESS framebufferPhysical;
    SIZE_T framebufferLength;
    PHYSICAL_ADDRESS fifoPhysical;
    SIZE_T fifoLength;
    ULONG width;
    ULONG height;
    ULONG bpp;
    ULONG depth;
    ULONG pitch;
    ULONG fbOffset;
    ULONG fbSize;
    ULONG vramSize;
    ULONG redMask;
    ULONG greenMask;
    ULONG blueMask;
    ULONG capabilities;
    volatile UCHAR* framebuffer;
    volatile ULONG* fifo;
} KswordArkSvgaContext, *PkswordArkSvgaContext;

typedef struct KswordArkBugcheckBitmapCache
{
    volatile LONG valid;
    volatile LONG uploading;
    ULONG width;
    ULONG height;
    ULONG stride;
    ULONG brandColorRgb;
    ULONG dataLength;
} KswordArkBugcheckBitmapCache, *PkswordArkBugcheckBitmapCache;

typedef struct KswordArkBugcheckState
{
    volatile LONG active;
    volatile LONG classicDisplayStarted;
    volatile LONG dumpDisplayStarted;
    volatile LONG modeSetDone;
    PDRIVER_OBJECT driverObject;
    PDEVICE_OBJECT deviceObject;
    KBUGCHECK_CALLBACK_RECORD classicRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD secondaryRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD dumpIoRecord;
    KBUGCHECK_REASON_CALLBACK_RECORD triageRecord;
    BOOLEAN classicRegistered;
    BOOLEAN secondaryRegistered;
    BOOLEAN dumpIoRegistered;
    BOOLEAN triageRegistered;
    volatile LONG trackingReady;
    KSPIN_LOCK moduleCacheLock;
    KSPIN_LOCK processCacheLock;
    KswordArkBugcheckBitmapCache bitmap;
    KswordArkBugcheckModuleEntry modules[KSWORD_ARK_BUGCHECK_MODULE_CACHE_COUNT];
    ULONG moduleCount;
    ULONG moduleNextSlot;
    KswordArkBugcheckProcessEntry processes[KSWORD_ARK_BUGCHECK_PROCESS_CACHE_COUNT];
    ULONG processCount;
    ULONG processNextSlot;
    KswordArkBugcheckDiagnostics diagnostics;
    KswordArkSvgaContext svga;
} KswordArkBugcheckState, *PkswordArkBugcheckState;

extern KswordArkBugcheckState gKswordArkBugcheckState;
extern UCHAR gKswordArkBugcheckBitmapPixels[KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES];

// The controller establishes only the sync state during DriverEntry; the full BGP diagnostic starts only after an explicit configuration IOCTL request.
NTSTATUS
kswordArkBugcheckControlConfigure(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST* request,
    _Out_ KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE* response
    );

// Call this function during the time-consuming preparation phase within the security boundary; returning STATUS_CANCELLED indicates
// the driver is unloading, while STATUS_IO_TIMEOUT indicates the current installation has exceeded the 30-second budget for R0.
NTSTATUS
kswordArkBugcheckControlCheckAbort(
    VOID
    );

NTSTATUS
kswordArkBugcheckSvgaInitialize(
    _Inout_ PkswordArkSvgaContext context
    );

VOID
kswordArkBugcheckSvgaShutdown(
    _Inout_ PkswordArkSvgaContext context
    );

VOID
kswordArkBugcheckSvgaModeSetNoLog(
    _Inout_ PkswordArkSvgaContext context
    );

VOID
kswordArkBugcheckSvgaDrawPanelNoLog(
    _Inout_ PkswordArkBugcheckState state
    );

PCSTR
kswordArkBugcheckName(
    _In_ ULONG bugCheckCode
    );

PCSTR
kswordArkBugcheckModuleClassText(
    _In_ ULONG classification
    );

PCSTR
kswordArkBugcheckConfidenceText(
    _In_ ULONG confidence
    );

PCSTR
kswordArkBugcheckVerdictText(
    _In_ ULONG classification
    );

PCSTR
kswordArkBugcheckReasonText(
    _In_ ULONG reason
    );

PCSTR
kswordArkBugcheckDumpTypeText(
    _In_ ULONG dumpType
    );
