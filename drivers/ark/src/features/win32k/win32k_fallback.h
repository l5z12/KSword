#pragma once

#include "win32k_support.h"
#include "../../platform/runtime_signature_scan.h"

EXTERN_C_START

#define KSW_WIN32K_FALLBACK_MAP_LIMIT       8192UL
#define KSW_WIN32K_FALLBACK_WINDOW_LIMIT    8192UL
#define KSW_WIN32K_FALLBACK_POOL_TAG        'fWkW'

typedef struct KswWiN32KFallbackLayout
{
    ULONG siloServerInfo;
    ULONG siloHandleEntrySize;
    ULONG siloHandleEntries;
    ULONG siloObjectSlots;
    ULONG serverHandleCount;
    ULONG handleEntryShift;
    ULONG objectSlotStride;
    ULONG handleGeneration;
    ULONG handleType;
    ULONG handleFlags;
    ULONG tagWndHandle;
    ULONG tagWndThreadInfo;
    ULONG tagThreadInfoQueue;
    ULONG tagQActiveWindow;
    ULONG tagQFocusWindow;
    ULONG tagQCaptureWindow;
    ULONG tagQCaretWindow;
} KswWiN32KFallbackLayout, *PkswWiN32KFallbackLayout;

typedef struct KswWiN32KFallbackWindow
{
    ULONG64 hwnd;
    ULONG64 tagWnd;
    ULONG64 threadInfo;
    ULONG processId;
    ULONG threadId;
    ULONG sessionId;
} KswWiN32KFallbackWindow, *PkswWiN32KFallbackWindow;

typedef struct KswWiN32KFallbackContext
{
    KswHookSystemModuleEntry win32kbase;
    KswHookSystemModuleEntry win32kfull;
    ULONG_PTR userGetSiloGlobals;
    KswWiN32KFallbackLayout layout;
    KswordArkWiN32KGuiThreadMapEntry* threadMap;
    ULONG threadMapCount;
    BOOLEAN threadMapTruncated;
    BOOLEAN handleLayoutResolved;
    BOOLEAN queueLayoutResolved;
} KswWiN32KFallbackContext, *PkswWiN32KFallbackContext;

typedef struct KswWiN32KFallbackQueue
{
    ULONG64 queueObject;
    ULONG64 activeHwnd;
    ULONG64 focusHwnd;
    ULONG64 captureHwnd;
    ULONG64 caretHwnd;
} KswWiN32KFallbackQueue, *PkswWiN32KFallbackQueue;

NTSTATUS
kswordArkWin32kFallbackInitialize(
    _Out_ KswWiN32KFallbackContext* context
    );

VOID
kswordArkWin32kFallbackCleanup(
    _Inout_ KswWiN32KFallbackContext* context
    );

NTSTATUS
kswordArkWin32kFallbackEnumerateWindows(
    _Inout_ KswWiN32KFallbackContext* context,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_writes_(windowCapacity) KswWiN32KFallbackWindow* windows,
    _In_ ULONG windowCapacity,
    _Out_ ULONG* windowCountOut,
    _Out_ ULONG* totalCountOut,
    _Out_ BOOLEAN* truncatedOut
    );

BOOLEAN
kswordArkWin32kFallbackReadQueue(
    _In_ const KswWiN32KFallbackContext* context,
    _In_ const KswordArkWiN32KGuiThreadMapEntry* threadEntry,
    _In_reads_(windowCount) const KswWiN32KFallbackWindow* windows,
    _In_ ULONG windowCount,
    _Out_ KswWiN32KFallbackQueue* queueOut
    );

VOID
kswordArkWin32kFallbackPublishOffsets(
    _In_ const KswWiN32KFallbackContext* context,
    _Out_ KSWORD_ARK_WIN32K_FIELD_OFFSETS* offsets
    );

BOOLEAN
kswordArkWin32kFallbackDecodeQueueLayout(
    _In_ const KswRuntimeImageView* view,
    _Inout_ KswWiN32KFallbackLayout* layout
    );

ULONG64
kswordArkWin32kFallbackProbeCapabilityMask(
    VOID
    );

NTSTATUS
kswordArkWin32kFallbackQueryWindowSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kFallbackQueryGuiThreadSnapshot(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_WIN32K_QUERY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkWin32kFallbackQueryWindowDetail(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END
