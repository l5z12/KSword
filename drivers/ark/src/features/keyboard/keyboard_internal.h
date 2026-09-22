#pragma once

#include <ntddk.h>

typedef struct KswKeyboardHotkeyRuntime
{
    PVOID win32kfullBase;
    ULONG win32kfullSize;
    PVOID win32kbaseBase;
    ULONG win32kbaseSize;
    ULONG_PTR isHotKeyAddress;
    ULONG_PTR sessionGlobals;
    ULONG_PTR tableBase;
    ULONG tableOffset;
    ULONG nextOffset;
    ULONG modifiersOffset;
    ULONG vkOffset;
    ULONG idOffset;
} KswKeyboardHotkeyRuntime, *PkswKeyboardHotkeyRuntime;

NTSTATUS
kswordArkKeyboardResolveHotkeyRuntime(
    _Out_ KswKeyboardHotkeyRuntime* runtimeOut
    );

ULONG64
kswordArkKeyboardHashHotkeyObject(
    _In_reads_bytes_(objectBytes) const UCHAR* object,
    _In_ SIZE_T objectBytes
    );
