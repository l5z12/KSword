/*++

Module Name:

    network_inventory.c

Abstract:

    Shared bounded-copy helpers for the read-only network inventory collectors.

Environment:

    Kernel mode

--*/

#include "network_inventory_internal.h"

VOID
kswordArkNetworkInventoryCopyWideText(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* destination,
    _In_opt_z_ PCWSTR source
    )
/*++

Routine Description:

    Bounded copy of the BFE name or device interface name, ensuring shared protocol text is always NUL-terminated.

--*/
{
    RtlZeroMemory(destination, sizeof(WCHAR) * KSWORD_ARK_NETWORK_NAME_CHARS);
    if (source != NULL) {
        (VOID)RtlStringCchCopyW(destination, KSWORD_ARK_NETWORK_NAME_CHARS, source);
    }
}

VOID
kswordArkNetworkInventoryCopyUnicodeString(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* destination,
    _In_opt_ const UNICODE_STRING* source
    )
/*++

Routine Description:

    Copies the driver object name from a WDK UNICODE_STRING with bounded copying, without relying on the source string being NUL-terminated.

--*/
{
    ULONG sourceChars = 0UL;
    ULONG copyChars = 0UL;

    RtlZeroMemory(destination, sizeof(WCHAR) * KSWORD_ARK_NETWORK_NAME_CHARS);
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }

    sourceChars = source->Length / sizeof(WCHAR);
    copyChars = sourceChars;
    if (copyChars >= KSWORD_ARK_NETWORK_NAME_CHARS) {
        copyChars = KSWORD_ARK_NETWORK_NAME_CHARS - 1UL;
    }
    RtlCopyMemory(destination, source->Buffer, copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}
