#pragma once

#include "network_inventory.h"

EXTERN_C_START

// Note: Public bounded copy function for WFP/NDIS collectors; output is always NUL-terminated.
VOID
kswordArkNetworkInventoryCopyWideText(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* destination,
    _In_opt_z_ PCWSTR source
    );

// Note: Copies a non-NUL-terminated kernel UNICODE_STRING to avoid out-of-bounds reads of the driver object name.
VOID
kswordArkNetworkInventoryCopyUnicodeString(
    _Out_writes_(KSWORD_ARK_NETWORK_NAME_CHARS) WCHAR* destination,
    _In_opt_ const UNICODE_STRING* source
    );

EXTERN_C_END
