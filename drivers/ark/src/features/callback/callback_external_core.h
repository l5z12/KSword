#pragma once

#include "callback_internal.h"

#if defined(KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL)
#include "callback_extended_kernel.h"
#include "callback_external_minifilter.h"
#include "callback_external_safe.h"
#include "callback_external_wfp.h"
#endif

static __inline VOID
kswordArkCallbackExternalAddCallbacks(
    _Inout_ KswordArkCallbackEnumBuilder* builder
    )
/*++

Routine Description:

    Aggregate external callback enumeration extension. Note: This inline entry point allows
    existing callback_enum.c to compile even before the core source file is added to the
    project; the actual heavy enumeration resides in optional callback_external_*.c files.

Arguments:

    Builder: Input/output enumeration response builder.

Return Value:

    No return value.

--*/
{
    if (builder == NULL) {
        return;
    }

#if defined(KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL)
    kswordArkCallbackExtendedAddBugcheckCallbacks(builder);
    kswordArkCallbackExtendedAddObjectCallbacks(builder);
    kswordArkCallbackExtendedAddSystemCallbacks(builder);
    kswordArkCallbackExtendedAddNmiCallbacks(builder);
    kswordArkCallbackExternalWfpAddCallbacks(builder);
    kswordArkCallbackExternalSafeAddCallbacks(builder);
    kswordArkCallbackExternalMinifilterAddCallbacks(builder);
#else
    KswordArkCallbackEnumAddUnsupportedRow(
        Builder,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT,
        L"WFP callout external package",
        L"外部回调扩展源文件尚未加入工程；主会话追加 callback_external_*.c 并定义启用宏后可使用公开 WFP 枚举/移除。");
    KswordArkCallbackEnumAddUnsupportedRow(
        Builder,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER,
        L"ETW callback external package",
        L"ETW 外部回调需要安全全局表定位；当前默认返回 STATUS_NOT_SUPPORTED。");
#endif
}

static __inline NTSTATUS
kswordArkCallbackExternalRemoveByRequest(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST* requestPacket,
    _Inout_ KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE* responsePacket
    )
/*++

Routine Description:

    Aggregate external callback removal extension. Note: Each sub-module is responsible for validating public APIs or
    returning STATUS_NOT_SUPPORTED; this inline entry point avoids making the new core compilation unit a hard dependency.

Arguments:

    RequestPacket - Input removal request.
    ResponsePacket - Input/output removal response.

Return Value:

    Returns: NTSTATUS of the specific removal implementation; returns STATUS_INVALID_PARAMETER for unknown categories.

--*/
{
    if (requestPacket == NULL || responsePacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

#if !defined(KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL)
    UNREFERENCED_PARAMETER(ResponsePacket);
#endif

    switch (requestPacket->callbackClass) {
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT:
#if defined(KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL)
        return kswordArkCallbackExternalWfpRemove(requestPacket, responsePacket);
#else
        return STATUS_NOT_SUPPORTED;
#endif

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER:
#if defined(KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL)
        return kswordArkCallbackExternalMinifilterRemove(requestPacket, responsePacket);
#else
        return STATUS_NOT_SUPPORTED;
#endif

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER:
#if defined(KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL)
        return kswordArkCallbackExternalSafeRemove(requestPacket, responsePacket);
#else
        return STATUS_NOT_SUPPORTED;
#endif

    default:
        return STATUS_INVALID_PARAMETER;
    }
}
