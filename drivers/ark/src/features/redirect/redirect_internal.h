#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "ark/ark_redirect.h"
#include "ark/ark_log.h"

#define KSWORD_ARK_REDIRECT_TAG_RULES 'rRsK'
#define KSWORD_ARK_REDIRECT_TAG_PATH  'pRsK'

typedef struct KswordArkRedirectRuntime
{
    EX_PUSH_LOCK lock;
    WDFDEVICE device;
    LARGE_INTEGER registryCookie;
    NTSTATUS registryRegisterStatus;
    ULONG runtimeFlags;
    ULONG fileRuleCount;
    ULONG registryRuleCount;
    ULONG generation;
    volatile LONG64 fileRedirectHits;
    volatile LONG64 registryRedirectHits;
    KSWORD_ARK_REDIRECT_RULE rules[KSWORD_ARK_REDIRECT_MAX_RULES];
} KswordArkRedirectRuntime;

EXTERN_C_START

KswordArkRedirectRuntime*
kswordArkRedirectGetRuntime(
    VOID
    );

VOID
kswordArkRedirectLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    );

ULONG
kswordArkRedirectCountRulesByTypeLocked(
    _In_ const KswordArkRedirectRuntime* runtime,
    _In_ ULONG type
    );

BOOLEAN
kswordArkRedirectIsRulePathValid(
    _In_ const WCHAR* text,
    _In_ ULONG maxChars,
    _Out_ USHORT* lengthCharsOut
    );

NTSTATUS
kswordArkRedirectCopyUnicodeToAllocatedString(
    _In_ const UNICODE_STRING* source,
    _Out_ UNICODE_STRING* destination,
    _In_ ULONG poolTag
    );

NTSTATUS
kswordArkRedirectFindMatchLocked(
    _In_ KswordArkRedirectRuntime* runtime,
    _In_ ULONG type,
    _In_ ULONG processId,
    _In_ const UNICODE_STRING* sourcePath,
    _Out_ KSWORD_ARK_REDIRECT_RULE* matchedRuleOut
    );

NTSTATUS
kswordArkRedirectRegistryRegister(
    _In_ KswordArkRedirectRuntime* runtime,
    _In_ PDRIVER_OBJECT driverObject
    );

VOID
kswordArkRedirectRegistryUnregister(
    _In_ KswordArkRedirectRuntime* runtime
    );

EXTERN_C_END
