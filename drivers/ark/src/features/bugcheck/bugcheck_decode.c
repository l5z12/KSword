/*++

Module Name:

    bugcheck_decode.c

Abstract:

    Crash-safe decoding of documented BugCheck address parameters. The helper
    is kept independent of module lookup so it can be replayed in user mode.

--*/

#include "bugcheck_decode.h"

#include <ntstrsafe.h>

static BOOLEAN
kswordArkBugcheckDecodeVerifierAddress(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _Out_ PULONG_PTR address,
    _Out_ PULONG parameterIndex,
    _Out_ PCSTR* meaning
    )
{
    if (diagnostics->bugCheckCode == 0x000000C4) {
        switch (diagnostics->parameter1) {
        case 0xDA:
            *address = diagnostics->parameter3;
            *parameterIndex = 3;
            *meaning = "WMI callback address inside unloading driver";
            return TRUE;
        case 0xDD:
        case 0xE3:
        case 0xE4:
        case 0xE6:
        case 0xFC:
        case 0x110:
        case 0x111:
        case 0x2000:
        case 0x2001:
        case 0x2002:
            *address = diagnostics->parameter2;
            *parameterIndex = 2;
            *meaning = "documented address inside the verified driver";
            return TRUE;
        case 0xF6:
            *address = diagnostics->parameter4;
            *parameterIndex = 4;
            *meaning = "driver address that referenced the handle";
            return TRUE;
        case 0xFA:
        case 0xFB:
            *address = diagnostics->parameter2;
            *parameterIndex = 2;
            *meaning = "driver completion routine address";
            return TRUE;
        default:
            return FALSE;
        }
    }

    if (diagnostics->bugCheckCode == 0x000000C9) {
        switch (diagnostics->parameter1) {
        case 0x07:
            *address = diagnostics->parameter2;
            *parameterIndex = 2;
            *meaning = "driver cancel routine address";
            return TRUE;
        case 0x11:
        case 0x12:
            *address = diagnostics->parameter2;
            *parameterIndex = 2;
            *meaning = "driver dispatch routine address";
            return TRUE;
        default:
            return FALSE;
        }
    }
    return FALSE;
}

BOOLEAN
kswordArkBugcheckDecodePrimaryAddress(
    _Inout_ PkswordArkBugcheckDiagnostics diagnostics,
    _Out_ PULONG_PTR address,
    _Out_ PULONG parameterIndex,
    _Out_ PULONG confidence
    )
{
    PCSTR meaning;

    if (diagnostics == NULL || address == NULL || parameterIndex == NULL ||
        confidence == NULL) {
        return FALSE;
    }

    meaning = "stop code has no direct instruction address";
    *address = 0;
    *parameterIndex = 0;
    *confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE;

    switch (diagnostics->bugCheckCode) {
    case 0x0000000A:
    case 0x000000D1:
        *address = diagnostics->parameter4;
        *parameterIndex = 4;
        *confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        meaning = "instruction address that referenced memory";
        break;
    case 0x0000001E:
    case 0x0000003B:
    case 0x0000007E:
        *address = diagnostics->parameter2;
        *parameterIndex = 2;
        *confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        meaning = "exception instruction address";
        break;
    case 0x00000050:
        *address = diagnostics->parameter3;
        *parameterIndex = 3;
        *confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM;
        meaning = "instruction address that referenced memory";
        break;
    case 0x000000C5:
        *address = diagnostics->parameter4;
        *parameterIndex = 4;
        *confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        meaning = "instruction address that referenced memory";
        break;
    case 0x000000D5:
        *address = diagnostics->parameter3;
        *parameterIndex = 3;
        *confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM;
        meaning = "instruction address that referenced memory";
        break;
    case 0x00000116:
    case 0x00000117:
        *address = diagnostics->parameter2;
        *parameterIndex = 2;
        *confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        meaning = "pointer inside responsible display module";
        break;
    case 0x000000C4:
    case 0x000000C9:
        if (kswordArkBugcheckDecodeVerifierAddress(
                diagnostics,
                address,
                parameterIndex,
                &meaning)) {
            *confidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
        }
        break;
    default:
        break;
    }

    diagnostics->faultAddress = *address;
    diagnostics->faultParameter = *parameterIndex;
    (VOID)RtlStringCbCopyA(
        diagnostics->faultMeaning,
        sizeof(diagnostics->faultMeaning),
        meaning);
    return (*address != 0 && *confidence != KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE)
        ? TRUE
        : FALSE;
}

static PCSTR
kswordArkBugcheckDecodePowerRole(
    _In_ ULONG_PTR subtype,
    _In_ ULONG parameterIndex
    )
{
    if (parameterIndex == 1) {
        return "VIOLATION TYPE";
    }
    switch (subtype) {
    case 0x1:
        return parameterIndex == 2 ? "DEVICE OBJECT" : "RESERVED";
    case 0x2:
        if (parameterIndex == 2) return "TARGET DEVICE";
        if (parameterIndex == 3) return "DEVICE OBJECT";
        return "DRIVER OBJECT";
    case 0x3:
        if (parameterIndex == 2) return "PHYSICAL DEVICE";
        if (parameterIndex == 3) return "POWER TRIAGE";
        return "BLOCKED IRP";
    case 0x4:
        if (parameterIndex == 2) return "TIMEOUT SECONDS";
        if (parameterIndex == 3) return "PNP LOCK THREAD";
        return "PNP TRIAGE";
    case 0x5:
        if (parameterIndex == 2) return "PHYSICAL DEVICE";
        if (parameterIndex == 3) return "POWER DEVICE";
        return "RESERVED";
    case 0x6:
        if (parameterIndex == 2) return "POWER DEVICE";
        if (parameterIndex == 3) return "POWER DIRECTION";
        return "RESERVED";
    case 0x500:
        if (parameterIndex == 2) return "RESERVED";
        if (parameterIndex == 3) return "TARGET DEVICE";
        return "DEVICE OBJECT";
    default:
        return "SUBTYPE DATA";
    }
}

static PCSTR
kswordArkBugcheckDecodeVerifierRole(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG parameterIndex
    )
{
    const ULONG_PTR kSubtype = diagnostics->parameter1;

    if (parameterIndex == 1) {
        return "VIOLATION CODE";
    }
    if (diagnostics->bugCheckCode == 0x000000C9) {
        if (kSubtype == 0x07) {
            return parameterIndex == 2 ? "CANCEL ROUTINE" :
                (parameterIndex == 3 ? "IRP" : "RESERVED");
        }
        if (kSubtype == 0x11 || kSubtype == 0x12) {
            return parameterIndex == 2 ? "DRIVER ROUTINE" :
                (parameterIndex == 3 ? "IRQL BEFORE" : "CURRENT IRQL");
        }
        return "VIOLATION DATA";
    }

    switch (kSubtype) {
    case 0xDA:
        return parameterIndex == 2 ? "DRIVER BASE" :
            (parameterIndex == 3 ? "WMI CALLBACK" : "RESERVED");
    case 0xDD:
        return parameterIndex == 2 ? "REGISTER CALL" :
            (parameterIndex == 3 ? "DRIVER BASE" : "REG HANDLE");
    case 0xE3:
    case 0xE4:
        return parameterIndex == 2 ? "CALL ADDRESS" :
            (parameterIndex == 3 ? "BAD ARGUMENT" : "RESERVED");
    case 0xE6:
        return parameterIndex == 2 ? "DRIVER ADDRESS" :
            (parameterIndex == 3 ? "CURRENT IRQL" : "APC STATE");
    case 0xF6:
        return parameterIndex == 2 ? "HANDLE" :
            (parameterIndex == 3 ? "PROCESS OBJECT" : "DRIVER ADDRESS");
    case 0xFA:
        return parameterIndex == 2 ? "COMPLETION ROUTINE" :
            (parameterIndex == 3 ? "IRQL BEFORE" : "IRQL AFTER");
    case 0xFB:
        return parameterIndex == 2 ? "COMPLETION ROUTINE" :
            (parameterIndex == 3 ? "APC DISABLE CURRENT" : "APC DISABLE BEFORE");
    case 0x110:
        return parameterIndex == 2 ? "ISR ADDRESS" :
            (parameterIndex == 3 ? "CONTEXT BEFORE" : "CONTEXT AFTER");
    case 0x111:
        return parameterIndex == 2 ? "ISR ADDRESS" :
            (parameterIndex == 3 ? "IRQL BEFORE" : "IRQL AFTER");
    case 0x2000:
    case 0x2001:
    case 0x2002:
        return parameterIndex == 2 ? "DRIVER ADDRESS" : "POLICY VALUE";
    default:
        return "VIOLATION DATA";
    }
}

PCSTR
kswordArkBugcheckDecodeParameterRole(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG parameterIndex
    )
{
    static const PCSTR kGenericRoles[4] = {
        "PARAMETER 1", "PARAMETER 2", "PARAMETER 3", "PARAMETER 4"
    };

    if (diagnostics == NULL || parameterIndex < 1 || parameterIndex > 4) {
        return "PARAMETER";
    }

    switch (diagnostics->bugCheckCode) {
    case 0x0000000A:
    case 0x000000D1:
        return parameterIndex == 1 ? "MEMORY" :
            (parameterIndex == 2 ? "IRQL" :
             (parameterIndex == 3 ? "ACCESS TYPE" : "INSTRUCTION"));
    case 0x0000001E:
    case 0x0000007E:
        return parameterIndex == 1 ? "EXCEPTION CODE" :
            (parameterIndex == 2 ? "INSTRUCTION" : "EXCEPTION DATA");
    case 0x0000003B:
        return parameterIndex == 1 ? "EXCEPTION CODE" :
            (parameterIndex == 2 ? "INSTRUCTION" :
             (parameterIndex == 3 ? "CONTEXT RECORD" : "RESERVED"));
    case 0x00000050:
        return parameterIndex == 1 ? "MEMORY" :
            (parameterIndex == 2 ? "ACCESS TYPE" :
             (parameterIndex == 3 ? "INSTRUCTION" : "RESERVED"));
    case 0x0000009F:
        return kswordArkBugcheckDecodePowerRole(
            diagnostics->parameter1,
            parameterIndex);
    case 0x000000C4:
    case 0x000000C9:
        return kswordArkBugcheckDecodeVerifierRole(
            diagnostics,
            parameterIndex);
    case 0x000000C5:
        return parameterIndex == 1 ? "MEMORY" :
            (parameterIndex == 2 ? "CURRENT IRQL" :
             (parameterIndex == 3 ? "ACCESS TYPE" : "INSTRUCTION"));
    case 0x000000D5:
        return parameterIndex == 1 ? "MEMORY" :
            (parameterIndex == 2 ? "ACCESS TYPE" :
             (parameterIndex == 3 ? "INSTRUCTION" : "RESERVED"));
    case 0x000000EA:
        return parameterIndex == 1 ? "STUCK THREAD" :
            (parameterIndex == 2 ? "WATCHDOG" :
             (parameterIndex == 3 ? "DRIVER NAME" : "HIT COUNT"));
    case 0x000000EF:
        return parameterIndex == 1 ? "PROCESS OBJECT" :
            (parameterIndex == 2 ? "OBJECT TYPE" : "RESERVED");
    case 0x00000116:
    case 0x00000117:
        return parameterIndex == 1 ? "TDR CONTEXT" :
            (parameterIndex == 2 ? "DRIVER ADDRESS" :
             (parameterIndex == 3 ? "ERROR CODE" : "INTERNAL DATA"));
    default:
        return kGenericRoles[parameterIndex - 1UL];
    }
}
