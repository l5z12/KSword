/*++

Module Name:

    dyndata_loader.c

Abstract:

    Lightweight System Informer DynData loader and Ksword offset activator.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_dyndata.h"
#include "ark/ark_push_lock.h"
#include "ark/ark_dyndata_fields.h"
#include "ark/ark_log.h"
#include "../../platform/dyndata_fallback_resolver.h"
#include "../../platform/kernel_module_identity.h"
#include "../../platform/process_resolver.h"
#include "ksw_si_dynconfig.h"

#include <ntstrsafe.h>

#define STATUS_SI_DYNDATA_UNSUPPORTED_KERNEL ((NTSTATUS)0xE0020001L)
#define STATUS_SI_DYNDATA_VERSION_MISMATCH   ((NTSTATUS)0xE0020002L)
#define STATUS_SI_DYNDATA_INVALID_LENGTH     ((NTSTATUS)0xE0020003L)

static KswDynState gKswordDynDataState;
static EX_PUSH_LOCK gKswordDynDataStateLock;

static const KswKernelModuleNameMatch kGKswordDynNtosNames[] = {
    { "ntoskrnl.exe", KSW_DYN_PROFILE_CLASS_NTOSKRNL },
    { "ntkrnlmp.exe", KSW_DYN_PROFILE_CLASS_NTOSKRNL },
    { "ntkrla57.exe", KSW_DYN_PROFILE_CLASS_NTKRLA57 }
};

static const KswKernelModuleNameMatch kGKswordDynLxcoreNames[] = {
    { "lxcore.sys", KSW_DYN_PROFILE_CLASS_LXCORE }
};

static VOID
kswordArkDynDataSetReason(
    _Inout_ KswDynState* state,
    _In_z_ PCWSTR reasonText
    )
/*++

Routine Description:

    Store a bounded human-readable DynData unavailability reason in the state.

Arguments:

    State - Mutable DynData state.
    ReasonText - NUL-terminated reason text.

Return Value:

    None.

--*/
{
    if (state == NULL) {
        return;
    }

    state->unavailableReason[0] = L'\0';
    if (reasonText == NULL) {
        return;
    }

    (VOID)RtlStringCchCopyW(
        state->unavailableReason,
        KSW_DYN_REASON_CHARS,
        reasonText);
    state->unavailableReason[KSW_DYN_REASON_CHARS - 1U] = L'\0';
}

static VOID
kswordArkDynDataInitializeKernelOffsets(
    _Out_ KswDynKernelOffsets* offsets
    )
/*++

Routine Description:

    initialize every kernel offset to the explicit unavailable sentinel.

Arguments:

    Offsets - Kernel offset block to initialize.

Return Value:

    None.

--*/
{
    if (offsets == NULL) {
        return;
    }

    offsets->epObjectTable = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSectionObject = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epUniqueProcessId = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epActiveProcessLinks = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epThreadListHead = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epImageFileName = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epToken = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epFlags = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epFlags2 = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epRundownProtect = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epProcessLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epCreateTime = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epExitTime = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epExitStatus = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epPeb = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSession = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epWin32Process = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epWow64Process = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epInheritedFromUniqueProcessId = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSeAuditProcessCreationInfo = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epJob = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epDeviceMap = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epDebugPort = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epExceptionPortData = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSectionBaseAddress = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epImageFilePointer = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epPriorityClass = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epActiveThreads = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epVadRoot = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epVadHint = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epCloneRoot = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epNumberOfPrivatePages = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epNumberOfLockedPages = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epCommitCharge = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epCommitChargePeak = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epPeakVirtualSize = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epVirtualSize = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSessionProcessLinks = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epMitigationFlags = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epMitigationFlags2 = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epProcessQuotaUsage = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epProcessQuotaPeak = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epAddressCreationLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epPageTableCommitmentLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epRotateInProgress = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epForkInProgress = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epCommitChargeJob = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epCookie = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epWorkingSetWatch = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epWin32WindowStation = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epOwnerProcessId = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epQuotaBlock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epEtwDataSource = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epPageDirectoryPte = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSecurityPort = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epJobLinks = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epHighestUserAddress = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epImagePathHash = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epDefaultHardErrorProcessing = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epLastThreadExitStatus = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epPrefetchTrace = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epLockedPagesList = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epReadOperationCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epWriteOperationCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epOtherOperationCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epReadTransferCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epWriteTransferCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epOtherTransferCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epCommitChargeLimit = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epVm = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epMmProcessLinks = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epModifiedPageCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epVadCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epVadPhysicalPages = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epVadPhysicalPagesLimit = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epAlpcContext = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epTimerResolutionLink = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epTimerResolutionStackRecord = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epRequestedTimerResolution = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSmallestTimerResolution = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epInvertedFunctionTable = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epInvertedFunctionTableLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epActiveThreadsHighWatermark = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epLargePrivateVadCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epThreadListLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epWnfContext = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epFlags3 = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epDiskCounters = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTokenSource = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTokenId = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokAuthenticationId = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokParentTokenId = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokExpirationTime = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTokenLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokModifiedId = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokPrivileges = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokAuditPolicy = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokSessionId = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokUserAndGroupCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokRestrictedSidCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokVariableLength = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokDynamicCharged = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokDynamicAvailable = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokDefaultOwnerIndex = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokUserAndGroups = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokRestrictedSids = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokPrimaryGroup = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokDynamicPart = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokDefaultDacl = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTokenType = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokImpersonationLevel = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTokenFlags = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTokenInUse = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokIntegrityLevelIndex = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokMandatoryPolicy = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokLogonSession = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokOriginatingLogonSession = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokSidHash = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokRestrictedSidHash = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokPSecurityAttributes = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokPackage = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokCapabilities = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokCapabilityCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokCapabilitiesHash = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokLowboxNumberEntry = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokLowboxHandlesEntry = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokPClaimAttributes = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTrustLevelSid = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTrustLinkedToken = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokIntegrityLevelSidValue = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokTokenSidValues = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokSessionObject = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->tokVariablePart = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->etCid = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->etThreadListEntry = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->etStartAddress = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->etWin32StartAddress = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktProcess = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->htHandleContentionEvent = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->htTableCode = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->htHandleCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->hteLowValue = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->otName = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->otIndex = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->obDecodeShift = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->obAttributesShift = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->egeGuid = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ereGuidEntry = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktInitialStack = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktStackLimit = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktStackBase = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktKernelStack = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktReadOperationCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktWriteOperationCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktOtherOperationCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktReadTransferCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktWriteTransferCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->ktOtherTransferCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->mmSectionControlArea = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->mmControlAreaListHead = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->mmControlAreaLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcCommunicationInfo = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcOwnerProcess = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcConnectionPort = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcServerCommunicationPort = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcClientCommunicationPort = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcHandleTable = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcHandleTableLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcAttributes = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcAttributesFlags = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcPortContext = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcPortObjectLock = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcSequenceNo = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->alpcState = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epProtection = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSignatureLevel = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->epSectionSignatureLevel = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->kldrInLoadOrderLinks = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->kldrDllBase = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->kldrSizeOfImage = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->kldrFullDllName = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->kldrBaseDllName = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->kldrFlags = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->doDriverStart = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->doDriverSize = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->doDriverSection = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->doMajorFunction = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->doFastIoDispatch = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->doDriverUnload = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->uldName = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->uldStartAddress = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->uldEndAddress = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->uldCurrentTime = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->uldTypeSize = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->rtlAvlBalancedRoot = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->rtlAvlOrderedPointer = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->rtlAvlWhichOrderedElement = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->rtlAvlNumberGenericTableElements = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->rtlAvlDepthOfTree = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->rtlAvlRestartKey = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->rtlAvlDeleteCount = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->rtlAvlTypeSize = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->piDdbDriverName = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->piDdbTimeDateStamp = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->piDdbLoadStatus = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->piDdbTypeSize = KSW_DYN_OFFSET_UNAVAILABLE;
}

static VOID
kswordArkDynDataInitializeLxcoreOffsets(
    _Out_ KswDynLxcoreOffsets* offsets
    )
/*++

Routine Description:

    initialize every lxcore offset to the explicit unavailable sentinel.

Arguments:

    Offsets - Lxcore offset block to initialize.

Return Value:

    None.

--*/
{
    if (offsets == NULL) {
        return;
    }

    offsets->lxPicoProc = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->lxPicoProcInfo = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->lxPicoProcInfoPid = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->lxPicoThrdInfo = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->lxPicoThrdInfoTid = KSW_DYN_OFFSET_UNAVAILABLE;
}

static VOID
kswordArkDynDataInitializeKernelGlobals(
    _Out_ KswDynKernelGlobals* globals
    )
/*++

Routine Description:

    initialize every non-callback kernel global RVA slot to the unavailable
    sentinel. These entries are optional PDB profile data for future cross-view,
    driver integrity, and kernel-memory attribution features.

Arguments:

    Globals - Kernel global RVA block to initialize.

Return Value:

    None.

--*/
{
    if (globals == NULL) {
        return;
    }

    globals->pspCidTable = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->psLoadedModuleList = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->mmUnloadedDrivers = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->piDdbCacheTable = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->piDdbLock = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->keServiceDescriptorTableShadow = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->mmLastUnloadedDriver = KSW_DYN_OFFSET_UNAVAILABLE;
}

static VOID
kswordArkDynDataInitializeCallbackGlobals(
    _Out_ KswDynCallbackGlobals* globals
    )
/*++

Routine Description:

    initialize every callback global RVA slot to the explicit unavailable
    sentinel. PDB profile v2 stores RVAs rather than kernel virtual addresses so
    identity checks stay tied to the loaded ntoskrnl image.

Arguments:

    Globals - Callback global RVA block to initialize.

Return Value:

    None.

--*/
{
    if (globals == NULL) {
        return;
    }

    globals->pspCreateProcessNotifyRoutine = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->pspCreateThreadNotifyRoutine = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->pspLoadImageNotifyRoutine = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->pspNotifyEnableMask = KSW_DYN_OFFSET_UNAVAILABLE;
    globals->cmCallbackListHead = KSW_DYN_OFFSET_UNAVAILABLE;
}

static VOID
kswordArkDynDataInitializeCallbackOffsets(
    _Out_ KswDynCallbackOffsets* offsets
    )
/*++

Routine Description:

    initialize every callback structure offset to the explicit unavailable
    sentinel. These offsets are consumed only by callback enumeration/removal
    code after the matching ntoskrnl PDB profile has been applied.

Arguments:

    Offsets - Callback structure offset block to initialize.

Return Value:

    None.

--*/
{
    if (offsets == NULL) {
        return;
    }

    offsets->objectTypeCallbackList = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->callbackEntryItemEntryList = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->callbackEntryItemPreOperation = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->callbackEntryItemPostOperation = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->callbackEntryItemOperations = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->callbackEntryItemCallbackEntry = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->callbackEntryAltitude = KSW_DYN_OFFSET_UNAVAILABLE;
    offsets->callbackEntryRegistrationContext = KSW_DYN_OFFSET_UNAVAILABLE;
}

static ULONG
kswordArkDynDataConvertOffset(
    _In_ USHORT sourceOffset
    )
/*++

Routine Description:

    Convert a System Informer USHORT offset into Ksword's ULONG offset format.

Arguments:

    SourceOffset - System Informer raw field value.

Return Value:

    ULONG field offset, or KSW_DYN_OFFSET_UNAVAILABLE for the 0xffff sentinel.

--*/
{
    if (sourceOffset == 0xFFFFU) {
        return KSW_DYN_OFFSET_UNAVAILABLE;
    }

    return (ULONG)sourceOffset;
}

static BOOLEAN
kswordArkDynDataOffsetPresent(
    _In_ ULONG offset
    )
/*++

Routine Description:

    Test whether one normalized DynData offset is usable. The helper is kept in
    the loader because profile application and System Informer conversion both
    need the same sentinel handling before they assign provenance.

Arguments:

    Offset - Normalized ULONG offset value.

Return Value:

    TRUE when the offset can be used; otherwise FALSE.

--*/
{
    return (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL) ? TRUE : FALSE;
}

static VOID
kswordArkDynDataStoreSourcedOffset(
    _In_ ULONG offset,
    _In_ ULONG source,
    _Out_ ULONG* destinationOffset,
    _Out_ ULONG* destinationSource
    )
/*++

Routine Description:

    Store a normalized offset and its provenance together. Missing offsets always
    clear the source to UNAVAILABLE so later query paths do not guess from static
    descriptor defaults.

Arguments:

    Offset - Normalized offset value.
    Source - KSW_DYN_FIELD_SOURCE_* value for a present offset.
    DestinationOffset - Mutable offset field.
    DestinationSource - Mutable source field parallel to DestinationOffset.

Return Value:

    None.

--*/
{
    if (destinationOffset == NULL || destinationSource == NULL) {
        return;
    }

    *destinationOffset = offset;
    *destinationSource = kswordArkDynDataOffsetPresent(offset) ? source : KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
}

static VOID
kswordArkDynDataStoreSystemInformerOffset(
    _In_ USHORT sourceOffset,
    _Out_ ULONG* destinationOffset,
    _Out_ ULONG* destinationSource
    )
/*++

Routine Description:

    Convert one System Informer USHORT offset and tag it with System Informer
    provenance when it is present.

Arguments:

    SourceOffset - Raw System Informer offset or 0xffff sentinel.
    DestinationOffset - Mutable normalized offset field.
    DestinationSource - Mutable source field parallel to DestinationOffset.

Return Value:

    None.

--*/
{
    kswordArkDynDataStoreSourcedOffset(
        kswordArkDynDataConvertOffset(sourceOffset),
        KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER,
        destinationOffset,
        destinationSource);
}

static BOOLEAN
kswordArkDynDataReadBlob(
    _In_ SIZE_T offset,
    _Out_writes_bytes_(bytesToRead) PVOID destination,
    _In_ SIZE_T bytesToRead
    )
/*++

Routine Description:

    Copy a bounded object from the vendored DynData byte blob after validating
    the requested range.

Arguments:

    Offset - Byte offset inside KphDynConfig.
    Destination - Destination buffer.
    BytesToRead - Number of bytes to copy.

Return Value:

    TRUE when the requested range is valid; otherwise FALSE.

--*/
{
    if (destination == NULL) {
        return FALSE;
    }
    if (offset > (SIZE_T)KphDynConfigLength) {
        return FALSE;
    }
    if (bytesToRead > ((SIZE_T)KphDynConfigLength - offset)) {
        return FALSE;
    }

    RtlCopyMemory(destination, KphDynConfig + offset, bytesToRead);
    return TRUE;
}

static NTSTATUS
kswordArkDynDataReadConfigHeader(
    _Out_ ULONG* versionOut,
    _Out_ ULONG* countOut,
    _Out_ SIZE_T* dataOffsetOut,
    _Out_ SIZE_T* fieldBaseOffsetOut
    )
/*++

Routine Description:

    Read the packed System Informer DynData header and compute the data/field
    base offsets without relying on naturally aligned structure reads.

Arguments:

    VersionOut - Receives KPH_DYN_CONFIG.Version.
    CountOut - Receives KPH_DYN_CONFIG.Count.
    DataOffsetOut - Receives byte offset of the KPH_DYN_DATA array.
    FieldBaseOffsetOut - Receives byte offset of the raw field payload block.

Return Value:

    STATUS_SUCCESS when the blob header is valid; otherwise invalid-length or
    version-mismatch status.

--*/
{
    ULONG version = 0UL;
    ULONG count = 0UL;
    SIZE_T dataOffset = FIELD_OFFSET(KPH_DYN_CONFIG, Data);
    SIZE_T countOffset = FIELD_OFFSET(KPH_DYN_CONFIG, Count);
    SIZE_T fieldBaseOffset = 0U;

    if (versionOut == NULL || countOut == NULL || dataOffsetOut == NULL || fieldBaseOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!kswordArkDynDataReadBlob(FIELD_OFFSET(KPH_DYN_CONFIG, Version), &version, sizeof(version)) ||
        !kswordArkDynDataReadBlob(countOffset, &count, sizeof(count))) {
        return STATUS_SI_DYNDATA_INVALID_LENGTH;
    }
    if (version != KPH_DYN_CONFIGURATION_VERSION) {
        return STATUS_SI_DYNDATA_VERSION_MISMATCH;
    }
    if (count == 0UL || count > 100000UL) {
        return STATUS_SI_DYNDATA_INVALID_LENGTH;
    }
    if (dataOffset > (SIZE_T)KphDynConfigLength) {
        return STATUS_SI_DYNDATA_INVALID_LENGTH;
    }
    if ((SIZE_T)count > (((SIZE_T)KphDynConfigLength - dataOffset) / sizeof(KPH_DYN_DATA))) {
        return STATUS_SI_DYNDATA_INVALID_LENGTH;
    }

    fieldBaseOffset = dataOffset + ((SIZE_T)count * sizeof(KPH_DYN_DATA));
    if (fieldBaseOffset > (SIZE_T)KphDynConfigLength) {
        return STATUS_SI_DYNDATA_INVALID_LENGTH;
    }

    *versionOut = version;
    *countOut = count;
    *dataOffsetOut = dataOffset;
    *fieldBaseOffsetOut = fieldBaseOffset;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDynDataFindProfile(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* identity,
    _In_ SIZE_T expectedPayloadBytes,
    _Out_ KPH_DYN_DATA* matchedDataOut,
    _Out_ SIZE_T* payloadOffsetOut
    )
/*++

Routine Description:

    Locate one exact DynData profile by class, machine, timestamp, and image
    size. Duplicate matches are rejected as data corruption.

Arguments:

    Identity - Loaded module identity packet.
    ExpectedPayloadBytes - Minimum bytes required for the target field body.
    MatchedDataOut - Receives the matched KPH_DYN_DATA row.
    PayloadOffsetOut - Receives the byte offset of the raw field payload.

Return Value:

    STATUS_SUCCESS on exactly one match, STATUS_SI_DYNDATA_UNSUPPORTED_KERNEL on
    no match, or STATUS_SI_DYNDATA_VERSION_MISMATCH on duplicate match.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG version = 0UL;
    ULONG count = 0UL;
    SIZE_T dataOffset = 0U;
    SIZE_T fieldBaseOffset = 0U;
    ULONG index = 0UL;
    ULONG matchCount = 0UL;
    KPH_DYN_DATA matchedData = { 0 };
    SIZE_T matchedPayloadOffset = 0U;

    if (identity == NULL || matchedDataOut == NULL || payloadOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (identity->present == 0UL) {
        return STATUS_NOT_FOUND;
    }

    status = kswordArkDynDataReadConfigHeader(&version, &count, &dataOffset, &fieldBaseOffset);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    UNREFERENCED_PARAMETER(version);

    for (index = 0UL; index < count; ++index) {
        KPH_DYN_DATA dynData = { 0 };
        SIZE_T entryOffset = dataOffset + ((SIZE_T)index * sizeof(KPH_DYN_DATA));
        SIZE_T payloadOffset = 0U;

        if (!kswordArkDynDataReadBlob(entryOffset, &dynData, sizeof(dynData))) {
            return STATUS_SI_DYNDATA_INVALID_LENGTH;
        }
        if ((ULONG)dynData.Class != identity->classId ||
            (ULONG)dynData.Machine != identity->machine ||
            dynData.TimeDateStamp != identity->timeDateStamp ||
            dynData.SizeOfImage != identity->sizeOfImage) {
            continue;
        }

        payloadOffset = fieldBaseOffset + (SIZE_T)dynData.Offset;
        if (payloadOffset > (SIZE_T)KphDynConfigLength ||
            expectedPayloadBytes > ((SIZE_T)KphDynConfigLength - payloadOffset)) {
            return STATUS_SI_DYNDATA_INVALID_LENGTH;
        }

        matchCount += 1UL;
        matchedData = dynData;
        matchedPayloadOffset = payloadOffset;
    }

    if (matchCount == 0UL) {
        return STATUS_SI_DYNDATA_UNSUPPORTED_KERNEL;
    }
    if (matchCount > 1UL) {
        return STATUS_SI_DYNDATA_VERSION_MISMATCH;
    }

    *matchedDataOut = matchedData;
    *payloadOffsetOut = matchedPayloadOffset;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDynDataActivateKernelFields(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* identity,
    _Inout_ KswDynState* state
    )
/*++

Routine Description:

    Match and convert the current ntoskrnl/ntkrla57 System Informer field body
    into Ksword's internal kernel offset block.

Arguments:

    Identity - Current kernel image identity.
    State - Mutable DynData state that receives converted offsets.

Return Value:

    STATUS_SUCCESS when the kernel profile was activated; otherwise match or
    validation failure status.

--*/
{
    KPH_DYN_DATA dynData = { 0 };
    KPH_DYN_KERNEL_FIELDS fields = { 0 };
    SIZE_T payloadOffset = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (identity == NULL || state == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDynDataFindProfile(
        identity,
        sizeof(fields),
        &dynData,
        &payloadOffset);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!kswordArkDynDataReadBlob(payloadOffset, &fields, sizeof(fields))) {
        return STATUS_SI_DYNDATA_INVALID_LENGTH;
    }

    state->ntosActive = TRUE;
    state->matchedProfileClass = (ULONG)dynData.Class;
    state->matchedProfileOffset = dynData.Offset;
    state->matchedFieldsId = 0UL;
    kswordArkDynDataStoreSystemInformerOffset(fields.EpObjectTable, &state->kernel.epObjectTable, &state->kernelSources.epObjectTable);
    kswordArkDynDataStoreSystemInformerOffset(fields.EpSectionObject, &state->kernel.epSectionObject, &state->kernelSources.epSectionObject);
    kswordArkDynDataStoreSystemInformerOffset(fields.HtHandleContentionEvent, &state->kernel.htHandleContentionEvent, &state->kernelSources.htHandleContentionEvent);
    kswordArkDynDataStoreSystemInformerOffset(fields.OtName, &state->kernel.otName, &state->kernelSources.otName);
    kswordArkDynDataStoreSystemInformerOffset(fields.OtIndex, &state->kernel.otIndex, &state->kernelSources.otIndex);
    kswordArkDynDataStoreSystemInformerOffset(fields.ObDecodeShift, &state->kernel.obDecodeShift, &state->kernelSources.obDecodeShift);
    kswordArkDynDataStoreSystemInformerOffset(fields.ObAttributesShift, &state->kernel.obAttributesShift, &state->kernelSources.obAttributesShift);
    kswordArkDynDataStoreSystemInformerOffset(fields.EgeGuid, &state->kernel.egeGuid, &state->kernelSources.egeGuid);
    kswordArkDynDataStoreSystemInformerOffset(fields.EreGuidEntry, &state->kernel.ereGuidEntry, &state->kernelSources.ereGuidEntry);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtInitialStack, &state->kernel.ktInitialStack, &state->kernelSources.ktInitialStack);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtStackLimit, &state->kernel.ktStackLimit, &state->kernelSources.ktStackLimit);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtStackBase, &state->kernel.ktStackBase, &state->kernelSources.ktStackBase);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtKernelStack, &state->kernel.ktKernelStack, &state->kernelSources.ktKernelStack);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtReadOperationCount, &state->kernel.ktReadOperationCount, &state->kernelSources.ktReadOperationCount);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtWriteOperationCount, &state->kernel.ktWriteOperationCount, &state->kernelSources.ktWriteOperationCount);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtOtherOperationCount, &state->kernel.ktOtherOperationCount, &state->kernelSources.ktOtherOperationCount);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtReadTransferCount, &state->kernel.ktReadTransferCount, &state->kernelSources.ktReadTransferCount);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtWriteTransferCount, &state->kernel.ktWriteTransferCount, &state->kernelSources.ktWriteTransferCount);
    kswordArkDynDataStoreSystemInformerOffset(fields.KtOtherTransferCount, &state->kernel.ktOtherTransferCount, &state->kernelSources.ktOtherTransferCount);
    kswordArkDynDataStoreSystemInformerOffset(fields.MmSectionControlArea, &state->kernel.mmSectionControlArea, &state->kernelSources.mmSectionControlArea);
    kswordArkDynDataStoreSystemInformerOffset(fields.MmControlAreaListHead, &state->kernel.mmControlAreaListHead, &state->kernelSources.mmControlAreaListHead);
    kswordArkDynDataStoreSystemInformerOffset(fields.MmControlAreaLock, &state->kernel.mmControlAreaLock, &state->kernelSources.mmControlAreaLock);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcCommunicationInfo, &state->kernel.alpcCommunicationInfo, &state->kernelSources.alpcCommunicationInfo);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcOwnerProcess, &state->kernel.alpcOwnerProcess, &state->kernelSources.alpcOwnerProcess);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcConnectionPort, &state->kernel.alpcConnectionPort, &state->kernelSources.alpcConnectionPort);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcServerCommunicationPort, &state->kernel.alpcServerCommunicationPort, &state->kernelSources.alpcServerCommunicationPort);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcClientCommunicationPort, &state->kernel.alpcClientCommunicationPort, &state->kernelSources.alpcClientCommunicationPort);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcHandleTable, &state->kernel.alpcHandleTable, &state->kernelSources.alpcHandleTable);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcHandleTableLock, &state->kernel.alpcHandleTableLock, &state->kernelSources.alpcHandleTableLock);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcAttributes, &state->kernel.alpcAttributes, &state->kernelSources.alpcAttributes);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcAttributesFlags, &state->kernel.alpcAttributesFlags, &state->kernelSources.alpcAttributesFlags);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcPortContext, &state->kernel.alpcPortContext, &state->kernelSources.alpcPortContext);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcPortObjectLock, &state->kernel.alpcPortObjectLock, &state->kernelSources.alpcPortObjectLock);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcSequenceNo, &state->kernel.alpcSequenceNo, &state->kernelSources.alpcSequenceNo);
    kswordArkDynDataStoreSystemInformerOffset(fields.AlpcState, &state->kernel.alpcState, &state->kernelSources.alpcState);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDynDataActivateLxcoreFields(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* identity,
    _Inout_ KswDynState* state
    )
/*++

Routine Description:

    Match and convert optional lxcore.sys DynData fields for WSL/Pico support.

Arguments:

    Identity - Current lxcore.sys identity when the module is loaded.
    State - Mutable DynData state that receives lxcore offsets.

Return Value:

    STATUS_SUCCESS when lxcore fields were activated; STATUS_NOT_FOUND when the
    module is absent; otherwise exact-match failure status.

--*/
{
    KPH_DYN_DATA dynData = { 0 };
    KPH_DYN_LXCORE_FIELDS fields = { 0 };
    SIZE_T payloadOffset = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (identity == NULL || state == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (identity->present == 0UL) {
        return STATUS_NOT_FOUND;
    }

    status = kswordArkDynDataFindProfile(
        identity,
        sizeof(fields),
        &dynData,
        &payloadOffset);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!kswordArkDynDataReadBlob(payloadOffset, &fields, sizeof(fields))) {
        return STATUS_SI_DYNDATA_INVALID_LENGTH;
    }

    state->lxcoreActive = TRUE;
    kswordArkDynDataStoreSystemInformerOffset(fields.LxPicoProc, &state->lxcoreOffsets.lxPicoProc, &state->lxcoreSources.lxPicoProc);
    kswordArkDynDataStoreSystemInformerOffset(fields.LxPicoProcInfo, &state->lxcoreOffsets.lxPicoProcInfo, &state->lxcoreSources.lxPicoProcInfo);
    kswordArkDynDataStoreSystemInformerOffset(fields.LxPicoProcInfoPID, &state->lxcoreOffsets.lxPicoProcInfoPid, &state->lxcoreSources.lxPicoProcInfoPid);
    kswordArkDynDataStoreSystemInformerOffset(fields.LxPicoThrdInfo, &state->lxcoreOffsets.lxPicoThrdInfo, &state->lxcoreSources.lxPicoThrdInfo);
    kswordArkDynDataStoreSystemInformerOffset(fields.LxPicoThrdInfoTID, &state->lxcoreOffsets.lxPicoThrdInfoTid, &state->lxcoreSources.lxPicoThrdInfoTid);
    UNREFERENCED_PARAMETER(dynData);
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkDynDataStoreRuntimeOffset(
    _In_ LONG resolvedOffset,
    _Inout_ ULONG* destinationOffset,
    _Out_ ULONG* destinationSource
    )
/*++

Routine Description:

    Store one runtime-pattern offset and tag it with runtime provenance if the
    resolver produced a positive value.

Arguments:

    ResolvedOffset - Signed resolver result; negative values mean unavailable.
    DestinationOffset - Offset field to update.
    DestinationSource - Source field parallel to DestinationOffset.

Return Value:

    TRUE when the destination was already present or a runtime offset was
    stored; otherwise FALSE.

--*/
{
    if (destinationOffset == NULL || destinationSource == NULL) {
        return FALSE;
    }
    if (kswordArkDynDataOffsetPresent(*destinationOffset)) {
        return TRUE;
    }
    if (resolvedOffset < 0) {
        return FALSE;
    }

    kswordArkDynDataStoreSourcedOffset(
        (ULONG)resolvedOffset,
        KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN,
        destinationOffset,
        destinationSource);
    return TRUE;
}

static VOID
kswordArkDynDataActivateRuntimeOffsets(
    _Inout_ KswDynState* state,
    _In_opt_ PDRIVER_OBJECT validationDriverObject
    )
/*++

Routine Description:

    Resolve the bounded, live-validated read-only accessor offsets and the
    existing Ksword-specific EPROCESS protection offsets, then fill only fields
    that were not already supplied by System Informer or an applied PDB profile.

Arguments:

    State - Mutable DynData state.
    ValidationDriverObject - Live KSword driver object for KLDR/public-layout checks.

Return Value:

    None.

--*/
{
    KswordRuntimeDyndataOffsets resolved;
    KswRuntimeKernelLayout kernelLayout;
    BOOLEAN protectionPresent = FALSE;
    BOOLEAN signaturePresent = FALSE;
    BOOLEAN sectionSignaturePresent = FALSE;

    if (state == NULL) {
        return;
    }

    kswordArkDriverResolveReadOnlyDynDataOffsets(&resolved);
    kswordArkDriverResolveKernelFallbackLayout(
        validationDriverObject,
        &state->ntoskrnl,
        &kernelLayout);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epUniqueProcessId,
        &state->kernel.epUniqueProcessId,
        &state->kernelSources.epUniqueProcessId);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epActiveProcessLinks,
        &state->kernel.epActiveProcessLinks,
        &state->kernelSources.epActiveProcessLinks);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epThreadListHead,
        &state->kernel.epThreadListHead,
        &state->kernelSources.epThreadListHead);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epImageFileName,
        &state->kernel.epImageFileName,
        &state->kernelSources.epImageFileName);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epToken,
        &state->kernel.epToken,
        &state->kernelSources.epToken);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epFlags,
        &state->kernel.epFlags,
        &state->kernelSources.epFlags);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epCreateTime,
        &state->kernel.epCreateTime,
        &state->kernelSources.epCreateTime);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epExitStatus,
        &state->kernel.epExitStatus,
        &state->kernelSources.epExitStatus);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epPeb,
        &state->kernel.epPeb,
        &state->kernelSources.epPeb);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epWin32Process,
        &state->kernel.epWin32Process,
        &state->kernelSources.epWin32Process);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epWow64Process,
        &state->kernel.epWow64Process,
        &state->kernelSources.epWow64Process);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epInheritedFromUniqueProcessId,
        &state->kernel.epInheritedFromUniqueProcessId,
        &state->kernelSources.epInheritedFromUniqueProcessId);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epSectionBaseAddress,
        &state->kernel.epSectionBaseAddress,
        &state->kernelSources.epSectionBaseAddress);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epJob,
        &state->kernel.epJob,
        &state->kernelSources.epJob);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epDebugPort,
        &state->kernel.epDebugPort,
        &state->kernelSources.epDebugPort);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epPriorityClass,
        &state->kernel.epPriorityClass,
        &state->kernelSources.epPriorityClass);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epActiveThreads,
        &state->kernel.epActiveThreads,
        &state->kernelSources.epActiveThreads);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epWin32WindowStation,
        &state->kernel.epWin32WindowStation,
        &state->kernelSources.epWin32WindowStation);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.epSecurityPort,
        &state->kernel.epSecurityPort,
        &state->kernelSources.epSecurityPort);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.tokUserAndGroupCount,
        &state->kernel.tokUserAndGroupCount,
        &state->kernelSources.tokUserAndGroupCount);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.tokUserAndGroups,
        &state->kernel.tokUserAndGroups,
        &state->kernelSources.tokUserAndGroups);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.tokIntegrityLevelIndex,
        &state->kernel.tokIntegrityLevelIndex,
        &state->kernelSources.tokIntegrityLevelIndex);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.tokMandatoryPolicy,
        &state->kernel.tokMandatoryPolicy,
        &state->kernelSources.tokMandatoryPolicy);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.etCid,
        &state->kernel.etCid,
        &state->kernelSources.etCid);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.etThreadListEntry,
        &state->kernel.etThreadListEntry,
        &state->kernelSources.etThreadListEntry);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.etStartAddress,
        &state->kernel.etStartAddress,
        &state->kernelSources.etStartAddress);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.etWin32StartAddress,
        &state->kernel.etWin32StartAddress,
        &state->kernelSources.etWin32StartAddress);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.ktProcess,
        &state->kernel.ktProcess,
        &state->kernelSources.ktProcess);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.ktInitialStack,
        &state->kernel.ktInitialStack,
        &state->kernelSources.ktInitialStack);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.ktStackLimit,
        &state->kernel.ktStackLimit,
        &state->kernelSources.ktStackLimit);
    kswordArkDynDataStoreRuntimeOffset(
        resolved.ktStackBase,
        &state->kernel.ktStackBase,
        &state->kernelSources.ktStackBase);

    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.kldrInLoadOrderLinks,
        &state->kernel.kldrInLoadOrderLinks,
        &state->kernelSources.kldrInLoadOrderLinks);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.kldrDllBase,
        &state->kernel.kldrDllBase,
        &state->kernelSources.kldrDllBase);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.kldrSizeOfImage,
        &state->kernel.kldrSizeOfImage,
        &state->kernelSources.kldrSizeOfImage);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.kldrFullDllName,
        &state->kernel.kldrFullDllName,
        &state->kernelSources.kldrFullDllName);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.kldrBaseDllName,
        &state->kernel.kldrBaseDllName,
        &state->kernelSources.kldrBaseDllName);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.doDriverStart,
        &state->kernel.doDriverStart,
        &state->kernelSources.doDriverStart);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.doDriverSize,
        &state->kernel.doDriverSize,
        &state->kernelSources.doDriverSize);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.doDriverSection,
        &state->kernel.doDriverSection,
        &state->kernelSources.doDriverSection);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.doMajorFunction,
        &state->kernel.doMajorFunction,
        &state->kernelSources.doMajorFunction);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.doFastIoDispatch,
        &state->kernel.doFastIoDispatch,
        &state->kernelSources.doFastIoDispatch);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.doDriverUnload,
        &state->kernel.doDriverUnload,
        &state->kernelSources.doDriverUnload);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.rtlAvlBalancedRoot,
        &state->kernel.rtlAvlBalancedRoot,
        &state->kernelSources.rtlAvlBalancedRoot);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.rtlAvlOrderedPointer,
        &state->kernel.rtlAvlOrderedPointer,
        &state->kernelSources.rtlAvlOrderedPointer);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.rtlAvlWhichOrderedElement,
        &state->kernel.rtlAvlWhichOrderedElement,
        &state->kernelSources.rtlAvlWhichOrderedElement);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.rtlAvlNumberGenericTableElements,
        &state->kernel.rtlAvlNumberGenericTableElements,
        &state->kernelSources.rtlAvlNumberGenericTableElements);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.rtlAvlDepthOfTree,
        &state->kernel.rtlAvlDepthOfTree,
        &state->kernelSources.rtlAvlDepthOfTree);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.rtlAvlRestartKey,
        &state->kernel.rtlAvlRestartKey,
        &state->kernelSources.rtlAvlRestartKey);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.rtlAvlDeleteCount,
        &state->kernel.rtlAvlDeleteCount,
        &state->kernelSources.rtlAvlDeleteCount);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.rtlAvlTypeSize,
        &state->kernel.rtlAvlTypeSize,
        &state->kernelSources.rtlAvlTypeSize);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.uldName,
        &state->kernel.uldName,
        &state->kernelSources.uldName);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.uldStartAddress,
        &state->kernel.uldStartAddress,
        &state->kernelSources.uldStartAddress);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.uldEndAddress,
        &state->kernel.uldEndAddress,
        &state->kernelSources.uldEndAddress);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.uldCurrentTime,
        &state->kernel.uldCurrentTime,
        &state->kernelSources.uldCurrentTime);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.uldTypeSize,
        &state->kernel.uldTypeSize,
        &state->kernelSources.uldTypeSize);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.piDdbDriverName,
        &state->kernel.piDdbDriverName,
        &state->kernelSources.piDdbDriverName);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.piDdbTimeDateStamp,
        &state->kernel.piDdbTimeDateStamp,
        &state->kernelSources.piDdbTimeDateStamp);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.piDdbLoadStatus,
        &state->kernel.piDdbLoadStatus,
        &state->kernelSources.piDdbLoadStatus);
    kswordArkDynDataStoreRuntimeOffset(
        kernelLayout.piDdbTypeSize,
        &state->kernel.piDdbTypeSize,
        &state->kernelSources.piDdbTypeSize);
    if (!kswordArkDynDataOffsetPresent(state->kernelGlobals.psLoadedModuleList) &&
        kernelLayout.psLoadedModuleListRva >= 0) {
        kswordArkDynDataStoreSourcedOffset(
            (ULONG)kernelLayout.psLoadedModuleListRva,
            KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN,
            &state->kernelGlobals.psLoadedModuleList,
            &state->kernelGlobalSources.psLoadedModuleList);
    }
    if (!kswordArkDynDataOffsetPresent(state->kernelGlobals.mmUnloadedDrivers) &&
        kernelLayout.mmUnloadedDriversRva >= 0) {
        kswordArkDynDataStoreSourcedOffset(
            (ULONG)kernelLayout.mmUnloadedDriversRva,
            KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN,
            &state->kernelGlobals.mmUnloadedDrivers,
            &state->kernelGlobalSources.mmUnloadedDrivers);
    }
    if (!kswordArkDynDataOffsetPresent(state->kernelGlobals.mmLastUnloadedDriver) &&
        kernelLayout.mmLastUnloadedDriverRva >= 0) {
        kswordArkDynDataStoreSourcedOffset(
            (ULONG)kernelLayout.mmLastUnloadedDriverRva,
            KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN,
            &state->kernelGlobals.mmLastUnloadedDriver,
            &state->kernelGlobalSources.mmLastUnloadedDriver);
    }
    if (!kswordArkDynDataOffsetPresent(state->kernelGlobals.piDdbCacheTable) &&
        kernelLayout.piDdbCacheTableRva >= 0) {
        kswordArkDynDataStoreSourcedOffset(
            (ULONG)kernelLayout.piDdbCacheTableRva,
            KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN,
            &state->kernelGlobals.piDdbCacheTable,
            &state->kernelGlobalSources.piDdbCacheTable);
    }
    if (!kswordArkDynDataOffsetPresent(state->kernelGlobals.piDdbLock) &&
        kernelLayout.piDdbLockRva >= 0) {
        kswordArkDynDataStoreSourcedOffset(
            (ULONG)kernelLayout.piDdbLockRva,
            KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN,
            &state->kernelGlobals.piDdbLock,
            &state->kernelGlobalSources.piDdbLock);
    }
    if (!kswordArkDynDataOffsetPresent(state->kernelGlobals.keServiceDescriptorTableShadow) &&
        kernelLayout.keServiceDescriptorTableShadowRva >= 0) {
        kswordArkDynDataStoreSourcedOffset(
            (ULONG)kernelLayout.keServiceDescriptorTableShadowRva,
            KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN,
            &state->kernelGlobals.keServiceDescriptorTableShadow,
            &state->kernelGlobalSources.keServiceDescriptorTableShadow);
    }

    protectionPresent = kswordArkDynDataStoreRuntimeOffset(
        kswordArkDriverResolveProcessProtectionOffset(),
        &state->kernel.epProtection,
        &state->kernelSources.epProtection);
    signaturePresent = kswordArkDynDataStoreRuntimeOffset(
        kswordArkDriverResolveProcessSignatureLevelOffset(),
        &state->kernel.epSignatureLevel,
        &state->kernelSources.epSignatureLevel);
    sectionSignaturePresent = kswordArkDynDataStoreRuntimeOffset(
        kswordArkDriverResolveProcessSectionSignatureLevelOffset(),
        &state->kernel.epSectionSignatureLevel,
        &state->kernelSources.epSectionSignatureLevel);

    //
    // EpObjectTable / EpSectionObject originally had only one source: the System Informer offset table. This table performs
    // precise matching based on ntoskrnl's TimeDateStamp + SizeOfImage, but new kernels often do not exist in this table.
    // These two runtime resolutions only write when the offset is still missing (StoreRuntimeOffset includes this check). On resolution
    // failure, the original state remains unavailable; it does not overwrite the packaged profile result, nor does it cause a rollback.
    //
    (VOID)kswordArkDynDataStoreRuntimeOffset(
        kswordArkDriverResolveProcessSectionObjectOffset(),
        &state->kernel.epSectionObject,
        &state->kernelSources.epSectionObject);
    (VOID)kswordArkDynDataStoreRuntimeOffset(
        kswordArkDriverResolveProcessObjectTableOffset(),
        &state->kernel.epObjectTable,
        &state->kernelSources.epObjectTable);

    state->extraActive = (protectionPresent && signaturePresent && sectionSignaturePresent) ? TRUE : FALSE;
}

static NTSTATUS
kswordArkDynDataBuildState(
    _Out_ KswDynState* state,
    _In_opt_ PDRIVER_OBJECT validationDriverObject
    )
/*++

Routine Description:

    Build one immutable DynData state snapshot from loaded module identities,
    the vendored System Informer blob, and Ksword runtime resolvers.

Arguments:

    State - Output state snapshot.
    ValidationDriverObject - Live KSword driver object for runtime validation.

Return Value:

    STATUS_SUCCESS when ntoskrnl DynData was active; otherwise the primary
    ntoskrnl match/identity status. Optional lxcore failure does not override
    successful ntoskrnl activation.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS ntosStatus = STATUS_SUCCESS;
    NTSTATUS lxcoreStatus = STATUS_SUCCESS;
    ULONG configVersion = 0UL;
    ULONG configCount = 0UL;
    SIZE_T dataOffset = 0U;
    SIZE_T fieldBaseOffset = 0U;

    if (state == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(state, sizeof(*state));
    state->systemInformerDataLength = KphDynConfigLength;
    state->lastStatus = STATUS_UNSUCCESSFUL;
    kswordArkDynDataInitializeKernelOffsets(&state->kernel);
    kswordArkDynDataInitializeLxcoreOffsets(&state->lxcoreOffsets);
    kswordArkDynDataInitializeKernelGlobals(&state->kernelGlobals);
    kswordArkDynDataInitializeCallbackGlobals(&state->callbackGlobals);
    kswordArkDynDataInitializeCallbackOffsets(&state->callbackOffsets);
    kswordArkDynDataSetReason(state, L"DynData initialization has not completed.");

    status = kswordArkDynDataReadConfigHeader(
        &configVersion,
        &configCount,
        &dataOffset,
        &fieldBaseOffset);
    if (!NT_SUCCESS(status)) {
        state->lastStatus = status;
        kswordArkDynDataSetReason(state, L"System Informer DynData blob header is invalid.");
        return status;
    }
    state->systemInformerDataVersion = configVersion;
    state->systemInformerDataLength = KphDynConfigLength;
    UNREFERENCED_PARAMETER(configCount);
    UNREFERENCED_PARAMETER(dataOffset);
    UNREFERENCED_PARAMETER(fieldBaseOffset);

    ntosStatus = kswordArkQueryKernelModuleIdentity(
        kGKswordDynNtosNames,
        (ULONG)(sizeof(kGKswordDynNtosNames) / sizeof(kGKswordDynNtosNames[0])),
        &state->ntoskrnl);
    if (NT_SUCCESS(ntosStatus)) {
        ntosStatus = kswordArkDynDataActivateKernelFields(&state->ntoskrnl, state);
    }

    lxcoreStatus = kswordArkQueryKernelModuleIdentity(
        kGKswordDynLxcoreNames,
        (ULONG)(sizeof(kGKswordDynLxcoreNames) / sizeof(kGKswordDynLxcoreNames[0])),
        &state->lxcore);
    if (NT_SUCCESS(lxcoreStatus)) {
        lxcoreStatus = kswordArkDynDataActivateLxcoreFields(&state->lxcore, state);
    }

    kswordArkDynDataActivateRuntimeOffsets(state, validationDriverObject);
    state->capabilityMask = kswordArkDynDataComputeCapabilities(state);
    state->initialized = TRUE;
    state->lastStatus = ntosStatus;

    if (NT_SUCCESS(ntosStatus)) {
        if (state->lxcore.present != 0UL && !NT_SUCCESS(lxcoreStatus)) {
            kswordArkDynDataSetReason(state, L"ntoskrnl DynData is active; lxcore.sys is loaded but did not match exactly.");
        }
        else {
            kswordArkDynDataSetReason(state, L"DynData profile matched exactly.");
        }
        return STATUS_SUCCESS;
    }

    if (ntosStatus == STATUS_NOT_FOUND) {
        kswordArkDynDataSetReason(state, L"ntoskrnl.exe/ntkrla57.exe module identity was not found.");
    }
    else if (ntosStatus == STATUS_SI_DYNDATA_UNSUPPORTED_KERNEL) {
        kswordArkDynDataSetReason(state, L"No exact System Informer profile matched this kernel image.");
    }
    else {
        kswordArkDynDataSetReason(state, L"DynData profile activation failed before capability gating.");
    }

    return ntosStatus;
}

NTSTATUS
kswordArkDynDataInitialize(
    _In_opt_ WDFDEVICE device
    )
/*++

Routine Description:

    initialize the global DynData state. This routine never blocks driver load;
    failures are recorded in the queryable state and reported through logs.

Arguments:

    Device - Optional WDF device used to enqueue a startup diagnostic log.

Return Value:

    STATUS_SUCCESS so callers do not fail driver startup because private offset
    data is unavailable.

--*/
{
    KswDynState newState;
    NTSTATUS stateStatus = STATUS_SUCCESS;
    PDRIVER_OBJECT validationDriverObject = NULL;
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };

    ExInitializePushLock(&gKswordDynDataStateLock);
    kswordArkDynDataV4Initialize();
    if (device != NULL) {
        PDEVICE_OBJECT wdmDeviceObject = WdfDeviceWdmGetDeviceObject(device);
        if (wdmDeviceObject != NULL) {
            validationDriverObject = wdmDeviceObject->DriverObject;
        }
    }
    stateStatus = kswordArkDynDataBuildState(&newState, validationDriverObject);
    kswordArkAcquirePushLockExclusive(&gKswordDynDataStateLock);
    RtlCopyMemory(&gKswordDynDataState, &newState, sizeof(gKswordDynDataState));
    kswordArkReleasePushLockExclusive(&gKswordDynDataStateLock);

    if (device != NULL) {
        (VOID)RtlStringCbPrintfA(
            logMessage,
            sizeof(logMessage),
            "DynData init: ntosActive=%u, lxcoreActive=%u, extraActive=%u, caps=0x%I64X, status=0x%08X.",
            (unsigned int)newState.ntosActive,
            (unsigned int)newState.lxcoreActive,
            (unsigned int)newState.extraActive,
            newState.capabilityMask,
            (unsigned int)stateStatus);
        (VOID)kswordArkDriverEnqueueLogFrame(
            device,
            NT_SUCCESS(stateStatus) ? "Info" : "Warn",
            logMessage);
    }

    return STATUS_SUCCESS;
}

VOID
kswordArkDynDataUninitialize(
    VOID
    )
/*++

Routine Description:

    Clear the global DynData state during driver unload.

Arguments:

    None.

Return Value:

    None.

--*/
{
    kswordArkDynDataV4Uninitialize();
    kswordArkAcquirePushLockExclusive(&gKswordDynDataStateLock);
    RtlZeroMemory(&gKswordDynDataState, sizeof(gKswordDynDataState));
    kswordArkReleasePushLockExclusive(&gKswordDynDataStateLock);
}

VOID
kswordArkDynDataSnapshot(
    _Out_ KswDynState* stateOut
    )
/*++

Routine Description:

    Copy the current global DynData state into a caller-owned buffer.

Arguments:

    StateOut - Receives the global state snapshot.

Return Value:

    None.

--*/
{
    if (stateOut == NULL) {
        return;
    }

    kswordArkAcquirePushLockShared(&gKswordDynDataStateLock);
    RtlCopyMemory(stateOut, &gKswordDynDataState, sizeof(*stateOut));
    kswordArkReleasePushLockShared(&gKswordDynDataStateLock);
}

static ULONG
kswordArkDynDataPublicStatusFlags(
    _In_ const KswDynState* state
    )
/*++

Routine Description:

    Convert one internal DynData state into public status bits. The loader keeps
    this private copy so profile-apply responses can be produced without
    reaching into dyndata_query.c static helpers.

Arguments:

    State - DynData state to summarize.

Return Value:

    KSW_DYN_STATUS_FLAG_* bit mask.

--*/
{
    ULONG flags = 0UL;

    if (state == NULL) {
        return 0UL;
    }
    if (state->initialized) {
        flags |= KSW_DYN_STATUS_FLAG_INITIALIZED;
    }
    if (state->ntosActive) {
        flags |= KSW_DYN_STATUS_FLAG_NTOS_ACTIVE;
    }
    if (state->lxcoreActive) {
        flags |= KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE;
    }
    if (state->extraActive) {
        flags |= KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE;
    }
    if (state->pdbProfileActive) {
        flags |= KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE;
    }
    if (state->callbackProfileActive) {
        flags |= KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE;
    }

    return flags;
}

static VOID
kswordArkDynDataApplySetMessage(
    _Out_writes_(KSW_DYN_REASON_CHARS) WCHAR* destination,
    _In_z_ PCWSTR message
    )
/*++

Routine Description:

    Store a bounded profile-apply message for R3 diagnostics.

Arguments:

    Destination - Fixed response message buffer.
    Message - NUL-terminated message text.

Return Value:

    None.

--*/
{
    if (destination == NULL) {
        return;
    }

    destination[0] = L'\0';
    if (message == NULL) {
        return;
    }

    (VOID)RtlStringCchCopyW(destination, KSW_DYN_REASON_CHARS, message);
    destination[KSW_DYN_REASON_CHARS - 1U] = L'\0';
}

static BOOLEAN
kswordArkDynDataIdentityMatches(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* currentIdentity,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* requestedIdentity
    )
/*++

Routine Description:

    Compare the identity tuple that makes a PDB profile safe to apply. Image
    base and module name are diagnostic only; class, machine, timestamp, and
    image size are the exact-match key.

Arguments:

    CurrentIdentity - Module identity captured by R0.
    RequestedIdentity - Module identity supplied by the R3 JSON profile manager.

Return Value:

    TRUE when the request targets the currently loaded kernel image.

--*/
{
    if (currentIdentity == NULL || requestedIdentity == NULL) {
        return FALSE;
    }
    if (currentIdentity->present == 0UL || requestedIdentity->present == 0UL) {
        return FALSE;
    }
    if (requestedIdentity->classId != KSW_DYN_PROFILE_CLASS_NTOSKRNL &&
        requestedIdentity->classId != KSW_DYN_PROFILE_CLASS_NTKRLA57) {
        return FALSE;
    }

    return currentIdentity->classId == requestedIdentity->classId &&
        currentIdentity->machine == requestedIdentity->machine &&
        currentIdentity->timeDateStamp == requestedIdentity->timeDateStamp &&
        currentIdentity->sizeOfImage == requestedIdentity->sizeOfImage;
}

static BOOLEAN
kswordArkDynDataKernelFieldPointers(
    _In_ ULONG fieldId,
    _Inout_ KswDynState* state,
    _Outptr_ ULONG** offsetOut,
    _Outptr_ ULONG** sourceOut
    )
/*++

Routine Description:

    Resolve one public ntoskrnl DynData field ID into the internal offset and
    source slots. v1 profile application intentionally handles only kernel
    fields; lxcore remains System Informer sourced until a separate profile class
    is added.

Arguments:

    FieldId - KSW_DYN_FIELD_ID_* value supplied by R3.
    State - Mutable state snapshot that owns destination fields.
    OffsetOut - Receives a pointer to the target offset slot.
    SourceOut - Receives a pointer to the target source slot.

Return Value:

    TRUE when FieldId is known and belongs to the ntoskrnl field set.

--*/
{
    if (state == NULL || offsetOut == NULL || sourceOut == NULL) {
        return FALSE;
    }

    *offsetOut = NULL;
    *sourceOut = NULL;

    switch (fieldId) {
    case KSW_DYN_FIELD_ID_EP_OBJECT_TABLE:
        *offsetOut = &state->kernel.epObjectTable;
        *sourceOut = &state->kernelSources.epObjectTable;
        break;
    case KSW_DYN_FIELD_ID_EP_SECTION_OBJECT:
        *offsetOut = &state->kernel.epSectionObject;
        *sourceOut = &state->kernelSources.epSectionObject;
        break;
    case KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID:
        *offsetOut = &state->kernel.epUniqueProcessId;
        *sourceOut = &state->kernelSources.epUniqueProcessId;
        break;
    case KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS:
        *offsetOut = &state->kernel.epActiveProcessLinks;
        *sourceOut = &state->kernelSources.epActiveProcessLinks;
        break;
    case KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD:
        *offsetOut = &state->kernel.epThreadListHead;
        *sourceOut = &state->kernelSources.epThreadListHead;
        break;
    case KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME:
        *offsetOut = &state->kernel.epImageFileName;
        *sourceOut = &state->kernelSources.epImageFileName;
        break;
    case KSW_DYN_FIELD_ID_EP_TOKEN:
        *offsetOut = &state->kernel.epToken;
        *sourceOut = &state->kernelSources.epToken;
        break;
    case KSW_DYN_FIELD_ID_EP_FLAGS:
        *offsetOut = &state->kernel.epFlags;
        *sourceOut = &state->kernelSources.epFlags;
        break;
    case KSW_DYN_FIELD_ID_EP_FLAGS2:
        *offsetOut = &state->kernel.epFlags2;
        *sourceOut = &state->kernelSources.epFlags2;
        break;
    case KSW_DYN_FIELD_ID_EP_RUNDOWN_PROTECT:
        *offsetOut = &state->kernel.epRundownProtect;
        *sourceOut = &state->kernelSources.epRundownProtect;
        break;
    case KSW_DYN_FIELD_ID_EP_PROCESS_LOCK:
        *offsetOut = &state->kernel.epProcessLock;
        *sourceOut = &state->kernelSources.epProcessLock;
        break;
    case KSW_DYN_FIELD_ID_EP_CREATE_TIME:
        *offsetOut = &state->kernel.epCreateTime;
        *sourceOut = &state->kernelSources.epCreateTime;
        break;
    case KSW_DYN_FIELD_ID_EP_EXIT_TIME:
        *offsetOut = &state->kernel.epExitTime;
        *sourceOut = &state->kernelSources.epExitTime;
        break;
    case KSW_DYN_FIELD_ID_EP_EXIT_STATUS:
        *offsetOut = &state->kernel.epExitStatus;
        *sourceOut = &state->kernelSources.epExitStatus;
        break;
    case KSW_DYN_FIELD_ID_EP_PEB:
        *offsetOut = &state->kernel.epPeb;
        *sourceOut = &state->kernelSources.epPeb;
        break;
    case KSW_DYN_FIELD_ID_EP_SESSION:
        *offsetOut = &state->kernel.epSession;
        *sourceOut = &state->kernelSources.epSession;
        break;
    case KSW_DYN_FIELD_ID_EP_WIN32_PROCESS:
        *offsetOut = &state->kernel.epWin32Process;
        *sourceOut = &state->kernelSources.epWin32Process;
        break;
    case KSW_DYN_FIELD_ID_EP_WOW64_PROCESS:
        *offsetOut = &state->kernel.epWow64Process;
        *sourceOut = &state->kernelSources.epWow64Process;
        break;
    case KSW_DYN_FIELD_ID_EP_INHERITED_FROM_UNIQUE_PROCESS_ID:
        *offsetOut = &state->kernel.epInheritedFromUniqueProcessId;
        *sourceOut = &state->kernelSources.epInheritedFromUniqueProcessId;
        break;
    case KSW_DYN_FIELD_ID_EP_SE_AUDIT_PROCESS_CREATION_INFO:
        *offsetOut = &state->kernel.epSeAuditProcessCreationInfo;
        *sourceOut = &state->kernelSources.epSeAuditProcessCreationInfo;
        break;
    case KSW_DYN_FIELD_ID_EP_JOB:
        *offsetOut = &state->kernel.epJob;
        *sourceOut = &state->kernelSources.epJob;
        break;
    case KSW_DYN_FIELD_ID_EP_DEVICE_MAP:
        *offsetOut = &state->kernel.epDeviceMap;
        *sourceOut = &state->kernelSources.epDeviceMap;
        break;
    case KSW_DYN_FIELD_ID_EP_DEBUG_PORT:
        *offsetOut = &state->kernel.epDebugPort;
        *sourceOut = &state->kernelSources.epDebugPort;
        break;
    case KSW_DYN_FIELD_ID_EP_EXCEPTION_PORT_DATA:
        *offsetOut = &state->kernel.epExceptionPortData;
        *sourceOut = &state->kernelSources.epExceptionPortData;
        break;
    case KSW_DYN_FIELD_ID_EP_SECTION_BASE_ADDRESS:
        *offsetOut = &state->kernel.epSectionBaseAddress;
        *sourceOut = &state->kernelSources.epSectionBaseAddress;
        break;
    case KSW_DYN_FIELD_ID_EP_IMAGE_FILE_POINTER:
        *offsetOut = &state->kernel.epImageFilePointer;
        *sourceOut = &state->kernelSources.epImageFilePointer;
        break;
    case KSW_DYN_FIELD_ID_EP_PRIORITY_CLASS:
        *offsetOut = &state->kernel.epPriorityClass;
        *sourceOut = &state->kernelSources.epPriorityClass;
        break;
    case KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS:
        *offsetOut = &state->kernel.epActiveThreads;
        *sourceOut = &state->kernelSources.epActiveThreads;
        break;
    case KSW_DYN_FIELD_ID_EP_VAD_ROOT:
        *offsetOut = &state->kernel.epVadRoot;
        *sourceOut = &state->kernelSources.epVadRoot;
        break;
    case KSW_DYN_FIELD_ID_EP_VAD_HINT:
        *offsetOut = &state->kernel.epVadHint;
        *sourceOut = &state->kernelSources.epVadHint;
        break;
    case KSW_DYN_FIELD_ID_EP_CLONE_ROOT:
        *offsetOut = &state->kernel.epCloneRoot;
        *sourceOut = &state->kernelSources.epCloneRoot;
        break;
    case KSW_DYN_FIELD_ID_EP_NUMBER_OF_PRIVATE_PAGES:
        *offsetOut = &state->kernel.epNumberOfPrivatePages;
        *sourceOut = &state->kernelSources.epNumberOfPrivatePages;
        break;
    case KSW_DYN_FIELD_ID_EP_NUMBER_OF_LOCKED_PAGES:
        *offsetOut = &state->kernel.epNumberOfLockedPages;
        *sourceOut = &state->kernelSources.epNumberOfLockedPages;
        break;
    case KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE:
        *offsetOut = &state->kernel.epCommitCharge;
        *sourceOut = &state->kernelSources.epCommitCharge;
        break;
    case KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_PEAK:
        *offsetOut = &state->kernel.epCommitChargePeak;
        *sourceOut = &state->kernelSources.epCommitChargePeak;
        break;
    case KSW_DYN_FIELD_ID_EP_PEAK_VIRTUAL_SIZE:
        *offsetOut = &state->kernel.epPeakVirtualSize;
        *sourceOut = &state->kernelSources.epPeakVirtualSize;
        break;
    case KSW_DYN_FIELD_ID_EP_VIRTUAL_SIZE:
        *offsetOut = &state->kernel.epVirtualSize;
        *sourceOut = &state->kernelSources.epVirtualSize;
        break;
    case KSW_DYN_FIELD_ID_EP_SESSION_PROCESS_LINKS:
        *offsetOut = &state->kernel.epSessionProcessLinks;
        *sourceOut = &state->kernelSources.epSessionProcessLinks;
        break;
    case KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS:
        *offsetOut = &state->kernel.epMitigationFlags;
        *sourceOut = &state->kernelSources.epMitigationFlags;
        break;
    case KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS2:
        *offsetOut = &state->kernel.epMitigationFlags2;
        *sourceOut = &state->kernelSources.epMitigationFlags2;
        break;
    case KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_USAGE:
        *offsetOut = &state->kernel.epProcessQuotaUsage;
        *sourceOut = &state->kernelSources.epProcessQuotaUsage;
        break;
    case KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_PEAK:
        *offsetOut = &state->kernel.epProcessQuotaPeak;
        *sourceOut = &state->kernelSources.epProcessQuotaPeak;
        break;
    case KSW_DYN_FIELD_ID_EP_ADDRESS_CREATION_LOCK:
        *offsetOut = &state->kernel.epAddressCreationLock;
        *sourceOut = &state->kernelSources.epAddressCreationLock;
        break;
    case KSW_DYN_FIELD_ID_EP_PAGE_TABLE_COMMITMENT_LOCK:
        *offsetOut = &state->kernel.epPageTableCommitmentLock;
        *sourceOut = &state->kernelSources.epPageTableCommitmentLock;
        break;
    case KSW_DYN_FIELD_ID_EP_ROTATE_IN_PROGRESS:
        *offsetOut = &state->kernel.epRotateInProgress;
        *sourceOut = &state->kernelSources.epRotateInProgress;
        break;
    case KSW_DYN_FIELD_ID_EP_FORK_IN_PROGRESS:
        *offsetOut = &state->kernel.epForkInProgress;
        *sourceOut = &state->kernelSources.epForkInProgress;
        break;
    case KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_JOB:
        *offsetOut = &state->kernel.epCommitChargeJob;
        *sourceOut = &state->kernelSources.epCommitChargeJob;
        break;
    case KSW_DYN_FIELD_ID_EP_COOKIE:
        *offsetOut = &state->kernel.epCookie;
        *sourceOut = &state->kernelSources.epCookie;
        break;
    case KSW_DYN_FIELD_ID_EP_WORKING_SET_WATCH:
        *offsetOut = &state->kernel.epWorkingSetWatch;
        *sourceOut = &state->kernelSources.epWorkingSetWatch;
        break;
    case KSW_DYN_FIELD_ID_EP_WIN32_WINDOW_STATION:
        *offsetOut = &state->kernel.epWin32WindowStation;
        *sourceOut = &state->kernelSources.epWin32WindowStation;
        break;
    case KSW_DYN_FIELD_ID_EP_OWNER_PROCESS_ID:
        *offsetOut = &state->kernel.epOwnerProcessId;
        *sourceOut = &state->kernelSources.epOwnerProcessId;
        break;
    case KSW_DYN_FIELD_ID_EP_QUOTA_BLOCK:
        *offsetOut = &state->kernel.epQuotaBlock;
        *sourceOut = &state->kernelSources.epQuotaBlock;
        break;
    case KSW_DYN_FIELD_ID_EP_ETW_DATA_SOURCE:
        *offsetOut = &state->kernel.epEtwDataSource;
        *sourceOut = &state->kernelSources.epEtwDataSource;
        break;
    case KSW_DYN_FIELD_ID_EP_PAGE_DIRECTORY_PTE:
        *offsetOut = &state->kernel.epPageDirectoryPte;
        *sourceOut = &state->kernelSources.epPageDirectoryPte;
        break;
    case KSW_DYN_FIELD_ID_EP_SECURITY_PORT:
        *offsetOut = &state->kernel.epSecurityPort;
        *sourceOut = &state->kernelSources.epSecurityPort;
        break;
    case KSW_DYN_FIELD_ID_EP_JOB_LINKS:
        *offsetOut = &state->kernel.epJobLinks;
        *sourceOut = &state->kernelSources.epJobLinks;
        break;
    case KSW_DYN_FIELD_ID_EP_HIGHEST_USER_ADDRESS:
        *offsetOut = &state->kernel.epHighestUserAddress;
        *sourceOut = &state->kernelSources.epHighestUserAddress;
        break;
    case KSW_DYN_FIELD_ID_EP_IMAGE_PATH_HASH:
        *offsetOut = &state->kernel.epImagePathHash;
        *sourceOut = &state->kernelSources.epImagePathHash;
        break;
    case KSW_DYN_FIELD_ID_EP_DEFAULT_HARD_ERROR_PROCESSING:
        *offsetOut = &state->kernel.epDefaultHardErrorProcessing;
        *sourceOut = &state->kernelSources.epDefaultHardErrorProcessing;
        break;
    case KSW_DYN_FIELD_ID_EP_LAST_THREAD_EXIT_STATUS:
        *offsetOut = &state->kernel.epLastThreadExitStatus;
        *sourceOut = &state->kernelSources.epLastThreadExitStatus;
        break;
    case KSW_DYN_FIELD_ID_EP_PREFETCH_TRACE:
        *offsetOut = &state->kernel.epPrefetchTrace;
        *sourceOut = &state->kernelSources.epPrefetchTrace;
        break;
    case KSW_DYN_FIELD_ID_EP_LOCKED_PAGES_LIST:
        *offsetOut = &state->kernel.epLockedPagesList;
        *sourceOut = &state->kernelSources.epLockedPagesList;
        break;
    case KSW_DYN_FIELD_ID_EP_READ_OPERATION_COUNT:
        *offsetOut = &state->kernel.epReadOperationCount;
        *sourceOut = &state->kernelSources.epReadOperationCount;
        break;
    case KSW_DYN_FIELD_ID_EP_WRITE_OPERATION_COUNT:
        *offsetOut = &state->kernel.epWriteOperationCount;
        *sourceOut = &state->kernelSources.epWriteOperationCount;
        break;
    case KSW_DYN_FIELD_ID_EP_OTHER_OPERATION_COUNT:
        *offsetOut = &state->kernel.epOtherOperationCount;
        *sourceOut = &state->kernelSources.epOtherOperationCount;
        break;
    case KSW_DYN_FIELD_ID_EP_READ_TRANSFER_COUNT:
        *offsetOut = &state->kernel.epReadTransferCount;
        *sourceOut = &state->kernelSources.epReadTransferCount;
        break;
    case KSW_DYN_FIELD_ID_EP_WRITE_TRANSFER_COUNT:
        *offsetOut = &state->kernel.epWriteTransferCount;
        *sourceOut = &state->kernelSources.epWriteTransferCount;
        break;
    case KSW_DYN_FIELD_ID_EP_OTHER_TRANSFER_COUNT:
        *offsetOut = &state->kernel.epOtherTransferCount;
        *sourceOut = &state->kernelSources.epOtherTransferCount;
        break;
    case KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_LIMIT:
        *offsetOut = &state->kernel.epCommitChargeLimit;
        *sourceOut = &state->kernelSources.epCommitChargeLimit;
        break;
    case KSW_DYN_FIELD_ID_EP_VM:
        *offsetOut = &state->kernel.epVm;
        *sourceOut = &state->kernelSources.epVm;
        break;
    case KSW_DYN_FIELD_ID_EP_MM_PROCESS_LINKS:
        *offsetOut = &state->kernel.epMmProcessLinks;
        *sourceOut = &state->kernelSources.epMmProcessLinks;
        break;
    case KSW_DYN_FIELD_ID_EP_MODIFIED_PAGE_COUNT:
        *offsetOut = &state->kernel.epModifiedPageCount;
        *sourceOut = &state->kernelSources.epModifiedPageCount;
        break;
    case KSW_DYN_FIELD_ID_EP_VAD_COUNT:
        *offsetOut = &state->kernel.epVadCount;
        *sourceOut = &state->kernelSources.epVadCount;
        break;
    case KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES:
        *offsetOut = &state->kernel.epVadPhysicalPages;
        *sourceOut = &state->kernelSources.epVadPhysicalPages;
        break;
    case KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES_LIMIT:
        *offsetOut = &state->kernel.epVadPhysicalPagesLimit;
        *sourceOut = &state->kernelSources.epVadPhysicalPagesLimit;
        break;
    case KSW_DYN_FIELD_ID_EP_ALPC_CONTEXT:
        *offsetOut = &state->kernel.epAlpcContext;
        *sourceOut = &state->kernelSources.epAlpcContext;
        break;
    case KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_LINK:
        *offsetOut = &state->kernel.epTimerResolutionLink;
        *sourceOut = &state->kernelSources.epTimerResolutionLink;
        break;
    case KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_STACK_RECORD:
        *offsetOut = &state->kernel.epTimerResolutionStackRecord;
        *sourceOut = &state->kernelSources.epTimerResolutionStackRecord;
        break;
    case KSW_DYN_FIELD_ID_EP_REQUESTED_TIMER_RESOLUTION:
        *offsetOut = &state->kernel.epRequestedTimerResolution;
        *sourceOut = &state->kernelSources.epRequestedTimerResolution;
        break;
    case KSW_DYN_FIELD_ID_EP_SMALLEST_TIMER_RESOLUTION:
        *offsetOut = &state->kernel.epSmallestTimerResolution;
        *sourceOut = &state->kernelSources.epSmallestTimerResolution;
        break;
    case KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE:
        *offsetOut = &state->kernel.epInvertedFunctionTable;
        *sourceOut = &state->kernelSources.epInvertedFunctionTable;
        break;
    case KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE_LOCK:
        *offsetOut = &state->kernel.epInvertedFunctionTableLock;
        *sourceOut = &state->kernelSources.epInvertedFunctionTableLock;
        break;
    case KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS_HIGH_WATERMARK:
        *offsetOut = &state->kernel.epActiveThreadsHighWatermark;
        *sourceOut = &state->kernelSources.epActiveThreadsHighWatermark;
        break;
    case KSW_DYN_FIELD_ID_EP_LARGE_PRIVATE_VAD_COUNT:
        *offsetOut = &state->kernel.epLargePrivateVadCount;
        *sourceOut = &state->kernelSources.epLargePrivateVadCount;
        break;
    case KSW_DYN_FIELD_ID_EP_THREAD_LIST_LOCK:
        *offsetOut = &state->kernel.epThreadListLock;
        *sourceOut = &state->kernelSources.epThreadListLock;
        break;
    case KSW_DYN_FIELD_ID_EP_WNF_CONTEXT:
        *offsetOut = &state->kernel.epWnfContext;
        *sourceOut = &state->kernelSources.epWnfContext;
        break;
    case KSW_DYN_FIELD_ID_EP_FLAGS3:
        *offsetOut = &state->kernel.epFlags3;
        *sourceOut = &state->kernelSources.epFlags3;
        break;
    case KSW_DYN_FIELD_ID_EP_DISK_COUNTERS:
        *offsetOut = &state->kernel.epDiskCounters;
        *sourceOut = &state->kernelSources.epDiskCounters;
        break;
    case KSW_DYN_FIELD_ID_TOK_TOKEN_SOURCE:
        *offsetOut = &state->kernel.tokTokenSource;
        *sourceOut = &state->kernelSources.tokTokenSource;
        break;
    case KSW_DYN_FIELD_ID_TOK_TOKEN_ID:
        *offsetOut = &state->kernel.tokTokenId;
        *sourceOut = &state->kernelSources.tokTokenId;
        break;
    case KSW_DYN_FIELD_ID_TOK_AUTHENTICATION_ID:
        *offsetOut = &state->kernel.tokAuthenticationId;
        *sourceOut = &state->kernelSources.tokAuthenticationId;
        break;
    case KSW_DYN_FIELD_ID_TOK_PARENT_TOKEN_ID:
        *offsetOut = &state->kernel.tokParentTokenId;
        *sourceOut = &state->kernelSources.tokParentTokenId;
        break;
    case KSW_DYN_FIELD_ID_TOK_EXPIRATION_TIME:
        *offsetOut = &state->kernel.tokExpirationTime;
        *sourceOut = &state->kernelSources.tokExpirationTime;
        break;
    case KSW_DYN_FIELD_ID_TOK_TOKEN_LOCK:
        *offsetOut = &state->kernel.tokTokenLock;
        *sourceOut = &state->kernelSources.tokTokenLock;
        break;
    case KSW_DYN_FIELD_ID_TOK_MODIFIED_ID:
        *offsetOut = &state->kernel.tokModifiedId;
        *sourceOut = &state->kernelSources.tokModifiedId;
        break;
    case KSW_DYN_FIELD_ID_TOK_PRIVILEGES:
        *offsetOut = &state->kernel.tokPrivileges;
        *sourceOut = &state->kernelSources.tokPrivileges;
        break;
    case KSW_DYN_FIELD_ID_TOK_AUDIT_POLICY:
        *offsetOut = &state->kernel.tokAuditPolicy;
        *sourceOut = &state->kernelSources.tokAuditPolicy;
        break;
    case KSW_DYN_FIELD_ID_TOK_SESSION_ID:
        *offsetOut = &state->kernel.tokSessionId;
        *sourceOut = &state->kernelSources.tokSessionId;
        break;
    case KSW_DYN_FIELD_ID_TOK_USER_AND_GROUP_COUNT:
        *offsetOut = &state->kernel.tokUserAndGroupCount;
        *sourceOut = &state->kernelSources.tokUserAndGroupCount;
        break;
    case KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_COUNT:
        *offsetOut = &state->kernel.tokRestrictedSidCount;
        *sourceOut = &state->kernelSources.tokRestrictedSidCount;
        break;
    case KSW_DYN_FIELD_ID_TOK_VARIABLE_LENGTH:
        *offsetOut = &state->kernel.tokVariableLength;
        *sourceOut = &state->kernelSources.tokVariableLength;
        break;
    case KSW_DYN_FIELD_ID_TOK_DYNAMIC_CHARGED:
        *offsetOut = &state->kernel.tokDynamicCharged;
        *sourceOut = &state->kernelSources.tokDynamicCharged;
        break;
    case KSW_DYN_FIELD_ID_TOK_DYNAMIC_AVAILABLE:
        *offsetOut = &state->kernel.tokDynamicAvailable;
        *sourceOut = &state->kernelSources.tokDynamicAvailable;
        break;
    case KSW_DYN_FIELD_ID_TOK_DEFAULT_OWNER_INDEX:
        *offsetOut = &state->kernel.tokDefaultOwnerIndex;
        *sourceOut = &state->kernelSources.tokDefaultOwnerIndex;
        break;
    case KSW_DYN_FIELD_ID_TOK_USER_AND_GROUPS:
        *offsetOut = &state->kernel.tokUserAndGroups;
        *sourceOut = &state->kernelSources.tokUserAndGroups;
        break;
    case KSW_DYN_FIELD_ID_TOK_RESTRICTED_SIDS:
        *offsetOut = &state->kernel.tokRestrictedSids;
        *sourceOut = &state->kernelSources.tokRestrictedSids;
        break;
    case KSW_DYN_FIELD_ID_TOK_PRIMARY_GROUP:
        *offsetOut = &state->kernel.tokPrimaryGroup;
        *sourceOut = &state->kernelSources.tokPrimaryGroup;
        break;
    case KSW_DYN_FIELD_ID_TOK_DYNAMIC_PART:
        *offsetOut = &state->kernel.tokDynamicPart;
        *sourceOut = &state->kernelSources.tokDynamicPart;
        break;
    case KSW_DYN_FIELD_ID_TOK_DEFAULT_DACL:
        *offsetOut = &state->kernel.tokDefaultDacl;
        *sourceOut = &state->kernelSources.tokDefaultDacl;
        break;
    case KSW_DYN_FIELD_ID_TOK_TOKEN_TYPE:
        *offsetOut = &state->kernel.tokTokenType;
        *sourceOut = &state->kernelSources.tokTokenType;
        break;
    case KSW_DYN_FIELD_ID_TOK_IMPERSONATION_LEVEL:
        *offsetOut = &state->kernel.tokImpersonationLevel;
        *sourceOut = &state->kernelSources.tokImpersonationLevel;
        break;
    case KSW_DYN_FIELD_ID_TOK_TOKEN_FLAGS:
        *offsetOut = &state->kernel.tokTokenFlags;
        *sourceOut = &state->kernelSources.tokTokenFlags;
        break;
    case KSW_DYN_FIELD_ID_TOK_TOKEN_IN_USE:
        *offsetOut = &state->kernel.tokTokenInUse;
        *sourceOut = &state->kernelSources.tokTokenInUse;
        break;
    case KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_INDEX:
        *offsetOut = &state->kernel.tokIntegrityLevelIndex;
        *sourceOut = &state->kernelSources.tokIntegrityLevelIndex;
        break;
    case KSW_DYN_FIELD_ID_TOK_MANDATORY_POLICY:
        *offsetOut = &state->kernel.tokMandatoryPolicy;
        *sourceOut = &state->kernelSources.tokMandatoryPolicy;
        break;
    case KSW_DYN_FIELD_ID_TOK_LOGON_SESSION:
        *offsetOut = &state->kernel.tokLogonSession;
        *sourceOut = &state->kernelSources.tokLogonSession;
        break;
    case KSW_DYN_FIELD_ID_TOK_ORIGINATING_LOGON_SESSION:
        *offsetOut = &state->kernel.tokOriginatingLogonSession;
        *sourceOut = &state->kernelSources.tokOriginatingLogonSession;
        break;
    case KSW_DYN_FIELD_ID_TOK_SID_HASH:
        *offsetOut = &state->kernel.tokSidHash;
        *sourceOut = &state->kernelSources.tokSidHash;
        break;
    case KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_HASH:
        *offsetOut = &state->kernel.tokRestrictedSidHash;
        *sourceOut = &state->kernelSources.tokRestrictedSidHash;
        break;
    case KSW_DYN_FIELD_ID_TOK_P_SECURITY_ATTRIBUTES:
        *offsetOut = &state->kernel.tokPSecurityAttributes;
        *sourceOut = &state->kernelSources.tokPSecurityAttributes;
        break;
    case KSW_DYN_FIELD_ID_TOK_PACKAGE:
        *offsetOut = &state->kernel.tokPackage;
        *sourceOut = &state->kernelSources.tokPackage;
        break;
    case KSW_DYN_FIELD_ID_TOK_CAPABILITIES:
        *offsetOut = &state->kernel.tokCapabilities;
        *sourceOut = &state->kernelSources.tokCapabilities;
        break;
    case KSW_DYN_FIELD_ID_TOK_CAPABILITY_COUNT:
        *offsetOut = &state->kernel.tokCapabilityCount;
        *sourceOut = &state->kernelSources.tokCapabilityCount;
        break;
    case KSW_DYN_FIELD_ID_TOK_CAPABILITIES_HASH:
        *offsetOut = &state->kernel.tokCapabilitiesHash;
        *sourceOut = &state->kernelSources.tokCapabilitiesHash;
        break;
    case KSW_DYN_FIELD_ID_TOK_LOWBOX_NUMBER_ENTRY:
        *offsetOut = &state->kernel.tokLowboxNumberEntry;
        *sourceOut = &state->kernelSources.tokLowboxNumberEntry;
        break;
    case KSW_DYN_FIELD_ID_TOK_LOWBOX_HANDLES_ENTRY:
        *offsetOut = &state->kernel.tokLowboxHandlesEntry;
        *sourceOut = &state->kernelSources.tokLowboxHandlesEntry;
        break;
    case KSW_DYN_FIELD_ID_TOK_P_CLAIM_ATTRIBUTES:
        *offsetOut = &state->kernel.tokPClaimAttributes;
        *sourceOut = &state->kernelSources.tokPClaimAttributes;
        break;
    case KSW_DYN_FIELD_ID_TOK_TRUST_LEVEL_SID:
        *offsetOut = &state->kernel.tokTrustLevelSid;
        *sourceOut = &state->kernelSources.tokTrustLevelSid;
        break;
    case KSW_DYN_FIELD_ID_TOK_TRUST_LINKED_TOKEN:
        *offsetOut = &state->kernel.tokTrustLinkedToken;
        *sourceOut = &state->kernelSources.tokTrustLinkedToken;
        break;
    case KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_SID_VALUE:
        *offsetOut = &state->kernel.tokIntegrityLevelSidValue;
        *sourceOut = &state->kernelSources.tokIntegrityLevelSidValue;
        break;
    case KSW_DYN_FIELD_ID_TOK_TOKEN_SID_VALUES:
        *offsetOut = &state->kernel.tokTokenSidValues;
        *sourceOut = &state->kernelSources.tokTokenSidValues;
        break;
    case KSW_DYN_FIELD_ID_TOK_SESSION_OBJECT:
        *offsetOut = &state->kernel.tokSessionObject;
        *sourceOut = &state->kernelSources.tokSessionObject;
        break;
    case KSW_DYN_FIELD_ID_TOK_VARIABLE_PART:
        *offsetOut = &state->kernel.tokVariablePart;
        *sourceOut = &state->kernelSources.tokVariablePart;
        break;
    case KSW_DYN_FIELD_ID_ET_CID:
        *offsetOut = &state->kernel.etCid;
        *sourceOut = &state->kernelSources.etCid;
        break;
    case KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY:
        *offsetOut = &state->kernel.etThreadListEntry;
        *sourceOut = &state->kernelSources.etThreadListEntry;
        break;
    case KSW_DYN_FIELD_ID_ET_START_ADDRESS:
        *offsetOut = &state->kernel.etStartAddress;
        *sourceOut = &state->kernelSources.etStartAddress;
        break;
    case KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS:
        *offsetOut = &state->kernel.etWin32StartAddress;
        *sourceOut = &state->kernelSources.etWin32StartAddress;
        break;
    case KSW_DYN_FIELD_ID_KT_PROCESS:
        *offsetOut = &state->kernel.ktProcess;
        *sourceOut = &state->kernelSources.ktProcess;
        break;
    case KSW_DYN_FIELD_ID_HT_HANDLE_CONTENTION_EVENT:
        *offsetOut = &state->kernel.htHandleContentionEvent;
        *sourceOut = &state->kernelSources.htHandleContentionEvent;
        break;
    case KSW_DYN_FIELD_ID_HT_TABLE_CODE:
        *offsetOut = &state->kernel.htTableCode;
        *sourceOut = &state->kernelSources.htTableCode;
        break;
    case KSW_DYN_FIELD_ID_HT_HANDLE_COUNT:
        *offsetOut = &state->kernel.htHandleCount;
        *sourceOut = &state->kernelSources.htHandleCount;
        break;
    case KSW_DYN_FIELD_ID_HTE_LOW_VALUE:
        *offsetOut = &state->kernel.hteLowValue;
        *sourceOut = &state->kernelSources.hteLowValue;
        break;
    case KSW_DYN_FIELD_ID_OT_NAME:
        *offsetOut = &state->kernel.otName;
        *sourceOut = &state->kernelSources.otName;
        break;
    case KSW_DYN_FIELD_ID_OT_INDEX:
        *offsetOut = &state->kernel.otIndex;
        *sourceOut = &state->kernelSources.otIndex;
        break;
    case KSW_DYN_FIELD_ID_OB_DECODE_SHIFT:
        *offsetOut = &state->kernel.obDecodeShift;
        *sourceOut = &state->kernelSources.obDecodeShift;
        break;
    case KSW_DYN_FIELD_ID_OB_ATTRIBUTES_SHIFT:
        *offsetOut = &state->kernel.obAttributesShift;
        *sourceOut = &state->kernelSources.obAttributesShift;
        break;
    case KSW_DYN_FIELD_ID_KT_INITIAL_STACK:
        *offsetOut = &state->kernel.ktInitialStack;
        *sourceOut = &state->kernelSources.ktInitialStack;
        break;
    case KSW_DYN_FIELD_ID_KT_STACK_LIMIT:
        *offsetOut = &state->kernel.ktStackLimit;
        *sourceOut = &state->kernelSources.ktStackLimit;
        break;
    case KSW_DYN_FIELD_ID_KT_STACK_BASE:
        *offsetOut = &state->kernel.ktStackBase;
        *sourceOut = &state->kernelSources.ktStackBase;
        break;
    case KSW_DYN_FIELD_ID_KT_KERNEL_STACK:
        *offsetOut = &state->kernel.ktKernelStack;
        *sourceOut = &state->kernelSources.ktKernelStack;
        break;
    case KSW_DYN_FIELD_ID_KT_READ_OPERATION_COUNT:
        *offsetOut = &state->kernel.ktReadOperationCount;
        *sourceOut = &state->kernelSources.ktReadOperationCount;
        break;
    case KSW_DYN_FIELD_ID_KT_WRITE_OPERATION_COUNT:
        *offsetOut = &state->kernel.ktWriteOperationCount;
        *sourceOut = &state->kernelSources.ktWriteOperationCount;
        break;
    case KSW_DYN_FIELD_ID_KT_OTHER_OPERATION_COUNT:
        *offsetOut = &state->kernel.ktOtherOperationCount;
        *sourceOut = &state->kernelSources.ktOtherOperationCount;
        break;
    case KSW_DYN_FIELD_ID_KT_READ_TRANSFER_COUNT:
        *offsetOut = &state->kernel.ktReadTransferCount;
        *sourceOut = &state->kernelSources.ktReadTransferCount;
        break;
    case KSW_DYN_FIELD_ID_KT_WRITE_TRANSFER_COUNT:
        *offsetOut = &state->kernel.ktWriteTransferCount;
        *sourceOut = &state->kernelSources.ktWriteTransferCount;
        break;
    case KSW_DYN_FIELD_ID_KT_OTHER_TRANSFER_COUNT:
        *offsetOut = &state->kernel.ktOtherTransferCount;
        *sourceOut = &state->kernelSources.ktOtherTransferCount;
        break;
    case KSW_DYN_FIELD_ID_MM_SECTION_CONTROL_AREA:
        *offsetOut = &state->kernel.mmSectionControlArea;
        *sourceOut = &state->kernelSources.mmSectionControlArea;
        break;
    case KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LIST_HEAD:
        *offsetOut = &state->kernel.mmControlAreaListHead;
        *sourceOut = &state->kernelSources.mmControlAreaListHead;
        break;
    case KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LOCK:
        *offsetOut = &state->kernel.mmControlAreaLock;
        *sourceOut = &state->kernelSources.mmControlAreaLock;
        break;
    case KSW_DYN_FIELD_ID_ALPC_COMMUNICATION_INFO:
        *offsetOut = &state->kernel.alpcCommunicationInfo;
        *sourceOut = &state->kernelSources.alpcCommunicationInfo;
        break;
    case KSW_DYN_FIELD_ID_ALPC_OWNER_PROCESS:
        *offsetOut = &state->kernel.alpcOwnerProcess;
        *sourceOut = &state->kernelSources.alpcOwnerProcess;
        break;
    case KSW_DYN_FIELD_ID_ALPC_CONNECTION_PORT:
        *offsetOut = &state->kernel.alpcConnectionPort;
        *sourceOut = &state->kernelSources.alpcConnectionPort;
        break;
    case KSW_DYN_FIELD_ID_ALPC_SERVER_COMMUNICATION_PORT:
        *offsetOut = &state->kernel.alpcServerCommunicationPort;
        *sourceOut = &state->kernelSources.alpcServerCommunicationPort;
        break;
    case KSW_DYN_FIELD_ID_ALPC_CLIENT_COMMUNICATION_PORT:
        *offsetOut = &state->kernel.alpcClientCommunicationPort;
        *sourceOut = &state->kernelSources.alpcClientCommunicationPort;
        break;
    case KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE:
        *offsetOut = &state->kernel.alpcHandleTable;
        *sourceOut = &state->kernelSources.alpcHandleTable;
        break;
    case KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE_LOCK:
        *offsetOut = &state->kernel.alpcHandleTableLock;
        *sourceOut = &state->kernelSources.alpcHandleTableLock;
        break;
    case KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES:
        *offsetOut = &state->kernel.alpcAttributes;
        *sourceOut = &state->kernelSources.alpcAttributes;
        break;
    case KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES_FLAGS:
        *offsetOut = &state->kernel.alpcAttributesFlags;
        *sourceOut = &state->kernelSources.alpcAttributesFlags;
        break;
    case KSW_DYN_FIELD_ID_ALPC_PORT_CONTEXT:
        *offsetOut = &state->kernel.alpcPortContext;
        *sourceOut = &state->kernelSources.alpcPortContext;
        break;
    case KSW_DYN_FIELD_ID_ALPC_PORT_OBJECT_LOCK:
        *offsetOut = &state->kernel.alpcPortObjectLock;
        *sourceOut = &state->kernelSources.alpcPortObjectLock;
        break;
    case KSW_DYN_FIELD_ID_ALPC_SEQUENCE_NO:
        *offsetOut = &state->kernel.alpcSequenceNo;
        *sourceOut = &state->kernelSources.alpcSequenceNo;
        break;
    case KSW_DYN_FIELD_ID_ALPC_STATE:
        *offsetOut = &state->kernel.alpcState;
        *sourceOut = &state->kernelSources.alpcState;
        break;
    case KSW_DYN_FIELD_ID_EP_PROTECTION:
        *offsetOut = &state->kernel.epProtection;
        *sourceOut = &state->kernelSources.epProtection;
        break;
    case KSW_DYN_FIELD_ID_EP_SIGNATURE_LEVEL:
        *offsetOut = &state->kernel.epSignatureLevel;
        *sourceOut = &state->kernelSources.epSignatureLevel;
        break;
    case KSW_DYN_FIELD_ID_EP_SECTION_SIGNATURE_LEVEL:
        *offsetOut = &state->kernel.epSectionSignatureLevel;
        *sourceOut = &state->kernelSources.epSectionSignatureLevel;
        break;
    case KSW_DYN_FIELD_ID_EGE_GUID:
        *offsetOut = &state->kernel.egeGuid;
        *sourceOut = &state->kernelSources.egeGuid;
        break;
    case KSW_DYN_FIELD_ID_ERE_GUID_ENTRY:
        *offsetOut = &state->kernel.ereGuidEntry;
        *sourceOut = &state->kernelSources.ereGuidEntry;
        break;
    case KSW_DYN_FIELD_ID_KLDR_IN_LOAD_ORDER_LINKS:
        *offsetOut = &state->kernel.kldrInLoadOrderLinks;
        *sourceOut = &state->kernelSources.kldrInLoadOrderLinks;
        break;
    case KSW_DYN_FIELD_ID_KLDR_DLL_BASE:
        *offsetOut = &state->kernel.kldrDllBase;
        *sourceOut = &state->kernelSources.kldrDllBase;
        break;
    case KSW_DYN_FIELD_ID_KLDR_SIZE_OF_IMAGE:
        *offsetOut = &state->kernel.kldrSizeOfImage;
        *sourceOut = &state->kernelSources.kldrSizeOfImage;
        break;
    case KSW_DYN_FIELD_ID_KLDR_FULL_DLL_NAME:
        *offsetOut = &state->kernel.kldrFullDllName;
        *sourceOut = &state->kernelSources.kldrFullDllName;
        break;
    case KSW_DYN_FIELD_ID_KLDR_BASE_DLL_NAME:
        *offsetOut = &state->kernel.kldrBaseDllName;
        *sourceOut = &state->kernelSources.kldrBaseDllName;
        break;
    case KSW_DYN_FIELD_ID_KLDR_FLAGS:
        *offsetOut = &state->kernel.kldrFlags;
        *sourceOut = &state->kernelSources.kldrFlags;
        break;
    case KSW_DYN_FIELD_ID_DO_DRIVER_START:
        *offsetOut = &state->kernel.doDriverStart;
        *sourceOut = &state->kernelSources.doDriverStart;
        break;
    case KSW_DYN_FIELD_ID_DO_DRIVER_SIZE:
        *offsetOut = &state->kernel.doDriverSize;
        *sourceOut = &state->kernelSources.doDriverSize;
        break;
    case KSW_DYN_FIELD_ID_DO_DRIVER_SECTION:
        *offsetOut = &state->kernel.doDriverSection;
        *sourceOut = &state->kernelSources.doDriverSection;
        break;
    case KSW_DYN_FIELD_ID_DO_MAJOR_FUNCTION:
        *offsetOut = &state->kernel.doMajorFunction;
        *sourceOut = &state->kernelSources.doMajorFunction;
        break;
    case KSW_DYN_FIELD_ID_DO_FAST_IO_DISPATCH:
        *offsetOut = &state->kernel.doFastIoDispatch;
        *sourceOut = &state->kernelSources.doFastIoDispatch;
        break;
    case KSW_DYN_FIELD_ID_DO_DRIVER_UNLOAD:
        *offsetOut = &state->kernel.doDriverUnload;
        *sourceOut = &state->kernelSources.doDriverUnload;
        break;
    case KSW_DYN_FIELD_ID_ULD_NAME:
        *offsetOut = &state->kernel.uldName;
        *sourceOut = &state->kernelSources.uldName;
        break;
    case KSW_DYN_FIELD_ID_ULD_START_ADDRESS:
        *offsetOut = &state->kernel.uldStartAddress;
        *sourceOut = &state->kernelSources.uldStartAddress;
        break;
    case KSW_DYN_FIELD_ID_ULD_END_ADDRESS:
        *offsetOut = &state->kernel.uldEndAddress;
        *sourceOut = &state->kernelSources.uldEndAddress;
        break;
    case KSW_DYN_FIELD_ID_ULD_CURRENT_TIME:
        *offsetOut = &state->kernel.uldCurrentTime;
        *sourceOut = &state->kernelSources.uldCurrentTime;
        break;
    case KSW_DYN_FIELD_ID_ULD_TYPE_SIZE:
        *offsetOut = &state->kernel.uldTypeSize;
        *sourceOut = &state->kernelSources.uldTypeSize;
        break;
    case KSW_DYN_FIELD_ID_RTL_AVL_BALANCED_ROOT:
        *offsetOut = &state->kernel.rtlAvlBalancedRoot;
        *sourceOut = &state->kernelSources.rtlAvlBalancedRoot;
        break;
    case KSW_DYN_FIELD_ID_RTL_AVL_ORDERED_POINTER:
        *offsetOut = &state->kernel.rtlAvlOrderedPointer;
        *sourceOut = &state->kernelSources.rtlAvlOrderedPointer;
        break;
    case KSW_DYN_FIELD_ID_RTL_AVL_WHICH_ORDERED_ELEMENT:
        *offsetOut = &state->kernel.rtlAvlWhichOrderedElement;
        *sourceOut = &state->kernelSources.rtlAvlWhichOrderedElement;
        break;
    case KSW_DYN_FIELD_ID_RTL_AVL_NUMBER_GENERIC_TABLE_ELEMENTS:
        *offsetOut = &state->kernel.rtlAvlNumberGenericTableElements;
        *sourceOut = &state->kernelSources.rtlAvlNumberGenericTableElements;
        break;
    case KSW_DYN_FIELD_ID_RTL_AVL_DEPTH_OF_TREE:
        *offsetOut = &state->kernel.rtlAvlDepthOfTree;
        *sourceOut = &state->kernelSources.rtlAvlDepthOfTree;
        break;
    case KSW_DYN_FIELD_ID_RTL_AVL_RESTART_KEY:
        *offsetOut = &state->kernel.rtlAvlRestartKey;
        *sourceOut = &state->kernelSources.rtlAvlRestartKey;
        break;
    case KSW_DYN_FIELD_ID_RTL_AVL_DELETE_COUNT:
        *offsetOut = &state->kernel.rtlAvlDeleteCount;
        *sourceOut = &state->kernelSources.rtlAvlDeleteCount;
        break;
    case KSW_DYN_FIELD_ID_RTL_AVL_TYPE_SIZE:
        *offsetOut = &state->kernel.rtlAvlTypeSize;
        *sourceOut = &state->kernelSources.rtlAvlTypeSize;
        break;
    case KSW_DYN_FIELD_ID_PIDDB_DRIVER_NAME:
        *offsetOut = &state->kernel.piDdbDriverName;
        *sourceOut = &state->kernelSources.piDdbDriverName;
        break;
    case KSW_DYN_FIELD_ID_PIDDB_TIME_DATE_STAMP:
        *offsetOut = &state->kernel.piDdbTimeDateStamp;
        *sourceOut = &state->kernelSources.piDdbTimeDateStamp;
        break;
    case KSW_DYN_FIELD_ID_PIDDB_LOAD_STATUS:
        *offsetOut = &state->kernel.piDdbLoadStatus;
        *sourceOut = &state->kernelSources.piDdbLoadStatus;
        break;
    case KSW_DYN_FIELD_ID_PIDDB_TYPE_SIZE:
        *offsetOut = &state->kernel.piDdbTypeSize;
        *sourceOut = &state->kernelSources.piDdbTypeSize;
        break;
    default:
        return FALSE;
    }

    return (*offsetOut != NULL && *sourceOut != NULL) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkDynDataKernelGlobalRvaPointers(
    _In_ ULONG fieldId,
    _Inout_ KswDynState* state,
    _Outptr_ ULONG** rvaOut,
    _Outptr_ ULONG** sourceOut
    )
/*++

Routine Description:

    Resolve one non-callback ntoskrnl global item ID into the internal
    RVA/source slots. These optional globals support future process/thread
    cross-view walks, module list validation, unloaded-driver attribution, and
    PiDDB cache checks, and Shadow SSDT service-routine resolution.

Arguments:

    FieldId - KSW_DYN_FIELD_ID_KG_* global item ID supplied by R3.
    State - Mutable state snapshot that owns destination fields.
    RvaOut - Receives a pointer to the target RVA slot.
    SourceOut - Receives a pointer to the target source slot.

Return Value:

    TRUE when the item ID is a supported kernel global RVA; otherwise FALSE.

--*/
{
    if (state == NULL || rvaOut == NULL || sourceOut == NULL) {
        return FALSE;
    }

    *rvaOut = NULL;
    *sourceOut = NULL;

    switch (fieldId) {
    case KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE:
        *rvaOut = &state->kernelGlobals.pspCidTable;
        *sourceOut = &state->kernelGlobalSources.pspCidTable;
        break;
    case KSW_DYN_FIELD_ID_KG_PS_LOADED_MODULE_LIST:
        *rvaOut = &state->kernelGlobals.psLoadedModuleList;
        *sourceOut = &state->kernelGlobalSources.psLoadedModuleList;
        break;
    case KSW_DYN_FIELD_ID_KG_MM_UNLOADED_DRIVERS:
        *rvaOut = &state->kernelGlobals.mmUnloadedDrivers;
        *sourceOut = &state->kernelGlobalSources.mmUnloadedDrivers;
        break;
    case KSW_DYN_FIELD_ID_KG_PIDDB_CACHE_TABLE:
        *rvaOut = &state->kernelGlobals.piDdbCacheTable;
        *sourceOut = &state->kernelGlobalSources.piDdbCacheTable;
        break;
    case KSW_DYN_FIELD_ID_KG_PIDDB_LOCK:
        *rvaOut = &state->kernelGlobals.piDdbLock;
        *sourceOut = &state->kernelGlobalSources.piDdbLock;
        break;
    case KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW:
        *rvaOut = &state->kernelGlobals.keServiceDescriptorTableShadow;
        *sourceOut = &state->kernelGlobalSources.keServiceDescriptorTableShadow;
        break;
    case KSW_DYN_FIELD_ID_KG_MM_LAST_UNLOADED_DRIVER:
        *rvaOut = &state->kernelGlobals.mmLastUnloadedDriver;
        *sourceOut = &state->kernelGlobalSources.mmLastUnloadedDriver;
        break;
    default:
        return FALSE;
    }

    return (*rvaOut != NULL && *sourceOut != NULL) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkDynDataCallbackGlobalPointers(
    _In_ ULONG fieldId,
    _Inout_ KswDynState* state,
    _Outptr_ ULONG** rvaOut,
    _Outptr_ ULONG** sourceOut
    )
/*++

Routine Description:

    Resolve one callback global item ID into the internal RVA/source slots. EX
    profile requests carry global addresses as RVAs so the driver can validate
    them against SizeOfImage before callback code converts them to VAs.

Arguments:

    FieldId - KSW_DYN_FIELD_ID_CB_* global item ID supplied by R3.
    State - Mutable state snapshot that owns destination fields.
    RvaOut - Receives a pointer to the target RVA slot.
    SourceOut - Receives a pointer to the target source slot.

Return Value:

    TRUE when the item ID is a supported callback global; otherwise FALSE.

--*/
{
    if (state == NULL || rvaOut == NULL || sourceOut == NULL) {
        return FALSE;
    }

    *rvaOut = NULL;
    *sourceOut = NULL;

    switch (fieldId) {
    case KSW_DYN_FIELD_ID_CB_PSP_CREATE_PROCESS_NOTIFY_ROUTINE:
        *rvaOut = &state->callbackGlobals.pspCreateProcessNotifyRoutine;
        *sourceOut = &state->callbackGlobalSources.pspCreateProcessNotifyRoutine;
        break;
    case KSW_DYN_FIELD_ID_CB_PSP_CREATE_THREAD_NOTIFY_ROUTINE:
        *rvaOut = &state->callbackGlobals.pspCreateThreadNotifyRoutine;
        *sourceOut = &state->callbackGlobalSources.pspCreateThreadNotifyRoutine;
        break;
    case KSW_DYN_FIELD_ID_CB_PSP_LOAD_IMAGE_NOTIFY_ROUTINE:
        *rvaOut = &state->callbackGlobals.pspLoadImageNotifyRoutine;
        *sourceOut = &state->callbackGlobalSources.pspLoadImageNotifyRoutine;
        break;
    case KSW_DYN_FIELD_ID_CB_PSP_NOTIFY_ENABLE_MASK:
        *rvaOut = &state->callbackGlobals.pspNotifyEnableMask;
        *sourceOut = &state->callbackGlobalSources.pspNotifyEnableMask;
        break;
    case KSW_DYN_FIELD_ID_CB_CM_CALLBACK_LIST_HEAD:
        *rvaOut = &state->callbackGlobals.cmCallbackListHead;
        *sourceOut = &state->callbackGlobalSources.cmCallbackListHead;
        break;
    default:
        return FALSE;
    }

    return (*rvaOut != NULL && *sourceOut != NULL) ? TRUE : FALSE;
}

static BOOLEAN
kswordArkDynDataCallbackOffsetPointers(
    _In_ ULONG fieldId,
    _Inout_ KswDynState* state,
    _Outptr_ ULONG** offsetOut,
    _Outptr_ ULONG** sourceOut
    )
/*++

Routine Description:

    Resolve one callback structure item ID into the internal offset/source
    slots. These fields describe private callback-related structures and are
    applied only after the ntoskrnl identity has matched exactly.

Arguments:

    FieldId - KSW_DYN_FIELD_ID_CB_* structure item ID supplied by R3.
    State - Mutable state snapshot that owns destination fields.
    OffsetOut - Receives a pointer to the target offset slot.
    SourceOut - Receives a pointer to the target source slot.

Return Value:

    TRUE when the item ID is a supported callback structure offset; otherwise
    FALSE.

--*/
{
    if (state == NULL || offsetOut == NULL || sourceOut == NULL) {
        return FALSE;
    }

    *offsetOut = NULL;
    *sourceOut = NULL;

    switch (fieldId) {
    case KSW_DYN_FIELD_ID_CB_OBJECT_TYPE_CALLBACK_LIST:
        *offsetOut = &state->callbackOffsets.objectTypeCallbackList;
        *sourceOut = &state->callbackOffsetSources.objectTypeCallbackList;
        break;
    case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST:
        *offsetOut = &state->callbackOffsets.callbackEntryItemEntryList;
        *sourceOut = &state->callbackOffsetSources.callbackEntryItemEntryList;
        break;
    case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_PRE_OPERATION:
        *offsetOut = &state->callbackOffsets.callbackEntryItemPreOperation;
        *sourceOut = &state->callbackOffsetSources.callbackEntryItemPreOperation;
        break;
    case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_POST_OPERATION:
        *offsetOut = &state->callbackOffsets.callbackEntryItemPostOperation;
        *sourceOut = &state->callbackOffsetSources.callbackEntryItemPostOperation;
        break;
    case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_OPERATIONS:
        *offsetOut = &state->callbackOffsets.callbackEntryItemOperations;
        *sourceOut = &state->callbackOffsetSources.callbackEntryItemOperations;
        break;
    case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_CALLBACK_ENTRY:
        *offsetOut = &state->callbackOffsets.callbackEntryItemCallbackEntry;
        *sourceOut = &state->callbackOffsetSources.callbackEntryItemCallbackEntry;
        break;
    case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ALTITUDE:
        *offsetOut = &state->callbackOffsets.callbackEntryAltitude;
        *sourceOut = &state->callbackOffsetSources.callbackEntryAltitude;
        break;
    case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_REGISTRATION_CONTEXT:
        *offsetOut = &state->callbackOffsets.callbackEntryRegistrationContext;
        *sourceOut = &state->callbackOffsetSources.callbackEntryRegistrationContext;
        break;
    default:
        return FALSE;
    }

    return (*offsetOut != NULL && *sourceOut != NULL) ? TRUE : FALSE;
}

NTSTATUS
kswordArkDynDataApplyProfile(
    _In_reads_bytes_(inputBufferLength) const KSW_APPLY_DYN_PROFILE_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSW_APPLY_DYN_PROFILE_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Validate and merge one R3-supplied PDB profile into the global DynData state.
    The driver accepts only packed field IDs and offsets; it never parses JSON or
    PDB data. The merge is copy-on-success: all request checks and all field
    checks complete against a local state copy before the global state is
    replaced, so invalid profiles cannot corrupt the active DynData snapshot.

Arguments:

    Request - Packed profile request from R3.
    InputBufferLength - Total request bytes available.
    Response - Fixed response packet.
    OutputBufferLength - Writable response bytes.
    BytesWrittenOut - Receives sizeof(KSW_APPLY_DYN_PROFILE_RESPONSE) on success
        and on handled validation failure.

Return Value:

    STATUS_SUCCESS when a profile was applied; validation status on rejected
    requests. Response->status mirrors the same result for R3 diagnostics.

--*/
{
    KswDynState candidateState;
    NTSTATUS status = STATUS_SUCCESS;
    size_t requiredBytes = 0U;
    ULONG index = 0UL;
    ULONG appliedCount = 0UL;
    ULONG rejectedCount = 0UL;
    ULONG unknownCount = 0UL;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (response == NULL || outputBufferLength < sizeof(KSW_APPLY_DYN_PROFILE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(response, outputBufferLength);
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
    response->status = STATUS_UNSUCCESSFUL;
    kswordArkDynDataApplySetMessage(response->message, L"PDB profile apply did not run.");
    *bytesWrittenOut = sizeof(*response);

    if (request == NULL) {
        status = STATUS_INVALID_PARAMETER;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile request is null.");
        response->status = status;
        return status;
    }
    if (inputBufferLength < KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE) {
        status = STATUS_BUFFER_TOO_SMALL;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile request header is too small.");
        response->status = status;
        return status;
    }
    if (request->version != KSWORD_ARK_DYNDATA_PROTOCOL_VERSION) {
        status = STATUS_REVISION_MISMATCH;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile protocol version mismatch.");
        response->status = status;
        return status;
    }
    if (request->fieldCount == 0UL || request->fieldCount > KSW_DYN_PROFILE_MAX_FIELDS) {
        status = STATUS_INVALID_PARAMETER;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile field count is invalid.");
        response->status = status;
        return status;
    }
    if (request->size < KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE) {
        status = STATUS_INVALID_PARAMETER;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile request size is invalid.");
        response->status = status;
        return status;
    }
    if ((request->fieldCount - 1UL) >
        ((MAXSIZE_T - KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE) / sizeof(KSW_DYN_PROFILE_FIELD_PACKET))) {
        status = STATUS_INTEGER_OVERFLOW;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile request size overflow.");
        response->status = status;
        return status;
    }

    requiredBytes = KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE +
        ((size_t)request->fieldCount * sizeof(KSW_DYN_PROFILE_FIELD_PACKET));
    if ((size_t)request->size < requiredBytes || inputBufferLength < requiredBytes) {
        status = STATUS_BUFFER_TOO_SMALL;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile request does not contain all fields.");
        response->status = status;
        return status;
    }

    kswordArkAcquirePushLockShared(&gKswordDynDataStateLock);
    RtlCopyMemory(&candidateState, &gKswordDynDataState, sizeof(candidateState));
    kswordArkReleasePushLockShared(&gKswordDynDataStateLock);

    if (!kswordArkDynDataIdentityMatches(&candidateState.ntoskrnl, &request->ntoskrnl)) {
        status = STATUS_NOT_SUPPORTED;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile does not match the current ntoskrnl identity.");
        response->status = status;
        response->statusFlags = kswordArkDynDataPublicStatusFlags(&candidateState);
        response->capabilityMask = candidateState.capabilityMask;
        return status;
    }

    for (index = 0UL; index < request->fieldCount; ++index) {
        const KSW_DYN_PROFILE_FIELD_PACKET* field = &request->fields[index];
        ULONG* destinationOffset = NULL;
        ULONG* destinationSource = NULL;

        if (field->fieldId == 0UL || field->fieldId > KSW_DYN_FIELD_ID_MAX ||
            field->offset == KSW_DYN_OFFSET_UNAVAILABLE ||
            field->offset > KSW_DYN_PROFILE_OFFSET_MAX) {
            rejectedCount += 1UL;
            continue;
        }

        if (!kswordArkDynDataKernelFieldPointers(
            field->fieldId,
            &candidateState,
            &destinationOffset,
            &destinationSource)) {
            unknownCount += 1UL;
            continue;
        }

        kswordArkDynDataStoreSourcedOffset(
            field->offset,
            KSW_DYN_FIELD_SOURCE_PDB_PROFILE,
            destinationOffset,
            destinationSource);
        appliedCount += 1UL;
    }

    response->appliedFieldCount = appliedCount;
    response->rejectedFieldCount = rejectedCount;
    response->unknownFieldCount = unknownCount;

    if (appliedCount == 0UL || rejectedCount != 0UL || unknownCount != 0UL) {
        status = STATUS_INVALID_PARAMETER;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile contained invalid or unsupported fields; active state was left unchanged.");
        response->status = status;
        response->statusFlags = kswordArkDynDataPublicStatusFlags(&candidateState);
        response->capabilityMask = candidateState.capabilityMask;
        return status;
    }

    candidateState.pdbProfileActive = TRUE;
    candidateState.ntosActive = TRUE;
    candidateState.capabilityMask = kswordArkDynDataComputeCapabilities(&candidateState);
    candidateState.lastStatus = STATUS_SUCCESS;
    kswordArkDynDataSetReason(&candidateState, L"PDB profile applied and merged with runtime DynData.");

    kswordArkAcquirePushLockExclusive(&gKswordDynDataStateLock);
    RtlCopyMemory(&gKswordDynDataState, &candidateState, sizeof(gKswordDynDataState));
    kswordArkReleasePushLockExclusive(&gKswordDynDataStateLock);

    response->status = STATUS_SUCCESS;
    response->statusFlags = kswordArkDynDataPublicStatusFlags(&candidateState);
    response->capabilityMask = candidateState.capabilityMask;
    kswordArkDynDataApplySetMessage(response->message, L"PDB profile applied successfully.");
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDynDataApplyProfileEx(
    _In_reads_bytes_(inputBufferLength) const KSW_APPLY_DYN_PROFILE_EX_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSW_APPLY_DYN_PROFILE_EX_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Validate and merge one extended R3-supplied PDB profile into the typed
    DynData portion of the global state. This v2/v3 path accepts only typed
    items: structure offsets and ntoskrnl global RVAs. The driver still never
    parses JSON/PDB/pack content; R3 must send compact numeric IDs after local
    schema validation. The merge is copy-on-success so malformed items never
    poison the active DynData snapshot.

Arguments:

    Request - Packed extended profile request from R3.
    InputBufferLength - Total request bytes available.
    Response - Fixed extended response packet.
    OutputBufferLength - Writable response bytes.
    BytesWrittenOut - Receives sizeof(KSW_APPLY_DYN_PROFILE_EX_RESPONSE) on
        success and on handled validation failure.

Return Value:

    STATUS_SUCCESS when at least one extended item was applied; validation
    status on rejected requests. Response->status mirrors the semantic result.

--*/
{
    KswDynState candidateState;
    NTSTATUS status = STATUS_SUCCESS;
    size_t requiredBytes = 0U;
    ULONG index = 0UL;
    ULONG appliedCount = 0UL;
    ULONG rejectedCount = 0UL;
    ULONG unknownCount = 0UL;
    BOOLEAN callbackItemApplied = FALSE;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (response == NULL || outputBufferLength < sizeof(KSW_APPLY_DYN_PROFILE_EX_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(response, outputBufferLength);
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
    response->status = STATUS_UNSUCCESSFUL;
    kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX apply did not run.");
    *bytesWrittenOut = sizeof(*response);

    if (request == NULL) {
        status = STATUS_INVALID_PARAMETER;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX request is null.");
        response->status = status;
        return status;
    }
    if (inputBufferLength < KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE) {
        status = STATUS_BUFFER_TOO_SMALL;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX request header is too small.");
        response->status = status;
        return status;
    }
    if (request->version != KSWORD_ARK_DYNDATA_PROTOCOL_VERSION) {
        status = STATUS_REVISION_MISMATCH;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX protocol version mismatch.");
        response->status = status;
        return status;
    }
    if (request->itemCount == 0UL || request->itemCount > KSW_DYN_PROFILE_EX_MAX_ITEMS) {
        status = STATUS_INVALID_PARAMETER;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX item count is invalid.");
        response->status = status;
        return status;
    }
    if (request->size < KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE) {
        status = STATUS_INVALID_PARAMETER;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX request size is invalid.");
        response->status = status;
        return status;
    }
    if ((request->itemCount - 1UL) >
        ((MAXSIZE_T - KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE) / sizeof(KSW_DYN_PROFILE_EX_ITEM_PACKET))) {
        status = STATUS_INTEGER_OVERFLOW;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX request size overflow.");
        response->status = status;
        return status;
    }

    requiredBytes = KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE +
        ((size_t)request->itemCount * sizeof(KSW_DYN_PROFILE_EX_ITEM_PACKET));
    if ((size_t)request->size < requiredBytes || inputBufferLength < requiredBytes) {
        status = STATUS_BUFFER_TOO_SMALL;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX request does not contain all items.");
        response->status = status;
        return status;
    }

    kswordArkAcquirePushLockShared(&gKswordDynDataStateLock);
    RtlCopyMemory(&candidateState, &gKswordDynDataState, sizeof(candidateState));
    kswordArkReleasePushLockShared(&gKswordDynDataStateLock);

    if (!kswordArkDynDataIdentityMatches(&candidateState.ntoskrnl, &request->ntoskrnl)) {
        status = STATUS_NOT_SUPPORTED;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX does not match the current ntoskrnl identity.");
        response->status = status;
        response->statusFlags = kswordArkDynDataPublicStatusFlags(&candidateState);
        response->capabilityMask = candidateState.capabilityMask;
        return status;
    }

    for (index = 0UL; index < request->itemCount; ++index) {
        const KSW_DYN_PROFILE_EX_ITEM_PACKET* item = &request->items[index];
        ULONG* destinationValue = NULL;
        ULONG* destinationSource = NULL;

        if (item->itemId == 0UL || item->itemId > KSW_DYN_FIELD_ID_MAX ||
            (item->flags & ~(KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED | KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK)) != 0UL) {
            rejectedCount += 1UL;
            continue;
        }

        if (item->itemKind == KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA) {
            if (item->value == 0UL ||
                item->value >= candidateState.ntoskrnl.sizeOfImage ||
                item->value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX) {
                rejectedCount += 1UL;
                continue;
            }
            if (!kswordArkDynDataCallbackGlobalPointers(
                    item->itemId,
                    &candidateState,
                    &destinationValue,
                    &destinationSource) &&
                !kswordArkDynDataKernelGlobalRvaPointers(
                    item->itemId,
                    &candidateState,
                    &destinationValue,
                    &destinationSource)) {
                unknownCount += 1UL;
                continue;
            }
        }
        else if (item->itemKind == KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET) {
            if (item->value == KSW_DYN_OFFSET_UNAVAILABLE ||
                item->value > KSW_DYN_PROFILE_OFFSET_MAX) {
                rejectedCount += 1UL;
                continue;
            }
            if (!kswordArkDynDataCallbackOffsetPointers(
                    item->itemId,
                    &candidateState,
                    &destinationValue,
                    &destinationSource) &&
                !kswordArkDynDataKernelFieldPointers(
                    item->itemId,
                    &candidateState,
                    &destinationValue,
                    &destinationSource)) {
                unknownCount += 1UL;
                continue;
            }
        }
        else {
            rejectedCount += 1UL;
            continue;
        }

        kswordArkDynDataStoreSourcedOffset(
            item->value,
            KSW_DYN_FIELD_SOURCE_PDB_PROFILE,
            destinationValue,
            destinationSource);
        if ((item->flags & KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK) != 0UL) {
            callbackItemApplied = TRUE;
        }
        appliedCount += 1UL;
    }

    response->appliedItemCount = appliedCount;
    response->rejectedItemCount = rejectedCount;
    response->unknownItemCount = unknownCount;

    if (appliedCount == 0UL || rejectedCount != 0UL || unknownCount != 0UL) {
        status = STATUS_INVALID_PARAMETER;
        kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX contained invalid or unsupported items; active state was left unchanged.");
        response->status = status;
        response->statusFlags = kswordArkDynDataPublicStatusFlags(&candidateState);
        response->capabilityMask = candidateState.capabilityMask;
        return status;
    }

    candidateState.pdbProfileActive = TRUE;
    candidateState.callbackProfileActive = callbackItemApplied ? TRUE : candidateState.callbackProfileActive;
    candidateState.ntosActive = TRUE;
    candidateState.capabilityMask = kswordArkDynDataComputeCapabilities(&candidateState);
    candidateState.lastStatus = STATUS_SUCCESS;
    kswordArkDynDataSetReason(&candidateState, L"PDB profile EX applied and merged with callback DynData.");

    kswordArkAcquirePushLockExclusive(&gKswordDynDataStateLock);
    RtlCopyMemory(&gKswordDynDataState, &candidateState, sizeof(gKswordDynDataState));
    kswordArkReleasePushLockExclusive(&gKswordDynDataStateLock);

    response->status = STATUS_SUCCESS;
    response->statusFlags = kswordArkDynDataPublicStatusFlags(&candidateState);
    response->capabilityMask = candidateState.capabilityMask;
    kswordArkDynDataApplySetMessage(response->message, L"PDB profile EX applied successfully.");
    return STATUS_SUCCESS;
}
