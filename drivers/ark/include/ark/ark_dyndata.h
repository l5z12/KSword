#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkDynDataIoctl.h"

EXTERN_C_START

#define KSW_DYN_OFFSET_UNAVAILABLE 0xFFFFFFFFUL
#define KSW_DYN_CAPABILITY_NONE 0ULL

typedef struct KswDynKernelOffsets
{
    ULONG epObjectTable;
    ULONG epSectionObject;
    ULONG epUniqueProcessId;
    ULONG epActiveProcessLinks;
    ULONG epThreadListHead;
    ULONG epImageFileName;
    ULONG epToken;
    ULONG epFlags;
    ULONG epFlags2;
    ULONG epRundownProtect;
    ULONG epProcessLock;
    ULONG epCreateTime;
    ULONG epExitTime;
    ULONG epExitStatus;
    ULONG epPeb;
    ULONG epSession;
    ULONG epWin32Process;
    ULONG epWow64Process;
    ULONG epInheritedFromUniqueProcessId;
    ULONG epSeAuditProcessCreationInfo;
    ULONG epJob;
    ULONG epDeviceMap;
    ULONG epDebugPort;
    ULONG epExceptionPortData;
    ULONG epSectionBaseAddress;
    ULONG epImageFilePointer;
    ULONG epPriorityClass;
    ULONG epActiveThreads;
    ULONG epVadRoot;
    ULONG epVadHint;
    ULONG epCloneRoot;
    ULONG epNumberOfPrivatePages;
    ULONG epNumberOfLockedPages;
    ULONG epCommitCharge;
    ULONG epCommitChargePeak;
    ULONG epPeakVirtualSize;
    ULONG epVirtualSize;
    ULONG epSessionProcessLinks;
    ULONG epMitigationFlags;
    ULONG epMitigationFlags2;
    ULONG epProcessQuotaUsage;
    ULONG epProcessQuotaPeak;
    ULONG epAddressCreationLock;
    ULONG epPageTableCommitmentLock;
    ULONG epRotateInProgress;
    ULONG epForkInProgress;
    ULONG epCommitChargeJob;
    ULONG epCookie;
    ULONG epWorkingSetWatch;
    ULONG epWin32WindowStation;
    ULONG epOwnerProcessId;
    ULONG epQuotaBlock;
    ULONG epEtwDataSource;
    ULONG epPageDirectoryPte;
    ULONG epSecurityPort;
    ULONG epJobLinks;
    ULONG epHighestUserAddress;
    ULONG epImagePathHash;
    ULONG epDefaultHardErrorProcessing;
    ULONG epLastThreadExitStatus;
    ULONG epPrefetchTrace;
    ULONG epLockedPagesList;
    ULONG epReadOperationCount;
    ULONG epWriteOperationCount;
    ULONG epOtherOperationCount;
    ULONG epReadTransferCount;
    ULONG epWriteTransferCount;
    ULONG epOtherTransferCount;
    ULONG epCommitChargeLimit;
    ULONG epVm;
    ULONG epMmProcessLinks;
    ULONG epModifiedPageCount;
    ULONG epVadCount;
    ULONG epVadPhysicalPages;
    ULONG epVadPhysicalPagesLimit;
    ULONG epAlpcContext;
    ULONG epTimerResolutionLink;
    ULONG epTimerResolutionStackRecord;
    ULONG epRequestedTimerResolution;
    ULONG epSmallestTimerResolution;
    ULONG epInvertedFunctionTable;
    ULONG epInvertedFunctionTableLock;
    ULONG epActiveThreadsHighWatermark;
    ULONG epLargePrivateVadCount;
    ULONG epThreadListLock;
    ULONG epWnfContext;
    ULONG epFlags3;
    ULONG epDiskCounters;
    ULONG tokTokenSource;
    ULONG tokTokenId;
    ULONG tokAuthenticationId;
    ULONG tokParentTokenId;
    ULONG tokExpirationTime;
    ULONG tokTokenLock;
    ULONG tokModifiedId;
    ULONG tokPrivileges;
    ULONG tokAuditPolicy;
    ULONG tokSessionId;
    ULONG tokUserAndGroupCount;
    ULONG tokRestrictedSidCount;
    ULONG tokVariableLength;
    ULONG tokDynamicCharged;
    ULONG tokDynamicAvailable;
    ULONG tokDefaultOwnerIndex;
    ULONG tokUserAndGroups;
    ULONG tokRestrictedSids;
    ULONG tokPrimaryGroup;
    ULONG tokDynamicPart;
    ULONG tokDefaultDacl;
    ULONG tokTokenType;
    ULONG tokImpersonationLevel;
    ULONG tokTokenFlags;
    ULONG tokTokenInUse;
    ULONG tokIntegrityLevelIndex;
    ULONG tokMandatoryPolicy;
    ULONG tokLogonSession;
    ULONG tokOriginatingLogonSession;
    ULONG tokSidHash;
    ULONG tokRestrictedSidHash;
    ULONG tokPSecurityAttributes;
    ULONG tokPackage;
    ULONG tokCapabilities;
    ULONG tokCapabilityCount;
    ULONG tokCapabilitiesHash;
    ULONG tokLowboxNumberEntry;
    ULONG tokLowboxHandlesEntry;
    ULONG tokPClaimAttributes;
    ULONG tokTrustLevelSid;
    ULONG tokTrustLinkedToken;
    ULONG tokIntegrityLevelSidValue;
    ULONG tokTokenSidValues;
    ULONG tokSessionObject;
    ULONG tokVariablePart;
    ULONG etCid;
    ULONG etThreadListEntry;
    ULONG etStartAddress;
    ULONG etWin32StartAddress;
    ULONG ktProcess;
    ULONG htHandleContentionEvent;
    ULONG htTableCode;
    ULONG htHandleCount;
    ULONG hteLowValue;
    ULONG otName;
    ULONG otIndex;
    ULONG obDecodeShift;
    ULONG obAttributesShift;
    ULONG egeGuid;
    ULONG ereGuidEntry;
    ULONG ktInitialStack;
    ULONG ktStackLimit;
    ULONG ktStackBase;
    ULONG ktKernelStack;
    ULONG ktReadOperationCount;
    ULONG ktWriteOperationCount;
    ULONG ktOtherOperationCount;
    ULONG ktReadTransferCount;
    ULONG ktWriteTransferCount;
    ULONG ktOtherTransferCount;
    ULONG mmSectionControlArea;
    ULONG mmControlAreaListHead;
    ULONG mmControlAreaLock;
    ULONG alpcCommunicationInfo;
    ULONG alpcOwnerProcess;
    ULONG alpcConnectionPort;
    ULONG alpcServerCommunicationPort;
    ULONG alpcClientCommunicationPort;
    ULONG alpcHandleTable;
    ULONG alpcHandleTableLock;
    ULONG alpcAttributes;
    ULONG alpcAttributesFlags;
    ULONG alpcPortContext;
    ULONG alpcPortObjectLock;
    ULONG alpcSequenceNo;
    ULONG alpcState;
    ULONG epProtection;
    ULONG epSignatureLevel;
    ULONG epSectionSignatureLevel;
    ULONG kldrInLoadOrderLinks;
    ULONG kldrDllBase;
    ULONG kldrSizeOfImage;
    ULONG kldrFullDllName;
    ULONG kldrBaseDllName;
    ULONG kldrFlags;
    ULONG doDriverStart;
    ULONG doDriverSize;
    ULONG doDriverSection;
    ULONG doMajorFunction;
    ULONG doFastIoDispatch;
    ULONG doDriverUnload;
    ULONG uldName;
    ULONG uldStartAddress;
    ULONG uldEndAddress;
    ULONG uldCurrentTime;
    ULONG uldTypeSize;
    ULONG rtlAvlBalancedRoot;
    ULONG rtlAvlOrderedPointer;
    ULONG rtlAvlWhichOrderedElement;
    ULONG rtlAvlNumberGenericTableElements;
    ULONG rtlAvlDepthOfTree;
    ULONG rtlAvlRestartKey;
    ULONG rtlAvlDeleteCount;
    ULONG rtlAvlTypeSize;
    ULONG piDdbDriverName;
    ULONG piDdbTimeDateStamp;
    ULONG piDdbLoadStatus;
    ULONG piDdbTypeSize;
} KswDynKernelOffsets, *PkswDynKernelOffsets;

typedef struct KswDynLxcoreOffsets
{
    ULONG lxPicoProc;
    ULONG lxPicoProcInfo;
    ULONG lxPicoProcInfoPid;
    ULONG lxPicoThrdInfo;
    ULONG lxPicoThrdInfoTid;
} KswDynLxcoreOffsets, *PkswDynLxcoreOffsets;

/*
 * KswDynKernelGlobals
 * Inputs:
 * - Populated from R3 PDB profile EX GlobalRva items after ntoskrnl identity
 *   matching.
 * Processing:
 * - Stores RVAs, not kernel virtual addresses, so consumers can validate them
 *   against the active image and derive addresses from the current image base.
 * Return behavior:
 * - Plain state container; no function-like return value.
 */
typedef struct KswDynKernelGlobals
{
    ULONG pspCidTable;
    ULONG psLoadedModuleList;
    ULONG mmUnloadedDrivers;
    ULONG piDdbCacheTable;
    ULONG piDdbLock;
    ULONG keServiceDescriptorTableShadow;
    ULONG mmLastUnloadedDriver;
} KswDynKernelGlobals, *PkswDynKernelGlobals;

typedef struct KswDynCallbackGlobals
{
    ULONG pspCreateProcessNotifyRoutine;
    ULONG pspCreateThreadNotifyRoutine;
    ULONG pspLoadImageNotifyRoutine;
    ULONG pspNotifyEnableMask;
    ULONG cmCallbackListHead;
} KswDynCallbackGlobals, *PkswDynCallbackGlobals;

typedef struct KswDynCallbackOffsets
{
    ULONG objectTypeCallbackList;
    ULONG callbackEntryItemEntryList;
    ULONG callbackEntryItemPreOperation;
    ULONG callbackEntryItemPostOperation;
    ULONG callbackEntryItemOperations;
    ULONG callbackEntryItemCallbackEntry;
    ULONG callbackEntryAltitude;
    ULONG callbackEntryRegistrationContext;
} KswDynCallbackOffsets, *PkswDynCallbackOffsets;

typedef struct KswDynFieldDescriptor
{
    ULONG fieldId;
    PCSTR fieldName;
    PCSTR featureName;
    ULONG64 capabilityMask;
    BOOLEAN required;
    ULONG source;
    ULONG offset;
} KswDynFieldDescriptor, *PkswDynFieldDescriptor;

typedef struct KswDynState
{
    BOOLEAN initialized;
    BOOLEAN ntosActive;
    BOOLEAN lxcoreActive;
    BOOLEAN extraActive;
    BOOLEAN pdbProfileActive;
    BOOLEAN callbackProfileActive;
    NTSTATUS lastStatus;
    ULONG64 capabilityMask;
    ULONG systemInformerDataVersion;
    ULONG systemInformerDataLength;
    ULONG matchedProfileClass;
    ULONG matchedProfileOffset;
    ULONG matchedFieldsId;
    KSW_DYN_MODULE_IDENTITY_PACKET ntoskrnl;
    KSW_DYN_MODULE_IDENTITY_PACKET lxcore;
    KswDynKernelOffsets kernel;
    KswDynKernelOffsets kernelSources;
    KswDynLxcoreOffsets lxcoreOffsets;
    KswDynLxcoreOffsets lxcoreSources;
    KswDynKernelGlobals kernelGlobals;
    KswDynKernelGlobals kernelGlobalSources;
    KswDynCallbackGlobals callbackGlobals;
    KswDynCallbackGlobals callbackGlobalSources;
    KswDynCallbackOffsets callbackOffsets;
    KswDynCallbackOffsets callbackOffsetSources;
    WCHAR unavailableReason[KSW_DYN_REASON_CHARS];
} KswDynState, *PkswDynState;

NTSTATUS
kswordArkDynDataInitialize(
    _In_opt_ WDFDEVICE device
    );

VOID
kswordArkDynDataUninitialize(
    VOID
    );

VOID
kswordArkDynDataSnapshot(
    _Out_ KswDynState* stateOut
    );

ULONG
kswordArkDynDataBuildFieldEntries(
    _Out_writes_opt_(entryCapacity) KSW_DYN_FIELD_ENTRY* entries,
    _In_ ULONG entryCapacity
    );

NTSTATUS
kswordArkDynDataQueryStatus(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataQueryFields(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataQueryCapabilities(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataApplyProfile(
    _In_reads_bytes_(inputBufferLength) const KSW_APPLY_DYN_PROFILE_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSW_APPLY_DYN_PROFILE_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataApplyProfileEx(
    _In_reads_bytes_(inputBufferLength) const KSW_APPLY_DYN_PROFILE_EX_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSW_APPLY_DYN_PROFILE_EX_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

VOID
kswordArkDynDataV4Initialize(
    VOID
    );

VOID
kswordArkDynDataV4Uninitialize(
    VOID
    );

NTSTATUS
kswordArkDynDataV4ApplyProfile(
    _In_reads_bytes_(inputBufferLength) const KSW_APPLY_DYN_PROFILE_V4_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSW_APPLY_DYN_PROFILE_V4_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataV4QueryModules(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataV4QueryCapabilityGroups(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataV4QueryMissingItems(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataV4QueryItems(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDynDataIoctlApplyProfileV4(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkDynDataIoctlQueryV4Modules(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkDynDataIoctlQueryV4CapabilityGroups(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkDynDataIoctlQueryV4MissingItems(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkDynDataIoctlQueryV4Items(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

EXTERN_C_END
