#pragma once

#include "ark/ark_dyndata.h"

EXTERN_C_START

// KswRuntimeKernelLayout contains only offsets and RVAs recovered from
// public layouts, exports, and live structural validation. A negative member
// is unavailable, so callers never have to interpret a guessed zero value.
typedef struct KswRuntimeKernelLayout
{
    LONG kldrInLoadOrderLinks;
    LONG kldrDllBase;
    LONG kldrSizeOfImage;
    LONG kldrFullDllName;
    LONG kldrBaseDllName;
    LONG doDriverStart;
    LONG doDriverSize;
    LONG doDriverSection;
    LONG doMajorFunction;
    LONG doFastIoDispatch;
    LONG doDriverUnload;
    LONG rtlAvlBalancedRoot;
    LONG rtlAvlOrderedPointer;
    LONG rtlAvlWhichOrderedElement;
    LONG rtlAvlNumberGenericTableElements;
    LONG rtlAvlDepthOfTree;
    LONG rtlAvlRestartKey;
    LONG rtlAvlDeleteCount;
    LONG rtlAvlTypeSize;
    LONG uldName;
    LONG uldStartAddress;
    LONG uldEndAddress;
    LONG uldCurrentTime;
    LONG uldTypeSize;
    LONG piDdbDriverName;
    LONG piDdbTimeDateStamp;
    LONG piDdbLoadStatus;
    LONG piDdbTypeSize;
    LONG psLoadedModuleListRva;
    LONG mmUnloadedDriversRva;
    LONG mmLastUnloadedDriverRva;
    LONG piDdbCacheTableRva;
    LONG piDdbLockRva;
    LONG keServiceDescriptorTableShadowRva;
} KswRuntimeKernelLayout, *PkswRuntimeKernelLayout;

VOID
kswordArkDriverResolveKernelFallbackLayout(
    _In_opt_ PDRIVER_OBJECT validationDriverObject,
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* ntoskrnlIdentity,
    _Out_ PkswRuntimeKernelLayout layoutOut
    );

EXTERN_C_END
