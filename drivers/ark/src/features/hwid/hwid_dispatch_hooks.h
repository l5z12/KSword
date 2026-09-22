#pragma once

/*
 * Note:
 * 1) This header file only declares the IRP completion routine installation entry point for HWID Dispatch hooks;
 * 2) The IOCTL layer is responsible for enabling/unloading MajorFunction hooks; this module only identifies the target IOCTL and rewrites the return buffer;
 * 3) This module does not contain physical memory scanning, SMBIOS physical table writing, or direct boot sector writing logic.
 */

#include "ark/ark_driver.h"
#include "driver/KswordArkHwidIoctl.h"

BOOLEAN
kswordArkHwidPrepareDispatchCompletion(
    _Inout_ PIRP irp,
    _Inout_ PIO_STACK_LOCATION ioStack,
    _In_ ULONG targetFlag,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* profile
    );
