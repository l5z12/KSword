/*++

Module Name:

    device_audit_targets.c

Abstract:

    Static target DriverObject lists used by read-only device audit profiles.

Environment:

    Kernel-mode Driver Framework

--*/

#include "device_audit_internal.h"

const KswDeviceAuditTarget kGKswDeviceAuditDeviceTargets[] = {
    { L"\\Driver\\ACPI", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\pci", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\swenum", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\vdrvroot", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\intelpep", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\processr", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\PDC", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\dam", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER }
};

const KswDeviceAuditTarget kGKswDeviceAuditInputTargets[] = {
    { L"\\Driver\\kbdclass", KSWORD_ARK_DEVICE_AUDIT_ROLE_CLASS_DRIVER },
    { L"\\Driver\\kbdhid", KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE },
    { L"\\Driver\\i8042prt", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\mouclass", KSWORD_ARK_DEVICE_AUDIT_ROLE_CLASS_DRIVER },
    { L"\\Driver\\mouhid", KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE },
    { L"\\Driver\\HidClass", KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE },
    { L"\\Driver\\HidUsb", KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE }
};

const KswDeviceAuditTarget kGKswDeviceAuditUsbTargets[] = {
    { L"\\Driver\\USBXHCI", KSWORD_ARK_DEVICE_AUDIT_ROLE_CONTROLLER },
    { L"\\Driver\\UCX01000", KSWORD_ARK_DEVICE_AUDIT_ROLE_CONTROLLER },
    { L"\\Driver\\USBHUB3", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\usbhub", KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER },
    { L"\\Driver\\usbccgp", KSWORD_ARK_DEVICE_AUDIT_ROLE_COMPOSITE },
    { L"\\Driver\\HidClass", KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE },
    { L"\\Driver\\HidUsb", KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE }
};

const KswDeviceAuditTarget kGKswDeviceAuditGpuTargets[] = {
    { L"\\Driver\\dxgkrnl", KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY },
    { L"\\Driver\\dxgmms2", KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY },
    { L"\\Driver\\cdd", KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY },
    { L"\\Driver\\monitor", KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY },
    { L"\\Driver\\BasicDisplay", KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY },
    { L"\\Driver\\BasicRender", KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY },
    { L"\\Driver\\watchdog", KSWORD_ARK_DEVICE_AUDIT_ROLE_WATCHDOG }
};



const ULONG kGKswDeviceAuditDeviceTargetCount = RTL_NUMBER_OF(kGKswDeviceAuditDeviceTargets);
const ULONG kGKswDeviceAuditInputTargetCount = RTL_NUMBER_OF(kGKswDeviceAuditInputTargets);
const ULONG kGKswDeviceAuditUsbTargetCount = RTL_NUMBER_OF(kGKswDeviceAuditUsbTargets);
const ULONG kGKswDeviceAuditGpuTargetCount = RTL_NUMBER_OF(kGKswDeviceAuditGpuTargets);
