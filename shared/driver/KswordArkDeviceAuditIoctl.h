#pragma once

#include "KswordArkKernelIoctl.h"

// ============================================================
// KswordArkDeviceAuditIoctl.h
// Purpose:
// - Defines the R3 <-> R0 device/input/USB/GPU read-only audit protocol;
// - The protocol returns only device objects, driver objects, link relationships, and risk warnings.
// - The protocol does not imply any write, unload, unbind, disable, or hook actions.
// ============================================================

#define KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_DEVICE_STACK_AUDIT           0x8E0UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_INPUT_STACK_AUDIT            0x8E1UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_USB_TOPOLOGY_AUDIT           0x8E2UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT   0x8E3UL

#define IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_DEVICE_STACK_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_INPUT_STACK_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_USB_TOPOLOGY_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK            0x00000001UL
#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK             0x00000002UL
#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY            0x00000004UL
#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG    0x00000008UL

#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_ALL \
    (KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK | \
     KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK | \
     KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY | \
     KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG)

#define KSWORD_ARK_DEVICE_AUDIT_STATUS_UNAVAILABLE         0UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_OK                  1UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL             2UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND           3UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_BUFFER_TRUNCATED    4UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED        5UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_UNSUPPORTED         6UL

#define KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY    1UL
#define KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DEVICE_ROW        2UL

#define KSWORD_ARK_DEVICE_AUDIT_ROLE_UNKNOWN               0UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_PDO                   1UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_FDO                   2UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_UPPER_FILTER          3UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_LOWER_FILTER          4UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_CLASS_DRIVER          5UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER            6UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_COMPOSITE             7UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE             8UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_CONTROLLER            9UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY               10UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_WATCHDOG              11UL

#define KSWORD_ARK_DEVICE_AUDIT_FIELD_DRIVER_NAME_PRESENT      0x00000001UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_SERVICE_NAME_PRESENT     0x00000002UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_DEVICE_NAME_PRESENT      0x00000004UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_IMAGE_PATH_PRESENT       0x00000008UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_DETAIL_PRESENT           0x00000010UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_ATTACHED_PRESENT         0x00000020UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_NEXT_PRESENT             0x00000040UL

#define KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED        0x00000001UL
#define KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_PARTIAL          0x00000002UL
#define KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_EMPTY            0x00000004UL

#define KSWORD_ARK_DEVICE_AUDIT_RISK_NONE                      0x00000000UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_UNAVAILABLE               0x00000001UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED              0x00000002UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_NAME_MISSING              0x00000004UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_IMAGE_PATH_MISSING        0x00000008UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_DEVICE_LOOP               0x00000010UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_ATTACHED_LOOP             0x00000020UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_CROSS_DRIVER_ATTACH       0x00000040UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_ROLE_AMBIGUOUS            0x00000080UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_STACK_TRUNCATED           0x00000100UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_INTEGRITY_PARTIAL         0x00000200UL

#define KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS              1024UL
#define KSWORD_ARK_DEVICE_AUDIT_HARD_MAX_ROWS                 1024UL
#define KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH      16UL
#define KSWORD_ARK_DEVICE_AUDIT_HARD_MAX_ATTACHED_DEPTH         64UL

#define KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS  KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS
#define KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS KSWORD_ARK_DRIVER_SERVICE_KEY_CHARS
#define KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS  KSWORD_ARK_DRIVER_DEVICE_NAME_CHARS
#define KSWORD_ARK_DEVICE_AUDIT_IMAGE_PATH_CHARS   KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS
#define KSWORD_ARK_DEVICE_AUDIT_DETAIL_CHARS       256U

typedef struct _KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST
{
    // Note: This is a read-only audit request header used to constrain version, page size, and single-target filtering.
    // Input: R3 passes version number, profileFlags, max rows, max nesting depth, and optional target name.
    // Note: R0 performs only validation and normalization; it does not modify system policies or traverse unknown object chains.
    // Returns: No return value; the structure is carried directly by the IOCTL input buffer.
    unsigned long size;
    unsigned long version;
    unsigned long profileFlags;
    unsigned long maxRows;
    unsigned long maxAttachedDepth;
    unsigned long reserved0;
    wchar_t targetName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST;

typedef struct _KSWORD_ARK_DEVICE_AUDIT_ENTRY
{
    // Note: This is the unified output row for device/driver auditing, capable of representing either a summary or device chain evidence.
    // Input: Converted from DriverObject integrity evidence by R0, or synthesized as partial rows on failure.
    // Processing: Fields carry only address, name, status, and risk hints; no write actions are triggered.
    // Return: No return value; the structure is placed in the variable-length response body entries[].
    unsigned long size;
    unsigned long profileFlags;
    unsigned long rowKind;
    unsigned long roleHint;
    unsigned long status;
    unsigned long riskFlags;
    unsigned long fieldFlags;
    unsigned long confidence;
    unsigned long relationDepth;
    unsigned long attachedDepth;
    unsigned long deviceType;
    unsigned long characteristics;
    unsigned long stackSize;
    unsigned long alignmentRequirement;
    long lastStatus;
    unsigned long reserved0;
    unsigned long long driverObjectAddress;
    unsigned long long deviceObjectAddress;
    unsigned long long attachedDeviceAddress;
    unsigned long long nextDeviceObjectAddress;
    wchar_t driverName[KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS];
    wchar_t serviceName[KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS];
    wchar_t deviceName[KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS];
    wchar_t imagePath[KSWORD_ARK_DEVICE_AUDIT_IMAGE_PATH_CHARS];
    wchar_t detail[KSWORD_ARK_DEVICE_AUDIT_DETAIL_CHARS];
} KSWORD_ARK_DEVICE_AUDIT_ENTRY;

typedef struct _KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE
{
    // Note: This is a variable-length audit response header, immediately followed by entries[].
    // Input: R0 fills in query results, return count, and status summary.
    // Handling: R3 enumerates rows one by one using returnedCount and entrySize.
    // Returns: no return value; the structure is written directly to the METHOD_BUFFERED output buffer.
    unsigned long size;
    unsigned long version;
    unsigned long queryStatus;
    unsigned long profileFlags;
    unsigned long responseFlags;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long targetCount;
    unsigned long driverCount;
    unsigned long deviceCount;
    long lastStatus;
    unsigned long reserved0;
    KSWORD_ARK_DEVICE_AUDIT_ENTRY entries[1];
} KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE;
