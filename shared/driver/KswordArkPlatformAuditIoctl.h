#pragma once

#include "KswordArkKernelIoctl.h"

// ============================================================
// KswordArkPlatformAuditIoctl.h
// Purpose:
// - Defines R3 <-> R0 HAL/WDF audit protocol and function slot controlled edit protocol.
// - Addresses are read only from publicly exported tables, WDF binding tables, or tables that have passed structural validation;
// - Edit slots by repositioning them in R0 based on scope/index, using table address, old value, and atomic CAS
//   constraints to bind a single function pointer; does not provide arbitrary address memory write capability.
// - The editable scope consists of four HAL sub-tables and WDF_FUNCTIONS. WDF_CALLBACKS describes compile-time
//   function addresses within the driver's own .text section, which has no writable slots and is always read-only.
// ============================================================

#define KSWORD_ARK_PLATFORM_AUDIT_PROTOCOL_VERSION 5UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PLATFORM_AUDIT 0x8E4UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_PLATFORM_AUDIT 0x8E6UL
#define IOCTL_KSWORD_ARK_QUERY_PLATFORM_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PLATFORM_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_CONTROL_PLATFORM_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONTROL_PLATFORM_AUDIT, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_DISPATCH       0x00000001UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_PRIVATE        0x00000002UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_ACPI           0x00000004UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_HAL_SUBCOMPONENTS  0x00000008UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_FUNCTIONS      0x00000010UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_WDF_CALLBACKS      0x00000020UL
#define KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL                0x0000003FUL

#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNAVAILABLE       0UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_OK                1UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_PARTIAL           2UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_UNSUPPORTED       3UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_SIGNATURE_MISMATCH 4UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_QUERY_FAILED      5UL
#define KSWORD_ARK_PLATFORM_AUDIT_STATUS_BUFFER_TRUNCATED  6UL

#define KSWORD_ARK_PLATFORM_AUDIT_ROW_TABLE                1UL
#define KSWORD_ARK_PLATFORM_AUDIT_ROW_FUNCTION             2UL
#define KSWORD_ARK_PLATFORM_AUDIT_ROW_CALLBACK             3UL
#define KSWORD_ARK_PLATFORM_AUDIT_ROW_DIAGNOSTIC           4UL

#define KSWORD_ARK_PLATFORM_HOOK_UNKNOWN                   0UL
#define KSWORD_ARK_PLATFORM_HOOK_CLEAN                     1UL
#define KSWORD_ARK_PLATFORM_HOOK_SUSPICIOUS                2UL
#define KSWORD_ARK_PLATFORM_HOOK_UNSUPPORTED               3UL

#define KSWORD_ARK_PLATFORM_CONFIDENCE_NONE                0UL
#define KSWORD_ARK_PLATFORM_CONFIDENCE_LOW                25UL
#define KSWORD_ARK_PLATFORM_CONFIDENCE_MEDIUM             60UL
#define KSWORD_ARK_PLATFORM_CONFIDENCE_HIGH               90UL

#define KSWORD_ARK_PLATFORM_FIELD_LIVE_ADDRESS             0x00000001UL
#define KSWORD_ARK_PLATFORM_FIELD_ORIGINAL_ADDRESS         0x00000002UL
#define KSWORD_ARK_PLATFORM_FIELD_TABLE_ADDRESS            0x00000004UL
#define KSWORD_ARK_PLATFORM_FIELD_MODULE                   0x00000008UL
#define KSWORD_ARK_PLATFORM_FIELD_PROLOGUE_FORMAT          0x00000020UL
#define KSWORD_ARK_PLATFORM_FIELD_OWNER_VALIDATED          0x00000040UL
#define KSWORD_ARK_PLATFORM_FIELD_STRUCTURE_VALIDATED      0x00000080UL
#define KSWORD_ARK_PLATFORM_FIELD_EXACT_EXPORT             0x00000100UL
#define KSWORD_ARK_PLATFORM_FIELD_EXECUTABLE_VALIDATED     0x00000200UL
#define KSWORD_ARK_PLATFORM_FIELD_READ_ONLY_RANGE          0x00000400UL
#define KSWORD_ARK_PLATFORM_FIELD_DETAIL_ARGS              0x00000800UL
#define KSWORD_ARK_PLATFORM_FIELD_BASELINE_VALIDATED       0x00001000UL
#define KSWORD_ARK_PLATFORM_FIELD_LOCATOR_VALIDATED        0x00002000UL

#define KSWORD_ARK_PLATFORM_RESPONSE_TRUNCATED              0x00000001UL
#define KSWORD_ARK_PLATFORM_RESPONSE_PARTIAL                0x00000002UL
#define KSWORD_ARK_PLATFORM_RESPONSE_FAIL_CLOSED            0x00000004UL
#define KSWORD_ARK_PLATFORM_RESPONSE_NO_PDB                 0x00000008UL

#define KSWORD_ARK_PLATFORM_SIGNATURE_NONE                  0UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V6         1UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_PUBLIC_HAL_V4_V5      2UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_WDF_BINDING_TABLE     3UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_X64_PROLOGUE          4UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_EXACT_EXPORT_ONLY     5UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_RIP_RELATIVE_MASKED   6UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V54       7UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V58       8UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V61       9UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V5          10UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_HAL_SUBCOMPONENTS_22 11UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_HAL_PRIVATE_V51      12UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_HAL_SUBCOMPONENTS_21 13UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V4          14UL
#define KSWORD_ARK_PLATFORM_SIGNATURE_MAX \
    KSWORD_ARK_PLATFORM_SIGNATURE_HAL_ACPI_V4

#define KSWORD_ARK_PLATFORM_SLOT_UNSPECIFIED                0UL
#define KSWORD_ARK_PLATFORM_SLOT_FUNCTION                   1UL
#define KSWORD_ARK_PLATFORM_SLOT_SCALAR                     2UL
#define KSWORD_ARK_PLATFORM_SLOT_DUMMY                      3UL

#define KSWORD_ARK_PLATFORM_OWNER_NONE                      0UL
#define KSWORD_ARK_PLATFORM_OWNER_NT_HAL                    1UL
#define KSWORD_ARK_PLATFORM_OWNER_NT_HAL_PCI                2UL
#define KSWORD_ARK_PLATFORM_OWNER_NT_HAL_ACPI               3UL
#define KSWORD_ARK_PLATFORM_OWNER_WDF                       4UL
#define KSWORD_ARK_PLATFORM_OWNER_KSWORD                    5UL

#define KSWORD_ARK_PLATFORM_ORIGINAL_SOURCE_NONE            0UL
#define KSWORD_ARK_PLATFORM_ORIGINAL_SOURCE_DISK_IMAGE      1UL

// R0 returns only stable detailCode/parameters; natural language is generated by R3 based on the current language pack.
#define KSWORD_ARK_PLATFORM_DETAIL_NONE                     0UL
#define KSWORD_ARK_PLATFORM_DETAIL_OWNER_CONSISTENT         1UL
#define KSWORD_ARK_PLATFORM_DETAIL_OWNER_MISMATCH           2UL
#define KSWORD_ARK_PLATFORM_DETAIL_NON_EXECUTABLE           3UL
#define KSWORD_ARK_PLATFORM_DETAIL_NULL_SLOT                4UL
#define KSWORD_ARK_PLATFORM_DETAIL_READ_FAILED              5UL
#define KSWORD_ARK_PLATFORM_DETAIL_BUILD_UNSUPPORTED        6UL
#define KSWORD_ARK_PLATFORM_DETAIL_VERSION_MISMATCH         7UL
#define KSWORD_ARK_PLATFORM_DETAIL_RANGE_INVALID            8UL
#define KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_UNIQUE       9UL
#define KSWORD_ARK_PLATFORM_DETAIL_LOCATOR_NOT_FOUND       10UL
#define KSWORD_ARK_PLATFORM_DETAIL_TABLE_INVALID           11UL
#define KSWORD_ARK_PLATFORM_DETAIL_MODULE_SNAPSHOT_FAILED  12UL
#define KSWORD_ARK_PLATFORM_DETAIL_SCALAR_VALUE            13UL
#define KSWORD_ARK_PLATFORM_DETAIL_DUMMY_SLOT              14UL
#define KSWORD_ARK_PLATFORM_DETAIL_DETOUR_EXTERNAL         15UL
#define KSWORD_ARK_PLATFORM_DETAIL_DETOUR_SAME_OWNER       16UL
#define KSWORD_ARK_PLATFORM_DETAIL_FORMAT_RECOGNIZED       17UL
#define KSWORD_ARK_PLATFORM_DETAIL_FORMAT_UNKNOWN          18UL
#define KSWORD_ARK_PLATFORM_DETAIL_WDF_TABLE_INVALID       19UL
#define KSWORD_ARK_PLATFORM_DETAIL_WDF_INDEX_INVALID       20UL
#define KSWORD_ARK_PLATFORM_DETAIL_ACPI_V5_VALIDATED       21UL
#define KSWORD_ARK_PLATFORM_DETAIL_SUBCOMPONENT_VALIDATED  22UL
#define KSWORD_ARK_PLATFORM_DETAIL_BASELINE_MATCH          23UL
#define KSWORD_ARK_PLATFORM_DETAIL_BASELINE_MISMATCH       24UL

#define KSWORD_ARK_PLATFORM_CONTROL_FLAG_UI_CONFIRMED       0x00000001UL
// Historically, only the HAL slot was editable, so the token retained 'HALE'; starting with protocol v5, the same token also covers the
// WDF_FUNCTIONS slot. Changing the value would cause mutual rejection between old and new binaries without providing additional security benefits.
#define KSWORD_ARK_PLATFORM_CONTROL_CONFIRMATION_TOKEN      0x48414C45UL /* 'HALE' */

#define KSWORD_ARK_PLATFORM_CONTROL_STATUS_OK                    0UL
#define KSWORD_ARK_PLATFORM_CONTROL_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_PLATFORM_CONTROL_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_PLATFORM_CONTROL_STATUS_UNSUPPORTED           3UL
#define KSWORD_ARK_PLATFORM_CONTROL_STATUS_STALE_SNAPSHOT        4UL
#define KSWORD_ARK_PLATFORM_CONTROL_STATUS_TARGET_INVALID        5UL
#define KSWORD_ARK_PLATFORM_CONTROL_STATUS_WRITE_FAILED          6UL
#define KSWORD_ARK_PLATFORM_CONTROL_STATUS_SAFETY_DENIED         7UL

#define KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_CHANGED             0x00000001UL
#define KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_TARGET_EXECUTABLE   0x00000002UL
#define KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_TABLE_REVALIDATED   0x00000004UL
// The segment containing the slot is not writable (the KMDF binding table resides in a read-only segment of Wdf01000.sys); R0 first
// creates a writable MDL alias, then performs CAS. HVCI will reject privilege escalation, returning WRITE_FAILED without setting this bit.
#define KSWORD_ARK_PLATFORM_CONTROL_RESPONSE_ALIAS_WRITE         0x00000008UL

#define KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS 1024UL
#define KSWORD_ARK_PLATFORM_HARD_MAX_ROWS    1024UL

#define KSWORD_ARK_PLATFORM_NAME_CHARS        96U
#define KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS 260U
#define KSWORD_ARK_PLATFORM_DETAIL_ARG_COUNT   4U

typedef struct _KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST
{
    // Note: R3 passes only the scope mask and row budget; R0 rejects unknown versions and reserved fields.
    unsigned long size;
    unsigned long version;
    unsigned long scopeMask;
    unsigned long maxRows;
    unsigned long flags;
    unsigned long reserved0;
} KSWORD_ARK_QUERY_PLATFORM_AUDIT_REQUEST;

typedef struct _KSWORD_ARK_PLATFORM_AUDIT_ENTRY
{
    // Note: Unifies HAL entries, WDF functions, WDF callbacks, and explicit downgrade diagnostics.
    unsigned long size;
    unsigned long scope;
    unsigned long rowKind;
    unsigned long status;
    unsigned long hookStatus;
    unsigned long confidence;
    unsigned long fieldFlags;
    unsigned long signatureId;
    unsigned long slotKind;
    unsigned long ownerPolicy;
    unsigned long entryIndex;
    long lastStatus;
    unsigned long moduleSize;
    unsigned long prologueSignatureId;
    unsigned long originalAddressSource;
    unsigned long reserved0;
    unsigned long long liveAddress;
    unsigned long long originalAddress;
    unsigned long long tableAddress;
    unsigned long long moduleBase;
    unsigned long long detailArgs[KSWORD_ARK_PLATFORM_DETAIL_ARG_COUNT];
    unsigned long detailCode;
    unsigned long reserved1;
    wchar_t name[KSWORD_ARK_PLATFORM_NAME_CHARS];
    wchar_t modulePath[KSWORD_ARK_PLATFORM_MODULE_PATH_CHARS];
} KSWORD_ARK_PLATFORM_AUDIT_ENTRY;

typedef struct _KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE
{
    // Note: METHOD_BUFFERED variable-length response; R3 must validate both entrySize and returnedCount.
    unsigned long size;
    unsigned long version;
    unsigned long queryStatus;
    unsigned long scopeMask;
    unsigned long responseFlags;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long buildNumber;
    unsigned long signaturePolicyFlags;
    long lastStatus;
    unsigned long reserved0;
    KSWORD_ARK_PLATFORM_AUDIT_ENTRY entries[1];
} KSWORD_ARK_QUERY_PLATFORM_AUDIT_RESPONSE;

typedef struct _KSWORD_ARK_CONTROL_PLATFORM_AUDIT_REQUEST
{
    // R3: identity snapshot submitted during refresh; R0: do not directly compute write address using tableAddress.
    unsigned long size;
    unsigned long version;
    unsigned long scope;
    unsigned long entryIndex;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long tableAddress;
    unsigned long long expectedValue;
    unsigned long long newValue;
} KSWORD_ARK_CONTROL_PLATFORM_AUDIT_REQUEST;

typedef struct _KSWORD_ARK_CONTROL_PLATFORM_AUDIT_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long status;
    unsigned long scope;
    unsigned long entryIndex;
    unsigned long responseFlags;
    long lastStatus;
    unsigned long reserved0;
    unsigned long long tableAddress;
    unsigned long long slotAddress;
    unsigned long long previousValue;
    unsigned long long currentValue;
    unsigned long long requestedValue;
} KSWORD_ARK_CONTROL_PLATFORM_AUDIT_RESPONSE;
