/*
 * License and archival notes for the referenced mechanism:
 * third_party/SystemWideTransmission/LICENSE.txt
 * third_party/SystemWideTransmission/NOTICE.md
 */
#pragma once

#include "KswordArkProcessIoctl.h"

/*
 * The system global rate-change protocol describes only the stable data contract between R3 and R0.
 * Kernel addresses are for diagnostic display only; R3 must not directly read or write these addresses.
 */
#define KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION 3UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_SYSTEM_TIME   0x865UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_SYSTEM_TIME 0x866UL

#define IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_SYSTEM_TIME, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONTROL_SYSTEM_TIME, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

/* The multiplier limit prevents counter increment overflow and system instability. */
#define KSWORD_ARK_SYSTEM_TIME_MIN_FACTOR 2UL
#define KSWORD_ARK_SYSTEM_TIME_MAX_FACTOR 64UL

/* Control commands uniformly override acceleration, deceleration, and restoration to the original timing path. */
#define KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET     1UL
#define KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP  2UL
#define KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN 3UL

/*
 * ORIGINAL_COMPAT directly locates the HAL counter descriptor based on system version characteristics.
 * GUARDED uses the same takeover principle but performs additional validation of the descriptor and function slot before returning the target.
 */
#define KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT 1UL
#define KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED         2UL

/*
 * HYPERV_SHARED_QPC takes over both the Hyper-V user-shared QPC page and the kernel HAL callback.
 * HAL_COMPAT preserves the legacy path that originally disabled user fast-path bypass and took over HAL callbacks.
 */
#define KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC 1UL
#define KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT        2UL

/* UI_CONFIRMED indicates that R3 has completed this dual confirmation beyond the persistent warning. */
#define KSWORD_ARK_SYSTEM_TIME_CONTROL_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_SYSTEM_TIME_CONFIRMATION_TOKEN        0x54494D45UL

/* Status bits describe current parsing, takeover, bypass correction, and conflict states. */
#define KSWORD_ARK_SYSTEM_TIME_STATE_INITIALIZED          0x00000001UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED            0x00000002UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_ACTIVE               0x00000004UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_SPEED_UP              0x00000008UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_SLOW_DOWN             0x00000010UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_PRIMARY_HOOKED        0x00000020UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_SECONDARY_HOOKED      0x00000040UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_QPC_BYPASS_DISABLED   0x00000080UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_INTERNAL_FLAG_PATCHED 0x00000100UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_HANDLER_TABLE         0x00000200UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_CONFLICT              0x00000400UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_PRESENT         0x00000800UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_SHARED_PAGE     0x00001000UL
#define KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_ACTIVE          0x00002000UL

/* Runtime status codes are separated from NTSTATUS to allow legacy UIs to stably interpret failure reasons. */
#define KSWORD_ARK_SYSTEM_TIME_STATUS_OK                    0UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_UNSUPPORTED_BUILD     3UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_RESOLVE_FAILED        4UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_PATCH_FAILED          5UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT              6UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_STALE_GENERATION      7UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_NOT_ACTIVE            8UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_INTERNAL_ERROR        9UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_NOT_PRESENT    10UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE 11UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_VALIDATION_FAILED 12UL
#define KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_WRITE_FAILED   13UL

/* The query request maintains a fixed size; future versions can extend read-only diagnostics via flags. */
typedef struct _KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST;

/*
 * Query response returns both user-visible status and limited parsed evidence.
 * counterValue is a snapshot of the continuous virtual counter after takeover, not the system wall-clock time.
 */
typedef struct _KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long stateFlags;
    unsigned long generation;
    unsigned long command;
    unsigned long factor;
    unsigned long osBuildNumber;
    long lastStatus;
    unsigned long resolutionMode;
    unsigned long backend;
    unsigned long reserved;
    unsigned long long counterValue;
    unsigned long long counterSourceAddress;
    unsigned long long primarySlotAddress;
    unsigned long long secondarySlotAddress;
    unsigned long long hypervisorSharedPageAddress;
    unsigned long long hypervisorTimeUpdateLock;
    unsigned long long hypervisorOriginalMultiplier;
    unsigned long long hypervisorOriginalBias;
    unsigned long long hypervisorCurrentMultiplier;
    unsigned long long hypervisorCurrentBias;
} KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE;

/*
 * expectedGeneration prevents pages from using stale states to overwrite operations by other controllers.
 * RESET always allows recovery without requiring a confirmationToken.
 */
typedef struct _KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long command;
    unsigned long factor;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long resolutionMode;
    unsigned long backend;
} KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST;

/* The control response returns the state before and after the action; R3 can update the page immediately without guessing. */
typedef struct _KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long oldStateFlags;
    unsigned long newStateFlags;
    unsigned long oldGeneration;
    unsigned long newGeneration;
    unsigned long command;
    unsigned long factor;
    unsigned long osBuildNumber;
    long lastStatus;
    unsigned long resolutionMode;
    unsigned long backend;
    unsigned long reserved;
    unsigned long long counterValue;
} KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE;
