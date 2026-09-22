#pragma once

#include "KswordArkProcessIoctl.h"
#include "KswordArkFileIoctl.h"

// ============================================================
// KswordArkFileIrpIoctl.h
// Purpose:
// - Defines the unique R3/R0 protocol for "custom IRP direct dispatch to file system stack";
// - The directory enumeration interface reuses the KSWORD_ARK_DIRECTORY_ENTRY line format, changing only
//   the request stack layer so R3 can compare the IRP view with the ZwQueryDirectoryFile view line by line.
// - The generic submit interface allows constructing all 28 IRP_MJ_* operations. Write semantics and dangerous
//   major codes require an explicit token, and R0 performs a second pre-check of the target type and parameters.
// Notes:
// - This protocol only sends IRPs to the device stack resolved from the FILE_OBJECT; it does not accept arbitrary
//   DEVICE_OBJECT addresses directly from R3, preventing raw kernel pointers from being passed to user mode for construction.
// ============================================================

#define KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_FILE_IRP_ENUM_DIRECTORY 0x90AUL
#define KSWORD_ARK_IOCTL_FUNCTION_FILE_IRP_SUBMIT         0x90BUL

#define IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_FILE_IRP_ENUM_DIRECTORY, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS)

#define IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_FILE_IRP_SUBMIT, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

// ------------------------------------------------------------
// Target stack layer
// ------------------------------------------------------------
// RELATED: IoGetRelatedDeviceObject(FileObject), equivalent to the top of the stack entered by Zw*
//          calls. The result must match IOCTL_KSWORD_ARK_ENUM_DIRECTORY and serves as a baseline for comparison.
// BASE_FS: Calls IoGetBaseFileSystemDeviceObject(FileObject) to skip legacy filter
//          layers above the file system and reach the base file system device directly.
// VPB_FS: VPB->DeviceObject, directly connected to the file system device object of the currently mounted volume.
// DEVICE: FileObject->DeviceObject, representing the volume device itself (without parsing file system semantics).
#define KSWORD_ARK_FILE_IRP_LAYER_RELATED 0UL
#define KSWORD_ARK_FILE_IRP_LAYER_BASE_FS 1UL
#define KSWORD_ARK_FILE_IRP_LAYER_VPB_FS  2UL
#define KSWORD_ARK_FILE_IRP_LAYER_DEVICE  3UL
#define KSWORD_ARK_FILE_IRP_LAYER_MAX     3UL

// ------------------------------------------------------------
// Request flags
// ------------------------------------------------------------
// UI_CONFIRMED: Write semantics or dangerous major operations must set this flag, and confirmationToken must match.
// SKIP_CLEANUP_CLOSE: Expresses the caller's intent to pair CLEANUP/CLOSE themselves. R0 still
//          unconditionally performs cleanup to prevent leaks—once an IOCTL returns, R3 can no longer reference the
//          kernel file object; skipping cleanup would permanently leak the file object and volume reference. This
//          flag currently only affects R3-side semantic annotation and does not change R0's release behavior.
// OPEN_REPARSE_POINT: Attach FILE_OPEN_REPARSE_POINT during the CREATE phase.
// DIRECTORY_INTENT: Attaches FILE_DIRECTORY_FILE during the CREATE phase.
// RESTART_SCAN: Set SL_RESTART_SCAN during the DIRECTORY_CONTROL phase.
// RETURN_SINGLE_ENTRY: Set SL_RETURN_SINGLE_ENTRY during the DIRECTORY_CONTROL phase.
// USE_RAW_CREATE_ONLY: Execute only CREATE and return the result without sending subsequent major functions.
#define KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED       0x00000001UL
#define KSWORD_ARK_FILE_IRP_FLAG_SKIP_CLEANUP_CLOSE 0x00000002UL
#define KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT 0x00000004UL
#define KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT   0x00000008UL
#define KSWORD_ARK_FILE_IRP_FLAG_RESTART_SCAN       0x00000010UL
#define KSWORD_ARK_FILE_IRP_FLAG_RETURN_SINGLE_ENTRY 0x00000020UL
#define KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY        0x00000040UL
#define KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS    0x00000080UL

#define KSWORD_ARK_FILE_IRP_FLAG_ALL \
    (KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED | \
     KSWORD_ARK_FILE_IRP_FLAG_SKIP_CLEANUP_CLOSE | \
     KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT | \
     KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT | \
     KSWORD_ARK_FILE_IRP_FLAG_RESTART_SCAN | \
     KSWORD_ARK_FILE_IRP_FLAG_RETURN_SINGLE_ENTRY | \
     KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY | \
     KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS)

// ------------------------------------------------------------
// Protocol-level status (separate from the IRP's own NTSTATUS to avoid conflating communication success with semantic success).
// ------------------------------------------------------------
#define KSWORD_ARK_FILE_IRP_STATUS_OK                  0UL
#define KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST     1UL
#define KSWORD_ARK_FILE_IRP_STATUS_OPEN_FAILED         2UL
#define KSWORD_ARK_FILE_IRP_STATUS_LAYER_UNAVAILABLE   3UL
#define KSWORD_ARK_FILE_IRP_STATUS_ALLOC_FAILED        4UL
#define KSWORD_ARK_FILE_IRP_STATUS_MAJOR_NOT_ALLOWED   5UL
#define KSWORD_ARK_FILE_IRP_STATUS_CONFIRMATION_REQUIRED 6UL
#define KSWORD_ARK_FILE_IRP_STATUS_TIMEOUT             7UL
#define KSWORD_ARK_FILE_IRP_STATUS_IRP_FAILED          8UL
#define KSWORD_ARK_FILE_IRP_STATUS_BUFFER_TOO_SMALL    9UL
#define KSWORD_ARK_FILE_IRP_STATUS_DENIED_BY_POLICY    10UL
#define KSWORD_ARK_FILE_IRP_STATUS_MAX                 10UL

// ------------------------------------------------------------
// Stage flags: indicate which stages R3 actually completed; unset stage status fields are meaningless.
// ------------------------------------------------------------
#define KSWORD_ARK_FILE_IRP_STAGE_CREATE     0x00000001UL
#define KSWORD_ARK_FILE_IRP_STAGE_OPERATION  0x00000002UL
#define KSWORD_ARK_FILE_IRP_STAGE_CLEANUP    0x00000004UL
#define KSWORD_ARK_FILE_IRP_STAGE_CLOSE      0x00000008UL
#define KSWORD_ARK_FILE_IRP_STAGE_CANCELLED  0x00000010UL
#define KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED 0x00000020UL

// Write semantics require UI_CONFIRMED + this token for both major and non-filesystem major.
#define KSWORD_ARK_FILE_IRP_CONFIRMATION_TOKEN 0x4B495250UL

#define KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS 1024U
#define KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS 256U
#define KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES  (64UL * 1024UL)
#define KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES (256UL * 1024UL)
#define KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS 10000UL
#define KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS     60000UL
#define KSWORD_ARK_FILE_IRP_MAJOR_COUNT 28UL

// KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST: A complete description of an 'open → send target major → cleanup' sequence.
// Each major version reads only the fields it needs; unused fields must be 0 to allow R0 to strictly reject invalid requests.
typedef struct _KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long confirmationToken;

    unsigned long majorFunction;      // IRP_MJ_*（0..27）。
    unsigned long minorFunction;      // IRP_MN_*; use 0 if not applicable.
    unsigned long targetLayer;        // KSWORD_ARK_FILE_IRP_LAYER_*。
    unsigned long timeoutMs;          // 0 indicates using the default timeout.

    unsigned long desiredAccess;      // ACCESS_MASK during CREATE phase.
    unsigned long shareAccess;        // Share access bits during CREATE phase.
    unsigned long createDisposition;  // CREATE phase: FILE_OPEN/FILE_CREATE/...
    unsigned long createOptions;      // FILE_* options during CREATE phase.
    unsigned long fileAttributes;     // Attributes during CREATE phase.

    unsigned long informationClass;   // QUERY/SET_INFORMATION、DIRECTORY_CONTROL、
                                      // Information class for QUERY/SET_VOLUME_INFORMATION.
    unsigned long controlCode;        // Control codes for DEVICE_CONTROL / FILE_SYSTEM_CONTROL.
    unsigned long securityInformation;// SECURITY_INFORMATION for QUERY/SET_SECURITY.

    unsigned long inputBytes;         // Inline input length immediately following the structure.
    unsigned long outputBytes;        // Expected output buffer length.
    unsigned long lockKey;            // Key for LOCK_CONTROL.
    unsigned long reserved0;

    unsigned long long byteOffset;    // Starting offset for READ/WRITE/LOCK_CONTROL.
    unsigned long long lockLength;    // Byte count for LOCK_CONTROL.

    unsigned short pathLengthChars;   // Number of characters in the NT path, excluding the trailing NUL.
    unsigned short patternLengthChars;// Number of wildcard characters in the file name for DIRECTORY_CONTROL.
    unsigned long reserved1;

    wchar_t path[KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS];
    wchar_t pattern[KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS];
    unsigned char inputData[1];       // Variable length; actual length is determined by inputBytes.
} KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST,
  *PKSWORD_ARK_FILE_IRP_SUBMIT_REQUEST;

#define KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST, inputData))

// KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE: Fixed header followed by variable-length output data.
// Keep NTSTATUS for each stage separately so the UI can distinguish between 'open failed' and 'target major rejected'.
typedef struct _KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;             // KSWORD_ARK_FILE_IRP_STATUS_*。
    unsigned long stageFlags;         // KSWORD_ARK_FILE_IRP_STAGE_*。

    unsigned long majorFunction;
    unsigned long minorFunction;
    unsigned long targetLayer;
    unsigned long outputBytes;        // Actual number of bytes written to outputData.

    long createStatus;
    long operationStatus;
    long cleanupStatus;
    long closeStatus;

    unsigned long long information;   // IoStatus.Information for the target major.
    unsigned long long fileObjectAddress;
    unsigned long long targetDeviceAddress;
    unsigned long long targetDriverAddress;
    unsigned long long relatedDeviceAddress;
    unsigned long long baseFsDeviceAddress;
    unsigned long long vpbDeviceAddress;
    unsigned long long dispatchAddress; // The MajorFunction entry point for this major number on the target driver.

    unsigned long targetStackSize;
    unsigned long targetDeviceFlags;
    unsigned long driverNameLengthChars;
    unsigned long deviceNameLengthChars;

    wchar_t driverName[KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS];
    wchar_t deviceName[KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS];
    unsigned char outputData[1];      // Variable length; actual length is determined by outputBytes.
} KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE,
  *PKSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE;

#define KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE, outputData))

// ------------------------------------------------------------
// IRP direct dispatch directory enumeration
// ------------------------------------------------------------
// Reuse KSWORD_ARK_DIRECTORY_ENTRY row format and pagination semantics, only adding targetLayer;
// R3 uses the same path to fetch RELATED and BASE_FS/VPB_FS results separately; the
// difference set represents entries visible only by bypassing the filter layer.
//
// Capability boundary (must truthfully inform the caller):
// This interface allows only IRP_MJ_DIRECTORY_CONTROL to bypass the filter layer; IRP_MJ_CREATE still follows the
// normal I/O manager path. Manually constructing a FILE_OBJECT to bypass CREATE causes NTFS to fail to detect
// UserDirectoryOpen during subsequent directory queries, returning STATUS_INVALID_PARAMETER. Therefore, the open
// phase falls back to the managed path. In other words: hiding techniques that modify entry lists after directory
// queries are completed can be detected, but interception performed solely at CREATE cannot be detected.
// Use IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT to construct manually when bypassing requires handling CREATE together.
typedef struct _KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long targetLayer;
    unsigned long startIndex;
    unsigned long maxEntries;
    unsigned short pathLengthChars;
    unsigned short reserved;
    wchar_t path[KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS];
} KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST,
  *PKSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST;

typedef struct _KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long queryStatus;        // Reuse KSWORD_ARK_DIRECTORY_ENUM_STATUS_*.
    unsigned long responseFlags;      // Reuses KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_*.
    unsigned long rowSize;
    unsigned long rowCount;
    unsigned long startIndex;
    unsigned long nextIndex;
    long openStatus;
    long lastStatus;
    unsigned long targetLayer;        // The actual stack layer used in R0, which may fall back if unavailable.
    unsigned long fileSystemNameLengthChars;
    unsigned long long targetDeviceAddress;
    unsigned long long targetDriverAddress;
    unsigned long driverNameLengthChars;
    unsigned long reserved;
    wchar_t fileSystemName[KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS];
    wchar_t driverName[KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS];
    KSWORD_ARK_DIRECTORY_ENTRY rows[1];
} KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE,
  *PKSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE;

#define KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE, rows))
