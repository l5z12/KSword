#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkFileIoctl.h"
#include "../driver/KswordArkFileIrpIoctl.h"
#include "../driver/KswordArkSectionIoctl.h"
#include "../driver/KswordArkTrustIoctl.h"

namespace ksword::ark
{
    // FileSectionMappingEntry is an R3 model row representing the R0 file Data/Image ControlArea mapping relationship.
    struct FileSectionMappingEntry
    {
        std::uint32_t sectionKind = KSWORD_ARK_FILE_SECTION_KIND_UNKNOWN; // Data or Image.
        std::uint32_t viewMapType = KSWORD_ARK_SECTION_MAP_TYPE_UNKNOWN;  // Process/Session/SystemCache。
        std::uint32_t processId = 0;                                      // Matched mapping process PID.
        std::uint64_t controlAreaAddress = 0;                             // Diagnosis display only.
        std::uint64_t startVa = 0;                                        // Mapping start VA.
        std::uint64_t endVa = 0;                                          // Mapping end VA.
    };

    // FileSectionMappingsQueryResult: Carries the Phase-7 file reverse lookup mapping process response.
    struct FileSectionMappingsQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::uint64_t fileObjectAddress = 0;
        std::uint64_t sectionObjectPointersAddress = 0;
        std::uint64_t dataControlAreaAddress = 0;
        std::uint64_t imageControlAreaAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t mmControlAreaListHeadOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::uint32_t mmControlAreaLockOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::vector<FileSectionMappingEntry> mappings;
    };

    // FileInfoQueryResult is the R3 model for Phase-10 R0 file basic information queries.
    struct FileInfoQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;        // Protocol version.
        std::uint32_t fieldFlags = 0;     // KSWORD_ARK_FILE_INFO_FIELD_*。
        std::uint32_t queryStatus = KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE; // Query aggregate status.
        long openStatus = 0;              // ZwCreateFile status.
        long basicStatus = 0;             // Query status via FileBasicInformation.
        long standardStatus = 0;          // Query status via FileStandardInformation.
        long objectStatus = 0;            // Status of ObReferenceObjectByHandle/SectionPointer.
        long nameStatus = 0;              // ObQueryNameString status.
        std::uint32_t fileAttributes = 0; // FILE_ATTRIBUTE_*。
        std::int64_t allocationSize = 0;  // Allocation size.
        std::int64_t endOfFile = 0;       // Logical file size.
        std::int64_t creationTime = 0;    // FILETIME-compatible timestamp.
        std::int64_t lastAccessTime = 0;  // FILETIME-compatible timestamp.
        std::int64_t lastWriteTime = 0;   // FILETIME-compatible timestamp.
        std::int64_t changeTime = 0;      // NTFS change time。
        std::uint64_t fileObjectAddress = 0; // For diagnostic display only; not used as evidence.
        std::uint64_t sectionObjectPointersAddress = 0; // Diagnostic display.
        std::uint64_t dataSectionObjectAddress = 0;     // Diagnostic display.
        std::uint64_t imageSectionObjectAddress = 0;    // Diagnostic display.
        std::wstring ntPath;            // Request to echo back the NT path.
        std::wstring objectName;        // File object name from ObQueryNameString.
    };

    // DirectoryEntryRecord is a validated directory record returned by the R0 file system driver enumeration.
    struct DirectoryEntryRecord
    {
        std::uint32_t flags = 0;          // KSWORD_ARK_DIRECTORY_ENTRY_FLAG_*。
        std::uint32_t fileAttributes = 0; // FILE_ATTRIBUTE_* raw bits.
        std::uint64_t fileId = 0;         // FileId provided by the file system, used for display/association only.
        std::int64_t allocationSize = 0;  // Allocation size; directories or unknown values may be 0.
        std::int64_t endOfFile = 0;       // Logical file length.
        std::int64_t creationTime = 0;    // NT timestamp in 100ns units.
        std::int64_t lastAccessTime = 0;  // NT timestamp in 100ns units.
        std::int64_t lastWriteTime = 0;   // NT timestamp in 100ns units.
        std::int64_t changeTime = 0;      // NT timestamp in 100ns units.
        std::wstring name;                // Filename with protocol boundary validation performed.
    };

    // DirectoryEnumerationResult aggregates all paged responses and explicitly preserves old driver/truncation state.
    struct DirectoryEnumerationResult
    {
        IoResult io;                      // Communication result of the last page or a local verification error.
        bool unsupported = false;         // Old drivers do not register directory enumeration IOCTLs.
        bool capped = false;              // The R3 total line budget has been reached; the result is not a complete directory.
        std::uint32_t queryStatus =
            KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE; // Semantic status of the last page.
        std::uint32_t responseFlags = 0;   // Last page of KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_*.
        long openStatus = 0;               // ZwCreateFile directory open status.
        long lastStatus = 0;               // ZwQueryDirectoryFile or boundary validation status.
        std::wstring fileSystemName;       // Name returned by R0 via FileFsAttributeInformation.
        std::vector<DirectoryEntryRecord> entries; // Directory entries merged in driver order.
    };

    // FileIrpDirectoryResult carries directory enumeration results from 'custom IRPs sent directly to a specific stack layer'.
    // The row format is identical to DirectoryEnumerationResult, with additional recording of the R0 stack level
    // actually applied and the driver name receiving the request: if the request layer differs from the applied layer,
    // a fallback has occurred; callers must not treat fallback results as 'views after bypassing filter layers'.
    struct FileIrpDirectoryResult
    {
        IoResult io;                      // Communication result of the last page or a local verification error.
        bool unsupported = false;         // Legacy driver unregistered IRP directory enumeration IOCTL.
        bool capped = false;              // The R3 total line budget has been reached; the result is not a complete directory.
        std::uint32_t queryStatus =
            KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE; // Semantic status of the last page.
        std::uint32_t responseFlags = 0;   // Last page of KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_*.
        std::uint32_t requestedLayer = 0;  // KSWORD_ARK_FILE_IRP_LAYER_* requested by R3.
        std::uint32_t resolvedLayer = 0;   // R0: Actual dispatch stack layer
        long openStatus = 0;               // Status during CREATE phase.
        long lastStatus = 0;               // QUERY_DIRECTORY or boundary check status.
        std::uint64_t targetDeviceAddress = 0; // The device object that actually receives the IRP.
        std::uint64_t targetDriverAddress = 0; // The driver object to which this device belongs.
        std::wstring driverName;           // Receive the requested driver name.
        std::wstring fileSystemName;       // Target volume file system name (may be empty).
        std::vector<DirectoryEntryRecord> entries; // Directory entries merged in driver order.
    };

    // FileIrpSubmitResult carries the complete result of a generic IRP construction submission.
    // Preserve NTSTATUS values separately for each stage: the UI must distinguish between 'open failure' and 'target major
    // rejected by the target driver', as these have entirely different meanings when troubleshooting filter layer interception.
    struct FileIrpSubmitResult
    {
        IoResult io;                       // Underlying DeviceIoControl status.
        bool unsupported = false;          // Old driver does not register IRP submission IOCTL.
        std::uint32_t status =
            KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST; // Protocol-level status.
        std::uint32_t stageFlags = 0;      // KSWORD_ARK_FILE_IRP_STAGE_*。
        std::uint32_t majorFunction = 0;
        std::uint32_t minorFunction = 0;
        std::uint32_t requestedLayer = 0;
        std::uint32_t resolvedLayer = 0;
        long createStatus = 0;
        long operationStatus = 0;
        long cleanupStatus = 0;
        long closeStatus = 0;
        std::uint64_t information = 0;     // IoStatus.Information for the target major.
        std::uint64_t fileObjectAddress = 0;
        std::uint64_t targetDeviceAddress = 0;
        std::uint64_t targetDriverAddress = 0;
        std::uint64_t relatedDeviceAddress = 0;
        std::uint64_t baseFsDeviceAddress = 0;
        std::uint64_t vpbDeviceAddress = 0;
        std::uint64_t dispatchAddress = 0; // The dispatch entry point for this major function on the target driver.
        std::uint32_t targetStackSize = 0;
        std::uint32_t targetDeviceFlags = 0;
        std::wstring driverName;
        std::wstring deviceName;
        std::vector<std::uint8_t> outputData; // Data written back by the target driver.
    };

    // FileIrpSubmitRequestParams is the set of construction parameters on the R3 side.
    // Separated from the protocol structure so the UI only fills fields it cares about; length and token are uniformly completed by the client.
    struct FileIrpSubmitRequestParams
    {
        std::wstring ntPath;               // Target NT path.
        std::wstring pattern;              // Wildcard for DIRECTORY_CONTROL; may be null.
        std::uint32_t majorFunction = 0;
        std::uint32_t minorFunction = 0;
        std::uint32_t targetLayer = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
        std::uint32_t flags = 0;           // KSWORD_ARK_FILE_IRP_FLAG_* (excluding token bits).
        std::uint32_t timeoutMs = 0;       // 0 indicates using the R0 default timeout.
        std::uint32_t desiredAccess = 0;
        std::uint32_t shareAccess = 0;
        std::uint32_t createDisposition = 0;
        std::uint32_t createOptions = 0;
        std::uint32_t fileAttributes = 0;
        std::uint32_t informationClass = 0;
        std::uint32_t controlCode = 0;
        std::uint32_t securityInformation = 0;
        std::uint32_t lockKey = 0;
        std::uint32_t outputBytes = 0;     // Expected output buffer length.
        std::uint64_t byteOffset = 0;
        std::uint64_t lockLength = 0;
        std::vector<std::uint8_t> inputData; // Inline input data.
        bool uiConfirmed = false;          // Write semantics/dangerous major must be true.
        bool allowDangerous = false;       // Additional gates for POWER/PNP/SHUTDOWN, etc.
    };

    // ImageSignatureQueryResult preserves the complete fixed R0 response so
    // callers can distinguish PE certificate-table structure from the
    // independent Code Integrity cached-signing-level result.
    struct ImageSignatureQueryResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE response{};
    };

    // FileIntegrityResult carries the R0 file Mandatory Label write response.
    // Input: Populated by DriverClient::setFileIntegrity, echoing back the request's flags, integrityRid, and pathLengthChars.
    // Handling: io.ok only indicates successful driver communication and response parsing; status/lastStatus represent the results of ZwCreateFile/ZwSetSecurityObject.
    // Return behavior: unsupported=true indicates the old driver lacks the IOCTL, allowing the caller to fall back to R3 based on policy.
    struct FileIntegrityResult
    {
        IoResult io;                         // io: status and response NTSTATUS from the underlying DeviceIoControl.
        bool unsupported = false;            // unsupported: the old driver has not registered the IOCTL or returns unsupported.
        std::uint32_t version = 0;           // version: protocol version.
        std::uint32_t flags = 0;             // flags: Echoes KSWORD_ARK_FILE_INTEGRITY_FLAG_*.
        std::uint32_t integrityRid = 0;      // integrityRid：S-1-16-* mandatory label RID。
        std::uint32_t status = KSWORD_ARK_FILE_INTEGRITY_STATUS_UNKNOWN; // status: R0 aggregated status.
        long lastStatus = 0;                 // lastStatus: NTSTATUS from ZwCreateFile, ZwSetSecurityObject, etc.
        std::uint32_t pathLengthChars = 0;   // pathLengthChars: Number of characters in the NT path received by the driver.
    };

    // FileDeleteBackend: The single-node execution backend for the DELETE_PATH IOCTL.
    // Native retains the original underlying Zw* scheme; IRP is dispatched via the file system stack as IRP_MJ_SET_INFORMATION.
    // Posix mandates using FileDispositionInformationEx with POSIX unlink semantics.
    enum class FileDeleteBackend : std::uint32_t
    {
        kNative = 0U,
        kIrp = 1U,
        kPosix = 2U
    };

    // DeletePathResult carries the statistical receipt for R0 deletion (single-item or recursive).
    // Input: populated by DriverClient::deletePathEx.
    // Handling: io.ok only indicates DeviceIoControl success; deletion semantics depend on response.deleteStatus.
    // Return behavior: unsupported=true indicates the driver does not recognize the selected recursive/backend flags. Only Native mode
    // can fall back to the legacy R3 unwind for item-by-item deletion; Irp/Posix modes must explicitly report backend unavailability.
    struct DeletePathResult
    {
        IoResult io;                                // io: Underlying DeviceIoControl status.
        bool unsupported = false;                   // unsupported: Old drivers reject new flags.
        bool responseValid = false;                 // responseValid: Whether a complete response packet was parsed.
        KSWORD_ARK_DELETE_PATH_RESPONSE response{}; // response: R0 fixed statistics response
    };

    // FileMonitorStatusResult is the R3 model representing the R0 file system minifilter runtime status.
    struct FileMonitorStatusResult
    {
        IoResult io;                    // io: DeviceIoControl call status.
        std::uint32_t version = 0;      // version: File monitoring protocol version.
        std::uint32_t size = 0;         // size: R0 return structure size.
        std::uint32_t runtimeFlags = 0; // runtimeFlags: Flags such as REGISTERED, STARTED, DROPPED, etc.
        std::uint32_t operationMask = 0;// operationMask: Bitmask for filtering current file event operations.
        std::uint32_t processIdFilter = 0; // processIdFilter: 0 indicates no PID filtering.
        std::uint32_t ringCapacity = 0; // ringCapacity: Capacity of the R0 ring buffer.
        std::uint32_t queuedCount = 0;  // queuedCount: Current number of pending events.
        std::uint32_t droppedCount = 0; // droppedCount: Cumulative count of overwrite drop events.
        std::uint64_t sequence = 0;     // sequence: R0 file event sequence number.
        long registerStatus = 0;        // registerStatus: FltRegisterFilter status.
        long startStatus = 0;           // startStatus: Status of FltStartFiltering.
        long lastErrorStatus = 0;       // lastErrorStatus: Most recent file monitoring error.
    };

    // FileMonitorEventRow is the R3 presentation model for the R0 file-monitor ring buffer.
    struct FileMonitorEventRow
    {
        std::uint32_t version = 0;       // version: Event protocol version.
        std::uint32_t size = 0;          // size: R0 event structure size.
        std::uint32_t operationType = 0; // operationType：KSWORD_ARK_FILE_MONITOR_OPERATION_*。
        std::uint32_t majorFunction = 0; // majorFunction：IRP_MJ_*。
        std::uint32_t minorFunction = 0; // minorFunction：IRP_MN_*。
        std::uint32_t processId = 0;     // processId: PID of the process initiating the request.
        std::uint32_t threadId = 0;      // threadId: ID of the thread initiating the request.
        std::uint32_t fieldFlags = 0;    // fieldFlags: Bitmap of valid fields.
        std::uint32_t desiredAccess = 0; // desiredAccess: Create/Open access mask.
        std::uint32_t shareAccess = 0;   // shareAccess: Create/Open share mask.
        std::uint32_t createOptions = 0; // createOptions：Create/Open options。
        std::uint32_t fileInformationClass = 0; // fileInformationClass：SetInformation class。
        long resultStatus = 0;           // resultStatus：post-operation NTSTATUS。
        std::uint32_t pathLengthChars = 0; // pathLengthChars: Path character count returned by R0.
        std::uint64_t sequence = 0;      // sequence: R0 event sequence number.
        std::int64_t timeUtc100ns = 0;   // timeUtc100ns：UTC FILETIME。
        std::uint64_t fileObjectAddress = 0; // fileObjectAddress: Address of the FileObject, for diagnostic display only.
        std::uint32_t fsControlCode = 0; // fsControlCode: IRP_MJ_FILE_SYSTEM_CONTROL control code.
        std::uint32_t fsInputBufferLength = 0; // fsInputBufferLength: Input buffer length.
        std::uint32_t fsOutputBufferLength = 0; // fsOutputBufferLength: Output buffer length.
        std::wstring path;               // path: The normalized/opened file name parsed in R0.
    };

    // FileMonitorDrainResult is the parsed result of the file monitor drain IOCTL.
    struct FileMonitorDrainResult
    {
        IoResult io;                     // io: DeviceIoControl call status.
        std::uint32_t version = 0;       // version: Response protocol version.
        std::uint32_t totalQueuedBeforeDrain = 0; // totalQueuedBeforeDrain: Queue depth before draining.
        std::uint32_t returnedCount = 0; // returnedCount: Number of events returned in this call.
        std::uint32_t entrySize = 0;     // entrySize: Size in bytes of a single R0 event.
        std::uint32_t droppedCount = 0;  // droppedCount: Cumulative count of dropped events.
        std::uint32_t runtimeFlags = 0;  // runtimeFlags：REGISTERED/STARTED/DROPPED。
        std::uint32_t ringCapacity = 0;  // ringCapacity: R0 ring capacity.
        std::vector<FileMonitorEventRow> events; // events: List of parsed events.
    };
}
