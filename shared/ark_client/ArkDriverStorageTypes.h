#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkStorageIoctl.h"
#include "../driver/KswordArkStorageForensicsIoctl.h"

namespace ksword::ark
{
    // StorageVolumeStackAuditResult carries audit results for the volume device stack and FVEVOL location.
    // Input: returned by queryVolumeStackAudit.
    // Note: rows store the device object, driver object, stack depth, risk, and confidence.
    // Return behavior: Does not return BitLocker key material and does not modify the storage stack.
    struct StorageVolumeStackAuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t maxRows = 0;
        std::uint32_t fvevolPresent = 0;
        std::uint32_t fvevolPosition = 0xFFFFFFFFUL;
        std::vector<KSWORD_ARK_VOLUME_STACK_ROW> rows;
    };

    // StorageBitlockerFveAuditResult carries a summary of BitLocker/FVE security status.
    // Input: queryBitlockerFveAudit. Output.
    // Processing: rows contain only protection status, transition status, lock status, and protector type counts.
    // Return behavior: The protocol does not carry key, recovery password, or metadata payloads.
    struct StorageBitlockerFveAuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t maxRows = 0;
        std::vector<KSWORD_ARK_BITLOCKER_FVE_ROW> rows;
    };

    // StorageMountMgrMappingAuditResult: Carries MountMgr drive letter/GUID/NT path mapping audit results.
    // Input: queryMountMgrMappingAudit response.
    // Note: rows store symbol names and risk flags without resolving volume data.
    // Return behavior: Displays mapping relationships only; mount points are not modified.
    struct StorageMountMgrMappingAuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t maxRows = 0;
        std::vector<KSWORD_ARK_MOUNTMGR_MAPPING_ROW> rows;
    };

    // StorageFilesystemIntegrityAuditResult carries the DriverObject/FastIo/dispatch integrity row for the file system.
    // Input: queryFilesystemIntegrityAudit return value.
    // Note: rows store slot owner, target address, and risk; no function pointers are written.
    // Returns behavior: read-only audit result.
    struct StorageFilesystemIntegrityAuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t maxRows = 0;
        std::vector<KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW> rows;
    };

    // RawDiskBackendResult encapsulates three-layer access capabilities and security boundaries for a physical disk.
    // Input: return value of queryRawDiskBackend.
    // Handling: response stores sector, capacity, bus, offline status, and system disk information detected by R0.
    // Return behavior: unsupported indicates the current driver does not implement the protocol; no implicit fallback to other backends.
    struct RawDiskBackendResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE response{};
    };

    // RawDiskReadResult: Carries a bounded, sector-aligned physical disk read result.
    // Input: return value of readRawDisk.
    // Note: bytes stores only the byte count explicitly reported as completed by R0.
    // Return behavior: retains protocol status, backendUsed, and lastStatus even on failure.
    struct RawDiskReadResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        std::uint32_t backendUsed = 0;
        std::uint32_t logicalSectorSize = 0;
        std::vector<std::uint8_t> bytes;
    };

    // RawDiskWriteResult carries the result of a physical disk write after explicit confirmation.
    // Input: Return from writeRawDisk.
    // Note: response retains the final state of the central security policy and the actual backend.
    // Return behavior: bytesTransferred indicates only the bytes explicitly reported as completed by the underlying layer.
    struct RawDiskWriteResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_RAW_DISK_WRITE_RESPONSE response{};
    };
}
