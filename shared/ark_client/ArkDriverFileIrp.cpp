#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

// ============================================================
// ArkDriverFileIrp.cpp
// Purpose:
// 1) Encapsulates two R0 interfaces for 'custom IRP direct dispatch to the file system stack';
// 2) Perform complete protocol version and line-boundary validation on responses; any inconsistency
//    degrades to communication failure, never passing partial responses as valid data to the UI.
// 3) No policy judgment at this layer: write semantics and dangerous major confirmation are provided
//    by the caller; this layer only translates them into protocol bits and confirmation tokens.
// ============================================================

namespace ksword::ark
{
    namespace
    {


        // appendDirectoryRows:
        // - Validate and append directory rows line by line; any out-of-bounds name invalidates the entire page rather than silently dropping the single row.
        bool appendDirectoryRows(
            const KSWORD_ARK_DIRECTORY_ENTRY* rows,
            const std::size_t rowCount,
            std::vector<DirectoryEntryRecord>& entriesOut)
        {
            for (std::size_t index = 0U; index < rowCount; ++index)
            {
                const KSWORD_ARK_DIRECTORY_ENTRY& source = rows[index];
                if (source.nameLengthChars >= KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS ||
                    source.name[source.nameLengthChars] != L'\0')
                {
                    return false;
                }

                DirectoryEntryRecord record{};
                record.flags = source.flags;
                record.fileAttributes = source.fileAttributes;
                record.fileId = source.fileId;
                record.allocationSize = source.allocationSize;
                record.endOfFile = source.endOfFile;
                record.creationTime = source.creationTime;
                record.lastAccessTime = source.lastAccessTime;
                record.lastWriteTime = source.lastWriteTime;
                record.changeTime = source.changeTime;
                record.name.assign(source.name, source.name + source.nameLengthChars);
                entriesOut.push_back(std::move(record));
            }
            return true;
        }
    }

    FileIrpDirectoryResult DriverClient::enumerateDirectoryByIrp(
        const std::wstring& ntPath,
        const unsigned long targetLayer,
        const unsigned long maxEntries) const
    {
        FileIrpDirectoryResult result{};
        result.requestedLayer = targetLayer;
        result.resolvedLayer = targetLayer;

        if (ntPath.empty() ||
            ntPath.size() >= KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS ||
            targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
            maxEntries == 0UL ||
            maxEntries > KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message =
                "irp-directory request invalid, chars=" +
                std::to_string(ntPath.size()) +
                ", layer=" + std::to_string(targetLayer) +
                ", maxEntries=" + std::to_string(maxEntries);
            return result;
        }

        DriverHandle handle = open();
        unsigned long startIndex = 0UL;
        while (result.entries.size() < static_cast<std::size_t>(maxEntries))
        {
            const unsigned long kRemainingEntries =
                maxEntries - static_cast<unsigned long>(result.entries.size());
            const unsigned long kPageEntries = (std::min)(
                kRemainingEntries,
                static_cast<unsigned long>(KSWORD_ARK_DIRECTORY_ENUM_MAX_PAGE_ENTRIES));
            const std::size_t kResponseBytes =
                KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
                (static_cast<std::size_t>(kPageEntries) *
                    sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
            std::vector<std::uint8_t> responseBuffer(kResponseBytes, 0U);

            KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST request{};
            request.version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
            request.size = static_cast<unsigned long>(sizeof(request));
            request.flags = 0UL;
            request.targetLayer = targetLayer;
            request.startIndex = startIndex;
            request.maxEntries = kPageEntries;
            request.pathLengthChars = static_cast<unsigned short>(ntPath.size());
            std::copy(ntPath.begin(), ntPath.end(), request.path);
            request.path[request.pathLengthChars] = L'\0';

            result.io = deviceIoControl(
                IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY,
                &request,
                static_cast<unsigned long>(sizeof(request)),
                responseBuffer.data(),
                static_cast<unsigned long>(responseBuffer.size()),
                &handle);
            if (!result.io.ok)
            {
                result.unsupported = detail::isUnsupportedIoctlError(result.io.win32Error);
                result.io.message =
                    "DeviceIoControl(IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY) failed, error=" +
                    std::to_string(result.io.win32Error);
                return result;
            }
            if (result.io.bytesReturned <
                KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message =
                    "irp-directory response header truncated, bytesReturned=" +
                    std::to_string(result.io.bytesReturned);
                return result;
            }

            const auto* response =
                reinterpret_cast<const KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE*>(
                    responseBuffer.data());
            if (response->version != KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION ||
                response->rowSize != static_cast<unsigned long>(sizeof(KSWORD_ARK_DIRECTORY_ENTRY)) ||
                response->startIndex != startIndex ||
                response->size < KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE ||
                response->size > result.io.bytesReturned ||
                response->reserved != 0UL ||
                response->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
                (response->responseFlags & ~(
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE |
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_FS_NAME_PRESENT)) != 0UL ||
                response->queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE ||
                response->queryStatus > KSWORD_ARK_DIRECTORY_ENUM_STATUS_INVALID_REQUEST)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_REVISION_MISMATCH;
                result.io.message = "irp-directory protocol header mismatch";
                return result;
            }

            const std::size_t kAvailableRows =
                (static_cast<std::size_t>(result.io.bytesReturned) -
                    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) /
                sizeof(KSWORD_ARK_DIRECTORY_ENTRY);
            const std::size_t kDeclaredRows = response->rowCount;
            const std::size_t kDeclaredBytes =
                KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
                (kDeclaredRows * sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
            if (kDeclaredRows > kAvailableRows ||
                kDeclaredRows > static_cast<std::size_t>(kPageEntries) ||
                kDeclaredBytes != static_cast<std::size_t>(response->size) ||
                response->nextIndex != startIndex + response->rowCount)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message =
                    "irp-directory row boundary invalid, rows=" +
                    std::to_string(kDeclaredRows);
                return result;
            }

            result.queryStatus = response->queryStatus;
            result.responseFlags = response->responseFlags;
            result.resolvedLayer = response->targetLayer;
            result.openStatus = response->openStatus;
            result.lastStatus = response->lastStatus;
            result.targetDeviceAddress = response->targetDeviceAddress;
            result.targetDriverAddress = response->targetDriverAddress;
            result.io.ntStatus = response->lastStatus;
            if (response->driverNameLengthChars != 0UL &&
                response->driverNameLengthChars < KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS)
            {
                result.driverName = detail::readFixedString(
                    response->driverName,
                    response->driverNameLengthChars);
            }
            if ((response->responseFlags &
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_FS_NAME_PRESENT) != 0UL)
            {
                if (response->fileSystemNameLengthChars == 0UL ||
                    response->fileSystemNameLengthChars >=
                        KSWORD_ARK_DIRECTORY_ENUM_FS_NAME_MAX_CHARS ||
                    response->fileSystemName[
                        response->fileSystemNameLengthChars] != L'\0')
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message =
                        "irp-directory filesystem name boundary invalid";
                    return result;
                }
                result.fileSystemName = std::wstring(
                    response->fileSystemName,
                    response->fileSystemName + response->fileSystemNameLengthChars);
            }

            if (!appendDirectoryRows(response->rows, kDeclaredRows, result.entries))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = "irp-directory entry name boundary invalid";
                return result;
            }

            if ((response->responseFlags &
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE) == 0UL)
            {
                return result;
            }
            if (kDeclaredRows == 0U)
            {
                // The driver claims more data exists, but this page provides none: continuing the loop would cause a deadlock, so terminate directly.
                result.capped = true;
                return result;
            }
            startIndex = response->nextIndex;
        }

        result.capped = true;
        return result;
    }

    FileIrpSubmitResult DriverClient::submitFileIrp(
        const FileIrpSubmitRequestParams& params) const
    {
        FileIrpSubmitResult result{};
        result.majorFunction = params.majorFunction;
        result.minorFunction = params.minorFunction;
        result.requestedLayer = params.targetLayer;
        result.resolvedLayer = params.targetLayer;

        if (params.ntPath.empty() ||
            params.ntPath.size() >= KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS ||
            params.pattern.size() >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS ||
            params.majorFunction >= KSWORD_ARK_FILE_IRP_MAJOR_COUNT ||
            params.minorFunction > 0xFFUL ||
            params.targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
            params.inputData.size() > KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES ||
            params.outputBytes > KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES ||
            params.timeoutMs > KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message =
                "irp-submit request invalid, major=" +
                std::to_string(params.majorFunction) +
                ", layer=" + std::to_string(params.targetLayer) +
                ", inputBytes=" + std::to_string(params.inputData.size()) +
                ", outputBytes=" + std::to_string(params.outputBytes);
            return result;
        }

        const std::size_t kInputBytes = params.inputData.size();
        const std::size_t kRequestBytes =
            static_cast<std::size_t>(KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE) +
            kInputBytes;
        const std::size_t kResponseBytes =
            static_cast<std::size_t>(KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE) +
            params.outputBytes;

        std::vector<std::uint8_t> requestBuffer(kRequestBytes, 0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST*>(requestBuffer.data());
        request->version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
        request->size = KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE;
        request->flags = params.flags & ~(
            KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED |
            KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS);
        if (params.uiConfirmed)
        {
            request->flags |= KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED;
            request->confirmationToken = KSWORD_ARK_FILE_IRP_CONFIRMATION_TOKEN;
        }
        if (params.allowDangerous)
        {
            request->flags |= KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS;
        }
        request->majorFunction = params.majorFunction;
        request->minorFunction = params.minorFunction;
        request->targetLayer = params.targetLayer;
        request->timeoutMs = params.timeoutMs;
        request->desiredAccess = params.desiredAccess;
        request->shareAccess = params.shareAccess;
        request->createDisposition = params.createDisposition;
        request->createOptions = params.createOptions;
        request->fileAttributes = params.fileAttributes;
        request->informationClass = params.informationClass;
        request->controlCode = params.controlCode;
        request->securityInformation = params.securityInformation;
        request->inputBytes = static_cast<unsigned long>(kInputBytes);
        request->outputBytes = params.outputBytes;
        request->lockKey = params.lockKey;
        request->byteOffset = params.byteOffset;
        request->lockLength = params.lockLength;
        request->pathLengthChars =
            static_cast<unsigned short>(params.ntPath.size());
        request->patternLengthChars =
            static_cast<unsigned short>(params.pattern.size());
        std::copy(params.ntPath.begin(), params.ntPath.end(), request->path);
        request->path[request->pathLengthChars] = L'\0';
        if (!params.pattern.empty())
        {
            std::copy(params.pattern.begin(), params.pattern.end(), request->pattern);
        }
        request->pattern[request->patternLengthChars] = L'\0';
        if (kInputBytes != 0U)
        {
            std::memcpy(request->inputData, params.inputData.data(), kInputBytes);
        }

        std::vector<std::uint8_t> responseBuffer(kResponseBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.unsupported = detail::isUnsupportedIoctlError(result.io.win32Error);
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message =
                "irp-submit response header truncated, bytesReturned=" +
                std::to_string(result.io.bytesReturned);
            return result;
        }

        const auto* response =
            reinterpret_cast<const KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE*>(
                responseBuffer.data());
        const std::size_t kAvailableOutputBytes =
            static_cast<std::size_t>(result.io.bytesReturned) -
            KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE;
        if (response->version != KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION ||
            response->status > KSWORD_ARK_FILE_IRP_STATUS_MAX ||
            response->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
            response->outputBytes > kAvailableOutputBytes ||
            response->size !=
                KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE + response->outputBytes ||
            response->driverNameLengthChars >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS ||
            response->deviceNameLengthChars >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_REVISION_MISMATCH;
            result.io.message = "irp-submit protocol header mismatch";
            return result;
        }

        result.status = response->status;
        result.stageFlags = response->stageFlags;
        result.majorFunction = response->majorFunction;
        result.minorFunction = response->minorFunction;
        result.resolvedLayer = response->targetLayer;
        result.createStatus = response->createStatus;
        result.operationStatus = response->operationStatus;
        result.cleanupStatus = response->cleanupStatus;
        result.closeStatus = response->closeStatus;
        result.information = response->information;
        result.fileObjectAddress = response->fileObjectAddress;
        result.targetDeviceAddress = response->targetDeviceAddress;
        result.targetDriverAddress = response->targetDriverAddress;
        result.relatedDeviceAddress = response->relatedDeviceAddress;
        result.baseFsDeviceAddress = response->baseFsDeviceAddress;
        result.vpbDeviceAddress = response->vpbDeviceAddress;
        result.dispatchAddress = response->dispatchAddress;
        result.targetStackSize = response->targetStackSize;
        result.targetDeviceFlags = response->targetDeviceFlags;
        result.io.ntStatus = response->operationStatus;
        result.driverName = detail::readFixedString(
            response->driverName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS);
        result.deviceName = detail::readFixedString(
            response->deviceName,
            KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS);
        if (response->outputBytes != 0UL)
        {
            result.outputData.assign(
                response->outputData,
                response->outputData + response->outputBytes);
        }
        return result;
    }
}
