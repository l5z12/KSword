#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

namespace ksword::ark
{
    namespace
    {


        template <typename TValue>
        void copyFileMonitorFieldIfPresent(
            const unsigned char* entryBytes,
            const std::size_t entrySize,
            const std::size_t fieldOffset,
            TValue* valueOut)
        {
            if (entryBytes == nullptr || valueOut == nullptr)
            {
                return;
            }
            if (entrySize < fieldOffset || (entrySize - fieldOffset) < sizeof(TValue))
            {
                return;
            }
            std::memcpy(valueOut, entryBytes + fieldOffset, sizeof(TValue));
        }

        FileMonitorEventRow parseFileMonitorEventRow(const unsigned char* entryBytes, const std::size_t entrySize)
        {
            FileMonitorEventRow row{};
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, version), &row.version);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, size), &row.size);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, operationType), &row.operationType);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, majorFunction), &row.majorFunction);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, minorFunction), &row.minorFunction);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, processId), &row.processId);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, threadId), &row.threadId);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, fieldFlags), &row.fieldFlags);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, desiredAccess), &row.desiredAccess);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, shareAccess), &row.shareAccess);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, createOptions), &row.createOptions);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, fileInformationClass), &row.fileInformationClass);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, resultStatus), &row.resultStatus);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, pathLengthChars), &row.pathLengthChars);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, sequence), &row.sequence);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, timeUtc100ns), &row.timeUtc100ns);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, fileObjectAddress), &row.fileObjectAddress);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, fsControlCode), &row.fsControlCode);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, fsInputBufferLength), &row.fsInputBufferLength);
            copyFileMonitorFieldIfPresent(entryBytes, entrySize, offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, fsOutputBufferLength), &row.fsOutputBufferLength);

            constexpr std::size_t kPathOffset = offsetof(KSWORD_ARK_FILE_MONITOR_EVENT, path);
            if (entryBytes != nullptr && entrySize > kPathOffset)
            {
                const std::size_t kAvailablePathBytes = entrySize - kPathOffset;
                const std::size_t kAvailablePathChars = std::min<std::size_t>(
                    KSWORD_ARK_FILE_MONITOR_PATH_CHARS,
                    kAvailablePathBytes / sizeof(wchar_t));
                row.path = detail::readFixedString(
                    reinterpret_cast<const wchar_t*>(entryBytes + kPathOffset),
                    kAvailablePathChars);
            }
            return row;
        }
    }

    std::string formatImageSignatureEvidence(const ImageSignatureQueryResult& result)
    {
        std::ostringstream stream;
        stream << "source=R0 direct PE Security Directory (WinTrust not used)\n";
        stream << "communication.ok=" << (result.io.ok ? "true" : "false")
               << "\ncommunication.win32_error=" << result.io.win32Error
               << "\ncommunication.bytes_returned=" << result.io.bytesReturned
               << "\ncommunication.unsupported=" << (result.unsupported ? "true" : "false")
               << "\ncommunication.detail=" << result.io.message << '\n';
        if (!result.io.ok)
        {
            return stream.str();
        }

        const KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE& response = result.response;
        const auto kWriteStatus = [&stream](const char* name, const long status)
        {
            stream << name << "=0x"
                   << std::hex << std::setw(8) << std::setfill('0')
                   << static_cast<unsigned long>(status)
                   << std::dec << std::setfill(' ') << '\n';
        };
        stream << "protocol.version=" << response.version
               << "\nprotocol.size=" << response.size
               << "\nquery.status=" << response.queryStatus
               << "\nquery.flags=0x" << std::hex << response.requestFlags
               << "\nquery.field_flags=0x" << response.fieldFlags
               << "\npe.structural_flags=0x" << response.structuralFlags
               << std::dec << '\n';
        stream << "pe.certificate_table_present="
               << ((response.fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_CERTIFICATE_TABLE) != 0UL ? "true" : "false")
               << "\npe.nested_signature_oid_present="
               << ((response.structuralFlags & KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_NESTED_SIGNATURE_PRESENT) != 0UL ? "true" : "false")
               << "\nloaded.module_base_match="
               << ((response.fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE) != 0UL ? "true" : "false")
               << "\nloaded.module_name_match="
               << ((response.fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE_NAME_MATCH) != 0UL ? "true" : "false")
               << "\nci.cached_signing_level_present="
               << ((response.fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_SIGNING_LEVEL) != 0UL ? "true" : "false")
               << "\npe.structural_findings=";
        bool firstFinding = true;
        const auto kAppendFinding = [&stream, &firstFinding, &response](const unsigned long flag, const char* name)
        {
            if ((response.structuralFlags & flag) == 0UL)
            {
                return;
            }
            stream << (firstFinding ? "" : ",") << name;
            firstFinding = false;
        };
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_UNALIGNED, "cert_table_unaligned");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OUT_OF_RANGE, "cert_table_out_of_range");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_HEADER_TRUNCATED, "entry_header_truncated");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_LENGTH_INVALID, "entry_length_invalid");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_RANGE_INVALID, "entry_range_invalid");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_UNKNOWN_REVISION, "unknown_revision");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_UNKNOWN_TYPE, "unknown_certificate_type");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_OUTPUT_TRUNCATED, "entry_output_truncated");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_TRAILING_BYTES, "trailing_bytes");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_PADDING_NONZERO, "certificate_padding_nonzero");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_SCAN_LIMIT_REACHED, "scan_limit_reached");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_NESTED_SIGNATURE_PRESENT, "nested_signature_oid_present");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_MULTIPLE_PKCS7_ENTRIES, "multiple_pkcs7_entries");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERTIFICATE_READ_FAILED, "certificate_read_failed");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_LOADED_NAME_MISMATCH, "loaded_name_mismatch");
        kAppendFinding(KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OVERLAPS_HEADERS, "cert_table_overlaps_headers");
        if (firstFinding)
        {
            stream << "none";
        }
        stream << '\n';
        kWriteStatus("status.open", response.openStatus);
        kWriteStatus("status.file_size", response.fileSizeStatus);
        kWriteStatus("status.file_object", response.objectStatus);
        kWriteStatus("status.pe_parse", response.parseStatus);
        kWriteStatus("status.certificate_table", response.certificateStatus);
        kWriteStatus("status.cached_signing_level", response.signingLevelStatus);
        kWriteStatus("status.loaded_module_match", response.loadedModuleStatus);
        stream << "file.size=" << response.fileSize
               << "\npe.header_offset=0x" << std::hex << response.peHeaderOffset
               << "\npe.machine=0x" << response.peMachine
               << "\npe.optional_magic=0x" << response.optionalHeaderMagic
               << "\npe.size_of_headers=0x" << response.sizeOfHeaders
               << "\ncertificate_table.file_offset=0x" << response.certificateTableOffset
               << "\ncertificate_table.size=0x" << response.certificateTableSize
               << std::dec
               << "\ncertificate_table.count=" << response.certificateCount
               << "\ncertificate_table.returned_count=" << response.returnedCertificateCount
               << "\ncertificate_table.pkcs7_count=" << response.pkcs7CertificateCount
               << "\ncertificate_table.nested_signature_oid_count=" << response.nestedSignatureCount
               << "\ncertificate_table.bytes_scanned=" << response.certificateBytesScanned
               << "\nloaded.expected_base=0x" << std::hex << response.expectedModuleBase
               << "\nloaded.matched_base=0x" << response.matchedModuleBase
               << "\nloaded.matched_size=0x" << response.matchedModuleSize
               << std::dec
               << "\nci.cached_signing_level=" << response.signingLevel
               << "\nci.cached_signing_flags=0x" << std::hex << response.signingLevelFlags
               << "\nci.thumbprint_algorithm=0x" << response.thumbprintAlgorithm
               << std::dec
               << "\nci.thumbprint=";
        const std::size_t kThumbprintSize = std::min<std::size_t>(
            response.thumbprintSize,
            sizeof(response.thumbprint));
        if (kThumbprintSize == 0U)
        {
            stream << "<unavailable>";
        }
        else
        {
            for (std::size_t index = 0U; index < kThumbprintSize; ++index)
            {
                stream << std::hex << std::setw(2) << std::setfill('0')
                       << static_cast<unsigned int>(response.thumbprint[index]);
            }
            stream << std::dec << std::setfill(' ');
        }
        stream << '\n';

        const std::size_t kEntryCount = std::min<std::size_t>(
            response.returnedCertificateCount,
            KSWORD_ARK_IMAGE_SIGNATURE_MAX_ENTRIES);
        for (std::size_t index = 0U; index < kEntryCount; ++index)
        {
            const KSWORD_ARK_IMAGE_SIGNATURE_CERTIFICATE_ENTRY& entry = response.certificates[index];
            stream << "certificate[" << index << "].file_offset=0x" << std::hex << entry.fileOffset
                   << "\ncertificate[" << index << "].length=0x" << entry.length
                   << "\ncertificate[" << index << "].aligned_length=0x" << entry.alignedLength
                   << "\ncertificate[" << index << "].revision=0x" << entry.revision
                   << "\ncertificate[" << index << "].type=0x" << entry.certificateType
                   << "\ncertificate[" << index << "].flags=0x" << entry.flags
                   << "\ncertificate[" << index << "].content_fnv1a64_noncrypto=0x" << entry.contentHashFnv1a64
                   << std::dec
                   << "\ncertificate[" << index << "].nested_signature_oid_count=" << entry.nestedSignatureCount
                   << "\ncertificate[" << index << "].content_bytes_scanned=" << entry.contentBytesScanned
                   << "\ncertificate[" << index << "].read_status=0x" << std::hex
                   << static_cast<unsigned long>(entry.readStatus) << std::dec << '\n';
        }
        return stream.str();
    }

    FileInfoQueryResult DriverClient::queryFileInfo(const std::wstring& ntPath, const unsigned long flags) const
    {
        // Purpose: Query R0 file basic information using an independent control handle.
        // Output: FileInfoQueryResult; on failure, io.message contains Win32/protocol diagnostics.
        DriverHandle handle = open();
        return queryFileInfo(handle, ntPath, flags);
    }

    DirectoryEnumerationResult DriverClient::enumerateDirectory(
        const std::wstring& ntPath,
        const unsigned long maxEntries) const
    {
        // Purpose: Use a driver control handle to fetch directory entries in pages, avoiding repeated KswordARK connection establishment per page.
        // Input: ntPath must be a \??\C:\... or another NT path the driver can open; maxEntries is the R3 total budget.
        // Return: DirectoryEnumerationResult preserves communication, semantics, truncation, and parsed lines.
        DirectoryEnumerationResult result{};
        if (ntPath.empty() ||
            ntPath.size() >= KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS ||
            maxEntries == 0UL ||
            maxEntries > KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message =
                "directory-enum request invalid, chars=" +
                std::to_string(ntPath.size()) +
                ", maxEntries=" + std::to_string(maxEntries);
            return result;
        }

        DriverHandle handle = open();
        unsigned long startIndex = 0UL;
        while (result.entries.size() < static_cast<std::size_t>(maxEntries))
        {
            const unsigned long kRemainingEntries =
                maxEntries - static_cast<unsigned long>(result.entries.size());
            const unsigned long kPageEntries = std::min<unsigned long>(
                kRemainingEntries,
                KSWORD_ARK_DIRECTORY_ENUM_MAX_PAGE_ENTRIES);
            const std::size_t kResponseBytes =
                KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
                (static_cast<std::size_t>(kPageEntries) *
                    sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
            std::vector<std::uint8_t> responseBuffer(kResponseBytes, 0U);

            KSWORD_ARK_ENUM_DIRECTORY_REQUEST request{};
            request.version = KSWORD_ARK_DIRECTORY_ENUM_PROTOCOL_VERSION;
            request.size = static_cast<unsigned long>(sizeof(request));
            request.flags = 0UL;
            request.startIndex = startIndex;
            request.maxEntries = kPageEntries;
            request.pathLengthChars =
                static_cast<unsigned short>(ntPath.size());
            std::copy(ntPath.begin(), ntPath.end(), request.path);
            request.path[request.pathLengthChars] = L'\0';

            result.io = deviceIoControl(
                IOCTL_KSWORD_ARK_ENUM_DIRECTORY,
                &request,
                static_cast<unsigned long>(sizeof(request)),
                responseBuffer.data(),
                static_cast<unsigned long>(responseBuffer.size()),
                &handle);
            if (!result.io.ok)
            {
                result.unsupported =
                    detail::isUnsupportedIoctlError(result.io.win32Error);
                result.io.message =
                    "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_DIRECTORY) failed, error=" +
                    std::to_string(result.io.win32Error);
                return result;
            }
            if (result.io.bytesReturned <
                KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message =
                    "directory-enum response header truncated, bytesReturned=" +
                    std::to_string(result.io.bytesReturned);
                return result;
            }

            const auto* response =
                reinterpret_cast<const KSWORD_ARK_ENUM_DIRECTORY_RESPONSE*>(
                    responseBuffer.data());
            if (response->version !=
                    KSWORD_ARK_DIRECTORY_ENUM_PROTOCOL_VERSION ||
                response->rowSize != static_cast<unsigned long>(sizeof(KSWORD_ARK_DIRECTORY_ENTRY)) ||
                response->startIndex != startIndex ||
                response->size <
                    KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE ||
                response->size > result.io.bytesReturned ||
                response->reserved != 0UL ||
                (response->responseFlags & ~(
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE |
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_FS_NAME_PRESENT)) != 0UL ||
                response->queryStatus == KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE ||
                response->queryStatus > KSWORD_ARK_DIRECTORY_ENUM_STATUS_INVALID_REQUEST)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_REVISION_MISMATCH;
                result.io.message =
                    "directory-enum protocol header mismatch";
                return result;
            }

            const std::size_t kAvailableRows =
                (static_cast<std::size_t>(result.io.bytesReturned) -
                    KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) /
                sizeof(KSWORD_ARK_DIRECTORY_ENTRY);
            const std::size_t kDeclaredRows = response->rowCount;
            const std::size_t kDeclaredBytes =
                KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
                (kDeclaredRows * sizeof(KSWORD_ARK_DIRECTORY_ENTRY));
            if (kDeclaredRows > kAvailableRows ||
                kDeclaredRows > static_cast<std::size_t>(kPageEntries) ||
                kDeclaredBytes != static_cast<std::size_t>(response->size) ||
                response->nextIndex != startIndex + response->rowCount)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message =
                    "directory-enum row boundary invalid, rows=" +
                    std::to_string(kDeclaredRows);
                return result;
            }

            result.queryStatus = response->queryStatus;
            result.responseFlags = response->responseFlags;
            result.openStatus = response->openStatus;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
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
                        "directory-enum filesystem name boundary invalid";
                    return result;
                }
                result.fileSystemName = std::wstring(
                    response->fileSystemName,
                    response->fileSystemName +
                        response->fileSystemNameLengthChars);
            }

            for (std::size_t index = 0U; index < kDeclaredRows; ++index)
            {
                const KSWORD_ARK_DIRECTORY_ENTRY& source =
                    response->rows[index];
                if (source.nameLengthChars >=
                        KSWORD_ARK_DIRECTORY_ENUM_NAME_MAX_CHARS ||
                    source.name[source.nameLengthChars] != L'\0')
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message =
                        "directory-enum entry name boundary invalid";
                    return result;
                }

                DirectoryEntryRecord entry{};
                entry.flags = source.flags;
                entry.fileAttributes = source.fileAttributes;
                entry.fileId = source.fileId;
                entry.allocationSize = source.allocationSize;
                entry.endOfFile = source.endOfFile;
                entry.creationTime = source.creationTime;
                entry.lastAccessTime = source.lastAccessTime;
                entry.lastWriteTime = source.lastWriteTime;
                entry.changeTime = source.changeTime;
                entry.name.assign(
                    source.name,
                    source.name + source.nameLengthChars);
                result.entries.push_back(std::move(entry));
            }

            if (result.queryStatus != KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK)
            {
                break;
            }

            const bool kMoreAvailable =
                (response->responseFlags &
                    KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE) != 0UL;
            if (!kMoreAvailable)
            {
                break;
            }
            if (response->rowCount == 0UL ||
                response->queryStatus != KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK ||
                response->nextIndex <= startIndex)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message =
                    "directory-enum pagination did not advance";
                return result;
            }
            startIndex = response->nextIndex;
        }

        result.capped = result.entries.size() >=
                static_cast<std::size_t>(maxEntries) &&
            (result.responseFlags &
                KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_MORE_AVAILABLE) != 0UL;
        std::ostringstream stream;
        stream << "directory enum status=" << result.queryStatus
            << ", rows=" << result.entries.size()
            << ", capped=" << (result.capped ? "true" : "false")
            << ", ntStatus=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }

    ImageSignatureQueryResult DriverClient::queryImageSignature(
        const std::wstring& ntPath,
        const std::uint64_t expectedModuleBase,
        const unsigned long flags) const
    {
        ImageSignatureQueryResult queryResult{};
        if (ntPath.empty() || ntPath.size() >= KSWORD_ARK_TRUST_PATH_MAX_CHARS)
        {
            queryResult.io.ok = false;
            queryResult.io.win32Error = ERROR_INVALID_PARAMETER;
            queryResult.io.message = "image-signature path invalid, chars=" + std::to_string(ntPath.size());
            return queryResult;
        }

        KSWORD_ARK_QUERY_IMAGE_SIGNATURE_REQUEST request{};
        request.flags = (flags == 0UL)
            ? KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT
            : flags;
        if (expectedModuleBase != 0U)
        {
            request.flags |= KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE;
        }
        request.pathLengthChars = static_cast<unsigned short>(ntPath.size());
        request.expectedModuleBase = expectedModuleBase;
        std::copy(ntPath.begin(), ntPath.end(), request.path);
        request.path[request.pathLengthChars] = L'\0';

        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &queryResult.response,
            static_cast<unsigned long>(sizeof(queryResult.response)));
        if (!queryResult.io.ok)
        {
            queryResult.unsupported = detail::isUnsupportedIoctlError(queryResult.io.win32Error);
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_IMAGE_SIGNATURE) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }
        if (queryResult.io.bytesReturned < sizeof(KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE))
        {
            queryResult.io.ok = false;
            queryResult.io.win32Error = ERROR_INVALID_DATA;
            queryResult.io.message =
                "image-signature response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }
        if (queryResult.response.version != KSWORD_ARK_IMAGE_SIGNATURE_PROTOCOL_VERSION ||
            queryResult.response.size < sizeof(KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE))
        {
            queryResult.io.ok = false;
            queryResult.io.win32Error = ERROR_REVISION_MISMATCH;
            queryResult.io.message =
                "image-signature protocol mismatch, version=" +
                std::to_string(queryResult.response.version) +
                ", size=" + std::to_string(queryResult.response.size);
            return queryResult;
        }

        std::ostringstream stream;
        stream << "queryStatus=" << queryResult.response.queryStatus
               << ", fieldFlags=0x" << std::hex << queryResult.response.fieldFlags
               << ", structuralFlags=0x" << queryResult.response.structuralFlags
               << std::dec << ", certificates=" << queryResult.response.certificateCount
               << ", nestedSignatures=" << queryResult.response.nestedSignatureCount;
        queryResult.io.message = stream.str();
        return queryResult;
    }

    FileInfoQueryResult DriverClient::queryFileInfo(
        DriverHandle& handle,
        const std::wstring& ntPath,
        const unsigned long flags) const
    {
        // Action: Call IOCTL_KSWORD_ARK_QUERY_FILE_INFO.
        // Note: Transmit only NT path and flags; the driver returns FileBasic/FileStandard and object diagnostic fields.
        // Returns: the parsed FileInfoQueryResult.
        FileInfoQueryResult queryResult{};
        if (ntPath.empty() || ntPath.size() >= KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS)
        {
            queryResult.io.ok = false;
            queryResult.io.win32Error = ERROR_INVALID_PARAMETER;
            queryResult.io.message = "file-info path invalid, chars=" + std::to_string(ntPath.size());
            return queryResult;
        }

        KSWORD_ARK_QUERY_FILE_INFO_REQUEST request{};
        KSWORD_ARK_QUERY_FILE_INFO_RESPONSE response{};
        request.flags = flags;
        request.pathLengthChars = static_cast<unsigned short>(ntPath.size());
        std::copy(ntPath.begin(), ntPath.end(), request.path);
        request.path[request.pathLengthChars] = L'\0';

        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_FILE_INFO,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            &handle);
        if (!queryResult.io.ok)
        {
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_FILE_INFO) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }
        if (queryResult.io.bytesReturned < sizeof(KSWORD_ARK_QUERY_FILE_INFO_RESPONSE))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-file-info response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        queryResult.version = static_cast<std::uint32_t>(response.version);
        queryResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        queryResult.queryStatus = static_cast<std::uint32_t>(response.queryStatus);
        queryResult.openStatus = static_cast<long>(response.openStatus);
        queryResult.basicStatus = static_cast<long>(response.basicStatus);
        queryResult.standardStatus = static_cast<long>(response.standardStatus);
        queryResult.objectStatus = static_cast<long>(response.objectStatus);
        queryResult.nameStatus = static_cast<long>(response.nameStatus);
        queryResult.fileAttributes = static_cast<std::uint32_t>(response.fileAttributes);
        queryResult.allocationSize = static_cast<std::int64_t>(response.allocationSize);
        queryResult.endOfFile = static_cast<std::int64_t>(response.endOfFile);
        queryResult.creationTime = static_cast<std::int64_t>(response.creationTime);
        queryResult.lastAccessTime = static_cast<std::int64_t>(response.lastAccessTime);
        queryResult.lastWriteTime = static_cast<std::int64_t>(response.lastWriteTime);
        queryResult.changeTime = static_cast<std::int64_t>(response.changeTime);
        queryResult.fileObjectAddress = static_cast<std::uint64_t>(response.fileObjectAddress);
        queryResult.sectionObjectPointersAddress = static_cast<std::uint64_t>(response.sectionObjectPointersAddress);
        queryResult.dataSectionObjectAddress = static_cast<std::uint64_t>(response.dataSectionObjectAddress);
        queryResult.imageSectionObjectAddress = static_cast<std::uint64_t>(response.imageSectionObjectAddress);
        queryResult.ntPath = detail::readFixedString(response.ntPath, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS);
        queryResult.objectName = detail::readFixedString(response.objectName, KSWORD_ARK_FILE_INFO_OBJECT_NAME_MAX_CHARS);

        std::ostringstream stream;
        stream << "version=" << queryResult.version
            << ", status=" << queryResult.queryStatus
            << ", fields=0x" << std::hex << std::uppercase << queryResult.fieldFlags
            << ", openStatus=0x" << static_cast<unsigned long>(static_cast<std::uint32_t>(queryResult.openStatus))
            << ", basicStatus=0x" << static_cast<unsigned long>(static_cast<std::uint32_t>(queryResult.basicStatus))
            << ", standardStatus=0x" << static_cast<unsigned long>(static_cast<std::uint32_t>(queryResult.standardStatus))
            << std::dec << ", bytesReturned=" << queryResult.io.bytesReturned;
        queryResult.io.message = stream.str();
        return queryResult;
    }

    FileIntegrityResult DriverClient::setFileIntegrity(
        const std::wstring& ntPath,
        const bool isDirectory,
        const unsigned long integrityRid) const
    {
        // Input: NT path directly openable by the driver, directory flags, and Mandatory Label RID.
        // Processing: Wrap IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY; the R0 side calls ZwCreateFile and ZwSetSecurityObject.
        // Return: FileIntegrityResult. io.ok indicates communication success; status/lastStatus indicate the file security API result.
        FileIntegrityResult integrityResult{};
        if (ntPath.empty() || ntPath.size() >= KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS)
        {
            integrityResult.io.ok = false;
            integrityResult.io.win32Error = ERROR_INVALID_PARAMETER;
            integrityResult.io.message =
                "file-integrity path invalid, chars=" + std::to_string(ntPath.size());
            return integrityResult;
        }

        KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST request{};
        KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_FILE_INTEGRITY_PROTOCOL_VERSION;
        request.flags = KSWORD_ARK_FILE_INTEGRITY_FLAG_UI_CONFIRMED |
            (isDirectory ? KSWORD_ARK_FILE_INTEGRITY_FLAG_DIRECTORY : 0UL);
        request.integrityRid = integrityRid;
        request.pathLengthChars = static_cast<unsigned short>(ntPath.size());
        std::copy(ntPath.begin(), ntPath.end(), request.path);
        request.path[request.pathLengthChars] = L'\0';

        integrityResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!integrityResult.io.ok)
        {
            integrityResult.unsupported = detail::isUnsupportedIoctlError(integrityResult.io.win32Error);
            integrityResult.io.message = integrityResult.unsupported
                ? "IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY) failed, error=" +
                    std::to_string(integrityResult.io.win32Error);
            return integrityResult;
        }
        if (integrityResult.io.bytesReturned < sizeof(response))
        {
            integrityResult.io.ok = false;
            integrityResult.io.message =
                "file-integrity response too small, bytesReturned=" +
                std::to_string(integrityResult.io.bytesReturned);
            return integrityResult;
        }

        integrityResult.version = static_cast<std::uint32_t>(response.version);
        integrityResult.flags = static_cast<std::uint32_t>(response.flags);
        integrityResult.integrityRid = static_cast<std::uint32_t>(response.integrityRid);
        integrityResult.status = static_cast<std::uint32_t>(response.status);
        integrityResult.lastStatus = static_cast<long>(response.lastStatus);
        integrityResult.pathLengthChars = static_cast<std::uint32_t>(response.pathLengthChars);
        integrityResult.io.ntStatus = integrityResult.lastStatus;

        std::ostringstream stream;
        stream << "pathChars=" << integrityResult.pathLengthChars
            << ", directory=" << (isDirectory ? 1 : 0)
            << ", rid=0x" << std::hex << std::uppercase << integrityResult.integrityRid
            << std::dec << ", status=" << integrityResult.status
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(integrityResult.lastStatus)
            << std::dec << ", bytesReturned=" << integrityResult.io.bytesReturned;
        integrityResult.io.message = stream.str();
        return integrityResult;
    }

    IoResult DriverClient::deletePath(const std::wstring& ntPath, const bool isDirectory) const
    {
        DriverHandle handle = open();
        return deletePath(handle, ntPath, isDirectory);
    }

    IoResult DriverClient::deletePath(DriverHandle& handle, const std::wstring& ntPath, const bool isDirectory) const
    {
        if (ntPath.empty() || ntPath.size() >= KSWORD_ARK_DELETE_PATH_MAX_CHARS)
        {
            IoResult result{};
            result.ok = false;
            result.win32Error = ERROR_INVALID_PARAMETER;
            result.message = "path too long for ioctl, chars=" + std::to_string(ntPath.size());
            return result;
        }

        KSWORD_ARK_DELETE_PATH_REQUEST request{};
        request.flags = isDirectory ? KSWORD_ARK_DELETE_PATH_FLAG_DIRECTORY : 0UL;
        request.pathLengthChars = static_cast<unsigned short>(ntPath.size());
        std::copy(ntPath.begin(), ntPath.end(), request.path);
        request.path[request.pathLengthChars] = L'\0';

        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_DELETE_PATH,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0,
            &handle);

        std::ostringstream stream;
        stream << "pathChars=" << ntPath.size()
            << ", directory=" << (isDirectory ? 1 : 0)
            << ", bytesReturned=" << result.bytesReturned;
        stream << (result.ok ? ", ioctl=ok" : ", ioctl=fail, error=" + std::to_string(result.win32Error));
        result.message = stream.str();
        return result;
    }

    DeletePathResult DriverClient::deletePathEx(
        const std::wstring& ntPath,
        const bool isDirectory,
        const bool recursive,
        const bool continueOnError,
        const FileDeleteBackend backend) const
    {
        DriverHandle handle = open();
        return deletePathEx(handle, ntPath, isDirectory, recursive, continueOnError, backend);
    }

    DeletePathResult DriverClient::deletePathEx(
        DriverHandle& handle,
        const std::wstring& ntPath,
        const bool isDirectory,
        const bool recursive,
        const bool continueOnError,
        const FileDeleteBackend backend) const
    {
        // Input: NT path, directory flags, and recursion policy.
        // Processing: Send DELETE_PATH IOCTL with response; recursive expansion occurs entirely in R0.
        // Returns: DeletePathResult. io.ok indicates successful communication; response.deleteStatus indicates the deletion semantics.
        DeletePathResult deleteResult{};
        if (ntPath.empty() || ntPath.size() >= KSWORD_ARK_DELETE_PATH_MAX_CHARS)
        {
            deleteResult.io.ok = false;
            deleteResult.io.win32Error = ERROR_INVALID_PARAMETER;
            deleteResult.io.message = "path too long for ioctl, chars=" + std::to_string(ntPath.size());
            return deleteResult;
        }
        if (recursive && !isDirectory)
        {
            deleteResult.io.ok = false;
            deleteResult.io.win32Error = ERROR_INVALID_PARAMETER;
            deleteResult.io.message = "recursive delete requires a directory target";
            return deleteResult;
        }

        unsigned long backendFlag = 0UL;
        const char* backendName = "native";
        switch (backend)
        {
        case FileDeleteBackend::kNative:
            break;
        case FileDeleteBackend::kIrp:
            backendFlag = KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_IRP;
            backendName = "irp";
            break;
        case FileDeleteBackend::kPosix:
            backendFlag = KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_POSIX;
            backendName = "posix";
            break;
        default:
            deleteResult.io.ok = false;
            deleteResult.io.win32Error = ERROR_INVALID_PARAMETER;
            deleteResult.io.message = "unknown file delete backend";
            return deleteResult;
        }

        KSWORD_ARK_DELETE_PATH_REQUEST request{};
        request.flags = (isDirectory ? KSWORD_ARK_DELETE_PATH_FLAG_DIRECTORY : 0UL) |
            (recursive ? KSWORD_ARK_DELETE_PATH_FLAG_RECURSIVE : 0UL) |
            (continueOnError ? KSWORD_ARK_DELETE_PATH_FLAG_CONTINUE_ON_ERROR : 0UL) |
            backendFlag;
        request.pathLengthChars = static_cast<unsigned short>(ntPath.size());
        std::copy(ntPath.begin(), ntPath.end(), request.path);
        request.path[request.pathLengthChars] = L'\0';

        deleteResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_DELETE_PATH,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &deleteResult.response,
            static_cast<unsigned long>(sizeof(deleteResult.response)),
            &handle);

        if (!deleteResult.io.ok)
        {
            // Old drivers reject the entire packet if they do not recognize RECURSIVE/CONTINUE_ON_ERROR/BACKEND_*. Here, we must distinguish
            // between 'capability unavailable' and 'deletion actually failed'; otherwise, the UI cannot decide whether to fall back.
            deleteResult.unsupported =
                (recursive || continueOnError || backend != FileDeleteBackend::kNative) &&
                detail::isUnsupportedIoctlError(deleteResult.io.win32Error);
            std::ostringstream failStream;
            failStream << "pathChars=" << ntPath.size()
                << ", directory=" << (isDirectory ? 1 : 0)
                << ", recursive=" << (recursive ? 1 : 0)
                << ", backend=" << backendName
                << ", ioctl=fail, error=" << deleteResult.io.win32Error;
            if (deleteResult.unsupported)
            {
                failStream << ", reason=driver-does-not-support-delete-mode";
            }
            deleteResult.io.message = failStream.str();
            return deleteResult;
        }

        deleteResult.responseValid =
            deleteResult.io.bytesReturned >= sizeof(deleteResult.response) &&
            deleteResult.response.size == sizeof(deleteResult.response) &&
            deleteResult.response.version == KSWORD_ARK_DELETE_PATH_RESPONSE_VERSION;
        if (!deleteResult.responseValid)
        {
            // Even if an old driver deletes successfully, it won't fill in the response packet; this must be interpreted as 'completed single-item deletion'.
            deleteResult.response = KSWORD_ARK_DELETE_PATH_RESPONSE{};
            deleteResult.response.size = static_cast<unsigned long>(sizeof(deleteResult.response));
            deleteResult.response.version = KSWORD_ARK_DELETE_PATH_RESPONSE_VERSION;
            deleteResult.response.requestFlags = request.flags;
            deleteResult.response.deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED;
            deleteResult.response.visitedCount = 1UL;
            if (isDirectory)
            {
                deleteResult.response.deletedDirectoryCount = 1UL;
            }
            else
            {
                deleteResult.response.deletedFileCount = 1UL;
            }
        }

        std::ostringstream stream;
        stream << "pathChars=" << ntPath.size()
            << ", directory=" << (isDirectory ? 1 : 0)
            << ", recursive=" << (recursive ? 1 : 0)
            << ", backend=" << backendName
            << ", state=" << deleteResult.response.deleteStatus
            << ", files=" << deleteResult.response.deletedFileCount
            << ", dirs=" << deleteResult.response.deletedDirectoryCount
            << ", failed=" << deleteResult.response.failedCount
            << ", visited=" << deleteResult.response.visitedCount
            << ", depth=" << deleteResult.response.maxDepthReached
            << ", responseFlags=0x" << std::hex << std::uppercase << deleteResult.response.responseFlags
            << ", lastStatus=0x"
            << static_cast<unsigned long>(static_cast<std::uint32_t>(deleteResult.response.lastStatus))
            << std::dec << ", bytesReturned=" << deleteResult.io.bytesReturned
            << ", responsePacket=" << (deleteResult.responseValid ? 1 : 0);
        deleteResult.io.message = stream.str();
        return deleteResult;
    }

    IoResult DriverClient::controlFileMonitor(
        const unsigned long action,
        const unsigned long operationMask,
        const unsigned long processId,
        const unsigned long flags) const
    {
        // Purpose: Controls the Start/Stop/Clear state of the R0 filesystem minifilter.
        // Processing: Construct a shared protocol control packet, issuing IOCTLs exclusively through ArkDriverClient.
        // Returns: IoResult, appends action/mask/pid to message for application log localization.
        KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST request{};
        request.action = action;
        request.operationMask = operationMask;
        request.processId = processId;
        request.flags = flags;

        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);

        std::ostringstream stream;
        stream << "file-monitor control action=" << action
            << ", mask=0x" << std::hex << std::uppercase << operationMask
            << std::dec << ", pid=" << processId
            << ", flags=0x" << std::hex << std::uppercase << flags
            << std::dec << ", bytesReturned=" << result.bytesReturned;
        stream << (result.ok ? ", ioctl=ok" : ", ioctl=fail, error=" + std::to_string(result.win32Error));
        result.message = stream.str();
        return result;
    }

    FileMonitorStatusResult DriverClient::queryFileMonitorStatus() const
    {
        // Purpose: Query the registration, startup, and event queue status of the R0 file system minifilter.
        // Note: Parse KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE into a UI-friendly model.
        // Returns: FileMonitorStatusResult; on failure, io.ok=false and error information is preserved.
        FileMonitorStatusResult statusResult{};
        KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE response{};

        statusResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS,
            nullptr,
            0,
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!statusResult.io.ok)
        {
            statusResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS) failed, error=" +
                std::to_string(statusResult.io.win32Error);
            return statusResult;
        }
        if (statusResult.io.bytesReturned < sizeof(response))
        {
            statusResult.io.ok = false;
            statusResult.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            statusResult.io.message =
                "file-monitor status response too small, bytesReturned=" +
                std::to_string(statusResult.io.bytesReturned);
            return statusResult;
        }

        statusResult.version = static_cast<std::uint32_t>(response.version);
        statusResult.size = static_cast<std::uint32_t>(response.size);
        statusResult.runtimeFlags = static_cast<std::uint32_t>(response.runtimeFlags);
        statusResult.operationMask = static_cast<std::uint32_t>(response.operationMask);
        statusResult.processIdFilter = static_cast<std::uint32_t>(response.processIdFilter);
        statusResult.ringCapacity = static_cast<std::uint32_t>(response.ringCapacity);
        statusResult.queuedCount = static_cast<std::uint32_t>(response.queuedCount);
        statusResult.droppedCount = static_cast<std::uint32_t>(response.droppedCount);
        statusResult.sequence = static_cast<std::uint64_t>(response.sequence);
        statusResult.registerStatus = static_cast<long>(response.registerStatus);
        statusResult.startStatus = static_cast<long>(response.startStatus);
        statusResult.lastErrorStatus = static_cast<long>(response.lastErrorStatus);
        statusResult.io.ntStatus = statusResult.lastErrorStatus;

        std::ostringstream stream;
        stream << "file-monitor status flags=0x" << std::hex << std::uppercase << statusResult.runtimeFlags
            << ", mask=0x" << statusResult.operationMask
            << ", register=0x" << static_cast<unsigned long>(static_cast<std::uint32_t>(statusResult.registerStatus))
            << ", start=0x" << static_cast<unsigned long>(static_cast<std::uint32_t>(statusResult.startStatus))
            << ", last=0x" << static_cast<unsigned long>(static_cast<std::uint32_t>(statusResult.lastErrorStatus))
            << std::dec << ", queued=" << statusResult.queuedCount
            << ", dropped=" << statusResult.droppedCount
            << ", bytesReturned=" << statusResult.io.bytesReturned;
        statusResult.io.message = stream.str();
        return statusResult;
    }

    FileMonitorDrainResult DriverClient::drainFileMonitor(const unsigned long maxEvents, const unsigned long flags) const
    {
        FileMonitorDrainResult drainResult{};
        const unsigned long kRequestedEvents = (maxEvents == 0UL) ? 128UL : std::min<unsigned long>(maxEvents, 512UL);
        constexpr std::size_t kResponseHeaderBytes =
            sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE) - sizeof(KSWORD_ARK_FILE_MONITOR_EVENT);
        const std::size_t kOutputBytes =
            kResponseHeaderBytes + (static_cast<std::size_t>(kRequestedEvents) * sizeof(KSWORD_ARK_FILE_MONITOR_EVENT));

        KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST request{};
        request.maxEvents = kRequestedEvents;
        request.flags = flags;
        std::vector<unsigned char> outputBuffer(kOutputBytes);

        drainResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            outputBuffer.data(),
            static_cast<unsigned long>(outputBuffer.size()));
        if (!drainResult.io.ok)
        {
            drainResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN) failed, error=" +
                std::to_string(drainResult.io.win32Error);
            return drainResult;
        }
        if (drainResult.io.bytesReturned < kResponseHeaderBytes)
        {
            drainResult.io.ok = false;
            drainResult.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            drainResult.io.message =
                "file-monitor drain response too small, bytesReturned=" +
                std::to_string(drainResult.io.bytesReturned);
            return drainResult;
        }

        KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE responseHeader{};
        std::memcpy(&responseHeader, outputBuffer.data(), kResponseHeaderBytes);
        drainResult.version = static_cast<std::uint32_t>(responseHeader.version);
        drainResult.totalQueuedBeforeDrain = static_cast<std::uint32_t>(responseHeader.totalQueuedBeforeDrain);
        drainResult.returnedCount = static_cast<std::uint32_t>(responseHeader.returnedCount);
        drainResult.entrySize = static_cast<std::uint32_t>(responseHeader.entrySize);
        drainResult.droppedCount = static_cast<std::uint32_t>(responseHeader.droppedCount);
        drainResult.runtimeFlags = static_cast<std::uint32_t>(responseHeader.runtimeFlags);
        drainResult.ringCapacity = static_cast<std::uint32_t>(responseHeader.ringCapacity);

        if (drainResult.entrySize == 0U)
        {
            drainResult.io.ok = false;
            drainResult.io.win32Error = ERROR_INVALID_DATA;
            drainResult.io.message = "file-monitor drain entrySize is zero.";
            return drainResult;
        }

        const std::size_t kAvailableEventBytes = drainResult.io.bytesReturned - kResponseHeaderBytes;
        const std::size_t kAvailableEvents = kAvailableEventBytes / drainResult.entrySize;
        const std::size_t kEventsToParse = std::min<std::size_t>(
            static_cast<std::size_t>(drainResult.returnedCount),
            kAvailableEvents);
        const unsigned char* firstEntry = outputBuffer.data() + kResponseHeaderBytes;
        drainResult.events.reserve(kEventsToParse);
        for (std::size_t eventIndex = 0U; eventIndex < kEventsToParse; ++eventIndex)
        {
            drainResult.events.push_back(parseFileMonitorEventRow(
                firstEntry + (eventIndex * drainResult.entrySize),
                drainResult.entrySize));
        }

        std::ostringstream stream;
        stream << "file-monitor drain returned=" << drainResult.returnedCount
            << ", parsed=" << drainResult.events.size()
            << ", queuedBefore=" << drainResult.totalQueuedBeforeDrain
            << ", dropped=" << drainResult.droppedCount
            << ", entrySize=" << drainResult.entrySize
            << ", bytesReturned=" << drainResult.io.bytesReturned;
        drainResult.io.message = stream.str();
        return drainResult;
    }
}
