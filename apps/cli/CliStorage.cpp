#include "CliSupport.h"

namespace ksword::cli
{
    // printFileInfoResponse renders the fixed file-info response.
    // Inputs: response struct and bytesReturned.
    // Processing: prints status, timestamps and optional names.
    // Returns: no value.
    void printFileInfoResponse(const KSWORD_ARK_QUERY_FILE_INFO_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.queryStatus, response.basicStatus, bytesReturned);
        std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                   << L" open=0x" << static_cast<unsigned long>(response.openStatus)
                   << L" object=0x" << static_cast<unsigned long>(response.objectStatus)
                   << L" name=0x" << static_cast<unsigned long>(response.nameStatus)
                   << L" attrs=0x" << response.fileAttributes
                   << L" fileObject=" << hex64(response.fileObjectAddress)
                   << L" sectionPointers=" << hex64(response.sectionObjectPointersAddress)
                   << L" dataSection=" << hex64(response.dataSectionObjectAddress)
                   << L" imageSection=" << hex64(response.imageSectionObjectAddress)
                   << std::dec << L" allocationSize=" << response.allocationSize
                   << L" endOfFile=" << response.endOfFile << L"\n";
        dumpWideText(L"ntPath", fixedWide(response.ntPath, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS));
        dumpWideText(L"objectName", fixedWide(response.objectName, KSWORD_ARK_FILE_INFO_OBJECT_NAME_MAX_CHARS));
    }

    // queryMinifilterInventory issues the read-only fltMgr public inventory IOCTL.
    // Inputs: parsed options for flags/max rows/visible row limit.
    // Processing: validates the variable response and prints filter/volume rows.
    // Returns: CLI exit code, including graceful unavailable status for old drivers.
    int queryMinifilterInventory(const NamedArgs& args)
    {
        KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_FILTER_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL);
        request.maxRows = getOptionU32(args, L"--max-rows", 256U);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY", IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"file minifilter", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY), L"minifilter inventory"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"size=" << response->size << L" flags=0x" << std::hex << response->flags << std::dec << L"\n";
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] status=" << row->status
                       << L" fields=0x" << std::hex << row->fieldFlags
                       << L" source=0x" << row->sourceFlags
                       << L" filter=" << hex64(row->filterObject)
                       << L" volume=" << hex64(row->volumeObject)
                       << std::dec << L" instances=" << row->instanceCount
                       << L" volumeInstances=" << row->volumeBindingInstanceCount
                       << L" frameId=" << row->frameId
                       << L" name='" << fixedWide(row->filterName, KSWORD_ARK_MINIFILTER_INVENTORY_NAME_CHARS)
                       << L"' altitude='" << fixedWide(row->altitude, KSWORD_ARK_MINIFILTER_INVENTORY_ALTITUDE_CHARS)
                       << L"' volumeName='" << fixedWide(row->volumeName, KSWORD_ARK_MINIFILTER_INVENTORY_VOLUME_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // buildStorageRequest normalizes common storage audit CLI options.
    // Inputs: parsed args and optional --volume path text.
    // Processing: fills protocol version, flags, row/depth limits and fixed path.
    // Returns: request packet ready for a read-only storage IOCTL.
    KSWORD_ARK_STORAGE_AUDIT_REQUEST buildStorageRequest(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request{};
        request.version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT);
        request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS);
        request.maxDepth = getOptionU32(args, L"--max-depth", KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH);
        if (const std::wstring* volume = getOptionText(args, L"--volume"))
        {
            request.volumePathLengthChars = boundedPathLength(*volume, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS);
            copyWideToFixed(request.volumePath, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS, *volume);
        }
        return request;
    }

    // queryVolumeStackAudit prints R0 volume/device-stack audit rows.
    // Inputs: parsed storage options.
    // Processing: uses the read-only volume stack IOCTL and prints bounded rows.
    // Returns: CLI exit code.
    int queryVolumeStackAudit(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT", IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"storage volume stack", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE) - sizeof(KSWORD_ARK_VOLUME_STACK_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->rowSize, sizeof(KSWORD_ARK_VOLUME_STACK_ROW), L"volume stack"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
        std::wcout << L"fieldFlags=0x" << std::hex << response->fieldFlags
                   << std::dec << L" fvevolPresent=" << response->fvevolPresent
                   << L" fvevolPosition=" << response->fvevolPosition << L"\n";
        const std::size_t kParsed = responseCountLimit(response->returnedRows, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_VOLUME_STACK_ROW*>(buffer.data() + kHeaderSize + (i * response->rowSize));
            std::wcout << L"  [" << i << L"] stackIndex=" << row->stackIndex
                       << L" deviceType=0x" << std::hex << row->deviceType
                       << L" fields=0x" << row->fieldFlags
                       << L" risk=0x" << row->riskFlags
                       << L" device=" << hex64(row->deviceObjectAddress)
                       << L" driverObject=" << hex64(row->driverObjectAddress)
                       << L" attached=" << hex64(row->attachedDeviceAddress)
                       << std::dec << L" confidence=" << row->confidence
                       << L" driver='" << fixedWide(row->driverName, KSWORD_ARK_STORAGE_DRIVER_NAME_CHARS)
                       << L"' volume='" << fixedWide(row->volumeDeviceName, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryBitlockerAudit prints safe BitLocker/FVE status rows only.
    // Inputs: parsed storage options.
    // Processing: never serializes key material; it only renders protocol labels.
    // Returns: CLI exit code.
    int queryBitlockerAudit(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT", IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"file bitlocker", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE) - sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->rowSize, sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW), L"bitlocker fve"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedRows, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_BITLOCKER_FVE_ROW*>(buffer.data() + kHeaderSize + (i * response->rowSize));
            std::wcout << L"  [" << i << L"] fields=0x" << std::hex << row->fieldFlags
                       << L" risk=0x" << row->riskFlags
                       << std::dec << L" fvevolPresent=" << row->fvevolPresent
                       << L" fvevolPosition=" << row->fvevolStackPosition
                       << L" protection=" << row->protectionStatus
                       << L" conversion=" << row->conversionStatus
                       << L" lock=" << row->lockStatus
                       << L" confidence=" << row->confidence
                       << L" volume='" << fixedWide(row->volumeDeviceName, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryMountMgrAudit prints drive-letter and Volume GUID cross-view rows.
    // Inputs: parsed storage options.
    // Processing: renders only symbolic mapping evidence.
    // Returns: CLI exit code.
    int queryMountMgrAudit(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT", IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"storage mountmgr", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE) - sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->rowSize, sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW), L"mountmgr mapping"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedRows, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_MOUNTMGR_MAPPING_ROW*>(buffer.data() + kHeaderSize + (i * response->rowSize));
            std::wcout << L"  [" << i << L"] fields=0x" << std::hex << row->fieldFlags
                       << L" risk=0x" << row->riskFlags
                       << std::dec << L" confidence=" << row->confidence
                       << L" drive='" << fixedWide(row->driveLetter, KSWORD_ARK_STORAGE_DRIVE_LETTER_CHARS)
                       << L"' guid='" << fixedWide(row->volumeGuid, KSWORD_ARK_STORAGE_VOLUME_GUID_CHARS)
                       << L"' nt='" << fixedWide(row->ntDevicePath, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryFilesystemIntegrityAudit prints FS dispatch/FastIo owner evidence.
    // Inputs: parsed storage options.
    // Processing: emits read-only driver/slot/risk rows.
    // Returns: CLI exit code.
    int queryFilesystemIntegrityAudit(const NamedArgs& args)
    {
        KSWORD_ARK_STORAGE_AUDIT_REQUEST request = buildStorageRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT", IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"file storage filesystem integrity", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->rowSize, sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW), L"filesystem integrity"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedRows, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW*>(buffer.data() + kHeaderSize + (i * response->rowSize));
            std::wcout << L"  [" << i << L"] fs=" << row->fileSystemKind
                       << L" slotType=" << row->slotType
                       << L" slotIndex=" << row->slotIndex
                       << L" risk=0x" << std::hex << row->riskFlags
                       << L" driverObject=" << hex64(row->driverObjectAddress)
                       << L" target=" << hex64(row->targetAddress)
                       << L" ownerBase=" << hex64(row->ownerModuleBase)
                       << std::dec << L" confidence=" << row->confidence
                       << L" driver='" << fixedWide(row->driverName, KSWORD_ARK_STORAGE_DRIVER_NAME_CHARS)
                       << L"' owner='" << fixedWide(row->ownerModuleName, KSWORD_ARK_STORAGE_MODULE_NAME_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }
}
