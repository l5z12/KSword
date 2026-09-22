#include "CliSupport.h"

namespace ksword::cli
{
    // buildNetworkAuditRequest fills the common bounded network audit request.
    // Inputs: parsed args with optional flags/max rows.
    // Processing: uses conservative protocol defaults and never requests mutation.
    // Returns: fixed query request for network endpoint/WFP/NDIS IOCTLs.
    KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST buildNetworkAuditRequest(const NamedArgs& args)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL);
        request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS);
        return request;
    }

    // networkAuditStatusText: Converts network audit protocol status to a stable CLI token.
    // Input: KSWORD_ARK_NETWORK_STATUS_* defined in shared/driver.
    // Processing: Mark unknown values separately to avoid misreporting DeviceIoControl success as R0 availability.
    // Returns: English status name suitable for script parsing.
    const wchar_t* networkAuditStatusText(const unsigned long status)
    {
        switch (status)
        {
        case KSWORD_ARK_NETWORK_STATUS_APPLIED: return L"applied";
        case KSWORD_ARK_NETWORK_STATUS_CLEARED: return L"cleared";
        case KSWORD_ARK_NETWORK_STATUS_DISABLED: return L"disabled";
        case KSWORD_ARK_NETWORK_STATUS_INVALID_RULE: return L"invalid-rule";
        case KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE: return L"wfp-unavailable";
        case KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED: return L"operation-failed";
        case KSWORD_ARK_NETWORK_STATUS_AUDIT_UNAVAILABLE: return L"audit-unavailable";
        case KSWORD_ARK_NETWORK_STATUS_AUDIT_STUB: return L"audit-stub";
        case KSWORD_ARK_NETWORK_STATUS_UNKNOWN:
        default:
            return L"unknown";
        }
    }

    // isRetainableNetworkInventoryPartial purpose: identify WFP/NDIS partial snapshots that can be retained.
    // Input: Protocol status, lastStatus, and returned row count.
    // Note: Only accept OPERATION_FAILED + PARTIAL_COPY/BUFFER_OVERFLOW + non-zero rows.
    // Returns: true indicates the CLI can output these valid lines, but they must be explicitly marked as partial.
    bool isRetainableNetworkInventoryPartial(
        const unsigned long status,
        const long lastStatus,
        const unsigned long returnedRows) noexcept
    {
        const std::uint32_t kNormalizedStatus =
            static_cast<std::uint32_t>(lastStatus);
        return status == KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED &&
            returnedRows != 0UL &&
            (kNormalizedStatus == kNetworkStatusPartialCopy ||
             kNormalizedStatus == kNetworkStatusBufferOverflow);
    }

    // validateNetworkAuditHeader: Validate the semantics of the shared response header for TCP/UDP/WFP/NDIS.
    // Input: response header fields, actual returned byte count, fixed header size, and command tag.
    // Processing: Validate version, size, status, source bit, count, and budget; reject corrupted or mismatched driver data.
    // Returns: true indicates that validateVariable can subsequently be called to parse detail lines.
    bool validateNetworkAuditHeader(
        const unsigned long version,
        const unsigned long size,
        const unsigned long status,
        const unsigned long flags,
        const unsigned long totalRows,
        const unsigned long returnedRows,
        const unsigned long sourceFlags,
        const unsigned long budgetRows,
        const DWORD bytesReturned,
        const std::size_t headerSize,
        const wchar_t* featureLabel)
    {
        constexpr unsigned long kKnownSourceFlags =
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
        const bool kValid =
            version == KSWORD_ARK_NETWORK_PROTOCOL_VERSION &&
            size == headerSize &&
            size <= bytesReturned &&
            status <= KSWORD_ARK_NETWORK_STATUS_AUDIT_STUB &&
            (flags & ~KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL) == 0UL &&
            (sourceFlags & ~kKnownSourceFlags) == 0UL &&
            returnedRows <= totalRows &&
            (budgetRows == 0UL || returnedRows <= budgetRows);
        if (!kValid)
        {
            std::wcerr << featureLabel
                       << L": invalid network audit response"
                       << L" version=" << version
                       << L" size=" << size
                       << L" status=" << status
                       << L" flags=0x" << std::hex << flags
                       << L" sourceFlags=0x" << sourceFlags
                       << std::dec << L" total=" << totalRows
                       << L" returned=" << returnedRows
                       << L" budgetRows=" << budgetRows
                       << L" bytesReturned=" << bytesReturned << L"\n";
        }
        return kValid;
    }

    // printNetworkAuditState: Outputs R0 availability and the explicit reason for degradation.
    // Input: Protocol status, NTSTATUS, source, budget, generation, count, and partial acceptance status.
    // Handling: Mark APPLIED or protocol-recognized partial lines as usableR0=1, and list complete/truncated separately.
    // Returns: Nothing.
    void printNetworkAuditState(
        const unsigned long status,
        const long lastStatus,
        const unsigned long sourceFlags,
        const unsigned long budgetRows,
        const unsigned long generation,
        const unsigned long totalRows,
        const unsigned long returnedRows,
        const bool partialRowsAccepted)
    {
        const bool kComplete =
            status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            totalRows == returnedRows;
        const bool kAppliedTruncated =
            status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            totalRows > returnedRows;
        const bool kRowsUsable =
            status == KSWORD_ARK_NETWORK_STATUS_APPLIED ||
            partialRowsAccepted;
        const bool kPartial = partialRowsAccepted || kAppliedTruncated;
        const bool kTruncated = kRowsUsable &&
            (totalRows > returnedRows ||
             (partialRowsAccepted &&
              static_cast<std::uint32_t>(lastStatus) ==
                  kNetworkStatusBufferOverflow));
        const wchar_t* scopeText = L"pdb/private";
        if (sourceFlags == KSWORD_ARK_NETWORK_AUDIT_SOURCE_NONE)
        {
            scopeText = L"none";
        }
        else if (sourceFlags == KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE)
        {
            scopeText = L"runtime-state-only";
        }
        std::wcout << L"evidence=R0-header"
                   << L" usableR0=" << (kRowsUsable ? 1 : 0)
                   << L" completeR0=" << (kComplete ? 1 : 0)
                   << L" partial=" << (kPartial ? 1 : 0)
                   << L" truncated=" << (kTruncated ? 1 : 0)
                   << L" retainedRows=" << (kRowsUsable ? returnedRows : 0UL)
                   << L" protocolStatus=" << networkAuditStatusText(status)
                   << L"(" << status << L")"
                   << L" scope=" << scopeText
                   << L" lastStatus=0x" << std::hex << static_cast<unsigned long>(lastStatus)
                   << L" sourceFlags=0x" << sourceFlags
                   << std::dec << L" budgetRows=" << budgetRows
                   << L" generation=" << generation << L"\n";
    }

    // networkAuditAddressToText purpose: Format IPv4/IPv6 addresses in the R0 endpoint entry.
    // Input: Shared protocol address family and fixed 16-byte address.
    // Processing: Call only documented InetNtopW; do not read any private network structures.
    // Returns: address text that can be directly concatenated with the host byte-order port.
    std::wstring networkAuditAddressToText(
        const unsigned long addressFamily,
        const unsigned char addressBytes[16])
    {
        wchar_t addressText[INET6_ADDRSTRLEN]{};
        if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4)
        {
            IN_ADDR address{};
            std::memcpy(&address, addressBytes, sizeof(address));
            return ::InetNtopW(AF_INET, &address, addressText, static_cast<DWORD>(std::size(addressText))) != nullptr
                ? std::wstring(addressText)
                : std::wstring(L"<invalid-ipv4>");
        }
        if (addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6)
        {
            IN6_ADDR address{};
            std::memcpy(&address, addressBytes, sizeof(address));
            return ::InetNtopW(AF_INET6, &address, addressText, static_cast<DWORD>(std::size(addressText))) != nullptr
                ? std::wstring(addressText)
                : std::wstring(L"<invalid-ipv6>");
        }
        return L"<unknown-address-family>";
    }

    // networkNdisObjectKindText: Converts NDIS line type to an auditable token.
    // UNKNOWN is a valid degraded evidence when the collector cannot prove object boundaries; it must not be falsely claimed as a miniport/LWF.
    const wchar_t* networkNdisObjectKindText(const unsigned long kind)
    {
        switch (kind)
        {
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN: return L"unknown-unproven";
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT: return L"miniport";
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_FILTER: return L"filter";
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_PROTOCOL: return L"protocol";
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING: return L"binding";
        default: return L"invalid";
        }
    }

    // networkWfpObjectKindText purpose: Convert WFP row types into stable, auditable tokens.
    const wchar_t* networkWfpObjectKindText(const unsigned long kind)
    {
        switch (kind)
        {
        case KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER: return L"provider";
        case KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER: return L"sublayer";
        case KSWORD_ARK_NETWORK_WFP_OBJECT_FILTER: return L"filter";
        case KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT: return L"callout";
        default: return L"invalid";
        }
    }

    // queryNetworkEndpoints prints TCP or UDP R0 endpoint audit rows.
    // Inputs: parsed args plus IOCTL code and display labels.
    // Processing: validates variable response rows and renders endpoint evidence.
    // Returns: CLI exit code.
    int queryNetworkEndpoints(const NamedArgs& args, DWORD code, const wchar_t* ioctlLabel, const wchar_t* featureLabel)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkAuditRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(ioctlLabel, code, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(featureLabel, io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*>(buffer.data());
        if (!validateNetworkAuditHeader(
            response->version,
            response->size,
            response->status,
            response->flags,
            response->totalRowCount,
            response->returnedRowCount,
            response->sourceFlags,
            response->budgetRows,
            io.bytesReturned,
            kHeaderSize,
            featureLabel))
        {
            return 4;
        }
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW), featureLabel); }
        catch (...) { return 4; }
        if (available < response->returnedRowCount)
        {
            std::wcerr << featureLabel << L": returned rows exceed response bytes\n";
            return 4;
        }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRowCount, response->returnedRowCount, response->entrySize, io.bytesReturned);
        printNetworkAuditState(
            response->status,
            response->lastStatus,
            response->sourceFlags,
            response->budgetRows,
            response->generation,
            response->totalRowCount,
            response->returnedRowCount,
            false);
        if (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED)
        {
            std::wcerr
                << L"unsupported / unavailable: "
                << featureLabel
                << L" did not return an APPLIED endpoint snapshot\n";
            return 5;
        }
        const std::size_t kParsed = responseCountLimit(response->returnedRowCount, available, getOptionU32(args, L"--limit", 128U));
        const unsigned long kExpectedProtocol =
            code == IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS
            ? KSWORD_ARK_NETWORK_PROTOCOL_TCP
            : KSWORD_ARK_NETWORK_PROTOCOL_UDP;
        constexpr unsigned long kKnownRowFlags =
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
        constexpr unsigned long kKnownSourceFlags =
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
        for (std::size_t i = 0; i < response->returnedRowCount; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_NETWORK_ENDPOINT_ROW*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            const bool kKnownFamily =
                row->addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN ||
                row->addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4 ||
                row->addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6;
            if (!kKnownFamily ||
                row->protocol != kExpectedProtocol ||
                (row->flags & ~kKnownRowFlags) != 0UL ||
                (row->sourceFlags & ~kKnownSourceFlags) != 0UL)
            {
                std::wcerr << featureLabel << L": invalid endpoint row at index " << i << L"\n";
                return 4;
            }
            if (i >= kParsed)
            {
                continue;
            }
            std::wcout << L"  [" << i << L"] rowId=" << row->rowId
                       << L" af=" << row->addressFamily
                       << L" proto=" << row->protocol
                       << L" state=" << row->state
                       << L" pid=" << row->owningPid
                       << L" local=" << networkAuditAddressToText(row->addressFamily, row->localAddress) << L":" << row->localPort
                       << L" remote=" << networkAuditAddressToText(row->addressFamily, row->remoteAddress) << L":" << row->remotePort
                       << L" compartment=" << row->compartmentId
                       << L" ifIndex=" << row->interfaceIndex
                       << L" flags=0x" << std::hex << row->flags
                       << L" source=0x" << row->sourceFlags
                       << L" fieldMask=0x" << row->fieldMask
                       << L" endpoint=" << hex64(row->endpointObject)
                       << L" processObject=" << hex64(row->owningProcessObject)
                       << L" transport=" << hex64(row->transportObject)
                       << L" interfaceLuid=" << hex64(row->interfaceLuid)
                       << std::dec << L"\n";
        }
        return 0;
    }

    // queryNetworkWfp prints WFP provider/filter/callout inventory rows.
    // Inputs: parsed network options.
    // Processing: supports audit-stub responses without treating them as crashes.
    // Returns: CLI exit code.
    int queryNetworkWfp(const NamedArgs& args)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkAuditRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY", IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"network wfp", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE*>(buffer.data());
        if (!validateNetworkAuditHeader(
            response->version,
            response->size,
            response->status,
            response->flags,
            response->totalRowCount,
            response->returnedRowCount,
            response->sourceFlags,
            response->budgetRows,
            io.bytesReturned,
            kHeaderSize,
            L"network wfp"))
        {
            return 4;
        }
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW), L"network wfp"); }
        catch (...) { return 4; }
        if (available < response->returnedRowCount)
        {
            std::wcerr << L"network wfp: returned rows exceed response bytes\n";
            return 4;
        }
        const bool kPartialRowsAccepted =
            isRetainableNetworkInventoryPartial(
                response->status,
                response->lastStatus,
                response->returnedRowCount);
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRowCount, response->returnedRowCount, response->entrySize, io.bytesReturned);
        printNetworkAuditState(
            response->status,
            response->lastStatus,
            response->sourceFlags,
            response->budgetRows,
            response->generation,
            response->totalRowCount,
            response->returnedRowCount,
            kPartialRowsAccepted);
        if (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            !kPartialRowsAccepted)
        {
            std::wcerr
                << L"unsupported / unavailable: network wfp returned no retainable partial snapshot\n";
            return 5;
        }
        const std::size_t kParsed = responseCountLimit(response->returnedRowCount, available, getOptionU32(args, L"--limit", 128U));
        constexpr unsigned long kKnownRowFlags =
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
        for (std::size_t i = 0; i < response->returnedRowCount; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            if (row->objectKind < KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER ||
                row->objectKind > KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT ||
                (row->flags & ~kKnownRowFlags) != 0UL)
            {
                std::wcerr << L"network wfp: invalid row at index " << i << L"\n";
                return 4;
            }
            if (i >= kParsed)
            {
                continue;
            }
            std::wcout << L"  [" << i << L"] rowId=" << row->rowId
                       << L" kind=" << networkWfpObjectKindText(row->objectKind)
                       << L"(" << row->objectKind << L")"
                       << L" layer=" << row->layerId
                       << L" calloutId=" << row->calloutId
                       << L" filterId=" << row->filterId
                       << L" classify=" << hex64(row->classifyAddress)
                       << L" notify=" << hex64(row->notifyAddress)
                       << L" flowDelete=" << hex64(row->flowDeleteAddress)
                       << L" ownerBase=" << hex64(row->ownerImageBase)
                       << L" owner='" << fixedWide(row->ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryNetworkNdis prints NDIS miniport/filter/protocol/binding rows.
    // Inputs: parsed network options.
    // Processing: renders object graph hints without changing bindings.
    // Returns: CLI exit code.
    int queryNetworkNdis(const NamedArgs& args)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkAuditRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN", IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"network ndis", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW);
        const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE*>(buffer.data());
        if (!validateNetworkAuditHeader(
            response->version,
            response->size,
            response->status,
            response->flags,
            response->totalRowCount,
            response->returnedRowCount,
            response->sourceFlags,
            response->budgetRows,
            io.bytesReturned,
            kHeaderSize,
            L"network ndis"))
        {
            return 4;
        }
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW), L"network ndis"); }
        catch (...) { return 4; }
        if (available < response->returnedRowCount)
        {
            std::wcerr << L"network ndis: returned rows exceed response bytes\n";
            return 4;
        }
        const bool kPartialRowsAccepted =
            isRetainableNetworkInventoryPartial(
                response->status,
                response->lastStatus,
                response->returnedRowCount);
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalRowCount, response->returnedRowCount, response->entrySize, io.bytesReturned);
        printNetworkAuditState(
            response->status,
            response->lastStatus,
            response->sourceFlags,
            response->budgetRows,
            response->generation,
            response->totalRowCount,
            response->returnedRowCount,
            kPartialRowsAccepted);
        if (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            !kPartialRowsAccepted)
        {
            std::wcerr
                << L"unsupported / unavailable: network ndis returned no retainable partial snapshot\n";
            return 5;
        }
        const std::size_t kParsed = responseCountLimit(response->returnedRowCount, available, getOptionU32(args, L"--limit", 128U));
        constexpr unsigned long kKnownRowFlags =
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
            KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
        for (std::size_t i = 0; i < response->returnedRowCount; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            if (row->objectKind > KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING ||
                (row->flags & ~kKnownRowFlags) != 0UL)
            {
                std::wcerr << L"network ndis: invalid row at index " << i << L"\n";
                return 4;
            }
            if (i >= kParsed)
            {
                continue;
            }
            std::wcout << L"  [" << i << L"] rowId=" << row->rowId
                       << L" kind=" << networkNdisObjectKindText(row->objectKind)
                       << L"(" << row->objectKind << L")"
                       << L" ifIndex=" << row->ifIndex
                       << L" order=" << row->filterOrder
                       << L" object=" << hex64(row->objectAddress)
                       << L" parent=" << hex64(row->parentObjectAddress)
                       << L" driverObject=" << hex64(row->driverObject)
                       << L" imageBase=" << hex64(row->imageBase)
                       << L" component='" << fixedWide(row->componentName, KSWORD_ARK_NETWORK_NAME_CHARS)
                       << L"' owner='" << fixedWide(row->ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // ipv4AddressToText: Converts an IPv4 address returned by IP Helper to a wide-character string.
    // Input: address is an IPv4 address from the MIB_* table, preserving the byte order returned by the system API.
    // Processing: Call InetNtopW; on failure, output a placeholder diagnostic to prevent CLI crashes.
    // Returns: An IPv4 text string ready for printing.
    std::wstring ipv4AddressToText(const DWORD address)
    {
        IN_ADDR inAddress{};
        inAddress.S_un.S_addr = address;

        wchar_t addressText[INET_ADDRSTRLEN]{};
        if (::InetNtopW(AF_INET, &inAddress, addressText, static_cast<DWORD>(sizeof(addressText) / sizeof(addressText[0]))) == nullptr)
        {
            return L"<invalid-ipv4>";
        }
        return addressText;
    }

    // ipv6AddressToText: Converts an IPv6 address returned by IP Helper to a wide-character string.
    // Input: addressBytes points to a 16-byte IPv6 address, scopeId is the interface scope.
    // Processing: Format the address and append %scope when scopeId exists to facilitate locating link-local addresses.
    // Returns: An IPv6 text string ready for printing.
    std::wstring ipv6AddressToText(const UCHAR addressBytes[16], const DWORD scopeId)
    {
        IN6_ADDR inAddress{};
        std::memcpy(&inAddress, addressBytes, sizeof(inAddress));

        wchar_t addressText[INET6_ADDRSTRLEN]{};
        if (::InetNtopW(AF_INET6, &inAddress, addressText, static_cast<DWORD>(sizeof(addressText) / sizeof(addressText[0]))) == nullptr)
        {
            return L"<invalid-ipv6>";
        }

        std::wostringstream stream;
        stream << addressText;
        if (scopeId != 0U)
        {
            stream << L"%" << scopeId;
        }
        return stream.str();
    }

    // networkPortToHost: Converts network byte-order ports from the IP Helper table to host byte-order.
    // Input: portValue is a port field stored as DWORD.
    // Note: Truncate to the lower 16 bits and call ntohs.
    // Returns: Readable port number.
    std::uint16_t networkPortToHost(const DWORD portValue)
    {
        return ntohs(static_cast<u_short>(portValue));
    }

    // printAfdTcp4Fallback: Prints IPv4 TCP owner rows for AFD fallback.
    // Input: limit is the maximum number of output rows; printedRows is a reference to the cumulative count of printed rows.
    // Handling: GetExtendedTcpTable reads only the owner PID table without accessing R0 AFD private structures.
    // Return: Win32 status code; ERROR_SUCCESS indicates successful enumeration or no rows.
    DWORD printAfdTcp4Fallback(const std::size_t limit, std::size_t& printedRows)
    {
        ULONG bufferBytes = 0U;
        DWORD status = ::GetExtendedTcpTable(
            nullptr,
            &bufferBytes,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0U);
        if (status != ERROR_INSUFFICIENT_BUFFER || bufferBytes == 0U)
        {
            return status;
        }

        std::vector<std::uint8_t> buffer(bufferBytes, 0U);
        status = ::GetExtendedTcpTable(
            buffer.data(),
            &bufferBytes,
            FALSE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0U);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }

        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD rowIndex = 0U; rowIndex < table->dwNumEntries && printedRows < limit; ++rowIndex)
        {
            const MIB_TCPROW_OWNER_PID& row = table->table[rowIndex];
            std::wcout << L"  afd-fallback[tcp4][" << printedRows << L"] pid=" << row.dwOwningPid
                       << L" local=" << ipv4AddressToText(row.dwLocalAddr) << L":" << networkPortToHost(row.dwLocalPort)
                       << L" remote=" << ipv4AddressToText(row.dwRemoteAddr) << L":" << networkPortToHost(row.dwRemotePort)
                       << L" state=" << row.dwState
                       << L" source=GetExtendedTcpTable\n";
            ++printedRows;
        }
        return ERROR_SUCCESS;
    }

    // printAfdUdp4Fallback: Prints IPv4 UDP owner rows for AFD fallback.
    // Input: limit is the maximum number of output rows; printedRows is a reference to the cumulative count of printed rows.
    // Processing: GetExtendedUdpTable reads-only the UDP owner PID table.
    // Return: Win32 status code.
    DWORD printAfdUdp4Fallback(const std::size_t limit, std::size_t& printedRows)
    {
        ULONG bufferBytes = 0U;
        DWORD status = ::GetExtendedUdpTable(
            nullptr,
            &bufferBytes,
            FALSE,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0U);
        if (status != ERROR_INSUFFICIENT_BUFFER || bufferBytes == 0U)
        {
            return status;
        }

        std::vector<std::uint8_t> buffer(bufferBytes, 0U);
        status = ::GetExtendedUdpTable(
            buffer.data(),
            &bufferBytes,
            FALSE,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0U);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }

        const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
        for (DWORD rowIndex = 0U; rowIndex < table->dwNumEntries && printedRows < limit; ++rowIndex)
        {
            const MIB_UDPROW_OWNER_PID& row = table->table[rowIndex];
            std::wcout << L"  afd-fallback[udp4][" << printedRows << L"] pid=" << row.dwOwningPid
                       << L" local=" << ipv4AddressToText(row.dwLocalAddr) << L":" << networkPortToHost(row.dwLocalPort)
                       << L" source=GetExtendedUdpTable\n";
            ++printedRows;
        }
        return ERROR_SUCCESS;
    }

    // commandNetworkAfdFallback purpose: Provides read-only fallback evidence for network afd.
    // Input: CLI arguments, supporting --limit to control the number of printed lines.
    // Processing: explicitly declare no dedicated R0 IOCTL, and use the documented IP Helper owner table to present approximate AFD evidence.
    // Return: 0 indicates the fallback query completed successfully; non-zero indicates the system API is unavailable or failed.
    int commandNetworkAfdFallback(const NamedArgs& args)
    {
        const std::size_t kLimit = getOptionU32(args, L"--limit", 128U);
        std::size_t printedRows = 0U;

        std::wcout << L"network afd: degraded fallback\n"
                   << L"status=degraded unsupportedR0=1 reason='no dedicated AFD audit IOCTL is present in shared protocol'\n"
                   << L"source=R3 documented IP Helper owner PID tables\n";

        const DWORD kTcp4Status = printAfdTcp4Fallback(kLimit, printedRows);
        const DWORD kUdp4Status = printAfdUdp4Fallback(kLimit, printedRows);

        std::wcout << L"summary rows=" << printedRows
                   << L" limit=" << kLimit
                   << L" tcp4Status=" << kTcp4Status
                   << L" udp4Status=" << kUdp4Status
                   << L" ipv6OwnerPid='covered by network nsi fallback; SDK hides MIB_*6_OWNER_PID in this build context'\n";

        if (kTcp4Status != ERROR_SUCCESS && kUdp4Status != ERROR_SUCCESS)
        {
            std::wcerr << L"unsupported / unavailable: network afd fallback APIs failed\n";
            return 5;
        }
        return 0;
    }

    // socketAddressToText purpose: Format the SOCKET_ADDRESS from GetAdaptersAddresses.
    // Input: socketAddress is the raw socket address in the adapter address node.
    // Processing: Convert based on AF_INET/AF_INET6 branches; return diagnostic text for unknown address families.
    // Return: printable address text.
    std::wstring socketAddressToText(const SOCKET_ADDRESS& socketAddress)
    {
        if (socketAddress.lpSockaddr == nullptr)
        {
            return L"<null-address>";
        }
        if (socketAddress.lpSockaddr->sa_family == AF_INET)
        {
            const auto* ipv4 = reinterpret_cast<const SOCKADDR_IN*>(socketAddress.lpSockaddr);
            return ipv4AddressToText(ipv4->sin_addr.S_un.S_addr);
        }
        if (socketAddress.lpSockaddr->sa_family == AF_INET6)
        {
            const auto* ipv6 = reinterpret_cast<const SOCKADDR_IN6*>(socketAddress.lpSockaddr);
            return ipv6AddressToText(ipv6->sin6_addr.u.Byte, ipv6->sin6_scope_id);
        }
        return L"<unsupported-address-family>";
    }

    // commandNetworkNsiFallback purpose: Provides read-only fallback evidence for network nsi.
    // Input: CLI arguments, supporting --limit to control the number of unicast addresses printed.
    // Handling: Use GetAdaptersAddresses to project interface/address status, replacing the missing dedicated NSI R0 IOCTL.
    // Return: 0 indicates the fallback query completed successfully; non-zero indicates the system API is unavailable or failed.
    int commandNetworkNsiFallback(const NamedArgs& args)
    {
        const std::size_t kLimit = getOptionU32(args, L"--limit", 128U);
        ULONG bufferBytes = 16U * 1024U;
        std::vector<std::uint8_t> buffer(bufferBytes, 0U);
        constexpr ULONG kQueryFlags =
            GAA_FLAG_INCLUDE_PREFIX |
            GAA_FLAG_INCLUDE_GATEWAYS |
            GAA_FLAG_INCLUDE_ALL_INTERFACES;

        DWORD status = ::GetAdaptersAddresses(AF_UNSPEC, kQueryFlags, nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferBytes);
        if (status == ERROR_BUFFER_OVERFLOW)
        {
            buffer.assign(bufferBytes, 0U);
            status = ::GetAdaptersAddresses(AF_UNSPEC, kQueryFlags, nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferBytes);
        }

        std::wcout << L"network nsi: degraded fallback\n"
                   << L"status=degraded unsupportedR0=1 reason='no dedicated NSI audit IOCTL is present in shared protocol'\n"
                   << L"source=R3 documented GetAdaptersAddresses interface projection\n";

        if (status != ERROR_SUCCESS)
        {
            std::wcerr << L"unsupported / unavailable: GetAdaptersAddresses failed, win32=" << status
                       << L" (0x" << std::hex << status << std::dec << L")\n";
            return 5;
        }

        std::size_t adapterCount = 0U;
        std::size_t printedAdapterCount = 0U;
        std::size_t addressCount = 0U;
        const auto* adapter = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data());
        for (; adapter != nullptr; adapter = adapter->Next)
        {
            ++adapterCount;
            if (printedAdapterCount >= kLimit)
            {
                continue;
            }
            std::wcout << L"  nsi-adapter[" << (adapterCount - 1U) << L"] ifIndex=" << adapter->IfIndex
                       << L" ipv6IfIndex=" << adapter->Ipv6IfIndex
                       << L" operStatus=" << adapter->OperStatus
                       << L" ifType=" << adapter->IfType
                       << L" mtu=" << adapter->Mtu
                       << L" name='" << (adapter->FriendlyName != nullptr ? adapter->FriendlyName : L"")
                       << L"' description='" << (adapter->Description != nullptr ? adapter->Description : L"")
                       << L"'\n";
            ++printedAdapterCount;

            const IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
            for (; unicast != nullptr && addressCount < kLimit; unicast = unicast->Next)
            {
                std::wcout << L"    nsi-unicast[" << addressCount << L"] address="
                           << socketAddressToText(unicast->Address)
                           << L" prefixLength=" << static_cast<unsigned int>(unicast->OnLinkPrefixLength)
                           << L" dadState=" << unicast->DadState
                           << L" validLifetime=" << unicast->ValidLifetime
                           << L" preferredLifetime=" << unicast->PreferredLifetime
                           << L"\n";
                ++addressCount;
            }
        }

        std::wcout << L"summary adapters=" << adapterCount
                   << L" printedAdapters=" << printedAdapterCount
                   << L" addresses=" << addressCount
                   << L" limit=" << kLimit
                   << L" truncated=" << ((adapterCount > printedAdapterCount || addressCount >= kLimit) ? 1U : 0U) << L"\n";
        return 0;
    }
}
