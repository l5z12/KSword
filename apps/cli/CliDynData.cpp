#include "CliSupport.h"

namespace ksword::cli
{
    // printV4ModuleIdentity renders DynData v4 module and PDB identity.
    // Inputs: v4 module packet from the shared protocol.
    // Processing: prints image identity first, then profile/PDB identity.
    // Returns: no value.
    void printV4ModuleIdentity(const KSW_DYN_V4_MODULE_IDENTITY_PACKET& module)
    {
        printModuleIdentity(L"image", module.image);
        std::wcout << L"    pdbName='" << fixedAnsiWide(module.pdb.pdbName, KSW_DYN_PDB_NAME_CHARS)
                   << L"' pdbGuid='" << fixedAnsiWide(module.pdb.pdbGuid, KSW_DYN_PDB_GUID_CHARS)
                   << L"' pdbAge=" << module.pdb.pdbAge
                   << L" profile='" << fixedAnsiWide(module.profileName, KSW_DYN_V4_PROFILE_NAME_CHARS) << L"'\n";
    }

    // queryDynV4Modules prints the applied multi-module profile state.
    // Inputs: parsed command options.
    // Processing: issues the read-only v4 modules IOCTL and bounds row output.
    // Returns: CLI exit code.
    int queryDynV4Modules(const NamedArgs& args)
    {
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int kRc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES",
            IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES,
            nullptr,
            0U,
            buffer,
            io);
        if (kRc != 0) return normalizeIoctlRc(L"dyn v4 modules", io, kRc);
        constexpr std::size_t kHeaderSize = KSW_QUERY_DYN_V4_MODULES_RESPONSE_HEADER_SIZE;
        const auto* response = reinterpret_cast<const KSW_QUERY_DYN_V4_MODULES_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSW_DYN_V4_MODULE_STATUS_ENTRY), L"dyn v4 modules"); }
        catch (...) { return 4; }
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 64U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSW_DYN_V4_MODULE_STATUS_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] moduleIndex=" << entry->moduleIndex
                       << L" statusFlags=0x" << std::hex << entry->statusFlags
                       << std::dec << L" itemCount=" << entry->itemCount
                       << L" groupCount=" << entry->capabilityGroupCount
                       << L" activeGroups=" << entry->activeCapabilityGroupCount
                       << L" missingRequired=" << entry->missingRequiredItemCount
                       << L" missingOptional=" << entry->missingOptionalItemCount << L"\n";
            printV4ModuleIdentity(entry->module);
        }
        return 0;
    }

    // queryDynV4CapabilityGroups prints v4 capability coverage rows.
    // Inputs: parsed command options.
    // Processing: reads active/required/optional counts per group.
    // Returns: CLI exit code.
    int queryDynV4CapabilityGroups(const NamedArgs& args)
    {
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int kRc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS",
            IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS,
            nullptr,
            0U,
            buffer,
            io);
        if (kRc != 0) return normalizeIoctlRc(L"dyn v4 capability groups", io, kRc);
        constexpr std::size_t kHeaderSize = KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE_HEADER_SIZE;
        const auto* response = reinterpret_cast<const KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY), L"dyn v4 capability groups"); }
        catch (...) { return 4; }
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] moduleClass=" << entry->moduleClassId
                       << L" groupId=" << entry->groupId
                       << L" statusFlags=0x" << std::hex << entry->statusFlags
                       << std::dec << L" required=" << entry->presentRequiredItemCount << L"/" << entry->requiredItemCount
                       << L" optional=" << entry->presentOptionalItemCount << L"/" << entry->optionalItemCount
                       << L" group='" << fixedAnsiWide(entry->groupName, KSW_DYN_V4_CAPABILITY_NAME_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryDynV4MissingItems prints required/optional item gaps.
    // Inputs: parsed command options.
    // Processing: queries missing item summaries and prints bounded rows.
    // Returns: CLI exit code.
    int queryDynV4MissingItems(const NamedArgs& args)
    {
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int kRc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS",
            IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS,
            nullptr,
            0U,
            buffer,
            io);
        if (kRc != 0) return normalizeIoctlRc(L"dyn v4 missing items", io, kRc);
        constexpr std::size_t kHeaderSize = KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE_HEADER_SIZE;
        const auto* response = reinterpret_cast<const KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSW_DYN_V4_MISSING_ITEM_ENTRY), L"dyn v4 missing items"); }
        catch (...) { return 4; }
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSW_DYN_V4_MISSING_ITEM_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] moduleClass=" << entry->moduleClassId
                       << L" itemId=" << entry->itemId
                       << L" kind=" << entry->itemKind
                       << L" groupId=" << entry->capabilityGroupId
                       << L" missingKind=" << entry->missingKind
                       << L" item='" << fixedAnsiWide(entry->itemName, KSW_DYN_V4_ITEM_NAME_CHARS)
                       << L"' reason='" << fixedAnsiWide(entry->reason, KSW_DYN_V4_MISSING_REASON_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryDynV4Items prints every applied DynData v4 item packet.
    // Inputs: parsed command options; --limit caps console output only.
    // Processing: issues IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS and renders the
    // module class, item identity, group membership, values and auxiliary words.
    // Returns: CLI exit code; old drivers are reported through normalizeIoctlRc.
    int queryDynV4Items(const NamedArgs& args)
    {
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int kRc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS",
            IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS,
            nullptr,
            0U,
            buffer,
            io);
        if (kRc != 0) return normalizeIoctlRc(L"dyn v4 items", io, kRc);
        constexpr std::size_t kHeaderSize = KSW_QUERY_DYN_V4_ITEMS_RESPONSE_HEADER_SIZE;
        const auto* response = reinterpret_cast<const KSW_QUERY_DYN_V4_ITEMS_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSW_DYN_V4_ITEM_STATUS_ENTRY), L"dyn v4 items"); }
        catch (...) { return 4; }
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 256U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSW_DYN_V4_ITEM_STATUS_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            const KSW_DYN_V4_ITEM_PACKET& item = entry->item;
            const std::uint64_t kValue64 =
                (static_cast<std::uint64_t>(item.valueHigh) << 32) |
                static_cast<std::uint64_t>(item.valueLow);
            std::wcout << L"  [" << i << L"] moduleClass=" << entry->moduleClassId
                       << L" itemIndex=" << entry->itemIndex
                       << L" itemId=" << item.itemId
                       << L" kind=" << item.itemKind
                       << L" groupId=" << item.capabilityGroupId
                       << L" flags=0x" << std::hex << item.flags
                       << L" valueLow=0x" << item.valueLow
                       << L" valueHigh=0x" << item.valueHigh
                       << L" value64=" << hex64(kValue64)
                       << L" aux=" << item.aux0 << L"/" << item.aux1 << L"/" << item.aux2 << L"/" << item.aux3
                       << std::dec << L"\n";
        }
        return 0;
    }

    // commandDynFamily implements DynData status, field and profile IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: handles fixed status/capability queries and raw profile blobs.
    // Returns: process exit code.
    int commandDynFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: dyn requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (kSub == L"status")
        {
            KSW_QUERY_DYN_STATUS_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_DYN_STATUS, L"IOCTL_KSWORD_ARK_QUERY_DYN_STATUS", response, io))
            {
                return normalizeIoctlRc(L"dyn status", io, 3);
            }
            printResponseBanner(response.version, response.statusFlags, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" systemInformerDataVersion=" << response.systemInformerDataVersion
                       << L" systemInformerDataLength=" << response.systemInformerDataLength
                       << L" matchedProfileClass=" << response.matchedProfileClass
                       << L" matchedProfileOffset=" << response.matchedProfileOffset
                       << L" matchedFieldsId=" << response.matchedFieldsId
                       << L" fieldCount=" << response.fieldCount
                       << L" capabilityMask=0x" << std::hex << response.capabilityMask << std::dec << L"\n";
            printModuleIdentity(L"ntoskrnl", response.ntoskrnl);
            printModuleIdentity(L"lxcore", response.lxcore);
            dumpWideText(L"unavailableReason", fixedWide(response.unavailableReason, KSW_DYN_REASON_CHARS));
            return 0;
        }
        if (kSub == L"fields")
        {
            std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS", IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS, nullptr, 0U, buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"dyn fields", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSW_QUERY_DYN_FIELDS_RESPONSE) - sizeof(KSW_DYN_FIELD_ENTRY);
            const auto* response = reinterpret_cast<const KSW_QUERY_DYN_FIELDS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSW_DYN_FIELD_ENTRY), L"dyn fields"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSW_DYN_FIELD_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] id=" << entry->fieldId
                           << L" flags=0x" << std::hex << entry->flags
                           << L" source=" << std::dec << entry->source
                           << L" offset=0x" << std::hex << entry->offset
                           << L" capabilityMask=0x" << entry->capabilityMask
                           << std::dec << L" field='" << fixedAnsiWide(entry->fieldName, KSW_DYN_FIELD_NAME_CHARS)
                           << L"' sourceName='" << fixedAnsiWide(entry->sourceName, KSW_DYN_FIELD_SOURCE_CHARS)
                           << L"' feature='" << fixedAnsiWide(entry->featureName, KSW_DYN_FIELD_FEATURE_CHARS) << L"'\n";
            }
            return 0;
        }
        if (kSub == L"capabilities")
        {
            KSW_QUERY_CAPABILITIES_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_CAPABILITIES, L"IOCTL_KSWORD_ARK_QUERY_CAPABILITIES", response, io))
            {
                return normalizeIoctlRc(L"dyn capabilities", io, 3);
            }
            printResponseBanner(response.version, response.statusFlags, 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" capabilityMask=0x" << std::hex << response.capabilityMask
                       << std::dec << L" reserved=" << response.reserved << L"\n";
            return 0;
        }
        if (kSub == L"profile" || kSub == L"v4-modules")
        {
            return queryDynV4Modules(kArgs);
        }
        if (kSub == L"v4-capabilities" || kSub == L"capability-groups")
        {
            return queryDynV4CapabilityGroups(kArgs);
        }
        if (kSub == L"v4-missing" || kSub == L"missing-items")
        {
            return queryDynV4MissingItems(kArgs);
        }
        if (kSub == L"v4-items")
        {
            return queryDynV4Items(kArgs);
        }
        if (kSub == L"apply-profile-v4")
        {
            // apply-profile-v4 purpose:
            // - Input: --blob points to the raw KSW_APPLY_DYN_PROFILE_V4_REQUEST packet generated later by the PDB extractor;
            // - Processing: CLI pass-through only; do not redefine protocol fields or guess offsets in user mode.
            // - Return: Print driver-side validation/application summary; return unsupported/unavailable stably when the old driver lacks the IOCTL.
            const std::size_t kMaxBytes =
                KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE +
                (static_cast<std::size_t>(KSW_DYN_V4_MAX_ITEMS_PER_MODULE) * sizeof(KSW_DYN_V4_ITEM_PACKET));
            std::vector<std::uint8_t> blob = readRequiredBlobOption(kArgs, L"--blob", kMaxBytes);
            KSW_APPLY_DYN_PROFILE_V4_RESPONSE response{};
            // This IOCTL requires FILE_WRITE_ACCESS: opening the device with only GENERIC_READ causes the I/O
            // manager to return ACCESS_DENIED before the handler is invoked, so this subcommand will always fail.
            // Use default READ|WRITE, consistent with the adjacent apply-profile / apply-profile-ex.
            if (!sendBlobFixedResponse(
                    IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4,
                    L"IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4",
                    blob,
                    response,
                    io))
            {
                if (isUnsupportedTransportError(io.win32Error))
                {
                    return commandUnsupported(L"dyn apply-profile-v4", L"driver does not expose IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4");
                }
                return 3;
            }
            printResponseBanner(response.version, static_cast<std::uint32_t>(response.status), response.status, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" statusFlags=0x" << std::hex << response.statusFlags
                       << std::dec << L" appliedItemCount=" << response.appliedItemCount
                       << L" rejectedItemCount=" << response.rejectedItemCount
                       << L" required=" << response.presentRequiredItemCount << L"/" << response.requiredItemCount
                       << L" optional=" << response.presentOptionalItemCount << L"/" << response.optionalItemCount
                       << L" activeCapabilityGroupCount=" << response.activeCapabilityGroupCount
                       << L" missingRequired=" << response.missingRequiredItemCount
                       << L" missingOptional=" << response.missingOptionalItemCount << L"\n";
            printV4ModuleIdentity(response.module);
            dumpWideText(L"message", fixedWide(response.message, KSW_DYN_REASON_CHARS));
            return 0;
        }
        if (kSub == L"apply-profile")
        {
            const std::size_t kMaxBytes = KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE + (static_cast<std::size_t>(KSW_DYN_PROFILE_MAX_FIELDS) * sizeof(KSW_DYN_PROFILE_FIELD_PACKET));
            std::vector<std::uint8_t> blob = readRequiredBlobOption(kArgs, L"--blob", kMaxBytes);
            KSW_APPLY_DYN_PROFILE_RESPONSE response{};
            if (!sendBlobFixedResponse(IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE, L"IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE", blob, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, static_cast<std::uint32_t>(response.status), 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" appliedFieldCount=" << response.appliedFieldCount
                       << L" rejectedFieldCount=" << response.rejectedFieldCount
                       << L" unknownFieldCount=" << response.unknownFieldCount
                       << L" statusFlags=0x" << std::hex << response.statusFlags
                       << L" capabilityMask=0x" << response.capabilityMask << std::dec << L"\n";
            dumpWideText(L"message", fixedWide(response.message, KSW_DYN_REASON_CHARS));
            return 0;
        }
        if (kSub == L"apply-profile-ex")
        {
            const std::size_t kMaxBytes = KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE + (static_cast<std::size_t>(KSW_DYN_PROFILE_EX_MAX_ITEMS) * sizeof(KSW_DYN_PROFILE_EX_ITEM_PACKET));
            std::vector<std::uint8_t> blob = readRequiredBlobOption(kArgs, L"--blob", kMaxBytes);
            KSW_APPLY_DYN_PROFILE_EX_RESPONSE response{};
            if (!sendBlobFixedResponse(IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX, L"IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX", blob, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, static_cast<std::uint32_t>(response.status), 0, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" appliedItemCount=" << response.appliedItemCount
                       << L" rejectedItemCount=" << response.rejectedItemCount
                       << L" unknownItemCount=" << response.unknownItemCount
                       << L" statusFlags=0x" << std::hex << response.statusFlags
                       << L" capabilityMask=0x" << response.capabilityMask << std::dec << L"\n";
            dumpWideText(L"message", fixedWide(response.message, KSW_DYN_REASON_CHARS));
            return 0;
        }
        std::wcerr << L"error: unknown dyn subcommand '" << kSub << L"'\n";
        return 1;
    }

    // commandCapabilityFamily implements the unified driver capability query.
    // Inputs: argc/argv from wmain.
    // Processing: parses a variable response containing feature rows.
    // Returns: process exit code.
    int commandCapabilityFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: capability requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub != L"query-driver-capabilities")
        {
            std::wcerr << L"error: unknown capability subcommand '" << kSub << L"'\n";
            return 1;
        }

        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES", IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES, nullptr, 0U, buffer, io);
        if (kRc != 0) return kRc;
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE) - sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY), L"driver capabilities"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->statusFlags, response->lastErrorStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalFeatureCount, response->returnedFeatureCount, response->entrySize, io.bytesReturned);
        std::wcout << L"size=" << response->size
                   << L" driverProtocolVersion=0x" << std::hex << response->driverProtocolVersion
                   << L" securityPolicyFlags=0x" << response->securityPolicyFlags
                   << L" dynDataStatusFlags=0x" << response->dynDataStatusFlags
                   << L" dynDataCapabilityMask=0x" << response->dynDataCapabilityMask
                   << std::dec << L" lastErrorSource='" << fixedAnsiWide(response->lastErrorSource, KSWORD_ARK_CAPABILITY_ERROR_SOURCE_CHARS)
                   << L"' lastErrorSummary='" << fixedAnsiWide(response->lastErrorSummary, KSWORD_ARK_CAPABILITY_ERROR_SUMMARY_CHARS) << L"'\n";
        const std::size_t kParsed = responseCountLimit(response->returnedFeatureCount, available, getOptionU32(kArgs, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSWORD_ARK_FEATURE_CAPABILITY_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] featureId=" << entry->featureId
                       << L" state=" << entry->state
                       << L" flags=0x" << std::hex << entry->flags
                       << L" requiredPolicy=0x" << entry->requiredPolicyFlags
                       << L" deniedPolicy=0x" << entry->deniedPolicyFlags
                       << L" requiredDyn=0x" << entry->requiredDynDataMask
                       << L" presentDyn=0x" << entry->presentDynDataMask
                       << std::dec << L" feature='" << fixedAnsiWide(entry->featureName, KSWORD_ARK_CAPABILITY_NAME_CHARS)
                       << L"' stateName='" << fixedAnsiWide(entry->stateName, KSWORD_ARK_CAPABILITY_STATE_CHARS)
                       << L"' reason='" << fixedAnsiWide(entry->reasonText, KSWORD_ARK_CAPABILITY_REASON_CHARS) << L"'\n";
        }
        return 0;
    }
}
