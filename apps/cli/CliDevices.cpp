#include "CliSupport.h"

namespace ksword::cli
{
    // queryDeviceAudit prints device/input/USB/GPU audit rows.
    // Inputs: parsed args plus protocol code/profile and labels.
    // Processing: sends a read-only request and renders bounded device evidence rows.
    // Returns: CLI exit code.
    int queryDeviceAudit(const NamedArgs& args, DWORD code, unsigned long profileFlags, const wchar_t* ioctlLabel, const wchar_t* featureLabel)
    {
        KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION;
        request.profileFlags = getOptionU32(args, L"--profile-flags", profileFlags);
        request.maxRows = getOptionU32(args, L"--max-rows", KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS);
        request.maxAttachedDepth = getOptionU32(args, L"--max-attached", KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH);
        copyOptionalWideOption(args, L"--target", request.targetName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(ioctlLabel, code, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(featureLabel, io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE) - sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY), featureLabel); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"profileFlags=0x" << std::hex << response->profileFlags
                   << L" responseFlags=0x" << response->responseFlags
                   << std::dec << L" targetCount=" << response->targetCount
                   << L" driverCount=" << response->driverCount
                   << L" deviceCount=" << response->deviceCount << L"\n";
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_DEVICE_AUDIT_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] kind=" << row->rowKind
                       << L" role=" << row->roleHint
                       << L" status=" << row->status
                       << L" risk=0x" << std::hex << row->riskFlags
                       << L" driverObject=" << hex64(row->driverObjectAddress)
                       << L" deviceObject=" << hex64(row->deviceObjectAddress)
                       << L" attached=" << hex64(row->attachedDeviceAddress)
                       << L" next=" << hex64(row->nextDeviceObjectAddress)
                       << std::dec << L" confidence=" << row->confidence
                       << L" depth=" << row->relationDepth
                       << L" attachedDepth=" << row->attachedDepth
                       << L" driver='" << fixedWide(row->driverName, KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS)
                       << L"' service='" << fixedWide(row->serviceName, KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS)
                       << L"' device='" << fixedWide(row->deviceName, KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_DEVICE_AUDIT_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // commandKeyboardFamily implements keyboard hotkey and hook enumeration.
    // Inputs: argc/argv from wmain.
    // Processing: prints bounded row lists and diagnostic offsets.
    // Returns: process exit code.
    int commandKeyboardFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: keyboard requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (kSub == L"enum-hotkeys" || kSub == L"enum-hooks")
        {
            KSWORD_ARK_ENUM_KEYBOARD_REQUEST request{};
            request.version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_ALL);
            request.processId = getOptionU32(kArgs, L"--pid", 0U);
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", 256U);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            if (kSub == L"enum-hotkeys")
            {
                const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS", IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS, &request, sizeof(request), buffer, io);
                if (kRc != 0) return kRc;
                constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY);
                const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE*>(buffer.data());
                std::size_t available = 0U;
                try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY), L"keyboard hotkeys"); }
                catch (...) { return 4; }
                printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
                printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
                std::wcout << L"win32kBase=" << hex64(response->win32kBase)
                           << L" sessionGlobals=" << hex64(response->sessionGlobals)
                           << L" tableOffset=" << response->tableOffset
                           << L" hotkeyNextOffset=" << response->hotkeyNextOffset
                           << L" hotkeyModifiersOffset=" << response->hotkeyModifiersOffset
                           << L" hotkeyVkOffset=" << response->hotkeyVkOffset
                           << L" hotkeyIdOffset=" << response->hotkeyIdOffset << L"\n";
                const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
                for (std::size_t i = 0; i < kParsed; ++i)
                {
                    const auto* entry = reinterpret_cast<const KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                    std::wcout << L"  [" << i << L"] source=" << entry->source
                               << L" status=" << entry->status
                               << L" flags=0x" << std::hex << entry->flags
                               << L" bucket=" << entry->bucketIndex
                               << L" depth=" << entry->depth
                               << L" modifiers=0x" << entry->modifiers
                               << L" modifiers2=0x" << entry->modifierFlags2
                               << L" vk=" << std::dec << entry->virtualKey
                               << L" id=" << entry->hotkeyId
                               << L" pid=" << entry->processId
                               << L" tid=" << entry->threadId
                               << L" last=0x" << std::hex << static_cast<unsigned long>(entry->lastStatus)
                               << std::dec << L" detail='" << fixedWide(entry->detail, KSWORD_ARK_KEYBOARD_DETAIL_CHARS) << L"'\n";
                }
                return 0;
            }
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS", IOCTL_KSWORD_ARK_ENUM_KEYBOARD_HOOKS, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY), L"keyboard hooks"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"win32kBase=" << hex64(response->win32kBase)
                       << L" threadHookArrayOffset=" << response->threadHookArrayOffset
                       << L" desktopInfoOffset=" << response->desktopInfoOffset
                       << L" desktopHookArrayOffset=" << response->desktopHookArrayOffset
                       << L" hookNextOffset=" << response->hookNextOffset
                       << L" hookTypeOffset=" << response->hookTypeOffset
                       << L" hookProcedureOffset=" << response->hookProcedureOffset
                       << L" hookFlagsOffset=" << response->hookFlagsOffset
                       << L" hookModuleIdOffset=" << response->hookModuleIdOffset
                       << L" hookTargetThreadInfoOffset=" << response->hookTargetThreadInfoOffset << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_KEYBOARD_HOOK_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] source=" << entry->source
                           << L" status=" << entry->status
                           << L" flags=0x" << std::hex << entry->flags
                           << L" type=" << entry->hookType
                           << L" scope=" << entry->hookScope
                           << L" pid=" << std::dec << entry->processId
                           << L" tid=" << entry->threadId
                           << L" moduleId=" << entry->moduleId
                           << L" last=0x" << std::hex << static_cast<unsigned long>(entry->lastStatus)
                           << L" hook=" << hex64(entry->hookObject)
                           << L" proc=" << hex64(entry->procedureAddress)
                           << std::dec << L" detail='" << fixedWide(entry->detail, KSWORD_ARK_KEYBOARD_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }
        std::wcerr << L"error: unknown keyboard subcommand '" << kSub << L"'\n";
        return 1;
    }

    // commandHardwareFamily exposes input/USB/PnP/GPU device audit commands.
    // Inputs: argc/argv from wmain.
    // Processing: routes to read-only device audit IOCTLs where present.
    // Returns: process exit code.
    int commandHardwareFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: hardware requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub == L"audit" || kSub == L"pnp")
        {
            return queryDeviceAudit(kArgs, IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK, L"IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT", L"hardware audit");
        }
        if (kSub == L"input")
        {
            return queryDeviceAudit(kArgs, IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK, L"IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT", L"hardware input");
        }
        if (kSub == L"usb")
        {
            return queryDeviceAudit(kArgs, IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY, L"IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT", L"hardware usb");
        }
        std::wcerr << L"error: unknown hardware subcommand '" << kSub << L"'\n";
        return 1;
    }

    // parseHwidDispatchAction converts action names into shared HWID constants.
    // Inputs: --action text or numeric token.
    // Processing: accepts query/enable/disable/disable-all and decimal/hex values.
    // Returns: KSWORD_ARK_HWID_DISPATCH_ACTION_* value.
    std::uint32_t parseHwidDispatchAction(const std::wstring& text)
    {
        const std::wstring kLowered = lowerWide(text);
        if (kLowered == L"query") return KSWORD_ARK_HWID_DISPATCH_ACTION_QUERY;
        if (kLowered == L"enable") return KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE;
        if (kLowered == L"disable") return KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE;
        if (kLowered == L"disable-all" || kLowered == L"disableall") return KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL;
        return parseU32(text.c_str(), "hwid action");
    }

    // addHwidTargetToken ORs one target token into a HWID target mask.
    // Inputs: token and mutable mask.
    // Processing: recognizes individual target and group names.
    // Returns: no value; throws on unknown target names.
    void addHwidTargetToken(const std::wstring& token, std::uint32_t& flags)
    {
        const std::wstring kLowered = lowerWide(token);
        if (kLowered.empty()) return;
        if (kLowered == L"disk") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_DISK; return; }
        if (kLowered == L"partmgr" || kLowered == L"partition") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR; return; }
        if (kLowered == L"mountmgr" || kLowered == L"volume") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR; return; }
        if (kLowered == L"nvidia" || kLowered == L"gpu") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA; return; }
        if (kLowered == L"nsiproxy" || kLowered == L"nsi" || kLowered == L"network") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_NETWORK; return; }
        if (kLowered == L"storage") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_STORAGE; return; }
        if (kLowered == L"all") { flags |= KSWORD_ARK_HWID_DISPATCH_TARGET_ALL; return; }
        flags |= parseU32(token.c_str(), "hwid target");
    }

    // parseHwidTargetFlags parses --targets into a target mask.
    // Inputs: parsed args.
    // Processing: accepts comma/semicolon/pipe/space separated target names.
    // Returns: target mask; storage is the default to match the main UI defaults.
    std::uint32_t parseHwidTargetFlags(const NamedArgs& args)
    {
        const std::wstring* text = getOptionText(args, L"--targets");
        if (text == nullptr || text->empty())
        {
            return KSWORD_ARK_HWID_DISPATCH_TARGET_STORAGE;
        }
        std::uint32_t flags = 0U;
        std::wstring token;
        const auto kFlush = [&]()
        {
            addHwidTargetToken(token, flags);
            token.clear();
        };
        for (const wchar_t kCh : *text)
        {
            if (kCh == L',' || kCh == L';' || kCh == L'|' || std::iswspace(kCh) != 0)
            {
                kFlush();
                continue;
            }
            token.push_back(kCh);
        }
        kFlush();
        return flags;
    }

    // parseHwidDiskMode maps disk mode text to protocol constants.
    // Inputs: optional --disk-mode value.
    // Processing: accepts custom/random/null or numeric values.
    // Returns: protocol disk mode.
    std::uint32_t parseHwidDiskMode(const NamedArgs& args)
    {
        const std::wstring* text = getOptionText(args, L"--disk-mode");
        if (text == nullptr || text->empty()) return KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM;
        const std::wstring kLowered = lowerWide(*text);
        if (kLowered == L"custom") return KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM;
        if (kLowered == L"random") return KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM;
        if (kLowered == L"null" || kLowered == L"empty") return KSWORD_ARK_HWID_DISPATCH_DISK_MODE_NULL;
        return parseU32(text->c_str(), "hwid disk mode");
    }

    // parseHwidMacMode maps MAC mode text to protocol constants.
    // Inputs: optional --mac-mode value.
    // Processing: accepts random/custom or numeric values.
    // Returns: protocol MAC mode.
    std::uint32_t parseHwidMacMode(const NamedArgs& args)
    {
        const std::wstring* text = getOptionText(args, L"--mac-mode");
        if (text == nullptr || text->empty()) return KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM;
        const std::wstring kLowered = lowerWide(*text);
        if (kLowered == L"random") return KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM;
        if (kLowered == L"custom") return KSWORD_ARK_HWID_DISPATCH_MAC_MODE_CUSTOM;
        return parseU32(text->c_str(), "hwid mac mode");
    }

    // printHwidDispatchResponse renders HWID Dispatch state/control packets.
    // Inputs: response packet and bytesReturned.
    // Processing: prints summary, active profile and per-target dispatch rows.
    // Returns: no value.
    void printHwidDispatchResponse(const KSWORD_ARK_HWID_DISPATCH_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.overallStatus, response.lastStatus, bytesReturned);
        std::wcout << L"responseFlags=0x" << std::hex << response.responseFlags
                   << L" supported=0x" << response.supportedTargetFlags
                   << L" requested=0x" << response.requestedTargetFlags
                   << L" active=0x" << response.activeTargetFlags
                   << L" failed=0x" << response.failedTargetFlags
                   << L" generation=0x" << response.generation
                   << std::dec << L"\n";
        const KSWORD_ARK_HWID_DISPATCH_PROFILE& profile = response.activeProfile;
        std::wcout << L"profile targetFlags=0x" << std::hex << profile.targetFlags
                   << L" behaviorFlags=0x" << profile.behaviorFlags
                   << std::dec << L" diskMode=" << profile.diskMode
                   << L" macMode=" << profile.macMode << L"\n";
        dumpWideText(L"diskSerial", fixedWide(profile.diskSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"diskProduct", fixedWide(profile.diskProduct, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"diskRevision", fixedWide(profile.diskRevision, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"gpuSerial", fixedWide(profile.gpuSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"permanentMac", fixedWide(profile.permanentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        dumpWideText(L"currentMac", fixedWide(profile.currentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS));
        for (std::size_t index = 0U; index < KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT; ++index)
        {
            const KSWORD_ARK_HWID_DISPATCH_ENTRY& entry = response.entries[index];
            std::wcout << L"  [" << index << L"] target=0x" << std::hex << entry.targetFlag
                       << L" driverObject=" << hex64(entry.driverObjectAddress)
                       << L" original=" << hex64(entry.originalDispatchAddress)
                       << L" current=" << hex64(entry.currentDispatchAddress)
                       << L" lastStatus=0x" << static_cast<unsigned long>(entry.lastStatus)
                       << std::dec << L" active=" << entry.active
                       << L" driver='" << fixedWide(entry.driverName, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS) << L"'\n";
        }
    }

    // commandHwidFamily exposes HWID Dispatch query/control IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: routes fixed query and guarded control requests.
    // Returns: process exit code.
    int commandHwidFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: hwid requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (kSub == L"dispatch-query")
        {
            KSWORD_ARK_HWID_DISPATCH_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY, L"IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY", response, io))
            {
                return normalizeIoctlRc(L"hwid dispatch-query", io, 3);
            }
            printHwidDispatchResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"dispatch-control")
        {
            KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST request{};
            KSWORD_ARK_HWID_DISPATCH_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
            request.action = parseHwidDispatchAction(requireOptionText(kArgs, L"--action"));
            if (request.action != KSWORD_ARK_HWID_DISPATCH_ACTION_QUERY)
            {
                requireConfirmOption(kArgs, "hwid dispatch-control requires --confirm");
            }
            if (getOptionBool(kArgs, L"--confirm"))
            {
                request.requestFlags |= KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_UI_CONFIRMED;
            }
            if (getOptionBool(kArgs, L"--dry-run"))
            {
                request.requestFlags |= KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_DRY_RUN;
            }
            request.profile.size = sizeof(request.profile);
            request.profile.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
            request.profile.targetFlags = parseHwidTargetFlags(kArgs);
            request.profile.behaviorFlags = getOptionU32(kArgs, L"--flags", 0U);
            request.profile.diskMode = parseHwidDiskMode(kArgs);
            request.profile.macMode = parseHwidMacMode(kArgs);
            copyOptionalWideOption(kArgs, L"--disk-serial", request.profile.diskSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(kArgs, L"--disk-product", request.profile.diskProduct, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(kArgs, L"--disk-revision", request.profile.diskRevision, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(kArgs, L"--gpu-serial", request.profile.gpuSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(kArgs, L"--permanent-mac", request.profile.permanentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            copyOptionalWideOption(kArgs, L"--current-mac", request.profile.currentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
            if (!sendFixedRequestResponse(
                    IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL,
                    L"IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL",
                    request,
                    response,
                    io,
                    GENERIC_READ | GENERIC_WRITE))
            {
                return normalizeIoctlRc(L"hwid dispatch-control", io, 3);
            }
            printHwidDispatchResponse(response, io.bytesReturned);
            return 0;
        }
        std::wcerr << L"error: unknown hwid subcommand '" << kSub << L"'\n";
        return 1;
    }
}
