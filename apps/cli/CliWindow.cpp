#include "CliSupport.h"

namespace ksword::cli
{
    // buildWin32kRequest fills common win32k audit query fields.
    // Inputs: parsed args for session/pid/tid/limits.
    // Processing: keeps request bounded and current-session by default.
    // Returns: fixed win32k query request.
    KSWORD_ARK_WIN32K_QUERY_REQUEST buildWin32kRequest(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL);
        request.sessionId = getOptionU32(args, L"--session-id", 0U);
        request.processId = getOptionU32(args, L"--pid", 0U);
        request.threadId = getOptionU32(args, L"--tid", 0U);
        request.maxEntries = getOptionU32(args, L"--max-entries", KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES);
        return request;
    }

    // applyMessageHookMatchOption maps the readable --match option onto the
    // shared owner/target selector bits without disturbing other --flags bits.
    // Inputs: parsed arguments and the flags produced by buildWin32kRequest.
    // Processing: validates legacy|owner|target|both case-insensitively.
    // Returns: flags with only the selector mask replaced when --match exists.
    std::uint32_t applyMessageHookMatchOption(
        const NamedArgs& args,
        std::uint32_t flags)
    {
        const std::wstring* option = getOptionText(args, L"--match");
        if (option == nullptr)
        {
            return flags;
        }

        const std::wstring kMode = lowerWide(*option);
        flags &= ~KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK;
        if (kMode == L"legacy")
        {
            return flags;
        }
        if (kMode == L"owner")
        {
            return flags | KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER;
        }
        if (kMode == L"target")
        {
            return flags | KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET;
        }
        if (kMode == L"both")
        {
            return flags | KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK;
        }
        throw std::invalid_argument(
            "invalid --match value (expected legacy, owner, target, or both)");
    }

    // messageHookMatchName renders the effective selector bits returned by R0.
    // Inputs: response/request flags.
    // Processing: ignores all flags outside the shared selector mask.
    // Returns: a stable CLI label for diagnostics and scripts.
    const wchar_t* messageHookMatchName(const std::uint32_t flags)
    {
        switch (flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK)
        {
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_OWNER:
            return L"owner";
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_TARGET:
            return L"target";
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_QUERY_FLAG_MATCH_MASK:
            return L"both";
        default:
            return L"legacy";
        }
    }

    // queryWin32kProfileStatus prints module/profile/session readiness.
    // Inputs: parsed window options.
    // Processing: validates the variable session row response.
    // Returns: CLI exit code.
    int queryWin32kProfileStatus(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS", IOCTL_KSWORD_ARK_QUERY_WIN32K_PROFILE_STATUS, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"window win32k", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_PROFILE_STATUS_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_SESSION_ENTRY), L"win32k profile"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"capability=0x" << std::hex << response->capabilityMask
                   << L" missing=0x" << response->missingCapabilityMask
                   << L" userGetSiloGlobals=" << hex64(response->userGetSiloGlobals)
                   << std::dec << L"\n";
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 64U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_SESSION_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] session=" << row->sessionId
                       << L" status=" << row->status
                       << L" processCount=" << row->processCount
                       << L" guiThreadCount=" << row->guiThreadCount
                       << L" representativePid=" << row->representativeProcessId
                       << L" representativeTid=" << row->representativeThreadId
                       << L" capability=0x" << std::hex << row->capabilityMask
                       << std::dec << L" detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryWin32kWindows prints HWND/tagWND cross-view rows.
    // Inputs: parsed window options.
    // Processing: renders only snapshot evidence; no message interception.
    // Returns: CLI exit code.
    int queryWin32kWindows(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS", IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOWS, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"window gui", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_WINDOW_SNAPSHOT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_WINDOW_ENTRY), L"win32k windows"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_WINDOW_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] hwnd=" << hex64(row->hwnd)
                       << L" tagWnd=" << hex64(row->tagWnd)
                       << L" pid=" << row->processId
                       << L" tid=" << row->threadId
                       << L" session=" << row->sessionId
                       << L" status=" << row->status
                       << L" fields=0x" << std::hex << row->fieldFlags
                       << std::dec << L" title='" << fixedWide(row->title, KSWORD_ARK_WIN32K_TITLE_CHARS)
                       << L"' class='" << fixedWide(row->className, KSWORD_ARK_WIN32K_CLASS_CHARS)
                       << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryWin32kGuiThreads prints GUI thread/queue rows.
    // Inputs: parsed window options.
    // Processing: reports focus/capture/active evidence only.
    // Returns: CLI exit code.
    int queryWin32kGuiThreads(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS", IOCTL_KSWORD_ARK_QUERY_WIN32K_GUI_THREADS, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"window gui threads", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_GUI_THREAD_SNAPSHOT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY), L"win32k gui threads"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] pid=" << row->processId
                       << L" tid=" << row->threadId
                       << L" session=" << row->sessionId
                       << L" status=" << row->status
                       << L" threadInfo=" << hex64(row->threadInfo)
                       << L" queue=" << hex64(row->queueObject)
                       << L" active=" << hex64(row->activeHwnd)
                       << L" focus=" << hex64(row->focusHwnd)
                       << L" capture=" << hex64(row->captureHwnd)
                       << L" detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // printWin32kModuleState renders one fixed win32k module/profile state.
    // Inputs: display label and module state packet from a win32k response.
    // Processing: prints load/profile state and image identity.
    // Returns: no value.
    void printWin32kModuleState(const wchar_t* label, const KSWORD_ARK_WIN32K_MODULE_STATE& module)
    {
        std::wcout << label
                   << L" loaded=" << module.loaded
                   << L" profileState=" << module.profileState
                   << L" imageBase=" << hex64(module.imageBase)
                   << L" imageSize=" << module.imageSize
                   << L" name='" << fixedWide(module.moduleName, KSWORD_ARK_WIN32K_MODULE_NAME_CHARS) << L"'\n";
    }

    // queryWin32kHotkeysPdb prints PDB-backed win32k hotkey chain rows.
    // Inputs: parsed window options for session/pid/tid/filter budgets.
    // Processing: issues IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB and renders
    // diagnostic-only hotkey object rows.
    // Returns: CLI exit code with old-driver normalization.
    int queryWin32kHotkeysPdb(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB", IOCTL_KSWORD_ARK_QUERY_WIN32K_HOTKEYS_PDB, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"window hotkeys-pdb", io, kRc);
        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE) - sizeof(KSWORD_ARK_WIN32K_HOTKEY_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_HOTKEY_SNAPSHOT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_HOTKEY_ENTRY), L"win32k hotkeys-pdb"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"capability=0x" << std::hex << response->capabilityMask
                   << L" missing=0x" << response->missingCapabilityMask
                   << std::dec << L"\n";
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_HOTKEY_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] source=" << row->source
                       << L" status=" << row->status
                       << L" flags=0x" << std::hex << row->flags
                       << L" hotkey=" << hex64(row->hotkeyObject)
                       << L" next=" << hex64(row->nextHotkeyObject)
                       << L" hwnd=" << hex64(row->hwnd)
                       << L" tagWnd=" << hex64(row->tagWnd)
                       << L" threadInfo=" << hex64(row->threadInfo)
                       << L" desktop=" << hex64(row->desktopObject)
                       << std::dec << L" session=" << row->sessionId
                       << L" pid=" << row->processId
                       << L" tid=" << row->threadId
                       << L" modifiers=0x" << std::hex << row->modifiers
                       << std::dec << L" vk=" << row->virtualKey
                       << L" id=" << row->hotkeyId
                       << L" depth=" << row->depth
                       << L" last=0x" << std::hex << static_cast<unsigned long>(row->lastStatus)
                       << std::dec << L" detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryWin32kHooksPdb prints PDB-backed win32k hook chain rows.
    // Inputs: parsed window options for session/pid/tid/filter budgets.
    // Processing: issues IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB and renders
    // diagnostic-only hook object/procedure rows.
    // Returns: CLI exit code with old-driver normalization.
    int queryWin32kHooksPdb(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_QUERY_REQUEST request = buildWin32kRequest(args);
        request.flags = applyMessageHookMatchOption(args, request.flags);
        request.maxEntries = getOptionU32(
            args,
            L"--max-entries",
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES);
        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE) -
            sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY);
        constexpr std::size_t kHardMaxResponseBytes =
            kHeaderSize +
            (static_cast<std::size_t>(KSWORD_ARK_WIN32K_HARD_MAX_ENTRIES) *
                sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY));
        static_assert(
            kHardMaxResponseBytes <= kHugeResponseBytes,
            "win32k hook response buffer must hold the protocol hard maximum");
        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
        const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB", IOCTL_KSWORD_ARK_QUERY_WIN32K_HOOKS_PDB, &request, sizeof(request), buffer, io);
        if (kRc != 0) return normalizeIoctlRc(L"window hooks-pdb", io, kRc);
        const auto* response = reinterpret_cast<const KSWORD_ARK_WIN32K_HOOK_SNAPSHOT_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_WIN32K_HOOK_ENTRY), L"win32k hooks-pdb"); }
        catch (...) { return 4; }
        printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"capability=0x" << std::hex << response->capabilityMask
                   << L" missing=0x" << response->missingCapabilityMask
                   << std::dec
                   << L" match=" << messageHookMatchName(response->flags)
                   << L" chains=" << response->discoveredChainCount
                   << L" visited=" << response->visitedNodeCount
                   << L" readFailures=" << response->readFailureCount
                   << L" corruptLinks=" << response->corruptLinkCount
                   << L" duplicates=" << response->duplicateCount
                   << L"\n";
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(args, L"--limit", 128U));
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* row = reinterpret_cast<const KSWORD_ARK_WIN32K_HOOK_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
            std::wcout << L"  [" << i << L"] source=" << row->source
                       << L" status=" << row->status
                       << L" flags=0x" << std::hex << row->flags
                       << L" hook=" << hex64(row->hookObject)
                       << L" chainHead=" << hex64(row->chainHead)
                       << L" next=" << hex64(row->nextHookObject)
                       << L" threadInfo=" << hex64(row->threadInfo)
                       << L" targetThreadInfo=" << hex64(row->targetThreadInfo)
                       << L" desktop=" << hex64(row->desktopObject)
                       << L" proc=" << hex64(row->procedureAddress)
                       << L" moduleBase=" << hex64(row->moduleBase)
                       << std::dec << L" session=" << row->sessionId
                       << L" pid=" << row->processId
                       << L" tid=" << row->threadId
                       << L" targetSession=" << row->targetSessionId
                       << L" targetPid=" << row->targetProcessId
                       << L" targetTid=" << row->targetThreadId
                       << L" type=" << row->hookType
                       << L" scope=" << row->hookScope
                       << L" last=0x" << std::hex << static_cast<unsigned long>(row->lastStatus)
                       << std::dec << L" detail='" << fixedWide(row->detail, KSWORD_ARK_WIN32K_DETAIL_CHARS) << L"'\n";
        }
        return 0;
    }

    // queryWin32kWindowDetail prints one fixed HWND/tagWND detail packet.
    // Inputs: --hwnd plus optional --pid/--tid context and --flags.
    // Processing: never accepts a tagWND pointer from user mode; R0 resolves the
    // requested HWND and returns stable profile/readiness evidence.
    // Returns: CLI exit code with old-driver normalization.
    int queryWin32kWindowDetail(const NamedArgs& args)
    {
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_REQUEST request{};
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE response{};
        request.version = KSWORD_ARK_WIN32K_PROTOCOL_VERSION;
        request.flags = getOptionU32(args, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_DIAGNOSTICS);
        request.processId = getOptionU32(args, L"--pid", 0U);
        request.threadId = getOptionU32(args, L"--tid", 0U);
        request.hwnd = requireOptionU64(args, L"--hwnd");
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL, L"IOCTL_KSWORD_ARK_QUERY_WIN32K_WINDOW_DETAIL", request, response, io))
        {
            return normalizeIoctlRc(L"window detail", io, 3);
        }
        printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
        std::wcout << L"hwnd=" << hex64(response.hwnd)
                   << L" tagWnd=" << hex64(response.tagWnd)
                   << L" threadInfo=" << hex64(response.threadInfo)
                   << L" queue=" << hex64(response.queueObject)
                   << L" desktop=" << hex64(response.desktopObject)
                   << L" capability=0x" << std::hex << response.capabilityMask
                   << L" missing=0x" << response.missingCapabilityMask
                   << std::dec << L" pid=" << response.processId
                   << L" tid=" << response.threadId
                   << L" fields=0x" << std::hex << response.fieldFlags
                   << L" flags=0x" << response.flags
                   << std::dec << L"\n";
        printWin32kModuleState(L"win32k", response.win32k);
        printWin32kModuleState(L"win32kbase", response.win32kbase);
        printWin32kModuleState(L"win32kfull", response.win32kfull);
        dumpWideText(L"title", fixedWide(response.title, KSWORD_ARK_WIN32K_TITLE_CHARS));
        dumpWideText(L"className", fixedWide(response.className, KSWORD_ARK_WIN32K_CLASS_CHARS));
        dumpWideText(L"detail", fixedWide(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS));
        return 0;
    }

    // commandWindowFamily exposes read-only win32k/GUI/GPU/display commands.
    // Inputs: argc/argv from wmain.
    // Processing: uses win32k and device-audit protocols; unsupported pieces report clearly.
    // Returns: process exit code.
    int commandWindowFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: window requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub == L"win32k")
        {
            return queryWin32kProfileStatus(kArgs);
        }
        if (kSub == L"gui")
        {
            return queryWin32kWindows(kArgs);
        }
        if (kSub == L"gui-threads")
        {
            return queryWin32kGuiThreads(kArgs);
        }
        if (kSub == L"hotkeys-pdb")
        {
            return queryWin32kHotkeysPdb(kArgs);
        }
        if (kSub == L"hooks-pdb")
        {
            return queryWin32kHooksPdb(kArgs);
        }
        if (kSub == L"detail")
        {
            return queryWin32kWindowDetail(kArgs);
        }
        if (kSub == L"gpu" || kSub == L"display" || kSub == L"watchdog")
        {
            return queryDeviceAudit(kArgs, IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG, L"IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT", L"window gpu/display/watchdog");
        }
        std::wcerr << L"error: unknown window subcommand '" << kSub << L"'\n";
        return 1;
    }
}
