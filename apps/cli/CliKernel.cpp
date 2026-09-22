#include "CliSupport.h"

namespace ksword::cli
{
    // fixedAnsiWide widens a fixed ANSI protocol field for wide console output.
    // Inputs: a char buffer and its protocol capacity.
    // Processing: extracts the NUL-terminated ANSI text and widens byte-for-byte.
    // Returns: a wide string suitable for std::wcout.
    std::wstring fixedAnsiWide(const char* text, std::size_t maxBytes)
    {
        const std::string kValue = fixedAnsi(text, maxBytes);
        return std::wstring(kValue.begin(), kValue.end());
    }

    // requireWideCapacity rejects strings that cannot fit in fixed protocol fields.
    // Inputs: source text, destination capacity, and a human-readable field name.
    // Processing: enforces room for a trailing NUL to avoid silent truncation.
    // Returns: no value; throws when the string is empty or too long.
    void requireWideCapacity(const std::wstring& text, std::size_t capacity, const char* name)
    {
        if (text.empty() || text.size() >= capacity)
        {
            throw std::out_of_range(name);
        }
    }

    // copyRequiredWideOption copies a mandatory named option into a fixed field.
    // Inputs: parsed args, option key, destination field, and field capacity.
    // Processing: validates capacity and writes a NUL-terminated copy.
    // Returns: no value; throws when the option is missing or too long.
    void copyRequiredWideOption(const NamedArgs& args, const wchar_t* key, wchar_t* destination, std::size_t capacity)
    {
        const std::wstring& value = requireOptionText(args, key);
        requireWideCapacity(value, capacity, "wide option");
        copyWideToFixed(destination, capacity, value);
    }

    // copyOptionalWideOption copies an optional named option into a fixed field.
    // Inputs: parsed args, option key, destination field, and field capacity.
    // Processing: leaves the field unchanged when the option is absent.
    // Returns: true when the option was supplied.
    bool copyOptionalWideOption(const NamedArgs& args, const wchar_t* key, wchar_t* destination, std::size_t capacity)
    {
        const std::wstring* value = getOptionText(args, key);
        if (value == nullptr)
        {
            return false;
        }
        requireWideCapacity(*value, capacity, "wide option");
        copyWideToFixed(destination, capacity, *value);
        return true;
    }

    // printBytesInline renders a short byte array summary on one line.
    // Inputs: label, source pointer, byte count, and display cap.
    // Processing: prints hexadecimal bytes and an ellipsis when truncated.
    // Returns: no value.
    void printBytesInline(const wchar_t* label, const unsigned char* data, std::size_t count, std::size_t maxDisplay )
    {
        std::wcout << label << L"=";
        if (data == nullptr || count == 0U)
        {
            std::wcout << L"(empty)\n";
            return;
        }

        const std::size_t kShown = std::min<std::size_t>(count, maxDisplay);
        std::wcout << std::hex << std::setfill(L'0');
        for (std::size_t index = 0U; index < kShown; ++index)
        {
            std::wcout << (index == 0U ? L"" : L" ")
                       << std::setw(2) << static_cast<unsigned int>(data[index]);
        }
        std::wcout << std::dec << std::setfill(L' ');
        if (kShown < count)
        {
            std::wcout << L" ...";
        }
        std::wcout << L"\n";
    }

    // readRequiredBlobOption reads a mandatory blob-style file option.
    // Inputs: parsed args, option key, and protocol maximum length.
    // Processing: delegates to readFileBytes and rejects empty blobs.
    // Returns: the raw file bytes.
    std::vector<std::uint8_t> readRequiredBlobOption(const NamedArgs& args, const wchar_t* key, std::size_t maxBytes)
    {
        const std::wstring& path = requireOptionText(args, key);
        std::vector<std::uint8_t> bytes = readFileBytes(path, maxBytes);
        if (bytes.empty())
        {
            throw std::invalid_argument("empty blob");
        }
        return bytes;
    }

    // printModuleIdentity renders a DynData module identity packet.
    // Inputs: label and module packet.
    // Processing: prints stable scalar fields and the fixed module name.
    // Returns: no value.
    void printModuleIdentity(const wchar_t* label, const KSW_DYN_MODULE_IDENTITY_PACKET& module)
    {
        std::wcout << label << L": present=" << module.present
                   << L" class=" << module.classId
                   << L" machine=0x" << std::hex << module.machine
                   << L" timestamp=0x" << module.timeDateStamp
                   << L" imageBase=" << hex64(module.imageBase)
                   << std::dec << L" sizeOfImage=" << module.sizeOfImage
                   << L" name='" << fixedWide(module.moduleName, KSW_DYN_MODULE_NAME_CHARS) << L"'\n";
    }

    // commandKernelFamily implements kernel inspection and mutation IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: routes SSDT, hook, DriverObject, CPU, memory-layout and unload commands.
    // Returns: process exit code.
    int commandKernelFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: kernel requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (kSub == L"ssdt" || kSub == L"shadow-ssdt")
        {
            KSWORD_ARK_ENUM_SSDT_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const DWORD kCode = (kSub == L"ssdt") ? IOCTL_KSWORD_ARK_ENUM_SSDT : IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT;
            const wchar_t* label = (kSub == L"ssdt") ? L"IOCTL_KSWORD_ARK_ENUM_SSDT" : L"IOCTL_KSWORD_ARK_ENUM_SHADOW_SSDT";
            const int kRc = sendRawIoctl(label, kCode, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_SSDT_RESPONSE) - sizeof(KSWORD_ARK_SSDT_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_SSDT_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_SSDT_ENTRY), label); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"serviceTableBase=" << hex64(response->serviceTableBase)
                       << L" serviceCountFromTable=" << response->serviceCountFromTable << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_SSDT_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] index=" << entry->serviceIndex
                           << L" flags=0x" << std::hex << entry->flags
                           << L" zw=" << hex64(entry->zwRoutineAddress)
                           << L" service=" << hex64(entry->serviceRoutineAddress)
                           << std::dec << L" name='" << fixedAnsiWide(entry->serviceName, sizeof(entry->serviceName))
                           << L"' module='" << fixedAnsiWide(entry->moduleName, sizeof(entry->moduleName)) << L"'\n";
            }
            return 0;
        }

        if (kSub == L"scan-inline-hooks" || kSub == L"enum-iat-eat-hooks")
        {
            KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL);
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES);
            copyOptionalWideOption(kArgs, L"--module", request.moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            if (kSub == L"scan-inline-hooks")
            {
                const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS", IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS, &request, sizeof(request), buffer, io);
                if (kRc != 0) return kRc;
                constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY);
                const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE*>(buffer.data());
                std::size_t available = 0U;
                try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY), L"scan-inline-hooks"); }
                catch (...) { return 4; }
                printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
                printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
                std::wcout << L"moduleCount=" << response->moduleCount << L"\n";
                const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
                for (std::size_t i = 0; i < kParsed; ++i)
                {
                    const auto* entry = reinterpret_cast<const KSWORD_ARK_INLINE_HOOK_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                    std::wcout << L"  [" << i << L"] status=" << entry->status
                               << L" type=" << entry->hookType
                               << L" flags=0x" << std::hex << entry->flags
                               << L" function=" << hex64(entry->functionAddress)
                               << L" target=" << hex64(entry->targetAddress)
                               << L" moduleBase=" << hex64(entry->moduleBase)
                               << std::dec << L" function='" << fixedAnsiWide(entry->functionName, sizeof(entry->functionName))
                               << L"' module='" << fixedWide(entry->moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS)
                               << L"' targetModule='" << fixedWide(entry->targetModuleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS) << L"'\n";
                }
                return 0;
            }

            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS", IOCTL_KSWORD_ARK_ENUM_IAT_EAT_HOOKS, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_IAT_EAT_HOOKS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_IAT_EAT_HOOK_ENTRY), L"enum-iat-eat-hooks"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"moduleCount=" << response->moduleCount << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_IAT_EAT_HOOK_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] class=" << entry->hookClass
                           << L" status=" << entry->status
                           << L" ordinal=" << entry->ordinal
                           << L" thunk=" << hex64(entry->thunkAddress)
                           << L" current=" << hex64(entry->currentTarget)
                           << L" expected=" << hex64(entry->expectedTarget)
                           << L" function='" << fixedAnsiWide(entry->functionName, sizeof(entry->functionName))
                           << L"' module='" << fixedWide(entry->moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS) << L"'\n";
            }
            return 0;
        }

        if (kSub == L"patch-inline-hook")
        {
            KSWORD_ARK_PATCH_INLINE_HOOK_REQUEST request{};
            KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE response{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.mode = requireOptionU32(kArgs, L"--mode");
            request.functionAddress = requireOptionU64(kArgs, L"--function");
            const std::vector<std::uint8_t> kExpected = loadBytesFromHexOrFile(kArgs, L"--expected-hex", L"--expected-file", KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES, true);
            const std::vector<std::uint8_t> kRestore = loadBytesFromHexOrFile(kArgs, L"--restore-hex", L"--restore-file", KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES, false);
            request.patchBytes = static_cast<unsigned long>(std::max(kExpected.size(), kRestore.size()));
            copyBytesToFixed(request.expectedCurrentBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES, kExpected);
            copyBytesToFixed(request.restoreBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES, kRestore);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK, L"IOCTL_KSWORD_ARK_PATCH_INLINE_HOOK", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"bytesPatched=" << response.bytesPatched
                       << L" fieldFlags=0x" << std::hex << response.fieldFlags
                       << L" function=" << hex64(response.functionAddress) << std::dec << L"\n";
            printBytesInline(L"beforeBytes", response.beforeBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES);
            printBytesInline(L"afterBytes", response.afterBytes, KSWORD_ARK_KERNEL_HOOK_PATCH_MAX_BYTES);
            return 0;
        }

        if (kSub == L"query-driver-object")
        {
            KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL);
            request.maxDevices = getOptionU32(kArgs, L"--max-devices", KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT);
            request.maxAttachedDevices = getOptionU32(kArgs, L"--max-attached", KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
            copyRequiredWideOption(kArgs, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT", IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->deviceEntrySize, sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY), L"query-driver-object"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalDeviceCount, response->returnedDeviceCount, response->deviceEntrySize, io.bytesReturned);
            std::wcout << L"fieldFlags=0x" << std::hex << response->fieldFlags
                       << L" driverObject=" << hex64(response->driverObjectAddress)
                       << L" driverStart=" << hex64(response->driverStart)
                       << L" driverSection=" << hex64(response->driverSection)
                       << L" driverUnload=" << hex64(response->driverUnload)
                       << std::dec << L" majorFunctionCount=" << response->majorFunctionCount
                       << L" driverFlags=0x" << std::hex << response->driverFlags
                       << std::dec << L" driverSize=" << response->driverSize << L"\n";
            dumpWideText(L"driverName", fixedWide(response->driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS));
            dumpWideText(L"serviceKeyName", fixedWide(response->serviceKeyName, KSWORD_ARK_DRIVER_SERVICE_KEY_CHARS));
            dumpWideText(L"imagePath", fixedWide(response->imagePath, KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS));
            const std::size_t kMajorCount = std::min<std::size_t>(response->majorFunctionCount, KSWORD_ARK_DRIVER_MAJOR_FUNCTION_COUNT);
            for (std::size_t i = 0; i < kMajorCount; ++i)
            {
                const auto& major = response->majorFunctions[i];
                std::wcout << L"  major[" << i << L"] fn=" << major.majorFunction
                           << L" flags=0x" << std::hex << major.flags
                           << L" dispatch=" << hex64(major.dispatchAddress)
                           << L" moduleBase=" << hex64(major.moduleBase)
                           << std::dec << L" module='" << fixedWide(major.moduleName, KSWORD_ARK_DRIVER_MODULE_NAME_CHARS) << L"'\n";
            }
            const std::size_t kParsed = responseCountLimit(response->returnedDeviceCount, available, getOptionU32(kArgs, L"--limit", 64U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* device = reinterpret_cast<const KSWORD_ARK_DRIVER_DEVICE_ENTRY*>(buffer.data() + kHeaderSize + (i * response->deviceEntrySize));
                std::wcout << L"  device[" << i << L"] depth=" << device->relationDepth
                           << L" type=0x" << std::hex << device->deviceType
                           << L" flags=0x" << device->flags
                           << L" object=" << hex64(device->deviceObjectAddress)
                           << L" attached=" << hex64(device->attachedDeviceObjectAddress)
                           << L" driver=" << hex64(device->driverObjectAddress)
                           << L" nameStatus=0x" << static_cast<unsigned long>(device->nameStatus)
                           << std::dec << L" name='" << fixedWide(device->deviceName, KSWORD_ARK_DRIVER_DEVICE_NAME_CHARS) << L"'\n";
            }
            return 0;
        }

        if (kSub == L"query-driver-integrity")
        {
            KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST request{};
            request.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT);
            request.maxRows = getOptionU32(kArgs, L"--max-rows", KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS);
            request.maxIdtVectorsPerCpu = getOptionU32(kArgs, L"--max-idt-vectors", KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);
            request.maxDevices = getOptionU32(kArgs, L"--max-devices", KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT);
            request.maxAttachedDevices = getOptionU32(kArgs, L"--max-attached", KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
            request.targetModuleBase = getOptionU64(kArgs, L"--module-base", 0ULL);
            copyOptionalWideOption(kArgs, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY", IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE), L"query-driver-integrity"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"flags=0x" << std::hex << response->flags
                       << L" sourceMask=0x" << response->sourceMask
                       << std::dec << L" cpuCount=" << response->cpuCount
                       << L" moduleCount=" << response->moduleCount << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] class=" << entry->evidenceClass
                           << L" risk=0x" << std::hex << entry->riskFlags
                           << L" source=0x" << entry->sourceMask
                           << L" object=" << hex64(entry->objectAddress)
                           << L" target=" << hex64(entry->targetAddress)
                           << L" ownerBase=" << hex64(entry->ownerModuleBase)
                           << std::dec << L" confidence=" << entry->confidence
                           << L" owner='" << fixedWide(entry->ownerModule, KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS)
                           << L"' detail='" << fixedWide(entry->detail, KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }

        if (kSub == L"force-unload-driver")
        {
            KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST request{};
            KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE response{};
            request.version = KSWORD_ARK_FORCE_UNLOAD_DRIVER_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.timeoutMilliseconds = getOptionU32(kArgs, L"--timeout-ms", 5000U);
            request.targetModuleBase = getOptionU64(kArgs, L"--module-base", 0ULL);
            copyRequiredWideOption(kArgs, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER, L"IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"flags=0x" << std::hex << response.flags
                       << L" waitStatus=0x" << static_cast<unsigned long>(response.waitStatus)
                       << L" driverObject=" << hex64(response.driverObjectAddress)
                       << L" unload=" << hex64(response.driverUnloadAddress)
                       << std::dec << L" cleanupFlagsApplied=" << response.cleanupFlagsApplied
                       << L" deletedDeviceCount=" << response.deletedDeviceCount
                       << L" callbackCandidates=" << response.callbackCandidates
                       << L" callbacksRemoved=" << response.callbacksRemoved
                       << L" callbackFailures=" << response.callbackFailures
                       << L" callbackLastStatus=0x" << std::hex << static_cast<unsigned long>(response.callbackLastStatus)
                       << std::dec << L" driverName='" << fixedWide(response.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) << L"'\n";
            return 0;
        }

        if (kSub == L"query-cpu")
        {
            KSWORD_ARK_QUERY_CPU_HARDWARE_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE, L"IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE", response, io)) return 3;
            printResponseBanner(response.version, response.fieldFlags, response.lastStatus, io.bytesReturned);
            std::wcout << L"logical=" << response.logicalProcessorCount
                       << L" active=" << response.activeProcessorCount
                       << L" packages=" << response.packageCount
                       << L" family=" << response.family
                       << L" model=" << response.model
                       << L" stepping=" << response.stepping
                       << L" featureMask=0x" << std::hex << response.featureMask
                       << L" leaf1Ecx=0x" << response.leaf1Ecx
                       << L" leaf1Edx=0x" << response.leaf1Edx
                       << std::dec << L" vendor='" << fixedAnsiWide(response.vendor, KSWORD_ARK_CPU_HARDWARE_VENDOR_CHARS)
                       << L"' brand='" << fixedAnsiWide(response.brand, KSWORD_ARK_CPU_HARDWARE_BRAND_CHARS) << L"'\n";
            return 0;
        }

        if (kSub == L"query-phys-layout")
        {
            KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT, L"IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT", response, io)) return 3;
            printResponseBanner(response.version, response.fieldFlags, response.lastStatus, io.bytesReturned);
            std::wcout << L"rangeCount=" << response.rangeCount
                       << L" zeroLengthRangeCount=" << response.zeroLengthRangeCount
                       << L" truncated=" << response.truncated
                       << L" totalPhysicalBytes=" << response.totalPhysicalBytes
                       << L" highestPhysicalAddress=" << hex64(response.highestPhysicalAddress)
                       << L" largestRangeBytes=" << response.largestRangeBytes
                       << L" smallestRangeBytes=" << response.smallestRangeBytes
                       << L" firstBaseAddress=" << hex64(response.firstBaseAddress)
                       << L" lastEndAddress=" << hex64(response.lastEndAddress)
                       << L" estimatedAddressSpaceGapBytes=" << response.estimatedAddressSpaceGapBytes << L"\n";
            return 0;
        }
        if (kSub == L"cid")
        {
            KSWORD_ARK_ENUM_CID_TABLE_REQUEST request{};
            request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL);
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", 4096U);
            request.maxVisitCount = getOptionU32(kArgs, L"--max-visits", 65536U);
            request.startCid = getOptionU32(kArgs, L"--start-cid", 0U);
            request.endCid = getOptionU32(kArgs, L"--end-cid", 0U);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_CID_TABLE", IOCTL_KSWORD_ARK_ENUM_CID_TABLE, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"kernel cid", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_CID_TABLE_RESPONSE) - sizeof(KSWORD_ARK_CID_TABLE_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_CID_TABLE_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_CID_TABLE_ENTRY), L"kernel cid"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"flags=0x" << std::hex << response->flags
                       << L" pspCidTable=" << hex64(response->pspCidTableAddress)
                       << L" dyn=0x" << response->dynDataCapabilityMask
                       << std::dec << L" visited=" << response->visitedCount
                       << L" maxVisitCount=" << response->maxVisitCount << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_CID_TABLE_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] cid=" << entry->cidValue
                           << L" index=" << entry->handleIndex
                           << L" kind=" << entry->expectedObjectKind
                           << L" lookup=" << entry->lookupStatus
                           << L" flags=0x" << std::hex << entry->flags
                           << L" object=" << hex64(entry->objectAddress)
                           << L" refStatus=0x" << static_cast<unsigned long>(entry->referenceStatus)
                           << std::dec << L"\n";
            }
            return 0;
        }
        if (kSub == L"object-summary")
        {
            // kernel object-summary:
            // - Inputs: --target-kind plus either --cid and/or --object evidence.
            // - Processing: sends the fixed KernelObject summary protocol and
            //   prints object header/type/counter status without mutating objects.
            // - Returns: normalized CLI status for old-driver compatibility.
            KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST request{};
            KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE response{};
            request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_ALL);
            request.targetKind = requireOptionU32(kArgs, L"--target-kind");
            request.cidValue = getOptionU32(kArgs, L"--cid", 0U);
            request.expectedObjectAddress = getOptionU64(kArgs, L"--object", 0ULL);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY, L"IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY", request, response, io))
            {
                return normalizeIoctlRc(L"kernel object-summary", io, 3);
            }
            printResponseBanner(response.version, response.status, response.lookupStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" fields=0x" << std::hex << response.fieldFlags
                       << L" object=" << hex64(response.objectAddress)
                       << L" expected=" << hex64(response.expectedObjectAddress)
                       << L" typeObject=" << hex64(response.objectTypeAddress)
                       << L" dyn=0x" << response.dynDataCapabilityMask
                       << std::dec << L" targetKind=" << response.targetKind
                       << L" cid=" << response.cidValue
                       << L" typeStatus=0x" << std::hex << static_cast<unsigned long>(response.typeStatus)
                       << L" counterStatus=0x" << static_cast<unsigned long>(response.counterStatus)
                       << std::dec << L" headerStatus=" << response.objectHeaderStatus
                       << L" typeIndex=" << response.typeIndex
                       << L" pointerCount=" << response.pointerCount
                       << L" handleCount=" << response.handleCount
                       << L" otNameOffset=0x" << std::hex << response.otNameOffset
                       << L" otIndexOffset=0x" << response.otIndexOffset
                       << std::dec << L" type='" << fixedWide(response.typeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS)
                       << L"' detail='" << fixedWide(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS) << L"'\n";
            return 0;
        }
        if (kSub == L"ipc")
        {
            KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST request{};
            KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE response{};
            request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL);
            request.processId = getOptionU32(kArgs, L"--pid", 0U);
            request.handleValue = getOptionU64(kArgs, L"--handle", 0ULL);
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", 128U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY, L"IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY", request, response, io))
            {
                return normalizeIoctlRc(L"kernel ipc", io, 3);
            }
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" fields=0x" << std::hex << response.fieldFlags
                       << L" handle=" << hex64(response.handleValue)
                       << L" alpcObject=" << hex64(response.alpcObjectAddress)
                       << L" dyn=0x" << response.dynDataCapabilityMask
                       << std::dec << L" pid=" << response.processId
                       << L" alpcStatus=" << ipcSummaryStatusName(response.alpcStatus)
                       << L"(" << response.alpcStatus << L")"
                       << L" pipeStatus=" << ipcSummaryStatusName(response.namedPipeStatus)
                       << L"(" << response.namedPipeStatus << L")"
                       << L" mailslotStatus=" << ipcSummaryStatusName(response.mailslotStatus)
                       << L"(" << response.mailslotStatus << L")"
                       << L" type='" << fixedWide(response.alpcTypeName, KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS)
                       << L"' detail='" << fixedWide(response.detail, KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS) << L"'\n";
            return 0;
        }
        if (kSub == L"callbacks")
        {
            return queryCallbackInventory(kArgs);
        }
        if (kSub == L"hooks")
        {
            KSWORD_ARK_SCAN_KERNEL_HOOKS_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_CLEAN | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_INTERNAL);
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES);
            copyOptionalWideOption(kArgs, L"--module", request.moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS", IOCTL_KSWORD_ARK_SCAN_INLINE_HOOKS, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"kernel hooks", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_INLINE_HOOKS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_INLINE_HOOK_ENTRY), L"kernel hooks"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_INLINE_HOOK_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] status=" << entry->status
                           << L" type=" << entry->hookType
                           << L" function=" << hex64(entry->functionAddress)
                           << L" target=" << hex64(entry->targetAddress)
                           << L" module='" << fixedWide(entry->moduleName, KSWORD_ARK_KERNEL_HOOK_MODULE_CHARS)
                           << L"' functionName='" << fixedAnsiWide(entry->functionName, sizeof(entry->functionName)) << L"'\n";
            }
            return 0;
        }

        std::wcerr << L"error: unknown kernel subcommand '" << kSub << L"'\n";
        return 1;
    }
}
