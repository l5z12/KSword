#include "CliSupport.h"

namespace ksword::cli
{
    // printRegistryOperationResponse renders common registry mutation response fields.
    // Inputs: response and bytesReturned.
    // Processing: prints status and NTSTATUS.
    // Returns: no value.
    void printRegistryOperationResponse(const KSWORD_ARK_REGISTRY_OPERATION_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
    }

    // commandRegistryFamily implements all registry read/enumeration/mutation IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: copies fixed key/value fields and optional binary data file.
    // Returns: process exit code.
    int commandRegistryFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: registry requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (kSub == L"read-value")
        {
            KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST request{};
            KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.maxDataBytes = getOptionU32(kArgs, L"--max-data-bytes", KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);
            copyRequiredWideOption(kArgs, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            if (copyOptionalWideOption(kArgs, L"--value", request.valueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS))
            {
                request.flags |= KSWORD_ARK_REGISTRY_READ_FLAG_VALUE_NAME_PRESENT;
            }
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE, L"IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"valueType=" << response.valueType
                       << L" dataBytes=" << response.dataBytes
                       << L" requiredBytes=" << response.requiredBytes << L"\n";
            const std::size_t kDataBytes = std::min<std::size_t>(response.dataBytes, KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);
            if (getOptionBool(kArgs, L"--hexdump")) hexdump(response.data, kDataBytes);
            else printBytesInline(L"data", response.data, kDataBytes);
            return 0;
        }
        if (kSub == L"enum-key")
        {
            KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST request{};
            KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES);
            request.maxSubKeys = getOptionU32(kArgs, L"--max-subkeys", KSWORD_ARK_REGISTRY_ENUM_MAX_SUBKEYS);
            request.maxValues = getOptionU32(kArgs, L"--max-values", KSWORD_ARK_REGISTRY_ENUM_MAX_VALUES);
            request.maxValueDataBytes = getOptionU32(kArgs, L"--max-value-data-bytes", KSWORD_ARK_REGISTRY_ENUM_VALUE_DATA_MAX_BYTES);
            copyRequiredWideOption(kArgs, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY, L"IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"subKeyCount=" << response.subKeyCount
                       << L" returnedSubKeyCount=" << response.returnedSubKeyCount
                       << L" valueCount=" << response.valueCount
                       << L" returnedValueCount=" << response.returnedValueCount << L"\n";
            const std::size_t kSubKeyCount = std::min<std::size_t>({ response.returnedSubKeyCount, KSWORD_ARK_REGISTRY_ENUM_MAX_SUBKEYS, getOptionU32(kArgs, L"--limit", 128U) });
            for (std::size_t i = 0; i < kSubKeyCount; ++i)
            {
                std::wcout << L"  subkey[" << i << L"] '" << fixedWide(response.subKeys[i].name, KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS) << L"'\n";
            }
            const std::size_t kValueCount = std::min<std::size_t>({ response.returnedValueCount, KSWORD_ARK_REGISTRY_ENUM_MAX_VALUES, getOptionU32(kArgs, L"--limit", 128U) });
            for (std::size_t i = 0; i < kValueCount; ++i)
            {
                const auto& value = response.values[i];
                std::wcout << L"  value[" << i << L"] type=" << value.valueType
                           << L" dataBytes=" << value.dataBytes
                           << L" requiredBytes=" << value.requiredBytes
                           << L" flags=0x" << std::hex << value.flags << std::dec
                           << L" name='" << fixedWide(value.name, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS) << L"'\n";
                printBytesInline(L"    data", value.data, std::min<std::size_t>(value.dataBytes, KSWORD_ARK_REGISTRY_ENUM_VALUE_DATA_MAX_BYTES), 24U);
            }
            return 0;
        }
        if (kSub == L"set-value")
        {
            KSWORD_ARK_SET_REGISTRY_VALUE_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.valueType = requireOptionU32(kArgs, L"--type");
            copyRequiredWideOption(kArgs, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            if (copyOptionalWideOption(kArgs, L"--value", request.valueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS))
            {
                request.flags |= KSWORD_ARK_REGISTRY_SET_FLAG_VALUE_NAME_PRESENT;
            }
            const std::vector<std::uint8_t> kData = readRequiredBlobOption(kArgs, L"--data-file", KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);
            request.dataBytes = static_cast<unsigned long>(kData.size());
            copyBytesToFixed(request.data, KSWORD_ARK_REGISTRY_DATA_MAX_BYTES, kData);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE, L"IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"delete-value")
        {
            KSWORD_ARK_REGISTRY_VALUE_NAME_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            copyRequiredWideOption(kArgs, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            if (copyOptionalWideOption(kArgs, L"--value", request.valueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS))
            {
                request.flags |= KSWORD_ARK_REGISTRY_DELETE_VALUE_FLAG_NAME_PRESENT;
            }
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE, L"IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"create-key" || kSub == L"delete-key")
        {
            KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            copyRequiredWideOption(kArgs, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            const DWORD kCode = (kSub == L"create-key") ? IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY : IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY;
            const wchar_t* label = (kSub == L"create-key") ? L"IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY" : L"IOCTL_KSWORD_ARK_DELETE_REGISTRY_KEY";
            if (!sendFixedRequestResponse(kCode, label, request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"rename-value")
        {
            KSWORD_ARK_RENAME_REGISTRY_VALUE_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            copyRequiredWideOption(kArgs, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            copyRequiredWideOption(kArgs, L"--old-value", request.oldValueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS);
            copyRequiredWideOption(kArgs, L"--new-value", request.newValueName, KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE, L"IOCTL_KSWORD_ARK_RENAME_REGISTRY_VALUE", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"rename-key")
        {
            KSWORD_ARK_RENAME_REGISTRY_KEY_REQUEST request{};
            KSWORD_ARK_REGISTRY_OPERATION_RESPONSE response{};
            request.version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            copyRequiredWideOption(kArgs, L"--key", request.keyPath, KSWORD_ARK_REGISTRY_PATH_CHARS);
            copyRequiredWideOption(kArgs, L"--new-name", request.newKeyName, KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY, L"IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printRegistryOperationResponse(response, io.bytesReturned);
            return 0;
        }
        std::wcerr << L"error: unknown registry subcommand '" << kSub << L"'\n";
        return 1;
    }

    // commandRedirectFamily implements redirect rule load and status query.
    // Inputs: argc/argv from wmain.
    // Processing: accepts a blob for rule snapshots and prints runtime rules.
    // Returns: process exit code.
    int commandRedirectFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: redirect requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (kSub == L"set-rules")
        {
            std::vector<std::uint8_t> blob = readRequiredBlobOption(kArgs, L"--blob", kMaxCommandBytes);
            KSWORD_ARK_REDIRECT_SET_RULES_RESPONSE response{};
            if (!sendBlobFixedResponse(IOCTL_KSWORD_ARK_REDIRECT_SET_RULES, L"IOCTL_KSWORD_ARK_REDIRECT_SET_RULES", blob, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"runtimeFlags=0x" << std::hex << response.runtimeFlags
                       << L" appliedCount=" << std::dec << response.appliedCount
                       << L" rejectedIndex=" << response.rejectedIndex
                       << L" fileRuleCount=" << response.fileRuleCount
                       << L" registryRuleCount=" << response.registryRuleCount
                       << L" generation=" << response.generation << L"\n";
            return 0;
        }
        if (kSub == L"query-status")
        {
            KSWORD_ARK_REDIRECT_STATUS_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS, L"IOCTL_KSWORD_ARK_REDIRECT_QUERY_STATUS", response, io)) return 3;
            printResponseBanner(response.version, response.status, response.registryRegisterStatus, io.bytesReturned);
            std::wcout << L"runtimeFlags=0x" << std::hex << response.runtimeFlags
                       << std::dec << L" fileRuleCount=" << response.fileRuleCount
                       << L" registryRuleCount=" << response.registryRuleCount
                       << L" generation=" << response.generation
                       << L" fileHits=" << response.fileRedirectHits
                       << L" registryHits=" << response.registryRedirectHits
                       << L" registryRegisterStatus=0x" << std::hex << static_cast<unsigned long>(response.registryRegisterStatus) << std::dec << L"\n";
            const std::size_t kLimit = getOptionU32(kArgs, L"--limit", 16U);
            for (std::size_t i = 0; i < std::min<std::size_t>(KSWORD_ARK_REDIRECT_MAX_RULES, kLimit); ++i)
            {
                const auto& rule = response.rules[i];
                if (rule.ruleId == 0U && rule.sourcePath[0] == L'\0' && rule.targetPath[0] == L'\0')
                {
                    continue;
                }
                std::wcout << L"  rule[" << i << L"] id=" << rule.ruleId
                           << L" type=" << rule.type
                           << L" action=" << rule.action
                           << L" matchMode=" << rule.matchMode
                           << L" flags=0x" << std::hex << rule.flags
                           << std::dec << L" pid=" << rule.processId
                           << L" source='" << fixedWide(rule.sourcePath, KSWORD_ARK_REDIRECT_PATH_CHARS)
                           << L"' target='" << fixedWide(rule.targetPath, KSWORD_ARK_REDIRECT_PATH_CHARS) << L"'\n";
            }
            return 0;
        }
        std::wcerr << L"error: unknown redirect subcommand '" << kSub << L"'\n";
        return 1;
    }
}
