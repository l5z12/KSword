#include "pch.h"
#include "MonitorConfig.h"

namespace apimon
{
    namespace
    {
        std::vector<std::wstring> splitIniList(const std::wstring& listText);

        std::wstring queryIniText(const std::wstring& iniPath, const wchar_t* keyName, const wchar_t* defaultText)
        {
            wchar_t textBuffer[4096] = {};
            const DWORD kCopiedLength = ::GetPrivateProfileStringW(
                L"monitor",
                keyName,
                defaultText,
                textBuffer,
                static_cast<DWORD>(std::size(textBuffer)),
                iniPath.c_str());
            return std::wstring(textBuffer, kCopiedLength);
        }

        bool queryIniBool(const std::wstring& iniPath, const wchar_t* keyName, const bool defaultValue)
        {
            const UINT kRawValue = ::GetPrivateProfileIntW(
                L"monitor",
                keyName,
                defaultValue ? 1U : 0U,
                iniPath.c_str());
            return kRawValue != 0;
        }

        std::wstring trimWideCopy(const std::wstring& textValue)
        {
            const auto kFirstIt = std::find_if_not(
                textValue.begin(),
                textValue.end(),
                [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; });
            const auto kLastIt = std::find_if_not(
                textValue.rbegin(),
                textValue.rend(),
                [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; }).base();
            if (kFirstIt >= kLastIt)
            {
                return std::wstring();
            }
            return std::wstring(kFirstIt, kLastIt);
        }

        std::wstring toLowerWideCopy(std::wstring textValue)
        {
            std::transform(
                textValue.begin(),
                textValue.end(),
                textValue.begin(),
                [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
            return textValue;
        }

        std::vector<std::wstring> splitWideText(const std::wstring& textValue, const wchar_t delimiter)
        {
            std::vector<std::wstring> partList;
            std::wstring currentPart;
            for (const wchar_t kCh : textValue)
            {
                if (kCh == delimiter)
                {
                    partList.push_back(trimWideCopy(currentPart));
                    currentPart.clear();
                    continue;
                }
                currentPart.push_back(kCh);
            }
            partList.push_back(trimWideCopy(currentPart));
            return partList;
        }

        bool parseUnsignedInteger(const std::wstring& textValue, std::uint64_t* valueOut)
        {
            if (valueOut == nullptr)
            {
                return false;
            }

            const std::wstring kNormalizedText = trimWideCopy(textValue);
            if (kNormalizedText.empty())
            {
                return false;
            }

            wchar_t* endPointer = nullptr;
            errno = 0;
            if (!kNormalizedText.empty() && kNormalizedText.front() == L'-')
            {
                const long long kParsedValue = std::wcstoll(kNormalizedText.c_str(), &endPointer, 0);
                if (errno != 0 || endPointer == kNormalizedText.c_str() || (endPointer != nullptr && *endPointer != L'\0'))
                {
                    return false;
                }
                *valueOut = static_cast<std::uint64_t>(kParsedValue);
                return true;
            }

            const unsigned long long kParsedValue = std::wcstoull(kNormalizedText.c_str(), &endPointer, 0);
            if (errno != 0 || endPointer == kNormalizedText.c_str() || (endPointer != nullptr && *endPointer != L'\0'))
            {
                return false;
            }

            *valueOut = static_cast<std::uint64_t>(kParsedValue);
            return true;
        }

        FakeSuccessReturnType parseFakeSuccessReturnType(const std::wstring& textValue)
        {
            const std::wstring kLowerText = toLowerWideCopy(trimWideCopy(textValue));
            if (kLowerText == L"bool")
            {
                return FakeSuccessReturnType::kBool;
            }
            if (kLowerText == L"handle" || kLowerText == L"pvoid" || kLowerText == L"pointer" || kLowerText == L"ptr")
            {
                return FakeSuccessReturnType::kHandle;
            }
            if (kLowerText == L"dword" || kLowerText == L"uint" || kLowerText == L"int")
            {
                return FakeSuccessReturnType::kDword;
            }
            if (kLowerText == L"ntstatus" || kLowerText == L"status")
            {
                return FakeSuccessReturnType::kNtStatus;
            }
            if (kLowerText == L"hresult")
            {
                return FakeSuccessReturnType::kHResult;
            }
            if (kLowerText == L"lstatus")
            {
                return FakeSuccessReturnType::kLStatus;
            }
            if (kLowerText == L"socket" || kLowerText == L"socketint" || kLowerText == L"wsa")
            {
                return FakeSuccessReturnType::kSocketInt;
            }
            return FakeSuccessReturnType::kScalar;
        }

        FakeSuccessLastErrorKind parseFakeSuccessLastErrorKind(const std::wstring& textValue)
        {
            const std::wstring kLowerText = toLowerWideCopy(trimWideCopy(textValue));
            if (kLowerText == L"win32" || kLowerText == L"last_error" || kLowerText == L"lasterror")
            {
                return FakeSuccessLastErrorKind::kWin32;
            }
            if (kLowerText == L"wsa" || kLowerText == L"wsa_error" || kLowerText == L"wsaerror")
            {
                return FakeSuccessLastErrorKind::kWsa;
            }
            return FakeSuccessLastErrorKind::kNone;
        }

        std::vector<FakeSuccessRule> parseFakeSuccessRules(const std::wstring& ruleText)
        {
            std::vector<FakeSuccessRule> ruleList;
            std::wstring normalizedText = ruleText;
            std::size_t searchOffset = 0;
            while ((searchOffset = normalizedText.find(L";;", searchOffset)) != std::wstring::npos)
            {
                normalizedText.replace(searchOffset, 2, L"\n");
                searchOffset += 1;
            }

            for (const std::wstring& rawLine : splitIniList(normalizedText))
            {
                const std::vector<std::wstring> kPartList = splitWideText(rawLine, L'|');
                if (kPartList.size() < 6)
                {
                    continue;
                }

                FakeSuccessRule ruleValue;
                ruleValue.moduleName = trimWideCopy(kPartList[0]);
                ruleValue.apiName = trimWideCopy(kPartList[1]);
                ruleValue.returnType = parseFakeSuccessReturnType(kPartList[2]);
                if (ruleValue.moduleName.empty() || ruleValue.apiName.empty())
                {
                    continue;
                }
                if (!parseUnsignedInteger(kPartList[3], &ruleValue.returnValue))
                {
                    continue;
                }
                ruleValue.lastErrorKind = parseFakeSuccessLastErrorKind(kPartList[4]);

                std::uint64_t lastErrorValue = 0;
                if (parseUnsignedInteger(kPartList[5], &lastErrorValue))
                {
                    ruleValue.lastErrorValue = static_cast<std::uint32_t>(lastErrorValue & 0xFFFFFFFFULL);
                }

                ruleList.push_back(std::move(ruleValue));
            }
            return ruleList;
        }

        // splitIniList:
        // - Input: List text in INI format, separated by semicolons, commas, or newlines;
        // - Processing: Trim leading/trailing whitespace and ignore empty items to prevent invalid Raw Hook targets after UI editing.
        // - Return: A normalized string array; case folding is not performed here and is handled uniformly during the matching phase.
        std::vector<std::wstring> splitIniList(const std::wstring& listText)
        {
            std::vector<std::wstring> itemList;
            std::wstring currentItem;
            const auto kFlushItem = [&itemList, &currentItem]() {
                const auto kFirstIt = std::find_if_not(
                    currentItem.begin(),
                    currentItem.end(),
                    [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; });
                const auto kLastIt = std::find_if_not(
                    currentItem.rbegin(),
                    currentItem.rend(),
                    [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; }).base();
                if (kFirstIt < kLastIt)
                {
                    itemList.emplace_back(kFirstIt, kLastIt);
                }
                currentItem.clear();
            };

            for (const wchar_t kCh : listText)
            {
                if (kCh == L';' || kCh == L',' || kCh == L'\r' || kCh == L'\n')
                {
                    kFlushItem();
                    continue;
                }
                currentItem.push_back(kCh);
            }
            kFlushItem();
            return itemList;
        }
    }

    bool loadMonitorConfigForCurrentProcess(MonitorConfig* configOut, std::wstring* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (configOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"configOut is null.";
            }
            return false;
        }

        MonitorConfig configValue;
        configValue.targetPid = static_cast<std::uint32_t>(::GetCurrentProcessId());
        configValue.configPath = ks::winapi_monitor::buildConfigPathForPid(configValue.targetPid);

        const DWORD kFileAttributes = ::GetFileAttributesW(configValue.configPath.c_str());
        if (kFileAttributes == INVALID_FILE_ATTRIBUTES || (kFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"Monitor config file does not exist: " + configValue.configPath;
            }
            return false;
        }

        configValue.pipeName = queryIniText(
            configValue.configPath,
            L"pipe_name",
            ks::winapi_monitor::buildPipeNameForPid(configValue.targetPid).c_str());
        configValue.stopFlagPath = queryIniText(
            configValue.configPath,
            L"stop_flag_path",
            ks::winapi_monitor::buildStopFlagPathForPid(configValue.targetPid).c_str());
        configValue.sessionId = queryIniText(
            configValue.configPath,
            L"session_id",
            L"");
        configValue.agentDllPath = queryIniText(
            configValue.configPath,
            L"agent_dll_path",
            L"");
        configValue.enableFile = queryIniBool(configValue.configPath, L"enable_file", true);
        configValue.enableRegistry = queryIniBool(configValue.configPath, L"enable_registry", true);
        configValue.enableNetwork = queryIniBool(configValue.configPath, L"enable_network", true);
        configValue.enableProcess = queryIniBool(configValue.configPath, L"enable_process", true);
        configValue.enableLoader = queryIniBool(configValue.configPath, L"enable_loader", true);
        configValue.autoInjectChild = queryIniBool(configValue.configPath, L"auto_inject_child", false);
        configValue.enableRawFallback = queryIniBool(configValue.configPath, L"enable_raw_fallback", false);
        configValue.rawUseDefaultDenyList = queryIniBool(configValue.configPath, L"raw_use_default_denylist", true);
        configValue.rawModuleList = splitIniList(queryIniText(
            configValue.configPath,
            L"raw_modules",
            ks::winapi_monitor::kDefaultRawHookModules));
        // rawDenyList: reads only user-defined additional rules:
        // - Input: raw_denylist from the session INI;
        // - Handling: Stop writing built-in default denylists here to avoid accidentally overriding user-defined rules when raw_use_default_denylist=false.
        // - Returns: an empty configuration indicates "no additional rules"; built-in default rules are merged separately during the matching phase by HookTargets.cpp.
        configValue.rawDenyList = splitIniList(queryIniText(
            configValue.configPath,
            L"raw_denylist",
            L""));
        configValue.fakeSuccessEnabled = queryIniBool(configValue.configPath, L"fake_success_enabled", false);
        configValue.fakeSuccessRawFallback = queryIniBool(configValue.configPath, L"fake_success_raw_fallback", false);
        configValue.fakeSuccessRulesText = queryIniText(
            configValue.configPath,
            L"fake_success_rules",
            L"");
        configValue.fakeSuccessRules = parseFakeSuccessRules(configValue.fakeSuccessRulesText);

        const int kRawDetailLimit = static_cast<int>(::GetPrivateProfileIntW(
            L"monitor",
            L"detail_limit",
            static_cast<UINT>(ks::winapi_monitor::kMaxDetailChars - 1),
            configValue.configPath.c_str()));
        configValue.detailLimitChars = static_cast<std::size_t>(std::clamp(
            kRawDetailLimit,
            64,
            static_cast<int>(ks::winapi_monitor::kMaxDetailChars - 1)));

        configValue.valid = !configValue.pipeName.empty() && !configValue.stopFlagPath.empty();
        if (!configValue.valid)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"Monitor config missing required pipe_name or stop_flag_path.";
            }
            return false;
        }

        *configOut = configValue;
        return true;
    }

    bool isStopFlagPresent(const MonitorConfig& configValue)
    {
        if (configValue.stopFlagPath.empty())
        {
            return false;
        }

        const DWORD kFileAttributes = ::GetFileAttributesW(configValue.stopFlagPath.c_str());
        return kFileAttributes != INVALID_FILE_ATTRIBUTES && (kFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }
}
