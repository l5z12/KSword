#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <cstring>
#include <iostream>
#include "../../../apps/desktop/other_dock/DwmAgentDeployment.h"

namespace
{
    std::wstring dacl(const std::wstring& path)
    {
        PSECURITY_DESCRIPTOR security = nullptr;
        if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr, &security)) return {};
        LPWSTR text = nullptr;
        std::wstring value;
        if (ConvertSecurityDescriptorToStringSecurityDescriptorW(security, SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION, &text, nullptr)) { value = text; LocalFree(text); }
        LocalFree(security);
        return value;
    }

    bool readerAccess(const std::wstring& path, PSID sid)
    {
        PACL acl = nullptr;
        PSECURITY_DESCRIPTOR security = nullptr;
        if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &acl, nullptr, &security)) return false;
        DWORD granted = 0;
        bool valid = acl != nullptr;
        for (DWORD i = 0; acl && i < acl->AceCount; ++i)
        {
            void* entry = nullptr;
            if (!GetAce(acl, i, &entry)) { valid = false; break; }
            const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
            if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !(ace->Header.AceFlags & INHERITED_ACE)
                && EqualSid(const_cast<DWORD*>(&ace->SidStart), sid)) granted |= ace->Mask;
        }
        LocalFree(security);
        return valid && granted == (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
    }

    std::vector<unsigned char> contents(const std::wstring& path)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return {};
        const DWORD kSize = GetFileSize(file, nullptr);
        std::vector<unsigned char> data;
        if (kSize && kSize <= 64 * 1024 * 1024)
        {
            data.resize(kSize);
            DWORD read = 0;
            if (!ReadFile(file, data.data(), kSize, &read, nullptr) || read != kSize) data.clear();
        }
        CloseHandle(file);
        return data;
    }
}

ks::dwm_order::transport::PreparedAgent runDeploymentTests(void (*check)(bool, const char*), const wchar_t* agentPath)
{
    using namespace ks::dwm_order::transport;
    PreparedAgent prepared;
    std::vector<unsigned char> currentUser;
    check(readProcessUserSid(GetCurrentProcess(), currentUser) == ERROR_SUCCESS && !currentUser.empty(),
        "read the target process primary user SID without impersonation");
    PSID reader = nullptr;
    check(ConvertStringSidToSidW(L"S-1-5-90-0", &reader) != FALSE, "construct a separate Window Manager reader SID");
    if (!reader) return prepared;
    std::vector<unsigned char> readerSid(GetLengthSid(reader));
    std::memcpy(readerSid.data(), reader, readerSid.size());
    const auto kOriginalDacl = dacl(agentPath);
    const DWORD kError = prepareAgentCopy(agentPath, readerSid, prepared);
    std::cout << "DEPLOYMENT_WIN32=" << kError << '\n';
    check(!kOriginalDacl.empty() && !kError && prepared.lease && prepared.path != agentPath,
        "prepare a verified sidecar copy of the agent");
    check(dacl(agentPath) == kOriginalDacl, "deployment does not change the source DLL permissions");
    if (!kError)
    {
        const auto kVersion = prepared.path.substr(0, prepared.path.find_last_of(L'\\'));
        const auto kRoot = kVersion.substr(0, kVersion.find_last_of(L'\\'));
        check(readerAccess(kRoot, reader) && readerAccess(kVersion, reader) && readerAccess(prepared.path, reader),
            "only read and execute rights are explicitly granted to the reader on the managed copy and directories");
        const auto kOriginal = contents(agentPath);
        check(!kOriginal.empty() && contents(prepared.path) == kOriginal, "deployed agent bytes exactly match the source");
        HANDLE replace = CreateFileW(prepared.path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const DWORD kReplaceError = GetLastError();
        check(replace == INVALID_HANDLE_VALUE && kReplaceError == ERROR_SHARING_VIOLATION,
            "deployment lease prevents replacing the DLL during loading");
        if (replace != INVALID_HANDLE_VALUE) CloseHandle(replace);
        PreparedAgent repeated;
        check(prepareAgentCopy(agentPath, readerSid, repeated) == ERROR_SUCCESS && repeated.path == prepared.path,
            "unchanged agent content reuses the existing verified copy");
        wchar_t absoluteSource[MAX_PATH]{}, absoluteCopy[MAX_PATH]{}, currentDirectory[32768]{};
        const DWORD kSourceLength = GetFullPathNameW(agentPath, MAX_PATH, absoluteSource, nullptr);
        const DWORD kCopyLength = GetFullPathNameW(prepared.path.c_str(), MAX_PATH, absoluteCopy, nullptr);
        const DWORD kDirectoryLength = GetCurrentDirectoryW(32768, currentDirectory);
        check(kCopyLength && kCopyLength < MAX_PATH && prepared.path == absoluteCopy,
            "deployment publishes a fully qualified path for DLL_LOAD_DIR");
        const bool kPathsReady = kSourceLength && kSourceLength < MAX_PATH
            && kDirectoryLength && kDirectoryLength < 32768;
        check(kPathsReady, "capture absolute source and caller directory for relative-path regression");
        if (kPathsReady)
        {
            const std::wstring kSourcePath(absoluteSource);
            const auto kSeparator = kSourcePath.find_last_of(L'\\');
            const auto kName = kSourcePath.substr(kSeparator + 1);
            const bool kChanged = SetCurrentDirectoryW(kSourcePath.substr(0, kSeparator).c_str()) != FALSE;
            check(kChanged, "enter source directory to test bare and relative DLL names");
            if (kChanged)
            {
                for (const auto& alias : {kName, L".\\" + kName, L"./" + kName})
                {
                    PreparedAgent relative;
                    check(prepareAgentCopy(alias, readerSid, relative) == ERROR_SUCCESS
                        && relative.path == prepared.path && relative.lease,
                        "bare, backslash and forward-slash paths reuse the same absolute agent copy");
                }
                check(SetCurrentDirectoryW(currentDirectory) != FALSE,
                    "restore caller directory before remote loading from a different child directory");
            }
        }
        PreparedAgent invalid;
        check(prepareAgentCopy(agentPath, {}, invalid) == ERROR_INVALID_SID && invalid.path.empty(),
            "missing target SID is rejected without preparing another copy");
        for (const auto& invalidPath : {std::wstring(), std::wstring(agentPath) + L'\0' + L"suffix"})
        {
            invalid = prepared;
            check(prepareAgentCopy(invalidPath, readerSid, invalid) == ERROR_BAD_PATHNAME
                && invalid.path.empty() && !invalid.lease,
                "empty and embedded-NUL paths are rejected without retaining a stale deployment");
        }
    }
    LocalFree(reader);
    return prepared;
}
