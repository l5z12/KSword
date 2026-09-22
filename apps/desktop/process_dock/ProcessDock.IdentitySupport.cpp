#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    // formatProcessWin32Error:
    // - Input: stepText indicates the failed step, errorCode is the Win32 error code;
    // - Processing: Concatenate stable English step name with decimal error code to avoid cross-language system FormatMessage text differences.
    // - Returns: UTF-8 string directly writable to batch action detailText.
    std::string formatProcessWin32Error(const char* stepText, const DWORD errorCode)
    {
        std::ostringstream stream;
        stream << (stepText == nullptr ? "Win32 call" : stepText)
            << " failed, error=" << errorCode;
        return stream.str();
    }

    // acquireProcessActionIdentityHold: Reads the creation time on a process handle and passes the handle to the caller
    // to hold until the action completes. Based on the Windows PID lifecycle, the PID will not be reused for a different
    // process during this hold period; if the identity is incomplete or mismatched, the action is safely skipped.
    bool acquireProcessActionIdentityHold(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        HANDLE* const processHandleOut,
        std::string* const detailText)
    {
        if (processHandleOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = "process action identity output is null";
            }
            return false;
        }
        *processHandleOut = nullptr;
        if (pid == 0U || expectedCreationTime100ns == 0U)
        {
            if (detailText != nullptr)
            {
                *detailText = "process identity is unavailable; action skipped";
            }
            return false;
        }

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (processHandle == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error(
                    "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)",
                    ::GetLastError());
            }
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL kQueryOk = ::GetProcessTimes(
            processHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        const DWORD kQueryError = kQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        const std::uint64_t kActualCreationTime100ns = kQueryOk != FALSE
            ? (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
                static_cast<std::uint64_t>(creationTime.dwLowDateTime)
            : 0U;
        if (kQueryOk == FALSE ||
            kActualCreationTime100ns == 0U ||
            kActualCreationTime100ns != expectedCreationTime100ns)
        {
            ::CloseHandle(processHandle);
            if (detailText != nullptr)
            {
                *detailText = kQueryOk == FALSE
                    ? formatProcessWin32Error("GetProcessTimes", kQueryError)
                    : "process identity changed (PID was reused); action skipped";
            }
            return false;
        }

        *processHandleOut = processHandle;
        return true;
    }

    // enableProcessContextPrivilege:
    // - Input: privilegeName is the name of the privilege to be temporarily enabled for the current process
    // - Processing: Open the current process token and call AdjustTokenPrivileges.
    // - Returns: true if the privilege was enabled successfully; false indicates the current token lacks the privilege or enabling failed.
    bool enableProcessContextPrivilege(const wchar_t* privilegeName)
    {
        if (privilegeName == nullptr)
        {
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            ::CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        const BOOL kAdjustOk = ::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr);
        const DWORD kAdjustError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        return kAdjustOk != FALSE && kAdjustError == ERROR_SUCCESS;
    }

    // allocateMandatoryIntegritySid:
    // - Input: integrityRid is the Mandatory Label RID, e.g., Low/Medium/High.
    // - Processing: Construct an S-1-16-integrityRid SID; the caller is responsible for calling FreeSid.
    // - Returns: true on success with sidOut written; false on failure with detailText output.
    bool allocateMandatoryIntegritySid(
        const DWORD integrityRid,
        PSID* sidOut,
        std::string* detailText)
    {
        if (sidOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = "sidOut is null";
            }
            return false;
        }
        *sidOut = nullptr;

        SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        if (::AllocateAndInitializeSid(
            &mandatoryLabelAuthority,
            1,
            integrityRid,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            sidOut) == FALSE)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("AllocateAndInitializeSid", ::GetLastError());
            }
            return false;
        }
        return true;
    }

    // processIntegrityNameFromRid:
    // - Input: Mandatory Label RID;
    // - Processing: Prefer matching right-click menu presets; otherwise, fall back to RID hexadecimal text.
    // - Returns: display text for prompts, logs, and menu tooltips.
    QString processIntegrityNameFromRid(const DWORD integrityRid)
    {
        for (const ProcessIntegrityLevelPreset& preset : kProcessIntegrityLevelPresets)
        {
            if (preset.rid == integrityRid)
            {
                return QString::fromLatin1(preset.nameText);
            }
        }
        return QStringLiteral("RID=0x%1").arg(integrityRid, 0, 16).toUpper();
    }

    // queryProcessIntegrityRid:
    // - Input: pid is the target process ID;
    // - Processing: Open process token and read TokenIntegrityLevel to parse the last RID from S-1-16-*.
    // - Returns: true on success with ridOut populated; false on failure with a Win32 diagnostic message output.
    bool queryProcessIntegrityRid(
        const DWORD pid,
        DWORD* ridOut,
        std::string* detailText)
    {
        if (ridOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = "ridOut is null";
            }
            return false;
        }
        *ridOut = 0;

        (void)enableProcessContextPrivilege(SE_DEBUG_NAME);

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (processHandle == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)", ::GetLastError());
            }
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            const DWORD kOpenTokenError = ::GetLastError();
            ::CloseHandle(processHandle);
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("OpenProcessToken(TOKEN_QUERY)", kOpenTokenError);
            }
            return false;
        }

        DWORD requiredLength = 0;
        (void)::GetTokenInformation(tokenHandle, TokenIntegrityLevel, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            const DWORD kLengthError = ::GetLastError();
            ::CloseHandle(tokenHandle);
            ::CloseHandle(processHandle);
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("GetTokenInformation(TokenIntegrityLevel length)", kLengthError);
            }
            return false;
        }

        std::vector<BYTE> tokenBuffer(requiredLength);
        const BOOL kQueryOk = ::GetTokenInformation(
            tokenHandle,
            TokenIntegrityLevel,
            tokenBuffer.data(),
            requiredLength,
            &requiredLength);
        const DWORD kQueryError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        ::CloseHandle(processHandle);
        if (kQueryOk == FALSE)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("GetTokenInformation(TokenIntegrityLevel)", kQueryError);
            }
            return false;
        }

        const TOKEN_MANDATORY_LABEL* mandatoryLabel =
            reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(tokenBuffer.data());
        if (mandatoryLabel->Label.Sid == nullptr ||
            ::IsValidSid(mandatoryLabel->Label.Sid) == FALSE ||
            *::GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) == 0)
        {
            if (detailText != nullptr)
            {
                *detailText = "TokenIntegrityLevel returned an invalid SID";
            }
            return false;
        }

        *ridOut = *::GetSidSubAuthority(
            mandatoryLabel->Label.Sid,
            static_cast<DWORD>(*::GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) - 1));
        return true;
    }

    // setProcessIntegrityLevelByPid:
    // - Input: pid is the target process, integrityRid is the target Mandatory Label RID;
    // - Processing: Open the target token, construct a TOKEN_MANDATORY_LABEL, and call SetTokenInformation.
    // - Returns: true indicates the API accepted the write; false on failure with specific step errors output.
    bool setProcessIntegrityLevelByPid(
        const DWORD pid,
        const DWORD integrityRid,
        std::string* detailText)
    {
        (void)enableProcessContextPrivilege(SE_DEBUG_NAME);

        HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (processHandle == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)", ::GetLastError());
            }
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            const DWORD kOpenTokenError = ::GetLastError();
            ::CloseHandle(processHandle);
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("OpenProcessToken(TOKEN_ADJUST_DEFAULT)", kOpenTokenError);
            }
            return false;
        }

        PSID integritySid = nullptr;
        if (!allocateMandatoryIntegritySid(integrityRid, &integritySid, detailText))
        {
            ::CloseHandle(tokenHandle);
            ::CloseHandle(processHandle);
            return false;
        }

        TOKEN_MANDATORY_LABEL mandatoryLabel{};
        mandatoryLabel.Label.Attributes = SE_GROUP_INTEGRITY;
        mandatoryLabel.Label.Sid = integritySid;
        const DWORD kInformationLength =
            static_cast<DWORD>(sizeof(mandatoryLabel) + ::GetLengthSid(integritySid));
        const BOOL kSetOk = ::SetTokenInformation(
            tokenHandle,
            TokenIntegrityLevel,
            &mandatoryLabel,
            kInformationLength);
        const DWORD kSetError = ::GetLastError();
        ::FreeSid(integritySid);
        ::CloseHandle(tokenHandle);
        ::CloseHandle(processHandle);

        if (kSetOk == FALSE)
        {
            if (detailText != nullptr)
            {
                *detailText = formatProcessWin32Error("SetTokenInformation(TokenIntegrityLevel)", kSetError);
            }
            return false;
        }

        if (detailText != nullptr)
        {
            std::ostringstream stream;
            stream << "pid=" << pid
                << ", integrity=" << processIntegrityNameFromRid(integrityRid).toStdString()
                << ", rid=0x" << std::hex << integrityRid;
            *detailText = stream.str();
        }
        return true;
    }
}
