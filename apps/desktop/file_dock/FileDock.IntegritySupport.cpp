#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    // isSupportedFileMandatoryIntegrityRid:
    // - Input: integrityRid is the S-1-16-* RID intended to be written to the file/directory Mandatory Label.
    // - Handling: Only MIC levels acceptable to Windows file objects are allowed. ProtectedProcess/SecureProcess are
    //   token/process semantics; writing to a file SACL will be rejected by the kernel security API as STATUS_INVALID_LABEL.
    // - Return: true indicates it is safe to proceed with R0/R3 writes to LABEL_SECURITY_INFORMATION; false indicates the frontend should reject directly.
    bool isSupportedFileMandatoryIntegrityRid(const DWORD integrityRid)
    {
        for (const FileIntegrityLevelPreset& preset : kFileIntegrityLevelPresets)
        {
            if (preset.rid == integrityRid)
            {
                return true;
            }
        }
        return false;
    }

    // formatFileWin32Error:
    // - Input: stepText indicates the failed step, errorCode is the Win32 error code;
    // - Processing: Generate stable error text to avoid inconsistencies in FormatMessage output across different system languages.
    // - Returns: A QString ready for display and logging.
    QString formatFileWin32Error(const QString& stepText, const DWORD errorCode)
    {
        return QStringLiteral("%1 failed, error=%2").arg(stepText).arg(errorCode);
    }

    // enableFileContextPrivilege:
    // - Input: privilegeName is the privilege name in the current process token, e.g., SeSecurityPrivilege.
    // - Processing: Temporarily enable existing privileges on the current process token; silently fail if the privilege is not present.
    // - Returns: true if AdjustTokenPrivileges successfully enabled the privilege; false if it failed.
    bool enableFileContextPrivilege(const wchar_t* privilegeName)
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

    // allocateFileMandatoryIntegritySid:
    // - Input: integrityRid is the Mandatory Label RID;
    // - Processing: Construct S-1-16-integrityRid SID; caller is responsible for FreeSid.
    // - Returns: true on success with sidOut written; false on failure with detailText output.
    bool allocateFileMandatoryIntegritySid(
        const DWORD integrityRid,
        PSID* sidOut,
        QString* detailText)
    {
        if (sidOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("sidOut is null");
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
                *detailText = formatFileWin32Error(
                    QStringLiteral("AllocateAndInitializeSid"),
                    ::GetLastError());
            }
            return false;
        }
        return true;
    }

    // fileIntegrityNameFromRid:
    // - Input: Mandatory Label RID;
    // - Processing: Prefer matching menu preset, otherwise degrade to hexadecimal RID;
    // - Returns: Short name for menus, message boxes, and logs.
    QString fileIntegrityNameFromRid(const DWORD integrityRid)
    {
        for (const FileIntegrityLevelPreset& preset : kFileIntegrityLevelPresets)
        {
            if (preset.rid == integrityRid)
            {
                return QString::fromLatin1(preset.nameText);
            }
        }
        return QStringLiteral("RID=0x%1").arg(integrityRid, 0, 16).toUpper();
    }

    // queryFileIntegrityRid:
    // - Input: filePath is the file or directory path;
    // - Handling: Read LABEL_SECURITY_INFORMATION and scan for SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    // - Returns: true on success with ridOut populated; if no explicit label exists, defaults to Windows Medium.
    bool queryFileIntegrityRid(
        const QString& filePath,
        DWORD* ridOut,
        bool* implicitMediumOut,
        QString* detailText)
    {
        if (ridOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("ridOut is null");
            }
            return false;
        }
        *ridOut = 0;
        if (implicitMediumOut != nullptr)
        {
            *implicitMediumOut = false;
        }

        (void)enableFileContextPrivilege(SE_SECURITY_NAME);

        std::wstring pathBuffer = QDir::toNativeSeparators(filePath).toStdWString();
        PACL labelAcl = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        const DWORD kQueryResult = ::GetNamedSecurityInfoW(
            pathBuffer.data(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            nullptr,
            &labelAcl,
            &securityDescriptor);
        if (kQueryResult != ERROR_SUCCESS)
        {
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(
                    QStringLiteral("GetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)"),
                    kQueryResult);
            }
            return false;
        }

        bool foundLabel = false;
        DWORD foundRid = SECURITY_MANDATORY_MEDIUM_RID;
        if (labelAcl != nullptr)
        {
            ACL_SIZE_INFORMATION aclSizeInfo{};
            if (::GetAclInformation(
                labelAcl,
                &aclSizeInfo,
                static_cast<DWORD>(sizeof(aclSizeInfo)),
                AclSizeInformation) != FALSE)
            {
                for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
                {
                    LPVOID acePointer = nullptr;
                    if (::GetAce(labelAcl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                    {
                        continue;
                    }

                    const ACE_HEADER* aceHeader = reinterpret_cast<const ACE_HEADER*>(acePointer);
                    if (aceHeader->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
                    {
                        continue;
                    }

                    const ACCESS_ALLOWED_ACE* mandatoryAce =
                        reinterpret_cast<const ACCESS_ALLOWED_ACE*>(acePointer);
                    PSID labelSid = const_cast<DWORD*>(&mandatoryAce->SidStart);
                    if (labelSid == nullptr ||
                        ::IsValidSid(labelSid) == FALSE ||
                        *::GetSidSubAuthorityCount(labelSid) == 0)
                    {
                        continue;
                    }

                    foundRid = *::GetSidSubAuthority(
                        labelSid,
                        static_cast<DWORD>(*::GetSidSubAuthorityCount(labelSid) - 1));
                    foundLabel = true;
                    break;
                }
            }
        }

        if (securityDescriptor != nullptr)
        {
            ::LocalFree(securityDescriptor);
        }

        *ridOut = foundRid;
        if (!foundLabel && implicitMediumOut != nullptr)
        {
            *implicitMediumOut = true;
        }
        if (detailText != nullptr)
        {
            *detailText = foundLabel
                ? QStringLiteral("explicit label=%1").arg(fileIntegrityNameFromRid(foundRid))
                : QStringLiteral("no explicit mandatory label; using implicit Medium");
        }
        return true;
    }

    // setFileIntegrityLevelByPath:
    // - Input: filePath is the path to the file or directory, and integrityRid is the target Mandatory Label RID.
    // - Processing: Construct an ACL containing only a Mandatory Label ACE and write it using LABEL_SECURITY_INFORMATION.
    // - Return: ERROR_SUCCESS indicates successful write; on failure, detailText contains Win32 diagnostics.
    DWORD setFileIntegrityLevelByPath(
        const QString& filePath,
        const DWORD integrityRid,
        QString* detailText)
    {
        if (!isSupportedFileMandatoryIntegrityRid(integrityRid))
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("unsupported file mandatory label RID=0x%1; "
                    "ProtectedProcess/SecureProcess labels are token-only and cannot be written to file objects")
                    .arg(integrityRid, 0, 16);
            }
            return ERROR_INVALID_PARAMETER;
        }

        (void)enableFileContextPrivilege(SE_SECURITY_NAME);
        (void)enableFileContextPrivilege(SE_RESTORE_NAME);

        PSID integritySid = nullptr;
        QString sidDetailText;
        if (!allocateFileMandatoryIntegritySid(integrityRid, &integritySid, &sidDetailText))
        {
            DWORD sidError = ::GetLastError();
            if (sidError == ERROR_SUCCESS)
            {
                sidError = ERROR_INVALID_SID;
            }
            if (detailText != nullptr)
            {
                *detailText = sidDetailText;
            }
            return sidError;
        }

        const DWORD kSidLength = ::GetLengthSid(integritySid);
        const DWORD kAclBytes = static_cast<DWORD>(
            sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + kSidLength);
        PACL labelAcl = reinterpret_cast<PACL>(::LocalAlloc(LPTR, kAclBytes));
        if (labelAcl == nullptr)
        {
            const DWORD kAllocError = ::GetLastError();
            ::FreeSid(integritySid);
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("LocalAlloc(ACL)"), kAllocError);
            }
            return kAllocError;
        }

        DWORD result = ERROR_SUCCESS;
        if (::InitializeAcl(labelAcl, kAclBytes, ACL_REVISION) == FALSE)
        {
            result = ::GetLastError();
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("InitializeAcl"), result);
            }
        }
        else if (::AddMandatoryAce(
            labelAcl,
            ACL_REVISION,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            integritySid) == FALSE)
        {
            result = ::GetLastError();
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("AddMandatoryAce"), result);
            }
        }
        else
        {
            std::wstring pathBuffer = QDir::toNativeSeparators(filePath).toStdWString();
            result = ::SetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                nullptr,
                labelAcl);
            if (detailText != nullptr)
            {
                *detailText = result == ERROR_SUCCESS
                    ? QStringLiteral("已写入文件完整性：%1，RID=0x%2，路径=%3")
                        .arg(fileIntegrityNameFromRid(integrityRid))
                        .arg(integrityRid, 0, 16)
                        .arg(QDir::toNativeSeparators(filePath))
                    : formatFileWin32Error(
                        QStringLiteral("SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)"),
                        result);
            }
        }

        ::LocalFree(labelAcl);
        ::FreeSid(integritySid);
        return result;
    }
}
