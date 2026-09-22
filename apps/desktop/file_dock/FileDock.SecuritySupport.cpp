#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    // sidUseToText:
    // Convert SID_NAME_USE enum to readable text.
    // - Used to display the principal type (user/group/domain, etc.) in the ACL list.
    QString sidUseToText(const SID_NAME_USE sidUse)
    {
        switch (sidUse)
        {
        case SidTypeUser: return QStringLiteral("User");
        case SidTypeGroup: return QStringLiteral("Group");
        case SidTypeDomain: return QStringLiteral("Domain");
        case SidTypeAlias: return QStringLiteral("Alias");
        case SidTypeWellKnownGroup: return QStringLiteral("WellKnownGroup");
        case SidTypeDeletedAccount: return QStringLiteral("DeletedAccount");
        case SidTypeInvalid: return QStringLiteral("Invalid");
        case SidTypeUnknown: return QStringLiteral("Unknown");
        case SidTypeComputer: return QStringLiteral("Computer");
        case SidTypeLabel: return QStringLiteral("Label");
        default: return QStringLiteral("Other");
        }
    }

    // sidToStringText:
    // - Convert PSID to standard string format (S-1-5-...).
    // - Return placeholder text containing error information on failure.
    QString sidToStringText(PSID sidValue)
    {
        if (sidValue == nullptr)
        {
            return QStringLiteral("<空SID>");
        }
        LPWSTR sidStringBuffer = nullptr;
        if (::ConvertSidToStringSidW(sidValue, &sidStringBuffer) == FALSE || sidStringBuffer == nullptr)
        {
            return QStringLiteral("<SID转换失败 code=%1>").arg(::GetLastError());
        }
        QString sidText = QString::fromWCharArray(sidStringBuffer);
        ::LocalFree(sidStringBuffer);
        return sidText;
    }

    // sidToAccountText:
    // - Parse the domain name and account name of the SID via LookupAccountSidW.
    // - Preserve error code on parse failure to facilitate permission audit localization.
    QString sidToAccountText(PSID sidValue)
    {
        if (sidValue == nullptr)
        {
            return QStringLiteral("<空SID>");
        }

        wchar_t accountBuffer[256] = {};
        wchar_t domainBuffer[256] = {};
        DWORD accountSize = static_cast<DWORD>(std::size(accountBuffer));
        DWORD domainSize = static_cast<DWORD>(std::size(domainBuffer));
        SID_NAME_USE sidUse = SidTypeUnknown;
        if (::LookupAccountSidW(
            nullptr,
            sidValue,
            accountBuffer,
            &accountSize,
            domainBuffer,
            &domainSize,
            &sidUse) == FALSE)
        {
            return QStringLiteral("<账户解析失败 code=%1>").arg(::GetLastError());
        }

        const QString kAccountText = QString::fromWCharArray(accountBuffer);
        const QString kDomainText = QString::fromWCharArray(domainBuffer);
        if (kDomainText.isEmpty())
        {
            return QStringLiteral("%1 (%2)").arg(kAccountText, sidUseToText(sidUse));
        }
        return QStringLiteral("%1\\%2 (%3)").arg(kDomainText, kAccountText, sidUseToText(sidUse));
    }

    // aceTypeToText:
    // - Converts ACE_HEADER::AceType to human-readable text.
    // - Uncovered types retain original numeric values to avoid data loss.
    QString aceTypeToText(const BYTE aceType)
    {
        switch (aceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE: return QStringLiteral("ACCESS_ALLOWED");
        case ACCESS_DENIED_ACE_TYPE: return QStringLiteral("ACCESS_DENIED");
        case SYSTEM_AUDIT_ACE_TYPE: return QStringLiteral("SYSTEM_AUDIT");
        case SYSTEM_ALARM_ACE_TYPE: return QStringLiteral("SYSTEM_ALARM");
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE: return QStringLiteral("ACCESS_ALLOWED_OBJECT");
        case ACCESS_DENIED_OBJECT_ACE_TYPE: return QStringLiteral("ACCESS_DENIED_OBJECT");
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE: return QStringLiteral("SYSTEM_AUDIT_OBJECT");
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE: return QStringLiteral("MANDATORY_LABEL");
        default:
            return QStringLiteral("ACE_%1").arg(aceType);
        }
    }

    // aceFlagsToText:
    // - Parse ACE inheritance and audit flag bits.
    // - Returns a composite text string separated by '|'.
    QString aceFlagsToText(const BYTE aceFlags)
    {
        QStringList flagList;
        if ((aceFlags & OBJECT_INHERIT_ACE) != 0) flagList << QStringLiteral("OBJECT_INHERIT");
        if ((aceFlags & CONTAINER_INHERIT_ACE) != 0) flagList << QStringLiteral("CONTAINER_INHERIT");
        if ((aceFlags & NO_PROPAGATE_INHERIT_ACE) != 0) flagList << QStringLiteral("NO_PROPAGATE");
        if ((aceFlags & INHERIT_ONLY_ACE) != 0) flagList << QStringLiteral("INHERIT_ONLY");
        if ((aceFlags & INHERITED_ACE) != 0) flagList << QStringLiteral("INHERITED");
        if ((aceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) != 0) flagList << QStringLiteral("AUDIT_SUCCESS");
        if ((aceFlags & FAILED_ACCESS_ACE_FLAG) != 0) flagList << QStringLiteral("AUDIT_FAIL");
        return flagList.isEmpty() ? QStringLiteral("None") : flagList.join('|');
    }

    // accessMaskToText:
    // - Decompose the file system access mask into common permission names.
    // - Retains both GENERIC_* and FILE_* fine-grained permissions.
    QString accessMaskToText(const DWORD accessMask)
    {
        QStringList rightList;
        if ((accessMask & GENERIC_ALL) != 0) rightList << QStringLiteral("GENERIC_ALL");
        if ((accessMask & GENERIC_READ) != 0) rightList << QStringLiteral("GENERIC_READ");
        if ((accessMask & GENERIC_WRITE) != 0) rightList << QStringLiteral("GENERIC_WRITE");
        if ((accessMask & GENERIC_EXECUTE) != 0) rightList << QStringLiteral("GENERIC_EXECUTE");
        if ((accessMask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) rightList << QStringLiteral("FILE_ALL_ACCESS");
        if ((accessMask & FILE_GENERIC_READ) == FILE_GENERIC_READ) rightList << QStringLiteral("FILE_GENERIC_READ");
        if ((accessMask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE) rightList << QStringLiteral("FILE_GENERIC_WRITE");
        if ((accessMask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE) rightList << QStringLiteral("FILE_GENERIC_EXECUTE");
        if ((accessMask & FILE_READ_DATA) != 0) rightList << QStringLiteral("READ_DATA");
        if ((accessMask & FILE_WRITE_DATA) != 0) rightList << QStringLiteral("WRITE_DATA");
        if ((accessMask & FILE_APPEND_DATA) != 0) rightList << QStringLiteral("APPEND_DATA");
        if ((accessMask & FILE_EXECUTE) != 0) rightList << QStringLiteral("EXECUTE");
        if ((accessMask & FILE_READ_ATTRIBUTES) != 0) rightList << QStringLiteral("READ_ATTRIBUTES");
        if ((accessMask & FILE_WRITE_ATTRIBUTES) != 0) rightList << QStringLiteral("WRITE_ATTRIBUTES");
        if ((accessMask & FILE_READ_EA) != 0) rightList << QStringLiteral("READ_EA");
        if ((accessMask & FILE_WRITE_EA) != 0) rightList << QStringLiteral("WRITE_EA");
        if ((accessMask & DELETE) != 0) rightList << QStringLiteral("DELETE");
        if ((accessMask & READ_CONTROL) != 0) rightList << QStringLiteral("READ_CONTROL");
        if ((accessMask & WRITE_DAC) != 0) rightList << QStringLiteral("WRITE_DAC");
        if ((accessMask & WRITE_OWNER) != 0) rightList << QStringLiteral("WRITE_OWNER");
        if ((accessMask & SYNCHRONIZE) != 0) rightList << QStringLiteral("SYNCHRONIZE");
        return rightList.isEmpty() ? QStringLiteral("None") : rightList.join('|');
    }

    // appendAclRows：
    // - Input scopeText/aclValue: ACL name and Windows ACL pointer.
    // - Processing: Parse supported ACE structures and convert them to UI table rows; unknown ACEs still appear in the text details.
    // - Returns: void; appends the parsed rows to rowsOut.
    void appendAclRows(const QString& scopeText, PACL aclValue, std::vector<FileSecurityAceRow>& rowsOut)
    {
        if (aclValue == nullptr)
        {
            return;
        }

        ACL_SIZE_INFORMATION aclSizeInfo{};
        if (::GetAclInformation(
            aclValue,
            &aclSizeInfo,
            static_cast<DWORD>(sizeof(aclSizeInfo)),
            AclSizeInformation) == FALSE)
        {
            return;
        }

        for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
        {
            LPVOID acePointer = nullptr;
            if (::GetAce(aclValue, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
            {
                continue;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            DWORD accessMask = 0;
            PSID aceSid = nullptr;
            bool editableAce = false;

            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                editableAce = scopeText == QStringLiteral("DACL") && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                break;
            }
            case ACCESS_DENIED_ACE_TYPE:
            {
                ACCESS_DENIED_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                editableAce = scopeText == QStringLiteral("DACL") && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                break;
            }
            case SYSTEM_AUDIT_ACE_TYPE:
            {
                SYSTEM_AUDIT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            {
                ACCESS_ALLOWED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
            {
                ACCESS_DENIED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            {
                SYSTEM_AUDIT_OBJECT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            default:
                break;
            }

            FileSecurityAceRow row;
            row.scopeText = scopeText;
            row.typeText = aceTypeToText(aceHeader->AceType);
            row.flagsText = aceFlagsToText(aceHeader->AceFlags);
            row.mask = accessMask;
            row.rightsText = accessMaskToText(accessMask);
            row.sidText = sidToStringText(aceSid);
            row.accountText = sidToAccountText(aceSid);
            row.aceIndex = aceIndex;
            row.canEdit = editableAce && aceSid != nullptr;
            rowsOut.push_back(row);
        }
    }

    // createReadonlyTableItem：
    // - Input cellText: Text to be displayed.
    // - Processing: Create non-editable table items to prevent accidental edits in the permissions table.
    // - Return: Creates a new QTableWidgetItem, with the table assuming ownership of its lifetime.
    QTableWidgetItem* createReadonlyTableItem(const QString& cellText)
    {
        QTableWidgetItem* item = new QTableWidgetItem(cellText);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // formatAccessMaskHex：
    // - Input: accessMask - Win32 file access mask.
    // - Processing: Uniformly format as 8-digit hexadecimal.
    // - Returns: Uppercase text with '0x' prefix.
    QString formatAccessMaskHex(const DWORD accessMask)
    {
        return QStringLiteral("0x%1")
            .arg(accessMask, 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // appendAclText:
    // - Parse each ACE in the ACL, outputting type, flags, mask, SID, and account name.
    // - titleText distinguishes between DACL and SACL sections.
    void appendAclText(const QString& titleText, PACL aclValue, QString& contentOut)
    {
        contentOut += QStringLiteral("\n[%1]\n").arg(titleText);
        if (aclValue == nullptr)
        {
            contentOut += QStringLiteral("ACL: <null>\n");
            return;
        }

        ACL_SIZE_INFORMATION aclSizeInfo{};
        if (::GetAclInformation(
            aclValue,
            &aclSizeInfo,
            static_cast<DWORD>(sizeof(aclSizeInfo)),
            AclSizeInformation) == FALSE)
        {
            contentOut += QStringLiteral("读取 ACL 信息失败, code=%1\n").arg(::GetLastError());
            return;
        }

        contentOut += QStringLiteral("ACE数量: %1\n").arg(aclSizeInfo.AceCount);
        for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
        {
            LPVOID acePointer = nullptr;
            if (::GetAce(aclValue, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
            {
                contentOut += QStringLiteral("  - ACE[%1] 读取失败, code=%2\n").arg(aceIndex).arg(::GetLastError());
                continue;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            DWORD accessMask = 0;
            PSID aceSid = nullptr;

            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_ACE_TYPE:
            {
                ACCESS_DENIED_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_ACE_TYPE:
            {
                SYSTEM_AUDIT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            {
                ACCESS_ALLOWED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
            {
                ACCESS_DENIED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            {
                SYSTEM_AUDIT_OBJECT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            default:
                break;
            }

            contentOut += QStringLiteral("  - ACE[%1]\n").arg(aceIndex);
            contentOut += QStringLiteral("    类型: %1\n").arg(aceTypeToText(aceHeader->AceType));
            contentOut += QStringLiteral("    标志: %1\n").arg(aceFlagsToText(aceHeader->AceFlags));
            contentOut += QStringLiteral("    Mask: 0x%1\n").arg(accessMask, 8, 16, QLatin1Char('0'));
            contentOut += QStringLiteral("    权限: %1\n").arg(accessMaskToText(accessMask));
            contentOut += QStringLiteral("    SID: %1\n").arg(sidToStringText(aceSid));
            contentOut += QStringLiteral("    账户: %1\n").arg(sidToAccountText(aceSid));
        }
    }
}
