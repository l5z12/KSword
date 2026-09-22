#include "OtherDock.h"
#include "../Theme.h"
#include "../ui/TableInteractionSupport.h"

// ============================================================
// OtherDock.Desktop.cpp
// Purpose:
// 1) Split the window station/desktop enumeration logic for the 'Desktop Management' page in OtherDock;
// 2) Supplement display of window station, desktop, SessionId, owner SID, desktop heap, and switching capabilities;
// 3) Keep SwitchDesktop logic scoped to the current process window station to avoid affecting the Qt main interface context.
// ============================================================

#include <QColor>
#include <QFont>
#include <QLabel>
#include <QPointer>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <vector>

namespace
{
    // Desktop management table column indices:
    // - Maintain column order uniformly to avoid scattering magic numbers in refresh and switch logic.
    // - The current column definition covers Window Station, Desktop, SessionId, SID, and remarks.
    constexpr int kDesktopColumnWindowStation = 0;
    constexpr int kDesktopColumnDesktopName = 1;
    constexpr int kDesktopColumnCurrentWindowStation = 2;
    constexpr int kDesktopColumnCurrentDesktop = 3;
    constexpr int kDesktopColumnInteractive = 4;
    constexpr int kDesktopColumnReadable = 5;
    constexpr int kDesktopColumnSwitchable = 6;
    constexpr int kDesktopColumnSessionId = 7;
    constexpr int kDesktopColumnOwner = 8;
    constexpr int kDesktopColumnSid = 9;
    constexpr int kDesktopColumnSidDetail = 10;
    constexpr int kDesktopColumnHeapKb = 11;
    constexpr int kDesktopColumnRemark = 12;

    // item data role：
    // - Attach window station name, desktop name, and 'is current window station' metadata to table rows.
    // - switchToSelectedDesktop directly reuses this data to perform target validation.
    constexpr int kDesktopRoleWindowStationName = Qt::UserRole;
    constexpr int kDesktopRoleDesktopName = Qt::UserRole + 1;
    constexpr int kDesktopRoleIsCurrentWindowStation = Qt::UserRole + 2;
    constexpr int kDesktopRoleOwnerSidText = Qt::UserRole + 3;
    constexpr int kDesktopRoleOwnerSidDetailText = Qt::UserRole + 4;

    // DesktopCapabilityState：
    // - Represents the test result for 'readable/toggleable' capabilities.
    // - Unknown indicates untested or actively skipped due to unsafe current context.
    enum class DesktopCapabilityState
    {
        kUnknown = 0,
        kYes,
        kNo
    };

    // SidDescription：
    // - Purpose: Uniformly hold account names, SID strings, and SID structure details.
    // - Usage: Reuse the resolved owner of the window station/desktop object for table columns and the right-click menu.
    struct SidDescription
    {
        QString accountText; // accountText: readable name in domain\account format.
        QString sidText;     // sidText: SID string in S-1-5-... format.
        QString detailText;  // detailText: Detailed information such as SID type, organization, and sub-permissions.
    };

    // DesktopOpenResult：
    // - Purpose: Uniformly describe the result of the OpenDesktopW attempt.
    // - Call: Both capability detection and switching capability detection are reused.
    struct DesktopOpenResult
    {
        HDESK desktopHandle = nullptr; // desktopHandle: Desktop handle returned upon successful opening.
        QString methodText;            // methodText: Description of the method used upon success.
        QString detailText;            // detailText: Details on failure or process.
    };

    // DesktopRowData：
    // - Purpose: Cache single-row window station/desktop records, then write them uniformly to QTableWidget;
    // - ownerAccountText / ownerSidText prioritize displaying the desktop object owner; fall back to the window station owner on failure.
    struct DesktopRowData
    {
        QString windowStationName;                          // windowStationName: Window station name.
        QString desktopName;                                // desktopName: The desktop name.
        bool isCurrentWindowStation = false;                // isCurrentWindowStation: Indicates whether the current process is in the current window station.
        bool isCurrentDesktop = false;                      // isCurrentDesktop: whether it is the desktop where the current thread resides.
        bool isInteractiveWindowStation = false;            // isInteractiveWindowStation: whether the window station is visible/interactive.
        bool inputDesktopKnown = false;                     // inputDesktopKnown: Whether the desktop input capability was successfully read.
        bool inputDesktopEnabled = false;                   // inputDesktopEnabled: Whether the desktop receives input.
        DesktopCapabilityState readCapability = DesktopCapabilityState::kUnknown;     // readCapability: Desktop readability test result.
        DesktopCapabilityState switchCapability = DesktopCapabilityState::kUnknown;   // switchCapability: Desktop switch test result.
        std::uint32_t sessionId = std::numeric_limits<std::uint32_t>::max();         // sessionId: Current process session ID.
        QString ownerAccountText;                           // ownerAccountText: The owner account name.
        QString ownerSidText;                               // ownerSidText: The owner SID text.
        QString ownerSidDetailText;                         // ownerSidDetailText: Details on SID type, authority, sub-privileges, etc.
        QString heapSizeText;                               // heapSizeText: desktop heap size (KB).
        QString remarkText;                                 // remarkText: Comprehensive remarks (flags, errors, restrictions).
    };

    // capabilityStateText: Converts DesktopCapabilityState to Chinese text.
    QString capabilityStateText(const DesktopCapabilityState capabilityState)
    {
        switch (capabilityState)
        {
        case DesktopCapabilityState::kYes:
            return QStringLiteral("是");
        case DesktopCapabilityState::kNo:
            return QStringLiteral("否");
        default:
            return QStringLiteral("未测");
        }
    }

    // queryUserObjectName: Read the name of a window station or desktop object.
    QString queryUserObjectName(HANDLE userObjectHandle)
    {
        if (userObjectHandle == nullptr)
        {
            return QString();
        }

        // requiredBytes: API-estimated buffer size in bytes, used for subsequent wchar_t buffer allocation.
        DWORD requiredBytes = 0;
        ::GetUserObjectInformationW(userObjectHandle, UOI_NAME, nullptr, 0, &requiredBytes);
        if (requiredBytes < sizeof(wchar_t))
        {
            return QString();
        }

        // nameBuffer: Holds the UOI_NAME query result, with an extra reserved position for the null terminator.
        std::vector<wchar_t> nameBuffer(requiredBytes / sizeof(wchar_t) + 1, L'\0');
        const BOOL kQueryOk = ::GetUserObjectInformationW(
            userObjectHandle,
            UOI_NAME,
            nameBuffer.data(),
            static_cast<DWORD>(nameBuffer.size() * sizeof(wchar_t)),
            &requiredBytes);
        if (kQueryOk == FALSE)
        {
            return QString();
        }

        return QString::fromWCharArray(nameBuffer.data()).trimmed();
    }

    // queryUserObjectFlags: Read USEROBJECTFLAGS.
    bool queryUserObjectFlags(HANDLE userObjectHandle, USEROBJECTFLAGS& userObjectFlagsOut)
    {
        DWORD returnedBytes = 0;
        const BOOL kQueryOk = ::GetUserObjectInformationW(
            userObjectHandle,
            UOI_FLAGS,
            &userObjectFlagsOut,
            sizeof(userObjectFlagsOut),
            &returnedBytes);
        return kQueryOk != FALSE && returnedBytes >= sizeof(userObjectFlagsOut);
    }

    // queryDesktopInputState: read whether the desktop accepts input.
    bool queryDesktopInputState(HDESK desktopHandle, bool& inputEnabledOut)
    {
        BOOL inputEnabled = FALSE;
        DWORD returnedBytes = 0;
        const BOOL kQueryOk = ::GetUserObjectInformationW(
            desktopHandle,
            UOI_IO,
            &inputEnabled,
            sizeof(inputEnabled),
            &returnedBytes);
        if (kQueryOk == FALSE || returnedBytes < sizeof(inputEnabled))
        {
            return false;
        }

        inputEnabledOut = inputEnabled != FALSE;
        return true;
    }

    // formatUserObjectFlags: Formats USEROBJECTFLAGS into text.
    QString formatUserObjectFlags(
        const USEROBJECTFLAGS& userObjectFlagsValue,
        const bool treatAsWindowStation)
    {
        QStringList flagTextList;
        if (userObjectFlagsValue.fInherit != FALSE)
        {
            flagTextList << QStringLiteral("可继承");
        }
        if (treatAsWindowStation && (userObjectFlagsValue.dwFlags & WSF_VISIBLE) != 0)
        {
            flagTextList << QStringLiteral("可见/交互式");
        }
        if (flagTextList.isEmpty())
        {
            flagTextList << QStringLiteral("无特殊标志");
        }
        return flagTextList.join(QStringLiteral(" | "));
    }

    // sidToStringText: Converts a binary SID to an S-1-5-... string.
    QString sidToStringText(PSID sidValue)
    {
        if (sidValue == nullptr)
        {
            return QStringLiteral("-");
        }

        LPWSTR sidStringBuffer = nullptr;
        if (::ConvertSidToStringSidW(sidValue, &sidStringBuffer) == FALSE || sidStringBuffer == nullptr)
        {
            return QStringLiteral("<SID转换失败:%1>").arg(::GetLastError());
        }

        // sidText: Managed SID text; immediately free the Win32-allocated buffer.
        const QString kSidText = QString::fromWCharArray(sidStringBuffer);
        ::LocalFree(sidStringBuffer);
        return kSidText;
    }

    // sidUseToText: Converts SID_NAME_USE enumeration values to Chinese text.
    QString sidUseToText(const SID_NAME_USE sidUse)
    {
        switch (sidUse)
        {
        case SidTypeUser: return QStringLiteral("用户");
        case SidTypeGroup: return QStringLiteral("组");
        case SidTypeDomain: return QStringLiteral("域");
        case SidTypeAlias: return QStringLiteral("别名");
        case SidTypeWellKnownGroup: return QStringLiteral("众所周知组");
        case SidTypeDeletedAccount: return QStringLiteral("已删除账户");
        case SidTypeInvalid: return QStringLiteral("无效");
        case SidTypeUnknown: return QStringLiteral("未知");
        case SidTypeComputer: return QStringLiteral("计算机");
        case SidTypeLabel: return QStringLiteral("完整性标签");
        default:
            return QStringLiteral("未识别类型");
        }
    }

    // sidIdentifierAuthorityText: extracts the Identifier Authority from the SID.
    QString sidIdentifierAuthorityText(PSID sidValue)
    {
        if (sidValue == nullptr || ::IsValidSid(sidValue) == FALSE)
        {
            return QStringLiteral("<无效机构>");
        }

        // authorityValue: Convert the 6-byte Identifier Authority to decimal text.
        const SID_IDENTIFIER_AUTHORITY* authorityValue = ::GetSidIdentifierAuthority(sidValue);
        unsigned long long authorityNumber = 0;
        for (int i = 0; i < 6; ++i)
        {
            authorityNumber = (authorityNumber << 8) | authorityValue->Value[i];
        }
        return QString::number(authorityNumber);
    }

    // sidSubAuthorityText: Extract the SID sub-authority chain.
    QString sidSubAuthorityText(PSID sidValue)
    {
        if (sidValue == nullptr || ::IsValidSid(sidValue) == FALSE)
        {
            return QStringLiteral("<无效子权限>");
        }

        QStringList subAuthorityTextList;
        const UCHAR kSubAuthorityCount = *::GetSidSubAuthorityCount(sidValue);
        for (UCHAR i = 0; i < kSubAuthorityCount; ++i)
        {
            subAuthorityTextList << QString::number(*::GetSidSubAuthority(sidValue, i));
        }
        return subAuthorityTextList.isEmpty()
            ? QStringLiteral("<空>")
            : subAuthorityTextList.join(',');
    }

    // describeSid: Parses the raw SID into 'account name + SID + structural details'.
    SidDescription describeSid(PSID sidValue)
    {
        SidDescription sidDescription;
        if (sidValue == nullptr || ::IsValidSid(sidValue) == FALSE)
        {
            sidDescription.accountText = QStringLiteral("-");
            sidDescription.sidText = QStringLiteral("-");
            sidDescription.detailText = QStringLiteral("<无效SID>");
            return sidDescription;
        }

        sidDescription.sidText = sidToStringText(sidValue);

        // First perform a round of empty buffer queries to obtain the character counts required for the name and domain.
        DWORD accountNameLength = 0;
        DWORD domainNameLength = 0;
        SID_NAME_USE sidUse = SidTypeUnknown;
        ::LookupAccountSidW(
            nullptr,
            sidValue,
            nullptr,
            &accountNameLength,
            nullptr,
            &domainNameLength,
            &sidUse);
        const DWORD kFirstLookupError = ::GetLastError();

        if (kFirstLookupError == ERROR_INSUFFICIENT_BUFFER || kFirstLookupError == ERROR_SUCCESS)
        {
            std::vector<wchar_t> accountNameBuffer(accountNameLength + 1, L'\0');
            std::vector<wchar_t> domainNameBuffer(domainNameLength + 1, L'\0');
            const BOOL kLookupOk = ::LookupAccountSidW(
                nullptr,
                sidValue,
                accountNameBuffer.data(),
                &accountNameLength,
                domainNameBuffer.data(),
                &domainNameLength,
                &sidUse);
            if (kLookupOk != FALSE)
            {
                const QString kDomainName = QString::fromWCharArray(domainNameBuffer.data()).trimmed();
                const QString kAccountName = QString::fromWCharArray(accountNameBuffer.data()).trimmed();
                sidDescription.accountText = kDomainName.isEmpty()
                    ? (kAccountName.isEmpty() ? QStringLiteral("<空账户名>") : kAccountName)
                    : QStringLiteral("%1\\%2").arg(kDomainName, kAccountName);
            }
        }

        if (sidDescription.accountText.isEmpty())
        {
            sidDescription.accountText = QStringLiteral("<账户解析失败:%1>").arg(kFirstLookupError);
        }

        sidDescription.detailText = QStringLiteral("类型=%1；修订=%2；机构=%3；子权限=%4")
            .arg(sidUseToText(sidUse))
            .arg(static_cast<int>(reinterpret_cast<const SID*>(sidValue)->Revision))
            .arg(sidIdentifierAuthorityText(sidValue))
            .arg(sidSubAuthorityText(sidValue));
        if (!sidDescription.accountText.isEmpty())
        {
            sidDescription.detailText.prepend(QStringLiteral("账户=%1；").arg(sidDescription.accountText));
        }
        return sidDescription;
    }

    // queryWindowObjectOwnerInfo: Read the full SID description of the owner of the window station or desktop object.
    SidDescription queryWindowObjectOwnerInfo(HANDLE userObjectHandle)
    {
        SidDescription sidDescription;
        if (userObjectHandle == nullptr)
        {
            sidDescription.accountText = QStringLiteral("-");
            sidDescription.sidText = QStringLiteral("-");
            sidDescription.detailText = QStringLiteral("<空对象句柄>");
            return sidDescription;
        }

        // ownerSid/securityDescriptor: Returned by GetSecurityInfo; securityDescriptor must be freed using LocalFree.
        PSID ownerSid = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        const DWORD kSecurityStatus = ::GetSecurityInfo(
            userObjectHandle,
            SE_WINDOW_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &ownerSid,
            nullptr,
            nullptr,
            nullptr,
            &securityDescriptor);
        if (kSecurityStatus != ERROR_SUCCESS)
        {
            if (securityDescriptor != nullptr)
            {
                ::LocalFree(securityDescriptor);
            }
            sidDescription.accountText = QStringLiteral("<查询失败:%1>").arg(kSecurityStatus);
            sidDescription.sidText = QStringLiteral("<查询失败:%1>").arg(kSecurityStatus);
            sidDescription.detailText = QStringLiteral("<对象所有者查询失败:%1>").arg(kSecurityStatus);
            return sidDescription;
        }

        sidDescription = describeSid(ownerSid);
        if (securityDescriptor != nullptr)
        {
            ::LocalFree(securityDescriptor);
        }
        return sidDescription;
    }

    // tryOpenDesktopHandle: Attempts to call OpenDesktopW on the desktop regardless of whether it is the current window station.
    DesktopOpenResult tryOpenDesktopHandle(
        const QString& windowStationName,
        const QString& desktopName,
        const ACCESS_MASK accessMask)
    {
        DesktopOpenResult openResult;
        QStringList detailTextList;

        auto tryOpenOnce = [&openResult, &detailTextList, accessMask](const QString& candidateName, const QString& tag) -> bool {
            if (candidateName.trimmed().isEmpty())
            {
                return false;
            }
            HDESK desktopHandle = ::OpenDesktopW(
                reinterpret_cast<LPCWSTR>(candidateName.utf16()),
                0,
                FALSE,
                accessMask);
            if (desktopHandle != nullptr)
            {
                openResult.desktopHandle = desktopHandle;
                openResult.methodText = tag;
                return true;
            }
            detailTextList << QStringLiteral("%1=错误码%2").arg(tag).arg(::GetLastError());
            return false;
        };

        if (tryOpenOnce(desktopName, QStringLiteral("直接名")))
        {
            openResult.detailText = QStringLiteral("OpenDesktopW 成功");
            return openResult;
        }

        const QString kQualifiedDesktopName = windowStationName.trimmed().isEmpty()
            ? QString()
            : QStringLiteral("%1\\%2").arg(windowStationName, desktopName);
        if (kQualifiedDesktopName.compare(desktopName, Qt::CaseInsensitive) != 0
            && tryOpenOnce(kQualifiedDesktopName, QStringLiteral("带窗口站名")))
        {
            openResult.detailText = QStringLiteral("OpenDesktopW 成功");
            return openResult;
        }

        openResult.detailText = detailTextList.join(QStringLiteral("；"));
        return openResult;
    }

    // queryCurrentSessionId: Query the current process session ID.
    std::uint32_t queryCurrentSessionId()
    {
        DWORD sessionId = 0;
        if (::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId) == FALSE)
        {
            return std::numeric_limits<std::uint32_t>::max();
        }
        return static_cast<std::uint32_t>(sessionId);
    }

    // formatSessionIdText: Converts the session ID to UI text.
    QString formatSessionIdText(const std::uint32_t sessionId)
    {
        if (sessionId == std::numeric_limits<std::uint32_t>::max())
        {
            return QStringLiteral("<未知>");
        }
        return QString::number(sessionId);
    }

    // queryDesktopHeapSizeText: Read the heap size of the desktop object.
    QString queryDesktopHeapSizeText(HDESK desktopHandle)
    {
        DWORD heapSizeKb = 0;
        DWORD returnedBytes = 0;
        const BOOL kQueryOk = ::GetUserObjectInformationW(
            desktopHandle,
            UOI_HEAPSIZE,
            &heapSizeKb,
            sizeof(heapSizeKb),
            &returnedBytes);
        if (kQueryOk == FALSE || returnedBytes < sizeof(heapSizeKb))
        {
            return QStringLiteral("<失败:%1>").arg(::GetLastError());
        }
        return QString::number(heapSizeKb);
    }

    // enumerateWindowStationNameList: Enumerates window station names visible in the current session.
    std::vector<QString> enumerateWindowStationNameList(DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;

        // nameList: Accumulate window station names in the callback, then sort and deduplicate at the end of the function.
        std::vector<QString> nameList;
        nameList.reserve(8);

        struct WindowStationEnumContext
        {
            std::vector<QString>* outputNameList = nullptr; // outputNameList: The container for window station name outputs.
        };

        WindowStationEnumContext enumContext;
        enumContext.outputNameList = &nameList;
        auto enumWindowStationProc = [](LPWSTR windowStationName, LPARAM lParam) -> BOOL {
            WindowStationEnumContext* context = reinterpret_cast<WindowStationEnumContext*>(lParam);
            if (context == nullptr || context->outputNameList == nullptr)
            {
                return FALSE;
            }
            if (windowStationName != nullptr)
            {
                context->outputNameList->push_back(QString::fromWCharArray(windowStationName));
            }
            return TRUE;
        };

        const BOOL kEnumOk = ::EnumWindowStationsW(
            enumWindowStationProc,
            reinterpret_cast<LPARAM>(&enumContext));
        if (kEnumOk == FALSE)
        {
            errorCodeOut = ::GetLastError();
        }

        std::sort(nameList.begin(), nameList.end(), [](const QString& left, const QString& right) {
            return left.localeAwareCompare(right) < 0;
        });
        nameList.erase(
            std::unique(nameList.begin(), nameList.end()),
            nameList.end());
        return nameList;
    }

    // enumerateDesktopNameList: Enumerates desktop names in the specified window station.
    std::vector<QString> enumerateDesktopNameList(HWINSTA windowStationHandle, DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;

        // nameList: Appends desktop names in the callback, then sorts and deduplicates at the end.
        std::vector<QString> nameList;
        nameList.reserve(16);

        struct DesktopEnumContext
        {
            std::vector<QString>* outputNameList = nullptr; // outputNameList: container for desktop names output.
        };

        DesktopEnumContext enumContext;
        enumContext.outputNameList = &nameList;
        auto enumDesktopProc = [](LPWSTR desktopName, LPARAM lParam) -> BOOL {
            DesktopEnumContext* context = reinterpret_cast<DesktopEnumContext*>(lParam);
            if (context == nullptr || context->outputNameList == nullptr)
            {
                return FALSE;
            }
            if (desktopName != nullptr)
            {
                context->outputNameList->push_back(QString::fromWCharArray(desktopName));
            }
            return TRUE;
        };

        const BOOL kEnumOk = ::EnumDesktopsW(
            windowStationHandle,
            enumDesktopProc,
            reinterpret_cast<LPARAM>(&enumContext));
        if (kEnumOk == FALSE)
        {
            errorCodeOut = ::GetLastError();
        }

        std::sort(nameList.begin(), nameList.end(), [](const QString& left, const QString& right) {
            return left.localeAwareCompare(right) < 0;
        });
        nameList.erase(
            std::unique(nameList.begin(), nameList.end()),
            nameList.end());
        return nameList;
    }

    // applyDesktopRowStyle: Apply visual distinction for the current desktop, current window station, and unreadable rows.
    void applyDesktopRowStyle(QTableWidgetItem* item, const DesktopRowData& rowData)
    {
        if (item == nullptr)
        {
            return;
        }

        if (rowData.isCurrentDesktop)
        {
            QFont currentFont = item->font();
            currentFont.setBold(true);
            item->setFont(currentFont);
            item->setBackground(ksword_theme::successBackgroundColor());
            item->setForeground(ksword_theme::successColor());
            return;
        }

        if (rowData.isCurrentWindowStation)
        {
            item->setBackground(ksword_theme::primaryBlueSubtleColor());
        }

        if (rowData.readCapability == DesktopCapabilityState::kNo)
        {
            item->setForeground(ksword_theme::errorColor());
        }
    }

    // setDesktopTableItem: Uniformly create table items and write metadata required for the right-click menu and switching.
    void setDesktopTableItem(
        QTableWidget* table,
        const int row,
        const int column,
        const QString& text,
        const DesktopRowData& rowData)
    {
        if (table == nullptr)
        {
            return;
        }

        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setToolTip(text);
        item->setData(kDesktopRoleWindowStationName, rowData.windowStationName);
        item->setData(kDesktopRoleDesktopName, rowData.desktopName);
        item->setData(kDesktopRoleIsCurrentWindowStation, rowData.isCurrentWindowStation);
        item->setData(kDesktopRoleOwnerSidText, rowData.ownerSidText);
        item->setData(kDesktopRoleOwnerSidDetailText, rowData.ownerSidDetailText);

        if (column >= kDesktopColumnCurrentWindowStation
            && column <= kDesktopColumnHeapKb
            && column != kDesktopColumnSidDetail)
        {
            item->setTextAlignment(Qt::AlignCenter);
        }

        applyDesktopRowStyle(item, rowData);
        table->setItem(row, column, item);
    }
}

void OtherDock::refreshDesktopList()
{
    // refreshEvent: The entire 'window station enumeration -> desktop enumeration -> UI refresh' chain shares a single event GUID.
    KLogEvent refreshEvent;
    info << refreshEvent
        << "[OtherDock] 开始刷新桌面列表（窗口站/桌面扩展模式）。"
        << eol;

    if (desktopTable_ == nullptr || desktopStatusLabel_ == nullptr)
    {
        err << refreshEvent
            << "[OtherDock] 刷新桌面列表失败：桌面管理控件未初始化。"
            << eol;
        return;
    }

    const QPointer<OtherDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("desktop-management-table-refresh"),
        {desktopTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->refreshDesktopList();
            }
        }))
    {
        return;
    }

    // currentWindowStationHandle/currentWindowStationName/currentDesktopName: Record the current context for highlighting and switching restrictions.
    HWINSTA currentWindowStationHandle = ::GetProcessWindowStation();
    const QString kCurrentWindowStationName = queryUserObjectName(currentWindowStationHandle);
    const QString kCurrentDesktopName = queryUserObjectName(::GetThreadDesktop(::GetCurrentThreadId()));
    const std::uint32_t kCurrentSessionId = queryCurrentSessionId();

    if (currentWindowStationHandle == nullptr)
    {
        const DWORD kErrorCode = ::GetLastError();
        err << refreshEvent
            << "[OtherDock] 刷新桌面列表失败：GetProcessWindowStation失败, code="
            << kErrorCode
            << eol;
        desktopTable_->clearContents();
        desktopTable_->setRowCount(0);
        desktopStatusLabel_->setText(QStringLiteral("刷新失败：无法获取当前窗口站，错误码=%1").arg(kErrorCode));
        return;
    }

    // windowStationEnumError/windowStationNameList: Enumerates window stations first; if failed, retains at least the current window station.
    DWORD windowStationEnumError = ERROR_SUCCESS;
    std::vector<QString> windowStationNameList = enumerateWindowStationNameList(windowStationEnumError);
    if (!kCurrentWindowStationName.isEmpty())
    {
        windowStationNameList.push_back(kCurrentWindowStationName);
    }
    std::sort(windowStationNameList.begin(), windowStationNameList.end(), [](const QString& left, const QString& right) {
        return left.localeAwareCompare(right) < 0;
    });
    windowStationNameList.erase(
        std::unique(windowStationNameList.begin(), windowStationNameList.end()),
        windowStationNameList.end());

    if (windowStationNameList.empty())
    {
        err << refreshEvent
            << "[OtherDock] 刷新桌面列表失败：未能获取任何窗口站名称, enumCode="
            << windowStationEnumError
            << eol;
        desktopTable_->clearContents();
        desktopTable_->setRowCount(0);
        desktopStatusLabel_->setText(QStringLiteral("刷新失败：无法枚举窗口站，错误码=%1").arg(windowStationEnumError));
        return;
    }

    // rowDataList: Caches all rows to be written into the table; selectRowIndex: Prioritizes selecting the row corresponding to the current desktop.
    std::vector<DesktopRowData> rowDataList;
    rowDataList.reserve(32);
    int selectRowIndex = -1;
    int desktopCountForStatus = 0;
    int accessibleWindowStationCount = 0;
    QStringList enumeratedDesktopKeyList; // Real desktop keys already enumerated by EnumDesktopsW, used later to complete the private reserved handle entries.

    // makeDesktopKey：
    // - Purpose: Fold the window station name and desktop name into a case-insensitive deduplicated key.
    // - Input: windowStationName/desktopName;
    // - Output: lowercase key in station\desktop format.
    auto makeDesktopKey = [](const QString& windowStationName, const QString& desktopName) -> QString {
        return QStringLiteral("%1\\%2")
            .arg(windowStationName.trimmed().toLower(), desktopName.trimmed().toLower());
    };

    // findRetainedRecord：
    // - Purpose: Find newly created desktop handles retained by this process by window station/desktop name.
    // - Input: windowStationName/desktopName come from the current enumeration row;
    // - Output: Returns a read-only record pointer on match, otherwise nullptr.
    auto findRetainedRecord = [this](const QString& windowStationName, const QString& desktopName) -> const CreatedDesktopRecord* {
        for (const CreatedDesktopRecord& createdRecord : createdDesktopHandles_)
        {
            if (createdRecord.desktopHandle == nullptr)
            {
                continue;
            }
            const bool kStationMatched = createdRecord.windowStationName.isEmpty()
                || windowStationName.isEmpty()
                || QString::compare(createdRecord.windowStationName, windowStationName, Qt::CaseInsensitive) == 0;
            const bool kDesktopMatched = QString::compare(createdRecord.desktopName, desktopName, Qt::CaseInsensitive) == 0;
            if (kStationMatched && kDesktopMatched)
            {
                return &createdRecord;
            }
        }
        return static_cast<const CreatedDesktopRecord*>(nullptr);
    };

    for (const QString& windowStationName : windowStationNameList)
    {
        // isCurrentWindowStation: Indicates whether the window station currently being processed in the loop is the same as the current process's window station.
        const bool kIsCurrentWindowStation = !kCurrentWindowStationName.isEmpty()
            && QString::compare(windowStationName, kCurrentWindowStationName, Qt::CaseInsensitive) == 0;

        // windowStationHandle/needCloseWindowStation: Non-current window stations require explicit Open/Close.
        HWINSTA windowStationHandle = currentWindowStationHandle;
        bool needCloseWindowStation = false;
        if (!kIsCurrentWindowStation)
        {
            windowStationHandle = ::OpenWindowStationW(
                reinterpret_cast<LPCWSTR>(windowStationName.utf16()),
                FALSE,
                WINSTA_ENUMDESKTOPS | WINSTA_ENUMERATE | WINSTA_READATTRIBUTES | READ_CONTROL);
            needCloseWindowStation = windowStationHandle != nullptr;
        }

        // stationFlags/stationFlagsText/stationOwnerInfo: window station-level context.
        USEROBJECTFLAGS stationFlags{};
        const bool kStationFlagsOk = windowStationHandle != nullptr
            && queryUserObjectFlags(windowStationHandle, stationFlags);
        const QString kStationFlagsText = kStationFlagsOk
            ? formatUserObjectFlags(stationFlags, true)
            : QStringLiteral("未知");
        const bool kIsInteractiveWindowStation = kStationFlagsOk
            && ((stationFlags.dwFlags & WSF_VISIBLE) != 0);

        const SidDescription kStationOwnerInfo = windowStationHandle != nullptr
            ? queryWindowObjectOwnerInfo(windowStationHandle)
            : SidDescription{
                QStringLiteral("-"),
                QStringLiteral("-"),
                QStringLiteral("<窗口站句柄为空>")
            };

        if (windowStationHandle == nullptr)
        {
            const DWORD kOpenErrorCode = ::GetLastError();
            DesktopRowData rowData;
            rowData.windowStationName = windowStationName;
            rowData.desktopName = QStringLiteral("<窗口站无法打开>");
            rowData.isCurrentWindowStation = kIsCurrentWindowStation;
            rowData.isInteractiveWindowStation = false;
            rowData.sessionId = kCurrentSessionId;
            rowData.ownerAccountText = QStringLiteral("-");
            rowData.ownerSidText = QStringLiteral("-");
            rowData.ownerSidDetailText = QStringLiteral("<窗口站无法打开>");
            rowData.heapSizeText = QStringLiteral("-");
            rowData.remarkText = QStringLiteral("OpenWindowStationW 失败，错误码=%1").arg(kOpenErrorCode);
            rowDataList.push_back(rowData);

            warn << refreshEvent
                << "[OtherDock] 窗口站打开失败, station="
                << windowStationName.toStdString()
                << ", code="
                << kOpenErrorCode
                << eol;
            continue;
        }

        ++accessibleWindowStationCount;

        // desktopEnumError/desktopNameList: enumerate desktop names under the specified window station.
        DWORD desktopEnumError = ERROR_SUCCESS;
        const std::vector<QString> kDesktopNameList = enumerateDesktopNameList(windowStationHandle, desktopEnumError);
        if (kDesktopNameList.empty())
        {
            DesktopRowData rowData;
            rowData.windowStationName = windowStationName;
            rowData.desktopName = desktopEnumError == ERROR_SUCCESS
                ? QStringLiteral("<无桌面>")
                : QStringLiteral("<枚举失败>");
            rowData.isCurrentWindowStation = kIsCurrentWindowStation;
            rowData.isInteractiveWindowStation = kIsInteractiveWindowStation;
            rowData.sessionId = kCurrentSessionId;
            rowData.ownerAccountText = kStationOwnerInfo.accountText;
            rowData.ownerSidText = kStationOwnerInfo.sidText;
            rowData.ownerSidDetailText = kStationOwnerInfo.detailText;
            rowData.heapSizeText = QStringLiteral("-");
            rowData.remarkText = desktopEnumError == ERROR_SUCCESS
                ? QStringLiteral("该窗口站未枚举到桌面；工作站标志=%1").arg(kStationFlagsText)
                : QStringLiteral("EnumDesktopsW 失败，错误码=%1；工作站标志=%2")
                    .arg(desktopEnumError)
                    .arg(kStationFlagsText);
            rowDataList.push_back(rowData);

            if (desktopEnumError != ERROR_SUCCESS)
            {
                warn << refreshEvent
                    << "[OtherDock] 枚举桌面失败, station="
                    << windowStationName.toStdString()
                    << ", code="
                    << desktopEnumError
                    << eol;
            }

            if (needCloseWindowStation)
            {
                ::CloseWindowStation(windowStationHandle);
            }
            continue;
        }

        desktopCountForStatus += static_cast<int>(kDesktopNameList.size());

        for (const QString& desktopName : kDesktopNameList)
        {
            DesktopRowData rowData;
            rowData.windowStationName = windowStationName;
            rowData.desktopName = desktopName;
            rowData.isCurrentWindowStation = kIsCurrentWindowStation;
            rowData.isCurrentDesktop = kIsCurrentWindowStation
                && !kCurrentDesktopName.isEmpty()
                && QString::compare(desktopName, kCurrentDesktopName, Qt::CaseInsensitive) == 0;
            rowData.isInteractiveWindowStation = kIsInteractiveWindowStation;
            rowData.sessionId = kCurrentSessionId;
            rowData.ownerAccountText = kStationOwnerInfo.accountText;
            rowData.ownerSidText = kStationOwnerInfo.sidText;
            rowData.ownerSidDetailText = kStationOwnerInfo.detailText;
            rowData.heapSizeText = QStringLiteral("-");

            // remarkList: aggregates the workstation flag, input capability, error code, and restriction description for this row.
            QStringList remarkList;
            remarkList << QStringLiteral("工作站标志=%1").arg(kStationFlagsText);
            const CreatedDesktopRecord* retainedRecord = findRetainedRecord(
                rowData.windowStationName,
                rowData.desktopName);
            const DesktopOpenResult kReadOpenResult = tryOpenDesktopHandle(
                windowStationName,
                desktopName,
                DESKTOP_READOBJECTS | READ_CONTROL);
            if (kReadOpenResult.desktopHandle != nullptr)
            {
                rowData.readCapability = DesktopCapabilityState::kYes;
                rowData.heapSizeText = queryDesktopHeapSizeText(kReadOpenResult.desktopHandle);
                remarkList << QStringLiteral("打开(读)=%1").arg(kReadOpenResult.methodText);

                bool inputDesktopEnabled = false;
                if (queryDesktopInputState(kReadOpenResult.desktopHandle, inputDesktopEnabled))
                {
                    rowData.inputDesktopKnown = true;
                    rowData.inputDesktopEnabled = inputDesktopEnabled;
                    remarkList << QStringLiteral("接收输入=%1")
                        .arg(inputDesktopEnabled ? QStringLiteral("是") : QStringLiteral("否"));
                }
                else
                {
                    remarkList << QStringLiteral("接收输入=<查询失败:%1>").arg(::GetLastError());
                }

                const SidDescription kDesktopOwnerInfo = queryWindowObjectOwnerInfo(kReadOpenResult.desktopHandle);
                if (!kDesktopOwnerInfo.sidText.startsWith(QStringLiteral("<查询失败")))
                {
                    rowData.ownerAccountText = kDesktopOwnerInfo.accountText;
                    rowData.ownerSidText = kDesktopOwnerInfo.sidText;
                    rowData.ownerSidDetailText = kDesktopOwnerInfo.detailText;
                    remarkList << QStringLiteral("所有者来源=桌面对象");
                }
                else
                {
                    remarkList << QStringLiteral("所有者来源=窗口站（桌面查询失败）");
                }

                ::CloseDesktop(kReadOpenResult.desktopHandle);
            }
            else
            {
                if (retainedRecord != nullptr && retainedRecord->desktopHandle != nullptr)
                {
                    HDESK retainedDesktopHandle = reinterpret_cast<HDESK>(retainedRecord->desktopHandle);
                    rowData.readCapability = DesktopCapabilityState::kYes;
                    rowData.heapSizeText = queryDesktopHeapSizeText(retainedDesktopHandle);
                    remarkList << QStringLiteral("打开(读)失败=%1").arg(kReadOpenResult.detailText);
                    remarkList << QStringLiteral("读取回退=本进程保留句柄");

                    bool inputDesktopEnabled = false;
                    if (queryDesktopInputState(retainedDesktopHandle, inputDesktopEnabled))
                    {
                        rowData.inputDesktopKnown = true;
                        rowData.inputDesktopEnabled = inputDesktopEnabled;
                        remarkList << QStringLiteral("接收输入=%1")
                            .arg(inputDesktopEnabled ? QStringLiteral("是") : QStringLiteral("否"));
                    }

                    const SidDescription kRetainedOwnerInfo = queryWindowObjectOwnerInfo(retainedDesktopHandle);
                    rowData.ownerAccountText = kRetainedOwnerInfo.accountText;
                    rowData.ownerSidText = kRetainedOwnerInfo.sidText;
                    rowData.ownerSidDetailText = kRetainedOwnerInfo.detailText;
                    remarkList << QStringLiteral("所有者来源=本进程保留句柄");
                }
                else
                {
                    rowData.readCapability = DesktopCapabilityState::kNo;
                    rowData.heapSizeText = QStringLiteral("-");
                    remarkList << QStringLiteral("打开(读)失败=%1").arg(kReadOpenResult.detailText);
                    remarkList << QStringLiteral("所有者来源=窗口站");
                }
            }

            const DesktopOpenResult kSwitchOpenResult = tryOpenDesktopHandle(
                windowStationName,
                desktopName,
                DESKTOP_SWITCHDESKTOP | DESKTOP_READOBJECTS);
            if (kSwitchOpenResult.desktopHandle != nullptr)
            {
                rowData.switchCapability = DesktopCapabilityState::kYes;
                remarkList << QStringLiteral("打开(切换)=%1").arg(kSwitchOpenResult.methodText);
                ::CloseDesktop(kSwitchOpenResult.desktopHandle);
            }
            else
            {
                const bool kRetainedHandleMatched = retainedRecord != nullptr
                    && retainedRecord->desktopHandle != nullptr
                    && (retainedRecord->desiredAccess & DESKTOP_SWITCHDESKTOP) != 0;
                if (kRetainedHandleMatched)
                {
                    rowData.switchCapability = DesktopCapabilityState::kYes;
                    remarkList << QStringLiteral("打开(切换)失败=%1").arg(kSwitchOpenResult.detailText);
                    remarkList << QStringLiteral("切换回退=本进程保留句柄");
                }
                else
                {
                    rowData.switchCapability = DesktopCapabilityState::kNo;
                    remarkList << QStringLiteral("打开(切换)失败=%1").arg(kSwitchOpenResult.detailText);
                }
            }

            if (!kIsCurrentWindowStation)
            {
                remarkList << QStringLiteral("非当前窗口站也已尝试 OpenDesktopW");
            }

            rowData.remarkText = remarkList.join(QStringLiteral("；"));
            rowDataList.push_back(rowData);
            enumeratedDesktopKeyList << makeDesktopKey(rowData.windowStationName, rowData.desktopName);

            if (rowData.isCurrentDesktop)
            {
                selectRowIndex = static_cast<int>(rowDataList.size()) - 1;
            }
        }

        if (needCloseWindowStation)
        {
            ::CloseWindowStation(windowStationHandle);
        }
    }

    // Private DACL desktops may not be reopenable via OpenDesktopW and may be unstable to enumerate in extreme cases.
    // Therefore, the creation handles retained by this process are converted into synthetic rows to ensure users can still see and perform the switch in the table.
    for (const CreatedDesktopRecord& createdRecord : createdDesktopHandles_)
    {
        if (createdRecord.desktopHandle == nullptr || createdRecord.desktopName.trimmed().isEmpty())
        {
            continue;
        }

        const QString kRetainedWindowStationName = createdRecord.windowStationName.trimmed().isEmpty()
            ? kCurrentWindowStationName
            : createdRecord.windowStationName.trimmed();
        const QString kRetainedKey = makeDesktopKey(kRetainedWindowStationName, createdRecord.desktopName);
        if (enumeratedDesktopKeyList.contains(kRetainedKey, Qt::CaseInsensitive))
        {
            continue;
        }

        HDESK retainedDesktopHandle = reinterpret_cast<HDESK>(createdRecord.desktopHandle);
        DesktopRowData rowData;
        rowData.windowStationName = kRetainedWindowStationName;
        rowData.desktopName = createdRecord.desktopName;
        rowData.isCurrentWindowStation = !kCurrentWindowStationName.isEmpty()
            && QString::compare(kRetainedWindowStationName, kCurrentWindowStationName, Qt::CaseInsensitive) == 0;
        rowData.isCurrentDesktop = rowData.isCurrentWindowStation
            && !kCurrentDesktopName.isEmpty()
            && QString::compare(createdRecord.desktopName, kCurrentDesktopName, Qt::CaseInsensitive) == 0;
        rowData.isInteractiveWindowStation = rowData.isCurrentWindowStation;
        rowData.sessionId = kCurrentSessionId;
        rowData.readCapability = DesktopCapabilityState::kYes;
        rowData.switchCapability = (createdRecord.desiredAccess & DESKTOP_SWITCHDESKTOP) != 0
            ? DesktopCapabilityState::kYes
            : DesktopCapabilityState::kNo;
        rowData.heapSizeText = queryDesktopHeapSizeText(retainedDesktopHandle);

        bool inputDesktopEnabled = false;
        if (queryDesktopInputState(retainedDesktopHandle, inputDesktopEnabled))
        {
            rowData.inputDesktopKnown = true;
            rowData.inputDesktopEnabled = inputDesktopEnabled;
        }

        const SidDescription kRetainedOwnerInfo = queryWindowObjectOwnerInfo(retainedDesktopHandle);
        rowData.ownerAccountText = kRetainedOwnerInfo.accountText;
        rowData.ownerSidText = kRetainedOwnerInfo.sidText;
        rowData.ownerSidDetailText = kRetainedOwnerInfo.detailText;
        rowData.remarkText = QStringLiteral(
            "本进程保留句柄合成行；私有=%1；句柄继承=%2；访问掩码=0x%3；接收输入=%4")
            .arg(createdRecord.privateAccess ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(createdRecord.inheritableHandle ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(QStringLiteral("%1")
                .arg(static_cast<qulonglong>(createdRecord.desiredAccess), 8, 16, QChar('0'))
                .toUpper())
            .arg(rowData.inputDesktopKnown
                ? (rowData.inputDesktopEnabled ? QStringLiteral("是") : QStringLiteral("否"))
                : QStringLiteral("未知"));

        rowDataList.push_back(rowData);
        ++desktopCountForStatus;
        if (rowData.isCurrentDesktop)
        {
            selectRowIndex = static_cast<int>(rowDataList.size()) - 1;
        }
    }

    // Clear old table contents first, then write uniformly to avoid residual wide-table data from the previous round.
    desktopTable_->clearContents();
    desktopTable_->setRowCount(static_cast<int>(rowDataList.size()));

    for (int row = 0; row < static_cast<int>(rowDataList.size()); ++row)
    {
        const DesktopRowData& rowData = rowDataList[static_cast<std::size_t>(row)];
        setDesktopTableItem(desktopTable_, row, kDesktopColumnWindowStation, rowData.windowStationName, rowData);
        setDesktopTableItem(desktopTable_, row, kDesktopColumnDesktopName, rowData.desktopName, rowData);
        setDesktopTableItem(
            desktopTable_,
            row,
            kDesktopColumnCurrentWindowStation,
            rowData.isCurrentWindowStation ? QStringLiteral("是") : QStringLiteral("否"),
            rowData);
        setDesktopTableItem(
            desktopTable_,
            row,
            kDesktopColumnCurrentDesktop,
            rowData.isCurrentDesktop ? QStringLiteral("是") : QStringLiteral("否"),
            rowData);
        setDesktopTableItem(
            desktopTable_,
            row,
            kDesktopColumnInteractive,
            rowData.isInteractiveWindowStation ? QStringLiteral("是") : QStringLiteral("否"),
            rowData);
        setDesktopTableItem(
            desktopTable_,
            row,
            kDesktopColumnReadable,
            capabilityStateText(rowData.readCapability),
            rowData);
        setDesktopTableItem(
            desktopTable_,
            row,
            kDesktopColumnSwitchable,
            capabilityStateText(rowData.switchCapability),
            rowData);
        setDesktopTableItem(
            desktopTable_,
            row,
            kDesktopColumnSessionId,
            formatSessionIdText(rowData.sessionId),
            rowData);
        setDesktopTableItem(desktopTable_, row, kDesktopColumnOwner, rowData.ownerAccountText, rowData);
        setDesktopTableItem(desktopTable_, row, kDesktopColumnSid, rowData.ownerSidText, rowData);
        setDesktopTableItem(desktopTable_, row, kDesktopColumnSidDetail, rowData.ownerSidDetailText, rowData);
        setDesktopTableItem(desktopTable_, row, kDesktopColumnHeapKb, rowData.heapSizeText, rowData);
        setDesktopTableItem(desktopTable_, row, kDesktopColumnRemark, rowData.remarkText, rowData);
    }

    if (selectRowIndex >= 0 && selectRowIndex < desktopTable_->rowCount())
    {
        desktopTable_->selectRow(selectRowIndex);
    }
    else if (desktopTable_->rowCount() > 0)
    {
        desktopTable_->selectRow(0);
    }

    const QString kStatusText = QStringLiteral(
        "已枚举 %1 个窗口站（可访问 %2 个）、%3 个桌面；当前站：%4；当前桌面：%5；SessionId：%6")
        .arg(windowStationNameList.size())
        .arg(accessibleWindowStationCount)
        .arg(desktopCountForStatus)
        .arg(kCurrentWindowStationName.isEmpty() ? QStringLiteral("<未知>") : kCurrentWindowStationName)
        .arg(kCurrentDesktopName.isEmpty() ? QStringLiteral("<未知>") : kCurrentDesktopName)
        .arg(formatSessionIdText(kCurrentSessionId));
    desktopStatusLabel_->setText(kStatusText);

    info << refreshEvent
        << "[OtherDock] 桌面列表刷新完成, windowStationCount="
        << windowStationNameList.size()
        << ", accessibleWindowStationCount="
        << accessibleWindowStationCount
        << ", desktopCount="
        << desktopCountForStatus
        << ", currentWindowStation="
        << kCurrentWindowStationName.toStdString()
        << ", currentDesktop="
        << kCurrentDesktopName.toStdString()
        << eol;
}
