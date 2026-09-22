#include "NetworkFirewallPage.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/DetailLayoutRegistry.h"

// ============================================================
// NetworkFirewallPage.cpp
// Purpose:
// 1) Displays WFP firewall events following the fwmon/fwtab approach from System Informer.
// 2) Dynamically resolve fwpuclnt.dll to support historical enumeration and real-time subscription.
// 3) Performs only UI display and read-only monitoring; does not send IOCTLs to the KswordARK driver.
// ============================================================

#include "../Theme.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/GlobalDialogTheme.h"
#include "../../../shared/platform/process/Process.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAction>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHash>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QSplitter>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <comdef.h>
#include <fwpmu.h>
#include <fwpsu.h>
#include <netfw.h>
#include <Objbase.h>
#include <Rpc.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace
{
    // FirewallTableColumn：
    // - Purpose: Define firewall event table column indices.
    // - Handling logic: use a unified reference during insertion, filtering, and highlighting.
    // - Returns behavior: the enumeration itself has no return value.
    enum FirewallTableColumn : int
    {
        kColumnName = 0,
        kColumnAction,
        kColumnDirection,
        kColumnRule,
        kColumnDescription,
        kColumnLocalAddress,
        kColumnLocalPort,
        kColumnLocalHost,
        kColumnRemoteAddress,
        kColumnRemotePort,
        kColumnRemoteHost,
        kColumnProtocol,
        kColumnTimestamp,
        kColumnCount
    };

    constexpr int kMaximumDisplayedFirewallEvents = 5000;
    constexpr std::size_t kMaximumQueuedLiveEvents = 2000U;

    void installFirewallTableCopyMenu(
        QTableWidget* tableWidget,
        const std::function<void(int)>& addBlockRuleHandler = {})
    {
        // installFirewallTableCopyMenu:
        // - Input: WFP event table or rule table;
        // - Processing: Synchronize the current row on right-click and copy all visible columns of that row as TSV.
        // - Return: None. This menu only copies audit/rule evidence and does not modify firewall status.
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            tableWidget,
            &QTableWidget::customContextMenuRequested,
            tableWidget,
            [tableWidget, addBlockRuleHandler](const QPoint& localPosition)
            {
                const QModelIndex kClickedIndex = tableWidget->indexAt(localPosition);
                if (kClickedIndex.isValid())
                {
                    tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
                }

                QMenu contextMenu(tableWidget);
                contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
                QAction* copyRowAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
                QAction* addBlockRuleAction = nullptr;
                if (addBlockRuleHandler)
                {
                    addBlockRuleAction = contextMenu.addAction(
                        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
                        QStringLiteral("预填阻断规则"));
                    addBlockRuleAction->setEnabled(tableWidget->currentRow() >= 0);
                }

                const QAction* selectedAction = contextMenu.exec(
                    tableWidget->viewport()->mapToGlobal(localPosition));
                if (selectedAction == addBlockRuleAction)
                {
                    addBlockRuleHandler(tableWidget->currentRow());
                    return;
                }
                if (selectedAction != copyRowAction)
                {
                    return;
                }

                QClipboard* clipboardObject = QGuiApplication::clipboard();
                const int kRowIndex = tableWidget->currentRow();
                if (clipboardObject == nullptr || kRowIndex < 0 || kRowIndex >= tableWidget->rowCount())
                {
                    return;
                }

                QStringList rowFields;
                rowFields.reserve(tableWidget->columnCount());
                for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* item = tableWidget->item(kRowIndex, columnIndex);
                    rowFields.push_back(item != nullptr ? item->text() : QString());
                }
                clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
            });
    }

    // FirewallRuleTableColumn：
    // - Purpose: Define the column index for the rule management table.
    // - Handling logic: Unified reference when synchronizing Insert, Filter, and Enable/Disable button states;
    // - Returns behavior: the enumeration itself has no return value.
    enum FirewallRuleTableColumn : int
    {
        kRuleColumnName = 0,
        kRuleColumnEnabled,
        kRuleColumnAction,
        kRuleColumnDirection,
        kRuleColumnProfiles,
        kRuleColumnProtocol,
        kRuleColumnLocalPorts,
        kRuleColumnRemotePorts,
        kRuleColumnApplication,
        kRuleColumnService,
        kRuleColumnGrouping,
        kRuleColumnDescription,
        kRuleColumnCount
    };

    // WfpApi：
    // - Purpose: Stores function pointers to fwpuclnt.dll resolved dynamically.
    // - Processing logic: populated by NetworkFirewallPage::ensureWfpApiLoaded;
    // - Return behavior: Pure struct, no function return.
    struct WfpApi
    {
        using FwpmEngineOpen0Fn = DWORD(WINAPI*)(
            const wchar_t*,
            UINT32,
            SEC_WINNT_AUTH_IDENTITY_W*,
            const FWPM_SESSION0*,
            HANDLE*);
        using FwpmEngineClose0Fn = DWORD(WINAPI*)(HANDLE);
        using FwpmEngineSetOption0Fn = DWORD(WINAPI*)(HANDLE, FWPM_ENGINE_OPTION, const FWP_VALUE0*);
        using FwpmFreeMemory0Fn = void(WINAPI*)(void**);
        using FwpmFilterGetById0Fn = DWORD(WINAPI*)(HANDLE, UINT64, FWPM_FILTER0**);
        using FwpmNetEventCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_NET_EVENT_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmNetEventDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);
        using WfpNetEventCallbackFn = void(CALLBACK*)(void*, const void*);
        using FwpmNetEventEnumGenericFn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, void***, UINT32*);
        using FwpmNetEventSubscribeGenericFn = DWORD(WINAPI*)(
            HANDLE,
            const FWPM_NET_EVENT_SUBSCRIPTION0*,
            WfpNetEventCallbackFn,
            void*,
            HANDLE*);
        using FwpmNetEventUnsubscribe0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);

        FwpmEngineOpen0Fn engineOpen = nullptr;
        FwpmEngineClose0Fn engineClose = nullptr;
        FwpmEngineSetOption0Fn engineSetOption = nullptr;
        FwpmFreeMemory0Fn freeMemory = nullptr;
        FwpmFilterGetById0Fn filterGetById = nullptr;
        FwpmNetEventCreateEnumHandle0Fn eventCreateEnumHandle = nullptr;
        FwpmNetEventDestroyEnumHandle0Fn eventDestroyEnumHandle = nullptr;
        FwpmNetEventEnumGenericFn eventEnum = nullptr;
        FwpmNetEventSubscribeGenericFn eventSubscribe = nullptr;
        FwpmNetEventUnsubscribe0Fn eventUnsubscribe = nullptr;
    };

    WfpApi gWfpApi;

    // ScopedBstr：
    // - Purpose: Manage BSTR lifecycle to prevent SysFreeString leaks;
    // - Handling logic: accepts BSTR on construction and automatically releases it on destruction.
    // - Return behavior: The underlying handle can be passed via get()/release().
    class ScopedBstr final
    {
    public:
        explicit ScopedBstr(BSTR value = nullptr)
            : value_(value)
        {
        }

        ~ScopedBstr()
        {
            if (value_ != nullptr)
            {
                SysFreeString(value_);
                value_ = nullptr;
            }
        }

        ScopedBstr(const ScopedBstr&) = delete;
        ScopedBstr& operator=(const ScopedBstr&) = delete;

        ScopedBstr(ScopedBstr&& other) noexcept
            : value_(other.value_)
        {
            other.value_ = nullptr;
        }

        ScopedBstr& operator=(ScopedBstr&& other) noexcept
        {
            if (this != &other)
            {
                if (value_ != nullptr)
                {
                    SysFreeString(value_);
                }
                value_ = other.value_;
                other.value_ = nullptr;
            }
            return *this;
        }

        BSTR get() const
        {
            return value_;
        }

        BSTR* put()
        {
            if (value_ != nullptr)
            {
                SysFreeString(value_);
                value_ = nullptr;
            }
            return &value_;
        }

        BSTR release()
        {
            BSTR value = value_;
            value_ = nullptr;
            return value;
        }

    private:
        BSTR value_ = nullptr;
    };

    // ScopedVariant：
    // - Purpose: Manage the VARIANT lifecycle;
    // - Handling logic: Call VariantInit during construction and VariantClear during destruction.
    // - Return behavior: exposed to COM API via get().
    class ScopedVariant final
    {
    public:
        ScopedVariant()
        {
            VariantInit(&value_);
        }

        ~ScopedVariant()
        {
            VariantClear(&value_);
        }

        ScopedVariant(const ScopedVariant&) = delete;
        ScopedVariant& operator=(const ScopedVariant&) = delete;

        VARIANT* get()
        {
            return &value_;
        }

        const VARIANT* get() const
        {
            return &value_;
        }

    private:
        VARIANT value_{};
    };

    // ScopedComInitialize：
    // - Purpose: initialize/Uninitialize COM within the current thread.
    // - Handling logic: Call CoInitializeEx on construction; automatically call CoUninitialize in the destructor if initialization succeeds.
    // - Return behavior: Exposes initialization status via succeeded()/result().
    class ScopedComInitialize final
    {
    public:
        explicit ScopedComInitialize(const DWORD coinitFlags)
            : result_(CoInitializeEx(nullptr, coinitFlags))
        {
            shouldUninitialize_ = SUCCEEDED(result_);
        }

        ~ScopedComInitialize()
        {
            if (shouldUninitialize_)
            {
                CoUninitialize();
            }
        }

        bool succeeded() const
        {
            return SUCCEEDED(result_) || result_ == RPC_E_CHANGED_MODE;
        }

        HRESULT result() const
        {
            return result_;
        }

    private:
        HRESULT result_ = E_FAIL;
        bool shouldUninitialize_ = false;
    };

    // releaseComPointer:
    // - Input: Any COM interface pointer;
    // - Processing: Call Release if not null.
    // - Returns: Nothing.
    template <typename T>
    void releaseComPointer(T*& pointerValue)
    {
        if (pointerValue != nullptr)
        {
            pointerValue->Release();
            pointerValue = nullptr;
        }
    }

    // safeText:
    // - Input: candidate text
    // - Processing: Display empty text uniformly as '-'.
    // - Returns: displayable text.
    QString safeText(const QString& valueText)
    {
        return valueText.trimmed().isEmpty() ? QStringLiteral("-") : valueText.trimmed();
    }

    // rawTextOrEmpty:
    // - Input: candidate text
    // - Handling: only performs trimming, preserving actual empty strings.
    // - Returns: Raw text suitable for writing back to the rule object.
    QString rawTextOrEmpty(const QString& valueText)
    {
        return valueText.trimmed();
    }

    // qStringFromBstr:
    // - Input: COM BSTR.
    // - Handling: Return empty QString when nullptr.
    // - Returns: Qt string.
    QString qStringFromBstr(BSTR valueText)
    {
        return valueText == nullptr ? QString() : QString::fromWCharArray(valueText);
    }

    // bstrFromQString:
    // - Input: Qt text;
    // - Handling: return nullptr if empty; otherwise allocate a BSTR.
    // - Returns: BSTR that the caller is responsible for freeing.
    BSTR bstrFromQString(const QString& valueText)
    {
        const QString kTrimmedText = valueText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return nullptr;
        }
        return SysAllocString(reinterpret_cast<const OLECHAR*>(kTrimmedText.utf16()));
    }

    // win32ErrorText:
    // - Input: Win32 error code;
    // - Processing: Call FormatMessage to retrieve system messages.
    // - Returns: text containing the error code and description.
    QString win32ErrorText(const DWORD errorCode)
    {
        wchar_t* messageBuffer = nullptr;
        const DWORD kLength = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            0,
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);
        QString messageText;
        if (kLength > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer).trimmed();
            LocalFree(messageBuffer);
        }
        if (messageText.isEmpty())
        {
            messageText = QStringLiteral("未知错误");
        }
        return QStringLiteral("%1 (%2)").arg(messageText).arg(errorCode);
    }

    // fileTimeToText:
    // - Input: WFP event FILETIME.
    // - Processing: Convert to local time;
    // - Returns: Time text; returns '-' on failure.
    QString fileTimeToText(const FILETIME& fileTime)
    {
        FILETIME localFileTime{};
        SYSTEMTIME systemTime{};
        if (!FileTimeToLocalFileTime(&fileTime, &localFileTime)
            || !FileTimeToSystemTime(&localFileTime, &systemTime))
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("%1-%2-%3 %4:%5:%6.%7")
            .arg(systemTime.wYear, 4, 10, QLatin1Char('0'))
            .arg(systemTime.wMonth, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wDay, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wHour, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wMinute, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wSecond, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wMilliseconds, 3, 10, QLatin1Char('0'));
    }

    // protocolText:
    // - Input: IP protocol number;
    // - Processing: Convert common protocols;
    // - Returns: human-readable text for protocols like TCP/UDP/ICMP.
    QString protocolText(const UINT8 protocol)
    {
        switch (protocol)
        {
        case IPPROTO_TCP:
            return QStringLiteral("TCP");
        case IPPROTO_UDP:
            return QStringLiteral("UDP");
        case IPPROTO_ICMP:
            return QStringLiteral("ICMP");
        case IPPROTO_ICMPV6:
            return QStringLiteral("ICMPv6");
        default:
            return protocol == 0
                ? QStringLiteral("-")
                : QStringLiteral("%1").arg(static_cast<unsigned int>(protocol));
        }
    }

    // firewallRuleProtocolText:
    // - Input: Windows Firewall protocol value;
    // - Processing: Convert to human-readable text for the rule management page.
    // - Returns: TCP/UDP/Any/numeric protocol.
    QString firewallRuleProtocolText(const long protocolValue)
    {
        switch (protocolValue)
        {
        case NET_FW_IP_PROTOCOL_TCP:
            return QStringLiteral("TCP");
        case NET_FW_IP_PROTOCOL_UDP:
            return QStringLiteral("UDP");
        case NET_FW_IP_PROTOCOL_ANY:
            return QStringLiteral("Any");
        case 1:
            return QStringLiteral("ICMPv4");
        case 58:
            return QStringLiteral("ICMPv6");
        default:
            return QString::number(protocolValue);
        }
    }

    // firewallRuleDirectionText:
    // - Input: rule direction value;
    // - Processing: Convert to In/Out;
    // - Returns: human-readable text.
    QString firewallRuleDirectionText(const long directionValue)
    {
        switch (directionValue)
        {
        case NET_FW_RULE_DIR_IN:
            return QStringLiteral("In");
        case NET_FW_RULE_DIR_OUT:
            return QStringLiteral("Out");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // firewallRuleActionText:
    // - Input: rule action value;
    // - Processing: Convert to Allow/Block;
    // - Returns: human-readable text.
    QString firewallRuleActionText(const long actionValue)
    {
        switch (actionValue)
        {
        case NET_FW_ACTION_ALLOW:
            return QStringLiteral("Allow");
        case NET_FW_ACTION_BLOCK:
            return QStringLiteral("Block");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // firewallProfilesText:
    // - Input: Profile bitmask;
    // - Processing: Expand to Domain/Private/Public text.
    // - Returns: Concatenated human-readable text.
    QString firewallProfilesText(const long profilesValue)
    {
        if (profilesValue == NET_FW_PROFILE2_ALL)
        {
            return QStringLiteral("All");
        }

        QStringList profileTextList;
        if ((profilesValue & NET_FW_PROFILE2_DOMAIN) != 0)
        {
            profileTextList.push_back(QStringLiteral("Domain"));
        }
        if ((profilesValue & NET_FW_PROFILE2_PRIVATE) != 0)
        {
            profileTextList.push_back(QStringLiteral("Private"));
        }
        if ((profilesValue & NET_FW_PROFILE2_PUBLIC) != 0)
        {
            profileTextList.push_back(QStringLiteral("Public"));
        }
        return profileTextList.isEmpty()
            ? QStringLiteral("-")
            : profileTextList.join(QStringLiteral(" | "));
    }

    // composeRuleFingerprint:
    // - Input: Key display fields of the rule;
    // - Processing: Generate a stable matching key within the current snapshot.
    // - Returns: Rule match fingerprint.
    QString composeRuleFingerprint(
        const QString& nameText,
        const QString& applicationText,
        const QString& serviceText,
        const QString& localPortsText,
        const QString& remotePortsText,
        const QString& localAddressesText,
        const QString& remoteAddressesText,
        const long protocolValue,
        const long directionValue,
        const long actionValue,
        const long profilesValue)
    {
        return QStringLiteral("%1||%2||%3||%4||%5||%6||%7||%8||%9||%10||%11")
            .arg(rawTextOrEmpty(nameText))
            .arg(rawTextOrEmpty(applicationText))
            .arg(rawTextOrEmpty(serviceText))
            .arg(rawTextOrEmpty(localPortsText))
            .arg(rawTextOrEmpty(remotePortsText))
            .arg(rawTextOrEmpty(localAddressesText))
            .arg(rawTextOrEmpty(remoteAddressesText))
            .arg(protocolValue)
            .arg(directionValue)
            .arg(actionValue)
            .arg(profilesValue);
    }

    // directionText:
    // - Input: WFP direction value.
    // - Handling: Compatible with standard FWP_DIRECTION_* and DirectionMap used by System Informer;
    // - Return: In/Out/FWD/BI/Unknown.
    QString directionText(const UINT32 direction)
    {
        constexpr UINT32 kDirectionMapInbound = 0x3900;
        constexpr UINT32 kDirectionMapOutbound = 0x3901;
        constexpr UINT32 kDirectionMapForward = 0x3902;
        constexpr UINT32 kDirectionMapBidirectional = 0x3903;
        switch (direction)
        {
        case FWP_DIRECTION_INBOUND:
        case kDirectionMapInbound:
            return QStringLiteral("In");
        case FWP_DIRECTION_OUTBOUND:
        case kDirectionMapOutbound:
            return QStringLiteral("Out");
        case kDirectionMapForward:
            return QStringLiteral("FWD");
        case kDirectionMapBidirectional:
            return QStringLiteral("BI");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // actionText:
    // - Input: WFP event type.
    // - Processing: Map to System Informer-style action names.
    // - Returns: the action text.
    QString actionText(const FWPM_NET_EVENT_TYPE type)
    {
        switch (type)
        {
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
            return QStringLiteral("DROP");
        case FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP:
            return QStringLiteral("IPsec Block");
        case FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP:
            return QStringLiteral("Flood Protection");
        case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
            return QStringLiteral("Allowed");
        case FWPM_NET_EVENT_TYPE_CAPABILITY_DROP:
            return QStringLiteral("DROP (AppContainer)");
        case FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
            return QStringLiteral("Allowed (AppContainer)");
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
            return QStringLiteral("DROP (MAC)");
        case FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL:
            return QStringLiteral("QoS Policy Packet");
        case FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE:
            return QStringLiteral("VPN Failure (Phase 1)");
        case FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE:
            return QStringLiteral("VPN Failure (Phase 2)");
        case FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE:
            return QStringLiteral("VPN Auth Failure");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // isDropEvent:
    // - Input: WFP event type.
    // - Processing: Determine if the event should be highlighted in red;
    // - Return: true for DROP/Block events.
    bool isDropEvent(const FWPM_NET_EVENT_TYPE type)
    {
        return type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP
            || type == FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP
            || type == FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP
            || type == FWPM_NET_EVENT_TYPE_CAPABILITY_DROP
            || type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC;
    }

    // addressTextFromHeader:
    // - Input: WFP event header, local/remote flag;
    // - Processing: Convert the address to IPv4/IPv6 format.
    // - Returns: address text; returns an empty string if the field is not set.
    QString addressTextFromHeader(const FWPM_NET_EVENT_HEADER3& header, const bool localAddress)
    {
        const UINT32 kAddressFlag = localAddress
            ? FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET
            : FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET;
        if ((header.flags & kAddressFlag) == 0)
        {
            return QString();
        }

        wchar_t buffer[INET6_ADDRSTRLEN] = {};
        if (header.ipVersion == FWP_IP_VERSION_V4)
        {
            IN_ADDR address{};
            address.S_un.S_addr = htonl(localAddress ? header.localAddrV4 : header.remoteAddrV4);
            if (InetNtopW(AF_INET, &address, buffer, static_cast<DWORD>(std::size(buffer))) != nullptr)
            {
                return QString::fromWCharArray(buffer);
            }
        }
        else if (header.ipVersion == FWP_IP_VERSION_V6)
        {
            IN6_ADDR address{};
            const FWP_BYTE_ARRAY16& sourceBytes = localAddress ? header.localAddrV6 : header.remoteAddrV6;
            std::memcpy(address.u.Byte, sourceBytes.byteArray16, 16);
            if (InetNtopW(AF_INET6, &address, buffer, static_cast<DWORD>(std::size(buffer))) != nullptr)
            {
                return QString::fromWCharArray(buffer);
            }
        }
        return QString();
    }

    // portTextFromHeader:
    // - Input: WFP event header, local/remote flag;
    // - Processing: Extract port field;
    // - Return: Port text; returns an empty string if the field is not set.
    QString portTextFromHeader(const FWPM_NET_EVENT_HEADER3& header, const bool localPort)
    {
        const UINT32 kPortFlag = localPort
            ? FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET
            : FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET;
        if ((header.flags & kPortFlag) == 0)
        {
            return QString();
        }
        return QString::number(localPort ? header.localPort : header.remotePort);
    }

    // appPathFromHeader:
    // - Input: WFP event header.
    // - Processing: Retain the original NT/Win32 path from the appId byte blob;
    // - Returns: Application path or empty string.
    QString appPathFromHeader(const FWPM_NET_EVENT_HEADER3& header)
    {
        if ((header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) == 0
            || header.appId.data == nullptr
            || header.appId.size <= sizeof(wchar_t))
        {
            return QString();
        }

        const int kCharCount = static_cast<int>((header.appId.size / sizeof(wchar_t)) - 1U);
        return QString::fromWCharArray(
            reinterpret_cast<const wchar_t*>(header.appId.data),
            std::max(0, kCharCount)).trimmed();
    }

    // appNameFromHeader:
    // - Input: WFP event header.
    // - Handling: Extract filename from appId path for table display;
    // - Returns: Application name or empty string.
    QString appNameFromHeader(const FWPM_NET_EVENT_HEADER3& header)
    {
        QString pathText = appPathFromHeader(header);
        pathText = pathText.replace(QLatin1Char('\\'), QLatin1Char('/'));
        const int kSlashIndex = pathText.lastIndexOf(QLatin1Char('/'));
        return kSlashIndex >= 0 ? pathText.mid(kSlashIndex + 1) : pathText;
    }

    // resolveHostnameText:
    // - Input: IP address text.
    // - Processing: Keep operations lightweight for empty addresses and loopback/local scenarios; call getnameinfo for reverse lookup.
    // - Returns: The hostname if parsing succeeds; otherwise, an empty string.
    QString resolveHostnameText(const QString& addressText)
    {
        if (addressText.isEmpty()
            || addressText == QStringLiteral("0.0.0.0")
            || addressText == QStringLiteral("::"))
        {
            return QString();
        }

        sockaddr_storage storage{};
        int family = AF_UNSPEC;
        if (InetPtonW(AF_INET, reinterpret_cast<PCWSTR>(addressText.utf16()), &reinterpret_cast<sockaddr_in*>(&storage)->sin_addr) == 1)
        {
            family = AF_INET;
            reinterpret_cast<sockaddr_in*>(&storage)->sin_family = AF_INET;
        }
        else if (InetPtonW(AF_INET6, reinterpret_cast<PCWSTR>(addressText.utf16()), &reinterpret_cast<sockaddr_in6*>(&storage)->sin6_addr) == 1)
        {
            family = AF_INET6;
            reinterpret_cast<sockaddr_in6*>(&storage)->sin6_family = AF_INET6;
        }
        if (family == AF_UNSPEC)
        {
            return QString();
        }

        wchar_t hostBuffer[NI_MAXHOST] = {};
        const int kLength = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        const int kStatus = GetNameInfoW(
            reinterpret_cast<sockaddr*>(&storage),
            kLength,
            hostBuffer,
            static_cast<DWORD>(std::size(hostBuffer)),
            nullptr,
            0,
            NI_NAMEREQD);
        return kStatus == 0 ? QString::fromWCharArray(hostBuffer) : QString();
    }

    // procAddress:
    // - Input: Module handle and exported name;
    // - Handling: Call GetProcAddress and cast to the target function pointer;
    // - Returns: Target function pointer or nullptr.
    template <typename T>
    T procAddress(HMODULE moduleHandle, const char* name)
    {
        return reinterpret_cast<T>(GetProcAddress(moduleHandle, name));
    }

    // FirewallRuleEditorDialog：
    // - Purpose: Unify the input container for adding/editing firewall rules.
    // - Handling logic: map common fields to a lightweight form, validate required items, and output a rule snapshot.
    // - Return behavior: on accept, returns user input via ruleEntry().
    class FirewallRuleEditorDialog final : public QDialog
    {
    public:
        explicit FirewallRuleEditorDialog(
            const NetworkFirewallPage::FirewallRuleEntry* initialRuleEntry,
            QWidget* parent = nullptr)
            : QDialog(parent)
        {
            setWindowTitle(initialRuleEntry == nullptr ? QStringLiteral("新增防火墙规则") : QStringLiteral("编辑防火墙规则"));
            resize(620, 460);
            ks::ui::refreshGlobalDialogTheme();

            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(12, 12, 12, 12);
            rootLayout->setSpacing(10);

            QLabel* tipLabel = new QLabel(
                QStringLiteral("规则修改将直接写入 Windows Firewall。程序路径、端口和地址支持留空。"),
                this);
            tipLabel->setWordWrap(true);
            rootLayout->addWidget(tipLabel, 0);

            QFormLayout* formLayout = new QFormLayout();
            formLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
            formLayout->setFormAlignment(Qt::AlignTop);
            formLayout->setSpacing(8);

            nameEdit_ = new QLineEdit(this);
            descriptionEdit_ = new QLineEdit(this);
            applicationEdit_ = new QLineEdit(this);
            serviceEdit_ = new QLineEdit(this);
            localPortsEdit_ = new QLineEdit(this);
            remotePortsEdit_ = new QLineEdit(this);
            localAddressesEdit_ = new QLineEdit(this);
            remoteAddressesEdit_ = new QLineEdit(this);
            groupingEdit_ = new QLineEdit(this);

            protocolCombo_ = new QComboBox(this);
            protocolCombo_->addItem(QStringLiteral("Any"), NET_FW_IP_PROTOCOL_ANY);
            protocolCombo_->addItem(QStringLiteral("TCP"), NET_FW_IP_PROTOCOL_TCP);
            protocolCombo_->addItem(QStringLiteral("UDP"), NET_FW_IP_PROTOCOL_UDP);
            protocolCombo_->addItem(QStringLiteral("ICMPv4"), 1);
            protocolCombo_->addItem(QStringLiteral("ICMPv6"), 58);

            directionCombo_ = new QComboBox(this);
            directionCombo_->addItem(QStringLiteral("Inbound"), NET_FW_RULE_DIR_IN);
            directionCombo_->addItem(QStringLiteral("Outbound"), NET_FW_RULE_DIR_OUT);

            actionCombo_ = new QComboBox(this);
            actionCombo_->addItem(QStringLiteral("Allow"), NET_FW_ACTION_ALLOW);
            actionCombo_->addItem(QStringLiteral("Block"), NET_FW_ACTION_BLOCK);

            enabledCheck_ = new QCheckBox(QStringLiteral("启用规则"), this);
            enabledCheck_->setChecked(true);
            profileDomainCheck_ = new QCheckBox(QStringLiteral("Domain"), this);
            profilePrivateCheck_ = new QCheckBox(QStringLiteral("Private"), this);
            profilePublicCheck_ = new QCheckBox(QStringLiteral("Public"), this);

            QWidget* profileWidget = new QWidget(this);
            QHBoxLayout* profileLayout = new QHBoxLayout(profileWidget);
            profileLayout->setContentsMargins(0, 0, 0, 0);
            profileLayout->setSpacing(10);
            profileLayout->addWidget(profileDomainCheck_);
            profileLayout->addWidget(profilePrivateCheck_);
            profileLayout->addWidget(profilePublicCheck_);
            profileLayout->addStretch(1);

            formLayout->addRow(QStringLiteral("名称"), nameEdit_);
            formLayout->addRow(QStringLiteral("描述"), descriptionEdit_);
            formLayout->addRow(QStringLiteral("程序"), applicationEdit_);
            formLayout->addRow(QStringLiteral("服务"), serviceEdit_);
            formLayout->addRow(QStringLiteral("方向"), directionCombo_);
            formLayout->addRow(QStringLiteral("动作"), actionCombo_);
            formLayout->addRow(QStringLiteral("协议"), protocolCombo_);
            formLayout->addRow(QStringLiteral("本地端口"), localPortsEdit_);
            formLayout->addRow(QStringLiteral("远端端口"), remotePortsEdit_);
            formLayout->addRow(QStringLiteral("本地地址"), localAddressesEdit_);
            formLayout->addRow(QStringLiteral("远端地址"), remoteAddressesEdit_);
            formLayout->addRow(QStringLiteral("分组"), groupingEdit_);
            formLayout->addRow(QStringLiteral("配置文件"), profileWidget);
            formLayout->addRow(QStringLiteral("状态"), enabledCheck_);
            rootLayout->addLayout(formLayout, 1);

            QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
            rootLayout->addWidget(buttonBox, 0);

            connect(buttonBox, &QDialogButtonBox::accepted, this, [this]()
            {
                if (!buildRuleEntryFromUi(&ruleEntry_))
                {
                    return;
                }
                accept();
            });
            connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

            if (initialRuleEntry != nullptr)
            {
                loadRuleEntry(*initialRuleEntry);
            }
            else
            {
                profileDomainCheck_->setChecked(true);
                profilePrivateCheck_->setChecked(true);
                profilePublicCheck_->setChecked(true);
            }
        }

        NetworkFirewallPage::FirewallRuleEntry ruleEntry() const
        {
            return ruleEntry_;
        }

    private:
        void loadRuleEntry(const NetworkFirewallPage::FirewallRuleEntry& ruleEntry)
        {
            ruleEntry_ = ruleEntry;
            nameEdit_->setText(ruleEntry.nameText);
            descriptionEdit_->setText(ruleEntry.descriptionText);
            applicationEdit_->setText(ruleEntry.applicationText);
            serviceEdit_->setText(ruleEntry.serviceText);
            localPortsEdit_->setText(ruleEntry.localPortsText);
            remotePortsEdit_->setText(ruleEntry.remotePortsText);
            localAddressesEdit_->setText(ruleEntry.localAddressesText);
            remoteAddressesEdit_->setText(ruleEntry.remoteAddressesText);
            groupingEdit_->setText(ruleEntry.groupingText);
            enabledCheck_->setChecked(ruleEntry.enabled);

            const int kProtocolIndex = protocolCombo_->findData(QVariant::fromValue(static_cast<qlonglong>(ruleEntry.protocolValue)));
            if (kProtocolIndex >= 0)
            {
                protocolCombo_->setCurrentIndex(kProtocolIndex);
            }

            const int kDirectionIndex = directionCombo_->findData(QVariant::fromValue(static_cast<qlonglong>(ruleEntry.directionValue)));
            if (kDirectionIndex >= 0)
            {
                directionCombo_->setCurrentIndex(kDirectionIndex);
            }

            const int kActionIndex = actionCombo_->findData(QVariant::fromValue(static_cast<qlonglong>(ruleEntry.actionValue)));
            if (kActionIndex >= 0)
            {
                actionCombo_->setCurrentIndex(kActionIndex);
            }

            profileDomainCheck_->setChecked((ruleEntry.profilesValue & NET_FW_PROFILE2_DOMAIN) != 0);
            profilePrivateCheck_->setChecked((ruleEntry.profilesValue & NET_FW_PROFILE2_PRIVATE) != 0);
            profilePublicCheck_->setChecked((ruleEntry.profilesValue & NET_FW_PROFILE2_PUBLIC) != 0);
        }

        bool buildRuleEntryFromUi(NetworkFirewallPage::FirewallRuleEntry* ruleEntryOut)
        {
            if (ruleEntryOut == nullptr)
            {
                return false;
            }

            const QString kNameText = nameEdit_->text().trimmed();
            if (kNameText.isEmpty())
            {
                QMessageBox::warning(this, QStringLiteral("规则校验"), QStringLiteral("规则名称不能为空。"));
                nameEdit_->setFocus();
                return false;
            }

            long profilesValue = 0;
            if (profileDomainCheck_->isChecked())
            {
                profilesValue |= NET_FW_PROFILE2_DOMAIN;
            }
            if (profilePrivateCheck_->isChecked())
            {
                profilesValue |= NET_FW_PROFILE2_PRIVATE;
            }
            if (profilePublicCheck_->isChecked())
            {
                profilesValue |= NET_FW_PROFILE2_PUBLIC;
            }
            if (profilesValue == 0)
            {
                QMessageBox::warning(this, QStringLiteral("规则校验"), QStringLiteral("至少需要选择一个配置文件。"));
                return false;
            }

            NetworkFirewallPage::FirewallRuleEntry ruleEntry = ruleEntry_;
            ruleEntry.nameText = kNameText;
            ruleEntry.descriptionText = rawTextOrEmpty(descriptionEdit_->text());
            ruleEntry.applicationText = rawTextOrEmpty(applicationEdit_->text());
            ruleEntry.serviceText = rawTextOrEmpty(serviceEdit_->text());
            ruleEntry.localPortsText = rawTextOrEmpty(localPortsEdit_->text());
            ruleEntry.remotePortsText = rawTextOrEmpty(remotePortsEdit_->text());
            ruleEntry.localAddressesText = rawTextOrEmpty(localAddressesEdit_->text());
            ruleEntry.remoteAddressesText = rawTextOrEmpty(remoteAddressesEdit_->text());
            ruleEntry.groupingText = rawTextOrEmpty(groupingEdit_->text());
            ruleEntry.enabled = enabledCheck_->isChecked();
            ruleEntry.protocolValue = protocolCombo_->currentData().toLongLong();
            ruleEntry.directionValue = directionCombo_->currentData().toLongLong();
            ruleEntry.actionValue = actionCombo_->currentData().toLongLong();
            ruleEntry.profilesValue = profilesValue;
            ruleEntry.protocolText = firewallRuleProtocolText(ruleEntry.protocolValue);
            ruleEntry.directionText = firewallRuleDirectionText(ruleEntry.directionValue);
            ruleEntry.actionText = firewallRuleActionText(ruleEntry.actionValue);
            ruleEntry.profilesText = firewallProfilesText(ruleEntry.profilesValue);
            ruleEntry.fingerprintText = composeRuleFingerprint(
                ruleEntry.nameText,
                ruleEntry.applicationText,
                ruleEntry.serviceText,
                ruleEntry.localPortsText,
                ruleEntry.remotePortsText,
                ruleEntry.localAddressesText,
                ruleEntry.remoteAddressesText,
                ruleEntry.protocolValue,
                ruleEntry.directionValue,
                ruleEntry.actionValue,
                ruleEntry.profilesValue);
            *ruleEntryOut = std::move(ruleEntry);
            return true;
        }

    private:
        QLineEdit* nameEdit_ = nullptr;
        QLineEdit* descriptionEdit_ = nullptr;
        QLineEdit* applicationEdit_ = nullptr;
        QLineEdit* serviceEdit_ = nullptr;
        QLineEdit* localPortsEdit_ = nullptr;
        QLineEdit* remotePortsEdit_ = nullptr;
        QLineEdit* localAddressesEdit_ = nullptr;
        QLineEdit* remoteAddressesEdit_ = nullptr;
        QLineEdit* groupingEdit_ = nullptr;
        QComboBox* protocolCombo_ = nullptr;
        QComboBox* directionCombo_ = nullptr;
        QComboBox* actionCombo_ = nullptr;
        QCheckBox* enabledCheck_ = nullptr;
        QCheckBox* profileDomainCheck_ = nullptr;
        QCheckBox* profilePrivateCheck_ = nullptr;
        QCheckBox* profilePublicCheck_ = nullptr;
        NetworkFirewallPage::FirewallRuleEntry ruleEntry_;
    };

    // ============================================================
    // Cross-thread execution zone: The following file-level state and functions use only parameters, local
    // variables, and global state within this file, never touching any members of NetworkFirewallPage.
    // Background tasks are always detached, ensuring they can safely complete or be cancelled even after
    // the page is destroyed; before re-injection, the owner is re-verified via FirewallAsyncTaskState.
    // ============================================================

    // FirewallAsyncTaskState：
    // - Purpose: Carry the lifecycle handshake and task serialization bit between background tasks and the page;
    // - Handling: On page destruction, first set the cancellation flag, then clear the owner; background tasks use this to abandon re-submission.
    // - Return behavior: Pure state structure, no function return.
    struct FirewallAsyncTaskState final
    {
        std::mutex dispatchMutex;                           // dispatchMutex: Protects owner read/write, real-time handle persistence, and rollback submission.
        NetworkFirewallPage* owner = nullptr;               // owner: points to the page during its lifetime; set to null during destruction.
        std::atomic_bool cancelRequested{ false };          // cancelRequested: unified cancellation flag for background loops.
        std::atomic_bool ruleMutationInProgress{ false };   // ruleMutationInProgress: a serialized flag for editing, enabling/disabling, or deleting rules.
        std::atomic_bool liveTransitionInProgress{ false }; // liveTransitionInProgress: Serial flag for live transition startup.
        std::mutex completionMutex;                         // completionMutex: Protects the running task count.
        std::condition_variable completionSignal;           // completionSignal: Wakes the destructor-side timed wait when the task exits.
        int activeWorkerCount = 0;                          // activeWorkerCount: number of background tasks still executing.
        std::mutex hostnameQueueMutex;                      // hostnameQueueMutex: Protects the queue of addresses pending reverse lookup.
        QStringList pendingHostnameAddressList;             // pendingHostnameAddressList: Addresses waiting for reverse DNS resolution.
        QSet<QString> pendingHostnameAddressSet;            // pendingHostnameAddressSet: Deduplication set for the queue.
        bool hostnameWorkerRunning = false;                 // hostnameWorkerRunning: At most one reverse lookup task runs concurrently.
    };

    // kAsyncWorkerShutdownWaitMilliseconds: The maximum wait timeout during destruction for tasks currently in progress.
    // The background task does not touch page members; destructing after timeout is safe, so we never wait indefinitely.
    constexpr int kAsyncWorkerShutdownWaitMilliseconds = 500;

    // kResolvedHostnameBatchSize: Number of reverse DNS results accumulated before submitting a batch.
    constexpr int kResolvedHostnameBatchSize = 64;

    // kMaximumCachedHostnameCount: Maximum number of reverse lookup cache entries; clears the entire cache and restarts when exceeded.
    constexpr int kMaximumCachedHostnameCount = 8192;

    std::mutex gFirewallTaskStateMutex; // g_firewallTaskStateMutex: Protects the page-to-handshake state registry.
    QHash<const NetworkFirewallPage*, std::shared_ptr<FirewallAsyncTaskState>> gFirewallTaskStateTable; // Registry root.

    // acquireFirewallAsyncTaskState:
    // - Input: page pointer;
    // Processing: Retrieve the handshake state for this page; if not registered, create it and set the owner to the page.
    // - Returns: handshake state; returns nullptr if the page pointer is null.
    std::shared_ptr<FirewallAsyncTaskState> acquireFirewallAsyncTaskState(NetworkFirewallPage* pagePointer)
    {
        if (pagePointer == nullptr)
        {
            return {};
        }

        std::lock_guard<std::mutex> registryGuard(gFirewallTaskStateMutex);
        const auto kTableIterator = gFirewallTaskStateTable.constFind(pagePointer);
        if (kTableIterator != gFirewallTaskStateTable.constEnd())
        {
            return kTableIterator.value();
        }

        std::shared_ptr<FirewallAsyncTaskState> taskState = std::make_shared<FirewallAsyncTaskState>();
        taskState->owner = pagePointer;
        gFirewallTaskStateTable.insert(pagePointer, taskState);
        return taskState;
    }

    // lookupFirewallAsyncTaskState:
    // - Input: page pointer;
    // - Processing: Only query registered handshake states; do not create new ones.
    // - Returns: The handshake state, or a null pointer if not registered.
    std::shared_ptr<FirewallAsyncTaskState> lookupFirewallAsyncTaskState(const NetworkFirewallPage* pagePointer)
    {
        std::lock_guard<std::mutex> registryGuard(gFirewallTaskStateMutex);
        const auto kTableIterator = gFirewallTaskStateTable.constFind(pagePointer);
        return kTableIterator != gFirewallTaskStateTable.constEnd() ? kTableIterator.value() : std::shared_ptr<FirewallAsyncTaskState>();
    }

    // detachFirewallAsyncTaskState:
    // - Input: page pointer;
    // - Processing: Detach handshake state from registry by first setting the cancel flag and then clearing the owner; this order is critical.
    //         Real-time subscription tasks rely on detecting the cancel flag first to avoid attaching callbacks to pages that are already being destroyed.
    // - Return: The detached handshake state for the caller to continue waiting within the time limit.
    std::shared_ptr<FirewallAsyncTaskState> detachFirewallAsyncTaskState(const NetworkFirewallPage* pagePointer)
    {
        std::shared_ptr<FirewallAsyncTaskState> taskState;
        {
            std::lock_guard<std::mutex> registryGuard(gFirewallTaskStateMutex);
            const auto kTableIterator = gFirewallTaskStateTable.find(pagePointer);
            if (kTableIterator == gFirewallTaskStateTable.end())
            {
                return taskState;
            }
            taskState = kTableIterator.value();
            gFirewallTaskStateTable.erase(kTableIterator);
        }

        taskState->cancelRequested.store(true);
        {
            std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
            taskState->owner = nullptr;
        }
        return taskState;
    }

    // AsyncWorkerScope：
    // - Purpose: Register an ongoing background task.
    // - Processing logic: Increment the counter upon construction and decrement it upon destruction, waking the destructor-side timeout wait.
    // - Return behavior: pure RAII object with no function return.
    class AsyncWorkerScope final
    {
    public:
        explicit AsyncWorkerScope(std::shared_ptr<FirewallAsyncTaskState> taskState)
            : taskState_(std::move(taskState))
        {
            if (taskState_)
            {
                std::lock_guard<std::mutex> completionGuard(taskState_->completionMutex);
                ++taskState_->activeWorkerCount;
            }
        }

        ~AsyncWorkerScope()
        {
            if (!taskState_)
            {
                return;
            }
            {
                std::lock_guard<std::mutex> completionGuard(taskState_->completionMutex);
                --taskState_->activeWorkerCount;
            }
            taskState_->completionSignal.notify_all();
        }

        AsyncWorkerScope(const AsyncWorkerScope&) = delete;
        AsyncWorkerScope& operator=(const AsyncWorkerScope&) = delete;

    private:
        std::shared_ptr<FirewallAsyncTaskState> taskState_;
    };

    // waitForFirewallAsyncWorkers:
    // - Input: Handshake state, maximum wait time in milliseconds;
    // - Processing: After the cancel flag is set, wait with a timeout for running tasks to exit; return immediately on timeout to avoid indefinite blocking.
    // - Returns: Nothing.
    void waitForFirewallAsyncWorkers(
        const std::shared_ptr<FirewallAsyncTaskState>& taskState,
        const int timeoutMilliseconds)
    {
        if (!taskState)
        {
            return;
        }

        std::unique_lock<std::mutex> completionGuard(taskState->completionMutex);
        (void)taskState->completionSignal.wait_for(
            completionGuard,
            std::chrono::milliseconds(timeoutMilliseconds),
            [&taskState]()
            {
                return taskState->activeWorkerCount <= 0;
            });
    }

    std::mutex gHostnameCacheMutex;              // g_hostnameCacheMutex: Protects the reverse DNS result cache.
    QHash<QString, QString> gHostnameCacheTable; // g_hostnameCacheTable: Maps addresses to hostnames; a null value indicates a lookup was performed but no PTR record exists.

    // lookupCachedHostnameText:
    // - Input: IP address text, hostname output;
    // - Processing: Perform read-only hits against the process-level reverse lookup cache; never initiate DNS requests.
    // - Return: Returns true when a cached conclusion (including 'checked but no record' empty results) is available.
    bool lookupCachedHostnameText(const QString& addressText, QString* hostnameTextOut)
    {
        if (addressText.isEmpty())
        {
            return true;
        }

        std::lock_guard<std::mutex> cacheGuard(gHostnameCacheMutex);
        const auto kCacheIterator = gHostnameCacheTable.constFind(addressText);
        if (kCacheIterator == gHostnameCacheTable.constEnd())
        {
            return false;
        }
        if (hostnameTextOut != nullptr)
        {
            *hostnameTextOut = kCacheIterator.value();
        }
        return true;
    }

    // resolveAndCacheHostnameText:
    // - Input: IP address text.
    // - Processing: Return immediately if cache hit; on miss, perform a synchronous reverse DNS lookup and write the result
    //         (including empty results) back to the cache to avoid repeated DNS timeouts for the same address in each refresh cycle.
    // - Returns: the hostname; an empty string if no PTR record exists.
    QString resolveAndCacheHostnameText(const QString& addressText)
    {
        QString cachedHostnameText;
        if (lookupCachedHostnameText(addressText, &cachedHostnameText))
        {
            return cachedHostnameText;
        }

        const QString kResolvedHostnameText = resolveHostnameText(addressText);
        std::lock_guard<std::mutex> cacheGuard(gHostnameCacheMutex);
        if (gHostnameCacheTable.size() >= kMaximumCachedHostnameCount)
        {
            gHostnameCacheTable.clear();
        }
        gHostnameCacheTable.insert(addressText, kResolvedHostnameText);
        return kResolvedHostnameText;
    }

    // collectUnresolvedAddressList:
    // - Input: a batch of events
    // - Processing: Select addresses without hostnames and without conclusions in the cache, then deduplicate.
    // - Returns: List of addresses pending asynchronous reverse lookup.
    QStringList collectUnresolvedAddressList(
        const std::vector<NetworkFirewallPage::FirewallEventEntry>& eventList)
    {
        QStringList pendingAddressList;
        QSet<QString> pendingAddressSet;
        for (const NetworkFirewallPage::FirewallEventEntry& eventEntry : eventList)
        {
            const std::array<QString, 2> kCandidateAddressList = {
                eventEntry.localAddressText,
                eventEntry.remoteAddressText
            };
            const std::array<QString, 2> kResolvedHostnameList = {
                eventEntry.localHostText,
                eventEntry.remoteHostText
            };
            for (std::size_t candidateIndex = 0; candidateIndex < kCandidateAddressList.size(); ++candidateIndex)
            {
                const QString& addressText = kCandidateAddressList[candidateIndex];
                if (addressText.isEmpty() || !kResolvedHostnameList[candidateIndex].isEmpty())
                {
                    continue;
                }
                if (pendingAddressSet.contains(addressText))
                {
                    continue;
                }
                if (lookupCachedHostnameText(addressText, nullptr))
                {
                    continue;
                }
                pendingAddressSet.insert(addressText);
                pendingAddressList.push_back(addressText);
            }
        }
        return pendingAddressList;
    }

    // applyResolvedHostnamesToEventTable:
    // - Input: event table control, address-to-hostname mapping;
    // - Processing: Fill in local/remote hostname columns based on address column text in the UI thread.
    // - Returns: Nothing.
    void applyResolvedHostnamesToEventTable(
        QTableWidget* eventTable,
        const QHash<QString, QString>& resolvedHostnameMap)
    {
        if (eventTable == nullptr || resolvedHostnameMap.isEmpty())
        {
            return;
        }

        constexpr std::array<int, 2> kAddressColumnList = { kColumnLocalAddress, kColumnRemoteAddress };
        constexpr std::array<int, 2> kHostnameColumnList = { kColumnLocalHost, kColumnRemoteHost };
        eventTable->setUpdatesEnabled(false);
        for (int rowIndex = 0; rowIndex < eventTable->rowCount(); ++rowIndex)
        {
            for (std::size_t columnPairIndex = 0; columnPairIndex < kAddressColumnList.size(); ++columnPairIndex)
            {
                const QTableWidgetItem* addressItem = eventTable->item(rowIndex, kAddressColumnList[columnPairIndex]);
                QTableWidgetItem* hostnameItem = eventTable->item(rowIndex, kHostnameColumnList[columnPairIndex]);
                if (addressItem == nullptr || hostnameItem == nullptr)
                {
                    continue;
                }
                const auto kResolvedIterator = resolvedHostnameMap.constFind(addressItem->text());
                if (kResolvedIterator == resolvedHostnameMap.constEnd() || kResolvedIterator.value().isEmpty())
                {
                    continue;
                }
                hostnameItem->setText(kResolvedIterator.value());
            }
        }
        eventTable->setUpdatesEnabled(true);
    }

    // submitResolvedHostnames:
    // - Input: event table control, handshake state, this batch of resolution results;
    // - Processing: Push results back to the UI thread to write to the table while the owner is still valid.
    // - Return false if the page has been destructed; the caller uses this to terminate the reverse lookup task.
    bool submitResolvedHostnames(
        QTableWidget* eventTable,
        const std::shared_ptr<FirewallAsyncTaskState>& taskState,
        const QHash<QString, QString>& resolvedHostnameMap)
    {
        if (resolvedHostnameMap.isEmpty())
        {
            return true;
        }

        std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
        NetworkFirewallPage* const kReceiver = taskState->owner;
        if (kReceiver == nullptr)
        {
            return false;
        }
        QMetaObject::invokeMethod(
            kReceiver,
            [eventTable, taskState, resolvedHostnameMap]()
            {
                // The event table is a child control of the page: a non-null owner indicates the control is still alive.
                std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                if (taskState->owner == nullptr)
                {
                    return;
                }
                applyResolvedHostnamesToEventTable(eventTable, resolvedHostnameMap);
            },
            Qt::QueuedConnection);
        return true;
    }

    // runHostnameResolutionWorker:
    // - Input: event table control, handshake state;
    // - Processing: Consume the pending reverse lookup queue serially; check the cancellation flag for each address and batch them before re-injection.
    // - Returns: None. The entire task uses only file-level caching and public control interfaces, without accessing page members.
    void runHostnameResolutionWorker(QTableWidget* eventTable, const std::shared_ptr<FirewallAsyncTaskState>& taskState)
    {
        // The reverse lookup task does not register AsyncWorkerScope: a single GetNameInfoW call may take seconds to timeout when PTR is missing,
        // so the destructor should not wait for it; additionally, it does not touch page members and can run to completion independently.
        QHash<QString, QString> resolvedHostnameMap;
        while (true)
        {
            QString addressText;
            {
                std::lock_guard<std::mutex> queueGuard(taskState->hostnameQueueMutex);
                if (taskState->cancelRequested.load() || taskState->pendingHostnameAddressList.isEmpty())
                {
                    taskState->pendingHostnameAddressList.clear();
                    taskState->pendingHostnameAddressSet.clear();
                    taskState->hostnameWorkerRunning = false;
                    break;
                }
                addressText = taskState->pendingHostnameAddressList.takeFirst();
                taskState->pendingHostnameAddressSet.remove(addressText);
            }

            const QString kResolvedHostnameText = resolveAndCacheHostnameText(addressText);
            if (!kResolvedHostnameText.isEmpty())
            {
                resolvedHostnameMap.insert(addressText, kResolvedHostnameText);
            }
            if (resolvedHostnameMap.size() < kResolvedHostnameBatchSize)
            {
                continue;
            }
            if (!submitResolvedHostnames(eventTable, taskState, resolvedHostnameMap))
            {
                std::lock_guard<std::mutex> queueGuard(taskState->hostnameQueueMutex);
                taskState->pendingHostnameAddressList.clear();
                taskState->pendingHostnameAddressSet.clear();
                taskState->hostnameWorkerRunning = false;
                return;
            }
            resolvedHostnameMap.clear();
        }

        (void)submitResolvedHostnames(eventTable, taskState, resolvedHostnameMap);
    }

    // enqueueHostnameResolution:
    // - Input: event table control, handshake state, list of addresses to resolve;
    // - Processing: Merge address into deduplication queue; detach the sole reverse lookup task if necessary.
    // - Returns: Nothing.
    void enqueueHostnameResolution(
        QTableWidget* eventTable,
        const std::shared_ptr<FirewallAsyncTaskState>& taskState,
        const QStringList& pendingAddressList)
    {
        if (eventTable == nullptr || !taskState || pendingAddressList.isEmpty())
        {
            return;
        }

        bool shouldStartWorker = false;
        {
            std::lock_guard<std::mutex> queueGuard(taskState->hostnameQueueMutex);
            for (const QString& addressText : pendingAddressList)
            {
                if (taskState->pendingHostnameAddressSet.contains(addressText))
                {
                    continue;
                }
                taskState->pendingHostnameAddressSet.insert(addressText);
                taskState->pendingHostnameAddressList.push_back(addressText);
            }
            if (!taskState->hostnameWorkerRunning && !taskState->pendingHostnameAddressList.isEmpty())
            {
                taskState->hostnameWorkerRunning = true;
                shouldStartWorker = true;
            }
        }
        if (!shouldStartWorker)
        {
            return;
        }

        try
        {
            std::thread([eventTable, taskState]()
            {
                runHostnameResolutionWorker(eventTable, taskState);
            }).detach();
        }
        catch (...)
        {
            // On thread creation failure, abandon hostname completion and retain pure IP display in the event table.
            std::lock_guard<std::mutex> queueGuard(taskState->hostnameQueueMutex);
            taskState->pendingHostnameAddressList.clear();
            taskState->pendingHostnameAddressSet.clear();
            taskState->hostnameWorkerRunning = false;
        }
    }

    std::mutex gWfpApiLoadMutex;         // g_wfpApiLoadMutex: Protects the one-time resolution of fwpuclnt.dll.
    HMODULE gFwpuclntModule = nullptr;   // g_fwpuclntModule: Handle to the fwpuclnt.dll module in the resident process.
    bool gWfpApiReady = false;           // g_wfpApiReady: Whether g_wfpApi has been fully resolved.

    // ensureWfpApiLoadedShared:
    // - Input: error text output;
    // - Processing: Parse exports of fwpuclnt.dll only once within the process; keep the module resident and never unload
    //         to prevent background tasks or real-time subscription callbacks from executing code that has already been unloaded.
    // - Returns: true when all critical exports are available.
    bool ensureWfpApiLoadedShared(QString* errorTextOut)
    {
        std::lock_guard<std::mutex> loadGuard(gWfpApiLoadMutex);
        if (gWfpApiReady)
        {
            return true;
        }

        if (gFwpuclntModule == nullptr)
        {
            gFwpuclntModule = LoadLibraryW(L"fwpuclnt.dll");
        }
        if (gFwpuclntModule == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法加载 fwpuclnt.dll：%1").arg(win32ErrorText(GetLastError()));
            }
            return false;
        }

        HMODULE moduleHandle = gFwpuclntModule;
        gWfpApi.engineOpen = procAddress<WfpApi::FwpmEngineOpen0Fn>(moduleHandle, "FwpmEngineOpen0");
        gWfpApi.engineClose = procAddress<WfpApi::FwpmEngineClose0Fn>(moduleHandle, "FwpmEngineClose0");
        gWfpApi.engineSetOption = procAddress<WfpApi::FwpmEngineSetOption0Fn>(moduleHandle, "FwpmEngineSetOption0");
        gWfpApi.freeMemory = procAddress<WfpApi::FwpmFreeMemory0Fn>(moduleHandle, "FwpmFreeMemory0");
        gWfpApi.filterGetById = procAddress<WfpApi::FwpmFilterGetById0Fn>(moduleHandle, "FwpmFilterGetById0");
        gWfpApi.eventCreateEnumHandle =
            procAddress<WfpApi::FwpmNetEventCreateEnumHandle0Fn>(moduleHandle, "FwpmNetEventCreateEnumHandle0");
        gWfpApi.eventDestroyEnumHandle =
            procAddress<WfpApi::FwpmNetEventDestroyEnumHandle0Fn>(moduleHandle, "FwpmNetEventDestroyEnumHandle0");
        gWfpApi.eventEnum = procAddress<WfpApi::FwpmNetEventEnumGenericFn>(moduleHandle, "FwpmNetEventEnum5");
        if (gWfpApi.eventEnum == nullptr)
        {
            gWfpApi.eventEnum = procAddress<WfpApi::FwpmNetEventEnumGenericFn>(moduleHandle, "FwpmNetEventEnum4");
        }
        if (gWfpApi.eventEnum == nullptr)
        {
            gWfpApi.eventEnum = procAddress<WfpApi::FwpmNetEventEnumGenericFn>(moduleHandle, "FwpmNetEventEnum3");
        }

        gWfpApi.eventSubscribe = procAddress<WfpApi::FwpmNetEventSubscribeGenericFn>(moduleHandle, "FwpmNetEventSubscribe4");
        if (gWfpApi.eventSubscribe == nullptr)
        {
            gWfpApi.eventSubscribe = procAddress<WfpApi::FwpmNetEventSubscribeGenericFn>(moduleHandle, "FwpmNetEventSubscribe3");
        }
        gWfpApi.eventUnsubscribe =
            procAddress<WfpApi::FwpmNetEventUnsubscribe0Fn>(moduleHandle, "FwpmNetEventUnsubscribe0");

        if (gWfpApi.engineOpen == nullptr
            || gWfpApi.engineClose == nullptr
            || gWfpApi.engineSetOption == nullptr
            || gWfpApi.freeMemory == nullptr
            || gWfpApi.filterGetById == nullptr
            || gWfpApi.eventCreateEnumHandle == nullptr
            || gWfpApi.eventDestroyEnumHandle == nullptr
            || gWfpApi.eventEnum == nullptr
            || gWfpApi.eventSubscribe == nullptr
            || gWfpApi.eventUnsubscribe == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("fwpuclnt.dll 缺少必要的 WFP 导出，当前系统不支持该防火墙事件视图。");
            }
            return false;
        }

        gWfpApiReady = true;
        return true;
    }

    // openWfpEngineShared:
    // - Input: Whether to enable event collection, engine handle output, and error text output;
    // - Processing: Open the BFE engine and, if necessary, write the global network event collection switch;
    //         both operations involve BFE RPC/policy submission and must be called from a background thread;
    // - Returns: true on success.
    bool openWfpEngineShared(const bool enableCollection, HANDLE* engineHandleOut, QString* errorTextOut)
    {
        if (engineHandleOut == nullptr)
        {
            return false;
        }
        *engineHandleOut = nullptr;
        if (!ensureWfpApiLoadedShared(errorTextOut))
        {
            return false;
        }

        FWPM_SESSION0 session{};
        session.displayData.name = const_cast<wchar_t*>(L"KswordFirewallMonitor");
        session.displayData.description = const_cast<wchar_t*>(L"Ksword WFP firewall event monitor");
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        HANDLE engineHandle = nullptr;
        DWORD status = gWfpApi.engineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &engineHandle);
        if (status != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("打开 BFE/WFP engine 失败：%1。防火墙事件通常需要管理员权限。")
                    .arg(win32ErrorText(status));
            }
            return false;
        }

        if (enableCollection)
        {
            FWP_VALUE0 value{};
            value.type = FWP_UINT32;
            value.uint32 = TRUE;
            status = gWfpApi.engineSetOption(engineHandle, FWPM_ENGINE_COLLECT_NET_EVENTS, &value);
            if (status != ERROR_SUCCESS)
            {
                gWfpApi.engineClose(engineHandle);
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("开启 WFP net event collection 失败：%1。请以管理员运行。")
                        .arg(win32ErrorText(status));
                }
                return false;
            }

            value.type = FWP_UINT32;
            value.uint32 = FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST
                | FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST
                | FWPM_NET_EVENT_KEYWORD_CAPABILITY_DROP
                | FWPM_NET_EVENT_KEYWORD_CAPABILITY_ALLOW
                | FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW;
            gWfpApi.engineSetOption(engineHandle, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &value);
        }

        *engineHandleOut = engineHandle;
        return true;
    }

    // closeWfpEngineShared:
    // - Input: engine handle, whether to disable collection;
    // - Processing: Optionally reset the global event collection switch and close the engine.
    // - Returns: Nothing.
    void closeWfpEngineShared(HANDLE engineHandle, const bool disableCollection)
    {
        if (engineHandle == nullptr || gWfpApi.engineClose == nullptr)
        {
            return;
        }
        if (disableCollection && gWfpApi.engineSetOption != nullptr)
        {
            FWP_VALUE0 value{};
            value.type = FWP_UINT32;
            value.uint32 = FALSE;
            gWfpApi.engineSetOption(engineHandle, FWPM_ENGINE_COLLECT_NET_EVENTS, &value);
        }
        gWfpApi.engineClose(engineHandle);
    }

    // convertWfpEventToEntryShared:
    // - Input: FWPM_NET_EVENT pointer and engine handle;
    // - Handling: Extracts fields such as action, direction, address, port, protocol, and rule name. Hostname resolution uses only the process-level
    //         cache; synchronous reverse DNS lookups are strictly avoided here to prevent blocking both the main enumeration loop and the WFP callback thread.
    // - Returns: displayable event.
    NetworkFirewallPage::FirewallEventEntry convertWfpEventToEntryShared(
        const void* wfpEventPointer,
        HANDLE engineHandle)
    {
        NetworkFirewallPage::FirewallEventEntry entry;
        const FWPM_NET_EVENT5* eventPointer = static_cast<const FWPM_NET_EVENT5*>(wfpEventPointer);
        if (eventPointer == nullptr)
        {
            return entry;
        }

        entry.actionText = actionText(eventPointer->type);
        entry.isDrop = isDropEvent(eventPointer->type);
        entry.descriptionText = entry.actionText;
        entry.timestampText = fileTimeToText(eventPointer->header.timeStamp);
        entry.protocolText = (eventPointer->header.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) != 0
            ? protocolText(eventPointer->header.ipProtocol)
            : QString();
        entry.localAddressText = addressTextFromHeader(eventPointer->header, true);
        entry.localPortText = portTextFromHeader(eventPointer->header, true);
        entry.remoteAddressText = addressTextFromHeader(eventPointer->header, false);
        entry.remotePortText = portTextFromHeader(eventPointer->header, false);
        entry.applicationPathText = appPathFromHeader(eventPointer->header);
        entry.nameText = appNameFromHeader(eventPointer->header);
        if (entry.nameText.isEmpty())
        {
            entry.nameText = entry.actionText;
        }

        UINT64 filterId = 0;
        UINT32 rawDirection = 0;
        switch (eventPointer->type)
        {
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
            if (eventPointer->classifyDrop != nullptr)
            {
                filterId = eventPointer->classifyDrop->filterId;
                rawDirection = eventPointer->classifyDrop->msFwpDirection;
            }
            break;
        case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
            if (eventPointer->classifyAllow != nullptr)
            {
                filterId = eventPointer->classifyAllow->filterId;
                rawDirection = eventPointer->classifyAllow->msFwpDirection;
            }
            break;
        case FWPM_NET_EVENT_TYPE_CAPABILITY_DROP:
            if (eventPointer->capabilityDrop != nullptr)
            {
                filterId = eventPointer->capabilityDrop->filterId;
                rawDirection = FWP_DIRECTION_OUTBOUND;
            }
            break;
        case FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
            if (eventPointer->capabilityAllow != nullptr)
            {
                filterId = eventPointer->capabilityAllow->filterId;
                rawDirection = FWP_DIRECTION_OUTBOUND;
            }
            break;
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
            if (eventPointer->classifyDropMac != nullptr)
            {
                filterId = eventPointer->classifyDropMac->filterId;
                rawDirection = eventPointer->classifyDropMac->msFwpDirection;
            }
            break;
        case FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP:
            if (eventPointer->ipsecDrop != nullptr)
            {
                filterId = eventPointer->ipsecDrop->filterId;
                rawDirection = static_cast<UINT32>(eventPointer->ipsecDrop->direction);
            }
            break;
        default:
            break;
        }
        entry.directionText = directionText(rawDirection);

        if (filterId != 0 && engineHandle != nullptr && gWfpApi.filterGetById != nullptr)
        {
            FWPM_FILTER0* filterPointer = nullptr;
            if (gWfpApi.filterGetById(engineHandle, filterId, &filterPointer) == ERROR_SUCCESS
                && filterPointer != nullptr)
            {
                if (filterPointer->displayData.name != nullptr)
                {
                    entry.ruleText = QString::fromWCharArray(filterPointer->displayData.name);
                }
                if (filterPointer->displayData.description != nullptr)
                {
                    entry.descriptionText = QString::fromWCharArray(filterPointer->displayData.description);
                }
                gWfpApi.freeMemory(reinterpret_cast<void**>(&filterPointer));
            }
            if (entry.ruleText.isEmpty())
            {
                entry.ruleText = QStringLiteral("FilterId=%1").arg(filterId);
            }
        }

        (void)lookupCachedHostnameText(entry.localAddressText, &entry.localHostText);
        (void)lookupCachedHostnameText(entry.remoteAddressText, &entry.remoteHostText);
        return entry;
    }

    // enumerateHistoryWithEngineShared:
    // - Input: an open engine handle, cancellation flag, and error text output;
    // - Handling: Batch calls to FwpmNetEventEnum*; check the cancellation flag before
    //         each batch and each event to ensure immediate convergence upon page destruction;
    // - Returns: the event list.
    std::vector<NetworkFirewallPage::FirewallEventEntry> enumerateHistoryWithEngineShared(
        HANDLE engineHandle,
        const std::atomic_bool* cancelFlag,
        QString* errorTextOut)
    {
        std::vector<NetworkFirewallPage::FirewallEventEntry> resultList;
        if (engineHandle == nullptr)
        {
            return resultList;
        }

        FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTemplate{};
        HANDLE enumHandle = nullptr;
        DWORD status = gWfpApi.eventCreateEnumHandle(engineHandle, &enumTemplate, &enumHandle);
        if (status != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 WFP 事件枚举句柄失败：%1").arg(win32ErrorText(status));
            }
            return resultList;
        }

        while (cancelFlag == nullptr || !cancelFlag->load())
        {
            void** entries = nullptr;
            UINT32 count = 0;
            status = gWfpApi.eventEnum(engineHandle, enumHandle, 256, &entries, &count);
            if (status != ERROR_SUCCESS)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("枚举 WFP 事件失败：%1").arg(win32ErrorText(status));
                }
                break;
            }
            if (count == 0 || entries == nullptr)
            {
                if (entries != nullptr)
                {
                    gWfpApi.freeMemory(reinterpret_cast<void**>(&entries));
                }
                break;
            }

            for (UINT32 index = 0; index < count; ++index)
            {
                if (cancelFlag != nullptr && cancelFlag->load())
                {
                    break;
                }
                if (entries[index] != nullptr)
                {
                    resultList.push_back(convertWfpEventToEntryShared(entries[index], engineHandle));
                }
            }
            gWfpApi.freeMemory(reinterpret_cast<void**>(&entries));
            if (resultList.size() >= static_cast<std::size_t>(kMaximumDisplayedFirewallEvents))
            {
                break;
            }
        }

        gWfpApi.eventDestroyEnumHandle(engineHandle, enumHandle);
        std::reverse(resultList.begin(), resultList.end());
        return resultList;
    }

    // enumerateFirewallRulesSnapshotShared:
    // - Input: error text output;
    // - Processing: initialize COM within the calling thread, enumerate all system firewall rules, and sort them by name.
    // - Return: The rule list; on failure, returns the error via errorTextOut.
    std::vector<NetworkFirewallPage::FirewallRuleEntry> enumerateFirewallRulesSnapshotShared(QString* errorTextOut)
    {
        std::vector<NetworkFirewallPage::FirewallRuleEntry> resultList;
        ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
        if (!comInitializer.succeeded())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                    .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
            }
            return resultList;
        }

        INetFwPolicy2* policyPointer = nullptr;
        HRESULT result = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&policyPointer));
        if (FAILED(result) || policyPointer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 INetFwPolicy2 失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return resultList;
        }

        INetFwRules* rulesPointer = nullptr;
        result = policyPointer->get_Rules(&rulesPointer);
        if (FAILED(result) || rulesPointer == nullptr)
        {
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("获取防火墙规则集合失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return resultList;
        }

        IUnknown* enumUnknownPointer = nullptr;
        result = rulesPointer->get__NewEnum(&enumUnknownPointer);
        if (FAILED(result) || enumUnknownPointer == nullptr)
        {
            releaseComPointer(rulesPointer);
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("获取规则枚举器失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return resultList;
        }

        IEnumVARIANT* enumVariantPointer = nullptr;
        result = enumUnknownPointer->QueryInterface(IID_IEnumVARIANT, reinterpret_cast<void**>(&enumVariantPointer));
        releaseComPointer(enumUnknownPointer);
        if (FAILED(result) || enumVariantPointer == nullptr)
        {
            releaseComPointer(rulesPointer);
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("转换规则枚举器失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return resultList;
        }

        while (true)
        {
            ScopedVariant currentVariant;
            ULONG fetchedCount = 0;
            result = enumVariantPointer->Next(1, currentVariant.get(), &fetchedCount);
            if (result != S_OK || fetchedCount == 0)
            {
                break;
            }
            if (currentVariant.get()->vt != VT_DISPATCH || currentVariant.get()->pdispVal == nullptr)
            {
                continue;
            }

            INetFwRule* rulePointer = nullptr;
            result = currentVariant.get()->pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&rulePointer));
            if (FAILED(result) || rulePointer == nullptr)
            {
                continue;
            }

            NetworkFirewallPage::FirewallRuleEntry ruleEntry;
            ScopedBstr nameText;
            ScopedBstr descriptionText;
            ScopedBstr applicationText;
            ScopedBstr serviceText;
            ScopedBstr localPortsText;
            ScopedBstr remotePortsText;
            ScopedBstr localAddressesText;
            ScopedBstr remoteAddressesText;
            ScopedBstr groupingText;
            VARIANT_BOOL enabledValue = VARIANT_FALSE;
            long protocolValue = 0;
            long directionValue = 0;
            long profilesValue = 0;
            NET_FW_ACTION actionValue = NET_FW_ACTION_BLOCK;

            rulePointer->get_Name(nameText.put());
            rulePointer->get_Description(descriptionText.put());
            rulePointer->get_ApplicationName(applicationText.put());
            rulePointer->get_ServiceName(serviceText.put());
            rulePointer->get_LocalPorts(localPortsText.put());
            rulePointer->get_RemotePorts(remotePortsText.put());
            rulePointer->get_LocalAddresses(localAddressesText.put());
            rulePointer->get_RemoteAddresses(remoteAddressesText.put());
            rulePointer->get_Grouping(groupingText.put());
            rulePointer->get_Enabled(&enabledValue);
            rulePointer->get_Protocol(&protocolValue);
            rulePointer->get_Direction(reinterpret_cast<NET_FW_RULE_DIRECTION*>(&directionValue));
            rulePointer->get_Profiles(&profilesValue);
            rulePointer->get_Action(&actionValue);

            ruleEntry.nameText = rawTextOrEmpty(qStringFromBstr(nameText.get()));
            ruleEntry.descriptionText = rawTextOrEmpty(qStringFromBstr(descriptionText.get()));
            ruleEntry.applicationText = rawTextOrEmpty(qStringFromBstr(applicationText.get()));
            ruleEntry.serviceText = rawTextOrEmpty(qStringFromBstr(serviceText.get()));
            ruleEntry.localPortsText = rawTextOrEmpty(qStringFromBstr(localPortsText.get()));
            ruleEntry.remotePortsText = rawTextOrEmpty(qStringFromBstr(remotePortsText.get()));
            ruleEntry.localAddressesText = rawTextOrEmpty(qStringFromBstr(localAddressesText.get()));
            ruleEntry.remoteAddressesText = rawTextOrEmpty(qStringFromBstr(remoteAddressesText.get()));
            ruleEntry.groupingText = rawTextOrEmpty(qStringFromBstr(groupingText.get()));
            ruleEntry.enabled = enabledValue == VARIANT_TRUE;
            ruleEntry.protocolValue = protocolValue;
            ruleEntry.directionValue = directionValue;
            ruleEntry.profilesValue = profilesValue;
            ruleEntry.actionValue = static_cast<long>(actionValue);
            ruleEntry.protocolText = firewallRuleProtocolText(ruleEntry.protocolValue);
            ruleEntry.directionText = firewallRuleDirectionText(ruleEntry.directionValue);
            ruleEntry.actionText = firewallRuleActionText(ruleEntry.actionValue);
            ruleEntry.profilesText = firewallProfilesText(ruleEntry.profilesValue);
            ruleEntry.fingerprintText = composeRuleFingerprint(
                ruleEntry.nameText,
                ruleEntry.applicationText,
                ruleEntry.serviceText,
                ruleEntry.localPortsText,
                ruleEntry.remotePortsText,
                ruleEntry.localAddressesText,
                ruleEntry.remoteAddressesText,
                ruleEntry.protocolValue,
                ruleEntry.directionValue,
                ruleEntry.actionValue,
                ruleEntry.profilesValue);
            resultList.push_back(std::move(ruleEntry));
            releaseComPointer(rulePointer);
        }

        releaseComPointer(enumVariantPointer);
        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);

        std::sort(
            resultList.begin(),
            resultList.end(),
            [](const NetworkFirewallPage::FirewallRuleEntry& leftEntry,
               const NetworkFirewallPage::FirewallRuleEntry& rightEntry)
            {
                const int kNameCompare = QString::compare(leftEntry.nameText, rightEntry.nameText, Qt::CaseInsensitive);
                if (kNameCompare != 0)
                {
                    return kNameCompare < 0;
                }
                return QString::compare(leftEntry.applicationText, rightEntry.applicationText, Qt::CaseInsensitive) < 0;
            });
        return resultList;
    }

    // firewallRuleNameOf:
    // - Input: A system rule;
    // - Processing: Read only the rule name to enable short-circuiting during full enumeration.
    // - Returns: rule name.
    QString firewallRuleNameOf(INetFwRule* rulePointer)
    {
        if (rulePointer == nullptr)
        {
            return QString();
        }
        ScopedBstr nameText;
        rulePointer->get_Name(nameText.put());
        return rawTextOrEmpty(qStringFromBstr(nameText.get()));
    }

    // firewallRuleFingerprintOf:
    // - Input: A system rule;
    // - Processing: Read 11 attributes involved in matching and construct the fingerprint;
    // - Returns: The rule fingerprint.
    QString firewallRuleFingerprintOf(INetFwRule* rulePointer)
    {
        if (rulePointer == nullptr)
        {
            return QString();
        }

        ScopedBstr nameText;
        ScopedBstr applicationText;
        ScopedBstr serviceText;
        ScopedBstr localPortsText;
        ScopedBstr remotePortsText;
        ScopedBstr localAddressesText;
        ScopedBstr remoteAddressesText;
        long protocolValue = 0;
        long directionValue = 0;
        long profilesValue = 0;
        NET_FW_ACTION actionValue = NET_FW_ACTION_BLOCK;

        rulePointer->get_Name(nameText.put());
        rulePointer->get_ApplicationName(applicationText.put());
        rulePointer->get_ServiceName(serviceText.put());
        rulePointer->get_LocalPorts(localPortsText.put());
        rulePointer->get_RemotePorts(remotePortsText.put());
        rulePointer->get_LocalAddresses(localAddressesText.put());
        rulePointer->get_RemoteAddresses(remoteAddressesText.put());
        rulePointer->get_Protocol(&protocolValue);
        rulePointer->get_Direction(reinterpret_cast<NET_FW_RULE_DIRECTION*>(&directionValue));
        rulePointer->get_Profiles(&profilesValue);
        rulePointer->get_Action(&actionValue);

        return composeRuleFingerprint(
            rawTextOrEmpty(qStringFromBstr(nameText.get())),
            rawTextOrEmpty(qStringFromBstr(applicationText.get())),
            rawTextOrEmpty(qStringFromBstr(serviceText.get())),
            rawTextOrEmpty(qStringFromBstr(localPortsText.get())),
            rawTextOrEmpty(qStringFromBstr(remotePortsText.get())),
            rawTextOrEmpty(qStringFromBstr(localAddressesText.get())),
            rawTextOrEmpty(qStringFromBstr(remoteAddressesText.get())),
            protocolValue,
            directionValue,
            static_cast<long>(actionValue),
            profilesValue);
    }

    // acquireFirewallRuleByFingerprint:
    // - Input: Rule collection, target rule name, and target rule fingerprint;
    // - Handling: first attempt a direct lookup by name using INetFwRules::Item; if the fingerprint matches, the rule is found immediately. Only in
    //         cases of multiple rules with the same name or a fingerprint mismatch does it degrade to a full enumeration. During enumeration, it short-circuits
    //         after reading the Name property to avoid reading all 11 attributes for every rule in the system (which can number in the thousands).
    // - Returns: Pointer to the matched rule (caller responsible for Release); nullptr if not found.
    INetFwRule* acquireFirewallRuleByFingerprint(
        INetFwRules* rulesPointer,
        const QString& ruleNameText,
        const QString& fingerprintText)
    {
        if (rulesPointer == nullptr)
        {
            return nullptr;
        }

        if (!ruleNameText.isEmpty())
        {
            ScopedBstr ruleNameBstr(bstrFromQString(ruleNameText));
            INetFwRule* candidateRulePointer = nullptr;
            if (ruleNameBstr.get() != nullptr
                && SUCCEEDED(rulesPointer->Item(ruleNameBstr.get(), &candidateRulePointer))
                && candidateRulePointer != nullptr)
            {
                if (firewallRuleFingerprintOf(candidateRulePointer) == fingerprintText)
                {
                    return candidateRulePointer;
                }
                releaseComPointer(candidateRulePointer);
            }
        }

        IUnknown* enumUnknownPointer = nullptr;
        if (FAILED(rulesPointer->get__NewEnum(&enumUnknownPointer)) || enumUnknownPointer == nullptr)
        {
            return nullptr;
        }

        IEnumVARIANT* enumVariantPointer = nullptr;
        const HRESULT kQueryResult =
            enumUnknownPointer->QueryInterface(IID_IEnumVARIANT, reinterpret_cast<void**>(&enumVariantPointer));
        releaseComPointer(enumUnknownPointer);
        if (FAILED(kQueryResult) || enumVariantPointer == nullptr)
        {
            return nullptr;
        }

        INetFwRule* matchedRulePointer = nullptr;
        while (true)
        {
            ScopedVariant currentVariant;
            ULONG fetchedCount = 0;
            if (enumVariantPointer->Next(1, currentVariant.get(), &fetchedCount) != S_OK || fetchedCount == 0)
            {
                break;
            }
            if (currentVariant.get()->vt != VT_DISPATCH || currentVariant.get()->pdispVal == nullptr)
            {
                continue;
            }

            INetFwRule* rulePointer = nullptr;
            if (FAILED(currentVariant.get()->pdispVal->QueryInterface(
                    __uuidof(INetFwRule),
                    reinterpret_cast<void**>(&rulePointer)))
                || rulePointer == nullptr)
            {
                continue;
            }

            if (!ruleNameText.isEmpty() && firewallRuleNameOf(rulePointer) != ruleNameText)
            {
                releaseComPointer(rulePointer);
                continue;
            }
            if (firewallRuleFingerprintOf(rulePointer) == fingerprintText)
            {
                matchedRulePointer = rulePointer;
                break;
            }
            releaseComPointer(rulePointer);
        }

        releaseComPointer(enumVariantPointer);
        return matchedRulePointer;
    }

    // openFirewallRuleCollection:
    // - Input: policy object output, rule collection output, error text output;
    // - Processing: Create INetFwPolicy2 and retrieve the rule collection; on failure, uniformly populate the error text.
    // - Returns: true on success; the caller is responsible for releasing the two output parameters.
    bool openFirewallRuleCollection(
        INetFwPolicy2** policyPointerOut,
        INetFwRules** rulesPointerOut,
        QString* errorTextOut)
    {
        if (policyPointerOut == nullptr || rulesPointerOut == nullptr)
        {
            return false;
        }
        *policyPointerOut = nullptr;
        *rulesPointerOut = nullptr;

        INetFwPolicy2* policyPointer = nullptr;
        HRESULT result = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&policyPointer));
        if (FAILED(result) || policyPointer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 INetFwPolicy2 失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }

        INetFwRules* rulesPointer = nullptr;
        result = policyPointer->get_Rules(&rulesPointer);
        if (FAILED(result) || rulesPointer == nullptr)
        {
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("获取规则集合失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }

        *policyPointerOut = policyPointer;
        *rulesPointerOut = rulesPointer;
        return true;
    }

    // updateFirewallRuleInSystemShared:
    // - Input: original rule name, original fingerprint, new rule content, and error text output;
    // - Processing: initialize COM within the calling thread, locate the target rule, and write back field by field.
    // - Returns: true on successful write-back.
    bool updateFirewallRuleInSystemShared(
        const QString& originalNameText,
        const QString& originalFingerprintText,
        const NetworkFirewallPage::FirewallRuleEntry& updatedRuleEntry,
        QString* errorTextOut)
    {
        ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
        if (!comInitializer.succeeded())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                    .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
            }
            return false;
        }

        INetFwPolicy2* policyPointer = nullptr;
        INetFwRules* rulesPointer = nullptr;
        if (!openFirewallRuleCollection(&policyPointer, &rulesPointer, errorTextOut))
        {
            return false;
        }

        INetFwRule* rulePointer = acquireFirewallRuleByFingerprint(rulesPointer, originalNameText, originalFingerprintText);
        if (rulePointer == nullptr)
        {
            releaseComPointer(rulesPointer);
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("未找到要编辑的防火墙规则，规则可能已被外部修改。");
            }
            return false;
        }

        ScopedBstr updatedNameText(bstrFromQString(updatedRuleEntry.nameText));
        ScopedBstr updatedDescriptionText(bstrFromQString(updatedRuleEntry.descriptionText));
        ScopedBstr updatedApplicationText(bstrFromQString(updatedRuleEntry.applicationText));
        ScopedBstr updatedServiceText(bstrFromQString(updatedRuleEntry.serviceText));
        ScopedBstr updatedLocalPortsText(bstrFromQString(updatedRuleEntry.localPortsText));
        ScopedBstr updatedRemotePortsText(bstrFromQString(updatedRuleEntry.remotePortsText));
        ScopedBstr updatedLocalAddressesText(bstrFromQString(updatedRuleEntry.localAddressesText));
        ScopedBstr updatedRemoteAddressesText(bstrFromQString(updatedRuleEntry.remoteAddressesText));
        ScopedBstr updatedGroupingText(bstrFromQString(updatedRuleEntry.groupingText));

        HRESULT result = rulePointer->put_Name(updatedNameText.get());
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Description(updatedDescriptionText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_ApplicationName(updatedApplicationText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_ServiceName(updatedServiceText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Protocol(updatedRuleEntry.protocolValue);
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_LocalPorts(updatedLocalPortsText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_RemotePorts(updatedRemotePortsText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_LocalAddresses(updatedLocalAddressesText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_RemoteAddresses(updatedRemoteAddressesText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Grouping(updatedGroupingText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(updatedRuleEntry.directionValue));
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Profiles(updatedRuleEntry.profilesValue);
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Action(static_cast<NET_FW_ACTION>(updatedRuleEntry.actionValue));
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Enabled(updatedRuleEntry.enabled ? VARIANT_TRUE : VARIANT_FALSE);
        }

        releaseComPointer(rulePointer);
        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);

        if (FAILED(result))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("更新防火墙规则失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }
        return true;
    }

    // setFirewallRuleEnabledInSystemShared:
    // - Input: rule name, rule fingerprint, target enabled state, and error text output;
    // - Processing: initialize COM within the calling thread, locate the target rule, and write only to the Enabled property.
    // - Returns: true on successful write-back.
    bool setFirewallRuleEnabledInSystemShared(
        const QString& ruleNameText,
        const QString& fingerprintText,
        const bool enabled,
        QString* errorTextOut)
    {
        ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
        if (!comInitializer.succeeded())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                    .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
            }
            return false;
        }

        INetFwPolicy2* policyPointer = nullptr;
        INetFwRules* rulesPointer = nullptr;
        if (!openFirewallRuleCollection(&policyPointer, &rulesPointer, errorTextOut))
        {
            return false;
        }

        INetFwRule* rulePointer = acquireFirewallRuleByFingerprint(rulesPointer, ruleNameText, fingerprintText);
        if (rulePointer == nullptr)
        {
            releaseComPointer(rulesPointer);
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("未找到要更新的防火墙规则，规则可能已被外部修改。");
            }
            return false;
        }

        const HRESULT kResult = rulePointer->put_Enabled(enabled ? VARIANT_TRUE : VARIANT_FALSE);
        releaseComPointer(rulePointer);
        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);

        if (FAILED(kResult))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("更新规则启用状态失败：0x%1")
                    .arg(static_cast<unsigned long>(kResult), 0, 16);
            }
            return false;
        }
        return true;
    }

    // deleteFirewallRulesFromSystemShared:
    // - Input: Rule name list, success count output, and error text output.
    // - Handling: Create INetFwPolicy2/INetFwRules only once, then loop through Remove calls to avoid repeatedly creating COM objects per rule count.
    // - Return: Return true only if all deletions succeed; otherwise, return immediately and retain the count of successfully deleted items.
    bool deleteFirewallRulesFromSystemShared(
        const QStringList& ruleNameList,
        int* deletedCountOut,
        QString* errorTextOut)
    {
        if (deletedCountOut != nullptr)
        {
            *deletedCountOut = 0;
        }

        ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
        if (!comInitializer.succeeded())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                    .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
            }
            return false;
        }

        INetFwPolicy2* policyPointer = nullptr;
        INetFwRules* rulesPointer = nullptr;
        if (!openFirewallRuleCollection(&policyPointer, &rulesPointer, errorTextOut))
        {
            return false;
        }

        HRESULT result = S_OK;
        int deletedCount = 0;
        for (const QString& ruleNameText : ruleNameList)
        {
            ScopedBstr ruleNameBstr(bstrFromQString(ruleNameText));
            result = rulesPointer->Remove(ruleNameBstr.get());
            if (FAILED(result))
            {
                break;
            }
            ++deletedCount;
        }

        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);
        if (deletedCountOut != nullptr)
        {
            *deletedCountOut = deletedCount;
        }

        if (FAILED(result))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("删除防火墙规则失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }
        return true;
    }
}

NetworkFirewallPage::NetworkFirewallPage(QWidget* parent)
    : QWidget(parent)
{
    // Background tasks and the page communicate solely via this handshake state; it is registered
    // during construction to prevent any task from creating a state before the page has registered.
    (void)acquireFirewallAsyncTaskState(this);
    initializeUi();
    initializeConnections();
}

NetworkFirewallPage::~NetworkFirewallPage()
{
    // All background tasks use only file-level functions and parameter copies, never touching page members. Here, we first set the
    // cancellation flag and clear the back-injection owner, then wait with a timeout for running tasks to converge. If the wait times out,
    // we do not block indefinitely; tasks continue to completion safely, as they will detect the empty owner and abandon back-injection.
    shuttingDown_.store(true);
    if (liveFlushTimer_ != nullptr)
    {
        liveFlushTimer_->stop();
    }

    const std::shared_ptr<FirewallAsyncTaskState> kTaskState = detachFirewallAsyncTaskState(this);
    waitForFirewallAsyncWorkers(kTaskState, kAsyncWorkerShutdownWaitMilliseconds);

    // The real-time subscription callback context is this page itself; it must unsubscribe synchronously before the object is destroyed. Since m_shuttingDown is
    // already set, stopLiveMonitor will synchronously complete the engine shutdown, ensuring the global event collection switch is reset before the process exits.
    stopLiveMonitor();
    // fwpuclnt.dll is intentionally kept resident and not unloaded: background tasks detached may
    // still be executing; calling FreeLibrary prematurely would cause them to jump into unloaded code.
}

void NetworkFirewallPage::requestInitialRefresh()
{
    bool expected = false;
    if (!initialRefreshRequested_.compare_exchange_strong(expected, true))
    {
        return;
    }

    refreshHistoryAsync(false);
    refreshRulesAsync(false);
}

void NetworkFirewallPage::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("防火墙"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    headerLayout->addWidget(titleLabel, 0);

    statusLabel_ = new QLabel(QStringLiteral("正在加载 WFP 事件..."), this);
    statusLabel_->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(ksword_theme::textSecondaryHex()));
    statusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    headerLayout->addWidget(statusLabel_, 1);
    rootLayout_->addLayout(headerLayout, 0);

    innerTabWidget_ = new QTabWidget(this);
    rootLayout_->addWidget(innerTabWidget_, 1);

    initializeEventMonitorUi();
    initializeRuleManagerUi();

    liveFlushTimer_ = new QTimer(this);
    liveFlushTimer_->setInterval(250);
}

void NetworkFirewallPage::initializeEventMonitorUi()
{
    eventMonitorPage_ = new QWidget(this);
    QVBoxLayout* pageLayout = new QVBoxLayout(eventMonitorPage_);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(6);

    QHBoxLayout* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(8);

    refreshHistoryButton_ = new QPushButton(QStringLiteral("刷新历史"), eventMonitorPage_);
    refreshHistoryButton_->setToolTip(QStringLiteral("枚举当前 BFE 会话可见的 WFP net event 历史记录"));
    toolbarLayout->addWidget(refreshHistoryButton_, 0);

    startLiveButton_ = new QPushButton(QStringLiteral("启动实时"), eventMonitorPage_);
    startLiveButton_->setToolTip(QStringLiteral("开启 WFP net event collection 并订阅实时事件，需要管理员权限。"));
    toolbarLayout->addWidget(startLiveButton_, 0);

    stopLiveButton_ = new QPushButton(QStringLiteral("停止实时"), eventMonitorPage_);
    stopLiveButton_->setEnabled(false);
    stopLiveButton_->setToolTip(QStringLiteral("停止实时监控防火墙（WFP）事件"));
    toolbarLayout->addWidget(stopLiveButton_, 0);

    clearButton_ = new QPushButton(QStringLiteral("清空"), eventMonitorPage_);
    clearButton_->setToolTip(QStringLiteral("清空下方的防火墙事件列表"));
    toolbarLayout->addWidget(clearButton_, 0);

    searchEdit_ = new QLineEdit(eventMonitorPage_);
    searchEdit_->setPlaceholderText(QStringLiteral("搜索 Name/Action/Rule/地址/端口/协议..."));
    searchEdit_->setMinimumWidth(240);
    toolbarLayout->addWidget(searchEdit_, 1);

    dropOnlyCheck_ = new QCheckBox(QStringLiteral("仅 DROP"), eventMonitorPage_);
    toolbarLayout->addWidget(dropOnlyCheck_, 0);
    pageLayout->addLayout(toolbarLayout, 0);

    eventTable_ = new ks::ui::VisibleTableWidget(eventMonitorPage_);
    eventTable_->setColumnCount(kColumnCount);
    eventTable_->setHorizontalHeaderLabels({
        QStringLiteral("Name"),
        QStringLiteral("Action"),
        QStringLiteral("Direction"),
        QStringLiteral("Rule"),
        QStringLiteral("Description"),
        QStringLiteral("Local address"),
        QStringLiteral("Local port"),
        QStringLiteral("Local host"),
        QStringLiteral("Remote address"),
        QStringLiteral("Remote port"),
        QStringLiteral("Remote host"),
        QStringLiteral("Protocol"),
        QStringLiteral("Timestamp")
        });
    eventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    eventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    eventTable_->setAlternatingRowColors(true);
    eventTable_->verticalHeader()->setVisible(false);
    eventTable_->horizontalHeader()->setStretchLastSection(false);
    eventTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    eventTable_->setColumnWidth(kColumnName, 150);
    eventTable_->setColumnWidth(kColumnAction, 125);
    eventTable_->setColumnWidth(kColumnDirection, 70);
    eventTable_->setColumnWidth(kColumnRule, 230);
    eventTable_->setColumnWidth(kColumnDescription, 210);
    eventTable_->setColumnWidth(kColumnLocalAddress, 130);
    eventTable_->setColumnWidth(kColumnRemoteAddress, 130);
    eventTable_->setColumnWidth(kColumnTimestamp, 170);
    installFirewallTableCopyMenu(eventTable_, [this](const int rowIndex)
    {
        if (eventTable_ == nullptr || rowIndex < 0 || rowIndex >= eventTable_->rowCount())
        {
            return;
        }

        const auto kTextAt = [this, rowIndex](const int column) -> QString
        {
            const QTableWidgetItem* item = eventTable_->item(rowIndex, column);
            return item != nullptr ? item->text().trimmed() : QString();
        };
        const QTableWidgetItem* nameItem = eventTable_->item(rowIndex, kColumnName);
        const QString kApplicationPathHint = nameItem != nullptr
            ? nameItem->data(Qt::UserRole + 1).toString().trimmed()
            : QString();
        const QString kWfpDirection = kTextAt(kColumnDirection);
        const QString kFirewallDirection = kWfpDirection.compare(QStringLiteral("In"), Qt::CaseInsensitive) == 0
            ? QStringLiteral("Inbound")
            : kWfpDirection.compare(QStringLiteral("Out"), Qt::CaseInsensitive) == 0
                ? QStringLiteral("Outbound")
                : QStringLiteral("Unknown");
        addBlockRuleFromEvidence(
            kTextAt(kColumnRemoteAddress),
            kTextAt(kColumnRemotePort),
            kTextAt(kColumnProtocol),
            kFirewallDirection,
            QStringLiteral("WFP 事件"),
            0U,
            0U,
            QString(),
            kApplicationPathHint);
    });
    pageLayout->addWidget(eventTable_, 1);

    if (innerTabWidget_ != nullptr)
    {
        innerTabWidget_->addTab(eventMonitorPage_, QStringLiteral("事件监控"));
    }
}

void NetworkFirewallPage::initializeRuleManagerUi()
{
    ruleManagerPage_ = new QWidget(this);
    QVBoxLayout* pageLayout = new QVBoxLayout(ruleManagerPage_);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(6);

    QHBoxLayout* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(8);

    refreshRulesButton_ = new QPushButton(QStringLiteral("刷新规则"), ruleManagerPage_);
    refreshRulesButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    refreshRulesButton_->setToolTip(QStringLiteral("重新枚举 Windows Firewall 规则"));
    toolbarLayout->addWidget(refreshRulesButton_, 0);

    addRuleButton_ = new QPushButton(QStringLiteral("新增"), ruleManagerPage_);
    addRuleButton_->setIcon(QIcon(QStringLiteral(":/Icon/plus.svg")));
    addRuleButton_->setToolTip(QStringLiteral("新增 Windows Firewall 规则"));
    toolbarLayout->addWidget(addRuleButton_, 0);

    editRuleButton_ = new QPushButton(QStringLiteral("编辑"), ruleManagerPage_);
    editRuleButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_details.svg")));
    editRuleButton_->setToolTip(QStringLiteral("编辑选中的规则"));
    editRuleButton_->setEnabled(false);
    toolbarLayout->addWidget(editRuleButton_, 0);

    toggleRuleButton_ = new QPushButton(QStringLiteral("启用/禁用"), ruleManagerPage_);
    toggleRuleButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_suspend.svg")));
    toggleRuleButton_->setToolTip(QStringLiteral("切换选中规则的启用状态"));
    toggleRuleButton_->setEnabled(false);
    toolbarLayout->addWidget(toggleRuleButton_, 0);

    deleteRuleButton_ = new QPushButton(QStringLiteral("删除"), ruleManagerPage_);
    deleteRuleButton_->setIcon(QIcon(QStringLiteral(":/Icon/log_clear.svg")));
    deleteRuleButton_->setToolTip(QStringLiteral("删除选中的规则"));
    deleteRuleButton_->setEnabled(false);
    toolbarLayout->addWidget(deleteRuleButton_, 0);

    ruleSearchEdit_ = new QLineEdit(ruleManagerPage_);
    ruleSearchEdit_->setPlaceholderText(QStringLiteral("搜索 Name/Application/Port/Protocol/Group..."));
    ruleSearchEdit_->setMinimumWidth(240);
    toolbarLayout->addWidget(ruleSearchEdit_, 1);

    ruleEnabledOnlyCheck_ = new QCheckBox(QStringLiteral("仅启用"), ruleManagerPage_);
    toolbarLayout->addWidget(ruleEnabledOnlyCheck_, 0);
    pageLayout->addLayout(toolbarLayout, 0);

    ruleSplitter_ = new QSplitter(Qt::Vertical, ruleManagerPage_);
    ruleTable_ = new ks::ui::VisibleTableWidget(ruleSplitter_);
    ruleTable_->setColumnCount(kRuleColumnCount);
    ruleTable_->setHorizontalHeaderLabels({
        QStringLiteral("Name"),
        QStringLiteral("Enabled"),
        QStringLiteral("Action"),
        QStringLiteral("Direction"),
        QStringLiteral("Profiles"),
        QStringLiteral("Protocol"),
        QStringLiteral("Local Ports"),
        QStringLiteral("Remote Ports"),
        QStringLiteral("Application"),
        QStringLiteral("Service"),
        QStringLiteral("Grouping"),
        QStringLiteral("Description")
        });
    ruleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    ruleTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    ruleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ruleTable_->setAlternatingRowColors(true);
    ruleTable_->verticalHeader()->setVisible(false);
    ruleTable_->horizontalHeader()->setStretchLastSection(false);
    ruleTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    ruleTable_->setColumnWidth(kRuleColumnName, 180);
    ruleTable_->setColumnWidth(kRuleColumnApplication, 220);
    ruleTable_->setColumnWidth(kRuleColumnGrouping, 150);
    ruleTable_->setColumnWidth(kRuleColumnDescription, 220);
    ruleTable_->setContextMenuPolicy(Qt::CustomContextMenu);

    // Full details are fixed below the rule table, occupying approximately one-quarter of the page height by default.
    ruleDetailEditor_ = new CodeEditorWidget(ruleSplitter_);
    ruleDetailEditor_->setReadOnly(true);
    ruleDetailEditor_->setLocalizedText(QStringLiteral("请选择一条防火墙规则查看完整详情。"));
    ruleSplitter_->addWidget(ruleTable_);
    ruleSplitter_->addWidget(ruleDetailEditor_);
    ruleSplitter_->setStretchFactor(0, 3);
    ruleSplitter_->setStretchFactor(1, 1);
    ruleSplitter_->setSizes({ 720, 240 });
    pageLayout->addWidget(ruleSplitter_, 1);

    ks::ui::DetailLayoutRegistry::registerHost(
        ruleTable_, ruleDetailEditor_, ruleManagerPage_);

    if (innerTabWidget_ != nullptr)
    {
        innerTabWidget_->addTab(ruleManagerPage_, QStringLiteral("规则管理"));
    }
}

void NetworkFirewallPage::initializeConnections()
{
    connect(refreshHistoryButton_, &QPushButton::clicked, this, [this]()
    {
        refreshHistoryAsync(true);
    });
    connect(startLiveButton_, &QPushButton::clicked, this, [this]()
    {
        startLiveMonitor();
    });
    connect(stopLiveButton_, &QPushButton::clicked, this, [this]()
    {
        stopLiveMonitor();
    });
    connect(clearButton_, &QPushButton::clicked, this, [this]()
    {
        if (eventTable_ != nullptr)
        {
            eventTable_->setRowCount(0);
        }
    });
    connect(searchEdit_, &QLineEdit::textChanged, this, [this]()
    {
        applyFilterToRows();
    });
    connect(dropOnlyCheck_, &QCheckBox::toggled, this, [this]()
    {
        applyFilterToRows();
    });
    connect(liveFlushTimer_, &QTimer::timeout, this, [this]()
    {
        flushLiveEventsToUi();
    });
    connect(refreshRulesButton_, &QPushButton::clicked, this, [this]()
    {
        refreshRulesAsync(true);
    });
    connect(addRuleButton_, &QPushButton::clicked, this, [this]()
    {
        addFirewallRule();
    });
    connect(editRuleButton_, &QPushButton::clicked, this, [this]()
    {
        editSelectedFirewallRule();
    });
    connect(toggleRuleButton_, &QPushButton::clicked, this, [this]()
    {
        toggleSelectedFirewallRuleEnabled();
    });
    connect(deleteRuleButton_, &QPushButton::clicked, this, [this]()
    {
        deleteSelectedFirewallRules();
    });
    connect(ruleSearchEdit_, &QLineEdit::textChanged, this, [this]()
    {
        applyRuleFilterToRows();
    });
    connect(ruleEnabledOnlyCheck_, &QCheckBox::toggled, this, [this]()
    {
        applyRuleFilterToRows();
    });
    connect(ruleTable_, &QTableWidget::itemSelectionChanged, this, [this]()
    {
        updateRuleActionButtons();
        updateRuleDetailEditor();
    });
    connect(ruleTable_, &QTableWidget::cellDoubleClicked, this, [this](const int, const int)
    {
        editSelectedFirewallRule();
    });
    connect(ruleTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position)
    {
        showRuleContextMenu(position);
    });
    liveFlushTimer_->start();
}

void NetworkFirewallPage::refreshHistoryAsync(const bool forceRefresh)
{
    bool expectedValue = false;
    if (!refreshingHistory_.compare_exchange_strong(expectedValue, true))
    {
        if (forceRefresh)
        {
            setStatusText(QStringLiteral("历史事件正在刷新，请稍候。"));
        }
        return;
    }

    if (refreshHistoryButton_ != nullptr)
    {
        refreshHistoryButton_->setEnabled(false);
    }
    setStatusText(QStringLiteral("正在枚举 WFP 历史事件..."));

    const std::shared_ptr<FirewallAsyncTaskState> kTaskState = acquireFirewallAsyncTaskState(this);
    if (!kTaskState)
    {
        refreshingHistory_.store(false);
        return;
    }
    // The event table is a child control of the page: it is only used after the owner (the page) has passed validation and remains active.
    QTableWidget* const kEventTablePointer = eventTable_;

    try
    {
        // Enum tasks call only file-level functions; they can safely complete after page destruction, so detach directly.
        std::thread([kTaskState, kEventTablePointer]()
        {
            const AsyncWorkerScope kWorkerScope(kTaskState);
            std::vector<FirewallEventEntry> eventList;
            QString errorText;
            try
            {
                HANDLE engineHandle = nullptr;
                if (openWfpEngineShared(false, &engineHandle, &errorText))
                {
                    try
                    {
                        eventList = enumerateHistoryWithEngineShared(engineHandle, &kTaskState->cancelRequested, &errorText);
                    }
                    catch (...)
                    {
                        closeWfpEngineShared(engineHandle, false);
                        throw;
                    }
                    closeWfpEngineShared(engineHandle, false);
                }
            }
            catch (const std::exception& exception)
            {
                errorText = QStringLiteral("刷新失败：%1").arg(QString::fromUtf8(exception.what()));
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            if (kTaskState->cancelRequested.load())
            {
                return;
            }

            // Reverse DNS is separated from the enumeration of primary links: first add the IP to the table, then have an independent task fill in the hostname.
            const QStringList kPendingAddressList = collectUnresolvedAddressList(eventList);

            std::lock_guard<std::mutex> dispatchGuard(kTaskState->dispatchMutex);
            NetworkFirewallPage* const kReceiver = kTaskState->owner;
            if (kReceiver == nullptr)
            {
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                kReceiver,
                [kTaskState, kEventTablePointer, eventList = std::move(eventList), errorText, kPendingAddressList]() mutable
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(kTaskState->dispatchMutex);
                        pagePointer = kTaskState->owner;
                    }
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (errorText.isEmpty())
                    {
                        pagePointer->appendEventsToTable(eventList, true);
                        pagePointer->setStatusText(
                            QStringLiteral("历史事件：%1 条，刷新：%2")
                            .arg(static_cast<int>(eventList.size()))
                            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
                        enqueueHostnameResolution(kEventTablePointer, kTaskState, kPendingAddressList);
                    }
                    else
                    {
                        pagePointer->setStatusText(errorText);
                    }
                    if (pagePointer->refreshHistoryButton_ != nullptr)
                    {
                        pagePointer->refreshHistoryButton_->setEnabled(true);
                    }
                    pagePointer->refreshingHistory_.store(false);
                },
                Qt::QueuedConnection);
            if (!kInvokeOk)
            {
                kReceiver->refreshingHistory_.store(false);
            }
        }).detach();
    }
    catch (...)
    {
        refreshingHistory_.store(false);
        if (refreshHistoryButton_ != nullptr)
        {
            refreshHistoryButton_->setEnabled(true);
        }
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::startLiveMonitor()
{
    if (liveRunning_.load())
    {
        setStatusText(QStringLiteral("实时防火墙监控已经启动。"));
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("实时防火墙事件监控"));
        return;
    }

    const std::shared_ptr<FirewallAsyncTaskState> kTaskState = acquireFirewallAsyncTaskState(this);
    if (!kTaskState)
    {
        return;
    }
    bool expectedTransition = false;
    if (!kTaskState->liveTransitionInProgress.compare_exchange_strong(expectedTransition, true))
    {
        setStatusText(QStringLiteral("实时防火墙监控已经启动。"));
        return;
    }

    // FwpmEngineOpen0 is an RPC to BFE, and FWPM_ENGINE_COLLECT_NET_EVENTS is a global engine policy submission; together they
    // typically take 200ms~1.5s. Move the entire sequence to a background thread and disable the start button on the UI side first.
    if (startLiveButton_ != nullptr)
    {
        startLiveButton_->setEnabled(false);
    }

    try
    {
        std::thread([kTaskState]()
        {
            const AsyncWorkerScope kWorkerScope(kTaskState);
            QString errorText;
            HANDLE engineHandle = nullptr;
            bool subscribed = false;
            try
            {
                if (openWfpEngineShared(true, &engineHandle, &errorText))
                {
                    FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTemplate{};
                    FWPM_NET_EVENT_SUBSCRIPTION0 subscription{};
                    subscription.enumTemplate = &enumTemplate;
                    const HRESULT kGuidStatus = ::CoCreateGuid(&subscription.sessionKey);
                    if (FAILED(kGuidStatus))
                    {
                        errorText = QStringLiteral("启动实时防火墙事件订阅失败：%1。请确认以管理员运行。")
                            .arg(win32ErrorText(static_cast<DWORD>(kGuidStatus)));
                    }
                    else
                    {
                        // Subscription and handle persistence must occur within the same lock: page destruction first sets the cancel flag, then acquires this lock to
                        // clear the owner. Thus, either the subscription was never installed, or the handle was already written to the page and will be unsubscribed
                        // by stopLiveMonitor in the destructor. There is no intermediate state where a callback is attached to a page that is about to be destroyed.
                        std::lock_guard<std::mutex> dispatchGuard(kTaskState->dispatchMutex);
                        NetworkFirewallPage* const kReceiver = kTaskState->owner;
                        if (kReceiver != nullptr && !kTaskState->cancelRequested.load())
                        {
                            HANDLE subscriptionHandle = nullptr;
                            const DWORD kStatus = gWfpApi.eventSubscribe(
                                engineHandle,
                                &subscription,
                                &NetworkFirewallPage::liveEventCallback,
                                kReceiver,
                                &subscriptionHandle);
                            if (kStatus == ERROR_SUCCESS)
                            {
                                kReceiver->liveEngineHandle_ = engineHandle;
                                kReceiver->liveSubscriptionHandle_ = subscriptionHandle;
                                kReceiver->liveRunning_.store(true);
                                subscribed = true;
                                QMetaObject::invokeMethod(
                                    kReceiver,
                                    [kTaskState]()
                                    {
                                        NetworkFirewallPage* pagePointer = nullptr;
                                        {
                                            std::lock_guard<std::mutex> stateGuard(kTaskState->dispatchMutex);
                                            pagePointer = kTaskState->owner;
                                        }
                                        kTaskState->liveTransitionInProgress.store(false);
                                        if (pagePointer == nullptr)
                                        {
                                            return;
                                        }
                                        if (pagePointer->startLiveButton_ != nullptr)
                                        {
                                            pagePointer->startLiveButton_->setEnabled(false);
                                        }
                                        if (pagePointer->stopLiveButton_ != nullptr)
                                        {
                                            pagePointer->stopLiveButton_->setEnabled(true);
                                        }
                                        pagePointer->setStatusText(QStringLiteral("实时防火墙监控已启动。"));
                                    },
                                    Qt::QueuedConnection);
                            }
                            else
                            {
                                errorText = QStringLiteral("启动实时防火墙事件订阅失败：%1。请确认以管理员运行。")
                                    .arg(win32ErrorText(kStatus));
                            }
                        }
                    }
                }
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            if (subscribed)
            {
                return;
            }

            // Subscription failed: this task exclusively owns the engine handle, so reset the collection switch in place and close it.
            if (engineHandle != nullptr)
            {
                closeWfpEngineShared(engineHandle, true);
            }

            std::lock_guard<std::mutex> dispatchGuard(kTaskState->dispatchMutex);
            NetworkFirewallPage* const kReceiver = kTaskState->owner;
            if (kReceiver == nullptr)
            {
                kTaskState->liveTransitionInProgress.store(false);
                return;
            }
            QMetaObject::invokeMethod(
                kReceiver,
                [kTaskState, errorText]()
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(kTaskState->dispatchMutex);
                        pagePointer = kTaskState->owner;
                    }
                    kTaskState->liveTransitionInProgress.store(false);
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (pagePointer->startLiveButton_ != nullptr)
                    {
                        pagePointer->startLiveButton_->setEnabled(true);
                    }
                    if (!errorText.isEmpty())
                    {
                        pagePointer->setStatusText(errorText);
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }
    catch (...)
    {
        kTaskState->liveTransitionInProgress.store(false);
        if (startLiveButton_ != nullptr)
        {
            startLiveButton_->setEnabled(true);
        }
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::stopLiveMonitor()
{
    void* engineHandleToClose = nullptr;
    {
        // Shares the same lock as the 'Start Real-time' background task: serializes writing and retrieval of real-time handles, preventing a
        // race condition where a subscription is installed but the handle hasn't been persisted yet, which could cause the stop path to miss it.
        const std::shared_ptr<FirewallAsyncTaskState> kTaskState = lookupFirewallAsyncTaskState(this);
        std::unique_lock<std::mutex> dispatchGuard;
        if (kTaskState)
        {
            dispatchGuard = std::unique_lock<std::mutex>(kTaskState->dispatchMutex);
        }

        if (liveSubscriptionHandle_ != nullptr && gWfpApi.eventUnsubscribe != nullptr && liveEngineHandle_ != nullptr)
        {
            // Unsubscribe must complete synchronously: only after the function returns does WFP guarantee no further callbacks to this page; asynchronous execution would leave dangling contexts.
            gWfpApi.eventUnsubscribe(
                static_cast<HANDLE>(liveEngineHandle_),
                static_cast<HANDLE>(liveSubscriptionHandle_));
            liveSubscriptionHandle_ = nullptr;
        }
        engineHandleToClose = liveEngineHandle_;
        liveEngineHandle_ = nullptr;
    }

    const bool kWasRunning = liveRunning_.exchange(false);
    if (engineHandleToClose != nullptr)
    {
        if (shuttingDown_.load())
        {
            // Destructor path: performs synchronous closure to ensure the global net event collection switch is reset before process exit.
            closeWfpEngineShared(static_cast<HANDLE>(engineHandleToClose), true);
        }
        else
        {
            // Closing event collection is also a global engine policy submission; offload it to a background thread to prevent UI blocking on button clicks.
            try
            {
                std::thread([engineHandleToClose]()
                {
                    closeWfpEngineShared(static_cast<HANDLE>(engineHandleToClose), true);
                }).detach();
            }
            catch (...)
            {
                closeWfpEngineShared(static_cast<HANDLE>(engineHandleToClose), true);
            }
        }
    }

    if (startLiveButton_ != nullptr)
    {
        startLiveButton_->setEnabled(true);
    }
    if (stopLiveButton_ != nullptr)
    {
        stopLiveButton_->setEnabled(false);
    }
    if (kWasRunning)
    {
        setStatusText(QStringLiteral("实时防火墙监控已停止。"));
    }
}

void NetworkFirewallPage::appendEventsToTable(
    const std::vector<FirewallEventEntry>& eventList,
    const bool clearBeforeAppend)
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    if (ks::ui::isTableUiCommitBlockedByContextMenu({eventTable_}))
    {
        const QPointer<NetworkFirewallPage> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("firewall-event-table-append"),
            {eventTable_},
            [kSafeThis, eventList, clearBeforeAppend]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->appendEventsToTable(eventList, clearBeforeAppend);
                }
            });
        return;
    }

    const std::size_t kMaximumDisplayedEventCount =
        static_cast<std::size_t>(kMaximumDisplayedFirewallEvents);
    const std::size_t kFirstEventIndex = eventList.size() > kMaximumDisplayedEventCount
        ? eventList.size() - kMaximumDisplayedEventCount
        : 0U;
    const int kIncomingRowCount = static_cast<int>(eventList.size() - kFirstEventIndex);

    eventTable_->setUpdatesEnabled(false);
    if (clearBeforeAppend)
    {
        eventTable_->setRowCount(0);
    }

    // Only retain the latest old rows that, together with this batch of new events, fit within the display limit. QTableWidget's model can
    // batch-move remaining rows via a single removeRows call, avoiding repeated full 2D table shifts from individual removeRow(0) calls.
    const int kExistingRowCount = eventTable_->rowCount();
    const int kExistingRowsToKeep = std::max(0, kMaximumDisplayedFirewallEvents - kIncomingRowCount);
    const int kExistingRowsToRemove = std::max(0, kExistingRowCount - kExistingRowsToKeep);
    if (kExistingRowsToRemove > 0)
    {
        QAbstractItemModel* const kEventTableModel = eventTable_->model();
        if (kEventTableModel == nullptr || !kEventTableModel->removeRows(0, kExistingRowsToRemove))
        {
            // QTableWidget's internal model normally supports batch deletion; clearing in abnormal implementations ensures the upper bound remains valid.
            eventTable_->setRowCount(0);
        }
    }

    const int kFirstNewRow = eventTable_->rowCount();
    eventTable_->setRowCount(kFirstNewRow + kIncomingRowCount);
    for (std::size_t eventIndex = kFirstEventIndex; eventIndex < eventList.size(); ++eventIndex)
    {
        const FirewallEventEntry& entry = eventList[eventIndex];
        const int kRow = kFirstNewRow + static_cast<int>(eventIndex - kFirstEventIndex);
        const std::array<QString, kColumnCount> kValues = {
            safeText(entry.nameText),
            safeText(entry.actionText),
            safeText(entry.directionText),
            safeText(entry.ruleText),
            safeText(entry.descriptionText),
            safeText(entry.localAddressText),
            safeText(entry.localPortText),
            safeText(entry.localHostText),
            safeText(entry.remoteAddressText),
            safeText(entry.remotePortText),
            safeText(entry.remoteHostText),
            safeText(entry.protocolText),
            safeText(entry.timestampText)
        };

        for (int column = 0; column < kColumnCount; ++column)
        {
            QTableWidgetItem* item = new QTableWidgetItem(kValues[static_cast<std::size_t>(column)]);
            item->setData(Qt::UserRole, entry.isDrop);
            if (column == kColumnName)
            {
                item->setData(Qt::UserRole + 1, entry.applicationPathText);
            }
            // Do not write a fixed foreground color: DROP/Allowed inherit the table palette and auto-update with theme changes.
            // Action category is still determined via the Action column and the 'DROP only' filter.
            eventTable_->setItem(kRow, column, item);
        }
    }
    applyFilterToRowRange(kFirstNewRow, kIncomingRowCount);
    eventTable_->setUpdatesEnabled(true);
}

void NetworkFirewallPage::applyFilterToRows()
{
    if (eventTable_ == nullptr)
    {
        return;
    }
    applyFilterToRowRange(0, eventTable_->rowCount());
}

void NetworkFirewallPage::applyFilterToRowRange(const int firstRow, const int rowCount)
{
    if (eventTable_ == nullptr || rowCount <= 0)
    {
        return;
    }
    const QString kFilterText = searchEdit_ != nullptr ? searchEdit_->text().trimmed().toLower() : QString();
    const bool kDropOnly = dropOnlyCheck_ != nullptr && dropOnlyCheck_->isChecked();

    const int kFirstValidRow = std::clamp(firstRow, 0, eventTable_->rowCount());
    const int kLastValidRow = std::min(eventTable_->rowCount(), kFirstValidRow + rowCount);
    for (int row = kFirstValidRow; row < kLastValidRow; ++row)
    {
        bool isDrop = false;
        QString rowText;
        for (int column = 0; column < kColumnCount; ++column)
        {
            QTableWidgetItem* item = eventTable_->item(row, column);
            if (item == nullptr)
            {
                continue;
            }
            rowText.append(item->text()).append(QLatin1Char('\n'));
            if (column == kColumnAction)
            {
                isDrop = item->data(Qt::UserRole).toBool();
            }
        }
        const bool kTextMatched = kFilterText.isEmpty() || rowText.toLower().contains(kFilterText);
        const bool kDropMatched = !kDropOnly || isDrop;
        eventTable_->setRowHidden(row, !(kTextMatched && kDropMatched));
    }
}

void NetworkFirewallPage::flushLiveEventsToUi()
{
    // Do not drain early when the menu is open: the real-time queue preserves the original order and is consumed all at once after closing.
    const QPointer<NetworkFirewallPage> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("firewall-live-event-flush"),
        {eventTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->flushLiveEventsToUi();
            }
        }))
    {
        return;
    }

    std::deque<FirewallEventEntry> queuedEvents;
    {
        std::lock_guard<std::mutex> guard(liveEventMutex_);
        if (liveEventQueue_.empty())
        {
            return;
        }
        queuedEvents.swap(liveEventQueue_);
    }

    std::vector<FirewallEventEntry> eventList;
    eventList.reserve(queuedEvents.size());
    while (!queuedEvents.empty())
    {
        eventList.push_back(std::move(queuedEvents.front()));
        queuedEvents.pop_front();
    }
    appendEventsToTable(eventList, false);
    // The hostname for real-time events is also not synchronously resolved in the WFP callback thread; instead, it is asynchronously filled in afterward.
    enqueueHostnameResolution(
        eventTable_,
        acquireFirewallAsyncTaskState(this),
        collectUnresolvedAddressList(eventList));
    setStatusText(QStringLiteral("实时事件：追加 %1 条，总计 %2 条")
        .arg(static_cast<int>(eventList.size()))
        .arg(eventTable_ != nullptr ? eventTable_->rowCount() : 0));
}

void NetworkFirewallPage::setStatusText(const QString& statusText)
{
    if (QThread::currentThread() == thread())
    {
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(statusText);
        }
        return;
    }
    QPointer<NetworkFirewallPage> safeThis(this);
    QMetaObject::invokeMethod(
        this,
        [safeThis, statusText]()
        {
            if (!safeThis.isNull() && safeThis->statusLabel_ != nullptr)
            {
                safeThis->statusLabel_->setText(statusText);
            }
        },
        Qt::QueuedConnection);
}

void NetworkFirewallPage::refreshRulesAsync(const bool forceRefresh)
{
    bool expectedValue = false;
    if (!refreshingRules_.compare_exchange_strong(expectedValue, true))
    {
        if (forceRefresh)
        {
            setStatusText(QStringLiteral("防火墙规则正在刷新，请稍候。"));
        }
        return;
    }

    if (refreshRulesButton_ != nullptr)
    {
        refreshRulesButton_->setEnabled(false);
    }
    setStatusText(QStringLiteral("正在枚举 Windows Firewall 规则..."));

    const std::shared_ptr<FirewallAsyncTaskState> kTaskState = acquireFirewallAsyncTaskState(this);
    if (!kTaskState)
    {
        refreshingRules_.store(false);
        return;
    }

    try
    {
        // Enum tasks call only file-level functions; they can safely complete after page destruction, so detach directly.
        std::thread([kTaskState]()
        {
            const AsyncWorkerScope kWorkerScope(kTaskState);
            std::vector<FirewallRuleEntry> ruleList;
            QString errorText;
            try
            {
                ruleList = enumerateFirewallRulesSnapshotShared(&errorText);
            }
            catch (const std::exception& exception)
            {
                errorText = QStringLiteral("刷新失败：%1").arg(QString::fromUtf8(exception.what()));
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            if (kTaskState->cancelRequested.load())
            {
                return;
            }

            std::lock_guard<std::mutex> dispatchGuard(kTaskState->dispatchMutex);
            NetworkFirewallPage* const kReceiver = kTaskState->owner;
            if (kReceiver == nullptr)
            {
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                kReceiver,
                [kTaskState, ruleList = std::move(ruleList), errorText]() mutable
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(kTaskState->dispatchMutex);
                        pagePointer = kTaskState->owner;
                    }
                    if (pagePointer == nullptr)
                    {
                        return;
                    }

                    auto applyResult = [
                        kTaskState,
                        ruleSnapshot = std::move(ruleList),
                        errorText]() mutable
                    {
                        NetworkFirewallPage* deferredPagePointer = nullptr;
                        {
                            std::lock_guard<std::mutex> stateGuard(kTaskState->dispatchMutex);
                            deferredPagePointer = kTaskState->owner;
                        }
                        if (deferredPagePointer == nullptr)
                        {
                            return;
                        }

                        if (errorText.isEmpty())
                        {
                            deferredPagePointer->ruleEntryList_ = ruleSnapshot;
                            deferredPagePointer->appendRulesToTable(deferredPagePointer->ruleEntryList_, true);
                            deferredPagePointer->setStatusText(
                                QStringLiteral("防火墙规则：%1 条，刷新：%2")
                                .arg(static_cast<int>(deferredPagePointer->ruleEntryList_.size()))
                                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
                        }
                        else
                        {
                            deferredPagePointer->setStatusText(errorText);
                        }

                        if (deferredPagePointer->refreshRulesButton_ != nullptr)
                        {
                            deferredPagePointer->refreshRulesButton_->setEnabled(true);
                        }
                        deferredPagePointer->updateRuleActionButtons();
                        deferredPagePointer->updateRuleDetailEditor();
                        deferredPagePointer->refreshingRules_.store(false);
                    };

                    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                            pagePointer,
                            QStringLiteral("firewall-rule-refresh-result-apply"),
                            {pagePointer->ruleTable_},
                            applyResult))
                    {
                        return;
                    }
                    applyResult();
                },
                Qt::QueuedConnection);
            if (!kInvokeOk)
            {
                kReceiver->refreshingRules_.store(false);
            }
        }).detach();
    }
    catch (...)
    {
        refreshingRules_.store(false);
        if (refreshRulesButton_ != nullptr)
        {
            refreshRulesButton_->setEnabled(true);
        }
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::appendRulesToTable(
    const std::vector<FirewallRuleEntry>& ruleList,
    const bool clearBeforeAppend)
{
    if (ruleTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(ruleDetailEditor_);

    if (ks::ui::isTableUiCommitBlockedByContextMenu({ruleTable_}))
    {
        const QPointer<NetworkFirewallPage> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("firewall-rule-table-append"),
            {ruleTable_},
            [kSafeThis, ruleList, clearBeforeAppend]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->appendRulesToTable(ruleList, clearBeforeAppend);
                }
            });
        return;
    }

    if (clearBeforeAppend)
    {
        ruleTable_->setRowCount(0);
    }

    ruleTable_->setUpdatesEnabled(false);
    for (const FirewallRuleEntry& ruleEntry : ruleList)
    {
        const int kRow = ruleTable_->rowCount();
        ruleTable_->insertRow(kRow);

        const std::array<QString, kRuleColumnCount> kValueList = {
            safeText(ruleEntry.nameText),
            ruleEntry.enabled ? QStringLiteral("Yes") : QStringLiteral("No"),
            safeText(ruleEntry.actionText),
            safeText(ruleEntry.directionText),
            safeText(ruleEntry.profilesText),
            safeText(ruleEntry.protocolText),
            safeText(ruleEntry.localPortsText),
            safeText(ruleEntry.remotePortsText),
            safeText(ruleEntry.applicationText),
            safeText(ruleEntry.serviceText),
            safeText(ruleEntry.groupingText),
            safeText(ruleEntry.descriptionText)
        };

        for (int column = 0; column < kRuleColumnCount; ++column)
        {
            QTableWidgetItem* item = new QTableWidgetItem(kValueList[static_cast<std::size_t>(column)]);
            item->setData(Qt::UserRole, ruleEntry.fingerprintText);
            item->setData(Qt::UserRole + 1, ruleEntry.enabled);
            if (!ruleEntry.enabled)
            {
                item->setForeground(ksword_theme::textSecondaryColor());
            }
            else if (column == kRuleColumnAction && ruleEntry.actionValue == NET_FW_ACTION_BLOCK)
            {
                item->setForeground(ksword_theme::errorColor());
            }
            ruleTable_->setItem(kRow, column, item);
        }
    }
    ruleTable_->setUpdatesEnabled(true);
    applyRuleFilterToRows();
}

void NetworkFirewallPage::applyRuleFilterToRows()
{
    if (ruleTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(ruleDetailEditor_);

    const QString kFilterText = ruleSearchEdit_ != nullptr ? ruleSearchEdit_->text().trimmed().toLower() : QString();
    const bool kEnabledOnly = ruleEnabledOnlyCheck_ != nullptr && ruleEnabledOnlyCheck_->isChecked();

    for (int row = 0; row < ruleTable_->rowCount(); ++row)
    {
        QString rowText;
        bool enabled = false;
        for (int column = 0; column < kRuleColumnCount; ++column)
        {
            QTableWidgetItem* item = ruleTable_->item(row, column);
            if (item == nullptr)
            {
                continue;
            }
            rowText.append(item->text()).append(QLatin1Char('\n'));
            if (column == kRuleColumnEnabled)
            {
                enabled = item->data(Qt::UserRole + 1).toBool();
            }
        }

        const bool kTextMatched = kFilterText.isEmpty() || rowText.toLower().contains(kFilterText);
        const bool kEnabledMatched = !kEnabledOnly || enabled;
        ruleTable_->setRowHidden(row, !(kTextMatched && kEnabledMatched));
    }
}

void NetworkFirewallPage::updateRuleActionButtons()
{
    int visibleSelectedRowCount = 0;
    if (ruleTable_ != nullptr)
    {
        const QModelIndexList kRowIndexList = ruleTable_->selectionModel() != nullptr
            ? ruleTable_->selectionModel()->selectedRows()
            : QModelIndexList{};
        for (const QModelIndex& rowIndex : kRowIndexList)
        {
            if (!ruleTable_->isRowHidden(rowIndex.row()))
            {
                ++visibleSelectedRowCount;
            }
        }
    }

    const bool kHasSingleSelection = visibleSelectedRowCount == 1;
    const bool kHasSelection = visibleSelectedRowCount > 0;

    if (editRuleButton_ != nullptr)
    {
        editRuleButton_->setEnabled(kHasSingleSelection);
    }
    if (toggleRuleButton_ != nullptr)
    {
        toggleRuleButton_->setEnabled(kHasSingleSelection);
    }
    if (deleteRuleButton_ != nullptr)
    {
        deleteRuleButton_->setEnabled(kHasSelection);
    }

    if (toggleRuleButton_ != nullptr && kHasSingleSelection)
    {
        FirewallRuleEntry selectedRuleEntryValue;
        if (selectedRuleEntry(&selectedRuleEntryValue))
        {
            toggleRuleButton_->setText(selectedRuleEntryValue.enabled ? QStringLiteral("禁用") : QStringLiteral("启用"));
        }
    }
    else if (toggleRuleButton_ != nullptr)
    {
        toggleRuleButton_->setText(QStringLiteral("启用/禁用"));
    }
}

void NetworkFirewallPage::updateRuleDetailEditor()
{
    if (ruleDetailEditor_ == nullptr)
    {
        return;
    }

    FirewallRuleEntry ruleEntry;
    if (!selectedRuleEntry(&ruleEntry))
    {
        ruleDetailEditor_->setLocalizedText(
            QStringLiteral("请选择一条防火墙规则查看完整详情。"));
        return;
    }

    const QString kDetailText = QStringLiteral(
        "名称：%1\n"
        "启用：%2\n"
        "动作：%3\n"
        "方向：%4\n"
        "配置文件：%5\n"
        "协议：%6\n"
        "本地端口：%7\n"
        "远端端口：%8\n"
        "本地地址：%9\n"
        "远端地址：%10\n"
        "应用程序：%11\n"
        "服务：%12\n"
        "分组：%13\n"
        "描述：%14\n"
        "规则指纹：%15")
        .arg(safeText(ruleEntry.nameText))
        .arg(ruleEntry.enabled ? QStringLiteral("是") : QStringLiteral("否"))
        .arg(safeText(ruleEntry.actionText))
        .arg(safeText(ruleEntry.directionText))
        .arg(safeText(ruleEntry.profilesText))
        .arg(safeText(ruleEntry.protocolText))
        .arg(safeText(ruleEntry.localPortsText))
        .arg(safeText(ruleEntry.remotePortsText))
        .arg(safeText(ruleEntry.localAddressesText))
        .arg(safeText(ruleEntry.remoteAddressesText))
        .arg(safeText(ruleEntry.applicationText))
        .arg(safeText(ruleEntry.serviceText))
        .arg(safeText(ruleEntry.groupingText))
        .arg(safeText(ruleEntry.descriptionText))
        .arg(safeText(ruleEntry.fingerprintText));
    ruleDetailEditor_->setLocalizedText(kDetailText);
}

void NetworkFirewallPage::showRuleContextMenu(const QPoint& localPosition)
{
    if (ruleTable_ == nullptr)
    {
        return;
    }

    // Do not reset selection when the right-click occurs on an already selected row: selectRow collapses multi-selection to a
    // single row. If a user selects ten rules via box-selection and then right-clicks 'Delete Rule', only the rule under the mouse
    // is deleted. After the list refreshes, the remaining nine rules persist, making it appear as if the operation had no effect.
    // Only move the selection if the right-click is outside the current selection, matching File Explorer behavior.
    const QModelIndex kClickedIndex = ruleTable_->indexAt(localPosition);
    if (kClickedIndex.isValid())
    {
        QItemSelectionModel* ruleSelectionModel = ruleTable_->selectionModel();
        // This table uses SelectRows; clicking a cell in a fully selected row naturally falls within the selection.
        const bool kClickedRowAlreadySelected =
            ruleSelectionModel != nullptr && ruleSelectionModel->isSelected(kClickedIndex);
        if (!kClickedRowAlreadySelected)
        {
            ruleTable_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            ruleTable_->selectRow(kClickedIndex.row());
        }
        else if (ruleSelectionModel != nullptr)
        {
            // Preserve the entire selection range, only moving the "current item" to the right-click position so that single actions in the menu still have a clear target.
            ruleSelectionModel->setCurrentIndex(kClickedIndex, QItemSelectionModel::NoUpdate);
        }
    }

    FirewallRuleEntry selectedEntry;
    const bool kHasSingleRule = selectedRuleEntry(&selectedEntry);
    const bool kHasAnySelection =
        ruleTable_->selectionModel() != nullptr
        && !ruleTable_->selectionModel()->selectedRows().isEmpty();

    QMenu menu(ruleTable_);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* addAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/plus.svg")),
        QStringLiteral("新增规则"));
    QAction* editAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("编辑规则"));
    editAction->setEnabled(kHasSingleRule);
    QAction* toggleAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_suspend.svg")),
        kHasSingleRule && selectedEntry.enabled
            ? QStringLiteral("禁用规则")
            : QStringLiteral("启用规则"));
    toggleAction->setEnabled(kHasSingleRule);
    QAction* refreshAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        QStringLiteral("刷新规则"));
    QAction* deleteAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")),
        QStringLiteral("删除规则"));
    deleteAction->setEnabled(kHasAnySelection);
    menu.addSeparator();
    QAction* copyAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));
    copyAction->setEnabled(ruleTable_->currentRow() >= 0);

    const QAction* selectedAction = menu.exec(
        ruleTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == addAction)
    {
        addFirewallRule();
    }
    else if (selectedAction == editAction)
    {
        editSelectedFirewallRule();
    }
    else if (selectedAction == toggleAction)
    {
        toggleSelectedFirewallRuleEnabled();
    }
    else if (selectedAction == refreshAction)
    {
        refreshRulesAsync(true);
    }
    else if (selectedAction == deleteAction)
    {
        deleteSelectedFirewallRules();
    }
    else if (selectedAction == copyAction)
    {
        const int kRowIndex = ruleTable_->currentRow();
        QStringList rowFields;
        rowFields.reserve(ruleTable_->columnCount());
        for (int columnIndex = 0; columnIndex < ruleTable_->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = ruleTable_->item(kRowIndex, columnIndex);
            rowFields.push_back(item != nullptr ? item->text() : QString());
        }
        if (QGuiApplication::clipboard() != nullptr)
        {
            QGuiApplication::clipboard()->setText(rowFields.join(QLatin1Char('\t')));
        }
    }
}

bool NetworkFirewallPage::selectedRuleEntry(FirewallRuleEntry* ruleEntryOut) const
{
    if (ruleEntryOut == nullptr || ruleTable_ == nullptr || ruleTable_->selectionModel() == nullptr)
    {
        return false;
    }

    const QModelIndexList kRowIndexList = ruleTable_->selectionModel()->selectedRows();
    if (kRowIndexList.isEmpty())
    {
        return false;
    }

    const int kRow = kRowIndexList.front().row();
    const QTableWidgetItem* nameItem = ruleTable_->item(kRow, kRuleColumnName);
    if (nameItem == nullptr)
    {
        return false;
    }

    const QString kFingerprintText = nameItem->data(Qt::UserRole).toString();
    const auto kIt = std::find_if(
        ruleEntryList_.begin(),
        ruleEntryList_.end(),
        [&kFingerprintText](const FirewallRuleEntry& ruleEntry)
        {
            return ruleEntry.fingerprintText == kFingerprintText;
        });
    if (kIt == ruleEntryList_.end())
    {
        return false;
    }

    *ruleEntryOut = *kIt;
    return true;
}

int NetworkFirewallPage::ruleNameDuplicateCount(const QString& ruleNameText) const
{
    return static_cast<int>(std::count_if(
        ruleEntryList_.begin(),
        ruleEntryList_.end(),
        [&ruleNameText](const FirewallRuleEntry& ruleEntry)
        {
            return ruleEntry.nameText.compare(ruleNameText, Qt::CaseSensitive) == 0;
        }));
}

// enumerateFirewallRulesSnapshot:
// - Input: error text output;
// - Handling: Delegates to the file-level enumerateFirewallRulesSnapshotShared; implementation is moved to
//         the file level to ensure detached background tasks can complete safely even after the page is destructed.
// - Returns: The rule list.
std::vector<NetworkFirewallPage::FirewallRuleEntry>
NetworkFirewallPage::enumerateFirewallRulesSnapshot(QString* errorTextOut) const
{
    return enumerateFirewallRulesSnapshotShared(errorTextOut);
}

bool NetworkFirewallPage::addFirewallRuleEntryToSystem(
    const FirewallRuleEntry& ruleEntry,
    QString* errorTextOut) const
{
    ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
    if (!comInitializer.succeeded())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
        }
        return false;
    }

    INetFwPolicy2* policyPointer = nullptr;
    HRESULT result = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(&policyPointer));
    if (FAILED(result) || policyPointer == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("创建 INetFwPolicy2 失败：0x%1")
                .arg(static_cast<unsigned long>(result), 0, 16);
        }
        return false;
    }

    INetFwRules* rulesPointer = nullptr;
    result = policyPointer->get_Rules(&rulesPointer);
    if (FAILED(result) || rulesPointer == nullptr)
    {
        releaseComPointer(policyPointer);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("获取规则集合失败：0x%1")
                .arg(static_cast<unsigned long>(result), 0, 16);
        }
        return false;
    }

    INetFwRule* newRulePointer = nullptr;
    result = CoCreateInstance(
        __uuidof(NetFwRule),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule),
        reinterpret_cast<void**>(&newRulePointer));
    if (FAILED(result) || newRulePointer == nullptr)
    {
        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("创建 INetFwRule 失败：0x%1")
                .arg(static_cast<unsigned long>(result), 0, 16);
        }
        return false;
    }

    ScopedBstr nameText(bstrFromQString(ruleEntry.nameText));
    ScopedBstr descriptionText(bstrFromQString(ruleEntry.descriptionText));
    ScopedBstr applicationText(bstrFromQString(ruleEntry.applicationText));
    ScopedBstr serviceText(bstrFromQString(ruleEntry.serviceText));
    ScopedBstr localPortsText(bstrFromQString(ruleEntry.localPortsText));
    ScopedBstr remotePortsText(bstrFromQString(ruleEntry.remotePortsText));
    ScopedBstr localAddressesText(bstrFromQString(ruleEntry.localAddressesText));
    ScopedBstr remoteAddressesText(bstrFromQString(ruleEntry.remoteAddressesText));
    ScopedBstr groupingText(bstrFromQString(ruleEntry.groupingText));

    result = newRulePointer->put_Name(nameText.get());
    if (SUCCEEDED(result) && descriptionText.get() != nullptr)
    {
        result = newRulePointer->put_Description(descriptionText.get());
    }
    if (SUCCEEDED(result) && applicationText.get() != nullptr)
    {
        result = newRulePointer->put_ApplicationName(applicationText.get());
    }
    if (SUCCEEDED(result) && serviceText.get() != nullptr)
    {
        result = newRulePointer->put_ServiceName(serviceText.get());
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Protocol(ruleEntry.protocolValue);
    }
    if (SUCCEEDED(result) && localPortsText.get() != nullptr)
    {
        result = newRulePointer->put_LocalPorts(localPortsText.get());
    }
    if (SUCCEEDED(result) && remotePortsText.get() != nullptr)
    {
        result = newRulePointer->put_RemotePorts(remotePortsText.get());
    }
    if (SUCCEEDED(result) && localAddressesText.get() != nullptr)
    {
        result = newRulePointer->put_LocalAddresses(localAddressesText.get());
    }
    if (SUCCEEDED(result) && remoteAddressesText.get() != nullptr)
    {
        result = newRulePointer->put_RemoteAddresses(remoteAddressesText.get());
    }
    if (SUCCEEDED(result) && groupingText.get() != nullptr)
    {
        result = newRulePointer->put_Grouping(groupingText.get());
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(ruleEntry.directionValue));
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Profiles(ruleEntry.profilesValue);
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Action(static_cast<NET_FW_ACTION>(ruleEntry.actionValue));
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Enabled(ruleEntry.enabled ? VARIANT_TRUE : VARIANT_FALSE);
    }
    if (SUCCEEDED(result))
    {
        result = rulesPointer->Add(newRulePointer);
    }

    releaseComPointer(newRulePointer);
    releaseComPointer(rulesPointer);
    releaseComPointer(policyPointer);

    if (FAILED(result))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("写入防火墙规则失败：0x%1")
                .arg(static_cast<unsigned long>(result), 0, 16);
        }
        return false;
    }
    return true;
}

// updateFirewallRuleEntryInSystem:
// - Input: Original fingerprint, new rule content, and error text output;
// - Processing: Delegate to the file-level updateFirewallRuleInSystemShared; the rule name is taken from the first
//         segment of the fingerprint to allow direct access via INetFwRules::Item instead of enumerating the entire table.
// - Returns: true on successful write-back.
bool NetworkFirewallPage::updateFirewallRuleEntryInSystem(
    const QString& originalFingerprintText,
    const FirewallRuleEntry& updatedRuleEntry,
    QString* errorTextOut) const
{
    return updateFirewallRuleInSystemShared(
        originalFingerprintText.section(QStringLiteral("||"), 0, 0),
        originalFingerprintText,
        updatedRuleEntry,
        errorTextOut);
}

// setFirewallRuleEnabledInSystem:
// - Input: rule fingerprint, target enabled state, and error text output;
// - Handling: Delegate to the file-level setFirewallRuleEnabledInSystemShared; the rule name is derived from the first segment of the fingerprint.
// - Returns: true on successful write-back.
bool NetworkFirewallPage::setFirewallRuleEnabledInSystem(
    const QString& fingerprintText,
    const bool enabled,
    QString* errorTextOut) const
{
    return setFirewallRuleEnabledInSystemShared(
        fingerprintText.section(QStringLiteral("||"), 0, 0),
        fingerprintText,
        enabled,
        errorTextOut);
}

// deleteFirewallRuleFromSystem:
// - Input: rule name, error text output;
// - Processing: Delegate to the file-level deleteFirewallRulesFromSystemShared to delete a single rule.
// - Returns: true on successful deletion.
bool NetworkFirewallPage::deleteFirewallRuleFromSystem(
    const QString& ruleNameText,
    QString* errorTextOut) const
{
    int deletedCount = 0;
    return deleteFirewallRulesFromSystemShared(QStringList{ruleNameText}, &deletedCount, errorTextOut);
}

void NetworkFirewallPage::addFirewallRule()
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("新增防火墙规则"));
        return;
    }
    FirewallRuleEditorDialog dialog(nullptr, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    const FirewallRuleEntry kRuleEntry = dialog.ruleEntry();
    QString errorText;
    if (!addFirewallRuleEntryToSystem(kRuleEntry, &errorText))
    {
        // privilegePromptHandled: When the privilege recovery prompt has been displayed, retain only the page state without showing a duplicate popup.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新增防火墙规则"), errorText);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新增规则失败"), errorText);
        }
        setStatusText(errorText);
        return;
    }

    setStatusText(QStringLiteral("已新增防火墙规则：%1").arg(kRuleEntry.nameText));
    refreshRulesAsync(true);
}

void NetworkFirewallPage::addBlockRuleFromEvidence(
    const QString& remoteAddress,
    const QString& remotePort,
    const QString& protocolText,
    const QString& directionText,
    const QString& sourceText,
    const std::uint32_t observedProcessId,
    const std::uint64_t expectedProcessCreationTime100ns,
    const QString& expectedProcessImagePath,
    const QString& applicationPathHint)
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("新增防火墙规则"));
        return;
    }

    const bool kIsInbound = directionText.compare(QStringLiteral("Inbound"), Qt::CaseInsensitive) == 0;
    const bool kIsOutbound = directionText.compare(QStringLiteral("Outbound"), Qt::CaseInsensitive) == 0;
    if (!kIsInbound && !kIsOutbound)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("预填阻断规则"),
            QStringLiteral("审计证据未包含可信的入站或出站方向，无法安全预填防火墙规则。"));
        return;
    }
    if (remoteAddress.trimmed().isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("预填阻断规则"),
            QStringLiteral("审计证据未包含可信的远端地址，无法安全预填防火墙规则。"));
        return;
    }

    FirewallRuleEntry initialRule;
    initialRule.nameText = QStringLiteral("KSword 阻断 - %1").arg(sourceText);

    // Do not write raw PIDs from historical NIDS entries directly into rules. Only pre-fill the 'program' condition in the Windows
    // Firewall rule if both the current creation time and image path match the snapshot taken when the alert was generated.
    bool processIdentityMatches = false;
    QString currentProcessImagePath;
    if (observedProcessId != 0U &&
        expectedProcessCreationTime100ns != 0U &&
        !expectedProcessImagePath.trimmed().isEmpty())
    {
        std::uint64_t creationTimeBeforePathRead100ns = 0U;
        if (ks::process::queryProcessCreationTimeByPid(
                observedProcessId,
                &creationTimeBeforePathRead100ns,
                nullptr) &&
            creationTimeBeforePathRead100ns == expectedProcessCreationTime100ns)
        {
            currentProcessImagePath = QString::fromStdString(
                ks::process::queryProcessPathByPid(observedProcessId)).trimmed();
            std::uint64_t creationTimeAfterPathRead100ns = 0U;
            if (ks::process::queryProcessCreationTimeByPid(
                    observedProcessId,
                    &creationTimeAfterPathRead100ns,
                    nullptr) &&
                creationTimeAfterPathRead100ns == expectedProcessCreationTime100ns)
            {
                processIdentityMatches =
                    !currentProcessImagePath.isEmpty() &&
                    currentProcessImagePath.compare(
                        expectedProcessImagePath.trimmed(),
                        Qt::CaseInsensitive) == 0;
            }
        }
    }

    const QString kTrimmedApplicationPathHint = applicationPathHint.trimmed();
    const bool kHasUsableApplicationPathHint =
        kTrimmedApplicationPathHint.size() >= 3 &&
        kTrimmedApplicationPathHint.at(1) == QLatin1Char(':') &&
        (kTrimmedApplicationPathHint.at(2) == QLatin1Char('\\') ||
            kTrimmedApplicationPathHint.at(2) == QLatin1Char('/'));
    if (processIdentityMatches)
    {
        initialRule.applicationText = currentProcessImagePath;
        initialRule.descriptionText = QStringLiteral(
            "由审计证据预填；已复核 PID=%1 的当前进程身份。请在保存前核对匹配范围。")
            .arg(observedProcessId);
    }
    else if (kHasUsableApplicationPathHint)
    {
        initialRule.applicationText = kTrimmedApplicationPathHint;
        initialRule.descriptionText = QStringLiteral(
            "由审计证据预填；已带入 WFP 事件的应用程序路径。请在保存前核对匹配范围。");
    }
    else
    {
        initialRule.descriptionText = expectedProcessCreationTime100ns != 0U || !expectedProcessImagePath.trimmed().isEmpty()
            ? QStringLiteral("由审计证据预填；关联进程已退出、不可访问或 PID 已复用，未预填程序范围。请在保存前核对匹配范围。")
            : QStringLiteral("由审计证据预填；未能核验或提取应用程序范围。请在保存前核对匹配范围。");
    }
    initialRule.remoteAddressesText = remoteAddress.trimmed();
    initialRule.remotePortsText = remotePort.trimmed();
    initialRule.actionValue = NET_FW_ACTION_BLOCK;
    initialRule.directionValue = kIsInbound ? NET_FW_RULE_DIR_IN : NET_FW_RULE_DIR_OUT;
    initialRule.protocolValue = protocolText.compare(QStringLiteral("UDP"), Qt::CaseInsensitive) == 0
        ? NET_FW_IP_PROTOCOL_UDP
        : protocolText.compare(QStringLiteral("TCP"), Qt::CaseInsensitive) == 0
            ? NET_FW_IP_PROTOCOL_TCP
            : NET_FW_IP_PROTOCOL_ANY;
    initialRule.enabled = true;
    initialRule.profilesValue = NET_FW_PROFILE2_ALL;

    FirewallRuleEditorDialog dialog(&initialRule, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    const FirewallRuleEntry kRuleEntry = dialog.ruleEntry();
    QString errorText;
    if (!addFirewallRuleEntryToSystem(kRuleEntry, &errorText))
    {
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新增防火墙规则"), errorText);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新增规则失败"), errorText);
        }
        setStatusText(errorText);
        return;
    }
    setStatusText(QStringLiteral("已新增防火墙规则：%1").arg(kRuleEntry.nameText));
    refreshRulesAsync(true);
}

void NetworkFirewallPage::addUdpEndpointBlockRuleFromEvidence(
    const QString& localEndpointText,
    const std::uint32_t observedProcessId)
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("新增防火墙规则"));
        return;
    }

    const QString kNormalizedEndpoint = localEndpointText.trimmed();
    const int kPortSeparator = kNormalizedEndpoint.lastIndexOf(QLatin1Char(':'));
    bool portOk = false;
    const quint16 kLocalPort = kPortSeparator > 0
        ? kNormalizedEndpoint.mid(kPortSeparator + 1).toUShort(&portOk, 10)
        : 0U;
    QString localAddress = kPortSeparator > 0
        ? kNormalizedEndpoint.left(kPortSeparator).trimmed()
        : QString();
    if (localAddress.startsWith(QLatin1Char('[')) && localAddress.endsWith(QLatin1Char(']')))
    {
        localAddress = localAddress.mid(1, localAddress.size() - 2);
    }
    if (!portOk || kLocalPort == 0U || localAddress.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("预填 UDP 阻断规则"),
            QStringLiteral("所选 UDP 端点格式无效，无法安全预填防火墙规则。"));
        return;
    }

    FirewallRuleEntry initialRule;
    initialRule.nameText = QStringLiteral("KSword 阻断 - NSI UDP");
    initialRule.descriptionText = QStringLiteral(
        "由 NSI UDP 端点预填；端点不携带方向，默认出站。请在保存前核对方向和匹配范围。PID=%1")
        .arg(observedProcessId);
    // 0.0.0.0/:: represents any local address; leaving it empty is required to express a rule for the same port across all local interfaces.
    if (localAddress != QStringLiteral("0.0.0.0") && localAddress != QStringLiteral("::"))
    {
        initialRule.localAddressesText = localAddress;
    }
    initialRule.localPortsText = QString::number(kLocalPort);
    initialRule.actionValue = NET_FW_ACTION_BLOCK;
    initialRule.directionValue = NET_FW_RULE_DIR_OUT;
    initialRule.protocolValue = NET_FW_IP_PROTOCOL_UDP;
    initialRule.enabled = true;
    initialRule.profilesValue = NET_FW_PROFILE2_ALL;

    FirewallRuleEditorDialog dialog(&initialRule, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    const FirewallRuleEntry kRuleEntry = dialog.ruleEntry();
    QString errorText;
    if (!addFirewallRuleEntryToSystem(kRuleEntry, &errorText))
    {
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新增防火墙规则"), errorText);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新增规则失败"), errorText);
        }
        setStatusText(errorText);
        return;
    }
    setStatusText(QStringLiteral("已新增防火墙规则：%1").arg(kRuleEntry.nameText));
    refreshRulesAsync(true);
}

void NetworkFirewallPage::editSelectedFirewallRule()
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("编辑防火墙规则"));
        return;
    }
    FirewallRuleEntry originalRuleEntry;
    if (!selectedRuleEntry(&originalRuleEntry))
    {
        return;
    }

    FirewallRuleEditorDialog dialog(&originalRuleEntry, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    const FirewallRuleEntry kUpdatedRuleEntry = dialog.ruleEntry();
    const std::shared_ptr<FirewallAsyncTaskState> kTaskState = acquireFirewallAsyncTaskState(this);
    if (!kTaskState)
    {
        return;
    }
    bool expectedMutation = false;
    if (!kTaskState->ruleMutationInProgress.compare_exchange_strong(expectedMutation, true))
    {
        setStatusText(QStringLiteral("防火墙规则正在刷新，请稍候。"));
        return;
    }

    // Rule location and field-by-field writeback both submit to MPSSVC policies; the entire block is moved to a background thread;
    // Grays out rule action buttons on the UI side first; restores them via updateRuleActionButtons after results return.
    if (editRuleButton_ != nullptr)
    {
        editRuleButton_->setEnabled(false);
    }
    if (toggleRuleButton_ != nullptr)
    {
        toggleRuleButton_->setEnabled(false);
    }
    if (deleteRuleButton_ != nullptr)
    {
        deleteRuleButton_->setEnabled(false);
    }

    try
    {
        std::thread([kTaskState,
                     originalNameText = originalRuleEntry.nameText,
                     originalFingerprintText = originalRuleEntry.fingerprintText,
                     kUpdatedRuleEntry]()
        {
            const AsyncWorkerScope kWorkerScope(kTaskState);
            QString errorText;
            bool updated = false;
            try
            {
                updated = updateFirewallRuleInSystemShared(
                    originalNameText,
                    originalFingerprintText,
                    kUpdatedRuleEntry,
                    &errorText);
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            std::lock_guard<std::mutex> dispatchGuard(kTaskState->dispatchMutex);
            NetworkFirewallPage* const kReceiver = kTaskState->owner;
            if (kReceiver == nullptr)
            {
                kTaskState->ruleMutationInProgress.store(false);
                return;
            }
            QMetaObject::invokeMethod(
                kReceiver,
                [kTaskState, updated, errorText, ruleNameText = kUpdatedRuleEntry.nameText]()
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(kTaskState->dispatchMutex);
                        pagePointer = kTaskState->owner;
                    }
                    kTaskState->ruleMutationInProgress.store(false);
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (!updated)
                    {
                        // privilegePromptHandled: When the privilege recovery prompt has been displayed, retain only the page state without showing a duplicate popup.
                        const bool kPrivilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(pagePointer, QStringLiteral("编辑防火墙规则"), errorText);
                        if (!kPrivilegePromptHandled)
                        {
                            QMessageBox::warning(pagePointer, QStringLiteral("编辑规则失败"), errorText);
                        }
                        pagePointer->setStatusText(errorText);
                        pagePointer->updateRuleActionButtons();
                        return;
                    }

                    pagePointer->setStatusText(QStringLiteral("已更新防火墙规则：%1").arg(ruleNameText));
                    pagePointer->refreshRulesAsync(true);
                },
                Qt::QueuedConnection);
        }).detach();
    }
    catch (...)
    {
        kTaskState->ruleMutationInProgress.store(false);
        updateRuleActionButtons();
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::toggleSelectedFirewallRuleEnabled()
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("切换防火墙规则状态"));
        return;
    }
    FirewallRuleEntry selectedRuleEntryValue;
    if (!selectedRuleEntry(&selectedRuleEntryValue))
    {
        return;
    }

    const std::shared_ptr<FirewallAsyncTaskState> kTaskState = acquireFirewallAsyncTaskState(this);
    if (!kTaskState)
    {
        return;
    }
    bool expectedMutation = false;
    if (!kTaskState->ruleMutationInProgress.compare_exchange_strong(expectedMutation, true))
    {
        setStatusText(QStringLiteral("防火墙规则正在刷新，请稍候。"));
        return;
    }

    // Starting and stopping also requires locating the rule in the system and submitting the policy first, just like editing paths, so this is moved to background execution.
    if (editRuleButton_ != nullptr)
    {
        editRuleButton_->setEnabled(false);
    }
    if (toggleRuleButton_ != nullptr)
    {
        toggleRuleButton_->setEnabled(false);
    }
    if (deleteRuleButton_ != nullptr)
    {
        deleteRuleButton_->setEnabled(false);
    }

    const bool kTargetEnabled = !selectedRuleEntryValue.enabled;
    try
    {
        std::thread([kTaskState,
                     ruleNameText = selectedRuleEntryValue.nameText,
                     fingerprintText = selectedRuleEntryValue.fingerprintText,
                     kTargetEnabled]()
        {
            const AsyncWorkerScope kWorkerScope(kTaskState);
            QString errorText;
            bool updated = false;
            try
            {
                updated = setFirewallRuleEnabledInSystemShared(ruleNameText, fingerprintText, kTargetEnabled, &errorText);
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            std::lock_guard<std::mutex> dispatchGuard(kTaskState->dispatchMutex);
            NetworkFirewallPage* const kReceiver = kTaskState->owner;
            if (kReceiver == nullptr)
            {
                kTaskState->ruleMutationInProgress.store(false);
                return;
            }
            QMetaObject::invokeMethod(
                kReceiver,
                [kTaskState, updated, errorText, ruleNameText, kTargetEnabled]()
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(kTaskState->dispatchMutex);
                        pagePointer = kTaskState->owner;
                    }
                    kTaskState->ruleMutationInProgress.store(false);
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (!updated)
                    {
                        // privilegePromptHandled: When the privilege recovery prompt has been displayed, retain only the page state without showing a duplicate popup.
                        const bool kPrivilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(pagePointer, QStringLiteral("切换防火墙规则状态"), errorText);
                        if (!kPrivilegePromptHandled)
                        {
                            QMessageBox::warning(pagePointer, QStringLiteral("更新规则状态失败"), errorText);
                        }
                        pagePointer->setStatusText(errorText);
                        pagePointer->updateRuleActionButtons();
                        return;
                    }

                    pagePointer->setStatusText(QStringLiteral("规则 %1：%2")
                        .arg(ruleNameText)
                        .arg(kTargetEnabled ? QStringLiteral("已启用") : QStringLiteral("已禁用")));
                    pagePointer->refreshRulesAsync(true);
                },
                Qt::QueuedConnection);
        }).detach();
    }
    catch (...)
    {
        kTaskState->ruleMutationInProgress.store(false);
        updateRuleActionButtons();
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::deleteSelectedFirewallRules()
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("删除防火墙规则"));
        return;
    }
    if (ruleTable_ == nullptr || ruleTable_->selectionModel() == nullptr)
    {
        return;
    }

    QStringList ruleNameList;
    const QModelIndexList kRowIndexList = ruleTable_->selectionModel()->selectedRows();
    for (const QModelIndex& rowIndex : kRowIndexList)
    {
        if (ruleTable_->isRowHidden(rowIndex.row()))
        {
            continue;
        }
        QTableWidgetItem* nameItem = ruleTable_->item(rowIndex.row(), kRuleColumnName);
        if (nameItem != nullptr)
        {
            ruleNameList.push_back(nameItem->text());
        }
    }
    ruleNameList.removeDuplicates();
    if (ruleNameList.isEmpty())
    {
        return;
    }

    const int kDuplicateCount = ruleNameList.size() == 1 ? ruleNameDuplicateCount(ruleNameList.front()) : 0;
    // Rule names are raw system data; only translate the confirmation sentences generated by the page to avoid altering rule evidence.
    QString warningText = ruleNameList.size() == 1
        ? ks::i18n::sourceText(QStringLiteral("确定删除规则“%1”吗？")).arg(ruleNameList.front())
        : ks::i18n::sourceText(QStringLiteral("确定删除选中的 %1 条规则吗？")).arg(ruleNameList.size());
    if (kDuplicateCount > 1)
    {
        warningText.append(ks::i18n::sourceText(
            QStringLiteral("\n注意：同名规则存在 %1 条，Windows Firewall 将按名称删除同名项。"))
            .arg(kDuplicateCount));
    }

    const QMessageBox::StandardButton kButton = QMessageBox::question(
        this,
        QStringLiteral("删除防火墙规则"),
        warningText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kButton != QMessageBox::Yes)
    {
        return;
    }

    const std::shared_ptr<FirewallAsyncTaskState> kTaskState = acquireFirewallAsyncTaskState(this);
    if (!kTaskState)
    {
        return;
    }
    bool expectedMutation = false;
    if (!kTaskState->ruleMutationInProgress.compare_exchange_strong(expectedMutation, true))
    {
        setStatusText(QStringLiteral("防火墙规则正在刷新，请稍候。"));
        return;
    }

    // Each Remove triggers a policy submission to MPSSVC; when multiple rows are selected, they are accumulated linearly. The entire loop
    // is moved to a background thread, and a single INetFwPolicy2/INetFwRules instance is created and reused for all Remove operations.
    if (editRuleButton_ != nullptr)
    {
        editRuleButton_->setEnabled(false);
    }
    if (toggleRuleButton_ != nullptr)
    {
        toggleRuleButton_->setEnabled(false);
    }
    if (deleteRuleButton_ != nullptr)
    {
        deleteRuleButton_->setEnabled(false);
    }

    try
    {
        std::thread([kTaskState, ruleNameList]()
        {
            const AsyncWorkerScope kWorkerScope(kTaskState);
            QString errorText;
            int deletedCount = 0;
            bool deleted = false;
            try
            {
                deleted = deleteFirewallRulesFromSystemShared(ruleNameList, &deletedCount, &errorText);
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            std::lock_guard<std::mutex> dispatchGuard(kTaskState->dispatchMutex);
            NetworkFirewallPage* const kReceiver = kTaskState->owner;
            if (kReceiver == nullptr)
            {
                kTaskState->ruleMutationInProgress.store(false);
                return;
            }
            QMetaObject::invokeMethod(
                kReceiver,
                [kTaskState, deleted, deletedCount, errorText]()
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(kTaskState->dispatchMutex);
                        pagePointer = kTaskState->owner;
                    }
                    kTaskState->ruleMutationInProgress.store(false);
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (!deleted)
                    {
                        // privilegePromptHandled: When the privilege recovery prompt has been displayed, retain only the page state without showing a duplicate popup.
                        const bool kPrivilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(pagePointer, QStringLiteral("删除防火墙规则"), errorText);
                        if (!kPrivilegePromptHandled)
                        {
                            QMessageBox::warning(pagePointer, QStringLiteral("删除规则失败"), errorText);
                        }
                        pagePointer->setStatusText(errorText);
                    }
                    else
                    {
                        pagePointer->setStatusText(QStringLiteral("已删除 %1 条防火墙规则。").arg(deletedCount));
                    }
                    pagePointer->refreshRulesAsync(true);
                },
                Qt::QueuedConnection);
        }).detach();
    }
    catch (...)
    {
        kTaskState->ruleMutationInProgress.store(false);
        updateRuleActionButtons();
        setStatusText(QStringLiteral("刷新失败"));
    }
}

// ensureWfpApiLoaded:
// - Input: error text output;
// - Processing: Delegate to the file-level ensureWfpApiLoadedShared; the module handle
//         is also kept at the file level so background tasks do not depend on page members.
// - Returns: true when all critical exports are available.
bool NetworkFirewallPage::ensureWfpApiLoaded(QString* errorTextOut)
{
    return ensureWfpApiLoadedShared(errorTextOut);
}

// openWfpEngine:
// - Input: Whether to enable event collection, engine handle output, and error text output;
// - Processing: Delegate to the file-level openWfpEngineShared;
// - Returns: true on success.
bool NetworkFirewallPage::openWfpEngine(
    const bool enableCollection,
    void** engineHandleOut,
    QString* errorTextOut)
{
    if (engineHandleOut == nullptr)
    {
        return false;
    }
    HANDLE engineHandle = nullptr;
    const bool kOpened = openWfpEngineShared(enableCollection, &engineHandle, errorTextOut);
    *engineHandleOut = engineHandle;
    return kOpened;
}

// closeWfpEngine:
// - Input: engine handle, whether to disable collection;
// - Processing: Delegate to the file-level closeWfpEngineShared.
// - No return value.
void NetworkFirewallPage::closeWfpEngine(void* engineHandle, const bool disableCollection)
{
    closeWfpEngineShared(static_cast<HANDLE>(engineHandle), disableCollection);
}

// enumerateHistoryWithEngine:
// - Input: open BFE engine and error text output;
// - Handling: Delegate to the file-level `enumerateHistoryWithEngineShared`; this entry point lacks a
//         cancellation flag, while background history refresh uses the file-level version with a cancellation flag.
// - Returns: the event list.
std::vector<NetworkFirewallPage::FirewallEventEntry>
NetworkFirewallPage::enumerateHistoryWithEngine(void* engineHandle, QString* errorTextOut)
{
    return enumerateHistoryWithEngineShared(static_cast<HANDLE>(engineHandle), nullptr, errorTextOut);
}

// convertWfpEventToEntry:
// - Input: FWPM_NET_EVENT pointer and engine handle;
// - Handling: Delegate to the file-level convertWfpEventToEntryShared. Hostnames are looked up only from
//         the cache, preventing the WFP callback thread from being blocked by synchronous reverse DNS lookups.
// - Returns: displayable event.
NetworkFirewallPage::FirewallEventEntry NetworkFirewallPage::convertWfpEventToEntry(
    const void* wfpEventPointer,
    void* engineHandle)
{
    return convertWfpEventToEntryShared(wfpEventPointer, static_cast<HANDLE>(engineHandle));
}

void NetworkFirewallPage::enqueueLiveEvent(const void* wfpEventPointer)
{
    if (!liveRunning_.load() || wfpEventPointer == nullptr)
    {
        return;
    }
    FirewallEventEntry entry = convertWfpEventToEntry(wfpEventPointer, liveEngineHandle_);
    std::lock_guard<std::mutex> guard(liveEventMutex_);
    while (liveEventQueue_.size() >= kMaximumQueuedLiveEvents)
    {
        liveEventQueue_.pop_front();
    }
    liveEventQueue_.push_back(std::move(entry));
}

void __stdcall NetworkFirewallPage::liveEventCallback(void* context, const void* eventPointer)
{
    NetworkFirewallPage* pagePointer = static_cast<NetworkFirewallPage*>(context);
    if (pagePointer != nullptr)
    {
        pagePointer->enqueueLiveEvent(eventPointer);
    }
}
