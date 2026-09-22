#include "NetworkAuditPage.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// NetworkAuditPage.cpp
// Purpose:
// 1) Provides the UI and snapshot refresh logic for the network audit page.
// 2) Merge TCP/UDP Cross-View connection refresh, PID filtering, copy, and TCP termination actions;
// 3) AFD/WFP/NDIS/NSI maintain a read-only audit boundary.
// ============================================================

#include "../Theme.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../../../shared/platform/file/FileHandleTools.h"
#include "../../../shared/platform/network/Network.h"
#include "../../../shared/platform/network/NetworkConnectionTools.h"
#include "../../../shared/platform/process/Process.h"
#include "../../../shared/platform/log/Log.h"
#include "../online_scan/SandboxUploadActions.h"

#include <QDateTime>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QJsonParseError>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPixmap>
#include <QProcess>
#include <QPushButton>
#include <QSizePolicy>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThread>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <objbase.h>
#include <Rpc.h>
#include <Shellapi.h>
#include <fwpmu.h>

#pragma comment(lib, "Ws2_32.lib")

// NetworkAuditAsyncState places the return target of the detached worker in shared mutex state.
// The destructor clears the owner first; the worker can only submit queued calls under the same lock
// protection, and the GUI callback re-verifies the owner and releases the lock before accessing page members.
struct NetworkAuditAsyncState
{
    std::mutex mutex;
    NetworkAuditPage* owner = nullptr;
};

namespace
{
    // kAuditProcessIdColumn / kAuditProcessNameColumn：
    // - The TCP, UDP, and Cross-View tables all place the PID in column 0 and the process name in column 1.
    // - Locate the cell by these two column indices when asynchronously filling icons.
    constexpr int kAuditProcessIdColumn = 0;
    constexpr int kAuditProcessNameColumn = 1;

    // auditProcessPlaceholderIcon:
    // - Returns the unified process placeholder icon for the audit page; used when the icon fails to load or parse.
    // - Parameters: None;
    // - Returns: a shared QIcon reference, usable only on the UI thread.
    const QIcon& auditProcessPlaceholderIcon()
    {
        static const QIcon kPlaceholderIcon(QStringLiteral(":/Icon/process_main.svg"));
        return kPlaceholderIcon;
    }

    // extractProcessIconImageForPid:
    // - Parse the executable path by PID in a thread pool worker thread and query the small icon via Shell;
    // - SHGetFileInfoW depends on COM; worker threads must explicitly pair CoInitializeEx and CoUninitialize.
    // - Input parameter processId: Target process PID.
    // - Return: QImage safe for cross-thread transfer; returns an empty QImage on failure (caller falls back to placeholder icon).
    QImage extractProcessIconImageForPid(const quint32 processId)
    {
        const std::string kProcessPath = ks::process::queryProcessPathByPid(processId);
        if (kProcessPath.empty())
        {
            return QImage();
        }

        const HRESULT kComInitializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool kComInitializedHere = SUCCEEDED(kComInitializeResult);

        const QString kProcessPathText = QString::fromUtf8(kProcessPath.c_str());
        SHFILEINFOW shellFileInfo{};
        const DWORD_PTR kShellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(kProcessPathText.utf16()),
            0,
            &shellFileInfo,
            sizeof(shellFileInfo),
            SHGFI_ICON | SHGFI_SMALLICON);

        QImage processIconImage;
        if (kShellQueryResult != 0 && shellFileInfo.hIcon != nullptr)
        {
            // QImage::fromHICON copies pixel data; the HICON allocated by Shell must be released after conversion.
            processIconImage = QImage::fromHICON(shellFileInfo.hIcon);
            ::DestroyIcon(shellFileInfo.hIcon);
        }

        if (kComInitializedHere)
        {
            ::CoUninitialize();
        }
        return processIconImage;
    }

    // applyResolvedIconToAuditTableRows:
    // - Apply asynchronously resolved process icons to all rows in the specified table matching the given PID;
    // - Input tableWidget: one of the TCP / UDP / Cross-View tables, may be null;
    // - Input parameter processId: The PID for the current resolved operation;
    // - Parameter resolvedIcon: resolved icon or placeholder icon.
    // - Return: None. This function must be called only on the UI thread.
    void applyResolvedIconToAuditTableRows(
        QTableWidget* const tableWidget,
        const quint32 processId,
        const QIcon& resolvedIcon)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        const QString kProcessIdText = QString::number(processId);
        for (int rowIndex = 0; rowIndex < tableWidget->rowCount(); ++rowIndex)
        {
            const QTableWidgetItem* const kProcessIdItem =
                tableWidget->item(rowIndex, kAuditProcessIdColumn);
            if (kProcessIdItem == nullptr || kProcessIdItem->text() != kProcessIdText)
            {
                continue;
            }

            QTableWidgetItem* const kProcessNameItem =
                tableWidget->item(rowIndex, kAuditProcessNameColumn);
            if (kProcessNameItem != nullptr)
            {
                kProcessNameItem->setIcon(resolvedIcon);
            }
        }
    }

    // createReadOnlyCell:
    // - Create a non-editable table cell.
    // - Input cellText: text to be displayed.
    // - Returns a pointer to an item that can be directly written into the table.
    QTableWidgetItem* createReadOnlyCell(const QString& cellText)
    {
        QTableWidgetItem* item = new QTableWidgetItem(cellText);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // tableMenuStyle:
    // - Provide an opaque background for the newly added right-click menu on the Network Audit page.
    // - Inputs: None;
    // - Return: QMenu stylesheet to prevent black text on a black background in light mode.
    QString tableMenuStyle()
    {
        // Network audit page menu:
        // - Inputs: None;
        // - Processing: Uniformly reuse the global opaque menu style to prevent palette roles from being incorrectly inherited against the Dock's transparent background.
        // - Returns: Style text directly applicable to QMenu.
        return ksword_theme::contextMenuStyle();
    }

    // copyCurrentTableRow:
    // - Copy the current QTableWidget row as TSV;
    // - Input table: Target table.
    // - Return: None; returns immediately if the clipboard is unavailable or no selection exists.
    void copyCurrentTableRow(QTableWidget* table)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kRowIndex = table->currentRow();
        if (kRowIndex < 0 || kRowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join('\t'));
    }

    // installCopyMenu:
    // - Install a 'Copy Current Row' menu for the read-only audit table.
    // - processIdColumn is the explicitly specified PID column; -1 indicates the table has no PID column.
    // - Return: None. The menu is read-only and does not alter the network stack state.
    void installCopyMenu(QTableWidget* table, const int processIdColumn = -1)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table, processIdColumn](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
                table->selectRow(kClickedIndex.row());
            }

            QMenu menu(table);
            menu.setStyleSheet(tableMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            quint32 processId = 0;
            if (processIdColumn >= 0 && processIdColumn < table->columnCount() &&
                table->currentRow() >= 0 && table->currentRow() < table->rowCount())
            {
                const QTableWidgetItem* processIdItem = table->item(table->currentRow(), processIdColumn);
                bool parseOk = false;
                const uint kParsedProcessId = processIdItem != nullptr
                    ? processIdItem->text().toUInt(&parseOk, 10)
                    : 0U;
                if (parseOk && kParsedProcessId != 0U)
                {
                    processId = static_cast<quint32>(kParsedProcessId);
                }
            }
            QAction* openProcessDetailAction = nullptr;
            if (processIdColumn >= 0)
            {
                openProcessDetailAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessDetailAction->setEnabled(processId != 0U);
            }

            const QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(localPosition));
            if (selectedAction == copyRowAction)
            {
                copyCurrentTableRow(table);
            }
            else if (selectedAction == openProcessDetailAction)
            {
                ks::ui::openProcessDetailByPid(processId);
            }
        });
    }

    // joinCompactLines:
    // - Merge multiple short lines into a single summary line.
    // - Suitable for cross-view and summary pages.
    QString joinCompactLines(const QStringList& lines)
    {
        QStringList filteredLines;
        filteredLines.reserve(lines.size());
        for (const QString& line : lines)
        {
            if (!line.trimmed().isEmpty())
            {
                filteredLines.push_back(line.trimmed());
            }
        }
        return filteredLines.join(QStringLiteral(" | "));
    }

    // ioMessageToText:
    // - Converts ArkDriverClient UTF-8 messages to Qt text.
    // - Input messageText: IoResult::message;
    // - Returns: A displayable QString; empty messages are normalized to "No additional information".
    QString ioMessageToText(const std::string& messageText)
    {
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        const QString kRawText = QString::fromUtf8(messageText.c_str()).trimmed();
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该网络审计入口");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            // Old driver compatibility:
            // - Input: unsupported/not supported text returned by ArkDriverClient.
            // - Processing: Collapse into a unified human-readable status for the Network Audit page.
            // - Returns: Does not expose underlying IOCTL names, allowing users to directly determine if a driver update is needed.
            return QStringLiteral("当前驱动不支持网络审计，请更新为匹配版本");
        }
        if (kRawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("profile"), Qt::CaseInsensitive))
        {
            // Dynamic offset diagnosis:
            // - Input: description related to capability/DynData/profile returned by the driver;
            // - Processing: Convert to user-understandable capability offset gaps;
            // - Return: Points to the kernel DynData page for further investigation.
            return QStringLiteral("当前驱动缺少网络审计所需能力，请更新驱动或相关数据文件");
        }
        if (kRawText.contains(QStringLiteral("access denied"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("privilege"), Qt::CaseInsensitive))
        {
            return QStringLiteral("权限不足，无法完成网络审计查询");
        }
        if (kRawText.contains(QStringLiteral("invalid parameter"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("R0/R3 网络审计协议参数不兼容，请同步 shared 协议与驱动版本");
        }
        if (kRawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("entrySize"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，已保留 R3 审计结果");
        }
        if (kRawText.contains(QStringLiteral("timeout"), Qt::CaseInsensitive))
        {
            return QStringLiteral("R0 网络审计查询超时，已保留现有 R3 审计结果");
        }
        if (kRawText.contains(QStringLiteral("invalid response"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("invalid endpoint row"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("invalid WFP row"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("invalid NDIS row"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("returned rows exceed"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回的网络审计响应未通过协议校验，已丢弃 R0 数据");
        }
        if (kRawText.contains(QStringLiteral("protocolStatus="), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动已返回并通过校验的结构化网络审计数据");
        }
        if (kRawText.startsWith(QStringLiteral("version="), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动已返回结构化网络审计数据");
        }
        return kRawText;
    }

    // r0AuditStatusText:
    // - Convert R0 wrapper status (ok/partial/unsupported/unavailable) to UI text.
    // - Input result: any ArkDriverClient audit result containing io/unsupported fields;
    // - Returns: ok / partial / unsupported / unavailable as per acceptance requirements.
    template <typename TResult>
    QString r0AuditStatusText(const TResult& result)
    {
        if (!result.io.ok)
        {
            return result.unsupported
                ? QStringLiteral("unsupported")
                : QStringLiteral("unavailable");
        }

        // DeviceIoControl success only indicates a structured response header was retrieved; only when APPLIED and total == returned is the snapshot complete.
        // ArkDriverClient strictly filters partial; other OPERATION_FAILED cases do not retain detail rows.
        if (result.partial ||
            result.truncated ||
            result.totalCount > result.returnedCount)
        {
            return QStringLiteral("partial");
        }
        if (result.status != KSWORD_ARK_NETWORK_STATUS_APPLIED)
        {
            return QStringLiteral("unavailable");
        }
        return result.sourceFlags != KSWORD_ARK_NETWORK_AUDIT_SOURCE_NONE
            ? QStringLiteral("ok")
            : QStringLiteral("unavailable");
    }

    // r0AuditTruncatedText:
    // - Determine if the R0 result was truncated based on wrapper completeness and the total/returned counts.
    // - Input result: Any VariableAuditResultBase derived result;
    // - Returns: true/false text for direct display in the summary table.
    template <typename TResult>
    QString r0AuditTruncatedText(const TResult& result)
    {
        return result.truncated || result.totalCount > result.returnedCount
            ? QStringLiteral("true")
            : QStringLiteral("false");
    }

    // r0Hex32:
    // - Input value: 32-bit flags/status/fieldMask in the R0 protocol;
    // - Processing: Uniformly pad with zeros for hexadecimal display.
    // - Returns: Text suitable for copying to the table details column.
    QString r0Hex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 8, 16, QChar('0'))
            .toUpper();
    }

    // r0Hex64:
    // - Input: value is an object address, LUID, or image base from the R0 protocol.
    // - Processing: Uniformly pad with zeros for hexadecimal display.
    // - Returns: Text suitable for copying to the table details column.
    QString r0Hex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    // fixedNetworkWideText:
    // - Input buffer/maxChars: Fixed-length wchar_t string from shared/driver.
    // - Processing: Stop at NUL terminator to avoid displaying padding in the UI.
    // - Returns: Readable text, using fallback for empty strings.
    QString fixedNetworkWideText(const wchar_t* buffer, const std::size_t maxChars, const QString& fallback = QStringLiteral("<空>"))
    {
        if (buffer == nullptr || maxChars == 0U)
        {
            return fallback;
        }

        std::size_t length = 0U;
        while (length < maxChars && buffer[length] != L'\0')
        {
            ++length;
        }
        if (length == 0U)
        {
            return fallback;
        }
        return QString::fromWCharArray(buffer, static_cast<int>(length));
    }

    // r0AddressText:
    // - Input family/address: the original address family and 16-byte address from the R0 endpoint row;
    // - Processing: Display IPv4 in dotted-decimal notation and IPv6 in 8 groups of hexadecimal.
    // - Returns: Readable IP address; unknown address family retains diagnostic info.
    QString r0AddressText(const unsigned long family, const unsigned char address[16])
    {
        if (address == nullptr)
        {
            return QStringLiteral("<无地址>");
        }
        if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4)
        {
            return QStringLiteral("%1.%2.%3.%4")
                .arg(static_cast<unsigned int>(address[0]))
                .arg(static_cast<unsigned int>(address[1]))
                .arg(static_cast<unsigned int>(address[2]))
                .arg(static_cast<unsigned int>(address[3]));
        }
        if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6)
        {
            QStringList groups;
            groups.reserve(8);
            for (int index = 0; index < 16; index += 2)
            {
                const unsigned int kGroupValue =
                    (static_cast<unsigned int>(address[index]) << 8U) |
                    static_cast<unsigned int>(address[index + 1]);
                groups.push_back(QStringLiteral("%1").arg(kGroupValue, 4, 16, QChar('0')));
            }
            return groups.join(':').toUpper();
        }
        return QStringLiteral("<AF=%1>").arg(family);
    }

    // r0EndpointText:
    // - Input family/address/port: R0 endpoint address and port;
    // - Processing: Merge address and port into a single endpoint text.
    // - Return: IPv6 addresses are automatically wrapped in brackets to distinguish them from ports.
    QString r0EndpointText(const unsigned long family, const unsigned char address[16], const unsigned short port)
    {
        const QString kAddressText = r0AddressText(family, address);
        if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6)
        {
            return QStringLiteral("[%1]:%2").arg(kAddressText).arg(port);
        }
        return QStringLiteral("%1:%2").arg(kAddressText).arg(port);
    }

    // r0TcpStateText:
    // - Input state: KSWORD_ARK_NETWORK_TCP_STATE_*;
    // - Processing: Convert common TCP states to English enum names; retain numeric values for unknown states.
    // - Returns: Text for the 'Status' column in the TCP details table.
    QString r0TcpStateText(const unsigned long state)
    {
        switch (state)
        {
        case KSWORD_ARK_NETWORK_TCP_STATE_CLOSED: return QStringLiteral("CLOSED");
        case KSWORD_ARK_NETWORK_TCP_STATE_LISTEN: return QStringLiteral("LISTEN");
        case KSWORD_ARK_NETWORK_TCP_STATE_SYN_SENT: return QStringLiteral("SYN_SENT");
        case KSWORD_ARK_NETWORK_TCP_STATE_SYN_RCVD: return QStringLiteral("SYN_RCVD");
        case KSWORD_ARK_NETWORK_TCP_STATE_ESTABLISHED: return QStringLiteral("ESTABLISHED");
        case KSWORD_ARK_NETWORK_TCP_STATE_FIN_WAIT_1: return QStringLiteral("FIN_WAIT_1");
        case KSWORD_ARK_NETWORK_TCP_STATE_FIN_WAIT_2: return QStringLiteral("FIN_WAIT_2");
        case KSWORD_ARK_NETWORK_TCP_STATE_CLOSE_WAIT: return QStringLiteral("CLOSE_WAIT");
        case KSWORD_ARK_NETWORK_TCP_STATE_CLOSING: return QStringLiteral("CLOSING");
        case KSWORD_ARK_NETWORK_TCP_STATE_LAST_ACK: return QStringLiteral("LAST_ACK");
        case KSWORD_ARK_NETWORK_TCP_STATE_TIME_WAIT: return QStringLiteral("TIME_WAIT");
        case KSWORD_ARK_NETWORK_TCP_STATE_DELETE_TCB: return QStringLiteral("DELETE_TCB");
        default: return QStringLiteral("STATE(%1)").arg(state);
        }
    }

    // r0GuidText:
    // - Input bytes: 16-byte GUID from the R0 WFP entry;
    // - Processing: Copy to GUID and reuse Qt/Windows formatted path.
    // - Returns: Standard GUID text.
    QString r0GuidText(const unsigned char bytes[16])
    {
        if (bytes == nullptr)
        {
            return QStringLiteral("<无GUID>");
        }
        GUID guid{};
        std::memcpy(&guid, bytes, sizeof(guid));
        return QStringLiteral("{%1-%2-%3-%4%5-%6%7%8%9%10%11}")
            .arg(guid.Data1, 8, 16, QChar('0'))
            .arg(guid.Data2, 4, 16, QChar('0'))
            .arg(guid.Data3, 4, 16, QChar('0'))
            .arg(guid.Data4[0], 2, 16, QChar('0'))
            .arg(guid.Data4[1], 2, 16, QChar('0'))
            .arg(guid.Data4[2], 2, 16, QChar('0'))
            .arg(guid.Data4[3], 2, 16, QChar('0'))
            .arg(guid.Data4[4], 2, 16, QChar('0'))
            .arg(guid.Data4[5], 2, 16, QChar('0'))
            .arg(guid.Data4[6], 2, 16, QChar('0'))
            .arg(guid.Data4[7], 2, 16, QChar('0'))
            .toUpper();
    }

    // r0WfpObjectKindText:
    // - Input kind: R0 WFP objectKind;
    // - Returns: Readable categories such as Provider, Sublayer, Filter, or Callout.
    QString r0WfpObjectKindText(const unsigned long kind)
    {
        switch (kind)
        {
        case KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER: return QStringLiteral("Provider");
        case KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER: return QStringLiteral("Sublayer");
        case KSWORD_ARK_NETWORK_WFP_OBJECT_FILTER: return QStringLiteral("Filter");
        case KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT: return QStringLiteral("Callout");
        default: return QStringLiteral("WFP(%1)").arg(kind);
        }
    }

    // r0NdisObjectKindText:
    // - Input: kind - R0 NDIS objectKind;
    // - Return: explicitly marks unknown objects as Unknown/Unproven; does not disguise public device-stack evidence as LWF.
    QString r0NdisObjectKindText(const unsigned long kind)
    {
        switch (kind)
        {
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_UNKNOWN:
            return QStringLiteral("未知/未证明");
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT: return QStringLiteral("Miniport");
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_FILTER: return QStringLiteral("Filter");
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_PROTOCOL: return QStringLiteral("Protocol");
        case KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING: return QStringLiteral("Binding");
        default: return QStringLiteral("NDIS(%1)").arg(kind);
        }
    }

    // WfpApi: Stores dynamically resolved WFP read-only enumeration entry points.
    struct WfpApi
    {
        using FwpmEngineOpen0Fn = DWORD(WINAPI*)(const wchar_t*, UINT32, SEC_WINNT_AUTH_IDENTITY_W*, const FWPM_SESSION0*, HANDLE*);
        using FwpmEngineClose0Fn = DWORD(WINAPI*)(HANDLE);
        using FwpmFreeMemory0Fn = void(WINAPI*)(void**);
        using FwpmProviderCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_PROVIDER_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmProviderEnum0Fn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, FWPM_PROVIDER0***, UINT32*);
        using FwpmProviderDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);
        using FwpmSubLayerCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_SUBLAYER_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmSubLayerEnum0Fn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, FWPM_SUBLAYER0***, UINT32*);
        using FwpmSubLayerDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);
        using FwpmCalloutCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_CALLOUT_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmCalloutEnum0Fn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, FWPM_CALLOUT0***, UINT32*);
        using FwpmCalloutDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);
        using FwpmFilterCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_FILTER_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmFilterEnum0Fn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, FWPM_FILTER0***, UINT32*);
        using FwpmFilterDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);

        HMODULE moduleHandle = nullptr;
        FwpmEngineOpen0Fn engineOpen = nullptr;
        FwpmEngineClose0Fn engineClose = nullptr;
        FwpmFreeMemory0Fn freeMemory = nullptr;
        FwpmProviderCreateEnumHandle0Fn providerCreateEnumHandle = nullptr;
        FwpmProviderEnum0Fn providerEnum = nullptr;
        FwpmProviderDestroyEnumHandle0Fn providerDestroyEnumHandle = nullptr;
        FwpmSubLayerCreateEnumHandle0Fn subLayerCreateEnumHandle = nullptr;
        FwpmSubLayerEnum0Fn subLayerEnum = nullptr;
        FwpmSubLayerDestroyEnumHandle0Fn subLayerDestroyEnumHandle = nullptr;
        FwpmCalloutCreateEnumHandle0Fn calloutCreateEnumHandle = nullptr;
        FwpmCalloutEnum0Fn calloutEnum = nullptr;
        FwpmCalloutDestroyEnumHandle0Fn calloutDestroyEnumHandle = nullptr;
        FwpmFilterCreateEnumHandle0Fn filterCreateEnumHandle = nullptr;
        FwpmFilterEnum0Fn filterEnum = nullptr;
        FwpmFilterDestroyEnumHandle0Fn filterDestroyEnumHandle = nullptr;
    };

    WfpApi& wfpApi()
    {
        static WfpApi api;
        return api;
    }

    // loadWfpApi:
    // - Read-only load of fwpuclnt.dll and parsing of WFP enumeration entry points.
    // - errorTextOut records the reason for failure.
    // - Returns true to indicate enumeration can continue.
    bool loadWfpApi(QString* errorTextOut)
    {
        WfpApi& api = wfpApi();
        if (api.moduleHandle == nullptr)
        {
            api.moduleHandle = ::LoadLibraryW(L"fwpuclnt.dll");
        }
        if (api.moduleHandle == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法加载 fwpuclnt.dll。");
            }
            return false;
        }

        auto procAddress = [moduleHandle = api.moduleHandle](const char* nameText) -> FARPROC
        {
            return ::GetProcAddress(moduleHandle, nameText);
        };

        api.engineOpen = reinterpret_cast<WfpApi::FwpmEngineOpen0Fn>(procAddress("FwpmEngineOpen0"));
        api.engineClose = reinterpret_cast<WfpApi::FwpmEngineClose0Fn>(procAddress("FwpmEngineClose0"));
        api.freeMemory = reinterpret_cast<WfpApi::FwpmFreeMemory0Fn>(procAddress("FwpmFreeMemory0"));
        api.providerCreateEnumHandle = reinterpret_cast<WfpApi::FwpmProviderCreateEnumHandle0Fn>(procAddress("FwpmProviderCreateEnumHandle0"));
        api.providerEnum = reinterpret_cast<WfpApi::FwpmProviderEnum0Fn>(procAddress("FwpmProviderEnum0"));
        api.providerDestroyEnumHandle = reinterpret_cast<WfpApi::FwpmProviderDestroyEnumHandle0Fn>(procAddress("FwpmProviderDestroyEnumHandle0"));
        api.subLayerCreateEnumHandle = reinterpret_cast<WfpApi::FwpmSubLayerCreateEnumHandle0Fn>(procAddress("FwpmSubLayerCreateEnumHandle0"));
        api.subLayerEnum = reinterpret_cast<WfpApi::FwpmSubLayerEnum0Fn>(procAddress("FwpmSubLayerEnum0"));
        api.subLayerDestroyEnumHandle = reinterpret_cast<WfpApi::FwpmSubLayerDestroyEnumHandle0Fn>(procAddress("FwpmSubLayerDestroyEnumHandle0"));
        api.calloutCreateEnumHandle = reinterpret_cast<WfpApi::FwpmCalloutCreateEnumHandle0Fn>(procAddress("FwpmCalloutCreateEnumHandle0"));
        api.calloutEnum = reinterpret_cast<WfpApi::FwpmCalloutEnum0Fn>(procAddress("FwpmCalloutEnum0"));
        api.calloutDestroyEnumHandle = reinterpret_cast<WfpApi::FwpmCalloutDestroyEnumHandle0Fn>(procAddress("FwpmCalloutDestroyEnumHandle0"));
        api.filterCreateEnumHandle = reinterpret_cast<WfpApi::FwpmFilterCreateEnumHandle0Fn>(procAddress("FwpmFilterCreateEnumHandle0"));
        api.filterEnum = reinterpret_cast<WfpApi::FwpmFilterEnum0Fn>(procAddress("FwpmFilterEnum0"));
        api.filterDestroyEnumHandle = reinterpret_cast<WfpApi::FwpmFilterDestroyEnumHandle0Fn>(procAddress("FwpmFilterDestroyEnumHandle0"));

        if (api.engineOpen == nullptr || api.engineClose == nullptr || api.freeMemory == nullptr ||
            api.providerCreateEnumHandle == nullptr || api.providerEnum == nullptr || api.providerDestroyEnumHandle == nullptr ||
            api.subLayerCreateEnumHandle == nullptr || api.subLayerEnum == nullptr || api.subLayerDestroyEnumHandle == nullptr ||
            api.calloutCreateEnumHandle == nullptr || api.calloutEnum == nullptr || api.calloutDestroyEnumHandle == nullptr ||
            api.filterCreateEnumHandle == nullptr || api.filterEnum == nullptr || api.filterDestroyEnumHandle == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("fwpuclnt.dll 缺少必要导出。");
            }
            return false;
        }

        return true;
    }

    // openWfpEngine:
    // - Open a read-only WFP engine session;
    // - On failure, return false and write the error text.
    bool openWfpEngine(HANDLE& engineHandleOut, QString* errorTextOut)
    {
        engineHandleOut = nullptr;
        if (!loadWfpApi(errorTextOut))
        {
            return false;
        }

        FWPM_SESSION0 session{};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = const_cast<wchar_t*>(L"KswordNetworkAudit");
        session.displayData.description = const_cast<wchar_t*>(L"Ksword network readonly audit session");

        const DWORD kStatus = wfpApi().engineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &engineHandleOut);
        if (kStatus != ERROR_SUCCESS)
        {
            engineHandleOut = nullptr;
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("FwpmEngineOpen0 失败：%1").arg(kStatus);
            }
            return false;
        }

        return true;
    }

    QString displayDataText(const FWPM_DISPLAY_DATA0* displayData)
    {
        if (displayData == nullptr)
        {
            return QString();
        }
        QStringList list;
        if (displayData->name != nullptr)
        {
            list.push_back(QString::fromWCharArray(displayData->name));
        }
        if (displayData->description != nullptr)
        {
            list.push_back(QString::fromWCharArray(displayData->description));
        }
        return joinCompactLines(list);
    }

    QString wfpFlagsText(const std::uint64_t flags)
    {
        return QStringLiteral("0x%1").arg(QString::number(flags, 16));
    }

    // normalizeJsonArray:
    // - normalize PowerShell ConvertTo-Json's 'single object/array' output into a unified array.
    // - The returned array can be iterated directly.
    QJsonArray normalizeJsonArray(const QJsonValue& value)
    {
        if (value.isArray())
        {
            return value.toArray();
        }
        if (value.isObject())
        {
            QJsonArray array;
            array.push_back(value.toObject());
            return array;
        }
        return {};
    }
}

NetworkAuditPage::NetworkAuditPage(QWidget* parent)
    : QWidget(parent),
      asyncState_(std::make_shared<NetworkAuditAsyncState>())
{
    asyncState_->owner = this;
    initializeUi();
    crossAutoRefreshTimer_ = new QTimer(this);
    crossAutoRefreshTimer_->setInterval(2200);
    initializeConnections();
}

NetworkAuditPage::~NetworkAuditPage()
{
    if (asyncState_)
    {
        std::lock_guard<std::mutex> lock(asyncState_->mutex);
        asyncState_->owner = nullptr;
    }
}

void NetworkAuditPage::requestInitialRefresh()
{
    bool expected = false;
    if (initialRefreshRequested_.compare_exchange_strong(expected, true))
    {
        refreshAllSnapshotsAsync(false);
    }
}

void NetworkAuditPage::focusProcessIds(const QSet<quint32>& processIds)
{
    processFilterSet_ = processIds;
    activateCrossView();
    if (crossFilterLabel_ != nullptr)
    {
        QStringList processIdTextList;
        processIdTextList.reserve(processFilterSet_.size());
        for (const quint32 kProcessId : processFilterSet_)
        {
            processIdTextList.push_back(QString::number(kProcessId));
        }
        processIdTextList.sort();
        crossFilterLabel_->setText(
            processFilterSet_.isEmpty()
                ? QStringLiteral("PID 筛选：无")
                : QStringLiteral("PID 筛选：%1 个进程")
                    .arg(processFilterSet_.size()));
        crossFilterLabel_->setToolTip(
            processFilterSet_.isEmpty()
                ? QString()
                : QStringLiteral("PID：%1")
                    .arg(processIdTextList.join(',')));
    }
    updateCrossViewActionState();
    refreshAllSnapshotsAsync(true);
}

void NetworkAuditPage::activateCrossView()
{
    if (sectionTabWidget_ != nullptr && crossViewPage_ != nullptr)
    {
        sectionTabWidget_->setCurrentWidget(crossViewPage_);
    }
}

void NetworkAuditPage::setTrackProcessHandler(ProcessActionHandler handler)
{
    trackProcessHandler_ = std::move(handler);
}

void NetworkAuditPage::setOpenProcessDetailHandler(ProcessActionHandler handler)
{
    openProcessDetailHandler_ = std::move(handler);
}

void NetworkAuditPage::setUdpEndpointBlockRuleHandler(UdpEndpointBlockRuleHandler handler)
{
    udpEndpointBlockRuleHandler_ = std::move(handler);
}

void NetworkAuditPage::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    headerLayout_ = new QHBoxLayout();
    headerLayout_->setContentsMargins(0, 0, 0, 0);
    headerLayout_->setSpacing(6);

    QLabel* titleLabel = new QLabel(QStringLiteral("网络只读审计"), this);
    titleLabel->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;color:%1;").arg(ksword_theme::textPrimaryHex()));
    headerLayout_->addWidget(titleLabel);

    statusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setMinimumWidth(0);
    statusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    headerLayout_->addWidget(statusLabel_, 1);

    refreshButton_ = new QPushButton(QStringLiteral("刷新"), this);
    refreshButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    headerLayout_->addWidget(refreshButton_);

    rootLayout_->addLayout(headerLayout_);

    sectionTabWidget_ = new QTabWidget(this);
    sectionTabWidget_->setTabPosition(QTabWidget::North);
    rootLayout_->addWidget(sectionTabWidget_, 1);

    // TCP/UDP cross-view。
    crossViewPage_ = new QWidget(this);
    QVBoxLayout* crossLayout = new QVBoxLayout(crossViewPage_);
    crossLayout->setContentsMargins(4, 4, 4, 4);
    crossLayout->setSpacing(6);

    // Connection management actions have been merged into Cross-View and no longer occupy a top-level Tab independently.
    QHBoxLayout* crossSearchLayout = new QHBoxLayout();
    crossSearchLayout->setContentsMargins(0, 0, 0, 0);
    crossSearchLayout->setSpacing(6);
    crossSearchEdit_ = new QLineEdit(crossViewPage_);
    crossSearchEdit_->setClearButtonEnabled(true);
    crossSearchEdit_->setPlaceholderText(QStringLiteral("搜索 PID / 进程 / 端点 / 状态 / 来源 / 明细 / 摘要"));
    crossSearchEdit_->setMinimumWidth(220);
    crossSearchLayout->addWidget(crossSearchEdit_, 1);
    crossLayout->addLayout(crossSearchLayout);

    crossControlLayout_ = new QHBoxLayout();
    crossControlLayout_->setContentsMargins(0, 0, 0, 0);
    crossControlLayout_->setSpacing(6);

    crossAutoRefreshButton_ = new QPushButton(QStringLiteral("自动刷新"), crossViewPage_);
    crossAutoRefreshButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    crossAutoRefreshButton_->setToolTip(QStringLiteral("每 2.2 秒自动刷新 TCP/UDP Cross-View"));
    crossAutoRefreshButton_->setCheckable(true);
    crossAutoRefreshButton_->setChecked(true);
    crossControlLayout_->addWidget(crossAutoRefreshButton_);

    crossTerminateButton_ = new QPushButton(QStringLiteral("终止 TCP"), crossViewPage_);
    crossTerminateButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_terminate.svg")));
    crossTerminateButton_->setToolTip(QStringLiteral("终止选中的 R3 IPv4 TCP 活动连接"));
    crossTerminateButton_->setEnabled(false);
    crossControlLayout_->addWidget(crossTerminateButton_);

    clearProcessFilterButton_ = new QPushButton(QStringLiteral("清除 PID 筛选"), crossViewPage_);
    clearProcessFilterButton_->setIcon(QIcon(QStringLiteral(":/Icon/log_clear.svg")));
    clearProcessFilterButton_->setToolTip(QStringLiteral("显示全部进程的 TCP/UDP 连接"));
    clearProcessFilterButton_->setEnabled(false);
    crossControlLayout_->addWidget(clearProcessFilterButton_);

    crossFilterLabel_ = new QLabel(QStringLiteral("PID 筛选：无"), crossViewPage_);
    crossFilterLabel_->setMinimumWidth(0);
    crossFilterLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    crossControlLayout_->addWidget(crossFilterLabel_, 1);
    crossLayout->addLayout(crossControlLayout_);

    crossViewSplitter_ = new QSplitter(Qt::Vertical, crossViewPage_);
    crossViewTopSplitter_ = new QSplitter(Qt::Horizontal, crossViewSplitter_);

    tcpTable_ = new ks::ui::VisibleTableWidget(crossViewTopSplitter_);
    tcpTable_->setColumnCount(6);
    tcpTable_->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("远端端点"),
        QStringLiteral("状态"),
        QStringLiteral("来源/明细")
    });
    tcpTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tcpTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tcpTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    tcpTable_->verticalHeader()->setVisible(false);
    tcpTable_->horizontalHeader()->setStretchLastSection(true);
    tcpTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    tcpTable_->setContextMenuPolicy(Qt::CustomContextMenu);

    udpTable_ = new ks::ui::VisibleTableWidget(crossViewTopSplitter_);
    udpTable_->setColumnCount(5);
    udpTable_->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("来源"),
        QStringLiteral("明细")
    });
    udpTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    udpTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    udpTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    udpTable_->verticalHeader()->setVisible(false);
    udpTable_->horizontalHeader()->setStretchLastSection(true);
    udpTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    udpTable_->setContextMenuPolicy(Qt::CustomContextMenu);

    crossSummaryTable_ = new ks::ui::VisibleTableWidget(crossViewSplitter_);
    crossSummaryTable_->setColumnCount(5);
    crossSummaryTable_->setHorizontalHeaderLabels({ QStringLiteral("PID"), QStringLiteral("进程"), QStringLiteral("TCP"), QStringLiteral("UDP"), QStringLiteral("摘要") });
    crossSummaryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    crossSummaryTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    crossSummaryTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    crossSummaryTable_->verticalHeader()->setVisible(false);
    crossSummaryTable_->horizontalHeader()->setStretchLastSection(true);
    crossSummaryTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    installCopyMenu(crossSummaryTable_, 0);

    crossViewSplitter_->addWidget(crossViewTopSplitter_);
    crossViewSplitter_->addWidget(crossSummaryTable_);
    crossViewSplitter_->setStretchFactor(0, 3);
    crossViewSplitter_->setStretchFactor(1, 2);
    crossLayout->addWidget(crossViewSplitter_, 1);
    sectionTabWidget_->addTab(crossViewPage_, QStringLiteral("TCP/UDP Cross-View"));

    // AFD。
    afdPage_ = new QWidget(this);
    QVBoxLayout* afdLayout = new QVBoxLayout(afdPage_);
    afdLayout->setContentsMargins(4, 4, 4, 4);
    afdLayout->setSpacing(6);
    afdTable_ = new ks::ui::VisibleTableWidget(afdPage_);
    afdTable_->setColumnCount(8);
    afdTable_->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("句柄"),
        QStringLiteral("类型"),
        QStringLiteral("对象名"),
        QStringLiteral("来源"),
        QStringLiteral("交叉视图"),
        QStringLiteral("详情")
    });
    afdTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    afdTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    afdTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    afdTable_->verticalHeader()->setVisible(false);
    afdTable_->horizontalHeader()->setStretchLastSection(true);
    afdTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    installCopyMenu(afdTable_, 0);
    afdLayout->addWidget(afdTable_, 1);
    sectionTabWidget_->addTab(afdPage_, QStringLiteral("AFD"));

    // WFP。
    wfpPage_ = new QWidget(this);
    QVBoxLayout* wfpLayout = new QVBoxLayout(wfpPage_);
    wfpLayout->setContentsMargins(4, 4, 4, 4);
    wfpLayout->setSpacing(6);
    wfpTabWidget_ = new QTabWidget(wfpPage_);
    wfpTabWidget_->setTabPosition(QTabWidget::North);
    wfpLayout->addWidget(wfpTabWidget_, 1);

    auto buildWfpTable = [](QWidget* parent, const QStringList& headers) -> QTableWidget*
    {
        QTableWidget* table = new ks::ui::VisibleTableWidget(parent);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        installCopyMenu(table);
        return table;
    };
    wfpProviderTable_ = buildWfpTable(wfpPage_, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("GUID"), QStringLiteral("Flags"), QStringLiteral("Service"), QStringLiteral("数据大小") });
    wfpSubLayerTable_ = buildWfpTable(wfpPage_, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("GUID"), QStringLiteral("Flags"), QStringLiteral("Provider"), QStringLiteral("Weight") });
    wfpCalloutTable_ = buildWfpTable(wfpPage_, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("GUID"), QStringLiteral("Flags"), QStringLiteral("Provider"), QStringLiteral("Layer"), QStringLiteral("CalloutId") });
    wfpFilterTable_ = buildWfpTable(wfpPage_, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("GUID"), QStringLiteral("Flags"), QStringLiteral("Provider"), QStringLiteral("Layer"), QStringLiteral("Sublayer"), QStringLiteral("Weight"), QStringLiteral("Action"), QStringLiteral("Conditions"), QStringLiteral("FilterId") });
    wfpTabWidget_->addTab(wfpProviderTable_, QStringLiteral("Provider"));
    wfpTabWidget_->addTab(wfpSubLayerTable_, QStringLiteral("Sublayer"));
    wfpTabWidget_->addTab(wfpCalloutTable_, QStringLiteral("Callout"));
    wfpTabWidget_->addTab(wfpFilterTable_, QStringLiteral("Filter"));
    sectionTabWidget_->addTab(wfpPage_, QStringLiteral("WFP"));

    // NDIS。
    ndisPage_ = new QWidget(this);
    QVBoxLayout* ndisLayout = new QVBoxLayout(ndisPage_);
    ndisLayout->setContentsMargins(4, 4, 4, 4);
    ndisLayout->setSpacing(6);
    ndisTabWidget_ = new QTabWidget(ndisPage_);
    ndisTabWidget_->setTabPosition(QTabWidget::North);
    ndisLayout->addWidget(ndisTabWidget_, 1);
    ndisAdapterTable_ = buildWfpTable(ndisPage_, { QStringLiteral("名称"), QStringLiteral("描述"), QStringLiteral("IfIndex"), QStringLiteral("状态"), QStringLiteral("MAC"), QStringLiteral("速率"), QStringLiteral("连接") });
    ndisBindingTable_ = buildWfpTable(ndisPage_, { QStringLiteral("网卡"), QStringLiteral("显示名"), QStringLiteral("ComponentId"), QStringLiteral("启用"), QStringLiteral("InstanceId") });
    ndisProtocolTable_ = buildWfpTable(ndisPage_, { QStringLiteral("别名"), QStringLiteral("IfIndex"), QStringLiteral("地址族"), QStringLiteral("连接"), QStringLiteral("Metric"), QStringLiteral("MTU") });
    ndisUnknownTable_ = buildWfpTable(ndisPage_, { QStringLiteral("类型"), QStringLiteral("组件"), QStringLiteral("所属模块"), QStringLiteral("对象地址"), QStringLiteral("详情") });
    ndisTabWidget_->addTab(ndisAdapterTable_, QStringLiteral("Miniport"));
    ndisTabWidget_->addTab(ndisBindingTable_, QStringLiteral("Binding"));
    ndisTabWidget_->addTab(ndisProtocolTable_, QStringLiteral("Protocol"));
    ndisTabWidget_->addTab(
        ndisUnknownTable_,
        QStringLiteral("未知/未证明"));
    sectionTabWidget_->addTab(ndisPage_, QStringLiteral("NDIS"));

    // NSI。
    nsiPage_ = new QWidget(this);
    QVBoxLayout* nsiLayout = new QVBoxLayout(nsiPage_);
    nsiLayout->setContentsMargins(4, 4, 4, 4);
    nsiLayout->setSpacing(6);
    nsiSummaryTable_ = new ks::ui::VisibleTableWidget(nsiPage_);
    nsiSummaryTable_->setColumnCount(5);
    nsiSummaryTable_->setHorizontalHeaderLabels({
        QStringLiteral("指标"),
        QStringLiteral("状态/数值"),
        QStringLiteral("返回情况"),
        QStringLiteral("是否截断"),
        QStringLiteral("说明")
    });
    nsiSummaryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    nsiSummaryTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    nsiSummaryTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    nsiSummaryTable_->verticalHeader()->setVisible(false);
    nsiSummaryTable_->horizontalHeader()->setStretchLastSection(true);
    nsiSummaryTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    installCopyMenu(nsiSummaryTable_);
    nsiLayout->addWidget(nsiSummaryTable_, 1);
    sectionTabWidget_->addTab(nsiPage_, QStringLiteral("NSI"));
}

void NetworkAuditPage::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
    {
        refreshAllSnapshotsAsync(true);
    });

    connect(crossAutoRefreshButton_, &QPushButton::toggled, this, [this](const bool enabled)
    {
        if (crossAutoRefreshTimer_ == nullptr)
        {
            return;
        }
        enabled ? crossAutoRefreshTimer_->start() : crossAutoRefreshTimer_->stop();
    });
    connect(crossAutoRefreshTimer_, &QTimer::timeout, this, [this]()
    {
        if (isVisible()
            && sectionTabWidget_ != nullptr
            && sectionTabWidget_->currentWidget() == crossViewPage_)
        {
            refreshCrossViewAsync();
        }
    });
    if (crossAutoRefreshButton_ != nullptr && crossAutoRefreshButton_->isChecked())
    {
        crossAutoRefreshTimer_->start();
    }

    connect(crossSearchEdit_, &QLineEdit::textChanged, this, [this](const QString&)
    {
        applyCrossViewSearchFilter();
    });

    connect(crossTerminateButton_, &QPushButton::clicked, this, [this]()
    {
        terminateSelectedTcpConnection();
    });
    connect(clearProcessFilterButton_, &QPushButton::clicked, this, [this]()
    {
        focusProcessIds({});
    });
    connect(tcpTable_, &QTableWidget::itemSelectionChanged, this, [this]()
    {
        updateCrossViewActionState();
    });
    connect(tcpTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position)
    {
        showCrossViewContextMenu(tcpTable_, position);
    });
    connect(udpTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position)
    {
        showCrossViewContextMenu(udpTable_, position);
    });
}

void NetworkAuditPage::refreshAllSnapshotsAsync(const bool forceRefresh)
{
    bool expected = false;
    if (!refreshInProgress_.compare_exchange_strong(expected, true))
    {
        if (forceRefresh && statusLabel_ != nullptr)
        {
            statusLabel_->setText(QStringLiteral("状态：已有刷新任务在运行"));
        }
        return;
    }

    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(forceRefresh ? QStringLiteral("状态：正在重新采集...") : QStringLiteral("状态：正在采集..."));
    }

    const std::shared_ptr<NetworkAuditAsyncState> kAsyncState = asyncState_;
    std::thread([kAsyncState]()
    {
        AuditSnapshot snapshot;
        QString failureText;
        try
        {
            snapshot = buildAuditSnapshot();
        }
        catch (const std::exception& exception)
        {
            failureText = QStringLiteral("刷新失败：%1").arg(QString::fromUtf8(exception.what()));
        }
        catch (...)
        {
            failureText = QStringLiteral("刷新失败");
        }

        std::lock_guard<std::mutex> dispatchLock(kAsyncState->mutex);
        NetworkAuditPage* const kReceiver = kAsyncState->owner;
        if (kReceiver == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(kReceiver, [kAsyncState, snapshot = std::move(snapshot), failureText]() mutable
        {
            NetworkAuditPage* page = nullptr;
            {
                std::lock_guard<std::mutex> stateLock(kAsyncState->mutex);
                page = kAsyncState->owner;
            }
            if (page == nullptr)
            {
                return;
            }
            if (failureText.isEmpty())
            {
                page->applySnapshot(snapshot);
            }
            else
            {
                KLogEvent failureEvent;
                warn << failureEvent
                    << "[NetworkAuditPage] refresh failed, detail="
                    << failureText.toStdString()
                    << eol;
                if (page->statusLabel_ != nullptr)
                {
                    page->statusLabel_->setText(QStringLiteral(
                        "状态：刷新失败；详情已写入日志。"));
                }
            }
            if (page->refreshButton_ != nullptr)
            {
                page->refreshButton_->setEnabled(true);
            }
            page->refreshInProgress_.store(false);
        }, Qt::QueuedConnection);
    }).detach();
}

void NetworkAuditPage::refreshCrossViewAsync()
{
    bool expected = false;
    if (!refreshInProgress_.compare_exchange_strong(expected, true))
    {
        return;
    }

    const std::shared_ptr<NetworkAuditAsyncState> kAsyncState = asyncState_;
    std::thread([kAsyncState]()
    {
        AuditSnapshot snapshot;
        QString failureText;
        try
        {
            snapshot = buildAuditSnapshot(true);
        }
        catch (const std::exception& exception)
        {
            failureText = QStringLiteral("刷新失败：%1").arg(QString::fromUtf8(exception.what()));
        }
        catch (...)
        {
            failureText = QStringLiteral("刷新失败");
        }

        std::lock_guard<std::mutex> dispatchLock(kAsyncState->mutex);
        NetworkAuditPage* const kReceiver = kAsyncState->owner;
        if (kReceiver == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            kReceiver,
            [kAsyncState, snapshot = std::move(snapshot), failureText]() mutable
            {
                NetworkAuditPage* page = nullptr;
                {
                    std::lock_guard<std::mutex> stateLock(kAsyncState->mutex);
                    page = kAsyncState->owner;
                }
                if (page == nullptr)
                {
                    return;
                }

                if (failureText.isEmpty())
                {
                    // R0 rows are collected via full audit; high-frequency connection refreshes only replace R3 rows.
                    for (const TcpEndpointRow& cachedRow : page->tcpEndpointCache_)
                    {
                        if (cachedRow.isR0Snapshot)
                        {
                            snapshot.tcpEndpointRows.push_back(cachedRow);
                        }
                    }
                    for (const UdpEndpointRow& cachedRow : page->udpEndpointCache_)
                    {
                        if (cachedRow.sourceText.startsWith(QStringLiteral("R0")))
                        {
                            snapshot.udpEndpointRows.push_back(cachedRow);
                        }
                    }
                    page->refreshCrossViewTable(snapshot);
                }
                else
                {
                    KLogEvent failureEvent;
                    warn << failureEvent
                        << "[NetworkAuditPage] cross-view refresh failed, detail="
                        << failureText.toStdString()
                        << eol;
                    if (page->statusLabel_ != nullptr)
                    {
                        page->statusLabel_->setText(QStringLiteral(
                            "状态：刷新失败；详情已写入日志。"));
                    }
                }
                page->refreshInProgress_.store(false);
            },
            Qt::QueuedConnection);
    }).detach();
}

NetworkAuditPage::AuditSnapshot NetworkAuditPage::buildAuditSnapshot(const bool crossViewOnly)
{
    AuditSnapshot snapshot;

    // TCP/UDP cross-view: enumerate separately first, then aggregate by PID.
    std::vector<ks::network::TcpConnectionRecord> tcpRecords;
    std::vector<ks::network::UdpEndpointRecord> udpRecords;
    std::string tcpError;
    std::string udpError;
    const bool kTcpOk = ks::network::enumerateTcpConnectionRecords(tcpRecords, &tcpError);
    const bool kUdpOk = ks::network::enumerateUdpEndpointRecords(udpRecords, &udpError);

    std::unordered_map<std::uint32_t, CrossViewRow> crossMap;
    snapshot.tcpEndpointRows.reserve(tcpRecords.size());
    for (const ks::network::TcpConnectionRecord& tcpRecord : tcpRecords)
    {
        CrossViewRow& row = crossMap[tcpRecord.processId];
        row.processId = tcpRecord.processId;
        row.processName = QString::fromUtf8(tcpRecord.processName.c_str());
        ++row.tcpCount;
        row.tcpSummary = joinCompactLines({
            row.tcpSummary,
            QStringLiteral("%1:%2 -> %3:%4 (%5)")
            .arg(QString::fromUtf8(tcpRecord.localAddressText.c_str()))
            .arg(tcpRecord.localPort)
            .arg(QString::fromUtf8(tcpRecord.remoteAddressText.c_str()))
            .arg(tcpRecord.remotePort)
            .arg(QString::fromUtf8(tcpRecord.tcpStateText.c_str()))
        });

        TcpEndpointRow endpointRow;
        endpointRow.processId = tcpRecord.processId;
        endpointRow.processName = QString::fromUtf8(tcpRecord.processName.c_str());
        endpointRow.localEndpointText = QStringLiteral("%1:%2")
            .arg(QString::fromUtf8(tcpRecord.localAddressText.c_str()))
            .arg(tcpRecord.localPort);
        endpointRow.remoteEndpointText = QStringLiteral("%1:%2")
            .arg(QString::fromUtf8(tcpRecord.remoteAddressText.c_str()))
            .arg(tcpRecord.remotePort);
        endpointRow.stateText = QString::fromUtf8(tcpRecord.tcpStateText.c_str());
        endpointRow.detailText = QStringLiteral("来源=R3 TCP table；PID=%1；状态=%2")
            .arg(tcpRecord.processId)
            .arg(endpointRow.stateText);
        endpointRow.canTerminate = true;
        endpointRow.connectionRecord = tcpRecord;
        snapshot.tcpEndpointRows.push_back(std::move(endpointRow));
    }
    snapshot.udpEndpointRows.reserve(udpRecords.size());
    for (const ks::network::UdpEndpointRecord& udpRecord : udpRecords)
    {
        CrossViewRow& row = crossMap[udpRecord.processId];
        row.processId = udpRecord.processId;
        row.processName = QString::fromUtf8(udpRecord.processName.c_str());
        ++row.udpCount;
        row.udpSummary = joinCompactLines({
            row.udpSummary,
            QStringLiteral("%1:%2")
            .arg(QString::fromUtf8(udpRecord.localAddressText.c_str()))
            .arg(udpRecord.localPort)
        });

        UdpEndpointRow endpointRow;
        endpointRow.processId = udpRecord.processId;
        endpointRow.processName = QString::fromUtf8(udpRecord.processName.c_str());
        endpointRow.localEndpointText = QStringLiteral("%1:%2")
            .arg(QString::fromUtf8(udpRecord.localAddressText.c_str()))
            .arg(udpRecord.localPort);
        endpointRow.sourceText = QStringLiteral("R3 UDP table");
        endpointRow.detailText = QStringLiteral("来源=R3 UDP endpoint；PID=%1").arg(udpRecord.processId);
        snapshot.udpEndpointRows.push_back(std::move(endpointRow));
    }
    snapshot.crossViewRows.reserve(crossMap.size());
    for (auto& pair : crossMap)
    {
        snapshot.crossViewRows.push_back(pair.second);
    }
    std::sort(snapshot.crossViewRows.begin(), snapshot.crossViewRows.end(), [](const CrossViewRow& left, const CrossViewRow& right)
    {
        if (left.processId != right.processId)
        {
            return left.processId < right.processId;
        }
        return left.processName < right.processName;
    });

    if (crossViewOnly)
    {
        return snapshot;
    }

    // AFD: First perform a read-only enumeration based on system handles, then filter for AFD-related objects.
    ks::file::HandleSnapshotOptions handleOptions;
    handleOptions.resolveObjectName = true;
    handleOptions.nameResolveBudget = 220;
    handleOptions.basicInfoQueryBudget = 220;
    handleOptions.enumMode = ks::file::HandleEnumMode::kDuplicateHandle;
    const ks::file::HandleSnapshotResult kHandleSnapshot = ks::file::buildHandleSnapshot(handleOptions);
    snapshot.afdRows.reserve(kHandleSnapshot.rows.size());
    for (const ks::file::HandleSnapshotRow& handleRow : kHandleSnapshot.rows)
    {
        if (handleRow.objectName.empty())
        {
            continue;
        }
        const QString kObjectNameText = QString::fromWCharArray(handleRow.objectName.c_str());
        if (!compareContainsAfd(kObjectNameText))
        {
            continue;
        }

        AfdHandleRow row;
        row.processId = handleRow.processId;
        row.processName = QString::fromWCharArray(handleRow.processName.c_str());
        row.handleValueText = QStringLiteral("0x%1").arg(QString::number(handleRow.handleValue, 16));
        row.typeName = QString::fromWCharArray(handleRow.typeName.c_str());
        row.objectName = kObjectNameText;
        row.sourceText = QStringLiteral("R3 Handle Snapshot");
        row.diffText = handleRow.diffStatus == ks::file::HandleDiffStatus::kNotCompared ? QStringLiteral("未对比") : QStringLiteral("已对比");
        row.accessText = QStringLiteral("0x%1").arg(QString::number(handleRow.grantedAccess, 16));
        row.detailText = QStringLiteral("handleCount=%1 pointerCount=%2")
            .arg(handleRow.handleCount)
            .arg(handleRow.pointerCount);
        snapshot.afdRows.push_back(std::move(row));
    }

    // WFP: Dynamically load fwpuclnt.dll and directly enumerate providers, sublayers, callouts, and filters.
    HANDLE wfpEngineHandle = nullptr;
    QString wfpErrorText;
    if (openWfpEngine(wfpEngineHandle, &wfpErrorText))
    {
        auto& api = wfpApi();
        auto enumProviders = [&snapshot, &api, wfpEngineHandle]()
        {
            HANDLE enumHandle = nullptr;
            FWPM_PROVIDER_ENUM_TEMPLATE0 enumTemplate{};
            if (api.providerCreateEnumHandle(wfpEngineHandle, &enumTemplate, &enumHandle) != ERROR_SUCCESS || enumHandle == nullptr)
            {
                return;
            }

            while (true)
            {
                FWPM_PROVIDER0** entries = nullptr;
                UINT32 count = 0;
                const DWORD kStatus = api.providerEnum(wfpEngineHandle, enumHandle, 128, &entries, &count);
                if (kStatus != ERROR_SUCCESS)
                {
                    break;
                }
                if (entries == nullptr || count == 0)
                {
                    if (entries != nullptr)
                    {
                        api.freeMemory(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 index = 0; index < count; ++index)
                {
                    const FWPM_PROVIDER0* provider = entries[index];
                    if (provider == nullptr)
                    {
                        continue;
                    }
                    WfpProviderRow row;
                    row.nameText = displayDataText(&provider->displayData);
                    row.descriptionText = provider->displayData.description != nullptr ? QString::fromWCharArray(provider->displayData.description) : QString();
                    row.guidText = guidToText(provider->providerKey);
                    row.flagsText = wfpFlagsText(provider->flags);
                    row.serviceNameText = provider->serviceName != nullptr ? QString::fromWCharArray(provider->serviceName) : QString();
                    row.dataSizeText = provider->providerData.size > 0 ? QString::number(provider->providerData.size) : QStringLiteral("0");
                    snapshot.wfpProviderRows.push_back(std::move(row));
                }
                api.freeMemory(reinterpret_cast<void**>(&entries));
                if (snapshot.wfpProviderRows.size() >= 256)
                {
                    break;
                }
            }

            api.providerDestroyEnumHandle(wfpEngineHandle, enumHandle);
        };

        auto enumSubLayers = [&snapshot, &api, wfpEngineHandle]()
        {
            HANDLE enumHandle = nullptr;
            FWPM_SUBLAYER_ENUM_TEMPLATE0 enumTemplate{};
            if (api.subLayerCreateEnumHandle(wfpEngineHandle, &enumTemplate, &enumHandle) != ERROR_SUCCESS || enumHandle == nullptr)
            {
                return;
            }

            while (true)
            {
                FWPM_SUBLAYER0** entries = nullptr;
                UINT32 count = 0;
                const DWORD kStatus = api.subLayerEnum(wfpEngineHandle, enumHandle, 128, &entries, &count);
                if (kStatus != ERROR_SUCCESS)
                {
                    break;
                }
                if (entries == nullptr || count == 0)
                {
                    if (entries != nullptr)
                    {
                        api.freeMemory(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 index = 0; index < count; ++index)
                {
                    const FWPM_SUBLAYER0* subLayer = entries[index];
                    if (subLayer == nullptr)
                    {
                        continue;
                    }
                    WfpSubLayerRow row;
                    row.nameText = displayDataText(&subLayer->displayData);
                    row.descriptionText = subLayer->displayData.description != nullptr ? QString::fromWCharArray(subLayer->displayData.description) : QString();
                    row.guidText = guidToText(subLayer->subLayerKey);
                    row.flagsText = wfpFlagsText(subLayer->flags);
                    row.providerGuidText = subLayer->providerKey != nullptr ? guidToText(*subLayer->providerKey) : QString();
                    row.weightText = QString::number(subLayer->weight);
                    snapshot.wfpSubLayerRows.push_back(std::move(row));
                }
                api.freeMemory(reinterpret_cast<void**>(&entries));
                if (snapshot.wfpSubLayerRows.size() >= 256)
                {
                    break;
                }
            }

            api.subLayerDestroyEnumHandle(wfpEngineHandle, enumHandle);
        };

        auto enumCallouts = [&snapshot, &api, wfpEngineHandle]()
        {
            HANDLE enumHandle = nullptr;
            FWPM_CALLOUT_ENUM_TEMPLATE0 enumTemplate{};
            if (api.calloutCreateEnumHandle(wfpEngineHandle, &enumTemplate, &enumHandle) != ERROR_SUCCESS || enumHandle == nullptr)
            {
                return;
            }

            while (true)
            {
                FWPM_CALLOUT0** entries = nullptr;
                UINT32 count = 0;
                const DWORD kStatus = api.calloutEnum(wfpEngineHandle, enumHandle, 128, &entries, &count);
                if (kStatus != ERROR_SUCCESS)
                {
                    break;
                }
                if (entries == nullptr || count == 0)
                {
                    if (entries != nullptr)
                    {
                        api.freeMemory(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 index = 0; index < count; ++index)
                {
                    const FWPM_CALLOUT0* callout = entries[index];
                    if (callout == nullptr)
                    {
                        continue;
                    }
                    WfpCalloutRow row;
                    row.nameText = displayDataText(&callout->displayData);
                    row.descriptionText = callout->displayData.description != nullptr ? QString::fromWCharArray(callout->displayData.description) : QString();
                    row.guidText = guidToText(callout->calloutKey);
                    row.flagsText = wfpFlagsText(callout->flags);
                    row.providerGuidText = callout->providerKey != nullptr ? guidToText(*callout->providerKey) : QString();
                    row.layerGuidText = guidToText(callout->applicableLayer);
                    row.calloutIdText = QString::number(callout->calloutId);
                    snapshot.wfpCalloutRows.push_back(std::move(row));
                }
                api.freeMemory(reinterpret_cast<void**>(&entries));
                if (snapshot.wfpCalloutRows.size() >= 256)
                {
                    break;
                }
            }

            api.calloutDestroyEnumHandle(wfpEngineHandle, enumHandle);
        };

        auto enumFilters = [&snapshot, &api, wfpEngineHandle]()
        {
            HANDLE enumHandle = nullptr;
            FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate{};
            if (api.filterCreateEnumHandle(wfpEngineHandle, &enumTemplate, &enumHandle) != ERROR_SUCCESS || enumHandle == nullptr)
            {
                return;
            }

            while (true)
            {
                FWPM_FILTER0** entries = nullptr;
                UINT32 count = 0;
                const DWORD kStatus = api.filterEnum(wfpEngineHandle, enumHandle, 128, &entries, &count);
                if (kStatus != ERROR_SUCCESS)
                {
                    break;
                }
                if (entries == nullptr || count == 0)
                {
                    if (entries != nullptr)
                    {
                        api.freeMemory(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 index = 0; index < count; ++index)
                {
                    const FWPM_FILTER0* filter = entries[index];
                    if (filter == nullptr)
                    {
                        continue;
                    }
                    WfpFilterRow row;
                    row.nameText = displayDataText(&filter->displayData);
                    row.descriptionText = filter->displayData.description != nullptr ? QString::fromWCharArray(filter->displayData.description) : QString();
                    row.guidText = guidToText(filter->filterKey);
                    row.flagsText = wfpFlagsText(filter->flags);
                    row.providerGuidText = filter->providerKey != nullptr ? guidToText(*filter->providerKey) : QString();
                    row.layerGuidText = guidToText(filter->layerKey);
                    row.subLayerGuidText = guidToText(filter->subLayerKey);
                    row.weightText = QStringLiteral("type=%1").arg(static_cast<int>(filter->weight.type));
                    row.actionText = QStringLiteral("type=%1").arg(static_cast<int>(filter->action.type));
                    row.conditionText = QStringLiteral("conditions=%1").arg(filter->numFilterConditions);
                    row.filterIdText = QString::number(filter->filterId);
                    snapshot.wfpFilterRows.push_back(std::move(row));
                }
                api.freeMemory(reinterpret_cast<void**>(&entries));
                if (snapshot.wfpFilterRows.size() >= 400)
                {
                    break;
                }
            }

            api.filterDestroyEnumHandle(wfpEngineHandle, enumHandle);
        };

        enumProviders();
        enumSubLayers();
        enumCallouts();
        enumFilters();
        api.engineClose(wfpEngineHandle);
    }
    else
    {
        snapshot.wfpProviderRows.push_back({ QStringLiteral("WFP"), wfpErrorText, QString(), QString(), QString(), QString() });
    }

    QString ndisScript = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$adapters = Get-NetAdapter | Select-Object -First 200 Name,InterfaceDescription,ifIndex,Status,MacAddress,LinkSpeed; "
        "$bindings = Get-NetAdapterBinding | Select-Object -First 200 Name,DisplayName,ComponentID,Enabled,InstanceID; "
        "$ifaces = Get-NetIPInterface | Select-Object -First 200 InterfaceAlias,ifIndex,AddressFamily,ConnectionState,InterfaceMetric,NlMtu; "
        "[pscustomobject]@{ adapters=$adapters; bindings=$bindings; ifaces=$ifaces } | ConvertTo-Json -Depth 4 -Compress");
    QString ndisErrorText;
    QString ndisJson = runPowerShellTextSync(ndisScript, 12000, &ndisErrorText);
    QJsonParseError parseError{};
    const QJsonDocument kNdisDoc = QJsonDocument::fromJson(ndisJson.toUtf8(), &parseError);
    if (parseError.error == QJsonParseError::NoError && kNdisDoc.isObject())
    {
        const QJsonArray kAdaptersArray = normalizeJsonArray(kNdisDoc.object().value(QStringLiteral("adapters")));
        for (const QJsonValue& value : kAdaptersArray)
        {
            const QJsonObject kObject = value.toObject();
            NdisAdapterRow row;
            row.nameText = kObject.value(QStringLiteral("Name")).toString();
            row.descriptionText = kObject.value(QStringLiteral("InterfaceDescription")).toString();
            row.ifIndexText = kObject.value(QStringLiteral("ifIndex")).toVariant().toString();
            row.statusText = kObject.value(QStringLiteral("Status")).toString();
            row.macText = kObject.value(QStringLiteral("MacAddress")).toString();
            row.linkSpeedText = kObject.value(QStringLiteral("LinkSpeed")).toString();
            row.connectionStateText = QStringLiteral("已枚举");
            snapshot.ndisAdapterRows.push_back(std::move(row));
        }

        const QJsonArray kBindingsArray = normalizeJsonArray(kNdisDoc.object().value(QStringLiteral("bindings")));
        for (const QJsonValue& value : kBindingsArray)
        {
            const QJsonObject kObject = value.toObject();
            NdisBindingRow row;
            row.adapterNameText = kObject.value(QStringLiteral("Name")).toString();
            row.displayNameText = kObject.value(QStringLiteral("DisplayName")).toString();
            row.componentIdText = kObject.value(QStringLiteral("ComponentID")).toString();
            row.enabledText = kObject.value(QStringLiteral("Enabled")).toVariant().toString();
            row.instanceIdText = kObject.value(QStringLiteral("InstanceID")).toString();
            snapshot.ndisBindingRows.push_back(std::move(row));
        }

        const QJsonArray kIfacesArray = normalizeJsonArray(kNdisDoc.object().value(QStringLiteral("ifaces")));
        for (const QJsonValue& value : kIfacesArray)
        {
            const QJsonObject kObject = value.toObject();
            NdisProtocolRow row;
            row.interfaceAliasText = kObject.value(QStringLiteral("InterfaceAlias")).toString();
            row.ifIndexText = kObject.value(QStringLiteral("ifIndex")).toVariant().toString();
            row.addressFamilyText = kObject.value(QStringLiteral("AddressFamily")).toString();
            row.connectionStateText = kObject.value(QStringLiteral("ConnectionState")).toString();
            row.interfaceMetricText = kObject.value(QStringLiteral("InterfaceMetric")).toVariant().toString();
            row.mtuText = kObject.value(QStringLiteral("NlMtu")).toVariant().toString();
            snapshot.ndisProtocolRows.push_back(std::move(row));
        }
    }
    else
    {
        NdisAdapterRow row;
        row.nameText = QStringLiteral("NDIS");
        row.descriptionText = ndisErrorText;
        snapshot.ndisAdapterRows.push_back(std::move(row));
    }

    // R0 network audit:
    // - Input: four read-only wrappers of ArkDriverClient;
    // - Processing: First collect the ok/unsupported/count/truncated/message summaries, then append the R0 details to the existing table.
    // - Return: Write to snapshot.r0SummaryRows and each detail row collection for UI appending.
    {
        const ksword::ark::DriverClient kDriverClient;
        const auto kTcpR0 = kDriverClient.queryNetworkTcpEndpoints();
        const auto kUdpR0 = kDriverClient.queryNetworkUdpEndpoints();
        const auto kWfpR0 = kDriverClient.queryNetworkWfpInventory();
        const auto kNdisR0 = kDriverClient.queryNetworkNdisChain();
        snapshot.r0TcpStatusText = r0AuditStatusText(kTcpR0);
        snapshot.r0UdpStatusText = r0AuditStatusText(kUdpR0);

        auto appendR0Summary = [&snapshot](const QString& nameText, const auto& result)
        {
            R0NetworkSummaryRow row;
            row.nameText = nameText;
            row.statusText = r0AuditStatusText(result);
            // returned/total come from the R0 response header; parsed is used to indicate the actual number of rows parsed by ArkDriverClient.
            // These three numbers are displayed side-by-side to distinguish between the 'driver-reported count' and the 'user-mode parsed count'.
            row.countText = QStringLiteral("已解析 %3 行；驱动报告 %1/%2 行")
                .arg(result.returnedCount)
                .arg(result.totalCount)
                .arg(static_cast<qulonglong>(result.entries.size()));
            if (result.partial)
            {
                if (result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                    result.totalCount > result.returnedCount)
                {
                    row.truncatedText =
                        QStringLiteral("是，达到返回预算（仅展示驱动返回子集）");
                }
                else
                {
                    row.truncatedText =
                        static_cast<std::uint32_t>(result.lastStatus) == 0x80000005UL
                        ? QStringLiteral("是，部分结果（达到遍历或缓冲上限，合法行已保留）")
                        : QStringLiteral("部分结果（部分枚举失败，合法行已保留）");
                }
            }
            else
            {
                row.truncatedText =
                    r0AuditTruncatedText(result) == QStringLiteral("true")
                    ? QStringLiteral("是，结果可能未完整返回")
                    : QStringLiteral("否");
            }
            row.messageText = QStringLiteral("%1；protocolStatus=%2；lastStatus=%3；sourceFlags=%4；generation=%5；partial=%6；truncated=%7；retainedRows=%8")
                .arg(ioMessageToText(result.io.message))
                .arg(result.status)
                .arg(r0Hex32(static_cast<std::uint32_t>(result.lastStatus)))
                .arg(r0Hex32(result.sourceFlags))
                .arg(result.generation)
                .arg(result.partial ? QStringLiteral("true") : QStringLiteral("false"))
                .arg(result.truncated ? QStringLiteral("true") : QStringLiteral("false"))
                .arg(static_cast<qulonglong>(result.entries.size()));
            snapshot.r0SummaryRows.push_back(std::move(row));
        };

        appendR0Summary(QStringLiteral("R0 TCP"), kTcpR0);
        appendR0Summary(QStringLiteral("R0 UDP"), kUdpR0);
        appendR0Summary(QStringLiteral("R0 WFP"), kWfpR0);
        appendR0Summary(QStringLiteral("R0 NDIS"), kNdisR0);

        // R0 detail expansion:
        // - Input: four ArkDriverClient wrapper entries;
        // - Processing: Append endpoint/WFP/NDIS rows to the existing detail table without replacing R3 enumeration results;
        // - Return: None. All text is for read-only audit display only.
        auto appendR0Endpoints = [&snapshot](const ksword::ark::NetworkEndpointAuditResult& result, const bool tcpRows)
        {
            const QString kCompletenessText = result.partial || result.truncated
                ? QStringLiteral("部分/截断子集")
                : QStringLiteral("完整结果");
            for (const KSWORD_ARK_NETWORK_ENDPOINT_ROW& entry : result.entries)
            {
                const QString kDetailText = QStringLiteral("来源=R0 endpoint；快照=%1；rowId=%2；protocol=%3；AF=%4；compartment=%5；ifIndex=%6；flags=%7；sourceFlags=%8；fieldMask=%9；endpointObject=%10；owningProcessObject=%11；transportObject=%12；interfaceLuid=%13")
                    .arg(kCompletenessText)
                    .arg(entry.rowId)
                    .arg(entry.protocol)
                    .arg(entry.addressFamily)
                    .arg(entry.compartmentId)
                    .arg(entry.interfaceIndex)
                    .arg(r0Hex32(entry.flags))
                    .arg(r0Hex32(entry.sourceFlags))
                    .arg(r0Hex32(entry.fieldMask))
                    .arg(r0Hex64(entry.endpointObject))
                    .arg(r0Hex64(entry.owningProcessObject))
                    .arg(r0Hex64(entry.transportObject))
                    .arg(r0Hex64(entry.interfaceLuid));

                if (tcpRows)
                {
                    TcpEndpointRow row;
                    row.processId = entry.owningPid;
                    row.processName = QStringLiteral("R0 PID %1").arg(entry.owningPid);
                    row.localEndpointText = r0EndpointText(entry.addressFamily, entry.localAddress, entry.localPort);
                    row.remoteEndpointText = r0EndpointText(entry.addressFamily, entry.remoteAddress, entry.remotePort);
                    row.stateText = r0TcpStateText(entry.state);
                    row.detailText = kDetailText;
                    row.isR0Snapshot = true;
                    snapshot.tcpEndpointRows.push_back(std::move(row));
                }
                else
                {
                    UdpEndpointRow row;
                    row.processId = entry.owningPid;
                    row.processName = QStringLiteral("R0 PID %1").arg(entry.owningPid);
                    row.localEndpointText = r0EndpointText(entry.addressFamily, entry.localAddress, entry.localPort);
                    row.sourceText = QStringLiteral("R0 UDP endpoint");
                    row.detailText = kDetailText;
                    snapshot.udpEndpointRows.push_back(std::move(row));
                }
            }
        };

        auto appendR0WfpRows = [&snapshot](const ksword::ark::NetworkWfpInventoryResult& result)
        {
            const QString kCompletenessText = result.partial || result.truncated
                ? QStringLiteral("部分/截断子集")
                : QStringLiteral("完整结果");
            for (const KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW& entry : result.entries)
            {
                const QString kOwnerModuleText = fixedNetworkWideText(entry.ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS, QStringLiteral("<owner unknown>"));
                const QString kDetailText = QStringLiteral("来源=R0 WFP；快照=%1；kind=%2；rowId=%3；flags=%4；fieldMask=%5；layerId=%6；calloutId=%7；object=%8；classify=%9；notify=%10；flowDelete=%11；ownerBase=%12；ownerModule=%13")
                    .arg(kCompletenessText)
                    .arg(r0WfpObjectKindText(entry.objectKind))
                    .arg(entry.rowId)
                    .arg(r0Hex32(entry.flags))
                    .arg(r0Hex32(entry.fieldMask))
                    .arg(entry.layerId)
                    .arg(entry.calloutId)
                    .arg(r0Hex64(entry.objectAddress))
                    .arg(r0Hex64(entry.classifyAddress))
                    .arg(r0Hex64(entry.notifyAddress))
                    .arg(r0Hex64(entry.flowDeleteAddress))
                    .arg(r0Hex64(entry.ownerImageBase))
                    .arg(kOwnerModuleText);

                if (entry.objectKind == KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER)
                {
                    WfpProviderRow row;
                    row.nameText = QStringLiteral("R0 Provider #%1").arg(entry.rowId);
                    row.descriptionText = kDetailText;
                    row.guidText = r0GuidText(entry.objectKey);
                    row.flagsText = r0Hex32(entry.flags);
                    row.serviceNameText = kOwnerModuleText;
                    row.dataSizeText = QStringLiteral("fieldMask=%1").arg(r0Hex32(entry.fieldMask));
                    snapshot.wfpProviderRows.push_back(std::move(row));
                }
                else if (entry.objectKind == KSWORD_ARK_NETWORK_WFP_OBJECT_SUBLAYER)
                {
                    WfpSubLayerRow row;
                    row.nameText = QStringLiteral("R0 Sublayer #%1").arg(entry.rowId);
                    row.descriptionText = kDetailText;
                    row.guidText = r0GuidText(entry.objectKey);
                    row.flagsText = r0Hex32(entry.flags);
                    row.providerGuidText = r0GuidText(entry.providerKey);
                    row.weightText = QString::number(entry.weight);
                    snapshot.wfpSubLayerRows.push_back(std::move(row));
                }
                else if (entry.objectKind == KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT)
                {
                    WfpCalloutRow row;
                    row.nameText = QStringLiteral("R0 Callout #%1").arg(entry.rowId);
                    row.descriptionText = kDetailText;
                    row.guidText = r0GuidText(entry.objectKey);
                    row.flagsText = r0Hex32(entry.flags);
                    row.providerGuidText = r0GuidText(entry.providerKey);
                    row.layerGuidText = QStringLiteral("layerId=%1").arg(entry.layerId);
                    row.calloutIdText = QString::number(entry.calloutId);
                    snapshot.wfpCalloutRows.push_back(std::move(row));
                }
                else
                {
                    WfpFilterRow row;
                    row.nameText = QStringLiteral("R0 Filter #%1").arg(entry.rowId);
                    row.descriptionText = kDetailText;
                    row.guidText = r0GuidText(entry.objectKey);
                    row.flagsText = r0Hex32(entry.flags);
                    row.providerGuidText = r0GuidText(entry.providerKey);
                    row.layerGuidText = QStringLiteral("layerId=%1").arg(entry.layerId);
                    row.subLayerGuidText = r0GuidText(entry.subLayerKey);
                    row.weightText = QString::number(entry.weight);
                    row.actionText = QStringLiteral("calloutId=%1").arg(entry.calloutId);
                    row.conditionText = kDetailText;
                    row.filterIdText = QString::number(entry.filterId);
                    snapshot.wfpFilterRows.push_back(std::move(row));
                }
            }
        };

        auto appendR0NdisRows = [&snapshot](const ksword::ark::NetworkNdisChainResult& result)
        {
            const QString kCompletenessText = result.partial || result.truncated
                ? QStringLiteral("部分/截断子集")
                : QStringLiteral("完整结果");
            for (const KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW& entry : result.entries)
            {
                const QString kComponentText = fixedNetworkWideText(entry.componentName, KSWORD_ARK_NETWORK_NAME_CHARS, QStringLiteral("<component unknown>"));
                const QString kOwnerModuleText = fixedNetworkWideText(entry.ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS, QStringLiteral("<owner unknown>"));
                const QString kKindText = r0NdisObjectKindText(entry.objectKind);
                const QString kDetailText = QStringLiteral("来源=R0 NDIS；快照=%1；kind=%2；rowId=%3；flags=%4；fieldMask=%5；ifIndex=%6；filterOrder=%7；adapterLuid=%8；object=%9；parent=%10；driverObject=%11；imageBase=%12；ownerModule=%13")
                    .arg(kCompletenessText)
                    .arg(kKindText)
                    .arg(entry.rowId)
                    .arg(r0Hex32(entry.flags))
                    .arg(r0Hex32(entry.fieldMask))
                    .arg(entry.ifIndex)
                    .arg(entry.filterOrder)
                    .arg(r0Hex64(entry.adapterLuid))
                    .arg(r0Hex64(entry.objectAddress))
                    .arg(r0Hex64(entry.parentObjectAddress))
                    .arg(r0Hex64(entry.driverObject))
                    .arg(r0Hex64(entry.imageBase))
                    .arg(kOwnerModuleText);

                if (entry.objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_MINIPORT)
                {
                    NdisAdapterRow row;
                    row.nameText = kComponentText;
                    row.descriptionText = kDetailText;
                    row.ifIndexText = QString::number(entry.ifIndex);
                    row.statusText = kKindText;
                    row.macText = QStringLiteral("R0");
                    row.linkSpeedText = QStringLiteral("object=%1").arg(r0Hex64(entry.objectAddress));
                    row.connectionStateText = kOwnerModuleText;
                    snapshot.ndisAdapterRows.push_back(std::move(row));
                }
                else if (entry.objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_PROTOCOL)
                {
                    NdisProtocolRow row;
                    row.interfaceAliasText = kComponentText;
                    row.ifIndexText = QString::number(entry.ifIndex);
                    row.addressFamilyText = kKindText;
                    row.connectionStateText = kOwnerModuleText;
                    row.interfaceMetricText = QStringLiteral("flags=%1").arg(r0Hex32(entry.flags));
                    row.mtuText = kDetailText;
                    snapshot.ndisProtocolRows.push_back(std::move(row));
                }
                else if (
                    entry.objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_FILTER ||
                    entry.objectKind == KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING)
                {
                    NdisBindingRow row;
                    row.adapterNameText = kComponentText;
                    row.displayNameText = kKindText;
                    row.componentIdText = kOwnerModuleText;
                    row.enabledText = QStringLiteral("flags=%1").arg(r0Hex32(entry.flags));
                    row.instanceIdText = kDetailText;
                    snapshot.ndisBindingRows.push_back(std::move(row));
                }
                else
                {
                    NdisUnknownRow row;
                    row.kindText = QStringLiteral("未知/未证明（kind=%1）")
                        .arg(entry.objectKind);
                    row.componentText = kComponentText;
                    row.ownerModuleText = kOwnerModuleText;
                    row.objectAddressText = r0Hex64(entry.objectAddress);
                    row.detailText = kDetailText;
                    snapshot.ndisUnknownRows.push_back(std::move(row));
                }
            }
        };

        appendR0Endpoints(kTcpR0, true);
        appendR0Endpoints(kUdpR0, false);
        appendR0WfpRows(kWfpR0);
        appendR0NdisRows(kNdisR0);
    }

    snapshot.nsiSummaryRows = {
        { QStringLiteral("TCP 条目"), QString::number(tcpRecords.size()) },
        { QStringLiteral("UDP 端点"), QString::number(udpRecords.size()) },
        { QStringLiteral("AFD 候选句柄"), QString::number(snapshot.afdRows.size()) },
        { QStringLiteral("WFP Provider"), QString::number(snapshot.wfpProviderRows.size()) },
        { QStringLiteral("NDIS Adapter"), QString::number(snapshot.ndisAdapterRows.size()) }
    };

    snapshot.statusText = QStringLiteral("完成：TCP=%1, UDP=%2, AFD=%3, WFP=%4, NDIS=%5")
        .arg(tcpRecords.size())
        .arg(udpRecords.size())
        .arg(snapshot.afdRows.size())
        .arg(snapshot.wfpProviderRows.size())
        .arg(snapshot.ndisAdapterRows.size());
    snapshot.detailText = QStringLiteral("TCP:%1 | UDP:%2")
        .arg(kTcpOk ? QStringLiteral("ok") : QString::fromUtf8(tcpError.c_str()))
        .arg(kUdpOk ? QStringLiteral("ok") : QString::fromUtf8(udpError.c_str()));
    for (const R0NetworkSummaryRow& row : snapshot.r0SummaryRows)
    {
        snapshot.detailText += QStringLiteral(" | %1：%2，%3，截断：%4，说明：%5")
            .arg(row.nameText)
            .arg(row.statusText)
            .arg(row.countText)
            .arg(row.truncatedText)
            .arg(row.messageText);
    }

    return snapshot;
}

void NetworkAuditPage::applySnapshot(const AuditSnapshot& snapshot)
{
    // Full audit rebuilds multiple associated tables; if any right-click menu is open, the entire commit must be deferred. Otherwise,
    // a single snapshot may update only partial tables, potentially causing menu row indices to point to data from the next round.
    const QPointer<NetworkAuditPage> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-audit-full-snapshot"),
        {
            tcpTable_,
            udpTable_,
            crossSummaryTable_,
            afdTable_,
            wfpProviderTable_,
            wfpSubLayerTable_,
            wfpCalloutTable_,
            wfpFilterTable_,
            ndisAdapterTable_,
            ndisBindingTable_,
            ndisProtocolTable_,
            nsiSummaryTable_
        },
        [kSafeThis, snapshot]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applySnapshot(snapshot);
            }
        }))
    {
        return;
    }

    refreshCrossViewTable(snapshot);
    refreshAfdTable(snapshot.afdRows);
    refreshWfpTables(snapshot);
    refreshNdisTables(snapshot);
    refreshNsiSummaryTable(snapshot);

    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(snapshot.statusText);
        statusLabel_->setToolTip(snapshot.detailText);
    }
}

void NetworkAuditPage::refreshCrossViewTable(const AuditSnapshot& snapshot)
{
    // High-frequency TCP/UDP auto-refresh only rebuilds the three cross-view tables; while the menu is open, merge into the latest snapshot.
    const QPointer<NetworkAuditPage> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("network-audit-cross-view"),
        { tcpTable_, udpTable_, crossSummaryTable_ },
        [kSafeThis, snapshot]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->refreshCrossViewTable(snapshot);
            }
        }))
    {
        return;
    }

    tcpEndpointCache_ = snapshot.tcpEndpointRows;
    udpEndpointCache_ = snapshot.udpEndpointRows;
    if (!snapshot.r0TcpStatusText.isEmpty())
    {
        r0TcpStatusText_ = snapshot.r0TcpStatusText;
    }
    if (!snapshot.r0UdpStatusText.isEmpty())
    {
        r0UdpStatusText_ = snapshot.r0UdpStatusText;
    }

    // Cross-View must re-aggregate the current cache by source. A full refresh provides R0 rows, while a high-frequency refresh replaces R3 rows
    // and retains the most recent R0 row; recalculating here prevents the summary table from degenerating to R3-only after an automatic refresh.
    struct CrossViewAggregate
    {
        CrossViewRow row;
        std::size_t tcpR0Count = 0U;
        std::size_t udpR0Count = 0U;
        QString tcpR0Summary;
        QString udpR0Summary;
    };
    std::unordered_map<std::uint32_t, CrossViewAggregate> crossMap;
    for (const TcpEndpointRow& endpointRow : tcpEndpointCache_)
    {
        CrossViewAggregate& aggregate = crossMap[endpointRow.processId];
        aggregate.row.processId = endpointRow.processId;
        if (!endpointRow.isR0Snapshot || aggregate.row.processName.isEmpty())
        {
            aggregate.row.processName = endpointRow.processName;
        }
        const QString kEndpointSummary = QStringLiteral("%1 -> %2 (%3)")
            .arg(endpointRow.localEndpointText)
            .arg(endpointRow.remoteEndpointText)
            .arg(endpointRow.stateText);
        if (endpointRow.isR0Snapshot)
        {
            ++aggregate.tcpR0Count;
            aggregate.tcpR0Summary = joinCompactLines({ aggregate.tcpR0Summary, kEndpointSummary });
        }
        else
        {
            ++aggregate.row.tcpCount;
            aggregate.row.tcpSummary = joinCompactLines({ aggregate.row.tcpSummary, kEndpointSummary });
        }
    }
    for (const UdpEndpointRow& endpointRow : udpEndpointCache_)
    {
        CrossViewAggregate& aggregate = crossMap[endpointRow.processId];
        aggregate.row.processId = endpointRow.processId;
        const bool kIsR0Snapshot = endpointRow.sourceText.startsWith(QStringLiteral("R0"));
        if (!kIsR0Snapshot || aggregate.row.processName.isEmpty())
        {
            aggregate.row.processName = endpointRow.processName;
        }
        if (kIsR0Snapshot)
        {
            ++aggregate.udpR0Count;
            aggregate.udpR0Summary = joinCompactLines({ aggregate.udpR0Summary, endpointRow.localEndpointText });
        }
        else
        {
            ++aggregate.row.udpCount;
            aggregate.row.udpSummary = joinCompactLines({ aggregate.row.udpSummary, endpointRow.localEndpointText });
        }
    }
    std::vector<CrossViewAggregate> effectiveCrossRows;
    effectiveCrossRows.reserve(crossMap.size());
    for (auto& pair : crossMap)
    {
        effectiveCrossRows.push_back(std::move(pair.second));
    }
    std::sort(effectiveCrossRows.begin(), effectiveCrossRows.end(), [](const CrossViewAggregate& left, const CrossViewAggregate& right)
    {
        if (left.row.processId != right.row.processId)
        {
            return left.row.processId < right.row.processId;
        }
        return left.row.processName < right.row.processName;
    });

    if (tcpTable_ != nullptr)
    {
        tcpTable_->setRowCount(0);
        for (std::size_t cacheIndex = 0; cacheIndex < tcpEndpointCache_.size(); ++cacheIndex)
        {
            const TcpEndpointRow& row = tcpEndpointCache_[cacheIndex];
            if (!processFilterSet_.isEmpty()
                && !processFilterSet_.contains(static_cast<quint32>(row.processId)))
            {
                continue;
            }

            const int kRowIndex = tcpTable_->rowCount();
            tcpTable_->insertRow(kRowIndex);
            QTableWidgetItem* pidItem = createReadOnlyCell(QString::number(row.processId));
            pidItem->setData(Qt::UserRole, static_cast<qulonglong>(cacheIndex));
            tcpTable_->setItem(kRowIndex, 0, pidItem);
            QTableWidgetItem* processItem = createReadOnlyCell(row.processName);
            processItem->setIcon(resolveProcessIcon(row.processId));
            tcpTable_->setItem(kRowIndex, 1, processItem);
            tcpTable_->setItem(kRowIndex, 2, createReadOnlyCell(row.localEndpointText));
            tcpTable_->setItem(kRowIndex, 3, createReadOnlyCell(row.remoteEndpointText));
            tcpTable_->setItem(kRowIndex, 4, createReadOnlyCell(row.stateText));
            tcpTable_->setItem(kRowIndex, 5, createReadOnlyCell(row.detailText));
        }
    }

    if (udpTable_ != nullptr)
    {
        udpTable_->setRowCount(0);
        for (const UdpEndpointRow& row : snapshot.udpEndpointRows)
        {
            if (!processFilterSet_.isEmpty()
                && !processFilterSet_.contains(static_cast<quint32>(row.processId)))
            {
                continue;
            }

            const int kRowIndex = udpTable_->rowCount();
            udpTable_->insertRow(kRowIndex);
            udpTable_->setItem(kRowIndex, 0, createReadOnlyCell(QString::number(row.processId)));
            QTableWidgetItem* processItem = createReadOnlyCell(row.processName);
            processItem->setIcon(resolveProcessIcon(row.processId));
            udpTable_->setItem(kRowIndex, 1, processItem);
            udpTable_->setItem(kRowIndex, 2, createReadOnlyCell(row.localEndpointText));
            udpTable_->setItem(kRowIndex, 3, createReadOnlyCell(row.sourceText));
            udpTable_->setItem(kRowIndex, 4, createReadOnlyCell(row.detailText));
        }
    }

    if (crossSummaryTable_ != nullptr)
    {
        crossSummaryTable_->setRowCount(0);
        for (const CrossViewAggregate& aggregate : effectiveCrossRows)
        {
            const CrossViewRow& row = aggregate.row;
            if (!processFilterSet_.isEmpty()
                && !processFilterSet_.contains(static_cast<quint32>(row.processId)))
            {
                continue;
            }

            const int kRowIndex = crossSummaryTable_->rowCount();
            crossSummaryTable_->insertRow(kRowIndex);
            crossSummaryTable_->setItem(kRowIndex, 0, createReadOnlyCell(QString::number(row.processId)));
            QTableWidgetItem* processItem = createReadOnlyCell(row.processName);
            processItem->setIcon(resolveProcessIcon(row.processId));
            crossSummaryTable_->setItem(kRowIndex, 1, processItem);
            const auto kR0CountText = [](const std::size_t count, const QString& statusText)
            {
                if (statusText == QStringLiteral("ok"))
                {
                    return QString::number(static_cast<qulonglong>(count));
                }
                if (count != 0U)
                {
                    return QStringLiteral("%1:%2")
                        .arg(statusText.isEmpty() ? QStringLiteral("?") : statusText)
                        .arg(static_cast<qulonglong>(count));
                }
                return statusText.isEmpty() ? QStringLiteral("?") : statusText;
            };
            crossSummaryTable_->setItem(kRowIndex, 2, createReadOnlyCell(
                QStringLiteral("R3:%1 / R0:%2")
                .arg(static_cast<qulonglong>(row.tcpCount))
                .arg(kR0CountText(aggregate.tcpR0Count, r0TcpStatusText_))));
            crossSummaryTable_->setItem(kRowIndex, 3, createReadOnlyCell(
                QStringLiteral("R3:%1 / R0:%2")
                .arg(static_cast<qulonglong>(row.udpCount))
                .arg(kR0CountText(aggregate.udpR0Count, r0UdpStatusText_))));
            crossSummaryTable_->setItem(kRowIndex, 4, createReadOnlyCell(
                QStringLiteral("R3 TCP: %1 | R0 TCP: %2 | R3 UDP: %3 | R0 UDP: %4")
                .arg(row.tcpSummary.isEmpty() ? QStringLiteral("<无>") : row.tcpSummary)
                .arg(aggregate.tcpR0Summary.isEmpty() ? QStringLiteral("<无>") : aggregate.tcpR0Summary)
                .arg(row.udpSummary.isEmpty() ? QStringLiteral("<无>") : row.udpSummary)
                .arg(aggregate.udpR0Summary.isEmpty() ? QStringLiteral("<无>") : aggregate.udpR0Summary)));
        }
    }
    applyCrossViewSearchFilter();
    updateCrossViewActionState();
}

void NetworkAuditPage::applyCrossViewSearchFilter()
{
    const QString kFilterText = crossSearchEdit_ != nullptr
        ? crossSearchEdit_->text().trimmed()
        : QString();

    const auto kApplyToTable = [&kFilterText](QTableWidget* tableWidget)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        for (int rowIndex = 0; rowIndex < tableWidget->rowCount(); ++rowIndex)
        {
            bool matched = kFilterText.isEmpty();
            if (!matched)
            {
                for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
                {
                    if (tableWidget->isColumnHidden(columnIndex))
                    {
                        continue;
                    }

                    const QTableWidgetItem* item = tableWidget->item(rowIndex, columnIndex);
                    if (item != nullptr && item->text().contains(kFilterText, Qt::CaseInsensitive))
                    {
                        matched = true;
                        break;
                    }
                }
            }
            tableWidget->setRowHidden(rowIndex, !matched);
        }
    };

    kApplyToTable(tcpTable_);
    kApplyToTable(udpTable_);
    kApplyToTable(crossSummaryTable_);
    updateCrossViewActionState();
}

QIcon NetworkAuditPage::resolveProcessIcon(const std::uint32_t processId)
{
    if (processId == 0U)
    {
        return auditProcessPlaceholderIcon();
    }

    const quint32 kProcessIdKey = static_cast<quint32>(processId);
    const auto kCachedIterator = processIconCache_.constFind(kProcessIdKey);
    if (kCachedIterator != processIconCache_.constEnd())
    {
        return kCachedIterator.value();
    }

    // Table-building chain allows only cache queries: the first screen often contains hundreds of connected processes;
    // individually calling OpenProcess and extracting Shell icons would drag the entire table-building process into seconds.
    scheduleProcessIconResolution(processId);
    return auditProcessPlaceholderIcon();
}

void NetworkAuditPage::scheduleProcessIconResolution(const std::uint32_t processId)
{
    const quint32 kProcessIdKey = static_cast<quint32>(processId);
    if (kProcessIdKey == 0U ||
        processIconCache_.contains(kProcessIdKey) ||
        processIconPendingPidSet_.contains(kProcessIdKey))
    {
        return;
    }
    processIconPendingPidSet_.insert(kProcessIdKey);

    // Reuse the existing 'shared state + owner verification' rollback pattern for this page:
    // When the page is destructed, the owner is already null; the worker thread will not dispatch calls to the destroyed QWidget.
    const std::shared_ptr<NetworkAuditAsyncState> kAsyncState = asyncState_;
    QThreadPool::globalInstance()->start([kAsyncState, kProcessIdKey]()
        {
            QImage processIconImage = extractProcessIconImageForPid(kProcessIdKey);

            std::lock_guard<std::mutex> dispatchLock(kAsyncState->mutex);
            NetworkAuditPage* const kReceiver = kAsyncState->owner;
            if (kReceiver == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                kReceiver,
                [kAsyncState, kProcessIdKey, processIconImage = std::move(processIconImage)]() mutable
                {
                    NetworkAuditPage* page = nullptr;
                    {
                        std::lock_guard<std::mutex> stateLock(kAsyncState->mutex);
                        page = kAsyncState->owner;
                    }
                    if (page == nullptr)
                    {
                        return;
                    }
                    page->applyProcessIconResolutionResult(kProcessIdKey, std::move(processIconImage));
                },
                Qt::QueuedConnection);
        });
}

void NetworkAuditPage::applyProcessIconResolutionResult(
    const std::uint32_t processId,
    QImage iconImage)
{
    const quint32 kProcessIdKey = static_cast<quint32>(processId);
    processIconPendingPidSet_.remove(kProcessIdKey);

    // QPixmap/QIcon must be constructed on the UI thread; even if resolution fails, write to cache to avoid repeated cold lookups for the same PID.
    const QIcon kResolvedIcon = iconImage.isNull()
        ? auditProcessPlaceholderIcon()
        : QIcon(QPixmap::fromImage(iconImage));
    processIconCache_.insert(kProcessIdKey, kResolvedIcon);

    // The PID for all three tables is in column 0, and the process name is in column 1; directly fill back the rows already in the table by text.
    applyResolvedIconToAuditTableRows(tcpTable_, kProcessIdKey, kResolvedIcon);
    applyResolvedIconToAuditTableRows(udpTable_, kProcessIdKey, kResolvedIcon);
    applyResolvedIconToAuditTableRows(crossSummaryTable_, kProcessIdKey, kResolvedIcon);
}

void NetworkAuditPage::updateCrossViewActionState()
{
    bool canTerminateSelection = false;
    if (tcpTable_ != nullptr
        && tcpTable_->currentRow() >= 0
        && !tcpTable_->isRowHidden(tcpTable_->currentRow()))
    {
        const QTableWidgetItem* pidItem = tcpTable_->item(tcpTable_->currentRow(), 0);
        bool cacheIndexOk = false;
        const qulonglong kCacheIndexValue = pidItem != nullptr
            ? pidItem->data(Qt::UserRole).toULongLong(&cacheIndexOk)
            : 0ULL;
        canTerminateSelection =
            cacheIndexOk
            && kCacheIndexValue < tcpEndpointCache_.size()
            && tcpEndpointCache_[static_cast<std::size_t>(kCacheIndexValue)].canTerminate;
    }
    if (crossTerminateButton_ != nullptr)
    {
        crossTerminateButton_->setEnabled(canTerminateSelection);
    }
    if (clearProcessFilterButton_ != nullptr)
    {
        clearProcessFilterButton_->setEnabled(!processFilterSet_.isEmpty());
    }
}

void NetworkAuditPage::terminateSelectedTcpConnection()
{
    if (tcpTable_ == nullptr || tcpTable_->currentRow() < 0)
    {
        QMessageBox::information(this, QStringLiteral("网络审计"), QStringLiteral("请先选中一条 TCP 连接。"));
        return;
    }

    const QTableWidgetItem* pidItem = tcpTable_->item(tcpTable_->currentRow(), 0);
    bool cacheIndexOk = false;
    const qulonglong kCacheIndexValue = pidItem != nullptr
        ? pidItem->data(Qt::UserRole).toULongLong(&cacheIndexOk)
        : 0ULL;
    if (!cacheIndexOk || kCacheIndexValue >= tcpEndpointCache_.size())
    {
        QMessageBox::warning(this, QStringLiteral("网络审计"), QStringLiteral("所选连接已过期，请刷新后重试。"));
        return;
    }

    const TcpEndpointRow kEndpointRow = tcpEndpointCache_[static_cast<std::size_t>(kCacheIndexValue)];
    if (!kEndpointRow.canTerminate)
    {
        QMessageBox::information(
            this,
            QStringLiteral("网络审计"),
            QStringLiteral("该行来自 R0 只读快照；请选中对应的 R3 TCP 行执行终止。"));
        return;
    }

    const std::string kUnsupportedReason =
        ks::network::getTcpTerminationUnsupportedReason(kEndpointRow.connectionRecord);
    if (!kUnsupportedReason.empty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("网络审计"),
            QStringLiteral("当前 TCP 行不能终止：%1")
                .arg(QString::fromUtf8(kUnsupportedReason.c_str())));
        return;
    }

    const int kConfirmation = QMessageBox::question(
        this,
        QStringLiteral("终止 TCP 连接"),
        QStringLiteral("确认终止连接？\nPID=%1\n本地=%2\n远端=%3")
            .arg(kEndpointRow.processId)
            .arg(kEndpointRow.localEndpointText)
            .arg(kEndpointRow.remoteEndpointText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmation != QMessageBox::Yes)
    {
        return;
    }

    std::string detailText;
    const bool kTerminateOk =
        ks::network::terminateTcpConnectionByRecord(kEndpointRow.connectionRecord, &detailText);
    if (kTerminateOk)
    {
        QMessageBox::information(this, QStringLiteral("网络审计"), QStringLiteral("连接终止请求已提交。"));
        refreshAllSnapshotsAsync(true);
        return;
    }

    const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
        this,
        QStringLiteral("终止 TCP 连接"),
        QString::fromUtf8(detailText.c_str()));
    if (!kPrivilegePromptHandled)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("网络审计"),
            QStringLiteral("终止连接失败：%1").arg(QString::fromUtf8(detailText.c_str())));
    }
}

void NetworkAuditPage::showCrossViewContextMenu(
    QTableWidget* tableWidget,
    const QPoint& localPosition)
{
    if (tableWidget == nullptr)
    {
        return;
    }

    const QModelIndex kClickedIndex = tableWidget->indexAt(localPosition);
    if (kClickedIndex.isValid())
    {
        tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
        tableWidget->selectRow(kClickedIndex.row());
    }

    const int kSelectedRow = tableWidget->currentRow();
    bool processIdOk = false;
    const QTableWidgetItem* processIdItem =
        kSelectedRow >= 0 ? tableWidget->item(kSelectedRow, 0) : nullptr;
    const quint32 kSelectedProcessId = processIdItem != nullptr
        ? processIdItem->text().toUInt(&processIdOk)
        : 0U;
    const bool kHasProcess = processIdOk && kSelectedProcessId != 0U;

    bool canTerminateSelection = false;
    if (tableWidget == tcpTable_ && processIdItem != nullptr)
    {
        bool cacheIndexOk = false;
        const qulonglong kCacheIndexValue =
            processIdItem->data(Qt::UserRole).toULongLong(&cacheIndexOk);
        canTerminateSelection =
            cacheIndexOk
            && kCacheIndexValue < tcpEndpointCache_.size()
            && tcpEndpointCache_[static_cast<std::size_t>(kCacheIndexValue)].canTerminate;
    }

    QMenu menu(tableWidget);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* terminateAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        QStringLiteral("终止此 TCP 连接"));
    terminateAction->setVisible(tableWidget == tcpTable_);
    terminateAction->setEnabled(canTerminateSelection);
    QAction* copyAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制行"));
    copyAction->setEnabled(kSelectedRow >= 0);
    QAction* trackProcessAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_track.svg")),
        QStringLiteral("跟踪此进程"));
    trackProcessAction->setEnabled(kHasProcess && static_cast<bool>(trackProcessHandler_));
    QAction* openProcessDetailAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("转到进程详细信息"));
    openProcessDetailAction->setEnabled(
        kHasProcess && static_cast<bool>(openProcessDetailHandler_));
    const QTableWidgetItem* localEndpointItem = kSelectedRow >= 0
        ? tableWidget->item(kSelectedRow, 2)
        : nullptr;
    const bool kCanPrefillUdpBlockRule =
        tableWidget == udpTable_ &&
        localEndpointItem != nullptr &&
        !localEndpointItem->text().trimmed().isEmpty() &&
        static_cast<bool>(udpEndpointBlockRuleHandler_);
    QAction* addUdpBlockRuleAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        QStringLiteral("预填 UDP 阻断规则"));
    addUdpBlockRuleAction->setVisible(tableWidget == udpTable_);
    addUdpBlockRuleAction->setEnabled(kCanPrefillUdpBlockRule);
    const bool kIsTcpTable = tableWidget == tcpTable_;
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [kIsTcpTable, kSelectedProcessId, kHasProcess]() -> ks::online_scan::SandboxUploadTarget
        {
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (!kHasProcess)
            {
                uploadTarget.errorText = kIsTcpTable
                    ? QStringLiteral("当前 TCP 行没有可解析 PID。")
                    : QStringLiteral("当前 UDP 行没有可解析 PID。");
                return uploadTarget;
            }
            uploadTarget.filePath = QString::fromStdString(
                ks::process::queryProcessPathByPid(kSelectedProcessId));
            uploadTarget.sourceText = kIsTcpTable
                ? QStringLiteral("网络 TCP 连接 PID=%1").arg(kSelectedProcessId)
                : QStringLiteral("网络 UDP 端点 PID=%1").arg(kSelectedProcessId);
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(kHasProcess);
    }
    menu.addSeparator();
    QAction* refreshAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        QStringLiteral("刷新 TCP/UDP"));
    QAction* clearFilterAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")),
        QStringLiteral("清除 PID 筛选"));
    clearFilterAction->setEnabled(!processFilterSet_.isEmpty());

    const QAction* selectedAction = menu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
    if (selectedAction == terminateAction)
    {
        terminateSelectedTcpConnection();
    }
    else if (selectedAction == copyAction)
    {
        copyCurrentTableRow(tableWidget);
    }
    else if (selectedAction == trackProcessAction)
    {
        trackProcessHandler_(kSelectedProcessId);
    }
    else if (selectedAction == openProcessDetailAction)
    {
        openProcessDetailHandler_(kSelectedProcessId);
    }
    else if (selectedAction == addUdpBlockRuleAction && kCanPrefillUdpBlockRule)
    {
        udpEndpointBlockRuleHandler_(kSelectedProcessId, localEndpointItem->text());
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == refreshAction)
    {
        refreshAllSnapshotsAsync(true);
    }
    else if (selectedAction == clearFilterAction)
    {
        focusProcessIds({});
    }
}

void NetworkAuditPage::refreshAfdTable(const std::vector<AfdHandleRow>& snapshot)
{
    if (afdTable_ == nullptr)
    {
        return;
    }
    afdTable_->setRowCount(static_cast<int>(snapshot.size()));
    int rowIndex = 0;
    for (const AfdHandleRow& row : snapshot)
    {
        afdTable_->setItem(rowIndex, 0, createReadOnlyCell(QString::number(row.processId)));
        afdTable_->setItem(rowIndex, 1, createReadOnlyCell(row.processName));
        afdTable_->setItem(rowIndex, 2, createReadOnlyCell(row.handleValueText));
        afdTable_->setItem(rowIndex, 3, createReadOnlyCell(row.typeName));
        afdTable_->setItem(rowIndex, 4, createReadOnlyCell(row.objectName));
        afdTable_->setItem(rowIndex, 5, createReadOnlyCell(row.sourceText));
        afdTable_->setItem(rowIndex, 6, createReadOnlyCell(row.diffText));
        afdTable_->setItem(rowIndex, 7, createReadOnlyCell(row.detailText + QStringLiteral(" | access=") + row.accessText));
        ++rowIndex;
    }
}

void NetworkAuditPage::refreshWfpTables(const AuditSnapshot& snapshot)
{
    auto fillTable = [](QTableWidget* tableWidget, const auto& rows, const auto& writer)
    {
        if (tableWidget == nullptr)
        {
            return;
        }
        tableWidget->setRowCount(static_cast<int>(rows.size()));
        int rowIndex = 0;
        for (const auto& row : rows)
        {
            writer(tableWidget, rowIndex, row);
            ++rowIndex;
        }
    };

    fillTable(wfpProviderTable_, snapshot.wfpProviderRows, [](QTableWidget* tableWidget, int rowIndex, const WfpProviderRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.guidText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.flagsText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.serviceNameText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.dataSizeText));
    });

    fillTable(wfpSubLayerTable_, snapshot.wfpSubLayerRows, [](QTableWidget* tableWidget, int rowIndex, const WfpSubLayerRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.guidText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.flagsText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.providerGuidText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.weightText));
    });

    fillTable(wfpCalloutTable_, snapshot.wfpCalloutRows, [](QTableWidget* tableWidget, int rowIndex, const WfpCalloutRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.guidText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.flagsText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.providerGuidText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.layerGuidText));
        tableWidget->setItem(rowIndex, 6, createReadOnlyCell(row.calloutIdText));
    });

    fillTable(wfpFilterTable_, snapshot.wfpFilterRows, [](QTableWidget* tableWidget, int rowIndex, const WfpFilterRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.guidText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.flagsText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.providerGuidText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.layerGuidText));
        tableWidget->setItem(rowIndex, 6, createReadOnlyCell(row.subLayerGuidText));
        tableWidget->setItem(rowIndex, 7, createReadOnlyCell(row.weightText));
        tableWidget->setItem(rowIndex, 8, createReadOnlyCell(row.actionText));
        tableWidget->setItem(rowIndex, 9, createReadOnlyCell(row.conditionText));
        tableWidget->setItem(rowIndex, 10, createReadOnlyCell(row.filterIdText));
    });
}

void NetworkAuditPage::refreshNdisTables(const AuditSnapshot& snapshot)
{
    auto fillTable = [](QTableWidget* tableWidget, const auto& rows, const auto& writer)
    {
        if (tableWidget == nullptr)
        {
            return;
        }
        tableWidget->setRowCount(static_cast<int>(rows.size()));
        int rowIndex = 0;
        for (const auto& row : rows)
        {
            writer(tableWidget, rowIndex, row);
            ++rowIndex;
        }
    };

    fillTable(ndisAdapterTable_, snapshot.ndisAdapterRows, [](QTableWidget* tableWidget, int rowIndex, const NdisAdapterRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.descriptionText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.ifIndexText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.statusText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.macText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.linkSpeedText));
        tableWidget->setItem(rowIndex, 6, createReadOnlyCell(row.connectionStateText));
    });

    fillTable(ndisBindingTable_, snapshot.ndisBindingRows, [](QTableWidget* tableWidget, int rowIndex, const NdisBindingRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.adapterNameText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.displayNameText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.componentIdText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.enabledText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.instanceIdText));
    });

    fillTable(ndisProtocolTable_, snapshot.ndisProtocolRows, [](QTableWidget* tableWidget, int rowIndex, const NdisProtocolRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.interfaceAliasText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.ifIndexText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.addressFamilyText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.connectionStateText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.interfaceMetricText));
        tableWidget->setItem(rowIndex, 5, createReadOnlyCell(row.mtuText));
    });

    fillTable(ndisUnknownTable_, snapshot.ndisUnknownRows, [](QTableWidget* tableWidget, int rowIndex, const NdisUnknownRow& row)
    {
        tableWidget->setItem(rowIndex, 0, createReadOnlyCell(row.kindText));
        tableWidget->setItem(rowIndex, 1, createReadOnlyCell(row.componentText));
        tableWidget->setItem(rowIndex, 2, createReadOnlyCell(row.ownerModuleText));
        tableWidget->setItem(rowIndex, 3, createReadOnlyCell(row.objectAddressText));
        tableWidget->setItem(rowIndex, 4, createReadOnlyCell(row.detailText));
    });
}

void NetworkAuditPage::refreshNsiSummaryTable(const AuditSnapshot& snapshot)
{
    if (nsiSummaryTable_ == nullptr)
    {
        return;
    }
    const int kR3RowCount = static_cast<int>(snapshot.nsiSummaryRows.size());
    const int kR0RowCount = static_cast<int>(snapshot.r0SummaryRows.size());
    nsiSummaryTable_->setRowCount(kR3RowCount + kR0RowCount);
    int rowIndex = 0;
    for (const NsiSummaryRow& row : snapshot.nsiSummaryRows)
    {
        nsiSummaryTable_->setItem(rowIndex, 0, createReadOnlyCell(row.metricText));
        nsiSummaryTable_->setItem(rowIndex, 1, createReadOnlyCell(row.valueText));
        nsiSummaryTable_->setItem(rowIndex, 2, createReadOnlyCell(QStringLiteral("-")));
        nsiSummaryTable_->setItem(rowIndex, 3, createReadOnlyCell(QStringLiteral("-")));
        nsiSummaryTable_->setItem(rowIndex, 4, createReadOnlyCell(QStringLiteral("R3 summary")));
        ++rowIndex;
    }
    for (const R0NetworkSummaryRow& row : snapshot.r0SummaryRows)
    {
        nsiSummaryTable_->setItem(rowIndex, 0, createReadOnlyCell(row.nameText));
        nsiSummaryTable_->setItem(rowIndex, 1, createReadOnlyCell(row.statusText));
        nsiSummaryTable_->setItem(rowIndex, 2, createReadOnlyCell(row.countText));
        nsiSummaryTable_->setItem(rowIndex, 3, createReadOnlyCell(row.truncatedText));
        nsiSummaryTable_->setItem(rowIndex, 4, createReadOnlyCell(row.messageText));
        ++rowIndex;
    }
}

QString NetworkAuditPage::runPowerShellTextSync(const QString& scriptText, const int timeoutMs, QString* errorTextOut)
{
    QProcess process;
    process.setProgram(QStringLiteral("powershell.exe"));
    process.setArguments({
        QStringLiteral("-NoProfile"),
        QStringLiteral("-ExecutionPolicy"),
        QStringLiteral("Bypass"),
        QStringLiteral("-Command"),
        scriptText
    });
    process.start();

    if (!process.waitForStarted(2000))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("PowerShell 启动失败：%1").arg(process.errorString());
        }
        return QString();
    }

    if (!process.waitForFinished(timeoutMs))
    {
        process.kill();
        process.waitForFinished(500);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("PowerShell 执行超时：%1 ms").arg(timeoutMs);
        }
        return QString();
    }

    const QString kStdoutText = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
    const QString kStderrText = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("PowerShell 退出异常：%1 / %2").arg(process.exitCode()).arg(kStderrText);
        }
        return kStdoutText;
    }
    return kStdoutText;
}

QTableWidgetItem* NetworkAuditPage::createCell(const QString& cellText)
{
    return createReadOnlyCell(cellText);
}

QString NetworkAuditPage::guidToText(const GUID& guid)
{
    return QStringLiteral("{%1-%2-%3-%4%5%6%7%8%9%10%11}")
        .arg(guid.Data1, 8, 16, QLatin1Char('0'))
        .arg(guid.Data2, 4, 16, QLatin1Char('0'))
        .arg(guid.Data3, 4, 16, QLatin1Char('0'))
        .arg(guid.Data4[0], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[1], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[2], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[3], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[4], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[5], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[6], 2, 16, QLatin1Char('0'))
        .arg(guid.Data4[7], 2, 16, QLatin1Char('0'));
}

QString NetworkAuditPage::bytesToHexText(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(QString::number(value, 16));
}

QString NetworkAuditPage::objectToText(const QJsonValue& value)
{
    if (value.isString())
    {
        return value.toString();
    }
    if (value.isBool())
    {
        return value.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    }
    if (value.isDouble())
    {
        return QString::number(value.toDouble());
    }
    if (value.isArray() || value.isObject())
    {
        if (value.isObject())
        {
            return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
        }
        return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact));
    }
    return QString();
}

bool NetworkAuditPage::compareContainsAfd(const QString& objectNameText)
{
    const QString kLowered = objectNameText.toLower();
    return kLowered.contains(QStringLiteral("\\device\\afd")) || kLowered.contains(QStringLiteral("\\device\\winsock"));
}
