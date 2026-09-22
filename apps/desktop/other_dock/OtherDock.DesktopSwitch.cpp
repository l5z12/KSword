#include "OtherDock.h"
#include "../Theme.h"

// ============================================================
// OtherDock.DesktopSwitch.cpp
// Purpose:
// 1) Independently hosts the SwitchDesktop logic and right-click menu in the Desktop Management page;
// 2) Separates from the enumeration logic to control single-file size and maintain the "split files by Tab" organization style;
// 3) Attempt to OpenDesktopW for desktops not belonging to the current window station (using direct name or window station name) to improve reachability.
// ============================================================

#include <QApplication>
#include <QClipboard>
#include <QIcon>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <vector>

namespace
{
    // Desktop management table column indices:
    // - Keep consistent with OtherDock.Desktop.cpp.
    // - Right-click menu and switching logic depend on four column types: Window Station, Desktop, SID, and SID details.
    constexpr int kDesktopColumnWindowStation = 0;
    constexpr int kDesktopColumnDesktopName = 1;
    constexpr int kDesktopColumnSid = 9;
    constexpr int kDesktopColumnSidDetail = 10;

    // data role：
    // - Reuse window station name, desktop name, and SID metadata attached to table items.
    // - refreshDesktopList is responsible for writing this metadata into each cell.
    constexpr int kDesktopRoleWindowStationName = Qt::UserRole;
    constexpr int kDesktopRoleDesktopName = Qt::UserRole + 1;
    constexpr int kDesktopRoleOwnerSidText = Qt::UserRole + 3;
    constexpr int kDesktopRoleOwnerSidDetailText = Qt::UserRole + 4;

    // DesktopOpenResult：
    // - Purpose: Describes the result of the OpenDesktopW attempt;
    // - Invocation: Reused by switchToSelectedDesktop to avoid duplicating two rounds of attempt code.
    struct DesktopOpenResult
    {
        HDESK desktopHandle = nullptr; // desktopHandle: Desktop handle returned upon successful opening.
        QString methodText;            // methodText: Description of the method that opened successfully.
        QString detailText;            // detailText: Failure chain or supplementary explanation.
    };

    // tryOpenDesktopForSwitch：
    // - Purpose: Attempts to open the desktop using both the 'desktop name' and 'window station\desktop name' formats.
    // - Call: executed before desktop switch.
    // - Pass switchAccessMask: permissions required for this switch.
    // - Output: returns the desktop handle on success; returns the full error chain on failure.
    DesktopOpenResult tryOpenDesktopForSwitch(
        const QString& windowStationName,
        const QString& desktopName,
        const ACCESS_MASK switchAccessMask)
    {
        DesktopOpenResult openResult;
        QStringList detailTextList;

        auto tryOpenOnce = [&openResult, &detailTextList, switchAccessMask](const QString& candidateName, const QString& tag) -> bool {
            if (candidateName.trimmed().isEmpty())
            {
                return false;
            }
            HDESK desktopHandle = ::OpenDesktopW(
                reinterpret_cast<LPCWSTR>(candidateName.utf16()),
                0,
                FALSE,
                switchAccessMask);
            if (desktopHandle != nullptr)
            {
                openResult.desktopHandle = desktopHandle;
                openResult.methodText = tag;
                openResult.detailText = QStringLiteral("OpenDesktopW 成功");
                return true;
            }
            detailTextList << QStringLiteral("%1=错误码%2").arg(tag).arg(::GetLastError());
            return false;
        };

        if (tryOpenOnce(desktopName, QStringLiteral("直接名")))
        {
            return openResult;
        }

        const QString kQualifiedDesktopName = windowStationName.trimmed().isEmpty()
            ? QString()
            : QStringLiteral("%1\\%2").arg(windowStationName, desktopName);
        if (kQualifiedDesktopName.compare(desktopName, Qt::CaseInsensitive) != 0
            && tryOpenOnce(kQualifiedDesktopName, QStringLiteral("带窗口站名")))
        {
            return openResult;
        }

        openResult.detailText = detailTextList.join(QStringLiteral("；"));
        return openResult;
    }

    // findRetainedDesktopHandle：
    // - Purpose: Search for the target desktop in the list of retained desktop handles created by OtherDock;
    // - Fallback path for switching to a private DACL desktop if OpenDesktopW fails.
    // - Returns: HDESK on match; nullptr if not found.
    HDESK findRetainedDesktopHandle(
        const std::vector<OtherDock::CreatedDesktopRecord>& desktopRecords,
        const QString& windowStationName,
        const QString& desktopName)
    {
        for (const OtherDock::CreatedDesktopRecord& record : desktopRecords)
        {
            if (record.desktopHandle == nullptr)
            {
                continue;
            }
            const bool kStationMatched = record.windowStationName.isEmpty()
                || windowStationName.isEmpty()
                || QString::compare(record.windowStationName, windowStationName, Qt::CaseInsensitive) == 0;
            const bool kDesktopMatched = QString::compare(record.desktopName, desktopName, Qt::CaseInsensitive) == 0;
            const bool kSwitchAccessPresent = (record.desiredAccess & DESKTOP_SWITCHDESKTOP) != 0;
            if (kStationMatched && kDesktopMatched && kSwitchAccessPresent)
            {
                return reinterpret_cast<HDESK>(record.desktopHandle);
            }
        }
        return nullptr;
    }
}

void OtherDock::switchToSelectedDesktop()
{
    // actionEvent: The entire 'read selected row -> OpenDesktopW -> SwitchDesktop' flow shares a single log event.
    KLogEvent actionEvent;

    if (desktopTable_ == nullptr || desktopStatusLabel_ == nullptr || desktopTable_->currentRow() < 0)
    {
        warn << actionEvent
            << "[OtherDock] 切换桌面失败：未选中目标桌面。"
            << eol;
        if (desktopStatusLabel_ != nullptr)
        {
            desktopStatusLabel_->setText(QStringLiteral("请先选择要切换的桌面。"));
        }
        return;
    }

    // row/windowStationItem/desktopItem: Retrieves the window station name and desktop name required for switching from the current row.
    const int kRow = desktopTable_->currentRow();
    QTableWidgetItem* windowStationItem = desktopTable_->item(kRow, kDesktopColumnWindowStation);
    QTableWidgetItem* desktopItem = desktopTable_->item(kRow, kDesktopColumnDesktopName);
    if (windowStationItem == nullptr || desktopItem == nullptr)
    {
        err << actionEvent
            << "[OtherDock] 切换桌面失败：目标行缺少窗口站或桌面列。"
            << eol;
        desktopStatusLabel_->setText(QStringLiteral("切换失败：选中行缺少窗口站或桌面信息。"));
        return;
    }

    // windowStationName/desktopName: row metadata written during the refresh phase.
    const QString kWindowStationName = windowStationItem->data(kDesktopRoleWindowStationName).toString().trimmed();
    const QString kDesktopName = desktopItem->data(kDesktopRoleDesktopName).toString().trimmed();
    if (kWindowStationName.isEmpty() || kDesktopName.isEmpty())
    {
        err << actionEvent
            << "[OtherDock] 切换桌面失败：窗口站名或桌面名为空。"
            << eol;
        desktopStatusLabel_->setText(QStringLiteral("切换失败：窗口站名或桌面名为空。"));
        return;
    }

    if (kDesktopName.startsWith('<') && kDesktopName.endsWith('>'))
    {
        warn << actionEvent
            << "[OtherDock] 切换桌面失败：选中行不是可切换的真实桌面, station="
            << kWindowStationName.toStdString()
            << ", desktop="
            << kDesktopName.toStdString()
            << eol;
        desktopStatusLabel_->setText(QStringLiteral("切换失败：当前行是状态占位项，不是真实桌面。"));
        return;
    }

    info << actionEvent
        << "[OtherDock] 开始切换桌面, station="
        << kWindowStationName.toStdString()
        << ", desktop="
        << kDesktopName.toStdString()
        << eol;

    // openResult: Perform two OpenDesktopW attempts regardless of whether the current window station is active.
    const DesktopOpenResult kOpenResult = tryOpenDesktopForSwitch(
        kWindowStationName,
        kDesktopName,
        DESKTOP_SWITCHDESKTOP | DESKTOP_READOBJECTS);
    if (kOpenResult.desktopHandle == nullptr)
    {
        err << actionEvent
            << "[OtherDock] 切换桌面失败：OpenDesktopW失败, station="
            << kWindowStationName.toStdString()
            << ", desktop="
            << kDesktopName.toStdString()
            << ", detail="
            << kOpenResult.detailText.toStdString()
            << eol;
        HDESK retainedDesktopHandle = findRetainedDesktopHandle(
            createdDesktopHandles_,
            kWindowStationName,
            kDesktopName);
        if (retainedDesktopHandle == nullptr)
        {
            desktopStatusLabel_->setText(
                QStringLiteral("切换失败：OpenDesktopW 详情=%1").arg(kOpenResult.detailText));
            return;
        }

        const BOOL kRetainedSwitchOk = ::SwitchDesktop(retainedDesktopHandle);
        const DWORD kRetainedSwitchErrorCode = kRetainedSwitchOk ? ERROR_SUCCESS : ::GetLastError();
        if (kRetainedSwitchOk == FALSE)
        {
            err << actionEvent
                << "[OtherDock] 切换桌面失败：保留句柄 SwitchDesktop 失败, station="
                << kWindowStationName.toStdString()
                << ", desktop="
                << kDesktopName.toStdString()
                << ", code="
                << kRetainedSwitchErrorCode
                << eol;
            desktopStatusLabel_->setText(
                QStringLiteral("切换失败：OpenDesktopW 失败且保留句柄 SwitchDesktop 错误码=%1")
                .arg(kRetainedSwitchErrorCode));
            return;
        }

        info << actionEvent
            << "[OtherDock] 切换桌面成功（保留句柄）, station="
            << kWindowStationName.toStdString()
            << ", desktop="
            << kDesktopName.toStdString()
            << eol;
        desktopStatusLabel_->setText(
            QStringLiteral("切换成功：%1\\%2（方式=本进程保留句柄）")
            .arg(kWindowStationName, kDesktopName));
        refreshDesktopList();
        return;
    }

    const BOOL kSwitchOk = ::SwitchDesktop(kOpenResult.desktopHandle);
    const DWORD kSwitchErrorCode = kSwitchOk ? ERROR_SUCCESS : ::GetLastError();
    ::CloseDesktop(kOpenResult.desktopHandle);

    if (kSwitchOk == FALSE)
    {
        err << actionEvent
            << "[OtherDock] 切换桌面失败：SwitchDesktop失败, station="
            << kWindowStationName.toStdString()
            << ", desktop="
            << kDesktopName.toStdString()
            << ", openMethod="
            << kOpenResult.methodText.toStdString()
            << ", code="
            << kSwitchErrorCode
            << eol;
        desktopStatusLabel_->setText(QStringLiteral("切换失败：SwitchDesktop 错误码=%1").arg(kSwitchErrorCode));
        return;
    }

    info << actionEvent
        << "[OtherDock] 切换桌面成功, station="
        << kWindowStationName.toStdString()
        << ", desktop="
        << kDesktopName.toStdString()
        << ", openMethod="
        << kOpenResult.methodText.toStdString()
        << eol;
    desktopStatusLabel_->setText(
        QStringLiteral("切换成功：%1\\%2（方式=%3）")
        .arg(kWindowStationName, kDesktopName, kOpenResult.methodText));
    refreshDesktopList();
}

void OtherDock::showDesktopContextMenu(const QPoint& localPos)
{
    // Desktop table context menu: provides 'Go to Desktop', 'View SID Details', 'Copy SID', 'Copy Full Desktop Name', and 'Refresh'.
    if (desktopTable_ == nullptr)
    {
        return;
    }

    const QModelIndex kIndexAtPos = desktopTable_->indexAt(localPos);
    if (!kIndexAtPos.isValid())
    {
        return;
    }

    const int kRow = kIndexAtPos.row();
    desktopTable_->selectRow(kRow);

    // stationItem/desktopItem/sidItem/sidDetailItem: Collect data required for subsequent actions in the right-click menu.
    QTableWidgetItem* stationItem = desktopTable_->item(kRow, kDesktopColumnWindowStation);
    QTableWidgetItem* desktopItem = desktopTable_->item(kRow, kDesktopColumnDesktopName);
    QTableWidgetItem* sidItem = desktopTable_->item(kRow, kDesktopColumnSid);
    QTableWidgetItem* sidDetailItem = desktopTable_->item(kRow, kDesktopColumnSidDetail);
    if (stationItem == nullptr || desktopItem == nullptr)
    {
        return;
    }

    const QString kWindowStationName = stationItem->data(kDesktopRoleWindowStationName).toString().trimmed();
    const QString kDesktopName = desktopItem->data(kDesktopRoleDesktopName).toString().trimmed();
    const QString kSidText = sidItem != nullptr
        ? sidItem->data(kDesktopRoleOwnerSidText).toString().trimmed()
        : QString();
    const QString kSidDetailText = sidDetailItem != nullptr
        ? sidDetailItem->data(kDesktopRoleOwnerSidDetailText).toString().trimmed()
        : QString();
    const QString kQualifiedDesktopName = QStringLiteral("%1\\%2").arg(kWindowStationName, kDesktopName);

    QMenu menu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* goDesktopAction = menu.addAction(QIcon(":/Icon/desktop_switch.svg"), QStringLiteral("转到桌面"));
    QAction* createDesktopAction = menu.addAction(QIcon(":/Icon/desktop_create.svg"), QStringLiteral("新建桌面"));
    QAction* sidDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看SID详情"));
    QAction* copySidAction = menu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("复制SID"));
    QAction* copyDesktopAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("复制完整桌面名"));
    menu.addSeparator();
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新桌面列表"));

    const bool kIsPlaceholderDesktop = kDesktopName.startsWith('<') && kDesktopName.endsWith('>');
    goDesktopAction->setEnabled(!kIsPlaceholderDesktop);
    sidDetailAction->setEnabled(!kSidDetailText.trimmed().isEmpty());
    copySidAction->setEnabled(!kSidText.trimmed().isEmpty());

    QAction* selectedAction = menu.exec(desktopTable_->viewport()->mapToGlobal(localPos));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == goDesktopAction)
    {
        switchToSelectedDesktop();
        return;
    }

    if (selectedAction == createDesktopAction)
    {
        showCreateDesktopDialog();
        return;
    }

    if (selectedAction == sidDetailAction)
    {
        QMessageBox::information(
            this,
            QStringLiteral("SID详情"),
            QStringLiteral("对象：%1\nSID：%2\n\n%3")
                .arg(kQualifiedDesktopName, kSidText.isEmpty() ? QStringLiteral("<空>") : kSidText, kSidDetailText));
        return;
    }

    if (selectedAction == copySidAction)
    {
        QApplication::clipboard()->setText(kSidText);
        if (desktopStatusLabel_ != nullptr)
        {
            desktopStatusLabel_->setText(QStringLiteral("已复制 SID：%1").arg(kSidText));
        }
        return;
    }

    if (selectedAction == copyDesktopAction)
    {
        QApplication::clipboard()->setText(kQualifiedDesktopName);
        if (desktopStatusLabel_ != nullptr)
        {
            desktopStatusLabel_->setText(QStringLiteral("已复制桌面名：%1").arg(kQualifiedDesktopName));
        }
        return;
    }

    if (selectedAction == refreshAction)
    {
        refreshDesktopList();
    }
}
