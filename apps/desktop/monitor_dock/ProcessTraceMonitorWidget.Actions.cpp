#include "ProcessTraceMonitorWidget.h"
#include "../Theme.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/ThemeStatusRole.h"

// ============================================================
// ProcessTraceMonitorWidget.Actions.cpp
// Purpose:
// 1) Implement process target selection, event filtering, export, and right-click menu.
// 2) Consolidate all UI interactions into a separate file to avoid coupling with ETW collection logic;
// 3) Unifies table and status text updates on the main thread to ensure UI stability.
// ============================================================

#include <QApplication>
#include <QAbstractItemModel>
#include <QBrush>
#include <QCheckBox>
#include <QColor>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <set>
#include <tuple>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // Event row cache roles:
    // - Purpose: Cache frequently used concatenated filter text in the first column item to reduce repeated string concatenation per filter round;
    // - Invocation: Written by appendEventRow, read by applyEventFilter.
    constexpr int kEventRoleGlobalSearchText = Qt::UserRole;
    constexpr int kEventRoleProcessSearchText = Qt::UserRole + 1;
    constexpr int kEventRoleEventSearchText = Qt::UserRole + 2;
    constexpr int kEventRoleTime100nsValue = Qt::UserRole + 3;

    // tableRowAsTsv：
    // - Purpose: Convert a single row from any read-only table to TSV text;
    // - Input tableWidget/rowIndex: Target table and row index;
    // - Return: Empty string if the row index is invalid; otherwise, returns the text of the currently visible columns.
    QString tableRowAsTsv(const QTableWidget* tableWidget, const int rowIndex)
    {
        if (tableWidget == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
        {
            return QString();
        }

        QStringList cellTextList;
        cellTextList.reserve(tableWidget->columnCount());
        for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* itemPointer = tableWidget->item(rowIndex, columnIndex);
            cellTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }
        return cellTextList.join('\t');
    }

    // selectedTableRows：
    // - Purpose: Extract unique row numbers from the currently selected rows in QTableWidget;
    // - Input tableWidget: Target table.
    // - Returns: A list of row numbers in ascending order, used for copying multiple rows or determining menu enablement state.
    std::vector<int> selectedTableRows(const QTableWidget* tableWidget)
    {
        std::vector<int> rowList;
        if (tableWidget == nullptr)
        {
            return rowList;
        }

        std::set<int> rowSet;
        const QList<QTableWidgetItem*> kItemList = tableWidget->selectedItems();
        for (const QTableWidgetItem* itemPointer : kItemList)
        {
            if (itemPointer != nullptr)
            {
                rowSet.insert(itemPointer->row());
            }
        }

        rowList.assign(rowSet.begin(), rowSet.end());
        return rowList;
    }

    // copyTableRowsToClipboard：
    // - Purpose: Copy several table rows to the system clipboard.
    // - Parameters tableWidget/rowList: Target table and rows to be copied.
    // - Return: None. If the list is empty, the clipboard remains unchanged to avoid accidentally clearing user content.
    void copyTableRowsToClipboard(const QTableWidget* tableWidget, const std::vector<int>& rowList)
    {
        if (tableWidget == nullptr || rowList.empty())
        {
            return;
        }

        QStringList lineList;
        for (const int kRowIndex : rowList)
        {
            const QString kRowText = tableRowAsTsv(tableWidget, kRowIndex);
            if (!kRowText.isEmpty())
            {
                lineList << kRowText;
            }
        }

        if (!lineList.isEmpty())
        {
            QApplication::clipboard()->setText(lineList.join('\n'));
        }
    }

    // queryLightweightProcessPath：
    // - Purpose: Query process paths only for those displayed on the current page.
    // - Unlike full static details, this does not read high-cost fields such as command line or signature.
    QString queryLightweightProcessPath(const HANDLE processHandle)
    {
        std::vector<wchar_t> pathBuffer(32768, L'\0');
        DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
        if (::QueryFullProcessImageNameW(processHandle, 0, pathBuffer.data(), &pathLength) == FALSE
            || pathLength == 0)
        {
            return QString();
        }

        return QString::fromWCharArray(pathBuffer.data(), static_cast<int>(pathLength));
    }

    // queryLightweightProcessUser：
    // - Purpose: Read the process's owning user with minimal privileges;
    // - Used solely for display in the monitoring page table; no additional token analysis is performed.
    QString queryLightweightProcessUser(const HANDLE processHandle)
    {
        HANDLE processToken = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &processToken) == FALSE)
        {
            return QString();
        }

        DWORD requiredLength = 0;
        ::GetTokenInformation(processToken, TokenUser, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            ::CloseHandle(processToken);
            return QString();
        }

        std::vector<BYTE> tokenBuffer(requiredLength, 0);
        if (::GetTokenInformation(
            processToken,
            TokenUser,
            tokenBuffer.data(),
            requiredLength,
            &requiredLength) == FALSE)
        {
            ::CloseHandle(processToken);
            return QString();
        }
        ::CloseHandle(processToken);

        const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.data());
        if (tokenUser == nullptr || tokenUser->User.Sid == nullptr)
        {
            return QString();
        }

        DWORD nameLength = 0;
        DWORD domainLength = 0;
        SID_NAME_USE sidType = SidTypeUnknown;
        ::LookupAccountSidW(nullptr, tokenUser->User.Sid, nullptr, &nameLength, nullptr, &domainLength, &sidType);
        if (nameLength == 0)
        {
            return QString();
        }

        std::vector<wchar_t> nameBuffer(nameLength, L'\0');
        std::vector<wchar_t> domainBuffer(domainLength > 0 ? domainLength : 1, L'\0');
        if (::LookupAccountSidW(
            nullptr,
            tokenUser->User.Sid,
            nameBuffer.data(),
            &nameLength,
            domainBuffer.data(),
            &domainLength,
            &sidType) == FALSE)
        {
            return QString();
        }

        const QString kAccountName = QString::fromWCharArray(nameBuffer.data());
        const QString kDomainName = domainLength > 0
            ? QString::fromWCharArray(domainBuffer.data())
            : QString();
        if (kAccountName.isEmpty())
        {
            return QString();
        }

        return kDomainName.isEmpty()
            ? kAccountName
            : QStringLiteral("%1\\%2").arg(kDomainName, kAccountName);
    }

    // fillLightweightMonitorProcessRecord：
    // - Purpose: Populate lightweight fields required for the monitoring page.
    // - Populate only path, user, creation time, and name; do not trigger full static detail queries.
    bool fillLightweightMonitorProcessRecord(ks::process::ProcessRecord* recordPointer)
    {
        if (recordPointer == nullptr || recordPointer->pid == 0)
        {
            return false;
        }

        if (!recordPointer->imagePath.empty()
            && !recordPointer->userName.empty()
            && recordPointer->creationTime100ns != 0)
        {
            return true;
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(recordPointer->pid));
        if (processHandle == nullptr)
        {
            return false;
        }

        if (recordPointer->imagePath.empty())
        {
            recordPointer->imagePath = queryLightweightProcessPath(processHandle).toUtf8().toStdString();
        }
        if (recordPointer->userName.empty())
        {
            recordPointer->userName = queryLightweightProcessUser(processHandle).toUtf8().toStdString();
        }
        if (recordPointer->creationTime100ns == 0)
        {
            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                ULARGE_INTEGER creationTimeValue{};
                creationTimeValue.LowPart = creationTime.dwLowDateTime;
                creationTimeValue.HighPart = creationTime.dwHighDateTime;
                recordPointer->creationTime100ns = static_cast<std::uint64_t>(creationTimeValue.QuadPart);
            }
        }
        ::CloseHandle(processHandle);

        if (recordPointer->processName.empty() && !recordPointer->imagePath.empty())
        {
            const QString kPathText = QString::fromUtf8(recordPointer->imagePath.c_str());
            const int kSlashIndex = std::max(kPathText.lastIndexOf('/'), kPathText.lastIndexOf('\\'));
            const QString kFileNameText = kSlashIndex >= 0 ? kPathText.mid(kSlashIndex + 1) : kPathText;
            recordPointer->processName = kFileNameText.toUtf8().toStdString();
        }

        return !recordPointer->imagePath.empty()
            || !recordPointer->userName.empty()
            || recordPointer->creationTime100ns != 0;
    }

    // buildLightweightMonitorProcessRecord：
    // - Purpose: Construct the minimal process record displayable on the monitoring page by PID.
    // - If access fails, retain the PID text as a placeholder at minimum.
    ks::process::ProcessRecord buildLightweightMonitorProcessRecord(const std::uint32_t pidValue)
    {
        ks::process::ProcessRecord record;
        record.pid = pidValue;
        fillLightweightMonitorProcessRecord(&record);
        if (record.processName.empty())
        {
            record.processName = "PID_" + std::to_string(pidValue);
        }
        return record;
    }

    // SuspendedTargetDialogInput: Collected results for creating and suspending the monitoring target dialog.
    struct SuspendedTargetDialogInput
    {
        QString imagePath;
        QString argumentText;
        bool runAsAdministrator = false;
    };

    // showSuspendedTargetDialog: Display the program path, original parameters, and administrator options.
    // Returns true if the user confirms creation, false if cancelled, with no process side effects.
    bool showSuspendedTargetDialog(
        QWidget* const parentWidget,
        SuspendedTargetDialogInput* const inputOut)
    {
        if (inputOut == nullptr)
        {
            return false;
        }

        QDialog dialog(parentWidget);
        dialog.setWindowTitle(QStringLiteral("创建并挂起监控目标"));
        dialog.setModal(true);
        dialog.setMinimumWidth(560);

        QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
        rootLayout->setContentsMargins(16, 16, 16, 16);
        rootLayout->setSpacing(10);

        QFormLayout* formLayout = new QFormLayout();
        formLayout->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);
        formLayout->setHorizontalSpacing(10);
        formLayout->setVerticalSpacing(8);

        QLineEdit* imagePathEdit = new QLineEdit(&dialog);
        imagePathEdit->setPlaceholderText(QStringLiteral("选择要创建的可执行文件"));
        imagePathEdit->setClearButtonEnabled(true);

        QPushButton* browseButton = new QPushButton(QStringLiteral("浏览…"), &dialog);
        QHBoxLayout* imagePathLayout = new QHBoxLayout();
        imagePathLayout->setContentsMargins(0, 0, 0, 0);
        imagePathLayout->setSpacing(6);
        imagePathLayout->addWidget(imagePathEdit, 1);
        imagePathLayout->addWidget(browseButton, 0);

        QWidget* imagePathWidget = new QWidget(&dialog);
        imagePathWidget->setLayout(imagePathLayout);
        formLayout->addRow(QStringLiteral("程序路径:"), imagePathWidget);

        QLineEdit* argumentEdit = new QLineEdit(&dialog);
        argumentEdit->setPlaceholderText(QStringLiteral("将按原样传递给目标进程"));
        argumentEdit->setClearButtonEnabled(true);
        formLayout->addRow(QStringLiteral("进程参数（可选）"), argumentEdit);

        QCheckBox* runAsAdministratorCheck = new QCheckBox(QStringLiteral("以管理员运行"), &dialog);
        formLayout->addRow(QString(), runAsAdministratorCheck);
        rootLayout->addLayout(formLayout);

        QDialogButtonBox* buttonBox = new QDialogButtonBox(&dialog);
        QPushButton* createButton = buttonBox->addButton(
            QStringLiteral("创建并挂起"),
            QDialogButtonBox::AcceptRole);
        buttonBox->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
        rootLayout->addWidget(buttonBox);

        QObject::connect(browseButton, &QPushButton::clicked, &dialog, [&dialog, imagePathEdit]() {
            const QString kImagePath = QFileDialog::getOpenFileName(
                &dialog,
                QStringLiteral("选择可执行文件"),
                imagePathEdit->text().trimmed(),
                QStringLiteral("可执行文件 (*.exe);;所有文件 (*.*)"));
            if (!kImagePath.isEmpty())
            {
                imagePathEdit->setText(QDir::toNativeSeparators(kImagePath));
            }
        });
        QObject::connect(createButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

        if (dialog.exec() != QDialog::Accepted)
        {
            return false;
        }

        inputOut->imagePath = imagePathEdit->text().trimmed();
        inputOut->argumentText = argumentEdit->text();
        inputOut->runAsAdministrator = runAsAdministratorCheck->isChecked();
        return true;
    }
}

void ProcessTraceMonitorWidget::initializeConnections()
{
    // Interaction in the optional process area:
    // - Supports keyword filtering, refreshing process snapshots, double-click to add, and manual PID addition.
    // - These actions allow changing the target set only when monitoring is not running.
    if (availableFilterEdit_ != nullptr)
    {
        connect(availableFilterEdit_, &QLineEdit::textChanged, this, [this]() {
            applyAvailableProcessFilter();
        });
    }

    if (availableRefreshButton_ != nullptr)
    {
        connect(availableRefreshButton_, &QPushButton::clicked, this, [this]() {
            KLogEvent event;
            info << event << "[ProcessTraceMonitorWidget] 用户请求刷新可选进程列表。" << eol;
            refreshAvailableProcessListAsync();
        });
    }

    if (createTargetButton_ != nullptr)
    {
        connect(createTargetButton_, &QPushButton::clicked, this, [this]() {
            createSuspendedTargetProcess();
        });
    }

    if (addSelectedButton_ != nullptr)
    {
        connect(addSelectedButton_, &QPushButton::clicked, this, [this]() {
            addSelectedAvailableProcesses();
        });
    }

    if (addManualPidButton_ != nullptr)
    {
        connect(addManualPidButton_, &QPushButton::clicked, this, [this]() {
            addManualProcessByPid();
        });
    }

    if (manualPidEdit_ != nullptr)
    {
        connect(manualPidEdit_, &QLineEdit::returnPressed, this, [this]() {
            addManualProcessByPid();
        });
    }

    if (availableTable_ != nullptr)
    {
        connect(availableTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
            updateActionState();
        });
        connect(availableTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem*) {
            addSelectedAvailableProcesses();
        });
        connect(availableTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            showAvailableContextMenu(position);
        });
    }

    // Interaction for the monitored target area:
    // - Allow removing the selected item or clearing all at once.
    // - Refresh the target table and total status bar after every change to the target list.
    if (removeTargetButton_ != nullptr)
    {
        connect(removeTargetButton_, &QPushButton::clicked, this, [this]() {
            removeSelectedTargetProcesses();
        });
    }

    if (clearTargetButton_ != nullptr)
    {
        connect(clearTargetButton_, &QPushButton::clicked, this, [this]() {
            clearTargetProcesses();
        });
    }

    if (targetTable_ != nullptr)
    {
        connect(targetTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
            updateActionState();
        });
        connect(targetTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            showTargetContextMenu(position);
        });
    }

    // Control bar interaction:
    // - Start/Stop/Pause all use independent methods to facilitate future insertion of logging and thread control;
    // - The export button exports only the currently visible results, facilitating disk persistence around filtered results.
    if (startButton_ != nullptr)
    {
        connect(startButton_, &QPushButton::clicked, this, [this]() {
            startMonitoring();
        });
    }

    if (stopButton_ != nullptr)
    {
        connect(stopButton_, &QPushButton::clicked, this, [this]() {
            stopMonitoring();
        });
    }

    if (pauseButton_ != nullptr)
    {
        connect(pauseButton_, &QPushButton::clicked, this, [this]() {
            if (!capturePaused_.load())
            {
                setMonitoringPaused(true);
            }
        });
    }

    if (exportButton_ != nullptr)
    {
        connect(exportButton_, &QPushButton::clicked, this, [this]() {
            exportVisibleRowsToTsv();
        });
    }

    // Event filter interaction:
    // - Recalculate visible rows in real-time after changes to the type dropdown or text boxes.
    // - Regex, case sensitivity, and reverse options also reuse the same filter entry point.
    if (eventTypeCombo_ != nullptr)
    {
        connect(eventTypeCombo_, &QComboBox::currentTextChanged, this, [this]() {
            scheduleEventFilterApply();
        });
    }

    const auto kBindEventFilterEdit = [this](QLineEdit* editPointer) {
        if (editPointer == nullptr)
        {
            return;
        }
        connect(editPointer, &QLineEdit::textChanged, this, [this]() {
            scheduleEventFilterApply();
        });
    };
    kBindEventFilterEdit(eventProviderFilterEdit_);
    kBindEventFilterEdit(eventProcessFilterEdit_);
    kBindEventFilterEdit(eventNameFilterEdit_);
    kBindEventFilterEdit(eventDetailFilterEdit_);
    kBindEventFilterEdit(eventGlobalFilterEdit_);

    if (eventRegexCheck_ != nullptr)
    {
        connect(eventRegexCheck_, &QCheckBox::toggled, this, [this]() {
            scheduleEventFilterApply();
        });
    }
    if (eventCaseCheck_ != nullptr)
    {
        connect(eventCaseCheck_, &QCheckBox::toggled, this, [this]() {
            scheduleEventFilterApply();
        });
    }
    if (eventInvertCheck_ != nullptr)
    {
        connect(eventInvertCheck_, &QCheckBox::toggled, this, [this]() {
            scheduleEventFilterApply();
        });
    }
    if (eventClearFilterButton_ != nullptr)
    {
        connect(eventClearFilterButton_, &QPushButton::clicked, this, [this]() {
            clearEventFilter();
        });
    }

    if (eventTable_ != nullptr)
    {
        connect(eventTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            showEventContextMenu(position);
        });
        connect(eventTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* itemPointer) {
            if (itemPointer == nullptr)
            {
                return;
            }
            openEventDetailViewerForRow(itemPointer->row());
        });
    }

    if (eventTimelineWidget_ != nullptr)
    {
        eventTimelineWidget_->setSelectionChangedCallback(
            [this](const std::uint64_t start100ns, const std::uint64_t end100ns) {
                applyTimelineSelection(start100ns, end100ns);
            });
    }

    // Timer:
    // - The UI refresh timer batches events accumulated by the background collection thread into the table;
    // - Runtime snapshot timer for correcting the process tree; an auxiliary link outside ETW.
    if (uiUpdateTimer_ != nullptr)
    {
        connect(uiUpdateTimer_, &QTimer::timeout, this, [this]() {
            flushPendingRows();
        });
    }

    if (eventFilterDebounceTimer_ != nullptr)
    {
        connect(eventFilterDebounceTimer_, &QTimer::timeout, this, [this]() {
            applyEventFilter();
        });
    }

    if (runtimeRefreshTimer_ != nullptr)
    {
        connect(runtimeRefreshTimer_, &QTimer::timeout, this, [this]() {
            refreshTrackedProcessSnapshotAsync();
        });
    }
}

void ProcessTraceMonitorWidget::refreshAvailableProcessListAsync()
{
    if (availableRefreshPending_.exchange(true))
    {
        return;
    }

    if (availableStatusLabel_ != nullptr)
    {
        availableStatusLabel_->setText(QStringLiteral("● 正在刷新当前系统进程快照..."));
        ks::ui::applyStatusRole(availableStatusLabel_, ks::ui::StatusRole::kInfo);
    }
    updateActionState();

    QPointer<ProcessTraceMonitorWidget> guardThis(this);
    std::thread([guardThis]() {
        std::vector<ks::process::ProcessRecord> processList = ks::process::enumerateProcesses(
            ks::process::ProcessEnumStrategy::kAuto);

        for (ks::process::ProcessRecord& record : processList)
        {
            fillLightweightMonitorProcessRecord(&record);
        }

        std::sort(
            processList.begin(),
            processList.end(),
            [](const ks::process::ProcessRecord& left, const ks::process::ProcessRecord& right) {
                return left.pid < right.pid;
            });

        QMetaObject::invokeMethod(qApp, [guardThis, processList = std::move(processList)]() {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->availableRefreshPending_.store(false);
            guardThis->populateAvailableProcessTable(processList);
            guardThis->updateActionState();
        }, Qt::QueuedConnection);
    }).detach();
}

void ProcessTraceMonitorWidget::populateAvailableProcessTable(const std::vector<ks::process::ProcessRecord>& processList)
{
    availableProcessList_ = processList;
    if (availableTable_ == nullptr)
    {
        return;
    }

    availableTable_->setSortingEnabled(false);
    availableTable_->clearContents();
    availableTable_->setRowCount(static_cast<int>(availableProcessList_.size()));

    for (int row = 0; row < static_cast<int>(availableProcessList_.size()); ++row)
    {
        const ks::process::ProcessRecord& record = availableProcessList_[static_cast<std::size_t>(row)];
        availableTable_->setItem(row, kAvailableProcessColumnPid, createReadOnlyItem(QString::number(record.pid)));
        availableTable_->setItem(
            row,
            kAvailableProcessColumnName,
            createReadOnlyItem(QString::fromStdString(record.processName.empty() ? std::string("<Unknown>") : record.processName)));
        availableTable_->setItem(
            row,
            kAvailableProcessColumnPath,
            createReadOnlyItem(QString::fromStdString(record.imagePath)));
        availableTable_->setItem(
            row,
            kAvailableProcessColumnUser,
            createReadOnlyItem(QString::fromStdString(record.userName)));
    }

    availableTable_->setSortingEnabled(true);
    applyAvailableProcessFilter();

    if (availableStatusLabel_ != nullptr)
    {
        availableStatusLabel_->setText(QStringLiteral("● 已刷新 %1 个进程").arg(availableProcessList_.size()));
        ks::ui::applyStatusRole(availableStatusLabel_, ks::ui::StatusRole::kSuccess);
    }
}

void ProcessTraceMonitorWidget::applyAvailableProcessFilter()
{
    if (availableTable_ == nullptr)
    {
        return;
    }

    const QString kKeywordText = availableFilterEdit_ != nullptr
        ? availableFilterEdit_->text().trimmed()
        : QString();

    int visibleRowCount = 0;
    for (int row = 0; row < availableTable_->rowCount(); ++row)
    {
        QStringList rowTextList;
        for (int column = 0; column < kAvailableProcessColumnCount; ++column)
        {
            QTableWidgetItem* itemPointer = availableTable_->item(row, column);
            rowTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }

        const QString kMergedText = rowTextList.join(QStringLiteral(" | "));
        const bool kVisible = kKeywordText.isEmpty()
            || kMergedText.contains(kKeywordText, Qt::CaseInsensitive);
        availableTable_->setRowHidden(row, !kVisible);
        if (kVisible)
        {
            ++visibleRowCount;
        }
    }

    if (availableStatusLabel_ != nullptr)
    {
        availableStatusLabel_->setText(
            QStringLiteral("● 可见 %1 / %2 个进程")
            .arg(visibleRowCount)
            .arg(availableTable_->rowCount()));
        ks::ui::applyStatusRole(availableStatusLabel_, ks::ui::StatusRole::kIdle);
    }
}

void ProcessTraceMonitorWidget::addSelectedAvailableProcesses()
{
    if (availableTable_ == nullptr)
    {
        return;
    }

    std::set<int> selectedRowSet;
    const QList<QTableWidgetItem*> kItemList = availableTable_->selectedItems();
    for (QTableWidgetItem* itemPointer : kItemList)
    {
        if (itemPointer != nullptr)
        {
            selectedRowSet.insert(itemPointer->row());
        }
    }

    if (selectedRowSet.empty())
    {
        return;
    }

    int addedCount = 0;
    for (const int kRow : selectedRowSet)
    {
        QTableWidgetItem* pidItem = availableTable_->item(kRow, kAvailableProcessColumnPid);
        std::uint32_t pidValue = 0;
        if (pidItem == nullptr || !tryParseUint32Text(pidItem->text(), &pidValue))
        {
            continue;
        }

        const std::size_t kBeforeSize = targetProcessList_.size();
        addTargetProcessByPid(pidValue, QStringLiteral("来自可选进程列表"));
        if (targetProcessList_.size() > kBeforeSize)
        {
            ++addedCount;
        }
    }

    KLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 批量添加监控目标完成, selectedRows="
        << selectedRowSet.size()
        << ", addedCount="
        << addedCount
        << eol;
}

void ProcessTraceMonitorWidget::addManualProcessByPid()
{
    if (manualPidEdit_ == nullptr)
    {
        return;
    }

    std::uint32_t pidValue = 0;
    if (!tryParseUint32Text(manualPidEdit_->text(), &pidValue))
    {
        QMessageBox::information(this, QStringLiteral("添加监控目标"), QStringLiteral("请输入有效的 PID。"));
        return;
    }

    addTargetProcessByPid(pidValue, QStringLiteral("手动输入 PID"));
}

void ProcessTraceMonitorWidget::createSuspendedTargetProcess()
{
    // Runtime does not accept modifications to the root target set; this maintains the same constraint as existing 'manual add' and 'batch add' operations.
    if (captureRunning_.load())
    {
        return;
    }

    SuspendedTargetDialogInput dialogInput;
    if (!showSuspendedTargetDialog(this, &dialogInput))
    {
        return;
    }

    if (dialogInput.imagePath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("创建并挂起监控目标"), QStringLiteral("程序路径不能为空。"));
        return;
    }

    const QFileInfo kImageInfo(dialogInput.imagePath);
    if (!kImageInfo.exists() || !kImageInfo.isFile())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("创建并挂起监控目标"),
            QStringLiteral("程序路径无效或不是文件：%1").arg(dialogInput.imagePath));
        return;
    }

    const auto kLaunchTarget = [this, &dialogInput, &kImageInfo](const bool allowElevatedFallback) {
        ks::process::SuspendedProcessLaunchRequest request;
        request.imagePath = QDir::toNativeSeparators(kImageInfo.absoluteFilePath()).toUtf8().toStdString();
        request.argumentText = dialogInput.argumentText.toUtf8().toStdString();
        request.workingDirectory = QDir::toNativeSeparators(kImageInfo.absolutePath()).toUtf8().toStdString();
        request.runAsAdministrator = dialogInput.runAsAdministrator;
        request.allowElevatedFallback = allowElevatedFallback;

        ks::process::SuspendedProcessLaunchResult launchResult;
        const bool kLaunchOk = ks::process::launchSuspendedProcess(request, &launchResult);
        return std::pair<bool, ks::process::SuspendedProcessLaunchResult>(kLaunchOk, std::move(launchResult));
    };

    auto [launchOk, launchResult] = kLaunchTarget(false);
    if (!launchOk && launchResult.failure == ks::process::SuspendedProcessLaunchFailure::kAdministratorRequired)
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("以管理员权限创建并挂起监控目标"));
        return;
    }

    if (!launchOk && launchResult.failure == ks::process::SuspendedProcessLaunchFailure::kUnelevatedTokenUnavailable)
    {
        QMessageBox fallbackDialog(this);
        fallbackDialog.setWindowTitle(QStringLiteral("普通权限令牌不可用"));
        fallbackDialog.setIcon(QMessageBox::Warning);
        fallbackDialog.setText(
            QStringLiteral("无法将目标降级为普通权限：%1\n\n是否继续以管理员权限创建？")
            .arg(QString::fromUtf8(launchResult.detailText.c_str())));
        QPushButton* continueButton = fallbackDialog.addButton(
            QStringLiteral("继续以管理员权限创建"),
            QMessageBox::AcceptRole);
        fallbackDialog.addButton(QStringLiteral("取消"), QMessageBox::RejectRole);
        fallbackDialog.exec();
        if (fallbackDialog.clickedButton() != continueButton)
        {
            return;
        }

        std::tie(launchOk, launchResult) = kLaunchTarget(true);
    }

    if (!launchOk)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("创建进程失败"),
            QStringLiteral("创建并挂起目标进程失败：%1")
            .arg(QString::fromUtf8(launchResult.detailText.c_str())));
        return;
    }

    const QString kProcessName = kImageInfo.fileName().isEmpty()
        ? QStringLiteral("<Unknown>")
        : kImageInfo.fileName();
    const QString kPrivilegeText = launchResult.usedUnelevatedToken
        || (!dialogInput.runAsAdministrator && !launchResult.usedElevatedFallback)
        ? QStringLiteral("普通权限")
        : QStringLiteral("管理员权限");
    const QString kInitialRemark = QStringLiteral("定向创建（已挂起，%1）").arg(kPrivilegeText);
    addTargetProcessByPid(launchResult.processId, kInitialRemark);

    const int kProgressTaskId = kPro.add(
        this,
        QStringLiteral("创建并挂起目标进程").toUtf8().toStdString(),
        QStringLiteral("已加入监控目标，等待选择").toUtf8().toStdString());
    kPro.set(
        kProgressTaskId,
        QStringLiteral("目标 PID=%1，%2 已创建并保持挂起").arg(launchResult.processId).arg(kProcessName).toUtf8().toStdString(),
        0,
        40.0f);

    QString choicePrompt = QStringLiteral(
        "对于进程 pid:%1，%2，请明确选择恢复进程并继续追踪，或终止进程并放弃追踪。关闭窗口只会取消本次选择，不会丢失恢复句柄。")
        .arg(launchResult.processId)
        .arg(kProcessName);
    const std::string kResumeOptionText =
        QStringLiteral("选项 1：恢复进程并继续追踪").toUtf8().toStdString();
    const std::string kTerminateOptionText =
        QStringLiteral("选项 2：终止进程并放弃追踪").toUtf8().toStdString();

    // Initial thread handle ownership:
    // - Close only after ResumeThread or TerminateProcess succeeds.
    // - Closing the option window, recovery failure, or termination failure all return to the selection loop to ensure retries remain possible.
    // - Therefore, no normal UI exit path will leave a CREATE_SUSPENDED process without a recoverable handle.
    for (;;)
    {
        const int kSelectedOption = kPro.ui(
            kProgressTaskId,
            choicePrompt.toUtf8().toStdString(),
            kResumeOptionText,
            kTerminateOptionText);

        if (kSelectedOption == 0)
        {
            updateTargetProcessRemarkByPid(
                launchResult.processId,
                QStringLiteral("选择已取消，目标仍挂起且恢复句柄已保留"));
            kPro.set(
                kProgressTaskId,
                QStringLiteral("已取消本次选择；目标仍挂起，可继续选择恢复或终止").toUtf8().toStdString(),
                0,
                40.0f);
            choicePrompt = QStringLiteral(
                "已取消关闭选项窗口。进程 pid:%1 仍处于挂起状态，恢复句柄已保留；请选择恢复进程或终止进程。")
                .arg(launchResult.processId);
            continue;
        }

        if (kSelectedOption == 1)
        {
            std::string resumeError;
            const bool kResumeOk = ks::process::resumeSuspendedProcessInitialThread(
                launchResult.initialThreadHandle,
                &resumeError);
            if (!kResumeOk)
            {
                const QString kErrorText = QString::fromUtf8(resumeError.c_str());
                updateTargetProcessRemarkByPid(
                    launchResult.processId,
                    QStringLiteral("恢复失败，目标仍挂起且句柄已保留：%1").arg(kErrorText));
                kPro.set(
                    kProgressTaskId,
                    QStringLiteral("恢复失败；句柄已保留，可重试恢复或终止").toUtf8().toStdString(),
                    0,
                    90.0f);
                choicePrompt = QStringLiteral(
                    "恢复进程 pid:%1 失败：%2\n\n目标仍处于挂起状态，恢复句柄已保留；请选择重试恢复或终止进程。")
                    .arg(launchResult.processId)
                    .arg(kErrorText);
                QMessageBox::warning(
                    this,
                    QStringLiteral("恢复新建目标失败"),
                    choicePrompt);
                continue;
            }

            ks::process::closeSuspendedProcessInitialThreadHandle(
                launchResult.initialThreadHandle);
            ks::process::closeSuspendedProcessHandle(
                launchResult.processHandle);
            updateTargetProcessRemarkByPid(
                launchResult.processId,
                QStringLiteral("已恢复，等待手动开始监听"));
            kPro.set(
                kProgressTaskId,
                QStringLiteral("已取消挂起，等待手动开始监听").toUtf8().toStdString(),
                0,
                100.0f);
            KLogEvent event;
            info << event
                << "[ProcessTraceMonitorWidget] 已创建并恢复监控目标, pid="
                << launchResult.processId
                << ", process="
                << kProcessName.toStdString()
                << eol;
            break;
        }

        if (kSelectedOption == 2)
        {
            std::string terminateError;
            const bool kTerminateOk = ks::process::terminateSuspendedProcessByHandle(
                launchResult.processHandle,
                &terminateError);
            if (!kTerminateOk)
            {
                const QString kErrorText = QString::fromUtf8(terminateError.c_str());
                updateTargetProcessRemarkByPid(
                    launchResult.processId,
                    QStringLiteral("终止失败，目标仍挂起且句柄已保留：%1").arg(kErrorText));
                kPro.set(
                    kProgressTaskId,
                    QStringLiteral("终止失败；句柄已保留，可重试恢复或终止").toUtf8().toStdString(),
                    0,
                    90.0f);
                choicePrompt = QStringLiteral(
                    "终止进程 pid:%1 失败：%2\n\n目标仍处于挂起状态，恢复句柄已保留；请选择恢复进程或重试终止。")
                    .arg(launchResult.processId)
                    .arg(kErrorText);
                QMessageBox::warning(
                    this,
                    QStringLiteral("终止新建目标失败"),
                    choicePrompt);
                continue;
            }

            ks::process::closeSuspendedProcessInitialThreadHandle(
                launchResult.initialThreadHandle);
            ks::process::closeSuspendedProcessHandle(
                launchResult.processHandle);
            removeTrackedProcessFromTargetListByPid(
                launchResult.processId,
                QStringLiteral("用户终止进程并放弃追踪"));
            updateActionState();
            kPro.set(
                kProgressTaskId,
                QStringLiteral("已终止进程并放弃追踪").toUtf8().toStdString(),
                0,
                100.0f);

            KLogEvent event;
            info << event
                << "[ProcessTraceMonitorWidget] 用户终止新建目标并放弃追踪, pid="
                << launchResult.processId
                << ", process="
                << kProcessName.toStdString()
                << eol;
            break;
        }

        // Unknown return values are treated as cancellations just like closing the window; handles are never released and targets are never removed.
        kPro.set(
            kProgressTaskId,
            QStringLiteral("选项返回值无效；目标仍挂起，可继续选择恢复或终止").toUtf8().toStdString(),
            0,
            40.0f);
    }
}

void ProcessTraceMonitorWidget::addTargetProcessByPid(const std::uint32_t pidValue, const QString& sourceText)
{
    if (pidValue == 0)
    {
        return;
    }

    const auto kDuplicateFound = std::find_if(
        targetProcessList_.begin(),
        targetProcessList_.end(),
        [pidValue](const TargetProcessEntry& entry) {
            return entry.pid == pidValue;
        });
    if (kDuplicateFound != targetProcessList_.end())
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加监控目标"),
            QStringLiteral("PID=%1 已经在监控目标列表中。").arg(pidValue));
        return;
    }

    TargetProcessEntry targetEntry;
    targetEntry.pid = pidValue;
    targetEntry.remarkText = sourceText;

    const auto kFound = std::find_if(
        availableProcessList_.begin(),
        availableProcessList_.end(),
        [pidValue](const ks::process::ProcessRecord& record) {
            return record.pid == pidValue;
        });

    if (kFound != availableProcessList_.end())
    {
        targetEntry.processName = QString::fromStdString(kFound->processName);
        targetEntry.imagePath = QString::fromStdString(kFound->imagePath);
        targetEntry.userName = QString::fromStdString(kFound->userName);
        targetEntry.creationTime100ns = kFound->creationTime100ns;
        targetEntry.alive = true;
    }
    else
    {
        ks::process::ProcessRecord detailRecord = buildLightweightMonitorProcessRecord(pidValue);
        targetEntry.processName = QString::fromStdString(detailRecord.processName);
        targetEntry.imagePath = QString::fromStdString(detailRecord.imagePath);
        targetEntry.userName = QString::fromStdString(detailRecord.userName);
        targetEntry.creationTime100ns = detailRecord.creationTime100ns;
        targetEntry.alive = !detailRecord.imagePath.empty()
            || !detailRecord.userName.empty()
            || detailRecord.creationTime100ns != 0;

        if (!targetEntry.alive)
        {
            targetEntry.processName = targetEntry.processName.trimmed().isEmpty()
                ? QStringLiteral("<Unknown>")
                : targetEntry.processName;
            targetEntry.remarkText += QStringLiteral("；无法读取静态详情");
        }
    }

    targetProcessList_.push_back(targetEntry);
    refreshTargetTable();
    updateActionState();
    updateStatusLabel();

    KLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 添加监控目标, pid="
        << pidValue
        << ", source="
        << sourceText.toStdString()
        << eol;
}

void ProcessTraceMonitorWidget::updateTargetProcessRemarkByPid(
    const std::uint32_t pidValue,
    const QString& remarkText)
{
    const auto kFound = std::find_if(
        targetProcessList_.begin(),
        targetProcessList_.end(),
        [pidValue](const TargetProcessEntry& entry) {
            return entry.pid == pidValue;
        });
    if (kFound == targetProcessList_.end())
    {
        return;
    }

    kFound->remarkText = remarkText;
    refreshTargetTable();
    updateActionState();
    updateStatusLabel();
}

void ProcessTraceMonitorWidget::upsertAutoTrackedProcessInTargetList(
    const std::uint32_t pidValue,
    const std::uint32_t parentPidValue,
    const QString& processNameText,
    const QString& processPathText,
    const std::uint64_t creationTime100ns)
{
    if (pidValue == 0)
    {
        return;
    }

    // normalizedProcessName/normalizedProcessPath: Cleans up whitespace that may be present in ETW events.
    const QString kNormalizedProcessName = processNameText.trimmed();
    const QString kNormalizedProcessPath = processPathText.trimmed();
    // autoRemarkText: Used to explicitly mark that the entry is an ETW auto-join.
    const QString kAutoRemarkText = QStringLiteral("ETW 自动加入（父PID=%1）").arg(parentPidValue);

    auto targetIt = std::find_if(
        targetProcessList_.begin(),
        targetProcessList_.end(),
        [pidValue](const TargetProcessEntry& entry) {
            return entry.pid == pidValue;
        });

    bool targetAdded = false;
    if (targetIt == targetProcessList_.end())
    {
        TargetProcessEntry targetEntry;
        targetEntry.pid = pidValue;
        targetEntry.processName = kNormalizedProcessName;
        targetEntry.imagePath = kNormalizedProcessPath;
        targetEntry.creationTime100ns = creationTime100ns;
        targetEntry.alive = true;
        targetEntry.remarkText = kAutoRemarkText;
        targetProcessList_.push_back(targetEntry);
        targetIt = std::prev(targetProcessList_.end());
        targetAdded = true;
    }
    else
    {
        targetIt->alive = true;
        if (!kNormalizedProcessName.isEmpty())
        {
            targetIt->processName = kNormalizedProcessName;
        }
        if (!kNormalizedProcessPath.isEmpty())
        {
            targetIt->imagePath = kNormalizedProcessPath;
        }
        if (creationTime100ns != 0)
        {
            targetIt->creationTime100ns = creationTime100ns;
        }

        const bool kCanRewriteRemark = targetIt->remarkText.trimmed().isEmpty()
            || targetIt->remarkText.contains(QStringLiteral("ETW 自动加入"), Qt::CaseInsensitive);
        if (kCanRewriteRemark)
        {
            targetIt->remarkText = kAutoRemarkText;
        }
    }

    // needDetailLookup: When ETW lacks full fields, perform a lightweight static detail lookup by PID.
    const bool kNeedDetailLookup = targetIt->processName.trimmed().isEmpty()
        || targetIt->imagePath.trimmed().isEmpty()
        || targetIt->userName.trimmed().isEmpty()
        || targetIt->creationTime100ns == 0;
    if (kNeedDetailLookup)
    {
        const ks::process::ProcessRecord kDetailRecord = buildLightweightMonitorProcessRecord(pidValue);
        if (targetIt->processName.trimmed().isEmpty())
        {
            targetIt->processName = QString::fromStdString(kDetailRecord.processName);
        }
        if (targetIt->imagePath.trimmed().isEmpty())
        {
            targetIt->imagePath = QString::fromStdString(kDetailRecord.imagePath);
        }
        if (targetIt->userName.trimmed().isEmpty())
        {
            targetIt->userName = QString::fromStdString(kDetailRecord.userName);
        }
        if (targetIt->creationTime100ns == 0)
        {
            targetIt->creationTime100ns = kDetailRecord.creationTime100ns;
        }

        // Keep alive=true here:
        // - The trigger source is the "ETW process creation event," indicating that the PID was reachable at the time of the event;
        // - Even if lightweight detail completion fails, it should not be mistaken for the process having exited.
        targetIt->alive = true;
    }

    refreshTargetTable();
    updateStatusLabel();

    KLogEvent autoAddEvent;
    info << autoAddEvent
        << "[ProcessTraceMonitorWidget] ETW自动同步监控目标, pid="
        << pidValue
        << ", parentPid="
        << parentPidValue
        << ", action="
        << (targetAdded ? "add" : "update")
        << eol;
}

void ProcessTraceMonitorWidget::removeTrackedProcessFromTargetListByPid(
    const std::uint32_t pidValue,
    const QString& reasonText)
{
    if (pidValue == 0 || targetProcessList_.empty())
    {
        return;
    }

    // removeBegin: points to the first entry to be removed, used for batch erasing records with the same PID.
    const auto kRemoveBegin = std::remove_if(
        targetProcessList_.begin(),
        targetProcessList_.end(),
        [pidValue](const TargetProcessEntry& entry) {
            return entry.pid == pidValue;
        });
    if (kRemoveBegin == targetProcessList_.end())
    {
        return;
    }

    const std::size_t kRemovedCount = static_cast<std::size_t>(targetProcessList_.end() - kRemoveBegin);
    targetProcessList_.erase(kRemoveBegin, targetProcessList_.end());

    refreshTargetTable();
    updateStatusLabel();

    KLogEvent autoRemoveEvent;
    info << autoRemoveEvent
        << "[ProcessTraceMonitorWidget] 自动取消追踪, pid="
        << pidValue
        << ", removedCount="
        << kRemovedCount
        << ", reason="
        << reasonText.toStdString()
        << eol;
}

void ProcessTraceMonitorWidget::refreshTargetTable()
{
    if (targetTable_ == nullptr)
    {
        return;
    }

    targetTable_->clearContents();
    targetTable_->setRowCount(static_cast<int>(targetProcessList_.size()));

    int aliveCount = 0;
    for (int row = 0; row < static_cast<int>(targetProcessList_.size()); ++row)
    {
        const TargetProcessEntry& entry = targetProcessList_[static_cast<std::size_t>(row)];

        QTableWidgetItem* stateItem = createReadOnlyItem(entry.alive
            ? QStringLiteral("运行中")
            : QStringLiteral("未知/已退出"));
        if (entry.alive)
        {
            ++aliveCount;
            stateItem->setForeground(QBrush(ksword_theme::successColor()));
        }
        else
        {
            stateItem->setForeground(QBrush(ksword_theme::textSecondaryColor()));
        }

        targetTable_->setItem(row, kTargetProcessColumnState, stateItem);
        targetTable_->setItem(row, kTargetProcessColumnPid, createReadOnlyItem(QString::number(entry.pid)));
        targetTable_->setItem(row, kTargetProcessColumnName, createReadOnlyItem(entry.processName));
        targetTable_->setItem(row, kTargetProcessColumnPath, createReadOnlyItem(entry.imagePath));
        targetTable_->setItem(row, kTargetProcessColumnUser, createReadOnlyItem(entry.userName));
        targetTable_->setItem(row, kTargetProcessColumnRemark, createReadOnlyItem(entry.remarkText));
    }

    if (targetStatusLabel_ != nullptr)
    {
        targetStatusLabel_->setText(
            QStringLiteral("● 目标 %1 个，其中存活 %2 个")
            .arg(targetProcessList_.size())
            .arg(aliveCount));
        ks::ui::applyStatusRole(targetStatusLabel_,
            targetProcessList_.empty()
            ? ks::ui::StatusRole::kIdle
            : ks::ui::StatusRole::kSuccess);
    }
}

void ProcessTraceMonitorWidget::removeSelectedTargetProcesses()
{
    if (targetTable_ == nullptr || targetProcessList_.empty())
    {
        return;
    }

    std::set<int, std::greater<int>> selectedRowSet;
    const QList<QTableWidgetItem*> kItemList = targetTable_->selectedItems();
    for (QTableWidgetItem* itemPointer : kItemList)
    {
        if (itemPointer != nullptr)
        {
            selectedRowSet.insert(itemPointer->row());
        }
    }

    if (selectedRowSet.empty())
    {
        return;
    }

    for (const int kRow : selectedRowSet)
    {
        if (kRow >= 0 && kRow < static_cast<int>(targetProcessList_.size()))
        {
            targetProcessList_.erase(targetProcessList_.begin() + kRow);
        }
    }

    refreshTargetTable();
    updateActionState();
    updateStatusLabel();

    KLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 已移除选中监控目标, removedCount="
        << selectedRowSet.size()
        << eol;
}

void ProcessTraceMonitorWidget::clearTargetProcesses()
{
    if (targetProcessList_.empty())
    {
        return;
    }

    targetProcessList_.clear();
    refreshTargetTable();
    updateActionState();
    updateStatusLabel();

    KLogEvent event;
    info << event << "[ProcessTraceMonitorWidget] 已清空全部监控目标。" << eol;
}

void ProcessTraceMonitorWidget::showAvailableContextMenu(const QPoint& position)
{
    // showAvailableContextMenu：
    // - Input position: Optional process table viewport coordinates;
    // - Processing: Synchronize right-click row selection, provide options to add to target, copy current row, and copy selected rows.
    // - Return: None. The copy action only writes to the clipboard; the target reuse leverages existing business functions.
    if (availableTable_ == nullptr)
    {
        return;
    }

    const QModelIndex kIndex = availableTable_->indexAt(position);
    if (kIndex.isValid())
    {
        const int kRow = kIndex.row();
        if (!availableTable_->selectionModel()->isRowSelected(kRow, QModelIndex()))
        {
            availableTable_->clearSelection();
            availableTable_->selectRow(kRow);
        }
        // Right-click current row synchronization:
        // - Input: Selectable process row where the mouse is located;
        // - Handling: selectRow only ensures selection state; explicit setCurrentCell is required to stably copy the right-clicked row.
        // - Return: None; subsequent menu actions continue with the existing read-only/add-to-target logic.
        availableTable_->setCurrentCell(kRow, 0);
    }

    const std::vector<int> kSelectedRows = selectedTableRows(availableTable_);
    const int kCurrentRow = availableTable_->currentRow();
    const bool kRunning = captureRunning_.load();

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* addSelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_start.svg")),
        QStringLiteral("加入监控目标"));
    menu.addSeparator();
    QAction* copyCurrentAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));
    QAction* copySelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
        QStringLiteral("复制选中行"));

    addSelectedAction->setEnabled(!kRunning && !kSelectedRows.empty());
    copyCurrentAction->setEnabled(kCurrentRow >= 0);
    copySelectedAction->setEnabled(!kSelectedRows.empty());

    QAction* selectedAction = menu.exec(availableTable_->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == addSelectedAction)
    {
        addSelectedAvailableProcesses();
        return;
    }

    if (selectedAction == copyCurrentAction)
    {
        copyTableRowsToClipboard(availableTable_, std::vector<int>{ kCurrentRow });
        return;
    }

    if (selectedAction == copySelectedAction)
    {
        copyTableRowsToClipboard(availableTable_, kSelectedRows);
    }
}

void ProcessTraceMonitorWidget::showTargetContextMenu(const QPoint& position)
{
    if (targetTable_ == nullptr)
    {
        return;
    }

    const QModelIndex kIndex = targetTable_->indexAt(position);
    if (kIndex.isValid())
    {
        const int kRow = kIndex.row();
        if (!targetTable_->selectionModel()->isRowSelected(kRow, QModelIndex()))
        {
            targetTable_->clearSelection();
            targetTable_->selectRow(kRow);
        }
        // Right-click current row synchronization:
        // - Input: Monitoring target row where the mouse is located;
        // - Processing: Explicitly synchronize the current cell to avoid copying the old focused row when copying the current row.
        // - Returns: None; does not change monitoring state.
        targetTable_->setCurrentCell(kRow, 0);
    }

    const std::vector<int> kSelectedRows = selectedTableRows(targetTable_);
    const int kCurrentRow = targetTable_->currentRow();

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyCurrentAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));
    QAction* copySelectedAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clipboard.svg")),
        QStringLiteral("复制选中行"));
    menu.addSeparator();
    QAction* removeSelectedAction = menu.addAction(
        QIcon(":/Icon/process_pause.svg"),
        QStringLiteral("移除选中目标"));
    QAction* clearAllAction = menu.addAction(
        QIcon(":/Icon/process_terminate.svg"),
        QStringLiteral("清空全部目标"));

    const bool kRunning = captureRunning_.load();
    copyCurrentAction->setEnabled(kCurrentRow >= 0);
    copySelectedAction->setEnabled(!kSelectedRows.empty());
    removeSelectedAction->setEnabled(!kRunning && !targetTable_->selectedItems().isEmpty());
    clearAllAction->setEnabled(!kRunning && !targetProcessList_.empty());

    QAction* selectedAction = menu.exec(targetTable_->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == copyCurrentAction)
    {
        copyTableRowsToClipboard(targetTable_, std::vector<int>{ kCurrentRow });
        return;
    }

    if (selectedAction == copySelectedAction)
    {
        copyTableRowsToClipboard(targetTable_, kSelectedRows);
        return;
    }

    if (selectedAction == removeSelectedAction)
    {
        removeSelectedTargetProcesses();
        return;
    }

    if (selectedAction == clearAllAction)
    {
        clearTargetProcesses();
    }
}

void ProcessTraceMonitorWidget::scheduleEventFilterApply()
{
    if (eventFilterDebounceTimer_ == nullptr)
    {
        applyEventFilter();
        return;
    }

    eventFilterDebounceTimer_->start();
}

bool ProcessTraceMonitorWidget::hasAnyEventFilterActive() const
{
    const bool kTypeFilterActive = eventTypeCombo_ != nullptr
        && eventTypeCombo_->currentText().trimmed() != QStringLiteral("全部类型");
    const bool kProviderFilterActive = eventProviderFilterEdit_ != nullptr
        && !eventProviderFilterEdit_->text().trimmed().isEmpty();
    const bool kProcessFilterActive = eventProcessFilterEdit_ != nullptr
        && !eventProcessFilterEdit_->text().trimmed().isEmpty();
    const bool kEventNameFilterActive = eventNameFilterEdit_ != nullptr
        && !eventNameFilterEdit_->text().trimmed().isEmpty();
    const bool kDetailFilterActive = eventDetailFilterEdit_ != nullptr
        && !eventDetailFilterEdit_->text().trimmed().isEmpty();
    const bool kGlobalFilterActive = eventGlobalFilterEdit_ != nullptr
        && !eventGlobalFilterEdit_->text().trimmed().isEmpty();
    const bool kAnyTextPatternActive = kProviderFilterActive
        || kProcessFilterActive
        || kEventNameFilterActive
        || kDetailFilterActive
        || kGlobalFilterActive;
    const bool kRegexFilterActive = kAnyTextPatternActive
        && eventRegexCheck_ != nullptr
        && eventRegexCheck_->isChecked();
    const bool kCaseFilterActive = kAnyTextPatternActive
        && eventCaseCheck_ != nullptr
        && eventCaseCheck_->isChecked();
    const bool kInvertFilterActive = eventInvertCheck_ != nullptr && eventInvertCheck_->isChecked();

    return kTypeFilterActive
        || kProviderFilterActive
        || kProcessFilterActive
        || kEventNameFilterActive
        || kDetailFilterActive
        || kGlobalFilterActive
        || kRegexFilterActive
        || kCaseFilterActive
        || kInvertFilterActive
        || isTimelineFilterActive();
}

void ProcessTraceMonitorWidget::updateEventFilterStatusText(const int visibleCount, const int totalCount)
{
    if (eventFilterStatusLabel_ == nullptr)
    {
        return;
    }

    eventFilterStatusLabel_->setText(
        QStringLiteral("筛选结果：%1 / %2")
        .arg(visibleCount)
        .arg(totalCount));
    ks::ui::applyStatusRole(eventFilterStatusLabel_,
        visibleCount > 0 ? ks::ui::StatusRole::kSuccess : ks::ui::StatusRole::kIdle);
}

void ProcessTraceMonitorWidget::applyTimelineSelection(
    const std::uint64_t start100ns,
    const std::uint64_t end100ns)
{
    // The timeline interprets mouse actions; the event table executes filtering.
    // Here, store absolute timestamps to ensure the graphical selection and table rows are linked via data, not via screen coordinates.
    timelineSelectionStart100ns_ = std::min(start100ns, end100ns);
    timelineSelectionEnd100ns_ = std::max(start100ns, end100ns);
    timelineUserSelectionActive_ = true;
    applyEventFilter();
}

void ProcessTraceMonitorWidget::refreshTimelineRange(const bool captureFinished)
{
    if (eventTimelineWidget_ == nullptr || captureStartTime100ns_ == 0)
    {
        return;
    }

    // captureEnd100ns：
    // - Use current system time during capture to allow real-time expansion of the right side of the timeline;
    // - Uses the recorded stop time after stopping to keep the right side fixed.
    std::uint64_t captureEnd100ns = captureFinished && captureStopTime100ns_ != 0
        ? captureStopTime100ns_
        : currentSystemTime100ns();

    if (captureEnd100ns <= captureStartTime100ns_)
    {
        captureEnd100ns = captureStartTime100ns_ + 1;
    }

    eventTimelineWidget_->setCaptureRange(captureStartTime100ns_, captureEnd100ns);
    timelineSelectionStart100ns_ = eventTimelineWidget_->selectionStart100ns();
    timelineSelectionEnd100ns_ = eventTimelineWidget_->selectionEnd100ns();
}

void ProcessTraceMonitorWidget::refreshTimelinePoints()
{
    if (eventTimelineWidget_ == nullptr)
    {
        return;
    }

    eventTimelineWidget_->setEventPoints(timelineEventPoints_);
}

bool ProcessTraceMonitorWidget::isTimelineFilterActive() const
{
    if (captureStartTime100ns_ == 0
        || !timelineUserSelectionActive_
        || timelineSelectionStart100ns_ == 0
        || timelineSelectionEnd100ns_ == 0
        || timelineSelectionEnd100ns_ <= timelineSelectionStart100ns_)
    {
        return false;
    }

    const std::uint64_t kEffectiveEnd100ns = captureStopTime100ns_ != 0
        ? captureStopTime100ns_
        : currentSystemTime100ns();
    if (kEffectiveEnd100ns <= captureStartTime100ns_)
    {
        return false;
    }

    // A full-range selection is not treated as an additional filter to prevent hiding newly appended events in the default auto-follow state.
    return timelineSelectionStart100ns_ > captureStartTime100ns_
        || timelineSelectionEnd100ns_ < kEffectiveEnd100ns;
}

void ProcessTraceMonitorWidget::applyEventFilter()
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    const QString kTypeText = eventTypeCombo_ != nullptr ? eventTypeCombo_->currentText().trimmed() : QString();
    const QString kProviderText = eventProviderFilterEdit_ != nullptr ? eventProviderFilterEdit_->text() : QString();
    const QString kProcessText = eventProcessFilterEdit_ != nullptr ? eventProcessFilterEdit_->text() : QString();
    const QString kEventNameText = eventNameFilterEdit_ != nullptr ? eventNameFilterEdit_->text() : QString();
    const QString kDetailText = eventDetailFilterEdit_ != nullptr ? eventDetailFilterEdit_->text() : QString();
    const QString kGlobalText = eventGlobalFilterEdit_ != nullptr ? eventGlobalFilterEdit_->text() : QString();
    const bool kUseRegex = eventRegexCheck_ != nullptr && eventRegexCheck_->isChecked();
    const bool kInvertMatch = eventInvertCheck_ != nullptr && eventInvertCheck_->isChecked();
    const bool kTimelineFilterActive = isTimelineFilterActive();
    const Qt::CaseSensitivity kCaseSensitivity =
        (eventCaseCheck_ != nullptr && eventCaseCheck_->isChecked())
        ? Qt::CaseSensitive
        : Qt::CaseInsensitive;

    const bool kAnyFilterActive = hasAnyEventFilterActive();
    if (!kAnyFilterActive)
    {
        for (int row = 0; row < eventTable_->rowCount(); ++row)
        {
            eventTable_->setRowHidden(row, false);
        }
        updateEventFilterStatusText(eventTable_->rowCount(), eventTable_->rowCount());
        updateActionState();
        updateStatusLabel();
        return;
    }

    int visibleCount = 0;
    for (int row = 0; row < eventTable_->rowCount(); ++row)
    {
        QTableWidgetItem* timeItem = eventTable_->item(row, kEventColumnTime100ns);
        const QString kRowType = eventTable_->item(row, kEventColumnType) != nullptr
            ? eventTable_->item(row, kEventColumnType)->text()
            : QString();
        const QString kRowProvider = eventTable_->item(row, kEventColumnProvider) != nullptr
            ? eventTable_->item(row, kEventColumnProvider)->text()
            : QString();
        const QString kRowDetail = eventTable_->item(row, kEventColumnDetail) != nullptr
            ? eventTable_->item(row, kEventColumnDetail)->text()
            : QString();
        const QString kProcessMergedText = timeItem != nullptr
            ? timeItem->data(kEventRoleProcessSearchText).toString()
            : QString();
        const QString kEventMergedText = timeItem != nullptr
            ? timeItem->data(kEventRoleEventSearchText).toString()
            : QString();
        const QString kGlobalMergedText = timeItem != nullptr
            ? timeItem->data(kEventRoleGlobalSearchText).toString()
            : QString();

        // timelineMatched：
        // - The time window is always the outer constraint;
        // - The existing 'reverse' option cannot invert this to 'outside the time box' without breaking the time-box selection semantics.
        bool timelineMatched = true;
        if (kTimelineFilterActive)
        {
            const std::uint64_t kRowTime100ns = timeItem != nullptr
                ? timeItem->data(kEventRoleTime100nsValue).toULongLong()
                : 0;
            timelineMatched = kRowTime100ns >= timelineSelectionStart100ns_
                && kRowTime100ns <= timelineSelectionEnd100ns_;
        }

        bool matched = true;
        if (!kTypeText.isEmpty() && kTypeText != QStringLiteral("全部类型"))
        {
            matched = matched && (QString::compare(kRowType, kTypeText, Qt::CaseInsensitive) == 0);
        }

        matched = matched && textMatch(kRowProvider, kProviderText, kUseRegex, kCaseSensitivity);
        matched = matched && textMatch(kProcessMergedText, kProcessText, kUseRegex, kCaseSensitivity);
        matched = matched && textMatch(kEventMergedText, kEventNameText, kUseRegex, kCaseSensitivity);
        matched = matched && textMatch(kRowDetail, kDetailText, kUseRegex, kCaseSensitivity);
        matched = matched && textMatch(kGlobalMergedText, kGlobalText, kUseRegex, kCaseSensitivity);

        if (kInvertMatch)
        {
            matched = !matched;
        }
        matched = matched && timelineMatched;

        eventTable_->setRowHidden(row, !matched);
        if (matched)
        {
            ++visibleCount;
        }
    }

    updateEventFilterStatusText(visibleCount, eventTable_->rowCount());

    updateActionState();
    updateStatusLabel();
}

void ProcessTraceMonitorWidget::clearEventFilter()
{
    const QSignalBlocker kTypeBlocker(eventTypeCombo_);
    const QSignalBlocker kProviderBlocker(eventProviderFilterEdit_);
    const QSignalBlocker kProcessBlocker(eventProcessFilterEdit_);
    const QSignalBlocker kEventNameBlocker(eventNameFilterEdit_);
    const QSignalBlocker kDetailBlocker(eventDetailFilterEdit_);
    const QSignalBlocker kGlobalBlocker(eventGlobalFilterEdit_);
    const QSignalBlocker kRegexBlocker(eventRegexCheck_);
    const QSignalBlocker kCaseBlocker(eventCaseCheck_);
    const QSignalBlocker kInvertBlocker(eventInvertCheck_);

    if (eventTypeCombo_ != nullptr)
    {
        eventTypeCombo_->setCurrentIndex(0);
    }
    if (eventProviderFilterEdit_ != nullptr)
    {
        eventProviderFilterEdit_->clear();
    }
    if (eventProcessFilterEdit_ != nullptr)
    {
        eventProcessFilterEdit_->clear();
    }
    if (eventNameFilterEdit_ != nullptr)
    {
        eventNameFilterEdit_->clear();
    }
    if (eventDetailFilterEdit_ != nullptr)
    {
        eventDetailFilterEdit_->clear();
    }
    if (eventGlobalFilterEdit_ != nullptr)
    {
        eventGlobalFilterEdit_->clear();
    }
    if (eventRegexCheck_ != nullptr)
    {
        eventRegexCheck_->setChecked(false);
    }
    if (eventCaseCheck_ != nullptr)
    {
        eventCaseCheck_->setChecked(false);
    }
    if (eventInvertCheck_ != nullptr)
    {
        eventInvertCheck_->setChecked(false);
    }
    if (eventTimelineWidget_ != nullptr)
    {
        eventTimelineWidget_->resetSelectionToFullRange();
        timelineSelectionStart100ns_ = eventTimelineWidget_->selectionStart100ns();
        timelineSelectionEnd100ns_ = eventTimelineWidget_->selectionEnd100ns();
        timelineUserSelectionActive_ = false;
    }

    applyEventFilter();

    KLogEvent event;
    info << event << "[ProcessTraceMonitorWidget] 已清空事件筛选条件。" << eol;
}

void ProcessTraceMonitorWidget::flushPendingRows()
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    // Defer the entire UI commit before drain; with the same key timeout, only one retry is retained. The original event
    // remains in m_pendingRows, so closing the menu won't drop batches or alter the header truncation's action target.
    const QPointer<ProcessTraceMonitorWidget> kGuardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("process-trace-event-flush"),
        { eventTable_ },
        [kGuardThis]()
        {
            if (!kGuardThis.isNull())
            {
                kGuardThis->flushPendingRows();
            }
        }))
    {
        return;
    }

    std::vector<CapturedEventRow> rowList;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        const std::size_t kTakeCount = std::min(kUiFlushRowLimit, pendingRows_.size());
        rowList.reserve(kTakeCount);
        for (std::size_t index = 0; index < kTakeCount; ++index)
        {
            rowList.push_back(std::move(pendingRows_.front()));
            pendingRows_.pop_front();
        }
    }

    if (rowList.empty())
    {
        refreshTimelineRange(false);
        if (!captureRunning_.load() && uiUpdateTimer_ != nullptr)
        {
            uiUpdateTimer_->stop();
        }
        return;
    }

    const bool kUpdatesEnabled = eventTable_->updatesEnabled();
    eventTable_->setUpdatesEnabled(false);
    QElapsedTimer budgetTimer;
    budgetTimer.start();
    std::size_t renderedCount = 0;
    for (const CapturedEventRow& rowValue : rowList)
    {
        appendEventRow(rowValue);
        ++renderedCount;
        if (budgetTimer.elapsed() >= kUiFlushBudgetMs)
        {
            break;
        }
    }

    const int kRemoveCount = std::max(0, eventTable_->rowCount() - 12000);
    if (kRemoveCount > 0 && eventTable_->model() != nullptr)
    {
        eventTable_->model()->removeRows(0, kRemoveCount);
        const std::size_t kTimelineEraseCount = std::min(
            static_cast<std::size_t>(kRemoveCount),
            timelineEventPoints_.size());
        timelineEventPoints_.erase(
            timelineEventPoints_.begin(),
            timelineEventPoints_.begin() + static_cast<std::ptrdiff_t>(kTimelineEraseCount));
    }

    eventTable_->setUpdatesEnabled(kUpdatesEnabled);
    if (kUpdatesEnabled && eventTable_->viewport() != nullptr)
    {
        eventTable_->viewport()->update();
    }

    if (renderedCount < rowList.size())
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        for (std::size_t index = rowList.size(); index > renderedCount; --index)
        {
            pendingRows_.push_front(std::move(rowList[index - 1]));
        }
        while (pendingRows_.size() > kPendingRowCapacity)
        {
            pendingRows_.pop_back();
            ++pendingDroppedRows_;
        }
    }

    refreshTimelineRange(false);
    const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
    if (!captureRunning_.load() || (kNowMs - lastTimelineRefreshMs_) >= 250)
    {
        refreshTimelinePoints();
        lastTimelineRefreshMs_ = kNowMs;
    }

    if (hasAnyEventFilterActive())
    {
        applyEventFilter();
    }
    else
    {
        updateEventFilterStatusText(eventTable_->rowCount(), eventTable_->rowCount());
    }
    updateActionState();
    updateStatusLabel();

    if (eventKeepBottomCheck_ != nullptr
        && eventKeepBottomCheck_->isChecked()
        && eventTable_ != nullptr)
    {
        eventTable_->scrollToBottom();
    }
}

void ProcessTraceMonitorWidget::appendEventRow(const CapturedEventRow& rowValue)
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    const int kRow = eventTable_->rowCount();
    eventTable_->insertRow(kRow);

    QTableWidgetItem* timeItem = createReadOnlyItem(rowValue.time100nsText);
    timeItem->setData(kEventRoleTime100nsValue, QVariant::fromValue<qulonglong>(
        static_cast<qulonglong>(rowValue.time100ns)));
    timeItem->setData(
        kEventRoleProcessSearchText,
        QStringLiteral("%1 | %2 | %3 | %4")
        .arg(rowValue.pidText, rowValue.processText, rowValue.rootPidText, rowValue.relationText));
    timeItem->setData(
        kEventRoleEventSearchText,
        QStringLiteral("%1 | %2").arg(rowValue.eventName, QString::number(rowValue.eventId)));
    timeItem->setData(
        kEventRoleGlobalSearchText,
        QStringLiteral("%1 | %2 | %3 | %4 | %5 | %6 | %7 | %8 | %9 | %10")
        .arg(
            rowValue.typeText,
            rowValue.providerText,
            QString::number(rowValue.eventId),
            rowValue.eventName,
            rowValue.pidText,
            rowValue.processText,
            rowValue.rootPidText,
            rowValue.relationText,
            rowValue.detailText,
            rowValue.activityIdText));

    eventTable_->setItem(kRow, kEventColumnTime100ns, timeItem);
    eventTable_->setItem(kRow, kEventColumnType, createReadOnlyItem(rowValue.typeText));
    eventTable_->setItem(kRow, kEventColumnProvider, createReadOnlyItem(rowValue.providerText));
    eventTable_->setItem(kRow, kEventColumnEventId, createReadOnlyItem(QString::number(rowValue.eventId)));
    eventTable_->setItem(kRow, kEventColumnEventName, createReadOnlyItem(rowValue.eventName));
    eventTable_->setItem(kRow, kEventColumnPidTid, createReadOnlyItem(rowValue.pidText));
    eventTable_->setItem(kRow, kEventColumnProcess, createReadOnlyItem(rowValue.processText));
    eventTable_->setItem(kRow, kEventColumnRootPid, createReadOnlyItem(rowValue.rootPidText));
    eventTable_->setItem(kRow, kEventColumnRelation, createReadOnlyItem(rowValue.relationText));
    eventTable_->setItem(kRow, kEventColumnDetail, createReadOnlyItem(rowValue.detailText));
    eventTable_->setItem(kRow, kEventColumnActivityId, createReadOnlyItem(rowValue.activityIdText));

    ProcessTraceTimelineEventPoint pointValue;
    pointValue.time100ns = rowValue.time100ns;
    pointValue.typeText = rowValue.typeText;
    timelineEventPoints_.push_back(std::move(pointValue));
}
