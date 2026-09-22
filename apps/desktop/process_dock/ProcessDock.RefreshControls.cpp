#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::initializeCreateProcessConnections()
{
    if (applicationBrowseButton_ != nullptr)
    {
        connect(applicationBrowseButton_, &QPushButton::clicked, this, [this]() {
            browseCreateProcessApplicationPath();
            });
    }
    if (currentDirectoryBrowseButton_ != nullptr)
    {
        connect(currentDirectoryBrowseButton_, &QPushButton::clicked, this, [this]() {
            browseCreateProcessCurrentDirectory();
            });
    }
    if (launchProcessButton_ != nullptr)
    {
        connect(launchProcessButton_, &QPushButton::clicked, this, [this]() {
            executeCreateProcessRequest();
            });
    }
    if (resetCreateFormButton_ != nullptr)
    {
        connect(resetCreateFormButton_, &QPushButton::clicked, this, [this]() {
            resetCreateProcessForm();
            });
    }
    if (applyTokenPrivilegeButton_ != nullptr)
    {
        connect(applyTokenPrivilegeButton_, &QPushButton::clicked, this, [this]() {
            executeApplyTokenPrivilegeEditsOnly();
            });
    }
    if (resetTokenPrivilegeButton_ != nullptr && tokenPrivilegeTable_ != nullptr)
    {
        connect(resetTokenPrivilegeButton_, &QPushButton::clicked, this, [this]() {
            for (int row = 0; row < tokenPrivilegeTable_->rowCount(); ++row)
            {
                QComboBox* actionCombo = qobject_cast<QComboBox*>(tokenPrivilegeTable_->cellWidget(row, 1));
                if (actionCombo != nullptr)
                {
                    actionCombo->setCurrentIndex(0);
                }
            }
            appendCreateResultLine("已重置全部特权动作到“保持”。");
            });
    }

    // After selecting the application path, automatically fill lpCommandLine if empty to facilitate quick execution.
    if (applicationNameEdit_ != nullptr && commandLineEdit_ != nullptr)
    {
        connect(applicationNameEdit_, &QLineEdit::textChanged, this, [this](const QString& textValue) {
            if (textValue.trimmed().isEmpty())
            {
                return;
            }
            if (commandLineEdit_->text().trimmed().isEmpty())
            {
                commandLineEdit_->setText(QStringLiteral("\"%1\"").arg(textValue.trimmed()));
            }
            });
    }

    if (createMethodCombo_ != nullptr && tokenSourcePidEdit_ != nullptr)
    {
        connect(createMethodCombo_, &QComboBox::currentIndexChanged, this, [this](const int indexValue) {
            const bool kTokenMode = (indexValue == 1);
            tokenSourcePidEdit_->setEnabled(kTokenMode);
            tokenDesiredAccessEdit_->setEnabled(kTokenMode);
            tokenDuplicatePrimaryCheck_->setEnabled(kTokenMode);
            tokenPrivilegeTable_->setEnabled(kTokenMode);
            applyTokenPrivilegeButton_->setEnabled(kTokenMode);
            resetTokenPrivilegeButton_->setEnabled(kTokenMode);
            appendCreateResultLine(kTokenMode
                ? "已切换到 Token 创建模式。"
                : "已切换到普通 CreateProcessW 模式。");
            });
        createMethodCombo_->setCurrentIndex(0);
    }

    // Synchronize bit-flag editing:
    // - Automatically combine checkboxes into a bitmask and write back to the input field.
    // - Manual modification of the input box refreshes the checkbox state in reverse.
    bindBitmaskEditor(creationFlagsEdit_, &creationFlagChecks_, "dwCreationFlags");
    bindBitmaskEditor(siFlagsEdit_, &startupFlagChecks_, "STARTUPINFO.dwFlags");
    bindBitmaskEditor(siFillAttributeEdit_, &startupFillAttributeChecks_, "STARTUPINFO.dwFillAttribute");
    bindBitmaskEditor(tokenDesiredAccessEdit_, &tokenDesiredAccessChecks_, "Token DesiredAccess");

    const bool kTokenMode = (createMethodCombo_ != nullptr && createMethodCombo_->currentIndex() == 1);
    if (tokenSourcePidEdit_ != nullptr) tokenSourcePidEdit_->setEnabled(kTokenMode);
    if (tokenDesiredAccessEdit_ != nullptr) tokenDesiredAccessEdit_->setEnabled(kTokenMode);
    if (tokenDuplicatePrimaryCheck_ != nullptr) tokenDuplicatePrimaryCheck_->setEnabled(kTokenMode);
    if (tokenPrivilegeTable_ != nullptr) tokenPrivilegeTable_->setEnabled(kTokenMode);
    if (applyTokenPrivilegeButton_ != nullptr) applyTokenPrivilegeButton_->setEnabled(kTokenMode);
    if (resetTokenPrivilegeButton_ != nullptr) resetTokenPrivilegeButton_->setEnabled(kTokenMode);
}

void ProcessDock::initializeTimer()
{
    // Periodic monitoring timer:
    // - By default, performs background process refresh and activity sampling every 1 second.
    // - Whether the process table below is repainted is throttled by an independent 'List Refresh (s)' input.
    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(refreshIntervalMillisecondsFromInput());
    connect(refreshTimer_, &QTimer::timeout, this, [this]() {
        requestAsyncRefresh(false);
    });
    // Do not start before the first display to prevent background refresh from running prematurely during main window startup.
}

int ProcessDock::refreshIntervalMillisecondsFromInput() const
{
    // The spin control itself restricts values to a valid range; if the control is missing, fall back to a default of 1s.
    // clamp is retained as a fallback to ensure the control range always matches the timer's upper and lower limit constants.
    const double kSafeSeconds = (refreshIntervalSpin_ != nullptr)
        ? refreshIntervalSpin_->value()
        : 1.0;
    const double kClampedSeconds = std::clamp(
        kSafeSeconds,
        static_cast<double>(kActivityMinimumIntervalMilliseconds) / 1000.0,
        static_cast<double>(kActivityMaximumIntervalMilliseconds) / 1000.0);
    const int kMilliseconds = static_cast<int>(std::llround(kClampedSeconds * 1000.0));
    return std::clamp(
        kMilliseconds,
        kActivityMinimumIntervalMilliseconds,
        kActivityMaximumIntervalMilliseconds);
}

void ProcessDock::applyRefreshIntervalInput()
{
    const int kIntervalMs = refreshIntervalMillisecondsFromInput();
    const double kNormalizedSeconds = static_cast<double>(kIntervalMs) / 1000.0;

    // Write back the normalized value: when the control range matches the constant, it is a no-op write;
    // if a discrepancy arises later, the UI will still display the interval actually used by the timer.
    if (refreshIntervalSpin_ != nullptr)
    {
        QSignalBlocker blocker(refreshIntervalSpin_);
        refreshIntervalSpin_->setValue(kNormalizedSeconds);
    }

    if (refreshTimer_ != nullptr)
    {
        refreshTimer_->setInterval(kIntervalMs);
        if (monitoringEnabled_ && isProcessActivityRefreshAllowedNow())
        {
            refreshTimer_->start(kIntervalMs);
        }
    }
    updateProcessActivityStatusLabel();

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 活动采样/后台监视间隔变更为 "
        << kIntervalMs
        << " ms。"
        << eol;
}

int ProcessDock::tableRefreshIntervalMillisecondsFromInput() const
{
    // Table refresh defaults to 2 seconds; this value affects only UI repainting, not background sampling.
    const double kSafeSeconds = (tableRefreshIntervalSpin_ != nullptr)
        ? tableRefreshIntervalSpin_->value()
        : 2.0;
    const double kClampedSeconds = std::clamp(
        kSafeSeconds,
        static_cast<double>(kProcessTableMinimumIntervalMilliseconds) / 1000.0,
        static_cast<double>(kProcessTableMaximumIntervalMilliseconds) / 1000.0);
    const int kMilliseconds = static_cast<int>(std::llround(kClampedSeconds * 1000.0));
    return std::clamp(
        kMilliseconds,
        kProcessTableMinimumIntervalMilliseconds,
        kProcessTableMaximumIntervalMilliseconds);
}

void ProcessDock::applyTableRefreshIntervalInput()
{
    const int kIntervalMs = tableRefreshIntervalMillisecondsFromInput();
    const double kNormalizedSeconds = static_cast<double>(kIntervalMs) / 1000.0;

    // Write back the normalized value to ensure the UI displays the exact interval actually used by the timer.
    if (tableRefreshIntervalSpin_ != nullptr)
    {
        QSignalBlocker blocker(tableRefreshIntervalSpin_);
        tableRefreshIntervalSpin_->setValue(kNormalizedSeconds);
    }

    updateProcessActivityStatusLabel();

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 进程表格刷新间隔变更为 "
        << kIntervalMs
        << " ms。"
        << eol;
}

void ProcessDock::focusProcessSearchBox(const bool selectAllText)
{
    if (processSearchLineEdit_ == nullptr)
    {
        return;
    }

    // Use singleShot(0) to defer the focus action to the end of the current event loop:
    // - Avoid focus competition with internal tab switching and display events.
    // - Ensure users can immediately start typing search terms right after switching pages.
    QPointer<QLineEdit> guardSearchLineEdit(processSearchLineEdit_);
    QTimer::singleShot(0, this, [guardSearchLineEdit, selectAllText]() {
        if (guardSearchLineEdit == nullptr)
        {
            return;
        }

        guardSearchLineEdit->setFocus(Qt::ShortcutFocusReason);
        if (selectAllText)
        {
            guardSearchLineEdit->selectAll();
        }
    });
}

QString ProcessDock::currentProcessSearchText() const
{
    if (processSearchLineEdit_ == nullptr)
    {
        return QString();
    }

    return processSearchLineEdit_->text().trimmed();
}

bool ProcessDock::processRecordMatchesSearch(const ks::process::ProcessRecord& processRecord) const
{
    const QString kSearchText = currentProcessSearchText();
    if (kSearchText.isEmpty())
    {
        return true;
    }

    // Explicit PID filter syntax:
    // - The crosshair picker writes pid:<number> to ensure convergence to the process belonging to the target window;
    // - Keep the original fuzzy search behavior for plain numeric input to preserve existing user habits.
    const QString kLowerSearchText = kSearchText.toLower();
    if (kLowerSearchText.startsWith(QStringLiteral("pid:")) ||
        kLowerSearchText.startsWith(QStringLiteral("pid=")))
    {
        bool pidParseOk = false;
        const std::uint32_t kFilterPid = kSearchText.mid(4).trimmed().toUInt(&pidParseOk);
        if (pidParseOk)
        {
            return processRecord.pid == kFilterPid;
        }
    }

    // Search field coverage:
    // - Process name, PID, path, command line, user, signature, start time, and parent PID.
    // - Use case-insensitive contains() for fuzzy matching to enable fast location.
    const QStringList kSearchableFields{
        QString::fromStdString(processRecord.processName),
        QString::number(processRecord.pid),
        QString::fromStdString(processRecord.imagePath),
        QString::fromStdString(processRecord.r0ImagePath),
        QString::fromStdString(processRecord.commandLine),
        QString::fromStdString(processRecord.userName),
        QString::fromStdString(processRecord.signatureState),
        processR0StatusText(processRecord.r0Status),
        processFieldSourceText(processRecord.r0ProtectionSource),
        QString::fromStdString(processRecord.startTimeText),
        QString::number(processRecord.parentPid)
    };
    for (const QString& fieldText : kSearchableFields)
    {
        if (fieldText.contains(kSearchText, Qt::CaseInsensitive))
        {
            return true;
        }
    }

    return false;
}

void ProcessDock::applyDefaultColumnWidths()
{
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kName), 280);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPid), 80);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kCpu), 80);
    processTable_->setColumnWidth(
        toColumnIndex(TableColumn::kCpuCore),
        ks::ui::processCpuCapacityCellSizeHint(
            processTable_->fontMetrics(),
            logicalCpuCount_).width());
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kRam), 90);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kDisk), 95);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kGpu), 80);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kNet), 95);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kSignature), 260);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPath), 280);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kParentPid), 90);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kCommandLine), 320);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kUser), 180);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kStartTime), 160);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kIsAdmin), 90);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPplLevel), 220);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kProtection), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPpl), 120);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kHandleCount), 90);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kHandleTable), 180);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kSectionObject), 180);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kR0Status), 130);

    // ======== Task Manager column alignment ======== Widths estimated based on 'header text +
    // typical value'; user-adjusted widths are preserved by the global column width adapter.
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPackageName), 280);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kStatus), 90);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kSessionId), 80);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kJobObject), 100);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kInjectionSurface), 170);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kCpuTime), 100);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kCycleTime), 140);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kWorkingSet), 120);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPeakWorkingSet), 150);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kWorkingSetDelta), 150);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kActivePrivateWorkingSet), 190);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPrivateWorkingSet), 160);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kSharedWorkingSet), 160);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kCommitSize), 110);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPagedPool), 120);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kNonPagedPool), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPageFaults), 110);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPageFaultDelta), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kBasePriority), 100);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kThreadCount), 70);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kUserObjects), 90);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kGdiObjects), 90);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kIoReads), 100);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kIoWrites), 100);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kIoOther), 100);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kIoReadBytes), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kIoWriteBytes), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kIoOtherBytes), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kOsContext), 140);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPlatform), 90);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kUacVirtualization), 110);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kDescription), 260);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kDataExecutionPrevention), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kControlFlowGuard), 120);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kHardwareStackProtection), 190);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kEnterpriseContext), 110);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kDpiAwareness), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kPowerThrottling), 100);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kGpuEngine), 130);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kGpuDedicatedMemory), 140);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kGpuSharedMemory), 140);
    processTable_->setColumnWidth(toColumnIndex(TableColumn::kProcessType), 110);
}
