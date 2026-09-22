#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    // openKswordArkDriverHandle：
    // - Purpose: Connect to the KswordARK control device via ArkDriverClient.
    // - Returns a move-only handle object to prevent the Dock from directly calling CloseHandle.
    ksword::ark::DriverHandle openKswordArkDriverHandle(std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        const ksword::ark::DriverClient kDriverClient;
        ksword::ark::DriverHandle driverHandle = kDriverClient.open();
        if (driverHandle.isValid())
        {
            return driverHandle;
        }

        if (detailTextOut != nullptr)
        {
            const DWORD kLastError = ::GetLastError();
            std::ostringstream oss;
            oss << "open KswordARK driver failed, error=" << kLastError;
            *detailTextOut = oss.str();
        }
        return driverHandle;
    }

    // deletePathByR0Driver：
    // - Purpose: Send an IOCTL to ArkDriverClient to delete a single path;
    // - The isDirectory parameter is used by the driver to select directory or file open semantics.
    bool deletePathByR0Driver(
        ksword::ark::DriverHandle& driverHandle,
        const QString& path,
        const bool isDirectory,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (!driverHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid driver handle";
            }
            return false;
        }

        const QString kDriverNtPath = buildDriverNtPath(path);
        if (kDriverNtPath.isEmpty())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "empty path";
            }
            return false;
        }

        const std::wstring kNtPathText = kDriverNtPath.toStdWString();
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kResult = kDriverClient.deletePath(driverHandle, kNtPathText, isDirectory);
        if (detailTextOut != nullptr)
        {
            std::ostringstream oss;
            oss << "path=" << QDir::toNativeSeparators(path).toStdString()
                << ", directory=" << (isDirectory ? 1 : 0)
                << ", bytesReturned=" << kResult.bytesReturned;
            if (kResult.ok)
            {
                oss << ", ioctl=ok";
            }
            else
            {
                oss << ", ioctl=fail, error=" << kResult.win32Error;
                if (!kResult.message.empty())
                {
                    oss << ", detail=" << kResult.message;
                }
            }
            *detailTextOut = oss.str();
        }
        return kResult.ok;
    }

    bool shouldFallbackFileIntegrityToR3(
        const ksword::ark::IoResult& io,
        const bool unsupported)
    {
        // Input: ArkDriverClient communication result and unsupported flag.
        // Note: Classify driver unloading, missing IOCTLs in older drivers, or requests that cannot be sent via the current R0 protocol as R3 fallback.
        // Returns: true indicates R3 can be attempted; returns false when R0 has already returned a semantic failure to avoid masking the cause of a ZwSetSecurityObject failure.
        if (io.ok)
        {
            return false;
        }
        if (unsupported)
        {
            return true;
        }

        return io.win32Error == ERROR_FILE_NOT_FOUND ||
            io.win32Error == ERROR_PATH_NOT_FOUND ||
            io.win32Error == ERROR_SERVICE_DOES_NOT_EXIST ||
            io.win32Error == ERROR_INVALID_FUNCTION ||
            io.win32Error == ERROR_NOT_SUPPORTED ||
            io.win32Error == ERROR_INVALID_PARAMETER;
    }

    DWORD setFileIntegrityLevelByR0ThenR3(
        const QString& filePath,
        const DWORD integrityRid,
        QString* const detailText)
    {
        // Input: Win32/Qt file path and Mandatory Label RID.
        // Handling: Convert path to driver NT path and call R0 first; fall back to SetNamedSecurityInfoW if driver is unavailable or outdated.
        // Returns: ERROR_SUCCESS indicates R0 or fallback R3 success; on failure, returns a Win32 or NTSTATUS value and writes to detailText.
        if (!isSupportedFileMandatoryIntegrityRid(integrityRid))
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("unsupported file mandatory label RID=0x%1; "
                    "file objects only support Untrusted/Low/Medium/MediumPlus/High/System")
                    .arg(integrityRid, 0, 16);
            }
            return ERROR_INVALID_PARAMETER;
        }

        const QString kDriverNtPath = buildDriverNtPath(filePath);
        if (kDriverNtPath.isEmpty())
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("empty path");
            }
            return ERROR_INVALID_PARAMETER;
        }

        const QFileInfo kFileInfo(filePath);
        const bool kIsDirectory = kFileInfo.isDir();
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::FileIntegrityResult kR0Result =
            kDriverClient.setFileIntegrity(kDriverNtPath.toStdWString(), kIsDirectory, integrityRid);
        const bool kR0Applied = kR0Result.io.ok &&
            kR0Result.status == KSWORD_ARK_FILE_INTEGRITY_STATUS_APPLIED &&
            kR0Result.lastStatus >= 0;
        if (kR0Applied)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("R0 ok: %1, ntPath=%2")
                    .arg(QString::fromStdString(kR0Result.io.message))
                    .arg(kDriverNtPath);
            }
            return ERROR_SUCCESS;
        }

        if (shouldFallbackFileIntegrityToR3(kR0Result.io, kR0Result.unsupported))
        {
            QString r3DetailText;
            const DWORD kR3Result = setFileIntegrityLevelByPath(
                filePath,
                integrityRid,
                &r3DetailText);
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("R0 unavailable/unsupported: %1 | R3 %2: %3")
                    .arg(QString::fromStdString(kR0Result.io.message))
                    .arg(kR3Result == ERROR_SUCCESS ? QStringLiteral("ok") : QStringLiteral("failed"))
                    .arg(r3DetailText.isEmpty() ? QStringLiteral("no detail") : r3DetailText);
            }
            return kR3Result;
        }

        if (detailText != nullptr)
        {
            *detailText = QStringLiteral("R0 failed: %1, status=%2, nt=0x%3, win32=%4, ntPath=%5")
                .arg(QString::fromStdString(kR0Result.io.message))
                .arg(kR0Result.status)
                .arg(static_cast<unsigned long>(kR0Result.lastStatus), 0, 16)
                .arg(kR0Result.io.win32Error)
                .arg(kDriverNtPath);
        }
        if (!kR0Result.io.ok)
        {
            return kR0Result.io.win32Error == ERROR_SUCCESS
                ? ERROR_GEN_FAILURE
                : kR0Result.io.win32Error;
        }
        return kR0Result.lastStatus == 0
            ? ERROR_GEN_FAILURE
            : static_cast<DWORD>(kR0Result.lastStatus);
    }

    // terminateProcessByR0Driver：
    // - Purpose: Reuse the same ArkDriverClient handle to send the process termination IOCTL.
    // - Returns true if the driver succeeds; false if the driver fails or the handle is invalid.
    bool terminateProcessByR0Driver(
        ksword::ark::DriverHandle& driverHandle,
        const std::uint32_t processId,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (!driverHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid driver handle";
            }
            return false;
        }

        if (processId == 0U || processId <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::IoResult kResult = kDriverClient.terminateProcess(
            driverHandle,
            processId,
            static_cast<long>(0xC0000005u));
        if (detailTextOut != nullptr)
        {
            *detailTextOut = kResult.message;
        }
        return kResult.ok;
    }

    bool terminateProcessByR3(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (processId == 0U || processId <= 4U || processId == static_cast<std::uint32_t>(::GetCurrentProcessId()))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        // Verify the PID using the creation time from the scan, and terminate the process using the same verified handle.
        // The old process object cannot be destroyed while holding this handle, so the PID cannot be reused by another process.
        HANDLE processHandle = nullptr;
        std::string identityDetailText;
        if (!ks::file::openProcessForVerifiedAction(
                processId,
                expectedCreationTime,
                PROCESS_TERMINATE | SYNCHRONIZE,
                processHandle,
                identityDetailText))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = identityDetailText;
            }
            return false;
        }

        const BOOL kTerminateResult = ::TerminateProcess(processHandle, static_cast<UINT>(0xC0000005U));
        const DWORD kTerminateError = kTerminateResult == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(processHandle);
        const bool kTerminateOk = kTerminateResult != FALSE;

        if (detailTextOut != nullptr)
        {
            std::ostringstream oss;
            oss << "pid=" << processId;
            if (kTerminateOk)
            {
                oss << ", TerminateProcess=ok";
            }
            else
            {
                oss << ", TerminateProcess=fail, error=" << kTerminateError;
            }
            *detailTextOut = oss.str();
        }
        return kTerminateOk;
    }

    // showUnlockSelectionDialog：
    // - Purpose: Display file unlocker scan results and allow the user to choose to close handles or terminate processes;
    // - Parameter parent: Parent window, used to determine the owner of the modal dialog;
    // - Parameter processCandidateList: List of occupying processes aggregated by PID;
    // - Parameter handleCandidateList: expandable list of closable handles by PID+Handle;
    // - Return: The user-confirmed operation mode and selected targets; accepted=false if cancelled.
    UnlockSelectionResult showUnlockSelectionDialog(
        QWidget* const parent,
        const std::vector<UnlockProcessCandidate>& processCandidateList,
        const std::vector<UnlockHandleCandidate>& handleCandidateList)
    {
        UnlockSelectionResult result;
        if (processCandidateList.empty() && handleCandidateList.empty())
        {
            return result;
        }

        QDialog dialog(parent);
        dialog.setObjectName(QStringLiteral("FileUnlockerSelectionDialog"));
        dialog.setStyleSheet(buildOpaqueStandaloneDialogStyle(dialog.objectName()));
        dialog.setWindowTitle(QStringLiteral("文件解锁器 - 选择操作目标"));
        dialog.resize(1080, 620);

        QVBoxLayout* const kRootLayout = new QVBoxLayout(&dialog);
        QLabel* const kTipLabel = new QLabel(
            QStringLiteral("已扫描到以下占用来源。建议先关闭选中句柄；若仍无法删除/重命名，再改用结束进程兜底。未勾选的目标不会处理。"),
            &dialog);
        kTipLabel->setWordWrap(true);
        kRootLayout->addWidget(kTipLabel);

        QHBoxLayout* const kModeLayout = new QHBoxLayout();
        QLabel* const kModeLabel = new QLabel(QStringLiteral("操作方式："), &dialog);
        QComboBox* const kModeComboBox = new QComboBox(&dialog);
        const bool kHasClosableHandle = std::any_of(
            handleCandidateList.begin(),
            handleCandidateList.end(),
            [](const UnlockHandleCandidate& candidate) {
                return candidate.handleValue != 0U
                    && candidate.processCreationTime != 0U
                    && !candidate.matchedTargetPath.trimmed().isEmpty()
                    && candidate.processId > 4U
                    && !candidate.isCurrentProcess
                    && !candidate.isCriticalProcess;
            });
        kModeComboBox->addItem(QStringLiteral("关闭选中句柄(R3，推荐先尝试)"));
        kModeComboBox->addItem(QStringLiteral("结束选中进程(R3)"));
        kModeComboBox->addItem(QStringLiteral("结束选中进程(R0，更强力)"));
        if (!kHasClosableHandle)
        {
            kModeComboBox->setCurrentIndex(1);
        }
        kModeLayout->addWidget(kModeLabel);
        kModeLayout->addWidget(kModeComboBox, 1);
        kRootLayout->addLayout(kModeLayout);

        QStackedWidget* const kTableStack = new QStackedWidget(&dialog);
        QTableWidget* const kHandleTable = new ks::ui::VisibleTableWidget(static_cast<int>(handleCandidateList.size()), 7, &dialog);
        kHandleTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("选择"),
            QStringLiteral("PID"),
            QStringLiteral("进程名"),
            QStringLiteral("Handle"),
            QStringLiteral("GrantedAccess"),
            QStringLiteral("命中路径"),
            QStringLiteral("说明") });
        kHandleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        kHandleTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        kHandleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        kHandleTable->verticalHeader()->setVisible(false);
        kHandleTable->horizontalHeader()->setStretchLastSection(true);
        installFileTableCopyMenu(kHandleTable, 1);

        QTableWidget* const kProcessTable = new ks::ui::VisibleTableWidget(static_cast<int>(processCandidateList.size()), 6, &dialog);
        kProcessTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("选择"),
            QStringLiteral("PID"),
            QStringLiteral("进程名"),
            QStringLiteral("命中数"),
            QStringLiteral("命中路径"),
            QStringLiteral("说明") });
        kProcessTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        kProcessTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        kProcessTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        kProcessTable->verticalHeader()->setVisible(false);
        kProcessTable->horizontalHeader()->setStretchLastSection(true);
        installFileTableCopyMenu(kProcessTable, 1);

        auto makeTableItem = [](const QString& text, const bool enabled) {
            QTableWidgetItem* const kItem = new QTableWidgetItem(text);
            kItem->setFlags(enabled
                ? (Qt::ItemIsSelectable | Qt::ItemIsEnabled)
                : Qt::ItemIsSelectable);
            return kItem;
            };

        for (int row = 0; row < static_cast<int>(handleCandidateList.size()); ++row)
        {
            const UnlockHandleCandidate& candidate = handleCandidateList[static_cast<std::size_t>(row)];
            const bool kCanCloseHandle = candidate.handleValue != 0U
                && candidate.processCreationTime != 0U
                && !candidate.matchedTargetPath.trimmed().isEmpty()
                && !candidate.isCurrentProcess
                && !candidate.isCriticalProcess
                && candidate.processId > 4U;

            QTableWidgetItem* const kCheckItem = new QTableWidgetItem();
            kCheckItem->setCheckState(Qt::Unchecked);
            kCheckItem->setData(Qt::UserRole, row);
            kCheckItem->setFlags(kCanCloseHandle
                ? (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable | Qt::ItemIsEnabled)
                : (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable));
            kHandleTable->setItem(row, 0, kCheckItem);

            QStringList noteList;
            appendUniqueText(noteList, candidate.objectName);
            appendUniqueText(noteList, candidate.processImagePath);
            appendUniqueText(noteList, candidate.matchRuleText);
            appendUniqueText(noteList, candidate.enumerationSource);
            if (candidate.handleValue == 0U)
            {
                noteList.push_back(QStringLiteral("无句柄值：该来源可能是进程映像/模块映射，不能用 R3 关闭句柄处理"));
            }
            if (candidate.isCurrentProcess)
            {
                noteList.push_back(QStringLiteral("已保护：当前 Ksword 进程，不可关闭句柄"));
            }
            if (candidate.isCriticalProcess)
            {
                noteList.push_back(QStringLiteral("已保护：关键系统进程，不可关闭句柄"));
            }
            if (candidate.processCreationTime == 0U || candidate.matchedTargetPath.trimmed().isEmpty())
            {
                noteList.push_back(QStringLiteral("身份不可验证：请重新扫描后再操作"));
            }

            kHandleTable->setItem(row, 1, makeTableItem(QString::number(candidate.processId), kCanCloseHandle));
            kHandleTable->setItem(row, 2, makeTableItem(candidate.processName.isEmpty() ? QStringLiteral("Unknown") : candidate.processName, kCanCloseHandle));
            kHandleTable->setItem(row, 3, makeTableItem(formatHandleValueText(candidate.handleValue), kCanCloseHandle));
            kHandleTable->setItem(row, 4, makeTableItem(formatHandleValueText(candidate.grantedAccess), kCanCloseHandle));
            kHandleTable->setItem(row, 5, makeTableItem(candidate.matchedTargetPath, kCanCloseHandle));
            kHandleTable->setItem(row, 6, makeTableItem(noteList.join(QStringLiteral("\n")), kCanCloseHandle));
        }

        for (int row = 0; row < static_cast<int>(processCandidateList.size()); ++row)
        {
            const UnlockProcessCandidate& candidate = processCandidateList[static_cast<std::size_t>(row)];
            const bool kProtectedProcess = candidate.isCurrentProcess
                || candidate.isCriticalProcess
                || candidate.processCreationTime == 0U;

            QTableWidgetItem* const kCheckItem = new QTableWidgetItem();
            kCheckItem->setCheckState(Qt::Unchecked);
            kCheckItem->setData(Qt::UserRole, static_cast<qulonglong>(candidate.processId));
            kCheckItem->setFlags(kProtectedProcess
                ? (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable)
                : (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable | Qt::ItemIsEnabled));
            kProcessTable->setItem(row, 0, kCheckItem);

            auto makeTextItem = [kProtectedProcess](const QString& text) {
                QTableWidgetItem* const kItem = new QTableWidgetItem(text);
                kItem->setFlags(kProtectedProcess
                    ? Qt::ItemIsSelectable
                    : (Qt::ItemIsSelectable | Qt::ItemIsEnabled));
                return kItem;
                };

            QStringList noteList;
            appendUniqueText(noteList, candidate.processImagePath);
            for (const QString& ruleText : candidate.matchRuleList)
            {
                appendUniqueText(noteList, ruleText);
            }
            if (candidate.isCurrentProcess)
            {
                noteList.push_back(QStringLiteral("已保护：当前 Ksword 进程，不可选择"));
            }
            if (candidate.isCriticalProcess)
            {
                noteList.push_back(QStringLiteral("已保护：关键系统进程，不可选择"));
            }
            if (candidate.processCreationTime == 0U)
            {
                noteList.push_back(QStringLiteral("身份不可验证：请重新扫描后再操作"));
            }

            kProcessTable->setItem(row, 1, makeTextItem(QString::number(candidate.processId)));
            kProcessTable->setItem(row, 2, makeTextItem(candidate.processName.isEmpty() ? QStringLiteral("Unknown") : candidate.processName));
            kProcessTable->setItem(row, 3, makeTextItem(QString::number(candidate.matchCount)));
            kProcessTable->setItem(row, 4, makeTextItem(candidate.matchedTargetList.join(QStringLiteral("\n"))));
            kProcessTable->setItem(row, 5, makeTextItem(noteList.join(QStringLiteral("\n"))));
        }

        kHandleTable->resizeColumnsToContents();
        kProcessTable->resizeColumnsToContents();
        kTableStack->addWidget(kHandleTable);
        kTableStack->addWidget(kProcessTable);
        kTableStack->setCurrentIndex(kModeComboBox->currentIndex() == 0 ? 0 : 1);
        kRootLayout->addWidget(kTableStack, 1);

        QDialogButtonBox* const kButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        QPushButton* const kSelectAllButton = kButtonBox->addButton(QStringLiteral("全选当前可操作项"), QDialogButtonBox::ActionRole);
        QPushButton* const kClearButton = kButtonBox->addButton(QStringLiteral("清空选择"), QDialogButtonBox::ActionRole);
        kButtonBox->button(QDialogButtonBox::Ok)->setText(kModeComboBox->currentIndex() == 0
            ? QStringLiteral("关闭选中句柄")
            : QStringLiteral("执行选中操作"));
        kButtonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        kRootLayout->addWidget(kButtonBox);

        auto collectSelectedHandles = [&kHandleTable, &handleCandidateList]() {
            std::vector<UnlockHandleCandidate> selectedHandleList;
            for (int row = 0; row < kHandleTable->rowCount(); ++row)
            {
                QTableWidgetItem* const kItem = kHandleTable->item(row, 0);
                if (kItem == nullptr
                    || !(kItem->flags() & Qt::ItemIsEnabled)
                    || kItem->checkState() != Qt::Checked)
                {
                    continue;
                }
                selectedHandleList.push_back(handleCandidateList[static_cast<std::size_t>(row)]);
            }
            return selectedHandleList;
            };

        auto collectSelectedIds = [&kProcessTable, &processCandidateList]() {
            std::vector<std::uint32_t> selectedProcessIdList;
            for (int row = 0; row < kProcessTable->rowCount(); ++row)
            {
                QTableWidgetItem* const kItem = kProcessTable->item(row, 0);
                if (kItem == nullptr
                    || !(kItem->flags() & Qt::ItemIsEnabled)
                    || kItem->checkState() != Qt::Checked)
                {
                    continue;
                }
                selectedProcessIdList.push_back(processCandidateList[static_cast<std::size_t>(row)].processId);
            }
            return selectedProcessIdList;
            };

        auto setCheckedForTable = [](QTableWidget* const targetTable, const Qt::CheckState checkState) {
            for (int row = 0; row < targetTable->rowCount(); ++row)
            {
                QTableWidgetItem* const kItem = targetTable->item(row, 0);
                if (kItem != nullptr && (kItem->flags() & Qt::ItemIsEnabled))
                {
                    kItem->setCheckState(checkState);
                }
            }
            };
        QObject::connect(kSelectAllButton, &QPushButton::clicked, [&kModeComboBox, &kHandleTable, &kProcessTable, &setCheckedForTable]() {
            setCheckedForTable(kModeComboBox->currentIndex() == 0 ? kHandleTable : kProcessTable, Qt::Checked);
            });
        QObject::connect(kClearButton, &QPushButton::clicked, [&kModeComboBox, &kHandleTable, &kProcessTable, &setCheckedForTable]() {
            setCheckedForTable(kModeComboBox->currentIndex() == 0 ? kHandleTable : kProcessTable, Qt::Unchecked);
            });
        QObject::connect(kModeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [&kTableStack, &kButtonBox](const int modeIndex) {
                kTableStack->setCurrentIndex(modeIndex == 0 ? 0 : 1);
                kButtonBox->button(QDialogButtonBox::Ok)->setText(modeIndex == 0
                    ? QStringLiteral("关闭选中句柄")
                    : QStringLiteral("执行选中操作"));
            });
        QObject::connect(kButtonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        QObject::connect(kButtonBox, &QDialogButtonBox::accepted, [&dialog, &kModeComboBox, &collectSelectedHandles, &collectSelectedIds]() {
            if (kModeComboBox->currentIndex() == 0 && collectSelectedHandles().empty())
            {
                return;
            }
            if (kModeComboBox->currentIndex() != 0 && collectSelectedIds().empty())
            {
                return;
            }
            dialog.accept();
            });

        if (dialog.exec() != QDialog::Accepted)
        {
            return result;
        }

        result.accepted = true;
        result.operationMode = kModeComboBox->currentIndex() == 0
            ? UnlockOperationMode::kCloseHandleR3
            : (kModeComboBox->currentIndex() == 2
                ? UnlockOperationMode::kTerminateProcessR0
                : UnlockOperationMode::kTerminateProcessR3);
        if (result.operationMode == UnlockOperationMode::kCloseHandleR3)
        {
            result.selectedHandleList = collectSelectedHandles();
        }
        else
        {
            result.selectedProcessIdList = collectSelectedIds();
        }
        return result;
    }

    // collectOccupyProcessIdsByPath：
    // - Purpose: Call the existing occupancy scanner to extract the set of PIDs occupying the target path.
    // - Note: This runs in R3; results are for display/diagnostics only and must not implicitly terminate processes.
    std::vector<std::uint32_t> collectOccupyProcessIdsByPath(
        const QString& path,
        QStringList* const detailTextListOut)
    {
        if (detailTextListOut != nullptr)
        {
            detailTextListOut->clear();
        }

        const std::vector<QString> kScanTargets{ path };
        const filedock::handleusage::HandleUsageScanResult kScanResult =
            filedock::handleusage::scanHandleUsageByPaths(
                kScanTargets,
                0,
                false);

        std::set<std::uint32_t> processIdSet;
        QStringList processPreviewList;
        constexpr std::size_t kMaxPreviewCount = 6U;
        for (const filedock::handleusage::HandleUsageEntry& entry : kScanResult.entries)
        {
            if (entry.processId == 0U || entry.processId <= 4U)
            {
                continue;
            }

            const std::uint32_t kProcessId = entry.processId;
            const auto kInsertResult = processIdSet.insert(kProcessId);
            if (!kInsertResult.second)
            {
                continue;
            }

            if (processPreviewList.size() < static_cast<int>(kMaxPreviewCount))
            {
                const QString kProcessName =
                    entry.processName.trimmed().isEmpty()
                    ? QStringLiteral("Unknown")
                    : entry.processName.trimmed();
                processPreviewList.push_back(
                    QStringLiteral("%1(%2)").arg(kProcessName).arg(kProcessId));
            }
        }

        if (detailTextListOut != nullptr)
        {
            const QString kDiagnosticText = kScanResult.diagnosticText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : kScanResult.diagnosticText.simplified();
            detailTextListOut->push_back(
                QStringLiteral("occupyScan matched=%1, diagnostic=%2")
                .arg(kScanResult.matchedHandleCount)
                .arg(kDiagnosticText));

            if (!processPreviewList.isEmpty())
            {
                detailTextListOut->push_back(
                    QStringLiteral("occupyPidPreview=%1")
                    .arg(processPreviewList.join(QStringLiteral(", "))));
            }
        }

        return std::vector<std::uint32_t>(processIdSet.begin(), processIdSet.end());
    }
}
