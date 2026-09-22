#include "WinAPIDock.h"
#include "../ui/CodeEditorWidget.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/ThemeStatusRole.h"
#include "../Theme.h"

// ============================================================
// WinAPIDock.Actions.cpp
// Purpose:
// 1) Implement interaction logic, session control, and export capabilities for the WinAPI Dock;
// 2) Centralize management of button actions, filtering, and configuration file writing;
// 3) Decouple from Pipe read logic to reduce coupling between concurrent code and UI code.
// ============================================================

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCompleter>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QPointer>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSaveFile>
#include <QSet>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>

#include <algorithm>
#include <cerrno>
#include <cwchar>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <TlHelp32.h>

namespace
{
    // normalizeRawListForSessionConfig：
    // - Input: Raw configuration multi-line edit text;
    // - Processing: Replace newlines with semicolons to ensure each session INI item is on a single line, while preserving the list delimiter semantics supported by the Agent.
    // - Return: Normalized text safe for writing to raw_modules or raw_denylist.
    QString normalizeRawListForSessionConfig(QString textValue)
    {
        textValue.replace(QStringLiteral("\r\n"), QStringLiteral(";"));
        textValue.replace(u'\r', u';');
        textValue.replace(u'\n', u';');
        return textValue.trimmed();
    }

    // toUtf8StdString：
    // - Purpose: Convert Qt wide-character text into UTF-8 std::string.
    // - Call: Process names returned by Toolhelp need to be bridged to ks::process::ProcessRecord.
    std::string toUtf8StdString(const QString& textValue)
    {
        return textValue.toUtf8().toStdString();
    }

    // collectProcessListLikeMemoryDock：
    // - Purpose: Reuse the Toolhelp snapshot traversal used by the memory page dock to avoid heavy static detail queries for each process.
    // - Call: Invoked on background thread when entering WinAPI page or manually refreshing.
    std::vector<ks::process::ProcessRecord> collectProcessListLikeMemoryDock()
    {
        std::vector<ks::process::ProcessRecord> processList;

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return processList;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle, &processEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            return processList;
        }

        do
        {
            ks::process::ProcessRecord record;
            record.pid = static_cast<std::uint32_t>(processEntry.th32ProcessID);
            record.parentPid = static_cast<std::uint32_t>(processEntry.th32ParentProcessID);
            record.threadCount = static_cast<std::uint32_t>(processEntry.cntThreads);
            record.processName = toUtf8StdString(QString::fromWCharArray(processEntry.szExeFile));
            record.imagePath = ks::process::queryProcessPathByPid(record.pid);

            DWORD sessionId = 0;
            if (::ProcessIdToSessionId(static_cast<DWORD>(record.pid), &sessionId) != FALSE)
            {
                record.sessionId = static_cast<std::uint32_t>(sessionId);
            }

            processList.push_back(std::move(record));
        } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
        std::sort(
            processList.begin(),
            processList.end(),
            [](const ks::process::ProcessRecord& left, const ks::process::ProcessRecord& right) {
                return left.pid < right.pid;
            });
        return processList;
    }

    // processIconForPath：
    // - Purpose: Parses system file icons for the process dropdown.
    // - Processing: Prioritize retrieving the shell icon via imagePath; fall back to the project's built-in process icon on failure.
    // - Return: QIcon directly settable to QComboBox item.
    QIcon processIconForPath(const QString& imagePathText)
    {
        static QFileIconProvider iconProvider;
        if (!imagePathText.trimmed().isEmpty())
        {
            const QIcon kFileIcon = iconProvider.icon(QFileInfo(imagePathText));
            if (!kFileIcon.isNull())
            {
                return kFileIcon;
            }
        }
        return QIcon(QStringLiteral(":/Icon/process_main.svg"));
    }

    // processDisplayName：
    // - Purpose: Convert a process snapshot into the main display text for the dropdown.
    // - Processing: Retain PID, process name, and path so user input fragments match via QCompleter or manual search.
    // - Returns: Single-line candidate text for end users.
    QString processDisplayName(const ks::process::ProcessRecord& record)
    {
        const QString kProcessName = QString::fromStdString(
            record.processName.empty() ? std::string("<Unknown>") : record.processName);
        const QString kImagePathText = QString::fromStdString(record.imagePath);
        if (kImagePathText.trimmed().isEmpty())
        {
            return QStringLiteral("%1  [PID %2]").arg(kProcessName).arg(record.pid);
        }
        return QStringLiteral("%1  [PID %2]  %3").arg(kProcessName).arg(record.pid).arg(kImagePathText);
    }

    // comboIndexForPid：
    // - Purpose: Locate the candidate row in the process combo box based on PID.
    // - Processing: Read the PID saved in Qt::UserRole.
    // - Returns: the index of the matched item, or -1 if not found.
    int comboIndexForPid(QComboBox* comboPointer, const std::uint32_t pidValue)
    {
        if (comboPointer == nullptr || pidValue == 0)
        {
            return -1;
        }
        for (int index = 0; index < comboPointer->count(); ++index)
        {
            if (comboPointer->itemData(index, Qt::UserRole).toUInt() == pidValue)
            {
                return index;
            }
        }
        return -1;
    }

    QString tableCellText(QTableWidget* const tablePointer, const int rowValue, const int columnValue)
    {
        // tableCellText:
        // - Input: a table pointer plus row/column coordinates.
        // - Processing: safely reads the item text and trims user-visible whitespace.
        // - Return: an empty string when the table/item is missing.
        if (tablePointer == nullptr)
        {
            return QString();
        }
        QTableWidgetItem* const kItemPointer = tablePointer->item(rowValue, columnValue);
        return kItemPointer != nullptr ? kItemPointer->text().trimmed() : QString();
    }

    bool containsFakeRuleDelimiter(const QString& textValue)
    {
        // containsFakeRuleDelimiter:
        // - Input: a field that will be serialized into fake_success_rules.
        // - Processing: checks the delimiters used by the Agent parser.
        // - Return: true when the field would corrupt the single-line INI format.
        return textValue.contains('|')
            || textValue.contains(';')
            || textValue.contains(',')
            || textValue.contains('\r')
            || textValue.contains('\n');
    }

    bool parseFakeUnsigned64(const QString& textValue, quint64* valueOut)
    {
        // parseFakeUnsigned64:
        // - Input: decimal or 0x-prefixed integer text; negative values are accepted for two's-complement masks.
        // - Processing: uses wcstoull/wcstoll so 0xFFFFFFFFFFFFFFFF and -1 both become stable uint64 values.
        // - Return: true on full-string parse success, false on empty/invalid text.
        if (valueOut == nullptr)
        {
            return false;
        }

        const QString kNormalizedText = textValue.trimmed();
        if (kNormalizedText.isEmpty())
        {
            return false;
        }

        const std::wstring kWideText = kNormalizedText.toStdWString();
        wchar_t* endPointer = nullptr;
        errno = 0;
        if (kWideText.front() == L'-')
        {
            const long long kParsedValue = std::wcstoll(kWideText.c_str(), &endPointer, 0);
            if (errno != 0 || endPointer == kWideText.c_str() || (endPointer != nullptr && *endPointer != L'\0'))
            {
                return false;
            }
            *valueOut = static_cast<quint64>(kParsedValue);
            return true;
        }

        const unsigned long long kParsedValue = std::wcstoull(kWideText.c_str(), &endPointer, 0);
        if (errno != 0 || endPointer == kWideText.c_str() || (endPointer != nullptr && *endPointer != L'\0'))
        {
            return false;
        }
        *valueOut = static_cast<quint64>(kParsedValue);
        return true;
    }

    QString normalizeFakeIntegerText(const QString& textValue)
    {
        // normalizeFakeIntegerText:
        // - Input: user-entered integer text.
        // - Processing: parses through parseFakeUnsigned64 and emits a canonical decimal uint64 string.
        // - Return: canonical decimal text, or the trimmed original text if parsing unexpectedly fails.
        quint64 parsedValue = 0;
        if (!parseFakeUnsigned64(textValue, &parsedValue))
        {
            return textValue.trimmed();
        }
        return QString::number(parsedValue);
    }

    QString comboCurrentDataText(QComboBox* const comboPointer, const QString& fallbackText)
    {
        // comboCurrentDataText:
        // - Input: a combo box and fallback token.
        // - Processing: returns item data first, then visible text if no data exists.
        // - Return: a stable lower-case token for INI serialization.
        if (comboPointer == nullptr)
        {
            return fallbackText;
        }
        const QString kDataText = comboPointer->currentData().toString().trimmed();
        if (!kDataText.isEmpty())
        {
            return kDataText;
        }
        return comboPointer->currentText().trimmed().toLower();
    }
}

void WinAPIDock::initializeConnections()
{
    if (processCombo_ != nullptr)
    {
        connect(processCombo_, &QComboBox::currentIndexChanged, this, [this](const int) {
            updateProcessSelectorStatus();
            updateActionState();
        });
        if (processCombo_->lineEdit() != nullptr)
        {
            connect(processCombo_->lineEdit(), &QLineEdit::textChanged, this, [this]() {
                updateProcessSelectorStatus();
                updateActionState();
            });
            connect(processCombo_->lineEdit(), &QLineEdit::returnPressed, this, [this]() {
                if (!pipeRunning_.load())
                {
                    startMonitoring();
                }
            });
        }
        connect(processCombo_, QOverload<int>::of(&QComboBox::activated), this, [this](const int) {
            updateProcessSelectorStatus();
            updateActionState();
        });
    }
    if (processRefreshButton_ != nullptr)
    {
        connect(processRefreshButton_, &QPushButton::clicked, this, [this]() {
            refreshProcessListAsync();
        });
    }
    if (browseAgentDllButton_ != nullptr)
    {
        connect(browseAgentDllButton_, &QPushButton::clicked, this, [this]() {
            browseAgentDllPath();
        });
    }
    if (agentDllPathEdit_ != nullptr)
    {
        connect(agentDllPathEdit_, &QLineEdit::textChanged, this, [this]() {
            updateActionState();
        });
    }
    if (manualPidEdit_ != nullptr)
    {
        connect(manualPidEdit_, &QLineEdit::textChanged, this, [this]() {
            updateActionState();
        });
        connect(manualPidEdit_, &QLineEdit::returnPressed, this, [this]() {
            startMonitoring();
        });
    }
    if (rawFallbackCheck_ != nullptr)
    {
        connect(rawFallbackCheck_, &QCheckBox::toggled, this, [this]() {
            updateActionState();
        });
    }
    if (fakeAddRuleButton_ != nullptr)
    {
        connect(fakeAddRuleButton_, &QPushButton::clicked, this, [this]() {
            addFakeSuccessRuleFromInputs();
        });
    }
    if (fakeRemoveRuleButton_ != nullptr)
    {
        connect(fakeRemoveRuleButton_, &QPushButton::clicked, this, [this]() {
            removeSelectedFakeSuccessRule();
        });
    }
    if (fakeApplyRuleButton_ != nullptr)
    {
        connect(fakeApplyRuleButton_, &QPushButton::clicked, this, [this]() {
            if (pipeRunning_.load())
            {
                QMessageBox::information(
                    this,
                    QStringLiteral("Fake Success"),
                    QStringLiteral("当前 Agent 会话已运行。Fake Success 第一版不做热更新，请先停止会话后再应用规则。"));
                return;
            }
            QString errorText;
            if (!validateFakeSuccessRules(&errorText))
            {
                QMessageBox::warning(this, QStringLiteral("Fake Success"), errorText);
                return;
            }
            startMonitoring();
        });
    }
    if (fakeStopRuleButton_ != nullptr)
    {
        connect(fakeStopRuleButton_, &QPushButton::clicked, this, [this]() {
            stopMonitoring();
        });
    }
    if (fakeRuleTable_ != nullptr)
    {
        connect(fakeRuleTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
            updateActionState();
        });
    }
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
    if (terminateHookButton_ != nullptr)
    {
        connect(terminateHookButton_, &QPushButton::clicked, this, [this]() {
            terminateHooksForSelectedProcess();
        });
    }
    if (exportButton_ != nullptr)
    {
        connect(exportButton_, &QPushButton::clicked, this, [this]() {
            exportVisibleRowsToTsv();
        });
    }
    if (clearEventButton_ != nullptr)
    {
        connect(clearEventButton_, &QPushButton::clicked, this, [this]() {
            if (eventTable_ != nullptr && !pipeRunning_.load())
            {
                eventTable_->clearContents();
                eventTable_->setRowCount(0);
                applyEventFilter();
                updateActionState();
                updateStatusLabel();
            }
        });
    }

    if (eventFilterEdit_ != nullptr)
    {
        connect(eventFilterEdit_, &QLineEdit::textChanged, this, [this]() {
            applyEventFilter();
        });
    }
    if (eventFilterClearButton_ != nullptr)
    {
        connect(eventFilterClearButton_, &QPushButton::clicked, this, [this]() {
            clearEventFilter();
        });
    }
    if (eventTable_ != nullptr)
    {
        connect(eventTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            showEventContextMenu(position);
        });
        connect(eventTable_, &QTableWidget::cellDoubleClicked, this, [this](const int row, const int) {
            showEventDetailDialog(row);
        });
    }
    if (uiFlushTimer_ != nullptr)
    {
        connect(uiFlushTimer_, &QTimer::timeout, this, [this]() {
            flushPendingRows();
        });
        uiFlushTimer_->start();
    }
}

void WinAPIDock::refreshProcessListAsync()
{
    if (processRefreshPending_.exchange(true))
    {
        return;
    }

    if (processStatusLabel_ != nullptr)
    {
        processStatusLabel_->setText(QStringLiteral("● 正在刷新系统进程快照..."));
        ks::ui::applyStatusRole(processStatusLabel_, ks::ui::StatusRole::kInfo);
    }
    updateActionState();

    QPointer<WinAPIDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<ks::process::ProcessRecord> processList = collectProcessListLikeMemoryDock();

        QMetaObject::invokeMethod(qApp, [guardThis, processList = std::move(processList)]() {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->processRefreshPending_.store(false);
            guardThis->lastProcessRefreshMs_ = QDateTime::currentMSecsSinceEpoch();
            guardThis->populateProcessSelector(processList);
            guardThis->updateActionState();
        }, Qt::QueuedConnection);
    }).detach();
}

void WinAPIDock::populateProcessSelector(const std::vector<ks::process::ProcessRecord>& processList)
{
    if (processCombo_ == nullptr)
    {
        processList_ = processList;
        return;
    }

    // Clearing and repopulating the dropdown during the popup expansion causes the popup to retain mouse/keyboard focus while its content becomes
    // invalid, resulting in the UI appearing unresponsive after opening the process dropdown. Defer the update until the popup is closed.
    // Defer cache updates as well: process cache and combo-box items must share the same snapshot.
    {
        const QPointer<WinAPIDock> kGuardedSelf(this);
        if (ks::ui::deferUiCommitIfComboBoxPopupOpen(
                this,
                QStringLiteral("winapi-dock-process-selector-apply"),
                [kGuardedSelf, processList]()
                {
                    if (!kGuardedSelf.isNull())
                    {
                        kGuardedSelf->populateProcessSelector(processList);
                    }
                }))
        {
            return;
        }
    }

    processList_ = processList;

    std::uint32_t previousPid = 0;
    (void)currentSelectedPid(&previousPid);
    const QString kPreviousInputText = processCombo_->currentText();

    {
        const QSignalBlocker kComboBlocker(processCombo_);
        QSignalBlocker lineEditBlocker(processCombo_->lineEdit());
        processCombo_->clear();

        for (const ks::process::ProcessRecord& record : processList_)
        {
            const QString kProcessName = QString::fromStdString(
                record.processName.empty() ? std::string("<Unknown>") : record.processName);
            const QString kImagePathText = QString::fromStdString(record.imagePath);
            const QIcon kProcessIcon = processIconForPath(kImagePathText);
            const QString kDisplayText = processDisplayName(record);
            processCombo_->addItem(kProcessIcon, kDisplayText, QVariant::fromValue(static_cast<quint32>(record.pid)));

            const int kItemIndex = processCombo_->count() - 1;
            processCombo_->setItemData(kItemIndex, kProcessName, Qt::UserRole + 1);
            processCombo_->setItemData(kItemIndex, kImagePathText, Qt::UserRole + 2);
            processCombo_->setItemData(kItemIndex, kDisplayText, Qt::ToolTipRole);
        }

        const int kPreviousIndex = comboIndexForPid(processCombo_, previousPid);
        if (kPreviousIndex >= 0)
        {
            processCombo_->setCurrentIndex(kPreviousIndex);
        }
        else
        {
            processCombo_->setCurrentIndex(-1);
            if (processCombo_->lineEdit() != nullptr)
            {
                processCombo_->lineEdit()->setText(kPreviousInputText);
            }
        }
    }

    if (processCombo_->completer() != nullptr)
    {
        processCombo_->completer()->setCaseSensitivity(Qt::CaseInsensitive);
        processCombo_->completer()->setFilterMode(Qt::MatchContains);
        processCombo_->completer()->setCompletionMode(QCompleter::PopupCompletion);
    }

    if (processStatusLabel_ != nullptr)
    {
        processStatusLabel_->setText(QStringLiteral("● 已刷新 %1 个进程").arg(processList_.size()));
        ks::ui::applyStatusRole(processStatusLabel_, ks::ui::StatusRole::kSuccess);
    }
    updateProcessSelectorStatus();
}

void WinAPIDock::updateProcessSelectorStatus()
{
    if (processCombo_ == nullptr)
    {
        return;
    }

    std::uint32_t pidValue = 0;
    const bool kHasPid = currentSelectedPid(&pidValue);
    const int kSelectedIndex = comboIndexForPid(processCombo_, pidValue);
    if (processIconLabel_ != nullptr)
    {
        QIcon displayIcon(QStringLiteral(":/Icon/process_main.svg"));
        if (kSelectedIndex >= 0)
        {
            const QIcon kItemIcon = processCombo_->itemIcon(kSelectedIndex);
            if (!kItemIcon.isNull())
            {
                displayIcon = kItemIcon;
            }
        }
        processIconLabel_->setPixmap(displayIcon.pixmap(20, 20));
    }

    if (processStatusLabel_ == nullptr)
    {
        return;
    }

    if (kHasPid)
    {
        if (kSelectedIndex >= 0)
        {
            const QString kProcessName = processCombo_->itemData(kSelectedIndex, Qt::UserRole + 1).toString();
            processStatusLabel_->setText(QStringLiteral("● 已选择 PID=%1 %2").arg(pidValue).arg(kProcessName));
            ks::ui::applyStatusRole(processStatusLabel_, ks::ui::StatusRole::kSuccess);
        }
        else
        {
            processStatusLabel_->setText(QStringLiteral("● 使用手动 PID=%1").arg(pidValue));
            ks::ui::applyStatusRole(processStatusLabel_, ks::ui::StatusRole::kWarning);
        }
        return;
    }

    const QString kInputText = processCombo_->currentText().trimmed();
    if (kInputText.isEmpty())
    {
        processStatusLabel_->setText(QStringLiteral("● 候选 %1 个；输入进程名/PID 选择目标").arg(processCombo_->count()));
        ks::ui::applyStatusRole(processStatusLabel_, ks::ui::StatusRole::kIdle);
        return;
    }
    processStatusLabel_->setText(QStringLiteral("● 未明确选中目标；请从下拉候选选择或输入数字 PID"));
    ks::ui::applyStatusRole(processStatusLabel_, ks::ui::StatusRole::kWarning);
}

bool WinAPIDock::currentSelectedPid(std::uint32_t* pidOut) const
{
    if (pidOut == nullptr)
    {
        return false;
    }
    *pidOut = 0;

    if (manualPidEdit_ != nullptr)
    {
        const QString kManualPidText = manualPidEdit_->text().trimmed();
        if (!kManualPidText.isEmpty())
        {
            return tryParseUint32Text(kManualPidText, pidOut);
        }
    }

    if (processCombo_ == nullptr)
    {
        return false;
    }

    const QString kInputText = processCombo_->currentText().trimmed();
    const int kComboIndex = processCombo_->currentIndex();
    if (kComboIndex >= 0 && processCombo_->itemText(kComboIndex).trimmed().compare(kInputText, Qt::CaseInsensitive) == 0)
    {
        const std::uint32_t kPidValue = static_cast<std::uint32_t>(
            processCombo_->itemData(kComboIndex, Qt::UserRole).toUInt());
        if (kPidValue != 0)
        {
            *pidOut = kPidValue;
            return true;
        }
    }

    if (kInputText.isEmpty())
    {
        return false;
    }

    if (tryParseUint32Text(kInputText, pidOut))
    {
        return true;
    }

    int matchedIndex = -1;
    const QString kNormalizedInput = kInputText.toLower();
    int exactMatchCount = 0;
    for (int index = 0; index < processCombo_->count(); ++index)
    {
        const QString kDisplayText = processCombo_->itemText(index).trimmed().toLower();
        const QString kNameText = processCombo_->itemData(index, Qt::UserRole + 1).toString().trimmed().toLower();
        if (kDisplayText == kNormalizedInput || kNameText == kNormalizedInput)
        {
            matchedIndex = index;
            ++exactMatchCount;
            if (exactMatchCount > 1)
            {
                matchedIndex = -1;
                break;
            }
        }
    }

    if (matchedIndex < 0)
    {
        int containsMatchCount = 0;
        for (int index = 0; index < processCombo_->count(); ++index)
        {
            const QString kDisplayText = processCombo_->itemText(index).trimmed().toLower();
            const QString kNameText = processCombo_->itemData(index, Qt::UserRole + 1).toString().trimmed().toLower();
            const QString kPathText = processCombo_->itemData(index, Qt::UserRole + 2).toString().trimmed().toLower();
            if (kDisplayText.contains(kNormalizedInput)
                || kNameText.contains(kNormalizedInput)
                || kPathText.contains(kNormalizedInput))
            {
                matchedIndex = index;
                ++containsMatchCount;
                if (containsMatchCount > 1)
                {
                    matchedIndex = -1;
                    break;
                }
            }
        }
    }

    if (matchedIndex < 0)
    {
        return false;
    }

    const std::uint32_t kPidValue = static_cast<std::uint32_t>(
        processCombo_->itemData(matchedIndex, Qt::UserRole).toUInt());
    if (kPidValue == 0)
    {
        return false;
    }

    *pidOut = kPidValue;
    return true;
}

void WinAPIDock::browseAgentDllPath()
{
    const QString kDefaultPath = agentDllPathEdit_ != nullptr
        ? agentDllPathEdit_->text().trimmed()
        : defaultDllPathHint();

    const QString kSelectedPath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("选择 APIMonitor_x64.dll"),
        kDefaultPath,
        QStringLiteral("DLL 文件 (*.dll)"));
    if (kSelectedPath.trimmed().isEmpty())
    {
        return;
    }

    if (agentDllPathEdit_ != nullptr)
    {
        agentDllPathEdit_->setText(QDir::cleanPath(kSelectedPath));
    }
}

bool WinAPIDock::prepareSessionArtifacts(const std::uint32_t pidValue, QString* errorTextOut)
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    const QString kSessionDirectory = QString::fromStdWString(ks::winapi_monitor::buildSessionDirectory());
    QDir sessionDir;
    if (!sessionDir.mkpath(kSessionDirectory))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法创建会话目录：%1").arg(kSessionDirectory);
        }
        return false;
    }

    currentSessionPid_ = pidValue;
    currentPipeName_ = QString::fromStdWString(ks::winapi_monitor::buildPipeNameForPid(pidValue));
    currentConfigPath_ = QString::fromStdWString(ks::winapi_monitor::buildConfigPathForPid(pidValue));
    currentStopFlagPath_ = QString::fromStdWString(ks::winapi_monitor::buildStopFlagPathForPid(pidValue));
    currentSessionId_ = QUuid::createUuid().toString(QUuid::WithoutBraces);
    return true;
}

bool WinAPIDock::hasResidentAgentForProcess(const std::uint32_t pidValue)
{
    // hasResidentAgentForProcess：
    // - Input: pidValue is the target PID for the session being started;
    // - Processing: Confirm the same instance still retains the previously injected resident Agent using PID and process creation time.
    // - Returns: true if the identity is confirmed and reusable; clears the cache and returns false if the identity cannot be confirmed or the PID has been reused.
    if (pidValue == 0 || pidValue != residentAgentPid_ || residentAgentCreationTime100ns_ == 0)
    {
        return false;
    }

    std::uint64_t observedCreationTime100ns = 0;
    if (!ks::process::queryProcessCreationTimeByPid(pidValue, &observedCreationTime100ns, nullptr)
        || observedCreationTime100ns != residentAgentCreationTime100ns_)
    {
        residentAgentPid_ = 0;
        residentAgentCreationTime100ns_ = 0;
        return false;
    }
    return true;
}

void WinAPIDock::rememberResidentAgentForProcess(const std::uint32_t pidValue)
{
    // rememberResidentAgentForProcess：
    // - Input: pidValue is the target PID that has just completed DLL injection;
    // - Processing: Records PID and creation time; reuses an Agent worker currently waiting for the same process instance during subsequent start-stop-start cycles.
    // - Returns: No return value; if identity cannot be read, the cache is actively discarded, and the next session will conservatively re-execute injection.
    std::uint64_t creationTime100ns = 0;
    if (!ks::process::queryProcessCreationTimeByPid(pidValue, &creationTime100ns, nullptr)
        || creationTime100ns == 0)
    {
        residentAgentPid_ = 0;
        residentAgentCreationTime100ns_ = 0;
        return;
    }

    residentAgentPid_ = pidValue;
    residentAgentCreationTime100ns_ = creationTime100ns;
}

QString WinAPIDock::fakeSuccessRulesIniText() const
{
    // fakeSuccessRulesIniText:
    // - Input: the current Fake Success rule table.
    // - Processing: serializes each exact rule as module|api|returnType|returnValue|lastErrorKind|lastErrorValue.
    // - Return: a single INI-safe line; empty means Fake Success is disabled for the session.
    if (fakeRuleTable_ == nullptr || fakeRuleTable_->rowCount() == 0)
    {
        return QString();
    }

    const auto kCellToken = [this](const int rowValue, const int columnValue) -> QString {
        QTableWidgetItem* const kItemPointer = fakeRuleTable_->item(rowValue, columnValue);
        if (kItemPointer == nullptr)
        {
            return QString();
        }
        const QString kDataText = kItemPointer->data(Qt::UserRole).toString().trimmed();
        return kDataText.isEmpty() ? kItemPointer->text().trimmed() : kDataText;
    };

    QStringList serializedRuleList;
    for (int row = 0; row < fakeRuleTable_->rowCount(); ++row)
    {
        serializedRuleList << QStringList{
            kCellToken(row, kFakeRuleColumnModule),
            kCellToken(row, kFakeRuleColumnApi),
            kCellToken(row, kFakeRuleColumnReturnType),
            kCellToken(row, kFakeRuleColumnReturnValue),
            kCellToken(row, kFakeRuleColumnLastErrorKind),
            kCellToken(row, kFakeRuleColumnLastErrorValue)
        }.join('|');
    }
    return serializedRuleList.join(QStringLiteral(";;"));
}

bool WinAPIDock::validateFakeSuccessRules(QString* errorTextOut) const
{
    // validateFakeSuccessRules:
    // - Input: current table rows that will be serialized into the Agent INI.
    // - Processing: checks required fields, delimiter safety, numeric ranges, and duplicate exact module!api keys.
    // - Return: true when all rows can be parsed by APIMonitor_x64; false and an error message otherwise.
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    if (fakeRuleTable_ == nullptr || fakeRuleTable_->rowCount() == 0)
    {
        return true;
    }

    const auto kNormalizedKey = [](QString moduleText, QString apiText) -> QString {
        moduleText = moduleText.trimmed().toLower();
        apiText = apiText.trimmed().toLower();
        if (moduleText.endsWith(QStringLiteral(".dll")))
        {
            moduleText.chop(4);
        }
        return moduleText + QLatin1Char('!') + apiText;
    };

    QSet<QString> seenRuleKeys;
    for (int row = 0; row < fakeRuleTable_->rowCount(); ++row)
    {
        const QString kModuleText = tableCellText(fakeRuleTable_, row, kFakeRuleColumnModule);
        const QString kApiText = tableCellText(fakeRuleTable_, row, kFakeRuleColumnApi);
        const QString kReturnTypeText = tableCellText(fakeRuleTable_, row, kFakeRuleColumnReturnType);
        const QString kReturnValueText = tableCellText(fakeRuleTable_, row, kFakeRuleColumnReturnValue);
        const QString kLastErrorKindText = tableCellText(fakeRuleTable_, row, kFakeRuleColumnLastErrorKind);
        const QString kLastErrorValueText = tableCellText(fakeRuleTable_, row, kFakeRuleColumnLastErrorValue);

        if (kModuleText.isEmpty() || kApiText.isEmpty() || kReturnTypeText.isEmpty()
            || kReturnValueText.isEmpty() || kLastErrorKindText.isEmpty() || kLastErrorValueText.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 第 %1 行存在空字段。").arg(row + 1);
            }
            return false;
        }
        if (containsFakeRuleDelimiter(kModuleText)
            || containsFakeRuleDelimiter(kApiText)
            || containsFakeRuleDelimiter(kReturnTypeText)
            || containsFakeRuleDelimiter(kReturnValueText)
            || containsFakeRuleDelimiter(kLastErrorKindText)
            || containsFakeRuleDelimiter(kLastErrorValueText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 第 %1 行包含非法分隔符（| ; , 或换行）。").arg(row + 1);
            }
            return false;
        }

        quint64 parsedReturnValue = 0;
        if (!parseFakeUnsigned64(kReturnValueText, &parsedReturnValue))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 第 %1 行返回值不是有效整数。").arg(row + 1);
            }
            return false;
        }

        quint64 parsedLastErrorValue = 0;
        if (!parseFakeUnsigned64(kLastErrorValueText, &parsedLastErrorValue) || parsedLastErrorValue > 0xFFFFFFFFULL)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 第 %1 行错误码必须是 0 到 0xFFFFFFFF。").arg(row + 1);
            }
            return false;
        }

        const QString kRuleKey = kNormalizedKey(kModuleText, kApiText);
        if (seenRuleKeys.contains(kRuleKey))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Fake Success 存在重复规则：%1!%2。").arg(kModuleText, kApiText);
            }
            return false;
        }
        seenRuleKeys.insert(kRuleKey);
    }
    return true;
}

void WinAPIDock::addFakeSuccessRuleFromInputs()
{
    // addFakeSuccessRuleFromInputs:
    // - Input: module/API/return/error widgets in the Fake Success panel.
    // - Processing: validates a single exact rule, rejects duplicates, then appends it to the rule table.
    // - Return: no return value; user-facing errors are shown with QMessageBox.
    if (fakeRuleTable_ == nullptr || pipeRunning_.load())
    {
        return;
    }

    const QString kModuleText = fakeModuleEdit_ != nullptr ? fakeModuleEdit_->text().trimmed() : QString();
    const QString kApiText = fakeApiEdit_ != nullptr ? fakeApiEdit_->text().trimmed() : QString();
    const QString kReturnTypeToken = comboCurrentDataText(fakeReturnTypeCombo_, QStringLiteral("scalar"));
    const QString kReturnTypeDisplay = fakeReturnTypeCombo_ != nullptr
        ? fakeReturnTypeCombo_->currentText().trimmed()
        : kReturnTypeToken;
    const QString kReturnValueText = fakeReturnValueEdit_ != nullptr ? fakeReturnValueEdit_->text().trimmed() : QString();
    const QString kLastErrorKindToken = comboCurrentDataText(fakeLastErrorKindCombo_, QStringLiteral("none"));
    const QString kLastErrorKindDisplay = fakeLastErrorKindCombo_ != nullptr
        ? fakeLastErrorKindCombo_->currentText().trimmed()
        : kLastErrorKindToken;
    const QString kLastErrorValueText = fakeLastErrorValueEdit_ != nullptr ? fakeLastErrorValueEdit_->text().trimmed() : QStringLiteral("0");

    if (kModuleText.isEmpty() || kApiText.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("Fake Success"), QStringLiteral("请填写模块名和 API 导出名。"));
        return;
    }
    if (containsFakeRuleDelimiter(kModuleText) || containsFakeRuleDelimiter(kApiText))
    {
        QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("模块名和 API 名不能包含 | ; , 或换行。"));
        return;
    }

    quint64 parsedReturnValue = 0;
    if (!parseFakeUnsigned64(kReturnValueText, &parsedReturnValue))
    {
        QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("返回值不是有效整数。支持十进制、0x 十六进制和 -1。"));
        return;
    }

    quint64 parsedLastErrorValue = 0;
    if (!parseFakeUnsigned64(kLastErrorValueText, &parsedLastErrorValue) || parsedLastErrorValue > 0xFFFFFFFFULL)
    {
        QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("错误码必须是 0 到 0xFFFFFFFF。"));
        return;
    }

    const auto kNormalizedKey = [](QString moduleValue, QString apiValue) -> QString {
        moduleValue = moduleValue.trimmed().toLower();
        apiValue = apiValue.trimmed().toLower();
        if (moduleValue.endsWith(QStringLiteral(".dll")))
        {
            moduleValue.chop(4);
        }
        return moduleValue + QLatin1Char('!') + apiValue;
    };
    const QString kNewRuleKey = kNormalizedKey(kModuleText, kApiText);
    for (int row = 0; row < fakeRuleTable_->rowCount(); ++row)
    {
        if (kNormalizedKey(
            tableCellText(fakeRuleTable_, row, kFakeRuleColumnModule),
            tableCellText(fakeRuleTable_, row, kFakeRuleColumnApi)) == kNewRuleKey)
        {
            QMessageBox::warning(this, QStringLiteral("Fake Success"), QStringLiteral("已存在相同 module!api 的规则。"));
            return;
        }
    }

    const int kRow = fakeRuleTable_->rowCount();
    fakeRuleTable_->insertRow(kRow);

    QTableWidgetItem* moduleItem = createReadOnlyItem(kModuleText);
    QTableWidgetItem* apiItem = createReadOnlyItem(kApiText);
    QTableWidgetItem* returnTypeItem = createReadOnlyItem(kReturnTypeDisplay);
    QTableWidgetItem* returnValueItem = createReadOnlyItem(QString::number(parsedReturnValue));
    QTableWidgetItem* lastErrorKindItem = createReadOnlyItem(kLastErrorKindDisplay);
    QTableWidgetItem* lastErrorValueItem = createReadOnlyItem(QString::number(parsedLastErrorValue));

    returnTypeItem->setData(Qt::UserRole, kReturnTypeToken);
    returnValueItem->setData(Qt::UserRole, QString::number(parsedReturnValue));
    lastErrorKindItem->setData(Qt::UserRole, kLastErrorKindToken);
    lastErrorValueItem->setData(Qt::UserRole, QString::number(parsedLastErrorValue));

    fakeRuleTable_->setItem(kRow, kFakeRuleColumnModule, moduleItem);
    fakeRuleTable_->setItem(kRow, kFakeRuleColumnApi, apiItem);
    fakeRuleTable_->setItem(kRow, kFakeRuleColumnReturnType, returnTypeItem);
    fakeRuleTable_->setItem(kRow, kFakeRuleColumnReturnValue, returnValueItem);
    fakeRuleTable_->setItem(kRow, kFakeRuleColumnLastErrorKind, lastErrorKindItem);
    fakeRuleTable_->setItem(kRow, kFakeRuleColumnLastErrorValue, lastErrorValueItem);
    fakeRuleTable_->selectRow(kRow);

    if (fakeRuleStatusLabel_ != nullptr)
    {
        fakeRuleStatusLabel_->setText(QStringLiteral("规则：%1 条；启动会话时应用。").arg(fakeRuleTable_->rowCount()));
        ks::ui::applyStatusRole(fakeRuleStatusLabel_, ks::ui::StatusRole::kInfo);
    }
    updateActionState();
}

void WinAPIDock::removeSelectedFakeSuccessRule()
{
    // removeSelectedFakeSuccessRule:
    // - Input: the current selected row in the Fake Success rule table.
    // - Processing: removes the selected rule while monitoring is stopped.
    // - Return: no return value; silently skips when no row is selected.
    if (fakeRuleTable_ == nullptr || pipeRunning_.load())
    {
        return;
    }

    const QList<QTableWidgetItem*> kSelectedItems = fakeRuleTable_->selectedItems();
    if (kSelectedItems.isEmpty())
    {
        return;
    }

    fakeRuleTable_->removeRow(kSelectedItems.front()->row());
    if (fakeRuleStatusLabel_ != nullptr)
    {
        fakeRuleStatusLabel_->setText(QStringLiteral("规则：%1 条；启动会话时应用。").arg(fakeRuleTable_->rowCount()));
        ks::ui::applyStatusRole(fakeRuleStatusLabel_, ks::ui::StatusRole::kIdle);
    }
    updateActionState();
}

bool WinAPIDock::writeSessionConfigFile(QString* errorTextOut) const
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }
    if (!validateFakeSuccessRules(errorTextOut))
    {
        return false;
    }

    QSaveFile configFile(currentConfigPath_);
    if (!configFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法写入会话配置：%1").arg(currentConfigPath_);
        }
        return false;
    }

    QTextStream outputStream(&configFile);
    outputStream << "[monitor]\n";
    outputStream << "pipe_name=" << currentPipeName_ << '\n';
    outputStream << "stop_flag_path=" << currentStopFlagPath_ << '\n';
    outputStream << "session_id=" << currentSessionId_ << '\n';
    outputStream << "agent_dll_path=" << (agentDllPathEdit_ != nullptr ? QDir::cleanPath(agentDllPathEdit_->text().trimmed()) : QString()) << '\n';
    outputStream << "enable_file=" << ((hookFileCheck_ != nullptr && hookFileCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_registry=" << ((hookRegistryCheck_ != nullptr && hookRegistryCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_network=" << ((hookNetworkCheck_ != nullptr && hookNetworkCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_process=" << ((hookProcessCheck_ != nullptr && hookProcessCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_loader=" << ((hookLoaderCheck_ != nullptr && hookLoaderCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "auto_inject_child=" << ((autoInjectChildCheck_ != nullptr && autoInjectChildCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "enable_raw_fallback=" << ((rawFallbackCheck_ != nullptr && rawFallbackCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "raw_use_default_denylist=" << ((rawDefaultDenyListCheck_ != nullptr && rawDefaultDenyListCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "raw_modules=" << normalizeRawListForSessionConfig(
        rawModuleListEdit_ != nullptr ? rawModuleListEdit_->toPlainText() : defaultRawHookModulesText()) << '\n';
    outputStream << "raw_denylist=" << normalizeRawListForSessionConfig(
        rawDenyListEdit_ != nullptr ? rawDenyListEdit_->toPlainText() : QString()) << '\n';
    outputStream << "fake_success_enabled=" << ((fakeRuleTable_ != nullptr && fakeRuleTable_->rowCount() > 0) ? 1 : 0) << '\n';
    outputStream << "fake_success_raw_fallback=" << ((fakeRawFallbackCheck_ != nullptr && fakeRawFallbackCheck_->isChecked()) ? 1 : 0) << '\n';
    outputStream << "fake_success_rules=" << fakeSuccessRulesIniText() << '\n';
    outputStream << "detail_limit=" << static_cast<int>(ks::winapi_monitor::kMaxDetailChars - 1) << '\n';
    outputStream.flush();
    if (outputStream.status() != QTextStream::Ok || !configFile.commit())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法原子提交会话配置：%1").arg(currentConfigPath_);
        }
        return false;
    }

    // Only remove the stop flag after the complete new configuration is visible to prevent the resident Agent from starting the next session on a partially written INI file.
    if (QFile::exists(currentStopFlagPath_) && !QFile::remove(currentStopFlagPath_))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("会话配置已写入，但无法撤销停止标记：%1").arg(currentStopFlagPath_);
        }
        return false;
    }
    return true;
}

void WinAPIDock::appendInternalEvent(const QString& categoryText, const QString& apiText, const QString& detailText)
{
    EventRow rowValue;
    rowValue.time100nsText = now100nsText();
    rowValue.categoryText = categoryText;
    rowValue.apiText = apiText;
    rowValue.resultText = QStringLiteral("OK");
    rowValue.pidTidText = currentSessionPid_ == 0 ? QStringLiteral("-") : QStringLiteral("%1 / -").arg(currentSessionPid_);
    rowValue.detailText = detailText;
    rowValue.internalEvent = true;
    appendEventRow(rowValue);
    applyEventFilter();
    updateActionState();
    updateStatusLabel();
}

void WinAPIDock::showEventDetailDialog(const int rowValue)
{
    // showEventDetailDialog:
    // - Input: rowValue is the physical row index in the event table;
    // - Processing: Read all columns in this row, concatenate into a multi-line copyable detail text, and display in a modal window.
    // - Return: None; returns immediately if the row index is invalid or the table does not exist.
    if (eventTable_ == nullptr || rowValue < 0 || rowValue >= eventTable_->rowCount())
    {
        return;
    }

    const auto kColumnText = [this, rowValue](const int columnValue) -> QString {
        QTableWidgetItem* const kItemPointer = eventTable_->item(rowValue, columnValue);
        return kItemPointer != nullptr ? kItemPointer->text() : QString();
    };

    const QString kDetailText = QStringLiteral(
        "时间(100ns): %1\n"
        "分类: %2\n"
        "API: %3\n"
        "结果: %4\n"
        "PID/TID: %5\n\n"
        "详情:\n%6")
        .arg(kColumnText(kEventColumnTime100ns),
            kColumnText(kEventColumnCategory),
            kColumnText(kEventColumnApi),
            kColumnText(kEventColumnResult),
            kColumnText(kEventColumnPidTid),
            kColumnText(kEventColumnDetail));

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("WinAPI 事件详情"));
    dialog.resize(760, 420);

    QVBoxLayout* const kLayout = new QVBoxLayout(&dialog);
    kLayout->setContentsMargins(10, 10, 10, 10);
    kLayout->setSpacing(8);

    // Event details are assembled on this page; using a unified editor allows immediate redrawing of fixed field names in English mode.
    CodeEditorWidget* const kDetailEdit = new CodeEditorWidget(&dialog);
    kDetailEdit->setReadOnly(true);
    kDetailEdit->setLocalizedText(kDetailText);
    kLayout->addWidget(kDetailEdit, 1);

    QDialogButtonBox* const kButtonBox = new QDialogButtonBox(QDialogButtonBox::Ok, &dialog);
    kButtonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("关闭"));
    connect(kButtonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    kLayout->addWidget(kButtonBox, 0);

    dialog.exec();
}

void WinAPIDock::startMonitoring()
{
    if (pipeRunning_.load())
    {
        return;
    }

    std::uint32_t pidValue = 0;
    if (!currentSelectedPid(&pidValue))
    {
        QMessageBox::information(this, QStringLiteral("WinAPI 监控"), QStringLiteral("请先选择目标进程或手动输入 PID。"));
        return;
    }

    if (agentDllPathEdit_ == nullptr)
    {
        return;
    }

    const QString kDllPathText = QDir::cleanPath(agentDllPathEdit_->text().trimmed());
    const QFileInfo kDllFileInfo(kDllPathText);
    if (!kDllFileInfo.exists() || !kDllFileInfo.isFile())
    {
        QMessageBox::warning(this, QStringLiteral("WinAPI 监控"), QStringLiteral("Agent DLL 不存在：%1").arg(kDllPathText));
        return;
    }

    QString errorText;
    if (!prepareSessionArtifacts(pidValue, &errorText))
    {
        QMessageBox::warning(this, QStringLiteral("WinAPI 监控"), errorText);
        return;
    }
    if (!writeSessionConfigFile(&errorText))
    {
        QMessageBox::warning(this, QStringLiteral("WinAPI 监控"), errorText);
        return;
    }

    // After the same process instance stops, the Agent worker remains resident waiting for the next configuration; reusing it avoids repeated `LoadLibraryW` calls that would increment the module reference count.
    const bool kReuseResidentAgent = hasResidentAgentForProcess(pidValue);

    if (eventTable_ != nullptr)
    {
        eventTable_->clearContents();
        eventTable_->setRowCount(0);
    }
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingRows_.clear();
        pendingDroppedRows_ = 0;
    }

    pipeStopFlag_.store(false);
    pipeRunning_.store(true);
    pipeConnected_.store(false);
    pipeReconnectAttempts_.store(0);
    {
        std::lock_guard<std::mutex> lock(childPipeMutex_);
        childSessionPids_.clear();
        childPipeHandleValues_.clear();
    }

    if (sessionProgressPid_ == 0)
    {
        sessionProgressPid_ = kPro.addReusable(this, "WinAPI", "准备会话");
    }
    kPro.set(sessionProgressPid_, "准备命名管道连接", 0, 20.0f);

    startPipeReadThread();

    std::string detailText;
    const bool kInjectOk = kReuseResidentAgent
        || ks::process::injectDllByPath(pidValue, kDllPathText.toStdString(), &detailText);
    if (!kInjectOk)
    {
        const QString kInjectErrorText = QString::fromStdString(detailText);
        // privilegePromptHandled: Only retain internal logs and session cleanup if the privilege escalation prompt has been handled.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("注入 API 监控 DLL"),
            kInjectErrorText);
        appendInternalEvent(QStringLiteral("内部"), QStringLiteral("InjectDllByPath"), QString::fromStdString(detailText));
        stopMonitoringInternal(false);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("WinAPI 监控"),
                QStringLiteral("DLL 注入失败：%1").arg(kInjectErrorText));
        }
        return;
    }

    if (!kReuseResidentAgent)
    {
        rememberResidentAgentForProcess(pidValue);
    }

    appendInternalEvent(
        QStringLiteral("内部"),
        QStringLiteral("会话已启动"),
        kReuseResidentAgent
            ? QStringLiteral("已原子写入配置并复用常驻 Agent，等待其重新创建命名管道。")
            : QStringLiteral("已原子写入配置并完成 DLL 注入，等待 Agent 创建命名管道。"));

    kPro.set(
        sessionProgressPid_,
        kReuseResidentAgent ? "复用常驻 Agent，等待握手" : "DLL 已注入，等待 Agent 握手",
        0,
        45.0f);
    updateActionState();
    updateStatusLabel();
}

void WinAPIDock::stopMonitoring()
{
    stopMonitoringInternal(false);
}

void WinAPIDock::stopMonitoringInternal(const bool waitForThread)
{
    if (!pipeRunning_.load() && (pipeThread_ == nullptr || !pipeThread_->joinable()))
    {
        return;
    }

    pipeStopFlag_.store(true);
    writeChildStopFlags();

    if (!currentStopFlagPath_.trimmed().isEmpty())
    {
        QFile stopFile(currentStopFlagPath_);
        if (stopFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
        {
            stopFile.write("stop");
            stopFile.close();
        }
    }

    if (pipeThread_ != nullptr && pipeThread_->joinable())
    {
        // The reader owns a synchronous ReadFile, so cancel it before joining.
        (void)::CancelSynchronousIo(pipeThread_->native_handle());
        pipeThread_->join();
    }
    pipeThread_.reset();

    const std::uintptr_t kPipeHandleValue = pipeHandleValue_.exchange(0);
    if (kPipeHandleValue != 0)
    {
        ::CloseHandle(reinterpret_cast<HANDLE>(kPipeHandleValue));
    }
    joinChildPipeThreads();
    closeChildPipeHandles();

    pipeRunning_.store(false);
    pipeConnected_.store(false);
    kPro.set(sessionProgressPid_, "WinAPI 监控已停止", 0, 100.0f);

    if (!waitForThread)
    {
        appendInternalEvent(QStringLiteral("内部"), QStringLiteral("停止监控"), QStringLiteral("已发出停止标记并回收本地管道线程。"));
    }

    updateActionState();
    updateStatusLabel();
}

void WinAPIDock::terminateHooksForSelectedProcess()
{
    std::uint32_t pidValue = 0;
    if (!currentSelectedPid(&pidValue))
    {
        QMessageBox::information(this, QStringLiteral("终止 Hook"), QStringLiteral("请先选择目标进程或手动输入 PID。"));
        return;
    }

    const QString kSessionDirectory = QString::fromStdWString(ks::winapi_monitor::buildSessionDirectory());
    QDir sessionDir;
    if (!sessionDir.mkpath(kSessionDirectory))
    {
        QMessageBox::warning(this, QStringLiteral("终止 Hook"), QStringLiteral("无法创建会话目录：%1").arg(kSessionDirectory));
        return;
    }

    const QString kStopFlagPath = QString::fromStdWString(ks::winapi_monitor::buildStopFlagPathForPid(pidValue));
    QFile stopFile(kStopFlagPath);
    if (!stopFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("终止 Hook"), QStringLiteral("无法写入停止标记：%1").arg(kStopFlagPath));
        return;
    }
    stopFile.write("stop");
    stopFile.close();

    if (pipeRunning_.load() && currentSessionPid_ == pidValue)
    {
        stopMonitoringInternal(false);
    }
    else
    {
        appendInternalEvent(
            QStringLiteral("内部"),
            QStringLiteral("手动终止 Hook"),
            QStringLiteral("已为 PID=%1 写入停止标记。").arg(pidValue));
        updateActionState();
        updateStatusLabel();
    }
}

void WinAPIDock::applyEventFilter()
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    const QString kKeywordText = eventFilterEdit_ != nullptr ? eventFilterEdit_->text().trimmed() : QString();
    if (kKeywordText.isEmpty())
    {
        if (eventFilterActive_)
        {
            for (int row = 0; row < eventTable_->rowCount(); ++row)
            {
                eventTable_->setRowHidden(row, false);
            }
        }
        eventFilterActive_ = false;
        if (eventFilterStatusLabel_ != nullptr)
        {
            eventFilterStatusLabel_->setText(
                QStringLiteral("筛选结果：%1 / %2")
                    .arg(eventTable_->rowCount())
                    .arg(eventTable_->rowCount()));
            ks::ui::applyStatusRole(eventFilterStatusLabel_,
                eventTable_->rowCount() > 0 ? ks::ui::StatusRole::kSuccess : ks::ui::StatusRole::kIdle);
        }
        return;
    }

    eventFilterActive_ = true;
    int visibleCount = 0;

    for (int row = 0; row < eventTable_->rowCount(); ++row)
    {
        QStringList rowTextList;
        for (int column = 0; column < kEventColumnCount; ++column)
        {
            QTableWidgetItem* itemPointer = eventTable_->item(row, column);
            rowTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }

        const QString kMergedText = rowTextList.join(QStringLiteral(" | "));
        const bool kVisible = kKeywordText.isEmpty() || kMergedText.contains(kKeywordText, Qt::CaseInsensitive);
        eventTable_->setRowHidden(row, !kVisible);
        if (kVisible)
        {
            ++visibleCount;
        }
    }

    if (eventFilterStatusLabel_ != nullptr)
    {
        eventFilterStatusLabel_->setText(
            QStringLiteral("筛选结果：%1 / %2").arg(visibleCount).arg(eventTable_->rowCount()));
        ks::ui::applyStatusRole(eventFilterStatusLabel_,
            visibleCount > 0 ? ks::ui::StatusRole::kSuccess : ks::ui::StatusRole::kIdle);
    }
}

void WinAPIDock::clearEventFilter()
{
    if (eventFilterEdit_ != nullptr)
    {
        eventFilterEdit_->clear();
    }
    applyEventFilter();
}

void WinAPIDock::exportVisibleRowsToTsv()
{
    if (eventTable_ == nullptr || eventTable_->rowCount() == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出 WinAPI 事件"), QStringLiteral("当前没有可导出的事件。"));
        return;
    }

    int visibleCount = 0;
    for (int row = 0; row < eventTable_->rowCount(); ++row)
    {
        if (!eventTable_->isRowHidden(row))
        {
            ++visibleCount;
        }
    }
    if (visibleCount == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出 WinAPI 事件"), QStringLiteral("当前筛选结果为空。"));
        return;
    }

    const QString kDefaultFileName = QStringLiteral("winapi_events_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString kExportPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 WinAPI 事件"),
        kDefaultFileName,
        QStringLiteral("TSV 文件 (*.tsv);;文本文件 (*.txt)"));
    if (kExportPath.trimmed().isEmpty())
    {
        return;
    }

    QFile exportFile(kExportPath);
    if (!exportFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("导出 WinAPI 事件"), QStringLiteral("无法写入文件：%1").arg(kExportPath));
        return;
    }

    QTextStream outputStream(&exportFile);
    QStringList headerTextList;
    for (int column = 0; column < kEventColumnCount; ++column)
    {
        QTableWidgetItem* headerItem = eventTable_->horizontalHeaderItem(column);
        headerTextList << (headerItem != nullptr ? headerItem->text() : QString());
    }
    outputStream << headerTextList.join('\t') << '\n';

    for (int row = 0; row < eventTable_->rowCount(); ++row)
    {
        if (eventTable_->isRowHidden(row))
        {
            continue;
        }

        QStringList rowTextList;
        for (int column = 0; column < kEventColumnCount; ++column)
        {
            QTableWidgetItem* itemPointer = eventTable_->item(row, column);
            rowTextList << (itemPointer != nullptr ? itemPointer->text().replace('\t', ' ') : QString());
        }
        outputStream << rowTextList.join('\t') << '\n';
    }
    exportFile.close();
}

void WinAPIDock::showEventContextMenu(const QPoint& position)
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    const QModelIndex kIndexValue = eventTable_->indexAt(position);
    if (!kIndexValue.isValid())
    {
        return;
    }

    const int kRow = kIndexValue.row();
    const int kColumn = kIndexValue.column();

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyCellAction = menu.addAction(QStringLiteral("复制单元格"));
    QAction* copyRowAction = menu.addAction(QStringLiteral("复制整行"));
    const QTableWidgetItem* processIdItem = eventTable_->item(kRow, kEventColumnPidTid);
    std::uint32_t processId = 0;
    const bool kHasProcessId = processIdItem != nullptr &&
        ks::online_scan::tryParsePidFromText(processIdItem->text(), &processId) &&
        processId != 0U;
    QAction* openProcessDetailAction = menu.addAction(QStringLiteral("转到进程详细信息"));
    openProcessDetailAction->setEnabled(kHasProcessId);
    menu.addSeparator();
    ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, kRow]() -> ks::online_scan::SandboxUploadTarget {
            // Input: The row currently right-clicked in the WinAPI monitor event table.
            // Handling: Parse process PID from the PID/TID column, then resolve the process image path.
            // Return: VT upload target; on parse failure, returns errorText to the unified helper popup.
            QTableWidgetItem* pidItem = eventTable_ != nullptr
                ? eventTable_->item(kRow, kEventColumnPidTid)
                : nullptr;
            std::uint32_t pidValue = 0;
            if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("WinAPI 监控事件"),
                    QStringLiteral("当前事件行未解析出有效 PID，无法上传发起进程文件。")
                };
            }

            const QString kProcessPath = QString::fromStdString(ks::process::queryProcessPathByPid(pidValue)).trimmed();
            if (kProcessPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("WinAPI 监控事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                kProcessPath,
                QStringLiteral("WinAPI 监控事件 PID=%1").arg(pidValue),
                QString()
            };
        });

    QAction* selectedAction = menu.exec(eventTable_->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == copyCellAction)
    {
        QTableWidgetItem* itemPointer = eventTable_->item(kRow, kColumn);
        if (itemPointer != nullptr)
        {
            QApplication::clipboard()->setText(itemPointer->text());
        }
        return;
    }

    if (selectedAction == openProcessDetailAction)
    {
        ks::ui::openProcessDetailByPid(processId);
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QStringList rowTextList;
        for (int currentColumn = 0; currentColumn < kEventColumnCount; ++currentColumn)
        {
            QTableWidgetItem* itemPointer = eventTable_->item(kRow, currentColumn);
            rowTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }
        QApplication::clipboard()->setText(rowTextList.join('\t'));
    }
}
