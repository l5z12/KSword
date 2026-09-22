#include "WinAPIDock.h"
#include "../ui/ThemeStatusRole.h"

// ============================================================
// WinAPIDock.cpp
// Purpose:
// 1) Place basic styles, constructors/destructors, and lightweight utility functions for WinAPI Dock;
// 2) Centralize general logic unrelated to UI structure;
// 3) Avoid cramming initialization, action, and pipeline code into the same implementation file.
// ============================================================

#include "../Theme.h"

#include <QCoreApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>

WinAPIDock::WinAPIDock(QWidget* parent)
    : QWidget(parent)
{
    // initEvent：
    // - Purpose: Chains the entire Dock initialization pipeline;
    // - Constraint: Use the same KLogEvent during the initialization phase.
    KLogEvent initEvent;
    info << initEvent << "[WinAPIDock] 开始初始化 WinAPI 监控页。" << eol;

    initializeUi();
    initializeConnections();
    updateActionState();
    updateStatusLabel();

    info << initEvent << "[WinAPIDock] WinAPI 监控页初始化完成。" << eol;
}

WinAPIDock::~WinAPIDock()
{
    stopMonitoringInternal(true);

    if (uiFlushTimer_ != nullptr)
    {
        uiFlushTimer_->stop();
    }

    KLogEvent destroyEvent;
    info << destroyEvent << "[WinAPIDock] WinAPI 监控页已析构。" << eol;
}

void WinAPIDock::notifyPageActivated()
{
    // Refresh immediately upon first entering the tab; subsequent switches within 5 seconds will not re-scan processes to avoid meaningless jitter.
    const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
    const bool kShouldRefresh = !hasActivatedOnce_
        || (lastProcessRefreshMs_ <= 0)
        || ((kNowMs - lastProcessRefreshMs_) >= 5000);

    hasActivatedOnce_ = true;
    if (kShouldRefresh)
    {
        refreshProcessListAsync();
    }
}

QString WinAPIDock::blueButtonStyle()
{
    return ksword_theme::themedButtonStyle();
}

QString WinAPIDock::blueInputStyle()
{
    return QStringLiteral(
        "QLineEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
        "QPlainTextEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:4px 6px;}"
        "QTableWidget{border:1px solid %2;border-radius:3px;background:transparent;background-color:transparent;color:%4;padding:2px 6px;gridline-color:%2;alternate-background-color:transparent;}"
        "QTableWidget::viewport{background:transparent;background-color:transparent;}"
        "QLineEdit:focus,QPlainTextEdit:focus{border:1px solid %1;}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex());
}

QString WinAPIDock::blueHeaderStyle()
{
    return QStringLiteral(
        "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;padding:4px;font-weight:600;}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::borderHex());
}

QString WinAPIDock::eventCategoryText(const std::uint32_t categoryValue)
{
    return QString::fromStdWString(
        ks::winapi_monitor::eventCategoryToText(
            static_cast<ks::winapi_monitor::EventCategory>(categoryValue)));
}

QString WinAPIDock::defaultDllPathHint()
{
    const QDir kAppDir(QCoreApplication::applicationDirPath());
    const QStringList kCandidatePathList{
        kAppDir.filePath(QStringLiteral("APIMonitor_x64.dll")),
        kAppDir.filePath(QStringLiteral("../APIMonitor_x64.dll")),
        kAppDir.filePath(QStringLiteral("../../APIMonitor_x64.dll")),
        kAppDir.filePath(QStringLiteral("../../../../APIMonitor_x64/x64/Debug/APIMonitor_x64.dll")),
        kAppDir.filePath(QStringLiteral("../../../../APIMonitor_x64/x64/Release/APIMonitor_x64.dll"))
    };

    for (const QString& candidatePath : kCandidatePathList)
    {
        const QFileInfo kFileInfo(candidatePath);
        if (kFileInfo.exists() && kFileInfo.isFile())
        {
            return QDir::cleanPath(kFileInfo.absoluteFilePath());
        }
    }

    return QDir::cleanPath(kCandidatePathList.front());
}

QString WinAPIDock::defaultRawHookModulesText()
{
    // defaultRawHookModulesText：
    // - Inputs: None;
    // - Processing: Read the default module directory for Raw Fallback from shared protocol constants.
    // - Return: semicolon-delimited text for UI edit box display and session INI write.
    return QString::fromWCharArray(ks::winapi_monitor::kDefaultRawHookModules);
}

QString WinAPIDock::defaultRawHookDenyListText()
{
    // defaultRawHookDenyListText：
    // - Inputs: None;
    // - Processing: Read the built-in default blacklist for Raw Fallback from shared protocol constants.
    // - Return: Semicolon-separated text, primarily for tooltip/explanation display; user-added extra blacklist entries should not default to this value.
    return QString::fromWCharArray(ks::winapi_monitor::kDefaultRawHookDenyList);
}

QString WinAPIDock::resultCodeText(const std::int32_t resultCodeValue)
{
    if (resultCodeValue == 0)
    {
        return QStringLiteral("OK");
    }
    return QStringLiteral("%1 (0x%2)")
        .arg(resultCodeValue)
        .arg(QString::number(static_cast<quint32>(resultCodeValue), 16).toUpper());
}

QString WinAPIDock::now100nsText()
{
    FILETIME fileTimeValue{};
    ::GetSystemTimeAsFileTime(&fileTimeValue);

    ULARGE_INTEGER largeValue{};
    largeValue.LowPart = fileTimeValue.dwLowDateTime;
    largeValue.HighPart = fileTimeValue.dwHighDateTime;
    return QString::number(static_cast<qulonglong>(largeValue.QuadPart));
}

bool WinAPIDock::tryParseUint32Text(const QString& textValue, std::uint32_t* valueOut)
{
    if (valueOut == nullptr)
    {
        return false;
    }

    bool parseOk = false;
    const QString kNormalizedText = textValue.trimmed();
    if (kNormalizedText.isEmpty())
    {
        return false;
    }

    const std::uint32_t kParsedValue = kNormalizedText.toUInt(&parseOk, 10);
    if (!parseOk || kParsedValue == 0)
    {
        return false;
    }

    *valueOut = kParsedValue;
    return true;
}

QTableWidgetItem* WinAPIDock::createReadOnlyItem(const QString& textValue)
{
    QTableWidgetItem* itemPointer = new QTableWidgetItem(textValue);
    itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
    itemPointer->setToolTip(textValue);
    return itemPointer;
}

void WinAPIDock::updateActionState()
{
    std::uint32_t currentPidValue = 0;
    const bool kHasPid = currentSelectedPid(&currentPidValue);
    const bool kRunning = pipeRunning_.load();
    const bool kHasEvents = eventTable_ != nullptr && eventTable_->rowCount() > 0;

    if (processRefreshButton_ != nullptr)
    {
        processRefreshButton_->setEnabled(!processRefreshPending_.load() && !kRunning);
    }
    if (processCombo_ != nullptr)
    {
        processCombo_->setEnabled(!kRunning);
    }
    if (browseAgentDllButton_ != nullptr)
    {
        browseAgentDllButton_->setEnabled(!kRunning);
    }
    if (manualPidEdit_ != nullptr)
    {
        manualPidEdit_->setEnabled(!kRunning);
    }
    if (agentDllPathEdit_ != nullptr)
    {
        agentDllPathEdit_->setEnabled(!kRunning);
    }
    if (rawFallbackCheck_ != nullptr)
    {
        rawFallbackCheck_->setEnabled(!kRunning);
    }
    if (rawDefaultDenyListCheck_ != nullptr)
    {
        rawDefaultDenyListCheck_->setEnabled(!kRunning && rawFallbackCheck_ != nullptr && rawFallbackCheck_->isChecked());
    }
    if (rawModuleListEdit_ != nullptr)
    {
        rawModuleListEdit_->setEnabled(!kRunning && rawFallbackCheck_ != nullptr && rawFallbackCheck_->isChecked());
    }
    if (rawDenyListEdit_ != nullptr)
    {
        rawDenyListEdit_->setEnabled(!kRunning && rawFallbackCheck_ != nullptr && rawFallbackCheck_->isChecked());
    }
    if (fakeModuleEdit_ != nullptr)
    {
        fakeModuleEdit_->setEnabled(!kRunning);
    }
    if (fakeApiEdit_ != nullptr)
    {
        fakeApiEdit_->setEnabled(!kRunning);
    }
    if (fakeReturnTypeCombo_ != nullptr)
    {
        fakeReturnTypeCombo_->setEnabled(!kRunning);
    }
    if (fakeReturnValueEdit_ != nullptr)
    {
        fakeReturnValueEdit_->setEnabled(!kRunning);
    }
    if (fakeLastErrorKindCombo_ != nullptr)
    {
        fakeLastErrorKindCombo_->setEnabled(!kRunning);
    }
    if (fakeLastErrorValueEdit_ != nullptr)
    {
        fakeLastErrorValueEdit_->setEnabled(!kRunning);
    }
    if (fakeRawFallbackCheck_ != nullptr)
    {
        fakeRawFallbackCheck_->setEnabled(!kRunning);
    }
    if (fakeAddRuleButton_ != nullptr)
    {
        fakeAddRuleButton_->setEnabled(!kRunning);
    }
    if (fakeRemoveRuleButton_ != nullptr)
    {
        fakeRemoveRuleButton_->setEnabled(
            !kRunning
            && fakeRuleTable_ != nullptr
            && !fakeRuleTable_->selectedItems().isEmpty());
    }
    if (fakeApplyRuleButton_ != nullptr)
    {
        fakeApplyRuleButton_->setEnabled(
            !kRunning
            && kHasPid
            && agentDllPathEdit_ != nullptr
            && !agentDllPathEdit_->text().trimmed().isEmpty());
    }
    if (fakeStopRuleButton_ != nullptr)
    {
        fakeStopRuleButton_->setEnabled(kRunning);
    }
    if (fakeRuleTable_ != nullptr)
    {
        fakeRuleTable_->setEnabled(!kRunning);
    }
    if (startButton_ != nullptr)
    {
        startButton_->setEnabled(
            !kRunning
            && kHasPid
            && agentDllPathEdit_ != nullptr
            && !agentDllPathEdit_->text().trimmed().isEmpty());
    }
    if (stopButton_ != nullptr)
    {
        stopButton_->setEnabled(kRunning);
    }
    if (terminateHookButton_ != nullptr)
    {
        terminateHookButton_->setEnabled(kHasPid);
    }
    if (exportButton_ != nullptr)
    {
        exportButton_->setEnabled(kHasEvents);
    }
    if (clearEventButton_ != nullptr)
    {
        clearEventButton_->setEnabled(kHasEvents && !kRunning);
    }
}

void WinAPIDock::updateStatusLabel()
{
    if (sessionStatusLabel_ == nullptr)
    {
        return;
    }

    const int kEventCount = eventTable_ != nullptr ? eventTable_->rowCount() : 0;
    const QString kPidText = currentSessionPid_ == 0
        ? QStringLiteral("-")
        : QString::number(currentSessionPid_);

    if (pipeRunning_.load())
    {
        if (pipeConnected_.load())
        {
            sessionStatusLabel_->setText(
                QStringLiteral("● 监控中  PID=%1 | 事件=%2").arg(kPidText).arg(kEventCount));
            ks::ui::applyStatusRole(sessionStatusLabel_, ks::ui::StatusRole::kInfo);
        }
        else
        {
            sessionStatusLabel_->setText(
                QStringLiteral("● 等待 Agent 连接  PID=%1 | 事件=%2").arg(kPidText).arg(kEventCount));
            ks::ui::applyStatusRole(sessionStatusLabel_, ks::ui::StatusRole::kWarning);
        }
    }
    else
    {
        sessionStatusLabel_->setText(
            QStringLiteral("● 空闲  PID=%1 | 事件=%2").arg(kPidText).arg(kEventCount));
        ks::ui::applyStatusRole(sessionStatusLabel_, ks::ui::StatusRole::kIdle);
    }
}
