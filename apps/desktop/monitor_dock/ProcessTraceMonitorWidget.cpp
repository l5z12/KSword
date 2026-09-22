#include "ProcessTraceMonitorWidget.h"
#include "../ui/ThemeStatusRole.h"

// ============================================================
// ProcessTraceMonitorWidget.cpp
// Purpose:
// 1) Provide common styles and basic utility functions for the process targeted monitoring control;
// 2) Provide lightweight logic for construction, destruction, and status text refresh;
// 3) Avoid stacking UI, actions, and collection implementation into the same large file.
// ============================================================

#include "../Theme.h"

#include <QDateTime>
#include <QEvent>
#include <QLabel>
#include <QList>
#include <QPushButton>
#include <QRegularExpression>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QToolButton>
#include <QTimer>
#include <QWidget>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>
#include <evntcons.h>
#include <tdh.h>

#pragma comment(lib, "Tdh.lib")

ProcessTraceMonitorWidget::ProcessTraceMonitorWidget(QWidget* parent)
    : QWidget(parent)
{
    // initEvent: Reuse the same log event during construction to link the entire initialization chain.
    KLogEvent initEvent;
    info << initEvent << "[ProcessTraceMonitorWidget] 开始初始化进程定向监控页。" << eol;

    initializeUi();
    initializeConnections();
    refreshAvailableProcessListAsync();
    updateActionState();
    updateStatusLabel();

    info << initEvent << "[ProcessTraceMonitorWidget] 进程定向监控页初始化完成。" << eol;
}

ProcessTraceMonitorWidget::~ProcessTraceMonitorWidget()
{
    // Synchronously stops background threads during destruction to prevent callbacks from accessing members after the object is released.
    stopMonitoringInternal(true);

    if (uiUpdateTimer_ != nullptr)
    {
        uiUpdateTimer_->stop();
    }

    if (eventFilterDebounceTimer_ != nullptr)
    {
        eventFilterDebounceTimer_->stop();
    }

    if (runtimeRefreshTimer_ != nullptr)
    {
        runtimeRefreshTimer_->stop();
    }

    KLogEvent destroyEvent;
    info << destroyEvent << "[ProcessTraceMonitorWidget] 进程定向监控页已析构。" << eol;
}

bool ProcessTraceMonitorWidget::event(QEvent* eventPointer)
{
    // handled：
    // - Retain the original QWidget event handling result first to prevent theme refresh logic from swallowing other input/layout events.
    // - Subsequently, only refresh Collapse dynamic styles on style-related events.
    const bool kHandled = QWidget::event(eventPointer);
    if (eventPointer != nullptr
        && (eventPointer->type() == QEvent::PaletteChange
            || eventPointer->type() == QEvent::ApplicationPaletteChange
            || eventPointer->type() == QEvent::StyleChange))
    {
        refreshCollapseTheme(this);
    }
    return kHandled;
}

QString ProcessTraceMonitorWidget::blueButtonStyle()
{
    return ksword_theme::themedButtonStyle();
}

QString ProcessTraceMonitorWidget::blueInputStyle()
{
    return QStringLiteral(
        "QLineEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
        "QTableWidget{border:1px solid %2;border-radius:3px;background:transparent;background-color:transparent;color:%4;padding:2px 6px;gridline-color:%2;alternate-background-color:transparent;}"
        "QTableWidget::viewport{background:transparent;background-color:transparent;}"
        "QLineEdit:focus{border:1px solid %1;}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex())
        + ksword_theme::themedComboBoxStyle();
}

QString ProcessTraceMonitorWidget::blueHeaderStyle()
{
    return QStringLiteral(
        "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;padding:4px;font-weight:600;}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::borderHex());
}

QString ProcessTraceMonitorWidget::collapsePanelStyle()
{
    // Style reuse follows the existing independent Collapse convention in MonitorDock:
    // - Use the outer kswordCollapsePanel marker to display a unified border and rounded corners.
    // - The content host uses the kswordCollapseContent marker to avoid redundant borders in nested regions.
    return QStringLiteral(
        "QWidget[kswordCollapsePanel=\"true\"]{"
        "  background:transparent;"
        "  background-color:transparent;"
        "  color:%2;"
        "  border:1px solid %3;"
        "  border-radius:5px;"
        "}"
        "QWidget[kswordCollapseContent=\"true\"]{"
        "  background:transparent;"
        "  background-color:transparent;"
        "  color:%2;"
        "  border:none;"
        "}")
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::borderHex());
}

QString ProcessTraceMonitorWidget::collapseHeaderButtonStyle()
{
    // Keep the header button style consistent with the custom collapsible section of MonitorDock.
    // - Use the secondary panel background color in normal state;
    // - Use a weak main blue background for hover/expanded states to emphasize that the current configuration area remains expanded.
    return QStringLiteral(
        "QToolButton{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %3;"
        "  border-radius:5px;"
        "  padding:5px 8px;"
        "  font-weight:600;"
        "  text-align:left;"
        "}"
        "QToolButton:hover{"
        "  background:%4;"
        "  color:%2;"
        "  border-color:%5;"
        "}"
        "QToolButton:checked{"
        "  background:%4;"
        "  color:%2;"
        "  border-color:%5;"
        "}")
        .arg(ksword_theme::surfaceAltHex())
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::primaryBlueSubtleHex())
        .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue));
}

void ProcessTraceMonitorWidget::refreshCollapseTheme(QWidget* rootWidget)
{
    // Return immediately if the root widget is null, allowing safe calls to event() during very early initialization.
    if (rootWidget == nullptr)
    {
        return;
    }

    // Refresh panel style by property:
    // - palette()/theme function values change with light/dark themes;
    // - Re-applying setStyleSheet forces Qt to re-parse dynamic colors.
    const QList<QWidget*> kWidgetList = rootWidget->findChildren<QWidget*>();
    for (QWidget* widgetPointer : kWidgetList)
    {
        if (widgetPointer == nullptr)
        {
            continue;
        }

        if (widgetPointer->property("kswordCollapsePanel").toString() == QStringLiteral("true")
            || widgetPointer->property("kswordCollapseContent").toString() == QStringLiteral("true"))
        {
            widgetPointer->setStyleSheet(collapsePanelStyle());
        }
    }

    // Refresh header buttons individually:
    // - Match only QToolButton elements under the outer layer of the collapsed section to avoid inadvertently modifying ordinary tool buttons.
    // - Returns null; this function is responsible only for theme synchronization side effects.
    const QList<QToolButton*> kHeaderButtonList = rootWidget->findChildren<QToolButton*>();
    for (QToolButton* buttonPointer : kHeaderButtonList)
    {
        if (buttonPointer != nullptr
            && buttonPointer->parentWidget() != nullptr
            && buttonPointer->parentWidget()->property("kswordCollapsePanel").toString() == QStringLiteral("true"))
        {
            buttonPointer->setStyleSheet(collapseHeaderButtonStyle());
        }
    }
}

QString ProcessTraceMonitorWidget::providerTypeFromName(const QString& providerNameText)
{
    const QString kNameText = providerNameText.trimmed();
    if (kNameText.contains(QStringLiteral("Kernel-Process"), Qt::CaseInsensitive))
    {
        return QStringLiteral("进程");
    }
    if (kNameText.contains(QStringLiteral("Kernel-Thread"), Qt::CaseInsensitive))
    {
        return QStringLiteral("线程");
    }
    if (kNameText.contains(QStringLiteral("Kernel-Image"), Qt::CaseInsensitive))
    {
        return QStringLiteral("镜像");
    }
    if (kNameText.contains(QStringLiteral("Kernel-File"), Qt::CaseInsensitive))
    {
        return QStringLiteral("文件");
    }
    if (kNameText.contains(QStringLiteral("Kernel-Registry"), Qt::CaseInsensitive))
    {
        return QStringLiteral("注册表");
    }
    if (kNameText.contains(QStringLiteral("DNS-Client"), Qt::CaseInsensitive))
    {
        return QStringLiteral("DNS");
    }
    if (kNameText.contains(QStringLiteral("TCPIP"), Qt::CaseInsensitive)
        || kNameText.contains(QStringLiteral("AFD"), Qt::CaseInsensitive))
    {
        return QStringLiteral("网络");
    }
    if (kNameText.contains(QStringLiteral("PowerShell"), Qt::CaseInsensitive))
    {
        return QStringLiteral("PowerShell");
    }
    if (kNameText.contains(QStringLiteral("WMI-Activity"), Qt::CaseInsensitive))
    {
        return QStringLiteral("WMI");
    }
    if (kNameText.contains(QStringLiteral("TaskScheduler"), Qt::CaseInsensitive))
    {
        return QStringLiteral("计划任务");
    }
    if (kNameText.contains(QStringLiteral("Security-Auditing"), Qt::CaseInsensitive))
    {
        return QStringLiteral("安全审计");
    }
    if (kNameText.contains(QStringLiteral("Defender"), Qt::CaseInsensitive))
    {
        return QStringLiteral("Defender");
    }
    return QStringLiteral("其他");
}

QString ProcessTraceMonitorWidget::now100nsText()
{
    return QString::number(static_cast<qulonglong>(currentSystemTime100ns()));
}

std::uint64_t ProcessTraceMonitorWidget::currentSystemTime100ns()
{
    FILETIME fileTimeValue{};
    ::GetSystemTimeAsFileTime(&fileTimeValue);

    ULARGE_INTEGER largeValue{};
    largeValue.LowPart = fileTimeValue.dwLowDateTime;
    largeValue.HighPart = fileTimeValue.dwHighDateTime;
    return static_cast<std::uint64_t>(largeValue.QuadPart);
}

QString ProcessTraceMonitorWidget::guidToText(const GUID& guidValue)
{
    wchar_t guidBuffer[64] = {};
    if (::StringFromGUID2(guidValue, guidBuffer, static_cast<int>(std::size(guidBuffer))) <= 0)
    {
        return QStringLiteral("{00000000-0000-0000-0000-000000000000}");
    }
    return QString::fromWCharArray(guidBuffer);
}

QString ProcessTraceMonitorWidget::queryEtwEventName(const struct _EVENT_RECORD* eventRecordPtr)
{
    const auto kTextAtOffset = [](const unsigned char* bufferPointer, const ULONG offsetValue) -> QString {
        if (bufferPointer == nullptr || offsetValue == 0)
        {
            return QString();
        }

        const wchar_t* textPointer = reinterpret_cast<const wchar_t*>(bufferPointer + offsetValue);
        if (textPointer == nullptr || *textPointer == L'\0')
        {
            return QString();
        }
        return QString::fromWCharArray(textPointer).trimmed();
    };

    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return QString();
    }

    DWORD bufferSize = 0;
    ULONG status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        nullptr,
        &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0)
    {
        return QString();
    }

    std::vector<unsigned char> infoBuffer(bufferSize, 0);
    auto* eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
    status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        eventInfo,
        &bufferSize);
    if (status != ERROR_SUCCESS || eventInfo == nullptr)
    {
        return QString();
    }

    const unsigned char* infoBufferPointer = infoBuffer.data();
    const QString kEventNameText = kTextAtOffset(infoBufferPointer, eventInfo->EventNameOffset);
    if (!kEventNameText.isEmpty())
    {
        return kEventNameText;
    }

    const QString kTaskNameText = kTextAtOffset(infoBufferPointer, eventInfo->TaskNameOffset);
    if (!kTaskNameText.isEmpty())
    {
        return kTaskNameText;
    }

    return kTextAtOffset(infoBufferPointer, eventInfo->OpcodeNameOffset);
}

bool ProcessTraceMonitorWidget::textMatch(
    const QString& sourceText,
    const QString& patternText,
    const bool useRegex,
    const Qt::CaseSensitivity caseSensitivity)
{
    if (patternText.trimmed().isEmpty())
    {
        return true;
    }

    if (!useRegex)
    {
        return sourceText.contains(patternText, caseSensitivity);
    }

    QRegularExpression::PatternOptions options = QRegularExpression::NoPatternOption;
    if (caseSensitivity == Qt::CaseInsensitive)
    {
        options |= QRegularExpression::CaseInsensitiveOption;
    }

    const QRegularExpression kRegex(patternText, options);
    if (!kRegex.isValid())
    {
        return false;
    }
    return kRegex.match(sourceText).hasMatch();
}

bool ProcessTraceMonitorWidget::tryParseUint32Text(const QString& textValue, std::uint32_t* valueOut)
{
    if (valueOut == nullptr)
    {
        return false;
    }

    bool parseOk = false;
    QString normalizedText = textValue.trimmed();
    if (normalizedText.isEmpty())
    {
        return false;
    }

    std::uint32_t parsedValue = 0;
    if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        parsedValue = normalizedText.mid(2).toUInt(&parseOk, 16);
    }
    else
    {
        parsedValue = normalizedText.toUInt(&parseOk, 10);
        if (!parseOk)
        {
            parsedValue = normalizedText.toUInt(&parseOk, 16);
        }
    }

    if (!parseOk || parsedValue == 0)
    {
        return false;
    }

    *valueOut = parsedValue;
    return true;
}

QTableWidgetItem* ProcessTraceMonitorWidget::createReadOnlyItem(const QString& textValue)
{
    QTableWidgetItem* itemPointer = new QTableWidgetItem(textValue);
    itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
    itemPointer->setToolTip(textValue);
    return itemPointer;
}

void ProcessTraceMonitorWidget::updateActionState()
{
    const bool kHasTargets = !targetProcessList_.empty();
    const bool kRunning = captureRunning_.load();
    const bool kPaused = capturePaused_.load();

    if (availableRefreshButton_ != nullptr)
    {
        availableRefreshButton_->setEnabled(!kRunning && !availableRefreshPending_.load());
    }
    if (createTargetButton_ != nullptr)
    {
        createTargetButton_->setEnabled(!kRunning);
    }
    if (addSelectedButton_ != nullptr)
    {
        addSelectedButton_->setEnabled(!kRunning && availableTable_ != nullptr && availableTable_->selectedItems().size() > 0);
    }
    if (addManualPidButton_ != nullptr)
    {
        addManualPidButton_->setEnabled(!kRunning);
    }
    if (removeTargetButton_ != nullptr)
    {
        removeTargetButton_->setEnabled(!kRunning && targetTable_ != nullptr && targetTable_->selectedItems().size() > 0);
    }
    if (clearTargetButton_ != nullptr)
    {
        clearTargetButton_->setEnabled(!kRunning && kHasTargets);
    }
    if (startButton_ != nullptr)
    {
        startButton_->setEnabled((!kRunning && kHasTargets) || (kRunning && kPaused));
        startButton_->setIcon(QIcon(kPaused
            ? QStringLiteral(":/Icon/process_resume.svg")
            : QStringLiteral(":/Icon/process_start.svg")));
        startButton_->setToolTip(kPaused
            ? QStringLiteral("继续处理与目标进程相关的事件")
            : QStringLiteral("开始监控已选择的目标进程"));
    }
    if (stopButton_ != nullptr)
    {
        stopButton_->setEnabled(kRunning);
    }
    if (pauseButton_ != nullptr)
    {
        pauseButton_->setEnabled(kRunning && !kPaused);
        pauseButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_pause.svg")));
        pauseButton_->setToolTip(QStringLiteral("暂停处理与目标进程相关的事件"));
    }
    if (exportButton_ != nullptr)
    {
        exportButton_->setEnabled(eventTable_ != nullptr && eventTable_->rowCount() > 0);
    }
}

void ProcessTraceMonitorWidget::updateStatusLabel()
{
    if (statusLabel_ == nullptr)
    {
        return;
    }

    std::size_t trackedCount = 0;
    {
        std::lock_guard<std::mutex> lock(runtimeMutex_);
        trackedCount = trackedProcessMap_.size();
    }

    const int kEventCount = (eventTable_ != nullptr) ? eventTable_->rowCount() : 0;
    const QString kSummaryText = QStringLiteral("目标=%1 | 进程树=%2 | 事件=%3")
        .arg(targetProcessList_.size())
        .arg(static_cast<qulonglong>(trackedCount))
        .arg(kEventCount);

    if (captureRunning_.load())
    {
        if (capturePaused_.load())
        {
            statusLabel_->setText(QStringLiteral("● 已暂停  %1").arg(kSummaryText));
            ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kWarning);
        }
        else
        {
            statusLabel_->setText(QStringLiteral("● 监听中  %1").arg(kSummaryText));
            ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kInfo);
        }
    }
    else
    {
        statusLabel_->setText(QStringLiteral("● 空闲  %1").arg(kSummaryText));
        ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kIdle);
    }
}
