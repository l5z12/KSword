#include "DriverDock.Internal.h"

#include <QScrollBar>
#include <QStringList>

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::driver_dock_internal;

void DriverDock::startDebugOutputCapture()
{
    if (kernelDebugCaptureRunning_.exchange(true))
    {
        appendLocalizedDebugOutputLine(QStringLiteral("捕获线程已在运行。"));
        return;
    }

    // The previous thread may have already exited on its own; the joinable object must be joined before restarting.
    if (kernelDebugCaptureThread_ != nullptr && kernelDebugCaptureThread_->joinable())
    {
        kernelDebugCaptureThread_->join();
    }
    kernelDebugCaptureThread_.reset();

    appendLocalizedDebugOutputLine(QStringLiteral("正在注册 R0 内核调试输出回调..."));
    try
    {
        kernelDebugCaptureThread_ = std::make_unique<std::thread>([this]()
            {
                runKernelDebugOutputCaptureLoop();
            });
    }
    catch (...)
    {
        kernelDebugCaptureRunning_.store(false);
        kernelDebugCaptureThread_.reset();
        appendLocalizedDebugOutputLine(QStringLiteral("启动失败：无法创建后台线程。"));
    }

    updateDebugCaptureButtonState();
}

void DriverDock::stopDebugOutputCapture()
{
    kernelDebugCaptureRunning_.store(false);
    if (kernelDebugCaptureThread_ != nullptr && kernelDebugCaptureThread_->joinable())
    {
        kernelDebugCaptureThread_->join();
    }
    kernelDebugCaptureThread_.reset();
    updateDebugCaptureButtonState();
}

void DriverDock::runKernelDebugOutputCaptureLoop()
{
    // guardThis: Check for null when posting an update back to the UI to avoid accessing a dangling object after destruction.
    QPointer<DriverDock> guardThis(this);
    ksword::ark::DriverClient driverClient;
    ksword::ark::DriverHandle driverHandle = driverClient.open();
    if (!driverHandle.isValid())
    {
        const unsigned long kOpenError = ::GetLastError();
        kernelDebugCaptureRunning_.store(false);
        QMetaObject::invokeMethod(this, [guardThis, kOpenError]()
            {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->appendLocalizedDebugOutputLine(
                    QStringLiteral("启动失败：无法打开 KswordARK 控制设备（Win32=%1）。")
                        .arg(kOpenError));
                guardThis->updateDebugCaptureButtonState();
            }, Qt::QueuedConnection);
        return;
    }

    const ksword::ark::DebugOutputControlResult kStartResult = driverClient.controlDebugOutput(
        driverHandle,
        KSWORD_ARK_DEBUG_OUTPUT_ACTION_START);
    if (!kStartResult.io.ok)
    {
        const QString kErrorDetail = QString::fromStdString(kStartResult.io.message);
        const bool kUnsupported = kStartResult.unsupported;
        kernelDebugCaptureRunning_.store(false);
        QMetaObject::invokeMethod(this, [guardThis, kErrorDetail, kUnsupported]()
            {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->appendLocalizedDebugOutputLine(
                    kUnsupported
                        ? QStringLiteral("启动失败：当前 KswordARK 驱动版本不支持内核调试输出 IOCTL。")
                        : QStringLiteral("启动失败：R0 调试输出回调注册失败：%1")
                            .arg(kErrorDetail));
                guardThis->updateDebugCaptureButtonState();
            }, Qt::QueuedConnection);
        return;
    }

    QMetaObject::invokeMethod(this, [guardThis]()
        {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->appendLocalizedDebugOutputLine(
                QStringLiteral("R0 内核调试输出回调已启动，等待 DbgPrint/DbgPrintEx/KdPrintEx 消息..."));
            guardThis->updateDebugCaptureButtonState();
        }, Qt::QueuedConnection);

    std::uint64_t nextSequence = 0;
    std::uint64_t reportedDroppedCount = 0;
    while (kernelDebugCaptureRunning_.load())
    {
        const ksword::ark::DebugOutputDrainResult kDrainResult = driverClient.drainDebugOutput(
            driverHandle,
            nextSequence,
            KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS);
        if (!kDrainResult.io.ok)
        {
            const QString kErrorDetail = QString::fromStdString(kDrainResult.io.message);
            QMetaObject::invokeMethod(this, [guardThis, kErrorDetail]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->appendLocalizedDebugOutputLine(
                        QStringLiteral("读取 R0 调试输出失败：%1")
                        .arg(kErrorDetail));
                }, Qt::QueuedConnection);
            break;
        }

        nextSequence = kDrainResult.nextSequence;
        if ((kDrainResult.responseFlags & KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_OVERFLOW) != 0U &&
            kDrainResult.lostBeforeFirst != 0U)
        {
            const qulonglong kLostCount = static_cast<qulonglong>(kDrainResult.lostBeforeFirst);
            QMetaObject::invokeMethod(this, [guardThis, kLostCount]()
                {
                    if (guardThis != nullptr)
                    {
                        guardThis->appendLocalizedDebugOutputLine(
                            QStringLiteral("警告：读取游标落后，已有 %1 条内核调试消息被环形缓冲区覆盖。")
                            .arg(kLostCount));
                    }
                }, Qt::QueuedConnection);
        }
        if (kDrainResult.droppedCount > reportedDroppedCount)
        {
            const qulonglong kDroppedDelta = static_cast<qulonglong>(
                kDrainResult.droppedCount - reportedDroppedCount);
            reportedDroppedCount = kDrainResult.droppedCount;
            QMetaObject::invokeMethod(this, [guardThis, kDroppedDelta]()
                {
                    if (guardThis != nullptr)
                    {
                        guardThis->appendLocalizedDebugOutputLine(
                            QStringLiteral("警告：高 IRQL 并发写入期间丢弃了 %1 条内核调试消息。")
                            .arg(kDroppedDelta));
                    }
                }, Qt::QueuedConnection);
        }

        for (const ksword::ark::DebugOutputRecord& record : kDrainResult.records)
        {
            QString messageText = QString::fromUtf8(
                record.text.data(),
                static_cast<int>(record.text.size())).trimmed();
            if (messageText.isEmpty())
            {
                continue;
            }
            const bool kTextTruncated =
                (record.flags & KSWORD_ARK_DEBUG_OUTPUT_RECORD_FLAG_TEXT_TRUNCATED) != 0U;
            const QString kComponentText = QString::number(record.componentId, 16)
                .toUpper()
                .rightJustified(8, QLatin1Char('0'));
            const QString kLevelText = QString::number(record.level, 16)
                .toUpper()
                .rightJustified(8, QLatin1Char('0'));
            const QString kOutputLine = QStringLiteral("[Seq=%1][Component=0x%2][Level=0x%3] %4")
                .arg(static_cast<qulonglong>(record.sequence))
                .arg(kComponentText, kLevelText, messageText);
            QMetaObject::invokeMethod(this, [guardThis, kOutputLine, kTextTruncated]()
                {
                    if (guardThis != nullptr)
                    {
                        guardThis->appendDebugOutputLine(
                            kOutputLine,
                            kTextTruncated ? QStringLiteral(" [已截断]") : QString());
                    }
                }, Qt::QueuedConnection);
        }

        // Continue reading immediately if more records are available; otherwise, sleep briefly to reduce busy-wait overhead.
        if ((kDrainResult.responseFlags & KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_MORE_AVAILABLE) == 0U)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    const ksword::ark::DebugOutputControlResult kStopResult = driverClient.controlDebugOutput(
        driverHandle,
        KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP);
    kernelDebugCaptureRunning_.store(false);
    QMetaObject::invokeMethod(this, [guardThis, stopOk = kStopResult.io.ok]()
        {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->appendLocalizedDebugOutputLine(
                stopOk
                    ? QStringLiteral("R0 调试输出回调已停止。")
                    : QStringLiteral("捕获线程已退出，但 R0 回调注销返回失败。"));
            guardThis->updateDebugCaptureButtonState();
        }, Qt::QueuedConnection);
}

void DriverDock::updateDebugCaptureButtonState()
{
    const bool kRunning = kernelDebugCaptureRunning_.load();
    if (startCaptureButton_ != nullptr)
    {
        startCaptureButton_->setEnabled(!kRunning);
    }
    if (stopCaptureButton_ != nullptr)
    {
        stopCaptureButton_->setEnabled(kRunning);
    }
    if (debugCaptureStatusLabel_ != nullptr)
    {
        debugCaptureStatusLabel_->setText(
            kRunning
                ? driverText("driver.debug.status.running", QStringLiteral("状态：捕获运行中"))
                : driverText("driver.debug.status.not_started", QStringLiteral("状态：未启动")));
    }
}

void DriverDock::appendOperateLogLine(const QString& logText)
{
    if (operateLogOutput_ == nullptr)
    {
        return;
    }

    const QString kTimePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    operateLogOutput_->appendPlainText(QStringLiteral("[%1] %2").arg(kTimePrefix, logText));
}

void DriverDock::appendDebugOutputLine(
    const QString& debugText,
    const QString& localizedSuffixSource)
{
    if (debugOutputEdit_ == nullptr)
    {
        return;
    }

    constexpr std::size_t kMaximumDebugOutputLines = 2000U;
    if (debugOutputLines_.size() >= kMaximumDebugOutputLines)
    {
        debugOutputLines_.erase(debugOutputLines_.begin());
    }

    DebugOutputLineRecord record;
    record.timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    record.sourceText = debugText;
    record.localizedSuffixSource = localizedSuffixSource;
    record.translateSourceText = false;
    debugOutputLines_.push_back(record);

    debugOutputEdit_->appendPlainText(QStringLiteral("[%1] %2%3")
        .arg(record.timePrefix, record.sourceText, ks::i18n::displayText(record.localizedSuffixSource)));
}

void DriverDock::appendLocalizedDebugOutputLine(const QString& sourceText)
{
    if (debugOutputEdit_ == nullptr)
    {
        return;
    }

    constexpr std::size_t kMaximumDebugOutputLines = 2000U;
    if (debugOutputLines_.size() >= kMaximumDebugOutputLines)
    {
        debugOutputLines_.erase(debugOutputLines_.begin());
    }

    DebugOutputLineRecord record;
    record.timePrefix = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    record.sourceText = sourceText;
    record.translateSourceText = true;
    debugOutputLines_.push_back(record);
    debugOutputEdit_->appendPlainText(QStringLiteral("[%1] %2")
        .arg(record.timePrefix, ks::i18n::displayText(record.sourceText)));
}

void DriverDock::refreshDebugOutputLines()
{
    if (debugOutputEdit_ == nullptr)
    {
        return;
    }

    const QScrollBar* const kVerticalScrollBar = debugOutputEdit_->verticalScrollBar();
    const bool kKeepAtBottom = kVerticalScrollBar != nullptr &&
        kVerticalScrollBar->value() >= kVerticalScrollBar->maximum();
    QStringList renderedLines;
    renderedLines.reserve(static_cast<int>(debugOutputLines_.size()));
    for (const DebugOutputLineRecord& record : debugOutputLines_)
    {
        const QString kLineText = record.translateSourceText
            ? ks::i18n::displayText(record.sourceText)
            : record.sourceText;
        renderedLines.push_back(QStringLiteral("[%1] %2%3")
            .arg(
                record.timePrefix,
                kLineText,
                ks::i18n::displayText(record.localizedSuffixSource)));
    }
    debugOutputEdit_->setPlainText(renderedLines.join(QLatin1Char('\n')));
    if (kKeepAtBottom && debugOutputEdit_->verticalScrollBar() != nullptr)
    {
        debugOutputEdit_->verticalScrollBar()->setValue(
            debugOutputEdit_->verticalScrollBar()->maximum());
    }
}

void DriverDock::clearDebugOutputLines()
{
    debugOutputLines_.clear();
    if (debugOutputEdit_ != nullptr)
    {
        debugOutputEdit_->clear();
    }
}

bool DriverDock::queryDriverServiceRecords(
    std::vector<DriverServiceRecord>& recordListOut,
    std::string* errorTextOut)
{
    // DriverDock now delegates raw SCM enumeration/config reads to ks::service:
    // - input: no UI widgets are passed into the reusable layer;
    // - processing: this wrapper only converts std::wstring records into QString rows;
    // - return: true when SCM enumeration completed, false with UTF-8 error text.
    recordListOut.clear();
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    std::vector<ks::service::ServiceRecord> serviceRecordList;
    if (!ks::service::enumerateServiceRecords(
        SERVICE_DRIVER,
        SERVICE_STATE_ALL,
        &serviceRecordList,
        errorTextOut))
    {
        return false;
    }

    recordListOut.reserve(serviceRecordList.size());
    for (const ks::service::ServiceRecord& serviceRecord : serviceRecordList)
    {
        DriverServiceRecord driverRecord;
        driverRecord.serviceName = QString::fromStdWString(serviceRecord.serviceName);
        driverRecord.displayName = QString::fromStdWString(serviceRecord.displayName);
        driverRecord.currentState = serviceRecord.status.currentState;
        driverRecord.serviceType = serviceRecord.status.serviceType;
        if (serviceRecord.hasConfig)
        {
            driverRecord.startType = serviceRecord.config.startType;
            driverRecord.errorControl = serviceRecord.config.errorControl;
            driverRecord.binaryPath = QString::fromStdWString(serviceRecord.config.binaryPath);
            if (driverRecord.displayName.trimmed().isEmpty())
            {
                driverRecord.displayName = QString::fromStdWString(serviceRecord.config.displayName);
            }
        }
        driverRecord.description = QString::fromStdWString(serviceRecord.description);
        recordListOut.push_back(std::move(driverRecord));
    }

    std::sort(
        recordListOut.begin(),
        recordListOut.end(),
        [](const DriverServiceRecord& left, const DriverServiceRecord& right)
        {
            return left.serviceName.compare(right.serviceName, Qt::CaseInsensitive) < 0;
        });
    return true;
}

bool DriverDock::queryLoadedKernelModuleRecords(
    std::vector<LoadedKernelModuleRecord>& recordListOut,
    std::string* errorTextOut)
{
    recordListOut.clear();
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    // Dynamically resize the driver base address array to avoid truncation at a fixed 1024 when the number of drivers is large.
    std::vector<LPVOID> moduleBaseList(1024, nullptr);
    DWORD bytesNeeded = 0;
    while (true)
    {
        if (!::EnumDeviceDrivers(
            moduleBaseList.data(),
            static_cast<DWORD>(moduleBaseList.size() * sizeof(LPVOID)),
            &bytesNeeded))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("EnumDeviceDrivers failed: %1")
                    .arg(formatWin32ErrorText(::GetLastError()))
                    .toStdString();
            }
            return false;
        }

        const std::size_t kCurrentCapacityBytes = moduleBaseList.size() * sizeof(LPVOID);
        if (bytesNeeded <= kCurrentCapacityBytes)
        {
            break;
        }

        const std::size_t kRequiredCount =
            (static_cast<std::size_t>(bytesNeeded) + sizeof(LPVOID) - 1) / sizeof(LPVOID);
        moduleBaseList.assign(kRequiredCount + 128, nullptr);
    }

    const std::size_t kModuleCount = static_cast<std::size_t>(bytesNeeded / sizeof(LPVOID));
    recordListOut.reserve(kModuleCount);
    for (std::size_t index = 0; index < kModuleCount; ++index)
    {
        LPVOID moduleBase = moduleBaseList[index];
        if (moduleBase == nullptr)
        {
            continue;
        }

        std::array<wchar_t, MAX_PATH> moduleNameBuffer{};
        std::array<wchar_t, 1024> modulePathBuffer{};
        const DWORD kNameLength = ::GetDeviceDriverBaseNameW(
            moduleBase,
            moduleNameBuffer.data(),
            static_cast<DWORD>(moduleNameBuffer.size()));
        const DWORD kPathLength = ::GetDeviceDriverFileNameW(
            moduleBase,
            modulePathBuffer.data(),
            static_cast<DWORD>(modulePathBuffer.size()));

        LoadedKernelModuleRecord moduleRecord;
        moduleRecord.moduleName = (kNameLength == 0)
            ? QStringLiteral("<unknown>")
            : QString::fromWCharArray(moduleNameBuffer.data());
        moduleRecord.imagePath = (kPathLength == 0)
            ? QStringLiteral("<unknown>")
            : QString::fromWCharArray(modulePathBuffer.data());
        moduleRecord.baseAddress = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(moduleBase));
        recordListOut.push_back(std::move(moduleRecord));
    }

    std::sort(
        recordListOut.begin(),
        recordListOut.end(),
        [](const LoadedKernelModuleRecord& left, const LoadedKernelModuleRecord& right)
        {
            return left.moduleName.compare(right.moduleName, Qt::CaseInsensitive) < 0;
        });
    return true;
}

QString DriverDock::serviceStateToText(const std::uint32_t stateValue)
{
    switch (stateValue)
    {
    case SERVICE_STOPPED:
        return driverText("driver.service.state.stopped", QStringLiteral("已停止"));
    case SERVICE_START_PENDING:
        return driverText("driver.service.state.start_pending", QStringLiteral("启动中"));
    case SERVICE_STOP_PENDING:
        return driverText("driver.service.state.stop_pending", QStringLiteral("停止中"));
    case SERVICE_RUNNING:
        return driverText("driver.service.state.running", QStringLiteral("运行中"));
    case SERVICE_CONTINUE_PENDING:
        return driverText("driver.service.state.continue_pending", QStringLiteral("继续中"));
    case SERVICE_PAUSE_PENDING:
        return driverText("driver.service.state.pause_pending", QStringLiteral("暂停中"));
    case SERVICE_PAUSED:
        return driverText("driver.service.state.paused", QStringLiteral("已暂停"));
    default:
        return driverText("driver.service.state.unknown", QStringLiteral("未知状态(%1)"))
            .arg(stateValue);
    }
}

QString DriverDock::startTypeToText(const std::uint32_t startTypeValue)
{
    switch (startTypeValue)
    {
    case SERVICE_BOOT_START:   return QStringLiteral("BOOT");
    case SERVICE_SYSTEM_START: return QStringLiteral("SYSTEM");
    case SERVICE_AUTO_START:   return QStringLiteral("AUTO");
    case SERVICE_DEMAND_START: return QStringLiteral("DEMAND");
    case SERVICE_DISABLED:     return QStringLiteral("DISABLED");
    default:                   return QStringLiteral("UNKNOWN(%1)").arg(startTypeValue);
    }
}

QString DriverDock::errorControlToText(const std::uint32_t errorControlValue)
{
    switch (errorControlValue)
    {
    case SERVICE_ERROR_IGNORE:   return QStringLiteral("IGNORE");
    case SERVICE_ERROR_NORMAL:   return QStringLiteral("NORMAL");
    case SERVICE_ERROR_SEVERE:   return QStringLiteral("SEVERE");
    case SERVICE_ERROR_CRITICAL: return QStringLiteral("CRITICAL");
    default:                     return QStringLiteral("UNKNOWN(%1)").arg(errorControlValue);
    }
}

QString DriverDock::formatWin32ErrorText(const std::uint32_t win32ErrorCode)
{
    // Keep DriverDock formatting as a UI adapter only:
    // - input: raw Win32 error code;
    // - processing: ks::service owns FormatMessageW and UTF-8 formatting;
    // - return: QString text suitable for existing log lines.
    return QString::fromUtf8(ks::service::formatWin32ErrorText(win32ErrorCode).c_str());
}

QString DriverDock::trimQuotedText(const QString& textValue)
{
    QString normalizedText = textValue.trimmed();
    if (normalizedText.startsWith('"') && normalizedText.endsWith('"') && normalizedText.size() >= 2)
    {
        normalizedText = normalizedText.mid(1, normalizedText.size() - 2);
    }
    return normalizedText.trimmed();
}

QString DriverDock::normalizeDriverBinaryPath(const QString& pathText)
{
    QString normalizedPath = pathText.trimmed();
    if (normalizedPath.isEmpty())
    {
        return normalizedPath;
    }

    const bool kQuoted =
        normalizedPath.startsWith('"') &&
        normalizedPath.endsWith('"') &&
        normalizedPath.size() >= 2;
    if (!kQuoted && normalizedPath.contains(' '))
    {
        normalizedPath = QStringLiteral("\"%1\"").arg(normalizedPath);
    }
    return normalizedPath;
}
