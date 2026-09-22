#include "WinAPIDock.h"
#include "../Theme.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../ui/TableInteractionSupport.h"

// ============================================================
// WinAPIDock.Pipe.cpp
// Purpose:
// 1) Implement connection and reading with the APIMonitor_x64 named pipe server;
// 2) Converts fixed-length event packets received by the backend into EventRow objects for UI display.
// 3) Unified handling of background thread exit, connection failure, and batch refresh of the event table.
// ============================================================

#include <QApplication>
#include <QAbstractItemModel>
#include <QBrush>
#include <QCheckBox>
#include <QColor>
#include <QElapsedTimer>
#include <QFile>
#include <QMetaObject>
#include <QPointer>
#include <QTableWidget>
#include <QTableWidgetItem>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>

namespace
{
    // kApiMonitorPacketSize：
    // - Purpose: Standardize the fixed packet size for each read operation on the UI-side named pipe.
    // - Usage: The main target pipe and the auto-injection child process pipe share the same protocol structure.
    constexpr DWORD kApiMonitorPacketSize = static_cast<DWORD>(sizeof(ks::winapi_monitor::ApiMonitorEventPacket));

    // packetWideText：
    // - Purpose: Convert a fixed-length wchar_t buffer to QString;
    // - Invocation: Reused when parsing moduleName/apiName/detailText returned by the Agent.
    template <std::size_t kCount>
    QString packetWideText(const wchar_t(&bufferValue)[kCount])
    {
        QString textValue = QString::fromWCharArray(bufferValue, static_cast<int>(kCount));
        const int kNullIndex = textValue.indexOf(QChar(u'\0'));
        if (kNullIndex >= 0)
        {
            textValue.truncate(kNullIndex);
        }
        return textValue.trimmed();
    }

    // packetEventCategoryText：
    // - Purpose: Convert protocol category codes to UI text;
    // - Invocation: Used in Pipe.cpp for local parsing of main process/child process event packets.
    // - Returns: The Chinese name of the category; returns "Unknown" for unknown categories.
    QString packetEventCategoryText(const std::uint32_t categoryValue)
    {
        switch (static_cast<ks::winapi_monitor::EventCategory>(categoryValue))
        {
        case ks::winapi_monitor::EventCategory::kFile:
            return QStringLiteral("文件");
        case ks::winapi_monitor::EventCategory::kRegistry:
            return QStringLiteral("注册表");
        case ks::winapi_monitor::EventCategory::kNetwork:
            return QStringLiteral("网络");
        case ks::winapi_monitor::EventCategory::kProcess:
            return QStringLiteral("进程");
        case ks::winapi_monitor::EventCategory::kLoader:
            return QStringLiteral("加载器");
        case ks::winapi_monitor::EventCategory::kInternal:
            return QStringLiteral("内部");
        default:
            break;
        }
        return QStringLiteral("未知");
    }

    // packetResultCodeText：
    // - Purpose: Convert the Agent resultCode to table text.
    // - Invocation: Used in Pipe.cpp to locally parse event packets, avoiding access to WinAPIDock's private static functions;
    // - Return: 0 indicates OK; non-zero indicates a decimal error code.
    QString packetResultCodeText(const std::int32_t resultCodeValue)
    {
        return resultCodeValue == 0
            ? QStringLiteral("OK")
            : QString::number(resultCodeValue);
    }

    // packetToEventRow：
    // - Purpose: Convert the Agent's fixed packet into a WinAPIDock::EventRow.
    // - Usage: Shared between the main process pipe and child process pipe read threads.
    // - Returns: The converted event row; the caller is responsible for enqueueing or displaying it.
    WinAPIDock::EventRow packetToEventRow(const ks::winapi_monitor::ApiMonitorEventPacket& packetValue)
    {
        WinAPIDock::EventRow rowValue;
        rowValue.time100nsText = QString::number(static_cast<qulonglong>(packetValue.timestamp100ns));
        rowValue.categoryText = packetEventCategoryText(packetValue.category);

        const QString kModuleNameText = packetWideText(packetValue.moduleName);
        const QString kApiNameText = packetWideText(packetValue.apiName);
        rowValue.apiText = kModuleNameText.trimmed().isEmpty()
            ? kApiNameText
            : QStringLiteral("%1!%2").arg(kModuleNameText, kApiNameText);
        rowValue.resultText = packetResultCodeText(packetValue.resultCode);
        rowValue.pidTidText = QStringLiteral("%1 / %2").arg(packetValue.pid).arg(packetValue.tid);
        rowValue.detailText = packetWideText(packetValue.detailText);
        rowValue.internalEvent =
            packetValue.category == static_cast<std::uint32_t>(ks::winapi_monitor::EventCategory::kInternal);
        return rowValue;
    }

    // tryExtractAutoInjectChildPid：
    // - Purpose: Extract childPid from the Agent's internal AutoInjectChild event details;
    // - Called: After the main target pipe receives a child process injection success event, it starts the corresponding child pipe read thread.
    // - Return: true if parsing succeeds, outputting PID via childPidOut.
    bool tryExtractAutoInjectChildPid(
        const ks::winapi_monitor::ApiMonitorEventPacket& packetValue,
        std::uint32_t* const childPidOut)
    {
        if (childPidOut == nullptr)
        {
            return false;
        }
        *childPidOut = 0;

        const QString kApiNameText = packetWideText(packetValue.apiName);
        if (packetValue.category != static_cast<std::uint32_t>(ks::winapi_monitor::EventCategory::kInternal)
            || kApiNameText != QStringLiteral("AutoInjectChild"))
        {
            return false;
        }

        const QString kDetailText = packetWideText(packetValue.detailText);
        const QString kMarkerText = QStringLiteral("childPid=");
        const int kMarkerIndex = kDetailText.indexOf(kMarkerText);
        if (kMarkerIndex < 0)
        {
            return false;
        }

        int valueStart = kMarkerIndex + kMarkerText.size();
        int valueEnd = valueStart;
        while (valueEnd < kDetailText.size() && kDetailText.at(valueEnd).isDigit())
        {
            ++valueEnd;
        }

        bool parseOk = false;
        const std::uint32_t kPidValue = kDetailText.mid(valueStart, valueEnd - valueStart).toUInt(&parseOk, 10);
        if (!parseOk || kPidValue == 0)
        {
            return false;
        }

        *childPidOut = kPidValue;
        return true;
    }
}

void WinAPIDock::startPipeReadThread()
{
    if (pipeThread_ != nullptr && pipeThread_->joinable())
    {
        pipeThread_->join();
        pipeThread_.reset();
    }

    const QString kPipeNameText = currentPipeName_;
    const std::uint32_t kSessionPidValue = currentSessionPid_;
    QPointer<WinAPIDock> guardThis(this);

    pipeThread_ = std::make_unique<std::thread>([guardThis, kPipeNameText, kSessionPidValue]() {
        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 120; ++attempt)
        {
            if (guardThis == nullptr || guardThis->pipeStopFlag_.load())
            {
                return;
            }

            pipeHandle = ::CreateFileW(
                reinterpret_cast<LPCWSTR>(kPipeNameText.utf16()),
                GENERIC_READ,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (pipeHandle != INVALID_HANDLE_VALUE)
            {
                break;
            }

            const DWORD kLastError = ::GetLastError();
            if (kLastError != ERROR_FILE_NOT_FOUND && kLastError != ERROR_PIPE_BUSY)
            {
                QMetaObject::invokeMethod(qApp, [guardThis, kLastError]() {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    (void)ks::ui::promptForPrivilegeFailure(
                        guardThis,
                        QStringLiteral("连接 API 监控命名管道"),
                        kLastError);
                    guardThis->appendInternalEvent(
                        QStringLiteral("内部"),
                        QStringLiteral("命名管道连接失败"),
                        QStringLiteral("CreateFileW 返回错误码 %1。").arg(kLastError));
                }, Qt::QueuedConnection);
                guardThis->pipeRunning_.store(false);
                return;
            }

            ::WaitNamedPipeW(reinterpret_cast<LPCWSTR>(kPipeNameText.utf16()), 250);
            ::Sleep(120);
        }

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            QMetaObject::invokeMethod(qApp, [guardThis]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->appendInternalEvent(
                    QStringLiteral("内部"),
                    QStringLiteral("命名管道连接超时"),
                    QStringLiteral("在限定时间内未等到 Agent 建立管道服务端。"));
                guardThis->pipeRunning_.store(false);
                guardThis->pipeConnected_.store(false);
                guardThis->updateActionState();
                guardThis->updateStatusLabel();
            }, Qt::QueuedConnection);
            return;
        }

        guardThis->pipeHandleValue_.store(reinterpret_cast<std::uintptr_t>(pipeHandle));
        guardThis->pipeConnected_.store(true);
        kPro.set(guardThis->sessionProgressPid_, "Agent 已连接，开始接收 WinAPI 事件", 0, 70.0f);

        QMetaObject::invokeMethod(qApp, [guardThis, kSessionPidValue]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->appendInternalEvent(
                QStringLiteral("内部"),
                QStringLiteral("管道已连接"),
                QStringLiteral("已与 PID=%1 的 Agent 建立命名管道连接。").arg(kSessionPidValue));
            guardThis->updateActionState();
            guardThis->updateStatusLabel();
        }, Qt::QueuedConnection);

        while (!guardThis->pipeStopFlag_.load())
        {
            ks::winapi_monitor::ApiMonitorEventPacket packetValue{};
            DWORD bytesRead = 0;
            const BOOL kReadOk = ::ReadFile(
                pipeHandle,
                &packetValue,
                kApiMonitorPacketSize,
                &bytesRead,
                nullptr);
            if (kReadOk == FALSE || bytesRead == 0)
            {
                break;
            }
            if (bytesRead < sizeof(packetValue)
                || packetValue.size != sizeof(packetValue)
                || packetValue.version != ks::winapi_monitor::kProtocolVersion)
            {
                continue;
            }

            std::uint32_t childPidValue = 0;
            if (tryExtractAutoInjectChildPid(packetValue, &childPidValue))
            {
                QMetaObject::invokeMethod(qApp, [guardThis, childPidValue]() {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->startChildPipeReadThread(childPidValue);
                }, Qt::QueuedConnection);
            }

            guardThis->enqueuePendingRow(packetToEventRow(packetValue));
        }

        const std::uintptr_t kStoredHandleValue = guardThis->pipeHandleValue_.exchange(0);
        if (kStoredHandleValue != 0)
        {
            ::CloseHandle(reinterpret_cast<HANDLE>(kStoredHandleValue));
        }

        const bool kRetryConnection = !guardThis->pipeStopFlag_.load()
            && guardThis->pipeRunning_.load()
            && guardThis->pipeReconnectAttempts_.fetch_add(1) < kPipeReconnectLimit;

        QMetaObject::invokeMethod(qApp, [guardThis, kRetryConnection]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->pipeConnected_.store(false);
            if (kRetryConnection && !guardThis->pipeStopFlag_.load() && guardThis->pipeRunning_.load())
            {
                guardThis->appendInternalEvent(
                    QStringLiteral("内部"),
                    QStringLiteral("管道短暂断开"),
                    QStringLiteral("Agent 正在切换会话，正在重新连接命名管道。"));
                guardThis->startPipeReadThread();
                return;
            }
            if (guardThis->pipeStopFlag_.load())
            {
                guardThis->appendInternalEvent(
                    QStringLiteral("内部"),
                    QStringLiteral("会话结束"),
                    QStringLiteral("本地已停止接收 WinAPI 事件。"));
            }
            else
            {
                guardThis->appendInternalEvent(
                    QStringLiteral("内部"),
                    QStringLiteral("管道已断开"),
                    QStringLiteral("Agent 主动关闭或目标进程已退出。"));
            }
            guardThis->pipeRunning_.store(false);
            guardThis->updateActionState();
            guardThis->updateStatusLabel();
            kPro.set(guardThis->sessionProgressPid_, "WinAPI 事件接收结束", 0, 100.0f);
        }, Qt::QueuedConnection);
    });
}

void WinAPIDock::startChildPipeReadThread(const std::uint32_t childPidValue)
{
    if (childPidValue == 0 || childPidValue == currentSessionPid_ || pipeStopFlag_.load())
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(childPipeMutex_);
        if (std::find(childSessionPids_.begin(), childSessionPids_.end(), childPidValue) != childSessionPids_.end())
        {
            return;
        }
        childSessionPids_.push_back(childPidValue);
    }

    const QString kPipeNameText = QString::fromStdWString(ks::winapi_monitor::buildPipeNameForPid(childPidValue));
    QPointer<WinAPIDock> guardThis(this);
    auto childThread = std::make_unique<std::thread>([guardThis, kPipeNameText, childPidValue]() {
        HANDLE pipeHandle = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 120; ++attempt)
        {
            if (guardThis == nullptr || guardThis->pipeStopFlag_.load())
            {
                return;
            }

            pipeHandle = ::CreateFileW(
                reinterpret_cast<LPCWSTR>(kPipeNameText.utf16()),
                GENERIC_READ,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (pipeHandle != INVALID_HANDLE_VALUE)
            {
                break;
            }

            const DWORD kLastError = ::GetLastError();
            if (kLastError != ERROR_FILE_NOT_FOUND && kLastError != ERROR_PIPE_BUSY)
            {
                QMetaObject::invokeMethod(qApp, [guardThis, childPidValue, kLastError]() {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    (void)ks::ui::promptForPrivilegeFailure(
                        guardThis,
                        QStringLiteral("连接子进程 API 监控命名管道"),
                        kLastError);
                    guardThis->appendInternalEvent(
                        QStringLiteral("内部"),
                        QStringLiteral("子进程管道连接失败"),
                        QStringLiteral("PID=%1 CreateFileW 错误码 %2。").arg(childPidValue).arg(kLastError));
                }, Qt::QueuedConnection);
                return;
            }

            ::WaitNamedPipeW(reinterpret_cast<LPCWSTR>(kPipeNameText.utf16()), 250);
            ::Sleep(120);
        }

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            QMetaObject::invokeMethod(qApp, [guardThis, childPidValue]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                guardThis->appendInternalEvent(
                    QStringLiteral("内部"),
                    QStringLiteral("子进程管道连接超时"),
                    QStringLiteral("PID=%1 的 Agent 管道未在限定时间内建立。").arg(childPidValue));
            }, Qt::QueuedConnection);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(guardThis->childPipeMutex_);
            guardThis->childPipeHandleValues_.push_back(reinterpret_cast<std::uintptr_t>(pipeHandle));
        }

        QMetaObject::invokeMethod(qApp, [guardThis, childPidValue]() {
            if (guardThis == nullptr)
            {
                return;
            }
            guardThis->appendInternalEvent(
                QStringLiteral("内部"),
                QStringLiteral("子进程管道已连接"),
                QStringLiteral("已开始接收 PID=%1 的自动注入 Agent 事件。").arg(childPidValue));
        }, Qt::QueuedConnection);

        while (!guardThis->pipeStopFlag_.load())
        {
            ks::winapi_monitor::ApiMonitorEventPacket packetValue{};
            DWORD bytesRead = 0;
            const BOOL kReadOk = ::ReadFile(
                pipeHandle,
                &packetValue,
                kApiMonitorPacketSize,
                &bytesRead,
                nullptr);
            if (kReadOk == FALSE || bytesRead == 0)
            {
                break;
            }
            if (bytesRead < sizeof(packetValue)
                || packetValue.size != sizeof(packetValue)
                || packetValue.version != ks::winapi_monitor::kProtocolVersion)
            {
                continue;
            }

            guardThis->enqueuePendingRow(packetToEventRow(packetValue));
        }

        bool shouldClosePipeHandle = false;
        {
            std::lock_guard<std::mutex> lock(guardThis->childPipeMutex_);
            auto& handleList = guardThis->childPipeHandleValues_;
            const std::uintptr_t kHandleValue = reinterpret_cast<std::uintptr_t>(pipeHandle);
            const auto kHandleIt = std::find(handleList.begin(), handleList.end(), kHandleValue);
            if (kHandleIt != handleList.end())
            {
                handleList.erase(kHandleIt);
                shouldClosePipeHandle = true;
            }
        }
        if (shouldClosePipeHandle)
        {
            ::CloseHandle(pipeHandle);
        }
    });

    std::lock_guard<std::mutex> lock(childPipeMutex_);
    childPipeThreads_.push_back(std::move(childThread));
}

void WinAPIDock::closeChildPipeHandles()
{
    std::vector<std::uintptr_t> handleList;
    {
        std::lock_guard<std::mutex> lock(childPipeMutex_);
        handleList.swap(childPipeHandleValues_);
    }

    for (const std::uintptr_t kHandleValue : handleList)
    {
        if (kHandleValue != 0)
        {
            ::CloseHandle(reinterpret_cast<HANDLE>(kHandleValue));
        }
    }
}

void WinAPIDock::joinChildPipeThreads()
{
    std::vector<std::unique_ptr<std::thread>> threadList;
    {
        std::lock_guard<std::mutex> lock(childPipeMutex_);
        threadList.swap(childPipeThreads_);
    }

    for (std::unique_ptr<std::thread>& threadPointer : threadList)
    {
        if (threadPointer != nullptr && threadPointer->joinable())
        {
            // Each child reader owns a synchronous ReadFile on its pipe handle.
            (void)::CancelSynchronousIo(threadPointer->native_handle());
        }
    }

    for (std::unique_ptr<std::thread>& threadPointer : threadList)
    {
        if (threadPointer != nullptr && threadPointer->joinable())
        {
            threadPointer->join();
        }
    }
}

void WinAPIDock::writeChildStopFlags()
{
    std::vector<std::uint32_t> childPidList;
    {
        std::lock_guard<std::mutex> lock(childPipeMutex_);
        childPidList = childSessionPids_;
    }

    for (const std::uint32_t kChildPidValue : childPidList)
    {
        const QString kStopFlagPath = QString::fromStdWString(ks::winapi_monitor::buildStopFlagPathForPid(kChildPidValue));
        QFile stopFile(kStopFlagPath);
        if (stopFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
        {
            stopFile.write("stop");
            stopFile.close();
        }
    }
}

void WinAPIDock::enqueuePendingRow(EventRow rowValue)
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    if (pendingRows_.size() >= kPendingRowCapacity)
    {
        pendingRows_.pop_front();
        ++pendingDroppedRows_;
    }
    pendingRows_.push_back(std::move(rowValue));
}

void WinAPIDock::flushPendingRows()
{
    // Do not drain pipe events while the table menu is open. If a refresh with the same key is superseded, already-drained
    // EventRow records would be lost; removeRows(0, ...) would also invalidate the row indices retained by the menu.
    const QPointer<WinAPIDock> kGuardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("winapi-event-flush"),
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

    std::vector<EventRow> rowList;
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
        return;
    }

    QElapsedTimer budgetTimer;
    budgetTimer.start();

    std::size_t renderedCount = 0;
    if (eventTable_ != nullptr)
    {
        const bool kUpdatesEnabled = eventTable_->updatesEnabled();
        eventTable_->setUpdatesEnabled(false);

        for (const EventRow& rowValue : rowList)
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
        }

        eventTable_->setUpdatesEnabled(kUpdatesEnabled);
        if (kUpdatesEnabled && eventTable_->viewport() != nullptr)
        {
            eventTable_->viewport()->update();
        }
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

    applyEventFilter();
    updateActionState();
    updateStatusLabel();

    if (eventKeepBottomCheck_ != nullptr
        && eventKeepBottomCheck_->isChecked()
        && eventTable_ != nullptr)
    {
        eventTable_->scrollToBottom();
    }
}

void WinAPIDock::appendEventRow(const EventRow& rowValue)
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    const int kRow = eventTable_->rowCount();
    eventTable_->insertRow(kRow);

    QTableWidgetItem* timeItem = createReadOnlyItem(rowValue.time100nsText);
    QTableWidgetItem* categoryItem = createReadOnlyItem(rowValue.categoryText);
    QTableWidgetItem* apiItem = createReadOnlyItem(rowValue.apiText);
    QTableWidgetItem* resultItem = createReadOnlyItem(rowValue.resultText);
    QTableWidgetItem* pidTidItem = createReadOnlyItem(rowValue.pidTidText);
    QTableWidgetItem* detailItem = createReadOnlyItem(rowValue.detailText);

    if (rowValue.internalEvent)
    {
        const QBrush kInternalBrush(ksword_theme::infoColor());
        categoryItem->setForeground(kInternalBrush);
        apiItem->setForeground(kInternalBrush);
    }
    else if (rowValue.resultText != QStringLiteral("OK"))
    {
        const QBrush kErrorBrush(ksword_theme::errorColor());
        resultItem->setForeground(kErrorBrush);
    }

    eventTable_->setItem(kRow, kEventColumnTime100ns, timeItem);
    eventTable_->setItem(kRow, kEventColumnCategory, categoryItem);
    eventTable_->setItem(kRow, kEventColumnApi, apiItem);
    eventTable_->setItem(kRow, kEventColumnResult, resultItem);
    eventTable_->setItem(kRow, kEventColumnPidTid, pidTidItem);
    eventTable_->setItem(kRow, kEventColumnDetail, detailItem);
}
