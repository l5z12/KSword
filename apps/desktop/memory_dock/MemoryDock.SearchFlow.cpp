#include "MemoryDock.Internal.h"
#include "../ui/TableInteractionSupport.h"

#include <memory>

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.SearchFlow.cpp
// Purpose: Carries the logic for the first/second scan flow and background scan execution.
// ============================================================

void MemoryDock::startFirstScan()
{
    // First scan entry log: record the current attached PID and scan parameters.
    KLogEvent firstScanStartEvent;
    info << firstScanStartEvent
        << "[MemoryDock] startFirstScan: 请求开始首次扫描, attachedPid="
        << attachedPid_
        << ", scanThreadCount="
        << scanThreadCount_
        << ", scanChunkSizeKB="
        << scanChunkSizeKB_
        << eol;

    // Prevent duplicate initiation during scanning to avoid multiple background threads concurrently reading the same state.
    if (scanInProgress_.load())
    {
        KLogEvent firstScanBusyEvent;
        warn << firstScanBusyEvent
            << "[MemoryDock] startFirstScan: 已有扫描在执行，拒绝重复启动。"
            << eol;
        QMessageBox::information(this, "内存扫描", "当前已有扫描任务正在执行。");
        return;
    }

    // Process must be attached before the first scan.
    if (attachedProcessHandle_ == nullptr || attachedPid_ == 0)
    {
        KLogEvent firstScanNoAttachEvent;
        warn << firstScanNoAttachEvent
            << "[MemoryDock] startFirstScan: 未附加进程，无法扫描。"
            << eol;
        QMessageBox::warning(this, "内存扫描", "请先附加目标进程。");
        return;
    }

    // Parse input values first, then collect scan regions; both steps may fail and return a readable error.
    ParsedSearchPattern pattern{};
    QString parseError;
    if (!parseSearchPatternFromUi(pattern, parseError))
    {
        KLogEvent firstScanParseFailEvent;
        warn << firstScanParseFailEvent
            << "[MemoryDock] startFirstScan: 解析扫描值失败, error="
            << parseError.toStdString()
            << eol;
        QMessageBox::warning(this, "内存扫描", parseError);
        return;
    }

    std::vector<RegionEntry> scanRegions;
    QString regionError;
    if (!collectSearchRegionsFromUi(scanRegions, regionError))
    {
        KLogEvent firstScanCollectFailEvent;
        warn << firstScanCollectFailEvent
            << "[MemoryDock] startFirstScan: 收集扫描区域失败, error="
            << regionError.toStdString()
            << eol;
        QMessageBox::warning(this, "内存扫描", regionError);
        return;
    }

    // On the first scan, reset the previous results and update the 'last scanned type' to the current dropdown selection.
    lastSearchValueType_ = pattern.valueType;
    searchResultCache_.clear();
    rebuildSearchResultTable();

    // UI state transition: Disable the start button, enable the cancel button, and display the 'preparing' prompt text.
    scanInProgress_.store(true);
    scanCancelRequested_.store(false);
    firstScanButton_->setEnabled(false);
    nextScanButton_->setEnabled(false);
    resetScanButton_->setEnabled(false);
    cancelScanButton_->setEnabled(true);
    scanProgressBar_->setValue(0);
    scanStatusLabel_->setText(
        QString("扫描中：区域=%1，线程=%2")
        .arg(scanRegions.size())
        .arg(scanThreadCount_));

    // First scan preparation ready log: record pattern byte length and total region count.
    KLogEvent firstScanPreparedEvent;
    info << firstScanPreparedEvent
        << "[MemoryDock] startFirstScan: 准备完成, patternBytes="
        << pattern.exactBytes.size()
        << ", regionCount="
        << scanRegions.size()
        << eol;

    // Enter the background scan thread to prevent the ReadProcessMemory loop from blocking the main UI.
    scanMemoryRegionsInBackground(scanRegions, pattern);
}

void MemoryDock::startNextScan()
{
    // Log for re-scan entry: output current result count and comparison condition index.
    KLogEvent nextScanStartEvent;
    info << nextScanStartEvent
        << "[MemoryDock] startNextScan: 开始再次扫描, cachedResultCount="
        << searchResultCache_.size()
        << ", compareIndex="
        << nextScanCompareCombo_->currentIndex()
        << eol;

    // A subsequent scan depends on the result of the initial scan; if no result is found, prompt directly without executing a meaningless loop.
    if (scanInProgress_.load())
    {
        KLogEvent nextScanBusyEvent;
        warn << nextScanBusyEvent
            << "[MemoryDock] startNextScan: 扫描忙碌中，拒绝重复请求。"
            << eol;
        QMessageBox::information(this, "再次扫描", "当前正在执行扫描，请稍候。");
        return;
    }
    if (attachedProcessHandle_ == nullptr || searchResultCache_.empty())
    {
        KLogEvent nextScanPrerequisiteFailEvent;
        warn << nextScanPrerequisiteFailEvent
            << "[MemoryDock] startNextScan: 前置条件不满足, attachedPid="
            << attachedPid_
            << ", cachedResultCount="
            << searchResultCache_.size()
            << eol;
        QMessageBox::warning(this, "再次扫描", "请先完成首次扫描并保留结果。");
        return;
    }

    // Inline the common 'bytes to value' logic as a local lambda for easier reuse across multiple conditional comparisons.
    const auto kBytesToDouble = [](const QByteArray& sourceBytes, const SearchValueType valueType, double& numberOut) -> bool
        {
            if (sourceBytes.isEmpty())
            {
                return false;
            }

            switch (valueType)
            {
            case SearchValueType::kByte:
            {
                if (sourceBytes.size() < static_cast<int>(sizeof(std::uint8_t))) return false;
                std::uint8_t value = 0;
                std::memcpy(&value, sourceBytes.constData(), sizeof(value));
                numberOut = static_cast<double>(value);
                return true;
            }
            case SearchValueType::kInt16:
            {
                if (sourceBytes.size() < static_cast<int>(sizeof(std::int16_t))) return false;
                std::int16_t value = 0;
                std::memcpy(&value, sourceBytes.constData(), sizeof(value));
                numberOut = static_cast<double>(value);
                return true;
            }
            case SearchValueType::kInt32:
            {
                if (sourceBytes.size() < static_cast<int>(sizeof(std::int32_t))) return false;
                std::int32_t value = 0;
                std::memcpy(&value, sourceBytes.constData(), sizeof(value));
                numberOut = static_cast<double>(value);
                return true;
            }
            case SearchValueType::kInt64:
            {
                if (sourceBytes.size() < static_cast<int>(sizeof(std::int64_t))) return false;
                std::int64_t value = 0;
                std::memcpy(&value, sourceBytes.constData(), sizeof(value));
                numberOut = static_cast<double>(value);
                return true;
            }
            case SearchValueType::kFloat32:
            {
                if (sourceBytes.size() < static_cast<int>(sizeof(float))) return false;
                float value = 0.0f;
                std::memcpy(&value, sourceBytes.constData(), sizeof(value));
                numberOut = static_cast<double>(value);
                return true;
            }
            case SearchValueType::kFloat64:
            {
                if (sourceBytes.size() < static_cast<int>(sizeof(double))) return false;
                double value = 0.0;
                std::memcpy(&value, sourceBytes.constData(), sizeof(value));
                numberOut = value;
                return true;
            }
            default:
                return false;
            }
        };

    // The current comparison mode determines whether numeric input is required; change-type conditions do not need additional input.
    const auto kCompareMode = static_cast<SearchCompareMode>(
        nextScanCompareCombo_->itemData(nextScanCompareCombo_->currentIndex()).toInt());
    const bool kNeedNumericInput = (
        kCompareMode == SearchCompareMode::kEqual ||
        kCompareMode == SearchCompareMode::kGreater ||
        kCompareMode == SearchCompareMode::kLess ||
        kCompareMode == SearchCompareMode::kBetween);

    const bool kIsNumericType = (
        lastSearchValueType_ == SearchValueType::kByte ||
        lastSearchValueType_ == SearchValueType::kInt16 ||
        lastSearchValueType_ == SearchValueType::kInt32 ||
        lastSearchValueType_ == SearchValueType::kInt64 ||
        lastSearchValueType_ == SearchValueType::kFloat32 ||
        lastSearchValueType_ == SearchValueType::kFloat64);

    // Non-numeric types do not support >, <, between, or increment/decrement comparisons to avoid semantic confusion.
    if (!kIsNumericType && kCompareMode != SearchCompareMode::kEqual &&
        kCompareMode != SearchCompareMode::kChanged &&
        kCompareMode != SearchCompareMode::kUnchanged)
    {
        KLogEvent nextScanCompareUnsupportedEvent;
        warn << nextScanCompareUnsupportedEvent
            << "[MemoryDock] startNextScan: 当前数据类型不支持比较模式, valueType="
            << static_cast<int>(lastSearchValueType_)
            << ", compareMode="
            << static_cast<int>(kCompareMode)
            << eol;
        QMessageBox::warning(this, "再次扫描", "当前数据类型仅支持 等于/变化/未变化 条件。");
        return;
    }

    double compareA = 0.0;
    double compareB = 0.0;
    if (kNeedNumericInput && kIsNumericType)
    {
        bool parseOkA = false;
        compareA = nextScanValueEdit_->text().trimmed().toDouble(&parseOkA);
        if (!parseOkA)
        {
            KLogEvent nextScanValueAParseFailEvent;
            warn << nextScanValueAParseFailEvent
                << "[MemoryDock] startNextScan: 条件值A解析失败, text="
                << nextScanValueEdit_->text().trimmed().toStdString()
                << eol;
            QMessageBox::warning(this, "再次扫描", "条件值A解析失败。");
            return;
        }

        if (kCompareMode == SearchCompareMode::kBetween)
        {
            bool parseOkB = false;
            compareB = nextScanValueBEdit_->text().trimmed().toDouble(&parseOkB);
            if (!parseOkB)
            {
                KLogEvent nextScanValueBParseFailEvent;
                warn << nextScanValueBParseFailEvent
                    << "[MemoryDock] startNextScan: 条件值B解析失败, text="
                    << nextScanValueBEdit_->text().trimmed().toStdString()
                    << eol;
                QMessageBox::warning(this, "再次扫描", "条件值B解析失败。");
                return;
            }
            if (compareA > compareB)
            {
                std::swap(compareA, compareB);
            }
        }
    }

    // For non-numeric types under the "Equal" condition, reconstruct comparison bytes based on user input text.
    QByteArray nonNumericCompareBytes;
    QByteArray nonNumericWildcardMask;
    if (!kIsNumericType && kCompareMode == SearchCompareMode::kEqual)
    {
        const QString kCompareText = nextScanValueEdit_->text().trimmed();
        if (kCompareText.isEmpty())
        {
            KLogEvent nextScanTextEmptyEvent;
            warn << nextScanTextEmptyEvent
                << "[MemoryDock] startNextScan: 非数值等于比较值为空。"
                << eol;
            QMessageBox::warning(this, "再次扫描", "请输入用于“等于”比较的目标值。");
            return;
        }

        if (lastSearchValueType_ == SearchValueType::kStringAscii)
        {
            nonNumericCompareBytes = kCompareText.toLatin1();
        }
        else if (lastSearchValueType_ == SearchValueType::kStringUnicode)
        {
            const auto* utf16Data = reinterpret_cast<const char*>(kCompareText.utf16());
            nonNumericCompareBytes = QByteArray(
                utf16Data,
                kCompareText.size() * static_cast<int>(sizeof(char16_t)));
        }
        else
        {
            // ByteArray mode supports the "AA ?? BB" syntax; mask=0 indicates the byte position is ignored.
            QString normalizedText = kCompareText;
            normalizedText.replace(',', ' ');
            normalizedText.replace(';', ' ');
            const QStringList kTokens = normalizedText.split(' ', Qt::SkipEmptyParts);
            if (kTokens.isEmpty())
            {
                KLogEvent nextScanByteArrayEmptyEvent;
                warn << nextScanByteArrayEmptyEvent
                    << "[MemoryDock] startNextScan: ByteArray 比较 token 为空。"
                    << eol;
                QMessageBox::warning(this, "再次扫描", "字节数组比较值无效。");
                return;
            }

            for (const QString& tokenText : kTokens)
            {
                const QString kToken = tokenText.trimmed().toUpper();
                if (kToken == "??")
                {
                    nonNumericCompareBytes.push_back('\0');
                    nonNumericWildcardMask.push_back('\0');
                    continue;
                }

                std::uint8_t parsedByte = 0;
                if (!parseHexByte(kToken, parsedByte))
                {
                    KLogEvent nextScanByteArrayTokenFailEvent;
                    warn << nextScanByteArrayTokenFailEvent
                        << "[MemoryDock] startNextScan: ByteArray token 无效, token="
                        << tokenText.toStdString()
                        << eol;
                    QMessageBox::warning(this, "再次扫描", QString("字节数组项无效：%1").arg(tokenText));
                    return;
                }
                nonNumericCompareBytes.push_back(static_cast<char>(parsedByte));
                nonNumericWildcardMask.push_back('\1');
            }
        }
    }

    // Re-scanning only re-verify each hit address from the previous round. Reading the target process memory must be done in the background;
    // otherwise, a large number of hits will block the GUI thread for a long time, and processEvents would introduce reentrancy.
    const HANDLE kProcessHandle = attachedProcessHandle_;
    const SearchValueType kValueType = lastSearchValueType_;
    std::vector<SearchResultEntry> previousResultCache = searchResultCache_;
    const int kTotalCount = static_cast<int>(previousResultCache.size());
    const QPointer<MemoryDock> kSelfGuard(this);
    const std::shared_ptr<MemoryScanTaskState> kTaskState = scanTaskState_;

    // Same as the first scan: the backend and DDMA session are snapshot by value on the UI thread; the worker does not read live configuration.
    const ksword::memory_backend::MemoryAccessBackend kScanBackend = currentSearchBackend();
    const ksword::memory_backend::DdmaSession kScanDdmaSession = currentDdmaSession();
    const std::uint32_t kScanTargetPid = attachedPid_;

    // Subsequent scans also use the 'scanning' state to ensure consistent behavior for the cancel button and top buttons.
    scanInProgress_.store(true);
    scanCancelRequested_.store(false);
    firstScanButton_->setEnabled(false);
    nextScanButton_->setEnabled(false);
    resetScanButton_->setEnabled(false);
    cancelScanButton_->setEnabled(true);

    scanProgressBar_->setValue(0);
    scanStatusLabel_->setText(QString("再次扫描中：总计 %1 条").arg(kTotalCount));

    // Register the task before thread startup; the close/detach path waits based on this to avoid relying solely on QPointer for lifecycle checks.
    {
        std::lock_guard<std::mutex> lock(kTaskState->mutex);
        ++kTaskState->activeTaskCount;
    }

    std::thread([kSelfGuard,
        kTaskState,
        kProcessHandle,
        kValueType,
        previousResultCache = std::move(previousResultCache),
        kCompareMode,
        kIsNumericType,
        compareA,
        compareB,
        nonNumericCompareBytes,
        nonNumericWildcardMask,
        kBytesToDouble,
        kScanBackend,
        kScanDdmaSession,
        kScanTargetPid]() mutable
    {
        const auto kFinishScanTask = [kTaskState]()
        {
            std::lock_guard<std::mutex> lock(kTaskState->mutex);
            if (kTaskState->activeTaskCount > 0)
            {
                --kTaskState->activeTaskCount;
                if (kTaskState->activeTaskCount == 0)
                {
                    kTaskState->completion.notify_all();
                }
            }
        };

        if (kSelfGuard == nullptr || kProcessHandle == nullptr)
        {
            kFinishScanTask();
            return;
        }

        const auto kScanStartTime = std::chrono::steady_clock::now();
        const int kWorkerTotalCount = static_cast<int>(previousResultCache.size());
        std::vector<SearchResultEntry> nextResultCache;
        nextResultCache.reserve(previousResultCache.size());
        int processedCount = 0;
        bool cancelled = false;

        for (const SearchResultEntry& oldEntry : previousResultCache)
        {
            if (kSelfGuard->scanCancelRequested_.load())
            {
                cancelled = true;
                break;
            }

            const std::size_t kReadLength = std::max<std::size_t>(
                1,
                static_cast<std::size_t>(oldEntry.currentValueBytes.size()));
            QByteArray currentBytes(static_cast<int>(kReadLength), '\0');
            SIZE_T bytesRead = 0;
            bool readSucceeded = false;

            if (kScanBackend == ksword::memory_backend::MemoryAccessBackend::kDdma)
            {
                const ksword::memory_backend::AccessOutcome kDdmaOutcome =
                    ksword::memory_backend::readVirtual(
                        ksword::memory_backend::MemoryAccessBackend::kDdma,
                        kScanDdmaSession,
                        kScanTargetPid,
                        oldEntry.address,
                        static_cast<std::uint64_t>(kReadLength));
                if (kDdmaOutcome.ok &&
                    static_cast<std::size_t>(kDdmaOutcome.data.size()) == kReadLength)
                {
                    currentBytes = kDdmaOutcome.data;
                    bytesRead = static_cast<SIZE_T>(kReadLength);
                    readSucceeded = true;
                }
            }
            else
            {
                const BOOL kReadOk = ::ReadProcessMemory(
                    kProcessHandle,
                    reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(oldEntry.address)),
                    currentBytes.data(),
                    static_cast<SIZE_T>(kReadLength),
                    &bytesRead);
                readSucceeded = (kReadOk != FALSE && bytesRead == kReadLength);
            }

            bool keepThisEntry = false;
            if (readSucceeded)
            {
                switch (kCompareMode)
                {
                case SearchCompareMode::kEqual:
                    if (kIsNumericType)
                    {
                        double currentNumber = 0.0;
                        keepThisEntry = kBytesToDouble(currentBytes, kValueType, currentNumber) &&
                            (std::fabs(currentNumber - compareA) <= 0.000001);
                    }
                    else if (currentBytes.size() == nonNumericCompareBytes.size())
                    {
                        if (nonNumericWildcardMask.size() == nonNumericCompareBytes.size())
                        {
                            keepThisEntry = true;
                            for (int byteIndex = 0; byteIndex < nonNumericCompareBytes.size(); ++byteIndex)
                            {
                                if (nonNumericWildcardMask.at(byteIndex) != '\0' &&
                                    currentBytes.at(byteIndex) != nonNumericCompareBytes.at(byteIndex))
                                {
                                    keepThisEntry = false;
                                    break;
                                }
                            }
                        }
                        else
                        {
                            keepThisEntry = (currentBytes == nonNumericCompareBytes);
                        }
                    }
                    break;
                case SearchCompareMode::kGreater:
                {
                    double currentNumber = 0.0;
                    keepThisEntry = kBytesToDouble(currentBytes, kValueType, currentNumber) && currentNumber > compareA;
                    break;
                }
                case SearchCompareMode::kLess:
                {
                    double currentNumber = 0.0;
                    keepThisEntry = kBytesToDouble(currentBytes, kValueType, currentNumber) && currentNumber < compareA;
                    break;
                }
                case SearchCompareMode::kBetween:
                {
                    double currentNumber = 0.0;
                    keepThisEntry = kBytesToDouble(currentBytes, kValueType, currentNumber) &&
                        currentNumber >= compareA && currentNumber <= compareB;
                    break;
                }
                case SearchCompareMode::kChanged:
                    keepThisEntry = (currentBytes != oldEntry.currentValueBytes);
                    break;
                case SearchCompareMode::kUnchanged:
                    keepThisEntry = (currentBytes == oldEntry.currentValueBytes);
                    break;
                case SearchCompareMode::kIncreased:
                {
                    double currentNumber = 0.0;
                    double previousNumber = 0.0;
                    keepThisEntry = kBytesToDouble(currentBytes, kValueType, currentNumber) &&
                        kBytesToDouble(oldEntry.currentValueBytes, kValueType, previousNumber) &&
                        currentNumber > previousNumber;
                    break;
                }
                case SearchCompareMode::kDecreased:
                {
                    double currentNumber = 0.0;
                    double previousNumber = 0.0;
                    keepThisEntry = kBytesToDouble(currentBytes, kValueType, currentNumber) &&
                        kBytesToDouble(oldEntry.currentValueBytes, kValueType, previousNumber) &&
                        currentNumber < previousNumber;
                    break;
                }
                default:
                    break;
                }
            }

            if (keepThisEntry)
            {
                SearchResultEntry nextEntry = oldEntry;
                nextEntry.previousValueBytes = oldEntry.currentValueBytes;
                nextEntry.currentValueBytes = std::move(currentBytes);
                nextResultCache.push_back(std::move(nextEntry));
            }

            ++processedCount;
            if ((processedCount % 1024) == 0 || processedCount == kWorkerTotalCount)
            {
                const int kProgressPercent = kWorkerTotalCount <= 0
                    ? 100
                    : (processedCount * 100 / kWorkerTotalCount);
                QMetaObject::invokeMethod(kSelfGuard.data(), [kSelfGuard, kProgressPercent, processedCount, kWorkerTotalCount]()
                {
                    if (kSelfGuard == nullptr)
                    {
                        return;
                    }
                    kSelfGuard->scanProgressBar_->setValue(kProgressPercent);
                    kSelfGuard->scanStatusLabel_->setText(
                        QString("再次扫描中：%1 / %2 条").arg(processedCount).arg(kWorkerTotalCount));
                }, Qt::QueuedConnection);
            }
        }

        const auto kElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kScanStartTime).count();
        QMetaObject::invokeMethod(kSelfGuard.data(), [kSelfGuard,
            cancelled,
            kElapsedMs,
            nextResultCache = std::move(nextResultCache)]() mutable
        {
            if (kSelfGuard == nullptr)
            {
                return;
            }

            auto resultsSnapshot =
                std::make_shared<std::vector<SearchResultEntry>>(std::move(nextResultCache));
            auto commitSnapshot = [kSelfGuard, cancelled, kElapsedMs, resultsSnapshot]() mutable
            {
                if (kSelfGuard == nullptr)
                {
                    return;
                }

                // Events may be delayed due to table menu freezing; absorb any cancellation requests arriving during the interval before submission.
                const bool kEffectiveCancelled =
                    cancelled || kSelfGuard->scanCancelRequested_.load();
                kSelfGuard->scanInProgress_.store(false);
                kSelfGuard->scanCancelRequested_.store(false);
                kSelfGuard->firstScanButton_->setEnabled(true);
                kSelfGuard->resetScanButton_->setEnabled(true);
                kSelfGuard->cancelScanButton_->setEnabled(false);

                if (!kEffectiveCancelled)
                {
                    kSelfGuard->searchResultCache_ = std::move(*resultsSnapshot);
                    kSelfGuard->rebuildSearchResultTable();
                }

                kSelfGuard->nextScanButton_->setEnabled(!kSelfGuard->searchResultCache_.empty());
                QString finishText;
                if (kEffectiveCancelled)
                {
                    finishText = QString("再次扫描已取消：保留上一轮 %1 项，耗时 %2 ms")
                        .arg(kSelfGuard->searchResultCache_.size())
                        .arg(kElapsedMs);
                }
                else
                {
                    finishText = QString("再次扫描完成：保留 %1 项，耗时 %2 ms")
                        .arg(kSelfGuard->searchResultCache_.size())
                        .arg(kElapsedMs);
                }
                if (kSelfGuard->searchResultCache_.size() > kSelfGuard->searchResultVisibleCount_)
                {
                    finishText += QString("（仅显示前 %1 项）").arg(kSelfGuard->searchResultVisibleCount_);
                }
                kSelfGuard->scanStatusLabel_->setText(finishText);

                KLogEvent nextScanFinishEvent;
                info << nextScanFinishEvent
                    << "[MemoryDock] startNextScan: 完成, remainingCount="
                    << kSelfGuard->searchResultCache_.size()
                    << ", elapsedMs="
                    << kElapsedMs
                    << ", cancelled="
                    << (kEffectiveCancelled ? "true" : "false")
                    << eol;
            };

            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                kSelfGuard.data(),
                QStringLiteral("memory-search-next-scan"),
                { kSelfGuard->searchResultTable_ },
                commitSnapshot))
            {
                return;
            }
            commitSnapshot();
        }, Qt::QueuedConnection);
        kFinishScanTask();
    }).detach();
}

void MemoryDock::resetScanState()
{
    // Reset entry log: used to track user-initiated clearing of scan state.
    KLogEvent resetScanEvent;
    info << resetScanEvent
        << "[MemoryDock] resetScanState: 清空扫描缓存与状态。"
        << eol;

    // Reset actions first issue a cancellation request to prevent late-arriving background thread results from overwriting the cleared state.
    cancelCurrentScan();

    searchResultCache_.clear();
    lastSearchValueType_ = SearchValueType::kByte;
    rebuildSearchResultTable();

    // Restore button states and reset the progress bar and status text to 'Ready'.
    scanProgressBar_->setValue(0);
    scanStatusLabel_->setText("已重置，等待首次扫描。");
    firstScanButton_->setEnabled(true);
    nextScanButton_->setEnabled(false);
    resetScanButton_->setEnabled(true);
    cancelScanButton_->setEnabled(false);
}

void MemoryDock::cancelCurrentScan()
{
    // Set the cancellation flag only when scanning is in progress; no modification is needed when idle.
    if (scanInProgress_.load())
    {
        scanCancelRequested_.store(true);
        scanStatusLabel_->setText("正在请求取消扫描...");
        KLogEvent cancelScanEvent;
        warn << cancelScanEvent
            << "[MemoryDock] cancelCurrentScan: 已设置取消标志。"
            << eol;
    }
}

void MemoryDock::cancelAndWaitForMemoryScanTasks()
{
    // Before closing handles or destructing, wait for the coordination thread to exit to prevent detached workers from accessing controls.
    cancelCurrentScan();
    scanCancelRequested_.store(true);

    const std::shared_ptr<MemoryScanTaskState> kTaskState = scanTaskState_;
    std::unique_lock<std::mutex> lock(kTaskState->mutex);
    kTaskState->completion.wait(lock, [kTaskState]()
    {
        return kTaskState->activeTaskCount == 0;
    });
}

void MemoryDock::rebuildSearchResultTable()
{
    // Rebuild result table entry log: records result scale and display type.
    KLogEvent rebuildResultEvent;
    dbg << rebuildResultEvent
        << "[MemoryDock] rebuildSearchResultTable: 结果重建, count="
        << searchResultCache_.size()
        << ", valueType="
        << static_cast<int>(lastSearchValueType_)
        << eol;

    // Note: To prevent UI freezing due to excessively large result sets, the UI layer displays only the first N items.
    constexpr std::size_t kSearchResultDisplayLimit = 10000;
    const std::size_t kTotalCount = searchResultCache_.size();
    const std::size_t kVisibleCount = std::min<std::size_t>(kTotalCount, kSearchResultDisplayLimit);
    const std::size_t kHiddenCount = kTotalCount - kVisibleCount;
    searchResultVisibleCount_ = kVisibleCount;

    // Disable sorting and repainting before rebuilding the table to reduce the overhead of batch setItem calls.
    searchResultTable_->setSortingEnabled(false);
    searchResultTable_->setUpdatesEnabled(false);
    searchResultTable_->clearContents();
    searchResultTable_->setRowCount(static_cast<int>(kVisibleCount));

    for (int row = 0; row < static_cast<int>(kVisibleCount); ++row)
    {
        const SearchResultEntry& entry = searchResultCache_[static_cast<std::size_t>(row)];

        // Address column uses a numeric sort item: it displays fixed-width hexadecimal text, but sorting must follow the actual numeric value;
        // otherwise, clicking the header would degrade to string-based sorting. Qt::UserRole is retained for existing jump logic to read.
        QTableWidgetItem* addressItem = new ks::ui::NumericTableItem(
            formatAddress(entry.address),
            static_cast<qulonglong>(entry.address));
        addressItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(entry.address)));
        searchResultTable_->setItem(row, 0, addressItem);

        searchResultTable_->setItem(
            row,
            1,
            new QTableWidgetItem(bytesToDisplayString(entry.currentValueBytes, lastSearchValueType_)));

        searchResultTable_->setItem(
            row,
            2,
            new QTableWidgetItem(bytesToDisplayString(entry.previousValueBytes, lastSearchValueType_)));

        searchResultTable_->setItem(row, 3, new QTableWidgetItem(entry.noteText));
    }
    searchResultTable_->setUpdatesEnabled(true);
    // Restore sorting capability after populating the table: sorting enabled during construction is temporarily disabled before
    // batch writes and must be restored here; otherwise, the result table can never be sorted by address again after the first scan.
    searchResultTable_->setSortingEnabled(true);

    // Provide a clear explanation in the tooltip when results are truncated.
    if (kHiddenCount > 0)
    {
        searchResultTable_->setToolTip(
            QString("结果总数 %1，当前仅显示前 %2 条以保持界面响应。")
            .arg(kTotalCount)
            .arg(kVisibleCount));
    }
    else
    {
        searchResultTable_->setToolTip(QString());
    }

    // Allow re-scanning when results exist; disable the button when no results exist to prevent accidental operations.
    nextScanButton_->setEnabled(!searchResultCache_.empty() && !scanInProgress_.load());

    KLogEvent rebuildResultFinishEvent;
    dbg << rebuildResultFinishEvent
        << "[MemoryDock] rebuildSearchResultTable: 重建完成, nextScanEnabled="
        << (nextScanButton_->isEnabled() ? "true" : "false")
        << ", visibleCount="
        << kVisibleCount
        << ", hiddenCount="
        << kHiddenCount
        << eol;
}

void MemoryDock::scanMemoryRegionsInBackground(
    const std::vector<RegionEntry>& scanRegions,
    const ParsedSearchPattern& pattern)
{
    // Background scan entry log: record the total region count, thread count, and matched pattern byte count.
    KLogEvent scanBackgroundStartEvent;
    info << scanBackgroundStartEvent
        << "[MemoryDock] scanMemoryRegionsInBackground: 启动后台扫描, regionCount="
        << scanRegions.size()
        << ", threadCount="
        << scanThreadCount_
        << ", patternBytes="
        << pattern.exactBytes.size()
        << eol;

    // Use QPointer to protect the this pointer, preventing access to a dangling object after the window is destroyed.
    const QPointer<MemoryDock> kSelfGuard(this);

    // Scan parameters are fixed via value capture to prevent the background thread from reading a changing object if the UI modifies them later.
    const HANDLE kProcessHandle = attachedProcessHandle_;
    const std::vector<RegionEntry> kRegions = scanRegions;
    const ParsedSearchPattern kScanPattern = pattern;
    const std::uint32_t kThreadCount = std::max<std::uint32_t>(1, scanThreadCount_);
    const std::size_t kChunkSize = static_cast<std::size_t>(std::max<std::uint32_t>(64, scanChunkSizeKB_) * 1024u);
    const auto kStartTime = std::chrono::steady_clock::now();
    const std::shared_ptr<MemoryScanTaskState> kTaskState = scanTaskState_;

    // Backend selection and DDMA session must be snapshot by value on the UI thread: after the worker starts, the user may change
    // these configurations at any time; reading a changing session from a background thread yields half-new, half-old parameters.
    const ksword::memory_backend::MemoryAccessBackend kScanBackend = currentSearchBackend();
    const ksword::memory_backend::DdmaSession kScanDdmaSession = currentDdmaSession();
    const std::uint32_t kScanTargetPid = attachedPid_;

    // The outer coordinating thread waits for its internal workers, so registering at this level covers the entire first scan round.
    {
        std::lock_guard<std::mutex> lock(kTaskState->mutex);
        ++kTaskState->activeTaskCount;
    }

    // The background main thread is only responsible for launching workers and aggregating results, without directly manipulating UI controls.
    std::thread([kSelfGuard, kTaskState, kProcessHandle, kRegions, kScanPattern, kThreadCount, kChunkSize, kStartTime,
                 kScanBackend, kScanDdmaSession, kScanTargetPid]() {
        const auto kFinishScanTask = [kTaskState]()
        {
            std::lock_guard<std::mutex> lock(kTaskState->mutex);
            if (kTaskState->activeTaskCount > 0)
            {
                --kTaskState->activeTaskCount;
                if (kTaskState->activeTaskCount == 0)
                {
                    kTaskState->completion.notify_all();
                }
            }
        };

        if (kSelfGuard == nullptr || kProcessHandle == nullptr)
        {
            KLogEvent scanBackgroundGuardFailEvent;
            warn << scanBackgroundGuardFailEvent
                << "[MemoryDock] scanMemoryRegionsInBackground: selfGuard 或 processHandle 无效，线程直接返回。"
                << eol;
            kFinishScanTask();
            return;
        }

        std::vector<SearchResultEntry> mergedResults;
        mergedResults.reserve(1024);
        std::mutex resultMutex;
        std::atomic<std::size_t> finishedRegionCount{ 0 };

        const std::size_t kPatternLength = static_cast<std::size_t>(kScanPattern.exactBytes.size());
        if (kPatternLength == 0)
        {
            KLogEvent scanBackgroundPatternEmptyEvent;
            err << scanBackgroundPatternEmptyEvent
                << "[MemoryDock] scanMemoryRegionsInBackground: patternLength 为 0，终止扫描。"
                << eol;
            QMetaObject::invokeMethod(kSelfGuard.data(), [kSelfGuard]() {
                if (kSelfGuard == nullptr) return;
                kSelfGuard->scanInProgress_.store(false);
                kSelfGuard->scanCancelRequested_.store(false);
                kSelfGuard->firstScanButton_->setEnabled(true);
                kSelfGuard->resetScanButton_->setEnabled(true);
                kSelfGuard->cancelScanButton_->setEnabled(false);
                kSelfGuard->scanStatusLabel_->setText("扫描失败：匹配模式为空。");
                }, Qt::QueuedConnection);
            kFinishScanTask();
            return;
        }

        // Single-position matching function: Support exact matches and ByteArray wildcard-mask matches.
        const auto kMatchesPatternAt = [&kScanPattern, kPatternLength](const char* dataPtr) -> bool
            {
                for (std::size_t byteIndex = 0; byteIndex < kPatternLength; ++byteIndex)
                {
                    const bool kHasMask = (kScanPattern.wildcardMask.size() == static_cast<int>(kPatternLength));
                    if (kHasMask && kScanPattern.wildcardMask.at(static_cast<int>(byteIndex)) == '\0')
                    {
                        continue;
                    }
                    if (dataPtr[byteIndex] != kScanPattern.exactBytes.at(static_cast<int>(byteIndex)))
                    {
                        return false;
                    }
                }
                return true;
            };

        // Each worker processes region slices with 'same index modulo' to achieve low-cost load balancing.
        const auto kWorkerBody = [&](const std::uint32_t workerId) {
            // Hit count for a single worker, used for logging statistics only.
            std::vector<SearchResultEntry> localResults;
            localResults.reserve(256);
            std::size_t workerHitCount = 0;

            for (std::size_t regionIndex = workerId; regionIndex < kRegions.size(); regionIndex += kThreadCount)
            {
                if (kSelfGuard->scanCancelRequested_.load())
                {
                    break;
                }

                const RegionEntry& region = kRegions[regionIndex];
                if (region.regionSize == 0)
                {
                    ++finishedRegionCount;
                    continue;
                }

                std::uint64_t cursor = region.baseAddress;
                std::uint64_t remainBytes = region.regionSize;
                QByteArray carryBytes;

                while (remainBytes > 0 && !kSelfGuard->scanCancelRequested_.load())
                {
                    const std::size_t kRequestSize = static_cast<std::size_t>(
                        std::min<std::uint64_t>(remainBytes, static_cast<std::uint64_t>(kChunkSize)));
                    QByteArray readBuffer(static_cast<int>(kRequestSize), '\0');
                    SIZE_T bytesRead = 0;

                    if (kScanBackend == ksword::memory_backend::MemoryAccessBackend::kDdma)
                    {
                        // DDMA channel: Page-by-page translation + disk DMA. Several orders of magnitude
                        // slower than ReadProcessMemory, but capable of scanning content redirected by SLAT.
                        const ksword::memory_backend::AccessOutcome kDdmaOutcome =
                            ksword::memory_backend::readVirtual(
                                ksword::memory_backend::MemoryAccessBackend::kDdma,
                                kScanDdmaSession,
                                kScanTargetPid,
                                cursor,
                                static_cast<std::uint64_t>(kRequestSize));
                        if (!kDdmaOutcome.ok || kDdmaOutcome.data.isEmpty())
                        {
                            cursor += kRequestSize;
                            remainBytes -= kRequestSize;
                            carryBytes.clear();
                            continue;
                        }
                        readBuffer = kDdmaOutcome.data;
                        bytesRead = static_cast<SIZE_T>(kDdmaOutcome.data.size());
                    }
                    else
                    {
                        const BOOL kReadOk = ::ReadProcessMemory(
                            kProcessHandle,
                            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(cursor)),
                            readBuffer.data(),
                            static_cast<SIZE_T>(kRequestSize),
                            &bytesRead);
                        if (kReadOk == FALSE || bytesRead == 0)
                        {
                            // When a block read fails, skip it and continue scanning to ensure fault tolerance.
                            cursor += kRequestSize;
                            remainBytes -= kRequestSize;
                            carryBytes.clear();
                            continue;
                        }
                    }

                    // Merge 'tail of the previous block + current block' to handle boundary hits and avoid missing cross-block patterns.
                    const int kValidReadLength = static_cast<int>(bytesRead);
                    QByteArray mergedBuffer = carryBytes + readBuffer.left(kValidReadLength);
                    const std::size_t kCarryLength = static_cast<std::size_t>(carryBytes.size());
                    const std::uint64_t kMergedBaseAddress = cursor - kCarryLength;

                    // Start offset calculation: only re-examine the window where the previous block's tail is less than one pattern length.
                    const std::size_t kOverlap = (kPatternLength > 0) ? (kPatternLength - 1) : 0;
                    const std::size_t kStartOffset = (kCarryLength > kOverlap) ? (kCarryLength - kOverlap) : 0;

                    if (mergedBuffer.size() >= static_cast<int>(kPatternLength))
                    {
                        const std::size_t kMaxOffset =
                            static_cast<std::size_t>(mergedBuffer.size()) - kPatternLength;
                        for (std::size_t offset = kStartOffset; offset <= kMaxOffset; ++offset)
                        {
                            const char* candidatePtr = mergedBuffer.constData() + static_cast<int>(offset);
                            if (!kMatchesPatternAt(candidatePtr))
                            {
                                continue;
                            }

                            SearchResultEntry resultEntry{};
                            resultEntry.address = kMergedBaseAddress + offset;
                            resultEntry.currentValueBytes = QByteArray(candidatePtr, static_cast<int>(kPatternLength));
                            localResults.push_back(std::move(resultEntry));
                            ++workerHitCount;
                        }
                    }

                    // Retain the last patternLength-1 bytes for concatenation with the next block; if insufficient, retain all bytes.
                    if (kPatternLength > 1)
                    {
                        const int kTailCount = std::min<int>(
                            static_cast<int>(kPatternLength - 1),
                            mergedBuffer.size());
                        carryBytes = mergedBuffer.right(kTailCount);
                    }
                    else
                    {
                        carryBytes.clear();
                    }

                    cursor += kRequestSize;
                    remainBytes -= kRequestSize;
                }

                // Merge into the total results after partition scanning completes to reduce lock contention.
                {
                    std::lock_guard<std::mutex> lock(resultMutex);
                    mergedResults.insert(
                        mergedResults.end(),
                        std::make_move_iterator(localResults.begin()),
                        std::make_move_iterator(localResults.end()));
                }
                localResults.clear();

                const std::size_t kFinishedCount = ++finishedRegionCount;
                if ((kFinishedCount % 16 == 0) || kFinishedCount == kRegions.size())
                {
                    QMetaObject::invokeMethod(kSelfGuard.data(), [kSelfGuard, kFinishedCount, totalCount = kRegions.size()]() {
                        if (kSelfGuard == nullptr || totalCount == 0)
                        {
                            return;
                        }
                        const int kProgress = static_cast<int>((kFinishedCount * 100) / totalCount);
                        kSelfGuard->scanProgressBar_->setValue(kProgress);
                        kSelfGuard->scanStatusLabel_->setText(
                            QString("扫描中：%1 / %2 区域")
                            .arg(kFinishedCount)
                            .arg(totalCount));
                        }, Qt::QueuedConnection);
                }
            }

            // worker completion log: record the total hits for this worker to observe load balancing.
            KLogEvent workerFinishEvent;
            dbg << workerFinishEvent
                << "[MemoryDock] scanMemoryRegionsInBackground: worker完成, workerId="
                << workerId
                << ", hitCount="
                << workerHitCount
                << eol;
            };

        // Launch the worker thread pool; the thread count will not exceed the number of regions to avoid idle spinning.
        std::vector<std::thread> workers;
        workers.reserve(kThreadCount);
        const std::uint32_t kRealThreadCount = static_cast<std::uint32_t>(
            std::min<std::size_t>(kRegions.size(), static_cast<std::size_t>(kThreadCount)));
        for (std::uint32_t workerId = 0; workerId < kRealThreadCount; ++workerId)
        {
            workers.emplace_back(kWorkerBody, workerId);
        }

        for (std::thread& worker : workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }

        // Sort uniformly by address in ascending order to facilitate user browsing and ensure stable result order during 'rescan'.
        std::sort(mergedResults.begin(), mergedResults.end(), [](const SearchResultEntry& left, const SearchResultEntry& right) {
            return left.address < right.address;
            });

        const bool kCancelled = kSelfGuard->scanCancelRequested_.load();
        const auto kElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kStartTime).count();

        // Background thread completion log: distinguish between cancellation and normal completion.
        KLogEvent scanBackgroundThreadFinishEvent;
        info << scanBackgroundThreadFinishEvent
            << "[MemoryDock] scanMemoryRegionsInBackground: 后台线程结束, cancelled="
            << (kCancelled ? "true" : "false")
            << ", mergedCount="
            << mergedResults.size()
            << ", elapsedMs="
            << kElapsedMs
            << eol;

        // All UI modifications are unified to execute on the main thread.
        QMetaObject::invokeMethod(kSelfGuard.data(), [kSelfGuard, kCancelled, kElapsedMs, finalResults = std::move(mergedResults)]() mutable {
            if (kSelfGuard == nullptr)
            {
                return;
            }

            auto resultsSnapshot =
                std::make_shared<std::vector<SearchResultEntry>>(std::move(finalResults));
            auto commitSnapshot = [kSelfGuard, kCancelled, kElapsedMs, resultsSnapshot]() mutable
            {
                if (kSelfGuard == nullptr)
                {
                    return;
                }

                // Cancellation during deferred submission is also effective to prevent old scan results from overwriting the user's current state.
                const bool kEffectiveCancelled =
                    kCancelled || kSelfGuard->scanCancelRequested_.load();
                kSelfGuard->scanInProgress_.store(false);
                kSelfGuard->scanCancelRequested_.store(false);
                kSelfGuard->firstScanButton_->setEnabled(true);
                kSelfGuard->resetScanButton_->setEnabled(true);
                kSelfGuard->cancelScanButton_->setEnabled(false);

                if (kEffectiveCancelled)
                {
                    kSelfGuard->scanStatusLabel_->setText("扫描已取消。");
                    KLogEvent scanBackgroundCancelledUiEvent;
                    warn << scanBackgroundCancelledUiEvent
                        << "[MemoryDock] scanMemoryRegionsInBackground: 主线程收到取消结果。"
                        << eol;
                    return;
                }

                kSelfGuard->scanProgressBar_->setValue(100);
                kSelfGuard->searchResultCache_ = std::move(*resultsSnapshot);
                kSelfGuard->rebuildSearchResultTable();
                QString finishText = QString("首次扫描完成：命中 %1 项，耗时 %2 ms")
                    .arg(kSelfGuard->searchResultCache_.size())
                    .arg(kElapsedMs);
                if (kSelfGuard->searchResultCache_.size() > kSelfGuard->searchResultVisibleCount_)
                {
                    finishText += QString("（仅显示前 %1 项）").arg(kSelfGuard->searchResultVisibleCount_);
                }
                kSelfGuard->scanStatusLabel_->setText(finishText);

                // UI submission completion log: Confirm results are persisted to cache and tables.
                KLogEvent scanBackgroundUiFinishEvent;
                info << scanBackgroundUiFinishEvent
                    << "[MemoryDock] scanMemoryRegionsInBackground: 主线程提交完成, resultCount="
                    << kSelfGuard->searchResultCache_.size()
                    << ", elapsedMs="
                    << kElapsedMs
                    << eol;
            };

            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                kSelfGuard.data(),
                QStringLiteral("memory-search-first-scan"),
                { kSelfGuard->searchResultTable_ },
                commitSnapshot))
            {
                return;
            }
            commitSnapshot();
            }, Qt::QueuedConnection);
        kFinishScanTask();
    }).detach();
}
