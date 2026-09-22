#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

struct FileDock::FileOplockAccessRecord

{

    std::uint32_t processId = 0U;

    QString processName;

    QString processImagePath;

    std::uint64_t hitCount = 0U;

    std::uint64_t handleHitCount = 0U;

    std::uint64_t firstBreakSequence = 0U;

    std::uint64_t lastBreakSequence = 0U;

    std::uint64_t lastHandleValue = 0U;

    std::uint32_t lastGrantedAccess = 0U;

    QString firstSeenText;

    QString lastSeenText;

    QStringList matchedTargetList;

    QStringList matchRuleList;

    QStringList enumerationSourceList;

    QStringList objectNameList;

};

struct FileDock::FileOplockEntry

{

    QString path;

    FileOplockLevel level = FileOplockLevel::kLevel1;

    HANDLE fileHandle = INVALID_HANDLE_VALUE;

    HANDLE eventHandle = nullptr;

    OVERLAPPED overlapped{};

    bool ioPending = false;

    std::thread waitThread;

    std::mutex ioMutex;

    std::mutex accessRecordMutex;

    std::vector<FileOplockAccessRecord> accessRecords;

    QString lastAccessScanDiagnostic;

    std::uint64_t uncapturedBreakCount = 0U;

    std::atomic_bool releaseRequested{ false };

    std::atomic_bool rearmWarningReported{ false };

    std::atomic<std::uint64_t> breakCount{ 0 };



    ~FileOplockEntry()

    {

        closeWin32Handle(fileHandle);

        closeWin32Handle(eventHandle);

    }

};

QString FileDock::fileOplockLevelText(const FileOplockLevel level)
{
    switch (level)
    {
    case FileOplockLevel::kLevel1:
        return QStringLiteral("Level 1");
    case FileOplockLevel::kLevel2:
        return QStringLiteral("Level 2");
    case FileOplockLevel::kBatch:
        return QStringLiteral("Batch");
    case FileOplockLevel::kFilter:
        return QStringLiteral("Filter");
    }
    return QStringLiteral("Level 1");
}

unsigned long FileDock::fileOplockControlCode(const FileOplockLevel level)
{
    switch (level)
    {
    case FileOplockLevel::kLevel1:
        return FSCTL_REQUEST_OPLOCK_LEVEL_1;
    case FileOplockLevel::kLevel2:
        return FSCTL_REQUEST_OPLOCK_LEVEL_2;
    case FileOplockLevel::kBatch:
        return FSCTL_REQUEST_BATCH_OPLOCK;
    case FileOplockLevel::kFilter:
        return FSCTL_REQUEST_FILTER_OPLOCK;
    }
    return FSCTL_REQUEST_OPLOCK_LEVEL_1;
}

bool FileDock::requestFileOplock(FileOplockEntry& entry, unsigned long& requestError)
{
    requestError = ERROR_SUCCESS;
    if (entry.releaseRequested.load())
    {
        requestError = ERROR_OPERATION_ABORTED;
        return false;
    }

    std::lock_guard<std::mutex> lock(entry.ioMutex);
    if (entry.releaseRequested.load())
    {
        requestError = ERROR_OPERATION_ABORTED;
        return false;
    }
    if (entry.fileHandle == nullptr ||
        entry.fileHandle == INVALID_HANDLE_VALUE ||
        entry.eventHandle == nullptr)
    {
        requestError = ERROR_INVALID_HANDLE;
        return false;
    }

    (void)::ResetEvent(entry.eventHandle);
    entry.overlapped = OVERLAPPED{};
    entry.overlapped.hEvent = entry.eventHandle;

    const BOOL kRequestOk = ::DeviceIoControl(
        entry.fileHandle,
        static_cast<DWORD>(fileOplockControlCode(entry.level)),
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        &entry.overlapped);
    requestError = kRequestOk ? ERROR_SUCCESS : ::GetLastError();
    entry.ioPending = kRequestOk == FALSE && requestError == ERROR_IO_PENDING;
    if (kRequestOk != FALSE)
    {
        return false;
    }
    if (requestError == ERROR_IO_PENDING)
    {
        entry.rearmWarningReported.store(false);
        return true;
    }

    return false;
}

bool FileDock::acknowledgeFileOplockBreak(FileOplockEntry& entry, unsigned long& acknowledgeError)
{
    acknowledgeError = ERROR_SUCCESS;
    if (entry.level == FileOplockLevel::kLevel2 || entry.releaseRequested.load())
    {
        return true;
    }
    if (entry.fileHandle == nullptr || entry.fileHandle == INVALID_HANDLE_VALUE)
    {
        acknowledgeError = ERROR_INVALID_HANDLE;
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL acknowledgeOk = FALSE;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(entry.ioMutex);
        if (entry.releaseRequested.load())
        {
            acknowledgeError = ERROR_OPERATION_ABORTED;
            return false;
        }
        if (entry.fileHandle == nullptr ||
            entry.fileHandle == INVALID_HANDLE_VALUE ||
            entry.eventHandle == nullptr)
        {
            acknowledgeError = ERROR_INVALID_HANDLE;
            return false;
        }

        fileHandle = entry.fileHandle;
        (void)::ResetEvent(entry.eventHandle);
        entry.overlapped = OVERLAPPED{};
        entry.overlapped.hEvent = entry.eventHandle;
        acknowledgeOk = ::DeviceIoControl(
            fileHandle,
            FSCTL_OPLOCK_BREAK_ACK_NO_2,
            nullptr,
            0,
            nullptr,
            0,
            &bytesReturned,
            &entry.overlapped);
        acknowledgeError = acknowledgeOk ? ERROR_SUCCESS : ::GetLastError();
        entry.ioPending = acknowledgeOk == FALSE && acknowledgeError == ERROR_IO_PENDING;
    }

    if (!acknowledgeOk && acknowledgeError == ERROR_IO_PENDING)
    {
        acknowledgeOk = ::GetOverlappedResult(
            fileHandle,
            &entry.overlapped,
            &bytesReturned,
            TRUE);
        acknowledgeError = acknowledgeOk ? ERROR_SUCCESS : ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(entry.ioMutex);
            entry.ioPending = false;
        }
    }

    return acknowledgeOk != FALSE;
}

void FileDock::cancelFileOplockRequest(FileOplockEntry& entry)
{
    std::lock_guard<std::mutex> lock(entry.ioMutex);
    if (entry.fileHandle != nullptr && entry.fileHandle != INVALID_HANDLE_VALUE)
    {
        if (entry.ioPending)
        {
            (void)::CancelIoEx(entry.fileHandle, &entry.overlapped);
        }
    }
    if (!entry.ioPending && entry.eventHandle != nullptr)
    {
        (void)::SetEvent(entry.eventHandle);
    }
}

std::size_t FileDock::recordFileOplockAccessPrograms(
    FileOplockEntry& entry,
    const std::uint64_t breakSequence)
{
    if (entry.path.trimmed().isEmpty() || entry.releaseRequested.load())
    {
        return 0U;
    }

    const std::vector<QString> kScanTargets{ entry.path };
    const filedock::handleusage::HandleUsageScanResult kScanResult =
        filedock::handleusage::scanHandleUsageByPaths(kScanTargets, 0, true);

    const std::uint32_t kCurrentProcessId = static_cast<std::uint32_t>(::GetCurrentProcessId());
    const QString kNowText = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    std::map<std::uint32_t, FileOplockAccessRecord> scanRecordByPid;
    for (const filedock::handleusage::HandleUsageEntry& scanEntry : kScanResult.entries)
    {
        if (scanEntry.processId == 0U ||
            scanEntry.processId <= 4U ||
            scanEntry.processId == kCurrentProcessId)
        {
            continue;
        }

        FileOplockAccessRecord& scanRecord = scanRecordByPid[scanEntry.processId];
        if (scanRecord.processId == 0U)
        {
            scanRecord.processId = scanEntry.processId;
            scanRecord.processName = scanEntry.processName.trimmed();
            scanRecord.processImagePath = scanEntry.processImagePath.trimmed();
            scanRecord.firstBreakSequence = breakSequence;
            scanRecord.firstSeenText = kNowText;
        }
        if (scanRecord.processName.isEmpty() && !scanEntry.processName.trimmed().isEmpty())
        {
            scanRecord.processName = scanEntry.processName.trimmed();
        }
        if (scanRecord.processImagePath.isEmpty() && !scanEntry.processImagePath.trimmed().isEmpty())
        {
            scanRecord.processImagePath = scanEntry.processImagePath.trimmed();
        }

        scanRecord.lastBreakSequence = breakSequence;
        scanRecord.lastSeenText = kNowText;
        scanRecord.handleHitCount += 1U;
        scanRecord.lastHandleValue = scanEntry.handleValue;
        scanRecord.lastGrantedAccess = scanEntry.grantedAccess;
        appendUniqueText(scanRecord.matchedTargetList, scanEntry.matchedTargetPath);
        appendUniqueText(scanRecord.matchRuleList, scanEntry.matchRuleText);
        appendUniqueText(scanRecord.enumerationSourceList, scanEntry.enumerationSource);
        appendUniqueText(scanRecord.objectNameList, scanEntry.objectName);
    }

    std::lock_guard<std::mutex> lock(entry.accessRecordMutex);
    entry.lastAccessScanDiagnostic = kScanResult.diagnosticText.trimmed().isEmpty()
        ? QStringLiteral("-")
        : kScanResult.diagnosticText.simplified();
    if (scanRecordByPid.empty())
    {
        entry.uncapturedBreakCount += 1U;
        return 0U;
    }

    for (const auto& scanPair : scanRecordByPid)
    {
        const FileOplockAccessRecord& scanRecord = scanPair.second;
        auto existingIterator = std::find_if(
            entry.accessRecords.begin(),
            entry.accessRecords.end(),
            [&scanRecord](const FileOplockAccessRecord& record) {
                return record.processId == scanRecord.processId;
            });

        if (existingIterator == entry.accessRecords.end())
        {
            FileOplockAccessRecord newRecord = scanRecord;
            newRecord.hitCount = 1U;
            entry.accessRecords.push_back(newRecord);
            continue;
        }

        FileOplockAccessRecord& existingRecord = *existingIterator;
        existingRecord.hitCount += 1U;
        existingRecord.handleHitCount += scanRecord.handleHitCount;
        existingRecord.lastBreakSequence = scanRecord.lastBreakSequence;
        existingRecord.lastSeenText = scanRecord.lastSeenText;
        existingRecord.lastHandleValue = scanRecord.lastHandleValue;
        existingRecord.lastGrantedAccess = scanRecord.lastGrantedAccess;
        if (existingRecord.processName.isEmpty() && !scanRecord.processName.isEmpty())
        {
            existingRecord.processName = scanRecord.processName;
        }
        if (existingRecord.processImagePath.isEmpty() && !scanRecord.processImagePath.isEmpty())
        {
            existingRecord.processImagePath = scanRecord.processImagePath;
        }
        for (const QString& text : scanRecord.matchedTargetList)
        {
            appendUniqueText(existingRecord.matchedTargetList, text);
        }
        for (const QString& text : scanRecord.matchRuleList)
        {
            appendUniqueText(existingRecord.matchRuleList, text);
        }
        for (const QString& text : scanRecord.enumerationSourceList)
        {
            appendUniqueText(existingRecord.enumerationSourceList, text);
        }
        for (const QString& text : scanRecord.objectNameList)
        {
            appendUniqueText(existingRecord.objectNameList, text);
        }
    }

    return scanRecordByPid.size();
}

void FileDock::addOplockToSelectedFile(FilePanelWidgets& panel, const FileOplockLevel level)
{
    const QString kLevelText = fileOplockLevelText(level);
    const unsigned long kControlCode = fileOplockControlCode(level);
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("请只选择一个文件。"));
        return;
    }

    const QFileInfo kFileInfo(kPaths.front());
    if (!kFileInfo.isFile())
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("Oplock 入口当前只支持普通文件。"));
        return;
    }

    const QString kNormalizedPath = normalizeFileDockPath(kFileInfo.absoluteFilePath());
    if (hasActiveOplockForPath(kNormalizedPath))
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("该文件已经由 FileDock 持有 Oplock：\n%1").arg(kNormalizedPath));
        return;
    }

    std::wstring nativePath = kNormalizedPath.toStdWString();
    HANDLE fileHandle = ::CreateFileW(
        nativePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        const DWORD kErrorCode = ::GetLastError();
        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("打开文件失败，无法请求 %1 Oplock，Win32=%2：\n%3")
                .arg(kLevelText)
                .arg(kErrorCode)
                .arg(kNormalizedPath));
        KLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：CreateFileW, path="
            << kNormalizedPath.toStdString()
            << ", level="
            << kLevelText.toStdString()
            << ", error="
            << kErrorCode
            << eol;
        return;
    }

    auto oplockEntry = std::make_shared<FileOplockEntry>();
    oplockEntry->path = kNormalizedPath;
    oplockEntry->level = level;
    oplockEntry->fileHandle = fileHandle;
    oplockEntry->eventHandle = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (oplockEntry->eventHandle == nullptr)
    {
        const DWORD kErrorCode = ::GetLastError();
        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("创建 %1 Oplock 等待事件失败，Win32=%2。").arg(kLevelText).arg(kErrorCode));
        KLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：CreateEventW, path="
            << kNormalizedPath.toStdString()
            << ", level="
            << kLevelText.toStdString()
            << ", error="
            << kErrorCode
            << eol;
        return;
    }
    unsigned long requestError = ERROR_SUCCESS;
    if (!requestFileOplock(*oplockEntry, requestError))
    {
        if (requestError == ERROR_SUCCESS)
        {
            QMessageBox::information(
                this,
                QStringLiteral("添加 Oplock"),
                QStringLiteral("%1 Oplock 请求已立即完成，没有保持中的 Oplock：\n%2")
                    .arg(kLevelText, kNormalizedPath));
            KLogEvent event;
            info << event
                << "[FileDock] 添加 Oplock：请求同步完成, path="
                << kNormalizedPath.toStdString()
                << ", level="
                << kLevelText.toStdString()
                << eol;
            return;
        }

        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("请求 %1 Oplock 失败，Win32=%2：\n%3")
                .arg(kLevelText)
                .arg(requestError)
                .arg(kNormalizedPath));
        KLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：DeviceIoControl, path="
            << kNormalizedPath.toStdString()
            << ", level="
            << kLevelText.toStdString()
            << ", controlCode=0x"
            << QString::number(kControlCode, 16).toStdString()
            << ", error="
            << requestError
            << eol;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(activeOplockMutex_);
        activeOplocks_.push_back(oplockEntry);
    }

    QPointer<FileDock> safeThis(this);
    oplockEntry->waitThread = std::thread([safeThis, oplockEntry]() {
        for (;;)
        {
            bool completionOk = false;
            DWORD completionError = ERROR_SUCCESS;
            DWORD bytesTransferred = 0;
            HANDLE fileHandle = INVALID_HANDLE_VALUE;
            {
                std::lock_guard<std::mutex> lock(oplockEntry->ioMutex);
                fileHandle = oplockEntry->fileHandle;
            }
            completionOk = (::GetOverlappedResult(
                fileHandle,
                &oplockEntry->overlapped,
                &bytesTransferred,
                TRUE) != FALSE);
            if (!completionOk)
            {
                completionError = ::GetLastError();
            }
            {
                std::lock_guard<std::mutex> lock(oplockEntry->ioMutex);
                oplockEntry->ioPending = false;
            }

            if (oplockEntry->releaseRequested.load())
            {
                break;
            }

            const std::uint64_t kBreakSequence = oplockEntry->breakCount.fetch_add(1U) + 1U;
            unsigned long acknowledgeError = ERROR_SUCCESS;
            const bool kAcknowledgeOk = completionOk
                ? FileDock::acknowledgeFileOplockBreak(*oplockEntry, acknowledgeError)
                : false;
            const std::size_t kCapturedProcessCount =
                (completionOk && kAcknowledgeOk && !oplockEntry->releaseRequested.load())
                ? FileDock::recordFileOplockAccessPrograms(*oplockEntry, kBreakSequence)
                : 0U;

            if (safeThis != nullptr)
            {
                QMetaObject::invokeMethod(
                    safeThis,
                    [
                        safeThis,
                        oplockEntry,
                        completionOk,
                        completionError,
                        kAcknowledgeOk,
                        acknowledgeError,
                        kCapturedProcessCount
                    ]() {
                        if (safeThis != nullptr)
                        {
                            safeThis->handleOplockCompleted(
                                oplockEntry,
                                completionOk,
                                completionError,
                                kAcknowledgeOk,
                                acknowledgeError,
                                kCapturedProcessCount);
                        }
                    },
                    Qt::QueuedConnection);
            }

            if (!completionOk || !kAcknowledgeOk)
            {
                break;
            }

            for (;;)
            {
                if (oplockEntry->releaseRequested.load())
                {
                    break;
                }

                unsigned long rearmError = ERROR_SUCCESS;
                if (FileDock::requestFileOplock(*oplockEntry, rearmError))
                {
                    break;
                }
                if (oplockEntry->releaseRequested.load())
                {
                    break;
                }

                if (!oplockEntry->rearmWarningReported.exchange(true) && safeThis != nullptr)
                {
                    QMetaObject::invokeMethod(
                        safeThis,
                        [safeThis, oplockEntry, rearmError]() {
                            if (safeThis != nullptr)
                            {
                                safeThis->handleOplockRearmPending(oplockEntry, rearmError);
                            }
                        },
                        Qt::QueuedConnection);
                }

                if (oplockEntry->eventHandle != nullptr)
                {
                    (void)::ResetEvent(oplockEntry->eventHandle);
                    (void)::WaitForSingleObject(oplockEntry->eventHandle, 250);
                }
                else
                {
                    ::Sleep(250);
                }
            }

            if (oplockEntry->releaseRequested.load())
            {
                break;
            }
        }
    });

    QMessageBox::information(
        this,
        QStringLiteral("添加 Oplock"),
        QStringLiteral("已为文件添加 %1 Oplock。保持期间如果其它进程触发访问，将累计次数并自动重新挂起，直到手动释放：\n%2")
            .arg(kLevelText, kNormalizedPath));
    KLogEvent event;
    info << event
        << "[FileDock] 添加 Oplock 成功, path="
        << kNormalizedPath.toStdString()
        << ", level="
        << kLevelText.toStdString()
        << ", controlCode=0x"
        << QString::number(kControlCode, 16).toStdString()
        << ", activeCount="
        << activeOplockCount()
        << eol;
}

void FileDock::releaseSelectedFileOplock(FilePanelWidgets& panel)
{
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("释放 Oplock"),
            QStringLiteral("请只选择一个已添加 Oplock 的文件。"));
        return;
    }

    const QString kNormalizedPath = normalizeFileDockPath(kPaths.front());
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(activeOplockMutex_);
        auto iterator = std::find_if(
            activeOplocks_.begin(),
            activeOplocks_.end(),
            [&kNormalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr && pathEqualsCaseInsensitive(entry->path, kNormalizedPath);
            });
        if (iterator != activeOplocks_.end())
        {
            targetEntry = *iterator;
            activeOplocks_.erase(iterator);
        }
    }

    if (targetEntry == nullptr)
    {
        QMessageBox::information(
            this,
            QStringLiteral("释放 Oplock"),
            QStringLiteral("当前文件没有由 FileDock 持有的 Oplock：\n%1").arg(kNormalizedPath));
        return;
    }

    const std::uint64_t kBreakCount = targetEntry->breakCount.load();
    std::size_t accessProcessCount = 0U;
    std::uint64_t uncapturedBreakCount = 0U;
    {
        std::lock_guard<std::mutex> lock(targetEntry->accessRecordMutex);
        accessProcessCount = targetEntry->accessRecords.size();
        uncapturedBreakCount = targetEntry->uncapturedBreakCount;
    }
    const QString kLevelText = fileOplockLevelText(targetEntry->level);
    targetEntry->releaseRequested.store(true);
    cancelFileOplockRequest(*targetEntry);
    if (targetEntry->waitThread.joinable() &&
        targetEntry->waitThread.get_id() != std::this_thread::get_id())
    {
        targetEntry->waitThread.join();
    }

    QMessageBox::information(
        this,
        QStringLiteral("释放 Oplock"),
        QStringLiteral("已释放 %1 Oplock。\n触发次数：%2\n记录进程：%3\n未捕获触发：%4\n文件：%5")
            .arg(kLevelText)
            .arg(kBreakCount)
            .arg(accessProcessCount)
            .arg(uncapturedBreakCount)
            .arg(kNormalizedPath));
    KLogEvent event;
    info << event
        << "[FileDock] 释放当前 Oplock, path="
        << kNormalizedPath.toStdString()
        << ", level="
        << kLevelText.toStdString()
        << ", breakCount="
        << kBreakCount
        << ", accessProcessCount="
        << accessProcessCount
        << ", uncapturedBreakCount="
        << uncapturedBreakCount
        << ", activeCount="
        << activeOplockCount()
        << eol;
}

void FileDock::showSelectedFileOplockAccessRecords(FilePanelWidgets& panel)
{
    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("Oplock 访问记录"),
            QStringLiteral("请只选择一个已添加 Oplock 的文件。"));
        return;
    }

    const QString kNormalizedPath = normalizeFileDockPath(kPaths.front());
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(activeOplockMutex_);
        auto iterator = std::find_if(
            activeOplocks_.begin(),
            activeOplocks_.end(),
            [&kNormalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr &&
                    !entry->releaseRequested.load() &&
                    pathEqualsCaseInsensitive(entry->path, kNormalizedPath);
            });
        if (iterator != activeOplocks_.end())
        {
            targetEntry = *iterator;
        }
    }

    if (targetEntry == nullptr)
    {
        QMessageBox::information(
            this,
            QStringLiteral("Oplock 访问记录"),
            QStringLiteral("当前文件没有由 FileDock 持有的 Oplock：\n%1").arg(kNormalizedPath));
        return;
    }

    std::vector<FileOplockAccessRecord> accessRecords;
    QString diagnosticText;
    std::uint64_t uncapturedBreakCount = 0U;
    {
        std::lock_guard<std::mutex> lock(targetEntry->accessRecordMutex);
        accessRecords = targetEntry->accessRecords;
        diagnosticText = targetEntry->lastAccessScanDiagnostic;
        uncapturedBreakCount = targetEntry->uncapturedBreakCount;
    }
    std::sort(
        accessRecords.begin(),
        accessRecords.end(),
        [](const FileOplockAccessRecord& left, const FileOplockAccessRecord& right) {
            if (left.lastBreakSequence != right.lastBreakSequence)
            {
                return left.lastBreakSequence > right.lastBreakSequence;
            }
            return left.processId < right.processId;
        });

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Oplock 访问记录"));
    dialog.resize(1180, 620);

    auto* layout = new QVBoxLayout(&dialog);
    auto* summaryLabel = new QLabel(
        QStringLiteral("文件：%1\n级别：%2 | 触发次数：%3 | 记录进程：%4 | 未捕获触发：%5\n最近扫描：%6")
            .arg(kNormalizedPath)
            .arg(fileOplockLevelText(targetEntry->level))
            .arg(targetEntry->breakCount.load())
            .arg(accessRecords.size())
            .arg(uncapturedBreakCount)
            .arg(diagnosticText.trimmed().isEmpty() ? QStringLiteral("-") : diagnosticText),
        &dialog);
    summaryLabel->setWordWrap(true);
    layout->addWidget(summaryLabel);

    auto* table = new ks::ui::VisibleTableWidget(static_cast<int>(accessRecords.size()), 13, &dialog);
    table->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("触发命中"),
        QStringLiteral("句柄命中"),
        QStringLiteral("访问掩码"),
        QStringLiteral("最近句柄"),
        QStringLiteral("首次触发"),
        QStringLiteral("最近触发"),
        QStringLiteral("首次时间"),
        QStringLiteral("最近时间"),
        QStringLiteral("命中路径"),
        QStringLiteral("规则/来源"),
        QStringLiteral("映像路径")
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setStretchLastSection(true);
    installFileTableCopyMenu(table, 0);

    auto makeItem = [](const QString& text) {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    };

    for (int row = 0; row < static_cast<int>(accessRecords.size()); ++row)
    {
        const FileOplockAccessRecord& record = accessRecords[static_cast<std::size_t>(row)];
        const QStringList kRuleAndSourceList = QStringList{
            record.matchRuleList.join(QStringLiteral("\n")),
            record.enumerationSourceList.join(QStringLiteral("\n")),
            record.objectNameList.join(QStringLiteral("\n"))
        };
        table->setItem(row, 0, makeItem(QString::number(record.processId)));
        table->setItem(row, 1, makeItem(record.processName.isEmpty() ? QStringLiteral("Unknown") : record.processName));
        table->setItem(row, 2, makeItem(QString::number(record.hitCount)));
        table->setItem(row, 3, makeItem(QString::number(record.handleHitCount)));
        table->setItem(row, 4, makeItem(formatHandleValueText(record.lastGrantedAccess)));
        table->setItem(row, 5, makeItem(formatHandleValueText(record.lastHandleValue)));
        table->setItem(row, 6, makeItem(QString::number(record.firstBreakSequence)));
        table->setItem(row, 7, makeItem(QString::number(record.lastBreakSequence)));
        table->setItem(row, 8, makeItem(record.firstSeenText));
        table->setItem(row, 9, makeItem(record.lastSeenText));
        table->setItem(row, 10, makeItem(record.matchedTargetList.join(QStringLiteral("\n"))));
        table->setItem(row, 11, makeItem(kRuleAndSourceList.join(QStringLiteral("\n"))));
        table->setItem(row, 12, makeItem(record.processImagePath));
    }
    table->resizeColumnsToContents();
    layout->addWidget(table, 1);

    auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    dialog.exec();
}

void FileDock::releaseAllActiveOplocks(const bool showMessage)
{
    std::vector<std::shared_ptr<FileOplockEntry>> entries;
    {
        std::lock_guard<std::mutex> lock(activeOplockMutex_);
        entries.swap(activeOplocks_);
    }

    std::uint64_t totalBreakCount = 0;
    std::uint64_t totalUncapturedBreakCount = 0;
    std::size_t totalAccessProcessCount = 0U;
    for (const std::shared_ptr<FileOplockEntry>& entry : entries)
    {
        if (entry == nullptr)
        {
            continue;
        }
        totalBreakCount += entry->breakCount.load();
        {
            std::lock_guard<std::mutex> lock(entry->accessRecordMutex);
            totalAccessProcessCount += entry->accessRecords.size();
            totalUncapturedBreakCount += entry->uncapturedBreakCount;
        }
        entry->releaseRequested.store(true);
        cancelFileOplockRequest(*entry);
    }

    for (const std::shared_ptr<FileOplockEntry>& entry : entries)
    {
        if (entry != nullptr &&
            entry->waitThread.joinable() &&
            entry->waitThread.get_id() != std::this_thread::get_id())
        {
            entry->waitThread.join();
        }
    }

    if (showMessage)
    {
        QMessageBox::information(
            this,
            QStringLiteral("释放全部 Oplock"),
            QStringLiteral("已释放 %1 个 Oplock，累计触发 %2 次，记录进程 %3 个，未捕获触发 %4 次。")
                .arg(entries.size())
                .arg(totalBreakCount)
                .arg(totalAccessProcessCount)
                .arg(totalUncapturedBreakCount));
    }
    if (!entries.empty())
    {
        KLogEvent event;
        info << event
            << "[FileDock] 释放全部 Oplock, count="
            << entries.size()
            << ", totalBreakCount="
            << totalBreakCount
            << ", totalAccessProcessCount="
            << totalAccessProcessCount
            << ", totalUncapturedBreakCount="
            << totalUncapturedBreakCount
            << eol;
    }
}

bool FileDock::hasActiveOplockForPath(const QString& filePath) const
{
    const QString kNormalizedPath = normalizeFileDockPath(filePath);
    std::lock_guard<std::mutex> lock(activeOplockMutex_);
    return std::any_of(
        activeOplocks_.begin(),
        activeOplocks_.end(),
        [&kNormalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr &&
                !entry->releaseRequested.load() &&
                pathEqualsCaseInsensitive(entry->path, kNormalizedPath);
        });
}

std::size_t FileDock::activeOplockCount() const
{
    std::lock_guard<std::mutex> lock(activeOplockMutex_);
    return static_cast<std::size_t>(std::count_if(
        activeOplocks_.begin(),
        activeOplocks_.end(),
        [](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr && !entry->releaseRequested.load();
        }));
}

std::uint64_t FileDock::activeOplockBreakCountForPath(const QString& filePath) const
{
    const QString kNormalizedPath = normalizeFileDockPath(filePath);
    std::lock_guard<std::mutex> lock(activeOplockMutex_);
    auto iterator = std::find_if(
        activeOplocks_.begin(),
        activeOplocks_.end(),
        [&kNormalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr &&
                !entry->releaseRequested.load() &&
                pathEqualsCaseInsensitive(entry->path, kNormalizedPath);
        });
    if (iterator == activeOplocks_.end() || *iterator == nullptr)
    {
        return 0U;
    }
    return (*iterator)->breakCount.load();
}

std::size_t FileDock::activeOplockAccessProcessCountForPath(const QString& filePath) const
{
    const QString kNormalizedPath = normalizeFileDockPath(filePath);
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(activeOplockMutex_);
        auto iterator = std::find_if(
            activeOplocks_.begin(),
            activeOplocks_.end(),
            [&kNormalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr &&
                    !entry->releaseRequested.load() &&
                    pathEqualsCaseInsensitive(entry->path, kNormalizedPath);
            });
        if (iterator != activeOplocks_.end())
        {
            targetEntry = *iterator;
        }
    }
    if (targetEntry == nullptr)
    {
        return 0U;
    }

    std::lock_guard<std::mutex> lock(targetEntry->accessRecordMutex);
    return targetEntry->accessRecords.size();
}

void FileDock::handleOplockCompleted(
    std::shared_ptr<FileOplockEntry> entry,
    const bool completionOk,
    const unsigned long completionError,
    const bool acknowledgeOk,
    const unsigned long acknowledgeError,
    const std::size_t capturedProcessCount)
{
    if (entry == nullptr)
    {
        return;
    }

    const bool kWasManualRelease = entry->releaseRequested.load();
    if (kWasManualRelease)
    {
        return;
    }

    const QString kStateText = oplockCompletionText(completionOk, completionError);
    const QString kLevelText = fileOplockLevelText(entry->level);
    const std::uint64_t kBreakCount = entry->breakCount.load();
    KLogEvent event;
    info << event
        << "[FileDock] Oplock 访问触发, path="
        << entry->path.toStdString()
        << ", level="
        << kLevelText.toStdString()
        << ", breakCount="
        << kBreakCount
        << ", completionOk="
        << (completionOk ? "true" : "false")
        << ", completionError="
        << completionError
        << ", state="
        << kStateText.toStdString()
        << ", acknowledgeOk="
        << (acknowledgeOk ? "true" : "false")
        << ", acknowledgeError="
        << acknowledgeError
        << ", capturedProcessCount="
        << capturedProcessCount
        << ", activeCount="
        << activeOplockCount()
        << eol;
}

void FileDock::handleOplockRearmPending(
    std::shared_ptr<FileOplockEntry> entry,
    const unsigned long requestError)
{
    if (entry == nullptr || entry->releaseRequested.load())
    {
        return;
    }

    const QString kLevelText = fileOplockLevelText(entry->level);
    KLogEvent event;
    warn << event
        << "[FileDock] Oplock 触发后重新挂起暂时失败，将后台重试, path="
        << entry->path.toStdString()
        << ", level="
        << kLevelText.toStdString()
        << ", breakCount="
        << entry->breakCount.load()
        << ", requestError="
        << requestError
        << eol;
}
