#include "MemoryDock.Internal.h"
#include "../kernel_dock/KernelThreadAuditTab.h"
#include "../ui/TableInteractionSupport.h"

// ============================================================
// MemoryDock.DriverMemorySource.cpp
// Purpose:
// - Target source extensions for pages carrying "driver memory read/write": kernel module list and physical memory channels;
// - The kernel module list comes from an R3 SystemModuleInformation snapshot and does not depend on drivers being online;
// - Physical memory read/write operations directly encapsulate R0 physical memory IOCTLs, adhering to the protocol's length and flags constraints.
// ============================================================

using namespace ksword::memory_dock_internal;

namespace
{
    // kDriverMemoryKernelModuleRole: Custom role storing the kernel module base address in the dropdown.
    // A separate role is used instead of reusing Qt::UserRole because UserRole is already occupied by the process item for the PID.
    constexpr int kDriverMemoryKernelModuleBaseRole = Qt::UserRole + 2;

    // kDriverMemoryKernelModulePathRole: The role used to store the kernel module NT path in the dropdown item, for disambiguation and prompting.
    constexpr int kDriverMemoryKernelModulePathRole = Qt::UserRole + 3;

    // kDriverMemoryKernelModuleSizeRole: Role storing the kernel module image size in the dropdown for offset-out-of-bounds warnings.
    constexpr int kDriverMemoryKernelModuleSizeRole = Qt::UserRole + 4;
}

int MemoryDock::driverMemoryKernelModuleBaseRole()
{
    // Expose the role constant externally to avoid other .cpp files redefining the same magic number.
    return kDriverMemoryKernelModuleBaseRole;
}

MemoryDock::DriverMemorySourceMode MemoryDock::currentDriverMemorySourceMode() const
{
    // When the source dropdown is not initialized, default to "process virtual memory" to ensure safety for early calls.
    if (driverMemorySourceCombo_ == nullptr)
    {
        return DriverMemorySourceMode::kProcessVirtual;
    }
    const int kSelectedIndex = driverMemorySourceCombo_->currentIndex();
    if (kSelectedIndex < 0
        || kSelectedIndex > static_cast<int>(DriverMemorySourceMode::kPhysical))
    {
        return DriverMemorySourceMode::kProcessVirtual;
    }
    return static_cast<DriverMemorySourceMode>(kSelectedIndex);
}

void MemoryDock::refreshKernelModuleCacheAsync()
{
    // Log the refresh: the kernel module list serves as the dropdown data source; this step must be locatable if issues arise.
    KLogEvent kernelModuleEvent;
    info << kernelModuleEvent
        << "[MemoryDock] refreshKernelModuleCacheAsync: 开始异步枚举已加载内核模块。"
        << eol;

    // Only one enumeration cycle is allowed at a time; repeated clicks are ignored.
    bool expectedIdle = false;
    if (!kernelModuleRefreshInProgress_.compare_exchange_strong(expectedIdle, true))
    {
        return;
    }

    // Tickets are used to discard stale results: the later request on the UI always wins.
    const std::uint64_t kCurrentTicket = ++kernelModuleRefreshTicket_;
    if (driverMemoryKernelModuleRefreshButton_ != nullptr)
    {
        driverMemoryKernelModuleRefreshButton_->setEnabled(false);
    }
    if (driverMemoryStatusLabel_ != nullptr)
    {
        driverMemoryStatusLabel_->setText(QStringLiteral("正在枚举已加载内核模块..."));
    }

    // Enumeration uses a thread pool to prevent large buffer allocations from NtQuerySystemInformation from blocking the UI thread.
    QThreadPool::globalInstance()->start([this, kCurrentTicket]() {
        KernelThreadAuditTab::ModuleQueryStatus queryStatus =
            KernelThreadAuditTab::ModuleQueryStatus::kOk;
        long nativeStatus = 0L;
        unsigned long requiredBytes = 0UL;
        const std::vector<KernelThreadAuditTab::ModuleRecord> kModuleRecords =
            KernelThreadAuditTab::queryKernelModules(&queryStatus, &nativeStatus, &requiredBytes);

        // The background thread performs only data shaping; all UI updates are executed on the main thread.
        std::vector<KernelModuleEntry> convertedEntries;
        convertedEntries.reserve(kModuleRecords.size());
        for (const KernelThreadAuditTab::ModuleRecord& record : kModuleRecords)
        {
            KernelModuleEntry entry;
            entry.moduleName = record.name;
            entry.ntPath = record.path;
            entry.baseAddress = record.baseAddress;
            entry.sizeBytes = record.imageSize;
            entry.kernelImage = record.kernelImage;
            convertedEntries.push_back(entry);
        }

        const bool kQuerySucceeded =
            (queryStatus == KernelThreadAuditTab::ModuleQueryStatus::kOk);
        QMetaObject::invokeMethod(
            this,
            [this, kCurrentTicket, convertedEntries, kQuerySucceeded, nativeStatus]() {
                // An expired ticket indicates a newer round has completed; discard the results of this round entirely.
                if (kCurrentTicket != kernelModuleRefreshTicket_.load())
                {
                    return;
                }
                kernelModuleRefreshInProgress_.store(false);
                if (driverMemoryKernelModuleRefreshButton_ != nullptr)
                {
                    driverMemoryKernelModuleRefreshButton_->setEnabled(true);
                }

                if (!kQuerySucceeded)
                {
                    // On failure, retain the previous round's cache and update only the status text to avoid the dropdown suddenly clearing.
                    if (driverMemoryStatusLabel_ != nullptr)
                    {
                        driverMemoryStatusLabel_->setText(
                            QStringLiteral("内核模块枚举失败，NTSTATUS=0x%1。")
                                .arg(static_cast<qulonglong>(
                                    static_cast<std::uint32_t>(nativeStatus)), 8, 16, QChar('0'))
                                .toUpper());
                    }
                    return;
                }

                kernelModuleCache_ = convertedEntries;
                updateDriverMemoryBaseComboFromProcessCache();
                if (driverMemoryStatusLabel_ != nullptr)
                {
                    driverMemoryStatusLabel_->setText(
                        QStringLiteral("已加载 %1 个内核模块，可直接输入“模块名+偏移”定位。")
                            .arg(kernelModuleCache_.size()));
                }
            },
            Qt::QueuedConnection);
        });
}

bool MemoryDock::resolveDriverMemoryKernelModuleExpression(
    const QString& moduleToken,
    const std::uint64_t moduleOffset,
    std::uint64_t& resolvedBaseOut,
    QString& errorTextOut) const
{
    resolvedBaseOut = 0ULL;
    errorTextOut.clear();

    // Empty cache indicates enumeration hasn't occurred yet; provide explicit next-step guidance instead of a generic error.
    if (kernelModuleCache_.empty())
    {
        errorTextOut = QStringLiteral(
            "尚未加载内核模块列表，请先点击“刷新内核模块”。");
        return false;
    }
    if (kernelModuleRefreshInProgress_.load())
    {
        errorTextOut = QStringLiteral("内核模块列表正在刷新，请稍候重试。");
        return false;
    }

    // If the input contains a path separator, compare against the full path; otherwise, compare only the module filename.
    QString normalizedInput = moduleToken;
    normalizedInput.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const bool kInputContainsPath = normalizedInput.contains(QLatin1Char('\\'));
    const QString kInputFileName = QFileInfo(normalizedInput).fileName();

    std::vector<const KernelModuleEntry*> matchedEntries;
    for (const KernelModuleEntry& entry : kernelModuleCache_)
    {
        bool matched = false;
        if (kInputContainsPath)
        {
            // Kernel paths are like \SystemRoot\system32\CI.dll; use tail containment matching to support user shorthand.
            QString normalizedPath = entry.ntPath;
            normalizedPath.replace(QLatin1Char('/'), QLatin1Char('\\'));
            matched = normalizedPath.endsWith(normalizedInput, Qt::CaseInsensitive)
                || normalizedPath.compare(normalizedInput, Qt::CaseInsensitive) == 0;
        }
        else
        {
            matched = (entry.moduleName.compare(kInputFileName, Qt::CaseInsensitive) == 0);
        }
        if (matched)
        {
            matchedEntries.push_back(&entry);
        }
    }

    if (matchedEntries.empty())
    {
        errorTextOut = QStringLiteral(
            "在已加载内核模块中找不到 %1。可先点击“刷新内核模块”，或改用完整路径。")
            .arg(moduleToken);
        return false;
    }
    if (matchedEntries.size() > 1U)
    {
        errorTextOut = QStringLiteral(
            "内核模块 %1 命中 %2 项，请改用完整路径消歧。")
            .arg(moduleToken)
            .arg(matchedEntries.size());
        return false;
    }

    // Overflow protection: base address plus offset must not wrap around, otherwise it would read a completely unrelated address.
    const KernelModuleEntry* matchedEntry = matchedEntries.front();
    if (moduleOffset > (std::numeric_limits<std::uint64_t>::max() - matchedEntry->baseAddress))
    {
        errorTextOut = QStringLiteral("模块基址加偏移超出 64 位地址范围。");
        return false;
    }

    // Only warn and do not intercept when the offset exceeds the image size: debug scenarios may legitimately require reading beyond the module's tail.
    resolvedBaseOut = matchedEntry->baseAddress + moduleOffset;
    return true;
}

void MemoryDock::driverReadPhysicalMemoryFromUi()
{
    // Log physical read: the physical memory channel bypasses all process isolation, so it must be logged.
    KLogEvent physicalReadEvent;
    info << physicalReadEvent
        << "[MemoryDock] driverReadPhysicalMemoryFromUi: 请求通过 R0 读取物理内存。"
        << eol;

    if (driverMemoryAddressEdit_ == nullptr)
    {
        return;
    }

    // Physical addresses do not accept module offsets or process filters; only the address input box is parsed.
    std::uint64_t physicalAddress = 0ULL;
    if (!parseAddressText(driverMemoryAddressEdit_->text(), physicalAddress))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("驱动内存读写"),
            QStringLiteral("物理地址解析失败，请填写十六进制物理地址，例如 0x1000。"));
        return;
    }

    // The protocol specifies that physical addresses must not exceed 52 bits; reject locally if exceeded to avoid wasting an IOCTL.
    constexpr std::uint64_t kMaxPhysicalAddress = 0x000FFFFFFFFFFFFFULL;
    if (physicalAddress > kMaxPhysicalAddress)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("驱动内存读写"),
            QStringLiteral("物理地址超过驱动支持的 52 位上限。"));
        return;
    }

    // Physical read single-shot limit is 64KB; here we sum the before/after budgets and then extract.
    const std::uint64_t kBeforeBytes = (driverMemoryBeforeSpin_ != nullptr)
        ? static_cast<std::uint64_t>(driverMemoryBeforeSpin_->value())
        : 0ULL;
    const std::uint64_t kAfterBytes = (driverMemoryAfterSpin_ != nullptr)
        ? static_cast<std::uint64_t>(driverMemoryAfterSpin_->value())
        : 4096ULL;
    const std::uint64_t kBaseAddress =
        (physicalAddress >= kBeforeBytes) ? (physicalAddress - kBeforeBytes) : 0ULL;
    std::uint64_t totalBytes = kBeforeBytes + kAfterBytes;
    if (totalBytes == 0ULL)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("驱动内存读写"),
            QStringLiteral("读取长度为 0，请调整向前/向后字节数。"));
        return;
    }
    if (totalBytes > static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES))
    {
        // The physical channel limit is far lower than the virtual channel limit; we proactively truncate here and note it in the status bar rather than failing directly.
        totalBytes = static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES);
    }
    if (kBaseAddress > (kMaxPhysicalAddress - (totalBytes - 1ULL)))
    {
        QMessageBox::warning(
            this,
            QStringLiteral("驱动内存读写"),
            QStringLiteral("读取范围末端超过物理地址上限，请缩小范围。"));
        return;
    }

    // The DDMA backend accesses disk DMA directly via physical addresses, bypassing VA-to-PA translation; this is the most direct usage
    // on this channel. Since its response model differs from standard physical reads, it takes a separate branch and returns immediately.
    const ksword::memory_backend::MemoryAccessBackend kBackend = currentDriverMemoryBackend();
    if (kBackend == ksword::memory_backend::MemoryAccessBackend::kDdma)
    {
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(QStringLiteral("正在通过 DDMA 读取物理内存..."));
        }
        const ksword::memory_backend::AccessOutcome kDdmaOutcome =
            ksword::memory_backend::readPhysical(
                ksword::memory_backend::MemoryAccessBackend::kDdma,
                currentDdmaSession(),
                kBaseAddress,
                totalBytes);
        if (!kDdmaOutcome.ok)
        {
            resetDriverMemoryRwState();
            if (driverMemoryStatusLabel_ != nullptr)
            {
                driverMemoryStatusLabel_->setText(QStringLiteral("DDMA 物理读取失败。"));
            }
            QMessageBox::warning(this, QStringLiteral("驱动内存读写"), kDdmaOutcome.failureText);
            return;
        }

        driverMemoryBaseAddress_ = kBaseAddress;
        driverMemoryOffsetBase_ = 0ULL;
        driverMemoryCenterAddress_ = physicalAddress;
        driverMemorySnapshotPid_ = 0U;
        driverMemorySnapshotProcessName_ = QStringLiteral("物理内存 (DDMA)");
        driverMemorySnapshotIsPhysical_ = true;
        driverMemoryOriginalBytes_ = kDdmaOutcome.data;
        driverMemoryEditedBytes_ = driverMemoryOriginalBytes_;
        driverMemoryHasSnapshot_ = true;

        if (driverMemoryHexEditor_ != nullptr)
        {
            driverMemoryHexEditor_->setEditable(true);
            driverMemoryHexEditor_->setByteArray(
                driverMemoryEditedBytes_, driverMemoryBaseAddress_);
        }
        refreshDriverMemoryViewsFromSnapshot();

        if (driverMemoryApplyButton_ != nullptr)
        {
            driverMemoryApplyButton_->setEnabled(false);
        }
        if (driverMemoryRangeLabel_ != nullptr)
        {
            driverMemoryRangeLabel_->setText(
                QStringLiteral("物理范围(DDMA): 0x%1 - 0x%2 | 已读取 %3 字节")
                    .arg(formatAddress(driverMemoryBaseAddress_))
                    .arg(formatAddress(driverMemoryBaseAddress_
                        + static_cast<std::uint64_t>(driverMemoryOriginalBytes_.size()) - 1ULL))
                    .arg(driverMemoryOriginalBytes_.size()));
        }
        QString ddmaStatusText = QStringLiteral("DDMA 物理读取成功，共 %1 字节。")
            .arg(driverMemoryOriginalBytes_.size());
        if (kDdmaOutcome.scratchDirty)
        {
            ddmaStatusText += QStringLiteral(
                " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
        }
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(ddmaStatusText);
        }
        return;
    }

    if (driverMemoryStatusLabel_ != nullptr)
    {
        driverMemoryStatusLabel_->setText(QStringLiteral("正在通过 R0 读取物理内存..."));
    }

    // The flags for physical reads must be 0; the protocol rejects any non-zero flags.
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::PhysicalMemoryReadResult kReadResult =
        kDriverClient.readPhysicalMemory(
            kBaseAddress,
            static_cast<std::uint32_t>(totalBytes),
            0UL);

    if (!kReadResult.io.ok)
    {
        resetDriverMemoryRwState();
        const QString kFailureText = QStringLiteral(
            "物理内存读取失败。\nWin32 错误: %1\n驱动消息: %2")
            .arg(kReadResult.io.win32Error)
            .arg(QString::fromStdString(kReadResult.io.message));
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(QStringLiteral("物理内存读取失败。"));
        }
        QMessageBox::warning(this, QStringLiteral("驱动内存读写"), kFailureText);
        return;
    }

    // io.ok only indicates the IOCTL round-trip succeeded; the actual result depends on readStatus.
    const bool kHasUsableBytes =
        (kReadResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_OK
            || kReadResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_PARTIAL);
    if (!kHasUsableBytes || kReadResult.data.empty())
    {
        resetDriverMemoryRwState();
        const QString kStatusText = QStringLiteral(
            "物理内存读取未返回可用数据。\nreadStatus=%1  copyStatus=0x%2  bytesRead=%3")
            .arg(kReadResult.readStatus)
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(kReadResult.copyStatus)),
                8, 16, QChar('0'))
            .arg(kReadResult.bytesRead);
        if (driverMemoryStatusLabel_ != nullptr)
        {
            driverMemoryStatusLabel_->setText(QStringLiteral("物理内存读取未返回数据。"));
        }
        QMessageBox::warning(this, QStringLiteral("驱动内存读写"), kStatusText.toUpper());
        return;
    }

    // Physical snapshots reuse the same set of cache members, distinguished by the write-back channel using only m_driverMemorySnapshotIsPhysical.
    driverMemoryBaseAddress_ = kReadResult.requestedPhysicalAddress;
    driverMemoryOffsetBase_ = 0ULL;
    driverMemoryCenterAddress_ = physicalAddress;
    driverMemorySnapshotPid_ = 0U;
    driverMemorySnapshotProcessName_ = QStringLiteral("物理内存");
    driverMemorySnapshotIsPhysical_ = true;
    driverMemoryOriginalBytes_ = QByteArray(
        reinterpret_cast<const char*>(kReadResult.data.data()),
        static_cast<qsizetype>(kReadResult.data.size()));
    driverMemoryEditedBytes_ = driverMemoryOriginalBytes_;
    driverMemoryHasSnapshot_ = true;

    // Refresh the hex view and derived views so all three views see the same snapshot.
    if (driverMemoryHexEditor_ != nullptr)
    {
        driverMemoryHexEditor_->setEditable(true);
        driverMemoryHexEditor_->setByteArray(driverMemoryEditedBytes_, driverMemoryBaseAddress_);
    }
    refreshDriverMemoryViewsFromSnapshot();

    if (driverMemoryApplyButton_ != nullptr)
    {
        driverMemoryApplyButton_->setEnabled(false);
        driverMemoryApplyButton_->setToolTip(
            QStringLiteral("把编辑器中改动过的字节写回物理内存，单块上限 %1 字节。")
                .arg(KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES));
    }
    if (driverMemoryRangeLabel_ != nullptr)
    {
        driverMemoryRangeLabel_->setText(
            QStringLiteral("物理范围: 0x%1 - 0x%2 | 已读取 %3 字节")
                .arg(formatAddress(driverMemoryBaseAddress_))
                .arg(formatAddress(driverMemoryBaseAddress_
                    + static_cast<std::uint64_t>(driverMemoryOriginalBytes_.size()) - 1ULL))
                .arg(driverMemoryOriginalBytes_.size()));
    }
    if (driverMemoryStatusLabel_ != nullptr)
    {
        QString statusText = QStringLiteral("物理内存读取成功，共 %1 字节。")
            .arg(driverMemoryOriginalBytes_.size());
        if (kReadResult.readStatus == KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_PARTIAL)
        {
            statusText += QStringLiteral(" 驱动报告为部分读取，尾部可能不完整。");
        }
        driverMemoryStatusLabel_->setText(statusText);
    }

    KLogEvent physicalReadDoneEvent;
    info << physicalReadDoneEvent
        << "[MemoryDock] driverReadPhysicalMemoryFromUi: 物理内存读取完成。"
        << eol;
}

bool MemoryDock::applyDriverMemoryPhysicalDiff(
    const std::vector<DriverDiffBlock>& diffBlocks,
    QString& failureTextOut)
{
    failureTextOut.clear();

    // Log physical write: This is the most destructive path for page corruption.
    KLogEvent physicalWriteEvent;
    warn << physicalWriteEvent
        << "[MemoryDock] applyDriverMemoryPhysicalDiff: 开始把差异块写回物理内存。"
        << eol;

    // One-time approval of FORCE applies to all subsequent blocks in this round, avoiding a confirmation prompt for each block.
    bool forceApproved = false;
    std::uint64_t writtenBytesTotal = 0ULL;
    const ksword::ark::DriverClient kDriverClient;

    // The DDMA backend slices pages for disk DMA; slice rules, status codes, and alert bits
    // are all in the backend facade. This layer only handles force confirmation and messaging.
    if (currentDriverMemoryBackend() == ksword::memory_backend::MemoryAccessBackend::kDdma)
    {
        bool scratchDirty = false;
        bool lostUpdate = false;

        for (const DriverDiffBlock& diffBlock : diffBlocks)
        {
            ksword::memory_backend::AccessOutcome blockOutcome =
                ksword::memory_backend::writePhysical(
                    ksword::memory_backend::MemoryAccessBackend::kDdma,
                    currentDdmaSession(),
                    diffBlock.address,
                    diffBlock.bytes,
                    forceApproved);

            if (blockOutcome.forceRequired && !forceApproved)
            {
                if (!confirmForceDriverMemoryWrite(
                        diffBlock.address,
                        static_cast<std::uint32_t>(diffBlock.bytes.size()),
                        blockOutcome.failureText))
                {
                    failureTextOut = QStringLiteral("用户取消了 DDMA 强制写入。");
                    return false;
                }
                forceApproved = true;
                blockOutcome = ksword::memory_backend::writePhysical(
                    ksword::memory_backend::MemoryAccessBackend::kDdma,
                    currentDdmaSession(),
                    diffBlock.address,
                    diffBlock.bytes,
                    true);
            }

            scratchDirty = scratchDirty || blockOutcome.scratchDirty;
            lostUpdate = lostUpdate || blockOutcome.lostUpdateWindow;
            writtenBytesTotal += blockOutcome.bytesDone;

            if (!blockOutcome.ok)
            {
                failureTextOut = QStringLiteral(
                    "DDMA 物理写入失败。\n%1\n本轮累计已写入 %2 字节，失败前的改动不会自动回滚。")
                    .arg(blockOutcome.failureText)
                    .arg(writtenBytesTotal);
                if (scratchDirty)
                {
                    failureTextOut += QStringLiteral(
                        "\n严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
                }
                return false;
            }
        }

        // Alerts on the success path must also be propagated: write success does not imply a clean disk.
        if (scratchDirty || lostUpdate)
        {
            failureTextOut = QStringLiteral("DDMA 写入已完成，但存在告警：");
            if (lostUpdate)
            {
                failureTextOut += QStringLiteral(
                    "含非整页写入，驱动做了读-改-写，同页其它字节存在覆盖窗口。");
            }
            if (scratchDirty)
            {
                failureTextOut += QStringLiteral(
                    "暂存扇区未能还原，磁盘上留下了脏扇区。");
            }
        }
        return true;
    }

    for (const DriverDiffBlock& diffBlock : diffBlocks)
    {
        // Physical write limit is 4KB per operation; excess differences in the block are sliced and submitted in chunks up to the limit.
        const qsizetype kBlockSize = diffBlock.bytes.size();
        for (qsizetype chunkStart = 0; chunkStart < kBlockSize;
             chunkStart += static_cast<qsizetype>(KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES))
        {
            const qsizetype kChunkSize = std::min<qsizetype>(
                static_cast<qsizetype>(KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES),
                kBlockSize - chunkStart);
            const QByteArray kChunkBytes = diffBlock.bytes.mid(chunkStart, kChunkSize);
            const std::uint64_t kChunkAddress =
                diffBlock.address + static_cast<std::uint64_t>(chunkStart);

            const std::vector<std::uint8_t> kPayload(
                reinterpret_cast<const std::uint8_t*>(kChunkBytes.constData()),
                reinterpret_cast<const std::uint8_t*>(kChunkBytes.constData()) + kChunkBytes.size());

            // The first round includes only UI_CONFIRMED; if the driver requires FORCE, retry after obtaining user consent.
            unsigned long writeFlags = KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED;
            if (forceApproved)
            {
                writeFlags |= KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
            }
            ksword::ark::PhysicalMemoryWriteResult writeResult =
                kDriverClient.writePhysicalMemory(kChunkAddress, kPayload, writeFlags);

            if (writeResult.io.ok
                && writeResult.writeStatus == KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED
                && !forceApproved)
            {
                // Driver explicitly requires the force flag; display a single, non-dismissable confirmation dialog.
                if (!confirmForceDriverMemoryWrite(
                        kChunkAddress,
                        static_cast<std::uint32_t>(kChunkBytes.size()),
                        QStringLiteral("驱动要求对物理内存写入附加强制标志。")))
                {
                    failureTextOut = QStringLiteral("用户取消了物理内存强制写入。");
                    return false;
                }
                forceApproved = true;
                writeFlags |= KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
                writeResult = kDriverClient.writePhysicalMemory(kChunkAddress, kPayload, writeFlags);
            }

            const bool kChunkOk = writeResult.io.ok
                && writeResult.writeStatus == KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_OK
                && writeResult.bytesWritten == static_cast<std::uint32_t>(kChunkBytes.size());
            if (!kChunkOk)
            {
                // Physical writes lack transactions and rollback; failure stops immediately, leaving written portions as-is and reporting accurately.
                failureTextOut = QStringLiteral(
                    "物理内存写入失败。\n地址: 0x%1\n长度: %2 字节\n"
                    "writeStatus=%3  mapStatus=0x%4  copyStatus=0x%5\n"
                    "本轮已成功写入 %6 字节，失败块之前的改动不会自动回滚。")
                    .arg(formatAddress(kChunkAddress))
                    .arg(kChunkBytes.size())
                    .arg(writeResult.writeStatus)
                    .arg(static_cast<qulonglong>(
                        static_cast<std::uint32_t>(writeResult.mapStatus)), 8, 16, QChar('0'))
                    .arg(static_cast<qulonglong>(
                        static_cast<std::uint32_t>(writeResult.copyStatus)), 8, 16, QChar('0'))
                    .arg(writtenBytesTotal);
                return false;
            }
            writtenBytesTotal += static_cast<std::uint64_t>(kChunkBytes.size());
        }
    }

    KLogEvent physicalWriteDoneEvent;
    warn << physicalWriteDoneEvent
        << "[MemoryDock] applyDriverMemoryPhysicalDiff: 物理内存写入完成。"
        << eol;
    return true;
}
