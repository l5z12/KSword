#include "ProcessDock.h"
#include "ThreadAffinityMenu.h"
#include "ThreadStackWindow.h"

#include "../internationalization/LanguageManager.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QBrush>
#include <QChar>
#include <QClipboard>
#include <QColor>
#include <QComboBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QPushButton>
#include <QRunnable>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace
{
    // Thread table headers: emphasize thread basic identity, scheduling status, and time statistics.
    const QStringList kThreadTableHeaders{
        "TID",
        "PID",
        "进程",
        "类别",
        "启动地址",
        "Win32Start",
        "TEB",
        "UserStackBase",
        "UserStackLimit",
        "KernelStack",
        "KStackBase",
        "KStackLimit",
        "InitialStack",
        "ReadOps",
        "WriteOps",
        "OtherOps",
        "ReadBytes",
        "WriteBytes",
        "OtherBytes",
        "R0状态",
        "动态优先级",
        "基础优先级",
        "线程状态",
        "等待原因",
        "Kernel(ms)",
        "User(ms)",
        "CPU累计(ms)",
        "WaitTick",
        "上下文切换",
        "创建时间",
        "进程路径",
        "CPU占用"
    };

    // Thread page icon constants: Read uniformly from qrc aliases to avoid hard-coding disk paths.
    constexpr const char* kIconThreadTab = ":/Icon/process_threads.svg";
    constexpr const char* kIconThreadRefresh = ":/Icon/process_refresh.svg";

    // ThreadIdentityKey: Merges R3 base threads with R0 KTHREAD extensions based on PID/TID.
    struct ThreadIdentityKey
    {
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;

        bool operator==(const ThreadIdentityKey& other) const noexcept
        {
            return processId == other.processId && threadId == other.threadId;
        }
    };

    // ThreadIdentityKeyHash: Provides a lightweight hash for unordered_map.
    struct ThreadIdentityKeyHash
    {
        std::size_t operator()(const ThreadIdentityKey& key) const noexcept
        {
            const std::uint64_t kCombined =
                (static_cast<std::uint64_t>(key.processId) << 32U) |
                static_cast<std::uint64_t>(key.threadId);
            return std::hash<std::uint64_t>{}(kCombined);
        }
    };

    // hexPointerText purpose: unify address formatting; display 'Unavailable' for invalid addresses as requested by the caller.
    QString hexPointerText(const std::uint64_t addressValue, const bool zeroAsUnavailable)
    {
        if (zeroAsUnavailable && addressValue == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        // Pad with zeros to 16 digits: the table sorts by display text; without padding, "0x7FF..."
        // would sort after "0xFFFF...", and addresses of varying lengths would be unordered, contrary
        // to the behavior of pages for typed objects, SSDTs, and kernel hooks which do pad with zeros.
        // toUpper: Only affects hexadecimal digits to avoid converting the prefix to "0X".
        return QStringLiteral("0x%1")
            .arg(QString::number(static_cast<qulonglong>(addressValue), 16)
                     .rightJustified(16, QChar('0'))
                     .toUpper());
    }

    // threadR0StatusText: Converts shared protocol status values to short text for the thread table.
    QString threadR0StatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_THREAD_R0_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_THREAD_R0_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData missing");
        case KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED:
            return QStringLiteral("Read failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // threadR0CrossViewStatusText:
    // - Input: threadRecord is the merged record of R3 base threads and R0 thread extensions.
    // - Handling: Prioritize rendering cross-view suspicious status, then fall back to reading the standard R0 field status.
    // - Return: Text for the "R0 Status" column in the thread table; R0-only rows are explicitly marked as "hidden suspect".
    QString threadR0CrossViewStatusText(const ks::process::SystemThreadRecord& threadRecord)
    {
        const bool kHiddenFromActiveThreadList =
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST) != 0U;
        const bool kOwnerProcessHidden =
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_OWNER_PROCESS_HIDDEN) != 0U;

        if (threadRecord.isR0OnlyThread || kHiddenFromActiveThreadList)
        {
            return kOwnerProcessHidden
                ? QStringLiteral("R0-only / hidden suspect / owner hidden")
                : QStringLiteral("R0-only / hidden suspect");
        }
        if (kOwnerProcessHidden)
        {
            return QStringLiteral("Owner process hidden");
        }
        return threadR0StatusText(threadRecord.r0ThreadStatus);
    }

    // isSystemThreadRecord: System threads created by PsCreateSystemThread, hosted by the System process (fixed PID 4).
    bool isSystemThreadRecord(const ks::process::SystemThreadRecord& threadRecord)
    {
        return threadRecord.ownerPid == 4U;
    }

    // threadClassText: The 'present' bit for ActiveExWorker distinguishes false from unavailable DynData.
    QString threadClassText(const ks::process::SystemThreadRecord& threadRecord)
    {
        const bool kWorkerKnown =
            (threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT) != 0U;
        const bool kActiveWorker =
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER) != 0U;
        if (kWorkerKnown && kActiveWorker)
        {
            return ks::i18n::contextText(
                QStringLiteral("process.thread.class.worker"),
                QStringLiteral("工作线程"));
        }
        if (isSystemThreadRecord(threadRecord))
        {
            return kWorkerKnown
                ? ks::i18n::contextText(
                    QStringLiteral("process.thread.class.system"),
                    QStringLiteral("系统线程"))
                : ks::i18n::contextText(
                    QStringLiteral("process.thread.class.system_unknown"),
                    QStringLiteral("系统线程（Worker未知）"));
        }
        return kWorkerKnown
            ? ks::i18n::contextText(
                QStringLiteral("process.thread.class.regular"),
                QStringLiteral("普通线程"))
            : ks::i18n::contextText(
                QStringLiteral("process.thread.class.regular_unknown"),
                QStringLiteral("普通线程（Worker未知）"));
    }

    // threadDynFieldSourceText:
    // - Input sourceValue: KSW_DYN_FIELD_SOURCE_* field source enumeration.
    // - Processing: Convert the source value returned by R0 into a tooltip-readable text;
    // - Returns: Stable UI text; unknown values retain the original number for protocol drift diagnostics.
    QString threadDynFieldSourceText(const std::uint32_t sourceValue)
    {
        switch (sourceValue)
        {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            return QStringLiteral("System Informer DynData");
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Runtime pattern");
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            return QStringLiteral("Ksword extra table");
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        case KSW_DYN_FIELD_SOURCE_UNAVAILABLE:
            return QStringLiteral("Unavailable");
        default:
            return QStringLiteral("Unknown(%1)").arg(sourceValue);
        }
    }

    // threadIoMessageText:
    // - Input: thread enumeration io.message returned by ArkDriverClient
    // - Processing: Convert low-level text such as DeviceIoControl, unsupported, capability, and buffer into human-readable descriptions.
    // - Return: Short text suitable for the thread page status bar, diagnostic text, and log displays.
    QString threadIoMessageText(const QString& rawMessageText)
    {
        const QString kTrimmedText = rawMessageText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明。");
        }

        const QString kLowerText = kTrimmedText.toLower();
        if (kLowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return QStringLiteral("驱动线程枚举接口调用失败或当前驱动版本不匹配。");
        }
        if (kLowerText.contains(QStringLiteral("unsupported")) ||
            kLowerText.contains(QStringLiteral("not supported")) ||
            kLowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return QStringLiteral("当前驱动暂不支持线程 cross-view / KTHREAD 扩展枚举。");
        }
        if (kLowerText.contains(QStringLiteral("dyndata")) ||
            kLowerText.contains(QStringLiteral("capability")))
        {
            return QStringLiteral("DynData 动态偏移能力未满足，线程 R0 扩展字段暂不可用。");
        }
        if (kLowerText.contains(QStringLiteral("buffer")) &&
            (kLowerText.contains(QStringLiteral("small")) || kLowerText.contains(QStringLiteral("trunc"))))
        {
            return QStringLiteral("驱动返回缓冲区不足，线程枚举结果可能被截断。");
        }
        return kTrimmedText;
    }

    // threadIoMessageStdString:
    // - Input: std::string raw message from ArkDriverClient
    // - Processing: Reuse threadIoMessageText for normalization, then convert back to UTF-8.
    // - Return: a std::string compatible with the legacy diagnosticTextOut concatenation pipeline.
    std::string threadIoMessageStdString(const std::string& rawMessageText)
    {
        return threadIoMessageText(QString::fromStdString(rawMessageText)).toStdString();
    }

    // threadR0DiagnosticText:
    // - Display field source and original offset when a thread is selected or the R0 status column is hovered.
    // - Phase 3 will not add a detailed view page yet; diagnostic information will be exposed via the status bar and tooltips instead.
    QString threadR0DiagnosticText(const ks::process::SystemThreadRecord& threadRecord)
    {
        auto offsetText = [](const std::uint32_t offsetValue) -> QString {
            if (offsetValue == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE)
            {
                return QStringLiteral("Unavailable");
            }
            return QStringLiteral("0x%1").arg(offsetValue, 0, 16).toUpper();
        };

        QStringList offsetParts;
        offsetParts
            << QStringLiteral("Initial=%1").arg(offsetText(threadRecord.r0KtInitialStackOffset))
            << QStringLiteral("StackLimit=%1").arg(offsetText(threadRecord.r0KtStackLimitOffset))
            << QStringLiteral("StackBase=%1").arg(offsetText(threadRecord.r0KtStackBaseOffset))
            << QStringLiteral("KernelStack=%1").arg(offsetText(threadRecord.r0KtKernelStackOffset))
            << QStringLiteral("ReadOps=%1").arg(offsetText(threadRecord.r0KtReadOperationCountOffset))
            << QStringLiteral("WriteOps=%1").arg(offsetText(threadRecord.r0KtWriteOperationCountOffset))
            << QStringLiteral("OtherOps=%1").arg(offsetText(threadRecord.r0KtOtherOperationCountOffset))
            << QStringLiteral("ReadBytes=%1").arg(offsetText(threadRecord.r0KtReadTransferCountOffset))
            << QStringLiteral("WriteBytes=%1").arg(offsetText(threadRecord.r0KtWriteTransferCountOffset))
            << QStringLiteral("OtherBytes=%1").arg(offsetText(threadRecord.r0KtOtherTransferCountOffset));

        return QStringLiteral("R0=%1 | Flags=0x%2 | StackSource=%3 | IoSource=%4 | Cap=0x%5 | Offsets: %6")
            .arg(threadR0CrossViewStatusText(threadRecord))
            .arg(static_cast<qulonglong>(threadRecord.r0ThreadFlags), 0, 16)
            .arg(threadDynFieldSourceText(threadRecord.r0StackFieldSource))
            .arg(threadDynFieldSourceText(threadRecord.r0IoFieldSource))
            .arg(static_cast<qulonglong>(threadRecord.r0ThreadDynDataCapabilityMask), 0, 16)
            .arg(offsetParts.join(QStringLiteral(", ")));
    }

    // mergeThreadR0Entry purpose: Overwrite the R3 thread record with the R0 entry parsed by ArkDriverClient.
    void mergeThreadR0Entry(
        ks::process::SystemThreadRecord& threadRecord,
        const ksword::ark::ThreadEntry& r0Entry)
    {
        threadRecord.r0ThreadFlags = r0Entry.flags;
        threadRecord.r0ThreadFieldFlags = r0Entry.fieldFlags;
        threadRecord.r0ThreadStatus = r0Entry.r0Status;
        threadRecord.r0StackFieldSource = r0Entry.stackFieldSource;
        threadRecord.r0IoFieldSource = r0Entry.ioFieldSource;
        threadRecord.r0InitialStack = r0Entry.initialStack;
        threadRecord.r0StackLimit = r0Entry.stackLimit;
        threadRecord.r0StackBase = r0Entry.stackBase;
        threadRecord.r0KernelStack = r0Entry.kernelStack;
        threadRecord.r0ReadOperationCount = r0Entry.readOperationCount;
        threadRecord.r0WriteOperationCount = r0Entry.writeOperationCount;
        threadRecord.r0OtherOperationCount = r0Entry.otherOperationCount;
        threadRecord.r0ReadTransferCount = r0Entry.readTransferCount;
        threadRecord.r0WriteTransferCount = r0Entry.writeTransferCount;
        threadRecord.r0OtherTransferCount = r0Entry.otherTransferCount;
        threadRecord.r0KtInitialStackOffset = r0Entry.ktInitialStackOffset;
        threadRecord.r0KtStackLimitOffset = r0Entry.ktStackLimitOffset;
        threadRecord.r0KtStackBaseOffset = r0Entry.ktStackBaseOffset;
        threadRecord.r0KtKernelStackOffset = r0Entry.ktKernelStackOffset;
        threadRecord.r0KtReadOperationCountOffset = r0Entry.ktReadOperationCountOffset;
        threadRecord.r0KtWriteOperationCountOffset = r0Entry.ktWriteOperationCountOffset;
        threadRecord.r0KtOtherOperationCountOffset = r0Entry.ktOtherOperationCountOffset;
        threadRecord.r0KtReadTransferCountOffset = r0Entry.ktReadTransferCountOffset;
        threadRecord.r0KtWriteTransferCountOffset = r0Entry.ktWriteTransferCountOffset;
        threadRecord.r0KtOtherTransferCountOffset = r0Entry.ktOtherTransferCountOffset;
        threadRecord.r0ThreadDynDataCapabilityMask = r0Entry.dynDataCapabilityMask;
    }

    // mergeThreadR0Snapshot:
    // - R3 base thread list must be preserved first;
    // - On driver absence or IOCTL failure, only append diagnostics without clearing R3 results;
    // - Merge KTHREAD stack fields and I/O counters by PID/TID on success.
    bool mergeThreadR0Snapshot(
        std::vector<ks::process::SystemThreadRecord>& threadList,
        std::string* diagnosticTextOut)
    {
        const ksword::ark::DriverClient kDriverClient;
        const ksword::ark::ThreadEnumResult kR0Result =
            kDriverClient.enumerateThreads(
                KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL | KSWORD_ARK_ENUM_THREAD_FLAG_SCAN_CID_TABLE);
        if (!kR0Result.io.ok)
        {
            if (diagnosticTextOut != nullptr)
            {
                if (!diagnosticTextOut->empty())
                {
                    *diagnosticTextOut += " | ";
                }
                *diagnosticTextOut += "R0 thread extension unavailable: " + threadIoMessageStdString(kR0Result.io.message);
            }
            return false;
        }

        std::unordered_map<ThreadIdentityKey, const ksword::ark::ThreadEntry*, ThreadIdentityKeyHash> r0ByThread;
        r0ByThread.reserve(kR0Result.entries.size());
        std::unordered_map<std::uint32_t, const ksword::ark::ThreadEntry*> r0OnlyByTid;
        for (const ksword::ark::ThreadEntry& r0Entry : kR0Result.entries)
        {
            if (r0Entry.threadId == 0U)
            {
                continue;
            }
            r0ByThread.insert_or_assign(
                ThreadIdentityKey{ r0Entry.processId, r0Entry.threadId },
                &r0Entry);
            if ((r0Entry.flags & KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST) != 0U)
            {
                r0OnlyByTid.insert_or_assign(r0Entry.threadId, &r0Entry);
            }
        }

        const std::size_t kR3BaseThreadCount = threadList.size();
        std::size_t mergedCount = 0;
        for (ks::process::SystemThreadRecord& threadRecord : threadList)
        {
            const auto kR0It = r0ByThread.find(ThreadIdentityKey{ threadRecord.ownerPid, threadRecord.threadId });
            if (kR0It == r0ByThread.end() || kR0It->second == nullptr)
            {
                continue;
            }
            mergeThreadR0Entry(threadRecord, *(kR0It->second));
            ++mergedCount;
        }

        std::size_t appendedR0OnlyCount = 0;
        for (const auto& r0OnlyPair : r0OnlyByTid)
        {
            const ksword::ark::ThreadEntry* r0OnlyEntry = r0OnlyPair.second;
            if (r0OnlyEntry == nullptr)
            {
                continue;
            }

            const bool kAlreadyPresent = std::any_of(
                threadList.begin(),
                threadList.end(),
                [r0OnlyEntry](const ks::process::SystemThreadRecord& threadRecord)
                {
                    return threadRecord.threadId == r0OnlyEntry->threadId &&
                        threadRecord.ownerPid == r0OnlyEntry->processId;
                });
            if (kAlreadyPresent)
            {
                continue;
            }

            ks::process::SystemThreadRecord threadRecord{};
            threadRecord.threadId = r0OnlyEntry->threadId;
            threadRecord.ownerPid = r0OnlyEntry->processId;
            threadRecord.ownerProcessName = "Unknown";
            threadRecord.priority = std::numeric_limits<int>::min();
            threadRecord.basePriority = std::numeric_limits<int>::min();
            threadRecord.threadState = std::numeric_limits<std::uint32_t>::max();
            threadRecord.waitReason = std::numeric_limits<std::uint32_t>::max();
            threadRecord.r0ThreadFlags = r0OnlyEntry->flags;
            threadRecord.isR0OnlyThread = true;
            mergeThreadR0Entry(threadRecord, *r0OnlyEntry);
            threadList.push_back(std::move(threadRecord));
            ++appendedR0OnlyCount;
        }

        if (diagnosticTextOut != nullptr)
        {
            if (!diagnosticTextOut->empty())
            {
                *diagnosticTextOut += " | ";
            }
            std::ostringstream stream;
            stream << "R0 thread extension merged: " << mergedCount
                << "/" << kR3BaseThreadCount
                << ", r0OnlyAppended=" << appendedR0OnlyCount
                << ", " << threadIoMessageStdString(kR0Result.io.message);
            *diagnosticTextOut += stream.str();
        }
        return true;
    }

    // buildThreadButtonStyle:
    // - Provide a unified blue style for thread tab buttons.
    // - Icon-only buttons and text buttons share the same border/hover color logic.
    QString buildThreadButtonStyle(const bool iconOnlyButton)
    {
        const QString kPaddingText = iconOnlyButton ? QStringLiteral("4px") : QStringLiteral("4px 10px");
        return QStringLiteral(
            "QPushButton {"
            "  color: %1;"
            "  background: %6;"
            "  border: 1px solid %2;"
            "  border-radius: 3px;"
            "  padding: %5;"
            "}"
            "QPushButton:hover {"
            "  background: %3;"
            "  color: %7;"
            "  border: 1px solid %3;"
            "}"
            "QPushButton:pressed {"
            "  background: %4;"
            "  color: %7;"
            "}")
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue, 0, -26))
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue, -14, -40))
            .arg(kPaddingText)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::onAccentDynamicHex());
    }

    // buildThreadSearchStyle: Unifies the search box border and focus color for the thread tab.
    QString buildThreadSearchStyle()
    {
        return QStringLiteral(
            "QLineEdit {"
            "  border: 1px solid %2;"
            "  border-radius: 3px;"
            "  background: %3;"
            "  color: %4;"
            "  padding: 3px 5px;"
            "}"
            "QLineEdit:focus {"
            "  border: 1px solid %1;"
            "}")
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // buildThreadPresetButtonStyle: A/B adjacent buttons share checked highlighting; only round the outer corners.
    QString buildThreadPresetButtonStyle(const bool leftButton)
    {
        const QString kOuterRadius = leftButton
            ? QStringLiteral("border-top-left-radius:3px;border-bottom-left-radius:3px;")
            : QStringLiteral("border-top-right-radius:3px;border-bottom-right-radius:3px;border-left:0px;");
        return QStringLiteral(
            "QPushButton{"
            "  min-width:27px;max-width:27px;min-height:26px;max-height:26px;"
            "  padding:0px;font-weight:700;"
            "  color:%1;background:%2;border:1px solid %3;"
            "  border-radius:0px;%4"
            "}"
            "QPushButton:hover:!checked{background:%5;color:%1;}"
            "QPushButton:checked{background:%6;color:%7;border-color:%6;}"
            "QPushButton:pressed{background:%8;color:%7;}")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex())
            .arg(kOuterRadius)
            .arg(ksword_theme::primaryBlueSubtleHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::onAccentDynamicHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue, -10, -36));
    }
}

int ProcessDock::toThreadColumnIndex(const ThreadTableColumn column)
{
    return static_cast<int>(column);
}

void ProcessDock::initializeThreadPage()
{
    // Thread page structure:
    // 1) Top action bar (Refresh button + Search box + Status);
    // 2) Thread table below (supports sorting and right-click actions).
    threadPage_ = new QWidget(this);
    threadPageLayout_ = new QVBoxLayout(threadPage_);
    threadPageLayout_->setContentsMargins(6, 6, 6, 6);
    threadPageLayout_->setSpacing(6);

    // Top action bar controls: all use icon buttons + tooltips.
    threadTopLayout_ = new QHBoxLayout();
    threadTopLayout_->setContentsMargins(0, 0, 0, 0);
    threadTopLayout_->setSpacing(8);

    threadRefreshButton_ = new QPushButton(QIcon(kIconThreadRefresh), "", threadPage_);
    ksword_theme::applyCompactIconButtonMetrics(threadRefreshButton_);
    threadRefreshButton_->setToolTip("刷新系统线程列表（优先 NtQuerySystemInformation）");
    threadRefreshButton_->setStyleSheet(buildThreadButtonStyle(true));

    // A/B buttons must be adjacent: A is highlighted by default; B provides address and R0 diagnostic columns.
    threadColumnPresetWidget_ = new QWidget(threadPage_);
    threadColumnPresetLayout_ = new QHBoxLayout(threadColumnPresetWidget_);
    threadColumnPresetLayout_->setContentsMargins(0, 0, 0, 0);
    threadColumnPresetLayout_->setSpacing(0);
    threadColumnPresetAButton_ = new QPushButton(QStringLiteral("A"), threadColumnPresetWidget_);
    threadColumnPresetBButton_ = new QPushButton(QStringLiteral("B"), threadColumnPresetWidget_);
    threadColumnPresetAButton_->setCheckable(true);
    threadColumnPresetBButton_->setCheckable(true);
    threadColumnPresetLayout_->addWidget(threadColumnPresetAButton_);
    threadColumnPresetLayout_->addWidget(threadColumnPresetBButton_);
    ks::i18n::LanguageManager::instance().bindToolTip(
        threadColumnPresetAButton_,
        QStringLiteral("process.thread.columns.preset_a.tooltip"),
        QStringLiteral("线程列预设 A：调度概览"));
    ks::i18n::LanguageManager::instance().bindToolTip(
        threadColumnPresetBButton_,
        QStringLiteral("process.thread.columns.preset_b.tooltip"),
        QStringLiteral("线程列预设 B：地址与 R0 诊断"));

    threadScopeCombo_ = new QComboBox(threadPage_);
    threadScopeCombo_->addItem(QStringLiteral("全部线程"), static_cast<int>(ThreadScopeFilter::kAll));
    threadScopeCombo_->addItem(QStringLiteral("系统线程"), static_cast<int>(ThreadScopeFilter::kSystem));
    threadScopeCombo_->addItem(QStringLiteral("工作线程"), static_cast<int>(ThreadScopeFilter::kWorker));
    ks::i18n::LanguageManager::instance().bindComboBoxItem(
        threadScopeCombo_, 0, QStringLiteral("process.thread.scope.all"), QStringLiteral("全部线程"));
    ks::i18n::LanguageManager::instance().bindComboBoxItem(
        threadScopeCombo_, 1, QStringLiteral("process.thread.scope.system"), QStringLiteral("系统线程"));
    ks::i18n::LanguageManager::instance().bindComboBoxItem(
        threadScopeCombo_, 2, QStringLiteral("process.thread.scope.worker"), QStringLiteral("工作线程"));
    ks::i18n::LanguageManager::instance().bindToolTip(
        threadScopeCombo_,
        QStringLiteral("process.thread.scope.tooltip"),
        QStringLiteral("按线程类别筛选；工作线程由 R0 DynData v4 的 _ETHREAD.ActiveExWorker 位识别"));
    threadScopeCombo_->setMinimumWidth(112);

    threadSearchLineEdit_ = new QLineEdit(threadPage_);
    threadSearchLineEdit_->setClearButtonEnabled(true);
    threadSearchLineEdit_->setPlaceholderText("搜索 TID / PID / 进程名 / 状态 / 启动地址");
    threadSearchLineEdit_->setToolTip("过滤当前线程列表，不触发新的系统查询");
    threadSearchLineEdit_->setStyleSheet(buildThreadSearchStyle());
    threadSearchLineEdit_->setMaximumWidth(360);

    threadTopLayout_->addWidget(threadRefreshButton_);
    threadTopLayout_->addWidget(threadColumnPresetWidget_);
    threadTopLayout_->addWidget(threadScopeCombo_);
    threadTopLayout_->addWidget(threadSearchLineEdit_);
    threadTopLayout_->addStretch(1);
    threadPageLayout_->addLayout(threadTopLayout_);

    // initialize the thread table: use QTreeWidget to support icons in the first column and multi-column sorting.
    threadTable_ = new QTreeWidget(threadPage_);
    threadTable_->setColumnCount(static_cast<int>(ThreadTableColumn::kCount));
    threadTable_->setHeaderLabels(kThreadTableHeaders);
    threadTable_->setRootIsDecorated(false);
    threadTable_->setItemsExpandable(false);
    threadTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    threadTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    threadTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    threadTable_->setUniformRowHeights(true);
    threadTable_->setAlternatingRowColors(true);
    threadTable_->setSortingEnabled(true);
    threadTable_->setContextMenuPolicy(Qt::CustomContextMenu);

    QHeaderView* threadHeaderView = threadTable_->header();
    threadHeaderView->setSectionsMovable(true);
    threadHeaderView->setStretchLastSection(false);
    threadHeaderView->setContextMenuPolicy(Qt::CustomContextMenu);
    threadHeaderView->setStyleSheet(QStringLiteral(
        "QHeaderView::section {"
        "  color: %1;"
        "  background: transparent; /* %2 */"
        "  border: 1px solid %3;"
        "  padding: 4px;"
        "  font-weight: 600;"
        "}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::borderHex()));

    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kThreadId), 90);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kOwnerPid), 90);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kProcessName), 240);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kThreadClass), 150);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kStartAddress), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kWin32StartAddress), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kTebBaseAddress), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kUserStackBase), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kUserStackLimit), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kKernelStack), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kKStackBase), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kKStackLimit), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kInitialStack), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kReadOps), 100);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kWriteOps), 100);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kOtherOps), 100);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kReadBytes), 120);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kWriteBytes), 120);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kOtherBytes), 120);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kThreadR0Status), 130);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kPriority), 96);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kBasePriority), 96);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kThreadState), 140);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kWaitReason), 170);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kKernelTimeMs), 110);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kUserTimeMs), 110);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kCpuTimeMs), 120);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kWaitTimeTick), 110);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kContextSwitches), 120);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kCreateTime), 170);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kProcessPath), 360);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kCpuPercent), 105);

    // Issue #33: Specify default use of A; apply the hidden set here after all initial column widths are configured.
    applyThreadColumnLayout(ThreadColumnLayout::kPresetA);

    threadPageLayout_->addWidget(threadTable_, 1);
    sideTabWidget_->addTab(threadPage_, blueTintedIcon(kIconThreadTab), "线程列表");
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        threadPage_,
        QStringLiteral("process.tab.threads"),
        QStringLiteral("线程列表"));
    refreshSideTabIconContrast();
}

void ProcessDock::applyThreadColumnLayout(const ThreadColumnLayout layout)
{
    if (threadTable_ == nullptr || layout == ThreadColumnLayout::kCustom)
    {
        threadColumnLayout_ = layout;
        updateThreadColumnPresetButtons();
        return;
    }

    static constexpr std::array<ThreadTableColumn, 10> kPresetAColumns{
        ThreadTableColumn::kThreadId,
        ThreadTableColumn::kOwnerPid,
        ThreadTableColumn::kProcessName,
        ThreadTableColumn::kThreadClass,
        ThreadTableColumn::kPriority,
        ThreadTableColumn::kThreadState,
        ThreadTableColumn::kWaitReason,
        ThreadTableColumn::kCpuTimeMs,
        ThreadTableColumn::kCpuPercent,
        ThreadTableColumn::kContextSwitches
    };
    static constexpr std::array<ThreadTableColumn, 9> kPresetBColumns{
        ThreadTableColumn::kThreadId,
        ThreadTableColumn::kOwnerPid,
        ThreadTableColumn::kProcessName,
        ThreadTableColumn::kThreadClass,
        ThreadTableColumn::kStartAddress,
        ThreadTableColumn::kWin32StartAddress,
        ThreadTableColumn::kTebBaseAddress,
        ThreadTableColumn::kKernelStack,
        ThreadTableColumn::kThreadR0Status
    };
    const auto kColumnIsVisible = [layout](const ThreadTableColumn column) {
        if (layout == ThreadColumnLayout::kPresetA)
        {
            return std::find(kPresetAColumns.cbegin(), kPresetAColumns.cend(), column) !=
                kPresetAColumns.cend();
        }
        return std::find(kPresetBColumns.cbegin(), kPresetBColumns.cend(), column) !=
            kPresetBColumns.cend();
    };

    threadApplyingColumnLayout_ = true;
    for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::kCount); ++columnIndex)
    {
        const ThreadTableColumn kColumn = static_cast<ThreadTableColumn>(columnIndex);
        const bool kVisible = kColumnIsVisible(kColumn);
        threadTable_->setColumnHidden(columnIndex, !kVisible);
    }

    // Both preset configurations are kept within approximately one screen width to avoid horizontal scrolling for core information.
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kThreadId), 78);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kOwnerPid), 78);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kProcessName), 180);
    threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kThreadClass), 140);
    if (layout == ThreadColumnLayout::kPresetA)
    {
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kPriority), 88);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kThreadState), 125);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kWaitReason), 145);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kCpuTimeMs), 105);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kCpuPercent), 100);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kContextSwitches), 115);
    }
    else
    {
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kStartAddress), 132);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kWin32StartAddress), 132);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kTebBaseAddress), 132);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kKernelStack), 132);
        threadTable_->setColumnWidth(toThreadColumnIndex(ThreadTableColumn::kThreadR0Status), 130);
    }
    threadApplyingColumnLayout_ = false;
    threadColumnLayout_ = layout;
    updateThreadColumnPresetButtons();
}

void ProcessDock::clearThreadColumnPresetSelection()
{
    if (threadApplyingColumnLayout_)
    {
        return;
    }
    threadColumnLayout_ = ThreadColumnLayout::kCustom;
    updateThreadColumnPresetButtons();
}

void ProcessDock::updateThreadColumnPresetButtons()
{
    if (threadColumnPresetAButton_ == nullptr || threadColumnPresetBButton_ == nullptr)
    {
        return;
    }

    const QSignalBlocker kPresetABlocker(threadColumnPresetAButton_);
    const QSignalBlocker kPresetBBlocker(threadColumnPresetBButton_);
    threadColumnPresetAButton_->setStyleSheet(buildThreadPresetButtonStyle(true));
    threadColumnPresetBButton_->setStyleSheet(buildThreadPresetButtonStyle(false));
    threadColumnPresetAButton_->setChecked(threadColumnLayout_ == ThreadColumnLayout::kPresetA);
    threadColumnPresetBButton_->setChecked(threadColumnLayout_ == ThreadColumnLayout::kPresetB);
}

void ProcessDock::showThreadHeaderContextMenu(const QPoint& localPosition)
{
    if (threadTable_ == nullptr || threadTable_->header() == nullptr)
    {
        return;
    }

    // The header menu explicitly uses an opaque theme style; each column can be independently shown or hidden.
    QMenu columnMenu(threadTable_);
    columnMenu.setStyleSheet(buildThreadContextMenuStyle());
    for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::kCount); ++columnIndex)
    {
        QAction* columnAction = columnMenu.addAction(
            ks::i18n::displayText(kThreadTableHeaders.value(columnIndex)));
        columnAction->setCheckable(true);
        columnAction->setChecked(!threadTable_->isColumnHidden(columnIndex));
        connect(columnAction, &QAction::toggled, &columnMenu, [this, columnIndex](const bool visible)
            {
                threadTable_->setColumnHidden(columnIndex, !visible);
                clearThreadColumnPresetSelection();
            });
    }
    columnMenu.exec(threadTable_->header()->mapToGlobal(localPosition));
}

void ProcessDock::initializeThreadPageConnections()
{
    // Refresh button: User-initiated refresh of the thread list, ignoring the monitoring switch.
    if (threadRefreshButton_ != nullptr)
    {
        connect(threadRefreshButton_, &QPushButton::clicked, this, [this]() {
            requestAsyncThreadRefresh(true);
        });
    }

    // Search box: filters only the current cached results without triggering system calls.
    if (threadSearchLineEdit_ != nullptr)
    {
        connect(threadSearchLineEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
            rebuildThreadTable();
        });
    }

    // Category filter: only filters the current thread snapshot to avoid redundant R0 requests when switching filters.
    if (threadScopeCombo_ != nullptr)
    {
        connect(threadScopeCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
            rebuildThreadTable();
        });
    }

    if (threadColumnPresetAButton_ != nullptr)
    {
        connect(threadColumnPresetAButton_, &QPushButton::clicked, this, [this]() {
            applyThreadColumnLayout(ThreadColumnLayout::kPresetA);
        });
    }
    if (threadColumnPresetBButton_ != nullptr)
    {
        connect(threadColumnPresetBButton_, &QPushButton::clicked, this, [this]() {
            applyThreadColumnLayout(ThreadColumnLayout::kPresetB);
        });
    }

    // Thread table right-click menu: Suspend/Resume/Terminate thread + Navigate to process details.
    if (threadTable_ != nullptr)
    {
        connect(threadTable_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showThreadTableContextMenu(localPosition);
        });

        QHeaderView* threadHeader = threadTable_->header();
        connect(threadHeader, &QHeaderView::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showThreadHeaderContextMenu(localPosition);
        });
        connect(threadHeader, &QHeaderView::sectionMoved, this, [this](int, int, int) {
            clearThreadColumnPresetSelection();
        });
        connect(threadHeader, &QHeaderView::sectionResized, this, [this](int, int, int) {
            clearThreadColumnPresetSelection();
        });
    }
}

void ProcessDock::requestAsyncThreadRefresh(const bool forceRefresh)
{
    if (threadTable_ == nullptr)
    {
        return;
    }

    // On non-forced refresh, adhere to monitoring toggle and menu freeze rules.
    if (!forceRefresh)
    {
        if (!monitoringEnabled_ || threadContextMenuVisible_)
        {
            return;
        }
    }

    // Concurrency protection: only one background task is allowed to refresh threads at any given moment.
    if (threadRefreshInProgress_)
    {
        return;
    }

    threadRefreshInProgress_ = true;
    const std::uint64_t kLocalTicket = ++threadRefreshTicket_;
    auto previousThreadCounters = threadCounterSampleByIdentity_;
    auto cpuCoreUsageSnapshot = latestCpuCoreUsageSnapshot_;
    const std::uint32_t kLogicalCpuCount = logicalCpuCount_;

    if (threadRefreshButton_ != nullptr)
    {
        threadRefreshButton_->setEnabled(false);
    }

    {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 线程列表刷新开始, ticket=" << kLocalTicket
            << ", force=" << (forceRefresh ? "true" : "false")
            << eol;
    }

    QPointer<ProcessDock> guardThis(this);
    QRunnable* backgroundTask = QRunnable::create([
        guardThis,
        kLocalTicket,
        kLogicalCpuCount,
        previousThreadCounters = std::move(previousThreadCounters),
        cpuCoreUsageSnapshot = std::move(cpuCoreUsageSnapshot)]() mutable {
        bool usedNtQuery = false;
        std::string diagnosticText;
        std::vector<ks::process::SystemThreadRecord> threadList =
            ks::process::enumerateSystemThreads(&usedNtQuery, &diagnosticText);
        const bool kR0ThreadExtensionMerged = mergeThreadR0Snapshot(threadList, &diagnosticText);

        const std::uint64_t kCurrentTick100ns = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count() / 100);
        auto nextThreadCounters =
            std::make_shared<std::unordered_map<std::string, ks::process::ThreadCounterSample>>();
        nextThreadCounters->reserve(threadList.size());
        for (ks::process::SystemThreadRecord& threadRecord : threadList)
        {
            const std::string kIdentityKey = ks::process::buildThreadIdentityKey(
                threadRecord.ownerPid,
                threadRecord.threadId,
                threadRecord.createTime100ns);
            const auto kPreviousIt = previousThreadCounters.find(kIdentityKey);
            ks::process::ThreadCounterSample nextSample{};
            ks::process::updateThreadCpuUsage(
                threadRecord,
                kPreviousIt != previousThreadCounters.end() ? &kPreviousIt->second : nullptr,
                nextSample,
                kLogicalCpuCount,
                kCurrentTick100ns);
            nextThreadCounters->emplace(kIdentityKey, nextSample);

            // Prefer real scheduling attribution when the CSwitch interval is available; surviving threads without running events are displayed as 0%.
            if (cpuCoreUsageSnapshot != nullptr &&
                cpuCoreUsageSnapshot->monitorRunning &&
                cpuCoreUsageSnapshot->sampleReady &&
                !cpuCoreUsageSnapshot->dataLossDetected)
            {
                const auto kCoreUsageIt = cpuCoreUsageSnapshot->threadUsageByIdentity.find(
                    ks::process::buildCpuThreadIdentity(threadRecord.ownerPid, threadRecord.threadId));
                threadRecord.cpuPercent = kCoreUsageIt != cpuCoreUsageSnapshot->threadUsageByIdentity.end()
                    ? kCoreUsageIt->second.coreEquivalentPercent
                    : 0.0;
                threadRecord.cpuUsageReady = true;
            }
        }

        auto deferredThreadList =
            std::make_shared<std::vector<ks::process::SystemThreadRecord>>(std::move(threadList));
        QMetaObject::invokeMethod(guardThis, [guardThis, kLocalTicket, usedNtQuery, kR0ThreadExtensionMerged, diagnosticText, deferredThreadList, nextThreadCounters]() {
            if (guardThis == nullptr)
            {
                return;
            }

            if (guardThis->threadRefreshTicket_ != kLocalTicket)
            {
                guardThis->threadRefreshInProgress_ = false;
                if (guardThis->threadRefreshButton_ != nullptr)
                {
                    guardThis->threadRefreshButton_->setEnabled(true);
                }
                return;
            }

            auto commit = [
                guardThis,
                kLocalTicket,
                usedNtQuery,
                kR0ThreadExtensionMerged,
                diagnosticText,
                deferredThreadList,
                nextThreadCounters]() mutable
            {
                if (guardThis == nullptr || guardThis->threadRefreshTicket_ != kLocalTicket)
                {
                    return;
                }

                guardThis->threadRecordList_ = std::move(*deferredThreadList);
                guardThis->threadCounterSampleByIdentity_ = std::move(*nextThreadCounters);
                guardThis->threadDiagnosticText_ = diagnosticText;
                guardThis->rebuildThreadTable();

                {
                    KLogEvent logEvent;
                    info << logEvent
                        << "[ProcessDock] 线程列表刷新完成, ticket=" << kLocalTicket
                        << ", count=" << guardThis->threadRecordList_.size()
                        << ", usedNtQuery=" << (usedNtQuery ? "true" : "false")
                        << ", r0ThreadExtensionMerged=" << (kR0ThreadExtensionMerged ? "true" : "false")
                        << ", diagnostic=" << guardThis->threadDiagnosticText_
                        << eol;
                }

                guardThis->threadRefreshInProgress_ = false;
                if (guardThis->threadRefreshButton_ != nullptr)
                {
                    guardThis->threadRefreshButton_->setEnabled(true);
                }
            };
            if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                    guardThis.data(),
                    QStringLiteral("process-thread-snapshot-apply"),
                    {guardThis->threadTable_},
                    commit))
            {
                return;
            }
            commit();
        }, Qt::QueuedConnection);
    });
    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}

bool ProcessDock::threadRecordMatchesSearch(const ks::process::SystemThreadRecord& threadRecord) const
{
    if (threadSearchLineEdit_ == nullptr)
    {
        return true;
    }

    const QString kSearchText = threadSearchLineEdit_->text().trimmed();
    if (kSearchText.isEmpty())
    {
        return true;
    }

    const QStringList kSearchableFields{
        QString::number(threadRecord.threadId),
        QString::number(threadRecord.ownerPid),
        QString::fromStdString(threadRecord.ownerProcessName),
        threadClassText(threadRecord),
        hexPointerText(threadRecord.startAddress, false),
        QString("0x%1").arg(static_cast<qulonglong>(threadRecord.win32StartAddress), 0, 16).toUpper(),
        QString("0x%1").arg(static_cast<qulonglong>(threadRecord.tebBaseAddress), 0, 16).toUpper(),
        QString("0x%1").arg(static_cast<qulonglong>(threadRecord.r0KernelStack), 0, 16).toUpper(),
        threadStateText(threadRecord.threadState),
        threadWaitReasonText(threadRecord.waitReason),
        threadR0CrossViewStatusText(threadRecord)
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

bool ProcessDock::threadRecordMatchesScope(const ks::process::SystemThreadRecord& threadRecord) const
{
    if (threadScopeCombo_ == nullptr)
    {
        return true;
    }

    const ThreadScopeFilter kScope = static_cast<ThreadScopeFilter>(
        threadScopeCombo_->currentData().toInt());
    if (kScope == ThreadScopeFilter::kSystem)
    {
        return isSystemThreadRecord(threadRecord);
    }
    if (kScope == ThreadScopeFilter::kWorker)
    {
        return
            (threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT) != 0U &&
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER) != 0U;
    }
    return true;
}

void ProcessDock::rebuildThreadTable()
{
    if (threadTable_ == nullptr)
    {
        return;
    }

    QSignalBlocker tableSignalBlocker(threadTable_);
    threadTable_->setSortingEnabled(false);
    threadTable_->clear();

    // processRecordByPid usage: Reuses path and icon information from the process cache by PID.
    std::unordered_map<std::uint32_t, const ks::process::ProcessRecord*> processRecordByPid;
    processRecordByPid.reserve(cacheByIdentity_.size());
    for (const auto& cachePair : cacheByIdentity_)
    {
        const ks::process::ProcessRecord& processRecord = cachePair.second.record;
        const auto kPidIt = processRecordByPid.find(processRecord.pid);
        if (kPidIt == processRecordByPid.end())
        {
            processRecordByPid.emplace(processRecord.pid, &processRecord);
            continue;
        }

        // Select the entry with a non-empty imagePath to improve the process icon hit rate on the thread tab.
        if (kPidIt->second != nullptr &&
            kPidIt->second->imagePath.empty() &&
            !processRecord.imagePath.empty())
        {
            processRecordByPid[processRecord.pid] = &processRecord;
        }
    }

    // Build the thread list line by line:
    // - Filter by search term first;
    // - Then populate text and icons.
    // - Finally write TID/PID to UserRole for right-click actions to read.
    for (const ks::process::SystemThreadRecord& threadRecord : threadRecordList_)
    {
        if (!threadRecordMatchesScope(threadRecord) || !threadRecordMatchesSearch(threadRecord))
        {
            continue;
        }

        const auto kProcessIt = processRecordByPid.find(threadRecord.ownerPid);

        QTreeWidgetItem* rowItem = new QTreeWidgetItem();
        for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::kCount); ++columnIndex)
        {
            const ThreadTableColumn kColumn = static_cast<ThreadTableColumn>(columnIndex);
            rowItem->setText(columnIndex, formatThreadColumnText(threadRecord, kColumn));
        }

        // Process column icons: prioritize the imagePath from the process cache to ensure icon reuse for the same process.
        ks::process::ProcessRecord iconSourceRecord{};
        if (kProcessIt != processRecordByPid.end() && kProcessIt->second != nullptr)
        {
            iconSourceRecord = *(kProcessIt->second);
            if (threadRecord.ownerProcessName.empty() || threadRecord.ownerProcessName == "Unknown")
            {
                rowItem->setText(
                    toThreadColumnIndex(ThreadTableColumn::kProcessName),
                    QString::fromStdString(iconSourceRecord.processName.empty() ? "Unknown" : iconSourceRecord.processName));
            }
        }
        else
        {
            iconSourceRecord.pid = threadRecord.ownerPid;
            iconSourceRecord.processName = threadRecord.ownerProcessName;
        }
        rowItem->setIcon(toThreadColumnIndex(ThreadTableColumn::kProcessName), resolveProcessIcon(iconSourceRecord));

        rowItem->setData(
            toThreadColumnIndex(ThreadTableColumn::kThreadId),
            Qt::UserRole,
            QVariant::fromValue(static_cast<qulonglong>(threadRecord.threadId)));
        rowItem->setData(
            toThreadColumnIndex(ThreadTableColumn::kThreadId),
            Qt::UserRole + 1,
            QVariant::fromValue(static_cast<qulonglong>(threadRecord.ownerPid)));
        rowItem->setToolTip(
            toThreadColumnIndex(ThreadTableColumn::kThreadR0Status),
            threadR0DiagnosticText(threadRecord));

        // R0-only threads are highlighted in red; terminated threads are highlighted in gray; both affect display only.
        if (threadRecord.isR0OnlyThread ||
            (threadRecord.r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST) != 0U)
        {
            const QColor kSuspectForeground = ksword_theme::errorColor();
            const QColor kSuspectBackground = ksword_theme::withAlpha(
                ksword_theme::errorBackgroundColor(),
                ksword_theme::isDarkModeEnabled() ? 140 : 255);
            for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::kCount); ++columnIndex)
            {
                rowItem->setForeground(columnIndex, QBrush(kSuspectForeground));
                rowItem->setBackground(columnIndex, QBrush(kSuspectBackground));
            }
        }
        else if (threadRecord.threadState == 4)
        {
            for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::kCount); ++columnIndex)
            {
                rowItem->setForeground(columnIndex, QBrush(ksword_theme::exitedRowForegroundColor()));
            }
        }

        threadTable_->addTopLevelItem(rowItem);
    }

    threadTable_->setSortingEnabled(true);
    threadTable_->sortItems(toThreadColumnIndex(ThreadTableColumn::kOwnerPid), Qt::AscendingOrder);
}

QString ProcessDock::formatThreadColumnText(
    const ks::process::SystemThreadRecord& threadRecord,
    const ThreadTableColumn column) const
{
    switch (column)
    {
    case ThreadTableColumn::kThreadId:
        return QString::number(threadRecord.threadId);
    case ThreadTableColumn::kOwnerPid:
        return QString::number(threadRecord.ownerPid);
    case ThreadTableColumn::kProcessName:
        return QString::fromStdString(threadRecord.ownerProcessName.empty() ? "Unknown" : threadRecord.ownerProcessName);
    case ThreadTableColumn::kThreadClass:
        return threadClassText(threadRecord);
    case ThreadTableColumn::kStartAddress:
        return hexPointerText(threadRecord.startAddress, false);
    case ThreadTableColumn::kWin32StartAddress:
        return hexPointerText(threadRecord.win32StartAddress, true);
    case ThreadTableColumn::kTebBaseAddress:
        return hexPointerText(threadRecord.tebBaseAddress, true);
    case ThreadTableColumn::kUserStackBase:
        return hexPointerText(threadRecord.stackBase, true);
    case ThreadTableColumn::kUserStackLimit:
        return hexPointerText(threadRecord.stackLimit, true);
    case ThreadTableColumn::kKernelStack:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_KERNEL_STACK_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return hexPointerText(threadRecord.r0KernelStack, true);
    case ThreadTableColumn::kKStackBase:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_STACK_BASE_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return hexPointerText(threadRecord.r0StackBase, true);
    case ThreadTableColumn::kKStackLimit:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_STACK_LIMIT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return hexPointerText(threadRecord.r0StackLimit, true);
    case ThreadTableColumn::kInitialStack:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_INITIAL_STACK_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return hexPointerText(threadRecord.r0InitialStack, true);
    case ThreadTableColumn::kReadOps:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_READ_OPERATION_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0ReadOperationCount));
    case ThreadTableColumn::kWriteOps:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_WRITE_OPERATION_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0WriteOperationCount));
    case ThreadTableColumn::kOtherOps:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_OTHER_OPERATION_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0OtherOperationCount));
    case ThreadTableColumn::kReadBytes:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_READ_TRANSFER_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0ReadTransferCount));
    case ThreadTableColumn::kWriteBytes:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_WRITE_TRANSFER_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0WriteTransferCount));
    case ThreadTableColumn::kOtherBytes:
        if ((threadRecord.r0ThreadFieldFlags & KSWORD_ARK_THREAD_FIELD_OTHER_TRANSFER_COUNT_PRESENT) == 0U)
        {
            return QStringLiteral("Unavailable");
        }
        return QString::number(static_cast<qulonglong>(threadRecord.r0OtherTransferCount));
    case ThreadTableColumn::kThreadR0Status:
        return threadR0CrossViewStatusText(threadRecord);
    case ThreadTableColumn::kPriority:
        if (threadRecord.priority == std::numeric_limits<int>::min())
        {
            return QStringLiteral("N/A");
        }
        return QString::number(threadRecord.priority);
    case ThreadTableColumn::kBasePriority:
        if (threadRecord.basePriority == std::numeric_limits<int>::min())
        {
            return QStringLiteral("N/A");
        }
        return QString::number(threadRecord.basePriority);
    case ThreadTableColumn::kThreadState:
        return threadStateText(threadRecord.threadState);
    case ThreadTableColumn::kWaitReason:
        return threadWaitReasonText(threadRecord.waitReason);
    case ThreadTableColumn::kKernelTimeMs:
        return QString::number(static_cast<double>(threadRecord.kernelTime100ns) / 10000.0, 'f', 2);
    case ThreadTableColumn::kUserTimeMs:
        return QString::number(static_cast<double>(threadRecord.userTime100ns) / 10000.0, 'f', 2);
    case ThreadTableColumn::kCpuTimeMs:
        return QString::number(
            static_cast<double>(threadRecord.kernelTime100ns + threadRecord.userTime100ns) / 10000.0,
            'f',
            2);
    case ThreadTableColumn::kWaitTimeTick:
        return QString::number(threadRecord.waitTimeTick);
    case ThreadTableColumn::kContextSwitches:
        return QString::number(threadRecord.contextSwitchCount);
    case ThreadTableColumn::kCreateTime:
        if (threadRecord.createTime100ns == 0)
        {
            return QStringLiteral("-");
        }
        return QString::fromStdString(ks::str::fileTime100nsToLocalText(threadRecord.createTime100ns));
    case ThreadTableColumn::kProcessPath:
    {
        for (const auto& cachePair : cacheByIdentity_)
        {
            if (cachePair.second.record.pid == threadRecord.ownerPid &&
                !cachePair.second.record.imagePath.empty())
            {
                return QString::fromStdString(cachePair.second.record.imagePath);
            }
        }
        return QStringLiteral("-");
    }
    case ThreadTableColumn::kCpuPercent:
        return threadRecord.cpuUsageReady
            ? QString::number(threadRecord.cpuPercent, 'f', 2) + QStringLiteral("%")
            : QStringLiteral("-");
    default:
        return QString();
    }
}

QString ProcessDock::threadStateText(const std::uint32_t stateValue) const
{
    if (stateValue == std::numeric_limits<std::uint32_t>::max())
    {
        return QStringLiteral("N/A");
    }

    switch (stateValue)
    {
    case 0: return QStringLiteral("Initialized(0)");
    case 1: return QStringLiteral("Ready(1)");
    case 2: return QStringLiteral("Running(2)");
    case 3: return QStringLiteral("Standby(3)");
    case 4: return QStringLiteral("Terminated(4)");
    case 5: return QStringLiteral("Waiting(5)");
    case 6: return QStringLiteral("Transition(6)");
    case 7: return QStringLiteral("DeferredReady(7)");
    case 8: return QStringLiteral("GateWait(8)");
    case 9: return QStringLiteral("WaitingForProcessInSwap(9)");
    default:
        return QString("Unknown(%1)").arg(stateValue);
    }
}

QString ProcessDock::threadWaitReasonText(const std::uint32_t waitReasonValue) const
{
    if (waitReasonValue == std::numeric_limits<std::uint32_t>::max())
    {
        return QStringLiteral("N/A");
    }

    switch (waitReasonValue)
    {
    case 0: return QStringLiteral("Executive(0)");
    case 1: return QStringLiteral("FreePage(1)");
    case 2: return QStringLiteral("PageIn(2)");
    case 3: return QStringLiteral("PoolAllocation(3)");
    case 4: return QStringLiteral("DelayExecution(4)");
    case 5: return QStringLiteral("Suspended(5)");
    case 6: return QStringLiteral("UserRequest(6)");
    case 7: return QStringLiteral("WrExecutive(7)");
    case 8: return QStringLiteral("WrFreePage(8)");
    case 9: return QStringLiteral("WrPageIn(9)");
    case 10: return QStringLiteral("WrPoolAllocation(10)");
    case 11: return QStringLiteral("WrDelayExecution(11)");
    case 12: return QStringLiteral("WrSuspended(12)");
    case 13: return QStringLiteral("WrUserRequest(13)");
    case 14: return QStringLiteral("WrEventPair(14)");
    case 15: return QStringLiteral("WrQueue(15)");
    case 16: return QStringLiteral("WrLpcReceive(16)");
    case 17: return QStringLiteral("WrLpcReply(17)");
    case 18: return QStringLiteral("WrVirtualMemory(18)");
    case 19: return QStringLiteral("WrPageOut(19)");
    case 20: return QStringLiteral("WrRendezvous(20)");
    case 21: return QStringLiteral("Spare2(21)");
    case 22: return QStringLiteral("Spare3(22)");
    case 23: return QStringLiteral("Spare4(23)");
    case 24: return QStringLiteral("Spare5(24)");
    case 25: return QStringLiteral("WrCalloutStack(25)");
    case 26: return QStringLiteral("WrKernel(26)");
    case 27: return QStringLiteral("WrResource(27)");
    case 28: return QStringLiteral("WrPushLock(28)");
    case 29: return QStringLiteral("WrMutex(29)");
    case 30: return QStringLiteral("WrQuantumEnd(30)");
    case 31: return QStringLiteral("WrDispatchInt(31)");
    case 32: return QStringLiteral("WrPreempted(32)");
    case 33: return QStringLiteral("WrYieldExecution(33)");
    case 34: return QStringLiteral("WrFastMutex(34)");
    case 35: return QStringLiteral("WrGuardedMutex(35)");
    case 36: return QStringLiteral("WrRundown(36)");
    case 37: return QStringLiteral("WrAlertByThreadId(37)");
    case 38: return QStringLiteral("WrDeferredPreempt(38)");
    case 39: return QStringLiteral("WrPhysicalFault(39)");
    case 40: return QStringLiteral("WrIoRing(40)");
    case 41: return QStringLiteral("WrMdlCache(41)");
    case 42: return QStringLiteral("WrRcu(42)");
    default:
        return QString("Unknown(%1)").arg(waitReasonValue);
    }
}

QString ProcessDock::buildThreadContextMenuStyle() const
{
    // Handle high-risk points in the right-click menu:
    // - Explicitly hardcode background and text colors for light and dark themes.
    // - Do not rely on default styles to avoid the black-on-black issue in light mode.
    const QString kMenuBackgroundColor = ksword_theme::surfaceHex();
    const QString kMenuTextColor = ksword_theme::textPrimaryHex();
    const QString kMenuBorderColor = ksword_theme::borderHex();
    const QString kMenuDisabledColor = ksword_theme::textDisabledColorHex();

    return QStringLiteral(
        "QMenu{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %3;"
        "}"
        "QMenu::item{"
        "  padding:4px 16px 4px 12px;"
        "  background:transparent;"
        "}"
        "QMenu::item:selected{"
        "  background:%4;"
        "  color:%6;"
        "}"
        "QMenu::item:disabled{"
        "  color:%5;"
        "  background:transparent;"
        "}"
        "QMenu::separator{"
        "  height:1px;"
        "  background:%3;"
        "  margin:2px 6px;"
        "}")
        .arg(kMenuBackgroundColor)
        .arg(kMenuTextColor)
        .arg(kMenuBorderColor)
        .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
        .arg(kMenuDisabledColor)
        .arg(ksword_theme::onAccentDynamicHex());
}

void ProcessDock::bindThreadContextActionToItem(QTreeWidgetItem* clickedItem)
{
    clearThreadContextActionBinding();
    if (clickedItem == nullptr)
    {
        return;
    }

    threadContextActionTid_ = clickedItem->data(
        toThreadColumnIndex(ThreadTableColumn::kThreadId),
        Qt::UserRole).toULongLong();
    threadContextActionPid_ = clickedItem->data(
        toThreadColumnIndex(ThreadTableColumn::kThreadId),
        Qt::UserRole + 1).toULongLong();
}

void ProcessDock::clearThreadContextActionBinding()
{
    threadContextActionTid_ = 0;
    threadContextActionPid_ = 0;
    threadContextMenuVisible_ = false;
}

const ks::process::SystemThreadRecord* ProcessDock::selectedThreadRecord() const
{
    std::uint32_t targetTid = threadContextActionTid_;
    std::uint32_t targetPid = threadContextActionPid_;

    // If the right-click binding is empty, fall back to the currently selected row (this path is taken when triggered by keyboard).
    if ((targetTid == 0 || targetPid == 0) && threadTable_ != nullptr)
    {
        QTreeWidgetItem* currentItem = threadTable_->currentItem();
        if (currentItem != nullptr)
        {
            targetTid = currentItem->data(
                toThreadColumnIndex(ThreadTableColumn::kThreadId),
                Qt::UserRole).toULongLong();
            targetPid = currentItem->data(
                toThreadColumnIndex(ThreadTableColumn::kThreadId),
                Qt::UserRole + 1).toULongLong();
        }
    }

    if (targetTid == 0 || targetPid == 0)
    {
        return nullptr;
    }

    for (const ks::process::SystemThreadRecord& threadRecord : threadRecordList_)
    {
        if (threadRecord.threadId == targetTid && threadRecord.ownerPid == targetPid)
        {
            return &threadRecord;
        }
    }
    return nullptr;
}

void ProcessDock::showThreadTableContextMenu(const QPoint& localPosition)
{
    if (threadTable_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* clickedItem = threadTable_->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        clearThreadContextActionBinding();
        return;
    }

    threadTable_->setCurrentItem(clickedItem);
    const int kClickedColumn = threadTable_->columnAt(localPosition.x());
    if (kClickedColumn >= 0)
    {
        threadTable_->setCurrentItem(clickedItem, kClickedColumn);
    }
    bindThreadContextActionToItem(clickedItem);

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(buildThreadContextMenuStyle());

    QAction* copyCellAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_copy_cell.svg"),
        "复制单元格");
    QAction* copyRowAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_copy_row.svg"),
        "复制行");
    contextMenu.addSeparator();
    QAction* detailAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_details.svg"),
        "转到进程详细信息");
    QAction* stackAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_threads.svg"),
        "查看调用栈");
    const ks::process::SystemThreadRecord* clickedThreadRecord = selectedThreadRecord();
    const bool kClickedThreadIsR0Only =
        clickedThreadRecord != nullptr &&
        (clickedThreadRecord->isR0OnlyThread ||
            ((clickedThreadRecord->r0ThreadFlags & KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST) != 0U));
    QMenu* const kAffinityMenu = ks::process::addThreadAffinitySubMenu(
        &contextMenu,
        blueTintedIcon(":/Icon/process_priority.svg"),
        clickedThreadRecord != nullptr ? clickedThreadRecord->ownerPid : 0U,
        clickedThreadRecord != nullptr ? clickedThreadRecord->threadId : 0U,
        clickedThreadRecord != nullptr ? clickedThreadRecord->createTime100ns : 0U,
        buildThreadContextMenuStyle(),
        [this](const bool actionOk, const QString& resultText)
        {
            KLogEvent actionEvent;
            (actionOk ? info : err) << actionEvent
                << "[ProcessDock] thread affinity update: actionOk="
                << (actionOk ? "true" : "false")
                << ", detail="
                << resultText.toStdString()
                << eol;
            showActionResultMessage(
                ks::i18n::contextText(
                    QStringLiteral("process.thread.menu.affinity"),
                    QStringLiteral("线程亲和性")),
                actionOk,
                resultText.toStdString(),
                actionEvent);
            requestAsyncThreadRefresh(true);
        });
    QAction* suspendAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_suspend.svg"),
        "挂起线程");
    QAction* resumeAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_resume.svg"),
        "恢复线程");
    QAction* r0SuspendThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_suspend.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.r0_suspend"),
            QStringLiteral("R0挂起线程")));
    QAction* r0ResumeThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_resume.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.r0_resume"),
            QStringLiteral("R0恢复线程")));
    QAction* suspendDriverThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_suspend.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_suspend"),
            QStringLiteral("ZwSuspendThread / NtSuspendThread（实验性）")));
    QAction* resumeDriverThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_resume.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_resume"),
            QStringLiteral("ZwResumeThread / NtResumeThread（实验性）")));
    QMenu* terminateDriverThreadMenu = contextMenu.addMenu(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate_experimental"),
            QStringLiteral("结束驱动线程（实验性原始 API）")));
    QAction* terminateDriverThreadPspAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate.psp"),
            QStringLiteral("PspTerminateThreadByPointer（实验性/未文档化）")));
    QAction* terminateDriverThreadZwAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate.zw"),
            QStringLiteral("ZwTerminateThread / NtTerminateThread（实验性）")));
    QAction* terminateDriverThreadNormalApcAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate.normal_apc"),
            QStringLiteral("KeInsertQueueApc → Normal Kernel APC → PsTerminateSystemThread（实验性）")));
    QAction* terminateDriverThreadSpecialApcAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.driver_terminate.special_apc"),
            QStringLiteral("KeInsertQueueApc → Special Kernel APC → Normal Kernel APC → PsTerminateSystemThread（实验性）")));
    terminateDriverThreadMenu->addSeparator();
    QAction* firmwareRebootAction = terminateDriverThreadMenu->addAction(
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.hal_return_to_firmware"),
            QStringLiteral("HalReturnToFirmware(HalRebootRoutine)（实验性/整机动作）")));
    QAction* terminateAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        "结束线程");
    QAction* r0TerminateThreadAction = contextMenu.addAction(
        blueTintedIcon(":/Icon/process_terminate.svg"),
        ks::i18n::contextText(
            QStringLiteral("process.thread.menu.r0_terminate"),
            QStringLiteral("R0结束线程")));

    const bool kHasR0ThreadControlTarget =
        clickedThreadRecord != nullptr &&
        clickedThreadRecord->ownerPid > 4U &&
        clickedThreadRecord->threadId != 0U;
    const bool kHasDriverThreadTarget =
        clickedThreadRecord != nullptr &&
        clickedThreadRecord->ownerPid == 4U &&
        clickedThreadRecord->threadId != 0U &&
        clickedThreadRecord->createTime100ns != 0ULL &&
        (clickedThreadRecord->startAddress != 0ULL ||
         clickedThreadRecord->win32StartAddress != 0ULL);
    r0SuspendThreadAction->setEnabled(kHasR0ThreadControlTarget);
    r0ResumeThreadAction->setEnabled(kHasR0ThreadControlTarget);
    r0TerminateThreadAction->setEnabled(kHasR0ThreadControlTarget);
    suspendDriverThreadAction->setVisible(kHasDriverThreadTarget);
    resumeDriverThreadAction->setVisible(kHasDriverThreadTarget);
    terminateDriverThreadMenu->menuAction()->setVisible(kHasDriverThreadTarget);
    if (kClickedThreadIsR0Only)
    {
        // R0-only/CID-only rows do not pass suspect TIDs to R3 for operations, but allow terminating a single thread via R0 using verified PID/TID.
        stackAction->setEnabled(false);
        suspendAction->setEnabled(false);
        resumeAction->setEnabled(false);
        terminateAction->setEnabled(false);
        stackAction->setToolTip(QStringLiteral("R0-only / hidden suspect 行只读展示，不执行线程操作。"));
        suspendAction->setToolTip(QStringLiteral("R0-only / hidden suspect 行只读展示，不执行线程操作。"));
        resumeAction->setToolTip(QStringLiteral("R0-only / hidden suspect 行只读展示，不执行线程操作。"));
        terminateAction->setToolTip(QStringLiteral("R0-only / hidden suspect 行只读展示，不执行线程操作。"));
        if (kAffinityMenu != nullptr)
        {
            kAffinityMenu->setEnabled(false);
            kAffinityMenu->setToolTip(ks::i18n::contextText(
                QStringLiteral("process.thread.menu.affinity.suspect.tooltip"),
                QStringLiteral("R0-only / hidden suspect 行不执行 R3 线程亲和性操作。")));
        }
        const QString kR0ControlToolTip = ks::i18n::contextText(
            QStringLiteral("process.thread.r0_control.suspect.tooltip"),
            QStringLiteral("R0-only / hidden suspect 行可按 TID/PID 通过 R0 挂起或恢复指定线程。"));
        r0SuspendThreadAction->setToolTip(kR0ControlToolTip);
        r0ResumeThreadAction->setToolTip(kR0ControlToolTip);
        r0TerminateThreadAction->setToolTip(
            ks::i18n::contextText(
                QStringLiteral("process.thread.r0_terminate.suspect.tooltip"),
                QStringLiteral("R0-only / hidden suspect 行可按 TID/PID 结束指定线程。")));
    }

    threadContextMenuVisible_ = true;
    QAction* selectedAction = contextMenu.exec(threadTable_->viewport()->mapToGlobal(localPosition));
    threadContextMenuVisible_ = false;
    if (selectedAction == nullptr)
    {
        clearThreadContextActionBinding();
        return;
    }

    {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 线程右键菜单执行动作: " << selectedAction->text().toStdString()
            << eol;
    }

    if (selectedAction == copyCellAction) { copyCurrentThreadCell(); }
    else if (selectedAction == copyRowAction) { copyCurrentThreadRow(); }
    else if (selectedAction == detailAction) { openThreadOwnerProcessDetails(); }
    else if (selectedAction == stackAction) { openThreadStackWindow(); }
    else if (selectedAction == suspendAction) { executeSuspendThreadAction(); }
    else if (selectedAction == resumeAction) { executeResumeThreadAction(); }
    else if (selectedAction == r0SuspendThreadAction) { executeR0SuspendThreadAction(); }
    else if (selectedAction == r0ResumeThreadAction) { executeR0ResumeThreadAction(); }
    else if (selectedAction == suspendDriverThreadAction) { executeSuspendDriverThreadAction(); }
    else if (selectedAction == resumeDriverThreadAction) { executeResumeDriverThreadAction(); }
    else if (selectedAction == terminateDriverThreadPspAction) { executeTerminateDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER); }
    else if (selectedAction == terminateDriverThreadZwAction) { executeTerminateDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT); }
    else if (selectedAction == terminateDriverThreadNormalApcAction) { executeTerminateDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC); }
    else if (selectedAction == terminateDriverThreadSpecialApcAction) { executeTerminateDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC); }
    else if (selectedAction == firmwareRebootAction) { executeExperimentalFirmwareRebootAction(); }
    else if (selectedAction == terminateAction) { executeTerminateThreadAction(); }
    else if (selectedAction == r0TerminateThreadAction) { executeR0TerminateThreadAction(); }

    clearThreadContextActionBinding();
}

void ProcessDock::copyCurrentThreadCell()
{
    if (threadTable_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* currentItem = threadTable_->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }

    const int kCurrentColumn = threadTable_->currentColumn();
    if (kCurrentColumn < 0)
    {
        return;
    }

    QApplication::clipboard()->setText(currentItem->text(kCurrentColumn));
}

void ProcessDock::copyCurrentThreadRow()
{
    if (threadTable_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* currentItem = threadTable_->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }

    QStringList rowFields;
    rowFields.reserve(static_cast<int>(ThreadTableColumn::kCount));
    for (int columnIndex = 0; columnIndex < static_cast<int>(ThreadTableColumn::kCount); ++columnIndex)
    {
        rowFields.push_back(currentItem->text(columnIndex));
    }
    QApplication::clipboard()->setText(rowFields.join("\t"));
}

void ProcessDock::openThreadOwnerProcessDetails()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    KLogEvent actionEvent;
    if (threadRecord->ownerPid == 0)
    {
        const std::string kDetailText = "当前线程没有可用的所属进程 PID。";
        warn << actionEvent << "[ProcessDock] openThreadOwnerProcessDetails: ownerPid=0" << eol;
        showActionResultMessage("转到进程详细信息", false, kDetailText, actionEvent);
        return;
    }

    info << actionEvent
        << "[ProcessDock] openThreadOwnerProcessDetails: pid=" << threadRecord->ownerPid
        << ", tid=" << threadRecord->threadId
        << eol;
    openProcessDetailWindowByPid(threadRecord->ownerPid);
}

void ProcessDock::openThreadStackWindow()
{
    // Phase-8 call stack entry:
    // - Constructs a ThreadStackTarget from the current thread row.
    // - The user-mode call stack is captured by ThreadStackWindow.
    // - R0 KTHREAD fields are used solely for kernel stack boundary diagnostics display.
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    ThreadStackTarget target{};
    target.processId = threadRecord->ownerPid;
    target.threadId = threadRecord->threadId;
    target.processName = QString::fromStdString(threadRecord->ownerProcessName);
    target.startAddress = threadRecord->startAddress;
    target.win32StartAddress = threadRecord->win32StartAddress;
    target.tebBaseAddress = threadRecord->tebBaseAddress;
    target.userStackBase = threadRecord->stackBase;
    target.userStackLimit = threadRecord->stackLimit;
    target.r0KernelStack = threadRecord->r0KernelStack;
    target.r0StackBase = threadRecord->r0StackBase;
    target.r0StackLimit = threadRecord->r0StackLimit;
    target.r0InitialStack = threadRecord->r0InitialStack;
    target.r0ThreadStatus = threadRecord->r0ThreadStatus;
    target.r0CapabilityMask = threadRecord->r0ThreadDynDataCapabilityMask;

    for (const auto& cachePair : cacheByIdentity_)
    {
        if (cachePair.second.record.pid == threadRecord->ownerPid &&
            !cachePair.second.record.imagePath.empty())
        {
            target.processPath = QString::fromStdString(cachePair.second.record.imagePath);
            break;
        }
    }

    auto* stackWindow = new ThreadStackWindow(target, this);
    stackWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    stackWindow->show();
    stackWindow->raise();
    stackWindow->activateWindow();

    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDock] openThreadStackWindow: pid=" << target.processId
        << ", tid=" << target.threadId
        << eol;
}

void ProcessDock::executeSuspendThreadAction()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    KLogEvent actionEvent;
    std::string detailText;
    const bool kActionOk = ks::process::suspendThreadIfIdentityMatches(
        threadRecord->threadId,
        threadRecord->ownerPid,
        threadRecord->createTime100ns,
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDock] executeSuspendThreadAction: tid=" << threadRecord->threadId
        << ", actionOk=" << (kActionOk ? "true" : "false")
        << eol;
    showActionResultMessage("挂起线程", kActionOk, detailText, actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeResumeThreadAction()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    KLogEvent actionEvent;
    std::string detailText;
    const bool kActionOk = ks::process::resumeThreadIfIdentityMatches(
        threadRecord->threadId,
        threadRecord->ownerPid,
        threadRecord->createTime100ns,
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDock] executeResumeThreadAction: tid=" << threadRecord->threadId
        << ", actionOk=" << (kActionOk ? "true" : "false")
        << eol;
    showActionResultMessage("恢复线程", kActionOk, detailText, actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeR0SuspendThreadAction()
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid <= 4U ||
        selectedThread->threadId == 0U)
    {
        return;
    }
    const ks::process::SystemThreadRecord kThreadRecord = *selectedThread;

    const QMessageBox::StandardButton kConfirmation = QMessageBox::warning(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.confirm.title"),
            QStringLiteral("R0挂起线程")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.confirm.body"),
            QStringLiteral("将通过 R0 挂起 PID %2 的线程 %1。目标程序可能失去响应，是否继续？"))
            .arg(kThreadRecord.threadId)
            .arg(kThreadRecord.ownerPid),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmation != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.setThreadSuspended(
        kThreadRecord.threadId,
        kThreadRecord.ownerPid,
        true);
    const std::string kDetailText = threadIoMessageStdString(kResult.message);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDock] executeR0SuspendThreadAction: pid="
        << kThreadRecord.ownerPid
        << ", tid="
        << kThreadRecord.threadId
        << ", actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail="
        << kDetailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_suspend.result.title"),
            QStringLiteral("R0挂起线程")),
        kResult.ok,
        kDetailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeR0ResumeThreadAction()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr || threadRecord->ownerPid <= 4U || threadRecord->threadId == 0U)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.setThreadSuspended(
        threadRecord->threadId,
        threadRecord->ownerPid,
        false);
    const std::string kDetailText = threadIoMessageStdString(kResult.message);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDock] executeR0ResumeThreadAction: pid="
        << threadRecord->ownerPid
        << ", tid="
        << threadRecord->threadId
        << ", actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail="
        << kDetailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_resume.result.title"),
            QStringLiteral("R0恢复线程")),
        kResult.ok,
        kDetailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeSuspendDriverThreadAction()
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid != 4U ||
        selectedThread->threadId == 0U || selectedThread->createTime100ns == 0ULL)
    {
        return;
    }
    // QMessageBox::critical enters a nested event loop. Preserve the complete
    // identity before opening it so an async table refresh cannot invalidate
    // the selected m_threadRecordList element or replace the requested target.
    const ks::process::SystemThreadRecord kThreadRecord = *selectedThread;
    const std::uint64_t kStartAddress = kThreadRecord.startAddress != 0ULL
        ? kThreadRecord.startAddress
        : kThreadRecord.win32StartAddress;
    if (kStartAddress == 0ULL)
    {
        return;
    }

    const QMessageBox::StandardButton kConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_suspend.confirm.title"),
            QStringLiteral("挂起驱动线程")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_suspend.confirm.body"),
            QStringLiteral("即将挂起 System(PID 4) 的驱动线程 %1。此操作可能冻结磁盘、网络或安全组件，并可能导致系统死锁或蓝屏。仅在已保存工作且可强制重启时继续。"))
            .arg(kThreadRecord.threadId),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmation != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.controlDriverThread(
        kThreadRecord.threadId,
        kStartAddress,
        kThreadRecord.createTime100ns,
        KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND,
        KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE,
        true);
    const std::string kDetailText = threadIoMessageStdString(kResult.message);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDock] executeSuspendDriverThreadAction: tid=" << kThreadRecord.threadId
        << ", start=0x" << std::hex << kStartAddress << std::dec
        << ", actionOk=" << (kResult.ok ? "true" : "false")
        << ", detail=" << kDetailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_suspend.result.title"),
            QStringLiteral("挂起驱动线程")),
        kResult.ok,
        kDetailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeResumeDriverThreadAction()
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid != 4U ||
        selectedThread->threadId == 0U || selectedThread->createTime100ns == 0ULL)
    {
        return;
    }
    const ks::process::SystemThreadRecord kThreadRecord = *selectedThread;
    const std::uint64_t kStartAddress = kThreadRecord.startAddress != 0ULL
        ? kThreadRecord.startAddress
        : kThreadRecord.win32StartAddress;
    if (kStartAddress == 0ULL)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.controlDriverThread(
        kThreadRecord.threadId,
        kStartAddress,
        kThreadRecord.createTime100ns,
        KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME,
        KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE,
        false);
    const std::string kDetailText = threadIoMessageStdString(kResult.message);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDock] executeResumeDriverThreadAction: tid=" << kThreadRecord.threadId
        << ", start=0x" << std::hex << kStartAddress << std::dec
        << ", actionOk=" << (kResult.ok ? "true" : "false")
        << ", detail=" << kDetailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_resume.result.title"),
            QStringLiteral("恢复驱动线程")),
        kResult.ok,
        kDetailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeTerminateDriverThreadAction(const unsigned long terminateMethod)
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid != 4U ||
        selectedThread->threadId == 0U || selectedThread->createTime100ns == 0ULL)
    {
        return;
    }
    // Keep the identity tuple immutable while invoking the driver action.
    const ks::process::SystemThreadRecord kThreadRecord = *selectedThread;
    const std::uint64_t kStartAddress = kThreadRecord.startAddress != 0ULL
        ? kThreadRecord.startAddress
        : kThreadRecord.win32StartAddress;
    if (kStartAddress == 0ULL)
    {
        return;
    }

    switch (terminateMethod)
    {
    case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER:
    case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT:
    case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC:
    case KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC:
        break;
    default:
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.controlDriverThread(
        kThreadRecord.threadId,
        kStartAddress,
        kThreadRecord.createTime100ns,
        KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
        terminateMethod,
        true);
    const std::string kDetailText = threadIoMessageStdString(kResult.message);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDock] executeTerminateDriverThreadAction: tid=" << kThreadRecord.threadId
        << ", start=0x" << std::hex << kStartAddress << std::dec
        << ", terminateMethod=" << terminateMethod
        << ", actionOk=" << (kResult.ok ? "true" : "false")
        << ", detail=" << kDetailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.driver_terminate.result.title"),
            QStringLiteral("强制结束驱动线程")),
        kResult.ok,
        kDetailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeExperimentalFirmwareRebootAction()
{
    const QMessageBox::StandardButton kFirstConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.confirm.title"),
            QStringLiteral("HalReturnToFirmware 实验性整机动作")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.confirm.body"),
            QStringLiteral("HalReturnToFirmware(HalRebootRoutine) 不是线程终止 API，而是不受支持的整机固件返回动作。它会绕过所选线程和进程保护，可能立即重启、丢失所有未保存数据，或在当前平台失败/崩溃。是否进入最终确认？")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kFirstConfirmation != QMessageBox::Yes)
    {
        return;
    }
    const QMessageBox::StandardButton kFinalConfirmation = QMessageBox::critical(
        this,
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.final.title"),
            QStringLiteral("最终确认：立即调用原始 API")),
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.final.body"),
            QStringLiteral("最后确认：立即调用 HalReturnToFirmware(HalRebootRoutine)。成功时系统不会返回本程序。")),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kFinalConfirmation != QMessageBox::Yes)
    {
        return;
    }

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.experimentalReturnToFirmware();
    const std::string kDetailText = threadIoMessageStdString(kResult.message);
    (kResult.ok ? warn : err) << actionEvent
        << "[ProcessDock] executeExperimentalFirmwareRebootAction: actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail=" << kDetailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.hal_return.result.title"),
            QStringLiteral("HalReturnToFirmware 实验性整机动作")),
        kResult.ok,
        kDetailText,
        actionEvent);
}

void ProcessDock::executeTerminateThreadAction()
{
    const ks::process::SystemThreadRecord* threadRecord = selectedThreadRecord();
    if (threadRecord == nullptr)
    {
        return;
    }

    KLogEvent actionEvent;
    std::string detailText;
    const bool kActionOk = ks::process::terminateThreadIfIdentityMatches(
        threadRecord->threadId,
        threadRecord->ownerPid,
        threadRecord->createTime100ns,
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDock] executeTerminateThreadAction: tid=" << threadRecord->threadId
        << ", actionOk=" << (kActionOk ? "true" : "false")
        << eol;
    showActionResultMessage("结束线程", kActionOk, detailText, actionEvent);
    requestAsyncThreadRefresh(true);
}

void ProcessDock::executeR0TerminateThreadAction()
{
    const ks::process::SystemThreadRecord* selectedThread = selectedThreadRecord();
    if (selectedThread == nullptr || selectedThread->ownerPid <= 4U ||
        selectedThread->threadId == 0U)
    {
        return;
    }
    const ks::process::SystemThreadRecord kThreadRecord = *selectedThread;

    KLogEvent actionEvent;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.terminateThread(
        kThreadRecord.threadId,
        kThreadRecord.ownerPid,
        static_cast<long>(0xC0000005u));
    const std::string kDetailText = threadIoMessageStdString(kResult.message);
    (kResult.ok ? info : err) << actionEvent
        << "[ProcessDock] executeR0TerminateThreadAction: pid="
        << kThreadRecord.ownerPid
        << ", tid="
        << kThreadRecord.threadId
        << ", actionOk="
        << (kResult.ok ? "true" : "false")
        << ", detail="
        << kDetailText
        << eol;
    showActionResultMessage(
        ks::i18n::contextText(
            QStringLiteral("process.thread.r0_terminate.result.title"),
            QStringLiteral("R0结束线程")),
        kResult.ok,
        kDetailText,
        actionEvent);
    requestAsyncThreadRefresh(true);
}
