#include "SystemMemoryAuditPage.h"

#include "../internationalization/LanguageManager.h"
#include "../Theme.h"
// Table interaction and visible table base class: provide numeric sorting cells, global action bars, and frozen row/column capabilities.
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../../../shared/platform/log/Log.h"
#include "MemoryAccessBackend.h"

#include <QAbstractItemView>
#include <QHBoxLayout>
#include <QCoreApplication>
#include <QCheckBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSizePolicy>
#include <QSpinBox>
#include <QSplitter>
#include <QTableWidget>
#include <QTabWidget>
#include <QTimer>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <utility>

#pragma comment(lib, "Psapi.lib")

namespace
{
    using NtQuerySystemInformationFunction = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

    constexpr ULONG kSystemPerformanceInformation = 2;
    constexpr ULONG kSystemProcessInformation = 5;
    constexpr ULONG kSystemPoolTagInformation = 22;
    constexpr ULONG kSystemBigPoolInformation = 66;
    constexpr ULONG kSystemMemoryListInformation = 80;
    constexpr ULONG kSystemMemoryUsageInformation = 181;
    constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
    constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
    constexpr std::size_t kMaximumNativeQueryBytes = 128ULL * 1024ULL * 1024ULL;
    constexpr std::size_t kMaximumWorkingSetQueryBytes = 512ULL * 1024ULL * 1024ULL;

    struct NativeUnicodeString
    {
        USHORT length;
        USHORT maximumLength;
        PWSTR buffer;
    };

    struct NativeSystemProcessInformation
    {
        ULONG nextEntryOffset;
        ULONG numberOfThreads;
        ULONGLONG workingSetPrivateSize;
        ULONG hardFaultCount;
        ULONG numberOfThreadsHighWatermark;
        ULONGLONG cycleTime;
        LARGE_INTEGER createTime;
        LARGE_INTEGER userTime;
        LARGE_INTEGER kernelTime;
        NativeUnicodeString imageName;
        LONG basePriority;
        HANDLE uniqueProcessId;
        HANDLE inheritedFromUniqueProcessId;
        ULONG handleCount;
        ULONG sessionId;
        ULONG_PTR uniqueProcessKey;
        SIZE_T peakVirtualSize;
        SIZE_T virtualSize;
        ULONG pageFaultCount;
        SIZE_T peakWorkingSetSize;
        SIZE_T workingSetSize;
        SIZE_T quotaPeakPagedPoolUsage;
        SIZE_T quotaPagedPoolUsage;
        SIZE_T quotaPeakNonPagedPoolUsage;
        SIZE_T quotaNonPagedPoolUsage;
        SIZE_T pagefileUsage;
        SIZE_T peakPagefileUsage;
        SIZE_T privatePageCount;
        LARGE_INTEGER readOperationCount;
        LARGE_INTEGER writeOperationCount;
        LARGE_INTEGER otherOperationCount;
        LARGE_INTEGER readTransferCount;
        LARGE_INTEGER writeTransferCount;
        LARGE_INTEGER otherTransferCount;
    };

    struct NativeSystemPoolTag
    {
        union
        {
            UCHAR tag[4];
            ULONG tagUlong;
        };
        ULONG pagedAllocs;
        ULONG pagedFrees;
        SIZE_T pagedUsed;
        ULONG nonPagedAllocs;
        ULONG nonPagedFrees;
        SIZE_T nonPagedUsed;
    };

    struct NativeSystemPoolTagInformation
    {
        ULONG count;
        NativeSystemPoolTag tagInfo[1];
    };

    struct NativeSystemBigPoolEntry
    {
        ULONG_PTR virtualAddressAndFlags;
        SIZE_T sizeInBytes;
        union
        {
            UCHAR tag[4];
            ULONG tagUlong;
        };
    };

    struct NativeSystemBigPoolInformation
    {
        ULONG count;
        NativeSystemBigPoolEntry allocatedInfo[1];
    };

    struct NativeSystemMemoryListInformation
    {
        SIZE_T zeroPageCount;
        SIZE_T freePageCount;
        SIZE_T modifiedPageCount;
        SIZE_T modifiedNoWritePageCount;
        SIZE_T badPageCount;
        SIZE_T pageCountByPriority[8];
        SIZE_T repurposedPagesByPriority[8];
        SIZE_T modifiedPageCountPageFile;
    };

    struct NativeSystemMemoryUsageInformation
    {
        ULONGLONG totalPhysicalBytes;
        ULONGLONG availableBytes;
        LONGLONG residentAvailableBytes;
        ULONGLONG committedBytes;
        ULONGLONG sharedCommittedBytes;
        ULONGLONG commitLimitBytes;
        ULONGLONG peakCommitmentBytes;
    };

    // This layout is stable through ResidentSystemDriverPage. Newer optional fields
    // are read only when NtQuerySystemInformation reports enough returned bytes.
    // Reference: System Informer PHNT ntexapi.h, SYSTEM_PERFORMANCE_INFORMATION.
    struct NativeSystemPerformanceInformation
    {
        LARGE_INTEGER idleProcessTime;
        LARGE_INTEGER ioReadTransferCount;
        LARGE_INTEGER ioWriteTransferCount;
        LARGE_INTEGER ioOtherTransferCount;
        ULONG ioReadOperationCount;
        ULONG ioWriteOperationCount;
        ULONG ioOtherOperationCount;
        ULONG availablePages;
        ULONG committedPages;
        ULONG commitLimit;
        ULONG peakCommitment;
        ULONG pageFaultCount;
        ULONG copyOnWriteCount;
        ULONG transitionCount;
        ULONG cacheTransitionCount;
        ULONG demandZeroCount;
        ULONG pageReadCount;
        ULONG pageReadIoCount;
        ULONG cacheReadCount;
        ULONG cacheIoCount;
        ULONG dirtyPagesWriteCount;
        ULONG dirtyWriteIoCount;
        ULONG mappedPagesWriteCount;
        ULONG mappedWriteIoCount;
        ULONG pagedPoolPages;
        ULONG nonPagedPoolPages;
        ULONG pagedPoolAllocs;
        ULONG pagedPoolFrees;
        ULONG nonPagedPoolAllocs;
        ULONG nonPagedPoolFrees;
        ULONG freeSystemPtes;
        ULONG residentSystemCodePage;
        ULONG totalSystemDriverPages;
        ULONG totalSystemCodePages;
        ULONG nonPagedPoolLookasideHits;
        ULONG pagedPoolLookasideHits;
        ULONG availablePagedPoolPages;
        ULONG residentSystemCachePage;
        ULONG residentPagedPoolPage;
        ULONG residentSystemDriverPage;
        ULONG ccFastReadNoWait;
        ULONG ccFastReadWait;
        ULONG ccFastReadResourceMiss;
        ULONG ccFastReadNotPossible;
        ULONG ccFastMdlReadNoWait;
        ULONG ccFastMdlReadWait;
        ULONG ccFastMdlReadResourceMiss;
        ULONG ccFastMdlReadNotPossible;
        ULONG ccMapDataNoWait;
        ULONG ccMapDataWait;
        ULONG ccMapDataNoWaitMiss;
        ULONG ccMapDataWaitMiss;
        ULONG ccPinMappedDataCount;
        ULONG ccPinReadNoWait;
        ULONG ccPinReadWait;
        ULONG ccPinReadNoWaitMiss;
        ULONG ccPinReadWaitMiss;
        ULONG ccCopyReadNoWait;
        ULONG ccCopyReadWait;
        ULONG ccCopyReadNoWaitMiss;
        ULONG ccCopyReadWaitMiss;
        ULONG ccMdlReadNoWait;
        ULONG ccMdlReadWait;
        ULONG ccMdlReadNoWaitMiss;
        ULONG ccMdlReadWaitMiss;
        ULONG ccReadAheadIos;
        ULONG ccLazyWriteIos;
        ULONG ccLazyWritePages;
        ULONG ccDataFlushes;
        ULONG ccDataPages;
        ULONG contextSwitches;
        ULONG firstLevelTbFills;
        ULONG secondLevelTbFills;
        ULONG systemCalls;
        ULONGLONG ccTotalDirtyPages;
        ULONGLONG ccDirtyPageThreshold;
        LONGLONG residentAvailablePages;
        ULONGLONG sharedCommittedPages;
        ULONGLONG mdlPagesAllocated;
        ULONGLONG pfnDatabaseCommittedPages;
        ULONGLONG systemPageTableCommittedPages;
        ULONGLONG contiguousPagesAllocated;
    };

    // SummaryTileTitle:
    // - Describe the objectName and English source text for the upper subtitle of a summary tile;
    // - objectName is used to re-lookup and re-translate after language switching (findChild); the title is a local control and does not occupy a member variable.
    // - sourceText is passed to localized() to utilize source_translations from the language pack.
    struct SummaryTileTitle
    {
        const char* objectName;
        const char* sourceText;
    };

    // kSummaryTileTitles:
    // - Provide titles for 6 summary tiles in grid layout order;
    // - Order must strictly correspond to the numeric label array in initializeUi; otherwise, titles will be misaligned.
    // - Build and re-translation share the same table to avoid inconsistent wording.
    constexpr std::array<SummaryTileTitle, 6> kSummaryTileTitles{ {
        { "kswordMemoryAuditTileTitleInstalled", "Installed RAM" },
        { "kswordMemoryAuditTileTitleUsable", "Windows usable" },
        { "kswordMemoryAuditTileTitleInUse", "In use" },
        { "kswordMemoryAuditTileTitleAvailable", "Available" },
        { "kswordMemoryAuditTileTitleCommit", "Commit" },
        { "kswordMemoryAuditTileTitleUnattributed", "Unattributed" }
    } };

    // summaryTileObjectName:
    // - Returns the objectName used uniformly for the summary card shell.
    // - Takes no parameters; the return value is used by both the stylesheet selector and findChildren, ensuring consistency in both locations.
    QString summaryTileObjectName()
    {
        return QStringLiteral("kswordMemoryAuditSummaryTile");
    }

    NtQuerySystemInformationFunction resolveNtQuerySystemInformation()
    {
        static const auto kFunction = reinterpret_cast<NtQuerySystemInformationFunction>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
        return kFunction;
    }

    bool nativeSuccess(const LONG status)
    {
        return status >= 0;
    }

    QString statusHex(const LONG status)
    {
        return QStringLiteral("0x%1").arg(static_cast<quint32>(status), 8, 16, QLatin1Char('0')).toUpper();
    }

    bool queryVariableSystemInformation(
        const NtQuerySystemInformationFunction queryFunction,
        const ULONG informationClass,
        std::vector<std::byte>& bufferOut,
        LONG& statusOut)
    {
        bufferOut.clear();
        if (queryFunction == nullptr)
        {
            statusOut = static_cast<LONG>(0xC0000002UL);
            return false;
        }

        ULONG requiredBytes = 0;
        statusOut = queryFunction(informationClass, nullptr, 0, &requiredBytes);
        std::size_t bufferBytes = std::max<std::size_t>(requiredBytes, 64ULL * 1024ULL);
        for (int attempt = 0; attempt < 8 && bufferBytes <= kMaximumNativeQueryBytes; ++attempt)
        {
            bufferOut.assign(bufferBytes, std::byte{});
            ULONG returnedBytes = 0;
            statusOut = queryFunction(
                informationClass,
                bufferOut.data(),
                static_cast<ULONG>(bufferOut.size()),
                &returnedBytes);
            if (nativeSuccess(statusOut))
            {
                if (returnedBytes > 0 && returnedBytes <= bufferOut.size())
                {
                    bufferOut.resize(returnedBytes);
                }
                return true;
            }
            if (statusOut != kStatusInfoLengthMismatch && statusOut != kStatusBufferTooSmall)
            {
                bufferOut.clear();
                return false;
            }
            const std::size_t kRequestedBytes = returnedBytes > bufferOut.size()
                ? static_cast<std::size_t>(returnedBytes)
                : bufferOut.size() * 2ULL;
            bufferBytes = std::min<std::size_t>(
                std::max<std::size_t>(kRequestedBytes, bufferOut.size() + 64ULL * 1024ULL),
                kMaximumNativeQueryBytes + 1ULL);
        }
        bufferOut.clear();
        return false;
    }

    QString printableTag(const UCHAR tag[4])
    {
        char text[5]{};
        for (int index = 0; index < 4; ++index)
        {
            const unsigned char kValue = tag[index];
            text[index] = (kValue >= 0x20 && kValue <= 0x7E) ? static_cast<char>(kValue) : '.';
        }
        return QString::fromLatin1(text, 4);
    }

    std::uint64_t multiplyPages(const std::uint64_t pages, const std::uint64_t pageSize)
    {
        if (pageSize == 0 || pages > (std::numeric_limits<std::uint64_t>::max)() / pageSize)
        {
            return (std::numeric_limits<std::uint64_t>::max)();
        }
        return pages * pageSize;
    }

    QString localized(const char* sourceText)
    {
        return ks::i18n::packedSourceText(QString::fromUtf8(sourceText));
    }

    class ScopedHandle final
    {
    public:
        explicit ScopedHandle(HANDLE handle = nullptr)
            : handle_(handle)
        {
        }

        ~ScopedHandle()
        {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle_);
            }
        }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        HANDLE get() const
        {
            return handle_;
        }

        explicit operator bool() const
        {
            return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
        }

    private:
        HANDLE handle_ = nullptr;
    };

    bool queryProcessWorkingSet(
        HANDLE processHandle,
        const std::uint64_t estimatedWorkingSetBytes,
        const std::uint64_t pageSize,
        std::vector<PSAPI_WORKING_SET_BLOCK>& blocksOut)
    {
        blocksOut.clear();
        if (processHandle == nullptr || pageSize == 0)
        {
            return false;
        }

        const std::size_t kHeaderBytes = offsetof(PSAPI_WORKING_SET_INFORMATION, WorkingSetInfo);
        const std::uint64_t kEstimatedPages = estimatedWorkingSetBytes / pageSize;
        std::size_t bufferBytes = kHeaderBytes + static_cast<std::size_t>(
            std::min<std::uint64_t>(kEstimatedPages + 2048ULL, kMaximumWorkingSetQueryBytes / sizeof(PSAPI_WORKING_SET_BLOCK)))
            * sizeof(PSAPI_WORKING_SET_BLOCK);
        bufferBytes = std::max<std::size_t>(bufferBytes, 256ULL * 1024ULL);

        for (int attempt = 0; attempt < 8 && bufferBytes <= kMaximumWorkingSetQueryBytes; ++attempt)
        {
            std::vector<std::byte> buffer(bufferBytes, std::byte{});
            if (::QueryWorkingSet(processHandle, buffer.data(), static_cast<DWORD>(buffer.size())) != FALSE)
            {
                const auto* const kInformation =
                    reinterpret_cast<const PSAPI_WORKING_SET_INFORMATION*>(buffer.data());
                const std::size_t kCapacity = (buffer.size() - kHeaderBytes) / sizeof(PSAPI_WORKING_SET_BLOCK);
                const std::size_t kCount = std::min<std::size_t>(kInformation->NumberOfEntries, kCapacity);
                blocksOut.assign(kInformation->WorkingSetInfo, kInformation->WorkingSetInfo + kCount);
                return true;
            }

            if (::GetLastError() != ERROR_BAD_LENGTH || bufferBytes == kMaximumWorkingSetQueryBytes)
            {
                return false;
            }
            bufferBytes = std::min<std::size_t>(bufferBytes * 2ULL, kMaximumWorkingSetQueryBytes);
        }
        return false;
    }

    QString mappedFilePath(HANDLE processHandle, const void* address)
    {
        std::wstring buffer(32768, L'\0');
        const DWORD kLength = ::GetMappedFileNameW(
            processHandle,
            const_cast<void*>(address),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (kLength == 0)
        {
            return {};
        }
        buffer.resize(kLength);
        QString path = QString::fromStdWString(buffer);

        static const std::vector<std::pair<QString, QString>> kDeviceMappings = []() {
            std::vector<std::pair<QString, QString>> mappings;
            for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
            {
                const wchar_t kDriveName[]{ driveLetter, L':', L'\0' };
                std::wstring deviceBuffer(32768, L'\0');
                const DWORD kDeviceLength = ::QueryDosDeviceW(
                    kDriveName,
                    deviceBuffer.data(),
                    static_cast<DWORD>(deviceBuffer.size()));
                if (kDeviceLength != 0)
                {
                    mappings.emplace_back(
                        QString::fromWCharArray(deviceBuffer.c_str()),
                        QString::fromWCharArray(kDriveName));
                }
            }
            return mappings;
        }();
        for (const auto& [devicePrefix, driveName] : kDeviceMappings)
        {
            if (path.startsWith(devicePrefix, Qt::CaseInsensitive))
            {
                path = driveName + path.mid(devicePrefix.size());
                break;
            }
        }
        return QDir::toNativeSeparators(path);
    }

    void configureTable(QTableWidget* table, const QStringList& headers)
    {
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setStretchLastSection(true);
    }

    QTableWidgetItem* textItem(const QString& text)
    {
        return new QTableWidgetItem(text);
    }

    // numericItem:
    // - Generate a cell where the display text can be arbitrary but sorting is based on the actual numeric value, suitable for Address/Size/Page Count/Count columns.
    // - Input 'text' is the UI text (hexadecimal, KiB, or MiB allowed), and 'value' is the unsigned actual value used for sorting.
    // - Returns the newly created item; ownership is transferred to the table via setItem.
    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        return new ks::ui::NumericTableItem(text, value);
    }

    // signedNumericItem:
    // - Signed version of numericItem, specifically for delta columns that can be positive or negative.
    // - Input text is the display string with sign; value is the signed actual value used for sorting.
    // - Returns the newly created cell; cannot use the unsigned overload, or negative increments would be sorted to the maximum end.
    QTableWidgetItem* signedNumericItem(const QString& text, const qlonglong value)
    {
        return new ks::ui::NumericTableItem(text, value);
    }

    void applyDeltaColor(QTableWidgetItem* item, const std::int64_t delta)
    {
        if (item == nullptr || delta == 0)
        {
            return;
        }
        item->setForeground(delta > 0
            ? ksword_theme::errorColor()
            : ksword_theme::successColor());
    }
}

SystemMemoryAuditPage::SystemMemoryAuditPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    loadPoolTagMetadata();
    initializeConnections();
    startUserResidencyScanAfterSnapshot_ = true;
    refreshSnapshot();
}

void SystemMemoryAuditPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr)
    {
        return;
    }

    // Re-applies styles dependent on tokens when the palette changes (theme switching, following system light/dark mode).
    // Incremental columns in the table use snapshot QColor values, so colors can only change by rebuilding rows; therefore, mark the data as dirty as a side effect.
    if (event->type() == QEvent::ApplicationPaletteChange ||
        event->type() == QEvent::PaletteChange)
    {
        applyThemedStyle();
        if (statusLabel_ != nullptr)
        {
            updateStatus();
        }
        if (hasSnapshot_)
        {
            overviewDirty_ = true;
            userResidencyTableDirty_ = true;
            processTableDirty_ = true;
            poolTagTableDirty_ = true;
            bigPoolTableDirty_ = true;
            scheduleCurrentDetailViewRebuild();
        }
        return;
    }

    if (event->type() != QEvent::LanguageChange)
    {
        return;
    }

    retranslateUi();
    if (hasSnapshot_)
    {
        overviewDirty_ = true;
        userResidencyTableDirty_ = true;
        processTableDirty_ = true;
        poolTagTableDirty_ = true;
        bigPoolTableDirty_ = true;
        scheduleCurrentDetailViewRebuild();
        updateDetails();
        updateStatus();
    }
}

void SystemMemoryAuditPage::initializeUi()
{
    QVBoxLayout* const kRootLayout = new QVBoxLayout(this);
    kRootLayout->setContentsMargins(6, 6, 6, 6);
    kRootLayout->setSpacing(6);

    QHBoxLayout* const kControls = new QHBoxLayout();
    // Refresh button: manual entry point for collecting a whole-machine physical memory snapshot, reusing the global refresh icon alias.
    refreshButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")), localized("Refresh snapshot"), this);
    refreshButton_->setToolTip(localized("Re-collect the whole-machine physical memory snapshot."));
    // Deep scan button: Iterating through working sets per process is a time-consuming collection operation, so use the log_track icon.
    userResidencyScanButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_track.svg")), localized("Deep scan user-mode residency"), this);
    userResidencyScanButton_->setToolTip(
        localized("Walk every accessible process working set and attribute resident pages to their backing."));
    autoRefreshCheck_ = new QCheckBox(localized("Auto refresh"), this);
    autoRefreshCheck_->setChecked(true);
    intervalSpin_ = new QSpinBox(this);
    intervalSpin_->setRange(1, 60);
    intervalSpin_->setValue(2);
    intervalSpin_->setSuffix(localized(" s"));
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(localized("Filter process, category, file, tag, or address"));
    kControls->addWidget(refreshButton_);
    kControls->addWidget(userResidencyScanButton_);
    kControls->addWidget(autoRefreshCheck_);
    kControls->addWidget(intervalSpin_);
    kControls->addSpacing(12);
    kControls->addWidget(filterEdit_, 1);
    kRootLayout->addLayout(kControls);

    QGridLayout* const kSummaryLayout = new QGridLayout();
    kSummaryLayout->setSpacing(6);
    installedLabel_ = new QLabel(this);
    totalLabel_ = new QLabel(this);
    inUseLabel_ = new QLabel(this);
    availableLabel_ = new QLabel(this);
    commitLabel_ = new QLabel(this);
    unattributedLabel_ = new QLabel(this);
    // The order of numeric labels must correspond one-to-one with kSummaryTileTitles; otherwise, titles will be attached to the wrong values.
    const std::array<QLabel*, 6> kSummaryLabels{
        installedLabel_, totalLabel_, inUseLabel_,
        availableLabel_, commitLabel_, unattributedLabel_
    };

    // buildSummaryTile:
    // - Wrap a summary cell into a card with 'upper subtitle + lower large value', replacing the original bare label with only a thin border;
    // - Input parameter valueLabel is an already created value label (reuses existing members, does not add new member variables);
    // - Input parameter titleEntry provides the objectName and English source text for the tile's subtitle.
    // - Returns a card shell ready for grid insertion; the card and its two internal rows share a unified color scheme applied via applyThemedStyle.
    const auto kBuildSummaryTile = [this](
        QLabel* const valueLabel,
        const SummaryTileTitle& titleEntry) {
        QFrame* const kTile = new QFrame(this);
        kTile->setObjectName(summaryTileObjectName());
        kTile->setFrameShape(QFrame::NoFrame);
        QVBoxLayout* const kTileLayout = new QVBoxLayout(kTile);
        // Margins are handled by the stylesheet's padding; keep this at 0 to avoid double spacing when combined with QSS.
        kTileLayout->setContentsMargins(0, 0, 0, 0);
        kTileLayout->setSpacing(2);

        QLabel* const kTitleLabel = new QLabel(localized(titleEntry.sourceText), kTile);
        kTitleLabel->setObjectName(QString::fromLatin1(titleEntry.objectName));
        valueLabel->setParent(kTile);
        valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        // The first frame has no snapshot yet; insert a short dash to prevent card height from jumping during the first refresh.
        valueLabel->setText(QStringLiteral("-"));
        kTileLayout->addWidget(kTitleLabel);
        kTileLayout->addWidget(valueLabel);
        return kTile;
    };

    for (std::size_t index = 0; index < kSummaryLabels.size(); ++index)
    {
        QFrame* const kTile = kBuildSummaryTile(kSummaryLabels[index], kSummaryTileTitles[index]);
        kSummaryLayout->addWidget(
            kTile,
            static_cast<int>(index / 3),
            static_cast<int>(index % 3));
    }
    kSummaryLayout->setColumnStretch(0, 1);
    kSummaryLayout->setColumnStretch(1, 1);
    kSummaryLayout->setColumnStretch(2, 1);
    kRootLayout->addLayout(kSummaryLayout);

    detailTabs_ = new QTabWidget(this);

    QWidget* const kOverviewPage = new QWidget(detailTabs_);
    QVBoxLayout* const kOverviewLayout = new QVBoxLayout(kOverviewPage);
    kOverviewLayout->setContentsMargins(0, 0, 0, 0);
    overviewTree_ = new QTreeWidget(kOverviewPage);
    overviewTree_->setColumnCount(6);
    overviewTree_->setHeaderLabels(QStringList{
        localized("Memory source"), localized("Bytes"), localized("RAM %"),
        localized("Delta"), localized("Accounting role"), localized("Interpretation")
    });
    overviewTree_->setRootIsDecorated(true);
    overviewTree_->setAlternatingRowColors(true);
    overviewTree_->setSelectionBehavior(QAbstractItemView::SelectRows);
    overviewTree_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    overviewTree_->header()->setStretchLastSection(true);
    kOverviewLayout->addWidget(overviewTree_);

    QWidget* const kUserResidencyPage = new QWidget(detailTabs_);
    QVBoxLayout* const kUserResidencyLayout = new QVBoxLayout(kUserResidencyPage);
    kUserResidencyLayout->setContentsMargins(0, 0, 0, 0);
    // All four tables now use VisibleTableWidget: it reserves a global action bar above the header and supports freezing rows and columns.
    userResidencyTable_ = new ks::ui::VisibleTableWidget(kUserResidencyPage);
    configureTable(userResidencyTable_, QStringList{
        localized("Process"), localized("PID"), localized("Resident kind"),
        localized("Backing / owner evidence"), localized("Resident references"),
        localized("Private resident"), localized("Shareable refs"),
        localized("Shared refs"), localized("Proportional estimate")
    });
    kUserResidencyLayout->addWidget(userResidencyTable_);

    QWidget* const kProcessPage = new QWidget(detailTabs_);
    QVBoxLayout* const kProcessLayout = new QVBoxLayout(kProcessPage);
    kProcessLayout->setContentsMargins(0, 0, 0, 0);
    processTable_ = new ks::ui::VisibleTableWidget(kProcessPage);
    configureTable(processTable_, QStringList{
        localized("Process"), localized("PID"), localized("Session"),
        localized("Private resident"), localized("Working set"), localized("Shared WS refs"),
        localized("Private commit"), localized("Paged quota"), localized("Nonpaged quota"),
        localized("Hard faults"), localized("Private delta")
    });
    kProcessLayout->addWidget(processTable_);

    QWidget* const kPoolPage = new QWidget(detailTabs_);
    QVBoxLayout* const kPoolLayout = new QVBoxLayout(kPoolPage);
    kPoolLayout->setContentsMargins(0, 0, 0, 0);
    poolTagTable_ = new ks::ui::VisibleTableWidget(kPoolPage);
    configureTable(poolTagTable_, QStringList{
        localized("Tag"), localized("Paged bytes"), localized("Nonpaged bytes"),
        localized("Total bytes"), localized("Delta"), localized("Paged outstanding"),
        localized("Nonpaged outstanding"), localized("Source"), localized("Description")
    });
    kPoolLayout->addWidget(poolTagTable_);

    QWidget* const kBigPoolPage = new QWidget(detailTabs_);
    QVBoxLayout* const kBigPoolLayout = new QVBoxLayout(kBigPoolPage);
    kBigPoolLayout->setContentsMargins(0, 0, 0, 0);
    bigPoolTable_ = new ks::ui::VisibleTableWidget(kBigPoolPage);
    configureTable(bigPoolTable_, QStringList{
        localized("Tag"), localized("Virtual address"), localized("Size"),
        localized("Pool type"), localized("Delta"), localized("Source"), localized("Description")
    });
    kBigPoolLayout->addWidget(bigPoolTable_);

    detailTabs_->addTab(kOverviewPage, localized("Physical distribution"));
    detailTabs_->addTab(kUserResidencyPage, localized("User-mode residency"));
    detailTabs_->addTab(kProcessPage, localized("Kernel process snapshot"));
    detailTabs_->addTab(kPoolPage, localized("Pool tags"));
    detailTabs_->addTab(kBigPoolPage, localized("Big Pool allocations"));
    ks::i18n::LanguageManager::instance().bindTab(
        detailTabs_, kOverviewPage, QStringLiteral("memory.audit.tab.distribution"), QStringLiteral("物理内存分布"));
    ks::i18n::LanguageManager::instance().bindTab(
        detailTabs_, kUserResidencyPage, QStringLiteral("memory.audit.tab.user_residency"), QStringLiteral("用户态驻留"));
    ks::i18n::LanguageManager::instance().bindTab(
        detailTabs_, kProcessPage, QStringLiteral("memory.audit.tab.processes"), QStringLiteral("内核进程快照"));
    ks::i18n::LanguageManager::instance().bindTab(
        detailTabs_, kPoolPage, QStringLiteral("memory.audit.tab.pool_tags"), QStringLiteral("Pool 标签"));
    ks::i18n::LanguageManager::instance().bindTab(
        detailTabs_, kBigPoolPage, QStringLiteral("memory.audit.tab.big_pool"), QStringLiteral("Big Pool 分配"));

    detailText_ = new QPlainTextEdit(this);
    detailText_->setReadOnly(true);
    detailText_->setMinimumHeight(64);

    // The details section is no longer fixed by setMaximumHeight: the Tab and description text are placed in
    // a vertical splitter, allowing users to drag the description area larger to read the full conclusion.
    QSplitter* const kDetailSplitter = new QSplitter(Qt::Vertical, this);
    kDetailSplitter->setObjectName(QStringLiteral("kswordMemoryAuditDetailSplitter"));
    kDetailSplitter->setChildrenCollapsible(false);
    kDetailSplitter->addWidget(detailTabs_);
    kDetailSplitter->addWidget(detailText_);
    kDetailSplitter->setStretchFactor(0, 3);
    kDetailSplitter->setStretchFactor(1, 2);
    // When only stretchFactor is provided without an initial value, both panes in the first frame will participate in layout allocation with a height
    // of 0 outside their sizeHint, causing the detail pane to collapse into a line; here, a set of initial sizes must be provided simultaneously.
    kDetailSplitter->setSizes(QList<int>{ 420, 160 });
    kRootLayout->addWidget(kDetailSplitter, 1);

    // DDMA verification row: This page statistics reflect 'physical memory visible via standard channels';
    // pages redirected by SLAT appear here only as unattributable residual space. Re-reading the same page
    // via DDMA is the only method within this page to directly verify 'whether this memory is hidden'.
    {
        QWidget* const kDdmaRow = new QWidget(this);
        QHBoxLayout* const kDdmaLayout = new QHBoxLayout(kDdmaRow);
        kDdmaLayout->setContentsMargins(0, 0, 0, 0);
        kDdmaLayout->setSpacing(6);

        ddmaCrossCheckAddressEdit_ = new QLineEdit(kDdmaRow);
        ddmaCrossCheckAddressEdit_->setPlaceholderText(
            localized("Physical page address, e.g. 0x1000"));
        ddmaCrossCheckAddressEdit_->setClearButtonEnabled(true);

        ddmaCrossCheckButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/file_find.svg")),
            localized("Cross-check with DDMA"),
            kDdmaRow);
        ddmaCrossCheckButton_->setEnabled(false);

        ddmaCrossCheckResultLabel_ = new QLabel(kDdmaRow);
        ddmaCrossCheckResultLabel_->setWordWrap(true);
        ddmaCrossCheckResultLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);

        kDdmaLayout->addWidget(new QLabel(localized("DDMA cross-check"), kDdmaRow));
        kDdmaLayout->addWidget(ddmaCrossCheckAddressEdit_);
        kDdmaLayout->addWidget(ddmaCrossCheckButton_);
        kDdmaLayout->addWidget(ddmaCrossCheckResultLabel_, 1);
        kRootLayout->addWidget(kDdmaRow);
    }

    statusLabel_ = new QLabel(this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setMinimumWidth(0);
    statusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    kRootLayout->addWidget(statusLabel_);

    autoRefreshTimer_ = new QTimer(this);
    autoRefreshTimer_->setInterval(intervalSpin_->value() * 1000);
    autoRefreshTimer_->start();

    // Apply the themed style for the first time; subsequent applications are triggered by the palette branch in changeEvent.
    applyThemedStyle();
}

// applyThemedStyle:
// - Centralize the application of all style tokens dependent on the theme for this page: summary card shell, card subtitles, and large numeric values.
// - Called once during construction; changeEvent re-invokes it on theme or system light/dark
//   mode switches to prevent snapshot-style colors from remaining stuck on the old theme.
// - No parameters; no return value; silently return if controls are not yet created, tolerating palette events arriving during early construction.
void SystemMemoryAuditPage::applyThemedStyle()
{
    // Card shell: base color + 1px border + 4px border-radius + 8px padding, making the 6-summary tiles look like cards rather than input fields.
    const QString kTileStyle = QStringLiteral(
        "QFrame#%1{background:%2;border:1px solid %3;border-radius:4px;padding:8px;}")
        .arg(summaryTileObjectName(), ksword_theme::surfaceAltHex(), ksword_theme::borderHex());
    const QList<QFrame*> kTiles = findChildren<QFrame*>(summaryTileObjectName());
    for (QFrame* const kTile : kTiles)
    {
        kTile->setStyleSheet(kTileStyle);
    }

    // Upward subheading: secondary text color + 12px, layered over large values for hierarchy.
    const QString kTitleStyle = QStringLiteral("QLabel{color:%1;font-size:12px;}")
        .arg(ksword_theme::textSecondaryHex());
    for (const SummaryTileTitle& titleEntry : kSummaryTileTitles)
    {
        QLabel* const kTitleLabel = findChild<QLabel*>(QString::fromLatin1(titleEntry.objectName));
        if (kTitleLabel != nullptr)
        {
            kTitleLabel->setStyleSheet(kTitleStyle);
        }
    }

    // Large values below: primary text color + 16px + 700 font weight; this is the actual information in this cell that will be read.
    const QString kValueStyle = QStringLiteral("QLabel{color:%1;font-size:16px;font-weight:700;}")
        .arg(ksword_theme::textPrimaryHex());
    const std::array<QLabel*, 6> kSummaryLabels{
        installedLabel_, totalLabel_, inUseLabel_,
        availableLabel_, commitLabel_, unattributedLabel_
    };
    for (QLabel* const kValueLabel : kSummaryLabels)
    {
        if (kValueLabel != nullptr)
        {
            kValueLabel->setStyleSheet(kValueStyle);
        }
    }
}

// updateSummaryTiles:
// - Write the current snapshot's numeric values to the bottom row of the 6-tile summary cards; titles remain fixed in the top row and are maintained by retranslateUi.
// - Use this single entry point after both collection completion and language switching to avoid inconsistent text from duplicating the logic.
// No parameters; no return value; silently return if the snapshot is not yet obtained or the control has not been created.
void SystemMemoryAuditPage::updateSummaryTiles()
{
    if (installedLabel_ == nullptr || !hasSnapshot_)
    {
        return;
    }

    installedLabel_->setText(formatBytes(snapshot_.installedPhysicalBytes));
    totalLabel_->setText(formatBytes(snapshot_.totalPhysicalBytes));
    // The three cells below are a combination of 'absolute value + ratio/cap'; the template uses only parentheses and slashes, so it does not need to be added to the language pack.
    inUseLabel_->setText(QStringLiteral("%1 (%2)").arg(
        formatBytes(snapshot_.inUseBytes),
        formatPercent(snapshot_.inUseBytes, snapshot_.totalPhysicalBytes)));
    availableLabel_->setText(QStringLiteral("%1 (%2)").arg(
        formatBytes(snapshot_.availableBytes),
        formatPercent(snapshot_.availableBytes, snapshot_.totalPhysicalBytes)));
    commitLabel_->setText(QStringLiteral("%1 / %2").arg(
        formatBytes(snapshot_.committedBytes),
        formatBytes(snapshot_.commitLimitBytes)));
    unattributedLabel_->setText(QStringLiteral("%1 (%2)").arg(
        formatBytes(snapshot_.unattributedResidentBytes),
        formatPercent(snapshot_.unattributedResidentBytes, snapshot_.totalPhysicalBytes)));
}

void SystemMemoryAuditPage::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        startUserResidencyScanAfterSnapshot_ = true;
        refreshSnapshot();
        });
    connect(userResidencyScanButton_, &QPushButton::clicked, this, [this]() {
        startUserResidencyScan();
        });
    connect(autoRefreshCheck_, &QCheckBox::toggled, this, [this](const bool checked) {
        if (checked)
        {
            autoRefreshTimer_->start(intervalSpin_->value() * 1000);
        }
        else
        {
            autoRefreshTimer_->stop();
        }
        });
    connect(intervalSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](const int seconds) {
        autoRefreshTimer_->setInterval(seconds * 1000);
        });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() {
        userResidencyTableDirty_ = true;
        processTableDirty_ = true;
        poolTagTableDirty_ = true;
        bigPoolTableDirty_ = true;
        scheduleCurrentDetailViewRebuild();
        updateStatus();
        });
    connect(autoRefreshTimer_, &QTimer::timeout, this, [this]() {
        if (isVisible())
        {
            refreshSnapshot();
        }
        });
    connect(detailTabs_, &QTabWidget::currentChanged, this, [this]() {
        scheduleCurrentDetailViewRebuild();
        updateDetails();
    });
    connect(ddmaCrossCheckButton_, &QPushButton::clicked, this, [this]() {
        runDdmaCrossCheck();
        });
    connect(ddmaCrossCheckAddressEdit_, &QLineEdit::returnPressed, this, [this]() {
        runDdmaCrossCheck();
        });
}

void SystemMemoryAuditPage::setDdmaSessionProvider(
    std::function<const ksword::memory_backend::DdmaSession&()> provider)
{
    ddmaSessionProvider_ = std::move(provider);
    refreshDdmaCrossCheckState();
}

void SystemMemoryAuditPage::refreshDdmaCrossCheckState()
{
    if (ddmaCrossCheckButton_ == nullptr)
    {
        return;
    }
    if (!ddmaSessionProvider_)
    {
        ddmaCrossCheckButton_->setEnabled(false);
        ddmaCrossCheckButton_->setToolTip(localized("DDMA channel is not available in this view."));
        return;
    }

    QString reason;
    const bool kUsable =
        ksword::memory_backend::isDdmaUsable(ddmaSessionProvider_(), &reason);
    ddmaCrossCheckButton_->setEnabled(kUsable);
    ddmaCrossCheckButton_->setToolTip(kUsable
        ? localized("Read the same physical page through both backends and compare byte by byte.")
        : reason);
}

void SystemMemoryAuditPage::runDdmaCrossCheck()
{
    if (ddmaCrossCheckResultLabel_ == nullptr || ddmaCrossCheckAddressEdit_ == nullptr)
    {
        return;
    }
    if (!ddmaSessionProvider_)
    {
        ddmaCrossCheckResultLabel_->setText(
            localized("DDMA channel is not available in this view."));
        return;
    }

    const QString kAddressText = ddmaCrossCheckAddressEdit_->text().trimmed();
    bool converted = false;
    std::uint64_t physicalAddress = 0ULL;
    if (kAddressText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        physicalAddress = kAddressText.mid(2).toULongLong(&converted, 16);
    }
    else
    {
        physicalAddress = kAddressText.toULongLong(&converted, 16);
    }
    if (!converted)
    {
        ddmaCrossCheckResultLabel_->setText(
            localized("Physical address could not be parsed; use hexadecimal, e.g. 0x1000."));
        ddmaCrossCheckResultLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        return;
    }

    // Verify fixed ratio against a full page; two backends reading the same segment are comparable. Granularity is taken
    // from the backend facade; this compilation unit does not need to include driver protocol headers for a single constant.
    const std::uint64_t kTransferBytes =
        static_cast<std::uint64_t>(ksword::memory_backend::ddmaTransferBytes());
    const std::uint64_t kPageBase = physicalAddress & ~(kTransferBytes - 1ULL);
    const ksword::memory_backend::DdmaSession& session = ddmaSessionProvider_();

    const ksword::memory_backend::AccessOutcome kStandardOutcome =
        ksword::memory_backend::readPhysical(
            ksword::memory_backend::MemoryAccessBackend::kStandardDriver,
            session,
            kPageBase,
            kTransferBytes);
    const ksword::memory_backend::AccessOutcome kDdmaOutcome =
        ksword::memory_backend::readPhysical(
            ksword::memory_backend::MemoryAccessBackend::kDdma,
            session,
            kPageBase,
            kTransferBytes);

    // A read failure on either side precludes a 'consistent/inconsistent' conclusion; it simply means comparison is impossible.
    if (!kStandardOutcome.ok || !kDdmaOutcome.ok)
    {
        const QString kDetail = !kStandardOutcome.ok
            ? kStandardOutcome.failureText
            : kDdmaOutcome.failureText;
        ddmaCrossCheckResultLabel_->setText(
            QStringLiteral("%1 %2").arg(localized("Cannot compare:")).arg(kDetail));
        ddmaCrossCheckResultLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        return;
    }

    const qsizetype kCompareLength =
        std::min<qsizetype>(kStandardOutcome.data.size(), kDdmaOutcome.data.size());
    qsizetype diffCount = 0;
    for (qsizetype index = 0; index < kCompareLength; ++index)
    {
        if (kStandardOutcome.data[index] != kDdmaOutcome.data[index])
        {
            ++diffCount;
        }
    }

    if (diffCount == 0)
    {
        ddmaCrossCheckResultLabel_->setText(
            QStringLiteral("0x%1: %2")
                .arg(kPageBase, 0, 16)
                .arg(localized("both backends returned identical bytes; no redirection observed.")));
        ddmaCrossCheckResultLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
    }
    else
    {
        ddmaCrossCheckResultLabel_->setText(
            QStringLiteral("0x%1: %2/%3 %4")
                .arg(kPageBase, 0, 16)
                .arg(diffCount)
                .arg(kCompareLength)
                .arg(localized(
                    "bytes differ. The standard channel is subject to SLAT; DDMA is not. "
                    "This usually means the page is redirected or hidden by a hypervisor.")));
        ddmaCrossCheckResultLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
    }
}

void SystemMemoryAuditPage::retranslateUi()
{
    refreshButton_->setText(localized("Refresh snapshot"));
    refreshButton_->setToolTip(localized("Re-collect the whole-machine physical memory snapshot."));
    userResidencyScanButton_->setText(localized("Deep scan user-mode residency"));
    userResidencyScanButton_->setToolTip(
        localized("Walk every accessible process working set and attribute resident pages to their backing."));
    autoRefreshCheck_->setText(localized("Auto refresh"));
    intervalSpin_->setSuffix(localized(" s"));
    filterEdit_->setPlaceholderText(localized("Filter process, category, file, tag, or address"));

    overviewTree_->setHeaderLabels(QStringList{
        localized("Memory source"), localized("Bytes"), localized("RAM %"),
        localized("Delta"), localized("Accounting role"), localized("Interpretation")
    });
    userResidencyTable_->setHorizontalHeaderLabels(QStringList{
        localized("Process"), localized("PID"), localized("Resident kind"),
        localized("Backing / owner evidence"), localized("Resident references"),
        localized("Private resident"), localized("Shareable refs"),
        localized("Shared refs"), localized("Proportional estimate")
    });
    processTable_->setHorizontalHeaderLabels(QStringList{
        localized("Process"), localized("PID"), localized("Session"),
        localized("Private resident"), localized("Working set"), localized("Shared WS refs"),
        localized("Private commit"), localized("Paged quota"), localized("Nonpaged quota"),
        localized("Hard faults"), localized("Private delta")
    });
    poolTagTable_->setHorizontalHeaderLabels(QStringList{
        localized("Tag"), localized("Paged bytes"), localized("Nonpaged bytes"),
        localized("Total bytes"), localized("Delta"), localized("Paged outstanding"),
        localized("Nonpaged outstanding"), localized("Source"), localized("Description")
    });
    bigPoolTable_->setHorizontalHeaderLabels(QStringList{
        localized("Tag"), localized("Virtual address"), localized("Size"),
        localized("Pool type"), localized("Delta"), localized("Source"), localized("Description")
    });

    detailTabs_->setTabText(0, localized("Physical distribution"));
    detailTabs_->setTabText(1, localized("User-mode residency"));
    detailTabs_->setTabText(2, localized("Kernel process snapshot"));
    detailTabs_->setTabText(3, localized("Pool tags"));
    detailTabs_->setTabText(4, localized("Big Pool allocations"));

    // The sub-headers of summary tiles are local controls; re-translate each cell by looking up via objectName.
    for (const SummaryTileTitle& titleEntry : kSummaryTileTitles)
    {
        QLabel* const kTitleLabel = findChild<QLabel*>(QString::fromLatin1(titleEntry.objectName));
        if (kTitleLabel != nullptr)
        {
            kTitleLabel->setText(localized(titleEntry.sourceText));
        }
    }
    updateSummaryTiles();
}

void SystemMemoryAuditPage::refreshSnapshot()
{
    if (refreshing_)
    {
        return;
    }
    refreshing_ = true;
    const std::uint64_t kTicket = snapshotRefreshTicket_.fetch_add(1) + 1;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(localized("Collecting system memory evidence..."));

    const QPointer<SystemMemoryAuditPage> kGuardedPage(this);
    std::thread([kGuardedPage, kTicket]() mutable {
        Snapshot snapshot = collectSnapshot();
        if (kGuardedPage.isNull())
        {
            return;
        }

        QMetaObject::invokeMethod(
            kGuardedPage.data(),
            [kGuardedPage, kTicket, snapshot = std::move(snapshot)]() mutable {
                if (!kGuardedPage.isNull())
                {
                    kGuardedPage->applySnapshot(std::move(snapshot), kTicket);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void SystemMemoryAuditPage::applySnapshot(Snapshot snapshot, const std::uint64_t ticket)
{
    if (ticket != snapshotRefreshTicket_.load())
    {
        return;
    }

    summaryDeltaBytes_.clear();
    snapshot.errors.clear();
    for (const SnapshotError& error : snapshot.pendingErrors)
    {
        QString errorText = ks::i18n::packedSourceText(error.sourceText);
        if (!error.argument.isNull())
        {
            errorText = errorText.arg(error.argument);
        }
        snapshot.errors << errorText;
    }
    snapshot.pendingErrors.clear();

    const QHash<QString, std::uint64_t> kCurrentSummary{
        { QStringLiteral("in_use"), snapshot.inUseBytes },
        { QStringLiteral("available"), snapshot.availableBytes },
        { QStringLiteral("process_private"), snapshot.processPrivateResidentBytes },
        { QStringLiteral("nonpaged_pool"), snapshot.nonPagedPoolBytes },
        { QStringLiteral("paged_pool_resident"), snapshot.pagedPoolResidentBytes },
        { QStringLiteral("system_code"), snapshot.systemCodeResidentBytes },
        { QStringLiteral("system_driver"), snapshot.systemDriverResidentBytes },
        { QStringLiteral("modified"), snapshot.modifiedBytes + snapshot.modifiedNoWriteBytes },
        { QStringLiteral("unattributed"), snapshot.unattributedResidentBytes }
    };
    for (auto iterator = kCurrentSummary.constBegin(); iterator != kCurrentSummary.constEnd(); ++iterator)
    {
        const std::uint64_t kPrevious = hasSnapshot_
            ? previousSummaryBytes_.value(iterator.key(), iterator.value())
            : iterator.value();
        summaryDeltaBytes_.insert(
            iterator.key(),
            static_cast<std::int64_t>(iterator.value()) - static_cast<std::int64_t>(kPrevious));
    }
    previousSummaryBytes_ = kCurrentSummary;

    QHash<std::uint64_t, std::uint64_t> currentProcessBytes;
    for (ProcessRow& row : snapshot.processes)
    {
        const std::uint64_t kPrevious = hasSnapshot_
            ? previousProcessPrivateBytes_.value(row.identity, row.privateResidentBytes)
            : row.privateResidentBytes;
        row.privateResidentDeltaBytes =
            static_cast<std::int64_t>(row.privateResidentBytes) - static_cast<std::int64_t>(kPrevious);
        currentProcessBytes.insert(row.identity, row.privateResidentBytes);
    }
    previousProcessPrivateBytes_ = std::move(currentProcessBytes);

    QHash<std::uint32_t, std::uint64_t> currentPoolBytes;
    for (PoolTagRow& row : snapshot.poolTags)
    {
        const std::uint64_t kTotal = row.pagedBytes + row.nonPagedBytes;
        const std::uint64_t kPrevious = hasSnapshot_
            ? previousPoolTagBytes_.value(row.tag, kTotal)
            : kTotal;
        row.totalDeltaBytes = static_cast<std::int64_t>(kTotal) - static_cast<std::int64_t>(kPrevious);
        currentPoolBytes.insert(row.tag, kTotal);
    }
    previousPoolTagBytes_ = std::move(currentPoolBytes);

    QHash<std::uint64_t, std::uint64_t> currentBigPoolBytes;
    for (BigPoolRow& row : snapshot.bigPool)
    {
        const std::uint64_t kPrevious = hasSnapshot_
            ? previousBigPoolBytes_.value(row.identity, row.sizeBytes)
            : row.sizeBytes;
        row.sizeDeltaBytes = static_cast<std::int64_t>(row.sizeBytes) - static_cast<std::int64_t>(kPrevious);
        currentBigPoolBytes.insert(row.identity, row.sizeBytes);
    }
    previousBigPoolBytes_ = std::move(currentBigPoolBytes);

    snapshot_ = std::move(snapshot);
    const QString kWarningSignature = snapshot_.errors.join(QChar(0x1F));
    if (!kWarningSignature.isEmpty() &&
        kWarningSignature != lastSnapshotWarningSignature_)
    {
        lastSnapshotWarningSignature_ = kWarningSignature;
        KLogEvent warningEvent;
        warn << warningEvent
            << "[SystemMemoryAuditPage] snapshot completed with warnings, warningCount="
            << snapshot_.errors.size()
            << ", details="
            << snapshot_.errors.join(QStringLiteral("; ")).toStdString()
            << eol;
    }
    else if (kWarningSignature.isEmpty())
    {
        // Clearing allows a new Warn notification to be generated if the same issue occurs again in the future.
        lastSnapshotWarningSignature_.clear();
    }
    hasSnapshot_ = true;
    updateSummaryTiles();
    overviewDirty_ = true;
    processTableDirty_ = true;
    poolTagTableDirty_ = true;
    bigPoolTableDirty_ = true;
    refreshButton_->setEnabled(true);
    refreshing_ = false;
    scheduleCurrentDetailViewRebuild();
    updateDetails();
    updateStatus();

    if (startUserResidencyScanAfterSnapshot_)
    {
        startUserResidencyScanAfterSnapshot_ = false;
        startUserResidencyScan();
    }
}

void SystemMemoryAuditPage::startUserResidencyScan()
{
    if (userResidencyScanInProgress_.exchange(true))
    {
        return;
    }

    const std::uint64_t kTicket = userResidencyScanTicket_.fetch_add(1) + 1;
    const std::vector<ProcessRow> kProcesses = snapshot_.processes;
    const std::uint64_t kPageSize = snapshot_.pageSize;
    userResidencyScanButton_->setEnabled(false);
    userResidencyScanButton_->setText(localized("Scanning user-mode residency..."));
    updateStatus();

    const QPointer<SystemMemoryAuditPage> kGuardedPage(this);
    std::thread([kGuardedPage, kTicket, kProcesses, kPageSize]() mutable {
        UserResidencyScan scan = collectUserResidency(kProcesses, kPageSize);
        if (kGuardedPage.isNull())
        {
            return;
        }

        QMetaObject::invokeMethod(
            kGuardedPage.data(),
            [kGuardedPage, kTicket, scan = std::move(scan)]() mutable {
                if (!kGuardedPage.isNull())
                {
                    kGuardedPage->applyUserResidencyScan(std::move(scan), kTicket);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void SystemMemoryAuditPage::applyUserResidencyScan(UserResidencyScan scan, const std::uint64_t ticket)
{
    if (ticket != userResidencyScanTicket_.load())
    {
        return;
    }

    userResidencyScan_ = std::move(scan);
    if (!userResidencyScan_.errors.isEmpty())
    {
        KLogEvent warningEvent;
        warn << warningEvent
            << "[SystemMemoryAuditPage] user residency scan completed with warnings, warningCount="
            << userResidencyScan_.errors.size()
            << ", details="
            << userResidencyScan_.errors.join(QStringLiteral("; ")).toStdString()
            << eol;
    }
    userResidencyScanInProgress_.store(false);
    userResidencyScanButton_->setEnabled(true);
    userResidencyScanButton_->setText(localized("Deep scan user-mode residency"));
    userResidencyTableDirty_ = true;
    overviewDirty_ = true;
    scheduleCurrentDetailViewRebuild();
    updateDetails();
    updateStatus();
}

void SystemMemoryAuditPage::scheduleCurrentDetailViewRebuild()
{
    if (detailViewRebuildScheduled_)
    {
        return;
    }

    detailViewRebuildScheduled_ = true;
    QTimer::singleShot(0, this, [this]() {
        detailViewRebuildScheduled_ = false;
        rebuildCurrentDetailView();
    });
}

void SystemMemoryAuditPage::rebuildCurrentDetailView()
{
    switch (detailTabs_->currentIndex())
    {
    case 0:
        if (overviewDirty_)
        {
            rebuildOverview();
            overviewDirty_ = false;
        }
        break;
    case 1:
        if (userResidencyTableDirty_)
        {
            rebuildUserResidencyTable();
            userResidencyTableDirty_ = false;
        }
        break;
    case 2:
        if (processTableDirty_)
        {
            rebuildProcessTable();
            processTableDirty_ = false;
        }
        break;
    case 3:
        if (poolTagTableDirty_)
        {
            rebuildPoolTagTable();
            poolTagTableDirty_ = false;
        }
        break;
    case 4:
        if (bigPoolTableDirty_)
        {
            rebuildBigPoolTable();
            bigPoolTableDirty_ = false;
        }
        break;
    default:
        break;
    }
}

void SystemMemoryAuditPage::rebuildOverview()
{
    overviewTree_->setUpdatesEnabled(false);
    overviewTree_->clear();

    const auto kAddRow = [this](
        QTreeWidgetItem* parent,
        const QString& name,
        const std::uint64_t bytes,
        const std::int64_t delta,
        const QString& role,
        const QString& interpretation) {
        QTreeWidgetItem* const kItem = parent != nullptr
            ? new QTreeWidgetItem(parent)
            : new QTreeWidgetItem(overviewTree_);
        kItem->setText(0, name);
        kItem->setText(1, formatBytes(bytes));
        kItem->setText(2, formatPercent(bytes, snapshot_.totalPhysicalBytes));
        kItem->setText(3, formatDelta(delta));
        kItem->setText(4, role);
        kItem->setText(5, interpretation);
        kItem->setTextAlignment(1, Qt::AlignRight | Qt::AlignVCenter);
        kItem->setTextAlignment(2, Qt::AlignRight | Qt::AlignVCenter);
        kItem->setTextAlignment(3, Qt::AlignRight | Qt::AlignVCenter);
        if (delta != 0)
        {
            kItem->setForeground(3, delta > 0
                ? ksword_theme::errorColor()
                : ksword_theme::successColor());
        }
        return kItem;
    };

    QTreeWidgetItem* const kInstalled = kAddRow(
        nullptr, localized("Installed physical RAM"), snapshot_.installedPhysicalBytes, 0,
        localized("Exact boundary"), localized("Physical memory installed in the machine."));
    kAddRow(kInstalled, localized("Hardware and firmware reserved"), snapshot_.hardwareReservedBytes, 0,
        localized("Exact partition"),
        localized("Installed RAM not exposed as usable pages to Windows, including device and firmware reservations."));
    QTreeWidgetItem* const kPhysical = kAddRow(
        kInstalled, localized("Windows usable physical RAM"), snapshot_.totalPhysicalBytes, 0,
        localized("Exact partition"), localized("The physical-memory denominator exposed by the Windows memory manager."));
    kAddRow(kPhysical, localized("In use"), snapshot_.inUseBytes,
        summaryDeltaBytes_.value(QStringLiteral("in_use")), localized("Exact partition"),
        localized("Physical RAM that is not currently available for immediate reuse."));
    kAddRow(kPhysical, localized("Available"), snapshot_.availableBytes,
        summaryDeltaBytes_.value(QStringLiteral("available")), localized("Exact partition"),
        localized("Standby, free, and zeroed pages available to satisfy demand."));

    QTreeWidgetItem* const kIdentified = kAddRow(
        nullptr, localized("Identified in-use lower bound"), snapshot_.identifiedResidentLowerBoundBytes, 0,
        localized("Additive lower bound"),
        localized("Non-overlapping categories that can be safely added without counting shared working sets twice."));
    kAddRow(kIdentified, localized("Process private resident"), snapshot_.processPrivateResidentBytes,
        summaryDeltaBytes_.value(QStringLiteral("process_private")), localized("Additive"),
        localized("Private physical pages from the kernel process snapshot, including protected and system processes."));
    kAddRow(kIdentified, localized("Nonpaged pool"), snapshot_.nonPagedPoolBytes,
        summaryDeltaBytes_.value(QStringLiteral("nonpaged_pool")), localized("Additive"),
        localized("Kernel and driver allocations that cannot be paged out."));
    kAddRow(kIdentified, localized("Paged pool resident"), snapshot_.pagedPoolResidentBytes,
        summaryDeltaBytes_.value(QStringLiteral("paged_pool_resident")), localized("Additive"),
        localized("The resident subset of pageable kernel pool."));
    kAddRow(kIdentified, localized("Kernel code resident"), snapshot_.systemCodeResidentBytes,
        summaryDeltaBytes_.value(QStringLiteral("system_code")), localized("Additive"),
        localized("Resident operating-system code pages."));
    kAddRow(kIdentified, localized("Driver code resident"), snapshot_.systemDriverResidentBytes,
        summaryDeltaBytes_.value(QStringLiteral("system_driver")), localized("Additive"),
        localized("Resident loaded-driver code pages."));
    kAddRow(kIdentified, localized("Modified page lists"),
        snapshot_.modifiedBytes + snapshot_.modifiedNoWriteBytes,
        summaryDeltaBytes_.value(QStringLiteral("modified")), localized("Additive"),
        localized("Dirty transition pages that still occupy RAM and are not immediately reusable."));
    QTreeWidgetItem* const kResidual = kAddRow(
        kIdentified, localized("Unattributed in-use remainder"), snapshot_.unattributedResidentBytes,
        summaryDeltaBytes_.value(QStringLiteral("unattributed")), localized("Explicit remainder"),
        localized("Shared/image pages, page tables, kernel stacks, locked pages, compression, secure memory, and other categories not uniquely attributable here."));
    kResidual->setForeground(0, ksword_theme::warningColor());
    kResidual->setForeground(1, ksword_theme::warningColor());

    if (snapshot_.memoryListAvailable)
    {
        std::uint64_t standbyTotal = 0;
        for (const std::uint64_t kBytes : snapshot_.standbyBytes)
        {
            standbyTotal += kBytes;
        }
        QTreeWidgetItem* const kLists = kAddRow(
            nullptr, localized("Physical page lists"),
            snapshot_.zeroBytes + snapshot_.freeBytes + standbyTotal +
                snapshot_.modifiedBytes + snapshot_.modifiedNoWriteBytes + snapshot_.badBytes,
            0, localized("Page-state evidence"),
            localized("A page-list view; some rows are available while modified pages remain in use."));
        kAddRow(kLists, localized("Standby total"), standbyTotal, 0, localized("Available"),
            localized("Cached pages split by memory priority and reclaimable under pressure."));
        for (int priority = 0; priority < static_cast<int>(snapshot_.standbyBytes.size()); ++priority)
        {
            kAddRow(kLists,
                localized("Standby priority %1").arg(priority),
                snapshot_.standbyBytes[priority], 0, localized("Available"),
                localized("Priority-specific standby pages."));
        }
        kAddRow(kLists, localized("Free"), snapshot_.freeBytes, 0, localized("Available"),
            localized("Free pages that have not yet been zeroed."));
        kAddRow(kLists, localized("Zeroed"), snapshot_.zeroBytes, 0, localized("Available"),
            localized("Zero-filled pages ready for immediate allocation."));
        kAddRow(kLists, localized("Modified"), snapshot_.modifiedBytes, 0, localized("In use"),
            localized("Dirty pages waiting for writeback or another backing-store action."));
        kAddRow(kLists, localized("Modified no-write"), snapshot_.modifiedNoWriteBytes, 0, localized("In use"),
            localized("Modified pages owned by a no-write memory manager path."));
        kAddRow(kLists, localized("Bad pages"), snapshot_.badBytes, 0, localized("Unavailable"),
            localized("Physical pages retired because they cannot be used safely."));
    }

    QTreeWidgetItem* const kOverlap = kAddRow(
        nullptr, localized("Overlapping and commit evidence"), 0, 0,
        localized("Do not add"),
        localized("These counters explain pressure or sharing but overlap the physical accounting above."));
    kAddRow(kOverlap, localized("All process working-set references"), snapshot_.processWorkingSetReferenceBytes, 0,
        localized("Overlapping"), localized("Shared pages may appear in multiple process working sets."));
    kAddRow(kOverlap, localized("Shared process WS references"), snapshot_.processSharedResidentReferenceBytes, 0,
        localized("Overlapping"), localized("Working-set references beyond private resident pages; not unique physical bytes."));
    kAddRow(kOverlap, localized("User-mode mapped resident references"), userResidencyScan_.residentReferenceBytes, 0,
        localized("Overlapping"),
        localized("Deep-scan references grouped by process, private allocation, image, and mapped-file backing."));
    kAddRow(kOverlap, localized("User-mode proportional resident estimate"), userResidencyScan_.proportionalResidentBytes, 0,
        localized("Estimate, do not add"),
        localized("Each shared page reference is divided by the observed share count, which is capped by Windows and is not a PFN identity."));
    kAddRow(kOverlap, localized("System cache resident"), snapshot_.systemCacheResidentBytes, 0,
        localized("Overlapping"), localized("Resident cache pages can overlap shared or file-backed mappings."));
    kAddRow(kOverlap, localized("Broad system cache"), snapshot_.broadSystemCacheBytes, 0,
        localized("Overlapping"), localized("Includes cache plus shareable standby and modified pages on supported systems."));
    kAddRow(kOverlap, localized("Paged pool committed"), snapshot_.pagedPoolCommittedBytes, 0,
        localized("Commit, not residency"), localized("Pageable pool bytes can reside in RAM or backing storage."));
    kAddRow(kOverlap, localized("Process private commit"), snapshot_.processPrivateCommitBytes, 0,
        localized("Commit, not residency"), localized("Private committed virtual memory can be in RAM or the page file."));
    kAddRow(kOverlap, localized("Shared committed"), snapshot_.sharedCommittedBytes, 0,
        localized("Commit, not residency"), localized("System-wide shared commitment."));
    if (snapshot_.mdlAllocatedBytes != 0 || snapshot_.pfnDatabaseCommittedBytes != 0 ||
        snapshot_.systemPageTableCommittedBytes != 0 || snapshot_.contiguousAllocatedBytes != 0)
    {
        kAddRow(kOverlap, localized("MDL pages"), snapshot_.mdlAllocatedBytes, 0,
            localized("Potentially overlapping"), localized("Pages represented by MDLs; may also belong to a process or I/O cache."));
        kAddRow(kOverlap, localized("PFN database committed"), snapshot_.pfnDatabaseCommittedBytes, 0,
            localized("Kernel metadata"), localized("Memory-manager metadata used to track physical pages."));
        kAddRow(kOverlap, localized("System page tables committed"), snapshot_.systemPageTableCommittedBytes, 0,
            localized("Kernel metadata"), localized("Commit used for system page-table structures."));
        kAddRow(kOverlap, localized("Contiguous pages allocated"), snapshot_.contiguousAllocatedBytes, 0,
            localized("Potentially overlapping"), localized("Physically contiguous allocations, often used by drivers or DMA paths."));
    }

    overviewTree_->expandToDepth(1);
    for (int column = 0; column < 5; ++column)
    {
        overviewTree_->resizeColumnToContents(column);
    }
    overviewTree_->setUpdatesEnabled(true);
}

void SystemMemoryAuditPage::rebuildUserResidencyTable()
{
    const QString kFilter = filterEdit_->text().trimmed();
    userResidencyTable_->setSortingEnabled(false);
    userResidencyTable_->setRowCount(0);

    const auto kKindText = [](const UserMemoryKind kind) {
        switch (kind)
        {
        case UserMemoryKind::kPrivate:
            return localized("Private anonymous");
        case UserMemoryKind::kImage:
            return localized("Mapped image");
        case UserMemoryKind::kMappedFile:
            return localized("Mapped file");
        case UserMemoryKind::kPagefileSection:
            return localized("Pagefile-backed section");
        default:
            return localized("Unknown mapping");
        }
    };

    for (const UserResidencyRow& row : userResidencyScan_.rows)
    {
        const QString kCategory = kKindText(row.kind);
        QString backingEvidence = row.backingPath;
        if (backingEvidence == QStringLiteral(":private"))
        {
            backingEvidence = localized("Private allocation owned by this process");
        }
        else if (backingEvidence == QStringLiteral(":pagefile"))
        {
            backingEvidence = localized("Pagefile-backed shared section without a file path");
        }
        else if (backingEvidence == QStringLiteral(":image"))
        {
            backingEvidence = localized("Mapped image path unavailable");
        }
        else if (backingEvidence == QStringLiteral(":unknown"))
        {
            backingEvidence = localized("Virtual region type unavailable");
        }
        const QString kSearchable = QStringLiteral("%1 %2 %3 %4")
            .arg(row.processName)
            .arg(row.pid)
            .arg(kCategory, backingEvidence);
        if (!kFilter.isEmpty() && !kSearchable.contains(kFilter, Qt::CaseInsensitive))
        {
            continue;
        }

        const int kRowIndex = userResidencyTable_->rowCount();
        userResidencyTable_->insertRow(kRowIndex);
        userResidencyTable_->setItem(kRowIndex, 0, textItem(row.processName));
        userResidencyTable_->setItem(kRowIndex, 1, numericItem(QString::number(row.pid), row.pid));
        userResidencyTable_->setItem(kRowIndex, 2, textItem(kCategory));
        userResidencyTable_->setItem(kRowIndex, 3, textItem(backingEvidence));
        userResidencyTable_->setItem(kRowIndex, 4, numericItem(
            formatBytes(row.residentReferenceBytes), static_cast<qulonglong>(row.residentReferenceBytes)));
        userResidencyTable_->setItem(kRowIndex, 5, numericItem(
            formatBytes(row.privateResidentBytes), static_cast<qulonglong>(row.privateResidentBytes)));
        userResidencyTable_->setItem(kRowIndex, 6, numericItem(
            formatBytes(row.shareableResidentBytes), static_cast<qulonglong>(row.shareableResidentBytes)));
        userResidencyTable_->setItem(kRowIndex, 7, numericItem(
            formatBytes(row.sharedResidentReferenceBytes), static_cast<qulonglong>(row.sharedResidentReferenceBytes)));
        userResidencyTable_->setItem(kRowIndex, 8, numericItem(
            formatBytes(row.proportionalResidentBytes), static_cast<qulonglong>(row.proportionalResidentBytes)));
    }

    userResidencyTable_->setSortingEnabled(true);
    userResidencyTable_->sortItems(4, Qt::DescendingOrder);
    userResidencyTable_->resizeColumnsToContents();
    userResidencyTable_->horizontalHeader()->setStretchLastSection(false);
    userResidencyTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
}

void SystemMemoryAuditPage::rebuildProcessTable()
{
    const QString kFilter = filterEdit_->text().trimmed();
    processTable_->setSortingEnabled(false);
    processTable_->setRowCount(0);
    for (const ProcessRow& row : snapshot_.processes)
    {
        const QString kSearchable = QStringLiteral("%1 %2 %3")
            .arg(row.name)
            .arg(row.pid)
            .arg(row.sessionId);
        if (!kFilter.isEmpty() && !kSearchable.contains(kFilter, Qt::CaseInsensitive))
        {
            continue;
        }
        const int kRowIndex = processTable_->rowCount();
        processTable_->insertRow(kRowIndex);
        processTable_->setItem(kRowIndex, 0, textItem(row.name));
        processTable_->setItem(kRowIndex, 1, numericItem(QString::number(row.pid), row.pid));
        processTable_->setItem(kRowIndex, 2, numericItem(QString::number(row.sessionId), row.sessionId));
        processTable_->setItem(kRowIndex, 3, numericItem(formatBytes(row.privateResidentBytes), static_cast<qulonglong>(row.privateResidentBytes)));
        processTable_->setItem(kRowIndex, 4, numericItem(formatBytes(row.workingSetBytes), static_cast<qulonglong>(row.workingSetBytes)));
        processTable_->setItem(kRowIndex, 5, numericItem(formatBytes(row.sharedResidentReferenceBytes), static_cast<qulonglong>(row.sharedResidentReferenceBytes)));
        processTable_->setItem(kRowIndex, 6, numericItem(formatBytes(row.privateCommitBytes), static_cast<qulonglong>(row.privateCommitBytes)));
        processTable_->setItem(kRowIndex, 7, numericItem(formatBytes(row.pagedPoolQuotaBytes), static_cast<qulonglong>(row.pagedPoolQuotaBytes)));
        processTable_->setItem(kRowIndex, 8, numericItem(formatBytes(row.nonPagedPoolQuotaBytes), static_cast<qulonglong>(row.nonPagedPoolQuotaBytes)));
        processTable_->setItem(kRowIndex, 9, numericItem(QString::number(row.hardFaultCount), row.hardFaultCount));
        QTableWidgetItem* const kDeltaItem = signedNumericItem(
            formatDelta(row.privateResidentDeltaBytes),
            static_cast<qlonglong>(row.privateResidentDeltaBytes));
        applyDeltaColor(kDeltaItem, row.privateResidentDeltaBytes);
        processTable_->setItem(kRowIndex, 10, kDeltaItem);
    }
    processTable_->setSortingEnabled(true);
    processTable_->sortItems(3, Qt::DescendingOrder);
    processTable_->resizeColumnsToContents();
    processTable_->horizontalHeader()->setStretchLastSection(true);
}

void SystemMemoryAuditPage::rebuildPoolTagTable()
{
    const QString kFilter = filterEdit_->text().trimmed();
    poolTagTable_->setSortingEnabled(false);
    poolTagTable_->setRowCount(0);
    for (const PoolTagRow& row : snapshot_.poolTags)
    {
        const TagMetadata kMetadata = poolTagMetadata_.value(row.tag);
        const QString kSearchable = QStringLiteral("%1 %2 %3")
            .arg(row.tagText, kMetadata.source, kMetadata.description);
        if (!kFilter.isEmpty() && !kSearchable.contains(kFilter, Qt::CaseInsensitive))
        {
            continue;
        }
        const std::uint64_t kTotal = row.pagedBytes + row.nonPagedBytes;
        const int kRowIndex = poolTagTable_->rowCount();
        poolTagTable_->insertRow(kRowIndex);
        poolTagTable_->setItem(kRowIndex, 0, textItem(row.tagText));
        poolTagTable_->setItem(kRowIndex, 1, numericItem(formatBytes(row.pagedBytes), static_cast<qulonglong>(row.pagedBytes)));
        poolTagTable_->setItem(kRowIndex, 2, numericItem(formatBytes(row.nonPagedBytes), static_cast<qulonglong>(row.nonPagedBytes)));
        poolTagTable_->setItem(kRowIndex, 3, numericItem(formatBytes(kTotal), static_cast<qulonglong>(kTotal)));
        QTableWidgetItem* const kDeltaItem = signedNumericItem(
            formatDelta(row.totalDeltaBytes),
            static_cast<qlonglong>(row.totalDeltaBytes));
        applyDeltaColor(kDeltaItem, row.totalDeltaBytes);
        poolTagTable_->setItem(kRowIndex, 4, kDeltaItem);
        poolTagTable_->setItem(kRowIndex, 5, numericItem(QString::number(row.pagedOutstanding), static_cast<qulonglong>(row.pagedOutstanding)));
        poolTagTable_->setItem(kRowIndex, 6, numericItem(QString::number(row.nonPagedOutstanding), static_cast<qulonglong>(row.nonPagedOutstanding)));
        poolTagTable_->setItem(kRowIndex, 7, textItem(kMetadata.source));
        poolTagTable_->setItem(kRowIndex, 8, textItem(kMetadata.description));
    }
    poolTagTable_->setSortingEnabled(true);
    poolTagTable_->sortItems(3, Qt::DescendingOrder);
    poolTagTable_->resizeColumnsToContents();
    poolTagTable_->horizontalHeader()->setStretchLastSection(true);
}

void SystemMemoryAuditPage::rebuildBigPoolTable()
{
    const QString kFilter = filterEdit_->text().trimmed();
    bigPoolTable_->setSortingEnabled(false);
    bigPoolTable_->setRowCount(0);
    for (const BigPoolRow& row : snapshot_.bigPool)
    {
        const TagMetadata kMetadata = poolTagMetadata_.value(row.tag);
        const QString kAddressText = QStringLiteral("0x%1").arg(row.virtualAddress, 16, 16, QLatin1Char('0')).toUpper();
        const QString kPoolType = row.nonPaged ? localized("Nonpaged") : localized("Paged");
        const QString kSearchable = QStringLiteral("%1 %2 %3 %4 %5")
            .arg(row.tagText, kAddressText, kPoolType, kMetadata.source, kMetadata.description);
        if (!kFilter.isEmpty() && !kSearchable.contains(kFilter, Qt::CaseInsensitive))
        {
            continue;
        }
        const int kRowIndex = bigPoolTable_->rowCount();
        bigPoolTable_->insertRow(kRowIndex);
        bigPoolTable_->setItem(kRowIndex, 0, textItem(row.tagText));
        bigPoolTable_->setItem(kRowIndex, 1, numericItem(kAddressText, static_cast<qulonglong>(row.virtualAddress)));
        bigPoolTable_->setItem(kRowIndex, 2, numericItem(formatBytes(row.sizeBytes), static_cast<qulonglong>(row.sizeBytes)));
        bigPoolTable_->setItem(kRowIndex, 3, textItem(kPoolType));
        QTableWidgetItem* const kDeltaItem = signedNumericItem(
            formatDelta(row.sizeDeltaBytes),
            static_cast<qlonglong>(row.sizeDeltaBytes));
        applyDeltaColor(kDeltaItem, row.sizeDeltaBytes);
        bigPoolTable_->setItem(kRowIndex, 4, kDeltaItem);
        bigPoolTable_->setItem(kRowIndex, 5, textItem(kMetadata.source));
        bigPoolTable_->setItem(kRowIndex, 6, textItem(kMetadata.description));
    }
    bigPoolTable_->setSortingEnabled(true);
    bigPoolTable_->sortItems(2, Qt::DescendingOrder);
    bigPoolTable_->resizeColumnsToContents();
    bigPoolTable_->horizontalHeader()->setStretchLastSection(true);
}

void SystemMemoryAuditPage::updateDetails()
{
    QString text;
    if (detailTabs_->currentIndex() == 0)
    {
        text = localized(
            "The unattributed remainder is deliberate: it prevents false precision. It can contain shared/image pages, kernel stacks, page tables, locked MDL/AWE/large pages, the compression store, VBS/Hyper-V secure memory, and hardware-reserved consumers. Use the other tabs to narrow it without adding overlapping counters together.");
    }
    else if (detailTabs_->currentIndex() == 1)
    {
        text = localized(
            "The user-mode deep scan follows each resident virtual-page reference back to its process and VirtualQueryEx region, separating private allocations, mapped images, mapped files, and pagefile-backed sections. Shared pages intentionally remain attached to every observed owner; the proportional column is an estimate, not a unique PFN count.");
    }
    else if (detailTabs_->currentIndex() == 2)
    {
        text = localized(
            "Processes come from the kernel SystemProcessInformation snapshot, not a Toolhelp visible-process list. Private resident is additive; total working set and shared WS references are diagnostic because shared physical pages can appear in more than one process.");
    }
    else if (detailTabs_->currentIndex() == 3)
    {
        text = localized(
            "Pool tags follow the PoolMonX principle and report allocation/frees plus bytes by four-byte tag. Nonpaged bytes are resident; paged bytes are pageable commitment. A tag identifies an allocator convention, not cryptographic ownership, so source metadata is evidence rather than proof.");
    }
    else
    {
        text = localized(
            "Big Pool lists individual page-sized or larger kernel allocations. The low address bit encodes nonpaged state and is removed before display. These rows are already included in pool totals and must not be added again to physical usage.");
    }
    if (!poolTagMetadataSource_.isEmpty())
    {
        text += localized("\nPool tag metadata: %1").arg(QDir::toNativeSeparators(poolTagMetadataSource_));
    }
    else
    {
        text += localized("\nPool tag metadata was not found; tag bytes and usage remain valid, but source descriptions are unavailable.");
    }
    detailText_->setPlainText(text);
}

void SystemMemoryAuditPage::updateStatus()
{
    const QString kFilter = filterEdit_->text().trimmed();
    QString text = localized("Sample %1 | processes %2/%3 | pool tags %4/%5 | Big Pool %6/%7")
        .arg(snapshot_.sampledAt)
        .arg(processTable_->rowCount())
        .arg(snapshot_.processes.size())
        .arg(poolTagTable_->rowCount())
        .arg(snapshot_.poolTags.size())
        .arg(bigPoolTable_->rowCount())
        .arg(snapshot_.bigPool.size());
    if (userResidencyScanInProgress_.load())
    {
        text += localized(" | user residency: scanning");
    }
    else if (!userResidencyScan_.sampledAt.isEmpty())
    {
        text += localized(" | user residency %1: processes %2/%3, rows %4")
            .arg(userResidencyScan_.sampledAt)
            .arg(userResidencyScan_.accessibleProcessCount)
            .arg(userResidencyScan_.processCount)
            .arg(userResidencyTable_->rowCount());
    }
    if (!kFilter.isEmpty())
    {
        text += localized(" | filter: %1").arg(kFilter);
    }
    const bool kHasWarnings = !snapshot_.errors.isEmpty() || !userResidencyScan_.errors.isEmpty();
    if (!snapshot_.errors.isEmpty())
    {
        text += localized(" | partial evidence warnings: %1 (details in log)")
            .arg(snapshot_.errors.size());
    }
    if (!userResidencyScan_.errors.isEmpty())
    {
        text += localized(" | user-scan warnings: %1 (details in log)")
            .arg(userResidencyScan_.errors.size());
    }
    statusLabel_->setStyleSheet(kHasWarnings
        ? QStringLiteral("color: %1;").arg(ksword_theme::warningHex())
        : QString());
    statusLabel_->setText(text);
}

void SystemMemoryAuditPage::loadPoolTagMetadata()
{
    QStringList candidates;
    const QString kProgramFilesX86 = qEnvironmentVariable("ProgramFiles(x86)");
    const QString kProgramFiles = qEnvironmentVariable("ProgramFiles");
    if (!kProgramFilesX86.isEmpty())
    {
        candidates << QDir(kProgramFilesX86).filePath(QStringLiteral("Windows Kits/10/Debuggers/x64/triage/pooltag.txt"));
        candidates << QDir(kProgramFilesX86).filePath(QStringLiteral("Windows Kits/10/Debuggers/x86/triage/pooltag.txt"));
    }
    if (!kProgramFiles.isEmpty())
    {
        candidates << QDir(kProgramFiles).filePath(QStringLiteral("Windows Kits/10/Debuggers/x64/triage/pooltag.txt"));
    }
    candidates << QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("pooltag.txt"));

    QFile file;
    for (const QString& candidate : std::as_const(candidates))
    {
        file.setFileName(candidate);
        if (file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            poolTagMetadataSource_ = candidate;
            break;
        }
    }
    if (!file.isOpen())
    {
        return;
    }

    while (!file.atEnd())
    {
        const QByteArray kRawLine = file.readLine();
        if (kRawLine.size() < 4 || kRawLine.startsWith("//") || kRawLine.startsWith("rem"))
        {
            continue;
        }
        std::uint32_t tag = 0;
        std::memcpy(&tag, kRawLine.constData(), sizeof(tag));
        const QString kLine = QString::fromLocal8Bit(kRawLine).trimmed();
        const int kFirstDash = kLine.indexOf(QLatin1Char('-'), 4);
        if (kFirstDash < 0)
        {
            continue;
        }
        const int kSecondDash = kLine.indexOf(QLatin1Char('-'), kFirstDash + 1);
        TagMetadata metadata;
        metadata.source = kSecondDash >= 0
            ? kLine.mid(kFirstDash + 1, kSecondDash - kFirstDash - 1).trimmed()
            : kLine.mid(kFirstDash + 1).trimmed();
        if (kSecondDash >= 0)
        {
            metadata.description = kLine.mid(kSecondDash + 1).trimmed();
        }
        if (!metadata.source.isEmpty() || !metadata.description.isEmpty())
        {
            poolTagMetadata_.insert(tag, std::move(metadata));
        }
    }
}

SystemMemoryAuditPage::UserResidencyScan SystemMemoryAuditPage::collectUserResidency(
    const std::vector<ProcessRow>& processes,
    const std::uint64_t pageSize)
{
    UserResidencyScan scan;
    scan.sampledAt = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    if (pageSize == 0)
    {
        scan.errors << QStringLiteral("invalid-page-size");
        return scan;
    }

    QHash<QString, int> rowIndexByKey;
    for (const ProcessRow& process : processes)
    {
        if (process.pid == 0)
        {
            continue;
        }
        ++scan.processCount;

        ScopedHandle processHandle(::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            process.pid));
        if (!processHandle)
        {
            ++scan.inaccessibleProcessCount;
            continue;
        }

        std::vector<PSAPI_WORKING_SET_BLOCK> workingSetBlocks;
        if (!queryProcessWorkingSet(
                processHandle.get(),
                process.workingSetBytes,
                pageSize,
                workingSetBlocks))
        {
            ++scan.inaccessibleProcessCount;
            continue;
        }
        ++scan.accessibleProcessCount;

        MEMORY_BASIC_INFORMATION region{};
        std::uintptr_t regionBegin = 0;
        std::uintptr_t regionEnd = 0;
        QHash<quintptr, QString> mappedPathByAllocationBase;

        for (const PSAPI_WORKING_SET_BLOCK& block : workingSetBlocks)
        {
            if (block.VirtualPage > (std::numeric_limits<std::uintptr_t>::max)() / pageSize)
            {
                continue;
            }
            const std::uintptr_t kVirtualAddress =
                static_cast<std::uintptr_t>(block.VirtualPage * pageSize);
            if (kVirtualAddress < regionBegin || kVirtualAddress >= regionEnd)
            {
                std::memset(&region, 0, sizeof(region));
                if (::VirtualQueryEx(
                        processHandle.get(),
                        reinterpret_cast<const void*>(kVirtualAddress),
                        &region,
                        sizeof(region)) != sizeof(region))
                {
                    regionBegin = kVirtualAddress;
                    regionEnd = kVirtualAddress + static_cast<std::uintptr_t>(pageSize);
                    region.Type = 0;
                    region.AllocationBase = nullptr;
                }
                else
                {
                    regionBegin = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
                    const std::uintptr_t kRegionSize = static_cast<std::uintptr_t>(region.RegionSize);
                    regionEnd = kRegionSize > (std::numeric_limits<std::uintptr_t>::max)() - regionBegin
                        ? (std::numeric_limits<std::uintptr_t>::max)()
                        : regionBegin + kRegionSize;
                }
            }

            UserMemoryKind kind = UserMemoryKind::kUnknown;
            QString backingKey = QStringLiteral(":unknown");
            if (region.Type == MEM_PRIVATE)
            {
                kind = UserMemoryKind::kPrivate;
                backingKey = QStringLiteral(":private");
            }
            else if (region.Type == MEM_IMAGE)
            {
                kind = UserMemoryKind::kImage;
                const quintptr kAllocationBase = reinterpret_cast<quintptr>(region.AllocationBase);
                QString path = mappedPathByAllocationBase.value(kAllocationBase);
                if (path.isNull())
                {
                    path = mappedFilePath(processHandle.get(), reinterpret_cast<const void*>(kVirtualAddress));
                    mappedPathByAllocationBase.insert(kAllocationBase, path);
                }
                backingKey = path.isEmpty() ? QStringLiteral(":image") : path;
            }
            else if (region.Type == MEM_MAPPED)
            {
                const quintptr kAllocationBase = reinterpret_cast<quintptr>(region.AllocationBase);
                QString path = mappedPathByAllocationBase.value(kAllocationBase);
                if (path.isNull())
                {
                    path = mappedFilePath(processHandle.get(), reinterpret_cast<const void*>(kVirtualAddress));
                    mappedPathByAllocationBase.insert(kAllocationBase, path);
                }
                if (path.isEmpty())
                {
                    kind = UserMemoryKind::kPagefileSection;
                    backingKey = QStringLiteral(":pagefile");
                }
                else
                {
                    kind = UserMemoryKind::kMappedFile;
                    backingKey = path;
                }
            }

            const QString kAggregationKey = QStringLiteral("%1\x1f%2\x1f%3")
                .arg(process.pid)
                .arg(static_cast<int>(kind))
                .arg(backingKey);
            int rowIndex = rowIndexByKey.value(kAggregationKey, -1);
            if (rowIndex < 0)
            {
                UserResidencyRow row;
                row.pid = process.pid;
                row.processName = process.name;
                row.kind = kind;
                row.backingPath = backingKey;
                scan.rows.push_back(std::move(row));
                rowIndex = static_cast<int>(scan.rows.size() - 1);
                rowIndexByKey.insert(kAggregationKey, rowIndex);
            }

            UserResidencyRow& row = scan.rows[static_cast<std::size_t>(rowIndex)];
            row.residentReferenceBytes += pageSize;
            scan.residentReferenceBytes += pageSize;

            if (block.ShareCount == 0)
            {
                row.privateResidentBytes += pageSize;
                scan.privateResidentBytes += pageSize;
            }
            if (block.Shared != 0)
            {
                row.shareableResidentBytes += pageSize;
            }
            if (block.ShareCount > 1)
            {
                row.sharedResidentReferenceBytes += pageSize;
                scan.sharedResidentReferenceBytes += pageSize;
            }

            const std::uint64_t kDivisor = block.ShareCount > 1
                ? static_cast<std::uint64_t>(block.ShareCount)
                : 1ULL;
            const std::uint64_t kProportionalBytes = pageSize / kDivisor;
            row.proportionalResidentBytes += kProportionalBytes;
            scan.proportionalResidentBytes += kProportionalBytes;
        }
    }

    std::sort(
        scan.rows.begin(),
        scan.rows.end(),
        [](const UserResidencyRow& left, const UserResidencyRow& right) {
            if (left.residentReferenceBytes != right.residentReferenceBytes)
            {
                return left.residentReferenceBytes > right.residentReferenceBytes;
            }
            if (left.pid != right.pid)
            {
                return left.pid < right.pid;
            }
            return left.backingPath.compare(right.backingPath, Qt::CaseInsensitive) < 0;
        });
    return scan;
}

SystemMemoryAuditPage::Snapshot SystemMemoryAuditPage::collectSnapshot()
{
    Snapshot snapshot;
    snapshot.sampledAt = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));

    SYSTEM_INFO systemInfo{};
    ::GetSystemInfo(&systemInfo);
    snapshot.pageSize = systemInfo.dwPageSize != 0 ? systemInfo.dwPageSize : 4096;

    ULONGLONG installedKilobytes = 0;
    if (::GetPhysicallyInstalledSystemMemory(&installedKilobytes) != FALSE &&
        installedKilobytes <= (std::numeric_limits<std::uint64_t>::max)() / 1024ULL)
    {
        snapshot.installedPhysicalBytes = installedKilobytes * 1024ULL;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus))
    {
        snapshot.totalPhysicalBytes = memoryStatus.ullTotalPhys;
        snapshot.availableBytes = memoryStatus.ullAvailPhys;
        snapshot.committedBytes = memoryStatus.ullTotalPageFile >= memoryStatus.ullAvailPageFile
            ? memoryStatus.ullTotalPageFile - memoryStatus.ullAvailPageFile
            : 0;
        snapshot.commitLimitBytes = memoryStatus.ullTotalPageFile;
    }
    else
    {
        snapshot.pendingErrors.push_back({ QStringLiteral("GlobalMemoryStatusEx failed"), {} });
    }

    PERFORMANCE_INFORMATION publicPerformance{};
    publicPerformance.cb = sizeof(publicPerformance);
    if (::GetPerformanceInfo(&publicPerformance, sizeof(publicPerformance)))
    {
        const std::uint64_t kPublicPageSize = publicPerformance.PageSize != 0
            ? static_cast<std::uint64_t>(publicPerformance.PageSize)
            : snapshot.pageSize;
        snapshot.pageSize = kPublicPageSize;
        snapshot.pagedPoolCommittedBytes = multiplyPages(publicPerformance.KernelPaged, kPublicPageSize);
        snapshot.nonPagedPoolBytes = multiplyPages(publicPerformance.KernelNonpaged, kPublicPageSize);
        snapshot.broadSystemCacheBytes = multiplyPages(publicPerformance.SystemCache, kPublicPageSize);
        if (snapshot.totalPhysicalBytes == 0)
        {
            snapshot.totalPhysicalBytes = multiplyPages(publicPerformance.PhysicalTotal, kPublicPageSize);
        }
        if (snapshot.availableBytes == 0)
        {
            snapshot.availableBytes = multiplyPages(publicPerformance.PhysicalAvailable, kPublicPageSize);
        }
        if (snapshot.committedBytes == 0)
        {
            snapshot.committedBytes = multiplyPages(publicPerformance.CommitTotal, kPublicPageSize);
            snapshot.commitLimitBytes = multiplyPages(publicPerformance.CommitLimit, kPublicPageSize);
        }
        snapshot.peakCommitmentBytes = multiplyPages(publicPerformance.CommitPeak, kPublicPageSize);
    }
    else
    {
        snapshot.pendingErrors.push_back({ QStringLiteral("GetPerformanceInfo failed"), {} });
    }

    const NtQuerySystemInformationFunction kQueryFunction = resolveNtQuerySystemInformation();
    if (kQueryFunction == nullptr)
    {
        snapshot.pendingErrors.push_back({ QStringLiteral("NtQuerySystemInformation is unavailable"), {} });
    }

    if (kQueryFunction != nullptr)
    {
        NativeSystemMemoryUsageInformation memoryUsage{};
        ULONG returnedBytes = 0;
        const LONG kStatus = kQueryFunction(
            kSystemMemoryUsageInformation,
            &memoryUsage,
            sizeof(memoryUsage),
            &returnedBytes);
        if (nativeSuccess(kStatus))
        {
            snapshot.totalPhysicalBytes = memoryUsage.totalPhysicalBytes;
            snapshot.availableBytes = memoryUsage.availableBytes;
            snapshot.residentAvailableBytes = memoryUsage.residentAvailableBytes > 0
                ? static_cast<std::uint64_t>(memoryUsage.residentAvailableBytes)
                : 0;
            snapshot.committedBytes = memoryUsage.committedBytes;
            snapshot.sharedCommittedBytes = memoryUsage.sharedCommittedBytes;
            snapshot.commitLimitBytes = memoryUsage.commitLimitBytes;
            snapshot.peakCommitmentBytes = memoryUsage.peakCommitmentBytes;
        }

        NativeSystemMemoryListInformation memoryList{};
        returnedBytes = 0;
        const LONG kMemoryListStatus = kQueryFunction(
            kSystemMemoryListInformation,
            &memoryList,
            sizeof(memoryList),
            &returnedBytes);
        if (nativeSuccess(kMemoryListStatus))
        {
            snapshot.memoryListAvailable = true;
            snapshot.zeroBytes = multiplyPages(memoryList.zeroPageCount, snapshot.pageSize);
            snapshot.freeBytes = multiplyPages(memoryList.freePageCount, snapshot.pageSize);
            snapshot.modifiedBytes = multiplyPages(memoryList.modifiedPageCount, snapshot.pageSize);
            snapshot.modifiedNoWriteBytes = multiplyPages(memoryList.modifiedNoWritePageCount, snapshot.pageSize);
            snapshot.badBytes = multiplyPages(memoryList.badPageCount, snapshot.pageSize);
            snapshot.modifiedPageFileBytes = multiplyPages(memoryList.modifiedPageCountPageFile, snapshot.pageSize);
            for (std::size_t index = 0; index < snapshot.standbyBytes.size(); ++index)
            {
                snapshot.standbyBytes[index] = multiplyPages(memoryList.pageCountByPriority[index], snapshot.pageSize);
                snapshot.repurposedBytes[index] = multiplyPages(memoryList.repurposedPagesByPriority[index], snapshot.pageSize);
            }
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("Memory page-list query failed (%1)"), statusHex(kMemoryListStatus) });
        }

        std::array<std::byte, 1024> performanceBuffer{};
        returnedBytes = 0;
        const LONG kPerformanceStatus = kQueryFunction(
            kSystemPerformanceInformation,
            performanceBuffer.data(),
            static_cast<ULONG>(performanceBuffer.size()),
            &returnedBytes);
        constexpr std::size_t kRequiredPerformanceBytes =
            offsetof(NativeSystemPerformanceInformation, residentSystemDriverPage) + sizeof(ULONG);
        if (nativeSuccess(kPerformanceStatus) &&
            (returnedBytes == 0 || returnedBytes >= kRequiredPerformanceBytes))
        {
            snapshot.performanceAvailable = true;
            const auto* const kPerformance = reinterpret_cast<const NativeSystemPerformanceInformation*>(performanceBuffer.data());
            snapshot.pagedPoolCommittedBytes = multiplyPages(kPerformance->pagedPoolPages, snapshot.pageSize);
            snapshot.nonPagedPoolBytes = multiplyPages(kPerformance->nonPagedPoolPages, snapshot.pageSize);
            snapshot.pagedPoolResidentBytes = multiplyPages(kPerformance->residentPagedPoolPage, snapshot.pageSize);
            snapshot.systemCodeResidentBytes = multiplyPages(kPerformance->residentSystemCodePage, snapshot.pageSize);
            snapshot.systemDriverResidentBytes = multiplyPages(kPerformance->residentSystemDriverPage, snapshot.pageSize);
            snapshot.systemCacheResidentBytes = multiplyPages(kPerformance->residentSystemCachePage, snapshot.pageSize);
            if (returnedBytes >= offsetof(NativeSystemPerformanceInformation, mdlPagesAllocated) + sizeof(ULONGLONG))
            {
                snapshot.mdlAllocatedBytes = multiplyPages(kPerformance->mdlPagesAllocated, snapshot.pageSize);
            }
            if (returnedBytes >= offsetof(NativeSystemPerformanceInformation, pfnDatabaseCommittedPages) + sizeof(ULONGLONG))
            {
                snapshot.pfnDatabaseCommittedBytes = multiplyPages(kPerformance->pfnDatabaseCommittedPages, snapshot.pageSize);
            }
            if (returnedBytes >= offsetof(NativeSystemPerformanceInformation, systemPageTableCommittedPages) + sizeof(ULONGLONG))
            {
                snapshot.systemPageTableCommittedBytes = multiplyPages(kPerformance->systemPageTableCommittedPages, snapshot.pageSize);
            }
            if (returnedBytes >= offsetof(NativeSystemPerformanceInformation, contiguousPagesAllocated) + sizeof(ULONGLONG))
            {
                snapshot.contiguousAllocatedBytes = multiplyPages(kPerformance->contiguousPagesAllocated, snapshot.pageSize);
            }
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("System performance query failed (%1)"), statusHex(kPerformanceStatus) });
        }

        std::vector<std::byte> processBuffer;
        LONG processStatus = 0;
        if (queryVariableSystemInformation(kQueryFunction, kSystemProcessInformation, processBuffer, processStatus))
        {
            std::size_t offset = 0;
            while (offset + sizeof(NativeSystemProcessInformation) <= processBuffer.size())
            {
                const auto* const kProcess = reinterpret_cast<const NativeSystemProcessInformation*>(processBuffer.data() + offset);
                ProcessRow row;
                row.pid = static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(kProcess->uniqueProcessId));
                row.sessionId = kProcess->sessionId;
                row.privateResidentBytes = kProcess->workingSetPrivateSize;
                row.workingSetBytes = kProcess->workingSetSize;
                row.sharedResidentReferenceBytes = row.workingSetBytes > row.privateResidentBytes
                    ? row.workingSetBytes - row.privateResidentBytes
                    : 0;
                row.privateCommitBytes = kProcess->privatePageCount;
                row.pagedPoolQuotaBytes = kProcess->quotaPagedPoolUsage;
                row.nonPagedPoolQuotaBytes = kProcess->quotaNonPagedPoolUsage;
                row.hardFaultCount = kProcess->hardFaultCount;
                row.identity = (static_cast<std::uint64_t>(row.pid) << 32) ^
                    static_cast<std::uint64_t>(kProcess->createTime.QuadPart);

                const auto kBufferStart = reinterpret_cast<std::uintptr_t>(processBuffer.data());
                const auto kBufferEnd = kBufferStart + processBuffer.size();
                const auto kNameStart = reinterpret_cast<std::uintptr_t>(kProcess->imageName.buffer);
                const auto kNameEnd = kNameStart + kProcess->imageName.length;
                if (kProcess->imageName.buffer != nullptr &&
                    kProcess->imageName.length % sizeof(wchar_t) == 0 &&
                    kNameStart >= kBufferStart && kNameEnd >= kNameStart && kNameEnd <= kBufferEnd)
                {
                    row.name = QString::fromWCharArray(
                        kProcess->imageName.buffer,
                        kProcess->imageName.length / sizeof(wchar_t));
                }
                if (row.name.isEmpty())
                {
                    row.name = row.pid == 0 ? QStringLiteral("[Idle]")
                        : row.pid == 4 ? QStringLiteral("System")
                        : QStringLiteral("[unnamed]");
                }

                snapshot.processPrivateResidentBytes += row.privateResidentBytes;
                snapshot.processWorkingSetReferenceBytes += row.workingSetBytes;
                snapshot.processSharedResidentReferenceBytes += row.sharedResidentReferenceBytes;
                snapshot.processPrivateCommitBytes += row.privateCommitBytes;
                snapshot.processPagedPoolQuotaBytes += row.pagedPoolQuotaBytes;
                snapshot.processNonPagedPoolQuotaBytes += row.nonPagedPoolQuotaBytes;
                snapshot.processes.push_back(std::move(row));

                if (kProcess->nextEntryOffset == 0)
                {
                    break;
                }
                if (kProcess->nextEntryOffset < sizeof(NativeSystemProcessInformation) ||
                    kProcess->nextEntryOffset > processBuffer.size() - offset)
                {
                    snapshot.pendingErrors.push_back({ QStringLiteral("Kernel process snapshot contained an invalid next-entry offset"), {} });
                    break;
                }
                offset += kProcess->nextEntryOffset;
            }
            std::sort(snapshot.processes.begin(), snapshot.processes.end(), [](const ProcessRow& left, const ProcessRow& right) {
                return left.privateResidentBytes > right.privateResidentBytes;
                });
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("Kernel process snapshot failed (%1)"), statusHex(processStatus) });
        }

        std::vector<std::byte> poolTagBuffer;
        LONG poolTagStatus = 0;
        if (queryVariableSystemInformation(kQueryFunction, kSystemPoolTagInformation, poolTagBuffer, poolTagStatus) &&
            poolTagBuffer.size() >= offsetof(NativeSystemPoolTagInformation, tagInfo))
        {
            const auto* const kInformation = reinterpret_cast<const NativeSystemPoolTagInformation*>(poolTagBuffer.data());
            const std::size_t kMaximumCount =
                (poolTagBuffer.size() - offsetof(NativeSystemPoolTagInformation, tagInfo)) / sizeof(NativeSystemPoolTag);
            const std::size_t kCount = std::min<std::size_t>(kInformation->count, kMaximumCount);
            snapshot.poolTags.reserve(kCount);
            for (std::size_t index = 0; index < kCount; ++index)
            {
                const NativeSystemPoolTag& nativeRow = kInformation->tagInfo[index];
                PoolTagRow row;
                row.tag = nativeRow.tagUlong;
                row.tagText = printableTag(nativeRow.tag);
                row.pagedBytes = nativeRow.pagedUsed;
                row.nonPagedBytes = nativeRow.nonPagedUsed;
                row.pagedOutstanding = nativeRow.pagedAllocs >= nativeRow.pagedFrees
                    ? static_cast<std::uint64_t>(nativeRow.pagedAllocs - nativeRow.pagedFrees)
                    : 0;
                row.nonPagedOutstanding = nativeRow.nonPagedAllocs >= nativeRow.nonPagedFrees
                    ? static_cast<std::uint64_t>(nativeRow.nonPagedAllocs - nativeRow.nonPagedFrees)
                    : 0;
                snapshot.poolTagPagedBytes += row.pagedBytes;
                snapshot.poolTagNonPagedBytes += row.nonPagedBytes;
                snapshot.poolTags.push_back(std::move(row));
            }
            std::sort(snapshot.poolTags.begin(), snapshot.poolTags.end(), [](const PoolTagRow& left, const PoolTagRow& right) {
                return left.pagedBytes + left.nonPagedBytes > right.pagedBytes + right.nonPagedBytes;
                });
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("Pool-tag query failed (%1)"), statusHex(poolTagStatus) });
        }

        std::vector<std::byte> bigPoolBuffer;
        LONG bigPoolStatus = 0;
        if (queryVariableSystemInformation(kQueryFunction, kSystemBigPoolInformation, bigPoolBuffer, bigPoolStatus) &&
            bigPoolBuffer.size() >= offsetof(NativeSystemBigPoolInformation, allocatedInfo))
        {
            const auto* const kInformation = reinterpret_cast<const NativeSystemBigPoolInformation*>(bigPoolBuffer.data());
            const std::size_t kMaximumCount =
                (bigPoolBuffer.size() - offsetof(NativeSystemBigPoolInformation, allocatedInfo)) / sizeof(NativeSystemBigPoolEntry);
            const std::size_t kCount = std::min<std::size_t>(kInformation->count, kMaximumCount);
            snapshot.bigPool.reserve(kCount);
            for (std::size_t index = 0; index < kCount; ++index)
            {
                const NativeSystemBigPoolEntry& nativeRow = kInformation->allocatedInfo[index];
                BigPoolRow row;
                row.nonPaged = (nativeRow.virtualAddressAndFlags & 1ULL) != 0;
                row.virtualAddress = nativeRow.virtualAddressAndFlags & ~1ULL;
                row.sizeBytes = nativeRow.sizeInBytes;
                row.tag = nativeRow.tagUlong;
                row.tagText = printableTag(nativeRow.tag);
                row.identity = row.virtualAddress ^ (static_cast<std::uint64_t>(row.tag) << 32);
                snapshot.bigPool.push_back(std::move(row));
            }
            std::sort(snapshot.bigPool.begin(), snapshot.bigPool.end(), [](const BigPoolRow& left, const BigPoolRow& right) {
                return left.sizeBytes > right.sizeBytes;
                });
        }
        else
        {
            snapshot.pendingErrors.push_back({ QStringLiteral("Big Pool query failed (%1)"), statusHex(bigPoolStatus) });
        }
    }

    snapshot.inUseBytes = snapshot.totalPhysicalBytes >= snapshot.availableBytes
        ? snapshot.totalPhysicalBytes - snapshot.availableBytes
        : 0;
    const std::uint64_t kModifiedInUseBytes = snapshot.modifiedBytes + snapshot.modifiedNoWriteBytes;
    const std::array<std::uint64_t, 6> kAdditiveComponents{
        snapshot.processPrivateResidentBytes,
        snapshot.nonPagedPoolBytes,
        snapshot.pagedPoolResidentBytes,
        snapshot.systemCodeResidentBytes,
        snapshot.systemDriverResidentBytes,
        kModifiedInUseBytes
    };
    for (const std::uint64_t kComponent : kAdditiveComponents)
    {
        if (snapshot.identifiedResidentLowerBoundBytes >
            (std::numeric_limits<std::uint64_t>::max)() - kComponent)
        {
            snapshot.identifiedResidentLowerBoundBytes = (std::numeric_limits<std::uint64_t>::max)();
            break;
        }
        snapshot.identifiedResidentLowerBoundBytes += kComponent;
    }
    snapshot.installedPhysicalBytes = std::max(
        snapshot.installedPhysicalBytes,
        snapshot.totalPhysicalBytes);
    snapshot.hardwareReservedBytes = snapshot.installedPhysicalBytes > snapshot.totalPhysicalBytes
        ? snapshot.installedPhysicalBytes - snapshot.totalPhysicalBytes
        : 0;

    snapshot.unattributedResidentBytes = snapshot.inUseBytes > snapshot.identifiedResidentLowerBoundBytes
        ? snapshot.inUseBytes - snapshot.identifiedResidentLowerBoundBytes
        : 0;
    return snapshot;
}

QString SystemMemoryAuditPage::formatBytes(const std::uint64_t bytes)
{
    constexpr double kKib = 1024.0;
    constexpr double kMib = kKib * 1024.0;
    constexpr double kGib = kMib * 1024.0;
    const double kValue = static_cast<double>(bytes);
    if (kValue >= kGib)
    {
        return QStringLiteral("%1 GiB").arg(kValue / kGib, 0, 'f', 2);
    }
    if (kValue >= kMib)
    {
        return QStringLiteral("%1 MiB").arg(kValue / kMib, 0, 'f', 2);
    }
    if (kValue >= kKib)
    {
        return QStringLiteral("%1 KiB").arg(kValue / kKib, 0, 'f', 2);
    }
    return QStringLiteral("%1 B").arg(bytes);
}

QString SystemMemoryAuditPage::formatDelta(const std::int64_t bytes)
{
    if (bytes == 0)
    {
        return QStringLiteral("0 B");
    }
    const bool kPositive = bytes > 0;
    const std::uint64_t kMagnitude = kPositive
        ? static_cast<std::uint64_t>(bytes)
        : static_cast<std::uint64_t>(-(bytes + 1)) + 1ULL;
    return QStringLiteral("%1%2").arg(kPositive ? QStringLiteral("+") : QStringLiteral("-"), formatBytes(kMagnitude));
}

QString SystemMemoryAuditPage::formatPercent(const std::uint64_t bytes, const std::uint64_t totalBytes)
{
    if (totalBytes == 0)
    {
        return QStringLiteral("-");
    }
    return QStringLiteral("%1%").arg(
        static_cast<double>(bytes) * 100.0 / static_cast<double>(totalBytes), 0, 'f', 2);
}
