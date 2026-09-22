#include "DiskMonitorStoragePanel.h"
#include "DiskMonitorStorageLeaseCoordinator.h"

#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QBrush>
#include <QColor>
#include <QHeaderView>
#include <QPointer>
#include <QSet>
#include <QSignalBlocker>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <cwchar>
#include <iterator>
#include <limits>
#include <memory>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

struct DiskMonitorStoragePerformanceState
{
    using Lease = disk_monitor_storage_lease::Lease;
    using LeasePointer = disk_monitor_storage_lease::LeasePointer;

    // leaseByVolumeGuid: stores only the active leases currently being sampled by this panel.
    // The global coordinator holds the same shared_ptr simultaneously, responsible for volume-unique identification and retirement quarantine.
    QHash<QString, LeasePointer> leaseByVolumeGuid;
};

namespace
{
    constexpr int kStorageColumnDrive = 0;          // kStorageColumnDrive: Volume root directory column.
    constexpr int kStorageColumnLabel = 1;          // kStorageColumnLabel: Volume label column.
    constexpr int kStorageColumnFileSystem = 2;     // kStorageColumnFileSystem: File system column.
    constexpr int kStorageColumnActiveTime = 3;     // kStorageColumnActiveTime: Column for active time percentage.
    constexpr int kStorageColumnAvailable = 4;      // kStorageColumnAvailable: Available space column.
    constexpr int kStorageColumnTotal = 5;          // kStorageColumnTotal: Total number of space columns.
    constexpr int kStorageColumnReadRate = 6;       // kStorageColumnReadRate: Read rate column.
    constexpr int kStorageColumnWriteRate = 7;      // kStorageColumnWriteRate: Write rate column.
    constexpr int kStorageColumnResponse = 8;       // kStorageColumnResponse: Average response time column.
    constexpr int kStorageColumnQueueDepth = 9;     // kStorageColumnQueueDepth: Queue depth column.
    constexpr int kStorageColumnCount = 10;         // kStorageColumnCount: Total number of columns in the storage table.

    std::uint64_t nonNegativeLargeInteger(const LARGE_INTEGER value)
    {
        // nonNegativeLargeInteger：
        // - Input: Windows disk performance LARGE_INTEGER;
        // - Returns 0 for negative values to avoid conversion to a large unsigned number.
        return value.QuadPart > 0
            ? static_cast<std::uint64_t>(value.QuadPart)
            : 0U;
    }

    bool samplingShouldStop(const std::atomic_bool* stopRequested)
    {
        return stopRequested != nullptr &&
            stopRequested->load(std::memory_order_acquire);
    }

    QString storageManagerName(const DISK_PERFORMANCE& performance)
    {
        int characterCount = 0;
        while (characterCount < static_cast<int>(std::size(performance.StorageManagerName)) &&
               performance.StorageManagerName[characterCount] != L'\0')
        {
            ++characterCount;
        }
        return QString::fromWCharArray(
            performance.StorageManagerName,
            characterCount).trimmed();
    }

    QString normalizedVolumeGuidName(const QString& volumeGuidName)
    {
        QString normalizedName = volumeGuidName.trimmed();
        normalizedName.replace(QLatin1Char('/'), QLatin1Char('\\'));
        return normalizedName.toUpper();
    }

    bool hasStorageManagerIdentity(
        const std::array<std::uint16_t, 8>& managerIdentity)
    {
        return std::any_of(
            managerIdentity.cbegin(),
            managerIdentity.cend(),
            [](const std::uint16_t character)
            {
                return character != 0U;
            });
    }

    QString storageManagerIdentityKey(
        const std::array<std::uint16_t, 8>& managerIdentity)
    {
        QString key;
        key.reserve(static_cast<int>(managerIdentity.size() * 4U));
        for (const std::uint16_t kCharacter : managerIdentity)
        {
            key.append(
                QString::number(kCharacter, 16)
                    .rightJustified(4, QLatin1Char('0')));
        }
        return key;
    }

    QString storageIdentityKey(
        const QString& volumeGuidName,
        const std::uint32_t volumeSerialNumber,
        const std::array<std::uint16_t, 8>& managerIdentity,
        const std::uint32_t storageDeviceNumber)
    {
        if (volumeGuidName.isEmpty() ||
            !hasStorageManagerIdentity(managerIdentity))
        {
            return {};
        }

        return QStringLiteral("%1|%2|%3|%4")
            .arg(normalizedVolumeGuidName(volumeGuidName))
            .arg(
                QString::number(volumeSerialNumber, 16)
                    .rightJustified(8, QLatin1Char('0')))
            .arg(storageManagerIdentityKey(
                managerIdentity))
            .arg(storageDeviceNumber);
    }

    QString storageIdentityKey(const DiskMonitorStorageSample& sample)
    {
        if (!sample.volumeSerialAvailable ||
            !sample.performanceAvailable)
        {
            return {};
        }
        return storageIdentityKey(
            sample.volumeGuidName,
            sample.volumeSerialNumber,
            sample.storageManagerIdentity,
            sample.storageDeviceNumber);
    }

    QString storageIdentityKey(
        const DiskMonitorStoragePerformanceState::Lease& lease)
    {
        return storageIdentityKey(
            lease.volumeGuidName,
            lease.volumeSerialNumber,
            lease.storageManagerIdentity,
            lease.storageDeviceNumber);
    }

    bool counter32Delta(
        const std::uint32_t currentValue,
        const std::uint32_t previousValue,
        std::uint64_t* deltaOut)
    {
        if (deltaOut == nullptr)
        {
            return false;
        }
        if (currentValue >= previousValue)
        {
            *deltaOut =
                static_cast<std::uint64_t>(currentValue) -
                static_cast<std::uint64_t>(previousValue);
            return true;
        }

        // Only wraparounds spanning the 32-bit counter boundary are considered natural; other decreases indicate an epoch reset.
        constexpr std::uint32_t kWrapHighWatermark = 0xf0000000U;
        constexpr std::uint32_t kWrapLowWatermark = 0x0fffffffU;
        if (previousValue >= kWrapHighWatermark &&
            currentValue <= kWrapLowWatermark)
        {
            *deltaOut =
                (static_cast<std::uint64_t>(
                    std::numeric_limits<std::uint32_t>::max()) + 1U) -
                static_cast<std::uint64_t>(previousValue) +
                static_cast<std::uint64_t>(currentValue);
            return true;
        }
        return false;
    }

    void populatePerformanceSample(
        const DISK_PERFORMANCE& performance,
        const std::uint64_t sampleTickMs,
        DiskMonitorStorageSample* sample)
    {
        if (sample == nullptr)
        {
            return;
        }

        sample->sampleTickMs = sampleTickMs;
        sample->bytesRead = nonNegativeLargeInteger(performance.BytesRead);
        sample->bytesWritten = nonNegativeLargeInteger(performance.BytesWritten);
        sample->readCount = performance.ReadCount;
        sample->writeCount = performance.WriteCount;
        sample->readTime100ns = nonNegativeLargeInteger(performance.ReadTime);
        sample->writeTime100ns = nonNegativeLargeInteger(performance.WriteTime);
        sample->idleTime100ns = nonNegativeLargeInteger(performance.IdleTime);
        sample->queryTime100ns = nonNegativeLargeInteger(performance.QueryTime);
        sample->storageDeviceNumber = performance.StorageDeviceNumber;
        sample->storageManagerName = storageManagerName(performance);
        for (std::size_t managerIndex = 0U;
             managerIndex < sample->storageManagerIdentity.size();
             ++managerIndex)
        {
            sample->storageManagerIdentity[managerIndex] =
                static_cast<std::uint16_t>(
                    performance.StorageManagerName[managerIndex]);
        }
        sample->queueDepth = performance.QueueDepth;
    }

    bool performanceIdentityMatches(
        const DiskMonitorStoragePerformanceState::Lease& lease,
        const DiskMonitorStorageSample& sample)
    {
        return sample.volumeSerialAvailable &&
            lease.volumeSerialNumber == sample.volumeSerialNumber &&
            lease.storageDeviceNumber == sample.storageDeviceNumber &&
            lease.storageManagerIdentity ==
                sample.storageManagerIdentity;
    }

    bool performanceIdentityComplete(
        const DiskMonitorStorageSample& sample)
    {
        return !sample.volumeGuidName.isEmpty() &&
            sample.volumeSerialAvailable &&
            hasStorageManagerIdentity(sample.storageManagerIdentity);
    }

    bool isImmediateLeaseRetirementError(const DWORD errorCode)
    {
        switch (errorCode)
        {
        case ERROR_INVALID_HANDLE:
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_DRIVE:
        case ERROR_NOT_READY:
        case ERROR_GEN_FAILURE:
        case ERROR_DEV_NOT_EXIST:
        case ERROR_NO_SUCH_DEVICE:
        case ERROR_DEVICE_NOT_CONNECTED:
        case ERROR_DEVICE_REMOVED:
        case ERROR_NO_MEDIA_IN_DRIVE:
        case ERROR_MEDIA_CHANGED:
        case ERROR_INVALID_FUNCTION:
            return true;
        default:
            return false;
        }
    }

    void clearPerformanceSample(DiskMonitorStorageSample* sample)
    {
        if (sample == nullptr)
        {
            return;
        }
        sample->storageManagerName.clear();
        sample->storageManagerIdentity.fill(0U);
        sample->sampleTickMs = 0U;
        sample->bytesRead = 0U;
        sample->bytesWritten = 0U;
        sample->readCount = 0U;
        sample->writeCount = 0U;
        sample->readTime100ns = 0U;
        sample->writeTime100ns = 0U;
        sample->idleTime100ns = 0U;
        sample->queryTime100ns = 0U;
        sample->storageDeviceNumber = 0U;
        sample->queueDepth = 0U;
        sample->performanceError = ERROR_SUCCESS;
        sample->performanceAvailable = false;
        sample->baselinePending = false;
    }

    QTableWidgetItem* createStorageItem(
        const QString& text,
        const double numericValue = std::numeric_limits<double>::quiet_NaN())
    {
        // createStorageItem：
        // - Input: Display text and optional numeric value.
        // - Return: Read-only table cell; numeric values are written to UserRole to support correct sorting.
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        if (std::isfinite(numericValue))
        {
            item->setData(Qt::UserRole, numericValue);
            item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        }
        return item;
    }
}

DiskMonitorStoragePanel::DiskMonitorStoragePanel(QWidget* parent)
    : QWidget(parent),
      performanceState_(
          std::make_unique<DiskMonitorStoragePerformanceState>())
{
    // The storage area is responsible only for table display; sampling is uniformly scheduled by the existing background thread
    // of DiskMonitorPage to avoid adding another timer to the hardware page and causing a race condition with page destruction.
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(kStorageColumnCount);
    table_->setHorizontalHeaderLabels({
        QStringLiteral("驱动器"),
        QStringLiteral("卷标"),
        QStringLiteral("文件系统"),
        QStringLiteral("活动时间"),
        QStringLiteral("可用空间"),
        QStringLiteral("总空间"),
        QStringLiteral("读(字节/秒)"),
        QStringLiteral("写(字节/秒)"),
        QStringLiteral("响应时间(ms)"),
        QStringLiteral("队列长度")
        });
    table_->setAlternatingRowColors(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSortingEnabled(true);
    table_->verticalHeader()->setVisible(false);
    table_->verticalHeader()->setDefaultSectionSize(24);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(kStorageColumnLabel, QHeaderView::Stretch);
    table_->setStyleSheet(QStringLiteral(
        "QTableWidget{background:transparent;border:1px solid %1;}"
        "QHeaderView::section{background:%2;color:%3;border:0;border-right:1px solid %1;"
        "border-bottom:1px solid %1;padding:5px 7px;font-weight:600;}")
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::surfaceAltHex())
        .arg(ksword_theme::textPrimaryHex()));
    rootLayout->addWidget(table_, 1);

    summaryText_ = QStringLiteral("存储：等待首轮采样");
}

DiskMonitorStoragePanel::~DiskMonitorStoragePanel()
{
    retirePerformanceCountersAsync(
        QStringLiteral("storage-panel-destructor"));
}

void DiskMonitorStoragePanel::retirePerformanceCountersAsync(
    const QString& reason)
{
    if (performanceState_ == nullptr)
    {
        return;
    }

    for (auto leaseIterator =
             performanceState_->leaseByVolumeGuid.begin();
         leaseIterator !=
             performanceState_->leaseByVolumeGuid.end();)
    {
        // activeLease: shared_ptr held jointly by the coordinator and the panel.
        // retireLeaseAsync only switches state and wakes the worker; it does not execute OFF on the calling thread.
        const DiskMonitorStoragePerformanceState::LeasePointer kActiveLease =
            leaseIterator.value();
        if (disk_monitor_storage_lease::retireLeaseAsync(
                kActiveLease,
                reason))
        {
            leaseIterator =
                performanceState_->leaseByVolumeGuid.erase(
                    leaseIterator);
            continue;
        }
        ++leaseIterator;
    }
}

DiskMonitorStorageBatch DiskMonitorStoragePanel::collectSamples(
    const std::atomic_bool* stopRequested)
{
    DiskMonitorStorageBatch sampleBatch;
    std::vector<DiskMonitorStorageSample>& sampleList =
        sampleBatch.sampleList;
    if (performanceState_ == nullptr)
    {
        sampleBatch.enumerationError = ERROR_INVALID_HANDLE;
        return sampleBatch;
    }
    if (samplingShouldStop(stopRequested))
    {
        sampleBatch.enumerationError = ERROR_OPERATION_ABORTED;
        return sampleBatch;
    }

    // First, let Windows return the length of the multi-string buffer, then read all logical drive root directories in one go.
    SetLastError(ERROR_SUCCESS);
    const DWORD kRequiredCharacterCount = GetLogicalDriveStringsW(0U, nullptr);
    if (kRequiredCharacterCount == 0U)
    {
        const DWORD kErrorCode = GetLastError();
        sampleBatch.enumerationError =
            kErrorCode != ERROR_SUCCESS
            ? kErrorCode
            : ERROR_GEN_FAILURE;
        return sampleBatch;
    }
    std::vector<wchar_t> driveBuffer(
        static_cast<std::size_t>(kRequiredCharacterCount) + 1U,
        L'\0');
    const DWORD kCopiedCharacterCount = GetLogicalDriveStringsW(
        static_cast<DWORD>(driveBuffer.size()),
        driveBuffer.data());
    if (kCopiedCharacterCount == 0U ||
        static_cast<std::size_t>(kCopiedCharacterCount) >= driveBuffer.size())
    {
        const DWORD kErrorCode = GetLastError();
        sampleBatch.enumerationError =
            kErrorCode != ERROR_SUCCESS
            ? kErrorCode
            : ERROR_INSUFFICIENT_BUFFER;
        return sampleBatch;
    }

    QSet<QString> seenVolumeGuidSet;
    auto retireActiveLease =
        [
            this,
            &sampleBatch
        ](
            auto leaseIterator,
            const QString& reason) -> bool
    {
        const DiskMonitorStoragePerformanceState::LeasePointer kActiveLease =
            leaseIterator.value();
        const QString kInvalidatedIdentity =
            kActiveLease != nullptr
            ? storageIdentityKey(*kActiveLease)
            : QString();
        if (!kInvalidatedIdentity.isEmpty() &&
            !sampleBatch.invalidatedBaselineKeys.contains(
                kInvalidatedIdentity))
        {
            sampleBatch.invalidatedBaselineKeys.append(
                kInvalidatedIdentity);
        }

        if (!disk_monitor_storage_lease::retireLeaseAsync(
                kActiveLease,
                reason))
        {
            return false;
        }
        performanceState_->leaseByVolumeGuid.erase(leaseIterator);
        return true;
    };

    // enumerate only fixed volumes; network drives and removable media may block for extended periods during
    // background queries, which is inconsistent with the local disk audit targets of Resource Monitor.
    const wchar_t* driveRootPointer = driveBuffer.data();
    while (driveRootPointer != nullptr && *driveRootPointer != L'\0')
    {
        const std::size_t kDriveRootLength = std::wcslen(driveRootPointer);
        if (kDriveRootLength == 0U)
        {
            break;
        }
        if (samplingShouldStop(stopRequested))
        {
            break;
        }

        if (GetDriveTypeW(driveRootPointer) == DRIVE_FIXED)
        {
            DiskMonitorStorageSample sample;
            sample.driveRoot = QString::fromWCharArray(driveRootPointer);

            wchar_t volumeGuidBuffer[MAX_PATH + 1]{};
            if (GetVolumeNameForVolumeMountPointW(
                driveRootPointer,
                volumeGuidBuffer,
                static_cast<DWORD>(std::size(volumeGuidBuffer))))
            {
                sample.volumeGuidName =
                    normalizedVolumeGuidName(
                        QString::fromWCharArray(volumeGuidBuffer));
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // A single volume may have multiple drive letters/mount points. Query and aggregate by volume
            // GUID only once to avoid inflating performance references and double-counting throughput.
            if (!sample.volumeGuidName.isEmpty() &&
                seenVolumeGuidSet.contains(sample.volumeGuidName))
            {
                driveRootPointer += kDriveRootLength + 1U;
                continue;
            }
            if (!sample.volumeGuidName.isEmpty())
            {
                seenVolumeGuidSet.insert(sample.volumeGuidName);
            }

            ULARGE_INTEGER availableBytes{};
            ULARGE_INTEGER totalBytes{};
            ULARGE_INTEGER totalFreeBytes{};
            if (GetDiskFreeSpaceExW(
                driveRootPointer,
                &availableBytes,
                &totalBytes,
                &totalFreeBytes))
            {
                sample.availableBytes = availableBytes.QuadPart;
                sample.totalBytes = totalBytes.QuadPart;
                sample.capacityAvailable = true;
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // Volume label and file system are for display only; the volume serial number is used for stable
            // identification, so if this call fails, no performance baseline is established in this round.
            wchar_t volumeLabelBuffer[MAX_PATH + 1]{};
            wchar_t fileSystemBuffer[MAX_PATH + 1]{};
            DWORD volumeSerialNumber = 0U;
            if (GetVolumeInformationW(
                driveRootPointer,
                volumeLabelBuffer,
                static_cast<DWORD>(std::size(volumeLabelBuffer)),
                &volumeSerialNumber,
                nullptr,
                nullptr,
                fileSystemBuffer,
                static_cast<DWORD>(std::size(fileSystemBuffer))))
            {
                sample.volumeLabel = QString::fromWCharArray(volumeLabelBuffer);
                sample.fileSystemName = QString::fromWCharArray(fileSystemBuffer);
                sample.volumeSerialNumber = volumeSerialNumber;
                sample.volumeSerialAvailable = true;
            }
            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            // IOCTL_DISK_PERFORMANCE increments an enable reference count on every successful call.
            // The session keeps one anchor per volume. Issue OFF immediately after each
            // subsequent query so only this page's single reference remains between samples.
            const QString kVolumeGuidKey =
                normalizedVolumeGuidName(sample.volumeGuidName);
            bool mayOpenNewLease =
                !kVolumeGuidKey.isEmpty() &&
                sample.volumeSerialAvailable;
            auto leaseIterator =
                performanceState_->leaseByVolumeGuid.find(kVolumeGuidKey);
            if (leaseIterator !=
                performanceState_->leaseByVolumeGuid.end())
            {
                mayOpenNewLease = false;
                DiskMonitorStoragePerformanceState::Lease& lease =
                    *leaseIterator.value();
                const bool kPrimaryIdentityMatches =
                    lease.volumeHandle != INVALID_HANDLE_VALUE &&
                    normalizedVolumeGuidName(lease.volumeGuidName) ==
                        kVolumeGuidKey &&
                    sample.volumeSerialAvailable &&
                    lease.volumeSerialNumber ==
                        sample.volumeSerialNumber;
                if (!kPrimaryIdentityMatches)
                {
                    const bool kRetirementQueued = retireActiveLease(
                        leaseIterator,
                        QStringLiteral(
                            "primary-guid-or-volume-serial-changed"));
                    if (!kRetirementQueued)
                    {
                        sample.performanceError = ERROR_GEN_FAILURE;
                    }
                }
                else
                {
                    DISK_PERFORMANCE performance{};
                    DWORD returnedBytes = 0U;
                    const BOOL kQueryOk = DeviceIoControl(
                        lease.volumeHandle,
                        IOCTL_DISK_PERFORMANCE,
                        nullptr,
                        0U,
                        &performance,
                        static_cast<DWORD>(sizeof(performance)),
                        &returnedBytes,
                        nullptr);
                    const std::uint64_t kSampleTickMs = GetTickCount64();
                    if (kQueryOk)
                    {
                        ++lease.ownedEnableReferenceCount;
                        lease.lastQueryError = ERROR_SUCCESS;
                        lease.consecutiveQueryFailureCount = 0U;
                        const bool kCompleteResult =
                            returnedBytes >=
                            static_cast<DWORD>(sizeof(performance));
                        if (kCompleteResult)
                        {
                            populatePerformanceSample(
                                performance,
                                kSampleTickMs,
                                &sample);
                        }

                        // Regardless of whether the returned length is valid, a successful IOCTL has already incremented the reference count.
                        DWORD balanceError = ERROR_SUCCESS;
                        const bool kBalancedQueryReference =
                            disk_monitor_storage_lease::turnOffOneReference(
                                &lease,
                                &balanceError);
                        const bool kSecondaryIdentityMatches =
                            kCompleteResult &&
                            performanceIdentityComplete(sample) &&
                            performanceIdentityMatches(lease, sample);
                        if (kCompleteResult &&
                            kBalancedQueryReference &&
                            kSecondaryIdentityMatches)
                        {
                            sample.performanceAvailable = true;
                        }
                        else
                        {
                            sample.performanceError =
                                !kCompleteResult
                                ? ERROR_INVALID_DATA
                                : (!kBalancedQueryReference
                                    ? balanceError
                                    : ERROR_INVALID_DATA);
                            if (!kBalancedQueryReference)
                            {
                                lease.lastQueryError = balanceError;
                                ++lease.consecutiveQueryFailureCount;
                            }
                            const bool kRetirementQueued = retireActiveLease(
                                leaseIterator,
                                !kBalancedQueryReference
                                ? QStringLiteral(
                                    "query-reference-off-failed")
                                : QStringLiteral(
                                    "secondary-manager-or-device-changed"));
                            if (!kRetirementQueued)
                            {
                                sample.performanceError =
                                    ERROR_GEN_FAILURE;
                            }
                        }
                    }
                    else
                    {
                        const DWORD kQueryError = GetLastError();
                        sample.performanceError = kQueryError;
                        lease.lastQueryError = kQueryError;
                        ++lease.consecutiveQueryFailureCount;

                        const bool kStopCancellation =
                            samplingShouldStop(stopRequested) &&
                            kQueryError == ERROR_OPERATION_ABORTED;
                        const bool kRetireFailedLease =
                            kStopCancellation ||
                            isImmediateLeaseRetirementError(kQueryError) ||
                            lease.consecutiveQueryFailureCount >= 2U;
                        if (kRetireFailedLease)
                        {
                            const bool kRetirementQueued = retireActiveLease(
                                leaseIterator,
                                kStopCancellation
                                ? QStringLiteral(
                                    "sampling-cancelled")
                                : QStringLiteral(
                                    "query-failure-threshold"));
                            if (!kRetirementQueued)
                            {
                                sample.performanceError =
                                    ERROR_GEN_FAILURE;
                            }
                        }
                    }
                }
            }

            if (mayOpenNewLease &&
                !samplingShouldStop(stopRequested))
            {
                clearPerformanceSample(&sample);
                // newLease: The coordinator atomically acquires the volume slot first. Returns null if an active
                // or retiring state already exists, preventing 1 Hz repeated handle acquisition at the source.
                const DiskMonitorStoragePerformanceState::LeasePointer kNewLease =
                    disk_monitor_storage_lease::tryAcquireActiveLease(
                        kVolumeGuidKey);
                if (kNewLease == nullptr)
                {
                    sample.performanceError = ERROR_RETRY;
                }
                else
                {
                    kNewLease->volumeSerialNumber =
                        sample.volumeSerialNumber;
                    QString volumeDevicePath = sample.volumeGuidName;
                    while (volumeDevicePath.endsWith(
                        QLatin1Char('\\')))
                    {
                        volumeDevicePath.chop(1);
                    }
                    kNewLease->volumeHandle = CreateFileW(
                        reinterpret_cast<LPCWSTR>(
                            volumeDevicePath.utf16()),
                        0U,
                        FILE_SHARE_READ |
                            FILE_SHARE_WRITE |
                            FILE_SHARE_DELETE,
                        nullptr,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        nullptr);

                    if (kNewLease->volumeHandle !=
                        INVALID_HANDLE_VALUE)
                    {
                        DISK_PERFORMANCE performance{};
                        DWORD returnedBytes = 0U;
                        const BOOL kQueryOk = DeviceIoControl(
                            kNewLease->volumeHandle,
                            IOCTL_DISK_PERFORMANCE,
                            nullptr,
                            0U,
                            &performance,
                            static_cast<DWORD>(
                                sizeof(performance)),
                            &returnedBytes,
                            nullptr);
                        const std::uint64_t kSampleTickMs =
                            GetTickCount64();
                        if (kQueryOk)
                        {
                            kNewLease->ownedEnableReferenceCount = 1U;
                            const bool kCompleteResult =
                                returnedBytes >=
                                static_cast<DWORD>(
                                    sizeof(performance));
                            if (kCompleteResult)
                            {
                                populatePerformanceSample(
                                    performance,
                                    kSampleTickMs,
                                    &sample);
                                kNewLease->storageDeviceNumber =
                                    sample.storageDeviceNumber;
                                kNewLease->storageManagerName =
                                    sample.storageManagerName;
                                kNewLease->storageManagerIdentity =
                                    sample.storageManagerIdentity;
                                if (performanceIdentityComplete(
                                    sample))
                                {
                                    sample.performanceAvailable =
                                        true;
                                    sample.baselinePending = true;
                                    performanceState_->
                                        leaseByVolumeGuid.insert(
                                            kVolumeGuidKey,
                                            kNewLease);
                                }
                                else
                                {
                                    sample.performanceError =
                                        ERROR_INVALID_DATA;
                                    if (!disk_monitor_storage_lease::
                                            retireLeaseAsync(
                                                kNewLease,
                                                QStringLiteral(
                                                    "initial-identity-incomplete")))
                                    {
                                        sample.performanceError =
                                            ERROR_GEN_FAILURE;
                                        performanceState_->
                                            leaseByVolumeGuid.insert(
                                                kVolumeGuidKey,
                                                kNewLease);
                                    }
                                }
                            }
                            else
                            {
                                sample.performanceError =
                                    ERROR_INVALID_DATA;
                                if (!disk_monitor_storage_lease::
                                        retireLeaseAsync(
                                            kNewLease,
                                            QStringLiteral(
                                                "initial-query-short-result")))
                                {
                                    sample.performanceError =
                                        ERROR_GEN_FAILURE;
                                    performanceState_->
                                        leaseByVolumeGuid.insert(
                                            kVolumeGuidKey,
                                            kNewLease);
                                }
                            }
                        }
                        else
                        {
                            sample.performanceError = GetLastError();
                            CloseHandle(kNewLease->volumeHandle);
                            kNewLease->volumeHandle =
                                INVALID_HANDLE_VALUE;
                            disk_monitor_storage_lease::
                                releaseUnusedActiveLease(kNewLease);
                        }
                    }
                    else
                    {
                        sample.performanceError = GetLastError();
                        disk_monitor_storage_lease::
                            releaseUnusedActiveLease(kNewLease);
                    }
                }
            }

            if (samplingShouldStop(stopRequested))
            {
                break;
            }

            if (sample.performanceAvailable)
            {
                // Performance identity must be complete; if identity cannot be confirmed, retain only capacity information.
                sample.performanceAvailable =
                    !storageIdentityKey(sample).isEmpty();
            }

            if (!sample.performanceAvailable)
            {
                sample.sampleTickMs = 0U;
            }
            sampleList.push_back(std::move(sample));
        }
        driveRootPointer += kDriveRootLength + 1U;
    }

    if (samplingShouldStop(stopRequested))
    {
        sampleBatch.enumerationError = ERROR_OPERATION_ABORTED;
    }
    else
    {
        sampleBatch.enumerationSucceeded = true;
        sampleBatch.enumerationError = ERROR_SUCCESS;

        // Volumes not appearing in this round have been unloaded/removed; transfer from the active map to the sole worker.
        // While OFF is not cleared, the same GUID remains in quarantine and the lease cannot be reopened.
        for (auto leaseIterator =
                 performanceState_->leaseByVolumeGuid.begin();
             leaseIterator !=
                 performanceState_->leaseByVolumeGuid.end();)
        {
            auto currentLeaseIterator = leaseIterator;
            ++leaseIterator;
            if (!seenVolumeGuidSet.contains(
                currentLeaseIterator.key()))
            {
                retireActiveLease(
                    currentLeaseIterator,
                    QStringLiteral("volume-no-longer-enumerated"));
            }
        }
    }

    std::sort(
        sampleList.begin(),
        sampleList.end(),
        [](const DiskMonitorStorageSample& left, const DiskMonitorStorageSample& right)
        {
            return left.driveRoot.compare(right.driveRoot, Qt::CaseInsensitive) < 0;
        });

    sampleBatch.fixedVolumeCount =
        static_cast<int>(sampleList.size());
    for (const DiskMonitorStorageSample& sample : sampleList)
    {
        if (sample.performanceAvailable)
        {
            ++sampleBatch.performanceAvailableCount;
        }
        if (sample.baselinePending)
        {
            ++sampleBatch.baselinePendingCount;
        }
    }
    sampleBatch.failedPerformanceCount =
        sampleBatch.fixedVolumeCount -
        sampleBatch.performanceAvailableCount;
    return sampleBatch;
}

void DiskMonitorStoragePanel::applySamples(
    DiskMonitorStorageBatch sampleBatch)
{
    if (table_ == nullptr)
    {
        return;
    }

    if (ks::ui::isTableUiCommitBlockedByContextMenu({table_}))
    {
        const QPointer<DiskMonitorStoragePanel> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("disk-monitor-storage-snapshot-apply"),
            {table_},
            [kSafeThis, sampleBatch = std::move(sampleBatch)]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applySamples(std::move(sampleBatch));
                }
            });
        return;
    }

    for (const QString& invalidatedBaseline :
         sampleBatch.invalidatedBaselineKeys)
    {
        baselineByIdentity_.remove(invalidatedBaseline);
    }

    std::vector<DiskMonitorStorageSample>& sampleList =
        sampleBatch.sampleList;
    const QSignalBlocker kTableSignalBlocker(table_);
    const bool kSortingWasEnabled = table_->isSortingEnabled();
    table_->setSortingEnabled(false);
    table_->clearSpans();
    table_->setRowCount(static_cast<int>(sampleList.size()));

    double highestActivePercent = 0.0;
    double totalReadRate = 0.0;
    double totalWriteRate = 0.0;
    int validRateSampleCount = 0;
    int baselinePendingCount = 0;
    QHash<QString, StorageBaseline> nextBaselineByIdentity;

    for (std::size_t sampleIndex = 0U;
         sampleIndex < sampleList.size();
         ++sampleIndex)
    {
        const DiskMonitorStorageSample& sample = sampleList[sampleIndex];
        const QString kBaselineKey = storageIdentityKey(sample);
        const auto kBaselineIterator =
            baselineByIdentity_.constFind(kBaselineKey);

        double readRate = 0.0;
        double writeRate = 0.0;
        double activePercent = 0.0;
        double responseTimeMs = 0.0;
        bool rateAvailable = false;
        bool responseTimeAvailable = false;
        if (!kBaselineKey.isEmpty() &&
            kBaselineIterator != baselineByIdentity_.constEnd() &&
            kBaselineIterator->performanceAvailable &&
            sample.performanceAvailable &&
            sample.sampleTickMs > kBaselineIterator->sampleTickMs)
        {
            std::uint64_t readOperationDelta = 0U;
            std::uint64_t writeOperationDelta = 0U;
            const bool kCumulativeEpochContinues =
                sample.bytesRead >= kBaselineIterator->bytesRead &&
                sample.bytesWritten >= kBaselineIterator->bytesWritten &&
                sample.readTime100ns >=
                    kBaselineIterator->readTime100ns &&
                sample.writeTime100ns >=
                    kBaselineIterator->writeTime100ns &&
                sample.idleTime100ns >=
                    kBaselineIterator->idleTime100ns &&
                sample.queryTime100ns >
                    kBaselineIterator->queryTime100ns &&
                counter32Delta(
                    sample.readCount,
                    kBaselineIterator->readCount,
                    &readOperationDelta) &&
                counter32Delta(
                    sample.writeCount,
                    kBaselineIterator->writeCount,
                    &writeOperationDelta);

            if (kCumulativeEpochContinues)
            {
                const std::uint64_t kElapsedMs =
                    sample.sampleTickMs -
                    kBaselineIterator->sampleTickMs;
                const std::uint64_t kQueryDelta =
                    sample.queryTime100ns -
                    kBaselineIterator->queryTime100ns;
                const std::uint64_t kMonotonicDelta100ns =
                    kElapsedMs <=
                        std::numeric_limits<std::uint64_t>::max() / 10000U
                    ? kElapsedMs * 10000U
                    : std::numeric_limits<std::uint64_t>::max();

                // QueryTime is a system timestamp. If it is significantly inconsistent with the monotonic interval near
                // the IOCTL, treat it as a system time adjustment or counter epoch change and rebuild the baseline.
                const bool kQueryIntervalConsistent =
                    kQueryDelta > 0U &&
                    kMonotonicDelta100ns > 0U &&
                    kQueryDelta >= kMonotonicDelta100ns / 4U &&
                    kQueryDelta <=
                        (kMonotonicDelta100ns <=
                             std::numeric_limits<std::uint64_t>::max() / 4U
                             ? kMonotonicDelta100ns * 4U
                             : std::numeric_limits<std::uint64_t>::max());
                if (kQueryIntervalConsistent)
                {
                    const double kElapsedSeconds =
                        static_cast<double>(kElapsedMs) / 1000.0;
                    readRate =
                        static_cast<double>(
                            sample.bytesRead -
                            kBaselineIterator->bytesRead) /
                        kElapsedSeconds;
                    writeRate =
                        static_cast<double>(
                            sample.bytesWritten -
                            kBaselineIterator->bytesWritten) /
                        kElapsedSeconds;

                    const std::uint64_t kIdleDelta =
                        sample.idleTime100ns -
                        kBaselineIterator->idleTime100ns;
                    const std::uint64_t kBusyDelta =
                        kQueryDelta > kIdleDelta
                        ? kQueryDelta - kIdleDelta
                        : 0U;
                    activePercent = std::clamp(
                        static_cast<double>(kBusyDelta) * 100.0 /
                        static_cast<double>(kQueryDelta),
                        0.0,
                        100.0);

                    const std::uint64_t kOperationDelta =
                        readOperationDelta + writeOperationDelta;
                    const std::uint64_t kOperationTimeDelta =
                        (sample.readTime100ns -
                         kBaselineIterator->readTime100ns) +
                        (sample.writeTime100ns -
                         kBaselineIterator->writeTime100ns);
                    if (kOperationDelta > 0U)
                    {
                        responseTimeMs =
                            static_cast<double>(kOperationTimeDelta) /
                            static_cast<double>(kOperationDelta) /
                            10000.0;
                        responseTimeAvailable = true;
                    }
                    rateAvailable = true;
                    ++validRateSampleCount;
                }
            }
        }

        // Refresh the entire baseline group only when identity integrity is confirmed and the current round's performance value is valid.
        if (!kBaselineKey.isEmpty() && sample.performanceAvailable)
        {
            StorageBaseline nextBaseline;
            nextBaseline.sampleTickMs = sample.sampleTickMs;
            nextBaseline.bytesRead = sample.bytesRead;
            nextBaseline.bytesWritten = sample.bytesWritten;
            nextBaseline.readCount = sample.readCount;
            nextBaseline.writeCount = sample.writeCount;
            nextBaseline.readTime100ns = sample.readTime100ns;
            nextBaseline.writeTime100ns = sample.writeTime100ns;
            nextBaseline.idleTime100ns = sample.idleTime100ns;
            nextBaseline.queryTime100ns = sample.queryTime100ns;
            nextBaseline.performanceAvailable = true;
            nextBaselineByIdentity.insert(kBaselineKey, nextBaseline);
        }
        if (sample.performanceAvailable && !rateAvailable)
        {
            ++baselinePendingCount;
        }

        const int kRowIndex = static_cast<int>(sampleIndex);
        table_->setItem(
            kRowIndex,
            kStorageColumnDrive,
            createStorageItem(sample.driveRoot));
        table_->setItem(
            kRowIndex,
            kStorageColumnLabel,
            createStorageItem(
                sample.volumeLabel.isEmpty()
                    ? QStringLiteral("-")
                    : sample.volumeLabel));
        table_->setItem(
            kRowIndex,
            kStorageColumnFileSystem,
            createStorageItem(
                sample.fileSystemName.isEmpty()
                    ? QStringLiteral("-")
                    : sample.fileSystemName));
        table_->setItem(
            kRowIndex,
            kStorageColumnActiveTime,
            createStorageItem(
                rateAvailable
                    ? QStringLiteral("%1%").arg(activePercent, 0, 'f', 1)
                    : QStringLiteral("N/A"),
                rateAvailable
                    ? activePercent
                    : std::numeric_limits<double>::quiet_NaN()));
        table_->setItem(
            kRowIndex,
            kStorageColumnAvailable,
            createStorageItem(
                sample.capacityAvailable
                    ? formatBytes(static_cast<double>(sample.availableBytes))
                    : QStringLiteral("N/A"),
                sample.capacityAvailable
                    ? static_cast<double>(sample.availableBytes)
                    : std::numeric_limits<double>::quiet_NaN()));
        table_->setItem(
            kRowIndex,
            kStorageColumnTotal,
            createStorageItem(
                sample.capacityAvailable
                    ? formatBytes(static_cast<double>(sample.totalBytes))
                    : QStringLiteral("N/A"),
                sample.capacityAvailable
                    ? static_cast<double>(sample.totalBytes)
                    : std::numeric_limits<double>::quiet_NaN()));
        table_->setItem(
            kRowIndex,
            kStorageColumnReadRate,
            createStorageItem(
                rateAvailable ? formatRate(readRate) : QStringLiteral("N/A"),
                rateAvailable
                    ? readRate
                    : std::numeric_limits<double>::quiet_NaN()));
        table_->setItem(
            kRowIndex,
            kStorageColumnWriteRate,
            createStorageItem(
                rateAvailable ? formatRate(writeRate) : QStringLiteral("N/A"),
                rateAvailable
                    ? writeRate
                    : std::numeric_limits<double>::quiet_NaN()));
        table_->setItem(
            kRowIndex,
            kStorageColumnResponse,
            createStorageItem(
                responseTimeAvailable
                    ? QStringLiteral("%1").arg(responseTimeMs, 0, 'f', 2)
                    : QStringLiteral("N/A"),
                responseTimeAvailable
                    ? responseTimeMs
                    : std::numeric_limits<double>::quiet_NaN()));
        table_->setItem(
            kRowIndex,
            kStorageColumnQueueDepth,
            createStorageItem(
                sample.performanceAvailable
                    ? QString::number(sample.queueDepth)
                    : QStringLiteral("N/A"),
                sample.performanceAvailable
                    ? static_cast<double>(sample.queueDepth)
                    : std::numeric_limits<double>::quiet_NaN()));

        if (rateAvailable)
        {
            highestActivePercent =
                std::max(highestActivePercent, activePercent);
            totalReadRate += readRate;
            totalWriteRate += writeRate;
        }
    }

    sampleBatch.baselinePendingCount = baselinePendingCount;
    baselineByIdentity_ = std::move(nextBaselineByIdentity);
    if (!sampleBatch.enumerationSucceeded)
    {
        if (sampleList.empty())
        {
            table_->setRowCount(1);
            table_->setItem(
                0,
                kStorageColumnDrive,
                createStorageItem(
                    QStringLiteral("存储枚举失败，错误码：%1")
                        .arg(sampleBatch.enumerationError)));
            table_->setSpan(
                0,
                kStorageColumnDrive,
                1,
                kStorageColumnCount);
        }
        summaryText_ = QStringLiteral(
            "存储：枚举未完成（错误 %1）    已取得性能：%2    等待基线：%3    采集失败：%4    汇总：N/A")
            .arg(sampleBatch.enumerationError)
            .arg(sampleBatch.performanceAvailableCount)
            .arg(sampleBatch.baselinePendingCount)
            .arg(sampleBatch.failedPerformanceCount);
    }
    else if (sampleBatch.fixedVolumeCount == 0)
    {
        table_->setRowCount(1);
        table_->setItem(
            0,
            kStorageColumnDrive,
            createStorageItem(QStringLiteral("未发现可用的本机固定卷")));
        table_->setSpan(0, kStorageColumnDrive, 1, kStorageColumnCount);
        summaryText_ = QStringLiteral("存储：未发现可用固定卷");
    }
    else if (validRateSampleCount ==
                 sampleBatch.fixedVolumeCount &&
             sampleBatch.baselinePendingCount == 0 &&
             sampleBatch.failedPerformanceCount == 0)
    {
        summaryText_ = QStringLiteral(
            "存储：%1 个卷    最高活动时间：%2%    总吞吐：%3")
            .arg(sampleBatch.fixedVolumeCount)
            .arg(highestActivePercent, 0, 'f', 1)
            .arg(formatRate(totalReadRate + totalWriteRate));
    }
    else
    {
        const QString kActiveSummary =
            validRateSampleCount > 0
            ? QStringLiteral("%1%").arg(
                highestActivePercent,
                0,
                'f',
                1)
            : QStringLiteral("N/A");
        const QString kThroughputSummary =
            validRateSampleCount > 0
            ? formatRate(totalReadRate + totalWriteRate)
            : QStringLiteral("N/A");
        summaryText_ = QStringLiteral(
            "存储：有效 %1/%2 个卷（部分）    等待基线：%3    采集失败：%4    有效卷最高活动：%5    有效卷总吞吐：%6")
            .arg(validRateSampleCount)
            .arg(sampleBatch.fixedVolumeCount)
            .arg(sampleBatch.baselinePendingCount)
            .arg(sampleBatch.failedPerformanceCount)
            .arg(kActiveSummary)
            .arg(kThroughputSummary);
    }
    table_->setSortingEnabled(kSortingWasEnabled);
}

QString DiskMonitorStoragePanel::summaryText() const
{
    return summaryText_;
}

QString DiskMonitorStoragePanel::formatBytes(const double byteCount)
{
    static const QStringList kUnitList = {
        QStringLiteral("B"),
        QStringLiteral("KB"),
        QStringLiteral("MB"),
        QStringLiteral("GB"),
        QStringLiteral("TB")
    };
    double displayValue = std::max(0.0, byteCount);
    int unitIndex = 0;
    while (displayValue >= 1024.0 && unitIndex + 1 < kUnitList.size())
    {
        displayValue /= 1024.0;
        ++unitIndex;
    }
    const int kPrecision = unitIndex == 0 ? 0 : (displayValue >= 100.0 ? 0 : 1);
    return QStringLiteral("%1 %2")
        .arg(displayValue, 0, 'f', kPrecision)
        .arg(kUnitList[unitIndex]);
}

QString DiskMonitorStoragePanel::formatRate(const double bytesPerSecond)
{
    return QStringLiteral("%1/s").arg(formatBytes(bytesPerSecond));
}
