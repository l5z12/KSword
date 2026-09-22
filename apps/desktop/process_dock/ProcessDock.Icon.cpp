#include "ProcessDock.h"
#include "../ui/FlatTableModel.h"

#include <QImage>
#include <QMetaObject>
#include <QPixmap>
#include <QRunnable>
#include <QSortFilterProxyModel>
#include <QTableView>

#include <algorithm>
#include <cstddef>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Shellapi.h>

#pragma comment(lib, "Shell32.lib")

namespace
{
    // Icon cache upper limit: deduplicated by executable path, retaining sufficient space to prevent unbounded growth during long-running operations.
    constexpr qsizetype kProcessIconCacheMaximumCount = 4096;

    // processPlaceholderIcon: Provides a stable process placeholder icon when the process is incomplete or cannot be resolved.
    // Return value: Share the QIcon to avoid repeatedly reading resources for each empty icon cell.
    const QIcon& processPlaceholderIcon()
    {
        static const QIcon kIcon(QStringLiteral(":/Icon/process_main.svg"));
        return kIcon;
    }

    // isProcessIconPathUsable: Filters out empty paths and non-file placeholder text from process enumeration.
    // Parameter imagePath: Image path from the process record; returns true to allow submitting a Shell icon query.
    bool isProcessIconPathUsable(const QString& imagePath)
    {
        return !imagePath.isEmpty() &&
            !imagePath.startsWith('[') &&
            imagePath != QStringLiteral("历史快照");
    }

    // extractProcessIconImageFromPath: Query small icons from the Windows Shell within a thread pool worker thread.
    // Parameter imagePath: normalized executable file path; return value is an independent QImage, not carrying a GUI-thread-specific QPixmap.
    QImage extractProcessIconImageFromPath(const QString& imagePath)
    {
        // shellInfo holds the HICON allocated by the Shell; the caller must destroy this handle after converting it to a QImage.
        SHFILEINFOW shellInfo{};
        const DWORD_PTR kShellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(imagePath.utf16()),
            0,
            &shellInfo,
            sizeof(shellInfo),
            SHGFI_ICON | SHGFI_SMALLICON);
        if (kShellQueryResult == 0 || shellInfo.hIcon == nullptr)
        {
            return QImage();
        }

        // QImage can be safely passed between threads; QImage::fromHICON copies the pixel data from the HICON.
        QImage iconImage = QImage::fromHICON(shellInfo.hIcon);
        ::DestroyIcon(shellInfo.hIcon);
        return iconImage;
    }
}

QIcon ProcessDock::resolveProcessIcon(const ks::process::ProcessRecord& processRecord)
{
    // processNameText is used as the cache key for historical activities; pathText comes only from background refresh results, and the UI thread does not query paths by PID.
    const QString kProcessNameText = QString::fromStdString(processRecord.processName).trimmed();
    const QString kPathText = QString::fromStdString(processRecord.imagePath).trimmed();
    const QString kActivityIconKey = kProcessNameText + QStringLiteral("|") + kPathText;

    // Historical activity snapshots prefer reusing icons fixed at sampling time to prevent icon changes when reviewing history as the current process evolves.
    const auto kActivityIconIt = activityIconCacheByProcessKey_.constFind(kActivityIconKey);
    if (kActivityIconIt != activityIconCacheByProcessKey_.constEnd())
    {
        return kActivityIconIt.value();
    }

    // The current list and history list share a path cache; on cache hit, drawing the path triggers no asynchronous work.
    const auto kIconIt = iconCacheByPath_.constFind(kPathText);
    if (kIconIt != iconCacheByPath_.constEnd())
    {
        return kIconIt.value();
    }

    // A historical row not yet in this round's cache can still have a task submitted, but current rendering immediately returns a placeholder without blocking the main thread.
    if (isProcessIconPathUsable(kPathText))
    {
        queueProcessIconExtraction(kPathText);
    }
    return processPlaceholderIcon();
}

void ProcessDock::queueProcessIconExtractionsForCurrentProcesses()
{
    // This cache iteration includes all current processes and temporarily retained exit entries; collecting paths first avoids duplicate submissions for the same application instance.
    QSet<QString> imagePaths;
    for (const auto& cachePair : cacheByIdentity_)
    {
        const QString kImagePath = QString::fromStdString(cachePair.second.record.imagePath).trimmed();
        if (isProcessIconPathUsable(kImagePath))
        {
            imagePaths.insert(kImagePath);
        }
    }

    // Immediately submit each unmatched application path to a dedicated thread pool, without waiting for scroll stop or mouse leave from the table.
    for (const QString& imagePath : imagePaths)
    {
        queueProcessIconExtraction(imagePath);
    }
}

void ProcessDock::queueProcessIconExtraction(const QString& imagePath)
{
    // normalizedPath is the unique key for the cache and in-flight collection; all related containers are accessed only on the main thread.
    const QString kNormalizedPath = imagePath.trimmed();
    if (!monitoringEnabled_ ||
        !isProcessIconPathUsable(kNormalizedPath) ||
        iconCacheByPath_.contains(kNormalizedPath) ||
        processIconPathsInFlight_.contains(kNormalizedPath))
    {
        return;
    }

    // Record current task generation: generation increments after pause; old tasks cannot overwrite the new icon cache even if completed.
    const std::uint64_t kExtractionGeneration = processIconExtractionGeneration_;
    QPointer<ProcessDock> guard(this);
    processIconPathsInFlight_.insert(kNormalizedPath);

    // Create a separate task for each distinct image path; the thread pool executes multiple shell queries concurrently up to the concurrency limit.
    QRunnable* const kExtractionTask = QRunnable::create([
        guard,
        kNormalizedPath,
        kExtractionGeneration]() {
            QImage iconImage = extractProcessIconImageFromPath(kNormalizedPath);
            if (guard == nullptr)
            {
                return;
            }

            // Worker threads return only QImage; QPixmap/QIcon construction and table repainting are deferred to the main thread.
            QMetaObject::invokeMethod(
                guard,
                [guard, kNormalizedPath, kExtractionGeneration, iconImage = std::move(iconImage)]() mutable {
                    if (guard != nullptr)
                    {
                        guard->applyProcessIconExtractionResult(
                            kNormalizedPath,
                            std::move(iconImage),
                            kExtractionGeneration);
                    }
                },
                Qt::QueuedConnection);
        });
    kExtractionTask->setAutoDelete(true);
    processIconExtractionPool_.start(kExtractionTask);
}

void ProcessDock::applyProcessIconExtractionResult(
    const QString& imagePath,
    QImage iconImage,
    const std::uint64_t extractionGeneration)
{
    // Generation mismatch indicates the user paused and resumed; the current in-flight collection belongs to the new task, and old callbacks cannot modify it.
    if (extractionGeneration != processIconExtractionGeneration_)
    {
        return;
    }
    processIconPathsInFlight_.remove(imagePath);

    // Do not write task results to the cache after pausing to avoid changing the display of the paused process page.
    if (!monitoringEnabled_ || iconCacheByPath_.contains(imagePath))
    {
        return;
    }

    // QPixmap can only be created on the GUI thread; empty images uniformly fall back to the process placeholder icon, caching the result to avoid repeated failed queries.
    const QIcon kResolvedIcon = iconImage.isNull()
        ? processPlaceholderIcon()
        : QIcon(QPixmap::fromImage(iconImage));
    if (iconCacheByPath_.size() >= kProcessIconCacheMaximumCount)
    {
        iconCacheByPath_.erase(iconCacheByPath_.begin());
    }
    iconCacheByPath_.insert(imagePath, kResolvedIcon);

    // Only request a viewport repaint for the name cell referencing this path; other rows will naturally read the new cache upon entering the viewport.
    refreshProcessTableRowsForIcon(imagePath);
}

void ProcessDock::refreshProcessTableRowsForIcon(const QString& imagePath)
{
    // The main thread updates only visible name cells to avoid triggering a full process table relayout when a single icon is returned.
    if (processTable_ == nullptr ||
        processTableModel_ == nullptr ||
        processSortProxy_ == nullptr ||
        processTable_->viewport() == nullptr)
    {
        return;
    }

    // normalizedImagePath ensures the path text uses the same comparison rules as in the process record.
    const QString kNormalizedImagePath = imagePath.trimmed();
    if (kNormalizedImagePath.isEmpty())
    {
        return;
    }

    // tableRows is a snapshot of the model's current source rows; viewIndex is used to convert the actual display row position after sorting/filtering.
    QWidget* const kTableViewport = processTable_->viewport();
    const std::vector<ProcessTableRow>& tableRows = processTableModel_->rows();
    const int kNameColumn = toColumnIndex(TableColumn::kName);
    for (int sourceRow = 0; sourceRow < static_cast<int>(tableRows.size()); ++sourceRow)
    {
        const ProcessTableRow& tableRow = tableRows[static_cast<std::size_t>(sourceRow)];
        if (QString::fromStdString(tableRow.record.imagePath).trimmed() != kNormalizedImagePath)
        {
            continue;
        }

        const QModelIndex kSourceIndex = processTableModel_->index(sourceRow, kNameColumn);
        const QModelIndex kViewIndex = processSortProxy_->mapFromSource(kSourceIndex);
        const QRect kVisibleRect = processTable_->visualRect(kViewIndex);
        if (kVisibleRect.isValid() && kVisibleRect.intersects(kTableViewport->rect()))
        {
            kTableViewport->update(kVisibleRect);
        }
    }
}
