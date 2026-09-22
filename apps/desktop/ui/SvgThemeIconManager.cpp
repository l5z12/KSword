#include "SvgThemeIconManager.h"

// ============================================================
// SvgThemeIconManager.cpp
// Implementation notes:
// - Do not modify the SVG source in qrc, and do not require buttons to switch to the new API;
// - Traverse existing controls only once during theme load/switch.
// - Iterate by time-budget slices, yielding the event loop between slices using QTimer::singleShot(0).
//   Do not call processEvents on the call stack to avoid reentrancy during theme refresh.
// - Subsequent lazy-loaded controls enter the shared cache via the same event filter.
// ============================================================

#include <QAbstractButton>
#include <QAction>
#include <QActionEvent>
#include <QApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QEvent>
#include <QHash>
#include <QImage>
#include <QList>
#include <QMenu>
#include <QPainter>
#include <QPixmap>
#include <QPointer>
#include <QSet>
#include <QSize>
#include <QTabWidget>
#include <QTimer>
#include <QVariant>
#include <QWidget>

#include <algorithm>

namespace
{
    constexpr auto kOriginalButtonIconProperty =
        "ksword_svg_theme_original_button_icon"; // Button original icon property name.
    constexpr auto kLastButtonIconKeyProperty =
        "ksword_svg_theme_last_button_icon_key"; // The QIcon cacheKey for the button last written by the manager.
    constexpr auto kOriginalActionIconProperty =
        "ksword_svg_theme_original_action_icon"; // QAction original icon property name.
    constexpr auto kLastActionIconKeyProperty =
        "ksword_svg_theme_last_action_icon_key"; // The cacheKey recently written by the manager to the QAction.
    constexpr auto kOriginalWindowIconProperty =
        "ksword_svg_theme_original_window_icon"; // Original value for the windowIcon of a standard control.
    constexpr auto kLastWindowIconKeyProperty =
        "ksword_svg_theme_last_window_icon_key"; // The cacheKey most recently written by the manager to windowIcon.
    constexpr auto kOriginalTabIconProperty =
        "ksword_svg_theme_original_tab_icon"; // Tab page saves the original icon of the associated tab.
    constexpr auto kLastTabIconKeyProperty =
        "ksword_svg_theme_last_tab_icon_key"; // The cacheKey for the tab icon most recently written by the manager.

    // cachedTintedIcons：
    // - key: original image pixel signature + target color.
    // - value is a QIcon containing pre-constructed multi-size pixmaps, shared across all windows.
    QHash<QByteArray, QIcon>& cachedTintedIcons()
    {
        static QHash<QByteArray, QIcon> iconCache;
        return iconCache;
    }

    // cachedIconsBySourceKey：
    // - The key is QIcon::cacheKey() of the source icon; Qt assigns monotonically increasing IDs to each icon data instance, which are never reused after destruction.
    // - value is the colored result of the source icon under the current accent color; an empty QIcon indicates it has been determined as non-candidate and will not be colored.
    // - Skip the entire 24x24 re-rendering, per-pixel candidate evaluation, and SHA-256 pixel signature computation upon a cache hit.
    QHash<qint64, QIcon>& cachedIconsBySourceKey()
    {
        static QHash<qint64, QIcon> sourceKeyedIconCache;
        return sourceKeyedIconCache;
    }

    // MaximumSourceIconCacheEntries：
    // - Source icon identity cache is merely a speedup table; when entries exceed the limit, discard and rebuild entirely.
    // - Prevent unbounded cache growth from continuously created QIcon objects during long-running sessions.
    constexpr int kMaximumSourceIconCacheEntries = 4096;

    // clearThemedIconCaches：
    // - When the accent color changes, clear both the pixel signature cache and the source image identity cache simultaneously.
    // - Clearing only one cache causes old themed results to be reused in the next round.
    void clearThemedIconCaches()
    {
        cachedTintedIcons().clear();
        cachedIconsBySourceKey().clear();
    }

    // IconApplySliceBudgetMilliseconds：
    // - Maximum milliseconds allowed for a single slice to occupy the UI thread.
    // - Immediately yield the event loop if the budget is exceeded; remaining widgets continue in the next slice.
    constexpr qint64 kIconApplySliceBudgetMilliseconds = 8;

    // IconApplyBudgetCheckStride：
    // - Read the clock once every N controls processed.
    // - The overhead for a single icon-less control is only a few microseconds; fetching them one by one becomes the primary cost.
    // - Value is kept small to ensure that a few controls requiring full SVG rasterization do not exhaust the single-slice budget.
    constexpr int kIconApplyBudgetCheckStride = 8;

    // IconApplySliceState：
    // - SvgThemeIconManager is a process-local singleton; since the slice state is unique per instance, it can be placed directly in the implementation file.
    // - generation: Used to evict old slices replaced by the new theme switch.
    struct IconApplySliceState
    {
        QList<QPointer<QWidget>> pendingWidgets; // pendingWidgets: Control snapshots pending for this round.
        int nextWidgetIndex = 0;                 // nextWidgetIndex: Index of the next widget to process.
        QSet<QAction*> processedActions;         // processedActions: Performs identity deduplication only; never dereferenced.
        std::function<void(int, int)> progressCallback; // progressCallback: Progress callback, may be null.
        quint64 generation = 0;                  // generation: Generation of this batch processing round.
        bool nextSliceScheduled = false;         // nextSliceScheduled: Whether the next slice is already queued.
    };

    // iconApplySliceState：
    // - Returns the unique slice state within the process.
    // - accessible only on the UI thread; no additional locking required.
    IconApplySliceState& iconApplySliceState()
    {
        static IconApplySliceState sliceState;
        return sliceState;
    }

    // iconApplyGenerationCounter：
    // - Incremented once per applyToApplication call to serve as the identity for this shard batch;
    // - If an old queued slice has a generation mismatch, discard it entirely without writing the old emphasized color back to the control.
    quint64& iconApplyGenerationCounter()
    {
        static quint64 generationCounter = 0;
        return generationCounter;
    }

    // resetIconApplySliceState：
    // - Release control snapshots, deduplicated action sets, and progress callbacks.
    // - Avoid the manager holding QPointers to closed windows and closures from call sites for extended periods.
    void resetIconApplySliceState(IconApplySliceState& sliceState)
    {
        sliceState.pendingWidgets.clear();
        sliceState.nextWidgetIndex = 0;
        sliceState.processedActions.clear();
        sliceState.progressCallback = {};
        sliceState.nextSliceScheduled = false;
    }

    // normalizedIconImage：
    // - normalize any QIcon to a 24x24 ARGB image;
    // - Also used for candidate recognition and stable cache signature.
    QImage normalizedIconImage(const QIcon& sourceIcon)
    {
        QPixmap sourcePixmap =
            sourceIcon.pixmap(QSize(24, 24), QIcon::Normal, QIcon::Off);
        if (sourcePixmap.isNull())
        {
            return QImage();
        }
        return sourcePixmap.toImage().convertToFormat(QImage::Format_ARGB32);
    }

    // isThemeTintCandidate：
    // - SVG icons are typically scalable and availableSizes is empty;
    // - The legacy createBlueIcon has been converted to bitmaps, so 'low color count' is now used to identify flat icons.
    // - Multi-color process/file icons exceed the threshold and will not be overridden by the theme color.
    bool isThemeTintCandidate(const QIcon& sourceIcon, const QImage& normalizedImage)
    {
        if (sourceIcon.isNull() || normalizedImage.isNull())
        {
            return false;
        }
        if (sourceIcon.availableSizes(QIcon::Normal, QIcon::Off).isEmpty())
        {
            return true;
        }

        QSet<QRgb> opaqueColors; // opaqueColors: set of RGB values visible after ignoring transparency.
        int visiblePixelCount = 0; // visiblePixelCount: Used to exclude fully transparent placeholder icons.
        constexpr int kMaximumFlatColorCount = 48; // Maximum number of colors allowed for flat icons.
        for (int y = 0; y < normalizedImage.height(); ++y)
        {
            const QRgb* scanLine =
                reinterpret_cast<const QRgb*>(normalizedImage.constScanLine(y));
            for (int x = 0; x < normalizedImage.width(); ++x)
            {
                const QRgb kPixelValue = scanLine[x];
                if (qAlpha(kPixelValue) == 0)
                {
                    continue;
                }
                ++visiblePixelCount;
                opaqueColors.insert(qRgb(
                    qRed(kPixelValue),
                    qGreen(kPixelValue),
                    qBlue(kPixelValue)));
                if (opaqueColors.size() > kMaximumFlatColorCount)
                {
                    return false;
                }
            }
        }
        return visiblePixelCount > 0;
    }

    // iconCacheKey：
    // - Generates a SHA-256 hash from the normalized image's complete bytes and the target QColor.
    // - Even if multiple QIcon objects are constructed from the same SVG, they hit the same cache.
    QByteArray iconCacheKey(
        const QImage& normalizedImage,
        const QColor& themeColor)
    {
        QByteArray signatureBytes;
        signatureBytes.reserve(
            static_cast<int>(normalizedImage.sizeInBytes()) + 16);
        signatureBytes.append(
            reinterpret_cast<const char*>(normalizedImage.constBits()),
            static_cast<qsizetype>(normalizedImage.sizeInBytes()));
        signatureBytes.append(themeColor.name(QColor::HexArgb).toUtf8());
        return QCryptographicHash::hash(
            signatureBytes,
            QCryptographicHash::Sha256);
    }

    // tintPixmap：
    // - Preserves the source image's alpha channel and outline.
    // - Replaces all visible pixels with the current theme color in one go using SourceIn.
    QPixmap tintPixmap(const QPixmap& sourcePixmap, const QColor& themeColor)
    {
        if (sourcePixmap.isNull())
        {
            return QPixmap();
        }
        QPixmap tintedPixmapValue = sourcePixmap;
        tintedPixmapValue.fill(Qt::transparent);

        QPainter painter(&tintedPixmapValue);
        painter.setCompositionMode(QPainter::CompositionMode_Source);
        painter.drawPixmap(0, 0, sourcePixmap);
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(tintedPixmapValue.rect(), themeColor);
        painter.end();
        return tintedPixmapValue;
    }

    // iconRenderSizes：
    // - Pre-render common UI sizes; subsequent drawing no longer triggers SVG parsing.
    // - Retain the reasonable sizes declared by the source bitmap and cap the maximum at 96px to prevent cache bloat.
    QList<QSize> iconRenderSizes(const QIcon& sourceIcon)
    {
        QList<QSize> renderSizes{
            QSize(16, 16),
            QSize(20, 20),
            QSize(24, 24),
            QSize(32, 32),
            QSize(48, 48),
            QSize(64, 64)
        };
        const QList<QSize> kSourceSizes =
            sourceIcon.availableSizes(QIcon::Normal, QIcon::Off);
        for (const QSize& sourceSize : kSourceSizes)
        {
            if (sourceSize.isValid() &&
                sourceSize.width() <= 96 &&
                sourceSize.height() <= 96 &&
                !renderSizes.contains(sourceSize))
            {
                renderSizes.push_back(sourceSize);
            }
        }
        std::sort(
            renderSizes.begin(),
            renderSizes.end(),
            [](const QSize& leftSize, const QSize& rightSize)
            {
                return leftSize.width() * leftSize.height() <
                    rightSize.width() * rightSize.height();
            });
        return renderSizes;
    }

    // originalIconFromProperty：
    // - On first handling, save the current icon to the QObject dynamic property;
    // - Subsequent color changes are always generated from the original icon to avoid redundant recoloring and loss of clarity.
    QIcon originalIconFromProperty(
        QObject* ownerObject,
        const char* propertyName,
        const char* lastAppliedKeyPropertyName,
        const QIcon& currentIcon)
    {
        if (ownerObject == nullptr)
        {
            return currentIcon;
        }
        const QVariant kLastAppliedKeyValue =
            ownerObject->property(lastAppliedKeyPropertyName);
        bool lastAppliedKeyValid = false;
        const qulonglong kLastAppliedKey =
            kLastAppliedKeyValue.toULongLong(&lastAppliedKeyValid);
        // If an external theme refresh replaces icons between two batches of processing, the current value is the new correct baseline.
        // Only reuse the original attributes if the current icon is still the value last written by the manager.
        if (lastAppliedKeyValid &&
            static_cast<qulonglong>(currentIcon.cacheKey()) != kLastAppliedKey)
        {
            ownerObject->setProperty(
                propertyName,
                QVariant::fromValue(currentIcon));
            return currentIcon;
        }
        const QVariant kStoredValue = ownerObject->property(propertyName);
        if (kStoredValue.isValid() && kStoredValue.canConvert<QIcon>())
        {
            return kStoredValue.value<QIcon>();
        }
        ownerObject->setProperty(propertyName, QVariant::fromValue(currentIcon));
        return currentIcon;
    }

    // rememberAppliedIconKey：
    // - Record the icon identity last written by the manager;
    // - Distinguish in the next round whether the icon is still a result of the manager's coloring or if the control has refreshed a new icon on its own.
    void rememberAppliedIconKey(
        QObject* ownerObject,
        const char* propertyName,
        const QIcon& appliedIcon)
    {
        if (ownerObject == nullptr)
        {
            return;
        }
        ownerObject->setProperty(
            propertyName,
            QVariant::fromValue<qulonglong>(appliedIcon.cacheKey()));
    }

    // directWidgetActions：
    // - Merge actions() associated with the control with its directly owned QAction objects;
    // - Prohibit recursive findChildren on every widget to prevent startup traversal from degrading to O(N²).
    QList<QAction*> directWidgetActions(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return {};
        }
        QList<QAction*> actionList = widgetPointer->actions();
        const QList<QAction*> kOwnedActionList =
            widgetPointer->findChildren<QAction*>(
                QString(),
                Qt::FindDirectChildrenOnly);
        for (QAction* actionPointer : kOwnedActionList)
        {
            if (actionPointer != nullptr &&
                !actionList.contains(actionPointer))
            {
                actionList.push_back(actionPointer);
            }
        }
        return actionList;
    }
}

ks::ui::SvgThemeIconManager& ks::ui::SvgThemeIconManager::instance()
{
    static SvgThemeIconManager manager;
    return manager;
}

ks::ui::SvgThemeIconApplyResult
ks::ui::SvgThemeIconManager::applyToApplication(
    QApplication* application,
    const QColor& themeColor,
    const bool isDefaultThemeColor,
    const std::function<void(int, int)>& progressCallback)
{
    SvgThemeIconApplyResult result;
    QElapsedTimer elapsedTimer;
    elapsedTimer.start();

    // Discard residual state from the previous round and increment the generation counter for the new request: old slices that are queued but not yet executed
    // will detect the generation mismatch upon their next execution and abort entirely, preventing old highlight colors from being written back to the control.
    IconApplySliceState& sliceState = iconApplySliceState();
    resetIconApplySliceState(sliceState);
    ++iconApplyGenerationCounter();
    const quint64 kCurrentGeneration = iconApplyGenerationCounter();
    sliceState.generation = kCurrentGeneration;

    if (application == nullptr || !themeColor.isValid())
    {
        result.elapsedMilliseconds = elapsedTimer.elapsed();
        return result;
    }

    if (!filterInstalled_)
    {
        application->installEventFilter(this);
        filterInstalled_ = true;
    }

    // Do not scan controls on first launch with default colors; only traverse and restore original images when reverting from custom colors to default.
    const bool kRestoreOriginalIcons =
        isDefaultThemeColor && customTintActive_;
    if (isDefaultThemeColor && !kRestoreOriginalIcons)
    {
        customTintActive_ = false;
        result.skippedDefaultTheme = true;
        result.elapsedMilliseconds = elapsedTimer.elapsed();
        if (progressCallback)
        {
            progressCallback(0, 0);
        }
        return result;
    }

    // The cache serves only the current accent color; switching colors releases multi-size pixmaps for the old color
    // to prevent unbounded growth of the icon cache within the process lifetime due to users repeatedly trying colors.
    if (themeColor_.isValid() && themeColor_ != themeColor)
    {
        clearThemedIconCaches();
    }
    themeColor_ = themeColor;
    customTintActive_ = !isDefaultThemeColor;
    // allWidgets() returns a raw pointer snapshot, while sharded processing yields the event loop between shards; wrap
    // everything in QPointer first to prevent dangling QWidget dereferences caused by delayed destruction during the yield.
    const QWidgetList kCurrentWidgetList = application->allWidgets();
    sliceState.pendingWidgets.reserve(kCurrentWidgetList.size());
    for (QWidget* widgetPointer : kCurrentWidgetList)
    {
        sliceState.pendingWidgets.push_back(QPointer<QWidget>(widgetPointer));
    }
    sliceState.progressCallback = progressCallback;
    result.visitedWidgetCount = static_cast<int>(sliceState.pendingWidgets.size());

    // The first batch executes synchronously, so most icons in the currently active window are recolored before the call
    // site returns. The remaining controls are filled in incrementally by the event loop. Unlike the original approach of
    // calling processEvents every 64 controls, this no longer dispatches events on the applyAppearanceSettings stack,
    // preventing queued deferred initialization or another appearance refresh from re-entering the theme refresh mid-flight.
    // Controls created during slicing are covered by the Polish event filter, ensuring no coloring is missed.
    result.recoloredIconCount =
        runIconApplySlice(kCurrentGeneration, &result.cacheHitCount);
    result.elapsedMilliseconds = elapsedTimer.elapsed();
    return result;
}

int ks::ui::SvgThemeIconManager::runIconApplySlice(
    const quint64 runGeneration,
    int* cacheHitCount)
{
    IconApplySliceState& sliceState = iconApplySliceState();
    if (sliceState.generation != runGeneration)
    {
        return 0;
    }
    sliceState.nextSliceScheduled = false;

    QElapsedTimer sliceTimer;
    sliceTimer.start();
    int recoloredCount = 0; // recoloredCount: Number of icon slots replaced or restored in this batch.
    const int kTotalWidgetCount =
        static_cast<int>(sliceState.pendingWidgets.size());
    while (sliceState.nextWidgetIndex < kTotalWidgetCount)
    {
        QWidget* const kWidgetPointer =
            sliceState.pendingWidgets.at(sliceState.nextWidgetIndex).data();
        ++sliceState.nextWidgetIndex;
        if (kWidgetPointer != nullptr)
        {
            recoloredCount += applyToWidget(kWidgetPointer, cacheHitCount);

            const QList<QAction*> kActionList =
                directWidgetActions(kWidgetPointer);
            for (QAction* actionPointer : kActionList)
            {
                if (actionPointer == nullptr ||
                    sliceState.processedActions.contains(actionPointer))
                {
                    continue;
                }
                sliceState.processedActions.insert(actionPointer);
                if (applyToAction(actionPointer, cacheHitCount))
                {
                    ++recoloredCount;
                }
            }
        }

        if ((sliceState.nextWidgetIndex % kIconApplyBudgetCheckStride) == 0 &&
            sliceTimer.elapsed() >= kIconApplySliceBudgetMilliseconds)
        {
            break;
        }
    }

    const int kProcessedWidgetCount = sliceState.nextWidgetIndex;
    const bool kSliceRunFinished = kProcessedWidgetCount >= kTotalWidgetCount;
    // Schedule the next slice before invoking the progress callback: even if the callback internally triggers another theme
    // application, slices from the old generation will exit on their own during execution and will not overwrite the new round.
    if (!kSliceRunFinished && !sliceState.nextSliceScheduled)
    {
        sliceState.nextSliceScheduled = true;
        QTimer::singleShot(
            0,
            this,
            [this, runGeneration]()
            {
                int ignoredCacheHitCount = 0; // ignoredCacheHitCount: resumed shard runs do not return to standard counting.
                (void)runIconApplySlice(runGeneration, &ignoredCacheHitCount);
            });
    }

    // The callback may include its own event pump; copy it first before invoking, then do not touch the slice state again.
    const std::function<void(int, int)> kProgressCallbackCopy =
        sliceState.progressCallback;
    if (kSliceRunFinished)
    {
        resetIconApplySliceState(sliceState);
    }
    if (kProgressCallbackCopy && kTotalWidgetCount > 0)
    {
        kProgressCallbackCopy(kProcessedWidgetCount, kTotalWidgetCount);
    }
    return recoloredCount;
}

bool ks::ui::SvgThemeIconManager::eventFilter(
    QObject* watchedObject,
    QEvent* eventObject)
{
    if (!customTintActive_ ||
        watchedObject == nullptr ||
        eventObject == nullptr)
    {
        return QObject::eventFilter(watchedObject, eventObject);
    }

    // Polish covers pages created on demand; ActionAdded covers right-click menus created at runtime.
    if (eventObject->type() == QEvent::Polish)
    {
        if (QWidget* widgetPointer = qobject_cast<QWidget*>(watchedObject))
        {
            int ignoredCacheHits = 0; // ignoredCacheHits: Lazy-loaded single controls are not recorded separately in statistics.
            (void)applyToWidget(widgetPointer, &ignoredCacheHits);
            const QList<QAction*> kActionList =
                directWidgetActions(widgetPointer);
            for (QAction* actionPointer : kActionList)
            {
                (void)applyToAction(actionPointer, &ignoredCacheHits);
            }
        }
    }
    else if (eventObject->type() == QEvent::ActionAdded)
    {
        auto* actionEvent = static_cast<QActionEvent*>(eventObject);
        int ignoredCacheHits = 0; // ignoredCacheHits: Event incremental processing is not included in batch reports.
        (void)applyToAction(actionEvent->action(), &ignoredCacheHits);
    }
    return QObject::eventFilter(watchedObject, eventObject);
}

int ks::ui::SvgThemeIconManager::applyToWidget(
    QWidget* widgetPointer,
    int* cacheHitCount)
{
    if (widgetPointer == nullptr)
    {
        return 0;
    }
    int changedCount = 0; // changedCount: Number of icon slots replaced or restored for the current control.

    if (auto* buttonPointer = qobject_cast<QAbstractButton*>(widgetPointer))
    {
        const QIcon kCurrentIcon = buttonPointer->icon();
        if (!kCurrentIcon.isNull())
        {
            const QIcon kOriginalIcon = originalIconFromProperty(
                buttonPointer,
                kOriginalButtonIconProperty,
                kLastButtonIconKeyProperty,
                kCurrentIcon);
            if (!customTintActive_)
            {
                buttonPointer->setIcon(kOriginalIcon);
                rememberAppliedIconKey(
                    buttonPointer,
                    kLastButtonIconKeyProperty,
                    kOriginalIcon);
                ++changedCount;
            }
            else
            {
                bool cacheHit = false;
                const QIcon kReplacementIcon = themedIcon(kOriginalIcon, &cacheHit);
                if (!kReplacementIcon.isNull())
                {
                    buttonPointer->setIcon(kReplacementIcon);
                    rememberAppliedIconKey(
                        buttonPointer,
                        kLastButtonIconKeyProperty,
                        kReplacementIcon);
                    ++changedCount;
                    if (cacheHit && cacheHitCount != nullptr)
                    {
                        ++(*cacheHitCount);
                    }
                }
            }
        }
    }

    if (auto* tabWidgetPointer = qobject_cast<QTabWidget*>(widgetPointer))
    {
        changedCount += applyToTabWidget(tabWidgetPointer, cacheHitCount);
    }

    // Dock/panel icons may also come from SVG; the top-level main window icon is typically a multi-color resource and will be excluded by candidate detection.
    const QIcon kCurrentWindowIcon = widgetPointer->windowIcon();
    if (widgetPointer->isWindow() && !kCurrentWindowIcon.isNull())
    {
        const QIcon kOriginalWindowIcon = originalIconFromProperty(
            widgetPointer,
            kOriginalWindowIconProperty,
            kLastWindowIconKeyProperty,
            kCurrentWindowIcon);
        if (!customTintActive_)
        {
            widgetPointer->setWindowIcon(kOriginalWindowIcon);
            rememberAppliedIconKey(
                widgetPointer,
                kLastWindowIconKeyProperty,
                kOriginalWindowIcon);
            ++changedCount;
        }
        else
        {
            bool cacheHit = false;
            const QIcon kReplacementIcon =
                themedIcon(kOriginalWindowIcon, &cacheHit);
            if (!kReplacementIcon.isNull())
            {
                widgetPointer->setWindowIcon(kReplacementIcon);
                rememberAppliedIconKey(
                    widgetPointer,
                    kLastWindowIconKeyProperty,
                    kReplacementIcon);
                ++changedCount;
                if (cacheHit && cacheHitCount != nullptr)
                {
                    ++(*cacheHitCount);
                }
            }
        }
    }
    return changedCount;
}

bool ks::ui::SvgThemeIconManager::applyToAction(
    QAction* actionPointer,
    int* cacheHitCount)
{
    if (actionPointer == nullptr || actionPointer->icon().isNull())
    {
        return false;
    }
    const QIcon kOriginalIcon = originalIconFromProperty(
        actionPointer,
        kOriginalActionIconProperty,
        kLastActionIconKeyProperty,
        actionPointer->icon());
    if (!customTintActive_)
    {
        actionPointer->setIcon(kOriginalIcon);
        rememberAppliedIconKey(
            actionPointer,
            kLastActionIconKeyProperty,
            kOriginalIcon);
        return true;
    }

    bool cacheHit = false;
    const QIcon kReplacementIcon = themedIcon(kOriginalIcon, &cacheHit);
    if (kReplacementIcon.isNull())
    {
        return false;
    }
    actionPointer->setIcon(kReplacementIcon);
    rememberAppliedIconKey(
        actionPointer,
        kLastActionIconKeyProperty,
        kReplacementIcon);
    if (cacheHit && cacheHitCount != nullptr)
    {
        ++(*cacheHitCount);
    }
    return true;
}

int ks::ui::SvgThemeIconManager::applyToTabWidget(
    QTabWidget* tabWidgetPointer,
    int* cacheHitCount)
{
    if (tabWidgetPointer == nullptr)
    {
        return 0;
    }
    int changedCount = 0; // changedCount: The actual number of tabs processed by the current QTabWidget.
    for (int tabIndex = 0; tabIndex < tabWidgetPointer->count(); ++tabIndex)
    {
        QWidget* pagePointer = tabWidgetPointer->widget(tabIndex);
        const QIcon kCurrentIcon = tabWidgetPointer->tabIcon(tabIndex);
        if (pagePointer == nullptr || kCurrentIcon.isNull())
        {
            continue;
        }
        const QIcon kOriginalIcon = originalIconFromProperty(
            pagePointer,
            kOriginalTabIconProperty,
            kLastTabIconKeyProperty,
            kCurrentIcon);
        if (!customTintActive_)
        {
            tabWidgetPointer->setTabIcon(tabIndex, kOriginalIcon);
            rememberAppliedIconKey(
                pagePointer,
                kLastTabIconKeyProperty,
                kOriginalIcon);
            ++changedCount;
            continue;
        }

        bool cacheHit = false;
        const QIcon kReplacementIcon = themedIcon(kOriginalIcon, &cacheHit);
        if (kReplacementIcon.isNull())
        {
            continue;
        }
        tabWidgetPointer->setTabIcon(tabIndex, kReplacementIcon);
        rememberAppliedIconKey(
            pagePointer,
            kLastTabIconKeyProperty,
            kReplacementIcon);
        ++changedCount;
        if (cacheHit && cacheHitCount != nullptr)
        {
            ++(*cacheHitCount);
        }
    }
    return changedCount;
}

QIcon ks::ui::SvgThemeIconManager::themedIcon(
    const QIcon& sourceIcon,
    bool* cacheHitOut)
{
    if (cacheHitOut != nullptr)
    {
        *cacheHitOut = false;
    }
    if (sourceIcon.isNull())
    {
        return QIcon();
    }

    // First, perform a cheap cache lookup by source icon identity: when the same QIcon (including implicitly shared copies) appears
    // across multiple controls, skip the 24x24 re-rendering, per-pixel candidate determination, and SHA-256 pixel signature.
    QHash<qint64, QIcon>& sourceKeyedIconCache = cachedIconsBySourceKey();
    const qint64 kSourceIconKey = sourceIcon.cacheKey();
    const auto kSourceCachedIterator = sourceKeyedIconCache.constFind(kSourceIconKey);
    if (kSourceCachedIterator != sourceKeyedIconCache.constEnd())
    {
        const QIcon kSourceCachedIcon = kSourceCachedIterator.value();
        if (cacheHitOut != nullptr && !kSourceCachedIcon.isNull())
        {
            *cacheHitOut = true;
        }
        return kSourceCachedIcon;
    }

    // rememberSourceKeyedResult：
    // - Register the current result in the source icon identity cache; an empty QIcon indicates 'not a candidate, no coloring';
    // - Return the input parameter as-is to allow a single-line cleanup at each exit point.
    const auto kRememberSourceKeyedResult =
        [&sourceKeyedIconCache, kSourceIconKey](const QIcon& resolvedIcon) -> QIcon
        {
            if (sourceKeyedIconCache.size() >= kMaximumSourceIconCacheEntries)
            {
                sourceKeyedIconCache.clear();
            }
            sourceKeyedIconCache.insert(kSourceIconKey, resolvedIcon);
            return resolvedIcon;
        };

    const QImage kNormalizedImage = normalizedIconImage(sourceIcon);
    if (!isThemeTintCandidate(sourceIcon, kNormalizedImage))
    {
        return kRememberSourceKeyedResult(QIcon());
    }

    const QByteArray kCacheKey = iconCacheKey(kNormalizedImage, themeColor_);
    const auto kCachedIterator = cachedTintedIcons().constFind(kCacheKey);
    if (kCachedIterator != cachedTintedIcons().constEnd())
    {
        if (cacheHitOut != nullptr)
        {
            *cacheHitOut = true;
        }
        return kRememberSourceKeyedResult(kCachedIterator.value());
    }

    QIcon replacementIcon; // replacementIcon: Final theme icon containing common sizes.
    const QList<QSize> kRenderSizes = iconRenderSizes(sourceIcon);
    for (const QSize& renderSize : kRenderSizes)
    {
        const QPixmap kSourcePixmap =
            sourceIcon.pixmap(renderSize, QIcon::Normal, QIcon::Off);
        const QPixmap kTintedPixmapValue =
            tintPixmap(kSourcePixmap, themeColor_);
        if (!kTintedPixmapValue.isNull())
        {
            replacementIcon.addPixmap(
                kTintedPixmapValue,
                QIcon::Normal,
                QIcon::Off);
        }
    }
    if (!replacementIcon.isNull())
    {
        cachedTintedIcons().insert(kCacheKey, replacementIcon);
    }
    return kRememberSourceKeyedResult(replacementIcon);
}
