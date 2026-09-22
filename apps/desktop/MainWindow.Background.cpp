#include "MainWindow.h"
#include "ui/styles/UiStyleSheet.h"

#include <QTimer>
#include <QCoreApplication>
#include <QFileInfo>
#include <QPainter>
#include <QPalette>
#include <QPointF>
#include <QPixmap>
#include <QPointer>
#include <QRectF>
#include <QImage>
#include <QThreadPool>
#include <QMetaObject>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "include/ads/FloatingDockContainer.h"
#include "ui/DockTabInteraction.h"
#include "Theme.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <vector>
#include <TlHelp32.h>

#include "MainWindow.BackgroundSupport.h"
#include "MainWindow.DockTabsSupport.h"
#include "MainWindow.NativeFrameSupport.h"

namespace ksword::ui::main_window
{
    // normalizeOpacityPercent:
    // - Clamp opacity values to the 0~100 range to prevent invalid parameters from affecting rendering.
    // Invocation: Call before generating the background brush.
    // Parameter rawOpacityPercent: raw opacity value.
    // Returns: Valid opacity value.
    int normalizeOpacityPercent(const int rawOpacityPercent)
    {
        if (rawOpacityPercent < 0)
        {
            return 0;
        }
        if (rawOpacityPercent > 100)
        {
            return 100;
        }
        return rawOpacityPercent;
    }

    // kMaxBlurSourceEdgePixels:
    // - Downsample the background image's long edge to this limit before blurring.
    // - Box blur cost scales linearly with pixel count; blurring a 4K wallpaper directly causes visible lag when dragging the slider on the settings page.
    // - The blur result itself is a low-frequency signal; scaling it back to the window size during rendering does not expose downsampling artifacts.
    constexpr int kMaxBlurSourceEdgePixels = 1280;

    // kMaxBlurRadiusRatio:
    // - Ratio of the blur radius corresponding to 100% blur strength to the longer side of the downsampled image;
    // - Use a ratio instead of fixed pixels to ensure consistent visual appearance across different resolutions at the same blur level.
    constexpr double kMaxBlurRadiusRatio = 0.06;

    // kBlurPassCount:
    // - Number of repeated box-blur passes; three passes make the square kernel approximate a Gaussian closely enough to be visually indistinguishable.
    constexpr int kBlurPassCount = 3;

    // applyBoxBlurPass:
    // - Performs a single 'horizontal + vertical' box blur on an ARGB32_Premultiplied image;
    // - Under premultiplied alpha, each channel can be independently linearly averaged, so a per-channel sliding window suffices; no
    //   need to un-premultiply first (un-premultiplying would introduce significant quantization errors on near-transparent pixels).
    // Call site: invoked in a loop by iteration count within buildBlurredPixmap.
    // Input parameter targetImage: the image to be blurred in-place; must be in Format_ARGB32_Premultiplied format.
    // Input radiusPixels: blur radius (in pixels) for a single pass; returns immediately if <= 0.
    void applyBoxBlurPass(QImage& targetImage, const int radiusPixels)
    {
        if (radiusPixels <= 0
            || targetImage.isNull()
            || targetImage.format() != QImage::Format_ARGB32_Premultiplied)
        {
            return;
        }

        const int kImageWidth = targetImage.width();
        const int kImageHeight = targetImage.height();
        if (kImageWidth <= 0 || kImageHeight <= 0)
        {
            return;
        }

        // blurAxis: Performs sliding window averaging along a single direction.
        // Horizontal and vertical operations differ only by the byte stride between 'next pixel' and 'next line', so
        // they share the same implementation to avoid drift between two nearly identical boundary-handling code paths.
        const auto kBlurAxis = [](uchar* const imageBits,
            const int lineCount,
            const int lineLength,
            const int lineStrideBytes,
            const int pixelStrideBytes,
            const int passRadiusPixels)
            {
                if (lineLength <= 1)
                {
                    return;
                }

                // windowSize usage: pixel count for the box-style window overlay, with passRadiusPixels on each side of the center pixel.
                const int kWindowSize = passRadiusPixels * 2 + 1;
                std::vector<QRgb> lineBuffer(static_cast<size_t>(lineLength));

                for (int lineIndex = 0; lineIndex < lineCount; ++lineIndex)
                {
                    uchar* const kLineStart =
                        imageBits + static_cast<size_t>(lineIndex) * static_cast<size_t>(lineStrideBytes);

                    // Copy the entire line into the buffer first: the sliding window reads while writing, so in-place reads would fetch newly overwritten values.
                    for (int offset = 0; offset < lineLength; ++offset)
                    {
                        lineBuffer[static_cast<size_t>(offset)] = *reinterpret_cast<const QRgb*>(
                            kLineStart + static_cast<size_t>(offset) * static_cast<size_t>(pixelStrideBytes));
                    }

                    // initialize window: clamp out-of-bounds positions to edge pixels; otherwise, the window
                    // accumulates only partial pixels at the ends, leaving a dark band along the image border.
                    int sumRed = 0;
                    int sumGreen = 0;
                    int sumBlue = 0;
                    int sumAlpha = 0;
                    for (int windowOffset = -passRadiusPixels; windowOffset <= passRadiusPixels; ++windowOffset)
                    {
                        const QRgb kSamplePixel =
                            lineBuffer[static_cast<size_t>(std::clamp(windowOffset, 0, lineLength - 1))];
                        sumRed += qRed(kSamplePixel);
                        sumGreen += qGreen(kSamplePixel);
                        sumBlue += qBlue(kSamplePixel);
                        sumAlpha += qAlpha(kSamplePixel);
                    }

                    for (int offset = 0; offset < lineLength; ++offset)
                    {
                        *reinterpret_cast<QRgb*>(
                            kLineStart + static_cast<size_t>(offset) * static_cast<size_t>(pixelStrideBytes)) =
                            qRgba(
                                sumRed / kWindowSize,
                                sumGreen / kWindowSize,
                                sumBlue / kWindowSize,
                                sumAlpha / kWindowSize);

                        const QRgb kLeavingPixel =
                            lineBuffer[static_cast<size_t>(std::clamp(offset - passRadiusPixels, 0, lineLength - 1))];
                        const QRgb kEnteringPixel =
                            lineBuffer[static_cast<size_t>(std::clamp(offset + passRadiusPixels + 1, 0, lineLength - 1))];
                        sumRed += qRed(kEnteringPixel) - qRed(kLeavingPixel);
                        sumGreen += qGreen(kEnteringPixel) - qGreen(kLeavingPixel);
                        sumBlue += qBlue(kEnteringPixel) - qBlue(kLeavingPixel);
                        sumAlpha += qAlpha(kEnteringPixel) - qAlpha(kLeavingPixel);
                    }
                }
            };

        // bytesPerLine may include row padding; therefore, vertical traversal must use it as the stride and cannot assume width*4.
        const int kBytesPerLine = static_cast<int>(targetImage.bytesPerLine());
        uchar* const kImageBits = targetImage.bits();
        if (kImageBits == nullptr)
        {
            return;
        }
        kBlurAxis(kImageBits, kImageHeight, kImageWidth, kBytesPerLine, 4, radiusPixels);
        kBlurAxis(kImageBits, kImageWidth, kImageHeight, 4, kBytesPerLine, radiusPixels);
    }

    // buildBlurredPixmap:
    // - Generate a blurred copy of the background image with a 'glass blur radius' intensity of 0~100;
    // - Shared between the main window's root container and floating dock brush to ensure consistent appearance and blur only once.
    // Invocation: mainWindow::refreshBackgroundImageBlurCache is called when the radius or source image changes.
    // Input sourcePixmap: Decoded background image original.
    // Parameter blurRadiusPercent: blur intensity percentage (0–100).
    // Returns: the blurred pixmap; if the intensity is 0 or the source pixmap is null, an empty pixmap is returned, indicating the original pixmap should be used directly.
    QPixmap buildBlurredPixmap(const QPixmap& sourcePixmap, const int blurRadiusPercent)
    {
        const int kNormalizedPercent = normalizeOpacityPercent(blurRadiusPercent);
        if (sourcePixmap.isNull() || kNormalizedPercent <= 0)
        {
            return QPixmap();
        }

        QImage workingImage = sourcePixmap.toImage();
        if (workingImage.isNull())
        {
            return QPixmap();
        }

        const int kSourceLongEdge = std::max(workingImage.width(), workingImage.height());
        if (kSourceLongEdge > kMaxBlurSourceEdgePixels)
        {
            workingImage = (workingImage.width() >= workingImage.height())
                ? workingImage.scaledToWidth(kMaxBlurSourceEdgePixels, Qt::SmoothTransformation)
                : workingImage.scaledToHeight(kMaxBlurSourceEdgePixels, Qt::SmoothTransformation);
        }
        if (workingImage.format() != QImage::Format_ARGB32_Premultiplied)
        {
            workingImage = workingImage.convertToFormat(QImage::Format_ARGB32_Premultiplied);
        }
        if (workingImage.isNull())
        {
            return QPixmap();
        }

        // totalRadiusPixels usage: Total blur radius corresponding to the current intensity.
        // After distributing the box blur across multiple passes, the radius per pass must be at least 1; otherwise, the entire loop becomes a no-op.
        const int kWorkingLongEdge = std::max(workingImage.width(), workingImage.height());
        const int kTotalRadiusPixels = static_cast<int>(std::lround(
            static_cast<double>(kWorkingLongEdge)
            * kMaxBlurRadiusRatio
            * (static_cast<double>(kNormalizedPercent) / 100.0)));
        if (kTotalRadiusPixels <= 0)
        {
            return QPixmap();
        }
        const int kPassRadiusPixels = std::max(1, kTotalRadiusPixels / kBlurPassCount);

        for (int passIndex = 0; passIndex < kBlurPassCount; ++passIndex)
        {
            applyBoxBlurPass(workingImage, kPassRadiusPixels);
        }
        return QPixmap::fromImage(workingImage);
    }

    // buildBackgroundBrush:
    // - Compose a brush texture from 'solid background + optional background image + transparency';
    // - For use only by floating Dock containers still using independent palettes for painting.
    // Invocation: mainWindow::applyFloatingDockContainerAppearance.
    // Input parameter windowSize: target window size.
    // Input parameter baseColor: theme base color (dark black, light white);
    // Input sourceImage: cached image decoded in thread pool and converted by UI thread; may be null.
    // Input parameter imageOpacityPercent: background image opacity (0~100).
    // Returns: a brush that can be directly set to QPalette::Window.
    QBrush buildBackgroundBrush(
        const QSize& windowSize,
        const QColor& baseColor,
        const QPixmap* sourceImage,
        const int imageOpacityPercent)
    {
        const QSize kSafeSize = windowSize.isValid() ? windowSize : QSize(1, 1);
        const int kNormalizedOpacityPercent = normalizeOpacityPercent(imageOpacityPercent);
        // effectiveSourceImage usage: skip compositing when opacity is zero, while avoiding any file path access.
        const QPixmap* effectiveSourceImage = kNormalizedOpacityPercent > 0 ? sourceImage : nullptr;
        const quint64 kSourceImageCacheKey =
            effectiveSourceImage == nullptr ? 0 : effectiveSourceImage->cacheKey();

        // During main window resize, identical size or adjacent layout events are typically received consecutively.
        // Cache the most recent composite image to avoid repeatedly allocating full-window pixel buffers and performing smooth scaling again.
        static QSize cachedSize;
        static QColor cachedBaseColor;
        static int cachedOpacityPercent = -1;
        static quint64 cachedSourceImageCacheKey = 0;
        static QPixmap cachedComposedPixmap;
        const bool kCacheHit =
            cachedSize == kSafeSize
            && cachedBaseColor == baseColor
            && cachedOpacityPercent == kNormalizedOpacityPercent
            && cachedSourceImageCacheKey == kSourceImageCacheKey
            && !cachedComposedPixmap.isNull();
        if (kCacheHit)
        {
            return QBrush(cachedComposedPixmap);
        }

        QPixmap composedPixmap(kSafeSize);
        composedPixmap.fill(baseColor);
        if (effectiveSourceImage != nullptr)
        {
            QPainter painter(&composedPixmap);
            painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
            painter.setOpacity(static_cast<double>(kNormalizedOpacityPercent) / 100.0);

            // scaledImageSize: Calculates the scaled size using the 'cover entire window' strategy.
            QSizeF scaledImageSize = effectiveSourceImage->size();
            scaledImageSize.scale(kSafeSize, Qt::KeepAspectRatioByExpanding);

            const QRectF kTargetRect(
                (static_cast<double>(kSafeSize.width()) - scaledImageSize.width()) / 2.0,
                (static_cast<double>(kSafeSize.height()) - scaledImageSize.height()) / 2.0,
                scaledImageSize.width(),
                scaledImageSize.height());

            painter.drawPixmap(
                kTargetRect,
                *effectiveSourceImage,
                QRectF(QPointF(0, 0), effectiveSourceImage->size()));
        }

        cachedSize = kSafeSize;
        cachedBaseColor = baseColor;
        cachedOpacityPercent = kNormalizedOpacityPercent;
        cachedSourceImageCacheKey = kSourceImageCacheKey;
        cachedComposedPixmap = composedPixmap;
        return QBrush(composedPixmap);
    }
}

using namespace ksword::ui::main_window;

void MainWindow::queueBackgroundImageValidation(const QString& rawImagePath)
{
    // cacheKey usage: Used for memory comparison only; trimmed does not access UNC or offline drives.
    const QString kCacheKey = rawImagePath.trimmed();
    ++backgroundImageValidationGeneration_;
    // validationGeneration usage: Evict old results replaced by updated paths when background tasks return.
    const quint64 kValidationGeneration = backgroundImageValidationGeneration_;
    backgroundImageCacheKey_ = kCacheKey;
    backgroundImageResolvedPath_.clear();
    backgroundImagePixmap_ = QPixmap();
    backgroundImageReady_ = false;
    // The blurred copy belongs to the old image; the path change must invalidate it, otherwise the new image will briefly display the previous image's blur result before decoding.
    backgroundImageBlurredPixmap_ = QPixmap();
    backgroundImageBlurRadiusApplied_ = -1;
    backgroundImageBlurSourceCacheKey_ = 0;
    if (kCacheKey.isEmpty())
    {
        return;
    }

    // guardedWindow usage: Background tasks may outlive the main window; verify lifecycle before re-entrance.
    const QPointer<MainWindow> kGuardedWindow(this);
    QThreadPool::globalInstance()->start(
        [kGuardedWindow, rawImagePath, kCacheKey, kValidationGeneration]()
        {
            // The following path resolution, QFileInfo probing, and image decoding are all executed in the thread pool.
            // Unreachable UNC paths only occupy background tasks and do not block the Qt UI event loop.
            const QString kResolvedImagePath =
                ks::settings::resolveBackgroundImagePathForLoad(rawImagePath);
            QImage decodedImage;
            if (!kResolvedImagePath.trimmed().isEmpty())
            {
                // imageFileInfo purpose: Verify the target exists, is a regular file, and is readable.
                const QFileInfo kImageFileInfo(kResolvedImagePath);
                if (kImageFileInfo.exists()
                    && kImageFileInfo.isFile()
                    && kImageFileInfo.isReadable())
                {
                    decodedImage.load(kResolvedImagePath);
                }
            }

            QCoreApplication* const kAppInstance = QCoreApplication::instance();
            if (kAppInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                kAppInstance,
                [kGuardedWindow,
                    kCacheKey,
                    kResolvedImagePath,
                    kValidationGeneration,
                    decodedImage]()
                {
                    if (kGuardedWindow == nullptr)
                    {
                        return;
                    }
                    MainWindow* const kMainWindow = kGuardedWindow.data();
                    const bool kResultIsCurrent =
                        kMainWindow->backgroundImageValidationGeneration_ == kValidationGeneration
                        && kMainWindow->backgroundImageCacheKey_.compare(
                            kCacheKey,
                            Qt::CaseInsensitive) == 0;
                    if (!kResultIsCurrent)
                    {
                        return;
                    }

                    kMainWindow->backgroundImageResolvedPath_ = kResolvedImagePath;
                    kMainWindow->backgroundImagePixmap_ = decodedImage.isNull()
                        ? QPixmap()
                        : QPixmap::fromImage(decodedImage);
                    // nextReady usage: Transparent Dock is allowed only if both path validation and image decoding succeed.
                    const bool kNextReady = !kMainWindow->backgroundImagePixmap_.isNull();
                    const bool kReadinessChanged =
                        kMainWindow->backgroundImageReady_ != kNextReady;
                    kMainWindow->backgroundImageReady_ = kNextReady;
                    if (!kReadinessChanged)
                    {
                        return;
                    }

                    // Asynchronous results set the rebuild-once flag only; reapplying the same settings does not re-verify the path.
                    kMainWindow->backgroundReadinessRefreshPending_ = true;
                    kMainWindow->applyAppearanceSettings(
                        kMainWindow->currentAppearanceSettings_,
                        QStringLiteral("背景图异步验证完成"));
                },
                Qt::QueuedConnection);
        });
}

bool MainWindow::isCachedBackgroundImageReady(const QString& rawImagePath) const
{
    // requestedCacheKey usage: Only normalizes leading/trailing whitespace; does not parse paths or query the file system.
    const QString kRequestedCacheKey = rawImagePath.trimmed();
    return !kRequestedCacheKey.isEmpty()
        && backgroundImageCacheKey_.compare(kRequestedCacheKey, Qt::CaseInsensitive) == 0
        && backgroundImageReady_
        && !backgroundImagePixmap_.isNull();
}

bool MainWindow::shouldRenderTransparentDockContent() const
{
    return isCachedBackgroundImageReady(currentAppearanceSettings_.backgroundImagePath)
        || testAttribute(Qt::WA_TranslucentBackground);
}

const QPixmap* MainWindow::cachedBackgroundImage(const QString& rawImagePath) const
{
    if (!isCachedBackgroundImageReady(rawImagePath))
    {
        return nullptr;
    }
    // The blurred copy replaces the original only when the 'Glass Blur Radius' is > 0 and has been generated by refreshBackgroundImageBlurCache.
    // Both the main window root container and floating dock brush use this path, ensuring they always reference the same background image.
    return backgroundImageBlurredPixmap_.isNull()
        ? &backgroundImagePixmap_
        : &backgroundImageBlurredPixmap_;
}

void MainWindow::scheduleWindowBackdropRefresh()
{
    // Resample by window position only when system acrylic is active; otherwise, ignore.
    if (backdropMaterialState_ != static_cast<int>(BackdropBlurKind::kAcrylic)
        || backdropRefreshQueued_)
    {
        return;
    }

    // Drag and resize operations generate continuous events; merge them here into a single delayed refresh:
    // - Ensures correct rendering after action completion while avoiding repeated feature combination dispatches during dragging.
    backdropRefreshQueued_ = true;
    QTimer::singleShot(kBackdropRefreshThrottleMs, this, [this]()
        {
            backdropRefreshQueued_ = false;
            if (backdropMaterialState_ != static_cast<int>(BackdropBlurKind::kAcrylic))
            {
                return;
            }
            // Only re-dispatch combined features to restore material states that may have been downgraded by the system.
            // Do not trigger root container repaint here: ACRYLIC is generated by DWM in the compositor; no
            // application-side pixels changed, while a full tree repaint in transparent mode takes ~41ms.
            // Scenarios truly requiring background redraw (e.g., size changes) are handled by resizeEvent's own update.
            refreshWindowBackdropMaterial();
        });
}

void MainWindow::refreshWindowBackdropMaterial()
{
    // translucencyActive: Whether the window declared per-pixel transparency at startup.
    const bool kTranslucencyActive = testAttribute(Qt::WA_TranslucentBackground);
    const int kNormalizedOpacityPercent = normalizeOpacityPercent(
        currentAppearanceSettings_.backgroundOpacityPercent);
    // sourceImage usage: Only reads the decoded cache; material decision logic does not access the file system.
    const QPixmap* sourceImage = kNormalizedOpacityPercent > 0
        ? cachedBackgroundImage(currentAppearanceSettings_.backgroundImagePath)
        : nullptr;

    // Material decision based on explicit user selection.
    // - acrylic: always acrylic blur; desktop: always direct desktop transparency;
    // - auto (default): Use image transparency if a background image exists; otherwise, use acrylic frosted glass.
    // Compatibility: Old config values 'blur' and 'mica' both meant 'frosted'; unify migration to Acrylic—on Windows
    // 11, traditional BLURBEHIND has degraded to pure transparency, making Acrylic the only true frosted effect.
    const QString kTranslucencyMaterialMode =
        currentAppearanceSettings_.backgroundTranslucencyMaterial.trimmed().toLower();
    BackdropBlurKind blurKind = BackdropBlurKind::kNone;
    if (kTranslucencyActive)
    {
        if (kTranslucencyMaterialMode == QStringLiteral("acrylic")
            || kTranslucencyMaterialMode == QStringLiteral("blur")
            || kTranslucencyMaterialMode == QStringLiteral("mica"))
        {
            blurKind = BackdropBlurKind::kAcrylic;
        }
        else if (kTranslucencyMaterialMode == QStringLiteral("desktop"))
        {
            blurKind = BackdropBlurKind::kNone;
        }
        else
        {
            blurKind = (sourceImage == nullptr)
                ? BackdropBlurKind::kAcrylic
                : BackdropBlurKind::kNone;
        }
    }

    // acrylicMaterialActive usage: Whether the system acrylic material is actually active.
    // When active, coloring is composited by the system; the root container must be nearly fully transparent.
    // If ineffective (on older systems or due to call failure), fall back to a custom-drawn color layer to ensure foreground text remains readable.
    const bool kAcrylicMaterialActive = applyMainWindowBackdropMaterial(blurKind);
    if (mainRootContainer_ != nullptr)
    {
        static_cast<MainWindowBackgroundWidget*>(mainRootContainer_)->setTranslucentMode(
            kTranslucencyActive,
            !kAcrylicMaterialActive,
            ks::settings::tintAlphaFromOpacityPercent(
                currentAppearanceSettings_.desktopTintOpacityPercent));
    }
}

void MainWindow::refreshBackgroundImageBlurCache()
{
    const int kBlurRadiusPercent = normalizeOpacityPercent(
        currentAppearanceSettings_.backgroundBlurRadiusPercent);
    // sourceCacheKey usage: cacheKey must change after image replacement or re-decoding to evict stale blurred copies.
    // Comparing only the radius would cause the old blurred result to be reused when the path changes but the radius remains the same.
    const quint64 kSourceCacheKey = backgroundImagePixmap_.isNull()
        ? 0
        : backgroundImagePixmap_.cacheKey();
    if (backgroundImageBlurRadiusApplied_ == kBlurRadiusPercent
        && backgroundImageBlurSourceCacheKey_ == kSourceCacheKey)
    {
        return;
    }

    backgroundImageBlurRadiusApplied_ = kBlurRadiusPercent;
    backgroundImageBlurSourceCacheKey_ = kSourceCacheKey;
    // Do not generate a copy when the radius is 0: cachedBackgroundImage falls back to decoding the original image, incurring zero additional memory and time.
    backgroundImageBlurredPixmap_ = (kBlurRadiusPercent > 0)
        ? buildBlurredPixmap(backgroundImagePixmap_, kBlurRadiusPercent)
        : QPixmap();
}

void MainWindow::rebuildWindowBackgroundBrush(const bool includeBackgroundImage)
{
    // Solid background and background image compositing both use an independent main background color; if not customized, fall back to the current light/dark theme's default color.
    const QColor kBaseColor = ksword_theme::mainBackgroundColor();

    // The blurred copy must be refreshed before retrieving any cachedBackgroundImage:
    // The root container, floating Dock, and material decision in this call chain will all read this cache.
    refreshBackgroundImageBlurCache();

    const int kNormalizedOpacityPercent = normalizeOpacityPercent(
        currentAppearanceSettings_.backgroundOpacityPercent);
    // sourceImage usage: Read only from the asynchronous decode cache; theme refreshes do not access the original path again.
    const QPixmap* sourceImage = includeBackgroundImage && kNormalizedOpacityPercent > 0
        ? cachedBackgroundImage(currentAppearanceSettings_.backgroundImagePath)
        : nullptr;

    // translucencyActive: The window is declared as per-pixel transparent at startup per configuration.
    // At this point, the background layer is rendered by the root container in pass-through mode; the main window itself no longer fills an opaque background.
    const bool kTranslucencyActive = testAttribute(Qt::WA_TranslucentBackground);
    refreshWindowBackdropMaterial();
    if (mainRootContainer_ != nullptr)
    {
        static_cast<MainWindowBackgroundWidget*>(mainRootContainer_)->setBackground(
            kBaseColor,
            sourceImage,
            kNormalizedOpacityPercent);
    }

    QPalette mainPalette = palette();
    mainPalette.setColor(QPalette::Window, kBaseColor);
    setPalette(mainPalette);
    setAutoFillBackground(!kTranslucencyActive);

    if (pDockManager_ != nullptr)
    {
        QPalette dockPalette = pDockManager_->palette();
        dockPalette.setColor(QPalette::Window, kBaseColor);
        pDockManager_->setPalette(dockPalette);
        // DockManager is responsible only for the transparent content layer; the background is uniformly rendered by the root container.
        pDockManager_->setAutoFillBackground(false);
    }
}

void MainWindow::applyFloatingDockContainerAppearance(ads::CFloatingDockContainer* floatingWidget) const
{
    if (floatingWidget == nullptr)
    {
        return;
    }

    const bool kDarkModeEnabled = isDarkModeEffective(currentAppearanceSettings_);
    const QColor kBaseColor = ksword_theme::mainBackgroundColor();
    const bool kEnableDockContentTransparency =
        isCachedBackgroundImageReady(currentAppearanceSettings_.backgroundImagePath);
    // sourceImage usage: Floating container reuses thread pool decoding results; no path probing or file loading is performed.
    const QPixmap* sourceImage =
        cachedBackgroundImage(currentAppearanceSettings_.backgroundImagePath);

    // floatingSize usage: Current size of the floating container; defaults to at least 1x1 if invalid to prevent brush construction failure.
    const QSize kFloatingSize = floatingWidget->size().isValid() ? floatingWidget->size() : QSize(1, 1);
    const QBrush kBackgroundBrush = buildBackgroundBrush(
        kFloatingSize,
        kBaseColor,
        sourceImage,
        currentAppearanceSettings_.backgroundOpacityPercent);

    QPalette floatingPalette = floatingWidget->palette();
    floatingPalette.setColor(QPalette::Window, kBaseColor);
    floatingPalette.setBrush(QPalette::Window, kBackgroundBrush);
    floatingPalette.setColor(
        QPalette::WindowText,
        ksword_theme::mainBackgroundTextColor());
    floatingWidget->setPalette(floatingPalette);
    floatingWidget->setAutoFillBackground(true);
    floatingWidget->setAttribute(Qt::WA_StyledBackground, false);

    // Floating windows are top-level independent windows and do not inherit the mainWindow's local stylesheet;
    // Explicitly reuse the same appearance style here to ensure consistent rules for Tabs, TitleBar, and content areas.
    const QString kAppearanceStyleSheet =
        kQssMainWindowTabWidget
        + kQssMainWindowDockStyle
        + buildAppearanceOverlayStyleSheet(
            currentAppearanceSettings_,
            kDarkModeEnabled,
            kEnableDockContentTransparency);
    floatingWidget->setStyleSheet(kAppearanceStyleSheet);
    refreshAdsDockTabVisualIdentities(floatingWidget);

    ads::CDockContainerWidget* dockContainer = floatingWidget->dockContainer();
    if (dockContainer != nullptr)
    {
        QPalette dockContainerPalette = dockContainer->palette();
        dockContainerPalette.setColor(QPalette::Window, kBaseColor);
        dockContainerPalette.setBrush(QPalette::Window, kBackgroundBrush);
        dockContainer->setPalette(dockContainerPalette);
        dockContainer->setAutoFillBackground(true);
        dockContainer->setAttribute(Qt::WA_StyledBackground, false);
    }
}
