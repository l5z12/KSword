#pragma once

// Implementation details shared by mainWindow's responsibility-specific units.
// Public window API remains in mainWindow.h.
#include <QColor>
#include <QPixmap>
#include <QWidget>
#include <QPainter>
#include <QPaintEvent>
#include <algorithm>

class MainWindow;

namespace ksword::ui::main_window
{
    class MainWindowBackgroundWidget;

    // kTranslucentTintAlpha:
    // - Default theme-tint opacity (0~255) in translucent mode when no background image is set;
    // - Serves solely as an initial value before appearance configuration is applied; at runtime, it is overridden by the 'translucent tint opacity' setting;
    // - Lower values allow more desktop transparency; higher values improve foreground readability.
    inline constexpr int kTranslucentTintAlpha = 165;

    int normalizeOpacityPercent(const int rawOpacityPercent);

    // The root container owns background painting and uses its actual rect for
    // centered aspect-fill, including during startup and native window resize.
    class MainWindowBackgroundWidget final : public QWidget
    {
    public:
        explicit MainWindowBackgroundWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setAutoFillBackground(false);
            setAttribute(Qt::WA_StyledBackground, false);
            setAttribute(Qt::WA_OpaquePaintEvent, true);
        }

        void setBackground(
            const QColor& baseColor,
            const QPixmap* sourceImage,
            const int imageOpacityPercent)
        {
            const int kNormalizedOpacityPercent = normalizeOpacityPercent(imageOpacityPercent);
            const quint64 kSourceImageCacheKey = sourceImage == nullptr ? 0 : sourceImage->cacheKey();
            if (baseColor_ == baseColor
                && imageOpacityPercent_ == kNormalizedOpacityPercent
                && sourceImageCacheKey_ == kSourceImageCacheKey)
            {
                return;
            }

            baseColor_ = baseColor;
            imageOpacityPercent_ = kNormalizedOpacityPercent;
            sourceImageCacheKey_ = kSourceImageCacheKey;
            sourceImage_ = sourceImage == nullptr ? QPixmap() : *sourceImage;
            update();
        }

        // setTranslucentMode:
        // - Toggle the 'background transparent penetration' rendering mode;
        // - When in translucent mode, the background layer is no longer filled; transparency is determined by the background image's alpha or system material.
        // - Requires the top-level window to have WA_TranslucentBackground enabled to achieve actual transparency effects.
        // Parameter translucentEnabled: whether to enter translucent rendering mode.
        // Input paintTintWhenNoImage: whether to self-draw the tint layer when no background image is present.
        //   Must pass false when acrylic is composited and tinted by the system; otherwise, double-layer tinting will cause blurriness.
        // Input parameter tintAlpha: opacity of the custom-drawn tint layer (0–255), from the 'Direct Tint Opacity' setting.
        void setTranslucentMode(
            const bool translucentEnabled,
            const bool paintTintWhenNoImage,
            const int tintAlpha)
        {
            // Purpose of hitTestSafeTintAlpha: layered windows perform input pass-through on pixels with alpha==0. If the pass-through
            // intensity is set to 0 and rendered as 0, the entire window loses mouse responsiveness, so the lower bound is clamped to 1.
            const int kHitTestSafeTintAlpha = std::clamp(tintAlpha, 1, 255);
            if (translucentMode_ == translucentEnabled
                && paintTintWhenNoImage_ == paintTintWhenNoImage
                && tintAlpha_ == kHitTestSafeTintAlpha)
            {
                return;
            }
            translucentMode_ = translucentEnabled;
            paintTintWhenNoImage_ = paintTintWhenNoImage;
            tintAlpha_ = kHitTestSafeTintAlpha;
            // Transparent rendering leaves transparent pixels; the 'fully opaque rendering' performance assumption must be abandoned.
            setAttribute(Qt::WA_OpaquePaintEvent, !translucentEnabled);
            update();
        }

    protected:
        void paintEvent(QPaintEvent* event) override
        {
            QPainter painter(this);
            if (event != nullptr)
            {
                painter.setClipRegion(event->region());
            }

            // hasBackgroundImage usage: Distinguishes between two rendering paths in translucent mode.
            const bool kHasBackgroundImage = !sourceImage_.isNull() && imageOpacityPercent_ > 0;
            if (translucentMode_)
            {
                // hitTestFloorColor usage: Replaces 'fully transparent' background color.
                // Layered windows pass mouse input through pixels with alpha==0 to the window behind
                // them. Use a minimum alpha of 1 for translucent painting: the visual difference is
                // imperceptible, but the entire window can still receive mouse messages.
                QColor hitTestFloorColor = baseColor_;
                hitTestFloorColor.setAlpha(1);

                painter.setCompositionMode(QPainter::CompositionMode_Source);
                if (kHasBackgroundImage)
                {
                    // When a background image exists: the base layer is nearly fully transparent, with the image's own alpha determining the transparency level.
                    painter.fillRect(rect(), hitTestFloorColor);
                }
                else if (paintTintWhenNoImage_)
                {
                    // No background image and system frosted effect unavailable (including user-selected 'transparent desktop').
                    // Custom-drawn semi-transparent tint layer; opacity is determined by the 'direct tint opacity' setting:
                    // low values favor direct desktop visibility, while high values favor foreground text readability.
                    QColor tintColor = baseColor_;
                    tintColor.setAlpha(tintAlpha_);
                    painter.fillRect(rect(), tintColor);
                }
                else
                {
                    // No background image and system Acrylic is active: coloring is handled by
                    // system composition; here we only retain the alpha lower bound for hit tests.
                    painter.fillRect(rect(), hitTestFloorColor);
                }
                painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
            }
            else
            {
                painter.fillRect(rect(), baseColor_);
            }

            if (sourceImage_.isNull() || imageOpacityPercent_ <= 0 || rect().isEmpty())
            {
                return;
            }

            painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
            painter.setOpacity(static_cast<double>(imageOpacityPercent_) / 100.0);
            painter.drawPixmap(
                coverTargetRectFor(sourceImage_.size()),
                sourceImage_,
                QRectF(QPointF(0, 0), sourceImage_.size()));
        }

    private:
        // coverTargetRectFor:
        // - Calculate the target rectangle where the source image should be drawn to achieve 'centered, aspect-ratio-preserving cover' filling the current control.
        // Input sourceSize: Source image size.
        // Returns: The target drawing rectangle (may extend beyond the control boundary, creating a cover effect via centering and cropping).
        QRectF coverTargetRectFor(const QSize& sourceSize) const
        {
            QSizeF scaledSize(sourceSize);
            scaledSize.scale(QSizeF(rect().size()), Qt::KeepAspectRatioByExpanding);
            return QRectF(
                (static_cast<double>(rect().width()) - scaledSize.width()) / 2.0,
                (static_cast<double>(rect().height()) - scaledSize.height()) / 2.0,
                scaledSize.width(),
                scaledSize.height());
        }

        QColor baseColor_ = Qt::black;
        QPixmap sourceImage_;
        int imageOpacityPercent_ = 0;
        quint64 sourceImageCacheKey_ = 0;
        bool translucentMode_ = false;      // m_translucentMode: Whether the background transparent area penetrates the window.
        bool paintTintWhenNoImage_ = true;  // m_paintTintWhenNoImage: Whether to paint a tint fallback when no background image is available.
        int tintAlpha_ = kTranslucentTintAlpha; // m_tintAlpha: Custom tint layer opacity, configured via appearance settings.
    };
}
