#include <QPushButton>
#include <QGraphicsDropShadowEffect>
#include <QEnterEvent>
#include <QIcon>
#include <QPixmap>
#include <QImage>
#include <QColor>

class GlowIconButton : public QPushButton {
    Q_OBJECT
public:
    // Constructor: accepts icon path and icon size (dimensions are entirely determined by the icon size).
    explicit GlowIconButton(const QString& iconPath, const QSize& iconSize, QWidget* parent = nullptr)
        : QPushButton(parent) {
        // 1. Load icon and verify.
        originalIcon_ = QIcon(iconPath);
        configuredIconSize_ = iconSize;
        if (originalIcon_.isNull()) {
            qWarning() << "图标加载失败！路径：" << iconPath;
            return;
        }

        // 2. Precise colorization (process only the icon body, preserving the transparent background)
        QIcon coloredIcon = colorizeIcon(originalIcon_, iconSize, tintColor_);
        setIcon(coloredIcon);
        setIconSize(iconSize); // Force icon size

        // 3. Glow effect
        glowEffect_ = new QGraphicsDropShadowEffect(this);
        glowEffect_->setColor(tintColor_);
        glowEffect_->setBlurRadius(8); // Glow intensity (moderate)
        glowEffect_->setOffset(0, 0);
        glowEffect_->setEnabled(false);
        setGraphicsEffect(glowEffect_);

        // 4. Style sheet: adaptive borders, no fixed size
        setStyleSheet(R"(
            QPushButton {
                border: 0px solid #ccc;
                border-radius: 3px;
                padding: 3px; /* Spacing between the icon and the border (smaller for a tighter layout). */
                background-color: transparent;
                /* Remove fixed width/height; size is determined entirely by the icon and padding. */
            }
            QPushButton:hover {
                border-color: #43A0FF;
            }
            QPushButton:pressed {
                background-color: rgba(67, 160, 255, 0.14);
            }
        )");
    }

    // setTintColor: Takes an icon and a glow target color as input; recolors the existing icon and updates hover visuals; returns nothing.
    void setTintColor(const QColor& color) {
        if (tintColor_ == color || originalIcon_.isNull()) {
            return;
        }

        tintColor_ = color;
        setIcon(colorizeIcon(originalIcon_, configuredIconSize_, tintColor_));
        if (glowEffect_ != nullptr) {
            glowEffect_->setColor(tintColor_);
        }
        const QString kColorName = tintColor_.name();
        setStyleSheet(QStringLiteral(
            "QPushButton { border: 0px solid %1; border-radius: 3px; padding: 3px; background-color: transparent; }"
            "QPushButton:hover { border-color: %1; }"
            "QPushButton:pressed { background-color: rgba(%2, %3, %4, 36); }")
            .arg(kColorName)
            .arg(tintColor_.red())
            .arg(tintColor_.green())
            .arg(tintColor_.blue()));
    }

protected:
    // Mouse enter: enable glow
    void enterEvent(QEnterEvent* event) override {
        if (glowEffect_ != nullptr) {
            glowEffect_->setEnabled(true);
        }
        QPushButton::enterEvent(event);
    }

    // Mouse leave: disable glow
    void leaveEvent(QEvent* event) override {
        if (glowEffect_ != nullptr) {
            glowEffect_->setEnabled(false);
        }
        QPushButton::leaveEvent(event);
    }

private:
    QGraphicsDropShadowEffect* glowEffect_ = nullptr; // Glow effect used when hovering over the icon button.
    QIcon originalIcon_;                    // Original icon without color; used to recolor when switching themes.
    QSize configuredIconSize_;              // Fixed pixel size maintained when recoloring icons.
    QColor tintColor_ = QColor("#43A0FF"); // Icon tinting under the current theme.

    // Precise color change algorithm: only process non-transparent dark pixels.
    QIcon colorizeIcon(const QIcon& original, const QSize& iconSize, const QColor& targetColor) {
        QIcon coloredIcon;
        // Use the specified icon size directly (to avoid issues caused by automatic scaling).
        QPixmap pix = original.pixmap(iconSize);
        QImage img = pix.toImage(); // Convert to QImage for pixel processing.

        // Iterate over each pixel
        for (int y = 0; y < img.height(); ++y) {
            for (int x = 0; x < img.width(); ++x) {
                QRgb pixel = img.pixel(x, y);
                int alpha = qAlpha(pixel); // Get transparency (0 = fully transparent, 255 = fully opaque).

                // Process only 'non-transparent' and 'dark' pixels (the icon body).
                if (alpha > 50) { // Exclude nearly transparent pixels (background).
                    int red = qRed(pixel);
                    int green = qGreen(pixel);
                    int blue = qBlue(pixel);
                    // Check if the color is dark (all RGB values are low).
                    if (red < 100 && green < 100 && blue < 100) {
                        // Replace with target color, preserving original alpha.
                        QRgb newPixel = qRgba(
                            targetColor.red(),
                            targetColor.green(),
                            targetColor.blue(),
                            alpha // Critical: Preserve original icon transparency.
                        );
                        img.setPixel(x, y, newPixel);
                    }
                }
            }
        }

        // Convert back to QPixmap and add to the icon.
        coloredIcon.addPixmap(QPixmap::fromImage(img));
        return coloredIcon;
    }
};
