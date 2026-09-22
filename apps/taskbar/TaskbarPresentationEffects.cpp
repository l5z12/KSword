#include "Taskbar.h"
#include "Override.h"

#include <QColor>
#include <QGraphicsOpacityEffect>
#include <QPainter>
#include <QPropertyAnimation>
#include <QResizeEvent>
#include <QVariantAnimation>

namespace
{
// Tint the logo to the specified foreground color while preserving the original PNG alpha channel to avoid filling QLabel's transparent areas with solid rectangles.
QPixmap tintPixmapPreservingAlpha(const QPixmap& source, const QColor& color)
{
    if (source.isNull())
    {
        return QPixmap();
    }

    QPixmap tinted(source.size());
    tinted.fill(Qt::transparent);
    QPainter painter(&tinted);
    painter.setCompositionMode(QPainter::CompositionMode_Source);
    painter.drawPixmap(0, 0, source);
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(tinted.rect(), color);
    return tinted;
}
}

void Taskbar::applyTaskbarTheme(bool earthquakeAlert, const QColor& backgroundColor)
{
    // In alert state, the entire Taskbar uses white foreground to ensure earthquake information is clearly readable against red or dark red backgrounds.
    const QColor kForeground = earthquakeAlert ? QColor(Qt::white) : QColor(QStringLiteral("#00FFFF"));
    const QString kForegroundName = kForeground.name();
    centralWidget_->setStyleSheet(QStringLiteral("background-color: %1;").arg(backgroundColor.name()));
    contentLabel_->setStyleSheet(QStringLiteral("border: none; background: transparent; padding: 5px 0; color: %1; font-size: 12px;")
        .arg(kForegroundName));
    timeLabel_->setStyleSheet(QStringLiteral("border: none; background: transparent; color: %1; font-size: 12px;")
        .arg(kForegroundName));
    notificationSourceLabel_->setStyleSheet(QStringLiteral("background: transparent; color: %1; font-size: 10px;")
        .arg(kForegroundName));
    notificationTitleLabel_->setStyleSheet(QStringLiteral("background: transparent; color: %1; font-size: 12px; font-weight: 600;")
        .arg(kForegroundName));
    notificationBodyLabel_->setStyleSheet(QStringLiteral("background: transparent; color: %1; font-size: 11px;")
        .arg(kForegroundName));
    uploadSpeedLabel_->setStyleSheet(QStringLiteral("border: none; background: transparent; color: %1; font-size: 10px;")
        .arg(kForegroundName));
    downloadSpeedLabel_->setStyleSheet(QStringLiteral("border: none; background: transparent; color: %1; font-size: 10px;")
        .arg(kForegroundName));
    for (QLabel* bar : cpuBars_)
    {
        if (bar != nullptr)
        {
            bar->setStyleSheet(QStringLiteral("background-color: %1;").arg(kForegroundName));
        }
    }
    leftSpectrum_->setBarColor(kForeground);
    rightSpectrum_->setBarColor(kForeground);
    if (logoLabel_ != nullptr && !logoPixmap_.isNull())
    {
        const QPixmap kDisplayPixmap = earthquakeAlert
            ? tintPixmapPreservingAlpha(logoPixmap_, kForeground)
            : logoPixmap_;
        logoLabel_->setPixmap(kDisplayPixmap.scaled(QSize(QWIDGETSIZE_MAX, logoLabel_->height()),
            Qt::KeepAspectRatio, Qt::SmoothTransformation));
    }
    for (GlowIconButton* button : { lockBtn_, toolBtn_, settingsBtn_, userBtn_ })
    {
        if (button != nullptr)
        {
            button->setTintColor(kForeground);
        }
    }
    if (exitBtn_ != nullptr)
    {
        static_cast<GlowIconButton*>(exitBtn_)->setTintColor(kForeground);
    }
}

void Taskbar::startAlertFlashCycle()
{
    // The transition from bright red to dark red uses a 500ms linear gradient; immediately after the animation ends, it jumps back to bright red to start the next cycle.
    if (!earthquakePresentation_ || alertFlashAnimation_ == nullptr)
    {
        return;
    }

    alertFlashAnimation_->stop();
    alertFlashAnimation_->setStartValue(QColor(QStringLiteral("#D90000")));
    alertFlashAnimation_->setEndValue(QColor(QStringLiteral("#480000")));
    alertFlashAnimation_->start();
}

void Taskbar::flashNotificationBackground()
{
    // The highlight layer displays momentarily, then fades out over a linear 500ms; repeated messages reset the timer from the new bright state.
    if (notificationFlashWidget_ == nullptr || notificationFlashOpacity_ == nullptr ||
        notificationFlashAnimation_ == nullptr)
    {
        return;
    }

    notificationFlashAnimation_->stop();
    notificationFlashWidget_->raise();
    notificationFlashOpacity_->setOpacity(1.0);
    notificationFlashAnimation_->setStartValue(1.0);
    notificationFlashAnimation_->setEndValue(0.0);
    notificationFlashAnimation_->start();
}

void Taskbar::resizeEvent(QResizeEvent* event)
{
    // First let QMainWindow update the centralWidget geometry, then synchronize the coverage range of the entire highlight layer.
    QMainWindow::resizeEvent(event);
    if (notificationFlashWidget_ != nullptr && centralWidget_ != nullptr)
    {
        notificationFlashWidget_->setGeometry(centralWidget_->rect());
        notificationFlashWidget_->raise();
    }
}
