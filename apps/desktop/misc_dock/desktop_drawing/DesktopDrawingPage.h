#pragma once

#include "DesktopDrawingRenderer.h"

#include <QAbstractNativeEventFilter>
#include <QColor>
#include <QWidget>

class QComboBox;
class QLabel;
class QPushButton;
class QSpinBox;
class QTimer;

namespace ks::misc
{
    class DesktopDrawingPage final : public QWidget, public QAbstractNativeEventFilter
    {
    public:
        explicit DesktopDrawingPage(QWidget* parent = nullptr);
        ~DesktopDrawingPage() override;

        bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

    private:
        void initializeUi();
        void refreshDisplays();
        void updateCoordinates();
        void chooseColor();
        void updateColorButton();
        void startDrawing();
        void stopDrawing();
        void drawFrame();
        void showFailure(desktop_drawing::DrawResult result);
        void setRunning(bool running);

        desktop_drawing::Renderer renderer_;
        std::vector<desktop_drawing::Display> displays_;
        QColor color_{ 255, 80, 80 };
        QTimer* timer_ = nullptr;
        QWidget* settings_ = nullptr;
        QComboBox* displayCombo_ = nullptr;
        QComboBox* patternCombo_ = nullptr;
        QSpinBox* xSpin_ = nullptr;
        QSpinBox* ySpin_ = nullptr;
        QSpinBox* sizeSpin_ = nullptr;
        QSpinBox* lineWidthSpin_ = nullptr;
        QSpinBox* rateSpin_ = nullptr;
        QPushButton* colorButton_ = nullptr;
        QPushButton* startButton_ = nullptr;
        QPushButton* stopButton_ = nullptr;
        QLabel* statusLabel_ = nullptr;
        QLabel* hotkeyLabel_ = nullptr;
        bool hotkeyRegistered_ = false;
    };
}
