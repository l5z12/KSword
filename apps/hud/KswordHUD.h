#pragma once

#include <QtWidgets/QMainWindow>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QSpacerItem>
#include <QOpenGLWidget>
#include <QOpenGLFunctions>
#include <QPropertyAnimation>
#include <QParallelAnimationGroup>
#include <QPixmap>
#include <QPainter>
#include <QKeyEvent>
#include <QRect>
#include <QAbstractAnimation>
#include <QDebug>
#include <QElapsedTimer>
#include <QGraphicsOpacityEffect>

// QWidget + QPainter chart components within the repository.
#include "../../shared/ui/KsPainterChart.h"
#include "HardwareQueries.h"

class HudPerformancePanel;
class HudProcessListPanel;
class QTabWidget;
class QTimer;

// Custom OpenGL widget for hardware-accelerated rendering.
class OpenGLWidget : public QOpenGLWidget, protected QOpenGLFunctions
{
    Q_OBJECT
public:
    explicit OpenGLWidget(QWidget* parent = nullptr);
    ~OpenGLWidget();
    qreal opacity() const { return opacity_; } // New interface to get current opacity.
    void setBackgroundPixmap(const QPixmap& pixmap);
    void setOpacity(qreal opacity);
    void setChildWidgets(QWidget* left, QWidget* right);

    QPixmap captureContent(); // Capture the current content as an image.

protected:
    void initializeGL() override;
    void resizeGL(int w, int h) override;
    void paintGL() override;

private:
    QPixmap backgroundPixmap_;
    qreal opacity_;
    QWidget* leftWidget_ = nullptr;
    QWidget* rightWidget_ = nullptr;
};

class KswordHUD : public QMainWindow
{
    Q_OBJECT

        Q_PROPERTY(qreal windowOpacity READ windowOpacity WRITE setWindowOpacity)

public:
    KswordHUD(QWidget* parent = nullptr);
    ~KswordHUD();

    qreal windowOpacity() const { return windowOpacity_; }
    void setWindowOpacity(qreal opacity);

protected:
    bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override;
    void keyPressEvent(QKeyEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

private:
    struct HudConfig
    {
        QString backgroundImagePath;
        int leftWidgetOpacityPercent = 100;
        int rightWidgetOpacityPercent = 100;
        QString leftWidgetBackgroundColor = "#0A0F16";
        int leftWidgetBackgroundOpacityPercent = 0;
        QString leftProcessTableFontColor = "#FFFFFF";
        QString rightWidgetBackgroundColor = "#0A0F16";
        int rightWidgetBackgroundOpacityPercent = 0;
    };

    static LRESULT CALLBACK lowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
    static bool isRightCtrlEvent(WPARAM wParam, const KBDLLHOOKSTRUCT* keyboardInfo);

    qreal windowOpacity_;
    bool isVisible_;
    bool isAnimating_;
    bool pendingToggleRequest_ = false;
    QRect originalRect_;
    QWidget* leftWidget_;
    QWidget* rightWidget_;
    QTableWidget* tableWidget_;
    QPropertyAnimation* hideAnimation_;
    QPropertyAnimation* showAnimation_;
    OpenGLWidget* glWidget_;

    QPixmap cachedContent_;
    QPixmap lastStableContent_;
    qreal contentScale_;

    // Debug-related
    QElapsedTimer debugTimer_;
    int paintFrameCount_;
    int animationFrameCount_;

    void toggleVisibility();
    void initializeAnimations();
    HudConfig loadOrCreateConfig() const;
    void applyHudConfig(const HudConfig& config);
    void cacheWindowContent(bool refreshFromLiveScene = true);
    void debugOutput(const QString& message);
    void clearCache();
    void forceUpdateCache();

    HardwareMonitor* hwMonitor_ = nullptr;    // Legacy hardware monitor object (deprecated).
    QTimer* updateTimer_ = nullptr;           // Old timer (disabled).

    // 2. Right-side TabWidget and chart-related components
    QTabWidget* rightTabWidget_ = nullptr;    // Right-side tab container
    HudProcessListPanel* processListPanel_ = nullptr;
    HudPerformancePanel* performancePanel_ = nullptr;
    QGraphicsOpacityEffect* leftOpacityEffect_ = nullptr;
    QGraphicsOpacityEffect* rightOpacityEffect_ = nullptr;
    // CPU chart (series + data set + axis + view).
    QBarSeries* cpuSeries_ = nullptr;
    QList<QBarSet*> cpuBarSets_;
    QValueAxis* cpuAxisX_ = nullptr;
    QValueAxis* cpuAxisY_ = nullptr;
    QChartView* cpuChartView_ = nullptr;
    // RAM chart (same as above)
    QBarSeries* ramSeries_ = nullptr;
    QList<QBarSet*> ramBarSets_;
    QValueAxis* ramAxisX_ = nullptr;
    QValueAxis* ramAxisY_ = nullptr;
    QChartView* ramChartView_ = nullptr;
    // Disk chart (same as above).
    QBarSeries* diskSeries_ = nullptr;
    QList<QBarSet*> diskBarSets_;
    QValueAxis* diskAxisX_ = nullptr;
    QValueAxis* diskAxisY_ = nullptr;
    QChartView* diskChartView_ = nullptr;

    // 3. New function declarations
    void initCPUChart();     // initialize CPU bar chart
    void initRAMChart();     // initialize RAM bar chart
    void initDiskChart();    // initialize the disk bar chart.
    void onUpdateTimerTimeout(); // Timer slot function (updates data every second).

    static HHOOK sKeyboardHook;
    static KswordHUD* sInstance;
    static bool sRightCtrlDown;
};
