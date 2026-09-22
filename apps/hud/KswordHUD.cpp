//#include "stdafx.h"

#include <windows.h>
#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMetaObject>
#include <QOpenGLPaintDevice>
#include <QPainter>

#include <QEasingCurve>
#include <QAbstractAnimation>
#include <QScreen>
#include <QTimer>
#include <QSurfaceFormat>

#include <algorithm>
// Hardware monitoring header file
#include "HardwareQueries.h"
#include "HudProcessListPanel.h"
#include "HudPerformancePanel.h"
#include "KswordHUD.h"
// Namespace (code simplification).

namespace
{
    constexpr int kHudOuterMargin = 36;
    constexpr int kHudCenterGap = 24;
    constexpr int kDefaultLeftWidgetBackgroundOpacityPercent = 38;
    constexpr int kDefaultRightWidgetBackgroundOpacityPercent = 45;

    QColor parseConfigColor(const QString& colorText, const QColor& fallbackColor)
    {
        const QColor kParsedColor(colorText.trimmed());
        return kParsedColor.isValid() ? kParsedColor : fallbackColor;
    }

    QString buildWidgetBackgroundStyle(const QColor& color, const int opacityPercent)
    {
        const int kAlphaValue = qBound(0, opacityPercent, 100) * 255 / 100;
        return QStringLiteral("background-color: rgba(%1, %2, %3, %4);")
            .arg(color.red())
            .arg(color.green())
            .arg(color.blue())
            .arg(kAlphaValue);
    }
}

HHOOK KswordHUD::sKeyboardHook = nullptr;
KswordHUD* KswordHUD::sInstance = nullptr;
bool KswordHUD::sRightCtrlDown = false;

OpenGLWidget::OpenGLWidget(QWidget* parent)
    : QOpenGLWidget(parent), opacity_(0.5) {
    // Set vertical sync
    QSurfaceFormat format;
    format.setSwapInterval(1);
    setFormat(format);
}

OpenGLWidget::~OpenGLWidget() {
}

void OpenGLWidget::setBackgroundPixmap(const QPixmap& pixmap) {
    backgroundPixmap_ = pixmap;
    update();
}

void OpenGLWidget::setOpacity(qreal opacity) {
    opacity_ = opacity;
    update();
}

void OpenGLWidget::setChildWidgets(QWidget* left, QWidget* right) {
    leftWidget_ = left;
    rightWidget_ = right;
    if (left) {
        left->setParent(this);
        left->show();
    }
    if (right) {
        right->setParent(this);
        right->show();
    }
}

QPixmap OpenGLWidget::captureContent() {
    QPixmap pixmap(size());
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::SmoothPixmapTransform);
    painter.setRenderHint(QPainter::Antialiasing);

    // Draw background (identical to paintGL)
    if (!backgroundPixmap_.isNull()) {
        painter.setOpacity(opacity_);
        QPixmap scaled = backgroundPixmap_.scaled(
            size(), Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation
        );
        QRect rect = scaled.rect();
        rect.moveCenter(QRect(QPoint(), size()).center());
        painter.drawPixmap(rect, scaled);
    }
    else {
        painter.setOpacity(opacity_);
        painter.fillRect(rect(), QColor(0, 0, 0, 128));
    }

    // Render child widgets: use the actual grab result to avoid losing complex child controls or transparency effects under the render() path.
    painter.setOpacity(1);
    if (leftWidget_ && leftWidget_->isVisible()) {
        const QPixmap kLeftPixmap = leftWidget_->grab();
        painter.drawPixmap(leftWidget_->geometry().topLeft(), kLeftPixmap);
    }
    if (rightWidget_ && rightWidget_->isVisible()) {
        const QPixmap kRightPixmap = rightWidget_->grab();
        painter.drawPixmap(rightWidget_->geometry().topLeft(), kRightPixmap);
    }
    // Remove the fluctuation operations of setWindowOpacity(1.0) and setWindowOpacity(0.5)
    return pixmap;
}
void OpenGLWidget::initializeGL() {
    initializeOpenGLFunctions();
    glClearColor(0, 0, 0, 0);
}

void OpenGLWidget::resizeGL(int w, int h) {
    glViewport(0, 0, w, h);
    if (leftWidget_ && rightWidget_) {
        const int kContentWidth = std::max(0, w - 2 * kHudOuterMargin - kHudCenterGap);
        const int kPaneWidth = kContentWidth / 2;
        const int kPaneHeight = std::max(0, h - 2 * kHudOuterMargin);
        const int kLeftX = kHudOuterMargin;
        const int kRightX = kLeftX + kPaneWidth + kHudCenterGap;
        const int kTopY = kHudOuterMargin;
        leftWidget_->setGeometry(kLeftX, kTopY, kPaneWidth, kPaneHeight);
        rightWidget_->setGeometry(kRightX, kTopY, kContentWidth - kPaneWidth, kPaneHeight);
    }
}

void OpenGLWidget::paintGL() {
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

    QPainter painter(this);
    painter.setRenderHint(QPainter::SmoothPixmapTransform);
    painter.setRenderHint(QPainter::Antialiasing);

    // Draw background image (unchanged).
    if (!backgroundPixmap_.isNull()) {
        painter.setOpacity(opacity_);
        QPixmap scaled = backgroundPixmap_.scaled(
            size(), Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation
        );
        QRect rect = scaled.rect();
        rect.moveCenter(QRect(QPoint(), size()).center());
        painter.drawPixmap(rect, scaled);
    }
    else {
        painter.setOpacity(opacity_);
        painter.fillRect(rect(), QColor(0, 0, 0, 128));
    }

    // Critical fix: render child widgets directly to the current painter without using a temporary QPixmap.
    painter.setOpacity(0.99);
    //if (m_leftWidget && m_leftWidget->isVisible()) {
    //    m_leftWidget->render(&painter, m_leftWidget->pos(), QRegion(),
    //        QWidget::DrawWindowBackground | QWidget::DrawChildren);
    //}
    //if (m_rightWidget && m_rightWidget->isVisible()) {
    //    m_rightWidget->render(&painter, m_rightWidget->pos(), QRegion(),
    //        QWidget::DrawWindowBackground | QWidget::DrawChildren);
    //}
}
KswordHUD::KswordHUD(QWidget* parent)
    : QMainWindow(parent)
    , windowOpacity_(0.5)
    , isVisible_(false)
    , isAnimating_(false)
    , pendingToggleRequest_(false)
    , leftWidget_(nullptr)
    , rightWidget_(nullptr)
    , tableWidget_(nullptr)
    , hideAnimation_(nullptr)
    , showAnimation_(nullptr)
    , glWidget_(nullptr)
    , contentScale_(1.0)
    , paintFrameCount_(0)
    , animationFrameCount_(0)
{
    debugTimer_.start();
    debugOutput("KswordHUD 构造函数开始");

    // Window basic settings
    setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
    setAttribute(Qt::WA_TranslucentBackground);

    // Get the primary screen and set full screen.
    QScreen* primaryScreen = QApplication::primaryScreen();
    if (primaryScreen) {
        setGeometry(primaryScreen->geometry());
        debugOutput("设置主屏幕几何:" + QString::number(primaryScreen->geometry().x()) + "," +
            QString::number(primaryScreen->geometry().y()) + " " +
            QString::number(primaryScreen->geometry().width()) + "x" +
            QString::number(primaryScreen->geometry().height()));
    }
    else {
        showFullScreen();
    }

    originalRect_ = geometry();
    debugOutput("窗口初始几何:" + QString::number(originalRect_.x()) + "," +
        QString::number(originalRect_.y()) + " " +
        QString::number(originalRect_.width()) + "x" +
        QString::number(originalRect_.height()));

    // Create the OpenGL acceleration widget.
    glWidget_ = new OpenGLWidget(this);
    setCentralWidget(glWidget_);

    const HudConfig kConfig = loadOrCreateConfig();

    // Left container (50% width)
    leftWidget_ = new QWidget(glWidget_);
    leftWidget_->setAttribute(Qt::WA_StyledBackground, true);
    leftWidget_->setStyleSheet("background-color: transparent;");
    QVBoxLayout* leftLayout = new QVBoxLayout(leftWidget_);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(0);

    // Display the tiled process resource list on the left; tree-based grouping is not implemented yet.
    processListPanel_ = new HudProcessListPanel(leftWidget_);
    leftLayout->addWidget(processListPanel_, 1);

    // Right container (50% width, transparent background).
    rightWidget_ = new QWidget(glWidget_);
    rightWidget_->setAttribute(Qt::WA_StyledBackground, true);
    rightWidget_->setStyleSheet("background-color: transparent;");
    QVBoxLayout* rightLayout = new QVBoxLayout(rightWidget_);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(0);

    // Attach the full performance panel directly to the right side, removing the outer Tab layer.
    performancePanel_ = new HudPerformancePanel(rightWidget_);
    rightLayout->addWidget(performancePanel_, 1);

    // Hand over left and right widgets to the OpenGL widget for management.
    glWidget_->setChildWidgets(leftWidget_, rightWidget_);
    applyHudConfig(kConfig);

    // initialize animations.
    initializeAnimations();

    sInstance = this;
    if (sKeyboardHook == nullptr) {
        sKeyboardHook = SetWindowsHookExW(
            WH_KEYBOARD_LL,
            &KswordHUD::lowLevelKeyboardProc,
            GetModuleHandleW(nullptr),
            0);
        debugOutput(sKeyboardHook != nullptr
            ? QStringLiteral("右Ctrl键盘钩子安装成功")
            : QStringLiteral("右Ctrl键盘钩子安装失败"));
    }

    QTimer::singleShot(0, this, [this]() {
        hide();
        isVisible_ = false;
        debugOutput("窗口初始状态: 隐藏");
        });
}

KswordHUD::~KswordHUD()
{
    if (sInstance == this) {
        sInstance = nullptr;
    }
    if (sKeyboardHook != nullptr) {
        UnhookWindowsHookEx(sKeyboardHook);
        sKeyboardHook = nullptr;
        sRightCtrlDown = false;
    }
    if (updateTimer_) {
        updateTimer_->stop();
        delete updateTimer_;
    }

    // 2. Stop and release hardware monitoring.
    if (hwMonitor_) {
        hwMonitor_->stopMonitoring();
        delete hwMonitor_;
    }

    // 3. Release chart resources
    qDeleteAll(cpuBarSets_);
    qDeleteAll(ramBarSets_);
    qDeleteAll(diskBarSets_);
    delete cpuChartView_;
    delete ramChartView_;
    delete diskChartView_;
    debugOutput("KswordHUD 析构函数");
}

void KswordHUD::setWindowOpacity(qreal opacity)
{
    // Ensure opacity is within valid range
    windowOpacity_ = qBound(0.0, opacity, 1.0);
    debugOutput(QString("setWindowOpacity 被调用，新透明度: %1").arg(windowOpacity_));

    // Update immediately only when not animating.
    if (!isAnimating_) {
        update();
    }
    // While in animation state, update() is called within the animation's valueChanged signal.
}

KswordHUD::HudConfig KswordHUD::loadOrCreateConfig() const
{
    const QString kStyleDirPath = QCoreApplication::applicationDirPath() + "/Style";
    QDir styleDir(kStyleDirPath);
    if (!styleDir.exists()) {
        styleDir.mkpath(QStringLiteral("."));
    }

    const QString kConfigPath = styleDir.filePath(QStringLiteral("KswordHudConfig.json"));
    QJsonObject configObject;
    bool shouldWriteConfig = false;

    QFile configFile(kConfigPath);
    if (configFile.exists() && configFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        const QJsonDocument kConfigDocument = QJsonDocument::fromJson(configFile.readAll());
        if (kConfigDocument.isObject()) {
            configObject = kConfigDocument.object();
        }
        else {
            shouldWriteConfig = true;
        }
        configFile.close();
    }
    else {
        shouldWriteConfig = true;
    }

    if (!configObject.contains(QStringLiteral("backgroundImagePath"))) {
        configObject.insert(QStringLiteral("backgroundImagePath"), QStringLiteral("HUD_background.png"));
        shouldWriteConfig = true;
    }
    if (!configObject.contains(QStringLiteral("leftWidgetOpacityPercent"))) {
        configObject.insert(QStringLiteral("leftWidgetOpacityPercent"), 100);
        shouldWriteConfig = true;
    }
    if (!configObject.contains(QStringLiteral("rightWidgetOpacityPercent"))) {
        configObject.insert(QStringLiteral("rightWidgetOpacityPercent"), 100);
        shouldWriteConfig = true;
    }
    if (!configObject.contains(QStringLiteral("leftWidgetBackgroundColor"))) {
        configObject.insert(QStringLiteral("leftWidgetBackgroundColor"), QStringLiteral("#0A0F16"));
        shouldWriteConfig = true;
    }
    if (!configObject.contains(QStringLiteral("leftWidgetBackgroundOpacityPercent"))) {
        configObject.insert(QStringLiteral("leftWidgetBackgroundOpacityPercent"), kDefaultLeftWidgetBackgroundOpacityPercent);
        shouldWriteConfig = true;
    }
    if (!configObject.contains(QStringLiteral("leftProcessTableFontColor"))) {
        configObject.insert(QStringLiteral("leftProcessTableFontColor"), QStringLiteral("#FFFFFF"));
        shouldWriteConfig = true;
    }
    if (!configObject.contains(QStringLiteral("rightWidgetBackgroundColor"))) {
        configObject.insert(QStringLiteral("rightWidgetBackgroundColor"), QStringLiteral("#0A0F16"));
        shouldWriteConfig = true;
    }
    if (!configObject.contains(QStringLiteral("rightWidgetBackgroundOpacityPercent"))) {
        configObject.insert(QStringLiteral("rightWidgetBackgroundOpacityPercent"), kDefaultRightWidgetBackgroundOpacityPercent);
        shouldWriteConfig = true;
    }
    if (shouldWriteConfig && configFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        configFile.write(QJsonDocument(configObject).toJson(QJsonDocument::Indented));
        configFile.close();
    }

    HudConfig config;
    config.backgroundImagePath = configObject.value(QStringLiteral("backgroundImagePath")).toString(QStringLiteral("HUD_background.png"));
    config.leftWidgetOpacityPercent = qBound(
        0,
        configObject.value(QStringLiteral("leftWidgetOpacityPercent")).toInt(100),
        100);
    config.rightWidgetOpacityPercent = qBound(
        0,
        configObject.value(QStringLiteral("rightWidgetOpacityPercent")).toInt(100),
        100);
    config.leftWidgetBackgroundColor =
        configObject.value(QStringLiteral("leftWidgetBackgroundColor")).toString(QStringLiteral("#0A0F16"));
    config.leftWidgetBackgroundOpacityPercent = qBound(
        0,
        configObject.value(QStringLiteral("leftWidgetBackgroundOpacityPercent")).toInt(kDefaultLeftWidgetBackgroundOpacityPercent),
        100);
    config.leftProcessTableFontColor =
        configObject.value(QStringLiteral("leftProcessTableFontColor")).toString(QStringLiteral("#FFFFFF"));
    config.rightWidgetBackgroundColor =
        configObject.value(QStringLiteral("rightWidgetBackgroundColor")).toString(QStringLiteral("#0A0F16"));
    config.rightWidgetBackgroundOpacityPercent = qBound(
        0,
        configObject.value(QStringLiteral("rightWidgetBackgroundOpacityPercent")).toInt(kDefaultRightWidgetBackgroundOpacityPercent),
        100);
    return config;
}

void KswordHUD::applyHudConfig(const HudConfig& config)
{
    const QString kStyleDirPath = QCoreApplication::applicationDirPath() + "/Style";
    QString backgroundPath = config.backgroundImagePath.trimmed();
    if (backgroundPath.isEmpty()) {
        backgroundPath = QStringLiteral("HUD_background.png");
    }
    if (QDir::isRelativePath(backgroundPath)) {
        backgroundPath = QDir(kStyleDirPath).filePath(backgroundPath);
    }

    QPixmap background;
    if (background.load(backgroundPath)) {
        glWidget_->setBackgroundPixmap(background);
        debugOutput("背景图片加载成功:" + backgroundPath);
    }
    else {
        debugOutput("[警告] 背景图片加载失败！路径：" + backgroundPath);
        background = QPixmap(size());
        background.fill(QColor(30, 30, 30, 200));
        glWidget_->setBackgroundPixmap(background);
    }

    if (leftOpacityEffect_ == nullptr && leftWidget_ != nullptr) {
        leftOpacityEffect_ = new QGraphicsOpacityEffect(leftWidget_);
        leftWidget_->setGraphicsEffect(leftOpacityEffect_);
    }
    if (rightOpacityEffect_ == nullptr && rightWidget_ != nullptr) {
        rightOpacityEffect_ = new QGraphicsOpacityEffect(rightWidget_);
        rightWidget_->setGraphicsEffect(rightOpacityEffect_);
    }

    if (leftOpacityEffect_ != nullptr) {
        leftOpacityEffect_->setOpacity(static_cast<qreal>(config.leftWidgetOpacityPercent) / 100.0);
    }
    if (rightOpacityEffect_ != nullptr) {
        rightOpacityEffect_->setOpacity(static_cast<qreal>(config.rightWidgetOpacityPercent) / 100.0);
    }

    const QColor kDefaultWidgetColor(0, 0, 0);
    const QColor kLeftBackgroundColor =
        parseConfigColor(config.leftWidgetBackgroundColor, kDefaultWidgetColor);
    const QColor kLeftProcessTableFontColor =
        parseConfigColor(config.leftProcessTableFontColor, QColor(255, 255, 255));
    const QColor kRightBackgroundColor =
        parseConfigColor(config.rightWidgetBackgroundColor, kDefaultWidgetColor);
    if (leftWidget_ != nullptr) {
        leftWidget_->setStyleSheet(buildWidgetBackgroundStyle(
            kLeftBackgroundColor,
            config.leftWidgetBackgroundOpacityPercent > 0
            ? config.leftWidgetBackgroundOpacityPercent
            : kDefaultLeftWidgetBackgroundOpacityPercent));
    }
    if (rightWidget_ != nullptr) {
        rightWidget_->setStyleSheet(buildWidgetBackgroundStyle(
            kRightBackgroundColor,
            config.rightWidgetBackgroundOpacityPercent > 0
            ? config.rightWidgetBackgroundOpacityPercent
            : kDefaultRightWidgetBackgroundOpacityPercent));
    }
    if (processListPanel_ != nullptr) {
        processListPanel_->setTableTextColor(kLeftProcessTableFontColor);
    }
}

bool KswordHUD::isRightCtrlEvent(const WPARAM wParam, const KBDLLHOOKSTRUCT* keyboardInfo)
{
    if (keyboardInfo == nullptr) {
        return false;
    }

    const bool kIsKeyTransition =
        wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN || wParam == WM_KEYUP || wParam == WM_SYSKEYUP;
    if (!kIsKeyTransition) {
        return false;
    }

    if (keyboardInfo->vkCode == VK_RCONTROL) {
        return true;
    }

    return keyboardInfo->vkCode == VK_CONTROL
        && (keyboardInfo->flags & LLKHF_EXTENDED) != 0;
}

LRESULT CALLBACK KswordHUD::lowLevelKeyboardProc(const int nCode, const WPARAM wParam, const LPARAM lParam)
{
    if (nCode == HC_ACTION) {
        const auto* keyboardInfo = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if (isRightCtrlEvent(wParam, keyboardInfo)) {
            if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                if (!sRightCtrlDown && sInstance != nullptr) {
                    sRightCtrlDown = true;
                    QMetaObject::invokeMethod(sInstance, [instance = sInstance]() {
                        if (instance != nullptr) {
                            instance->toggleVisibility();
                        }
                    }, Qt::QueuedConnection);
                }
            }
            else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
                sRightCtrlDown = false;
            }
        }
    }

    return CallNextHookEx(sKeyboardHook, nCode, wParam, lParam);
}

void KswordHUD::keyPressEvent(QKeyEvent* event)
{
    QMainWindow::keyPressEvent(event);
}

bool KswordHUD::nativeEvent(const QByteArray& eventType, void* message, qintptr* result)
{
    return QMainWindow::nativeEvent(eventType, message, result);
}

void KswordHUD::resizeEvent(QResizeEvent* event)
{
    QMainWindow::resizeEvent(event);
    originalRect_ = geometry();
    debugOutput("窗口大小改变:" + QString::number(originalRect_.x()) + "," +
        QString::number(originalRect_.y()) + " " +
        QString::number(originalRect_.width()) + "x" +
        QString::number(originalRect_.height()));
}

void KswordHUD::paintEvent(QPaintEvent* event)
{
    paintFrameCount_++;

    // Only draw the cached content if animation is in progress and the cached content is valid.
    if (isAnimating_ && !cachedContent_.isNull()) {

        debugOutput(QString("paintEvent [动画帧 %1] - 透明度: %2, 缩放: %3")
            .arg(paintFrameCount_)
            .arg(windowOpacity_, 0, 'f', 3)
            .arg(contentScale_, 0, 'f', 3));

        QPainter painter(this);
        painter.setRenderHint(QPainter::SmoothPixmapTransform);

        // Calculate the scaled size and position.
        QSize scaledSize = cachedContent_.size() * contentScale_;
        QPoint centerPoint = rect().center() - QPoint(scaledSize.width() / 2, scaledSize.height() / 2);
        QRect drawRect(centerPoint, scaledSize);

        // Set window opacity.
        painter.setOpacity(windowOpacity_);

        // Draw scaled content
        painter.drawPixmap(drawRect, cachedContent_);
    }
    else {
        // Normal rendering - ensure cache is cleared
        if (!cachedContent_.isNull()) {
            clearCache(); // Additional security check
        }

        debugOutput(QString("paintEvent [正常帧 %1] - 透明度: %2")
            .arg(paintFrameCount_)
            .arg(windowOpacity_, 0, 'f', 3));
                //clearCache();
        QMainWindow::paintEvent(event);
    }
}
void KswordHUD::cacheWindowContent(const bool refreshFromLiveScene)
{
    if (glWidget_) {
        if (refreshFromLiveScene) {
            cachedContent_ = glWidget_->captureContent();
            lastStableContent_ = cachedContent_;
        }
        else {
            cachedContent_ = lastStableContent_;
        }
        debugOutput("已缓存窗口内容");
    }
}

void KswordHUD::debugOutput(const QString& message)
{
    if (!qEnvironmentVariableIsSet("KSWORDHUD_DEBUG")) {
        return;
    }
    qint64 elapsed = debugTimer_.elapsed();
    qDebug() << QString("[%1 ms] %2").arg(elapsed, 6).arg(message);
}

void KswordHUD::initializeAnimations()
{
    debugOutput("初始化动画系统");
    // Hide animation: opacity transitions from 1.0 to 0.0 (or 0.5 to 0.0 after overlay).
    hideAnimation_ = new QPropertyAnimation(this, "windowOpacity");
    hideAnimation_->setDuration(500);
    hideAnimation_->setEasingCurve(QEasingCurve::OutCubic);
    hideAnimation_->setStartValue(1.0);  // Initial opacity 1.0 (0.5 after overlay).
    hideAnimation_->setEndValue(0.0);    // Fully transparent at end

    connect(hideAnimation_, &QPropertyAnimation::valueChanged, this, [this](const QVariant& value) {
        animationFrameCount_++;
        qreal opacity = value.toReal();

        // Progress calculation: 1.0→0.0 corresponds to 0→1 progress.
        qreal progress = 1.0 - opacity;  // Key modification: Progress = 1 - current opacity.
        contentScale_ = 1.0 + progress * 0.5;  // Scale remains 1.0→1.5

        debugOutput(QString("隐藏动画 [帧 %1] - 透明度: %2, 缩放: %3, 进度: %4")
            .arg(animationFrameCount_)
            .arg(opacity, 0, 'f', 3)
            .arg(contentScale_, 0, 'f', 3)
            .arg(progress, 0, 'f', 3));
        update();
        });
    // Keep other code unchanged...
    connect(hideAnimation_, &QPropertyAnimation::finished, this, [this]() {
        hide();
        clearCache(); // Important: Clear cache.
        isVisible_ = false;
        isAnimating_ = false;
        glWidget_->show();

        glWidget_->update(); // Force repaint of the OpenGL widget.
        debugOutput("隐藏动画完成，窗口已隐藏");
        animationFrameCount_ = 0;
        if (pendingToggleRequest_) {
            pendingToggleRequest_ = false;
            QTimer::singleShot(0, this, [this]() { toggleVisibility(); });
        }
        });

    // Show animation: opacity transitions from 0.0 to 1.0 (0.0 to 0.5 after overlay).

    showAnimation_ = new QPropertyAnimation(this, "windowOpacity");
    showAnimation_->setDuration(500);
    showAnimation_->setEasingCurve(QEasingCurve::OutCubic);
    showAnimation_->setStartValue(0.0);  // Initially fully transparent.
    showAnimation_->setEndValue(1.0);    // End transparency 1.0 (0.5 after overlay).
    setWindowOpacity(1.0);
    connect(showAnimation_, &QPropertyAnimation::valueChanged, this, [this](const QVariant& value) {
        animationFrameCount_++;
        qreal opacity = value.toReal();

        // Progress calculation: 0.0→1.0 corresponds to 0→1 progress.
        qreal progress = opacity;  // Key change: progress = current opacity.
        contentScale_ = 1.5 - progress * 0.5;  // Scale remains 1.5→1.0

        debugOutput(QString("显示动画 [帧 %1] - 透明度: %2, 缩放: %3, 进度: %4")
            .arg(animationFrameCount_)
            .arg(opacity, 0, 'f', 3)
            .arg(contentScale_, 0, 'f', 3)
            .arg(progress, 0, 'f', 3));
        update();
        });
    connect(showAnimation_, &QPropertyAnimation::finished, this, [this]() {
        isVisible_ = true;
        isAnimating_ = false;
        glWidget_->show(); // Restore display of the OpenGL widget.
        clearCache(); // Important: Clear cache.
        glWidget_->update(); // Force repaint of the OpenGL widget.

        debugOutput("显示动画完成，窗口已显示");
        animationFrameCount_ = 0;
        if (pendingToggleRequest_) {
            pendingToggleRequest_ = false;
            QTimer::singleShot(0, this, [this]() { toggleVisibility(); });
        }
        });
    setWindowOpacity(0.5);
}

void KswordHUD::toggleVisibility()
{
    if (isAnimating_) {
        pendingToggleRequest_ = true;
        debugOutput("动画进行中，已记录切换请求");
        return;
    }

    pendingToggleRequest_ = false;

    debugOutput("切换可见性，当前状态:" + QString(isVisible_ ? "显示" : "隐藏"));

    // Stop all running animations.
    if (hideAnimation_->state() == QAbstractAnimation::Running) {
        hideAnimation_->stop();
        debugOutput("停止正在运行的隐藏动画");
    }
    if (showAnimation_->state() == QAbstractAnimation::Running) {
        showAnimation_->stop();
        debugOutput("停止正在运行的显示动画");
    }

    if (isVisible_) {
        // Hide window
        debugOutput("开始隐藏动画");

        isAnimating_ = true;
        animationFrameCount_ = 0;

        // Cache current window content
        cacheWindowContent(true);

        // Hide the OpenGL widget and display only the cached content.
        glWidget_->hide();

        hideAnimation_->start();
    }
    else {
        // Show window
        debugOutput("开始显示动画");

        if (lastStableContent_.isNull()) {
            show();
            raise();
            activateWindow();
            isVisible_ = true;
            isAnimating_ = false;
            clearCache();
            glWidget_->show();
            glWidget_->update();
            debugOutput("无历史快照，直接显示窗口");
        }
        else {
            cacheWindowContent(false);
            glWidget_->hide();

            isAnimating_ = true;
            animationFrameCount_ = 0;

            // Use the last snapshot directly for display animation to avoid the real panel flashing first.
            show();
            raise();
            activateWindow();

            showAnimation_->start();
        }
    }
}
void KswordHUD::clearCache() {
    cachedContent_ = QPixmap();
    debugOutput("缓存已清除");
}

void KswordHUD::forceUpdateCache() {
    clearCache();
    if (glWidget_) {
        glWidget_->update(); // Force OpenGLWidget repaint.
    }
    update(); // Force window redraw
    debugOutput("强制更新缓存");
}

// 1. initialize CPU bar chart (60-second history, Y-axis 0-100%)
void KswordHUD::initCPUChart() {
    // initialize 60 data sets (corresponding to 60 seconds of history, initial value 0).
    cpuBarSets_.clear();
    for (int i = 0; i < HardwareMonitor::kHistorySize; ++i) {
        QBarSet* set = new QBarSet(QString("第%1秒").arg(i));
        *set << 0.0; // Initial usage is 0%.
        set->setBrush(QColor(255, 100, 100)); // Bar color: light red
        set->setLabelBrush(QColor(255, 255, 255)); // Label white
        cpuBarSets_.append(set);
    }

    // Create a bar series (integrating 60 data sets).
    cpuSeries_ = new QBarSeries();
    cpuSeries_->append(cpuBarSets_);
    cpuSeries_->setName("CPU使用率(%)");

    // Create chart core object
    QChart* cpuChart = new QChart();
    cpuChart->addSeries(cpuSeries_);
    cpuChart->setTitle("CPU使用率历史（最近60秒）");
    cpuChart->setBackgroundBrush(QColor(0, 0, 0, 0)); // Transparent background
    cpuChart->setTitleBrush(QColor(255, 255, 255)); // Title white
    cpuChart->legend()->setLabelBrush(QColor(255, 255, 255)); // Legend white

    // X-axis: Time (0-59 seconds)
    cpuAxisX_ = new QValueAxis();
    cpuAxisX_->setRange(0, HardwareMonitor::kHistorySize - 1);
    cpuAxisX_->setLabelFormat("%d");
    cpuAxisX_->setTitleText("时间（秒）");
    cpuAxisX_->setTitleBrush(QColor(255, 255, 255));
    cpuAxisX_->setLabelsBrush(QColor(255, 255, 255));

    // Y-axis: Usage rate (0-100%, fixed range to avoid fluctuations).
    cpuAxisY_ = new QValueAxis();
    cpuAxisY_->setRange(0, 100);
    cpuAxisY_->setLabelFormat("%.0f%%");
    cpuAxisY_->setTitleText("使用率");
    cpuAxisY_->setTitleBrush(QColor(255, 255, 255));
    cpuAxisY_->setLabelsBrush(QColor(255, 255, 255));

    // Bind axes to chart
    cpuChart->addAxis(cpuAxisX_, Qt::AlignBottom);
    cpuChart->addAxis(cpuAxisY_, Qt::AlignLeft);
    cpuSeries_->attachAxis(cpuAxisX_);
    cpuSeries_->attachAxis(cpuAxisY_);

    // Create the chart view (for display).
    cpuChartView_ = new QChartView(cpuChart);
    cpuChartView_->setRenderHint(QPainter::Antialiasing); // Anti-aliasing
    cpuChartView_->setStyleSheet("background-color: transparent;"); // Transparent background

    // Add to Tab page.
    rightTabWidget_->addTab(cpuChartView_, "CPU");
}

// 2. initialize the RAM bar chart (logic matches CPU, differing only in data fields and colors).
void KswordHUD::initRAMChart() {
    ramBarSets_.clear();
    for (int i = 0; i < HardwareMonitor::kHistorySize; ++i) {
        QBarSet* set = new QBarSet(QString("第%1秒").arg(i));
        *set << 0.0;
        set->setBrush(QColor(100, 255, 100)); // Bar color: light green
        set->setLabelBrush(QColor(255, 255, 255));
        ramBarSets_.append(set);
    }

    ramSeries_ = new QBarSeries();
    ramSeries_->append(ramBarSets_);
    ramSeries_->setName("内存使用率(%)");

    QChart* ramChart = new QChart();
    ramChart->addSeries(ramSeries_);
    ramChart->setTitle("内存使用率历史（最近60秒）");
    ramChart->setBackgroundBrush(QColor(0, 0, 0, 0));
    ramChart->setTitleBrush(QColor(255, 255, 255));
    ramChart->legend()->setLabelBrush(QColor(255, 255, 255));

    ramAxisX_ = new QValueAxis();
    ramAxisX_->setRange(0, HardwareMonitor::kHistorySize - 1);
    ramAxisX_->setLabelFormat("%d");
    ramAxisX_->setTitleText("时间（秒）");
    ramAxisX_->setTitleBrush(QColor(255, 255, 255));
    ramAxisX_->setLabelsBrush(QColor(255, 255, 255));

    ramAxisY_ = new QValueAxis();
    ramAxisY_->setRange(0, 100);
    ramAxisY_->setLabelFormat("%.0f%%");
    ramAxisY_->setTitleText("使用率");
    ramAxisY_->setTitleBrush(QColor(255, 255, 255));
    ramAxisY_->setLabelsBrush(QColor(255, 255, 255));

    ramChart->addAxis(ramAxisX_, Qt::AlignBottom);
    ramChart->addAxis(ramAxisY_, Qt::AlignLeft);
    ramSeries_->attachAxis(ramAxisX_);
    ramSeries_->attachAxis(ramAxisY_);

    ramChartView_ = new QChartView(ramChart);
    ramChartView_->setRenderHint(QPainter::Antialiasing);
    ramChartView_->setStyleSheet("background-color: transparent;");

    rightTabWidget_->addTab(ramChartView_, "RAM");
}

// 3. Initializes the Disk bar chart (logic matches CPU, differing only in data fields and colors).
void KswordHUD::initDiskChart() {
    diskBarSets_.clear();
    for (int i = 0; i < HardwareMonitor::kHistorySize; ++i) {
        QBarSet* set = new QBarSet(QString("第%1秒").arg(i));
        *set << 0.0;
        set->setBrush(QColor(100, 100, 255)); // Bar color: light blue
        set->setLabelBrush(QColor(255, 255, 255));
        diskBarSets_.append(set);
    }

    diskSeries_ = new QBarSeries();
    diskSeries_->append(diskBarSets_);
    diskSeries_->setName("磁盘使用率(%)");

    QChart* diskChart = new QChart();
    diskChart->addSeries(diskSeries_);
    diskChart->setTitle("磁盘使用率历史（最近60秒）");
    diskChart->setBackgroundBrush(QColor(0, 0, 0, 0));
    diskChart->setTitleBrush(QColor(255, 255, 255));
    diskChart->legend()->setLabelBrush(QColor(255, 255, 255));

    diskAxisX_ = new QValueAxis();
    diskAxisX_->setRange(0, HardwareMonitor::kHistorySize - 1);
    diskAxisX_->setLabelFormat("%d");
    diskAxisX_->setTitleText("时间（秒）");
    diskAxisX_->setTitleBrush(QColor(255, 255, 255));
    diskAxisX_->setLabelsBrush(QColor(255, 255, 255));

    diskAxisY_ = new QValueAxis();
    diskAxisY_->setRange(0, 100);
    diskAxisY_->setLabelFormat("%.0f%%");
    diskAxisY_->setTitleText("使用率");
    diskAxisY_->setTitleBrush(QColor(255, 255, 255));
    diskAxisY_->setLabelsBrush(QColor(255, 255, 255));

    diskChart->addAxis(diskAxisX_, Qt::AlignBottom);
    diskChart->addAxis(diskAxisY_, Qt::AlignLeft);
    diskSeries_->attachAxis(diskAxisX_);
    diskSeries_->attachAxis(diskAxisY_);

    diskChartView_ = new QChartView(diskChart);
    diskChartView_->setRenderHint(QPainter::Antialiasing);
    diskChartView_->setStyleSheet("background-color: transparent;");

    rightTabWidget_->addTab(diskChartView_, "Disk");
}

void KswordHUD::onUpdateTimerTimeout() {
    if (!hwMonitor_) return;

    // -------------------------- Key: Retrieve hardware history data (thread-safe) --------------------------
    // Note: You must first modify getHistory() in hGet.h to add a mutex (see the supplement below).
    std::array<HardwareSnapshot, HardwareMonitor::kHistorySize> hwHistory = hwMonitor_->getHistory();

    // -------------------------- 1. Update CPU chart data --------------------------
    for (int i = 0; i < HardwareMonitor::kHistorySize; ++i) {
        double cpuUsage = hwHistory[i].cpuUsage;
        cpuUsage = qBound(0.0, cpuUsage, 100.0); // Ensure the value is between 0 and 100.
        cpuBarSets_[i]->replace(0, cpuUsage);   // Update the usage rate for the i-th second.
    }

    // -------------------------- 2. Update RAM chart data --------------------------
    for (int i = 0; i < HardwareMonitor::kHistorySize; ++i) {
        double ramUsage = hwHistory[i].memoryUsagePercent;
        ramUsage = qBound(0.0, ramUsage, 100.0);
        ramBarSets_[i]->replace(0, ramUsage);
    }

    // -------------------------- 3. Update Disk chart data --------------------------
    for (int i = 0; i < HardwareMonitor::kHistorySize; ++i) {
        double diskUsage = hwHistory[i].diskUsagePercent;
        diskUsage = qBound(0.0, diskUsage, 100.0);
        diskBarSets_[i]->replace(0, diskUsage);
    }

    // Force chart refresh (ensure immediate UI update).
    cpuChartView_->chart()->update();
    ramChartView_->chart()->update();
    diskChartView_->chart()->update();

    debugOutput("硬件数据已更新，图表刷新完成");
}
