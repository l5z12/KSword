#include "RenderBenchmarkPage.h"

// ============================================================
// RenderBenchmarkPage.cpp
// Purpose:
// 1) Implement the four tests for the 'Render Benchmark' page and unified report output.
// 2) All measurements are performed on the UI thread—the subject under test is the UI thread itself;
// 3) Report only locally measured values; do not embed any 'expected' thresholds.
// ============================================================

#include "../../internationalization/LanguageManager.h"
#include "../../settings_dock/AppearanceSettings.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QElapsedTimer>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QPaintEvent>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRect>
#include <QScreen>
#include <QScrollArea>
#include <QSpinBox>
#include <QTextStream>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <tlhelp32.h>

namespace
{
    // kFrameBudgetMs:
    // - Time budget per frame at 60fps; samples exceeding it are counted as "dropped frames".
    constexpr double kFrameBudgetMs = 1000.0 / 60.0;

    // Constants related to composition attributes: maintain the same values as mainWindow.
    // Here, we deliberately do not reuse internal constants from mainWindow; the benchmark page should independently clarify what it is issuing.
    constexpr DWORD kWindowCompositionAttributeAccentPolicy = 19;
    constexpr DWORD kAccentEnableAcrylicBlurBehind = 4;

    struct AccentPolicyData
    {
        DWORD accentState = 0;
        DWORD accentFlags = 0;
        DWORD gradientColor = 0;
        DWORD animationId = 0;
    };

    struct WindowCompositionAttributeData
    {
        DWORD attribute = 0;
        void* dataPointer = nullptr;
        SIZE_T dataSizeBytes = 0;
    };

    using SetWindowCompositionAttributeFunction = BOOL(WINAPI*)(HWND, void*);

    // resolveSetWindowCompositionAttribute:
    // - Retrieve the unexported entry point for user32 composition attributes; it may not exist on older systems, returning a null pointer for the caller to handle gracefully.
    SetWindowCompositionAttributeFunction resolveSetWindowCompositionAttribute()
    {
        static SetWindowCompositionAttributeFunction cachedEntry =
            []() -> SetWindowCompositionAttributeFunction {
                HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
                if (user32ModuleHandle == nullptr)
                {
                    return nullptr;
                }
                return reinterpret_cast<SetWindowCompositionAttributeFunction>(
                    ::GetProcAddress(user32ModuleHandle, "SetWindowCompositionAttribute"));
            }();
        return cachedEntry;
    }

    // submitAcrylicAccent:
    // - Sends a one-time acrylic accent composition attribute to the specified window.
    // Input windowHandle: target window; Input tintAlpha: tint layer opacity (0~255).
    // Returns: true if submission succeeded.
    bool submitAcrylicAccent(HWND windowHandle, const int tintAlpha)
    {
        SetWindowCompositionAttributeFunction entry = resolveSetWindowCompositionAttribute();
        if (entry == nullptr || windowHandle == nullptr)
        {
            return false;
        }
        AccentPolicyData accentPolicy{};
        accentPolicy.accentState = kAccentEnableAcrylicBlurBehind;
        // gradientColor is arranged as 0xAABBGGRR; here we use a neutral dark gray, as the color itself does not affect the measurement conclusion.
        accentPolicy.gradientColor =
            (static_cast<DWORD>(std::clamp(tintAlpha, 0, 255)) << 24) | 0x00202020;
        WindowCompositionAttributeData compositionData{};
        compositionData.attribute = kWindowCompositionAttributeAccentPolicy;
        compositionData.dataPointer = &accentPolicy;
        compositionData.dataSizeBytes = sizeof(accentPolicy);
        return entry(windowHandle, &compositionData) != FALSE;
    }

    // summarizeSamples:
    // - Normalizes a set of latency samples into a unified statistical format.
    // Input samples: Latency samples (ms), order may be arbitrary.
    // Return: Statistical results; returns all zeros if the sample set is empty.
    ks::misc::BenchmarkSampleSummary summarizeSamples(std::vector<double> samples)
    {
        ks::misc::BenchmarkSampleSummary summary;
        if (samples.empty())
        {
            return summary;
        }
        double total = 0.0;
        for (const double kValue : samples)
        {
            total += kValue;
            summary.worstMs = std::max(summary.worstMs, kValue);
            if (kValue > kFrameBudgetMs)
            {
                ++summary.overBudgetCount;
            }
        }
        std::sort(samples.begin(), samples.end());
        summary.sampleCount = static_cast<int>(samples.size());
        summary.averageMs = total / static_cast<double>(samples.size());
        summary.p95Ms = samples[samples.size() * 95 / 100];
        return summary;
    }

    // pumpUserInterface:
    // - Allow event processing once during long tests to refresh button states and progress bars.
    // - Avoid using QThread::msleep to idle, which makes the interface appear frozen.
    void pumpUserInterface(const int milliseconds)
    {
        QElapsedTimer waitTimer;
        waitTimer.start();
        do
        {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
            if (waitTimer.elapsed() < milliseconds)
            {
                ::Sleep(2);
            }
        } while (waitTimer.elapsed() < milliseconds);
    }

    // locateMainRootContainer:
    // - Locate the main window's background root container by objectName;
    // - The benchmark page may be embedded elsewhere, so search all top-level windows instead of assuming the parent chain.
    // Return: Pointer to the root container; returns null if not found.
    QWidget* locateMainRootContainer()
    {
        const QWidgetList kTopLevelWidgets = QApplication::topLevelWidgets();
        for (QWidget* const kTopLevelWidget : kTopLevelWidgets)
        {
            if (kTopLevelWidget == nullptr)
            {
                continue;
            }
            if (kTopLevelWidget->objectName() == QStringLiteral("ksMainRootContainer"))
            {
                return kTopLevelWidget;
            }
            QWidget* const kFoundWidget =
                kTopLevelWidget->findChild<QWidget*>(QStringLiteral("ksMainRootContainer"));
            if (kFoundWidget != nullptr)
            {
                return kFoundWidget;
            }
        }
        return nullptr;
    }

    // buildGradientWallpaper:
    // - Synthesize a gradient bitmap when no background image is available to ensure the drag test still has a real image rendering load;
    // Parameter imageSize: Target size.
    // Returns: A bitmap ready for direct rendering.
    QPixmap buildGradientWallpaper(const QSize& imageSize)
    {
        QImage generatedImage(imageSize, QImage::Format_ARGB32_Premultiplied);
        for (int rowIndex = 0; rowIndex < imageSize.height(); ++rowIndex)
        {
            QRgb* const kScanLine = reinterpret_cast<QRgb*>(generatedImage.scanLine(rowIndex));
            for (int columnIndex = 0; columnIndex < imageSize.width(); ++columnIndex)
            {
                kScanLine[columnIndex] = qRgba(
                    (columnIndex * 255) / std::max(1, imageSize.width()),
                    (rowIndex * 255) / std::max(1, imageSize.height()),
                    128,
                    255);
            }
        }
        return QPixmap::fromImage(generatedImage);
    }

    // ProbeBackgroundWidget:
    // - Replicate the critical path of the main window background painter: penetrate the base color and overlay the background image centered and scaled proportionally.
    // - The cost measured by dragging the benchmark is exactly the cost of this path after overlaying transparent child control trees.
    class ProbeBackgroundWidget final : public QWidget
    {
    public:
        ProbeBackgroundWidget(QPixmap backgroundImage, const int imageOpacityPercent, QWidget* parent)
            : QWidget(parent)
            , backgroundImage_(std::move(backgroundImage))
            , imageOpacityPercent_(std::clamp(imageOpacityPercent, 0, 100))
        {
            setAutoFillBackground(false);
            setAttribute(Qt::WA_StyledBackground, false);
            setAttribute(Qt::WA_OpaquePaintEvent, false);
        }

    protected:
        void paintEvent(QPaintEvent* event) override
        {
            QPainter painter(this);
            if (event != nullptr)
            {
                painter.setClipRegion(event->region());
            }
            // As in the main window, keep the background alpha at 1 in translucent mode to preserve mouse hit testing.
            QColor hitTestFloorColor(18, 18, 18);
            hitTestFloorColor.setAlpha(1);
            painter.setCompositionMode(QPainter::CompositionMode_Source);
            painter.fillRect(rect(), hitTestFloorColor);
            painter.setCompositionMode(QPainter::CompositionMode_SourceOver);

            if (backgroundImage_.isNull() || imageOpacityPercent_ <= 0 || rect().isEmpty())
            {
                return;
            }
            QSizeF scaledSize(backgroundImage_.size());
            scaledSize.scale(QSizeF(rect().size()), Qt::KeepAspectRatioByExpanding);
            const QRectF kTargetRect(
                (static_cast<double>(rect().width()) - scaledSize.width()) / 2.0,
                (static_cast<double>(rect().height()) - scaledSize.height()) / 2.0,
                scaledSize.width(),
                scaledSize.height());
            painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
            painter.setOpacity(static_cast<double>(imageOpacityPercent_) / 100.0);
            painter.drawPixmap(
                kTargetRect,
                backgroundImage_,
                QRectF(QPointF(0, 0), backgroundImage_.size()));
        }

    private:
        QPixmap backgroundImage_;
        int imageOpacityPercent_ = 0;
    };

    // SolidColorPanel:
    // - Solid color background panel for composition detection, serving as 'known content behind the window'.
    class SolidColorPanel final : public QWidget
    {
    public:
        explicit SolidColorPanel(const QColor& fillColor)
            : fillColor_(fillColor)
        {
            setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
            setAttribute(Qt::WA_ShowWithoutActivating, true);
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.fillRect(rect(), fillColor_);
        }

    private:
        QColor fillColor_;
    };

    // ScreenAreaSample purpose: Average color obtained from screen capture sampling.
    struct ScreenAreaSample
    {
        double redAverage = 0.0;
        double greenAverage = 0.0;
        double blueAverage = 0.0;
        bool valid = false;
    };

    // sampleScreenArea:
    // - Read the final rendered frame after DWM composition for the window's screen area and calculate the average color.
    // - Must use GetDC(nullptr) + BitBlt: PrintWindow only captures the window's
    //   own pixels and cannot capture the acrylic blur effect on content behind it.
    // Input windowHandle: target window; Input insetRatio: inset ratio for all sides to avoid edge shadows.
    // Returns: Average color sampling result.
    ScreenAreaSample sampleScreenArea(HWND windowHandle, const double insetRatio)
    {
        ScreenAreaSample sample;
        RECT windowRect{};
        if (windowHandle == nullptr || ::GetWindowRect(windowHandle, &windowRect) == FALSE)
        {
            return sample;
        }
        const int kFullWidth = windowRect.right - windowRect.left;
        const int kFullHeight = windowRect.bottom - windowRect.top;
        const int kInsetX = static_cast<int>(kFullWidth * insetRatio);
        const int kInsetY = static_cast<int>(kFullHeight * insetRatio);
        const int kSampleWidth = kFullWidth - kInsetX * 2;
        const int kSampleHeight = kFullHeight - kInsetY * 2;
        if (kSampleWidth <= 0 || kSampleHeight <= 0)
        {
            return sample;
        }

        HDC screenDeviceContext = ::GetDC(nullptr);
        if (screenDeviceContext == nullptr)
        {
            return sample;
        }
        HDC memoryDeviceContext = ::CreateCompatibleDC(screenDeviceContext);
        HBITMAP memoryBitmap = ::CreateCompatibleBitmap(screenDeviceContext, kSampleWidth, kSampleHeight);
        HGDIOBJ previousObject = ::SelectObject(memoryDeviceContext, memoryBitmap);
        const BOOL kBlitOk = ::BitBlt(
            memoryDeviceContext,
            0,
            0,
            kSampleWidth,
            kSampleHeight,
            screenDeviceContext,
            windowRect.left + kInsetX,
            windowRect.top + kInsetY,
            SRCCOPY);

        if (kBlitOk != FALSE)
        {
            BITMAPINFO bitmapInfo{};
            bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
            bitmapInfo.bmiHeader.biWidth = kSampleWidth;
            bitmapInfo.bmiHeader.biHeight = -kSampleHeight; // Negative height indicates top-down layout.
            bitmapInfo.bmiHeader.biPlanes = 1;
            bitmapInfo.bmiHeader.biBitCount = 32;
            bitmapInfo.bmiHeader.biCompression = BI_RGB;
            std::vector<BYTE> pixelBuffer(static_cast<size_t>(kSampleWidth) * kSampleHeight * 4);
            const int kCopiedLines = ::GetDIBits(
                memoryDeviceContext,
                memoryBitmap,
                0,
                static_cast<UINT>(kSampleHeight),
                pixelBuffer.data(),
                &bitmapInfo,
                DIB_RGB_COLORS);
            if (kCopiedLines != 0)
            {
                double totalRed = 0.0;
                double totalGreen = 0.0;
                double totalBlue = 0.0;
                const size_t kPixelCount = static_cast<size_t>(kSampleWidth) * kSampleHeight;
                for (size_t pixelIndex = 0; pixelIndex < kPixelCount; ++pixelIndex)
                {
                    totalBlue += pixelBuffer[pixelIndex * 4 + 0];
                    totalGreen += pixelBuffer[pixelIndex * 4 + 1];
                    totalRed += pixelBuffer[pixelIndex * 4 + 2];
                }
                sample.redAverage = totalRed / static_cast<double>(kPixelCount);
                sample.greenAverage = totalGreen / static_cast<double>(kPixelCount);
                sample.blueAverage = totalBlue / static_cast<double>(kPixelCount);
                sample.valid = true;
            }
        }

        ::SelectObject(memoryDeviceContext, previousObject);
        ::DeleteObject(memoryBitmap);
        ::DeleteDC(memoryDeviceContext);
        ::ReleaseDC(nullptr, screenDeviceContext);
        return sample;
    }

    // probeWindowResponseMs:
    // - Post an empty message to the target window's message queue and wait for it to be processed.
    // - When the UI thread is busy repainting, it cannot respond to WM_NULL; the round-trip duration equals the blocked time.
    // - SMTO_BLOCK ensures we are not released prematurely, while SMTO_ABORTIFHUNG causes hung windows to return quickly.
    // Input parameters: windowHandle is the target window; timeoutMs is the upper limit, where timeouts are counted as the upper limit.
    // Returns: Round-trip latency in milliseconds.
    double probeWindowResponseMs(HWND windowHandle, const UINT timeoutMs)
    {
        DWORD_PTR messageResult = 0;
        QElapsedTimer roundTripTimer;
        roundTripTimer.start();
        const LRESULT kSendResult = ::SendMessageTimeoutW(
            windowHandle,
            WM_NULL,
            0,
            0,
            SMTO_BLOCK | SMTO_ABORTIFHUNG,
            timeoutMs,
            &messageResult);
        const double kElapsedMs = static_cast<double>(roundTripTimer.nsecsElapsed()) / 1e6;
        return kSendResult == 0 ? static_cast<double>(timeoutMs) : kElapsedMs;
    }

    // WindowEnumerationContext purpose: Collection context for EnumWindows callbacks.
    struct WindowEnumerationContext
    {
        QVector<ks::misc::TargetWindowEntry>* entries = nullptr;
        DWORD selfProcessId = 0;
    };

    // queryProcessImageName:
    // - Retrieve image name by PID; return empty string on failure, with caller handling fallback display.
    QString queryProcessImageName(const DWORD processId)
    {
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return QString();
        }
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        QString imageName;
        if (::Process32FirstW(snapshotHandle, &processEntry) != FALSE)
        {
            do
            {
                if (processEntry.th32ProcessID == processId)
                {
                    imageName = QString::fromWCharArray(processEntry.szExeFile);
                    break;
                }
            } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);
        }
        ::CloseHandle(snapshotHandle);
        return imageName;
    }

    // enumerateVisibleTopLevelWindow: EnumWindows callback to collect visible top-level windows with titles.
    BOOL CALLBACK enumerateVisibleTopLevelWindow(HWND windowHandle, LPARAM callbackParameter)
    {
        WindowEnumerationContext* const kContext =
            reinterpret_cast<WindowEnumerationContext*>(callbackParameter);
        if (kContext == nullptr || kContext->entries == nullptr)
        {
            return FALSE;
        }
        if (::IsWindowVisible(windowHandle) == FALSE || ::GetWindow(windowHandle, GW_OWNER) != nullptr)
        {
            return TRUE;
        }
        RECT windowRect{};
        if (::GetWindowRect(windowHandle, &windowRect) == FALSE)
        {
            return TRUE;
        }
        // Filter out tool windows and extremely small windows: they have no reference value when moved.
        if ((windowRect.right - windowRect.left) < 200 || (windowRect.bottom - windowRect.top) < 200)
        {
            return TRUE;
        }
        wchar_t titleBuffer[512] = {};
        ::GetWindowTextW(windowHandle, titleBuffer, static_cast<int>(std::size(titleBuffer)) - 1);
        const QString kTitleText = QString::fromWCharArray(titleBuffer).trimmed();
        if (kTitleText.isEmpty())
        {
            return TRUE;
        }

        DWORD ownerProcessId = 0;
        ::GetWindowThreadProcessId(windowHandle, &ownerProcessId);
        const QString kImageName = queryProcessImageName(ownerProcessId);

        ks::misc::TargetWindowEntry entry;
        entry.windowHandleValue = reinterpret_cast<quint64>(windowHandle);
        entry.belongsToSelf = (ownerProcessId == kContext->selfProcessId);
        entry.displayText = QStringLiteral("%1 - %2 (PID %3)")
            .arg(kTitleText.left(60))
            .arg(kImageName.isEmpty() ? QStringLiteral("?") : kImageName)
            .arg(ownerProcessId);
        kContext->entries->push_back(entry);
        return TRUE;
    }
}

namespace ks::misc
{
    RenderBenchmarkPage::RenderBenchmarkPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
        refreshTargetWindowList();

        KLogEvent initEvent;
        info << initEvent << "[RenderBenchmark] 渲染基准页初始化完成。" << eol;
    }

    void RenderBenchmarkPage::initializeUi()
    {
        QVBoxLayout* const kRootLayout = new QVBoxLayout(this);
        kRootLayout->setContentsMargins(10, 10, 10, 10);
        kRootLayout->setSpacing(8);

        ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

        // ===== Top Action Bar =====
        QHBoxLayout* const kTopActionLayout = new QHBoxLayout();
        kTopActionLayout->setSpacing(6);

        runAllButton_ = new QPushButton(QStringLiteral("运行全部测试"), this);
        // The subject under test is the UI thread itself; this message must be visible to the user before they click, otherwise the expected freeze will be mistaken for a crash.
        runAllButton_->setToolTip(
            QStringLiteral("所有测量都在 UI 线程执行，每项测试运行时界面会短暂无响应，属于预期行为。结论随 Windows 版本和当前外观设置变化，此页只报告实测值。"));
        languageManager.bindText(
            runAllButton_,
            QStringLiteral("misc.render_benchmark.run_all"),
            QStringLiteral("运行全部测试"));
        kTopActionLayout->addWidget(runAllButton_);

        statusLabel_ = new QLabel(QStringLiteral("就绪。"), this);
        languageManager.bindText(
            statusLabel_,
            QStringLiteral("misc.render_benchmark.status.idle"),
            QStringLiteral("就绪。"));
        kTopActionLayout->addWidget(statusLabel_, 1);

        progressBar_ = new QProgressBar(this);
        progressBar_->setRange(0, 100);
        progressBar_->setValue(0);
        progressBar_->setFixedWidth(180);
        progressBar_->setVisible(false);
        kTopActionLayout->addWidget(progressBar_);

        kRootLayout->addLayout(kTopActionLayout);

        // ===== Test 1: Main window repaint benchmark =====
        QGroupBox* const kRepaintGroupBox = new QGroupBox(QStringLiteral("主窗口整树重绘"), this);
        languageManager.bindText(
            kRepaintGroupBox,
            QStringLiteral("misc.render_benchmark.repaint.group"),
            QStringLiteral("主窗口整树重绘"));
        QVBoxLayout* const kRepaintLayout = new QVBoxLayout(kRepaintGroupBox);
        kRepaintLayout->setSpacing(6);

        QLabel* const kRepaintHintLabel = new QLabel(
            QStringLiteral("把主窗口根容器渲染到离屏位图，量一次完整重绘的耗时，并拆出“仅背景层”与“子控件树”各占多少。"
                "启用透明背景后所有 Dock 内容都是透明的，父容器重绘会连带重画整棵控件树，这一项就是用来看那个代价的。"
                "测量走离屏渲染，不会改动屏幕上的真实界面。"),
            kRepaintGroupBox);
        kRepaintHintLabel->setWordWrap(true);
        languageManager.bindText(
            kRepaintHintLabel,
            QStringLiteral("misc.render_benchmark.repaint.hint"),
            QStringLiteral("把主窗口根容器渲染到离屏位图，量一次完整重绘的耗时，并拆出“仅背景层”与“子控件树”各占多少。"
                "启用透明背景后所有 Dock 内容都是透明的，父容器重绘会连带重画整棵控件树，这一项就是用来看那个代价的。"
                "测量走离屏渲染，不会改动屏幕上的真实界面。"));
        kRepaintLayout->addWidget(kRepaintHintLabel);

        QHBoxLayout* const kRepaintActionLayout = new QHBoxLayout();
        kRepaintActionLayout->setSpacing(6);
        QLabel* const kRepaintIterationLabel = new QLabel(QStringLiteral("采样次数"), kRepaintGroupBox);
        languageManager.bindText(
            kRepaintIterationLabel,
            QStringLiteral("misc.render_benchmark.repaint.iterations"),
            QStringLiteral("采样次数"));
        kRepaintActionLayout->addWidget(kRepaintIterationLabel);
        repaintIterationSpin_ = new QSpinBox(kRepaintGroupBox);
        repaintIterationSpin_->setRange(3, 200);
        repaintIterationSpin_->setValue(20);
        kRepaintActionLayout->addWidget(repaintIterationSpin_);
        runRepaintButton_ = new QPushButton(QStringLiteral("运行重绘基准"), kRepaintGroupBox);
        languageManager.bindText(
            runRepaintButton_,
            QStringLiteral("misc.render_benchmark.repaint.run"),
            QStringLiteral("运行重绘基准"));
        kRepaintActionLayout->addWidget(runRepaintButton_);
        kRepaintActionLayout->addStretch();
        kRepaintLayout->addLayout(kRepaintActionLayout);
        kRootLayout->addWidget(kRepaintGroupBox);

        // ===== Test 2: Drag A/B =====
        QGroupBox* const kDragGroupBox = new QGroupBox(QStringLiteral("拖动流畅度 A/B"), this);
        languageManager.bindText(
            kDragGroupBox,
            QStringLiteral("misc.render_benchmark.drag.group"),
            QStringLiteral("拖动流畅度 A/B"));
        QVBoxLayout* const kDragLayout = new QVBoxLayout(kDragGroupBox);
        kDragLayout->setSpacing(6);

        QLabel* const kDragHintLabel = new QLabel(
            QStringLiteral("建一个与主窗口同构的测试窗口（无边框、透明背景、磨砂材质、铺满透明表格），模拟 60fps 拖动，"
                "对比“每次材质刷新都重绘整树”与“只下发材质不重绘”两种策略的掉帧率。运行时屏幕上会出现一个测试窗口并自行移动，测完自动关闭。"),
            kDragGroupBox);
        kDragHintLabel->setWordWrap(true);
        languageManager.bindText(
            kDragHintLabel,
            QStringLiteral("misc.render_benchmark.drag.hint"),
            QStringLiteral("建一个与主窗口同构的测试窗口（无边框、透明背景、磨砂材质、铺满透明表格），模拟 60fps 拖动，"
                "对比“每次材质刷新都重绘整树”与“只下发材质不重绘”两种策略的掉帧率。运行时屏幕上会出现一个测试窗口并自行移动，测完自动关闭。"));
        kDragLayout->addWidget(kDragHintLabel);

        QHBoxLayout* const kDragActionLayout = new QHBoxLayout();
        kDragActionLayout->setSpacing(6);
        QLabel* const kDragFrameLabel = new QLabel(QStringLiteral("模拟帧数"), kDragGroupBox);
        languageManager.bindText(
            kDragFrameLabel,
            QStringLiteral("misc.render_benchmark.drag.frames"),
            QStringLiteral("模拟帧数"));
        kDragActionLayout->addWidget(kDragFrameLabel);
        dragFrameSpin_ = new QSpinBox(kDragGroupBox);
        dragFrameSpin_->setRange(30, 600);
        dragFrameSpin_->setValue(120);
        kDragActionLayout->addWidget(dragFrameSpin_);

        QLabel* const kDragRowLabel = new QLabel(QStringLiteral("表格行数"), kDragGroupBox);
        languageManager.bindText(
            kDragRowLabel,
            QStringLiteral("misc.render_benchmark.drag.rows"),
            QStringLiteral("表格行数"));
        kDragActionLayout->addWidget(kDragRowLabel);
        dragRowSpin_ = new QSpinBox(kDragGroupBox);
        dragRowSpin_->setRange(0, 3000);
        dragRowSpin_->setValue(600);
        kDragActionLayout->addWidget(dragRowSpin_);

        runDragButton_ = new QPushButton(QStringLiteral("运行拖动对比"), kDragGroupBox);
        languageManager.bindText(
            runDragButton_,
            QStringLiteral("misc.render_benchmark.drag.run"),
            QStringLiteral("运行拖动对比"));
        kDragActionLayout->addWidget(runDragButton_);
        kDragActionLayout->addStretch();
        kDragLayout->addLayout(kDragActionLayout);
        kRootLayout->addWidget(kDragGroupBox);

        // ===== Test 3: DWM composition capability detection =====
        QGroupBox* const kCompositionGroupBox = new QGroupBox(QStringLiteral("DWM 合成能力探测"), this);
        languageManager.bindText(
            kCompositionGroupBox,
            QStringLiteral("misc.render_benchmark.composition.group"),
            QStringLiteral("DWM 合成能力探测"));
        QVBoxLayout* const kCompositionLayout = new QVBoxLayout(kCompositionGroupBox);
        kCompositionLayout->setSpacing(6);

        QLabel* const kCompositionHintLabel = new QLabel(
            QStringLiteral("在屏幕上铺一块纯红面板和一块纯蓝面板，把磨砂窗口在两者之间移动，"
                "用 BitBlt 抓 DWM 合成后的画面求平均色。据此判断两件事：磨砂是否真的生效（采样值应偏离面板本色），"
                "以及移动后不做任何处理时磨砂是否仍会跟随重采样。运行时屏幕会短暂出现彩色面板。"),
            kCompositionGroupBox);
        kCompositionHintLabel->setWordWrap(true);
        languageManager.bindText(
            kCompositionHintLabel,
            QStringLiteral("misc.render_benchmark.composition.hint"),
            QStringLiteral("在屏幕上铺一块纯红面板和一块纯蓝面板，把磨砂窗口在两者之间移动，"
                "用 BitBlt 抓 DWM 合成后的画面求平均色。据此判断两件事：磨砂是否真的生效（采样值应偏离面板本色），"
                "以及移动后不做任何处理时磨砂是否仍会跟随重采样。运行时屏幕会短暂出现彩色面板。"));
        kCompositionLayout->addWidget(kCompositionHintLabel);

        QHBoxLayout* const kCompositionActionLayout = new QHBoxLayout();
        kCompositionActionLayout->setSpacing(6);
        runCompositionButton_ = new QPushButton(QStringLiteral("运行合成探测"), kCompositionGroupBox);
        languageManager.bindText(
            runCompositionButton_,
            QStringLiteral("misc.render_benchmark.composition.run"),
            QStringLiteral("运行合成探测"));
        kCompositionActionLayout->addWidget(runCompositionButton_);
        kCompositionActionLayout->addStretch();
        kCompositionLayout->addLayout(kCompositionActionLayout);
        kRootLayout->addWidget(kCompositionGroupBox);

        // ===== Test 4: Target Window Response Probe =====
        QGroupBox* const kResponseGroupBox = new QGroupBox(QStringLiteral("窗口响应探针"), this);
        languageManager.bindText(
            kResponseGroupBox,
            QStringLiteral("misc.render_benchmark.response.group"),
            QStringLiteral("窗口响应探针"));
        QVBoxLayout* const kResponseLayout = new QVBoxLayout(kResponseGroupBox);
        kResponseLayout->setSpacing(6);

        QLabel* const kResponseHintLabel = new QLabel(
            QStringLiteral("对选定窗口连续 SetWindowPos 模拟拖动，每帧用 WM_NULL 往返测它的 UI 线程被阻塞多久——"
                "线程忙着重绘就回不了空消息，往返耗时即卡顿时长。可以测别的进程的窗口。"
                "测试只移动窗口位置，结束后放回原处；最大化的窗口无法移动，请先还原。"),
            kResponseGroupBox);
        kResponseHintLabel->setWordWrap(true);
        languageManager.bindText(
            kResponseHintLabel,
            QStringLiteral("misc.render_benchmark.response.hint"),
            QStringLiteral("对选定窗口连续 SetWindowPos 模拟拖动，每帧用 WM_NULL 往返测它的 UI 线程被阻塞多久——"
                "线程忙着重绘就回不了空消息，往返耗时即卡顿时长。可以测别的进程的窗口。"
                "测试只移动窗口位置，结束后放回原处；最大化的窗口无法移动，请先还原。"));
        kResponseLayout->addWidget(kResponseHintLabel);

        QHBoxLayout* const kResponseTargetLayout = new QHBoxLayout();
        kResponseTargetLayout->setSpacing(6);
        QLabel* const kResponseTargetLabel = new QLabel(QStringLiteral("目标窗口"), kResponseGroupBox);
        languageManager.bindText(
            kResponseTargetLabel,
            QStringLiteral("misc.render_benchmark.response.target"),
            QStringLiteral("目标窗口"));
        kResponseTargetLayout->addWidget(kResponseTargetLabel);
        targetWindowCombo_ = new QComboBox(kResponseGroupBox);
        targetWindowCombo_->setMinimumWidth(360);
        kResponseTargetLayout->addWidget(targetWindowCombo_, 1);
        refreshTargetsButton_ = new QPushButton(QStringLiteral("刷新窗口列表"), kResponseGroupBox);
        languageManager.bindText(
            refreshTargetsButton_,
            QStringLiteral("misc.render_benchmark.response.refresh"),
            QStringLiteral("刷新窗口列表"));
        kResponseTargetLayout->addWidget(refreshTargetsButton_);
        kResponseLayout->addLayout(kResponseTargetLayout);

        QHBoxLayout* const kResponseActionLayout = new QHBoxLayout();
        kResponseActionLayout->setSpacing(6);
        QLabel* const kResponseFrameLabel = new QLabel(QStringLiteral("模拟帧数"), kResponseGroupBox);
        languageManager.bindText(
            kResponseFrameLabel,
            QStringLiteral("misc.render_benchmark.response.frames"),
            QStringLiteral("模拟帧数"));
        kResponseActionLayout->addWidget(kResponseFrameLabel);
        responseFrameSpin_ = new QSpinBox(kResponseGroupBox);
        responseFrameSpin_->setRange(30, 600);
        responseFrameSpin_->setValue(120);
        kResponseActionLayout->addWidget(responseFrameSpin_);
        runResponseButton_ = new QPushButton(QStringLiteral("运行响应探针"), kResponseGroupBox);
        languageManager.bindText(
            runResponseButton_,
            QStringLiteral("misc.render_benchmark.response.run"),
            QStringLiteral("运行响应探针"));
        kResponseActionLayout->addWidget(runResponseButton_);
        kResponseActionLayout->addStretch();
        kResponseLayout->addLayout(kResponseActionLayout);
        kRootLayout->addWidget(kResponseGroupBox);

        // ===== Report Section =====
        QHBoxLayout* const kReportActionLayout = new QHBoxLayout();
        kReportActionLayout->setSpacing(6);
        QLabel* const kReportLabel = new QLabel(QStringLiteral("测试报告"), this);
        languageManager.bindText(
            kReportLabel,
            QStringLiteral("misc.render_benchmark.report"),
            QStringLiteral("测试报告"));
        kReportActionLayout->addWidget(kReportLabel);
        kReportActionLayout->addStretch();
        copyReportButton_ = new QPushButton(QStringLiteral("复制报告"), this);
        languageManager.bindText(
            copyReportButton_,
            QStringLiteral("misc.render_benchmark.report.copy"),
            QStringLiteral("复制报告"));
        kReportActionLayout->addWidget(copyReportButton_);
        saveReportButton_ = new QPushButton(QStringLiteral("导出报告"), this);
        languageManager.bindText(
            saveReportButton_,
            QStringLiteral("misc.render_benchmark.report.save"),
            QStringLiteral("导出报告"));
        kReportActionLayout->addWidget(saveReportButton_);
        clearReportButton_ = new QPushButton(QStringLiteral("清空报告"), this);
        languageManager.bindText(
            clearReportButton_,
            QStringLiteral("misc.render_benchmark.report.clear"),
            QStringLiteral("清空报告"));
        kReportActionLayout->addWidget(clearReportButton_);
        kRootLayout->addLayout(kReportActionLayout);

        reportEdit_ = new QPlainTextEdit(this);
        reportEdit_->setReadOnly(true);
        reportEdit_->setLineWrapMode(QPlainTextEdit::NoWrap);
        reportEdit_->setMinimumHeight(180);
        kRootLayout->addWidget(reportEdit_, 1);
    }

    void RenderBenchmarkPage::initializeConnections()
    {
        connect(runAllButton_, &QPushButton::clicked, this, [this]() { runAllBenchmarks(); });
        connect(runRepaintButton_, &QPushButton::clicked, this, [this]() { runMainWindowRepaintBenchmark(); });
        connect(runDragButton_, &QPushButton::clicked, this, [this]() { runDragSimulationBenchmark(); });
        connect(runCompositionButton_, &QPushButton::clicked, this, [this]() { runCompositionProbe(); });
        connect(runResponseButton_, &QPushButton::clicked, this, [this]() { runWindowResponseProbe(); });
        connect(refreshTargetsButton_, &QPushButton::clicked, this, [this]() { refreshTargetWindowList(); });
        connect(copyReportButton_, &QPushButton::clicked, this, [this]() { copyReportToClipboard(); });
        connect(saveReportButton_, &QPushButton::clicked, this, [this]() { saveReportToFile(); });
        connect(clearReportButton_, &QPushButton::clicked, this, [this]() { reportEdit_->clear(); });
    }

    void RenderBenchmarkPage::appendReportLine(const QString& lineText)
    {
        if (reportEdit_ != nullptr)
        {
            reportEdit_->appendPlainText(lineText);
        }
    }

    void RenderBenchmarkPage::appendReportSection(const QString& titleText)
    {
        appendReportLine(QString());
        appendReportLine(QStringLiteral("=== %1 @ %2 ===")
            .arg(titleText)
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
    }

    void RenderBenchmarkPage::appendSummaryLine(
        const QString& labelText,
        const BenchmarkSampleSummary& summary)
    {
        if (summary.sampleCount <= 0)
        {
            appendReportLine(QStringLiteral("  %1: 无有效样本").arg(labelText));
            return;
        }
        appendReportLine(QStringLiteral("  %1: 平均 %2 ms / p95 %3 ms / 最差 %4 ms / 超预算 %5 of %6 (%7%)")
            .arg(labelText)
            .arg(summary.averageMs, 0, 'f', 2)
            .arg(summary.p95Ms, 0, 'f', 2)
            .arg(summary.worstMs, 0, 'f', 2)
            .arg(summary.overBudgetCount)
            .arg(summary.sampleCount)
            .arg(100.0 * summary.overBudgetCount / summary.sampleCount, 0, 'f', 1));
    }

    void RenderBenchmarkPage::setBusy(const bool busy, const QString& statusText)
    {
        busy_ = busy;
        // Do not release the button even if an individual test finishes during batch execution.
        // The event loop must be allowed to refresh progress between the two actions; that brief window is sufficient for the user to click into the second test.
        const bool kEnabled = !busy && !batchRunning_;
        runAllButton_->setEnabled(kEnabled);
        runRepaintButton_->setEnabled(kEnabled);
        runDragButton_->setEnabled(kEnabled);
        runCompositionButton_->setEnabled(kEnabled);
        runResponseButton_->setEnabled(kEnabled);
        refreshTargetsButton_->setEnabled(kEnabled);
        progressBar_->setVisible(busy);
        if (!statusText.isEmpty())
        {
            statusLabel_->setText(statusText);
        }
        else if (!busy)
        {
            statusLabel_->setText(QStringLiteral("就绪。"));
        }
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }

    void RenderBenchmarkPage::refreshTargetWindowList()
    {
        targetWindows_.clear();
        WindowEnumerationContext context;
        context.entries = &targetWindows_;
        context.selfProcessId = ::GetCurrentProcessId();
        ::EnumWindows(enumerateVisibleTopLevelWindow, reinterpret_cast<LPARAM>(&context));

        targetWindowCombo_->clear();
        int preferredIndex = -1;
        for (int entryIndex = 0; entryIndex < targetWindows_.size(); ++entryIndex)
        {
            const TargetWindowEntry& entry = targetWindows_.at(entryIndex);
            targetWindowCombo_->addItem(entry.displayText, QVariant(entry.windowHandleValue));
            if (entry.belongsToSelf && preferredIndex < 0)
            {
                preferredIndex = entryIndex;
            }
        }
        if (preferredIndex >= 0)
        {
            targetWindowCombo_->setCurrentIndex(preferredIndex);
        }
    }

    void RenderBenchmarkPage::runMainWindowRepaintBenchmark()
    {
        if (busy_)
        {
            return;
        }
        appendReportSection(QStringLiteral("主窗口整树重绘"));

        QWidget* const kRootContainer = locateMainRootContainer();
        if (kRootContainer == nullptr || kRootContainer->size().isEmpty())
        {
            appendReportLine(QStringLiteral("  未找到主窗口根容器（ksMainRootContainer），跳过。"));
            return;
        }

        setBusy(true, QStringLiteral("正在测量主窗口重绘..."));
        const int kIterationCount = repaintIterationSpin_->value();

        // Render to offscreen bitmap: follows the same draw path as a real repaint but does not touch screen pixels.
        QPixmap offscreenCanvas(kRootContainer->size());
        std::vector<double> fullTreeSamples;
        std::vector<double> backgroundOnlySamples;
        fullTreeSamples.reserve(static_cast<size_t>(kIterationCount));
        backgroundOnlySamples.reserve(static_cast<size_t>(kIterationCount));

        QElapsedTimer renderTimer;
        for (int iterationIndex = 0; iterationIndex < kIterationCount; ++iterationIndex)
        {
            offscreenCanvas.fill(Qt::transparent);
            renderTimer.restart();
            kRootContainer->render(
                &offscreenCanvas,
                QPoint(),
                QRegion(),
                QWidget::DrawWindowBackground | QWidget::DrawChildren);
            fullTreeSamples.push_back(static_cast<double>(renderTimer.nsecsElapsed()) / 1e6);

            offscreenCanvas.fill(Qt::transparent);
            renderTimer.restart();
            kRootContainer->render(
                &offscreenCanvas,
                QPoint(),
                QRegion(),
                QWidget::RenderFlags(QWidget::DrawWindowBackground));
            backgroundOnlySamples.push_back(static_cast<double>(renderTimer.nsecsElapsed()) / 1e6);

            progressBar_->setValue((iterationIndex + 1) * 100 / std::max(1, kIterationCount));
            QCoreApplication::processEvents(QEventLoop::AllEvents, 2);
        }

        const BenchmarkSampleSummary kFullSummary = summarizeSamples(fullTreeSamples);
        const BenchmarkSampleSummary kBackgroundSummary = summarizeSamples(backgroundOnlySamples);

        appendReportLine(QStringLiteral("  根容器尺寸: %1 x %2，采样 %3 次")
            .arg(kRootContainer->width())
            .arg(kRootContainer->height())
            .arg(kIterationCount));
        appendSummaryLine(QStringLiteral("整树重绘"), kFullSummary);
        appendSummaryLine(QStringLiteral("仅背景层"), kBackgroundSummary);
        appendReportLine(QStringLiteral("  子控件树占用: %1 ms（整树平均 - 背景层平均）")
            .arg(std::max(0.0, kFullSummary.averageMs - kBackgroundSummary.averageMs), 0, 'f', 2));
        appendReportLine(QStringLiteral("  含义: 每让根容器重绘一次，就要付出“整树重绘”这个耗时。"
            "若它超过帧预算 %1 ms，任何按帧触发根容器重绘的逻辑都会造成可见掉帧。")
            .arg(kFrameBudgetMs, 0, 'f', 1));

        setBusy(false);
    }

    void RenderBenchmarkPage::runDragSimulationBenchmark()
    {
        if (busy_)
        {
            return;
        }
        appendReportSection(QStringLiteral("拖动流畅度 A/B"));
        setBusy(true, QStringLiteral("正在模拟拖动..."));

        const int kFrameCount = dragFrameSpin_->value();
        const int kRowCount = dragRowSpin_->value();

        // Reuse the current appearance settings to ensure the measured cost reflects the user's actual configuration.
        const ks::settings::AppearanceSettings kAppearanceSettings = ks::settings::loadAppearanceSettings();
        const QString kResolvedImagePath =
            ks::settings::resolveBackgroundImagePathForLoad(kAppearanceSettings.backgroundImagePath);
        QPixmap backgroundImage;
        if (!kResolvedImagePath.isEmpty())
        {
            backgroundImage.load(kResolvedImagePath);
        }
        if (backgroundImage.isNull())
        {
            backgroundImage = buildGradientWallpaper(QSize(1920, 1080));
        }

        QScreen* const kPrimaryScreen = QApplication::primaryScreen();
        const QRect kAvailableRect = kPrimaryScreen != nullptr
            ? kPrimaryScreen->availableGeometry()
            : QRect(0, 0, 1280, 720);
        const QSize kProbeSize(
            std::min(1200, std::max(600, kAvailableRect.width() / 2)),
            std::min(800, std::max(400, kAvailableRect.height() / 2)));

        struct DragScenarioResult
        {
            QString label;
            BenchmarkSampleSummary summary;
        };
        QVector<DragScenarioResult> scenarioResults;

        // Two rounds: corresponding to 'repaint entire tree on refresh' and 'only issue materials without repaint'.
        for (int scenarioIndex = 0; scenarioIndex < 2; ++scenarioIndex)
        {
            const bool kRepaintOnRefresh = (scenarioIndex == 0);

            QWidget probeWindow;
            probeWindow.setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
            probeWindow.setAttribute(Qt::WA_TranslucentBackground, true);
            probeWindow.setAttribute(Qt::WA_ShowWithoutActivating, true);
            probeWindow.resize(kProbeSize);

            QVBoxLayout* const kProbeLayout = new QVBoxLayout(&probeWindow);
            kProbeLayout->setContentsMargins(0, 0, 0, 0);
            kProbeLayout->setSpacing(0);

            ProbeBackgroundWidget* const kProbeBackground = new ProbeBackgroundWidget(
                backgroundImage,
                kAppearanceSettings.backgroundOpacityPercent,
                &probeWindow);
            kProbeLayout->addWidget(kProbeBackground, 1);

            QVBoxLayout* const kBackgroundLayout = new QVBoxLayout(kProbeBackground);
            kBackgroundLayout->setContentsMargins(0, 0, 0, 0);

            QTreeWidget* const kProbeTree = new QTreeWidget(kProbeBackground);
            kProbeTree->setColumnCount(6);
            kProbeTree->setUniformRowHeights(true);
            kProbeTree->setHeaderLabels(QStringList()
                << QStringLiteral("名称")
                << QStringLiteral("标识")
                << QStringLiteral("占用")
                << QStringLiteral("路径")
                << QStringLiteral("状态")
                << QStringLiteral("计数"));
            // Isomorphic to Dock content in transparent mode: all surfaces are transparent; parent repaint triggers a full tree repaint.
            kProbeTree->setStyleSheet(QStringLiteral(
                "QTreeWidget { background: transparent; border: none; }"
                "QTreeWidget::item { background: transparent; }"
                "QHeaderView::section { background: transparent; }"));
            for (int rowIndex = 0; rowIndex < kRowCount; ++rowIndex)
            {
                QTreeWidgetItem* const kRowItem = new QTreeWidgetItem(kProbeTree);
                kRowItem->setText(0, QStringLiteral("benchmark_row_%1").arg(rowIndex));
                kRowItem->setText(1, QString::number(1000 + rowIndex));
                kRowItem->setText(2, QStringLiteral("%1 KB").arg((rowIndex * 137) % 900000));
                kRowItem->setText(3, QStringLiteral("C:\\Windows\\System32\\benchmark.dll"));
                kRowItem->setText(4, QStringLiteral("running"));
                kRowItem->setText(5, QString::number((rowIndex * 7) % 4096));
            }
            kBackgroundLayout->addWidget(kProbeTree, 1);

            const QPoint kStartPoint(
                kAvailableRect.left() + 40,
                kAvailableRect.top() + std::max(0, (kAvailableRect.height() - kProbeSize.height()) / 2));
            probeWindow.move(kStartPoint);
            probeWindow.show();
            pumpUserInterface(220);

            const HWND kProbeHandle = reinterpret_cast<HWND>(probeWindow.winId());
            const int kAcrylicTintAlpha =
                ks::settings::tintAlphaFromOpacityPercent(kAppearanceSettings.acrylicTintOpacityPercent);
            submitAcrylicAccent(kProbeHandle, kAcrylicTintAlpha);
            pumpUserInterface(200);

            const int kTravelRange = std::max(
                60,
                kAvailableRect.width() - kProbeSize.width() - 80);
            std::vector<double> frameSamples;
            frameSamples.reserve(static_cast<size_t>(kFrameCount));

            QElapsedTimer frameTimer;
            bool refreshQueued = false;
            QElapsedTimer throttleTimer;
            throttleTimer.start();

            for (int frameIndex = 0; frameIndex < kFrameCount; ++frameIndex)
            {
                const int kOffsetX = (frameIndex % 120) * kTravelRange / 120;
                frameTimer.restart();
                probeWindow.move(kStartPoint.x() + kOffsetX, kStartPoint.y());

                // Replicate 40ms throttling: refresh materials at fixed intervals during dragging.
                if (!refreshQueued && throttleTimer.elapsed() >= 40)
                {
                    refreshQueued = true;
                }
                if (refreshQueued)
                {
                    refreshQueued = false;
                    throttleTimer.restart();
                    submitAcrylicAccent(kProbeHandle, kAcrylicTintAlpha);
                    if (kRepaintOnRefresh)
                    {
                        kProbeBackground->repaint();
                    }
                }
                QCoreApplication::processEvents(QEventLoop::AllEvents, 4);
                const double kBusyMs = static_cast<double>(frameTimer.nsecsElapsed()) / 1e6;
                frameSamples.push_back(kBusyMs);

                if (kBusyMs < kFrameBudgetMs)
                {
                    ::Sleep(static_cast<DWORD>(kFrameBudgetMs - kBusyMs));
                }
                progressBar_->setValue(
                    (scenarioIndex * 50) + (frameIndex + 1) * 50 / std::max(1, kFrameCount));
            }

            probeWindow.hide();
            pumpUserInterface(120);

            DragScenarioResult scenarioResult;
            scenarioResult.label = kRepaintOnRefresh
                ? QStringLiteral("刷新时重绘整树")
                : QStringLiteral("只下发材质不重绘");
            scenarioResult.summary = summarizeSamples(frameSamples);
            scenarioResults.push_back(scenarioResult);
        }

        appendReportLine(QStringLiteral("  测试窗口: %1 x %2，表格 %3 行，模拟 %4 帧 @ 60fps")
            .arg(kProbeSize.width())
            .arg(kProbeSize.height())
            .arg(kRowCount)
            .arg(kFrameCount));
        for (const DragScenarioResult& scenarioResult : scenarioResults)
        {
            appendSummaryLine(scenarioResult.label, scenarioResult.summary);
        }
        if (scenarioResults.size() == 2
            && scenarioResults.at(0).summary.sampleCount > 0
            && scenarioResults.at(1).summary.sampleCount > 0)
        {
            const double kRepaintJankRate = 100.0
                * scenarioResults.at(0).summary.overBudgetCount
                / scenarioResults.at(0).summary.sampleCount;
            const double kPlainJankRate = 100.0
                * scenarioResults.at(1).summary.overBudgetCount
                / scenarioResults.at(1).summary.sampleCount;
            appendReportLine(QStringLiteral("  掉帧率差异: %1% -> %2%")
                .arg(kRepaintJankRate, 0, 'f', 1)
                .arg(kPlainJankRate, 0, 'f', 1));
        }

        setBusy(false);
    }

    void RenderBenchmarkPage::runCompositionProbe()
    {
        if (busy_)
        {
            return;
        }
        appendReportSection(QStringLiteral("DWM 合成能力探测"));

        if (resolveSetWindowCompositionAttribute() == nullptr)
        {
            appendReportLine(QStringLiteral("  本机 user32 未导出 SetWindowCompositionAttribute，无法测试亚克力。"));
            return;
        }

        setBusy(true, QStringLiteral("正在探测 DWM 合成..."));

        QScreen* const kPrimaryScreen = QApplication::primaryScreen();
        const QRect kAvailableRect = kPrimaryScreen != nullptr
            ? kPrimaryScreen->availableGeometry()
            : QRect(0, 0, 1280, 720);
        const int kPanelWidth = kAvailableRect.width() / 2;
        const int kPanelHeight = kAvailableRect.height() / 2;
        const int kPanelTop = kAvailableRect.top() + kAvailableRect.height() / 4;

        // Uses two known solid colors as 'content behind the window'; red and blue are chosen because the difference in their red and blue components is sufficient for distinction.
        const QColor kRedPanelColor(220, 20, 20);
        const QColor kBluePanelColor(20, 20, 220);
        SolidColorPanel redPanel(kRedPanelColor);
        redPanel.setGeometry(kAvailableRect.left(), kPanelTop, kPanelWidth, kPanelHeight);
        redPanel.show();
        SolidColorPanel bluePanel(kBluePanelColor);
        bluePanel.setGeometry(kAvailableRect.left() + kPanelWidth, kPanelTop, kPanelWidth, kPanelHeight);
        bluePanel.show();
        pumpUserInterface(200);

        const QSize kProbeSize(360, 260);
        QWidget acrylicProbe;
        acrylicProbe.setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
        acrylicProbe.setAttribute(Qt::WA_TranslucentBackground, true);
        acrylicProbe.setAttribute(Qt::WA_ShowWithoutActivating, true);
        acrylicProbe.resize(kProbeSize);

        const QPoint kOverRedPoint(
            kAvailableRect.left() + kPanelWidth / 2 - kProbeSize.width() / 2,
            kPanelTop + kPanelHeight / 2 - kProbeSize.height() / 2);
        const QPoint kOverBluePoint(
            kAvailableRect.left() + kPanelWidth + kPanelWidth / 2 - kProbeSize.width() / 2,
            kPanelTop + kPanelHeight / 2 - kProbeSize.height() / 2);

        acrylicProbe.move(kOverRedPoint);
        acrylicProbe.show();
        pumpUserInterface(220);

        const HWND kProbeHandle = reinterpret_cast<HWND>(acrylicProbe.winId());
        // Lower the alpha of the color to let the background panel dominate the sample; otherwise, the measurement would be of the color layer itself.
        const bool kAccentApplied = submitAcrylicAccent(kProbeHandle, 24);
        pumpUserInterface(500);
        progressBar_->setValue(30);

        const ScreenAreaSample kOverRedSample = sampleScreenArea(kProbeHandle, 0.20);

        // Do nothing after moving to the blue zone: this step asks whether DWM will resample on its own.
        acrylicProbe.move(kOverBluePoint);
        pumpUserInterface(600);
        progressBar_->setValue(70);
        const ScreenAreaSample kOverBlueSample = sampleScreenArea(kProbeHandle, 0.20);

        acrylicProbe.hide();
        redPanel.hide();
        bluePanel.hide();
        pumpUserInterface(120);
        progressBar_->setValue(100);

        appendReportLine(QStringLiteral("  组合特性下发: %1")
            .arg(kAccentApplied ? QStringLiteral("成功") : QStringLiteral("失败")));
        if (!kOverRedSample.valid || !kOverBlueSample.valid)
        {
            appendReportLine(QStringLiteral("  屏幕采样失败，无法判定。"));
            setBusy(false);
            return;
        }

        const double kRedBias = kOverRedSample.redAverage - kOverRedSample.blueAverage;
        const double kBlueBias = kOverBlueSample.redAverage - kOverBlueSample.blueAverage;
        appendReportLine(QStringLiteral("  红面板上方采样: R %1 / G %2 / B %3，R-B %4")
            .arg(kOverRedSample.redAverage, 0, 'f', 1)
            .arg(kOverRedSample.greenAverage, 0, 'f', 1)
            .arg(kOverRedSample.blueAverage, 0, 'f', 1)
            .arg(kRedBias, 0, 'f', 1));
        appendReportLine(QStringLiteral("  蓝面板上方采样: R %1 / G %2 / B %3，R-B %4")
            .arg(kOverBlueSample.redAverage, 0, 'f', 1)
            .arg(kOverBlueSample.greenAverage, 0, 'f', 1)
            .arg(kOverBlueSample.blueAverage, 0, 'f', 1)
            .arg(kBlueBias, 0, 'f', 1));

        // A significant deviation between the sampled value and the panel's original color indicates the acrylic has applied coloring and brightness processing rather than being directly transparent.
        const double kRedDeviation = std::abs(kOverRedSample.redAverage - kRedPanelColor.red());
        const bool kAcrylicEffective = kAccentApplied && kRedDeviation > 5.0;
        appendReportLine(QStringLiteral("  磨砂是否生效: %1（红面板本色 R %2，采样 R %3，偏离 %4）")
            .arg(kAcrylicEffective ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(kRedPanelColor.red())
            .arg(kOverRedSample.redAverage, 0, 'f', 1)
            .arg(kRedDeviation, 0, 'f', 1));

        const bool kResampled = (kRedBias > 10.0) && (kBlueBias < -10.0);
        appendReportLine(QStringLiteral("  移动后自动重采样: %1")
            .arg(kResampled ? QStringLiteral("是") : QStringLiteral("否")));
        appendReportLine(kResampled
            ? QStringLiteral("  含义: 窗口移动后无需重下发组合特性，也无需重绘，DWM 会自行跟随。"
                "按帧刷新材质只会白白付出重绘代价。")
            : QStringLiteral("  含义: 本机 DWM 不会自动跟随窗口位置重采样，"
                "移动结束后需要补下发一次组合特性才能拿到正确画面。"));

        setBusy(false);
    }

    void RenderBenchmarkPage::runWindowResponseProbe()
    {
        if (busy_)
        {
            return;
        }
        appendReportSection(QStringLiteral("窗口响应探针"));

        if (targetWindowCombo_->currentIndex() < 0)
        {
            appendReportLine(QStringLiteral("  没有可用的目标窗口，请先刷新窗口列表。"));
            return;
        }
        const quint64 kHandleValue = targetWindowCombo_->currentData().toULongLong();
        HWND targetHandle = reinterpret_cast<HWND>(kHandleValue);
        if (targetHandle == nullptr || ::IsWindow(targetHandle) == FALSE)
        {
            appendReportLine(QStringLiteral("  目标窗口已失效，请刷新窗口列表后重试。"));
            return;
        }
        if (::IsZoomed(targetHandle) != FALSE)
        {
            appendReportLine(QStringLiteral("  目标窗口处于最大化状态，无法移动。请先还原窗口再测。"));
            return;
        }

        RECT originRect{};
        if (::GetWindowRect(targetHandle, &originRect) == FALSE)
        {
            appendReportLine(QStringLiteral("  读取目标窗口位置失败，跳过。"));
            return;
        }

        setBusy(true, QStringLiteral("正在探测窗口响应..."));
        const int kFrameCount = responseFrameSpin_->value();
        const int kOriginX = originRect.left;
        const int kOriginY = originRect.top;

        // Measure idle baseline first: Distinguish between 'this window is inherently slow' and 'lag caused by movement'.
        std::vector<double> idleSamples;
        for (int idleIndex = 0; idleIndex < 30; ++idleIndex)
        {
            idleSamples.push_back(probeWindowResponseMs(targetHandle, 200));
            ::Sleep(10);
            QCoreApplication::processEvents(QEventLoop::AllEvents, 2);
        }

        std::vector<double> movingSamples;
        movingSamples.reserve(static_cast<size_t>(kFrameCount));
        QElapsedTimer frameTimer;
        for (int frameIndex = 0; frameIndex < kFrameCount; ++frameIndex)
        {
            frameTimer.restart();
            const int kOffsetX = (frameIndex % 60) * 4;
            ::SetWindowPos(
                targetHandle,
                nullptr,
                kOriginX + kOffsetX,
                kOriginY,
                0,
                0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
            movingSamples.push_back(probeWindowResponseMs(targetHandle, 500));
            const double kSpentMs = static_cast<double>(frameTimer.nsecsElapsed()) / 1e6;
            if (kSpentMs < kFrameBudgetMs)
            {
                ::Sleep(static_cast<DWORD>(kFrameBudgetMs - kSpentMs));
            }
            progressBar_->setValue((frameIndex + 1) * 100 / std::max(1, kFrameCount));
            QCoreApplication::processEvents(QEventLoop::AllEvents, 2);
        }

        // Always restore the window regardless of the measurement result: this is someone else's window.
        ::SetWindowPos(
            targetHandle,
            nullptr,
            kOriginX,
            kOriginY,
            0,
            0,
            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

        appendReportLine(QStringLiteral("  目标: %1").arg(targetWindowCombo_->currentText()));
        appendSummaryLine(QStringLiteral("静止基线"), summarizeSamples(idleSamples));
        appendSummaryLine(QStringLiteral("移动期间"), summarizeSamples(movingSamples));
        appendReportLine(QStringLiteral("  含义: 往返耗时即目标窗口 UI 线程被阻塞的时长；"
            "移动期间显著高于静止基线，说明它在按窗口位置做重绘。"));
        appendReportLine(QStringLiteral("  窗口已放回原位置 %1,%2").arg(kOriginX).arg(kOriginY));

        setBusy(false);
    }

    void RenderBenchmarkPage::runAllBenchmarks()
    {
        if (busy_ || batchRunning_)
        {
            return;
        }
        batchRunning_ = true;
        appendReportSection(QStringLiteral("完整基准"));
        appendReportLine(QStringLiteral("  开始时间: %1")
            .arg(QDateTime::currentDateTime().toString(Qt::ISODate)));

        runMainWindowRepaintBenchmark();
        pumpUserInterface(150);
        runDragSimulationBenchmark();
        pumpUserInterface(150);
        runCompositionProbe();
        pumpUserInterface(150);
        runWindowResponseProbe();

        appendReportLine(QString());
        appendReportLine(QStringLiteral("完整基准结束。"));

        // The batch flag must be cleared after the last setBusy call; otherwise, the button will not re-enable.
        batchRunning_ = false;
        setBusy(false);
    }

    void RenderBenchmarkPage::copyReportToClipboard()
    {
        QClipboard* const kClipboard = QApplication::clipboard();
        if (kClipboard != nullptr && reportEdit_ != nullptr)
        {
            kClipboard->setText(reportEdit_->toPlainText());
            statusLabel_->setText(QStringLiteral("报告已复制到剪贴板。"));
        }
    }

    void RenderBenchmarkPage::saveReportToFile()
    {
        if (reportEdit_ == nullptr)
        {
            return;
        }
        const QString kTargetPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出渲染基准报告"),
            QStringLiteral("ksword_render_benchmark.txt"),
            QStringLiteral("Text (*.txt)"));
        if (kTargetPath.isEmpty())
        {
            return;
        }
        QFile reportFile(kTargetPath);
        if (!reportFile.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            statusLabel_->setText(QStringLiteral("导出失败：无法写入所选路径。"));
            return;
        }
        QTextStream reportStream(&reportFile);
        reportStream << reportEdit_->toPlainText();
        reportFile.close();
        statusLabel_->setText(QStringLiteral("报告已导出。"));
    }
}
