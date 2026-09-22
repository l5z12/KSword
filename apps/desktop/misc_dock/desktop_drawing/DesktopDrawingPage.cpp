#include "DesktopDrawingPage.h"

#include "../../internationalization/LanguageManager.h"
#include "../../ui/ThemeStatusRole.h"

#include <QApplication>
#include <QColorDialog>
#include <QComboBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QPixmap>
#include <QPushButton>
#include <QScrollArea>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

namespace
{
    constexpr int kStopHotkeyId = 0x4B44;

    QSpinBox* makeSpin(QWidget* parent, int minimum, int maximum, int value)
    {
        auto* spin = new QSpinBox(parent);
        spin->setRange(minimum, maximum);
        spin->setValue(value);
        spin->setKeyboardTracking(false);
        return spin;
    }
}

namespace ks::misc
{
    DesktopDrawingPage::DesktopDrawingPage(QWidget* parent) : QWidget(parent)
    {
        initializeUi();
        timer_ = new QTimer(this);
        timer_->setTimerType(Qt::PreciseTimer);
        connect(timer_, &QTimer::timeout, this, &DesktopDrawingPage::drawFrame);
        connect(qApp, &QCoreApplication::aboutToQuit, this, &DesktopDrawingPage::stopDrawing);
        qApp->installNativeEventFilter(this);
        refreshDisplays();
    }

    DesktopDrawingPage::~DesktopDrawingPage()
    {
        stopDrawing();
        if (qApp)
        {
            qApp->removeNativeEventFilter(this);
        }
    }

    void DesktopDrawingPage::initializeUi()
    {
        auto& language = ks::i18n::LanguageManager::instance();
        auto* root = new QVBoxLayout(this);
        root->setContentsMargins(12, 12, 12, 12);
        root->setSpacing(10);

        auto* scroll = new QScrollArea(this);
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        settings_ = new QWidget(scroll);
        auto* form = new QFormLayout(settings_);
        form->setContentsMargins(0, 0, 0, 0);
        form->setRowWrapPolicy(QFormLayout::WrapLongRows);
        auto addRow = [&](const QString& key, const QString& text, QWidget* control)
            {
                auto* label = new QLabel(settings_);
                language.bindText(label, key, text);
                label->setBuddy(control);
                form->addRow(label, control);
            };

        displayCombo_ = new QComboBox(settings_);
        displayCombo_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
        displayCombo_->setMinimumContentsLength(20);
        addRow(QStringLiteral("misc.desktop_drawing.display"), QStringLiteral("绘制显示器"), displayCombo_);
        auto* refresh = new QPushButton(settings_);
        language.bindText(refresh, QStringLiteral("misc.desktop_drawing.refresh"), QStringLiteral("刷新显示器"));
        form->addRow(QString(), refresh);

        patternCombo_ = new QComboBox(settings_);
        auto addPattern = [&](desktop_drawing::Pattern pattern, const QString& key, const QString& text)
            {
                const int kIndex = patternCombo_->count();
                patternCombo_->addItem(text, static_cast<int>(pattern));
                language.bindComboBoxItem(patternCombo_, kIndex, key, text);
            };
        addPattern(desktop_drawing::Pattern::kCross, QStringLiteral("misc.desktop_drawing.cross"), QStringLiteral("十字准星"));
        addPattern(desktop_drawing::Pattern::kCircle, QStringLiteral("misc.desktop_drawing.circle"), QStringLiteral("圆环"));
        addPattern(desktop_drawing::Pattern::kRectangle, QStringLiteral("misc.desktop_drawing.rectangle"), QStringLiteral("矩形边框"));
        addPattern(desktop_drawing::Pattern::kDiamond, QStringLiteral("misc.desktop_drawing.diamond"), QStringLiteral("菱形"));
        addPattern(desktop_drawing::Pattern::kStar, QStringLiteral("misc.desktop_drawing.star"), QStringLiteral("五角星"));
        patternCombo_->setCurrentIndex(4);
        addRow(QStringLiteral("misc.desktop_drawing.pattern"), QStringLiteral("绘制图案"), patternCombo_);

        xSpin_ = makeSpin(settings_, 0, 0, 0);
        ySpin_ = makeSpin(settings_, 0, 0, 0);
        sizeSpin_ = makeSpin(settings_, 16, 1024, 160);
        lineWidthSpin_ = makeSpin(settings_, 1, 32, 3);
        rateSpin_ = makeSpin(settings_, 5, 120, 30);
        addRow(QStringLiteral("misc.desktop_drawing.x"), QStringLiteral("中心横坐标（物理像素）"), xSpin_);
        addRow(QStringLiteral("misc.desktop_drawing.y"), QStringLiteral("中心纵坐标（物理像素）"), ySpin_);
        auto* center = new QPushButton(settings_);
        language.bindText(center, QStringLiteral("misc.desktop_drawing.center"), QStringLiteral("居中到所选显示器"));
        form->addRow(QString(), center);
        addRow(QStringLiteral("misc.desktop_drawing.size"), QStringLiteral("图案尺寸（物理像素）"), sizeSpin_);
        addRow(QStringLiteral("misc.desktop_drawing.line_width"), QStringLiteral("线条宽度（物理像素）"), lineWidthSpin_);
        addRow(QStringLiteral("misc.desktop_drawing.rate"), QStringLiteral("每秒重绘次数"), rateSpin_);
        colorButton_ = new QPushButton(settings_);
        updateColorButton();
        addRow(QStringLiteral("misc.desktop_drawing.color"), QStringLiteral("图案颜色"), colorButton_);
        scroll->setWidget(settings_);
        root->addWidget(scroll, 1);

        auto* actions = new QHBoxLayout;
        startButton_ = new QPushButton(this);
        stopButton_ = new QPushButton(this);
        language.bindText(startButton_, QStringLiteral("misc.desktop_drawing.start"), QStringLiteral("开始绘制"));
        language.bindText(stopButton_, QStringLiteral("misc.desktop_drawing.stop"), QStringLiteral("停止并刷新"));
        stopButton_->setEnabled(false);
        actions->addWidget(startButton_);
        actions->addWidget(stopButton_);
        actions->addStretch();
        root->addLayout(actions);
        hotkeyLabel_ = new QLabel(this);
        hotkeyLabel_->setWordWrap(true);
        language.bindText(hotkeyLabel_, QStringLiteral("misc.desktop_drawing.hotkey"),
            QStringLiteral("按 Ctrl+Alt+F10 停止绘制。"));
        root->addWidget(hotkeyLabel_);
        statusLabel_ = new QLabel(this);
        statusLabel_->setWordWrap(true);
        language.bindText(statusLabel_, QStringLiteral("misc.desktop_drawing.idle"), QStringLiteral("尚未开始绘制。"));
        ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kIdle);
        root->addWidget(statusLabel_);

        connect(refresh, &QPushButton::clicked, this, &DesktopDrawingPage::refreshDisplays);
        connect(center, &QPushButton::clicked, this, &DesktopDrawingPage::updateCoordinates);
        connect(displayCombo_, &QComboBox::currentIndexChanged, this, &DesktopDrawingPage::updateCoordinates);
        connect(colorButton_, &QPushButton::clicked, this, &DesktopDrawingPage::chooseColor);
        connect(startButton_, &QPushButton::clicked, this, &DesktopDrawingPage::startDrawing);
        connect(stopButton_, &QPushButton::clicked, this, &DesktopDrawingPage::stopDrawing);
    }

    void DesktopDrawingPage::refreshDisplays()
    {
        stopDrawing();
        const QString kPrevious = displayCombo_->currentData().toString();
        const QSignalBlocker kBlocker(displayCombo_);
        displays_ = desktop_drawing::enumerateDisplays();
        displayCombo_->clear();
        for (const auto& display : displays_)
        {
            const QString kName = QString::fromStdWString(display.name);
            displayCombo_->addItem(QStringLiteral("%1  (%2 x %3)").arg(kName)
                .arg(display.bounds.right - display.bounds.left)
                .arg(display.bounds.bottom - display.bounds.top), kName);
        }
        const int kPreviousIndex = displayCombo_->findData(kPrevious);
        if (kPreviousIndex >= 0)
        {
            displayCombo_->setCurrentIndex(kPreviousIndex);
        }
        updateCoordinates();
        startButton_->setEnabled(!displays_.empty());
        if (displays_.empty())
        {
            showFailure(desktop_drawing::DrawResult::kDisplayChanged);
        }
    }

    void DesktopDrawingPage::updateCoordinates()
    {
        const int kIndex = displayCombo_->currentIndex();
        if (kIndex < 0 || kIndex >= static_cast<int>(displays_.size()))
        {
            return;
        }
        const RECT& bounds = displays_[kIndex].bounds;
        xSpin_->setRange(0, bounds.right - bounds.left - 1);
        ySpin_->setRange(0, bounds.bottom - bounds.top - 1);
        xSpin_->setValue((bounds.right - bounds.left) / 2);
        ySpin_->setValue((bounds.bottom - bounds.top) / 2);
    }

    void DesktopDrawingPage::chooseColor()
    {
        const QColor kColor = QColorDialog::getColor(color_, this,
            ks::i18n::text(QStringLiteral("misc.desktop_drawing.color"), QStringLiteral("图案颜色")));
        if (kColor.isValid())
        {
            color_ = kColor;
            updateColorButton();
        }
    }

    void DesktopDrawingPage::updateColorButton()
    {
        QPixmap swatch(20, 20);
        swatch.fill(color_);
        colorButton_->setIcon(QIcon(swatch));
        colorButton_->setText(color_.name(QColor::HexRgb));
    }

    void DesktopDrawingPage::startDrawing()
    {
        if (timer_->isActive())
        {
            return;
        }
        const int kIndex = displayCombo_->currentIndex();
        if (kIndex < 0 || kIndex >= static_cast<int>(displays_.size()))
        {
            showFailure(desktop_drawing::DrawResult::kDisplayChanged);
            return;
        }
        desktop_drawing::Options options;
        options.display = displays_[kIndex];
        options.pattern = static_cast<desktop_drawing::Pattern>(patternCombo_->currentData().toInt());
        options.x = xSpin_->value();
        options.y = ySpin_->value();
        options.size = sizeSpin_->value();
        options.lineWidth = lineWidthSpin_->value();
        options.color = RGB(color_.red(), color_.green(), color_.blue());
        const auto kResult = renderer_.start(options);
        if (kResult != desktop_drawing::DrawResult::kSuccess)
        {
            showFailure(kResult);
            return;
        }
        // Passing nullptr associates the hotkey with the current thread's message queue, so no window needs to be created for drawing.
        hotkeyRegistered_ = ::RegisterHotKey(nullptr, kStopHotkeyId,
            MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, VK_F10) != FALSE;
        auto& language = ks::i18n::LanguageManager::instance();
        if (hotkeyRegistered_)
        {
            language.bindText(hotkeyLabel_, QStringLiteral("misc.desktop_drawing.hotkey"),
                QStringLiteral("按 Ctrl+Alt+F10 停止绘制。"));
        }
        else
        {
            language.bindText(hotkeyLabel_, QStringLiteral("misc.desktop_drawing.hotkey_unavailable"),
                QStringLiteral("快捷键不可用，请使用“停止并刷新”。"));
        }
        ks::ui::applyStatusRole(hotkeyLabel_, hotkeyRegistered_ ? ks::ui::StatusRole::kNone : ks::ui::StatusRole::kWarning);
        timer_->start((1000 + rateSpin_->value() - 1) / rateSpin_->value());
        setRunning(true);
        language.bindText(statusLabel_, QStringLiteral("misc.desktop_drawing.running"),
            QStringLiteral("正在绘制。"));
        ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kInfo);
    }

    void DesktopDrawingPage::stopDrawing()
    {
        const bool kWasRunning = timer_ && timer_->isActive();
        if (timer_)
        {
            timer_->stop();
        }
        if (hotkeyRegistered_)
        {
            ::UnregisterHotKey(nullptr, kStopHotkeyId);
            hotkeyRegistered_ = false;
        }
        renderer_.stop();
        setRunning(false);
        if (kWasRunning)
        {
            ks::i18n::LanguageManager::instance().bindText(statusLabel_,
                QStringLiteral("misc.desktop_drawing.stopped"), QStringLiteral("已停止绘制。"));
            ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kIdle);
        }
    }

    void DesktopDrawingPage::setRunning(bool running)
    {
        settings_->setEnabled(!running);
        startButton_->setEnabled(!running && !displays_.empty());
        stopButton_->setEnabled(running);
    }

    void DesktopDrawingPage::drawFrame()
    {
        const auto kResult = renderer_.drawFrame();
        if (kResult != desktop_drawing::DrawResult::kSuccess)
        {
            stopDrawing();
            showFailure(kResult);
        }
    }

    void DesktopDrawingPage::showFailure(desktop_drawing::DrawResult result)
    {
        auto& language = ks::i18n::LanguageManager::instance();
        if (result == desktop_drawing::DrawResult::kDesktopUnavailable)
        {
            language.bindText(statusLabel_, QStringLiteral("misc.desktop_drawing.desktop_unavailable"),
                QStringLiteral("桌面已切换，绘制已停止。"));
        }
        else if (result == desktop_drawing::DrawResult::kDisplayChanged)
        {
            language.bindText(statusLabel_, QStringLiteral("misc.desktop_drawing.display_changed"),
                QStringLiteral("显示器不可用或布局已变化。请刷新显示器后重新开始。"));
        }
        else
        {
            language.bindText(statusLabel_, QStringLiteral("misc.desktop_drawing.failed"),
                QStringLiteral("绘制失败，请重新开始。"));
        }
        ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kWarning);
    }

    bool DesktopDrawingPage::nativeEventFilter(const QByteArray&, void* message, qintptr* result)
    {
        const auto* native = static_cast<const MSG*>(message);
        if (!native)
        {
            return false;
        }
        if (native->message == WM_HOTKEY && native->wParam == kStopHotkeyId && hotkeyRegistered_)
        {
            stopDrawing();
            if (result)
            {
                *result = 0;
            }
            return true;
        }
        if (native->message == WM_DISPLAYCHANGE)
        {
            const bool kWasRunning = timer_->isActive();
            stopDrawing();
            if (kWasRunning)
            {
                showFailure(desktop_drawing::DrawResult::kDisplayChanged);
            }
        }
        return false;
    }
}
