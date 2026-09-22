#include "NotificationCardManager.h"

#include "../Framework.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QApplication>
#include <QClipboard>
#include <QCursor>
#include <QDateTime>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPointer>
#include <QProgressBar>
#include <QPropertyAnimation>
#include <QScreen>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWindow>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <functional>
#include <utility>

namespace
{
    constexpr int kCardWidth = 400;
    constexpr int kScreenMargin = 12;
    constexpr int kCardSpacing = 8;
    constexpr int kAnimationDurationMs = 150;
    constexpr int kCardBackgroundAlpha = 191; // 75%

    QPointer<ks::ui::NotificationCardManager> gNotificationCardManager;

    QString toUiText(const std::string& utf8Text)
    {
        return QString::fromUtf8(utf8Text.data(), static_cast<int>(utf8Text.size()));
    }

    // localizedBackendText:
    // - The backend writes log and progress text in the source language (Chinese) to std::string; translate it only for display;
    // - Follows the same approach as DriverDock debug output: displayText line by line to avoid mismatch of multi-line content as a whole.
    // - Unregistered text is returned as-is without data loss.
    QString localizedBackendText(const std::string& utf8Text)
    {
        const QString kRawText = toUiText(utf8Text);
        if (kRawText.isEmpty())
        {
            return kRawText;
        }
        if (!kRawText.contains(QChar(u'\n')))
        {
            return ks::i18n::displayText(kRawText);
        }

        QStringList localizedLines;
        const QStringList kRawLines = kRawText.split(QChar(u'\n'));
        localizedLines.reserve(kRawLines.size());
        for (const QString& rawLine : kRawLines)
        {
            localizedLines.append(ks::i18n::displayText(rawLine));
        }
        return localizedLines.join(QChar(u'\n'));
    }

    QColor levelColor(const KLogLevel level)
    {
        switch (level)
        {
        // The color scheme for log levels must align with the same theme semantics used in LogDockWidget::getLevelColor.
        case KLogLevel::kDebug: return ksword_theme::accentColor(ksword_theme::AccentRole::kBlue, -12, -38);
        case KLogLevel::kInfo: return ksword_theme::successColor();
        case KLogLevel::kWarn: return ksword_theme::warningColor();
        case KLogLevel::kError: return ksword_theme::errorColor();
        case KLogLevel::kFatal: return ksword_theme::accentTextColor(ksword_theme::AccentRole::kRed, ksword_theme::blackColor());
        // PrimaryBlueHex is a "palette(highlight)" stylesheet placeholder that QColor cannot parse into a color.
        // The drawing path must use the real accent color.
        default: return ksword_theme::primaryAccentColor();
        }
    }

    QString logCopyText(const KEvent& eventItem)
    {
        return ks::i18n::contextText(
                QStringLiteral("notification.copy.log_template"),
                QStringLiteral("%1\n%2\n%3\n文件：%4\n函数：%5\nGUID：%6"))
            .arg(QString::fromStdString(logLevelToString(eventItem.level)))
            .arg(QString::fromStdString(formatTimeToString(eventItem.timestamp)).right(8))
            .arg(localizedBackendText(eventItem.content))
            .arg(toUiText(eventItem.fileLocation))
            .arg(toUiText(eventItem.functionName))
            .arg(QString::fromStdString(guidToString(eventItem.guid)));
    }

    QString progressCopyText(const KProgressTask& taskItem)
    {
        const int kPercent = std::clamp(static_cast<int>(std::lround(taskItem.progress * 100.0f)), 0, 100);
        return QStringLiteral("%1\n%2\n%3%")
            .arg(localizedBackendText(taskItem.taskName))
            .arg(localizedBackendText(taskItem.stepName))
            .arg(kPercent);
    }

    QRect resolveScreenBounds(QWidget* const hostWindow)
    {
        QScreen* targetScreen = nullptr;
        if (hostWindow != nullptr)
        {
            targetScreen = QGuiApplication::screenAt(hostWindow->frameGeometry().center());
            if (targetScreen == nullptr && hostWindow->windowHandle() != nullptr)
            {
                targetScreen = hostWindow->windowHandle()->screen();
            }
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QGuiApplication::primaryScreen();
        }
        return targetScreen != nullptr ? targetScreen->availableGeometry() : QRect(0, 0, 1920, 1080);
    }
}

namespace ks::ui
{
    class NotificationCard final : public QWidget
    {
    public:
        enum class Kind
        {
            kLog,
            kProgress
        };

        explicit NotificationCard(const Kind kind, std::function<void()> layoutChangedCallback = {})
            : QWidget(nullptr)
            , kind_(kind)
            , layoutChangedCallback_(std::move(layoutChangedCallback))
        {
            setAttribute(Qt::WA_TranslucentBackground, true);
            setAttribute(Qt::WA_ShowWithoutActivating, true);
            setWindowFlags(
                Qt::Tool |
                Qt::FramelessWindowHint |
                Qt::WindowStaysOnTopHint |
                Qt::WindowDoesNotAcceptFocus);
            setFocusPolicy(Qt::NoFocus);
            setFixedWidth(kCardWidth);

            frame_ = new QWidget(this);
            frame_->setObjectName(QStringLiteral("ksNotificationCardFrame"));
            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(0, 0, 0, 0);
            rootLayout->addWidget(frame_);

            QVBoxLayout* frameLayout = new QVBoxLayout(frame_);
            frameLayout->setContentsMargins(14, 10, 10, 12);
            frameLayout->setSpacing(7);

            QHBoxLayout* titleLayout = new QHBoxLayout();
            titleLayout->setSpacing(6);
            titleLabel_ = new QLabel(frame_);
            titleLabel_->setObjectName(QStringLiteral("ksNotificationCardTitle"));
            titleLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
            titleLayout->addWidget(titleLabel_, 1);
            copyButton_ = new QToolButton(frame_);
            copyButton_->setObjectName(QStringLiteral("ksNotificationCardCopy"));
            copyButton_->setText(ks::i18n::text(QStringLiteral("notification.copy"), QStringLiteral("复制")));
            copyButton_->setToolTip(ks::i18n::text(QStringLiteral("notification.copy.tooltip"), QStringLiteral("复制卡片内容到剪贴板")));
            copyButton_->setAutoRaise(true);
            copyButton_->setFocusPolicy(Qt::NoFocus);
            titleLayout->addWidget(copyButton_, 0, Qt::AlignTop);
            expandButton_ = new QToolButton(frame_);
            expandButton_->setObjectName(QStringLiteral("ksNotificationCardExpand"));
            expandButton_->setArrowType(Qt::DownArrow);
            expandButton_->setToolTip(ks::i18n::text(QStringLiteral("notification.expand"), QStringLiteral("展开完整日志")));
            expandButton_->setAutoRaise(true);
            expandButton_->setFocusPolicy(Qt::NoFocus);
            expandButton_->hide();
            titleLayout->addWidget(expandButton_, 0, Qt::AlignTop);
            frameLayout->addLayout(titleLayout);

            bodyLabel_ = new QLabel(frame_);
            bodyLabel_->setObjectName(QStringLiteral("ksNotificationCardBody"));
            bodyLabel_->setWordWrap(true);
            bodyLabel_->setTextInteractionFlags(Qt::NoTextInteraction);
            frameLayout->addWidget(bodyLabel_);

            if (kind_ == Kind::kProgress)
            {
                progressBar_ = new QProgressBar(frame_);
                progressBar_->setObjectName(QStringLiteral("ksNotificationCardProgress"));
                progressBar_->setRange(0, 100);
                progressBar_->setTextVisible(true);
                frameLayout->addWidget(progressBar_);
            }

            connect(copyButton_, &QToolButton::clicked, this, [this]() {
                if (QClipboard* clipboard = QApplication::clipboard())
                {
                    // First, read the current text from the system's primary clipboard:
                    // - Only rewrite if the content differs to avoid redundant writes to already copied content.
                    // - Check on every click; automatically re-copy if the card content updates or the clipboard is modified by another program.
                    if (clipboard->text(QClipboard::Clipboard) != copyText_)
                    {
                        clipboard->setText(copyText_, QClipboard::Clipboard);
                    }
                    copyButton_->setText(
                        ks::i18n::text(QStringLiteral("notification.copy.done"), QStringLiteral("已复制")));
                }
            });
            connect(expandButton_, &QToolButton::clicked, this, [this]() {
                logExpanded_ = !logExpanded_;
                updateLogHeightLimit();
                if (layoutChangedCallback_)
                {
                    layoutChangedCallback_();
                }
            });

            refreshVisuals();
        }

        void setLogEvent(
            const KEvent& eventItem,
            const bool heightLimitEnabled,
            const int maximumLines)
        {
            titleLabel_->setText(
                QStringLiteral("%1  %2")
                .arg(QString::fromStdString(logLevelToString(eventItem.level)))
                .arg(QString::fromStdString(formatTimeToString(eventItem.timestamp)).right(8)));
            bodyLabel_->setText(localizedBackendText(eventItem.content));
            copyText_ = logCopyText(eventItem);
            accentColor_ = levelColor(eventItem.level);
            logHeightLimitEnabled_ = heightLimitEnabled;
            logMaximumLines_ = std::max(1, maximumLines);
            logExpanded_ = false;
            refreshVisuals();
            adjustToContent();
        }

        void setLogHeightLimit(const bool heightLimitEnabled, const int maximumLines)
        {
            if (kind_ != Kind::kLog)
            {
                return;
            }
            logHeightLimitEnabled_ = heightLimitEnabled;
            logMaximumLines_ = std::max(1, maximumLines);
            if (!logHeightLimitEnabled_)
            {
                logExpanded_ = false;
            }
            updateLogHeightLimit();
        }

        void setProgressTask(const KProgressTask& taskItem)
        {
            titleLabel_->setText(localizedBackendText(taskItem.taskName));
            bodyLabel_->setText(localizedBackendText(taskItem.stepName));
            if (progressBar_ != nullptr)
            {
                progressBar_->setValue(std::clamp(static_cast<int>(std::lround(taskItem.progress * 100.0f)), 0, 100));
            }
            copyText_ = progressCopyText(taskItem);
            accentColor_ = ksword_theme::primaryAccentColor();
            refreshVisuals();
            adjustToContent();
        }

        void refreshVisuals()
        {
            QColor backgroundColor = ksword_theme::surfaceColor();
            backgroundColor.setAlpha(kCardBackgroundAlpha);
            const QColor kAccent = accentColor_.isValid()
                ? accentColor_
                : ksword_theme::primaryAccentColor();
            frame_->setStyleSheet(QStringLiteral(
                "#ksNotificationCardFrame{"
                "background-color:%1;border:1px solid %2;border-left:4px solid %3;border-radius:8px;"
                "}"
                "#ksNotificationCardTitle{color:%4;font-weight:600;}"
                "#ksNotificationCardBody{color:%4;}"
                "#ksNotificationCardCopy{color:%3;border:1px solid transparent;border-radius:4px;padding:2px 5px;}"
                "#ksNotificationCardCopy:hover{background:%5;border-color:%3;}"
                "#ksNotificationCardExpand{color:%3;border:1px solid transparent;border-radius:4px;padding:2px;}"
                "#ksNotificationCardExpand:hover{background:%5;border-color:%3;}"
                "#ksNotificationCardProgress{border:1px solid %2;border-radius:4px;text-align:center;color:%4;background:%6;height:16px;}"
                "#ksNotificationCardProgress::chunk{background:%3;border-radius:3px;}")
                .arg(backgroundColor.name(QColor::HexArgb))
                .arg(ksword_theme::borderColorHex())
                .arg(kAccent.name())
                .arg(ksword_theme::textPrimaryColorHex())
                .arg(ksword_theme::rgbaColorName(kAccent, 36))
                .arg(ksword_theme::surfaceMutedColorHex()));
        }

        void animateTo(const QPoint& targetPosition, const bool animate)
        {
            if (!isVisible())
            {
                move(targetPosition);
                setWindowOpacity(0.0);
                show();
                QPropertyAnimation* fadeIn = new QPropertyAnimation(this, "windowOpacity", this);
                fadeIn->setDuration(kAnimationDurationMs);
                fadeIn->setStartValue(0.0);
                fadeIn->setEndValue(1.0);
                fadeIn->start(QAbstractAnimation::DeleteWhenStopped);
                return;
            }

            if (!animate || pos() == targetPosition)
            {
                move(targetPosition);
                return;
            }
            QPropertyAnimation* moveAnimation = new QPropertyAnimation(this, "pos", this);
            moveAnimation->setDuration(kAnimationDurationMs);
            moveAnimation->setEasingCurve(QEasingCurve::OutCubic);
            moveAnimation->setStartValue(pos());
            moveAnimation->setEndValue(targetPosition);
            moveAnimation->start(QAbstractAnimation::DeleteWhenStopped);
        }

        void dismiss(const bool animate)
        {
            if (!animate)
            {
                hide();
                deleteLater();
                return;
            }
            QPropertyAnimation* fadeOut = new QPropertyAnimation(this, "windowOpacity", this);
            fadeOut->setDuration(kAnimationDurationMs);
            fadeOut->setStartValue(windowOpacity());
            fadeOut->setEndValue(0.0);
            connect(fadeOut, &QPropertyAnimation::finished, this, [this]() {
                hide();
                deleteLater();
            });
            fadeOut->start(QAbstractAnimation::DeleteWhenStopped);
        }

    protected:
        bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override
        {
            Q_UNUSED(eventType);
            MSG* nativeMessage = static_cast<MSG*>(message);
            if (nativeMessage != nullptr && nativeMessage->message == WM_NCHITTEST && result != nullptr)
            {
                // Use Qt's global cursor logical coordinates and convert to the button's own coordinate system:
                // - Avoid using Win32 physical coordinates directly to prevent hit area offset under high DPI.
                // - Prevent misinterpreting button rectangles nested within m_frame as card coordinates.
                const QPoint kCardPosition = mapFromGlobal(QCursor::pos());
                const auto kControlHit = [this, &kCardPosition](const QToolButton* const button) {
                    return button != nullptr
                        && button->isVisible()
                        && button->rect().contains(button->mapFrom(this, kCardPosition));
                };
                if (!kControlHit(copyButton_) && !kControlHit(expandButton_))
                {
                    *result = HTTRANSPARENT;
                    return true;
                }
            }
            return QWidget::nativeEvent(eventType, message, result);
        }

    private:
        void adjustToContent()
        {
            const int kBodyWidth = kCardWidth - 42;
            bodyLabel_->setMaximumWidth(kBodyWidth);
            updateLogHeightLimit();
            setFixedWidth(kCardWidth);
        }

        void updateLogHeightLimit()
        {
            bodyLabel_->setMaximumHeight(QWIDGETSIZE_MAX);
            bodyLabel_->adjustSize();
            const int kNaturalHeight = bodyLabel_->sizeHint().height();
            const int kMaximumHeight = QFontMetrics(bodyLabel_->font()).lineSpacing()
                * std::max(1, logMaximumLines_);
            const bool kCanExpand = kind_ == Kind::kLog
                && logHeightLimitEnabled_
                && kNaturalHeight > kMaximumHeight;
            expandButton_->setVisible(kCanExpand);
            if (kCanExpand && !logExpanded_)
            {
                bodyLabel_->setMaximumHeight(kMaximumHeight);
            }
            expandButton_->setArrowType(logExpanded_ ? Qt::UpArrow : Qt::DownArrow);
            expandButton_->setToolTip(ks::i18n::text(
                logExpanded_ ? QStringLiteral("notification.collapse") : QStringLiteral("notification.expand"),
                logExpanded_ ? QStringLiteral("收起日志") : QStringLiteral("展开完整日志")));
            layout()->activate();
            adjustSize();
        }

        Kind kind_;
        QWidget* frame_ = nullptr;
        QLabel* titleLabel_ = nullptr;
        QLabel* bodyLabel_ = nullptr;
        QProgressBar* progressBar_ = nullptr;
        QToolButton* copyButton_ = nullptr;
        QToolButton* expandButton_ = nullptr;
        QColor accentColor_;
        QString copyText_;
        std::function<void()> layoutChangedCallback_;
        bool logHeightLimitEnabled_ = true;
        int logMaximumLines_ = 5;
        bool logExpanded_ = false;
    };

    struct NotificationCardRecord
    {
        NotificationCard::Kind kind = NotificationCard::Kind::kLog;
        QPointer<NotificationCard> card;
        int progressPid = 0;
        qint64 expiresAtMs = 0;
    };

    NotificationCardManager::NotificationCardManager(
        QWidget* const mainWindow,
        QWidget* const clientAnchor,
        QObject* const parent)
        : QObject(parent)
        , mainWindow_(mainWindow)
        , clientAnchor_(clientAnchor)
    {
        gNotificationCardManager = this;
        lastLogRevision_ = kswordArkEventEntry.revision();
        knownLogCount_ = kswordArkEventEntry.snapshot().size();
        lastProgressRevision_ = kPro.revision();

        refreshTimer_ = new QTimer(this);
        refreshTimer_->setInterval(100);
        connect(refreshTimer_, &QTimer::timeout, this, [this]() { refreshFromManagers(); });
        refreshTimer_->start();
    }

    NotificationCardManager::~NotificationCardManager()
    {
        if (gNotificationCardManager == this)
        {
            gNotificationCardManager = nullptr;
        }
        clearCards();
    }

    void NotificationCardManager::applySettings(const ks::settings::AppearanceSettings& settings)
    {
        const bool kWasEnabled = settings_.notificationCardsEnabled;
        settings_ = settings;
        if (!settings_.notificationCardsEnabled)
        {
            clearCards();
            return;
        }
        if (!kWasEnabled)
        {
            lastLogRevision_ = kswordArkEventEntry.revision();
            knownLogCount_ = kswordArkEventEntry.snapshot().size();
            lastProgressRevision_ = 0;
        }
        for (const std::unique_ptr<NotificationCardRecord>& record : cards_)
        {
            if (record != nullptr && record->kind == NotificationCard::Kind::kLog && record->card != nullptr)
            {
                record->card->setLogHeightLimit(
                    settings_.notificationLogHeightLimitEnabled,
                    settings_.notificationLogMaximumLines);
            }
        }
        trimLogCardsToMaximum(true);
        reflowCards(true);
    }

    void NotificationCardManager::refreshVisuals()
    {
        for (const std::unique_ptr<NotificationCardRecord>& record : cards_)
        {
            if (record != nullptr && record->card != nullptr)
            {
                record->card->refreshVisuals();
            }
        }
        reflowCards(false);
    }

    void NotificationCardManager::onHostGeometryChanged()
    {
        reflowCards(true);
    }

    void NotificationCardManager::clearCards()
    {
        for (const std::unique_ptr<NotificationCardRecord>& record : cards_)
        {
            if (record != nullptr && record->card != nullptr)
            {
                record->card->dismiss(false);
            }
        }
        cards_.clear();
        overflowProgressTaskIds_.clear();
    }

    bool NotificationCardManager::isProgressTaskOverflowed(const int pid) const
    {
        return std::find(overflowProgressTaskIds_.cbegin(), overflowProgressTaskIds_.cend(), pid)
            != overflowProgressTaskIds_.cend();
    }

    QWidget* NotificationCardManager::hostWindow() const
    {
        return mainWindow_;
    }

    void NotificationCardManager::refreshFromManagers()
    {
        if (!settings_.notificationCardsEnabled)
        {
            return;
        }
        refreshLogCards();
        refreshProgressCards();
        removeExpiredLogCards();
        reflowCards(true);
    }

    void NotificationCardManager::refreshLogCards()
    {
        const std::size_t kRevision = kswordArkEventEntry.revision();
        if (kRevision == lastLogRevision_)
        {
            return;
        }
        const std::vector<KEvent> kSnapshot = kswordArkEventEntry.snapshot();
        if (kSnapshot.size() < knownLogCount_)
        {
            // After the log is cleared, do not resend history from before or after the clear; the next new log will display normally.
            knownLogCount_ = kSnapshot.size();
            lastLogRevision_ = kRevision;
            return;
        }
        for (std::size_t index = knownLogCount_; index < kSnapshot.size(); ++index)
        {
            if (static_cast<int>(kSnapshot[index].level) >= settings_.notificationMinimumLevel)
            {
                appendLogCard(kSnapshot[index]);
            }
        }
        knownLogCount_ = kSnapshot.size();
        lastLogRevision_ = kRevision;
    }

    void NotificationCardManager::refreshProgressCards()
    {
        const std::size_t kRevision = kPro.revision();
        if (kRevision == lastProgressRevision_)
        {
            return;
        }
        const std::vector<KProgressTask> kSnapshot = kPro.snapshot();
        std::vector<int> activeTaskIds;
        activeTaskIds.reserve(kSnapshot.size());
        for (const KProgressTask& taskItem : kSnapshot)
        {
            if (taskItem.hiddenInList)
            {
                continue;
            }
            activeTaskIds.push_back(taskItem.pid);
            auto existingIterator = std::find_if(
                cards_.begin(),
                cards_.end(),
                [&taskItem](const std::unique_ptr<NotificationCardRecord>& record) {
                    return record != nullptr
                        && record->kind == NotificationCard::Kind::kProgress
                        && record->progressPid == taskItem.pid;
                });
            if (existingIterator == cards_.end())
            {
                appendProgressCard(taskItem);
            }
            else if ((*existingIterator)->card != nullptr)
            {
                (*existingIterator)->card->setProgressTask(taskItem);
            }
        }

        for (std::size_t index = 0; index < cards_.size();)
        {
            const std::unique_ptr<NotificationCardRecord>& record = cards_[index];
            if (record != nullptr
                && record->kind == NotificationCard::Kind::kProgress
                && std::find(activeTaskIds.cbegin(), activeTaskIds.cend(), record->progressPid) == activeTaskIds.cend())
            {
                removeRecordAt(index, false);
                continue;
            }
            ++index;
        }
        lastProgressRevision_ = kRevision;
    }

    void NotificationCardManager::removeExpiredLogCards()
    {
        const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
        for (std::size_t index = 0; index < cards_.size();)
        {
            const std::unique_ptr<NotificationCardRecord>& record = cards_[index];
            if (record != nullptr
                && record->kind == NotificationCard::Kind::kLog
                && record->expiresAtMs > 0
                && record->expiresAtMs <= kNowMs)
            {
                removeRecordAt(index, true);
                continue;
            }
            ++index;
        }
    }

    void NotificationCardManager::appendLogCard(const KEvent& eventItem)
    {
        auto record = std::make_unique<NotificationCardRecord>();
        record->kind = NotificationCard::Kind::kLog;
        const QPointer<NotificationCardManager> kManagerGuard(this);
        record->card = new NotificationCard(NotificationCard::Kind::kLog, [kManagerGuard]() {
            if (kManagerGuard != nullptr)
            {
                kManagerGuard->reflowCards(true);
            }
        });
        record->card->setLogEvent(
            eventItem,
            settings_.notificationLogHeightLimitEnabled,
            settings_.notificationLogMaximumLines);
        if (settings_.notificationLogDisplaySeconds > 0)
        {
            record->expiresAtMs = QDateTime::currentMSecsSinceEpoch()
                + static_cast<qint64>(settings_.notificationLogDisplaySeconds) * 1000;
        }
        cards_.push_back(std::move(record));
        trimLogCardsToMaximum(true);
    }

    void NotificationCardManager::appendProgressCard(const KProgressTask& taskItem)
    {
        auto record = std::make_unique<NotificationCardRecord>();
        record->kind = NotificationCard::Kind::kProgress;
        record->progressPid = taskItem.pid;
        record->card = new NotificationCard(NotificationCard::Kind::kProgress);
        record->card->setProgressTask(taskItem);
        cards_.push_back(std::move(record));
    }

    void NotificationCardManager::removeRecordAt(const std::size_t index, const bool animate)
    {
        if (index >= cards_.size())
        {
            return;
        }
        if (cards_[index] != nullptr && cards_[index]->card != nullptr)
        {
            cards_[index]->card->dismiss(animate);
        }
        cards_.erase(cards_.begin() + static_cast<std::ptrdiff_t>(index));
    }

    void NotificationCardManager::trimLogCardsToMaximum(const bool animate)
    {
        const int kMaximumLogCards = settings_.notificationMaximumVisibleLogCards;
        if (kMaximumLogCards <= 0)
        {
            return;
        }
        int logCardCount = 0;
        for (const std::unique_ptr<NotificationCardRecord>& record : cards_)
        {
            if (record != nullptr && record->kind == NotificationCard::Kind::kLog)
            {
                ++logCardCount;
            }
        }
        while (logCardCount > kMaximumLogCards)
        {
            const auto kOldestLogIterator = std::find_if(
                cards_.cbegin(),
                cards_.cend(),
                [](const std::unique_ptr<NotificationCardRecord>& record) {
                    return record != nullptr && record->kind == NotificationCard::Kind::kLog;
                });
            if (kOldestLogIterator == cards_.cend())
            {
                return;
            }
            removeRecordAt(
                static_cast<std::size_t>(std::distance(cards_.cbegin(), kOldestLogIterator)),
                animate);
            --logCardCount;
        }
    }

    void NotificationCardManager::reflowCards(const bool animate)
    {
        if (!settings_.notificationCardsEnabled || cards_.empty())
        {
            overflowProgressTaskIds_.clear();
            return;
        }

        QRect targetBounds;
        const bool kUseMainWindowClientArea =
            settings_.notificationDisplayPlacement == ks::settings::NotificationDisplayPlacement::kMainWindow
            && mainWindow_ != nullptr
            && !mainWindow_->isMinimized()
            && clientAnchor_ != nullptr
            && clientAnchor_->isVisible();
        if (kUseMainWindowClientArea)
        {
            targetBounds = QRect(clientAnchor_->mapToGlobal(QPoint(0, 0)), clientAnchor_->size());
        }
        else
        {
            targetBounds = resolveScreenBounds(mainWindow_);
        }
        if (targetBounds.width() <= 0 || targetBounds.height() <= 0)
        {
            return;
        }

        // Log priority takes precedence: when mixed stacking exceeds available height, continuously log out the oldest entries.
        const auto kOccupiedHeight = [this]() {
            int total = 0;
            int count = 0;
            for (const std::unique_ptr<NotificationCardRecord>& record : cards_)
            {
                if (record != nullptr && record->card != nullptr)
                {
                    total += record->card->sizeHint().height();
                    ++count;
                }
            }
            return total + std::max(0, count - 1) * kCardSpacing;
        };
        const int kUsableHeight = std::max(1, targetBounds.height() - 2 * kScreenMargin);
        while (kOccupiedHeight() > kUsableHeight)
        {
            const auto kOldestLogIterator = std::find_if(
                cards_.cbegin(),
                cards_.cend(),
                [](const std::unique_ptr<NotificationCardRecord>& record) {
                    return record != nullptr && record->kind == NotificationCard::Kind::kLog;
                });
            if (kOldestLogIterator == cards_.cend())
            {
                break;
            }
            const std::size_t kIndex = static_cast<std::size_t>(std::distance(cards_.cbegin(), kOldestLogIterator));
            removeRecordAt(kIndex, true);
        }

        overflowProgressTaskIds_.clear();
        const int kXPosition = targetBounds.right() - kScreenMargin - kCardWidth + 1;
        int cursorY = settings_.notificationStackDirection == ks::settings::NotificationStackDirection::kBottomUp
            ? targetBounds.bottom() - kScreenMargin + 1
            : targetBounds.top() + kScreenMargin;

        // New cards are near the stack start, matching the expectation that bottom-right or top-right notifications show the latest events.
        for (auto iterator = cards_.rbegin(); iterator != cards_.rend(); ++iterator)
        {
            const std::unique_ptr<NotificationCardRecord>& record = *iterator;
            if (record == nullptr || record->card == nullptr)
            {
                continue;
            }
            const int kCardHeight = std::max(record->card->sizeHint().height(), record->card->height());
            int yPosition = cursorY;
            if (settings_.notificationStackDirection == ks::settings::NotificationStackDirection::kBottomUp)
            {
                yPosition = cursorY - kCardHeight;
                cursorY = yPosition - kCardSpacing;
            }
            else
            {
                cursorY += kCardHeight + kCardSpacing;
            }
            const QRect kCardRect(kXPosition, yPosition, kCardWidth, kCardHeight);
            if (record->kind == NotificationCard::Kind::kProgress
                && !targetBounds.adjusted(kScreenMargin, kScreenMargin, -kScreenMargin, -kScreenMargin).contains(kCardRect))
            {
                overflowProgressTaskIds_.push_back(record->progressPid);
            }
            record->card->animateTo(kCardRect.topLeft(), animate);
        }
    }

    bool isProgressTaskNotificationOverflowed(const int pid)
    {
        return gNotificationCardManager != nullptr
            && gNotificationCardManager->isProgressTaskOverflowed(pid);
    }

    QWidget* notificationCardHostWindow()
    {
        return gNotificationCardManager != nullptr
            ? gNotificationCardManager->hostWindow()
            : nullptr;
    }
}
