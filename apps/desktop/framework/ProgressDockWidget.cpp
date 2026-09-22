#include "ProgressDockWidget.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QEvent>
#include <QFrame>        // Task card container
#include <QLabel>        // Task and step text.
#include <QProgressBar>  // Progress bar display
#include <QScrollArea>   // List scroll container
#include <QTimer>        // Periodic refresh
#include <QVBoxLayout>   // Vertical layout

ProgressDockWidget::ProgressDockWidget(QWidget* parent)
    : QWidget(parent)
{
    // Performs UI and timer initialization during construction, followed by an initial refresh.
    initializeUi();
    initializeRefreshTimer();
    refreshTaskCards(true);
}

void ProgressDockWidget::initializeUi()
{
    // Root layout: fills the entire Dock and adapts to size changes.
    setObjectName(QStringLiteral("ksProgressDockRoot"));
    setAutoFillBackground(false);
    setAttribute(Qt::WA_StyledBackground, true);

    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(0, 0, 0, 0);
    rootLayout_->setSpacing(0);

    // Scroll area: Used to contain the expandable list of task cards.
    scrollArea_ = new QScrollArea(this);
    scrollArea_->setObjectName(QStringLiteral("ksProgressDockScrollArea"));
    scrollArea_->setWidgetResizable(true);
    scrollArea_->setFrameShape(QFrame::NoFrame);
    scrollArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea_->setAutoFillBackground(false);
    scrollArea_->setAttribute(Qt::WA_StyledBackground, true);

    // Viewport is named separately and forced transparent to prevent the default background color of QAbstractScrollArea from showing.
    scrollArea_->viewport()->setObjectName(QStringLiteral("ksProgressDockViewport"));
    scrollArea_->viewport()->setAutoFillBackground(false);
    scrollArea_->viewport()->setAttribute(Qt::WA_StyledBackground, true);

    // Scroll content widget: The intermediate layer that actually hosts the card layout.
    scrollContent_ = new QWidget(scrollArea_);
    scrollContent_->setObjectName(QStringLiteral("ksProgressDockScrollContent"));
    scrollContent_->setAutoFillBackground(false);
    scrollContent_->setAttribute(Qt::WA_StyledBackground, true);
    cardLayout_ = new QVBoxLayout(scrollContent_);
    cardLayout_->setContentsMargins(8, 8, 8, 8);
    cardLayout_->setSpacing(8);

    // Unify transparency policy: let the Dock background show through, keeping only the task content visible.
    applyTransparentBackgroundPolicy();

    // Empty list hint: Displayed when there are no tasks to improve readability.
    emptyTipLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("progress.empty"),
            QStringLiteral("当前没有进行中的任务。")),
        scrollContent_);
    emptyTipLabel_->setAlignment(Qt::AlignCenter);
    emptyTipLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-size:13px; background:transparent;")
        .arg(buildHighContrastTextHex()));
    cardLayout_->addWidget(emptyTipLabel_);
    cardLayout_->addStretch(1);

    // Attach the content widget to the scroll area, then attach the scroll area to the root layout.
    scrollArea_->setWidget(scrollContent_);
    rootLayout_->addWidget(scrollArea_);
}

void ProgressDockWidget::applyTransparentBackgroundPolicy()
{
    // Scope of transparent style:
    // - Root control;
    // - QScrollArea；
    // - viewport；
    // - Scroll content layer hosting cards.
    setStyleSheet(
        QStringLiteral(
        "#ksProgressDockRoot,"
        "#ksProgressDockScrollArea,"
        "#ksProgressDockViewport,"
        "#ksProgressDockScrollContent{"
        "  background:transparent;"
        "  background-color:transparent;"
        "  color:%1;"
        "  border:none;"
        "}"
        "#ksProgressDockRoot QLabel{"
        "  color:%1;"
        "  background:transparent;"
        "}"
        "#ksProgressDockRoot QProgressBar{"
        "  color:%1;"
        "}")
        .arg(buildHighContrastTextHex()));
}

void ProgressDockWidget::initializeRefreshTimer()
{
    // Refresh interval is 250ms, consistent with the log panel.
    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(250);

    // On timer trigger, attempt an incremental refresh; skip if the revision has not changed.
    connect(
        refreshTimer_,
        &QTimer::timeout,
        this,
        [this]()
        {
            refreshTaskCards(false);
        });
    refreshTimer_->start();
}

void ProgressDockWidget::refreshThemeVisuals()
{
    // Reapply the transparent background policy and rebuild all task cards during theme refresh.
    applyTransparentBackgroundPolicy();
    if (emptyTipLabel_ != nullptr)
    {
        emptyTipLabel_->setStyleSheet(
            QStringLiteral("color:%1; font-size:13px; background:transparent;")
            .arg(buildHighContrastTextHex()));
    }
    refreshTaskCards(true);
}

void ProgressDockWidget::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
}

void ProgressDockWidget::retranslateUi()
{
    if (emptyTipLabel_ != nullptr)
    {
        emptyTipLabel_->setText(ks::i18n::contextText(
            QStringLiteral("progress.empty"),
            QStringLiteral("当前没有进行中的任务。")));
    }
    refreshTaskCards(true);
}

void ProgressDockWidget::refreshTaskCards(const bool forceRefresh)
{
    const std::size_t kCurrentRevision = kPro.revision();
    if (!forceRefresh && kCurrentRevision == lastRevision_)
    {
        return;
    }
    lastRevision_ = kCurrentRevision;

    // Fetch the task snapshot and clear old cards first.
    const std::vector<KProgressTask> kTaskSnapshot = kPro.snapshot();
    clearCardLayout();

    int visibleTaskCount = 0;

    // Iterate the snapshot, skipping completed tasks marked hiddenInList.
    for (const KProgressTask& taskItem : kTaskSnapshot)
    {
        if (taskItem.hiddenInList)
        {
            continue;
        }

        QWidget* cardWidget = createTaskCardWidget(taskItem);
        cardLayout_->addWidget(cardWidget);
        ++visibleTaskCount;
    }

    // Show the hint when there are no tasks; hide it when tasks exist.
    emptyTipLabel_->setVisible(visibleTaskCount == 0);
    if (visibleTaskCount == 0)
    {
        cardLayout_->addWidget(emptyTipLabel_);
    }

    // Add a spacer at the bottom to ensure cards are always top-aligned.
    cardLayout_->addStretch(1);
}

void ProgressDockWidget::clearCardLayout()
{
    // Pop and remove layout items one by one to ensure complete release of cards.
    while (QLayoutItem* layoutItem = cardLayout_->takeAt(0))
    {
        if (QWidget* childWidget = layoutItem->widget())
        {
            // Note: m_emptyTipLabel is a long-term reusable object and is not destroyed here.
            if (childWidget != emptyTipLabel_)
            {
                childWidget->deleteLater();
            }
        }
        delete layoutItem;
    }
}

QWidget* ProgressDockWidget::createTaskCardWidget(const KProgressTask& taskItem) const
{
    // Card container: remove the border, keep only a lightweight semi-transparent background to avoid a 'framed' appearance.
    QFrame* cardFrame = new QFrame();
    cardFrame->setFrameShape(QFrame::NoFrame);
    cardFrame->setStyleSheet(
        QStringLiteral(
        "QFrame {"
        "  border:none;"
        "  border-radius:4px;"
        "  background:%1;"
        "}")
        .arg(buildCardBackgroundHex()));

    // Card internal layout: task title, steps, and progress bar are arranged sequentially.
    QVBoxLayout* cardLayout = new QVBoxLayout(cardFrame);
    cardLayout->setContentsMargins(10, 8, 10, 8);
    cardLayout->setSpacing(6);

    // Top title: Display task name and PID for easier troubleshooting and identification.
    const QString kTranslatedTaskName = ks::i18n::sourceText(
        QString::fromUtf8(taskItem.taskName.c_str()));
    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("progress.task.title"),
            QStringLiteral("%1  (PID:%2)"))
        .arg(kTranslatedTaskName)
        .arg(taskItem.pid),
        cardFrame);
    titleLabel->setStyleSheet(
        QStringLiteral("font-weight:600; color:%1; background:transparent;")
        .arg(buildHighContrastTextHex()));
    cardLayout->addWidget(titleLabel);

    // Second line: change the step text to a high-contrast color at the same level as the title to avoid unreadable gray text.
    const QString kTranslatedStepName = ks::i18n::sourceText(
        QString::fromUtf8(taskItem.stepName.c_str()));
    QLabel* stepLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("progress.task.step"),
            QStringLiteral("步骤：%1"))
        .arg(kTranslatedStepName),
        cardFrame);
    stepLabel->setStyleSheet(
        QStringLiteral("color:%1; background:transparent;")
        .arg(buildHighContrastTextHex()));
    cardLayout->addWidget(stepLabel);

    // Progress bar: retain the blue progress block, and synchronize high-contrast text with a borderless track.
    QProgressBar* progressBar = new QProgressBar(cardFrame);
    progressBar->setRange(0, 100);
    progressBar->setValue(static_cast<int>(taskItem.progress * 100.0f + 0.5f));
    progressBar->setFormat(QStringLiteral("%p%"));
    progressBar->setVisible(!taskItem.hideProgressBarTemporarily);
    progressBar->setTextVisible(true);
    progressBar->setStyleSheet(buildProgressBarStyleSheet());
    cardLayout->addWidget(progressBar);

    return cardFrame;
}

QString ProgressDockWidget::buildHighContrastTextHex() const
{
    // High-contrast foreground strategy:
    // - Use the project's primary text white-blue color for dark themes;
    // - Uses dark ink color for light themes;
    // Avoid insufficient contrast of palette(mid) gray text after transparent background stacking.
    return ksword_theme::textPrimaryColorHex();
}

QString ProgressDockWidget::buildCardBackgroundHex() const
{
    // Card background color strategy:
    // - Retain only a slightly translucent background to improve readability;
    // - No borders are drawn to satisfy the 'remove border' requirement.
    return ksword_theme::rgbaColorName(
        ksword_theme::isDarkModeEnabled()
            ? ksword_theme::blackColor()
            : ksword_theme::whiteColor(),
        ksword_theme::isDarkModeEnabled() ? 96 : 176);
}

QString ProgressDockWidget::buildProgressBarStyleSheet() const
{
    // Progress bar style strategy:
    // - Do not draw border on bottom track;
    // - Text color matches the theme;
    // - Blue progress blocks maintain consistency with the global primary color.
    const QString kProgressTrackColor = ksword_theme::rgbaColorName(
        ksword_theme::isDarkModeEnabled()
            ? ksword_theme::whiteColor()
            : ksword_theme::blackColor(),
        ksword_theme::isDarkModeEnabled() ? 48 : 28);

    return QStringLiteral(
        "QProgressBar{"
        "  border:none;"
        "  border-radius:3px;"
        "  background:%1;"
        "  color:%2;"
        "  text-align:center;"
        "  min-height:16px;"
        "}"
        "QProgressBar::chunk{"
        "  border:none;"
        "  border-radius:3px;"
        "  background:%3;"
        "}")
        .arg(kProgressTrackColor)
        .arg(buildHighContrastTextHex())
        .arg(ksword_theme::kPrimaryBlueHex);
}
