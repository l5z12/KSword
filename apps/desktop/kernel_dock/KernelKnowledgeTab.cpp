#include "KernelKnowledgeTab.h"

#include "KernelKnowledgeCatalog.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFont>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QMetaObject>
#include <QPointer>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStringList>
#include <QTextBrowser>
#include <QTextEdit>
#include <QTextCursor>
#include <QTextDocument>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTreeWidgetItemIterator>
#include <QUrl>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>
#include <utility>

namespace
{
    constexpr int kTopicIndexRole = Qt::UserRole + 201;
    constexpr int kAllCoverageData = -1;

    // uiText purpose: Read common interface text from the knowledge center.
    // Input: keySuffix; Returns localized text; if the key is missing, retains the full key for verification and location.
    QString uiText(const char* keySuffix)
    {
        const QString kKey = QStringLiteral("kernel.knowledge.ui.%1")
            .arg(QString::fromLatin1(keySuffix));
        return ks::i18n::text(kKey);
    }

    // badgeStyle: Generates a compact status badge style without injecting geometric rules into global QSS.
    // Input: text color; Return: local style intended solely for QLabel on the knowledge page.
    QString badgeStyle(const QString& textColor)
    {
        return QStringLiteral(
            "QLabel{padding:3px 8px;border:1px solid %1;border-radius:9px;"
            "background:%2;color:%3;font-weight:600;}")
            .arg(
                ksword_theme::borderColorHex(),
                ksword_theme::surfaceAltColorHex(),
                textColor);
    }

    // coverageColor: Selects semantic colors for underlying capability coverage tags.
    // Input: coverage. Returns the text color with readable contrast for the current theme.
    QString coverageColor(const ks::kernel_knowledge::Coverage coverage)
    {
        using ks::kernel_knowledge::Coverage;
        switch (coverage)
        {
        case Coverage::kAvailable:
            return ksword_theme::successHex();
        case Coverage::kAvailableNeedsExplanation:
            return ksword_theme::infoHex();
        case Coverage::kPartial:
            return ksword_theme::warningHex();
        case Coverage::kPlanned:
            return ksword_theme::textSecondaryColorHex();
        }
        return ksword_theme::textSecondaryColorHex();
    }
}

KernelKnowledgeTab::KernelKnowledgeTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    retranslateUi();
    applyTheme();
}

void KernelKnowledgeTab::setRouteHandler(RouteHandler handler)
{
    routeHandler_ = std::move(handler);
    if (routeButton_ != nullptr)
    {
        routeButton_->setEnabled(
            static_cast<bool>(routeHandler_) && !currentRouteId_.isEmpty());
    }
}

void KernelKnowledgeTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr)
    {
        return;
    }

    if (event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
    else if (event->type() == QEvent::PaletteChange ||
             event->type() == QEvent::ApplicationPaletteChange)
    {
        applyTheme();
        if (currentTopicIndex_ >= 0)
        {
            showTopic(currentTopicIndex_);
        }
    }
}

void KernelKnowledgeTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* mainSplitter = new QSplitter(Qt::Horizontal, this);
    mainSplitter->setChildrenCollapsible(false);
    rootLayout->addWidget(mainSplitter, 1);

    // Note: The left side only handles filtering and directory; set a reasonable minimum width but allow users to freely drag the splitter.
    auto* directoryPanel = new QWidget(mainSplitter);
    auto* directoryLayout = new QVBoxLayout(directoryPanel);
    directoryLayout->setContentsMargins(0, 0, 0, 0);
    directoryLayout->setSpacing(6);

    searchEdit_ = new QLineEdit(directoryPanel);
    searchEdit_->setClearButtonEnabled(true);
    directoryLayout->addWidget(searchEdit_, 0);

    auto* filterLayout = new QHBoxLayout();
    filterLayout->setContentsMargins(0, 0, 0, 0);
    filterLayout->setSpacing(6);
    coverageCombo_ = new QComboBox(directoryPanel);
    resultCountLabel_ = new QLabel(directoryPanel);
    resultCountLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    filterLayout->addWidget(coverageCombo_, 1);
    filterLayout->addWidget(resultCountLabel_, 0);
    directoryLayout->addLayout(filterLayout);

    topicTree_ = new QTreeWidget(directoryPanel);
    topicTree_->setColumnCount(2);
    topicTree_->setRootIsDecorated(true);
    topicTree_->setUniformRowHeights(true);
    topicTree_->setSelectionMode(QAbstractItemView::SingleSelection);
    topicTree_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    topicTree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    topicTree_->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    directoryLayout->addWidget(topicTree_, 1);

    // The right-side article uses semantic Markdown (headings, code block relationship diagrams, and external
    // references); QTextBrowser is better suited than a code editor for such non-editable rich-text teaching materials.
    auto* articlePanel = new QWidget(mainSplitter);
    auto* articleLayout = new QVBoxLayout(articlePanel);
    articleLayout->setContentsMargins(0, 0, 0, 0);
    articleLayout->setSpacing(6);

    titleLabel_ = new QLabel(articlePanel);
    titleLabel_->setWordWrap(true);
    titleLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    articleLayout->addWidget(titleLabel_, 0);

    summaryLabel_ = new QLabel(articlePanel);
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    articleLayout->addWidget(summaryLabel_, 0);

    auto* articleToolLayout = new QHBoxLayout();
    articleToolLayout->setContentsMargins(0, 0, 0, 0);
    articleToolLayout->setSpacing(6);
    coverageBadge_ = new QLabel(articlePanel);
    knowledgeBadge_ = new QLabel(articlePanel);
    articleToolLayout->addWidget(coverageBadge_, 0);
    articleToolLayout->addWidget(knowledgeBadge_, 0);
    articleToolLayout->addStretch(1);

    previousButton_ = new QToolButton(articlePanel);
    previousButton_->setIcon(QIcon(QStringLiteral(":/Icon/file_nav_back.svg")));
    nextButton_ = new QToolButton(articlePanel);
    nextButton_->setIcon(QIcon(QStringLiteral(":/Icon/file_nav_forward.svg")));
    copyButton_ = new QToolButton(articlePanel);
    copyButton_->setIcon(QIcon(QStringLiteral(":/Icon/codeeditor_copy.svg")));
    evidenceButton_ = new QToolButton(articlePanel);
    evidenceButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    routeButton_ = new QToolButton(articlePanel);
    routeButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_details.svg")));
    referenceButton_ = new QToolButton(articlePanel);
    referenceButton_->setIcon(QIcon(QStringLiteral(":/Icon/codeeditor_open.svg")));

    // All simple actions remain icon-only; button sizes uniformly use the global compact toolbar token.
    const QList<QToolButton*> kActionButtons{
        previousButton_,
        nextButton_,
        copyButton_,
        evidenceButton_,
        routeButton_,
        referenceButton_
    };
    for (QToolButton* button : kActionButtons)
    {
        button->setAutoRaise(true);
        ksword_theme::applyCompactIconButtonMetrics(button);
        articleToolLayout->addWidget(button, 0);
    }
    articleLayout->addLayout(articleToolLayout);

    articleView_ = new QTextBrowser(articlePanel);
    articleView_->setOpenExternalLinks(false);
    articleView_->setReadOnly(true);
    articleView_->setTextInteractionFlags(
        Qt::TextBrowserInteraction | Qt::TextSelectableByKeyboard);
    articleLayout->addWidget(articleView_, 1);

    mainSplitter->addWidget(directoryPanel);
    mainSplitter->addWidget(articlePanel);
    mainSplitter->setStretchFactor(0, 1);
    mainSplitter->setStretchFactor(1, 3);
    mainSplitter->setSizes({ 330, 990 });

    // Filtering, directory selection, and tool buttons all synchronously update the same current topic state.
    connect(searchEdit_, &QLineEdit::textChanged, this, [this]() {
        const QString kCurrentId = currentTopicIndex_ >= 0
            ? QString::fromLatin1(
                ks::kernel_knowledge::topics()[static_cast<std::size_t>(currentTopicIndex_)].id)
            : QString();
        rebuildTree(kCurrentId);
    });
    connect(
        coverageCombo_,
        qOverload<int>(&QComboBox::currentIndexChanged),
        this,
        [this]()
        {
            const QString kCurrentId = currentTopicIndex_ >= 0
                ? QString::fromLatin1(
                    ks::kernel_knowledge::topics()[static_cast<std::size_t>(currentTopicIndex_)].id)
                : QString();
            rebuildTree(kCurrentId);
        });
    connect(
        topicTree_,
        &QTreeWidget::currentItemChanged,
        this,
        [this](QTreeWidgetItem* currentItem, QTreeWidgetItem*)
        {
            if (currentItem == nullptr)
            {
                return;
            }
            const QVariant kIndexValue = currentItem->data(0, kTopicIndexRole);
            if (kIndexValue.isValid())
            {
                showTopic(kIndexValue.toInt());
            }
        });
    connect(previousButton_, &QToolButton::clicked, this, [this]() {
        navigateRelative(-1);
    });
    connect(nextButton_, &QToolButton::clicked, this, [this]() {
        navigateRelative(1);
    });
    connect(copyButton_, &QToolButton::clicked, this, [this]() {
        copyCurrentTopic();
    });
    connect(evidenceButton_, &QToolButton::clicked, this, [this]() {
        collectCurrentEvidence();
    });
    connect(routeButton_, &QToolButton::clicked, this, [this]() {
        openCurrentRoute();
    });
    connect(referenceButton_, &QToolButton::clicked, this, [this]() {
        openCurrentReference();
    });
    connect(articleView_, &QTextBrowser::anchorClicked, this, [](const QUrl& url) {
        // Article content comes from a swappable language pack; only Microsoft Learn domains declared in the directory are allowed.
        if (url.scheme() == QStringLiteral("https") &&
            url.host().compare(QStringLiteral("learn.microsoft.com"), Qt::CaseInsensitive) == 0)
        {
            QDesktopServices::openUrl(url);
        }
    });
}

void KernelKnowledgeTab::retranslateUi()
{
    const QString kCurrentTopicId = currentTopicIndex_ >= 0
        ? QString::fromLatin1(
            ks::kernel_knowledge::topics()[static_cast<std::size_t>(currentTopicIndex_)].id)
        : QString();
    const int kSelectedCoverage = coverageCombo_->currentData().isValid()
        ? coverageCombo_->currentData().toInt()
        : kAllCoverageData;

    searchEdit_->setPlaceholderText(uiText("search.placeholder"));
    searchEdit_->setToolTip(uiText("search.tooltip"));
    coverageCombo_->setToolTip(uiText("coverage.tooltip"));

    // Block currentIndexChanged when rebuilding dropdown items to avoid triggering directory rebuild twice during language switching.
    {
        const QSignalBlocker kBlocker(coverageCombo_);
        coverageCombo_->clear();
        coverageCombo_->addItem(uiText("coverage.all"), kAllCoverageData);
        const auto kAddCoverageWhenPresent = [this](
            const ks::kernel_knowledge::Coverage coverage)
        {
            const auto& catalog = ks::kernel_knowledge::topics();
            const bool kPresent = std::any_of(
                catalog.cbegin(),
                catalog.cend(),
                [coverage](const ks::kernel_knowledge::TopicDefinition& topic)
                {
                    return topic.coverage == coverage;
                });
            if (kPresent)
            {
                coverageCombo_->addItem(
                    ks::kernel_knowledge::coverageText(coverage),
                    static_cast<int>(coverage));
            }
        };
        kAddCoverageWhenPresent(ks::kernel_knowledge::Coverage::kAvailable);
        kAddCoverageWhenPresent(
            ks::kernel_knowledge::Coverage::kAvailableNeedsExplanation);
        kAddCoverageWhenPresent(ks::kernel_knowledge::Coverage::kPartial);
        kAddCoverageWhenPresent(ks::kernel_knowledge::Coverage::kPlanned);
        const int kRestoredIndex = coverageCombo_->findData(kSelectedCoverage);
        coverageCombo_->setCurrentIndex(kRestoredIndex >= 0 ? kRestoredIndex : 0);
    }

    previousButton_->setToolTip(uiText("action.previous.tooltip"));
    nextButton_->setToolTip(uiText("action.next.tooltip"));
    copyButton_->setToolTip(uiText("action.copy.tooltip"));
    evidenceButton_->setToolTip(uiText("action.evidence.tooltip"));
    routeButton_->setToolTip(uiText("action.route.tooltip"));
    referenceButton_->setToolTip(uiText("action.reference.tooltip"));
    previousButton_->setAccessibleName(previousButton_->toolTip());
    nextButton_->setAccessibleName(nextButton_->toolTip());
    copyButton_->setAccessibleName(copyButton_->toolTip());
    evidenceButton_->setAccessibleName(evidenceButton_->toolTip());
    routeButton_->setAccessibleName(routeButton_->toolTip());
    referenceButton_->setAccessibleName(referenceButton_->toolTip());

    rebuildTree(kCurrentTopicId);
}

void KernelKnowledgeTab::applyTheme()
{
    titleLabel_->setStyleSheet(QStringLiteral(
        "QLabel{color:%1;font-size:18px;font-weight:700;padding:2px 0;}")
        .arg(ksword_theme::textPrimaryHex()));
    summaryLabel_->setStyleSheet(QStringLiteral(
        "QLabel{color:%1;padding:0 0 4px 0;}")
        .arg(ksword_theme::textSecondaryHex()));
    resultCountLabel_->setStyleSheet(QStringLiteral("color:%1;")
        .arg(ksword_theme::textSecondaryHex()));
    knowledgeBadge_->setStyleSheet(badgeStyle(ksword_theme::successHex()));

    topicTree_->setStyleSheet(QStringLiteral(
        "QTreeWidget{background:%1;color:%2;border:1px solid %3;border-radius:4px;}"
        "QTreeWidget::item:selected{background:%4;color:%5;}")
        .arg(
            ksword_theme::surfaceHex(),
            ksword_theme::textPrimaryHex(),
            ksword_theme::borderHex(),
            ksword_theme::kPrimaryBlueHex,
            ksword_theme::onAccentDynamicHex()));
    articleView_->setStyleSheet(QStringLiteral(
        "QTextBrowser{background:%1;color:%2;border:1px solid %3;"
        "border-radius:4px;padding:8px;}")
        .arg(
            ksword_theme::surfaceHex(),
            ksword_theme::textPrimaryHex(),
            ksword_theme::borderHex()));

    // QTextDocument uses solid colors instead of palette() to ensure Markdown headings, code blocks, and links remain readable across themes.
    articleView_->document()->setDefaultStyleSheet(QStringLiteral(
        "body{color:%1;font-size:14px;line-height:1.45;}"
        "h3{color:%2;margin-top:16px;margin-bottom:6px;}"
        "pre{background:%3;border:1px solid %4;border-radius:4px;padding:8px;}"
        "code{font-family:Consolas,'Cascadia Mono',monospace;}"
        "a{color:%2;text-decoration:none;}"
        "hr{color:%4;}")
        .arg(
            ksword_theme::textPrimaryColorHex(),
            ksword_theme::controlAccentHex(),
            ksword_theme::surfaceAltColorHex(),
            ksword_theme::borderColorHex()));
}

void KernelKnowledgeTab::rebuildTree(const QString& preferredTopicId)
{
    using namespace ks::kernel_knowledge;

    const QStringList kSearchTerms = searchEdit_->text()
        .simplified()
        .toCaseFolded()
        .split(QLatin1Char(' '), Qt::SkipEmptyParts);
    const int kCoverageFilter = coverageCombo_->currentData().isValid()
        ? coverageCombo_->currentData().toInt()
        : kAllCoverageData;
    const auto& topicCatalog = topics();

    visibleTopicIndexes_.clear();
    {
        // clear() triggers currentItemChanged; block signals and restore selection only once after the complete tree is built.
        const QSignalBlocker kBlocker(topicTree_);
        topicTree_->clear();
        topicTree_->setHeaderLabels({
            uiText("tree.header.topic"),
            uiText("tree.header.coverage")
        });

        for (const CategoryDefinition& category : categories())
        {
            QTreeWidgetItem* categoryItem = nullptr;
            for (std::size_t topicOffset = 0; topicOffset < topicCatalog.size(); ++topicOffset)
            {
                const TopicDefinition& topic = topicCatalog[topicOffset];
                if (QString::fromLatin1(topic.categoryId) != QString::fromLatin1(category.id))
                {
                    continue;
                }
                if (kCoverageFilter != kAllCoverageData &&
                    kCoverageFilter != static_cast<int>(topic.coverage))
                {
                    continue;
                }

                // Search covers the full text; users can directly locate items by API, struct name, constraints, or Ksword fields.
                QString searchableText = QStringLiteral("%1 %2 %3 %4")
                    .arg(
                        QString::fromLatin1(topic.id),
                        topicText(topic, "title"),
                        topicText(topic, "summary"),
                        topicText(topic, "body"))
                    .toCaseFolded();
                const bool kMatchesSearch = std::all_of(
                    kSearchTerms.cbegin(),
                    kSearchTerms.cend(),
                    [&searchableText](const QString& term)
                    {
                        return searchableText.contains(term);
                    });
                if (!kMatchesSearch)
                {
                    continue;
                }

                if (categoryItem == nullptr)
                {
                    categoryItem = new QTreeWidgetItem(topicTree_);
                    categoryItem->setText(0, categoryText(category));
                    categoryItem->setFirstColumnSpanned(true);
                    QFont categoryFont = categoryItem->font(0);
                    categoryFont.setBold(true);
                    categoryItem->setFont(0, categoryFont);
                }

                auto* topicItem = new QTreeWidgetItem(categoryItem);
                topicItem->setText(0, topicText(topic, "title"));
                topicItem->setText(1, coverageText(topic.coverage));
                topicItem->setToolTip(0, topicText(topic, "summary"));
                topicItem->setData(
                    0,
                    kTopicIndexRole,
                    static_cast<int>(topicOffset));
                visibleTopicIndexes_.push_back(static_cast<int>(topicOffset));
            }

            if (categoryItem != nullptr)
            {
                categoryItem->setExpanded(true);
            }
        }
    }

    resultCountLabel_->setText(
        uiText("result_count")
            .arg(static_cast<qulonglong>(visibleTopicIndexes_.size()))
            .arg(static_cast<qulonglong>(topicCatalog.size())));

    int targetIndex = findTopicIndex(preferredTopicId);
    if (std::find(
            visibleTopicIndexes_.cbegin(),
            visibleTopicIndexes_.cend(),
            targetIndex) == visibleTopicIndexes_.cend())
    {
        targetIndex = visibleTopicIndexes_.empty() ? -1 : visibleTopicIndexes_.front();
    }

    if (targetIndex >= 0)
    {
        selectTopic(targetIndex);
        showTopic(targetIndex);
    }
    else
    {
        showTopic(-1);
    }
}

void KernelKnowledgeTab::showTopic(const int topicIndex)
{
    using namespace ks::kernel_knowledge;
    const auto& topicCatalog = topics();
    if (topicIndex < 0 || topicIndex >= static_cast<int>(topicCatalog.size()))
    {
        ++evidenceGeneration_;
        currentTopicIndex_ = -1;
        currentRouteId_.clear();
        currentReferenceUrl_.clear();
        titleLabel_->setText(uiText("empty.title"));
        summaryLabel_->setText(uiText("empty.summary"));
        coverageBadge_->clear();
        knowledgeBadge_->clear();
        articleView_->clear();
        previousButton_->setEnabled(false);
        nextButton_->setEnabled(false);
        copyButton_->setEnabled(false);
        evidenceButton_->setEnabled(false);
        routeButton_->setEnabled(false);
        referenceButton_->setEnabled(false);
        return;
    }

    if (currentTopicIndex_ != topicIndex)
    {
        ++evidenceGeneration_;
    }
    currentTopicIndex_ = topicIndex;
    const TopicDefinition& topic = topicCatalog[static_cast<std::size_t>(topicIndex)];
    const CategoryDefinition* category = categoryForTopic(topic);
    currentRouteId_ = QString::fromLatin1(topic.routeId != nullptr ? topic.routeId : "");
    currentReferenceUrl_ = category != nullptr && category->referenceUrl != nullptr
        ? QString::fromLatin1(category->referenceUrl)
        : QString();

    titleLabel_->setText(topicText(topic, "title"));
    summaryLabel_->setText(topicText(topic, "summary"));
    coverageBadge_->setText(
        uiText("badge.coverage").arg(coverageText(topic.coverage)));
    coverageBadge_->setStyleSheet(badgeStyle(coverageColor(topic.coverage)));
    knowledgeBadge_->setText(uiText("badge.knowledge_complete"));

    QString articleMarkdown = topicText(topic, "body");
    if (!currentReferenceUrl_.isEmpty())
    {
        articleMarkdown += QStringLiteral("\n\n---\n\n[%1](%2)")
            .arg(uiText("reference.microsoft"), currentReferenceUrl_);
    }
    const QTextDocument::MarkdownFeatures kMarkdownFeatures =
        QTextDocument::MarkdownFeatures(QTextDocument::MarkdownDialectGitHub) |
        QTextDocument::MarkdownNoHTML;
    articleView_->document()->setMarkdown(articleMarkdown, kMarkdownFeatures);
    QTextCursor topCursor = articleView_->textCursor();
    topCursor.movePosition(QTextCursor::Start);
    articleView_->setTextCursor(topCursor);
    articleView_->verticalScrollBar()->setValue(0);

    const auto kVisiblePosition = std::find(
        visibleTopicIndexes_.cbegin(),
        visibleTopicIndexes_.cend(),
        topicIndex);
    const int kPosition = kVisiblePosition != visibleTopicIndexes_.cend()
        ? static_cast<int>(std::distance(visibleTopicIndexes_.cbegin(), kVisiblePosition))
        : -1;
    previousButton_->setEnabled(kPosition > 0);
    nextButton_->setEnabled(
        kPosition >= 0 && kPosition + 1 < static_cast<int>(visibleTopicIndexes_.size()));
    copyButton_->setEnabled(true);
    evidenceButton_->setToolTip(uiText("action.evidence.tooltip"));
    evidenceButton_->setEnabled(true);
    routeButton_->setEnabled(
        static_cast<bool>(routeHandler_) && !currentRouteId_.isEmpty());
    referenceButton_->setEnabled(!currentReferenceUrl_.isEmpty());
}

bool KernelKnowledgeTab::selectTopic(const int topicIndex)
{
    QTreeWidgetItemIterator iterator(topicTree_);
    while (*iterator != nullptr)
    {
        QTreeWidgetItem* item = *iterator;
        const QVariant kIndexValue = item->data(0, kTopicIndexRole);
        if (kIndexValue.isValid() && kIndexValue.toInt() == topicIndex)
        {
            topicTree_->setCurrentItem(item);
            topicTree_->scrollToItem(item, QAbstractItemView::PositionAtCenter);
            return true;
        }
        ++iterator;
    }
    return false;
}

int KernelKnowledgeTab::findTopicIndex(const QString& topicId) const
{
    if (topicId.isEmpty())
    {
        return -1;
    }

    const auto& topicCatalog = ks::kernel_knowledge::topics();
    for (std::size_t topicIndex = 0; topicIndex < topicCatalog.size(); ++topicIndex)
    {
        if (QString::fromLatin1(topicCatalog[topicIndex].id) == topicId)
        {
            return static_cast<int>(topicIndex);
        }
    }
    return -1;
}

void KernelKnowledgeTab::navigateRelative(const int delta)
{
    const auto kCurrentPosition = std::find(
        visibleTopicIndexes_.cbegin(),
        visibleTopicIndexes_.cend(),
        currentTopicIndex_);
    if (kCurrentPosition == visibleTopicIndexes_.cend())
    {
        return;
    }

    const int kSourcePosition = static_cast<int>(
        std::distance(visibleTopicIndexes_.cbegin(), kCurrentPosition));
    const int kTargetPosition = kSourcePosition + delta;
    if (kTargetPosition < 0 ||
        kTargetPosition >= static_cast<int>(visibleTopicIndexes_.size()))
    {
        return;
    }

    const int kTargetTopicIndex = visibleTopicIndexes_[static_cast<std::size_t>(kTargetPosition)];
    selectTopic(kTargetTopicIndex);
    showTopic(kTargetTopicIndex);
}

void KernelKnowledgeTab::copyCurrentTopic() const
{
    if (currentTopicIndex_ < 0)
    {
        return;
    }

    const auto& topic = ks::kernel_knowledge::topics()[
        static_cast<std::size_t>(currentTopicIndex_)];
    QString copyText = QStringLiteral("# %1\n\n%2\n\n%3")
        .arg(
            ks::kernel_knowledge::topicText(topic, "title"),
            ks::kernel_knowledge::topicText(topic, "summary"),
            ks::kernel_knowledge::topicText(topic, "body"));
    if (!currentReferenceUrl_.isEmpty())
    {
        copyText += QStringLiteral("\n\n%1: %2")
            .arg(uiText("reference.microsoft"), currentReferenceUrl_);
    }
    QApplication::clipboard()->setText(copyText);
}

void KernelKnowledgeTab::openCurrentRoute() const
{
    if (routeHandler_ && !currentRouteId_.isEmpty())
    {
        routeHandler_(currentRouteId_);
    }
}

void KernelKnowledgeTab::openCurrentReference() const
{
    if (!currentReferenceUrl_.isEmpty())
    {
        QDesktopServices::openUrl(QUrl(currentReferenceUrl_));
    }
}

void KernelKnowledgeTab::collectCurrentEvidence()
{
    if (currentTopicIndex_ < 0 || evidenceButton_ == nullptr)
    {
        return;
    }

    const unsigned long kTopicId = static_cast<unsigned long>(currentTopicIndex_ + 1);
    const QString kTopicTitle = titleLabel_->text();
    const std::uint64_t kGeneration = ++evidenceGeneration_;
    evidenceButton_->setEnabled(false);
    evidenceButton_->setToolTip(uiText("evidence.collecting"));

    QPointer<KernelKnowledgeTab> guard(this);
    std::thread([guard, kGeneration, kTopicId, kTopicTitle]() mutable
    {
        auto result = ksword::ark::DriverClient().queryResearchTopic(kTopicId);
        if (guard.isNull())
        {
            return;
        }
        QMetaObject::invokeMethod(
            guard.data(),
            [guard, kGeneration, kTopicId, kTopicTitle, result = std::move(result)]() mutable
            {
                if (guard.isNull() || guard->evidenceGeneration_ != kGeneration)
                {
                    return;
                }

                guard->evidenceButton_->setEnabled(true);
                guard->evidenceButton_->setToolTip(uiText("action.evidence.tooltip"));

                auto* dialog = new QDialog(guard.data());
                dialog->setAttribute(Qt::WA_DeleteOnClose, true);
                dialog->setWindowTitle(
                    uiText("evidence.dialog.title").arg(kTopicTitle));
                dialog->resize(900, 620);

                auto* layout = new QVBoxLayout(dialog);
                layout->setContentsMargins(10, 10, 10, 10);
                layout->setSpacing(8);
                auto* editor = new QTextEdit(dialog);
                editor->setReadOnly(true);
                editor->setLineWrapMode(QTextEdit::NoWrap);
                editor->setFont(QFont(QStringLiteral("Consolas"), 10));
                editor->setStyleSheet(QStringLiteral(
                    "QTextEdit{background:%1;color:%2;border:1px solid %3;"
                    "border-radius:4px;padding:6px;}")
                    .arg(
                        ksword_theme::surfaceHex(),
                        ksword_theme::textPrimaryHex(),
                        ksword_theme::borderHex()));
                layout->addWidget(editor, 1);

                auto* buttons = new QDialogButtonBox(
                    QDialogButtonBox::Close,
                    dialog);
                QObject::connect(
                    buttons,
                    &QDialogButtonBox::rejected,
                    dialog,
                    &QDialog::reject);
                layout->addWidget(buttons, 0);

                QString report;
                if (!result.io.ok)
                {
                    report = uiText("evidence.unavailable")
                        .arg(kTopicId)
                        .arg(result.io.win32Error)
                        .arg(QString::fromStdString(result.io.message));
                }
                else
                {
                    const auto& response = result.response;
                    report += uiText("evidence.summary")
                        .arg(kTopicId)
                        .arg(response.queryStatus)
                        .arg(QString::number(response.responseFlags, 16).toUpper())
                        .arg(response.returnedCount)
                        .arg(response.totalCount)
                        .arg(response.registeredIoctlCount)
                        .arg(response.duplicateIoctlCount);
                    report += QLatin1Char('\n');
                    report += uiText("evidence.context")
                        .arg(response.requestorProcessId)
                        .arg(response.requestorThreadId)
                        .arg(response.currentIrql)
                        .arg(response.processorGroup)
                        .arg(response.processorNumber)
                        .arg(response.activeGroupCount)
                        .arg(response.activeProcessorCount)
                        .arg(QString::number(response.systemTime100ns))
                        .arg(QString::number(response.performanceCounter));
                    report += QStringLiteral("\n\n");

                    for (std::size_t index = 0U; index < result.entries.size(); ++index)
                    {
                        const auto& row = result.entries[index];
                        const QString kState = row.state ==
                                KSWORD_ARK_RESEARCH_EVIDENCE_AVAILABLE
                            ? uiText("evidence.state.available")
                            : uiText("evidence.state.unavailable");
                        report += uiText("evidence.row")
                            .arg(static_cast<qulonglong>(index + 1U))
                            .arg(QString::fromLatin1(row.name))
                            .arg(row.kind)
                            .arg(kState)
                            .arg(row.confidence)
                            .arg(QString::number(row.sourceMask, 16).toUpper())
                            .arg(QString::number(row.ioControlCode, 16).toUpper())
                            .arg(QString::number(
                                static_cast<unsigned long>(row.lastStatus),
                                16).toUpper())
                            .arg(QString::number(row.value0, 16).toUpper())
                            .arg(QString::number(row.value1, 16).toUpper())
                            .arg(QString::number(row.value2, 16).toUpper())
                            .arg(QString::number(row.value3, 16).toUpper());
                        report += QLatin1Char('\n');
                    }
                    report += QStringLiteral("\n");
                    report += uiText("evidence.boundary");
                }

                editor->setPlainText(report);
                dialog->show();
            },
            Qt::QueuedConnection);
    }).detach();
}
