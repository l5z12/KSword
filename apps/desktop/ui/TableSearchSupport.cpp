#include "TableSearchSupport.h"

#include "GlobalUiSearch.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QAbstractItemModel>
#include <QApplication>

#include <QEvent>
#include <QFrame>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLineEdit>
#include <QMargins>
#include <QPoint>
#include <QScrollBar>

#include <QSize>
#include <QSizePolicy>
#include <QStackedWidget>
#include <QStringList>
#include <QTabWidget>
#include <QTableView>
#include <QTimer>
#include <QToolButton>
#include <QVariant>

#include <algorithm>

namespace
{
    constexpr char kSearchSupportObjectName[] = "KSWORD_TABLE_SEARCH_SUPPORT";
    constexpr char kSearchSupportPropertyName[] = "KSWORD_TABLE_SEARCH_SUPPORT_OBJECT";
    constexpr char kTableActionBarObjectName[] = "KSWORD_TABLE_INTERACTION_ACTION_BAR";
    constexpr char kGenericSearchControlPropertyName[] = "ksword_generic_table_search_control";
    constexpr char kGlobalSearchInputPropertyName[] = "ksword_global_ui_search_input";
    constexpr char kExplicitTableNamePropertyName[] = "ksword_table_search_name";
    constexpr int kCollapsedSearchWidth = 28;
    constexpr int kSearchControlHeight = 24;
    constexpr int kSearchOuterMargin = 4;

    // textLooksLikeSearchControl: Identify existing search/filter input fields on the page using control metadata.
    bool textLooksLikeSearchControl(const QString& sourceText)
    {
        const QString kNormalizedText = sourceText.trimmed().toLower();
        return kNormalizedText.contains(QStringLiteral("搜索"))
            || kNormalizedText.contains(QStringLiteral("筛选"))
            || kNormalizedText.contains(QStringLiteral("过滤"))
            || kNormalizedText.contains(QStringLiteral("search"))
            || kNormalizedText.contains(QStringLiteral("filter"))
            || kNormalizedText.contains(QStringLiteral("find"));
    }

    // nearestPageRoot: Returns the nearest tab page containing the table; falls back to the top-level window content root if not found.
    QWidget* nearestPageRoot(QWidget* childWidget)
    {
        QWidget* fallbackRoot = childWidget;
        for (QWidget* cursorWidget = childWidget;
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            fallbackRoot = cursorWidget;
            QWidget* parentWidget = cursorWidget->parentWidget();
            if (qobject_cast<QStackedWidget*>(parentWidget) != nullptr)
            {
                return cursorWidget;
            }
            if (cursorWidget->isWindow())
            {
                break;
            }
        }
        return fallbackRoot;
    }

    // hasDedicatedSearchControl: checks for a dedicated search input box on the same page, located above or in the same group as the table.
    bool hasDedicatedSearchControl(QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return false;
        }

        QWidget* pageRoot = nearestPageRoot(tableView);
        if (pageRoot == nullptr)
        {
            return false;
        }
        const QPoint kTableTopLeft = tableView->mapTo(pageRoot, QPoint(0, 0));
        const QList<QLineEdit*> kLineEditList = pageRoot->findChildren<QLineEdit*>();
        for (QLineEdit* lineEdit : kLineEditList)
        {
            if (lineEdit == nullptr
                || lineEdit->property(kGenericSearchControlPropertyName).toBool()
                || lineEdit->property(kGlobalSearchInputPropertyName).toBool())
            {
                continue;
            }

            const QString kSearchMetadata = lineEdit->objectName()
                + QLatin1Char(' ')
                + lineEdit->placeholderText()
                + QLatin1Char(' ')
                + lineEdit->toolTip()
                + QLatin1Char(' ')
                + lineEdit->accessibleName();
            if (!textLooksLikeSearchControl(kSearchMetadata))
            {
                continue;
            }

            const QPoint kEditTopLeft = lineEdit->mapTo(pageRoot, QPoint(0, 0));
            const bool kDirectlyAboveTable = kEditTopLeft.y() <= kTableTopLeft.y()
                && kTableTopLeft.y() - kEditTopLeft.y() <= 180;
            const bool kSharesImmediateContainer = lineEdit->parentWidget() == tableView->parentWidget();
            if (kDirectlyAboveTable || kSharesImmediateContainer)
            {
                return true;
            }
        }
        return false;
    }

    // tableNeedsSearchAccess: Access is required only when the model content actually exceeds the current vertical viewport.
    bool tableNeedsSearchAccess(QTableView* tableView)
    {
        return tableView != nullptr
            && tableView->model() != nullptr
            && tableView->model()->rowCount() > 0
            && tableView->verticalScrollBar() != nullptr
            && tableView->verticalScrollBar()->maximum()
                > tableView->verticalScrollBar()->minimum();
    }

    // resolveSearchHost: Prefer the existing table toolbar; otherwise, use the blank area at the end of the horizontal header.
    QWidget* resolveSearchHost(QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return nullptr;
        }
        QWidget* actionBar = tableView->findChild<QWidget*>(
            QString::fromLatin1(kTableActionBarObjectName),
            Qt::FindDirectChildrenOnly);
        return actionBar != nullptr ? actionBar : tableView->horizontalHeader();
    }

    // trailingHeaderSpace: calculates the pixel width on the far right of the horizontal header not occupied by visible columns.
    int trailingHeaderSpace(QTableView* tableView)
    {
        QHeaderView* headerView = tableView != nullptr ? tableView->horizontalHeader() : nullptr;
        if (headerView == nullptr)
        {
            return 0;
        }

        int occupiedRight = 0;
        for (int logicalIndex = 0; logicalIndex < headerView->count(); ++logicalIndex)
        {
            if (headerView->isSectionHidden(logicalIndex))
            {
                continue;
            }
            const int kSectionLeft = headerView->sectionViewportPosition(logicalIndex);
            const int kSectionRight = kSectionLeft + headerView->sectionSize(logicalIndex);
            occupiedRight = std::max(occupiedRight, kSectionRight);
        }
        return std::max(0, headerView->width() - occupiedRight);
    }

    // TableSearchAccessWidget: Manages the search button and host space reservation for a single table.
    class TableSearchAccessWidget final : public QFrame
    {
    public:
        explicit TableSearchAccessWidget(QTableView* tableView)
            : QFrame(resolveSearchHost(tableView))
            , tableView_(tableView)
            , hostWidget_(resolveSearchHost(tableView))
        {
            setObjectName(QString::fromLatin1(kSearchSupportObjectName));
            setFrameShape(QFrame::NoFrame);
            setAttribute(Qt::WA_StyledBackground, true);

            auto* rootLayout = new QHBoxLayout(this);
            rootLayout->setContentsMargins(0, 0, 0, 0);
            rootLayout->setSpacing(0);

            searchButton_ = new QToolButton(this);
            searchButton_->setProperty(kGenericSearchControlPropertyName, true);
            searchButton_->setAutoRaise(true);
            searchButton_->setIcon(QIcon(QStringLiteral(":/Icon/file_find.svg")));
            searchButton_->setIconSize(QSize(16, 16));
            searchButton_->setFixedSize(kCollapsedSearchWidth, kSearchControlHeight);
            rootLayout->addWidget(searchButton_);

            connect(searchButton_, &QToolButton::clicked, this, [this]() {
                if (!tableView_.isNull())
                {
                    ks::ui::activateGlobalUiSearchForTable(
                        tableView_.data(),
                        QString(),
                        true);
                }
            });
            if (hostWidget_ != nullptr && hostWidget_->layout() != nullptr)
            {
                originalHostMargins_ = hostWidget_->layout()->contentsMargins();
            }
            installObservers();
            refreshPresentation();
        }

        ~TableSearchAccessWidget() override
        {
            clearResultFilter();
            restoreHostMargins();
        }

        bool isGenericSearchEligible() const
        {
            return !tableView_.isNull()
                && tableView_->model() != nullptr
                && !hasDedicatedSearchControl(tableView_.data());
        }

        bool applyResultFilter(const QString& queryText)
        {
            const QString kNormalizedQuery = queryText.trimmed();
            if (!isGenericSearchEligible() || kNormalizedQuery.isEmpty())
            {
                clearResultFilter();
                return false;
            }

            QAbstractItemModel* currentModel = tableView_->model();
            observeFilterModel(currentModel);
            if (!resultFilterActive_)
            {
                keepSearchAccessVisible_ = tableNeedsSearchAccess(
                    tableView_.data());
                captureBaselineHiddenRows();
            }
            else
            {
                restoreBaselineHiddenRows();
            }

            resultFilterActive_ = true;
            resultFilterQuery_ = kNormalizedQuery;
            applyResultFilterRows();

            scheduleRefresh();
            return true;
        }

        void clearResultFilter()
        {
            const bool kStateChanged = resultFilterActive_;
            if (resultFilterActive_)
            {
                restoreBaselineHiddenRows();
            }
            resultFilterActive_ = false;
            modelMutationPrepared_ = false;
            keepSearchAccessVisible_ = false;
            resultFilterQuery_.clear();
            baselineHiddenRowList_.clear();

            if (kStateChanged)
            {
                scheduleRefresh();
            }
        }


        void refreshPresentation()
        {
            if (tableView_.isNull() || hostWidget_.isNull())
            {
                hide();
                return;
            }

            QTableView* tableView = tableView_.data();
            const QString kTableName = ks::ui::resolveTableSearchDisplayName(tableView);
            searchButton_->setToolTip(
                ks::i18n::sourceText(QStringLiteral("搜索当前表格：%1")).arg(kTableName));

            if (hasDedicatedSearchControl(tableView))
            {
                clearResultFilter();
                applyPresentation(0);
                return;
            }
            if (!tableNeedsSearchAccess(tableView)
                && !(resultFilterActive_ && keepSearchAccessVisible_))
            {
                applyPresentation(0);
                return;
            }

            QWidget* hostWidget = hostWidget_.data();
            const bool kHostedByActionBar = hostWidget != tableView->horizontalHeader();
            int availableWidth = trailingHeaderSpace(tableView);
            if (kHostedByActionBar)
            {
                const int kMinimumContentWidth = hostWidget->layout() != nullptr
                    ? hostWidget->layout()->minimumSize().width()
                    : 0;
                // minimumSize already includes the current search reservation; add back this width before deciding to promote
                // or demote to avoid a LayoutRequest loop caused by repeatedly removing and re-adding margins on each refresh.
                availableWidth = std::max(
                    0,
                    hostWidget->width() - kMinimumContentWidth + reservedHostWidth_);
            }

            if (availableWidth >= kCollapsedSearchWidth + kSearchOuterMargin)
            {
                applyPresentation(kCollapsedSearchWidth);
            }
            else
            {
                applyPresentation(0);
            }
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject != nullptr
                && (eventObject->type() == QEvent::Resize
                    || eventObject->type() == QEvent::LayoutRequest
                    || eventObject->type() == QEvent::Show
                    || eventObject->type() == QEvent::StyleChange
                    || eventObject->type() == QEvent::LanguageChange))
            {
                scheduleRefresh();
            }
            return QFrame::eventFilter(watchedObject, eventObject);
        }

    private:
        void observeFilterModel(QAbstractItemModel* model)
        {
            if (filterModel_ == model)
            {
                return;
            }
            resultFilterActive_ = false;
            modelMutationPrepared_ = false;
            baselineHiddenRowList_.clear();
            if (!filterModel_.isNull())
            {
                QObject::disconnect(filterModel_.data(), nullptr, this, nullptr);
            }

            filterModel_ = model;
            if (model == nullptr)
            {
                return;
            }

            // Before structural changes, revoke additional hidden states; after changes, re-collect the original business hidden states.
            const auto kPrepareMutation = [this]() {
                prepareForModelMutation();
            };
            const auto kFinishMutation = [this]() {
                scheduleFilterReapply(true);
            };
            connect(model, &QAbstractItemModel::rowsAboutToBeInserted, this, kPrepareMutation);
            connect(model, &QAbstractItemModel::rowsAboutToBeRemoved, this, kPrepareMutation);
            connect(model, &QAbstractItemModel::rowsAboutToBeMoved, this, kPrepareMutation);
            connect(model, &QAbstractItemModel::columnsAboutToBeInserted, this, kPrepareMutation);
            connect(model, &QAbstractItemModel::columnsAboutToBeRemoved, this, kPrepareMutation);
            connect(model, &QAbstractItemModel::columnsAboutToBeMoved, this, kPrepareMutation);
            connect(model, &QAbstractItemModel::layoutAboutToBeChanged, this, kPrepareMutation);
            connect(model, &QAbstractItemModel::modelAboutToBeReset, this, kPrepareMutation);

            connect(model, &QAbstractItemModel::rowsInserted, this, kFinishMutation);
            connect(model, &QAbstractItemModel::rowsRemoved, this, kFinishMutation);
            connect(model, &QAbstractItemModel::rowsMoved, this, kFinishMutation);
            connect(model, &QAbstractItemModel::columnsInserted, this, kFinishMutation);
            connect(model, &QAbstractItemModel::columnsRemoved, this, kFinishMutation);
            connect(model, &QAbstractItemModel::columnsMoved, this, kFinishMutation);
            connect(model, &QAbstractItemModel::layoutChanged, this, kFinishMutation);
            connect(model, &QAbstractItemModel::modelReset, this, kFinishMutation);
            connect(
                model,
                &QAbstractItemModel::dataChanged,
                this,
                [this]() { scheduleFilterReapply(false); });
        }

        void prepareForModelMutation()
        {
            if (!resultFilterActive_ || modelMutationPrepared_)
            {
                return;
            }
            restoreBaselineHiddenRows();
            baselineHiddenRowList_.clear();
            modelMutationPrepared_ = true;
        }

        void scheduleFilterReapply(const bool recaptureBaseline)
        {
            if (!resultFilterActive_ || filterRefreshPending_)
            {
                return;
            }
            filterRefreshPending_ = true;
            QTimer::singleShot(0, this, [this, recaptureBaseline]() {
                filterRefreshPending_ = false;
                if (!resultFilterActive_ || tableView_.isNull())
                {
                    return;
                }

                if (recaptureBaseline || modelMutationPrepared_)
                {
                    captureBaselineHiddenRows();
                    modelMutationPrepared_ = false;
                }
                else
                {
                    restoreBaselineHiddenRows();
                }
                applyResultFilterRows();
                scheduleRefresh();
            });
        }

        void captureBaselineHiddenRows()
        {
            baselineHiddenRowList_.clear();
            if (tableView_.isNull() || tableView_->model() == nullptr)
            {
                return;
            }

            const int kRowCount = tableView_->model()->rowCount();
            baselineHiddenRowList_.reserve(kRowCount);
            for (int rowIndex = 0; rowIndex < kRowCount; ++rowIndex)
            {
                baselineHiddenRowList_.push_back(
                    tableView_->isRowHidden(rowIndex));
            }
        }

        void restoreBaselineHiddenRows()
        {
            if (tableView_.isNull()
                || tableView_->model() == nullptr
                || filterModel_ != tableView_->model())
            {
                return;
            }

            const int kRestorableRowCount = std::min(
                tableView_->model()->rowCount(),
                static_cast<int>(baselineHiddenRowList_.size()));
            for (int rowIndex = 0; rowIndex < kRestorableRowCount; ++rowIndex)
            {
                tableView_->setRowHidden(
                    rowIndex,
                    baselineHiddenRowList_.at(rowIndex));
            }
        }

        bool rowMatchesQuery(const int rowIndex) const
        {
            if (tableView_.isNull() || tableView_->model() == nullptr)
            {
                return false;
            }

            QAbstractItemModel* model = tableView_->model();
            for (int columnIndex = 0;
                 columnIndex < model->columnCount();
                 ++columnIndex)
            {
                if (tableView_->isColumnHidden(columnIndex))
                {
                    continue;
                }
                const QString kCellText = model
                    ->index(rowIndex, columnIndex)
                    .data(Qt::DisplayRole)
                    .toString();
                if (kCellText.contains(resultFilterQuery_, Qt::CaseInsensitive))
                {
                    return true;
                }
            }
            return false;
        }

        void applyResultFilterRows()
        {
            if (!resultFilterActive_
                || tableView_.isNull()
                || tableView_->model() == nullptr)
            {
                return;
            }

            const int kRowCount = tableView_->model()->rowCount();
            if (baselineHiddenRowList_.size() != kRowCount)
            {
                captureBaselineHiddenRows();
            }
            for (int rowIndex = 0; rowIndex < kRowCount; ++rowIndex)
            {
                const bool kBaselineHidden = baselineHiddenRowList_.at(rowIndex);
                tableView_->setRowHidden(
                    rowIndex,
                    kBaselineHidden || !rowMatchesQuery(rowIndex));
            }
        }

        void installObservers()
        {
            if (!tableView_.isNull())
            {
                tableView_->installEventFilter(this);
                if (tableView_->verticalScrollBar() != nullptr)
                {
                    connect(
                        tableView_->verticalScrollBar(),
                        &QScrollBar::rangeChanged,
                        this,
                        [this](int, int) { scheduleRefresh(); });
                }
                if (tableView_->horizontalHeader() != nullptr)
                {
                    tableView_->horizontalHeader()->installEventFilter(this);
                    connect(
                        tableView_->horizontalHeader(),
                        &QHeaderView::geometriesChanged,
                        this,
                        [this]() { scheduleRefresh(); });
                }
            }
            if (!hostWidget_.isNull())
            {
                hostWidget_->installEventFilter(this);
            }
        }

        void scheduleRefresh()
        {
            if (refreshPending_)
            {
                return;
            }
            refreshPending_ = true;
            QTimer::singleShot(0, this, [this]() {
                refreshPending_ = false;
                refreshPresentation();
            });
        }

        void restoreHostMargins()
        {
            if (!hostWidget_.isNull()
                && hostWidget_->layout() != nullptr
                && !tableView_.isNull()
                && hostWidget_.data() != tableView_->horizontalHeader()
                && reservedHostWidth_ > 0)
            {
                hostWidget_->layout()->setContentsMargins(originalHostMargins_);
                reservedHostWidth_ = 0;
            }
        }

        void applyPresentation(const int requestedWidth)
        {
            if (requestedWidth <= 0 || hostWidget_.isNull())
            {
                restoreHostMargins();
                hide();
                return;
            }

            QWidget* hostWidget = hostWidget_.data();
            searchButton_->setVisible(true);

            if (hostWidget->layout() != nullptr
                && hostWidget != tableView_->horizontalHeader())
            {
                const int kRequestedReservation = requestedWidth + kSearchOuterMargin;
                if (reservedHostWidth_ != kRequestedReservation)
                {
                    QMargins reservedMargins = originalHostMargins_;
                    reservedMargins.setRight(
                        reservedMargins.right() + kRequestedReservation);
                    hostWidget->layout()->setContentsMargins(reservedMargins);
                    reservedHostWidth_ = kRequestedReservation;
                }
            }

            const int kControlTop = std::max(0, (hostWidget->height() - kSearchControlHeight) / 2);
            const int kControlLeft = std::max(
                0,
                hostWidget->width() - requestedWidth - kSearchOuterMargin);
            setGeometry(
                kControlLeft,
                kControlTop,
                requestedWidth,
                kSearchControlHeight);
            setStyleSheet(QStringLiteral(
                "QFrame#KSWORD_TABLE_SEARCH_SUPPORT{background:transparent;}"
                "QLineEdit{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:0 6px;}"
                "QLineEdit:focus{border-color:%4;}"

                "QToolButton{background:transparent;color:%2;border:1px solid transparent;border-radius:3px;}"
                "QToolButton:hover{background:%5;border-color:%4;}" )
                .arg(
                    ksword_theme::surfaceHex(),
                    ksword_theme::textPrimaryHex(),
                    ksword_theme::borderStrongHex(),
                    ksword_theme::kPrimaryBlueHex,
                    ksword_theme::surfaceAltHex()));
            show();
            raise();
        }

        QPointer<QTableView> tableView_;    // m_tableView: Original table corresponding to the search entry.
        QPointer<QWidget> hostWidget_;      // m_hostWidget: Host for the toolbar or horizontal header.
        QToolButton* searchButton_ = nullptr; // m_searchButton: Icon button to activate table search in the title bar.
        QMargins originalHostMargins_;      // m_originalHostMargins: Original layout margins of the toolbar.
        QPointer<QAbstractItemModel> filterModel_; // m_filterModel: The current model observed when filtering is enabled.
        QVector<bool> baselineHiddenRowList_; // m_baselineHiddenRowList: Hides rows one-by-one in the snapshot before enabling filtering.
        QString resultFilterQuery_;         // m_resultFilterQuery: Keyword for the current result display filter.
        int reservedHostWidth_ = 0;         // m_reservedHostWidth: Reserved right-side width for the search entry.
        bool resultFilterActive_ = false;   // m_resultFilterActive: Whether the common row filter is attached.
        bool keepSearchAccessVisible_ = false; // m_keepSearchAccessVisible: Whether the entry satisfies the condition to be displayed as a super-page before filtering.
        bool modelMutationPrepared_ = false; // m_modelMutationPrepared: Whether the baseline has been restored before structure mutation.
        bool filterRefreshPending_ = false; // m_filterRefreshPending: Filter refresh triggered by merged model changes.
        bool refreshPending_ = false;       // m_refreshPending: Merge refresh requests within the same event loop.
    };

    // searchSupportForTable: Retrieves the installed search entry object for the table.
    TableSearchAccessWidget* searchSupportForTable(QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return nullptr;
        }
        QObject* supportObject = tableView->property(kSearchSupportPropertyName).value<QObject*>();
        return dynamic_cast<TableSearchAccessWidget*>(supportObject);
    }

    // normalizedMatchRank: Calculates the sort priority for cell match results.
    int normalizedMatchRank(const QString& cellText, const QString& queryText)
    {
        if (cellText.compare(queryText, Qt::CaseInsensitive) == 0)
        {
            return 0;
        }
        return cellText.startsWith(queryText, Qt::CaseInsensitive) ? 1 : 2;
    }
}

namespace ks::ui
{
    void installTableSearchSupport(QTableView* tableView)
    {
        if (tableView == nullptr || searchSupportForTable(tableView) != nullptr)
        {
            return;
        }
        auto* searchSupport = new TableSearchAccessWidget(tableView);
        tableView->setProperty(
            kSearchSupportPropertyName,
            QVariant::fromValue<QObject*>(searchSupport));
    }

    void refreshTableSearchSupport(QTableView* tableView)
    {
        if (TableSearchAccessWidget* searchSupport = searchSupportForTable(tableView))
        {
            searchSupport->refreshPresentation();
        }
    }

    bool isGenericTableSearchEligible(QTableView* tableView)
    {
        if (TableSearchAccessWidget* searchSupport = searchSupportForTable(tableView))
        {
            return searchSupport->isGenericSearchEligible();
        }
        return false;
    }

    bool applyTableSearchResultFilter(
        QTableView* tableView,
        const QString& queryText)
    {
        if (TableSearchAccessWidget* searchSupport = searchSupportForTable(tableView))
        {
            return searchSupport->applyResultFilter(queryText);
        }
        return false;
    }

    void clearTableSearchResultFilter(QTableView* tableView)
    {
        if (TableSearchAccessWidget* searchSupport = searchSupportForTable(tableView))
        {
            searchSupport->clearResultFilter();
        }
    }


    QString resolveTableSearchDisplayName(const QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return ks::i18n::sourceText(QStringLiteral("表格"));
        }

        const QString kExplicitName = tableView->property(kExplicitTableNamePropertyName)
            .toString()
            .trimmed();
        if (!kExplicitName.isEmpty())
        {
            return kExplicitName;
        }
        if (!tableView->accessibleName().trimmed().isEmpty())
        {
            return tableView->accessibleName().trimmed();
        }

        for (QWidget* cursorWidget = tableView->parentWidget();
             cursorWidget != nullptr;
             cursorWidget = cursorWidget->parentWidget())
        {
            if (QGroupBox* groupBox = qobject_cast<QGroupBox*>(cursorWidget))
            {
                if (!groupBox->title().trimmed().isEmpty())
                {
                    return groupBox->title().trimmed();
                }
            }
            QWidget* parentWidget = cursorWidget->parentWidget();
            if (QStackedWidget* stackedWidget = qobject_cast<QStackedWidget*>(parentWidget))
            {
                if (QTabWidget* tabWidget = qobject_cast<QTabWidget*>(stackedWidget->parentWidget()))
                {
                    const int kTabIndex = tabWidget->indexOf(cursorWidget);
                    if (kTabIndex >= 0 && !tabWidget->tabText(kTabIndex).trimmed().isEmpty())
                    {
                        return tabWidget->tabText(kTabIndex).trimmed();
                    }
                }
            }
        }

        QString objectName = tableView->objectName().trimmed();
        if (objectName.startsWith(QStringLiteral("m_"), Qt::CaseInsensitive))
        {
            objectName.remove(0, 2);
        }
        const QStringList kKnownSuffixList = {
            QStringLiteral("tableWidget"),
            QStringLiteral("tableView"),
            QStringLiteral("table")
        };
        for (const QString& knownSuffix : kKnownSuffixList)
        {
            if (objectName.endsWith(knownSuffix, Qt::CaseInsensitive))
            {
                objectName.chop(knownSuffix.size());
                break;
            }
        }
        if (!objectName.isEmpty())
        {
            return objectName;
        }
        return ks::i18n::sourceText(QStringLiteral("表格"));
    }

    QVector<TableCellSearchMatch> collectTableCellSearchMatches(
        QTableView* tableView,
        const QString& queryText,
        const int maxHitCount)
    {
        QVector<TableCellSearchMatch> resultList;
        if (tableView == nullptr
            || tableView->model() == nullptr
            || queryText.trimmed().isEmpty()
            || maxHitCount <= 0)
        {
            return resultList;
        }

        QAbstractItemModel* itemModel = tableView->model();
        const QString kNormalizedQuery = queryText.trimmed();
        const QString kTableName = resolveTableSearchDisplayName(tableView);
        const int kColumnCount = itemModel->columnCount();
        for (int columnIndex = 0;
             columnIndex < kColumnCount && resultList.size() < maxHitCount;
             ++columnIndex)
        {
            if (tableView->isColumnHidden(columnIndex) || itemModel->rowCount() <= 0)
            {
                continue;
            }

            const int kRemainingHitCount = maxHitCount - resultList.size();
            const QModelIndex kStartIndex = itemModel->index(0, columnIndex);
            const QModelIndexList kMatchedIndexList = itemModel->match(
                kStartIndex,
                Qt::DisplayRole,
                kNormalizedQuery,
                kRemainingHitCount,
                Qt::MatchContains | Qt::MatchRecursive);
            const QString kColumnName = itemModel
                ->headerData(columnIndex, Qt::Horizontal, Qt::DisplayRole)
                .toString()
                .trimmed();
            for (const QModelIndex& matchedIndex : kMatchedIndexList)
            {
                const QString kMatchedText = matchedIndex.data(Qt::DisplayRole).toString().trimmed();
                if (kMatchedText.isEmpty())
                {
                    continue;
                }

                TableCellSearchMatch searchMatch;
                searchMatch.tableView = tableView;
                searchMatch.modelIndex = QPersistentModelIndex(matchedIndex);
                searchMatch.matchedText = kMatchedText;
                searchMatch.locationText = kColumnName.isEmpty()
                    ? ks::i18n::sourceText(QStringLiteral("%1，第 %2 行"))
                        .arg(kTableName)
                        .arg(matchedIndex.row() + 1)
                    : ks::i18n::sourceText(QStringLiteral("%1，第 %2 行，%3 列"))
                        .arg(kTableName)
                        .arg(matchedIndex.row() + 1)
                        .arg(kColumnName);
                searchMatch.matchRank = normalizedMatchRank(kMatchedText, kNormalizedQuery);
                resultList.push_back(searchMatch);
                if (resultList.size() >= maxHitCount)
                {
                    break;
                }
            }
        }
        return resultList;
    }

    void revealTableCellSearchMatch(const TableCellSearchMatch& searchMatch)
    {
        QTableView* tableView = searchMatch.tableView.data();
        if (tableView == nullptr || !searchMatch.modelIndex.isValid())
        {
            return;
        }

        const QModelIndex kModelIndex = searchMatch.modelIndex;
        tableView->scrollTo(kModelIndex, QAbstractItemView::PositionAtCenter);
        tableView->setCurrentIndex(kModelIndex);
        if (tableView->selectionModel() != nullptr)
        {
            tableView->selectionModel()->select(
                kModelIndex,
                QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        }
        tableView->setFocus(Qt::OtherFocusReason);
    }
}
