#include "DetailLayoutHost.h"

#include "CodeEditorWidget.h"
#include "EmbeddedRowDelegate.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QApplication>
#include <QBoxLayout>
#include <QDialog>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QPlainTextEdit>
#include <QScreen>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <utility>

namespace
{
    // Use a dedicated role to avoid conflicting with the page's commonly used Qt::UserRole cache indices.
    constexpr int kOriginalDecorationRole = Qt::UserRole + 411;
    constexpr int kOriginalDecorationCapturedRole = Qt::UserRole + 412;

    QIcon embeddedIndicatorIcon(const bool expanded)
    {
        return QIcon(expanded
            ? QStringLiteral(":/Icon/detail_node_expanded.svg")
            : QStringLiteral(":/Icon/detail_node_collapsed.svg"));
    }

    // directChildUnder: Returns the first-level child of widget under ancestor, used to identify separator panels.
    QWidget* directChildUnder(QWidget* widget, QWidget* ancestor)
    {
        QWidget* childWidget = widget;
        while (childWidget != nullptr && childWidget->parentWidget() != ancestor)
        {
            childWidget = childWidget->parentWidget();
        }
        return childWidget != nullptr && childWidget->parentWidget() == ancestor
            ? childWidget
            : nullptr;
    }

    // findSharedSplitter: Searches upward from the table's ancestor to find the splitter containing both the detail editor.
    QSplitter* findSharedSplitter(QAbstractItemView* tableView, CodeEditorWidget* detailEditor)
    {
        QWidget* ancestorWidget = tableView;
        while (ancestorWidget != nullptr)
        {
            QSplitter* splitter = qobject_cast<QSplitter*>(ancestorWidget);
            if (splitter != nullptr && splitter->isAncestorOf(detailEditor))
            {
                // Only take over if the table and detail panes are in different direct panels of the splitter.
                // Common outer splitters on pages may enclose the entire table page; mistaking this can cause
                // the entire panel containing the table to be hidden during folding, leaving only an arrow.
                QWidget* tablePane = directChildUnder(tableView, splitter);
                QWidget* detailPane = directChildUnder(detailEditor, splitter);
                if (tablePane != nullptr && detailPane != nullptr && tablePane != detailPane)
                {
                    return splitter;
                }
            }
            ancestorWidget = ancestorWidget->parentWidget();
        }
        return nullptr;
    }

    // findCommonParent: Find the nearest common QWidget ancestor for two widgets.
    QWidget* findCommonParent(QWidget* firstWidget, QWidget* secondWidget)
    {
        for (QWidget* firstParent = firstWidget; firstParent != nullptr;
            firstParent = firstParent->parentWidget())
        {
            for (QWidget* secondParent = secondWidget; secondParent != nullptr;
                secondParent = secondParent->parentWidget())
            {
                if (firstParent == secondParent)
                {
                    return firstParent;
                }
            }
        }
        return nullptr;
    }

    // createReadOnlyInlineEditor: Creates a standard read-only text box used for Solution 3.
    QPlainTextEdit* createReadOnlyInlineEditor(QWidget* parentWidget, const QString& detailText)
    {
        QPlainTextEdit* textEditor = new QPlainTextEdit(parentWidget);
        textEditor->setReadOnly(true);
        textEditor->setPlainText(detailText);
        textEditor->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        // The editor directly overlays the viewport; its geometry is determined by the source
        // line height and cannot propagate its minimum height to the entire table or tree.
        textEditor->setMinimumSize(0, 0);
        textEditor->setContextMenuPolicy(Qt::DefaultContextMenu);
        return textEditor;
    }

}

ks::ui::DetailLayoutHost::DetailLayoutHost(
    QAbstractItemView* tableView,
    CodeEditorWidget* detailEditor,
    QWidget* ownerWidget)
    : QObject(ownerWidget),
      tableView_(tableView),
      detailEditor_(detailEditor),
      ownerWidget_(ownerWidget)
{
    initializeHostUi();
    initializeConnections();
    scheduleHostUiInitialization();
}

ks::ui::DetailLayoutHost::~DetailLayoutHost()
{
    // Before destroying the host, restore the row height and the original page delegate to prevent temporary wrappers from remaining in the shared view.
    clearEmbeddedDetails();
    destroyFloatingWindow();
}

void ks::ui::DetailLayoutHost::setTableView(QAbstractItemView* tableView)
{
    if (tableView == nullptr || tableView_ == tableView)
    {
        return;
    }
    tableView_ = tableView;
    initializeConnections();
    scheduleHostUiInitialization();
}

void ks::ui::DetailLayoutHost::setDetailEditor(CodeEditorWidget* detailEditor)
{
    if (detailEditor == nullptr || detailEditor_ == detailEditor)
    {
        return;
    }
    detailEditor_ = detailEditor;
    initializeConnections();
    scheduleHostUiInitialization();
}

CodeEditorWidget* ks::ui::DetailLayoutHost::detailEditor() const
{
    return detailEditor_.data();
}

void ks::ui::DetailLayoutHost::initializeHostUi()
{
    ensureManagedSplitter();
    if (splitter_.isNull())
    {
        return;
    }

    if (!toggleBar_.isNull())
    {
        return;
    }

    if (!detailPane_.isNull() && tablePane_.isNull())
    {
        tablePane_ = directChildUnder(tableView_.data(), splitter_.data());
    }

    // Fixed-width buttons cannot directly become children of a vertical QSplitter, as their maximumWidth would compress the splitter's
    // horizontal dimension. Use a horizontally expandable container bar, keeping only the central arrow at a compact width.
    toggleBar_ = new QWidget(splitter_.data());
    toggleBar_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    toggleBar_->setMinimumWidth(0);
    toggleBar_->setMaximumWidth(QWIDGETSIZE_MAX);
    toggleBar_->setFixedHeight(18);

    QHBoxLayout* toggleLayout = new QHBoxLayout(toggleBar_.data());
    toggleLayout->setContentsMargins(0, 0, 0, 0);
    toggleLayout->setSpacing(0);
    toggleLayout->addStretch(1);

    toggleButton_ = new QToolButton(toggleBar_.data());
    toggleButton_->setAutoRaise(true);
    toggleButton_->setArrowType(Qt::UpArrow);
    toggleButton_->setFocusPolicy(Qt::NoFocus);
    toggleButton_->setFixedSize(44, 18);
    toggleButton_->setToolTip(ks::i18n::text(
        QStringLiteral("detail.layout.toggle.tooltip"),
        QStringLiteral("展开或收起当前行详情")));
    toggleLayout->addWidget(toggleButton_.data(), 0, Qt::AlignCenter);
    toggleLayout->addStretch(1);

    // The arrow acts as a separator item; when collapsed, it sits exactly at the table's bottom edge, and when expanded, it positions itself between the table and the details.
    splitter_->insertWidget(1, toggleBar_.data());
}

void ks::ui::DetailLayoutHost::scheduleHostUiInitialization()
{
    if (hostUiInitializationScheduled_ || ownerWidget_.isNull())
    {
        return;
    }
    hostUiInitializationScheduled_ = true;
    QTimer::singleShot(0, this,
        [this]()
        {
            hostUiInitializationScheduled_ = false;
            if (splitter_.isNull() || detailPane_.isNull())
            {
                initializeHostUi();
            }
            if (!splitter_.isNull() && !detailPane_.isNull())
            {
                applyScheme(scheme_);
                updateEmbeddedEditorGeometries();
            }
        });
}

void ks::ui::DetailLayoutHost::ensureManagedSplitter()
{
    if (tableView_.isNull() || detailEditor_.isNull())
    {
        return;
    }

    QSplitter* sharedSplitter = findSharedSplitter(tableView_.data(), detailEditor_.data());
    if (sharedSplitter != nullptr)
    {
        splitter_ = sharedSplitter;
        tablePane_ = directChildUnder(tableView_.data(), sharedSplitter);
        detailPane_ = directChildUnder(detailEditor_.data(), sharedSplitter);
        if (tablePane_ == nullptr || detailPane_ == nullptr || tablePane_ == detailPane_)
        {
            splitter_.clear();
            tablePane_.clear();
            detailPane_.clear();
            return;
        }
        detailEditor_->setMinimumHeight(0);
        detailEditor_->setMaximumHeight(QWIDGETSIZE_MAX);
        return;
    }

    // The direct layout page lacks an existing QSplitter: retain the original control objects and wrap both into a unified splitter.
    QWidget* commonParent = findCommonParent(tableView_.data(), detailEditor_.data());
    QBoxLayout* commonLayout = commonParent != nullptr
        ? qobject_cast<QBoxLayout*>(commonParent->layout())
        : nullptr;
    if (commonParent == nullptr || commonLayout == nullptr)
    {
        return;
    }

    QWidget* tablePane = directChildUnder(tableView_.data(), commonParent);
    QWidget* detailPane = directChildUnder(detailEditor_.data(), commonParent);
    if (tablePane == nullptr || detailPane == nullptr || tablePane == detailPane)
    {
        return;
    }

    const int kTableIndex = commonLayout->indexOf(tablePane);
    const int kDetailIndex = commonLayout->indexOf(detailPane);
    const int kInsertionIndex = std::max(0, std::min(kTableIndex, kDetailIndex));
    commonLayout->removeWidget(tablePane);
    commonLayout->removeWidget(detailPane);

    QSplitter* splitter = new QSplitter(Qt::Vertical, commonParent);
    tablePane->setParent(splitter);
    detailPane->setParent(splitter);
    splitter->addWidget(tablePane);
    splitter->addWidget(detailPane);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    commonLayout->insertWidget(kInsertionIndex, splitter, 1);

    splitter_ = splitter;
    tablePane_ = tablePane;
    detailPane_ = detailPane;
    detailEditor_->setMinimumHeight(0);
    detailEditor_->setMaximumHeight(QWIDGETSIZE_MAX);
}

void ks::ui::DetailLayoutHost::initializeConnections()
{
    if (!tableView_.isNull())
    {
        // UniqueConnection is incompatible with member lambdas, so dynamic properties are used to ensure each view is bound only once.
        if (!tableView_->property("kswordDetailLayoutConnected").toBool())
        {
            tableView_->setProperty("kswordDetailLayoutConnected", true);
            if (tableView_->viewport() != nullptr)
            {
                tableView_->viewport()->installEventFilter(this);
            }
            connect(tableView_.data(), &QAbstractItemView::clicked, this,
                [this](const QModelIndex& modelIndex)
                {
                    handleViewClicked(QPersistentModelIndex(modelIndex));
                });

            if (tableView_->model() != nullptr)
            {
                connect(tableView_->model(), &QAbstractItemModel::rowsInserted, this,
                    [this](const QModelIndex&, int, int)
                    {
                        if (scheme_ != ks::settings::DetailDisplayScheme::kEmbedded)
                        {
                            return;
                        }
                        scheduleEmbeddedIndicatorRefresh();
                    });
                connect(tableView_->model(), &QAbstractItemModel::modelAboutToBeReset, this,
                    [this]()
                    {
                        clearEmbeddedDetails();
                    });
                connect(tableView_->model(), &QAbstractItemModel::layoutAboutToBeChanged, this,
                    [this]()
                    {
                        // QPersistentModelIndex moves with the data item after the sort layout is complete, but QHeaderView's row height
                        // remains bound to the logical row before sorting. Row heights must be restored and the covering editor removed
                        // before index remapping to prevent residual blank space from old rows and clipping of details in new rows.
                        clearEmbeddedDetails();
                    });
            }
        }
    }

    if (!detailEditor_.isNull() &&
        !detailEditor_->property("kswordDetailLayoutConnected").toBool())
    {
        detailEditor_->setProperty("kswordDetailLayoutConnected", true);
        connect(detailEditor_.data(), &CodeEditorWidget::contentChanged, this,
            [this](const QString& detailText) { handleDetailChanged(detailText); });
    }

    if (!toggleButton_.isNull())
    {
        connect(toggleButton_.data(), &QToolButton::clicked, this,
            [this]() { updateBottomExpanded(!bottomExpanded_); });
    }
}

void ks::ui::DetailLayoutHost::applyScheme(
    const ks::settings::DetailDisplayScheme scheme)
{
    if (splitter_.isNull() || detailPane_.isNull())
    {
        scheme_ = scheme;
        scheduleHostUiInitialization();
        return;
    }

    if (scheme_ == ks::settings::DetailDisplayScheme::kEmbedded &&
        scheme != ks::settings::DetailDisplayScheme::kEmbedded)
    {
        clearEmbeddedDetails();
    }
    if (scheme_ == ks::settings::DetailDisplayScheme::kFloating &&
        scheme != ks::settings::DetailDisplayScheme::kFloating)
    {
        destroyFloatingWindow();
    }

    const bool kSchemeChanged = scheme_ != scheme;
    scheme_ = scheme;
    if (!toggleBar_.isNull())
    {
        toggleBar_->setVisible(scheme == ks::settings::DetailDisplayScheme::kBottomCollapsed);
    }
    if (!tablePane_.isNull())
    {
        tablePane_->setVisible(true);
        tablePane_->setMinimumSize(0, 0);
        tablePane_->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
    }
    switch (scheme)
    {
    case ks::settings::DetailDisplayScheme::kRight:
        splitter_->setOrientation(Qt::Horizontal);
        detailPane_->setMinimumSize(0, 0);
        detailPane_->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
        detailPane_->setVisible(true);
        if (kSchemeChanged)
        {
            // Right detail pane defaults to ~18% width, preserving the splitter handle for further adjustment on the current page.
            setManagedSplitterSizes(820, 0, 180);
        }
        break;
    case ks::settings::DetailDisplayScheme::kEmbedded:
        splitter_->setOrientation(Qt::Vertical);
        detailPane_->setVisible(false);
        detailPane_->setMinimumHeight(0);
        detailPane_->setMaximumHeight(0);
        if (kSchemeChanged)
        {
            setManagedSplitterSizes(1000, 0, 0);
        }
        refreshEmbeddedIndicators();
        break;
    case ks::settings::DetailDisplayScheme::kFloating:
        splitter_->setOrientation(Qt::Vertical);
        detailPane_->setVisible(false);
        detailPane_->setMinimumHeight(0);
        detailPane_->setMaximumHeight(0);
        if (kSchemeChanged)
        {
            setManagedSplitterSizes(1000, 0, 0);
        }
        break;
    case ks::settings::DetailDisplayScheme::kBottomCollapsed:
    default:
        splitter_->setOrientation(Qt::Vertical);
        if (kSchemeChanged || (!bottomExpanded_ && detailPane_->isVisible()))
        {
            bottomExpanded_ = false;
            updateBottomExpanded(false);
        }
        break;
    }
    updateEmbeddedEditorGeometries();
}

void ks::ui::DetailLayoutHost::setManagedSplitterSizes(
    const int tableSize,
    const int toggleSize,
    const int detailSize)
{
    if (splitter_.isNull())
    {
        return;
    }
    // QSplitter normalizes the relative values of setSizes based on available space. Using non-zero table sizes ensures
    // the business panel is not compressed to 0, even if the page is not yet shown or the window just switched tabs.
    const int kSafeTable = std::max(1, tableSize);
    const int kSafeToggle = std::max(0, toggleSize);
    const int kSafeDetail = std::max(0, detailSize);
    splitter_->setSizes({ kSafeTable, kSafeToggle, kSafeDetail });
}

void ks::ui::DetailLayoutHost::updateBottomExpanded(const bool expanded)
{
    if (scheme_ != ks::settings::DetailDisplayScheme::kBottomCollapsed ||
        detailPane_.isNull())
    {
        return;
    }
    bottomExpanded_ = expanded;
    detailPane_->setMinimumHeight(0);
    if (expanded)
    {
        detailPane_->setMaximumHeight(QWIDGETSIZE_MAX);
        detailPane_->setVisible(true);
    }
    else
    {
        detailPane_->setVisible(false);
        detailPane_->setMaximumHeight(0);
    }
    if (!toggleButton_.isNull())
    {
        toggleButton_->setArrowType(expanded ? Qt::DownArrow : Qt::UpArrow);
        toggleButton_->setToolTip(ks::i18n::text(
            expanded
                ? QStringLiteral("detail.layout.collapse.tooltip")
                : QStringLiteral("detail.layout.expand.tooltip"),
            expanded
                ? QStringLiteral("收起当前行详情")
                : QStringLiteral("展开当前行详情")));
    }
    if (expanded && !splitter_.isNull())
    {
        setManagedSplitterSizes(720, 18, 240);
    }
    else if (!splitter_.isNull())
    {
        setManagedSplitterSizes(1000, 18, 0);
    }
}

void ks::ui::DetailLayoutHost::handleViewClicked(
    const QPersistentModelIndex& sourceIndex)
{
    if (!sourceIndex.isValid())
    {
        return;
    }

    switch (scheme_)
    {
    case ks::settings::DetailDisplayScheme::kEmbedded:
        // The original page's selection callback first updates the CodeEditorWidget; here, the latest text is mirrored to the inline view.
        QTimer::singleShot(0, this, [this, sourceIndex]()
            {
                if (sourceIndex.isValid())
                {
                    toggleEmbeddedDetail(sourceIndex.sibling(sourceIndex.row(), 0));
                }
            });
        break;
    case ks::settings::DetailDisplayScheme::kFloating:
        QTimer::singleShot(0, this, [this]() { showFloatingWindow(); });
        break;
    case ks::settings::DetailDisplayScheme::kBottomCollapsed:
        updateBottomExpanded(true);
        break;
    case ks::settings::DetailDisplayScheme::kRight:
    default:
        break;
    }
}

void ks::ui::DetailLayoutHost::handleDetailChanged(const QString& detailText)
{
    if (scheme_ == ks::settings::DetailDisplayScheme::kFloating && !floatingEditor_.isNull())
    {
        floatingEditor_->setRawText(detailText);
    }

    if (scheme_ != ks::settings::DetailDisplayScheme::kEmbedded || tableView_.isNull())
    {
        return;
    }

    const QModelIndex kRawCurrentIndex = tableView_->currentIndex();
    const QPersistentModelIndex kCurrentIndex(
        kRawCurrentIndex.isValid()
            ? kRawCurrentIndex.sibling(kRawCurrentIndex.row(), 0)
            : QModelIndex());
    for (EmbeddedEntry& entry : embeddedEntries_)
    {
        if (!entry.textEditor.isNull() && entry.sourceIndex.isValid() &&
            kCurrentIndex.isValid() && entry.sourceIndex == kCurrentIndex)
        {
            entry.textEditor->setPlainText(detailText);
        }
    }
}

void ks::ui::DetailLayoutHost::toggleEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex)
{
    if (!sourceIndex.isValid() || detailEditor_.isNull())
    {
        return;
    }
    if (removeEmbeddedEntry(sourceIndex))
    {
        setSourceExpandedIndicator(sourceIndex, false);
        return;
    }

    if (qobject_cast<QTableWidget*>(tableView_.data()) != nullptr)
    {
        insertTableEmbeddedDetail(sourceIndex, detailEditor_->text());
    }
    else if (qobject_cast<QTreeWidget*>(tableView_.data()) != nullptr)
    {
        insertTreeEmbeddedDetail(sourceIndex, detailEditor_->text());
    }
}

void ks::ui::DetailLayoutHost::insertTableEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex,
    const QString& detailText)
{
    QTableWidget* tableWidget = qobject_cast<QTableWidget*>(tableView_.data());
    if (tableWidget == nullptr || sourceIndex.row() < 0)
    {
        return;
    }

    const int kSourceRow = sourceIndex.row();
    // Use the actual visible rectangle before expansion as the baseline. `rowHeight()` retrieves the header
    // section state, which may differ from the row height in the viewport during layout updates after sorting
    // or asynchronous filling, causing the detail editor to shift down by a full row and leave a blank space.
    const int kOriginalHeight = std::max(1, tableWidget->visualRect(sourceIndex).height());
    constexpr int kInlineDetailHeight = 128;

    // First install the wrapper delegate and register the original height, then increase the row height to avoid rendering the source text into the detail area during a single repaint.
    installEmbeddedRowDelegate();
    QPlainTextEdit* textEditor = createReadOnlyInlineEditor(tableWidget->viewport(), detailText);
    EmbeddedEntry entry;
    entry.sourceIndex = sourceIndex;
    entry.textEditor = textEditor;
    entry.originalRowHeight = kOriginalHeight;
    entry.detailHeight = kInlineDetailHeight;
    embeddedEntries_.append(entry);
    tableWidget->setRowHeight(kSourceRow, kOriginalHeight + kInlineDetailHeight);
    textEditor->show();
    updateEmbeddedEditorGeometries();
    QTimer::singleShot(0, this, [this]() { updateEmbeddedEditorGeometries(); });
    setSourceExpandedIndicator(sourceIndex, true);
}

void ks::ui::DetailLayoutHost::insertTreeEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex,
    const QString& detailText)
{
    QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(tableView_.data());
    QTreeWidgetItem* sourceItem = treeWidget != nullptr
        ? treeWidget->itemFromIndex(sourceIndex)
        : nullptr;
    if (treeWidget == nullptr || sourceItem == nullptr)
    {
        return;
    }

    const QSize kOriginalSizeHint = sourceItem->sizeHint(0);
    const int kOriginalHeight = std::max(1, treeWidget->visualRect(sourceIndex).height());
    constexpr int kInlineDetailHeight = 128;

    // Tree nodes first register the clipped height, then update the size hint to ensure the original row height is used during the first repaint.
    installEmbeddedRowDelegate();
    QPlainTextEdit* textEditor = createReadOnlyInlineEditor(treeWidget->viewport(), detailText);
    EmbeddedEntry entry;
    entry.sourceIndex = sourceIndex;
    entry.textEditor = textEditor;
    entry.treeSourceItem = sourceItem;
    entry.originalRowHeight = kOriginalHeight;
    entry.detailHeight = kInlineDetailHeight;
    entry.originalSizeHint = kOriginalSizeHint;
    embeddedEntries_.append(entry);
    sourceItem->setSizeHint(0, QSize(-1, kOriginalHeight + kInlineDetailHeight));
    textEditor->show();
    updateEmbeddedEditorGeometries();
    QTimer::singleShot(0, this, [this]() { updateEmbeddedEditorGeometries(); });
    setSourceExpandedIndicator(sourceIndex, true);
}

bool ks::ui::DetailLayoutHost::removeEmbeddedEntry(
    const QPersistentModelIndex& sourceIndex)
{
    for (int entryIndex = 0; entryIndex < embeddedEntries_.size(); ++entryIndex)
    {
        EmbeddedEntry& entry = embeddedEntries_[entryIndex];
        if (!entry.sourceIndex.isValid() || entry.sourceIndex != sourceIndex)
        {
            continue;
        }

        restoreEmbeddedEntryLayout(entry);
        if (!entry.textEditor.isNull())
        {
            delete entry.textEditor.data();
        }
        embeddedEntries_.removeAt(entryIndex);
        if (embeddedEntries_.isEmpty())
        {
            restoreEmbeddedRowDelegate();
        }
        updateEmbeddedEditorGeometries();
        return true;
    }
    return false;
}

void ks::ui::DetailLayoutHost::clearEmbeddedDetails()
{
    if (tableView_.isNull())
    {
        embeddedEntries_.clear();
        restoreEmbeddedRowDelegate();
        return;
    }

    indicatorRefreshScheduled_ = false;
    for (const EmbeddedEntry& entry : std::as_const(embeddedEntries_))
    {
        restoreEmbeddedEntryLayout(entry);
        if (!entry.textEditor.isNull())
        {
            delete entry.textEditor.data();
        }
    }
    embeddedEntries_.clear();
    restoreEmbeddedRowDelegate();
    pendingIndicatorIndexes_.clear();
    ++indicatorGeneration_;
    restoreEmbeddedIndicators();
    updateEmbeddedEditorGeometries();
}

void ks::ui::DetailLayoutHost::prepareDataRebuild()
{
    clearEmbeddedDetails();
}

void ks::ui::DetailLayoutHost::installEmbeddedRowDelegate()
{
    if (tableView_.isNull() ||
        (!embeddedRowDelegate_.isNull() &&
         tableView_->itemDelegate() == embeddedRowDelegate_.data()))
    {
        return;
    }

    // When the current view has no delegate set, Qt guarantees falling back to default rendering; no source-less wrapper is needed.
    QAbstractItemDelegate* sourceDelegate = tableView_->itemDelegate();
    if (sourceDelegate == nullptr)
    {
        return;
    }

    // The source delegate is borrowed only; ownership remains with the page view; the wrapper is destroyed with the detail host.
    embeddedSourceDelegate_ = sourceDelegate;
    embeddedRowDelegate_ = new EmbeddedRowDelegate(
        sourceDelegate,
        [this](const QModelIndex& modelIndex)
        {
            return embeddedOriginalRowHeight(modelIndex);
        },
        this);
    tableView_->setItemDelegate(embeddedRowDelegate_.data());
    if (tableView_->viewport() != nullptr)
    {
        tableView_->viewport()->update();
    }
}

void ks::ui::DetailLayoutHost::restoreEmbeddedRowDelegate()
{
    if (!tableView_.isNull() && !embeddedRowDelegate_.isNull() &&
        tableView_->itemDelegate() == embeddedRowDelegate_.data() &&
        !embeddedSourceDelegate_.isNull())
    {
        // Restore only if the current delegate is still this wrapper to avoid overwriting a delegate replaced at runtime.
        tableView_->setItemDelegate(embeddedSourceDelegate_.data());
        if (tableView_->viewport() != nullptr)
        {
            tableView_->viewport()->update();
        }
    }

    // deleteLater ensures Qt does not destroy a delegate that may still be accessed within the current paint call stack.
    if (!embeddedRowDelegate_.isNull())
    {
        embeddedRowDelegate_->deleteLater();
    }
    embeddedRowDelegate_.clear();
    embeddedSourceDelegate_.clear();
}

int ks::ui::DetailLayoutHost::embeddedOriginalRowHeight(const QModelIndex& modelIndex) const
{
    if (!modelIndex.isValid())
    {
        return -1;
    }

    // The delegate is called separately for each column; compare the stable source index of column 0 to match the same logical row.
    const QModelIndex kSourceIndex = modelIndex.sibling(modelIndex.row(), 0);
    for (const EmbeddedEntry& entry : embeddedEntries_)
    {
        if (entry.sourceIndex.isValid() && entry.sourceIndex == kSourceIndex)
        {
            return entry.originalRowHeight;
        }
    }
    return -1;
}

void ks::ui::DetailLayoutHost::restoreEmbeddedEntryLayout(const EmbeddedEntry& entry)
{
    if (!tableView_.isNull())
    {
        if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(tableView_.data()))
        {
            if (entry.sourceIndex.isValid() && entry.originalRowHeight > 0)
            {
                tableWidget->setRowHeight(entry.sourceIndex.row(), entry.originalRowHeight);
            }
        }
        else if (entry.treeSourceItem != nullptr && !entry.originalSizeHint.isNull())
        {
            entry.treeSourceItem->setSizeHint(0, entry.originalSizeHint.toSize());
        }
    }
}

void ks::ui::DetailLayoutHost::updateEmbeddedEditorGeometries()
{
    if (tableView_.isNull())
    {
        return;
    }
    QWidget* viewport = tableView_->viewport();
    if (viewport == nullptr)
    {
        return;
    }
    for (const EmbeddedEntry& entry : std::as_const(embeddedEntries_))
    {
        if (entry.textEditor.isNull() || !entry.sourceIndex.isValid())
        {
            continue;
        }
        QRect itemRect = tableView_->visualRect(entry.sourceIndex);
        if (!itemRect.isValid() || itemRect.height() <= 0 || !viewport->rect().intersects(itemRect))
        {
            entry.textEditor->setVisible(false);
            continue;
        }
        const int kTopPadding = qMax(0, entry.originalRowHeight);
        const int kDetailHeight = qMax(1, entry.detailHeight);
        QRect editorRect = itemRect;
        editorRect.setTop(editorRect.top() + kTopPadding);
        editorRect.setLeft(0);
        editorRect.setWidth(viewport->width());
        editorRect.setBottom(qMin(itemRect.bottom(), editorRect.top() + kDetailHeight - 1));
        if (editorRect.height() <= 0)
        {
            entry.textEditor->setVisible(false);
            continue;
        }
        entry.textEditor->setGeometry(editorRect);
        entry.textEditor->setVisible(true);
        entry.textEditor->raise();
    }
}

void ks::ui::DetailLayoutHost::refreshEmbeddedIndicators()
{
    if (tableView_.isNull() || scheme_ != ks::settings::DetailDisplayScheme::kEmbedded)
    {
        return;
    }
    const int kRowCount = tableView_->model() != nullptr
        ? tableView_->model()->rowCount()
        : 0;
    queueEmbeddedIndicatorRows(QModelIndex(), 0, kRowCount - 1);
}

void ks::ui::DetailLayoutHost::scheduleEmbeddedIndicatorRefresh()
{
    if (indicatorRefreshScheduled_)
    {
        return;
    }
    indicatorRefreshScheduled_ = true;
    QTimer::singleShot(0, this,
        [this]()
        {
            indicatorRefreshScheduled_ = false;
            refreshEmbeddedIndicators();
        });
}

void ks::ui::DetailLayoutHost::queueEmbeddedIndicatorRows(
    const QModelIndex& parentIndex,
    const int firstRow,
    const int lastRow)
{
    if (tableView_.isNull() || tableView_->model() == nullptr || firstRow > lastRow)
    {
        return;
    }
    ++indicatorGeneration_;
    pendingIndicatorIndexes_.clear();
    const int kBoundedFirst = qMax(0, firstRow);
    const int kBoundedLast = qMin(lastRow, tableView_->model()->rowCount(parentIndex) - 1);
    for (int row = kBoundedFirst; row <= kBoundedLast; ++row)
    {
        const QModelIndex kIndex = tableView_->model()->index(row, 0, parentIndex);
        if (kIndex.isValid())
        {
            pendingIndicatorIndexes_.append(QPersistentModelIndex(kIndex));
        }
    }
    if (!indicatorBatchScheduled_)
    {
        indicatorBatchScheduled_ = true;
        const quint64 kGeneration = indicatorGeneration_;
        QTimer::singleShot(0, this, [this, kGeneration]() { processEmbeddedIndicatorBatch(kGeneration); });
    }
}

void ks::ui::DetailLayoutHost::processEmbeddedIndicatorBatch(const quint64 generation)
{
    if (generation != indicatorGeneration_ || scheme_ != ks::settings::DetailDisplayScheme::kEmbedded ||
        tableView_.isNull() || tableView_->model() == nullptr)
    {
        indicatorBatchScheduled_ = false;
        if (generation != indicatorGeneration_ && !pendingIndicatorIndexes_.isEmpty() &&
            scheme_ == ks::settings::DetailDisplayScheme::kEmbedded)
        {
            indicatorBatchScheduled_ = true;
            const quint64 kCurrentGeneration = indicatorGeneration_;
            QTimer::singleShot(0, this,
                [this, kCurrentGeneration]() { processEmbeddedIndicatorBatch(kCurrentGeneration); });
        }
        return;
    }
    int processed = 0;
    while (!pendingIndicatorIndexes_.isEmpty() && processed < 128)
    {
        const QPersistentModelIndex kIndex = pendingIndicatorIndexes_.takeLast();
        if (!kIndex.isValid())
        {
            continue;
        }
        installEmbeddedIndicator(kIndex, false);
        if (qobject_cast<QTreeWidget*>(tableView_.data()) != nullptr)
        {
            const int kChildCount = tableView_->model()->rowCount(kIndex);
            for (int child = 0; child < kChildCount; ++child)
            {
                const QModelIndex kChildIndex = tableView_->model()->index(child, 0, kIndex);
                if (kChildIndex.isValid())
                {
                    pendingIndicatorIndexes_.append(QPersistentModelIndex(kChildIndex));
                }
            }
        }
        ++processed;
    }
    if (!pendingIndicatorIndexes_.isEmpty())
    {
        QTimer::singleShot(0, this, [this, generation]() { processEmbeddedIndicatorBatch(generation); });
        return;
    }
    indicatorBatchScheduled_ = false;
    for (const EmbeddedEntry& entry : std::as_const(embeddedEntries_))
    {
        if (entry.sourceIndex.isValid())
        {
            setSourceExpandedIndicator(entry.sourceIndex, true);
        }
    }
}

void ks::ui::DetailLayoutHost::installEmbeddedIndicator(
    const QPersistentModelIndex& sourceIndex,
    const bool expanded)
{
    if (tableView_.isNull() || !sourceIndex.isValid())
    {
        return;
    }
    if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(tableView_.data()))
    {
        QTableWidgetItem* firstItem = tableWidget->item(sourceIndex.row(), 0);
        if (firstItem == nullptr)
        {
            return;
        }
        if (!firstItem->data(kOriginalDecorationCapturedRole).toBool())
        {
            firstItem->setData(kOriginalDecorationRole, firstItem->data(Qt::DecorationRole));
            firstItem->setData(kOriginalDecorationCapturedRole, true);
            indicatorIndexes_.append(sourceIndex);
        }
        firstItem->setIcon(embeddedIndicatorIcon(expanded));
    }
    else if (QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(tableView_.data()))
    {
        QTreeWidgetItem* item = treeWidget->itemFromIndex(sourceIndex);
        if (item == nullptr)
        {
            return;
        }
        if (!item->data(0, kOriginalDecorationCapturedRole).toBool())
        {
            item->setData(0, kOriginalDecorationRole, item->data(0, Qt::DecorationRole));
            item->setData(0, kOriginalDecorationCapturedRole, true);
            indicatorIndexes_.append(sourceIndex);
        }
        item->setIcon(0, embeddedIndicatorIcon(expanded));
    }
}

void ks::ui::DetailLayoutHost::restoreEmbeddedIndicators()
{
    for (const QPersistentModelIndex& sourceIndex : std::as_const(indicatorIndexes_))
    {
        if (!sourceIndex.isValid())
        {
            continue;
        }
        if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(tableView_.data()))
        {
            QTableWidgetItem* firstItem = tableWidget->item(sourceIndex.row(), 0);
            if (firstItem != nullptr && firstItem->data(kOriginalDecorationCapturedRole).toBool())
            {
                firstItem->setData(Qt::DecorationRole, firstItem->data(kOriginalDecorationRole));
                firstItem->setData(kOriginalDecorationRole, QVariant());
                firstItem->setData(kOriginalDecorationCapturedRole, false);
            }
        }
        else if (QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(tableView_.data()))
        {
            QTreeWidgetItem* item = treeWidget->itemFromIndex(sourceIndex);
            if (item != nullptr && item->data(0, kOriginalDecorationCapturedRole).toBool())
            {
                item->setData(0, Qt::DecorationRole, item->data(0, kOriginalDecorationRole));
                item->setData(0, kOriginalDecorationRole, QVariant());
                item->setData(0, kOriginalDecorationCapturedRole, false);
            }
        }
    }
    indicatorIndexes_.clear();
}

void ks::ui::DetailLayoutHost::setSourceExpandedIndicator(
    const QPersistentModelIndex& sourceIndex,
    const bool expanded)
{
    installEmbeddedIndicator(sourceIndex, expanded);
}

void ks::ui::DetailLayoutHost::showFloatingWindow()
{
    if (detailEditor_.isNull() || ownerWidget_.isNull())
    {
        return;
    }
    const bool kWindowWasVisible = !floatingWindow_.isNull() && floatingWindow_->isVisible();
    if (floatingWindow_.isNull())
    {
        QDialog* detailWindow = new QDialog(ownerWidget_.data(), Qt::Window);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, false);
        detailWindow->setModal(false);
        detailWindow->setWindowTitle(ks::i18n::text(
            QStringLiteral("detail.layout.window.title"),
            QStringLiteral("详情")));
        detailWindow->setStyleSheet(QStringLiteral(
            "QDialog{background:%1;color:%2;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex()));

        QVBoxLayout* windowLayout = new QVBoxLayout(detailWindow);
        windowLayout->setContentsMargins(8, 8, 8, 8);
        CodeEditorWidget* floatingEditor = new CodeEditorWidget(detailWindow);
        floatingEditor->setReadOnly(true);
        floatingEditor->setRawText(detailEditor_->text());
        windowLayout->addWidget(floatingEditor, 1);

        QScreen* targetScreen = ownerWidget_->screen();
        if (targetScreen == nullptr)
        {
            targetScreen = QApplication::primaryScreen();
        }
        if (targetScreen != nullptr)
        {
            const QRect kAvailableRect = targetScreen->availableGeometry();
            const QSize kInitialSize(
                std::max(320, kAvailableRect.width() / 3),
                std::max(240, kAvailableRect.height() / 3));
            detailWindow->resize(kInitialSize);
            detailWindow->move(kAvailableRect.center() - QPoint(
                kInitialSize.width() / 2,
                kInitialSize.height() / 2));
        }

        detailWindow->installEventFilter(this);
        floatingWindow_ = detailWindow;
        floatingEditor_ = floatingEditor;
    }
    else if (!floatingEditor_.isNull())
    {
        floatingEditor_->setRawText(detailEditor_->text());
    }

    // When the window is already visible, refresh only the text; do not steal focus again due to table selection changes.
    // Perform display and activation only on initial creation or when re-invoked after user closure.
    if (!kWindowWasVisible)
    {
        floatingWindow_->setWindowOpacity(1.0);
        floatingWindow_->show();
        floatingWindow_->raise();
        floatingWindow_->activateWindow();
    }
}

void ks::ui::DetailLayoutHost::destroyFloatingWindow()
{
    if (!floatingWindow_.isNull())
    {
        floatingWindow_->removeEventFilter(this);
        floatingWindow_->close();
        floatingWindow_->deleteLater();
    }
    floatingEditor_.clear();
    floatingWindow_.clear();
}

bool ks::ui::DetailLayoutHost::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    if (!tableView_.isNull() && watchedObject == tableView_->viewport() && eventObject != nullptr)
    {
        switch (eventObject->type())
        {
        case QEvent::Resize:
        case QEvent::Scroll:
        case QEvent::LayoutRequest:
            updateEmbeddedEditorGeometries();
            break;
        default:
            break;
        }
    }
    if (watchedObject == floatingWindow_.data() && eventObject != nullptr)
    {
        if (eventObject->type() == QEvent::WindowActivate)
        {
            floatingWindow_->setWindowOpacity(1.0);
        }
        else if (eventObject->type() == QEvent::WindowDeactivate)
        {
            floatingWindow_->setWindowOpacity(0.30);
        }
    }
    return QObject::eventFilter(watchedObject, eventObject);
}
