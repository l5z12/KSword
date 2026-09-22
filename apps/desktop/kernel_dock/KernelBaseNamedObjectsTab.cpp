#include "KernelBaseNamedObjectsTab.h"
#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// KernelBaseNamedObjectsTab.cpp
// Purpose:
// 1) Display the results of the BaseNamedObjects specialized aggregation;
// 2) Support filtering by Session, object type, and keywords.
// 3) Perform background read-only enumeration of the object directory without compiling, loading, or invoking drivers.
// ============================================================

#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QClipboard>
#include <QComboBox>
#include <QGuiApplication>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <set>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum class BaseNamedObjectsColumn : int
    {
        kScope = 0,
        kDirectoryPath,
        kObjectName,
        kObjectType,
        kFullPath,
        kSymbolicTarget,
        kStatus,
        kCount
    };

    QString buttonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    QString inputStyle()
    {
        return QStringLiteral("QLineEdit{background:transparent;/* %1 */color:%2;border:1px solid %3;border-radius:3px;padding:4px 6px;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            + ksword_theme::themedComboBoxStyle();
    }

    QTableWidgetItem* readOnlyItem(const QString& textValue)
    {
        auto* item = new QTableWidgetItem(textValue);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString safeCellText(const QString& textValue)
    {
        return textValue.isEmpty() ? QStringLiteral("-") : textValue;
    }

    QString sessionFilterKey(const KernelBaseNamedObjectEntry& entry)
    {
        return entry.hasSessionId
            ? QStringLiteral("session:%1").arg(entry.sessionId)
            : QStringLiteral("global");
    }

    // tableMenuStyle:
    // - Inputs: None;
    // - Processing: Generate an opaque right-click menu style to avoid black text on a black background in light themes.
    // - Returns: Style text directly passable to QMenu::setStyleSheet.
    QString tableMenuStyle()
    {
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;}"
            "QMenu::item{padding:5px 24px 5px 24px;background:transparent;}"
            "QMenu::item:selected{background:%4;color:%6;}"
            "QMenu::item:disabled{color:%5;}")
            .arg(ksword_theme::surfaceColorHex())
            .arg(ksword_theme::textPrimaryColorHex())
            .arg(ksword_theme::borderColorHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::textSecondaryColorHex())
            .arg(ksword_theme::onAccentHex());
    }

    // copyTableRow:
    // - Input table/rowIndex: target table and row index to copy;
    // - Processing: Concatenate visible columns in order and write to clipboard as TSV;
    // - Return: None; silently returns if the table is invalid or the row index is out of bounds.
    void copyTableRow(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
        {
            return;
        }
        if (rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    // installTableCopyMenu:
    // - Input: table; BaseNamedObjects result table.
    // - Processing: Install the 'Copy Current Row' context menu;
    // - Return: None; read-only copy; does not trigger any object operations.
    void installTableCopyMenu(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            const int kRowIndex = kClickedIndex.isValid() ? kClickedIndex.row() : table->currentRow();
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(tableMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                kernelText("kernel.base_named_objects.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(kRowIndex >= 0 && kRowIndex < table->rowCount());
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyTableRow(table, kRowIndex);
            }
        });
    }
}

KernelBaseNamedObjectsTab::KernelBaseNamedObjectsTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    refreshSnapshotAsync(false);
}

void KernelBaseNamedObjectsTab::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    auto* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);

    auto* titleLabel = new QLabel(QStringLiteral("BaseNamedObjects"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:16px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    toolbarLayout->addWidget(titleLabel, 0);

    refreshButton_ = new QPushButton(kernelText("kernel.base_named_objects.toolbar.refresh", QStringLiteral("刷新")), this);
    refreshButton_->setToolTip(kernelText("kernel.base_named_objects.toolbar.refresh.tooltip", QStringLiteral("重新枚举 Global 与 Session BaseNamedObjects")));
    refreshButton_->setStyleSheet(buttonStyle());
    toolbarLayout->addWidget(refreshButton_, 0);

    sessionFilterCombo_ = new QComboBox(this);
    sessionFilterCombo_->setToolTip(kernelText("kernel.base_named_objects.toolbar.session_filter.tooltip", QStringLiteral("按 Global / Session 过滤")));
    sessionFilterCombo_->setStyleSheet(inputStyle());
    toolbarLayout->addWidget(sessionFilterCombo_, 0);

    typeFilterCombo_ = new QComboBox(this);
    typeFilterCombo_->setToolTip(kernelText("kernel.base_named_objects.toolbar.type_filter.tooltip", QStringLiteral("按对象类型过滤")));
    typeFilterCombo_->setStyleSheet(inputStyle());
    toolbarLayout->addWidget(typeFilterCombo_, 0);

    keywordFilterEdit_ = new QLineEdit(this);
    keywordFilterEdit_->setPlaceholderText(kernelText("kernel.base_named_objects.toolbar.keyword_filter.placeholder", QStringLiteral("过滤 scope / 目录 / 名称 / 类型 / 目标 / 状态")));
    keywordFilterEdit_->setClearButtonEnabled(true);
    keywordFilterEdit_->setStyleSheet(inputStyle());
    toolbarLayout->addWidget(keywordFilterEdit_, 1);

    statusLabel_ = new QLabel(kernelText("kernel.base_named_objects.status.waiting", QStringLiteral("等待刷新")), this);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    toolbarLayout->addWidget(statusLabel_, 0);
    rootLayout_->addLayout(toolbarLayout, 0);

    table_ = new ks::ui::VisibleTableWidget(this);
    table_->setColumnCount(static_cast<int>(BaseNamedObjectsColumn::kCount));
    table_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("scope"),
        QStringLiteral("directoryPath"),
        QStringLiteral("objectName"),
        QStringLiteral("objectType"),
        QStringLiteral("fullPath"),
        QStringLiteral("symbolicTarget"),
        QStringLiteral("statusText")
        });
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setWordWrap(false);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(static_cast<int>(BaseNamedObjectsColumn::kFullPath), QHeaderView::Stretch);
    installTableCopyMenu(table_);
    rootLayout_->addWidget(table_, 1);
}

void KernelBaseNamedObjectsTab::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshSnapshotAsync(true);
    });
    connect(sessionFilterCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
        applyFilters();
    });
    connect(typeFilterCombo_, &QComboBox::currentIndexChanged, this, [this](int) {
        applyFilters();
    });
    connect(keywordFilterEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        applyFilters();
    });
}

void KernelBaseNamedObjectsTab::refreshSnapshotAsync(const bool forceRefresh)
{
    bool expected = false;
    if (!refreshing_.compare_exchange_strong(expected, true))
    {
        if (forceRefresh)
        {
            setStatusText(kernelText("kernel.base_named_objects.status.already_refreshing", QStringLiteral("正在刷新，请稍候。")));
        }
        return;
    }

    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }
    setStatusText(forceRefresh
        ? kernelText("kernel.base_named_objects.status.refreshing", QStringLiteral("正在刷新..."))
        : kernelText("kernel.base_named_objects.status.loading", QStringLiteral("正在加载...")));

    QPointer<KernelBaseNamedObjectsTab> safeThis(this);
    std::thread([safeThis]() {
        std::vector<KernelBaseNamedObjectEntry> rows;
        QString errorText;
        const bool kSuccess = runBaseNamedObjectsSnapshotTask(rows, errorText);

        if (safeThis.isNull())
        {
            return;
        }

        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kSuccess, rows = std::move(rows), errorText]() mutable {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->refreshing_.store(false);
                if (safeThis->refreshButton_ != nullptr)
                {
                    safeThis->refreshButton_->setEnabled(true);
                }
                if (!kSuccess)
                {
                    safeThis->setStatusText(kernelText("kernel.base_named_objects.status.refresh_failed", QStringLiteral("刷新失败：%1")).arg(errorText));
                    return;
                }
                safeThis->populateTable(rows);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelBaseNamedObjectsTab::populateTable(const std::vector<KernelBaseNamedObjectEntry>& rows)
{
    const QPointer<KernelBaseNamedObjectsTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-base-named-objects-snapshot"),
        { table_ },
        [kSafeThis, rows]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->populateTable(rows);
            }
        }))
    {
        return;
    }

    rows_ = rows;
    rebuildFilterOptions();

    if (table_ == nullptr)
    {
        return;
    }

    table_->setRowCount(static_cast<int>(rows_.size()));
    for (int rowIndex = 0; rowIndex < static_cast<int>(rows_.size()); ++rowIndex)
    {
        const KernelBaseNamedObjectEntry& entry = rows_[static_cast<std::size_t>(rowIndex)];
        auto* scopeItem = readOnlyItem(entry.scopeText);
        scopeItem->setData(Qt::UserRole, rowIndex);

        table_->setItem(rowIndex, static_cast<int>(BaseNamedObjectsColumn::kScope), scopeItem);
        table_->setItem(rowIndex, static_cast<int>(BaseNamedObjectsColumn::kDirectoryPath), readOnlyItem(entry.directoryPathText));
        table_->setItem(rowIndex, static_cast<int>(BaseNamedObjectsColumn::kObjectName), readOnlyItem(safeCellText(entry.objectNameText)));
        table_->setItem(rowIndex, static_cast<int>(BaseNamedObjectsColumn::kObjectType), readOnlyItem(safeCellText(entry.objectTypeText)));
        table_->setItem(rowIndex, static_cast<int>(BaseNamedObjectsColumn::kFullPath), readOnlyItem(safeCellText(entry.fullPathText)));
        table_->setItem(rowIndex, static_cast<int>(BaseNamedObjectsColumn::kSymbolicTarget), readOnlyItem(safeCellText(entry.symbolicTargetText)));
        table_->setItem(rowIndex, static_cast<int>(BaseNamedObjectsColumn::kStatus), readOnlyItem(safeCellText(entry.statusText)));
    }

    applyFilters();
}

void KernelBaseNamedObjectsTab::rebuildFilterOptions()
{
    if (sessionFilterCombo_ == nullptr || typeFilterCombo_ == nullptr)
    {
        return;
    }

    const QString kOldSessionKey = sessionFilterCombo_->currentData().toString();
    const QString kOldTypeText = typeFilterCombo_->currentData().toString();

    sessionFilterCombo_->blockSignals(true);
    typeFilterCombo_->blockSignals(true);
    sessionFilterCombo_->clear();
    typeFilterCombo_->clear();
    sessionFilterCombo_->addItem(kernelText("kernel.base_named_objects.filter.all_sessions", QStringLiteral("全部 Session")), QStringLiteral("*"));
    typeFilterCombo_->addItem(kernelText("kernel.base_named_objects.filter.all_types", QStringLiteral("全部类型")), QStringLiteral("*"));

    std::set<QString> sessionKeys;
    std::set<QString> typeKeys;
    for (const KernelBaseNamedObjectEntry& entry : rows_)
    {
        sessionKeys.insert(sessionFilterKey(entry));
        typeKeys.insert(entry.typeCategoryText);
    }

    for (const QString& keyText : sessionKeys)
    {
        if (keyText == QStringLiteral("global"))
        {
            sessionFilterCombo_->addItem(QStringLiteral("Global"), keyText);
        }
        else
        {
            sessionFilterCombo_->addItem(keyText.mid(QStringLiteral("session:").size()), keyText);
        }
    }
    for (const QString& typeText : typeKeys)
    {
        typeFilterCombo_->addItem(typeText, typeText);
    }

    const int kSessionIndex = sessionFilterCombo_->findData(kOldSessionKey);
    if (kSessionIndex >= 0) sessionFilterCombo_->setCurrentIndex(kSessionIndex);
    const int kTypeIndex = typeFilterCombo_->findData(kOldTypeText);
    if (kTypeIndex >= 0) typeFilterCombo_->setCurrentIndex(kTypeIndex);

    sessionFilterCombo_->blockSignals(false);
    typeFilterCombo_->blockSignals(false);
}

void KernelBaseNamedObjectsTab::applyFilters()
{
    if (table_ == nullptr)
    {
        return;
    }

    int visibleCount = 0;
    for (int rowIndex = 0; rowIndex < table_->rowCount(); ++rowIndex)
    {
        const QTableWidgetItem* scopeItem = table_->item(rowIndex, static_cast<int>(BaseNamedObjectsColumn::kScope));
        const int kSourceIndex = scopeItem != nullptr ? scopeItem->data(Qt::UserRole).toInt() : -1;
        const bool kMatches =
            kSourceIndex >= 0
            && kSourceIndex < static_cast<int>(rows_.size())
            && rowMatchesFilters(rows_[static_cast<std::size_t>(kSourceIndex)]);

        table_->setRowHidden(rowIndex, !kMatches);
        if (kMatches)
        {
            ++visibleCount;
        }
    }

    setStatusText(kernelText("kernel.base_named_objects.status.summary", QStringLiteral("共 %1 项，当前显示 %2 项"))
        .arg(rows_.size())
        .arg(visibleCount));
}

bool KernelBaseNamedObjectsTab::rowMatchesFilters(const KernelBaseNamedObjectEntry& entry) const
{
    const QString kSessionKey = sessionFilterCombo_ != nullptr
        ? sessionFilterCombo_->currentData().toString()
        : QStringLiteral("*");
    if (kSessionKey != QStringLiteral("*") && kSessionKey != sessionFilterKey(entry))
    {
        return false;
    }

    const QString kTypeKey = typeFilterCombo_ != nullptr
        ? typeFilterCombo_->currentData().toString()
        : QStringLiteral("*");
    if (kTypeKey != QStringLiteral("*") && kTypeKey.compare(entry.typeCategoryText, Qt::CaseInsensitive) != 0)
    {
        return false;
    }

    const QString kKeyword = keywordFilterEdit_ != nullptr
        ? keywordFilterEdit_->text().trimmed()
        : QString();
    if (kKeyword.isEmpty())
    {
        return true;
    }

    return entry.scopeText.contains(kKeyword, Qt::CaseInsensitive)
        || entry.directoryPathText.contains(kKeyword, Qt::CaseInsensitive)
        || entry.objectNameText.contains(kKeyword, Qt::CaseInsensitive)
        || entry.objectTypeText.contains(kKeyword, Qt::CaseInsensitive)
        || entry.typeCategoryText.contains(kKeyword, Qt::CaseInsensitive)
        || entry.fullPathText.contains(kKeyword, Qt::CaseInsensitive)
        || entry.symbolicTargetText.contains(kKeyword, Qt::CaseInsensitive)
        || entry.statusText.contains(kKeyword, Qt::CaseInsensitive);
}

void KernelBaseNamedObjectsTab::setStatusText(const QString& statusText)
{
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(statusText);
    }
}
