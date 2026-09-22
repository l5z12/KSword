#include "LogDockWidget.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"
#include "../ui/FlatTableModel.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

#include <QAction>
#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QApplication>
#include <QBrush>
#include <QCheckBox>
#include <QClipboard>
#include <QHash>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QStyledItemDelegate>
#include <QStyle>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPen>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QScrollBar>
#include <QSize>
#include <QSpinBox>
#include <QStringList>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <QSvgRenderer>

// On Windows, prefer using the native shell save dialog (to satisfy the explorer scenario requirement).
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <commdlg.h>
#pragma comment(lib, "Comdlg32.lib")
#endif

namespace
{
    using LogTableModel = ks::ui::FlatTableModel<KEvent>;

    // Table column constants: ensure consistent semantic references throughout the code.
    constexpr int kLevelColumn = 0;      // Level column (colored squares only, title left blank).
    constexpr int kTimeColumn = 1;       // Time column.
    constexpr int kContentColumn = 2;    // Content column.
    constexpr int kFileColumn = 3;       // File column.
    constexpr int kFunctionColumn = 4;   // Function column.
    constexpr int kTotalColumns = 5;     // Total columns.

    // Unified resource path constant to avoid scattered hardcoding.
    constexpr const char* kIconExportPath = ":/Icon/log_export.svg";
    constexpr const char* kIconClearPath = ":/Icon/log_clear.svg";
    constexpr const char* kIconCopyPath = ":/Icon/log_copy.svg";
    constexpr const char* kIconClipboardPath = ":/Icon/log_clipboard.svg";
    constexpr const char* kIconTrackPath = ":/Icon/log_track.svg";
    constexpr const char* kIconCancelTrackPath = ":/Icon/log_cancel_track.svg";

    // LogContentWrapDelegate：
    // - Input: Log table model index and default paint option;
    // Processing: Allow line wrapping only for long-text columns (Content, File, Function); keep Time and Level columns single-line.
    // - Returns: Affects view rendering via sizeHint/paint without modifying model data.
    class LogContentWrapDelegate final : public QStyledItemDelegate
    {
    public:
        explicit LogContentWrapDelegate(QTableView* tableView)
            : QStyledItemDelegate(tableView)
            , tableView_(tableView)
        {
        }

        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QStyleOptionViewItem adjustedOption(option);
            const bool kRowSelected = (adjustedOption.state & QStyle::State_Selected) != 0;
            initStyleOption(&adjustedOption, index);
            adjustedOption.textElideMode = isWrappingColumn(index.column()) ? Qt::ElideNone : Qt::ElideRight;
            adjustedOption.features.setFlag(QStyleOptionViewItem::WrapText, isWrappingColumn(index.column()));
            adjustedOption.state &= ~QStyle::State_Selected;
            adjustedOption.state &= ~QStyle::State_HasFocus;
            QStyledItemDelegate::paint(painter, adjustedOption, index);
            if (kRowSelected)
            {
                drawRowSelectionOutline(painter, option, index);
            }
        }

        QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            if (!isWrappingColumn(index.column()))
            {
                QSize baseSize = QStyledItemDelegate::sizeHint(option, index);
                baseSize.setHeight(24);
                return baseSize;
            }

            QStyleOptionViewItem adjustedOption(option);
            initStyleOption(&adjustedOption, index);
            adjustedOption.textElideMode = Qt::ElideNone;
            adjustedOption.features.setFlag(QStyleOptionViewItem::WrapText, true);
            QSize baseSize = QStyledItemDelegate::sizeHint(adjustedOption, index);
            baseSize.setHeight(std::clamp(baseSize.height(), 24, 120));
            return baseSize;
        }

    private:
        void drawRowSelectionOutline(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const
        {
            if (painter == nullptr || tableView_ == nullptr || !index.isValid())
            {
                return;
            }

            QHeaderView* headerView = tableView_->horizontalHeader();
            const QAbstractItemModel* model = index.model();
            if (headerView == nullptr || model == nullptr)
            {
                return;
            }

            int firstVisibleVisualIndex = std::numeric_limits<int>::max();
            int lastVisibleVisualIndex = std::numeric_limits<int>::min();
            const int kColumnCount = model->columnCount(index.parent());
            for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
            {
                if (tableView_->isColumnHidden(columnIndex))
                {
                    continue;
                }

                const int kVisualIndex = headerView->visualIndex(columnIndex);
                if (kVisualIndex < 0)
                {
                    continue;
                }
                firstVisibleVisualIndex = std::min(firstVisibleVisualIndex, kVisualIndex);
                lastVisibleVisualIndex = std::max(lastVisibleVisualIndex, kVisualIndex);
            }

            const int kCurrentVisualIndex = headerView->visualIndex(index.column());
            if (kCurrentVisualIndex < 0 ||
                firstVisibleVisualIndex == std::numeric_limits<int>::max() ||
                lastVisibleVisualIndex == std::numeric_limits<int>::min())
            {
                return;
            }

            const QRect kBorderRect = option.rect.adjusted(0, 1, -1, -2);
            if (!kBorderRect.isValid())
            {
                return;
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, false);
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(ksword_theme::primaryBlueColor, 3.0));
            painter->drawLine(kBorderRect.topLeft(), kBorderRect.topRight());
            painter->drawLine(kBorderRect.bottomLeft(), kBorderRect.bottomRight());
            if (kCurrentVisualIndex == firstVisibleVisualIndex)
            {
                painter->drawLine(kBorderRect.topLeft(), kBorderRect.bottomLeft());
            }
            if (kCurrentVisualIndex == lastVisibleVisualIndex)
            {
                painter->drawLine(kBorderRect.topRight(), kBorderRect.bottomRight());
            }
            painter->restore();
        }

        static bool isWrappingColumn(const int column)
        {
            return column == kContentColumn || column == kFileColumn || column == kFunctionColumn;
        }

        QPointer<QTableView> tableView_;
    };

    // DefaultButtonIconSize: Default size for log panel buttons and menu icons.
    constexpr QSize kDefaultButtonIconSize(16, 16);
    constexpr int kActionButtonExtent = 28; // ActionButtonExtent: Side length of top icon buttons (pixels).
    constexpr int kDefaultVisibleLogLimit = 200;  // By default, render only the most recent 200 log entries to the UI to reduce Dock refresh pressure.
    constexpr int kMinVisibleLogLimit = 1;        // Allow a minimum of 1 visible log entry to prevent the 'count' control from having an unintuitive hidden lower bound.
    constexpr int kMaxVisibleLogLimit = 10000;    // Retain diagnostic flexibility with the maximum value while preventing extreme row counts from crashing table rendering.

    // logRowKey:
    // - Convert the monotonically increasing sequence number allocated by the log manager into a stable row key required by FlatTableModel;
    // - Let new logs trigger insert/remove/layout changes instead of beginResetModel/endResetModel.
    // Parameter logItem: a log record that has been archived and includes a unique recordSequence.
    // Return value: The global unique string key for this log entry.
    std::string logRowKey(const KEvent& logItem)
    {
        return std::to_string(logItem.recordSequence);
    }

    // createBlueThemedIcon:
    // - Recolor monochrome SVG icons from qrc to the theme blue.
    // - Avoid modifying original SVG files to implement runtime color swapping.
    // Parameter resourcePath: qrc resource path (e.g., :/Icon/log_copy.svg).
    // Parameter iconSize: Output icon size.
    // Returns: recolored QIcon; falls back to the original icon if rendering fails.
    QIcon createBlueThemedIcon(const char* resourcePath, const QSize& iconSize = kDefaultButtonIconSize)
    {
        const QString kIconPath = QString::fromUtf8(resourcePath);

        // Use the Qt SVG renderer to draw vector graphics onto a transparent pixel buffer.
        QSvgRenderer svgRenderer(kIconPath);
        if (!svgRenderer.isValid())
        {
            // Fall back to the default icon when resources are abnormal to avoid functionality becoming invisible.
            return QIcon(kIconPath);
        }

        QPixmap tintedPixmap(iconSize);
        tintedPixmap.fill(Qt::transparent);

        // First, render the original SVG; second, use SourceIn to uniformly tint non-transparent pixels to the theme blue.
        QPainter painter(&tintedPixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        svgRenderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(tintedPixmap.rect(), ksword_theme::primaryBlueColor);
        painter.end();

        return QIcon(tintedPixmap);
    }

    // buildBlueCheckBoxStyleSheet:
    // - Generate a unified blue checkbox style for the log panel (text, border, and selected state).
    // Return value: QSS string.
    QString buildBlueCheckBoxStyleSheet()
    {
        return QStringLiteral(
            "QCheckBox {"
            "  color: %1;"
            "  spacing: 6px;"
            "}")
            .arg(ksword_theme::textPrimaryHex());
    }

    // buildBlueButtonStyleSheet:
    // - Generate a transparent background style for the log panel icon button;
    // - Default background is transparent; apply lightweight highlighting only on hover/pressed.
    // Return value: QSS string.
    QString buildBlueButtonStyleSheet()
    {
        return QStringLiteral(
            "QPushButton {"
            "  color: %1;"
            "  background: transparent;"
            "  border: 1px solid transparent;"
            "  border-radius: 4px;"
            "  padding: 4px;"
            "}"
            "QPushButton:hover {"
            "  background: %2;"
            "  border: 1px solid %3;"
            "}"
            "QPushButton:pressed {"
            "  background: %4;"
            "  border: 1px solid %5;"
            "}")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::rgbaColorName(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue), 28))
            .arg(ksword_theme::rgbaColorName(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue), 96))
            .arg(ksword_theme::rgbaColorName(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue), 46))
            .arg(ksword_theme::rgbaColorName(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue), 136));
    }

    // buildBlueHeaderStyleSheet:
    // - Set the log table header text to the theme blue color.
    // Return value: QHeaderView section style string.
    QString buildBlueHeaderStyleSheet()
    {
        return QStringLiteral(
            "QHeaderView::section {"
            "  color: %1;"
            "  background: transparent; /* %2 */"
            "  border: 1px solid %3;"
            "  padding: 4px;"
            "  font-weight: 600;"
            "}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // buildBlueInputStyleSheet:
    // - Generate theme styles for numeric input fields and labels in the log toolbar.
    // - Explicitly specify background, foreground, and hover/focus borders to prevent inheriting light-colored white blocks in dark mode.
    // - Return value: a QSS string directly applicable to QSpinBox/QLabel.
    QString buildBlueInputStyleSheet()
    {
        return QStringLiteral(
            "QSpinBox {"
            "  color: %3;"
            "  background: %2;"
            "  border: 1px solid %1;"
            "  border-radius: 3px;"
            "  padding: 2px 6px;"
            "}"
            "QSpinBox:hover, QSpinBox:focus {"
            "  border: 1px solid %4;"
            "}"
            // Do not override the step button here: the global baseline already provides a complete implementation with arrows and hover/limit
            // feedback. Making it locally transparent and borderless would only degrade it to a state where it is indistinguishable as a button.
            "QLabel {"
            "  color: %3;"
            "}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }
}

LogDockWidget::LogDockWidget(QWidget* parent)
    : QWidget(parent)
{
    // Construction phase initializes in the order: 'UI -> Signals -> Refresh Timer' for easier maintenance.
    initializeUi();
    initializeConnections();
    initializeRefreshTimer();

    // Force a refresh before the first display to ensure logs are visible immediately upon opening the Dock.
    refreshTableFromManager(true);
}

void LogDockWidget::refreshNow()
{
    refreshTableFromManager(true);
}

void LogDockWidget::initializeUi()
{
    // Root layout: two rows arranged vertically (single-line toolbar + table).
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(0, 0, 0, 0);
    rootLayout_->setSpacing(4);

    // Single-line toolbar:
    // - Place the three action buttons and all filter/status checkboxes on the same row;
    // - Satisfy the layout requirement that all checkboxes and buttons are stacked on a single line.
    actionLayout_ = new QHBoxLayout();
    actionLayout_->setContentsMargins(6, 6, 6, 4);
    actionLayout_->setSpacing(6);

    exportButton_ = new QPushButton(createBlueThemedIcon(kIconExportPath), QString(), this);
    clearButton_ = new QPushButton(createBlueThemedIcon(kIconClearPath), QString(), this);
    copyVisibleButton_ = new QPushButton(createBlueThemedIcon(kIconCopyPath), QString(), this);
    debugCheck_ = new QCheckBox("Debug", this);
    infoCheck_ = new QCheckBox("Info", this);
    warnCheck_ = new QCheckBox("Warn", this);
    errorCheck_ = new QCheckBox("Error", this);
    fatalCheck_ = new QCheckBox("Fatal", this);
    detailCheck_ = new QCheckBox("详细信息", this);
    autoScrollCheck_ = new QCheckBox("保持滚动到最底端", this);
    visibleLimitSpin_ = new QSpinBox(this);

    // Number of recent log entries:
    // - Only limit the number of rows actually rendered in QTableView to prevent the GUI from freezing due to thousands of rows during a log storm;
    // - Do not truncate internal history of KswordARKEventEntry; therefore, changing the limit from 200 to 1000 will immediately fill in missing entries from the old logs.
    visibleLimitSpin_->setRange(kMinVisibleLogLimit, kMaxVisibleLogLimit);
    visibleLimitSpin_->setSingleStep(100);
    visibleLimitSpin_->setValue(kDefaultVisibleLogLimit);
    visibleLimitSpin_->setSuffix(QStringLiteral(" 条"));
    visibleLimitSpin_->setKeyboardTracking(false);
    visibleLimitSpin_->setMaximumWidth(96);

    // Buttons are configured with icons and tooltips to adhere to the principle of using icons with hover descriptions for functionality.
    exportButton_->setToolTip("导出全部日志到 .txt 文件");
    clearButton_->setToolTip("清空日志管理器中的全部日志（双重确认）");
    copyVisibleButton_->setToolTip("复制当前可见列表内容（支持追踪过滤状态）");
    detailCheck_->setToolTip("显示文件列和函数列");
    autoScrollCheck_->setToolTip("开启后表格刷新将自动滚动到最后一行");
    visibleLimitSpin_->setToolTip("限制界面显示的最近日志条数；提高上限可显示更早记录。");

    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    languageManager.bindText(debugCheck_, QStringLiteral("log.level.debug"), QStringLiteral("Debug"));
    languageManager.bindText(infoCheck_, QStringLiteral("log.level.info"), QStringLiteral("Info"));
    languageManager.bindText(warnCheck_, QStringLiteral("log.level.warn"), QStringLiteral("Warn"));
    languageManager.bindText(errorCheck_, QStringLiteral("log.level.error"), QStringLiteral("Error"));
    languageManager.bindText(fatalCheck_, QStringLiteral("log.level.fatal"), QStringLiteral("Fatal"));
    languageManager.bindText(detailCheck_, QStringLiteral("log.detail"), QStringLiteral("详细信息"));
    languageManager.bindText(autoScrollCheck_, QStringLiteral("log.autoscroll"), QStringLiteral("保持滚动到最底端"));
    languageManager.bindSuffix(
        visibleLimitSpin_,
        QStringLiteral("log.suffix.entries"),
        QStringLiteral(" 条"));
    languageManager.bindToolTip(exportButton_, QStringLiteral("log.tooltip.export"), QStringLiteral("导出全部日志到 .txt 文件"));
    languageManager.bindToolTip(clearButton_, QStringLiteral("log.tooltip.clear"), QStringLiteral("清空日志管理器中的全部日志（双重确认）"));
    languageManager.bindToolTip(copyVisibleButton_, QStringLiteral("log.tooltip.copy_visible"), QStringLiteral("复制当前可见列表内容（支持追踪过滤状态）"));
    languageManager.bindToolTip(detailCheck_, QStringLiteral("log.tooltip.detail"), QStringLiteral("显示文件列和函数列"));
    languageManager.bindToolTip(autoScrollCheck_, QStringLiteral("log.tooltip.autoscroll"), QStringLiteral("开启后表格刷新将自动滚动到最后一行"));
    languageManager.bindToolTip(visibleLimitSpin_, QStringLiteral("log.tooltip.visible_limit"), QStringLiteral("限制界面显示的最近日志条数；提高上限可显示更早记录。"));

    // Icon sizes match button sizes to ensure a compact toolbar appearance while maintaining a pure icon style.
    exportButton_->setIconSize(kDefaultButtonIconSize);
    clearButton_->setIconSize(kDefaultButtonIconSize);
    copyVisibleButton_->setIconSize(kDefaultButtonIconSize);
    exportButton_->setFixedSize(kActionButtonExtent, kActionButtonExtent);
    clearButton_->setFixedSize(kActionButtonExtent, kActionButtonExtent);
    copyVisibleButton_->setFixedSize(kActionButtonExtent, kActionButtonExtent);
    exportButton_->setCursor(Qt::PointingHandCursor);
    clearButton_->setCursor(Qt::PointingHandCursor);
    copyVisibleButton_->setCursor(Qt::PointingHandCursor);
    autoScrollCheck_->setChecked(true);

    // Set the log area buttons' background to transparent, keeping only icons and hover feedback.
    const QString kBlueButtonStyle = buildBlueButtonStyleSheet();
    exportButton_->setStyleSheet(kBlueButtonStyle);
    clearButton_->setStyleSheet(kBlueButtonStyle);
    copyVisibleButton_->setStyleSheet(kBlueButtonStyle);

    // Unify checkbox text and indicator to the same blue as the welcome page.
    const QString kBlueCheckBoxStyle = buildBlueCheckBoxStyleSheet();
    debugCheck_->setStyleSheet(kBlueCheckBoxStyle);
    infoCheck_->setStyleSheet(kBlueCheckBoxStyle);
    warnCheck_->setStyleSheet(kBlueCheckBoxStyle);
    errorCheck_->setStyleSheet(kBlueCheckBoxStyle);
    fatalCheck_->setStyleSheet(kBlueCheckBoxStyle);
    detailCheck_->setStyleSheet(kBlueCheckBoxStyle);
    autoScrollCheck_->setStyleSheet(kBlueCheckBoxStyle);
    visibleLimitSpin_->setStyleSheet(buildBlueInputStyleSheet());

    // Debug is disabled by default to prevent the log output Dock from being flooded with debug-level noise upon its first opening.
    debugCheck_->setChecked(false);
    infoCheck_->setChecked(true);
    warnCheck_->setChecked(true);
    errorCheck_->setChecked(true);
    fatalCheck_->setChecked(true);
    actionLayout_->addWidget(exportButton_);
    actionLayout_->addWidget(clearButton_);
    actionLayout_->addWidget(copyVisibleButton_);
    actionLayout_->addSpacing(8);
    actionLayout_->addWidget(debugCheck_);
    actionLayout_->addWidget(infoCheck_);
    actionLayout_->addWidget(warnCheck_);
    actionLayout_->addWidget(errorCheck_);
    actionLayout_->addWidget(fatalCheck_);
    actionLayout_->addWidget(detailCheck_);
    actionLayout_->addWidget(autoScrollCheck_);
    actionLayout_->addSpacing(8);

    QLabel* visibleLimitLabel = new QLabel(QStringLiteral("展示最近日志条数:"), this);
    languageManager.bindText(visibleLimitLabel, QStringLiteral("log.label.visible_limit"), QStringLiteral("展示最近日志条数:"));
    visibleLimitLabel->setToolTip(visibleLimitSpin_->toolTip());
    visibleLimitLabel->setStyleSheet(buildBlueInputStyleSheet());
    actionLayout_->addWidget(visibleLimitLabel);
    actionLayout_->addWidget(visibleLimitSpin_);
    actionLayout_->addStretch(1);

    // Phase 3: Log table, required to be non-editable and fill the entire Dock.
    // Selection policy:
    // - SelectRows ensures that clicking any cell selects the entire row;
    // - ExtendedSelection supports Ctrl+click to add multiple rows to the selection;
    // - Subsequent right-click menus will restrict actions to 'Copy' based on the multi-selection state.
    // Performance policy:
    // - QTableView is responsible only for visualization;
    // - FlatTableModel stores the currently visible kEvent snapshot and returns cell data on demand;
    // - Avoids creating and destroying QTableWidgetItem objects for every row * column during each refresh.
    std::vector<LogTableModel::ColumnSpec> logColumns;
    logColumns.reserve(kTotalColumns);
    logColumns.push_back({ QString(), Qt::AlignCenter });
    logColumns.push_back({ QStringLiteral("时间"), Qt::AlignCenter });
    logColumns.push_back({ QStringLiteral("内容"), Qt::AlignLeft | Qt::AlignVCenter });
    logColumns.push_back({ QStringLiteral("文件"), Qt::AlignLeft | Qt::AlignVCenter });
    logColumns.push_back({ QStringLiteral("函数"), Qt::AlignLeft | Qt::AlignVCenter });

    logModel_ = new LogTableModel(
        std::move(logColumns),
        [this](const KEvent& logItem, const int column, const int role) {
            return resolveLogTableData(logItem, column, role);
        },
        this,
        LogTableModel::FlagsResolver(),
        logRowKey);

    logTable_ = new ks::ui::TableActionTableView(this);
    logTable_->setModel(logModel_);
    logTable_->setItemDelegate(new LogContentWrapDelegate(logTable_));
    logTable_->setProperty("ksword_preserve_custom_table_delegate", true);
    logTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    logTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    logTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    logTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    logTable_->setWordWrap(true);
    logTable_->setShowGrid(true);
    logTable_->setAlternatingRowColors(false);
    logTable_->setSortingEnabled(false);
    logTable_->setTextElideMode(Qt::ElideNone);

    // Table header policy: Level column has fixed width; other columns are interactive and draggable.
    QHeaderView* horizontalHeader = logTable_->horizontalHeader();
    horizontalHeader->setSectionResizeMode(kLevelColumn, QHeaderView::Fixed);
    horizontalHeader->setSectionResizeMode(kTimeColumn, QHeaderView::Interactive);
    horizontalHeader->setSectionResizeMode(kContentColumn, QHeaderView::Stretch);
    horizontalHeader->setSectionResizeMode(kFileColumn, QHeaderView::Interactive);
    horizontalHeader->setSectionResizeMode(kFunctionColumn, QHeaderView::Interactive);
    horizontalHeader->setStretchLastSection(false);
    horizontalHeader->setStyleSheet(buildBlueHeaderStyleSheet());
    horizontalHeader->setVisible(false);

    // The Level column only accommodates colored squares, so the narrow column width is locked.
    logTable_->setColumnWidth(kLevelColumn, 24);
    logTable_->setColumnWidth(kTimeColumn, 170);
    logTable_->setColumnWidth(kContentColumn, 320);
    logTable_->setColumnWidth(kFileColumn, 240);
    logTable_->setColumnWidth(kFunctionColumn, 320);
    logTable_->verticalHeader()->setVisible(false);
    logTable_->verticalHeader()->setDefaultSectionSize(28);
    logTable_->verticalHeader()->setMinimumSectionSize(24);
    logTable_->verticalHeader()->setMaximumSectionSize(120);
    // Long logs measure variable row heights only within the current viewport; re-measure newly visible rows on demand after scrolling.
    // The model still holds the full log snapshot; filtering/copying and other full-set logic remain unaffected.
    ks::ui::installVisibleRowHeightRefresh(logTable_);

    // Details mode is disabled by default; only level, time, and content are shown.
    applyDetailColumnVisibility();

    // Finally assemble the two layout layers.
    rootLayout_->addLayout(actionLayout_);
    rootLayout_->addWidget(logTable_, 1);
}

void LogDockWidget::initializeConnections()
{
    // Button action connections: export, clear, copy visible.
    connect(exportButton_, &QPushButton::clicked, this, [this]() { exportAllLogs(); });
    connect(clearButton_, &QPushButton::clicked, this, [this]() { clearAllLogsWithDoubleConfirm(); });
    connect(copyVisibleButton_, &QPushButton::clicked, this, [this]() { copyVisibleRows(); });

    // The detail visibility toggle only changes column visibility; no full table rebuild is needed.
    connect(detailCheck_, &QCheckBox::toggled, this, [this]() { applyDetailColumnVisibility(); });

    // Force refresh the table whenever any of the five-level checkboxes change.
    connect(debugCheck_, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(infoCheck_, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(warnCheck_, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(errorCheck_, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(fatalCheck_, &QCheckBox::toggled, this, [this]() { refreshTableFromManager(true); });
    connect(visibleLimitSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](const int) {
        // When the user increases the display count, old logs must be immediately supplemented from the internal full history.
        // Therefore, force a refresh here and rebuild the visible snapshot even if the log revision has not changed.
        refreshTableFromManager(true);
    });

    // Right-click menu connection.
    connect(logTable_, &QWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showTableContextMenu(position);
    });
}

void LogDockWidget::applyDetailColumnVisibility()
{
    if (logTable_ == nullptr)
    {
        return;
    }

    // detailVisible usage: Records the current state of the 'Details' toggle to determine if additional columns are visible.
    const bool kDetailVisible = (detailCheck_ != nullptr) && detailCheck_->isChecked();
    logTable_->setColumnHidden(kFileColumn, !kDetailVisible);
    logTable_->setColumnHidden(kFunctionColumn, !kDetailVisible);
}

void LogDockWidget::initializeRefreshTimer()
{
    // 250ms refresh interval: trade-off between real-time performance and efficiency.
    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(250);

    // Non-forced refresh: rebuild the UI only when the revision changes.
    connect(refreshTimer_, &QTimer::timeout, this, [this]() {
        refreshTableFromManager(false);
    });
    refreshTimer_->start();
}

void LogDockWidget::refreshTableFromManager(const bool forceRefresh)
{
    // When the right-click menu is executing within a nested event loop, resetting the model invalidates the row numbers recorded in the menu.
    // Only the latest refresh of the same type is retained; re-injecting after the menu closes ensures copy/trace operations still target the log row at the time of the right-click.
    const QPointer<LogDockWidget> kSafeThis(this);
    const QString kRefreshCommitKey = forceRefresh
        ? QStringLiteral("log-table-force-refresh")
        : QStringLiteral("log-table-periodic-refresh");
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        kRefreshCommitKey,
        { logTable_ },
        [kSafeThis, forceRefresh]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->refreshTableFromManager(forceRefresh);
            }
        }))
    {
        return;
    }

    const std::size_t kCurrentRevision = kswordArkEventEntry.revision();
    if (!forceRefresh && kCurrentRevision == lastRevision_)
    {
        return;
    }
    lastRevision_ = kCurrentRevision;

    // Read 'last N matching logs' from the global log manager instead of a full snapshot:
    // - KswordARKEventEntry internally retains the full history; export and clear behaviors remain unchanged.
    // - The UI retrieves only the most recent visibleLogLimit() entries filtered by the current level/GUID to prevent the table model and row height calculations from being overwhelmed by massive logs.
    // - When the user increases the threshold from 200 to 1000, this re-scans the internal history and immediately fills in previously recorded logs.
    std::uint32_t enabledLevelMask = 0;
    for (const KLogLevel kLevel : {
        KLogLevel::kDebug,
        KLogLevel::kInfo,
        KLogLevel::kWarn,
        KLogLevel::kError,
        KLogLevel::kFatal })
    {
        if (isLevelEnabledByCheckbox(kLevel))
        {
            enabledLevelMask |= (std::uint32_t{ 1 } << static_cast<unsigned int>(kLevel));
        }
    }

    // filteredEvents are then held by the model; copy and tracking logic reads the model snapshot via visibleEvents()/visibleEventAt().
    std::vector<KEvent> filteredEvents = kswordArkEventEntry.snapshotRecent(
        static_cast<std::size_t>(visibleLogLimit()),
        enabledLevelMask,
        isTracking_ ? &trackingGuid_ : nullptr);
    rebuildTable(std::move(filteredEvents));
}

void LogDockWidget::rebuildTable(std::vector<KEvent> filteredEvents)
{
    if (logTable_ == nullptr || logModel_ == nullptr)
    {
        return;
    }

    // If auto-scroll is disabled, save the scroll bar position first and restore it after refresh.
    const int kPreviousScrollValue = logTable_->verticalScrollBar()->value();

    // Each archived log has a unique sequence number, so setRows publishes incremental insertions/deletions and layout adjustments by key.
    // Qt preserves selection, current index, and persistent indices for visible rows automatically upon model signals, eliminating the need to manually reverse-lookup by content.
    logModel_->setRows(std::move(filteredEvents));
    ks::ui::refreshVisibleRowHeights(logTable_);

    // Determine scroll behavior after refresh based on the 'Keep Scrolled to Bottom' switch.
    if (autoScrollCheck_->isChecked())
    {
        logTable_->scrollToBottom();
    }
    else
    {
        logTable_->verticalScrollBar()->setValue(kPreviousScrollValue);
    }
}

int LogDockWidget::visibleLogLimit() const
{
    // The spin box may be null during early UI construction or in unit test environments; fall back to the default value in that case.
    // Return value is used only to limit the number of items rendered in the UI and does not participate in internal storage trimming of KswordARKEventEntry.
    if (visibleLimitSpin_ == nullptr)
    {
        return kDefaultVisibleLogLimit;
    }

    return std::clamp(visibleLimitSpin_->value(), kMinVisibleLogLimit, kMaxVisibleLogLimit);
}

QVariant LogDockWidget::resolveLogTableData(const KEvent& logItem, const int column, const int role) const
{
    // DecorationRole is used only for the Level column: the UI retains the original 'colored square' style.
    if (role == Qt::DecorationRole && column == kLevelColumn)
    {
        return makeLevelSquareIcon(getLevelColor(logItem.level));
    }

    // Row coloring for Error/Fatal has migrated from QTableWidgetItem properties to model roles.
    if (role == Qt::BackgroundRole || role == Qt::ForegroundRole)
    {
        return getRowHighlightBrush(logItem, role);
    }

    // Preserve original behavior for Qt::ToolTipRole: the Level column shows text descriptions, while the Long Text column shows full content hints.
    if (role == Qt::ToolTipRole)
    {
        switch (column)
        {
        case kLevelColumn:
            return getLevelText(logItem.level);
        case kContentColumn:
            return QString::fromStdString(logItem.content);
        case kFileColumn:
            return QString::fromStdString(logItem.fileLocation);
        case kFunctionColumn:
            return QString::fromStdString(logItem.functionName);
        default:
            return {};
        }
    }

    if (role != Qt::DisplayRole)
    {
        return {};
    }

    // DisplayRole returns only the text actually displayed in the UI; the Level column appears visually empty.
    switch (column)
    {
    case kLevelColumn:
        return QString();
    case kTimeColumn:
        return QString::fromStdString(formatTimeToString(logItem.timestamp));
    case kContentColumn:
        return QString::fromStdString(logItem.content);
    case kFileColumn:
        return QString::fromStdString(logItem.fileLocation);
    case kFunctionColumn:
        return QString::fromStdString(logItem.functionName);
    default:
        return {};
    }
}

QVariant LogDockWidget::getRowHighlightBrush(const KEvent& logItem, const int role) const
{
    if (role != Qt::BackgroundRole && role != Qt::ForegroundRole)
    {
        return {};
    }

    // By default, do not change the row color; only Error/Fatal levels receive special coloring.
    if (logItem.level == KLogLevel::kFatal)
    {
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(ksword_theme::blackColor()))
            : QVariant(QBrush(ksword_theme::whiteColor()));
    }

    if (logItem.level == KLogLevel::kError)
    {
        const QColor kRowBackground = ksword_theme::errorBackgroundColor();
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(kRowBackground))
            : QVariant(QBrush(ksword_theme::onAccentColor()));
    }

    return {};
}

QIcon LogDockWidget::makeLevelSquareIcon(const QColor& color) const
{
    // DecorationRole may be requested multiple times during Model/View rendering.
    // Cache small icons using the final RGBA color as the key to avoid reallocating QPixmap and running QPainter on every paint.
    static QHash<QRgb, QIcon> levelIconCache;
    const QRgb kCacheKey = color.rgba();
    const auto kCachedIcon = levelIconCache.constFind(kCacheKey);
    if (kCachedIcon != levelIconCache.constEnd())
    {
        return kCachedIcon.value();
    }

    // Use QPainter to draw a solid-color small square on a transparent background.
    QPixmap squarePixmap(12, 12);
    squarePixmap.fill(Qt::transparent);

    QPainter painter(&squarePixmap);
    painter.setRenderHint(QPainter::Antialiasing, true);
    painter.setPen(Qt::NoPen);
    painter.setBrush(color);
    painter.drawRect(1, 1, 10, 10);

    const QIcon kSquareIcon(squarePixmap);
    levelIconCache.insert(kCacheKey, kSquareIcon);
    return kSquareIcon;
}

QColor LogDockWidget::getLevelColor(const KLogLevel level) const
{
    switch (level)
    {
    case KLogLevel::kDebug:
        return ksword_theme::accentColor(ksword_theme::AccentRole::kBlue, -12, -38);
    case KLogLevel::kInfo:
        return ksword_theme::successColor();
    case KLogLevel::kWarn:
        return ksword_theme::warningColor();
    case KLogLevel::kError:
        return ksword_theme::errorColor();
    case KLogLevel::kFatal:
        return ksword_theme::accentTextColor(ksword_theme::AccentRole::kRed, ksword_theme::blackColor());
    default:
        return ksword_theme::textDisabledColor();
    }
}

QString LogDockWidget::getLevelText(const KLogLevel level) const
{
    return QString::fromStdString(logLevelToString(level));
}

bool LogDockWidget::isLevelEnabledByCheckbox(const KLogLevel level) const
{
    switch (level)
    {
    case KLogLevel::kDebug:
        return debugCheck_->isChecked();
    case KLogLevel::kInfo:
        return infoCheck_->isChecked();
    case KLogLevel::kWarn:
        return warnCheck_->isChecked();
    case KLogLevel::kError:
        return errorCheck_->isChecked();
    case KLogLevel::kFatal:
        return fatalCheck_->isChecked();
    default:
        return true;
    }
}

void LogDockWidget::showTableContextMenu(const QPoint& position)
{
    if (logTable_ == nullptr)
    {
        return;
    }

    // Locate row and column via right-click position; if the point is in a blank area, row/column is -1.
    int row = -1;
    int column = -1;
    const QModelIndex kClickedIndex = logTable_->indexAt(position);
    if (kClickedIndex.isValid())
    {
        row = kClickedIndex.row();
        column = kClickedIndex.column();
    }

    // selectedRowIndexes: Records the rows already selected in the table before the right-click popup.
    // If the user Ctrl+clicked to select multiple rows, the right-click menu must only retain 'Copy'.
    std::vector<int> selectedRowIndexes = collectSelectedRowIndexes();
    const bool kClickedRowIsSelected =
        std::find(selectedRowIndexes.cbegin(), selectedRowIndexes.cend(), row) != selectedRowIndexes.cend();

    // When right-clicking an unselected row, switch to that single row following common table behavior.
    // This prevents a standard right-click from accidentally operating on rows left selected by Ctrl-multi-selection.
    const bool kHasValidCell = row >= 0 && column >= 0 && visibleEventAt(row) != nullptr;
    if (kHasValidCell && !kClickedRowIsSelected)
    {
        logTable_->clearSelection();
        logTable_->selectRow(row);
        selectedRowIndexes.clear();
        selectedRowIndexes.push_back(row);
    }

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());

    // Multi-row selection scenario:
    // - The menu only shows 'Copy';
    // - The copy range is fixed to all selected rows to avoid ambiguity caused by tracking or cell duplication.
    if (selectedRowIndexes.size() > 1)
    {
        QAction* copySelectedRowsAction = contextMenu.addAction(
            createBlueThemedIcon(kIconCopyPath),
            ks::i18n::contextText(QStringLiteral("log.menu.copy"), QStringLiteral("复制")));
        copySelectedRowsAction->setEnabled(!selectedRowIndexes.empty());

        QAction* selectedAction = contextMenu.exec(logTable_->viewport()->mapToGlobal(position));
        if (selectedAction == copySelectedRowsAction)
        {
            copySelectedRows();
        }
        return;
    }

    QAction* copyCellAction = contextMenu.addAction(
        createBlueThemedIcon(kIconCopyPath),
        ks::i18n::contextText(QStringLiteral("log.menu.copy_cell"), QStringLiteral("复制单元格")));
    QAction* copyRowAction = contextMenu.addAction(
        createBlueThemedIcon(kIconClipboardPath),
        ks::i18n::contextText(QStringLiteral("log.menu.copy_row"), QStringLiteral("复制行")));

    // If no valid cell is selected, copy operations are disabled.
    copyCellAction->setEnabled(kHasValidCell);
    copyRowAction->setEnabled(kHasValidCell);

    // The third action toggles between "track events" and "cancel tracking" based on state.
    QAction* trackAction = nullptr;
    if (isTracking_)
    {
        trackAction = contextMenu.addAction(
            createBlueThemedIcon(kIconCancelTrackPath),
            ks::i18n::contextText(QStringLiteral("log.menu.cancel_track"), QStringLiteral("取消追踪")));
    }
    else
    {
        trackAction = contextMenu.addAction(
            createBlueThemedIcon(kIconTrackPath),
            ks::i18n::contextText(QStringLiteral("log.menu.track"), QStringLiteral("跟踪事件")));
        trackAction->setEnabled(kHasValidCell);
    }

    QAction* selectedAction = contextMenu.exec(logTable_->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == copyCellAction)
    {
        copySingleCell(row, column);
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copySingleRow(row);
        return;
    }
    if (selectedAction == trackAction)
    {
        if (isTracking_)
        {
            cancelTracking();
        }
        else
        {
            startTrackingByRow(row);
        }
    }
}

void LogDockWidget::copySingleCell(const int row, const int column)
{
    const KEvent* logItem = visibleEventAt(row);
    if (logItem == nullptr || column < 0)
    {
        return;
    }

    QString textToCopy;
    if (column == kLevelColumn)
    {
        // The level column visually shows only colored blocks; append the level text when copying.
        textToCopy = getLevelText(logItem->level);
    }
    else
    {
        switch (column)
        {
        case kTimeColumn:
            textToCopy = QString::fromStdString(formatTimeToString(logItem->timestamp));
            break;
        case kContentColumn:
            textToCopy = QString::fromStdString(logItem->content);
            break;
        case kFileColumn:
            textToCopy = QString::fromStdString(logItem->fileLocation);
            break;
        case kFunctionColumn:
            textToCopy = QString::fromStdString(logItem->functionName);
            break;
        default:
            break;
        }
    }

    QApplication::clipboard()->setText(textToCopy);
}

void LogDockWidget::copySingleRow(const int row)
{
    const KEvent* logItem = visibleEventAt(row);
    if (logItem == nullptr)
    {
        return;
    }

    // Row copy outputs only currently visible columns to avoid copying hidden columns.
    QApplication::clipboard()->setText(buildVisibleRowText(*logItem));
}

void LogDockWidget::copySelectedRows()
{
    const std::vector<int> kSelectedRowIndexes = collectSelectedRowIndexes();
    if (kSelectedRowIndexes.empty())
    {
        return;
    }

    QStringList lines;
    lines.reserve(static_cast<int>(kSelectedRowIndexes.size()));

    // selectedRowIndexes are sorted in ascending order by visual row index; output directly in visual order.
    for (const int kRow : kSelectedRowIndexes)
    {
        const KEvent* logItem = visibleEventAt(kRow);
        if (logItem == nullptr)
        {
            continue;
        }

        // Each line still reuses buildVisibleRowText to ensure that copying results when hidden columns are not displayed does not include hidden columns.
        lines.push_back(buildVisibleRowText(*logItem));
    }

    if (!lines.isEmpty())
    {
        QApplication::clipboard()->setText(lines.join("\n"));
    }
}

void LogDockWidget::copyVisibleRows()
{
    const std::vector<KEvent>& currentVisibleEvents = visibleEvents();
    QStringList lines;
    lines.reserve(static_cast<int>(currentVisibleEvents.size()));

    // Iterate through the current visible events list to ensure consistency with the screen display (including tracking and filtering states).
    for (const KEvent& logItem : currentVisibleEvents)
    {
        lines.push_back(buildVisibleRowText(logItem));
    }

    QApplication::clipboard()->setText(lines.join("\n"));
}

std::vector<int> LogDockWidget::collectSelectedRowIndexes() const
{
    std::vector<int> selectedRows;
    if (logTable_ == nullptr || logTable_->selectionModel() == nullptr)
    {
        return selectedRows;
    }

    // selectedRows() returns only one index per row in SelectRows mode, traversing fewer columns than selectedIndexes().
    // If future changes to cell selection cause selectedRows() to be empty, fall back to selectedIndexes() to maintain compatibility with the old logic.
    const QModelIndexList kSelectedRowIndexes = logTable_->selectionModel()->selectedRows();
    const QModelIndexList kSelectedIndexes = kSelectedRowIndexes.isEmpty()
        ? logTable_->selectionModel()->selectedIndexes()
        : kSelectedRowIndexes;
    selectedRows.reserve(static_cast<std::size_t>(kSelectedIndexes.size()));

    for (const QModelIndex& selectedIndex : kSelectedIndexes)
    {
        const int kRow = selectedIndex.row();
        if (visibleEventAt(kRow) != nullptr)
        {
            selectedRows.push_back(kRow);
        }
    }

    std::sort(selectedRows.begin(), selectedRows.end());
    selectedRows.erase(std::unique(selectedRows.begin(), selectedRows.end()), selectedRows.end());
    return selectedRows;
}

const std::vector<KEvent>& LogDockWidget::visibleEvents() const
{
    // emptyEvents is a safe read-only return value when the model is not created.
    // This avoids a null-check branch at every call site while not generating an extra temporary vector.
    static const std::vector<KEvent> kEmptyEvents;
    if (logModel_ == nullptr)
    {
        return kEmptyEvents;
    }

    return logModel_->rows();
}

const KEvent* LogDockWidget::visibleEventAt(const int row) const
{
    if (logModel_ == nullptr)
    {
        return nullptr;
    }

    return logModel_->rowAt(row);
}

QString LogDockWidget::buildVisibleRowText(const KEvent& logItem) const
{
    QStringList visibleFieldList;
    visibleFieldList.reserve(kTotalColumns);

    // Always output the base three columns; append file/function columns only when detailed information is enabled.
    visibleFieldList.push_back(getLevelText(logItem.level));
    visibleFieldList.push_back(QString::fromStdString(formatTimeToString(logItem.timestamp)));
    visibleFieldList.push_back(QString::fromStdString(logItem.content));

    // detailVisible usage: Records whether detailed column text should be output currently.
    const bool kDetailVisible = (detailCheck_ != nullptr) && detailCheck_->isChecked();
    if (kDetailVisible)
    {
        visibleFieldList.push_back(QString::fromStdString(logItem.fileLocation));
        visibleFieldList.push_back(QString::fromStdString(logItem.functionName));
    }

    return visibleFieldList.join("\t");
}

void LogDockWidget::startTrackingByRow(const int row)
{
    const KEvent* logItem = visibleEventAt(row);
    if (logItem == nullptr)
    {
        return;
    }

    // Read the target row's GUID and enter tracking mode.
    trackingGuid_ = logItem->guid;
    isTracking_ = true;
    refreshTableFromManager(true);
}

void LogDockWidget::cancelTracking()
{
    // After exiting tracking, return to the standard view with "level filtering only".
    isTracking_ = false;
    trackingGuid_ = GUID{};
    refreshTableFromManager(true);
}

void LogDockWidget::exportAllLogs()
{
    QString outputPath = chooseExportPath();
    if (outputPath.isEmpty())
    {
        return;
    }

    // Ensure the suffix is .txt.
    if (!outputPath.endsWith(".txt", Qt::CaseInsensitive))
    {
        outputPath += ".txt";
    }

    // Pass a UTF-8 string to Save to support Chinese file paths.
    const bool kSaveOk = kswordArkEventEntry.save(outputPath.toUtf8().toStdString());
    if (!kSaveOk)
    {
        QMessageBox::critical(this, "导出失败", "日志文件写入失败，请检查路径和权限。");
        return;
    }

    QMessageBox::information(this, "导出成功", "日志导出完成。");
}

QString LogDockWidget::chooseExportPath()
{
#ifdef _WIN32
    // Windows: Prefer calling the native shell save dialog.
    wchar_t fileBuffer[MAX_PATH] = L"KswordARK_Log.txt";
    OPENFILENAMEW saveDialog{};
    saveDialog.lStructSize = sizeof(OPENFILENAMEW);
    saveDialog.hwndOwner = reinterpret_cast<HWND>(this->winId());
    saveDialog.lpstrFilter = L"Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    saveDialog.lpstrFile = fileBuffer;
    saveDialog.nMaxFile = MAX_PATH;
    saveDialog.lpstrDefExt = L"txt";
    saveDialog.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (::GetSaveFileNameW(&saveDialog) != FALSE)
    {
        return QString::fromWCharArray(fileBuffer).trimmed();
    }

    // Only treat the dialog as failed to open when CommDlgExtendedError != 0 (not when the user cancels).
    const DWORD kShellErrorCode = ::CommDlgExtendedError();
    if (kShellErrorCode != 0)
    {
        bool inputOk = false;
        const QString kManualPath = QInputDialog::getText(
            this,
            "Shell 打开失败",
            "检测到原生保存对话框调用失败，请手动输入导出路径：",
            QLineEdit::Normal,
            "KswordARK_Log.txt",
            &inputOk).trimmed();

        if (inputOk)
        {
            return kManualPath;
        }
    }
    return QString();
#else
    // Non-Windows platform: Use Qt's native interface.
    bool inputOk = false;
    const QString manualPath = QInputDialog::getText(
        this,
        "导出日志",
        "请输入导出路径：",
        QLineEdit::Normal,
        "KswordARK_Log.txt",
        &inputOk).trimmed();
    if (inputOk)
    {
        return manualPath;
    }
    return QString();
#endif
}

void LogDockWidget::clearAllLogsWithDoubleConfirm()
{
    // First confirmation: standard confirmation.
    const QMessageBox::StandardButton kFirstConfirm = QMessageBox::question(
        this,
        "确认清空",
        "确定要清空日志列表吗？",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kFirstConfirm != QMessageBox::Yes)
    {
        return;
    }

    // Second confirmation: irreversible warning.
    const QMessageBox::StandardButton kSecondConfirm = QMessageBox::warning(
        this,
        "二次确认",
        "该操作不可恢复，是否继续清空全部日志？",
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kSecondConfirm != QMessageBox::Yes)
    {
        return;
    }

    // Actually clear and exit tracking state to avoid view deadlock from an empty tracking lock.
    kswordArkEventEntry.clear();
    isTracking_ = false;
    trackingGuid_ = GUID{};
    refreshTableFromManager(true);
}
