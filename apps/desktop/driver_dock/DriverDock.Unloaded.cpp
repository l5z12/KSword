#include "DriverDock.Internal.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

#include <QTimeZone>

using namespace ksword::driver_dock_internal;

namespace
{
    // UnloadedColumn corresponds one-to-one with the six columns in the issue screenshot.
    enum class UnloadedColumn : int
    {
        kName = 0,
        kBase,
        kSize,
        kTimeDateStamp,
        kLoadStatus,
        kUnloadTime,
        kCount
    };

    // FilterField::All uses -1; other values directly reuse UnloadedColumn indices.
    constexpr int kFilterAllFields = -1;
    constexpr int kUnloadedCacheIndexRole = Qt::UserRole + 57;
    constexpr std::uint64_t kWindowsEpochDelta100Ns = 116444736000000000ULL;

    constexpr int columnIndex(const UnloadedColumn column)
    {
        // Input: Strongly-typed column enumeration.
        // Processing: Convert to Qt column index.
        // Returns: Stable column index.
        return static_cast<int>(column);
    }

    QString fixedHex64(const std::uint64_t value)
    {
        // Input: address, size, or raw FILETIME value.
        // Handling: Format as fixed-width hexadecimal.
        // Return: uppercase text with 0x prefix.
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString fixedHex32(const std::uint32_t value)
    {
        // Input: timestamp, NTSTATUS, or flags.
        // Processing: Format as an 8-digit hexadecimal string.
        // Return: uppercase text with 0x prefix.
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(value), 8, 16, QChar('0'))
            .toUpper();
    }

    QString unloadTimeText(const std::uint64_t fileTime)
    {
        // Input: 100ns FILETIME value from R0 _UNLOADED_DRIVERS.CurrentTime.
        // Processing: Safely convert to local time; retain original hexadecimal values for anomalies earlier than the Windows epoch.
        // Returns: Human-readable time with millisecond precision.
        if (fileTime < kWindowsEpochDelta100Ns)
        {
            return fixedHex64(fileTime);
        }

        const std::uint64_t kUnixMilliseconds =
            (fileTime - kWindowsEpochDelta100Ns) / 10000ULL;
        if (kUnixMilliseconds >
            static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()))
        {
            return fixedHex64(fileTime);
        }
        return QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(kUnixMilliseconds),
            QTimeZone::UTC)
            .toLocalTime()
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    QString sourceName(const std::uint32_t source)
    {
        // Input: KSWORD_ARK_UNLOADED_DRIVER_SOURCE_*.
        // Processing: Map to the three technical source names shown in the screenshot.
        // Returns: Reserved value for unknown sources.
        switch (source)
        {
        case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS:
            return QStringLiteral("MmUnloadedDrivers");
        case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE:
            return QStringLiteral("PiDDBCacheTable");
        case KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST:
            return QStringLiteral("g_KernelHashBucketList");
        default:
            return QStringLiteral("Source(%1)").arg(source);
        }
    }

    std::array<QString, columnIndex(UnloadedColumn::kCount)> displayCells(
        const ksword::ark::UnloadedDriverEntry& row)
    {
        // Input: ArkDriverClient unified row.
        // Handling: Strictly generate six columns based on HAS_* flags; columns unsupported by the source display '-' instead of faking 0.
        // Returns: Display text suitable for tables, filtering, and copying.
        std::array<QString, columnIndex(UnloadedColumn::kCount)> cells{};
        cells[columnIndex(UnloadedColumn::kName)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_NAME) != 0U
            ? QString::fromStdWString(row.driverName)
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::kBase)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE) != 0U
            ? fixedHex64(row.baseAddress)
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::kSize)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE) != 0U
            ? fixedHex64(row.imageSize)
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::kTimeDateStamp)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP) != 0U
            ? fixedHex32(row.timeDateStamp)
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::kLoadStatus)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS) != 0U
            ? fixedHex32(static_cast<std::uint32_t>(row.loadStatus))
            : QStringLiteral("-");
        cells[columnIndex(UnloadedColumn::kUnloadTime)] =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U
            ? unloadTimeText(row.unloadTime)
            : QStringLiteral("-");
        return cells;
    }

    QTableWidgetItem* textItem(const QString& text)
    {
        // Input: Cell display text.
        // Processing: Create a non-editable, left-aligned cell.
        // Returns: ownership is transferred to the QTableWidget.
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    class NumericItem final : public QTableWidgetItem
    {
    public:
        NumericItem(const QString& text, const std::uint64_t sortValue)
            : QTableWidgetItem(text)
        {
            // Input: Display text and original unsigned value.
            // Handling: UserRole stores the sort key; cells remain read-only.
            // Returns: Constructor has no return value.
            setFlags(flags() & ~Qt::ItemIsEditable);
            setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
            setData(
                Qt::UserRole,
                QVariant::fromValue<qulonglong>(
                    static_cast<qulonglong>(sortValue)));
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // Input: The other cell for sorting comparison.
            // Note: Compare raw values when both sides have a UserRole; otherwise, fall back to text comparison.
            // Returns: whether it precedes other.
            bool leftOk = false;
            bool rightOk = false;
            const qulonglong kLeftValue =
                data(Qt::UserRole).toULongLong(&leftOk);
            const qulonglong kRightValue =
                other.data(Qt::UserRole).toULongLong(&rightOk);
            if (leftOk && rightOk)
            {
                return kLeftValue < kRightValue;
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* numericItem(
        const QString& text,
        const std::uint64_t sortValue)
    {
        // Input: display text and original numeric value.
        // Processing: Save numeric values in UserRole to ensure stable hexadecimal column sorting.
        // Returns: ownership is transferred to the QTableWidget.
        return new NumericItem(text, sortValue);
    }

    QString escapedTsvCell(QString text)
    {
        // Input: table text.
        // Processing: Flatten tabs and newlines to avoid breaking the TSV column structure after copying.
        // Returns: Safe cell text.
        text.replace(QLatin1Char('\t'), QLatin1Char(' '));
        text.replace(QLatin1Char('\r'), QLatin1Char(' '));
        text.replace(QLatin1Char('\n'), QLatin1Char(' '));
        return text.trimmed();
    }

    QString tableCellText(
        const QTableWidget* table,
        const int row,
        const int column)
    {
        // Input: Target table and cell coordinates.
        // Processing: normalize null items to empty text.
        // Returns: The currently displayed content.
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(row, column);
        return item != nullptr ? item->text() : QString();
    }

    void updateQueryStatusLabel(
        QLabel* label,
        const ksword::ark::UnloadedDriverQueryResult& result)
    {
        // Input: Status label and the most recent query result.
        // Handling: Distinguish between transmission failure, missing profile/layout, partial success, and full success.
        // Return: None; the status explains only the read result and provides no cleanup suggestions.
        if (label == nullptr)
        {
            return;
        }
        if (result.source == 0U && result.io.message.empty())
        {
            label->setText(
                driverText(
                    "driver.unloaded.status.waiting",
                    QStringLiteral("状态：等待刷新")));
            label->setStyleSheet(QString());
            return;
        }
        if (!result.io.ok)
        {
            label->setText(
                result.unsupported
                ? driverText(
                    "driver.unloaded.status.unsupported",
                    QStringLiteral("状态：当前驱动未集成已卸载驱动只读查询"))
                : driverText(
                    "driver.unloaded.status.io_failed",
                    QStringLiteral("状态：查询失败：%1"))
                    .arg(describeDriverCollection(result.io)));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
            return;
        }

        const QString kSourceText = sourceName(result.source);
        switch (result.queryStatus)
        {
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_OK:
            label->setText(
                driverText(
                    "driver.unloaded.status.ok",
                    QStringLiteral("状态：%1 查询完成，返回 %2/%3 条。"))
                    .arg(kSourceText)
                    .arg(result.entries.size())
                    .arg(result.totalRows));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(ksword_theme::successColor().name(QColor::HexRgb)));
            break;
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_PARTIAL:
            label->setText(
                driverText(
                    "driver.unloaded.status.partial",
                    QStringLiteral("状态：%1 部分完成，返回 %2/%3 条，跳过 %4 条。"))
                    .arg(kSourceText)
                    .arg(result.entries.size())
                    .arg(result.totalRows)
                    .arg(result.skippedRows));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(ksword_theme::warningColor().name(QColor::HexRgb)));
            break;
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_DYNDATA_UNAVAILABLE:
            label->setText(
                driverText(
                    "driver.unloaded.status.dyndata_missing",
                    QStringLiteral("状态：%1 所需 ntoskrnl DynData 尚未应用。"))
                    .arg(kSourceText));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(ksword_theme::warningColor().name(QColor::HexRgb)));
            break;
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_MODULE_PROFILE_UNAVAILABLE:
            label->setText(
                driverText(
                    "driver.unloaded.status.module_profile_missing",
                    QStringLiteral("状态：%1 所需模块 PDB profile 尚未应用。"))
                    .arg(kSourceText));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(ksword_theme::warningColor().name(QColor::HexRgb)));
            break;
        case KSWORD_ARK_UNLOADED_DRIVER_STATUS_LAYOUT_UNAVAILABLE:
            label->setText(
                driverText(
                    "driver.unloaded.status.layout_missing",
                    QStringLiteral("状态：%1 的当前 PDB profile 缺少安全读取布局。"))
                    .arg(kSourceText));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(ksword_theme::warningColor().name(QColor::HexRgb)));
            break;
        default:
            label->setText(
                driverText(
                    "driver.unloaded.status.read_failed",
                    QStringLiteral("状态：%1 读取失败，NTSTATUS=%2。"))
                    .arg(kSourceText)
                    .arg(fixedHex32(
                        static_cast<std::uint32_t>(result.lastStatus))));
            label->setStyleSheet(
                QStringLiteral("color:%1; font-weight:700;")
                    .arg(ksword_theme::errorColor().name(QColor::HexRgb)));
            break;
        }
    }
}

void DriverDock::initializeUnloadedPiddbTab()
{
    // Input: m_tabWidget.
    // Note: Strictly arrange the UI as 'table -> source radio buttons -> field filter/regex/count -> status' per the issue screenshot.
    // Return: None. The page only connects query, filter, details, and copy actions.
    unloadedPiddbPage_ = new QWidget(tabWidget_);
    unloadedPiddbLayout_ = new QVBoxLayout(unloadedPiddbPage_);
    unloadedPiddbLayout_->setContentsMargins(4, 4, 4, 4);
    unloadedPiddbLayout_->setSpacing(6);

    unloadedPiddbTable_ =
        new ks::ui::VisibleTableWidget(unloadedPiddbPage_);
    unloadedPiddbTable_->setColumnCount(
        columnIndex(UnloadedColumn::kCount));
    unloadedPiddbTable_->setHorizontalHeaderLabels(
        driverUnloadedDriverTableHeaders());
    unloadedPiddbTable_->setSelectionBehavior(
        QAbstractItemView::SelectRows);
    unloadedPiddbTable_->setSelectionMode(
        QAbstractItemView::SingleSelection);
    unloadedPiddbTable_->setEditTriggers(
        QAbstractItemView::NoEditTriggers);
    unloadedPiddbTable_->setAlternatingRowColors(true);
    unloadedPiddbTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    unloadedPiddbTable_->verticalHeader()->setVisible(false);
    unloadedPiddbTable_->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    unloadedPiddbTable_->horizontalHeader()->setSectionResizeMode(
        columnIndex(UnloadedColumn::kName),
        QHeaderView::Stretch);
    unloadedPiddbTable_->horizontalHeader()->setSectionResizeMode(
        columnIndex(UnloadedColumn::kUnloadTime),
        QHeaderView::Stretch);
    unloadedPiddbLayout_->addWidget(unloadedPiddbTable_, 1);

    unloadedPiddbSourceLayout_ = new QHBoxLayout();
    unloadedPiddbSourceLayout_->setContentsMargins(0, 0, 0, 0);
    unloadedPiddbSourceLayout_->setSpacing(12);
    unloadedPiddbSourceGroup_ = new QButtonGroup(unloadedPiddbPage_);
    unloadedPiddbMmSourceRadio_ =
        new QRadioButton(QStringLiteral("MmUnloadedDrivers"), unloadedPiddbPage_);
    unloadedPiddbPiDdbSourceRadio_ =
        new QRadioButton(QStringLiteral("PiDDBCacheTable"), unloadedPiddbPage_);
    unloadedPiddbCiSourceRadio_ =
        new QRadioButton(QStringLiteral("g_KernelHashBucketList"), unloadedPiddbPage_);
    unloadedPiddbSourceGroup_->addButton(
        unloadedPiddbMmSourceRadio_,
        KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS);
    unloadedPiddbSourceGroup_->addButton(
        unloadedPiddbPiDdbSourceRadio_,
        KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE);
    unloadedPiddbSourceGroup_->addButton(
        unloadedPiddbCiSourceRadio_,
        KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST);
    // Note: The issue screenshot defaults to selecting PiDDBCacheTable.
    unloadedPiddbPiDdbSourceRadio_->setChecked(true);

    unloadedPiddbRefreshButton_ = new QPushButton(unloadedPiddbPage_);
    unloadedPiddbRefreshButton_->setIcon(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    unloadedPiddbRefreshButton_->setToolTip(
        driverText(
            "driver.unloaded.refresh.tooltip",
            QStringLiteral("重新查询当前已卸载驱动来源")));
    ksword_theme::applyCompactIconButtonMetrics(unloadedPiddbRefreshButton_);

    unloadedPiddbSourceLayout_->addWidget(unloadedPiddbMmSourceRadio_);
    unloadedPiddbSourceLayout_->addWidget(unloadedPiddbPiDdbSourceRadio_);
    unloadedPiddbSourceLayout_->addWidget(unloadedPiddbCiSourceRadio_);
    unloadedPiddbSourceLayout_->addStretch(1);
    unloadedPiddbSourceLayout_->addWidget(unloadedPiddbRefreshButton_);
    unloadedPiddbLayout_->addLayout(unloadedPiddbSourceLayout_);

    unloadedPiddbFilterLayout_ = new QHBoxLayout();
    unloadedPiddbFilterLayout_->setContentsMargins(0, 0, 0, 0);
    unloadedPiddbFilterLayout_->setSpacing(6);
    unloadedPiddbFieldCombo_ = new QComboBox(unloadedPiddbPage_);
    unloadedPiddbFieldCombo_->addItem(
        driverText("driver.unloaded.filter.all", QStringLiteral("所有")),
        kFilterAllFields);
    const QStringList kFilterFields = driverUnloadedDriverTableHeaders();
    for (int column = 0; column < kFilterFields.size(); ++column)
    {
        unloadedPiddbFieldCombo_->addItem(kFilterFields.at(column), column);
    }
    unloadedPiddbFilterEdit_ = new QLineEdit(unloadedPiddbPage_);
    unloadedPiddbFilterEdit_->setClearButtonEnabled(true);
    unloadedPiddbFilterEdit_->setPlaceholderText(
        driverText(
            "driver.unloaded.filter.placeholder",
            QStringLiteral("过滤")));
    unloadedPiddbFilterEdit_->setToolTip(
        driverText(
            "driver.unloaded.filter.tooltip",
            QStringLiteral("只筛选当前来源缓存，不会重新访问驱动。")));
    unloadedPiddbRegexCheck_ = new QCheckBox(
        driverText("driver.unloaded.filter.regex", QStringLiteral("正则")),
        unloadedPiddbPage_);
    // Note: In the issue screenshot, 'Regex' is checked by default; an empty filter text does not change the results.
    unloadedPiddbRegexCheck_->setChecked(true);
    unloadedPiddbCountLabel_ = new QLabel(
        driverText("driver.unloaded.count", QStringLiteral("数量：%1")).arg(0),
        unloadedPiddbPage_);
    unloadedPiddbFilterLayout_->addWidget(unloadedPiddbFieldCombo_);
    unloadedPiddbFilterLayout_->addWidget(unloadedPiddbFilterEdit_, 1);
    unloadedPiddbFilterLayout_->addWidget(unloadedPiddbRegexCheck_);
    unloadedPiddbFilterLayout_->addWidget(unloadedPiddbCountLabel_);
    unloadedPiddbLayout_->addLayout(unloadedPiddbFilterLayout_);

    unloadedPiddbStatusLabel_ = new QLabel(
        driverText(
            "driver.unloaded.status.waiting",
            QStringLiteral("状态：等待刷新")),
        unloadedPiddbPage_);
    unloadedPiddbStatusLabel_->setWordWrap(true);
    unloadedPiddbLayout_->addWidget(unloadedPiddbStatusLabel_);

    tabWidget_->addTab(
        unloadedPiddbPage_,
        QIcon(QStringLiteral(":/Icon/process_uncritical.svg")),
        driverText(
            "driver.tab.unloaded_piddb",
            QStringLiteral("已卸载驱动")));

    // Query immediately upon source change; filter relevant controls to repaint only the local cache.
    const auto kConnectSource = [this](QRadioButton* radio) {
        connect(radio, &QRadioButton::toggled, this, [this](const bool checked) {
            if (checked)
            {
                refreshUnloadedDriversAsync();
            }
        });
    };
    kConnectSource(unloadedPiddbMmSourceRadio_);
    kConnectSource(unloadedPiddbPiDdbSourceRadio_);
    kConnectSource(unloadedPiddbCiSourceRadio_);
    connect(
        unloadedPiddbRefreshButton_,
        &QPushButton::clicked,
        this,
        &DriverDock::refreshUnloadedDriversAsync);
    connect(
        unloadedPiddbFieldCombo_,
        &QComboBox::currentIndexChanged,
        this,
        [this](int) { rebuildUnloadedPiddbTable(); });
    connect(
        unloadedPiddbFilterEdit_,
        &QLineEdit::textChanged,
        this,
        [this](const QString&) { rebuildUnloadedPiddbTable(); });
    connect(
        unloadedPiddbRegexCheck_,
        &QCheckBox::toggled,
        this,
        [this](bool) { rebuildUnloadedPiddbTable(); });
    connect(
        unloadedPiddbTable_,
        &QTableWidget::customContextMenuRequested,
        this,
        &DriverDock::showUnloadedPiddbContextMenu);
    connect(
        unloadedPiddbTable_,
        &QTableWidget::cellDoubleClicked,
        this,
        [this](int, int) { showSelectedUnloadedPiddbDetailDialog(); });
}

void DriverDock::refreshUnloadedDriversAsync()
{
    // Input: Current source selection value.
    // Processing: Allocate a new ticket for each query; the background only calls ArkDriverClient.
    // Returns: None; late-arriving results from old sources are discarded.
    if (unloadedPiddbSourceGroup_ == nullptr)
    {
        return;
    }
    const int kCheckedId = unloadedPiddbSourceGroup_->checkedId();
    if (kCheckedId < 0)
    {
        return;
    }
    const std::uint32_t kSource = static_cast<std::uint32_t>(kCheckedId);
    const std::uint64_t kTicket = ++unloadedDriverQueryTicket_;
    unloadedDriverQuerying_ = true;
    if (unloadedPiddbRefreshButton_ != nullptr)
    {
        unloadedPiddbRefreshButton_->setEnabled(false);
    }
    if (unloadedPiddbStatusLabel_ != nullptr)
    {
        unloadedPiddbStatusLabel_->setText(
            driverText(
                "driver.unloaded.status.querying",
                QStringLiteral("状态：正在查询 %1..."))
                .arg(sourceName(kSource)));
        unloadedPiddbStatusLabel_->setStyleSheet(
            QStringLiteral("color:%1; font-weight:700;")
                .arg(ksword_theme::kPrimaryBlueHex));
    }

    QPointer<DriverDock> guardThis(this);
    QRunnable* task = QRunnable::create([guardThis, kTicket, kSource]() {
        const ksword::ark::DriverClient kClient;
        ksword::ark::UnloadedDriverQueryResult result =
            kClient.queryUnloadedDrivers(
                kSource,
                KSWORD_ARK_UNLOADED_DRIVER_MAX_ROWS);

        // Dispatch using a long-lived GUI receiver and re-check QPointer within the GUI thread.
        // This ensures that when DriverDock is destructed during a query, the
        // worker thread does not pass a dangling raw pointer to invokeMethod.
        QCoreApplication* application = QCoreApplication::instance();
        if (application == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            application,
            [guardThis, kTicket, result = std::move(result)]() mutable {
                if (guardThis != nullptr)
                {
                    guardThis->applyUnloadedDriverQueryResult(
                        kTicket,
                        std::move(result));
                }
            },
            Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void DriverDock::applyUnloadedDriverQueryResult(
    const std::uint64_t ticket,
    ksword::ark::UnloadedDriverQueryResult result)
{
    // Input: Background result and its ticket.
    // Processing: Accept only the latest query; refresh UI after decoupling row cache from query metadata.
    // Returns: Nothing.
    if (ticket != unloadedDriverQueryTicket_)
    {
        return;
    }

    // The query result contains a variable-length row cache; defer both cache replacement and menu
    // opening to avoid invalidating the source index that actions depend on before rebuilding.
    const QPointer<DriverDock> kGuardThis(this);
    const auto kDeferredResult =
        std::make_shared<ksword::ark::UnloadedDriverQueryResult>(std::move(result));
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("driver-unloaded-snapshot-apply"),
        { unloadedPiddbTable_ },
        [kGuardThis, ticket, kDeferredResult]() mutable
        {
            if (!kGuardThis.isNull())
            {
                kGuardThis->applyUnloadedDriverQueryResult(
                    ticket,
                    std::move(*kDeferredResult));
            }
        }))
    {
        return;
    }
    result = std::move(*kDeferredResult);

    unloadedDriverQuerying_ = false;
    if (unloadedPiddbRefreshButton_ != nullptr)
    {
        unloadedPiddbRefreshButton_->setEnabled(true);
    }

    unloadedDriverCache_ = std::move(result.entries);
    result.entries.clear();
    lastUnloadedDriverResult_ = std::move(result);
    lastUnloadedDriverResult_.entries = unloadedDriverCache_;
    rebuildUnloadedPiddbTable();
    updateQueryStatusLabel(
        unloadedPiddbStatusLabel_,
        lastUnloadedDriverResult_);
}

void DriverDock::rebuildUnloadedPiddbTable()
{
    // Input: current row cache, field selection, keywords, and regex toggle.
    // Processing: Filter locally and write the six columns required for screenshots; UserRole saves the source cache index.
    // Returns: Nothing.
    if (unloadedPiddbTable_ == nullptr)
    {
        return;
    }
    const QSignalBlocker kBlocker(unloadedPiddbTable_);
    unloadedPiddbTable_->setSortingEnabled(false);
    unloadedPiddbTable_->setRowCount(0);

    const QString kPattern = unloadedPiddbFilterEdit_ != nullptr
        ? unloadedPiddbFilterEdit_->text().trimmed()
        : QString();
    const int kFilterField = unloadedPiddbFieldCombo_ != nullptr
        ? unloadedPiddbFieldCombo_->currentData().toInt()
        : kFilterAllFields;
    const bool kRegularExpressionEnabled =
        unloadedPiddbRegexCheck_ != nullptr &&
        unloadedPiddbRegexCheck_->isChecked();
    QRegularExpression expression;
    if (kRegularExpressionEnabled && !kPattern.isEmpty())
    {
        expression = QRegularExpression(
            kPattern,
            QRegularExpression::CaseInsensitiveOption);
        if (!expression.isValid())
        {
            if (unloadedPiddbCountLabel_ != nullptr)
            {
                unloadedPiddbCountLabel_->setText(
                    driverText(
                        "driver.unloaded.count",
                        QStringLiteral("数量：%1"))
                        .arg(0));
            }
            if (unloadedPiddbStatusLabel_ != nullptr)
            {
                unloadedPiddbStatusLabel_->setText(
                    driverText(
                        "driver.unloaded.status.regex_invalid",
                        QStringLiteral("状态：正则表达式无效：%1"))
                        .arg(expression.errorString()));
                unloadedPiddbStatusLabel_->setStyleSheet(
                    QStringLiteral("color:%1; font-weight:700;")
                        .arg(ksword_theme::warningColor().name(QColor::HexRgb)));
            }
            return;
        }
    }

    for (std::size_t cacheIndex = 0U;
         cacheIndex < unloadedDriverCache_.size();
         ++cacheIndex)
    {
        const ksword::ark::UnloadedDriverEntry& row =
            unloadedDriverCache_[cacheIndex];
        const auto kCells = displayCells(row);
        QString haystack;
        if (kFilterField >= 0 &&
            kFilterField < columnIndex(UnloadedColumn::kCount))
        {
            haystack = kCells[static_cast<std::size_t>(kFilterField)];
        }
        else
        {
            QStringList parts;
            for (const QString& cell : kCells)
            {
                parts << cell;
            }
            haystack = parts.join(QLatin1Char('\n'));
        }

        const bool kMatches = kPattern.isEmpty() ||
            (kRegularExpressionEnabled
                ? expression.match(haystack).hasMatch()
                : haystack.contains(kPattern, Qt::CaseInsensitive));
        if (!kMatches)
        {
            continue;
        }

        const int kOutputRow = unloadedPiddbTable_->rowCount();
        unloadedPiddbTable_->insertRow(kOutputRow);
        QTableWidgetItem* nameItem =
            textItem(kCells[columnIndex(UnloadedColumn::kName)]);
        nameItem->setData(
            kUnloadedCacheIndexRole,
            QVariant::fromValue<qulonglong>(
                static_cast<qulonglong>(cacheIndex)));
        nameItem->setToolTip(sourceName(row.source));
        unloadedPiddbTable_->setItem(
            kOutputRow,
            columnIndex(UnloadedColumn::kName),
            nameItem);

        unloadedPiddbTable_->setItem(
            kOutputRow,
            columnIndex(UnloadedColumn::kBase),
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_BASE) != 0U
                ? numericItem(
                    kCells[columnIndex(UnloadedColumn::kBase)],
                    row.baseAddress)
                : textItem(QStringLiteral("-")));
        unloadedPiddbTable_->setItem(
            kOutputRow,
            columnIndex(UnloadedColumn::kSize),
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_SIZE) != 0U
                ? numericItem(
                    kCells[columnIndex(UnloadedColumn::kSize)],
                    row.imageSize)
                : textItem(QStringLiteral("-")));
        unloadedPiddbTable_->setItem(
            kOutputRow,
            columnIndex(UnloadedColumn::kTimeDateStamp),
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_TIMESTAMP) != 0U
                ? numericItem(
                    kCells[columnIndex(UnloadedColumn::kTimeDateStamp)],
                    row.timeDateStamp)
                : textItem(QStringLiteral("-")));
        unloadedPiddbTable_->setItem(
            kOutputRow,
            columnIndex(UnloadedColumn::kLoadStatus),
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_LOAD_STATUS) != 0U
                ? numericItem(
                    kCells[columnIndex(UnloadedColumn::kLoadStatus)],
                    static_cast<std::uint32_t>(row.loadStatus))
                : textItem(QStringLiteral("-")));
        QTableWidgetItem* unloadItem =
            (row.flags & KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U
            ? numericItem(
                kCells[columnIndex(UnloadedColumn::kUnloadTime)],
                row.unloadTime)
            : textItem(QStringLiteral("-"));
        if ((row.flags &
                KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U)
        {
            unloadItem->setToolTip(fixedHex64(row.unloadTime));
        }
        unloadedPiddbTable_->setItem(
            kOutputRow,
            columnIndex(UnloadedColumn::kUnloadTime),
            unloadItem);
    }

    unloadedPiddbTable_->setSortingEnabled(true);
    if (unloadedPiddbCountLabel_ != nullptr)
    {
        unloadedPiddbCountLabel_->setText(
            driverText(
                "driver.unloaded.count",
                QStringLiteral("数量：%1"))
                .arg(unloadedPiddbTable_->rowCount()));
    }
    updateQueryStatusLabel(
        unloadedPiddbStatusLabel_,
        lastUnloadedDriverResult_);
}

void DriverDock::showUnloadedPiddbContextMenu(
    const QPoint& localPosition)
{
    // Input: Local coordinates of the table.
    // Processing: Provide only details, copy, and re-query operations; no kernel write actions are performed.
    // Returns: Nothing.
    if (unloadedPiddbTable_ == nullptr)
    {
        return;
    }
    const QModelIndex kClickedIndex =
        unloadedPiddbTable_->indexAt(localPosition);
    if (kClickedIndex.isValid())
    {
        unloadedPiddbTable_->setCurrentCell(
            kClickedIndex.row(),
            kClickedIndex.column());
        unloadedPiddbTable_->selectRow(kClickedIndex.row());
    }

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* detailAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        driverText(
            "driver.unloaded.menu.detail",
            QStringLiteral("查看已卸载驱动详情")));
    QAction* copyRowAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        driverText(
            "driver.menu.copy_row",
            QStringLiteral("复制当前行")));
    QAction* copyVisibleAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/log_copy.svg")),
        driverText(
            "driver.menu.copy_visible_rows",
            QStringLiteral("复制可见行")));
    contextMenu.addSeparator();
    QAction* refreshAction = contextMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        driverText(
            "driver.unloaded.menu.refresh",
            QStringLiteral("重新查询当前来源")));
    detailAction->setEnabled(unloadedPiddbTable_->currentRow() >= 0);
    copyRowAction->setEnabled(unloadedPiddbTable_->currentRow() >= 0);

    QAction* selectedAction = contextMenu.exec(
        unloadedPiddbTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == detailAction)
    {
        showSelectedUnloadedPiddbDetailDialog();
    }
    else if (selectedAction == copyRowAction)
    {
        copySelectedUnloadedPiddbRow();
    }
    else if (selectedAction == copyVisibleAction)
    {
        copyVisibleUnloadedPiddbRows();
    }
    else if (selectedAction == refreshAction)
    {
        refreshUnloadedDriversAsync();
    }
}

void DriverDock::showSelectedUnloadedPiddbDetailDialog()
{
    // Input: Currently selected row.
    // Processing: Expand unified protocol rows and raw values based on the UserRole source index.
    // Returns: none; displays read-only using CodeEditorWidget with opaqueDialogStyle.
    if (unloadedPiddbTable_ == nullptr)
    {
        return;
    }
    const int kCurrentRow = unloadedPiddbTable_->currentRow();
    const QTableWidgetItem* nameItem = kCurrentRow >= 0
        ? unloadedPiddbTable_->item(
            kCurrentRow,
            columnIndex(UnloadedColumn::kName))
        : nullptr;
    bool indexOk = false;
    const qulonglong kCacheIndex = nameItem != nullptr
        ? nameItem->data(kUnloadedCacheIndexRole).toULongLong(&indexOk)
        : 0ULL;
    if (!indexOk ||
        kCacheIndex >= static_cast<qulonglong>(unloadedDriverCache_.size()))
    {
        return;
    }

    const ksword::ark::UnloadedDriverEntry& row =
        unloadedDriverCache_[static_cast<std::size_t>(kCacheIndex)];
    const auto kCells = displayCells(row);
    QString detail;
    detail += driverText(
        "driver.unloaded.detail.title",
        QStringLiteral("已卸载驱动只读详情\n"));
    detail += QStringLiteral("Source: %1 (%2)\n")
        .arg(sourceName(row.source))
        .arg(row.source);
    detail += QStringLiteral("EntryAddress: %1\n")
        .arg(fixedHex64(row.entryAddress));
    detail += QStringLiteral("Flags: %1\n")
        .arg(fixedHex32(row.flags));
    detail += QStringLiteral("Name: %1\n")
        .arg(kCells[columnIndex(UnloadedColumn::kName)]);
    detail += QStringLiteral("BaseAddress: %1\n")
        .arg(kCells[columnIndex(UnloadedColumn::kBase)]);
    detail += QStringLiteral("ImageSize: %1\n")
        .arg(kCells[columnIndex(UnloadedColumn::kSize)]);
    detail += QStringLiteral("TimeDateStamp: %1\n")
        .arg(kCells[columnIndex(UnloadedColumn::kTimeDateStamp)]);
    detail += QStringLiteral("LoadStatus: %1\n")
        .arg(kCells[columnIndex(UnloadedColumn::kLoadStatus)]);
    detail += QStringLiteral("UnloadTime: %1\n")
        .arg(kCells[columnIndex(UnloadedColumn::kUnloadTime)]);
    if ((row.flags &
            KSWORD_ARK_UNLOADED_DRIVER_ROW_FLAG_HAS_UNLOAD_TIME) != 0U)
    {
        detail += QStringLiteral("UnloadTimeRaw: %1\n")
            .arg(fixedHex64(row.unloadTime));
    }
    detail += QStringLiteral("QueryStatus: %1\n")
        .arg(lastUnloadedDriverResult_.queryStatus);
    detail += QStringLiteral("ResponseFlags: %1\n")
        .arg(fixedHex32(lastUnloadedDriverResult_.responseFlags));
    detail += QStringLiteral("LastStatus: %1\n")
        .arg(fixedHex32(
            static_cast<std::uint32_t>(
                lastUnloadedDriverResult_.lastStatus)));

    QDialog dialog(this);
    dialog.setObjectName(
        QStringLiteral("driverDockUnloadedDriverDetailDialog"));
    dialog.setWindowTitle(
        driverText(
            "driver.unloaded.dialog.title",
            QStringLiteral("已卸载驱动详情")));
    dialog.resize(860, 620);
    dialog.setStyleSheet(
        ksword_theme::opaqueDialogStyle(dialog.objectName()));
    QVBoxLayout* layout = new QVBoxLayout(&dialog);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(8);

    CodeEditorWidget* editor = new CodeEditorWidget(&dialog);
    editor->setReadOnly(true);
    editor->setText(detail);
    layout->addWidget(editor, 1);

    QDialogButtonBox* buttonBox =
        new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QPushButton* copyButton = buttonBox->addButton(
        driverText(
            "driver.dialog.copy_detail",
            QStringLiteral("复制详情")),
        QDialogButtonBox::ActionRole);
    connect(copyButton, &QPushButton::clicked, &dialog, [editor]() {
        if (editor != nullptr && QGuiApplication::clipboard() != nullptr)
        {
            QGuiApplication::clipboard()->setText(editor->text());
        }
    });
    connect(
        buttonBox,
        &QDialogButtonBox::rejected,
        &dialog,
        &QDialog::reject);
    layout->addWidget(buttonBox);
    dialog.exec();
}

void DriverDock::copySelectedUnloadedPiddbRow()
{
    // Input: Current table selection.
    // Processing: Copy one TSV row.
    // Returns: Nothing.
    if (unloadedPiddbTable_ == nullptr ||
        QGuiApplication::clipboard() == nullptr ||
        unloadedPiddbTable_->currentRow() < 0)
    {
        return;
    }
    QStringList cells;
    for (int column = 0;
         column < unloadedPiddbTable_->columnCount();
         ++column)
    {
        cells << escapedTsvCell(
            tableCellText(
                unloadedPiddbTable_,
                unloadedPiddbTable_->currentRow(),
                column));
    }
    QGuiApplication::clipboard()->setText(
        cells.join(QLatin1Char('\t')));
}

void DriverDock::copyVisibleUnloadedPiddbRows()
{
    // Input: Currently filtered table.
    // Processing: Copy table headers and all visible rows as TSV.
    // Returns: Nothing.
    if (unloadedPiddbTable_ == nullptr ||
        QGuiApplication::clipboard() == nullptr)
    {
        return;
    }
    QStringList lines;
    QStringList headers;
    for (int column = 0;
         column < unloadedPiddbTable_->columnCount();
         ++column)
    {
        const QTableWidgetItem* header =
            unloadedPiddbTable_->horizontalHeaderItem(column);
        headers << escapedTsvCell(
            header != nullptr ? header->text() : QString());
    }
    lines << headers.join(QLatin1Char('\t'));
    for (int row = 0; row < unloadedPiddbTable_->rowCount(); ++row)
    {
        QStringList cells;
        for (int column = 0;
             column < unloadedPiddbTable_->columnCount();
             ++column)
        {
            cells << escapedTsvCell(
                tableCellText(unloadedPiddbTable_, row, column));
        }
        lines << cells.join(QLatin1Char('\t'));
    }
    QGuiApplication::clipboard()->setText(
        lines.join(QLatin1Char('\n')));
}
