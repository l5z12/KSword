#include "KernelCallbackMonitorWidget.h"

#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractTableModel>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QScrollBar>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QSplitter>
#include <QTextStream>
#include <QStringConverter>
#include <QTimer>
#include <QTimeZone>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <chrono>
#include <limits>

namespace
{
    enum CallbackColumn
    {
        kCallbackColumnSequence = 0,
        kCallbackColumnTime,
        kCallbackColumnCategory,
        kCallbackColumnOperation,
        kCallbackColumnProcess,
        kCallbackColumnPidTid,
        kCallbackColumnTarget,
        kCallbackColumnResult,
        kCallbackColumnPath,
        kCallbackColumnSummary,
        kCallbackColumnCount
    };

    QString callbackCategoryText(const std::uint32_t category)
    {
        switch (category)
        {
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS:
            return QStringLiteral("进程");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD:
            return QStringLiteral("线程");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE:
            return QStringLiteral("镜像");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY:
            return QStringLiteral("注册表");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT:
            return QStringLiteral("对象");
        case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER:
            return QStringLiteral("文件");
        default:
            return QStringLiteral("未知");
        }
    }

    QString callbackOperationText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS)
        {
            return row.operation == KSWORD_ARK_CALLBACK_MONITOR_PROCESS_OP_EXIT
                ? QStringLiteral("退出")
                : QStringLiteral("创建");
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD)
        {
            return row.operation == KSWORD_ARK_THREAD_OP_EXIT
                ? QStringLiteral("退出")
                : QStringLiteral("创建");
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE)
        {
            return QStringLiteral("加载");
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY)
        {
            switch (row.operation)
            {
            case KSWORD_ARK_REG_OP_CREATE_KEY: return QStringLiteral("创建键");
            case KSWORD_ARK_REG_OP_OPEN_KEY: return QStringLiteral("打开键");
            case KSWORD_ARK_REG_OP_DELETE_KEY: return QStringLiteral("删除键");
            case KSWORD_ARK_REG_OP_SET_VALUE: return QStringLiteral("设置值");
            case KSWORD_ARK_REG_OP_DELETE_VALUE: return QStringLiteral("删除值");
            case KSWORD_ARK_REG_OP_RENAME_KEY: return QStringLiteral("重命名键");
            case KSWORD_ARK_REG_OP_SET_INFO: return QStringLiteral("设置键信息");
            case KSWORD_ARK_REG_OP_QUERY_VALUE: return QStringLiteral("查询值");
            default: break;
            }
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT)
        {
            const QString kObjectText = (row.operation & KSWORD_ARK_OBJECT_OP_TYPE_THREAD) != 0UL
                ? QStringLiteral("线程句柄")
                : QStringLiteral("进程句柄");
            const QString kActionText = (row.operation & KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE) != 0UL
                ? QStringLiteral("复制")
                : QStringLiteral("创建");
            return QStringLiteral("%1%2").arg(kActionText, kObjectText);
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)
        {
            switch (row.operation)
            {
            case KSWORD_ARK_FILE_MONITOR_OPERATION_CREATE: return QStringLiteral("创建/打开");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_READ: return QStringLiteral("读取");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_WRITE: return QStringLiteral("写入");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_SETINFO: return QStringLiteral("设置信息");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_RENAME: return QStringLiteral("重命名");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_DELETE: return QStringLiteral("删除");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_CLEANUP: return QStringLiteral("清理");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_CLOSE: return QStringLiteral("关闭");
            case KSWORD_ARK_FILE_MONITOR_OPERATION_FSCTL: return QStringLiteral("FSCTL");
            default: break;
            }
        }
        return QStringLiteral("0x%1").arg(row.operation, 8, 16, QLatin1Char('0')).toUpper();
    }

    QString callbackTimeText(const std::int64_t timeUtc100ns)
    {
        constexpr std::int64_t kWindowsToUnix100ns = 116444736000000000LL;
        const std::int64_t kUnixMilliseconds = (timeUtc100ns - kWindowsToUnix100ns) / 10000LL;
        return QDateTime::fromMSecsSinceEpoch(kUnixMilliseconds, QTimeZone::UTC)
            .toLocalTime()
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    }

    QString callbackProcessText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        const QString kFullText = QString::fromStdWString(row.processName);
        const QString kFileName = QFileInfo(kFullText).fileName();
        return kFileName.isEmpty() ? kFullText : kFileName;
    }

    QString callbackPidTidText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        return QStringLiteral("%1 / %2")
            .arg(row.originatingProcessId)
            .arg(row.originatingThreadId);
    }

    QString callbackTargetText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        if (row.targetProcessId == 0U && row.targetThreadId == 0U)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("%1 / %2")
            .arg(row.targetProcessId)
            .arg(row.targetThreadId);
    }

    QString callbackResultText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        if ((row.flags & KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_STATUS_PRESENT) == 0UL)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(row.resultStatus), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    QString callbackSummaryText(const ksword::ark::CallbackMonitorEventRow& row)
    {
        if ((row.flags & KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_ACCESS_PRESENT) != 0UL)
        {
            return QStringLiteral("访问 0x%1 → 0x%2")
                .arg(row.originalAccess, 8, 16, QLatin1Char('0'))
                .arg(row.desiredAccess, 8, 16, QLatin1Char('0'))
                .toUpper();
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE)
        {
            return QStringLiteral("地址 0x%1，大小 0x%2")
                .arg(row.address, 0, 16)
                .arg(row.regionSize, 0, 16)
                .toUpper();
        }
        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)
        {
            return QStringLiteral("Major/Minor 0x%1/0x%2")
                .arg((row.detailCode >> 8) & 0xFFU, 2, 16, QLatin1Char('0'))
                .arg(row.detailCode & 0xFFU, 2, 16, QLatin1Char('0'))
                .toUpper();
        }
        return QStringLiteral("父 PID %1，Session %2")
            .arg(row.parentProcessId)
            .arg(row.sessionId);
    }

    QPushButton* createCallbackIconButton(
        QWidget* parent,
        const QString& iconPath,
        const QString& toolTip)
    {
        QPushButton* button = new QPushButton(parent);
        button->setIcon(QIcon(iconPath));
        button->setToolTip(toolTip);
        ksword_theme::applyCompactIconButtonMetrics(button);
        return button;
    }
}

class KernelCallbackEventModel final : public QAbstractTableModel
{
public:
    explicit KernelCallbackEventModel(QObject* parent = nullptr)
        : QAbstractTableModel(parent)
    {
    }

    int rowCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : static_cast<int>(rows_.size());
    }

    int columnCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : kCallbackColumnCount;
    }

    QVariant headerData(
        const int section,
        const Qt::Orientation orientation,
        const int role) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
        {
            return {};
        }
        static const QStringList kHeaders{
            QStringLiteral("序号"),
            QStringLiteral("时间"),
            QStringLiteral("类别"),
            QStringLiteral("操作"),
            QStringLiteral("进程"),
            QStringLiteral("PID / TID"),
            QStringLiteral("目标 PID / TID"),
            QStringLiteral("结果"),
            QStringLiteral("路径"),
            QStringLiteral("摘要")
        };
        return section >= 0 && section < kHeaders.size()
            ? ks::i18n::sourceText(kHeaders.at(section))
            : QVariant();
    }

    QVariant data(const QModelIndex& index, const int role) const override
    {
        const ksword::ark::CallbackMonitorEventRow* row = rowAt(index.row());
        if (row == nullptr || index.column() < 0 || index.column() >= kCallbackColumnCount)
        {
            return {};
        }
        if (role == Qt::UserRole)
        {
            switch (index.column())
            {
            case kCallbackColumnSequence: return QVariant::fromValue<qulonglong>(row->sequence);
            case kCallbackColumnTime: return QVariant::fromValue<qlonglong>(row->timeUtc100ns);
            case kCallbackColumnCategory: return row->category;
            case kCallbackColumnOperation: return row->operation;
            case kCallbackColumnPidTid: return row->originatingProcessId;
            case kCallbackColumnTarget: return row->targetProcessId;
            case kCallbackColumnResult: return static_cast<qlonglong>(row->resultStatus);
            default: break;
            }
        }
        if (role != Qt::DisplayRole && role != Qt::ToolTipRole)
        {
            return {};
        }

        switch (index.column())
        {
        case kCallbackColumnSequence: return QString::number(row->sequence);
        case kCallbackColumnTime: return callbackTimeText(row->timeUtc100ns);
        case kCallbackColumnCategory: return ks::i18n::sourceText(callbackCategoryText(row->category));
        case kCallbackColumnOperation: return ks::i18n::sourceText(callbackOperationText(*row));
        case kCallbackColumnProcess: return callbackProcessText(*row);
        case kCallbackColumnPidTid: return callbackPidTidText(*row);
        case kCallbackColumnTarget: return callbackTargetText(*row);
        case kCallbackColumnResult: return callbackResultText(*row);
        case kCallbackColumnPath: return QString::fromStdWString(row->path);
        case kCallbackColumnSummary: return ks::i18n::sourceText(callbackSummaryText(*row));
        default: return {};
        }
    }

    const ksword::ark::CallbackMonitorEventRow* rowAt(const int row) const
    {
        if (row < 0 || row >= static_cast<int>(rows_.size()))
        {
            return nullptr;
        }
        return &rows_[static_cast<std::size_t>(row)];
    }

    void appendRows(
        std::vector<ksword::ark::CallbackMonitorEventRow> rows,
        const int maximumRows)
    {
        if (rows.empty())
        {
            return;
        }
        const int kFirstRow = static_cast<int>(rows_.size());
        beginInsertRows(QModelIndex(), kFirstRow, kFirstRow + static_cast<int>(rows.size()) - 1);
        for (auto& row : rows)
        {
            rows_.push_back(std::move(row));
        }
        endInsertRows();
        trimRows(maximumRows);
    }

    void trimRows(const int maximumRows)
    {
        const int kRemoveCount = std::max(0, static_cast<int>(rows_.size()) - maximumRows);
        if (kRemoveCount == 0)
        {
            return;
        }
        beginRemoveRows(QModelIndex(), 0, kRemoveCount - 1);
        rows_.erase(rows_.begin(), rows_.begin() + kRemoveCount);
        endRemoveRows();
    }

    void clearRows()
    {
        if (rows_.empty())
        {
            return;
        }
        beginResetModel();
        rows_.clear();
        endResetModel();
    }

private:
    std::deque<ksword::ark::CallbackMonitorEventRow> rows_;
};

class KernelCallbackFilterModel final : public QSortFilterProxyModel
{
public:
    explicit KernelCallbackFilterModel(QObject* parent = nullptr)
        : QSortFilterProxyModel(parent)
    {
        setDynamicSortFilter(true);
        setSortRole(Qt::UserRole);
    }

    void setFilters(
        const std::uint32_t category,
        const QString& operation,
        const QString& pid,
        const QString& process,
        const QString& path,
        const QString& result,
        const bool regex)
    {
        const QString kNormalizedOperation = operation.trimmed();
        const QString kNormalizedPid = pid.trimmed();
        const QString kNormalizedProcess = process.trimmed();
        const QString kNormalizedPath = path.trimmed();
        const QString kNormalizedResult = result.trimmed();
        if (category_ == category &&
            operation_ == kNormalizedOperation &&
            pid_ == kNormalizedPid &&
            process_ == kNormalizedProcess &&
            path_ == kNormalizedPath &&
            result_ == kNormalizedResult &&
            regex_ == regex)
        {
            return;
        }

        category_ = category;
        operation_ = kNormalizedOperation;
        pid_ = kNormalizedPid;
        process_ = kNormalizedProcess;
        path_ = kNormalizedPath;
        result_ = kNormalizedResult;
        regex_ = regex;
        invalidRegex_ = false;
        if (regex_)
        {
            operationRegex_ = QRegularExpression(operation_, QRegularExpression::CaseInsensitiveOption);
            pidRegex_ = QRegularExpression(pid_, QRegularExpression::CaseInsensitiveOption);
            processRegex_ = QRegularExpression(process_, QRegularExpression::CaseInsensitiveOption);
            pathRegex_ = QRegularExpression(path_, QRegularExpression::CaseInsensitiveOption);
            resultRegex_ = QRegularExpression(result_, QRegularExpression::CaseInsensitiveOption);
            invalidRegex_ =
                (!operation_.isEmpty() && !operationRegex_.isValid()) ||
                (!pid_.isEmpty() && !pidRegex_.isValid()) ||
                (!process_.isEmpty() && !processRegex_.isValid()) ||
                (!path_.isEmpty() && !pathRegex_.isValid()) ||
                (!result_.isEmpty() && !resultRegex_.isValid());
        }
        invalidateRowsFilter();
    }

    bool invalidRegex() const
    {
        return invalidRegex_;
    }

protected:
    bool filterAcceptsRow(const int sourceRow, const QModelIndex& sourceParent) const override
    {
        Q_UNUSED(sourceParent);
        const auto* model = static_cast<const KernelCallbackEventModel*>(sourceModel());
        const auto* row = model != nullptr ? model->rowAt(sourceRow) : nullptr;
        if (row == nullptr || invalidRegex_)
        {
            return false;
        }
        if (category_ != 0U && row->category != category_)
        {
            return false;
        }
        const QString kPidText = QStringLiteral("%1 %2 %3 %4 %5")
            .arg(row->originatingProcessId)
            .arg(row->originatingThreadId)
            .arg(row->targetProcessId)
            .arg(row->targetThreadId)
            .arg(row->parentProcessId);
        const QString kProcessText = QStringLiteral("%1 %2")
            .arg(QString::fromStdWString(row->processName), callbackProcessText(*row));
        const QString kOperationSourceText = callbackOperationText(*row);
        const QString kOperationDisplayText = ks::i18n::sourceText(kOperationSourceText);
        const QString kOperationSearchText = kOperationDisplayText == kOperationSourceText
            ? kOperationSourceText
            : QStringLiteral("%1 %2").arg(kOperationSourceText, kOperationDisplayText);
        return matches(operation_, kOperationSearchText, operationRegex_) &&
            matches(pid_, kPidText, pidRegex_) &&
            matches(process_, kProcessText, processRegex_) &&
            matches(path_, QString::fromStdWString(row->path), pathRegex_) &&
            matches(result_, callbackResultText(*row), resultRegex_);
    }

private:
    bool matches(
        const QString& pattern,
        const QString& value,
        const QRegularExpression& expression) const
    {
        if (pattern.isEmpty())
        {
            return true;
        }
        if (!regex_)
        {
            return value.contains(pattern, Qt::CaseInsensitive);
        }
        return expression.match(value).hasMatch();
    }

    std::uint32_t category_ = 0;
    QString operation_;
    QString pid_;
    QString process_;
    QString path_;
    QString result_;
    QRegularExpression operationRegex_;
    QRegularExpression pidRegex_;
    QRegularExpression processRegex_;
    QRegularExpression pathRegex_;
    QRegularExpression resultRegex_;
    bool regex_ = false;
    bool invalidRegex_ = false;
};

KernelCallbackMonitorWidget::KernelCallbackMonitorWidget(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    updateActionState();
    updateStatusLabel();
}

KernelCallbackMonitorWidget::~KernelCallbackMonitorWidget()
{
    if (uiTimer_ != nullptr)
    {
        uiTimer_->stop();
    }
    stopCapture(true);
}

void KernelCallbackMonitorWidget::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    QWidget* controlPanel = new QWidget(this);
    QGridLayout* controlLayout = new QGridLayout(controlPanel);
    controlLayout->setContentsMargins(6, 6, 6, 6);
    controlLayout->setHorizontalSpacing(8);
    controlLayout->setVerticalSpacing(6);
    controlLayout->addWidget(new QLabel(QStringLiteral("采集类别"), controlPanel), 0, 0);
    processCheck_ = new QCheckBox(QStringLiteral("进程"), controlPanel);
    threadCheck_ = new QCheckBox(QStringLiteral("线程"), controlPanel);
    imageCheck_ = new QCheckBox(QStringLiteral("镜像"), controlPanel);
    registryCheck_ = new QCheckBox(QStringLiteral("注册表"), controlPanel);
    objectCheck_ = new QCheckBox(QStringLiteral("对象"), controlPanel);
    fileCheck_ = new QCheckBox(QStringLiteral("文件（高频）"), controlPanel);
    processCheck_->setChecked(true);
    threadCheck_->setChecked(true);
    imageCheck_->setChecked(true);
    registryCheck_->setChecked(true);
    objectCheck_->setChecked(true);
    fileCheck_->setChecked(false);
    controlLayout->addWidget(processCheck_, 0, 1);
    controlLayout->addWidget(threadCheck_, 0, 2);
    controlLayout->addWidget(imageCheck_, 0, 3);
    controlLayout->addWidget(registryCheck_, 0, 4);
    controlLayout->addWidget(objectCheck_, 0, 5);
    controlLayout->addWidget(fileCheck_, 0, 6);

    controlLayout->addWidget(new QLabel(QStringLiteral("最大行数"), controlPanel), 1, 0);
    maxRowsSpin_ = new QSpinBox(controlPanel);
    maxRowsSpin_->setRange(1000, 100000);
    maxRowsSpin_->setSingleStep(1000);
    maxRowsSpin_->setValue(20000);
    controlLayout->addWidget(maxRowsSpin_, 1, 1, 1, 2);
    startButton_ = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/process_start.svg"),
        QStringLiteral("开始内核回调监控"));
    stopButton_ = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/process_terminate.svg"),
        QStringLiteral("停止内核回调监控"));
    pauseButton_ = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/process_pause.svg"),
        QStringLiteral("暂停事件入表，后台继续读取"));
    clearButton_ = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/log_clear.svg"),
        QStringLiteral("清空当前页面并跳过已有事件"));
    exportButton_ = createCallbackIconButton(
        controlPanel,
        QStringLiteral(":/Icon/log_export.svg"),
        QStringLiteral("导出当前可见事件为 CSV"));
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(6);
    buttonLayout->addWidget(startButton_);
    buttonLayout->addWidget(stopButton_);
    buttonLayout->addWidget(pauseButton_);
    buttonLayout->addWidget(clearButton_);
    buttonLayout->addWidget(exportButton_);
    buttonLayout->addStretch(1);
    controlLayout->addLayout(buttonLayout, 1, 3, 1, 4);
    statusLabel_ = new QLabel(QStringLiteral("● 空闲"), controlPanel);
    controlLayout->addWidget(statusLabel_, 2, 0, 1, 7);
    rootLayout_->addWidget(controlPanel, 0);

    QWidget* filterPanel = new QWidget(this);
    QGridLayout* filterLayout = new QGridLayout(filterPanel);
    filterLayout->setContentsMargins(6, 6, 6, 6);
    filterLayout->setHorizontalSpacing(6);
    filterLayout->setVerticalSpacing(6);
    filterLayout->addWidget(new QLabel(QStringLiteral("类别"), filterPanel), 0, 0);
    categoryFilterCombo_ = new QComboBox(filterPanel);
    categoryFilterCombo_->addItem(QStringLiteral("全部类别"), QVariant::fromValue<qulonglong>(0U));
    categoryFilterCombo_->addItem(QStringLiteral("进程"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS));
    categoryFilterCombo_->addItem(QStringLiteral("线程"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD));
    categoryFilterCombo_->addItem(QStringLiteral("镜像"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE));
    categoryFilterCombo_->addItem(QStringLiteral("注册表"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY));
    categoryFilterCombo_->addItem(QStringLiteral("对象"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT));
    categoryFilterCombo_->addItem(QStringLiteral("文件"), QVariant::fromValue<qulonglong>(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER));
    filterLayout->addWidget(categoryFilterCombo_, 0, 1);
    filterLayout->addWidget(new QLabel(QStringLiteral("操作"), filterPanel), 0, 2);
    operationFilterEdit_ = new QLineEdit(filterPanel);
    operationFilterEdit_->setPlaceholderText(QStringLiteral("创建、退出、写入…"));
    filterLayout->addWidget(operationFilterEdit_, 0, 3);
    filterLayout->addWidget(new QLabel(QStringLiteral("PID"), filterPanel), 0, 4);
    pidFilterEdit_ = new QLineEdit(filterPanel);
    pidFilterEdit_->setPlaceholderText(QStringLiteral("来源、目标或父 PID"));
    filterLayout->addWidget(pidFilterEdit_, 0, 5);

    filterLayout->addWidget(new QLabel(QStringLiteral("进程"), filterPanel), 1, 0);
    processFilterEdit_ = new QLineEdit(filterPanel);
    processFilterEdit_->setPlaceholderText(QStringLiteral("进程名或映像路径"));
    filterLayout->addWidget(processFilterEdit_, 1, 1);
    filterLayout->addWidget(new QLabel(QStringLiteral("路径"), filterPanel), 1, 2);
    pathFilterEdit_ = new QLineEdit(filterPanel);
    pathFilterEdit_->setPlaceholderText(QStringLiteral("映像、注册表或文件路径"));
    filterLayout->addWidget(pathFilterEdit_, 1, 3);
    filterLayout->addWidget(new QLabel(QStringLiteral("结果"), filterPanel), 1, 4);
    resultFilterEdit_ = new QLineEdit(filterPanel);
    resultFilterEdit_->setPlaceholderText(QStringLiteral("NTSTATUS 十六进制"));
    filterLayout->addWidget(resultFilterEdit_, 1, 5);
    regexCheck_ = new QCheckBox(QStringLiteral("正则"), filterPanel);
    keepBottomCheck_ = new QCheckBox(QStringLiteral("保持贴底"), filterPanel);
    keepBottomCheck_->setChecked(true);
    filterStatusLabel_ = new QLabel(QStringLiteral("筛选结果：0 / 0"), filterPanel);
    filterLayout->addWidget(regexCheck_, 2, 0);
    filterLayout->addWidget(keepBottomCheck_, 2, 1);
    filterLayout->addWidget(filterStatusLabel_, 2, 2, 1, 4);
    rootLayout_->addWidget(filterPanel, 0);

    eventModel_ = new KernelCallbackEventModel(this);
    filterModel_ = new KernelCallbackFilterModel(this);
    filterModel_->setSourceModel(eventModel_);
    eventTable_ = new ks::ui::TableActionTableView(this);
    eventTable_->setModel(filterModel_);
    eventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    eventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    eventTable_->setAlternatingRowColors(true);
    eventTable_->setSortingEnabled(true);
    eventTable_->sortByColumn(kCallbackColumnSequence, Qt::AscendingOrder);
    eventTable_->verticalHeader()->setVisible(false);
    eventTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    eventTable_->setColumnWidth(kCallbackColumnSequence, 90);
    eventTable_->setColumnWidth(kCallbackColumnTime, 170);
    eventTable_->setColumnWidth(kCallbackColumnCategory, 78);
    eventTable_->setColumnWidth(kCallbackColumnOperation, 120);
    eventTable_->setColumnWidth(kCallbackColumnProcess, 160);
    eventTable_->setColumnWidth(kCallbackColumnPidTid, 110);
    eventTable_->setColumnWidth(kCallbackColumnTarget, 120);
    eventTable_->setColumnWidth(kCallbackColumnResult, 100);
    eventTable_->setColumnWidth(kCallbackColumnPath, 360);
    eventTable_->setColumnWidth(kCallbackColumnSummary, 260);

    detailEdit_ = new QPlainTextEdit(this);
    detailEdit_->setReadOnly(true);
    detailEdit_->setPlaceholderText(QStringLiteral("选择事件后查看完整字段详情"));
    QSplitter* resultSplitter = new QSplitter(Qt::Vertical, this);
    resultSplitter->addWidget(eventTable_);
    resultSplitter->addWidget(detailEdit_);
    resultSplitter->setStretchFactor(0, 4);
    resultSplitter->setStretchFactor(1, 1);
    resultSplitter->setSizes(QList<int>{ 620, 150 });
    rootLayout_->addWidget(resultSplitter, 1);

    uiTimer_ = new QTimer(this);
    uiTimer_->setInterval(100);
    uiTimer_->start();
}

void KernelCallbackMonitorWidget::initializeConnections()
{
    connect(startButton_, &QPushButton::clicked, this, [this]() { startCapture(); });
    connect(stopButton_, &QPushButton::clicked, this, [this]() { stopCapture(false); });
    connect(pauseButton_, &QPushButton::clicked, this, [this]() { setPaused(!paused_.load()); });
    connect(clearButton_, &QPushButton::clicked, this, [this]() { clearLocalEvents(); });
    connect(exportButton_, &QPushButton::clicked, this, [this]() { exportVisibleRows(); });
    connect(uiTimer_, &QTimer::timeout, this, [this]() { flushPendingEvents(); });
    connect(maxRowsSpin_, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](const int value) {
        pendingLimit_.store(value);
        eventModel_->trimRows(value);
        updateStatusLabel();
    });

    const auto kFilterChanged = [this]() { applyFilters(); };
    connect(categoryFilterCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, kFilterChanged);
    connect(operationFilterEdit_, &QLineEdit::textChanged, this, kFilterChanged);
    connect(pidFilterEdit_, &QLineEdit::textChanged, this, kFilterChanged);
    connect(processFilterEdit_, &QLineEdit::textChanged, this, kFilterChanged);
    connect(pathFilterEdit_, &QLineEdit::textChanged, this, kFilterChanged);
    connect(resultFilterEdit_, &QLineEdit::textChanged, this, kFilterChanged);
    connect(regexCheck_, &QCheckBox::toggled, this, kFilterChanged);
    connect(eventTable_->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this]() {
        updateDetailPanel();
    });
}

unsigned long KernelCallbackMonitorWidget::selectedCategoryMask() const
{
    unsigned long mask = 0UL;
    if (processCheck_->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
    if (threadCheck_->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
    if (imageCheck_->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
    if (registryCheck_->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY;
    if (objectCheck_->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
    if (fileCheck_->isChecked()) mask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
    return mask;
}

void KernelCallbackMonitorWidget::startCapture()
{
    const unsigned long kMask = selectedCategoryMask();
    if (kMask == 0UL)
    {
        lastDisplayedError_ = QStringLiteral("请至少选择一个采集类别");
        updateStatusLabel();
        return;
    }
    if (captureRunning_.load())
    {
        setPaused(false);
        return;
    }
    if (worker_.joinable())
    {
        worker_.join();
    }

    ksword::ark::DriverClient client;
    if (driverCaptureActive_.load())
    {
        const ksword::ark::CallbackMonitorStatusResult kCleanupStatus = client.controlCallbackMonitor(
            KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
            0UL);
        if (!kCleanupStatus.io.ok)
        {
            lastDisplayedError_ = QString::fromStdString(kCleanupStatus.io.message);
            updateActionState();
            updateStatusLabel();
            return;
        }
        driverCaptureActive_.store(false);
        runtimeFlags_.store(kCleanupStatus.runtimeFlags);
        activeCategoryMask_.store(kCleanupStatus.categoryMask);
    }
    const ksword::ark::CallbackMonitorStatusResult kStatus = client.controlCallbackMonitor(
        KSWORD_ARK_CALLBACK_MONITOR_ACTION_START,
        kMask);
    if (!kStatus.io.ok)
    {
        lastDisplayedError_ = kStatus.unsupported
            ? QStringLiteral("当前驱动不支持内核回调监控，请更新驱动")
            : QString::fromStdString(kStatus.io.message);
        updateStatusLabel();
        return;
    }

    workerStop_.store(false);
    paused_.store(false);
    cursorResetRequested_.store(false);
    readerGeneration_.fetch_add(1ULL);
    latestSequence_.store(kStatus.latestSequence);
    cursorResetValue_.store(kStatus.latestSequence);
    cursorResetRequested_.store(true);
    r0DroppedCount_.store(kStatus.droppedCount);
    cursorLostCount_.store(0ULL);
    r3DroppedCount_.store(0ULL);
    runtimeFlags_.store(kStatus.runtimeFlags);
    activeCategoryMask_.store(kStatus.categoryMask);
    ringCapacity_.store(kStatus.ringCapacity);
    lastDisplayedError_.clear();
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingEvents_.clear();
        workerError_.clear();
        workerUnsupported_ = false;
    }
    eventModel_->clearRows();
    driverCaptureActive_.store(true);
    captureRunning_.store(true);
    worker_ = std::thread(&KernelCallbackMonitorWidget::workerMain, this);
    updateActionState();
    updateStatusLabel();
}

void KernelCallbackMonitorWidget::stopCapture(const bool destroying)
{
    const bool kWasRunning = captureRunning_.exchange(false);
    workerStop_.store(true);
    workerWake_.notify_all();
    if (worker_.joinable())
    {
        worker_.join();
    }
    paused_.store(false);
    if (kWasRunning || driverCaptureActive_.load())
    {
        ksword::ark::DriverClient client;
        const ksword::ark::CallbackMonitorStatusResult kStatus = client.controlCallbackMonitor(
            KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
            0UL);
        if (!destroying && !kStatus.io.ok)
        {
            lastDisplayedError_ = QString::fromStdString(kStatus.io.message);
        }
        if (kStatus.io.ok)
        {
            driverCaptureActive_.store(false);
        }
        runtimeFlags_.store(kStatus.runtimeFlags);
        activeCategoryMask_.store(kStatus.categoryMask);
    }
    if (!destroying)
    {
        updateActionState();
        updateStatusLabel();
    }
}

void KernelCallbackMonitorWidget::setPaused(const bool paused)
{
    if (!captureRunning_.load())
    {
        return;
    }
    paused_.store(paused);
    updateActionState();
    updateStatusLabel();
}

void KernelCallbackMonitorWidget::clearLocalEvents()
{
    ksword::ark::DriverClient client;
    const auto kStatus = client.queryCallbackMonitorStatus();
    const std::uint64_t kLatest = kStatus.io.ok ? kStatus.latestSequence : latestSequence_.load();
    if (kStatus.io.ok)
    {
        ringCapacity_.store(kStatus.ringCapacity);
    }
    readerGeneration_.fetch_add(1ULL);
    cursorResetValue_.store(kLatest);
    cursorResetRequested_.store(true);
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingEvents_.clear();
    }
    eventModel_->clearRows();
    cursorLostCount_.store(0ULL);
    r3DroppedCount_.store(0ULL);
    detailEdit_->clear();
    applyFilters();
    updateStatusLabel();
    workerWake_.notify_all();
}

void KernelCallbackMonitorWidget::workerMain()
{
    ksword::ark::DriverClient client;
    const auto kStopDriverAfterFailure = [this, &client](ksword::ark::DriverHandle* const existingHandle) {
        const ksword::ark::CallbackMonitorStatusResult kStopStatus = existingHandle != nullptr
            ? client.controlCallbackMonitor(
                *existingHandle,
                KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
                0UL)
            : client.controlCallbackMonitor(
                KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
                0UL);
        if (kStopStatus.io.ok)
        {
            driverCaptureActive_.store(false);
            runtimeFlags_.store(kStopStatus.runtimeFlags);
            activeCategoryMask_.store(kStopStatus.categoryMask);
        }
        captureRunning_.store(false);
        paused_.store(false);
        workerStop_.store(true);
    };

    ksword::ark::DriverHandle handle = client.open();
    if (!handle.isValid())
    {
        recordWorkerFailure("open KswordARK control device failed", false);
        kStopDriverAfterFailure(nullptr);
        return;
    }

    std::uint64_t cursor = cursorResetValue_.load();
    while (!workerStop_.load())
    {
        if (cursorResetRequested_.exchange(false))
        {
            cursor = cursorResetValue_.load();
        }
        const std::uint64_t kGeneration = readerGeneration_.load();
        ksword::ark::CallbackMonitorReadResult readResult = client.readCallbackMonitor(
            handle,
            cursor,
            KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS);
        if (!readResult.io.ok)
        {
            recordWorkerFailure(readResult.io.message, readResult.unsupported);
            kStopDriverAfterFailure(&handle);
            break;
        }
        if (kGeneration != readerGeneration_.load())
        {
            continue;
        }

        cursor = readResult.nextSequence;
        latestSequence_.store(readResult.latestSequence);
        r0DroppedCount_.store(readResult.droppedCount);
        cursorLostCount_.fetch_add(readResult.lostBeforeFirst);
        runtimeFlags_.store(readResult.runtimeFlags);
        activeCategoryMask_.store(readResult.categoryMask);
        ringCapacity_.store(readResult.ringCapacity);
        if (!readResult.records.empty())
        {
            std::lock_guard<std::mutex> lock(pendingMutex_);
            for (auto& record : readResult.records)
            {
                pendingEvents_.push_back(std::move(record));
            }
            const std::size_t kLimit = static_cast<std::size_t>(std::max(1000, pendingLimit_.load()));
            while (pendingEvents_.size() > kLimit)
            {
                pendingEvents_.pop_front();
                r3DroppedCount_.fetch_add(1ULL);
            }
        }

        if ((readResult.responseFlags & KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_MORE_AVAILABLE) == 0UL)
        {
            std::unique_lock<std::mutex> lock(pendingMutex_);
            workerWake_.wait_for(lock, std::chrono::milliseconds(80), [this]() {
                return workerStop_.load();
            });
        }
    }
}

void KernelCallbackMonitorWidget::recordWorkerFailure(
    const std::string& message,
    const bool unsupported)
{
    std::lock_guard<std::mutex> lock(pendingMutex_);
    workerError_ = message;
    workerUnsupported_ = unsupported;
}

void KernelCallbackMonitorWidget::flushPendingEvents()
{
    std::string workerError;
    bool workerUnsupported = false;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        workerError = workerError_;
        workerUnsupported = workerUnsupported_;
        workerError_.clear();
    }
    if (!workerError.empty())
    {
        lastDisplayedError_ = workerUnsupported
            ? QStringLiteral("当前驱动不支持内核回调监控，请更新驱动")
            : QString::fromStdString(workerError);
        updateActionState();
    }

    if (paused_.load() ||
        ks::ui::isTableUiCommitBlockedByContextMenu(QList<QTableView*>{ eventTable_ }))
    {
        updateStatusLabel();
        return;
    }

    std::vector<ksword::ark::CallbackMonitorEventRow> batch;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        const std::size_t kBatchSize = std::min<std::size_t>(pendingEvents_.size(), 1000U);
        batch.reserve(kBatchSize);
        for (std::size_t index = 0U; index < kBatchSize; ++index)
        {
            batch.push_back(std::move(pendingEvents_.front()));
            pendingEvents_.pop_front();
        }
    }
    if (!batch.empty())
    {
        const bool kKeepBottom = keepBottomCheck_->isChecked() &&
            eventTable_->verticalScrollBar()->value() >=
                eventTable_->verticalScrollBar()->maximum() - 2;
        eventModel_->appendRows(std::move(batch), maxRowsSpin_->value());
        if (kKeepBottom)
        {
            eventTable_->scrollToBottom();
        }
        applyFilters();
    }
    updateStatusLabel();
}

void KernelCallbackMonitorWidget::applyFilters()
{
    filterModel_->setFilters(
        categoryFilterCombo_->currentData().toUInt(),
        operationFilterEdit_->text(),
        pidFilterEdit_->text(),
        processFilterEdit_->text(),
        pathFilterEdit_->text(),
        resultFilterEdit_->text(),
        regexCheck_->isChecked());
    filterStatusLabel_->setText(filterModel_->invalidRegex()
        ? ks::i18n::sourceText(QStringLiteral("正则表达式无效"))
        : ks::i18n::sourceText(QStringLiteral("筛选结果：%1 / %2"))
            .arg(filterModel_->rowCount())
            .arg(eventModel_->rowCount()));
}

void KernelCallbackMonitorWidget::updateActionState()
{
    const bool kRunning = captureRunning_.load();
    const bool kPaused = paused_.load();
    startButton_->setEnabled(!kRunning || kPaused);
    stopButton_->setEnabled(kRunning || driverCaptureActive_.load());
    pauseButton_->setEnabled(kRunning);
    pauseButton_->setIcon(QIcon(kPaused
        ? QStringLiteral(":/Icon/process_start.svg")
        : QStringLiteral(":/Icon/process_pause.svg")));
    pauseButton_->setToolTip(ks::i18n::sourceText(kPaused
        ? QStringLiteral("继续把后台事件提交到表格")
        : QStringLiteral("暂停事件入表，后台继续读取")));
    const QList<QCheckBox*> kCategoryChecks{
        processCheck_, threadCheck_, imageCheck_, registryCheck_, objectCheck_, fileCheck_
    };
    for (QCheckBox* checkBox : kCategoryChecks)
    {
        checkBox->setEnabled(!kRunning);
    }
}

void KernelCallbackMonitorWidget::updateStatusLabel()
{
    std::size_t pendingCount = 0U;
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        pendingCount = pendingEvents_.size();
    }
    QString stateText = ks::i18n::sourceText(QStringLiteral("空闲"));
    if (captureRunning_.load())
    {
        stateText = ks::i18n::sourceText(
            paused_.load() ? QStringLiteral("暂停显示") : QStringLiteral("正在采集"));
    }
    if (!lastDisplayedError_.isEmpty())
    {
        stateText = ks::i18n::sourceText(QStringLiteral("错误：%1"))
            .arg(ks::i18n::sourceText(lastDisplayedError_));
    }
    statusLabel_->setText(ks::i18n::sourceText(QStringLiteral(
        "● %1 | 类别 0x%2 | R0 容量 %3 | 最新 %4 | R0 丢弃 %5 | 游标丢失 %6 | R3 丢弃 %7 | 待提交 %8 | 行 %9 / %10"))
        .arg(stateText)
        .arg(activeCategoryMask_.load(), 2, 16, QLatin1Char('0'))
        .arg(ringCapacity_.load())
        .arg(latestSequence_.load())
        .arg(r0DroppedCount_.load())
        .arg(cursorLostCount_.load())
        .arg(r3DroppedCount_.load())
        .arg(pendingCount)
        .arg(filterModel_->rowCount())
        .arg(eventModel_->rowCount()));
}

void KernelCallbackMonitorWidget::updateDetailPanel()
{
    const QModelIndex kCurrentIndex = eventTable_->currentIndex();
    if (!kCurrentIndex.isValid())
    {
        detailEdit_->clear();
        return;
    }
    const QModelIndex kSourceIndex = filterModel_->mapToSource(kCurrentIndex);
    const auto* row = eventModel_->rowAt(kSourceIndex.row());
    if (row == nullptr)
    {
        detailEdit_->clear();
        return;
    }

    const QString kDetailText = ks::i18n::sourceText(QStringLiteral(
        "序号：%1\n时间：%2\n类别：%3\n操作：%4\n来源 PID/TID：%5\n目标 PID/TID：%6\n父 PID：%7\nSession：%8\n结果：%9\n原始/最终访问：0x%10 / 0x%11\n对象类型：%12\nDetailCode：0x%13\n地址/大小：0x%14 / 0x%15\n进程：%16\n路径：%17\n事件标志：0x%18"))
        .arg(row->sequence)
        .arg(callbackTimeText(row->timeUtc100ns))
        .arg(ks::i18n::sourceText(callbackCategoryText(row->category)))
        .arg(ks::i18n::sourceText(callbackOperationText(*row)))
        .arg(callbackPidTidText(*row))
        .arg(callbackTargetText(*row))
        .arg(row->parentProcessId)
        .arg(row->sessionId)
        .arg(callbackResultText(*row))
        .arg(row->originalAccess, 8, 16, QLatin1Char('0'))
        .arg(row->desiredAccess, 8, 16, QLatin1Char('0'))
        .arg(row->objectType)
        .arg(row->detailCode, 8, 16, QLatin1Char('0'))
        .arg(row->address, 0, 16)
        .arg(row->regionSize, 0, 16)
        .arg(QString::fromStdWString(row->processName))
        .arg(QString::fromStdWString(row->path))
        .arg(row->flags, 8, 16, QLatin1Char('0'));
    detailEdit_->setPlainText(kDetailText);
}

void KernelCallbackMonitorWidget::exportVisibleRows()
{
    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        ks::i18n::sourceText(QStringLiteral("导出内核回调事件")),
        QStringLiteral("kernel-callback-events.csv"),
        ks::i18n::sourceText(QStringLiteral("CSV 文件 (*.csv);;所有文件 (*.*)")));
    if (kOutputPath.isEmpty())
    {
        return;
    }
    QSaveFile outputFile(kOutputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        lastDisplayedError_ = QStringLiteral("无法创建导出文件");
        updateStatusLabel();
        return;
    }

    QTextStream stream(&outputFile);
    stream.setEncoding(QStringConverter::Utf8);
    stream << QChar(0xFEFF);
    for (int column = 0; column < kCallbackColumnCount; ++column)
    {
        if (column != 0) stream << QLatin1Char(',');
        stream << QLatin1Char('"')
            << filterModel_->headerData(column, Qt::Horizontal, Qt::DisplayRole)
                .toString().replace(QLatin1Char('"'), QStringLiteral("\"\""))
            << QLatin1Char('"');
    }
    stream << QLatin1Char('\n');
    for (int row = 0; row < filterModel_->rowCount(); ++row)
    {
        for (int column = 0; column < kCallbackColumnCount; ++column)
        {
            if (column != 0) stream << QLatin1Char(',');
            QString text = filterModel_->index(row, column).data(Qt::DisplayRole).toString();
            text.replace(QLatin1Char('"'), QStringLiteral("\"\""));
            stream << QLatin1Char('"') << text << QLatin1Char('"');
        }
        stream << QLatin1Char('\n');
    }
    if (!outputFile.commit())
    {
        lastDisplayedError_ = QStringLiteral("写入导出文件失败");
        updateStatusLabel();
    }
}
