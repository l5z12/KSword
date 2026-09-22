#include "FileMappedProcessWindow.h"

// ============================================================
// FileMappedProcessWindow.cpp
// Purpose:
// - Implement file-mapped process reverse lookup window.
// - Query R0 Data/Image ControlArea mappings for each file via ArkDriverClient.
// - The UI only displays results and diagnostics; it does not directly invoke KswordARK DeviceIoControl.
// ============================================================

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/UiSupport.h"
#include "../ui/TableInteractionSupport.h"
#include "../../../shared/platform/log/Log.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QDir>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QThreadPool>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QResizeEvent>
#include <QSizePolicy>
#include <QVBoxLayout>

#include <TlHelp32.h>
#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <utility>

namespace
{
    // buildOpaqueDialogStyle purpose: Override parent transparent styles to ensure the dialog remains readable in light themes.
    // Parameter dialogObjectName: QDialog objectName.
    // Returns: QSS text.
    QString buildOpaqueDialogStyle(const QString& dialogObjectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(dialogObjectName);
    }

    // formatHex purpose: Format an integer as hexadecimal text with a 0x prefix.
    // Parameter value: the numeric value.
    // Parameter width: Hexadecimal width; 0 indicates no padding.
    // Returns: The formatted string.
    QString formatHex(const std::uint64_t value, const int width = 0)
    {
        if (width > 0)
        {
            return QStringLiteral("0x%1")
                .arg(static_cast<qulonglong>(value), width, 16, QChar('0'))
                .toUpper();
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    // buildDriverNtPath usage: convert a Win32 path to an NT path that the driver can open.
    // Parameter path: User-mode file path.
    // Return: Path with \??\ or \Device\ prefix; returns empty on failure.
    QString buildDriverNtPath(const QString& path)
    {
        const QString kNativePathText = QDir::toNativeSeparators(path).trimmed();
        if (kNativePathText.isEmpty())
        {
            return QString();
        }
        if (kNativePathText.startsWith(QStringLiteral("\\??\\")))
        {
            return kNativePathText;
        }
        if (kNativePathText.startsWith(QStringLiteral("\\\\?\\")))
        {
            return QStringLiteral("\\??\\") + kNativePathText.mid(4);
        }
        if (kNativePathText.startsWith(QStringLiteral("\\Device\\")))
        {
            return kNativePathText;
        }
        if (kNativePathText.startsWith(QStringLiteral("\\\\")))
        {
            return QStringLiteral("\\??\\UNC\\") + kNativePathText.mid(2);
        }
        return QStringLiteral("\\??\\") + kNativePathText;
    }

    // sectionKindText role: converts R0 sectionKind to UI text.
    // Parameter sectionKind: KSWORD_ARK_FILE_SECTION_KIND_*.
    // Return: Data/Image/Unknown.
    QString sectionKindText(const std::uint32_t sectionKind)
    {
        switch (sectionKind)
        {
        case KSWORD_ARK_FILE_SECTION_KIND_DATA:
            return QStringLiteral("Data");
        case KSWORD_ARK_FILE_SECTION_KIND_IMAGE:
            return QStringLiteral("Image");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // viewMapTypeText purpose: Convert ControlArea mapping types to UI text.
    // Parameter viewMapType: KSWORD_ARK_SECTION_MAP_TYPE_*.
    // Returns: The mapping type text.
    QString viewMapTypeText(const std::uint32_t viewMapType)
    {
        switch (viewMapType)
        {
        case KSWORD_ARK_SECTION_MAP_TYPE_PROCESS:
            return QStringLiteral("Process");
        case KSWORD_ARK_SECTION_MAP_TYPE_SESSION:
            return QStringLiteral("Session");
        case KSWORD_ARK_SECTION_MAP_TYPE_SYSTEM_CACHE:
            return QStringLiteral("SystemCache");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // queryStatusText: Converts the file Section query status into human-readable text.
    // Parameter queryStatus: KSWORD_ARK_FILE_SECTION_QUERY_STATUS_*.
    // Returns: Status string.
    QString queryStatusText(const std::uint32_t queryStatus)
    {
        switch (queryStatus)
        {
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData Missing");
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OPEN_FAILED:
            return QStringLiteral("File Open Failed");
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OBJECT_FAILED:
            return QStringLiteral("FileObject Failed");
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_SECTION_POINTERS_MISSING:
            return QStringLiteral("SectionObjectPointer Missing");
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_CONTROL_AREA_MISSING:
            return QStringLiteral("ControlArea Missing");
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED:
            return QStringLiteral("Mapping Query Failed");
        case KSWORD_ARK_FILE_SECTION_QUERY_STATUS_BUFFER_TOO_SMALL:
            return QStringLiteral("Buffer Too Small");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // fileSectionIoMessageText:
    // Translate low-level IO text from ArkDriverClient into diagnostic messages that the file-mapped window can display directly.
    // - Parameter messageText: A narrow string returned by DriverClient, which may contain internal fields such as DeviceIoControl or operation.
    // - Returns: User-facing Chinese description, preserving key signals like 'unsupported'/'unavailable' while hiding implementation noise.
    QString fileSectionIoMessageText(const std::string& messageText)
    {
        const QString kRawMessageText = QString::fromStdString(messageText).trimmed();
        if (kRawMessageText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明。");
        }

        const QString kLowerMessageText = kRawMessageText.toLower();
        if (kLowerMessageText.contains(QStringLiteral("unsupported")) ||
            kLowerMessageText.contains(QStringLiteral("not supported")) ||
            kLowerMessageText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return QStringLiteral("当前驱动不支持文件映射反查。");
        }
        if (kLowerMessageText.contains(QStringLiteral("unavailable")) ||
            kLowerMessageText.contains(QStringLiteral("device handle unavailable")))
        {
            return QStringLiteral("KswordARK 驱动当前不可用或尚未打开。");
        }
        if (kLowerMessageText.contains(QStringLiteral("buffer too small")) ||
            kLowerMessageText.contains(QStringLiteral("buffer_too_small")))
        {
            return QStringLiteral("驱动返回缓冲区不足，结果可能被截断。");
        }
        if (kLowerMessageText.contains(QStringLiteral("deviceiocontrol")))
        {
            return QStringLiteral("文件映射查询失败，请确认驱动已加载且版本匹配。");
        }
        if (kLowerMessageText.contains(QStringLiteral("file-section path invalid")) ||
            kLowerMessageText.contains(QStringLiteral("path invalid")))
        {
            return QStringLiteral("传入驱动的 NT 文件路径无效。");
        }

        return kRawMessageText;
    }

    // collectProcessNameMap purpose: Collects PID -> process name mapping to avoid repeated Toolhelp calls per line.
    // Parameters: None.
    // Returns: a map from PID to exe name.
    std::map<std::uint32_t, QString> collectProcessNameMap()
    {
        std::map<std::uint32_t, QString> processNameMap;
        const HANDLE kSnapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (kSnapshotHandle == INVALID_HANDLE_VALUE)
        {
            return processNameMap;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(kSnapshotHandle, &processEntry) != FALSE)
        {
            do
            {
                processNameMap[processEntry.th32ProcessID] = QString::fromWCharArray(processEntry.szExeFile);
            } while (::Process32NextW(kSnapshotHandle, &processEntry) != FALSE);
        }
        ::CloseHandle(kSnapshotHandle);
        return processNameMap;
    }

    // appendUniqueLine purpose: Append deduplicated text to the diagnostic list.
    // Parameter lines: The diagnostic list.
    // Parameter line: The text to append.
    // Returns: Nothing.
    void appendUniqueLine(QStringList& lines, const QString& line)
    {
        const QString kNormalizedLine = line.trimmed();
        if (!kNormalizedLine.isEmpty() && !lines.contains(kNormalizedLine))
        {
            lines.push_back(kNormalizedLine);
        }
    }
}

FileMappedProcessWindow::FileMappedProcessWindow(const std::vector<QString>& targetPaths, QWidget* parent)
    : QDialog(parent)
    , targetPaths_(targetPaths)
{
    initializeUi();
    initializeConnections();
    requestRefresh(true);
}

void FileMappedProcessWindow::setOpenProcessDetailCallback(OpenProcessDetailCallback callback)
{
    openProcessDetailCallback_ = std::move(callback);
}

void FileMappedProcessWindow::resizeEvent(QResizeEvent* event)
{
    QDialog::resizeEvent(event);
    applyAdaptiveColumnWidths();
}

void FileMappedProcessWindow::initializeUi()
{
    setObjectName(QStringLiteral("FileMappedProcessWindowRoot"));
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);
    setStyleSheet(buildOpaqueDialogStyle(objectName()));
    setWindowTitle(QStringLiteral("文件映射进程(R0 Section/ControlArea)"));
    ks::ui::applyResponsiveWindowGeometry(
        this,
        parentWidget(),
        QSize(1120, 680),
        QSize(720, 480));

    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(8, 8, 8, 8);
    rootLayout_->setSpacing(6);

    toolbarLayout_ = new QHBoxLayout();
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    refreshButton_ = new QPushButton(this);
    refreshButton_->setIcon(QIcon(":/Icon/handle_refresh.svg"));
    ksword_theme::applyCompactIconButtonMetrics(refreshButton_);
    refreshButton_->setToolTip(QStringLiteral("刷新 R0 映射进程扫描"));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    openProcessButton_ = new QPushButton(this);
    openProcessButton_->setIcon(QIcon(":/Icon/process_details.svg"));
    ksword_theme::applyCompactIconButtonMetrics(openProcessButton_);
    openProcessButton_->setToolTip(QStringLiteral("转到当前行进程详情"));
    openProcessButton_->setStyleSheet(ksword_theme::themedButtonStyle());

    QStringList targetTextList;
    for (const QString& pathText : targetPaths_)
    {
        targetTextList.push_back(QDir::toNativeSeparators(pathText));
    }
    targetLabel_ = new QLabel(QStringLiteral("目标：%1").arg(targetTextList.join(QStringLiteral(" | "))), this);
    targetLabel_->setMinimumWidth(0);
    targetLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    targetLabel_->setToolTip(targetLabel_->text());
    targetLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    targetLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textPrimaryHex()));

    statusLabel_ = new QLabel(QStringLiteral("● 等待扫描"), this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setMinimumWidth(0);
    statusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));

    resultTable_ = new QTreeWidget(this);
    resultTable_->setColumnCount(static_cast<int>(TableColumn::kCount));
    resultTable_->setHeaderLabels(QStringList{
        QStringLiteral("目标文件"),
        QStringLiteral("Section"),
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("映射类型"),
        QStringLiteral("Base"),
        QStringLiteral("End"),
        QStringLiteral("大小"),
        QStringLiteral("ControlArea")
        });
    resultTable_->setRootIsDecorated(false);
    resultTable_->setItemsExpandable(false);
    resultTable_->setAlternatingRowColors(true);
    resultTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    resultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    resultTable_->setSortingEnabled(true);
    resultTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    if (resultTable_->header() != nullptr)
    {
        resultTable_->header()->setSectionResizeMode(QHeaderView::Interactive);
        resultTable_->header()->setStretchLastSection(false);
    }

    toolbarLayout_->addWidget(refreshButton_);
    toolbarLayout_->addWidget(openProcessButton_);
    toolbarLayout_->addWidget(targetLabel_, 1);
    rootLayout_->addLayout(toolbarLayout_);
    rootLayout_->addWidget(statusLabel_);
    rootLayout_->addWidget(resultTable_, 1);
    applyAdaptiveColumnWidths();
}

void FileMappedProcessWindow::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            requestRefresh(true);
        });
    connect(openProcessButton_, &QPushButton::clicked, this, [this]()
        {
            openCurrentProcessDetail();
        });
    connect(resultTable_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            showTableContextMenu(localPosition);
        });
}

void FileMappedProcessWindow::requestRefresh(const bool forceRefresh)
{
    if (refreshInProgress_)
    {
        if (forceRefresh)
        {
            refreshPending_ = true;
        }
        return;
    }

    const std::uint64_t kCurrentTicket = ++refreshTicket_;
    refreshInProgress_ = true;
    statusLabel_->setText(QStringLiteral("● 正在通过 R0 查询 Section/ControlArea 映射..."));
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(ksword_theme::kPrimaryBlueHex));

    if (refreshProgressPid_ <= 0)
    {
        refreshProgressPid_ = kPro.addReusable(this, "文件映射", "准备 R0 Section 反查");
    }
    kPro.set(refreshProgressPid_, "后台查询文件映射进程", 0, 20.0f);

    const std::vector<QString> kTargetPathsSnapshot = targetPaths_;
    const int kProgressPid = refreshProgressPid_;
    QPointer<FileMappedProcessWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kCurrentTicket, kTargetPathsSnapshot, kProgressPid]()
        {
            const auto kBeginTime = std::chrono::steady_clock::now();
            RefreshResult refreshResult{};
            QStringList diagnosticLines;
            std::set<QString> dedupeKeys;
            const std::map<std::uint32_t, QString> kProcessNameMap = collectProcessNameMap();
            const ksword::ark::DriverClient kDriverClient;

            for (const QString& targetPath : kTargetPathsSnapshot)
            {
                QFileInfo fileInfo(targetPath);
                if (!fileInfo.exists() || !fileInfo.isFile())
                {
                    appendUniqueLine(diagnosticLines, QStringLiteral("%1: 不是可扫描文件").arg(QDir::toNativeSeparators(targetPath)));
                    continue;
                }

                const QString kNtPath = buildDriverNtPath(fileInfo.absoluteFilePath());
                if (kNtPath.isEmpty())
                {
                    appendUniqueLine(diagnosticLines, QStringLiteral("%1: NT路径转换失败").arg(QDir::toNativeSeparators(targetPath)));
                    continue;
                }

                const ksword::ark::FileSectionMappingsQueryResult kQueryResult =
                    kDriverClient.queryFileSectionMappings(
                        kNtPath.toStdWString(),
                        KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL,
                        KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
                if (!kQueryResult.io.ok)
                {
                    appendUniqueLine(
                        diagnosticLines,
                        QStringLiteral("%1: IO失败 %2")
                            .arg(QDir::toNativeSeparators(targetPath), fileSectionIoMessageText(kQueryResult.io.message)));
                    continue;
                }

                appendUniqueLine(
                    diagnosticLines,
                    QStringLiteral("%1: %2 total=%3 returned=%4 dataCA=%5 imageCA=%6")
                        .arg(QFileInfo(targetPath).fileName())
                        .arg(queryStatusText(kQueryResult.queryStatus))
                        .arg(kQueryResult.totalCount)
                        .arg(kQueryResult.returnedCount)
                        .arg(formatHex(kQueryResult.dataControlAreaAddress))
                        .arg(formatHex(kQueryResult.imageControlAreaAddress)));

                for (const ksword::ark::FileSectionMappingEntry& mappingEntry : kQueryResult.mappings)
                {
                    const QString kDedupeKey = QStringLiteral("%1|%2|%3|%4|%5")
                        .arg(QDir::toNativeSeparators(fileInfo.absoluteFilePath()).toLower())
                        .arg(mappingEntry.sectionKind)
                        .arg(mappingEntry.processId)
                        .arg(static_cast<qulonglong>(mappingEntry.startVa), 0, 16)
                        .arg(static_cast<qulonglong>(mappingEntry.endVa), 0, 16);
                    if (dedupeKeys.find(kDedupeKey) != dedupeKeys.end())
                    {
                        continue;
                    }
                    dedupeKeys.insert(kDedupeKey);

                    MappedProcessRow row{};
                    row.targetPath = fileInfo.absoluteFilePath();
                    row.map = mappingEntry;
                    const auto kProcessNameIt = kProcessNameMap.find(mappingEntry.processId);
                    row.processName = (kProcessNameIt != kProcessNameMap.end())
                        ? kProcessNameIt->second
                        : QStringLiteral("PID %1").arg(mappingEntry.processId);
                    refreshResult.rows.push_back(std::move(row));
                }

                if (kProgressPid > 0)
                {
                    kPro.set(kProgressPid, "正在合并文件映射进程结果", 0, 70.0f);
                }
            }

            std::sort(
                refreshResult.rows.begin(),
                refreshResult.rows.end(),
                [](const MappedProcessRow& left, const MappedProcessRow& right)
                {
                    if (left.targetPath.compare(right.targetPath, Qt::CaseInsensitive) != 0)
                    {
                        return left.targetPath.compare(right.targetPath, Qt::CaseInsensitive) < 0;
                    }
                    if (left.map.processId != right.map.processId)
                    {
                        return left.map.processId < right.map.processId;
                    }
                    if (left.map.sectionKind != right.map.sectionKind)
                    {
                        return left.map.sectionKind < right.map.sectionKind;
                    }
                    return left.map.startVa < right.map.startVa;
                });

            refreshResult.diagnosticText = diagnosticLines.join(QStringLiteral(" | "));
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());

            if (guardThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kCurrentTicket, refreshResult]()
                {
                    if (guardThis == nullptr)
                    {
                        return;
                    }
                    guardThis->applyRefreshResult(kCurrentTicket, refreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void FileMappedProcessWindow::applyRefreshResult(
    const std::uint64_t refreshTicket,
    const RefreshResult& refreshResult)
{
    if (refreshTicket < refreshTicket_)
    {
        return;
    }

    if (ks::ui::isItemViewUiCommitBlockedByContextMenu({ resultTable_ }))
    {
        const auto kRefreshSnapshot = std::make_shared<RefreshResult>(refreshResult);
        const QPointer<FileMappedProcessWindow> kSafeThis(this);
        if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("file-mapped-process-snapshot"),
            { resultTable_ },
            [kSafeThis, refreshTicket, kRefreshSnapshot]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyRefreshResult(refreshTicket, *kRefreshSnapshot);
                }
            }))
        {
            return;
        }
    }

    rows_ = refreshResult.rows;
    rebuildTable();
    refreshInProgress_ = false;
    kPro.set(refreshProgressPid_, "文件映射进程扫描完成", 0, 100.0f);

    QString statusText = QStringLiteral("● 扫描完成 %1 ms | 映射行:%2")
        .arg(refreshResult.elapsedMs)
        .arg(rows_.size());
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 存在诊断；详情已写入日志。");
        KLogEvent diagnosticEvent;
        warn << diagnosticEvent
            << "[FileMappedProcessWindow] scan completed with diagnostics, targetCount="
            << targetPaths_.size()
            << ", rowCount=" << rows_.size()
            << ", detail=" << refreshResult.diagnosticText.toStdString()
            << eol;
    }
    statusLabel_->setText(statusText);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg((rows_.empty() ? ksword_theme::warningColor() : ksword_theme::successColor())
            .name(QColor::HexRgb)));

    if (refreshPending_)
    {
        refreshPending_ = false;
        QMetaObject::invokeMethod(this, [this]()
            {
                requestRefresh(true);
            }, Qt::QueuedConnection);
    }
}

void FileMappedProcessWindow::rebuildTable()
{
    resultTable_->setSortingEnabled(false);
    resultTable_->clear();

    for (std::size_t rowIndex = 0; rowIndex < rows_.size(); ++rowIndex)
    {
        const MappedProcessRow& row = rows_[rowIndex];
        auto* item = new QTreeWidgetItem();
        const std::uint64_t kSizeBytes = (row.map.endVa > row.map.startVa)
            ? (row.map.endVa - row.map.startVa)
            : 0ULL;

        item->setText(static_cast<int>(TableColumn::kTargetPath), QDir::toNativeSeparators(row.targetPath));
        item->setText(static_cast<int>(TableColumn::kSectionKind), sectionKindText(row.map.sectionKind));
        item->setText(static_cast<int>(TableColumn::kProcessId), QString::number(row.map.processId));
        item->setText(static_cast<int>(TableColumn::kProcessName), row.processName);
        item->setText(static_cast<int>(TableColumn::kViewMapType), viewMapTypeText(row.map.viewMapType));
        item->setText(static_cast<int>(TableColumn::kBaseAddress), formatHex(row.map.startVa));
        item->setText(static_cast<int>(TableColumn::kEndAddress), formatHex(row.map.endVa));
        item->setText(static_cast<int>(TableColumn::kSize), QString::number(static_cast<qulonglong>(kSizeBytes)));
        item->setText(static_cast<int>(TableColumn::kControlArea), formatHex(row.map.controlAreaAddress));
        item->setData(static_cast<int>(TableColumn::kProcessId), Qt::UserRole, static_cast<qulonglong>(rowIndex));
        resultTable_->addTopLevelItem(item);
    }

    if (resultTable_->topLevelItemCount() > 0)
    {
        resultTable_->setCurrentItem(resultTable_->topLevelItem(0));
    }

    applyAdaptiveColumnWidths();
    resultTable_->setSortingEnabled(true);
}

const FileMappedProcessWindow::MappedProcessRow* FileMappedProcessWindow::selectedRow() const
{
    if (resultTable_ == nullptr || resultTable_->currentItem() == nullptr)
    {
        return nullptr;
    }
    const QVariant kRowIndexValue =
        resultTable_->currentItem()->data(static_cast<int>(TableColumn::kProcessId), Qt::UserRole);
    if (!kRowIndexValue.isValid())
    {
        return nullptr;
    }
    const std::size_t kRowIndex = static_cast<std::size_t>(kRowIndexValue.toULongLong());
    if (kRowIndex >= rows_.size())
    {
        return nullptr;
    }
    return &rows_[kRowIndex];
}

void FileMappedProcessWindow::openCurrentProcessDetail()
{
    const MappedProcessRow* row = selectedRow();
    if (row == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("进程详情"), QStringLiteral("请先选择一条映射记录。"));
        return;
    }
    if (row->map.processId == 0)
    {
        QMessageBox::information(this, QStringLiteral("进程详情"), QStringLiteral("当前映射没有关联进程 PID。"));
        return;
    }
    if (!openProcessDetailCallback_)
    {
        QMessageBox::warning(this, QStringLiteral("进程详情"), QStringLiteral("未配置进程详情跳转回调。"));
        return;
    }
    openProcessDetailCallback_(row->map.processId);
}

void FileMappedProcessWindow::copyCurrentRow()
{
    if (resultTable_ == nullptr || resultTable_->currentItem() == nullptr)
    {
        return;
    }

    QStringList fields;
    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::kCount); ++columnIndex)
    {
        fields.push_back(resultTable_->currentItem()->text(columnIndex));
    }
    QApplication::clipboard()->setText(fields.join('\t'));
}

void FileMappedProcessWindow::showTableContextMenu(const QPoint& localPosition)
{
    if (resultTable_ == nullptr)
    {
        return;
    }
    QTreeWidgetItem* clickedItem = resultTable_->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        return;
    }
    resultTable_->setCurrentItem(clickedItem);

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* openProcessAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/handle_copy_row.svg"), QStringLiteral("复制整行"));

    QAction* selectedAction = menu.exec(resultTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == openProcessAction)
    {
        openCurrentProcessDetail();
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyCurrentRow();
    }
}

void FileMappedProcessWindow::applyAdaptiveColumnWidths()
{
    if (resultTable_ == nullptr || resultTable_->header() == nullptr)
    {
        return;
    }

    QHeaderView* header = resultTable_->header();
    header->setSectionResizeMode(QHeaderView::Interactive);

    const int kViewportWidth = resultTable_->viewport()->width();
    if (kViewportWidth <= 0)
    {
        return;
    }

    const int kSectionWidth = 90;
    const int kPidWidth = 82;
    const int kNameWidth = 150;
    const int kTypeWidth = 120;
    const int kAddressWidth = 150;
    const int kSizeWidth = 100;
    const int kControlAreaWidth = 150;
    const int kFixedWidth = kSectionWidth + kPidWidth + kNameWidth + kTypeWidth + kAddressWidth * 2 + kSizeWidth + kControlAreaWidth;
    const int kTargetWidth = std::max(280, kViewportWidth - kFixedWidth - 24);

    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kTargetPath), kTargetWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kSectionKind), kSectionWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kProcessId), kPidWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kProcessName), kNameWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kViewMapType), kTypeWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kBaseAddress), kAddressWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kEndAddress), kAddressWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kSize), kSizeWidth);
    resultTable_->setColumnWidth(static_cast<int>(TableColumn::kControlArea), kControlAreaWidth);
}
