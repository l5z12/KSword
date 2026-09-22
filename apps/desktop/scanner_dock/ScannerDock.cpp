#include "ScannerDock.h"

#include "internationalization/LanguageManager.h"
#include "../../../shared/platform/scanner/AtomicFilePatch.h"
#include "../../../shared/platform/scanner/BinaryScanner.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QByteArray>
#include <QCheckBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QRegularExpression>
#include <QStyle>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#include <limits>
#include <mutex>
#include <utility>
#include <vector>

// ScannerAsyncState purpose: place worker re-entrancy targets in shared mutex state.
// The destructor clears the owner first. Workers can only submit queued calls under the same lock,
// eliminating QPointer check/data issues and receiver race conditions during application shutdown.
struct ScannerAsyncState
{
    std::mutex mutex;
    ScannerDock* owner = nullptr;
};

namespace
{
    // fromUtf8 function: Safely convert UTF-8 text from the scanning backend to a Qt string.
    // Parameter value: Backend text; Return value: QString ready for display.
    QString fromUtf8(const std::string& value)
    {
        return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
    }

    // bytesToHexPreview usage: limit the byte preview length in the confirmation dialog to prevent UI freezing from excessively large text.
    // Parameter bytes: bytes to preview; return value: uppercase hexadecimal summary.
    QString bytesToHexPreview(const QByteArray& bytes)
    {
        constexpr qsizetype kPreviewBytes = 128; // kPreviewBytes: Maximum number of bytes displayed in the confirmation dialog.
        const QByteArray kPreview = bytes.left(kPreviewBytes).toHex(' ').toUpper(); // preview: Hexadecimal prefix.
        if (bytes.size() <= kPreviewBytes)
        {
            return QString::fromLatin1(kPreview);
        }
        return QStringLiteral("%1 ... (%2 bytes)")
            .arg(QString::fromLatin1(kPreview))
            .arg(bytes.size());
    }

    // parseOffset: Parses a decimal or 0x-prefixed hex file offset.
    // Parameter text: user input; offsetOut: unsigned offset on success; Return value: validity status.
    bool parseOffset(const QString& text, std::uint64_t& offsetOut)
    {
        QString normalized = text.trimmed(); // normalized: The trimmed text with leading and trailing whitespace removed.
        int base = 10; // base: The radix used for Qt numeric conversion.
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized.remove(0, 2);
            base = 16;
        }

        bool ok = false; // ok: Whether the numeric conversion completed successfully.
        const qulonglong kValue = normalized.toULongLong(&ok, base); // value: Parsed file offset.
        if (!ok || normalized.isEmpty())
        {
            return false;
        }
        offsetOut = static_cast<std::uint64_t>(kValue);
        return true;
    }

    // parseReplacementBytes: Accepts common delimiters and strictly parses an even number of hexadecimal characters.
    // Parameters: text is user input; bytesOut is the parsed result; return value indicates whether non-empty bytes were obtained.
    bool parseReplacementBytes(const QString& text, QByteArray& bytesOut)
    {
        // tokens: Split only at explicit delimiters; 0x is allowed only as a prefix for each token.
        const QStringList kTokens = text.split(
            QRegularExpression(QStringLiteral("[\\s,:;_\\-]+")),
            Qt::SkipEmptyParts);
        QString normalized; // normalized: Concatenated continuous hexadecimal text after validation.
        for (QString token : kTokens)
        {
            if (token.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
            {
                token.remove(0, 2);
            }
            if (token.isEmpty() ||
                token.contains(QRegularExpression(QStringLiteral("[^0-9A-Fa-f]"))))
            {
                return false;
            }
            normalized += token;
        }
        if (normalized.isEmpty() ||
            (normalized.size() % 2) != 0)
        {
            return false;
        }

        bytesOut = QByteArray::fromHex(normalized.toLatin1());
        return !bytesOut.isEmpty() && bytesOut.size() * 2 == normalized.size();
    }

    // toByteVector purpose: Copy Qt byte array to an unsigned backend buffer.
    // Parameter bytes: Qt data; Return value: std::vector independently owning the content.
    std::vector<std::uint8_t> toByteVector(const QByteArray& bytes)
    {
        const auto* begin = reinterpret_cast<const std::uint8_t*>(bytes.constData()); // begin: Start address of the Qt buffer.
        return std::vector<std::uint8_t>(begin, begin + bytes.size());
    }

}

ScannerDock::ScannerDock(QWidget* parent)
    : QWidget(parent)
{
    asyncState_ = std::make_shared<ScannerAsyncState>();
    asyncState_->owner = this;
    setObjectName(QStringLiteral("ScannerDock"));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    buildUi();
    retranslateUi();
    setStatus("scanner.status.ready", "请选择 PE、ELF、Mach-O 或 ISO9660 镜像开始扫描。");
}

ScannerDock::~ScannerDock()
{
    ++scanGeneration_;
    ++patchGeneration_;
    if (asyncState_)
    {
        std::lock_guard<std::mutex> lock(asyncState_->mutex);
        asyncState_->owner = nullptr;
    }
}

void ScannerDock::buildUi()
{
    // rootLayout: Hosts the path toolbar, status hints, and two main function pages.
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(8);

    // pathLayout: Arranges path input, file selection, and scan action on the same row.
    auto* pathLayout = new QHBoxLayout();
    pathLayout->setSpacing(6);
    pathLabel_ = new QLabel(this);
    pathEdit_ = new QLineEdit(this);
    pathEdit_->setClearButtonEnabled(true);
    browseButton_ = new QPushButton(this);
    scanButton_ = new QPushButton(this);
    browseButton_->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
    scanButton_->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    pathLayout->addWidget(pathLabel_);
    pathLayout->addWidget(pathEdit_, 1);
    pathLayout->addWidget(browseButton_);
    pathLayout->addWidget(scanButton_);
    rootLayout->addLayout(pathLayout);

    // m_statusLabel: Allows copying diagnostic status; long paths wrap automatically.
    statusLabel_ = new QLabel(this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(statusLabel_);

    // m_mainTabs: Explicitly separates read-only checks from high-risk editing to prevent accidental triggers.
    mainTabs_ = new QTabWidget(this);
    mainTabs_->setDocumentMode(true);
    rootLayout->addWidget(mainTabs_, 1);

    // inspectionLayout: holds only the dynamic label set for the current results.
    inspectionPage_ = new QWidget(mainTabs_);
    auto* inspectionLayout = new QVBoxLayout(inspectionPage_);
    inspectionLayout->setContentsMargins(0, 0, 0, 0);
    resultTabs_ = new QTabWidget(inspectionPage_);
    resultTabs_->setDocumentMode(true);
    inspectionLayout->addWidget(resultTabs_);
    mainTabs_->addTab(inspectionPage_, QString());

    // editorLayout: Start directly from input controls; risk scope is attached to each control's tooltip.
    editorPage_ = new QWidget(mainTabs_);
    auto* editorLayout = new QVBoxLayout(editorPage_);
    editorLayout->setContentsMargins(12, 12, 12, 12);
    editorLayout->setSpacing(10);

    // editForm: Collects only offsets and new bytes required for equal-length replacements; does not provide insertion/deletion entry points.
    auto* editForm = new QFormLayout();
    editForm->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    offsetLabel_ = new QLabel(editorPage_);
    offsetEdit_ = new QLineEdit(editorPage_);
    offsetEdit_->setPlaceholderText(QStringLiteral("0x00000000"));
    replacementLabel_ = new QLabel(editorPage_);
    replacementEdit_ = new QLineEdit(editorPage_);
    replacementEdit_->setPlaceholderText(QStringLiteral("90 90 90 90"));
    editForm->addRow(offsetLabel_, offsetEdit_);
    editForm->addRow(replacementLabel_, replacementEdit_);
    editorLayout->addLayout(editForm);

    backupCheckBox_ = new QCheckBox(editorPage_);
    backupCheckBox_->setChecked(true);
    editorLayout->addWidget(backupCheckBox_);

    riskCheckBox_ = new QCheckBox(editorPage_);
    riskCheckBox_->setChecked(false);
    editorLayout->addWidget(riskCheckBox_);

    auto* applyLayout = new QHBoxLayout();
    applyLayout->addStretch(1);
    applyPatchButton_ = new QPushButton(editorPage_);
    applyPatchButton_->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
    applyLayout->addWidget(applyPatchButton_);
    editorLayout->addLayout(applyLayout);
    editorLayout->addStretch(1);
    mainTabs_->addTab(editorPage_, QString());

    // All button clicks and Enter key actions enter the same validation flow via ScannerDock methods.
    connect(browseButton_, &QPushButton::clicked, this, [this]() { chooseFile(); });
    connect(scanButton_, &QPushButton::clicked, this, [this]() { beginScan(); });
    connect(pathEdit_, &QLineEdit::returnPressed, this, [this]() { beginScan(); });
    connect(applyPatchButton_, &QPushButton::clicked, this, [this]() { beginPatch(); });
}

QString ScannerDock::translated(const char* key, const char* fallback) const
{
    return ks::i18n::text(
        QString::fromLatin1(key),
        QString::fromUtf8(fallback));
}

void ScannerDock::retranslateUi()
{
    pathLabel_->setText(translated("scanner.path.label", "文件路径"));
    pathEdit_->setPlaceholderText(translated(
        "scanner.path.placeholder",
        "选择要进行结构化解析和攻击路径检测的二进制文件或镜像"));
    browseButton_->setText(translated("scanner.action.browse", "浏览…"));
    scanButton_->setText(translated("scanner.action.scan", "扫描"));
    browseButton_->setToolTip(translated(
        "scanner.action.browse.tooltip",
        "选择要扫描或安全编辑的普通文件"));
    scanButton_->setToolTip(translated(
        "scanner.action.scan.tooltip",
        "在后台只读解析 PE、ELF、Mach-O 或 ISO9660/Joliet 结构与攻击路径"));
    mainTabs_->setTabText(
        mainTabs_->indexOf(inspectionPage_),
        translated("scanner.tab.inspection", "结构化扫描"));
    mainTabs_->setTabText(
        mainTabs_->indexOf(editorPage_),
        translated("scanner.tab.editor", "安全字节编辑"));
    offsetLabel_->setText(translated("scanner.editor.offset", "文件偏移"));
    replacementLabel_->setText(translated("scanner.editor.replacement", "替换字节（十六进制）"));
    replacementEdit_->setToolTip(translated(
        "scanner.editor.replacement.tooltip",
        "只支持等长替换：字节数必须与原始内容完全一致，不能插入或删除。"));
    backupCheckBox_->setText(translated(
        "scanner.editor.create_backup",
        "应用前创建独立备份（推荐）"));
    backupCheckBox_->setToolTip(translated(
        "scanner.editor.create_backup.tooltip",
        "备份是同目录下带时间戳的独立副本，不会覆盖之前的备份。"));
    riskCheckBox_->setText(translated(
        "scanner.editor.risk_ack",
        "我已核对目标、偏移和字节，并理解修改二进制文件的风险"));
    riskCheckBox_->setToolTip(translated(
        "scanner.editor.risk_ack.tooltip",
        "从释放文件锁到原子替换之间仍有极短竞态，其它进程的并发写入可能破坏快照校验。"));
    applyPatchButton_->setText(translated("scanner.editor.apply", "核对并应用"));
    applyPatchButton_->setToolTip(translated(
        "scanner.editor.apply.tooltip",
        "比较当前字节，最终确认后原子替换目标文件"));
    refreshStatus();

    if (lastResult_)
    {
        renderResult(*lastResult_);
    }
}

void ScannerDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
}

void ScannerDock::chooseFile()
{
    const QString kSelectedPath = QFileDialog::getOpenFileName(
        this,
        translated("scanner.dialog.choose_file", "选择二进制文件"),
        pathEdit_->text().trimmed(),
        translated(
            "scanner.dialog.file_filter",
            "二进制与镜像 (*.exe *.dll *.sys *.efi *.elf *.so *.dylib *.o *.bin *.img *.iso);;所有文件 (*.*)"));
    if (kSelectedPath.isEmpty())
    {
        return;
    }
    pathEdit_->setText(QDir::toNativeSeparators(kSelectedPath));
    beginScan();
}

void ScannerDock::beginScan()
{
    if (scanBusy_ || patchBusy_)
    {
        return;
    }

    // fileInfo: Exclude empty paths, directories, and non-existent targets before starting the thread.
    const QString kPath = QDir::toNativeSeparators(pathEdit_->text().trimmed());
    const QFileInfo kFileInfo(kPath);
    if (kPath.isEmpty() || !kFileInfo.exists() || !kFileInfo.isFile())
    {
        QMessageBox::warning(
            this,
            translated("scanner.dialog.invalid_file.title", "无法扫描"),
            translated("scanner.dialog.invalid_file.body", "请选择一个存在的普通文件。"));
        return;
    }

    pathEdit_->setText(kPath);
    setScanBusy(true);
    setStatus(
        "scanner.status.scanning",
        "正在扫描：%1",
        QStringList{ kPath });

    // generation: Only results from the latest generation can be written back to avoid old scans overwriting new targets.
    const std::uint64_t kGeneration = ++scanGeneration_;
    const std::wstring kNativePath = kPath.toStdWString();
    const std::shared_ptr<ScannerAsyncState> kAsyncState = asyncState_;
    QThreadPool::globalInstance()->start(
        [kAsyncState, kGeneration, kPath, kNativePath]()
        {
            auto result = std::make_shared<ks::scanner::BinaryScanResult>(
                ks::scanner::scanBinaryFile(kNativePath));
            std::lock_guard<std::mutex> lock(kAsyncState->mutex);
            ScannerDock* receiver = kAsyncState->owner;
            if (receiver == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [kAsyncState, kGeneration, kPath, result = std::move(result)]()
                {
                    ScannerDock* owner = nullptr;
                    {
                        std::lock_guard<std::mutex> stateLock(kAsyncState->mutex);
                        owner = kAsyncState->owner;
                    }
                    if (owner != nullptr)
                    {
                        owner->finishScan(kGeneration, kPath, result);
                    }
                },
                Qt::QueuedConnection);
        });
}

void ScannerDock::finishScan(
    const std::uint64_t generation,
    const QString& scannedPath,
    std::shared_ptr<ks::scanner::BinaryScanResult> result)
{
    if (generation != scanGeneration_.load() || !result)
    {
        return;
    }

    setScanBusy(false);
    lastResult_ = std::move(result);
    renderResult(*lastResult_);

    if (lastResult_->success && lastResult_->attackPath.matched)
    {
        setStatus(
            "scanner.status.attack_detected",
            "扫描完成并检测到 EXIT / GhostSystemDriver 攻击路径：%1，评分 %2/100。",
            QStringList{
                scannedPath,
                QString::number(lastResult_->attackPath.score)
            });
    }
    else if (lastResult_->success)
    {
        setStatus(
            "scanner.status.success",
            "扫描完成：%1，格式 %2，大小 %3 字节。",
            QStringList{
                scannedPath,
                QString::fromLatin1(ks::scanner::formatName(lastResult_->format)),
                QString::number(lastResult_->fileSize)
            });
    }
    else if (lastResult_->recognized)
    {
        setStatus(
            "scanner.status.malformed",
            "已识别格式，但文件结构无效或不完整：%1",
            QStringList{ scannedPath });
    }
    else
    {
        setStatus(
            "scanner.status.unsupported",
            "未识别为受支持的 PE、ELF、Mach-O 或 ISO9660 文件：%1",
            QStringList{ scannedPath });
    }
}

QTableWidget* ScannerDock::createReadOnlyTable(QWidget* parent) const
{
    auto* table = new QTableWidget(parent);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table->setAlternatingRowColors(true);
    table->setWordWrap(false);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setSectionsMovable(true);
    table->horizontalHeader()->setStretchLastSection(true);
    return table;
}

void ScannerDock::clearResultTabs()
{
    while (resultTabs_->count() > 0)
    {
        QWidget* page = resultTabs_->widget(0);
        resultTabs_->removeTab(0);
        delete page;
    }
}

void ScannerDock::renderResult(const ks::scanner::BinaryScanResult& result)
{
    clearResultTabs();

    auto* summaryTable = createReadOnlyTable(resultTabs_);
    summaryTable->setColumnCount(2);
    summaryTable->setHorizontalHeaderLabels({
        translated("scanner.column.field", "字段"),
        translated("scanner.column.value", "值")
    });

    // summaryFields: first place format-neutral metadata, then append backend-specific summaries and remove three duplicates.
    std::vector<ks::scanner::BinaryField> summaryFields{
        { "Format", ks::scanner::formatName(result.format) },
        { "Byte order", ks::scanner::byteOrderName(result.byteOrder) },
        { "File size", std::to_string(result.fileSize) }
    };
    for (const ks::scanner::BinaryField& field : result.summary)
    {
        const QString kNormalizedName = fromUtf8(field.name).trimmed().toLower(); // normalizedName: Field name used for summary deduplication.
        if (kNormalizedName == QStringLiteral("format") ||
            kNormalizedName == QStringLiteral("byte order") ||
            kNormalizedName == QStringLiteral("file size"))
        {
            continue;
        }
        summaryFields.push_back(field);
    }
    summaryTable->setRowCount(static_cast<int>(summaryFields.size()));
    for (int row = 0; row < summaryTable->rowCount(); ++row)
    {
        const auto& field = summaryFields[static_cast<std::size_t>(row)];
        summaryTable->setItem(row, 0, new QTableWidgetItem(localizedColumnTitle(field.name)));
        summaryTable->setItem(
            row,
            1,
            new QTableWidgetItem(ks::i18n::sourceText(fromUtf8(field.value))));
    }
    summaryTable->resizeColumnsToContents();
    resultTabs_->addTab(summaryTable, translated("scanner.result.summary", "摘要"));

    if (!result.attackPath.evidence.empty())
    {
        resultTabs_->addTab(
            createAttackPathPage(result),
            translated("scanner.result.attack_path", "攻击路径"));
    }

    auto* headerTable = createReadOnlyTable(resultTabs_);
    headerTable->setColumnCount(2);
    headerTable->setHorizontalHeaderLabels({
        translated("scanner.column.field", "字段"),
        translated("scanner.column.value", "值")
    });
    headerTable->setRowCount(static_cast<int>(result.headers.size()));
    for (int row = 0; row < headerTable->rowCount(); ++row)
    {
        const auto& field = result.headers[static_cast<std::size_t>(row)];
        headerTable->setItem(row, 0, new QTableWidgetItem(localizedColumnTitle(field.name)));
        headerTable->setItem(
            row,
            1,
            new QTableWidgetItem(ks::i18n::sourceText(fromUtf8(field.value))));
    }
    headerTable->resizeColumnsToContents();
    resultTabs_->addTab(headerTable, translated("scanner.result.headers", "文件头"));

    for (const ks::scanner::BinaryTable& sourceTable : result.tables)
    {
        // table: Created with stable backend column order; row count is already limited by ScanOptions on the backend.
        auto* table = createReadOnlyTable(resultTabs_);
        table->setColumnCount(static_cast<int>(sourceTable.columns.size()));
        QStringList columnTitles;
        for (const std::string& column : sourceTable.columns)
        {
            columnTitles.push_back(localizedColumnTitle(column));
        }
        table->setHorizontalHeaderLabels(columnTitles);
        table->setRowCount(static_cast<int>(sourceTable.rows.size()));
        for (int row = 0; row < table->rowCount(); ++row)
        {
            const auto& sourceRow = sourceTable.rows[static_cast<std::size_t>(row)];
            for (int column = 0; column < table->columnCount(); ++column)
            {
                const QString kValue = column < static_cast<int>(sourceRow.size())
                    ? localizedTableValue(
                        sourceTable.id,
                        column,
                        sourceRow[static_cast<std::size_t>(column)])
                    : QString();
                table->setItem(row, column, new QTableWidgetItem(kValue));
            }
        }
        table->resizeColumnsToContents();
        QString title = localizedTableTitle(sourceTable.id, sourceTable.title);
        if (sourceTable.truncated)
        {
            title += translated("scanner.result.truncated_suffix", "（已截断）");
        }
        resultTabs_->addTab(
            createStructuredTablePage(table, table->columnCount()),
            title);
    }

    auto* diagnosticsTable = createReadOnlyTable(resultTabs_);
    diagnosticsTable->setColumnCount(4);
    diagnosticsTable->setHorizontalHeaderLabels({
        translated("scanner.column.severity", "级别"),
        translated("scanner.column.code", "代码"),
        translated("scanner.column.message", "说明"),
        translated("scanner.column.offset", "偏移")
    });
    diagnosticsTable->setRowCount(static_cast<int>(result.diagnostics.size()));
    for (int row = 0; row < diagnosticsTable->rowCount(); ++row)
    {
        const auto& diagnostic = result.diagnostics[static_cast<std::size_t>(row)];
        diagnosticsTable->setItem(
            row,
            0,
            new QTableWidgetItem(diagnosticSeverityText(static_cast<int>(diagnostic.severity))));
        diagnosticsTable->setItem(row, 1, new QTableWidgetItem(fromUtf8(diagnostic.code)));
        diagnosticsTable->setItem(
            row,
            2,
            new QTableWidgetItem(
                localizedDiagnosticMessage(diagnostic.code, diagnostic.message)));
        diagnosticsTable->setItem(
            row,
            3,
            new QTableWidgetItem(
                diagnostic.hasOffset
                    ? QStringLiteral("0x%1").arg(diagnostic.offset, 0, 16).toUpper()
                    : QString()));
    }
    diagnosticsTable->resizeColumnsToContents();
    resultTabs_->addTab(
        diagnosticsTable,
        translated("scanner.result.diagnostics", "诊断"));
}

void ScannerDock::beginPatch()
{
    if (patchBusy_ || scanBusy_)
    {
        return;
    }

    // fileInfo: UI rejects directories and symlinks first; the backend rejects all reparse points.
    const QString kPath = QDir::toNativeSeparators(pathEdit_->text().trimmed());
    const QFileInfo kFileInfo(kPath);
    if (kPath.isEmpty() || !kFileInfo.exists() || !kFileInfo.isFile() || kFileInfo.isSymLink())
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.invalid_target.title", "无法编辑"),
            translated(
                "scanner.editor.invalid_target.body",
                "目标必须是存在的普通文件，不能是目录或符号链接。"));
        return;
    }

    std::uint64_t offset = 0;
    if (!parseOffset(offsetEdit_->text(), offset))
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.invalid_offset.title", "偏移无效"),
            translated(
                "scanner.editor.invalid_offset.body",
                "请输入十进制偏移，或以 0x 开头的十六进制偏移。"));
        return;
    }

    // replacementBytes: parsed result must be non-empty, cover the same length, and not exceed the backend hard limit.
    QByteArray replacementBytes;
    if (!parseReplacementBytes(replacementEdit_->text(), replacementBytes))
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.invalid_bytes.title", "替换字节无效"),
            translated(
                "scanner.editor.invalid_bytes.body",
                "请输入偶数个十六进制字符；可使用空格、逗号、冒号或短横线分隔。"));
        return;
    }

    constexpr qsizetype kUiPatchLimit = 16 * 1024 * 1024;
    if (replacementBytes.size() > kUiPatchLimit)
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.patch_too_large.title", "修改范围过大"),
            translated(
                "scanner.editor.patch_too_large.body",
                "单次修改不能超过 16 MiB。"));
        return;
    }
    if (!riskCheckBox_->isChecked())
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.ack_required.title", "需要风险确认"),
            translated(
                "scanner.editor.ack_required.body",
                "请先核对目标和修改内容，并勾选风险确认。"));
        return;
    }

    // target/expectedBytes: Read current byte before confirmation; backend re-compares upon submission.
    QFile target(kPath);
    if (!target.open(QIODevice::ReadOnly))
    {
        QMessageBox::critical(
            this,
            translated("scanner.editor.read_failed.title", "无法读取目标"),
            translated("scanner.editor.read_failed.body", "无法打开目标文件进行修改前核对。"));
        return;
    }
    const std::uint64_t kFileSize = static_cast<std::uint64_t>(target.size());
    const std::uint64_t kPatchSize = static_cast<std::uint64_t>(replacementBytes.size());
    if (offset > kFileSize || kPatchSize > kFileSize - offset ||
        offset > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
        !target.seek(static_cast<qint64>(offset)))
    {
        QMessageBox::warning(
            this,
            translated("scanner.editor.range_invalid.title", "修改范围越界"),
            translated(
                "scanner.editor.range_invalid.body",
                "偏移和替换字节长度超出了当前文件范围。"));
        return;
    }
    const QByteArray kExpectedBytes = target.read(replacementBytes.size());
    target.close();
    if (kExpectedBytes.size() != replacementBytes.size())
    {
        QMessageBox::critical(
            this,
            translated("scanner.editor.read_failed.title", "无法读取目标"),
            translated("scanner.editor.read_failed.body", "无法打开目标文件进行修改前核对。"));
        return;
    }
    if (kExpectedBytes == replacementBytes)
    {
        QMessageBox::information(
            this,
            translated("scanner.editor.no_change.title", "无需修改"),
            translated("scanner.editor.no_change.body", "目标范围已经包含相同字节。"));
        return;
    }

    // backupPath: Each modification uses a new UTC timestamped file; never silently overwrites old backups.
    const bool kCreateBackup = backupCheckBox_->isChecked();
    const QString kBackupPath = kCreateBackup
        ? QStringLiteral("%1.ksword.%2.bak")
            .arg(
                kPath,
                QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmsszzz")))
        : QString();
    const QString kConfirmation = translated(
        "scanner.editor.confirm.body",
        "即将修改：%1\n偏移：0x%2\n长度：%3 字节\n当前：%4\n替换：%5\n备份：%6\n\n提交前会再次核对当前字节和整文件快照；Windows 仍存在释放文件锁到原子替换间的极短竞态。修改后请重新扫描确认。是否继续？")
        .arg(kPath)
        .arg(offset, 0, 16)
        .arg(replacementBytes.size())
        .arg(bytesToHexPreview(kExpectedBytes))
        .arg(bytesToHexPreview(replacementBytes))
        .arg(
            kCreateBackup
                ? kBackupPath
                : translated("scanner.editor.no_backup", "不创建备份"));
    const QMessageBox::StandardButton kDecision = QMessageBox::warning(
        this,
        translated("scanner.editor.confirm.title", "最终确认：修改二进制文件"),
        kConfirmation,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kDecision != QMessageBox::Yes)
    {
        return;
    }

    // options: Pass the current byte as a compare-before-write precondition to the atomic write backend.
    ks::scanner::AtomicPatchOptions options;
    options.createBackup = kCreateBackup;
    options.overwriteBackup = false;
    options.rejectReparsePoints = true;
    options.expectedBytes = toByteVector(kExpectedBytes);
    if (kCreateBackup)
    {
        options.backupPath = kBackupPath.toStdWString();
    }

    setPatchBusy(true);
    setStatus(
        "scanner.status.patching",
        "正在安全写入并校验：%1",
        QStringList{ kPath });

    // generation: Locks relevant controls before write completion; expired callbacks must not update the current page.
    const std::uint64_t kGeneration = ++patchGeneration_;
    const std::wstring kNativePath = kPath.toStdWString();
    std::vector<std::uint8_t> replacement = toByteVector(replacementBytes);
    const std::shared_ptr<ScannerAsyncState> kAsyncState = asyncState_;
    QThreadPool::globalInstance()->start(
        [kAsyncState,
         kGeneration,
         kPath,
         kNativePath,
         offset,
         replacement = std::move(replacement),
         options = std::move(options)]() mutable
        {
            auto result = std::make_shared<ks::scanner::AtomicPatchResult>(
                ks::scanner::patchFileAtOffsetAtomic(
                    kNativePath,
                    offset,
                    replacement,
                    options));
            std::lock_guard<std::mutex> lock(kAsyncState->mutex);
            ScannerDock* receiver = kAsyncState->owner;
            if (receiver == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [kAsyncState, kGeneration, kPath, result = std::move(result)]()
                {
                    ScannerDock* owner = nullptr;
                    {
                        std::lock_guard<std::mutex> stateLock(kAsyncState->mutex);
                        owner = kAsyncState->owner;
                    }
                    if (owner != nullptr)
                    {
                        owner->finishPatch(kGeneration, kPath, result);
                    }
                },
                Qt::QueuedConnection);
        });
}

void ScannerDock::finishPatch(
    const std::uint64_t generation,
    const QString& patchedPath,
    std::shared_ptr<ks::scanner::AtomicPatchResult> result)
{
    if (generation != patchGeneration_.load() || !result)
    {
        return;
    }

    setPatchBusy(false);
    if (!result->success)
    {
        const QString kDetail = QString::fromStdWString(result->errorText);
        const QString kErrorText = result->systemError != 0
            ? translated(
                "scanner.editor.failed_with_code",
                "%1\n系统错误：%2")
                .arg(kDetail)
                .arg(result->systemError)
            : kDetail;
        setStatus(
            "scanner.status.patch_failed",
            "安全写入失败：%1",
            QStringList{ patchedPath });
        QMessageBox::critical(
            this,
            translated("scanner.editor.failed.title", "修改失败"),
            kErrorText.isEmpty()
                ? translated("scanner.editor.failed.unknown", "未能原子替换目标文件。")
                : kErrorText);
        return;
    }

    const QString kBackupPath = QString::fromStdWString(result->backupPath);
    riskCheckBox_->setChecked(false);
    setStatus(
        "scanner.status.patch_success",
        "修改已原子提交：%1",
        QStringList{ patchedPath });
    QString successText = kBackupPath.isEmpty()
        ? translated(
            "scanner.editor.success.no_backup",
            "修改已提交。此次操作未创建备份。")
        : translated(
            "scanner.editor.success.with_backup",
            "修改已提交。\n原文件备份：%1")
            .arg(kBackupPath);
    if (result->recoveredAfterReplaceFailure)
    {
        successText += QStringLiteral("\n\n") + translated(
            "scanner.editor.success.recovered",
            "Windows 原子替换曾进入部分完成状态；KSword 已将完整刷新后的替换文件恢复到目标路径并核对修改范围。请立即重新扫描确认文件。");
        QMessageBox::warning(
            this,
            translated("scanner.editor.success.title", "修改完成"),
            successText);
    }
    else
    {
        QMessageBox::information(
            this,
            translated("scanner.editor.success.title", "修改完成"),
            successText);
    }

    if (QDir::toNativeSeparators(pathEdit_->text().trimmed())
        .compare(patchedPath, Qt::CaseInsensitive) == 0)
    {
        beginScan();
    }
}

void ScannerDock::setStatus(
    const char* key,
    const char* fallback,
    const QStringList& arguments)
{
    statusKey_ = QString::fromLatin1(key);
    statusFallback_ = QString::fromUtf8(fallback);
    statusArguments_ = arguments;
    refreshStatus();
}

void ScannerDock::refreshStatus()
{
    if (statusLabel_ == nullptr || statusKey_.isEmpty())
    {
        return;
    }
    QString text = ks::i18n::text(statusKey_, statusFallback_);
    for (const QString& argument : statusArguments_)
    {
        text = text.arg(argument);
    }
    statusLabel_->setText(text);
}

void ScannerDock::setScanBusy(const bool busy)
{
    scanBusy_ = busy;
    scanButton_->setEnabled(!busy && !patchBusy_);
    browseButton_->setEnabled(!busy && !patchBusy_);
    applyPatchButton_->setEnabled(!busy && !patchBusy_);
    // Lock the path during scanning to ensure the path field, background snapshot, and final result always point to the same file.
    pathEdit_->setEnabled(!busy && !patchBusy_);
}

void ScannerDock::setPatchBusy(const bool busy)
{
    patchBusy_ = busy;
    scanButton_->setEnabled(!busy && !scanBusy_);
    browseButton_->setEnabled(!busy && !scanBusy_);
    applyPatchButton_->setEnabled(!busy);
    pathEdit_->setEnabled(!busy && !scanBusy_);
    offsetEdit_->setEnabled(!busy);
    replacementEdit_->setEnabled(!busy);
    backupCheckBox_->setEnabled(!busy);
    riskCheckBox_->setEnabled(!busy);
}
