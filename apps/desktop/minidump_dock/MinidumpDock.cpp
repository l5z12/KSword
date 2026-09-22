// ============================================================
// MinidumpDock.cpp
// Purpose:
// - Implement the UI skeleton and interaction for the dump analysis page.
//   Toolbar (path + browse + system directory + parse + export), status bar, and result tabs;
// - Parsing tasks are executed via a global thread pool, using generation + shared owner state to
//   prevent race conditions between stale result writes and the exit phase (same pattern as ScannerDock).
// - The implementation for table rendering and report generation is located in MinidumpDock.Tables.cpp.
// ============================================================

#include "MinidumpDock.h"

#include "../Framework.h"
#include "CrashHistory.h"
#include "DumpAnalyzer.h"
#include "DumpAutoCheck.h"
#include "DumpMemoryView.h"
#include "DumpPoolTag.h"
#include "DumpSymbolResolver.h"
#include "internationalization/LanguageManager.h"
#include "MinidumpParser.h"
#include "ui/CodeEditorWidget.h"
#include "Theme.h"

#include <QDesktopServices>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QStyle>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextBrowser>
#include <QThreadPool>
#include <QUrl>
#include <QVBoxLayout>

#include <exception>
#include <mutex>
#include <utility>

// MinidumpAsyncState purpose: Place the worker's back-injection target in a shared mutex state.
// Clear the owner before destruction; workers can only submit queued calls under
// the same lock protection, eliminating receiver races during application shutdown.
struct MinidumpAsyncState
{
    std::mutex mutex;               // mutex: Protects owner read/write operations.
    MinidumpDock* owner = nullptr;  // owner: Target control for result callback; becomes null after destruction.
};

namespace
{
    // Note: Purpose of dumpInputStyle / dumpButtonStyle
    // - Apply a consistent theme appearance to the input fields and buttons on this page, matching other Dock components.
    // - Colors are exclusively taken from dynamic tokens in ksword_theme (expanded to palette(...) literals), evaluated
    //   by Qt against the control's current palette on each draw, ensuring theme changes take effect synchronously.
    QString dumpInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{"
            "  border:1px solid %2;"
            "  border-radius:4px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus{ border:1px solid %1; }")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    QString dumpButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // defaultDumpDirectory purpose: provides a meaningful starting directory for the file picker.
    // Prefer the system blue screen minidump directory, then the Windows directory (where MEMORY.DMP
    // resides); if neither exists, fall back to the user's home directory; return a local-style path.
    QString defaultDumpDirectory()
    {
        // systemRoot: SystemRoot environment variable; may be empty in service environments.
        const QString kSystemRoot = qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows"));
        const QString kMinidumpDir = kSystemRoot + QStringLiteral("\\Minidump");
        if (QFileInfo::exists(kMinidumpDir))
        {
            return QDir::toNativeSeparators(kMinidumpDir);
        }
        if (QFileInfo::exists(kSystemRoot))
        {
            return QDir::toNativeSeparators(kSystemRoot);
        }
        return QDir::toNativeSeparators(QDir::homePath());
    }
}

MinidumpDock::MinidumpDock(QWidget* parent)
    : QWidget(parent)
{
    // m_asyncState: Lifecycle state shared with the worker; must be established before any parsing.
    asyncState_ = std::make_shared<MinidumpAsyncState>();
    asyncState_->owner = this;
    buildUi();
    retranslateUi();
    setStatus(
        "minidump.status.idle",
        "选择一个转储文件开始解析：支持应用崩溃 MDMP 与系统蓝屏 DMP。");
}

MinidumpDock::~MinidumpDock()
{
    // Lock and clear owner: even if the worker completes later, it will no longer dispatch results to this control.
    std::lock_guard<std::mutex> lock(asyncState_->mutex);
    asyncState_->owner = nullptr;
}

void MinidumpDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
}

void MinidumpDock::buildUi()
{
    // rootLayout: Container for the path toolbar, status hints, and result tabs.
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(8);

    // pathLayout: Path input and all action buttons are arranged on the same line.
    auto* pathLayout = new QHBoxLayout();
    pathLayout->setSpacing(6);
    pathLabel_ = new QLabel(this);
    pathEdit_ = new QLineEdit(this);
    pathEdit_->setClearButtonEnabled(true);
    browseButton_ = new QPushButton(this);
    systemDirButton_ = new QPushButton(this);
    parseButton_ = new QPushButton(this);
    exportButton_ = new QPushButton(this);
    // Icons: Use standard icons for buttons with simple meanings, with text provided via hover tooltips.
    browseButton_->setIcon(style()->standardIcon(QStyle::SP_DialogOpenButton));
    systemDirButton_->setIcon(style()->standardIcon(QStyle::SP_DirIcon));
    parseButton_->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    exportButton_->setIcon(style()->standardIcon(QStyle::SP_DialogSaveButton));
    exportButton_->setEnabled(false);

    // Theming: Previously, these controls used the default Qt appearance, which did not match the blue theme of other docks.
    const QString kInputStyle = dumpInputStyle();
    const QString kButtonStyle = dumpButtonStyle();
    pathEdit_->setStyleSheet(kInputStyle);
    for (QPushButton* const kActionButton :
        { browseButton_, systemDirButton_, parseButton_, exportButton_ })
    {
        kActionButton->setStyleSheet(kButtonStyle);
    }

    pathLayout->addWidget(pathLabel_);
    pathLayout->addWidget(pathEdit_, 1);
    pathLayout->addWidget(browseButton_);
    pathLayout->addWidget(systemDirButton_);
    pathLayout->addWidget(parseButton_);
    pathLayout->addWidget(exportButton_);
    rootLayout->addLayout(pathLayout);

    // Symbol path line: The default path does not cover the most common self-check scenario of 'drivers compiled by oneself'. Their
    // .pdb files are typically located in the build output directory, neither beside the dump nor in the system symbol cache.
    // Without this entry, crashes in this project's own driver will only show module+offset.
    QHBoxLayout* const kSymbolLayout = new QHBoxLayout();
    kSymbolLayout->setContentsMargins(0, 0, 0, 0);
    kSymbolLayout->setSpacing(6);
    symbolPathLabel_ = new QLabel(this);
    symbolPathEdit_ = new QLineEdit(this);
    symbolPathEdit_->setClearButtonEnabled(true);
    symbolPathEdit_->setStyleSheet(kInputStyle);
    kSymbolLayout->addWidget(symbolPathLabel_);
    kSymbolLayout->addWidget(symbolPathEdit_, 1);
    rootLayout->addLayout(kSymbolLayout);

    // m_statusLabel: Allows copying diagnostic status; long paths wrap automatically.
    statusLabel_ = new QLabel(this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(statusLabel_);

    // m_resultTabs: Parsing result tabs; specific tabs are dynamically mounted in renderResult based on data.
    resultTabs_ = new QTabWidget(this);
    resultTabs_->setDocumentMode(true);
    rootLayout->addWidget(resultTabs_, 1);

    // Pre-create all tables and report editors: reuse during language switching or re-parsing without repeated destruction.
    analysisView_ = new QTextBrowser(resultTabs_);
    analysisView_->setOpenExternalLinks(false);
    analysisView_->setFrameShape(QFrame::NoFrame);
    blameTable_ = createReadOnlyTable(resultTabs_);
    stackTable_ = createReadOnlyTable(resultTabs_);
    registerTable_ = createReadOnlyTable(resultTabs_);
    overviewTable_ = createReadOnlyTable(resultTabs_);
    exceptionTable_ = createReadOnlyTable(resultTabs_);
    executionContextTable_ = createReadOnlyTable(resultTabs_);
    streamTable_ = createReadOnlyTable(resultTabs_);
    moduleTable_ = createReadOnlyTable(resultTabs_);
    threadTable_ = createReadOnlyTable(resultTabs_);
    memoryTable_ = createReadOnlyTable(resultTabs_);
    handleTable_ = createReadOnlyTable(resultTabs_);
    unloadedTable_ = createReadOnlyTable(resultTabs_);
    symbolTable_ = createReadOnlyTable(resultTabs_);
    poolTagTable_ = createReadOnlyTable(resultTabs_);
    crashHistoryTable_ = createReadOnlyTable(resultTabs_);
    crashHistoryTable_->setWordWrap(true);
    // The evidence column in the culprit module table contains long text; line wrapping is enabled to prevent truncation by ellipses.
    blameTable_->setWordWrap(true);
    // The 'Description' column of the symbol status table follows the same rule: specific mismatches must be fully read and cannot be truncated.
    symbolTable_->setWordWrap(true);
    poolTagTable_->setWordWrap(true);
    // Do not split the call stack table into A/B/C: its 'Source' column indicates 'Stack Scan (possible false positive)'; if
    // hidden by the column group preset, there is no longer any indication on the entire page that these frames are inferred.
    // Six columns fit within a normal window width, so there is no need to sacrifice this hint for them.
    stackPage_ = stackTable_;
    // Wide tables are wrapped into A/B/C column group pages; the column count remains consistent with the filling logic in Tables.cpp.
    modulePage_ = createStructuredTablePage(moduleTable_, 8);
    threadPage_ = createStructuredTablePage(threadTable_, 13);
    memoryPage_ = createStructuredTablePage(memoryTable_, 6);
    handlePage_ = createStructuredTablePage(handleTable_, 7);
    rawMemoryEditor_ = new CodeEditorWidget(resultTabs_);
    rawMemoryEditor_->setReadOnly(true);
    memoryView_ = new DumpMemoryView(resultTabs_);
    reportEditor_ = new CodeEditorWidget(resultTabs_);
    reportEditor_->setReadOnly(true);

    // All pre-created pages have m_resultTabs as their parent, but none have been added via addTab at this point.
    // Controls with a parent but not in the tab stack will float as ordinary child controls of the QTabWidget in the
    // client area, resulting in "several tables and column group buttons overlapping". They must be explicitly hidden;
    // addTab is responsible for showing them when needed; clearResultTabs must also re-hide them after removal.
    for (QWidget* const kPendingPage : {
            static_cast<QWidget*>(analysisView_),
            static_cast<QWidget*>(blameTable_),
            static_cast<QWidget*>(overviewTable_),
            static_cast<QWidget*>(exceptionTable_),
            static_cast<QWidget*>(executionContextTable_),
            static_cast<QWidget*>(streamTable_),
            static_cast<QWidget*>(unloadedTable_),
            static_cast<QWidget*>(registerTable_),
            static_cast<QWidget*>(symbolTable_),
            static_cast<QWidget*>(poolTagTable_),
            static_cast<QWidget*>(crashHistoryTable_),
            stackPage_, modulePage_, threadPage_, memoryPage_, handlePage_,
            static_cast<QWidget*>(rawMemoryEditor_),
            static_cast<QWidget*>(memoryView_),
            static_cast<QWidget*>(reportEditor_) })
    {
        if (kPendingPage != nullptr)
        {
            kPendingPage->hide();
        }
    }

    // All actions are unified to enter the member function's validation flow.
    connect(browseButton_, &QPushButton::clicked, this, [this]() { chooseFile(); });
    connect(systemDirButton_, &QPushButton::clicked, this, [this]()
        {
            // System directory button: directly position the file picker to the crash dump directory.
            pathEdit_->setText(defaultDumpDirectory());
            chooseFile();
        });
    connect(parseButton_, &QPushButton::clicked, this, [this]() { beginParse(); });
    connect(exportButton_, &QPushButton::clicked, this, [this]() { exportReport(); });
    connect(pathEdit_, &QLineEdit::returnPressed, this, [this]() { beginParse(); });
}

QString MinidumpDock::translated(const char* key, const char* fallback) const
{
    return ks::i18n::text(
        QString::fromLatin1(key),
        QString::fromUtf8(fallback));
}

void MinidumpDock::retranslateUi()
{
    pathLabel_->setText(translated("minidump.path.label", "转储文件"));
    pathEdit_->setPlaceholderText(translated(
        "minidump.path.placeholder",
        "选择要解析的转储文件（应用崩溃 .dmp / 蓝屏 Minidump / MEMORY.DMP）"));
    symbolPathLabel_->setText(translated("minidump.symbol.label", "符号路径"));
    symbolPathEdit_->setPlaceholderText(translated(
        "minidump.symbol.placeholder",
        "留空则搜索转储所在目录与本机符号缓存；分号分隔可加自己的构建输出目录"));
    symbolPathEdit_->setToolTip(translated(
        "minidump.symbol.tooltip",
        "只搜索本地目录，不联网下载符号。"
        "映像与转储记录不一致时会明确判为不匹配，并拒绝给出会误导人的行号。"));
    browseButton_->setText(translated("minidump.action.browse", "浏览…"));
    browseButton_->setToolTip(translated(
        "minidump.action.browse.tooltip",
        "选择一个转储文件进行只读解析"));
    systemDirButton_->setText(translated("minidump.action.system_dir", "系统转储"));
    systemDirButton_->setToolTip(translated(
        "minidump.action.system_dir.tooltip",
        "定位到系统蓝屏转储目录（C:\\Windows\\Minidump）"));
    parseButton_->setText(translated("minidump.action.parse", "解析"));
    parseButton_->setToolTip(translated(
        "minidump.action.parse.tooltip",
        "在后台解析转储结构，不会修改目标文件"));
    exportButton_->setText(translated("minidump.action.export", "导出报告"));
    exportButton_->setToolTip(translated(
        "minidump.action.export.tooltip",
        "把当前解析结果的全文报告保存为文本文件"));
    refreshStatus();

    // If a result exists, rebuild all tab texts using the new language.
    if (lastResult_)
    {
        renderResult(*lastResult_);
    }
}

void MinidumpDock::chooseFile()
{
    // startDir: Prioritizes the currently entered path (or its directory); otherwise, uses the system dump directory.
    QString startDir = pathEdit_->text().trimmed();
    if (!startDir.isEmpty())
    {
        const QFileInfo kStartInfo(startDir);
        startDir = kStartInfo.isDir() ? kStartInfo.absoluteFilePath() : kStartInfo.absolutePath();
    }
    if (startDir.isEmpty() || !QFileInfo::exists(startDir))
    {
        startDir = defaultDumpDirectory();
    }
    const QString kSelectedPath = QFileDialog::getOpenFileName(
        this,
        translated("minidump.dialog.choose_file", "选择转储文件"),
        startDir,
        translated(
            "minidump.dialog.file_filter",
            "转储文件 (*.dmp *.mdmp *.hdmp *.kdmp);;所有文件 (*.*)"));
    if (kSelectedPath.isEmpty())
    {
        return;
    }
    pathEdit_->setText(QDir::toNativeSeparators(kSelectedPath));
    beginParse();
}

void MinidumpDock::beginParse()
{
    if (parseBusy_)
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
            translated("minidump.dialog.invalid_file.title", "无法解析"),
            translated("minidump.dialog.invalid_file.body", "请选择一个存在的转储文件。"));
        return;
    }

    pathEdit_->setText(kPath);
    setBusy(true);
    setStatus(
        "minidump.status.parsing",
        "正在解析：%1",
        QStringList{ kPath });

    {
        // Log for start of parsing: the entire action chain shares a single KLogEvent for easier tracing.
        KLogEvent parseEvent;
        info << parseEvent << "MinidumpDock 开始解析转储文件: "
             << kPath.toStdString() << eol;
    }

    // generation: Only the latest generation's results can be written back to avoid older parses overwriting newer targets.
    const std::uint64_t kGeneration = ++parseGeneration_;
    const std::shared_ptr<MinidumpAsyncState> kAsyncState = asyncState_;
    // symbolPath: Retrieved on the UI thread and passed by value to the worker; the worker must not access controls.
    const QString kSymbolPath = symbolPathEdit_->text().trimmed();
    QThreadPool::globalInstance()->start(
        [kAsyncState, kGeneration, kPath, kSymbolPath]()
        {
            // result: the parsing product completed in the worker; self-contained and unrelated to file mappings.
            // Parsed input is untrusted; malformed samples may cause excessive memory allocation for a list.
            // Exceptions escaping from a thread pool worker will directly std::terminate the
            // entire process, so this must be caught and downgraded to a 'parse failure'.
            std::shared_ptr<ks::minidump::DumpParseResult> result;
            try
            {
                result = std::make_shared<ks::minidump::DumpParseResult>(
                    ks::minidump::parseDumpFile(kPath));
                // Symbolication occurs after parsing but before returning to the main thread: DbgHelp loading PDBs can take seconds
                // and must never run on the UI thread. Failure does not invalidate existing conclusions, so success remains unchanged.
                if (result->success)
                {
                    ks::minidump::applySymbols(kSymbolPath, *result);
                    // Pool tag attribution may also read large amounts of disk (searching
                    // for tag bytes within module images), so it is kept in the worker.
                    ks::minidump::applyPoolTagAttribution(*result);
                    // Crash timeline: A single dump cannot answer whether this was a BSOD or a hard hang without a dump, nor
                    // can it identify which driver build was running at the time of the crash. The filter name is set to Ksword
                    // because the primary reconciliation target for this project is the image timestamp of its own driver.
                    result->crashHistory = ks::minidump::collectCrashHistory(
                        30, QStringLiteral("Ksword"), nullptr);
                }
            }
            catch (const std::exception& error)
            {
                result = std::make_shared<ks::minidump::DumpParseResult>();
                result->filePath = kPath;
                result->errorText =
                    QStringLiteral("解析过程中发生异常，文件可能已损坏或结构异常：%1")
                        .arg(QString::fromUtf8(error.what()));
            }
            catch (...)
            {
                result = std::make_shared<ks::minidump::DumpParseResult>();
                result->filePath = kPath;
                result->errorText =
                    QStringLiteral("解析过程中发生未知异常，文件可能已损坏或结构异常。");
            }
            std::lock_guard<std::mutex> lock(kAsyncState->mutex);
            MinidumpDock* receiver = kAsyncState->owner;
            if (receiver == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [kAsyncState, kGeneration, result = std::move(result)]()
                {
                    // owner verification: The control may have been destroyed when the queued callback actually executes.
                    MinidumpDock* owner = nullptr;
                    {
                        std::lock_guard<std::mutex> stateLock(kAsyncState->mutex);
                        owner = kAsyncState->owner;
                    }
                    if (owner != nullptr)
                    {
                        owner->finishParse(kGeneration, result);
                    }
                },
                Qt::QueuedConnection);
        });
}

void MinidumpDock::finishParse(
    const std::uint64_t generation,
    std::shared_ptr<ks::minidump::DumpParseResult> result)
{
    if (generation != parseGeneration_.load() || !result)
    {
        return;
    }

    setBusy(false);
    lastResult_ = std::move(result);
    renderResult(*lastResult_);
    exportButton_->setEnabled(lastResult_->success);

    {
        // Parse end log: Record result category and success/failure for easy tracing.
        KLogEvent parseEvent;
        if (lastResult_->success)
        {
            info << parseEvent << "MinidumpDock 解析完成: "
                 << lastResult_->filePath.toStdString()
                 << " 模块 " << lastResult_->modules.size()
                 << " 线程 " << lastResult_->threads.size() << eol;
        }
        else
        {
            warn << parseEvent << "MinidumpDock 解析失败: "
                 << lastResult_->filePath.toStdString()
                 << " 原因: " << lastResult_->errorText.toStdString() << eol;
        }
    }

    if (lastResult_->success)
    {
        // kindText: Status word for the result category; translated via term translation before being inserted into the status text.
        QString kindText;
        switch (lastResult_->kind)
        {
        case ks::minidump::DumpKind::kUserMinidump:
            kindText = translated("minidump.kind.user", "用户态 MDMP");
            break;
        case ks::minidump::DumpKind::kKernelDump64:
            kindText = translated("minidump.kind.kernel64", "64 位内核转储");
            break;
        case ks::minidump::DumpKind::kKernelDump32:
            kindText = translated("minidump.kind.kernel32", "32 位内核转储");
            break;
        default:
            kindText = translated("minidump.kind.unknown", "未知");
            break;
        }
        // Place the conclusion in the status line rather than the path: the path is already in the input box above, so repeating
        // it adds no value, whereas "conclusion + confidence" is the single sentence users want to see immediately after parsing.
        if (!lastResult_->analysis.headline.isEmpty())
        {
            setStatus(
                "minidump.status.success_analysis",
                "%1（%2 · 可信度 %3）",
                QStringList{
                    ks::i18n::sourceText(lastResult_->analysis.headline),
                    kindText,
                    ks::i18n::sourceText(ks::minidump::analysisConfidenceText(
                        lastResult_->analysis.confidence)) });
        }
        else
        {
            setStatus(
                "minidump.status.success",
                "解析完成：%1（%2）。",
                QStringList{ lastResult_->filePath, kindText });
        }
    }
    else if (lastResult_->recognized)
    {
        // errorText is the Chinese specification text produced by the parsing layer; translate the entire string of terms before substitution.
        setStatus(
            "minidump.status.malformed",
            "已识别转储格式，但内容损坏或截断：%1",
            QStringList{ ks::i18n::sourceText(lastResult_->errorText) });
    }
    else
    {
        setStatus(
            "minidump.status.unrecognized",
            "不是受支持的转储文件：%1",
            QStringList{ ks::i18n::sourceText(lastResult_->errorText) });
    }

    if (lastResult_->success)
    {
        promptKswordRelatedCrash(*lastResult_);
    }
}

void MinidumpDock::openDumpFile(const QString& filePath)
{
    const QString kNormalizedPath = QDir::toNativeSeparators(filePath.trimmed());
    if (kNormalizedPath.isEmpty() || pathEdit_ == nullptr)
    {
        return;
    }
    pathEdit_->setText(kNormalizedPath);
    beginParse();
}

void MinidumpDock::promptKswordRelatedCrash(const ks::minidump::DumpParseResult& result)
{
    const ks::minidump::KswordRelevance kRelevance =
        ks::minidump::evaluateKswordRelevance(result);
    if (!kRelevance.related)
    {
        return;
    }

    {
        KLogEvent relatedEvent;
        warn << relatedEvent << "MinidumpDock 解析结果指向 KSword 自身组件: "
             << result.filePath.toStdString()
             << " 命中 " << kRelevance.matchedModules.join(QStringLiteral(",")).toStdString()
             << eol;
    }

    QMessageBox messageBox(this);
    messageBox.setIcon(QMessageBox::Warning);
    messageBox.setWindowTitle(
        translated("minidump.dialog.ksword_related.title", "这次崩溃与 KSword 有关"));
    messageBox.setText(
        translated("minidump.dialog.ksword_related.text", "这次崩溃与 KSword 有关"));
    messageBox.setInformativeText(
        ks::minidump::buildKswordReportGuidance(kRelevance, result.filePath));

    QPushButton* const kQqButton = messageBox.addButton(
        translated("minidump.dialog.ksword_related.qq", "加入 QQ 群反馈"),
        QMessageBox::ActionRole);
    QPushButton* const kIssueButton = messageBox.addButton(
        translated("minidump.dialog.ksword_related.issue", "打开 GitHub Issues"),
        QMessageBox::ActionRole);
    QPushButton* const kExportButton = messageBox.addButton(
        translated("minidump.dialog.ksword_related.export", "先导出报告"),
        QMessageBox::ActionRole);
    messageBox.addButton(
        translated("minidump.dialog.ksword_related.close", "知道了"),
        QMessageBox::RejectRole);
    messageBox.exec();

    // None of the three action buttons close the 'Don't show again' switch: crashes related to KSword are always worth reminding about.
    if (messageBox.clickedButton() == kQqButton)
    {
        QDesktopServices::openUrl(QUrl(ks::minidump::kswordQqGroupUrl()));
    }
    else if (messageBox.clickedButton() == kIssueButton)
    {
        QDesktopServices::openUrl(QUrl(ks::minidump::kswordIssuesUrl()));
    }
    else if (messageBox.clickedButton() == kExportButton)
    {
        exportReport();
    }
}

void MinidumpDock::exportReport()
{
    if (!lastResult_ || !lastResult_->success)
    {
        return;
    }
    // suggestedName: .txt report file with the same name as the dump by default.
    const QFileInfo kDumpInfo(lastResult_->filePath);
    const QString kSuggestedName = kDumpInfo.completeBaseName() + QStringLiteral("_report.txt");
    const QString kSavePath = QFileDialog::getSaveFileName(
        this,
        translated("minidump.dialog.export_report", "导出解析报告"),
        QDir::toNativeSeparators(kDumpInfo.absolutePath() + QStringLiteral("/") + kSuggestedName),
        translated("minidump.dialog.report_filter", "文本文件 (*.txt);;所有文件 (*.*)"));
    if (kSavePath.isEmpty())
    {
        return;
    }
    QFile reportFile(kSavePath);
    if (!reportFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(
            this,
            translated("minidump.dialog.export_failed.title", "导出失败"),
            translated("minidump.dialog.export_failed.body", "无法写入目标文件：%1")
                .arg(reportFile.errorString()));
        return;
    }
    // Render the report in the current UI language and write it as UTF-8 text.
    const QString kLocalizedReport =
        ks::ui::localizeGeneratedReport(buildReportText(*lastResult_));
    reportFile.write(kLocalizedReport.toUtf8());
    reportFile.close();
    setStatus(
        "minidump.status.exported",
        "报告已导出：%1",
        QStringList{ QDir::toNativeSeparators(kSavePath) });
}

void MinidumpDock::setStatus(
    const char* key,
    const char* fallback,
    const QStringList& arguments)
{
    // Record the key and arguments: when language changes, refreshStatus re-renders using the new language.
    statusKey_ = QString::fromLatin1(key);
    statusFallback_ = QString::fromUtf8(fallback);
    statusArguments_ = arguments;
    refreshStatus();
}

void MinidumpDock::refreshStatus()
{
    if (statusLabel_ == nullptr || statusKey_.isEmpty())
    {
        return;
    }
    // text: Fetch the entry first, then substitute parameters sequentially; parameters remain unchanged (e.g., dynamic content like paths).
    QString text = ks::i18n::text(statusKey_, statusFallback_);
    for (const QString& argument : statusArguments_)
    {
        text = text.arg(argument);
    }
    statusLabel_->setText(text);
}

void MinidumpDock::setBusy(const bool busy)
{
    parseBusy_ = busy;
    // Freeze all entry buttons during parsing to prevent concurrent parsing of the same control state.
    parseButton_->setEnabled(!busy);
    browseButton_->setEnabled(!busy);
    systemDirButton_->setEnabled(!busy);
    exportButton_->setEnabled(!busy && lastResult_ && lastResult_->success);
}
