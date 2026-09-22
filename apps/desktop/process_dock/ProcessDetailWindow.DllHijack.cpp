#include "ProcessDetailWindow.InternalCommon.h"

#include "../../../shared/platform/process/DllHijackDetector.h"

#include <QBrush>

using namespace process_detail_window_internal;

namespace
{
    QString dllHijackText(const char* const key, const QString& sourceText)
    {
        static_cast<void>(key);
        return ks::i18n::sourceText(sourceText);
    }

    int riskRank(const ks::process::DllHijackRisk risk)
    {
        switch (risk)
        {
        case ks::process::DllHijackRisk::kHigh:
            return 3;
        case ks::process::DllHijackRisk::kSuspicious:
            return 2;
        case ks::process::DllHijackRisk::kInformational:
            return 1;
        case ks::process::DllHijackRisk::kSafe:
        default:
            return 0;
        }
    }

    QString riskText(const ks::process::DllHijackRisk risk)
    {
        switch (risk)
        {
        case ks::process::DllHijackRisk::kHigh:
            return dllHijackText(
                "process.detail.dll_hijack.risk.high",
                QStringLiteral("高风险"));
        case ks::process::DllHijackRisk::kSuspicious:
            return dllHijackText(
                "process.detail.dll_hijack.risk.suspicious",
                QStringLiteral("可疑"));
        case ks::process::DllHijackRisk::kInformational:
            return dllHijackText(
                "process.detail.dll_hijack.risk.informational",
                QStringLiteral("提示"));
        case ks::process::DllHijackRisk::kSafe:
        default:
            return dllHijackText(
                "process.detail.dll_hijack.risk.safe",
                QStringLiteral("一致"));
        }
    }

    QColor riskColor(const ks::process::DllHijackRisk risk)
    {
        switch (risk)
        {
        case ks::process::DllHijackRisk::kHigh:
            return ksword_theme::errorColor();
        case ks::process::DllHijackRisk::kSuspicious:
            return ksword_theme::warningColor();
        case ks::process::DllHijackRisk::kSafe:
            return ksword_theme::successColor();
        case ks::process::DllHijackRisk::kInformational:
        default:
            return ksword_theme::textSecondaryColor();
        }
    }

    QString presenceText(const ks::process::DllHijackPresence presence)
    {
        return presence == ks::process::DllHijackPresence::kLoaded
            ? dllHijackText(
                "process.detail.dll_hijack.presence.loaded",
                QStringLiteral("已实际加载"))
            : dllHijackText(
                "process.detail.dll_hijack.presence.present_only",
                QStringLiteral("仅程序目录存在"));
    }

    QString trustSourceText(const ks::process::DllHijackTrustSource source)
    {
        switch (source)
        {
        case ks::process::DllHijackTrustSource::kEmbedded:
            return dllHijackText(
                "process.detail.dll_hijack.trust.embedded",
                QStringLiteral("嵌入签名"));
        case ks::process::DllHijackTrustSource::kCatalog:
            return dllHijackText(
                "process.detail.dll_hijack.trust.catalog",
                QStringLiteral("目录签名"));
        case ks::process::DllHijackTrustSource::kNone:
        default:
            return dllHijackText(
                "process.detail.dll_hijack.trust.none",
                QStringLiteral("未建立信任"));
        }
    }

    QString trustText(const ks::process::DllFileEvidence& evidence)
    {
        if (!evidence.trusted)
        {
            return dllHijackText(
                "process.detail.dll_hijack.trust.untrusted",
                QStringLiteral("不可信或未签名"));
        }
        const QString kSigner = evidence.signer.isEmpty()
            ? dllHijackText(
                "process.detail.dll_hijack.trust.signer_unknown",
                QStringLiteral("签名者未知"))
            : evidence.signer;
        return dllHijackText(
            "process.detail.dll_hijack.trust.valid",
            QStringLiteral("可信（%1，%2）"))
            .arg(trustSourceText(evidence.trustSource), kSigner);
    }

    QString machineText(const std::uint16_t machine)
    {
        if (machine == 0U)
        {
            return dllHijackText(
                "process.detail.dll_hijack.machine.unknown",
                QStringLiteral("未知"));
        }
        return QStringLiteral("0x%1")
            .arg(machine, 4, 16, QChar('0'))
            .toUpper();
    }

    QString differenceText(const ks::process::DllHijackFinding& finding)
    {
        QStringList evidence;
        if (!finding.hashComparable)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.hash_unavailable",
                QStringLiteral("SHA-256 无法比较")));
        }
        else if (finding.hashesMatch)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.identical",
                QStringLiteral("字节完全一致")));
        }
        else
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.hash_differs",
                QStringLiteral("SHA-256 不同")));
        }
        if (!finding.localFile.trusted)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.local_untrusted",
                QStringLiteral("本地签名不可信")));
        }
        if (finding.signerComparable && !finding.signersMatch)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.signer_differs",
                QStringLiteral("签名者不同")));
        }
        if (finding.companyComparable && !finding.companiesMatch)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.company_differs",
                QStringLiteral("公司信息不同")));
        }
        if (finding.originalFilenameComparable &&
            !finding.originalFilenamesMatch)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.original_name_differs",
                QStringLiteral("原始文件名不同")));
        }
        if (finding.versionComparable && !finding.versionsMatch)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.version_differs",
                QStringLiteral("文件版本不同")));
        }
        if (!finding.machineCompatible)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.machine_mismatch",
                QStringLiteral("体系结构不兼容")));
        }
        if (finding.localFile.reparsePoint)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.reparse_point",
                QStringLiteral("本地路径是重解析点")));
        }
        if (finding.knownDll)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.known_dll",
                QStringLiteral("命中 KnownDLL")));
        }
        if (finding.dllRedirectionPresent)
        {
            evidence.push_back(dllHijackText(
                "process.detail.dll_hijack.evidence.dot_local",
                QStringLiteral("存在 .local 重定向")));
        }
        return evidence.join(dllHijackText(
            "process.detail.dll_hijack.evidence.separator",
            QStringLiteral("；")));
    }

    QString findingDetailText(const ks::process::DllHijackFinding& finding)
    {
        const auto kValueOrDash = [](const QString& value)
        {
            return value.trimmed().isEmpty() ? QStringLiteral("-") : value;
        };

        QStringList lines;
        lines
            << dllHijackText(
                "process.detail.dll_hijack.detail.risk",
                QStringLiteral("风险：%1"))
                .arg(riskText(finding.risk))
            << dllHijackText(
                "process.detail.dll_hijack.detail.presence",
                QStringLiteral("加载状态：%1"))
                .arg(presenceText(finding.presence))
            << dllHijackText(
                "process.detail.dll_hijack.detail.evidence",
                QStringLiteral("差异证据：%1"))
                .arg(differenceText(finding))
            << QString()
            << dllHijackText(
                "process.detail.dll_hijack.detail.local_path",
                QStringLiteral("程序目录 DLL：%1"))
                .arg(finding.localFile.path)
            << dllHijackText(
                "process.detail.dll_hijack.detail.local_trust",
                QStringLiteral("本地签名：%1"))
                .arg(trustText(finding.localFile))
            << dllHijackText(
                "process.detail.dll_hijack.detail.local_sha256",
                QStringLiteral("本地 SHA-256：%1"))
                .arg(kValueOrDash(finding.localFile.sha256))
            << dllHijackText(
                "process.detail.dll_hijack.detail.local_version",
                QStringLiteral("本地版本：%1 | 公司：%2 | 原始文件名：%3 | 机器：%4"))
                .arg(
                    kValueOrDash(finding.localFile.fileVersion),
                    kValueOrDash(finding.localFile.companyName),
                    kValueOrDash(finding.localFile.originalFilename),
                    machineText(finding.localFile.machine))
            << QString()
            << dllHijackText(
                "process.detail.dll_hijack.detail.system_path",
                QStringLiteral("系统签名基线：%1"))
                .arg(finding.systemFile.path)
            << dllHijackText(
                "process.detail.dll_hijack.detail.system_trust",
                QStringLiteral("系统签名：%1"))
                .arg(trustText(finding.systemFile))
            << dllHijackText(
                "process.detail.dll_hijack.detail.system_sha256",
                QStringLiteral("系统 SHA-256：%1"))
                .arg(kValueOrDash(finding.systemFile.sha256))
            << dllHijackText(
                "process.detail.dll_hijack.detail.system_version",
                QStringLiteral("系统版本：%1 | 公司：%2 | 原始文件名：%3 | 机器：%4"))
                .arg(
                    kValueOrDash(finding.systemFile.fileVersion),
                    kValueOrDash(finding.systemFile.companyName),
                    kValueOrDash(finding.systemFile.originalFilename),
                    machineText(finding.systemFile.machine));
        return lines.join(QChar('\n'));
    }

    QString scanFailureText(const ks::process::DllHijackScanResult& result)
    {
        switch (result.status)
        {
        case ks::process::DllHijackScanStatus::kProcessIdentityUnavailable:
            return dllHijackText(
                "process.detail.dll_hijack.failure.identity_unavailable",
                QStringLiteral("无法验证当前进程实例，检测已安全停止。"));
        case ks::process::DllHijackScanStatus::kProcessIdentityMismatch:
            return dllHijackText(
                "process.detail.dll_hijack.failure.identity_mismatch",
                QStringLiteral("PID 已被复用或进程实例已变化，检测结果已丢弃。"));
        case ks::process::DllHijackScanStatus::kImagePathUnavailable:
            return dllHijackText(
                "process.detail.dll_hijack.failure.image_path",
                QStringLiteral("无法读取目标进程映像路径。"));
        case ks::process::DllHijackScanStatus::kApplicationDirectoryUnavailable:
            return dllHijackText(
                "process.detail.dll_hijack.failure.application_directory",
                QStringLiteral("目标程序目录不可访问。"));
        case ks::process::DllHijackScanStatus::kSystemDirectoryUnavailable:
            return dllHijackText(
                "process.detail.dll_hijack.failure.system_directory",
                QStringLiteral("无法定位架构匹配的 Windows 系统目录。"));
        case ks::process::DllHijackScanStatus::kComplete:
        default:
            return QString();
        }
    }

    QString buildScanReport(
        const ks::process::DllHijackScanResult& result,
        const QString& processName,
        const std::uint32_t pid)
    {
        QStringList report;
        report
            << dllHijackText(
                "process.detail.dll_hijack.report.title",
                QStringLiteral("KSword DLL 劫持检测报告"))
            << dllHijackText(
                "process.detail.dll_hijack.report.process",
                QStringLiteral("进程：%1 (PID %2)"))
                .arg(processName)
                .arg(pid)
            << dllHijackText(
                "process.detail.dll_hijack.report.image",
                QStringLiteral("映像：%1"))
                .arg(result.processImagePath)
            << dllHijackText(
                "process.detail.dll_hijack.report.application_directory",
                QStringLiteral("程序目录：%1"))
                .arg(result.applicationDirectory)
            << dllHijackText(
                "process.detail.dll_hijack.report.system_directory",
                QStringLiteral("系统基线目录：%1"))
                .arg(result.systemDirectory)
            << dllHijackText(
                "process.detail.dll_hijack.report.boundary",
                QStringLiteral("结论边界：同名本身不是恶意结论；风险由实际加载状态、Windows 信任链、SHA-256、版本身份和路径证据共同决定。检测全程不会加载待检 DLL。"))
            << QString();

        const QString kFailure = scanFailureText(result);
        if (!kFailure.isEmpty())
        {
            report << kFailure;
            if (!result.diagnosticText.isEmpty())
            {
                report << dllHijackText(
                    "process.detail.dll_hijack.report.diagnostic",
                    QStringLiteral("技术信息：%1"))
                    .arg(result.diagnosticText);
            }
            return report.join(QChar('\n'));
        }

        report << dllHijackText(
            "process.detail.dll_hijack.report.counts",
            QStringLiteral("程序目录 DLL：%1 | 系统同名：%2 | 签名基线：%3 | 结果：%4"))
            .arg(result.scannedApplicationDllCount)
            .arg(result.systemNameCollisionCount)
            .arg(result.signedSystemBaselineCount)
            .arg(result.findings.size());
        for (const ks::process::DllHijackFinding& finding : result.findings)
        {
            report << QString() << findingDetailText(finding);
        }
        return report.join(QChar('\n'));
    }

    void showDllHijackResultDialog(
        QWidget* const parent,
        const ks::process::DllHijackScanResult& result,
        const QString& processName,
        const std::uint32_t pid)
    {
        QDialog dialog(parent);
        dialog.setWindowTitle(dllHijackText(
            "process.detail.dll_hijack.dialog.title",
            QStringLiteral("DLL 劫持检测 - %1"))
            .arg(processName));
        dialog.resize(1180, 720);

        QVBoxLayout* const kLayout = new QVBoxLayout(&dialog);
        kLayout->setContentsMargins(10, 10, 10, 10);
        kLayout->setSpacing(8);

        int highCount = 0;
        int suspiciousCount = 0;
        int informationalCount = 0;
        int safeCount = 0;
        for (const ks::process::DllHijackFinding& finding : result.findings)
        {
            switch (finding.risk)
            {
            case ks::process::DllHijackRisk::kHigh: ++highCount; break;
            case ks::process::DllHijackRisk::kSuspicious: ++suspiciousCount; break;
            case ks::process::DllHijackRisk::kInformational: ++informationalCount; break;
            case ks::process::DllHijackRisk::kSafe: ++safeCount; break;
            }
        }

        QString summaryText;
        const QString kFailure = scanFailureText(result);
        if (!kFailure.isEmpty())
        {
            summaryText = kFailure;
            if (!result.diagnosticText.isEmpty())
            {
                summaryText += QChar('\n') + dllHijackText(
                    "process.detail.dll_hijack.report.diagnostic",
                    QStringLiteral("技术信息：%1"))
                    .arg(result.diagnosticText);
            }
        }
        else
        {
            summaryText = dllHijackText(
                "process.detail.dll_hijack.dialog.summary",
                QStringLiteral("扫描 %1 个程序目录 DLL，命中 %2 个系统同名文件；高风险 %3，可疑 %4，提示 %5，一致 %6。"))
                .arg(result.scannedApplicationDllCount)
                .arg(result.systemNameCollisionCount)
                .arg(highCount)
                .arg(suspiciousCount)
                .arg(informationalCount)
                .arg(safeCount);
            if (!result.loadedModuleEvidenceAvailable)
            {
                summaryText += QChar('\n') + dllHijackText(
                    "process.detail.dll_hijack.dialog.loaded_unavailable",
                    QStringLiteral("当前无法取得模块快照；结果只包含落盘候选，未声称 DLL 已被加载。"));
            }
            if (result.directoryEnumerationTruncated)
            {
                summaryText += QChar('\n') + dllHijackText(
                    "process.detail.dll_hijack.dialog.truncated",
                    QStringLiteral("程序目录 DLL 数量超过安全上限，本次结果已截断。"));
            }
            if (result.dllRedirectionPresent)
            {
                summaryText += QChar('\n') + dllHijackText(
                    "process.detail.dll_hijack.dialog.dot_local",
                    QStringLiteral("检测到与进程映像同名的 .local 重定向标记，程序目录优先级证据已计入风险。"));
            }
        }

        QLabel* const kSummaryLabel = new QLabel(summaryText, &dialog);
        kSummaryLabel->setWordWrap(true);
        kLayout->addWidget(kSummaryLabel);

        QLabel* const kBoundaryLabel = new QLabel(
            dllHijackText(
                "process.detail.dll_hijack.dialog.boundary",
                QStringLiteral("同名 DLL 仅是候选：字节一致副本不会告警；合法私有版本会保留为提示。只有加载状态、签名/签名者、哈希、版本身份和路径证据组合后才提高风险。")),
            &dialog);
        kBoundaryLabel->setWordWrap(true);
        kBoundaryLabel->setStyleSheet(QStringLiteral("color:%1;")
            .arg(ksword_theme::textSecondaryHex()));
        kLayout->addWidget(kBoundaryLabel);

        QTableWidget* const kTable = new QTableWidget(&dialog);
        const QStringList kHeaders{
            dllHijackText("process.detail.dll_hijack.header.risk", QStringLiteral("风险")),
            dllHijackText("process.detail.dll_hijack.header.presence", QStringLiteral("加载状态")),
            dllHijackText("process.detail.dll_hijack.header.dll", QStringLiteral("DLL")),
            dllHijackText("process.detail.dll_hijack.header.local_trust", QStringLiteral("本地签名")),
            dllHijackText("process.detail.dll_hijack.header.system_trust", QStringLiteral("系统签名")),
            dllHijackText("process.detail.dll_hijack.header.hash", QStringLiteral("SHA-256")),
            dllHijackText("process.detail.dll_hijack.header.evidence", QStringLiteral("差异证据")),
            dllHijackText("process.detail.dll_hijack.header.local_path", QStringLiteral("程序目录路径")),
            dllHijackText("process.detail.dll_hijack.header.system_path", QStringLiteral("系统基线路径"))
        };
        kTable->setColumnCount(kHeaders.size());
        kTable->setHorizontalHeaderLabels(kHeaders);
        kTable->setRowCount(result.findings.size());
        kTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        kTable->setSelectionMode(QAbstractItemView::SingleSelection);
        kTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        kTable->setAlternatingRowColors(true);
        kTable->setSortingEnabled(false);

        for (int row = 0; row < result.findings.size(); ++row)
        {
            const ks::process::DllHijackFinding& finding = result.findings.at(row);
            const QString kHashState = !finding.hashComparable
                ? dllHijackText(
                    "process.detail.dll_hijack.hash.unavailable",
                    QStringLiteral("无法比较"))
                : finding.hashesMatch
                ? dllHijackText(
                    "process.detail.dll_hijack.hash.identical",
                    QStringLiteral("相同"))
                : dllHijackText(
                    "process.detail.dll_hijack.hash.different",
                    QStringLiteral("不同"));
            const QStringList kCells{
                riskText(finding.risk),
                presenceText(finding.presence),
                QFileInfo(finding.localFile.path).fileName(),
                trustText(finding.localFile),
                trustText(finding.systemFile),
                kHashState,
                differenceText(finding),
                finding.localFile.path,
                finding.systemFile.path
            };
            const QString kDetail = findingDetailText(finding);
            for (int column = 0; column < kCells.size(); ++column)
            {
                QTableWidgetItem* const kItem = new QTableWidgetItem(kCells.at(column));
                kItem->setToolTip(kDetail.left(8000));
                kItem->setForeground(QBrush(riskColor(finding.risk)));
                if (column == 0)
                {
                    kItem->setData(Qt::UserRole, riskRank(finding.risk));
                }
                kTable->setItem(row, column, kItem);
            }
        }
        kTable->horizontalHeader()->setStretchLastSection(false);
        kTable->setColumnWidth(0, 80);
        kTable->setColumnWidth(1, 115);
        kTable->setColumnWidth(2, 150);
        kTable->setColumnWidth(3, 210);
        kTable->setColumnWidth(4, 210);
        kTable->setColumnWidth(5, 85);
        kTable->setColumnWidth(6, 300);
        kTable->setColumnWidth(7, 360);
        kTable->setColumnWidth(8, 360);
        kLayout->addWidget(kTable, 1);

        QPlainTextEdit* const kDetailPane = new QPlainTextEdit(&dialog);
        kDetailPane->setReadOnly(true);
        kDetailPane->setMaximumHeight(180);
        if (!result.findings.isEmpty())
        {
            kDetailPane->setPlainText(findingDetailText(result.findings.first()));
        }
        else
        {
            kDetailPane->setPlainText(kFailure.isEmpty()
                ? dllHijackText(
                    "process.detail.dll_hijack.dialog.no_candidates",
                    QStringLiteral("未发现可与签名系统 DLL 建立基线的程序目录同名候选。"))
                : kFailure);
        }
        kLayout->addWidget(kDetailPane);

        QObject::connect(
            kTable,
            &QTableWidget::currentCellChanged,
            &dialog,
            [kDetailPane, result](const int currentRow, int, int, int)
            {
                if (currentRow >= 0 && currentRow < result.findings.size())
                {
                    kDetailPane->setPlainText(
                        findingDetailText(result.findings.at(currentRow)));
                }
            });

        QHBoxLayout* const kButtonLayout = new QHBoxLayout();
        kButtonLayout->addStretch(1);
        QPushButton* const kCopyButton = new QPushButton(
            QIcon(":/Icon/process_copy_row.svg"),
            dllHijackText(
                "process.detail.dll_hijack.action.copy_report",
                QStringLiteral("复制报告")),
            &dialog);
        QPushButton* const kOpenDirectoryButton = new QPushButton(
            QIcon(":/Icon/process_open_folder.svg"),
            dllHijackText(
                "process.detail.dll_hijack.action.open_directory",
                QStringLiteral("打开程序目录")),
            &dialog);
        QPushButton* const kCloseButton = new QPushButton(
            dllHijackText(
                "process.detail.dll_hijack.action.close",
                QStringLiteral("关闭")),
            &dialog);
        kCopyButton->setStyleSheet(buildBlueButtonStyle());
        kOpenDirectoryButton->setStyleSheet(buildBlueButtonStyle());
        kOpenDirectoryButton->setEnabled(
            QFileInfo(result.applicationDirectory).isDir());
        kCloseButton->setStyleSheet(buildBlueButtonStyle());
        kButtonLayout->addWidget(kCopyButton);
        kButtonLayout->addWidget(kOpenDirectoryButton);
        kButtonLayout->addWidget(kCloseButton);
        kLayout->addLayout(kButtonLayout);

        const QString kReportText = buildScanReport(result, processName, pid);
        QObject::connect(kCopyButton, &QPushButton::clicked, &dialog, [kReportText]()
        {
            QApplication::clipboard()->setText(kReportText);
        });
        QObject::connect(
            kOpenDirectoryButton,
            &QPushButton::clicked,
            &dialog,
            [applicationDirectory = result.applicationDirectory]()
            {
                std::string detailText;
                ks::process::openFolderByPath(
                    applicationDirectory.toStdString(),
                    &detailText);
            });
        QObject::connect(kCloseButton, &QPushButton::clicked, &dialog, &QDialog::accept);

        if (kTable->rowCount() > 0)
        {
            kTable->selectRow(0);
        }
        dialog.exec();
    }
}

void ProcessDetailWindow::requestAsyncDllHijackScan()
{
    if (dllHijackScanRunning_)
    {
        return;
    }

    dllHijackScanRunning_ = true;
    const std::uint64_t kLocalTicket = ++dllHijackScanTicket_;
    if (dllHijackScanButton_ != nullptr)
    {
        dllHijackScanButton_->setEnabled(false);
    }
    updateModuleStatusLabel(
        dllHijackText(
            "process.detail.dll_hijack.status.scanning",
            QStringLiteral("● 正在只读检测 DLL 劫持候选...")),
        true);

    const std::uint32_t kPid = baseRecord_.pid;
    const std::uint64_t kCreationTime100ns = baseRecord_.creationTime100ns;
    const QString kFallbackImagePath = QString::fromStdString(baseRecord_.imagePath);
    const QString kProcessName = QString::fromStdString(baseRecord_.processName);

    KLogEvent scanStartEvent;
    info << scanStartEvent
        << "[ProcessDetailWindow] DLL hijack scan start, pid="
        << kPid
        << ", creationTime100ns="
        << kCreationTime100ns
        << eol;

    QPointer<ProcessDetailWindow> guard(this);
    QRunnable* const kTask = QRunnable::create([
        guard,
        kLocalTicket,
        kPid,
        kCreationTime100ns,
        kFallbackImagePath,
        kProcessName]()
    {
        const ks::process::DllHijackScanResult kResult =
            ks::process::scanProcessDllHijacking(
                kPid,
                kCreationTime100ns,
                kFallbackImagePath);
        if (guard == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(
            guard,
            [guard, kLocalTicket, kPid, kProcessName, kResult]()
            {
                if (guard == nullptr ||
                    kLocalTicket != guard->dllHijackScanTicket_)
                {
                    return;
                }

                guard->dllHijackScanRunning_ = false;
                if (guard->dllHijackScanButton_ != nullptr)
                {
                    guard->dllHijackScanButton_->setEnabled(true);
                }

                int highCount = 0;
                int suspiciousCount = 0;
                for (const ks::process::DllHijackFinding& finding : kResult.findings)
                {
                    if (finding.risk == ks::process::DllHijackRisk::kHigh)
                    {
                        ++highCount;
                    }
                    else if (finding.risk == ks::process::DllHijackRisk::kSuspicious)
                    {
                        ++suspiciousCount;
                    }
                }

                if (kResult.status == ks::process::DllHijackScanStatus::kComplete)
                {
                    guard->updateModuleStatusLabel(
                        dllHijackText(
                            "process.detail.dll_hijack.status.completed",
                            QStringLiteral("● DLL 劫持检测完成：高风险 %1，可疑 %2，候选 %3"))
                            .arg(highCount)
                            .arg(suspiciousCount)
                            .arg(kResult.findings.size()),
                        false);
                }
                else
                {
                    guard->updateModuleStatusLabel(
                        dllHijackText(
                            "process.detail.dll_hijack.status.failed",
                            QStringLiteral("● DLL 劫持检测未完成")),
                        false);
                    if (guard->moduleStatusLabel_ != nullptr)
                    {
                        guard->moduleStatusLabel_->setStyleSheet(
                            buildStateLabelStyle(statusErrorColor(), 700));
                    }
                }

                KLogEvent scanFinishEvent;
                info << scanFinishEvent
                    << "[ProcessDetailWindow] DLL hijack scan finish, pid="
                    << kPid
                    << ", status="
                    << static_cast<int>(kResult.status)
                    << ", findings="
                    << kResult.findings.size()
                    << ", high="
                    << highCount
                    << ", suspicious="
                    << suspiciousCount
                    << eol;

                showDllHijackResultDialog(
                    guard,
                    kResult,
                    kProcessName,
                    kPid);
            },
            Qt::QueuedConnection);
    });
    kTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(kTask);
}
