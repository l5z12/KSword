#include "ApplicationControlPage.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

#include "../ui/CodeEditorWidget.h"

#include "../../../shared/platform/startup/Startup.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../Theme.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPlainTextEdit>
#include <QMetaObject>
#include <QMetaType>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTabWidget>
#include <QTableWidget>
#include <QUuid>
#include <QVariant>
#include <QVBoxLayout>
#include <QXmlStreamReader>

#include <algorithm>
#include <atomic>
#include <exception>
#include <thread>
#include <utility>

namespace
{
    // makeReadOnlyItem：
    // - Create a read-only table item;
    // - text: cell text
    // - Returns an item that can be directly inserted into a QTableWidget.
    QTableWidgetItem* makeReadOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        return item;
    }

    // sizeTextFromBytes：
    // - Format byte count into human-readable text;
    // - Return a dash when bytes is less than 0.
    QString sizeTextFromBytes(const qint64 bytes)
    {
        if (bytes < 0)
        {
            return QStringLiteral("—");
        }

        const double kValue = static_cast<double>(bytes);
        if (kValue < 1024.0)
        {
            return QStringLiteral("%1 B").arg(bytes);
        }
        if (kValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB").arg(kValue / 1024.0, 0, 'f', 2);
        }
        if (kValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB").arg(kValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB").arg(kValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // dateTimeText：
    // - Convert local time to a display string;
    // - Return a dash for invalid time.
    QString dateTimeText(const QDateTime& dateTime)
    {
        return dateTime.isValid()
            ? dateTime.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
            : QStringLiteral("—");
    }

    // sidToFriendlyText：
    // - Map common SIDs to more readable text;
    // - Unknown SID falls back to the original value.
    QString sidToFriendlyText(const QString& sidText)
    {
        const QString kTrimmedSid = sidText.trimmed();
        if (kTrimmedSid == QStringLiteral("S-1-1-0")) return QStringLiteral("Everyone");
        if (kTrimmedSid == QStringLiteral("S-1-5-32-545")) return QStringLiteral("Users");
        if (kTrimmedSid == QStringLiteral("S-1-5-32-544")) return QStringLiteral("Administrators");
        if (kTrimmedSid == QStringLiteral("S-1-5-18")) return QStringLiteral("SYSTEM");
        if (kTrimmedSid == QStringLiteral("S-1-5-19")) return QStringLiteral("LOCAL SERVICE");
        if (kTrimmedSid == QStringLiteral("S-1-5-20")) return QStringLiteral("NETWORK SERVICE");
        return kTrimmedSid;
    }

    // pathLikeTextToRegex：
    // - Convert path wildcards containing * and ? into a regular expression.
    // - Used for potential hit judgment of AppLocker path rules.
    QRegularExpression pathLikeTextToRegex(QString text)
    {
        text = text.trimmed();
        text.replace(QStringLiteral("/"), QStringLiteral("\\"));
        text.replace(QStringLiteral("\\"), QStringLiteral("\\\\"));
        text.replace(QStringLiteral("."), QStringLiteral("\\."));
        text.replace(QStringLiteral("+"), QStringLiteral("\\+"));
        text.replace(QStringLiteral("("), QStringLiteral("\\("));
        text.replace(QStringLiteral(")"), QStringLiteral("\\)"));
        text.replace(QStringLiteral("$"), QStringLiteral("\\$"));
        text.replace(QStringLiteral("^"), QStringLiteral("\\^"));
        text.replace(QStringLiteral("{"), QStringLiteral("\\{"));
        text.replace(QStringLiteral("}"), QStringLiteral("\\}"));
        text.replace(QStringLiteral("|"), QStringLiteral("\\|"));
        text.replace(QStringLiteral("*"), QStringLiteral(".*"));
        text.replace(QStringLiteral("?"), QStringLiteral("."));
        return QRegularExpression(QStringLiteral("^%1$").arg(text), QRegularExpression::CaseInsensitiveOption);
    }

    // expandCommonEnvironmentTokens：
    // - Expand common environment variables in AppLocker path rules;
    // - Perform a round of common variable substitution first, then leave it for regex wildcard matching.
    QString expandCommonEnvironmentTokens(QString text)
    {
        const QProcessEnvironment kEnv = QProcessEnvironment::systemEnvironment();
        const auto kReplaceToken = [&text, &kEnv](const QString& token, const QString& envName) {
            const QString kValue = kEnv.value(envName);
            if (!kValue.isEmpty())
            {
                text.replace(token, QDir::toNativeSeparators(kValue), Qt::CaseInsensitive);
            }
        };

        kReplaceToken(QStringLiteral("%WINDIR%"), QStringLiteral("WINDIR"));
        kReplaceToken(QStringLiteral("%SYSTEMROOT%"), QStringLiteral("SystemRoot"));
        kReplaceToken(QStringLiteral("%OSDRIVE%"), QStringLiteral("SystemDrive"));
        kReplaceToken(QStringLiteral("%PROGRAMFILES%"), QStringLiteral("ProgramFiles"));
        kReplaceToken(QStringLiteral("%PROGRAMFILES(X86)%"), QStringLiteral("ProgramFiles(x86)"));
        kReplaceToken(QStringLiteral("%USERPROFILE%"), QStringLiteral("USERPROFILE"));
        kReplaceToken(QStringLiteral("%LOCALAPPDATA%"), QStringLiteral("LOCALAPPDATA"));
        kReplaceToken(QStringLiteral("%APPDATA%"), QStringLiteral("APPDATA"));
        kReplaceToken(QStringLiteral("%TEMP%"), QStringLiteral("TEMP"));
        kReplaceToken(QStringLiteral("%TMP%"), QStringLiteral("TMP"));
        return text;
    }

    // isBroadPathRuleText：
    // - Check if the path rule is too broad.
    // - Used to mark risks in the AppLocker table.
    bool isBroadPathRuleText(const QString& conditionText)
    {
        const QString kLower = conditionText.toLower();
        return conditionText.trimmed() == QStringLiteral("*")
            || kLower.contains(QStringLiteral("\\users\\"))
            || kLower.contains(QStringLiteral("\\downloads\\"))
            || kLower.contains(QStringLiteral("\\desktop\\"))
            || kLower.contains(QStringLiteral("\\temp\\"))
            || kLower.contains(QStringLiteral("\\appdata\\local\\temp"))
            || kLower.contains(QStringLiteral("\\programdata\\"))
            || kLower.contains(QStringLiteral("%temp%"))
            || kLower.contains(QStringLiteral("%userprofile%"))
            || kLower.contains(QStringLiteral("%localappdata%"))
            || kLower.contains(QStringLiteral("%appdata%"));
    }


    // auditStateText：
    // - Input: State enum value in the R0 security audit protocol.
    // - Processing: Convert numeric values like UNKNOWN/PRESENT/ENABLED into UI-readable text.
    // - Returns: Chinese status text; unknown enums retain the original numeric value.
    QString auditStateText(const unsigned long stateValue)
    {
        switch (stateValue)
        {
        case KSWORD_ARK_SECURITY_AUDIT_STATE_UNKNOWN:
            return QStringLiteral("Unknown");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT:
            return QStringLiteral("Present");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_ABSENT:
            return QStringLiteral("Absent");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_ENABLED:
            return QStringLiteral("Enabled");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_DISABLED:
            return QStringLiteral("Disabled");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE:
            return QStringLiteral("Unavailable");
        case KSWORD_ARK_SECURITY_AUDIT_STATE_DEGRADED:
            return QStringLiteral("Degraded");
        default:
            return QStringLiteral("Unknown(%1)").arg(stateValue);
        }
    }

    // boolFlagText：
    // - Input: 0/1 boolean flag returned by R0.
    // - Processing: Convert 0/1 to No/Yes; retain the original number for invalid values.
    // - Returns: Short text suitable for summary rows.
    QString boolFlagText(const unsigned long flagValue)
    {
        if (flagValue == 0UL)
        {
            return QStringLiteral("No");
        }
        if (flagValue == 1UL)
        {
            return QStringLiteral("Yes");
        }
        return QStringLiteral("Value(%1)").arg(flagValue);
    }

    // ntStatusText：
    // - Input: NTSTATUS/status code propagated from R0 or wrapper;
    // - Processing: Preserve the original diagnostic value as an 8-digit hexadecimal number.
    // - Return: 0xXXXXXXXX text.
    QString ntStatusText(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(statusValue), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // hexMaskText：
    // - Input: Unsigned bitmaps such as fieldFlags/sourceMask;
    // - Processing: Format uniformly as hexadecimal to avoid auditing difficulties with decimal bitmaps.
    // - Return: 0xXXXXXXXX text.
    QString hexMaskText(const unsigned long maskValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(maskValue), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // fixedWideText：
    // - Input: R0 fixed-length wchar_t buffer and maximum character count;
    // - Processing: Read only content up to the first NUL to avoid including trailing padding in the UI.
    // - Returns: trimmed QString; returns a dash if null.
    QString fixedWideText(const wchar_t* bufferText, const int maxCharacters)
    {
        if (bufferText == nullptr || maxCharacters <= 0)
        {
            return QStringLiteral("—");
        }

        int textLength = 0;
        while (textLength < maxCharacters && bufferText[textLength] != L'\0')
        {
            ++textLength;
        }

        const QString kConvertedText = QString::fromWCharArray(bufferText, textLength).trimmed();
        return kConvertedText.isEmpty() ? QStringLiteral("—") : kConvertedText;
    }

    // r0IoMessageText：
    // - Input: Raw io.message returned by ArkDriverClient;
    // - Processing: normalize DeviceIoControl/version/empty message strings from the underlying layer into human-readable descriptions.
    // - Returns: Chinese text suitable for the 'Description' column in the platform security table.
    QString r0IoMessageText(const std::string& messageText)
    {
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString kRawText = QString::fromStdString(messageText).trimmed();
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该安全审计入口");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供该安全审计入口");
        }
        if (kRawText.startsWith(QStringLiteral("version="), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动已返回结构化安全审计数据");
        }
        return kRawText.isEmpty() ? QStringLiteral("无额外驱动消息") : kRawText;
    }

    // ioSummaryText：
    // - Input: ArkDriverClient standard IoResult;
    // - Processing: Merge transfer status, Win32 error, NTSTATUS, returned byte count, and a friendly description.
    // - Returns: single-line diagnostic text for platform security table display.
    QString ioSummaryText(const ksword::ark::IoResult& ioResult)
    {
        QStringList parts;
        parts << QStringLiteral("ok=%1").arg(ioResult.ok ? QStringLiteral("true") : QStringLiteral("false"));
        parts << QStringLiteral("win32=%1").arg(ioResult.win32Error);
        parts << QStringLiteral("nt=%1").arg(ntStatusText(ioResult.ntStatus));
        parts << QStringLiteral("bytes=%1").arg(ioResult.bytesReturned);
        parts << QStringLiteral("说明=%1").arg(r0IoMessageText(ioResult.message));
        return parts.join(QStringLiteral(" | "));
    }

    // collapseSpaces：
    // - Compress extra whitespace in text.
    // Facilitates table display
    QString collapseSpaces(QString text)
    {
        text = text.simplified();
        return text;
    }

    // appLockerPowerShellPrelude: explicitly locate and load the module to avoid automatic loading and PSModulePath differences.
    QString appLockerPowerShellPrelude()
    {
        return QStringLiteral(
            "$module=Get-Module -ListAvailable -Name AppLocker | Select-Object -First 1;"
            "if($null -eq $module){throw 'AppLocker PowerShell 模块不可用'};"
            "Import-Module -Name $module.Path -ErrorAction Stop;"
            "foreach($commandName in @('Get-AppLockerPolicy','Set-AppLockerPolicy','Test-AppLockerPolicy')){"
            "if($null -eq (Get-Command $commandName -ErrorAction SilentlyContinue)){throw ('AppLocker 模块未提供必需命令: '+$commandName)}};");
    }

    // jsonValueToText：
    // - Convert a JSON value to display text.
    // - Fallback to compacting arrays and objects to avoid data loss.
    QString jsonValueToText(const QJsonValue& value)
    {
        switch (value.type())
        {
        case QJsonValue::String:
            return value.toString();
        case QJsonValue::Double:
            return QString::number(value.toDouble());
        case QJsonValue::Bool:
            return value.toBool() ? QStringLiteral("True") : QStringLiteral("False");
        case QJsonValue::Array:
            return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact));
        case QJsonValue::Object:
            return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
        case QJsonValue::Null:
        case QJsonValue::Undefined:
        default:
            return QString();
        }
    }

    // classifyCodeIntegrityVerdict：
    // - Perform coarse-grained allow/block/audit classification based on event message and level.
    // - For display purposes only, not used for system judgment.
    QString classifyCodeIntegrityVerdict(const QString& messageText, const QString& levelText)
    {
        const QString kLower = messageText.toLower();
        if (kLower.contains(QStringLiteral("audit")) || kLower.contains(QStringLiteral("审计")) || kLower.contains(QStringLiteral("would have been blocked")))
        {
            return QStringLiteral("审计");
        }
        if (kLower.contains(QStringLiteral("block")) || kLower.contains(QStringLiteral("deny")) || kLower.contains(QStringLiteral("阻止")) || kLower.contains(QStringLiteral("not allowed")))
        {
            return QStringLiteral("阻止");
        }
        if (kLower.contains(QStringLiteral("allow")) || kLower.contains(QStringLiteral("loaded")) || kLower.contains(QStringLiteral("允许")))
        {
            return QStringLiteral("允许");
        }
        if (levelText.contains(QStringLiteral("warning"), Qt::CaseInsensitive))
        {
            return QStringLiteral("审计");
        }
        return QStringLiteral("事件");
    }

    // collectElementSummary：
    // - Recursively collect XML element names and attribute summaries.
    // - reader must be at StartElement;
    // - Returns format similar to "FilePathCondition Path=C:\\*".
    QString collectElementSummary(QXmlStreamReader& reader)
    {
        const QString kElementName = reader.name().toString();
        QStringList fragments;
        const auto kAttributes = reader.attributes();
        for (const QXmlStreamAttribute& attribute : kAttributes)
        {
            fragments.push_back(QStringLiteral("%1=%2")
                .arg(attribute.name().toString(), attribute.value().toString()));
        }

        while (reader.readNextStartElement())
        {
            fragments.push_back(collectElementSummary(reader));
        }

        if (fragments.isEmpty())
        {
            return kElementName;
        }
        return QStringLiteral("%1 %2").arg(kElementName, fragments.join(QStringLiteral(" | ")));
    }

    // fillTable：
    // - Rebuild QTableWidget from a plain-text 2D array;
    // - headers are the column titles.
    void fillTable(
        QTableWidget* table,
        const QStringList& headers,
        const QVector<QStringList>& rows,
        const QVector<QVariant>& firstColumnUserData = {})
    {
        if (table == nullptr)
        {
            return;
        }

        const bool kSortingEnabled = table->isSortingEnabled();
        table->setSortingEnabled(false);
        table->clear();
        table->setColumnCount(headers.size());
        table->setRowCount(rows.size());
        table->setHorizontalHeaderLabels(headers);

        for (int row = 0; row < rows.size(); ++row)
        {
            const QStringList& values = rows.at(row);
            for (int column = 0; column < headers.size(); ++column)
            {
                const QString kCellText = column < values.size() ? values.at(column) : QString();
                QTableWidgetItem* item = makeReadOnlyItem(kCellText);
                if (column == 0 && row < firstColumnUserData.size())
                {
                    item->setData(Qt::UserRole, firstColumnUserData.at(row));
                }
                table->setItem(row, column, item);
            }
        }

        table->setSortingEnabled(kSortingEnabled);
        if (table->horizontalHeader() != nullptr)
        {
            table->horizontalHeader()->setStretchLastSection(true);
        }
    }

    // selectTableContextRow: Synchronously returns the row hit by the right-click; returns -1 for empty areas.
    int selectTableContextRow(QTableWidget* table, const QPoint& localPosition)
    {
        if (table == nullptr)
        {
            return -1;
        }

        const QModelIndex kIndex = table->indexAt(localPosition);
        if (!kIndex.isValid())
        {
            return -1;
        }

        table->setCurrentIndex(kIndex);
        if (table->selectionModel() != nullptr && !table->selectionModel()->isRowSelected(kIndex.row(), QModelIndex()))
        {
            table->selectRow(kIndex.row());
        }
        return kIndex.row();
    }

    // tableCellText: Safely read the display text of a table cell.
    QString tableCellText(const QTableWidget* table, const int row, const int column)
    {
        if (table == nullptr || row < 0 || column < 0)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(row, column);
        return item != nullptr ? item->text().trimmed() : QString();
    }
}

namespace ks::misc
{
    ApplicationControlPage::ApplicationControlPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        refreshAsync();
    }

    void ApplicationControlPage::initializeUi()
    {
        rootLayout_ = new QVBoxLayout(this);
        rootLayout_->setContentsMargins(0, 0, 0, 0);
        rootLayout_->setSpacing(6);

        toolbarWidget_ = new QWidget(this);
        auto* toolbarLayout = new QHBoxLayout(toolbarWidget_);
        toolbarLayout->setContentsMargins(0, 0, 0, 0);
        toolbarLayout->setSpacing(8);

        refreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), toolbarWidget_);
        refreshButton_->setToolTip(QStringLiteral("重新采集 AppLocker / WDAC / Defender / 事件日志"));
        exportButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/log_export.svg")), QStringLiteral("导出 TSV"), toolbarWidget_);
        exportButton_->setToolTip(QStringLiteral("导出当前页主表格为 TSV"));
        statusLabel_ = new QLabel(QStringLiteral("状态: 正在加载…"), toolbarWidget_);
        statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);

        toolbarLayout->addWidget(refreshButton_);
        toolbarLayout->addWidget(exportButton_);
        toolbarLayout->addStretch(1);
        toolbarLayout->addWidget(statusLabel_);
        rootLayout_->addWidget(toolbarWidget_, 0);

        tabWidget_ = new QTabWidget(this);
        rootLayout_->addWidget(tabWidget_, 1);

        appLockerPage_ = buildAppLockerPage();
        wdacPage_ = buildWdacPage();
        defenderPage_ = buildDefenderPage();
        platformPage_ = buildPlatformPage();
        eventPage_ = buildEventLogPage();
        fileDiagnosisPage_ = buildFileDiagnosisPage();

        tabWidget_->addTab(appLockerPage_, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("AppLocker"));
        tabWidget_->addTab(wdacPage_, QIcon(QStringLiteral(":/Icon/disk_storage.svg")), QStringLiteral("WDAC / Code Integrity"));
        tabWidget_->addTab(defenderPage_, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("Defender / ASR"));
        tabWidget_->addTab(platformPage_, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("平台安全"));
        tabWidget_->addTab(eventPage_, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("事件日志"));
        tabWidget_->addTab(fileDiagnosisPage_, QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("文件诊断"));

        connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
        connect(exportButton_, &QPushButton::clicked, this, [this]() { exportCurrentTableTsv(); });
    }

    QWidget* ApplicationControlPage::buildAppLockerPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        appLockerSummary_ = new CodeEditorWidget(page);
        appLockerSummary_->setReadOnly(true);
        appLockerSummary_->setText(QStringLiteral("AppLocker 摘要会在后台刷新后显示。"));
        appLockerSummary_->setMaximumHeight(160);

        auto* actionRow = new QWidget(page);
        auto* actionLayout = new QHBoxLayout(actionRow);
        actionLayout->setContentsMargins(0, 0, 0, 0);
        appLockerEditButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑策略…"), actionRow);
        appLockerEditButton_->setToolTip(QStringLiteral("读取本地 AppLocker XML 策略并在确认后写回。需要管理员权限。"));
        appLockerEditButton_->setEnabled(false);
        actionLayout->addWidget(appLockerEditButton_);
        actionLayout->addStretch(1);

        appLockerTable_ = new ks::ui::VisibleTableWidget(page);
        initializeTable(appLockerTable_, true);
        appLockerTable_->setContextMenuPolicy(Qt::CustomContextMenu);

        layout->addWidget(appLockerSummary_, 0);
        layout->addWidget(actionRow, 0);
        layout->addWidget(appLockerTable_, 1);
        connect(appLockerEditButton_, &QPushButton::clicked, this, [this]() { editAppLockerPolicy(); });
        connect(appLockerTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showAppLockerContextMenu(localPosition);
        });
        return page;
    }

    QWidget* ApplicationControlPage::buildWdacPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        wdacSummary_ = new CodeEditorWidget(page);
        wdacSummary_->setReadOnly(true);
        wdacSummary_->setText(QStringLiteral("WDAC / Code Integrity 摘要会在后台刷新后显示。"));
        wdacSummary_->setMaximumHeight(160);

        auto* actionRow = new QWidget(page);
        auto* actionLayout = new QHBoxLayout(actionRow);
        actionLayout->setContentsMargins(0, 0, 0, 0);
        wdacEditButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑策略 XML…"), actionRow);
        wdacEditButton_->setToolTip(QStringLiteral("编辑 WDAC 源 XML；可选择编译并通过 CiTool 部署。部署前请确认策略经过验证。"));
        actionLayout->addWidget(wdacEditButton_);
        actionLayout->addStretch(1);

        policyFileTable_ = new ks::ui::VisibleTableWidget(page);
        initializeTable(policyFileTable_, true);
        policyFileTable_->setContextMenuPolicy(Qt::CustomContextMenu);

        codeIntegrityEventTable_ = new ks::ui::VisibleTableWidget(page);
        initializeTable(codeIntegrityEventTable_, true);

        layout->addWidget(wdacSummary_, 0);
        layout->addWidget(actionRow, 0);
        layout->addWidget(policyFileTable_, 1);
        layout->addWidget(codeIntegrityEventTable_, 1);
        connect(wdacEditButton_, &QPushButton::clicked, this, [this]() { editWdacPolicy(); });
        connect(policyFileTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showWdacContextMenu(localPosition);
        });
        return page;
    }

    QWidget* ApplicationControlPage::buildDefenderPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        defenderSummary_ = new CodeEditorWidget(page);
        defenderSummary_->setReadOnly(true);
        defenderSummary_->setText(QStringLiteral("Defender 状态会在后台刷新后显示。"));
        defenderSummary_->setMaximumHeight(160);

        auto* actionRow = new QWidget(page);
        auto* actionLayout = new QHBoxLayout(actionRow);
        actionLayout->setContentsMargins(0, 0, 0, 0);
        defenderEditButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑选中项…"), actionRow);
        defenderEditButton_->setToolTip(QStringLiteral("编辑表格当前选中的 Defender / ASR 配置。需要管理员权限，受篡改防护限制时系统会拒绝写入。"));
        actionLayout->addWidget(defenderEditButton_);
        actionLayout->addStretch(1);

        defenderTable_ = new ks::ui::VisibleTableWidget(page);
        initializeTable(defenderTable_, true);
        defenderTable_->setContextMenuPolicy(Qt::CustomContextMenu);

        layout->addWidget(defenderSummary_, 0);
        layout->addWidget(actionRow, 0);
        layout->addWidget(defenderTable_, 1);
        connect(defenderEditButton_, &QPushButton::clicked, this, [this]() { editDefenderSetting(); });
        connect(defenderTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
            showDefenderContextMenu(localPosition);
        });
        return page;
    }

    QWidget* ApplicationControlPage::buildPlatformPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        platformSummary_ = new CodeEditorWidget(page);
        platformSummary_->setReadOnly(true);
        platformSummary_->setText(QStringLiteral("CI / VBS / Hyper-V / Driver Trust / BAM 摘要会在后台刷新后显示。"));
        platformSummary_->setMaximumHeight(160);

        platformTable_ = new ks::ui::VisibleTableWidget(page);
        initializeTable(platformTable_, true);

        layout->addWidget(platformSummary_, 0);
        layout->addWidget(platformTable_, 1);
        return page;
    }

    QWidget* ApplicationControlPage::buildEventLogPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        auto* filterRow = new QWidget(page);
        auto* filterLayout = new QHBoxLayout(filterRow);
        filterLayout->setContentsMargins(0, 0, 0, 0);
        filterLayout->setSpacing(8);

        eventVerdictFilterCombo_ = new QComboBox(filterRow);
        eventVerdictFilterCombo_->addItems({
            QStringLiteral("全部分类"),
            QStringLiteral("阻止"),
            QStringLiteral("审计"),
            QStringLiteral("允许"),
            QStringLiteral("事件"),
            QStringLiteral("读取失败")
            });
        eventVerdictFilterCombo_->setToolTip(QStringLiteral("按 Code Integrity 判定分类筛选事件。"));

        eventLimitCombo_ = new QComboBox(filterRow);
        eventLimitCombo_->addItems({
            QStringLiteral("最近 100 条"),
            QStringLiteral("最近 200 条"),
            QStringLiteral("最近 500 条"),
            QStringLiteral("最近 1000 条")
            });
        eventLimitCombo_->setCurrentIndex(1);
        eventLimitCombo_->setToolTip(QStringLiteral("控制本页从 Code Integrity 事件日志读取的最大事件数。"));

        filterLayout->addWidget(new QLabel(QStringLiteral("分类"), filterRow), 0);
        filterLayout->addWidget(eventVerdictFilterCombo_, 0);
        filterLayout->addWidget(new QLabel(QStringLiteral("数量"), filterRow), 0);
        filterLayout->addWidget(eventLimitCombo_, 0);
        filterLayout->addStretch(1);

        eventSummary_ = new CodeEditorWidget(page);
        eventSummary_->setReadOnly(true);
        eventSummary_->setText(QStringLiteral("Code Integrity 事件摘要会在后台刷新后显示。"));
        eventSummary_->setMaximumHeight(150);

        eventTable_ = new ks::ui::VisibleTableWidget(page);
        initializeTable(eventTable_, true);
        eventTable_->setMinimumHeight(220);

        layout->addWidget(filterRow, 0);
        layout->addWidget(eventSummary_, 0);
        layout->addWidget(eventTable_, 1);

        connect(eventVerdictFilterCombo_, &QComboBox::currentTextChanged, this, [this]() {
            rebuildEventTable();
        });
        connect(eventLimitCombo_, &QComboBox::currentTextChanged, this, [this]() {
            refreshAsync();
        });
        return page;
    }

    QWidget* ApplicationControlPage::buildFileDiagnosisPage()
    {
        auto* page = new QWidget(this);
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(6);

        auto* inputRow = new QWidget(page);
        auto* inputLayout = new QHBoxLayout(inputRow);
        inputLayout->setContentsMargins(0, 0, 0, 0);
        inputLayout->setSpacing(8);

        filePathEdit_ = new QLineEdit(inputRow);
        filePathEdit_->setPlaceholderText(QStringLiteral("输入 exe / dll / script 文件路径"));
        fileBrowseButton_ = new QPushButton(QStringLiteral("浏览…"), inputRow);
        fileDiagnoseButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("诊断"), inputRow);
        fileDiagnoseButton_->setToolTip(QStringLiteral("诊断所选文件是否会被 AppLocker / WDAC / Defender 拦截"));

        inputLayout->addWidget(filePathEdit_, 1);
        inputLayout->addWidget(fileBrowseButton_);
        inputLayout->addWidget(fileDiagnoseButton_);

        fileDiagnosisSummary_ = new CodeEditorWidget(page);
        fileDiagnosisSummary_->setReadOnly(true);
        fileDiagnosisSummary_->setText(QStringLiteral("文件诊断结果会在运行后显示。"));
        fileDiagnosisSummary_->setMaximumHeight(180);

        fileDiagnosisTable_ = new ks::ui::VisibleTableWidget(page);
        initializeTable(fileDiagnosisTable_, true);

        layout->addWidget(inputRow, 0);
        layout->addWidget(fileDiagnosisSummary_, 0);
        layout->addWidget(fileDiagnosisTable_, 1);

        connect(fileBrowseButton_, &QPushButton::clicked, this, [this]() {
            const QString kFilePath = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("选择待诊断文件"),
                QString(),
                QStringLiteral("可执行文件 (*.exe *.dll *.sys *.scr *.cpl *.ocx *.msi *.ps1 *.vbs *.js *.cmd *.bat);;所有文件 (*.*)"));
            if (!kFilePath.isEmpty())
            {
                filePathEdit_->setText(kFilePath);
            }
        });

        connect(fileDiagnoseButton_, &QPushButton::clicked, this, [this]() { runFileDiagnosisAsync(); });
        return page;
    }

    void ApplicationControlPage::initializeTable(QTableWidget* table, const bool stretchLastColumn)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::ExtendedSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        // Global table support registers copy selected rows and export TSV for DefaultContextMenu.
        // Do not manually add similar actions here to avoid duplicate menu entries.
        table->setContextMenuPolicy(Qt::DefaultContextMenu);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->horizontalHeader()->setStretchLastSection(stretchLastColumn);
        table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    }

    QTableWidget* ApplicationControlPage::currentExportTable() const
    {
        if (tabWidget_ == nullptr)
        {
            return nullptr;
        }

        switch (tabWidget_->currentIndex())
        {
        case 0: return appLockerTable_;
        case 1:
            if (codeIntegrityEventTable_ != nullptr
                && (codeIntegrityEventTable_->hasFocus()
                    || (codeIntegrityEventTable_->selectionModel() != nullptr
                        && !codeIntegrityEventTable_->selectionModel()->selectedRows().isEmpty())))
            {
                return codeIntegrityEventTable_;
            }
            return policyFileTable_;
        case 2: return defenderTable_;
        case 3: return platformTable_;
        case 4: return eventTable_;
        case 5: return fileDiagnosisTable_;
        default: return nullptr;
        }
    }

    void ApplicationControlPage::showAppLockerContextMenu(const QPoint& localPosition)
    {
        const int kSelectedRow = selectTableContextRow(appLockerTable_, localPosition);
        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* addAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("新增路径规则…"));
        QAction* editAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑选中规则…"));
        QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("删除选中规则"));
        const bool kCanModify = appLockerModuleAvailable_ && pendingMutationCount_ == 0;
        addAction->setEnabled(kCanModify);
        editAction->setEnabled(kCanModify && kSelectedRow >= 0);
        deleteAction->setEnabled(kCanModify && kSelectedRow >= 0);

        QAction* selectedAction = menu.exec(appLockerTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == addAction)
        {
            addAppLockerRule();
        }
        else if (selectedAction == editAction)
        {
            editAppLockerRule(kSelectedRow);
        }
        else if (selectedAction == deleteAction)
        {
            deleteAppLockerRule();
        }
    }

    void ApplicationControlPage::showWdacContextMenu(const QPoint& localPosition)
    {
        const int kSelectedRow = selectTableContextRow(policyFileTable_, localPosition);
        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* addAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("新增源策略 XML…"));
        QAction* editAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑源策略 XML…"));
        QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("删除源策略 XML…"));

        QAction* selectedAction = menu.exec(policyFileTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == addAction)
        {
            addWdacPolicy();
        }
        else if (selectedAction == editAction)
        {
            const QString kSelectedPath = tableCellText(policyFileTable_, kSelectedRow, 0);
            editWdacPolicy(kSelectedPath.endsWith(QStringLiteral(".xml"), Qt::CaseInsensitive) ? kSelectedPath : QString());
        }
        else if (selectedAction == deleteAction)
        {
            deleteWdacPolicy();
        }
    }

    void ApplicationControlPage::showDefenderContextMenu(const QPoint& localPosition)
    {
        const int kSelectedRow = selectTableContextRow(defenderTable_, localPosition);
        QMenu menu(this);
        menu.setStyleSheet(ksword_theme::contextMenuStyle());
        QAction* addAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("新增 ASR 规则…"));
        QAction* editAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("编辑选中配置…"));
        QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("删除/重置选中配置"));
        editAction->setEnabled(kSelectedRow >= 0);
        deleteAction->setEnabled(kSelectedRow >= 0);

        QAction* selectedAction = menu.exec(defenderTable_->viewport()->mapToGlobal(localPosition));
        if (selectedAction == addAction)
        {
            addDefenderAsrRule();
        }
        else if (selectedAction == editAction)
        {
            editDefenderSetting();
        }
        else if (selectedAction == deleteAction)
        {
            deleteDefenderSetting();
        }
    }

    void ApplicationControlPage::runPowerShellMutationAsync(
        const QString& operationName,
        const QString& scriptText)
    {
        ++pendingMutationCount_;
        if (refreshButton_ != nullptr) refreshButton_->setEnabled(false);
        if (exportButton_ != nullptr) exportButton_->setEnabled(false);
        if (appLockerEditButton_ != nullptr) appLockerEditButton_->setEnabled(false);
        if (wdacEditButton_ != nullptr) wdacEditButton_->setEnabled(false);
        if (defenderEditButton_ != nullptr) defenderEditButton_->setEnabled(false);
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(QStringLiteral("状态: 正在%1…").arg(operationName));
        }

        const QPointer<ApplicationControlPage> kGuardThis(this);
        std::thread([kGuardThis, operationName, scriptText]() {
            QString errorText;
            const QString kOutputText = runPowerShellCaptureText(scriptText, 30000, &errorText);
            const bool kSucceeded = kOutputText.contains(QStringLiteral("__OK__")) && errorText.trimmed().isEmpty();
            QString diagnosticText = kOutputText;
            diagnosticText.remove(QStringLiteral("__OK__"));
            diagnosticText.remove(QStringLiteral("__ERROR__"));
            diagnosticText = diagnosticText.trimmed();
            if (!errorText.trimmed().isEmpty())
            {
                diagnosticText = diagnosticText.isEmpty()
                    ? errorText.trimmed()
                    : QStringLiteral("%1\n%2").arg(diagnosticText, errorText.trimmed());
            }

            QMetaObject::invokeMethod(qApp, [kGuardThis, operationName, kSucceeded, diagnosticText]() {
                if (kGuardThis.isNull())
                {
                    return;
                }

                kGuardThis->pendingMutationCount_ = std::max(0, kGuardThis->pendingMutationCount_ - 1);
                const bool kHasPendingMutation = kGuardThis->pendingMutationCount_ > 0;
                if (kGuardThis->refreshButton_ != nullptr) kGuardThis->refreshButton_->setEnabled(!kHasPendingMutation);
                if (kGuardThis->exportButton_ != nullptr) kGuardThis->exportButton_->setEnabled(!kHasPendingMutation);
                if (kGuardThis->appLockerEditButton_ != nullptr) kGuardThis->appLockerEditButton_->setEnabled(!kHasPendingMutation && kGuardThis->appLockerModuleAvailable_);
                if (kGuardThis->wdacEditButton_ != nullptr) kGuardThis->wdacEditButton_->setEnabled(!kHasPendingMutation);
                if (kGuardThis->defenderEditButton_ != nullptr) kGuardThis->defenderEditButton_->setEnabled(!kHasPendingMutation);

                if (!kSucceeded)
                {
                    if (kGuardThis->statusLabel_ != nullptr)
                    {
                        kGuardThis->statusLabel_->setText(QStringLiteral("状态: %1失败").arg(operationName));
                    }
                    QMessageBox::warning(
                        kGuardThis.data(),
                        operationName,
                        QStringLiteral("操作失败。\n%1")
                            .arg(diagnosticText.isEmpty() ? QStringLiteral("未返回额外错误信息。") : diagnosticText));
                    return;
                }

                if (kGuardThis->statusLabel_ != nullptr)
                {
                    kGuardThis->statusLabel_->setText(QStringLiteral("状态: %1完成，正在刷新…").arg(operationName));
                }
                QMessageBox::information(kGuardThis.data(), operationName, QStringLiteral("操作已完成，正在重新读取配置。"));
                kGuardThis->refreshAsync();
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ApplicationControlPage::editAppLockerPolicy()
    {
        if (!appLockerModuleAvailable_ || pendingMutationCount_ > 0 || appLockerEditButton_ == nullptr)
        {
            return;
        }

        appLockerEditButton_->setEnabled(false);
        const QPointer<ApplicationControlPage> kGuardThis(this);
        std::thread([kGuardThis]() {
            const QString kQueryScript = appLockerPowerShellPrelude() + QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "try {"
                "  $xml=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop);"
                "  if([string]::IsNullOrWhiteSpace($xml)){Write-Output '__NO_POLICY__'} else {Write-Output '__OK__'; Write-Output $xml}"
                "} catch { Write-Output '__ERROR__'; Write-Output $_.Exception.Message; exit 1 }");
            QString errorText;
            const QString kOutputText = runPowerShellCaptureText(kQueryScript, 15000, &errorText);

            QMetaObject::invokeMethod(qApp, [kGuardThis, kOutputText, errorText]() {
                if (kGuardThis.isNull())
                {
                    return;
                }
                if (kGuardThis->appLockerEditButton_ != nullptr)
                {
                    kGuardThis->appLockerEditButton_->setEnabled(
                        kGuardThis->appLockerModuleAvailable_ && kGuardThis->pendingMutationCount_ == 0);
                }

                QString policyXml;
                if (kOutputText.contains(QStringLiteral("__OK__")))
                {
                    policyXml = kOutputText.section(QChar::LineFeed, 1);
                }
                else if (kOutputText.contains(QStringLiteral("__NO_POLICY__")))
                {
                    policyXml = QStringLiteral("<AppLockerPolicy Version=\"1\">\n</AppLockerPolicy>\n");
                }
                else
                {
                    QString diagnosticText = kOutputText;
                    diagnosticText.remove(QStringLiteral("__ERROR__"));
                    diagnosticText = diagnosticText.trimmed();
                    if (!errorText.trimmed().isEmpty())
                    {
                        diagnosticText = diagnosticText.isEmpty()
                            ? errorText.trimmed()
                            : QStringLiteral("%1\n%2").arg(diagnosticText, errorText.trimmed());
                    }
                    QMessageBox::warning(
                        kGuardThis.data(),
                        QStringLiteral("编辑 AppLocker 策略"),
                        QStringLiteral("无法读取本地 AppLocker 策略。\n%1")
                            .arg(diagnosticText.isEmpty() ? QStringLiteral("未返回额外错误信息。") : diagnosticText));
                    return;
                }

                QDialog dialog(kGuardThis.data());
                dialog.setWindowTitle(QStringLiteral("编辑 AppLocker 策略 XML"));
                dialog.resize(900, 620);
                auto* layout = new QVBoxLayout(&dialog);
                auto* hintLabel = new QLabel(
                    QStringLiteral("仅编辑本地策略。保存将以 Replace 模式写回并覆盖当前本地 AppLocker 策略，组策略下发的规则仍由组策略管理。"),
                    &dialog);
                hintLabel->setWordWrap(true);
                hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
                auto* editor = new QPlainTextEdit(&dialog);
                editor->setPlainText(policyXml);
                editor->setLineWrapMode(QPlainTextEdit::NoWrap);
                auto* buttonBox = new QDialogButtonBox(&dialog);
                QPushButton* applyButton = buttonBox->addButton(QStringLiteral("保存并应用"), QDialogButtonBox::AcceptRole);
                buttonBox->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
                layout->addWidget(hintLabel);
                layout->addWidget(editor, 1);
                layout->addWidget(buttonBox);
                QObject::connect(applyButton, &QPushButton::clicked, &dialog, &QDialog::accept);
                QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
                if (dialog.exec() != QDialog::Accepted)
                {
                    return;
                }

                const QString kEditedXml = editor->toPlainText().trimmed();
                QXmlStreamReader xmlReader(kEditedXml);
                QString rootElementName;
                while (!xmlReader.atEnd())
                {
                    xmlReader.readNext();
                    if (rootElementName.isEmpty() && xmlReader.isStartElement())
                    {
                        rootElementName = xmlReader.name().toString();
                    }
                }
                if (xmlReader.hasError() || rootElementName.compare(QStringLiteral("AppLockerPolicy"), Qt::CaseInsensitive) != 0)
                {
                    QMessageBox::warning(
                        kGuardThis.data(),
                        QStringLiteral("编辑 AppLocker 策略"),
                        QStringLiteral("策略 XML 无效。根元素必须为 AppLockerPolicy。%1")
                            .arg(xmlReader.hasError() ? QStringLiteral("\n%1").arg(xmlReader.errorString()) : QString()));
                    return;
                }

                if (QMessageBox::warning(
                    kGuardThis.data(),
                    QStringLiteral("确认应用 AppLocker 策略"),
                    QStringLiteral("将覆盖当前本地 AppLocker 策略。错误策略可能导致应用或脚本无法启动。是否继续？"),
                    QMessageBox::Yes | QMessageBox::Cancel,
                    QMessageBox::Cancel) != QMessageBox::Yes)
                {
                    return;
                }

                const QString kEncodedXml = QString::fromLatin1(kEditedXml.toUtf8().toBase64());
                const QString kApplyScript = appLockerPowerShellPrelude() + QStringLiteral(
                    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                    "try {"
                    "  $xml=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%1'));"
                    "  Set-AppLockerPolicy -XmlPolicy $xml -ErrorAction Stop;"
                    "  Write-Output '__OK__'"
                    "} catch { Write-Output '__ERROR__'; Write-Output $_.Exception.Message; exit 1 }")
                    .arg(kEncodedXml);
                kGuardThis->runPowerShellMutationAsync(QStringLiteral("应用 AppLocker 策略"), kApplyScript);
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ApplicationControlPage::addAppLockerRule()
    {
        editAppLockerRule(-1);
    }

    void ApplicationControlPage::editAppLockerRule(const int row)
    {
        const bool kIsNewRule = row < 0;
        if (!appLockerModuleAvailable_ || pendingMutationCount_ > 0 || appLockerTable_ == nullptr)
        {
            return;
        }

        QString ruleId;
        QString initialCollectionText = QStringLiteral("EXE");
        QString initialActionText = QStringLiteral("Allow");
        QString initialSidText = QStringLiteral("S-1-1-0");
        QString initialNameText = QStringLiteral("Ksword Path Rule");
        QString initialDescriptionText;
        QString initialPathText;
        if (!kIsNewRule)
        {
            if (row >= appLockerTable_->rowCount())
            {
                return;
            }
            const QTableWidgetItem* idItem = appLockerTable_->item(row, 0);
            ruleId = idItem != nullptr ? idItem->data(Qt::UserRole).toString().trimmed() : QString();
            if (ruleId.isEmpty())
            {
                QMessageBox::information(this, QStringLiteral("编辑 AppLocker 规则"), QStringLiteral("当前规则没有可写入的本地规则 ID，可能由组策略下发。"));
                return;
            }
            if (!tableCellText(appLockerTable_, row, 4).contains(QStringLiteral("Path"), Qt::CaseInsensitive))
            {
                QMessageBox::information(
                    this,
                    QStringLiteral("编辑 AppLocker 规则"),
                    QStringLiteral("右键表单只编辑路径规则。发布者和哈希规则请使用“编辑策略…”中的 XML 编辑器。"));
                editAppLockerPolicy();
                return;
            }

            initialCollectionText = tableCellText(appLockerTable_, row, 0);
            initialActionText = tableCellText(appLockerTable_, row, 1);
            initialSidText = tableCellText(appLockerTable_, row, 3);
            initialNameText = tableCellText(appLockerTable_, row, 6);
            initialDescriptionText = initialNameText;
            const QRegularExpression kPathPattern(QStringLiteral("Path=([^;|]+)"), QRegularExpression::CaseInsensitiveOption);
            const QRegularExpressionMatch kPathMatch = kPathPattern.match(tableCellText(appLockerTable_, row, 5));
            initialPathText = kPathMatch.hasMatch() ? kPathMatch.captured(1).trimmed() : QString();
        }

        QDialog dialog(this);
        dialog.setWindowTitle(kIsNewRule ? QStringLiteral("新增 AppLocker 路径规则") : QStringLiteral("编辑 AppLocker 路径规则"));
        auto* formLayout = new QFormLayout(&dialog);
        auto* collectionCombo = new QComboBox(&dialog);
        collectionCombo->addItem(QStringLiteral("EXE"), QStringLiteral("Exe"));
        collectionCombo->addItem(QStringLiteral("DLL"), QStringLiteral("Dll"));
        collectionCombo->addItem(QStringLiteral("MSI"), QStringLiteral("Msi"));
        collectionCombo->addItem(QStringLiteral("Script"), QStringLiteral("Script"));
        auto* actionCombo = new QComboBox(&dialog);
        actionCombo->addItem(QStringLiteral("Allow"));
        actionCombo->addItem(QStringLiteral("Deny"));
        auto* sidEdit = new QLineEdit(initialSidText, &dialog);
        auto* nameEdit = new QLineEdit(initialNameText, &dialog);
        auto* pathEdit = new QLineEdit(initialPathText, &dialog);
        auto* descriptionEdit = new QLineEdit(initialDescriptionText, &dialog);
        pathEdit->setPlaceholderText(QStringLiteral("例如 %WINDIR%\\* 或 C:\\Program Files\\App\\*"));
        for (int index = 0; index < collectionCombo->count(); ++index)
        {
            if (collectionCombo->itemText(index).compare(initialCollectionText, Qt::CaseInsensitive) == 0)
            {
                collectionCombo->setCurrentIndex(index);
                break;
            }
        }
        collectionCombo->setEnabled(kIsNewRule);
        actionCombo->setCurrentIndex(initialActionText.compare(QStringLiteral("Deny"), Qt::CaseInsensitive) == 0 ? 1 : 0);
        formLayout->addRow(QStringLiteral("规则集合"), collectionCombo);
        formLayout->addRow(QStringLiteral("操作"), actionCombo);
        formLayout->addRow(QStringLiteral("用户或组 SID"), sidEdit);
        formLayout->addRow(QStringLiteral("规则名称"), nameEdit);
        formLayout->addRow(QStringLiteral("路径"), pathEdit);
        formLayout->addRow(QStringLiteral("说明"), descriptionEdit);
        auto* hintLabel = new QLabel(
            QStringLiteral("新增和编辑仅写入本地 AppLocker 路径规则。规则 ID、XML 转义和策略写回由程序处理，需要管理员权限。"),
            &dialog);
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        formLayout->addRow(hintLabel);
        auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        buttonBox->button(QDialogButtonBox::Ok)->setText(kIsNewRule ? QStringLiteral("新增") : QStringLiteral("应用"));
        buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        formLayout->addRow(buttonBox);
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }

        const QString kPathText = pathEdit->text().trimmed();
        const QString kSidText = sidEdit->text().trimmed();
        const QString kNameText = nameEdit->text().trimmed();
        if (kPathText.isEmpty() || kSidText.isEmpty() || kNameText.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("AppLocker 路径规则"), QStringLiteral("路径、用户或组 SID 和规则名称不能为空。"));
            return;
        }
        if (QMessageBox::warning(
            this,
            kIsNewRule ? QStringLiteral("确认新增 AppLocker 规则") : QStringLiteral("确认修改 AppLocker 规则"),
            QStringLiteral("将写入本地 AppLocker 策略。错误规则可能阻止应用或脚本启动。是否继续？"),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const auto kEncoded = [](const QString& text) {
            return QString::fromLatin1(text.toUtf8().toBase64());
        };
        const QString kEffectiveRuleId = kIsNewRule ? QUuid::createUuid().toString() : ruleId;
        QString mutationScript;
        if (kIsNewRule)
        {
            mutationScript = QStringLiteral(
                "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));"
                "$collectionType=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%2'));"
                "$action=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%3'));"
                "$sid=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%4'));"
                "$name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%5'));"
                "$description=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%6'));"
                "$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%7'));"
                "$xml=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop);"
                "$doc=New-Object System.Xml.XmlDocument;"
                "if([string]::IsNullOrWhiteSpace($xml)){$doc.LoadXml('<AppLockerPolicy Version=\"1\"></AppLockerPolicy>')}else{$doc.LoadXml($xml)};"
                "$collection=$null;foreach($candidate in $doc.DocumentElement.SelectNodes('RuleCollection')){if($candidate.GetAttribute('Type') -eq $collectionType){$collection=$candidate;break}};"
                "if($null -eq $collection){$collection=$doc.CreateElement('RuleCollection');$collection.SetAttribute('Type',$collectionType);$collection.SetAttribute('EnforcementMode','Enabled');[void]$doc.DocumentElement.AppendChild($collection)};"
                "$rule=$doc.CreateElement('FilePathRule');$rule.SetAttribute('Id',$ruleId);$rule.SetAttribute('Name',$name);$rule.SetAttribute('Description',$description);$rule.SetAttribute('UserOrGroupSid',$sid);$rule.SetAttribute('Action',$action);"
                "$conditions=$doc.CreateElement('Conditions');$condition=$doc.CreateElement('FilePathCondition');$condition.SetAttribute('Path',$path);[void]$conditions.AppendChild($condition);[void]$rule.AppendChild($conditions);[void]$collection.AppendChild($rule);"
                "Set-AppLockerPolicy -XmlPolicy $doc.OuterXml -ErrorAction Stop")
                .arg(kEncoded(kEffectiveRuleId))
                .arg(kEncoded(collectionCombo->currentData().toString()))
                .arg(kEncoded(actionCombo->currentText()))
                .arg(kEncoded(kSidText))
                .arg(kEncoded(kNameText))
                .arg(kEncoded(descriptionEdit->text()))
                .arg(kEncoded(kPathText));
        }
        else
        {
            mutationScript = QStringLiteral(
                "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));"
                "$action=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%2'));"
                "$sid=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%3'));"
                "$name=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%4'));"
                "$description=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%5'));"
                "$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%6'));"
                "$xml=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop);if([string]::IsNullOrWhiteSpace($xml)){throw '未配置本地 AppLocker 策略'};"
                "$doc=New-Object System.Xml.XmlDocument;$doc.LoadXml($xml);$rule=$null;foreach($candidate in $doc.SelectNodes('//*')){if($candidate.HasAttribute('Id') -and $candidate.GetAttribute('Id') -ieq $ruleId){$rule=$candidate;break}};"
                "if($null -eq $rule){throw '所选规则不在本地策略中，可能由组策略下发'};if($rule.LocalName -ne 'FilePathRule'){throw '所选规则不是路径规则'};"
                "$rule.SetAttribute('Name',$name);$rule.SetAttribute('Description',$description);$rule.SetAttribute('UserOrGroupSid',$sid);$rule.SetAttribute('Action',$action);$condition=$rule.SelectSingleNode('Conditions/FilePathCondition');if($null -eq $condition){throw '未找到路径条件'};$condition.SetAttribute('Path',$path);"
                "Set-AppLockerPolicy -XmlPolicy $doc.OuterXml -ErrorAction Stop")
                .arg(kEncoded(kEffectiveRuleId))
                .arg(kEncoded(actionCombo->currentText()))
                .arg(kEncoded(kSidText))
                .arg(kEncoded(kNameText))
                .arg(kEncoded(descriptionEdit->text()))
                .arg(kEncoded(kPathText));
        }
        mutationScript = appLockerPowerShellPrelude() + QStringLiteral(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
            "try{%1;Write-Output '__OK__'}catch{Write-Output '__ERROR__';Write-Output $_.Exception.Message;exit 1}")
            .arg(mutationScript);
        runPowerShellMutationAsync(kIsNewRule ? QStringLiteral("新增 AppLocker 路径规则") : QStringLiteral("修改 AppLocker 路径规则"), mutationScript);
    }

    void ApplicationControlPage::deleteAppLockerRule()
    {
        if (!appLockerModuleAvailable_ || pendingMutationCount_ > 0 || appLockerTable_ == nullptr || appLockerTable_->currentRow() < 0)
        {
            return;
        }
        const int kRow = appLockerTable_->currentRow();
        const QTableWidgetItem* idItem = appLockerTable_->item(kRow, 0);
        const QString kRuleId = idItem != nullptr ? idItem->data(Qt::UserRole).toString().trimmed() : QString();
        if (kRuleId.isEmpty())
        {
            QMessageBox::information(this, QStringLiteral("删除 AppLocker 规则"), QStringLiteral("当前规则没有可写入的本地规则 ID，可能由组策略下发。"));
            return;
        }
        if (QMessageBox::warning(
            this,
            QStringLiteral("确认删除 AppLocker 规则"),
            QStringLiteral("将从本地 AppLocker 策略删除“%1”。是否继续？").arg(tableCellText(appLockerTable_, kRow, 6)),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const QString kEncodedRuleId = QString::fromLatin1(kRuleId.toUtf8().toBase64());
        const QString kMutationScript = appLockerPowerShellPrelude() + QStringLiteral(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
            "try{"
            "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));$xml=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop);if([string]::IsNullOrWhiteSpace($xml)){throw '未配置本地 AppLocker 策略'};"
            "$doc=New-Object System.Xml.XmlDocument;$doc.LoadXml($xml);$rule=$null;foreach($candidate in $doc.SelectNodes('//*')){if($candidate.HasAttribute('Id') -and $candidate.GetAttribute('Id') -ieq $ruleId){$rule=$candidate;break}};"
            "if($null -eq $rule){throw '所选规则不在本地策略中，可能由组策略下发'};$collection=$rule.ParentNode;[void]$collection.RemoveChild($rule);if($collection.SelectNodes('*[contains(local-name(),\"Rule\")]').Count -eq 0){[void]$collection.ParentNode.RemoveChild($collection)};"
            "Set-AppLockerPolicy -XmlPolicy $doc.OuterXml -ErrorAction Stop;Write-Output '__OK__'"
            "}catch{Write-Output '__ERROR__';Write-Output $_.Exception.Message;exit 1}")
            .arg(kEncodedRuleId);
        runPowerShellMutationAsync(QStringLiteral("删除 AppLocker 规则"), kMutationScript);
    }

    void ApplicationControlPage::editWdacPolicy(const QString& requestedSourcePath)
    {
        if (pendingMutationCount_ > 0)
        {
            return;
        }

        QString sourcePath = requestedSourcePath;
        if (sourcePath.isEmpty())
        {
            sourcePath = QFileDialog::getOpenFileName(
                this,
                QStringLiteral("选择 WDAC 源策略 XML"),
                QString(),
                QStringLiteral("WDAC 策略 XML (*.xml);;所有文件 (*.*)"));
        }
        if (sourcePath.isEmpty())
        {
            return;
        }

        QFile sourceFile(sourcePath);
        if (!sourceFile.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            QMessageBox::warning(this, QStringLiteral("编辑 WDAC 策略"), QStringLiteral("无法读取：%1").arg(sourcePath));
            return;
        }
        const QString kOriginalXml = QString::fromUtf8(sourceFile.readAll());
        sourceFile.close();

        QDialog dialog(this);
        dialog.setWindowTitle(QStringLiteral("编辑 WDAC 源策略 XML"));
        dialog.resize(900, 620);
        auto* layout = new QVBoxLayout(&dialog);
        auto* hintLabel = new QLabel(
            QStringLiteral("保存仅更新所选 XML 源文件。选择“保存并部署”会调用 ConfigCI 编译为 CIP，再由 CiTool 更新系统策略。部署前请在测试环境验证策略。"),
            &dialog);
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        auto* editor = new QPlainTextEdit(&dialog);
        editor->setPlainText(kOriginalXml);
        editor->setLineWrapMode(QPlainTextEdit::NoWrap);
        auto* buttonBox = new QDialogButtonBox(&dialog);
        QPushButton* saveButton = buttonBox->addButton(QStringLiteral("保存源 XML"), QDialogButtonBox::AcceptRole);
        QPushButton* deployButton = buttonBox->addButton(QStringLiteral("保存并部署"), QDialogButtonBox::ActionRole);
        buttonBox->addButton(QStringLiteral("取消"), QDialogButtonBox::RejectRole);
        bool deployRequested = false;
        layout->addWidget(hintLabel);
        layout->addWidget(editor, 1);
        layout->addWidget(buttonBox);
        QObject::connect(saveButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        QObject::connect(deployButton, &QPushButton::clicked, &dialog, [&dialog, &deployRequested]() {
            deployRequested = true;
            dialog.accept();
        });
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }

        const QString kEditedXml = editor->toPlainText().trimmed();
        QXmlStreamReader xmlReader(kEditedXml);
        QString rootElementName;
        while (!xmlReader.atEnd())
        {
            xmlReader.readNext();
            if (rootElementName.isEmpty() && xmlReader.isStartElement())
            {
                rootElementName = xmlReader.name().toString();
            }
        }
        if (xmlReader.hasError() || rootElementName.compare(QStringLiteral("SiPolicy"), Qt::CaseInsensitive) != 0)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("编辑 WDAC 策略"),
                QStringLiteral("策略 XML 无效。根元素必须为 SiPolicy。%1")
                    .arg(xmlReader.hasError() ? QStringLiteral("\n%1").arg(xmlReader.errorString()) : QString()));
            return;
        }

        QSaveFile outputFile(sourcePath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text) ||
            outputFile.write(kEditedXml.toUtf8()) != kEditedXml.toUtf8().size() ||
            !outputFile.commit())
        {
            QMessageBox::warning(this, QStringLiteral("编辑 WDAC 策略"), QStringLiteral("无法保存：%1").arg(sourcePath));
            return;
        }

        if (!deployRequested)
        {
            QMessageBox::information(this, QStringLiteral("编辑 WDAC 策略"), QStringLiteral("已保存源 XML：%1").arg(sourcePath));
            return;
        }

        const QFileInfo kSourceInfo(sourcePath);
        const QString kBinaryPath = kSourceInfo.dir().absoluteFilePath(kSourceInfo.completeBaseName() + QStringLiteral(".cip"));
        if (QMessageBox::warning(
            this,
            QStringLiteral("确认部署 WDAC 策略"),
            QStringLiteral("将编译并部署：\n%1\n\n错误的 WDAC 策略可能阻止应用、驱动或系统组件加载。是否继续？").arg(sourcePath),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const QString kEncodedSourcePath = QString::fromLatin1(sourcePath.toUtf8().toBase64());
        const QString kEncodedBinaryPath = QString::fromLatin1(kBinaryPath.toUtf8().toBase64());
        const QString kDeployScript = QStringLiteral(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
            "try {"
            "  $xmlPath=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%1'));"
            "  $binaryPath=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%2'));"
            "  Import-Module ConfigCI -ErrorAction Stop;"
            "  ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binaryPath -ErrorAction Stop;"
            "  $ciTool=Join-Path $env:WINDIR 'System32\\CiTool.exe';"
            "  if(-not (Test-Path -LiteralPath $ciTool)){throw '未找到 CiTool.exe；CIP 已生成但未部署。'};"
            "  & $ciTool --update-policy $binaryPath;"
            "  if($LASTEXITCODE -ne 0){throw ('CiTool 退出码 '+$LASTEXITCODE)};"
            "  Write-Output '__OK__'"
            "} catch { Write-Output '__ERROR__'; Write-Output $_.Exception.Message; exit 1 }")
            .arg(kEncodedSourcePath, kEncodedBinaryPath);
        runPowerShellMutationAsync(QStringLiteral("部署 WDAC 策略"), kDeployScript);
    }

    void ApplicationControlPage::addWdacPolicy()
    {
        if (pendingMutationCount_ > 0)
        {
            return;
        }

        const QString kSourcePath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("新增 WDAC 源策略 XML"),
            QStringLiteral("wdac-policy.xml"),
            QStringLiteral("WDAC 策略 XML (*.xml)"));
        if (kSourcePath.isEmpty())
        {
            return;
        }
        if (QFileInfo::exists(kSourcePath) && QMessageBox::warning(
            this,
            QStringLiteral("新增 WDAC 源策略"),
            QStringLiteral("文件已存在，继续将覆盖该源 XML。是否继续？"),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const QString kPolicyTemplate = QStringLiteral(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<SiPolicy xmlns=\"urn:schemas-microsoft-com:sipolicy\">\n"
            "</SiPolicy>\n");
        QSaveFile outputFile(kSourcePath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text) ||
            outputFile.write(kPolicyTemplate.toUtf8()) != kPolicyTemplate.toUtf8().size() ||
            !outputFile.commit())
        {
            QMessageBox::warning(this, QStringLiteral("新增 WDAC 源策略"), QStringLiteral("无法创建：%1").arg(kSourcePath));
            return;
        }
        QMessageBox::information(
            this,
            QStringLiteral("新增 WDAC 源策略"),
            QStringLiteral("已创建 XML 草稿。请在编辑器中补充有效策略内容后再编译部署。"));
        editWdacPolicy(kSourcePath);
    }

    void ApplicationControlPage::deleteWdacPolicy()
    {
        if (pendingMutationCount_ > 0)
        {
            return;
        }

        const QString kSourcePath = QFileDialog::getOpenFileName(
            this,
            QStringLiteral("选择要删除的 WDAC 源策略 XML"),
            QString(),
            QStringLiteral("WDAC 策略 XML (*.xml);;所有文件 (*.*)"));
        if (kSourcePath.isEmpty())
        {
            return;
        }
        if (QMessageBox::warning(
            this,
            QStringLiteral("确认删除 WDAC 源策略"),
            QStringLiteral("将删除源 XML：\n%1\n\n已部署的 CIP 策略不会随文件删除自动卸载。是否继续？").arg(kSourcePath),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }
        if (!QFile::remove(kSourcePath))
        {
            QMessageBox::warning(this, QStringLiteral("删除 WDAC 源策略"), QStringLiteral("无法删除：%1").arg(kSourcePath));
            return;
        }
        QMessageBox::information(this, QStringLiteral("删除 WDAC 源策略"), QStringLiteral("已删除源 XML：%1").arg(kSourcePath));
    }

    void ApplicationControlPage::editDefenderSetting()
    {
        if (pendingMutationCount_ > 0 || defenderTable_ == nullptr || defenderTable_->currentRow() < 0)
        {
            QMessageBox::information(this, QStringLiteral("编辑 Defender 配置"), QStringLiteral("请先在表格中选中要编辑的配置项。"));
            return;
        }

        const int kSelectedRow = defenderTable_->currentRow();
        const QTableWidgetItem* nameItem = defenderTable_->item(kSelectedRow, 0);
        const QTableWidgetItem* valueItem = defenderTable_->item(kSelectedRow, 1);
        const QString kSettingName = nameItem != nullptr ? nameItem->text().trimmed() : QString();
        const QString kCurrentValue = valueItem != nullptr ? valueItem->text().trimmed() : QString();

        enum class DefenderSettingKind { kControlledFolderAccess, kPuaProtection, kNetworkProtection, kAsrRule, kRealTimeProtection };
        DefenderSettingKind settingKind{};
        QString asrRuleId;
        if (kSettingName.compare(QStringLiteral("Controlled Folder Access"), Qt::CaseInsensitive) == 0)
        {
            settingKind = DefenderSettingKind::kControlledFolderAccess;
        }
        else if (kSettingName.compare(QStringLiteral("PUA Protection"), Qt::CaseInsensitive) == 0)
        {
            settingKind = DefenderSettingKind::kPuaProtection;
        }
        else if (kSettingName.compare(QStringLiteral("Network Protection"), Qt::CaseInsensitive) == 0)
        {
            settingKind = DefenderSettingKind::kNetworkProtection;
        }
        else if (kSettingName.compare(QStringLiteral("Real Time Protection"), Qt::CaseInsensitive) == 0)
        {
            settingKind = DefenderSettingKind::kRealTimeProtection;
        }
        else
        {
            const QRegularExpression kAsrPattern(QStringLiteral("^ASR\\s+([0-9A-Fa-f-]{36})$"));
            const QRegularExpressionMatch kAsrMatch = kAsrPattern.match(kSettingName);
            if (!kAsrMatch.hasMatch())
            {
                QMessageBox::information(
                    this,
                    QStringLiteral("编辑 Defender 配置"),
                    QStringLiteral("当前项不支持在此编辑。支持受控文件夹访问、PUA、防网络保护、ASR 规则和实时保护。"));
                return;
            }
            settingKind = DefenderSettingKind::kAsrRule;
            asrRuleId = kAsrMatch.captured(1);
        }

        QDialog dialog(this);
        dialog.setWindowTitle(QStringLiteral("编辑 Defender 配置"));
        auto* formLayout = new QFormLayout(&dialog);
        auto* valueCombo = new QComboBox(&dialog);
        formLayout->addRow(QStringLiteral("配置项"), new QLabel(kSettingName, &dialog));
        formLayout->addRow(QStringLiteral("当前值"), new QLabel(kCurrentValue, &dialog));
        if (settingKind == DefenderSettingKind::kRealTimeProtection)
        {
            valueCombo->addItem(QStringLiteral("启用"), true);
            valueCombo->addItem(QStringLiteral("关闭"), false);
        }
        else if (settingKind == DefenderSettingKind::kAsrRule)
        {
            valueCombo->addItem(QStringLiteral("禁用 (0)"), 0);
            valueCombo->addItem(QStringLiteral("阻止 (1)"), 1);
            valueCombo->addItem(QStringLiteral("审核 (2)"), 2);
            valueCombo->addItem(QStringLiteral("警告 (6)"), 6);
        }
        else
        {
            valueCombo->addItem(QStringLiteral("关闭 (0)"), 0);
            valueCombo->addItem(QStringLiteral("阻止/启用 (1)"), 1);
            valueCombo->addItem(QStringLiteral("审核 (2)"), 2);
        }
        for (int index = 0; index < valueCombo->count(); ++index)
        {
            const QString kValueText = valueCombo->itemData(index).typeId() == QMetaType::Bool
                ? (valueCombo->itemData(index).toBool() ? QStringLiteral("True") : QStringLiteral("False"))
                : valueCombo->itemData(index).toString();
            if (kValueText.compare(kCurrentValue, Qt::CaseInsensitive) == 0)
            {
                valueCombo->setCurrentIndex(index);
                break;
            }
        }
        formLayout->addRow(QStringLiteral("新值"), valueCombo);
        auto* hintLabel = new QLabel(
            QStringLiteral("写入使用 Set-MpPreference。篡改防护、组织策略或 Defender 服务不可用时，Windows 会拒绝该操作并显示详细错误。"),
            &dialog);
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        formLayout->addRow(hintLabel);
        auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("应用"));
        buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        formLayout->addRow(buttonBox);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }

        if (QMessageBox::warning(
            this,
            QStringLiteral("确认修改 Defender 配置"),
            QStringLiteral("将修改“%1”。是否继续？").arg(kSettingName),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        QString mutationScript;
        if (settingKind == DefenderSettingKind::kControlledFolderAccess)
        {
            mutationScript = QStringLiteral("Set-MpPreference -EnableControlledFolderAccess %1 -ErrorAction Stop").arg(valueCombo->currentData().toInt());
        }
        else if (settingKind == DefenderSettingKind::kPuaProtection)
        {
            mutationScript = QStringLiteral("Set-MpPreference -PUAProtection %1 -ErrorAction Stop").arg(valueCombo->currentData().toInt());
        }
        else if (settingKind == DefenderSettingKind::kNetworkProtection)
        {
            mutationScript = QStringLiteral("Set-MpPreference -EnableNetworkProtection %1 -ErrorAction Stop").arg(valueCombo->currentData().toInt());
        }
        else if (settingKind == DefenderSettingKind::kRealTimeProtection)
        {
            mutationScript = QStringLiteral("Set-MpPreference -DisableRealtimeMonitoring $%1 -ErrorAction Stop")
                .arg(valueCombo->currentData().toBool() ? QStringLiteral("false") : QStringLiteral("true"));
        }
        else
        {
            const QString kEncodedRuleId = QString::fromLatin1(asrRuleId.toUtf8().toBase64());
            mutationScript = QStringLiteral(
                "$ruleId=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%1'));"
                "$pref=Get-MpPreference -ErrorAction Stop;"
                "$ids=@($pref.AttackSurfaceReductionRules_Ids);"
                "$actions=@($pref.AttackSurfaceReductionRules_Actions);"
                "$found=$false;"
                "for($i=0;$i -lt $ids.Count;$i++){if([string]$ids[$i] -ieq $ruleId){$actions[$i]=%2;$found=$true;break}};"
                "if(-not $found){$ids+=@($ruleId);$actions+=@(%2)};"
                "Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop")
                .arg(kEncodedRuleId)
                .arg(valueCombo->currentData().toInt());
        }
        mutationScript = QStringLiteral(
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
            "try { %1; Write-Output '__OK__' }"
            "catch { Write-Output '__ERROR__'; Write-Output $_.Exception.Message; exit 1 }")
            .arg(mutationScript);
        runPowerShellMutationAsync(QStringLiteral("修改 Defender 配置"), mutationScript);
    }


    void ApplicationControlPage::addDefenderAsrRule()
    {
        if (pendingMutationCount_ > 0)
        {
            return;
        }

        QDialog dialog(this);
        dialog.setWindowTitle(QStringLiteral("新增 ASR 规则"));
        auto* formLayout = new QFormLayout(&dialog);
        auto* ruleIdEdit = new QLineEdit(&dialog);
        ruleIdEdit->setPlaceholderText(QStringLiteral("输入 ASR 规则 GUID，例如 D4F..."));
        auto* actionCombo = new QComboBox(&dialog);
        actionCombo->addItem(QStringLiteral("禁用 (0)"), 0);
        actionCombo->addItem(QStringLiteral("阻止 (1)"), 1);
        actionCombo->addItem(QStringLiteral("审核 (2)"), 2);
        actionCombo->addItem(QStringLiteral("警告 (6)"), 6);
        formLayout->addRow(QStringLiteral("ASR 规则 GUID"), ruleIdEdit);
        formLayout->addRow(QStringLiteral("操作"), actionCombo);
        auto* hintLabel = new QLabel(
            QStringLiteral("请输入 Microsoft 支持的 ASR 规则 GUID。程序会保留现有 ASR 规则并添加新项，需要管理员权限。"),
            &dialog);
        hintLabel->setWordWrap(true);
        hintLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        formLayout->addRow(hintLabel);
        auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("新增"));
        buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        formLayout->addRow(buttonBox);
        connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() != QDialog::Accepted)
        {
            return;
        }

        const QUuid kRuleUuid(ruleIdEdit->text().trimmed());
        if (kRuleUuid.isNull())
        {
            QMessageBox::warning(this, QStringLiteral("新增 ASR 规则"), QStringLiteral("ASR 规则 GUID 格式无效。"));
            return;
        }
        if (QMessageBox::warning(
            this,
            QStringLiteral("确认新增 ASR 规则"),
            QStringLiteral("将新增 ASR 规则 %1。是否继续？").arg(kRuleUuid.toString(QUuid::WithoutBraces)),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }

        const QString kEncodedRuleId = QString::fromLatin1(kRuleUuid.toString(QUuid::WithoutBraces).toUtf8().toBase64());
        QString mutationScript = QStringLiteral(
            "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));"
            "$pref=Get-MpPreference -ErrorAction Stop;$ids=@($pref.AttackSurfaceReductionRules_Ids);$actions=@($pref.AttackSurfaceReductionRules_Actions);"
            "foreach($id in $ids){if([string]$id -ieq $ruleId){throw '该 ASR 规则已存在，请使用编辑操作'}};"
            "$ids+=@($ruleId);$actions+=@(%2);"
            "Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop")
            .arg(kEncodedRuleId)
            .arg(actionCombo->currentData().toInt());
        mutationScript = QStringLiteral(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
            "try{%1;Write-Output '__OK__'}catch{Write-Output '__ERROR__';Write-Output $_.Exception.Message;exit 1}")
            .arg(mutationScript);
        runPowerShellMutationAsync(QStringLiteral("新增 ASR 规则"), mutationScript);
    }

    void ApplicationControlPage::deleteDefenderSetting()
    {
        if (pendingMutationCount_ > 0 || defenderTable_ == nullptr || defenderTable_->currentRow() < 0)
        {
            return;
        }

        const int kRow = defenderTable_->currentRow();
        const QString kSettingName = tableCellText(defenderTable_, kRow, 0);
        QString mutationScript;
        QString operationName;
        const QRegularExpression kAsrPattern(QStringLiteral("^ASR\\s+([0-9A-Fa-f-]{36})$"));
        const QRegularExpressionMatch kAsrMatch = kAsrPattern.match(kSettingName);
        if (kAsrMatch.hasMatch())
        {
            const QString kEncodedRuleId = QString::fromLatin1(kAsrMatch.captured(1).toUtf8().toBase64());
            operationName = QStringLiteral("删除 ASR 规则");
            mutationScript = QStringLiteral(
                "$ruleId=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%1'));"
                "$pref=Get-MpPreference -ErrorAction Stop;$ids=@($pref.AttackSurfaceReductionRules_Ids);$actions=@($pref.AttackSurfaceReductionRules_Actions);$newIds=@();$newActions=@();$found=$false;"
                "for($i=0;$i -lt $ids.Count;$i++){if([string]$ids[$i] -ieq $ruleId){$found=$true;continue};$newIds+=@($ids[$i]);if($i -lt $actions.Count){$newActions+=@($actions[$i])}};"
                "if(-not $found){throw '未找到 ASR 规则'};Set-MpPreference -AttackSurfaceReductionRules_Ids $newIds -AttackSurfaceReductionRules_Actions $newActions -ErrorAction Stop")
                .arg(kEncodedRuleId);
        }
        else if (kSettingName.compare(QStringLiteral("Controlled Folder Access"), Qt::CaseInsensitive) == 0)
        {
            operationName = QStringLiteral("重置受控文件夹访问");
            mutationScript = QStringLiteral("Set-MpPreference -EnableControlledFolderAccess 0 -ErrorAction Stop");
        }
        else if (kSettingName.compare(QStringLiteral("PUA Protection"), Qt::CaseInsensitive) == 0)
        {
            operationName = QStringLiteral("重置 PUA 保护");
            mutationScript = QStringLiteral("Set-MpPreference -PUAProtection 0 -ErrorAction Stop");
        }
        else if (kSettingName.compare(QStringLiteral("Network Protection"), Qt::CaseInsensitive) == 0)
        {
            operationName = QStringLiteral("重置网络保护");
            mutationScript = QStringLiteral("Set-MpPreference -EnableNetworkProtection 0 -ErrorAction Stop");
        }
        else if (kSettingName.compare(QStringLiteral("Real Time Protection"), Qt::CaseInsensitive) == 0)
        {
            operationName = QStringLiteral("重置实时保护");
            mutationScript = QStringLiteral("Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop");
        }
        else
        {
            QMessageBox::information(
                this,
                QStringLiteral("删除/重置 Defender 配置"),
                QStringLiteral("当前项没有可由 Defender 命令行删除或重置的接口。"));
            return;
        }

        if (QMessageBox::warning(
            this,
            QStringLiteral("确认%1").arg(operationName),
            kAsrMatch.hasMatch()
                ? QStringLiteral("将删除 ASR 规则“%1”。是否继续？").arg(kSettingName)
                : QStringLiteral("将把“%1”重置为默认关闭状态。是否继续？").arg(kSettingName),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel) != QMessageBox::Yes)
        {
            return;
        }
        mutationScript = QStringLiteral(
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"
            "try{%1;Write-Output '__OK__'}catch{Write-Output '__ERROR__';Write-Output $_.Exception.Message;exit 1}")
            .arg(mutationScript);
        runPowerShellMutationAsync(operationName, mutationScript);
    }

    QString ApplicationControlPage::tableToTsv(QTableWidget* table, const bool selectedOnly) const
    {
        if (table == nullptr)
        {
            return QString();
        }

        QStringList lines;
        QStringList headerValues;
        for (int column = 0; column < table->columnCount(); ++column)
        {
            QTableWidgetItem* headerItem = table->horizontalHeaderItem(column);
            headerValues.push_back(headerItem != nullptr ? headerItem->text() : QStringLiteral("Column %1").arg(column + 1));
        }
        lines.push_back(headerValues.join(QStringLiteral("\t")));

        QVector<int> rowIndexes;
        if (selectedOnly && table->selectionModel() != nullptr)
        {
            const QModelIndexList kSelectedRows = table->selectionModel()->selectedRows();
            rowIndexes.reserve(kSelectedRows.size());
            for (const QModelIndex& index : kSelectedRows)
            {
                rowIndexes.push_back(index.row());
            }
        }
        else
        {
            rowIndexes.reserve(table->rowCount());
            for (int row = 0; row < table->rowCount(); ++row)
            {
                rowIndexes.push_back(row);
            }
        }

        for (const int kRow : rowIndexes)
        {
            QStringList values;
            values.reserve(table->columnCount());
            for (int column = 0; column < table->columnCount(); ++column)
            {
                QTableWidgetItem* item = table->item(kRow, column);
                values.push_back(item != nullptr ? item->text() : QString());
            }
            lines.push_back(values.join(QStringLiteral("\t")));
        }

        return lines.join(QStringLiteral("\n"));
    }

    void ApplicationControlPage::exportCurrentTableTsv()
    {
        QTableWidget* const kTable = currentExportTable();
        if (kTable == nullptr)
        {
            QMessageBox::information(this, QStringLiteral("导出 TSV"), QStringLiteral("当前页没有可导出的表格。"));
            return;
        }

        const QString kOutputPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出 TSV"),
            QStringLiteral("application_control.tsv"),
            QStringLiteral("TSV 文件 (*.tsv)"));
        if (kOutputPath.isEmpty())
        {
            return;
        }

        QFile outputFile(kOutputPath);
        if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        {
            QMessageBox::warning(this, QStringLiteral("导出 TSV"), QStringLiteral("无法写入：%1").arg(kOutputPath));
            return;
        }

        outputFile.write(tableToTsv(kTable, false).toUtf8());
        outputFile.close();
        QMessageBox::information(this, QStringLiteral("导出 TSV"), QStringLiteral("已导出：%1").arg(kOutputPath));
    }

    QString ApplicationControlPage::buildAppLockerRiskText(
        const QString& actionText,
        const QString& sidText,
        const QString& conditionTypeText,
        const QString& conditionText)
    {
        QStringList riskList;
        const QString kLoweredSid = sidText.trimmed();
        if (actionText.compare(QStringLiteral("Allow"), Qt::CaseInsensitive) == 0
            && (kLoweredSid == QStringLiteral("S-1-1-0") || sidToFriendlyText(kLoweredSid) == QStringLiteral("Everyone")))
        {
            riskList.push_back(QStringLiteral("Everyone Allow"));
        }

        if (conditionTypeText.compare(QStringLiteral("Path"), Qt::CaseInsensitive) == 0)
        {
            if (isBroadPathRuleText(conditionText))
            {
                riskList.push_back(QStringLiteral("Users writable path"));
            }
            const QString kLower = conditionText.toLower();
            if (conditionText.trimmed() == QStringLiteral("*")
                || kLower == QStringLiteral("*")
                || kLower.contains(QStringLiteral("\\*"))
                || kLower.contains(QStringLiteral("*\\"))
                || kLower.contains(QStringLiteral("*.*")))
            {
                riskList.push_back(QStringLiteral("宽泛 * 规则"));
            }
        }
        else if (conditionText.trimmed().contains(QStringLiteral("*")))
        {
            riskList.push_back(QStringLiteral("宽泛 * 规则"));
        }

        return riskList.isEmpty() ? QString() : riskList.join(QStringLiteral("; "));
    }

    QString ApplicationControlPage::runPowerShellCaptureText(
        const QString& scriptText,
        const int timeoutMs,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        QProcess process;
        process.setProgram(QStringLiteral("powershell.exe"));
        process.setArguments(QStringList{
            QStringLiteral("-NoLogo"),
            QStringLiteral("-NoProfile"),
            QStringLiteral("-ExecutionPolicy"),
            QStringLiteral("Bypass"),
            QStringLiteral("-Command"),
            scriptText
        });
        process.start();
        if (!process.waitForStarted(5000))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法启动 powershell.exe。");
            }
            return QString();
        }

        if (!process.waitForFinished(timeoutMs))
        {
            process.kill();
            process.waitForFinished(2000);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("PowerShell 查询超时。");
            }
            return QString();
        }

        const QString kStdOutText = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        const QString kStdErrText = QString::fromUtf8(process.readAllStandardError()).trimmed();
        if (errorTextOut != nullptr)
        {
            *errorTextOut = kStdErrText;
            if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
            {
                const QString kExitHint = QStringLiteral("PowerShell 退出码 %1。").arg(process.exitCode());
                if (errorTextOut->isEmpty())
                {
                    *errorTextOut = kExitHint;
                }
                else
                {
                    *errorTextOut += QStringLiteral("\n");
                    *errorTextOut += kExitHint;
                }
            }
        }

        return kStdOutText;
    }

    std::pair<QVector<ApplicationControlPage::AppLockerRuleRecord>, QString> ApplicationControlPage::parseAppLockerPolicyXml(
        const QString& xmlText)
    {
        QVector<AppLockerRuleRecord> records;
        if (xmlText.trimmed().isEmpty())
        {
            return { records, QStringLiteral("AppLocker: 未配置") };
        }

        QXmlStreamReader reader(xmlText);
        QStringList summaryParts;
        int collectionCount = 0;

        const auto kCollectionToText = [](const QString& typeText) {
            if (typeText.compare(QStringLiteral("Exe"), Qt::CaseInsensitive) == 0) return QStringLiteral("EXE");
            if (typeText.compare(QStringLiteral("Dll"), Qt::CaseInsensitive) == 0) return QStringLiteral("DLL");
            if (typeText.compare(QStringLiteral("Msi"), Qt::CaseInsensitive) == 0) return QStringLiteral("MSI");
            if (typeText.compare(QStringLiteral("Script"), Qt::CaseInsensitive) == 0) return QStringLiteral("Script");
            if (typeText.compare(QStringLiteral("Appx"), Qt::CaseInsensitive) == 0 || typeText.contains(QStringLiteral("Packaged"), Qt::CaseInsensitive))
            {
                return QStringLiteral("Packaged app");
            }
            return typeText.isEmpty() ? QStringLiteral("Unknown") : typeText;
        };

        const auto kConditionTypeFromSummary = [](const QString& summaryText) {
            const QString kLower = summaryText.toLower();
            if (kLower.contains(QStringLiteral("publisher"))) return QStringLiteral("Publisher");
            if (kLower.contains(QStringLiteral("path"))) return QStringLiteral("Path");
            if (kLower.contains(QStringLiteral("hash"))) return QStringLiteral("Hash");
            return QStringLiteral("Unknown");
        };

        while (!reader.atEnd())
        {
            reader.readNext();
            if (!reader.isStartElement())
            {
                continue;
            }

            if (reader.name().toString().compare(QStringLiteral("RuleCollection"), Qt::CaseInsensitive) != 0)
            {
                reader.skipCurrentElement();
                continue;
            }

            ++collectionCount;
            const QString kCollectionTypeText = kCollectionToText(reader.attributes().value(QStringLiteral("Type")).toString());
            int collectionRuleCount = 0;

            auto parseRuleElement = [&](const QString& ruleElementName) {
                AppLockerRuleRecord record;
                record.collectionText = kCollectionTypeText;
                const QXmlStreamAttributes kAttributes = reader.attributes();
                record.idText = kAttributes.value(QStringLiteral("Id")).toString();
                record.actionText = kAttributes.value(QStringLiteral("Action")).toString();
                record.sidText = kAttributes.value(QStringLiteral("UserOrGroupSid")).toString();
                record.userText = sidToFriendlyText(record.sidText);
                record.descriptionText = kAttributes.value(QStringLiteral("Description")).toString();
                if (record.descriptionText.trimmed().isEmpty())
                {
                    record.descriptionText = kAttributes.value(QStringLiteral("Name")).toString();
                }
                if (record.actionText.trimmed().isEmpty())
                {
                    record.actionText = QStringLiteral("—");
                }
                if (record.sidText.trimmed().isEmpty())
                {
                    record.sidText = QStringLiteral("—");
                }
                if (record.userText.trimmed().isEmpty())
                {
                    record.userText = QStringLiteral("—");
                }
                if (record.descriptionText.trimmed().isEmpty())
                {
                    record.descriptionText = QStringLiteral("—");
                }

                QStringList conditionSummaries;
                while (reader.readNextStartElement())
                {
                    const QString kChildName = reader.name().toString();
                    if (kChildName.compare(QStringLiteral("Conditions"), Qt::CaseInsensitive) == 0)
                    {
                        while (reader.readNextStartElement())
                        {
                            conditionSummaries.push_back(collectElementSummary(reader));
                        }
                    }
                    else
                    {
                        conditionSummaries.push_back(collectElementSummary(reader));
                    }
                }

                if (!conditionSummaries.isEmpty())
                {
                    record.conditionText = collapseSpaces(conditionSummaries.join(QStringLiteral(" ; ")));
                    record.conditionTypeText = kConditionTypeFromSummary(conditionSummaries.front());
                }
                else
                {
                    record.conditionTypeText = QStringLiteral("Unknown");
                    record.conditionText = QStringLiteral("—");
                }

                record.riskText = buildAppLockerRiskText(
                    record.actionText,
                    record.sidText,
                    record.conditionTypeText,
                    record.conditionText);
                records.push_back(record);
                ++collectionRuleCount;
                Q_UNUSED(ruleElementName);
            };

            while (reader.readNextStartElement())
            {
                const QString kChildName = reader.name().toString();
                if (kChildName.endsWith(QStringLiteral("Rule"), Qt::CaseInsensitive))
                {
                    parseRuleElement(kChildName);
                }
                else
                {
                    reader.skipCurrentElement();
                }
            }

            summaryParts.push_back(QStringLiteral("%1: %2 条规则").arg(kCollectionTypeText).arg(collectionRuleCount));
        }

        if (reader.hasError())
        {
            return { records, QStringLiteral("AppLocker XML 解析失败：%1").arg(reader.errorString()) };
        }

        if (records.isEmpty())
        {
            return { records, QStringLiteral("AppLocker: 未配置") };
        }

        QString summaryText = QStringLiteral("AppLocker 规则集共 %1 个，规则共 %2 条。")
            .arg(collectionCount)
            .arg(records.size());
        if (!summaryParts.isEmpty())
        {
            summaryText += QStringLiteral("\n");
            summaryText += summaryParts.join(QStringLiteral("\n"));
        }
        return { records, summaryText };
    }

    std::pair<QVector<ApplicationControlPage::EventRecord>, QString> ApplicationControlPage::parseEventsJson(
        const QString& jsonText)
    {
        QVector<EventRecord> records;
        const QString kTrimmedText = jsonText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return { records, QStringLiteral("未获取到 Code Integrity 事件。") };
        }

        QJsonParseError parseError{};
        const QJsonDocument kDocument = QJsonDocument::fromJson(kTrimmedText.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError)
        {
            return { records, QStringLiteral("事件 JSON 解析失败：%1").arg(parseError.errorString()) };
        }

        QJsonArray array;
        if (kDocument.isArray())
        {
            array = kDocument.array();
        }
        else if (kDocument.isObject())
        {
            array.push_back(kDocument.object());
        }

        int allowCount = 0;
        int blockCount = 0;
        int auditCount = 0;

        for (const QJsonValue& value : array)
        {
            const QJsonObject kObject = value.toObject();
            EventRecord record;
            QString timeText = jsonValueToText(kObject.value(QStringLiteral("TimeText")));
            if (timeText.isEmpty())
            {
                timeText = jsonValueToText(kObject.value(QStringLiteral("TimeCreated")));
            }
            record.timeText = collapseSpaces(timeText);

            record.idText = jsonValueToText(kObject.value(QStringLiteral("IdText")));
            if (record.idText.isEmpty())
            {
                record.idText = jsonValueToText(kObject.value(QStringLiteral("Id")));
            }

            record.levelText = jsonValueToText(kObject.value(QStringLiteral("LevelText")));
            if (record.levelText.isEmpty())
            {
                record.levelText = jsonValueToText(kObject.value(QStringLiteral("LevelDisplayName")));
            }

            record.messageText = jsonValueToText(kObject.value(QStringLiteral("MessageText")));
            if (record.messageText.isEmpty())
            {
                record.messageText = jsonValueToText(kObject.value(QStringLiteral("Message")));
            }
            record.messageText = collapseSpaces(record.messageText);
            {
                QStringList errorParts;
                const QString kErrorText = jsonValueToText(kObject.value(QStringLiteral("ErrorText"))).trimmed();
                const QString kErrorCategory = jsonValueToText(kObject.value(QStringLiteral("ErrorCategory"))).trimmed();
                const QString kErrorType = jsonValueToText(kObject.value(QStringLiteral("ErrorType"))).trimmed();
                const QString kHresultText = jsonValueToText(kObject.value(QStringLiteral("HResult"))).trimmed();
                if (!kErrorText.isEmpty()) errorParts << QStringLiteral("ErrorId=%1").arg(kErrorText);
                if (!kErrorCategory.isEmpty()) errorParts << QStringLiteral("Category=%1").arg(kErrorCategory);
                if (!kErrorType.isEmpty()) errorParts << QStringLiteral("Type=%1").arg(kErrorType);
                if (!kHresultText.isEmpty()) errorParts << QStringLiteral("HResult=%1").arg(kHresultText);
                if (!errorParts.isEmpty())
                {
                    record.messageText = QStringLiteral("%1 | %2")
                        .arg(record.messageText)
                        .arg(errorParts.join(QStringLiteral(" | "))).trimmed();
                }
            }

            record.verdictText = jsonValueToText(kObject.value(QStringLiteral("VerdictText")));
            if (record.verdictText.isEmpty())
            {
                record.verdictText = jsonValueToText(kObject.value(QStringLiteral("Verdict")));
            }
            if (record.verdictText.trimmed().isEmpty())
            {
                record.verdictText = classifyCodeIntegrityVerdict(record.messageText, record.levelText);
            }

            if (record.verdictText == QStringLiteral("允许")) ++allowCount;
            else if (record.verdictText == QStringLiteral("阻止")) ++blockCount;
            else if (record.verdictText == QStringLiteral("审计")) ++auditCount;

            if (record.messageText.isEmpty())
            {
                record.messageText = QStringLiteral("—");
            }
            if (record.idText.isEmpty())
            {
                record.idText = QStringLiteral("—");
            }
            if (record.levelText.isEmpty())
            {
                record.levelText = QStringLiteral("—");
            }
            if (record.timeText.isEmpty())
            {
                record.timeText = QStringLiteral("—");
            }
            records.push_back(record);
        }

        if (records.size() == 1)
        {
            const EventRecord& onlyRecord = records.front();
            if (onlyRecord.timeText == QStringLiteral("—")
                && onlyRecord.idText == QStringLiteral("—")
                && onlyRecord.messageText.contains(QStringLiteral("error"), Qt::CaseInsensitive))
            {
                return { records, QStringLiteral("Code Integrity 事件读取失败：%1").arg(onlyRecord.messageText) };
            }
        }

        QString summaryText = QStringLiteral("最近 %1 条事件：允许 %2，阻止 %3，审计 %4。")
            .arg(records.size())
            .arg(allowCount)
            .arg(blockCount)
            .arg(auditCount);
        return { records, summaryText };
    }

    std::pair<QVector<ApplicationControlPage::KeyValueRecord>, QString> ApplicationControlPage::parseDefenderJson(
        const QString& jsonText)
    {
        QVector<KeyValueRecord> records;
        const QString kTrimmedText = jsonText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return { records, QStringLiteral("未获取到 Defender 数据。") };
        }

        QJsonParseError parseError{};
        const QJsonDocument kDocument = QJsonDocument::fromJson(kTrimmedText.toUtf8(), &parseError);
        if (parseError.error != QJsonParseError::NoError)
        {
            return { records, QStringLiteral("Defender JSON 解析失败：%1").arg(parseError.errorString()) };
        }

        QJsonArray array;
        if (kDocument.isArray())
        {
            array = kDocument.array();
        }
        else if (kDocument.isObject())
        {
            const QJsonObject kRootObject = kDocument.object();
            if (kRootObject.value(QStringLiteral("Rows")).isArray())
            {
                array = kRootObject.value(QStringLiteral("Rows")).toArray();
            }
            else
            {
                array.push_back(kRootObject);
            }
        }

        for (const QJsonValue& value : array)
        {
            const QJsonObject kObject = value.toObject();
            KeyValueRecord record;
            record.nameText = jsonValueToText(kObject.value(QStringLiteral("Name")));
            record.valueText = jsonValueToText(kObject.value(QStringLiteral("Value")));
            record.detailText = jsonValueToText(kObject.value(QStringLiteral("Detail")));
            if (record.nameText.isEmpty())
            {
                record.nameText = jsonValueToText(kObject.value(QStringLiteral("Key")));
            }
            if (record.valueText.isEmpty())
            {
                record.valueText = QStringLiteral("—");
            }
            if (record.detailText.isEmpty())
            {
                record.detailText = QStringLiteral("—");
            }
            records.push_back(record);
        }

        QStringList queryFailureSummaries;
        for (const KeyValueRecord& record : records)
        {
            const bool kIsDefenderFailure = record.nameText.contains(QStringLiteral("Defender"), Qt::CaseInsensitive)
                && (record.valueText.contains(QStringLiteral("Failed"), Qt::CaseInsensitive)
                    || record.valueText.contains(QStringLiteral("Unavailable"), Qt::CaseInsensitive));
            if (!kIsDefenderFailure)
            {
                continue;
            }

            const QString kDetailText = record.detailText.trimmed();
            if (kDetailText.contains(QStringLiteral("0x800106BA"), Qt::CaseInsensitive))
            {
                queryFailureSummaries.push_back(
                    QStringLiteral("%1：HRESULT 0x800106BA，Microsoft Defender Antivirus Service (WinDefend) 未启动、已禁用或已由其他安全产品接管。")
                        .arg(record.nameText));
            }
            else
            {
                queryFailureSummaries.push_back(
                    QStringLiteral("%1：%2")
                        .arg(record.nameText, kDetailText.isEmpty() ? QStringLiteral("未返回错误代码。") : kDetailText));
            }
        }
        if (!queryFailureSummaries.isEmpty())
        {
            return { records, queryFailureSummaries.join(QStringLiteral("\n")) };
        }

        const QString kSummaryText = QStringLiteral("Defender 状态共 %1 条。").arg(records.size());
        return { records, kSummaryText };
    }

    void ApplicationControlPage::refreshAsync()
    {
        if (refreshButton_ != nullptr)
        {
            refreshButton_->setEnabled(false);
        }
        if (exportButton_ != nullptr)
        {
            exportButton_->setEnabled(false);
        }
        if (appLockerEditButton_ != nullptr)
        {
            appLockerEditButton_->setEnabled(false);
        }
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(QStringLiteral("状态: 正在刷新…"));
        }
        if (appLockerSummary_ != nullptr) appLockerSummary_->setText(QStringLiteral("正在采集 AppLocker…"));
        if (wdacSummary_ != nullptr) wdacSummary_->setText(QStringLiteral("正在采集 WDAC / Code Integrity…"));
        if (defenderSummary_ != nullptr) defenderSummary_->setText(QStringLiteral("正在采集 Defender…"));
        if (platformSummary_ != nullptr) platformSummary_->setText(QStringLiteral("正在采集平台安全…"));
        if (eventSummary_ != nullptr) eventSummary_->setText(QStringLiteral("正在采集事件日志…"));

        const std::uint64_t kRefreshGeneration = ++refreshGeneration_;
        const int kRequestedEventLimit = selectedEventLimit();
        const QPointer<ApplicationControlPage> kGuardThis(this);
        std::thread([kGuardThis, kRequestedEventLimit, kRefreshGeneration]() {
            QVector<AppLockerRuleRecord> appLockerRules;
            QVector<PolicyFileRecord> policyFiles;
            QVector<EventRecord> events;
            QVector<KeyValueRecord> defenderRows;
            QVector<KeyValueRecord> platformRows;
            QString appLockerSummary = QStringLiteral("AppLocker: 未配置");
            QString wdacSummary = QStringLiteral("WDAC / Code Integrity: 未发现常见策略文件。");
            QString defenderSummary = QStringLiteral("Defender: 未获取到状态。");
            QString platformSummary = QStringLiteral("平台安全: 未获取到状态。");
            QString eventSummary = QStringLiteral("未获取到 Code Integrity 事件。");
            QString statusText = QStringLiteral("刷新完成");
            QStringList r0PlatformSummaryParts;

            // appendPlatformRow：
            // - Input: Name, value, and description for a row in the platform security table;
            // - Processing: Append to the platformRows cache in the background thread.
            // - Return: None. The table is ultimately refreshed uniformly by the UI thread.
            const auto kAppendPlatformRow = [&platformRows](
                const QString& nameText,
                const QString& valueText,
                const QString& detailText) {
                KeyValueRecord record;
                record.nameText = nameText;
                record.valueText = valueText;
                record.detailText = detailText;
                platformRows.push_back(record);
            };

            // 1) WDAC / Code Integrity file scanning is performed directly by C++ to avoid extra script dependencies.
            const QFileInfo kSipolicyFile(QStringLiteral("C:/Windows/System32/CodeIntegrity/SIPolicy.p7b"));
            const QFileInfo kActiveDir(QStringLiteral("C:/Windows/System32/CodeIntegrity/CiPolicies/Active"));
            const auto kAppendPolicyFile = [&policyFiles](const QString& pathText, const QFileInfo& fileInfo, const QString& detailText, const QString& countText) {
                PolicyFileRecord record;
                record.pathText = pathText;
                record.existsText = fileInfo.exists() ? QStringLiteral("Yes") : QStringLiteral("No");
                record.sizeText = fileInfo.exists() ? sizeTextFromBytes(fileInfo.size()) : QStringLiteral("—");
                record.modifiedText = fileInfo.exists() ? dateTimeText(fileInfo.lastModified()) : QStringLiteral("—");
                record.countText = countText;
                record.detailText = detailText;
                policyFiles.push_back(record);
            };

            kAppendPolicyFile(
                QStringLiteral("C:\\Windows\\System32\\CodeIntegrity\\SIPolicy.p7b"),
                kSipolicyFile,
                QStringLiteral("主 SIPolicy 文件"),
                kSipolicyFile.exists() ? QStringLiteral("1") : QStringLiteral("0"));

            int activeCount = 0;
            if (kActiveDir.exists())
            {
                const QFileInfoList kActiveFiles = QDir(kActiveDir.absoluteFilePath()).entryInfoList(
                    QStringList{ QStringLiteral("*.cip") },
                    QDir::Files | QDir::Readable,
                    QDir::Name);
                activeCount = kActiveFiles.size();
                for (const QFileInfo& fileInfo : kActiveFiles)
                {
                    kAppendPolicyFile(
                        fileInfo.absoluteFilePath(),
                        fileInfo,
                        QStringLiteral("Active 目录下的 CIP 策略"),
                        QStringLiteral("1"));
                }
            }
            else
            {
                kAppendPolicyFile(
                    QStringLiteral("C:\\Windows\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip"),
                    QFileInfo(),
                    QStringLiteral("Active 目录不存在"),
                    QStringLiteral("0"));
            }

            const int kPolicyFileCount = (kSipolicyFile.exists() ? 1 : 0) + activeCount;
            wdacSummary = QStringLiteral(
                "WDAC / Code Integrity 常见策略文件数: %1\n"
                "- SIPolicy.p7b: %2\n"
                "- Active/*.cip: %3")
                .arg(kPolicyFileCount)
                .arg(kSipolicyFile.exists() ? QStringLiteral("存在") : QStringLiteral("未找到"))
                .arg(activeCount);

            // 2) AppLocker: Probe for the module first. If the module is unavailable (e.g., on Windows Home Edition), do not misreport the missing capability as a permission or service failure.
            const QString kAppLockerScript = QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "$module=Get-Module -ListAvailable -Name AppLocker | Select-Object -First 1;"
                "if($null -eq $module){Write-Output '__APPLOCKER_MODULE_UNAVAILABLE__';exit 0};"
                "try {"
                "  Import-Module -Name $module.Path -ErrorAction Stop;"
                "  $xml=[string](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop);"
                "  if([string]::IsNullOrWhiteSpace($xml)){Write-Output '__NO_POLICY__'; exit 0};"
                "  Write-Output '__OK__';"
                "  Write-Output $xml;"
                "} catch {"
                "  $msg=$_.Exception.Message;"
                "  if($msg -match 'No AppLocker policy|not configured|未配置'){Write-Output '__NO_POLICY__'}"
                "  else { Write-Output '__ERROR__'; Write-Output $msg }"
                "}");
            QString appLockerErrorText;
            const QString kAppLockerOutput = runPowerShellCaptureText(kAppLockerScript, 15000, &appLockerErrorText);
            QString appLockerXmlText;
            if (kAppLockerOutput.startsWith(QStringLiteral("__OK__")))
            {
                appLockerXmlText = kAppLockerOutput.section(QChar::LineFeed, 1);
            }
            else if (kAppLockerOutput.contains(QStringLiteral("__APPLOCKER_MODULE_UNAVAILABLE__")))
            {
                appLockerSummary = QStringLiteral(
                    "AppLocker 模块不可用。\n"
                    "当前 Windows 未提供 AppLocker PowerShell 管理组件，无法读取、创建或修改 AppLocker 策略。\n"
                    "Windows 家庭版通常不支持 AppLocker。\n"
                    "WDAC、Defender、平台安全、事件日志和文件诊断仍可使用。");
            }
            else if (kAppLockerOutput.contains(QStringLiteral("__NO_POLICY__")))
            {
                appLockerSummary = QStringLiteral("AppLocker: 未配置");
            }
            else
            {
                const QString kParseHint = appLockerErrorText.isEmpty() ? kAppLockerOutput : appLockerErrorText;
                appLockerSummary = QStringLiteral("AppLocker 读取失败。\n建议：以管理员身份运行，并确认 Application Identity (AppIDSvc) 服务可用。\n%1")
                    .arg(kParseHint.isEmpty() ? QStringLiteral("未返回额外错误信息。") : kParseHint);
            }

            if (!appLockerXmlText.trimmed().isEmpty())
            {
                const auto kParsedAppLocker = parseAppLockerPolicyXml(appLockerXmlText);
                appLockerRules = kParsedAppLocker.first;
                if (!kParsedAppLocker.second.trimmed().isEmpty())
                {
                    appLockerSummary = kParsedAppLocker.second;
                }
                if (appLockerRules.isEmpty())
                {
                    appLockerSummary = QStringLiteral("AppLocker: 未配置");
                }
            }

            // 3) Defender / ASR outputs as a JSON array via PowerShell, enabling direct UI consumption.
            const QString kDefenderScript = QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "function Get-DefenderErrorDetail($errorRecord){"
                "  $parts=@();$exception=$errorRecord.Exception;"
                "  while($null -ne $exception){"
                "    $parts+=('ErrorType='+$exception.GetType().FullName);"
                "    if($exception.HResult -ne 0){$parts+=('HRESULT=0x{0:X8}' -f ($exception.HResult -band 0xFFFFFFFF))};"
                "    foreach($propertyName in @('NativeErrorCode','ErrorCode','StatusCode')){"
                "      $property=$exception.PSObject.Properties[$propertyName];"
                "      if($null -ne $property -and $null -ne $property.Value){$parts+=($propertyName+'='+$property.Value)}"
                "    };"
                "    $exception=$exception.InnerException"
                "  };"
                "  foreach($match in [regex]::Matches([string]$errorRecord.Exception.Message,'(?i)0x[0-9a-f]{8}')){$parts+=('UnderlyingHRESULT='+$match.Value.ToUpper())};"
                "  if(-not [string]::IsNullOrWhiteSpace($errorRecord.FullyQualifiedErrorId)){$parts+=('FullyQualifiedErrorId='+$errorRecord.FullyQualifiedErrorId)};"
                "  if($null -ne $errorRecord.CategoryInfo){$parts+=('Category='+$errorRecord.CategoryInfo.Category)};"
                "  ($parts | Select-Object -Unique) -join ' | '"
                "};"
                "$rows=@();$pref=$null;"
                "try {"
                "  $pref=Get-MpPreference -ErrorAction Stop;"
                "  $rows += [pscustomobject]@{Name='Controlled Folder Access'; Value=($pref.EnableControlledFolderAccess); Detail='0=Off,1=Block,2=Audit'};"
                "  $rows += [pscustomobject]@{Name='PUA Protection'; Value=($pref.PUAProtection); Detail='0=Disabled,1=Enabled,2=Audit'};"
                "  $rows += [pscustomobject]@{Name='Network Protection'; Value=($pref.EnableNetworkProtection); Detail='0=Disabled,1=Block,2=Audit'};"
                "  $asrIds=$pref.AttackSurfaceReductionRules_Ids;$asrActions=$pref.AttackSurfaceReductionRules_Actions;"
                "  $count=[Math]::Min(@($asrIds).Count,@($asrActions).Count);"
                "  for($i=0; $i -lt $count; $i++){ $rows += [pscustomobject]@{Name=('ASR '+$asrIds[$i]); Value=($asrActions[$i]); Detail='AttackSurfaceReduction rule'} }"
                "} catch { $rows += [pscustomobject]@{Name='Defender preferences'; Value='Unavailable'; Detail=(Get-DefenderErrorDetail $_)} };"
                "try {"
                "  $status=Get-MpComputerStatus -ErrorAction Stop;"
                "  if($status.PSObject.Properties['SmartScreenEnabled']) { $rows += [pscustomobject]@{Name='SmartScreen'; Value=($status.SmartScreenEnabled); Detail='Available from Get-MpComputerStatus'} };"
                "  $rows += [pscustomobject]@{Name='Real Time Protection'; Value=($status.RealTimeProtectionEnabled); Detail='Get-MpComputerStatus'};"
                "  $rows += [pscustomobject]@{Name='Tamper Protection'; Value=($status.IsTamperProtected); Detail='Get-MpComputerStatus'}"
                "} catch {"
                "  $detail=Get-DefenderErrorDetail $_;"
                "  if($detail -match '(?i)0x800106ba'){$detail='HRESULT=0x800106BA | WinDefend service is not active | '+$detail};"
                "  $rows += [pscustomobject]@{Name='Defender service status'; Value='Unavailable'; Detail=$detail}"
                "};"
                "$rows | ConvertTo-Json -Depth 4");
            QString defenderErrorText;
            const QString kDefenderJsonText = runPowerShellCaptureText(kDefenderScript, 15000, &defenderErrorText);
            if (!kDefenderJsonText.trimmed().isEmpty())
            {
                const auto kParsedDefender = parseDefenderJson(kDefenderJsonText);
                defenderRows = kParsedDefender.first;
                defenderSummary = kParsedDefender.second;
                if (!defenderErrorText.trimmed().isEmpty())
                {
                    defenderSummary += QStringLiteral("\n%1").arg(defenderErrorText);
                }
            }
            else if (!defenderErrorText.trimmed().isEmpty())
            {
                defenderSummary = QStringLiteral("Defender 模块不可用或读取失败：%1").arg(defenderErrorText);
            }

            // 4) Platform security, CI, VBS, Hyper-V, Driver Trust, and BAM are all collected in read-only mode.
            const QString kPlatformScript = QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "try {"
                "  $rows=@();"
                "  $dg=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop;"
                "  $rows += [pscustomobject]@{Name='CI SecurityServicesConfigured'; Value=([string]::Join(',', @($dg.SecurityServicesConfigured))); Detail='DeviceGuard'};"
                "  $rows += [pscustomobject]@{Name='CI SecurityServicesRunning'; Value=([string]::Join(',', @($dg.SecurityServicesRunning))); Detail='DeviceGuard'};"
                "  $rows += [pscustomobject]@{Name='VirtualizationBasedSecurityStatus'; Value=$dg.VirtualizationBasedSecurityStatus; Detail='0=Off,1=Enabled,2=Running'};"
                "  $rows += [pscustomobject]@{Name='RequiresPlatformSecurityFeatures'; Value=$dg.RequiredSecurityProperties; Detail='DeviceGuard'};"
                "  $rows += [pscustomobject]@{Name='Hyper-V Service'; Value=((Get-Service vmms -ErrorAction SilentlyContinue).Status); Detail='Virtual Machine Management Service'};"
                "  $rows += [pscustomobject]@{Name='VMBus Service'; Value=((Get-Service vmbus -ErrorAction SilentlyContinue).Status); Detail='Virtual Machine Bus'};"
                "  $rows += [pscustomobject]@{Name='vSwitch Service'; Value=((Get-Service vswitch -ErrorAction SilentlyContinue).Status); Detail='Hyper-V Virtual Switch'};"
                "  $rows += [pscustomobject]@{Name='vPCI Service'; Value=((Get-Service vpci -ErrorAction SilentlyContinue).Status); Detail='Virtual PCI'};"
                "  $rows += [pscustomobject]@{Name='HvSocket Service'; Value=((Get-Service hvsocket -ErrorAction SilentlyContinue).Status); Detail='Hyper-V Socket'};"
                "  $bam=@(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\*' -ErrorAction SilentlyContinue | Measure-Object).Count;"
                "  $rows += [pscustomobject]@{Name='BAM Keys'; Value=$bam; Detail='HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings'};"
                "  $ah=@(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\amcache' -ErrorAction SilentlyContinue | Measure-Object).Count;"
                "  $rows += [pscustomobject]@{Name='ahcache Keys'; Value=$ah; Detail='HKLM\\SYSTEM\\CurrentControlSet\\Services\\amcache'};"
                "  $rows | ConvertTo-Json -Depth 4"
                "} catch {"
                "  [pscustomobject]@{Name='Platform query'; Value='Failed'; Detail=$_.Exception.Message} | ConvertTo-Json -Depth 3"
                "}");
            QString platformErrorText;
            const QString kPlatformJsonText = runPowerShellCaptureText(kPlatformScript, 15000, &platformErrorText);
            if (!kPlatformJsonText.trimmed().isEmpty())
            {
                const auto kParsedPlatform = parseDefenderJson(kPlatformJsonText);
                platformRows = kParsedPlatform.first;
                platformSummary = kParsedPlatform.second;
                if (!platformErrorText.trimmed().isEmpty())
                {
                    platformSummary += QStringLiteral("\n%1").arg(platformErrorText);
                }
            }
            else if (!platformErrorText.trimmed().isEmpty())
            {
                platformSummary = QStringLiteral("平台安全读取失败：%1").arg(platformErrorText);
            }


            // 5) R0 security posture audit is queried via ArkDriverClient wrapper; only appends summary lines, does not replace WMI/PowerShell baselines.
            try
            {
                const ksword::ark::DriverClient kArkClient;
                const ksword::ark::SecurityStatusAuditResult kSecurityStatus = kArkClient.querySecurityStatus();
                const ksword::ark::DriverTrustViewAuditResult kDriverTrust = kArkClient.queryDriverTrustView();
                const ksword::ark::HyperVSummaryAuditResult kHyperVSummary = kArkClient.queryHyperVSummary();
                const ksword::ark::AppControlStatusAuditResult kAppControlStatus = kArkClient.queryAppControlStatus();

                const auto& securityResponse = kSecurityStatus.response;
                kAppendPlatformRow(
                    QStringLiteral("R0 Security / CI"),
                    QStringLiteral("CI=%1, UMCI=%2, Options=%3")
                        .arg(boolFlagText(securityResponse.ciEnabled))
                        .arg(boolFlagText(securityResponse.umciEnabled))
                        .arg(hexMaskText(securityResponse.codeIntegrityOptions)),
                    QStringLiteral("fieldFlags=%1, sourceMask=%2, query=%3, ciStatus=%4, io=%5")
                        .arg(hexMaskText(securityResponse.fieldFlags))
                        .arg(hexMaskText(securityResponse.sourceMask))
                        .arg(ntStatusText(securityResponse.queryStatus))
                        .arg(ntStatusText(securityResponse.codeIntegrityStatus))
                        .arg(ioSummaryText(kSecurityStatus.io)));

                kAppendPlatformRow(
                    QStringLiteral("R0 Security / VBS-HVCI-SKCI"),
                    QStringLiteral("VBS=%1, HVCI=%2, SKCI=%3")
                        .arg(boolFlagText(securityResponse.vbsPresent))
                        .arg(boolFlagText(securityResponse.hvciKmciEnabled))
                        .arg(boolFlagText(securityResponse.skciModuleLoaded)),
                    QStringLiteral("secureKernel=%1, hvciAudit=%2, hvciStrict=%3, hvciIum=%4, moduleStatus=%5")
                        .arg(boolFlagText(securityResponse.secureKernelModuleLoaded))
                        .arg(boolFlagText(securityResponse.hvciAuditMode))
                        .arg(boolFlagText(securityResponse.hvciStrictMode))
                        .arg(boolFlagText(securityResponse.hvciIumEnabled))
                        .arg(ntStatusText(securityResponse.moduleQueryStatus)));

                kAppendPlatformRow(
                    QStringLiteral("R0 Security / Test signing"),
                    QStringLiteral("testSigning=%1, testBuild=%2")
                        .arg(boolFlagText(securityResponse.testSigningEnabled))
                        .arg(boolFlagText(securityResponse.testBuild)),
                    QStringLiteral("flightBuild=%1, flighting=%2, secureBoot=%3, secureBootCapable=%4, secureBootStatus=%5")
                        .arg(boolFlagText(securityResponse.flightBuild))
                        .arg(boolFlagText(securityResponse.flightingEnabled))
                        .arg(boolFlagText(securityResponse.secureBootEnabled))
                        .arg(boolFlagText(securityResponse.secureBootCapable))
                        .arg(ntStatusText(securityResponse.secureBootStatus)));

                kAppendPlatformRow(
                    QStringLiteral("R0 Security / Debug posture"),
                    QStringLiteral("kdEnabled=%1, kdNotPresent=%2, ciDebug=%3")
                        .arg(boolFlagText(securityResponse.kernelDebuggerEnabled))
                        .arg(boolFlagText(securityResponse.kernelDebuggerNotPresent))
                        .arg(boolFlagText(securityResponse.ciDebugModeEnabled)),
                    QStringLiteral("debuggerStatus=%1, ciModuleLoaded=%2, io=%3")
                        .arg(ntStatusText(securityResponse.debuggerStatus))
                        .arg(boolFlagText(securityResponse.ciModuleLoaded))
                        .arg(r0IoMessageText(kSecurityStatus.io.message)));

                const auto& hyperVResponse = kHyperVSummary.response;
                kAppendPlatformRow(
                    QStringLiteral("R0 Hyper-V / Present"),
                    QStringLiteral("present=%1, vendor=%2")
                        .arg(boolFlagText(hyperVResponse.hypervisorPresent))
                        .arg(fixedWideText(hyperVResponse.hypervisorVendor, KSWORD_ARK_SECURITY_AUDIT_VENDOR_CHARS)),
                    QStringLiteral("fieldFlags=%1, sourceMask=%2, query=%3, root=%4, io=%5")
                        .arg(hexMaskText(hyperVResponse.fieldFlags))
                        .arg(hexMaskText(hyperVResponse.sourceMask))
                        .arg(ntStatusText(hyperVResponse.queryStatus))
                        .arg(auditStateText(hyperVResponse.rootPartitionStatus))
                        .arg(ioSummaryText(kHyperVSummary.io)));

                kAppendPlatformRow(
                    QStringLiteral("R0 Hyper-V / Modules"),
                    QStringLiteral("vmbus=%1, vswitch=%2, vpci=%3, hvsocket=%4")
                        .arg(auditStateText(hyperVResponse.vmbusStatus))
                        .arg(auditStateText(hyperVResponse.vSwitchStatus))
                        .arg(auditStateText(hyperVResponse.vPciStatus))
                        .arg(auditStateText(hyperVResponse.hvSocketStatus)),
                    QStringLiteral("winhv=%1, winhvruntime=%2, hvloader=%3, moduleStatus=%4")
                        .arg(auditStateText(hyperVResponse.winHvStatus))
                        .arg(auditStateText(hyperVResponse.winHvRuntimeStatus))
                        .arg(auditStateText(hyperVResponse.hvLoaderStatus))
                        .arg(ntStatusText(hyperVResponse.moduleQueryStatus)));

                const auto& appControlResponse = kAppControlStatus.response;
                kAppendPlatformRow(
                    QStringLiteral("R0 AppControl / Summary"),
                    QStringLiteral("AppID=%1, policy=%2, AppLocker=%3")
                        .arg(auditStateText(appControlResponse.appidStatus))
                        .arg(auditStateText(appControlResponse.appidPolicyStatus))
                        .arg(auditStateText(appControlResponse.appLockerFilterStatus)),
                    QStringLiteral("fieldFlags=%1, sourceMask=%2, query=%3, moduleStatus=%4, io=%5")
                        .arg(hexMaskText(appControlResponse.fieldFlags))
                        .arg(hexMaskText(appControlResponse.sourceMask))
                        .arg(ntStatusText(appControlResponse.queryStatus))
                        .arg(ntStatusText(appControlResponse.moduleQueryStatus))
                        .arg(ioSummaryText(kAppControlStatus.io)));

                kAppendPlatformRow(
                    QStringLiteral("R0 AppControl / Filters"),
                    QStringLiteral("mssecflt=%1, BAM=%2, ahcache=%3")
                        .arg(auditStateText(appControlResponse.mssecfltStatus))
                        .arg(auditStateText(appControlResponse.bamStatus))
                        .arg(auditStateText(appControlResponse.ahcacheStatus)),
                    QStringLiteral("AppLockerOwner=%1, AppLockerOwnerStatus=%2, mssecfltOwner=%3, mssecfltOwnerStatus=%4")
                        .arg(fixedWideText(appControlResponse.appLockerOwnerModule, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS))
                        .arg(auditStateText(appControlResponse.appLockerCallbackOwnerStatus))
                        .arg(fixedWideText(appControlResponse.mssecfltOwnerModule, KSWORD_ARK_SECURITY_AUDIT_NAME_CHARS))
                        .arg(auditStateText(appControlResponse.mssecfltCallbackOwnerStatus)));

                kAppendPlatformRow(
                    QStringLiteral("R0 DriverTrust / Counts"),
                    QStringLiteral("returned=%1, total=%2, truncated=%3")
                        .arg(kDriverTrust.returnedCount)
                        .arg(kDriverTrust.totalCount)
                        .arg(kDriverTrust.truncated),
                    QStringLiteral("fieldFlags=%1, sourceMask=%2, maxAccepted=%3, moduleStatus=%4, signingStatus=%5")
                        .arg(hexMaskText(kDriverTrust.fieldFlags))
                        .arg(hexMaskText(kDriverTrust.sourceMask))
                        .arg(kDriverTrust.maxEntriesAccepted)
                        .arg(ntStatusText(kDriverTrust.moduleQueryStatus))
                        .arg(ntStatusText(kDriverTrust.signingResolverStatus)));

                kAppendPlatformRow(
                    QStringLiteral("R0 DriverTrust / IO"),
                    r0IoMessageText(kDriverTrust.io.message),
                    ioSummaryText(kDriverTrust.io));

                r0PlatformSummaryParts << QStringLiteral("SecurityStatus=%1/%2")
                    .arg(kSecurityStatus.io.ok ? QStringLiteral("OK") : QStringLiteral("Fail"))
                    .arg(ntStatusText(kSecurityStatus.io.ntStatus));
                r0PlatformSummaryParts << QStringLiteral("DriverTrust returned=%1 total=%2 truncated=%3")
                    .arg(kDriverTrust.returnedCount)
                    .arg(kDriverTrust.totalCount)
                    .arg(kDriverTrust.truncated);
                r0PlatformSummaryParts << QStringLiteral("HyperV present=%1 vendor=%2 flags=%3")
                    .arg(boolFlagText(hyperVResponse.hypervisorPresent))
                    .arg(fixedWideText(hyperVResponse.hypervisorVendor, KSWORD_ARK_SECURITY_AUDIT_VENDOR_CHARS))
                    .arg(hexMaskText(hyperVResponse.fieldFlags));
                r0PlatformSummaryParts << QStringLiteral("AppControl AppID=%1 AppLocker=%2 mssecflt=%3 BAM=%4")
                    .arg(auditStateText(appControlResponse.appidStatus))
                    .arg(auditStateText(appControlResponse.appLockerFilterStatus))
                    .arg(auditStateText(appControlResponse.mssecfltStatus))
                    .arg(auditStateText(appControlResponse.bamStatus));
            }
            catch (const std::exception& exception)
            {
                kAppendPlatformRow(
                    QStringLiteral("内核安全审计"),
                    QStringLiteral("Exception"),
                    QString::fromLocal8Bit(exception.what()));
                r0PlatformSummaryParts << QStringLiteral("R0 安全态势读取异常: %1").arg(QString::fromLocal8Bit(exception.what()));
            }
            catch (...)
            {
                kAppendPlatformRow(
                    QStringLiteral("内核安全审计"),
                    QStringLiteral("Exception"),
                    QStringLiteral("未知异常"));
                r0PlatformSummaryParts << QStringLiteral("R0 安全态势读取异常: 未知异常");
            }

            if (!r0PlatformSummaryParts.isEmpty())
            {
                platformSummary += QStringLiteral("\nR0 安全态势：%1").arg(r0PlatformSummaryParts.join(QStringLiteral(" | ")));
            }

            // 5) Code Integrity events are also output as a JSON array via PowerShell.
            const QString kEventScript = QStringLiteral(
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                "try {"
                "  $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'} -MaxEvents %1 -ErrorAction Stop;"
                "  $events | ForEach-Object {"
                "    $message = $_.Message;"
                "    $level = $_.LevelDisplayName;"
                "    $lower = if($message){ $message.ToLower() } else { '' };"
                "    $verdict = if($lower -match 'audit|审计|would have been blocked'){ '审计' } elseif($lower -match 'block|deny|阻止|not allowed'){ '阻止' } elseif($lower -match 'allow|loaded|允许'){ '允许' } else { '事件' };"
                "    [pscustomobject]@{TimeText=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); IdText=$_.Id; LevelText=$level; VerdictText=$verdict; MessageText=$message}"
                "  } | ConvertTo-Json -Depth 4"
                "} catch {"
                "  [pscustomobject]@{TimeText=''; IdText=''; LevelText=''; VerdictText='读取失败'; MessageText=$_.Exception.Message; ErrorText=$_.FullyQualifiedErrorId; ErrorCategory=$_.CategoryInfo.Category; ErrorType=$_.Exception.GetType().FullName; HResult=('0x{0:X8}' -f ($_.Exception.HResult -band 0xFFFFFFFF))} | ConvertTo-Json -Depth 3"
                "}").arg(kRequestedEventLimit);
            QString eventErrorText;
            const QString kEventJsonText = runPowerShellCaptureText(kEventScript, 15000, &eventErrorText);
            if (!kEventJsonText.trimmed().isEmpty())
            {
                const auto kParsedEvents = parseEventsJson(kEventJsonText);
                events = kParsedEvents.first;
                eventSummary = kParsedEvents.second;
                if (!eventErrorText.trimmed().isEmpty())
                {
                    eventSummary += QStringLiteral("\n%1").arg(eventErrorText);
                }
            }
            else if (!eventErrorText.trimmed().isEmpty())
            {
                eventSummary = QStringLiteral("Code Integrity 事件读取失败：%1").arg(eventErrorText);
            }

            if (appLockerSummary.isEmpty())
            {
                appLockerSummary = QStringLiteral("AppLocker: 未配置");
            }

            if (kGuardThis == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(qApp, [kGuardThis,
                                             kRefreshGeneration,
                                             statusText,
                                             appLockerSummary,
                                              wdacSummary,
                                              defenderSummary,
                                              platformSummary,
                                              eventSummary,
                                              appLockerRules = std::move(appLockerRules),
                                              policyFiles = std::move(policyFiles),
                                              events = std::move(events),
                                              defenderRows = std::move(defenderRows),
                                              platformRows = std::move(platformRows)]() mutable {
                if (kGuardThis == nullptr)
                {
                    return;
                }
                kGuardThis->applyRefreshResult(
                    kRefreshGeneration,
                    statusText,
                    appLockerSummary,
                    wdacSummary,
                    defenderSummary,
                    platformSummary,
                    eventSummary,
                    std::move(appLockerRules),
                    std::move(policyFiles),
                    std::move(events),
                    std::move(defenderRows),
                    std::move(platformRows));
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ApplicationControlPage::applyRefreshResult(
        const std::uint64_t refreshGeneration,
        QString statusText,
        QString appLockerSummary,
        QString wdacSummary,
        QString defenderSummary,
        QString platformSummary,
        QString eventSummary,
        QVector<AppLockerRuleRecord> appLockerRules,
        QVector<PolicyFileRecord> policyFiles,
        QVector<EventRecord> events,
        QVector<KeyValueRecord> defenderRows,
        QVector<KeyValueRecord> platformRows)
    {
        // Only allow the last initiated task to write back; this check also covers re-entry after a right-click menu delay.
        if (refreshGeneration != refreshGeneration_)
        {
            return;
        }

        const QList<QTableView*> kApplicationControlTables = {
            appLockerTable_,
            policyFileTable_,
            codeIntegrityEventTable_,
            defenderTable_,
            platformTable_,
            eventTable_
        };
        if (ks::ui::isTableUiCommitBlockedByContextMenu(kApplicationControlTables))
        {
            const QPointer<ApplicationControlPage> kSafeThis(this);
            ks::ui::deferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("application-control-refresh-apply"),
                kApplicationControlTables,
                [kSafeThis,
                    refreshGeneration,
                    statusText = std::move(statusText),
                    appLockerSummary = std::move(appLockerSummary),
                    wdacSummary = std::move(wdacSummary),
                    defenderSummary = std::move(defenderSummary),
                    platformSummary = std::move(platformSummary),
                    eventSummary = std::move(eventSummary),
                    appLockerRules = std::move(appLockerRules),
                    policyFiles = std::move(policyFiles),
                    events = std::move(events),
                    defenderRows = std::move(defenderRows),
                    platformRows = std::move(platformRows)]() mutable
                {
                    if (!kSafeThis.isNull())
                    {
                        kSafeThis->applyRefreshResult(
                            refreshGeneration,
                            std::move(statusText),
                            std::move(appLockerSummary),
                            std::move(wdacSummary),
                            std::move(defenderSummary),
                            std::move(platformSummary),
                            std::move(eventSummary),
                            std::move(appLockerRules),
                            std::move(policyFiles),
                            std::move(events),
                            std::move(defenderRows),
                            std::move(platformRows));
                    }
                });
            return;
        }

        appLockerRules_ = std::move(appLockerRules);
        appLockerModuleAvailable_ = !appLockerSummary.startsWith(QStringLiteral("AppLocker 模块不可用"));

        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(QStringLiteral("状态: %1").arg(statusText));
        }

        if (appLockerSummary_ != nullptr)
        {
            appLockerSummary_->setText(appLockerSummary);
        }
        if (appLockerEditButton_ != nullptr)
        {
            appLockerEditButton_->setEnabled(appLockerModuleAvailable_ && pendingMutationCount_ == 0);
        }
        if (wdacSummary_ != nullptr)
        {
            wdacSummary_->setText(wdacSummary);
        }
        if (defenderSummary_ != nullptr)
        {
            defenderSummary_->setText(defenderSummary);
        }
        if (platformSummary_ != nullptr)
        {
            platformSummary_->setText(platformSummary);
        }
        if (eventSummary_ != nullptr)
        {
            eventSummary_->setProperty("ks_event_base_summary", eventSummary);
            eventSummary_->setText(eventSummary);
        }

        QVector<QStringList> appLockerRows;
        QVector<QVariant> appLockerRuleIds;
        appLockerRows.reserve(appLockerRules_.size());
        appLockerRuleIds.reserve(appLockerRules_.size());
        for (const AppLockerRuleRecord& record : appLockerRules_)
        {
            appLockerRows.push_back(QStringList{
                record.collectionText,
                record.actionText,
                record.userText,
                record.sidText,
                record.conditionTypeText,
                record.conditionText,
                record.descriptionText,
                record.riskText
            });
            appLockerRuleIds.push_back(record.idText);
        }
        fillTable(
            appLockerTable_,
            QStringList{
                QStringLiteral("规则集合"),
                QStringLiteral("Action"),
                QStringLiteral("User"),
                QStringLiteral("SID"),
                QStringLiteral("条件类型"),
                QStringLiteral("路径 / 发布者 / Hash"),
                QStringLiteral("描述"),
                QStringLiteral("风险")
            },
            appLockerRows,
            appLockerRuleIds);

        QVector<QStringList> policyRows;
        policyRows.reserve(policyFiles.size());
        for (const PolicyFileRecord& record : policyFiles)
        {
            policyRows.push_back(QStringList{
                record.pathText,
                record.existsText,
                record.sizeText,
                record.modifiedText,
                record.countText,
                record.detailText
            });
        }
        fillTable(
            policyFileTable_,
            QStringList{
                QStringLiteral("文件路径"),
                QStringLiteral("存在"),
                QStringLiteral("大小"),
                QStringLiteral("修改时间"),
                QStringLiteral("策略数量"),
                QStringLiteral("说明")
            },
            policyRows);

        eventRows_ = std::move(events);

        QVector<QStringList> eventRows;
        eventRows.reserve(eventRows_.size());
        for (const EventRecord& record : eventRows_)
        {
            eventRows.push_back(QStringList{
                record.timeText,
                record.idText,
                record.levelText,
                record.verdictText,
                record.messageText
            });
        }
        fillTable(
            codeIntegrityEventTable_,
            QStringList{
                QStringLiteral("时间"),
                QStringLiteral("事件 ID"),
                QStringLiteral("级别"),
                QStringLiteral("判定"),
                QStringLiteral("消息")
            },
            eventRows);
        rebuildEventTable();

        QVector<QStringList> defenderRowsTable;
        defenderRowsTable.reserve(defenderRows.size());
        for (const KeyValueRecord& record : defenderRows)
        {
            defenderRowsTable.push_back(QStringList{
                record.nameText,
                record.valueText,
                record.detailText
            });
        }
        fillTable(
            defenderTable_,
            QStringList{
                QStringLiteral("字段"),
                QStringLiteral("值"),
                QStringLiteral("说明")
            },
            defenderRowsTable);

        QVector<QStringList> platformRowsTable;
        platformRowsTable.reserve(platformRows.size());
        for (const KeyValueRecord& record : platformRows)
        {
            platformRowsTable.push_back(QStringList{
                record.nameText,
                record.valueText,
                record.detailText
            });
        }
        fillTable(
            platformTable_,
            QStringList{
                QStringLiteral("字段"),
                QStringLiteral("值"),
                QStringLiteral("说明")
            },
            platformRowsTable);

        if (refreshButton_ != nullptr)
        {
            refreshButton_->setEnabled(true);
        }
        if (exportButton_ != nullptr)
        {
            exportButton_->setEnabled(true);
        }
    }

    int ApplicationControlPage::selectedEventLimit() const
    {
        const QString kText = eventLimitCombo_ != nullptr
            ? eventLimitCombo_->currentText()
            : QStringLiteral("最近 200 条");
        const QRegularExpression kNumberPattern(QStringLiteral("(\\d+)"));
        const QRegularExpressionMatch kMatch = kNumberPattern.match(kText);
        if (!kMatch.hasMatch())
        {
            return 200;
        }
        return std::clamp(kMatch.captured(1).toInt(), 50, 2000);
    }

    void ApplicationControlPage::rebuildEventTable()
    {
        const QPointer<ApplicationControlPage> kSafeThis(this);
        if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("application-control-event-filter-rebuild"),
            {eventTable_},
            [kSafeThis]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->rebuildEventTable();
                }
            }))
        {
            return;
        }

        const QString kSelectedVerdictText = eventVerdictFilterCombo_ != nullptr
            ? eventVerdictFilterCombo_->currentText()
            : QStringLiteral("全部分类");

        QVector<QStringList> visibleRows;
        visibleRows.reserve(eventRows_.size());
        for (const EventRecord& record : eventRows_)
        {
            const bool kMatched =
                kSelectedVerdictText == QStringLiteral("全部分类") ||
                record.verdictText.compare(kSelectedVerdictText, Qt::CaseInsensitive) == 0;
            if (!kMatched)
            {
                continue;
            }

            visibleRows.push_back(QStringList{
                record.timeText,
                record.idText,
                record.levelText,
                record.verdictText,
                record.messageText
            });
        }

        fillTable(
            eventTable_,
            QStringList{
                QStringLiteral("时间"),
                QStringLiteral("事件 ID"),
                QStringLiteral("级别"),
                QStringLiteral("判定"),
                QStringLiteral("消息")
            },
            visibleRows);

        if (eventSummary_ != nullptr)
        {
            const QString kBaseSummary = eventSummary_->property("ks_event_base_summary").toString().trimmed().isEmpty()
                ? eventSummary_->text().section(QStringLiteral("\n筛选："), 0, 0)
                : eventSummary_->property("ks_event_base_summary").toString();
            if (kSelectedVerdictText == QStringLiteral("全部分类"))
            {
                eventSummary_->setText(kBaseSummary);
            }
            else
            {
                eventSummary_->setText(QStringLiteral("%1\n筛选：%2，显示 %3 / %4。")
                    .arg(kBaseSummary)
                    .arg(kSelectedVerdictText)
                    .arg(visibleRows.size())
                    .arg(eventRows_.size()));
            }
        }
    }

    QString ApplicationControlPage::buildPathMatchHint(
        const QString& filePathText,
        const QVector<AppLockerRuleRecord>& appLockerRules)
    {
        if (appLockerRules.isEmpty())
        {
            return QStringLiteral("当前没有 AppLocker 规则缓存，无法判断路径命中。");
        }

        QString sanitizedPathText = filePathText.trimmed();
        sanitizedPathText.remove(QChar('"'));
        const QFileInfo kFileInfo(sanitizedPathText);
        const QString kNormalizedPath = QDir::toNativeSeparators(kFileInfo.exists() ? kFileInfo.absoluteFilePath() : sanitizedPathText);
        QStringList matches;

        for (const AppLockerRuleRecord& record : appLockerRules)
        {
            if (!record.conditionTypeText.contains(QStringLiteral("Path"), Qt::CaseInsensitive))
            {
                continue;
            }

            QString conditionText = record.conditionText;
            const QRegularExpression kPathExtractor(QStringLiteral("Path=([^;|]+)"), QRegularExpression::CaseInsensitiveOption);
            const QRegularExpressionMatch kMatch = kPathExtractor.match(conditionText);
            if (kMatch.hasMatch())
            {
                conditionText = kMatch.captured(1).trimmed();
            }

            conditionText = expandCommonEnvironmentTokens(conditionText);
            const QRegularExpression kRegex = pathLikeTextToRegex(conditionText);
            const bool kMatched = kRegex.isValid()
                ? kRegex.match(kNormalizedPath).hasMatch()
                : kNormalizedPath.compare(conditionText, Qt::CaseInsensitive) == 0;
            if (!kMatched)
            {
                continue;
            }

            matches.push_back(QStringLiteral("%1 | %2 | %3 | %4")
                .arg(record.collectionText, record.actionText, record.userText, conditionText));
        }

        if (matches.isEmpty())
        {
            return QStringLiteral("未发现明显的 AppLocker 路径规则命中。");
        }

        return QStringLiteral("可能命中 %1 条 AppLocker 路径规则：\n%2")
            .arg(matches.size())
            .arg(matches.join(QStringLiteral("\n")));
    }

    void ApplicationControlPage::runFileDiagnosisAsync()
    {
        QString filePath = filePathEdit_ != nullptr ? filePathEdit_->text().trimmed() : QString();
        filePath.remove(QChar('"'));
        if (filePath.isEmpty())
        {
            QMessageBox::information(this, QStringLiteral("文件诊断"), QStringLiteral("请输入文件路径。"));
            return;
        }

        if (fileDiagnoseButton_ != nullptr)
        {
            fileDiagnoseButton_->setEnabled(false);
        }
        if (fileDiagnosisSummary_ != nullptr)
        {
            fileDiagnosisSummary_->setText(QStringLiteral("正在诊断：%1").arg(filePath));
        }

        // Take an implicit shared snapshot on the UI thread so the background thread no longer reads the QWidget-owned cache.
        QVector<AppLockerRuleRecord> appLockerRulesSnapshot = appLockerRules_;
        const QPointer<ApplicationControlPage> kGuardThis(this);
        std::thread([kGuardThis,
                     filePath,
                     appLockerRulesSnapshot = std::move(appLockerRulesSnapshot)]() {
            QVector<KeyValueRecord> rows;
            QString summaryText;

            const QFileInfo kFileInfo(filePath);
            const bool kExists = kFileInfo.exists() && kFileInfo.isFile();
            const QString kNormalizedPath = QDir::toNativeSeparators(kFileInfo.exists() ? kFileInfo.absoluteFilePath() : filePath);
            const QString kSuffixText = kFileInfo.suffix().toLower();
            const QString kPublisherText = kExists
                ? QString::fromStdString(ks::startup::queryPublisherTextByPath(filePath.toStdString()))
                : QString();
            const QString kPathMatchHint = ApplicationControlPage::buildPathMatchHint(
                filePath,
                appLockerRulesSnapshot);

            const auto kPushRow = [&rows](const QString& nameText, const QString& valueText, const QString& detailText) {
                KeyValueRecord record;
                record.nameText = nameText;
                record.valueText = valueText;
                record.detailText = detailText;
                rows.push_back(record);
            };

            kPushRow(QStringLiteral("文件存在"), kExists ? QStringLiteral("Yes") : QStringLiteral("No"), kNormalizedPath);
            kPushRow(QStringLiteral("文件类型"), kSuffixText.isEmpty() ? QStringLiteral("—") : kSuffixText.toUpper(), QStringLiteral("输入文件扩展名"));

            if (kExists)
            {
                QFile file(kFileInfo.absoluteFilePath());
                if (file.open(QIODevice::ReadOnly))
                {
                    QCryptographicHash sha256(QCryptographicHash::Sha256);
                    while (!file.atEnd())
                    {
                        const QByteArray kChunk = file.read(1024 * 1024);
                        if (!kChunk.isEmpty())
                        {
                            sha256.addData(kChunk);
                        }
                    }
                    kPushRow(QStringLiteral("SHA256"), QString::fromLatin1(sha256.result().toHex()), QStringLiteral("QCryptographicHash"));
                }
                else
                {
                    kPushRow(QStringLiteral("SHA256"), QStringLiteral("读取失败"), file.errorString());
                }
            }
            else
            {
                kPushRow(QStringLiteral("SHA256"), QStringLiteral("—"), QStringLiteral("文件不存在"));
            }

            kPushRow(
                QStringLiteral("签名/发布者"),
                kPublisherText.isEmpty() ? QStringLiteral("未获取到") : kPublisherText,
                QStringLiteral("复用 ks::startup::QueryPublisherTextByPath / WinVerifyTrust"));

            kPushRow(
                QStringLiteral("AppLocker 路径命中"),
                kPathMatchHint,
                QStringLiteral("只读推测，不修改策略"));

            kPushRow(
                QStringLiteral("WDAC 提示"),
                QStringLiteral("若系统存在 WDAC / Code Integrity 策略，请结合事件日志判断最终结果。"),
                QStringLiteral("第一版仅做存在性和事件诊断"));

            QString testAppLockerText;
            if (kExists)
            {
                QString escapedFilePath = filePath;
                escapedFilePath.replace(QStringLiteral("'"), QStringLiteral("''"));
                const QString kTestScript = appLockerPowerShellPrelude() + QStringLiteral(
                    "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
                    "try {"
                    "  $path='%1';"
                    "  $result = Test-AppLockerPolicy -Path $path -ErrorAction Stop;"
                    "  if($null -eq $result){ Write-Output '__NO_RESULT__' } else { $result | Out-String -Width 65535 }"
                    "} catch {"
                    "  Write-Output '__ERROR__';"
                    "  Write-Output $_.Exception.Message"
                    "}")
                    .arg(escapedFilePath);
                QString testErrorText;
                testAppLockerText = runPowerShellCaptureText(kTestScript, 12000, &testErrorText);
                if (!testAppLockerText.trimmed().isEmpty())
                {
                    kPushRow(QStringLiteral("Test-AppLockerPolicy"), collapseSpaces(testAppLockerText), QStringLiteral("PowerShell 结构化测试"));
                }
                else if (!testErrorText.trimmed().isEmpty())
                {
                    kPushRow(QStringLiteral("Test-AppLockerPolicy"), QStringLiteral("不可用"), testErrorText);
                }
            }

            summaryText = QStringLiteral(
                "文件：%1\n存在：%2\n发布者：%3\n路径命中：%4")
                .arg(kNormalizedPath)
                .arg(kExists ? QStringLiteral("Yes") : QStringLiteral("No"))
                .arg(kPublisherText.isEmpty() ? QStringLiteral("未获取到") : kPublisherText)
                .arg(kPathMatchHint);

            if (kGuardThis == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(qApp, [kGuardThis, summaryText, rows = std::move(rows)]() mutable {
                if (kGuardThis == nullptr)
                {
                    return;
                }
                kGuardThis->applyFileDiagnosisResult(summaryText, std::move(rows));
            }, Qt::QueuedConnection);
        }).detach();
    }

    void ApplicationControlPage::applyFileDiagnosisResult(QString summaryText, QVector<KeyValueRecord> rows)
    {
        if (ks::ui::isTableUiCommitBlockedByContextMenu({fileDiagnosisTable_}))
        {
            const QPointer<ApplicationControlPage> kSafeThis(this);
            ks::ui::deferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("application-control-file-diagnosis-apply"),
                {fileDiagnosisTable_},
                [kSafeThis,
                    summaryText = std::move(summaryText),
                    rows = std::move(rows)]() mutable
                {
                    if (!kSafeThis.isNull())
                    {
                        kSafeThis->applyFileDiagnosisResult(
                            std::move(summaryText),
                            std::move(rows));
                    }
                });
            return;
        }

        if (fileDiagnosisSummary_ != nullptr)
        {
            fileDiagnosisSummary_->setText(summaryText);
        }

        QVector<QStringList> tableRows;
        tableRows.reserve(rows.size());
        for (const KeyValueRecord& record : rows)
        {
            tableRows.push_back(QStringList{ record.nameText, record.valueText, record.detailText });
        }
        fillTable(
            fileDiagnosisTable_,
            QStringList{ QStringLiteral("检查项"), QStringLiteral("结果"), QStringLiteral("说明") },
            tableRows);

        if (fileDiagnoseButton_ != nullptr)
        {
            fileDiagnoseButton_->setEnabled(true);
        }
    }
}
