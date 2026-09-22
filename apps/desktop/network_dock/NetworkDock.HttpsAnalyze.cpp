#include "NetworkDock.InternalCommon.h"
#include "../ui/UiSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "HttpsProxyService.h"
#include "../Theme.h"

#include <QApplication>
#include <QFileDialog>
#include <QSaveFile>
#include <QTextStream>
#include <WinInet.h>

#pragma comment(lib, "Wininet.lib")

using namespace network_dock_detail;

namespace
{
    // HttpsParsedColumn: HTTPS parsed table column index definition.
    enum HttpsParsedColumn
    {
        kHttpsParsedColumnTime = 0,
        kHttpsParsedColumnSession,
        kHttpsParsedColumnClient,
        kHttpsParsedColumnProcess,
        kHttpsParsedColumnHost,
        kHttpsParsedColumnEvent,
        kHttpsParsedColumnMethod,
        kHttpsParsedColumnPath,
        kHttpsParsedColumnStatus,
        kHttpsParsedColumnContentType,
        kHttpsParsedColumnTls,
        kHttpsParsedColumnAlpn,
        kHttpsParsedColumnElapsed,
        kHttpsParsedColumnUpload,
        kHttpsParsedColumnDownload,
        kHttpsParsedColumnDetail,
        kHttpsParsedColumnCount
    };

    // kMaxHttpsParsedEntries usage: Limits the number of records in the UI and detail cache to prevent memory growth during long-term monitoring.
    constexpr int kMaxHttpsParsedEntries = 10000;

    // g_httpsProxyBusyOperationActive usage:
    // - Flag whether the HTTPS analysis page has background tasks like 'root certificate preparation' or 'proxy stop' in progress;
    // - Disable control bar buttons uniformly during the task to prevent re-entry and provide clear user feedback.
    // - Only one HTTPS parsing page exists within the process, and all read/write operations occur on the UI thread;
    //   therefore, a file-level static state is used to avoid modifying the shared NetworkDock.h across multiple files.
    bool gHttpsProxyBusyOperationActive = false;

    // buildHttpsProxyStatusText:
    // - Construct the status label text based on the proxy running state, allowing the same text to be reused when restoring the label via asynchronous callbacks.
    // Parameter proxyRunning: whether the proxy is running.
    // Parameter listenAddressText: current listening address text.
    // Parameter listenPort: Current listening port.
    // Returns: Status text ready to be passed directly to updateHttpsProxyStatusLabel.
    QString buildHttpsProxyStatusText(
        const bool proxyRunning,
        const QString& listenAddressText,
        const std::uint16_t listenPort)
    {
        if (!proxyRunning)
        {
            return QStringLiteral("状态：HTTPS代理未启动");
        }
        return QStringLiteral("状态：HTTPS代理已启动，监听 %1:%2")
            .arg(listenAddressText)
            .arg(listenPort);
    }

    // buildHttpsDetailWindowStyle:
    // - Generate independent theme styles for the HTTPS detail window.
    // - Focus coverage on QPlainTextEdit/QTabWidget/QLabel; fix residual white backgrounds in dark mode.
    QString buildHttpsDetailWindowStyle()
    {
        const QString kWindowBackground = ksword_theme::surfaceHex();
        const QString kPanelBackground = ksword_theme::surfaceAltHex();
        // The muted background color has no corresponding role in the palette; fall back to alternate-base.
        // The input area retains a 1px border for distinction; the visual difference is negligible.
        const QString kInputBackground = ksword_theme::surfaceAltHex();
        const QString kBorderColor = ksword_theme::borderHex();
        const QString kTextColor = ksword_theme::textPrimaryHex();
        const QString kSecondaryTextColor = ksword_theme::textSecondaryHex();
        const QString kAccentColor = ksword_theme::kPrimaryBlueHex;

        return QStringLiteral(
            "QWidget{"
            "  background:%1;"
            "  color:%2;"
            "}"
            "QLabel{"
            "  background:transparent;"
            "  color:%2;"
            "}"
            "QTabWidget::pane{"
            "  background:%3;"
            "  border:1px solid %4;"
            "  border-radius:4px;"
            "}"
            "QTabBar::tab{"
            "  background:%1;"
            "  color:%5;"
            "  border:1px solid %4;"
            "  padding:6px 12px;"
            "  margin-right:2px;"
            "  border-top-left-radius:4px;"
            "  border-top-right-radius:4px;"
            "}"
            "QTabBar::tab:selected{"
            "  background:%3;"
            "  color:%2;"
            "  border-bottom-color:%3;"
            "}"
            "QPlainTextEdit{"
            "  background:%6;"
            "  color:%2;"
            "  border:1px solid %4;"
            "  selection-background-color:%7;"
            "  selection-color:%8;"
            "}"
            "QMenu{"
            "  background:%6;"
            "  color:%2;"
            "  border:1px solid %4;"
            "}"
            "QMenu::item:selected{"
            "  background:%7;"
            "  color:%8;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%4;"
            "  margin:2px 6px;"
            "}"
            "QScrollBar:vertical,QScrollBar:horizontal{"
            "  background:%3;"
            "}"
            "QScrollBar::handle:vertical,QScrollBar::handle:horizontal{"
            "  background:%7;"
            "}")
            .arg(kWindowBackground)
            .arg(kTextColor)
            .arg(kPanelBackground)
            .arg(kBorderColor)
            .arg(kSecondaryTextColor)
            .arg(kInputBackground)
            .arg(kAccentColor)
            .arg(ksword_theme::onAccentDynamicHex());
    }

    class HttpsParsedDetailWindow final : public QWidget
    {
    public:
        explicit HttpsParsedDetailWindow(const ks::network::HttpsProxyParsedEntry& parsedEntry, QWidget* parent = nullptr)
            : QWidget(parent)
        {
            // wrapFieldHtml:
            // - Wrap long fields into auto-wrapping rich text blocks;
            // - Prevent long paths/hostnames from expanding the details window horizontally beyond the screen;
            const auto kWrapFieldHtml =
                [](const QString& fieldText) -> QString
                {
                    return QStringLiteral(
                        "<div style='white-space:pre-wrap;word-break:break-all;'>%1</div>")
                        .arg(fieldText.toHtmlEscaped());
                };

            setAttribute(Qt::WA_DeleteOnClose, true);
            setWindowFlag(Qt::Window, true);
            setAttribute(Qt::WA_StyledBackground, true);
            setAutoFillBackground(true);
            setWindowTitle(QStringLiteral("HTTPS详情 - #%1 %2")
                .arg(parsedEntry.sessionId)
                .arg(parsedEntry.eventTypeText));
            ks::ui::applyResponsiveWindowGeometry(
                this,
                parent,
                QSize(1376, 720),
                QSize(720, 480));
            setStyleSheet(buildHttpsDetailWindowStyle());

            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(8, 8, 8, 8);
            rootLayout->setSpacing(6);

            QLabel* metaLabel = new QLabel(this);
            metaLabel->setWordWrap(true);
            metaLabel->setTextFormat(Qt::RichText);
            metaLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            metaLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
            metaLabel->setStyleSheet(QStringLiteral("padding:6px 8px;border:1px solid %1;border-radius:4px;")
                .arg(ksword_theme::borderHex()));
            metaLabel->setText(QStringLiteral(
                "时间: %1<br/>客户端: %2<br/>进程: %3<br/>目标: %4:%5<br/>事件: %6<br/>方法: %7<br/>路径: %8<br/>状态码: %9<br/>内容类型: %10<br/>内容长度: %11<br/>耗时: %12 ms<br/>上行/下行: %13 / %14 字节<br/>TLS: %15<br/>ALPN: %16<br/>密码套件: %17<br/>SNI: %18<br/>证书主体: %19<br/>证书签发者: %20<br/>证书到期: %21<br/>证书 SHA-256: %22<br/>详情: %23")
                .arg(QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(parsedEntry.timestampMs)).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")))
                .arg(kWrapFieldHtml(parsedEntry.clientEndpointText))
                .arg(kWrapFieldHtml(parsedEntry.clientProcessText))
                .arg(kWrapFieldHtml(parsedEntry.targetHostText))
                .arg(parsedEntry.targetPort)
                .arg(kWrapFieldHtml(parsedEntry.eventTypeText))
                .arg(kWrapFieldHtml(parsedEntry.methodText))
                .arg(kWrapFieldHtml(parsedEntry.pathText))
                .arg(parsedEntry.statusCode)
                .arg(kWrapFieldHtml(parsedEntry.contentTypeText))
                .arg(parsedEntry.contentLength >= 0 ? QString::number(parsedEntry.contentLength) : QStringLiteral("未知"))
                .arg(parsedEntry.elapsedMs)
                .arg(parsedEntry.uploadBytes)
                .arg(parsedEntry.downloadBytes)
                .arg(kWrapFieldHtml(parsedEntry.tlsVersionText))
                .arg(kWrapFieldHtml(parsedEntry.alpnText))
                .arg(kWrapFieldHtml(parsedEntry.cipherSuiteText))
                .arg(kWrapFieldHtml(parsedEntry.sniText))
                .arg(kWrapFieldHtml(parsedEntry.certificateSubjectText))
                .arg(kWrapFieldHtml(parsedEntry.certificateIssuerText))
                .arg(kWrapFieldHtml(parsedEntry.certificateExpiryText))
                .arg(kWrapFieldHtml(parsedEntry.certificateSha256Text))
                .arg(kWrapFieldHtml(parsedEntry.detailText)));
            rootLayout->addWidget(metaLabel);

            QTabWidget* tabWidget = new QTabWidget(this);
            rootLayout->addWidget(tabWidget, 1);

            QWidget* hexPage = new QWidget(tabWidget);
            QVBoxLayout* hexLayout = new QVBoxLayout(hexPage);
            hexLayout->setContentsMargins(0, 0, 0, 0);
            hexLayout->setSpacing(4);

            QLabel* hintLabel = new QLabel(QStringLiteral("下方使用项目内现有 HexEditorWidget 展示 HTTPS 事件原始字节。"), hexPage);
            hintLabel->setWordWrap(true);
            hintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
            hexLayout->addWidget(hintLabel);

            HexEditorWidget* hexEditorWidget = new HexEditorWidget(hexPage);
            hexEditorWidget->setEditable(false);
            hexEditorWidget->setBytesPerRow(16);
            if (!parsedEntry.rawBytes.isEmpty())
            {
                hexEditorWidget->setByteArray(parsedEntry.rawBytes, 0);
            }
            else
            {
                hexEditorWidget->clearData();
            }
            hexLayout->addWidget(hexEditorWidget, 1);
            tabWidget->addTab(hexPage, QStringLiteral("十六进制"));

            QWidget* textPage = new QWidget(tabWidget);
            QVBoxLayout* textLayout = new QVBoxLayout(textPage);
            textLayout->setContentsMargins(0, 0, 0, 0);
            textLayout->setSpacing(4);

            QPlainTextEdit* textEditor = new QPlainTextEdit(textPage);
            textEditor->setReadOnly(true);
            textEditor->setLineWrapMode(QPlainTextEdit::NoWrap);
            textEditor->setPlainText(QString::fromUtf8(parsedEntry.rawBytes));
            textLayout->addWidget(textEditor, 1);
            tabWidget->addTab(textPage, QStringLiteral("文本"));
        }
    };

    // refreshInternetSettings:
    // - Notify WinINet to refresh proxy settings.
    // - Returns true only if both notifications succeed; the transaction recovery uses this to determine if it is safe to clear.
    bool refreshInternetSettings(QString* errorTextOut)
    {
        const BOOL kChangedOk = ::InternetSetOptionW(
            nullptr,
            INTERNET_OPTION_SETTINGS_CHANGED,
            nullptr,
            0);
        const DWORD kChangedError = kChangedOk ? ERROR_SUCCESS : ::GetLastError();
        const BOOL kRefreshOk = ::InternetSetOptionW(
            nullptr,
            INTERNET_OPTION_REFRESH,
            nullptr,
            0);
        const DWORD kRefreshError = kRefreshOk ? ERROR_SUCCESS : ::GetLastError();
        if (kChangedOk && kRefreshOk)
        {
            return true;
        }
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral(
                "刷新 WinINet 代理配置失败：SETTINGS_CHANGED=%1，REFRESH=%2")
                .arg(kChangedError)
                .arg(kRefreshError);
        }
        return false;
    }

    // writeInternetSettingString:
    // - Write string-type proxy items to the current user's Internet Settings.
    bool writeInternetSettingString(const wchar_t* valueName, const QString& valueText, QString* errorTextOut)
    {
        const std::wstring kValueNameText = std::wstring(valueName);
        const std::wstring kValueDataText = valueText.toStdWString();
        const LONG kResultCode = ::RegSetKeyValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            kValueNameText.c_str(),
            REG_SZ,
            kValueDataText.c_str(),
            static_cast<DWORD>((kValueDataText.size() + 1) * sizeof(wchar_t)));
        if (kResultCode != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("写入注册表失败：%1").arg(kResultCode);
            }
            return false;
        }
        return true;
    }

    // writeInternetSettingDword:
    // - Write the DWORD-type proxy entry to the current user's Internet Settings.
    bool writeInternetSettingDword(const wchar_t* valueName, const DWORD valueData, QString* errorTextOut)
    {
        const LONG kResultCode = ::RegSetKeyValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName,
            REG_DWORD,
            &valueData,
            sizeof(valueData));
        if (kResultCode != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("写入注册表失败：%1").arg(kResultCode);
            }
            return false;
        }
        return true;
    }

    // readInternetSettingString: Reads optional string configuration items under the current user's Internet Settings.
    bool readInternetSettingString(const wchar_t* valueName, std::optional<QString>* valueOut, QString* errorTextOut)
    {
        if (valueOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("代理配置输出对象为空。");
            }
            return false;
        }

        DWORD dataSize = 0;
        const LONG kSizeResult = ::RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName,
            RRF_RT_REG_SZ,
            nullptr,
            nullptr,
            &dataSize);
        if (kSizeResult == ERROR_FILE_NOT_FOUND)
        {
            valueOut->reset();
            return true;
        }
        if (kSizeResult != ERROR_SUCCESS || dataSize > 64 * 1024 || dataSize % sizeof(wchar_t) != 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("读取代理配置失败：%1").arg(kSizeResult);
            }
            return false;
        }

        std::vector<wchar_t> valueBuffer(static_cast<std::size_t>(dataSize / sizeof(wchar_t)) + 1, L'\0');
        DWORD readSize = dataSize;
        const LONG kReadResult = ::RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName,
            RRF_RT_REG_SZ,
            nullptr,
            valueBuffer.data(),
            &readSize);
        if (kReadResult != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("读取代理配置失败：%1").arg(kReadResult);
            }
            return false;
        }

        *valueOut = QString::fromWCharArray(valueBuffer.data());
        return true;
    }

    // readInternetSettingDword purpose: Read optional DWORD configuration items under the current user's Internet Settings.
    bool readInternetSettingDword(const wchar_t* valueName, std::optional<std::uint32_t>* valueOut, QString* errorTextOut)
    {
        if (valueOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("代理配置输出对象为空。");
            }
            return false;
        }

        DWORD valueData = 0;
        DWORD dataSize = sizeof(valueData);
        const LONG kReadResult = ::RegGetValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName,
            RRF_RT_REG_DWORD,
            nullptr,
            &valueData,
            &dataSize);
        if (kReadResult == ERROR_FILE_NOT_FOUND)
        {
            valueOut->reset();
            return true;
        }
        if (kReadResult != ERROR_SUCCESS || dataSize != sizeof(valueData))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("读取代理配置失败：%1").arg(kReadResult);
            }
            return false;
        }

        *valueOut = static_cast<std::uint32_t>(valueData);
        return true;
    }

    // deleteInternetSetting purpose: Delete the specified value under the current user's Internet Settings to restore it to a non-existent state.
    bool deleteInternetSetting(const wchar_t* valueName, QString* errorTextOut)
    {
        const LONG kDeleteResult = ::RegDeleteKeyValueW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            valueName);
        if (kDeleteResult != ERROR_SUCCESS && kDeleteResult != ERROR_FILE_NOT_FOUND)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("删除代理配置失败：%1").arg(kDeleteResult);
            }
            return false;
        }
        return true;
    }

    // buildHttpsProxyServerText: Replaces only the HTTPS proxy endpoint while preserving existing protocol-specific proxy entries.
    QString buildHttpsProxyServerText(const QString& originalProxyServerText, const QString& httpsEndpointText)
    {
        const QString kTrimmedOriginalText = originalProxyServerText.trimmed();
        if (kTrimmedOriginalText.isEmpty())
        {
            return QStringLiteral("https=%1").arg(httpsEndpointText);
        }

        const QStringList kEntryList = kTrimmedOriginalText.split(';', Qt::SkipEmptyParts);
        QStringList outputEntryList;
        outputEntryList.reserve(kEntryList.size() + 1);
        bool hasProtocolSpecificEntry = false;
        bool httpsEntryReplaced = false;
        for (const QString& rawEntryText : kEntryList)
        {
            const QString kEntryText = rawEntryText.trimmed();
            const int kEqualIndex = kEntryText.indexOf('=');
            if (kEqualIndex <= 0)
            {
                outputEntryList.append(kEntryText);
                continue;
            }

            hasProtocolSpecificEntry = true;
            const QString kProtocolText = kEntryText.left(kEqualIndex).trimmed();
            if (kProtocolText.compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0)
            {
                outputEntryList.append(QStringLiteral("https=%1").arg(httpsEndpointText));
                httpsEntryReplaced = true;
            }
            else
            {
                outputEntryList.append(kEntryText);
            }
        }

        if (hasProtocolSpecificEntry)
        {
            if (!httpsEntryReplaced)
            {
                outputEntryList.append(QStringLiteral("https=%1").arg(httpsEndpointText));
            }
            return outputEntryList.join(';');
        }

        // The original configuration applies a single endpoint to all protocols. During HTTPS monitoring, explicitly retain this endpoint for HTTP to avoid losing the original HTTP proxy.
        return QStringLiteral("http=%1;https=%2").arg(kTrimmedOriginalText, httpsEndpointText);
    }
}

void NetworkDock::initializeHttpsAnalyzeTab()
{
    httpsAnalyzePage_ = new QWidget(this);
    httpsAnalyzeLayout_ = new QVBoxLayout(httpsAnalyzePage_);
    httpsAnalyzeLayout_->setContentsMargins(6, 6, 6, 6);
    httpsAnalyzeLayout_->setSpacing(6);

    httpsAnalyzeControlLayout_ = new QHBoxLayout();
    httpsAnalyzeControlLayout_->setSpacing(6);

    httpsListenAddressEdit_ = new QLineEdit(QStringLiteral("127.0.0.1"), httpsAnalyzePage_);
    httpsListenAddressEdit_->setToolTip(QStringLiteral("HTTPS代理监听地址。"));
    httpsListenAddressEdit_->setMaximumWidth(140);

    httpsListenPortSpin_ = new QSpinBox(httpsAnalyzePage_);
    httpsListenPortSpin_->setRange(1, 65535);
    httpsListenPortSpin_->setValue(8889);
    httpsListenPortSpin_->setToolTip(QStringLiteral("HTTPS代理监听端口。"));

    httpsStartProxyButton_ = new QPushButton(QStringLiteral("启动代理"), httpsAnalyzePage_);
    httpsStartProxyButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    // Capture scope integrated with the start button: Users decide whether to enable it here, and this is also where they learn what traffic cannot be captured.
    httpsStartProxyButton_->setToolTip(QStringLiteral("启动本地 HTTPS 解析代理。只记录经过本地系统代理的 HTTP/1.1 流量；QUIC/HTTP/3、直连流量和启用证书锁定的应用不会进入本表。"));

    httpsStopProxyButton_ = new QPushButton(QStringLiteral("停止代理"), httpsAnalyzePage_);
    httpsStopProxyButton_->setIcon(QIcon(":/Icon/process_pause.svg"));
    httpsStopProxyButton_->setToolTip(QStringLiteral("停止本地 HTTPS 解析代理。"));

    httpsTrustCertButton_ = new QPushButton(QStringLiteral("信任证书"), httpsAnalyzePage_);
    httpsTrustCertButton_->setIcon(QIcon(":/Icon/process_details.svg"));
    httpsTrustCertButton_->setToolTip(QStringLiteral("一键生成并信任 HTTPS 代理根证书。"));

    httpsApplyProxyButton_ = new QPushButton(QStringLiteral("应用系统代理"), httpsAnalyzePage_);
    httpsApplyProxyButton_->setIcon(QIcon(":/Icon/process_main.svg"));
    httpsApplyProxyButton_->setToolTip(QStringLiteral("把系统代理切换到本地 HTTPS 代理。"));

    httpsClearProxyButton_ = new QPushButton(QStringLiteral("还原系统代理"), httpsAnalyzePage_);
    httpsClearProxyButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    httpsClearProxyButton_->setToolTip(QStringLiteral("恢复本页应用 HTTPS 代理前保存的系统代理配置。"));

    httpsProxyStatusLabel_ = new QLabel(QStringLiteral("状态：HTTPS代理未启动"), httpsAnalyzePage_);
    httpsProxyStatusLabel_->setWordWrap(true);
    httpsProxyStatusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    httpsAnalyzeControlLayout_->addWidget(new QLabel(QStringLiteral("监听地址:"), httpsAnalyzePage_));
    httpsAnalyzeControlLayout_->addWidget(httpsListenAddressEdit_);
    httpsAnalyzeControlLayout_->addWidget(new QLabel(QStringLiteral("端口:"), httpsAnalyzePage_));
    httpsAnalyzeControlLayout_->addWidget(httpsListenPortSpin_);
    httpsAnalyzeControlLayout_->addWidget(httpsStartProxyButton_);
    httpsAnalyzeControlLayout_->addWidget(httpsStopProxyButton_);
    httpsAnalyzeControlLayout_->addWidget(httpsTrustCertButton_);
    httpsAnalyzeControlLayout_->addWidget(httpsApplyProxyButton_);
    httpsAnalyzeControlLayout_->addWidget(httpsClearProxyButton_);
    httpsAnalyzeControlLayout_->addWidget(httpsProxyStatusLabel_, 1);
    httpsAnalyzeLayout_->addLayout(httpsAnalyzeControlLayout_);

    QHBoxLayout* parsedFilterLayout = new QHBoxLayout();
    parsedFilterLayout->setSpacing(6);
    httpsParsedFilterEdit_ = new QLineEdit(httpsAnalyzePage_);
    httpsParsedFilterEdit_->setClearButtonEnabled(true);
    httpsParsedFilterEdit_->setPlaceholderText(QStringLiteral("筛选主机、路径、方法、状态码、内容类型、TLS 或详情..."));
    httpsParsedFilterEdit_->setToolTip(QStringLiteral("实时筛选当前 HTTPS 解析记录，不影响代理转发或完整缓存。"));
    httpsParsedEventFilterCombo_ = new QComboBox(httpsAnalyzePage_);
    httpsParsedEventFilterCombo_->addItem(QStringLiteral("全部事件"));
    httpsParsedEventFilterCombo_->addItem(QStringLiteral("CONNECT"));
    httpsParsedEventFilterCombo_->addItem(QStringLiteral("TLS"));
    httpsParsedEventFilterCombo_->addItem(QStringLiteral("REQUEST"));
    httpsParsedEventFilterCombo_->addItem(QStringLiteral("RESPONSE"));
    httpsParsedEventFilterCombo_->addItem(QStringLiteral("SUMMARY"));
    httpsParsedEventFilterCombo_->addItem(QStringLiteral("ERROR"));
    httpsParsedEventFilterCombo_->setToolTip(QStringLiteral("按 HTTPS 代理事件类型筛选。"));
    httpsClearParsedButton_ = new QPushButton(QStringLiteral("清空解析结果"), httpsAnalyzePage_);
    httpsClearParsedButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    httpsClearParsedButton_->setToolTip(QStringLiteral("清空解析表和详情缓存，不停止 HTTPS 代理。"));
    httpsExportParsedButton_ = new QPushButton(QStringLiteral("导出可见 CSV"), httpsAnalyzePage_);
    httpsExportParsedButton_->setIcon(QIcon(":/Icon/log_copy.svg"));
    httpsExportParsedButton_->setToolTip(QStringLiteral("将当前筛选后可见的 HTTPS 解析记录导出为 UTF-8 CSV。"));
    httpsAutoScrollCheck_ = new QCheckBox(QStringLiteral("自动滚动"), httpsAnalyzePage_);
    httpsAutoScrollCheck_->setChecked(true);
    httpsAutoScrollCheck_->setToolTip(QStringLiteral("新记录到达时自动定位到最后一条可见记录。"));
    httpsParsedSummaryLabel_ = new QLabel(QStringLiteral("显示 0 / 0，请求 0，响应 0，错误 0"), httpsAnalyzePage_);
    httpsParsedSummaryLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    parsedFilterLayout->addWidget(new QLabel(QStringLiteral("筛选:"), httpsAnalyzePage_));
    parsedFilterLayout->addWidget(httpsParsedFilterEdit_, 1);
    parsedFilterLayout->addWidget(httpsParsedEventFilterCombo_);
    parsedFilterLayout->addWidget(httpsAutoScrollCheck_);
    parsedFilterLayout->addWidget(httpsExportParsedButton_);
    parsedFilterLayout->addWidget(httpsClearParsedButton_);
    parsedFilterLayout->addWidget(httpsParsedSummaryLabel_);
    httpsAnalyzeLayout_->addLayout(parsedFilterLayout);

    httpsParsedTable_ = new ks::ui::VisibleTableWidget(httpsAnalyzePage_);
    httpsParsedTable_->setColumnCount(kHttpsParsedColumnCount);
    httpsParsedTable_->setHorizontalHeaderLabels({
        QStringLiteral("时间"),
        QStringLiteral("会话"),
        QStringLiteral("客户端"),
        QStringLiteral("进程"),
        QStringLiteral("主机"),
        QStringLiteral("事件"),
        QStringLiteral("方法"),
        QStringLiteral("路径"),
        QStringLiteral("状态码"),
        QStringLiteral("内容类型"),
        QStringLiteral("TLS"),
        QStringLiteral("ALPN"),
        QStringLiteral("耗时"),
        QStringLiteral("上行"),
        QStringLiteral("下行"),
        QStringLiteral("详情")
        });
    httpsParsedTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    httpsParsedTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    httpsParsedTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    httpsParsedTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    httpsParsedTable_->verticalHeader()->setVisible(false);
    httpsParsedTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    httpsParsedTable_->horizontalHeader()->setSectionResizeMode(kHttpsParsedColumnDetail, QHeaderView::Stretch);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnTime, 120);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnSession, 70);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnClient, 140);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnProcess, 180);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnHost, 160);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnEvent, 90);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnMethod, 70);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnPath, 220);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnStatus, 70);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnContentType, 160);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnTls, 80);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnAlpn, 80);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnElapsed, 80);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnUpload, 100);
    httpsParsedTable_->setColumnWidth(kHttpsParsedColumnDownload, 100);
    httpsAnalyzeLayout_->addWidget(httpsParsedTable_, 1);

    httpsProxyLogOutput_ = new QPlainTextEdit(httpsAnalyzePage_);
    httpsProxyLogOutput_->setReadOnly(true);
    httpsProxyLogOutput_->setMaximumBlockCount(600);
    httpsProxyLogOutput_->setPlaceholderText(QStringLiteral("HTTPS 代理启动、证书安装和解析异常会显示在这里。"));
    httpsProxyLogOutput_->setFixedHeight(150);
    httpsAnalyzeLayout_->addWidget(httpsProxyLogOutput_, 0);

    sideTabWidget_->addTab(httpsAnalyzePage_, QIcon(":/Icon/process_details.svg"), QStringLiteral("HTTPS解析"));
    updateHttpsProxyStatusLabel(QStringLiteral("状态：HTTPS代理未启动"));
    updateHttpsParsedSummary();

    connect(httpsParsedFilterEdit_, &QLineEdit::textChanged, this, [this](const QString&) { applyHttpsParsedTableFilter(); });
    connect(httpsParsedEventFilterCombo_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](const int) { applyHttpsParsedTableFilter(); });
    connect(httpsClearParsedButton_, &QPushButton::clicked, this, [this]() { clearHttpsParsedEntries(); });
    connect(httpsExportParsedButton_, &QPushButton::clicked, this, [this]() { exportVisibleHttpsParsedEntries(); });

    connect(httpsParsedTable_, &QTableWidget::cellDoubleClicked, this, [this](const int row, const int /*column*/)
        {
            openHttpsParsedDetailByRow(row);
        });
    connect(httpsParsedTable_, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            if (httpsParsedTable_ == nullptr)
            {
                return;
            }

            const QTableWidgetItem* clickedItem = httpsParsedTable_->itemAt(localPosition);
            if (clickedItem == nullptr)
            {
                return;
            }

            const int kRowIndex = clickedItem->row();
            httpsParsedTable_->setCurrentCell(kRowIndex, clickedItem->column());

            QMenu contextMenu(this);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* detailAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看详情"));
            QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制当前行"));
            QAction* copyDetailAction = contextMenu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制详情文本"));
            QAction* selectedAction = contextMenu.exec(httpsParsedTable_->viewport()->mapToGlobal(localPosition));
            if (selectedAction == detailAction)
            {
                openHttpsParsedDetailByRow(kRowIndex);
            }
            else if (selectedAction == copyRowAction)
            {
                // Copy current row:
                // - Input: The HTTPS parsed row selected by the user via right-click;
                // - Processing: Read cell text column by column and concatenate in TSV format.
                // - Outputs: writes to system clipboard for easy pasting into tables or tickets.
                QStringList rowTextParts;
                rowTextParts.reserve(kHttpsParsedColumnCount);
                for (int columnIndex = 0; columnIndex < kHttpsParsedColumnCount; ++columnIndex)
                {
                    const QTableWidgetItem* cellItem = httpsParsedTable_->item(kRowIndex, columnIndex);
                    rowTextParts.append(cellItem != nullptr ? cellItem->text() : QString());
                }
                QApplication::clipboard()->setText(rowTextParts.join(QChar('\t')));
            }
            else if (selectedAction == copyDetailAction)
            {
                if (kRowIndex >= 0 && kRowIndex < static_cast<int>(httpsParsedEntryCache_.size()))
                {
                    const ks::network::HttpsProxyParsedEntry& parsedEntry = httpsParsedEntryCache_[static_cast<std::size_t>(kRowIndex)];
                    QApplication::clipboard()->setText(QString::fromUtf8(parsedEntry.rawBytes));
                }
            }
        });
}

void NetworkDock::startHttpsProxyService()
{
    if (httpsProxyService_ == nullptr)
    {
        appendHttpsProxyLogLine(QStringLiteral("HTTPS代理服务尚未初始化。"));
        return;
    }
    if (gHttpsProxyBusyOperationActive)
    {
        // A certificate is already being prepared or a stop task is running; ignore this click. The button will automatically restore after the callback completes.
        return;
    }

    const QHostAddress kListenAddress(httpsListenAddressEdit_ != nullptr ? httpsListenAddressEdit_->text().trimmed() : QStringLiteral("127.0.0.1"));
    if (kListenAddress.isNull())
    {
        appendHttpsProxyLogLine(QStringLiteral("监听地址无效。"));
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("监听地址无效。"));
        return;
    }

    const std::uint16_t kListenPort = static_cast<std::uint16_t>(httpsListenPortSpin_ != nullptr ? httpsListenPortSpin_->value() : 8889);

    // Root certificate generation/export requires launching powershell.exe; the first startup typically takes 1–5 seconds.
    // This entire block is delegated to the service's background thread; the UI thread only grays out the button and displays a 'preparing' status.
    gHttpsProxyBusyOperationActive = true;
    updateHttpsProxyStatusLabel(QStringLiteral("状态：正在准备根证书..."));

    const QPointer<NetworkDock> kGuardedSelf(this);
    httpsProxyService_->ensureRootCertificateAsync(
        false,
        [kGuardedSelf, kListenAddress, kListenPort](const bool certificatePrepared, const QString& certificateErrorText)
        {
            gHttpsProxyBusyOperationActive = false;
            if (kGuardedSelf == nullptr)
            {
                return;
            }

            NetworkDock* const kNetworkDock = kGuardedSelf.data();
            if (kNetworkDock->httpsProxyService_ == nullptr)
            {
                kNetworkDock->updateHttpsProxyStatusLabel(QStringLiteral("状态：HTTPS代理未启动"));
                return;
            }

            QString failureText = certificateErrorText;
            bool startSucceeded = false;
            if (certificatePrepared)
            {
                QString startErrorText;
                startSucceeded = kNetworkDock->httpsProxyService_->start(kListenAddress, kListenPort, &startErrorText);
                if (!startSucceeded)
                {
                    failureText = startErrorText;
                }
            }

            if (!startSucceeded)
            {
                kNetworkDock->appendHttpsProxyLogLine(QStringLiteral("启动失败：%1").arg(failureText));
                kNetworkDock->updateHttpsProxyStatusLabel(
                    buildHttpsProxyStatusText(kNetworkDock->httpsProxyRunning_, kListenAddress.toString(), kListenPort));
                QMessageBox::warning(
                    kNetworkDock,
                    QStringLiteral("HTTPS解析"),
                    QStringLiteral("启动 HTTPS 代理失败：\n%1").arg(failureText));
                return;
            }

            kNetworkDock->httpsProxyRunning_ = true;
            kNetworkDock->updateHttpsProxyStatusLabel(
                buildHttpsProxyStatusText(true, kListenAddress.toString(), kListenPort));
        });
}

void NetworkDock::stopHttpsProxyService()
{
    if (httpsProxyService_ == nullptr)
    {
        return;
    }
    if (gHttpsProxyBusyOperationActive)
    {
        return;
    }

    // Waiting for the session thread to exit may be time-consuming (the session thread might be blocked on certificate generation in
    // powershell.exe). This logic runs on a background service thread; the UI thread only grays out the button and displays the 'stopping' status.
    gHttpsProxyBusyOperationActive = true;
    httpsProxyRunning_ = false;
    updateHttpsProxyStatusLabel(QStringLiteral("状态：正在停止HTTPS代理..."));

    // The system proxy points to a port that is about to be decommissioned. Synchronously restore it first (pure registry
    // write, negligible overhead) to avoid new traffic being directed to the stopped proxy during session teardown.
    if (httpsSystemProxySnapshotCaptured_)
    {
        clearHttpsSystemProxy();
    }

    const QPointer<NetworkDock> kGuardedSelf(this);
    httpsProxyService_->stopAsync(
        [kGuardedSelf]()
        {
            gHttpsProxyBusyOperationActive = false;
            if (kGuardedSelf == nullptr)
            {
                return;
            }
            kGuardedSelf->updateHttpsProxyStatusLabel(QStringLiteral("状态：HTTPS代理已停止"));
        });
}

void NetworkDock::ensureHttpsRootCertificateTrusted()
{
    if (httpsProxyService_ == nullptr)
    {
        appendHttpsProxyLogLine(QStringLiteral("HTTPS代理服务尚未初始化。"));
        return;
    }
    if (gHttpsProxyBusyOperationActive)
    {
        return;
    }

    const QMessageBox::StandardButton kConfirmation = QMessageBox::question(
        this,
        QStringLiteral("信任 HTTPS 根证书"),
        QStringLiteral("此操作会将 Ksword 根证书加入“当前用户”的受信任根证书颁发机构。\n\n"
            "仅在你拥有或获授权分析的流量环境中继续。是否信任该证书？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmation != QMessageBox::Yes)
    {
        return;
    }

    // Generating and importing the root certificate also requires running powershell.exe; the entire sequence is offloaded to a background thread.
    gHttpsProxyBusyOperationActive = true;
    updateHttpsProxyStatusLabel(QStringLiteral("状态：正在准备根证书..."));

    const QPointer<NetworkDock> kGuardedSelf(this);
    httpsProxyService_->ensureRootCertificateAsync(
        true,
        [kGuardedSelf](const bool certificatePrepared, const QString& certificateErrorText)
        {
            gHttpsProxyBusyOperationActive = false;
            if (kGuardedSelf == nullptr)
            {
                return;
            }

            NetworkDock* const kNetworkDock = kGuardedSelf.data();
            if (!certificatePrepared)
            {
                const QString kListenAddressText = (kNetworkDock->httpsProxyService_ != nullptr)
                    ? kNetworkDock->httpsProxyService_->currentListenAddress().toString()
                    : QString();
                const std::uint16_t kListenPort = (kNetworkDock->httpsProxyService_ != nullptr)
                    ? kNetworkDock->httpsProxyService_->currentListenPort()
                    : static_cast<std::uint16_t>(0);
                kNetworkDock->appendHttpsProxyLogLine(QStringLiteral("信任证书失败：%1").arg(certificateErrorText));
                kNetworkDock->updateHttpsProxyStatusLabel(
                    buildHttpsProxyStatusText(kNetworkDock->httpsProxyRunning_, kListenAddressText, kListenPort));
                QMessageBox::warning(
                    kNetworkDock,
                    QStringLiteral("HTTPS解析"),
                    QStringLiteral("信任根证书失败：\n%1").arg(certificateErrorText));
                return;
            }

            kNetworkDock->appendHttpsProxyLogLine(QStringLiteral("HTTPS 根证书已生成并导入当前用户信任根。"));
            kNetworkDock->updateHttpsProxyStatusLabel(QStringLiteral("状态：根证书已信任，可启动代理"));
        });
}

void NetworkDock::applyHttpsSystemProxy()
{
    if (httpsProxyRecoveryRequired_)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("HTTPS解析"),
            QStringLiteral(
                "存在尚未成功恢复的 HTTPS 系统代理事务。请先重新启动 KSword 完成自动恢复，"
                "当前不会覆盖原始代理快照。"));
        return;
    }
    if (httpsProxyService_ == nullptr || !httpsProxyService_->isRunning())
    {
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("请先启动 HTTPS 代理，再应用系统代理。"));
        return;
    }
    if (!httpsProxyService_->isRootTrusted())
    {
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("请先信任 HTTPS 根证书，否则客户端会拒绝代理证书。"));
        return;
    }

    const QString kListenAddressText = (httpsListenAddressEdit_ != nullptr)
        ? httpsListenAddressEdit_->text().trimmed()
        : QStringLiteral("127.0.0.1");

    const QMessageBox::StandardButton kConfirmation = QMessageBox::question(
        this,
        QStringLiteral("应用 HTTPS 系统代理"),
        QStringLiteral("将把当前用户的 HTTPS 系统代理切换到 %1:%2。\n\n"
            "该代理会解密并显示通过此代理的 HTTPS 请求头和响应头，正文只转发不保存。停止代理或点击“还原系统代理”会恢复当前配置。是否继续？")
            .arg(kListenAddressText)
            .arg(httpsListenPortSpin_ != nullptr ? httpsListenPortSpin_->value() : 8889),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmation != QMessageBox::Yes)
    {
        return;
    }

    QString errorText;
    if (!captureHttpsSystemProxySnapshot(&errorText))
    {
        appendHttpsProxyLogLine(QStringLiteral("保存系统代理配置失败：%1").arg(errorText));
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("保存原系统代理配置失败：\n%1").arg(errorText));
        return;
    }

    const QString kOriginalProxyServerText = httpsPreviousProxyServer_.value_or(QString());
    const QString kProxyServerText = buildHttpsProxyServerText(
        kOriginalProxyServerText,
        QStringLiteral("%1:%2").arg(kListenAddressText).arg(httpsListenPortSpin_ != nullptr ? httpsListenPortSpin_->value() : 8889));
    if (!writeInternetSettingString(L"ProxyServer", kProxyServerText, &errorText)
        || !writeInternetSettingString(L"ProxyOverride", QStringLiteral("localhost;127.*;<local>"), &errorText)
        || !writeInternetSettingDword(L"ProxyEnable", 1, &errorText)
        || !writeInternetSettingDword(L"AutoDetect", 0, &errorText)
        || !writeInternetSettingString(L"AutoConfigURL", QString(), &errorText))
    {
        const QString kApplyErrorText = errorText;
        QString restoreErrorText;
        const bool kRestoreOk = restoreHttpsSystemProxySnapshot(&restoreErrorText);
        errorText = kRestoreOk
            ? kApplyErrorText
            : QStringLiteral("%1\n回滚原系统代理也失败：%2")
                .arg(kApplyErrorText, restoreErrorText);
        appendHttpsProxyLogLine(QStringLiteral("应用系统代理失败：%1").arg(errorText));
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("应用系统代理失败：\n%1").arg(errorText));
        return;
    }

    if (!refreshInternetSettings(&errorText))
    {
        const QString kApplyErrorText = errorText;
        QString restoreErrorText;
        const bool kRestoreOk = restoreHttpsSystemProxySnapshot(&restoreErrorText);
        errorText = kRestoreOk
            ? kApplyErrorText
            : QStringLiteral("%1\n回滚原系统代理也失败：%2")
                .arg(kApplyErrorText, restoreErrorText);
        appendHttpsProxyLogLine(QStringLiteral("应用系统代理失败：%1").arg(errorText));
        QMessageBox::warning(
            this,
            QStringLiteral("HTTPS解析"),
            QStringLiteral("应用系统代理失败：\n%1").arg(errorText));
        return;
    }
    appendHttpsProxyLogLine(QStringLiteral("系统代理已切换到 %1。").arg(kProxyServerText));
}

void NetworkDock::clearHttpsSystemProxy()
{
    if (!httpsSystemProxySnapshotCaptured_)
    {
        appendHttpsProxyLogLine(QStringLiteral("未发现由 HTTPS 解析页保存的系统代理快照，不修改当前系统代理。"));
        return;
    }

    QString errorText;
    if (!restoreHttpsSystemProxySnapshot(&errorText))
    {
        appendHttpsProxyLogLine(QStringLiteral("还原系统代理失败：%1").arg(errorText));
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("还原系统代理失败：\n%1").arg(errorText));
        return;
    }

    appendHttpsProxyLogLine(QStringLiteral("系统代理已恢复为 HTTPS 解析页应用前的配置。"));
}

bool NetworkDock::captureHttpsSystemProxySnapshot(QString* errorTextOut)
{
    if (httpsProxyRecoveryRequired_)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral(
                "存在尚未完成的 HTTPS 代理恢复事务，不能覆盖原始代理快照。");
        }
        return false;
    }
    if (httpsSystemProxySnapshotCaptured_)
    {
        return true;
    }

    std::optional<std::uint32_t> previousProxyEnable;
    std::optional<std::uint32_t> previousAutoDetect;
    std::optional<QString> previousProxyServer;
    std::optional<QString> previousProxyOverride;
    std::optional<QString> previousAutoConfigUrl;
    QString errorText;
    if (!readInternetSettingDword(L"ProxyEnable", &previousProxyEnable, &errorText)
        || !readInternetSettingDword(L"AutoDetect", &previousAutoDetect, &errorText)
        || !readInternetSettingString(L"ProxyServer", &previousProxyServer, &errorText)
        || !readInternetSettingString(L"ProxyOverride", &previousProxyOverride, &errorText)
        || !readInternetSettingString(L"AutoConfigURL", &previousAutoConfigUrl, &errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    if (!persistHttpsSystemProxyRecoveryTransaction(
            previousProxyEnable,
            previousAutoDetect,
            previousProxyServer,
            previousProxyOverride,
            previousAutoConfigUrl,
            &errorText))
    {
        httpsProxyRecoveryRequired_ = true;
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    httpsPreviousProxyEnable_ = previousProxyEnable;
    httpsPreviousAutoDetect_ = previousAutoDetect;
    httpsPreviousProxyServer_ = previousProxyServer;
    httpsPreviousProxyOverride_ = previousProxyOverride;
    httpsPreviousAutoConfigUrl_ = previousAutoConfigUrl;
    httpsSystemProxySnapshotCaptured_ = true;
    return true;
}

bool NetworkDock::restoreHttpsSystemProxySnapshot(QString* errorTextOut)
{
    if (!httpsSystemProxySnapshotCaptured_)
    {
        return true;
    }

    QString errorText;
    const auto kRestoreDword = [&errorText](const wchar_t* valueName, const std::optional<std::uint32_t>& value) -> bool
        {
            return value.has_value()
                ? writeInternetSettingDword(valueName, static_cast<DWORD>(*value), &errorText)
                : deleteInternetSetting(valueName, &errorText);
        };
    const auto kRestoreString = [&errorText](const wchar_t* valueName, const std::optional<QString>& value) -> bool
        {
            return value.has_value()
                ? writeInternetSettingString(valueName, *value, &errorText)
                : deleteInternetSetting(valueName, &errorText);
        };

    if (!kRestoreDword(L"ProxyEnable", httpsPreviousProxyEnable_)
        || !kRestoreDword(L"AutoDetect", httpsPreviousAutoDetect_)
        || !kRestoreString(L"ProxyServer", httpsPreviousProxyServer_)
        || !kRestoreString(L"ProxyOverride", httpsPreviousProxyOverride_)
        || !kRestoreString(L"AutoConfigURL", httpsPreviousAutoConfigUrl_))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    if (!refreshInternetSettings(&errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }
    if (!clearHttpsSystemProxyRecoveryTransaction(&errorText))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = errorText;
        }
        return false;
    }

    httpsPreviousProxyEnable_.reset();
    httpsPreviousAutoDetect_.reset();
    httpsPreviousProxyServer_.reset();
    httpsPreviousProxyOverride_.reset();
    httpsPreviousAutoConfigUrl_.reset();
    httpsSystemProxySnapshotCaptured_ = false;
    httpsProxyRecoveryRequired_ = false;
    return true;
}

void NetworkDock::onHttpsProxyParsedEntryArrived(const ks::network::HttpsProxyParsedEntry& parsedEntry)
{
    if (httpsParsedTable_ == nullptr)
    {
        return;
    }

    if (httpsParsedTable_->rowCount() >= kMaxHttpsParsedEntries)
    {
        httpsParsedTable_->removeRow(0);
        if (!httpsParsedEntryCache_.empty())
        {
            httpsParsedEntryCache_.erase(httpsParsedEntryCache_.begin());
        }
    }

    httpsParsedEntryCache_.push_back(parsedEntry);
    const int kRowIndex = httpsParsedTable_->rowCount();
    httpsParsedTable_->insertRow(kRowIndex);

    const QString kTimeText = QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(parsedEntry.timestampMs)).toString(QStringLiteral("HH:mm:ss.zzz"));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnTime, createPacketCell(kTimeText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnSession, createPacketCell(QString::number(parsedEntry.sessionId)));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnClient, createPacketCell(parsedEntry.clientEndpointText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnProcess, createPacketCell(parsedEntry.clientProcessText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnHost, createPacketCell(QStringLiteral("%1:%2").arg(parsedEntry.targetHostText).arg(parsedEntry.targetPort)));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnEvent, createPacketCell(parsedEntry.eventTypeText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnMethod, createPacketCell(parsedEntry.methodText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnPath, createPacketCell(parsedEntry.pathText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnStatus, createPacketCell(parsedEntry.statusCode > 0 ? QString::number(parsedEntry.statusCode) : QString()));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnContentType, createPacketCell(parsedEntry.contentTypeText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnTls, createPacketCell(parsedEntry.tlsVersionText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnAlpn, createPacketCell(parsedEntry.alpnText));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnElapsed, createPacketCell(parsedEntry.elapsedMs > 0 ? QStringLiteral("%1 ms").arg(parsedEntry.elapsedMs) : QString()));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnUpload, createPacketCell(parsedEntry.uploadBytes > 0 ? QString::number(parsedEntry.uploadBytes) : QString()));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnDownload, createPacketCell(parsedEntry.downloadBytes > 0 ? QString::number(parsedEntry.downloadBytes) : QString()));
    httpsParsedTable_->setItem(kRowIndex, kHttpsParsedColumnDetail, createPacketCell(parsedEntry.detailText));
    applyHttpsParsedTableFilter();
    if (httpsAutoScrollCheck_ != nullptr && httpsAutoScrollCheck_->isChecked() && !httpsParsedTable_->isRowHidden(kRowIndex))
    {
        httpsParsedTable_->scrollToBottom();
    }
}

void NetworkDock::applyHttpsParsedTableFilter()
{
    if (httpsParsedTable_ == nullptr)
    {
        return;
    }

    const QString kKeywordText = httpsParsedFilterEdit_ != nullptr
        ? httpsParsedFilterEdit_->text().trimmed()
        : QString();
    const QString kEventTypeText = httpsParsedEventFilterCombo_ != nullptr
        ? httpsParsedEventFilterCombo_->currentText()
        : QStringLiteral("全部事件");
    const bool kFilterByEventType = !kEventTypeText.isEmpty() && kEventTypeText != QStringLiteral("全部事件");

    for (int rowIndex = 0; rowIndex < httpsParsedTable_->rowCount(); ++rowIndex)
    {
        bool keywordMatched = kKeywordText.isEmpty();
        if (!keywordMatched)
        {
            for (int columnIndex = 0; columnIndex < kHttpsParsedColumnCount; ++columnIndex)
            {
                const QTableWidgetItem* cellItem = httpsParsedTable_->item(rowIndex, columnIndex);
                if (cellItem != nullptr && cellItem->text().contains(kKeywordText, Qt::CaseInsensitive))
                {
                    keywordMatched = true;
                    break;
                }
            }
        }

        const QTableWidgetItem* eventItem = httpsParsedTable_->item(rowIndex, kHttpsParsedColumnEvent);
        const bool kEventMatched = !kFilterByEventType
            || (eventItem != nullptr && eventItem->text().compare(kEventTypeText, Qt::CaseInsensitive) == 0);
        httpsParsedTable_->setRowHidden(rowIndex, !keywordMatched || !kEventMatched);
    }

    updateHttpsParsedSummary();
}

void NetworkDock::clearHttpsParsedEntries()
{
    if (httpsParsedTable_ == nullptr)
    {
        return;
    }

    httpsParsedEntryCache_.clear();
    httpsParsedTable_->setRowCount(0);
    updateHttpsParsedSummary();
    appendHttpsProxyLogLine(QStringLiteral("HTTPS 解析结果和详情缓存已清空。"));
}

void NetworkDock::exportVisibleHttpsParsedEntries()
{
    if (httpsParsedTable_ == nullptr)
    {
        return;
    }

    const QString kFilePath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 HTTPS 解析记录"),
        QStringLiteral("https-analysis.csv"),
        QStringLiteral("CSV 文件 (*.csv)"));
    if (kFilePath.isEmpty())
    {
        return;
    }

    QSaveFile outputFile(kFilePath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("无法创建导出文件：%1").arg(outputFile.errorString()));
        return;
    }

    const auto kEscapeCsvField = [](QString fieldText) -> QString
        {
            fieldText.replace('"', QStringLiteral("\"\""));
            return QStringLiteral("\"%1\"").arg(fieldText);
        };

    outputFile.write("\xEF\xBB\xBF");
    QTextStream outputStream(&outputFile);
    QStringList headerTextList;
    for (int columnIndex = 0; columnIndex < kHttpsParsedColumnCount; ++columnIndex)
    {
        const QTableWidgetItem* headerItem = httpsParsedTable_->horizontalHeaderItem(columnIndex);
        headerTextList.append(kEscapeCsvField(headerItem != nullptr ? headerItem->text() : QString()));
    }
    outputStream << headerTextList.join(',') << Qt::endl;

    int exportedRowCount = 0;
    for (int rowIndex = 0; rowIndex < httpsParsedTable_->rowCount(); ++rowIndex)
    {
        if (httpsParsedTable_->isRowHidden(rowIndex))
        {
            continue;
        }

        QStringList rowTextList;
        rowTextList.reserve(kHttpsParsedColumnCount);
        for (int columnIndex = 0; columnIndex < kHttpsParsedColumnCount; ++columnIndex)
        {
            const QTableWidgetItem* cellItem = httpsParsedTable_->item(rowIndex, columnIndex);
            rowTextList.append(kEscapeCsvField(cellItem != nullptr ? cellItem->text() : QString()));
        }
        outputStream << rowTextList.join(',') << Qt::endl;
        ++exportedRowCount;
    }

    if (!outputFile.commit())
    {
        QMessageBox::warning(this, QStringLiteral("HTTPS解析"), QStringLiteral("写入导出文件失败：%1").arg(outputFile.errorString()));
        return;
    }
    appendHttpsProxyLogLine(QStringLiteral("已导出 %1 条可见 HTTPS 解析记录：%2").arg(exportedRowCount).arg(kFilePath));
}

void NetworkDock::updateHttpsParsedSummary()
{
    if (httpsParsedSummaryLabel_ == nullptr || httpsParsedTable_ == nullptr)
    {
        return;
    }

    int visibleCount = 0;
    int requestCount = 0;
    int responseCount = 0;
    int errorCount = 0;
    for (int rowIndex = 0; rowIndex < httpsParsedTable_->rowCount(); ++rowIndex)
    {
        if (!httpsParsedTable_->isRowHidden(rowIndex))
        {
            ++visibleCount;
        }

        const QTableWidgetItem* eventItem = httpsParsedTable_->item(rowIndex, kHttpsParsedColumnEvent);
        if (eventItem == nullptr)
        {
            continue;
        }
        const QString kEventText = eventItem->text();
        if (kEventText == QStringLiteral("REQUEST"))
        {
            ++requestCount;
        }
        else if (kEventText == QStringLiteral("RESPONSE"))
        {
            ++responseCount;
        }
        else if (kEventText == QStringLiteral("ERROR"))
        {
            ++errorCount;
        }
    }

    httpsParsedSummaryLabel_->setText(QStringLiteral("显示 %1 / %2，请求 %3，响应 %4，错误 %5")
        .arg(visibleCount)
        .arg(httpsParsedTable_->rowCount())
        .arg(requestCount)
        .arg(responseCount)
        .arg(errorCount));
}

void NetworkDock::openHttpsParsedDetailByRow(const int row)
{
    if (row < 0 || row >= static_cast<int>(httpsParsedEntryCache_.size()))
    {
        return;
    }

    HttpsParsedDetailWindow* detailWindow =
        new HttpsParsedDetailWindow(httpsParsedEntryCache_[static_cast<std::size_t>(row)], nullptr);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();
}

void NetworkDock::appendHttpsProxyLogLine(const QString& logLine)
{
    if (httpsProxyLogOutput_ == nullptr)
    {
        return;
    }

    const QString kPrefixedLine = QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
        .arg(logLine);
    httpsProxyLogOutput_->appendPlainText(kPrefixedLine);
}

void NetworkDock::updateHttpsProxyStatusLabel(const QString& statusText)
{
    if (httpsProxyStatusLabel_ != nullptr)
    {
        httpsProxyStatusLabel_->setText(statusText);
    }

    // Uniformly disable the control bar during background certificate preparation or proxy stop: prevents re-entrancy and clearly indicates to the user that processing is in progress.
    const bool kBusyOperationActive = gHttpsProxyBusyOperationActive;
    if (httpsStartProxyButton_ != nullptr)
    {
        httpsStartProxyButton_->setEnabled(!httpsProxyRunning_ && !kBusyOperationActive);
    }
    if (httpsStopProxyButton_ != nullptr)
    {
        httpsStopProxyButton_->setEnabled(httpsProxyRunning_ && !kBusyOperationActive);
    }
    if (httpsTrustCertButton_ != nullptr)
    {
        httpsTrustCertButton_->setEnabled(!kBusyOperationActive);
    }
    if (httpsApplyProxyButton_ != nullptr)
    {
        httpsApplyProxyButton_->setEnabled(!kBusyOperationActive);
    }
    if (httpsClearProxyButton_ != nullptr)
    {
        httpsClearProxyButton_->setEnabled(!kBusyOperationActive);
    }
}
