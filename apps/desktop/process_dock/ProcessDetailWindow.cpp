#include "ProcessDetailWindow.InternalCommon.h"

// ============================================================
// ProcessDetailWindow.cpp
// Purpose:
// - Provides internal constants and utility functions shared across multiple implementation files of ProcessDetailWindow.
// - Keep other .cpp files focused on member functions, avoiding text concatenation via .inc files.
// ============================================================

namespace process_detail_window_internal
{
    // Thread detail table headers: correspond one-to-one with development plan fields.
    const QStringList kThreadInspectHeaders{
        "ThreadID",
        "状态",
        "优先级",
        "上下文切换",
        "起始地址",
        "TEB地址",
        "亲和性",
        "寄存器",
        "R0栈边界",
        "R0详情"
    };

    int toThreadColumnIndex(const ThreadRowColumn column)
    {
        return static_cast<int>(column);
    }

    // Module header text.
    const QStringList kModuleHeaders{
        "模块路径",
        "大小",
        "数字签名",
        "入口偏移量",
        "运行状态",
        "ThreadID"
    };

    int toModuleColumnIndex(const ModuleColumn column)
    {
        return static_cast<int>(column);
    }

    // Unified button styles use dynamic theme roles; switching between light and dark themes while the detail window is open will follow suit.
    QString buildBlueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    QString buildProcessDetailRootStyle()
    {
        return QStringLiteral(
            "QWidget#ProcessDetailWindowRoot{"
            "  background:%1;"
            "  color:%2;"
            "}"
            "QWidget#ProcessDetailWindowRoot QGroupBox{"
            "  border:1px solid %3;"
            "  border-radius:4px;"
            "  margin-top:8px;"
            "  padding-top:8px;"
            "  background:%4;"
            "  color:%2;"
            "}"
            "QWidget#ProcessDetailWindowRoot QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  left:8px;"
            "  padding:0 4px;"
            "  color:%2;"
            "}"
            "QWidget#ProcessDetailWindowRoot QLineEdit,"
            "QWidget#ProcessDetailWindowRoot QPlainTextEdit,"
            "QWidget#ProcessDetailWindowRoot QTextEdit{"
            "  background:transparent; /* %4 */"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:3px 6px;"
            "  selection-background-color:%5;"
            "  selection-color:%7;"
            "}"
            "QWidget#ProcessDetailWindowRoot QLineEdit[readOnly=\"true\"]{"
            "  background:transparent; /* %6 */"
            "}"
            "QWidget#ProcessDetailWindowRoot QTableWidget,"
            "QWidget#ProcessDetailWindowRoot QTreeWidget{"
            "  background:%4;"
            "  alternate-background-color:%6;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  gridline-color:%3;"
            "}"
            "QWidget#ProcessDetailWindowRoot QTableCornerButton::section{"
            "  background:transparent; /* %4 */"
            "  border:1px solid %3;"
            "}"
            "QWidget#ProcessDetailWindowRoot QHeaderView::section{"
            "  background:transparent; /* %4 */"
            "  color:%2;"
            "  border:1px solid %3;"
            "  padding:4px;"
            "  font-weight:600;"
            "}"
            "QWidget#ProcessDetailWindowRoot QTabWidget::pane{"
            "  border:1px solid %3;"
            "  background:%4;"
            "}"
            "QWidget#ProcessDetailTabNavigation{"
            "  background:%4;"
            "  border:1px solid %3;"
            "  border-radius:4px;"
            "}"
            "QWidget#ProcessDetailTabNavigation QToolButton{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:5px 8px;"
            "}"
            "QWidget#ProcessDetailTabNavigation QToolButton:checked{"
            "  background:%5;"
            "  color:%7;"
            "  border-color:%5;"
            "}"
            "QWidget#ProcessDetailTabNavigation QToolButton:hover:!checked{"
            "  background:%6;"
            "}"
            "QWidget#ProcessDetailWindowRoot QTabBar::tab{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-bottom:none;"
            "  padding:6px 10px;"
            "  margin-right:1px;"
            "}"
            "QWidget#ProcessDetailWindowRoot QTabBar::tab:selected{"
            "  background:%5;"
            "  color:%7;"
            "  border-color:%5;"
            "}"
            "QWidget#ProcessDetailWindowRoot QTabBar::tab:hover:!selected{"
            "  background:%6;"
            "}"
            "QWidget#ProcessDetailWindowRoot QMenu{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "}"
            "QWidget#ProcessDetailWindowRoot QMenu::item{"
            "  padding:5px 24px 5px 24px;"
            "  background:transparent;"
            "}"
            "QWidget#ProcessDetailWindowRoot QMenu::item:selected{"
            "  background:%5;"
            "  color:%7;"
            "}"
            "QWidget#ProcessDetailWindowRoot QMenu::item:disabled{"
            "  color:%6;"
            "  background:%4;"
            "}"
            "QWidget#ProcessDetailWindowRoot QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:2px 6px;"
            "}"
            "QWidget#ProcessDetailWindowRoot QScrollBar:vertical{"
            "  background:%4;"
            "  width:12px;"
            "  margin:0;"
            "}"
            "QWidget#ProcessDetailWindowRoot QScrollBar:horizontal{"
            "  background:%4;"
            "  height:12px;"
            "  margin:0;"
            "}"
            "QWidget#ProcessDetailWindowRoot QScrollBar::handle:vertical,"
            "QWidget#ProcessDetailWindowRoot QScrollBar::handle:horizontal{"
            "  background:%5;"
            "  min-height:20px;"
            "  min-width:20px;"
            "  border-radius:4px;"
            "}"
            "QWidget#ProcessDetailWindowRoot QScrollBar::handle:vertical:hover,"
            "QWidget#ProcessDetailWindowRoot QScrollBar::handle:horizontal:hover{"
            "  background:%1;"
            "}"
            "QWidget#ProcessDetailWindowRoot QScrollBar::add-line,"
            "QWidget#ProcessDetailWindowRoot QScrollBar::sub-line{"
            "  background:%4;"
            "  border:none;"
            "}"
            "QWidget#ProcessDetailWindowRoot QScrollBar::add-page,"
            "QWidget#ProcessDetailWindowRoot QScrollBar::sub-page{"
            "  background:%4;"
            "}")
            .arg(ksword_theme::mainBackgroundHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::primaryBlueSubtleHex())
            .arg(ksword_theme::onAccentDynamicHex());
    }

    QString buildProcessDetailMenuStyle()
    {
        // Menu styles must explicitly declare background, text, selection, and disabled states to avoid black text on a black background caused by transparent parent controls.
        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  padding:4px;"
            "}"
            "QMenu::item{"
            "  padding:5px 24px 5px 24px;"
            "  background:transparent;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:%6;"
            "}"
            "QMenu::item:disabled{"
            "  color:%5;"
            "  background:%1;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:3px 6px;"
            "}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::textSecondaryHex())
            .arg(ksword_theme::onAccentDynamicHex());
    }

    QIcon buildProcessDetailR0ActionIcon(const QString& iconPath)
    {
        // R0 button uses the corresponding business icon; the button text explicitly indicates the R0 source.
        constexpr QSize kDetailR0IconSize(18, 18);
        QPixmap iconPixmap(iconPath);
        if (!iconPixmap.isNull())
        {
            iconPixmap = iconPixmap.scaled(
                kDetailR0IconSize,
                Qt::KeepAspectRatio,
                Qt::SmoothTransformation);
        }
        if (iconPixmap.isNull())
        {
            iconPixmap = QPixmap(kDetailR0IconSize);
            iconPixmap.fill(Qt::transparent);
        }

        return QIcon(iconPixmap);
    }

    QString buildStateLabelStyle(const QColor& textColor, const int fontWeight)
    {
        return QStringLiteral("color:%1; font-weight:%2;")
            .arg(textColor.name(QColor::HexRgb))
            .arg(fontWeight);
    }

    QColor statusIdleColor()
    {
        return ksword_theme::successColor();
    }

    QColor statusWarningColor()
    {
        return ksword_theme::warningColor();
    }

    QColor statusErrorColor()
    {
        return ksword_theme::errorColor();
    }

    QColor statusSecondaryColor()
    {
        return ksword_theme::textSecondaryColor();
    }

    QColor signatureTrustedColor()
    {
        return ksword_theme::successColor();
    }

    QColor signatureUntrustedColor()
    {
        return ksword_theme::errorColor();
    }

    QString formatDoubleText(const double value, const int precision)
    {
        return QString::number(value, 'f', precision);
    }

    QString uint64ToHex(const std::uint64_t value)
    {
        return QString("0x%1").arg(static_cast<qulonglong>(value), 0, 16).toUpper();
    }

    QString convertSidToText(PSID sid)
    {
        if (sid == nullptr)
        {
            return QStringLiteral("<null sid>");
        }

        WCHAR accountName[256] = {};
        WCHAR domainName[256] = {};
        DWORD accountNameLength = static_cast<DWORD>(std::size(accountName));
        DWORD domainNameLength = static_cast<DWORD>(std::size(domainName));
        SID_NAME_USE sidType = SidTypeUnknown;
        const BOOL kAccountOk = LookupAccountSidW(
            nullptr,
            sid,
            accountName,
            &accountNameLength,
            domainName,
            &domainNameLength,
            &sidType);

        LPWSTR sidTextRaw = nullptr;
        const BOOL kSidTextOk = ConvertSidToStringSidW(sid, &sidTextRaw);
        QString sidText = kSidTextOk && sidTextRaw != nullptr
            ? QString::fromWCharArray(sidTextRaw)
            : QStringLiteral("N/A");
        if (sidTextRaw != nullptr)
        {
            LocalFree(sidTextRaw);
            sidTextRaw = nullptr;
        }

        if (kAccountOk == FALSE)
        {
            return QString("SID=%1").arg(sidText);
        }

        return QString("%1\\%2 (SID=%3)")
            .arg(QString::fromWCharArray(domainName))
            .arg(QString::fromWCharArray(accountName))
            .arg(sidText);
    }

    QString readRemoteUnicodeString(HANDLE processHandle, const UNICODE_STRING& remoteUnicode)
    {
        if (processHandle == nullptr || remoteUnicode.Length == 0 || remoteUnicode.Buffer == nullptr)
        {
            return QString();
        }

        std::vector<wchar_t> buffer(
            static_cast<std::size_t>(remoteUnicode.Length / sizeof(wchar_t)) + 1,
            L'\0');
        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ReadProcessMemory(
            processHandle,
            remoteUnicode.Buffer,
            buffer.data(),
            remoteUnicode.Length,
            &bytesRead);
        if (kReadOk == FALSE || bytesRead == 0)
        {
            return QString();
        }

        return QString::fromWCharArray(buffer.data());
    }

    int calculateStandaloneWindowInitialWidth(
        QWidget* candidateParent,
        QWidget* fallbackWindow,
        const double ratio,
        const int fallbackWidth)
    {
        // Inputs:
        // - candidateParent: The preferred client area control, typically the Dock or main window that opened the independent window.
        // - fallbackWindow: the current standalone window used to locate the screen when no parent control exists.
        // - ratio: initial width ratio; the caller side of this requirement always passes 0.75.
        // - fallbackWidth: default width when all sources are unavailable.
        // Processing:
        // - First locate the target screen, then clamp all candidate widths to within the available width of that screen;
        // - Prioritizes parent contentsRect to exclude window decorations/borders from calculations;
        // - Next, use the client area of the current active window.
        // - Fall back to the screen's availableGeometry.
        // Returns: Initially calculated width based on proportion; falls back to a default width only when no judgment is possible.
        int clientWidth = 0;
        if (candidateParent != nullptr && candidateParent->contentsRect().width() > 0)
        {
            clientWidth = candidateParent->contentsRect().width();
        }

        if (clientWidth <= 0)
        {
            QWidget* activeWindow = QApplication::activeWindow();
            if (activeWindow != nullptr &&
                activeWindow != fallbackWindow &&
                activeWindow->contentsRect().width() > 0)
            {
                clientWidth = activeWindow->contentsRect().width();
            }
        }

        QScreen* targetScreen = nullptr;
        if (candidateParent != nullptr && candidateParent->windowHandle() != nullptr)
        {
            targetScreen = candidateParent->windowHandle()->screen();
        }
        if (targetScreen == nullptr && fallbackWindow != nullptr && fallbackWindow->windowHandle() != nullptr)
        {
            targetScreen = fallbackWindow->windowHandle()->screen();
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QApplication::primaryScreen();
        }
        if (clientWidth <= 0 && targetScreen != nullptr)
        {
            clientWidth = targetScreen->availableGeometry().width();
        }

        const int kBoundedFallbackWidth = std::max(1, fallbackWidth);
        if (clientWidth <= 0 || ratio <= 0.0)
        {
            return kBoundedFallbackWidth;
        }

        const int kScreenWidth = (targetScreen != nullptr)
            ? targetScreen->availableGeometry().width()
            : 0;
        if (kScreenWidth > 0)
        {
            // Initial width is not calculated based on the client area exceeding the target screen.
            clientWidth = std::min(clientWidth, kScreenWidth);
        }

        return std::max(1, static_cast<int>(std::floor(static_cast<double>(clientWidth) * ratio)));
    }
}
