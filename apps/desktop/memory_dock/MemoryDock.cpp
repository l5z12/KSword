#include "MemoryDock.Internal.h"

namespace ksword::memory_dock_internal
{
    // ========================================================
    // Theme style function: Unify the style for buttons, input fields, and dropdowns.
    // ========================================================

    // Button styles unified to use the global theme implementation:
    // Manually constructing QSS for the page will conflict with the baseline in
    // UI/GlobalUiBaseStyle.cpp, which already covers all states: hover, pressed, checked, and disabled.
    QString buildBlueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    QString buildBlueComboStyle()
    {
        return ksword_theme::themedComboBoxStyle();
    }

    // Input fields no longer apply page-specific styles: the global baseline already unifies borders, corner radius, and focus
    // states for QLineEdit, QTextEdit, and QPlainTextEdit; returning an empty string effectively 'reverts to the baseline'.
    QString buildBlueInputStyle()
    {
        return QString();
    }

    // Hex viewer constants: 16 bytes per row, 32 rows total, 512 bytes per page.
    const int kHexBytesPerRow = 16;
    const int kHexRowCount = 32;
    const std::uint64_t kHexPageBytes = static_cast<std::uint64_t>(kHexBytesPerRow * kHexRowCount);

    // Module table header text: directly aligns with the process details module page experience.
    const QStringList kModuleTreeHeaders{
        "模块路径",
        "大小",
        "数字签名",
        "入口偏移量",
        "运行状态",
        "ThreadID"
    };

    // Convert enum column to integer index to avoid scattered hardcoded numbers in code.
    int toModuleTreeColumnIndex(const ModuleTreeColumn column)
    {
        return static_cast<int>(column);
    }

    // Explicit PID-to-DWORD wrapper to avoid implicit conversion warnings.
    DWORD toDwordPid(const std::uint32_t pid)
    {
        return static_cast<DWORD>(pid);
    }

    // Check if the memory protection attribute is readable.
    bool isReadableProtect(const std::uint32_t protectValue)
    {
        if ((protectValue & PAGE_GUARD) != 0 || (protectValue & PAGE_NOACCESS) != 0)
        {
            return false;
        }
        const std::uint32_t kBaseProtect = protectValue & 0xFF;
        switch (kBaseProtect)
        {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    // Parse two-digit hexadecimal byte text, e.g., "7F", "ff".
    bool parseHexByte(const QString& text, std::uint8_t& valueOut)
    {
        bool parseOk = false;
        const int kValue = text.trimmed().toInt(&parseOk, 16);
        if (!parseOk || kValue < 0 || kValue > 0xFF)
        {
            return false;
        }
        valueOut = static_cast<std::uint8_t>(kValue);
        return true;
    }

    // Load icons uniformly by path with caching to reduce lag from repeated system icon reads.
    QIcon resolveIconByPath(const QString& absolutePath, QHash<QString, QIcon>& cache)
    {
        if (absolutePath.trimmed().isEmpty())
        {
            return QIcon(":/Icon/process_main.svg");
        }

        auto foundIt = cache.find(absolutePath);
        if (foundIt != cache.end())
        {
            return foundIt.value();
        }

        QIcon resolvedIcon(absolutePath);
        if (resolvedIcon.isNull())
        {
            QFileIconProvider iconProvider;
            resolvedIcon = iconProvider.icon(QFileInfo(absolutePath));
        }
        if (resolvedIcon.isNull())
        {
            resolvedIcon = QIcon(":/Icon/process_main.svg");
        }

        cache.insert(absolutePath, resolvedIcon);
        return resolvedIcon;
    }
}
