#include "WindowDock.h"
#include "WindowEventHookTab.h"
#include "WindowGlobalHotkeyTab.h"
#include "WindowGuiHandleTab.h"
#include "WindowTimerTab.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../other_dock/OtherDock.h"
#include "../internationalization/LanguageManager.h"
#include "../../../shared/platform/process/Process.h"
#include "../../../shared/platform/profile/ProfileJsonLoader.h"
#include "../../../shared/platform/log/Log.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QAction>
#include <QBrush>
#include <QClipboard>
#include <QColor>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileIconProvider>
#include <QGuiApplication>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QList>
#include <QMenu>
#include <QMetaObject>
#include <QMimeData>
#include <QModelIndex>
#include <QMutex>
#include <QMutexLocker>
#include <QPalette>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QSizePolicy>
#include <QRect>
#include <QScreen>
#include <QShowEvent>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QThread>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iterator>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#pragma comment(lib, "Version.lib")

namespace
{
    // kColumnPresetSelectedProperty: Identifies the current selection state of the A/B column preset buttons.
    // This internal property name is not user-visible text; defining it centrally avoids accidental inclusion in i18n language packs.
    constexpr char kColumnPresetSelectedProperty[] = {
        'k', 's', 'w', 'o', 'r', 'd',
        'C', 'o', 'l', 'u', 'm', 'n',
        'P', 'r', 'e', 's', 'e', 't',
        'S', 'e', 'l', 'e', 'c', 't', 'e', 'd',
        '\0'
    };

    enum HotkeyTableColumn : int
    {
        kHotkeyColumnName = 0,
        kHotkeyColumnProcessThread,
        kHotkeyColumnDisplay,
        kHotkeyColumnPath,
        kHotkeyColumnDescription,
        kHotkeyColumnObject,
        kHotkeyColumnId,
        kHotkeyColumnVirtualKey,
        kHotkeyColumnModifiers,
        kHotkeyColumnProcessId,
        kHotkeyColumnThreadId,
        kHotkeyColumnSession,
        kHotkeyColumnHwnd,
        kHotkeyColumnNext,
        kHotkeyColumnThreadInfo,
        kHotkeyColumnDepth,
        kHotkeyColumnSource,
        kHotkeyColumnStatus,
        kHotkeyColumnLastStatus,
        kHotkeyColumnDiagnostic,
        kHotkeyColumnCount
    };

    struct HotkeyProcessDisplayInfo
    {
        QString processName;
        QString imagePath;
        QString description;
    };

    // boolText:
    // - Convert boolean values to 'Yes/No';
    // - For direct display on read-only audit pages.
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    // formatHwndText:
    // - Convert HWND to readable hexadecimal text.
    // - Empty handles are uniformly displayed as 0x0.
    QString formatHwndText(const HWND windowHandle)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(windowHandle)), 0, 16)
            .toUpper();
    }

    // formatUInt64Hex:
    // - Convert diagnostic addresses, capability masks, and flags returned from R0 to hexadecimal.
    // - Input value: unsigned 64-bit numeric value;
    // - Returns: For display purposes only; not to be used as a credential for subsequent operations.
    QString formatUInt64Hex(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    // parseUInt64Text:
    // - Input: text; hexadecimal or decimal text in the table;
    // - Processing: Support the 0x prefix and return fallback for text that cannot be parsed, such as N/A or <empty>;
    // - Returns the parsed 64-bit value for on-demand detail queries.
    std::uint64_t parseUInt64Text(const QString& text, const std::uint64_t fallback)
    {
        QString trimmedText = text.trimmed();
        if (trimmedText.isEmpty() ||
            trimmedText == QStringLiteral("N/A") ||
            trimmedText.startsWith(QChar('<')))
        {
            return fallback;
        }

        int base = 10;
        if (trimmedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            trimmedText = trimmedText.mid(2);
            base = 16;
        }

        bool ok = false;
        const qulonglong kParsedValue = trimmedText.toULongLong(&ok, base);
        return ok ? static_cast<std::uint64_t>(kParsedValue) : fallback;
    }

    // parseUInt32Text:
    // - Input text: PID/TID text from the table;
    // - Processing: Reuse parseUInt64Text and truncate to 32 bits.
    // - Returns: fallback on parse failure.
    std::uint32_t parseUInt32Text(const QString& text, const std::uint32_t fallback)
    {
        const std::uint64_t kParsedValue = parseUInt64Text(text, fallback);
        return kParsedValue <= 0xFFFFFFFFULL ? static_cast<std::uint32_t>(kParsedValue) : fallback;
    }

    // formatNtStatusText:
    // - Display NTSTATUS/Win32 statuses returned by the driver uniformly in hexadecimal;
    // - Input statusValue: 32-bit status value returned from R0/R3
    // - Returns: Short text with common meanings to avoid displaying hard-to-read negative decimal numbers in tables.
    QString formatNtStatusText(const long statusValue)
    {
        const std::uint32_t kUnsignedStatus =
            static_cast<std::uint32_t>(statusValue);
        QString nameText;
        switch (kUnsignedStatus)
        {
        case 0x00000000UL:
            nameText = QStringLiteral("STATUS_SUCCESS");
            break;
        case 0xC00000BBUL:
            nameText = QStringLiteral("STATUS_NOT_SUPPORTED");
            break;
        case 0xC0000010UL:
            nameText = QStringLiteral("STATUS_INVALID_DEVICE_REQUEST");
            break;
        case 0xC000000DUL:
            nameText = QStringLiteral("STATUS_INVALID_PARAMETER");
            break;
        case 0xC0000023UL:
            nameText = QStringLiteral("STATUS_BUFFER_TOO_SMALL");
            break;
        case 0xC0000001UL:
            nameText = QStringLiteral("STATUS_UNSUCCESSFUL");
            break;
        default:
            nameText = QStringLiteral("NTSTATUS");
            break;
        }

        return QStringLiteral("0x%1 (%2)")
            .arg(static_cast<qulonglong>(kUnsignedStatus), 8, 16, QChar('0'))
            .arg(nameText)
            .toUpper();
    }

    // hotkeyModifierText:
    // - Convert RegisterHotKey-style modifiers bits to Alt/Ctrl/Shift/Win.
    // - Input: modifiers - Modifier key bitmap in R0 hotkey row;
    // - Returns: human-readable modifier key combination, preserving original hex for copy-audit.
    QString hotkeyModifierText(const std::uint32_t modifiers)
    {
        QStringList parts;
        if ((modifiers & MOD_ALT) != 0U)
        {
            parts.push_back(QStringLiteral("Alt"));
        }
        if ((modifiers & MOD_CONTROL) != 0U)
        {
            parts.push_back(QStringLiteral("Ctrl"));
        }
        if ((modifiers & MOD_SHIFT) != 0U)
        {
            parts.push_back(QStringLiteral("Shift"));
        }
        if ((modifiers & MOD_WIN) != 0U)
        {
            parts.push_back(QStringLiteral("Win"));
        }
        constexpr std::uint32_t kModNoRepeat = 0x4000U;
        if ((modifiers & kModNoRepeat) != 0U)
        {
            parts.push_back(QStringLiteral("NoRepeat"));
        }
        if (parts.isEmpty())
        {
            parts.push_back(QStringLiteral("<无修饰键>"));
        }
        return QStringLiteral("%1 (%2)")
            .arg(parts.join('+'))
            .arg(formatUInt64Hex(modifiers));
    }

    // virtualKeyName:
    // - Parse the RegisterHotKey VK numeric value into a human-readable key name according to fixed values in WinUser.h;
    // - Letters, digits, and F1-F24 are handled by range; other common VKs use explicit mapping.
    // - Unknown values retain VK_0xNN to avoid mislabeling unrecognized keys as other keys.
    QString virtualKeyName(const std::uint32_t virtualKey)
    {
        if (virtualKey >= '0' && virtualKey <= '9')
        {
            return QString(QChar(static_cast<ushort>(virtualKey)));
        }
        if (virtualKey >= 'A' && virtualKey <= 'Z')
        {
            return QString(QChar(static_cast<ushort>(virtualKey)));
        }
        if (virtualKey >= VK_NUMPAD0 && virtualKey <= VK_NUMPAD9)
        {
            return QStringLiteral("Num%1").arg(virtualKey - VK_NUMPAD0);
        }
        if (virtualKey >= VK_F1 && virtualKey <= VK_F24)
        {
            return QStringLiteral("F%1").arg(virtualKey - VK_F1 + 1U);
        }

        switch (virtualKey)
        {
        case VK_LBUTTON: return QStringLiteral("MouseLeft");
        case VK_RBUTTON: return QStringLiteral("MouseRight");
        case VK_CANCEL: return QStringLiteral("Break");
        case VK_MBUTTON: return QStringLiteral("MouseMiddle");
        case VK_XBUTTON1: return QStringLiteral("MouseX1");
        case VK_XBUTTON2: return QStringLiteral("MouseX2");
        case VK_BACK: return QStringLiteral("Backspace");
        case VK_TAB: return QStringLiteral("Tab");
        case VK_CLEAR: return QStringLiteral("Clear");
        case VK_RETURN: return QStringLiteral("Enter");
        case VK_SHIFT: return QStringLiteral("Shift");
        case VK_CONTROL: return QStringLiteral("Ctrl");
        case VK_MENU: return QStringLiteral("Alt");
        case VK_PAUSE: return QStringLiteral("Pause");
        case VK_CAPITAL: return QStringLiteral("CapsLock");
        case VK_KANA: return QStringLiteral("Kana/Hangul");
        case VK_IME_ON: return QStringLiteral("ImeOn");
        case VK_JUNJA: return QStringLiteral("Junja");
        case VK_FINAL: return QStringLiteral("Final");
        case VK_HANJA: return QStringLiteral("Hanja/Kanji");
        case VK_IME_OFF: return QStringLiteral("ImeOff");
        case VK_ESCAPE: return QStringLiteral("Esc");
        case VK_CONVERT: return QStringLiteral("Convert");
        case VK_NONCONVERT: return QStringLiteral("NonConvert");
        case VK_ACCEPT: return QStringLiteral("Accept");
        case VK_MODECHANGE: return QStringLiteral("ModeChange");
        case VK_SPACE: return QStringLiteral("Space");
        case VK_PRIOR: return QStringLiteral("PageUp");
        case VK_NEXT: return QStringLiteral("PageDown");
        case VK_END: return QStringLiteral("End");
        case VK_HOME: return QStringLiteral("Home");
        case VK_LEFT: return QStringLiteral("Left");
        case VK_UP: return QStringLiteral("Up");
        case VK_RIGHT: return QStringLiteral("Right");
        case VK_DOWN: return QStringLiteral("Down");
        case VK_SELECT: return QStringLiteral("Select");
        case VK_PRINT: return QStringLiteral("Print");
        case VK_EXECUTE: return QStringLiteral("Execute");
        case VK_SNAPSHOT: return QStringLiteral("Snapshot");
        case VK_INSERT: return QStringLiteral("Insert");
        case VK_DELETE: return QStringLiteral("Delete");
        case VK_HELP: return QStringLiteral("Help");
        case VK_LWIN: return QStringLiteral("LeftWin");
        case VK_RWIN: return QStringLiteral("RightWin");
        case VK_APPS: return QStringLiteral("Apps");
        case VK_SLEEP: return QStringLiteral("Sleep");
        case VK_MULTIPLY: return QStringLiteral("NumMultiply");
        case VK_ADD: return QStringLiteral("NumAdd");
        case VK_SEPARATOR: return QStringLiteral("NumSeparator");
        case VK_SUBTRACT: return QStringLiteral("NumSubtract");
        case VK_DECIMAL: return QStringLiteral("NumDecimal");
        case VK_DIVIDE: return QStringLiteral("NumDivide");
        case VK_NUMLOCK: return QStringLiteral("NumLock");
        case VK_SCROLL: return QStringLiteral("ScrollLock");
        case VK_LSHIFT: return QStringLiteral("LeftShift");
        case VK_RSHIFT: return QStringLiteral("RightShift");
        case VK_LCONTROL: return QStringLiteral("LeftCtrl");
        case VK_RCONTROL: return QStringLiteral("RightCtrl");
        case VK_LMENU: return QStringLiteral("LeftAlt");
        case VK_RMENU: return QStringLiteral("RightAlt");
        case VK_BROWSER_BACK: return QStringLiteral("BrowserBack");
        case VK_BROWSER_FORWARD: return QStringLiteral("BrowserForward");
        case VK_BROWSER_REFRESH: return QStringLiteral("BrowserRefresh");
        case VK_BROWSER_STOP: return QStringLiteral("BrowserStop");
        case VK_BROWSER_SEARCH: return QStringLiteral("BrowserSearch");
        case VK_BROWSER_FAVORITES: return QStringLiteral("BrowserFavorites");
        case VK_BROWSER_HOME: return QStringLiteral("BrowserHome");
        case VK_VOLUME_MUTE: return QStringLiteral("VolumeMute");
        case VK_VOLUME_DOWN: return QStringLiteral("VolumeDown");
        case VK_VOLUME_UP: return QStringLiteral("VolumeUp");
        case VK_MEDIA_NEXT_TRACK: return QStringLiteral("MediaNext");
        case VK_MEDIA_PREV_TRACK: return QStringLiteral("MediaPrevious");
        case VK_MEDIA_STOP: return QStringLiteral("MediaStop");
        case VK_MEDIA_PLAY_PAUSE: return QStringLiteral("MediaPlayPause");
        case VK_LAUNCH_MAIL: return QStringLiteral("LaunchMail");
        case VK_LAUNCH_MEDIA_SELECT: return QStringLiteral("LaunchMedia");
        case VK_LAUNCH_APP1: return QStringLiteral("LaunchApp1");
        case VK_LAUNCH_APP2: return QStringLiteral("LaunchApp2");
        case VK_OEM_1: return QStringLiteral(";");
        case VK_OEM_PLUS: return QStringLiteral("+");
        case VK_OEM_COMMA: return QStringLiteral(",");
        case VK_OEM_MINUS: return QStringLiteral("-");
        case VK_OEM_PERIOD: return QStringLiteral(".");
        case VK_OEM_2: return QStringLiteral("/");
        case VK_OEM_3: return QStringLiteral("`");
        case VK_OEM_4: return QStringLiteral("[");
        case VK_OEM_5: return QStringLiteral("\\");
        case VK_OEM_6: return QStringLiteral("]");
        case VK_OEM_7: return QStringLiteral("'");
        case VK_OEM_8: return QStringLiteral("OEM8");
        case VK_OEM_102: return QStringLiteral("OEM102");
        case VK_PROCESSKEY: return QStringLiteral("ProcessKey");
        case VK_PACKET: return QStringLiteral("Packet");
        case VK_ATTN: return QStringLiteral("Attn");
        case VK_CRSEL: return QStringLiteral("CrSel");
        case VK_EXSEL: return QStringLiteral("ExSel");
        case VK_EREOF: return QStringLiteral("EraseEof");
        case VK_PLAY: return QStringLiteral("Play");
        case VK_ZOOM: return QStringLiteral("Zoom");
        case VK_NONAME: return QStringLiteral("NoName");
        case VK_PA1: return QStringLiteral("Pa1");
        case VK_OEM_CLEAR: return QStringLiteral("OemClear");
        default:
            return QStringLiteral("VK_0x%1")
                .arg(virtualKey, 2, 16, QChar('0'))
                .toUpper();
        }
    }

    // hotkeyDisplayText purpose: Combine modifier keys with hardcoded VK names to generate human-readable hotkeys in OpenARK style.
    QString hotkeyDisplayText(const std::uint32_t modifiers, const std::uint32_t virtualKey)
    {
        QStringList parts;
        if ((modifiers & MOD_WIN) != 0U) parts.push_back(QStringLiteral("Win"));
        if ((modifiers & MOD_CONTROL) != 0U) parts.push_back(QStringLiteral("Ctrl"));
        if ((modifiers & MOD_ALT) != 0U) parts.push_back(QStringLiteral("Alt"));
        if ((modifiers & MOD_SHIFT) != 0U) parts.push_back(QStringLiteral("Shift"));
        parts.push_back(virtualKeyName(virtualKey));
        return parts.join(QChar('+'));
    }

    QString rawVirtualKeyText(const std::uint32_t virtualKey)
    {
        const QString kHexText = QStringLiteral("0x%1")
            .arg(virtualKey, 2, 16, QChar('0'))
            .toUpper();
        return QStringLiteral("%1 (%2)").arg(kHexText, virtualKeyName(virtualKey));
    }

    // queryFileDescription: Reads FileDescription from the process image version resources; returns an empty string on failure.
    QString queryFileDescription(const QString& imagePath)
    {
        if (imagePath.trimmed().isEmpty())
        {
            return QString();
        }

        DWORD ignoredHandle = 0;
        const DWORD kVersionBytes = ::GetFileVersionInfoSizeW(
            reinterpret_cast<LPCWSTR>(imagePath.utf16()),
            &ignoredHandle);
        if (kVersionBytes == 0U)
        {
            return QString();
        }

        std::vector<std::uint8_t> versionBuffer(kVersionBytes, 0U);
        if (::GetFileVersionInfoW(
            reinterpret_cast<LPCWSTR>(imagePath.utf16()),
            0,
            kVersionBytes,
            versionBuffer.data()) == FALSE)
        {
            return QString();
        }

        struct LanguageCodePage
        {
            WORD language;
            WORD codePage;
        };
        LanguageCodePage* translations = nullptr;
        UINT translationBytes = 0;
        if (::VerQueryValueW(
            versionBuffer.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<LPVOID*>(&translations),
            &translationBytes) != FALSE &&
            translations != nullptr)
        {
            const UINT kTranslationCount = translationBytes / sizeof(LanguageCodePage);
            for (UINT index = 0; index < kTranslationCount; ++index)
            {
                const QString kQueryPath = QStringLiteral("\\StringFileInfo\\%1%2\\FileDescription")
                    .arg(translations[index].language, 4, 16, QChar('0'))
                    .arg(translations[index].codePage, 4, 16, QChar('0'));
                wchar_t* description = nullptr;
                UINT descriptionChars = 0;
                if (::VerQueryValueW(
                    versionBuffer.data(),
                    reinterpret_cast<LPCWSTR>(kQueryPath.utf16()),
                    reinterpret_cast<LPVOID*>(&description),
                    &descriptionChars) != FALSE &&
                    description != nullptr &&
                    descriptionChars > 1U)
                {
                    return QString::fromWCharArray(description).trimmed();
                }
            }
        }

        constexpr const wchar_t* kFallbackQueries[] = {
            L"\\StringFileInfo\\040904B0\\FileDescription",
            L"\\StringFileInfo\\000004B0\\FileDescription"
        };
        for (const wchar_t* queryPath : kFallbackQueries)
        {
            wchar_t* description = nullptr;
            UINT descriptionChars = 0;
            if (::VerQueryValueW(
                versionBuffer.data(),
                queryPath,
                reinterpret_cast<LPVOID*>(&description),
                &descriptionChars) != FALSE &&
                description != nullptr &&
                descriptionChars > 1U)
            {
                return QString::fromWCharArray(description).trimmed();
            }
        }
        return QString();
    }

    HotkeyProcessDisplayInfo queryHotkeyProcessDisplayInfo(const std::uint32_t processId)
    {
        HotkeyProcessDisplayInfo displayInfo;
        if (processId == 0U)
        {
            return displayInfo;
        }

        displayInfo.imagePath = QString::fromStdString(ks::process::queryProcessPathByPid(processId));
        if (!displayInfo.imagePath.isEmpty())
        {
            displayInfo.processName = QFileInfo(displayInfo.imagePath).fileName();
            displayInfo.description = queryFileDescription(displayInfo.imagePath);
        }
        if (displayInfo.processName.isEmpty())
        {
            displayInfo.processName = QString::fromStdString(ks::process::getProcessNameByPid(processId));
        }
        return displayInfo;
    }

    QString processThreadDisplayText(const std::uint32_t processId, const std::uint32_t threadId)
    {
        return QStringLiteral("%1.%2")
            .arg(processId)
            .arg(threadId == 0U ? QStringLiteral("-") : QString::number(threadId));
    }

    // keyboardSourceText:
    // - Convert old keyboard fallback and source from win32k PDB lines into source names;
    // - Input source: KSWORD_ARK_KEYBOARD_SOURCE_* or compatible value;
    // - Return: Source description; unknown values retain the numeric value.
    QString keyboardSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE:
            return QStringLiteral("win32k HotkeyTable");
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_THREAD_HOOK_CHAIN:
            return QStringLiteral("win32k ThreadHookChain");
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN:
            return QStringLiteral("win32k GlobalHookChain");
        default:
            return QStringLiteral("Source(%1)").arg(source);
        }
    }

    // hookScopeText:
    // - Convert the Hook scope numeric value into readable categories such as thread/global;
    // - Input scope: KSWORD_ARK_KEYBOARD_HOOK_SCOPE_*;
    // - Returns: text for the 'Scope' column in the table.
    QString hookScopeText(const std::uint32_t scope)
    {
        switch (scope)
        {
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD:
            return QStringLiteral("Thread");
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL:
            return QStringLiteral("Global");
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_UNKNOWN:
            return QStringLiteral("Unknown");
        default:
            return QStringLiteral("Scope(%1)").arg(scope);
        }
    }

    // hookTypeText:
    // - Convert Win32 Hook type values to WH_* names;
    // - Input hookType: Type in the R0 Hook line;
    // - Returns: Text for the 'Type' column in the table; retains the original number for unknown types.
    QString hookTypeText(const std::uint32_t hookType)
    {
        switch (hookType)
        {
        case 0xFFFFFFFFUL:
            return QStringLiteral("WH_MSGFILTER(-1)");
        case 0UL:
            return QStringLiteral("WH_JOURNALRECORD");
        case 1UL:
            return QStringLiteral("WH_JOURNALPLAYBACK");
        case 2UL:
            return QStringLiteral("WH_KEYBOARD");
        case 3UL:
            return QStringLiteral("WH_GETMESSAGE");
        case 4UL:
            return QStringLiteral("WH_CALLWNDPROC");
        case 5UL:
            return QStringLiteral("WH_CBT");
        case 6UL:
            return QStringLiteral("WH_SYSMSGFILTER");
        case 7UL:
            return QStringLiteral("WH_MOUSE");
        case 8UL:
            return QStringLiteral("WH_HARDWARE");
        case 9UL:
            return QStringLiteral("WH_DEBUG");
        case 10UL:
            return QStringLiteral("WH_SHELL");
        case 11UL:
            return QStringLiteral("WH_FOREGROUNDIDLE");
        case 12UL:
            return QStringLiteral("WH_CALLWNDPROCRET");
        case 13UL:
            return QStringLiteral("WH_KEYBOARD_LL");
        case 14UL:
            return QStringLiteral("WH_MOUSE_LL");
        default:
            return QStringLiteral("WH_TYPE(%1)").arg(hookType);
        }
    }

    QString messageHookFlagsText(const std::uint32_t flags)
    {
        QStringList names;
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_GLOBAL) != 0U)
        {
            names << QStringLiteral("GLOBAL");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_ANSI) != 0U)
        {
            names << QStringLiteral("ANSI");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NEED_SKIP) != 0U)
        {
            names << QStringLiteral("NEED_SKIP");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_HUNG) != 0U)
        {
            names << QStringLiteral("HUNG");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_FAULTED) != 0U)
        {
            names << QStringLiteral("FAULTED");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NO_DELAY) != 0U)
        {
            names << QStringLiteral("NO_DELAY");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_WOW64_DLL) != 0U)
        {
            names << QStringLiteral("WOW64_DLL");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_DESTROYED) != 0U)
        {
            names << QStringLiteral("DESTROYED");
        }
        const std::uint32_t kKnownMask =
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_GLOBAL |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_ANSI |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NEED_SKIP |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_HUNG |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_FAULTED |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NO_DELAY |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_WOW64_DLL |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_DESTROYED;
        if ((flags & ~kKnownMask) != 0U)
        {
            names << formatUInt64Hex(flags & ~kKnownMask);
        }
        if (names.isEmpty())
        {
            names << QStringLiteral("0");
        }
        return QStringLiteral("%1 (%2)")
            .arg(names.join(QStringLiteral(" | ")))
            .arg(formatUInt64Hex(flags));
    }

    QString messageHookLayoutSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY:
            return ks::i18n::contextText(
                QStringLiteral("window.message_hook.layout.exact"),
                QStringLiteral("精确 PE 身份"));
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT_SOURCE_NEAREST_PREVIOUS:
            return ks::i18n::contextText(
                QStringLiteral("window.message_hook.layout.previous"),
                QStringLiteral("最近旧版回退"));
        default:
            return ks::i18n::contextText(
                QStringLiteral("window.message_hook.layout.unknown"),
                QStringLiteral("未知"));
        }
    }

    QString win32kAtomName(const std::uint32_t atomValue)
    {
        if (atomValue == 0U || atomValue > 0xFFFFU)
        {
            return {};
        }
        wchar_t buffer[512]{};
        const UINT kChars = ::GlobalGetAtomNameW(
            static_cast<ATOM>(atomValue),
            buffer,
            static_cast<int>(std::size(buffer)));
        return kChars == 0U
            ? QString()
            : QString::fromWCharArray(buffer, static_cast<qsizetype>(kChars));
    }

    // deviceAuditStatusText:
    // - Convert device/GPU/watchdog audit status to text.
    // - Input: status: KSWORD_ARK_DEVICE_AUDIT_STATUS_*.
    // - Returns: table status column text.
    QString deviceAuditStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_UNAVAILABLE:
            return QStringLiteral("Unavailable");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND:
            return QStringLiteral("NotFound");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("Truncated");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED:
            return QStringLiteral("QueryFailed");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported");
        default:
            return QStringLiteral("Status(%1)").arg(status);
        }
    }

    // deviceAuditRowKindText:
    // - Convert device audit rowKind to summary/device text;
    // - Input rowKind: Row type returned by R0;
    // - Returns: text for the 'Kind' column in the table.
    QString deviceAuditRowKindText(const std::uint32_t rowKind)
    {
        switch (rowKind)
        {
        case KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY:
            return QStringLiteral("DriverSummary");
        case KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DEVICE_ROW:
            return QStringLiteral("DeviceRow");
        default:
            return QStringLiteral("RowKind(%1)").arg(rowKind);
        }
    }

    // deviceAuditRoleText:
    // - Convert device stack roles into text such as PDO/FDO/filter/display/watchdog.
    // - Input: role is one of KSWORD_ARK_DEVICE_AUDIT_ROLE_*.
    // - Returns: text for the 'Role' column in the table.
    QString deviceAuditRoleText(const std::uint32_t role)
    {
        switch (role)
        {
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_PDO:
            return QStringLiteral("PDO");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_FDO:
            return QStringLiteral("FDO");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_UPPER_FILTER:
            return QStringLiteral("UpperFilter");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_LOWER_FILTER:
            return QStringLiteral("LowerFilter");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_CLASS_DRIVER:
            return QStringLiteral("ClassDriver");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER:
            return QStringLiteral("BusDriver");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_COMPOSITE:
            return QStringLiteral("Composite");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE:
            return QStringLiteral("Interface");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_CONTROLLER:
            return QStringLiteral("Controller");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY:
            return QStringLiteral("Display");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_WATCHDOG:
            return QStringLiteral("Watchdog");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_UNKNOWN:
            return QStringLiteral("Unknown");
        default:
            return QStringLiteral("Role(%1)").arg(role);
        }
    }

    // stdWideToQString:
    // - Convert ArkDriverClient's std::wstring detail fields to QString;
    // - Input value: wide string saved by the R3 client;
    // - Return: Display empty values uniformly as <empty> to avoid completely blank table cells.
    QString stdWideToQString(const std::wstring& value)
    {
        if (value.empty())
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromStdWString(value);
    }

    // win32kJsonString:
    // - Input object/name/fallback;
    // - Handling: Read string fields from the win32k public deep JSON object.
    // - Returns: the original value if the field exists, otherwise returns the fallback.
    QString win32kJsonString(
        const QJsonObject& object,
        const QString& name,
        const QString& fallback)
    {
        const QJsonValue kValue = object.value(name);
        return kValue.isString() ? kValue.toString() : fallback;
    }

    // win32kJsonInt:
    // - Input object/name/fallback;
    // - Processing: Read JSON numbers to avoid displaying blank content in the UI.
    // - Return: Integer value; returns fallback on failure.
    int win32kJsonInt(
        const QJsonObject& object,
        const QString& name,
        const int fallback)
    {
        const QJsonValue kValue = object.value(name);
        return kValue.isDouble() ? kValue.toInt(fallback) : fallback;
    }

    // findWin32kPublicDeepJsonPath:
    // - No input;
    // - Processing: Locate win32k public deep JSON by Release layout and development working directory layout.
    // - Returns: File path; returns an empty string if not found.
    QString findWin32kPublicDeepJsonPath()
    {
        QStringList candidateDirectories;
        const QString kApplicationDirectory = QCoreApplication::applicationDirPath();
        const QString kCurrentDirectory = QDir::currentPath();
        candidateDirectories.push_back(
            QDir(kApplicationDirectory).filePath(QStringLiteral("profiles/pdb_deep_offsets")));
        candidateDirectories.push_back(
            QDir(kApplicationDirectory).filePath(QStringLiteral("../profiles/pdb_deep_offsets")));
        candidateDirectories.push_back(
            QDir(kCurrentDirectory).filePath(QStringLiteral("profiles/pdb_deep_offsets")));
        candidateDirectories.push_back(
            QDir(kCurrentDirectory).filePath(QStringLiteral("apps/desktop/profiles/pdb_deep_offsets")));

        for (const QString& directoryText : candidateDirectories)
        {
            QDir directory(directoryText);
            if (!directory.exists())
            {
                continue;
            }

            QStringList fileNames = directory.entryList(
                QStringList{ QStringLiteral("win32k_gui_public_*_deep_offsets.json.qz") },
                QDir::Files,
                QDir::Name);
            if (fileNames.isEmpty())
            {
                fileNames = directory.entryList(
                    QStringList{ QStringLiteral("win32k_gui_public_*_deep_offsets.json") },
                    QDir::Files,
                    QDir::Name);
            }
            if (!fileNames.isEmpty())
            {
                return directory.absoluteFilePath(fileNames.first());
            }
        }
        return QString();
    }

    // appendWin32kPublicSymbolExamples:
    // - Input: lines (detail text lines); moduleObject (a win32k-family PDB module);
    // - Processing: Extract a few public symbol examples by symbol group to avoid the detail page showing only statistical summaries.
    // - Returns: None; directly appends human-readable text.
    void appendWin32kPublicSymbolExamples(
        QStringList& lines,
        const QJsonObject& moduleObject,
        const QString& groupName,
        const int maxExamples)
    {
        const QJsonArray kSymbolArray = moduleObject.value(QStringLiteral("publicSymbols")).toArray();
        QStringList examples;
        for (const QJsonValue& symbolValue : kSymbolArray)
        {
            const QJsonObject kSymbolObject = symbolValue.toObject();
            if (win32kJsonString(kSymbolObject, QStringLiteral("group"), QString()) != groupName)
            {
                continue;
            }

            examples.push_back(QStringLiteral("%1 @ %2")
                .arg(win32kJsonString(kSymbolObject, QStringLiteral("name"), QStringLiteral("<unnamed>")))
                .arg(win32kJsonString(kSymbolObject, QStringLiteral("sectionOffset"), QStringLiteral("<no section>"))));
            if (examples.size() >= maxExamples)
            {
                break;
            }
        }

        if (!examples.isEmpty())
        {
            lines << QStringLiteral("    publicSymbols[%1]: %2")
                .arg(groupName)
                .arg(examples.join(QStringLiteral(" | ")));
        }
    }

    // appendWin32kRuntimeDomainExamples:
    // - Input: lines: output text lines; domainObject: a single domain under runtimeDetailCatalog.domains;
    // - Processing: Select a few representative symbols from publicSymbolExamples by group.
    // - Returns: None. Directly appends to the detail text to prevent window details from remaining only at the readiness summary.
    void appendWin32kRuntimeDomainExamples(
        QStringList& lines,
        const QJsonObject& domainObject,
        const QString& groupName,
        const int maxExamples)
    {
        const QJsonObject kExamplesObject =
            domainObject.value(QStringLiteral("publicSymbolExamples")).toObject();
        const QJsonArray kExampleArray = kExamplesObject.value(groupName).toArray();
        QStringList examples;
        for (const QJsonValue& exampleValue : kExampleArray)
        {
            const QJsonObject kExampleObject = exampleValue.toObject();
            const QString kModuleName =
                win32kJsonString(kExampleObject, QStringLiteral("moduleName"), QStringLiteral("<module>"));
            const QString kSymbolName =
                win32kJsonString(kExampleObject, QStringLiteral("name"), QStringLiteral("<symbol>"));
            const QString kSectionOffset =
                win32kJsonString(kExampleObject, QStringLiteral("sectionOffset"), QStringLiteral("<section>"));
            examples.push_back(QStringLiteral("%1!%2 @ %3")
                .arg(kModuleName)
                .arg(kSymbolName)
                .arg(kSectionOffset));
            if (examples.size() >= maxExamples)
            {
                break;
            }
        }

        if (!examples.isEmpty())
        {
            lines << QStringLiteral("      examples[%1]: %2")
                .arg(groupName)
                .arg(examples.join(QStringLiteral(" | ")));
        }
    }

    // appendWin32kRuntimeCatalogPreview:
    // - Input lines: output text lines; rootObject: win32k public deep JSON root object;
    // - Processing: Display structured readiness for the five runtime domains: window, gui-thread, hotkey, hook, and desktop;
    // - Return: None. This function reads JSON only and does not trigger driver calls.
    void appendWin32kRuntimeCatalogPreview(
        QStringList& lines,
        const QJsonObject& rootObject)
    {
        const QJsonObject kCatalogObject =
            rootObject.value(QStringLiteral("runtimeDetailCatalog")).toObject();
        if (kCatalogObject.isEmpty())
        {
            lines << QStringLiteral("RuntimeDetailCatalog: <缺失，旧版 win32k public deep JSON>");
            return;
        }

        lines << QStringLiteral("[Win32K Runtime Detail Catalog]");
        lines << QStringLiteral("ReadyDomains/BlockedDomains: %1 / %2")
            .arg(win32kJsonInt(kCatalogObject, QStringLiteral("readyDomainCount"), 0))
            .arg(win32kJsonInt(kCatalogObject, QStringLiteral("blockedDomainCount"), 0));
        lines << QStringLiteral("CatalogReady: %1")
            .arg(kCatalogObject.value(QStringLiteral("ready")).toBool(false)
                ? QStringLiteral("是")
                : QStringLiteral("否"));

        const QJsonObject kDomainsObject =
            kCatalogObject.value(QStringLiteral("domains")).toObject();
        for (auto iterator = kDomainsObject.constBegin(); iterator != kDomainsObject.constEnd(); ++iterator)
        {
            const QString kDomainId = iterator.key();
            const QJsonObject kDomainObject = iterator.value().toObject();
            const QString kDisplayName =
                win32kJsonString(kDomainObject, QStringLiteral("displayName"), kDomainId);
            QStringList missingTypes;
            for (const QJsonValue& missingValue : kDomainObject.value(QStringLiteral("missingPrivateTypes")).toArray())
            {
                if (missingValue.isString())
                {
                    missingTypes.push_back(missingValue.toString());
                }
            }

            QStringList groupParts;
            const QJsonObject kGroupCounts =
                kDomainObject.value(QStringLiteral("publicSymbolGroups")).toObject();
            for (auto groupIterator = kGroupCounts.constBegin(); groupIterator != kGroupCounts.constEnd(); ++groupIterator)
            {
                groupParts.push_back(QStringLiteral("%1=%2")
                    .arg(groupIterator.key())
                    .arg(groupIterator.value().toInt(0)));
            }

            lines << QStringLiteral("  Domain[%1] %2").arg(kDomainId, kDisplayName);
            lines << QStringLiteral("    ready=%1; concreteFields=%2; publicEvidence=%3")
                .arg(kDomainObject.value(QStringLiteral("ready")).toBool(false)
                    ? QStringLiteral("是")
                    : QStringLiteral("否"))
                .arg(win32kJsonInt(kDomainObject, QStringLiteral("concreteFieldCount"), 0))
                .arg(kDomainObject.value(QStringLiteral("publicEvidenceAvailable")).toBool(false)
                    ? QStringLiteral("是")
                    : QStringLiteral("否"));
            lines << QStringLiteral("    missingPrivateTypes: %1")
                .arg(missingTypes.isEmpty()
                    ? QStringLiteral("<none>")
                    : missingTypes.join(QStringLiteral(", ")));
            lines << QStringLiteral("    publicSymbolGroups: %1")
                .arg(groupParts.isEmpty()
                    ? QStringLiteral("<none>")
                    : groupParts.join(QStringLiteral("; ")));
            lines << QStringLiteral("    intendedUse: %1")
                .arg(win32kJsonString(kDomainObject, QStringLiteral("intendedUse"), QStringLiteral("<none>")));
            const QString kBlockedBy =
                win32kJsonString(kDomainObject, QStringLiteral("blockedBy"), QString());
            if (!kBlockedBy.isEmpty())
            {
                lines << QStringLiteral("    blockedBy: %1").arg(kBlockedBy);
            }

            for (auto groupIterator = kGroupCounts.constBegin(); groupIterator != kGroupCounts.constEnd(); ++groupIterator)
            {
                appendWin32kRuntimeDomainExamples(lines, kDomainObject, groupIterator.key(), 2);
            }
        }
    }

    // win32kPublicPdbCatalogPreview:
    // - Note: Reads the win32k public PDB deep JSON distributed with the application.
    // - Display public symbol/open type statistics, private GUI layout gaps, and representative symbols;
    // - Return: Multi-line text suitable for display in the single HWND details area; does not trigger R0 calls.
    QString win32kPublicPdbCatalogPreview()
    {
        static QMutex cacheMutex;
        static QString cachedText;
        {
            QMutexLocker locker(&cacheMutex);
            if (!cachedText.isEmpty())
            {
                return cachedText;
            }
        }

        const auto kStoreAndReturn = [](const QString& text) -> QString
        {
            QMutexLocker locker(&cacheMutex);
            cachedText = text;
            return cachedText;
        };

        const QString kJsonPath = findWin32kPublicDeepJsonPath();
        if (kJsonPath.isEmpty())
        {
            return kStoreAndReturn(QStringLiteral(
                "[Win32K Public PDB Catalog]\n"
                "未找到 profiles/pdb_deep_offsets/win32k_gui_public_*_deep_offsets.json；"
                "窗口详情只能显示 R0 readiness，无法展示 public symbol 事实库。"));
        }

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument kDocument = ks::profile::readProfileJsonDocument(kJsonPath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
        {
            return kStoreAndReturn(QStringLiteral(
                "[Win32K Public PDB Catalog]\n"
                "win32k public deep JSON 解析失败：%1；文件=%2")
                .arg(readErrorText.isEmpty() ? parseError.errorString() : readErrorText)
                .arg(kJsonPath));
        }

        const QJsonObject kRootObject = kDocument.object();
        const QJsonObject kStatsObject = kRootObject.value(QStringLiteral("stats")).toObject();
        QStringList lines;
        lines << QStringLiteral("[Win32K Public PDB Catalog]");
        lines << QStringLiteral("Source: %1").arg(kJsonPath);
        lines << QStringLiteral("Modules/PublicSymbols/PublicFields: %1 / %2 / %3")
            .arg(win32kJsonInt(kStatsObject, QStringLiteral("moduleCount"), 0))
            .arg(win32kJsonInt(kStatsObject, QStringLiteral("publicSymbolCount"), 0))
            .arg(win32kJsonInt(kStatsObject, QStringLiteral("fieldCount"), 0));
        lines << QStringLiteral("PrivateGuiLayoutReady: %1")
            .arg(kStatsObject.value(QStringLiteral("privateTypeReady")).toBool(false) ? QStringLiteral("是") : QStringLiteral("否"));

        // runtimeDetailCatalog is the structured capability directory newly written by the generator:
        // - It separates windows, GUI threads, hotkeys, hooks, and Desktop/Session into independent domains.
        // - The UI details area displays missing private types and available public symbol examples based on this.
        // - This allows users to see why deep reading is not possible and what specific evidence is currently available.
        appendWin32kRuntimeCatalogPreview(lines, kRootObject);

        const QJsonObject kMissingByModule =
            kRootObject.value(QStringLiteral("missingPrivateTypesByModule")).toObject();
        for (auto iterator = kMissingByModule.constBegin(); iterator != kMissingByModule.constEnd(); ++iterator)
        {
            QStringList missingTypes;
            const QJsonArray kMissingArray = iterator.value().toArray();
            for (const QJsonValue& missingValue : kMissingArray)
            {
                if (missingValue.isString())
                {
                    missingTypes.push_back(missingValue.toString());
                }
            }
            lines << QStringLiteral("MissingPrivateTypes[%1]: %2")
                .arg(iterator.key())
                .arg(missingTypes.isEmpty() ? QStringLiteral("<none>") : missingTypes.join(QStringLiteral(", ")));
        }

        lines << QStringLiteral("说明: publicSymbols 可用于函数/模块归因；tagWND/tagTHREADINFO/tagQ/tagHOOK/tagHOTKEY 字段读取仍需要 private PDB 或经验证 profile。");

        const QJsonArray kModuleArray = kRootObject.value(QStringLiteral("modules")).toArray();
        for (const QJsonValue& moduleValue : kModuleArray)
        {
            const QJsonObject kModuleObject = moduleValue.toObject();
            const QJsonObject kSourceObject = kModuleObject.value(QStringLiteral("source")).toObject();
            const QJsonObject kModuleStatsObject = kModuleObject.value(QStringLiteral("stats")).toObject();
            lines << QStringLiteral("Module: %1 PDB=%2 Age=%3 PublicSymbols=%4 Fields=%5")
                .arg(win32kJsonString(kModuleObject, QStringLiteral("moduleName"), QStringLiteral("<module>")))
                .arg(win32kJsonString(kSourceObject, QStringLiteral("pdbGuid"), QStringLiteral("<guid>")))
                .arg(win32kJsonInt(kSourceObject, QStringLiteral("pdbAge"), 0))
                .arg(win32kJsonInt(kModuleStatsObject, QStringLiteral("publicSymbolCount"), 0))
                .arg(win32kJsonInt(kModuleStatsObject, QStringLiteral("fieldCount"), 0));
            appendWin32kPublicSymbolExamples(lines, kModuleObject, QStringLiteral("window_object"), 3);
            appendWin32kPublicSymbolExamples(lines, kModuleObject, QStringLiteral("gui_thread_queue"), 3);
            appendWin32kPublicSymbolExamples(lines, kModuleObject, QStringLiteral("hotkey_hook"), 3);
            appendWin32kPublicSymbolExamples(lines, kModuleObject, QStringLiteral("desktop_session"), 2);
        }

        const QJsonArray kNotesArray = kRootObject.value(QStringLiteral("notes")).toArray();
        for (const QJsonValue& noteValue : kNotesArray)
        {
            if (noteValue.isString())
            {
                lines << QStringLiteral("Note: %1").arg(noteValue.toString());
            }
        }

        return kStoreAndReturn(lines.join(QChar('\n')));
    }

    // win32kPrivateLayoutLimitationText:
    // - Note: The public win32k PDB currently lacks private structures such as tagWND, tagTHREADINFO, and tagQ.
    // - Inputs: None;
    // - Returns: A human-readable description suitable for summary areas and table detail columns.
    QString win32kPrivateLayoutLimitationText()
    {
        return QStringLiteral(
            "当前 public win32k PDB 只提供公共符号/部分类型，缺少 tagWND、tagTHREADINFO、tagQ、tagHOOK、tagHOTKEY、tagDESKTOP 等私有 GUI layout；"
            "因此 R0 单窗口详情只能报告模块/profile/capability readiness，不能安全读取 tagWND 字段。");
    }

    // readableDriverDetailText:
    // - Input: rawDetail: raw detail text returned by R0/R3 wrapper; fallbackText: null replacement description;
    // - Handling: Collapse common English IOCTL/unsupported/profile/capability logs into Chinese-readable explanations.
    // - Returns: Short text suitable for the 'Details' column in a table, avoiding direct exposure of raw DeviceIoControl logs.
    QString readableDriverDetailText(
        const QString& rawDetail,
        const QString& fallbackText = QStringLiteral("驱动未提供额外明细"))
    {
        QString detailText = rawDetail.trimmed();
        detailText.replace(QChar('\r'), QChar(' '));
        detailText.replace(QChar('\n'), QChar(' '));
        detailText = detailText.simplified();

        if (detailText.isEmpty() ||
            detailText == QStringLiteral("<empty>") ||
            detailText == QStringLiteral("<none>") ||
            detailText == QStringLiteral("无额外说明"))
        {
            return fallbackText;
        }
        if (detailText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动调用失败或当前 R3/R0 协议版本不匹配");
        }
        if (detailText.contains(QStringLiteral("tagWND"), Qt::CaseInsensitive) &&
            (detailText.contains(QStringLiteral("not wired"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("not been wired"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("waiting for"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("private"), Qt::CaseInsensitive)))
        {
            return win32kPrivateLayoutLimitationText();
        }
        if (detailText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            detailText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动/协议暂不支持该只读审计入口");
        }
        if (detailText.contains(QStringLiteral("profile"), Qt::CaseInsensitive) &&
            (detailText.contains(QStringLiteral("missing"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("not found"), Qt::CaseInsensitive)))
        {
            return QStringLiteral("缺少匹配的 PDB/DynData profile，已降级为可用字段展示");
        }
        if (detailText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) &&
            (detailText.contains(QStringLiteral("missing"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("denied"), Qt::CaseInsensitive)))
        {
            return QStringLiteral("DynData capability 未满足，相关深度字段暂不可用");
        }
        if (detailText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive) &&
            detailText.contains(QStringLiteral("trunc"), Qt::CaseInsensitive))
        {
            return QStringLiteral("结果过多，当前缓冲区内只展示截断后的前部证据");
        }
        return detailText;
    }

    // auditStateText:
    // - normalize the status of the new R0 variable audit wrapper to ok/unsupported/unavailable.
    // - Input result: result structure with io/unsupported fields;
    // - Returns: Short status text displayed in the table's diagnostic row.
    template <typename TResult>
    QString auditStateText(const TResult& result)
    {
        if (result.io.ok)
        {
            return QStringLiteral("ok");
        }
        if (result.unsupported)
        {
            return QStringLiteral("unsupported");
        }
        return QStringLiteral("unavailable");
    }

    // auditMessageText:
    // - Aggregate IO status, return row count, and error message;
    // - Input name: Wrapper name; result: ArkDriverClient result.
    // - Returns: a single line of diagnostic text to be placed in the 'Details' column.
    template <typename TResult>
    QString auditMessageText(const QString& name, const TResult& result)
    {
        const QString kMessageText = QString::fromStdString(result.io.message).trimmed().isEmpty()
            ? QStringLiteral("<empty>")
            : QString::fromStdString(result.io.message);
        const bool kIsWin32kAudit =
            name.contains(QStringLiteral("Win32k"), Qt::CaseInsensitive) ||
            name.contains(QStringLiteral("win32k"), Qt::CaseInsensitive);

        QString readableStateText;
        if (result.io.ok)
        {
            if (kIsWin32kAudit &&
                result.status == KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING)
            {
                readableStateText = QStringLiteral("驱动入口可用，但缺少对应 win32k PDB profile/字段映射，当前不会返回结构化行");
            }
            else if (kIsWin32kAudit &&
                result.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND)
            {
                readableStateText = QStringLiteral("驱动入口可用，但未定位 win32k/win32kbase/win32kfull 模块");
            }
            else if (kIsWin32kAudit &&
                result.status == KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED)
            {
                readableStateText = QStringLiteral("驱动入口可用，但底层枚举模式/Session 不匹配，当前不会返回结构化行");
            }
            else
            {
                readableStateText = result.returnedCount == 0U
                    ? QStringLiteral("驱动接口可用，但本次没有返回结构化行")
                    : QStringLiteral("驱动接口可用，已返回结构化行");
            }
        }
        else if (result.unsupported)
        {
            readableStateText = QStringLiteral("当前驱动未提供这个 win32k 审计入口");
        }
        else
        {
            readableStateText = QStringLiteral("驱动接口暂不可用，页面使用本地只读 fallback");
        }

        const QString kReadableMessageText =
            kMessageText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive)
            ? QStringLiteral("驱动调用失败或版本不匹配，已保留本地证据行")
            : (kMessageText == QStringLiteral("<empty>") ? QStringLiteral("无额外驱动消息") : kMessageText);

        return QStringLiteral("%1：%2；驱动报告 %3/%4 行；最近状态 %5；说明：%6")
            .arg(name)
            .arg(readableStateText)
            .arg(result.returnedCount)
            .arg(result.totalCount)
            .arg(formatNtStatusText(result.lastStatus))
            .arg(kReadableMessageText);
    }

    // win32kEmptyStateText:
    // - Input result: Win32K structured enumeration result;
    // - Processing: Decompose the root cause of 'IOCTL succeeded but no rows returned' into missing profile, missing module, or empty result.
    // - Return: Text for the table status column, avoiding misinterpretation of profile-gated empty responses as OK.
    template <typename TResult>
    QString win32kEmptyStateText(const TResult& result)
    {
        if (!result.io.ok)
        {
            return result.unsupported ? QStringLiteral("unsupported") : QStringLiteral("unavailable");
        }
        switch (result.status)
        {
        case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING:
            return QStringLiteral("profile-missing");
        case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND:
            return QStringLiteral("win32k-not-found");
        case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED:
            return QStringLiteral("unsupported");
        case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("truncated");
        case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED:
            return QStringLiteral("enum-failed");
        case KSWORD_ARK_WIN32K_STATUS_OK:
            return result.returnedCount == 0U ? QStringLiteral("empty") : QStringLiteral("ok");
        default:
            return QStringLiteral("status-%1").arg(result.status);
        }
    }

    // keyboardMessageText:
    // - Aggregate the status of legacy keyboard hotkey/hook wrappers;
    // - Input name: wrapper name; result: Keyboard enumeration result;
    // - Returns: A single line of text suitable for a fallback diagnostic line.
    template <typename TResult>
    QString keyboardMessageText(const QString& name, const TResult& result)
    {
        const QString kMessageText = QString::fromStdString(result.io.message).trimmed().isEmpty()
            ? QStringLiteral("<empty>")
            : QString::fromStdString(result.io.message);

        const QString kReadableStateText = result.io.ok
            ? (result.returnedCount == 0U
                ? QStringLiteral("键盘审计 fallback 可用，但未返回热键/Hook 行")
                : QStringLiteral("键盘审计 fallback 已返回结构化行"))
            : QStringLiteral("键盘审计 fallback 当前不可用");
        const QString kReadableMessageText =
            kMessageText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive)
            ? QStringLiteral("旧键盘审计接口调用失败或驱动未注册该入口")
            : (kMessageText == QStringLiteral("<empty>") ? QStringLiteral("无额外驱动消息") : kMessageText);

        return QStringLiteral("%1：%2；驱动报告 %3/%4 行；最近状态 %5；说明：%6")
            .arg(name)
            .arg(kReadableStateText)
            .arg(result.returnedCount)
            .arg(result.totalCount)
            .arg(formatNtStatusText(result.lastStatus))
            .arg(kReadableMessageText);
    }

    // keyboardEmptyStateText:
    // - Input result: old keyboard fallback enum result;
    // - Processing: Convert pattern/session/unsupported states to short text.
    // - Returns: the fallback status column text for the hotkey/Hook table.
    template <typename TResult>
    QString keyboardEmptyStateText(const TResult& result)
    {
        if (!result.io.ok)
        {
            return QStringLiteral("keyboard-unavailable");
        }
        switch (result.status)
        {
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK:
            return result.returnedCount == 0U ? QStringLiteral("keyboard-empty") : QStringLiteral("keyboard-ok");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED:
            return QStringLiteral("keyboard-unsupported");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND:
            return QStringLiteral("keyboard-win32k-not-found");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND:
            return QStringLiteral("keyboard-pattern-not-found");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE:
            return QStringLiteral("keyboard-session-unavailable");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("keyboard-truncated");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED:
            return QStringLiteral("keyboard-read-failed");
        default:
            return QStringLiteral("keyboard-status-%1").arg(result.status);
        }
    }

    // clipboardSnapshotRows:
    // - Input clipboardObject: Clipboard object accessible by the current UI thread;
    // - Processing: Generate only typed summaries to avoid misdisplaying the user's recently copied audit table TSV as 'actual clipboard audit content'.
    // - Return: Clipboard page key-value rows; do not capture messages, install hooks, or parse sensitive payloads.
    QVector<QStringList> clipboardSnapshotRows(const QClipboard* clipboardObject)
    {
        QVector<QStringList> rows;
        rows.reserve(8);
        if (clipboardObject == nullptr)
        {
            rows.push_back(QStringList{ QStringLiteral("ClipboardAvailable"), QStringLiteral("否") });
            rows.push_back(QStringList{ QStringLiteral("说明"), QStringLiteral("QApplication::clipboard 不可用，无法读取 UI 会话剪贴板摘要。") });
            return rows;
        }

        const QMimeData* mimeData = clipboardObject->mimeData(QClipboard::Clipboard);
        rows.push_back(QStringList{ QStringLiteral("ClipboardAvailable"), QStringLiteral("是") });
        rows.push_back(QStringList{ QStringLiteral("OwnsClipboard"), boolText(clipboardObject->ownsClipboard()) });
        if (mimeData == nullptr)
        {
            rows.push_back(QStringList{ QStringLiteral("MimeData"), QStringLiteral("<无>") });
            rows.push_back(QStringList{ QStringLiteral("说明"), QStringLiteral("剪贴板当前没有可读 MIME 数据。") });
            return rows;
        }

        rows.push_back(QStringList{ QStringLiteral("HasText"), boolText(mimeData->hasText()) });
        rows.push_back(QStringList{ QStringLiteral("HasHtml"), boolText(mimeData->hasHtml()) });
        rows.push_back(QStringList{ QStringLiteral("HasImage"), boolText(mimeData->hasImage()) });
        rows.push_back(QStringList{ QStringLiteral("HasUrls"), boolText(mimeData->hasUrls()) });
        rows.push_back(QStringList{ QStringLiteral("Formats"), mimeData->formats().join(QStringLiteral("; ")) });

        if (mimeData->hasText())
        {
            QString textPreview = mimeData->text();
            const bool kLooksLikeAuditTableRow =
                textPreview.contains(QChar('\t')) &&
                (textPreview.contains(QStringLiteral("queryWin32k"), Qt::CaseInsensitive) ||
                 textPreview.contains(QStringLiteral("<无Hook行>"), Qt::CaseInsensitive) ||
                 textPreview.contains(QStringLiteral("<无热键行>"), Qt::CaseInsensitive));
            if (kLooksLikeAuditTableRow)
            {
                rows.push_back(QStringList{
                    QStringLiteral("TextPreview"),
                    QStringLiteral("<已隐藏：当前剪贴板像是本工具表格复制行，避免和剪贴板审计结果混淆>") });
            }
            else
            {
                textPreview.replace(QChar('\r'), QChar(' '));
                textPreview.replace(QChar('\n'), QChar(' '));
                textPreview = textPreview.simplified();
                if (textPreview.size() > 160)
                {
                    textPreview = textPreview.left(160) + QStringLiteral("...");
                }
                rows.push_back(QStringList{ QStringLiteral("TextPreview"), textPreview.isEmpty() ? QStringLiteral("<空文本>") : textPreview });
            }
        }
        else
        {
            rows.push_back(QStringList{ QStringLiteral("TextPreview"), QStringLiteral("<非文本剪贴板>") });
        }

        rows.push_back(QStringList{ QStringLiteral("MessageOnly窗口"), QStringLiteral("建议在“窗口管理”窗口列表中 cross-view 标注") });
        rows.push_back(QStringList{ QStringLiteral("说明"), QStringLiteral("只读读取剪贴板 MIME 摘要；不做消息抓取，不展示疑似审计表复制行。") });
        return rows;
    }

    QString wideArrayToQString(const wchar_t* const bufferPointer, const std::size_t maxChars);

    // win32kRuntimeStatusText:
    // - Convert runtime detail status of a single HWND into human-readable short text;
    // - Input statusValue: KSWORD_ARK_WIN32K_STATUS_*;
    // - Returns: Stable description for the 'Details' column of the window table.
    QString win32kRuntimeStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_WIN32K_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_WIN32K_STATUS_PARTIAL:
            return QStringLiteral("Partial（部分字段可用）");
        case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported（驱动/协议不支持）");
        case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING:
            return QStringLiteral("ProfileMissing（缺少PDB profile）");
        case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND:
            return QStringLiteral("Win32kNotFound（模块未找到）");
        case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("BufferTruncated（结果被截断）");
        case KSWORD_ARK_WIN32K_STATUS_READ_FAILED:
            return QStringLiteral("ReadFailed（读取失败）");
        case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED:
            return QStringLiteral("EnumFailed（枚举失败）");
        case KSWORD_ARK_WIN32K_STATUS_UNKNOWN:
            return QStringLiteral("Unknown（未初始化）");
        default:
            return QStringLiteral("Status(%1)").arg(statusValue);
        }
    }

    // win32kRectText:
    // - Converts the R0-returned RECT to a short text string.
    // - Input rect: window or client rectangle;
    // - Returns: left, top, width, height format for easy table reading.
    QString win32kRectText(const KSWORD_ARK_WIN32K_RECT& rect)
    {
        const long kWidth = rect.right - rect.left;
        const long kHeight = rect.bottom - rect.top;
        return QStringLiteral("[%1,%2 %3x%4]")
            .arg(rect.left)
            .arg(rect.top)
            .arg(kWidth)
            .arg(kHeight);
    }

    // win32kReadStatusText:
    // - Convert field-level status values for title/class to human-readable text;
    // - Input statusValue: KSWORD_ARK_WIN32K_READ_STATUS_*.
    // - Returns: Field read result description.
    QString win32kReadStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_WIN32K_READ_STATUS_NOT_REQUESTED:
            return QStringLiteral("NotRequested");
        case KSWORD_ARK_WIN32K_READ_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_WIN32K_READ_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported");
        case KSWORD_ARK_WIN32K_READ_STATUS_PROFILE_MISSING:
            return QStringLiteral("ProfileMissing");
        case KSWORD_ARK_WIN32K_READ_STATUS_READ_FAILED:
            return QStringLiteral("ReadFailed");
        case KSWORD_ARK_WIN32K_READ_STATUS_TRUNCATED:
            return QStringLiteral("Truncated");
        default:
            return QStringLiteral("ReadStatus(%1)").arg(statusValue);
        }
    }

    // win32kWindowSnapshotDetailText:
    // - Convert single-line window snapshots into human-readable audit summaries;
    // - Input entry: R0 win32k window row, runtimeDetailText: optional single HWND detail;
    // - Returns: Detail text for the last column of the table; does not directly insert raw driver logs.
    QString win32kWindowSnapshotDetailText(
        const KSWORD_ARK_WIN32K_WINDOW_ENTRY& entry,
        const QString& runtimeDetailText)
    {
        const QString kSnapshotText =
            readableDriverDetailText(
                wideArrayToQString(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS),
                QStringLiteral("窗口快照未提供额外驱动说明"));
        return QStringLiteral(
            "快照：%1；fieldFlags=%2；tagWND=%3；threadInfo=%4；desktop=%5；"
            "windowRect=%6；clientRect=%7；titleRead=%8；classRead=%9；%10；驱动说明=%11")
            .arg(win32kRuntimeStatusText(entry.status))
            .arg(formatUInt64Hex(entry.fieldFlags))
            .arg(formatUInt64Hex(entry.tagWnd))
            .arg(formatUInt64Hex(entry.threadInfo))
            .arg(formatUInt64Hex(entry.desktopObject))
            .arg(win32kRectText(entry.windowRect))
            .arg(win32kRectText(entry.clientRect))
            .arg(win32kReadStatusText(entry.titleStatus))
            .arg(win32kReadStatusText(entry.classStatus))
            .arg(runtimeDetailText)
            .arg(kSnapshotText);
    }

    // win32kWindowRuntimeDetailText:
    // - Calls the ArkDriverClient single HWND detail wrapper and generates a readable summary.
    // - Input hwnd/processId/threadId: identity fields in the window snapshot row;
    // - Return: Read-only diagnostic text; no hooks are installed, and message payloads are not read.
    QString win32kWindowRuntimeDetailText(
        const std::uint64_t hwnd,
        const std::uint32_t processId,
        const std::uint32_t threadId)
    {
        const ksword::ark::Win32kWindowRuntimeDetailResult kDetailResult =
            ksword::ark::DriverClient().queryWin32kWindowDetail(hwnd, processId, threadId);
        if (!kDetailResult.io.ok)
        {
            const QString kRawMessage =
                QString::fromStdString(kDetailResult.io.message).trimmed();
            if (kDetailResult.unsupported)
            {
                return QStringLiteral("单窗口详情：当前驱动未提供该 IOCTL。");
            }
            if (kRawMessage.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
            {
                return QStringLiteral("单窗口详情：驱动调用失败或版本不匹配。");
            }
            return QStringLiteral("单窗口详情：%1")
                .arg(kRawMessage.isEmpty() ? QStringLiteral("暂不可用。") : kRawMessage);
        }

        const KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE& response = kDetailResult.response;
        return QStringLiteral(
            "单窗口详情：%1；HWND=%2；PID/TID=%3/%4；tagWND=%5；threadInfo=%6；"
            "queue=%7；desktop=%8；capability=%9；missing=%10；fieldFlags=%11；说明=%12")
            .arg(win32kRuntimeStatusText(response.status))
            .arg(formatUInt64Hex(response.hwnd))
            .arg(response.processId)
            .arg(response.threadId)
            .arg(formatUInt64Hex(response.tagWnd))
            .arg(formatUInt64Hex(response.threadInfo))
            .arg(formatUInt64Hex(response.queueObject))
            .arg(formatUInt64Hex(response.desktopObject))
            .arg(formatUInt64Hex(response.capabilityMask))
            .arg(formatUInt64Hex(response.missingCapabilityMask))
            .arg(formatUInt64Hex(response.fieldFlags))
            .arg(readableDriverDetailText(
                wideArrayToQString(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS),
                QStringLiteral("单窗口详情未提供额外驱动说明")));
    }

    // tableCopyMenuStyle:
    // - Provide an opaque background for the new context menu to avoid inheriting transparency or black-on-black text;
    // - Inputs: None;
    // - Returns: QMenu stylesheet.
    QString tableCopyMenuStyle()
    {
        return ksword_theme::contextMenuStyle();
    }

    // auditTableStyle:
    // - Explicitly set opaque background, text color, and selection state for the audit table in WindowDock.
    // - Inputs: None;
    // - Returns: style text directly applicable to QTableWidget to avoid 'rows visible but appearing blank' after inheriting parent transparent/dark styles.
    QString auditTableStyle()
    {
        // Here, real #RRGGBB values are used instead of dynamic roles like palette(base):
        // - Some parent Dock styles may incorrectly inherit palette roles as transparent or abnormal colors.
        // When users report that the table is completely invisible, the row model already has fallback data; the highest priority is to ensure the rendering layer is visible.
        // - The return value affects only the audit table's appearance, not the table data or any R0/R3 query logic.
        const QString kSurfaceColor = ksword_theme::surfaceColorHex();
        const QString kSurfaceAltColor = ksword_theme::surfaceAltColorHex();
        const QString kBorderColor = ksword_theme::borderColorHex();
        const QString kTextColor = ksword_theme::textPrimaryColorHex();

        return QStringLiteral(
            "QTableWidget{"
            "  background-color:%1;"
            "  alternate-background-color:%2;"
            "  color:%3;"
            "  gridline-color:%4;"
            "}"
            "QTableWidget::item{"
            "  color:%3;"
            "  padding:3px 5px;"
            "}"
            "QHeaderView::section{"
            "  background:transparent; /* %2 */"
            "  background-color:transparent;"
            "  color:%3;"
            "  border:1px solid %4;"
            "  padding:4px 6px;"
            "}")
            .arg(kSurfaceColor)
            .arg(kSurfaceAltColor)
            .arg(kTextColor)
            .arg(kBorderColor)
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue));
    }

    // transparentAuditTableStyle:
    // - Preserves the parent Tab page background for the transparent structured table in WindowDock.
    // - The table body, viewport, and alternating rows do not draw independent background colors to avoid obscuring the Dock background.
    // - Returns: Transparent style text directly applicable to QTableWidget.
    QString transparentAuditTableStyle()
    {
        const QString kBorderColor = ksword_theme::borderColorHex();
        const QString kTextColor = ksword_theme::textPrimaryColorHex();

        return QStringLiteral(
            "QTableWidget{"
            "  background:transparent;"
            "  background-color:transparent;"
            "  alternate-background-color:transparent;"
            "  color:%1;"
            "  gridline-color:%2;"
            "}"
            "QTableWidget::viewport{"
            "  background:transparent;"
            "  background-color:transparent;"
            "}"
            "QTableWidget::item{"
            "  color:%1;"
            "  padding:3px 5px;"
            "}"
            "QHeaderView::section{"
            "  background:transparent;"
            "  background-color:transparent;"
            "  color:%1;"
            "  border:1px solid %2;"
            "  padding:4px 6px;"
            "}")
            .arg(kTextColor)
            .arg(kBorderColor);
    }

    // applyAuditTablePalette:
    // - Input: table; Read-only table in the WindowDock audit page.
    // - Processing: Write both QPalette and viewport background simultaneously to prevent tables from having rows but being invisible due to parent transparent docks or abnormal QSS.
    // - Return: None; affects only control painting and does not alter any R0/R3 data paths.
    void applyAuditTablePalette(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        const bool kUsesTransparentBackground =
            table->property("ksword_transparent_audit_table").toBool();
        QPalette tablePalette = table->palette();
        tablePalette.setColor(QPalette::Base, ksword_theme::surfaceColor());
        tablePalette.setColor(QPalette::AlternateBase, ksword_theme::surfaceAltColor());
        tablePalette.setColor(QPalette::Text, ksword_theme::textPrimaryColor());
        tablePalette.setColor(QPalette::WindowText, ksword_theme::textPrimaryColor());
        tablePalette.setColor(QPalette::HighlightedText, ksword_theme::onAccentColor());
        tablePalette.setColor(QPalette::Highlight, ksword_theme::accentColor(ksword_theme::AccentRole::kBlue));
        table->setPalette(tablePalette);
        table->setAlternatingRowColors(!kUsesTransparentBackground);
        table->setAutoFillBackground(!kUsesTransparentBackground);
        table->setAttribute(Qt::WA_StyledBackground, kUsesTransparentBackground);
        if (table->viewport() != nullptr)
        {
            table->viewport()->setPalette(tablePalette);
            table->viewport()->setAutoFillBackground(!kUsesTransparentBackground);
            table->viewport()->setAttribute(Qt::WA_StyledBackground, kUsesTransparentBackground);
        }
    }

    // applyTransparentAuditTableBackground:
    // - Input table: WindowDock audit table requiring parent background transparency;
    // - Processing: Write persistent attributes, transparent QSS, and drawing properties.
    // - Return: None. Subsequent refresh calls to applyAuditTablePalette will preserve the transparent state.
    void applyTransparentAuditTableBackground(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setProperty("ksword_transparent_audit_table", true);
        table->setStyleSheet(transparentAuditTableStyle());
        applyAuditTablePalette(table);
    }

    // copyTableCurrentRow:
    // - Copy the current table row to the clipboard as TSV.
    // - Input table: Target table.
    // - Return: None; silently maintains UI stability on failure.
    void copyTableCurrentRow(QTableWidget* table)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kRowIndex = table->currentRow();
        if (kRowIndex < 0 || kRowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join('\t'));
    }

    // installTableCopyMenu:
    // - Install a 'Copy Current Row' context menu for read-only tables.
    // - When a business table explicitly sets ksword_process_detail_pid_column, add a 'Go to Process Details' action based on the PID in that column;
    // - If the table has the kswordSandboxPidColumn property set, additionally add an 'Upload to Sandbox -> VT' menu item and upload the process EXE based on the PID in that column.
    // - Input: table: table requiring menu installation
    // - Return: None. The menu action is read-only and triggers no system modifications.
    void installTableCopyMenu(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
                table->selectRow(kClickedIndex.row());
            }

            QMenu menu(table);
            menu.setStyleSheet(tableCopyMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);

            QAction* openProcessAction = nullptr;
            quint32 processId = 0U;
            const QVariant kProcessDetailPidColumnValue = table->property("ksword_process_detail_pid_column");
            if (kProcessDetailPidColumnValue.isValid())
            {
                const int kProcessDetailPidColumn = kProcessDetailPidColumnValue.toInt();
                const QTableWidgetItem* processIdItem =
                    kProcessDetailPidColumn >= 0 && kProcessDetailPidColumn < table->columnCount() && table->currentRow() >= 0
                    ? table->item(table->currentRow(), kProcessDetailPidColumn)
                    : nullptr;
                bool processIdOk = false;
                processId = processIdItem != nullptr
                    ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
                    : 0U;
                openProcessAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(processIdOk && processId != 0U);
            }

            QAction* uploadVirusTotalAction = nullptr;
            const int kSandboxPidColumn = table->property("kswordSandboxPidColumn").toInt();
            if (kSandboxPidColumn >= 0 && kSandboxPidColumn < table->columnCount())
            {
                menu.addSeparator();
                uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
                    &menu,
                    table,
                    [table, kSandboxPidColumn]() -> ks::online_scan::SandboxUploadTarget
                    {
                        // Input: Current row and configured PID column of the WindowDock table.
                        // Note: Parses the process owning the GUI thread/window from the PID column.
                        // Returns: An empty filePath indicates that the unified layer should query the EXE by PID.
                        ks::online_scan::SandboxUploadTarget uploadTarget;
                        const int kRowIndex = table != nullptr ? table->currentRow() : -1;
                        const QTableWidgetItem* pidItem =
                            (table != nullptr && kRowIndex >= 0) ? table->item(kRowIndex, kSandboxPidColumn) : nullptr;
                        std::uint32_t pidValue = 0;
                        if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
                        {
                            uploadTarget.errorText = QStringLiteral("当前窗口/GUI线程行没有可解析的 PID。");
                            return uploadTarget;
                        }

                        uploadTarget.filePath = QString::fromStdString(ks::process::queryProcessPathByPid(pidValue));
                        uploadTarget.sourceText = QStringLiteral("窗口/GUI线程 PID=%1").arg(pidValue);
                        return uploadTarget;
                    });
                if (uploadVirusTotalAction != nullptr)
                {
                    uploadVirusTotalAction->setEnabled(table->currentRow() >= 0);
                }
            }

            QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(localPosition));
            if (selectedAction == copyRowAction)
            {
                copyTableCurrentRow(table);
            }
            else if (selectedAction == openProcessAction)
            {
                ks::ui::openProcessDetailByPid(processId);
            }
        });
    }

    // containsColumnIndex:
    // - Input: columnGroup is the preset column index set; columnIndex is the candidate column index.
    // - Processing: Determine if the column belongs to the current A/B preset;
    // - Returns: true if the column should be displayed.
    bool containsColumnIndex(const QVector<int>& columnGroup, const int columnIndex)
    {
        return std::find(columnGroup.begin(), columnGroup.end(), columnIndex) != columnGroup.end();
    }

    // buildColumnPresetButtonStyle:
    // - Input selected: Whether the button corresponds to the current column group;
    // - Processing: Use the theme's primary color for the background when selected; keep a transparent background and theme text when not selected.
    // - Returns: QPushButton stylesheet text.
    QString buildColumnPresetButtonStyle(const bool selected)
    {
        const QString kBackgroundText = selected
            ? ksword_theme::accentHex(ksword_theme::AccentRole::kBlue)
            : QStringLiteral("transparent");
        const QString kBorderText = selected
            ? ksword_theme::accentHex(ksword_theme::AccentRole::kBlue)
            : ksword_theme::borderColorHex();
        const QString kTextColor = selected
            ? ksword_theme::onAccentHex()
            : ksword_theme::textPrimaryColorHex();
        return QStringLiteral(
            "QPushButton{min-width:24px;max-width:24px;padding:3px 0;border:1px solid %1;"
            "border-radius:0;color:%2;background:%3;font-weight:700;}"
            "QPushButton:hover{border-color:%4;}"
            "QPushButton:pressed{background:%4;color:%5;}")
            .arg(kBorderText)
            .arg(kTextColor)
            .arg(kBackgroundText)
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::onAccentHex());
    }

    // updateColumnPresetButtons:
    // - Input table: target table, buttonA/buttonB: column group buttons;
    // - Processing: Refresh button coloring based on table properties; both remain uncolored when customizing column layout.
    // - Returns: Nothing.
    void updateColumnPresetButtons(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB)
    {
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr)
        {
            return;
        }

        const QString kPresetText = table->property("kswordColumnPreset").toString();
        // Button property usage: save the current selected state to avoid re-capturing local lambda pointers during theme refresh.
        const bool kButtonASelected = kPresetText == QStringLiteral("A");
        const bool kButtonBSelected = kPresetText == QStringLiteral("B");
        buttonA->setProperty(kColumnPresetSelectedProperty, kButtonASelected);
        buttonB->setProperty(kColumnPresetSelectedProperty, kButtonBSelected);
        buttonA->setStyleSheet(buildColumnPresetButtonStyle(kButtonASelected));
        buttonB->setStyleSheet(buildColumnPresetButtonStyle(kButtonBSelected));
    }

    // applyColumnPresetToTable:
    // - Input table: target table, columnGroup: columns to display, presetText: A/B name;
    // - Handling: Toggle column visibility only; do not modify row model, sorting, or refresh state;
    // - Returns: Nothing.
    void applyColumnPresetToTable(
        QTableWidget* table,
        const QVector<int>& columnGroup,
        const QString& presetText,
        QPushButton* buttonA,
        QPushButton* buttonB)
    {
        if (table == nullptr)
        {
            return;
        }

        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            table->setColumnHidden(columnIndex, !containsColumnIndex(columnGroup, columnIndex));
        }
        table->setProperty("kswordColumnPreset", presetText);
        updateColumnPresetButtons(table, buttonA, buttonB);
    }

    // visibleColumnCount:
    // - Input table: Target table.
    // - Processing: Count visible columns to prevent hiding the last column via the right-click menu.
    // - Returns: Visible column count.
    int visibleColumnCount(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return 0;
        }

        int count = 0;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (!table->isColumnHidden(columnIndex))
            {
                ++count;
            }
        }
        return count;
    }

    // createColumnPresetButton:
    // - Inputs: parentWidget (parent widget), buttonText (A/B text), tooltipText (hover tooltip);
    // - Action: Create short buttons tightly aligned left and right;
    // - Return: QPushButton released by the Qt parent-child tree.
    QPushButton* createColumnPresetButton(
        QWidget* parentWidget,
        const QString& buttonText,
        const QString& tooltipText)
    {
        QPushButton* button = new QPushButton(buttonText, parentWidget);
        button->setToolTip(tooltipText);
        button->setCursor(Qt::PointingHandCursor);
        // This dynamic property identifier marks the A/B column preset buttons managed uniformly by the WindowDock theme refresh.
        button->setProperty(kColumnPresetSelectedProperty, false);
        button->setStyleSheet(buildColumnPresetButtonStyle(false));
        return button;
    }

    // installHeaderColumnMenu:
    // - Input table: target table, buttonA/buttonB: column group buttons;
    // - Processing: Install an explicit theme-style right-click menu on the header, allowing columns to be toggled for display individually.
    // - Return: None; after manually modifying columns, the state is set to Custom.
    void installHeaderColumnMenu(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB)
    {
        if (table == nullptr || table->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* headerView = table->horizontalHeader();
        headerView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(headerView, &QHeaderView::customContextMenuRequested, table, [table, headerView, buttonA, buttonB](const QPoint& localPosition)
        {
            QMenu menu(table);
            menu.setStyleSheet(tableCopyMenuStyle());
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* headerItem = table->horizontalHeaderItem(columnIndex);
                const QString kHeaderText = headerItem != nullptr
                    ? headerItem->text()
                    : QStringLiteral("Column %1").arg(columnIndex);
                QAction* columnAction = menu.addAction(kHeaderText);
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(columnIndex));
                columnAction->setData(columnIndex);
            }

            QAction* selectedAction = menu.exec(headerView->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            const int kColumnIndex = selectedAction->data().toInt();
            const bool kShouldShow = selectedAction->isChecked();
            if (!kShouldShow && visibleColumnCount(table) <= 1)
            {
                table->setColumnHidden(kColumnIndex, false);
                return;
            }

            table->setColumnHidden(kColumnIndex, !kShouldShow);
            table->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
            updateColumnPresetButtons(table, buttonA, buttonB);
        });
    }

    // installColumnPresetControls:
    // - Inputs: table (target table), buttonA/buttonB (column group buttons), groupA/groupB (two sets of trimmed columns);
    // - Processing: Bind A/B toggle and header column menu, applying Group A by default.
    // - Returns: Nothing.
    void installColumnPresetControls(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        const QVector<int>& groupA,
        const QVector<int>& groupB)
    {
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr)
        {
            return;
        }

        QObject::connect(buttonA, &QPushButton::clicked, table, [table, buttonA, buttonB, groupA]()
        {
            applyColumnPresetToTable(table, groupA, QStringLiteral("A"), buttonA, buttonB);
        });
        QObject::connect(buttonB, &QPushButton::clicked, table, [table, buttonA, buttonB, groupB]()
        {
            applyColumnPresetToTable(table, groupB, QStringLiteral("B"), buttonA, buttonB);
        });
        installHeaderColumnMenu(table, buttonA, buttonB);
        applyColumnPresetToTable(table, groupA, QStringLiteral("A"), buttonA, buttonB);
    }

    // wideArrayToQString:
    // - Convert the fixed wchar_t buffer from shared/driver to QString;
    // - Input bufferPointer: Fixed string start address; maxChars: Maximum character count;
    // - Return: Text after removing trailing NUL; display <empty> if null.
    QString wideArrayToQString(const wchar_t* const bufferPointer, const std::size_t maxChars)
    {
        if (bufferPointer == nullptr || maxChars == 0U)
        {
            return QStringLiteral("<empty>");
        }

        std::size_t textLength = 0U;
        while (textLength < maxChars && bufferPointer[textLength] != L'\0')
        {
            ++textLength;
        }

        if (textLength == 0U)
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromWCharArray(bufferPointer, static_cast<int>(textLength));
    }

    // appendIoSummary:
    // - append a unified IO/unsupported/readable explanation summary for each ArkDriverClient wrapper;
    // - Input text: output text, name: wrapper name, result: R0 wrapper result;
    // - Returns: Nothing; appends directly to `text`.
    template <typename TResult>
    void appendIoSummary(QString& text, const QString& name, const TResult& result)
    {
        text += QStringLiteral("%1:\n").arg(name);
        text += QStringLiteral("  io.ok: %1\n").arg(boolText(result.io.ok));
        text += QStringLiteral("  unsupported: %1\n").arg(boolText(result.unsupported));
        text += QStringLiteral("  status: %1\n").arg(result.status);
        text += QStringLiteral("  lastStatus: %1\n").arg(result.lastStatus);
        text += QStringLiteral("  returnedCount/totalCount: %1 / %2\n")
            .arg(result.returnedCount)
            .arg(result.totalCount);
        text += QStringLiteral("  entrySize: %1\n").arg(result.entrySize);
        text += QStringLiteral("  说明: %1\n")
            .arg(auditMessageText(name, result));
    }

    // appendKeyboardIoSummary:
    // - Append a human-readable diagnostic summary for legacy keyboard hotkey/hook wrappers.
    // - Input text: output text, name: wrapper name, result: Keyboard enum result;
    // - Returns: Nothing; appends directly to `text`.
    template <typename TResult>
    void appendKeyboardIoSummary(QString& text, const QString& name, const TResult& result)
    {
        text += QStringLiteral("%1:\n").arg(name);
        text += QStringLiteral("  io.ok: %1\n").arg(boolText(result.io.ok));
        text += QStringLiteral("  status: %1\n").arg(result.status);
        text += QStringLiteral("  lastStatus: %1\n").arg(result.lastStatus);
        text += QStringLiteral("  returnedCount/totalCount: %1 / %2\n")
            .arg(result.returnedCount)
            .arg(result.totalCount);
        text += QStringLiteral("  说明: %1\n")
            .arg(keyboardMessageText(name, result));
    }

    // appendWin32kProfileHeader:
    // - Displays win32k profile/module/capability readiness (excluding per-line session details; session lines are handled by the table).
    // - Input text: output text; result: return value of queryWin32kProfileStatus;
    // - Returns: Nothing.
    void appendWin32kProfileHeader(QString& text, const ksword::ark::Win32kProfileStatusResult& result)
    {
        appendIoSummary(text, QStringLiteral("queryWin32kProfileStatus"), result);
        text += QStringLiteral("  capabilityMask: %1\n").arg(formatUInt64Hex(result.capabilityMask));
        text += QStringLiteral("  missingCapabilityMask: %1\n").arg(formatUInt64Hex(result.missingCapabilityMask));
        text += QStringLiteral("  userGetSiloGlobals: %1\n").arg(formatUInt64Hex(result.userGetSiloGlobals));

        const auto kAppendModule = [&text](const QString& title, const KSWORD_ARK_WIN32K_MODULE_STATE& moduleState)
        {
            text += QStringLiteral("  %1.loaded/profile/base/size/name: %2 / %3 / %4 / %5 / %6\n")
                .arg(title)
                .arg(moduleState.loaded)
                .arg(moduleState.profileState)
                .arg(formatUInt64Hex(moduleState.imageBase))
                .arg(moduleState.imageSize)
                .arg(wideArrayToQString(moduleState.moduleName, KSWORD_ARK_WIN32K_MODULE_NAME_CHARS));
        };
        kAppendModule(QStringLiteral("win32k"), result.win32k);
        kAppendModule(QStringLiteral("win32kbase"), result.win32kbase);
        kAppendModule(QStringLiteral("win32kfull"), result.win32kfull);
    }

    // The following build*Rows functions: convert R0 structured entries into "row-by-row text", covering all rows without truncation.
    // - Construct QStringList in a background thread (without touching any controls), then dispatch to the UI thread to populate the table.

    QVector<QStringList> buildWindowsRows(const ksword::ark::Win32kWindowsResult& result)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_WINDOW_ENTRY& entry : result.entries)
        {
            rows.push_back(QStringList{
                formatUInt64Hex(entry.hwnd),
                QString::number(entry.processId),
                QString::number(entry.threadId),
                QString::number(entry.sessionId),
                wideArrayToQString(entry.title, KSWORD_ARK_WIN32K_TITLE_CHARS),
                wideArrayToQString(entry.className, KSWORD_ARK_WIN32K_CLASS_CHARS),
                formatUInt64Hex(entry.style),
                formatUInt64Hex(entry.exStyle),
                win32kRuntimeStatusText(entry.status),
                formatNtStatusText(entry.lastStatus),
                formatUInt64Hex(entry.parentHwnd),
                formatUInt64Hex(entry.ownerHwnd) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        // R3 fallback：
        // - Input: top-level HWND on the current interactive desktop;
        // - Handling: EnumWindows performs read-only enumeration; it does not read message content or install hooks.
        // - Output: Ensure the window audit table displays specific window evidence even if R0 has no tagWND rows.
        struct EnumContext
        {
            QVector<QStringList>* rows = nullptr;       // rows: Collection of output rows.
            const ksword::ark::Win32kWindowsResult* r0 = nullptr; // r0: Used to supplement R0 status.
            int limit = 512;                             // limit: Prevents unbounded expansion when the desktop is abnormal.
        };

        EnumContext context{ &rows, &result, 512 };
        ::EnumWindows(
            [](HWND windowHandle, LPARAM lParam) -> BOOL
            {
                EnumContext* contextPointer = reinterpret_cast<EnumContext*>(lParam);
                if (contextPointer == nullptr || contextPointer->rows == nullptr)
                {
                    return FALSE;
                }
                if (contextPointer->rows->size() >= contextPointer->limit)
                {
                    return FALSE;
                }

                DWORD processId = 0;
                const DWORD kThreadId = ::GetWindowThreadProcessId(windowHandle, &processId);
                DWORD sessionId = 0;
                ::ProcessIdToSessionId(processId, &sessionId);

                wchar_t titleBuffer[256] = {};
                wchar_t classBuffer[256] = {};
                ::GetWindowTextW(windowHandle, titleBuffer, static_cast<int>(_countof(titleBuffer)));
                ::GetClassNameW(windowHandle, classBuffer, static_cast<int>(_countof(classBuffer)));

                const LONG_PTR kStyleRaw = ::GetWindowLongPtrW(windowHandle, GWL_STYLE);
                const LONG_PTR kExStyleRaw = ::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE);
                const std::uint64_t kStyleValue = static_cast<std::uint64_t>(static_cast<ULONG_PTR>(kStyleRaw));
                const std::uint64_t kExStyleValue = static_cast<std::uint64_t>(static_cast<ULONG_PTR>(kExStyleRaw));
                contextPointer->rows->push_back(QStringList{
                    formatHwndText(windowHandle),
                    QString::number(processId),
                    QString::number(kThreadId),
                    QString::number(sessionId),
                    QString::fromWCharArray(titleBuffer).trimmed().isEmpty()
                        ? QStringLiteral("<无标题>")
                        : QString::fromWCharArray(titleBuffer).trimmed(),
                    QString::fromWCharArray(classBuffer).trimmed().isEmpty()
                        ? QStringLiteral("<无类名>")
                        : QString::fromWCharArray(classBuffer).trimmed(),
                    formatUInt64Hex(kStyleValue),
                    formatUInt64Hex(kExStyleValue),
                    QStringLiteral("R3"),
                    formatNtStatusText(contextPointer->r0 != nullptr ? contextPointer->r0->lastStatus : 0),
                    formatHwndText(::GetParent(windowHandle)),
                    formatHwndText(::GetWindow(windowHandle, GW_OWNER)) });
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&context));

        if (rows.isEmpty())
        {
            rows.push_back(QStringList{
                QStringLiteral("<无窗口行>"), QStringLiteral("N/A"), QStringLiteral("N/A"),
                QStringLiteral("N/A"), QStringLiteral("<empty>"), QStringLiteral("<empty>"),
                QStringLiteral("N/A"), QStringLiteral("N/A"), auditStateText(result),
                formatNtStatusText(result.lastStatus), QStringLiteral("N/A"), QStringLiteral("N/A") });
        }
        return rows;
    }

    QVector<QStringList> buildGuiThreadRows(const ksword::ark::Win32kGuiThreadsResult& result)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY& entry : result.entries)
        {
            rows.push_back(QStringList{
                QString::number(entry.threadId),
                QString::number(entry.processId),
                QString::number(entry.sessionId),
                QString::number(entry.queueStatus),
                formatUInt64Hex(entry.activeHwnd),
                formatUInt64Hex(entry.focusHwnd),
                formatUInt64Hex(entry.captureHwnd),
                formatUInt64Hex(entry.caretHwnd),
                win32kRuntimeStatusText(entry.status),
                formatNtStatusText(entry.lastStatus) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        // R3 fallback：
        // - Input: Thread owning the top-level window;
        // - Processing: Call GetGUIThreadInfo by unique TID; still write diagnostic line on failure.
        // - Output: GUI thread table displays actual TID/PID/session, not blank.
        struct ThreadContext
        {
            QVector<QStringList>* rows = nullptr;       // rows: Collection of output rows.
            QVector<DWORD> knownThreads;                // knownThreads: Deduplication using TID.
            const ksword::ark::Win32kGuiThreadsResult* r0 = nullptr; // r0: R0 status.
            int limit = 512;                             // limit: Maximum number of thread lines.
        };

        ThreadContext context{ &rows, {}, &result, 512 };
        ::EnumWindows(
            [](HWND windowHandle, LPARAM lParam) -> BOOL
            {
                ThreadContext* contextPointer = reinterpret_cast<ThreadContext*>(lParam);
                if (contextPointer == nullptr || contextPointer->rows == nullptr)
                {
                    return FALSE;
                }
                if (contextPointer->rows->size() >= contextPointer->limit)
                {
                    return FALSE;
                }

                DWORD processId = 0;
                const DWORD kThreadId = ::GetWindowThreadProcessId(windowHandle, &processId);
                if (kThreadId == 0 ||
                    std::find(contextPointer->knownThreads.begin(), contextPointer->knownThreads.end(), kThreadId) != contextPointer->knownThreads.end())
                {
                    return TRUE;
                }
                contextPointer->knownThreads.push_back(kThreadId);

                DWORD sessionId = 0;
                ::ProcessIdToSessionId(processId, &sessionId);
                GUITHREADINFO guiThreadInfo{};
                guiThreadInfo.cbSize = sizeof(guiThreadInfo);
                const bool kGuiReady = ::GetGUIThreadInfo(kThreadId, &guiThreadInfo) != FALSE;
                const DWORD kLastError = kGuiReady ? 0UL : ::GetLastError();
                contextPointer->rows->push_back(QStringList{
                    QString::number(kThreadId),
                    QString::number(processId),
                    QString::number(sessionId),
                    kGuiReady ? formatUInt64Hex(guiThreadInfo.flags) : QStringLiteral("N/A"),
                    kGuiReady ? formatHwndText(guiThreadInfo.hwndActive) : QStringLiteral("N/A"),
                    kGuiReady ? formatHwndText(guiThreadInfo.hwndFocus) : QStringLiteral("N/A"),
                    kGuiReady ? formatHwndText(guiThreadInfo.hwndCapture) : QStringLiteral("N/A"),
                    kGuiReady ? formatHwndText(guiThreadInfo.hwndCaret) : QStringLiteral("N/A"),
                    kGuiReady ? QStringLiteral("R3") : QStringLiteral("R3_FAIL"),
                    QStringLiteral("Win32=%1").arg(kLastError) });
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&context));

        if (rows.isEmpty())
        {
            rows.push_back(QStringList{
                QStringLiteral("<无GUI线程行>"), QStringLiteral("N/A"), QStringLiteral("N/A"),
                QStringLiteral("N/A"), QStringLiteral("N/A"), QStringLiteral("N/A"),
                QStringLiteral("N/A"), QStringLiteral("N/A"), auditStateText(result),
                formatNtStatusText(result.lastStatus) });
        }
        return rows;
    }

    QVector<QStringList> buildSessionRows(const ksword::ark::Win32kProfileStatusResult& result)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_SESSION_ENTRY& entry : result.entries)
        {
            rows.push_back(QStringList{
                QString::number(entry.sessionId),
                win32kRuntimeStatusText(entry.status),
                QString::number(entry.processCount),
                QString::number(entry.guiThreadCount),
                formatUInt64Hex(entry.capabilityMask) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        // R3 fallback：
        // - Input: Top-level window of the current desktop;
        // - Processing: Count unique PIDs/TIDs to provide local context for the session readiness table.
        // - Output: Root cause diagnosis row to prevent table blankness when R0 session entries are empty.
        struct SessionContext
        {
            QVector<DWORD> processIds; // processIds: Deduplicated set of processes belonging to the window.
            QVector<DWORD> threadIds;  // threadIds: deduplicated set of threads owning the window.
        };
        SessionContext context;
        ::EnumWindows(
            [](HWND windowHandle, LPARAM lParam) -> BOOL
            {
                SessionContext* contextPointer = reinterpret_cast<SessionContext*>(lParam);
                if (contextPointer == nullptr)
                {
                    return FALSE;
                }

                DWORD processId = 0;
                const DWORD kThreadId = ::GetWindowThreadProcessId(windowHandle, &processId);
                if (processId != 0 &&
                    std::find(contextPointer->processIds.begin(), contextPointer->processIds.end(), processId) == contextPointer->processIds.end())
                {
                    contextPointer->processIds.push_back(processId);
                }
                if (kThreadId != 0 &&
                    std::find(contextPointer->threadIds.begin(), contextPointer->threadIds.end(), kThreadId) == contextPointer->threadIds.end())
                {
                    contextPointer->threadIds.push_back(kThreadId);
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&context));

        DWORD currentSessionId = 0;
        ::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId);
        rows.push_back(QStringList{
            QString::number(currentSessionId),
            auditStateText(result),
            QString::number(context.processIds.size()),
            QString::number(context.threadIds.size()),
            formatUInt64Hex(result.capabilityMask) });
        return rows;
    }

    QVector<QStringList> buildHotkeyRows(
        const ksword::ark::Win32kHotkeysPdbResult& result,
        const ksword::ark::KeyboardHotkeyEnumResult* const fallbackResult)
    {
        QVector<QStringList> rows;
        QHash<std::uint32_t, HotkeyProcessDisplayInfo> processInfoCache;
        const auto kProcessInfoForPid = [&processInfoCache](const std::uint32_t processId) -> HotkeyProcessDisplayInfo
        {
            const auto kCachedInfo = processInfoCache.constFind(processId);
            if (kCachedInfo != processInfoCache.cend())
            {
                return kCachedInfo.value();
            }
            const HotkeyProcessDisplayInfo kDisplayInfo = queryHotkeyProcessDisplayInfo(processId);
            processInfoCache.insert(processId, kDisplayInfo);
            return kDisplayInfo;
        };

        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_HOTKEY_ENTRY& entry : result.entries)
        {
            const QString kDriverDetailText = readableDriverDetailText(
                wideArrayToQString(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS),
                QStringLiteral("热键快照未提供额外驱动说明"));
            const HotkeyProcessDisplayInfo kProcessInfo = kProcessInfoForPid(entry.processId);

            rows.push_back(QStringList{
                kProcessInfo.processName,
                processThreadDisplayText(entry.processId, entry.threadId),
                hotkeyDisplayText(entry.modifiers, entry.virtualKey),
                kProcessInfo.imagePath,
                kProcessInfo.description,
                formatUInt64Hex(entry.hotkeyObject),
                formatUInt64Hex(entry.hotkeyId),
                rawVirtualKeyText(entry.virtualKey),
                hotkeyModifierText(entry.modifiers),
                QString::number(entry.processId),
                QString::number(entry.threadId),
                QString::number(entry.sessionId),
                formatUInt64Hex(entry.hwnd),
                formatUInt64Hex(entry.nextHotkeyObject),
                formatUInt64Hex(entry.threadInfo),
                QString::number(entry.depth),
                keyboardSourceText(entry.source),
                win32kRuntimeStatusText(entry.status),
                formatNtStatusText(entry.lastStatus),
                QStringLiteral("flags=%1；tagWND=%2；desktop=%3；%4")
                    .arg(formatUInt64Hex(entry.flags))
                    .arg(formatUInt64Hex(entry.tagWnd))
                    .arg(formatUInt64Hex(entry.desktopObject))
                    .arg(kDriverDetailText) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        if (fallbackResult != nullptr && !fallbackResult->entries.empty())
        {
            rows.reserve(static_cast<int>(fallbackResult->entries.size()));
            for (const ksword::ark::KeyboardHotkeyEntry& entry : fallbackResult->entries)
            {
                const QString kDriverDetailText = readableDriverDetailText(
                    stdWideToQString(entry.detail),
                    QStringLiteral("键盘热键 fallback 未提供额外驱动说明"));
                const HotkeyProcessDisplayInfo kProcessInfo = kProcessInfoForPid(entry.processId);

                rows.push_back(QStringList{
                    kProcessInfo.processName,
                    processThreadDisplayText(entry.processId, entry.threadId),
                    hotkeyDisplayText(entry.modifiers, entry.virtualKey),
                    kProcessInfo.imagePath,
                    kProcessInfo.description,
                    formatUInt64Hex(entry.hotkeyObject),
                    formatUInt64Hex(entry.hotkeyId),
                    rawVirtualKeyText(entry.virtualKey),
                    hotkeyModifierText(entry.modifiers),
                    QString::number(entry.processId),
                    QString::number(entry.threadId),
                    QStringLiteral("N/A"),
                    formatUInt64Hex(entry.windowObject),
                    formatUInt64Hex(entry.nextHotkeyObject),
                    formatUInt64Hex(entry.threadInfo),
                    QString::number(entry.depth),
                    keyboardSourceText(entry.source),
                    QStringLiteral("KeyboardFallback(%1)").arg(entry.status),
                    formatNtStatusText(entry.lastStatus),
                    QStringLiteral("bucket=%1；threadObject=%2；flags=%3；%4；PDB=%5")
                        .arg(entry.bucketIndex)
                        .arg(formatUInt64Hex(entry.threadObject))
                        .arg(formatUInt64Hex(entry.flags))
                        .arg(kDriverDetailText)
                        .arg(auditMessageText(QStringLiteral("queryWin32kHotkeysPdb"), result)) });
            }
            return rows;
        }

        // Empty result diagnosis:
        // - The status column must display the true root cause from profile/fallback; do not incorrectly write 'ok' just because the IOCTL header succeeded;
        // - Retain complete wrapper descriptions in the detail column to facilitate determining whether the win32k profile is missing, the pattern failed to match, or the session is unavailable.
        const QString kPdbStateText = win32kEmptyStateText(result);
        const QString kFallbackStateText = fallbackResult != nullptr
            ? keyboardEmptyStateText(*fallbackResult)
            : QStringLiteral("keyboard-not-queried");
        const QString kEmptyDetailText = fallbackResult != nullptr
            ? QStringLiteral("PDB=%1；fallback=%2；解释：未枚举到结构化热键行不等于系统无热键，当前路径受 profile/字段映射或 keyboard fallback 模式匹配限制。")
                .arg(auditMessageText(QStringLiteral("queryWin32kHotkeysPdb"), result))
                .arg(keyboardMessageText(QStringLiteral("enumerateKeyboardHotkeys"), *fallbackResult))
            : QStringLiteral("PDB=%1；fallback 未执行；解释：未枚举到结构化热键行不等于系统无热键，当前路径受 profile/字段映射限制。")
                .arg(auditMessageText(QStringLiteral("queryWin32kHotkeysPdb"), result));
        QStringList emptyRow;
        emptyRow.reserve(kHotkeyColumnCount);
        for (int column = 0; column < kHotkeyColumnCount; ++column)
        {
            emptyRow.push_back(QStringLiteral("N/A"));
        }
        emptyRow[kHotkeyColumnName] = QStringLiteral("<无热键行>");
        emptyRow[kHotkeyColumnStatus] = QStringLiteral("%1 / %2").arg(kPdbStateText).arg(kFallbackStateText);
        emptyRow[kHotkeyColumnLastStatus] = formatNtStatusText(result.lastStatus);
        emptyRow[kHotkeyColumnDiagnostic] = kEmptyDetailText;
        rows.push_back(std::move(emptyRow));
        return rows;
    }

    QVector<QStringList> buildHookRows(
        const ksword::ark::Win32kHooksPdbResult& result,
        const ksword::ark::KeyboardHookEnumResult* const fallbackResult)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry : result.entries)
        {
            const QString kDriverDetailText = readableDriverDetailText(
                wideArrayToQString(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS),
                QStringLiteral("Hook快照未提供额外驱动说明"));
            const QString kModuleName = win32kAtomName(entry.moduleAtom);
            const QString kModuleAtomText = entry.moduleAtom == 0U
                ? QString()
                : QStringLiteral("%1 (%2)")
                    .arg(formatUInt64Hex(entry.moduleAtom), kModuleName);
            const QString kProcessPath = entry.processId == 0U
                ? QString()
                : QString::fromStdString(ks::process::queryProcessPathByPid(entry.processId));

            rows.push_back(QStringList{
                hookTypeText(entry.hookType),
                hookScopeText(entry.hookScope),
                QString::number(entry.processId),
                QString::number(entry.threadId),
                QString::number(entry.sessionId),
                entry.targetProcessId == 0U ? QString() : QString::number(entry.targetProcessId),
                entry.targetThreadId == 0U ? QString() : QString::number(entry.targetThreadId),
                entry.targetSessionId == 0U ? QString() : QString::number(entry.targetSessionId),
                formatUInt64Hex(entry.procedureAddress),
                formatUInt64Hex(entry.procedureOffset),
                QString::number(static_cast<std::int32_t>(entry.moduleId)),
                kModuleAtomText,
                kModuleName,
                kProcessPath,
                formatUInt64Hex(entry.hookHandle),
                formatUInt64Hex(entry.hookObject),
                formatUInt64Hex(entry.chainHead),
                formatUInt64Hex(entry.nextHookObject),
                formatUInt64Hex(entry.threadInfo),
                formatUInt64Hex(entry.targetThreadInfo),
                formatUInt64Hex(entry.desktopObject),
                messageHookFlagsText(entry.flags),
                keyboardSourceText(entry.source),
                win32kRuntimeStatusText(entry.status),
                formatNtStatusText(entry.lastStatus),
                QStringLiteral("fieldFlags=%1; moduleBase=%2; layout=%3; profileFull=%4/%5; currentFull=%6/%7; %8")
                    .arg(formatUInt64Hex(entry.fieldFlags))
                    .arg(formatUInt64Hex(entry.moduleBase))
                    .arg(messageHookLayoutSourceText(result.layout.source))
                    .arg(formatUInt64Hex(result.layout.timeDateStamp))
                    .arg(formatUInt64Hex(result.layout.imageSize))
                    .arg(formatUInt64Hex(result.win32kfullTimeDateStamp))
                    .arg(formatUInt64Hex(result.win32kfullImageSize))
                    .arg(kDriverDetailText) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        if (fallbackResult != nullptr && !fallbackResult->entries.empty())
        {
            rows.reserve(static_cast<int>(fallbackResult->entries.size()));
            for (const ksword::ark::KeyboardHookEntry& entry : fallbackResult->entries)
            {
                const QString kDriverDetailText = readableDriverDetailText(
                    stdWideToQString(entry.detail),
                    QStringLiteral("键盘 Hook fallback 未提供额外驱动说明"));
                const QString kProcessPath = entry.processId == 0U
                    ? QString()
                    : QString::fromStdString(ks::process::queryProcessPathByPid(entry.processId));

                rows.push_back(QStringList{
                    hookTypeText(entry.hookType),
                    hookScopeText(entry.hookScope),
                    QString::number(entry.processId),
                    QString::number(entry.threadId),
                    QStringLiteral("N/A"),
                    QStringLiteral("N/A"),
                    QStringLiteral("N/A"),
                    QStringLiteral("N/A"),
                    formatUInt64Hex(entry.procedureAddress),
                    formatUInt64Hex(entry.procedureOffset),
                    QString::number(static_cast<std::int32_t>(entry.moduleId)),
                    QStringLiteral("N/A"),
                    QStringLiteral("N/A"),
                    kProcessPath,
                    QStringLiteral("N/A"),
                    formatUInt64Hex(entry.hookObject),
                    formatUInt64Hex(entry.chainHead),
                    formatUInt64Hex(entry.nextHookObject),
                    formatUInt64Hex(entry.threadInfo),
                    formatUInt64Hex(entry.targetThreadInfo),
                    formatUInt64Hex(entry.desktopInfo),
                    messageHookFlagsText(entry.flags),
                    keyboardSourceText(entry.source),
                    QStringLiteral("KeyboardFallback(%1)").arg(entry.status),
                    formatNtStatusText(entry.lastStatus),
                    QStringLiteral("moduleId=%1；procedureOffset=%2；flags=%3；%4；PDB=%5")
                        .arg(entry.moduleId)
                        .arg(formatUInt64Hex(entry.procedureOffset))
                        .arg(formatUInt64Hex(entry.flags))
                        .arg(kDriverDetailText)
                        .arg(auditMessageText(QStringLiteral("queryWin32kHooksPdb"), result)) });
            }
            return rows;
        }

        // Empty result diagnosis:
        // - Hook chain enumeration depends on the win32k profile or an old keyboard fallback; if either is restricted, state this explicitly in the status column.
        // - This prevents users from seeing misleading combinations like 'ok + 0 rows' when copying the table.
        const QString kPdbStateText = win32kEmptyStateText(result);
        const QString kFallbackStateText = fallbackResult != nullptr
            ? keyboardEmptyStateText(*fallbackResult)
            : QStringLiteral("keyboard-not-queried");
        const QString kEmptyDetailText = fallbackResult != nullptr
            ? QStringLiteral("PDB=%1；fallback=%2；解释：未枚举到结构化 Hook 行不等于系统无 Hook，当前路径受 profile/字段映射、Session 或 fallback 模式匹配限制。")
                .arg(auditMessageText(QStringLiteral("queryWin32kHooksPdb"), result))
                .arg(keyboardMessageText(QStringLiteral("enumerateKeyboardHooks"), *fallbackResult))
            : QStringLiteral("PDB=%1；fallback 未执行；解释：未枚举到结构化 Hook 行不等于系统无 Hook，当前路径受 profile/字段映射限制。")
                .arg(auditMessageText(QStringLiteral("queryWin32kHooksPdb"), result));
        QStringList emptyRow;
        for (int column = 0; column < 26; ++column)
        {
            emptyRow << QStringLiteral("N/A");
        }
        emptyRow[0] = QStringLiteral("<无消息Hook行>");
        emptyRow[23] = QStringLiteral("%1 / %2").arg(kPdbStateText).arg(kFallbackStateText);
        emptyRow[24] = formatNtStatusText(result.lastStatus);
        emptyRow[25] = kEmptyDetailText + QStringLiteral(" driver=") + stdWideToQString(result.detail);
        rows.push_back(emptyRow);
        return rows;
    }

    QVector<QStringList> buildDeviceRows(const ksword::ark::DeviceAuditResult& result)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : result.entries)
        {
            rows.push_back(QStringList{
                deviceAuditRowKindText(entry.rowKind),
                deviceAuditRoleText(entry.roleHint),
                deviceAuditStatusText(entry.status),
                formatUInt64Hex(entry.riskFlags),
                wideArrayToQString(entry.driverName, KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS),
                wideArrayToQString(entry.deviceName, KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS),
                formatUInt64Hex(entry.driverObjectAddress),
                formatUInt64Hex(entry.deviceObjectAddress),
                formatUInt64Hex(entry.attachedDeviceAddress),
                formatUInt64Hex(entry.nextDeviceObjectAddress),
                QString::number(entry.relationDepth),
                QString::number(entry.attachedDepth),
                QString::number(entry.confidence),
                formatUInt64Hex(entry.fieldFlags),
                formatNtStatusText(entry.lastStatus),
                wideArrayToQString(entry.serviceName, KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS),
                wideArrayToQString(entry.imagePath, KSWORD_ARK_DEVICE_AUDIT_IMAGE_PATH_CHARS) });
        }
        if (rows.isEmpty())
        {
            rows.push_back(QStringList{
                QStringLiteral("<无设备行>"),
                QStringLiteral("N/A"),
                auditStateText(result),
                formatUInt64Hex(result.responseFlags),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                formatNtStatusText(result.lastStatus),
                QStringLiteral("N/A"),
                QStringLiteral("N/A") });
        }
        return rows;
    }

    // queryUserObjectName:
    // - Read the name of the window station or desktop object.
    // - On failure, return '<Unknown>' to maintain a read-only stable state for the page.
    QString queryUserObjectName(HANDLE userObjectHandle)
    {
        if (userObjectHandle == nullptr)
        {
            return QStringLiteral("<未知>");
        }

        wchar_t buffer[256] = {};
        DWORD requiredSize = 0;
        if (::GetUserObjectInformationW(userObjectHandle, UOI_NAME, buffer, sizeof(buffer), &requiredSize) == FALSE)
        {
            return QStringLiteral("<未知>");
        }
        return QString::fromWCharArray(buffer).trimmed().isEmpty()
            ? QStringLiteral("<未知>")
            : QString::fromWCharArray(buffer).trimmed();
    }

    // countTopLevelWindows:
    // - Count the total number of top-level windows on the desktop.
    // - Read-only audit page used for coarse-grained cross-view metrics of the window tree.
    int countTopLevelWindows()
    {
        int windowCount = 0;
        ::EnumWindows(
            [](HWND, LPARAM lParam) -> BOOL
            {
                int* countPointer = reinterpret_cast<int*>(lParam);
                if (countPointer != nullptr)
                {
                    ++(*countPointer);
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&windowCount));
        return windowCount;
    }

    // countCurrentProcessTopLevelWindows:
    // - Count the number of top-level windows owned by the current process.
    // - Summary of the current process perspective for the window tree/session cross-view.
    int countCurrentProcessTopLevelWindows()
    {
        int windowCount = 0;
        ::EnumWindows(
            [](HWND windowHandle, LPARAM lParam) -> BOOL
            {
                DWORD processId = 0;
                ::GetWindowThreadProcessId(windowHandle, &processId);
                if (processId == ::GetCurrentProcessId())
                {
                    int* countPointer = reinterpret_cast<int*>(lParam);
                    if (countPointer != nullptr)
                    {
                        ++(*countPointer);
                    }
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&windowCount));
        return windowCount;
    }

    // populateTable:
    // - Write the row model to QTableWidget with read-only cells and preserve the sort toggle;
    // - Input table: target table, rows: column text for each row;
    // - Returns: Nothing.
    void populateTable(QTableWidget* table, const QVector<QStringList>& rows)
    {
        if (table == nullptr)
        {
            return;
        }
        const bool kWasSorting = table->isSortingEnabled();
        const bool kUsesTransparentBackground =
            table->property("ksword_transparent_audit_table").toBool();
        table->setSortingEnabled(false);
        table->setVisible(true);
        table->clearContents();
        applyAuditTablePalette(table);
        table->setRowCount(rows.size());
        bool hasProcessIconColumn = false;
        bool hasProcessPathColumn = false;
        const int kProcessIconColumn = table->property("kswordProcessIconColumn").toInt(&hasProcessIconColumn);
        const int kProcessPathColumn = table->property("kswordProcessPathColumn").toInt(&hasProcessPathColumn);
        static QFileIconProvider fileIconProvider;
        static QHash<QString, QIcon> processIconCache;
        for (int rowIndex = 0; rowIndex < rows.size(); ++rowIndex)
        {
            const QStringList& columns = rows.at(rowIndex);
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QString kCellText = columnIndex < columns.size() ? columns.at(columnIndex) : QString();
                QTableWidgetItem* item = new QTableWidgetItem(kCellText);
                item->setFlags(item->flags() & ~Qt::ItemIsEditable);
                item->setToolTip(kCellText);
                // Cell foreground/background:
                // - Transparent audit tables do not write to the item background brush, allowing each cell to penetrate to the parent Tab page;
                // - Other audit tables retain alternating row backgrounds to ensure row readability on independent pages;
                // - item is still managed by QTableWidget for its lifetime
                item->setForeground(QBrush(ksword_theme::textPrimaryColor()));
                if (!kUsesTransparentBackground)
                {
                    item->setBackground(QBrush(
                        (rowIndex % 2) == 0
                        ? ksword_theme::surfaceColor()
                        : ksword_theme::surfaceAltColor()));
                }
                if (hasProcessIconColumn &&
                    hasProcessPathColumn &&
                    columnIndex == kProcessIconColumn &&
                    kProcessPathColumn >= 0 &&
                    kProcessPathColumn < columns.size() &&
                    !kCellText.startsWith(QChar('<')) &&
                    kCellText != QStringLiteral("N/A"))
                {
                    const QString kImagePath = columns.at(kProcessPathColumn).trimmed();
                    const QString kCacheKey = QDir::fromNativeSeparators(kImagePath).toLower();
                    QIcon processIcon = processIconCache.value(kCacheKey);
                    if (processIcon.isNull() && QFileInfo::exists(kImagePath))
                    {
                        processIcon = fileIconProvider.icon(QFileInfo(kImagePath));
                    }
                    if (processIcon.isNull())
                    {
                        processIcon = QIcon(QStringLiteral(":/Icon/process_main.svg"));
                    }
                    processIconCache.insert(kCacheKey, processIcon);
                    item->setIcon(processIcon);
                }
                table->setItem(rowIndex, columnIndex, item);
            }
        }
        table->setSortingEnabled(kWasSorting);
        table->resizeRowsToContents();
        if (table->viewport() != nullptr)
        {
            table->viewport()->update();
        }
    }

    // buildPendingRows:
    // - Generate a placeholder diagnostic row for the table being refreshed;
    // - Input table: target table for reading column count; primaryText: first column status; detailText: last column description;
    // - Returns: A QStringList row with column count matching the table, ready for immediate display by populateTable.
    QVector<QStringList> buildPendingRows(
        QTableWidget* table,
        const QString& primaryText,
        const QString& detailText)
    {
        const int kColumnCount = table != nullptr ? table->columnCount() : 0;
        if (kColumnCount <= 0)
        {
            return {};
        }

        QStringList row;
        row.reserve(kColumnCount);
        for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
        {
            row.push_back(QStringLiteral("N/A"));
        }

        row[0] = primaryText;
        row[kColumnCount - 1] = detailText;
        return QVector<QStringList>{ row };
    }

    // ensureNonEmptyAuditRows:
    // - Input table: target table; rows: row model to be written; primaryText/detailText: fallback diagnostics.
    // - Processing: When the background/local enumeration unexpectedly produces an empty row model, append a row with readable diagnostics;
    // - Return: None. Directly updates `rows` to ensure the critical audit table is never displayed in an empty state (rowCount=0).
    void ensureNonEmptyAuditRows(
        QTableWidget* table,
        QVector<QStringList>& rows,
        const QString& primaryText,
        const QString& detailText)
    {
        if (!rows.isEmpty())
        {
            return;
        }

        QVector<QStringList> fallbackRows = buildPendingRows(table, primaryText, detailText);
        if (!fallbackRows.isEmpty())
        {
            rows = std::move(fallbackRows);
        }
    }
}

WindowDock::WindowDock(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    // Initial state:
    // - The window list page retains its original behavior via the embedded OtherDock.
    // - The R0/R3 audit page added in this file does not automatically collect data by default; it waits for the user to click 'Refresh Audit'.
    // - This prevents heavy audits such as hotkeys, hooks, and GPU from being repeatedly triggered when switching the window tab.
    const QString kManualRefreshText =
        QStringLiteral("审计页默认不自动刷新；窗口列表保留原有刷新行为；点击顶部“刷新审计”后采集本页 R0/R3 审计数据。");
    cachedSessionSummary_ = QStringLiteral("[win32k GUI/session]\n%1\n").arg(kManualRefreshText);
    cachedHotkeyHookSummary_ = QStringLiteral("[Hotkey / Hook]\n%1\n").arg(kManualRefreshText);
    cachedDisplaySummary_ = QStringLiteral("[GPU / Display / Watchdog]\n%1\n").arg(kManualRefreshText);
    cachedWindowsRows_ = buildPendingRows(windowsTable_, QStringLiteral("<等待刷新>"), kManualRefreshText);
    cachedGuiThreadRows_ = buildPendingRows(guiThreadsTable_, QStringLiteral("<等待刷新>"), kManualRefreshText);
    if (windowsTable_ != nullptr)
    {
        windowsTable_->setProperty("kswordSandboxPidColumn", 1);
        windowsTable_->setProperty("ksword_process_detail_pid_column", 1);
    }
    if (guiThreadsTable_ != nullptr)
    {
        guiThreadsTable_->setProperty("kswordSandboxPidColumn", 1);
        guiThreadsTable_->setProperty("ksword_process_detail_pid_column", 1);
    }
    cachedSessionRows_ = buildPendingRows(sessionTable_, QStringLiteral("<等待刷新>"), kManualRefreshText);
    cachedHotkeyRows_ = buildPendingRows(hotkeysTable_, QStringLiteral("<等待刷新>"), kManualRefreshText);
    cachedHookRows_ = buildPendingRows(hooksTable_, QStringLiteral("<等待刷新>"), kManualRefreshText);
    cachedClipboardRows_ = buildPendingRows(clipboardTable_, QStringLiteral("<等待刷新>"), kManualRefreshText);
    cachedDeviceRows_ = buildPendingRows(deviceTable_, QStringLiteral("<等待刷新>"), kManualRefreshText);
    applyAuditViews();
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(QStringLiteral("窗口列表可独立刷新；审计页等待手动刷新。"));
    }
}

WindowDock::~WindowDock()
{
}

void WindowDock::focusWindowsByPids(const QVector<quint32>& processIds)
{
    if (tabWidget_ != nullptr && windowManagementDock_ != nullptr)
    {
        tabWidget_->setCurrentWidget(windowManagementDock_);
        windowManagementDock_->focusProcessIds(processIds);
    }
}

void WindowDock::refreshThemeVisuals()
{
    // auditTables usage: Contains only WindowDock's own audit tables to avoid overwriting the table strategy of embedded OtherDock.
    const QVector<QTableWidget*> kAuditTables = {
        windowsTable_,
        guiThreadsTable_,
        sessionTable_,
        hotkeysTable_,
        hooksTable_,
        clipboardTable_,
        deviceTable_
    };

    for (QTableWidget* const kTable : kAuditTables)
    {
        if (kTable == nullptr)
        {
            continue;
        }

        // usesTransparentBackground purpose: preserves original background transparency semantics after theme refresh.
        const bool kUsesTransparentBackground =
            kTable->property("ksword_transparent_audit_table").toBool();
        kTable->setStyleSheet(
            kUsesTransparentBackground
                ? transparentAuditTableStyle()
                : auditTableStyle());
        applyAuditTablePalette(kTable);

        // Existing items retain the QBrush from creation; they must be updated item-by-item and cannot rely solely on the new palette.
        for (int rowIndex = 0; rowIndex < kTable->rowCount(); ++rowIndex)
        {
            for (int columnIndex = 0; columnIndex < kTable->columnCount(); ++columnIndex)
            {
                QTableWidgetItem* const kItem = kTable->item(rowIndex, columnIndex);
                if (kItem == nullptr)
                {
                    continue;
                }

                kItem->setForeground(QBrush(ksword_theme::textPrimaryColor()));
                kItem->setBackground(
                    kUsesTransparentBackground
                        ? QBrush()
                        : QBrush(
                            (rowIndex % 2) == 0
                                ? ksword_theme::surfaceColor()
                                : ksword_theme::surfaceAltColor()));
            }
        }
        if (kTable->viewport() != nullptr)
        {
            kTable->viewport()->update();
        }
        kTable->update();
    }

    // presetButtons usage: Refresh all A/B buttons identified by dynamic properties without changing their selection state.
    const QList<QPushButton*> kPresetButtons = findChildren<QPushButton*>();
    for (QPushButton* const kButton : kPresetButtons)
    {
        if (kButton == nullptr
            || !kButton->property(kColumnPresetSelectedProperty).isValid())
        {
            continue;
        }
        kButton->setStyleSheet(
            buildColumnPresetButtonStyle(
                kButton->property(kColumnPresetSelectedProperty).toBool()));
    }

    if (queryWindowDetailButton_ != nullptr)
    {
        queryWindowDetailButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    }
}

void WindowDock::showEvent(QShowEvent* showEventPointer)
{
    QWidget::showEvent(showEventPointer);
}

void WindowDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(6);

    toolBarWidget_ = new QWidget(this);
    toolBarLayout_ = new QVBoxLayout(toolBarWidget_);
    toolBarLayout_->setContentsMargins(0, 0, 0, 0);
    toolBarLayout_->setSpacing(4);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("窗口"), toolBarWidget_);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    headerLayout->addWidget(titleLabel, 0);

    statusLabel_ = new QLabel(QStringLiteral("正在准备窗口审计快照..."), toolBarWidget_);
    statusLabel_->setWordWrap(true);
    statusLabel_->setMinimumWidth(0);
    statusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    statusLabel_->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;")
        .arg(ksword_theme::textSecondaryHex()));
    headerLayout->addWidget(statusLabel_, 1);

    refreshButton_ = new QPushButton(QStringLiteral("刷新审计"), toolBarWidget_);
    refreshButton_->setToolTip(QStringLiteral("重新采集 Win32K、热键/钩子与 GPU/Display/Watchdog 只读审计数据"));
    headerLayout->addWidget(refreshButton_, 0);

    toolBarLayout_->addLayout(headerLayout);
    rootLayout_->addWidget(toolBarWidget_, 0);

    tabWidget_ = new QTabWidget(this);
    // The root pages of the window dock are uniformly arranged in a top horizontal layout, preserving all existing pages and the currentIndex state source.
    tabWidget_->setTabPosition(QTabWidget::North);
    rootLayout_->addWidget(tabWidget_, 1);

    // Configure a read-only structured table: sortable, row selection, content-adaptive column widths, and stretch the last column.
    const auto kConfigureTable = [](QTableWidget* table)
    {
        // Table visibility protection:
        // - When WindowDock is embedded in a Dock/transparent parent container, the default palette may be polluted by the parent's style.
        // - Explicitly set background, text, selection state, and minimum height to ensure readability and visibility when a row model is present.
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->setWordWrap(false);
        table->setTextElideMode(Qt::ElideRight);
        table->setMinimumHeight(120);
        table->setStyleSheet(auditTableStyle());
        applyAuditTablePalette(table);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        table->horizontalHeader()->setStretchLastSection(true);
        installTableCopyMenu(table);
    };

    // Create a 'title + table' group to allow stacking multiple tables on a single page.
    const auto kMakeTableGroup =
        [this, &kConfigureTable](
            const QString& title,
            const QStringList& headers,
            const QVector<int>& groupA,
            const QVector<int>& groupB,
            QTableWidget** tableOut) -> QWidget*
    {
        QWidget* group = new QWidget(tabWidget_);
        QVBoxLayout* groupLayout = new QVBoxLayout(group);
        groupLayout->setContentsMargins(0, 0, 0, 0);
        groupLayout->setSpacing(3);

        QLabel* groupTitle = new QLabel(title, group);
        groupTitle->setStyleSheet(
            QStringLiteral("font-size:13px;font-weight:600;color:%1;")
            .arg(ksword_theme::textSecondaryHex()));
        groupLayout->addWidget(groupTitle, 0);

        QHBoxLayout* presetLayout = new QHBoxLayout();
        presetLayout->setContentsMargins(0, 0, 0, 0);
        presetLayout->setSpacing(0);

        QPushButton* groupAButton = createColumnPresetButton(
            group,
            QStringLiteral("A"),
            QStringLiteral("显示 A 组精简列：偏向对象身份、状态和常用定位字段。"));
        QPushButton* groupBButton = createColumnPresetButton(
            group,
            QStringLiteral("B"),
            QStringLiteral("显示 B 组精简列：偏向地址、来源、flags、路径或诊断字段。"));
        presetLayout->addWidget(groupAButton, 0);
        presetLayout->addWidget(groupBButton, 0);
        presetLayout->addStretch(1);
        groupLayout->addLayout(presetLayout, 0);

        QTableWidget* table = new ks::ui::VisibleTableWidget(group);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        kConfigureTable(table);
        installColumnPresetControls(table, groupAButton, groupBButton, groupA, groupB);
        groupLayout->addWidget(table, 1);

        if (tableOut != nullptr)
        {
            *tableOut = table;
        }
        return group;
    };

    // Read-only summary editor: used solely for non-table contextual notes.
    // Now the summary and table are placed in an inner tab, with no maximum height limit, to prevent the text box from being squashed.
    const auto kMakeSummaryEditor = [this](QWidget* parentWidget) -> CodeEditorWidget*
    {
        CodeEditorWidget* editor = new CodeEditorWidget(parentWidget);
        editor->setReadOnly(true);
        editor->setMinimumHeight(180);
        return editor;
    };

    // Common page header: title + 'Read-only audit page' hint.
    const auto kMakePageHeader = [this](QWidget* pageWidget, QVBoxLayout* pageLayout, const QString& titleText)
    {
        QLabel* pageTitleLabel = new QLabel(titleText, pageWidget);
        pageTitleLabel->setStyleSheet(
            QStringLiteral("font-size:18px;font-weight:700;color:%1;")
            .arg(ksword_theme::textPrimaryHex()));
        pageLayout->addWidget(pageTitleLabel, 0);
    };

    // makeInnerTabWidget:
    // - Input parentWidget: Current outer audit page;
    // - Processing: Create a compact inner tab container, splitting each table/text box into independent tabs.
    // - Returns: A QTabWidget ready for addTab, preventing vertically stacked large widgets from shrinking until they are no longer visible.
    const auto kMakeInnerTabWidget = [](QWidget* parentWidget) -> QTabWidget*
    {
        QTabWidget* innerTabWidget = new QTabWidget(parentWidget);
        innerTabWidget->setTabPosition(QTabWidget::North);
        innerTabWidget->setDocumentMode(true);
        innerTabWidget->setUsesScrollButtons(true);
        return innerTabWidget;
    };

    // makeEditorTabPage:
    // - Input innerTabWidget: internal tab container;
    // - Processing: Create a page dedicated solely to a text editor, ensuring text details do not compete for height with tables.
    // - Returns: Text page QWidget; editorOut returns the pointer to the created editor.
    const auto kMakeEditorTabPage =
        [this, &kMakeSummaryEditor](QTabWidget* innerTabWidget, CodeEditorWidget** editorOut) -> QWidget*
    {
        QWidget* editorPage = new QWidget(innerTabWidget);
        QVBoxLayout* editorLayout = new QVBoxLayout(editorPage);
        editorLayout->setContentsMargins(4, 4, 4, 4);
        editorLayout->setSpacing(4);

        CodeEditorWidget* editor = kMakeSummaryEditor(editorPage);
        editorLayout->addWidget(editor, 1);
        if (editorOut != nullptr)
        {
            *editorOut = editor;
        }
        return editorPage;
    };

    // ===== Tab 1: Window Management (Embedded OtherDock, restores detailed view of window list / desktop) =====
    windowManagementDock_ = new OtherDock(tabWidget_);
    const int kWindowManagementTabIndex =
        tabWidget_->addTab(windowManagementDock_, QStringLiteral("窗口列表 / 桌面"));
    tabWidget_->setTabToolTip(
        kWindowManagementTabIndex,
        QStringLiteral("原窗口列表与桌面管理入口在这里：包含窗口树、窗口详情、窗口站/桌面枚举和桌面切换。"));

    const int kGuiHandleTabIndex = tabWidget_->addTab(
        new WindowGuiHandleTab(tabWidget_),
        QStringLiteral("GUI句柄"));
    tabWidget_->setTabToolTip(
        kGuiHandleTabIndex,
        QStringLiteral("只读枚举当前 Session 的 USER Handle 共享表，显示对象类型、地址与窗口所有者信息。"));

    const int kTimerTabIndex = tabWidget_->addTab(
        new WindowTimerTab(tabWidget_),
        ks::i18n::contextText(QStringLiteral("window.timer.tab"), QStringLiteral("窗口定时器")));
    tabWidget_->setTabToolTip(
        kTimerTabIndex,
        ks::i18n::contextText(
            QStringLiteral("window.timer.tab.tooltip"),
            QStringLiteral("只读遍历 win32k gTimerHashTable，显示定时器对象、间隔、Flags、回调和 PID/TID 归属。")));

    const int kGlobalHotkeyTabIndex = tabWidget_->addTab(
        new WindowGlobalHotkeyTab(tabWidget_),
        ks::i18n::contextText(QStringLiteral("window.global_hotkey.tab"), QStringLiteral("全部热键")));
    tabWidget_->setTabToolTip(
        kGlobalHotkeyTabIndex,
        ks::i18n::contextText(
            QStringLiteral("window.global_hotkey.tab.tooltip"),
            QStringLiteral("只读汇总全部进程的窗口热键、菜单快捷键、PE Accelerator 和快捷方式热键。")));

    const int kEventHookTabIndex = tabWidget_->addTab(
        new WindowEventHookTab(tabWidget_),
        ks::i18n::contextText(QStringLiteral("window.event_hook.tab"), QStringLiteral("事件 Hook")));
    tabWidget_->setTabToolTip(
        kEventHookTabIndex,
        ks::i18n::contextText(
            QStringLiteral("window.event_hook.tab.tooltip"),
            QStringLiteral("只读遍历 win32kbase!gpWinEventHooks，显示事件范围、Flags、回调和 PID/TID 归属。")));

    // ===== Tab 2：win32k GUI / Session =====
    sessionPage_ = new QWidget(tabWidget_);
    {
        QVBoxLayout* pageLayout = new QVBoxLayout(sessionPage_);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);
        kMakePageHeader(sessionPage_, pageLayout, QStringLiteral("win32k GUI / Session"));

        QTabWidget* innerTabWidget = kMakeInnerTabWidget(sessionPage_);
        pageLayout->addWidget(innerTabWidget, 1);

        innerTabWidget->addTab(
            kMakeEditorTabPage(innerTabWidget, &sessionSummaryEditor_),
            QStringLiteral("摘要"));

        innerTabWidget->addTab(kMakeTableGroup(
            QStringLiteral("Win32K 窗口（HWND / tagWND cross-view，全部行）"),
            QStringList{ QStringLiteral("HWND"), QStringLiteral("PID"), QStringLiteral("TID"),
                         QStringLiteral("Session"), QStringLiteral("标题"), QStringLiteral("类名"),
                         QStringLiteral("Style"), QStringLiteral("ExStyle"), QStringLiteral("状态"),
                         QStringLiteral("LastStatus"), QStringLiteral("父HWND"), QStringLiteral("所有者") },
            QVector<int>{ 0, 1, 2, 3, 4, 5, 8 },
            QVector<int>{ 0, 1, 6, 7, 9, 10, 11 },
            &windowsTable_),
            QStringLiteral("窗口表"));
        applyTransparentAuditTableBackground(windowsTable_);
        innerTabWidget->addTab(kMakeTableGroup(
            QStringLiteral("GUI 线程（tagQ / focus / capture / caret）"),
            QStringList{ QStringLiteral("TID"), QStringLiteral("PID"), QStringLiteral("Session"),
                         QStringLiteral("队列状态"), QStringLiteral("ActiveHWND"), QStringLiteral("FocusHWND"),
                         QStringLiteral("CaptureHWND"), QStringLiteral("CaretHWND"), QStringLiteral("状态"),
                         QStringLiteral("LastStatus") },
            QVector<int>{ 0, 1, 2, 3, 4, 5, 8 },
            QVector<int>{ 0, 1, 6, 7, 8, 9 },
            &guiThreadsTable_),
            QStringLiteral("GUI线程"));
        applyTransparentAuditTableBackground(guiThreadsTable_);
        innerTabWidget->addTab(kMakeTableGroup(
            QStringLiteral("Session 就绪状态"),
            QStringList{ QStringLiteral("SessionId"), QStringLiteral("状态"), QStringLiteral("进程数"),
                         QStringLiteral("GUI线程数"), QStringLiteral("Capability") },
            QVector<int>{ 0, 1, 2, 3 },
            QVector<int>{ 0, 1, 4 },
            &sessionTable_),
            QStringLiteral("Session"));
        applyTransparentAuditTableBackground(sessionTable_);

        // Current window details:
        // - By default, only visible columns of the window table snapshot are shown to help users confirm the currently selected HWND.
        // - Call the single HWND detail IOCTL only after a button click to avoid blocking each window during batch refresh.
        QWidget* detailPage = new QWidget(innerTabWidget);
        QVBoxLayout* detailPageLayout = new QVBoxLayout(detailPage);
        detailPageLayout->setContentsMargins(4, 4, 4, 4);
        detailPageLayout->setSpacing(6);
        QHBoxLayout* detailToolLayout = new QHBoxLayout();
        detailToolLayout->setContentsMargins(0, 0, 0, 0);
        detailToolLayout->setSpacing(6);
        queryWindowDetailButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_tree.svg")), QStringLiteral("查询选中窗口详情"), detailPage);
        queryWindowDetailButton_->setToolTip(QStringLiteral("只对当前选中 HWND 按需查询 win32k window detail，不批量扫描全部窗口"));
        queryWindowDetailButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        detailToolLayout->addWidget(queryWindowDetailButton_, 0);
        QLabel* detailHintLabel = new QLabel(QStringLiteral("详情区：先显示快照，按需补充单 HWND runtime readiness/tagWND 诊断。"), detailPage);
        detailHintLabel->setStyleSheet(
            QStringLiteral("font-size:13px;color:%1;")
            .arg(ksword_theme::textSecondaryHex()));
        detailToolLayout->addWidget(detailHintLabel, 1);
        detailPageLayout->addLayout(detailToolLayout);

        windowDetailEditor_ = new CodeEditorWidget(detailPage);
        windowDetailEditor_->setReadOnly(true);
        windowDetailEditor_->setText(QStringLiteral("请选择 Win32K 窗口行查看快照；需要更深诊断时点击“查询选中窗口详情”。"));
        detailPageLayout->addWidget(windowDetailEditor_, 1);
        innerTabWidget->addTab(detailPage, QStringLiteral("窗口详情"));
    }
    tabWidget_->addTab(sessionPage_, QStringLiteral("GUI/Session"));

    // ===== Tab 3: Hotkeys / Hooks =====
    hotkeyHookPage_ = new QWidget(tabWidget_);
    {
        QVBoxLayout* pageLayout = new QVBoxLayout(hotkeyHookPage_);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);
        kMakePageHeader(hotkeyHookPage_, pageLayout, QStringLiteral("Hotkey / Hook"));

        QTabWidget* innerTabWidget = kMakeInnerTabWidget(hotkeyHookPage_);
        pageLayout->addWidget(innerTabWidget, 1);

        innerTabWidget->addTab(
            kMakeEditorTabPage(innerTabWidget, &hotkeyHookSummaryEditor_),
            QStringLiteral("摘要"));

        innerTabWidget->addTab(kMakeTableGroup(
            QStringLiteral("热键（只读审计，不删除热键）"),
            QStringList{ QStringLiteral("名称"), QStringLiteral("进程ID.线程ID"), QStringLiteral("热键"),
                         QStringLiteral("路径"), QStringLiteral("描述"), QStringLiteral("热键对象地址"),
                         QStringLiteral("热键ID"), QStringLiteral("VK"), QStringLiteral("修饰键"),
                         QStringLiteral("PID"), QStringLiteral("TID"), QStringLiteral("Session"),
                         QStringLiteral("HWND"),
                         QStringLiteral("NextHotkey"), QStringLiteral("ThreadInfo"),
                         QStringLiteral("Depth"), QStringLiteral("Source"),
                         QStringLiteral("状态"), QStringLiteral("LastStatus"),
                         QStringLiteral("诊断") },
            QVector<int>{ kHotkeyColumnName, kHotkeyColumnProcessThread, kHotkeyColumnDisplay,
                          kHotkeyColumnPath, kHotkeyColumnDescription, kHotkeyColumnObject, kHotkeyColumnId },
            QVector<int>{ kHotkeyColumnName, kHotkeyColumnVirtualKey, kHotkeyColumnModifiers,
                          kHotkeyColumnProcessId, kHotkeyColumnThreadId, kHotkeyColumnSession,
                          kHotkeyColumnHwnd, kHotkeyColumnNext, kHotkeyColumnThreadInfo,
                          kHotkeyColumnDepth, kHotkeyColumnSource, kHotkeyColumnStatus,
                          kHotkeyColumnLastStatus, kHotkeyColumnDiagnostic },
            &hotkeysTable_),
            QStringLiteral("热键表"));
        applyTransparentAuditTableBackground(hotkeysTable_);
        if (hotkeysTable_ != nullptr)
        {
            hotkeysTable_->setProperty("kswordProcessIconColumn", kHotkeyColumnName);
            hotkeysTable_->setProperty("kswordProcessPathColumn", kHotkeyColumnPath);
            hotkeysTable_->setProperty("ksword_process_detail_pid_column", kHotkeyColumnProcessId);
            hotkeysTable_->setIconSize(QSize(16, 16));
        }
        innerTabWidget->addTab(kMakeTableGroup(
            QStringLiteral("消息 Hook（只读审计，不 remove/unlink hook 链）"),
            QStringList{ QStringLiteral("类型"), QStringLiteral("范围"), QStringLiteral("所有者 PID"),
                         QStringLiteral("所有者 TID"), QStringLiteral("Session"), QStringLiteral("目标 PID"),
                         QStringLiteral("目标 TID"), QStringLiteral("目标 Session"), QStringLiteral("Procedure"),
                         QStringLiteral("ProcedureOffset"), QStringLiteral("ModuleId"), QStringLiteral("ModuleAtom"),
                         QStringLiteral("模块名"), QStringLiteral("进程路径"), QStringLiteral("HookHandle"),
                         QStringLiteral("HookObject"), QStringLiteral("ChainHead"), QStringLiteral("NextHook"),
                         QStringLiteral("OwnerThreadInfo"), QStringLiteral("TargetThreadInfo"),
                         QStringLiteral("Desktop"), QStringLiteral("Flags"), QStringLiteral("Source"),
                         QStringLiteral("状态"), QStringLiteral("LastStatus"), QStringLiteral("诊断") },
            QVector<int>{ 0, 1, 2, 3, 4, 5, 6, 8, 12, 14, 15, 23 },
            QVector<int>{ 0, 8, 9, 11, 13, 15, 16, 17, 18, 19, 21, 25 },
            &hooksTable_),
            QStringLiteral("消息 Hook 表"));
        applyTransparentAuditTableBackground(hooksTable_);
        if (hooksTable_ != nullptr)
        {
            hooksTable_->setProperty("ksword_process_detail_pid_column", 2);
        }
    }
    tabWidget_->addTab(hotkeyHookPage_, QStringLiteral("热键/钩子"));

    // ===== Tab 4: Clipboard / Message-Only =====
    clipboardPage_ = new QWidget(tabWidget_);
    {
        QVBoxLayout* pageLayout = new QVBoxLayout(clipboardPage_);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);
        kMakePageHeader(clipboardPage_, pageLayout, QStringLiteral("Clipboard / Message-Only"));

        QTabWidget* innerTabWidget = kMakeInnerTabWidget(clipboardPage_);
        pageLayout->addWidget(innerTabWidget, 1);

        QWidget* group = kMakeTableGroup(
            QStringLiteral("剪贴板上下文（只读，不做消息抓取）"),
            QStringList{ QStringLiteral("属性"), QStringLiteral("值") },
            QVector<int>{ 0, 1 },
            QVector<int>{ 0, 1 },
            &clipboardTable_);
        applyTransparentAuditTableBackground(clipboardTable_);
        innerTabWidget->addTab(group, QStringLiteral("剪贴板表"));
    }
    tabWidget_->addTab(clipboardPage_, QStringLiteral("剪贴板"));

    // ===== Tab 5：GPU / Display / Watchdog =====
    displayPage_ = new QWidget(tabWidget_);
    {
        QVBoxLayout* pageLayout = new QVBoxLayout(displayPage_);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);
        kMakePageHeader(displayPage_, pageLayout, QStringLiteral("GPU / Display / Watchdog"));

        QTabWidget* innerTabWidget = kMakeInnerTabWidget(displayPage_);
        pageLayout->addWidget(innerTabWidget, 1);

        innerTabWidget->addTab(
            kMakeEditorTabPage(innerTabWidget, &displaySummaryEditor_),
            QStringLiteral("摘要"));

        QWidget* group = kMakeTableGroup(
            QStringLiteral("设备审计（不禁用设备 / 不卸载驱动 / 不 detach stack，全部行）"),
            QStringList{ QStringLiteral("种类"), QStringLiteral("角色"), QStringLiteral("状态"),
                         QStringLiteral("风险"), QStringLiteral("驱动名"), QStringLiteral("设备名"),
                         QStringLiteral("DriverObject"), QStringLiteral("DeviceObject"),
                         QStringLiteral("AttachedDevice"), QStringLiteral("NextDevice"),
                         QStringLiteral("RelationDepth"), QStringLiteral("AttachedDepth"),
                         QStringLiteral("Confidence"), QStringLiteral("FieldFlags"),
                         QStringLiteral("LastStatus"), QStringLiteral("Service"),
                         QStringLiteral("ImagePath") },
            QVector<int>{ 0, 1, 2, 3, 4, 5, 10, 11 },
            QVector<int>{ 0, 2, 6, 7, 8, 9, 14, 16 },
            &deviceTable_);
        applyTransparentAuditTableBackground(deviceTable_);
        innerTabWidget->addTab(group, QStringLiteral("设备表"));
    }
    tabWidget_->addTab(displayPage_, QStringLiteral("显示"));
}

void WindowDock::initializeConnections()
{
    if (refreshButton_ != nullptr)
    {
        connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            requestAsyncRefresh();
        });
    }
    if (queryWindowDetailButton_ != nullptr)
    {
        connect(queryWindowDetailButton_, &QPushButton::clicked, this, [this]()
        {
            requestSelectedWindowRuntimeDetail();
        });
    }
    if (windowsTable_ != nullptr)
    {
        connect(windowsTable_, &QTableWidget::currentCellChanged, this, [this](int currentRow, int, int, int)
        {
            updateSelectedWindowSnapshotDetail(currentRow);
        });
    }
}

void WindowDock::setRefreshingPlaceholderRows()
{
    // These immediate rows only indicate that collection is in progress and do not replace the subsequent real R0/R3 rows.
    // Purpose: Prevent the GUI/Session and Hotkey/Hook pages from showing completely empty tables during background queries.
    // Handling: For windows/GUI threads/Sessions, first use local Win32 read-only enumeration to generate specific rows;
    //       for hotkeys/hooks, at least generate explicit diagnostic rows when no pure R3 secure enumeration path exists.
    const QString kPendingDetailText = QStringLiteral("正在收集窗口信息，请稍候...");

    ksword::ark::Win32kWindowsResult localWindowsResult;
    localWindowsResult.io.message = "R0 refresh is pending; showing local EnumWindows fallback rows.";

    ksword::ark::Win32kGuiThreadsResult localGuiThreadsResult;
    localGuiThreadsResult.io.message = "R0 refresh is pending; showing local GetGUIThreadInfo fallback rows.";

    ksword::ark::Win32kProfileStatusResult localProfileResult;
    localProfileResult.io.message = "R0 refresh is pending; showing local session fallback row.";

    ksword::ark::Win32kHotkeysPdbResult pendingHotkeyResult;
    pendingHotkeyResult.io.message = "R0 hotkey snapshot is still refreshing; no pure R3 system hotkey table is available.";

    ksword::ark::Win32kHooksPdbResult pendingHookResult;
    pendingHookResult.io.message = "R0 hook snapshot is still refreshing; no pure R3 global hook chain is available.";

    cachedSessionSummary_ =
        QStringLiteral("[win32k GUI/session]\n正在刷新结构化窗口、GUI线程和Session审计行...\n");
    cachedHotkeyHookSummary_ =
        QStringLiteral("[Hotkey / Hook]\n正在刷新热键与Hook只读审计行...\n");
    cachedDisplaySummary_ =
        QStringLiteral("[GPU / Display / Watchdog]\n正在刷新显示设备只读审计行...\n");

    cachedWindowsRows_ = buildWindowsRows(localWindowsResult);
    cachedGuiThreadRows_ = buildGuiThreadRows(localGuiThreadsResult);
    cachedSessionRows_ = buildSessionRows(localProfileResult);
    cachedHotkeyRows_ = buildHotkeyRows(pendingHotkeyResult, nullptr);
    cachedHookRows_ = buildHookRows(pendingHookResult, nullptr);
    cachedClipboardRows_ = buildPendingRows(
        clipboardTable_,
        QStringLiteral("<采集中>"),
        QStringLiteral("正在读取 UI 线程剪贴板快照。"));
    cachedDeviceRows_ = buildPendingRows(
        deviceTable_,
        QStringLiteral("<采集中>"),
        kPendingDetailText);

    applyAuditViews();
}

void WindowDock::requestAsyncRefresh()
{
    // A single window audit synchronously replaces seven associated tables; when any table's menu is open, the
    // placeholder cache and the seven-table commit during the startup phase must be deferred as a single atomic unit.
    const QPointer<WindowDock> kDeferredGuard(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-audit-refresh-start"),
        {
            windowsTable_,
            guiThreadsTable_,
            sessionTable_,
            hotkeysTable_,
            hooksTable_,
            clipboardTable_,
            deviceTable_
        },
        [kDeferredGuard]()
        {
            if (!kDeferredGuard.isNull())
            {
                kDeferredGuard->requestAsyncRefresh();
            }
        }))
    {
        return;
    }

    bool expectedFlag = false;
    if (!refreshing_.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(QStringLiteral("正在采集窗口审计快照..."));
    }
    setRefreshingPlaceholderRows();

    // UI thread snapshot:
    // - Input: Clipboard and screen objects safely accessible by the current Qt GUI thread;
    // - Processing: Copy to a plain value before starting the background thread.
    // - Returns: Snapshots consumed by the background thread, avoiding BlockingQueuedConnection stalls during construction or refresh.
    const QVector<QStringList> kClipboardSnapshot =
        clipboardSnapshotRows(QApplication::clipboard());

    QString primaryScreenName = QStringLiteral("<无>");
    QRect primaryScreenGeometry;
    double primaryScreenDpi = 0.0;
    const QScreen* primaryScreen = QGuiApplication::primaryScreen();
    if (primaryScreen != nullptr)
    {
        primaryScreenName = primaryScreen->name();
        primaryScreenGeometry = primaryScreen->geometry();
        primaryScreenDpi = primaryScreen->logicalDotsPerInch();
    }

    QPointer<WindowDock> safeThis(this);
    std::thread([safeThis, kClipboardSnapshot, primaryScreenName, primaryScreenGeometry, primaryScreenDpi]()
    {
        // reportRefreshFailure:
        // - Input failureText: exception or failure description captured by the background thread;
        // - Processing: Use queued connection to return to the UI thread for writing readable diagnostic lines.
        // - Returns: Nothing, but ensures m_refreshing is released to prevent the refresh button from becoming permanently unresponsive after a single exception.
        const auto kReportRefreshFailure = [safeThis](const QString& failureText)
        {
            if (safeThis.isNull())
            {
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, failureText]()
                {
                    const auto kCommitFailure = [safeThis, failureText]()
                    {
                    if (safeThis.isNull())
                    {
                        return;
                    }

                    const QString kSummaryText = QStringLiteral(
                        "[Window audit refresh]\n"
                        "后台刷新异常，已保留/写入诊断行，用户可再次点击刷新。\n"
                        "原因: %1\n").arg(failureText);

                    safeThis->cachedSessionSummary_ = kSummaryText;
                    safeThis->cachedHotkeyHookSummary_ = kSummaryText;
                    safeThis->cachedDisplaySummary_ = kSummaryText;
                    safeThis->cachedWindowsRows_ = buildPendingRows(
                        safeThis->windowsTable_,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->cachedGuiThreadRows_ = buildPendingRows(
                        safeThis->guiThreadsTable_,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->cachedSessionRows_ = buildPendingRows(
                        safeThis->sessionTable_,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->cachedHotkeyRows_ = buildPendingRows(
                        safeThis->hotkeysTable_,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->cachedHookRows_ = buildPendingRows(
                        safeThis->hooksTable_,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->cachedClipboardRows_ = buildPendingRows(
                        safeThis->clipboardTable_,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->cachedDeviceRows_ = buildPendingRows(
                        safeThis->deviceTable_,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->applyAuditViews();
                    KLogEvent failureEvent;
                    warn << failureEvent
                        << "[WindowDock] audit refresh failed, detail="
                        << failureText.toStdString()
                        << eol;
                    if (safeThis->statusLabel_ != nullptr)
                    {
                        safeThis->statusLabel_->setText(QStringLiteral(
                            "窗口审计刷新异常；详情已写入日志。"));
                    }
                    safeThis->refreshing_.store(false);
                    };

                    if (safeThis.isNull())
                    {
                        return;
                    }
                    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                        safeThis.data(),
                        QStringLiteral("window-audit-failure-apply"),
                        {
                            safeThis->windowsTable_,
                            safeThis->guiThreadsTable_,
                            safeThis->sessionTable_,
                            safeThis->hotkeysTable_,
                            safeThis->hooksTable_,
                            safeThis->clipboardTable_,
                            safeThis->deviceTable_
                        },
                        kCommitFailure))
                    {
                        return;
                    }
                    kCommitFailure();
                },
                Qt::QueuedConnection);

            if (!kInvokeOk && !safeThis.isNull())
            {
                safeThis->refreshing_.store(false);
            }
        };

        try
        {
            // ArkDriverClient read-only wrapper:
            // - Purpose: Uniformly access R0 PDB audit results via the R3 client.
            // - Processing: Collect data sequentially in a background thread to avoid blocking the UI.
            // - Return: Each result is for text/table display only; no write actions are triggered.
            const ksword::ark::DriverClient kArkDriverClient;
            const ksword::ark::Win32kProfileStatusResult kWin32kProfileResult =
                kArkDriverClient.queryWin32kProfileStatus();
            const ksword::ark::Win32kWindowsResult kWin32kWindowsResult =
                kArkDriverClient.queryWin32kWindows();
            const ksword::ark::Win32kGuiThreadsResult kWin32kGuiThreadsResult =
                kArkDriverClient.queryWin32kGuiThreads();
            const ksword::ark::Win32kHotkeysPdbResult kWin32kHotkeysResult =
                kArkDriverClient.queryWin32kHotkeysPdb();
            const ksword::ark::Win32kHooksPdbResult kWin32kHooksResult =
                kArkDriverClient.queryWin32kHooksPdb();
            ksword::ark::KeyboardHotkeyEnumResult keyboardHotkeysFallbackResult{};
            ksword::ark::KeyboardHookEnumResult keyboardHooksFallbackResult{};
            bool keyboardHotkeysFallbackQueried = false;
            bool keyboardHooksFallbackQueried = false;
            if (kWin32kHotkeysResult.entries.empty())
            {
                keyboardHotkeysFallbackQueried = true;
                keyboardHotkeysFallbackResult = kArkDriverClient.enumerateKeyboardHotkeys();
            }
            if (kWin32kHooksResult.entries.empty())
            {
                keyboardHooksFallbackQueried = true;
                keyboardHooksFallbackResult = kArkDriverClient.enumerateKeyboardHooks();
            }
            const ksword::ark::DeviceAuditResult kGpuAuditResult =
                kArkDriverClient.queryGpuDisplayWatchdogAudit();

            // Session page summary: Local session/window station/desktop + R0 profile/module overview (session details per line are passed to the table).
            QString sessionSummary;
            {
                GUITHREADINFO guiThreadInfo{};
                guiThreadInfo.cbSize = sizeof(guiThreadInfo);
                const bool kGuiInfoReady = ::GetGUIThreadInfo(::GetCurrentThreadId(), &guiThreadInfo) != FALSE;

                sessionSummary += QStringLiteral("[win32k GUI/session]\n");
                DWORD sessionId = 0;
                ::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId);
                sessionSummary += QStringLiteral("SessionId: %1\n").arg(sessionId);
                sessionSummary += QStringLiteral("LogicalProcessorCount: %1\n").arg(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
                sessionSummary += QStringLiteral("ForegroundWindow: %1\n").arg(formatHwndText(::GetForegroundWindow()));
                sessionSummary += QStringLiteral("ActiveWindow: %1\n").arg(formatHwndText(::GetActiveWindow()));
                sessionSummary += QStringLiteral("DesktopWindow: %1\n").arg(formatHwndText(::GetDesktopWindow()));
                sessionSummary += QStringLiteral("TopLevelWindowCount: %1\n").arg(countTopLevelWindows());
                sessionSummary += QStringLiteral("CurrentProcessTopLevelWindowCount: %1\n").arg(countCurrentProcessTopLevelWindows());
                sessionSummary += QStringLiteral("GUIThreadInfoReady: %1\n").arg(boolText(kGuiInfoReady));
                if (kGuiInfoReady)
                {
                    sessionSummary += QStringLiteral("Focus: %1\n").arg(formatHwndText(guiThreadInfo.hwndFocus));
                    sessionSummary += QStringLiteral("Capture: %1\n").arg(formatHwndText(guiThreadInfo.hwndCapture));
                    sessionSummary += QStringLiteral("Caret: %1\n").arg(formatHwndText(guiThreadInfo.hwndCaret));
                    sessionSummary += QStringLiteral("MenuOwner: %1\n").arg(formatHwndText(guiThreadInfo.hwndMenuOwner));
                }

                sessionSummary += QStringLiteral("\n[窗口站/桌面]\n");
                sessionSummary += QStringLiteral("当前窗口站: %1\n").arg(queryUserObjectName(::GetProcessWindowStation()));
                sessionSummary += QStringLiteral("当前桌面: %1\n").arg(queryUserObjectName(::GetThreadDesktop(::GetCurrentThreadId())));
                sessionSummary += QStringLiteral("说明: 详细窗口列表与桌面切换见“窗口管理”页；本页仅做只读审计，不做消息截获、不做输入抓取。\n");
                sessionSummary += QStringLiteral("Win32K private layout: %1\n")
                    .arg(win32kPrivateLayoutLimitationText());

                sessionSummary += QStringLiteral("\n[R0 Win32K PDB profile 概要]\n");
                appendWin32kProfileHeader(sessionSummary, kWin32kProfileResult);
                sessionSummary += QStringLiteral("\n");
                appendIoSummary(sessionSummary, QStringLiteral("queryWin32kWindows"), kWin32kWindowsResult);
                sessionSummary += QStringLiteral("\n");
                appendIoSummary(sessionSummary, QStringLiteral("queryWin32kGuiThreads"), kWin32kGuiThreadsResult);
            }

            // Hotkey/Hook page summary.
            QString hotkeyHookSummary =
                QStringLiteral("[Hotkey / Hook]\n")
                + QStringLiteral("系统级 Hook 链表：无官方通用枚举接口，R0 PDB 路径仅做只读链表快照。\n")
                + QStringLiteral("Hotkey: 只读审计，不删除热键；Hook: 只读审计，不 remove/unlink hook 链。\n")
                + QStringLiteral("风险标记: 不执行安装/卸载/截获。\n\n");
            appendIoSummary(hotkeyHookSummary, QStringLiteral("queryWin32kHotkeysPdb"), kWin32kHotkeysResult);
            if (keyboardHotkeysFallbackQueried)
            {
                hotkeyHookSummary += QStringLiteral("\n");
                appendKeyboardIoSummary(hotkeyHookSummary, QStringLiteral("enumerateKeyboardHotkeys fallback"), keyboardHotkeysFallbackResult);
            }
            hotkeyHookSummary += QStringLiteral("\n");
            appendIoSummary(hotkeyHookSummary, QStringLiteral("queryWin32kHooksPdb"), kWin32kHooksResult);
            if (keyboardHooksFallbackQueried)
            {
                hotkeyHookSummary += QStringLiteral("\n");
                appendKeyboardIoSummary(hotkeyHookSummary, QStringLiteral("enumerateKeyboardHooks fallback"), keyboardHooksFallbackResult);
            }

            // Clipboard page:
            // - Input: MIME summary rows pre-generated by the UI thread;
            // - Processing: The background thread forwards only plain QStringList; it no longer reads QApplication::clipboard.
            // - Output: Prevents the copied hotkey/Hook table from being mistakenly displayed as real audit content in ClipboardPreview.
            const QVector<QStringList> kClipboardRows = kClipboardSnapshot;

            // Display page summary.
            QString displaySummary;
            {
                displaySummary += QStringLiteral("[GPU / Display / Watchdog]\n");
                displaySummary += QStringLiteral("PrimaryScreen: %1\n").arg(primaryScreenName);
                displaySummary += QStringLiteral("ScreenGeometry: [%1,%2,%3,%4]\n")
                    .arg(primaryScreenGeometry.left()).arg(primaryScreenGeometry.top())
                    .arg(primaryScreenGeometry.width()).arg(primaryScreenGeometry.height());
                displaySummary += QStringLiteral("DPI: %1\n").arg(primaryScreenDpi);
                displaySummary += QStringLiteral("Watchdog: 仅记录显示状态，不做输入抓取。\n\n");
                appendIoSummary(displaySummary, QStringLiteral("queryGpuDisplayWatchdogAudit"), kGpuAuditResult);
                displaySummary += QStringLiteral("  profileFlags: %1\n").arg(formatUInt64Hex(kGpuAuditResult.profileFlags));
                displaySummary += QStringLiteral("  responseFlags: %1\n").arg(formatUInt64Hex(kGpuAuditResult.responseFlags));
                displaySummary += QStringLiteral("  target/driver/device count: %1 / %2 / %3\n")
                    .arg(kGpuAuditResult.targetCount).arg(kGpuAuditResult.driverCount).arg(kGpuAuditResult.deviceCount);
            }

            // Table row model is constructed in a background thread (pure data, no UI control access).
            const QVector<QStringList> kWindowsRows = buildWindowsRows(kWin32kWindowsResult);
            const QVector<QStringList> kGuiThreadRows = buildGuiThreadRows(kWin32kGuiThreadsResult);
            const QVector<QStringList> kSessionRows = buildSessionRows(kWin32kProfileResult);
            const QVector<QStringList> kHotkeyRows = buildHotkeyRows(
                kWin32kHotkeysResult,
                keyboardHotkeysFallbackQueried ? &keyboardHotkeysFallbackResult : nullptr);
            const QVector<QStringList> kHookRows = buildHookRows(
                kWin32kHooksResult,
                keyboardHooksFallbackQueried ? &keyboardHooksFallbackResult : nullptr);
            const QVector<QStringList> kDeviceRows = buildDeviceRows(kGpuAuditResult);

            if (safeThis.isNull())
            {
                return;
            }

            const bool kInvokeOk = QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, sessionSummary, hotkeyHookSummary, displaySummary,
                 kWindowsRows, kGuiThreadRows, kSessionRows, kHotkeyRows, kHookRows, kDeviceRows, kClipboardRows]()
                {
                    const auto kCommitSnapshot = [
                        safeThis,
                        sessionSummary,
                        hotkeyHookSummary,
                        displaySummary,
                        kWindowsRows,
                        kGuiThreadRows,
                        kSessionRows,
                        kHotkeyRows,
                        kHookRows,
                        kDeviceRows,
                        kClipboardRows]()
                    {
                    if (safeThis.isNull())
                    {
                        return;
                    }

                    safeThis->cachedSessionSummary_ = sessionSummary;
                    safeThis->cachedHotkeyHookSummary_ = hotkeyHookSummary;
                    safeThis->cachedDisplaySummary_ = displaySummary;
                    safeThis->cachedWindowsRows_ = kWindowsRows;
                    safeThis->cachedGuiThreadRows_ = kGuiThreadRows;
                    safeThis->cachedSessionRows_ = kSessionRows;
                    safeThis->cachedHotkeyRows_ = kHotkeyRows;
                    safeThis->cachedHookRows_ = kHookRows;
                    safeThis->cachedDeviceRows_ = kDeviceRows;
                    safeThis->cachedClipboardRows_ = kClipboardRows;
                    safeThis->applyAuditViews();
                    if (safeThis->statusLabel_ != nullptr)
                    {
                        safeThis->statusLabel_->setText(
                            QStringLiteral("最近刷新：%1")
                            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))));
                    }
                    safeThis->refreshing_.store(false);
                    };

                    if (safeThis.isNull())
                    {
                        return;
                    }
                    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                        safeThis.data(),
                        QStringLiteral("window-audit-seven-table-apply"),
                        {
                            safeThis->windowsTable_,
                            safeThis->guiThreadsTable_,
                            safeThis->sessionTable_,
                            safeThis->hotkeysTable_,
                            safeThis->hooksTable_,
                            safeThis->clipboardTable_,
                            safeThis->deviceTable_
                        },
                        kCommitSnapshot))
                    {
                        return;
                    }
                    kCommitSnapshot();
                },
                Qt::QueuedConnection);

            if (!kInvokeOk && !safeThis.isNull())
            {
                safeThis->refreshing_.store(false);
            }
        }
        catch (const std::exception& exceptionObject)
        {
            kReportRefreshFailure(QString::fromLocal8Bit(exceptionObject.what()));
        }
        catch (...)
        {
            kReportRefreshFailure(QStringLiteral("未知异常"));
        }
    }).detach();
}

void WindowDock::applyAuditViews()
{
    // Table empty hard protection:
    // - Input: cached rows generated by the background thread or refresh placeholder phase;
    // - Processing: For the critical audit page, even if an empty result is encountered due to an exception, supplement it with a single diagnostic row instead of an empty table with 0 rows;
    // - Return: None; subsequent populateTable writes to the table uniformly.
    ensureNonEmptyAuditRows(
        windowsTable_,
        cachedWindowsRows_,
        QStringLiteral("<无窗口行模型>"),
        QStringLiteral("窗口审计没有生成任何行；请重新刷新或检查 R0/R3 fallback 状态。"));
    ensureNonEmptyAuditRows(
        guiThreadsTable_,
        cachedGuiThreadRows_,
        QStringLiteral("<无GUI线程行模型>"),
        QStringLiteral("GUI 线程审计没有生成任何行；请重新刷新或检查 GetGUIThreadInfo/R0 状态。"));
    ensureNonEmptyAuditRows(
        sessionTable_,
        cachedSessionRows_,
        QStringLiteral("<无Session行模型>"),
        QStringLiteral("Session 审计没有生成任何行；请重新刷新或检查当前交互 Session。"));
    ensureNonEmptyAuditRows(
        hotkeysTable_,
        cachedHotkeyRows_,
        QStringLiteral("<无热键行模型>"),
        QStringLiteral("热键审计没有生成任何行；R0/PDB 与 keyboard fallback 均未返回可展示数据。"));
    ensureNonEmptyAuditRows(
        hooksTable_,
        cachedHookRows_,
        QStringLiteral("<无Hook行模型>"),
        QStringLiteral("Hook 审计没有生成任何行；R0/PDB 与 keyboard fallback 均未返回可展示数据。"));
    ensureNonEmptyAuditRows(
        clipboardTable_,
        cachedClipboardRows_,
        QStringLiteral("<无剪贴板行模型>"),
        QStringLiteral("剪贴板审计没有生成任何行；请重新刷新或检查当前 UI 会话剪贴板状态。"));
    ensureNonEmptyAuditRows(
        deviceTable_,
        cachedDeviceRows_,
        QStringLiteral("<无显示设备行模型>"),
        QStringLiteral("GPU/Display/Watchdog 审计没有生成任何行；请重新刷新或检查 R0 设备审计状态。"));

    if (sessionSummaryEditor_ != nullptr && !cachedSessionSummary_.isEmpty())
    {
        sessionSummaryEditor_->setText(cachedSessionSummary_);
    }
    if (hotkeyHookSummaryEditor_ != nullptr && !cachedHotkeyHookSummary_.isEmpty())
    {
        hotkeyHookSummaryEditor_->setText(cachedHotkeyHookSummary_);
    }
    if (displaySummaryEditor_ != nullptr && !cachedDisplaySummary_.isEmpty())
    {
        displaySummaryEditor_->setText(cachedDisplaySummary_);
    }

    populateTable(windowsTable_, cachedWindowsRows_);
    populateTable(guiThreadsTable_, cachedGuiThreadRows_);
    populateTable(sessionTable_, cachedSessionRows_);
    populateTable(hotkeysTable_, cachedHotkeyRows_);
    populateTable(hooksTable_, cachedHookRows_);
    populateTable(clipboardTable_, cachedClipboardRows_);
    populateTable(deviceTable_, cachedDeviceRows_);

    if (windowsTable_ != nullptr && windowsTable_->rowCount() > 0 && windowsTable_->currentRow() < 0)
    {
        windowsTable_->setCurrentCell(0, 0);
    }
    updateSelectedWindowSnapshotDetail(windowsTable_ != nullptr ? windowsTable_->currentRow() : -1);
}

void WindowDock::updateSelectedWindowSnapshotDetail(const int currentRow)
{
    // Selected window snapshot details:
    // - Input currentRow: current row of the window table;
    // - Handling: generate multi-line descriptions from visible columns without accessing the driver;
    // - Return: None; the detail area is for read-only display only.
    if (windowDetailEditor_ == nullptr)
    {
        return;
    }
    if (windowsTable_ == nullptr || currentRow < 0 || currentRow >= windowsTable_->rowCount())
    {
        windowDetailEditor_->setText(QStringLiteral("请选择 Win32K 窗口行查看快照；需要更深诊断时点击“查询选中窗口详情”。"));
        if (queryWindowDetailButton_ != nullptr)
        {
            queryWindowDetailButton_->setEnabled(false);
        }
        return;
    }

    const auto kCellText = [this, currentRow](const int columnIndex) -> QString
    {
        const QTableWidgetItem* item = windowsTable_->item(currentRow, columnIndex);
        return item != nullptr ? item->text() : QString();
    };

    const QString kHwndText = kCellText(0);
    const QString kProcessIdText = kCellText(1);
    const QString kThreadIdText = kCellText(2);
    const std::uint64_t kHwndValue = parseUInt64Text(kHwndText, 0U);
    QStringList lines;
    lines << QStringLiteral("[Win32K Window Snapshot]");
    lines << QStringLiteral("HWND / PID / TID / Session: %1 / %2 / %3 / %4")
        .arg(kHwndText)
        .arg(kProcessIdText)
        .arg(kThreadIdText)
        .arg(kCellText(3));
    lines << QStringLiteral("Title / Class: %1 / %2")
        .arg(kCellText(4).trimmed().isEmpty() ? QStringLiteral("<无标题>") : kCellText(4))
        .arg(kCellText(5).trimmed().isEmpty() ? QStringLiteral("<无类名>") : kCellText(5));
    lines << QStringLiteral("Style / ExStyle: %1 / %2")
        .arg(kCellText(6))
        .arg(kCellText(7));
    lines << QStringLiteral("Status / LastStatus: %1 / %2")
        .arg(kCellText(8))
        .arg(kCellText(9));
    lines << QStringLiteral("Parent / Owner: %1 / %2")
        .arg(kCellText(10))
        .arg(kCellText(11));
    lines << QStringLiteral("SnapshotDetail: GUI/Session 窗口表仅保留可见字段；tagWND/profile/capability 详情请使用下方按需查询。");
    lines << QString();
    lines << QStringLiteral("提示：批量刷新不会逐 HWND 查询 detail；如需查看 tagWND readiness/能力缺口，请点击“查询选中窗口详情”。");
    windowDetailEditor_->setText(lines.join(QChar('\n')));

    if (queryWindowDetailButton_ != nullptr)
    {
        queryWindowDetailButton_->setEnabled(kHwndValue != 0U && !windowDetailRefreshing_.load());
    }
}

void WindowDock::requestSelectedWindowRuntimeDetail()
{
    // Single HWND runtime detail:
    // - Input from the selected row in the current window table;
    // - Processing: Background read-only calls to ArkDriverClient wrapper without blocking the UI thread.
    // - Return: None; results are written to the detail editor via a queued connection.
    if (windowsTable_ == nullptr || windowDetailEditor_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = windowsTable_->currentRow();
    if (kCurrentRow < 0 || kCurrentRow >= windowsTable_->rowCount())
    {
        windowDetailEditor_->setText(QStringLiteral("请先选择一条 Win32K 窗口行。"));
        return;
    }

    const auto kCellText = [this, kCurrentRow](const int columnIndex) -> QString
    {
        const QTableWidgetItem* item = windowsTable_->item(kCurrentRow, columnIndex);
        return item != nullptr ? item->text() : QString();
    };

    const std::uint64_t kHwndValue = parseUInt64Text(kCellText(0), 0U);
    const std::uint32_t kProcessId = parseUInt32Text(kCellText(1), 0U);
    const std::uint32_t kThreadId = parseUInt32Text(kCellText(2), 0U);
    if (kHwndValue == 0U)
    {
        windowDetailEditor_->setText(QStringLiteral("当前行没有有效 HWND，不能执行单窗口 detail 查询。"));
        return;
    }

    bool expectedRefreshing = false;
    if (!windowDetailRefreshing_.compare_exchange_strong(expectedRefreshing, true))
    {
        windowDetailEditor_->setText(QStringLiteral("当前已有单窗口 detail 查询正在进行，请稍候。"));
        return;
    }

    updateSelectedWindowSnapshotDetail(kCurrentRow);
    const QString kSnapshotText = windowDetailEditor_->text();
    if (queryWindowDetailButton_ != nullptr)
    {
        queryWindowDetailButton_->setEnabled(false);
    }
    windowDetailEditor_->setText(QStringLiteral("%1\n\n[Win32K Window Runtime Detail]\n正在后台按需查询 HWND=%2 ...")
        .arg(kSnapshotText)
        .arg(formatUInt64Hex(kHwndValue)));

    QPointer<WindowDock> safeThis(this);
    std::thread([safeThis, kHwndValue, kProcessId, kThreadId, kSnapshotText]()
    {
        const QString kRuntimeDetailText = QStringLiteral("%1\n\n%2")
            .arg(win32kWindowRuntimeDetailText(kHwndValue, kProcessId, kThreadId))
            .arg(win32kPublicPdbCatalogPreview());
        if (safeThis.isNull())
        {
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kSnapshotText, kRuntimeDetailText]()
            {
                if (safeThis.isNull())
                {
                    return;
                }
                safeThis->windowDetailRefreshing_.store(false);
                if (safeThis->queryWindowDetailButton_ != nullptr)
                {
                    safeThis->queryWindowDetailButton_->setEnabled(true);
                }
                if (safeThis->windowDetailEditor_ != nullptr)
                {
                    safeThis->windowDetailEditor_->setText(QStringLiteral("%1\n\n[Win32K Window Runtime Detail]\n%2")
                        .arg(kSnapshotText)
                        .arg(kRuntimeDetailText));
                }
            },
            Qt::QueuedConnection);

        if (!kInvokeOk && !safeThis.isNull())
        {
            safeThis->windowDetailRefreshing_.store(false);
        }
    }).detach();
}
