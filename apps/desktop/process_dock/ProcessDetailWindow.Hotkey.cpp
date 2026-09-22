#include "ProcessDetailWindow.InternalCommon.h"
#include "ProcessHotkeyEnumerator.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

#include <algorithm>
#include <atomic>
#include <limits>
#include <thread>

#include <QInputDialog>

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.Hotkey.cpp
// Purpose:
// - Responsible for the 'Process Hotkey' page UI, asynchronous scanning, and result backfilling.
// - Current implementation uses only stable R3 APIs/resource resolution; does not directly access KswordARK devices at the Dock layer.
// ============================================================

namespace
{
    constexpr int kHotkeyRowIndexRole = Qt::UserRole + 1;

    QString hotkeyUiText(const QString& key, const QString& fallback)
    {
        return ks::i18n::contextText(key, fallback);
    }

    struct HotkeyCandidate
    {
        QString objectText;
        std::uint32_t hotkeyId = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
        QString hotkeyText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString processName;
        QString sourceText;
        QString detailText;
        bool hasR0MutationSnapshot = false;
        KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY r0MutationSnapshot{};
    };

    struct KeyboardHookCandidate
    {
        QString objectText;
        QString typeText;
        QString scopeText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString procedureText;
        QString moduleText;
        QString sourceText;
        QString flagsText;
        QString detailText;
    };

    void appendDiagnostic(QString& diagnosticText, const QString& message)
    {
        const QString kTrimmedMessage = message.trimmed();
        if (kTrimmedMessage.isEmpty())
        {
            return;
        }

        if (!diagnosticText.trimmed().isEmpty())
        {
            diagnosticText += QStringLiteral(" | ");
        }
        diagnosticText += kTrimmedMessage;
    }

    QString keyboardIoMessageText(const std::string& messageText)
    {
        // Input: ArkDriverClient returned keyboard hotkey/hook io.message.
        // Note: Translate underlying DeviceIoControl, unsupported, and empty messages into UI-readable descriptions.
        // Returns: A Chinese short phrase for the process hotkey page diagnostic bar.
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString kRawText = QString::fromStdString(messageText).trimmed();
        if (kRawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持键盘热键/钩子审计入口");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供键盘热键/钩子审计入口");
        }
        return kRawText;
    }

    QString keyboardMutationFailureText(
        const ksword::ark::KeyboardHotkeyMutationResult& result)
    {
        if (!result.io.ok)
        {
            return QString::fromStdString(result.io.message);
        }
        switch (result.response.status)
        {
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_INVALID_REQUEST:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.invalid_request"), QStringLiteral("驱动拒绝了无效的热键变更请求。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CONFIRMATION_REQUIRED:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.confirmation_required"), QStringLiteral("驱动要求重新确认此高风险操作。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSUPPORTED_BUILD:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.unsupported_build"), QStringLiteral("当前 win32kfull.sys 身份或内部布局与已验证版本不一致，驱动已安全拒绝。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CALLER_CONTEXT_REQUIRED:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.caller_context"), QStringLiteral("必须从当前交互式桌面的 GUI 线程执行此操作。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.stale_snapshot"), QStringLiteral("热键对象或链表已变化，请刷新后重试。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSAFE_TARGET:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.unsafe_target"), QStringLiteral("目标不是可安全修改的普通独立热键项。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CONFLICT:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.conflict"), QStringLiteral("目标组合已由另一个 RegisterHotKey 项占用。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.operation_failed"), QStringLiteral("驱动写后验证失败；若已开始写入，已尝试回滚。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_SAFETY_DENIED:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.safety_denied"), QStringLiteral("统一安全策略未允许内核修改操作。"));
        default:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.unknown_failure"), QStringLiteral("驱动返回未知变更状态：%1。"))
                .arg(result.response.status);
        }
    }

    QString hex64Text(const std::uint64_t value)
    {
        if (value == 0U)
        {
            return QStringLiteral("0x0");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    QString pointerText(const void* value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(reinterpret_cast<std::uintptr_t>(value)), 0, 16)
            .toUpper();
    }

    QString normalizedFilePath(const QString& pathText)
    {
        const QString kTrimmedPath = pathText.trimmed();
        if (kTrimmedPath.isEmpty())
        {
            return QString();
        }

        const QFileInfo kFileInfo(kTrimmedPath);
        const QString kNormalizedPath = kFileInfo.exists()
            ? kFileInfo.canonicalFilePath()
            : kFileInfo.absoluteFilePath();
        return QDir::fromNativeSeparators(kNormalizedPath).toLower();
    }

    QString windowTitleText(HWND windowHandle)
    {
        const int kTitleLength = ::GetWindowTextLengthW(windowHandle);
        if (kTitleLength <= 0)
        {
            return QString();
        }

        std::vector<wchar_t> titleBuffer(static_cast<std::size_t>(kTitleLength) + 1U, L'\0');
        const int kCopiedLength = ::GetWindowTextW(
            windowHandle,
            titleBuffer.data(),
            static_cast<int>(titleBuffer.size()));
        if (kCopiedLength <= 0)
        {
            return QString();
        }
        return QString::fromWCharArray(titleBuffer.data(), kCopiedLength);
    }

    std::uint32_t hotkeyModifiersFromHotkeyf(const std::uint32_t hotkeyf)
    {
        std::uint32_t modifiers = 0;
        if ((hotkeyf & HOTKEYF_ALT) != 0U) modifiers |= MOD_ALT;
        if ((hotkeyf & HOTKEYF_CONTROL) != 0U) modifiers |= MOD_CONTROL;
        if ((hotkeyf & HOTKEYF_SHIFT) != 0U) modifiers |= MOD_SHIFT;
        return modifiers;
    }

    QString virtualKeyName(const std::uint32_t virtualKey)
    {
        if (virtualKey >= 'A' && virtualKey <= 'Z')
        {
            return QString(QChar(static_cast<ushort>(virtualKey)));
        }
        if (virtualKey >= '0' && virtualKey <= '9')
        {
            return QString(QChar(static_cast<ushort>(virtualKey)));
        }
        if (virtualKey >= VK_F1 && virtualKey <= VK_F24)
        {
            return QStringLiteral("F%1").arg(virtualKey - VK_F1 + 1U);
        }

        switch (virtualKey)
        {
        case VK_BACK: return QStringLiteral("Backspace");
        case VK_TAB: return QStringLiteral("Tab");
        case VK_RETURN: return QStringLiteral("Enter");
        case VK_ESCAPE: return QStringLiteral("Esc");
        case VK_SPACE: return QStringLiteral("Space");
        case VK_PRIOR: return QStringLiteral("PageUp");
        case VK_NEXT: return QStringLiteral("PageDown");
        case VK_END: return QStringLiteral("End");
        case VK_HOME: return QStringLiteral("Home");
        case VK_LEFT: return QStringLiteral("Left");
        case VK_UP: return QStringLiteral("Up");
        case VK_RIGHT: return QStringLiteral("Right");
        case VK_DOWN: return QStringLiteral("Down");
        case VK_INSERT: return QStringLiteral("Insert");
        case VK_DELETE: return QStringLiteral("Delete");
        case VK_SNAPSHOT: return QStringLiteral("PrintScreen");
        case VK_PAUSE: return QStringLiteral("Pause");
        case VK_APPS: return QStringLiteral("Apps");
        case VK_OEM_PLUS: return QStringLiteral("+");
        case VK_OEM_MINUS: return QStringLiteral("-");
        case VK_OEM_COMMA: return QStringLiteral(",");
        case VK_OEM_PERIOD: return QStringLiteral(".");
        default:
            break;
        }

        const UINT kScanCode = ::MapVirtualKeyW(virtualKey, MAPVK_VK_TO_VSC);
        if (kScanCode != 0U)
        {
            LONG keyNameParam = static_cast<LONG>(kScanCode << 16);
            switch (virtualKey)
            {
            case VK_INSERT:
            case VK_DELETE:
            case VK_HOME:
            case VK_END:
            case VK_PRIOR:
            case VK_NEXT:
            case VK_LEFT:
            case VK_RIGHT:
            case VK_UP:
            case VK_DOWN:
                keyNameParam |= (1L << 24);
                break;
            default:
                break;
            }

            wchar_t keyNameBuffer[64] = {};
            if (::GetKeyNameTextW(keyNameParam, keyNameBuffer, static_cast<int>(std::size(keyNameBuffer))) > 0)
            {
                return QString::fromWCharArray(keyNameBuffer);
            }
        }

        return QStringLiteral("VK_0x%1")
            .arg(static_cast<unsigned int>(virtualKey), 2, 16, QChar('0'))
            .toUpper();
    }

    QString hotkeyTextFromParts(
        const std::uint32_t modifiers,
        const std::uint32_t virtualKey,
        const QString& keyOverride = QString())
    {
        QStringList parts;
        if ((modifiers & MOD_CONTROL) != 0U) parts << QStringLiteral("Ctrl");
        if ((modifiers & MOD_SHIFT) != 0U) parts << QStringLiteral("Shift");
        if ((modifiers & MOD_ALT) != 0U) parts << QStringLiteral("Alt");
        if ((modifiers & MOD_WIN) != 0U) parts << QStringLiteral("Win");
        parts << (keyOverride.trimmed().isEmpty() ? virtualKeyName(virtualKey) : keyOverride.trimmed());
        return parts.join(QStringLiteral("+"));
    }

    std::uint32_t hotkeyfFromModifiers(const std::uint32_t modifiers)
    {
        std::uint32_t hotkeyf = 0;
        if ((modifiers & MOD_ALT) != 0U) hotkeyf |= HOTKEYF_ALT;
        if ((modifiers & MOD_CONTROL) != 0U) hotkeyf |= HOTKEYF_CONTROL;
        if ((modifiers & MOD_SHIFT) != 0U) hotkeyf |= HOTKEYF_SHIFT;
        return hotkeyf;
    }

    QString keyboardEnumStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND:
            return QStringLiteral("win32k not found");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND:
            return QStringLiteral("pattern not found");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE:
            return QStringLiteral("session unavailable");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("buffer truncated");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED:
            return QStringLiteral("read failed");
        default:
            return QStringLiteral("Unknown");
        }
    }

    QString keyboardHotkeySourceText(const std::uint32_t sourceValue)
    {
        switch (sourceValue)
        {
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE:
            return QStringLiteral("R0 RegisterHotKey");
        default:
            return QStringLiteral("R0 Unknown");
        }
    }

    QString keyboardHookSourceText(const std::uint32_t sourceValue)
    {
        switch (sourceValue)
        {
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_THREAD_HOOK_CHAIN:
            return QStringLiteral("R0 Thread Hook Chain");
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN:
            return QStringLiteral("R0 Global Hook Chain");
        default:
            return QStringLiteral("R0 Unknown Hook Chain");
        }
    }

    QString keyboardHookScopeText(const std::uint32_t scopeValue)
    {
        switch (scopeValue)
        {
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD:
            return QStringLiteral("线程");
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL:
            return QStringLiteral("全局/桌面");
        default:
            return QStringLiteral("未知");
        }
    }

    QString keyboardHookTypeText(const std::uint32_t typeValue)
    {
        switch (typeValue)
        {
        case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD:
            return QStringLiteral("WH_KEYBOARD");
        case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD_LL:
            return QStringLiteral("WH_KEYBOARD_LL");
        default:
            return QStringLiteral("WH_%1").arg(typeValue);
        }
    }

    bool parseHotkeyToken(const QString& tokenText, std::uint32_t& virtualKeyOut, QString& keyTextOut)
    {
        QString token = tokenText.trimmed();
        token.remove(QLatin1Char('&'));
        token = token.trimmed();
        if (token.isEmpty())
        {
            return false;
        }

        const QString kUpperToken = token.toUpper();
        if (kUpperToken.size() == 1)
        {
            const QChar kCh = kUpperToken.at(0);
            if ((kCh >= QLatin1Char('A') && kCh <= QLatin1Char('Z')) ||
                (kCh >= QLatin1Char('0') && kCh <= QLatin1Char('9')))
            {
                virtualKeyOut = static_cast<std::uint32_t>(kCh.unicode());
                keyTextOut = QString(kCh);
                return true;
            }
        }

        if (kUpperToken.size() >= 2 && kUpperToken.at(0) == QLatin1Char('F'))
        {
            bool ok = false;
            const int kFunctionIndex = kUpperToken.mid(1).toInt(&ok);
            if (ok && kFunctionIndex >= 1 && kFunctionIndex <= 24)
            {
                virtualKeyOut = static_cast<std::uint32_t>(VK_F1 + kFunctionIndex - 1);
                keyTextOut = QStringLiteral("F%1").arg(kFunctionIndex);
                return true;
            }
        }

        static const std::unordered_map<std::string, std::uint32_t> kKeyNameMap{
            {"ESC", VK_ESCAPE},
            {"ESCAPE", VK_ESCAPE},
            {"TAB", VK_TAB},
            {"ENTER", VK_RETURN},
            {"RETURN", VK_RETURN},
            {"SPACE", VK_SPACE},
            {"BACKSPACE", VK_BACK},
            {"BKSP", VK_BACK},
            {"DEL", VK_DELETE},
            {"DELETE", VK_DELETE},
            {"INS", VK_INSERT},
            {"INSERT", VK_INSERT},
            {"HOME", VK_HOME},
            {"END", VK_END},
            {"PGUP", VK_PRIOR},
            {"PAGEUP", VK_PRIOR},
            {"PGDN", VK_NEXT},
            {"PAGEDOWN", VK_NEXT},
            {"LEFT", VK_LEFT},
            {"RIGHT", VK_RIGHT},
            {"UP", VK_UP},
            {"DOWN", VK_DOWN},
            {"PRINTSCREEN", VK_SNAPSHOT},
            {"PRTSC", VK_SNAPSHOT},
            {"PAUSE", VK_PAUSE},
            {"APPS", VK_APPS},
            {"PLUS", VK_OEM_PLUS},
            {"MINUS", VK_OEM_MINUS},
            {"COMMA", VK_OEM_COMMA},
            {"PERIOD", VK_OEM_PERIOD}
        };

        const auto kIt = kKeyNameMap.find(kUpperToken.toStdString());
        if (kIt == kKeyNameMap.end())
        {
            return false;
        }

        virtualKeyOut = kIt->second;
        keyTextOut = virtualKeyName(virtualKeyOut);
        return true;
    }

    bool parseHotkeyText(const QString& sourceText, std::uint32_t& modifiersOut, std::uint32_t& virtualKeyOut)
    {
        QString text = sourceText.trimmed();
        if (text.isEmpty())
        {
            return false;
        }

        text.replace(QStringLiteral("Control"), QStringLiteral("Ctrl"), Qt::CaseInsensitive);
        text.replace(QStringLiteral("Windows"), QStringLiteral("Win"), Qt::CaseInsensitive);
        const QStringList kParts = text.split(QLatin1Char('+'), Qt::SkipEmptyParts);
        if (kParts.isEmpty())
        {
            return false;
        }

        std::uint32_t modifiers = 0;
        for (int index = 0; index + 1 < kParts.size(); ++index)
        {
            const QString kModifierText = kParts.at(index).trimmed().toUpper();
            if (kModifierText == QStringLiteral("CTRL"))
            {
                modifiers |= MOD_CONTROL;
            }
            else if (kModifierText == QStringLiteral("SHIFT"))
            {
                modifiers |= MOD_SHIFT;
            }
            else if (kModifierText == QStringLiteral("ALT"))
            {
                modifiers |= MOD_ALT;
            }
            else if (kModifierText == QStringLiteral("WIN"))
            {
                modifiers |= MOD_WIN;
            }
            else
            {
                return false;
            }
        }

        QString keyText;
        std::uint32_t virtualKey = 0;
        if (!parseHotkeyToken(kParts.last(), virtualKey, keyText))
        {
            return false;
        }

        modifiersOut = modifiers;
        virtualKeyOut = virtualKey;
        return true;
    }

    void appendCandidate(std::vector<HotkeyCandidate>& rows, QSet<QString>& dedupeSet, HotkeyCandidate row)
    {
        if (row.hotkeyText.trimmed().isEmpty() && row.virtualKey != 0U)
        {
            row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey);
        }
        if (row.hotkeyText.trimmed().isEmpty())
        {
            return;
        }

        const QString kDedupeKey = QStringLiteral("%1|%2|%3|%4|%5|%6|%7")
            .arg(row.sourceText)
            .arg(row.objectText)
            .arg(row.hotkeyId)
            .arg(row.modifiers)
            .arg(row.virtualKey)
            .arg(row.threadId)
            .arg(row.detailText);
        if (dedupeSet.contains(kDedupeKey))
        {
            return;
        }
        dedupeSet.insert(kDedupeKey);
        rows.push_back(std::move(row));
    }

    struct WindowCollectorContext
    {
        std::uint32_t targetPid = 0;
        QSet<qulonglong>* seenWindows = nullptr;
        std::vector<HWND>* windows = nullptr;
    };

    BOOL CALLBACK collectTopLevelWindowProc(HWND windowHandle, LPARAM parameter)
    {
        auto* context = reinterpret_cast<WindowCollectorContext*>(parameter);
        if (context == nullptr || context->seenWindows == nullptr || context->windows == nullptr)
        {
            return TRUE;
        }

        DWORD processId = 0;
        ::GetWindowThreadProcessId(windowHandle, &processId);
        if (processId != context->targetPid)
        {
            return TRUE;
        }

        const qulonglong kKey = static_cast<qulonglong>(reinterpret_cast<std::uintptr_t>(windowHandle));
        if (!context->seenWindows->contains(kKey))
        {
            context->seenWindows->insert(kKey);
            context->windows->push_back(windowHandle);
        }
        return TRUE;
    }

    std::vector<DWORD> collectThreadIdsForProcess(const std::uint32_t processId)
    {
        std::vector<DWORD> threadIds;
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return threadIds;
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        BOOL hasThread = ::Thread32First(snapshotHandle, &threadEntry);
        while (hasThread != FALSE)
        {
            if (threadEntry.th32OwnerProcessID == processId)
            {
                threadIds.push_back(threadEntry.th32ThreadID);
            }
            hasThread = ::Thread32Next(snapshotHandle, &threadEntry);
        }

        ::CloseHandle(snapshotHandle);
        return threadIds;
    }

    std::vector<HWND> collectWindowsForProcess(const std::uint32_t processId)
    {
        std::vector<HWND> windows;
        QSet<qulonglong> seenWindows;
        WindowCollectorContext context{ processId, &seenWindows, &windows };
        ::EnumWindows(collectTopLevelWindowProc, reinterpret_cast<LPARAM>(&context));

        const std::vector<DWORD> kThreadIds = collectThreadIdsForProcess(processId);
        for (const DWORD kThreadId : kThreadIds)
        {
            ::EnumThreadWindows(kThreadId, collectTopLevelWindowProc, reinterpret_cast<LPARAM>(&context));
        }

        return windows;
    }

    void collectWindowActivationHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet)
    {
        const std::vector<HWND> kWindows = collectWindowsForProcess(processId);
        for (HWND windowHandle : kWindows)
        {
            DWORD ownerProcessId = 0;
            const DWORD kThreadId = ::GetWindowThreadProcessId(windowHandle, &ownerProcessId);
            DWORD_PTR resultValue = 0;
            const LRESULT kSendOk = ::SendMessageTimeoutW(
                windowHandle,
                WM_GETHOTKEY,
                0,
                0,
                SMTO_ABORTIFHUNG | SMTO_BLOCK,
                100,
                &resultValue);
            if (kSendOk == 0 || resultValue == 0)
            {
                continue;
            }

            const std::uint32_t kVirtualKey = static_cast<std::uint32_t>(LOBYTE(LOWORD(resultValue)));
            const std::uint32_t kHotkeyf = static_cast<std::uint32_t>(HIBYTE(LOWORD(resultValue)));
            if (kVirtualKey == 0U)
            {
                continue;
            }

            HotkeyCandidate row{};
            row.objectText = QStringLiteral("HWND=%1").arg(pointerText(windowHandle));
            row.hotkeyId = 0;
            row.modifiers = hotkeyModifiersFromHotkeyf(kHotkeyf);
            row.virtualKey = kVirtualKey;
            row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey);
            row.processId = processId;
            row.threadId = kThreadId;
            row.processName = processName;
            row.sourceText = QStringLiteral("窗口热键");
            row.detailText = windowTitleText(windowHandle);
            appendCandidate(rows, dedupeSet, std::move(row));
        }
    }

    void collectMenuHotkeysRecursive(
        HMENU menuHandle,
        HWND windowHandle,
        const QString& menuPath,
        const std::uint32_t processId,
        const std::uint32_t threadId,
        const QString& processName,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet,
        const int depth)
    {
        if (menuHandle == nullptr || depth > 12)
        {
            return;
        }

        const int kItemCount = ::GetMenuItemCount(menuHandle);
        if (kItemCount <= 0)
        {
            return;
        }

        for (int index = 0; index < kItemCount; ++index)
        {
            wchar_t textBuffer[512] = {};
            MENUITEMINFOW itemInfo{};
            itemInfo.cbSize = sizeof(itemInfo);
            itemInfo.fMask = MIIM_STRING | MIIM_SUBMENU | MIIM_ID;
            itemInfo.dwTypeData = textBuffer;
            itemInfo.cch = static_cast<UINT>(std::size(textBuffer));
            if (::GetMenuItemInfoW(menuHandle, static_cast<UINT>(index), TRUE, &itemInfo) == FALSE)
            {
                continue;
            }

            const QString kRawText = QString::fromWCharArray(textBuffer).trimmed();
            const QString kItemPath = menuPath.isEmpty()
                ? kRawText
                : QStringLiteral("%1 > %2").arg(menuPath, kRawText);

            const int kTabIndex = kRawText.indexOf(QLatin1Char('\t'));
            if (kTabIndex >= 0 && kTabIndex + 1 < kRawText.size())
            {
                const QString kShortcutText = kRawText.mid(kTabIndex + 1).trimmed();
                std::uint32_t modifiers = 0;
                std::uint32_t virtualKey = 0;
                if (parseHotkeyText(kShortcutText, modifiers, virtualKey))
                {
                    HotkeyCandidate row{};
                    row.objectText = QStringLiteral("HWND=%1 HMENU=%2")
                        .arg(pointerText(windowHandle), pointerText(menuHandle));
                    row.hotkeyId = itemInfo.wID;
                    row.modifiers = modifiers;
                    row.virtualKey = virtualKey;
                    row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey);
                    row.processId = processId;
                    row.threadId = threadId;
                    row.processName = processName;
                    row.sourceText = QStringLiteral("菜单快捷键");
                    row.detailText = kItemPath;
                    appendCandidate(rows, dedupeSet, std::move(row));
                }
            }

            if (itemInfo.hSubMenu != nullptr)
            {
                collectMenuHotkeysRecursive(
                    itemInfo.hSubMenu,
                    windowHandle,
                    kItemPath,
                    processId,
                    threadId,
                    processName,
                    rows,
                    dedupeSet,
                    depth + 1);
            }
        }
    }

    void collectMenuHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet)
    {
        const std::vector<HWND> kWindows = collectWindowsForProcess(processId);
        for (HWND windowHandle : kWindows)
        {
            DWORD ownerProcessId = 0;
            const DWORD kThreadId = ::GetWindowThreadProcessId(windowHandle, &ownerProcessId);
            HMENU menuHandle = ::GetMenu(windowHandle);
            if (menuHandle == nullptr)
            {
                continue;
            }
            collectMenuHotkeysRecursive(
                menuHandle,
                windowHandle,
                windowTitleText(windowHandle),
                processId,
                kThreadId,
                processName,
                rows,
                dedupeSet,
                0);
        }
    }

    QStringList shortcutSearchRoots()
    {
        QStringList roots;
        const auto kAppendRoot = [&roots](const QString& pathText)
        {
            const QString kCleaned = QDir::fromNativeSeparators(pathText.trimmed());
            if (!kCleaned.isEmpty() && QDir(kCleaned).exists() && !roots.contains(kCleaned, Qt::CaseInsensitive))
            {
                roots << kCleaned;
            }
        };

        kAppendRoot(QStandardPaths::writableLocation(QStandardPaths::DesktopLocation));
        kAppendRoot(QStringLiteral("C:/Users/Public/Desktop"));

        const QString kAppData = qEnvironmentVariable("APPDATA");
        if (!kAppData.isEmpty())
        {
            kAppendRoot(QDir::fromNativeSeparators(kAppData + QStringLiteral("/Microsoft/Windows/Start Menu/Programs")));
            kAppendRoot(QDir::fromNativeSeparators(kAppData + QStringLiteral("/Microsoft/Internet Explorer/Quick Launch")));
        }

        const QString kProgramData = qEnvironmentVariable("PROGRAMDATA");
        if (!kProgramData.isEmpty())
        {
            kAppendRoot(QDir::fromNativeSeparators(kProgramData + QStringLiteral("/Microsoft/Windows/Start Menu/Programs")));
        }

        return roots;
    }

    bool shortcutTargetMatchesProcess(
        const QString& shortcutTarget,
        const QString& processImagePath,
        const QString& processName)
    {
        const QString kNormalizedTarget = normalizedFilePath(shortcutTarget);
        const QString kNormalizedProcessImage = normalizedFilePath(processImagePath);
        if (!kNormalizedTarget.isEmpty() &&
            !kNormalizedProcessImage.isEmpty() &&
            kNormalizedTarget == kNormalizedProcessImage)
        {
            return true;
        }

        if (!kNormalizedProcessImage.isEmpty())
        {
            return false;
        }

        if (!processName.trimmed().isEmpty())
        {
            const QString kTargetName = QFileInfo(shortcutTarget).fileName();
            if (!kTargetName.isEmpty() && kTargetName.compare(processName, Qt::CaseInsensitive) == 0)
            {
                return true;
            }
        }
        return false;
    }

    struct ShellShortcutHotkeyCandidate
    {
        QString shortcutPath;
        QString targetPath;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
    };

    void collectShellShortcutHotkeyCandidates(
        std::vector<ShellShortcutHotkeyCandidate>& candidates,
        QString& diagnosticText)
    {
        HRESULT comResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool kNeedsUninitialize = SUCCEEDED(comResult);
        const bool kComUsable = SUCCEEDED(comResult) || comResult == RPC_E_CHANGED_MODE;
        if (!kComUsable)
        {
            diagnosticText += QStringLiteral(" | ShellLink COM初始化失败:0x%1")
                .arg(static_cast<unsigned long>(comResult), 0, 16);
            return;
        }

        const QStringList kRoots = shortcutSearchRoots();
        for (const QString& rootPath : kRoots)
        {
            QDirIterator shortcutIterator(
                rootPath,
                QStringList{ QStringLiteral("*.lnk") },
                QDir::Files,
                QDirIterator::Subdirectories);
            while (shortcutIterator.hasNext())
            {
                const QString kShortcutPath = shortcutIterator.next();
                IShellLinkW* shellLink = nullptr;
                HRESULT createResult = ::CoCreateInstance(
                    CLSID_ShellLink,
                    nullptr,
                    CLSCTX_INPROC_SERVER,
                    IID_PPV_ARGS(&shellLink));
                if (FAILED(createResult) || shellLink == nullptr)
                {
                    continue;
                }

                IPersistFile* persistFile = nullptr;
                HRESULT queryResult = shellLink->QueryInterface(IID_PPV_ARGS(&persistFile));
                if (SUCCEEDED(queryResult) && persistFile != nullptr)
                {
                    const std::wstring kShortcutPathW = kShortcutPath.toStdWString();
                    HRESULT loadResult = persistFile->Load(kShortcutPathW.c_str(), STGM_READ);
                    if (SUCCEEDED(loadResult))
                    {
                        WORD hotkeyValue = 0;
                        wchar_t targetPathBuffer[MAX_PATH] = {};
                        WIN32_FIND_DATAW findData{};
                        shellLink->GetHotkey(&hotkeyValue);
                        shellLink->GetPath(
                            targetPathBuffer,
                            static_cast<int>(std::size(targetPathBuffer)),
                            &findData,
                            SLGP_UNCPRIORITY);

                        const QString kTargetPath = QString::fromWCharArray(targetPathBuffer).trimmed();
                        if (hotkeyValue != 0 && !kTargetPath.isEmpty())
                        {
                            ShellShortcutHotkeyCandidate candidate{};
                            candidate.shortcutPath = kShortcutPath;
                            candidate.targetPath = kTargetPath;
                            candidate.modifiers = hotkeyModifiersFromHotkeyf(HIBYTE(hotkeyValue));
                            candidate.virtualKey = LOBYTE(hotkeyValue);
                            candidates.push_back(std::move(candidate));
                        }
                    }
                    persistFile->Release();
                }
                shellLink->Release();
            }
        }

        if (kNeedsUninitialize)
        {
            ::CoUninitialize();
        }
    }

    void appendShellShortcutHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        const QString& processImagePath,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet,
        const std::vector<ShellShortcutHotkeyCandidate>& candidates)
    {
        for (const ShellShortcutHotkeyCandidate& candidate : candidates)
        {
            if (!shortcutTargetMatchesProcess(candidate.targetPath, processImagePath, processName))
            {
                continue;
            }

            HotkeyCandidate row{};
            row.objectText = candidate.shortcutPath;
            row.hotkeyId = 0;
            row.modifiers = candidate.modifiers;
            row.virtualKey = candidate.virtualKey;
            row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey);
            row.processId = processId;
            row.threadId = 0;
            row.processName = processName;
            row.sourceText = QStringLiteral("快捷方式热键");
            row.detailText = candidate.targetPath;
            appendCandidate(rows, dedupeSet, std::move(row));
        }
    }

    void collectShellShortcutHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        const QString& processImagePath,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet,
        QString& diagnosticText)
    {
        std::vector<ShellShortcutHotkeyCandidate> candidates;
        collectShellShortcutHotkeyCandidates(candidates, diagnosticText);
        appendShellShortcutHotkeys(
            processId,
            processName,
            processImagePath,
            rows,
            dedupeSet,
            candidates);
    }

    struct AcceleratorResourceEntry
    {
        std::uint16_t flags = 0;
        std::uint16_t key = 0;
        std::uint16_t commandId = 0;
        std::uint16_t padding = 0;
    };
    static_assert(sizeof(AcceleratorResourceEntry) == 8U, "PE accelerator resource entries must be 8 bytes");

    QString acceleratorCharacterText(const std::uint16_t keyValue)
    {
        if (keyValue == 0U || keyValue > 0xFFU)
        {
            return QString();
        }

        const char kAnsiCharacter = static_cast<char>(keyValue & 0xFFU);
        wchar_t unicodeCharacter = L'\0';
        if (::MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                &kAnsiCharacter,
                1,
                &unicodeCharacter,
                1) != 1)
        {
            return QString();
        }

        const QChar kCharacter(static_cast<ushort>(unicodeCharacter));
        return kCharacter.isPrint() ? QString(kCharacter).toUpper() : QString();
    }

    struct AcceleratorEnumContext
    {
        HMODULE moduleHandle = nullptr;
        QString modulePath;
        std::uint32_t processId = 0;
        QString processName;
        std::vector<HotkeyCandidate>* rows = nullptr;
        QSet<QString>* dedupeSet = nullptr;
    };

    QString acceleratorResourceNameText(LPCWSTR resourceName)
    {
        if (IS_INTRESOURCE(resourceName))
        {
            return QStringLiteral("#%1").arg(static_cast<qulonglong>(reinterpret_cast<std::uintptr_t>(resourceName)));
        }
        return QString::fromWCharArray(resourceName);
    }

    BOOL CALLBACK enumerateAcceleratorResourceProc(
        HMODULE moduleHandle,
        LPCWSTR resourceType,
        LPWSTR resourceName,
        LONG_PTR parameter)
    {
        Q_UNUSED(resourceType);

        auto* context = reinterpret_cast<AcceleratorEnumContext*>(parameter);
        if (context == nullptr || context->rows == nullptr || context->dedupeSet == nullptr)
        {
            return TRUE;
        }

        HRSRC resourceHandle = ::FindResourceW(moduleHandle, resourceName, RT_ACCELERATOR);
        if (resourceHandle == nullptr)
        {
            return TRUE;
        }

        const DWORD kResourceBytes = ::SizeofResource(moduleHandle, resourceHandle);
        if (kResourceBytes < sizeof(AcceleratorResourceEntry))
        {
            return TRUE;
        }

        HGLOBAL loadedResource = ::LoadResource(moduleHandle, resourceHandle);
        const auto* resourceData = static_cast<const unsigned char*>(::LockResource(loadedResource));
        if (resourceData == nullptr)
        {
            return TRUE;
        }

        // RT_ACCELERATOR uses ACCELTABLEENTRY (four WORDs, eight bytes), not the
        // runtime ACCEL structure. Advancing by sizeof(ACCEL) misaligns every row
        // after the first and produces bogus VK=0/garbled key names.
        const std::size_t kEntryCount = kResourceBytes / sizeof(AcceleratorResourceEntry);
        const QString kResourceNameText = acceleratorResourceNameText(resourceName);
        for (std::size_t index = 0; index < kEntryCount; ++index)
        {
            AcceleratorResourceEntry acceleratorEntry{};
            std::memcpy(
                &acceleratorEntry,
                resourceData + index * sizeof(AcceleratorResourceEntry),
                sizeof(acceleratorEntry));

            const bool kIsLastEntry = (acceleratorEntry.flags & 0x0080U) != 0U;
            if ((acceleratorEntry.flags & ~0x009FU) != 0U)
            {
                if (kIsLastEntry) break;
                continue;
            }

            const std::uint16_t kFlags = acceleratorEntry.flags & 0x007FU;
            std::uint32_t modifiers = 0;
            if ((kFlags & FCONTROL) != 0U) modifiers |= MOD_CONTROL;
            if ((kFlags & FSHIFT) != 0U) modifiers |= MOD_SHIFT;
            if ((kFlags & FALT) != 0U) modifiers |= MOD_ALT;

            std::uint32_t virtualKey = 0;
            QString keyOverride;
            if ((kFlags & FVIRTKEY) != 0U)
            {
                virtualKey = acceleratorEntry.key;
            }
            else
            {
                keyOverride = acceleratorCharacterText(acceleratorEntry.key);
                if (!keyOverride.isEmpty())
                {
                    const SHORT kVkScan = ::VkKeyScanW(keyOverride.at(0).unicode());
                    if (kVkScan != -1)
                    {
                        virtualKey = LOBYTE(kVkScan);
                    }
                }
            }

            if (virtualKey != 0U || !keyOverride.isEmpty())
            {
                HotkeyCandidate row{};
                row.objectText = QStringLiteral("%1:%2")
                    .arg(context->modulePath, kResourceNameText);
                row.hotkeyId = acceleratorEntry.commandId;
                row.modifiers = modifiers;
                row.virtualKey = virtualKey;
                row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey, keyOverride);
                row.processId = context->processId;
                row.threadId = 0;
                row.processName = context->processName;
                row.sourceText = QStringLiteral("PE Accelerator");
                row.detailText = QStringLiteral("entry=%1 flags=0x%2")
                    .arg(static_cast<qulonglong>(index))
                    .arg(static_cast<unsigned int>(acceleratorEntry.flags), 4, 16, QChar('0'))
                    .toUpper();
                appendCandidate(*context->rows, *context->dedupeSet, std::move(row));
            }

            if (kIsLastEntry)
            {
                break;
            }
        }

        return TRUE;
    }

    void collectAcceleratorResourceHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        const QString& processImagePath,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet,
        QString& diagnosticText)
    {
        QStringList modulePaths;
        const auto kAppendModulePath = [&modulePaths](const QString& pathText)
        {
            const QString kNormalizedPath = normalizedFilePath(pathText);
            if (!kNormalizedPath.isEmpty() && QFileInfo(pathText).exists() && !modulePaths.contains(pathText, Qt::CaseInsensitive))
            {
                modulePaths << pathText;
            }
        };

        kAppendModulePath(processImagePath);
        const ks::process::ProcessModuleSnapshot kModuleSnapshot =
            ks::process::enumerateProcessModulesAndThreads(processId, false);
        for (const ks::process::ProcessModuleRecord& moduleRecord : kModuleSnapshot.modules)
        {
            kAppendModulePath(QString::fromStdString(moduleRecord.modulePath));
            if (modulePaths.size() >= 96)
            {
                diagnosticText += QStringLiteral(" | Accelerator模块扫描已限制为前96个模块");
                break;
            }
        }

        for (const QString& modulePath : modulePaths)
        {
            const std::wstring kModulePathW = modulePath.toStdWString();
            HMODULE moduleHandle = ::LoadLibraryExW(
                kModulePathW.c_str(),
                nullptr,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (moduleHandle == nullptr)
            {
                continue;
            }

            AcceleratorEnumContext context{};
            context.moduleHandle = moduleHandle;
            context.modulePath = modulePath;
            context.processId = processId;
            context.processName = processName;
            context.rows = &rows;
            context.dedupeSet = &dedupeSet;
            ::EnumResourceNamesW(
                moduleHandle,
                RT_ACCELERATOR,
                enumerateAcceleratorResourceProc,
                reinterpret_cast<LONG_PTR>(&context));
            ::FreeLibrary(moduleHandle);
        }
    }

    void collectDriverHotkeyTable(
        const std::uint32_t processId,
        const QString& processName,
        std::vector<HotkeyCandidate>& rows,
        QString& diagnosticText)
    {
        const unsigned long kFlags =
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS;
        const ksword::ark::KeyboardHotkeyEnumResult kDriverResult =
            ksword::ark::DriverClient().enumerateKeyboardHotkeys(processId, kFlags, 2048UL);
        if (!kDriverResult.io.ok)
        {
            appendDiagnostic(
                diagnosticText,
                QStringLiteral("R0热键不可用:%1").arg(keyboardIoMessageText(kDriverResult.io.message)));
            return;
        }

        appendDiagnostic(
            diagnosticText,
            QStringLiteral("R0热键:%1 total=%2 returned=%3")
                .arg(keyboardEnumStatusText(kDriverResult.status))
                .arg(kDriverResult.totalCount)
                .arg(kDriverResult.entries.size()));

        for (const ksword::ark::KeyboardHotkeyEntry& entry : kDriverResult.entries)
        {
            if (entry.processId != 0U && entry.processId != processId)
            {
                continue;
            }

            HotkeyCandidate row{};
            row.objectText = QStringLiteral("tagHOTKEY %1").arg(hex64Text(entry.hotkeyObject));
            row.hotkeyId = entry.hotkeyId;
            row.modifiers = entry.modifiers;
            row.virtualKey = entry.virtualKey;
            row.r0MutationSnapshot.source = entry.source;
            row.r0MutationSnapshot.status = entry.status;
            row.r0MutationSnapshot.flags = entry.flags;
            row.r0MutationSnapshot.bucketIndex = entry.bucketIndex;
            row.r0MutationSnapshot.depth = entry.depth;
            row.r0MutationSnapshot.modifiers = entry.modifiers;
            row.r0MutationSnapshot.modifierFlags2 = entry.modifierFlags2;
            row.r0MutationSnapshot.virtualKey = entry.virtualKey;
            row.r0MutationSnapshot.hotkeyId = entry.hotkeyId;
            row.r0MutationSnapshot.processId = entry.processId;
            row.r0MutationSnapshot.threadId = entry.threadId;
            row.r0MutationSnapshot.hotkeyObject = entry.hotkeyObject;
            row.r0MutationSnapshot.nextHotkeyObject = entry.nextHotkeyObject;
            row.r0MutationSnapshot.sessionGlobals = entry.sessionGlobals;
            row.r0MutationSnapshot.threadInfo = entry.threadInfo;
            row.r0MutationSnapshot.windowHandle = entry.windowHandle;
            row.r0MutationSnapshot.destinationHandle = entry.destinationHandle;
            row.r0MutationSnapshot.callbackAddress = entry.callbackAddress;
            row.r0MutationSnapshot.childListFlink = entry.childListFlink;
            row.r0MutationSnapshot.childListBlink = entry.childListBlink;
            row.r0MutationSnapshot.snapshotHash = entry.snapshotHash;
            row.r0MutationSnapshot.objectSize = entry.objectSize;
            row.r0MutationSnapshot.entryFlags = entry.entryFlags;
            row.hasR0MutationSnapshot =
                (entry.entryFlags & KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MUTABLE) != 0UL;
            row.hotkeyText = hotkeyTextFromParts(entry.modifiers, entry.virtualKey);
            row.processId = entry.processId == 0U ? processId : entry.processId;
            row.threadId = entry.threadId;
            row.processName = entry.processId == 0U || entry.processId == processId
                ? processName
                : QString::fromStdString(ks::process::getProcessNameByPid(entry.processId));
            row.sourceText = keyboardHotkeySourceText(entry.source);
            row.detailText = QStringLiteral(
                "status=%1 bucket=%2 depth=%3 next=%4 threadInfo=%5 thread=%6 hwnd=%7 flags2=0x%8 %9")
                .arg(keyboardEnumStatusText(entry.status))
                .arg(entry.bucketIndex)
                .arg(entry.depth)
                .arg(hex64Text(entry.nextHotkeyObject))
                .arg(hex64Text(entry.threadInfo))
                .arg(hex64Text(entry.threadObject))
                .arg(hex64Text(entry.windowObject))
                .arg(entry.modifierFlags2, 0, 16)
                .arg(QString::fromStdWString(entry.detail))
                .toUpper();
            rows.push_back(std::move(row));
        }
    }

    std::vector<KeyboardHookCandidate> collectDriverKeyboardHooks(
        const std::uint32_t processId,
        QString& diagnosticText)
    {
        std::vector<KeyboardHookCandidate> rows;
        const unsigned long kFlags =
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS;
        const ksword::ark::KeyboardHookEnumResult kDriverResult =
            ksword::ark::DriverClient().enumerateKeyboardHooks(processId, kFlags, 2048UL);
        if (!kDriverResult.io.ok)
        {
            appendDiagnostic(
                diagnosticText,
                QStringLiteral("R0键盘钩子不可用:%1").arg(keyboardIoMessageText(kDriverResult.io.message)));
            return rows;
        }

        appendDiagnostic(
            diagnosticText,
            QStringLiteral("R0键盘钩子:%1 total=%2 returned=%3")
                .arg(keyboardEnumStatusText(kDriverResult.status))
                .arg(kDriverResult.totalCount)
                .arg(kDriverResult.entries.size()));

        rows.reserve(kDriverResult.entries.size());
        for (const ksword::ark::KeyboardHookEntry& entry : kDriverResult.entries)
        {
            KeyboardHookCandidate row{};
            row.objectText = QStringLiteral("tagHOOK %1").arg(hex64Text(entry.hookObject));
            row.typeText = keyboardHookTypeText(entry.hookType);
            row.scopeText = keyboardHookScopeText(entry.hookScope);
            row.processId = entry.processId;
            row.threadId = entry.threadId;
            row.procedureText = entry.procedureAddress != 0U
                ? hex64Text(entry.procedureAddress)
                : QStringLiteral("offset=%1").arg(hex64Text(entry.procedureOffset));
            row.moduleText = entry.moduleBase != 0U
                ? hex64Text(entry.moduleBase)
                : QStringLiteral("moduleId=%1").arg(entry.moduleId);
            row.sourceText = keyboardHookSourceText(entry.source);
            row.flagsText = QStringLiteral("0x%1").arg(entry.flags, 0, 16).toUpper();
            row.detailText = QStringLiteral(
                "status=%1 chain=%2 next=%3 threadInfo=%4 targetThreadInfo=%5 desktop=%6 last=0x%7 %8")
                .arg(keyboardEnumStatusText(entry.status))
                .arg(hex64Text(entry.chainHead))
                .arg(hex64Text(entry.nextHookObject))
                .arg(hex64Text(entry.threadInfo))
                .arg(hex64Text(entry.targetThreadInfo))
                .arg(hex64Text(entry.desktopInfo))
                .arg(static_cast<unsigned long>(static_cast<std::uint32_t>(entry.lastStatus)), 0, 16)
                .arg(QString::fromStdWString(entry.detail))
                .toUpper();
            rows.push_back(std::move(row));
        }

        return rows;
    }

    std::vector<HotkeyCandidate> collectUserModeHotkeysForProcess(
        const std::uint32_t processId,
        QString processName,
        QString processImagePath,
        QString& diagnosticText,
        const std::vector<ShellShortcutHotkeyCandidate>* const sharedShortcutCandidates = nullptr)
    {
        if (processName.trimmed().isEmpty())
        {
            processName = QString::fromStdString(ks::process::getProcessNameByPid(processId));
        }
        if (processImagePath.trimmed().isEmpty())
        {
            processImagePath = QString::fromStdString(ks::process::queryProcessPathByPid(processId));
        }

        std::vector<HotkeyCandidate> rows;
        QSet<QString> dedupeSet;

        collectWindowActivationHotkeys(processId, processName, rows, dedupeSet);
        collectMenuHotkeys(processId, processName, rows, dedupeSet);
        collectAcceleratorResourceHotkeys(processId, processName, processImagePath, rows, dedupeSet, diagnosticText);
        if (sharedShortcutCandidates != nullptr)
        {
            appendShellShortcutHotkeys(
                processId,
                processName,
                processImagePath,
                rows,
                dedupeSet,
                *sharedShortcutCandidates);
        }
        else
        {
            collectShellShortcutHotkeys(processId, processName, processImagePath, rows, dedupeSet, diagnosticText);
        }

        std::sort(
            rows.begin(),
            rows.end(),
            [](const HotkeyCandidate& left, const HotkeyCandidate& right)
            {
                if (left.hotkeyText != right.hotkeyText) return left.hotkeyText < right.hotkeyText;
                if (left.sourceText != right.sourceText) return left.sourceText < right.sourceText;
                return left.objectText < right.objectText;
            });

        return rows;
    }

    std::vector<HotkeyCandidate> collectHotkeysForProcess(
        const std::uint32_t processId,
        QString processName,
        QString processImagePath,
        QString& diagnosticText)
    {
        std::vector<HotkeyCandidate> rows = collectUserModeHotkeysForProcess(
            processId,
            std::move(processName),
            std::move(processImagePath),
            diagnosticText);
        QString resolvedProcessName;
        if (!rows.empty())
        {
            resolvedProcessName = rows.front().processName;
        }
        if (resolvedProcessName.isEmpty())
        {
            resolvedProcessName = QString::fromStdString(ks::process::getProcessNameByPid(processId));
        }
        collectDriverHotkeyTable(processId, resolvedProcessName, rows, diagnosticText);

        std::sort(
            rows.begin(),
            rows.end(),
            [](const HotkeyCandidate& left, const HotkeyCandidate& right)
            {
                if (left.hotkeyText != right.hotkeyText) return left.hotkeyText < right.hotkeyText;
                if (left.sourceText != right.sourceText) return left.sourceText < right.sourceText;
                return left.objectText < right.objectText;
            });
        return rows;
    }

    QTableWidgetItem* createHotkeyCell(const QString& textValue)
    {
        auto* item = new QTableWidgetItem(textValue);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    void configureHotkeyTableGeometry(QTableWidget* tableWidget)
    {
        // Inputs:
        // - tableWidget: the table displaying hotkey/hook results in the Process Hotkey page or Keyboard page.
        // Processing:
        // - The sum of table column widths may exceed the initial width of the detail window, especially when the "Details/Object" field contains long paths or R0 diagnostics.
        // - Prevent the last column of the header from automatically stretching and expanding sizeHint in reverse;
        // - Fix the table's minimum width to 0, allowing overflowing columns to be accessed via the horizontal scrollbar.
        // Return: None; directly adjust the table's geometry policy.
        if (tableWidget == nullptr || tableWidget->horizontalHeader() == nullptr)
        {
            return;
        }

        tableWidget->setMinimumWidth(0);
        tableWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
        tableWidget->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
        tableWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        tableWidget->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        tableWidget->horizontalHeader()->setStretchLastSection(false);
    }

    QString compactStatusText(const QString& statusText)
    {
        // Input: Full status text, which may contain a long R0 diagnostic string.
        // Processing: Compress only the displayed text without losing the full diagnostic in the tooltip.
        // Returns: Short text suitable for a single-line QLabel.
        constexpr int kStatusTextLimit = 160;
        const QString kTrimmedText = statusText.trimmed();
        if (kTrimmedText.size() <= kStatusTextLimit)
        {
            return kTrimmedText;
        }
        return QStringLiteral("%1...")
            .arg(kTrimmedText.left(kStatusTextLimit - 3));
    }

    QString hotkeyTableCellText(QTableWidget* tableWidget, const int rowIndex, const int columnIndex)
    {
        // hotkeyTableCellText:
        // - Input: Hotkey/hook audit table and target row/column.
        // - Processing: Read only the current cell's display text, without accessing any underlying audit objects;
        // - Returns: Empty string if the cell does not exist, facilitating TSV concatenation.
        if (tableWidget == nullptr)
        {
            return QString();
        }

        const QTableWidgetItem* cellItem = tableWidget->item(rowIndex, columnIndex);
        return cellItem != nullptr ? cellItem->text() : QString();
    }

    void copyHotkeyTableCurrentRow(QTableWidget* tableWidget)
    {
        // copyHotkeyTableCurrentRow:
        // - Input: hotkey or keyboard hook table in the process details window;
        // - Processing: Write all visible columns of the current row to the clipboard as TSV.
        // - Return: None. This right-click action only copies audit evidence and triggers no modification operations.
        if (tableWidget == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kRowIndex = tableWidget->currentRow();
        if (kRowIndex < 0 || kRowIndex >= tableWidget->rowCount())
        {
            return;
        }

        QStringList rowFields;
        rowFields.reserve(tableWidget->columnCount());
        for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
        {
            rowFields.push_back(hotkeyTableCellText(tableWidget, kRowIndex, columnIndex));
        }
        QApplication::clipboard()->setText(rowFields.join(QLatin1Char('\t')));
    }

    quint32 hotkeyTableProcessId(
        const QTableWidget* tableWidget,
        const int rowIndex,
        const int processIdColumn)
    {
        if (tableWidget == nullptr || rowIndex < 0 || processIdColumn < 0)
        {
            return 0U;
        }

        const QTableWidgetItem* processIdItem = tableWidget->item(rowIndex, processIdColumn);
        bool ok = false;
        const qulonglong kProcessId = processIdItem != nullptr
            ? processIdItem->text().trimmed().toULongLong(&ok)
            : 0ULL;
        return ok && kProcessId <= std::numeric_limits<quint32>::max()
            ? static_cast<quint32>(kProcessId)
            : 0U;
    }

    bool isEditableHotkeySource(const QString& sourceText)
    {
        return sourceText == QStringLiteral("窗口热键") ||
               sourceText == QStringLiteral("快捷方式热键") ||
               sourceText == QStringLiteral("R0 RegisterHotKey");
    }

    bool setWindowActivationHotkey(
        const QString& objectText,
        const std::uint32_t processId,
        const std::uint32_t modifiers,
        const std::uint32_t virtualKey,
        QString& errorText,
        bool& conflictDetected)
    {
        conflictDetected = false;
        static const QRegularExpression kHandlePattern(QStringLiteral("^HWND=0x([0-9A-Fa-f]+)$"));
        const QRegularExpressionMatch kHandleMatch = kHandlePattern.match(objectText.trimmed());
        bool handleOk = false;
        const qulonglong kHandleValue = kHandleMatch.hasMatch()
            ? kHandleMatch.captured(1).toULongLong(&handleOk, 16)
            : 0ULL;
        HWND windowHandle = handleOk
            ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(kHandleValue))
            : nullptr;
        DWORD ownerProcessId = 0;
        if (windowHandle == nullptr ||
            ::IsWindow(windowHandle) == FALSE ||
            ::GetWindowThreadProcessId(windowHandle, &ownerProcessId) == 0U ||
            ownerProcessId != processId)
        {
            errorText = QStringLiteral("stale or invalid HWND");
            return false;
        }

        const WORD kHotkeyValue = virtualKey == 0U
            ? 0U
            : MAKEWORD(
                static_cast<BYTE>(virtualKey),
                static_cast<BYTE>(hotkeyfFromModifiers(modifiers)));
        DWORD_PTR messageResult = 0;
        ::SetLastError(ERROR_SUCCESS);
        const LRESULT kSendResult = ::SendMessageTimeoutW(
            windowHandle,
            WM_SETHOTKEY,
            kHotkeyValue,
            0,
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            500,
            &messageResult);
        const LRESULT kHotkeyResult = static_cast<LRESULT>(messageResult);
        if (kSendResult == 0 || kHotkeyResult <= 0)
        {
            errorText = QStringLiteral("WM_SETHOTKEY result=%1, Win32=%2")
                .arg(kHotkeyResult)
                .arg(::GetLastError());
            return false;
        }

        conflictDetected = kHotkeyResult == 2;
        return true;
    }

    bool setShellShortcutHotkey(
        const QString& objectText,
        const std::uint32_t modifiers,
        const std::uint32_t virtualKey,
        QString& errorText)
    {
        const QString kShortcutPath = QDir::toNativeSeparators(objectText.trimmed());
        if (kShortcutPath.isEmpty() || !QFileInfo::exists(kShortcutPath))
        {
            errorText = QStringLiteral("shortcut file no longer exists");
            return false;
        }

        const HRESULT kInitializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool kUninitializeCom = SUCCEEDED(kInitializeResult);
        if (FAILED(kInitializeResult) && kInitializeResult != RPC_E_CHANGED_MODE)
        {
            errorText = QStringLiteral("CoInitializeEx HRESULT=0x%1")
                .arg(static_cast<unsigned long>(kInitializeResult), 8, 16, QChar('0'))
                .toUpper();
            return false;
        }

        IShellLinkW* shellLink = nullptr;
        IPersistFile* persistFile = nullptr;
        HRESULT operationResult = ::CoCreateInstance(
            CLSID_ShellLink,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&shellLink));
        if (SUCCEEDED(operationResult) && shellLink != nullptr)
        {
            operationResult = shellLink->QueryInterface(IID_PPV_ARGS(&persistFile));
        }
        else if (SUCCEEDED(operationResult))
        {
            operationResult = E_POINTER;
        }
        const std::wstring kShortcutPathW = kShortcutPath.toStdWString();
        if (SUCCEEDED(operationResult) && persistFile != nullptr)
        {
            operationResult = persistFile->Load(kShortcutPathW.c_str(), STGM_READWRITE);
        }
        else if (SUCCEEDED(operationResult))
        {
            operationResult = E_NOINTERFACE;
        }
        if (SUCCEEDED(operationResult))
        {
            const WORD kHotkeyValue = virtualKey == 0U
                ? 0U
                : MAKEWORD(
                    static_cast<BYTE>(virtualKey),
                    static_cast<BYTE>(hotkeyfFromModifiers(modifiers)));
            operationResult = shellLink->SetHotkey(kHotkeyValue);
        }
        if (SUCCEEDED(operationResult))
        {
            operationResult = persistFile->Save(kShortcutPathW.c_str(), TRUE);
        }

        if (persistFile != nullptr) persistFile->Release();
        if (shellLink != nullptr) shellLink->Release();
        if (kUninitializeCom) ::CoUninitialize();

        if (FAILED(operationResult))
        {
            errorText = QStringLiteral("ShellLink HRESULT=0x%1")
                .arg(static_cast<unsigned long>(operationResult), 8, 16, QChar('0'))
                .toUpper();
            return false;
        }
        return true;
    }

    void installHotkeyTableContextMenu(QTableWidget* tableWidget, const int processIdColumn)
    {
        // installHotkeyTableContextMenu:
        // - Input: hotkey/hook table requiring right-click copy capability completion;
        // - Processing: Install the existing style's right-click menu and synchronize the current row at the click location.
        // - Return: None. The menu provides copy and opens process details by the current row's PID.
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            tableWidget,
            &QTableWidget::customContextMenuRequested,
            tableWidget,
            [tableWidget, processIdColumn](const QPoint& localPosition)
            {
                const QModelIndex kClickedIndex = tableWidget->indexAt(localPosition);
                if (kClickedIndex.isValid())
                {
                    tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
                }

                QMenu contextMenu(tableWidget);
                contextMenu.setStyleSheet(buildProcessDetailMenuStyle());
                QAction* copyRowAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
                const quint32 kProcessId = hotkeyTableProcessId(
                    tableWidget,
                    tableWidget->currentRow(),
                    processIdColumn);
                QAction* openProcessAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(kProcessId != 0U);

                QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
                if (selectedAction == copyRowAction)
                {
                    copyHotkeyTableCurrentRow(tableWidget);
                }
                else if (selectedAction == openProcessAction)
                {
                    ks::ui::openProcessDetailByPid(kProcessId);
                }
            });
    }
}

std::vector<ks::process::UserModeHotkeyRecord> ks::process::enumerateUserModeHotkeysForProcess(
    const std::uint32_t processId,
    QString processName,
    QString processImagePath,
    QString* const diagnosticTextOut)
{
    QString diagnosticText = QStringLiteral("R3 窗口/菜单/资源/.lnk");
    const std::vector<HotkeyCandidate> kCandidates = collectUserModeHotkeysForProcess(
        processId,
        std::move(processName),
        std::move(processImagePath),
        diagnosticText);

    std::vector<UserModeHotkeyRecord> records;
    records.reserve(kCandidates.size());
    for (const HotkeyCandidate& candidate : kCandidates)
    {
        UserModeHotkeyRecord record{};
        record.objectText = candidate.objectText;
        record.hotkeyId = candidate.hotkeyId;
        record.modifiers = candidate.modifiers;
        record.virtualKey = candidate.virtualKey;
        record.hotkeyText = candidate.hotkeyText;
        record.processId = candidate.processId;
        record.threadId = candidate.threadId;
        record.processName = candidate.processName;
        record.sourceText = candidate.sourceText;
        record.detailText = candidate.detailText;
        records.push_back(std::move(record));
    }

    if (diagnosticTextOut != nullptr)
    {
        *diagnosticTextOut = diagnosticText;
    }
    return records;
}

void ks::process::enumerateUserModeHotkeysForProcesses(
    const std::vector<UserModeHotkeyProcessTarget>& targets,
    const UserModeHotkeyBatchCallback& progressCallback,
    QString* const diagnosticTextOut)
{
    QString sharedDiagnosticText = QStringLiteral("R3 窗口/菜单/资源/.lnk");
    std::vector<ShellShortcutHotkeyCandidate> sharedShortcutCandidates;
    collectShellShortcutHotkeyCandidates(sharedShortcutCandidates, sharedDiagnosticText);

    const std::uint32_t kTotalProcessCount = static_cast<std::uint32_t>(targets.size());
    if (kTotalProcessCount == 0U)
    {
        if (diagnosticTextOut != nullptr)
        {
            *diagnosticTextOut = sharedDiagnosticText;
        }
        return;
    }

    const unsigned int kHardwareConcurrency = std::thread::hardware_concurrency();
    const unsigned int kWorkerCount = std::min<unsigned int>(
        kTotalProcessCount,
        std::clamp(kHardwareConcurrency == 0U ? 2U : kHardwareConcurrency / 2U, 2U, 4U));
    std::atomic_size_t nextTargetIndex{ 0U };
    std::atomic_uint32_t completedProcessCount{ 0U };
    std::vector<std::thread> workers;
    workers.reserve(kWorkerCount);

    for (unsigned int workerIndex = 0U; workerIndex < kWorkerCount; ++workerIndex)
    {
        workers.emplace_back([&targets,
                              &progressCallback,
                              &sharedShortcutCandidates,
                              &nextTargetIndex,
                              &completedProcessCount,
                              kTotalProcessCount]()
        {
            for (;;)
            {
                const std::size_t kTargetIndex = nextTargetIndex.fetch_add(1U);
                if (kTargetIndex >= targets.size())
                {
                    return;
                }

                const UserModeHotkeyProcessTarget& target = targets.at(kTargetIndex);
                QString diagnosticText = QStringLiteral("R3 窗口/菜单/资源/.lnk");
                const std::vector<HotkeyCandidate> kCandidates = collectUserModeHotkeysForProcess(
                    target.processId,
                    target.processName,
                    target.processImagePath,
                    diagnosticText,
                    &sharedShortcutCandidates);

                UserModeHotkeyBatchProgress progress{};
                progress.completedProcessCount = completedProcessCount.fetch_add(1U) + 1U;
                progress.totalProcessCount = kTotalProcessCount;
                progress.processName = target.processName;
                progress.diagnosticText = diagnosticText;
                progress.records.reserve(kCandidates.size());
                for (const HotkeyCandidate& candidate : kCandidates)
                {
                    UserModeHotkeyRecord record{};
                    record.objectText = candidate.objectText;
                    record.hotkeyId = candidate.hotkeyId;
                    record.modifiers = candidate.modifiers;
                    record.virtualKey = candidate.virtualKey;
                    record.hotkeyText = candidate.hotkeyText;
                    record.processId = candidate.processId;
                    record.threadId = candidate.threadId;
                    record.processName = candidate.processName;
                    record.sourceText = candidate.sourceText;
                    record.detailText = candidate.detailText;
                    progress.records.push_back(std::move(record));
                }

                if (progressCallback)
                {
                    progressCallback(std::move(progress));
                }
            }
        });
    }

    for (std::thread& worker : workers)
    {
        worker.join();
    }

    if (diagnosticTextOut != nullptr)
    {
        *diagnosticTextOut = sharedDiagnosticText;
    }
}

void ProcessDetailWindow::initializeHotkeyTab()
{
    KLogEvent initHotkeyTabEvent;
    info << initHotkeyTabEvent
        << "[ProcessDetailWindow] initializeHotkeyTab: 构建进程热键页面。"
        << eol;

    hotkeyLayout_ = new QVBoxLayout(hotkeyTab_);
    hotkeyLayout_->setContentsMargins(6, 6, 6, 6);
    hotkeyLayout_->setSpacing(8);

    QGroupBox* hotkeyGroup = new QGroupBox(QStringLiteral("进程热键检测"), hotkeyTab_);
    QVBoxLayout* hotkeyGroupLayout = new QVBoxLayout(hotkeyGroup);
    hotkeyGroupLayout->setContentsMargins(8, 8, 8, 8);
    hotkeyGroupLayout->setSpacing(6);

    QHBoxLayout* topBarLayout = new QHBoxLayout();
    refreshHotkeyButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新热键"), hotkeyGroup);
    refreshHotkeyButton_->setToolTip(QStringLiteral("扫描当前进程的窗口热键、菜单快捷键、Accelerator资源、快捷方式热键和R0热键表"));
    editHotkeyButton_ = new QPushButton(
        hotkeyUiText(QStringLiteral("process.hotkey.edit"), QStringLiteral("编辑热键")),
        hotkeyGroup);
    editHotkeyButton_->setToolTip(hotkeyUiText(
        QStringLiteral("process.hotkey.edit.tooltip"),
        QStringLiteral("修改选中的窗口激活热键或 .lnk 快捷方式热键；双击行也可编辑")));
    editHotkeyButton_->setEnabled(false);
    deleteHotkeyButton_ = new QPushButton(
        hotkeyUiText(QStringLiteral("process.hotkey.delete"), QStringLiteral("删除热键")),
        hotkeyGroup);
    deleteHotkeyButton_->setToolTip(hotkeyUiText(
        QStringLiteral("process.hotkey.delete.tooltip"),
        QStringLiteral("删除选中的窗口、快捷方式或可安全修改的 R0 RegisterHotKey 热键")));
    deleteHotkeyButton_->setEnabled(false);
    hotkeyStatusLabel_ = new QLabel(QStringLiteral("● 尚未刷新"), hotkeyGroup);
    hotkeyStatusLabel_->setMinimumWidth(0);
    hotkeyStatusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    hotkeyStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(ksword_theme::textSecondaryHex()));
    topBarLayout->addWidget(refreshHotkeyButton_);
    topBarLayout->addWidget(editHotkeyButton_);
    topBarLayout->addWidget(hotkeyStatusLabel_, 1);
    topBarLayout->addWidget(deleteHotkeyButton_);
    hotkeyGroupLayout->addLayout(topBarLayout);

    hotkeyTable_ = new ks::ui::VisibleTableWidget(hotkeyGroup);
    hotkeyTable_->setColumnCount(9);
    hotkeyTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("对象"),
        QStringLiteral("热键ID"),
        QStringLiteral("热键"),
        QStringLiteral("进程ID"),
        QStringLiteral("线程ID"),
        QStringLiteral("进程名"),
        QStringLiteral("来源"),
        QStringLiteral("VK/Mod"),
        QStringLiteral("详情")
    });
    hotkeyTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    hotkeyTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    hotkeyTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    hotkeyTable_->setAlternatingRowColors(true);
    hotkeyTable_->setSortingEnabled(true);
    hotkeyTable_->verticalHeader()->setVisible(false);
    configureHotkeyTableGeometry(hotkeyTable_);
    hotkeyTable_->setColumnWidth(0, 260);
    hotkeyTable_->setColumnWidth(1, 80);
    hotkeyTable_->setColumnWidth(2, 130);
    hotkeyTable_->setColumnWidth(3, 80);
    hotkeyTable_->setColumnWidth(4, 80);
    hotkeyTable_->setColumnWidth(5, 120);
    hotkeyTable_->setColumnWidth(6, 130);
    hotkeyTable_->setColumnWidth(7, 120);
    installHotkeyTableContextMenu(hotkeyTable_, 3);
    connect(editHotkeyButton_, &QPushButton::clicked, this, [this]() {
        editSelectedHotkey();
    });
    connect(deleteHotkeyButton_, &QPushButton::clicked, this, [this]() {
        deleteSelectedHotkey();
    });
    connect(hotkeyTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        if (editHotkeyButton_ != nullptr)
        {
            editHotkeyButton_->setEnabled(!hotkeyRefreshing_ && hotkeyTable_->currentRow() >= 0);
        }
        if (deleteHotkeyButton_ != nullptr)
        {
            deleteHotkeyButton_->setEnabled(!hotkeyRefreshing_ && hotkeyTable_->currentRow() >= 0);
        }
    });
    connect(hotkeyTable_, &QTableWidget::cellDoubleClicked, this, [this](const int, const int) {
        editSelectedHotkey();
    });
    hotkeyGroupLayout->addWidget(hotkeyTable_, 1);

    hotkeyLayout_->addWidget(hotkeyGroup, 1);

    const QString kButtonStyle = buildBlueButtonStyle();
    refreshHotkeyButton_->setStyleSheet(kButtonStyle);
    editHotkeyButton_->setStyleSheet(kButtonStyle);
    deleteHotkeyButton_->setStyleSheet(kButtonStyle);
}

void ProcessDetailWindow::editSelectedHotkey()
{
    const QString kTitleText = hotkeyUiText(
        QStringLiteral("process.hotkey.edit.title"),
        QStringLiteral("编辑热键"));
    if (hotkeyTable_ == nullptr || hotkeyTable_->currentRow() < 0)
    {
        QMessageBox::information(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.select_row"),
                QStringLiteral("请先选择一条热键记录。")));
        return;
    }

    const QTableWidgetItem* rowIdentityItem = hotkeyTable_->item(hotkeyTable_->currentRow(), 0);
    bool rowIndexOk = false;
    const qulonglong kRowIndexValue = rowIdentityItem != nullptr
        ? rowIdentityItem->data(kHotkeyRowIndexRole).toULongLong(&rowIndexOk)
        : 0ULL;
    if (!rowIndexOk || kRowIndexValue >= hotkeyRows_.size())
    {
        QMessageBox::warning(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.stale"),
                QStringLiteral("所选记录已失效，请刷新后重试。")));
        return;
    }

    const HotkeyInspectItem kRow = hotkeyRows_.at(static_cast<std::size_t>(kRowIndexValue));
    const bool kIsR0Hotkey = kRow.sourceText == QStringLiteral("R0 RegisterHotKey");
    if (!isEditableHotkeySource(kRow.sourceText))
    {
        QMessageBox::information(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.unsupported"),
                QStringLiteral("此来源是只读审计数据。当前仅支持修改窗口激活热键、.lnk 快捷方式热键和通过安全快照验证的 R0 RegisterHotKey 项。")));
        return;
    }
    if (kIsR0Hotkey && !kRow.hasR0MutationSnapshot)
    {
        QMessageBox::warning(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.r0.not_mutable"),
                QStringLiteral("该 R0 热键不是普通独立项，或枚举时未取得完整对象快照，因此不能修改。")));
        return;
    }

    bool accepted = false;
    const QString kEditedText = QInputDialog::getText(
        this,
        kTitleText,
        hotkeyUiText(
            QStringLiteral("process.hotkey.edit.prompt"),
            QStringLiteral("输入新热键（例如 Ctrl+Alt+K；留空可清除）：")),
        QLineEdit::Normal,
        kRow.hotkeyText,
        &accepted).trimmed();
    if (!accepted)
    {
        return;
    }

    if (kIsR0Hotkey && kEditedText.isEmpty())
    {
        QMessageBox::information(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.r0.use_delete"),
                QStringLiteral("R0 热键请使用“删除热键”按钮删除；编辑操作必须提供新的组合。")));
        return;
    }
    std::uint32_t modifiers = 0;
    std::uint32_t virtualKey = 0;
    if (!kEditedText.isEmpty() && !parseHotkeyText(kEditedText, modifiers, virtualKey))
    {
        QMessageBox::warning(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.invalid"),
                QStringLiteral("无法识别该热键。请使用 Ctrl、Shift、Alt 加字母、数字、F1-F24 或常用功能键。")));
        return;
    }
    if (kIsR0Hotkey)
    {
        modifiers |= kRow.modifiers & MOD_NOREPEAT;
    }
    if (!kIsR0Hotkey && (modifiers & MOD_WIN) != 0U)
    {
        QMessageBox::warning(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.win_unsupported"),
                QStringLiteral("Windows 键不受 WM_SETHOTKEY 或 .lnk 热键字段支持，请改用 Ctrl、Shift 或 Alt。")));
        return;
    }

    if (kIsR0Hotkey)
    {
        const QString kConfirmText = hotkeyUiText(
            QStringLiteral("process.hotkey.r0.edit.confirm"),
            QStringLiteral("这会在内核 USER 临界区内修改 RegisterHotKey 对象。驱动只接受完全一致的快照，并验证除组合键及必要链指针外的所有字节保持不变。\n\n确认将 %1 修改为 %2？"))
            .arg(kRow.hotkeyText, hotkeyTextFromParts(modifiers, virtualKey));
        if (QMessageBox::warning(
                this,
                kTitleText,
                kConfirmText,
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) != QMessageBox::Yes)
        {
            return;
        }

        const ksword::ark::KeyboardHotkeyMutationResult kMutationResult =
            ksword::ark::DriverClient().mutateKeyboardHotkey(
                kRow.r0MutationSnapshot,
                KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_EDIT,
                modifiers,
                virtualKey);
        if (!kMutationResult.io.ok ||
            kMutationResult.response.status != KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK ||
            (kMutationResult.response.responseFlags &
                KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_OTHER_BYTES_SAME) == 0UL)
        {
            QMessageBox::critical(
                this,
                kTitleText,
                hotkeyUiText(QStringLiteral("process.hotkey.edit.failed"), QStringLiteral("热键修改失败：%1"))
                    .arg(keyboardMutationFailureText(kMutationResult)));
            return;
        }
        QMessageBox::information(
            this,
            kTitleText,
            hotkeyUiText(QStringLiteral("process.hotkey.edit.success"), QStringLiteral("热键已修改为 %1。"))
                .arg(hotkeyTextFromParts(modifiers, virtualKey)));
        requestAsyncHotkeyRefresh();
        return;
    }

    QString errorText;
    bool conflictDetected = false;
    const bool kUpdateSucceeded = kRow.sourceText == QStringLiteral("窗口热键")
        ? setWindowActivationHotkey(kRow.objectText, kRow.processId, modifiers, virtualKey, errorText, conflictDetected)
        : setShellShortcutHotkey(kRow.objectText, modifiers, virtualKey, errorText);
    if (!kUpdateSucceeded)
    {
        QMessageBox::critical(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.failed"),
                QStringLiteral("热键修改失败：%1")).arg(errorText));
        return;
    }

    const QString kResultText = kEditedText.isEmpty()
        ? hotkeyUiText(
            QStringLiteral("process.hotkey.edit.cleared"),
            QStringLiteral("热键已清除。"))
        : hotkeyUiText(
            QStringLiteral("process.hotkey.edit.success"),
            QStringLiteral("热键已修改为 %1。")).arg(hotkeyTextFromParts(modifiers, virtualKey));
    QMessageBox::information(
        this,
        kTitleText,
        conflictDetected
            ? kResultText + QStringLiteral("\n") + hotkeyUiText(
                QStringLiteral("process.hotkey.edit.window_conflict"),
                QStringLiteral("提示：系统报告另一个窗口使用了相同热键。"))
            : kResultText);
    requestAsyncHotkeyRefresh();
}


void ProcessDetailWindow::deleteSelectedHotkey()
{
    const QString kTitleText = hotkeyUiText(
        QStringLiteral("process.hotkey.delete.title"),
        QStringLiteral("删除热键"));
    if (hotkeyTable_ == nullptr || hotkeyTable_->currentRow() < 0)
    {
        QMessageBox::information(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.select_row"),
                QStringLiteral("请先选择一条热键记录。")));
        return;
    }

    const QTableWidgetItem* rowIdentityItem = hotkeyTable_->item(hotkeyTable_->currentRow(), 0);
    bool rowIndexOk = false;
    const qulonglong kRowIndexValue = rowIdentityItem != nullptr
        ? rowIdentityItem->data(kHotkeyRowIndexRole).toULongLong(&rowIndexOk)
        : 0ULL;
    if (!rowIndexOk || kRowIndexValue >= hotkeyRows_.size())
    {
        QMessageBox::warning(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.stale"),
                QStringLiteral("所选记录已失效，请刷新后重试。")));
        return;
    }

    const HotkeyInspectItem kRow = hotkeyRows_.at(static_cast<std::size_t>(kRowIndexValue));
    const bool kIsR0Hotkey = kRow.sourceText == QStringLiteral("R0 RegisterHotKey");
    if (!isEditableHotkeySource(kRow.sourceText))
    {
        QMessageBox::information(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.delete.unsupported"),
                QStringLiteral("该来源是只读审计数据，不能删除。")));
        return;
    }
    if (kIsR0Hotkey && !kRow.hasR0MutationSnapshot)
    {
        QMessageBox::warning(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.r0.not_mutable"),
                QStringLiteral("该 R0 热键不是普通独立项，或枚举时未取得完整对象快照，因此不能修改。")));
        return;
    }

    const QString kConfirmText = kIsR0Hotkey
        ? hotkeyUiText(
            QStringLiteral("process.hotkey.r0.delete.confirm"),
            QStringLiteral("这会在内核 USER 临界区内调用 win32k 的标准热键删除路径。驱动会重新验证完整对象快照，并拒绝回调、占位或含子项的对象。\n\n确认删除 %1（%2）？"))
            .arg(kRow.hotkeyText, kRow.objectText)
        : hotkeyUiText(
            QStringLiteral("process.hotkey.delete.confirm"),
            QStringLiteral("确认删除 %1（%2）？"))
            .arg(kRow.hotkeyText, kRow.objectText);
    const QMessageBox::StandardButton kConfirmed = kIsR0Hotkey
        ? QMessageBox::warning(
            this,
            kTitleText,
            kConfirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No)
        : QMessageBox::question(
            this,
            kTitleText,
            kConfirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    if (kConfirmed != QMessageBox::Yes)
    {
        return;
    }

    QString errorText;
    if (kIsR0Hotkey)
    {
        const ksword::ark::KeyboardHotkeyMutationResult kMutationResult =
            ksword::ark::DriverClient().mutateKeyboardHotkey(
                kRow.r0MutationSnapshot,
                KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE);
        if (!kMutationResult.io.ok ||
            kMutationResult.response.status != KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK ||
            (kMutationResult.response.responseFlags &
                KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED) == 0UL)
        {
            errorText = keyboardMutationFailureText(kMutationResult);
        }
    }
    else
    {
        bool conflictDetected = false;
        const bool kDeleted = kRow.sourceText == QStringLiteral("窗口热键")
            ? setWindowActivationHotkey(kRow.objectText, kRow.processId, 0U, 0U, errorText, conflictDetected)
            : setShellShortcutHotkey(kRow.objectText, 0U, 0U, errorText);
        if (!kDeleted && errorText.isEmpty())
        {
            errorText = hotkeyUiText(
                QStringLiteral("process.hotkey.delete.operation_failed"),
                QStringLiteral("公开接口未能清除该热键。"));
        }
    }

    if (!errorText.isEmpty())
    {
        QMessageBox::critical(
            this,
            kTitleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.delete.failed"),
                QStringLiteral("热键删除失败：%1")).arg(errorText));
        return;
    }
    QMessageBox::information(
        this,
        kTitleText,
        hotkeyUiText(QStringLiteral("process.hotkey.delete.success"), QStringLiteral("热键已删除。")));
    requestAsyncHotkeyRefresh();
}
void ProcessDetailWindow::showHotkeyTabAndRefresh()
{
    // Right-click menu direct entry:
    // - Input: none; target process comes from m_baseRecord bound to the current detail window
    // - Processing: Switch to the 'Process Hotkey' tab first, then reuse the existing asynchronous hotkey refresh function.
    // - Returns: None. Maintains the current safe state if the control is not yet initialized or scanning is in progress.
    if (tabWidget_ != nullptr && hotkeyTab_ != nullptr)
    {
        tabWidget_->setCurrentWidget(hotkeyTab_);
    }

    if (!hotkeyRefreshing_)
    {
        requestAsyncHotkeyRefresh();
    }

    KLogEvent hotkeyEntryEvent;
    info << hotkeyEntryEvent
        << "[ProcessDetailWindow] showHotkeyTabAndRefresh: pid="
        << baseRecord_.pid
        << eol;
}

void ProcessDetailWindow::updateHotkeyStatusLabel(const QString& statusText, const bool refreshing)
{
    if (hotkeyStatusLabel_ == nullptr)
    {
        return;
    }

    hotkeyStatusLabel_->setToolTip(statusText);
    hotkeyStatusLabel_->setText(compactStatusText(statusText));
    if (refreshing)
    {
        hotkeyStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }
    else if (statusText.contains(QStringLiteral("无公开API")) || statusText.contains(QStringLiteral("失败")))
    {
        hotkeyStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
    }
    else
    {
        hotkeyStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
    }
}

void ProcessDetailWindow::requestAsyncHotkeyRefresh()
{
    if (hotkeyRefreshing_ || baseRecord_.pid == 0)
    {
        return;
    }

    hotkeyInitialRefreshStarted_ = true;
    hotkeyRefreshing_ = true;
    const std::uint64_t kTicketValue = ++hotkeyRefreshTicket_;
    const std::uint32_t kPidValue = baseRecord_.pid;
    const QString kProcessNameText = QString::fromStdString(baseRecord_.processName);
    const QString kProcessImagePathText = QString::fromStdString(baseRecord_.imagePath);

    if (refreshHotkeyButton_ != nullptr)
    {
        refreshHotkeyButton_->setEnabled(false);
    }
    if (editHotkeyButton_ != nullptr)
    {
        editHotkeyButton_->setEnabled(false);
    }
    updateHotkeyStatusLabel(QStringLiteral("● 正在扫描进程热键..."), true);

    if (deleteHotkeyButton_ != nullptr)
    {
        deleteHotkeyButton_->setEnabled(false);
    }
    if (hotkeyRefreshProgressPid_ == 0)
    {
        hotkeyRefreshProgressPid_ = kPro.addReusable(this, "进程详情", "扫描进程热键");
    }
    kPro.set(hotkeyRefreshProgressPid_, "枚举窗口/菜单/资源/快捷方式", 0, 20.0f);

    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create(
        [guardThis, kTicketValue, kPidValue, kProcessNameText, kProcessImagePathText]()
        {
            HotkeyInspectRefreshResult refreshResult{};
            const auto kBeginTime = std::chrono::steady_clock::now();

            QString diagnosticText = QStringLiteral("R3窗口/菜单/资源/.lnk + R0 win32k热键表");
            const std::vector<HotkeyCandidate> kCandidates = collectHotkeysForProcess(
                kPidValue,
                kProcessNameText,
                kProcessImagePathText,
                diagnosticText);

            refreshResult.rows.reserve(kCandidates.size());
            for (const HotkeyCandidate& candidate : kCandidates)
            {
                HotkeyInspectItem row{};
                row.objectText = candidate.objectText;
                row.hotkeyId = candidate.hotkeyId;
                row.modifiers = candidate.modifiers;
                row.virtualKey = candidate.virtualKey;
                row.hotkeyText = candidate.hotkeyText;
                row.processId = candidate.processId;
                row.threadId = candidate.threadId;
                row.processName = candidate.processName;
                row.sourceText = candidate.sourceText;
                row.detailText = candidate.detailText;
                row.hasR0MutationSnapshot = candidate.hasR0MutationSnapshot;
                row.r0MutationSnapshot = candidate.r0MutationSnapshot;
                refreshResult.rows.push_back(std::move(row));
            }

            refreshResult.diagnosticText = diagnosticText;
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kTicketValue, refreshResult]()
                {
                    if (guardThis == nullptr || guardThis->hotkeyRefreshTicket_ != kTicketValue)
                    {
                        return;
                    }
                    guardThis->applyHotkeyRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });

    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyHotkeyRefreshResult(const HotkeyInspectRefreshResult& refreshResult)
{
    QPointer<ProcessDetailWindow> guardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("process-detail-hotkey-snapshot-apply"),
            {hotkeyTable_, keyboardHotkeyTable_},
            [guardThis, refreshResult]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->applyHotkeyRefreshResult(refreshResult);
                }
            }))
    {
        return;
    }

    hotkeyRefreshing_ = false;
    if (refreshHotkeyButton_ != nullptr)
    {
        refreshHotkeyButton_->setEnabled(true);
    }

    hotkeyRows_ = refreshResult.rows;
    keyboardHotkeyRows_ = refreshResult.rows;
    rebuildHotkeyTable();
    rebuildKeyboardHotkeyTable();

    QString statusText = QStringLiteral("● 刷新完成 %1 ms | 热键:%2")
        .arg(refreshResult.elapsedMs)
        .arg(static_cast<qulonglong>(refreshResult.rows.size()));
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
    }
    updateHotkeyStatusLabel(statusText, false);

    if (hotkeyRefreshProgressPid_ > 0)
    {
        kPro.set(hotkeyRefreshProgressPid_, "进程热键扫描完成", 100, 1.0f);
    }

    KLogEvent hotkeyRefreshDoneEvent;
    info << hotkeyRefreshDoneEvent
        << "[ProcessDetailWindow] 进程热键扫描完成, pid="
        << baseRecord_.pid
        << ", rows="
        << refreshResult.rows.size()
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::rebuildHotkeyTable()
{
    if (hotkeyTable_ == nullptr)
    {
        return;
    }

    hotkeyTable_->setSortingEnabled(false);
    hotkeyTable_->setRowCount(0);

    for (std::size_t rowCacheIndex = 0; rowCacheIndex < hotkeyRows_.size(); ++rowCacheIndex)
    {
        const HotkeyInspectItem& rowItem = hotkeyRows_.at(rowCacheIndex);
        const int kRow = hotkeyTable_->rowCount();
        hotkeyTable_->insertRow(kRow);

        const QString kIdText = rowItem.hotkeyId == 0U
            ? QStringLiteral("0")
            : QStringLiteral("0x%1").arg(rowItem.hotkeyId, 0, 16).toUpper();
        const QString kThreadText = rowItem.threadId == 0U
            ? QStringLiteral("-")
            : QString::number(rowItem.threadId);
        const QString kVkModText = QStringLiteral("VK=0x%1 MOD=0x%2")
            .arg(rowItem.virtualKey, 2, 16, QChar('0'))
            .arg(rowItem.modifiers, 2, 16, QChar('0'))
            .toUpper();

        hotkeyTable_->setItem(kRow, 0, createHotkeyCell(rowItem.objectText));
        hotkeyTable_->setItem(kRow, 1, createHotkeyCell(kIdText));
        hotkeyTable_->setItem(kRow, 2, createHotkeyCell(rowItem.hotkeyText));
        hotkeyTable_->setItem(kRow, 3, createHotkeyCell(QString::number(rowItem.processId)));
        hotkeyTable_->setItem(kRow, 4, createHotkeyCell(kThreadText));
        hotkeyTable_->setItem(kRow, 5, createHotkeyCell(rowItem.processName));
        hotkeyTable_->setItem(kRow, 6, createHotkeyCell(rowItem.sourceText));
        hotkeyTable_->setItem(kRow, 7, createHotkeyCell(kVkModText));
        hotkeyTable_->setItem(kRow, 8, createHotkeyCell(rowItem.detailText));

        for (int column = 0; column < hotkeyTable_->columnCount(); ++column)
        {
            QTableWidgetItem* cellItem = hotkeyTable_->item(kRow, column);
            if (cellItem != nullptr)
            {
                cellItem->setData(kHotkeyRowIndexRole, static_cast<qulonglong>(rowCacheIndex));
                cellItem->setToolTip(cellItem->text());
            }
        }
    }

    hotkeyTable_->setSortingEnabled(true);
}

void ProcessDetailWindow::initializeKeyboardTab()
{
    KLogEvent initKeyboardTabEvent;
    info << initKeyboardTabEvent
        << "[ProcessDetailWindow] initializeKeyboardTab: 构建键盘页面。"
        << eol;

    keyboardLayout_ = new QVBoxLayout(keyboardTab_);
    keyboardLayout_->setContentsMargins(6, 6, 6, 6);
    keyboardLayout_->setSpacing(8);

    QGroupBox* keyboardGroup = new QGroupBox(QStringLiteral("键盘检测"), keyboardTab_);
    QVBoxLayout* keyboardGroupLayout = new QVBoxLayout(keyboardGroup);
    keyboardGroupLayout->setContentsMargins(8, 8, 8, 8);
    keyboardGroupLayout->setSpacing(6);

    QHBoxLayout* topBarLayout = new QHBoxLayout();
    refreshKeyboardButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新键盘"), keyboardGroup);
    refreshKeyboardButton_->setToolTip(QStringLiteral("扫描热键表和 WH_KEYBOARD/WH_KEYBOARD_LL 钩子链"));
    keyboardStatusLabel_ = new QLabel(QStringLiteral("● 尚未刷新"), keyboardGroup);
    keyboardStatusLabel_->setMinimumWidth(0);
    keyboardStatusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    keyboardStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(ksword_theme::textSecondaryHex()));
    topBarLayout->addWidget(refreshKeyboardButton_);
    topBarLayout->addWidget(keyboardStatusLabel_, 1);
    keyboardGroupLayout->addLayout(topBarLayout);

    keyboardInnerTabWidget_ = new QTabWidget(keyboardGroup);
    QWidget* hotkeyPage = new QWidget(keyboardInnerTabWidget_);
    QWidget* hookPage = new QWidget(keyboardInnerTabWidget_);
    keyboardTab_->setMinimumWidth(0);
    keyboardTab_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    keyboardGroup->setMinimumWidth(0);
    keyboardGroup->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    keyboardInnerTabWidget_->setMinimumWidth(0);
    keyboardInnerTabWidget_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    hotkeyPage->setMinimumWidth(0);
    hotkeyPage->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    hookPage->setMinimumWidth(0);
    hookPage->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    auto* hotkeyLayout = new QVBoxLayout(hotkeyPage);
    auto* hookLayout = new QVBoxLayout(hookPage);
    hotkeyLayout->setContentsMargins(0, 0, 0, 0);
    hookLayout->setContentsMargins(0, 0, 0, 0);

    keyboardHotkeyTable_ = new ks::ui::VisibleTableWidget(hotkeyPage);
    keyboardHotkeyTable_->setColumnCount(9);
    keyboardHotkeyTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("对象"),
        QStringLiteral("热键ID"),
        QStringLiteral("热键"),
        QStringLiteral("进程ID"),
        QStringLiteral("线程ID"),
        QStringLiteral("进程名"),
        QStringLiteral("来源"),
        QStringLiteral("VK/Mod"),
        QStringLiteral("详情")
    });
    keyboardHotkeyTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    keyboardHotkeyTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    keyboardHotkeyTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    keyboardHotkeyTable_->setAlternatingRowColors(true);
    keyboardHotkeyTable_->setSortingEnabled(true);
    keyboardHotkeyTable_->verticalHeader()->setVisible(false);
    configureHotkeyTableGeometry(keyboardHotkeyTable_);
    keyboardHotkeyTable_->setColumnWidth(0, 260);
    keyboardHotkeyTable_->setColumnWidth(1, 80);
    keyboardHotkeyTable_->setColumnWidth(2, 130);
    keyboardHotkeyTable_->setColumnWidth(3, 80);
    keyboardHotkeyTable_->setColumnWidth(4, 80);
    keyboardHotkeyTable_->setColumnWidth(5, 120);
    keyboardHotkeyTable_->setColumnWidth(6, 150);
    keyboardHotkeyTable_->setColumnWidth(7, 120);
    installHotkeyTableContextMenu(keyboardHotkeyTable_, 3);
    hotkeyLayout->addWidget(keyboardHotkeyTable_, 1);

    keyboardHookTable_ = new ks::ui::VisibleTableWidget(hookPage);
    keyboardHookTable_->setColumnCount(10);
    keyboardHookTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("对象"),
        QStringLiteral("类型"),
        QStringLiteral("范围"),
        QStringLiteral("进程ID"),
        QStringLiteral("线程ID"),
        QStringLiteral("函数/偏移"),
        QStringLiteral("模块"),
        QStringLiteral("来源"),
        QStringLiteral("Flags"),
        QStringLiteral("详情")
    });
    keyboardHookTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    keyboardHookTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    keyboardHookTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    keyboardHookTable_->setAlternatingRowColors(true);
    keyboardHookTable_->setSortingEnabled(true);
    keyboardHookTable_->verticalHeader()->setVisible(false);
    configureHotkeyTableGeometry(keyboardHookTable_);
    keyboardHookTable_->setColumnWidth(0, 180);
    keyboardHookTable_->setColumnWidth(1, 120);
    keyboardHookTable_->setColumnWidth(2, 90);
    keyboardHookTable_->setColumnWidth(3, 80);
    keyboardHookTable_->setColumnWidth(4, 80);
    keyboardHookTable_->setColumnWidth(5, 150);
    keyboardHookTable_->setColumnWidth(6, 130);
    keyboardHookTable_->setColumnWidth(7, 160);
    keyboardHookTable_->setColumnWidth(8, 80);
    installHotkeyTableContextMenu(keyboardHookTable_, 3);
    hookLayout->addWidget(keyboardHookTable_, 1);

    keyboardInnerTabWidget_->addTab(hotkeyPage, QIcon(":/Icon/process_hotkey.svg"), QStringLiteral("热键"));
    keyboardInnerTabWidget_->addTab(hookPage, QIcon(":/Icon/process_critical.svg"), QStringLiteral("键盘钩子"));
    keyboardGroupLayout->addWidget(keyboardInnerTabWidget_, 1);
    keyboardLayout_->addWidget(keyboardGroup, 1);

    refreshKeyboardButton_->setStyleSheet(buildBlueButtonStyle());
}

void ProcessDetailWindow::updateKeyboardStatusLabel(const QString& statusText, const bool refreshing)
{
    if (keyboardStatusLabel_ == nullptr)
    {
        return;
    }

    keyboardStatusLabel_->setToolTip(statusText);
    keyboardStatusLabel_->setText(compactStatusText(statusText));
    if (refreshing)
    {
        keyboardStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }
    else if (statusText.contains(QStringLiteral("失败")) || statusText.contains(QStringLiteral("不可用")))
    {
        keyboardStatusLabel_->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
    }
    else
    {
        keyboardStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
    }
}

void ProcessDetailWindow::requestAsyncKeyboardRefresh()
{
    if (keyboardRefreshing_ || baseRecord_.pid == 0)
    {
        return;
    }

    keyboardInitialRefreshStarted_ = true;
    keyboardRefreshing_ = true;
    const std::uint64_t kTicketValue = ++keyboardRefreshTicket_;
    const std::uint32_t kPidValue = baseRecord_.pid;
    const QString kProcessNameText = QString::fromStdString(baseRecord_.processName);
    const QString kProcessImagePathText = QString::fromStdString(baseRecord_.imagePath);

    if (refreshKeyboardButton_ != nullptr)
    {
        refreshKeyboardButton_->setEnabled(false);
    }
    updateKeyboardStatusLabel(QStringLiteral("● 正在扫描键盘热键与钩子..."), true);

    if (keyboardRefreshProgressPid_ == 0)
    {
        keyboardRefreshProgressPid_ = kPro.addReusable(this, "进程详情", "扫描键盘");
    }
    kPro.set(keyboardRefreshProgressPid_, "枚举热键表和键盘钩子链", 0, 20.0f);

    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create(
        [guardThis, kTicketValue, kPidValue, kProcessNameText, kProcessImagePathText]()
        {
            KeyboardInspectRefreshResult refreshResult{};
            const auto kBeginTime = std::chrono::steady_clock::now();

            QString diagnosticText = QStringLiteral("R3窗口/菜单/资源/.lnk + R0 win32k热键/钩子");
            const std::vector<HotkeyCandidate> kHotkeyCandidates = collectHotkeysForProcess(
                kPidValue,
                kProcessNameText,
                kProcessImagePathText,
                diagnosticText);
            refreshResult.hotkeyRows.reserve(kHotkeyCandidates.size());
            for (const HotkeyCandidate& candidate : kHotkeyCandidates)
            {
                HotkeyInspectItem row{};
                row.objectText = candidate.objectText;
                row.hotkeyId = candidate.hotkeyId;
                row.modifiers = candidate.modifiers;
                row.virtualKey = candidate.virtualKey;
                row.hotkeyText = candidate.hotkeyText;
                row.processId = candidate.processId;
                row.threadId = candidate.threadId;
                row.processName = candidate.processName;
                row.sourceText = candidate.sourceText;
                row.detailText = candidate.detailText;
                row.hasR0MutationSnapshot = candidate.hasR0MutationSnapshot;
                row.r0MutationSnapshot = candidate.r0MutationSnapshot;
                refreshResult.hotkeyRows.push_back(std::move(row));
            }

            const std::vector<KeyboardHookCandidate> kHookCandidates =
                collectDriverKeyboardHooks(kPidValue, diagnosticText);
            refreshResult.hookRows.reserve(kHookCandidates.size());
            for (const KeyboardHookCandidate& candidate : kHookCandidates)
            {
                KeyboardHookInspectItem row{};
                row.objectText = candidate.objectText;
                row.typeText = candidate.typeText;
                row.scopeText = candidate.scopeText;
                row.processId = candidate.processId;
                row.threadId = candidate.threadId;
                row.procedureText = candidate.procedureText;
                row.moduleText = candidate.moduleText;
                row.sourceText = candidate.sourceText;
                row.flagsText = candidate.flagsText;
                row.detailText = candidate.detailText;
                refreshResult.hookRows.push_back(std::move(row));
            }

            refreshResult.diagnosticText = diagnosticText;
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kTicketValue, refreshResult]()
                {
                    if (guardThis == nullptr || guardThis->keyboardRefreshTicket_ != kTicketValue)
                    {
                        return;
                    }
                    guardThis->applyKeyboardRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });

    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyKeyboardRefreshResult(const KeyboardInspectRefreshResult& refreshResult)
{
    QPointer<ProcessDetailWindow> guardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("process-detail-keyboard-snapshot-apply"),
            {hotkeyTable_, keyboardHotkeyTable_, keyboardHookTable_},
            [guardThis, refreshResult]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->applyKeyboardRefreshResult(refreshResult);
                }
            }))
    {
        return;
    }

    keyboardRefreshing_ = false;
    if (refreshKeyboardButton_ != nullptr)
    {
        refreshKeyboardButton_->setEnabled(true);
    }

    keyboardHotkeyRows_ = refreshResult.hotkeyRows;
    keyboardHookRows_ = refreshResult.hookRows;
    hotkeyRows_ = refreshResult.hotkeyRows;
    rebuildKeyboardHotkeyTable();
    rebuildKeyboardHookTable();
    rebuildHotkeyTable();

    QString statusText = QStringLiteral("● 刷新完成 %1 ms | 热键:%2 | 键盘钩子:%3")
        .arg(refreshResult.elapsedMs)
        .arg(static_cast<qulonglong>(refreshResult.hotkeyRows.size()))
        .arg(static_cast<qulonglong>(refreshResult.hookRows.size()));
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
    }
    updateKeyboardStatusLabel(statusText, false);
    if (hotkeyStatusLabel_ != nullptr)
    {
        updateHotkeyStatusLabel(statusText, false);
    }

    if (keyboardRefreshProgressPid_ > 0)
    {
        kPro.set(keyboardRefreshProgressPid_, "键盘扫描完成", 100, 1.0f);
    }

    KLogEvent keyboardRefreshDoneEvent;
    info << keyboardRefreshDoneEvent
        << "[ProcessDetailWindow] 键盘扫描完成, pid="
        << baseRecord_.pid
        << ", hotkeys="
        << refreshResult.hotkeyRows.size()
        << ", hooks="
        << refreshResult.hookRows.size()
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::rebuildKeyboardHotkeyTable()
{
    if (keyboardHotkeyTable_ == nullptr)
    {
        return;
    }

    keyboardHotkeyTable_->setSortingEnabled(false);
    keyboardHotkeyTable_->setRowCount(0);

    for (const HotkeyInspectItem& rowItem : keyboardHotkeyRows_)
    {
        const int kRow = keyboardHotkeyTable_->rowCount();
        keyboardHotkeyTable_->insertRow(kRow);

        const QString kIdText = rowItem.hotkeyId == 0U
            ? QStringLiteral("0")
            : QStringLiteral("0x%1").arg(rowItem.hotkeyId, 0, 16).toUpper();
        const QString kThreadText = rowItem.threadId == 0U
            ? QStringLiteral("-")
            : QString::number(rowItem.threadId);
        const QString kVkModText = QStringLiteral("VK=0x%1 MOD=0x%2")
            .arg(rowItem.virtualKey, 2, 16, QChar('0'))
            .arg(rowItem.modifiers, 2, 16, QChar('0'))
            .toUpper();

        keyboardHotkeyTable_->setItem(kRow, 0, createHotkeyCell(rowItem.objectText));
        keyboardHotkeyTable_->setItem(kRow, 1, createHotkeyCell(kIdText));
        keyboardHotkeyTable_->setItem(kRow, 2, createHotkeyCell(rowItem.hotkeyText));
        keyboardHotkeyTable_->setItem(kRow, 3, createHotkeyCell(QString::number(rowItem.processId)));
        keyboardHotkeyTable_->setItem(kRow, 4, createHotkeyCell(kThreadText));
        keyboardHotkeyTable_->setItem(kRow, 5, createHotkeyCell(rowItem.processName));
        keyboardHotkeyTable_->setItem(kRow, 6, createHotkeyCell(rowItem.sourceText));
        keyboardHotkeyTable_->setItem(kRow, 7, createHotkeyCell(kVkModText));
        keyboardHotkeyTable_->setItem(kRow, 8, createHotkeyCell(rowItem.detailText));

        for (int column = 0; column < keyboardHotkeyTable_->columnCount(); ++column)
        {
            QTableWidgetItem* cellItem = keyboardHotkeyTable_->item(kRow, column);
            if (cellItem != nullptr)
            {
                cellItem->setToolTip(cellItem->text());
            }
        }
    }

    keyboardHotkeyTable_->setSortingEnabled(true);
}

void ProcessDetailWindow::rebuildKeyboardHookTable()
{
    if (keyboardHookTable_ == nullptr)
    {
        return;
    }

    keyboardHookTable_->setSortingEnabled(false);
    keyboardHookTable_->setRowCount(0);

    for (const KeyboardHookInspectItem& rowItem : keyboardHookRows_)
    {
        const int kRow = keyboardHookTable_->rowCount();
        keyboardHookTable_->insertRow(kRow);
        const QString kThreadText = rowItem.threadId == 0U
            ? QStringLiteral("-")
            : QString::number(rowItem.threadId);

        keyboardHookTable_->setItem(kRow, 0, createHotkeyCell(rowItem.objectText));
        keyboardHookTable_->setItem(kRow, 1, createHotkeyCell(rowItem.typeText));
        keyboardHookTable_->setItem(kRow, 2, createHotkeyCell(rowItem.scopeText));
        keyboardHookTable_->setItem(kRow, 3, createHotkeyCell(QString::number(rowItem.processId)));
        keyboardHookTable_->setItem(kRow, 4, createHotkeyCell(kThreadText));
        keyboardHookTable_->setItem(kRow, 5, createHotkeyCell(rowItem.procedureText));
        keyboardHookTable_->setItem(kRow, 6, createHotkeyCell(rowItem.moduleText));
        keyboardHookTable_->setItem(kRow, 7, createHotkeyCell(rowItem.sourceText));
        keyboardHookTable_->setItem(kRow, 8, createHotkeyCell(rowItem.flagsText));
        keyboardHookTable_->setItem(kRow, 9, createHotkeyCell(rowItem.detailText));

        for (int column = 0; column < keyboardHookTable_->columnCount(); ++column)
        {
            QTableWidgetItem* cellItem = keyboardHookTable_->item(kRow, column);
            if (cellItem != nullptr)
            {
                cellItem->setToolTip(cellItem->text());
            }
        }
    }

    keyboardHookTable_->setSortingEnabled(true);
}
