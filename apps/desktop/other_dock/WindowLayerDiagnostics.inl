#pragma once

// This module is compiled once through OtherDock.WindowProtection.cpp and injects
// a diagnostics tab with guarded, reversible layer operations. WindowDetailDialog
// publishes its target HWND as metadata so this companion never has to infer it
// from user-visible text.

#include <QApplication>
#include <QByteArray>
#include <QClipboard>
#include <QCoreApplication>
#include <QCursor>
#include <QDateTime>
#include <QDialog>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFontDatabase>
#include <QGridLayout>
#include <QGroupBox>
#include <QHash>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QMutex>
#include <QMutexLocker>
#include <QObject>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QTabWidget>
#include <QTextCursor>
#include <QTextDocument>
#include <QTimer>
#include <QVariant>
#include <QVBoxLayout>

#include "../internationalization/LanguageManager.h"

#include <algorithm>
#include <array>
#include <optional>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x00005000L
#endif

namespace ks::window::layerdiag
{
    constexpr char kAttachedProperty[] = "ksword.windowLayerDiagnostics.attached";
    constexpr char kTargetHwndProperty[] = "ksword.windowDetail.targetHwnd";
    constexpr DWORD kDwmwaExtendedFrameBounds = 9;
    constexpr DWORD kDwmwaCloaked = 14;
    constexpr int kWalkLimit = 100000;
    constexpr int kEventBlockLimit = 1000;
    constexpr int kRollbackSeconds = 10;
    constexpr DWORD kWindowBandDefault = 0;
    constexpr DWORD kWindowBandUiAccess = 2;

    QString uiText(const char* key, const char* fallback)
    {
        return ks::i18n::text(QString::fromLatin1(key), QString::fromUtf8(fallback));
    }

    void bindUiText(QObject* object, const char* key, const char* fallback)
    {
        ks::i18n::LanguageManager::instance().bindText(
            object, QString::fromLatin1(key), QString::fromUtf8(fallback));
    }

    QString hwndText(HWND hwnd)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(hwnd)), 0, 16)
            .toUpper();
    }

    QString hexText(quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16).toUpper();
    }

    QString yesNo(bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    QString errorText(DWORD error)
    {
        return QStringLiteral("%1 (%2)").arg(error).arg(hexText(error));
    }

    QString className(HWND hwnd)
    {
        std::array<wchar_t, 512> buffer{};
        const int kLength = ::GetClassNameW(hwnd, buffer.data(), static_cast<int>(buffer.size()));
        return kLength > 0 ? QString::fromWCharArray(buffer.data(), kLength) : QString();
    }

    QString windowTitle(HWND hwnd)
    {
        const int kLength = ::GetWindowTextLengthW(hwnd);
        if (kLength <= 0)
        {
            return QString();
        }
        std::vector<wchar_t> buffer(static_cast<std::size_t>(kLength) + 1U, L'\0');
        const int kCopied = ::GetWindowTextW(hwnd, buffer.data(), static_cast<int>(buffer.size()));
        return kCopied > 0 ? QString::fromWCharArray(buffer.data(), kCopied) : QString();
    }

    QString objectName(HANDLE handle)
    {
        if (handle == nullptr)
        {
            return QString();
        }
        DWORD bytes = 0;
        ::GetUserObjectInformationW(handle, UOI_NAME, nullptr, 0, &bytes);
        if (bytes == 0)
        {
            return QString();
        }
        std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1U, L'\0');
        if (::GetUserObjectInformationW(handle, UOI_NAME, buffer.data(), bytes, &bytes) == FALSE)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data());
    }

    struct LongPtrResult
    {
        bool ok = false;
        LONG_PTR value = 0;
        DWORD error = ERROR_SUCCESS;
    };

    LongPtrResult readLongPtr(HWND hwnd, int index)
    {
        LongPtrResult result;
        ::SetLastError(ERROR_SUCCESS);
        result.value = ::GetWindowLongPtrW(hwnd, index);
        result.error = ::GetLastError();
        result.ok = result.value != 0 || result.error == ERROR_SUCCESS;
        return result;
    }

    QString longPtrText(const LongPtrResult& result)
    {
        return result.ok
            ? hexText(static_cast<quint64>(result.value))
            : QStringLiteral("<失败: %1>").arg(errorText(result.error));
    }

    struct BandResult
    {
        bool available = false;
        bool ok = false;
        DWORD value = 0;
        DWORD error = ERROR_SUCCESS;
    };

    using SetWindowBandFunction = BOOL(WINAPI*)(HWND, HWND, DWORD);

    SetWindowBandFunction resolveSetWindowBandFunction()
    {
        static const SetWindowBandFunction kFunction = []() -> SetWindowBandFunction {
            const HMODULE kUser32 = ::GetModuleHandleW(L"user32.dll");
            return kUser32 != nullptr
                ? reinterpret_cast<SetWindowBandFunction>(::GetProcAddress(kUser32, "SetWindowBand"))
                : nullptr;
        }();
        return kFunction;
    }

    struct BandWriteResult
    {
        bool available = false;
        bool ok = false;
        DWORD error = ERROR_SUCCESS;
    };

    BandWriteResult writeBand(HWND hwnd, HWND insertAfter, DWORD band)
    {
        BandWriteResult result;
        const SetWindowBandFunction kFunction = resolveSetWindowBandFunction();
        result.available = kFunction != nullptr;
        if (kFunction == nullptr)
        {
            result.error = ERROR_PROC_NOT_FOUND;
            return result;
        }

        ::SetLastError(ERROR_SUCCESS);
        result.ok = kFunction(hwnd, insertAfter, band) != FALSE;
        result.error = result.ok ? ERROR_SUCCESS : ::GetLastError();
        return result;
    }

    BandResult readBand(HWND hwnd)
    {
        using Fn = BOOL(WINAPI*)(HWND, PDWORD);
        static const Fn kFn = []() -> Fn {
            const HMODULE kUser32 = ::GetModuleHandleW(L"user32.dll");
            return kUser32 != nullptr
                ? reinterpret_cast<Fn>(::GetProcAddress(kUser32, "GetWindowBand"))
                : nullptr;
        }();

        BandResult result;
        result.available = kFn != nullptr;
        if (kFn == nullptr)
        {
            result.error = ERROR_PROC_NOT_FOUND;
            return result;
        }

        DWORD value = 0xFFFFFFFFUL;
        ::SetLastError(ERROR_SUCCESS);
        result.ok = kFn(hwnd, &value) != FALSE;
        result.error = result.ok ? ERROR_SUCCESS : ::GetLastError();
        if (result.ok)
        {
            result.value = value;
        }
        return result;
    }

    QString bandName(DWORD value)
    {
        switch (value)
        {
        case 0: return QStringLiteral("ZBID_DEFAULT");
        case 1: return QStringLiteral("ZBID_DESKTOP");
        case 2: return QStringLiteral("ZBID_UIACCESS");
        case 3: return QStringLiteral("ZBID_IMMERSIVE_IHM");
        case 4: return QStringLiteral("ZBID_IMMERSIVE_NOTIFICATION");
        case 5: return QStringLiteral("ZBID_IMMERSIVE_APPCHROME");
        case 6: return QStringLiteral("ZBID_IMMERSIVE_MOGO");
        case 7: return QStringLiteral("ZBID_IMMERSIVE_EDGY");
        case 8: return QStringLiteral("ZBID_IMMERSIVE_INACTIVEMOBODY");
        case 9: return QStringLiteral("ZBID_IMMERSIVE_INACTIVEDOCK");
        case 10: return QStringLiteral("ZBID_IMMERSIVE_ACTIVEMOBODY");
        case 11: return QStringLiteral("ZBID_IMMERSIVE_ACTIVEDOCK");
        case 12: return QStringLiteral("ZBID_IMMERSIVE_BACKGROUND");
        case 13: return QStringLiteral("ZBID_IMMERSIVE_SEARCH");
        case 14: return QStringLiteral("ZBID_GENUINE_WINDOWS");
        case 15: return QStringLiteral("ZBID_IMMERSIVE_RESTRICTED");
        case 16: return QStringLiteral("ZBID_SYSTEM_TOOLS");
        case 17: return QStringLiteral("ZBID_LOCK");
        case 18: return QStringLiteral("ZBID_ABOVELOCK_UX");
        default: return QStringLiteral("ZBID_UNKNOWN");
        }
    }

    struct ZOrderResult
    {
        int globalIndex = -1;
        int bandIndex = -1;
        int bandWindowCount = 0;
        int topMostGroupIndex = -1;
        int topMostGroupWindowCount = 0;
    };

    ZOrderResult zOrder(HWND target, const BandResult& targetBand, bool targetTopMost)
    {
        ZOrderResult result;
        QSet<quintptr> visited;
        HWND current = ::GetTopWindow(nullptr);
        for (int index = 0; current != nullptr && index < kWalkLimit; ++index)
        {
            const quintptr kRaw = reinterpret_cast<quintptr>(current);
            if (visited.contains(kRaw))
            {
                break;
            }
            visited.insert(kRaw);
            if (current == target)
            {
                result.globalIndex = index;
            }

            // Global Z order crosses bands.  Counting only peers with the
            // same observed band makes the diagnostic answer the question
            // users actually have: where is this window among its own layer?
            if (targetBand.ok)
            {
                const BandResult kCurrentBand = readBand(current);
                if (kCurrentBand.ok && kCurrentBand.value == targetBand.value)
                {
                    if (current == target)
                    {
                        result.bandIndex = result.bandWindowCount;
                    }
                    ++result.bandWindowCount;

                    const LongPtrResult kCurrentExStyle = readLongPtr(current, GWL_EXSTYLE);
                    const bool kCurrentTopMost = kCurrentExStyle.ok && (kCurrentExStyle.value & WS_EX_TOPMOST) != 0;
                    if (kCurrentTopMost == targetTopMost)
                    {
                        if (current == target)
                        {
                            result.topMostGroupIndex = result.topMostGroupWindowCount;
                        }
                        ++result.topMostGroupWindowCount;
                    }
                }
            }
            current = ::GetWindow(current, GW_HWNDNEXT);
        }
        return result;
    }

    struct TokenInfo
    {
        bool opened = false;
        DWORD error = ERROR_SUCCESS;
        QString integrity;
        bool integrityKnown = false;
        DWORD integrityRid = 0;
        bool uiAccessKnown = false;
        bool uiAccess = false;
        bool appContainerKnown = false;
        bool appContainer = false;
        bool sessionKnown = false;
        DWORD sessionId = 0;
    };

    QString integrityName(DWORD rid)
    {
        if (rid < SECURITY_MANDATORY_LOW_RID) return QStringLiteral("Untrusted");
        if (rid < SECURITY_MANDATORY_MEDIUM_RID) return QStringLiteral("Low");
        if (rid < SECURITY_MANDATORY_HIGH_RID) return QStringLiteral("Medium");
        if (rid < SECURITY_MANDATORY_SYSTEM_RID) return QStringLiteral("High");
        if (rid < SECURITY_MANDATORY_PROTECTED_PROCESS_RID) return QStringLiteral("System");
        return QStringLiteral("Protected");
    }

    TokenInfo tokenInfo(DWORD pid)
    {
        TokenInfo result;
        HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (process == nullptr)
        {
            result.error = ::GetLastError();
            return result;
        }

        HANDLE token = nullptr;
        if (::OpenProcessToken(process, TOKEN_QUERY, &token) == FALSE)
        {
            result.error = ::GetLastError();
            ::CloseHandle(process);
            return result;
        }
        result.opened = true;

        DWORD bytes = 0;
        ::GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &bytes);
        if (bytes > 0)
        {
            QByteArray buffer(static_cast<int>(bytes), '\0');
            if (::GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), bytes, &bytes) != FALSE)
            {
                const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.constData());
                if (label->Label.Sid != nullptr && ::IsValidSid(label->Label.Sid) != FALSE)
                {
                    const UCHAR kCount = *::GetSidSubAuthorityCount(label->Label.Sid);
                    if (kCount > 0)
                    {
                        const DWORD kRid = *::GetSidSubAuthority(label->Label.Sid, kCount - 1U);
                        result.integrityKnown = true;
                        result.integrityRid = kRid;
                        result.integrity = QStringLiteral("%1 RID=%2")
                            .arg(integrityName(kRid))
                            .arg(hexText(kRid));
                    }
                }
            }
        }

        DWORD value = 0;
        DWORD returned = 0;
        if (::GetTokenInformation(token, TokenUIAccess, &value, sizeof(value), &returned) != FALSE)
        {
            result.uiAccessKnown = true;
            result.uiAccess = value != 0;
        }
        value = 0;
        if (::GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value), &returned) != FALSE)
        {
            result.appContainerKnown = true;
            result.appContainer = value != 0;
        }
        value = 0;
        if (::GetTokenInformation(token, TokenSessionId, &value, sizeof(value), &returned) != FALSE)
        {
            result.sessionKnown = true;
            result.sessionId = value;
        }

        ::CloseHandle(token);
        ::CloseHandle(process);
        return result;
    }

    struct Snapshot
    {
        QDateTime time;
        HWND hwnd = nullptr;
        bool valid = false;
        bool visible = false;
        bool enabled = false;
        DWORD pid = 0;
        DWORD tid = 0;
        QString title;
        QString cls;
        RECT rect{};
        bool rectKnown = false;
        LongPtrResult style;
        LongPtrResult exStyle;
        LongPtrResult wndProc;
        LongPtrResult userData;
        LongPtrResult hInstance;
        BandResult band;
        HWND parent = nullptr;
        HWND owner = nullptr;
        HWND root = nullptr;
        HWND rootOwner = nullptr;
        HWND previous = nullptr;
        HWND next = nullptr;
        HWND top = nullptr;
        int z = -1;
        int bandZ = -1;
        int bandWindowCount = 0;
        int topMostGroupZ = -1;
        int topMostGroupWindowCount = 0;
        bool dwmAvailable = false;
        bool cloakedKnown = false;
        DWORD cloaked = 0;
        HRESULT cloakedHr = E_NOTIMPL;
        bool frameKnown = false;
        RECT frame{};
        HRESULT frameHr = E_NOTIMPL;
        bool guiKnown = false;
        DWORD guiError = ERROR_SUCCESS;
        GUITHREADINFO gui{};
        HWND foreground = nullptr;
        bool affinityKnown = false;
        DWORD affinity = 0;
        DWORD affinityError = ERROR_SUCCESS;
        bool layeredKnown = false;
        COLORREF colorKey = 0;
        BYTE alpha = 255;
        DWORD layeredFlags = 0;
        DWORD layeredError = ERROR_SUCCESS;
        POINT probe{};
        HWND hit = nullptr;
        HWND hitRoot = nullptr;
        HWND childHit = nullptr;
        HWND realChildHit = nullptr;
        TokenInfo token;
        QString desktop;
        QString inspectorWindowStation;
    };

    Snapshot capture(HWND hwnd)
    {
        Snapshot s;
        s.time = QDateTime::currentDateTime();
        s.hwnd = hwnd;
        s.valid = ::IsWindow(hwnd) != FALSE;
        if (!s.valid)
        {
            return s;
        }

        s.visible = ::IsWindowVisible(hwnd) != FALSE;
        s.enabled = ::IsWindowEnabled(hwnd) != FALSE;
        s.tid = ::GetWindowThreadProcessId(hwnd, &s.pid);
        s.title = windowTitle(hwnd);
        s.cls = className(hwnd);
        s.rectKnown = ::GetWindowRect(hwnd, &s.rect) != FALSE;
        s.style = readLongPtr(hwnd, GWL_STYLE);
        s.exStyle = readLongPtr(hwnd, GWL_EXSTYLE);
        s.wndProc = readLongPtr(hwnd, GWLP_WNDPROC);
        s.userData = readLongPtr(hwnd, GWLP_USERDATA);
        s.hInstance = readLongPtr(hwnd, GWLP_HINSTANCE);
        s.band = readBand(hwnd);
        s.parent = ::GetParent(hwnd);
        s.owner = ::GetWindow(hwnd, GW_OWNER);
        s.root = ::GetAncestor(hwnd, GA_ROOT);
        s.rootOwner = ::GetAncestor(hwnd, GA_ROOTOWNER);
        s.previous = ::GetWindow(hwnd, GW_HWNDPREV);
        s.next = ::GetWindow(hwnd, GW_HWNDNEXT);
        s.top = ::GetTopWindow(nullptr);
        const bool kTargetTopMost = s.exStyle.ok && (s.exStyle.value & WS_EX_TOPMOST) != 0;
        const ZOrderResult kOrder = zOrder(hwnd, s.band, kTargetTopMost);
        s.z = kOrder.globalIndex;
        s.bandZ = kOrder.bandIndex;
        s.bandWindowCount = kOrder.bandWindowCount;
        s.topMostGroupZ = kOrder.topMostGroupIndex;
        s.topMostGroupWindowCount = kOrder.topMostGroupWindowCount;

        using DwmFn = HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);
        static const DwmFn kDwm = []() -> DwmFn {
            const HMODULE kModule = ::LoadLibraryW(L"dwmapi.dll");
            return kModule != nullptr
                ? reinterpret_cast<DwmFn>(::GetProcAddress(kModule, "DwmGetWindowAttribute"))
                : nullptr;
        }();
        s.dwmAvailable = kDwm != nullptr;
        if (kDwm != nullptr)
        {
            s.cloakedHr = kDwm(hwnd, kDwmwaCloaked, &s.cloaked, sizeof(s.cloaked));
            s.cloakedKnown = SUCCEEDED(s.cloakedHr);
            s.frameHr = kDwm(hwnd, kDwmwaExtendedFrameBounds, &s.frame, sizeof(s.frame));
            s.frameKnown = SUCCEEDED(s.frameHr);
        }

        s.gui.cbSize = sizeof(s.gui);
        ::SetLastError(ERROR_SUCCESS);
        s.guiKnown = ::GetGUIThreadInfo(s.tid, &s.gui) != FALSE;
        s.guiError = s.guiKnown ? ERROR_SUCCESS : ::GetLastError();
        s.foreground = ::GetForegroundWindow();

        ::SetLastError(ERROR_SUCCESS);
        s.affinityKnown = ::GetWindowDisplayAffinity(hwnd, &s.affinity) != FALSE;
        s.affinityError = s.affinityKnown ? ERROR_SUCCESS : ::GetLastError();

        ::SetLastError(ERROR_SUCCESS);
        s.layeredKnown = ::GetLayeredWindowAttributes(
            hwnd, &s.colorKey, &s.alpha, &s.layeredFlags) != FALSE;
        s.layeredError = s.layeredKnown ? ERROR_SUCCESS : ::GetLastError();

        if (s.rectKnown)
        {
            s.probe.x = s.rect.left + (s.rect.right - s.rect.left) / 2;
            s.probe.y = s.rect.top + (s.rect.bottom - s.rect.top) / 2;
            s.hit = ::WindowFromPoint(s.probe);
            s.hitRoot = s.hit != nullptr ? ::GetAncestor(s.hit, GA_ROOT) : nullptr;
            POINT client = s.probe;
            if (::ScreenToClient(hwnd, &client) != FALSE)
            {
                s.childHit = ::ChildWindowFromPointEx(hwnd, client, CWP_ALL);
                s.realChildHit = ::RealChildWindowFromPoint(hwnd, client);
            }
        }

        s.token = tokenInfo(s.pid);
        s.desktop = objectName(::GetThreadDesktop(s.tid));
        s.inspectorWindowStation = objectName(::GetProcessWindowStation());
        return s;
    }

    bool hasStyleFlag(const Snapshot& snapshot, LONG_PTR flag)
    {
        return snapshot.style.ok && (snapshot.style.value & flag) != 0;
    }

    bool hasExStyleFlag(const Snapshot& snapshot, LONG_PTR flag)
    {
        return snapshot.exStyle.ok && (snapshot.exStyle.value & flag) != 0;
    }

    bool sameWindowIdentity(const Snapshot& baseline, HWND hwnd)
    {
        if (hwnd == nullptr || ::IsWindow(hwnd) == FALSE)
        {
            return false;
        }
        DWORD pid = 0;
        const DWORD kTid = ::GetWindowThreadProcessId(hwnd, &pid);
        return pid == baseline.pid && kTid == baseline.tid && className(hwnd) == baseline.cls;
    }

    QString windowNodeText(HWND hwnd)
    {
        if (hwnd == nullptr)
        {
            return QStringLiteral("<none>");
        }

        DWORD pid = 0;
        const DWORD kTid = ::GetWindowThreadProcessId(hwnd, &pid);
        const BandResult kBand = readBand(hwnd);
        const QString kBandText = kBand.ok
            ? QStringLiteral("%1(%2)").arg(bandName(kBand.value)).arg(kBand.value)
            : QStringLiteral("<unavailable>");
        const QString kTitle = windowTitle(hwnd);
        return QStringLiteral("%1  PID/TID=%2/%3  Band=%4  Class=%5  Title=%6")
            .arg(hwndText(hwnd))
            .arg(pid)
            .arg(kTid)
            .arg(kBandText, className(hwnd), kTitle.isEmpty() ? QStringLiteral("<empty>") : kTitle);
    }

    struct OwnedWindowEnumContext
    {
        HWND owner = nullptr;
        std::vector<HWND>* windows = nullptr;
    };

    std::vector<HWND> directOwnedWindows(HWND owner)
    {
        std::vector<HWND> windows;
        OwnedWindowEnumContext context{ owner, &windows };
        ::EnumWindows([](HWND hwnd, LPARAM parameter) -> BOOL {
            auto* current = reinterpret_cast<OwnedWindowEnumContext*>(parameter);
            if (current != nullptr && current->windows != nullptr && ::GetWindow(hwnd, GW_OWNER) == current->owner)
            {
                current->windows->push_back(hwnd);
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&context));
        return windows;
    }

    void appendOwnedTree(
        HWND owner,
        const QString& prefix,
        int depth,
        QSet<quintptr>* visited,
        QStringList* lines)
    {
        if (visited == nullptr || lines == nullptr || depth > 12)
        {
            return;
        }

        const std::vector<HWND> kChildren = directOwnedWindows(owner);
        for (std::size_t index = 0; index < kChildren.size(); ++index)
        {
            const HWND kChild = kChildren[index];
            const quintptr kRaw = reinterpret_cast<quintptr>(kChild);
            const bool kLast = index + 1U == kChildren.size();
            lines->append(prefix + (kLast ? QStringLiteral("└─ ") : QStringLiteral("├─ ")) + windowNodeText(kChild));
            if (visited->contains(kRaw))
            {
                lines->append(prefix + QStringLiteral("   <cycle>"));
                continue;
            }
            visited->insert(kRaw);
            appendOwnedTree(
                kChild,
                prefix + (kLast ? QStringLiteral("   ") : QStringLiteral("│  ")),
                depth + 1,
                visited,
                lines);
        }
    }

    QString relationshipGraph(HWND target)
    {
        QStringList lines;
        lines << uiText("window.layer.relations.target", "[目标]");
        lines << windowNodeText(target);

        lines << QString() << uiText("window.layer.relations.parent_chain", "[Parent 链]");
        QSet<quintptr> visitedParents;
        HWND current = ::GetParent(target);
        if (current == nullptr)
        {
            lines << QStringLiteral("<none>");
        }
        for (int depth = 0; current != nullptr && depth < 32; ++depth)
        {
            const quintptr kRaw = reinterpret_cast<quintptr>(current);
            lines << QString(depth * 2, QChar(' ')) + QStringLiteral("└─ ") + windowNodeText(current);
            if (visitedParents.contains(kRaw))
            {
                lines << QStringLiteral("<cycle>");
                break;
            }
            visitedParents.insert(kRaw);
            current = ::GetParent(current);
        }

        lines << QString() << uiText("window.layer.relations.owner_chain", "[Owner 链]");
        QSet<quintptr> visitedOwners;
        current = ::GetWindow(target, GW_OWNER);
        if (current == nullptr)
        {
            lines << QStringLiteral("<none>");
        }
        for (int depth = 0; current != nullptr && depth < 32; ++depth)
        {
            const quintptr kRaw = reinterpret_cast<quintptr>(current);
            lines << QString(depth * 2, QChar(' ')) + QStringLiteral("└─ ") + windowNodeText(current);
            if (visitedOwners.contains(kRaw))
            {
                lines << QStringLiteral("<cycle>");
                break;
            }
            visitedOwners.insert(kRaw);
            current = ::GetWindow(current, GW_OWNER);
        }

        lines << QString() << uiText("window.layer.relations.roots", "[Root / RootOwner / LastActivePopup]");
        lines << QStringLiteral("GA_ROOT: %1").arg(windowNodeText(::GetAncestor(target, GA_ROOT)));
        lines << QStringLiteral("GA_ROOTOWNER: %1").arg(windowNodeText(::GetAncestor(target, GA_ROOTOWNER)));
        lines << QStringLiteral("GetLastActivePopup: %1").arg(windowNodeText(::GetLastActivePopup(target)));

        lines << QString() << uiText("window.layer.relations.owned_tree", "[直接/间接 Owned 窗口树]");
        QSet<quintptr> visitedOwned;
        visitedOwned.insert(reinterpret_cast<quintptr>(target));
        const int kBeforeTreeLineCount = lines.size();
        appendOwnedTree(target, QString(), 0, &visitedOwned, &lines);
        if (lines.size() == kBeforeTreeLineCount)
        {
            lines << QStringLiteral("<none>");
        }
        return lines.join(QChar::LineFeed);
    }

    QString diagnosisText(const Snapshot& snapshot)
    {
        const TokenInfo kInspector = tokenInfo(::GetCurrentProcessId());
        const QString kInspectorDesktop = objectName(::GetThreadDesktop(::GetCurrentThreadId()));
        QStringList blockers;
        QStringList cautions;
        QStringList capabilities;

        if (!snapshot.valid)
        {
            blockers << uiText("window.layer.diagnosis.invalid", "目标 HWND 已失效，不能执行层级操作。");
        }
        if (hasStyleFlag(snapshot, WS_CHILD))
        {
            cautions << uiText("window.layer.diagnosis.child", "目标是子窗口；Z 序只在同一父窗口的兄弟窗口之间有意义，不能设置 Window Band。");
        }
        if (snapshot.token.sessionKnown && kInspector.sessionKnown && snapshot.token.sessionId != kInspector.sessionId)
        {
            blockers << uiText("window.layer.diagnosis.session", "目标与 KSword 位于不同 Session，User32 层级操作不会跨 Session 生效。");
        }
        if (!snapshot.desktop.isEmpty() && !kInspectorDesktop.isEmpty() && snapshot.desktop != kInspectorDesktop)
        {
            blockers << uiText("window.layer.diagnosis.desktop", "目标与 KSword 位于不同 Desktop；当前线程不能直接调整其 Z 序。");
        }
        if (snapshot.token.integrityKnown && kInspector.integrityKnown &&
            snapshot.token.integrityRid > kInspector.integrityRid && !(kInspector.uiAccessKnown && kInspector.uiAccess))
        {
            blockers << uiText("window.layer.diagnosis.uipi", "目标完整性级别高于 KSword，且当前令牌没有 UIAccess；操作可能被 UIPI 拒绝。");
        }
        if (snapshot.token.appContainerKnown && snapshot.token.appContainer)
        {
            cautions << uiText("window.layer.diagnosis.app_container", "目标属于 AppContainer；部分窗口属性和跨进程操作会被限制。");
        }
        if (snapshot.band.ok && snapshot.band.value != kWindowBandDefault && snapshot.band.value != kWindowBandUiAccess)
        {
            cautions << uiText("window.layer.diagnosis.special_band", "目标位于系统或沉浸式 Window Band；Band ID 不能按数字比较，系统可能拒绝移动。");
        }
        if (snapshot.cloakedKnown && snapshot.cloaked != 0)
        {
            cautions << uiText("window.layer.diagnosis.cloaked", "目标被 DWM Cloak；改变 Z 序不一定会让它出现在屏幕上。");
        }
        if (snapshot.owner != nullptr || snapshot.rootOwner != snapshot.root)
        {
            cautions << uiText("window.layer.diagnosis.owner", "目标存在 Owner/Owned 关系；TopMost 变化可能连带影响整个所有者窗口组。");
        }
        if (hasExStyleFlag(snapshot, WS_EX_NOACTIVATE))
        {
            cautions << uiText("window.layer.diagnosis.no_activate", "目标带 WS_EX_NOACTIVATE；置顶不代表能够获得前台焦点。");
        }
        if (!snapshot.band.available)
        {
            blockers << uiText("window.layer.diagnosis.band_api_missing", "当前系统未导出 GetWindowBand，无法验证 Band 操作结果。");
        }
        if (resolveSetWindowBandFunction() == nullptr)
        {
            blockers << uiText("window.layer.diagnosis.set_band_missing", "当前系统未导出 SetWindowBand，UIAccess Band 操作不可用。");
        }

        capabilities << uiText("window.layer.diagnosis.inspector_token", "KSword：Integrity=%1，TokenUIAccess=%2，Session=%3，Desktop=%4")
            .arg(kInspector.integrity.isEmpty() ? QStringLiteral("<unknown>") : kInspector.integrity)
            .arg(kInspector.uiAccessKnown ? yesNo(kInspector.uiAccess) : QStringLiteral("<unknown>"))
            .arg(kInspector.sessionKnown ? QString::number(kInspector.sessionId) : QStringLiteral("<unknown>"))
            .arg(kInspectorDesktop.isEmpty() ? QStringLiteral("<unknown>") : kInspectorDesktop);
        capabilities << uiText("window.layer.diagnosis.target_token", "目标：Integrity=%1，TokenUIAccess=%2，Session=%3，Desktop=%4")
            .arg(snapshot.token.integrity.isEmpty() ? QStringLiteral("<unknown>") : snapshot.token.integrity)
            .arg(snapshot.token.uiAccessKnown ? yesNo(snapshot.token.uiAccess) : QStringLiteral("<unknown>"))
            .arg(snapshot.token.sessionKnown ? QString::number(snapshot.token.sessionId) : QStringLiteral("<unknown>"))
            .arg(snapshot.desktop.isEmpty() ? QStringLiteral("<unknown>") : snapshot.desktop);
        capabilities << (kInspector.uiAccessKnown && kInspector.uiAccess
            ? uiText("window.layer.diagnosis.uiaccess_ready", "当前 KSword 令牌已带 UIAccess，可尝试实验性 UIAccess Band 操作。")
            : uiText("window.layer.diagnosis.uiaccess_missing", "当前 KSword 令牌没有 UIAccess；请使用主窗口 UIAccess 按钮重启后再试 UIAccess Band。"));

        QStringList out;
        out << uiText("window.layer.diagnosis.capabilities", "[能力状态]");
        out << capabilities;
        out << QString() << uiText("window.layer.diagnosis.blockers", "[可能阻断项]");
        out << (blockers.isEmpty() ? QStringList{ uiText("window.layer.diagnosis.none", "未发现明确阻断项；最终以 API 返回值和回读结果为准。") } : blockers);
        out << QString() << uiText("window.layer.diagnosis.cautions", "[风险提示]");
        out << (cautions.isEmpty() ? QStringList{ uiText("window.layer.diagnosis.no_cautions", "未发现额外结构风险。") } : cautions);
        out << QString() << uiText("window.layer.diagnosis.foreground_note", "说明：置顶、前台激活和实际像素命中是不同状态；本页分别验证，不将其合并为一个“层级”。");
        return out.join(QChar::LineFeed);
    }

    QString rectText(const RECT& r)
    {
        return QStringLiteral("[%1,%2,%3,%4]")
            .arg(r.left).arg(r.top).arg(r.right).arg(r.bottom);
    }

    QString keyFlags(const Snapshot& s)
    {
        if (!s.style.ok || !s.exStyle.ok)
        {
            return QStringLiteral("<样式读取失败>");
        }
        const quint64 kStyle = static_cast<quint64>(s.style.value);
        const quint64 kEx = static_cast<quint64>(s.exStyle.value);
        QStringList flags;
        if ((kStyle & WS_VISIBLE) != 0) flags << QStringLiteral("WS_VISIBLE");
        if ((kStyle & WS_CHILD) != 0) flags << QStringLiteral("WS_CHILD");
        if ((kStyle & WS_POPUP) != 0) flags << QStringLiteral("WS_POPUP");
        if ((kEx & WS_EX_TOPMOST) != 0) flags << QStringLiteral("WS_EX_TOPMOST");
        if ((kEx & WS_EX_TOOLWINDOW) != 0) flags << QStringLiteral("WS_EX_TOOLWINDOW");
        if ((kEx & WS_EX_LAYERED) != 0) flags << QStringLiteral("WS_EX_LAYERED");
        if ((kEx & WS_EX_TRANSPARENT) != 0) flags << QStringLiteral("WS_EX_TRANSPARENT");
        if ((kEx & WS_EX_NOACTIVATE) != 0) flags << QStringLiteral("WS_EX_NOACTIVATE");
#ifdef WS_EX_NOREDIRECTIONBITMAP
        if ((kEx & WS_EX_NOREDIRECTIONBITMAP) != 0) flags << QStringLiteral("WS_EX_NOREDIRECTIONBITMAP");
#endif
        return flags.isEmpty() ? QStringLiteral("<无关键标志>") : flags.join(QStringLiteral(" | "));
    }

    QString snapshotText(const Snapshot& s, DWORD initialPid, DWORD initialTid, const QString& initialClass)
    {
        QStringList out;
        out << QStringLiteral("CapturedAt: %1").arg(s.time.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")));
        out << QStringLiteral("HWND: %1").arg(hwndText(s.hwnd));
        out << QStringLiteral("Valid: %1").arg(yesNo(s.valid));
        if (!s.valid)
        {
            out << QStringLiteral("警告: 目标 HWND 已失效。");
            return out.join(QChar::LineFeed);
        }

        const bool kReused = s.pid != initialPid || s.tid != initialTid || s.cls != initialClass;
        out << QStringLiteral("Title: %1").arg(s.title.isEmpty() ? QStringLiteral("<空>") : s.title);
        out << QStringLiteral("Class: %1").arg(s.cls);
        out << QStringLiteral("PID/TID: %1 / %2").arg(s.pid).arg(s.tid);
        out << QStringLiteral("Visible/Enabled: %1 / %2").arg(yesNo(s.visible), yesNo(s.enabled));
        out << QStringLiteral("WindowRect: %1").arg(s.rectKnown ? rectText(s.rect) : QStringLiteral("<失败>"));
        out << QStringLiteral("HWND identity changed: %1").arg(yesNo(kReused));
        if (kReused) out << QStringLiteral("警告: HWND 可能已销毁并被复用。");

        out << QString() << QStringLiteral("[Window Band / Z-order]");
        if (!s.band.available)
            out << QStringLiteral("GetWindowBand: <API 不可用>");
        else if (!s.band.ok)
            out << QStringLiteral("GetWindowBand: <失败: %1>").arg(errorText(s.band.error));
        else
            out << QStringLiteral("GetWindowBand: %1 / %2 (%3)")
                .arg(s.band.value).arg(hexText(s.band.value), bandName(s.band.value));
        out << QStringLiteral("注意: ZBID 数字是标识符，不是可按大小排序的置顶高度。");
        out << QStringLiteral("Top-level Z index: %1").arg(s.z);
        out << QStringLiteral("Same-band Z index: %1 / %2")
            .arg(s.bandZ)
            .arg(s.band.ok ? QString::number(s.bandWindowCount) : QStringLiteral("<不可用>"));
        out << QStringLiteral("Same-band TopMost-group Z index: %1 / %2")
            .arg(s.topMostGroupZ)
            .arg(s.band.ok ? QString::number(s.topMostGroupWindowCount) : QStringLiteral("<不可用>"));
        out << QStringLiteral("GetTopWindow(NULL): %1").arg(hwndText(s.top));
        out << QStringLiteral("GW_HWNDPREV / NEXT: %1 / %2").arg(hwndText(s.previous), hwndText(s.next));

        out << QString() << QStringLiteral("[Styles / error-aware reads]");
        out << QStringLiteral("GWL_STYLE: %1").arg(longPtrText(s.style));
        out << QStringLiteral("GWL_EXSTYLE: %1").arg(longPtrText(s.exStyle));
        out << QStringLiteral("GWLP_WNDPROC: %1").arg(longPtrText(s.wndProc));
        out << QStringLiteral("GWLP_USERDATA: %1").arg(longPtrText(s.userData));
        out << QStringLiteral("GWLP_HINSTANCE: %1").arg(longPtrText(s.hInstance));
        out << QStringLiteral("关键标志: %1").arg(keyFlags(s));

        out << QString() << QStringLiteral("[Relationships]");
        out << QStringLiteral("GetParent: %1").arg(hwndText(s.parent));
        out << QStringLiteral("GW_OWNER: %1").arg(hwndText(s.owner));
        out << QStringLiteral("GA_ROOT: %1").arg(hwndText(s.root));
        out << QStringLiteral("GA_ROOTOWNER: %1").arg(hwndText(s.rootOwner));

        out << QString() << QStringLiteral("[DWM]");
        if (!s.dwmAvailable)
            out << QStringLiteral("DwmGetWindowAttribute: <API 不可用>");
        else
        {
            out << QStringLiteral("DWMWA_CLOAKED: %1")
                .arg(s.cloakedKnown ? hexText(s.cloaked)
                                    : QStringLiteral("<失败 HRESULT=%1>").arg(hexText(static_cast<quint64>(s.cloakedHr))));
            out << QStringLiteral("DWMWA_EXTENDED_FRAME_BOUNDS: %1")
                .arg(s.frameKnown ? rectText(s.frame)
                                  : QStringLiteral("<失败 HRESULT=%1>").arg(hexText(static_cast<quint64>(s.frameHr))));
        }

        out << QString() << QStringLiteral("[GUI thread]");
        out << QStringLiteral("ForegroundWindow: %1").arg(hwndText(s.foreground));
        if (s.guiKnown)
        {
            out << QStringLiteral("Active: %1").arg(hwndText(s.gui.hwndActive));
            out << QStringLiteral("Focus: %1").arg(hwndText(s.gui.hwndFocus));
            out << QStringLiteral("Capture: %1").arg(hwndText(s.gui.hwndCapture));
            out << QStringLiteral("Caret: %1").arg(hwndText(s.gui.hwndCaret));
            out << QStringLiteral("MenuOwner: %1").arg(hwndText(s.gui.hwndMenuOwner));
        }
        else out << QStringLiteral("GetGUIThreadInfo: <失败: %1>").arg(errorText(s.guiError));

        out << QString() << QStringLiteral("[Security / desktop]");
        if (!s.token.opened)
            out << QStringLiteral("Process token: <失败: %1>").arg(errorText(s.token.error));
        else
        {
            out << QStringLiteral("Integrity: %1").arg(s.token.integrity.isEmpty() ? QStringLiteral("<未知>") : s.token.integrity);
            out << QStringLiteral("TokenUIAccess: %1").arg(s.token.uiAccessKnown ? yesNo(s.token.uiAccess) : QStringLiteral("<未知>"));
            out << QStringLiteral("AppContainer: %1").arg(s.token.appContainerKnown ? yesNo(s.token.appContainer) : QStringLiteral("<未知>"));
            out << QStringLiteral("SessionId: %1").arg(s.token.sessionKnown ? QString::number(s.token.sessionId) : QStringLiteral("<未知>"));
        }
        out << QStringLiteral("Target desktop: %1").arg(s.desktop.isEmpty() ? QStringLiteral("<未知/无权限>") : s.desktop);
        out << QStringLiteral("Inspector window station: %1").arg(s.inspectorWindowStation.isEmpty() ? QStringLiteral("<未知>") : s.inspectorWindowStation);
        out << QStringLiteral("Target window station: <Win32 无稳定通用跨进程查询接口>");

        out << QString() << QStringLiteral("[Composition / hit test]");
        out << QStringLiteral("DisplayAffinity: %1")
            .arg(s.affinityKnown ? hexText(s.affinity) : QStringLiteral("<失败: %1>").arg(errorText(s.affinityError)));
        out << QStringLiteral("LayeredAttributes: %1")
            .arg(s.layeredKnown
                ? QStringLiteral("Alpha=%1 ColorKey=%2 Flags=%3").arg(s.alpha).arg(hexText(s.colorKey), hexText(s.layeredFlags))
                : QStringLiteral("<不可用/非 Layered: %1>").arg(errorText(s.layeredError)));
        out << QStringLiteral("ProbePoint: [%1,%2]").arg(s.probe.x).arg(s.probe.y);
        out << QStringLiteral("WindowFromPoint / root: %1 / %2").arg(hwndText(s.hit), hwndText(s.hitRoot));
        out << QStringLiteral("ChildWindowFromPointEx: %1").arg(hwndText(s.childHit));
        out << QStringLiteral("RealChildWindowFromPoint: %1").arg(hwndText(s.realChildHit));
        return out.join(QChar::LineFeed);
    }

    QStringList diff(const Snapshot& before, const Snapshot& after)
    {
        QStringList out;
        auto add = [&out](const QString& name, const QString& a, const QString& b) {
            if (a != b) out << QStringLiteral("%1: %2 -> %3").arg(name, a, b);
        };
        add(QStringLiteral("Valid"), yesNo(before.valid), yesNo(after.valid));
        add(QStringLiteral("Visible"), yesNo(before.visible), yesNo(after.visible));
        add(QStringLiteral("Band"), before.band.ok ? QString::number(before.band.value) : QStringLiteral("<失败>"),
            after.band.ok ? QString::number(after.band.value) : QStringLiteral("<失败>"));
        add(QStringLiteral("Style"), longPtrText(before.style), longPtrText(after.style));
        add(QStringLiteral("ExStyle"), longPtrText(before.exStyle), longPtrText(after.exStyle));
        add(QStringLiteral("ZIndex"), QString::number(before.z), QString::number(after.z));
        add(QStringLiteral("SameBandZIndex"), QString::number(before.bandZ), QString::number(after.bandZ));
        add(QStringLiteral("TopMostGroupZIndex"), QString::number(before.topMostGroupZ), QString::number(after.topMostGroupZ));
        add(QStringLiteral("Title"), before.title, after.title);
        add(QStringLiteral("WindowRect"), before.rectKnown ? rectText(before.rect) : QStringLiteral("<失败>"),
            after.rectKnown ? rectText(after.rect) : QStringLiteral("<失败>"));
        add(QStringLiteral("Enabled"), yesNo(before.enabled), yesNo(after.enabled));
        add(QStringLiteral("Owner"), hwndText(before.owner), hwndText(after.owner));
        add(QStringLiteral("Foreground"), hwndText(before.foreground), hwndText(after.foreground));
        add(QStringLiteral("Cloaked"), before.cloakedKnown ? hexText(before.cloaked) : QStringLiteral("<未知>"),
            after.cloakedKnown ? hexText(after.cloaked) : QStringLiteral("<未知>"));
        return out;
    }

    std::optional<HWND> parseHwnd(QString text)
    {
        text = text.trimmed();
        int base = 10;
        if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            text = text.mid(2);
            base = 16;
        }
        bool ok = false;
        const qulonglong kValue = text.toULongLong(&ok, base);
        if (!ok || kValue == 0) return std::nullopt;
        return reinterpret_cast<HWND>(static_cast<quintptr>(kValue));
    }

    QString compareText(const Snapshot& a, const Snapshot& b)
    {
        QStringList out;
        out << QStringLiteral("A: %1 [%2] PID/TID=%3/%4").arg(hwndText(a.hwnd), a.cls).arg(a.pid).arg(a.tid);
        out << QStringLiteral("B: %1 [%2] PID/TID=%3/%4").arg(hwndText(b.hwnd), b.cls).arg(b.pid).arg(b.tid);
        out << QStringLiteral("A Band: %1").arg(a.band.ok ? QStringLiteral("%1 (%2)").arg(a.band.value).arg(bandName(a.band.value)) : QStringLiteral("<失败>"));
        out << QStringLiteral("B Band: %1").arg(b.band.ok ? QStringLiteral("%1 (%2)").arg(b.band.value).arg(bandName(b.band.value)) : QStringLiteral("<失败>"));
        out << QStringLiteral("Band ID 不按数值大小比较。");
        out << QStringLiteral("A/B global Z index: %1 / %2").arg(a.z).arg(b.z);
        const bool kSameBand = a.band.ok && b.band.ok && a.band.value == b.band.value;
        out << QStringLiteral("Same band: %1").arg(yesNo(kSameBand));
        out << QStringLiteral("A/B same-band Z index: %1 / %2")
            .arg(kSameBand ? QString::number(a.bandZ) : QStringLiteral("<不适用>"))
            .arg(kSameBand ? QString::number(b.bandZ) : QStringLiteral("<不适用>"));
        out << QStringLiteral("Same desktop: %1").arg(yesNo(!a.desktop.isEmpty() && a.desktop == b.desktop));
        out << QStringLiteral("Same session: %1")
            .arg(a.token.sessionKnown && b.token.sessionKnown ? yesNo(a.token.sessionId == b.token.sessionId) : QStringLiteral("<未知>"));

        if (!a.rectKnown || !b.rectKnown)
        {
            out << QStringLiteral("Overlap test: <矩形不可用>");
            return out.join(QChar::LineFeed);
        }
        RECT r{};
        r.left = std::max(a.rect.left, b.rect.left);
        r.top = std::max(a.rect.top, b.rect.top);
        r.right = std::min(a.rect.right, b.rect.right);
        r.bottom = std::min(a.rect.bottom, b.rect.bottom);
        if (r.left >= r.right || r.top >= r.bottom)
        {
            out << QStringLiteral("Overlap test: 当前无重叠区域。");
            return out.join(QChar::LineFeed);
        }

        POINT p{ r.left + (r.right - r.left) / 2, r.top + (r.bottom - r.top) / 2 };
        const HWND kHit = ::WindowFromPoint(p);
        const HWND kRoot = kHit != nullptr ? ::GetAncestor(kHit, GA_ROOT) : nullptr;
        out << QStringLiteral("Overlap rect: %1").arg(rectText(r));
        out << QStringLiteral("Probe: [%1,%2], hit=%3, root=%4").arg(p.x).arg(p.y).arg(hwndText(kHit), hwndText(kRoot));
        if (kRoot == a.root || kRoot == a.hwnd) out << QStringLiteral("实际命中: A 覆盖采样点。");
        else if (kRoot == b.root || kRoot == b.hwnd) out << QStringLiteral("实际命中: B 覆盖采样点。");
        else out << QStringLiteral("实际命中: 被第三个窗口覆盖，无法判定 A/B。");
        return out.join(QChar::LineFeed);
    }

    QJsonArray zOrderJson()
    {
        QJsonArray array;
        QSet<quintptr> visited;
        QHash<DWORD, int> bandPositions;
        QHash<quint64, int> topMostGroupPositions;
        HWND hwnd = ::GetTopWindow(nullptr);
        for (int index = 0; hwnd != nullptr && index < kWalkLimit; ++index)
        {
            const quintptr kRaw = reinterpret_cast<quintptr>(hwnd);
            if (visited.contains(kRaw)) break;
            visited.insert(kRaw);

            DWORD pid = 0;
            const DWORD kTid = ::GetWindowThreadProcessId(hwnd, &pid);
            const BandResult kBand = readBand(hwnd);
            const LongPtrResult kExStyle = readLongPtr(hwnd, GWL_EXSTYLE);
            const bool kTopMost = kExStyle.ok && (kExStyle.value & WS_EX_TOPMOST) != 0;
            QJsonObject item;
            item.insert(QStringLiteral("index"), index);
            item.insert(QStringLiteral("hwnd"), hwndText(hwnd));
            item.insert(QStringLiteral("pid"), static_cast<double>(pid));
            item.insert(QStringLiteral("tid"), static_cast<double>(kTid));
            item.insert(QStringLiteral("class"), className(hwnd));
            item.insert(QStringLiteral("title"), windowTitle(hwnd));
            item.insert(QStringLiteral("visible"), ::IsWindowVisible(hwnd) != FALSE);
            item.insert(QStringLiteral("style"), longPtrText(readLongPtr(hwnd, GWL_STYLE)));
            item.insert(QStringLiteral("exStyle"), longPtrText(kExStyle));
            item.insert(QStringLiteral("topMost"), kTopMost);
            item.insert(QStringLiteral("owner"), hwndText(::GetWindow(hwnd, GW_OWNER)));
            item.insert(QStringLiteral("bandSuccess"), kBand.ok);
            item.insert(QStringLiteral("band"), static_cast<double>(kBand.value));
            item.insert(QStringLiteral("bandName"), bandName(kBand.value));
            const int kBandIndex = kBand.ok ? bandPositions.value(kBand.value, 0) : -1;
            item.insert(QStringLiteral("bandZIndex"), kBandIndex);
            if (kBand.ok)
            {
                bandPositions.insert(kBand.value, kBandIndex + 1);
                const quint64 kGroupKey = (static_cast<quint64>(kBand.value) << 1U) | (kTopMost ? 1U : 0U);
                const int kGroupIndex = topMostGroupPositions.value(kGroupKey, 0);
                item.insert(QStringLiteral("topMostGroupZIndex"), kGroupIndex);
                topMostGroupPositions.insert(kGroupKey, kGroupIndex + 1);
            }
            else
            {
                item.insert(QStringLiteral("topMostGroupZIndex"), -1);
            }
            item.insert(QStringLiteral("desktop"), objectName(::GetThreadDesktop(kTid)));
            array.append(item);
            hwnd = ::GetWindow(hwnd, GW_HWNDNEXT);
        }
        return array;
    }

    QString winEventName(DWORD event)
    {
        switch (event)
        {
        case EVENT_SYSTEM_FOREGROUND: return QStringLiteral("EVENT_SYSTEM_FOREGROUND");
        case EVENT_SYSTEM_MINIMIZESTART: return QStringLiteral("EVENT_SYSTEM_MINIMIZESTART");
        case EVENT_SYSTEM_MINIMIZEEND: return QStringLiteral("EVENT_SYSTEM_MINIMIZEEND");
        case EVENT_OBJECT_CREATE: return QStringLiteral("EVENT_OBJECT_CREATE");
        case EVENT_OBJECT_DESTROY: return QStringLiteral("EVENT_OBJECT_DESTROY");
        case EVENT_OBJECT_SHOW: return QStringLiteral("EVENT_OBJECT_SHOW");
        case EVENT_OBJECT_HIDE: return QStringLiteral("EVENT_OBJECT_HIDE");
        case EVENT_OBJECT_REORDER: return QStringLiteral("EVENT_OBJECT_REORDER");
        case EVENT_OBJECT_STATECHANGE: return QStringLiteral("EVENT_OBJECT_STATECHANGE");
        case EVENT_OBJECT_LOCATIONCHANGE: return QStringLiteral("EVENT_OBJECT_LOCATIONCHANGE");
        case EVENT_OBJECT_NAMECHANGE: return QStringLiteral("EVENT_OBJECT_NAMECHANGE");
        default: return QStringLiteral("EVENT_%1").arg(hexText(event));
        }
    }

    class Page;
    QMutex& hookMutex() { static QMutex mutex; return mutex; }
    QHash<quintptr, QPointer<Page>>& hookOwners()
    {
        static QHash<quintptr, QPointer<Page>> owners;
        return owners;
    }

    void CALLBACK winEventProc(HWINEVENTHOOK, DWORD, HWND, LONG, LONG, DWORD, DWORD);

    class Page final : public QWidget
    {
    public:
        explicit Page(HWND target, QWidget* parent = nullptr)
            : QWidget(parent), target_(target)
        {
            initialTid_ = ::GetWindowThreadProcessId(target_, &initialPid_);
            initialClass_ = className(target_);
            buildUi();
            refresh(uiText("window.layer.status.initial_snapshot", "初始快照"));
        }

        ~Page() override
        {
            if (rollbackBaseline_.has_value())
            {
                restoreOriginalState(false);
            }
            stopTracking();
        }

        void onWinEvent(DWORD event, HWND eventHwnd, LONG objectId, LONG childId, DWORD eventTid, DWORD eventTime)
        {
            if (!tracking_) return;
            bool relevant = event == EVENT_SYSTEM_FOREGROUND;
            if (!relevant && eventHwnd != nullptr)
            {
                relevant = eventHwnd == target_ ||
                    ::GetAncestor(eventHwnd, GA_ROOT) == target_ ||
                    ::GetAncestor(eventHwnd, GA_ROOTOWNER) == target_;
            }
            if (!relevant) return;

            const Snapshot kNow = capture(target_);
            QStringList lines;
            lines << QStringLiteral("[%1] %2 hwnd=%3 object=%4 child=%5 tid=%6 time=%7")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")))
                .arg(winEventName(event), hwndText(eventHwnd))
                .arg(objectId).arg(childId).arg(eventTid).arg(eventTime);
            if (eventSnapshot_.has_value())
            {
                const QStringList kChanges = diff(*eventSnapshot_, kNow);
                if (kChanges.isEmpty()) lines << QStringLiteral("change: <无关键字段变化>");
                else for (const QString& change : kChanges) lines << QStringLiteral("change: %1").arg(change);
            }
            eventSnapshot_ = kNow;
            events_->appendPlainText(lines.join(QChar::LineFeed) + QStringLiteral("\n"));
            while (events_->document()->blockCount() > kEventBlockLimit)
            {
                QTextCursor cursor(events_->document());
                cursor.movePosition(QTextCursor::Start);
                cursor.select(QTextCursor::BlockUnderCursor);
                cursor.removeSelectedText();
                cursor.deleteChar();
            }
        }

    private:
        enum class LayerAction
        {
            kMoveTop,
            kMoveBottom,
            kMakeTopMost,
            kMakeNotTopMost,
            kMoveBeforeReference,
            kMoveAfterReference,
            kMoveUiAccessBand,
            kMoveDefaultBand
        };

        void buildUi()
        {
            auto* root = new QVBoxLayout(this);
            root->setContentsMargins(8, 8, 8, 8);
            auto* warning = new QLabel(
                uiText("window.layer.warning", "Band ID 是标识符，不是线性高度。本页分别展示 Band、Band 内 Z 序和实际命中。"), this);
            warning->setWordWrap(true);
            root->addWidget(warning);

            auto* actions = new QHBoxLayout();
            auto* targetLabel = new QLabel(uiText("window.layer.target", "锁定 HWND: %1").arg(hwndText(target_)), this);
            actions->addWidget(targetLabel, 1);
            auto* refreshButton = new QPushButton(uiText("window.layer.action.refresh", "刷新"), this);
            auto* delayedButton = new QPushButton(uiText("window.layer.action.delayed_snapshot", "3 秒后快照"), this);
            auto* copyButton = new QPushButton(uiText("window.layer.action.copy", "复制"), this);
            auto* exportButton = new QPushButton(uiText("window.layer.action.export_snapshot", "导出快照"), this);
            auto* exportZButton = new QPushButton(uiText("window.layer.action.export_z_order", "导出完整 Z 序"), this);
            trackButton_ = new QPushButton(uiText("window.layer.action.track_start", "开始事件追踪"), this);
            actions->addWidget(refreshButton);
            actions->addWidget(delayedButton);
            actions->addWidget(copyButton);
            actions->addWidget(exportButton);
            actions->addWidget(exportZButton);
            actions->addWidget(trackButton_);
            root->addLayout(actions);

            auto* compareRow = new QHBoxLayout();
            auto* compareLabel = new QLabel(uiText("window.layer.compare.hwnd", "对比 HWND:"), this);
            compareRow->addWidget(compareLabel);
            compare_ = new QLineEdit(this);
            compare_->setPlaceholderText(uiText("window.layer.compare.placeholder", "0x104DE 或十进制"));
            auto* pickButton = new QPushButton(uiText("window.layer.action.pick_top_window", "取鼠标下顶层窗口"), this);
            auto* compareButton = new QPushButton(uiText("window.layer.action.compare", "对比"), this);
            auto* delayedCompareButton = new QPushButton(uiText("window.layer.action.delayed_compare", "3 秒后对比"), this);
            compareRow->addWidget(compare_, 1);
            compareRow->addWidget(pickButton);
            compareRow->addWidget(compareButton);
            compareRow->addWidget(delayedCompareButton);
            root->addLayout(compareRow);

            status_ = new QLabel(this);
            status_->setWordWrap(true);
            root->addWidget(status_);

            auto* tabs = new QTabWidget(this);
            output_ = new QPlainTextEdit(tabs);
            auto* operationPage = new QWidget(tabs);
            auto* operationLayout = new QVBoxLayout(operationPage);

            auto* zOrderGroup = new QGroupBox(
                uiText("window.layer.operations.z_group", "公开 Z 序操作"), operationPage);
            auto* zOrderGrid = new QGridLayout(zOrderGroup);
            auto* moveTopButton = new QPushButton(uiText("window.layer.action.move_top", "移到当前组最前"), zOrderGroup);
            auto* moveBottomButton = new QPushButton(uiText("window.layer.action.move_bottom", "移到当前组最后"), zOrderGroup);
            auto* topMostButton = new QPushButton(uiText("window.layer.action.make_topmost", "普通置顶"), zOrderGroup);
            auto* notTopMostButton = new QPushButton(uiText("window.layer.action.make_not_topmost", "取消普通置顶"), zOrderGroup);
            auto* beforeReferenceButton = new QPushButton(uiText("window.layer.action.before_reference", "移到对比窗口之前"), zOrderGroup);
            auto* afterReferenceButton = new QPushButton(uiText("window.layer.action.after_reference", "移到对比窗口之后"), zOrderGroup);
            zOrderGrid->addWidget(moveTopButton, 0, 0);
            zOrderGrid->addWidget(moveBottomButton, 0, 1);
            zOrderGrid->addWidget(topMostButton, 1, 0);
            zOrderGrid->addWidget(notTopMostButton, 1, 1);
            zOrderGrid->addWidget(beforeReferenceButton, 2, 0);
            zOrderGrid->addWidget(afterReferenceButton, 2, 1);
            operationLayout->addWidget(zOrderGroup);

            auto* bandGroup = new QGroupBox(
                uiText("window.layer.operations.band_group", "实验性 Window Band 操作"), operationPage);
            auto* bandLayout = new QVBoxLayout(bandGroup);
            auto* bandWarning = new QLabel(
                uiText("window.layer.operations.band_warning", "SetWindowBand 是未公开接口；仅在当前 KSword 令牌带 UIAccess 时尝试，并以 GetWindowBand 回读为准。"),
                bandGroup);
            bandWarning->setWordWrap(true);
            bandLayout->addWidget(bandWarning);
            auto* bandButtons = new QHBoxLayout();
            auto* uiAccessBandButton = new QPushButton(
                uiText("window.layer.action.uiaccess_band", "尝试提升至 UIAccess Band"), bandGroup);
            auto* defaultBandButton = new QPushButton(
                uiText("window.layer.action.default_band", "恢复 DEFAULT Band"), bandGroup);
            bandButtons->addWidget(uiAccessBandButton);
            bandButtons->addWidget(defaultBandButton);
            bandButtons->addStretch(1);
            bandLayout->addLayout(bandButtons);
            operationLayout->addWidget(bandGroup);

            auto* rollbackGroup = new QGroupBox(
                uiText("window.layer.operations.rollback_group", "安全回滚"), operationPage);
            auto* rollbackLayout = new QHBoxLayout(rollbackGroup);
            rollbackStatus_ = new QLabel(
                uiText("window.layer.rollback.idle", "当前没有待确认的层级修改。"), rollbackGroup);
            rollbackStatus_->setWordWrap(true);
            keepButton_ = new QPushButton(uiText("window.layer.action.keep", "保留修改"), rollbackGroup);
            restoreButton_ = new QPushButton(uiText("window.layer.action.restore", "立即恢复"), rollbackGroup);
            keepButton_->setEnabled(false);
            restoreButton_->setEnabled(false);
            rollbackLayout->addWidget(rollbackStatus_, 1);
            rollbackLayout->addWidget(keepButton_);
            rollbackLayout->addWidget(restoreButton_);
            operationLayout->addWidget(rollbackGroup);

            // When the system monospace font lacks Chinese glyphs, Windows falls back to SimSun; explicitly specify Microsoft YaHei for Chinese text.
            QFont diagnosticsFixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
            diagnosticsFixedFont.setFamilies(
                QStringList{ diagnosticsFixedFont.family(), QStringLiteral("Microsoft YaHei UI") });

            operationLog_ = new QPlainTextEdit(operationPage);
            operationLog_->setReadOnly(true);
            operationLog_->setLineWrapMode(QPlainTextEdit::NoWrap);
            operationLog_->setFont(diagnosticsFixedFont);
            operationLayout->addWidget(operationLog_, 1);

            relationships_ = new QPlainTextEdit(tabs);
            diagnostics_ = new QPlainTextEdit(tabs);
            events_ = new QPlainTextEdit(tabs);
            for (QPlainTextEdit* edit : { output_, relationships_, diagnostics_, events_ })
            {
                edit->setReadOnly(true);
                edit->setLineWrapMode(QPlainTextEdit::NoWrap);
                edit->setFont(diagnosticsFixedFont);
            }
            tabs->addTab(output_, uiText("window.layer.tab.snapshot", "快照 / 对比"));
            tabs->addTab(operationPage, uiText("window.layer.tab.operations", "层级操作"));
            tabs->addTab(relationships_, uiText("window.layer.tab.relationships", "Owner / Popup 关系"));
            tabs->addTab(diagnostics_, uiText("window.layer.tab.diagnostics", "失败原因诊断"));
            tabs->addTab(events_, uiText("window.layer.tab.events", "事件时间线"));
            root->addWidget(tabs, 1);

            rollbackTimer_ = new QTimer(this);
            rollbackTimer_->setInterval(1000);
            connect(rollbackTimer_, &QTimer::timeout, this, [this]() {
                if (!rollbackBaseline_.has_value())
                {
                    rollbackTimer_->stop();
                    return;
                }
                --rollbackSecondsRemaining_;
                if (rollbackSecondsRemaining_ <= 0)
                {
                    restoreOriginalState(true);
                    return;
                }
                updateRollbackUi();
            });

            // These bindings keep an already-open diagnostic page coherent
            // when the application language changes at runtime.
            bindUiText(warning, "window.layer.warning", "Band ID 是标识符，不是线性高度。本页分别展示 Band、Band 内 Z 序和实际命中。");
            bindUiText(refreshButton, "window.layer.action.refresh", "刷新");
            bindUiText(delayedButton, "window.layer.action.delayed_snapshot", "3 秒后快照");
            bindUiText(copyButton, "window.layer.action.copy", "复制");
            bindUiText(exportButton, "window.layer.action.export_snapshot", "导出快照");
            bindUiText(exportZButton, "window.layer.action.export_z_order", "导出完整 Z 序");
            bindUiText(pickButton, "window.layer.action.pick_top_window", "取鼠标下顶层窗口");
            bindUiText(compareButton, "window.layer.action.compare", "对比");
            bindUiText(delayedCompareButton, "window.layer.action.delayed_compare", "3 秒后对比");
            bindUiText(compareLabel, "window.layer.compare.hwnd", "对比 HWND:");
            bindUiText(zOrderGroup, "window.layer.operations.z_group", "公开 Z 序操作");
            bindUiText(moveTopButton, "window.layer.action.move_top", "移到当前组最前");
            bindUiText(moveBottomButton, "window.layer.action.move_bottom", "移到当前组最后");
            bindUiText(topMostButton, "window.layer.action.make_topmost", "普通置顶");
            bindUiText(notTopMostButton, "window.layer.action.make_not_topmost", "取消普通置顶");
            bindUiText(beforeReferenceButton, "window.layer.action.before_reference", "移到对比窗口之前");
            bindUiText(afterReferenceButton, "window.layer.action.after_reference", "移到对比窗口之后");
            bindUiText(bandGroup, "window.layer.operations.band_group", "实验性 Window Band 操作");
            bindUiText(bandWarning, "window.layer.operations.band_warning", "SetWindowBand 是未公开接口；仅在当前 KSword 令牌带 UIAccess 时尝试，并以 GetWindowBand 回读为准。");
            bindUiText(uiAccessBandButton, "window.layer.action.uiaccess_band", "尝试提升至 UIAccess Band");
            bindUiText(defaultBandButton, "window.layer.action.default_band", "恢复 DEFAULT Band");
            bindUiText(rollbackGroup, "window.layer.operations.rollback_group", "安全回滚");
            bindUiText(keepButton_, "window.layer.action.keep", "保留修改");
            bindUiText(restoreButton_, "window.layer.action.restore", "立即恢复");
            ks::i18n::LanguageManager::instance().bindPlaceholder(
                compare_, QStringLiteral("window.layer.compare.placeholder"), QStringLiteral("0x104DE 或十进制"));
            ks::i18n::LanguageManager::instance().bindTab(
                tabs, output_, QStringLiteral("window.layer.tab.snapshot"), QStringLiteral("快照 / 对比"));
            ks::i18n::LanguageManager::instance().bindTab(
                tabs, operationPage, QStringLiteral("window.layer.tab.operations"), QStringLiteral("层级操作"));
            ks::i18n::LanguageManager::instance().bindTab(
                tabs, relationships_, QStringLiteral("window.layer.tab.relationships"), QStringLiteral("Owner / Popup 关系"));
            ks::i18n::LanguageManager::instance().bindTab(
                tabs, diagnostics_, QStringLiteral("window.layer.tab.diagnostics"), QStringLiteral("失败原因诊断"));
            ks::i18n::LanguageManager::instance().bindTab(
                tabs, events_, QStringLiteral("window.layer.tab.events"), QStringLiteral("事件时间线"));
            updateTrackButtonText();

            connect(refreshButton, &QPushButton::clicked, this, [this]() { refresh(uiText("window.layer.status.manual_refresh", "手动刷新")); });
            connect(delayedButton, &QPushButton::clicked, this, [this, delayedButton]() {
                delayedButton->setEnabled(false);
                status_->setText(uiText("window.layer.status.delayed_snapshot", "3 秒后抓取；现在回到输入框并让候选框出现。"));
                QTimer::singleShot(3000, this, [this, delayedButton]() {
                    refresh(uiText("window.layer.status.delayed_snapshot_complete", "延迟快照"));
                    delayedButton->setEnabled(true);
                    QApplication::beep();
                });
            });
            connect(copyButton, &QPushButton::clicked, this, [this]() {
                QApplication::clipboard()->setText(output_->toPlainText());
                status_->setText(uiText("window.layer.status.copied", "已复制。"));
            });
            connect(exportButton, &QPushButton::clicked, this, [this]() { exportSnapshot(); });
            connect(exportZButton, &QPushButton::clicked, this, [this]() { exportZOrder(); });
            connect(trackButton_, &QPushButton::clicked, this, [this]() {
                tracking_ ? stopTracking() : startTracking();
            });
            connect(pickButton, &QPushButton::clicked, this, [this]() {
                const QPoint kQpoint = QCursor::pos();
                POINT point{ kQpoint.x(), kQpoint.y() };
                HWND hwnd = ::WindowFromPoint(point);
                const HWND kRoot = hwnd != nullptr ? ::GetAncestor(hwnd, GA_ROOT) : nullptr;
                if (kRoot != nullptr) hwnd = kRoot;
                if (hwnd != nullptr) compare_->setText(hwndText(hwnd));
            });
            connect(compareButton, &QPushButton::clicked, this, [this]() { compareNow(); });
            connect(delayedCompareButton, &QPushButton::clicked, this, [this, delayedCompareButton]() {
                delayedCompareButton->setEnabled(false);
                status_->setText(uiText("window.layer.status.delayed_compare", "3 秒后对比；请恢复待测遮挡状态。"));
                QTimer::singleShot(3000, this, [this, delayedCompareButton]() {
                    compareNow();
                    delayedCompareButton->setEnabled(true);
                    QApplication::beep();
                });
            });
            connect(moveTopButton, &QPushButton::clicked, this, [this]() { applyLayerAction(LayerAction::kMoveTop); });
            connect(moveBottomButton, &QPushButton::clicked, this, [this]() { applyLayerAction(LayerAction::kMoveBottom); });
            connect(topMostButton, &QPushButton::clicked, this, [this]() { applyLayerAction(LayerAction::kMakeTopMost); });
            connect(notTopMostButton, &QPushButton::clicked, this, [this]() { applyLayerAction(LayerAction::kMakeNotTopMost); });
            connect(beforeReferenceButton, &QPushButton::clicked, this, [this]() { applyLayerAction(LayerAction::kMoveBeforeReference); });
            connect(afterReferenceButton, &QPushButton::clicked, this, [this]() { applyLayerAction(LayerAction::kMoveAfterReference); });
            connect(uiAccessBandButton, &QPushButton::clicked, this, [this]() { applyLayerAction(LayerAction::kMoveUiAccessBand); });
            connect(defaultBandButton, &QPushButton::clicked, this, [this]() { applyLayerAction(LayerAction::kMoveDefaultBand); });
            connect(keepButton_, &QPushButton::clicked, this, [this]() { keepCurrentState(); });
            connect(restoreButton_, &QPushButton::clicked, this, [this]() { restoreOriginalState(true); });
        }

        QString actionText(const LayerAction action) const
        {
            switch (action)
            {
            case LayerAction::kMoveTop:
                return uiText("window.layer.action.move_top", "移到当前组最前");
            case LayerAction::kMoveBottom:
                return uiText("window.layer.action.move_bottom", "移到当前组最后");
            case LayerAction::kMakeTopMost:
                return uiText("window.layer.action.make_topmost", "普通置顶");
            case LayerAction::kMakeNotTopMost:
                return uiText("window.layer.action.make_not_topmost", "取消普通置顶");
            case LayerAction::kMoveBeforeReference:
                return uiText("window.layer.action.before_reference", "移到对比窗口之前");
            case LayerAction::kMoveAfterReference:
                return uiText("window.layer.action.after_reference", "移到对比窗口之后");
            case LayerAction::kMoveUiAccessBand:
                return uiText("window.layer.action.uiaccess_band", "尝试提升至 UIAccess Band");
            case LayerAction::kMoveDefaultBand:
                return uiText("window.layer.action.default_band", "恢复 DEFAULT Band");
            }
            return QStringLiteral("<unknown>");
        }

        void appendOperationLog(const QStringList& lines)
        {
            if (operationLog_ == nullptr)
            {
                return;
            }
            operationLog_->appendPlainText(lines.join(QChar::LineFeed) + QStringLiteral("\n"));
        }

        void updateAnalysisViews(const Snapshot& snapshot)
        {
            if (relationships_ != nullptr)
            {
                relationships_->setPlainText(relationshipGraph(target_));
            }
            if (diagnostics_ != nullptr)
            {
                diagnostics_->setPlainText(diagnosisText(snapshot));
            }
        }

        void refresh(const QString& reason)
        {
            current_ = capture(target_);
            output_->setPlainText(snapshotText(*current_, initialPid_, initialTid_, initialClass_));
            updateAnalysisViews(*current_);
            status_->setText(uiText("window.layer.status.completed", "%1完成：%2")
                .arg(reason, current_->time.toString(QStringLiteral("HH:mm:ss.zzz"))));
        }

        void compareNow()
        {
            const std::optional<HWND> kOther = parseHwnd(compare_->text());
            if (!kOther.has_value() || ::IsWindow(*kOther) == FALSE)
            {
                status_->setText(uiText("window.layer.status.invalid_compare_target", "对比 HWND 无效或已销毁。"));
                return;
            }
            const Snapshot kA = capture(target_);
            const Snapshot kB = capture(*kOther);
            current_ = kA;
            updateAnalysisViews(kA);
            output_->setPlainText(
                compareText(kA, kB) +
                QStringLiteral("\n\n========== A ==========\n") +
                snapshotText(kA, initialPid_, initialTid_, initialClass_) +
                QStringLiteral("\n\n========== B ==========\n") +
                snapshotText(kB, kB.pid, kB.tid, kB.cls));
            status_->setText(uiText("window.layer.status.compare_complete", "A/B 对比完成。"));
        }

        bool validateMutationTarget(const Snapshot& snapshot)
        {
            if (!snapshot.valid || snapshot.pid != initialPid_ || snapshot.tid != initialTid_ || snapshot.cls != initialClass_)
            {
                const QString kMessage = uiText(
                    "window.layer.status.identity_changed",
                    "目标 HWND 已失效或已被复用；为避免修改错误窗口，操作已取消。");
                status_->setText(kMessage);
                QMessageBox::warning(
                    this,
                    uiText("window.layer.operation.blocked_title", "层级操作已阻止"),
                    kMessage);
                return false;
            }
            if (hasStyleFlag(snapshot, WS_CHILD))
            {
                const QString kMessage = uiText(
                    "window.layer.status.child_mutation_blocked",
                    "当前目标是子窗口。本页只对顶层窗口开放层级写操作，以免破坏父子窗口消息和布局关系。");
                status_->setText(kMessage);
                QMessageBox::warning(
                    this,
                    uiText("window.layer.operation.blocked_title", "层级操作已阻止"),
                    kMessage);
                return false;
            }

            const TokenInfo kInspector = tokenInfo(::GetCurrentProcessId());
            const QString kInspectorDesktop = ks::window::layerdiag::objectName(
                ::GetThreadDesktop(::GetCurrentThreadId()));
            if (snapshot.token.sessionKnown && kInspector.sessionKnown && snapshot.token.sessionId != kInspector.sessionId)
            {
                const QString kMessage = uiText(
                    "window.layer.status.session_mismatch",
                    "目标与 KSword 不在同一 Session，层级操作已取消。");
                status_->setText(kMessage);
                QMessageBox::warning(this, uiText("window.layer.operation.blocked_title", "层级操作已阻止"), kMessage);
                return false;
            }
            if (!snapshot.desktop.isEmpty() && !kInspectorDesktop.isEmpty() && snapshot.desktop != kInspectorDesktop)
            {
                const QString kMessage = uiText(
                    "window.layer.status.desktop_mismatch",
                    "目标与 KSword 不在同一 Desktop，层级操作已取消。");
                status_->setText(kMessage);
                QMessageBox::warning(this, uiText("window.layer.operation.blocked_title", "层级操作已阻止"), kMessage);
                return false;
            }
            return true;
        }

        std::optional<Snapshot> referenceSnapshot() const
        {
            const std::optional<HWND> kReference = parseHwnd(compare_ != nullptr ? compare_->text() : QString());
            if (!kReference.has_value() || *kReference == target_ || ::IsWindow(*kReference) == FALSE)
            {
                return std::nullopt;
            }
            return capture(*kReference);
        }

        bool validateReference(const Snapshot& target, const Snapshot& reference)
        {
            if (!reference.valid || hasStyleFlag(reference, WS_CHILD))
            {
                return false;
            }
            if (target.token.sessionKnown && reference.token.sessionKnown && target.token.sessionId != reference.token.sessionId)
            {
                return false;
            }
            if (!target.desktop.isEmpty() && !reference.desktop.isEmpty() && target.desktop != reference.desktop)
            {
                return false;
            }
            if (target.band.ok && reference.band.ok && target.band.value != reference.band.value)
            {
                return false;
            }
            return true;
        }

        void applyLayerAction(const LayerAction action)
        {
            const Snapshot kBefore = capture(target_);
            if (!validateMutationTarget(kBefore))
            {
                updateAnalysisViews(kBefore);
                return;
            }

            std::optional<Snapshot> reference;
            if (action == LayerAction::kMoveBeforeReference || action == LayerAction::kMoveAfterReference)
            {
                reference = referenceSnapshot();
                if (!reference.has_value() || !validateReference(kBefore, *reference))
                {
                    const QString kMessage = uiText(
                        "window.layer.status.invalid_relative_target",
                        "相对排序要求有效的另一个顶层窗口，并且两个窗口必须位于同一 Session、Desktop 和 Window Band。");
                    status_->setText(kMessage);
                    QMessageBox::warning(this, uiText("window.layer.operation.blocked_title", "层级操作已阻止"), kMessage);
                    return;
                }
            }

            const bool kBandAction = action == LayerAction::kMoveUiAccessBand || action == LayerAction::kMoveDefaultBand;
            if (kBandAction)
            {
                const TokenInfo kInspector = tokenInfo(::GetCurrentProcessId());
                if (!(kInspector.uiAccessKnown && kInspector.uiAccess))
                {
                    const QString kMessage = uiText(
                        "window.layer.status.uiaccess_required",
                        "UIAccess Band 操作要求当前 KSword 令牌带 TokenUIAccess。请点击主窗口 UIAccess 状态按钮完成重启后再试。");
                    status_->setText(kMessage);
                    QMessageBox::warning(
                        this,
                        uiText("window.layer.operation.uiaccess_required_title", "需要 UIAccess"),
                        kMessage);
                    updateAnalysisViews(kBefore);
                    return;
                }
                const QMessageBox::StandardButton kConfirmation = QMessageBox::warning(
                    this,
                    uiText("window.layer.operation.experimental_title", "实验性 Window Band 操作"),
                    uiText(
                        "window.layer.operation.experimental_message",
                        "SetWindowBand 是未公开接口，系统可能拒绝、忽略或在后续版本改变行为。操作成功后将在 10 秒内自动恢复，除非点击“保留修改”。\n\n继续吗？"),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No);
                if (kConfirmation != QMessageBox::Yes)
                {
                    return;
                }
            }

            bool apiOk = false;
            DWORD apiError = ERROR_SUCCESS;
            if (kBandAction)
            {
                const DWORD kRequestedBand = action == LayerAction::kMoveUiAccessBand
                    ? kWindowBandUiAccess
                    : kWindowBandDefault;
                const HWND kInsertAfter = action == LayerAction::kMoveUiAccessBand ? HWND_TOPMOST : HWND_NOTOPMOST;
                const BandWriteResult kResult = writeBand(target_, kInsertAfter, kRequestedBand);
                apiOk = kResult.ok;
                apiError = kResult.error;
            }
            else
            {
                HWND insertAfter = HWND_TOP;
                switch (action)
                {
                case LayerAction::kMoveTop:
                    insertAfter = HWND_TOP;
                    break;
                case LayerAction::kMoveBottom:
                    insertAfter = HWND_BOTTOM;
                    break;
                case LayerAction::kMakeTopMost:
                    insertAfter = HWND_TOPMOST;
                    break;
                case LayerAction::kMakeNotTopMost:
                    insertAfter = HWND_NOTOPMOST;
                    break;
                case LayerAction::kMoveBeforeReference:
                {
                    const HWND kPrevious = ::GetWindow(reference->hwnd, GW_HWNDPREV);
                    if (kPrevious != nullptr && kPrevious != target_)
                    {
                        insertAfter = kPrevious;
                    }
                    else
                    {
                        insertAfter = hasExStyleFlag(*reference, WS_EX_TOPMOST) ? HWND_TOPMOST : HWND_TOP;
                    }
                    break;
                }
                case LayerAction::kMoveAfterReference:
                    insertAfter = reference->hwnd;
                    break;
                case LayerAction::kMoveUiAccessBand:
                case LayerAction::kMoveDefaultBand:
                    break;
                }

                ::SetLastError(ERROR_SUCCESS);
                apiOk = ::SetWindowPos(
                    target_,
                    insertAfter,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_ASYNCWINDOWPOS) != FALSE;
                apiError = apiOk ? ERROR_SUCCESS : ::GetLastError();
            }

            if (!apiOk)
            {
                const QString kFailure = uiText(
                    "window.layer.status.operation_failed",
                    "%1失败：Win32 错误 %2。请查看“失败原因诊断”页；权限不足时可通过主窗口 UIAccess/Admin 状态按钮恢复。")
                    .arg(actionText(action), errorText(apiError));
                appendOperationLog({
                    QStringLiteral("[%1] %2").arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")), actionText(action)),
                    kFailure
                });
                status_->setText(kFailure);
                QMessageBox::warning(this, uiText("window.layer.operation.failed_title", "层级操作失败"), kFailure);
                updateAnalysisViews(kBefore);
                return;
            }

            if (!rollbackBaseline_.has_value())
            {
                rollbackBaseline_ = kBefore;
            }
            rollbackSecondsRemaining_ = kRollbackSeconds;
            rollbackTimer_->start();
            updateRollbackUi();
            status_->setText(uiText(
                "window.layer.status.operation_submitted",
                "%1请求已提交；正在等待系统回读，未确认时将在 %2 秒后自动恢复。")
                .arg(actionText(action))
                .arg(kRollbackSeconds));

            const HWND kReferenceHwnd = reference.has_value() ? reference->hwnd : nullptr;
            QTimer::singleShot(200, this, [this, action, kBefore, kReferenceHwnd]() {
                verifyLayerAction(action, kBefore, kReferenceHwnd);
            });
        }

        void verifyLayerAction(
            const LayerAction action,
            const Snapshot& before,
            HWND referenceHwnd,
            int attempt = 0)
        {
            const Snapshot kAfter = capture(target_);
            current_ = kAfter;
            output_->setPlainText(snapshotText(kAfter, initialPid_, initialTid_, initialClass_));
            updateAnalysisViews(kAfter);

            bool verified = false;
            QString expectation;
            switch (action)
            {
            case LayerAction::kMoveTop:
                verified = kAfter.topMostGroupZ == 0;
                expectation = uiText("window.layer.verify.move_top", "当前 Band/TopMost 组内 Z index 为 0");
                break;
            case LayerAction::kMoveBottom:
                verified = kAfter.topMostGroupZ >= 0 && kAfter.topMostGroupWindowCount > 0 &&
                    kAfter.topMostGroupZ == kAfter.topMostGroupWindowCount - 1;
                expectation = uiText("window.layer.verify.move_bottom", "位于当前 Band/TopMost 组末端");
                break;
            case LayerAction::kMakeTopMost:
                verified = hasExStyleFlag(kAfter, WS_EX_TOPMOST);
                expectation = QStringLiteral("WS_EX_TOPMOST=1");
                break;
            case LayerAction::kMakeNotTopMost:
                verified = !hasExStyleFlag(kAfter, WS_EX_TOPMOST);
                expectation = QStringLiteral("WS_EX_TOPMOST=0");
                break;
            case LayerAction::kMoveBeforeReference:
            {
                const Snapshot kReference = capture(referenceHwnd);
                verified = kReference.valid && kAfter.z >= 0 && kReference.z >= 0 && kAfter.z < kReference.z;
                expectation = uiText("window.layer.verify.before_reference", "目标位于对比窗口之前");
                break;
            }
            case LayerAction::kMoveAfterReference:
            {
                const Snapshot kReference = capture(referenceHwnd);
                verified = kReference.valid && kAfter.z >= 0 && kReference.z >= 0 && kAfter.z > kReference.z;
                expectation = uiText("window.layer.verify.after_reference", "目标位于对比窗口之后");
                break;
            }
            case LayerAction::kMoveUiAccessBand:
                verified = kAfter.band.ok && kAfter.band.value == kWindowBandUiAccess;
                expectation = QStringLiteral("Band=ZBID_UIACCESS(2)");
                break;
            case LayerAction::kMoveDefaultBand:
                verified = kAfter.band.ok && kAfter.band.value == kWindowBandDefault;
                expectation = QStringLiteral("Band=ZBID_DEFAULT(0)");
                break;
            }

            if (!verified && attempt < 2 && sameWindowIdentity(before, target_))
            {
                QTimer::singleShot(350 * (attempt + 1), this, [this, action, before, referenceHwnd, attempt]() {
                    verifyLayerAction(action, before, referenceHwnd, attempt + 1);
                });
                return;
            }

            QStringList lines;
            lines << QStringLiteral("[%1] %2")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")), actionText(action));
            lines << uiText("window.layer.operation.api_accepted", "API 请求：已接受");
            lines << uiText("window.layer.operation.expectation", "验证条件：%1").arg(expectation);
            lines << uiText("window.layer.operation.readback", "回读：Band=%1，Z=%2，BandZ=%3/%4，GroupZ=%5/%6，TopMost=%7")
                .arg(kAfter.band.ok ? QStringLiteral("%1(%2)").arg(bandName(kAfter.band.value)).arg(kAfter.band.value) : QStringLiteral("<failed>"))
                .arg(kAfter.z)
                .arg(kAfter.bandZ)
                .arg(kAfter.bandWindowCount)
                .arg(kAfter.topMostGroupZ)
                .arg(kAfter.topMostGroupWindowCount)
                .arg(yesNo(hasExStyleFlag(kAfter, WS_EX_TOPMOST)));
            lines << (verified
                ? uiText("window.layer.operation.verified", "结果：回读验证通过")
                : uiText("window.layer.operation.not_verified", "结果：API 已接受，但回读未满足预期；目标进程或系统策略可能立即重写了层级。"));
            const QStringList kChanges = diff(before, kAfter);
            if (kChanges.isEmpty())
            {
                lines << uiText("window.layer.operation.no_changes", "关键字段变化：无");
            }
            else
            {
                lines << uiText("window.layer.operation.changes", "关键字段变化：");
                for (const QString& change : kChanges)
                {
                    lines << QStringLiteral("  %1").arg(change);
                }
            }
            appendOperationLog(lines);
            status_->setText(verified
                ? uiText("window.layer.status.operation_verified", "%1已通过系统回读验证；请保留或等待自动恢复。").arg(actionText(action))
                : uiText("window.layer.status.operation_not_verified", "%1未通过系统回读验证；请查看操作日志和失败原因诊断。").arg(actionText(action)));
        }

        void updateRollbackUi()
        {
            const bool kPending = rollbackBaseline_.has_value();
            if (keepButton_ != nullptr)
            {
                keepButton_->setEnabled(kPending);
            }
            if (restoreButton_ != nullptr)
            {
                restoreButton_->setEnabled(kPending);
            }
            if (rollbackStatus_ == nullptr)
            {
                return;
            }
            if (!kPending)
            {
                rollbackStatus_->setText(uiText("window.layer.rollback.idle", "当前没有待确认的层级修改。"));
                return;
            }
            rollbackStatus_->setText(uiText(
                "window.layer.rollback.pending",
                "%1 秒后自动恢复到操作前状态；连续操作仍回到第一次修改前的状态。")
                .arg(rollbackSecondsRemaining_));
        }

        void keepCurrentState()
        {
            if (!rollbackBaseline_.has_value())
            {
                return;
            }
            rollbackBaseline_.reset();
            rollbackTimer_->stop();
            rollbackSecondsRemaining_ = 0;
            updateRollbackUi();
            const QString kMessage = uiText("window.layer.status.changes_kept", "已保留当前层级修改，并取消自动恢复。");
            appendOperationLog({ QStringLiteral("[%1] %2")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")), kMessage) });
            status_->setText(kMessage);
        }

        void restoreOriginalState(const bool notify)
        {
            if (!rollbackBaseline_.has_value())
            {
                return;
            }

            const Snapshot kBaseline = *rollbackBaseline_;
            rollbackBaseline_.reset();
            if (rollbackTimer_ != nullptr)
            {
                rollbackTimer_->stop();
            }
            rollbackSecondsRemaining_ = 0;
            updateRollbackUi();

            if (!sameWindowIdentity(kBaseline, target_))
            {
                if (notify)
                {
                    const QString kMessage = uiText(
                        "window.layer.status.rollback_identity_changed",
                        "自动恢复已取消：目标 HWND 已销毁或被复用，继续写入可能影响错误窗口。");
                    appendOperationLog({ kMessage });
                    status_->setText(kMessage);
                    QMessageBox::warning(this, uiText("window.layer.rollback.failed_title", "层级恢复失败"), kMessage);
                }
                return;
            }

            BandWriteResult bandResult;
            if (kBaseline.band.ok)
            {
                const HWND kBandInsertAfter = hasExStyleFlag(kBaseline, WS_EX_TOPMOST) ? HWND_TOPMOST : HWND_NOTOPMOST;
                bandResult = writeBand(target_, kBandInsertAfter, kBaseline.band.value);
            }

            const bool kOriginallyTopMost = hasExStyleFlag(kBaseline, WS_EX_TOPMOST);
            ::SetLastError(ERROR_SUCCESS);
            const BOOL kGroupResult = ::SetWindowPos(
                target_,
                kOriginallyTopMost ? HWND_TOPMOST : HWND_NOTOPMOST,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            const DWORD kGroupError = kGroupResult != FALSE ? ERROR_SUCCESS : ::GetLastError();

            BOOL positionResult = kGroupResult;
            DWORD positionError = kGroupError;
            bool previousStillCompatible = false;
            if (kBaseline.previous != nullptr && kBaseline.previous != target_ && ::IsWindow(kBaseline.previous) != FALSE)
            {
                const BandResult kPreviousBand = readBand(kBaseline.previous);
                const LongPtrResult kPreviousExStyle = readLongPtr(kBaseline.previous, GWL_EXSTYLE);
                const bool kPreviousTopMost = kPreviousExStyle.ok && (kPreviousExStyle.value & WS_EX_TOPMOST) != 0;
                previousStillCompatible =
                    (!kBaseline.band.ok || (kPreviousBand.ok && kPreviousBand.value == kBaseline.band.value)) &&
                    kPreviousTopMost == kOriginallyTopMost;
            }
            if (previousStillCompatible)
            {
                ::SetLastError(ERROR_SUCCESS);
                positionResult = ::SetWindowPos(
                    target_,
                    kBaseline.previous,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                positionError = positionResult != FALSE ? ERROR_SUCCESS : ::GetLastError();
            }

            if (!notify)
            {
                return;
            }

            QTimer::singleShot(150, this, [this, kBaseline, bandResult, kGroupError, positionError, previousStillCompatible]() {
                const Snapshot kRestored = capture(target_);
                current_ = kRestored;
                output_->setPlainText(snapshotText(kRestored, initialPid_, initialTid_, initialClass_));
                updateAnalysisViews(kRestored);
                const bool kBandRestored = !kBaseline.band.ok || (kRestored.band.ok && kRestored.band.value == kBaseline.band.value);
                const bool kTopMostRestored = hasExStyleFlag(kRestored, WS_EX_TOPMOST) == hasExStyleFlag(kBaseline, WS_EX_TOPMOST);
                const bool kZRestored = kRestored.topMostGroupZ == kBaseline.topMostGroupZ ||
                    (previousStillCompatible && kRestored.previous == kBaseline.previous) || kRestored.z == kBaseline.z;
                const bool kRestoredOk = kBandRestored && kTopMostRestored && kZRestored;

                QStringList lines;
                lines << QStringLiteral("[%1] %2")
                    .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz")),
                         uiText("window.layer.rollback.log_title", "恢复操作前层级"));
                if (kBaseline.band.ok)
                {
                    lines << uiText("window.layer.rollback.band_result", "Band 恢复请求：%1，错误=%2")
                        .arg(bandResult.ok ? QStringLiteral("accepted") : QStringLiteral("failed"), errorText(bandResult.error));
                }
                lines << uiText("window.layer.rollback.position_result", "TopMost/Z 序恢复错误：group=%1，position=%2")
                    .arg(errorText(kGroupError), errorText(positionError));
                lines << (kRestoredOk
                    ? uiText("window.layer.rollback.verified", "恢复结果：回读验证通过")
                    : uiText("window.layer.rollback.not_verified", "恢复结果：未完全回到原始层级，请检查目标进程是否自行重排窗口。"));
                appendOperationLog(lines);
                status_->setText(kRestoredOk
                    ? uiText("window.layer.status.rollback_complete", "已恢复到操作前层级。")
                    : uiText("window.layer.status.rollback_incomplete", "恢复请求已执行，但回读未完全匹配原状态。"));
            });
        }

        void exportSnapshot()
        {
            if (!current_.has_value()) refresh(uiText("window.layer.status.refresh_before_export", "导出前刷新"));
            const QString kPath = QFileDialog::getSaveFileName(
                this, uiText("window.layer.export.snapshot_title", "导出窗口层级快照"),
                QStringLiteral("window-layer-%1.json").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"))),
                QStringLiteral("JSON (*.json)"));
            if (kPath.isEmpty()) return;

            QJsonObject root;
            root.insert(QStringLiteral("schemaVersion"), 2);
            root.insert(QStringLiteral("capturedAt"), current_->time.toString(Qt::ISODateWithMs));
            root.insert(QStringLiteral("hwnd"), hwndText(current_->hwnd));
            root.insert(QStringLiteral("bandSuccess"), current_->band.ok);
            root.insert(QStringLiteral("band"), static_cast<double>(current_->band.value));
            root.insert(QStringLiteral("bandName"), bandName(current_->band.value));
            root.insert(QStringLiteral("zOrderIndex"), current_->z);
            root.insert(QStringLiteral("bandZOrderIndex"), current_->bandZ);
            root.insert(QStringLiteral("topMostGroupZOrderIndex"), current_->topMostGroupZ);
            root.insert(QStringLiteral("topMostGroupWindowCount"), current_->topMostGroupWindowCount);
            root.insert(QStringLiteral("rollbackPending"), rollbackBaseline_.has_value());
            root.insert(QStringLiteral("relationships"), relationshipGraph(target_));
            root.insert(QStringLiteral("diagnosis"), diagnosisText(*current_));
            root.insert(QStringLiteral("operationLog"), operationLog_ != nullptr ? operationLog_->toPlainText() : QString());
            root.insert(QStringLiteral("text"), snapshotText(*current_, initialPid_, initialTid_, initialClass_));
            QFile file(kPath);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            {
                QMessageBox::warning(this, uiText("window.layer.export.failed_title", "导出失败"), uiText("window.layer.export.failed_message", "无法写入文件。"));
                return;
            }
            file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
            status_->setText(uiText("window.layer.status.snapshot_exported", "快照已导出。"));
        }

        void exportZOrder()
        {
            const QString kPath = QFileDialog::getSaveFileName(
                this, uiText("window.layer.export.z_order_title", "导出完整顶层 Z 序"),
                QStringLiteral("window-z-order-%1.json").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"))),
                QStringLiteral("JSON (*.json)"));
            if (kPath.isEmpty()) return;
            QJsonObject root;
            root.insert(QStringLiteral("generatedAt"), QDateTime::currentDateTime().toString(Qt::ISODateWithMs));
            root.insert(QStringLiteral("warning"), QStringLiteral("Band IDs are identifiers, not linear z-height."));
            root.insert(QStringLiteral("windows"), zOrderJson());
            QFile file(kPath);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            {
                QMessageBox::warning(this, uiText("window.layer.export.failed_title", "导出失败"), uiText("window.layer.export.failed_message", "无法写入文件。"));
                return;
            }
            file.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
            status_->setText(uiText("window.layer.status.z_order_exported", "完整 Z 序已导出。"));
        }

        void startTracking()
        {
            if (tracking_) return;
            auto addHook = [this](DWORD first, DWORD last) {
                const HWINEVENTHOOK kHook = ::SetWinEventHook(
                    first, last, nullptr, winEventProc, 0, 0, WINEVENT_OUTOFCONTEXT);
                if (kHook == nullptr) return;
                {
                    QMutexLocker locker(&hookMutex());
                    hookOwners().insert(reinterpret_cast<quintptr>(kHook), QPointer<Page>(this));
                }
                hooks_.push_back(kHook);
            };
            addHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND);
            addHook(EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND);
            addHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_LOCATIONCHANGE);
            addHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE);
            tracking_ = !hooks_.empty();
            eventSnapshot_ = capture(target_);
            updateTrackButtonText();
            status_->setText(tracking_
                ? uiText("window.layer.status.track_started", "事件追踪已启动。")
                : uiText("window.layer.status.track_failed", "SetWinEventHook 失败。"));
        }

        void stopTracking()
        {
            for (HWINEVENTHOOK hook : hooks_)
            {
                {
                    QMutexLocker locker(&hookMutex());
                    hookOwners().remove(reinterpret_cast<quintptr>(hook));
                }
                ::UnhookWinEvent(hook);
            }
            hooks_.clear();
            tracking_ = false;
            eventSnapshot_.reset();
            updateTrackButtonText();
        }

        void updateTrackButtonText()
        {
            if (trackButton_ == nullptr) return;
            if (tracking_)
            {
                bindUiText(trackButton_, "window.layer.action.track_stop", "停止事件追踪");
            }
            else
            {
                bindUiText(trackButton_, "window.layer.action.track_start", "开始事件追踪");
            }
        }

        HWND target_ = nullptr;
        DWORD initialPid_ = 0;
        DWORD initialTid_ = 0;
        QString initialClass_;
        QLabel* status_ = nullptr;
        QLabel* rollbackStatus_ = nullptr;
        QLineEdit* compare_ = nullptr;
        QPlainTextEdit* output_ = nullptr;
        QPlainTextEdit* operationLog_ = nullptr;
        QPlainTextEdit* relationships_ = nullptr;
        QPlainTextEdit* diagnostics_ = nullptr;
        QPlainTextEdit* events_ = nullptr;
        QPushButton* trackButton_ = nullptr;
        QPushButton* keepButton_ = nullptr;
        QPushButton* restoreButton_ = nullptr;
        QTimer* rollbackTimer_ = nullptr;
        int rollbackSecondsRemaining_ = 0;
        bool tracking_ = false;
        std::vector<HWINEVENTHOOK> hooks_;
        std::optional<Snapshot> current_;
        std::optional<Snapshot> eventSnapshot_;
        std::optional<Snapshot> rollbackBaseline_;
    };

    void CALLBACK winEventProc(
        HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG objectId,
        LONG childId, DWORD eventTid, DWORD eventTime)
    {
        QPointer<Page> owner;
        {
            QMutexLocker locker(&hookMutex());
            owner = hookOwners().value(reinterpret_cast<quintptr>(hook));
        }
        QCoreApplication* app = QCoreApplication::instance();
        if (owner.isNull() || app == nullptr) return;
        QMetaObject::invokeMethod(app, [owner, event, hwnd, objectId, childId, eventTid, eventTime]() {
            if (!owner.isNull()) owner->onWinEvent(event, hwnd, objectId, childId, eventTid, eventTime);
        }, Qt::QueuedConnection);
    }

    std::optional<HWND> targetFromDialog(const QDialog* dialog)
    {
        bool propertyOk = false;
        const qulonglong kPropertyValue = dialog->property(kTargetHwndProperty).toULongLong(&propertyOk);
        if (propertyOk && kPropertyValue != 0)
        {
            return reinterpret_cast<HWND>(static_cast<quintptr>(kPropertyValue));
        }

        // The fallback keeps compatibility with detail dialogs created by an
        // older executable which do not publish the structured HWND property.
        static const QRegularExpression kPattern(QStringLiteral(R"(\((0[xX][0-9A-Fa-f]+)\)\s*$)"));
        const QRegularExpressionMatch kMatch = kPattern.match(dialog->windowTitle());
        return kMatch.hasMatch() ? parseHwnd(kMatch.captured(1)) : std::nullopt;
    }

    QTabWidget* hostTabs(QDialog* dialog)
    {
        QTabWidget* best = nullptr;
        int bestScore = -1;
        for (QTabWidget* tabs : dialog->findChildren<QTabWidget*>())
        {
            int score = tabs->count() + (tabs->parentWidget() == dialog ? 1000 : 0);
            if (score > bestScore)
            {
                best = tabs;
                bestScore = score;
            }
        }
        return best;
    }

    void attach(QDialog* dialog)
    {
        if (dialog == nullptr || dialog->property(kAttachedProperty).toBool()) return;
        const std::optional<HWND> kTarget = targetFromDialog(dialog);
        QTabWidget* tabs = hostTabs(dialog);
        if (!kTarget.has_value() || tabs == nullptr) return;
        tabs->addTab(new Page(*kTarget, tabs), uiText("window.layer.tab.title", "层级诊断"));
        dialog->setProperty(kAttachedProperty, true);
    }

    class Injector final : public QObject
    {
    public:
        explicit Injector(QObject* parent) : QObject(parent) {}

    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (event != nullptr && event->type() == QEvent::Show)
            {
                auto* dialog = qobject_cast<QDialog*>(watched);
                if (dialog != nullptr && dialog->objectName() == QStringLiteral("WindowDetailDialogRoot"))
                {
                    const QPointer<QDialog> kSafe(dialog);
                    QTimer::singleShot(0, dialog, [kSafe]() {
                        if (!kSafe.isNull()) attach(kSafe.data());
                    });
                }
            }
            return QObject::eventFilter(watched, event);
        }
    };

    void install()
    {
        QCoreApplication* app = QCoreApplication::instance();
        if (app == nullptr) return;
        auto* injector = new Injector(app);
        app->installEventFilter(injector);
    }
}

static void installKswordWindowLayerDiagnostics()
{
    ks::window::layerdiag::install();
}

Q_COREAPP_STARTUP_FUNCTION(installKswordWindowLayerDiagnostics)
