#include <Windows.h>
#include "UacDesk.h"
#include "../desktop/Theme.h"

#include <QApplication>
#include <QBoxLayout>
#include <QEvent>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QLabel>
#include <QMessageBox>
#include <QFileIconProvider>
#include <QImage>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QScreen>
#include <QStyle>
#include <QStyleHints>
#include <QWindow>
#include <QMouseEvent>

#include <Psapi.h>
#include <TlHelp32.h>
#include <Sddl.h>
#include <Tdh.h>
#include <Objbase.h>
#include <oleacc.h>
#include <UIAutomation.h>
#include <WtsApi32.h>
#include <shellapi.h>
#include <strsafe.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

#include <algorithm>
#include <cwctype>
#include <cstring>
#include <functional>
#include <limits>
#include <numeric>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Oleacc.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Uiautomationcore.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Wintrust.lib")

namespace
{
    constexpr wchar_t kWinlogonDesktop[] = L"winsta0\\Winlogon";
    constexpr wchar_t kWinlogonDesktopName[] = L"Winlogon";
    constexpr wchar_t kOwnerMutexPrefix[] = L"Global\\KswordUacDesk.Owner.";
    constexpr wchar_t kReadyEventPrefix[] = L"Global\\KswordUacDesk.Ready.";
    constexpr ULONGLONG kLuaDiagnosticKeyword = 0x8000000000000000ULL;
    constexpr ULONGLONG kSystemAlpcKeyword = 0x0000000000000001ULL;
    constexpr GUID kUacAlpcEtwSessionGuid =
        {0x7a2d2d2c, 0x8ca4, 0x4a95, {0x9c, 0x84, 0x4f, 0x65, 0x6e, 0x9c, 0x7b, 0x1e}};
    constexpr wchar_t kEtwSessionPrefix[] = L"KswordUacDesk.";
    constexpr DWORD kDesktopSwitchEvent = EVENT_SYSTEM_DESKTOPSWITCH;
    constexpr ULONG kAlpcSendEvent = 33;
    constexpr ULONG kAlpcReceiveEvent = 34;
    constexpr quint64 kAlpcSendRetentionMs = 10000;
    constexpr quint64 kUacCorrelationWindowMs = 5000;
    // AppInfo's consent request is private implementation detail, not a
    // supported ABI.  The currently tested layouts differ between the
    // Windows 10 and Windows 11 build families.
    constexpr size_t kAppInfoWin10OriginPidOffset = 0x68;
    constexpr size_t kAppInfoWin10TargetPathOffset = 0x70;
    constexpr size_t kAppInfoWin11OriginPidOffset = 0xF0;
    constexpr size_t kAppInfoWin11TargetPathOffset = 0xFC;
    constexpr DWORD kWindows11BuildNumber = 22000;
    const GUID kLuaProvider = {0x93c05d69, 0x51a3, 0x485e, {0x87, 0x7f, 0x18, 0x06, 0xa8, 0x73, 0x13, 0x46}};
    const GUID kSystemAlpcProvider = {0xfcb9baaf, 0xe529, 0x4980, {0x92, 0xe9, 0xce, 0xd1, 0xa6, 0xaa, 0xdf, 0xdf}};
    // The legacy ALPCGuid is what the classic SystemTraceProvider emits in the
    // event header. Microsoft documents that system-provider enablement does not
    // rewrite those records to the individual SystemAlpcProvider GUID.
    const GUID kLegacyAlpcProvider = {0x45d8cccd, 0x539f, 0x4b72, {0xa8, 0xb7, 0x5c, 0x68, 0x31, 0x42, 0x60, 0x9a}};
    UacEventMonitor* gEventMonitor = nullptr;

    void appendDiagnosticLog(const QString& message)
    {
        CreateDirectoryW(L"E:\\Temp", nullptr);
        HANDLE file = CreateFileW(L"E:\\Temp\\KswordUacDesk-stage.log", FILE_APPEND_DATA,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return;

        SYSTEMTIME now{};
        GetLocalTime(&now);
        const QString kLine = QStringLiteral("%1-%2-%3 %4:%5:%6.%7 pid=%8 tid=%9 %10\r\n")
            .arg(now.wYear, 4, 10, QLatin1Char('0'))
            .arg(now.wMonth, 2, 10, QLatin1Char('0'))
            .arg(now.wDay, 2, 10, QLatin1Char('0'))
            .arg(now.wHour, 2, 10, QLatin1Char('0'))
            .arg(now.wMinute, 2, 10, QLatin1Char('0'))
            .arg(now.wSecond, 2, 10, QLatin1Char('0'))
            .arg(now.wMilliseconds, 3, 10, QLatin1Char('0'))
            .arg(GetCurrentProcessId())
            .arg(GetCurrentThreadId())
            .arg(message);
        const QByteArray kUtf8 = kLine.toUtf8();
        DWORD written = 0;
        WriteFile(file, kUtf8.constData(), static_cast<DWORD>(kUtf8.size()), &written, nullptr);
        CloseHandle(file);
    }

    QString winError(DWORD error = GetLastError())
    {
        wchar_t buffer[512] = {};
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0,
                       buffer, static_cast<DWORD>(std::size(buffer)), nullptr);
        return QString::fromWCharArray(buffer).trimmed() + QStringLiteral(" (0x") + QString::number(error, 16) + QLatin1Char(')');
    }

    DWORD windowsBuildNumber()
    {
        using RtlGetVersionFn = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);
        const HMODULE kNtdll = GetModuleHandleW(L"ntdll.dll");
        const auto kRtlGetVersion = kNtdll
            ? reinterpret_cast<RtlGetVersionFn>(GetProcAddress(kNtdll, "RtlGetVersion"))
            : nullptr;
        if (!kRtlGetVersion)
            return 0;

        RTL_OSVERSIONINFOEXW version{};
        version.dwOSVersionInfoSize = sizeof(version);
        return kRtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&version)) == 0
            ? version.dwBuildNumber
            : 0;
    }

    QString timestampedEtwSessionName(const QString& component = {})
    {
        const QString kTimestamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMddHHmmsszzz"));
        const QString kStem = component.isEmpty()
            ? QStringLiteral("KswordUacDesk")
            : QStringLiteral("KswordUacDesk.") + component;
        return QStringLiteral("%1.%2.%3").arg(kStem, kTimestamp).arg(GetCurrentProcessId());
    }

    void cleanupStaleEtwSessions()
    {
        constexpr ULONG kEtwQueryCapacity = 128;
        constexpr ULONG kEtwPropertyBytes = sizeof(EVENT_TRACE_PROPERTIES) + 2048;
        std::vector<std::vector<BYTE>> buffers;
        buffers.resize(kEtwQueryCapacity);
        std::vector<PEVENT_TRACE_PROPERTIES> properties;
        properties.reserve(kEtwQueryCapacity);
        for (auto& buffer : buffers)
        {
            buffer.resize(kEtwPropertyBytes, 0);
            auto* value = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
            value->Wnode.BufferSize = kEtwPropertyBytes;
            properties.push_back(value);
        }

        ULONG loggerCount = 0;
        const ULONG kQueryStatus = QueryAllTracesW(properties.data(), kEtwQueryCapacity, &loggerCount);
        if (kQueryStatus != ERROR_SUCCESS && kQueryStatus != ERROR_MORE_DATA)
        {
            PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                "etw-cleanup: QueryAllTracesW failed status=0x%1 (%2)")
                .arg(kQueryStatus, 0, 16).arg(winError(kQueryStatus)));
            return;
        }

        const ULONG kInspected = std::min(loggerCount, kEtwQueryCapacity);
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "etw-cleanup: enumerated sessions=%1 queryStatus=0x%2")
            .arg(kInspected).arg(kQueryStatus, 0, 16));
        for (ULONG i = 0; i < kInspected; ++i)
        {
            auto* value = properties[i];
            if (!value || value->LoggerNameOffset < sizeof(EVENT_TRACE_PROPERTIES) ||
                value->LoggerNameOffset >= kEtwPropertyBytes)
                continue;
            const auto* name = reinterpret_cast<const wchar_t*>(
                buffers[i].data() + value->LoggerNameOffset);
            const QString kSessionName = QString::fromWCharArray(name).trimmed();
            if (!kSessionName.startsWith(QString::fromWCharArray(kEtwSessionPrefix), Qt::CaseSensitive))
                continue;

            const ULONG kStopStatus = ControlTraceW(0, name, value, EVENT_TRACE_CONTROL_STOP);
            PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                "etw-cleanup: stop name=%1 status=0x%2")
                .arg(kSessionName).arg(kStopStatus, 0, 16));
        }
    }

    QString lowerFileName(const QString& path)
    {
        return QFileInfo(path).fileName().toLower();
    }

    QString versionStringValue(const QString& path, const wchar_t* valueName)
    {
        if (path.isEmpty() || !valueName) return {};
        const std::wstring kWidePath = path.toStdWString();
        DWORD ignored = 0;
        const DWORD kSize = GetFileVersionInfoSizeW(kWidePath.c_str(), &ignored);
        if (kSize == 0) return {};
        std::vector<BYTE> buffer(kSize);
        if (!GetFileVersionInfoW(kWidePath.c_str(), 0, kSize, buffer.data())) return {};

        struct Translation { WORD language; WORD codePage; };
        Translation* translations = nullptr;
        UINT translationBytes = 0;
        if (VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation",
                           reinterpret_cast<LPVOID*>(&translations), &translationBytes) &&
            translations && translationBytes >= sizeof(Translation))
        {
            const UINT kCount = translationBytes / sizeof(Translation);
            for (UINT i = 0; i < kCount; ++i)
            {
                const QString kQuery = QStringLiteral("\\StringFileInfo\\%1%2\\%3")
                    .arg(translations[i].language, 4, 16, QLatin1Char('0'))
                    .arg(translations[i].codePage, 4, 16, QLatin1Char('0'))
                    .arg(QString::fromWCharArray(valueName));
                LPVOID value = nullptr;
                UINT valueChars = 0;
                if (VerQueryValueW(buffer.data(), kQuery.toStdWString().c_str(), &value, &valueChars) &&
                    value && valueChars > 0)
                    return QString::fromWCharArray(static_cast<const wchar_t*>(value), static_cast<int>(valueChars)).trimmed();
            }
        }
        return {};
    }

    bool isSamePath(const QString& left, const QString& right)
    {
        return QString::compare(QDir::cleanPath(left), QDir::cleanPath(right), Qt::CaseInsensitive) == 0;
    }

    QString windowText(HWND hwnd)
    {
        const int kLength = GetWindowTextLengthW(hwnd);
        if (kLength <= 0)
            return {};
        std::wstring value(static_cast<size_t>(kLength) + 1, L'\0');
        GetWindowTextW(hwnd, value.data(), kLength + 1);
        return QString::fromStdWString(value.c_str());
    }

    QString windowClassName(HWND hwnd)
    {
        wchar_t buffer[256] = {};
        const int kLength = GetClassNameW(hwnd, buffer, static_cast<int>(std::size(buffer)));
        return kLength > 0 ? QString::fromWCharArray(buffer, kLength) : QStringLiteral("<unknown>");
    }

    bool containsAny(const QString& value, const QStringList& needles)
    {
        for (const QString& needle : needles)
        {
            if (value.contains(needle, Qt::CaseInsensitive))
                return true;
        }
        return false;
    }

    void appendUniqueText(QStringList& values, const QString& value)
    {
        const QString kTrimmed = value.trimmed();
        if (kTrimmed.isEmpty() || kTrimmed.size() > 512)
            return;
        for (const QString& existing : values)
        {
            if (existing.compare(kTrimmed, Qt::CaseSensitive) == 0)
                return;
        }
        values.push_back(kTrimmed);
    }

    QString etwPropertyValue(UCHAR inType, const BYTE* data, ULONG size)
    {
        if (!data || size == 0)
            return {};

        switch (inType)
        {
        case TDH_INTYPE_UNICODESTRING:
        case TDH_INTYPE_COUNTEDSTRING:
        case TDH_INTYPE_NONNULLTERMINATEDSTRING:
        {
            const size_t kChars = size / sizeof(wchar_t);
            return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data), static_cast<int>(kChars)).trimmed();
        }
        case TDH_INTYPE_ANSISTRING:
            return QString::fromUtf8(reinterpret_cast<const char*>(data), static_cast<int>(size)).trimmed();
        case TDH_INTYPE_UINT8:
            return size >= 1 ? QString::number(*data) : QString();
        case TDH_INTYPE_UINT16:
        {
            WORD value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return QString::number(value);
        }
        case TDH_INTYPE_UINT32:
        case TDH_INTYPE_HEXINT32:
        {
            DWORD value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return inType == TDH_INTYPE_HEXINT32
                ? QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0'))
                : QString::number(value);
        }
        case TDH_INTYPE_UINT64:
        case TDH_INTYPE_HEXINT64:
        {
            ULONGLONG value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return inType == TDH_INTYPE_HEXINT64
                ? QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0'))
                : QString::number(value);
        }
        case TDH_INTYPE_INT32:
        {
            LONG value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return QString::number(value);
        }
        case TDH_INTYPE_INT64:
        {
            LONGLONG value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return QString::number(value);
        }
        case TDH_INTYPE_BOOLEAN:
            return size >= sizeof(BOOL) && *reinterpret_cast<const BOOL*>(data) ? QStringLiteral("true") : QStringLiteral("false");
        default:
            return QByteArray(reinterpret_cast<const char*>(data), static_cast<int>(std::min<ULONG>(size, 32))).toHex(' ').toUpper();
        }
    }

    quint64 currentTraceTimeMs()
    {
        FILETIME fileTime{};
        GetSystemTimePreciseAsFileTime(&fileTime);
        return (static_cast<quint64>(fileTime.dwHighDateTime) << 32 | fileTime.dwLowDateTime) / 10000ULL;
    }

    quint64 eventTraceTimeMs(PEVENT_RECORD record)
    {
        if (!record)
            return currentTraceTimeMs();
        const quint64 kRaw = static_cast<quint64>(record->EventHeader.TimeStamp.QuadPart);
        return kRaw > 100000000000ULL ? kRaw / 10000ULL : currentTraceTimeMs();
    }

    bool tdhNumericProperty(PEVENT_RECORD record, const QStringList& names, ULONGLONG& value)
    {
        value = 0;
        if (!record) return false;
        ULONG infoSize = 0;
        if (TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize) != ERROR_INSUFFICIENT_BUFFER || infoSize == 0)
            return false;
        std::vector<BYTE> infoBuffer(infoSize);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
        if (TdhGetEventInformation(record, 0, nullptr, info, &infoSize) != ERROR_SUCCESS)
            return false;
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[i];
            if ((property.Flags & PropertyStruct) != 0 || property.NameOffset == 0) continue;
            const QString kPropertyName = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(infoBuffer.data() + property.NameOffset));
            bool wanted = false;
            for (const QString& name : names)
                if (kPropertyName.compare(name, Qt::CaseInsensitive) == 0) { wanted = true; break; }
            if (!wanted) continue;
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(infoBuffer.data() + property.NameOffset);
            descriptor.ArrayIndex = ULONG_MAX;
            ULONG size = 0;
            if (TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0 || size > sizeof(ULONGLONG))
                return false;
            std::vector<BYTE> data(size);
            if (TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, data.data()) != ERROR_SUCCESS)
                return false;
            std::memcpy(&value, data.data(), size);
            return true;
        }
        return false;
    }

    QString tdhStringProperty(PEVENT_RECORD record, const QStringList& names)
    {
        if (!record) return {};
        ULONG infoSize = 0;
        if (TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize) != ERROR_INSUFFICIENT_BUFFER || infoSize == 0)
            return {};
        std::vector<BYTE> infoBuffer(infoSize);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
        if (TdhGetEventInformation(record, 0, nullptr, info, &infoSize) != ERROR_SUCCESS)
            return {};
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[i];
            if ((property.Flags & PropertyStruct) != 0 || property.NameOffset == 0) continue;
            const QString kPropertyName = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(infoBuffer.data() + property.NameOffset));
            bool wanted = false;
            for (const QString& name : names)
                if (kPropertyName.compare(name, Qt::CaseInsensitive) == 0) { wanted = true; break; }
            if (!wanted) continue;
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(infoBuffer.data() + property.NameOffset);
            descriptor.ArrayIndex = ULONG_MAX;
            ULONG size = 0;
            if (TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0 || size > 65536)
                return {};
            std::vector<BYTE> data(size);
            if (TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, data.data()) != ERROR_SUCCESS)
                return {};
            return etwPropertyValue(property.nonStructType.InType, data.data(), size);
        }
        return {};
    }

    QString decodeEtwPayload(PEVENT_RECORD record)
    {
        if (!record)
            return {};

        ULONG infoSize = 0;
        TDHSTATUS status = TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize);
        if (status != ERROR_INSUFFICIENT_BUFFER || infoSize == 0)
            return QStringLiteral("schema-error=0x%1").arg(status, 0, 16);

        std::vector<BYTE> infoBuffer(infoSize);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
        status = TdhGetEventInformation(record, 0, nullptr, info, &infoSize);
        if (status != ERROR_SUCCESS)
            return QStringLiteral("schema-error=0x%1").arg(status, 0, 16);

        QStringList properties;
        const ULONG kPropertyCount = std::min<ULONG>(info->TopLevelPropertyCount, 32);
        for (ULONG i = 0; i < kPropertyCount; ++i)
        {
            const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[i];
            if ((property.Flags & PropertyStruct) != 0 || property.NameOffset == 0)
                continue;

            const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(infoBuffer.data() + property.NameOffset);
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
            descriptor.ArrayIndex = ULONG_MAX;

            ULONG propertySize = 0;
            status = TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &propertySize);
            if (status != ERROR_SUCCESS || propertySize == 0 || propertySize > 64 * 1024)
            {
                properties.push_back(QStringLiteral("%1=<unreadable:0x%2>")
                                         .arg(QString::fromWCharArray(propertyName))
                                         .arg(status, 0, 16));
                continue;
            }

            std::vector<BYTE> value(propertySize);
            status = TdhGetProperty(record, 0, nullptr, 1, &descriptor, propertySize, value.data());
            if (status != ERROR_SUCCESS)
            {
                properties.push_back(QStringLiteral("%1=<read-failed:0x%2>")
                                         .arg(QString::fromWCharArray(propertyName))
                                         .arg(status, 0, 16));
                continue;
            }

            const QString kFormatted = etwPropertyValue(property.nonStructType.InType, value.data(), propertySize);
            properties.push_back(QStringLiteral("%1=%2").arg(QString::fromWCharArray(propertyName), kFormatted.left(512)));
        }
        return properties.join(QStringLiteral(", "));
    }

    ULONG alpcMessageId(PEVENT_RECORD record)
    {
        ULONGLONG value = 0;
        if (!tdhNumericProperty(record, {QStringLiteral("MessageId"), QStringLiteral("MessageID")}, value))
            return 0;
        return static_cast<ULONG>(value);
    }

    QStringList uacTextValues(const QString& automationText)
    {
        QStringList values;
        for (const QString& part : automationText.split(QStringLiteral(" | "), Qt::SkipEmptyParts))
        {
            const int kMarker = part.indexOf(QStringLiteral("Text="));
            if (kMarker < 0)
                continue;
            appendUniqueText(values, part.mid(kMarker + 5));
        }
        return values;
    }

    QString uacApplicationNameFromText(const QString& automationText)
    {
        const QStringList kValues = uacTextValues(automationText);
        for (const QString& value : kValues)
        {
            if (value.compare(QStringLiteral("用户帐户控制"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("User Account Control"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("是"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("否"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("Yes"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("No"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("关闭"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("Close"), Qt::CaseInsensitive) == 0 ||
                value.contains(QStringLiteral("允许此应用"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("allow this app"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("已验证的发布者"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("verified publisher"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("显示更多详细信息"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("show more details"), Qt::CaseInsensitive))
                continue;
            return value;
        }
        return {};
    }

    QString uacPublisherFromText(const QString& automationText)
    {
        for (const QString& value : uacTextValues(automationText))
        {
            const QStringList kSeparators = {QStringLiteral(":"), QStringLiteral("：")};
            for (const QString& separator : kSeparators)
            {
                const int kIndex = value.indexOf(separator);
                if (kIndex >= 0 && (value.contains(QStringLiteral("发布者"), Qt::CaseInsensitive) ||
                                   value.contains(QStringLiteral("publisher"), Qt::CaseInsensitive)))
                    return value.mid(kIndex + 1).trimmed();
            }
        }
        return {};
    }

    QString uacPathFromText(const QString& automationText)
    {
        static const QRegularExpression kPathExpression(
            QStringLiteral(R"(([A-Za-z]:\\[^|\r\n"]+?\.exe))"),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch kMatch = kPathExpression.match(automationText);
        return kMatch.hasMatch() ? kMatch.captured(1).trimmed() : QString();
    }

    QString desktopProcessName(HWND hwnd)
    {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        ProcessIdentity identity;
        if (pid != 0 && ProcessInspector::query(pid, identity))
            return lowerFileName(identity.imagePath);
        return {};
    }

    QString collectChildText(HWND hwnd)
    {
        QStringList values;
        EnumChildWindows(hwnd, &UacWindowScanner::enumChildProc, reinterpret_cast<LPARAM>(&values));
        return values.join(QStringLiteral(" | "));
    }

    bool getTokenElevation(HANDLE token)
    {
        TOKEN_ELEVATION elevation{};
        DWORD length = 0;
        return GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length) && elevation.TokenIsElevated != 0;
    }

    bool tokenIsSystem(HANDLE token)
    {
        DWORD length = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &length);
        if (length == 0)
            return false;
        std::vector<BYTE> data(length);
        if (!GetTokenInformation(token, TokenUser, data.data(), length, &length))
            return false;
        const auto* user = reinterpret_cast<const TOKEN_USER*>(data.data());
        PSID systemSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid))
            return false;
        const bool kResult = EqualSid(user->User.Sid, systemSid) != FALSE;
        FreeSid(systemSid);
        return kResult;
    }

    bool enableTokenPrivilege(HANDLE token, LPCWSTR privilegeName)
    {
        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) return false;
        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) return false;
        return GetLastError() == ERROR_SUCCESS;
    }

    bool enableCurrentProcessPrivilege(LPCWSTR privilegeName)
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
        const bool kResult = enableTokenPrivilege(token, privilegeName);
        CloseHandle(token);
        return kResult;
    }

    bool tokenBelongsToLocalSystem(HANDLE token)
    {
        DWORD length = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &length);
        if (length == 0) return false;
        std::vector<BYTE> buffer(length);
        if (!GetTokenInformation(token, TokenUser, buffer.data(), length, &length)) return false;
        BYTE sidBuffer[SECURITY_MAX_SID_SIZE]{};
        DWORD sidLength = sizeof(sidBuffer);
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sidBuffer, &sidLength)) return false;
        const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
        return EqualSid(user->User.Sid, sidBuffer) != FALSE;
    }

    class ScopedImpersonation final
    {
    public:
        ~ScopedImpersonation() { reset(); }
        bool begin(HANDLE token) { reset(); active_ = ImpersonateLoggedOnUser(token) != FALSE; return active_; }
        void reset() { if (active_) RevertToSelf(); active_ = false; }
    private:
        bool active_ = false;
    };

    bool queryTokenSessionId(HANDLE token, DWORD& sessionId, QString& error)
    {
        sessionId = 0;
        DWORD length = 0;
        if (!GetTokenInformation(token, TokenSessionId, nullptr, 0, &length) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            error = QStringLiteral("GetTokenInformation(TokenSessionId) 查询大小失败：") + winError();
            return false;
        }
        if (length < sizeof(DWORD) || !GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId), &length))
        {
            error = QStringLiteral("GetTokenInformation(TokenSessionId) 读取失败：") + winError();
            return false;
        }
        return true;
    }

    bool duplicateSystemTokenForSession(DWORD sessionId, HANDLE& result, QString& error)
    {
        result = nullptr;
        error.clear();
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("token: begin, targetSession=%1").arg(sessionId));
        if (!PrivilegeStage::isProcessElevated())
        {
            error = QStringLiteral("当前阶段不是提升管理员，不能打开 SYSTEM 进程令牌。");
            return false;
        }
        enableCurrentProcessPrivilege(SE_DEBUG_NAME);
        enableCurrentProcessPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
        enableCurrentProcessPrivilege(SE_INCREASE_QUOTA_NAME);
        enableCurrentProcessPrivilege(SE_TCB_NAME);
        enableCurrentProcessPrivilege(SE_IMPERSONATE_NAME);

        DWORD sourcePid = 0;
        int bestRank = 0;

        PROCESSENTRY32W entry{sizeof(entry)};
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            error = QStringLiteral("CreateToolhelp32Snapshot：") + winError();
            return false;
        }
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry))
        {
            DWORD candidateSession = 0;
            ProcessIdToSessionId(entry.th32ProcessID, &candidateSession);
            const bool kSameSession = candidateSession == sessionId;
            int rank = 0;
            if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0) rank = kSameSession ? 40 : 30;
            else if (_wcsicmp(entry.szExeFile, L"services.exe") == 0) rank = kSameSession ? 20 : 10;
            if (rank > bestRank) { bestRank = rank; sourcePid = entry.th32ProcessID; }
        }
        CloseHandle(snapshot);
        if (sourcePid == 0)
        {
            error = QStringLiteral("没有找到当前 Session 的 winlogon.exe 或 services.exe SYSTEM 令牌源。");
            return false;
        }
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("token: selected source pid=%1 rank=%2").arg(sourcePid).arg(bestRank));

        HANDLE sourceProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid);
        if (!sourceProcess)
        {
            error = QStringLiteral("OpenProcess(SYSTEM 令牌源 PID=%1) 失败：").arg(sourcePid) + winError();
            return false;
        }
        HANDLE sourceToken = nullptr;
        if (!OpenProcessToken(sourceProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &sourceToken))
        {
            error = QStringLiteral("OpenProcessToken(SYSTEM 令牌源 PID=%1) 失败：").arg(sourcePid) + winError();
            CloseHandle(sourceProcess);
            return false;
        }
        const bool kSourceIsSystem = tokenBelongsToLocalSystem(sourceToken);
        if (!kSourceIsSystem)
        {
            error = QStringLiteral("选中的令牌源 PID=%1 不是 LocalSystem。").arg(sourcePid);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("token: source pid=%1 verified LocalSystem").arg(sourcePid));

        DWORD sourceTokenSession = 0;
        if (!queryTokenSessionId(sourceToken, sourceTokenSession, error))
        {
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("token: source token session=%1").arg(sourceTokenSession));

        SECURITY_ATTRIBUTES security{sizeof(security)};
        HANDLE impersonationToken = nullptr;
        if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &security, SecurityImpersonation, TokenImpersonation, &impersonationToken))
        {
            error = QStringLiteral("DuplicateTokenEx(TokenImpersonation) 失败：") + winError();
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        ScopedImpersonation impersonation;
        if (!impersonation.begin(impersonationToken))
        {
            error = QStringLiteral("ImpersonateLoggedOnUser(SYSTEM) 失败：") + winError();
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        enableTokenPrivilege(impersonationToken, SE_ASSIGNPRIMARYTOKEN_NAME);
        enableTokenPrivilege(impersonationToken, SE_INCREASE_QUOTA_NAME);
        enableTokenPrivilege(impersonationToken, SE_TCB_NAME);

        HANDLE primaryToken = nullptr;
        if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &security, SecurityImpersonation, TokenPrimary, &primaryToken))
        {
            error = QStringLiteral("DuplicateTokenEx(TokenPrimary) 失败：") + winError();
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        enableTokenPrivilege(primaryToken, SE_ASSIGNPRIMARYTOKEN_NAME);
        enableTokenPrivilege(primaryToken, SE_INCREASE_QUOTA_NAME);
        enableTokenPrivilege(primaryToken, SE_TCB_NAME);
        if (sourceTokenSession != sessionId && !SetTokenInformation(primaryToken, TokenSessionId, &sessionId, sizeof(sessionId)))
        {
            error = QStringLiteral("SetTokenInformation(TokenSessionId=%1) 失败：").arg(sessionId) + winError();
            CloseHandle(primaryToken);
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        DWORD uiAccess = 1;
        if (!SetTokenInformation(primaryToken, TokenUIAccess, &uiAccess, sizeof(uiAccess)))
        {
            error = QStringLiteral("SetTokenInformation(TokenUIAccess=1) 失败：") + winError();
            CloseHandle(primaryToken);
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        DWORD verifiedUiAccess = 0;
        DWORD verifiedLength = 0;
        if (!GetTokenInformation(primaryToken, TokenUIAccess, &verifiedUiAccess, sizeof(verifiedUiAccess), &verifiedLength) || verifiedUiAccess == 0)
        {
            error = QStringLiteral("TokenUIAccess 设置后校验失败：") + winError();
            CloseHandle(primaryToken);
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("token: primary token UIAccess verified=1, targetSession=%1").arg(sessionId));

        CloseHandle(impersonationToken);
        CloseHandle(sourceToken);
        CloseHandle(sourceProcess);
        result = primaryToken;
        return true;
    }

    QString ownerMutexName(DWORD sessionId)
    {
        return QString::fromWCharArray(kOwnerMutexPrefix) + QString::number(sessionId);
    }

    QString readyEventName(DWORD pid)
    {
        return QString::fromWCharArray(kReadyEventPrefix) + QString::number(pid);
    }

    bool isWinlogonDesktop()
    {
        return PrivilegeStage::currentDesktopName().compare(QStringLiteral("Winlogon"), Qt::CaseInsensitive) == 0;
    }

    QPixmap removeFlatBackground(const QPixmap& source)
    {
        if (source.isNull()) return source;
        QImage image = source.toImage().convertToFormat(QImage::Format_ARGB32);
        if (image.isNull()) return source;
        const QColor kCorner = image.pixelColor(0, 0);
        // Some icon sizes are already transparent at the corner while still
        // carrying an opaque white matte around the artwork.
        const QColor kKey = kCorner.alpha() == 0 ? QColor(Qt::white) : kCorner;
        for (int y = 0; y < image.height(); ++y)
        {
            for (int x = 0; x < image.width(); ++x)
            {
                const QColor kPixel = image.pixelColor(x, y);
                if (kPixel.alpha() != 0 &&
                    std::abs(kPixel.red() - kKey.red()) <= 24 &&
                    std::abs(kPixel.green() - kKey.green()) <= 24 &&
                    std::abs(kPixel.blue() - kKey.blue()) <= 24)
                {
                    image.setPixelColor(x, y, QColor(kPixel.red(), kPixel.green(), kPixel.blue(), 0));
                }
            }
        }
        return QPixmap::fromImage(image);
    }

    class UacBrandHeaderWidget final : public QWidget
    {
    public:
        explicit UacBrandHeaderWidget(const QIcon& icon, QWidget* parent = nullptr)
            : QWidget(parent),
              iconPixmap_(removeFlatBackground(icon.pixmap(QSize(32, 32))))
        {
            // Keep the branding bar compact.  The companion window height is
            // determined by its complete content, not by the UAC window.
            setFixedHeight(31);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            const QRect kBounds = rect();
            const QColor kSurface = palette().color(QPalette::Window);
            painter.fillRect(kBounds, kSurface);

            const QRect kIconRect(10, 3, 26, 25);
            if (!iconPixmap_.isNull())
            {
                const QPixmap kIconPixmap = iconPixmap_.scaled(QSize(22, 22),
                                                                Qt::KeepAspectRatio,
                                                                Qt::SmoothTransformation);
                painter.drawPixmap(kIconRect.center() - QPoint(kIconPixmap.width() / 2, kIconPixmap.height() / 2), kIconPixmap);
            }

            painter.setPen(palette().color(QPalette::WindowText));
            painter.setFont(font());
            painter.drawText(QRect(42, 0, width() - 42, height()),
                             Qt::AlignVCenter | Qt::AlignLeft, QStringLiteral("UAC诊断"));

            painter.setPen(palette().color(QPalette::Mid));
            painter.drawLine(0, height() - 1, width() - 1, height() - 1);
        }

    private:
        QPixmap iconPixmap_;
    };

    void applySystemPalette()
    {
        QPalette palette = qApp->palette();
        const QStyleHints* hints = QGuiApplication::styleHints();
        const Qt::ColorScheme kScheme = hints ? hints->colorScheme() : Qt::ColorScheme::Unknown;
        const bool kDark = kScheme == Qt::ColorScheme::Dark ||
                          (kScheme == Qt::ColorScheme::Unknown &&
                           palette.color(QPalette::Window).lightness() < 128);
        const QColor kWindow = kDark
            ? QColor(29, 31, 34)
            : QColor(250, 250, 250);
        const QColor kSurface = kDark
            ? QColor(39, 42, 46)
            : QColor(255, 255, 255);
        const QColor kText = kDark
            ? QColor(241, 243, 245)
            : QColor(24, 26, 28);
        const QColor kSecondary = kDark
            ? QColor(170, 176, 183)
            : QColor(92, 98, 105);
        const QColor kAccent = ksword_theme::defaultPrimaryAccentColor();
        palette.setColor(QPalette::Window, kWindow);
        palette.setColor(QPalette::Base, kSurface);
        palette.setColor(QPalette::AlternateBase, kWindow);
        palette.setColor(QPalette::Button, kSurface);
        palette.setColor(QPalette::WindowText, kText);
        palette.setColor(QPalette::Text, kText);
        palette.setColor(QPalette::ButtonText, kText);
        palette.setColor(QPalette::PlaceholderText, kSecondary);
        palette.setColor(QPalette::Mid, kDark ? QColor(100, 108, 117) : QColor(151, 158, 166));
        palette.setColor(QPalette::Highlight, kAccent);
        palette.setColor(QPalette::HighlightedText, Qt::white);
        qApp->setPalette(palette);
    }

    QString uacDeskSystemStyle()
    {
        return QStringLiteral(
            "QMainWindow{background:palette(window);color:palette(window-text);border:none;}"
            "QWidget#kswordUacDeskRoot{background:palette(window);color:palette(window-text);}"
            "QLabel{background:transparent;color:palette(window-text);}"
            "QLabel#uacIdentityLabel{color:palette(window-text);}"
            "QLabel#uacProcessDetailsLabel{color:#000000;}"
            "QPushButton{min-height:24px;max-height:24px;padding:1px 7px;background:palette(button);color:palette(button-text);"
            "border:1px solid palette(highlight);border-radius:0;}"
            "QPushButton#uacTerminateButton{background:palette(highlight);color:palette(highlighted-text);}"
            "QPushButton:hover{background:palette(highlight);color:palette(highlighted-text);}"
            "QPushButton:pressed{background:palette(dark);color:palette(button-text);}"
            "QPushButton:disabled{background:palette(window);color:palette(mid);border:1px solid palette(mid);}"
            "QPushButton:focus{border:1px solid palette(highlight);outline:none;}");
    }
}

void PrivilegeStage::writeDiagnosticLog(const QString& message)
{
    appendDiagnosticLog(message);
}

QString formatFileTime(quint64 fileTime)
{
    if (fileTime == 0)
        return QStringLiteral("未知");
    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(fileTime & 0xffffffffULL);
    ft.dwHighDateTime = static_cast<DWORD>(fileTime >> 32);
    SYSTEMTIME systemTime{};
    if (!FileTimeToSystemTime(&ft, &systemTime))
        return QStringLiteral("未知");
    return QStringLiteral("%1-%2-%3 %4:%5:%6")
        .arg(systemTime.wYear, 4, 10, QLatin1Char('0'))
        .arg(systemTime.wMonth, 2, 10, QLatin1Char('0'))
        .arg(systemTime.wDay, 2, 10, QLatin1Char('0'))
        .arg(systemTime.wHour, 2, 10, QLatin1Char('0'))
        .arg(systemTime.wMinute, 2, 10, QLatin1Char('0'))
        .arg(systemTime.wSecond, 2, 10, QLatin1Char('0'));
}

quint64 processCreationTime(HANDLE process)
{
    FILETIME creation{}, exitTime{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exitTime, &kernel, &user))
        return 0;
    return (static_cast<quint64>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
}

QString quoteArgument(const QString& value)
{
    QString result = QStringLiteral("\"");
    int backslashes = 0;
    for (const QChar kCh : value)
    {
        if (kCh == QLatin1Char('\\'))
        {
            ++backslashes;
        }
        else if (kCh == QLatin1Char('"'))
        {
            result += QString(backslashes * 2 + 1, QLatin1Char('\\'));
            result += QLatin1Char('"');
            backslashes = 0;
        }
        else
        {
            result += QString(backslashes, QLatin1Char('\\'));
            result += kCh;
            backslashes = 0;
        }
    }
    result += QString(backslashes * 2, QLatin1Char('\\'));
    result += QLatin1Char('"');
    return result;
}

QString ProcessInspector::fileName(const QString& path)
{
    return QFileInfo(path).fileName();
}

bool ProcessInspector::query(DWORD pid, ProcessIdentity& identity, DWORD desiredAccess)
{
    identity = {};
    HANDLE process = OpenProcess(desiredAccess | SYNCHRONIZE, FALSE, pid);
    if (!process)
        return false;
    identity.pid = pid;
    identity.creationTime = processCreationTime(process);
    DWORD session = 0;
    ProcessIdToSessionId(pid, &session);
    identity.sessionId = session;
    wchar_t path[32768] = {};
    DWORD pathLength = static_cast<DWORD>(std::size(path));
    QueryFullProcessImageNameW(process, 0, path, &pathLength);
    identity.imagePath = QString::fromWCharArray(path, static_cast<int>(pathLength));
    identity.commandLine.clear();
    queryCommandLine(process, identity.commandLine);
    identity.fileDescription = versionStringValue(identity.imagePath, L"FileDescription");
    CloseHandle(process);

    PROCESSENTRY32W entry{sizeof(entry)};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry))
        {
            if (entry.th32ProcessID == pid)
            {
                identity.parentPid = entry.th32ParentProcessID;
                break;
            }
        }
        CloseHandle(snapshot);
    }
    return identity.isValid();
}

bool ProcessInspector::queryCommandLine(HANDLE process, QString& commandLine)
{
    using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    struct BasicInfo { PVOID reserved1; PVOID peb; PVOID reserved2[2]; ULONG_PTR pid; PVOID reserved3; };
    struct UnicodeString { USHORT length; USHORT maximumLength; PWSTR buffer; };
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto query = ntdll ? reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(ntdll, "NtQueryInformationProcess")) : nullptr;
    if (!query)
        return false;
    BasicInfo basic{};
    if (query(process, 0, &basic, sizeof(basic), nullptr) != 0 || !basic.peb)
        return false;
    PVOID params = nullptr;
    if (!ReadProcessMemory(process, reinterpret_cast<BYTE*>(basic.peb) + 0x20, &params, sizeof(params), nullptr) || !params)
        return false;
    UnicodeString value{};
    if (!ReadProcessMemory(process, reinterpret_cast<BYTE*>(params) + 0x70, &value, sizeof(value), nullptr) || !value.buffer || value.length == 0)
        return false;
    std::vector<wchar_t> buffer(value.length / sizeof(wchar_t) + 1, L'\0');
    if (!ReadProcessMemory(process, value.buffer, buffer.data(), value.length, nullptr))
        return false;
    commandLine = QString::fromWCharArray(buffer.data(), value.length / sizeof(wchar_t));
    return !commandLine.isEmpty();
}

bool ProcessInspector::queryCommandLine(DWORD pid, QString& commandLine)
{
    commandLine.clear();
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process)
        return false;
    const bool kOk = queryCommandLine(process, commandLine);
    CloseHandle(process);
    return kOk;
}

bool ProcessInspector::identityStillMatches(const ProcessIdentity& expected)
{
    ProcessIdentity current;
    if (!query(expected.pid, current))
        return false;
    return current.creationTime == expected.creationTime && current.sessionId == expected.sessionId && isSamePath(current.imagePath, expected.imagePath);
}

bool ProcessInspector::isProtectedName(const QString& imagePath)
{
    static const QStringList kNames = {QStringLiteral("system"), QStringLiteral("system idle process"), QStringLiteral("smss.exe"),
                                      QStringLiteral("csrss.exe"), QStringLiteral("wininit.exe"), QStringLiteral("services.exe"),
                                      QStringLiteral("lsass.exe"), QStringLiteral("winlogon.exe"), QStringLiteral("dwm.exe"),
                                      QStringLiteral("consent.exe"), QStringLiteral("credentialuibroker.exe"), QStringLiteral("logonui.exe"),
                                      QStringLiteral("ksworduacdesk.exe")};
    return kNames.contains(lowerFileName(imagePath), Qt::CaseInsensitive);
}

namespace
{
    DWORD appInfoServicePid(DWORD& serviceState)
    {
        serviceState = SERVICE_STOPPED;
        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!manager)
            return 0;
        SC_HANDLE service = OpenServiceW(manager, L"Appinfo", SERVICE_QUERY_STATUS);
        if (!service)
        {
            CloseServiceHandle(manager);
            return 0;
        }

        SERVICE_STATUS_PROCESS status{};
        DWORD bytes = 0;
        const bool kOk = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                             reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes) != FALSE;
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        if (!kOk)
            return 0;
        serviceState = status.dwCurrentState;
        return status.dwProcessId;
    }

    QString processImagePathForWindow(HWND hwnd, DWORD& pid)
    {
        pid = 0;
        if (!hwnd || !GetWindowThreadProcessId(hwnd, &pid) || pid == 0)
            return {};
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return {};
        wchar_t path[32768] = {};
        DWORD length = static_cast<DWORD>(std::size(path));
        const bool kOk = QueryFullProcessImageNameW(process, 0, path, &length) != FALSE;
        CloseHandle(process);
        return kOk ? QString::fromWCharArray(path, static_cast<int>(length)) : QString();
    }

    QString utf16BufferString(const std::vector<BYTE>& buffer, size_t offset)
    {
        if (offset >= buffer.size() || (buffer.size() - offset) < sizeof(char16_t))
            return {};
        const size_t kMaxChars = (buffer.size() - offset) / sizeof(char16_t);
        size_t chars = 0;
        const auto* value = reinterpret_cast<const char16_t*>(buffer.data() + offset);
        while (chars < kMaxChars && value[chars] != u'\0')
            ++chars;
        return chars == 0 ? QString() : QString::fromUtf16(value, static_cast<qsizetype>(chars));
    }

    DWORD discoverConsentPid(DWORD sessionId)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;
        DWORD result = 0;
        PROCESSENTRY32W entry{sizeof(entry)};
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry))
        {
            if (_wcsicmp(entry.szExeFile, L"consent.exe") == 0)
            {
                DWORD candidateSession = 0;
                if (ProcessIdToSessionId(entry.th32ProcessID, &candidateSession) &&
                    candidateSession == sessionId)
                {
                    result = entry.th32ProcessID;
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        return result;
    }

    QString tokenIntegrityLevel(DWORD pid)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) return QStringLiteral("不可用");
        HANDLE token = nullptr;
        const bool kOpened = OpenProcessToken(process, TOKEN_QUERY, &token) != FALSE;
        CloseHandle(process);
        if (!kOpened) return QStringLiteral("不可用");

        DWORD length = 0;
        GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &length);
        std::vector<BYTE> buffer(length);
        QString result = QStringLiteral("不可用");
        if (length != 0 && GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), length, &length))
        {
            const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
            const DWORD kRid = *GetSidSubAuthority(label->Label.Sid,
                                                   static_cast<DWORD>(*GetSidSubAuthorityCount(label->Label.Sid) - 1));
            if (kRid >= SECURITY_MANDATORY_SYSTEM_RID) result = QStringLiteral("System");
            else if (kRid >= SECURITY_MANDATORY_HIGH_RID) result = QStringLiteral("High");
            else if (kRid >= SECURITY_MANDATORY_MEDIUM_RID) result = QStringLiteral("Medium");
            else if (kRid >= SECURITY_MANDATORY_LOW_RID) result = QStringLiteral("Low");
            else result = QStringLiteral("Untrusted");
        }
        CloseHandle(token);
        return result;
    }

    QString tokenElevationType(DWORD pid)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) return QStringLiteral("不可用");
        HANDLE token = nullptr;
        const bool kOpened = OpenProcessToken(process, TOKEN_QUERY, &token) != FALSE;
        CloseHandle(process);
        if (!kOpened) return QStringLiteral("不可用");
        TOKEN_ELEVATION_TYPE type = TokenElevationTypeDefault;
        DWORD length = 0;
        const bool kOk = GetTokenInformation(token, TokenElevationType, &type, sizeof(type), &length) != FALSE;
        CloseHandle(token);
        if (!kOk) return QStringLiteral("不可用");
        switch (type)
        {
        case TokenElevationTypeFull: return QStringLiteral("Full");
        case TokenElevationTypeLimited: return QStringLiteral("Limited");
        default: return QStringLiteral("Default");
        }
    }

    QString verifyFileSignature(const QString& imagePath)
    {
        if (imagePath.isEmpty()) return QStringLiteral("未取得");
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        const std::wstring kPath = imagePath.toStdWString();
        fileInfo.pcwszFilePath = kPath.c_str();
        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_IGNORE;
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG kStatus = WinVerifyTrust(nullptr, &action, &trustData);
        const QString kTrustText = kStatus == ERROR_SUCCESS
            ? QStringLiteral("Trusted")
            : QStringLiteral("Untrusted (0x%1)").arg(static_cast<unsigned long>(kStatus), 0, 16);

        // WinVerifyTrust reports trust only. Read the embedded signer
        // certificate as well so the UI shows the concrete signer text.
        HCERTSTORE store = nullptr;
        HCRYPTMSG message = nullptr;
        DWORD encoding = 0;
        DWORD contentType = 0;
        DWORD format = 0;
        QString signerText;
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                             kPath.c_str(),
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY,
                             0,
                             &encoding,
                             &contentType,
                             &format,
                             &store,
                             &message,
                             nullptr))
        {
            DWORD signerSize = 0;
            if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) && signerSize != 0)
            {
                std::vector<BYTE> signerBuffer(signerSize);
                if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signerBuffer.data(), &signerSize))
                {
                    const auto* signerInfo = reinterpret_cast<const CMSG_SIGNER_INFO*>(signerBuffer.data());
                    CERT_INFO certInfo{};
                    certInfo.Issuer = signerInfo->Issuer;
                    certInfo.SerialNumber = signerInfo->SerialNumber;
                    PCCERT_CONTEXT certificate = CertFindCertificateInStore(
                        store,
                        encoding,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        nullptr);
                    if (certificate)
                    {
                        wchar_t signerName[512] = {};
                        if (CertGetNameStringW(certificate,
                                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                               0,
                                               nullptr,
                                               signerName,
                                               static_cast<DWORD>(std::size(signerName))) > 1)
                        {
                            signerText = QString::fromWCharArray(signerName);
                        }
                        CertFreeCertificateContext(certificate);
                    }
                }
            }
            if (message) CryptMsgClose(message);
            if (store) CertCloseStore(store, 0);
        }
        return signerText.isEmpty()
            ? kTrustText
            : QStringLiteral("%1 · %2").arg(kTrustText, signerText);
    }

    QString processRunDuration(quint64 creationTime)
    {
        if (creationTime == 0) return QStringLiteral("不可用");
        FILETIME nowFileTime{};
        GetSystemTimeAsFileTime(&nowFileTime);
        const quint64 kNow = (static_cast<quint64>(nowFileTime.dwHighDateTime) << 32) | nowFileTime.dwLowDateTime;
        if (kNow <= creationTime) return QStringLiteral("00:00:00");
        const quint64 kTotalSeconds = (kNow - creationTime) / 10000000ULL;
        const quint64 kHours = kTotalSeconds / 3600;
        const quint64 kMinutes = (kTotalSeconds / 60) % 60;
        const quint64 kSeconds = kTotalSeconds % 60;
        return QStringLiteral("%1:%2:%3")
            .arg(kHours, 2, 10, QLatin1Char('0'))
            .arg(kMinutes, 2, 10, QLatin1Char('0'))
            .arg(kSeconds, 2, 10, QLatin1Char('0'));
    }

    QString processLaunchChain(const ProcessIdentity& origin)
    {
        QStringList names;
        QVector<DWORD> visited;
        ProcessIdentity current = origin;
        for (int depth = 0; depth < 16 && current.isValid(); ++depth)
        {
            if (std::find(visited.cbegin(), visited.cend(), current.pid) != visited.cend())
                break;
            visited.push_back(current.pid);
            const QString kName = ProcessInspector::fileName(current.imagePath);
            // The secure desktop can expose a fallback font without some
            // application-specific glyphs. Keep the chain readable and
            // deterministic: normal Windows executable names are ASCII;
            // otherwise show the PID instead of rendering tofu boxes.
            bool asciiName = !kName.isEmpty();
            for (const QChar kCharacter : kName)
            {
                if (kCharacter.unicode() < 0x20 || kCharacter.unicode() > 0x7e)
                {
                    asciiName = false;
                    break;
                }
            }
            names.push_back(asciiName ? kName : QStringLiteral("PID %1").arg(current.pid));
            if (current.parentPid == 0 || current.parentPid == current.pid)
                break;
            ProcessIdentity parent;
            if (!ProcessInspector::query(current.parentPid, parent))
                break;
            if (parent.sessionId != current.sessionId || parent.creationTime > current.creationTime)
                break;
            current = parent;
        }
        std::reverse(names.begin(), names.end());
        return names.join(QStringLiteral(" -> "));
    }

    QIcon processIcon(const QString& imagePath)
    {
        if (imagePath.isEmpty()) return {};
        QFileIconProvider provider;
        return provider.icon(QFileInfo(imagePath));
    }

    UINT dpiForWindow(HWND hwnd)
    {
        UINT dpi = 96;
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
        const auto kGetDpiForWindow = user32
            ? reinterpret_cast<GetDpiForWindowFn>(GetProcAddress(user32, "GetDpiForWindow"))
            : nullptr;
        if (kGetDpiForWindow && hwnd)
        {
            const UINT kReported = kGetDpiForWindow(hwnd);
            if (kReported >= 96) dpi = kReported;
        }
        return dpi;
    }
}

bool ProcessInspector::suspend(const ProcessIdentity& expected, QString& error)
{
    if (!identityStillMatches(expected) || isProtectedName(expected.imagePath)) { error = QStringLiteral("目标身份已变化或属于受保护进程"); return false; }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { error = winError(); return false; }
    THREADENTRY32 entry{sizeof(entry)};
    bool touched = false;
    for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry))
    {
        if (entry.th32OwnerProcessID != expected.pid) continue;
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
        if (!thread) continue;
        if (SuspendThread(thread) != static_cast<DWORD>(-1)) touched = true;
        CloseHandle(thread);
    }
    CloseHandle(snapshot);
    if (!touched) { error = winError(); return false; }
    return true;
}

bool ProcessInspector::resume(const ProcessIdentity& expected, QString& error)
{
    if (!identityStillMatches(expected) || isProtectedName(expected.imagePath)) { error = QStringLiteral("目标身份已变化或属于受保护进程"); return false; }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { error = winError(); return false; }
    THREADENTRY32 entry{sizeof(entry)};
    bool touched = false;
    for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry))
    {
        if (entry.th32OwnerProcessID != expected.pid) continue;
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
        if (!thread) continue;
        while (ResumeThread(thread) > 0) touched = true;
        CloseHandle(thread);
    }
    CloseHandle(snapshot);
    if (!touched) { error = winError(); return false; }
    return true;
}

bool ProcessInspector::terminate(const ProcessIdentity& expected, QString& error)
{
    if (!identityStillMatches(expected) || isProtectedName(expected.imagePath)) { error = QStringLiteral("目标身份已变化或属于受保护进程"); return false; }
    HANDLE process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, expected.pid);
    if (!process) { error = winError(); return false; }
    const bool kOk = TerminateProcess(process, 1) != FALSE;
    if (!kOk) error = winError();
    CloseHandle(process);
    return kOk;
}

bool PrivilegeStage::isProcessElevated()
{
    HANDLE token = nullptr;
    const bool kOk = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && getTokenElevation(token);
    if (token) CloseHandle(token);
    return kOk;
}

bool PrivilegeStage::isSystem()
{
    HANDLE token = nullptr;
    const bool kOk = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && tokenIsSystem(token);
    if (token) CloseHandle(token);
    return kOk;
}

bool PrivilegeStage::hasUiAccess()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD value = 0, length = 0;
    const bool kOk = GetTokenInformation(token, TokenUIAccess, &value, sizeof(value), &length) && value != 0;
    CloseHandle(token);
    return kOk;
}

bool PrivilegeStage::launchAdminStage(const QString& executable, const QStringList& args, QString& error)
{
    writeDiagnosticLog(QStringLiteral("admin-launch: begin executable=%1 args=%2")
                           .arg(executable, args.join(QLatin1Char(' '))));
    SHELLEXECUTEINFOW info{sizeof(info)};
    const QString kParameters = std::accumulate(args.cbegin(), args.cend(), QString(), [](const QString& a, const QString& b) { return a.isEmpty() ? b : a + QLatin1Char(' ') + b; });
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"runas";
    const std::wstring kFile = executable.toStdWString();
    const std::wstring kParams = kParameters.toStdWString();
    info.lpFile = kFile.c_str();
    info.lpParameters = kParams.c_str();
    info.nShow = SW_HIDE;
    const bool kOk = ShellExecuteExW(&info) != FALSE;
    if (!kOk)
        error = QStringLiteral("ShellExecuteExW(runas) 失败：") + winError();
    writeDiagnosticLog(kOk
        ? QStringLiteral("admin-launch: ShellExecuteExW succeeded")
        : QStringLiteral("admin-launch: %1").arg(error));
    if (info.hProcess) CloseHandle(info.hProcess);
    return kOk;
}

bool PrivilegeStage::launchSystemStage(const QString& executable, const QStringList& args, const QString& desktop,
                                       DWORD targetSession, QString& error)
{
    writeDiagnosticLog(QStringLiteral("system-launch: begin executable=%1 targetSession=%2 desktop=%3 args=%4")
                           .arg(executable).arg(targetSession).arg(desktop, args.join(QLatin1Char(' '))));
    HANDLE token = nullptr;
    if (!duplicateSystemTokenForSession(targetSession, token, error))
    {
        writeDiagnosticLog(QStringLiteral("system-launch: token preparation failed: %1").arg(error));
        return false;
    }
    const QString kParameters = std::accumulate(args.cbegin(), args.cend(), QString(), [](const QString& a, const QString& b) { return a.isEmpty() ? b : a + QLatin1Char(' ') + b; });
    const std::wstring kExecutablePath = executable.toStdWString();
    std::wstring command = quoteArgument(executable).toStdWString();
    if (!kParameters.isEmpty()) { command += L" "; command += kParameters.toStdWString(); }
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{sizeof(startup)};
    std::wstring desktopName = desktop.toStdWString();
    startup.lpDesktop = desktopName.data();
    PROCESS_INFORMATION processInfo{};
    // Use the standard System link creation method from existing Ksword5.1:
    // The source token comes from the LocalSystem token of winlogon/services; the copied primary token is passed directly to
    // CreateProcessWithTokenW. AdjustTokenPrivileges is only responsible for preparing the call conditions and never replaces the token source.
    const bool kOk = CreateProcessWithTokenW(token, LOGON_NETCREDENTIALS_ONLY, kExecutablePath.c_str(),
                                            mutableCommand.data(), NORMAL_PRIORITY_CLASS, nullptr, nullptr,
                                            &startup, &processInfo) != FALSE;
    if (!kOk)
        error = QStringLiteral("CreateProcessWithTokenW(SYSTEM/UIAccess, desktop=%1) 失败：").arg(desktop) + winError();
    writeDiagnosticLog(kOk
        ? QStringLiteral("system-launch: CreateProcessWithTokenW succeeded childPid=%1").arg(processInfo.dwProcessId)
        : QStringLiteral("system-launch: %1").arg(error));
    if (processInfo.hThread) CloseHandle(processInfo.hThread);
    if (processInfo.hProcess) CloseHandle(processInfo.hProcess);
    CloseHandle(token);
    return kOk;
}

QString PrivilegeStage::currentDesktopName()
{
    HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
    if (!desktop) return {};
    DWORD length = 0;
    GetUserObjectInformationW(desktop, UOI_NAME, nullptr, 0, &length);
    if (length == 0) return {};
    std::vector<wchar_t> buffer(length + 1, L'\0');
    if (!GetUserObjectInformationW(desktop, UOI_NAME, buffer.data(), static_cast<DWORD>(buffer.size() * sizeof(wchar_t)), &length)) return {};
    return QString::fromWCharArray(buffer.data());
}

namespace
{
    void logEtwCallbackException(DWORD code)
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw-callback: SEH exception code=0x%1, event dropped")
                                               .arg(code, 0, 16));
    }
}

DWORD PrivilegeStage::currentSessionId()
{
    DWORD session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    return session;
}

UacEventMonitor::UacEventMonitor(QObject* parent) : QObject(parent)
{
    consumeTimer_.setInterval(80);
    QObject::connect(&consumeTimer_, &QTimer::timeout, this, [this] { consumeEvents(); });
}

UacEventMonitor::~UacEventMonitor() { stop(); }

void UacEventMonitor::start()
{
    if (running_.exchange(true)) return;
    gEventMonitor = this;
    cleanupStaleEtwSessions();
    // WinEvent is only a wake-up/indexing signal.  It never becomes evidence
    // for a process action: the origin is accepted only after reading the
    // consent -> AppInfo request buffer below.
    winEventHook_ = SetWinEventHook(EVENT_SYSTEM_DESKTOPSWITCH, EVENT_SYSTEM_DESKTOPSWITCH,
                                     nullptr, &UacEventMonitor::winEventCallback,
                                     0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    objectEventHook_ = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_SHOW,
                                        nullptr, &UacEventMonitor::winEventCallback,
                                        0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    PrivilegeStage::writeDiagnosticLog(QStringLiteral(
        "winevent: desktopHook=0x%1 objectHook=0x%2; hooks are wake-up only")
                                           .arg(reinterpret_cast<quintptr>(winEventHook_), 0, 16)
                                           .arg(reinterpret_cast<quintptr>(objectEventHook_), 0, 16));
    DWORD serviceState = SERVICE_STOPPED;
    appInfoPid_ = appInfoServicePid(serviceState);
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-queue: Appinfo pid=%1 state=%2")
                                           .arg(appInfoPid_.load()).arg(serviceState));
    startEtw();
    startAlpcEtw();
    consumeTimer_.start();
}

void UacEventMonitor::stop()
{
    if (!running_.exchange(false)) return;
    consumeTimer_.stop();
    if (winEventHook_) { UnhookWinEvent(winEventHook_); winEventHook_ = nullptr; }
    if (objectEventHook_) { UnhookWinEvent(objectEventHook_); objectEventHook_ = nullptr; }
    stopAlpcEtw();
    stopEtw();
    if (gEventMonitor == this) gEventMonitor = nullptr;
}

std::optional<UacOriginEvidence> UacEventMonitor::readConsentOrigin(DWORD sessionId)
{
    if (!running_.load())
        return std::nullopt;

    const quint64 kNow = GetTickCount64();
    DWORD consentPid = consentPid_.load();
    if (consentPid == 0 || kNow - lastConsentDiscoveryMs_.load() >= 500)
    {
        const DWORD kDiscovered = discoverConsentPid(sessionId);
        lastConsentDiscoveryMs_.store(kNow);
        if (kDiscovered != 0)
            consentPid_.store(kDiscovered);
        else if (consentPid != 0)
        {
            QString ignored;
            if (!ProcessInspector::queryCommandLine(consentPid, ignored))
                consentPid_.store(0);
        }
        consentPid = consentPid_.load();
    }
    if (consentPid == 0)
        return std::nullopt;

    QString consentCommandLine;
    if (!ProcessInspector::queryCommandLine(consentPid, consentCommandLine))
    {
        consentPid_.store(0);
        return std::nullopt;
    }

    // Current Win10/Win11 consent.exe receives: AppInfo PID, declared byte
    // length, and a pointer into the AppInfo request buffer.  This is private
    // implementation detail, so every field is range-checked and failure is
    // reported as "unresolved" instead of becoming an action candidate.
    static const QRegularExpression kConsentArguments(
        QStringLiteral("consent\\.exe\\s+(\\d+)\\s+(\\d+)\\s+([0-9A-Fa-f]+)"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch kMatch = kConsentArguments.match(consentCommandLine);
    if (!kMatch.hasMatch())
        return std::nullopt;

    bool okPid = false;
    bool okLength = false;
    bool okAddress = false;
    const DWORD kAppInfoPid = kMatch.captured(1).toUInt(&okPid);
    const DWORD kBufferLength = kMatch.captured(2).toUInt(&okLength);
    const quintptr kRequestAddress = static_cast<quintptr>(kMatch.captured(3).toULongLong(&okAddress, 16));
    const DWORD kOsBuild = windowsBuildNumber();
    const bool kUseWin11Layout = kOsBuild >= kWindows11BuildNumber;
    const size_t kOriginPidOffset = kUseWin11Layout
        ? kAppInfoWin11OriginPidOffset
        : kAppInfoWin10OriginPidOffset;
    const size_t kTargetPathOffset = kUseWin11Layout
        ? kAppInfoWin11TargetPathOffset
        : kAppInfoWin10TargetPathOffset;
    if (!okPid || !okLength || !okAddress || kAppInfoPid == 0 || kRequestAddress == 0 ||
        kBufferLength < kTargetPathOffset || kBufferLength > 0x10000)
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "appinfo-origin: reject consentPid=%1 cmd=%2 parsed appInfo=%3 length=%4 address=0x%5")
                                               .arg(consentPid).arg(consentCommandLine.left(600))
                                               .arg(kAppInfoPid).arg(kBufferLength).arg(kRequestAddress, 0, 16));
        return std::nullopt;
    }

    HANDLE appInfo = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, kAppInfoPid);
    if (!appInfo)
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("appinfo-origin: OpenProcess failed pid=%1 error=%2")
                                               .arg(kAppInfoPid).arg(winError()));
        return std::nullopt;
    }

    std::vector<BYTE> request(kBufferLength);
    SIZE_T bytesRead = 0;
    const bool kReadOk = ReadProcessMemory(appInfo, reinterpret_cast<LPCVOID>(kRequestAddress),
                                          request.data(), request.size(), &bytesRead) != FALSE;
    CloseHandle(appInfo);
    if (!kReadOk || bytesRead != request.size())
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "appinfo-origin: ReadProcessMemory failed appInfoPid=%1 address=0x%2 requested=%3 read=%4 error=%5")
                                               .arg(kAppInfoPid).arg(kRequestAddress, 0, 16)
                                               .arg(kBufferLength).arg(static_cast<qulonglong>(bytesRead)).arg(winError()));
        return std::nullopt;
    }

    PrivilegeStage::writeDiagnosticLog(QStringLiteral(
        "appinfo-origin: layout osBuild=%1 family=%2 originPidOffset=0x%3 targetPathOffset=0x%4")
                                           .arg(kOsBuild)
                                           .arg(kUseWin11Layout ? QStringLiteral("Win11") : QStringLiteral("Win10/fallback"))
                                           .arg(kOriginPidOffset, 0, 16)
                                           .arg(kTargetPathOffset, 0, 16));

    DWORD originPid = 0;
    std::memcpy(&originPid, request.data() + kOriginPidOffset, sizeof(originPid));
    const QString kTargetPath = utf16BufferString(request, kTargetPathOffset);
    if (originPid == 0 || originPid == kAppInfoPid || originPid == consentPid ||
        originPid == GetCurrentProcessId())
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "appinfo-origin: invalid origin pid=%1 consent=%2 appInfo=%3 target=%4")
                                               .arg(originPid).arg(consentPid).arg(kAppInfoPid).arg(kTargetPath));
        return std::nullopt;
    }

    ProcessIdentity origin;
    if (!ProcessInspector::query(originPid, origin) || !origin.isValid())
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("appinfo-origin: origin process unavailable pid=%1")
                                               .arg(originPid));
        return std::nullopt;
    }
    if (origin.sessionId != sessionId || ProcessInspector::isProtectedName(origin.imagePath))
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "appinfo-origin: origin rejected pid=%1 originSession=%2 expectedSession=%3 path=%4")
                                               .arg(origin.pid).arg(origin.sessionId).arg(sessionId).arg(origin.imagePath));
        return std::nullopt;
    }

    UacOriginEvidence evidence;
    evidence.origin = origin;
    evidence.targetPath = kTargetPath;
    evidence.consentPid = consentPid;
    evidence.appInfoPid = kAppInfoPid;
    evidence.bufferLength = kBufferLength;
    evidence.requestAddress = kRequestAddress;
    evidence.originPidOffset = static_cast<DWORD>(kOriginPidOffset);
    evidence.targetPathOffset = static_cast<DWORD>(kTargetPathOffset);
    evidence.observedAtMs = kNow;

    const QString kKey = QStringLiteral("%1/%2/%3/%4/%5")
        .arg(consentPid).arg(kAppInfoPid).arg(originPid).arg(kRequestAddress, 0, 16).arg(kTargetPath);
    bool logEvidence = false;
    {
        QMutexLocker locker(&consentMutex_);
        logEvidence = kKey != lastOriginKey_;
        if (logEvidence)
            lastOriginKey_ = kKey;
    }
    if (logEvidence)
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "appinfo-origin: resolved consentPid=%1 appInfoPid=%2 length=%3 request=0x%4 originPid=%5 originPath=%6 targetPath=%7 pidOffset=0x%8 pathOffset=0x%9")
                                               .arg(consentPid).arg(kAppInfoPid).arg(kBufferLength)
                                               .arg(kRequestAddress, 0, 16).arg(origin.pid).arg(origin.imagePath).arg(kTargetPath)
                                               .arg(kOriginPidOffset, 0, 16).arg(kTargetPathOffset, 0, 16));
    }
    return evidence;
}

void WINAPI UacEventMonitor::winEventCallback(HWINEVENTHOOK, DWORD event, HWND hwnd, LONG objectId, LONG, DWORD, DWORD)
{
    if (!gEventMonitor)
        return;

    if (event == kDesktopSwitchEvent)
    {
        UacEventMonitor::EventItem item{};
        item.eventId = event;
        gEventMonitor->pushEvent(item);
        return;
    }

    if ((event == EVENT_OBJECT_CREATE || event == EVENT_OBJECT_SHOW) &&
        objectId == OBJID_WINDOW && hwnd)
    {
        DWORD pid = 0;
        const QString kPath = processImagePathForWindow(hwnd, pid);
        const QString kName = ProcessInspector::fileName(kPath);
        if (kName.compare(QStringLiteral("consent.exe"), Qt::CaseInsensitive) != 0 &&
            kName.compare(QStringLiteral("credentialuibroker.exe"), Qt::CaseInsensitive) != 0)
            return;

        if (kName.compare(QStringLiteral("consent.exe"), Qt::CaseInsensitive) == 0 && pid != 0)
        {
            gEventMonitor->consentPid_.store(pid);
            gEventMonitor->lastConsentDiscoveryMs_.store(GetTickCount64());
            PrivilegeStage::writeDiagnosticLog(QStringLiteral("winevent: %1 hwnd=0x%2 consentPid=%3 path=%4")
                                                   .arg(event == EVENT_OBJECT_CREATE ? QStringLiteral("CREATE") : QStringLiteral("SHOW"))
                                                   .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                                   .arg(pid).arg(kPath));
        }

        UacEventMonitor::EventItem item{};
        item.eventId = event;
        item.hwnd = hwnd;
        gEventMonitor->pushEvent(item);
    }
}

void WINAPI UacEventMonitor::etwEventCallback(PEVENT_RECORD record)
{
    __try
    {
        etwEventCallbackImpl(record);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        logEtwCallbackException(GetExceptionCode());
    }
}

void UacEventMonitor::etwEventCallbackImpl(PEVENT_RECORD record)
{
    static volatile LONG firstCallbackLogged = 0;
    if (InterlockedCompareExchange(&firstCallbackLogged, 1, 0) == 0)
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw-callback: first callback entered record=0x%1")
                                               .arg(reinterpret_cast<quintptr>(record), 0, 16));
    if (!gEventMonitor || !record) return;
    EventItem item{};
    item.provider = record->EventHeader.ProviderId;
    item.eventId = record->EventHeader.EventDescriptor.Id;
    item.task = record->EventHeader.EventDescriptor.Task;
    item.opcode = record->EventHeader.EventDescriptor.Opcode;
    item.pid = record->EventHeader.ProcessId;
    item.eventTimeMs = eventTraceTimeMs(record);
    const bool kIsAlpcRecord = IsEqualGUID(item.provider, kSystemAlpcProvider) ||
                              IsEqualGUID(item.provider, kLegacyAlpcProvider);
    if (kIsAlpcRecord)
    {
        // Keep a bounded raw sample. This is deliberately before event
        // classification: classic SystemTraceProvider records use ALPCGuid in
        // the header, even when enabled through SystemAlpcProvider.
        static volatile LONG rawAlpcLogCount = 0;
        const LONG kRawIndex = InterlockedIncrement(&rawAlpcLogCount);
        if (kRawIndex <= 64 || (kRawIndex % 256) == 0)
        {
            PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                "etw-alpc: raw provider=%1 id=%2 version=%3 channel=%4 task=%5 opcode=%6 level=%7 keyword=0x%8 pid=%9 tid=%10 userlen=%11 cpu=%12")
                .arg(IsEqualGUID(item.provider, kLegacyAlpcProvider) ? QStringLiteral("legacy") : QStringLiteral("system"))
                .arg(item.eventId)
                .arg(record->EventHeader.EventDescriptor.Version)
                .arg(record->EventHeader.EventDescriptor.Channel)
                .arg(item.task)
                .arg(item.opcode)
                .arg(record->EventHeader.EventDescriptor.Level)
                .arg(record->EventHeader.EventDescriptor.Keyword, 0, 16)
                .arg(record->EventHeader.ProcessId)
                .arg(record->EventHeader.ThreadId)
                .arg(record->UserDataLength)
                .arg(record->BufferContext.ProcessorNumber));
        }
        const ULONG kEventId = record->EventHeader.EventDescriptor.Id;
        const ULONG kTask = record->EventHeader.EventDescriptor.Task;
        const ULONG kOpcode = record->EventHeader.EventDescriptor.Opcode;
        const bool kSend = kEventId == kAlpcSendEvent;
        const bool kReceive = kEventId == kAlpcReceiveEvent;
        if (kSend || kReceive)
        {
            const ULONG kMessageId = alpcMessageId(record);
            static volatile LONG classifiedAlpcLogCount = 0;
            const LONG kClassifiedIndex = InterlockedIncrement(&classifiedAlpcLogCount);
            if (kClassifiedIndex <= 64 || (kClassifiedIndex % 512) == 0)
            {
                PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                    "etw-alpc: kind=%1 id=%2 opcode=%3 pid=%4 tid=%5 message=%6 payload=%7 sample=%8")
                    .arg(kSend ? QStringLiteral("send") : QStringLiteral("receive"))
                    .arg(kEventId).arg(kOpcode)
                    .arg(record->EventHeader.ProcessId)
                    .arg(record->EventHeader.ThreadId)
                    .arg(kMessageId)
                    .arg(record->UserDataLength)
                    .arg(kClassifiedIndex));
            }
            if (kMessageId != 0)
                gEventMonitor->observeAlpc(kReceive, record->EventHeader.ProcessId,
                                            record->EventHeader.ThreadId, kMessageId, item.eventTimeMs);
        }
    }
    if (IsEqualGUID(item.provider, kLuaProvider))
    {
        const QString kPayload = decodeEtwPayload(record);
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw-lua: id=%1 version=%2 channel=%3 task=%4 opcode=%5 pid=%6 payload=%7")
                                               .arg(item.eventId)
                                               .arg(record->EventHeader.EventDescriptor.Version)
                                               .arg(record->EventHeader.EventDescriptor.Channel)
                                               .arg(item.task)
                                               .arg(item.opcode)
                                               .arg(item.pid)
                                               .arg(kPayload.left(4000)));
    }
    gEventMonitor->pushEvent(item);
}

void UacEventMonitor::pushEvent(const EventItem& item)
{
    QMutexLocker locker(&queueMutex_);
    if (events_.size() > 1024) events_.dequeue();
    events_.enqueue(item);
}

void UacEventMonitor::observeAlpc(bool receive, DWORD pid, DWORD tid, ULONG messageId, quint64 eventTimeMs)
{
    if (pid == 0 || tid == 0 || messageId == 0)
        return;

    const quint64 kNow = GetTickCount64();
    const DWORD kAppInfoPid = appInfoPid_.load();
    QMutexLocker locker(&alpcMutex_);
    while (!alpcSends_.isEmpty() && kNow - alpcSends_.front().observedAtMs > kAlpcSendRetentionMs)
        alpcSends_.dequeue();
    while (!uacOrigins_.isEmpty() && kNow - uacOrigins_.front().observedAtMs > kAlpcSendRetentionMs)
        uacOrigins_.dequeue();

    if (!receive)
    {
        alpcSends_.enqueue({messageId, pid, tid, eventTimeMs, kNow});
        while (alpcSends_.size() > 512)
            alpcSends_.dequeue();
        return;
    }

    if (kAppInfoPid == 0 || pid != kAppInfoPid)
        return;

    PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-queue: Appinfo receive pid=%1 tid=%2 message=%3")
                                           .arg(pid).arg(tid).arg(messageId));
    for (auto it = alpcSends_.crbegin(); it != alpcSends_.crend(); ++it)
    {
        if (it->messageId != messageId || it->pid == kAppInfoPid)
            continue;
        if (eventTimeMs < it->eventTimeMs || eventTimeMs - it->eventTimeMs > kUacCorrelationWindowMs)
            continue;

        bool duplicate = false;
        for (const UacOriginItem& existing : uacOrigins_)
        {
            if (existing.messageId == messageId && existing.clientPid == it->pid && existing.clientTid == it->tid)
            {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
        {
            uacOrigins_.enqueue({messageId, it->pid, it->tid, kAppInfoPid, eventTimeMs, kNow});
            while (uacOrigins_.size() > 128)
                uacOrigins_.dequeue();
            PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-queue: candidate pid=%1 tid=%2 message=%3 ageMs=%4 appinfoPid=%5")
                                                   .arg(it->pid).arg(it->tid).arg(messageId)
                                                   .arg(kNow - it->observedAtMs).arg(kAppInfoPid));
        }
        return;
    }
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-queue: Appinfo receive has no matching send message=%1")
                                           .arg(messageId));
}

std::optional<ProcessIdentity> UacEventMonitor::takeUacOrigin(DWORD sessionId, quint64 uacObservedAtMs,
                                                              const QString& targetPath)
{
    if (uacObservedAtMs == 0)
        return std::nullopt;

    const quint64 kNow = GetTickCount64();
    QVector<UacOriginItem> recent;
    {
        QMutexLocker locker(&alpcMutex_);
        QQueue<UacOriginItem> retained;
        while (!uacOrigins_.isEmpty())
        {
            const UacOriginItem kItem = uacOrigins_.dequeue();
            if (kNow >= kItem.observedAtMs && kNow - kItem.observedAtMs <= kAlpcSendRetentionMs)
                retained.enqueue(kItem);
            if (kItem.eventTimeMs <= uacObservedAtMs + 1500 &&
                uacObservedAtMs <= kItem.eventTimeMs + kUacCorrelationWindowMs)
                recent.push_back(kItem);
        }
        uacOrigins_.swap(retained);
    }

    QVector<ProcessIdentity> matches;
    QVector<ULONG> matchMessages;
    for (const UacOriginItem& item : recent)
    {
        ProcessIdentity identity;
        if (!ProcessInspector::query(item.clientPid, identity))
            continue;
        if (identity.sessionId != sessionId || ProcessInspector::isProtectedName(identity.imagePath))
            continue;
        if (!targetPath.isEmpty() && isSamePath(identity.imagePath, targetPath))
        {
            PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-queue: requester path equals UAC target path pid=%1 path=%2")
                                                   .arg(identity.pid).arg(identity.imagePath));
        }

        bool duplicate = false;
        for (const ProcessIdentity& existing : matches)
        {
            if (existing.pid == identity.pid && existing.creationTime == identity.creationTime)
            {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
        {
            matches.push_back(identity);
            matchMessages.push_back(item.messageId);
        }
    }

    if (matches.size() != 1)
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-queue: resolve target=%1 recent=%2 valid=%3 result=%4")
                                               .arg(targetPath).arg(recent.size()).arg(matches.size())
                                               .arg(matches.size() == 1 ? QStringLiteral("unique") : QStringLiteral("ambiguous-or-none")));
        return std::nullopt;
    }

    {
        QMutexLocker locker(&alpcMutex_);
        for (auto it = uacOrigins_.begin(); it != uacOrigins_.end();)
        {
            if (it->messageId == matchMessages.front() && it->clientPid == matches.front().pid)
                it = uacOrigins_.erase(it);
            else
                ++it;
        }
    }
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-queue: resolved pid=%1 tidMessage=%2 path=%3")
                                           .arg(matches.front().pid).arg(matchMessages.front()).arg(matches.front().imagePath));
    return matches.front();
}

void UacEventMonitor::consumeEvents()
{
    const quint64 kNow = GetTickCount64();
    if (lastAppInfoPidRefreshMs_ == 0 || kNow - lastAppInfoPidRefreshMs_ >= 1000)
    {
        lastAppInfoPidRefreshMs_ = kNow;
        DWORD serviceState = SERVICE_STOPPED;
        const DWORD kPid = appInfoServicePid(serviceState);
        const DWORD kPrevious = appInfoPid_.exchange(kPid);
        if (kPrevious != kPid)
            PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-queue: Appinfo pid changed %1 -> %2 state=%3")
                                                   .arg(kPrevious).arg(kPid).arg(serviceState));
    }
    QQueue<EventItem> events;
    {
        QMutexLocker locker(&queueMutex_);
        events.swap(events_);
    }
    while (!events.isEmpty())
    {
        const EventItem kItem = events.dequeue();
        const bool kDesktopEvent = IsEqualGUID(kItem.provider, GUID{}) ||
                                  (IsEqualGUID(kItem.provider, kLuaProvider) &&
                                   (kItem.task == 15002 || kItem.task == 15003 || kItem.task == 15004 || kItem.task == 15005));
        if (kDesktopEvent && onDesktopChanged) onDesktopChanged();
    }
}

void UacEventMonitor::startEtw()
{
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw: start requested"));
    traceName_ = timestampedEtwSessionName();
    const size_t kSize = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, kSize));
    if (!properties) return;
    properties->Wnode.BufferSize = static_cast<ULONG>(kSize);
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 2;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wchar_t* name = reinterpret_cast<wchar_t*>(reinterpret_cast<BYTE*>(properties) + properties->LoggerNameOffset);
    StringCchCopyW(name, 1024, traceName_.toStdWString().c_str());
    ULONG status = StartTraceW(&traceSession_, name, properties);
    free(properties);
    if (status != ERROR_SUCCESS)
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw: StartTraceW failed status=0x%1").arg(status, 0, 16));
        return;
    }
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw: StartTraceW succeeded session=0x%1").arg(traceSession_, 0, 16));
    const ULONG kLuaStatus = EnableTraceEx2(traceSession_, &kLuaProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                           TRACE_LEVEL_VERBOSE, kLuaDiagnosticKeyword, 0, 0, nullptr);
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw: EnableTraceEx2(Microsoft-Windows-LUA) status=0x%1")
                                           .arg(kLuaStatus, 0, 16));
    if (kLuaStatus != ERROR_SUCCESS)
    {
        ControlTraceW(traceSession_, traceName_.toStdWString().data(), nullptr, EVENT_TRACE_CONTROL_STOP);
        traceSession_ = 0;
        return;
    }
    etwStop_ = false;
    etwThread_ = std::thread([this]
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw-thread: entered"));
        EVENT_TRACE_LOGFILEW logfile{};
        std::wstring name = traceName_.toStdWString();
        // EVENT_TRACE_LOGFILEW::LoggerName is an LPWSTR, not an embedded character array.
        // Previously, calling StringCchCopyW on a zero-initialized null pointer triggered an immediate 0xC0000005 in the ETW thread.
        logfile.LoggerName = name.data();
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = &UacEventMonitor::etwEventCallback;
        traceHandle_ = OpenTraceW(&logfile);
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw-thread: OpenTrace handle=0x%1").arg(traceHandle_, 0, 16));
        if (traceHandle_ != INVALID_PROCESSTRACE_HANDLE)
        {
            const ULONG kTraceStatus = ProcessTrace(&traceHandle_, 1, nullptr, nullptr);
            etwAvailable_ = kTraceStatus == ERROR_SUCCESS || kTraceStatus == ERROR_CANCELLED;
            PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw-thread: ProcessTrace returned status=0x%1 available=%2")
                                                   .arg(kTraceStatus, 0, 16)
                                                   .arg(etwAvailable_ ? 1 : 0));
            CloseTrace(traceHandle_);
            traceHandle_ = 0;
        }
    });
    etwAvailable_ = false;
}

void UacEventMonitor::stopEtw()
{
    if (traceSession_ != 0)
    {
        ControlTraceW(traceSession_, traceName_.toStdWString().data(), nullptr, EVENT_TRACE_CONTROL_STOP);
        traceSession_ = 0;
    }
    if (etwThread_.joinable()) etwThread_.join();
}

void UacEventMonitor::startAlpcEtw()
{
    if (alpcThread_.joinable())
        return;

    alpcStop_.store(false);
    alpcLastStatus_.store(ERROR_SUCCESS);
    alpcTraceName_ = timestampedEtwSessionName(QStringLiteral("Alpc"));
    const QString kTraceName = alpcTraceName_;

    // Match the main program's ETW ownership model: the worker owns the
    // controller and consumer handles from StartTrace through ProcessTrace.
    // This keeps the Qt thread out of potentially blocking ETW APIs.
    alpcThread_ = std::thread([this, kTraceName]
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw-alpc-thread: entered"));
        const std::wstring kSessionNameWide = kTraceName.toStdWString();
        const ULONG kTraceNameBytes = static_cast<ULONG>((kSessionNameWide.size() + 1) * sizeof(wchar_t));
        const ULONG kPropertyBufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + kTraceNameBytes);
        std::vector<unsigned char> propertyBuffer(kPropertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = kPropertyBufferSize;
        properties->Wnode.ClientContext = 2;
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->Wnode.Guid = kUacAlpcEtwSessionGuid;
        // System providers require a system logger. EnableFlags is also set so
        // the classic ALPCGuid path is active on builds where the newer mapped
        // provider is accepted but its records retain the legacy provider GUID.
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        properties->EnableFlags = EVENT_TRACE_FLAG_ALPC;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        properties->FlushTimer = 1;
        properties->BufferSize = 256;
        properties->MinimumBuffers = 16;
        properties->MaximumBuffers = 64;
        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(
            propertyBuffer.data() + properties->LoggerNameOffset);
        wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());

        TRACEHANDLE sessionHandle = 0;
        ULONG startStatus = StartTraceW(&sessionHandle, loggerNamePointer, properties);
        if (startStatus == ERROR_ALREADY_EXISTS)
        {
            PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                "etw-alpc-thread: stale/existing session found; stopping by name and retrying"));
            ControlTraceW(0, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            startStatus = StartTraceW(&sessionHandle, loggerNamePointer, properties);
        }
        alpcLastStatus_.store(startStatus);
        if (startStatus != ERROR_SUCCESS)
        {
            PrivilegeStage::writeDiagnosticLog(QStringLiteral("etw-alpc-thread: StartTraceW failed status=0x%1 (%2)")
                                                   .arg(startStatus, 0, 16).arg(winError(startStatus)));
            return;
        }
        alpcSession_.store(static_cast<ULONG64>(sessionHandle));
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "etw-alpc-thread: StartTraceW succeeded session=0x%1 name=%2 enableFlags=ALPC")
            .arg(static_cast<qulonglong>(sessionHandle), 0, 16).arg(kTraceName));

        if (alpcStop_.load())
        {
            const ULONG64 kOwnedSession = alpcSession_.exchange(0);
            if (kOwnedSession != 0)
                ControlTraceW(static_cast<TRACEHANDLE>(kOwnedSession), loggerNamePointer,
                              properties, EVENT_TRACE_CONTROL_STOP);
            return;
        }

        const ULONG kProviderStatus = EnableTraceEx2(
            sessionHandle, &kSystemAlpcProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE, kSystemAlpcKeyword, 0, 0, nullptr);
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "etw-alpc-thread: EnableTraceEx2(SystemAlpcProvider) status=0x%1")
            .arg(kProviderStatus, 0, 16));
        if (kProviderStatus != ERROR_SUCCESS)
        {
            alpcLastStatus_.store(kProviderStatus);
            const ULONG64 kOwnedSession = alpcSession_.exchange(0);
            if (kOwnedSession != 0)
                ControlTraceW(static_cast<TRACEHANDLE>(kOwnedSession), loggerNamePointer,
                              properties, EVENT_TRACE_CONTROL_STOP);
            return;
        }

        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName = loggerNamePointer;
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = &UacEventMonitor::etwEventCallback;
        const TRACEHANDLE kTraceHandle = OpenTraceW(&logfile);
        alpcTraceHandle_.store(static_cast<TRACEHANDLE>(kTraceHandle));
        PrivilegeStage::writeDiagnosticLog(QStringLiteral(
            "etw-alpc-thread: OpenTrace handle=0x%1")
            .arg(static_cast<qulonglong>(kTraceHandle), 0, 16));
        if (kTraceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            const ULONG kError = GetLastError();
            alpcLastStatus_.store(kError);
            PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                "etw-alpc-thread: OpenTrace failed status=0x%1 (%2)")
                .arg(kError, 0, 16).arg(winError(kError)));
        }
        else
        {
            if (!alpcStop_.load())
            {
                TRACEHANDLE processTraceHandle = kTraceHandle;
                const ULONG kTraceStatus = ProcessTrace(&processTraceHandle, 1, nullptr, nullptr);
                alpcLastStatus_.store(alpcStop_.load() ? ERROR_SUCCESS : kTraceStatus);
                PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                    "etw-alpc-thread: ProcessTrace returned status=0x%1 stop=%2")
                    .arg(kTraceStatus, 0, 16).arg(alpcStop_.load() ? 1 : 0));
            }
            CloseTrace(kTraceHandle);
            alpcTraceHandle_.store(0);
        }

        const ULONG64 kOwnedSession = alpcSession_.exchange(0);
        if (kOwnedSession != 0)
            ControlTraceW(static_cast<TRACEHANDLE>(kOwnedSession), loggerNamePointer,
                          properties, EVENT_TRACE_CONTROL_STOP);
    });
}

void UacEventMonitor::stopAlpcEtw()
{
    alpcStop_.store(true);
    const ULONG64 kOwnedSession = alpcSession_.exchange(0);
    if (kOwnedSession != 0)
    {
        const std::wstring kSessionNameWide = alpcTraceName_.toStdWString();
        std::vector<unsigned char> propertyBuffer(
            sizeof(EVENT_TRACE_PROPERTIES) + (kSessionNameWide.size() + 1) * sizeof(wchar_t), 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(propertyBuffer.size());
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(
            propertyBuffer.data() + properties->LoggerNameOffset);
        wcscpy_s(loggerNamePointer, kSessionNameWide.size() + 1, kSessionNameWide.c_str());
        ControlTraceW(static_cast<TRACEHANDLE>(kOwnedSession), loggerNamePointer,
                      properties, EVENT_TRACE_CONTROL_STOP);
    }
    if (alpcThread_.joinable())
        alpcThread_.join();
    alpcTraceHandle_.store(0);
}

UacApplicationIdentity UacWindowScanner::scan()
{
    UacApplicationIdentity result;
    HDESK desktop = OpenDesktopW(kWinlogonDesktopName, 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
    bool closeDesktop = true;
    if (!desktop)
    {
        // When the current thread is already in Winlogon, prefer reusing the current desktop handle as a fallback for OpenDesktop.
        desktop = GetThreadDesktop(GetCurrentThreadId());
        closeDesktop = false;
    }
    if (!desktop)
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-scan: cannot open Winlogon desktop: %1").arg(winError()));
        return result;
    }
    QVector<HWND> windows;
    EnumDesktopWindows(desktop, &enumWindowProc, reinterpret_cast<LPARAM>(&windows));
    if (closeDesktop) CloseDesktop(desktop);
    struct Candidate
    {
        HWND hwnd = nullptr;
        QRect rect;
        QString process;
        QString className;
        QString title;
        QString children;
        QString automation;
        QString allText;
        QString applicationName;
        QString publisher;
        QString imagePath;
        int score = 0;
    };

    bool sawConsentProcess = false;
    QStringList windowSummary;
    QVector<Candidate> candidates;
    const qint64 kVirtualArea = static_cast<qint64>(std::max(1, GetSystemMetrics(SM_CXVIRTUALSCREEN))) *
                               static_cast<qint64>(std::max(1, GetSystemMetrics(SM_CYVIRTUALSCREEN)));
    for (HWND hwnd : windows)
    {
        const QString kProcess = desktopProcessName(hwnd);
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        RECT nativeRect{};
        GetWindowRect(hwnd, &nativeRect);
        const QRect kRect(nativeRect.left, nativeRect.top,
                         nativeRect.right - nativeRect.left, nativeRect.bottom - nativeRect.top);
        const QString kClassName = windowClassName(hwnd);
        const QString kTitle = windowText(hwnd);
        windowSummary.push_back(QStringLiteral("hwnd=0x%1 pid=%2 process=%3 visible=%4 rect=%5,%6,%7,%8 class=%9 title=%10")
                                    .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                    .arg(pid)
                                    .arg(kProcess.isEmpty() ? QStringLiteral("<unresolved>") : kProcess)
                                    .arg(IsWindowVisible(hwnd) ? 1 : 0)
                                    .arg(kRect.left()).arg(kRect.top()).arg(kRect.width()).arg(kRect.height())
                                    .arg(kClassName)
                                    .arg(kTitle.left(120)));
        if (kProcess != QStringLiteral("consent.exe") && kProcess != QStringLiteral("credentialuibroker.exe")) continue;
        sawConsentProcess = true;

        if (!IsWindowVisible(hwnd) || kRect.width() < 120 || kRect.height() < 80) continue;
        if (kClassName.contains(QStringLiteral("tooltip"), Qt::CaseInsensitive) ||
            kTitle.compare(QStringLiteral("Tooltip"), Qt::CaseInsensitive) == 0) continue;

        Candidate candidate;
        candidate.hwnd = hwnd;
        candidate.rect = kRect;
        candidate.process = kProcess;
        candidate.className = kClassName;
        candidate.title = kTitle;
        candidate.children = collectChildText(hwnd);
        candidate.automation = readUiAutomationName(hwnd);
        candidate.applicationName = uacApplicationNameFromText(candidate.automation);
        candidate.publisher = uacPublisherFromText(candidate.automation);
        candidate.imagePath = uacPathFromText(candidate.automation);
        QStringList textParts;
        for (const QString& part : {candidate.title, candidate.children, candidate.automation})
            if (!part.trimmed().isEmpty()) textParts.push_back(part.trimmed());
        candidate.allText = textParts.join(QStringLiteral(" | "));
        candidate.score = kProcess == QStringLiteral("consent.exe") ? 30 : 20;
        if (containsAny(candidate.allText,
                        {QStringLiteral("用户帐户控制"), QStringLiteral("User Account Control"),
                         QStringLiteral("Windows 安全性"), QStringLiteral("Windows Security")}))
            candidate.score += 120;
        if (!candidate.children.isEmpty()) candidate.score += 35;
        if (!candidate.automation.isEmpty()) candidate.score += 35;
        if (kRect.width() >= 300 && kRect.width() <= 1600 && kRect.height() >= 180 && kRect.height() <= 1100)
            candidate.score += 25;

        const qint64 kArea = static_cast<qint64>(kRect.width()) * kRect.height();
        const bool kNearlyFullScreen = kArea * 100 >= kVirtualArea * 70;
        if (kNearlyFullScreen && candidate.allText.isEmpty()) continue;
        if (kNearlyFullScreen) candidate.score -= 100;
        candidates.push_back(std::move(candidate));
    }

    const auto kBest = std::max_element(candidates.cbegin(), candidates.cend(),
                                       [](const Candidate& left, const Candidate& right)
                                       {
                                           return left.score < right.score;
                                       });
    if (kBest != candidates.cend() && kBest->score >= 50)
    {
        result.consentWindow = kBest->hwnd;
        result.windowRect = kBest->rect;
        result.displayName = !kBest->applicationName.isEmpty()
            ? kBest->applicationName
            : (!kBest->title.isEmpty() ? kBest->title : kBest->automation);
        result.publisher = kBest->publisher;
        result.imagePath = kBest->imagePath;
        if (result.displayName.isEmpty() && !kBest->children.isEmpty())
            result.displayName = kBest->children.section(QLatin1Char('|'), 0, 0).trimmed();
        if (result.displayName.isEmpty()) result.displayName = QStringLiteral("UAC 安全桌面应用");
        result.matchText = kBest->allText;
        result.evidence = QStringLiteral("Winlogon 窗口：%1；类：%2；发布者：%3；路径：%4；控件文本：%5")
            .arg(kBest->process, kBest->className, kBest->publisher,
                 kBest->imagePath.isEmpty() ? QStringLiteral("未知") : kBest->imagePath,
                 kBest->allText.left(420));
        result.isUac = true;
        result.observedAtMs = currentTraceTimeMs();
        result.exact = false;
    }
    static QString previousWindowSummary;
    const QString kCurrentWindowSummary = windowSummary.join(QStringLiteral(" || "));
    if (kCurrentWindowSummary != previousWindowSummary)
    {
        previousWindowSummary = kCurrentWindowSummary;
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-scan: enumerated=%1 consent=%2 %3")
                                                .arg(windows.size())
                                                .arg(sawConsentProcess ? 1 : 0)
                                                .arg(kCurrentWindowSummary));
    }
    return result;
}

namespace
{
    ProcessActionState resolveTargetInWorker(UacApplicationIdentity& identity, DWORD sessionId)
    {
        ProcessActionState state;
        std::optional<UacOriginEvidence> appInfoEvidence;
        if (gEventMonitor)
            appInfoEvidence = gEventMonitor->readConsentOrigin(sessionId);

        // AppInfo evidence can arrive a little before the native window scan.
        // Keep it visible in that case, but do not pretend the target path is
        // the originating process and never enable process actions from it.
        if (appInfoEvidence.has_value())
        {
            identity.isUac = true;
            identity.observedAtMs = appInfoEvidence->observedAtMs;
            if (identity.displayName.isEmpty())
                identity.displayName = QStringLiteral("UAC 请求");
            if (!appInfoEvidence->targetPath.isEmpty())
                identity.imagePath = appInfoEvidence->targetPath;
            identity.exact = true;
            identity.evidence = QStringLiteral(
                "AppInfo 缓冲区：%1 字节；origin PID 位于 +0x%2；目标路径位于 +0x%3；consent PID=%4；目标=%5")
                .arg(appInfoEvidence->bufferLength)
                .arg(appInfoEvidence->originPidOffset, 0, 16)
                .arg(appInfoEvidence->targetPathOffset, 0, 16)
                .arg(appInfoEvidence->consentPid)
                .arg(appInfoEvidence->targetPath.isEmpty() ? QStringLiteral("未知") : appInfoEvidence->targetPath);
            state.origin = appInfoEvidence->origin;
            state.originResolved = true;
            state.unique = true;
            state.protectedProcess = ProcessInspector::isProtectedName(state.origin.imagePath) ||
                                     state.origin.pid == GetCurrentProcessId();
            state.reason = state.protectedProcess
                ? QStringLiteral("发起者属于受保护进程，动作已拒绝")
                : QStringLiteral("已读取 UAC 发起者");
            const QString kDetailKey = QStringLiteral("%1/%2/%3/%4/%5")
                .arg(appInfoEvidence->consentPid)
                .arg(appInfoEvidence->appInfoPid)
                .arg(state.origin.pid)
                .arg(state.origin.creationTime)
                .arg(appInfoEvidence->targetPath);
            static QMutex detailCacheMutex;
            static QString cachedDetailKey;
            static ProcessActionState cachedDetails;
            bool cacheHit = false;
            {
                QMutexLocker locker(&detailCacheMutex);
                if (kDetailKey == cachedDetailKey)
                {
                    state.originIcon = cachedDetails.originIcon;
                    state.launchChain = cachedDetails.launchChain;
                    state.integrityLevel = cachedDetails.integrityLevel;
                    state.elevationType = cachedDetails.elevationType;
                    state.startTime = cachedDetails.startTime;
                    state.runDuration = processRunDuration(state.origin.creationTime);
                    state.originSignature = cachedDetails.originSignature;
                    state.targetSignature = cachedDetails.targetSignature;
                    cacheHit = true;
                }
            }
            if (!cacheHit)
            {
                state.originIcon = processIcon(state.origin.imagePath);
                state.launchChain = processLaunchChain(state.origin);
                state.integrityLevel = tokenIntegrityLevel(state.origin.pid);
                state.elevationType = tokenElevationType(state.origin.pid);
                state.startTime = formatFileTime(state.origin.creationTime);
                state.runDuration = processRunDuration(state.origin.creationTime);
                state.originSignature = verifyFileSignature(state.origin.imagePath);
                state.targetSignature = verifyFileSignature(appInfoEvidence->targetPath);
                QMutexLocker locker(&detailCacheMutex);
                cachedDetailKey = kDetailKey;
                cachedDetails = state;
                PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                    "uac-match: AppInfo origin pid=%1 name=%2 target=%3 protected=%4 details=refreshed")
                                                       .arg(state.origin.pid)
                                                       .arg(ProcessInspector::fileName(state.origin.imagePath))
                                                       .arg(appInfoEvidence->targetPath)
                                                       .arg(state.protectedProcess ? 1 : 0));
            }
            else
            {
                state.runDuration = processRunDuration(state.origin.creationTime);
            }
        }

        if (!identity.isUac)
        {
            state.reason = QStringLiteral("当前未发现 UAC 窗口或有效 AppInfo 请求");
            return state;
        }

        // The old ALPC queue remains available for diagnostics, but it is not
        // used as an origin candidate: it observes transport participants and
        // cannot prove the request's original caller.
        if (!state.originResolved)
        {
            PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                "uac-match: UAC window seen but AppInfo origin is unresolved; actions disabled"));
            state.reason = QStringLiteral("已发现 UAC 窗口，尚未读取有效 AppInfo 发起者");
            return state;
        }
        // The request layout is selected coarsely by the Windows build family;
        // the action identity is the caller itself and every action still
        // revalidates its process identity.
        return state;
    }
}

BOOL CALLBACK UacWindowScanner::enumWindowProc(HWND hwnd, LPARAM lParam)
{
    auto* windows = reinterpret_cast<QVector<HWND>*>(lParam);
    windows->push_back(hwnd);
    return TRUE;
}

BOOL CALLBACK UacWindowScanner::enumChildProc(HWND hwnd, LPARAM lParam)
{
    auto* values = reinterpret_cast<QStringList*>(lParam);
    const QString kText = windowText(hwnd).trimmed();
    if (!kText.isEmpty()) values->push_back(kText);
    return TRUE;
}

QString UacWindowScanner::readUiAutomationName(HWND hwnd)
{
    if (!hwnd)
        return {};

    PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-ui: probe begin hwnd=0x%1")
                                           .arg(reinterpret_cast<quintptr>(hwnd), 0, 16));
    const HRESULT kInitResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool kShouldUninitialize = SUCCEEDED(kInitResult);
    if (FAILED(kInitResult) && kInitResult != RPC_E_CHANGED_MODE)
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-ui: CoInitializeEx(MTA) failed hr=0x%1")
                                               .arg(static_cast<unsigned long>(kInitResult), 0, 16));
        return {};
    }

    QStringList uiAutomationValues;
    IUIAutomation* automation = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_CUIAutomation, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&automation));
    if (SUCCEEDED(hr) && automation)
    {
        IUIAutomationElement* root = nullptr;
        hr = automation->ElementFromHandle(hwnd, &root);
        if (SUCCEEDED(hr) && root)
        {
            auto readRootBstr = [&](const wchar_t* label, HRESULT (STDMETHODCALLTYPE IUIAutomationElement::*getter)(BSTR*))
            {
                BSTR value = nullptr;
                const HRESULT kValueResult = (root->*getter)(&value);
                if (SUCCEEDED(kValueResult) && value)
                {
                    const QString kText = QString::fromWCharArray(value).trimmed();
                    if (!kText.isEmpty())
                        appendUniqueText(uiAutomationValues, QStringLiteral("%1=%2").arg(QString::fromWCharArray(label), kText));
                    SysFreeString(value);
                }
            };
            readRootBstr(L"Name", &IUIAutomationElement::get_CurrentName);
            readRootBstr(L"Class", &IUIAutomationElement::get_CurrentClassName);
            readRootBstr(L"AutomationId", &IUIAutomationElement::get_CurrentAutomationId);
            readRootBstr(L"Provider", &IUIAutomationElement::get_CurrentProviderDescription);

            IUIAutomationCondition* condition = nullptr;
            IUIAutomationElementArray* elements = nullptr;
            hr = automation->CreateTrueCondition(&condition);
            if (SUCCEEDED(hr) && condition)
                hr = root->FindAll(TreeScope_Descendants, condition, &elements);

            int elementCount = 0;
            if (SUCCEEDED(hr) && elements)
            {
                int length = 0;
                if (SUCCEEDED(elements->get_Length(&length)))
                    elementCount = std::min(length, 256);
                for (int i = 0; i < elementCount; ++i)
                {
                    IUIAutomationElement* element = nullptr;
                    if (FAILED(elements->GetElement(i, &element)) || !element)
                        continue;

                    BSTR name = nullptr;
                    if (SUCCEEDED(element->get_CurrentName(&name)) && name)
                    {
                        const QString kElementName = QString::fromWCharArray(name).trimmed();
                        appendUniqueText(uiAutomationValues, QStringLiteral("Text=%1").arg(kElementName));
                        SysFreeString(name);
                    }
                    element->Release();
                }
            }
            else
            {
                PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-ui: FindAll failed hwnd=0x%1 hr=0x%2")
                                                       .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                                       .arg(static_cast<unsigned long>(hr), 0, 16));
            }
            if (elements) elements->Release();
            if (condition) condition->Release();
            root->Release();
            PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-ui: UIA success hwnd=0x%1 elements=%2 values=%3")
                                                   .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                                   .arg(elementCount)
                                                   .arg(uiAutomationValues.join(QStringLiteral(" | ")).left(1000)));
        }
        else
        {
            PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-ui: ElementFromHandle failed hwnd=0x%1 hr=0x%2")
                                                   .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                                   .arg(static_cast<unsigned long>(hr), 0, 16));
        }
        automation->Release();
    }
    else
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-ui: CoCreateInstance(CUIAutomation) failed hr=0x%1")
                                               .arg(static_cast<unsigned long>(hr), 0, 16));
    }

    QStringList msaaValues;
    IAccessible* accessible = nullptr;
    hr = AccessibleObjectFromWindow(hwnd, OBJID_CLIENT, IID_IAccessible,
                                    reinterpret_cast<void**>(&accessible));
    if (SUCCEEDED(hr) && accessible)
    {
        LONG childCount = 0;
        accessible->get_accChildCount(&childCount);
        childCount = std::clamp<LONG>(childCount, 0, 256);
        for (LONG child = 0; child <= childCount; ++child)
        {
            VARIANT childId{};
            VariantInit(&childId);
            childId.vt = VT_I4;
            childId.lVal = child == 0 ? CHILDID_SELF : child;
            BSTR name = nullptr;
            if (SUCCEEDED(accessible->get_accName(childId, &name)) && name)
            {
                appendUniqueText(msaaValues, QString::fromWCharArray(name));
                SysFreeString(name);
            }
            VariantClear(&childId);
        }
        accessible->Release();
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-ui: MSAA success hwnd=0x%1 children=%2 values=%3")
                                               .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                               .arg(childCount)
                                               .arg(msaaValues.join(QStringLiteral(" | ")).left(1000)));
    }
    else
    {
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-ui: AccessibleObjectFromWindow failed hwnd=0x%1 hr=0x%2")
                                               .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                               .arg(static_cast<unsigned long>(hr), 0, 16));
    }

    if (kShouldUninitialize)
        CoUninitialize();

    QStringList result;
    if (!uiAutomationValues.isEmpty())
        result.push_back(QStringLiteral("UIA: ") + uiAutomationValues.join(QStringLiteral(" | ")));
    if (!msaaValues.isEmpty())
        result.push_back(QStringLiteral("MSAA: ") + msaaValues.join(QStringLiteral(" | ")));
    return result.join(QStringLiteral(" | "));
}

UacDeskWindow::UacDeskWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("Ksword UAC 诊断"));
    const QIcon kApplicationIcon(QStringLiteral(":/KswordUacDesk/KswordLogo.ico"));
    setWindowIcon(kApplicationIcon);
    setAttribute(Qt::WA_ShowWithoutActivating, true);
    // The Winlogon desktop lacks the standard Shell window management chain. Tool + TopMost are required to
    // ensure this independent auxiliary window enters a visible Z-order; ShowWithoutActivating/NOACTIVATE
    // ensures displaying the companion window does not change the UAC keyboard focus.
    setWindowFlags(Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    resize(430, 460);
    setMinimumWidth(320);
    setMinimumHeight(0);
    setMaximumWidth(460);
    setMaximumHeight(QWIDGETSIZE_MAX);
    auto* root = new QWidget(this);
    root->setObjectName(QStringLiteral("kswordUacDeskRoot"));
    auto* layout = new QVBoxLayout(root);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    brandHeader_ = new UacBrandHeaderWidget(kApplicationIcon, root);
    dragHandle_ = brandHeader_;
    dragHandle_->setCursor(Qt::OpenHandCursor);
    dragHandle_->installEventFilter(this);
    layout->addWidget(brandHeader_);
    PrivilegeStage::writeDiagnosticLog(QStringLiteral(
        "ui: brand resources horizontalLogo=0 icon=%1 accent=%2")
                                           .arg(kApplicationIcon.isNull() ? 0 : 1)
                                           .arg(ksword_theme::themeColorName(ksword_theme::defaultPrimaryAccentColor())));

    auto* content = new QWidget(root);
    auto* contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(18, 2, 18, 10);
    contentLayout->setSpacing(5);

    auto* originRow = new QWidget(content);
    auto* originLayout = new QHBoxLayout(originRow);
    originLayout->setContentsMargins(0, 0, 0, 0);
    originLayout->setSpacing(9);
    originIconLabel_ = new QLabel(originRow);
    originIconLabel_->setFixedSize(20, 20);
    originIconLabel_->setAlignment(Qt::AlignCenter);
    originIconLabel_->setPixmap(removeFlatBackground(kApplicationIcon.pixmap(20, 20)));
    originLayout->addWidget(originIconLabel_);
    identityLabel_ = new QLabel(QStringLiteral("等待 UAC 发起者..."), originRow);
    identityLabel_->setObjectName(QStringLiteral("uacIdentityLabel"));
    identityLabel_->setWordWrap(false);
    originLayout->addWidget(identityLabel_, 1);
    contentLayout->addWidget(originRow);

    processLabel_ = new QLabel(QStringLiteral(
        "启动参数：不可用\n进程位置：不可用\n启动链：不可用\n完整性级别：不可用\n提升类型：不可用\n启动时间：不可用\n运行时长：不可用\n数字签名（发起者）：不可用\n数字签名（目标）：不可用"), content);
    processLabel_->setObjectName(QStringLiteral("uacProcessDetailsLabel"));
    processLabel_->setWordWrap(true);
    processLabel_->setTextFormat(Qt::PlainText);
    contentLayout->addWidget(processLabel_);
    contentLayout->addStretch(1);
    auto* actions = new QGridLayout();
    actions->setHorizontalSpacing(14);
    actions->setVerticalSpacing(5);
    terminateButton_ = new QPushButton(QStringLiteral("结束发起者"), content);
    terminateButton_->setObjectName(QStringLiteral("uacTerminateButton"));
    suspendButton_ = new QPushButton(QStringLiteral("挂起发起者"), content);
    powerShellButton_ = new QPushButton(QStringLiteral("启动 PowerShell"), content);
    launchMainButton_ = new QPushButton(QStringLiteral("启动 Ksword"), content);
    const QSizePolicy kButtonPolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    terminateButton_->setSizePolicy(kButtonPolicy);
    suspendButton_->setSizePolicy(kButtonPolicy);
    powerShellButton_->setSizePolicy(kButtonPolicy);
    launchMainButton_->setSizePolicy(kButtonPolicy);
    terminateButton_->setFixedHeight(24);
    suspendButton_->setFixedHeight(24);
    powerShellButton_->setFixedHeight(24);
    launchMainButton_->setFixedHeight(24);
    actions->setContentsMargins(0, 0, 0, 0);
    actions->setColumnStretch(0, 1);
    actions->setColumnStretch(1, 1);
    actions->addWidget(terminateButton_, 0, 0);
    actions->addWidget(suspendButton_, 0, 1);
    actions->addWidget(powerShellButton_, 1, 0);
    actions->addWidget(launchMainButton_, 1, 1);
    contentLayout->addLayout(actions);
    layout->addWidget(content, 1);
    setCentralWidget(root);
    refreshAppearance();

    QObject::connect(suspendButton_, &QPushButton::clicked, this, [this] { runProcessAction(0); });
    QObject::connect(terminateButton_, &QPushButton::clicked, this, [this] { runProcessAction(2); });
    QObject::connect(powerShellButton_, &QPushButton::clicked, this, [this] { launchPowerShellOnSecureDesktop(); });
    QObject::connect(launchMainButton_, &QPushButton::clicked, this, [this] { launchMainOnSecureDesktop(); });
    // Window presence is cheap to poll on the Winlogon desktop. Keep this
    // independent from the slower UIA/process-evidence work in the scan worker.
    refreshTimer_.setInterval(500);
    refreshTimer_.setTimerType(Qt::CoarseTimer);
    QObject::connect(&refreshTimer_, &QTimer::timeout, this, [this] { refreshUacState(); });
    refreshTimer_.start();
    if (QScreen* screen = QGuiApplication::primaryScreen())
    {
        const QRect kWork = screen->availableGeometry();
        setMaximumWidth(std::min(maximumWidth(), std::max(320, kWork.width() - 40)));
        adjustToContent();
        const int kX = std::max(kWork.left(), kWork.right() - width() - 24);
        const int kY = std::max(kWork.top(), std::min(kWork.top() + 72, kWork.bottom() - height() + 1));
        move(kX, kY);
    }
    updateButtons();
    // The companion is event-driven UI for an actual UAC prompt.  It must not
    // leave a visible window on the shared Winlogon desktop while the machine
    // is merely locked (or while no prompt is present).
    hide();
}

UacDeskWindow::~UacDeskWindow()
{
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("window: UacDeskWindow destructor"));
    scanStop_ = true;
    scanGeneration_.fetch_add(1);
    if (scanThread_.joinable()) scanThread_.join();
    if (actionThread_.joinable()) actionThread_.join();
    if (launchThread_.joinable()) launchThread_.join();
    if (parentCheckThread_.joinable()) parentCheckThread_.join();
    if (parentProcess_) CloseHandle(parentProcess_);
}

void UacDeskWindow::setParentWatch(HANDLE processHandle, quint64 creationTime)
{
    parentProcess_ = processHandle;
    parentCreationTime_ = creationTime;
    if (parentProcess_)
    {
        parentTimer_.setInterval(400);
        QObject::connect(&parentTimer_, &QTimer::timeout, this, [this] { checkParent(); });
        parentTimer_.start();
    }
}

void UacDeskWindow::setInitialStatus(const QString& status) { showStatus(status); }

void UacDeskWindow::refreshNow()
{
    refreshUacState();
}

void UacDeskWindow::notifyUacActivity()
{
    fastPollUntilMs_ = GetTickCount64() + 5000;
    if (refreshTimer_.interval() != 75)
    {
        refreshTimer_.setInterval(75);
        refreshTimer_.setTimerType(Qt::PreciseTimer);
        refreshTimer_.start();
    }
}

void UacDeskWindow::refreshAppearance()
{
    applySystemPalette();
    setStyleSheet(uacDeskSystemStyle());
    adjustToContent();
    if (brandHeader_)
        brandHeader_->update();
}

void UacDeskWindow::adjustToContent()
{
    if (!centralWidget()) return;
    centralWidget()->layout()->activate();
    const int kDesiredHeight = qMax(1, sizeHint().height());
    if (height() != kDesiredHeight)
        resize(width(), kDesiredHeight);
}

bool UacDeskWindow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched != dragHandle_)
        return QMainWindow::eventFilter(watched, event);

    if (event->type() == QEvent::MouseButtonPress)
    {
        auto* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton)
        {
            dragging_ = true;
            dragOffset_ = mouseEvent->globalPosition().toPoint() - frameGeometry().topLeft();
            if (dragHandle_) dragHandle_->setCursor(Qt::ClosedHandCursor);
            return true;
        }
    }
    else if (event->type() == QEvent::MouseMove && dragging_)
    {
        auto* mouseEvent = static_cast<QMouseEvent*>(event);
        move(mouseEvent->globalPosition().toPoint() - dragOffset_);
        return true;
    }
    else if (event->type() == QEvent::MouseButtonRelease)
    {
        auto* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton)
        {
            dragging_ = false;
            if (dragHandle_) dragHandle_->setCursor(Qt::OpenHandCursor);
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void UacDeskWindow::changeEvent(QEvent* event)
{
    QMainWindow::changeEvent(event);
    if (event && event->type() == QEvent::ApplicationPaletteChange)
        refreshAppearance();
}

void UacDeskWindow::refreshUacState()
{
    const quint64 kNow = GetTickCount64();
    if (fastPollUntilMs_ != 0 && kNow >= fastPollUntilMs_)
    {
        fastPollUntilMs_ = 0;
        refreshTimer_.setInterval(500);
        refreshTimer_.setTimerType(Qt::CoarseTimer);
        refreshTimer_.start();
    }
    if (scanRunning_.exchange(true)) return;
    if (scanThread_.joinable()) scanThread_.join();
    scanStop_ = false;
    const quint64 kGeneration = scanGeneration_.fetch_add(1) + 1;
    const DWORD kSessionId = PrivilegeStage::currentSessionId();
    scanThread_ = std::thread([this, kGeneration, kSessionId]
    {
        UacApplicationIdentity identity = UacWindowScanner::scan();
        ProcessActionState actionState = resolveTargetInWorker(identity, kSessionId);
        if (!scanStop_.load())
        {
            QMetaObject::invokeMethod(this,
                                      [this, kGeneration, identity = std::move(identity), actionState = std::move(actionState)]() mutable
                                      {
                                          if (!scanStop_.load() && kGeneration == scanGeneration_.load())
                                              applyScanResult(identity, actionState);
                                      },
                                      Qt::QueuedConnection);
        }
        scanRunning_ = false;
    });
}

void UacDeskWindow::applyScanResult(const UacApplicationIdentity& identity, const ProcessActionState& actionState)
{
    // AppInfo evidence may arrive before the native window scan.  It is useful
    // for correlating the request, but it is not enough to make a visible panel
    // with no anchor rectangle: otherwise a lock-screen/transition state could
    // expose a stale panel at its previous position.
    const bool kHasVisibleUac = identity.isUac && identity.consentWindow != nullptr &&
                               !identity.windowRect.isEmpty();
    if (!kHasVisibleUac)
    {
        // Winlogon is shared by UAC and the lock screen.  Visibility is gated
        // by positive UAC detection, not by the fact that this process can
        // access the Winlogon desktop.  Hide immediately on a negative scan so
        // a stale panel cannot remain visible on the lock screen.
        if (isVisible())
        {
            hide();
            PrivilegeStage::writeDiagnosticLog(QStringLiteral(
                "uac-visibility: hidden because no valid UAC window was detected"));
        }
        positionedUacWindow_ = nullptr;
        identity_ = {};
        actionState_ = {};
        originIconLabel_->setPixmap(removeFlatBackground(QIcon(QStringLiteral(":/KswordUacDesk/KswordLogo.ico")).pixmap(20, 20)));
        identityLabel_->setText(QStringLiteral("等待 UAC 发起者..."));
        processLabel_->setText(QStringLiteral(
            "启动参数：不可用\n进程位置：不可用\n启动链：不可用\n完整性级别：不可用\n提升类型：不可用\n启动时间：不可用\n运行时长：不可用\n数字签名（发起者）：不可用\n数字签名（目标）：不可用"));
        adjustToContent();
        updateButtons();
        return;
    }
    const bool kShouldPosition = positionedUacWindow_ == nullptr || positionedUacWindow_ != identity.consentWindow;
    identity_ = identity;
    actionState_ = actionState;
    if (actionState_.originResolved)
    {
        const QString kProcessName = ProcessInspector::fileName(actionState_.origin.imagePath);
        const QIcon kIcon = actionState_.originIcon.isNull()
            ? QIcon(QStringLiteral(":/KswordUacDesk/KswordLogo.ico"))
            : actionState_.originIcon;
        originIconLabel_->setPixmap(removeFlatBackground(kIcon.pixmap(20, 20)));
        identityLabel_->setText(QStringLiteral("%1 · PID %2")
                                     .arg(kProcessName.isEmpty() ? QStringLiteral("未知") : kProcessName)
                                     .arg(actionState_.origin.pid));
        processLabel_->setText(QStringLiteral(
            "启动参数：%1\n进程位置：%2\n启动链：%3\n完整性级别：%4\n提升类型：%5\n启动时间：%6\n运行时长：%7\n数字签名（发起者）：%8\n数字签名（目标）：%9")
                                    .arg(actionState_.origin.commandLine.isEmpty() ? QStringLiteral("不可用") : actionState_.origin.commandLine)
                                    .arg(actionState_.origin.imagePath)
                                    .arg(actionState_.launchChain.isEmpty() ? QStringLiteral("不可用") : actionState_.launchChain)
                                    .arg(actionState_.integrityLevel)
                                    .arg(actionState_.elevationType)
                                    .arg(actionState_.startTime)
                                    .arg(actionState_.runDuration)
                                    .arg(actionState_.originSignature)
                                    .arg(actionState_.targetSignature));
    }
    else
    {
        originIconLabel_->setPixmap(removeFlatBackground(QIcon(QStringLiteral(":/KswordUacDesk/KswordLogo.ico")).pixmap(20, 20)));
        identityLabel_->setText(QStringLiteral("UAC 已出现，正在读取发起者..."));
        processLabel_->setText(QStringLiteral(
            "启动参数：不可用\n进程位置：不可用\n启动链：不可用\n完整性级别：不可用\n提升类型：不可用\n启动时间：不可用\n运行时长：不可用\n数字签名（发起者）：不可用\n数字签名（目标）：不可用"));
    }
    adjustToContent();
    updateButtons();
    if (kShouldPosition)
    {
        // Keep the panel attached only by its top-left relationship to the
        // newly observed consent window.  Its height is content-driven and is
        // intentionally not forced to match the native UAC window.
        show();
        repositionBesideUac(identity);
        positionedUacWindow_ = identity.consentWindow;
        PrivilegeStage::writeDiagnosticLog(QStringLiteral("uac-layout: positioned once hwnd=0x%1 rect=%2,%3,%4,%5")
                                               .arg(reinterpret_cast<quintptr>(identity.consentWindow), 0, 16)
                                               .arg(identity.windowRect.left()).arg(identity.windowRect.top())
                                               .arg(identity.windowRect.width()).arg(identity.windowRect.height()));
    }
    else if (!isVisible())
    {
        // A prompt can briefly disappear during its native transition.  If it
        // is still positively identified when the next result arrives, make
        // the companion visible again without activating it.
        show();
        SetWindowPos(reinterpret_cast<HWND>(winId()), HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }
}

void UacDeskWindow::repositionBesideUac(const UacApplicationIdentity& identity)
{
    if (!identity.consentWindow || identity.windowRect.isEmpty()) return;
    RECT nativeUac{};
    if (!GetWindowRect(identity.consentWindow, &nativeUac)) return;

    HWND ownWindow = reinterpret_cast<HWND>(winId());
    RECT nativePanel{};
    if (!ownWindow || !GetWindowRect(ownWindow, &nativePanel)) return;

    const UINT kDpi = dpiForWindow(identity.consentWindow);
    const double kScale = std::max(1.0, static_cast<double>(kDpi) / 96.0);
    const int kMinimumNativeWidth = qRound(minimumWidth() * kScale);
    const int kPreferredNativeWidth = qRound(430 * kScale);
    int panelWidth = nativePanel.right - nativePanel.left;
    const int kPanelHeight = nativePanel.bottom - nativePanel.top;

    // The panel is attached in the same native coordinate space as consent:
    // zero gap, identical top, and content-driven height. If the monitor edge
    // leaves a narrower strip, shrink the Qt window before placing it.
    HMONITOR monitor = MonitorFromWindow(identity.consentWindow, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{sizeof(monitorInfo)};
    if (monitor && GetMonitorInfoW(monitor, &monitorInfo))
    {
        const int kAvailableRight = monitorInfo.rcWork.right - nativeUac.right;
        const int kTargetWidth = kAvailableRight >= kMinimumNativeWidth
            ? std::min(kPreferredNativeWidth, kAvailableRight)
            : kPreferredNativeWidth;
        if (kTargetWidth > 0 && kTargetWidth < panelWidth)
        {
            const int kTargetLogicalWidth = qMax(minimumWidth(), qRound(kTargetWidth / kScale));
            resize(kTargetLogicalWidth, height());
            if (GetWindowRect(ownWindow, &nativePanel))
                panelWidth = nativePanel.right - nativePanel.left;
        }
    }

    const int kX = nativeUac.right;
    const int kY = nativeUac.top;
    const BOOL kPositioned = SetWindowPos(ownWindow,
                                         HWND_TOPMOST,
                                         kX,
                                         kY,
                                         panelWidth,
                                         kPanelHeight,
                                         SWP_NOACTIVATE | SWP_SHOWWINDOW);
    PrivilegeStage::writeDiagnosticLog(QStringLiteral(
        "uac-layout: native adjacent right result=%1 x=%2 y=%3 w=%4 h=%5 uacRight=%6 uacTop=%7")
                                           .arg(kPositioned ? 1 : 0)
                                           .arg(kX).arg(kY).arg(panelWidth).arg(kPanelHeight)
                                           .arg(nativeUac.right).arg(nativeUac.top));
}

void UacDeskWindow::updateButtons()
{
    const bool kAllowed = actionState_.unique && !actionState_.protectedProcess && !actionRunning_.load() && isWinlogonDesktop();
    suspendButton_->setEnabled(kAllowed);
    terminateButton_->setEnabled(kAllowed);
    powerShellButton_->setEnabled(!launchRunning_.load() && isWinlogonDesktop());
    launchMainButton_->setEnabled(!launchRunning_.load() && isWinlogonDesktop());
}

void UacDeskWindow::showStatus(const QString& status, bool error)
{
    Q_UNUSED(error);
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("ui-status: %1").arg(status));
}

void UacDeskWindow::launchMainOnSecureDesktop()
{
    if (launchRunning_.exchange(true)) return;
    if (launchThread_.joinable()) launchThread_.join();
    const QString kExecutable = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("Ksword5.1.exe"));
    PrivilegeStage::writeDiagnosticLog(QStringLiteral("system-launch: Ksword target resolved from application directory: %1")
                                           .arg(kExecutable));
    QStringList args;
    const DWORD kSessionId = PrivilegeStage::currentSessionId();
    updateButtons();
    launchThread_ = std::thread([this, kExecutable, args, kSessionId]
    {
        QString error;
        const bool kOk = PrivilegeStage::launchSystemStage(kExecutable, args,
                                                          QString::fromWCharArray(kWinlogonDesktop),
                                                          kSessionId, error);
        if (!scanStop_.load())
        {
            QMetaObject::invokeMethod(this, [this, kOk, error]
            {
                launchRunning_ = false;
                if (!kOk)
                    showStatus(QStringLiteral("打开 Ksword5.1 失败：%1").arg(error), true);
                else
                    showStatus(QStringLiteral("已在当前 Winlogon 安全桌面启动 Ksword5.1"));
                updateButtons();
            }, Qt::QueuedConnection);
        }
        else
        {
            launchRunning_ = false;
        }
    });
}

void UacDeskWindow::launchPowerShellOnSecureDesktop()
{
    if (launchRunning_.exchange(true)) return;
    if (launchThread_.joinable()) launchThread_.join();
    const QString kWindowsDirectory = QString::fromWCharArray([] {
        static wchar_t buffer[MAX_PATH] = {};
        static DWORD length = GetWindowsDirectoryW(buffer, static_cast<UINT>(std::size(buffer)));
        return buffer;
    }());
    const QString kExecutable = QDir(kWindowsDirectory).filePath(QStringLiteral("System32/WindowsPowerShell/v1.0/powershell.exe"));
    const QStringList kArgs{QStringLiteral("-NoLogo")};
    const DWORD kSessionId = PrivilegeStage::currentSessionId();
    updateButtons();
    launchThread_ = std::thread([this, kExecutable, kArgs, kSessionId]
    {
        QString error;
        const bool kOk = PrivilegeStage::launchSystemStage(kExecutable, kArgs,
                                                          QString::fromWCharArray(kWinlogonDesktop),
                                                          kSessionId, error);
        if (!scanStop_.load())
        {
            QMetaObject::invokeMethod(this, [this, kOk, error]
            {
                launchRunning_ = false;
                if (!kOk)
                    showStatus(QStringLiteral("启动 PowerShell 失败：%1").arg(error), true);
                else
                    showStatus(QStringLiteral("已在当前 Winlogon 安全桌面启动 PowerShell"));
                updateButtons();
            }, Qt::QueuedConnection);
        }
        else
        {
            launchRunning_ = false;
        }
    });
}

void UacDeskWindow::runProcessAction(int action)
{
    if (!actionState_.unique || actionState_.protectedProcess)
    {
        showStatus(QStringLiteral("发起者身份未唯一确认或属于受保护进程，动作已拒绝"), true);
        refreshUacState();
        return;
    }
    if (actionRunning_.exchange(true)) return;
    if (actionThread_.joinable()) actionThread_.join();
    const ProcessIdentity kTarget = actionState_.origin;
    updateButtons();
    actionThread_ = std::thread([this, action, kTarget]
    {
        QString error;
        bool ok = ProcessInspector::identityStillMatches(kTarget);
        if (ok)
        {
            if (action == 0) ok = ProcessInspector::suspend(kTarget, error);
            else ok = ProcessInspector::terminate(kTarget, error);
        }
        if (!scanStop_.load())
        {
            QMetaObject::invokeMethod(this, [this, ok, error]
            {
                actionRunning_ = false;
                if (!ok && error.isEmpty())
                    showStatus(QStringLiteral("发起者身份在执行前校验失败，动作已拒绝"), true);
                else
                    showStatus(ok ? QStringLiteral("进程动作已完成") : QStringLiteral("进程动作失败：%1").arg(error), !ok);
                updateButtons();
                if (ok) QTimer::singleShot(250, this, [this] { refreshUacState(); });
            }, Qt::QueuedConnection);
        }
        else
        {
            actionRunning_ = false;
        }
    });
}

bool UacDeskWindow::isAlive(HANDLE process) { return process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT; }

void UacDeskWindow::checkParent()
{
    if (!parentProcess_ || parentCheckRunning_.exchange(true)) return;
    if (parentCheckThread_.joinable()) parentCheckThread_.join();
    const HANDLE kParentProcess = parentProcess_;
    const quint64 kExpectedCreationTime = parentCreationTime_;
    parentCheckThread_ = std::thread([this, kParentProcess, kExpectedCreationTime]
    {
        const bool kAlive = isAlive(kParentProcess);
        const bool kIdentityMatches = kAlive && processCreationTime(kParentProcess) == kExpectedCreationTime;
        if ((!kAlive || !kIdentityMatches) && !scanStop_.load())
        {
            QMetaObject::invokeMethod(this, [this, kAlive]
            {
                parentCheckRunning_ = false;
                if (!kAlive)
                {
                    PrivilegeStage::writeDiagnosticLog(QStringLiteral("parent-watch: parent process is no longer alive, quitting"));
                    showStatus(QStringLiteral("Ksword5.1 已退出，安全桌面伴随程序即将退出"));
                }
                else
                {
                    PrivilegeStage::writeDiagnosticLog(QStringLiteral("parent-watch: parent creation time changed, quitting"));
                    showStatus(QStringLiteral("父进程身份发生变化，伴随程序即将退出"), true);
                }
                close();
                qApp->quit();
            }, Qt::QueuedConnection);
        }
        else
        {
            parentCheckRunning_ = false;
        }
    });
}
