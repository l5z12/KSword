#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    void stopActiveKswordTraceSessionsByPrefix(const QStringList& sessionPrefixList)
    {
        constexpr ULONG kQuerySessionCapacity = 96;
        constexpr ULONG kTraceNameChars = 1024;
        constexpr ULONG kLogFileChars = 1024;
        constexpr ULONG kPropertyBufferSize =
            sizeof(EVENT_TRACE_PROPERTIES)
            + (kTraceNameChars + kLogFileChars) * sizeof(wchar_t);

        std::vector<std::vector<unsigned char>> propertyBufferList(
            kQuerySessionCapacity,
            std::vector<unsigned char>(kPropertyBufferSize, 0));
        std::vector<EVENT_TRACE_PROPERTIES*> propertyPointerList(kQuerySessionCapacity, nullptr);

        for (ULONG indexValue = 0; indexValue < kQuerySessionCapacity; ++indexValue)
        {
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBufferList[indexValue].data());
            properties->Wnode.BufferSize = kPropertyBufferSize;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            properties->LogFileNameOffset =
                sizeof(EVENT_TRACE_PROPERTIES) + kTraceNameChars * sizeof(wchar_t);
            propertyPointerList[indexValue] = properties;
        }

        ULONG sessionCount = kQuerySessionCapacity;
        const ULONG kQueryStatus = ::QueryAllTracesW(
            propertyPointerList.data(),
            kQuerySessionCapacity,
            &sessionCount);
        if (kQueryStatus != ERROR_SUCCESS && kQueryStatus != ERROR_MORE_DATA)
        {
            return;
        }

        for (ULONG indexValue = 0; indexValue < sessionCount && indexValue < kQuerySessionCapacity; ++indexValue)
        {
            const EVENT_TRACE_PROPERTIES* properties = propertyPointerList[indexValue];
            if (properties == nullptr || properties->LoggerNameOffset == 0)
            {
                continue;
            }

            const wchar_t* loggerNamePointer = reinterpret_cast<const wchar_t*>(
                propertyBufferList[indexValue].data() + properties->LoggerNameOffset);
            const QString kLoggerNameText = QString::fromWCharArray(loggerNamePointer).trimmed();
            if (kLoggerNameText.isEmpty())
            {
                continue;
            }

            const bool kShouldStop = std::any_of(
                sessionPrefixList.begin(),
                sessionPrefixList.end(),
                [&kLoggerNameText](const QString& prefixText) {
                    return !prefixText.trimmed().isEmpty()
                        && kLoggerNameText.startsWith(prefixText, Qt::CaseInsensitive);
                });
            if (!kShouldStop)
            {
                continue;
            }

            const std::wstring kLoggerNameWide = kLoggerNameText.toStdWString();
            std::vector<unsigned char> stopBuffer(
                sizeof(EVENT_TRACE_PROPERTIES) + (kLoggerNameWide.size() + 1) * sizeof(wchar_t),
                0);
            auto* stopProperties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(stopBuffer.data());
            stopProperties->Wnode.BufferSize = static_cast<ULONG>(stopBuffer.size());
            stopProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wchar_t* stopLoggerNamePointer = reinterpret_cast<wchar_t*>(
                stopBuffer.data() + stopProperties->LoggerNameOffset);
            ::wcscpy_s(stopLoggerNamePointer, kLoggerNameWide.size() + 1, kLoggerNameWide.c_str());
            ::ControlTraceW(0, stopLoggerNamePointer, stopProperties, EVENT_TRACE_CONTROL_STOP);
        }
    }

    // bytesPerSecondToText:
    // - Convert byte rate to human-readable text (B/s, KB/s, MB/s, GB/s);
    // - Used to display real-time values in chart titles.
    QString bytesPerSecondToText(const double bytesPerSecondValue)
    {
        const double kAbsValue = std::max(0.0, bytesPerSecondValue);
        if (kAbsValue < 1024.0)
        {
            return QStringLiteral("%1 B/s").arg(kAbsValue, 0, 'f', 1);
        }
        if (kAbsValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(kAbsValue / 1024.0, 0, 'f', 1);
        }
        if (kAbsValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(kAbsValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB/s").arg(kAbsValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // fileTimeToUint64:
    // - Merges FILETIME into a 64-bit integer for easier time difference calculation.
    // - Used for CPU utilization sampling.
    std::uint64_t fileTimeToUint64(const FILETIME& fileTimeValue)
    {
        ULARGE_INTEGER largeIntValue{};
        largeIntValue.LowPart = fileTimeValue.dwLowDateTime;
        largeIntValue.HighPart = fileTimeValue.dwHighDateTime;
        return static_cast<std::uint64_t>(largeIntValue.QuadPart);
    }

    // Thread-local COM initialization.
    bool initCom(QString* errorOut)
    {
        if (errorOut != nullptr)
        {
            errorOut->clear();
        }

        const HRESULT kInitResult = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(kInitResult) && kInitResult != RPC_E_CHANGED_MODE)
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("CoInitializeEx失败:0x%1").arg(static_cast<unsigned long>(kInitResult), 0, 16);
            }
            return false;
        }

        const HRESULT kSecResult = ::CoInitializeSecurity(
            nullptr,
            -1,
            nullptr,
            nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE,
            nullptr);

        if (FAILED(kSecResult) && kSecResult != RPC_E_TOO_LATE)
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("CoInitializeSecurity失败:0x%1").arg(static_cast<unsigned long>(kSecResult), 0, 16);
            }
            return false;
        }

        return true;
    }

    // Convert VARIANT to QString.
    QString variantToText(const VARIANT& value)
    {
        switch (value.vt)
        {
        case VT_BSTR:
            return value.bstrVal != nullptr ? QString::fromWCharArray(value.bstrVal) : QString();
        case VT_I4:
        case VT_INT:
            return QString::number(value.intVal);
        case VT_UI4:
        case VT_UINT:
            return QString::number(value.uintVal);
        case VT_I8:
            return QString::number(static_cast<qint64>(value.llVal));
        case VT_UI8:
            return QString::number(static_cast<qulonglong>(value.ullVal));
        case VT_BOOL:
            return value.boolVal == VARIANT_TRUE ? QStringLiteral("true") : QStringLiteral("false");
        case VT_NULL:
        case VT_EMPTY:
            return QStringLiteral("<null>");
        default:
            return QString("<vt=%1>").arg(value.vt);
        }
    }

    // Text matching helper:
    // - Supports both standard 'contains' and regular expression matching modes.
    // - Support case-sensitive toggle;
    // - If pattern is empty, it is treated as a match.
    bool textMatch(
        const QString& sourceText,
        const QString& patternText,
        const bool useRegex,
        const Qt::CaseSensitivity caseSensitivity)
    {
        if (patternText.trimmed().isEmpty())
        {
            return true;
        }

        if (!useRegex)
        {
            return sourceText.contains(patternText, caseSensitivity);
        }

        QRegularExpression::PatternOptions options = QRegularExpression::NoPatternOption;
        if (caseSensitivity == Qt::CaseInsensitive)
        {
            options |= QRegularExpression::CaseInsensitiveOption;
        }
        const QRegularExpression kRegex(patternText, options);
        if (!kRegex.isValid())
        {
            return false;
        }
        return kRegex.match(sourceText).hasMatch();
    }

    // Connect to ROOT\\CIMV2.
    bool connectWmi(IWbemServices** serviceOut, QString* errorOut)
    {
        if (serviceOut == nullptr)
        {
            return false;
        }
        *serviceOut = nullptr;

        CComPtr<IWbemLocator> locator;
        const HRESULT kCreateResult = ::CoCreateInstance(
            CLSID_WbemLocator,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<void**>(&locator));

        if (FAILED(kCreateResult) || locator == nullptr)
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("创建WbemLocator失败:0x%1").arg(static_cast<unsigned long>(kCreateResult), 0, 16);
            }
            return false;
        }

        CComPtr<IWbemServices> service;
        const HRESULT kConnectResult = locator->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            nullptr,
            nullptr,
            nullptr,
            WBEM_FLAG_CONNECT_USE_MAX_WAIT,
            nullptr,
            nullptr,
            &service);

        if (FAILED(kConnectResult) || service == nullptr)
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("连接ROOT\\CIMV2失败:0x%1").arg(static_cast<unsigned long>(kConnectResult), 0, 16);
            }
            return false;
        }

        const HRESULT kBlanketResult = ::CoSetProxyBlanket(
            service,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            nullptr,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE);

        if (FAILED(kBlanketResult))
        {
            if (errorOut != nullptr)
            {
                *errorOut = QString("CoSetProxyBlanket失败:0x%1").arg(static_cast<unsigned long>(kBlanketResult), 0, 16);
            }
            return false;
        }

        *serviceOut = service.Detach();
        return true;
    }

    // GUID to text.
    QString guidToText(const GUID& guidValue)
    {
        wchar_t buffer[64] = {};
        if (::StringFromGUID2(guidValue, buffer, static_cast<int>(std::size(buffer))) <= 0)
        {
            return QStringLiteral("{00000000-0000-0000-0000-000000000000}");
        }
        return QString::fromWCharArray(buffer);
    }

    // Extract the PID from "pid/name" text.
    bool parsePid(const QString& text, std::uint32_t& pidOut)
    {
        pidOut = 0;
        const QRegularExpression kRegex(QStringLiteral("(\\d+)"));
        const QRegularExpressionMatch kMatch = kRegex.match(text);
        if (!kMatch.hasMatch())
        {
            return false;
        }

        bool ok = false;
        const std::uint32_t kPid = kMatch.captured(1).toUInt(&ok);
        if (!ok || kPid == 0)
        {
            return false;
        }

        pidOut = kPid;
        return true;
    }

    // Open process detail window.
    void openProcessDetail(QWidget* parent, std::uint32_t pid)
    {
        if (pid == 0)
        {
            return;
        }

        ks::process::ProcessRecord record;
        bool ok = ks::process::queryProcessStaticDetailByPid(pid, record);

        if (!ok)
        {
            std::vector<ks::process::ProcessRecord> list = ks::process::enumerateProcesses(
                ks::process::ProcessEnumStrategy::kAuto);
            const auto kFoundIt = std::find_if(
                list.begin(),
                list.end(),
                [pid](const ks::process::ProcessRecord& item) {
                    return item.pid == pid;
                });
            if (kFoundIt != list.end())
            {
                record = *kFoundIt;
                ok = true;
            }
        }

        if (!ok)
        {
            QMessageBox::warning(parent, QStringLiteral("进程详情"), QStringLiteral("未找到 PID=%1").arg(pid));
            return;
        }

        ProcessDetailWindow* window = new ProcessDetailWindow(record, nullptr);
        window->setAttribute(Qt::WA_DeleteOnClose, true);
        window->show();
        window->raise();
        window->activateWindow();
    }

    // currentSystemTime100ns：
    // - Purpose: Read the current system time as a FILETIME-compatible 100ns timestamp;
    // - Call: ETW listen start/stop, timeline real-time right boundary, and fallback timestamp reuse.
    // - Return: An integer in 100ns units since 1601-01-01 UTC.
    std::uint64_t currentSystemTime100ns()
    {
        FILETIME fileTime{};
        ::GetSystemTimeAsFileTime(&fileTime);

        ULARGE_INTEGER value{};
        value.LowPart = fileTime.dwLowDateTime;
        value.HighPart = fileTime.dwHighDateTime;
        return static_cast<std::uint64_t>(value.QuadPart);
    }

    // Convert current time to 100ns text.
    QString now100nsText()
    {
        return QString::number(static_cast<qulonglong>(currentSystemTime100ns()));
    }

    // Convert text GUID to GUID structure: supports both "{...}" and "..." input formats.
    bool parseGuidText(const QString& text, GUID& guidOut)
    {
        QString normalized = text.trimmed();
        if (normalized.isEmpty())
        {
            return false;
        }
        if (!normalized.startsWith('{'))
        {
            normalized = QStringLiteral("{%1}").arg(normalized);
        }

        const std::wstring kGuidTextWide = normalized.toStdWString();
        HRESULT hr = ::CLSIDFromString(
            const_cast<LPOLESTR>(kGuidTextWide.c_str()),
            &guidOut);
        return SUCCEEDED(hr);
    }

    // ETW level text maps to TRACE_LEVEL_*.
    UCHAR etwLevelFromText(const QString& levelText)
    {
        if (levelText.contains(QStringLiteral("Critical"), Qt::CaseInsensitive))
        {
            return TRACE_LEVEL_CRITICAL;
        }
        if (levelText.contains(QStringLiteral("Error"), Qt::CaseInsensitive))
        {
            return TRACE_LEVEL_ERROR;
        }
        if (levelText.contains(QStringLiteral("Warning"), Qt::CaseInsensitive))
        {
            return TRACE_LEVEL_WARNING;
        }
        if (levelText.contains(QStringLiteral("Verbose"), Qt::CaseInsensitive))
        {
            return TRACE_LEVEL_VERBOSE;
        }
        return TRACE_LEVEL_INFORMATION;
    }

    // Keyword mask parsing: supports "0x..." and decimal text.
    ULONGLONG parseKeywordMaskText(const QString& maskText)
    {
        const QString kTrimmed = maskText.trimmed();
        if (kTrimmed.isEmpty())
        {
            return 0ULL;
        }

        bool ok = false;
        ULONGLONG mask = 0ULL;
        if (kTrimmed.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            mask = kTrimmed.mid(2).toULongLong(&ok, 16);
        }
        else
        {
            mask = kTrimmed.toULongLong(&ok, 16);
            if (!ok)
            {
                mask = kTrimmed.toULongLong(&ok, 10);
            }
        }
        return ok ? mask : 0ULL;
    }
}
