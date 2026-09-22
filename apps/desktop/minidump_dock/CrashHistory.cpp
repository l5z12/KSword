#include "CrashHistory.h"

#include <QHash>
#include <QTimeZone>
#include <QXmlStreamReader>

#include <algorithm>
#include <vector>

#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

namespace ks::minidump
{
    namespace
    {
        // kMaxEvents: Maximum number of events to retrieve in a single query. Crashes are low-frequency events,
        // so this limit is sufficient and prevents the UI from being flooded when logs expand abnormally.
        constexpr int kMaxEvents = 200;

        // EventFields: Content of interest in an event.
        struct EventFields
        {
            QDateTime time;              // time: event time (converted to local time zone).
            QHash<QString, QString> data; // data: Named fields in EventData.
            QStringList unnamed;         // unnamed: Data values without a Name attribute, ordered sequentially.
        };

        // parseEventXml function: Extracts time and EventData from the rendered event XML.
        // Accepts an event XML string; returns the parsed result, where an invalid timestamp indicates the entry is unusable.
        EventFields parseEventXml(const QString& xml)
        {
            EventFields fields; // fields: Collection of fields to return.
            QXmlStreamReader reader(xml);
            bool inEventData = false; // inEventData: Indicates whether the current position is within an EventData element.

            while (!reader.atEnd())
            {
                reader.readNext();
                if (reader.isStartElement())
                {
                    const QStringView kName = reader.name();
                    if (kName == QLatin1String("TimeCreated"))
                    {
                        const QString kRaw =
                            reader.attributes().value(QLatin1String("SystemTime")).toString();
                        // Event timestamps are in UTC ISO8601 format; they only align with user memory after converting to the local time zone.
                        QDateTime parsed = QDateTime::fromString(kRaw, Qt::ISODateWithMs);
                        if (!parsed.isValid())
                        {
                            parsed = QDateTime::fromString(kRaw, Qt::ISODate);
                        }
                        if (parsed.isValid())
                        {
                            parsed.setTimeZone(QTimeZone::UTC);
                            fields.time = parsed.toLocalTime();
                        }
                    }
                    else if (kName == QLatin1String("EventData"))
                    {
                        inEventData = true;
                    }
                    else if (inEventData && kName == QLatin1String("Data"))
                    {
                        const QString kKey =
                            reader.attributes().value(QLatin1String("Name")).toString();
                        const QString kValue = reader.readElementText();
                        if (kKey.isEmpty())
                        {
                            fields.unnamed.append(kValue);
                        }
                        else
                        {
                            fields.data.insert(kKey, kValue);
                        }
                    }
                }
                else if (reader.isEndElement() &&
                         reader.name() == QLatin1String("EventData"))
                {
                    inEventData = false;
                }
            }
            return fields;
        }

        // queryEvents purpose: Query system logs via XPath, render each entry as XML, then parse.
        // Takes a query XPath string and an errorOut output for failure reasons; returns the parsed event fields.
        std::vector<EventFields> queryEvents(const QString& query, QString* const errorOut)
        {
            std::vector<EventFields> events; // events: parsing results.

            const std::wstring kQueryBuffer = query.toStdWString();
            // EvtQueryReverseDirection: Read backwards from the latest entry; combined with kMaxEvents to retrieve the most recent records.
            const EVT_HANDLE kHandle = ::EvtQuery(
                nullptr,
                L"System",
                kQueryBuffer.c_str(),
                EvtQueryChannelPath | EvtQueryReverseDirection);
            if (kHandle == nullptr)
            {
                if (errorOut != nullptr && errorOut->isEmpty())
                {
                    *errorOut = QStringLiteral("查询系统事件日志失败，错误码 %1。")
                                    .arg(::GetLastError());
                }
                return events;
            }

            std::vector<wchar_t> buffer(4096); // buffer: Output buffer for EvtRender, resized as needed.
            while (static_cast<int>(events.size()) < kMaxEvents)
            {
                EVT_HANDLE batch[16] = {};
                DWORD returned = 0;
                if (::EvtNext(kHandle, 16, batch, INFINITE, 0, &returned) == FALSE)
                {
                    break;
                }
                for (DWORD index = 0; index < returned; ++index)
                {
                    DWORD used = 0;
                    DWORD properties = 0;
                    BOOL rendered = ::EvtRender(
                        nullptr,
                        batch[index],
                        EvtRenderEventXml,
                        static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                        buffer.data(),
                        &used,
                        &properties);
                    if (rendered == FALSE &&
                        ::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        buffer.resize((used / sizeof(wchar_t)) + 1);
                        rendered = ::EvtRender(
                            nullptr,
                            batch[index],
                            EvtRenderEventXml,
                            static_cast<DWORD>(buffer.size() * sizeof(wchar_t)),
                            buffer.data(),
                            &used,
                            &properties);
                    }
                    if (rendered != FALSE)
                    {
                        EventFields fields =
                            parseEventXml(QString::fromWCharArray(buffer.data()));
                        if (fields.time.isValid())
                        {
                            events.push_back(std::move(fields));
                        }
                    }
                    ::EvtClose(batch[index]);
                }
                if (returned == 0)
                {
                    break;
                }
            }
            ::EvtClose(kHandle);
            return events;
        }

        // buildQuery: Constructs an XPath query string with a time window.
        // Passes provider (provider name), eventId (event ID), and windowMs (time window in milliseconds).
        QString buildQuery(
            const QString& provider,
            const int eventId,
            const qint64 windowMs)
        {
            return QStringLiteral(
                       "*[System[Provider[@Name='%1'] and (EventID=%2) and "
                       "TimeCreated[timediff(@SystemTime) <= %3]]]")
                .arg(provider)
                .arg(eventId)
                .arg(windowMs);
        }
    }

    QString crashEventKindText(const CrashEventKind kind)
    {
        switch (kind)
        {
        case CrashEventKind::kBugCheck:
            return QStringLiteral("蓝屏");
        case CrashEventKind::kHardHang:
            return QStringLiteral("硬挂死（无转储）");
        case CrashEventKind::kBugCheckReboot:
            return QStringLiteral("蓝屏后重启");
        case CrashEventKind::kFilterLoad:
        default:
            return QStringLiteral("筛选器加载");
        }
    }

    std::vector<CrashHistoryEntry> collectCrashHistory(
        const int maxDays,
        const QString& filterNameFilter,
        QString* const errorOut)
    {
        std::vector<CrashHistoryEntry> entries; // entries: Timeline records.
        if (errorOut != nullptr)
        {
            errorOut->clear();
        }

        const int kDays = (maxDays <= 0) ? 30 : maxDays;
        const qint64 kWindowMs = static_cast<qint64>(kDays) * 24LL * 3600LL * 1000LL;

        // 1. Blue Screen Records: param1 contains the stop code and four parameters; param2 contains the dump file path.
        for (const EventFields& fields : queryEvents(
                 buildQuery(
                     QStringLiteral("Microsoft-Windows-WER-SystemErrorReporting"),
                     1001,
                     kWindowMs),
                 errorOut))
        {
            CrashHistoryEntry entry;
            entry.time = fields.time;
            entry.kind = CrashEventKind::kBugCheck;
            entry.kindText = crashEventKindText(entry.kind);
            const QString kParameters = fields.data.value(QStringLiteral("param1"));
            entry.dumpPath = fields.data.value(QStringLiteral("param2"));
            entry.summary = kParameters;
            entry.detail = entry.dumpPath;
            // Extract the stop code itself from "0x00000050 (...)" for dump reconciliation.
            const int kSpaceAt = kParameters.indexOf(QLatin1Char(' '));
            const QString kCodeText =
                (kSpaceAt > 0) ? kParameters.left(kSpaceAt) : kParameters;
            bool converted = false;
            const std::uint32_t kCode =
                kCodeText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
                    ? kCodeText.mid(2).toUInt(&converted, 16)
                    : kCodeText.toUInt(&converted, 16);
            entry.bugCheckCode = converted ? kCode : 0;
            entries.push_back(entry);
        }

        // 2. Abnormal shutdown: A BugcheckCode of 0 indicates a hard hang with no dump generated.
        // This is the most valuable criterion for this module. Without it, hard hangs are mistakenly treated
        // as 'blue screen but dump not saved,' causing users to search for a dump file that does not exist.
        for (const EventFields& fields : queryEvents(
                 buildQuery(
                     QStringLiteral("Microsoft-Windows-Kernel-Power"),
                     41,
                     kWindowMs),
                 errorOut))
        {
            CrashHistoryEntry entry;
            entry.time = fields.time;
            const QString kCodeText = fields.data.value(QStringLiteral("BugcheckCode"));
            const std::uint32_t kCode = kCodeText.toUInt();
            entry.bugCheckCode = kCode;
            if (kCode == 0)
            {
                entry.kind = CrashEventKind::kHardHang;
                entry.summary = QStringLiteral(
                    "系统失去响应后被复位，未产生停止码，因此不会有转储文件。");
            }
            else
            {
                entry.kind = CrashEventKind::kBugCheckReboot;
                entry.summary = QStringLiteral("非正常关机，停止码 0x%1。")
                                    .arg(kCode, 8, 16, QLatin1Char('0'));
            }
            entry.kindText = crashEventKindText(entry.kind);
            // Power button timestamp and long-press flag distinguish 'manual power-off' from 'system hang followed by reset'.
            entry.detail =
                QStringLiteral("电源键时间戳 %1；长按电源键 %2")
                    .arg(fields.data.value(QStringLiteral("PowerButtonTimestamp")),
                         fields.data.value(QStringLiteral("LongPowerButtonPressDetected")));
            entries.push_back(entry);
        }

        // III. Filter load record: DeviceTime is the timestamp of the driver image.
        // After a crash, the code was modified, recompiled, and reloaded; this is the only way to confirm whether the crash occurred in the fixed version.
        if (!filterNameFilter.trimmed().isEmpty())
        {
            for (const EventFields& fields : queryEvents(
                     buildQuery(
                         QStringLiteral("Microsoft-Windows-FilterManager"),
                         6,
                         kWindowMs),
                     errorOut))
            {
                const QString kDeviceName = fields.data.value(QStringLiteral("DeviceName"));
                if (!kDeviceName.contains(filterNameFilter.trimmed(), Qt::CaseInsensitive))
                {
                    continue;
                }
                CrashHistoryEntry entry;
                entry.time = fields.time;
                entry.kind = CrashEventKind::kFilterLoad;
                entry.kindText = crashEventKindText(entry.kind);
                entry.summary = QStringLiteral("筛选器 %1 已加载。").arg(kDeviceName);
                entry.detail = QStringLiteral("映像时间戳 %1")
                                   .arg(fields.data.value(QStringLiteral("DeviceTime")));
                entries.push_back(entry);
            }
        }

        std::sort(
            entries.begin(),
            entries.end(),
            [](const CrashHistoryEntry& left, const CrashHistoryEntry& right)
            { return left.time > right.time; });
        return entries;
    }
}
