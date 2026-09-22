#include "ProcessTraceMonitorWidget.h"

// ============================================================
// ProcessTraceMonitorWidget.Capture.cpp
// Purpose:
// 1) Implement ETW session start, stop, and event callbacks;
// 2) Maintain the target process tree, associating the root process with its runtime child processes;
// 3) Primarily uses ETW with process snapshots as a supplement; retains only events related to the target.
// ============================================================

#include <QApplication>
#include <QByteArray>
#include <QDateTime>
#include <QMetaObject>
#include <QMessageBox>
#include <QPointer>
#include <QTableWidget>
#include <QTimer>

#include <algorithm>
#include <cstring>
#include <set>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>
#include <evntrace.h>
#include <evntcons.h>
#include <sddl.h>
#include <tdh.h>

#pragma comment(lib, "Tdh.lib")

namespace
{
    // trimUnicodeBuffer：
    // - Purpose: Convert Unicode buffer to QString and trim trailing NULs.
    // - Call: Reused during ETW property parsing.
    QString trimUnicodeBuffer(const wchar_t* textPointer, const int charCount)
    {
        if (textPointer == nullptr || charCount <= 0)
        {
            return QString();
        }

        QString textValue = QString::fromWCharArray(textPointer, charCount);
        const int kNullIndex = textValue.indexOf(QChar(u'\0'));
        if (kNullIndex >= 0)
        {
            textValue.truncate(kNullIndex);
        }
        return textValue.trimmed();
    }

    // trimAnsiBuffer：
    // - Purpose: Convert ANSI buffer to QString and trim trailing NULs;
    // - Call: Reused during ETW property parsing.
    QString trimAnsiBuffer(const char* textPointer, const int charCount)
    {
        if (textPointer == nullptr || charCount <= 0)
        {
            return QString();
        }

        QByteArray textBytes(textPointer, charCount);
        const int kNullIndex = textBytes.indexOf('\0');
        if (kNullIndex >= 0)
        {
            textBytes.truncate(kNullIndex);
        }
        return QString::fromLocal8Bit(textBytes).trimmed();
    }

    // binaryPreviewText：
    // - Purpose: Convert binary attributes to a hexadecimal preview.
    // - Call: Fallback output when the property type cannot be formatted in a user-friendly way.
    QString binaryPreviewText(const unsigned char* dataPointer, const std::size_t dataSize)
    {
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QStringLiteral("<empty>");
        }

        QStringList byteTextList;
        const std::size_t kPreviewSize = std::min<std::size_t>(dataSize, 16);
        for (std::size_t indexValue = 0; indexValue < kPreviewSize; ++indexValue)
        {
            byteTextList << QStringLiteral("%1").arg(dataPointer[indexValue], 2, 16, QChar(u'0')).toUpper();
        }
        QString previewText = byteTextList.join(' ');
        if (dataSize > kPreviewSize)
        {
            previewText += QStringLiteral(" ... (%1 bytes)").arg(dataSize);
        }
        return previewText;
    }

    // normalizePropertyName：
    // - Purpose: normalize ETW property names to text containing only lowercase letters and digits;
    // - Call: Subsequent heuristic identification of PID, parent PID, process name, etc., will uniformly reuse this.
    QString normalizePropertyName(const QString& propertyNameText)
    {
        QString normalizedText;
        normalizedText.reserve(propertyNameText.size());
        for (const QChar kCh : propertyNameText.toLower())
        {
            if (kCh.isLetterOrNumber())
            {
                normalizedText.push_back(kCh);
            }
        }
        return normalizedText;
    }

    // parseGuidText：
    // - Purpose: Supports parsing a GUID structure from "{...}" or raw GUID text.
    // - Call: Reused when parsing Provider GUID text.
    bool parseGuidText(const QString& guidText, GUID* guidOut)
    {
        if (guidOut == nullptr)
        {
            return false;
        }

        QString normalizedText = guidText.trimmed();
        if (normalizedText.isEmpty())
        {
            return false;
        }
        if (!normalizedText.startsWith('{'))
        {
            normalizedText = QStringLiteral("{%1}").arg(normalizedText);
        }

        const std::wstring kGuidWideText = normalizedText.toStdWString();
        return SUCCEEDED(::CLSIDFromString(const_cast<LPOLESTR>(kGuidWideText.c_str()), guidOut));
    }

    // guidToTextLocal：
    // - Purpose: Convert a GUID to a standard string.
    // - Call: The attribute decoding logic in the anonymous namespace cannot directly access the class's private static functions, so a local version is provided separately.
    QString guidToTextLocal(const GUID& guidValue)
    {
        wchar_t guidBuffer[64] = {};
        if (::StringFromGUID2(guidValue, guidBuffer, static_cast<int>(std::size(guidBuffer))) <= 0)
        {
            return QStringLiteral("{00000000-0000-0000-0000-000000000000}");
        }
        return QString::fromWCharArray(guidBuffer);
    }

    // isProcessCreateEvent：
    // - Purpose: Determine if an event is a 'process create/start' type based on Provider type and event name;
    // - Call: Used to include new child processes in the target process tree.
    bool isProcessCreateEvent(const QString& providerTypeText, const QString& eventNameText)
    {
        if (providerTypeText != QStringLiteral("进程"))
        {
            return false;
        }

        return eventNameText.contains(QStringLiteral("Start"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("Create"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("DCStart"), Qt::CaseInsensitive);
    }

    // isProcessStopEvent：
    // - Purpose: Determine if the event is a 'process termination/stop' event based on Provider type and event name.
    // - Call: Marks running child processes as exited.
    bool isProcessStopEvent(const QString& providerTypeText, const QString& eventNameText)
    {
        if (providerTypeText != QStringLiteral("进程"))
        {
            return false;
        }

        return eventNameText.contains(QStringLiteral("Stop"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("End"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("Terminate"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("DCStop"), Qt::CaseInsensitive);
    }

    // Forward declaration:
    // - propertyNameLooksLikeProcessId first excludes the parent PID property internally.
    // - Therefore, declare it here first to avoid symbol resolution issues due to definition order in the current compilation unit.
    bool propertyNameLooksLikeParentProcessId(const QString& normalizedName);

    // propertyNameLooksLikeProcessId：
    // - Purpose: Heuristically identify if this property resembles a PID/ProcessId;
    // - Called when constructing the candidate associated PID set for reuse.
    bool propertyNameLooksLikeProcessId(const QString& normalizedName)
    {
        if (propertyNameLooksLikeParentProcessId(normalizedName))
        {
            return false;
        }

        return normalizedName == QStringLiteral("processid")
            || normalizedName == QStringLiteral("pid")
            || normalizedName == QStringLiteral("targetprocessid")
            || normalizedName == QStringLiteral("newprocessid")
            || normalizedName == QStringLiteral("oldprocessid")
            || normalizedName == QStringLiteral("clientprocessid")
            || normalizedName == QStringLiteral("serverprocessid")
            || normalizedName == QStringLiteral("owningprocessid")
            || normalizedName == QStringLiteral("originatingprocessid")
            || normalizedName == QStringLiteral("requestorprocessid")
            || normalizedName == QStringLiteral("requesterprocessid")
            || normalizedName == QStringLiteral("applicationprocessid")
            || normalizedName == QStringLiteral("relatedprocessid")
            || normalizedName == QStringLiteral("subjectprocessid")
            || normalizedName == QStringLiteral("processidnew")
            || normalizedName == QStringLiteral("processidold");
    }

    // propertyNameLooksLikeParentProcessId：
    // - Purpose: Heuristically identify attributes related to the parent PID;
    // - Usage: Used to determine if a child process was spawned by a member of the target process tree.
    bool propertyNameLooksLikeParentProcessId(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("parentprocessid")
            || normalizedName == QStringLiteral("parentid")
            || normalizedName == QStringLiteral("creatingprocessid")
            || normalizedName == QStringLiteral("creatorprocessid")
            || normalizedName == QStringLiteral("sourceprocessid")
            || normalizedName == QStringLiteral("callingprocessid");
    }

    // propertyNameLooksLikeProcessName：
    // - Purpose: Heuristically identify properties related to process names or image paths;
    // - Call: Appends name and path when adding a child process node.
    bool propertyNameLooksLikeProcessName(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("imagename")
            || normalizedName == QStringLiteral("imagefilename")
            || normalizedName == QStringLiteral("processname")
            || normalizedName == QStringLiteral("applicationname")
            || normalizedName == QStringLiteral("commandline")
            || normalizedName == QStringLiteral("filename");
    }

    // readScalarNumber：
    // - Purpose: Reads an integer from a fixed-width binary buffer;
    // - Call: Reused when ETW properties are numeric types.
    template <typename TValue>
    bool readScalarNumber(const std::vector<unsigned char>& dataBuffer, TValue* valueOut)
    {
        if (valueOut == nullptr || dataBuffer.size() < sizeof(TValue))
        {
            return false;
        }

        TValue localValue{};
        std::memcpy(&localValue, dataBuffer.data(), sizeof(TValue));
        *valueOut = localValue;
        return true;
    }

    // decodePropertyValue：
    // - Purpose: Format ETW top-level properties into readable text as much as possible and extract numeric values;
    // - Call: extractEventProperties iterates and calls internally for each property.
    QString decodePropertyValue(
        const EVENT_PROPERTY_INFO& propertyInfo,
        const std::vector<unsigned char>& dataBuffer,
        bool* numericAvailableOut,
        std::uint64_t* numericValueOut)
    {
        if (numericAvailableOut != nullptr)
        {
            *numericAvailableOut = false;
        }
        if (numericValueOut != nullptr)
        {
            *numericValueOut = 0;
        }

        const USHORT kInTypeValue = propertyInfo.nonStructType.InType;
        switch (kInTypeValue)
        {
        case TDH_INTYPE_UNICODESTRING:
            return trimUnicodeBuffer(
                reinterpret_cast<const wchar_t*>(dataBuffer.data()),
                static_cast<int>(dataBuffer.size() / sizeof(wchar_t)));

        case TDH_INTYPE_ANSISTRING:
            return trimAnsiBuffer(
                reinterpret_cast<const char*>(dataBuffer.data()),
                static_cast<int>(dataBuffer.size()));

        case TDH_INTYPE_INT8:
        {
            std::int8_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = static_cast<std::uint64_t>(value); }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_UINT8:
        {
            std::uint8_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_INT16:
        {
            std::int16_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = static_cast<std::uint64_t>(value); }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_UINT16:
        {
            std::uint16_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_INT32:
        case TDH_INTYPE_HEXINT32:
        {
            std::uint32_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                if (kInTypeValue == TDH_INTYPE_HEXINT32)
                {
                    return QStringLiteral("0x%1").arg(value, 8, 16, QChar(u'0')).toUpper();
                }
                return QString::number(static_cast<std::int32_t>(value));
            }
            break;
        }

        case TDH_INTYPE_UINT32:
        {
            std::uint32_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_INT64:
        case TDH_INTYPE_HEXINT64:
        {
            std::uint64_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                if (kInTypeValue == TDH_INTYPE_HEXINT64)
                {
                    return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar(u'0')).toUpper();
                }
                return QString::number(static_cast<qlonglong>(value));
            }
            break;
        }

        case TDH_INTYPE_UINT64:
        {
            std::uint64_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return QString::number(static_cast<qulonglong>(value));
            }
            break;
        }

        case TDH_INTYPE_BOOLEAN:
        {
            std::uint32_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return value == 0 ? QStringLiteral("false") : QStringLiteral("true");
            }
            break;
        }

        case TDH_INTYPE_GUID:
        {
            GUID guidValue{};
            if (readScalarNumber(dataBuffer, &guidValue))
            {
                return guidToTextLocal(guidValue);
            }
            break;
        }

        case TDH_INTYPE_FILETIME:
        {
            std::uint64_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                return QString::number(static_cast<qulonglong>(value));
            }
            break;
        }

        case TDH_INTYPE_POINTER:
        {
            std::uint64_t value = 0;
            if (dataBuffer.size() >= sizeof(std::uint64_t) && readScalarNumber(dataBuffer, &value))
            {
                return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar(u'0')).toUpper();
            }

            std::uint32_t value32 = 0;
            if (readScalarNumber(dataBuffer, &value32))
            {
                return QStringLiteral("0x%1").arg(value32, 8, 16, QChar(u'0')).toUpper();
            }
            break;
        }

        case TDH_INTYPE_SID:
        {
            LPWSTR sidTextPointer = nullptr;
            if (::ConvertSidToStringSidW(
                reinterpret_cast<PSID>(const_cast<unsigned char*>(dataBuffer.data())),
                &sidTextPointer) != FALSE
                && sidTextPointer != nullptr)
            {
                const QString kSidText = QString::fromWCharArray(sidTextPointer);
                ::LocalFree(sidTextPointer);
                return kSidText;
            }
            break;
        }
        }

        return binaryPreviewText(dataBuffer.data(), dataBuffer.size());
    }

    // findNumericProperty：
    // - Purpose: Search the property list for the first parsable numeric value based on 'standardized property name';
    // - Call: reused when identifying key fields such as ParentPid and ProcessId.
    bool findNumericProperty(
        const std::vector<ProcessTraceMonitorWidget::EtwPropertyValue>& propertyList,
        bool (*predicate)(const QString&),
        std::uint32_t* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }

        for (const ProcessTraceMonitorWidget::EtwPropertyValue& property : propertyList)
        {
            if (!property.numericAvailable)
            {
                continue;
            }

            const QString kNormalizedName = normalizePropertyName(property.nameText);
            if (!predicate(kNormalizedName))
            {
                continue;
            }

            if (property.numericValue == 0 || property.numericValue > UINT32_MAX)
            {
                continue;
            }

            *valueOut = static_cast<std::uint32_t>(property.numericValue);
            return true;
        }
        return false;
    }

    // firstMeaningfulProcessText：
    // - Purpose: Find the first text resembling "Process Name / Image Path" from the property list.
    // - Call: Prioritize filling name and path with properties when creating a new child process node.
    QString firstMeaningfulProcessText(
        const std::vector<ProcessTraceMonitorWidget::EtwPropertyValue>& propertyList)
    {
        for (const ProcessTraceMonitorWidget::EtwPropertyValue& property : propertyList)
        {
            const QString kNormalizedName = normalizePropertyName(property.nameText);
            if (!propertyNameLooksLikeProcessName(kNormalizedName))
            {
                continue;
            }

            const QString kTextValue = property.valueText.trimmed();
            if (!kTextValue.isEmpty())
            {
                return kTextValue;
            }
        }
        return QString();
    }
}

void WINAPI ProcessTraceMonitorWidget::processTraceEtwCallback(struct _EVENT_RECORD* eventRecordPtr)
{
    if (eventRecordPtr == nullptr)
    {
        return;
    }

    EVENT_RECORD* eventRecord = reinterpret_cast<EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr || eventRecord->UserContext == nullptr)
    {
        return;
    }

    auto* widgetPointer = reinterpret_cast<ProcessTraceMonitorWidget*>(eventRecord->UserContext);
    widgetPointer->enqueueEventFromRecord(eventRecordPtr);
}

void ProcessTraceMonitorWidget::enqueueEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr || captureStopFlag_.load() || capturePaused_.load())
    {
        return;
    }

    const QString kProviderGuidText = guidToText(eventRecord->EventHeader.ProviderId);
    QString providerNameText = kProviderGuidText;
    QString providerTypeText = providerTypeFromName(kProviderGuidText);
    {
        std::lock_guard<std::mutex> lock(runtimeMutex_);
        const auto kFound = std::find_if(
            activeProviderList_.begin(),
            activeProviderList_.end(),
            [kProviderGuidText](const ProviderEntry& entry) {
                return entry.providerGuidText.compare(kProviderGuidText, Qt::CaseInsensitive) == 0;
            });
        if (kFound != activeProviderList_.end())
        {
            providerNameText = kFound->providerName;
            providerTypeText = kFound->providerTypeText;
        }
    }

    std::vector<EtwPropertyValue> propertyList;
    extractEventProperties(eventRecordPtr, &propertyList);

    CapturedEventRow rowValue;
    if (!buildRelevantEventRow(eventRecordPtr, providerNameText, providerTypeText, propertyList, &rowValue))
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        if (pendingRows_.size() >= kPendingRowCapacity)
        {
            pendingRows_.pop_front();
            ++pendingDroppedRows_;
        }
        pendingRows_.push_back(std::move(rowValue));
    }
}

bool ProcessTraceMonitorWidget::extractEventProperties(
    const struct _EVENT_RECORD* eventRecordPtr,
    std::vector<EtwPropertyValue>* propertyListOut) const
{
    if (propertyListOut == nullptr)
    {
        return false;
    }
    propertyListOut->clear();

    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return false;
    }

    DWORD infoBufferSize = 0;
    ULONG status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        nullptr,
        &infoBufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || infoBufferSize == 0)
    {
        return false;
    }

    std::vector<unsigned char> infoBuffer(infoBufferSize, 0);
    auto* eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
    status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        eventInfo,
        &infoBufferSize);
    if (status != ERROR_SUCCESS || eventInfo == nullptr)
    {
        return false;
    }

    propertyListOut->reserve(eventInfo->TopLevelPropertyCount);
    for (ULONG indexValue = 0; indexValue < eventInfo->TopLevelPropertyCount; ++indexValue)
    {
        const EVENT_PROPERTY_INFO& propertyInfo = eventInfo->EventPropertyInfoArray[indexValue];
        const wchar_t* propertyNamePointer = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const unsigned char*>(eventInfo) + propertyInfo.NameOffset);
        const QString kPropertyNameText = propertyNamePointer != nullptr
            ? QString::fromWCharArray(propertyNamePointer)
            : QStringLiteral("<Unknown>");

        if ((propertyInfo.Flags & PropertyStruct) != 0)
        {
            QStringList memberNameList;
            const ULONG kPropertyCount = eventInfo->PropertyCount;
            const ULONG kStructStartIndex = static_cast<ULONG>(propertyInfo.structType.StructStartIndex);
            const ULONG kStructMemberCount = static_cast<ULONG>(propertyInfo.structType.NumOfStructMembers);
            for (ULONG memberOffset = 0; memberOffset < kStructMemberCount; ++memberOffset)
            {
                const ULONG kMemberIndex = kStructStartIndex + memberOffset;
                if (kMemberIndex >= kPropertyCount)
                {
                    break;
                }

                const EVENT_PROPERTY_INFO& memberInfo = eventInfo->EventPropertyInfoArray[kMemberIndex];
                const wchar_t* memberNamePointer = reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<const unsigned char*>(eventInfo) + memberInfo.NameOffset);
                const QString kMemberNameText = memberNamePointer != nullptr
                    ? QString::fromWCharArray(memberNamePointer)
                    : QStringLiteral("<UnknownMember>");
                memberNameList << kMemberNameText;
            }

            QString rawPreviewText;
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyNamePointer);
            descriptor.ArrayIndex = ULONG_MAX;

            ULONG propertySize = 0;
            status = ::TdhGetPropertySize(
                const_cast<EVENT_RECORD*>(eventRecord),
                0,
                nullptr,
                1,
                &descriptor,
                &propertySize);
            if (status == ERROR_SUCCESS && propertySize > 0)
            {
                std::vector<unsigned char> propertyBuffer(propertySize, 0);
                status = ::TdhGetProperty(
                    const_cast<EVENT_RECORD*>(eventRecord),
                    0,
                    nullptr,
                    1,
                    &descriptor,
                    propertySize,
                    propertyBuffer.data());
                if (status == ERROR_SUCCESS)
                {
                    rawPreviewText = binaryPreviewText(propertyBuffer.data(), propertyBuffer.size());
                }
            }

            EtwPropertyValue propertyValue;
            propertyValue.nameText = kPropertyNameText;
            propertyValue.valueText = QStringLiteral("[Struct] members={%1}%2")
                .arg(memberNameList.isEmpty() ? QStringLiteral("<none>") : memberNameList.join(QStringLiteral(", ")))
                .arg(rawPreviewText.isEmpty() ? QString() : QStringLiteral(" raw=%1").arg(rawPreviewText));
            propertyListOut->push_back(std::move(propertyValue));
            continue;
        }

        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyNamePointer);
        descriptor.ArrayIndex = ULONG_MAX;

        ULONG propertySize = 0;
        status = ::TdhGetPropertySize(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            1,
            &descriptor,
            &propertySize);
        if (status != ERROR_SUCCESS || propertySize == 0)
        {
            continue;
        }

        std::vector<unsigned char> propertyBuffer(propertySize, 0);
        status = ::TdhGetProperty(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            1,
            &descriptor,
            propertySize,
            propertyBuffer.data());
        if (status != ERROR_SUCCESS)
        {
            continue;
        }

        EtwPropertyValue propertyValue;
        propertyValue.nameText = kPropertyNameText;
        propertyValue.valueText = decodePropertyValue(
            propertyInfo,
            propertyBuffer,
            &propertyValue.numericAvailable,
            &propertyValue.numericValue);
        propertyListOut->push_back(std::move(propertyValue));
    }

    return !propertyListOut->empty();
}

QString ProcessTraceMonitorWidget::buildEventDetailText(
    const QString& providerGuidText,
    const struct _EVENT_RECORD* eventRecordPtr,
    const std::vector<EtwPropertyValue>& propertyList) const
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return QString();
    }

    QStringList detailPartList;
    detailPartList << QStringLiteral("providerGuid=%1").arg(providerGuidText);
    detailPartList << QStringLiteral("level=%1").arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Level));
    detailPartList << QStringLiteral("task=%1").arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Task));
    detailPartList << QStringLiteral("opcode=%1").arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Opcode));
    detailPartList << QStringLiteral("keyword=0x%1").arg(
        QString::number(
            static_cast<qulonglong>(eventRecord->EventHeader.EventDescriptor.Keyword),
            16).toUpper());

    for (const EtwPropertyValue& property : propertyList)
    {
        QString valueText = property.valueText;
        if (valueText.size() > 256)
        {
            valueText = valueText.left(256) + QStringLiteral(" ...");
        }
        detailPartList << QStringLiteral("%1=%2").arg(property.nameText, valueText);
    }

    QString detailText = detailPartList.join(QStringLiteral(" ; "));
    if (detailText.size() > 6000)
    {
        detailText = detailText.left(6000) + QStringLiteral(" ...");
    }
    return detailText;
}

bool ProcessTraceMonitorWidget::buildRelevantEventRow(
    const struct _EVENT_RECORD* eventRecordPtr,
    const QString& providerNameText,
    const QString& providerTypeText,
    const std::vector<EtwPropertyValue>& propertyList,
    CapturedEventRow* rowOut)
{
    if (rowOut == nullptr)
    {
        return false;
    }

    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return false;
    }

    const int kEventIdValue = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id);
    QString eventNameText = queryEtwEventName(eventRecordPtr);
    if (eventNameText.trimmed().isEmpty())
    {
        eventNameText = QStringLiteral("Event_%1").arg(kEventIdValue);
    }

    const std::uint32_t kHeaderPidValue = static_cast<std::uint32_t>(eventRecord->EventHeader.ProcessId);
    const std::uint32_t kTidValue = static_cast<std::uint32_t>(eventRecord->EventHeader.ThreadId);
    const QString kProviderGuidText = guidToText(eventRecord->EventHeader.ProviderId);
    const std::uint64_t kEventTimestamp100ns = static_cast<std::uint64_t>(eventRecord->EventHeader.TimeStamp.QuadPart);

    std::uint32_t parentPidValue = 0;
    std::uint32_t propertyPidValue = 0;
    findNumericProperty(propertyList, propertyNameLooksLikeParentProcessId, &parentPidValue);
    findNumericProperty(propertyList, propertyNameLooksLikeProcessId, &propertyPidValue);

    const QString kProcessHintText = firstMeaningfulProcessText(propertyList);
    std::uint32_t displayPidValue = kHeaderPidValue != 0 ? kHeaderPidValue : propertyPidValue;
    std::uint32_t rootPidValue = 0;
    QString relationText;
    QString processNameText;
    QString processPathText;
    bool relevant = false;
    bool needsLazyDetailLookup = false;
    // shouldSyncAutoAddTargetList: flag indicating whether to write new child processes to the monitoring list (executed on the UI thread).
    bool shouldSyncAutoAddTargetList = false;
    // autoAdd*: Holds parameters required for 'auto-add to monitoring list'; dispatched to the UI via invokeMethod outside the lock.
    std::uint32_t autoAddPidValue = 0;
    std::uint32_t autoAddParentPidValue = 0;
    QString autoAddProcessNameText;
    QString autoAddProcessPathText;
    std::uint64_t autoAddCreationTime100ns = 0;
    // shouldAutoRemoveTargetList: flag indicating whether to remove exited processes from the monitoring list (executed on the UI thread).
    bool shouldAutoRemoveTargetList = false;
    // autoRemovePidValue: Holds the PID required for 'automatically remove from the monitoring list'.
    std::uint32_t autoRemovePidValue = 0;
    // allowStopAutoRemove: allows automatic removal of the monitoring item only when the exit process PID is explicitly matched.
    bool allowStopAutoRemove = false;

    {
        std::lock_guard<std::mutex> lock(runtimeMutex_);
        auto markTrackedAlive = [this](const std::uint32_t pidValue) {
            const auto kFound = trackedProcessMap_.find(pidValue);
            if (kFound != trackedProcessMap_.end())
            {
                kFound->second.alive = true;
                kFound->second.staleSnapshotRounds = 0;
            }
        };

        const auto kTrackedByPid = [this](const std::uint32_t pidValue) -> RuntimeTrackedProcess* {
            const auto kFound = trackedProcessMap_.find(pidValue);
            return kFound != trackedProcessMap_.end() ? &kFound->second : nullptr;
        };

        RuntimeTrackedProcess* matchedTrackedProcess = nullptr;
        if (kHeaderPidValue != 0)
        {
            matchedTrackedProcess = kTrackedByPid(kHeaderPidValue);
        }
        if (matchedTrackedProcess == nullptr && propertyPidValue != 0)
        {
            matchedTrackedProcess = kTrackedByPid(propertyPidValue);
            if (matchedTrackedProcess != nullptr)
            {
                displayPidValue = propertyPidValue;
            }
        }

        if (matchedTrackedProcess != nullptr
            && !matchedTrackedProcess->alive
            && !isProcessStopEvent(providerTypeText, eventNameText))
        {
            matchedTrackedProcess = nullptr;
        }

        if (matchedTrackedProcess != nullptr)
        {
            relevant = true;
            rootPidValue = matchedTrackedProcess->rootPid;
            relationText = matchedTrackedProcess->isRoot
                ? QStringLiteral("根进程")
                : QStringLiteral("子进程(%1)").arg(matchedTrackedProcess->parentPid);
            processNameText = matchedTrackedProcess->processName;
            processPathText = matchedTrackedProcess->imagePath;
            markTrackedAlive(matchedTrackedProcess->pid);
            needsLazyDetailLookup = matchedTrackedProcess->alive
                && processNameText.trimmed().isEmpty()
                && displayPidValue != 0;
            allowStopAutoRemove = true;
        }

        // Special handling for process creation events:
        // - Even if the current event header PID has already matched the parent process, the 'new child process PID' must still be added to the monitoring list.
        // - Therefore, do not use else-if here; instead, independently execute a second round of parent-child relationship processing.
        const bool kIsCreateEvent = isProcessCreateEvent(providerTypeText, eventNameText);
        if (parentPidValue != 0
            && propertyPidValue != 0
            && kIsCreateEvent)
        {
            RuntimeTrackedProcess* parentTrackedProcess = kTrackedByPid(parentPidValue);
            if (parentTrackedProcess != nullptr)
            {
                // parentRootPidValue: Copies the parent root PID first to avoid accessing the parent node after a map insertion invalidates pointers.
                const std::uint32_t kParentRootPidValue = parentTrackedProcess->rootPid;
                auto childIt = trackedProcessMap_.find(propertyPidValue);
                if (childIt == trackedProcessMap_.end())
                {
                    RuntimeTrackedProcess childTrackedProcess;
                    childTrackedProcess.pid = propertyPidValue;
                    childTrackedProcess.parentPid = parentPidValue;
                    childTrackedProcess.rootPid = kParentRootPidValue;
                    childTrackedProcess.processName = kProcessHintText;
                    childTrackedProcess.imagePath = kProcessHintText;
                    childTrackedProcess.creationTime100ns = 0;
                    childTrackedProcess.alive = true;
                    childTrackedProcess.isRoot = false;
                    childTrackedProcess.staleSnapshotRounds = 0;
                    childTrackedProcess.lastRelatedEventTime100ns = kEventTimestamp100ns;
                    trackedProcessMap_[propertyPidValue] = childTrackedProcess;
                    childIt = trackedProcessMap_.find(propertyPidValue);
                }
                else
                {
                    childIt->second.parentPid = parentPidValue;
                    childIt->second.rootPid = kParentRootPidValue;
                    childIt->second.alive = true;
                    childIt->second.isRoot = false;
                    childIt->second.staleSnapshotRounds = 0;
                    childIt->second.lastRelatedEventTime100ns = kEventTimestamp100ns;
                    if (!kProcessHintText.trimmed().isEmpty())
                    {
                        childIt->second.processName = kProcessHintText;
                        childIt->second.imagePath = kProcessHintText;
                    }
                }

                const RuntimeTrackedProcess& childTrackedProcess = childIt->second;
                relevant = true;
                displayPidValue = propertyPidValue;
                rootPidValue = childTrackedProcess.rootPid;
                relationText = QStringLiteral("子进程(%1)").arg(parentPidValue);
                processNameText = childTrackedProcess.processName;
                processPathText = childTrackedProcess.imagePath;
                needsLazyDetailLookup = childTrackedProcess.alive
                    && processNameText.trimmed().isEmpty()
                    && displayPidValue != 0;
                shouldSyncAutoAddTargetList = true;
                autoAddPidValue = childTrackedProcess.pid;
                autoAddParentPidValue = childTrackedProcess.parentPid;
                autoAddProcessNameText = childTrackedProcess.processName;
                autoAddProcessPathText = childTrackedProcess.imagePath;
                autoAddCreationTime100ns = childTrackedProcess.creationTime100ns;
            }
        }

        if (!relevant)
        {
            for (const EtwPropertyValue& property : propertyList)
            {
                if (!property.numericAvailable || property.numericValue == 0 || property.numericValue > UINT32_MAX)
                {
                    continue;
                }

                const QString kNormalizedName = normalizePropertyName(property.nameText);
                if (!propertyNameLooksLikeProcessId(kNormalizedName)
                    && !propertyNameLooksLikeParentProcessId(kNormalizedName))
                {
                    continue;
                }
                const bool kMatchedByProcessIdProperty = propertyNameLooksLikeProcessId(kNormalizedName);

                RuntimeTrackedProcess* linkedTrackedProcess = kTrackedByPid(static_cast<std::uint32_t>(property.numericValue));
                if (linkedTrackedProcess == nullptr || !linkedTrackedProcess->alive)
                {
                    continue;
                }

                relevant = true;
                displayPidValue = static_cast<std::uint32_t>(property.numericValue);
                rootPidValue = linkedTrackedProcess->rootPid;
                relationText = QStringLiteral("属性关联");
                processNameText = linkedTrackedProcess->processName;
                processPathText = linkedTrackedProcess->imagePath;
                markTrackedAlive(displayPidValue);
                needsLazyDetailLookup = linkedTrackedProcess->alive
                    && processNameText.trimmed().isEmpty()
                    && displayPidValue != 0;
                allowStopAutoRemove = kMatchedByProcessIdProperty;
                break;
            }
        }

        if (relevant
            && displayPidValue != 0
            && allowStopAutoRemove
            && isProcessStopEvent(providerTypeText, eventNameText))
        {
            auto found = trackedProcessMap_.find(displayPidValue);
            if (found != trackedProcessMap_.end())
            {
                found->second.alive = false;
                found->second.lastRelatedEventTime100ns = kEventTimestamp100ns;
                trackedProcessMap_.erase(found);
            }
            shouldAutoRemoveTargetList = true;
            autoRemovePidValue = displayPidValue;
        }
    }

    if (!relevant)
    {
        return false;
    }

    // Lazy detail lookup:
    // - Trigger only once when a new node is hit in the target tree but static details have not yet been retrieved.
    // - This reduces the overhead of querying Win32 for every event.
    if (needsLazyDetailLookup && displayPidValue != 0)
    {
        ks::process::ProcessRecord detailRecord;
        // ETW capture threads only need names/paths for display; signature verification cannot be performed synchronously.
        // includeSignatureCheck=false avoids slowing down event processing with WinVerifyTrust.
        if (ks::process::queryProcessStaticDetailByPid(displayPidValue, detailRecord, false))
        {
            processNameText = QString::fromStdString(detailRecord.processName);
            processPathText = QString::fromStdString(detailRecord.imagePath);

            std::lock_guard<std::mutex> lock(runtimeMutex_);
            auto found = trackedProcessMap_.find(displayPidValue);
            if (found != trackedProcessMap_.end())
            {
                found->second.processName = processNameText;
                found->second.imagePath = processPathText;
                found->second.creationTime100ns = detailRecord.creationTime100ns;
                found->second.alive = true;
                found->second.staleSnapshotRounds = 0;
            }
        }
    }

    if (processNameText.trimmed().isEmpty())
    {
        processNameText = kProcessHintText.trimmed();
    }
    if (processNameText.trimmed().isEmpty())
    {
        processNameText = QStringLiteral("PID=%1").arg(displayPidValue);
    }

    rowOut->time100ns = kEventTimestamp100ns;
    rowOut->time100nsText = QString::number(static_cast<qulonglong>(kEventTimestamp100ns));
    rowOut->typeText = providerTypeText;
    rowOut->providerText = providerNameText;
    rowOut->eventId = kEventIdValue;
    rowOut->eventName = eventNameText;
    rowOut->pidText = QStringLiteral("%1 / %2").arg(displayPidValue).arg(kTidValue);
    rowOut->processText = processPathText.trimmed().isEmpty()
        ? processNameText
        : QStringLiteral("%1 | %2").arg(processNameText, processPathText);
    rowOut->rootPidText = rootPidValue == 0
        ? QStringLiteral("-")
        : QString::number(rootPidValue);
    rowOut->relationText = relationText.trimmed().isEmpty()
        ? QStringLiteral("命中")
        : relationText;
    rowOut->detailText = buildEventDetailText(kProviderGuidText, eventRecordPtr, propertyList);
    rowOut->activityIdText = guidToText(eventRecord->EventHeader.ActivityId);

    // UI sync:
    // - ETW thread is responsible for judgment only.
    // - Unify list change handling to the UI thread to avoid concurrent writes to m_targetProcessList.
    if (shouldSyncAutoAddTargetList && autoAddPidValue != 0)
    {
        QMetaObject::invokeMethod(
            this,
            [this,
             autoAddPidValue,
             autoAddParentPidValue,
             autoAddProcessNameText,
             autoAddProcessPathText,
             autoAddCreationTime100ns]() {
                upsertAutoTrackedProcessInTargetList(
                    autoAddPidValue,
                    autoAddParentPidValue,
                    autoAddProcessNameText,
                    autoAddProcessPathText,
                    autoAddCreationTime100ns);
            },
            Qt::QueuedConnection);
    }

    if (shouldAutoRemoveTargetList && autoRemovePidValue != 0)
    {
        QMetaObject::invokeMethod(
            this,
            [this, autoRemovePidValue]() {
                removeTrackedProcessFromTargetListByPid(
                    autoRemovePidValue,
                    QStringLiteral("ETW 进程退出事件"));
            },
            Qt::QueuedConnection);
    }

    if (displayPidValue != 0 && !shouldAutoRemoveTargetList)
    {
        std::lock_guard<std::mutex> lock(runtimeMutex_);
        const auto kFound = trackedProcessMap_.find(displayPidValue);
        if (kFound != trackedProcessMap_.end())
        {
            kFound->second.lastRelatedEventTime100ns = kEventTimestamp100ns;
        }
    }
    return true;
}
