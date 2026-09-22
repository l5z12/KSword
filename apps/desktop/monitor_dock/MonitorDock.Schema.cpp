#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    // ETW schema global cache:
    // - Purpose: Avoid repeatedly calling TdhGetEventInformation for every event.
    // - Lifecycle: actively clear when starting to listen, then lazy-load by event type subsequently.
    std::mutex gEtwSchemaCacheMutex;

    std::unordered_map<std::string, EtwSchemaEntry> gEtwSchemaCacheByKey;

    // etwSchemaKeyFromRecord：
    // - Purpose: Generate event type cache key.
    // - Composition: ProviderGuid + EventId + Version + Task + Opcode.
    std::string etwSchemaKeyFromRecord(const EVENT_RECORD* eventRecord)
    {
        if (eventRecord == nullptr)
        {
            return std::string();
        }

        const QString kKeyText = QStringLiteral("%1|%2|%3|%4|%5")
            .arg(guidToText(eventRecord->EventHeader.ProviderId))
            .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id))
            .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Version))
            .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Task))
            .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Opcode));
        return kKeyText.toStdString();
    }

    // clearEtwSchemaCache：
    // - Purpose: Clear the ETW schema cache.
    // - Call: Invoke once before starting each monitoring round to ensure cache consistency with the current session.
    void clearEtwSchemaCache()
    {
        std::lock_guard<std::mutex> lock(gEtwSchemaCacheMutex);
        gEtwSchemaCacheByKey.clear();
    }

    // tryBuildEtwSchemaByTdh：
    // - Purpose: Builds the schema for a single event type using TDH;
    // - Call: Triggered only on cache miss to avoid redundant queries for every event.
    bool tryBuildEtwSchemaByTdh(const EVENT_RECORD* eventRecord, EtwSchemaEntry* schemaOut)
    {
        if (eventRecord == nullptr || schemaOut == nullptr)
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

        EtwSchemaEntry localSchema;
        const unsigned char* rawInfoBuffer = reinterpret_cast<const unsigned char*>(eventInfo);
        localSchema.cacheKeyText = QString::fromStdString(etwSchemaKeyFromRecord(eventRecord));
        localSchema.eventNameText = etwTextAtOffset(rawInfoBuffer, eventInfo->EventNameOffset);
        localSchema.taskNameText = etwTextAtOffset(rawInfoBuffer, eventInfo->TaskNameOffset);
        localSchema.opcodeNameText = etwTextAtOffset(rawInfoBuffer, eventInfo->OpcodeNameOffset);

        localSchema.propertyList.reserve(eventInfo->TopLevelPropertyCount);
        for (ULONG propertyIndex = 0; propertyIndex < eventInfo->TopLevelPropertyCount; ++propertyIndex)
        {
            const EVENT_PROPERTY_INFO& propertyInfo = eventInfo->EventPropertyInfoArray[propertyIndex];

            EtwSchemaPropertyEntry propertyEntry;
            propertyEntry.propertyIndex = propertyIndex;
            propertyEntry.propertyNameText = etwTextAtOffset(rawInfoBuffer, propertyInfo.NameOffset);
            if (propertyEntry.propertyNameText.isEmpty())
            {
                propertyEntry.propertyNameText = QStringLiteral("Property_%1").arg(propertyIndex);
            }
            propertyEntry.normalizedNameText = normalizeEtwPropertyName(propertyEntry.propertyNameText);
            propertyEntry.meaningText = etwPropertyMeaningText(propertyEntry.normalizedNameText);
            propertyEntry.flags = static_cast<ULONG>(propertyInfo.Flags);
            propertyEntry.isStruct = (propertyInfo.Flags & PropertyStruct) != 0;

            if (!propertyEntry.isStruct)
            {
                propertyEntry.inType = propertyInfo.nonStructType.InType;
                propertyEntry.outType = propertyInfo.nonStructType.OutType;
                propertyEntry.fixedLength = propertyInfo.length;
                propertyEntry.fixedCount = propertyInfo.count;
                propertyEntry.useLengthProperty = (propertyInfo.Flags & PropertyParamLength) != 0;
                propertyEntry.useCountProperty = (propertyInfo.Flags & PropertyParamCount) != 0;
                if (propertyEntry.useLengthProperty)
                {
                    propertyEntry.lengthPropertyIndex = propertyInfo.lengthPropertyIndex;
                }
                if (propertyEntry.useCountProperty)
                {
                    propertyEntry.countPropertyIndex = propertyInfo.countPropertyIndex;
                }
            }

            localSchema.propertyList.push_back(std::move(propertyEntry));
        }

        *schemaOut = std::move(localSchema);
        return true;
    }

    // tryGetEtwSchemaCached：
    // - Purpose: Prefer fetching schema from cache; on miss, build once and write back to cache.
    // - Call: Invoked at every event callback entry, but TDH queries occur only on the first hit.
    bool tryGetEtwSchemaCached(const EVENT_RECORD* eventRecord, EtwSchemaEntry* schemaOut)
    {
        if (eventRecord == nullptr || schemaOut == nullptr)
        {
            return false;
        }

        const std::string kCacheKey = etwSchemaKeyFromRecord(eventRecord);
        if (kCacheKey.empty())
        {
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(gEtwSchemaCacheMutex);
            const auto kFound = gEtwSchemaCacheByKey.find(kCacheKey);
            if (kFound != gEtwSchemaCacheByKey.end())
            {
                *schemaOut = kFound->second;
                return true;
            }
        }

        EtwSchemaEntry builtSchema;
        if (!tryBuildEtwSchemaByTdh(eventRecord, &builtSchema))
        {
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(gEtwSchemaCacheMutex);
            auto [iter, inserted] = gEtwSchemaCacheByKey.emplace(kCacheKey, builtSchema);
            if (!inserted)
            {
                iter->second = builtSchema;
            }
            *schemaOut = iter->second;
        }
        return true;
    }
}
