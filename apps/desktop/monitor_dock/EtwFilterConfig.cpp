#include "EtwFilterConfig.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QSet>
#include <algorithm>
#include <cmath>
#include <limits>

namespace ksword::monitor
{
constexpr const char* kEtwFilterJsonVersionKey = "version";
constexpr const char* kEtwFilterJsonPreGroupsKey = "pre_groups";
constexpr const char* kEtwFilterJsonPostGroupsKey = "post_groups";
constexpr const char* kEtwFilterJsonEnabledKey = "enabled";
constexpr const char* kEtwFilterJsonStringModeKey = "string_mode";
constexpr const char* kEtwFilterJsonCaseSensitiveKey = "case_sensitive";
constexpr const char* kEtwFilterJsonInvertKey = "invert";
constexpr const char* kEtwFilterJsonDetailVisibleOnlyKey = "detail_visible_only";
constexpr const char* kEtwFilterJsonDetailAllFieldsKey = "detail_all_fields";
constexpr const char* kEtwFilterJsonFieldsKey = "fields";
constexpr const char* kEtwFilterJsonFieldKey = "key";
constexpr const char* kEtwFilterJsonFieldValue = "value";
constexpr const char* kEtwFilterJsonProviderCategoriesKey = "provider_categories";
constexpr const char* kEtwFilterJsonSimplePreKey = "simple_pre";
constexpr const char* kEtwFilterJsonSimplePostKey = "simple_post";
constexpr const char* kEtwFilterJsonSimplePidKey = "pid";
constexpr const char* kEtwFilterJsonSimpleProcessNameKey = "process_name";
constexpr const char* kEtwFilterJsonSimpleFilePathKey = "file_path";
constexpr const char* kEtwFilterJsonSimpleEventIdKey = "event_id";
constexpr const char* kEtwFilterJsonSimpleEventNameKey = "event_name";
constexpr const char* kEtwFilterJsonSimpleRegistryPathKey = "registry_path";
constexpr const char* kEtwFilterJsonSimpleNetworkAddressKey = "network_address";
constexpr const char* kEtwFilterJsonSimpleNetworkPortKey = "network_port";
constexpr const char* kEtwFilterJsonSimpleStatusKey = "status";
constexpr const char* kEtwFilterJsonSimpleCustomProviderKey = "custom_provider";
constexpr const char* kEtwFilterJsonSimpleCustomActionKey = "custom_action";
constexpr const char* kEtwFilterJsonSimpleProvidersKey = "providers";
constexpr const char* kEtwFilterJsonSimpleActionsKey = "actions";
QStringList etwFilterProviderCategoryList()
    {
        return QStringList{
            QStringLiteral("进程线程"),
            QStringLiteral("文件注册表"),
            QStringLiteral("网络通信"),
            QStringLiteral("安全审计"),
            QStringLiteral("脚本管理"),
            QStringLiteral("自定义/其他")
        };
    }
const std::vector<EtwFilterFieldDescriptor>& etwFilterFieldDescriptorList()
    {
        static const std::vector<EtwFilterFieldDescriptor> kFieldList{
            { EtwFilterFieldId::kProviderName, "provider_name", "ProviderName", "Provider 名（支持多值）", EtwFilterFieldType::kText, false },
            { EtwFilterFieldId::kProviderGuid, "provider_guid", "ProviderGuid", "Provider GUID（支持多值）", EtwFilterFieldType::kText, false },
            { EtwFilterFieldId::kProviderCategory, "provider_category", "ProviderCategory", "Provider 分类（支持多值）", EtwFilterFieldType::kText, false },
            { EtwFilterFieldId::kEventId, "event_id", "EventId", "事件ID（单值/区间）", EtwFilterFieldType::kNumber, false },
            { EtwFilterFieldId::kEventName, "event_name", "EventName", "事件名（支持多值）", EtwFilterFieldType::kText, false },
            { EtwFilterFieldId::kTask, "task", "Task", "Task（数字区间或名称）", EtwFilterFieldType::kNumberOrText, false },
            { EtwFilterFieldId::kOpcode, "opcode", "Opcode", "Opcode（数字区间或名称）", EtwFilterFieldType::kNumberOrText, false },
            { EtwFilterFieldId::kLevel, "level", "Level", "Level（数字区间或等级名）", EtwFilterFieldType::kNumberOrText, false },
            { EtwFilterFieldId::kKeywordMask, "keyword_mask", "KeywordMask", "KeywordMask（十六进制/区间）", EtwFilterFieldType::kNumber, false },
            { EtwFilterFieldId::kHeaderPid, "header_pid", "HeaderPID", "发起PID（单值/区间）", EtwFilterFieldType::kNumber, false },
            { EtwFilterFieldId::kHeaderTid, "header_tid", "HeaderTID", "发起TID（单值/区间）", EtwFilterFieldType::kNumber, false },
            { EtwFilterFieldId::kActivityId, "activity_id", "ActivityId", "ActivityId（支持多值）", EtwFilterFieldType::kText, false },
            { EtwFilterFieldId::kTimestampRange, "timestamp", "TimeRange100ns", "100ns 时间戳（单值/区间）", EtwFilterFieldType::kTimeRange, false },
            { EtwFilterFieldId::kResourceType, "resource_type", "resourceType", "语义资源类型", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kAction, "action", "action", "语义动作", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kTarget, "target", "target", "语义目标", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kStatus, "status", "status", "语义状态", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kDetailKeyword, "detail_keyword", "DetailKeyword", "Detail 关键字", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kTargetPid, "target_pid", "TargetPID", "目标PID（ProcessId/TargetProcessId）", EtwFilterFieldType::kNumber, true },
            { EtwFilterFieldId::kParentPid, "parent_pid", "ParentPID", "父PID（ParentProcessId/PPID）", EtwFilterFieldType::kNumber, true },
            { EtwFilterFieldId::kTargetTid, "target_tid", "TargetTID", "目标TID（ThreadId/TargetThreadId）", EtwFilterFieldType::kNumber, true },
            { EtwFilterFieldId::kProcessName, "process_name", "ProcessName", "进程名", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kImagePath, "image_path", "ImagePath", "映像路径", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kCommandLine, "command_line", "CommandLine", "命令行", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kFilePath, "file_path", "FilePath", "文件路径", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kFileOldPath, "file_old_path", "OldPath", "旧路径", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kFileNewPath, "file_new_path", "NewPath", "新路径", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kFileOperation, "file_operation", "FileOperation", "文件操作类型", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kFileStatusCode, "file_status_code", "FileStatusCode", "文件状态码", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kFileAccessMask, "file_access_mask", "FileAccessMask", "文件访问掩码", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kRegistryKeyPath, "registry_key_path", "RegistryKeyPath", "KeyPath", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kRegistryValueName, "registry_value_name", "RegistryValueName", "ValueName", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kRegistryHive, "registry_hive", "RegistryHive", "Hive", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kRegistryOperation, "registry_operation", "RegistryOperation", "注册表操作类型", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kRegistryStatus, "registry_status", "RegistryStatus", "注册表状态码", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kSourceIp, "source_ip", "SourceIP", "源IP（单值/CIDR/范围）", EtwFilterFieldType::kIp, true },
            { EtwFilterFieldId::kSourcePort, "source_port", "SourcePort", "源端口（单值/范围）", EtwFilterFieldType::kPort, true },
            { EtwFilterFieldId::kDestinationIp, "destination_ip", "DestinationIP", "目的IP（单值/CIDR/范围）", EtwFilterFieldType::kIp, true },
            { EtwFilterFieldId::kDestinationPort, "destination_port", "DestinationPort", "目的端口（单值/范围）", EtwFilterFieldType::kPort, true },
            { EtwFilterFieldId::kProtocol, "protocol", "Protocol", "协议", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kDirection, "direction", "Direction", "方向", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kDomain, "domain", "Domain", "域名", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kHost, "host", "Host", "主机名", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kAuditResult, "audit_result", "AuditResult", "审计结果", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kUserText, "user", "User", "用户", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kSidText, "sid", "SID", "SID", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kSecurityPid, "security_pid", "SecurityPID", "安全相关PID（单值/范围）", EtwFilterFieldType::kNumber, true },
            { EtwFilterFieldId::kSecurityTid, "security_tid", "SecurityTID", "安全相关TID（单值/范围）", EtwFilterFieldType::kNumber, true },
            { EtwFilterFieldId::kSecurityLevel, "security_level", "SecurityLevel", "安全事件等级", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kScriptHostProcess, "script_host", "ScriptHostProcess", "脚本宿主进程", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kScriptKeyword, "script_keyword", "ScriptKeyword", "脚本关键字", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kScriptTaskName, "script_task", "ScriptTaskName", "任务名", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kWmiClassName, "wmi_class", "WMIClassName", "WMI 类名", EtwFilterFieldType::kText, true },
            { EtwFilterFieldId::kWmiNamespace, "wmi_namespace", "WMINamespace", "WMI 命名空间", EtwFilterFieldType::kText, true }
        };
        return kFieldList;
    }
const EtwFilterFieldDescriptor* findEtwFilterFieldDescriptorByKey(const QString& keyText)
    {
        const QString kNormalizedKey = keyText.trimmed().toLower();
        if (kNormalizedKey.isEmpty())
        {
            return nullptr;
        }

        const std::vector<EtwFilterFieldDescriptor>& fieldList = etwFilterFieldDescriptorList();
        const auto kFound = std::find_if(
            fieldList.begin(),
            fieldList.end(),
            [&kNormalizedKey](const EtwFilterFieldDescriptor& descriptor) {
                return QString::fromLatin1(descriptor.key).compare(kNormalizedKey, Qt::CaseInsensitive) == 0;
            });
        return kFound == fieldList.end() ? nullptr : &(*kFound);
    }
QString etwFilterStringModeToText(const EtwStringMatchMode mode)
    {
        switch (mode)
        {
        case EtwStringMatchMode::kExact: return QStringLiteral("exact");
        case EtwStringMatchMode::kContains: return QStringLiteral("contains");
        case EtwStringMatchMode::kPrefix: return QStringLiteral("prefix");
        case EtwStringMatchMode::kSuffix: return QStringLiteral("suffix");
        case EtwStringMatchMode::kRegex:
        default:
            return QStringLiteral("regex");
        }
    }
EtwStringMatchMode etwFilterStringModeFromText(const QString& modeText)
    {
        const QString kNormalized = modeText.trimmed().toLower();
        if (kNormalized == QStringLiteral("exact"))
        {
            return EtwStringMatchMode::kExact;
        }
        if (kNormalized == QStringLiteral("contains"))
        {
            return EtwStringMatchMode::kContains;
        }
        if (kNormalized == QStringLiteral("prefix"))
        {
            return EtwStringMatchMode::kPrefix;
        }
        if (kNormalized == QStringLiteral("suffix"))
        {
            return EtwStringMatchMode::kSuffix;
        }
        return EtwStringMatchMode::kRegex;
    }
bool parseEtwFilterConfigModel(
    const QByteArray& jsonData,
    const EtwFilterChoices& choices,
    EtwFilterConfigModel& filterModelOut)
{
    QJsonParseError parseError;
    const QJsonDocument kJsonDocument = QJsonDocument::fromJson(jsonData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !kJsonDocument.isObject())
    {
        return false;
    }

    const QJsonObject kRootObject = kJsonDocument.object();
    const QJsonValue kVersionValue =
        kRootObject.value(QString::fromLatin1(kEtwFilterJsonVersionKey));
    if (!kVersionValue.isUndefined())
    {
        if (!kVersionValue.isDouble())
        {
            return false;
        }
        const double kVersionNumber = kVersionValue.toDouble(-1.0);
        const int kVersion = kVersionValue.toInt(-1);
        if (kVersionNumber != static_cast<double>(kVersion)
            || (kVersion != 1 && kVersion != 2))
        {
            return false;
        }
    }

    const auto kReadBoolean = [](
        const QJsonObject& object,
        const char* key,
        const bool defaultValue,
        bool& valueOut) {
        const QJsonValue kValue = object.value(QString::fromLatin1(key));
        if (kValue.isUndefined())
        {
            valueOut = defaultValue;
            return true;
        }
        if (!kValue.isBool())
        {
            return false;
        }
        valueOut = kValue.toBool(defaultValue);
        return true;
    };
    const auto kReadString = [](
        const QJsonObject& object,
        const char* key,
        QString& valueOut) {
        const QJsonValue kValue = object.value(QString::fromLatin1(key));
        if (kValue.isUndefined())
        {
            valueOut.clear();
            return true;
        }
        if (!kValue.isString())
        {
            return false;
        }
        valueOut = kValue.toString().trimmed();
        return true;
    };
    const auto kReadStringList = [](
        const QJsonObject& object,
        const char* key,
        QStringList& valueListOut) {
        valueListOut.clear();
        const QJsonValue kValue = object.value(QString::fromLatin1(key));
        if (kValue.isUndefined())
        {
            return true;
        }
        if (!kValue.isArray())
        {
            return false;
        }
        for (const QJsonValue& itemValue : kValue.toArray())
        {
            if (!itemValue.isString())
            {
                return false;
            }
            const QString kItemText = itemValue.toString().trimmed();
            if (!kItemText.isEmpty())
            {
                valueListOut.push_back(kItemText);
            }
        }
        return true;
    };
    const auto kNormalizeKnownStringList = [](
        QStringList& valueList,
        const QStringList& knownValueList) {
        QStringList normalizedValueList;
        for (const QString& valueText : valueList)
        {
            const auto kFound = std::find_if(
                knownValueList.cbegin(),
                knownValueList.cend(),
                [&valueText](const QString& knownValue) {
                    return knownValue.compare(valueText, Qt::CaseInsensitive) == 0;
                });
            if (kFound == knownValueList.cend())
            {
                return false;
            }
            if (!normalizedValueList.contains(*kFound, Qt::CaseInsensitive))
            {
                normalizedValueList.push_back(*kFound);
            }
        }
        valueList = std::move(normalizedValueList);
        return true;
    };

    EtwFilterConfigModel candidateModel;
    const auto kParseSimpleFilter = [
        &choices,
        &kRootObject,
        &kReadBoolean,
        &kReadString,
        &kReadStringList,
        &kNormalizeKnownStringList](
        const EtwFilterStage stage,
        const char* objectKey,
        EtwSimpleFilterModel& simpleModelOut) {
        const QJsonValue kSimpleValue = kRootObject.value(QString::fromLatin1(objectKey));
        if (kSimpleValue.isUndefined())
        {
            simpleModelOut = EtwSimpleFilterModel{};
            return true;
        }
        if (!kSimpleValue.isObject())
        {
            return false;
        }

        const QJsonObject kSimpleObject = kSimpleValue.toObject();
        if (!kReadBoolean(
                kSimpleObject,
                kEtwFilterJsonEnabledKey,
                true,
                simpleModelOut.enabled)
            || !kReadString(kSimpleObject, kEtwFilterJsonSimplePidKey, simpleModelOut.pidText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleProcessNameKey,
                simpleModelOut.processNameText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleFilePathKey,
                simpleModelOut.filePathText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleEventIdKey,
                simpleModelOut.eventIdText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleEventNameKey,
                simpleModelOut.eventNameText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleRegistryPathKey,
                simpleModelOut.registryPathText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleNetworkAddressKey,
                simpleModelOut.networkAddressText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleNetworkPortKey,
                simpleModelOut.networkPortText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleStatusKey,
                simpleModelOut.statusText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleCustomProviderKey,
                simpleModelOut.customProviderText)
            || !kReadString(
                kSimpleObject,
                kEtwFilterJsonSimpleCustomActionKey,
                simpleModelOut.customActionText)
            || !kReadStringList(
                kSimpleObject,
                kEtwFilterJsonSimpleProvidersKey,
                simpleModelOut.providerPresetNameList)
            || !kReadStringList(
                kSimpleObject,
                kEtwFilterJsonSimpleActionsKey,
                simpleModelOut.actionPresetList))
        {
            return false;
        }

        const auto& known = stage == EtwFilterStage::kPre ? choices.pre : choices.post;
        return kNormalizeKnownStringList(
                simpleModelOut.providerPresetNameList,
                known.providers)
            && kNormalizeKnownStringList(
                simpleModelOut.actionPresetList,
                known.actions);
    };

    if (!kParseSimpleFilter(
            EtwFilterStage::kPre,
            kEtwFilterJsonSimplePreKey,
            candidateModel.preSimpleFilter)
        || !kParseSimpleFilter(
            EtwFilterStage::kPost,
            kEtwFilterJsonSimplePostKey,
            candidateModel.postSimpleFilter))
    {
        return false;
    }

    const auto kParseGroupList = [
        &kRootObject,
        &kReadBoolean,
        &kReadStringList,
        &kNormalizeKnownStringList](
        const char* arrayKey,
        std::vector<EtwFilterRuleGroupModel>& groupModelListOut) {
        groupModelListOut.clear();
        const QJsonValue kGroupListValue = kRootObject.value(QString::fromLatin1(arrayKey));
        if (kGroupListValue.isUndefined())
        {
            return true;
        }
        if (!kGroupListValue.isArray())
        {
            return false;
        }

        const QStringList kKnownCategoryList = etwFilterProviderCategoryList();
        const QStringList kKnownStringModeList{
            QStringLiteral("regex"),
            QStringLiteral("exact"),
            QStringLiteral("contains"),
            QStringLiteral("prefix"),
            QStringLiteral("suffix")
        };
        const QJsonArray kGroupArray = kGroupListValue.toArray();
        groupModelListOut.reserve(static_cast<std::size_t>(kGroupArray.size()));
        for (const QJsonValue& groupValue : kGroupArray)
        {
            if (!groupValue.isObject())
            {
                return false;
            }

            const QJsonObject kGroupObject = groupValue.toObject();
            EtwFilterRuleGroupModel groupModel;
            groupModel.groupId = static_cast<int>(groupModelListOut.size()) + 1;
            if (!kReadBoolean(
                    kGroupObject,
                    kEtwFilterJsonEnabledKey,
                    true,
                    groupModel.enabled)
                || !kReadBoolean(
                    kGroupObject,
                    kEtwFilterJsonCaseSensitiveKey,
                    false,
                    groupModel.caseSensitive)
                || !kReadBoolean(
                    kGroupObject,
                    kEtwFilterJsonInvertKey,
                    false,
                    groupModel.invertMatch)
                || !kReadBoolean(
                    kGroupObject,
                    kEtwFilterJsonDetailVisibleOnlyKey,
                    false,
                    groupModel.detailVisibleColumnsOnly)
                || !kReadBoolean(
                    kGroupObject,
                    kEtwFilterJsonDetailAllFieldsKey,
                    true,
                    groupModel.detailMatchAllFields)
                || !kReadStringList(
                    kGroupObject,
                    kEtwFilterJsonProviderCategoriesKey,
                    groupModel.providerCategoryList)
                || !kNormalizeKnownStringList(
                    groupModel.providerCategoryList,
                    kKnownCategoryList))
            {
                return false;
            }

            const QJsonValue kModeValue =
                kGroupObject.value(QString::fromLatin1(kEtwFilterJsonStringModeKey));
            QString modeText = QStringLiteral("regex");
            if (!kModeValue.isUndefined())
            {
                if (!kModeValue.isString())
                {
                    return false;
                }
                modeText = kModeValue.toString().trimmed().toLower();
            }
            if (!kKnownStringModeList.contains(modeText, Qt::CaseInsensitive))
            {
                return false;
            }
            groupModel.stringMode = etwFilterStringModeFromText(modeText);

            const QJsonValue kFieldListValue =
                kGroupObject.value(QString::fromLatin1(kEtwFilterJsonFieldsKey));
            if (!kFieldListValue.isUndefined() && !kFieldListValue.isArray())
            {
                return false;
            }
            const QJsonArray kFieldArray = kFieldListValue.toArray();
            QStringList loadedFieldKeyList;
            groupModel.fieldList.reserve(static_cast<std::size_t>(kFieldArray.size()));
            for (const QJsonValue& fieldValue : kFieldArray)
            {
                if (!fieldValue.isObject())
                {
                    return false;
                }
                const QJsonObject kFieldObject = fieldValue.toObject();
                const QJsonValue kFieldKeyValue =
                    kFieldObject.value(QString::fromLatin1(kEtwFilterJsonFieldKey));
                const QJsonValue kFieldTextValue =
                    kFieldObject.value(QString::fromLatin1(kEtwFilterJsonFieldValue));
                if (!kFieldKeyValue.isString() || !kFieldTextValue.isString())
                {
                    return false;
                }

                const QString kFieldKey = kFieldKeyValue.toString().trimmed().toLower();
                const EtwFilterFieldDescriptor* descriptor =
                    findEtwFilterFieldDescriptorByKey(kFieldKey);
                if (descriptor == nullptr
                    || loadedFieldKeyList.contains(kFieldKey, Qt::CaseInsensitive))
                {
                    return false;
                }
                loadedFieldKeyList.push_back(kFieldKey);

                const QString kFieldText = kFieldTextValue.toString().trimmed();
                if (kFieldText.isEmpty())
                {
                    continue;
                }
                EtwFilterRuleFieldModel fieldModel;
                fieldModel.fieldId = descriptor->fieldId;
                fieldModel.fieldKey = QString::fromLatin1(descriptor->key);
                fieldModel.fieldLabel = QString::fromUtf8(descriptor->label);
                fieldModel.inputText = kFieldText;
                groupModel.fieldList.push_back(std::move(fieldModel));
            }
            groupModelListOut.push_back(std::move(groupModel));
        }
        return true;
    };

    if (!kParseGroupList(kEtwFilterJsonPreGroupsKey, candidateModel.preGroupList)
        || !kParseGroupList(kEtwFilterJsonPostGroupsKey, candidateModel.postGroupList))
    {
        return false;
    }

    filterModelOut = std::move(candidateModel);
    return true;
}
QJsonObject serializeEtwFilterConfigModel(
    const EtwFilterConfigModel& filterModel)
{
    const auto kSerializeSimpleFilter = [](const EtwSimpleFilterModel& simpleModel) {
        QJsonObject simpleObject;
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonEnabledKey),
            simpleModel.enabled);
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimplePidKey),
            simpleModel.pidText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleProcessNameKey),
            simpleModel.processNameText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleFilePathKey),
            simpleModel.filePathText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleEventIdKey),
            simpleModel.eventIdText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleEventNameKey),
            simpleModel.eventNameText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleRegistryPathKey),
            simpleModel.registryPathText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleNetworkAddressKey),
            simpleModel.networkAddressText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleNetworkPortKey),
            simpleModel.networkPortText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleStatusKey),
            simpleModel.statusText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleCustomProviderKey),
            simpleModel.customProviderText.trimmed());
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleCustomActionKey),
            simpleModel.customActionText.trimmed());

        QJsonArray providerArray;
        for (const QString& providerName : simpleModel.providerPresetNameList)
        {
            providerArray.append(providerName);
        }
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleProvidersKey),
            providerArray);

        QJsonArray actionArray;
        for (const QString& actionText : simpleModel.actionPresetList)
        {
            actionArray.append(actionText);
        }
        simpleObject.insert(
            QString::fromLatin1(kEtwFilterJsonSimpleActionsKey),
            actionArray);
        return simpleObject;
    };
    const auto kSerializeGroupList = [](
        const std::vector<EtwFilterRuleGroupModel>& groupModelList) {
        QJsonArray groupArray;
        for (const EtwFilterRuleGroupModel& groupModel : groupModelList)
        {
            QJsonObject groupObject;
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonEnabledKey),
                groupModel.enabled);
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonStringModeKey),
                etwFilterStringModeToText(groupModel.stringMode));
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonCaseSensitiveKey),
                groupModel.caseSensitive);
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonInvertKey),
                groupModel.invertMatch);
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonDetailVisibleOnlyKey),
                groupModel.detailVisibleColumnsOnly);
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonDetailAllFieldsKey),
                groupModel.detailMatchAllFields);

            QJsonArray categoryArray;
            for (const QString& categoryText : groupModel.providerCategoryList)
            {
                categoryArray.append(categoryText);
            }
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonProviderCategoriesKey),
                categoryArray);

            QJsonArray fieldArray;
            for (const EtwFilterRuleFieldModel& fieldModel : groupModel.fieldList)
            {
                const QString kInputText = fieldModel.inputText.trimmed();
                if (kInputText.isEmpty())
                {
                    continue;
                }
                QJsonObject fieldObject;
                fieldObject.insert(
                    QString::fromLatin1(kEtwFilterJsonFieldKey),
                    fieldModel.fieldKey);
                fieldObject.insert(
                    QString::fromLatin1(kEtwFilterJsonFieldValue),
                    kInputText);
                fieldArray.append(fieldObject);
            }
            groupObject.insert(
                QString::fromLatin1(kEtwFilterJsonFieldsKey),
                fieldArray);
            groupArray.append(groupObject);
        }
        return groupArray;
    };

    QJsonObject rootObject;
    rootObject.insert(QString::fromLatin1(kEtwFilterJsonVersionKey), 2);
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonSimplePreKey),
        kSerializeSimpleFilter(filterModel.preSimpleFilter));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonSimplePostKey),
        kSerializeSimpleFilter(filterModel.postSimpleFilter));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonPreGroupsKey),
        kSerializeGroupList(filterModel.preGroupList));
    rootObject.insert(
        QString::fromLatin1(kEtwFilterJsonPostGroupsKey),
        kSerializeGroupList(filterModel.postGroupList));
    return rootObject;
}
}
