#pragma once

#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <vector>

namespace ksword::monitor
{
enum class EtwFilterStage : int
{
    kPre = 0,
    kPost = 1
};

enum class EtwStringMatchMode : int
{
    kRegex = 0,
    kExact = 1,
    kContains = 2,
    kPrefix = 3,
    kSuffix = 4
};

enum class EtwFilterFieldType : int
{
    kText = 0,
    kNumber = 1,
    kNumberOrText = 2,
    kIp = 3,
    kPort = 4,
    kTimeRange = 5
};

enum class EtwFilterFieldId : int
{
    kProviderName = 0,
    kProviderGuid,
    kProviderCategory,
    kEventId,
    kEventName,
    kTask,
    kOpcode,
    kLevel,
    kKeywordMask,
    kHeaderPid,
    kHeaderTid,
    kActivityId,
    kTimestampRange,
    kResourceType,
    kAction,
    kTarget,
    kStatus,
    kDetailKeyword,
    kTargetPid,
    kParentPid,
    kTargetTid,
    kProcessName,
    kImagePath,
    kCommandLine,
    kFilePath,
    kFileOldPath,
    kFileNewPath,
    kFileOperation,
    kFileStatusCode,
    kFileAccessMask,
    kRegistryKeyPath,
    kRegistryValueName,
    kRegistryHive,
    kRegistryOperation,
    kRegistryStatus,
    kSourceIp,
    kSourcePort,
    kDestinationIp,
    kDestinationPort,
    kProtocol,
    kDirection,
    kDomain,
    kHost,
    kAuditResult,
    kUserText,
    kSidText,
    kSecurityPid,
    kSecurityTid,
    kSecurityLevel,
    kScriptHostProcess,
    kScriptKeyword,
    kScriptTaskName,
    kWmiClassName,
    kWmiNamespace
};

struct EtwSimpleFilterModel
{
    bool enabled = true;                         // enabled: Whether to enable the simple filter for this stage.
    QString pidText;                             // pidText: PID single value or range list.
    QString processNameText;                     // processNameText: Process name inclusion condition.
    QString filePathText;                        // filePathText: File path inclusion condition.
    QString eventIdText;                         // eventIdText: Single event ID or range list.
    QString eventNameText;                       // eventNameText: Event name inclusion condition.
    QString registryPathText;                    // registryPathText: Registry path containing conditions.
    QString networkAddressText;                  // networkAddressText: IPv4, CIDR, or address range.
    QString networkPortText;                     // networkPortText: Single network port value or range.
    QString statusText;                          // statusText: status text includes conditions.
    QString customProviderText;                  // customProviderText: custom Provider name or GUID.
    QString customActionText;                    // customActionText: Custom action text.
    QStringList providerPresetNameList;          // providerPresetNameList: Selected Provider presets.
    QStringList actionPresetList;                // actionPresetList: selected action presets.
};

struct EtwFilterRuleFieldModel
{
    EtwFilterFieldId fieldId = EtwFilterFieldId::kProviderName; // fieldId: runtime field enumeration.
    QString fieldKey;                           // fieldKey: Stable field key in the configuration file.
    QString fieldLabel;                         // fieldLabel: Field name used in compilation errors.
    QString inputText;                          // inputText: Original rule text entered by the user.
};

struct EtwFilterRuleGroupModel
{
    int groupId = 0;                            // groupId: Rule group identifier within this model.
    bool enabled = true;                        // enabled: Whether the current rule group is enabled.
    EtwStringMatchMode stringMode = EtwStringMatchMode::kRegex; // stringMode: String matching mode.
    bool caseSensitive = false;                 // caseSensitive: Whether the string comparison is case-sensitive.
    bool invertMatch = false;                   // invertMatch: Whether to reverse-match rule groups.
    bool detailVisibleColumnsOnly = false;      // detailVisibleColumnsOnly: Whether Detail matches only visible columns.
    bool detailMatchAllFields = true;           // detailMatchAllFields: Whether details match all fields.
    QStringList providerCategoryList;           // providerCategoryList: Selected Provider categories.
    std::vector<EtwFilterRuleFieldModel> fieldList; // fieldList: non-empty field rule list.
};

struct EtwFilterConfigModel
{
    EtwSimpleFilterModel preSimpleFilter;        // preSimpleFilter: Pre-filter simple filter model.
    EtwSimpleFilterModel postSimpleFilter;       // postSimpleFilter: Post-simple filter model.
    std::vector<EtwFilterRuleGroupModel> preGroupList;  // preGroupList: Pre-configuration detailed rules.
    std::vector<EtwFilterRuleGroupModel> postGroupList; // postGroupList: Post-processing detailed rules.
};

struct EtwFilterFieldDescriptor
{
    EtwFilterFieldId fieldId = EtwFilterFieldId::kProviderName;
    const char* key = "";
    const char* label = "";
    const char* placeholder = "";
    EtwFilterFieldType fieldType = EtwFilterFieldType::kText;
    bool requiresDecodedPayload = false;
};

QStringList etwFilterProviderCategoryList();

const std::vector<EtwFilterFieldDescriptor>& etwFilterFieldDescriptorList();

const EtwFilterFieldDescriptor* findEtwFilterFieldDescriptorByKey(const QString& keyText);

QString etwFilterStringModeToText(const EtwStringMatchMode mode);

EtwStringMatchMode etwFilterStringModeFromText(const QString& modeText);

// Immutable choices captured by the UI before parsing. The parser never reads
// widgets, changes a running capture, or partially commits an invalid model.
struct EtwSimpleFilterChoices
{
    QStringList providers;
    QStringList actions;
};

struct EtwFilterChoices
{
    EtwSimpleFilterChoices pre;
    EtwSimpleFilterChoices post;
};

bool parseEtwFilterConfigModel(
    const QByteArray& jsonData,
    const EtwFilterChoices& choices,
    EtwFilterConfigModel& filterModelOut);

QJsonObject serializeEtwFilterConfigModel(
    const EtwFilterConfigModel& filterModel);
}
