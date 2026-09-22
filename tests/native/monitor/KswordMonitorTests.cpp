#include "../../../apps/desktop/monitor_dock/EtwFilterConfig.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <cstdio>
#include <stdexcept>

using namespace ksword::monitor;

namespace
{
void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

EtwFilterChoices choices()
{
    return { { { QStringLiteral("PreProvider") }, { QStringLiteral("Read") } },
             { { QStringLiteral("PostProvider") }, { QStringLiteral("Write") } } };
}

bool parse(const QByteArray& json, EtwFilterConfigModel& model)
{
    return parseEtwFilterConfigModel(json, choices(), model);
}

void testVersionsAndDefaults()
{
    EtwFilterConfigModel model;
    for (const auto* json : { "{}", R"({"version":1})", R"({"version":2})" })
    {
        require(parse(json, model), "legacy/current version rejected");
        require(model.preSimpleFilter.enabled && model.postSimpleFilter.enabled, "wrong default enabled state");
        require(model.preGroupList.empty() && model.postGroupList.empty(), "unexpected default groups");
    }
}

void testInvalidInputDoesNotCommit()
{
    EtwFilterConfigModel model;
    model.preSimpleFilter.pidText = QStringLiteral("42");
    model.postSimpleFilter.enabled = false;
    const auto kBefore = serializeEtwFilterConfigModel(model);
    for (const auto* json : {
        "", "[", "[]", "null", R"({"version":3})", R"({"version":1.5})", R"({"version":"2"})",
        R"({"simple_pre":{"enabled":1}})", R"({"simple_pre":{"pid":42}})",
        R"({"simple_pre":{"providers":"PreProvider"}})", R"({"simple_pre":{"providers":[2]}})",
        R"({"simple_pre":{"providers":["Unknown"]}})", R"({"simple_post":{"actions":["Unknown"]}})",
        R"({"pre_groups":{}})", R"({"pre_groups":[null]})", R"({"pre_groups":[{"fields":{}}]})",
        R"({"pre_groups":[{"provider_categories":["Unknown"]}]})",
        R"({"pre_groups":[{"string_mode":"Unknown"}]})",
        R"({"pre_groups":[{"fields":[{"key":"unknown","value":"x"}]}]})",
        R"({"pre_groups":[{"fields":[{"key":"provider_name","value":"x"},{"key":"PROVIDER_NAME","value":"y"}]}]})",
        R"({"simple_pre":{"pid":"99"},"post_groups":[{"fields":[{"key":"provider_name","value":1}]}]})"
    })
    {
        require(!parse(json, model), "invalid configuration accepted");
        require(serializeEtwFilterConfigModel(model) == kBefore, "failed parse partially committed");
    }
}

void testStageChoicesAndNormalization()
{
    EtwFilterConfigModel model;
    require(parse(R"({"simple_pre":{"pid":" 42 ","providers":["preprovider"],"actions":["read"]},
        "simple_post":{"providers":["POSTPROVIDER"],"actions":["WRITE"]}})", model), "known choices rejected");
    require(model.preSimpleFilter.pidText == QStringLiteral("42"), "text not trimmed");
    require(model.preSimpleFilter.providerPresetNameList == choices().pre.providers, "pre choices not canonicalized");
    require(model.postSimpleFilter.actionPresetList == choices().post.actions, "post choices not canonicalized");
    require(!parse(R"({"simple_pre":{"providers":["PostProvider"]}})", model), "pre used post catalog");
    require(!parse(R"({"simple_post":{"actions":["Read"]}})", model), "post used pre catalog");
}

void testAllFieldsRoundTrip()
{
    QJsonArray fields;
    for (const auto& descriptor : etwFilterFieldDescriptorList())
    {
        fields.append(QJsonObject{
            { QStringLiteral("key"), QString::fromLatin1(descriptor.key).toUpper() },
            { QStringLiteral("value"), QStringLiteral(" test ") }
        });
    }
    QJsonObject group{
        { QStringLiteral("fields"), fields },
        { QStringLiteral("provider_categories"), QJsonArray::fromStringList(etwFilterProviderCategoryList()) },
        { QStringLiteral("enabled"), false },
        { QStringLiteral("case_sensitive"), true },
        { QStringLiteral("invert"), true },
        { QStringLiteral("detail_visible_only"), true },
        { QStringLiteral("detail_all_fields"), false }
    };
    for (const auto* mode : { "regex", "exact", "contains", "prefix", "suffix" })
    {
        group.insert(QStringLiteral("string_mode"), QString::fromLatin1(mode));
        const QJsonObject kRoot{
            { QStringLiteral("pre_groups"), QJsonArray{ group } },
            { QStringLiteral("post_groups"), QJsonArray{ group } }
        };
        EtwFilterConfigModel model;
        require(parse(QJsonDocument(kRoot).toJson(), model), "all-field configuration rejected");
        require(model.preGroupList.size() == 1 && model.postGroupList.size() == 1, "groups lost");
        const auto& parsed = model.preGroupList.front();
        require(parsed.fieldList.size() == etwFilterFieldDescriptorList().size(), "fields lost");
        require(!parsed.enabled && parsed.caseSensitive && parsed.invertMatch
            && parsed.detailVisibleColumnsOnly && !parsed.detailMatchAllFields, "group options lost");
        require(etwFilterStringModeToText(parsed.stringMode) == QString::fromLatin1(mode), "string mode lost");
        for (std::size_t index = 0; index < parsed.fieldList.size(); ++index)
        {
            const auto& descriptor = etwFilterFieldDescriptorList()[index];
            const auto& field = parsed.fieldList[index];
            require(field.fieldId == descriptor.fieldId, "stable field ID changed");
            require(field.fieldKey == QString::fromLatin1(descriptor.key), "stable field key changed");
            require(field.inputText == QStringLiteral("test"), "field input not trimmed");
        }
        const auto kSerialized = serializeEtwFilterConfigModel(model);
        EtwFilterConfigModel restored;
        require(parse(QJsonDocument(kSerialized).toJson(), restored), "serialized model rejected");
        require(serializeEtwFilterConfigModel(restored) == kSerialized, "round trip changed configuration");
    }
}
}

int main()
{
    try
    {
        testVersionsAndDefaults();
        testInvalidInputDoesNotCommit();
        testStageChoicesAndNormalization();
        testAllFieldsRoundTrip();
        std::puts("PASS: ETW filter versions, atomic rejection, stage catalogs, and all-field round trips");
        return 0;
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
