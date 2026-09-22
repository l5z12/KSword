#include "HandleFilterConfig.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QUuid>

#include <limits>

namespace
{
    QString enumModeToText(const ks::handle::FilterEnumMode mode)
    {
        switch (mode)
        {
        case ks::handle::FilterEnumMode::kUserSnapshot:
            return QStringLiteral("user_snapshot");
        case ks::handle::FilterEnumMode::kKernelHandleTable:
            return QStringLiteral("kernel_handle_table");
        case ks::handle::FilterEnumMode::kDuplicateHandle:
        default:
            return QStringLiteral("duplicate_handle");
        }
    }

    bool enumModeFromText(
        const QString& sourceText,
        ks::handle::FilterEnumMode* modeOut)
    {
        if (modeOut == nullptr)
        {
            return false;
        }
        const QString kNormalizedText = sourceText.trimmed().toLower();
        if (kNormalizedText == QStringLiteral("user_snapshot"))
        {
            *modeOut = ks::handle::FilterEnumMode::kUserSnapshot;
            return true;
        }
        if (kNormalizedText == QStringLiteral("duplicate_handle"))
        {
            *modeOut = ks::handle::FilterEnumMode::kDuplicateHandle;
            return true;
        }
        if (kNormalizedText == QStringLiteral("kernel_handle_table"))
        {
            *modeOut = ks::handle::FilterEnumMode::kKernelHandleTable;
            return true;
        }
        return false;
    }

    QString diffStatusToText(const ks::handle::FilterDiffStatus status)
    {
        switch (status)
        {
        case ks::handle::FilterDiffStatus::kUserOnly:
            return QStringLiteral("user_only");
        case ks::handle::FilterDiffStatus::kKernelOnly:
            return QStringLiteral("kernel_only");
        case ks::handle::FilterDiffStatus::kBoth:
            return QStringLiteral("both");
        case ks::handle::FilterDiffStatus::kAny:
        default:
            return QStringLiteral("any");
        }
    }

    bool diffStatusFromText(
        const QString& sourceText,
        ks::handle::FilterDiffStatus* statusOut)
    {
        if (statusOut == nullptr)
        {
            return false;
        }
        const QString kNormalizedText = sourceText.trimmed().toLower();
        if (kNormalizedText == QStringLiteral("any"))
        {
            *statusOut = ks::handle::FilterDiffStatus::kAny;
            return true;
        }
        if (kNormalizedText == QStringLiteral("user_only"))
        {
            *statusOut = ks::handle::FilterDiffStatus::kUserOnly;
            return true;
        }
        if (kNormalizedText == QStringLiteral("kernel_only"))
        {
            *statusOut = ks::handle::FilterDiffStatus::kKernelOnly;
            return true;
        }
        if (kNormalizedText == QStringLiteral("both"))
        {
            *statusOut = ks::handle::FilterDiffStatus::kBoth;
            return true;
        }
        return false;
    }

    QJsonObject buildRuleObject(const ks::handle::HandleFilterRule& rule)
    {
        QJsonObject ruleObject;
        ruleObject.insert(QStringLiteral("id"), rule.id);
        ruleObject.insert(QStringLiteral("name"), rule.name);
        ruleObject.insert(QStringLiteral("enabled"), rule.enabled);

        QJsonArray processIdArray;
        for (const std::uint32_t kProcessId : rule.processIds)
        {
            processIdArray.push_back(static_cast<qint64>(kProcessId));
        }
        ruleObject.insert(QStringLiteral("processIds"), processIdArray);
        ruleObject.insert(QStringLiteral("keyword"), rule.keyword);
        ruleObject.insert(QStringLiteral("typeName"), rule.typeName);
        ruleObject.insert(QStringLiteral("diffStatus"), diffStatusToText(rule.diffStatus));
        ruleObject.insert(QStringLiteral("onlyNamed"), rule.onlyNamed);
        return ruleObject;
    }
}

namespace ks::handle
{
    QString createHandleFilterRuleId()
    {
        return QUuid::createUuid().toString(QUuid::WithoutBraces);
    }

    QString makeUniqueHandleFilterRuleName(
        const QString& requestedName,
        const QVector<HandleFilterRule>& existingRules,
        const QString& ignoredRuleId)
    {
        const QString kBaseName = requestedName.trimmed().isEmpty()
            ? QStringLiteral("规则")
            : requestedName.trimmed();
        auto nameExists = [&existingRules, &ignoredRuleId](const QString& candidateName)
        {
            for (const HandleFilterRule& rule : existingRules)
            {
                if (!ignoredRuleId.isEmpty() && rule.id == ignoredRuleId)
                {
                    continue;
                }
                if (rule.name.compare(candidateName, Qt::CaseInsensitive) == 0)
                {
                    return true;
                }
            }
            return false;
        };

        if (!nameExists(kBaseName))
        {
            return kBaseName;
        }
        for (int suffixIndex = 1; suffixIndex < 100000; ++suffixIndex)
        {
            const QString kCandidateName = QStringLiteral("%1（导入 %2）")
                .arg(kBaseName)
                .arg(suffixIndex);
            if (!nameExists(kCandidateName))
            {
                return kCandidateName;
            }
        }
        return kBaseName + QStringLiteral("（导入）");
    }

    HandleFilterDocument createDefaultHandleFilterDocument()
    {
        HandleFilterDocument document;
        HandleFilterRule defaultRule;
        defaultRule.id = createHandleFilterRuleId();
        defaultRule.name = QStringLiteral("全部句柄");
        document.rules.push_back(defaultRule);
        return document;
    }

    QByteArray serializeHandleFilterDocument(
        const HandleFilterDocument& document,
        QString* errorTextOut)
    {
        if (document.schemaVersion != kHandleFilterSchemaVersion)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("不支持的筛选器配置版本：%1")
                    .arg(document.schemaVersion);
            }
            return {};
        }

        QJsonObject rootObject;
        rootObject.insert(QStringLiteral("schemaVersion"), document.schemaVersion);
        rootObject.insert(
            QStringLiteral("exportedAtUtc"),
            document.exportedAtUtc.trimmed().isEmpty()
                ? QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)
                : document.exportedAtUtc);

        QJsonObject globalSettingsObject;
        globalSettingsObject.insert(
            QStringLiteral("enumMode"),
            enumModeToText(document.globalSettings.enumMode));
        globalSettingsObject.insert(
            QStringLiteral("resolveObjectName"),
            document.globalSettings.resolveObjectName);
        globalSettingsObject.insert(
            QStringLiteral("nameResolveBudget"),
            document.globalSettings.nameResolveBudget);
        rootObject.insert(QStringLiteral("globalSettings"), globalSettingsObject);

        QJsonArray ruleArray;
        for (const HandleFilterRule& rule : document.rules)
        {
            ruleArray.push_back(buildRuleObject(rule));
        }
        rootObject.insert(QStringLiteral("rules"), ruleArray);
        return QJsonDocument(rootObject).toJson(QJsonDocument::Indented);
    }

    bool deserializeHandleFilterDocument(
        const QByteArray& jsonBytes,
        HandleFilterDocument* documentOut,
        QStringList* warningListOut,
        QString* errorTextOut)
    {
        if (documentOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置输出对象为空。");
            }
            return false;
        }

        QJsonParseError parseError;
        const QJsonDocument kJsonDocument = QJsonDocument::fromJson(jsonBytes, &parseError);
        if (parseError.error != QJsonParseError::NoError || !kJsonDocument.isObject())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("JSON 解析失败：%1").arg(parseError.errorString());
            }
            return false;
        }

        const QJsonObject kRootObject = kJsonDocument.object();
        const QJsonValue kSchemaVersionValue = kRootObject.value(QStringLiteral("schemaVersion"));
        if (!kSchemaVersionValue.isDouble())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置版本 %1 与当前版本 %2 不兼容。")
                    .arg(0)
                    .arg(kHandleFilterSchemaVersion);
            }
            return false;
        }
        const int kSchemaVersion = kSchemaVersionValue.toInt(0);
        if (kSchemaVersionValue.toDouble() != static_cast<double>(kSchemaVersion))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置格式无效。");
            }
            return false;
        }
        if (kSchemaVersion != kHandleFilterSchemaVersion)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置版本 %1 与当前版本 %2 不兼容。")
                    .arg(kSchemaVersion)
                    .arg(kHandleFilterSchemaVersion);
            }
            return false;
        }
        if (!kRootObject.value(QStringLiteral("globalSettings")).isObject()
            || !kRootObject.value(QStringLiteral("rules")).isArray())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置缺少 globalSettings 或 rules。");
            }
            return false;
        }

        HandleFilterDocument parsedDocument;
        parsedDocument.schemaVersion = kSchemaVersion;
        const QJsonValue kExportedAtValue = kRootObject.value(QStringLiteral("exportedAtUtc"));
        QDateTime exportedAtUtc;
        if (kExportedAtValue.isString())
        {
            exportedAtUtc = QDateTime::fromString(kExportedAtValue.toString(), Qt::ISODateWithMs);
            if (!exportedAtUtc.isValid())
            {
                exportedAtUtc = QDateTime::fromString(kExportedAtValue.toString(), Qt::ISODate);
            }
        }
        if (!exportedAtUtc.isValid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("筛选器配置格式无效。");
            }
            return false;
        }
        parsedDocument.exportedAtUtc = kExportedAtValue.toString();

        const QJsonObject kGlobalSettingsObject =
            kRootObject.value(QStringLiteral("globalSettings")).toObject();
        const QJsonValue kEnumModeValue = kGlobalSettingsObject.value(QStringLiteral("enumMode"));
        FilterEnumMode enumMode = FilterEnumMode::kDuplicateHandle;
        if (!kEnumModeValue.isString() || !enumModeFromText(kEnumModeValue.toString(), &enumMode))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("globalSettings.enumMode 无效。");
            }
            return false;
        }
        parsedDocument.globalSettings.enumMode = enumMode;
        const QJsonValue kResolveNameValue =
            kGlobalSettingsObject.value(QStringLiteral("resolveObjectName"));
        const QJsonValue kNameBudgetValue =
            kGlobalSettingsObject.value(QStringLiteral("nameResolveBudget"));
        if (!kResolveNameValue.isBool() || !kNameBudgetValue.isDouble())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("对象名解析预算必须位于 0 到 10000 之间。");
            }
            return false;
        }
        const qint64 kParsedNameBudget = kNameBudgetValue.toInteger(-1);
        if (kNameBudgetValue.toDouble() != static_cast<double>(kParsedNameBudget))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("对象名解析预算必须位于 0 到 10000 之间。");
            }
            return false;
        }
        parsedDocument.globalSettings.resolveObjectName = kResolveNameValue.toBool();
        parsedDocument.globalSettings.nameResolveBudget = static_cast<int>(kParsedNameBudget);
        if (parsedDocument.globalSettings.nameResolveBudget < 0
            || parsedDocument.globalSettings.nameResolveBudget > 10000)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("对象名解析预算必须位于 0 到 10000 之间。");
            }
            return false;
        }

        const QJsonArray kRuleArray = kRootObject.value(QStringLiteral("rules")).toArray();
        QSet<QString> usedIds;
        for (qsizetype ruleIndex = 0; ruleIndex < kRuleArray.size(); ++ruleIndex)
        {
            if (!kRuleArray.at(ruleIndex).isObject())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("第 %1 条规则格式无效。")
                        .arg(ruleIndex + 1);
                }
                return false;
            }
            const QJsonObject kRuleObject = kRuleArray.at(ruleIndex).toObject();
            HandleFilterRule rule;
            const QJsonValue kIdValue = kRuleObject.value(QStringLiteral("id"));
            const QJsonValue kNameValue = kRuleObject.value(QStringLiteral("name"));
            const QJsonValue kEnabledValue = kRuleObject.value(QStringLiteral("enabled"));
            const QJsonValue kKeywordValue = kRuleObject.value(QStringLiteral("keyword"));
            const QJsonValue kTypeNameValue = kRuleObject.value(QStringLiteral("typeName"));
            const QJsonValue kDiffStatusValue = kRuleObject.value(QStringLiteral("diffStatus"));
            const QJsonValue kOnlyNamedValue = kRuleObject.value(QStringLiteral("onlyNamed"));
            if (!kIdValue.isString()
                || !kNameValue.isString()
                || !kEnabledValue.isBool()
                || !kKeywordValue.isString()
                || !kTypeNameValue.isString()
                || !kDiffStatusValue.isString()
                || !kOnlyNamedValue.isBool())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("第 %1 条规则格式无效。")
                        .arg(ruleIndex + 1);
                }
                return false;
            }
            rule.id = kIdValue.toString().trimmed();
            const QUuid kParsedId(rule.id);
            if (rule.id.isEmpty() || kParsedId.isNull() || usedIds.contains(rule.id))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("第 %1 条规则的 ID 无效或重复。")
                        .arg(ruleIndex + 1);
                }
                return false;
            }
            usedIds.insert(rule.id);

            const QString kRequestedName = kNameValue.toString().trimmed();
            if (kRequestedName.isEmpty())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("第 %1 条规则格式无效。")
                        .arg(ruleIndex + 1);
                }
                return false;
            }
            rule.name = makeUniqueHandleFilterRuleName(
                kRequestedName,
                parsedDocument.rules);
            if (rule.name != kRequestedName.trimmed() && warningListOut != nullptr)
            {
                warningListOut->push_back(
                    QStringLiteral("规则名称“%1”已调整为“%2”。")
                    .arg(kRequestedName, rule.name));
            }
            rule.enabled = kEnabledValue.toBool();
            rule.keyword = kKeywordValue.toString().trimmed();
            rule.typeName = kTypeNameValue.toString().trimmed();
            rule.onlyNamed = kOnlyNamedValue.toBool();

            FilterDiffStatus diffStatus = FilterDiffStatus::kAny;
            if (!diffStatusFromText(
                kDiffStatusValue.toString(),
                &diffStatus))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("规则“%1”的 diffStatus 无效。").arg(rule.name);
                }
                return false;
            }
            rule.diffStatus = diffStatus;

            if (!kRuleObject.value(QStringLiteral("processIds")).isArray())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("规则“%1”的 processIds 无效。").arg(rule.name);
                }
                return false;
            }
            QSet<std::uint32_t> seenProcessIds;
            const QJsonArray kProcessIdArray = kRuleObject.value(QStringLiteral("processIds")).toArray();
            for (const QJsonValue& processIdValue : kProcessIdArray)
            {
                if (!processIdValue.isDouble())
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("规则“%1”包含无效 PID。").arg(rule.name);
                    }
                    return false;
                }
                const qint64 kProcessId = processIdValue.toInteger(-1);
                if (processIdValue.toDouble() != static_cast<double>(kProcessId)
                    || kProcessId <= 0
                    || kProcessId > static_cast<qint64>(std::numeric_limits<std::uint32_t>::max()))
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("规则“%1”包含无效 PID。").arg(rule.name);
                    }
                    return false;
                }
                const std::uint32_t kNormalizedProcessId = static_cast<std::uint32_t>(kProcessId);
                if (!seenProcessIds.contains(kNormalizedProcessId))
                {
                    seenProcessIds.insert(kNormalizedProcessId);
                    rule.processIds.push_back(kNormalizedProcessId);
                }
            }
            parsedDocument.rules.push_back(std::move(rule));
        }

        *documentOut = std::move(parsedDocument);
        return true;
    }
}
