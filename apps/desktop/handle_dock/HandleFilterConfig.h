#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>

#include <cstdint>

namespace ks::handle
{
    constexpr int kHandleFilterSchemaVersion = 1;

    enum class FilterEnumMode : int
    {
        kUserSnapshot = 0,
        kDuplicateHandle,
        kKernelHandleTable
    };

    enum class FilterDiffStatus : int
    {
        kAny = 0,
        kUserOnly,
        kKernelOnly,
        kBoth
    };

    struct HandleFilterGlobalSettings
    {
        FilterEnumMode enumMode = FilterEnumMode::kDuplicateHandle;
        bool resolveObjectName = true;
        int nameResolveBudget = 1000;
    };

    struct HandleFilterRule
    {
        QString id;
        QString name;
        bool enabled = true;
        QVector<std::uint32_t> processIds;
        QString keyword;
        QString typeName;
        FilterDiffStatus diffStatus = FilterDiffStatus::kAny;
        bool onlyNamed = false;
    };

    struct HandleFilterDocument
    {
        int schemaVersion = kHandleFilterSchemaVersion;
        QString exportedAtUtc;
        HandleFilterGlobalSettings globalSettings;
        QVector<HandleFilterRule> rules;
    };

    HandleFilterDocument createDefaultHandleFilterDocument();
    QString createHandleFilterRuleId();
    QString makeUniqueHandleFilterRuleName(
        const QString& requestedName,
        const QVector<HandleFilterRule>& existingRules,
        const QString& ignoredRuleId = QString());

    QByteArray serializeHandleFilterDocument(
        const HandleFilterDocument& document,
        QString* errorTextOut = nullptr);

    bool deserializeHandleFilterDocument(
        const QByteArray& jsonBytes,
        HandleFilterDocument* documentOut,
        QStringList* warningListOut = nullptr,
        QString* errorTextOut = nullptr);
}
