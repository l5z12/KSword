#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    // etwPropertyValueMeaningful：
    // - Purpose: Filter empty values or placeholder values to avoid misjudgment during semantic extraction.
    bool etwPropertyValueMeaningful(const QString& valueText)
    {
        const QString kTrimmed = valueText.trimmed();
        if (kTrimmed.isEmpty())
        {
            return false;
        }
        return !kTrimmed.startsWith('<');
    }

    // findFirstEtwProperty：
    // - Purpose: Find the first valid property value based on the candidate property name list.
    // - Usage: Extracts common semantics such as target path, status code, and port.
    const EtwDecodedPropertyEntry* findFirstEtwProperty(
        const std::vector<EtwDecodedPropertyEntry>& propertyList,
        const QStringList& normalizedNameList)
    {
        for (const QString& normalizedName : normalizedNameList)
        {
            for (const EtwDecodedPropertyEntry& property : propertyList)
            {
                if (property.normalizedNameText == normalizedName
                    && etwPropertyValueMeaningful(property.valueText))
                {
                    return &property;
                }
            }
        }
        return nullptr;
    }

    // inferEtwResourceType：
    // - Purpose: Infers the resource category based on the Provider and event name;
    // - Called: Writes to JSON semantic.resourceType.
    QString inferEtwResourceType(const QString& providerNameText, const QString& eventNameText)
    {
        const QString kProviderLower = providerNameText.toLower();
        const QString kEventLower = eventNameText.toLower();

        if (kProviderLower.contains(QStringLiteral("registry")) || kEventLower.contains(QStringLiteral("reg")))
        {
            return QStringLiteral("注册表");
        }
        if (kProviderLower.contains(QStringLiteral("file")) || kProviderLower.contains(QStringLiteral("ntfs"))
            || kEventLower.contains(QStringLiteral("file")) || kEventLower.contains(QStringLiteral("createfile")))
        {
            return QStringLiteral("文件");
        }
        if (kProviderLower.contains(QStringLiteral("tcp")) || kProviderLower.contains(QStringLiteral("udp"))
            || kProviderLower.contains(QStringLiteral("network")) || kProviderLower.contains(QStringLiteral("winsock"))
            || kEventLower.contains(QStringLiteral("connect")) || kEventLower.contains(QStringLiteral("send"))
            || kEventLower.contains(QStringLiteral("recv")))
        {
            return QStringLiteral("网络");
        }
        if (kProviderLower.contains(QStringLiteral("process")) || kProviderLower.contains(QStringLiteral("thread"))
            || kEventLower.contains(QStringLiteral("process")) || kEventLower.contains(QStringLiteral("thread")))
        {
            return QStringLiteral("进程线程");
        }
        return QStringLiteral("通用");
    }

    // inferEtwActionText：
    // - Purpose: Extract action semantics based on the event name and opcode name.
    // - Call: Write to JSON semantic.action.
    QString inferEtwActionText(const QString& eventNameText, const QString& opcodeNameText)
    {
        const QString kActionProbe = (eventNameText + QLatin1Char(' ') + opcodeNameText).toLower();

        if (kActionProbe.contains(QStringLiteral("create")) || kActionProbe.contains(QStringLiteral("start")))
        {
            return QStringLiteral("创建/启动");
        }
        if (kActionProbe.contains(QStringLiteral("open")))
        {
            return QStringLiteral("打开");
        }
        if (kActionProbe.contains(QStringLiteral("close")) || kActionProbe.contains(QStringLiteral("cleanup")))
        {
            return QStringLiteral("关闭");
        }
        if (kActionProbe.contains(QStringLiteral("read")) || kActionProbe.contains(QStringLiteral("query")))
        {
            return QStringLiteral("读取/查询");
        }
        if (kActionProbe.contains(QStringLiteral("write")) || kActionProbe.contains(QStringLiteral("set")))
        {
            return QStringLiteral("写入/设置");
        }
        if (kActionProbe.contains(QStringLiteral("delete")) || kActionProbe.contains(QStringLiteral("remove")))
        {
            return QStringLiteral("删除");
        }
        if (kActionProbe.contains(QStringLiteral("rename")))
        {
            return QStringLiteral("重命名");
        }
        if (kActionProbe.contains(QStringLiteral("connect")))
        {
            return QStringLiteral("连接");
        }
        if (kActionProbe.contains(QStringLiteral("send")))
        {
            return QStringLiteral("发送");
        }
        if (kActionProbe.contains(QStringLiteral("recv")) || kActionProbe.contains(QStringLiteral("receive")))
        {
            return QStringLiteral("接收");
        }
        if (!eventNameText.trimmed().isEmpty())
        {
            return eventNameText.trimmed();
        }
        if (!opcodeNameText.trimmed().isEmpty())
        {
            return opcodeNameText.trimmed();
        }
        return QStringLiteral("未知动作");
    }

    // etwIpv4TextFromNumeric：
    // - Purpose: Display the 32-bit address value as an IPv4 text string.
    // - Call: Network event destination endpoint concatenation.
    QString etwIpv4TextFromNumeric(const std::uint32_t addressValue)
    {
        const std::uint8_t kByte1 = static_cast<std::uint8_t>((addressValue >> 0) & 0xFF);
        const std::uint8_t kByte2 = static_cast<std::uint8_t>((addressValue >> 8) & 0xFF);
        const std::uint8_t kByte3 = static_cast<std::uint8_t>((addressValue >> 16) & 0xFF);
        const std::uint8_t kByte4 = static_cast<std::uint8_t>((addressValue >> 24) & 0xFF);
        return QStringLiteral("%1.%2.%3.%4").arg(kByte1).arg(kByte2).arg(kByte3).arg(kByte4);
    }

    // etwToSingleLine：
    // - Purpose: Collapse multi-line text into a single line for table summary display.
    QString etwToSingleLine(const QString& valueText)
    {
        QString normalizedText = valueText;
        normalizedText.replace(QChar(u'\r'), QChar(u' '));
        normalizedText.replace(QChar(u'\n'), QChar(u' '));
        return normalizedText.simplified();
    }

    // appendEtwStatusSummary：
    // - Purpose: Append status text to the end of the summary as needed.
    QString appendEtwStatusSummary(const QString& summaryText, const QString& statusText)
    {
        const QString kNormalizedStatusText = etwToSingleLine(statusText);
        if (kNormalizedStatusText.isEmpty())
        {
            return summaryText;
        }
        return QStringLiteral("%1 | 状态=%2").arg(summaryText, kNormalizedStatusText);
    }

    // inferEtwSemanticSummary：
    // - Purpose: Aggregate target objects and states for common scenarios such as files, registry, and network.
    // - Call: Serves as the semantic summary block for the ETW details JSON.
    EtwSemanticSummary inferEtwSemanticSummary(
        const QString& providerNameText,
        const QString& eventNameText,
        const QString& opcodeNameText,
        const std::vector<EtwDecodedPropertyEntry>& propertyList)
    {
        EtwSemanticSummary summary;
        summary.resourceTypeText = inferEtwResourceType(providerNameText, eventNameText);
        summary.actionText = inferEtwActionText(eventNameText, opcodeNameText);

        const EtwDecodedPropertyEntry* filePathProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("filename"), QStringLiteral("filepath"), QStringLiteral("targetfilename"),
            QStringLiteral("newfilename"), QStringLiteral("oldfilename"), QStringLiteral("pathname"),
            QStringLiteral("targetname"), QStringLiteral("relativefilename"), QStringLiteral("fileobject") });
        const EtwDecodedPropertyEntry* oldFileProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("oldfilename") });
        const EtwDecodedPropertyEntry* newFileProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("newfilename"), QStringLiteral("targetfilename") });
        const EtwDecodedPropertyEntry* regKeyProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("keyname"), QStringLiteral("keypath"), QStringLiteral("hive"),
            QStringLiteral("objectname"), QStringLiteral("path") });
        const EtwDecodedPropertyEntry* regValueProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("valuename") });
        const EtwDecodedPropertyEntry* imageProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("imagename"), QStringLiteral("imagefilename"), QStringLiteral("commandline") });
        const EtwDecodedPropertyEntry* sourceAddressProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("saddr"), QStringLiteral("sourceaddress"), QStringLiteral("srcaddr") });
        const EtwDecodedPropertyEntry* targetAddressProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("daddr"), QStringLiteral("destaddress"), QStringLiteral("dstaddr") });
        const EtwDecodedPropertyEntry* sourcePortProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("sport"), QStringLiteral("sourceport"), QStringLiteral("srcport") });
        const EtwDecodedPropertyEntry* targetPortProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("dport"), QStringLiteral("destport"), QStringLiteral("dstport") });
        const EtwDecodedPropertyEntry* operationProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("operation"), QStringLiteral("opcode") });

        if (summary.actionText == QStringLiteral("未知动作")
            && operationProperty != nullptr
            && !operationProperty->valueText.trimmed().isEmpty())
        {
            summary.actionText = operationProperty->valueText.trimmed();
        }

        if (summary.resourceTypeText == QStringLiteral("文件") && filePathProperty != nullptr)
        {
            if (summary.actionText.contains(QStringLiteral("重命名"))
                && oldFileProperty != nullptr
                && newFileProperty != nullptr)
            {
                summary.targetText = QStringLiteral("%1 -> %2")
                    .arg(oldFileProperty->valueText, newFileProperty->valueText);
            }
            else
            {
                summary.targetText = filePathProperty->valueText;
            }
        }
        else if (summary.resourceTypeText == QStringLiteral("注册表") && regKeyProperty != nullptr)
        {
            summary.targetText = regKeyProperty->valueText;
            if (regValueProperty != nullptr && !regValueProperty->valueText.isEmpty())
            {
                summary.targetText += QStringLiteral("\\") + regValueProperty->valueText;
            }
        }
        else if (summary.resourceTypeText == QStringLiteral("进程线程") && imageProperty != nullptr)
        {
            summary.targetText = imageProperty->valueText;
        }
        else if (summary.resourceTypeText == QStringLiteral("网络"))
        {
            QString sourceAddressText;
            QString targetAddressText;
            if (sourceAddressProperty != nullptr)
            {
                if (sourceAddressProperty->numericAvailable)
                {
                    sourceAddressText = etwIpv4TextFromNumeric(
                        static_cast<std::uint32_t>(sourceAddressProperty->numericValue));
                }
                else
                {
                    sourceAddressText = sourceAddressProperty->valueText;
                }
            }
            if (targetAddressProperty != nullptr)
            {
                if (targetAddressProperty->numericAvailable)
                {
                    targetAddressText = etwIpv4TextFromNumeric(
                        static_cast<std::uint32_t>(targetAddressProperty->numericValue));
                }
                else
                {
                    targetAddressText = targetAddressProperty->valueText;
                }
            }

            const QString kSourcePortText = sourcePortProperty != nullptr
                ? sourcePortProperty->valueText
                : QString();
            const QString kTargetPortText = targetPortProperty != nullptr
                ? targetPortProperty->valueText
                : QString();

            if (!sourceAddressText.isEmpty() || !targetAddressText.isEmpty())
            {
                const QString kSourceEndpointText = kSourcePortText.isEmpty()
                    ? sourceAddressText
                    : QStringLiteral("%1:%2").arg(sourceAddressText, kSourcePortText);
                const QString kTargetEndpointText = kTargetPortText.isEmpty()
                    ? targetAddressText
                    : QStringLiteral("%1:%2").arg(targetAddressText, kTargetPortText);
                if (!kSourceEndpointText.isEmpty() && !kTargetEndpointText.isEmpty())
                {
                    summary.targetText = QStringLiteral("%1 -> %2")
                        .arg(kSourceEndpointText, kTargetEndpointText);
                }
                else if (!kTargetEndpointText.isEmpty())
                {
                    summary.targetText = kTargetEndpointText;
                }
                else
                {
                    summary.targetText = kSourceEndpointText;
                }
            }
        }
        else
        {
            const EtwDecodedPropertyEntry* genericTarget = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("objectname"), QStringLiteral("path"), QStringLiteral("targetname"),
                QStringLiteral("filename"), QStringLiteral("keyname"), QStringLiteral("keypath"),
                QStringLiteral("imagename"), QStringLiteral("pathname") });
            if (genericTarget != nullptr)
            {
                summary.targetText = genericTarget->valueText;
            }
        }

        const EtwDecodedPropertyEntry* statusProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("status"), QStringLiteral("ntstatus"), QStringLiteral("result"),
            QStringLiteral("hresult"), QStringLiteral("errorcode"), QStringLiteral("error"),
            QStringLiteral("win32error"), QStringLiteral("win32status") });
        if (statusProperty != nullptr)
        {
            if (statusProperty->numericAvailable)
            {
                const std::uint64_t kStatusValue = statusProperty->numericValue;
                summary.statusText = kStatusValue == 0
                    ? QStringLiteral("成功")
                    : QStringLiteral("0x%1").arg(static_cast<qulonglong>(kStatusValue), 8, 16, QChar(u'0')).toUpper();
            }
            else
            {
                summary.statusText = statusProperty->valueText;
            }
        }
        return summary;
    }

    // buildEtwSummaryText：
    // - Purpose: Generate a single-line key summary for the ETW table; handle common types with special cases.
    QString buildEtwSummaryText(
        const QString& providerNameText,
        const QString& eventNameText,
        const QString& opcodeNameText,
        const std::uint32_t pidValue,
        const std::uint32_t tidValue,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList)
    {
        const QString kResourceTypeText = etwToSingleLine(semanticSummary.resourceTypeText);
        QString actionText = etwToSingleLine(semanticSummary.actionText);
        QString targetText = etwToSingleLine(semanticSummary.targetText);
        const QString kStatusText = etwToSingleLine(semanticSummary.statusText);

        if (actionText.isEmpty())
        {
            actionText = etwToSingleLine(eventNameText);
        }
        if (actionText.isEmpty())
        {
            actionText = etwToSingleLine(opcodeNameText);
        }
        if (actionText.isEmpty())
        {
            actionText = QStringLiteral("事件");
        }

        const QString kProbeText = (providerNameText + QLatin1Char(' ') + eventNameText + QLatin1Char(' ') + opcodeNameText).toLower();
        const bool kIsThreadEvent = kProbeText.contains(QStringLiteral("thread"));

        if (kResourceTypeText == QStringLiteral("文件"))
        {
            if (targetText.isEmpty())
            {
                const EtwDecodedPropertyEntry* filePathProperty = findFirstEtwProperty(
                    propertyList,
                    QStringList{ QStringLiteral("filename"), QStringLiteral("filepath"),
                    QStringLiteral("targetfilename"), QStringLiteral("newfilename"),
                    QStringLiteral("oldfilename"), QStringLiteral("pathname"),
                    QStringLiteral("targetname"), QStringLiteral("relativefilename") });
                if (filePathProperty != nullptr)
                {
                    targetText = etwToSingleLine(filePathProperty->valueText);
                }
            }
            if (targetText.isEmpty())
            {
                targetText = QStringLiteral("<未知路径>");
            }
            const QString kSummaryText = QStringLiteral("文件 %1 | %2 | PID=%3 TID=%4")
                .arg(actionText, targetText)
                .arg(pidValue)
                .arg(tidValue);
            return appendEtwStatusSummary(kSummaryText, kStatusText);
        }

        if (kResourceTypeText == QStringLiteral("注册表"))
        {
            if (targetText.isEmpty())
            {
                const EtwDecodedPropertyEntry* keyProperty = findFirstEtwProperty(
                    propertyList,
                    QStringList{ QStringLiteral("keyname"), QStringLiteral("keypath"),
                    QStringLiteral("hive"), QStringLiteral("objectname"), QStringLiteral("path") });
                const EtwDecodedPropertyEntry* valueProperty = findFirstEtwProperty(
                    propertyList,
                    QStringList{ QStringLiteral("valuename") });
                if (keyProperty != nullptr)
                {
                    targetText = etwToSingleLine(keyProperty->valueText);
                    if (valueProperty != nullptr)
                    {
                        const QString kValueNameText = etwToSingleLine(valueProperty->valueText);
                        if (!kValueNameText.isEmpty())
                        {
                            targetText += QStringLiteral("\\") + kValueNameText;
                        }
                    }
                }
            }
            if (targetText.isEmpty())
            {
                targetText = QStringLiteral("<未知路径>");
            }
            const QString kSummaryText = QStringLiteral("注册表 %1 | %2 | PID=%3 TID=%4")
                .arg(actionText, targetText)
                .arg(pidValue)
                .arg(tidValue);
            return appendEtwStatusSummary(kSummaryText, kStatusText);
        }

        if (kResourceTypeText == QStringLiteral("进程线程"))
        {
            const EtwDecodedPropertyEntry* processIdProperty = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("processid"), QStringLiteral("pid"),
                QStringLiteral("targetprocessid") });
            const EtwDecodedPropertyEntry* threadIdProperty = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("threadid"), QStringLiteral("tid"),
                QStringLiteral("targetthreadid") });
            const EtwDecodedPropertyEntry* parentPidProperty = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("parentprocessid"), QStringLiteral("parentid"), QStringLiteral("ppid") });
            const EtwDecodedPropertyEntry* imageProperty = findFirstEtwProperty(
                propertyList,
                QStringList{ QStringLiteral("imagename"), QStringLiteral("imagefilename"),
                QStringLiteral("processname"), QStringLiteral("commandline") });

            const QString kProcessIdText = processIdProperty != nullptr
                ? etwToSingleLine(processIdProperty->valueText)
                : QString::number(pidValue);
            const QString kThreadIdText = threadIdProperty != nullptr
                ? etwToSingleLine(threadIdProperty->valueText)
                : QString::number(tidValue);

            QString processDisplayText = targetText;
            if (processDisplayText.isEmpty() && imageProperty != nullptr)
            {
                processDisplayText = etwToSingleLine(imageProperty->valueText);
            }

            QString summaryText;
            if (kIsThreadEvent)
            {
                summaryText = QStringLiteral("线程 %1 | PID=%2 TID=%3")
                    .arg(actionText, kProcessIdText, kThreadIdText);
                if (!processDisplayText.isEmpty())
                {
                    summaryText += QStringLiteral(" | 进程=%1").arg(processDisplayText);
                }
            }
            else
            {
                summaryText = QStringLiteral("进程 %1 | PID=%2 | TID=%3")
                    .arg(actionText, kProcessIdText, kThreadIdText);
                if (!processDisplayText.isEmpty())
                {
                    summaryText += QStringLiteral(" | %1").arg(processDisplayText);
                }
                if (parentPidProperty != nullptr)
                {
                    const QString kParentPidText = etwToSingleLine(parentPidProperty->valueText);
                    if (!kParentPidText.isEmpty())
                    {
                        summaryText += QStringLiteral(" | 父PID=%1").arg(kParentPidText);
                    }
                }
            }
            return appendEtwStatusSummary(summaryText, kStatusText);
        }

        QString targetDisplayText = targetText;
        if (targetDisplayText.isEmpty())
        {
            targetDisplayText = etwToSingleLine(providerNameText);
        }
        if (targetDisplayText.isEmpty())
        {
            targetDisplayText = QStringLiteral("<无目标>");
        }

        QString summaryText = QStringLiteral("%1 | %2 | PID=%3 TID=%4")
            .arg(actionText, targetDisplayText)
            .arg(pidValue)
            .arg(tidValue);
        if (!kResourceTypeText.isEmpty() && kResourceTypeText != QStringLiteral("通用"))
        {
            summaryText = QStringLiteral("%1 %2").arg(kResourceTypeText, summaryText);
        }
        return appendEtwStatusSummary(summaryText, kStatusText);
    }

    // buildEtwSummaryFromDetailJson：
    // - Purpose: Derive a single-line summary from the detailed JSON (fallback path to ensure summaries are displayed for legacy calls).
    QString buildEtwSummaryFromDetailJson(
        const QString& detailJsonText,
        const QString& providerNameText,
        const QString& eventNameText,
        const std::uint32_t pidValue,
        const std::uint32_t tidValue)
    {
        QJsonParseError parseError;
        const QJsonDocument kJsonDocument = QJsonDocument::fromJson(detailJsonText.toUtf8(), &parseError);
        if (kJsonDocument.isNull() || !kJsonDocument.isObject())
        {
            const QString kNormalizedEventName = etwToSingleLine(eventNameText).isEmpty()
                ? QStringLiteral("事件")
                : etwToSingleLine(eventNameText);
            return QStringLiteral("%1 | PID=%2 TID=%3")
                .arg(kNormalizedEventName)
                .arg(pidValue)
                .arg(tidValue);
        }

        const QJsonObject kRootObject = kJsonDocument.object();
        const QJsonObject kSemanticObject = kRootObject.value(QStringLiteral("semantic")).toObject();
        const QJsonObject kMetaObject = kRootObject.value(QStringLiteral("meta")).toObject();

        EtwSemanticSummary semanticSummary;
        semanticSummary.resourceTypeText = kSemanticObject.value(QStringLiteral("resourceType")).toString();
        semanticSummary.actionText = kSemanticObject.value(QStringLiteral("action")).toString();
        semanticSummary.targetText = kSemanticObject.value(QStringLiteral("target")).toString();
        semanticSummary.statusText = kSemanticObject.value(QStringLiteral("status")).toString();

        const QString kOpcodeNameText = kMetaObject.value(QStringLiteral("opcodeName")).toString();
        return buildEtwSummaryText(
            providerNameText,
            eventNameText,
            kOpcodeNameText,
            pidValue,
            tidValue,
            semanticSummary,
            std::vector<EtwDecodedPropertyEntry>{});
    }
}
