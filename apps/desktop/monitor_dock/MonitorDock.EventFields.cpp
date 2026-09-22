#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    // buildEtwDetailJson：
    // - Purpose: Pack metadata, semantic summary, attribute list, and trailing hex fallback into JSON.
    // - Call: enqueueEtwEventFromRecord constructs the raw data required for "View Return Details".
    QString buildEtwDetailJson(
        const EVENT_RECORD* eventRecord,
        const QString& providerGuidText,
        const QString& providerNameText,
        const EtwSchemaEntry& schemaEntry,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList,
        const ULONG parsedBytes,
        const QString& unparsedTailHexText)
    {
        QJsonObject rootObject;

        QJsonObject metaObject;
        QString eventNameText = schemaEntry.eventNameText.trimmed();
        if (eventNameText.isEmpty())
        {
            eventNameText = schemaEntry.taskNameText.trimmed();
        }
        if (eventNameText.isEmpty())
        {
            eventNameText = schemaEntry.opcodeNameText.trimmed();
        }
        if (eventNameText.isEmpty())
        {
            eventNameText = QStringLiteral("Event_%1")
                .arg(static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id));
        }

        metaObject.insert(QStringLiteral("providerGuid"), providerGuidText);
        metaObject.insert(QStringLiteral("providerName"), providerNameText);
        metaObject.insert(QStringLiteral("eventId"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id));
        metaObject.insert(QStringLiteral("eventName"), eventNameText);
        metaObject.insert(QStringLiteral("task"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Task));
        metaObject.insert(QStringLiteral("taskName"), schemaEntry.taskNameText);
        metaObject.insert(QStringLiteral("opcode"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Opcode));
        metaObject.insert(QStringLiteral("opcodeName"), schemaEntry.opcodeNameText);
        metaObject.insert(QStringLiteral("level"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Level));
        metaObject.insert(
            QStringLiteral("keyword"),
            QStringLiteral("0x%1").arg(
                static_cast<qulonglong>(eventRecord->EventHeader.EventDescriptor.Keyword),
                16,
                16,
                QChar(u'0')).toUpper());
        metaObject.insert(QStringLiteral("version"), static_cast<int>(eventRecord->EventHeader.EventDescriptor.Version));
        metaObject.insert(QStringLiteral("userDataLength"), static_cast<int>(eventRecord->UserDataLength));
        metaObject.insert(QStringLiteral("parsedBytes"), static_cast<int>(parsedBytes));
        rootObject.insert(QStringLiteral("meta"), metaObject);

        QJsonObject semanticObject;
        semanticObject.insert(QStringLiteral("resourceType"), semanticSummary.resourceTypeText);
        semanticObject.insert(QStringLiteral("action"), semanticSummary.actionText);
        semanticObject.insert(QStringLiteral("target"), semanticSummary.targetText);
        semanticObject.insert(QStringLiteral("status"), semanticSummary.statusText);
        rootObject.insert(QStringLiteral("semantic"), semanticObject);

        QJsonArray propertyArray;
        for (const EtwDecodedPropertyEntry& property : propertyList)
        {
            QJsonObject propertyObject;
            propertyObject.insert(QStringLiteral("name"), property.propertyNameText);
            propertyObject.insert(QStringLiteral("normalized"), property.normalizedNameText);
            propertyObject.insert(QStringLiteral("meaning"), property.meaningText);
            propertyObject.insert(QStringLiteral("type"), property.inTypeText);
            propertyObject.insert(QStringLiteral("value"), property.valueText);
            propertyObject.insert(
                QStringLiteral("offset"),
                QStringLiteral("0x%1-0x%2")
                .arg(property.beginOffset, 4, 16, QChar(u'0'))
                .arg(property.endOffset, 4, 16, QChar(u'0')));
            propertyObject.insert(QStringLiteral("hexPreview"), property.hexPreviewText);
            propertyObject.insert(QStringLiteral("fallback"), property.parseFallback);
            propertyArray.append(propertyObject);
        }
        rootObject.insert(QStringLiteral("properties"), propertyArray);

        if (!unparsedTailHexText.trimmed().isEmpty())
        {
            QJsonObject rawFallbackObject;
            rawFallbackObject.insert(QStringLiteral("note"), QStringLiteral("存在未解析尾部字节，已按十六进制保留"));
            rawFallbackObject.insert(QStringLiteral("hexDump"), unparsedTailHexText);
            rootObject.insert(QStringLiteral("rawFallback"), rawFallbackObject);
        }

        return QString::fromUtf8(QJsonDocument(rootObject).toJson(QJsonDocument::Compact));
    }

    QString etwPropertySingleLineValue(const EtwDecodedPropertyEntry* propertyPointer)
    {
        if (propertyPointer == nullptr)
        {
            return QString();
        }
        return etwSingleLineOrEmpty(propertyPointer->valueText);
    }

    bool etwPropertyToUInt32(const EtwDecodedPropertyEntry* propertyPointer, std::uint32_t* valueOut)
    {
        if (propertyPointer == nullptr || valueOut == nullptr)
        {
            return false;
        }
        if (propertyPointer->numericAvailable)
        {
            *valueOut = static_cast<std::uint32_t>(propertyPointer->numericValue);
            return true;
        }
        std::uint64_t parsedValue = 0;
        if (!tryParseUInt64Text(propertyPointer->valueText, parsedValue))
        {
            return false;
        }
        *valueOut = static_cast<std::uint32_t>(parsedValue & 0xFFFFFFFFULL);
        return true;
    }

    bool etwPropertyToUInt16(const EtwDecodedPropertyEntry* propertyPointer, std::uint16_t* valueOut)
    {
        std::uint32_t value32 = 0;
        if (!etwPropertyToUInt32(propertyPointer, &value32) || valueOut == nullptr || value32 > 65535U)
        {
            return false;
        }
        *valueOut = static_cast<std::uint16_t>(value32);
        return true;
    }

    void etwAssignIpFieldFromProperty(
        const EtwDecodedPropertyEntry* propertyPointer,
        QString* textOut,
        std::uint32_t* numericOut,
        bool* validOut)
    {
        if (textOut == nullptr || numericOut == nullptr || validOut == nullptr)
        {
            return;
        }
        *textOut = QString();
        *numericOut = 0;
        *validOut = false;
        if (propertyPointer == nullptr)
        {
            return;
        }

        QString ipText;
        if (propertyPointer->numericAvailable)
        {
            ipText = etwIpv4TextFromNumeric(static_cast<std::uint32_t>(propertyPointer->numericValue));
        }
        else
        {
            ipText = etwSingleLineOrEmpty(propertyPointer->valueText);
        }
        *textOut = ipText;
        std::uint32_t parsedIp = 0;
        if (tryParseIpv4Text(ipText, parsedIp))
        {
            *numericOut = parsedIp;
            *validOut = true;
        }
    }

    QString etwInferNetworkProtocol(
        const QString& providerNameText,
        const QString& eventNameText,
        const EtwDecodedPropertyEntry* protocolProperty)
    {
        const QString kPropertyText = etwPropertySingleLineValue(protocolProperty);
        if (!kPropertyText.isEmpty())
        {
            return kPropertyText;
        }

        const QString kProbe = (providerNameText + QLatin1Char(' ') + eventNameText).toLower();
        if (kProbe.contains(QStringLiteral("tcp")))
        {
            return QStringLiteral("TCP");
        }
        if (kProbe.contains(QStringLiteral("udp")))
        {
            return QStringLiteral("UDP");
        }
        if (kProbe.contains(QStringLiteral("dns")))
        {
            return QStringLiteral("DNS");
        }
        return QString();
    }

    QString etwInferNetworkDirection(
        const QString& eventNameText,
        const EtwDecodedPropertyEntry* directionProperty,
        const EtwDecodedPropertyEntry* opcodeProperty)
    {
        QString directionText = etwPropertySingleLineValue(directionProperty);
        if (!directionText.isEmpty())
        {
            return directionText;
        }

        directionText = etwPropertySingleLineValue(opcodeProperty);
        if (!directionText.isEmpty())
        {
            const QString kLower = directionText.toLower();
            if (kLower.contains(QStringLiteral("send")) || kLower.contains(QStringLiteral("out")))
            {
                return QStringLiteral("Outbound");
            }
            if (kLower.contains(QStringLiteral("recv")) || kLower.contains(QStringLiteral("in")))
            {
                return QStringLiteral("Inbound");
            }
        }

        const QString kEventLower = eventNameText.toLower();
        if (kEventLower.contains(QStringLiteral("send")) || kEventLower.contains(QStringLiteral("connect")))
        {
            return QStringLiteral("Outbound");
        }
        if (kEventLower.contains(QStringLiteral("recv")) || kEventLower.contains(QStringLiteral("accept")))
        {
            return QStringLiteral("Inbound");
        }
        return QString();
    }

    void fillEtwCapturedRowDecodedFields(
        MonitorDock::EtwCapturedEventRow* rowOut,
        const QString& providerNameText,
        const QString& eventNameText,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList)
    {
        if (rowOut == nullptr)
        {
            return;
        }

        rowOut->resourceTypeText = etwSingleLineOrEmpty(semanticSummary.resourceTypeText);
        rowOut->actionText = etwSingleLineOrEmpty(semanticSummary.actionText);
        rowOut->targetText = etwSingleLineOrEmpty(semanticSummary.targetText);
        rowOut->statusText = etwSingleLineOrEmpty(semanticSummary.statusText);

        const EtwDecodedPropertyEntry* targetPidProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("targetprocessid"), QStringLiteral("processid"), QStringLiteral("pid") });
        rowOut->targetPidValid = etwPropertyToUInt32(targetPidProperty, &rowOut->targetPid);

        const EtwDecodedPropertyEntry* parentPidProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("parentprocessid"), QStringLiteral("parentid"), QStringLiteral("ppid") });
        rowOut->parentPidValid = etwPropertyToUInt32(parentPidProperty, &rowOut->parentPid);

        const EtwDecodedPropertyEntry* targetTidProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("targetthreadid"), QStringLiteral("threadid"), QStringLiteral("tid") });
        rowOut->targetTidValid = etwPropertyToUInt32(targetTidProperty, &rowOut->targetTid);

        rowOut->processNameText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("processname"), QStringLiteral("imagename"), QStringLiteral("imagefilename") }));
        rowOut->imagePathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("imagename"), QStringLiteral("imagefilename"), QStringLiteral("path") }));
        rowOut->commandLineText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("commandline"), QStringLiteral("scriptblocktext") }));

        rowOut->filePathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("filename"), QStringLiteral("filepath"), QStringLiteral("pathname"),
            QStringLiteral("targetfilename"), QStringLiteral("relativefilename"), QStringLiteral("targetname") }));
        if (rowOut->filePathText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("文件"))
        {
            rowOut->filePathText = rowOut->targetText;
        }
        rowOut->fileOldPathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("oldfilename") }));
        rowOut->fileNewPathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("newfilename"), QStringLiteral("targetfilename") }));
        rowOut->fileOperationText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("operation"), QStringLiteral("opcode") }));
        if (rowOut->fileOperationText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("文件"))
        {
            rowOut->fileOperationText = rowOut->actionText;
        }
        rowOut->fileStatusCodeText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("status"), QStringLiteral("ntstatus"), QStringLiteral("result"),
            QStringLiteral("hresult"), QStringLiteral("errorcode"), QStringLiteral("win32error") }));
        if (rowOut->fileStatusCodeText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("文件"))
        {
            rowOut->fileStatusCodeText = rowOut->statusText;
        }
        rowOut->fileAccessMaskText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("desiredaccess"), QStringLiteral("accessmask"), QStringLiteral("shareaccess") }));

        rowOut->registryKeyPathText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("keypath"), QStringLiteral("keyname"), QStringLiteral("hive"),
            QStringLiteral("objectname"), QStringLiteral("path") }));
        if (rowOut->registryKeyPathText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("注册表"))
        {
            rowOut->registryKeyPathText = rowOut->targetText;
        }
        rowOut->registryValueNameText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("valuename") }));
        rowOut->registryHiveText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("hive") }));
        rowOut->registryOperationText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("operation"), QStringLiteral("opcode") }));
        if (rowOut->registryOperationText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("注册表"))
        {
            rowOut->registryOperationText = rowOut->actionText;
        }
        rowOut->registryStatusText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("status"), QStringLiteral("ntstatus"), QStringLiteral("result"),
            QStringLiteral("hresult"), QStringLiteral("errorcode"), QStringLiteral("win32status") }));
        if (rowOut->registryStatusText.isEmpty() && rowOut->resourceTypeText == QStringLiteral("注册表"))
        {
            rowOut->registryStatusText = rowOut->statusText;
        }

        const EtwDecodedPropertyEntry* sourceIpProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("sourceaddress"), QStringLiteral("saddr"), QStringLiteral("srcaddr") });
        const EtwDecodedPropertyEntry* destinationIpProperty = findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("destaddress"), QStringLiteral("daddr"), QStringLiteral("dstaddr") });
        etwAssignIpFieldFromProperty(
            sourceIpProperty,
            &rowOut->sourceIpText,
            &rowOut->sourceIpValue,
            &rowOut->sourceIpValid);
        etwAssignIpFieldFromProperty(
            destinationIpProperty,
            &rowOut->destinationIpText,
            &rowOut->destinationIpValue,
            &rowOut->destinationIpValid);

        rowOut->sourcePortValid = etwPropertyToUInt16(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("sourceport"), QStringLiteral("sport"), QStringLiteral("srcport") }),
            &rowOut->sourcePort);
        rowOut->destinationPortValid = etwPropertyToUInt16(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("destport"), QStringLiteral("dport"), QStringLiteral("dstport") }),
            &rowOut->destinationPort);

        rowOut->protocolText = etwInferNetworkProtocol(
            providerNameText,
            eventNameText,
            findFirstEtwProperty(propertyList, QStringList{ QStringLiteral("protocol"), QStringLiteral("ipprotocol") }));
        rowOut->directionText = etwInferNetworkDirection(
            eventNameText,
            findFirstEtwProperty(propertyList, QStringList{ QStringLiteral("direction") }),
            findFirstEtwProperty(propertyList, QStringList{ QStringLiteral("opcode"), QStringLiteral("operation") }));
        rowOut->domainText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("domainname"), QStringLiteral("queryname"), QStringLiteral("fqdn"), QStringLiteral("url") }));
        rowOut->hostText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("hostname"), QStringLiteral("host"), QStringLiteral("server") }));

        rowOut->auditResultText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("auditresult"), QStringLiteral("result"), QStringLiteral("status"),
            QStringLiteral("outcome"), QStringLiteral("ntstatus") }));
        if (rowOut->auditResultText.isEmpty())
        {
            rowOut->auditResultText = rowOut->statusText;
        }
        rowOut->userText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("username"), QStringLiteral("accountname"), QStringLiteral("user"),
            QStringLiteral("userid"), QStringLiteral("subjectusername") }));
        rowOut->sidText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("sid"), QStringLiteral("usersid"), QStringLiteral("subjectusersid") }));
        rowOut->securityPidValid = etwPropertyToUInt32(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("subjectprocessid"), QStringLiteral("processid"), QStringLiteral("pid") }),
            &rowOut->securityPid);
        if (!rowOut->securityPidValid && rowOut->headerPid != 0)
        {
            rowOut->securityPid = rowOut->headerPid;
            rowOut->securityPidValid = true;
        }
        rowOut->securityTidValid = etwPropertyToUInt32(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("threadid"), QStringLiteral("tid"), QStringLiteral("subjectthreadid") }),
            &rowOut->securityTid);
        if (!rowOut->securityTidValid && rowOut->headerTid != 0)
        {
            rowOut->securityTid = rowOut->headerTid;
            rowOut->securityTidValid = true;
        }
        rowOut->securityLevelText = rowOut->levelText;

        rowOut->scriptHostProcessText = rowOut->processNameText;
        if (rowOut->scriptHostProcessText.isEmpty())
        {
            rowOut->scriptHostProcessText = rowOut->imagePathText;
        }
        rowOut->scriptKeywordText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("scriptblocktext"), QStringLiteral("commandline"),
            QStringLiteral("query"), QStringLiteral("querytext") }));
        rowOut->scriptTaskNameText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("taskname"), QStringLiteral("scheduledtaskname"), QStringLiteral("task") }));
        rowOut->wmiClassNameText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("classname"), QStringLiteral("class"), QStringLiteral("wmiclass") }));
        rowOut->wmiNamespaceText = etwPropertySingleLineValue(findFirstEtwProperty(
            propertyList,
            QStringList{ QStringLiteral("namespace"), QStringLiteral("wminamespace") }));

        rowOut->decodedReady = true;
    }

    // 100ns timestamp text formatting: directly output the FILETIME base integer to meet scheduling requirements.
    QString etwTimestamp100nsText(const EVENT_RECORD* eventRecord)
    {
        if (eventRecord == nullptr)
        {
            return now100nsText();
        }
        return QString::number(static_cast<qulonglong>(eventRecord->EventHeader.TimeStamp.QuadPart));
    }
}
