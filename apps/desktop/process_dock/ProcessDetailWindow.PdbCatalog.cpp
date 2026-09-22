#include "ProcessDetailWindow.InternalCommon.h"

#include "../../../shared/platform/profile/ProfileJsonLoader.h"

// ============================================================
// ProcessDetailWindow.PdbCatalog.cpp
// Purpose:
// - Read-only parsing of the ntkrnlmp deep offset JSON in profiles\pdb_deep_offsets.
// - Provide a fallback PDB offset directory preview for process/thread details;
// - Does not trigger driver calls or modify any profile files.
// ============================================================

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMutex>
#include <QMutexLocker>
#include <QStringList>

#include <algorithm>
#include <utility>

namespace process_detail_window_internal
{
    namespace
    {
        // findPdbDeepOffsetDirectory:
        // - No input;
        // - Processing: Search for profiles\pdb_deep_offsets sequentially using Release layout and development working directory layout.
        // - Returns: The existing directory; an empty string if not found.
        QString findPdbDeepOffsetDirectory()
        {
            QStringList candidateDirectories;
            const QString kApplicationDirectory = QCoreApplication::applicationDirPath();
            const QString kCurrentDirectory = QDir::currentPath();

            candidateDirectories.push_back(
                QDir(kApplicationDirectory).filePath(QStringLiteral("profiles/pdb_deep_offsets")));
            candidateDirectories.push_back(
                QDir(kApplicationDirectory).filePath(QStringLiteral("../profiles/pdb_deep_offsets")));
            candidateDirectories.push_back(
                QDir(kCurrentDirectory).filePath(QStringLiteral("profiles/pdb_deep_offsets")));
            candidateDirectories.push_back(
                QDir(kCurrentDirectory).filePath(QStringLiteral("apps/desktop/profiles/pdb_deep_offsets")));

            for (const QString& directoryText : candidateDirectories)
            {
                QDir candidateDirectory(directoryText);
                if (candidateDirectory.exists())
                {
                    return candidateDirectory.absolutePath();
                }
            }

            return QString();
        }

        // findNtosDeepOffsetJsonPath:
        // - No input;
        // - Processing: Locate ntkrnlmp_*_deep_offsets.json in the deep offset directory.
        // - Return: The path of the first matching JSON file; return an empty string if not found.
        QString findNtosDeepOffsetJsonPath()
        {
            const QString kDirectoryText = findPdbDeepOffsetDirectory();
            if (kDirectoryText.isEmpty())
            {
                return QString();
            }

            QDir directory(kDirectoryText);
            QStringList fileNames = directory.entryList(
                QStringList{ QStringLiteral("ntkrnlmp_*_deep_offsets.json.qz") },
                QDir::Files,
                QDir::Name);
            if (fileNames.isEmpty())
            {
                fileNames = directory.entryList(
                    QStringList{ QStringLiteral("ntkrnlmp_*_deep_offsets.json") },
                    QDir::Files,
                    QDir::Name);
            }
            if (fileNames.isEmpty())
            {
                return QString();
            }

            return directory.absoluteFilePath(fileNames.first());
        }

        // findDynDataPackJsonPath:
        // - No input;
        // - Processing: prioritize locating ark_dyndata_pack_v4.json from the parent profiles directory of the deep offset directory.
        // - Returns: The found v4 pack path; returns an empty string if not found.
        QString findDynDataPackJsonPath()
        {
            QStringList candidatePaths;
            const QString kDeepDirectoryText = findPdbDeepOffsetDirectory();
            if (!kDeepDirectoryText.isEmpty())
            {
                QDir profileDirectory(kDeepDirectoryText);
                profileDirectory.cdUp();
                candidatePaths.push_back(profileDirectory.filePath(QStringLiteral("ark_dyndata_pack_v4.json")));
            }

            const QString kApplicationDirectory = QCoreApplication::applicationDirPath();
            const QString kCurrentDirectory = QDir::currentPath();
            candidatePaths.push_back(QDir(kApplicationDirectory).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
            candidatePaths.push_back(QDir(kApplicationDirectory).filePath(QStringLiteral("../profiles/ark_dyndata_pack_v4.json")));
            candidatePaths.push_back(QDir(kCurrentDirectory).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
            candidatePaths.push_back(QDir(kCurrentDirectory).filePath(QStringLiteral("apps/desktop/profiles/ark_dyndata_pack_v4.json")));

            for (const QString& pathText : candidatePaths)
            {
                const QString kResolvedPath = ks::profile::resolveProfileJsonPath(pathText);
                if (!kResolvedPath.isEmpty())
                {
                    return QFileInfo(kResolvedPath).absoluteFilePath();
                }
            }
            return QString();
        }

        // normalizeGuidText:
        // - Input: PDB GUID text, which may include braces or hyphens.
        // - Processing: Strip decoration characters and convert to lowercase for deep JSON and pack JSON comparison.
        // - Return: 32-bit hexadecimal GUID text; returns original lowercase text if normalization fails.
        QString normalizeGuidText(const QString& guidText)
        {
            QString normalizedText = guidText.trimmed().toLower();
            normalizedText.remove(QChar('{'));
            normalizedText.remove(QChar('}'));
            normalizedText.remove(QChar('-'));
            normalizedText.remove(QChar(' '));
            return normalizedText;
        }

        // readJsonObjectFromFile:
        // - Input pathText: JSON file path;
        // - Action: Open read-only and parse the object root;
        // - Returns: the parsed object on success; otherwise returns an empty object and writes to detailTextOut.
        QJsonObject readJsonObjectFromFile(const QString& pathText, QString* detailTextOut)
        {
            QJsonParseError parseError{};
            QString readErrorText;
            const QJsonDocument kDocument = ks::profile::readProfileJsonDocument(pathText, &parseError, &readErrorText);
            if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = QStringLiteral("JSON 解析失败：%1；文件=%2")
                        .arg(readErrorText.isEmpty() ? parseError.errorString() : readErrorText)
                        .arg(pathText);
                }
                return {};
            }

            return kDocument.object();
        }

        // jsonString:
        // - Input object/name/fallback;
        // - Processing: Read string field from JSON object;
        // - Returns: the string value if the field exists, otherwise returns the fallback.
        QString jsonString(const QJsonObject& object, const QString& name, const QString& fallback)
        {
            const QJsonValue kValue = object.value(name);
            return kValue.isString() ? kValue.toString() : fallback;
        }

        // jsonInt:
        // - Input object/name/fallback;
        // - Processing: Read an integer from a JSON object.
        // - Returns: the integer value if the field exists, otherwise returns the fallback.
        int jsonInt(const QJsonObject& object, const QString& name, const int fallback)
        {
            const QJsonValue kValue = object.value(name);
            return kValue.isDouble() ? kValue.toInt(fallback) : fallback;
        }

        // formatCatalogFieldLine:
        // - Input fieldObject: a single field description from the deep catalog;
        // - Processing: Extract qualifiedName/offset/type/bitfield/alias.
        // - Returns: A single line of readable offset catalog text.
        QString formatCatalogFieldLine(const QJsonObject& fieldObject)
        {
            const QString kQualifiedName = jsonString(
                fieldObject,
                QStringLiteral("qualifiedName"),
                jsonString(fieldObject, QStringLiteral("fieldName"), QStringLiteral("<unknown field>")));
            const QString kOffsetText = jsonString(fieldObject, QStringLiteral("offsetHex"), QStringLiteral("<no offset>"));
            const QString kTypeText = jsonString(fieldObject, QStringLiteral("fieldType"), QStringLiteral("<unknown type>"));
            const QString kAliasText = jsonString(fieldObject, QStringLiteral("kswordItemName"), QString());
            QString lineText = QStringLiteral("    - %1 @ %2 : %3")
                .arg(kQualifiedName)
                .arg(kOffsetText)
                .arg(kTypeText);

            const QJsonObject kBitFieldObject = fieldObject.value(QStringLiteral("bitField")).toObject();
            if (!kBitFieldObject.isEmpty())
            {
                lineText += QStringLiteral(" [bit=%1:%2]")
                    .arg(jsonInt(kBitFieldObject, QStringLiteral("bitOffset"), -1))
                    .arg(jsonInt(kBitFieldObject, QStringLiteral("bitSize"), -1));
            }

            if (!kAliasText.trimmed().isEmpty())
            {
                lineText += QStringLiteral(" [DynData=%1]").arg(kAliasText.trimmed());
            }

            return lineText;
        }

        // formatCatalogDomain:
        // - Input: domainObject/maxTypes/maxFieldsPerType;
        // - Processing: Trim types and fields under the target domain into a preview.
        // - Returns: Multi-line text suitable for display in CodeEditorWidget.
        // jsonHexUInt32:
        // - Input object/name/fallback;
        // - Processing: Prioritize parsing the '0x' prefixed string, then read the JSON number.
        // - Returns: 32-bit unsigned integer; returns fallback on failure.
        std::uint32_t jsonHexUInt32(
            const QJsonObject& object,
            const QString& name,
            const std::uint32_t fallback)
        {
            const QJsonValue kValue = object.value(name);
            if (kValue.isString())
            {
                QString text = kValue.toString().trimmed();
                if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
                {
                    text = text.mid(2);
                }
                bool ok = false;
                const quint64 kParsedValue = text.toULongLong(&ok, 16);
                return ok ? static_cast<std::uint32_t>(kParsedValue) : fallback;
            }
            if (kValue.isDouble())
            {
                return static_cast<std::uint32_t>(kValue.toDouble());
            }
            return fallback;
        }

        // inferRuntimeSampleSize:
        // - Input: PDB field type text and bitfield description;
        // - Processing: Only allow small structures that are safe to read with small reads, such as pointers, integers, LIST_ENTRY, and CLIENT_ID.
        // - Returns: 1/2/4/8/16 bytes; returns 0 to skip if undeterminable.
        std::uint32_t inferRuntimeSampleSize(const QString& fieldTypeText, const QJsonObject& bitFieldObject)
        {
            const QString kLowerTypeText = fieldTypeText.toLower();
            if (!bitFieldObject.isEmpty() || kLowerTypeText.contains(QStringLiteral("bitfield")))
            {
                return 4U;
            }
            if (kLowerTypeText.contains(QStringLiteral("[15]")) &&
                (kLowerTypeText.contains(QStringLiteral("char")) || kLowerTypeText.contains(QStringLiteral("0x0020"))))
            {
                return 15U;
            }
            if (kLowerTypeText.contains(QStringLiteral("_client_id")) ||
                kLowerTypeText.contains(QStringLiteral("_unicode_string")))
            {
                return 16U;
            }
            if (kLowerTypeText.contains(QStringLiteral("_ex_fast_ref")))
            {
                return 8U;
            }
            if (kLowerTypeText.contains(QStringLiteral("_ps_protection")))
            {
                return 1U;
            }
            if (kLowerTypeText.contains(QStringLiteral("_list_entry")))
            {
                return 16U;
            }
            if (kLowerTypeText.contains(QStringLiteral("void*")) || kLowerTypeText.contains(QChar('*')))
            {
                return 8U;
            }
            if (kLowerTypeText.contains(QStringLiteral("__int64")) ||
                kLowerTypeText.contains(QStringLiteral("large_integer")) ||
                kLowerTypeText.contains(QStringLiteral("unsigned long long")))
            {
                return 8U;
            }
            if (kLowerTypeText.contains(QStringLiteral("unsigned long")) ||
                kLowerTypeText.contains(QStringLiteral(" long")) ||
                kLowerTypeText.contains(QStringLiteral("enum")))
            {
                return 4U;
            }
            if (kLowerTypeText.contains(QStringLiteral("short")))
            {
                return 2U;
            }
            if (kLowerTypeText.contains(QStringLiteral("uchar")) ||
                kLowerTypeText.contains(QStringLiteral("unsigned char")) ||
                kLowerTypeText.contains(QStringLiteral("boolean")) ||
                kLowerTypeText.contains(QStringLiteral("char")))
            {
                return 1U;
            }
            return 0U;
        }

        // typeAllowedForRuntimeSample:
        // - Input: domain/typeName
        // - Handling: Samples only top-level/first-field embedded types originating from the same base address as the object.
        // - Return: true indicates that the offset can be interpreted directly using EPROCESS/ETHREAD base addresses.
        bool typeAllowedForRuntimeSample(const QString& domainName, const QString& typeName)
        {
            if (domainName == QStringLiteral("process_detail"))
            {
                return typeName == QStringLiteral("_EPROCESS") || typeName == QStringLiteral("_KPROCESS");
            }
            if (domainName == QStringLiteral("thread_detail"))
            {
                return typeName == QStringLiteral("_ETHREAD") || typeName == QStringLiteral("_KTHREAD");
            }
            return false;
        }

        struct RuntimeSampleCandidate
        {
            ksword::ark::RuntimeFieldSampleRequestItem item; // item: The sampling request item ultimately sent to ArkDriverClient.
            int priority = 100000;                           // priority: Lower values indicate higher priority to ensure key fields enter the list first.
            int sourceOrder = 0;                              // sourceOrder: Preserve the original JSON order for items with the same priority.
        };

        // prioritizedNameScore:
        // - Input haystackText: lowercase text formed by concatenating qualifiedName/alias/type.
        // - Input keywordText: keyword name to match;
        // - Input: score: priority returned after matching
        // - Return: Return score on match, otherwise return fallback.
        int prioritizedNameScore(
            const QString& haystackText,
            const QString& keywordText,
            const int score,
            const int fallback)
        {
            return haystackText.contains(keywordText, Qt::CaseInsensitive)
                ? qMin(score, fallback)
                : fallback;
        }

        // runtimeSamplePriority:
        // - Input: domain/type/fieldObject; field metadata from deep offset JSON.
        // - Processing: Sort by 'human-readable detail value', prioritizing fields like PID, CID, linked list, Token, stack, and start address.
        // - Return: Lower values indicate higher priority; regular fields are retained but placed after key fields.
        int runtimeSamplePriority(
            const QString& domainName,
            const QString& typeName,
            const QJsonObject& fieldObject)
        {
            const QString kQualifiedName = jsonString(
                fieldObject,
                QStringLiteral("qualifiedName"),
                jsonString(fieldObject, QStringLiteral("fieldName"), QString()));
            const QString kAliasName = jsonString(fieldObject, QStringLiteral("kswordItemName"), QString());
            const QString kFieldTypeText = jsonString(fieldObject, QStringLiteral("fieldType"), QString());
            const QString kHaystackText =
                QStringLiteral("%1 %2 %3 %4")
                .arg(kQualifiedName, kAliasName, kFieldTypeText, typeName)
                .toLower();

            int priority = 90000;
            if (domainName == QStringLiteral("process_detail"))
            {
                if (typeName == QStringLiteral("_EPROCESS"))
                {
                    priority = 10000;
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("epuniqueprocessid"), 100, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("uniqueprocessid"), 110, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("epactiveprocesslinks"), 120, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("activeprocesslinks"), 130, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("epimagefilename"), 140, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("imagefilename"), 150, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("eptoken"), 160, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral(" token"), 170, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("epobjecttable"), 180, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("objecttable"), 190, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("epsectionobject"), 200, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("sectionobject"), 210, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("epthreadlisthead"), 220, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("threadlisthead"), 230, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("epprotection"), 240, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("protection"), 250, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("epsignaturelevel"), 260, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("signaturelevel"), 270, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("exitstatus"), 320, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("create_time"), 330, priority);
                }
                else if (typeName == QStringLiteral("_KPROCESS"))
                {
                    priority = 20000;
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("directorytablebase"), 300, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("threadlisthead"), 310, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("processlock"), 340, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("affinity"), 360, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("basepriority"), 380, priority);
                }
            }
            else if (domainName == QStringLiteral("thread_detail"))
            {
                if (typeName == QStringLiteral("_ETHREAD"))
                {
                    priority = 10000;
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("etcid"), 100, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral(" cid"), 110, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("etstartaddress"), 120, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("startaddress"), 130, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("etwin32startaddress"), 140, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("win32startaddress"), 150, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("etthreadlistentry"), 160, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("threadlistentry"), 170, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("createtime"), 180, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("exittime"), 190, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("crossthreadflags"), 260, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("sameprocesspassiveflags"), 270, priority);
                }
                else if (typeName == QStringLiteral("_KTHREAD"))
                {
                    priority = 20000;
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("ktinitialstack"), 200, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("initialstack"), 210, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("ktstacklimit"), 220, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("stacklimit"), 230, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("ktstackbase"), 240, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("stackbase"), 250, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("ktkernelstack"), 280, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("kernelstack"), 290, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("ktprocess"), 300, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral(" process"), 310, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("readoperationcount"), 400, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("writeoperationcount"), 410, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("otheroperationcount"), 420, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("readtransfercount"), 430, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("writetransfercount"), 440, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("othertransfercount"), 450, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("state"), 520, priority);
                    priority = prioritizedNameScore(kHaystackText, QStringLiteral("priority"), 530, priority);
                }
            }

            if (!kAliasName.trimmed().isEmpty())
            {
                priority = qMin(priority, 1000);
            }
            return priority;
        }

        QString formatCatalogDomain(
            const QJsonObject& domainObject,
            const int maxTypes,
            const int maxFieldsPerType)
        {
            QStringList lines;
            const QString kDomainName = jsonString(domainObject, QStringLiteral("domain"), QStringLiteral("<unknown domain>"));
            const int kTypeCount = jsonInt(domainObject, QStringLiteral("typeCount"), 0);
            const int kFieldCount = jsonInt(domainObject, QStringLiteral("fieldCount"), 0);
            const int kAliasCount = jsonInt(domainObject, QStringLiteral("kswordAliasFieldCount"), 0);

            lines << QStringLiteral("Domain: %1").arg(kDomainName);
            lines << QStringLiteral("Types=%1, Fields=%2, DynDataAliasFields=%3")
                .arg(kTypeCount)
                .arg(kFieldCount)
                .arg(kAliasCount);

            const QJsonArray kTypeArray = domainObject.value(QStringLiteral("types")).toArray();
            int emittedTypeCount = 0;
            for (const QJsonValue& typeValue : kTypeArray)
            {
                if (emittedTypeCount >= maxTypes)
                {
                    break;
                }

                const QJsonObject kTypeObject = typeValue.toObject();
                if (kTypeObject.isEmpty())
                {
                    continue;
                }

                const QString kTypeName = jsonString(kTypeObject, QStringLiteral("typeName"), QStringLiteral("<unknown type>"));
                const int kTypeSize = jsonInt(kTypeObject, QStringLiteral("typeSize"), -1);
                const int kTypeFieldCount = jsonInt(kTypeObject, QStringLiteral("fieldCount"), 0);
                lines << QStringLiteral("  * %1 size=%2 fields=%3")
                    .arg(kTypeName)
                    .arg(kTypeSize)
                    .arg(kTypeFieldCount);

                const QJsonArray kFieldArray = kTypeObject.value(QStringLiteral("fields")).toArray();
                int emittedFieldCount = 0;
                for (const QJsonValue& fieldValue : kFieldArray)
                {
                    if (emittedFieldCount >= maxFieldsPerType)
                    {
                        break;
                    }

                    const QJsonObject kFieldObject = fieldValue.toObject();
                    if (!kFieldObject.isEmpty())
                    {
                        lines << formatCatalogFieldLine(kFieldObject);
                        ++emittedFieldCount;
                    }
                }

                if (kFieldArray.size() > emittedFieldCount)
                {
                    lines << QStringLiteral("    ... 还有 %1 个字段在 deep offset JSON 中备用")
                        .arg(kFieldArray.size() - emittedFieldCount);
                }

                ++emittedTypeCount;
            }

            if (kTypeArray.size() > emittedTypeCount)
            {
                lines << QStringLiteral("  ... 还有 %1 个类型在 deep offset JSON 中备用")
                    .arg(kTypeArray.size() - emittedTypeCount);
            }

            return lines.join(QChar('\n'));
        }

        // formatCatalogGlobalSymbolLine:
        // - Input symbolObject: A global symbol description from the deep catalog;
        // - Processing: Extract symbol name, RVA, section, runtime item ID, and DynData alias.
        // - Returns: a read-only global RVA catalog line suitable for display in the detail view.
        QString formatCatalogGlobalSymbolLine(const QJsonObject& symbolObject)
        {
            const QString kSymbolName = jsonString(
                symbolObject,
                QStringLiteral("symbolName"),
                QStringLiteral("<unknown symbol>"));
            const QString kKindText = jsonString(
                symbolObject,
                QStringLiteral("kind"),
                QStringLiteral("GlobalRva"));
            const QString kRvaText = jsonString(
                symbolObject,
                QStringLiteral("rvaHex"),
                QStringLiteral("<no rva>"));
            const QString kSectionName = jsonString(
                symbolObject,
                QStringLiteral("sectionName"),
                QStringLiteral("<unknown section>"));
            const QString kSectionOffsetText = jsonString(
                symbolObject,
                QStringLiteral("sectionOffsetHex"),
                QStringLiteral("<no section offset>"));
            const QString kRuntimeItemIdText = jsonString(
                symbolObject,
                QStringLiteral("runtimeItemIdHex"),
                QStringLiteral("<no runtime id>"));
            const QString kAliasText = jsonString(
                symbolObject,
                QStringLiteral("kswordItemName"),
                QString());

            QString lineText = QStringLiteral("    - %1 rva=%2 kind=%3 section=%4+%5 runtimeItemId=%6")
                .arg(kSymbolName)
                .arg(kRvaText)
                .arg(kKindText)
                .arg(kSectionName)
                .arg(kSectionOffsetText)
                .arg(kRuntimeItemIdText);
            if (!kAliasText.trimmed().isEmpty())
            {
                lineText += QStringLiteral(" [DynData=%1]").arg(kAliasText.trimmed());
            }

            return lineText;
        }

        // formatCatalogGlobalDomain:
        // - Input globalDomainObject/maxSymbols.
        // - Processing: Truncate global RVA domains like kernel_global_detail into a readable preview.
        // - Returns: read-only catalog text; has no side effects and does not trigger an R0 query.
        QString formatCatalogGlobalDomain(
            const QJsonObject& globalDomainObject,
            const int maxSymbols)
        {
            QStringList lines;
            const QString kDomainName = jsonString(
                globalDomainObject,
                QStringLiteral("domain"),
                QStringLiteral("<unknown global domain>"));
            const QString kKindText = jsonString(
                globalDomainObject,
                QStringLiteral("kind"),
                QStringLiteral("global"));
            const int kSymbolCount = jsonInt(
                globalDomainObject,
                QStringLiteral("symbolCount"),
                0);

            lines << QStringLiteral("Domain: %1").arg(kDomainName);
            lines << QStringLiteral("Kind=%1, Symbols=%2")
                .arg(kKindText)
                .arg(kSymbolCount);

            const QJsonArray kSymbolArray = globalDomainObject.value(QStringLiteral("symbols")).toArray();
            int emittedSymbolCount = 0;
            for (const QJsonValue& symbolValue : kSymbolArray)
            {
                if (emittedSymbolCount >= maxSymbols)
                {
                    break;
                }

                const QJsonObject kSymbolObject = symbolValue.toObject();
                if (!kSymbolObject.isEmpty())
                {
                    lines << formatCatalogGlobalSymbolLine(kSymbolObject);
                    ++emittedSymbolCount;
                }
            }

            if (kSymbolArray.size() > emittedSymbolCount)
            {
                lines << QStringLiteral("    ... 还有 %1 个全局符号在 deep offset JSON 中备用")
                    .arg(kSymbolArray.size() - emittedSymbolCount);
            }

            return lines.join(QChar('\n'));
        }
    }

    QString buildPdbRuntimeCatalogPreview(
        const QString& domainName,
        const int maxTypes,
        const int maxFieldsPerType)
    {
        // Function Purpose:
        // - Read-only access to ntkrnlmp deep offset JSON.
        // - Return the backup field catalog for runtime details of processes, threads, handles, etc., based on domainName;
        // - Returns text for display in the detail page without modifying any cache or driver state.
        static QMutex cacheMutex;
        static QHash<QString, QString> previewCache;

        const QString kCacheKey = QStringLiteral("%1|%2|%3")
            .arg(domainName)
            .arg(maxTypes)
            .arg(maxFieldsPerType);
        {
            QMutexLocker cacheLocker(&cacheMutex);
            const auto kCachedIterator = previewCache.constFind(kCacheKey);
            if (kCachedIterator != previewCache.constEnd())
            {
                return kCachedIterator.value();
            }
        }

        const auto kStoreAndReturn =
            [&kCacheKey](const QString& text) -> QString
            {
                QMutexLocker cacheLocker(&cacheMutex);
                previewCache.insert(kCacheKey, text);
                return text;
            };

        const QString kJsonPath = findNtosDeepOffsetJsonPath();
        if (kJsonPath.isEmpty())
        {
            return kStoreAndReturn(QStringLiteral("PDB deep offset JSON 未找到；请确认 profiles/pdb_deep_offsets 已随构建复制到程序目录。"));
        }

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument kDocument = ks::profile::readProfileJsonDocument(kJsonPath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
        {
            return kStoreAndReturn(QStringLiteral("PDB deep offset JSON 解析失败：%1；文件=%2")
                .arg(readErrorText.isEmpty() ? parseError.errorString() : readErrorText)
                .arg(kJsonPath));
        }

        const QJsonObject kRootObject = kDocument.object();
        const QJsonObject kCatalogObject = kRootObject.value(QStringLiteral("runtimeDetailCatalog")).toObject();
        const QJsonArray kDomainArray = kCatalogObject.value(QStringLiteral("domains")).toArray();
        for (const QJsonValue& domainValue : kDomainArray)
        {
            const QJsonObject kDomainObject = domainValue.toObject();
            if (jsonString(kDomainObject, QStringLiteral("domain"), QString()) == domainName)
            {
                return kStoreAndReturn(QStringLiteral("Source: %1\n%2")
                    .arg(kJsonPath)
                    .arg(formatCatalogDomain(
                        kDomainObject,
                        qMax(1, maxTypes),
                        qMax(1, maxFieldsPerType))));
            }
        }

        const QJsonArray kGlobalDomainArray = kCatalogObject.value(QStringLiteral("globalDomains")).toArray();
        for (const QJsonValue& globalDomainValue : kGlobalDomainArray)
        {
            const QJsonObject kGlobalDomainObject = globalDomainValue.toObject();
            if (jsonString(kGlobalDomainObject, QStringLiteral("domain"), QString()) == domainName)
            {
                return kStoreAndReturn(QStringLiteral("Source: %1\n%2")
                    .arg(kJsonPath)
                    .arg(formatCatalogGlobalDomain(
                        kGlobalDomainObject,
                        qMax(1, maxFieldsPerType))));
            }
        }

        return kStoreAndReturn(QStringLiteral("PDB deep offset JSON 中未找到 domain=%1；文件=%2")
            .arg(domainName)
            .arg(kJsonPath));
    }

    bool pdbRuntimeCatalogMatchesKernelIdentity(
        const std::uint32_t timeDateStamp,
        const std::uint32_t sizeOfImage,
        QString* detailTextOut)
    {
        // Function Purpose:
        // - Add an identity safety layer for the deep PDB runtime sampler on the R3 side.
        // - The deep JSON itself only knows the PDB GUID/Age; the v4 pack knows the PE TimeDateStamp/SizeOfImage corresponding to the same PDB.
        // - Sampling is allowed only when the R0 DynData-reported ntoskrnl identity exactly matches the pack profile.
        QStringList detailLines;
        detailLines << QStringLiteral("[PDB Deep Runtime Identity Guard]");
        detailLines << QStringLiteral("当前 ntoskrnl TimeDateStamp/SizeOfImage: 0x%1 / 0x%2")
            .arg(static_cast<qulonglong>(timeDateStamp), 8, 16, QChar('0')).toUpper()
            .arg(static_cast<qulonglong>(sizeOfImage), 8, 16, QChar('0')).toUpper();

        const auto kFinishWithDetail = [&detailLines, detailTextOut](const bool matchValue, const QString& reasonText) -> bool
        {
            detailLines << QStringLiteral("结论: %1").arg(matchValue ? QStringLiteral("匹配，可执行只读采样") : QStringLiteral("不匹配，跳过只读采样"));
            detailLines << QStringLiteral("原因: %1").arg(reasonText);
            if (detailTextOut != nullptr)
            {
                *detailTextOut = detailLines.join(QChar('\n'));
            }
            return matchValue;
        };

        if (timeDateStamp == 0U || sizeOfImage == 0U)
        {
            return kFinishWithDetail(false, QStringLiteral("R0 DynData 未提供有效 ntoskrnl 模块 identity。"));
        }

        const QString kDeepJsonPath = findNtosDeepOffsetJsonPath();
        if (kDeepJsonPath.isEmpty())
        {
            return kFinishWithDetail(false, QStringLiteral("未找到 profiles/pdb_deep_offsets 下的 ntkrnlmp deep offset JSON。"));
        }

        QString parseDetail;
        const QJsonObject kDeepRootObject = readJsonObjectFromFile(kDeepJsonPath, &parseDetail);
        if (kDeepRootObject.isEmpty())
        {
            return kFinishWithDetail(false, parseDetail);
        }

        const QJsonObject kSourceObject = kDeepRootObject.value(QStringLiteral("source")).toObject();
        const QString kDeepGuidText = normalizeGuidText(jsonString(kSourceObject, QStringLiteral("pdbGuid"), QString()));
        const std::uint32_t kDeepAge = jsonHexUInt32(kSourceObject, QStringLiteral("pdbAge"), 0U);
        detailLines << QStringLiteral("Deep JSON: %1").arg(kDeepJsonPath);
        detailLines << QStringLiteral("Deep PDB GUID/Age: %1 / %2").arg(kDeepGuidText).arg(kDeepAge);
        if (kDeepGuidText.isEmpty() || kDeepAge == 0U)
        {
            return kFinishWithDetail(false, QStringLiteral("deep JSON source 中缺少 PDB GUID/Age。"));
        }

        const QString kPackJsonPath = findDynDataPackJsonPath();
        if (kPackJsonPath.isEmpty())
        {
            return kFinishWithDetail(false, QStringLiteral("未找到 profiles/ark_dyndata_pack_v4.json，无法把 PDB identity 映射到 PE identity。"));
        }

        const QJsonObject kPackRootObject = readJsonObjectFromFile(kPackJsonPath, &parseDetail);
        if (kPackRootObject.isEmpty())
        {
            return kFinishWithDetail(false, parseDetail);
        }

        detailLines << QStringLiteral("Pack JSON: %1").arg(kPackJsonPath);
        const QJsonArray kProfileArray = kPackRootObject.value(QStringLiteral("profiles")).toArray();
        QStringList candidateProfileLines;
        for (const QJsonValue& profileValue : kProfileArray)
        {
            const QJsonObject kProfileObject = profileValue.toObject();
            const QString kProfileGuidText = normalizeGuidText(jsonString(kProfileObject, QStringLiteral("pdbGuid"), QString()));
            const std::uint32_t kProfileAge = jsonHexUInt32(kProfileObject, QStringLiteral("pdbAge"), 0U);
            if (kProfileGuidText != kDeepGuidText || kProfileAge != kDeepAge)
            {
                continue;
            }

            const std::uint32_t kProfileTimeDateStamp =
                jsonHexUInt32(kProfileObject, QStringLiteral("timeDateStamp"), 0U);
            const std::uint32_t kProfileSizeOfImage =
                jsonHexUInt32(kProfileObject, QStringLiteral("sizeOfImage"), 0U);
            const QString kProfileName =
                jsonString(kProfileObject, QStringLiteral("profileName"), QStringLiteral("<unnamed profile>"));
            candidateProfileLines << QStringLiteral("%1: TimeDateStamp=0x%2 SizeOfImage=0x%3")
                .arg(kProfileName)
                .arg(static_cast<qulonglong>(kProfileTimeDateStamp), 8, 16, QChar('0')).toUpper()
                .arg(static_cast<qulonglong>(kProfileSizeOfImage), 8, 16, QChar('0')).toUpper();

            if (kProfileTimeDateStamp == timeDateStamp && kProfileSizeOfImage == sizeOfImage)
            {
                detailLines << QStringLiteral("匹配 profile: %1").arg(kProfileName);
                return kFinishWithDetail(true, QStringLiteral("deep JSON 的 PDB identity 与当前 ntoskrnl PE identity 经 v4 pack 校验一致。"));
            }
        }

        if (candidateProfileLines.isEmpty())
        {
            return kFinishWithDetail(false, QStringLiteral("v4 pack 中没有与 deep JSON PDB GUID/Age 对应的 profile。"));
        }

        detailLines << QStringLiteral("同 PDB GUID/Age 的 pack profile 候选:");
        detailLines.append(candidateProfileLines);
        return kFinishWithDetail(false, QStringLiteral("当前 ntoskrnl PE identity 与 deep JSON 对应 profile 不一致，避免发送错误 offset。"));
    }

    std::vector<ksword::ark::RuntimeFieldSampleRequestItem> buildPdbRuntimeSampleItems(
        const QString& domainName,
        const int maxItems)
    {
        // Function Purpose:
        // - Extract small fields safely consumable by the R0 sampler from deep offset JSON.
        // - Only select types where the object base address of _EPROCESS/_KPROCESS or _ETHREAD/_KTHREAD can be directly interpreted;
        // - Collect candidates first, then sort by human-readable value: identity, linked list, token, stack, start address, IO count, etc.
        // - Return value can be directly passed to ArkDriverClient::query*RuntimeFieldSamples.
        std::vector<ksword::ark::RuntimeFieldSampleRequestItem> items;
        std::vector<RuntimeSampleCandidate> candidates;
        int sourceOrder = 0;
        if (maxItems <= 0)
        {
            return items;
        }

        const QString kJsonPath = findNtosDeepOffsetJsonPath();
        if (kJsonPath.isEmpty())
        {
            return items;
        }

        QJsonParseError parseError{};
        const QJsonDocument kDocument = ks::profile::readProfileJsonDocument(kJsonPath, &parseError);
        if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
        {
            return items;
        }

        const QJsonObject kCatalogObject = kDocument.object().value(QStringLiteral("runtimeDetailCatalog")).toObject();
        const QJsonArray kDomainArray = kCatalogObject.value(QStringLiteral("domains")).toArray();
        for (const QJsonValue& domainValue : kDomainArray)
        {
            const QJsonObject kDomainObject = domainValue.toObject();
            if (jsonString(kDomainObject, QStringLiteral("domain"), QString()) != domainName)
            {
                continue;
            }

            const QJsonArray kTypeArray = kDomainObject.value(QStringLiteral("types")).toArray();
            for (const QJsonValue& typeValue : kTypeArray)
            {
                const QJsonObject kTypeObject = typeValue.toObject();
                const QString kTypeName = jsonString(kTypeObject, QStringLiteral("typeName"), QString());
                if (!typeAllowedForRuntimeSample(domainName, kTypeName))
                {
                    continue;
                }

                const QJsonArray kFieldArray = kTypeObject.value(QStringLiteral("fields")).toArray();
                for (const QJsonValue& fieldValue : kFieldArray)
                {
                    const QJsonObject kFieldObject = fieldValue.toObject();
                    if (kFieldObject.isEmpty())
                    {
                        continue;
                    }

                    const QString kFieldTypeText = jsonString(kFieldObject, QStringLiteral("fieldType"), QString());
                    const std::uint32_t kSampleSize = inferRuntimeSampleSize(
                        kFieldTypeText,
                        kFieldObject.value(QStringLiteral("bitField")).toObject());
                    const std::uint32_t kRuntimeItemId = jsonHexUInt32(
                        kFieldObject,
                        QStringLiteral("runtimeItemIdHex"),
                        jsonHexUInt32(kFieldObject, QStringLiteral("runtimeItemId"), 0U));
                    const std::uint32_t kOffset = jsonHexUInt32(
                        kFieldObject,
                        QStringLiteral("offsetHex"),
                        jsonHexUInt32(kFieldObject, QStringLiteral("offset"), KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE));
                    if (kSampleSize == 0U || kRuntimeItemId == 0U || kOffset >= KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_OFFSET)
                    {
                        continue;
                    }

                    ksword::ark::RuntimeFieldSampleRequestItem item;
                    item.runtimeItemId = kRuntimeItemId;
                    item.offset = kOffset;
                    item.size = kSampleSize;
                    item.flags = 0U;
                    item.name = jsonString(
                        kFieldObject,
                        QStringLiteral("qualifiedName"),
                        jsonString(kFieldObject, QStringLiteral("fieldName"), QStringLiteral("<unknown>"))).toStdString();
                    item.type = kFieldTypeText.toStdString();

                    RuntimeSampleCandidate candidate;
                    candidate.item = std::move(item);
                    candidate.priority = runtimeSamplePriority(domainName, kTypeName, kFieldObject);
                    candidate.sourceOrder = sourceOrder++;
                    candidates.push_back(std::move(candidate));
                }
            }

            std::stable_sort(
                candidates.begin(),
                candidates.end(),
                [](const RuntimeSampleCandidate& left, const RuntimeSampleCandidate& right)
                {
                    if (left.priority != right.priority)
                    {
                        return left.priority < right.priority;
                    }
                    return left.sourceOrder < right.sourceOrder;
                });

            items.reserve(static_cast<std::size_t>(qMin(maxItems, static_cast<int>(candidates.size()))));
            for (const RuntimeSampleCandidate& candidate : candidates)
            {
                items.push_back(candidate.item);
                if (items.size() >= static_cast<std::size_t>(maxItems))
                {
                    break;
                }
            }
            return items;
        }

        return items;
    }

}
