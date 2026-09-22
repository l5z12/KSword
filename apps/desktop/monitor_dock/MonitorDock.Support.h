#pragma once

// Private contracts for capture, decoding, filtering, and presentation.

#include "MonitorDock.h"
#include "../../../shared/ui/KsPainterChart.h"
#include <monitor_dock/EtwArchiveCompression.h>
#include "../ui/VisibleTableWidget.h"
#include "DirectKernelCallMonitorWidget.h"
#include "KernelCallbackMonitorWidget.h"
#include "MonitorTextViewer.h"
#include "ProcessTraceMonitorWidget.h"
#include "WinAPIDock.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/ThemeStatusRole.h"

// Monitoring page implementation: includes WMI and ETW tabs; all heavy operations run on asynchronous threads.
#include "../online_scan/SandboxUploadActions.h"
#include "../process_dock/ProcessDetailWindow.h"
#include "../Theme.h"

#include <QApplication>
#include <QAbstractItemModel>
#include <QBuffer>
#include <QByteArray>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QEasingCurve>
#include <QDataStream>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLayoutItem>
#include <QLineEdit>
#include <QListWidget>
#include <QJsonArray>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QPainter>
#include <QRegularExpression>
#include <QSaveFile>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTableView>
#include <QTableWidget>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <QtEndian>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <set>
#include <span>
#include <thread>
#include <unordered_map>
#include <limits>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Wbemidl.h>
#include <Objbase.h>
#include <comdef.h>
#include <atlbase.h>
#include <evntrace.h>
#include <evntcons.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <tdh.h>

#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Iphlpapi.lib")


#include "EtwFilterConfig.h"

namespace ksword::ui::monitor_dock
{
    using ksword::monitor::EtwFilterFieldDescriptor;
    using ksword::monitor::etwFilterFieldDescriptorList;
    using ksword::monitor::etwFilterProviderCategoryList;
    using ksword::monitor::etwFilterStringModeFromText;
    using ksword::monitor::etwFilterStringModeToText;
    using ksword::monitor::findEtwFilterFieldDescriptorByKey;

    inline constexpr char kEtwArchiveMagic[] = "KSWETW1";

    inline constexpr std::uint32_t kEtwArchiveLegacyFileVersion = 1;

    inline constexpr std::uint32_t kEtwArchiveFileVersion = 2;

    inline constexpr std::uint32_t kEtwArchiveRowVersion = 2;

    inline constexpr std::uint32_t kEtwArchiveMaximumRecordBytes = 64U * 1024U * 1024U;

    inline constexpr qsizetype kEtwArchiveWriteBufferBytes = 1024 * 1024;

    inline constexpr std::uint32_t kEtwArchiveMaximumBlockBytes =
        kEtwArchiveMaximumRecordBytes + static_cast<std::uint32_t>(kEtwArchiveWriteBufferBytes)
        + static_cast<std::uint32_t>(sizeof(quint32));

    inline constexpr std::uint32_t kEtwArchiveMaximumStoredBlockBytes =
        kEtwArchiveMaximumBlockBytes + 1024U * 1024U;

    using EtwFilterFieldId = MonitorDock::EtwFilterFieldId;

    using EtwFilterFieldType = MonitorDock::EtwFilterFieldType;

    using EtwStringMatchMode = MonitorDock::EtwStringMatchMode;

    using EtwFilterStage = MonitorDock::EtwFilterStage;

    inline constexpr const char* kEtwFilterConfigRelativePath = "config/etw_filter.cfg";

    struct EtwPresetProviderDescriptor
    {
        QString categoryText;
        QString providerNameText;
        ULONG legacyKernelEnableFlags = 0;
    };

    inline constexpr GUID kKswordEtwKernelSessionGuid =
        { 0x0c3225e0, 0x7f4b, 0x4c2a, { 0x96, 0xae, 0x18, 0x23, 0x47, 0x42, 0xe6, 0xca } };

    inline constexpr GUID kWindowsKernelTraceProviderGuid =
        { 0x9e814aad, 0x3204, 0x11d2, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };

    // EtwSchemaPropertyEntry：
    // - Purpose: Cache the type, length policy, and semantic description of a single ETW top-level property;
    // - Call: Built once by TDH on the first hit of an event type, then directly reused subsequently.
    struct EtwSchemaPropertyEntry
    {
        ULONG propertyIndex = 0;               // propertyIndex: Property index, referenced by ParamLength/ParamCount.
        QString propertyNameText;              // propertyNameText: The original property name.
        QString normalizedNameText;            // normalizedNameText: Normalized attribute name (letters and digits only, lowercase).
        QString meaningText;                   // meaningText: Human-readable semantics for common attributes.
        USHORT inType = TDH_INTYPE_NULL;       // inType: TDH input type.
        USHORT outType = TDH_OUTTYPE_NULL;     // outType: TDH output type.
        USHORT fixedLength = 0;                // fixedLength: The fixed length of the attribute (if present).
        USHORT fixedCount = 0;                 // fixedCount: The number of fixed attribute arrays (if any).
        ULONG flags = 0;                       // flags: A bit set of PropertyFlags.
        bool isStruct = false;                 // isStruct: whether a structure property.
        bool useLengthProperty = false;        // useLengthProperty: Whether the length comes from the preceding property.
        bool useCountProperty = false;         // useCountProperty: Whether the count originates from a preceding property.
        ULONG lengthPropertyIndex = 0;         // lengthPropertyIndex: Index of the source property for length.
        ULONG countPropertyIndex = 0;          // countPropertyIndex: Index of the source property for the count.
    };

    // EtwSchemaEntry：
    // - Purpose: Cache event metadata corresponding to 'Provider + EventId + Version + Task + Opcode';
    // - Invocation: In the ETW callback, first check this cache; if hit, do not call TdhGetEventInformation again.
    struct EtwSchemaEntry
    {
        QString cacheKeyText;                               // cacheKeyText: Event type cache key.
        QString eventNameText;                              // eventNameText: Event name.
        QString taskNameText;                               // taskNameText: Task name.
        QString opcodeNameText;                             // opcodeNameText: Opcode name.
        std::vector<EtwSchemaPropertyEntry> propertyList;   // propertyList: Top-level property layout and semantic cache.
    };

    // EtwDecodedPropertyEntry：
    // - Purpose: Save the decoded result for a specific attribute within a single event.
    // - Called: Used to construct 'event data (JSON)' and the 'view detailed return' window content.
    struct EtwDecodedPropertyEntry
    {
        QString propertyNameText;              // propertyNameText: Property name.
        QString normalizedNameText;            // normalizedNameText: Normalized attribute name.
        QString meaningText;                   // meaningText: Attribute semantics.
        QString inTypeText;                    // inTypeText: Type text.
        QString valueText;                     // valueText: human-readable value.
        QString hexPreviewText;                // hexPreviewText: Hexadecimal preview of raw bytes.
        ULONG beginOffset = 0;                 // beginOffset: Attribute starting offset (relative to UserData).
        ULONG endOffset = 0;                   // endOffset: Property end offset (exclusive).
        bool numericAvailable = false;         // numericAvailable: Whether a numeric value was parsed.
        std::uint64_t numericValue = 0;        // numericValue: Numeric format, used for length reference/semantic analysis.
        bool parseFallback = false;            // parseFallback: indicates whether fallback parsing was used.
    };

    // EtwSemanticSummary：
    // - Purpose: Aggregates common semantic information such as 'resource type / action / target / status'.
    // - Call: Displayed at the top level of the ETW detail JSON for quick reading.
    struct EtwSemanticSummary
    {
        QString resourceTypeText;              // resourceTypeText: Resource type (file, registry, network, etc.).
        QString actionText;                    // actionText: Action type (open/create/delete, etc.).
        QString targetText;                    // targetText: The target object (path, key name, endpoint, etc.).
        QString statusText;                    // statusText: status code or result text.
    };

    extern std::mutex gEtwSchemaCacheMutex;

    extern std::unordered_map<std::string, EtwSchemaEntry> gEtwSchemaCacheByKey;

    QByteArray serializeEtwArchiveRow(const MonitorDock::EtwCapturedEventRow& row);

    bool deserializeEtwArchiveRow(
        const QByteArray& payload,
        MonitorDock::EtwCapturedEventRow* rowOut);

    QByteArray buildEtwArchiveFileHeader();

    bool writeAllToHandle(const HANDLE fileHandle, const QByteArray& data);

    bool writeEtwArchiveBlockToHandle(const HANDLE fileHandle, const QByteArray& uncompressedData);

    bool scanEtwArchiveFile(
        const QString& filePath,
        const std::function<bool(const MonitorDock::EtwCapturedEventRow&)>& rowVisitor,
        const std::function<bool()>& shouldCancel,
        std::uint64_t* scannedRowsInOut,
        std::uint64_t* maxSequenceInOut,
        QString* errorTextOut);

    QString blueButtonStyle();

    QString blueInputStyle();

    void installMonitorTableCopyMenu(QTableWidget* tableWidget);

    void installMonitorTableViewCopyMenu(QTableView* tableView);

    QWidget* createMonitorDeferredPlaceholder(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText);

    QString blueHeaderStyle();

    QString collapsePanelStyle();

    QString collapseHeaderButtonStyle();

    QWidget* createIndependentCollapseSection(
        QWidget* parent,
        const QString& titleText,
        QWidget* contentWidget,
        const bool expanded);

    void refreshIndependentCollapseTheme(QWidget* rootWidget);

    void stopActiveKswordTraceSessionsByPrefix(const QStringList& sessionPrefixList);

    QString bytesPerSecondToText(const double bytesPerSecondValue);

    std::uint64_t fileTimeToUint64(const FILETIME& fileTimeValue);

    bool initCom(QString* errorOut);

    QString variantToText(const VARIANT& value);

    bool textMatch(
        const QString& sourceText,
        const QString& patternText,
        const bool useRegex,
        const Qt::CaseSensitivity caseSensitivity);

    bool connectWmi(IWbemServices** serviceOut, QString* errorOut);

    QString guidToText(const GUID& guidValue);

    bool parsePid(const QString& text, std::uint32_t& pidOut);

    void openProcessDetail(QWidget* parent, std::uint32_t pid);

    std::uint64_t currentSystemTime100ns();

    QString now100nsText();

    bool parseGuidText(const QString& text, GUID& guidOut);

    UCHAR etwLevelFromText(const QString& levelText);

    ULONGLONG parseKeywordMaskText(const QString& maskText);

    const std::vector<EtwPresetProviderDescriptor>& etwPresetProviderDescriptorList();

    const EtwPresetProviderDescriptor* findEtwPresetProviderDescriptor(const QString& providerNameText);

    const QStringList& etwSimpleActionList();

    QString etwFilterStageText(const EtwFilterStage stage);

    QString etwInferProviderCategory(const QString& providerNameText);

    QString etwTimelineTypeFromCapturedRow(const MonitorDock::EtwCapturedEventRow& rowData);

    const EtwFilterFieldDescriptor* findEtwFilterFieldDescriptorById(const EtwFilterFieldId fieldId);

    QStringList splitEtwFilterTokens(const QString& inputText);

    bool tryParseUInt64Text(const QString& text, std::uint64_t& valueOut);

    bool tryParseUInt64RangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterNumericRange& rangeOut);

    bool tryParsePortRangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterPortRange& rangeOut);

    bool tryParseIpv4Text(const QString& text, std::uint32_t& valueOut);

    bool tryParseIpv4RangeToken(
        const QString& tokenText,
        MonitorDock::EtwFilterIpRange& rangeOut);

    QString etwFilterRegexPatternFromToken(const QString& tokenText, const EtwStringMatchMode mode);

    QString etwFilterLevelTextFromValue(const int levelValue);

    bool etwRegexAnyMatch(
        const QString& valueText,
        const std::vector<QRegularExpression>& regexList);

    bool etwNumericInRanges(
        const std::uint64_t value,
        const std::vector<MonitorDock::EtwFilterNumericRange>& rangeList);

    bool etwIpInRanges(
        const std::uint32_t value,
        const std::vector<MonitorDock::EtwFilterIpRange>& rangeList);

    bool etwPortInRanges(
        const std::uint16_t value,
        const std::vector<MonitorDock::EtwFilterPortRange>& rangeList);

    QString etwSingleLineOrEmpty(const QString& valueText);

    QString etwFieldTextValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        const bool detailVisibleOnly,
        const bool detailAllFields);

    bool etwFieldNumericValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint64_t* valueOut);

    bool etwFieldIpValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint32_t* valueOut);

    bool etwFieldPortValue(
        const MonitorDock::EtwCapturedEventRow& rowData,
        const MonitorDock::EtwFilterFieldId fieldId,
        std::uint16_t* valueOut);

    bool etwFilterFieldMatches(
        const MonitorDock::EtwFilterRuleFieldCompiled& fieldRule,
        const MonitorDock::EtwCapturedEventRow& rowData,
        const bool detailVisibleOnly,
        const bool detailAllFields);

    bool etwFilterGroupMatches(
        const MonitorDock::EtwFilterRuleGroupCompiled& groupRule,
        const MonitorDock::EtwCapturedEventRow& rowData);

    QStringList splitEtwSimpleFilterTokens(const QString& inputText);

    bool etwTextContainsAnyToken(const QString& valueText, const QStringList& tokenList);

    bool etwAnyTextValueContainsAnyToken(
        const std::initializer_list<const QString*> valueList,
        const QStringList& tokenList);

    bool etwSimpleProviderMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData);

    bool etwSimplePidMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData);

    bool etwSimpleFilterMatchesHeaderFields(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData,
        bool* decodedPayloadRequiredOut);

    bool etwSimpleFilterMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const MonitorDock::EtwCapturedEventRow& rowData);

    bool etwDetailedFilterMatches(
        const std::vector<MonitorDock::EtwFilterRuleGroupCompiled>& groupList,
        const MonitorDock::EtwCapturedEventRow& rowData);

    bool etwFilterStageMatches(
        const MonitorDock::EtwSimpleFilterCompiled& simpleFilter,
        const std::vector<MonitorDock::EtwFilterRuleGroupCompiled>& detailedGroupList,
        const MonitorDock::EtwCapturedEventRow& rowData);

    QString normalizeEtwPropertyName(const QString& propertyNameText);

    QString etwPropertyMeaningText(const QString& normalizedNameText);

    QString etwTypeText(const USHORT inTypeValue);

    QString etwTextAtOffset(const unsigned char* infoBufferPointer, const ULONG offsetValue);

    QString etwHexPreview(const unsigned char* dataPointer, const ULONG dataSize, const ULONG maxBytes = 64);

    QString etwHexDump(const unsigned char* dataPointer, const ULONG dataSize, const ULONG maxBytes = 512);

    std::string etwSchemaKeyFromRecord(const EVENT_RECORD* eventRecord);

    void clearEtwSchemaCache();

    bool tryBuildEtwSchemaByTdh(const EVENT_RECORD* eventRecord, EtwSchemaEntry* schemaOut);

    bool tryGetEtwSchemaCached(const EVENT_RECORD* eventRecord, EtwSchemaEntry* schemaOut);

    ULONG etwPointerSizeByHeader(const EVENT_RECORD* eventRecord);

    ULONG etwFixedTypeSize(const USHORT inTypeValue, const ULONG pointerSize);

    QString etwUnicodeBytesToText(const unsigned char* dataPointer, const ULONG dataSize);

    QString etwAnsiBytesToText(const unsigned char* dataPointer, const ULONG dataSize);

    bool tryConsumeUnicodeString(
        const unsigned char* dataPointer,
        const ULONG availableBytes,
        const ULONG explicitLengthBytes,
        QString* textOut,
        ULONG* consumedOut);

    bool tryConsumeAnsiString(
        const unsigned char* dataPointer,
        const ULONG availableBytes,
        const ULONG explicitLengthBytes,
        QString* textOut,
        ULONG* consumedOut);

    bool decodeEtwPropertiesBySchema(
        const EVENT_RECORD* eventRecord,
        const EtwSchemaEntry& schemaEntry,
        std::vector<EtwDecodedPropertyEntry>* decodedPropertyListOut,
        ULONG* parsedBytesOut,
        QString* unparsedTailHexOut);

    bool etwPropertyValueMeaningful(const QString& valueText);

    const EtwDecodedPropertyEntry* findFirstEtwProperty(
        const std::vector<EtwDecodedPropertyEntry>& propertyList,
        const QStringList& normalizedNameList);

    QString inferEtwResourceType(const QString& providerNameText, const QString& eventNameText);

    QString inferEtwActionText(const QString& eventNameText, const QString& opcodeNameText);

    QString etwIpv4TextFromNumeric(const std::uint32_t addressValue);

    QString etwToSingleLine(const QString& valueText);

    QString appendEtwStatusSummary(const QString& summaryText, const QString& statusText);

    EtwSemanticSummary inferEtwSemanticSummary(
        const QString& providerNameText,
        const QString& eventNameText,
        const QString& opcodeNameText,
        const std::vector<EtwDecodedPropertyEntry>& propertyList);

    QString buildEtwSummaryText(
        const QString& providerNameText,
        const QString& eventNameText,
        const QString& opcodeNameText,
        const std::uint32_t pidValue,
        const std::uint32_t tidValue,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList);

    QString buildEtwSummaryFromDetailJson(
        const QString& detailJsonText,
        const QString& providerNameText,
        const QString& eventNameText,
        const std::uint32_t pidValue,
        const std::uint32_t tidValue);

    QString buildEtwDetailJson(
        const EVENT_RECORD* eventRecord,
        const QString& providerGuidText,
        const QString& providerNameText,
        const EtwSchemaEntry& schemaEntry,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList,
        const ULONG parsedBytes,
        const QString& unparsedTailHexText);

    QString etwPropertySingleLineValue(const EtwDecodedPropertyEntry* propertyPointer);

    bool etwPropertyToUInt32(const EtwDecodedPropertyEntry* propertyPointer, std::uint32_t* valueOut);

    bool etwPropertyToUInt16(const EtwDecodedPropertyEntry* propertyPointer, std::uint16_t* valueOut);

    void etwAssignIpFieldFromProperty(
        const EtwDecodedPropertyEntry* propertyPointer,
        QString* textOut,
        std::uint32_t* numericOut,
        bool* validOut);

    QString etwInferNetworkProtocol(
        const QString& providerNameText,
        const QString& eventNameText,
        const EtwDecodedPropertyEntry* protocolProperty);

    QString etwInferNetworkDirection(
        const QString& eventNameText,
        const EtwDecodedPropertyEntry* directionProperty,
        const EtwDecodedPropertyEntry* opcodeProperty);

    void fillEtwCapturedRowDecodedFields(
        MonitorDock::EtwCapturedEventRow* rowOut,
        const QString& providerNameText,
        const QString& eventNameText,
        const EtwSemanticSummary& semanticSummary,
        const std::vector<EtwDecodedPropertyEntry>& propertyList);

    QString etwTimestamp100nsText(const EVENT_RECORD* eventRecord);

    QString buildEtwRowDetailText(QTableWidget* eventTable, const int row);

    QString buildWmiRowDetailText(QTableWidget* eventTable, const int row);

    // etwReadScalar：
    // - Purpose: Safely reads a fixed-width scalar from a byte buffer.
    // - Call: decoding attribute values and reading length parameters.
    template <typename TValue>
    bool etwReadScalar(const unsigned char* dataPointer, const ULONG dataSize, TValue* valueOut)
    {
        if (dataPointer == nullptr || valueOut == nullptr || dataSize < sizeof(TValue))
        {
            return false;
        }

        TValue localValue{};
        std::memcpy(&localValue, dataPointer, sizeof(TValue));
        *valueOut = localValue;
        return true;
    }
}
