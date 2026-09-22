#include "HandleDock.h"

#include "HandleObjectTypeWorker.h"
#include "../../../shared/platform/file/FileHandleTools.h"

#include <QChar>
#include <QStringList>

#include <chrono>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

HandleDock::HandleRefreshResult HandleDock::buildHandleRefreshResult(const HandleRefreshOptions& options)
{
    HandleRefreshResult result{};
    result.snapshotScopedToPid = options.hasPidFilter;
    result.scopedProcessId = options.hasPidFilter ? options.pidFilter : 0U;

    // Translate the UI-facing refresh options into the shared ks::file backend contract.
    // Keyword, only-named, and diff filters remain local UI filters in HandleDock.Filter.cpp.
    ks::file::HandleSnapshotOptions backendOptions{};
    backendOptions.hasPidFilter = options.hasPidFilter;
    backendOptions.pidFilter = options.pidFilter;
    backendOptions.typeFilterText = options.typeFilterText.toStdWString();
    backendOptions.resolveObjectName = options.resolveObjectName;
    backendOptions.nameResolveBudget = options.nameResolveBudget;
    backendOptions.typeNameCacheByIndex = options.typeNameCacheByIndex;
    backendOptions.typeNameMapFromObjectTab = options.typeNameMapFromObjectTab;

    auto toBackendMode = [](const HandleEnumMode mode) -> ks::file::HandleEnumMode
    {
        switch (mode)
        {
        case HandleEnumMode::kUserSnapshot: return ks::file::HandleEnumMode::kUserSnapshot;
        case HandleEnumMode::kDuplicateHandle: return ks::file::HandleEnumMode::kDuplicateHandle;
        case HandleEnumMode::kKernelHandleTable: return ks::file::HandleEnumMode::kKernelHandleTable;
        default: return ks::file::HandleEnumMode::kDuplicateHandle;
        }
    };
    auto fromBackendMode = [](const ks::file::HandleEnumMode mode) -> HandleEnumMode
    {
        switch (mode)
        {
        case ks::file::HandleEnumMode::kUserSnapshot: return HandleEnumMode::kUserSnapshot;
        case ks::file::HandleEnumMode::kDuplicateHandle: return HandleEnumMode::kDuplicateHandle;
        case ks::file::HandleEnumMode::kKernelHandleTable: return HandleEnumMode::kKernelHandleTable;
        default: return HandleEnumMode::kDuplicateHandle;
        }
    };
    auto fromBackendDiff = [](const ks::file::HandleDiffStatus status) -> HandleDiffStatus
    {
        switch (status)
        {
        case ks::file::HandleDiffStatus::kNotCompared: return HandleDiffStatus::kNotCompared;
        case ks::file::HandleDiffStatus::kUserOnly: return HandleDiffStatus::kUserOnly;
        case ks::file::HandleDiffStatus::kKernelOnly: return HandleDiffStatus::kKernelOnly;
        case ks::file::HandleDiffStatus::kBoth: return HandleDiffStatus::kBoth;
        default: return HandleDiffStatus::kNotCompared;
        }
    };
    backendOptions.enumMode = toBackendMode(options.enumMode);

    const ks::file::HandleSnapshotResult kBackendResult = ks::file::buildHandleSnapshot(backendOptions);

    // Copy aggregate statistics verbatim so existing status-bar and log text remain stable.
    result.totalHandleCount = kBackendResult.totalHandleCount;
    result.visibleHandleCount = kBackendResult.visibleHandleCount;
    result.basicInfoResolvedCount = kBackendResult.basicInfoResolvedCount;
    result.resolvedNameCount = kBackendResult.resolvedNameCount;
    result.fallbackNameCount = kBackendResult.fallbackNameCount;
    result.objectTypeMappedCount = kBackendResult.objectTypeMappedCount;
    result.kernelHandleCount = kBackendResult.kernelHandleCount;
    result.userOnlyCount = kBackendResult.userOnlyCount;
    result.kernelOnlyCount = kBackendResult.kernelOnlyCount;
    result.bothCount = kBackendResult.bothCount;
    result.elapsedMs = kBackendResult.elapsedMs;
    result.diagnosticText = QString::fromStdWString(kBackendResult.diagnosticText);
    result.updatedTypeNameCacheByIndex = kBackendResult.updatedTypeNameCacheByIndex;

    result.availableTypeList.reserve(kBackendResult.availableTypeList.size());
    for (const std::wstring& typeNameText : kBackendResult.availableTypeList)
    {
        result.availableTypeList.push_back(QString::fromStdWString(typeNameText));
    }

    result.rows.reserve(kBackendResult.rows.size());
    for (const ks::file::HandleSnapshotRow& backendRow : kBackendResult.rows)
    {
        HandleRow row{};
        row.processId = backendRow.processId;
        row.processCreationTime = backendRow.processCreationTime;
        row.processName = QString::fromStdWString(backendRow.processName);
        row.handleValue = backendRow.handleValue;
        row.typeIndex = backendRow.typeIndex;
        row.typeName = QString::fromStdWString(backendRow.typeName);
        row.objectName = QString::fromStdWString(backendRow.objectName);
        row.objectAddress = backendRow.objectAddress;
        row.grantedAccess = backendRow.grantedAccess;
        row.attributes = backendRow.attributes;
        row.handleCount = backendRow.handleCount;
        row.pointerCount = backendRow.pointerCount;
        row.basicInfoAvailable = backendRow.basicInfoAvailable;
        row.objectNameAvailable = backendRow.objectNameAvailable;
        row.objectNameFailed = backendRow.objectNameFailed;
        row.objectNameFromFallback = backendRow.objectNameFromFallback;
        row.sourceMode = fromBackendMode(backendRow.sourceMode);
        row.diffStatus = fromBackendDiff(backendRow.diffStatus);
        row.decodeStatus = backendRow.decodeStatus;
        row.r0FieldFlags = backendRow.r0FieldFlags;
        row.r0DynDataCapabilityMask = backendRow.r0DynDataCapabilityMask;
        row.epObjectTableOffset = backendRow.epObjectTableOffset;
        row.htHandleContentionEventOffset = backendRow.htHandleContentionEventOffset;
        row.obDecodeShift = backendRow.obDecodeShift;
        row.obAttributesShift = backendRow.obAttributesShift;
        row.otNameOffset = backendRow.otNameOffset;
        row.otIndexOffset = backendRow.otIndexOffset;
        result.rows.push_back(std::move(row));
    }

    return result;
}

HandleDock::ObjectTypeRefreshResult HandleDock::buildObjectTypeRefreshResult()
{
    ObjectTypeRefreshResult result{};
    const auto kBeginTime = std::chrono::steady_clock::now();

    QString errorText;
    std::vector<HandleObjectTypeEntry> rows;
    runHandleObjectTypeSnapshotTask(rows, errorText);
    result.rows = std::move(rows);
    result.typeNameMapByIndex = buildTypeNameMapFromObjectTypeRows(result.rows);
    result.diagnosticText = errorText;
    result.elapsedMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - kBeginTime).count());
    return result;
}

bool HandleDock::closeRemoteHandle(const HandleRow& expectedRow, std::string& detailTextOut)
{
    // The close action binds the process creation time and object address in the refreshed row, rejecting stale rows after PID/Handle reuse.
    return ks::file::closeRemoteHandleByObjectIdentity(
        expectedRow.processId,
        expectedRow.handleValue,
        expectedRow.processCreationTime,
        expectedRow.objectAddress,
        detailTextOut);
}

QString HandleDock::formatHex(const std::uint64_t value, const int width)
{
    if (width > 0)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), width, 16, QChar('0'))
            .toUpper();
    }
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(value), 0, 16)
        .toUpper();
}

QString HandleDock::formatOptionalObjectCount(
    const std::uint32_t countValue,
    const bool countAvailable)
{
    if (!countAvailable)
    {
        return QStringLiteral("未查到");
    }
    return QString::number(countValue);
}

QString HandleDock::formatObjectNameDisplayText(const HandleRow& row)
{
    if (row.objectNameAvailable)
    {
        if (row.objectName.trimmed().isEmpty())
        {
            return QStringLiteral("无名称");
        }
        return row.objectName;
    }

    if (row.objectNameFailed)
    {
        return QStringLiteral("未查到");
    }

    return QStringLiteral("未查询");
}

QString HandleDock::formatHandleSourceText(const HandleEnumMode mode)
{
    switch (mode)
    {
    case HandleEnumMode::kUserSnapshot:
        return QStringLiteral("User Snapshot");
    case HandleEnumMode::kDuplicateHandle:
        return QStringLiteral("DuplicateHandle");
    case HandleEnumMode::kKernelHandleTable:
        return QStringLiteral("Kernel HandleTable");
    default:
        return QStringLiteral("Unknown");
    }
}

QString HandleDock::formatHandleDecodeStatusText(const std::uint32_t status)
{
    switch (status)
    {
    case KSWORD_ARK_HANDLE_DECODE_STATUS_OK:
        return QStringLiteral("OK");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL:
        return QStringLiteral("Partial");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_DYNDATA_MISSING:
        return QStringLiteral("DynData Missing");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_LOOKUP_FAILED:
        return QStringLiteral("Process Lookup Failed");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_EXITING:
        return QStringLiteral("Process Exiting");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_HANDLE_TABLE_MISSING:
        return QStringLiteral("HandleTable Missing");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_OBJECT_DECODE_FAILED:
        return QStringLiteral("Object Decode Failed");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_TYPE_DECODE_FAILED:
        return QStringLiteral("Type Decode Failed");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_READ_FAILED:
        return QStringLiteral("Read Failed");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_BUFFER_TOO_SMALL:
        return QStringLiteral("Buffer Too Small");
    case KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE:
    default:
        return QStringLiteral("Unavailable");
    }
}

QString HandleDock::formatHandleDiffStatusText(const HandleDiffStatus status)
{
    switch (status)
    {
    case HandleDiffStatus::kUserOnly:
        return QStringLiteral("仅用户态可见");
    case HandleDiffStatus::kKernelOnly:
        return QStringLiteral("仅内核可见");
    case HandleDiffStatus::kBoth:
        return QStringLiteral("两者均可见");
    case HandleDiffStatus::kNotCompared:
    default:
        return QStringLiteral("未对比");
    }
}

QString HandleDock::formatTypeIndexDisplayText(
    const std::uint16_t typeIndex,
    const QString& typeName)
{
    const QString kTrimmedTypeName = typeName.trimmed();
    const QString kFallbackTypeText = QStringLiteral("Type#%1").arg(typeIndex);
    if (kTrimmedTypeName.isEmpty() ||
        kTrimmedTypeName.compare(kFallbackTypeText, Qt::CaseInsensitive) == 0 ||
        kTrimmedTypeName.startsWith(QStringLiteral("<UnknownType_"), Qt::CaseInsensitive))
    {
        return QString::number(typeIndex);
    }

    return QStringLiteral("%1 (%2)")
        .arg(kTrimmedTypeName)
        .arg(typeIndex);
}

QString HandleDock::formatHandleAttributes(const std::uint32_t attributes)
{
    QStringList flagTextList;
    if ((attributes & 0x00000001U) != 0)
    {
        flagTextList.push_back(QStringLiteral("PROTECT"));
    }
    if ((attributes & 0x00000002U) != 0)
    {
        flagTextList.push_back(QStringLiteral("INHERIT"));
    }
    if ((attributes & 0x00000004U) != 0)
    {
        flagTextList.push_back(QStringLiteral("AUDIT"));
    }
    if (flagTextList.isEmpty())
    {
        return QStringLiteral("None");
    }
    return flagTextList.join('|');
}

HandleDock::HandleEnumMode HandleDock::resolveHandleEnumModeFromText(const QString& modeText)
{
    const QString kNormalizedText = modeText.trimmed().toLower();
    if (kNormalizedText.contains(QStringLiteral("kernel")))
    {
        return HandleEnumMode::kKernelHandleTable;
    }
    if (kNormalizedText.contains(QStringLiteral("duplicate")))
    {
        return HandleEnumMode::kDuplicateHandle;
    }
    return HandleEnumMode::kUserSnapshot;
}

HandleDock::HandleDiffStatus HandleDock::resolveHandleDiffFilterFromText(const QString& filterText)
{
    const QString kNormalizedText = filterText.trimmed().toLower();
    if (kNormalizedText.contains(QStringLiteral("仅用户")) || kNormalizedText.contains(QStringLiteral("user")))
    {
        return HandleDiffStatus::kUserOnly;
    }
    if (kNormalizedText.contains(QStringLiteral("仅内核")) || kNormalizedText.contains(QStringLiteral("kernel")))
    {
        return HandleDiffStatus::kKernelOnly;
    }
    if (kNormalizedText.contains(QStringLiteral("两者")) || kNormalizedText.contains(QStringLiteral("both")))
    {
        return HandleDiffStatus::kBoth;
    }
    return HandleDiffStatus::kNotCompared;
}
