#include "KernelDock.h"
#include "../ui/TableInteractionSupport.h"

#include <memory>
#include "../ui/VisibleTableWidget.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/CodeEditorWidget.h"
#include "../../../shared/platform/profile/ProfileJsonLoader.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QByteArray>
#include <QClipboard>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdint>
#include <limits>
#include <thread>
#include <unordered_map>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // DynDataColumn：
    // - Purpose: Define the column index for dynamic offset fields.
    // - Purpose: Use `enum class` to prevent magic numbers from leaking into rendering and read logic.
    enum class DynDataColumn : int
    {
        kField = 0,
        kOffset,
        kStatus,
        kSource,
        kFeature,
        kCapability,
        kCount
    };

    // SummaryColumn：
    // - Purpose: Define the two-column layout for the summary table;
    // - Field/Value mode facilitates adding R0 diagnostic items.
    enum class SummaryColumn : int
    {
        kName = 0,
        kValue,
        kCount
    };

    // CapabilityDisplay：
    // - Purpose: Bind capability bits to UI text;
    // - Processing logic: reuse the same table when refreshing the summary and field details.
    struct CapabilityDisplay
    {
        std::uint64_t mask = 0;      // mask: Single KSW_CAP_* bit.
        const char* name = nullptr;  // name: stable English name.
        const wchar_t* title = nullptr; // title: Chinese functional description.
        const char* contextKey = nullptr;
    };

    // LocalPdbProfile：
    // - Purpose: Save the result of parsing a local JSON profile.
    // - Input source: profiles/ark_dyndata/*.json
    // - Return behavior: serves as input to DriverClient::applyDynDataProfile; does not hold the PDB file.
    struct LocalPdbProfile
    {
        bool valid = false;                              // valid: Whether R3 syntax and range checks passed.
        bool matched = false;                            // matched: Whether the module identity exactly matches the current ntoskrnl.
        std::uint32_t ignoredUnknownFields = 0;          // ignoredUnknownFields: Count of fields in JSON unrecognized by R3.
        QString sourceText;                              // sourceText: Profile source; distinguishes between pack and scattered JSON.
        QString pathText;                                // pathText: Profile file path.
        QString diagnosticsText;                         // diagnosticsText: Parsing and validation diagnostics.
        ksword::ark::DynDataProfileApplyInput applyInput; // applyInput: A v1 profile that can be directly packaged for R0.
        ksword::ark::DynDataProfileApplyExInput applyExInput; // applyExInput: can be directly packaged for R0 v2/v3 typed-item profile.
        ksword::ark::DynDataV4ApplyInput applyV4Input;    // applyV4Input: A stable item profile directly sendable to the R0 v4 storage layer.
        std::uint32_t exAppliedCount = 0;               // exAppliedCount: count of v2/v3 typed items.
        std::uint32_t callbackItemCount = 0;            // callbackItemCount: Original count of callbackItems entries.
        std::uint32_t typedItemCount = 0;               // typedItemCount: Number of v3 items/typedItems entries.
        std::uint32_t v4ItemCount = 0;                  // v4ItemCount: Count of v4 stable items.
    };

    QString safeText(const QString& valueText, const QString& fallbackText);
    QString safeText(const QString& valueText);
    QString formatHex32(std::uint32_t value);
    QString formatHex64(std::uint64_t value);
    QString formatNtStatus(long statusValue);
    QString formatOffset(std::uint32_t offsetValue);
    QString boolText(bool enabled);
    QString moduleClassText(std::uint32_t classId);
    bool statusFlagEnabled(std::uint32_t flags, std::uint32_t flag);

    // v4CountText：
    // - Input returnedCount/totalCount: Returned line count and total line count parsed by ArkDriverClient from the R0 response;
    // - Processing: Unified compression into 'returned / total' text for reuse in profile tables and details.
    // - Returns: Count string ready for direct display.
    QString v4CountText(std::uint32_t returnedCount, std::uint32_t totalCount)
    {
        return QStringLiteral("%1 / %2")
            .arg(returnedCount)
            .arg(totalCount);
    }

    // v4IoStateText：
    // - Input queryOk/unsupported: IO success status and legacy driver compatibility flag from the ArkDriverClient wrapper;
    // - Processing: Convert three status types (transfer success, old driver unsupported, and failure) into short text.
    // - Returns: status text used by the profile summary table.
    QString v4IoStateText(bool queryOk, bool unsupported)
    {
        if (queryOk)
        {
            return kernelText("kernel.dyndata.v4.io.success", QStringLiteral("成功"));
        }

        return unsupported
            ? kernelText("kernel.dyndata.v4.io.unsupported", QStringLiteral("旧驱动不支持"))
            : kernelText("kernel.dyndata.v4.io.failure", QStringLiteral("失败"));
    }

    // appendV4StatusLine：
    // - Input: lines/name/queryOk/unsupported/returnedCount/totalCount/messageText: Single-class v4 query status.
    // - Processing: Append count, IO status, and ArkDriverClient messages to the detail text.
    // - Return: None; lines are appended via reference.
    void appendV4StatusLine(
        QStringList& lines,
        const QString& name,
        bool queryOk,
        bool unsupported,
        std::uint32_t returnedCount,
        std::uint32_t totalCount,
        const QString& messageText)
    {
        lines << QStringLiteral("%1: count=%2, io=%3, message=%4")
            .arg(name)
            .arg(v4CountText(returnedCount, totalCount))
            .arg(v4IoStateText(queryOk, unsupported))
            .arg(safeText(messageText));
    }

    // appendV4ProfileSummaryLines：
    // - Input lines/summary: detail text buffer and DynData summary snapshot;
    // - Processing: Append four groups of read-only query statuses: v4 modules, capability groups, missing items, and accepted items.
    // - Return: None; lines are appended via reference.
    void appendV4ProfileSummaryLines(QStringList& lines, const KernelDynDataSummary& summary)
    {
        lines << QStringLiteral("");
        lines << QStringLiteral("DynData V4 profile query status:");
        appendV4StatusLine(
            lines,
            QStringLiteral("modules"),
            summary.dynDataV4ModulesQueryOk,
            summary.dynDataV4ModulesUnsupported,
            summary.dynDataV4ModulesReturnedCount,
            summary.dynDataV4ModulesTotalCount,
            summary.dynDataV4ModulesIoMessageText);
        appendV4StatusLine(
            lines,
            QStringLiteral("capability groups"),
            summary.dynDataV4CapabilityGroupsQueryOk,
            summary.dynDataV4CapabilityGroupsUnsupported,
            summary.dynDataV4CapabilityGroupsReturnedCount,
            summary.dynDataV4CapabilityGroupsTotalCount,
            summary.dynDataV4CapabilityGroupsIoMessageText);
        appendV4StatusLine(
            lines,
            QStringLiteral("missing items"),
            summary.dynDataV4MissingItemsQueryOk,
            summary.dynDataV4MissingItemsUnsupported,
            summary.dynDataV4MissingItemsReturnedCount,
            summary.dynDataV4MissingItemsTotalCount,
            summary.dynDataV4MissingItemsIoMessageText);
        appendV4StatusLine(
            lines,
            QStringLiteral("accepted items"),
            summary.dynDataV4ItemsQueryOk,
            summary.dynDataV4ItemsUnsupported,
            summary.dynDataV4ItemsReturnedCount,
            summary.dynDataV4ItemsTotalCount,
            summary.dynDataV4ItemsIoMessageText);
    }

    // v4ItemKindText：
    // - Input itemKind: numeric value of KSW_DYN_V4_ITEM_KIND_* returned by R0;
    // - Processing: Convert to the stable English type name in the schema.
    // - Return: Human-readable table text; unknown values retain numeric representation to facilitate debugging protocol version differences.
    QString v4ItemKindText(const std::uint32_t itemKind)
    {
        switch (itemKind)
        {
        case KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET:
            return QStringLiteral("StructOffset");
        case KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA:
            return QStringLiteral("GlobalRva");
        case KSW_DYN_V4_ITEM_KIND_FUNCTION_RVA:
            return QStringLiteral("FunctionRva");
        case KSW_DYN_V4_ITEM_KIND_ENUM_VALUE:
            return QStringLiteral("EnumValue");
        case KSW_DYN_V4_ITEM_KIND_TYPE_SIZE:
            return QStringLiteral("TypeSize");
        case KSW_DYN_V4_ITEM_KIND_BIT_FIELD:
            return QStringLiteral("BitField");
        case KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL:
            return QStringLiteral("ListHeadGlobal");
        default:
            return QStringLiteral("Unknown(%1)").arg(itemKind);
        }
    }

    // v4ItemFlagsText：
    // - Input: flags: v4 item flags returned by R0.
    // - Processing: Split required/optional bits into human-readable text while retaining the hexadecimal representation.
    // - Returns: Text for the table's "Flags" column.
    QString v4ItemFlagsText(const std::uint32_t flags)
    {
        QStringList parts;
        if ((flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U)
        {
            parts << QStringLiteral("required");
        }
        if ((flags & KSW_DYN_V4_ITEM_FLAG_OPTIONAL) != 0U)
        {
            parts << QStringLiteral("optional");
        }
        if (parts.isEmpty())
        {
            parts << QStringLiteral("none");
        }
        parts << formatHex32(flags);
        return parts.join(QStringLiteral(" / "));
    }

    // v4ItemValueText：
    // - Input item: complete v4 item packet returned by R0;
    // - Handling: Merge valueLow/valueHigh and add offset/RVA/size semantics based on item kind;
    // - Returns: Text for the "Value" column in the table.
    QString v4ItemValueText(const KSW_DYN_V4_ITEM_PACKET& item)
    {
        const std::uint64_t kValue =
            (static_cast<std::uint64_t>(item.valueHigh) << 32U) |
            static_cast<std::uint64_t>(item.valueLow);
        const QString kHexText = formatHex64(kValue);
        switch (item.itemKind)
        {
        case KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET:
            return QStringLiteral("offset %1").arg(kHexText);
        case KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA:
        case KSW_DYN_V4_ITEM_KIND_FUNCTION_RVA:
        case KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL:
            return QStringLiteral("RVA %1").arg(kHexText);
        case KSW_DYN_V4_ITEM_KIND_TYPE_SIZE:
            return QStringLiteral("size %1").arg(kHexText);
        default:
            return kHexText;
        }
    }

    // v4ItemMatchesFilter：
    // - Input entry/filterKeyword: v4 item row and user filter text;
    // - Processing: Perform substring matching in module, kind, id, group, value, and aux text.
    // - Return: true indicates the row should be displayed.
    bool v4ItemMatchesFilter(const KernelDynDataV4ItemEntry& entry, const QString& filterKeyword)
    {
        if (filterKeyword.isEmpty())
        {
            return true;
        }

        const QString kHaystack = QStringLiteral("%1 %2 %3 %4 %5 %6 %7")
            .arg(moduleClassText(entry.moduleClassId))
            .arg(entry.kindText)
            .arg(entry.itemId)
            .arg(entry.itemIndex)
            .arg(entry.capabilityGroupId)
            .arg(formatHex64(entry.value))
            .arg(entry.auxText);
        return kHaystack.contains(filterKeyword, Qt::CaseInsensitive);
    }

    // profileSummaryText：
    // - Input summary: Current DynData summary;
    // - Processing: Assemble compact descriptions for the profile status page.
    // - Returns: multi-line text.
    QString profileSummaryText(const KernelDynDataSummary& summary)
    {
        QStringList lines;
        lines << QStringLiteral("ntoskrnl: %1").arg(safeText(summary.ntoskrnl.moduleNameText));
        lines << QStringLiteral("classId: %1").arg(moduleClassText(summary.ntoskrnl.classId));
        lines << QStringLiteral("machine: %1").arg(formatHex32(summary.ntoskrnl.machine));
        lines << QStringLiteral("timeDateStamp: %1").arg(formatHex32(summary.ntoskrnl.timeDateStamp));
        lines << QStringLiteral("sizeOfImage: %1").arg(formatHex32(summary.ntoskrnl.sizeOfImage));
        lines << QStringLiteral("imageBase: %1").arg(formatHex64(summary.ntoskrnl.imageBase));
        lines << QStringLiteral("PDB profile active: %1")
            .arg(boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)));
        lines << QStringLiteral("PDB profile scan attempted: %1").arg(boolText(summary.pdbProfileScanAttempted));
        lines << QStringLiteral("PDB profile found: %1").arg(boolText(summary.pdbProfileFound));
        lines << QStringLiteral("PDB profile applied: %1").arg(boolText(summary.pdbProfileApplied));
        lines << QStringLiteral("PDB profile source: %1").arg(safeText(summary.pdbProfileSourceText));
        lines << QStringLiteral("PDB profile name: %1").arg(safeText(summary.pdbProfileNameText));
        lines << QStringLiteral("PDB profile path: %1").arg(safeText(summary.pdbProfilePathText));
        lines << QStringLiteral("PDB profile status: %1").arg(formatNtStatus(summary.pdbProfileStatus));
        lines << QStringLiteral("PDB profile fields: applied=%1 rejected=%2 unknown=%3 ignoredJson=%4")
            .arg(summary.pdbProfileAppliedFields)
            .arg(summary.pdbProfileRejectedFields)
            .arg(summary.pdbProfileUnknownFields)
            .arg(summary.pdbProfileIgnoredJsonFields);
        lines << QStringLiteral("message: %1").arg(safeText(summary.pdbProfileMessageText));
        lines << QStringLiteral("io: %1").arg(safeText(summary.pdbProfileIoMessageText));
        appendV4ProfileSummaryLines(lines, summary);
        return lines.join(QStringLiteral("\n"));
    }

    // buildProfileReport：
    // - Input summary/rows: current DynData summary and field list;
    // Processing: Compress profile activation info and field statuses into plain text for copying and detailed display.
    // - Returns: The report text.
    QString buildProfileReport(const KernelDynDataSummary& summary, const std::vector<KernelDynDataFieldEntry>& rows)
    {
        QStringList lines;
        lines << QStringLiteral("Ksword DynData PDB Profile Report");
        lines << QStringLiteral("StatusFlags: %1").arg(formatHex32(summary.statusFlags));
        lines << QStringLiteral("CapabilityMask: %1").arg(formatHex64(summary.capabilityMask));
        lines << QStringLiteral("PdbProfileActive: %1").arg(boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)));
        lines << QStringLiteral("PdbProfileScanAttempted: %1").arg(boolText(summary.pdbProfileScanAttempted));
        lines << QStringLiteral("PdbProfileFound: %1").arg(boolText(summary.pdbProfileFound));
        lines << QStringLiteral("PdbProfileApplied: %1").arg(boolText(summary.pdbProfileApplied));
        lines << QStringLiteral("PdbProfileStatus: %1").arg(formatNtStatus(summary.pdbProfileStatus));
        lines << QStringLiteral("PdbProfileAppliedFields: %1").arg(summary.pdbProfileAppliedFields);
        lines << QStringLiteral("PdbProfileRejectedFields: %1").arg(summary.pdbProfileRejectedFields);
        lines << QStringLiteral("PdbProfileUnknownFields: %1").arg(summary.pdbProfileUnknownFields);
        lines << QStringLiteral("PdbProfileIgnoredJsonFields: %1").arg(summary.pdbProfileIgnoredJsonFields);
        lines << QStringLiteral("PdbProfileSource: %1").arg(safeText(summary.pdbProfileSourceText));
        lines << QStringLiteral("PdbProfileName: %1").arg(safeText(summary.pdbProfileNameText));
        lines << QStringLiteral("PdbProfilePath: %1").arg(safeText(summary.pdbProfilePathText));
        lines << QStringLiteral("PdbProfileMessage: %1").arg(safeText(summary.pdbProfileMessageText));
        lines << QStringLiteral("PdbProfileIo: %1").arg(safeText(summary.pdbProfileIoMessageText));
        lines << QStringLiteral("");
        lines << profileSummaryText(summary);
        lines << QStringLiteral("");
        lines << QStringLiteral("Fields:");
        for (const KernelDynDataFieldEntry& entry : rows)
        {
            lines << QStringLiteral("%1\t%2\t%3\t%4\t%5\t%6")
                .arg(safeText(entry.fieldNameText))
                .arg(formatOffset(entry.offset))
                .arg(safeText(entry.statusText))
                .arg(safeText(entry.sourceNameText))
                .arg(safeText(entry.featureNameText))
                .arg(formatHex64(entry.capabilityMask));
        }
        return lines.join(QStringLiteral("\n"));
    }

    // kCapabilities：
    // - Purpose: enumerate all capabilities exposed in Phase 0;
    // - Return behavior: formatted into a summary, details, or missing list by a helper function.
    constexpr std::array<CapabilityDisplay, 23> kCapabilities{ {
        { KSW_CAP_DYN_NTOS_ACTIVE, "KSW_CAP_DYN_NTOS_ACTIVE", L"ntoskrnl profile 已激活", "kernel.driver_status.capability.ntos_active" },
        { KSW_CAP_DYN_LXCORE_ACTIVE, "KSW_CAP_DYN_LXCORE_ACTIVE", L"lxcore profile 已激活", "kernel.driver_status.capability.lxcore_active" },
        { KSW_CAP_OBJECT_TYPE_FIELDS, "KSW_CAP_OBJECT_TYPE_FIELDS", L"对象类型字段", "kernel.driver_status.capability.object_type_fields" },
        { KSW_CAP_HANDLE_TABLE_DECODE, "KSW_CAP_HANDLE_TABLE_DECODE", L"句柄表解码", "kernel.driver_status.capability.handle_table_decode" },
        { KSW_CAP_PROCESS_OBJECT_TABLE, "KSW_CAP_PROCESS_OBJECT_TABLE", L"进程 ObjectTable", "kernel.driver_status.capability.process_object_table" },
        { KSW_CAP_THREAD_STACK_FIELDS, "KSW_CAP_THREAD_STACK_FIELDS", L"线程栈字段", "kernel.driver_status.capability.thread_stack_fields" },
        { KSW_CAP_THREAD_IO_COUNTERS, "KSW_CAP_THREAD_IO_COUNTERS", L"线程 I/O 计数", "kernel.driver_status.capability.thread_io_counters" },
        { KSW_CAP_ALPC_FIELDS, "KSW_CAP_ALPC_FIELDS", L"ALPC 字段", "kernel.driver_status.capability.alpc_fields" },
        { KSW_CAP_SECTION_CONTROL_AREA, "KSW_CAP_SECTION_CONTROL_AREA", L"Section/ControlArea", "kernel.driver_status.capability.section_control_area" },
        { KSW_CAP_PROCESS_PROTECTION_PATCH, "KSW_CAP_PROCESS_PROTECTION_PATCH", L"进程保护修改", "kernel.driver_status.capability.process_protection" },
        { KSW_CAP_WSL_LXCORE_FIELDS, "KSW_CAP_WSL_LXCORE_FIELDS", L"WSL/lxcore 字段", "kernel.driver_status.capability.wsl_lxcore_fields" },
        { KSW_CAP_ETW_GUID_FIELDS, "KSW_CAP_ETW_GUID_FIELDS", L"ETW GUID/Registration 字段", "kernel.driver_status.capability.etw_guid_fields" },
        { KSW_CAP_CALLBACK_NOTIFY_GLOBALS, "KSW_CAP_CALLBACK_NOTIFY_GLOBALS", L"Callback Notify 全局 RVA", "kernel.driver_status.capability.callback_notify_globals" },
        { KSW_CAP_CALLBACK_REGISTRY_GLOBALS, "KSW_CAP_CALLBACK_REGISTRY_GLOBALS", L"Registry Callback 全局 RVA", "kernel.driver_status.capability.callback_registry_globals" },
        { KSW_CAP_CALLBACK_OBJECT_FIELDS, "KSW_CAP_CALLBACK_OBJECT_FIELDS", L"Object Callback 结构偏移", "kernel.driver_status.capability.callback_object_fields" },
        { KSW_CAP_PROCESS_LIST_FIELDS, "KSW_CAP_PROCESS_LIST_FIELDS", L"进程链表字段", "kernel.driver_status.capability.process_list_fields" },
        { KSW_CAP_THREAD_LIST_FIELDS, "KSW_CAP_THREAD_LIST_FIELDS", L"线程链表字段", "kernel.driver_status.capability.thread_list_fields" },
        { KSW_CAP_CID_TABLE_WALK, "KSW_CAP_CID_TABLE_WALK", L"CID 表遍历", "kernel.driver_status.capability.cid_table_walk" },
        { KSW_CAP_KERNEL_MODULE_LIST_FIELDS, "KSW_CAP_KERNEL_MODULE_LIST_FIELDS", L"内核模块链表字段", "kernel.driver_status.capability.kernel_module_list_fields" },
        { KSW_CAP_DRIVER_OBJECT_FIELDS, "KSW_CAP_DRIVER_OBJECT_FIELDS", L"驱动对象字段", "kernel.driver_status.capability.driver_object_fields" },
        { KSW_CAP_KERNEL_GLOBALS, "KSW_CAP_KERNEL_GLOBALS", L"内核全局 RVA", "kernel.driver_status.capability.kernel_globals" },
        { KSW_CAP_TOKEN_INTEGRITY_FIELDS, "KSW_CAP_TOKEN_INTEGRITY_FIELDS", L"Token 完整性字段", "kernel.driver_status.capability.token_integrity_fields" },
        { KSW_CAP_TOKEN_PRIVATE_FIELDS, "KSW_CAP_TOKEN_PRIVATE_FIELDS", L"Token 私有字段", "kernel.driver_status.capability.token_private_fields" }
    } };

    // blueButtonStyle：
    // - Inputs: None;
    // - Processing: Read global theme button styles.
    // - Return: Button style text ready for setStyleSheet.
    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // blueInputStyle：
    // - Inputs: None;
    // - Processing: Concatenate QLineEdit styles using the theme color.
    // - Returns: filter box style text.
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // headerStyle：
    // - Inputs: None;
    // - Processing: concatenate header styles using theme colors;
    // - Returns: style text directly applicable to QHeaderView.
    QString headerStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // itemSelectionStyle：
    // - Inputs: None;
    // - Processing: Unify the table selection state color.
    // - Returns: Table selection style string.
    QString itemSelectionStyle()
    {
        return QString();
    }

    // copyMenuStyle：
    // - Inputs: None;
    // - Processing: Provide an opaque background and a distinct selected state for the DynData table's right-click context menu.
    // - Returns: Style text directly applicable to QMenu.
    QString copyMenuStyle()
    {
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;}"
            "QMenu::item{padding:5px 24px 5px 24px;background:transparent;}"
            "QMenu::item:selected{background:%4;color:palette(highlighted-text);}"
            "QMenu::item:disabled{color:%5;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::textSecondaryHex());
    }

    // tableRowText：
    // - Input table and rowIndex: target table and source row index;
    // - Processing: Read the current text of each column and join them with tabs.
    // - Returns: A TSV row suitable for copying to the clipboard.
    QString tableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    // installDynDataCopyMenu：
    // - Input table: DynData summary, field, or profile table;
    // - Processing: Install a 'Copy Current Row' context menu, compatible with NoSelection summary tables.
    // - Return: None. Read-only copy; does not change driver state.
    void installDynDataCopyMenu(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            const int kRowIndex = kClickedIndex.isValid() ? kClickedIndex.row() : table->currentRow();
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(copyMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                kernelText("kernel.driver_status.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(kRowIndex >= 0 && kRowIndex < table->rowCount());
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                QClipboard* clipboard = QApplication::clipboard();
                if (clipboard != nullptr)
                {
                    clipboard->setText(tableRowText(table, kRowIndex));
                }
            }
        });
    }

    // statusLabelStyle：
    // - Input colorHex: target text color.
    // - Processing: Concatenate QLabel styles.
    // - Returns: Bold status text style.
    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // safeText：
    // - Input: valueText/fallbackText: text to display and fallback text;
    // - Processing: Check for null after trimming leading and trailing whitespace;
    // - Return: non-null original text or fallback placeholder.
    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.dyndata.placeholder.empty", QStringLiteral("<空>")));
    }

    // stringToQString：
    // - Input valueText: UTF-8/ANSI small string returned by ArkDriverClient;
    // - Processing: Convert to UTF-8, compatible with ASCII field names;
    // - Returns: Qt display string.
    QString stringToQString(const std::string& valueText)
    {
        return QString::fromUtf8(valueText.c_str(), static_cast<int>(valueText.size()));
    }

    // friendlyDynDataIoMessage：
    // - Input valueText: io.message from the DynData wrapper;
    // - Processing: Convert low-level IOCTL/unsupported/capability text into human-readable descriptions;
    // - Returns: Text suitable for direct display in the summary table, profile report, and details section.
    QString friendlyDynDataIoMessage(const std::string& valueText)
    {
        const QString kRawText = stringToQString(valueText).trimmed();
        if (kRawText.isEmpty())
        {
            return kernelText("kernel.dyndata.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.dyndata.message.communication_failure", QStringLiteral("驱动通信失败或当前驱动版本不支持该 DynData 查询入口。"));
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.dyndata.message.unsupported", QStringLiteral("当前驱动不支持该 DynData 协议版本。"));
        }
        if (kRawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.dyndata.message.capability", QStringLiteral("DynData 能力未满足，相关运行时详情暂不可用。"));
        }
        return kRawText;
    }

    // wideStringToQString：
    // - Input: valueText: wide string returned by ArkDriverClient;
    // - Processing: Convert using a wchar_t array.
    // - Returns: Qt display string.
    QString wideStringToQString(const std::wstring& valueText)
    {
        return QString::fromWCharArray(valueText.c_str(), static_cast<int>(valueText.size()));
    }

    // formatHex32：
    // - Input value: 32-bit numeric value;
    // - Processing: Pad with zeros and use uppercase hexadecimal.
    // - Return: Text in 0xXXXXXXXX format.
    QString formatHex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
    }

    // formatHex64：
    // - Input value: 64-bit numeric value;
    // - Processing: Pad with zeros and use uppercase hexadecimal.
    // - Returns text in the format: 0xXXXXXXXXXXXXXXXX.
    QString formatHex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0')).toUpper();
    }

    // formatNtStatus：
    // - Input statusValue: NTSTATUS signed long.
    // - Handling: preserve and display the underlying 32-bit value as-is;
    // - Return: Text in 0xXXXXXXXX format.
    QString formatNtStatus(const long statusValue)
    {
        return formatHex32(static_cast<std::uint32_t>(statusValue));
    }

    // formatOffset：
    // - Input offsetValue: field offset;
    // - Processing: Detect DynData unavailable sentinel values.
    // - Returns: A readable offset string or <Unavailable>.
    QString formatOffset(const std::uint32_t offsetValue)
    {
        if (offsetValue == 0xFFFFFFFFU || offsetValue == 0x0000FFFFU)
        {
            return kernelText("kernel.dyndata.placeholder.unavailable", QStringLiteral("<不可用>"));
        }
        return QStringLiteral("0x%1").arg(offsetValue, 4, 16, QChar('0')).toUpper();
    }

    // fieldPresent：
    // - Input flags/offset: R0 field flags and offset value.
    // - Processing: check both PRESENT bit and unavailable sentinel;
    // - Returns: true indicates the field is available.
    bool fieldPresent(const std::uint32_t flags, const std::uint32_t offset)
    {
        return (flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
            offset != 0xFFFFFFFFU &&
            offset != 0x0000FFFFU;
    }

    // statusFlagEnabled：
    // - Input flags/flag: Status bitmap and target bit;
    // - Handling: bitwise check;
    // - Return: true indicates the target state is enabled.
    bool statusFlagEnabled(const std::uint32_t flags, const std::uint32_t flag)
    {
        return (flags & flag) == flag;
    }

    // boolText：
    // - Input enabled: Boolean status.
    // - Processing: Convert to Chinese.
    // - Returns: "Yes" or "No".
    QString boolText(const bool enabled)
    {
        return enabled
            ? kernelText("kernel.driver_status.value.yes", QStringLiteral("是"))
            : kernelText("kernel.driver_status.value.no", QStringLiteral("否"));
    }

    // moduleClassText：
    // - Input classId: KSW_DYN_PROFILE_CLASS_*;
    // - Processing: Convert to UI-readable text.
    // - Returns: profile class text.
    QString moduleClassText(const std::uint32_t classId)
    {
        switch (classId)
        {
        case KSW_DYN_PROFILE_CLASS_NTOSKRNL:
            return QStringLiteral("ntoskrnl");
        case KSW_DYN_PROFILE_CLASS_NTKRLA57:
            return QStringLiteral("ntkrla57");
        case KSW_DYN_PROFILE_CLASS_LXCORE:
            return QStringLiteral("lxcore");
        case KSW_DYN_PROFILE_CLASS_FLTMGR:
            return QStringLiteral("fltmgr");
        case KSW_DYN_PROFILE_CLASS_CI:
            return QStringLiteral("ci");
        default:
            return QStringLiteral("unknown(%1)").arg(classId);
        }
    }

    // sourceText：
    // - Input source: KSW_DYN_FIELD_SOURCE_*
    // - Processing: Convert to UI-readable text.
    // - Returns: field source text.
    QString sourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            return QStringLiteral("System Informer");
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Ksword runtime pattern");
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            return QStringLiteral("Ksword extra table");
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // profileSourceDisplayText：
    // - Input: sourceTextValue: source identifier recorded in LocalPdbProfile.
    // - Processing: Convert internal source identifiers to readable text for the DynData summary page.
    // - Return: PDB profile pack, scattered JSON, or fallback source text.
    QString profileSourceDisplayText(const QString& sourceTextValue)
    {
        if (sourceTextValue == QStringLiteral("pack"))
        {
            return QStringLiteral("PDB profile pack");
        }
        if (sourceTextValue == QStringLiteral("scattered-json"))
        {
            return QStringLiteral("PDB profile scattered JSON");
        }
        if (sourceTextValue == QStringLiteral("runtime-exact-pdb"))
        {
            return kernelText(
                "kernel.dyndata.profile.source.runtime_exact_pdb",
                QStringLiteral("运行时精确 PDB"));
        }
        return sourceTextValue.trimmed().isEmpty()
            ? kernelText("kernel.dyndata.placeholder.empty", QStringLiteral("<空>"))
            : sourceTextValue;
    }

    // fieldIdForProfileName：
    // - Input fieldName: field name in the JSON profile;
    // - Processing: Map to field IDs in shared/driver/KswordArkDynDataIoctl.h;
    // - Returns: true if a match is found, otherwise false; the caller records unknown fields for diagnostics.
    bool fieldIdForProfileName(const QString& fieldName, std::uint32_t& fieldIdOut)
    {
        static const std::unordered_map<std::string, std::uint32_t> kFieldIds = {
            { "EpObjectTable", KSW_DYN_FIELD_ID_EP_OBJECT_TABLE },
            { "EpSectionObject", KSW_DYN_FIELD_ID_EP_SECTION_OBJECT },
            { "EpUniqueProcessId", KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID },
            { "_EPROCESS.UniqueProcessId", KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID },
            { "EpActiveProcessLinks", KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS },
            { "_EPROCESS.ActiveProcessLinks", KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS },
            { "EpThreadListHead", KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD },
            { "_EPROCESS.ThreadListHead", KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD },
            { "EpImageFileName", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME },
            { "_EPROCESS.ImageFileName", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME },
            { "EpToken", KSW_DYN_FIELD_ID_EP_TOKEN },
            { "_EPROCESS.Token", KSW_DYN_FIELD_ID_EP_TOKEN },
            { "EpFlags", KSW_DYN_FIELD_ID_EP_FLAGS },
            { "_EPROCESS.Flags", KSW_DYN_FIELD_ID_EP_FLAGS },
            { "EpFlags2", KSW_DYN_FIELD_ID_EP_FLAGS2 },
            { "_EPROCESS.Flags2", KSW_DYN_FIELD_ID_EP_FLAGS2 },
            { "EpRundownProtect", KSW_DYN_FIELD_ID_EP_RUNDOWN_PROTECT },
            { "_EPROCESS.RundownProtect", KSW_DYN_FIELD_ID_EP_RUNDOWN_PROTECT },
            { "EpProcessLock", KSW_DYN_FIELD_ID_EP_PROCESS_LOCK },
            { "_EPROCESS.ProcessLock", KSW_DYN_FIELD_ID_EP_PROCESS_LOCK },
            { "EpCreateTime", KSW_DYN_FIELD_ID_EP_CREATE_TIME },
            { "_EPROCESS.CreateTime", KSW_DYN_FIELD_ID_EP_CREATE_TIME },
            { "EpExitTime", KSW_DYN_FIELD_ID_EP_EXIT_TIME },
            { "_EPROCESS.ExitTime", KSW_DYN_FIELD_ID_EP_EXIT_TIME },
            { "EpExitStatus", KSW_DYN_FIELD_ID_EP_EXIT_STATUS },
            { "_EPROCESS.ExitStatus", KSW_DYN_FIELD_ID_EP_EXIT_STATUS },
            { "EpPeb", KSW_DYN_FIELD_ID_EP_PEB },
            { "_EPROCESS.Peb", KSW_DYN_FIELD_ID_EP_PEB },
            { "EpSession", KSW_DYN_FIELD_ID_EP_SESSION },
            { "_EPROCESS.Session", KSW_DYN_FIELD_ID_EP_SESSION },
            { "EpWin32Process", KSW_DYN_FIELD_ID_EP_WIN32_PROCESS },
            { "_EPROCESS.Win32Process", KSW_DYN_FIELD_ID_EP_WIN32_PROCESS },
            { "EpWow64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "EpWoW64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "_EPROCESS.WoW64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "EpInheritedFromUniqueProcessId", KSW_DYN_FIELD_ID_EP_INHERITED_FROM_UNIQUE_PROCESS_ID },
            { "_EPROCESS.InheritedFromUniqueProcessId", KSW_DYN_FIELD_ID_EP_INHERITED_FROM_UNIQUE_PROCESS_ID },
            { "EpSeAuditProcessCreationInfo", KSW_DYN_FIELD_ID_EP_SE_AUDIT_PROCESS_CREATION_INFO },
            { "_EPROCESS.SeAuditProcessCreationInfo", KSW_DYN_FIELD_ID_EP_SE_AUDIT_PROCESS_CREATION_INFO },
            { "EpJob", KSW_DYN_FIELD_ID_EP_JOB },
            { "_EPROCESS.Job", KSW_DYN_FIELD_ID_EP_JOB },
            { "EpDeviceMap", KSW_DYN_FIELD_ID_EP_DEVICE_MAP },
            { "_EPROCESS.DeviceMap", KSW_DYN_FIELD_ID_EP_DEVICE_MAP },
            { "EpDebugPort", KSW_DYN_FIELD_ID_EP_DEBUG_PORT },
            { "_EPROCESS.DebugPort", KSW_DYN_FIELD_ID_EP_DEBUG_PORT },
            { "EpExceptionPortData", KSW_DYN_FIELD_ID_EP_EXCEPTION_PORT_DATA },
            { "_EPROCESS.ExceptionPortData", KSW_DYN_FIELD_ID_EP_EXCEPTION_PORT_DATA },
            { "EpSectionBaseAddress", KSW_DYN_FIELD_ID_EP_SECTION_BASE_ADDRESS },
            { "_EPROCESS.SectionBaseAddress", KSW_DYN_FIELD_ID_EP_SECTION_BASE_ADDRESS },
            { "EpImageFilePointer", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_POINTER },
            { "_EPROCESS.ImageFilePointer", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_POINTER },
            { "EpPriorityClass", KSW_DYN_FIELD_ID_EP_PRIORITY_CLASS },
            { "_EPROCESS.PriorityClass", KSW_DYN_FIELD_ID_EP_PRIORITY_CLASS },
            { "EpActiveThreads", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS },
            { "_EPROCESS.ActiveThreads", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS },
            { "EpVadRoot", KSW_DYN_FIELD_ID_EP_VAD_ROOT },
            { "_EPROCESS.VadRoot", KSW_DYN_FIELD_ID_EP_VAD_ROOT },
            { "EpVadHint", KSW_DYN_FIELD_ID_EP_VAD_HINT },
            { "_EPROCESS.VadHint", KSW_DYN_FIELD_ID_EP_VAD_HINT },
            { "EpCloneRoot", KSW_DYN_FIELD_ID_EP_CLONE_ROOT },
            { "_EPROCESS.CloneRoot", KSW_DYN_FIELD_ID_EP_CLONE_ROOT },
            { "EpNumberOfPrivatePages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_PRIVATE_PAGES },
            { "_EPROCESS.NumberOfPrivatePages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_PRIVATE_PAGES },
            { "EpNumberOfLockedPages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_LOCKED_PAGES },
            { "_EPROCESS.NumberOfLockedPages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_LOCKED_PAGES },
            { "EpCommitCharge", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE },
            { "_EPROCESS.CommitCharge", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE },
            { "EpCommitChargePeak", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_PEAK },
            { "_EPROCESS.CommitChargePeak", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_PEAK },
            { "EpPeakVirtualSize", KSW_DYN_FIELD_ID_EP_PEAK_VIRTUAL_SIZE },
            { "_EPROCESS.PeakVirtualSize", KSW_DYN_FIELD_ID_EP_PEAK_VIRTUAL_SIZE },
            { "EpVirtualSize", KSW_DYN_FIELD_ID_EP_VIRTUAL_SIZE },
            { "_EPROCESS.VirtualSize", KSW_DYN_FIELD_ID_EP_VIRTUAL_SIZE },
            { "EpSessionProcessLinks", KSW_DYN_FIELD_ID_EP_SESSION_PROCESS_LINKS },
            { "_EPROCESS.SessionProcessLinks", KSW_DYN_FIELD_ID_EP_SESSION_PROCESS_LINKS },
            { "EpMitigationFlags", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS },
            { "_EPROCESS.MitigationFlags", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS },
            { "EpMitigationFlags2", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS2 },
            { "_EPROCESS.MitigationFlags2", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS2 },
            { "EpProcessQuotaUsage", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_USAGE },
            { "_EPROCESS.ProcessQuotaUsage", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_USAGE },
            { "EpProcessQuotaPeak", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_PEAK },
            { "_EPROCESS.ProcessQuotaPeak", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_PEAK },
            { "EpAddressCreationLock", KSW_DYN_FIELD_ID_EP_ADDRESS_CREATION_LOCK },
            { "_EPROCESS.AddressCreationLock", KSW_DYN_FIELD_ID_EP_ADDRESS_CREATION_LOCK },
            { "EpPageTableCommitmentLock", KSW_DYN_FIELD_ID_EP_PAGE_TABLE_COMMITMENT_LOCK },
            { "_EPROCESS.PageTableCommitmentLock", KSW_DYN_FIELD_ID_EP_PAGE_TABLE_COMMITMENT_LOCK },
            { "EpRotateInProgress", KSW_DYN_FIELD_ID_EP_ROTATE_IN_PROGRESS },
            { "_EPROCESS.RotateInProgress", KSW_DYN_FIELD_ID_EP_ROTATE_IN_PROGRESS },
            { "EpForkInProgress", KSW_DYN_FIELD_ID_EP_FORK_IN_PROGRESS },
            { "_EPROCESS.ForkInProgress", KSW_DYN_FIELD_ID_EP_FORK_IN_PROGRESS },
            { "EpCommitChargeJob", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_JOB },
            { "_EPROCESS.CommitChargeJob", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_JOB },
            { "EpCookie", KSW_DYN_FIELD_ID_EP_COOKIE },
            { "_EPROCESS.Cookie", KSW_DYN_FIELD_ID_EP_COOKIE },
            { "EpWorkingSetWatch", KSW_DYN_FIELD_ID_EP_WORKING_SET_WATCH },
            { "_EPROCESS.WorkingSetWatch", KSW_DYN_FIELD_ID_EP_WORKING_SET_WATCH },
            { "EpWin32WindowStation", KSW_DYN_FIELD_ID_EP_WIN32_WINDOW_STATION },
            { "_EPROCESS.Win32WindowStation", KSW_DYN_FIELD_ID_EP_WIN32_WINDOW_STATION },
            { "EpOwnerProcessId", KSW_DYN_FIELD_ID_EP_OWNER_PROCESS_ID },
            { "_EPROCESS.OwnerProcessId", KSW_DYN_FIELD_ID_EP_OWNER_PROCESS_ID },
            { "EpQuotaBlock", KSW_DYN_FIELD_ID_EP_QUOTA_BLOCK },
            { "_EPROCESS.QuotaBlock", KSW_DYN_FIELD_ID_EP_QUOTA_BLOCK },
            { "EpEtwDataSource", KSW_DYN_FIELD_ID_EP_ETW_DATA_SOURCE },
            { "_EPROCESS.EtwDataSource", KSW_DYN_FIELD_ID_EP_ETW_DATA_SOURCE },
            { "EpPageDirectoryPte", KSW_DYN_FIELD_ID_EP_PAGE_DIRECTORY_PTE },
            { "_EPROCESS.PageDirectoryPte", KSW_DYN_FIELD_ID_EP_PAGE_DIRECTORY_PTE },
            { "EpSecurityPort", KSW_DYN_FIELD_ID_EP_SECURITY_PORT },
            { "_EPROCESS.SecurityPort", KSW_DYN_FIELD_ID_EP_SECURITY_PORT },
            { "EpJobLinks", KSW_DYN_FIELD_ID_EP_JOB_LINKS },
            { "_EPROCESS.JobLinks", KSW_DYN_FIELD_ID_EP_JOB_LINKS },
            { "EpHighestUserAddress", KSW_DYN_FIELD_ID_EP_HIGHEST_USER_ADDRESS },
            { "_EPROCESS.HighestUserAddress", KSW_DYN_FIELD_ID_EP_HIGHEST_USER_ADDRESS },
            { "EpImagePathHash", KSW_DYN_FIELD_ID_EP_IMAGE_PATH_HASH },
            { "_EPROCESS.ImagePathHash", KSW_DYN_FIELD_ID_EP_IMAGE_PATH_HASH },
            { "EpDefaultHardErrorProcessing", KSW_DYN_FIELD_ID_EP_DEFAULT_HARD_ERROR_PROCESSING },
            { "_EPROCESS.DefaultHardErrorProcessing", KSW_DYN_FIELD_ID_EP_DEFAULT_HARD_ERROR_PROCESSING },
            { "EpLastThreadExitStatus", KSW_DYN_FIELD_ID_EP_LAST_THREAD_EXIT_STATUS },
            { "_EPROCESS.LastThreadExitStatus", KSW_DYN_FIELD_ID_EP_LAST_THREAD_EXIT_STATUS },
            { "EpPrefetchTrace", KSW_DYN_FIELD_ID_EP_PREFETCH_TRACE },
            { "_EPROCESS.PrefetchTrace", KSW_DYN_FIELD_ID_EP_PREFETCH_TRACE },
            { "EpLockedPagesList", KSW_DYN_FIELD_ID_EP_LOCKED_PAGES_LIST },
            { "_EPROCESS.LockedPagesList", KSW_DYN_FIELD_ID_EP_LOCKED_PAGES_LIST },
            { "EpReadOperationCount", KSW_DYN_FIELD_ID_EP_READ_OPERATION_COUNT },
            { "_EPROCESS.ReadOperationCount", KSW_DYN_FIELD_ID_EP_READ_OPERATION_COUNT },
            { "EpWriteOperationCount", KSW_DYN_FIELD_ID_EP_WRITE_OPERATION_COUNT },
            { "_EPROCESS.WriteOperationCount", KSW_DYN_FIELD_ID_EP_WRITE_OPERATION_COUNT },
            { "EpOtherOperationCount", KSW_DYN_FIELD_ID_EP_OTHER_OPERATION_COUNT },
            { "_EPROCESS.OtherOperationCount", KSW_DYN_FIELD_ID_EP_OTHER_OPERATION_COUNT },
            { "EpReadTransferCount", KSW_DYN_FIELD_ID_EP_READ_TRANSFER_COUNT },
            { "_EPROCESS.ReadTransferCount", KSW_DYN_FIELD_ID_EP_READ_TRANSFER_COUNT },
            { "EpWriteTransferCount", KSW_DYN_FIELD_ID_EP_WRITE_TRANSFER_COUNT },
            { "_EPROCESS.WriteTransferCount", KSW_DYN_FIELD_ID_EP_WRITE_TRANSFER_COUNT },
            { "EpOtherTransferCount", KSW_DYN_FIELD_ID_EP_OTHER_TRANSFER_COUNT },
            { "_EPROCESS.OtherTransferCount", KSW_DYN_FIELD_ID_EP_OTHER_TRANSFER_COUNT },
            { "EpCommitChargeLimit", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_LIMIT },
            { "_EPROCESS.CommitChargeLimit", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_LIMIT },
            { "EpVm", KSW_DYN_FIELD_ID_EP_VM },
            { "_EPROCESS.Vm", KSW_DYN_FIELD_ID_EP_VM },
            { "EpMmProcessLinks", KSW_DYN_FIELD_ID_EP_MM_PROCESS_LINKS },
            { "_EPROCESS.MmProcessLinks", KSW_DYN_FIELD_ID_EP_MM_PROCESS_LINKS },
            { "EpModifiedPageCount", KSW_DYN_FIELD_ID_EP_MODIFIED_PAGE_COUNT },
            { "_EPROCESS.ModifiedPageCount", KSW_DYN_FIELD_ID_EP_MODIFIED_PAGE_COUNT },
            { "EpVadCount", KSW_DYN_FIELD_ID_EP_VAD_COUNT },
            { "_EPROCESS.VadCount", KSW_DYN_FIELD_ID_EP_VAD_COUNT },
            { "EpVadPhysicalPages", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES },
            { "_EPROCESS.VadPhysicalPages", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES },
            { "EpVadPhysicalPagesLimit", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES_LIMIT },
            { "_EPROCESS.VadPhysicalPagesLimit", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES_LIMIT },
            { "EpAlpcContext", KSW_DYN_FIELD_ID_EP_ALPC_CONTEXT },
            { "_EPROCESS.AlpcContext", KSW_DYN_FIELD_ID_EP_ALPC_CONTEXT },
            { "EpTimerResolutionLink", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_LINK },
            { "_EPROCESS.TimerResolutionLink", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_LINK },
            { "EpTimerResolutionStackRecord", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_STACK_RECORD },
            { "_EPROCESS.TimerResolutionStackRecord", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_STACK_RECORD },
            { "EpRequestedTimerResolution", KSW_DYN_FIELD_ID_EP_REQUESTED_TIMER_RESOLUTION },
            { "_EPROCESS.RequestedTimerResolution", KSW_DYN_FIELD_ID_EP_REQUESTED_TIMER_RESOLUTION },
            { "EpSmallestTimerResolution", KSW_DYN_FIELD_ID_EP_SMALLEST_TIMER_RESOLUTION },
            { "_EPROCESS.SmallestTimerResolution", KSW_DYN_FIELD_ID_EP_SMALLEST_TIMER_RESOLUTION },
            { "EpInvertedFunctionTable", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE },
            { "_EPROCESS.InvertedFunctionTable", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE },
            { "EpInvertedFunctionTableLock", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE_LOCK },
            { "_EPROCESS.InvertedFunctionTableLock", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE_LOCK },
            { "EpActiveThreadsHighWatermark", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS_HIGH_WATERMARK },
            { "_EPROCESS.ActiveThreadsHighWatermark", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS_HIGH_WATERMARK },
            { "EpLargePrivateVadCount", KSW_DYN_FIELD_ID_EP_LARGE_PRIVATE_VAD_COUNT },
            { "_EPROCESS.LargePrivateVadCount", KSW_DYN_FIELD_ID_EP_LARGE_PRIVATE_VAD_COUNT },
            { "EpThreadListLock", KSW_DYN_FIELD_ID_EP_THREAD_LIST_LOCK },
            { "_EPROCESS.ThreadListLock", KSW_DYN_FIELD_ID_EP_THREAD_LIST_LOCK },
            { "EpWnfContext", KSW_DYN_FIELD_ID_EP_WNF_CONTEXT },
            { "_EPROCESS.WnfContext", KSW_DYN_FIELD_ID_EP_WNF_CONTEXT },
            { "EpFlags3", KSW_DYN_FIELD_ID_EP_FLAGS3 },
            { "_EPROCESS.Flags3", KSW_DYN_FIELD_ID_EP_FLAGS3 },
            { "EpDiskCounters", KSW_DYN_FIELD_ID_EP_DISK_COUNTERS },
            { "_EPROCESS.DiskCounters", KSW_DYN_FIELD_ID_EP_DISK_COUNTERS },
            { "TokTokenSource", KSW_DYN_FIELD_ID_TOK_TOKEN_SOURCE },
            { "_TOKEN.TokenSource", KSW_DYN_FIELD_ID_TOK_TOKEN_SOURCE },
            { "TokTokenId", KSW_DYN_FIELD_ID_TOK_TOKEN_ID },
            { "_TOKEN.TokenId", KSW_DYN_FIELD_ID_TOK_TOKEN_ID },
            { "TokAuthenticationId", KSW_DYN_FIELD_ID_TOK_AUTHENTICATION_ID },
            { "_TOKEN.AuthenticationId", KSW_DYN_FIELD_ID_TOK_AUTHENTICATION_ID },
            { "TokParentTokenId", KSW_DYN_FIELD_ID_TOK_PARENT_TOKEN_ID },
            { "_TOKEN.ParentTokenId", KSW_DYN_FIELD_ID_TOK_PARENT_TOKEN_ID },
            { "TokExpirationTime", KSW_DYN_FIELD_ID_TOK_EXPIRATION_TIME },
            { "_TOKEN.ExpirationTime", KSW_DYN_FIELD_ID_TOK_EXPIRATION_TIME },
            { "TokTokenLock", KSW_DYN_FIELD_ID_TOK_TOKEN_LOCK },
            { "_TOKEN.TokenLock", KSW_DYN_FIELD_ID_TOK_TOKEN_LOCK },
            { "TokModifiedId", KSW_DYN_FIELD_ID_TOK_MODIFIED_ID },
            { "_TOKEN.ModifiedId", KSW_DYN_FIELD_ID_TOK_MODIFIED_ID },
            { "TokPrivileges", KSW_DYN_FIELD_ID_TOK_PRIVILEGES },
            { "_TOKEN.Privileges", KSW_DYN_FIELD_ID_TOK_PRIVILEGES },
            { "TokAuditPolicy", KSW_DYN_FIELD_ID_TOK_AUDIT_POLICY },
            { "_TOKEN.AuditPolicy", KSW_DYN_FIELD_ID_TOK_AUDIT_POLICY },
            { "TokSessionId", KSW_DYN_FIELD_ID_TOK_SESSION_ID },
            { "_TOKEN.SessionId", KSW_DYN_FIELD_ID_TOK_SESSION_ID },
            { "TokUserAndGroupCount", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUP_COUNT },
            { "_TOKEN.UserAndGroupCount", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUP_COUNT },
            { "TokRestrictedSidCount", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_COUNT },
            { "_TOKEN.RestrictedSidCount", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_COUNT },
            { "TokVariableLength", KSW_DYN_FIELD_ID_TOK_VARIABLE_LENGTH },
            { "_TOKEN.VariableLength", KSW_DYN_FIELD_ID_TOK_VARIABLE_LENGTH },
            { "TokDynamicCharged", KSW_DYN_FIELD_ID_TOK_DYNAMIC_CHARGED },
            { "_TOKEN.DynamicCharged", KSW_DYN_FIELD_ID_TOK_DYNAMIC_CHARGED },
            { "TokDynamicAvailable", KSW_DYN_FIELD_ID_TOK_DYNAMIC_AVAILABLE },
            { "_TOKEN.DynamicAvailable", KSW_DYN_FIELD_ID_TOK_DYNAMIC_AVAILABLE },
            { "TokDefaultOwnerIndex", KSW_DYN_FIELD_ID_TOK_DEFAULT_OWNER_INDEX },
            { "_TOKEN.DefaultOwnerIndex", KSW_DYN_FIELD_ID_TOK_DEFAULT_OWNER_INDEX },
            { "TokUserAndGroups", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUPS },
            { "_TOKEN.UserAndGroups", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUPS },
            { "TokRestrictedSids", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SIDS },
            { "_TOKEN.RestrictedSids", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SIDS },
            { "TokPrimaryGroup", KSW_DYN_FIELD_ID_TOK_PRIMARY_GROUP },
            { "_TOKEN.PrimaryGroup", KSW_DYN_FIELD_ID_TOK_PRIMARY_GROUP },
            { "TokDynamicPart", KSW_DYN_FIELD_ID_TOK_DYNAMIC_PART },
            { "_TOKEN.DynamicPart", KSW_DYN_FIELD_ID_TOK_DYNAMIC_PART },
            { "TokDefaultDacl", KSW_DYN_FIELD_ID_TOK_DEFAULT_DACL },
            { "_TOKEN.DefaultDacl", KSW_DYN_FIELD_ID_TOK_DEFAULT_DACL },
            { "TokTokenType", KSW_DYN_FIELD_ID_TOK_TOKEN_TYPE },
            { "_TOKEN.TokenType", KSW_DYN_FIELD_ID_TOK_TOKEN_TYPE },
            { "TokImpersonationLevel", KSW_DYN_FIELD_ID_TOK_IMPERSONATION_LEVEL },
            { "_TOKEN.ImpersonationLevel", KSW_DYN_FIELD_ID_TOK_IMPERSONATION_LEVEL },
            { "TokTokenFlags", KSW_DYN_FIELD_ID_TOK_TOKEN_FLAGS },
            { "_TOKEN.TokenFlags", KSW_DYN_FIELD_ID_TOK_TOKEN_FLAGS },
            { "TokTokenInUse", KSW_DYN_FIELD_ID_TOK_TOKEN_IN_USE },
            { "_TOKEN.TokenInUse", KSW_DYN_FIELD_ID_TOK_TOKEN_IN_USE },
            { "TokIntegrityLevelIndex", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_INDEX },
            { "_TOKEN.IntegrityLevelIndex", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_INDEX },
            { "TokMandatoryPolicy", KSW_DYN_FIELD_ID_TOK_MANDATORY_POLICY },
            { "_TOKEN.MandatoryPolicy", KSW_DYN_FIELD_ID_TOK_MANDATORY_POLICY },
            { "TokLogonSession", KSW_DYN_FIELD_ID_TOK_LOGON_SESSION },
            { "_TOKEN.LogonSession", KSW_DYN_FIELD_ID_TOK_LOGON_SESSION },
            { "TokOriginatingLogonSession", KSW_DYN_FIELD_ID_TOK_ORIGINATING_LOGON_SESSION },
            { "_TOKEN.OriginatingLogonSession", KSW_DYN_FIELD_ID_TOK_ORIGINATING_LOGON_SESSION },
            { "TokSidHash", KSW_DYN_FIELD_ID_TOK_SID_HASH },
            { "_TOKEN.SidHash", KSW_DYN_FIELD_ID_TOK_SID_HASH },
            { "TokRestrictedSidHash", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_HASH },
            { "_TOKEN.RestrictedSidHash", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_HASH },
            { "TokPSecurityAttributes", KSW_DYN_FIELD_ID_TOK_P_SECURITY_ATTRIBUTES },
            { "_TOKEN.pSecurityAttributes", KSW_DYN_FIELD_ID_TOK_P_SECURITY_ATTRIBUTES },
            { "TokPackage", KSW_DYN_FIELD_ID_TOK_PACKAGE },
            { "_TOKEN.Package", KSW_DYN_FIELD_ID_TOK_PACKAGE },
            { "TokCapabilities", KSW_DYN_FIELD_ID_TOK_CAPABILITIES },
            { "_TOKEN.Capabilities", KSW_DYN_FIELD_ID_TOK_CAPABILITIES },
            { "TokCapabilityCount", KSW_DYN_FIELD_ID_TOK_CAPABILITY_COUNT },
            { "_TOKEN.CapabilityCount", KSW_DYN_FIELD_ID_TOK_CAPABILITY_COUNT },
            { "TokCapabilitiesHash", KSW_DYN_FIELD_ID_TOK_CAPABILITIES_HASH },
            { "_TOKEN.CapabilitiesHash", KSW_DYN_FIELD_ID_TOK_CAPABILITIES_HASH },
            { "TokLowboxNumberEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_NUMBER_ENTRY },
            { "_TOKEN.LowboxNumberEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_NUMBER_ENTRY },
            { "TokLowboxHandlesEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_HANDLES_ENTRY },
            { "_TOKEN.LowboxHandlesEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_HANDLES_ENTRY },
            { "TokPClaimAttributes", KSW_DYN_FIELD_ID_TOK_P_CLAIM_ATTRIBUTES },
            { "_TOKEN.pClaimAttributes", KSW_DYN_FIELD_ID_TOK_P_CLAIM_ATTRIBUTES },
            { "TokTrustLevelSid", KSW_DYN_FIELD_ID_TOK_TRUST_LEVEL_SID },
            { "_TOKEN.TrustLevelSid", KSW_DYN_FIELD_ID_TOK_TRUST_LEVEL_SID },
            { "TokTrustLinkedToken", KSW_DYN_FIELD_ID_TOK_TRUST_LINKED_TOKEN },
            { "_TOKEN.TrustLinkedToken", KSW_DYN_FIELD_ID_TOK_TRUST_LINKED_TOKEN },
            { "TokIntegrityLevelSidValue", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_SID_VALUE },
            { "_TOKEN.IntegrityLevelSidValue", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_SID_VALUE },
            { "TokTokenSidValues", KSW_DYN_FIELD_ID_TOK_TOKEN_SID_VALUES },
            { "_TOKEN.TokenSidValues", KSW_DYN_FIELD_ID_TOK_TOKEN_SID_VALUES },
            { "TokSessionObject", KSW_DYN_FIELD_ID_TOK_SESSION_OBJECT },
            { "_TOKEN.SessionObject", KSW_DYN_FIELD_ID_TOK_SESSION_OBJECT },
            { "TokVariablePart", KSW_DYN_FIELD_ID_TOK_VARIABLE_PART },
            { "_TOKEN.VariablePart", KSW_DYN_FIELD_ID_TOK_VARIABLE_PART },
            { "HtHandleContentionEvent", KSW_DYN_FIELD_ID_HT_HANDLE_CONTENTION_EVENT },
            { "HtTableCode", KSW_DYN_FIELD_ID_HT_TABLE_CODE },
            { "_HANDLE_TABLE.TableCode", KSW_DYN_FIELD_ID_HT_TABLE_CODE },
            { "HtHandleCount", KSW_DYN_FIELD_ID_HT_HANDLE_COUNT },
            { "_HANDLE_TABLE.HandleCount", KSW_DYN_FIELD_ID_HT_HANDLE_COUNT },
            { "HteLowValue", KSW_DYN_FIELD_ID_HTE_LOW_VALUE },
            { "_HANDLE_TABLE_ENTRY.LowValue", KSW_DYN_FIELD_ID_HTE_LOW_VALUE },
            { "OtName", KSW_DYN_FIELD_ID_OT_NAME },
            { "OtIndex", KSW_DYN_FIELD_ID_OT_INDEX },
            { "ObDecodeShift", KSW_DYN_FIELD_ID_OB_DECODE_SHIFT },
            { "ObAttributesShift", KSW_DYN_FIELD_ID_OB_ATTRIBUTES_SHIFT },
            { "KtInitialStack", KSW_DYN_FIELD_ID_KT_INITIAL_STACK },
            { "KtStackLimit", KSW_DYN_FIELD_ID_KT_STACK_LIMIT },
            { "KtStackBase", KSW_DYN_FIELD_ID_KT_STACK_BASE },
            { "KtKernelStack", KSW_DYN_FIELD_ID_KT_KERNEL_STACK },
            { "KtProcess", KSW_DYN_FIELD_ID_KT_PROCESS },
            { "_KTHREAD.Process", KSW_DYN_FIELD_ID_KT_PROCESS },
            { "EtCid", KSW_DYN_FIELD_ID_ET_CID },
            { "_ETHREAD.Cid", KSW_DYN_FIELD_ID_ET_CID },
            { "EtThreadListEntry", KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY },
            { "_ETHREAD.ThreadListEntry", KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY },
            { "EtStartAddress", KSW_DYN_FIELD_ID_ET_START_ADDRESS },
            { "_ETHREAD.StartAddress", KSW_DYN_FIELD_ID_ET_START_ADDRESS },
            { "EtWin32StartAddress", KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS },
            { "_ETHREAD.Win32StartAddress", KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS },
            { "KtReadOperationCount", KSW_DYN_FIELD_ID_KT_READ_OPERATION_COUNT },
            { "KtWriteOperationCount", KSW_DYN_FIELD_ID_KT_WRITE_OPERATION_COUNT },
            { "KtOtherOperationCount", KSW_DYN_FIELD_ID_KT_OTHER_OPERATION_COUNT },
            { "KtReadTransferCount", KSW_DYN_FIELD_ID_KT_READ_TRANSFER_COUNT },
            { "KtWriteTransferCount", KSW_DYN_FIELD_ID_KT_WRITE_TRANSFER_COUNT },
            { "KtOtherTransferCount", KSW_DYN_FIELD_ID_KT_OTHER_TRANSFER_COUNT },
            { "MmSectionControlArea", KSW_DYN_FIELD_ID_MM_SECTION_CONTROL_AREA },
            { "MmControlAreaListHead", KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LIST_HEAD },
            { "MmControlAreaLock", KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LOCK },
            { "AlpcCommunicationInfo", KSW_DYN_FIELD_ID_ALPC_COMMUNICATION_INFO },
            { "AlpcOwnerProcess", KSW_DYN_FIELD_ID_ALPC_OWNER_PROCESS },
            { "AlpcConnectionPort", KSW_DYN_FIELD_ID_ALPC_CONNECTION_PORT },
            { "AlpcServerCommunicationPort", KSW_DYN_FIELD_ID_ALPC_SERVER_COMMUNICATION_PORT },
            { "AlpcClientCommunicationPort", KSW_DYN_FIELD_ID_ALPC_CLIENT_COMMUNICATION_PORT },
            { "AlpcHandleTable", KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE },
            { "AlpcHandleTableLock", KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE_LOCK },
            { "AlpcAttributes", KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES },
            { "AlpcAttributesFlags", KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES_FLAGS },
            { "AlpcPortContext", KSW_DYN_FIELD_ID_ALPC_PORT_CONTEXT },
            { "AlpcPortObjectLock", KSW_DYN_FIELD_ID_ALPC_PORT_OBJECT_LOCK },
            { "AlpcSequenceNo", KSW_DYN_FIELD_ID_ALPC_SEQUENCE_NO },
            { "AlpcState", KSW_DYN_FIELD_ID_ALPC_STATE },
            { "LxPicoProc", KSW_DYN_FIELD_ID_LX_PICO_PROC },
            { "LxPicoProcInfo", KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO },
            { "LxPicoProcInfoPID", KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO_PID },
            { "LxPicoThrdInfo", KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO },
            { "LxPicoThrdInfoTID", KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO_TID },
            { "EpProtection", KSW_DYN_FIELD_ID_EP_PROTECTION },
            { "EpSignatureLevel", KSW_DYN_FIELD_ID_EP_SIGNATURE_LEVEL },
            { "EpSectionSignatureLevel", KSW_DYN_FIELD_ID_EP_SECTION_SIGNATURE_LEVEL },
            { "EgeGuid", KSW_DYN_FIELD_ID_EGE_GUID },
            { "EreGuidEntry", KSW_DYN_FIELD_ID_ERE_GUID_ENTRY },
            { "KldrInLoadOrderLinks", KSW_DYN_FIELD_ID_KLDR_IN_LOAD_ORDER_LINKS },
            { "_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks", KSW_DYN_FIELD_ID_KLDR_IN_LOAD_ORDER_LINKS },
            { "KldrDllBase", KSW_DYN_FIELD_ID_KLDR_DLL_BASE },
            { "_KLDR_DATA_TABLE_ENTRY.DllBase", KSW_DYN_FIELD_ID_KLDR_DLL_BASE },
            { "KldrSizeOfImage", KSW_DYN_FIELD_ID_KLDR_SIZE_OF_IMAGE },
            { "_KLDR_DATA_TABLE_ENTRY.SizeOfImage", KSW_DYN_FIELD_ID_KLDR_SIZE_OF_IMAGE },
            { "KldrFullDllName", KSW_DYN_FIELD_ID_KLDR_FULL_DLL_NAME },
            { "_KLDR_DATA_TABLE_ENTRY.FullDllName", KSW_DYN_FIELD_ID_KLDR_FULL_DLL_NAME },
            { "KldrBaseDllName", KSW_DYN_FIELD_ID_KLDR_BASE_DLL_NAME },
            { "_KLDR_DATA_TABLE_ENTRY.BaseDllName", KSW_DYN_FIELD_ID_KLDR_BASE_DLL_NAME },
            { "KldrFlags", KSW_DYN_FIELD_ID_KLDR_FLAGS },
            { "_KLDR_DATA_TABLE_ENTRY.Flags", KSW_DYN_FIELD_ID_KLDR_FLAGS },
            { "DoDriverStart", KSW_DYN_FIELD_ID_DO_DRIVER_START },
            { "_DRIVER_OBJECT.DriverStart", KSW_DYN_FIELD_ID_DO_DRIVER_START },
            { "DoDriverSize", KSW_DYN_FIELD_ID_DO_DRIVER_SIZE },
            { "_DRIVER_OBJECT.DriverSize", KSW_DYN_FIELD_ID_DO_DRIVER_SIZE },
            { "DoDriverSection", KSW_DYN_FIELD_ID_DO_DRIVER_SECTION },
            { "_DRIVER_OBJECT.DriverSection", KSW_DYN_FIELD_ID_DO_DRIVER_SECTION },
            { "DoMajorFunction", KSW_DYN_FIELD_ID_DO_MAJOR_FUNCTION },
            { "_DRIVER_OBJECT.MajorFunction", KSW_DYN_FIELD_ID_DO_MAJOR_FUNCTION },
            { "DoFastIoDispatch", KSW_DYN_FIELD_ID_DO_FAST_IO_DISPATCH },
            { "_DRIVER_OBJECT.FastIoDispatch", KSW_DYN_FIELD_ID_DO_FAST_IO_DISPATCH },
            { "DoDriverUnload", KSW_DYN_FIELD_ID_DO_DRIVER_UNLOAD },
            { "_DRIVER_OBJECT.DriverUnload", KSW_DYN_FIELD_ID_DO_DRIVER_UNLOAD },
            // Unloaded driver record fields:
            // - Input: Short field names or type.field names output by the PDB profile generator;
            // - Processing: Map to shared DynData ID for subsequent apply-profile(-ex) writes to R0.
            // - Returns: This table does not return a value; the caller obtains the protocol field ID via fieldIdOut.
            { "UldName", KSW_DYN_FIELD_ID_ULD_NAME },
            { "_UNLOADED_DRIVERS.Name", KSW_DYN_FIELD_ID_ULD_NAME },
            { "UldStartAddress", KSW_DYN_FIELD_ID_ULD_START_ADDRESS },
            { "_UNLOADED_DRIVERS.StartAddress", KSW_DYN_FIELD_ID_ULD_START_ADDRESS },
            { "UldEndAddress", KSW_DYN_FIELD_ID_ULD_END_ADDRESS },
            { "_UNLOADED_DRIVERS.EndAddress", KSW_DYN_FIELD_ID_ULD_END_ADDRESS },
            { "UldCurrentTime", KSW_DYN_FIELD_ID_ULD_CURRENT_TIME },
            { "_UNLOADED_DRIVERS.CurrentTime", KSW_DYN_FIELD_ID_ULD_CURRENT_TIME },
            { "UldTypeSize", KSW_DYN_FIELD_ID_ULD_TYPE_SIZE },
            { "_UNLOADED_DRIVERS.TypeSize", KSW_DYN_FIELD_ID_ULD_TYPE_SIZE },
            { "RtlAvlBalancedRoot", KSW_DYN_FIELD_ID_RTL_AVL_BALANCED_ROOT },
            { "_RTL_AVL_TABLE.BalancedRoot", KSW_DYN_FIELD_ID_RTL_AVL_BALANCED_ROOT },
            { "RtlAvlOrderedPointer", KSW_DYN_FIELD_ID_RTL_AVL_ORDERED_POINTER },
            { "_RTL_AVL_TABLE.OrderedPointer", KSW_DYN_FIELD_ID_RTL_AVL_ORDERED_POINTER },
            { "RtlAvlWhichOrderedElement", KSW_DYN_FIELD_ID_RTL_AVL_WHICH_ORDERED_ELEMENT },
            { "_RTL_AVL_TABLE.WhichOrderedElement", KSW_DYN_FIELD_ID_RTL_AVL_WHICH_ORDERED_ELEMENT },
            { "RtlAvlNumberGenericTableElements", KSW_DYN_FIELD_ID_RTL_AVL_NUMBER_GENERIC_TABLE_ELEMENTS },
            { "_RTL_AVL_TABLE.NumberGenericTableElements", KSW_DYN_FIELD_ID_RTL_AVL_NUMBER_GENERIC_TABLE_ELEMENTS },
            { "RtlAvlDepthOfTree", KSW_DYN_FIELD_ID_RTL_AVL_DEPTH_OF_TREE },
            { "_RTL_AVL_TABLE.DepthOfTree", KSW_DYN_FIELD_ID_RTL_AVL_DEPTH_OF_TREE },
            { "RtlAvlRestartKey", KSW_DYN_FIELD_ID_RTL_AVL_RESTART_KEY },
            { "_RTL_AVL_TABLE.RestartKey", KSW_DYN_FIELD_ID_RTL_AVL_RESTART_KEY },
            { "RtlAvlDeleteCount", KSW_DYN_FIELD_ID_RTL_AVL_DELETE_COUNT },
            { "_RTL_AVL_TABLE.DeleteCount", KSW_DYN_FIELD_ID_RTL_AVL_DELETE_COUNT },
            { "RtlAvlTypeSize", KSW_DYN_FIELD_ID_RTL_AVL_TYPE_SIZE },
            { "_RTL_AVL_TABLE.TypeSize", KSW_DYN_FIELD_ID_RTL_AVL_TYPE_SIZE },
            { "PiDdbDriverName", KSW_DYN_FIELD_ID_PIDDB_DRIVER_NAME },
            { "_PIDDB_CACHE_ENTRY.DriverName", KSW_DYN_FIELD_ID_PIDDB_DRIVER_NAME },
            { "PiDdbTimeDateStamp", KSW_DYN_FIELD_ID_PIDDB_TIME_DATE_STAMP },
            { "_PIDDB_CACHE_ENTRY.TimeDateStamp", KSW_DYN_FIELD_ID_PIDDB_TIME_DATE_STAMP },
            { "PiDdbLoadStatus", KSW_DYN_FIELD_ID_PIDDB_LOAD_STATUS },
            { "_PIDDB_CACHE_ENTRY.LoadStatus", KSW_DYN_FIELD_ID_PIDDB_LOAD_STATUS },
            { "PiDdbTypeSize", KSW_DYN_FIELD_ID_PIDDB_TYPE_SIZE },
            { "_PIDDB_CACHE_ENTRY.TypeSize", KSW_DYN_FIELD_ID_PIDDB_TYPE_SIZE },
            { "PspCidTable", KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE },
            { "PsLoadedModuleList", KSW_DYN_FIELD_ID_KG_PS_LOADED_MODULE_LIST },
            { "MmUnloadedDrivers", KSW_DYN_FIELD_ID_KG_MM_UNLOADED_DRIVERS },
            { "PiDDBCacheTable", KSW_DYN_FIELD_ID_KG_PIDDB_CACHE_TABLE },
            { "PiDDBLock", KSW_DYN_FIELD_ID_KG_PIDDB_LOCK },
            // Kernel Global RVA mapping:
            // - Input: Shadow SSDT global symbol name from the PDB profile pack.
            // - Processing: Map to shared DynData field ID to prevent EX apply from counting this item as ignored.
            // - Returns: This table does not return a value; the caller obtains the protocol field ID via fieldIdOut.
            { "KeServiceDescriptorTableShadow", KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW },
            { "KgKeServiceDescriptorTableShadow", KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW },
            { "MmLastUnloadedDriver", KSW_DYN_FIELD_ID_KG_MM_LAST_UNLOADED_DRIVER },
            { "PspCreateProcessNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_CREATE_PROCESS_NOTIFY_ROUTINE },
            { "PspCreateThreadNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_CREATE_THREAD_NOTIFY_ROUTINE },
            { "PspLoadImageNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_LOAD_IMAGE_NOTIFY_ROUTINE },
            { "PspNotifyEnableMask", KSW_DYN_FIELD_ID_CB_PSP_NOTIFY_ENABLE_MASK },
            { "CmCallbackListHead", KSW_DYN_FIELD_ID_CB_CM_CALLBACK_LIST_HEAD },
            { "_OBJECT_TYPE.CallbackList", KSW_DYN_FIELD_ID_CB_OBJECT_TYPE_CALLBACK_LIST },
            { "_CALLBACK_ENTRY_ITEM.EntryList", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST },
            { "_CALLBACK_ENTRY_ITEM.EntryItemList", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST },
            { "_CALLBACK_ENTRY_ITEM.PreOperation", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_PRE_OPERATION },
            { "_CALLBACK_ENTRY_ITEM.PostOperation", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_POST_OPERATION },
            { "_CALLBACK_ENTRY_ITEM.Operations", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_OPERATIONS },
            { "_CALLBACK_ENTRY_ITEM.CallbackEntry", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_CALLBACK_ENTRY },
            { "_CALLBACK_ENTRY.Altitude", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ALTITUDE },
            { "_CALLBACK_ENTRY.RegistrationContext", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_REGISTRATION_CONTEXT }
        };

        const auto kIterator = kFieldIds.find(fieldName.toStdString());
        if (kIterator == kFieldIds.end())
        {
            fieldIdOut = 0U;
            return false;
        }

        fieldIdOut = kIterator->second;
        return true;
    }


    // fieldIdIsCallbackGlobal：
    // - Input fieldId: shared protocol field ID;
    // - Processing: Identify the callback global RVA used by callbackItems/v2.
    // - Returns: true if the field should be sent to EX IOCTL as callback GlobalRva.
    bool fieldIdIsCallbackGlobal(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_CB_PSP_CREATE_PROCESS_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_CREATE_THREAD_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_LOAD_IMAGE_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_NOTIFY_ENABLE_MASK:
        case KSW_DYN_FIELD_ID_CB_CM_CALLBACK_LIST_HEAD:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsKernelGlobal：
    // - Input fieldId: shared protocol field ID;
    // - Processing: Identify kernel global RVAs used by v3 typed items.
    // - Returns: true indicates the field should be sent to EX IOCTL as a non-callback GlobalRva.
    bool fieldIdIsKernelGlobal(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE:
        case KSW_DYN_FIELD_ID_KG_PS_LOADED_MODULE_LIST:
        case KSW_DYN_FIELD_ID_KG_MM_UNLOADED_DRIVERS:
        case KSW_DYN_FIELD_ID_KG_PIDDB_CACHE_TABLE:
        case KSW_DYN_FIELD_ID_KG_PIDDB_LOCK:
        case KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW:
        case KSW_DYN_FIELD_ID_KG_MM_LAST_UNLOADED_DRIVER:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsGlobalRva：
    // - Input fieldId: shared protocol field ID;
    // - Processing: Aggregate GlobalRva entries from both callback and kernel global categories.
    // - Returns: true indicates the field value should be submitted with an RVA checksum.
    bool fieldIdIsGlobalRva(const std::uint32_t fieldId)
    {
        return fieldIdIsCallbackGlobal(fieldId) || fieldIdIsKernelGlobal(fieldId);
    }

    // fieldIdIsCallbackOffset：
    // - Input fieldId: shared protocol field ID;
    // - Processing: Identify callback structure offsets used by callbackItems/v2.
    // - Returns: true indicates the field should be sent to EX IOCTL as a callback StructOffset.
    bool fieldIdIsCallbackOffset(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_CB_OBJECT_TYPE_CALLBACK_LIST:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_PRE_OPERATION:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_POST_OPERATION:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_OPERATIONS:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_CALLBACK_ENTRY:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ALTITUDE:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_REGISTRATION_CONTEXT:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsLxcoreOffset：
    // - Input fieldId: shared protocol field ID;
    // - Processing: Identify System Informer lxcore profile fields; currently, ntoskrnl PDB EX does not carry these fields.
    // - Return: true if the field cannot be placed in an ntoskrnl v3 StructOffset typed item.
    bool fieldIdIsLxcoreOffset(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_LX_PICO_PROC:
        case KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO:
        case KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO_PID:
        case KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO:
        case KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO_TID:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsStructOffset：
    // - Input fieldId: shared protocol field ID;
    // - Processing: After excluding GlobalRva and lxcore-only fields, allow known fields to apply via the StructOffset path.
    // - Return: true to indicate the field value should be validated and submitted based on structure offset.
    bool fieldIdIsStructOffset(const std::uint32_t fieldId)
    {
        return fieldId != 0U &&
            fieldId <= KSW_DYN_FIELD_ID_MAX &&
            !fieldIdIsGlobalRva(fieldId) &&
            !fieldIdIsLxcoreOffset(fieldId);
    }

    QString callbackItemKindText(const QString& kindText)
    {
        const QString kNormalized = kindText.trimmed();
        if (kNormalized.compare(QStringLiteral("GlobalRva"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("GlobalRva");
        }
        if (kNormalized.compare(QStringLiteral("StructOffset"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("StructOffset");
        }
        if (kNormalized.compare(QStringLiteral("TypeSize"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("TypeSize");
        }
        return kNormalized;
    }

    // profileContainsExItem：
    // - Input profile/fieldId: Current local profile and candidate field ID;
    // - Handling: Scan expanded EX items to avoid duplicate submission of callbackItems and v3 items;
    // - Returns: true indicates the field ID already exists.
    bool profileContainsExItem(const LocalPdbProfile& profile, const std::uint32_t fieldId)
    {
        return std::any_of(
            profile.applyExInput.items.begin(),
            profile.applyExInput.items.end(),
            [fieldId](const ksword::ark::DynDataProfileExItem& item) {
                return item.itemId == fieldId;
            });
    }

    // appendProfileExItem：
    // - Input profile/fieldId/itemKind/value/required: typed item data to be appended;
    // - Processing: Set the itemKind, value, and callback/required flags required for EX IOCTL.
    // - Returns: None. An item is appended to profile.applyExInput.items as needed.
    void appendProfileExItem(
        LocalPdbProfile& profile,
        const std::uint32_t fieldId,
        const std::uint32_t itemKind,
        const std::uint32_t value,
        const bool required)
    {
        ksword::ark::DynDataProfileExItem exItem{};
        exItem.itemId = fieldId;
        exItem.itemKind = itemKind;
        exItem.value = value;
        exItem.flags = required ? KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED : 0U;
        if (fieldIdIsCallbackGlobal(fieldId) || fieldIdIsCallbackOffset(fieldId))
        {
            exItem.flags |= KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
        }
        profile.applyExInput.items.push_back(exItem);
        profile.exAppliedCount = static_cast<std::uint32_t>(profile.applyExInput.items.size());
    }

    // Forward declaration of parseProfileUInt32:
    // - Input value: JSON number or string;
    // Handling/Return: The actual parsing logic is defined below; this location only allows the callbackItems parsing helper to be called in advance.
    bool parseProfileUInt32(const QJsonValue& value, std::uint32_t& valueOut);

    bool loadCallbackItemsFromJson(
        const QJsonArray& callbackItemsArray,
        LocalPdbProfile& profile,
        QStringList& diagnostics,
        bool& hasCallbackItemsOut)
    {
        hasCallbackItemsOut = false;
        if (callbackItemsArray.isEmpty())
        {
            return true;
        }

        hasCallbackItemsOut = true;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& itemValue : callbackItemsArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.non_object", QStringLiteral("callbackItems 包含非对象项，已忽略。"));
                continue;
            }

            const QJsonObject kItemObject = itemValue.toObject();
            const QString kItemName = kItemObject.value(QStringLiteral("name")).toString().trimmed();
            const QString kItemKind = callbackItemKindText(kItemObject.value(QStringLiteral("kind")).toString());
            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(kItemName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }

            std::uint32_t value = 0U;
            if (!parseProfileUInt32(kItemObject.value(QStringLiteral("value")), value))
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.parse_failed", QStringLiteral("callbackItems 解析失败: %1")).arg(kItemName);
                return false;
            }

            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId])
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.duplicate", QStringLiteral("callbackItems 含重复字段: %1")).arg(kItemName);
                return false;
            }
            seenFieldIds[fieldId] = true;

            if (kItemKind == QStringLiteral("GlobalRva"))
            {
                if (!fieldIdIsCallbackGlobal(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_global_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 global")).arg(kItemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.global_rva_out_of_range", QStringLiteral("callbackItems global RVA 越界: %1")).arg(kItemName);
                    return false;
                }
                ksword::ark::DynDataProfileExItem exItem{};
                exItem.itemId = fieldId;
                exItem.itemKind = KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA;
                exItem.value = value;
                exItem.flags = KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED | KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
                profile.applyExInput.items.push_back(exItem);
            }
            else if (kItemKind == QStringLiteral("StructOffset"))
            {
                if (!fieldIdIsCallbackOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_struct_offset_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 struct offset")).arg(kItemName);
                    return false;
                }
                ksword::ark::DynDataProfileExItem exItem{};
                exItem.itemId = fieldId;
                exItem.itemKind = KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET;
                exItem.value = value;
                exItem.flags = KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED | KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
                profile.applyExInput.items.push_back(exItem);
            }
            else if (kItemKind == QStringLiteral("TypeSize"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_type_size_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 type size")).arg(kItemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, true);
            }
            else
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.kind_unsupported", QStringLiteral("callbackItems kind 不支持: %1")).arg(kItemName);
                return false;
            }

            profile.callbackItemCount += 1U;
        }

        profile.exAppliedCount = static_cast<std::uint32_t>(profile.applyExInput.items.size());
        return true;
    }

    // loadTypedItemsFromJson：
    // - Input: typedItemsArray/profile/diagnostics/hasTypedItemsOut; Output: v3 items array, profile, and diagnostics container.
    // - Processing: Parse name/kind/value, and uniformly expand StructOffset and GlobalRva into EX IOCTL items.
    // - Return: true indicates typed items are available or empty; false indicates a semantic or range error in the matched items.
    bool loadTypedItemsFromJson(
        const QJsonArray& typedItemsArray,
        LocalPdbProfile& profile,
        QStringList& diagnostics,
        bool& hasTypedItemsOut)
    {
        hasTypedItemsOut = false;
        if (typedItemsArray.isEmpty())
        {
            return true;
        }

        hasTypedItemsOut = true;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& itemValue : typedItemsArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.non_object", QStringLiteral("typed items 包含非对象项，已忽略。"));
                continue;
            }

            const QJsonObject kItemObject = itemValue.toObject();
            const QString kItemName = kItemObject.value(QStringLiteral("name")).toString().trimmed();
            const QString kItemKind = callbackItemKindText(kItemObject.value(QStringLiteral("kind")).toString());
            const bool kRequired = kItemObject.value(QStringLiteral("required")).toBool(false);

            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(kItemName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }

            std::uint32_t value = 0U;
            if (!parseProfileUInt32(kItemObject.value(QStringLiteral("value")), value))
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.parse_failed", QStringLiteral("typed items 解析失败: %1")).arg(kItemName);
                return false;
            }

            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId] || profileContainsExItem(profile, fieldId))
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.duplicate", QStringLiteral("typed items 含重复字段: %1")).arg(kItemName);
                return false;
            }
            seenFieldIds[fieldId] = true;

            if (kItemKind == QStringLiteral("GlobalRva"))
            {
                if (!fieldIdIsGlobalRva(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_global_rva_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 global RVA")).arg(kItemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.global_rva_out_of_range", QStringLiteral("typed items global RVA 越界: %1")).arg(kItemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA, value, kRequired);
            }
            else if (kItemKind == QStringLiteral("StructOffset"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_struct_offset_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 struct offset")).arg(kItemName);
                    return false;
                }
                if (value == 0xFFFFFFFFU || value > KSW_DYN_PROFILE_OFFSET_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.struct_offset_out_of_range", QStringLiteral("typed items struct offset 越界: %1")).arg(kItemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, kRequired);
            }
            else if (kItemKind == QStringLiteral("TypeSize"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_type_size_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 type size")).arg(kItemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_OFFSET_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.type_size_out_of_range", QStringLiteral("typed items type size 越界: %1")).arg(kItemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, kRequired);
            }
            else
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.kind_unsupported", QStringLiteral("typed items kind 不支持: %1")).arg(kItemName);
                return false;
            }
            profile.typedItemCount += 1U;
        }

        return true;
    }

    // parseProfileUInt32：
    // - Input value: JSON value or 0x-prefixed string;
    // - Processing: Perform 32-bit unsigned range validation.
    // - Returns: true on successful parse, false on failure.
    bool parseProfileUInt32(const QJsonValue& value, std::uint32_t& valueOut)
    {
        bool ok = false;
        qulonglong parsedValue = 0ULL;

        valueOut = 0U;
        if (value.isString())
        {
            QString text = value.toString().trimmed();
            int base = 10;
            if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
            {
                text = text.mid(2);
                base = 16;
            }
            parsedValue = text.toULongLong(&ok, base);
        }
        else if (value.isDouble())
        {
            const double kNumericValue = value.toDouble();
            if (kNumericValue >= 0.0 && kNumericValue <= static_cast<double>(std::numeric_limits<std::uint32_t>::max()))
            {
                parsedValue = static_cast<qulonglong>(kNumericValue);
                ok = true;
            }
        }

        if (!ok || parsedValue > static_cast<qulonglong>(std::numeric_limits<std::uint32_t>::max()))
        {
            return false;
        }

        valueOut = static_cast<std::uint32_t>(parsedValue);
        return true;
    }

    template <std::size_t Size>
    void copyV4Utf8(char (&destination)[Size], const QString& source)
    {
        static_assert(Size > 0U);
        const QByteArray kBytes = source.toUtf8();
        const std::size_t kCopyLength = std::min<std::size_t>(Size - 1U, static_cast<std::size_t>(kBytes.size()));
        std::memset(destination, 0, Size);
        if (kCopyLength != 0U)
        {
            std::memcpy(destination, kBytes.constData(), kCopyLength);
        }
    }

    template <std::size_t Size>
    void copyV4Wide(wchar_t (&destination)[Size], const std::wstring& source)
    {
        static_assert(Size > 0U);
        const std::size_t kCopyLength = std::min<std::size_t>(Size - 1U, source.size());
        std::fill(std::begin(destination), std::end(destination), L'\0');
        if (kCopyLength != 0U)
        {
            std::copy_n(source.begin(), kCopyLength, destination);
        }
    }

    bool v4ItemIdSupported(const std::uint32_t itemId)
    {
        if (itemId >= 1U && itemId <= KSW_DYN_FIELD_ID_MAX)
        {
            return true;
        }
        switch (itemId)
        {
        case KSW_DYN_V4_ITEM_ID_ETH_ACTIVE_EX_WORKER:
        case KSW_DYN_V4_ITEM_ID_KPRCB_TIMER_TABLE:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TIMER_ENTRIES:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_ENTRY:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_LIST_ENTRY:
        case KSW_DYN_V4_ITEM_ID_KTIMER_DUE_TIME:
        case KSW_DYN_V4_ITEM_ID_KTIMER_DPC:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_TYPE:
        case KSW_DYN_V4_ITEM_ID_KTIMER_PERIOD:
        case KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_ROUTINE:
        case KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_CONTEXT:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_KDPC_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_FLT_FILTER_OPERATIONS:
        case KSW_DYN_V4_ITEM_ID_CI_KERNEL_HASH_BUCKET_LIST:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_CACHE_LOCK:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_NEXT:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_DRIVER_NAME:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TIME_DATE_STAMP:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_LOAD_STATUS:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_BASE:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_SIZE:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_PSP_SYSTEM_PARTITION:
        case KSW_DYN_V4_ITEM_ID_WQ_EXP_BUILTIN_PRIORITIES:
        case KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_EX_PARTITION:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_WORK_QUEUES:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_WORK_PRI_QUEUE:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_QUEUE_INDEX:
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_ENTRY_LIST_HEAD:
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_THREAD_LIST_HEAD:
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE:
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE_LIST_ENTRY:
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_LIST:
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_ROUTINE:
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_PARAMETER:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_POOL_UNTRUSTED:
        case KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_START_ADDRESS:
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TCB:
            return true;
        default:
            return false;
        }
    }

    bool loadV4ItemsFromJson(
        const QJsonArray& itemArray,
        const QJsonArray& groupArray,
        const ksword::ark::ArkDynModuleIdentity& currentIdentity,
        const QString& profileName,
        const QString& pdbName,
        const QString& pdbGuid,
        const std::uint32_t pdbAge,
        LocalPdbProfile& profile,
        QStringList& diagnostics)
    {
        if (itemArray.isEmpty() || groupArray.isEmpty() ||
            itemArray.size() > static_cast<int>(KSW_DYN_V4_MAX_ITEMS_PER_MODULE) ||
            groupArray.size() > static_cast<int>(KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE))
        {
            diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
            return false;
        }

        std::array<bool, KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE + 1U> seenGroups{};
        std::unordered_map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> expectedCounts;
        profile.applyV4Input.capabilityGroups.clear();
        profile.applyV4Input.items.clear();
        for (const QJsonValue& groupValue : groupArray)
        {
            if (!groupValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            const QJsonObject kGroupObject = groupValue.toObject();
            std::uint32_t groupId = 0U;
            std::uint32_t flags = 0U;
            std::uint32_t requiredCount = 0U;
            std::uint32_t optionalCount = 0U;
            if (!parseProfileUInt32(kGroupObject.value(QStringLiteral("groupId")), groupId) ||
                !parseProfileUInt32(kGroupObject.value(QStringLiteral("flags")), flags) ||
                !parseProfileUInt32(kGroupObject.value(QStringLiteral("requiredItemCount")), requiredCount) ||
                !parseProfileUInt32(kGroupObject.value(QStringLiteral("optionalItemCount")), optionalCount) ||
                groupId == 0U || groupId > KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE || seenGroups[groupId])
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            seenGroups[groupId] = true;
            KSW_DYN_V4_CAPABILITY_GROUP_PACKET group{};
            group.groupId = groupId;
            group.flags = flags;
            group.requiredItemCount = requiredCount;
            group.optionalItemCount = optionalCount;
            copyV4Utf8(group.groupName, kGroupObject.value(QStringLiteral("groupName")).toString());
            profile.applyV4Input.capabilityGroups.push_back(group);
            expectedCounts[groupId] = {requiredCount, optionalCount};
        }

        std::array<bool, 2048U> seenItems{};
        std::unordered_map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> actualCounts;
        for (const QJsonValue& itemValue : itemArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            const QJsonObject kItemObject = itemValue.toObject();
            std::uint32_t itemId = 0U;
            std::uint32_t itemKind = 0U;
            std::uint32_t flags = 0U;
            std::uint32_t groupId = 0U;
            std::uint32_t valueLow = 0U;
            std::uint32_t valueHigh = 0U;
            std::uint32_t aux[4]{};
            if (!parseProfileUInt32(kItemObject.value(QStringLiteral("itemId")), itemId) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("itemKind")), itemKind) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("flags")), flags) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("capabilityGroupId")), groupId) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("valueLow")), valueLow) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("valueHigh")), valueHigh) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("aux0")), aux[0]) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("aux1")), aux[1]) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("aux2")), aux[2]) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("aux3")), aux[3]) ||
                !v4ItemIdSupported(itemId) || itemId >= seenItems.size() || seenItems[itemId] ||
                itemKind < KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET || itemKind > KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL ||
                (flags != KSW_DYN_V4_ITEM_FLAG_REQUIRED && flags != KSW_DYN_V4_ITEM_FLAG_OPTIONAL) ||
                groupId == 0U || !seenGroups[groupId])
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            seenItems[itemId] = true;
            KSW_DYN_V4_ITEM_PACKET item{};
            item.itemId = itemId;
            item.itemKind = itemKind;
            item.flags = flags;
            item.capabilityGroupId = groupId;
            item.valueLow = valueLow;
            item.valueHigh = valueHigh;
            item.aux0 = aux[0];
            item.aux1 = aux[1];
            item.aux2 = aux[2];
            item.aux3 = aux[3];
            profile.applyV4Input.items.push_back(item);
            // v4 core items are the single source of truth.  Derive the
            // legacy EX projection in memory so existing field consumers keep
            // working without storing a second offset array in the pack.
            if (itemId >= 1U && itemId <= KSW_DYN_FIELD_ID_MAX &&
                (itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_TYPE_SIZE ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL))
            {
                const std::uint32_t kExKind =
                    (itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA ||
                     itemKind == KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL)
                    ? KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA
                    : KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET;
                appendProfileExItem(
                    profile,
                    itemId,
                    kExKind,
                    valueLow,
                    (flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U);
            }
            auto& counts = actualCounts[groupId];
            if ((flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U)
            {
                counts.first += 1U;
            }
            else
            {
                counts.second += 1U;
            }
        }
        for (const auto& expected : expectedCounts)
        {
            const auto kActual = actualCounts[expected.first];
            if (kActual != expected.second)
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 计数不一致。"));
                return false;
            }
        }

        profile.applyV4Input.flags = 0U;
        profile.applyV4Input.module.image.present = currentIdentity.present ? 1UL : 0UL;
        profile.applyV4Input.module.image.classId = currentIdentity.classId;
        profile.applyV4Input.module.image.machine = currentIdentity.machine;
        profile.applyV4Input.module.image.timeDateStamp = currentIdentity.timeDateStamp;
        profile.applyV4Input.module.image.sizeOfImage = currentIdentity.sizeOfImage;
        profile.applyV4Input.module.image.imageBase = currentIdentity.imageBase;
        copyV4Wide(profile.applyV4Input.module.image.moduleName, currentIdentity.moduleName);
        copyV4Utf8(profile.applyV4Input.module.profileName, profileName);
        copyV4Utf8(profile.applyV4Input.module.pdb.pdbName, pdbName);
        copyV4Utf8(profile.applyV4Input.module.pdb.pdbGuid, pdbGuid);
        profile.applyV4Input.module.pdb.pdbAge = pdbAge;
        profile.applyExInput.profileName = profileName.toStdString();
        profile.applyExInput.pdbName = pdbName.toStdString();
        profile.applyExInput.pdbGuid = pdbGuid.toStdString();
        profile.applyExInput.pdbAge = pdbAge;
        profile.applyExInput.ntoskrnl = currentIdentity;
        profile.v4ItemCount = static_cast<std::uint32_t>(profile.applyV4Input.items.size());
        return true;
    }

    // profileClassIdFromText：
    // - Input classText: JSON module.class;
    // - Processing: Convert to R0 profile class ID.
    // - Returns: true on success, false if the class is unknown.
    bool profileClassIdFromText(const QString& classText, std::uint32_t& classIdOut)
    {
        const QString kNormalized = classText.trimmed().toLower();
        if (kNormalized == QStringLiteral("ntoskrnl") ||
            kNormalized == QStringLiteral("ntoskrnl.exe") ||
            kNormalized == QStringLiteral("ntkrnlmp") ||
            kNormalized == QStringLiteral("ntkrnlmp.exe"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_NTOSKRNL;
            return true;
        }
        if (kNormalized == QStringLiteral("ntkrla57") || kNormalized == QStringLiteral("ntkrla57.exe"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_NTKRLA57;
            return true;
        }
        if (kNormalized == QStringLiteral("fltmgr") || kNormalized == QStringLiteral("fltmgr.sys"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_FLTMGR;
            return true;
        }
        if (kNormalized == QStringLiteral("ci") ||
            kNormalized == QStringLiteral("ci.dll") ||
            kNormalized == QStringLiteral("ci.sys"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_CI;
            return true;
        }

        classIdOut = 0U;
        return false;
    }

    // profileClassIdFromJsonValue：
    // - Input: value is the moduleClassId from the pack profile.
    // - Processing: Parse uint32 and restrict to known class IDs.
    // - Returns: true on success, false on failure.
    bool profileClassIdFromJsonValue(const QJsonValue& value, std::uint32_t& classIdOut)
    {
        std::uint32_t parsedValue = 0U;
        if (!parseProfileUInt32(value, parsedValue))
        {
            classIdOut = 0U;
            return false;
        }

        switch (parsedValue)
        {
        case KSW_DYN_PROFILE_CLASS_NTOSKRNL:
        case KSW_DYN_PROFILE_CLASS_NTKRLA57:
        case KSW_DYN_PROFILE_CLASS_LXCORE:
        case KSW_DYN_PROFILE_CLASS_FLTMGR:
        case KSW_DYN_PROFILE_CLASS_CI:
            classIdOut = parsedValue;
            return true;
        default:
            classIdOut = 0U;
            return false;
        }
    }

    // appendUniquePath：
    // - Input paths/pathText: The list to maintain and the candidate path.
    // - Processing: Trim path and perform case-insensitive deduplication;
    // - Returns: Nothing; appends to `paths` as needed.
    void appendUniquePath(QStringList& paths, const QString& pathText)
    {
        const QString kTrimmed = pathText.trimmed();
        if (kTrimmed.isEmpty())
        {
            return;
        }

        const QString kCleaned = QDir::cleanPath(kTrimmed);
        if (!kCleaned.isEmpty() && !paths.contains(kCleaned, Qt::CaseInsensitive))
        {
            paths << kCleaned;
        }
    }

    // profilePackSearchPaths：
    // - Inputs: None;
    // - Processing: Prioritize reading the pack from the program directory, and allow specifying a debug pack via environment variables.
    // - Returns: A list of candidate pack file paths; existence is not guaranteed.
    QStringList profilePackSearchPaths()
    {
        QStringList paths;
        appendUniquePath(paths, qEnvironmentVariable("KSWORD_ARK_PROFILE_PACK"));
        appendUniquePath(paths, QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        appendUniquePath(paths, QDir::current().filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        return paths;
    }

    // profileSearchDirectories：
    // - Inputs: None;
    // - Processing: Enable scattered JSON debug fallback only when KSWORD_ARK_PROFILE_DIR is explicitly set.
    // - Returns: A list of candidate directories; existence is not guaranteed.
    QStringList profileSearchDirectories()
    {
        QStringList directories;
        appendUniquePath(directories, qEnvironmentVariable("KSWORD_ARK_PROFILE_DIR"));
        return directories;
    }

    // loadPdbProfileFile：
    // - Input: filePath/currentIdentity: candidate JSON file and current R0 ntoskrnl identity;
    // - Processing: Parse module identity, field tables, and offset ranges;
    // - Returns: LocalPdbProfile; matched=false indicates it is not the current kernel profile.
    LocalPdbProfile loadPdbProfileFile(const QString& filePath, const ksword::ark::ArkDynModuleIdentity& currentIdentity)
    {
        LocalPdbProfile profile;
        profile.sourceText = QStringLiteral("scattered-json");
        profile.pathText = QDir::toNativeSeparators(filePath);

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument kDocument = ks::profile::readProfileJsonDocument(filePath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
        {
            profile.diagnosticsText = readErrorText.isEmpty()
                ? kernelText("kernel.dyndata.profile.json_parse_failed", QStringLiteral("JSON 解析失败: %1")).arg(parseError.errorString())
                : readErrorText;
            return profile;
        }

        const QJsonObject kRootObject = kDocument.object();
        const QJsonObject kModuleObject = kRootObject.value(QStringLiteral("module")).toObject();
        std::uint32_t profileClass = 0U;
        std::uint32_t machine = 0U;
        std::uint32_t timeDateStamp = 0U;
        std::uint32_t sizeOfImage = 0U;
        if (!profileClassIdFromText(kModuleObject.value(QStringLiteral("class")).toString(), profileClass) ||
            !parseProfileUInt32(kModuleObject.value(QStringLiteral("machine")), machine) ||
            !parseProfileUInt32(kModuleObject.value(QStringLiteral("timeDateStamp")), timeDateStamp) ||
            !parseProfileUInt32(kModuleObject.value(QStringLiteral("sizeOfImage")), sizeOfImage))
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.identity_missing", QStringLiteral("profile module identity 字段缺失或格式无效。"));
            return profile;
        }

        profile.matched = currentIdentity.present &&
            currentIdentity.classId == profileClass &&
            currentIdentity.machine == machine &&
            currentIdentity.timeDateStamp == timeDateStamp &&
            currentIdentity.sizeOfImage == sizeOfImage;
        if (!profile.matched)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.identity_mismatch", QStringLiteral("profile identity 不匹配当前内核。"));
            return profile;
        }

        const QJsonObject kFieldsObject = kRootObject.value(QStringLiteral("fields")).toObject();
        profile.applyInput.profileName = kRootObject.value(QStringLiteral("profileName")).toString(QFileInfo(filePath).baseName()).toStdString();
        profile.applyInput.pdbName = kModuleObject.value(QStringLiteral("pdbName")).toString().toStdString();
        profile.applyInput.pdbGuid = kModuleObject.value(QStringLiteral("pdbGuid")).toString().toStdString();
        std::uint32_t pdbAge = 0U;
        if (parseProfileUInt32(kModuleObject.value(QStringLiteral("pdbAge")), pdbAge))
        {
            profile.applyInput.pdbAge = pdbAge;
        }
        profile.applyInput.ntoskrnl = currentIdentity;

        std::uint32_t invalidOffsetCount = 0U;
        for (auto iterator = kFieldsObject.constBegin(); iterator != kFieldsObject.constEnd(); ++iterator)
        {
            std::uint32_t fieldId = 0U;
            std::uint32_t offset = 0U;
            if (!fieldIdForProfileName(iterator.key(), fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }
            if (!parseProfileUInt32(iterator.value(), offset) ||
                offset == 0xFFFFFFFFU ||
                offset > KSW_DYN_PROFILE_OFFSET_MAX)
            {
                invalidOffsetCount += 1U;
                continue;
            }

            ksword::ark::DynDataProfileField field{};
            field.fieldId = fieldId;
            field.offset = offset;
            profile.applyInput.fields.push_back(field);
        }

        QJsonArray typedItemsArray = kRootObject.value(QStringLiteral("items")).toArray();
        if (typedItemsArray.isEmpty())
        {
            typedItemsArray = kRootObject.value(QStringLiteral("typedItems")).toArray();
        }
        const QJsonArray kCallbackItemsArray = typedItemsArray.isEmpty()
            ? kRootObject.value(QStringLiteral("callbackItems")).toArray()
            : QJsonArray();
        QStringList callbackDiagnostics;
        bool hasCallbackItems = false;
        if (!kCallbackItemsArray.isEmpty() && !loadCallbackItemsFromJson(kCallbackItemsArray, profile, callbackDiagnostics, hasCallbackItems))
        {
            profile.diagnosticsText = callbackDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasCallbackItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
        }
        QStringList typedDiagnostics;
        bool hasTypedItems = false;
        if (!loadTypedItemsFromJson(typedItemsArray, profile, typedDiagnostics, hasTypedItems))
        {
            profile.diagnosticsText = typedDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasTypedItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
            profile.applyInput.fields.clear();
        }
        if (kFieldsObject.isEmpty() && !hasTypedItems)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.fields_empty", QStringLiteral("profile fields 为空。"));
            return profile;
        }

        if (invalidOffsetCount != 0U && !hasTypedItems)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.invalid_offset", QStringLiteral("profile 含 %1 个越界或无效 offset，R3 已拒绝应用。")).arg(invalidOffsetCount);
            return profile;
        }
        if ((profile.applyInput.fields.empty() && profile.applyExInput.items.empty()) ||
            profile.applyInput.fields.size() > KSW_DYN_PROFILE_MAX_FIELDS ||
            profile.applyExInput.items.size() > KSW_DYN_PROFILE_EX_MAX_ITEMS)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.count_invalid", QStringLiteral("profile 有效字段/item 数量异常: fields=%1 items=%2。"))
                .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
                .arg(static_cast<qulonglong>(profile.applyExInput.items.size()));
            return profile;
        }

        profile.valid = true;
        profile.diagnosticsText = kernelText("kernel.dyndata.profile.matched_summary", QStringLiteral("profile 匹配，字段 %1 个，typed 项 %2 个，callback 项 %3 个，忽略未知字段 %4 个。"))
            .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
            .arg(static_cast<qulonglong>(profile.typedItemCount))
            .arg(static_cast<qulonglong>(profile.callbackItemCount))
            .arg(profile.ignoredUnknownFields);
        return profile;
    }

    // loadPdbProfilePackEntry：
    // - Input: pack record, currentIdentity, fieldDictionary, packVersion: pack profile entry, current kernel identity, field dictionary, and version;
    // - Processing: Expand v3 typed items and v4 stable items into apply input.
    // - Returns: LocalPdbProfile; matched=false indicates it is not the current kernel profile.
    LocalPdbProfile loadPdbProfilePackEntry(
        const QJsonObject& packEntry,
        const QJsonArray& fieldDictionary,
        const std::uint32_t packVersion,
        const ksword::ark::ArkDynModuleIdentity& currentIdentity)
    {
        LocalPdbProfile profile;
        profile.sourceText = QStringLiteral("pack");

        std::uint32_t profileClass = 0U;
        std::uint32_t machine = 0U;
        std::uint32_t timeDateStamp = 0U;
        std::uint32_t sizeOfImage = 0U;
        if (!profileClassIdFromJsonValue(packEntry.value(QStringLiteral("moduleClassId")), profileClass) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("machine")), machine) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("timeDateStamp")), timeDateStamp) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("sizeOfImage")), sizeOfImage))
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.identity_missing", QStringLiteral("pack profile identity 字段缺失或格式无效。"));
            return profile;
        }

        profile.matched = currentIdentity.present &&
            currentIdentity.classId == profileClass &&
            currentIdentity.machine == machine &&
            currentIdentity.timeDateStamp == timeDateStamp &&
            currentIdentity.sizeOfImage == sizeOfImage;
        if (!profile.matched)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.identity_mismatch", QStringLiteral("pack profile identity 不匹配当前内核。"));
            return profile;
        }

        // Release packs are v4-only.  The old fields/typedItems/legacyItems
        // projections are intentionally ignored even if a stale local file
        // still contains them.
        const QJsonArray kFieldsArray;
        const QJsonArray kTypedItemsArray;
        const QJsonArray kV4ItemsArray = packVersion == 4U
            ? packEntry.value(QStringLiteral("items")).toArray()
            : QJsonArray();
        if (kFieldsArray.isEmpty() && kTypedItemsArray.isEmpty() && kV4ItemsArray.isEmpty())
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.fields_empty", QStringLiteral("pack profile fields/items 均为空。"));
            return profile;
        }

        const QJsonValue kProfileNameValue = packEntry.value(QStringLiteral("profileName"));
        const QJsonValue kPdbNameValue = packEntry.value(QStringLiteral("pdbName"));
        const QJsonValue kPdbGuidValue = packEntry.value(QStringLiteral("pdbGuid"));
        QString profileNameText = kProfileNameValue.toString().trimmed();
        if (profileNameText.isEmpty())
        {
            profileNameText = QStringLiteral("pack-profile");
        }
        profile.applyInput.profileName = profileNameText.toStdString();
        profile.applyInput.pdbName = kPdbNameValue.toString().toStdString();
        profile.applyInput.pdbGuid = kPdbGuidValue.toString().toStdString();
        std::uint32_t pdbAge = 0U;
        if (parseProfileUInt32(packEntry.value(QStringLiteral("pdbAge")), pdbAge))
        {
            profile.applyInput.pdbAge = pdbAge;
        }
        profile.applyInput.ntoskrnl = currentIdentity;

        std::uint32_t invalidFieldCount = 0U;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& entryValue : kFieldsArray)
        {
            const QJsonArray kPairArray = entryValue.toArray();
            if (kPairArray.size() != 2)
            {
                invalidFieldCount += 1U;
                continue;
            }

            std::uint32_t fieldIndex = 0U;
            std::uint32_t offset = 0U;
            if (!parseProfileUInt32(kPairArray.at(0), fieldIndex) ||
                !parseProfileUInt32(kPairArray.at(1), offset) ||
                fieldIndex >= static_cast<std::uint32_t>(fieldDictionary.size()))
            {
                invalidFieldCount += 1U;
                continue;
            }

            const QString kFieldName = fieldDictionary.at(static_cast<int>(fieldIndex)).toString();
            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(kFieldName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }
            if (offset == 0xFFFFFFFFU || offset > KSW_DYN_PROFILE_OFFSET_MAX)
            {
                invalidFieldCount += 1U;
                continue;
            }
            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId])
            {
                invalidFieldCount += 1U;
                continue;
            }
            seenFieldIds[fieldId] = true;

            ksword::ark::DynDataProfileField field{};
            field.fieldId = fieldId;
            field.offset = offset;
            profile.applyInput.fields.push_back(field);
        }

        const QJsonArray kCallbackItemsArray;
        QStringList callbackDiagnostics;
        bool hasCallbackItems = false;
        if (!kCallbackItemsArray.isEmpty() && !loadCallbackItemsFromJson(kCallbackItemsArray, profile, callbackDiagnostics, hasCallbackItems))
        {
            profile.diagnosticsText = callbackDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasCallbackItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
        }

        QStringList typedDiagnostics;
        bool hasTypedItems = false;
        if (!loadTypedItemsFromJson(kTypedItemsArray, profile, typedDiagnostics, hasTypedItems))
        {
            profile.diagnosticsText = typedDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasTypedItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
            profile.applyInput.fields.clear();
        }
        if (packVersion == 4U)
        {
            QStringList v4Diagnostics;
            if (!loadV4ItemsFromJson(
                    kV4ItemsArray,
                    packEntry.value(QStringLiteral("capabilityGroups")).toArray(),
                    currentIdentity,
                    profileNameText,
                    QString::fromStdString(profile.applyInput.pdbName),
                    QString::fromStdString(profile.applyInput.pdbGuid),
                    profile.applyInput.pdbAge,
                    profile,
                    v4Diagnostics))
            {
                profile.diagnosticsText = v4Diagnostics.join(QStringLiteral(" | "));
                return profile;
            }
        }
        if (invalidFieldCount != 0U && kV4ItemsArray.isEmpty())
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.invalid_fields", QStringLiteral("pack profile 含 %1 个越界或无效字段，R3 已拒绝应用。"))
                .arg(invalidFieldCount);
            return profile;
        }
        if ((profile.applyInput.fields.empty() && profile.applyExInput.items.empty() && profile.applyV4Input.items.empty()) ||
            profile.applyInput.fields.size() > KSW_DYN_PROFILE_MAX_FIELDS ||
            profile.applyExInput.items.size() > KSW_DYN_PROFILE_EX_MAX_ITEMS)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.count_invalid", QStringLiteral("pack profile 有效字段/item 数量异常: fields=%1 items=%2。"))
                .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
                .arg(static_cast<qulonglong>(profile.applyExInput.items.size()));
            return profile;
        }

        profile.valid = true;
        profile.diagnosticsText = kernelText("kernel.dyndata.pack.matched_summary", QStringLiteral("pack profile 匹配，字段 %1 个，typed 项 %2 个，callback 项 %3 个，v4 项 %4 个，忽略未知字段 %5 个。"))
            .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
            .arg(static_cast<qulonglong>(profile.typedItemCount))
            .arg(static_cast<qulonglong>(profile.callbackItemCount))
            .arg(static_cast<qulonglong>(profile.v4ItemCount))
            .arg(profile.ignoredUnknownFields);
        return profile;
    }

    // loadPdbProfilePackFile：
    // - Inputs: filePath (candidate pack), currentIdentity (current kernel identity), and diagnosticsOut (diagnostic output).
    // - Processing: Validate v4 pack schema and profiles array to find an exact match entry.
    // - Returns: matching profile; valid=false/matched=false on miss or invalid pack.
    LocalPdbProfile loadPdbProfilePackFile(const QString& filePath, const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        bestProfile.sourceText = QStringLiteral("pack");
        bestProfile.pathText = QDir::toNativeSeparators(filePath);

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument kDocument = ks::profile::readProfileJsonDocument(filePath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
        {
            diagnosticsOut = readErrorText.isEmpty()
                ? kernelText("kernel.dyndata.pack.json_parse_failed", QStringLiteral("PDB profile pack JSON 解析失败: %1")).arg(parseError.errorString())
                : readErrorText;
            return bestProfile;
        }

        const QJsonObject kRootObject = kDocument.object();
        std::uint32_t schemaVersion = 0U;
        std::uint32_t packVersion = 0U;
        if (!parseProfileUInt32(kRootObject.value(QStringLiteral("schemaVersion")), schemaVersion) ||
            !parseProfileUInt32(kRootObject.value(QStringLiteral("packVersion")), packVersion) ||
            schemaVersion != 1U || packVersion != 4U)
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.version_unsupported", QStringLiteral("PDB profile pack schemaVersion/packVersion 不支持。"));
            return bestProfile;
        }

        const QJsonArray kFieldDictionary = kRootObject.value(QStringLiteral("fieldDictionary")).toArray();
        const QJsonArray kProfilesArray = kRootObject.value(QStringLiteral("profiles")).toArray();
        if (!kFieldDictionary.isEmpty() || kProfilesArray.isEmpty())
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.dictionary_or_profiles_empty", QStringLiteral("PDB profile pack 字段字典或 profile 列表为空。"));
            return bestProfile;
        }

        std::uint32_t invalidDictionaryFields = 0U;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenDictionaryFieldIds{};
        for (const QJsonValue& fieldNameValue : kFieldDictionary)
        {
            std::uint32_t ignoredFieldId = 0U;
            if (!fieldNameValue.isString() || !fieldIdForProfileName(fieldNameValue.toString(), ignoredFieldId))
            {
                invalidDictionaryFields += 1U;
                continue;
            }
            if (ignoredFieldId >= seenDictionaryFieldIds.size() || seenDictionaryFieldIds[ignoredFieldId])
            {
                invalidDictionaryFields += 1U;
                continue;
            }
            seenDictionaryFieldIds[ignoredFieldId] = true;
        }
        if (invalidDictionaryFields != 0U)
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.unknown_dictionary_fields", QStringLiteral("PDB profile pack 字段字典包含 %1 个未知字段，已拒绝。"))
                .arg(invalidDictionaryFields);
            return bestProfile;
        }

        std::uint32_t scannedCount = 0U;
        std::uint32_t invalidMatchedCount = 0U;
        for (const QJsonValue& profileValue : kProfilesArray)
        {
            if (!profileValue.isObject())
            {
                continue;
            }

            scannedCount += 1U;
            LocalPdbProfile profile = loadPdbProfilePackEntry(profileValue.toObject(), kFieldDictionary, packVersion, currentIdentity);
            profile.pathText = QDir::toNativeSeparators(filePath);
            if (profile.matched)
            {
                if (profile.valid)
                {
                    diagnosticsOut = kernelText("kernel.dyndata.pack.matched", QStringLiteral("PDB profile pack 命中；路径=%1，profiles=%2，扫描=%3，%4"))
                        .arg(QDir::toNativeSeparators(filePath))
                        .arg(static_cast<qulonglong>(kProfilesArray.size()))
                        .arg(scannedCount)
                        .arg(profile.diagnosticsText);
                    return profile;
                }

                invalidMatchedCount += 1U;
                if (!bestProfile.matched)
                {
                    bestProfile = profile;
                    bestProfile.pathText = QDir::toNativeSeparators(filePath);
                }
            }
        }

        diagnosticsOut = kernelText("kernel.dyndata.pack.not_matched", QStringLiteral("PDB profile pack 未命中；路径=%1，profiles=%2，扫描=%3，无效命中=%4。"))
            .arg(QDir::toNativeSeparators(filePath))
            .arg(static_cast<qulonglong>(kProfilesArray.size()))
            .arg(scannedCount)
            .arg(invalidMatchedCount);
        return bestProfile;
    }

    // findMatchingPdbProfilePack：
    // - Input currentIdentity/diagnosticsOut: Current kernel identity and diagnostic output;
    // - Processing: Search using the default pack path and environment variable paths, returning the first valid match;
    // - Returns: Matching profile; if not found, valid=false and matched=false.
    LocalPdbProfile findMatchingPdbProfilePack(const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        QStringList diagnostics;
        std::uint32_t existingPackCount = 0U;

        for (const QString& packPath : profilePackSearchPaths())
        {
            const QString kResolvedPackPath = ks::profile::resolveProfileJsonPath(packPath);
            if (kResolvedPackPath.isEmpty())
            {
                diagnostics << kernelText("kernel.dyndata.pack.missing", QStringLiteral("pack 不存在: %1")).arg(QDir::toNativeSeparators(packPath));
                continue;
            }

            existingPackCount += 1U;
            QString packDiagnostics;
            LocalPdbProfile profile = loadPdbProfilePackFile(kResolvedPackPath, currentIdentity, packDiagnostics);
            diagnostics << packDiagnostics;
            if (profile.matched)
            {
                if (profile.valid)
                {
                    diagnosticsOut = diagnostics.join(QStringLiteral(" | "));
                    return profile;
                }
                if (!bestProfile.matched)
                {
                    bestProfile = profile;
                }
            }
        }

        diagnosticsOut = kernelText("kernel.dyndata.pack.no_match", QStringLiteral("未找到匹配 PDB profile pack；检查 %1 个存在的 pack。%2"))
            .arg(existingPackCount)
            .arg(diagnostics.join(QStringLiteral(" | ")));
        return bestProfile;
    }

    // findMatchingPdbProfile：
    // - Input currentIdentity/diagnosticsOut: Current ntoskrnl identity and diagnostic output.
    // - Processing: prioritize scanning the compact pack; only scan scattered JSON files when KSWORD_ARK_PROFILE_DIR is explicitly set.
    // - Returns: Matching profile; if not found, valid=false and matched=false.
    LocalPdbProfile findMatchingPdbProfile(const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        QStringList diagnostics;

        if (!currentIdentity.present)
        {
            diagnosticsOut = kernelText("kernel.dyndata.profile.identity_unavailable", QStringLiteral("当前 ntoskrnl identity 不可用，跳过 PDB profile 扫描。"));
            return bestProfile;
        }

        QString packDiagnostics;
        LocalPdbProfile packProfile = findMatchingPdbProfilePack(currentIdentity, packDiagnostics);
        diagnostics << packDiagnostics;
        if (packProfile.valid)
        {
            diagnosticsOut = packDiagnostics;
            return packProfile;
        }
        if (packProfile.matched)
        {
            return packProfile;
        }

        diagnosticsOut = kernelText("kernel.dyndata.profile.pack_only_no_match", QStringLiteral("未找到匹配的 v4 PDB profile pack。%1"))
            .arg(diagnostics.join(QStringLiteral(" | ")));
        return packProfile;
    }

    // capabilityNames：
    // - Input mask: Capability bitmap;
    // - Processing: Iterate capability table and concatenate matched names.
    // - Returns: Comma-separated names; returns 'None' if no match is found.
    QString capabilityNames(const std::uint64_t mask)
    {
        QStringList names;
        for (const CapabilityDisplay& capability : kCapabilities)
        {
            if ((mask & capability.mask) == capability.mask)
            {
                names << QString::fromLatin1(capability.name);
            }
        }
        return names.isEmpty() ? QStringLiteral("None") : names.join(QStringLiteral(", "));
    }

    // capabilityReport：
    // - Input mask: Capability bitmap;
    // - Processing: List enabled/disabled items one by one.
    // - Returns: multi-line report text.
    QString capabilityReport(const std::uint64_t mask)
    {
        QStringList lines;
        for (const CapabilityDisplay& capability : kCapabilities)
        {
            const bool kEnabled = (mask & capability.mask) == capability.mask;
            lines << QStringLiteral("%1 [%2] %3")
                .arg(kEnabled ? QStringLiteral("[ON]") : QStringLiteral("[OFF]"))
                .arg(QString::fromLatin1(capability.name))
                .arg(kernelText(capability.contextKey, QString::fromWCharArray(capability.title)));
        }
        return lines.join(QStringLiteral("\n"));
    }

    // disabledCapabilitySummary：
    // - Input mask: Capability bitmap;
    // - Action: Collect Chinese names of disabled capabilities;
    // - Returns: Missing capability summary.
    QString disabledCapabilitySummary(const std::uint64_t mask)
    {
        QStringList disabledItems;
        for (const CapabilityDisplay& capability : kCapabilities)
        {
            if ((mask & capability.mask) != capability.mask)
            {
                disabledItems << kernelText(capability.contextKey, QString::fromWCharArray(capability.title));
            }
        }
        return disabledItems.isEmpty()
            ? kernelText("kernel.dyndata.capability.none", QStringLiteral("无"))
            : disabledItems.join(QStringLiteral(", "));
    }

    // convertModuleIdentity：
    // - Input source: ArkDriverClient module identity.
    // - Processing: Convert to KernelDock internal model;
    // - Returns: KernelDynDataModuleIdentity value object.
    KernelDynDataModuleIdentity convertModuleIdentity(const ksword::ark::ArkDynModuleIdentity& source)
    {
        KernelDynDataModuleIdentity result{};
        result.present = source.present;
        result.classId = source.classId;
        result.machine = source.machine;
        result.timeDateStamp = source.timeDateStamp;
        result.sizeOfImage = source.sizeOfImage;
        result.imageBase = source.imageBase;
        result.moduleNameText = wideStringToQString(source.moduleName);
        return result;
    }

    // convertV4PacketIdentity：
    // - Input: source: shared module identity packet returned by queryDynDataV4Modules.
    // - Processing: Safely extract module name by fixed length, then convert to R3 type required for profile lookup.
    // - Return: ArkDynModuleIdentity value object.
    ksword::ark::ArkDynModuleIdentity convertV4PacketIdentity(
        const KSW_DYN_MODULE_IDENTITY_PACKET& source)
    {
        ksword::ark::ArkDynModuleIdentity result{};
        result.present = source.present != 0UL;
        result.classId = static_cast<std::uint32_t>(source.classId);
        result.machine = static_cast<std::uint32_t>(source.machine);
        result.timeDateStamp =
            static_cast<std::uint32_t>(source.timeDateStamp);
        result.sizeOfImage =
            static_cast<std::uint32_t>(source.sizeOfImage);
        result.imageBase = static_cast<std::uint64_t>(source.imageBase);
        std::size_t moduleNameLength = 0U;
        while (moduleNameLength < KSW_DYN_MODULE_NAME_CHARS &&
            source.moduleName[moduleNameLength] != L'\0')
        {
            ++moduleNameLength;
        }
        result.moduleName.assign(
            source.moduleName,
            source.moduleName + moduleNameLength);
        return result;
    }

    // moduleDetailText：
    // - Input title/source: module title and identity structure;
    // - Processing: Format module identity.
    // - Returns: multi-line diagnostic text.
    QString moduleDetailText(const QString& title, const KernelDynDataModuleIdentity& source)
    {
        if (!source.present)
        {
            return kernelText("kernel.dyndata.module.unavailable", QStringLiteral("%1: <未加载或未识别>")).arg(title);
        }

        return QStringLiteral(
            "%1:\n"
            "  ModuleName: %2\n"
            "  Class: %3 (%4)\n"
            "  Machine: %5\n"
            "  TimeDateStamp: %6\n"
            "  SizeOfImage: %7\n"
            "  ImageBase: %8")
            .arg(title)
            .arg(safeText(source.moduleNameText))
            .arg(moduleClassText(source.classId))
            .arg(source.classId)
            .arg(formatHex32(source.machine))
            .arg(formatHex32(source.timeDateStamp))
            .arg(formatHex32(source.sizeOfImage))
            .arg(formatHex64(source.imageBase));
    }

    // appendSummaryRow：
    // - Input: table, name, value; Summary table, field name, and value.
    // - Processing: Append read-only row.
    // - Returns: Nothing.
    void appendSummaryRow(QTableWidget* table, const QString& nameText, const QString& valueText)
    {
        if (table == nullptr)
        {
            return;
        }

        const int kRowIndex = table->rowCount();
        table->insertRow(kRowIndex);

        auto* nameItem = new QTableWidgetItem(nameText);
        auto* valueItem = new QTableWidgetItem(valueText);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);

        table->setItem(kRowIndex, static_cast<int>(SummaryColumn::kName), nameItem);
        table->setItem(kRowIndex, static_cast<int>(SummaryColumn::kValue), valueItem);
    }

    // setReadonlyItem：
    // - Input table/row/column/item: target table, row, column, and item;
    // - Processing: Remove the editable flag before inserting into the table;
    // - Returns: Nothing.
    void setReadonlyItem(QTableWidget* table, const int rowIndex, const DynDataColumn column, QTableWidgetItem* item)
    {
        if (table == nullptr || item == nullptr)
        {
            delete item;
            return;
        }

        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        table->setItem(rowIndex, static_cast<int>(column), item);
    }

    // buildFieldDetail：
    // - Input entry/summary: field row and current summary.
    // - Handling: Generate detail panel text, including capability dependencies and global status.
    // - Returns: multi-line detail text.
    QString buildFieldDetail(const KernelDynDataFieldEntry& entry, const KernelDynDataSummary& summary)
    {
        return kernelText("kernel.dyndata.detail.field", QStringLiteral(
            "字段名: %1\n"
            "字段ID: %2\n"
            "偏移: %3\n"
            "状态: %4\n"
            "来源: %5\n"
            "功能: %6\n"
            "字段标志: %7\n"
            "字段能力位: %8\n"
            "字段能力名: %9\n\n"
            "当前全局能力位: %10\n"
            "当前未启用能力: %11\n\n"
            "R0不可用原因: %12")
            .arg(safeText(entry.fieldNameText))
            .arg(entry.fieldId)
            .arg(formatOffset(entry.offset))
            .arg(safeText(entry.statusText))
            .arg(safeText(entry.sourceNameText))
            .arg(safeText(entry.featureNameText))
            .arg(formatHex32(entry.flags))
            .arg(formatHex64(entry.capabilityMask))
            .arg(capabilityNames(entry.capabilityMask))
            .arg(formatHex64(summary.capabilityMask))
            .arg(disabledCapabilitySummary(summary.capabilityMask))
            .arg(safeText(summary.unavailableReasonText)));
    }

    // buildDynDataReport：
    // - Input: summary and rows; summary and field rows;
    // - Processing: Construct a complete, copyable diagnostic report.
    // - Returns: multi-line report text.
    QString buildDynDataReport(const KernelDynDataSummary& summary, const std::vector<KernelDynDataFieldEntry>& rows)
    {
        QStringList lines;
        lines << QStringLiteral("Ksword DynData Diagnostic Report");
        lines << QStringLiteral("StatusQueryOk: %1").arg(boolText(summary.statusQueryOk));
        lines << QStringLiteral("FieldsQueryOk: %1").arg(boolText(summary.fieldsQueryOk));
        lines << QStringLiteral("StatusFlags: %1").arg(formatHex32(summary.statusFlags));
        lines << QStringLiteral("CapabilityMask: %1").arg(formatHex64(summary.capabilityMask));
        lines << QStringLiteral("SystemInformerDataVersion: %1").arg(summary.systemInformerDataVersion);
        lines << QStringLiteral("SystemInformerDataLength: %1").arg(summary.systemInformerDataLength);
        lines << QStringLiteral("LastStatus: %1").arg(formatNtStatus(summary.lastStatus));
        lines << QStringLiteral("MatchedProfileClass: %1").arg(moduleClassText(summary.matchedProfileClass));
        lines << QStringLiteral("MatchedProfileOffset: %1").arg(formatHex32(summary.matchedProfileOffset));
        lines << QStringLiteral("MatchedFieldsId: %1").arg(summary.matchedFieldsId);
        lines << QStringLiteral("UnavailableReason: %1").arg(safeText(summary.unavailableReasonText));
        lines << QStringLiteral("PdbProfileActive: %1").arg(boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)));
        lines << QStringLiteral("PdbProfileScanAttempted: %1").arg(boolText(summary.pdbProfileScanAttempted));
        lines << QStringLiteral("PdbProfileFound: %1").arg(boolText(summary.pdbProfileFound));
        lines << QStringLiteral("PdbProfileAppliedThisRefresh: %1").arg(boolText(summary.pdbProfileApplied));
        lines << QStringLiteral("PdbProfileSource: %1").arg(safeText(summary.pdbProfileSourceText));
        lines << QStringLiteral("PdbProfileName: %1").arg(safeText(summary.pdbProfileNameText));
        lines << QStringLiteral("PdbProfilePath: %1").arg(safeText(summary.pdbProfilePathText));
        lines << QStringLiteral("PdbProfileStatus: %1").arg(formatNtStatus(summary.pdbProfileStatus));
        lines << QStringLiteral("PdbProfileAppliedFields: %1").arg(summary.pdbProfileAppliedFields);
        lines << QStringLiteral("PdbProfileRejectedFields: %1").arg(summary.pdbProfileRejectedFields);
        lines << QStringLiteral("PdbProfileUnknownFields: %1").arg(summary.pdbProfileUnknownFields);
        lines << QStringLiteral("PdbProfileIgnoredJsonFields: %1").arg(summary.pdbProfileIgnoredJsonFields);
        lines << QStringLiteral("PdbProfileMessage: %1").arg(safeText(summary.pdbProfileMessageText));
        lines << QStringLiteral("PdbProfileIo: %1").arg(safeText(summary.pdbProfileIoMessageText));
        lines << moduleDetailText(QStringLiteral("ntoskrnl"), summary.ntoskrnl);
        lines << moduleDetailText(QStringLiteral("lxcore"), summary.lxcore);
        lines << QStringLiteral("");
        lines << QStringLiteral("Capabilities:");
        lines << capabilityReport(summary.capabilityMask);
        lines << QStringLiteral("");
        lines << QStringLiteral("Fields:");
        for (const KernelDynDataFieldEntry& entry : rows)
        {
            lines << QStringLiteral("%1\t%2\t%3\t%4\t%5\t%6")
                .arg(safeText(entry.fieldNameText))
                .arg(formatOffset(entry.offset))
                .arg(safeText(entry.statusText))
                .arg(safeText(entry.sourceNameText))
                .arg(safeText(entry.featureNameText))
                .arg(formatHex64(entry.capabilityMask));
        }
        return lines.join(QStringLiteral("\n"));
    }

    // populateSummaryTable：
    // - Input table/summary/visibleRows: Summary table, summary data, and current total field count.
    // - Processing: Rebuild two-column table;
    // - Returns: Nothing.
    void populateSummaryTable(QTableWidget* table, const KernelDynDataSummary& summary, const std::size_t visibleRows)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setSortingEnabled(false);
        table->setRowCount(0);
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.initialized", QStringLiteral("DynData 初始化")), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_INITIALIZED)));
        appendSummaryRow(table, QStringLiteral("ntoskrnl profile"), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE)));
        appendSummaryRow(table, QStringLiteral("lxcore profile"), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE)));
        appendSummaryRow(table, QStringLiteral("Ksword runtime offset"), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE)));
        appendSummaryRow(table, QStringLiteral("PDB profile active"), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_scan", QStringLiteral("PDB profile 扫描")), boolText(summary.pdbProfileScanAttempted));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_found", QStringLiteral("PDB profile 命中")), boolText(summary.pdbProfileFound));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_applied", QStringLiteral("PDB profile 本次应用")), boolText(summary.pdbProfileApplied));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_source", QStringLiteral("PDB profile 来源")), safeText(summary.pdbProfileSourceText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_name", QStringLiteral("PDB profile 名称")), safeText(summary.pdbProfileNameText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_path", QStringLiteral("PDB profile 路径")), safeText(summary.pdbProfilePathText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_status", QStringLiteral("PDB profile 状态")), formatNtStatus(summary.pdbProfileStatus));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_fields", QStringLiteral("PDB profile 字段")), QStringLiteral("applied=%1 rejected=%2 unknown=%3 ignoredJson=%4")
            .arg(summary.pdbProfileAppliedFields)
            .arg(summary.pdbProfileRejectedFields)
            .arg(summary.pdbProfileUnknownFields)
            .arg(summary.pdbProfileIgnoredJsonFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_message", QStringLiteral("PDB profile 消息")), safeText(summary.pdbProfileMessageText));
        appendSummaryRow(table, QStringLiteral("PDB profile IO"), safeText(summary.pdbProfileIoMessageText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.system_informer_version", QStringLiteral("System Informer 版本")), QString::number(summary.systemInformerDataVersion));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.system_informer_length", QStringLiteral("System Informer 数据长度")), QString::number(summary.systemInformerDataLength));
        appendSummaryRow(table, QStringLiteral("LastStatus"), formatNtStatus(summary.lastStatus));
        appendSummaryRow(table, QStringLiteral("MatchedProfileClass"), QStringLiteral("%1 (%2)").arg(moduleClassText(summary.matchedProfileClass)).arg(summary.matchedProfileClass));
        appendSummaryRow(table, QStringLiteral("MatchedProfileOffset"), formatHex32(summary.matchedProfileOffset));
        appendSummaryRow(table, QStringLiteral("MatchedFieldsId"), QString::number(summary.matchedFieldsId));
        appendSummaryRow(table, QStringLiteral("CapabilityMask"), formatHex64(summary.capabilityMask));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.field_count", QStringLiteral("字段总数/当前返回")), QStringLiteral("%1 / %2")
            .arg(summary.fieldCount)
            .arg(static_cast<qulonglong>(visibleRows)));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.disabled_capabilities", QStringLiteral("禁用能力")), disabledCapabilitySummary(summary.capabilityMask));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.unavailable_reason", QStringLiteral("不可用原因")), safeText(summary.unavailableReasonText));
        appendSummaryRow(table, QStringLiteral("Status IO"), safeText(summary.statusIoMessageText));
        appendSummaryRow(table, QStringLiteral("Fields IO"), safeText(summary.fieldsIoMessageText));
        appendSummaryRow(table, QStringLiteral("ntoskrnl"), moduleDetailText(QStringLiteral("ntoskrnl"), summary.ntoskrnl).replace(QStringLiteral("\n"), QStringLiteral("; ")));
        appendSummaryRow(table, QStringLiteral("lxcore"), moduleDetailText(QStringLiteral("lxcore"), summary.lxcore).replace(QStringLiteral("\n"), QStringLiteral("; ")));
        table->setSortingEnabled(false);
    }

    // populateProfileStatusTable：
    // - Input: table/summary: profile status table and DynData summary;
    // - Processing: Display only PDB profile-related status to confirm hit, fallback, and downgrade conditions;
    // - Returns: Nothing.
    void populateProfileStatusTable(QTableWidget* table, const KernelDynDataSummary& summary)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setSortingEnabled(false);
        table->setRowCount(0);
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.scan_attempted", QStringLiteral("扫描尝试")), boolText(summary.pdbProfileScanAttempted));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.found", QStringLiteral("找到匹配")), boolText(summary.pdbProfileFound));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.applied", QStringLiteral("已应用")), boolText(summary.pdbProfileApplied));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.r0_status", QStringLiteral("R0 状态")), formatNtStatus(summary.pdbProfileStatus));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.applied_fields", QStringLiteral("已应用字段")), QString::number(summary.pdbProfileAppliedFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.rejected_fields", QStringLiteral("拒绝字段")), QString::number(summary.pdbProfileRejectedFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.unknown_fields", QStringLiteral("未知字段")), QString::number(summary.pdbProfileUnknownFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.ignored_json_fields", QStringLiteral("忽略 JSON 字段")), QString::number(summary.pdbProfileIgnoredJsonFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.source", QStringLiteral("来源")), profileSourceDisplayText(summary.pdbProfileSourceText));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.name", QStringLiteral("名称")), safeText(summary.pdbProfileNameText));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.path", QStringLiteral("路径")), safeText(summary.pdbProfilePathText));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.message", QStringLiteral("消息")), safeText(summary.pdbProfileMessageText));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.io_message", QStringLiteral("IO 消息")), safeText(summary.pdbProfileIoMessageText));
        appendSummaryRow(table, QStringLiteral("V4 modules"), QStringLiteral("%1, io=%2, %3")
            .arg(v4CountText(summary.dynDataV4ModulesReturnedCount, summary.dynDataV4ModulesTotalCount))
            .arg(v4IoStateText(summary.dynDataV4ModulesQueryOk, summary.dynDataV4ModulesUnsupported))
            .arg(safeText(summary.dynDataV4ModulesIoMessageText)));
        appendSummaryRow(table, QStringLiteral("V4 capability groups"), QStringLiteral("%1, io=%2, %3")
            .arg(v4CountText(summary.dynDataV4CapabilityGroupsReturnedCount, summary.dynDataV4CapabilityGroupsTotalCount))
            .arg(v4IoStateText(summary.dynDataV4CapabilityGroupsQueryOk, summary.dynDataV4CapabilityGroupsUnsupported))
            .arg(safeText(summary.dynDataV4CapabilityGroupsIoMessageText)));
        appendSummaryRow(table, QStringLiteral("V4 missing items"), QStringLiteral("%1, io=%2, %3")
            .arg(v4CountText(summary.dynDataV4MissingItemsReturnedCount, summary.dynDataV4MissingItemsTotalCount))
            .arg(v4IoStateText(summary.dynDataV4MissingItemsQueryOk, summary.dynDataV4MissingItemsUnsupported))
            .arg(safeText(summary.dynDataV4MissingItemsIoMessageText)));
        appendSummaryRow(table, QStringLiteral("V4 accepted items"), QStringLiteral("%1, io=%2, %3")
            .arg(v4CountText(summary.dynDataV4ItemsReturnedCount, summary.dynDataV4ItemsTotalCount))
            .arg(v4IoStateText(summary.dynDataV4ItemsQueryOk, summary.dynDataV4ItemsUnsupported))
            .arg(safeText(summary.dynDataV4ItemsIoMessageText)));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.field_stats", QStringLiteral("字段统计")), QStringLiteral("applied=%1 rejected=%2 unknown=%3 ignoredJson=%4")
            .arg(summary.pdbProfileAppliedFields)
            .arg(summary.pdbProfileRejectedFields)
            .arg(summary.pdbProfileUnknownFields)
            .arg(summary.pdbProfileIgnoredJsonFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.matched_module", QStringLiteral("匹配模块")), safeText(summary.ntoskrnl.moduleNameText));
        appendSummaryRow(table, QStringLiteral("classId"), moduleClassText(summary.ntoskrnl.classId));
        appendSummaryRow(table, QStringLiteral("machine"), formatHex32(summary.ntoskrnl.machine));
        appendSummaryRow(table, QStringLiteral("timestamp"), formatHex32(summary.ntoskrnl.timeDateStamp));
        appendSummaryRow(table, QStringLiteral("imageSize"), formatHex32(summary.ntoskrnl.sizeOfImage));
        appendSummaryRow(table, QStringLiteral("imageBase"), formatHex64(summary.ntoskrnl.imageBase));
        table->setSortingEnabled(false);
    }

    // shouldShowField：
    // - Input entry/filterKeyword: Field row and filter keyword.
    // - Processing: match in field name, offset, source, function, status, and capability name;
    // - Returns: true if the row should be displayed.
    bool shouldShowField(const KernelDynDataFieldEntry& entry, const QString& filterKeyword)
    {
        if (filterKeyword.isEmpty())
        {
            return true;
        }

        return entry.fieldNameText.contains(filterKeyword, Qt::CaseInsensitive) ||
            formatOffset(entry.offset).contains(filterKeyword, Qt::CaseInsensitive) ||
            entry.statusText.contains(filterKeyword, Qt::CaseInsensitive) ||
            entry.sourceNameText.contains(filterKeyword, Qt::CaseInsensitive) ||
            entry.featureNameText.contains(filterKeyword, Qt::CaseInsensitive) ||
            capabilityNames(entry.capabilityMask).contains(filterKeyword, Qt::CaseInsensitive);
    }

    // queryDynDataSnapshot：
    // - Inputs: summaryOut, rowsOut, v4ItemRowsOut: output summary, field cache, and v4 accepted item cache;
    // - Processing: Query DynData base/v4 IOCTLs via ArkDriverClient and convert the model.
    // - Returns: true if both status and fields queries succeed.
    bool queryDynDataSnapshot(
        KernelDynDataSummary& summaryOut,
        std::vector<KernelDynDataFieldEntry>& rowsOut,
        std::vector<KernelDynDataV4ItemEntry>& v4ItemRowsOut)
    {
        ksword::ark::DriverClient client;
        const ksword::ark::DynDataStatusResult kInitialStatusResult = client.queryDynDataStatus();
        const ksword::ark::DynDataV4ModulesResult kInitialV4ModulesResult = client.queryDynDataV4Modules();
        const ksword::ark::DynDataV4CapabilityGroupsResult kInitialV4GroupsResult =
            client.queryDynDataV4CapabilityGroups();

        bool pdbProfileScanAttempted = false;
        bool pdbProfileFound = false;
        bool pdbProfileApplied = false;
        bool requeryAfterProfileApply = false;
        long pdbProfileStatus = 0;
        std::uint32_t pdbProfileAppliedFields = 0U;
        std::uint32_t pdbProfileRejectedFields = 0U;
        std::uint32_t pdbProfileUnknownFields = 0U;
        std::uint32_t pdbProfileIgnoredJsonFields = 0U;
        QString pdbProfileNameText;
        QString pdbProfilePathText;
        QString pdbProfileSourceText;
        QString pdbProfileMessageText;
        QString pdbProfileIoMessageText;

        if (kInitialStatusResult.io.ok)
        {
            const bool kPdbProfileAlreadyActive =
                statusFlagEnabled(kInitialStatusResult.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
            const bool kCallbackProfileAlreadyActive =
                statusFlagEnabled(kInitialStatusResult.statusFlags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE);
            const bool kV3ProfileAlreadyActive =
                (kInitialStatusResult.capabilityMask &
                    (KSW_CAP_PROCESS_LIST_FIELDS |
                        KSW_CAP_THREAD_LIST_FIELDS |
                        KSW_CAP_CID_TABLE_WALK |
                        KSW_CAP_KERNEL_MODULE_LIST_FIELDS |
                        KSW_CAP_DRIVER_OBJECT_FIELDS |
                        KSW_CAP_KERNEL_GLOBALS)) != 0ULL;
            const bool kV4ModuleProfileAlreadyActive = kInitialV4ModulesResult.io.ok && std::any_of(
                kInitialV4ModulesResult.entries.begin(),
                kInitialV4ModulesResult.entries.end(),
                [&kInitialStatusResult](const KSW_DYN_V4_MODULE_STATUS_ENTRY& entry) {
                    return entry.module.image.classId == kInitialStatusResult.ntoskrnl.classId &&
                        entry.module.image.machine == kInitialStatusResult.ntoskrnl.machine &&
                        entry.module.image.timeDateStamp == kInitialStatusResult.ntoskrnl.timeDateStamp &&
                        entry.module.image.sizeOfImage == kInitialStatusResult.ntoskrnl.sizeOfImage &&
                        (entry.statusFlags & KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED) != 0U;
                });
            const bool kV4ProfileAlreadyActive = kV4ModuleProfileAlreadyActive;
            if (kPdbProfileAlreadyActive && kCallbackProfileAlreadyActive && kV3ProfileAlreadyActive && kV4ProfileAlreadyActive)
            {
                pdbProfileMessageText = kernelText("kernel.dyndata.profile.apply.already_active", QStringLiteral("R0 已经启用 v4 DynData profile，本次刷新跳过重复 apply。"));
            }
            else
            {
                pdbProfileScanAttempted = true;
                QString scanDiagnostics;
                LocalPdbProfile profile =
                    findMatchingPdbProfile(
                        kInitialStatusResult.ntoskrnl,
                        scanDiagnostics);
                pdbProfileMessageText = scanDiagnostics;
                if (profile.matched)
                {
                    pdbProfileFound = true;
                    pdbProfileSourceText = profileSourceDisplayText(profile.sourceText);
                    pdbProfileNameText = stringToQString(profile.applyInput.profileName);
                    pdbProfilePathText = profile.pathText;
                    pdbProfileIgnoredJsonFields = profile.ignoredUnknownFields;

                    if (!profile.valid)
                    {
                        pdbProfileMessageText = profile.diagnosticsText;
                    }
                    else if (kPdbProfileAlreadyActive &&
                        kCallbackProfileAlreadyActive &&
                        kV3ProfileAlreadyActive &&
                        profile.applyV4Input.items.empty())
                    {
                        pdbProfileMessageText = kernelText("kernel.dyndata.profile.apply.v4_skip", QStringLiteral("R0 已启用 v4 DynData profile，当前匹配 profile 无可用 item，本次刷新跳过重复 apply。"));
                    }
                    else
                    {
                        QStringList applyMessages;
                        bool anyApplySucceeded = false;

                        if (!profile.applyExInput.items.empty() &&
                            !(kPdbProfileAlreadyActive && kCallbackProfileAlreadyActive && kV3ProfileAlreadyActive))
                        {
                            const ksword::ark::DynDataProfileApplyExResult kApplyExResult =
                                client.applyDynDataProfileEx(profile.applyExInput);
                            if (!pdbProfileIoMessageText.isEmpty())
                            {
                                pdbProfileIoMessageText += QStringLiteral(" | ");
                            }
                            pdbProfileIoMessageText += friendlyDynDataIoMessage(kApplyExResult.io.message);
                            pdbProfileStatus = kApplyExResult.status;
                            pdbProfileAppliedFields += kApplyExResult.appliedItemCount;
                            pdbProfileRejectedFields += kApplyExResult.rejectedItemCount;
                            pdbProfileUnknownFields += kApplyExResult.unknownItemCount;
                            if (!kApplyExResult.message.empty())
                            {
                                applyMessages << wideStringToQString(kApplyExResult.message);
                            }
                            anyApplySucceeded = anyApplySucceeded || (kApplyExResult.io.ok && kApplyExResult.status == 0);
                        }

                        if (!profile.applyV4Input.items.empty() && !kV4ProfileAlreadyActive)
                        {
                            const ksword::ark::DynDataV4ApplyResult kApplyV4Result =
                                client.applyDynDataProfileV4(profile.applyV4Input);
                            if (!pdbProfileIoMessageText.isEmpty())
                            {
                                pdbProfileIoMessageText += QStringLiteral(" | ");
                            }
                            pdbProfileIoMessageText += friendlyDynDataIoMessage(kApplyV4Result.io.message);
                            pdbProfileStatus = kApplyV4Result.response.status;
                            pdbProfileAppliedFields += kApplyV4Result.response.appliedItemCount;
                            pdbProfileRejectedFields += kApplyV4Result.response.rejectedItemCount;
                            if (kApplyV4Result.response.message[0] != L'\0')
                            {
                                applyMessages << wideStringToQString(kApplyV4Result.response.message);
                            }
                            anyApplySucceeded = anyApplySucceeded ||
                                (kApplyV4Result.io.ok &&
                                 kApplyV4Result.response.status == 0 &&
                                 kApplyV4Result.response.rejectedItemCount == 0U &&
                                 kApplyV4Result.response.missingRequiredItemCount == 0U);
                        }

                        if (!applyMessages.isEmpty())
                        {
                            pdbProfileMessageText = applyMessages.join(QStringLiteral(" | "));
                        }
                        pdbProfileApplied = anyApplySucceeded;
                        requeryAfterProfileApply = anyApplySucceeded;
                    }
                }
            }
        }
        else
        {
            pdbProfileMessageText = kernelText("kernel.dyndata.profile.status_query_failed", QStringLiteral("DynData status 查询失败，无法确认 ntoskrnl identity，跳过 PDB profile 扫描。"));
            pdbProfileIoMessageText = friendlyDynDataIoMessage(kInitialStatusResult.io.message);
        }

        // v4 module profiles must be selected precisely based on their current image identity; since ntoskrnl status does
        // not include fltmgr/ci identity, companion profiles are loaded module-by-module from the v4 initial snapshot.
        if (kInitialV4ModulesResult.io.ok)
        {
            for (const KSW_DYN_V4_MODULE_STATUS_ENTRY& moduleEntry :
                 kInitialV4ModulesResult.entries)
            {
                const bool kSupportedCompanion =
                    moduleEntry.module.image.classId ==
                        KSW_DYN_PROFILE_CLASS_FLTMGR ||
                    moduleEntry.module.image.classId ==
                        KSW_DYN_PROFILE_CLASS_CI;
                if (!kSupportedCompanion ||
                    moduleEntry.module.image.present == 0UL ||
                    (moduleEntry.statusFlags &
                        KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED) != 0U)
                {
                    continue;
                }

                pdbProfileScanAttempted = true;
                const ksword::ark::ArkDynModuleIdentity kModuleIdentity =
                    convertV4PacketIdentity(moduleEntry.module.image);
                const QString kModuleLabel =
                    QString::fromStdWString(kModuleIdentity.moduleName);
                QString moduleScanDiagnostics;
                LocalPdbProfile moduleProfile =
                    findMatchingPdbProfile(
                        kModuleIdentity,
                        moduleScanDiagnostics);
                const QString kModuleDiagnosticBlock =
                    QStringLiteral("%1: %2")
                        .arg(kModuleLabel, moduleScanDiagnostics);
                if (!pdbProfileMessageText.isEmpty())
                {
                    pdbProfileMessageText += QStringLiteral(" | ");
                }
                pdbProfileMessageText += kModuleDiagnosticBlock;

                if (!moduleProfile.matched)
                {
                    continue;
                }
                pdbProfileFound = true;
                if (pdbProfileSourceText.isEmpty())
                {
                    pdbProfileSourceText =
                        profileSourceDisplayText(moduleProfile.sourceText);
                    pdbProfileNameText =
                        stringToQString(
                            moduleProfile.applyInput.profileName);
                    pdbProfilePathText = moduleProfile.pathText;
                }
                pdbProfileIgnoredJsonFields +=
                    moduleProfile.ignoredUnknownFields;
                if (!moduleProfile.valid ||
                    moduleProfile.applyV4Input.items.empty())
                {
                    continue;
                }

                const ksword::ark::DynDataV4ApplyResult kModuleApplyResult =
                    client.applyDynDataProfileV4(
                        moduleProfile.applyV4Input);
                if (!pdbProfileIoMessageText.isEmpty())
                {
                    pdbProfileIoMessageText += QStringLiteral(" | ");
                }
                pdbProfileIoMessageText +=
                    friendlyDynDataIoMessage(
                        kModuleApplyResult.io.message);
                pdbProfileStatus =
                    kModuleApplyResult.response.status;
                pdbProfileAppliedFields +=
                    kModuleApplyResult.response.appliedItemCount;
                pdbProfileRejectedFields +=
                    kModuleApplyResult.response.rejectedItemCount;
                if (kModuleApplyResult.response.message[0] != L'\0')
                {
                    pdbProfileMessageText +=
                        QStringLiteral(" | %1: ").arg(kModuleLabel);
                    pdbProfileMessageText +=
                        wideStringToQString(
                            kModuleApplyResult.response.message);
                }
                const bool kModuleApplySucceeded =
                    kModuleApplyResult.io.ok &&
                    kModuleApplyResult.response.status == 0 &&
                    kModuleApplyResult.response.rejectedItemCount == 0U &&
                    kModuleApplyResult.response.missingRequiredItemCount == 0U;
                pdbProfileApplied =
                    pdbProfileApplied || kModuleApplySucceeded;
                requeryAfterProfileApply =
                    requeryAfterProfileApply ||
                    kModuleApplySucceeded;
            }
        }

        ksword::ark::DynDataStatusResult statusResult = kInitialStatusResult;
        if (requeryAfterProfileApply)
        {
            const ksword::ark::DynDataStatusResult kRefreshedStatusResult = client.queryDynDataStatus();
            if (kRefreshedStatusResult.io.ok)
            {
                statusResult = kRefreshedStatusResult;
            }
            else if (pdbProfileIoMessageText.isEmpty())
            {
                pdbProfileIoMessageText = friendlyDynDataIoMessage(kRefreshedStatusResult.io.message);
            }
        }

        const ksword::ark::DynDataFieldsResult kFieldsResult = client.queryDynDataFields();
        const ksword::ark::DynDataCapabilitiesResult kCapabilitiesResult = client.queryDynDataCapabilities();
        const ksword::ark::DynDataV4ModulesResult kV4ModulesResult = client.queryDynDataV4Modules();
        const ksword::ark::DynDataV4CapabilityGroupsResult kV4CapabilityGroupsResult =
            client.queryDynDataV4CapabilityGroups();
        const ksword::ark::DynDataV4MissingItemsResult kV4MissingItemsResult =
            client.queryDynDataV4MissingItems();
        const ksword::ark::DynDataV4ItemsResult kV4ItemsResult =
            client.queryDynDataV4Items();

        summaryOut = KernelDynDataSummary{};
        rowsOut.clear();
        v4ItemRowsOut.clear();

        summaryOut.statusQueryOk = statusResult.io.ok;
        summaryOut.fieldsQueryOk = kFieldsResult.io.ok;
        summaryOut.statusIoMessageText = friendlyDynDataIoMessage(statusResult.io.message);
        summaryOut.fieldsIoMessageText = friendlyDynDataIoMessage(kFieldsResult.io.message);
        summaryOut.pdbProfileScanAttempted = pdbProfileScanAttempted;
        summaryOut.pdbProfileFound = pdbProfileFound;
        summaryOut.pdbProfileApplied = pdbProfileApplied;
        summaryOut.pdbProfileStatus = pdbProfileStatus;
        summaryOut.pdbProfileAppliedFields = pdbProfileAppliedFields;
        summaryOut.pdbProfileRejectedFields = pdbProfileRejectedFields;
        summaryOut.pdbProfileUnknownFields = pdbProfileUnknownFields;
        summaryOut.pdbProfileIgnoredJsonFields = pdbProfileIgnoredJsonFields;
        summaryOut.pdbProfileSourceText = pdbProfileSourceText;
        summaryOut.pdbProfileNameText = pdbProfileNameText;
        summaryOut.pdbProfilePathText = pdbProfilePathText;
        summaryOut.pdbProfileMessageText = pdbProfileMessageText;
        summaryOut.pdbProfileIoMessageText = pdbProfileIoMessageText;
        summaryOut.dynDataV4ModulesQueryOk = kV4ModulesResult.io.ok;
        summaryOut.dynDataV4ModulesUnsupported = kV4ModulesResult.unsupported;
        summaryOut.dynDataV4ModulesTotalCount = kV4ModulesResult.totalCount;
        summaryOut.dynDataV4ModulesReturnedCount = kV4ModulesResult.returnedCount;
        summaryOut.dynDataV4ModulesIoMessageText = friendlyDynDataIoMessage(kV4ModulesResult.io.message);
        summaryOut.dynDataV4CapabilityGroupsQueryOk = kV4CapabilityGroupsResult.io.ok;
        summaryOut.dynDataV4CapabilityGroupsUnsupported = kV4CapabilityGroupsResult.unsupported;
        summaryOut.dynDataV4CapabilityGroupsTotalCount = kV4CapabilityGroupsResult.totalCount;
        summaryOut.dynDataV4CapabilityGroupsReturnedCount = kV4CapabilityGroupsResult.returnedCount;
        summaryOut.dynDataV4CapabilityGroupsIoMessageText = friendlyDynDataIoMessage(kV4CapabilityGroupsResult.io.message);
        summaryOut.dynDataV4MissingItemsQueryOk = kV4MissingItemsResult.io.ok;
        summaryOut.dynDataV4MissingItemsUnsupported = kV4MissingItemsResult.unsupported;
        summaryOut.dynDataV4MissingItemsTotalCount = kV4MissingItemsResult.totalCount;
        summaryOut.dynDataV4MissingItemsReturnedCount = kV4MissingItemsResult.returnedCount;
        summaryOut.dynDataV4MissingItemsIoMessageText = friendlyDynDataIoMessage(kV4MissingItemsResult.io.message);
        summaryOut.dynDataV4ItemsQueryOk = kV4ItemsResult.io.ok;
        summaryOut.dynDataV4ItemsUnsupported = kV4ItemsResult.unsupported;
        summaryOut.dynDataV4ItemsTotalCount = kV4ItemsResult.totalCount;
        summaryOut.dynDataV4ItemsReturnedCount = kV4ItemsResult.returnedCount;
        summaryOut.dynDataV4ItemsIoMessageText = friendlyDynDataIoMessage(kV4ItemsResult.io.message);

        v4ItemRowsOut.reserve(kV4ItemsResult.entries.size());
        for (const KSW_DYN_V4_ITEM_STATUS_ENTRY& sourceEntry : kV4ItemsResult.entries)
        {
            const KSW_DYN_V4_ITEM_PACKET& sourceItem = sourceEntry.item;
            KernelDynDataV4ItemEntry row{};
            row.moduleClassId = sourceEntry.moduleClassId;
            row.itemIndex = sourceEntry.itemIndex;
            row.itemId = sourceItem.itemId;
            row.itemKind = sourceItem.itemKind;
            row.flags = sourceItem.flags;
            row.capabilityGroupId = sourceItem.capabilityGroupId;
            row.value =
                (static_cast<std::uint64_t>(sourceItem.valueHigh) << 32U) |
                static_cast<std::uint64_t>(sourceItem.valueLow);
            row.kindText = v4ItemKindText(sourceItem.itemKind);
            row.flagsText = v4ItemFlagsText(sourceItem.flags);
            row.auxText = QStringLiteral("aux0=%1; aux1=%2; aux2=%3; aux3=%4")
                .arg(formatHex32(sourceItem.aux0))
                .arg(formatHex32(sourceItem.aux1))
                .arg(formatHex32(sourceItem.aux2))
                .arg(formatHex32(sourceItem.aux3));
            row.detailText = QStringLiteral(
                "module=%1 (%2)\n"
                "itemIndex=%3\n"
                "itemId=%4\n"
                "kind=%5 (%6)\n"
                "flags=%7\n"
                "capabilityGroupId=%8\n"
                "value=%9\n"
                "%10")
                .arg(moduleClassText(row.moduleClassId))
                .arg(row.moduleClassId)
                .arg(row.itemIndex)
                .arg(row.itemId)
                .arg(row.kindText)
                .arg(row.itemKind)
                .arg(row.flagsText)
                .arg(row.capabilityGroupId)
                .arg(v4ItemValueText(sourceItem))
                .arg(row.auxText);
            v4ItemRowsOut.push_back(row);
        }

        if (statusResult.io.ok)
        {
            summaryOut.statusFlags = statusResult.statusFlags;
            summaryOut.systemInformerDataVersion = statusResult.systemInformerDataVersion;
            summaryOut.systemInformerDataLength = statusResult.systemInformerDataLength;
            summaryOut.lastStatus = statusResult.lastStatus;
            summaryOut.matchedProfileClass = statusResult.matchedProfileClass;
            summaryOut.matchedProfileOffset = statusResult.matchedProfileOffset;
            summaryOut.matchedFieldsId = statusResult.matchedFieldsId;
            summaryOut.fieldCount = statusResult.fieldCount;
            summaryOut.capabilityMask = statusResult.capabilityMask;
            summaryOut.ntoskrnl = convertModuleIdentity(statusResult.ntoskrnl);
            summaryOut.lxcore = convertModuleIdentity(statusResult.lxcore);
            summaryOut.unavailableReasonText = wideStringToQString(statusResult.unavailableReason);
        }

        if (kCapabilitiesResult.io.ok)
        {
            summaryOut.capabilityMask = kCapabilitiesResult.capabilityMask;
            summaryOut.statusFlags = kCapabilitiesResult.statusFlags != 0U ? kCapabilitiesResult.statusFlags : summaryOut.statusFlags;
        }

        if (kFieldsResult.io.ok)
        {
            rowsOut.reserve(kFieldsResult.entries.size());
            for (const ksword::ark::DynDataFieldEntry& sourceEntry : kFieldsResult.entries)
            {
                KernelDynDataFieldEntry row{};
                row.fieldId = sourceEntry.fieldId;
                row.flags = sourceEntry.flags;
                row.source = sourceEntry.source;
                row.offset = sourceEntry.offset;
                row.capabilityMask = sourceEntry.capabilityMask;
                row.fieldNameText = stringToQString(sourceEntry.fieldName);
                row.sourceNameText = !sourceEntry.sourceName.empty()
                    ? stringToQString(sourceEntry.sourceName)
                    : sourceText(sourceEntry.source);
                row.featureNameText = stringToQString(sourceEntry.featureName);
                row.statusText = fieldPresent(row.flags, row.offset)
                    ? kernelText("kernel.dyndata.field.status.available", QStringLiteral("可用"))
                    : (row.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U
                        ? kernelText("kernel.dyndata.field.status.required_missing", QStringLiteral("缺失(必需)"))
                        : kernelText("kernel.dyndata.field.status.optional_missing", QStringLiteral("缺失(可选)"));
                row.detailText = buildFieldDetail(row, summaryOut);
                rowsOut.push_back(row);
            }
        }

        return summaryOut.statusQueryOk && summaryOut.fieldsQueryOk;
    }
}

void KernelDock::initializeDynDataTab()
{
    if (selfDriverInnerTabWidget_ == nullptr ||
        dynDataOverviewLayout_ != nullptr)
    {
        return;
    }

    // The overview and PDB Profile are directly attached to the 'Ksword Self-Driver' tab container
    // to avoid an empty intermediate layer between 'dynamic offset' and 'overview/PDB Profile'.
    dynDataOverviewPage_ = new QWidget(selfDriverInnerTabWidget_);
    dynDataOverviewLayout_ = new QVBoxLayout(dynDataOverviewPage_);
    dynDataOverviewLayout_->setContentsMargins(0, 0, 0, 0);
    dynDataOverviewLayout_->setSpacing(6);

    dynDataToolLayout_ = new QHBoxLayout();
    dynDataToolLayout_->setContentsMargins(0, 0, 0, 0);
    dynDataToolLayout_->setSpacing(6);

    refreshDynDataButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), dynDataOverviewPage_);
    refreshDynDataButton_->setToolTip(kernelText("kernel.dyndata.toolbar.refresh.tooltip", QStringLiteral("刷新 R0 DynData 状态和字段表")));
    refreshDynDataButton_->setStyleSheet(blueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshDynDataButton_);

    copyDynDataReportButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), kernelText("kernel.dyndata.toolbar.copy_report", QStringLiteral("复制诊断")), dynDataOverviewPage_);
    copyDynDataReportButton_->setToolTip(kernelText("kernel.dyndata.toolbar.copy_report.tooltip", QStringLiteral("复制 DynData 状态、能力和字段列表到剪贴板")));
    copyDynDataReportButton_->setStyleSheet(blueButtonStyle());

    dynDataFilterEdit_ = new QLineEdit(dynDataOverviewPage_);
    dynDataFilterEdit_->setPlaceholderText(kernelText("kernel.dyndata.toolbar.filter.placeholder", QStringLiteral("按字段名/偏移/状态/来源/功能/capability 筛选")));
    dynDataFilterEdit_->setToolTip(kernelText("kernel.dyndata.toolbar.filter.tooltip", QStringLiteral("输入关键字后实时过滤动态偏移字段表")));
    dynDataFilterEdit_->setClearButtonEnabled(true);
    dynDataFilterEdit_->setStyleSheet(blueInputStyle());

    dynDataStatusLabel_ = new QLabel(kernelText("kernel.dyndata.status.waiting", QStringLiteral("状态：等待刷新")), dynDataOverviewPage_);
    dynDataStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    dynDataToolLayout_->addWidget(refreshDynDataButton_, 0);
    dynDataToolLayout_->addWidget(copyDynDataReportButton_, 0);
    dynDataToolLayout_->addWidget(dynDataFilterEdit_, 1);
    dynDataToolLayout_->addWidget(dynDataStatusLabel_, 0);
    dynDataOverviewLayout_->addLayout(dynDataToolLayout_);

    QSplitter* verticalSplitter = new QSplitter(Qt::Vertical, dynDataOverviewPage_);
    dynDataOverviewLayout_->addWidget(verticalSplitter, 1);

    dynDataSummaryTable_ = new ks::ui::VisibleTableWidget(verticalSplitter);
    dynDataSummaryTable_->setColumnCount(static_cast<int>(SummaryColumn::kCount));
    dynDataSummaryTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.driver_status.summary.header.item", QStringLiteral("项目")),
        kernelText("kernel.driver_status.summary.header.value", QStringLiteral("值")) });
    dynDataSummaryTable_->setSelectionMode(QAbstractItemView::NoSelection);
    dynDataSummaryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    dynDataSummaryTable_->setAlternatingRowColors(true);
    dynDataSummaryTable_->setStyleSheet(itemSelectionStyle());
    dynDataSummaryTable_->setCornerButtonEnabled(false);
    dynDataSummaryTable_->verticalHeader()->setVisible(false);
    dynDataSummaryTable_->horizontalHeader()->setStyleSheet(headerStyle());
    dynDataSummaryTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    dynDataSummaryTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(SummaryColumn::kValue), QHeaderView::Stretch);
    dynDataSummaryTable_->setColumnWidth(static_cast<int>(SummaryColumn::kName), 220);
    dynDataSummaryTable_->setToolTip(kernelText("kernel.dyndata.summary.tooltip", QStringLiteral("DynData 精确匹配、模块身份和 capability 摘要")));
    installDynDataCopyMenu(dynDataSummaryTable_);

    QSplitter* lowerSplitter = new QSplitter(Qt::Horizontal, verticalSplitter);

    dynDataFieldTable_ = new ks::ui::VisibleTableWidget(lowerSplitter);
    dynDataFieldTable_->setColumnCount(static_cast<int>(DynDataColumn::kCount));
    dynDataFieldTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.dyndata.table.header.field", QStringLiteral("字段")),
        kernelText("kernel.dyndata.table.header.offset", QStringLiteral("偏移")),
        kernelText("kernel.driver_status.capability.header.state", QStringLiteral("状态")),
        kernelText("kernel.dyndata.table.header.source", QStringLiteral("来源")),
        kernelText("kernel.driver_status.capability.header.feature", QStringLiteral("功能")),
        QStringLiteral("Capability")
        });
    dynDataFieldTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    dynDataFieldTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    dynDataFieldTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    dynDataFieldTable_->setAlternatingRowColors(true);
    dynDataFieldTable_->setStyleSheet(itemSelectionStyle());
    dynDataFieldTable_->setCornerButtonEnabled(false);
    dynDataFieldTable_->verticalHeader()->setVisible(false);
    dynDataFieldTable_->horizontalHeader()->setStyleSheet(headerStyle());
    dynDataFieldTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    dynDataFieldTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(DynDataColumn::kField), QHeaderView::Stretch);
    dynDataFieldTable_->setColumnWidth(static_cast<int>(DynDataColumn::kOffset), 100);
    dynDataFieldTable_->setColumnWidth(static_cast<int>(DynDataColumn::kStatus), 110);
    dynDataFieldTable_->setColumnWidth(static_cast<int>(DynDataColumn::kSource), 180);
    dynDataFieldTable_->setColumnWidth(static_cast<int>(DynDataColumn::kFeature), 180);
    dynDataFieldTable_->setColumnWidth(static_cast<int>(DynDataColumn::kCapability), 180);
    installDynDataCopyMenu(dynDataFieldTable_);

    dynDataDetailEditor_ = new CodeEditorWidget(lowerSplitter);
    dynDataDetailEditor_->setReadOnly(true);
    dynDataDetailEditor_->setText(kernelText("kernel.dyndata.detail.initial", QStringLiteral("请选择一条动态偏移字段查看详情。")));

    verticalSplitter->setStretchFactor(0, 2);
    verticalSplitter->setStretchFactor(1, 5);
    lowerSplitter->setStretchFactor(0, 3);
    lowerSplitter->setStretchFactor(1, 2);

    dynDataTabIndex_ = selfDriverInnerTabWidget_->addTab(
        dynDataOverviewPage_,
        QIcon(QStringLiteral(":/Icon/process_priority.svg")),
        kernelText("kernel.dyndata.tab.overview", QStringLiteral("总览")));
    selfDriverInnerTabWidget_->setTabToolTip(
        dynDataTabIndex_,
        kernelText(
            "kernel.main.tab.dyn_data.tooltip",
            QStringLiteral("System Informer DynData 精确匹配状态与字段列表")));

    dynDataProfilePage_ = new QWidget(selfDriverInnerTabWidget_);
    dynDataProfileLayout_ = new QVBoxLayout(dynDataProfilePage_);
    dynDataProfileLayout_->setContentsMargins(4, 4, 4, 4);
    dynDataProfileLayout_->setSpacing(6);

    dynDataProfileStatusLabel_ = new QLabel(kernelText("kernel.dyndata.profile_status.waiting", QStringLiteral("状态：等待刷新")), dynDataProfilePage_);
    dynDataProfileStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));
    dynDataProfileLayout_->addWidget(dynDataProfileStatusLabel_, 0);

    QSplitter* profileSplitter = new QSplitter(Qt::Vertical, dynDataProfilePage_);
    dynDataProfileLayout_->addWidget(profileSplitter, 1);

    dynDataProfileSummaryTable_ = new ks::ui::VisibleTableWidget(profileSplitter);
    dynDataProfileSummaryTable_->setColumnCount(2);
    dynDataProfileSummaryTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.driver_status.summary.header.item", QStringLiteral("项目")),
        kernelText("kernel.driver_status.summary.header.value", QStringLiteral("值")) });
    dynDataProfileSummaryTable_->setSelectionMode(QAbstractItemView::NoSelection);
    dynDataProfileSummaryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    dynDataProfileSummaryTable_->setAlternatingRowColors(true);
    dynDataProfileSummaryTable_->setStyleSheet(itemSelectionStyle());
    dynDataProfileSummaryTable_->setCornerButtonEnabled(false);
    dynDataProfileSummaryTable_->verticalHeader()->setVisible(false);
    dynDataProfileSummaryTable_->horizontalHeader()->setStyleSheet(headerStyle());
    dynDataProfileSummaryTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    dynDataProfileSummaryTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    installDynDataCopyMenu(dynDataProfileSummaryTable_);

    dynDataV4ItemTable_ = new ks::ui::VisibleTableWidget(profileSplitter);
    dynDataV4ItemTable_->setColumnCount(9);
    dynDataV4ItemTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.dyndata.v4.header.module", QStringLiteral("模块")),
        kernelText("kernel.dyndata.v4.header.index", QStringLiteral("序号")),
        QStringLiteral("ItemId"),
        QStringLiteral("Kind"),
        QStringLiteral("Group"),
        QStringLiteral("Flags"),
        QStringLiteral("Value"),
        QStringLiteral("Aux"),
        kernelText("kernel.dyndata.v4.header.description", QStringLiteral("说明"))
        });
    dynDataV4ItemTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    dynDataV4ItemTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    dynDataV4ItemTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    dynDataV4ItemTable_->setAlternatingRowColors(true);
    dynDataV4ItemTable_->setStyleSheet(itemSelectionStyle());
    dynDataV4ItemTable_->setCornerButtonEnabled(false);
    dynDataV4ItemTable_->verticalHeader()->setVisible(false);
    dynDataV4ItemTable_->horizontalHeader()->setStyleSheet(headerStyle());
    dynDataV4ItemTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    dynDataV4ItemTable_->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
    dynDataV4ItemTable_->setToolTip(kernelText("kernel.dyndata.v4.tooltip", QStringLiteral("R0 已接受并缓存的 DynData v4 PDB item 清单，只读展示，不触发业务消费。")));
    installDynDataCopyMenu(dynDataV4ItemTable_);

    dynDataProfileDetailEditor_ = new CodeEditorWidget(profileSplitter);
    dynDataProfileDetailEditor_->setReadOnly(true);
    dynDataProfileDetailEditor_->setText(kernelText("kernel.dyndata.profile_status.detail.initial", QStringLiteral("请先刷新动态偏移，再查看 PDB profile 管理状态。")));

    profileSplitter->setStretchFactor(0, 2);
    profileSplitter->setStretchFactor(1, 3);
    profileSplitter->setStretchFactor(2, 2);

    dynDataProfileTabIndex_ = selfDriverInnerTabWidget_->addTab(
        dynDataProfilePage_,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("PDB Profile"));

    // Signal connection: Refresh, filter, current row details, and report copy are all handled internally on this page.
    connect(refreshDynDataButton_, &QPushButton::clicked, this, [this]() {
        refreshDynDataAsync();
    });
    connect(copyDynDataReportButton_, &QPushButton::clicked, this, [this]() {
        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard != nullptr)
        {
            clipboard->setText(buildDynDataReport(dynDataSummary_, dynDataRows_));
            dynDataStatusLabel_->setText(kernelText("kernel.dyndata.status.report_copied", QStringLiteral("状态：诊断报告已复制")));
        }
    });
    connect(dynDataFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildDynDataFieldTable(filterText.trimmed());
        rebuildDynDataV4ItemTable(filterText.trimmed());
    });
    connect(dynDataFieldTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showDynDataDetailByCurrentRow();
    });
}

void KernelDock::requestDynDataRefresh()
{
    if (!dynDataTabInitialized_)
    {
        initializeDynDataTab();
        dynDataTabInitialized_ = true;
    }

    refreshDynDataAsync();
}

void KernelDock::refreshDynDataAsync()
{
    if (dynDataRefreshRunning_.exchange(true))
    {
        KLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] DynData 刷新被忽略：已有任务运行。" << eol;
        return;
    }

    refreshDynDataButton_->setEnabled(false);
    dynDataStatusLabel_->setText(kernelText("kernel.dyndata.status.refreshing", QStringLiteral("状态：刷新中...")));
    dynDataStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        KernelDynDataSummary summary;
        std::vector<KernelDynDataFieldEntry> rows;
        std::vector<KernelDynDataV4ItemEntry> v4ItemRows;
        const bool kSuccess = queryDynDataSnapshot(summary, rows, v4ItemRows);

        QMetaObject::invokeMethod(guardThis, [guardThis, kSuccess, summary = std::move(summary), rows = std::move(rows), v4ItemRows = std::move(v4ItemRows)]() mutable {
            const auto kDeferredSummary =
                std::make_shared<KernelDynDataSummary>(std::move(summary));
            const auto kDeferredRows =
                std::make_shared<std::vector<KernelDynDataFieldEntry>>(std::move(rows));
            const auto kDeferredV4Rows =
                std::make_shared<std::vector<KernelDynDataV4ItemEntry>>(std::move(v4ItemRows));
            auto commitResult = [
                guardThis,
                kSuccess,
                kDeferredSummary,
                kDeferredRows,
                kDeferredV4Rows]() mutable
            {
            KernelDynDataSummary& summary = *kDeferredSummary;
            std::vector<KernelDynDataFieldEntry>& rows = *kDeferredRows;
            std::vector<KernelDynDataV4ItemEntry>& v4ItemRows = *kDeferredV4Rows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->dynDataRefreshRunning_.store(false);
            guardThis->refreshDynDataButton_->setEnabled(true);
            guardThis->dynDataSummary_ = std::move(summary);
            guardThis->dynDataRows_ = std::move(rows);
            guardThis->dynDataV4ItemRows_ = std::move(v4ItemRows);

            populateSummaryTable(
                guardThis->dynDataSummaryTable_,
                guardThis->dynDataSummary_,
                guardThis->dynDataRows_.size());
            guardThis->rebuildDynDataFieldTable(guardThis->dynDataFilterEdit_->text().trimmed());
            guardThis->rebuildDynDataV4ItemTable(guardThis->dynDataFilterEdit_->text().trimmed());

            const std::size_t kMissingRequiredCount = static_cast<std::size_t>(
                std::count_if(
                    guardThis->dynDataRows_.begin(),
                    guardThis->dynDataRows_.end(),
                    [](const KernelDynDataFieldEntry& entry) {
                        return (entry.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U &&
                            !fieldPresent(entry.flags, entry.offset);
                    }));

            if (!kSuccess)
            {
                guardThis->dynDataStatusLabel_->setText(kernelText("kernel.dyndata.status.refresh_failed", QStringLiteral("状态：刷新失败")));
                guardThis->dynDataStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
                guardThis->dynDataDetailEditor_->setText(buildDynDataReport(guardThis->dynDataSummary_, guardThis->dynDataRows_));
                populateProfileStatusTable(guardThis->dynDataProfileSummaryTable_, guardThis->dynDataSummary_);
                if (guardThis->dynDataProfileStatusLabel_ != nullptr)
                {
                    guardThis->dynDataProfileStatusLabel_->setText(kernelText("kernel.dyndata.profile_status.failed", QStringLiteral("状态：profile 诊断失败，保留现有摘要")));
                    guardThis->dynDataProfileStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
                }
                if (guardThis->dynDataProfileDetailEditor_ != nullptr)
                {
                    guardThis->dynDataProfileDetailEditor_->setText(
                        profileSummaryText(guardThis->dynDataSummary_) + QStringLiteral("\n\n") +
                        buildDynDataReport(guardThis->dynDataSummary_, guardThis->dynDataRows_));
                }
            }
            else
            {
                const bool kNtosActive = statusFlagEnabled(guardThis->dynDataSummary_.statusFlags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE);
                const bool kPdbProfileActive = statusFlagEnabled(guardThis->dynDataSummary_.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
                guardThis->dynDataStatusLabel_->setText(
                    kernelText("kernel.dyndata.status.summary", QStringLiteral("状态：%1%2，字段 %3 项，缺失必需 %4 项"))
                    .arg(kNtosActive ? kernelText("kernel.dyndata.status.ntos_hit", QStringLiteral("ntos profile 已命中")) : kernelText("kernel.dyndata.status.ntos_miss", QStringLiteral("ntos profile 未命中")))
                    .arg(kPdbProfileActive ? kernelText("kernel.dyndata.status.pdb_enabled_suffix", QStringLiteral("，PDB profile 已启用")) : QString())
                    .arg(static_cast<qulonglong>(guardThis->dynDataRows_.size()))
                    .arg(static_cast<qulonglong>(kMissingRequiredCount)));
                guardThis->dynDataStatusLabel_->setStyleSheet(
                    statusLabelStyle(kNtosActive && kPdbProfileActive && kMissingRequiredCount == 0U ? ksword_theme::successHex() : ksword_theme::warningHex()));

                if (guardThis->dynDataFieldTable_->rowCount() > 0)
                {
                    guardThis->dynDataFieldTable_->setCurrentCell(0, 0);
                }
                else
                {
                    guardThis->dynDataDetailEditor_->setText(kernelText("kernel.dyndata.empty.filtered", QStringLiteral("当前筛选条件下没有动态偏移字段。")));
                }

                populateProfileStatusTable(guardThis->dynDataProfileSummaryTable_, guardThis->dynDataSummary_);
                if (guardThis->dynDataProfileStatusLabel_ != nullptr)
                {
                    guardThis->dynDataProfileStatusLabel_->setText(
                        kernelText("kernel.dyndata.profile_status.summary", QStringLiteral("状态：%1，profile %2"))
                        .arg(kNtosActive ? kernelText("kernel.dyndata.status.ntos_hit", QStringLiteral("ntos profile 已命中")) : kernelText("kernel.dyndata.status.ntos_miss", QStringLiteral("ntos profile 未命中")))
                        .arg(kPdbProfileActive ? kernelText("kernel.dyndata.status.enabled", QStringLiteral("已启用")) : kernelText("kernel.dyndata.status.disabled", QStringLiteral("未启用"))));
                    guardThis->dynDataProfileStatusLabel_->setStyleSheet(
                        statusLabelStyle(kNtosActive && kPdbProfileActive ? ksword_theme::successHex() : ksword_theme::warningHex()));
                }
                if (guardThis->dynDataProfileDetailEditor_ != nullptr)
                {
                    guardThis->dynDataProfileDetailEditor_->setText(
                        profileSummaryText(guardThis->dynDataSummary_) + QStringLiteral("\n\n") +
                        buildDynDataReport(guardThis->dynDataSummary_, guardThis->dynDataRows_));
                }
            }

            KLogEvent doneEvent;
            info << doneEvent
                << "[KernelDock] DynData 刷新完成, success="
                << kSuccess
                << ", fields="
                << guardThis->dynDataRows_.size()
                << ", caps="
                << formatHex64(guardThis->dynDataSummary_.capabilityMask)
                << eol;

            if (guardThis->timerDpcRefreshAfterDynData_.exchange(false))
            {
                guardThis->refreshTimerDpcAsync();
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-dyndata-snapshot-apply"),
                {
                    guardThis->dynDataSummaryTable_,
                    guardThis->dynDataFieldTable_,
                    guardThis->dynDataProfileSummaryTable_,
                    guardThis->dynDataV4ItemTable_
                },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildDynDataFieldTable(const QString& filterKeyword)
{
    if (dynDataFieldTable_ == nullptr)
    {
        return;
    }

    dynDataFieldTable_->setSortingEnabled(false);
    dynDataFieldTable_->setRowCount(0);

    for (std::size_t sourceIndex = 0U; sourceIndex < dynDataRows_.size(); ++sourceIndex)
    {
        const KernelDynDataFieldEntry& entry = dynDataRows_[sourceIndex];
        if (!shouldShowField(entry, filterKeyword))
        {
            continue;
        }

        const int kRowIndex = dynDataFieldTable_->rowCount();
        dynDataFieldTable_->insertRow(kRowIndex);

        auto* fieldItem = new QTableWidgetItem(safeText(entry.fieldNameText));
        auto* offsetItem = new QTableWidgetItem(formatOffset(entry.offset));
        auto* statusItem = new QTableWidgetItem(safeText(entry.statusText));
        auto* sourceItem = new QTableWidgetItem(safeText(entry.sourceNameText));
        auto* featureItem = new QTableWidgetItem(safeText(entry.featureNameText));
        auto* capabilityItem = new QTableWidgetItem(formatHex64(entry.capabilityMask));

        fieldItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        if (!fieldPresent(entry.flags, entry.offset))
        {
            statusItem->setForeground(QBrush((entry.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U
                ? ksword_theme::errorColor()
                : ksword_theme::warningAccentColor()));
        }
        else
        {
            statusItem->setForeground(QBrush(ksword_theme::successColor()));
        }

        setReadonlyItem(dynDataFieldTable_, kRowIndex, DynDataColumn::kField, fieldItem);
        setReadonlyItem(dynDataFieldTable_, kRowIndex, DynDataColumn::kOffset, offsetItem);
        setReadonlyItem(dynDataFieldTable_, kRowIndex, DynDataColumn::kStatus, statusItem);
        setReadonlyItem(dynDataFieldTable_, kRowIndex, DynDataColumn::kSource, sourceItem);
        setReadonlyItem(dynDataFieldTable_, kRowIndex, DynDataColumn::kFeature, featureItem);
        setReadonlyItem(dynDataFieldTable_, kRowIndex, DynDataColumn::kCapability, capabilityItem);
    }

    dynDataFieldTable_->setSortingEnabled(true);
}

void KernelDock::rebuildDynDataV4ItemTable(const QString& filterKeyword)
{
    if (dynDataV4ItemTable_ == nullptr)
    {
        return;
    }

    // insertReadonlyCell：
    // - Input row/column/text: Target cell position and display text;
    // - Processing: Create non-editable item and write to v4 item table.
    // - Return: None. All table columns contain read-only audit information.
    const auto kInsertReadonlyCell = [this](const int row, const int column, const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        dynDataV4ItemTable_->setItem(row, column, item);
    };

    dynDataV4ItemTable_->setSortingEnabled(false);
    dynDataV4ItemTable_->setRowCount(0);

    for (const KernelDynDataV4ItemEntry& entry : dynDataV4ItemRows_)
    {
        if (!v4ItemMatchesFilter(entry, filterKeyword))
        {
            continue;
        }

        const int kRowIndex = dynDataV4ItemTable_->rowCount();
        dynDataV4ItemTable_->insertRow(kRowIndex);
        kInsertReadonlyCell(kRowIndex, 0, moduleClassText(entry.moduleClassId));
        kInsertReadonlyCell(kRowIndex, 1, QString::number(entry.itemIndex));
        kInsertReadonlyCell(kRowIndex, 2, QString::number(entry.itemId));
        kInsertReadonlyCell(kRowIndex, 3, entry.kindText);
        kInsertReadonlyCell(kRowIndex, 4, QString::number(entry.capabilityGroupId));
        kInsertReadonlyCell(kRowIndex, 5, entry.flagsText);
        kInsertReadonlyCell(kRowIndex, 6, formatHex64(entry.value));
        kInsertReadonlyCell(kRowIndex, 7, entry.auxText);
        kInsertReadonlyCell(kRowIndex, 8, QString(entry.detailText).replace(QStringLiteral("\n"), QStringLiteral("; ")));
    }

    if (dynDataV4ItemTable_->rowCount() == 0)
    {
        const QString kStateText = v4IoStateText(dynDataSummary_.dynDataV4ItemsQueryOk, dynDataSummary_.dynDataV4ItemsUnsupported);
        const QString kDetailText = kernelText("kernel.dyndata.v4.empty.detail", QStringLiteral("V4 accepted item 查询状态：%1；返回 %2/%3；%4"))
            .arg(kStateText)
            .arg(dynDataSummary_.dynDataV4ItemsReturnedCount)
            .arg(dynDataSummary_.dynDataV4ItemsTotalCount)
            .arg(safeText(dynDataSummary_.dynDataV4ItemsIoMessageText));
        const int kRowIndex = dynDataV4ItemTable_->rowCount();
        dynDataV4ItemTable_->insertRow(kRowIndex);
        kInsertReadonlyCell(kRowIndex, 0, kernelText("kernel.dyndata.v4.empty.item", QStringLiteral("<无v4 item>")));
        kInsertReadonlyCell(kRowIndex, 1, QStringLiteral("N/A"));
        kInsertReadonlyCell(kRowIndex, 2, QStringLiteral("N/A"));
        kInsertReadonlyCell(kRowIndex, 3, kStateText);
        kInsertReadonlyCell(kRowIndex, 4, QStringLiteral("N/A"));
        kInsertReadonlyCell(kRowIndex, 5, QStringLiteral("N/A"));
        kInsertReadonlyCell(kRowIndex, 6, QStringLiteral("N/A"));
        kInsertReadonlyCell(kRowIndex, 7, QStringLiteral("N/A"));
        kInsertReadonlyCell(kRowIndex, 8, kDetailText);
    }

    dynDataV4ItemTable_->setSortingEnabled(true);
}

bool KernelDock::currentDynDataFieldSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;

    if (dynDataFieldTable_ == nullptr)
    {
        return false;
    }

    const int kCurrentRow = dynDataFieldTable_->currentRow();
    if (kCurrentRow < 0)
    {
        return false;
    }

    QTableWidgetItem* fieldItem = dynDataFieldTable_->item(kCurrentRow, static_cast<int>(DynDataColumn::kField));
    if (fieldItem == nullptr)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(fieldItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < dynDataRows_.size();
}

const KernelDynDataFieldEntry* KernelDock::currentDynDataFieldEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentDynDataFieldSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &dynDataRows_[sourceIndex];
}

void KernelDock::showDynDataDetailByCurrentRow()
{
    if (dynDataDetailEditor_ == nullptr)
    {
        return;
    }

    const KernelDynDataFieldEntry* entry = currentDynDataFieldEntry();
    if (entry == nullptr)
    {
        dynDataDetailEditor_->setText(buildDynDataReport(dynDataSummary_, dynDataRows_));
        return;
    }

    dynDataDetailEditor_->setText(QStringLiteral(
        "%1\n\n"
        "模块身份:\n"
        "%2\n\n"
        "%3\n\n"
        "Capability 状态:\n"
        "%4")
        .arg(entry->detailText)
        .arg(moduleDetailText(QStringLiteral("ntoskrnl"), dynDataSummary_.ntoskrnl))
        .arg(moduleDetailText(QStringLiteral("lxcore"), dynDataSummary_.lxcore))
        .arg(capabilityReport(dynDataSummary_.capabilityMask)));
}
