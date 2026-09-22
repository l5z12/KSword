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
#include <QJsonParseError>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QStringList>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <limits>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // DriverSummaryColumn and DriverCapabilityColumn keep table layout explicit.
    enum class DriverSummaryColumn : int { kName = 0, kValue, kCount };
    enum class DriverCapabilityColumn : int { kFeature = 0, kState, kPolicy, kRequiredDyn, kPresentDyn, kDependency, kReason, kCount };

    struct CapabilityDisplay
    {
        std::uint64_t mask = 0;
        const char* name = nullptr;
        const wchar_t* title = nullptr;
        const char* contextKey = nullptr;
    };

    struct PolicyDisplay
    {
        std::uint32_t mask = 0;
        const char* name = nullptr;
        const wchar_t* title = nullptr;
        const char* contextKey = nullptr;
    };

    // LocalPdbPackMatch：
    // - Input source: Compact profile pack specified by the program directory or environment variables;
    // - Processing logic: performs only local pack identity exact matching and lightweight diagnostics, without applying profiles;
    // - Return behavior: Filled by queryDriverStatusSnapshot for display in KernelDriverStatusSummary.
    struct LocalPdbPackMatch
    {
        bool scanned = false;                 // scanned: Whether at least one candidate pack was actually checked.
        bool matched = false;                 // matched: Indicates whether a profile with an exact match on class/machine/timestamp/size exists.
        bool valid = false;                   // valid: Whether the matched profile includes an available field array.
        std::uint32_t existingPackCount = 0;  // existingPackCount: The number of pack files parsed before attempting to read, if they exist.
        std::uint32_t profileCount = 0;       // profileCount: Total number of profiles in the pack.
        std::uint32_t scannedProfileCount = 0; // scannedProfileCount: The number of profiles scanned in this run.
        std::uint32_t fieldCount = 0;         // fieldCount: Number of fields declared in the matched profile.
        std::uint32_t typedItemCount = 0;     // typedItemCount: Number of v3 items declared in the profile hit.
        std::uint32_t callbackItemCount = 0;  // callbackItemCount: Number of callbackItems declared in the profile that were matched.
        bool activeProcessLinksPresent = false; // activeProcessLinksPresent: Indicates whether the profile contains ActiveProcessLinks.
        std::uint32_t activeProcessLinksOffset = 0xFFFFFFFFU; // activeProcessLinksOffset: Offset of ActiveProcessLinks in the local pack.
        double coveragePercent = -1.0;        // coveragePercent: profile coverage calculated by release_sync; negative value indicates unknown.
        QString profileNameText;              // profileNameText: The matching profileName.
        QString versionText;                  // versionText: Windows version number extracted from profileName.
        QString pathText;                     // pathText: Path of the matched or last diagnosed pack.
        QString messageText;                  // messageText: Match/failure reason displayed to the UI.
    };

    // kDynCapabilities：
    // - Purpose: List all capability bits exposed by R0 DynData;
    // - Logic: Driver status page, capability details, and filtering all reuse this table.
    constexpr std::array<CapabilityDisplay, 23> kDynCapabilities{ {
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

    // kSecurityPolicies lists every policy bit currently surfaced by Phase 1.
    constexpr std::array<PolicyDisplay, 6> kSecurityPolicies{ {
        { KSWORD_ARK_SECURITY_POLICY_FLAG_ACTIVE, "POLICY_ACTIVE", L"安全策略启用", "kernel.driver_status.policy.active" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_MUTATING_ACTIONS, "ALLOW_MUTATING_ACTIONS", L"允许进程修改动作", "kernel.driver_status.policy.mutating_actions" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_FILE_DELETE, "ALLOW_FILE_DELETE", L"允许文件删除", "kernel.driver_status.policy.file_delete" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_CALLBACK_CONTROL, "ALLOW_CALLBACK_CONTROL", L"允许回调控制", "kernel.driver_status.policy.callback_control" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_PROCESS_PROTECTION, "ALLOW_PROCESS_PROTECTION", L"允许进程保护修改", "kernel.driver_status.policy.process_protection" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_KERNEL_SNAPSHOTS, "ALLOW_KERNEL_SNAPSHOTS", L"允许内核快照", "kernel.driver_status.policy.kernel_snapshots" }
    } };

    QString blueButtonStyle() { return ksword_theme::themedButtonStyle(); }

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

    QString headerStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    QString itemSelectionStyle()
    {
        return QString();
    }

    // driverStatusCopyMenuStyle：
    // - Inputs: None;
    // - Processing: Explicitly set the right-click menu background, text, selected state, and disabled state.
    // - Returns: A style string directly applicable to QMenu.
    QString driverStatusCopyMenuStyle()
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

    // driverStatusRowText：
    // - Input: table/rowIndex: driver status table and target row;
    // - Processing: Read cell text by column and concatenate into TSV.
    // - Returns: copyable text; an empty string if the row is invalid.
    QString driverStatusRowText(QTableWidget* table, const int rowIndex)
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

    // installDriverStatusCopyMenu：
    // - Input: table; driver status summary table or capability matrix table;
    // - Processing: Install a read-only right-click menu to copy the current row.
    // - Return: None; performs no R0 queries or write operations.
    void installDriverStatusCopyMenu(QTableWidget* table)
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
            menu.setStyleSheet(driverStatusCopyMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                kernelText("kernel.driver_status.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(kRowIndex >= 0 && kRowIndex < table->rowCount());
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                QClipboard* clipboard = QApplication::clipboard();
                if (clipboard != nullptr)
                {
                    clipboard->setText(driverStatusRowText(table, kRowIndex));
                }
            }
        });
    }

    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.driver_status.placeholder.empty", QStringLiteral("<空>")));
    }

    QString stringToQString(const std::string& valueText)
    {
        return QString::fromUtf8(valueText.c_str(), static_cast<int>(valueText.size()));
    }

    // friendlyDriverStatusIoMessage：
    // - Input valueText: io.message returned by ArkDriverClient;
    // - Handling: Convert low-level phrases like DeviceIoControl/unsupported/DynData into Chinese diagnostics;
    // - Returns: Text suitable for direct display in driver status summary tables and detail reports.
    QString friendlyDriverStatusIoMessage(const std::string& valueText)
    {
        const QString kRawText = stringToQString(valueText).trimmed();
        if (kRawText.isEmpty())
        {
            return kernelText("kernel.driver_status.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.driver_status.message.communication_failure", QStringLiteral("驱动通信失败或当前驱动版本不支持该状态查询入口。"));
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.driver_status.message.unsupported", QStringLiteral("当前驱动不支持该状态/能力查询入口。"));
        }
        if (kRawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.driver_status.message.capability", QStringLiteral("动态偏移能力不足，部分驱动能力会显示为不可用。"));
        }
        return kRawText;
    }

    // wideStringToQString：
    // - Input: valueText: wide string returned by ArkDriverClient;
    // - Processing: Safely convert a wchar_t array to QString.
    // - Returns: Text directly displayable in Qt UI.
    QString wideStringToQString(const std::wstring& valueText)
    {
        return QString::fromWCharArray(valueText.c_str(), static_cast<int>(valueText.size()));
    }

    QString formatHex32(const std::uint32_t value) { return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper(); }
    QString formatHex64(const std::uint64_t value) { return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0')).toUpper(); }
    QString formatNtStatus(const long value) { return formatHex32(static_cast<std::uint32_t>(value)); }
    QString boolText(const bool value)
    {
        return value
            ? kernelText("kernel.driver_status.value.yes", QStringLiteral("是"))
            : kernelText("kernel.driver_status.value.no", QStringLiteral("否"));
    }
    bool flagEnabled(const std::uint32_t flags, const std::uint32_t flag) { return (flags & flag) == flag; }

    // fieldOffsetPresent：
    // - Input flags/offset: field status bit and offset returned by R0;
    // - Processing: check both PRESENT bit and unavailable sentinel;
    // - Returns: true indicates that the field currently has a trusted and available offset value.
    bool fieldOffsetPresent(const std::uint32_t flags, const std::uint32_t offset)
    {
        return (flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
            offset != 0xFFFFFFFFU &&
            offset != 0x0000FFFFU;
    }

    // offsetAvailable：
    // - Input offset: offset value in local profile or R0 field table;
    // - Processing: Uniformly filter two historical unavailable sentinels to prevent the UI from displaying missing values as valid offsets.
    // - Returns: true if the offset is available for subsequent diagnostic display.
    bool offsetAvailable(const std::uint32_t offset)
    {
        return offset != 0xFFFFFFFFU && offset != 0x0000FFFFU;
    }

    // formatOffset32：
    // - Input offset: 32-bit field offset;
    // - Processing: Display <Unavailable> for invalid sentinels; otherwise display both hex and decimal for comparison with WinDbg/PDB.
    // - Returns: Offset text directly insertable into summary tables or diagnostic reports.
    QString formatOffset32(const std::uint32_t offset)
    {
        if (!offsetAvailable(offset))
        {
            return kernelText("kernel.driver_status.placeholder.unavailable", QStringLiteral("<不可用>"));
        }
        return QStringLiteral("%1 (%2)").arg(formatHex32(offset)).arg(offset);
    }

    // parseProfileUInt32：
    // - Input value: value in packed JSON, which may be a number or a 0x string.
    // - Processing: Parse as 32-bit unsigned integer and perform range validation.
    // - Returns: true if parsing succeeds, false otherwise; valueOut is written on success.
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

    // appendUniquePath：
    // - Input paths/pathText: candidate path list and path to add.
    // - Processing: Trim paths and perform case-insensitive deduplication.
    // - Return: No return value; paths are appended as needed.
    void appendUniquePath(QStringList& paths, const QString& pathText)
    {
        const QString kTrimmed = pathText.trimmed();
        if (kTrimmed.isEmpty())
        {
            return;
        }

        const QString kCleanedPath = QDir::cleanPath(kTrimmed);
        if (!kCleanedPath.isEmpty() && !paths.contains(kCleanedPath, Qt::CaseInsensitive))
        {
            paths << kCleanedPath;
        }
    }

    // profilePackSearchPaths：
    // - Inputs: None;
    // - Processing: Construct candidate pack paths using Release default paths, debug environment variables, and current directory as fallback.
    // - Returns: A list of candidate file paths; the caller must still verify existence.
    QStringList profilePackSearchPaths()
    {
        QStringList paths;
        appendUniquePath(paths, qEnvironmentVariable("KSWORD_ARK_PROFILE_PACK"));
        appendUniquePath(paths, QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        appendUniquePath(paths, QDir::current().filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        return paths;
    }

    // moduleClassText：
    // - Input classId: KSW_DYN_PROFILE_CLASS_*;
    // - Processing: Convert to user-understandable kernel module classes;
    // - Returns: Text for ntoskrnl/ntkrla57/lxcore or unknown(...).
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
    // - Processing: Convert R0 field source to user-readable text;
    // - Return: Source name such as System Informer or runtime/PDB profile.
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

    // extractVersionFromProfileName：
    // - Input profileName: profileName written by the generator;
    // - Processing: Extract the first Windows four-part version number.
    // - Returns: version text if matched, otherwise an empty string.
    QString extractVersionFromProfileName(const QString& profileName)
    {
        static const QRegularExpression kVersionPattern(QStringLiteral("(\\d+\\.\\d+\\.\\d+\\.\\d+)"));
        const QRegularExpressionMatch kMatch = kVersionPattern.match(profileName);
        return kMatch.hasMatch() ? kMatch.captured(1) : QString();
    }

    // extractActiveProcessLinksFromPackEntry：
    // - Input profileObject/fieldDictionary: compact profile matching the current ntoskrnl identity;
    // - Processing: Parse the EpActiveProcessLinks StructOffset from v4 items.
    // - Returns: true if the available offset is successfully extracted and written to offsetOut; otherwise false.
    bool extractActiveProcessLinksFromPackEntry(
        const QJsonObject& profileObject,
        std::uint32_t& offsetOut)
    {
        offsetOut = 0xFFFFFFFFU;

        const QJsonArray kItemsArray = profileObject.value(QStringLiteral("items")).toArray();
        for (const QJsonValue& itemValue : kItemsArray)
        {
            if (!itemValue.isObject())
            {
                continue;
            }

            const QJsonObject kItemObject = itemValue.toObject();
            const QString kItemName = kItemObject.value(QStringLiteral("name")).toString().trimmed();
            std::uint32_t itemId = 0U;
            std::uint32_t itemKind = 0U;
            if (!parseProfileUInt32(kItemObject.value(QStringLiteral("itemId")), itemId) ||
                !parseProfileUInt32(kItemObject.value(QStringLiteral("itemKind")), itemKind) ||
                itemId != KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS ||
                itemKind != KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET ||
                (kItemName != QStringLiteral("EpActiveProcessLinks") &&
                 kItemName != QStringLiteral("_EPROCESS.ActiveProcessLinks")))
            {
                continue;
            }

            std::uint32_t parsedOffset = 0U;
            if (parseProfileUInt32(kItemObject.value(QStringLiteral("valueLow")), parsedOffset) &&
                offsetAvailable(parsedOffset))
            {
                offsetOut = parsedOffset;
                return true;
            }
        }

        return false;
    }

    // findMatchingLocalPdbProfilePack：
    // - Input currentIdentity: the current ntoskrnl identity detected by R0.
    // - Processing: Parse compact JSON pack and perform exact matching using class/machine/timestamp/size.
    // - Return: Match result and diagnostics; does not modify driver status or apply the profile.
    LocalPdbPackMatch findMatchingLocalPdbProfilePack(const ksword::ark::ArkDynModuleIdentity& currentIdentity)
    {
        LocalPdbPackMatch result;
        QStringList diagnostics;

        if (!currentIdentity.present)
        {
            result.messageText = kernelText("kernel.driver_status.pdb.identity_unavailable", QStringLiteral("当前 ntoskrnl identity 不可用，无法匹配本地 PDB profile pack。"));
            return result;
        }

        for (const QString& candidatePath : profilePackSearchPaths())
        {
            const QString kResolvedCandidatePath = ks::profile::resolveProfileJsonPath(candidatePath);
            if (kResolvedCandidatePath.isEmpty())
            {
                diagnostics << kernelText("kernel.driver_status.pdb.pack_missing", QStringLiteral("pack 不存在: %1")).arg(QDir::toNativeSeparators(candidatePath));
                continue;
            }

            result.scanned = true;
            result.existingPackCount += 1U;
            result.pathText = QDir::toNativeSeparators(kResolvedCandidatePath);

            QJsonParseError parseError{};
            QString readErrorText;
            const QJsonDocument kDocument = ks::profile::readProfileJsonDocument(kResolvedCandidatePath, &parseError, &readErrorText);
            if (parseError.error != QJsonParseError::NoError || !kDocument.isObject())
            {
                diagnostics << (readErrorText.isEmpty()
                    ? kernelText("kernel.driver_status.pdb.json_parse_failed", QStringLiteral("pack JSON 解析失败: %1 (%2)")).arg(result.pathText, parseError.errorString())
                    : kernelText("kernel.driver_status.pdb.json_read_failed", QStringLiteral("pack JSON 读取失败: %1 (%2)")).arg(result.pathText, readErrorText));
                continue;
            }

            const QJsonObject kRootObject = kDocument.object();
            std::uint32_t schemaVersion = 0U;
            std::uint32_t packVersion = 0U;
            if (!parseProfileUInt32(kRootObject.value(QStringLiteral("schemaVersion")), schemaVersion) ||
                !parseProfileUInt32(kRootObject.value(QStringLiteral("packVersion")), packVersion) ||
                schemaVersion != 1U ||
                packVersion != 4U)
            {
                diagnostics << kernelText("kernel.driver_status.pdb.version_unsupported", QStringLiteral("pack schemaVersion/packVersion 不支持: %1")).arg(result.pathText);
                continue;
            }

            const QJsonArray kProfilesArray = kRootObject.value(QStringLiteral("profiles")).toArray();
            result.profileCount = static_cast<std::uint32_t>(kProfilesArray.size());
            if (kProfilesArray.isEmpty())
            {
                diagnostics << kernelText("kernel.driver_status.pdb.profile_list_empty", QStringLiteral("pack profile 列表为空: %1")).arg(result.pathText);
                continue;
            }

            for (const QJsonValue& profileValue : kProfilesArray)
            {
                if (!profileValue.isObject())
                {
                    continue;
                }

                result.scannedProfileCount += 1U;
                const QJsonObject kProfileObject = profileValue.toObject();
                std::uint32_t moduleClassId = 0U;
                std::uint32_t machine = 0U;
                std::uint32_t timeDateStamp = 0U;
                std::uint32_t sizeOfImage = 0U;
                if (!parseProfileUInt32(kProfileObject.value(QStringLiteral("moduleClassId")), moduleClassId) ||
                    !parseProfileUInt32(kProfileObject.value(QStringLiteral("machine")), machine) ||
                    !parseProfileUInt32(kProfileObject.value(QStringLiteral("timeDateStamp")), timeDateStamp) ||
                    !parseProfileUInt32(kProfileObject.value(QStringLiteral("sizeOfImage")), sizeOfImage))
                {
                    continue;
                }

                if (currentIdentity.classId != moduleClassId ||
                    currentIdentity.machine != machine ||
                    currentIdentity.timeDateStamp != timeDateStamp ||
                    currentIdentity.sizeOfImage != sizeOfImage)
                {
                    continue;
                }

                const QJsonArray kItemsArray = kProfileObject.value(QStringLiteral("items")).toArray();
                result.matched = true;
                result.valid = !kItemsArray.isEmpty();
                result.fieldCount = 0U;
                result.typedItemCount = static_cast<std::uint32_t>(kItemsArray.size());
                result.callbackItemCount = 0U;
                result.activeProcessLinksPresent = extractActiveProcessLinksFromPackEntry(
                    kProfileObject,
                    result.activeProcessLinksOffset);
                const double kCoveragePercent = kProfileObject.value(QStringLiteral("coveragePercent")).toDouble(-1.0);
                result.coveragePercent = kCoveragePercent >= 0.0 ? kCoveragePercent : -1.0;
                result.profileNameText = kProfileObject.value(QStringLiteral("profileName")).toString(QStringLiteral("pack-profile"));
                result.versionText = extractVersionFromProfileName(result.profileNameText);
                result.messageText = result.valid
                    ? kernelText("kernel.driver_status.pdb.matched", QStringLiteral("本地 PDB profile pack 命中；profiles=%1，扫描=%2，字段=%3，typedItems=%4，callbackItems=%5，ActiveProcessLinks=%6，覆盖率=%7。"))
                        .arg(result.profileCount)
                        .arg(result.scannedProfileCount)
                        .arg(result.fieldCount)
                        .arg(result.typedItemCount)
                        .arg(result.callbackItemCount)
                        .arg(result.activeProcessLinksPresent ? formatOffset32(result.activeProcessLinksOffset) : kernelText("kernel.driver_status.placeholder.missing", QStringLiteral("<缺失>")))
                        .arg(result.coveragePercent >= 0.0 ? QStringLiteral("%1%").arg(result.coveragePercent, 0, 'f', 1) : kernelText("kernel.driver_status.placeholder.unknown", QStringLiteral("<未知>")))
                    : kernelText("kernel.driver_status.pdb.matched_invalid", QStringLiteral("本地 PDB profile pack 命中 identity，但 fields/items 均为空，已视为无效。"));
                return result;
            }

            diagnostics << kernelText("kernel.driver_status.pdb.not_matched", QStringLiteral("pack 未命中: %1 (profiles=%2)")).arg(result.pathText).arg(result.profileCount);
        }

        result.messageText = kernelText("kernel.driver_status.pdb.no_match", QStringLiteral("未找到匹配 PDB profile pack；检查 %1 个存在的 pack。%2"))
            .arg(result.existingPackCount)
            .arg(diagnostics.join(QStringLiteral(" | ")));
        return result;
    }

    QString capabilityNames(const std::uint64_t mask)
    {
        QStringList names;
        for (const CapabilityDisplay& item : kDynCapabilities)
        {
            if ((mask & item.mask) == item.mask)
            {
                names << QStringLiteral("%1 (%2)")
                    .arg(QString::fromLatin1(item.name))
                    .arg(kernelText(item.contextKey, QString::fromWCharArray(item.title)));
            }
        }
        return names.isEmpty() ? QStringLiteral("None") : names.join(QStringLiteral(", "));
    }

    QString policyNames(const std::uint32_t mask)
    {
        QStringList names;
        for (const PolicyDisplay& item : kSecurityPolicies)
        {
            if ((mask & item.mask) == item.mask)
            {
                names << QStringLiteral("%1 (%2)")
                    .arg(QString::fromLatin1(item.name))
                    .arg(kernelText(item.contextKey, QString::fromWCharArray(item.title)));
            }
        }
        return names.isEmpty() ? QStringLiteral("None") : names.join(QStringLiteral(", "));
    }

    // kernelIdentityText：
    // - Input summary: Driver status summary;
    // Processing: Compress key PE fields of the ntoskrnl identity into a single line.
    // - Returns: The current kernel identity text suitable for the summary table and diagnostic details.
    QString kernelIdentityText(const KernelDriverStatusSummary& summary)
    {
        if (!summary.ntoskrnlIdentityPresent)
        {
            return kernelText("kernel.driver_status.placeholder.unrecognized", QStringLiteral("<未识别>"));
        }

        return kernelText("kernel.driver_status.kernel_identity", QStringLiteral("%1，Class=%2 (%3)，Machine=%4，TimeDateStamp=%5，SizeOfImage=%6，Base=%7"))
            .arg(safeText(summary.ntoskrnlModuleNameText))
            .arg(moduleClassText(summary.ntoskrnlClassId))
            .arg(summary.ntoskrnlClassId)
            .arg(formatHex32(summary.ntoskrnlMachine))
            .arg(formatHex32(summary.ntoskrnlTimeDateStamp))
            .arg(formatHex32(summary.ntoskrnlSizeOfImage))
            .arg(formatHex64(summary.ntoskrnlImageBase));
    }

    // kernelVersionText：
    // - Input summary: Driver status summary;
    // - Processing: Prioritize the four-segment Windows version number from the local PDB profileName.
    // - Return: The detected Windows kernel version; returns a clear placeholder if not found.
    QString kernelVersionText(const KernelDriverStatusSummary& summary)
    {
        if (!summary.localPdbProfileVersionText.trimmed().isEmpty())
        {
            return summary.localPdbProfileVersionText;
        }
        return summary.ntoskrnlIdentityPresent
            ? kernelText("kernel.driver_status.placeholder.identity_version", QStringLiteral("<identity 已识别，版本号需匹配 PDB profile 后确认>"))
            : kernelText("kernel.driver_status.placeholder.unrecognized", QStringLiteral("<未识别>"));
    }

    // fieldCoverageText：
    // - Input summary: Driver status summary;
    // - Handling: Summarize total R0 fields, returned fields, and available fields.
    // - Return: The user-readable field coverage text.
    QString fieldCoverageText(const KernelDriverStatusSummary& summary)
    {
        QString coverageText = kernelText("kernel.driver_status.field_coverage", QStringLiteral("可用 %1 / 返回 %2 / R0声明 %3，必需缺失 %4"))
            .arg(summary.dynDataPresentFieldCount)
            .arg(summary.dynDataReturnedFieldCount)
            .arg(summary.dynDataFieldCount)
            .arg(summary.dynDataRequiredMissingCount);
        if (summary.localPdbProfileCoveragePercent >= 0.0)
        {
            coverageText += kernelText("kernel.driver_status.field_coverage.pack", QStringLiteral("，pack覆盖率 %1%"))
                .arg(summary.localPdbProfileCoveragePercent, 0, 'f', 1);
        }
        return coverageText;
    }

    // fieldSourceSummaryText：
    // - Input summary: Driver status summary;
    // - Processing: Categorize and count by the source of currently available fields.
    // - Returns: Field source distribution text.
    QString fieldSourceSummaryText(const KernelDriverStatusSummary& summary)
    {
        return kernelText("kernel.driver_status.field_sources", QStringLiteral("PDB=%1，RuntimePattern=%2，SystemInformer=%3，Extra=%4，不可用=%5"))
            .arg(summary.dynDataPdbProfileFieldCount)
            .arg(summary.dynDataRuntimePatternFieldCount)
            .arg(summary.dynDataSystemInformerFieldCount)
            .arg(summary.dynDataExtraTableFieldCount)
            .arg(summary.dynDataUnavailableFieldCount);
    }

    // localPdbProfileText：
    // - Input summary: Driver status summary;
    // - Processing: Synthesize local pack hit, version, fields, and path into a single line.
    // - Returns: The text for the local profile status displayed in the summary table.
    QString localPdbProfileText(const KernelDriverStatusSummary& summary)
    {
        if (summary.localPdbProfileMatched)
        {
            return kernelText("kernel.driver_status.pdb.summary.matched", QStringLiteral("命中：%1，版本=%2，字段=%3，typedItems=%4，callbackItems=%5，ActiveProcessLinks=%6，coverage=%7，packProfiles=%8，路径=%9"))
                .arg(safeText(summary.localPdbProfileNameText))
                .arg(safeText(summary.localPdbProfileVersionText, kernelText("kernel.driver_status.placeholder.not_extracted", QStringLiteral("<未提取>"))))
                .arg(summary.localPdbProfileFieldCount)
                .arg(summary.localPdbProfileTypedItemCount)
                .arg(summary.localPdbProfileCallbackItemCount)
                .arg(summary.localPdbProfileActiveProcessLinksPresent
                    ? formatOffset32(summary.localPdbProfileActiveProcessLinksOffset)
                    : kernelText("kernel.driver_status.placeholder.missing", QStringLiteral("<缺失>")))
                .arg(summary.localPdbProfileCoveragePercent >= 0.0 ? QStringLiteral("%1%").arg(summary.localPdbProfileCoveragePercent, 0, 'f', 1) : kernelText("kernel.driver_status.placeholder.unknown", QStringLiteral("<未知>")))
                .arg(summary.localPdbProfilePackProfileCount)
                .arg(safeText(summary.localPdbProfilePathText));
        }

        return safeText(summary.localPdbProfileMessageText, kernelText("kernel.driver_status.pdb.summary.not_matched", QStringLiteral("未命中或未扫描。")));
    }

    // activeProcessLinksOffsetText：
    // - Input summary: Driver status summary;
    // - Processing: Merge local pack extraction values with R0 current field table values to highlight whether both are available.
    // - Returns: diagnostic text for ActiveProcessLinks offset used in summary tables/reports.
    QString activeProcessLinksOffsetText(const KernelDriverStatusSummary& summary)
    {
        const QString kLocalText = summary.localPdbProfileActiveProcessLinksPresent
            ? formatOffset32(summary.localPdbProfileActiveProcessLinksOffset)
            : kernelText("kernel.driver_status.placeholder.missing", QStringLiteral("<缺失>"));
        const QString kR0Text = summary.dynDataActiveProcessLinksPresent
            ? formatOffset32(summary.dynDataActiveProcessLinksOffset)
            : kernelText("kernel.driver_status.placeholder.not_applied", QStringLiteral("<未应用>"));
        return kernelText("kernel.driver_status.active_process_links", QStringLiteral("LocalPack=%1；R0=%2；R0Source=%3"))
            .arg(kLocalText)
            .arg(kR0Text)
            .arg(sourceText(summary.dynDataActiveProcessLinksSource));
    }

    // callbackProfileCoverageText：
    // - Input summary: Driver status summary;
    // - Processing: Combine callback profile active flag with three types of callback capabilities into a single line.
    // - Return: Text allowing users to directly determine if notify/registry/object traverses trusted PDB data.
    QString callbackProfileCoverageText(const KernelDriverStatusSummary& summary)
    {
        return kernelText("kernel.driver_status.callback_coverage", QStringLiteral("Active=%1，Notify=%2，Registry=%3，Object=%4，packCallbackItems=%5，packTypedItems=%6"))
            .arg(boolText(summary.callbackProfileActive))
            .arg(boolText(summary.callbackNotifyTrusted))
            .arg(boolText(summary.callbackRegistryTrusted))
            .arg(boolText(summary.callbackObjectTrusted))
            .arg(summary.localPdbProfileCallbackItemCount)
            .arg(summary.localPdbProfileTypedItemCount);
    }

    // trustedOffsetText：
    // - Input summary: Driver status summary;
    // - Processing: Determine trusted offsets based on the R0 PDB profile active flag, field source, and pack hit status;
    // - Returns: The user-level trusted offset status description.
    QString trustedOffsetText(const KernelDriverStatusSummary& summary)
    {
        if (summary.trustedPdbOffsetsActive)
        {
            return kernelText("kernel.driver_status.trusted_offsets.active", QStringLiteral("已启用可信 PDB 偏移；PDB字段 %1 / 可用字段 %2，pack=%3，callback=%4。"))
                .arg(summary.dynDataPdbProfileFieldCount)
                .arg(summary.dynDataPresentFieldCount)
                .arg(summary.localPdbProfileMatched
                    ? kernelText("kernel.driver_status.value.matched", QStringLiteral("命中"))
                    : kernelText("kernel.driver_status.value.unconfirmed", QStringLiteral("未确认")))
                .arg(callbackProfileCoverageText(summary));
        }
        if (summary.localPdbProfileMatched)
        {
            return kernelText("kernel.driver_status.trusted_offsets.pack_matched", QStringLiteral("本地 pack 已匹配当前内核，但 R0 当前字段来源尚未切换到 PDB profile。"));
        }
        if (summary.dynDataPresentFieldCount != 0U)
        {
            return kernelText("kernel.driver_status.trusted_offsets.dyndata_only", QStringLiteral("当前有可用 DynData 字段，但未发现 PDB profile 字段；来源=%1。"))
                .arg(fieldSourceSummaryText(summary));
        }
        return kernelText("kernel.driver_status.trusted_offsets.none", QStringLiteral("暂无可用可信偏移。"));
    }

    // dynDataIoText：
    // - Input summary: Driver status summary;
    // - Processing: Concatenate the results of the two IOCTLs for DynData status and fields.
    // - Returns: R3/R0 communication diagnostic text.
    QString dynDataIoText(const KernelDriverStatusSummary& summary)
    {
        return kernelText("kernel.driver_status.dyndata_io", QStringLiteral("Status=%1 (%2)；Fields=%3 (%4)"))
            .arg(boolText(summary.dynDataStatusQueryOk))
            .arg(safeText(summary.dynDataStatusIoMessageText))
            .arg(boolText(summary.dynDataFieldsQueryOk))
            .arg(safeText(summary.dynDataFieldsIoMessageText));
    }

    QString statusBadges(const KernelDriverStatusSummary& summary)
    {
        QStringList badges;
        badges << (summary.driverLoaded ? QStringLiteral("Driver Loaded") : QStringLiteral("Driver Missing"));
        if (!summary.protocolOk) { badges << QStringLiteral("Protocol Mismatch"); }
        if (summary.dynDataMissing) { badges << QStringLiteral("DynData Missing"); }
        if (summary.pdbProfileActive) { badges << QStringLiteral("PDB Profile Active"); }
        if (summary.callbackProfileActive) { badges << QStringLiteral("Callback Profile Active"); }
        if (summary.localPdbProfileMatched) { badges << QStringLiteral("Pack Matched"); }
        if (summary.trustedPdbOffsetsActive) { badges << QStringLiteral("Trusted Offsets"); }
        if (summary.callbackNotifyTrusted || summary.callbackRegistryTrusted || summary.callbackObjectTrusted) { badges << QStringLiteral("Trusted Callback Data"); }
        if (summary.dynDataRequiredMissingCount != 0U) { badges << QStringLiteral("Required Offsets Missing"); }
        if (summary.limited) { badges << QStringLiteral("Limited"); }
        return badges.join(QStringLiteral(", "));
    }

    QString dynDataStatusText(const std::uint32_t flags)
    {
        QStringList parts;
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_INITIALIZED)) { parts << QStringLiteral("Initialized"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE)) { parts << QStringLiteral("NtosActive"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE)) { parts << QStringLiteral("LxcoreActive"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE)) { parts << QStringLiteral("ExtraActive"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)) { parts << QStringLiteral("PdbProfileActive"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE)) { parts << QStringLiteral("CallbackProfileActive"); }
        return parts.isEmpty() ? QStringLiteral("None") : parts.join(QStringLiteral(", "));
    }

    QString featureFlagText(const std::uint32_t flags)
    {
        QStringList parts;
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA)) { parts << QStringLiteral("Requires DynData"); }
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_MUTATING)) { parts << QStringLiteral("Mutating"); }
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY)) { parts << QStringLiteral("Kernel Only"); }
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_READ_ONLY)) { parts << QStringLiteral("Read Only"); }
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_POLICY_GATED)) { parts << QStringLiteral("Policy Gated"); }
        return parts.isEmpty() ? QStringLiteral("None") : parts.join(QStringLiteral(", "));
    }

    QString stateText(const std::uint32_t state, const QString& fallbackText)
    {
        switch (state)
        {
        case KSWORD_ARK_FEATURE_STATE_AVAILABLE: return QStringLiteral("Available");
        case KSWORD_ARK_FEATURE_STATE_UNAVAILABLE: return QStringLiteral("Unavailable");
        case KSWORD_ARK_FEATURE_STATE_DEGRADED: return QStringLiteral("Degraded");
        case KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY: return QStringLiteral("Denied by policy");
        default: return safeText(fallbackText, QStringLiteral("Unknown"));
        }
    }

    QBrush stateBrush(const std::uint32_t state)
    {
        if (state == KSWORD_ARK_FEATURE_STATE_AVAILABLE) { return QBrush(ksword_theme::successColor()); }
        if (state == KSWORD_ARK_FEATURE_STATE_DEGRADED) { return QBrush(ksword_theme::warningColor()); }
        if (state == KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY) { return QBrush(ksword_theme::accentColor(ksword_theme::AccentRole::kPurple)); }
        return QBrush(ksword_theme::errorColor());
    }

    void appendSummaryRow(QTableWidget* table, const QString& nameText, const QString& valueText)
    {
        if (table == nullptr) { return; }
        const int kRow = table->rowCount();
        table->insertRow(kRow);
        auto* nameItem = new QTableWidgetItem(nameText);
        auto* valueItem = new QTableWidgetItem(valueText);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);
        table->setItem(kRow, static_cast<int>(DriverSummaryColumn::kName), nameItem);
        table->setItem(kRow, static_cast<int>(DriverSummaryColumn::kValue), valueItem);
    }

    void setReadonlyItem(QTableWidget* table, const int row, const DriverCapabilityColumn column, QTableWidgetItem* item)
    {
        if (table == nullptr || item == nullptr) { delete item; return; }
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        table->setItem(row, static_cast<int>(column), item);
    }

    QString buildCapabilityDetail(const KernelDriverCapabilityEntry& entry, const KernelDriverStatusSummary& summary)
    {
        QStringList lines;
        lines << kernelText("kernel.driver_status.detail.feature", QStringLiteral("功能: %1")).arg(safeText(entry.featureNameText));
        lines << QStringLiteral("FeatureId: %1").arg(entry.featureId);
        lines << kernelText("kernel.driver_status.detail.state", QStringLiteral("状态: %1")).arg(stateText(entry.state, entry.stateNameText));
        lines << kernelText("kernel.driver_status.detail.feature_flags", QStringLiteral("功能标志: %1 (%2)")).arg(formatHex32(entry.flags), featureFlagText(entry.flags));
        lines << QStringLiteral("");
        lines << kernelText("kernel.driver_status.detail.dependencies", QStringLiteral("依赖字段: %1")).arg(safeText(entry.dependencyText, QStringLiteral("None")));
        lines << kernelText("kernel.driver_status.detail.reason", QStringLiteral("状态原因: %1")).arg(safeText(entry.reasonText, QStringLiteral("Feature is available.")));
        lines << QStringLiteral("");
        lines << kernelText("kernel.driver_status.detail.required_policy", QStringLiteral("所需安全策略: %1 (%2)")).arg(formatHex32(entry.requiredPolicyFlags), policyNames(entry.requiredPolicyFlags));
        lines << kernelText("kernel.driver_status.detail.denied_policy", QStringLiteral("被拒绝策略位: %1 (%2)")).arg(formatHex32(entry.deniedPolicyFlags), policyNames(entry.deniedPolicyFlags));
        lines << kernelText("kernel.driver_status.detail.required_capability", QStringLiteral("所需 DynData capability: %1 (%2)")).arg(formatHex64(entry.requiredDynDataMask), capabilityNames(entry.requiredDynDataMask));
        lines << kernelText("kernel.driver_status.detail.present_capability", QStringLiteral("已满足 DynData capability: %1 (%2)")).arg(formatHex64(entry.presentDynDataMask), capabilityNames(entry.presentDynDataMask));
        lines << kernelText("kernel.driver_status.detail.global_capability", QStringLiteral("全局 DynData capability: %1 (%2)")).arg(formatHex64(summary.dynDataCapabilityMask), capabilityNames(summary.dynDataCapabilityMask));
        lines << QStringLiteral("");
        lines << kernelText("kernel.driver_status.detail.current_kernel", QStringLiteral("当前内核: %1")).arg(kernelIdentityText(summary));
        lines << kernelText("kernel.driver_status.detail.recognized_version", QStringLiteral("识别版本: %1")).arg(kernelVersionText(summary));
        lines << kernelText("kernel.driver_status.detail.local_pdb", QStringLiteral("本地 PDB profile: %1")).arg(localPdbProfileText(summary));
        lines << kernelText("kernel.driver_status.detail.active_process_links", QStringLiteral("ActiveProcessLinks 偏移: %1")).arg(activeProcessLinksOffsetText(summary));
        lines << kernelText("kernel.driver_status.detail.trusted_offsets", QStringLiteral("可信偏移: %1")).arg(trustedOffsetText(summary));
        lines << kernelText("kernel.driver_status.detail.field_coverage", QStringLiteral("字段覆盖: %1")).arg(fieldCoverageText(summary));
        lines << kernelText("kernel.driver_status.detail.field_sources", QStringLiteral("字段来源: %1")).arg(fieldSourceSummaryText(summary));
        lines << QStringLiteral("");
        lines << kernelText("kernel.driver_status.detail.driver_status", QStringLiteral("驱动状态: %1")).arg(statusBadges(summary));
        lines << kernelText("kernel.driver_status.detail.last_r0_error", QStringLiteral("最近 R0 错误: %1 / %2 / %3"))
            .arg(formatNtStatus(summary.lastErrorStatus))
            .arg(safeText(summary.lastErrorSourceText, QStringLiteral("None")))
            .arg(safeText(summary.lastErrorSummaryText, QStringLiteral("None")));
        return lines.join(QStringLiteral("\n"));
    }

    QString buildDriverStatusReport(const KernelDriverStatusSummary& summary, const std::vector<KernelDriverCapabilityEntry>& rows)
    {
        QStringList lines;
        lines << QStringLiteral("Ksword Driver Capability Diagnostic Report");
        lines << QStringLiteral("Status: %1").arg(statusBadges(summary));
        lines << QStringLiteral("QueryOk: %1").arg(boolText(summary.queryOk));
        lines << QStringLiteral("IoMessage: %1").arg(safeText(summary.ioMessageText));
        lines << QStringLiteral("CapabilityProtocolVersion: %1").arg(summary.version);
        lines << QStringLiteral("DriverProtocolVersion: %1").arg(formatHex32(summary.driverProtocolVersion));
        lines << QStringLiteral("ExpectedDriverProtocolVersion: %1").arg(formatHex32(KSWORD_ARK_DRIVER_PROTOCOL_VERSION));
        lines << QStringLiteral("StatusFlags: %1").arg(formatHex32(summary.statusFlags));
        lines << QStringLiteral("SecurityPolicyFlags: %1 (%2)").arg(formatHex32(summary.securityPolicyFlags)).arg(policyNames(summary.securityPolicyFlags));
        lines << QStringLiteral("DynDataStatusFlags: %1 (%2)").arg(formatHex32(summary.dynDataStatusFlags)).arg(dynDataStatusText(summary.dynDataStatusFlags));
        lines << QStringLiteral("DynDataCapabilityMask: %1 (%2)").arg(formatHex64(summary.dynDataCapabilityMask)).arg(capabilityNames(summary.dynDataCapabilityMask));
        lines << QStringLiteral("DynDataStatusQueryOk: %1").arg(boolText(summary.dynDataStatusQueryOk));
        lines << QStringLiteral("DynDataFieldsQueryOk: %1").arg(boolText(summary.dynDataFieldsQueryOk));
        lines << QStringLiteral("CurrentKernel: %1").arg(kernelIdentityText(summary));
        lines << QStringLiteral("RecognizedVersion: %1").arg(kernelVersionText(summary));
        lines << QStringLiteral("LocalPdbProfileMatched: %1").arg(boolText(summary.localPdbProfileMatched));
        lines << QStringLiteral("LocalPdbProfileName: %1").arg(safeText(summary.localPdbProfileNameText, QStringLiteral("None")));
        lines << QStringLiteral("LocalPdbProfilePath: %1").arg(safeText(summary.localPdbProfilePathText, QStringLiteral("None")));
        lines << QStringLiteral("LocalPdbProfileMessage: %1").arg(safeText(summary.localPdbProfileMessageText, QStringLiteral("None")));
        lines << QStringLiteral("ActiveProcessLinksOffset: %1").arg(activeProcessLinksOffsetText(summary));
        lines << QStringLiteral("CallbackProfileCoverage: %1").arg(callbackProfileCoverageText(summary));
        lines << QStringLiteral("PdbProfileActive: %1").arg(boolText(summary.pdbProfileActive));
        lines << QStringLiteral("CallbackProfileActive: %1").arg(boolText(summary.callbackProfileActive));
        lines << QStringLiteral("TrustedPdbOffsetsActive: %1").arg(boolText(summary.trustedPdbOffsetsActive));
        lines << QStringLiteral("TrustedOffsetSummary: %1").arg(trustedOffsetText(summary));
        lines << QStringLiteral("FieldCoverage: %1").arg(fieldCoverageText(summary));
        lines << QStringLiteral("FieldSources: %1").arg(fieldSourceSummaryText(summary));
        lines << QStringLiteral("SystemInformerData: version=%1 length=%2")
            .arg(summary.dynDataSystemInformerDataVersion)
            .arg(summary.dynDataSystemInformerDataLength);
        lines << QStringLiteral("MatchedProfile: class=%1 (%2) offset=%3 fieldsId=%4")
            .arg(moduleClassText(summary.dynDataMatchedProfileClass))
            .arg(summary.dynDataMatchedProfileClass)
            .arg(formatHex32(summary.dynDataMatchedProfileOffset))
            .arg(summary.dynDataMatchedFieldsId);
        lines << QStringLiteral("DynDataUnavailableReason: %1").arg(safeText(summary.dynDataUnavailableReasonText, QStringLiteral("None")));
        lines << QStringLiteral("DynDataIo: %1").arg(dynDataIoText(summary));
        lines << QStringLiteral("LastError: %1 / %2 / %3").arg(formatNtStatus(summary.lastErrorStatus)).arg(safeText(summary.lastErrorSourceText, QStringLiteral("None"))).arg(safeText(summary.lastErrorSummaryText, QStringLiteral("None")));
        lines << QStringLiteral("FeatureCount: returned=%1 total=%2").arg(summary.returnedFeatureCount).arg(summary.totalFeatureCount);
        lines << QStringLiteral("\nFeatures:");
        for (const KernelDriverCapabilityEntry& entry : rows)
        {
            lines << QStringLiteral("%1\t%2\tpolicy=%3\tdynRequired=%4\tdynPresent=%5\t%6\t%7")
                .arg(safeText(entry.featureNameText)).arg(stateText(entry.state, entry.stateNameText))
                .arg(formatHex32(entry.requiredPolicyFlags)).arg(formatHex64(entry.requiredDynDataMask))
                .arg(formatHex64(entry.presentDynDataMask)).arg(safeText(entry.dependencyText, QStringLiteral("None")))
                .arg(safeText(entry.reasonText, QStringLiteral("None")));
        }
        return lines.join(QStringLiteral("\n"));
    }

    void populateSummaryTable(QTableWidget* table, const KernelDriverStatusSummary& summary, const std::size_t visibleRows)
    {
        if (table == nullptr) { return; }
        table->setSortingEnabled(false);
        table->setRowCount(0);
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.status_bar", QStringLiteral("状态栏")), statusBadges(summary));
        appendSummaryRow(table, QStringLiteral("Driver Loaded"), boolText(summary.driverLoaded));
        appendSummaryRow(table, QStringLiteral("Protocol OK"), boolText(summary.protocolOk));
        appendSummaryRow(table, QStringLiteral("DynData Missing"), boolText(summary.dynDataMissing));
        appendSummaryRow(table, QStringLiteral("Limited"), boolText(summary.limited));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.current_kernel", QStringLiteral("当前内核")), kernelIdentityText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.recognized_version", QStringLiteral("识别版本")), kernelVersionText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.local_pdb", QStringLiteral("本地 PDB profile")), localPdbProfileText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.active_process_links", QStringLiteral("ActiveProcessLinks 偏移")), activeProcessLinksOffsetText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.callback_coverage", QStringLiteral("Callback profile 覆盖")), callbackProfileCoverageText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.trusted_offsets", QStringLiteral("可信偏移")), trustedOffsetText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.field_coverage", QStringLiteral("字段覆盖")), fieldCoverageText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.field_sources", QStringLiteral("字段来源")), fieldSourceSummaryText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.required_missing", QStringLiteral("缺失必需字段")), QString::number(summary.dynDataRequiredMissingCount));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.capability_version", QStringLiteral("能力协议版本")), QString::number(summary.version));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.driver_protocol", QStringLiteral("驱动协议版本")), formatHex32(summary.driverProtocolVersion));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.expected_protocol", QStringLiteral("期望协议版本")), formatHex32(KSWORD_ARK_DRIVER_PROTOCOL_VERSION));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.status_flags", QStringLiteral("状态位")), formatHex32(summary.statusFlags));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.security_policy", QStringLiteral("安全策略位")), QStringLiteral("%1 (%2)").arg(formatHex32(summary.securityPolicyFlags)).arg(policyNames(summary.securityPolicyFlags)));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.dyndata_status", QStringLiteral("DynData 状态位")), QStringLiteral("%1 (%2)").arg(formatHex32(summary.dynDataStatusFlags)).arg(dynDataStatusText(summary.dynDataStatusFlags)));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.dyndata_capability", QStringLiteral("DynData 能力位")), QStringLiteral("%1 (%2)").arg(formatHex64(summary.dynDataCapabilityMask)).arg(capabilityNames(summary.dynDataCapabilityMask)));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.system_informer", QStringLiteral("System Informer 数据")), QStringLiteral("version=%1 length=%2")
            .arg(summary.dynDataSystemInformerDataVersion)
            .arg(summary.dynDataSystemInformerDataLength));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.matched_profile", QStringLiteral("匹配内置 Profile")), QStringLiteral("class=%1 (%2) offset=%3 fieldsId=%4")
            .arg(moduleClassText(summary.dynDataMatchedProfileClass))
            .arg(summary.dynDataMatchedProfileClass)
            .arg(formatHex32(summary.dynDataMatchedProfileOffset))
            .arg(summary.dynDataMatchedFieldsId));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.callback_trusted", QStringLiteral("Callback profile 可信覆盖")), callbackProfileCoverageText(summary));
        appendSummaryRow(table, QStringLiteral("DynData R3 IO"), dynDataIoText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.dyndata_unavailable_reason", QStringLiteral("DynData 不可用原因")), safeText(summary.dynDataUnavailableReasonText, QStringLiteral("None")));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.feature_count", QStringLiteral("功能数")), kernelText("kernel.driver_status.summary.feature_count_value", QStringLiteral("显示 %1 / 返回 %2 / 总计 %3")).arg(visibleRows).arg(summary.returnedFeatureCount).arg(summary.totalFeatureCount));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.last_error", QStringLiteral("最近错误")), QStringLiteral("%1 / %2 / %3").arg(formatNtStatus(summary.lastErrorStatus)).arg(safeText(summary.lastErrorSourceText, QStringLiteral("None"))).arg(safeText(summary.lastErrorSummaryText, QStringLiteral("None"))));
        appendSummaryRow(table, QStringLiteral("R3 IO"), safeText(summary.ioMessageText));
    }

    // buildDriverStatusLabelText：
    // - Input summary and capability row count;
    // - Handling: Generate a single readable summary for the top status bar.
    // - Returns: Status text suitable for direct display in a QLabel.
    QString buildDriverStatusLabelText(const KernelDriverStatusSummary& summary, const std::size_t capabilityCount)
    {
        const QString kKernelSummaryText = summary.ntoskrnlIdentityPresent
            ? QStringLiteral("%1 / %2").arg(safeText(summary.ntoskrnlModuleNameText), kernelVersionText(summary))
            : kernelText("kernel.driver_status.placeholder.kernel_unrecognized", QStringLiteral("内核未识别"));
        const QString kOffsetText = trustedOffsetText(summary);
        if (!summary.queryOk && !summary.dynDataStatusQueryOk)
        {
            return kernelText("kernel.driver_status.status.both_queries_failed", QStringLiteral("状态：驱动与 DynData 查询均失败"));
        }

        return kernelText("kernel.driver_status.status.summary", QStringLiteral("状态：%1；%2；功能 %3 项；可信偏移 %4"))
            .arg(statusBadges(summary))
            .arg(kKernelSummaryText)
            .arg(capabilityCount)
            .arg(kOffsetText);
    }

    bool shouldShowCapability(const KernelDriverCapabilityEntry& entry, const QString& filter)
    {
        if (filter.isEmpty()) { return true; }
        return entry.featureNameText.contains(filter, Qt::CaseInsensitive) ||
            stateText(entry.state, entry.stateNameText).contains(filter, Qt::CaseInsensitive) ||
            entry.dependencyText.contains(filter, Qt::CaseInsensitive) ||
            entry.reasonText.contains(filter, Qt::CaseInsensitive) ||
            featureFlagText(entry.flags).contains(filter, Qt::CaseInsensitive) ||
            policyNames(entry.requiredPolicyFlags).contains(filter, Qt::CaseInsensitive) ||
            capabilityNames(entry.requiredDynDataMask).contains(filter, Qt::CaseInsensitive) ||
            formatHex64(entry.requiredDynDataMask).contains(filter, Qt::CaseInsensitive);
    }

    bool queryDriverStatusSnapshot(KernelDriverStatusSummary& summaryOut, std::vector<KernelDriverCapabilityEntry>& rowsOut)
    {
        ksword::ark::DriverClient client;
        const ksword::ark::DriverCapabilitiesQueryResult kQueryResult = client.queryDriverCapabilities();
        const ksword::ark::DynDataStatusResult kStatusResult = client.queryDynDataStatus();
        const ksword::ark::DynDataFieldsResult kFieldsResult = client.queryDynDataFields();

        summaryOut = KernelDriverStatusSummary{};
        rowsOut.clear();
        summaryOut.queryOk = kQueryResult.io.ok;
        summaryOut.driverLoaded = kQueryResult.io.ok || kQueryResult.io.win32Error != ERROR_FILE_NOT_FOUND;
        summaryOut.ioMessageText = friendlyDriverStatusIoMessage(kQueryResult.io.message);

        summaryOut.dynDataStatusQueryOk = kStatusResult.io.ok;
        summaryOut.dynDataFieldsQueryOk = kFieldsResult.io.ok;
        summaryOut.dynDataStatusIoMessageText = friendlyDriverStatusIoMessage(kStatusResult.io.message);
        summaryOut.dynDataFieldsIoMessageText = friendlyDriverStatusIoMessage(kFieldsResult.io.message);

        if (kQueryResult.io.ok)
        {
            summaryOut.version = kQueryResult.version;
            summaryOut.driverProtocolVersion = kQueryResult.driverProtocolVersion;
            summaryOut.statusFlags = kQueryResult.statusFlags;
            summaryOut.securityPolicyFlags = kQueryResult.securityPolicyFlags;
            summaryOut.dynDataStatusFlags = kQueryResult.dynDataStatusFlags;
            summaryOut.lastErrorStatus = kQueryResult.lastErrorStatus;
            summaryOut.totalFeatureCount = kQueryResult.totalFeatureCount;
            summaryOut.returnedFeatureCount = kQueryResult.returnedFeatureCount;
            summaryOut.dynDataCapabilityMask = kQueryResult.dynDataCapabilityMask;
            summaryOut.lastErrorSourceText = stringToQString(kQueryResult.lastErrorSource);
            summaryOut.lastErrorSummaryText = stringToQString(kQueryResult.lastErrorSummary);
        }
        else if (kStatusResult.io.ok)
        {
            summaryOut.dynDataStatusFlags = kStatusResult.statusFlags;
            summaryOut.dynDataCapabilityMask = kStatusResult.capabilityMask;
            summaryOut.lastErrorStatus = kStatusResult.lastStatus;
        }

        summaryOut.driverLoaded = flagEnabled(summaryOut.statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_DRIVER_LOADED) ||
            kQueryResult.io.ok ||
            kStatusResult.io.ok ||
            kFieldsResult.io.ok;
        summaryOut.protocolOk = (kQueryResult.io.ok &&
            flagEnabled(summaryOut.statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_PROTOCOL_OK) &&
            summaryOut.driverProtocolVersion == KSWORD_ARK_DRIVER_PROTOCOL_VERSION);

        if (kStatusResult.io.ok)
        {
            summaryOut.dynDataStatusFlags = kStatusResult.statusFlags;
            summaryOut.dynDataSystemInformerDataVersion = kStatusResult.systemInformerDataVersion;
            summaryOut.dynDataSystemInformerDataLength = kStatusResult.systemInformerDataLength;
            summaryOut.dynDataMatchedProfileClass = kStatusResult.matchedProfileClass;
            summaryOut.dynDataMatchedProfileOffset = kStatusResult.matchedProfileOffset;
            summaryOut.dynDataMatchedFieldsId = kStatusResult.matchedFieldsId;
            summaryOut.dynDataFieldCount = kStatusResult.fieldCount;
            summaryOut.dynDataCapabilityMask = kStatusResult.capabilityMask;
            summaryOut.ntoskrnlIdentityPresent = kStatusResult.ntoskrnl.present;
            summaryOut.ntoskrnlClassId = kStatusResult.ntoskrnl.classId;
            summaryOut.ntoskrnlMachine = kStatusResult.ntoskrnl.machine;
            summaryOut.ntoskrnlTimeDateStamp = kStatusResult.ntoskrnl.timeDateStamp;
            summaryOut.ntoskrnlSizeOfImage = kStatusResult.ntoskrnl.sizeOfImage;
            summaryOut.ntoskrnlImageBase = kStatusResult.ntoskrnl.imageBase;
            summaryOut.ntoskrnlModuleNameText = wideStringToQString(kStatusResult.ntoskrnl.moduleName);
            summaryOut.dynDataUnavailableReasonText = wideStringToQString(kStatusResult.unavailableReason);
        }

        if (kFieldsResult.io.ok)
        {
            if (summaryOut.dynDataFieldCount == 0U)
            {
                summaryOut.dynDataFieldCount = kFieldsResult.totalCount;
            }
            summaryOut.dynDataReturnedFieldCount = kFieldsResult.returnedCount != 0U
                ? kFieldsResult.returnedCount
                : static_cast<std::uint32_t>(kFieldsResult.entries.size());
            for (const ksword::ark::DynDataFieldEntry& entry : kFieldsResult.entries)
            {
                if (fieldOffsetPresent(entry.flags, entry.offset))
                {
                    summaryOut.dynDataPresentFieldCount += 1U;
                    switch (entry.source)
                    {
                    case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
                        summaryOut.dynDataPdbProfileFieldCount += 1U;
                        break;
                    case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
                        summaryOut.dynDataRuntimePatternFieldCount += 1U;
                        break;
                    case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
                        summaryOut.dynDataSystemInformerFieldCount += 1U;
                        break;
                    case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
                        summaryOut.dynDataExtraTableFieldCount += 1U;
                        break;
                    default:
                        summaryOut.dynDataUnavailableFieldCount += 1U;
                        break;
                    }
                }
                else
                {
                    summaryOut.dynDataUnavailableFieldCount += 1U;
                }

                if ((entry.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U && !fieldOffsetPresent(entry.flags, entry.offset))
                {
                    summaryOut.dynDataRequiredMissingCount += 1U;
                }

                if (entry.fieldId == KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS)
                {
                    summaryOut.dynDataActiveProcessLinksPresent = fieldOffsetPresent(entry.flags, entry.offset);
                    summaryOut.dynDataActiveProcessLinksOffset = entry.offset;
                    summaryOut.dynDataActiveProcessLinksSource = entry.source;
                }
            }
        }

        if (kStatusResult.io.ok && kStatusResult.ntoskrnl.present)
        {
            const LocalPdbPackMatch kPackMatch = findMatchingLocalPdbProfilePack(kStatusResult.ntoskrnl);
            summaryOut.localPdbProfileMatched = kPackMatch.matched && kPackMatch.valid;
            summaryOut.localPdbProfilePackProfileCount = kPackMatch.profileCount;
            summaryOut.localPdbProfileFieldCount = kPackMatch.fieldCount;
            summaryOut.localPdbProfileTypedItemCount = kPackMatch.typedItemCount;
            summaryOut.localPdbProfileNameText = kPackMatch.profileNameText;
            summaryOut.localPdbProfileVersionText = kPackMatch.versionText;
            summaryOut.localPdbProfilePathText = kPackMatch.pathText;
            summaryOut.localPdbProfileMessageText = kPackMatch.messageText;
            summaryOut.localPdbProfileCallbackItemCount = kPackMatch.callbackItemCount;
            summaryOut.localPdbProfileActiveProcessLinksPresent = kPackMatch.activeProcessLinksPresent;
            summaryOut.localPdbProfileActiveProcessLinksOffset = kPackMatch.activeProcessLinksOffset;
            summaryOut.localPdbProfileCoveragePercent = kPackMatch.coveragePercent;
        }

        summaryOut.pdbProfileActive = flagEnabled(summaryOut.dynDataStatusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
        summaryOut.callbackProfileActive = flagEnabled(summaryOut.dynDataStatusFlags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE);
        summaryOut.callbackNotifyTrusted = (summaryOut.dynDataCapabilityMask & KSW_CAP_CALLBACK_NOTIFY_GLOBALS) != 0ULL;
        summaryOut.callbackRegistryTrusted = (summaryOut.dynDataCapabilityMask & KSW_CAP_CALLBACK_REGISTRY_GLOBALS) != 0ULL;
        summaryOut.callbackObjectTrusted = (summaryOut.dynDataCapabilityMask & KSW_CAP_CALLBACK_OBJECT_FIELDS) != 0ULL;
        summaryOut.trustedPdbOffsetsActive = summaryOut.pdbProfileActive ||
            summaryOut.callbackProfileActive ||
            summaryOut.dynDataPdbProfileFieldCount > 0U;
        summaryOut.dynDataMissing = !summaryOut.dynDataStatusQueryOk ||
            !flagEnabled(summaryOut.dynDataStatusFlags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE);
        summaryOut.limited = !summaryOut.protocolOk ||
            flagEnabled(summaryOut.statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_LIMITED) ||
            !summaryOut.dynDataStatusQueryOk;

        rowsOut.reserve(kQueryResult.entries.size());
        for (const ksword::ark::DriverFeatureCapabilityEntry& sourceEntry : kQueryResult.entries)
        {
            KernelDriverCapabilityEntry row{};
            row.featureId = sourceEntry.featureId;
            row.state = sourceEntry.state;
            row.flags = sourceEntry.flags;
            row.requiredPolicyFlags = sourceEntry.requiredPolicyFlags;
            row.deniedPolicyFlags = sourceEntry.deniedPolicyFlags;
            row.requiredDynDataMask = sourceEntry.requiredDynDataMask;
            row.presentDynDataMask = sourceEntry.presentDynDataMask;
            row.featureNameText = stringToQString(sourceEntry.featureName);
            row.stateNameText = stateText(sourceEntry.state, stringToQString(sourceEntry.stateName));
            row.dependencyText = stringToQString(sourceEntry.dependencyText);
            row.reasonText = stringToQString(sourceEntry.reasonText);
            row.detailText = buildCapabilityDetail(row, summaryOut);
            rowsOut.push_back(std::move(row));
        }

        return summaryOut.queryOk && summaryOut.protocolOk;
    }
}

void KernelDock::initializeDriverStatusTab()
{
    if (driverStatusPage_ == nullptr || driverStatusLayout_ != nullptr) { return; }

    driverStatusLayout_ = new QVBoxLayout(driverStatusPage_);
    driverStatusLayout_->setContentsMargins(4, 4, 4, 4);
    driverStatusLayout_->setSpacing(6);

    driverStatusToolLayout_ = new QHBoxLayout();
    driverStatusToolLayout_->setContentsMargins(0, 0, 0, 0);
    driverStatusToolLayout_->setSpacing(6);

    refreshDriverStatusButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), driverStatusPage_);
    refreshDriverStatusButton_->setToolTip(kernelText("kernel.driver_status.toolbar.refresh.tooltip", QStringLiteral("刷新 KswordARK 驱动状态、协议、安全策略和能力矩阵")));
    refreshDriverStatusButton_->setStyleSheet(blueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshDriverStatusButton_);

    copyDriverStatusReportButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), kernelText("kernel.driver_status.toolbar.copy_report", QStringLiteral("复制诊断")), driverStatusPage_);
    copyDriverStatusReportButton_->setToolTip(kernelText("kernel.driver_status.toolbar.copy_report.tooltip", QStringLiteral("复制统一驱动状态和能力矩阵诊断报告")));
    copyDriverStatusReportButton_->setStyleSheet(blueButtonStyle());

    driverStatusFilterEdit_ = new QLineEdit(driverStatusPage_);
    driverStatusFilterEdit_->setPlaceholderText(kernelText("kernel.driver_status.toolbar.filter.placeholder", QStringLiteral("按功能/状态/策略/DynData capability/依赖字段筛选")));
    driverStatusFilterEdit_->setToolTip(kernelText("kernel.driver_status.toolbar.filter.tooltip", QStringLiteral("输入关键字后实时过滤驱动能力矩阵")));
    driverStatusFilterEdit_->setClearButtonEnabled(true);
    driverStatusFilterEdit_->setStyleSheet(blueInputStyle());

    driverStatusLabel_ = new QLabel(kernelText("kernel.driver_status.status.waiting", QStringLiteral("状态：等待刷新")), driverStatusPage_);
    driverStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    driverStatusToolLayout_->addWidget(refreshDriverStatusButton_, 0);
    driverStatusToolLayout_->addWidget(copyDriverStatusReportButton_, 0);
    driverStatusToolLayout_->addWidget(driverStatusFilterEdit_, 1);
    driverStatusToolLayout_->addWidget(driverStatusLabel_, 0);
    driverStatusLayout_->addLayout(driverStatusToolLayout_);

    QSplitter* verticalSplitter = new QSplitter(Qt::Vertical, driverStatusPage_);
    driverStatusLayout_->addWidget(verticalSplitter, 1);

    driverStatusSummaryTable_ = new ks::ui::VisibleTableWidget(verticalSplitter);
    driverStatusSummaryTable_->setColumnCount(static_cast<int>(DriverSummaryColumn::kCount));
    driverStatusSummaryTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.driver_status.summary.header.item", QStringLiteral("项目")),
        kernelText("kernel.driver_status.summary.header.value", QStringLiteral("值")) });
    driverStatusSummaryTable_->setSelectionMode(QAbstractItemView::NoSelection);
    driverStatusSummaryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    driverStatusSummaryTable_->setAlternatingRowColors(true);
    driverStatusSummaryTable_->setStyleSheet(itemSelectionStyle());
    driverStatusSummaryTable_->setCornerButtonEnabled(false);
    driverStatusSummaryTable_->verticalHeader()->setVisible(false);
    driverStatusSummaryTable_->horizontalHeader()->setStyleSheet(headerStyle());
    driverStatusSummaryTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    driverStatusSummaryTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(DriverSummaryColumn::kValue), QHeaderView::Stretch);
    driverStatusSummaryTable_->setColumnWidth(static_cast<int>(DriverSummaryColumn::kName), 220);
    installDriverStatusCopyMenu(driverStatusSummaryTable_);

    QSplitter* lowerSplitter = new QSplitter(Qt::Horizontal, verticalSplitter);
    driverCapabilityTable_ = new ks::ui::VisibleTableWidget(lowerSplitter);
    driverCapabilityTable_->setColumnCount(static_cast<int>(DriverCapabilityColumn::kCount));
    driverCapabilityTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.driver_status.capability.header.feature", QStringLiteral("功能")),
        kernelText("kernel.driver_status.capability.header.state", QStringLiteral("状态")),
        kernelText("kernel.driver_status.capability.header.policy", QStringLiteral("策略")),
        kernelText("kernel.driver_status.capability.header.required_dyndata", QStringLiteral("所需DynData")),
        kernelText("kernel.driver_status.capability.header.present_dyndata", QStringLiteral("已满足DynData")),
        kernelText("kernel.driver_status.capability.header.dependency", QStringLiteral("依赖字段")),
        kernelText("kernel.driver_status.capability.header.reason", QStringLiteral("原因")) });
    driverCapabilityTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    driverCapabilityTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    driverCapabilityTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    driverCapabilityTable_->setAlternatingRowColors(true);
    driverCapabilityTable_->setStyleSheet(itemSelectionStyle());
    driverCapabilityTable_->setCornerButtonEnabled(false);
    driverCapabilityTable_->verticalHeader()->setVisible(false);
    driverCapabilityTable_->horizontalHeader()->setStyleSheet(headerStyle());
    driverCapabilityTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    driverCapabilityTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(DriverCapabilityColumn::kFeature), QHeaderView::Stretch);
    driverCapabilityTable_->setColumnWidth(static_cast<int>(DriverCapabilityColumn::kState), 140);
    driverCapabilityTable_->setColumnWidth(static_cast<int>(DriverCapabilityColumn::kRequiredDyn), 180);
    driverCapabilityTable_->setColumnWidth(static_cast<int>(DriverCapabilityColumn::kPresentDyn), 180);
    driverCapabilityTable_->setColumnWidth(static_cast<int>(DriverCapabilityColumn::kDependency), 280);
    installDriverStatusCopyMenu(driverCapabilityTable_);

    driverCapabilityDetailEditor_ = new CodeEditorWidget(lowerSplitter);
    driverCapabilityDetailEditor_->setReadOnly(true);
    driverCapabilityDetailEditor_->setText(kernelText("kernel.driver_status.detail.initial", QStringLiteral("请选择一条驱动功能能力查看依赖字段和诊断详情。")));

    verticalSplitter->setStretchFactor(0, 2);
    verticalSplitter->setStretchFactor(1, 5);
    lowerSplitter->setStretchFactor(0, 3);
    lowerSplitter->setStretchFactor(1, 2);

    connect(refreshDriverStatusButton_, &QPushButton::clicked, this, [this]() { refreshDriverStatusAsync(); });
    connect(copyDriverStatusReportButton_, &QPushButton::clicked, this, [this]() {
        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard != nullptr)
        {
            clipboard->setText(buildDriverStatusReport(driverStatusSummary_, driverCapabilityRows_));
            driverStatusLabel_->setText(kernelText("kernel.driver_status.status.report_copied", QStringLiteral("状态：诊断报告已复制")));
        }
    });
    connect(driverStatusFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildDriverCapabilityTable(filterText.trimmed());
    });
    connect(driverCapabilityTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showDriverCapabilityDetailByCurrentRow();
    });
}

void KernelDock::refreshDriverStatusAsync()
{
    if (driverStatusRefreshRunning_.exchange(true))
    {
        KLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] 驱动状态刷新被忽略：已有任务运行。" << eol;
        return;
    }

    refreshDriverStatusButton_->setEnabled(false);
    driverStatusLabel_->setText(kernelText("kernel.driver_status.status.refreshing", QStringLiteral("状态：刷新中...")));
    driverStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        KernelDriverStatusSummary summary;
        std::vector<KernelDriverCapabilityEntry> rows;
        const bool kSuccess = queryDriverStatusSnapshot(summary, rows);

        QMetaObject::invokeMethod(guardThis, [guardThis, kSuccess, summary = std::move(summary), rows = std::move(rows)]() mutable {
            const auto kDeferredSummary =
                std::make_shared<KernelDriverStatusSummary>(std::move(summary));
            const auto kDeferredRows =
                std::make_shared<std::vector<KernelDriverCapabilityEntry>>(std::move(rows));
            auto commitResult = [guardThis, kSuccess, kDeferredSummary, kDeferredRows]() mutable
            {
            KernelDriverStatusSummary& summary = *kDeferredSummary;
            std::vector<KernelDriverCapabilityEntry>& rows = *kDeferredRows;
            if (guardThis == nullptr) { return; }

            guardThis->driverStatusRefreshRunning_.store(false);
            guardThis->refreshDriverStatusButton_->setEnabled(true);
            guardThis->driverStatusSummary_ = std::move(summary);
            guardThis->driverCapabilityRows_ = std::move(rows);
            populateSummaryTable(guardThis->driverStatusSummaryTable_, guardThis->driverStatusSummary_, guardThis->driverCapabilityRows_.size());
            guardThis->rebuildDriverCapabilityTable(guardThis->driverStatusFilterEdit_->text().trimmed());

            if (!kSuccess)
            {
                guardThis->driverStatusLabel_->setText(buildDriverStatusLabelText(
                    guardThis->driverStatusSummary_,
                    guardThis->driverCapabilityRows_.size()));
                guardThis->driverStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
                guardThis->driverCapabilityDetailEditor_->setText(buildDriverStatusReport(guardThis->driverStatusSummary_, guardThis->driverCapabilityRows_));
                return;
            }

            const std::size_t kUnavailableCount = static_cast<std::size_t>(std::count_if(
                guardThis->driverCapabilityRows_.begin(),
                guardThis->driverCapabilityRows_.end(),
                [](const KernelDriverCapabilityEntry& entry) { return entry.state != KSWORD_ARK_FEATURE_STATE_AVAILABLE; }));
            guardThis->driverStatusLabel_->setText(buildDriverStatusLabelText(
                guardThis->driverStatusSummary_,
                guardThis->driverCapabilityRows_.size()));
            const bool kHealthyOffsets = guardThis->driverStatusSummary_.trustedPdbOffsetsActive &&
                guardThis->driverStatusSummary_.dynDataRequiredMissingCount == 0U;
            guardThis->driverStatusLabel_->setStyleSheet(statusLabelStyle(
            kUnavailableCount == 0U && kHealthyOffsets ? ksword_theme::successHex() : ksword_theme::warningHex()));

            if (guardThis->driverCapabilityTable_->rowCount() > 0)
            {
                guardThis->driverCapabilityTable_->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->driverCapabilityDetailEditor_->setText(kernelText("kernel.driver_status.empty.filtered", QStringLiteral("当前筛选条件下没有驱动能力记录。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-driver-status-snapshot-apply"),
                { guardThis->driverStatusSummaryTable_, guardThis->driverCapabilityTable_ },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildDriverCapabilityTable(const QString& filterKeyword)
{
    if (driverCapabilityTable_ == nullptr) { return; }

    driverCapabilityTable_->setSortingEnabled(false);
    driverCapabilityTable_->setRowCount(0);

    for (std::size_t sourceIndex = 0U; sourceIndex < driverCapabilityRows_.size(); ++sourceIndex)
    {
        const KernelDriverCapabilityEntry& entry = driverCapabilityRows_[sourceIndex];
        if (!shouldShowCapability(entry, filterKeyword)) { continue; }

        const int kRow = driverCapabilityTable_->rowCount();
        driverCapabilityTable_->insertRow(kRow);
        auto* featureItem = new QTableWidgetItem(safeText(entry.featureNameText));
        auto* stateItem = new QTableWidgetItem(stateText(entry.state, entry.stateNameText));
        auto* policyItem = new QTableWidgetItem(formatHex32(entry.requiredPolicyFlags));
        auto* requiredItem = new QTableWidgetItem(formatHex64(entry.requiredDynDataMask));
        auto* presentItem = new QTableWidgetItem(formatHex64(entry.presentDynDataMask));
        auto* dependencyItem = new QTableWidgetItem(safeText(entry.dependencyText, QStringLiteral("None")));
        auto* reasonItem = new QTableWidgetItem(safeText(entry.reasonText, QStringLiteral("None")));

        featureItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        stateItem->setForeground(stateBrush(entry.state));
        if (entry.deniedPolicyFlags != 0U) { policyItem->setForeground(QBrush(ksword_theme::errorColor())); }
        if (entry.requiredDynDataMask != 0ULL && entry.presentDynDataMask != entry.requiredDynDataMask)
        {
            presentItem->setForeground(QBrush(ksword_theme::errorColor()));
        }

        setReadonlyItem(driverCapabilityTable_, kRow, DriverCapabilityColumn::kFeature, featureItem);
        setReadonlyItem(driverCapabilityTable_, kRow, DriverCapabilityColumn::kState, stateItem);
        setReadonlyItem(driverCapabilityTable_, kRow, DriverCapabilityColumn::kPolicy, policyItem);
        setReadonlyItem(driverCapabilityTable_, kRow, DriverCapabilityColumn::kRequiredDyn, requiredItem);
        setReadonlyItem(driverCapabilityTable_, kRow, DriverCapabilityColumn::kPresentDyn, presentItem);
        setReadonlyItem(driverCapabilityTable_, kRow, DriverCapabilityColumn::kDependency, dependencyItem);
        setReadonlyItem(driverCapabilityTable_, kRow, DriverCapabilityColumn::kReason, reasonItem);
    }

    driverCapabilityTable_->setSortingEnabled(true);
    populateSummaryTable(driverStatusSummaryTable_, driverStatusSummary_, static_cast<std::size_t>(driverCapabilityTable_->rowCount()));
}

bool KernelDock::currentDriverCapabilitySourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;
    if (driverCapabilityTable_ == nullptr) { return false; }
    const int kCurrentRow = driverCapabilityTable_->currentRow();
    if (kCurrentRow < 0) { return false; }

    QTableWidgetItem* featureItem = driverCapabilityTable_->item(kCurrentRow, static_cast<int>(DriverCapabilityColumn::kFeature));
    if (featureItem == nullptr) { return false; }

    sourceIndexOut = static_cast<std::size_t>(featureItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < driverCapabilityRows_.size();
}

const KernelDriverCapabilityEntry* KernelDock::currentDriverCapabilityEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentDriverCapabilitySourceIndex(sourceIndex)) { return nullptr; }
    return &driverCapabilityRows_[sourceIndex];
}

void KernelDock::showDriverCapabilityDetailByCurrentRow()
{
    if (driverCapabilityDetailEditor_ == nullptr) { return; }

    const KernelDriverCapabilityEntry* entry = currentDriverCapabilityEntry();
    if (entry == nullptr)
    {
        driverCapabilityDetailEditor_->setText(buildDriverStatusReport(driverStatusSummary_, driverCapabilityRows_));
        return;
    }

    driverCapabilityDetailEditor_->setText(kernelText("kernel.driver_status.detail.report", QStringLiteral(
        "%1\n\n当前状态摘要:\n"
        "  %2\n"
        "  当前内核: %3\n"
        "  识别版本: %4\n"
        "  本地 PDB profile: %5\n"
        "  可信偏移: %6\n"
        "  字段覆盖: %7\n"
        "  字段来源: %8\n"
        "  SecurityPolicy: %9 (%10)\n"
        "  DynDataStatus: %11 (%12)\n"
        "  DynDataCapability: %13 (%14)")
        .arg(entry->detailText)
        .arg(statusBadges(driverStatusSummary_))
        .arg(kernelIdentityText(driverStatusSummary_))
        .arg(kernelVersionText(driverStatusSummary_))
        .arg(localPdbProfileText(driverStatusSummary_))
        .arg(trustedOffsetText(driverStatusSummary_))
        .arg(fieldCoverageText(driverStatusSummary_))
        .arg(fieldSourceSummaryText(driverStatusSummary_))
        .arg(formatHex32(driverStatusSummary_.securityPolicyFlags)).arg(policyNames(driverStatusSummary_.securityPolicyFlags))
        .arg(formatHex32(driverStatusSummary_.dynDataStatusFlags)).arg(dynDataStatusText(driverStatusSummary_.dynDataStatusFlags))
        .arg(formatHex64(driverStatusSummary_.dynDataCapabilityMask)).arg(capabilityNames(driverStatusSummary_.dynDataCapabilityMask))));
}
