#include "HardwareR0EvidencePage.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/TableColumnAutoFit.h"
#include "../ui/DetailLayoutRegistry.h"

#include <QAbstractItemView>
#include <QAction>
#include <QCheckBox>
#include <QClipboard>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QRunnable>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>
#include <QVector>

#include <algorithm>
#include <limits>
#include <string>

namespace
{
    // R0EvidenceColumn purpose: defines hardware R0 evidence table columns; return value is converted from columnIndex to int.
    enum class R0EvidenceColumn : int
    {
        kClass = 0,
        kCpu,
        kSource,
        kStatus,
        kObject,
        kTarget,
        kOwner,
        kRisk,
        kConfidence,
        kCr0,
        kCr4,
        kEfer,
        kMsrLstar,
        kSysenterEip,
        kIdtrBase,
        kIdtrLimit,
        kGdtrBase,
        kGdtrLimit,
        kSelector,
        kAttributes,
        kFieldMask,
        kStatusFlags,
        kRiskScore,
        kRemark,
        kCount
    };

    int columnIndex(const R0EvidenceColumn column)
    {
        // Input: R0EvidenceColumn enum.
        // Processing: Convert to the column index required by QTableWidget.
        // Return: column index.
        return static_cast<int>(column);
    }

    QString hex64(const std::uint64_t value)
    {
        // Input: 64-bit address, base address, or mask.
        // Handling: Uniformly format as 0x followed by 16 uppercase hexadecimal digits.
        // Returns: address text.
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString hex32(const std::uint32_t value)
    {
        // Input: 32-bit flags/status value.
        // Processing: Format uniformly as 0x + 8-digit uppercase hexadecimal.
        // Returns: Hexadecimal text.
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(value), 8, 16, QChar('0'))
            .toUpper();
    }

    QString ntStatusText(const long statusValue)
    {
        // Input: NTSTATUS-style integer.
        // Processing: Display as a fixed-width unsigned 32-bit value for easy comparison with WinDbg.
        // Returns: 0xXXXXXXXX text.
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusValue), 8, 16, QChar('0'))
            .toUpper();
    }

    QString wideToQString(const std::wstring& value)
    {
        // Input: std::wstring returned by ArkDriverClient.
        // Processing: Keep empty values as empty; convert non-empty values to QString.
        // Return: Qt string.
        return value.empty() ? QString() : QString::fromStdWString(value);
    }

    QString friendlyHardwareIoMessage(const std::string& messageText)
    {
        // friendlyHardwareIoMessage：
        // - Input: ArkDriverClient's raw io.message;
        // - Handling: Converts IOCTL/protocol errors into user-readable descriptions.
        // - Returns: Short text suitable for detail areas.
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息。");
        }
        const QString kRawText = QString::fromStdString(messageText).trimmed();
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该硬件证据入口。");
        }
        if (kRawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("entrySize"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，当前页只保留已解析出的证据。");
        }
        return kRawText;
    }

    QString buildBlueButtonStyle()
    {
        // Inputs: None.
        // Processing: Construct blue button styles based on the global theme.
        // Returns: stylesheet text.
        return QStringLiteral(
            "QPushButton{border:1px solid %1;border-radius:4px;padding:4px 10px;color:%2;background:transparent;}"
            "QPushButton:hover{background:%3;}"
            "QPushButton:pressed{background:%1;color:%5;}"
            "QPushButton:disabled{color:%4;border-color:%4;background:transparent;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::primaryBlueSubtleHex())
            .arg(ksword_theme::textSecondaryHex())
            .arg(ksword_theme::onAccentDynamicHex());
    }

    QString buildBlueInputStyle()
    {
        // Inputs: None.
        // Handling: Construct input box styles based on the global theme.
        // Returns: stylesheet text.
        return QStringLiteral(
            "QLineEdit{border:1px solid %1;border-radius:4px;padding:4px 6px;color:%2;background:transparent;/* %3 */}"
            "QLineEdit:focus{border:1px solid %4;}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    QString buildHeaderStyle()
    {
        // Inputs: None.
        // Processing: Construct a blue-emphasized header style.
        // Returns: stylesheet text.
        return QStringLiteral("QHeaderView::section{color:%1;font-weight:700;}")
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    QString statusStyle(const QString& colorText)
    {
        // Input: color text.
        // Processing: Generate a status label CSS string.
        // Returns: stylesheet text.
        return QStringLiteral("color:%1; font-weight:700;").arg(colorText);
    }

    QVector<int> r0EvidenceColumnGroupA()
    {
        // Inputs: None.
        // Processing: Define default R0 evidence Group A; retain only core context required to locate anomalies.
        // Returns: a collection of column indices, which the caller uses to hide other columns.
        return QVector<int>{
            columnIndex(R0EvidenceColumn::kClass),
            columnIndex(R0EvidenceColumn::kCpu),
            columnIndex(R0EvidenceColumn::kSource),
            columnIndex(R0EvidenceColumn::kStatus),
            columnIndex(R0EvidenceColumn::kObject),
            columnIndex(R0EvidenceColumn::kTarget),
            columnIndex(R0EvidenceColumn::kOwner),
            columnIndex(R0EvidenceColumn::kRisk),
            columnIndex(R0EvidenceColumn::kConfidence)
        };
    }

    QVector<int> r0EvidenceColumnGroupB()
    {
        // Inputs: None.
        // Handling: Define R0 Evidence Group B, focusing on control registers and MSR entry fields.
        // Returns: a collection of column indices, allowing a small number of context columns to overlap with Group A.
        return QVector<int>{
            columnIndex(R0EvidenceColumn::kClass),
            columnIndex(R0EvidenceColumn::kCpu),
            columnIndex(R0EvidenceColumn::kCr0),
            columnIndex(R0EvidenceColumn::kCr4),
            columnIndex(R0EvidenceColumn::kEfer),
            columnIndex(R0EvidenceColumn::kMsrLstar),
            columnIndex(R0EvidenceColumn::kSysenterEip)
        };
    }

    QVector<int> r0EvidenceColumnGroupC()
    {
        // Inputs: None.
        // Processing: Define R0 evidence Group C, focusing on descriptor table and IDT/GDT diagnostic fields.
        // Returns: A set of column indices complementary to other column groups to reduce crowding in a single view.
        return QVector<int>{
            columnIndex(R0EvidenceColumn::kClass),
            columnIndex(R0EvidenceColumn::kCpu),
            columnIndex(R0EvidenceColumn::kIdtrBase),
            columnIndex(R0EvidenceColumn::kIdtrLimit),
            columnIndex(R0EvidenceColumn::kGdtrBase),
            columnIndex(R0EvidenceColumn::kGdtrLimit),
            columnIndex(R0EvidenceColumn::kSelector),
            columnIndex(R0EvidenceColumn::kAttributes),
            columnIndex(R0EvidenceColumn::kStatusFlags)
        };
    }

    bool containsColumnIndex(const QVector<int>& columnGroup, const int columnIndexValue)
    {
        // Input: Column group and candidate column index.
        // Handling: Linearly check if the column index belongs to the group.
        // Returns: true if the column should be displayed.
        return std::find(columnGroup.begin(), columnGroup.end(), columnIndexValue) != columnGroup.end();
    }

    QString buildColumnPresetButtonStyle(const bool selected)
    {
        // Input: Whether the button represents the preset for the current column.
        // Processing: Use the theme's primary blue background when selected; otherwise, remain transparent with the theme's text color.
        // Returns: stylesheet text.
        const QString kBackgroundText = selected
            ? ksword_theme::kPrimaryBlueHex
            : QStringLiteral("transparent");
        const QString kBorderText = selected
            ? ksword_theme::kPrimaryBlueHex
            : ksword_theme::borderHex();
        const QString kTextColor = selected
            ? ksword_theme::onAccentDynamicHex()
            : ksword_theme::textPrimaryHex();
        return QStringLiteral(
            "QPushButton{min-width:24px;max-width:24px;padding:3px 0;border:1px solid %1;"
            "border-radius:0;color:%2;background:%3;font-weight:700;}"
            "QPushButton:hover{border-color:%4;}"
            "QPushButton:pressed{background:%4;color:%5;}")
            .arg(kBorderText)
            .arg(kTextColor)
            .arg(kBackgroundText)
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::onAccentDynamicHex());
    }

    void updateColumnPresetButtons(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
        // Input: Target table and A/B/C buttons.
        // Processing: Read table properties and refresh button colors; in Custom mode, none of the three buttons are colored.
        // Returns: Nothing.
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr || buttonC == nullptr)
        {
            return;
        }

        const QString kPresetText = table->property("kswordColumnPreset").toString();
        buttonA->setStyleSheet(buildColumnPresetButtonStyle(kPresetText == QStringLiteral("A")));
        buttonB->setStyleSheet(buildColumnPresetButtonStyle(kPresetText == QStringLiteral("B")));
        buttonC->setStyleSheet(buildColumnPresetButtonStyle(kPresetText == QStringLiteral("C")));
    }

    void applyColumnPresetToTable(
        QTableWidget* table,
        const QVector<int>& columnGroup,
        const QString& presetText,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
        // Input: Table, column group, preset name, and A/B/C buttons.
        // Processing: Display fields by column group and update current preset; do not modify row filter conditions.
        // Returns: Nothing.
        if (table == nullptr)
        {
            return;
        }

        for (int columnIndexValue = 0; columnIndexValue < table->columnCount(); ++columnIndexValue)
        {
            table->setColumnHidden(columnIndexValue, !containsColumnIndex(columnGroup, columnIndexValue));
        }
        table->setProperty("kswordColumnPreset", presetText);
        updateColumnPresetButtons(table, buttonA, buttonB, buttonC);
        ks::ui::requestTableColumnAutoFit(table);
    }

    int visibleColumnCount(QTableWidget* table)
    {
        // Input: target table.
        // Processing: Count currently unhidden columns to prevent manually hiding the last column via the context menu.
        // Returns: Number of visible columns.
        if (table == nullptr)
        {
            return 0;
        }

        int count = 0;
        for (int columnIndexValue = 0; columnIndexValue < table->columnCount(); ++columnIndexValue)
        {
            if (!table->isColumnHidden(columnIndexValue))
            {
                ++count;
            }
        }
        return count;
    }

    QPushButton* createColumnPresetButton(
        QWidget* parentWidget,
        const QString& buttonText,
        const QString& tooltipText)
    {
        // Input: Parent widget, button text, and tooltip.
        // Processing: Create compact A/B/C buttons displaying only a single letter on the button surface.
        // Returns: the button released by the Qt parent-child tree.
        QPushButton* button = new QPushButton(buttonText, parentWidget);
        button->setToolTip(tooltipText);
        button->setCursor(Qt::PointingHandCursor);
        button->setStyleSheet(buildColumnPresetButtonStyle(false));
        return button;
    }

    void installHeaderColumnMenu(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
        // Input: Target table and A/B/C buttons.
        // Processing: Install an explicit theme-style column visibility menu for the header; manually changing columns enters Custom state.
        // Returns: Nothing.
        if (table == nullptr || table->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* headerView = table->horizontalHeader();
        headerView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(headerView, &QHeaderView::customContextMenuRequested, table, [table, headerView, buttonA, buttonB, buttonC](const QPoint& localPosition)
        {
            QMenu menu(table);
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            for (int columnIndexValue = 0; columnIndexValue < table->columnCount(); ++columnIndexValue)
            {
                const QTableWidgetItem* headerItem = table->horizontalHeaderItem(columnIndexValue);
                const QString kHeaderText = headerItem != nullptr
                    ? headerItem->text()
                    : QStringLiteral("Column %1").arg(columnIndexValue);
                QAction* columnAction = menu.addAction(kHeaderText);
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(columnIndexValue));
                columnAction->setData(columnIndexValue);
            }

            QAction* selectedAction = menu.exec(headerView->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            const int kColumnIndexValue = selectedAction->data().toInt();
            const bool kShouldShow = selectedAction->isChecked();
            if (!kShouldShow && visibleColumnCount(table) <= 1)
            {
                table->setColumnHidden(kColumnIndexValue, false);
                return;
            }

            table->setColumnHidden(kColumnIndexValue, !kShouldShow);
            table->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
            updateColumnPresetButtons(table, buttonA, buttonB, buttonC);
            ks::ui::requestTableColumnAutoFit(table);
        });
    }

    void installColumnPresetControls(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC,
        const QVector<int>& groupA,
        const QVector<int>& groupB,
        const QVector<int>& groupC)
    {
        // Input: Table, A/B/C buttons, and three sets of column definitions.
        // Processing: Bind button toggles, install table header menu, and apply Group A by default.
        // Returns: Nothing.
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr || buttonC == nullptr)
        {
            return;
        }

        QObject::connect(buttonA, &QPushButton::clicked, table, [table, buttonA, buttonB, buttonC, groupA]()
        {
            applyColumnPresetToTable(table, groupA, QStringLiteral("A"), buttonA, buttonB, buttonC);
        });
        QObject::connect(buttonB, &QPushButton::clicked, table, [table, buttonA, buttonB, buttonC, groupB]()
        {
            applyColumnPresetToTable(table, groupB, QStringLiteral("B"), buttonA, buttonB, buttonC);
        });
        QObject::connect(buttonC, &QPushButton::clicked, table, [table, buttonA, buttonB, buttonC, groupC]()
        {
            applyColumnPresetToTable(table, groupC, QStringLiteral("C"), buttonA, buttonB, buttonC);
        });
        installHeaderColumnMenu(table, buttonA, buttonB, buttonC);
        applyColumnPresetToTable(table, groupA, QStringLiteral("A"), buttonA, buttonB, buttonC);
    }

    QString classText(const std::uint32_t evidenceClass)
    {
        // Input: KSWORD_ARK_DRIVER_INTEGRITY_CLASS_*.
        // Processing: Map to a read-only hardware page classification.
        // Returns: classification text.
        switch (evidenceClass)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL: return QStringLiteral("CPU控制寄存器");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE: return QStringLiteral("IDTR/GDTR");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY: return QStringLiteral("MSR入口");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER: return QStringLiteral("IDT向量");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return QStringLiteral("模块视图");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return QStringLiteral("PsLoadedModules");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return QStringLiteral("DriverObject");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return QStringLiteral("DriverSection");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return QStringLiteral("MajorFunction");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return QStringLiteral("FastIo");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return QStringLiteral("DeviceChain");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return QStringLiteral("Service");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return QStringLiteral("OptionalGlobal");
        default: return QStringLiteral("Class(%1)").arg(evidenceClass);
        }
    }

    QString sourceMaskText(const std::uint32_t sourceMask)
    {
        // Input: KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_* bitset.
        // Processing: Map to the collection source list.
        // Return: Source text.
        if (sourceMask == 0U)
        {
            return QStringLiteral("无");
        }
        QStringList parts;
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SYSTEM_MODULE) parts << QStringLiteral("SystemModule");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_AUXKLIB) parts << QStringLiteral("AuxKlib");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_PS_LOADED_MODULES) parts << QStringLiteral("PsLoadedModules");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_OBJECT) parts << QStringLiteral("DriverObject");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DRIVER_SECTION) parts << QStringLiteral("DriverSection");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_SERVICE_REGISTRY) parts << QStringLiteral("ServiceRegistry");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_CPU_REGISTER) parts << QStringLiteral("CPURegister");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_IDT) parts << QStringLiteral("IDT");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_GDT) parts << QStringLiteral("GDT");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_MSR) parts << QStringLiteral("MSR");
        if (sourceMask & KSWORD_ARK_DRIVER_INTEGRITY_SOURCE_DYNDATA) parts << QStringLiteral("DynData");
        return parts.join(QStringLiteral(" | "));
    }

    QString capabilityText(const ksword::ark::DriverCapabilitiesQueryResult& result)
    {
        // Input: ArkDriverClient driver capability query result.
        // Processing: Extract protocol, feature, DynData, and error summary for the status bar and detail area.
        // Returns: Single-line readable text.
        if (!result.io.ok)
        {
            return QStringLiteral("DriverCapabilities: 不可用");
        }
        return QStringLiteral("DriverCapabilities: version=%1 features=%2/%3 dynData=0x%4")
            .arg(result.driverProtocolVersion)
            .arg(result.returnedFeatureCount)
            .arg(result.totalFeatureCount)
            .arg(static_cast<qulonglong>(result.dynDataCapabilityMask), 0, 16)
            .toUpper();
    }

    QString dynDataText(const ksword::ark::DynDataCapabilitiesResult& result)
    {
        // Input: ArkDriverClient DynData capability query result.
        // Processing: Extract statusFlags and capabilityMask.
        // Returns: Single-line readable text.
        if (!result.io.ok)
        {
            return QStringLiteral("DynDataCapabilities: 不可用");
        }
        return QStringLiteral("DynDataCapabilities: status=0x%1 capability=0x%2")
            .arg(result.statusFlags, 8, 16, QChar('0'))
            .arg(static_cast<qulonglong>(result.capabilityMask), 0, 16)
            .toUpper();
    }

    QString riskText(const std::uint32_t flags)
    {
        // Input: KSWORD_ARK_DRIVER_INTEGRITY_RISK_* bitset.
        // Processing: Convert to risk tags of interest for the hardware page.
        // Return: No risk, return "Normal".
        if (flags == 0U)
        {
            return QStringLiteral("正常");
        }
        QStringList parts;
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE) parts << QStringLiteral("不可用");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED) parts << QStringLiteral("查询失败");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED) parts << QStringLiteral("模块未解析");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH) parts << QStringLiteral("Owner不匹配");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE) parts << QStringLiteral("外跳");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH) parts << QStringLiteral("Section不匹配");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING) parts << QStringLiteral("服务缺失");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD) parts << QStringLiteral("Unload为空");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP) parts << QStringLiteral("Device环");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP) parts << QStringLiteral("Attached环");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH) parts << QStringLiteral("跨驱动挂接");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER) parts << QStringLiteral("空指针");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER) parts << QStringLiteral("IDT外部Owner");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED) parts << QStringLiteral("WP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED) parts << QStringLiteral("NXE关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED) parts << QStringLiteral("SMEP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED) parts << QStringLiteral("SMAP关闭");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) parts << QStringLiteral("描述符异常");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE) parts << QStringLiteral("DynData缺失");
        if (flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED) parts << QStringLiteral("截断");
        return parts.join(QStringLiteral(" | "));
    }

    QString queryStatusText(const std::uint32_t statusValue)
    {
        // Input: KSWORD_ARK_DRIVER_INTEGRITY_STATUS_*.
        // Processing: Convert to status summary.
        // Returns: status text.
        switch (statusValue)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK: return QStringLiteral("OK");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_PARTIAL: return QStringLiteral("Partial");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_NOT_FOUND: return QStringLiteral("Not found");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_BUFFER_TOO_SMALL: return QStringLiteral("Buffer too small");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED: return QStringLiteral("Query failed");
        case KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE:
        default: return QStringLiteral("Unavailable");
        }
    }

    QString integrityStatusFlagText(const std::uint32_t statusFlags)
    {
        // Input: KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_* bitset.
        // Handling: Expand partial/unsupported/truncated/PDB-required states; display None for empty sets.
        // Returns: Readable status flags for the table and details area.
        if (statusFlags == 0U)
        {
            return QStringLiteral("None");
        }
        QStringList parts;
        if ((statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PARTIAL) != 0U)
        {
            parts << QStringLiteral("Partial");
        }
        if ((statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_UNSUPPORTED) != 0U)
        {
            parts << QStringLiteral("Unsupported");
        }
        if ((statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED) != 0U)
        {
            parts << QStringLiteral("Truncated");
        }
        if ((statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_PDB_REQUIRED) != 0U)
        {
            parts << QStringLiteral("PdbRequired");
        }
        return parts.join(QStringLiteral("|"));
    }

    QString cpuEvidenceDetailValue(const QString& detailText, const QString& keyText)
    {
        // Input: R0 CPU evidence detail raw text and a stable key name.
        // Processing: Extract hexadecimal values in key=0x... format, compatible with semicolon/space/period separators.
        // Returns: The extracted hexadecimal text; returns an empty string if not found.
        const QRegularExpression kExpression(
            QStringLiteral("%1\\s*=\\s*(0x[0-9A-Fa-f]+)")
                .arg(QRegularExpression::escape(keyText)),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch kMatch = kExpression.match(detailText);
        if (!kMatch.hasMatch())
        {
            return QString();
        }
        return kMatch.captured(1).trimmed().toUpper();
    }

    QString cpuEvidenceIdtValue(const QString& detailText, const QString& keyText)
    {
        // Input: R0 IDT row detail and gate/handler/selector/attr key names.
        // Processing: extract hexadecimal fields from IDT[n] details.
        // Returns: The extracted value; returns an empty string if not found.
        return cpuEvidenceDetailValue(detailText, keyText);
    }

    // CpuEvidenceParsedDetail:
    // - Input: Split result from parseCpuEvidenceDetail;
    // - Processing: Preserve semantic meaning of field names from driver detail.
    // - Return behavior: pure data structure with no function return value.
    struct CpuEvidenceParsedDetail
    {
        QString cr0;
        QString cr4;
        QString efer;
        QString msrLstar;
        QString sysenterEip;
        QString idtrBase;
        QString idtrLimit;
        QString gdtrBase;
        QString gdtrLimit;
        QString selector;
        QString attributes;
        QString gate;
        QString handler;
    };

    CpuEvidenceParsedDetail parseCpuEvidenceDetail(const ksword::ark::DriverIntegrityEvidenceEntry& row)
    {
        // Input: a DriverIntegrityEvidenceEntry.
        // Processing: Parse only CR/MSR/IDTR/GDTR/IDT key-value pairs fixed in driver source output.
        // Returns: structured fields for table columns; unmatched fields remain as empty strings.
        const QString kRawDetailText = wideToQString(row.detail).trimmed();
        CpuEvidenceParsedDetail parsed;
        parsed.cr0 = cpuEvidenceDetailValue(kRawDetailText, QStringLiteral("CR0"));
        parsed.cr4 = cpuEvidenceDetailValue(kRawDetailText, QStringLiteral("CR4"));
        parsed.efer = cpuEvidenceDetailValue(kRawDetailText, QStringLiteral("EFER"));
        parsed.msrLstar = cpuEvidenceDetailValue(kRawDetailText, QStringLiteral("MSR_LSTAR"));
        parsed.sysenterEip = cpuEvidenceDetailValue(kRawDetailText, QStringLiteral("SYSENTER_EIP"));
        parsed.idtrBase = cpuEvidenceDetailValue(kRawDetailText, QStringLiteral("IDTR base"));
        parsed.idtrLimit = cpuEvidenceDetailValue(kRawDetailText, QStringLiteral("limit"));

        const QRegularExpression kGdtrExpression(
            QStringLiteral("GDTR\\s+base\\s*=\\s*(0x[0-9A-Fa-f]+)\\s+limit\\s*=\\s*(0x[0-9A-Fa-f]+)"),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch kGdtrMatch = kGdtrExpression.match(kRawDetailText);
        if (kGdtrMatch.hasMatch())
        {
            parsed.gdtrBase = kGdtrMatch.captured(1).trimmed().toUpper();
            parsed.gdtrLimit = kGdtrMatch.captured(2).trimmed().toUpper();
        }

        parsed.selector = cpuEvidenceIdtValue(kRawDetailText, QStringLiteral("selector"));
        parsed.attributes = cpuEvidenceIdtValue(kRawDetailText, QStringLiteral("attr"));
        parsed.gate = cpuEvidenceIdtValue(kRawDetailText, QStringLiteral("gate"));
        parsed.handler = cpuEvidenceIdtValue(kRawDetailText, QStringLiteral("handler"));
        if (parsed.sysenterEip.isEmpty() &&
            row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY &&
            kRawDetailText.contains(QStringLiteral("SYSENTER_EIP captured"), Qt::CaseInsensitive))
        {
            parsed.sysenterEip = hex64(row.targetAddress);
        }
        if (parsed.idtrBase.isEmpty() && row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE)
        {
            parsed.idtrBase = hex64(row.objectAddress);
        }
        if (parsed.gdtrBase.isEmpty() && row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE)
        {
            parsed.gdtrBase = hex64(row.targetAddress);
        }
        if (parsed.gate.isEmpty() && row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
        {
            parsed.gate = hex64(row.objectAddress);
        }
        if (parsed.handler.isEmpty() && row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
        {
            parsed.handler = hex64(row.targetAddress);
        }
        return parsed;
    }

    bool isStructuredCpuEvidenceDetail(
        const ksword::ark::DriverIntegrityEvidenceEntry& row,
        const QString& rawDetailText)
    {
        // Input: Evidence line and raw detail.
        // Processing: Identify driver fixed formats already parsed into table columns.
        // Returns: true indicates the remarks column no longer repeats the full original sentence.
        return rawDetailText.contains(QStringLiteral("CR0="), Qt::CaseInsensitive) ||
            rawDetailText.contains(QStringLiteral("MSR_LSTAR="), Qt::CaseInsensitive) ||
            rawDetailText.contains(QStringLiteral("IDTR base="), Qt::CaseInsensitive) ||
            rawDetailText.contains(QStringLiteral("IDT["), Qt::CaseInsensitive) ||
            row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE ||
            row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY;
    }

    QString cpuVectorText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
    {
        // Input: R0 evidence row.
        // Processing: Combine processor group, processor number, and optional IDT vector.
        // Returns: CPU/Vector text.
        if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
        {
            return QStringLiteral("G%1 CPU%2 V%3")
                .arg(row.processorGroup)
                .arg(row.processorNumber)
                .arg(row.vector);
        }
        return QStringLiteral("G%1 CPU%2")
            .arg(row.processorGroup)
            .arg(row.processorNumber);
    }

    bool isHardwareCpuEvidenceClass(const std::uint32_t evidenceClass)
    {
        // Input: Integrity evidence class.
        // Processing: Determine if the evidence belongs to the first-phase hardware page focus on CPU/MSR/descriptor/IDT.
        // Returns: true indicates inclusion in default display.
        return evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL ||
            evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE ||
            evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY ||
            evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER;
    }

    bool entryMatchesFilter(
        const ksword::ark::DriverIntegrityEvidenceEntry& row,
        const QString& filterText)
    {
        // Input: Evidence row and user filter text.
        // Processing: Perform case-insensitive matching in class/cpu/address/owner/risk/detail.
        // Returns: true if the item should be displayed.
        if (filterText.isEmpty())
        {
            return true;
        }
        const CpuEvidenceParsedDetail kParsedDetail = parseCpuEvidenceDetail(row);
        const QStringList kFields{
            classText(row.evidenceClass),
            cpuVectorText(row),
            sourceMaskText(row.sourceMask),
            queryStatusText(row.entryStatus),
            hex64(row.objectAddress),
            hex64(row.targetAddress),
            wideToQString(row.ownerModule),
            riskText(row.riskFlags),
            hex32(row.fieldMask),
            hex32(row.statusFlags),
            integrityStatusFlagText(row.statusFlags),
            QString::number(row.riskScore),
            kParsedDetail.cr0,
            kParsedDetail.cr4,
            kParsedDetail.efer,
            kParsedDetail.msrLstar,
            kParsedDetail.sysenterEip,
            kParsedDetail.idtrBase,
            kParsedDetail.idtrLimit,
            kParsedDetail.gdtrBase,
            kParsedDetail.gdtrLimit,
            kParsedDetail.selector,
            kParsedDetail.attributes,
            wideToQString(row.detail)
        };
        for (const QString& field : kFields)
        {
            if (field.contains(filterText, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    QString detailText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
    {
        // Input: Current R0 evidence row.
        // Processing: expand all critical protocol fields for easy copying to debug logs.
        // Returns: Multi-line detail text.
        QString text;
        text += QStringLiteral("R0 硬件 / CPU 入口证据详情\n");
        text += QStringLiteral("Class: %1 (%2)\n").arg(classText(row.evidenceClass)).arg(row.evidenceClass);
        text += QStringLiteral("CPU: Group=%1 Processor=%2 Vector=%3\n")
            .arg(row.processorGroup)
            .arg(row.processorNumber)
            .arg(row.vector);
        text += QStringLiteral("ObjectAddress: %1\n").arg(hex64(row.objectAddress));
        text += QStringLiteral("TargetAddress: %1\n").arg(hex64(row.targetAddress));
        text += QStringLiteral("OwnerModule: %1\n").arg(wideToQString(row.ownerModule));
        text += QStringLiteral("OwnerModuleBase: %1\n").arg(hex64(row.ownerModuleBase));
        text += QStringLiteral("OwnerModuleSize: %1 (%2)\n")
            .arg(hex32(row.ownerModuleSize))
            .arg(row.ownerModuleSize);
        text += QStringLiteral("SourceMask: %1 (%2)\n").arg(sourceMaskText(row.sourceMask), hex32(row.sourceMask));
        text += QStringLiteral("RiskFlags: %1 (%2)\n").arg(riskText(row.riskFlags), hex32(row.riskFlags));
        text += QStringLiteral("Confidence: %1\n").arg(row.confidence);
        text += QStringLiteral("EntryStatus: %1 (%2)\n")
            .arg(queryStatusText(row.entryStatus))
            .arg(row.entryStatus);
        text += QStringLiteral("StatusFlags: %1 (%2)\n")
            .arg(integrityStatusFlagText(row.statusFlags))
            .arg(hex32(row.statusFlags));
        text += QStringLiteral("FieldMask: %1\n").arg(hex32(row.fieldMask));
        text += QStringLiteral("RiskScore: %1\n").arg(row.riskScore);
        text += QStringLiteral("RangeState: %1\n").arg(row.rangeState);
        text += QStringLiteral("Ordinal: %1\n").arg(row.ordinal);
        text += QStringLiteral("Detail: %1\n").arg(wideToQString(row.detail));
        return text;
    }

    class NumericItem final : public QTableWidgetItem
    {
    public:
        NumericItem(const QString& displayText, const qulonglong numericValue)
            : QTableWidgetItem(displayText)
        {
            // Input: display text and sort value.
            // Handling: UserRole stores the numeric value, while DisplayRole retains the original format.
            // Returns: Constructor has no return value.
            setData(Qt::UserRole, QVariant::fromValue<qulonglong>(numericValue));
            setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        }

        bool operator<(const QTableWidgetItem& other) const override
        {
            // Input: Another table item.
            // Handling: prioritize sorting by UserRole values.
            // Return: Comparison result.
            bool leftOk = false;
            bool rightOk = false;
            const qulonglong kLeftValue = data(Qt::UserRole).toULongLong(&leftOk);
            const qulonglong kRightValue = other.data(Qt::UserRole).toULongLong(&rightOk);
            if (leftOk && rightOk)
            {
                return kLeftValue < kRightValue;
            }
            return QTableWidgetItem::operator<(other);
        }
    };

    QTableWidgetItem* textItem(const QString& text)
    {
        // Input: display text.
        // Processing: Create a read-only table item.
        // Return: The QTableWidget assumes ownership of the object's lifetime.
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    QTableWidgetItem* numericItem(const QString& text, const qulonglong value)
    {
        // Input: display text and sort value.
        // Processing: Create a NumericItem.
        // Return: The QTableWidget assumes ownership of the object's lifetime.
        return new NumericItem(text, value);
    }

    QString hardwareTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        // hardwareTableCellText：
        // - Input: Table, row index, and column index;
        // - Processing: Safely read the current cell.
        // - Returns: Empty string if not found.
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    void copyHardwareTableCurrentRow(QTableWidget* table)
    {
        // copyHardwareTableCurrentRow：
        // - Input: R0 hardware evidence table.
        // - Processing: Copy the current row as TSV;
        // - Return: None; no additional R0 queries or write operations are triggered.
        if (table == nullptr || QGuiApplication::clipboard() == nullptr)
        {
            return;
        }

        const int kRowIndex = table->currentRow();
        if (kRowIndex < 0 || kRowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            fields.push_back(hardwareTableCellText(table, kRowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    void installHardwareTableCopyMenu(QTableWidget* table)
    {
        // installHardwareTableCopyMenu：
        // - Input: R0 hardware evidence table.
        // - Processing: Install read-only copy menu.
        // - Return: None, menu writes only to clipboard.
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex kClickedIndex = table->indexAt(localPosition);
            if (kClickedIndex.isValid())
            {
                table->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
                table->selectRow(kClickedIndex.row());
            }

            QMenu contextMenu(table);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (contextMenu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyHardwareTableCurrentRow(table);
            }
        });
    }

    struct R0EvidenceQueryBundle
    {
        // capabilityResult: Unified driver capability query result, used only for page header diagnostics.
        ksword::ark::DriverCapabilitiesQueryResult capabilityResult;
        // dynDataResult: DynData capability query result, used solely to indicate the quality of IDT ownership.
        ksword::ark::DynDataCapabilitiesResult dynDataResult;
        // integrityResult: Main result for CPU/MSR/IDT/GDT evidence.
        ksword::ark::DriverIntegrityResult integrityResult;
    };
}

HardwareR0EvidencePage::HardwareR0EvidencePage(QWidget* parent)
    : QWidget(parent)
{
    // Construction flow: create UI first, then connect signals, and finally start a delayed read-only R0 query to avoid blocking the Dock creation chain.
    initializeUi();
    initializeConnections();
    QTimer::singleShot(0, this, [this]()
    {
        refreshEvidenceAsync(false);
    });
}

void HardwareR0EvidencePage::initializeUi()
{
    // The root layout only holds the toolbar and splitters; all actual content widgets are attached to the Qt parent-child tree for automatic release.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    QHBoxLayout* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(8);

    QHBoxLayout* presetLayout = new QHBoxLayout();
    presetLayout->setContentsMargins(0, 0, 0, 0);
    presetLayout->setSpacing(0);

    QPushButton* groupAButton = createColumnPresetButton(
        this,
        QStringLiteral("A"),
        QStringLiteral("显示默认精简列：类别、CPU、来源、状态、对象、Owner、风险和置信度。"));
    QPushButton* groupBButton = createColumnPresetButton(
        this,
        QStringLiteral("B"),
        QStringLiteral("显示 B 组精简列：CR0/CR4/EFER/MSR 入口字段。"));
    QPushButton* groupCButton = createColumnPresetButton(
        this,
        QStringLiteral("C"),
        QStringLiteral("显示 C 组精简列：IDTR/GDTR/Selector/Attr/StatusFlags。"));
    presetLayout->addWidget(groupAButton, 0);
    presetLayout->addWidget(groupBButton, 0);
    presetLayout->addWidget(groupCButton, 0);

    refreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新R0证据"), this);
    refreshButton_->setToolTip(QStringLiteral("刷新内核硬件证据（只读）。"));
    refreshButton_->setStyleSheet(buildBlueButtonStyle());

    riskOnlyCheck_ = new QCheckBox(QStringLiteral("仅风险项"), this);
    riskOnlyCheck_->setToolTip(QStringLiteral("只显示存在风险标记的硬件证据。"));

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(QStringLiteral("搜索 类别/CPU/来源/状态/Owner/风险/CR/MSR/IDTR/GDTR/FieldMask/StatusFlags"));
    filterEdit_->setStyleSheet(buildBlueInputStyle());

    maxRowsSpin_ = new QSpinBox(this);
    maxRowsSpin_->setRange(64, 65536);
    maxRowsSpin_->setValue(static_cast<int>(KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS));
    maxRowsSpin_->setToolTip(QStringLiteral("限制单次查询返回的最大行数。"));

    idtVectorsSpin_ = new QSpinBox(this);
    idtVectorsSpin_->setRange(0, static_cast<int>(KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS));
    idtVectorsSpin_->setValue(64);
    idtVectorsSpin_->setToolTip(QStringLiteral("每 CPU 展开的 IDT 向量数；0 表示不展开 IDT 向量行。"));

    statusLabel_ = new QLabel(QStringLiteral("状态：等待 R0 查询"), this);
    statusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    statusLabel_->setStyleSheet(statusStyle(ksword_theme::textSecondaryHex()));

    toolLayout->addLayout(presetLayout, 0);
    toolLayout->addWidget(refreshButton_, 0);
    toolLayout->addWidget(riskOnlyCheck_, 0);
    toolLayout->addWidget(new QLabel(QStringLiteral("行数:"), this), 0);
    toolLayout->addWidget(maxRowsSpin_, 0);
    toolLayout->addWidget(new QLabel(QStringLiteral("IDT/CPU:"), this), 0);
    toolLayout->addWidget(idtVectorsSpin_, 0);
    toolLayout->addWidget(filterEdit_, 1);
    toolLayout->addWidget(statusLabel_, 0);
    rootLayout_->addLayout(toolLayout, 0);

    QSplitter* splitter = new QSplitter(Qt::Vertical, this);
    rootLayout_->addWidget(splitter, 1);

    evidenceTable_ = new ks::ui::VisibleTableWidget(splitter);
    evidenceTable_->setColumnCount(columnIndex(R0EvidenceColumn::kCount));
    evidenceTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("类别"),
        QStringLiteral("CPU/Vector"),
        QStringLiteral("来源"),
        QStringLiteral("状态"),
        QStringLiteral("对象/寄存器"),
        QStringLiteral("目标/入口"),
        QStringLiteral("Owner模块"),
        QStringLiteral("风险"),
        QStringLiteral("置信度"),
        QStringLiteral("CR0"),
        QStringLiteral("CR4"),
        QStringLiteral("EFER"),
        QStringLiteral("MSR_LSTAR"),
        QStringLiteral("SYSENTER_EIP"),
        QStringLiteral("IDTR base"),
        QStringLiteral("IDTR limit"),
        QStringLiteral("GDTR base"),
        QStringLiteral("GDTR limit"),
        QStringLiteral("Selector"),
        QStringLiteral("Attr"),
        QStringLiteral("FieldMask"),
        QStringLiteral("StatusFlags"),
        QStringLiteral("RiskScore"),
        QStringLiteral("备注")
        });
    evidenceTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    evidenceTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    evidenceTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    evidenceTable_->setAlternatingRowColors(true);
    evidenceTable_->setSortingEnabled(true);
    evidenceTable_->verticalHeader()->setVisible(false);
    evidenceTable_->horizontalHeader()->setStyleSheet(buildHeaderStyle());
    evidenceTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    evidenceTable_->horizontalHeader()->setSectionResizeMode(columnIndex(R0EvidenceColumn::kRemark), QHeaderView::Stretch);
    installHardwareTableCopyMenu(evidenceTable_);
    installColumnPresetControls(
        evidenceTable_,
        groupAButton,
        groupBButton,
        groupCButton,
        r0EvidenceColumnGroupA(),
        r0EvidenceColumnGroupB(),
        r0EvidenceColumnGroupC());
    splitter->addWidget(evidenceTable_);

    QWidget* detailPanel = new QWidget(splitter);
    QHBoxLayout* detailLayout = new QHBoxLayout(detailPanel);
    detailLayout->setContentsMargins(0, 0, 0, 0);
    detailLayout->setSpacing(8);

    detailEditor_ = new CodeEditorWidget(detailPanel);
    detailEditor_->setReadOnly(true);
    detailEditor_->setText(QStringLiteral("请选择一条 R0 CPU/MSR/IDT/GDT 证据查看详情。"));
    detailLayout->addWidget(detailEditor_, 1);

    ks::ui::DetailLayoutRegistry::registerHost(
        evidenceTable_, detailEditor_, this);
    splitter->addWidget(detailPanel);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
}

void HardwareR0EvidencePage::initializeConnections()
{
    // All UI events only trigger table repainting or asynchronous refreshes; R0 is never accessed directly on the UI thread.
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
    {
        refreshEvidenceAsync(true);
    });
    connect(riskOnlyCheck_, &QCheckBox::toggled, this, [this]()
    {
        rebuildEvidenceTable();
        showSelectedEvidenceDetail();
    });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]()
    {
        rebuildEvidenceTable();
        showSelectedEvidenceDetail();
    });
    connect(evidenceTable_, &QTableWidget::itemSelectionChanged, this, [this]()
    {
        showSelectedEvidenceDetail();
    });
}

void HardwareR0EvidencePage::refreshEvidenceAsync(const bool forceRefresh)
{
    // Input: forceRefresh affects only the status text.
    // Note: background serial queries for capabilities, DynData, and CPU integrity; main thread fills back by ticket.
    // Returns: Nothing.
    if (refreshing_.exchange(true))
    {
        setStatusText(QStringLiteral("状态：R0 查询仍在进行中"), ksword_theme::textSecondaryHex());
        return;
    }

    const std::uint64_t kTicket = ++refreshTicket_;
    const unsigned long kMaxRows = static_cast<unsigned long>(maxRowsSpin_ != nullptr ? maxRowsSpin_->value() : KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS);
    const unsigned long kIdtVectors = static_cast<unsigned long>(idtVectorsSpin_ != nullptr ? idtVectorsSpin_->value() : 64);
    const unsigned long kFlags = kIdtVectors == 0UL
        ? KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU
        : (KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES);

    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(false);
    }
    setStatusText(
        forceRefresh ? QStringLiteral("状态：正在刷新 R0 硬件证据...") : QStringLiteral("状态：正在查询 R0 硬件证据..."),
        ksword_theme::kPrimaryBlueHex);

    QPointer<HardwareR0EvidencePage> safeThis(this);
    QRunnable* task = QRunnable::create([safeThis, kTicket, kFlags, kMaxRows, kIdtVectors]() mutable
    {
        R0EvidenceQueryBundle bundle;
        const ksword::ark::DriverClient kClient;
        bundle.capabilityResult = kClient.queryDriverCapabilities();
        bundle.dynDataResult = kClient.queryDynDataCapabilities();
        bundle.integrityResult = kClient.queryKernelCpuIntegrity(kFlags, kMaxRows, kIdtVectors);

        if (safeThis == nullptr)
        {
            return;
        }

        QMetaObject::invokeMethod(safeThis.data(), [safeThis, kTicket, bundle = std::move(bundle)]() mutable
        {
            if (safeThis == nullptr)
            {
                return;
            }

            safeThis->applyEvidenceQueryResults(
                kTicket,
                std::move(bundle.capabilityResult),
                std::move(bundle.dynDataResult),
                std::move(bundle.integrityResult));
        }, Qt::QueuedConnection);
    });
    task->setAutoDelete(true);
    QThreadPool::globalInstance()->start(task);
}

void HardwareR0EvidencePage::applyEvidenceQueryResults(
    const std::uint64_t ticket,
    ksword::ark::DriverCapabilitiesQueryResult capabilityResult,
    ksword::ark::DynDataCapabilitiesResult dynDataResult,
    ksword::ark::DriverIntegrityResult integrityResult)
{
    if (refreshTicket_.load() != ticket)
    {
        return;
    }

    if (ks::ui::isTableUiCommitBlockedByContextMenu({evidenceTable_}))
    {
        const QPointer<HardwareR0EvidencePage> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("hardware-r0-evidence-snapshot-apply"),
            {evidenceTable_},
            [kSafeThis,
                ticket,
                capabilityResult = std::move(capabilityResult),
                dynDataResult = std::move(dynDataResult),
                integrityResult = std::move(integrityResult)]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyEvidenceQueryResults(
                        ticket,
                        std::move(capabilityResult),
                        std::move(dynDataResult),
                        std::move(integrityResult));
                }
            });
        return;
    }

    refreshing_.store(false);
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(true);
    }

    lastIntegrityResult_ = std::move(integrityResult);
    lastCapabilityResult_ = std::move(capabilityResult);
    lastDynDataResult_ = std::move(dynDataResult);
    evidenceCache_.clear();
    evidenceCache_.reserve(lastIntegrityResult_.entries.size());
    for (const auto& row : lastIntegrityResult_.entries)
    {
        if (isHardwareCpuEvidenceClass(row.evidenceClass))
        {
            evidenceCache_.push_back(row);
        }
    }
    rebuildEvidenceTable();
    showSelectedEvidenceDetail();

    if (!lastIntegrityResult_.io.ok)
    {
        const QString kMessage = lastIntegrityResult_.unsupported
            ? QStringLiteral("状态：当前 R0 驱动未支持 CPU Integrity IOCTL")
            : QStringLiteral("状态：R0 查询不可用：%1")
                .arg(friendlyHardwareIoMessage(lastIntegrityResult_.io.message));
        setStatusText(kMessage, ksword_theme::errorColor().name(QColor::HexRgb));
        return;
    }

    const QString kCapabilityText = lastCapabilityResult_.io.ok
        ? QStringLiteral("Cap:%1/%2")
            .arg(lastCapabilityResult_.returnedFeatureCount)
            .arg(lastCapabilityResult_.totalFeatureCount)
        : QStringLiteral("Cap不可用");
    const QString kDynDataText = lastDynDataResult_.io.ok
        ? QStringLiteral("Dyn:0x%1")
            .arg(static_cast<qulonglong>(lastDynDataResult_.capabilityMask), 0, 16)
            .toUpper()
        : QStringLiteral("Dyn不可用");
    const QString kStatusText =
        QStringLiteral("状态：%1，证据 %2/%3，CPU %4，模块 %5，%6，%7，Last=%8")
        .arg(queryStatusText(lastIntegrityResult_.queryStatus))
        .arg(evidenceCache_.size())
        .arg(lastIntegrityResult_.totalCount)
        .arg(lastIntegrityResult_.cpuCount)
        .arg(lastIntegrityResult_.moduleCount)
        .arg(kCapabilityText)
        .arg(kDynDataText)
        .arg(ntStatusText(lastIntegrityResult_.lastStatus));
    setStatusText(kStatusText, ksword_theme::kPrimaryBlueHex);
}

void HardwareR0EvidencePage::rebuildEvidenceTable()
{
    // Input: Reads the local cache and filter controls.
    // Handling: redraw the table only, without triggering any R0 calls.
    // Returns: Nothing.
    if (evidenceTable_ == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);

    const bool kRiskOnly = riskOnlyCheck_ != nullptr && riskOnlyCheck_->isChecked();
    const QString kFilterText = filterEdit_ != nullptr ? filterEdit_->text().trimmed() : QString();
    std::vector<std::size_t> visibleIndexes;
    visibleIndexes.reserve(evidenceCache_.size());
    for (std::size_t index = 0; index < evidenceCache_.size(); ++index)
    {
        const auto& row = evidenceCache_[index];
        if (kRiskOnly && row.riskFlags == 0U)
        {
            continue;
        }
        if (!entryMatchesFilter(row, kFilterText))
        {
            continue;
        }
        visibleIndexes.push_back(index);
    }

    const QSignalBlocker kBlocker(evidenceTable_);
    evidenceTable_->setSortingEnabled(false);
    evidenceTable_->setRowCount(static_cast<int>(visibleIndexes.size()));
    for (int rowIndex = 0; rowIndex < static_cast<int>(visibleIndexes.size()); ++rowIndex)
    {
        const std::size_t kCacheIndex = visibleIndexes[static_cast<std::size_t>(rowIndex)];
        const auto& row = evidenceCache_[kCacheIndex];
        const CpuEvidenceParsedDetail kParsedDetail = parseCpuEvidenceDetail(row);
        const QString kRawDetailText = wideToQString(row.detail).trimmed();
        QStringList remarkParts;
        if (!kRawDetailText.isEmpty() && !isStructuredCpuEvidenceDetail(row, kRawDetailText))
        {
            remarkParts << kRawDetailText;
        }
        if (row.rangeState != 0U)
        {
            remarkParts << QStringLiteral("rangeState=%1").arg(row.rangeState);
        }
        if (row.ordinal != 0U && row.ordinal != std::numeric_limits<std::uint32_t>::max())
        {
            remarkParts << QStringLiteral("ordinal=%1").arg(row.ordinal);
        }
        QTableWidgetItem* classItem = textItem(classText(row.evidenceClass));
        classItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(kCacheIndex)));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kClass), classItem);
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kCpu), textItem(cpuVectorText(row)));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kSource), textItem(sourceMaskText(row.sourceMask)));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kStatus), textItem(queryStatusText(row.entryStatus)));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kObject), numericItem(hex64(row.objectAddress), row.objectAddress));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kTarget), numericItem(hex64(row.targetAddress), row.targetAddress));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kOwner), textItem(
            QStringLiteral("%1 %2")
            .arg(wideToQString(row.ownerModule).isEmpty() ? QStringLiteral("<unknown>") : wideToQString(row.ownerModule))
            .arg(hex64(row.ownerModuleBase))));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kRisk), textItem(riskText(row.riskFlags)));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kConfidence), numericItem(QString::number(row.confidence), row.confidence));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kCr0), textItem(kParsedDetail.cr0));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kCr4), textItem(kParsedDetail.cr4));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kEfer), textItem(kParsedDetail.efer));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kMsrLstar), textItem(kParsedDetail.msrLstar));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kSysenterEip), textItem(kParsedDetail.sysenterEip));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kIdtrBase), textItem(kParsedDetail.idtrBase));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kIdtrLimit), textItem(kParsedDetail.idtrLimit));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kGdtrBase), textItem(kParsedDetail.gdtrBase));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kGdtrLimit), textItem(kParsedDetail.gdtrLimit));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kSelector), textItem(kParsedDetail.selector));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kAttributes), textItem(kParsedDetail.attributes));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kFieldMask), textItem(hex32(row.fieldMask)));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kStatusFlags), textItem(
            QStringLiteral("%1 (%2)")
            .arg(hex32(row.statusFlags))
            .arg(integrityStatusFlagText(row.statusFlags))));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kRiskScore), numericItem(QString::number(row.riskScore), row.riskScore));
        evidenceTable_->setItem(rowIndex, columnIndex(R0EvidenceColumn::kRemark), textItem(remarkParts.join(QStringLiteral("；"))));
    }

    if (evidenceTable_->rowCount() > 0 && evidenceTable_->currentRow() < 0)
    {
        evidenceTable_->setCurrentCell(0, columnIndex(R0EvidenceColumn::kClass));
    }
    evidenceTable_->setSortingEnabled(true);
    ks::ui::requestTableColumnAutoFit(evidenceTable_);
}

void HardwareR0EvidencePage::showSelectedEvidenceDetail()
{
    // Input: read the currently selected item in the table.
    // Processing: Expand details via the cache index of the class column UserRole+1.
    // Returns: Nothing.
    if (detailEditor_ == nullptr || evidenceTable_ == nullptr)
    {
        return;
    }

    const int kRowIndex = evidenceTable_->currentRow();
    if (kRowIndex < 0)
    {
        if (evidenceCache_.empty())
        {
            detailEditor_->setText(QStringLiteral("尚未返回 R0 CPU/MSR/IDT/GDT 证据。"));
        }
        else
        {
            detailEditor_->setText(QStringLiteral("当前过滤条件下没有可见证据。"));
        }
        return;
    }

    QTableWidgetItem* classItem = evidenceTable_->item(kRowIndex, columnIndex(R0EvidenceColumn::kClass));
    if (classItem == nullptr)
    {
        detailEditor_->setText(QStringLiteral("当前行缺少缓存索引。"));
        return;
    }

    bool ok = false;
    const qulonglong kCacheIndex = classItem->data(Qt::UserRole + 1).toULongLong(&ok);
    if (!ok || kCacheIndex >= static_cast<qulonglong>(evidenceCache_.size()))
    {
        detailEditor_->setText(QStringLiteral("当前行缓存索引无效。"));
        return;
    }

    QString text;
    text += QStringLiteral("R0 查询摘要\n");
    text += capabilityText(lastCapabilityResult_) + QStringLiteral("\n");
    text += dynDataText(lastDynDataResult_) + QStringLiteral("\n");
    text += QStringLiteral("ProtocolVersion: %1\n").arg(lastIntegrityResult_.version);
    text += QStringLiteral("QueryStatus: %1 (%2)\n").arg(queryStatusText(lastIntegrityResult_.queryStatus)).arg(lastIntegrityResult_.queryStatus);
    text += QStringLiteral("Flags: %1\n").arg(hex32(lastIntegrityResult_.flags));
    text += QStringLiteral("SourceMask: %1 (%2)\n").arg(sourceMaskText(lastIntegrityResult_.sourceMask), hex32(lastIntegrityResult_.sourceMask));
    text += QStringLiteral("ResponseFieldFlags: %1\n").arg(hex32(lastIntegrityResult_.fieldFlags));
    text += QStringLiteral("ResponseStatusFlags: %1 (%2)\n")
        .arg(integrityStatusFlagText(lastIntegrityResult_.statusFlags))
        .arg(hex32(lastIntegrityResult_.statusFlags));
    text += QStringLiteral("Total/Returned/Parsed: %1/%2/%3\n")
        .arg(lastIntegrityResult_.totalCount)
        .arg(lastIntegrityResult_.returnedCount)
        .arg(evidenceCache_.size());
    text += QStringLiteral("CpuCount: %1\n").arg(lastIntegrityResult_.cpuCount);
    text += QStringLiteral("ModuleCount: %1\n").arg(lastIntegrityResult_.moduleCount);
    text += QStringLiteral("LastStatus: %1\n").arg(ntStatusText(lastIntegrityResult_.lastStatus));
    text += QStringLiteral("驱动返回说明: %1\n\n").arg(friendlyHardwareIoMessage(lastIntegrityResult_.io.message));
    text += detailText(evidenceCache_[static_cast<std::size_t>(kCacheIndex)]);
    detailEditor_->setText(text);
}

void HardwareR0EvidencePage::setStatusText(const QString& text, const QString& colorText)
{
    // Input: Status text and CSS color.
    // Processing: Update status label text and style; ignore if label is null.
    // Returns: Nothing.
    if (statusLabel_ == nullptr)
    {
        return;
    }
    statusLabel_->setText(text);
    statusLabel_->setStyleSheet(statusStyle(colorText));
}
