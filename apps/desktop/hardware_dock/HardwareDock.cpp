#include "HardwareDock.h"
#include "../../../shared/ui/KsPainterChart.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "DiskMonitorPage.h"
#include "MemoryCompositionHistoryWidget.h"
#include "HardwarePowerPage.h"
#include "HardwareR0EvidencePage.h"
#include "HardwareOtherDevicesPage.h"
#include "HardwareDeviceManagerPage.h"
#include "HardwareHwidDispatchPage.h"
#include "HardwareI8042AuditPage.h"
#include "../internationalization/LanguageManager.h"

// ============================================================
// HardwareDock.cpp
// Purpose:
// 1) Provide a utilization-focused hardware monitoring view and hardware overview;
// 2) Leverage PDH + Power API for periodic sampling of CPU, memory, and per-core frequencies.
// 3) Displays graphics card and memory module information via PowerShell/WMI as text.
// ============================================================

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/PerformanceNavCard.h"

#include <QAbstractScrollArea>
#include <QAbstractItemView>
#include <QAction>
#include <QBrush>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QEasingCurve>
#include <QEvent>
#include <QFrame>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListWidgetItem>
#include <QList>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPainter>
#include <QPen>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QRunnable>
#include <QScrollArea>
#include <QShowEvent>
#include <QSizePolicy>
#include <QSplitter>
#include <QStackedWidget>
#include <QTabBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>
#include <QVariantAnimation>

#include <algorithm>
#include <atomic>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <mutex>
#include <thread>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <intrin.h>
#include <Objbase.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <PowrProf.h>
#include <Psapi.h>
#include <d3dkmthk.h>
#include <dxgi1_6.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "PowrProf.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "Dxgi.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace
{
    // hardwareR0QueryMutex: Purpose:
    // - Serialize health snapshots and device audit IOCTLs within HardwareDock.
    // - Avoid submitting large-volume queries to the same driver device simultaneously via automatic refresh and rapid page switching.
    std::mutex hardwareR0QueryMutex;

    // Forward declaration of queryPowerShellTextSync:
    // - Called by the hardware summary function below.
    // - Actual definition is located in the latter part of the same namespace.
    QString queryPowerShellTextSync(const QString& scriptText, int timeoutMs);

    // createReadOnlyTextPage:
    // - Input parent widget, title, and hint text;
    // - Processing: Create a standard read-only page with 'Title + Description + CodeEditorWidget'.
    // - Returns: Initialized page control.
    QWidget* createReadOnlyTextPage(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText,
        CodeEditorWidget** editorOut)
    {
        QWidget* pageWidget = new QWidget(parentWidget);
        QVBoxLayout* pageLayout = new QVBoxLayout(pageWidget);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);

        QLabel* titleLabel = new QLabel(titleText, pageWidget);
        // Page dimensions are attached to the title, no longer occupying a separate line: the four read-only audit pages share this factory, saving four lines of layout.
        titleLabel->setToolTip(hintText);
        titleLabel->setStyleSheet(
            QStringLiteral("font-size:18px;font-weight:700;color:%1;")
            .arg(ksword_theme::textPrimaryHex()));
        pageLayout->addWidget(titleLabel, 0);

        CodeEditorWidget* editor = new CodeEditorWidget(pageWidget);
        editor->setReadOnly(true);
        pageLayout->addWidget(editor, 1);

        if (editorOut != nullptr)
        {
            *editorOut = editor;
        }
        return pageWidget;
    }

    // hardwareDeviceAuditTableHeaders:
    // - Inputs: None;
    // - Processing: Centrally define the columns for the hardware device audit detail table to ensure consistency across the three device pages.
    // - Return: A list of table headers, passed directly to QTableWidget by the caller.
    QStringList hardwareDeviceAuditTableHeaders()
    {
        return QStringList{
            QStringLiteral("Profile"),
            QStringLiteral("行类型"),
            QStringLiteral("角色"),
            QStringLiteral("状态"),
            QStringLiteral("风险"),
            QStringLiteral("置信度"),
            QStringLiteral("链路深度"),
            QStringLiteral("附加深度"),
            QStringLiteral("驱动"),
            QStringLiteral("服务"),
            QStringLiteral("ImagePath"),
            QStringLiteral("设备"),
            QStringLiteral("DriverObject"),
            QStringLiteral("DeviceObject/AttachedDevice"),
            QStringLiteral("Attached/NextAttached"),
            QStringLiteral("NextDevice/Next"),
            QStringLiteral("OwnerDriver"),
            QStringLiteral("DeviceType"),
            QStringLiteral("DeviceFlags"),
            QStringLiteral("StackSize"),
            QStringLiteral("Alignment"),
            QStringLiteral("FieldFlags"),
            QStringLiteral("LastStatus"),
            QStringLiteral("IntegrityStatus"),
            QStringLiteral("IntegrityRows"),
            QStringLiteral("Modules"),
            QStringLiteral("IntegrityFlags"),
            QStringLiteral("备注")
        };
    }

    // hardwareAuditTableCellText:
    // - Input: Table, row index, and column index;
    // - Processing: Safely read cell text;
    // - Returns: Empty string if not found.
    QString hardwareAuditTableCellText(QTableWidget* table, const int rowIndex, const int columnIndex)
    {
        if (table == nullptr)
        {
            return QString();
        }
        const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
        return item != nullptr ? item->text() : QString();
    }

    // copyHardwareAuditCurrentRow:
    // - Input: Target device audit table;
    // - Processing: Write the current row to the clipboard as TSV.
    // - Return: None; does not trigger any R0/R3 queries.
    void copyHardwareAuditCurrentRow(QTableWidget* table)
    {
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
            fields.push_back(hardwareAuditTableCellText(table, kRowIndex, columnIndex));
        }
        QGuiApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    // installHardwareAuditCopyMenu:
    // - Input: device audit table requiring right-click copy;
    // - Processing: Install a 'Copy Current Row' menu with explicit styling to avoid transparent menus with black text on black backgrounds.
    // - Return: None; the menu action only copies text.
    void installHardwareAuditCopyMenu(QTableWidget* table)
    {
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
            }

            QMenu menu(table);
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyHardwareAuditCurrentRow(table);
            }
        });
    }

    // rowMatchesDeviceAuditFilter:
    // - Input: device audit table, row index, and filter text;
    // - Processing: Perform case-insensitive search across all visible fields in the row.
    // - Return: true indicates the row is retained for display; false indicates local hiding.
    bool rowMatchesDeviceAuditFilter(
        QTableWidget* table,
        const int rowIndex,
        const QString& filterText)
    {
        if (table == nullptr || filterText.trimmed().isEmpty())
        {
            return true;
        }

        const QString kNormalizedFilterText = filterText.trimmed();
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            const QString kCellText = item != nullptr ? item->text() : QString();
            if (kCellText.contains(kNormalizedFilterText, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    // applyDeviceAuditTableFilter:
    // - Input: device audit table and search box text;
    // - Processing: Perform local filtering via setRowHidden only to avoid redundant R0 queries.
    // - Return: None. Ignores directly if the table pointer is null.
    void applyDeviceAuditTableFilter(QTableWidget* table, const QString& filterText)
    {
        if (table == nullptr)
        {
            return;
        }

        const QString kNormalizedFilterText = filterText.trimmed();
        for (int rowIndex = 0; rowIndex < table->rowCount(); ++rowIndex)
        {
            table->setRowHidden(
                rowIndex,
                !rowMatchesDeviceAuditFilter(table, rowIndex, kNormalizedFilterText));
        }
    }

    // buildDeviceAuditSearchStyle:
    // - Inputs: None;
    // - Processing: Reuse global theme color to create search box style;
    // - Returns: QLineEdit stylesheet text.
    QString buildDeviceAuditSearchStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %1;border-radius:4px;padding:4px 6px;color:%2;background:transparent;/* %3 */}"
            "QLineEdit:focus{border:1px solid %4;}")
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    // deviceAuditColumnGroupA:
    // - Inputs: None;
    // - Processing: Define default column group A for device audit, prioritizing fields required for location risk and link relationship display.
    // - Returns: Set of column indices to display; caller hides other columns by index.
    QVector<int> deviceAuditColumnGroupA()
    {
        return QVector<int>{
            0,  // Profile: Distinguishes between DeviceStack, InputStack, and UsbTopology.
            1,  // Row type: distinguishes between DriverSummary and DeviceRow.
            2,  // Role: displays roles such as PDO, FDO, filter, and controller.
            3,  // Status: Display R0 single-line status.
            4,  // Risk: Displays risks such as Clean, IntegrityPartial, CrossDriverAttach, etc.
            8,  // Driver: display the DriverObject name.
            11, // Device: display a friendly placeholder name for the DeviceObject.
            22  // LastStatus: Displays the underlying NTSTATUS.
        };
    }

    // deviceAuditColumnGroupB:
    // - Inputs: None;
    // - Processing: Define Device Audit Group B condensed diagnostic columns, offering a different perspective from Group A rather than extending the full set.
    // - Return: Set of column indices to display, retaining only a few identity columns and service/flags/integrity diagnostic fields.
    QVector<int> deviceAuditColumnGroupB()
    {
        return QVector<int>{
            0,  // Profile: Reserved page source context.
            8,  // Driver: display the DriverObject name.
            6,  // Link depth: display the NextDevice/DeviceObject chain depth.
            7,  // Attached depth: displays the depth of the AttachedDevice chain.
            12, // DriverObject: Reserved object address context.
            13, // DeviceObject/AttachedDevice: Retain device object address context.
            14, // Attached/NextAttached: Reserved for attached chain address context.
            15, // NextDevice/Next: Preserves device chain address context.
            16  // OwnerDriver: Displays the attached object owner.
        };
    }

    // deviceAuditColumnGroupC:
    // - Inputs: None;
    // - Processing: Define the Device Audit C group's streamlined diagnostic columns, specifically for service paths, field flags, and integrity summaries.
    // - Return: Set of column indices to display, complementary to other column groups to reduce single-view congestion.
    QVector<int> deviceAuditColumnGroupC()
    {
        return QVector<int>{
            0,  // Profile: Reserved page source context.
            9,  // Service: display the service leaf.
            10, // ImagePath: Displays the image path field.
            21, // FieldFlags: Indicates field validity.
            23, // IntegrityStatus: Displays the DriverIntegrity status.
            24, // IntegrityRows: displays returned/total.
            25, // Modules: Display module count.
            26, // IntegrityFlags: displays DriverIntegrity statusFlags.
            27  // Note: Display unstructured difference information that cannot be serialized.
        };
    }

    // containsColumnIndex:
    // - Input: column group and target column index;
    // - Processing: Linearly check if the column index belongs to the current group.
    // - Returns: true if the column should be shown.
    bool containsColumnIndex(const QVector<int>& columnGroup, const int columnIndex)
    {
        return std::find(columnGroup.begin(), columnGroup.end(), columnIndex) != columnGroup.end();
    }

    // buildColumnPresetButtonStyle:
    // - Input: Whether the button is in the selected preset state;
    // - Processing: Use the theme's primary color for the background when selected; use a transparent background with the theme's text color when not selected.
    // - Returns: QPushButton stylesheet text.
    QString buildColumnPresetButtonStyle(const bool selected)
    {
        const QString kBackgroundText = selected
            ? ksword_theme::accentHex(ksword_theme::AccentRole::kBlue)
            : QStringLiteral("transparent");
        const QString kBorderText = selected
            ? ksword_theme::accentHex(ksword_theme::AccentRole::kBlue)
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
            .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
            .arg(ksword_theme::onAccentDynamicHex());
    }

    // updateColumnPresetButtons:
    // - Input: Table and buttons A/B/C.
    // - Processing: Refresh button coloring based on the table's current columnPreset property.
    // - Return: None, safely ignores null pointers.
    void updateColumnPresetButtons(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr || buttonC == nullptr)
        {
            return;
        }

        const QString kPresetText = table->property("kswordColumnPreset").toString();
        buttonA->setStyleSheet(buildColumnPresetButtonStyle(kPresetText == QStringLiteral("A")));
        buttonB->setStyleSheet(buildColumnPresetButtonStyle(kPresetText == QStringLiteral("B")));
        buttonC->setStyleSheet(buildColumnPresetButtonStyle(kPresetText == QStringLiteral("C")));
    }

    // applyColumnPresetToTable:
    // - Input: Table, column group to display, preset name, and A/B/C buttons;
    // - Processing: Hide fields outside the column group and update the A/B/C buttons to the corresponding highlight.
    // - Returns: None. Only valid columns are displayed if the column group is invalid.
    void applyColumnPresetToTable(
        QTableWidget* table,
        const QVector<int>& columnGroup,
        const QString& presetText,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
        if (table == nullptr)
        {
            return;
        }

        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            table->setColumnHidden(columnIndex, !containsColumnIndex(columnGroup, columnIndex));
        }
        table->setProperty("kswordColumnPreset", presetText);
        updateColumnPresetButtons(table, buttonA, buttonB, buttonC);
    }

    // visibleColumnCount:
    // - Input: target table
    // - Processing: Count currently visible columns to prevent the header menu from hiding all table columns.
    // - Returns: Visible column count.
    int visibleColumnCount(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return 0;
        }

        int count = 0;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (!table->isColumnHidden(columnIndex))
            {
                ++count;
            }
        }
        return count;
    }

    // createColumnPresetButton:
    // - Input: Parent widget, button text, and tooltip;
    // - Processing: Create A/B/C short buttons; button text displays only a single letter as required.
    // - Return: QPushButton released by the Qt parent object.
    QPushButton* createColumnPresetButton(
        QWidget* parentWidget,
        const QString& buttonText,
        const QString& tooltipText)
    {
        QPushButton* button = new QPushButton(buttonText, parentWidget);
        button->setToolTip(tooltipText);
        button->setStyleSheet(buildColumnPresetButtonStyle(false));
        button->setCursor(Qt::PointingHandCursor);
        return button;
    }

    // installHeaderColumnMenu:
    // - Input: table, A/B/C buttons;
    // - Processing: Install a right-click column visibility menu on the header, with explicit theme styling for the menu.
    // - Return: None. User manual column changes clear highlighting for A/B/C.
    void installHeaderColumnMenu(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC)
    {
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
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* headerItem = table->horizontalHeaderItem(columnIndex);
                const QString kTitleText = headerItem != nullptr
                    ? headerItem->text()
                    : QStringLiteral("Column %1").arg(columnIndex);
                QAction* columnAction = menu.addAction(kTitleText);
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(columnIndex));
                columnAction->setData(columnIndex);
            }

            QAction* selectedAction = menu.exec(headerView->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            const int kColumnIndex = selectedAction->data().toInt();
            const bool kShouldShow = selectedAction->isChecked();
            if (!kShouldShow && visibleColumnCount(table) <= 1)
            {
                table->setColumnHidden(kColumnIndex, false);
                return;
            }

            table->setColumnHidden(kColumnIndex, !kShouldShow);
            table->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
            updateColumnPresetButtons(table, buttonA, buttonB, buttonC);
        });
    }

    // installColumnPresetControls:
    // - Input: table, A/B/C buttons, and three logical column groups;
    // - Processing: Connect A/B/C switching, install header menu, and apply Group A by default.
    // - Returns: void; after calling, the table enters the default column layout for Group A.
    void installColumnPresetControls(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        QPushButton* buttonC,
        const QVector<int>& groupA,
        const QVector<int>& groupB,
        const QVector<int>& groupC)
    {
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

    // createDeviceAuditTable:
    // - Input: parent widget
    // - Processing: Create a read-only, sortable device audit table supporting row copying.
    // - Return: QTableWidget pointer, released by the Qt parent-child tree.
    QTableWidget* createDeviceAuditTable(QWidget* parentWidget)
    {
        QTableWidget* table = new ks::ui::VisibleTableWidget(parentWidget);
        const QStringList kHeaders = hardwareDeviceAuditTableHeaders();
        table->setColumnCount(kHeaders.size());
        table->setHorizontalHeaderLabels(kHeaders);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        table->horizontalHeader()->setStretchLastSection(true);
        installHardwareAuditCopyMenu(table);
        return table;
    }

    // createDeviceAuditPage:
    // - Input: parent widget, title, tooltip, output editor, and output table pointers;
    // - Processing: Create a standard page with 'summary text + full R0 row table';
    // - Returns: Initialized page control.
    QWidget* createDeviceAuditPage(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText,
        CodeEditorWidget** editorOut,
        QTableWidget** tableOut)
    {
        QWidget* pageWidget = createReadOnlyTextPage(parentWidget, titleText, hintText, editorOut);
        QVBoxLayout* pageLayout = qobject_cast<QVBoxLayout*>(pageWidget->layout());
        if (pageLayout != nullptr)
        {
            QLineEdit* searchEdit = new QLineEdit(pageWidget);
            searchEdit->setClearButtonEnabled(true);
            searchEdit->setPlaceholderText(
                QStringLiteral("搜索 Profile / 行类型 / 风险 / 地址 / FieldFlags / LastStatus / 备注"));
            searchEdit->setStyleSheet(buildDeviceAuditSearchStyle());
            QTableWidget* table = createDeviceAuditTable(pageWidget);

            QHBoxLayout* tableToolLayout = new QHBoxLayout();
            tableToolLayout->setContentsMargins(0, 0, 0, 0);
            tableToolLayout->setSpacing(6);

            QHBoxLayout* presetLayout = new QHBoxLayout();
            presetLayout->setContentsMargins(0, 0, 0, 0);
            presetLayout->setSpacing(0);

            QPushButton* groupAButton = createColumnPresetButton(
                pageWidget,
                QStringLiteral("A"),
                QStringLiteral("显示默认精简列：状态、风险、链路深度和关键对象地址。"));
            QPushButton* groupBButton = createColumnPresetButton(
                pageWidget,
                QStringLiteral("B"),
                QStringLiteral("显示 B 组精简列：链路深度和对象地址关系。"));
            QPushButton* groupCButton = createColumnPresetButton(
                pageWidget,
                QStringLiteral("C"),
                QStringLiteral("显示 C 组精简列：服务、路径、FieldFlags、integrity 和备注。"));
            presetLayout->addWidget(groupAButton, 0);
            presetLayout->addWidget(groupBButton, 0);
            presetLayout->addWidget(groupCButton, 0);

            tableToolLayout->addLayout(presetLayout, 0);
            tableToolLayout->addWidget(searchEdit, 1);
            pageLayout->addLayout(tableToolLayout, 0);
            pageLayout->addWidget(table, 2);
            table->setProperty("kswordDeviceAuditFilter", searchEdit->text());
            installColumnPresetControls(
                table,
                groupAButton,
                groupBButton,
                groupCButton,
                deviceAuditColumnGroupA(),
                deviceAuditColumnGroupB(),
                deviceAuditColumnGroupC());
            QObject::connect(searchEdit, &QLineEdit::textChanged, table, [table](const QString& filterText)
            {
                table->setProperty("kswordDeviceAuditFilter", filterText);
                applyDeviceAuditTableFilter(table, filterText);
            });
            if (tableOut != nullptr)
            {
                *tableOut = table;
            }
        }
        return pageWidget;
    }

    // CPU core chart compact layout constants:
    // - Input: used by the CPU utilization page grid and each per-core chart cell.
    // - Processing: reduce the grid gap and per-cell chrome so dense multi-core CPUs waste less blank space.
    // - Return behavior: constants only; no runtime return value.
    constexpr int kCpuCoreChartGridSpacingPx = 2;
    constexpr int kCpuCoreChartCellMarginPx = 2;
    constexpr int kCpuCoreChartInnerSpacingPx = 1;
    constexpr int kCpuCoreChartChromeReservePx = 5;

    struct CpuCoreGridShape
    {
        int columnCount = 1;
        int rowCount = 1;
    };

    // chooseCpuCoreGridShape:
    // - Input: current logical processor count
    // Processing: Restore the original near-square layout: columns = ceil(sqrt(count)), rows = ceil(remaining cores).
    // - Returns: 2x2 grid for 4 threads; other core counts do not degrade to a single long row.
    CpuCoreGridShape chooseCpuCoreGridShape(const int logicalProcessorCount)
    {
        const int kCoreCount = std::max(1, logicalProcessorCount);
        const int kColumnCount = std::max(
            1,
            static_cast<int>(std::ceil(std::sqrt(static_cast<double>(kCoreCount)))));
        const int kRowCount = std::max(
            1,
            static_cast<int>(std::ceil(
                static_cast<double>(kCoreCount) /
                static_cast<double>(kColumnCount))));
        return CpuCoreGridShape{kColumnCount, kRowCount};
    }

    // formatHardwareAuditHex32:
    // - Input: 32-bit status, flag, or counter field returned by R0 audit.
    // - Processing: Unified formatting to 0xXXXXXXXX for comparison with protocol documentation/logs;
    // - Return: Qt string; does not modify any R0/R3 state.
    QString formatHardwareAuditHex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 8, 16, QChar('0'))
            .toUpper();
    }

    // formatHardwareAuditHex64:
    // - Input: 64-bit addresses such as DriverObject/DeviceObject from the R0 device audit line;
    // - Processing: Uniformly format as 0xXXXXXXXXXXXXXXXX.
    // - Returns: A QString intended solely for UI text display.
    QString formatHardwareAuditHex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    // arkClientMessageToQString:
    // - Input: Narrow-byte diagnostic from ArkDriverClient IoResult::message;
    // - Processing: Convert to Qt string using UTF-8; use placeholder for empty messages.
    // - Returns: Text directly appendable to CodeEditorWidget.
    QString arkClientMessageToQString(const std::string& messageText)
    {
        if (messageText.empty())
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromUtf8(messageText.data(), static_cast<int>(messageText.size()));
    }

    // friendlyHardwareIoMessage:
    // - Input: The underlying message and unsupported flag returned by ArkDriverClient;
    // - Processing: Fold engineering logs like DeviceIoControl, status, and bytesReturned into human-readable descriptions.
    // - Return: Chinese descriptions suitable for summary pages, the last column of tables, and detail text displays.
    QString friendlyHardwareIoMessage(
        const std::string& messageText,
        const bool unsupported)
    {
        const QString kRawText = arkClientMessageToQString(messageText).trimmed();
        if (unsupported)
        {
            return QStringLiteral("当前加载的 R0 驱动不支持该硬件审计入口，请同步驱动版本。");
        }
        if (kRawText.isEmpty() || kRawText == QStringLiteral("<empty>"))
        {
            return QStringLiteral("驱动未返回额外说明。");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或 R3/R0 协议版本不匹配。");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动不支持该只读硬件审计查询。");
        }
        if (kRawText.contains(QStringLiteral("status="), Qt::CaseInsensitive) &&
            kRawText.contains(QStringLiteral("bytesReturned="), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动已返回结构化硬件审计结果；底层 IO 状态已在本页字段中展开。");
        }
        return kRawText;
    }

    // friendlyDeviceAuditEntryDetail:
    // - Input: R0 single device audit entry.detail text;
    // - Processing: Convert low-level IOCTL/DynData/unsupported engineering hints into readable descriptions in the last table column.
    // - Return: short Chinese description, avoiding direct insertion of DevNode/USB/HID details into driver logs.
    QString friendlyDeviceAuditEntryDetail(const QString& detailText)
    {
        const QString kRawText = detailText.trimmed();
        if (kRawText.isEmpty())
        {
            return QStringLiteral("R0 返回结构化设备对象行");
        }
        if (kRawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("设备审计行来自失败/兼容性诊断，底层驱动接口调用未成功。");
        }
        if (kRawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动不支持该设备链路的深度字段，已保留基础行。");
        }
        if (kRawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("profile"), Qt::CaseInsensitive))
        {
            return QStringLiteral("PDB/DynData 能力未完全满足，设备对象基础信息可用，深度字段暂不可用。");
        }
        if (kRawText.contains(QStringLiteral("trunc"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive))
        {
            return QStringLiteral("设备审计结果可能被缓冲区截断，当前仅展示已返回的结构化行。");
        }
        if (kRawText.contains(QStringLiteral("access denied"), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("privilege"), Qt::CaseInsensitive))
        {
            return QStringLiteral("权限不足，设备链路只能展示可访问的只读证据。");
        }
        return kRawText;
    }

    // hardwareIoOkText:
    // - Input: IoResult::ok boolean value.
    // - Processing: Convert to short Chinese status strings to avoid displaying true/false in the details view.
    // - Returns: success/failure text.
    QString hardwareIoOkText(const bool ok)
    {
        return ok ? QStringLiteral("成功") : QStringLiteral("失败");
    }

    // deviceAuditStatusText:
    // - Input: shared/driver device audit queryStatus
    // - Processing: Map to user-readable status while preserving unknown values.
    // - Return: Status label; triggers no queries.
    QString deviceAuditStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL:
            return QStringLiteral("PARTIAL");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND:
            return QStringLiteral("NOT_FOUND");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("BUFFER_TRUNCATED");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED:
            return QStringLiteral("QUERY_FAILED");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_UNSUPPORTED:
            return QStringLiteral("UNSUPPORTED");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_UNAVAILABLE:
        default:
            return QStringLiteral("UNAVAILABLE(%1)").arg(statusValue);
        }
    }

    // deviceAuditRoleText:
    // - Input: R0 device audit row roleHint;
    // - Processing: Map roles such as PDO, FDO, filter, and controller.
    // - Return: The short text for the risk row summary.
    QString deviceAuditRoleText(const std::uint32_t roleValue)
    {
        switch (roleValue)
        {
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_PDO:
            return QStringLiteral("PDO");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_FDO:
            return QStringLiteral("FDO");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_UPPER_FILTER:
            return QStringLiteral("UpperFilter");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_LOWER_FILTER:
            return QStringLiteral("LowerFilter");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_CLASS_DRIVER:
            return QStringLiteral("ClassDriver");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER:
            return QStringLiteral("BusDriver");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_COMPOSITE:
            return QStringLiteral("Composite");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE:
            return QStringLiteral("Interface");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_CONTROLLER:
            return QStringLiteral("Controller");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY:
            return QStringLiteral("Display");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_WATCHDOG:
            return QStringLiteral("Watchdog");
        default:
            return QStringLiteral("Unknown(%1)").arg(roleValue);
        }
    }

    // deviceAuditRiskText:
    // - Input: R0 device audit riskFlags;
    // - Processing: Expand critical risk bits; display 'Clean' if no match is found.
    // - Returns: Risk summary text; UI displays evidence only, no remediation actions.
    QString deviceAuditRiskText(const std::uint32_t riskFlags)
    {
        QStringList riskPartList;
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_UNAVAILABLE) != 0U)
        {
            riskPartList << QStringLiteral("Unavailable");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED) != 0U)
        {
            riskPartList << QStringLiteral("QueryFailed");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_NAME_MISSING) != 0U)
        {
            riskPartList << QStringLiteral("NameMissing");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_IMAGE_PATH_MISSING) != 0U)
        {
            riskPartList << QStringLiteral("ImagePathMissing");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_DEVICE_LOOP) != 0U)
        {
            riskPartList << QStringLiteral("DeviceLoop");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_ATTACHED_LOOP) != 0U)
        {
            riskPartList << QStringLiteral("AttachedLoop");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_CROSS_DRIVER_ATTACH) != 0U)
        {
            riskPartList << QStringLiteral("CrossDriverAttach");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_ROLE_AMBIGUOUS) != 0U)
        {
            riskPartList << QStringLiteral("RoleAmbiguous");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_STACK_TRUNCATED) != 0U)
        {
            riskPartList << QStringLiteral("StackTruncated");
        }
        if ((riskFlags & KSWORD_ARK_DEVICE_AUDIT_RISK_INTEGRITY_PARTIAL) != 0U)
        {
            riskPartList << QStringLiteral("IntegrityPartial");
        }
        if (riskPartList.isEmpty())
        {
            return QStringLiteral("Clean");
        }
        return riskPartList.join(QStringLiteral("|"));
    }

    // deviceAuditResponseFlagText:
    // - Input: R0 device audit responseFlags;
    // Processing: Expand truncated/partial/empty response-level statuses.
    // - Return: Status text for the summary first screen.
    QString deviceAuditResponseFlagText(const std::uint32_t responseFlags)
    {
        QStringList flagPartList;
        if ((responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED) != 0U)
        {
            flagPartList << QStringLiteral("Truncated");
        }
        if ((responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_PARTIAL) != 0U)
        {
            flagPartList << QStringLiteral("Partial");
        }
        if ((responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_EMPTY) != 0U)
        {
            flagPartList << QStringLiteral("Empty");
        }
        if (flagPartList.isEmpty())
        {
            return QStringLiteral("None");
        }
        return flagPartList.join(QStringLiteral("|"));
    }

    // deviceAuditRowKindText:
    // - Input: R0 device audit rowKind original enumeration;
    // - Processing: Clearly distinguish summary and device rows, preserve enum values, and facilitate verification against the driver protocol;
    // - Returns: Text for the 'Row Type' column in the table.
    QString deviceAuditRowKindText(const std::uint32_t rowKind)
    {
        switch (rowKind)
        {
        case KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY:
            return QStringLiteral("DriverSummary(%1)").arg(rowKind);
        case KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DEVICE_ROW:
            return QStringLiteral("DeviceRow(%1)").arg(rowKind);
        default:
            return QStringLiteral("RowKind(%1)").arg(rowKind);
        }
    }

    // DeviceAuditParsedDetail:
    // - Input: Generated by parseDeviceAuditDetailFromR0;
    // - Processing: Parse stable key-value pairs from the current driver detail text into UI columns.
    // - Return: Pure data structure, no member function return value.
    struct DeviceAuditParsedDetail
    {
        QString ownerDriver;      // ownerDriver: The OwnerDriver=0x... value in the AttachedDevice detail row.
        QString integrityStatus;  // integrityStatus: Driver integrity status in DriverSummary details.
        QString integrityRows;    // integrityRows: rows=returned/total in DriverSummary detail.
        QString modules;          // modules: modules=... in DriverSummary detail.
        QString integrityFlags;   // integrityFlags: statusFlags=0x... in DriverSummary detail.
    };

    // deviceAuditDetailValue:
    // - Input: R0 detail raw text and stable key names, e.g., OwnerDriver/statusFlags;
    // - Processing: Extract up to the first semicolon, period, or whitespace in 'key=value' format;
    // - Returns: the matched value; an empty string if not found.
    QString deviceAuditDetailValue(const QString& detailText, const QString& keyText)
    {
        const QRegularExpression kExpression(
            QStringLiteral("(?:^|[;\\s])%1\\s*=\\s*([^;\\s.]+)")
                .arg(QRegularExpression::escape(keyText)),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch kMatch = kExpression.match(detailText);
        if (!kMatch.hasMatch())
        {
            return QString();
        }
        return kMatch.captured(1).trimmed().toUpper();
    }

    // parseDeviceAuditDetailFromR0:
    // - Input: KSWORD_ARK_DEVICE_AUDIT_ENTRY.detail original text;
    // - Processing: Parse only key-value pairs stably generated in the driver source code to avoid inserting full English diagnostic sentences into table main columns.
    // - Returns: A set of fields directly mappable to structured columns.
    DeviceAuditParsedDetail parseDeviceAuditDetailFromR0(const QString& detailText)
    {
        DeviceAuditParsedDetail parsed;
        parsed.ownerDriver = deviceAuditDetailValue(detailText, QStringLiteral("OwnerDriver"));
        parsed.integrityStatus = deviceAuditDetailValue(detailText, QStringLiteral("status"));
        parsed.integrityRows = deviceAuditDetailValue(detailText, QStringLiteral("rows"));
        parsed.modules = deviceAuditDetailValue(detailText, QStringLiteral("modules"));
        parsed.integrityFlags = deviceAuditDetailValue(detailText, QStringLiteral("statusFlags"));
        return parsed;
    }

    // isStructuredDeviceAuditDetail:
    // - Input: R0 detail raw text.
    // - Processing: Identify stable formats already split by table columns;
    // - Return: true to indicate the original text should not be repeated in the 'Remarks' column.
    bool isStructuredDeviceAuditDetail(const QString& detailText)
    {
        const QString kRawText = detailText.trimmed();
        return kRawText.contains(QStringLiteral("Driver integrity status="), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("DeviceObject="), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("AttachedDevice="), Qt::CaseInsensitive) ||
            kRawText.contains(QStringLiteral("OwnerDriver="), Qt::CaseInsensitive);
    }

    // appendDeviceAuditSummaryText:
    // - Input: Page title, wrapper return value, and request depth.
    // - Processing: Summarize returnedCount/totalCount, maxDepth/truncated, IO status, and risk rows.
    // - Returns: Read-only text that can be appended to the device stack/input chain/USB topology CodeEditorWidget.
    QString appendDeviceAuditSummaryText(
        const QString& titleText,
        const ksword::ark::DeviceAuditResult& auditResult,
        const std::uint32_t requestedMaxDepth)
    {
        std::uint32_t maxObservedDepth = 0U;
        std::uint32_t riskRowCount = 0U;
        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : auditResult.entries)
        {
            maxObservedDepth = std::max(maxObservedDepth, static_cast<std::uint32_t>(entry.relationDepth));
            maxObservedDepth = std::max(maxObservedDepth, static_cast<std::uint32_t>(entry.attachedDepth));
            if (entry.riskFlags != KSWORD_ARK_DEVICE_AUDIT_RISK_NONE)
            {
                ++riskRowCount;
            }
        }

        const bool kTruncatedFlag =
            (auditResult.responseFlags & KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED) != 0U
            || auditResult.returnedCount < auditResult.totalCount;

        QString text;
        text += QStringLiteral("\n\n[%1]\n").arg(titleText);
        text += QStringLiteral("以下内容为只读设备证据，不会修改设备状态。\n");
        text += QStringLiteral("调用状态: %1；兼容性: %2；Win32=%3；NTSTATUS=%4；返回字节=%5\n")
            .arg(hardwareIoOkText(auditResult.io.ok))
            .arg(auditResult.unsupported ? QStringLiteral("驱动不支持") : QStringLiteral("接口可用"))
            .arg(auditResult.io.win32Error)
            .arg(formatHardwareAuditHex32(static_cast<std::uint32_t>(auditResult.io.ntStatus)))
            .arg(auditResult.io.bytesReturned);
        text += QStringLiteral("驱动说明: %1\n")
            .arg(friendlyHardwareIoMessage(auditResult.io.message, auditResult.unsupported));
        text += QStringLiteral("协议状态: version=%1；queryStatus=%2；lastStatus=%3；entrySize=%4\n")
            .arg(auditResult.version)
            .arg(deviceAuditStatusText(auditResult.status))
            .arg(formatHardwareAuditHex32(static_cast<std::uint32_t>(auditResult.lastStatus)))
            .arg(auditResult.entrySize);
        text += QStringLiteral("对象计数: returned=%1；total=%2；已解析=%3；目标=%4；驱动=%5；设备=%6\n")
            .arg(auditResult.returnedCount)
            .arg(auditResult.totalCount)
            .arg(auditResult.entries.size())
            .arg(auditResult.targetCount)
            .arg(auditResult.driverCount)
            .arg(auditResult.deviceCount);
        text += QStringLiteral("链路深度: 观察最大=%1；请求上限=%2；是否截断=%3；响应标志=%4（%5）\n")
            .arg(maxObservedDepth)
            .arg(requestedMaxDepth)
            .arg(kTruncatedFlag ? QStringLiteral("是") : QStringLiteral("否"))
            .arg(formatHardwareAuditHex32(auditResult.responseFlags))
            .arg(deviceAuditResponseFlagText(auditResult.responseFlags));
        text += QStringLiteral("风险摘要: 风险行=%1；profileFlags=%2；处理建议=%3\n")
            .arg(riskRowCount)
            .arg(formatHardwareAuditHex32(auditResult.profileFlags))
            .arg(riskRowCount == 0U ? QStringLiteral("未发现 R0 风险行") : QStringLiteral("请查看表格中非 Clean 的风险行"));

        int shownRows = 0;
        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : auditResult.entries)
        {
            if (entry.riskFlags == KSWORD_ARK_DEVICE_AUDIT_RISK_NONE && shownRows >= 8)
            {
                continue;
            }

            const QString kDriverNameText = QString::fromWCharArray(entry.driverName).trimmed();
            const QString kDeviceNameText = QString::fromWCharArray(entry.deviceName).trimmed();
            const QString kDetailText = QString::fromWCharArray(entry.detail).trimmed();
            const QString kReadableEntryDetailText = friendlyDeviceAuditEntryDetail(kDetailText);
            text += QStringLiteral("行[%1]: 角色=%2；状态=%3；风险=%4（%5）；置信度=%6；深度=%7/%8；驱动=%9；设备=%10；DriverObject=%11；DeviceObject=%12；说明=%13\n")
                .arg(shownRows)
                .arg(deviceAuditRoleText(entry.roleHint))
                .arg(deviceAuditStatusText(entry.status))
                .arg(deviceAuditRiskText(entry.riskFlags))
                .arg(formatHardwareAuditHex32(entry.riskFlags))
                .arg(entry.confidence)
                .arg(entry.relationDepth)
                .arg(entry.attachedDepth)
                .arg(kDriverNameText.isEmpty() ? QStringLiteral("<unnamed>") : kDriverNameText)
                .arg(kDeviceNameText.isEmpty() ? QStringLiteral("<unnamed>") : kDeviceNameText)
                .arg(formatHardwareAuditHex64(entry.driverObjectAddress))
                .arg(formatHardwareAuditHex64(entry.deviceObjectAddress))
                .arg(kReadableEntryDetailText);
            ++shownRows;
            if (shownRows >= 12)
            {
                break;
            }
        }

        if (auditResult.entries.empty())
        {
            text += QStringLiteral("明细行: <无返回行>\n");
        }
        return text;
    }

    // buildDeviceAuditRows:
    // - Input: wrapper name and ArkDriverClient device audit result;
    // - Processing: Convert all R0 entries into structured table rows, preserving a readable diagnostic row even for empty results.
    // - Return: QVector<QStringList>, with the number of columns per row matching hardwareDeviceAuditTableHeaders.
    QVector<QStringList> buildDeviceAuditRows(
        const QString& profileName,
        const ksword::ark::DeviceAuditResult& auditResult)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(auditResult.entries.size()) + 1);

        if (auditResult.entries.empty())
        {
            const QString kStateText = auditResult.io.ok
                ? QStringLiteral("驱动接口可用，但没有返回设备行")
                : (auditResult.unsupported
                    ? QStringLiteral("当前驱动不支持该设备审计入口")
                    : QStringLiteral("设备审计接口暂不可用"));
            rows.push_back(QStringList{
                profileName,
                QStringLiteral("NoRows"),
                QStringLiteral("<none>"),
                deviceAuditStatusText(auditResult.status),
                auditResult.unsupported ? QStringLiteral("Unsupported") : QStringLiteral("NoRows"),
                QStringLiteral("0"),
                QStringLiteral("0"),
                QStringLiteral("0"),
                QStringLiteral("<none>"),
                QStringLiteral("<none>"),
                QStringLiteral("<none>"),
                QStringLiteral("<none>"),
                QStringLiteral("0x0"),
                QStringLiteral("0x0"),
                QStringLiteral("0x0"),
                QStringLiteral("0x0"),
                QStringLiteral("0x0"),
                formatHardwareAuditHex32(0U),
                formatHardwareAuditHex32(0U),
                QStringLiteral("0"),
                QStringLiteral("0"),
                formatHardwareAuditHex32(0U),
                formatHardwareAuditHex32(static_cast<std::uint32_t>(auditResult.lastStatus)),
                deviceAuditStatusText(auditResult.status),
                QStringLiteral("%1/%2").arg(auditResult.returnedCount).arg(auditResult.totalCount),
                QString::number(auditResult.driverCount),
                formatHardwareAuditHex32(auditResult.responseFlags),
                QStringLiteral("%1；returned=%2 total=%3；%4")
                    .arg(kStateText)
                    .arg(auditResult.returnedCount)
                    .arg(auditResult.totalCount)
                    .arg(friendlyHardwareIoMessage(auditResult.io.message, auditResult.unsupported))
            });
            return rows;
        }

        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : auditResult.entries)
        {
            const QString kDriverNameText = QString::fromWCharArray(entry.driverName).trimmed();
            const QString kServiceNameText = QString::fromWCharArray(entry.serviceName).trimmed();
            const QString kDeviceNameText = QString::fromWCharArray(entry.deviceName).trimmed();
            const QString kImagePathText = QString::fromWCharArray(entry.imagePath).trimmed();
            const QString kDetailText = QString::fromWCharArray(entry.detail).trimmed();
            const QString kReadableEntryDetailText = friendlyDeviceAuditEntryDetail(kDetailText);
            const DeviceAuditParsedDetail kParsedDetail = parseDeviceAuditDetailFromR0(kDetailText);
            QStringList noteParts;
            if (!kDetailText.isEmpty() && !isStructuredDeviceAuditDetail(kDetailText))
            {
                noteParts << kReadableEntryDetailText;
            }
            if (kDetailText.isEmpty())
            {
                noteParts << QStringLiteral("R0 未返回额外备注");
            }
            if (auditResult.responseFlags != 0U)
            {
                noteParts << QStringLiteral("responseFlags=%1(%2)")
                    .arg(formatHardwareAuditHex32(auditResult.responseFlags))
                    .arg(deviceAuditResponseFlagText(auditResult.responseFlags));
            }
            if (entry.profileFlags != auditResult.profileFlags)
            {
                noteParts << QStringLiteral("entryProfile=%1")
                    .arg(formatHardwareAuditHex32(entry.profileFlags));
            }

            rows.push_back(QStringList{
                profileName,
                deviceAuditRowKindText(entry.rowKind),
                deviceAuditRoleText(entry.roleHint),
                deviceAuditStatusText(entry.status),
                deviceAuditRiskText(entry.riskFlags),
                QString::number(entry.confidence),
                QString::number(entry.relationDepth),
                QString::number(entry.attachedDepth),
                kDriverNameText.isEmpty() ? QStringLiteral("<unnamed>") : kDriverNameText,
                kServiceNameText.isEmpty() ? QStringLiteral("<none>") : kServiceNameText,
                kImagePathText.isEmpty() ? QStringLiteral("<none>") : kImagePathText,
                kDeviceNameText.isEmpty() ? QStringLiteral("<unnamed>") : kDeviceNameText,
                formatHardwareAuditHex64(entry.driverObjectAddress),
                formatHardwareAuditHex64(entry.deviceObjectAddress),
                formatHardwareAuditHex64(entry.attachedDeviceAddress),
                formatHardwareAuditHex64(entry.nextDeviceObjectAddress),
                kParsedDetail.ownerDriver.isEmpty()
                    ? QStringLiteral("<none>")
                    : kParsedDetail.ownerDriver,
                formatHardwareAuditHex32(entry.deviceType),
                formatHardwareAuditHex32(entry.characteristics),
                QString::number(entry.stackSize),
                QString::number(entry.alignmentRequirement),
                formatHardwareAuditHex32(entry.fieldFlags),
                formatHardwareAuditHex32(static_cast<std::uint32_t>(entry.lastStatus)),
                kParsedDetail.integrityStatus.isEmpty()
                    ? QString()
                    : kParsedDetail.integrityStatus,
                kParsedDetail.integrityRows,
                kParsedDetail.modules,
                kParsedDetail.integrityFlags,
                noteParts.join(QStringLiteral("；"))
            });
        }

        return rows;
    }

    // makeDeviceAuditItem:
    // - Input: Cell text;
    // - Processing: Create read-only QTableWidgetItem.
    // - Return: The item pointer, with lifecycle managed by the table.
    QTableWidgetItem* makeDeviceAuditItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        item->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        return item;
    }

    // populateDeviceAuditTable:
    // - Input: Target table and row model;
    // - Handling: Preserve sort state and populate all read-only rows.
    // - Return: None. Ignores directly if the table pointer is null.
    void populateDeviceAuditTable(QTableWidget* table, const QVector<QStringList>& rows)
    {
        if (table == nullptr)
        {
            return;
        }

        const bool kWasSortingEnabled = table->isSortingEnabled();
        table->setSortingEnabled(false);
        table->setRowCount(rows.size());
        for (int rowIndex = 0; rowIndex < rows.size(); ++rowIndex)
        {
            const QStringList& row = rows.at(rowIndex);
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QString kCellText = columnIndex < row.size() ? row.at(columnIndex) : QString();
                table->setItem(rowIndex, columnIndex, makeDeviceAuditItem(kCellText));
            }
        }
        table->setSortingEnabled(kWasSortingEnabled);
        applyDeviceAuditTableFilter(
            table,
            table->property("kswordDeviceAuditFilter").toString());
    }

    // createHardwareDeferredPlaceholder:
    // - Input: parent widget, title text, and description text;
    // - Processing: Create a lightweight placeholder page so that heavy pages load only after the user actually enters the sub-tab.
    // - Return: placeholder QWidget pointer; caller responsible for adding it to the target layout.
    QWidget* createHardwareDeferredPlaceholder(
        QWidget* parentWidget,
        const QString& titleText,
        const QString& hintText)
    {
        QWidget* placeholderWidget = new QWidget(parentWidget);
        placeholderWidget->setAutoFillBackground(false);
        placeholderWidget->setAttribute(Qt::WA_StyledBackground, false);

        QVBoxLayout* placeholderLayout = new QVBoxLayout(placeholderWidget);
        placeholderLayout->setContentsMargins(24, 24, 24, 24);
        placeholderLayout->setSpacing(8);
        placeholderLayout->addStretch(1);

        QLabel* titleLabel = new QLabel(titleText, placeholderWidget);
        titleLabel->setAlignment(Qt::AlignCenter);
        titleLabel->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
            .arg(ksword_theme::textPrimaryHex()));
        placeholderLayout->addWidget(titleLabel, 0);

        QLabel* hintLabel = new QLabel(hintText, placeholderWidget);
        hintLabel->setAlignment(Qt::AlignCenter);
        hintLabel->setWordWrap(true);
        hintLabel->setStyleSheet(
            QStringLiteral("font-size:12px;color:%1;")
            .arg(ksword_theme::textSecondaryHex()));
        placeholderLayout->addWidget(hintLabel, 0);
        placeholderLayout->addStretch(1);
        return placeholderWidget;
    }

    // appendTransparentBackgroundStyle:
    // - Add transparent background styles to controls on the 'Hardware -> Counters/Utilization' page.
    // - If the widget belongs to a scroll area, also set the viewport to transparent to avoid residual background colors.
    void appendTransparentBackgroundStyle(QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr)
        {
            return;
        }

        widgetPointer->setAttribute(Qt::WA_StyledBackground, true);
        widgetPointer->setAutoFillBackground(false);

        // transparentDeclarationText purpose: transparent background declaration snippet; transparentRuleText purpose: rule block specific to the current control.
        const QString kTransparentDeclarationText =
            QStringLiteral("background:transparent;background-color:transparent;border:none;");
        const QString kTransparentRuleText = QStringLiteral("%1{%2}")
            .arg(QString::fromLatin1(widgetPointer->metaObject()->className()))
            .arg(kTransparentDeclarationText);
        if (!widgetPointer->styleSheet().contains(QStringLiteral("background:transparent")))
        {
            widgetPointer->setStyleSheet(widgetPointer->styleSheet() + kTransparentRuleText);
        }

        QAbstractScrollArea* abstractScrollAreaPointer =
            qobject_cast<QAbstractScrollArea*>(widgetPointer);
        if (abstractScrollAreaPointer == nullptr || abstractScrollAreaPointer->viewport() == nullptr)
        {
            return;
        }

        abstractScrollAreaPointer->viewport()->setAttribute(Qt::WA_StyledBackground, true);
        abstractScrollAreaPointer->viewport()->setAutoFillBackground(false);
        if (!abstractScrollAreaPointer->viewport()->styleSheet().contains(QStringLiteral("background:transparent")))
        {
            const QString kViewportTransparentRuleText = QStringLiteral("%1{%2}")
                .arg(QString::fromLatin1(abstractScrollAreaPointer->viewport()->metaObject()->className()))
                .arg(kTransparentDeclarationText);
            abstractScrollAreaPointer->viewport()->setStyleSheet(
                abstractScrollAreaPointer->viewport()->styleSheet() + kViewportTransparentRuleText);
        }
    }

    // configureTransparentChart:
    // - Uniformly disable the chart background and the plot area background.
    // - Prevent QChart from drawing white/dark background blocks when inside a transparent container.
    void configureTransparentChart(QChart* chartPointer)
    {
        if (chartPointer == nullptr)
        {
            return;
        }

        chartPointer->setBackgroundVisible(false);
        chartPointer->setPlotAreaBackgroundVisible(false);
        chartPointer->setBackgroundRoundness(0);
        chartPointer->setMargins(QMargins(0, 0, 0, 0));
    }

    // configureTransparentChartViewOnly:
    // - Only clear the outer background of QChart without overwriting the plotArea background and grid borders set by the caller;
    // - The CPU single-core utilization chart requires retaining the drawing area frame/fill, so configureTransparentChart cannot be called.
    // - Return behavior: no return value; null pointers are ignored directly.
    void configureTransparentChartViewOnly(QChart* chartPointer)
    {
        if (chartPointer == nullptr)
        {
            return;
        }

        chartPointer->setBackgroundVisible(false);
        chartPointer->setBackgroundRoundness(0);
        chartPointer->setMargins(QMargins(0, 0, 0, 0));
    }

    // configureCompressibleWidget:
    // - Clear the widget's default minimum size to allow compression when the Dock is narrow or short, avoiding requests for outer scrollbars.
    // - horizontalPolicy/verticalPolicy specify horizontal/vertical distribution policies by page role.
    // - Return behavior: No return value; only modifies the QWidget's layout properties.
    void configureCompressibleWidget(
        QWidget* widgetPointer,
        const QSizePolicy::Policy horizontalPolicy = QSizePolicy::Preferred,
        const QSizePolicy::Policy verticalPolicy = QSizePolicy::Preferred)
    {
        if (widgetPointer == nullptr)
        {
            return;
        }

        widgetPointer->setMinimumSize(0, 0);
        widgetPointer->setSizePolicy(horizontalPolicy, verticalPolicy);
    }

    // configureCompressibleLabel:
    // - Compress or truncate long device names, CPU/GPU models, and detail text when space is insufficient.
    // - When page width/height decreases, content shrinks first instead of expanding the outer QScrollArea to show scrollbars.
    // - Return behavior: no return value; only modifies the QLabel's layout properties.
    void configureCompressibleLabel(
        QLabel* labelPointer,
        const QSizePolicy::Policy horizontalPolicy = QSizePolicy::Ignored,
        const QSizePolicy::Policy verticalPolicy = QSizePolicy::Preferred)
    {
        configureCompressibleWidget(labelPointer, horizontalPolicy, verticalPolicy);
    }

    // configurePersistentHeaderLabel:
    // - Used for the top title and right-side device model note on the 'Utilization' detail page.
    // - These labels must always maintain a visible height of one line and cannot be compressed to 0 by the chart area.
    // - Return behavior: No return value; only adjusts the single-line layout policy of the QLabel.
    void configurePersistentHeaderLabel(
        QLabel* labelPointer,
        const QSizePolicy::Policy horizontalPolicy = QSizePolicy::Preferred)
    {
        if (labelPointer == nullptr)
        {
            return;
        }

        labelPointer->setMinimumSize(0, 0);
        labelPointer->setWordWrap(false);
        labelPointer->setSizePolicy(horizontalPolicy, QSizePolicy::Fixed);
        labelPointer->setMinimumHeight(std::max(1, labelPointer->sizeHint().height()));
    }

    // lockLabelHeightToFont:
    // - Re-lock the QLabel row height based on font metrics after applying a large font style;
    // - Resolves the issue where QLabel's top/bottom is clipped by layout when it first calculates sizeHint for the normal font size and then applies 46px styling.
    // - Parameter extraVerticalPadding: Total extra vertical pixels reserved above and below the font ascent/descent.
    // - Return behavior: No return value; updates the label's minimum/maximum height only.
    void lockLabelHeightToFont(QLabel* labelPointer, const int extraVerticalPadding)
    {
        if (labelPointer == nullptr)
        {
            return;
        }

        // ensurePolished purpose: ensure stylesheet font-size/font-weight take effect before reading font metrics.
        labelPointer->ensurePolished();
        // fontHeight usage: Read the actual font height after applying application styles to avoid relying on stale sizeHint values.
        const int kFontHeight = labelPointer->fontMetrics().height();
        // targetHeight usage: preserve top/bottom padding for large titles to avoid clipping under high DPI or font fallback.
        const int kTargetHeight = std::max(
            labelPointer->sizeHint().height(),
            kFontHeight + std::max(0, extraVerticalPadding));
        labelPointer->setMinimumHeight(kTargetHeight);
        labelPointer->setMaximumHeight(kTargetHeight);
    }

    // bytesToGiBText:
    // - Converts byte count to GiB text, retaining 2 decimal places.
    QString bytesToGiBText(const std::uint64_t bytesValue)
    {
        const double kGibValue = static_cast<double>(bytesValue) / (1024.0 * 1024.0 * 1024.0);
        return QStringLiteral("%1 GiB").arg(kGibValue, 0, 'f', 2);
    }

    // bytesPerSecondToText:
    // - Convert bytes-per-second rates to human-readable text (B/s, KB/s, MB/s, GB/s);
    // - Used to display disk/network rates in the utilization sub-page summary.
    QString bytesPerSecondToText(const double bytesPerSecondValue)
    {
        const double kSafeValue = std::max(0.0, bytesPerSecondValue);
        if (kSafeValue < 1024.0)
        {
            return QStringLiteral("%1 B/s").arg(kSafeValue, 0, 'f', 1);
        }
        if (kSafeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(kSafeValue / 1024.0, 0, 'f', 1);
        }
        if (kSafeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(kSafeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB/s").arg(kSafeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // bytesToReadableText:
    // Convert byte count to readable text (B/KB/MB/GB).
    // - Used to display capacity information in the Task Manager parameter area.
    QString bytesToReadableText(const double bytesValue)
    {
        const double kSafeValue = std::max(0.0, bytesValue);
        if (kSafeValue < 1024.0)
        {
            return QStringLiteral("%1 B").arg(kSafeValue, 0, 'f', 0);
        }
        if (kSafeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB").arg(kSafeValue / 1024.0, 0, 'f', 1);
        }
        if (kSafeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB").arg(kSafeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB").arg(kSafeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // resolveGpuEngineKeyFromCounter:
    // Map PDH GPU engine counter names to fixed keys.
    // - Only cares about the four common Task Manager categories: 3D/Copy/Video Encode/Video Decode.
    QString resolveGpuEngineKeyFromCounter(const QString& counterNameText)
    {
        const QString kLowerText = counterNameText.toLower();
        if (kLowerText.contains(QStringLiteral("engtype_3d")))
        {
            return QStringLiteral("3d");
        }
        if (kLowerText.contains(QStringLiteral("engtype_copy")))
        {
            return QStringLiteral("copy");
        }
        if (kLowerText.contains(QStringLiteral("engtype_videoencode"))
            || kLowerText.contains(QStringLiteral("engtype_videncode")))
        {
            return QStringLiteral("video_encode");
        }
        if (kLowerText.contains(QStringLiteral("engtype_videodecode"))
            || kLowerText.contains(QStringLiteral("engtype_viddecode")))
        {
            return QStringLiteral("video_decode");
        }
        return QString();
    }

    // packLuidKey:
    // - Merge the HighPart and LowPart of a Windows LUID into a stable 64-bit key.
    // - Used to correlate DXGI graphics adapters with PDH GPU Engine instances.
    std::uint64_t packLuidKey(const LUID& luidValue)
    {
        const std::uint64_t kHighPartValue =
            static_cast<std::uint64_t>(static_cast<std::uint32_t>(luidValue.HighPart));
        const std::uint64_t kLowPartValue =
            static_cast<std::uint64_t>(luidValue.LowPart);
        return (kHighPartValue << 32U) | kLowPartValue;
    }

    // interfaceLuidToKey:
    // - Convert MIB_IF_ROW2::InterfaceLuid.Value to an unsigned key;
    // - Callers use this key to match the same network adapter across sampling periods.
    std::uint64_t interfaceLuidToKey(const std::uint64_t luidValue)
    {
        return luidValue;
    }

    // simplifyDiskInstanceName:
    // - Converts PDH PhysicalDisk instance names to Task Manager-style titles;
    // - Example: "0 C:" displays as "Disk 0 (C:)".
    QString simplifyDiskInstanceName(const QString& instanceNameText)
    {
        const QString kTrimmedText = instanceNameText.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return QStringLiteral("磁盘");
        }
        if (kTrimmedText == QStringLiteral("_Total"))
        {
            return QStringLiteral("磁盘总计");
        }

        const int kSpaceIndex = kTrimmedText.indexOf(QLatin1Char(' '));
        if (kSpaceIndex > 0)
        {
            const QString kDiskIndexText = kTrimmedText.left(kSpaceIndex).trimmed();
            const QString kVolumeText = kTrimmedText.mid(kSpaceIndex + 1).trimmed();
            if (!kVolumeText.isEmpty())
            {
                return QStringLiteral("磁盘 %1 (%2)").arg(kDiskIndexText, kVolumeText);
            }
            return QStringLiteral("磁盘 %1").arg(kDiskIndexText);
        }

        return QStringLiteral("磁盘 %1").arg(kTrimmedText);
    }

    // parseGpuAdapterKeyFromCounterName:
    // - Parse LUID from PDH GPU Engine or GPU Adapter Memory instance names.
    // - Common Windows format includes 'luid_0xHIGH_0xLOW'; returns false on failure.
    bool parseGpuAdapterKeyFromCounterName(
        const QString& counterNameText,
        std::uint64_t* adapterKeyOut)
    {
        if (adapterKeyOut == nullptr)
        {
            return false;
        }

        static const QRegularExpression kLuidRegex(
            QStringLiteral("luid_0x([0-9a-fA-F]+)_0x([0-9a-fA-F]+)"));
        const QRegularExpressionMatch kMatchValue = kLuidRegex.match(counterNameText);
        if (!kMatchValue.hasMatch())
        {
            return false;
        }

        bool highOk = false;
        bool lowOk = false;
        const std::uint64_t kHighValue = kMatchValue.captured(1).toULongLong(&highOk, 16);
        const std::uint64_t kLowValue = kMatchValue.captured(2).toULongLong(&lowOk, 16);
        if (!highOk || !lowOk)
        {
            return false;
        }

        *adapterKeyOut = ((kHighValue & 0xFFFFFFFFULL) << 32U) | (kLowValue & 0xFFFFFFFFULL);
        return true;
    }

    // GpuAdapterTelemetrySnapshot：
    // - Binds WDDM/D3DKMT data via DXGI adapter LUID to avoid 32-bit truncation of WMI AdapterRAM;
    // - Frequency represents the driver's current clock; MaxFrequency/MaxFrequencyOC are for maximum value reference only.
    struct GpuAdapterTelemetrySnapshot
    {
        std::uint64_t dedicatedVideoMemoryBytes = 0;
        std::uint64_t sharedSystemMemoryBytes = 0;
        double currentCoreClockMhz = 0.0;
        double maxCoreClockMhz = 0.0;
        double currentMemoryClockMhz = 0.0;
        double maxMemoryClockMhz = 0.0;
    };

    // queryD3dKmtAdapterInfo:
    // - Unified assembly of D3DKMTQueryAdapterInfo requests;
    // - Returns true if the driver accepts the query type; if an old WDDM driver does not support it, the caller continues using the DXGI fallback.
    bool queryD3dKmtAdapterInfo(
        const D3DKMT_HANDLE adapterHandle,
        const KMTQUERYADAPTERINFOTYPE queryType,
        void* queryBuffer,
        const UINT queryBufferSize)
    {
        if (adapterHandle == 0 || queryBuffer == nullptr || queryBufferSize == 0)
        {
            return false;
        }

        D3DKMT_QUERYADAPTERINFO queryInfo{};
        queryInfo.hAdapter = adapterHandle;
        queryInfo.Type = queryType;
        queryInfo.pPrivateDriverData = queryBuffer;
        queryInfo.PrivateDriverDataSize = queryBufferSize;
        return ::D3DKMTQueryAdapterInfo(&queryInfo) >= 0;
    }

    // queryGpuAdapterTelemetrySnapshot:
    // - Input: The same adapter LUID returned by DXGI; reads the real VRAM segment size and real-time 3D/VRAM frequency.
    // - 3D nodes are identified via NODEMETADATA to avoid mistaking Copy/Video node clocks for the GPU core speed;
    // - Return true if any D3DKMT query succeeds; missing fields remain 0 for upper layers to fall back by field.
    bool queryGpuAdapterTelemetrySnapshot(
        const LUID& adapterLuid,
        GpuAdapterTelemetrySnapshot* snapshotOut)
    {
        if (snapshotOut == nullptr)
        {
            return false;
        }
        *snapshotOut = GpuAdapterTelemetrySnapshot{};

        D3DKMT_OPENADAPTERFROMLUID openInfo{};
        openInfo.AdapterLuid = adapterLuid;
        if (::D3DKMTOpenAdapterFromLuid(&openInfo) < 0 || openInfo.hAdapter == 0)
        {
            return false;
        }

        bool anyQuerySucceeded = false;

        D3DKMT_SEGMENTSIZEINFO segmentSizeInfo{};
        if (queryD3dKmtAdapterInfo(
                openInfo.hAdapter,
                KMTQAITYPE_GETSEGMENTSIZE,
                &segmentSizeInfo,
                sizeof(segmentSizeInfo)))
        {
            snapshotOut->dedicatedVideoMemoryBytes =
                static_cast<std::uint64_t>(segmentSizeInfo.DedicatedVideoMemorySize);
            snapshotOut->sharedSystemMemoryBytes =
                static_cast<std::uint64_t>(segmentSizeInfo.SharedSystemMemorySize);
            anyQuerySucceeded = true;
        }

        D3DKMT_ADAPTER_PERFDATA adapterPerfData{};
        adapterPerfData.PhysicalAdapterIndex = 0;
        if (queryD3dKmtAdapterInfo(
                openInfo.hAdapter,
                KMTQAITYPE_ADAPTERPERFDATA,
                &adapterPerfData,
                sizeof(adapterPerfData)))
        {
            constexpr double kHertzPerMegahertz = 1000000.0;
            snapshotOut->currentMemoryClockMhz =
                static_cast<double>(adapterPerfData.MemoryFrequency) / kHertzPerMegahertz;
            const double kReportedMaxMemoryClockMhz = static_cast<double>(std::max(
                adapterPerfData.MaxMemoryFrequency,
                adapterPerfData.MaxMemoryFrequencyOC)) / kHertzPerMegahertz;
            snapshotOut->maxMemoryClockMhz = std::max(
                snapshotOut->currentMemoryClockMhz,
                kReportedMaxMemoryClockMhz);
            anyQuerySucceeded = true;
        }

        ULONG nodeCount = 1;
        D3DKMT_QUERYSTATISTICS adapterStatistics{};
        adapterStatistics.Type = D3DKMT_QUERYSTATISTICS_ADAPTER;
        adapterStatistics.AdapterLuid = adapterLuid;
        if (::D3DKMTQueryStatistics(&adapterStatistics) >= 0)
        {
            nodeCount = std::clamp(
                adapterStatistics.QueryResult.AdapterInformation.NodeCount,
                1UL,
                64UL);
        }

        double fallbackCurrentClockMhz = 0.0;
        double fallbackMaxClockMhz = 0.0;
        bool found3dNode = false;
        for (ULONG nodeOrdinal = 0; nodeOrdinal < nodeCount; ++nodeOrdinal)
        {
            D3DKMT_NODE_PERFDATA nodePerfData{};
            nodePerfData.NodeOrdinal = nodeOrdinal;
            nodePerfData.PhysicalAdapterIndex = 0;
            if (!queryD3dKmtAdapterInfo(
                    openInfo.hAdapter,
                    KMTQAITYPE_NODEPERFDATA,
                    &nodePerfData,
                    sizeof(nodePerfData)))
            {
                continue;
            }

            constexpr double kHertzPerMegahertz = 1000000.0;
            const double kCurrentClockMhz =
                static_cast<double>(nodePerfData.Frequency) / kHertzPerMegahertz;
            const double kReportedMaxClockMhz = static_cast<double>(std::max(
                nodePerfData.MaxFrequency,
                nodePerfData.MaxFrequencyOC)) / kHertzPerMegahertz;
            const double kMaxClockMhz = std::max(kCurrentClockMhz, kReportedMaxClockMhz);
            fallbackCurrentClockMhz = std::max(fallbackCurrentClockMhz, kCurrentClockMhz);
            fallbackMaxClockMhz = std::max(fallbackMaxClockMhz, kMaxClockMhz);
            anyQuerySucceeded = true;

            D3DKMT_NODEMETADATA nodeMetadata{};
            nodeMetadata.NodeOrdinalAndAdapterIndex = nodeOrdinal;
            if (queryD3dKmtAdapterInfo(
                    openInfo.hAdapter,
                    KMTQAITYPE_NODEMETADATA,
                    &nodeMetadata,
                    sizeof(nodeMetadata))
                && nodeMetadata.NodeData.EngineType == DXGK_ENGINE_TYPE_3D)
            {
                found3dNode = true;
                snapshotOut->currentCoreClockMhz = std::max(
                    snapshotOut->currentCoreClockMhz,
                    kCurrentClockMhz);
                snapshotOut->maxCoreClockMhz = std::max(
                    snapshotOut->maxCoreClockMhz,
                    kMaxClockMhz);
            }
        }

        if (!found3dNode || snapshotOut->currentCoreClockMhz <= 0.0)
        {
            snapshotOut->currentCoreClockMhz = fallbackCurrentClockMhz;
        }
        if (!found3dNode || snapshotOut->maxCoreClockMhz <= 0.0)
        {
            snapshotOut->maxCoreClockMhz = fallbackMaxClockMhz;
        }

        D3DKMT_CLOSEADAPTER closeInfo{};
        closeInfo.hAdapter = openInfo.hAdapter;
        ::D3DKMTCloseAdapter(&closeInfo);
        return anyQuerySucceeded;
    }

    // formatGpuClockMhzText:
    // - Format the MHz value returned by the driver as an integer.
    // - Explicitly display N/A when real-time performance data is not supported to avoid misreporting 0 MHz as an actual speed.
    QString formatGpuClockMhzText(const double clockMhz)
    {
        return clockMhz > 0.0
            ? QString::number(clockMhz, 'f', 0)
            : QStringLiteral("N/A");
    }

    // formatGpuMemoryUsageGiBText:
    // - Distinguish between actual 0 system-level GPU memory usage and unavailable counters;
    // - Display N/A when the counter is unavailable to avoid misreporting sampling failures as 0.00 GiB.
    QString formatGpuMemoryUsageGiBText(
        const double usageGiB,
        const bool usageAvailable,
        const int decimalPlaces = 2)
    {
        return usageAvailable
            ? QString::number(std::max(0.0, usageGiB), 'f', decimalPlaces)
            : QStringLiteral("N/A");
    }

    // formatDurationText:
    // - Format seconds as 'days:hours:minutes:seconds';
    // - Used for displaying CPU page 'uptime'.
    QString formatDurationText(const std::uint64_t totalSeconds)
    {
        const std::uint64_t kDayCount = totalSeconds / 86400ULL;
        const std::uint64_t kHourCount = (totalSeconds % 86400ULL) / 3600ULL;
        const std::uint64_t kMinuteCount = (totalSeconds % 3600ULL) / 60ULL;
        const std::uint64_t kSecondCount = totalSeconds % 60ULL;
        return QStringLiteral("%1:%2:%3:%4")
            .arg(kDayCount)
            .arg(kHourCount, 2, 10, QLatin1Char('0'))
            .arg(kMinuteCount, 2, 10, QLatin1Char('0'))
            .arg(kSecondCount, 2, 10, QLatin1Char('0'));
    }

    // queryCpuBrandTextByCpuid:
    // - Read CPU brand string via CPUID instruction.
    // - Avoid relying on PowerShell queries for CPU model detection.
    QString queryCpuBrandTextByCpuid()
    {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 0x80000000);
        const unsigned int kMaxExtendedLeaf = static_cast<unsigned int>(cpuInfo[0]);
        if (kMaxExtendedLeaf < 0x80000004)
        {
            return QStringLiteral("N/A");
        }

        char brandBuffer[49] = {};
        int* brandIntBuffer = reinterpret_cast<int*>(brandBuffer);
        __cpuid(brandIntBuffer, 0x80000002);
        __cpuid(brandIntBuffer + 4, 0x80000003);
        __cpuid(brandIntBuffer + 8, 0x80000004);

        const QString kBrandText = QString::fromLatin1(brandBuffer).trimmed();
        return kBrandText.isEmpty() ? QStringLiteral("N/A") : kBrandText;
    }

    // countBits:
    // - Calculate the number of set bits in the processor affinity mask.
    // - Used to count the number of logical processors.
    int countBits(const KAFFINITY affinityMask)
    {
        return std::popcount(static_cast<unsigned long long>(affinityMask));
    }

    // MemoryHardwareSummarySnapshot:
    // - Save memory hardware summary (frequency, slot, form factor).
    // - Populated by background PowerShell queries for display on the utilization details page.
    struct MemoryHardwareSummarySnapshot
    {
        int speedMhz = 0;               // speedMhz: Memory clock speed (MHz).
        int usedSlots = 0;              // usedSlots: number of used slots.
        int totalSlots = 0;             // totalSlots: Total number of motherboard slots.
        QString formFactorText = QStringLiteral("N/A"); // formFactorText: Memory form factor text.
    };

    // GpuHardwareSummarySnapshot:
    // - Saves GPU summary (name, driver, video memory);
    // - Populated by a background PowerShell query for display on the GPU utilization details page.
    struct GpuHardwareSummarySnapshot
    {
        QString adapterNameText = QStringLiteral("N/A");    // adapterNameText: graphics card name.
        QString driverVersionText = QStringLiteral("N/A");  // driverVersionText: Driver version.
        QString driverDateText = QStringLiteral("N/A");     // driverDateText: Driver date.
        QString pnpDeviceIdText = QStringLiteral("N/A");    // pnpDeviceIdText: PNP device ID.
        double dedicatedMemoryGiB = 0.0;                    // dedicatedMemoryGiB: Dedicated video memory in GiB.
        struct AdapterSnapshot
        {
            int adapterIndex = -1;
            QString adapterNameText = QStringLiteral("N/A");
            double dedicatedMemoryGiB = 0.0;
            double sharedMemoryGiB = 0.0;
            double currentCoreClockMhz = 0.0;
            double maxCoreClockMhz = 0.0;
            double currentMemoryClockMhz = 0.0;
            double maxMemoryClockMhz = 0.0;
        };
        QVector<AdapterSnapshot> adapterList;
    };

    // queryMemoryHardwareSummarySnapshot:
    // - Query memory hardware parameters (speed, slot, form factor);
    // - Called only on the background thread to avoid blocking the UI.
    MemoryHardwareSummarySnapshot queryMemoryHardwareSummarySnapshot()
    {
        const QString kScriptText = QStringLiteral(
            "$mods=Get-CimInstance Win32_PhysicalMemory; "
            "$arr=Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1 -ExpandProperty MemoryDevices; "
            "$speed=($mods | Select-Object -First 1 -ExpandProperty ConfiguredClockSpeed); "
            "$formCode=($mods | Select-Object -First 1 -ExpandProperty FormFactor); "
            "$formText=if([int]$formCode -eq 8){'DIMM'}elseif([int]$formCode -eq 12){'SODIMM'}elseif([int]$formCode -gt 0){'代码'+[string]$formCode}else{'N/A'}; "
            "\"$speed|$($mods.Count)|$arr|$formText\"");
        const QString kOutputText = queryPowerShellTextSync(kScriptText, 3200);
        const QStringList kFieldList = kOutputText.split('|');

        MemoryHardwareSummarySnapshot snapshot;
        if (kFieldList.size() >= 4)
        {
            snapshot.speedMhz = kFieldList.at(0).trimmed().toInt();
            snapshot.usedSlots = kFieldList.at(1).trimmed().toInt();
            snapshot.totalSlots = kFieldList.at(2).trimmed().toInt();
            snapshot.formFactorText = kFieldList.at(3).trimmed();
            if (snapshot.formFactorText.isEmpty())
            {
                snapshot.formFactorText = QStringLiteral("N/A");
            }
        }
        return snapshot;
    }

    // queryGpuHardwareSummarySnapshot:
    // - Query GPU summary (name, driver version, dedicated video memory).
    // - Called only on the background thread to avoid blocking the UI.
    GpuHardwareSummarySnapshot queryGpuHardwareSummarySnapshot()
    {
        const QString kScriptText = QStringLiteral(
            "$gpu=Get-CimInstance Win32_VideoController | Select-Object -First 1 Name,DriverVersion,DriverDate,PNPDeviceID; "
            "if($null -eq $gpu){'N/A|N/A|N/A|N/A'}else{\"$($gpu.Name)|$($gpu.DriverVersion)|$($gpu.DriverDate)|$($gpu.PNPDeviceID)\"}");
        const QString kOutputText = queryPowerShellTextSync(kScriptText, 2800);
        const QStringList kFieldList = kOutputText.split('|');

        GpuHardwareSummarySnapshot snapshot;
        if (kFieldList.size() >= 4)
        {
            snapshot.adapterNameText = kFieldList.at(0).trimmed();
            snapshot.driverVersionText = kFieldList.at(1).trimmed();
            snapshot.driverDateText = kFieldList.at(2).trimmed();
            snapshot.pnpDeviceIdText = kFieldList.at(3).trimmed();
        }

        // Win32_VideoController.AdapterRAM is a 32-bit field; large VRAM will be truncated to approximately 4 GiB.
        // Capacity must be read from the same DXGI LUID/WDDM adapter used for performance sampling.
        IDXGIFactory6* factoryPointer = nullptr;
        if (SUCCEEDED(::CreateDXGIFactory1(IID_PPV_ARGS(&factoryPointer)))
            && factoryPointer != nullptr)
        {
            double selectedDedicatedMemoryGiB = -1.0;
            for (UINT adapterIndex = 0;; ++adapterIndex)
            {
                IDXGIAdapter1* adapterPointer = nullptr;
                const HRESULT kEnumStatus = factoryPointer->EnumAdapters1(adapterIndex, &adapterPointer);
                if (kEnumStatus == DXGI_ERROR_NOT_FOUND)
                {
                    break;
                }
                if (FAILED(kEnumStatus) || adapterPointer == nullptr)
                {
                    continue;
                }

                DXGI_ADAPTER_DESC1 adapterDesc{};
                adapterPointer->GetDesc1(&adapterDesc);
                if ((adapterDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) == 0)
                {
                    GpuHardwareSummarySnapshot::AdapterSnapshot adapterSnapshot;
                    adapterSnapshot.adapterIndex = static_cast<int>(adapterIndex);
                    const QString kDxgiAdapterName =
                        QString::fromWCharArray(adapterDesc.Description).trimmed();
                    if (!kDxgiAdapterName.isEmpty())
                    {
                        adapterSnapshot.adapterNameText = kDxgiAdapterName;
                    }

                    GpuAdapterTelemetrySnapshot telemetrySnapshot;
                    queryGpuAdapterTelemetrySnapshot(adapterDesc.AdapterLuid, &telemetrySnapshot);
                    const std::uint64_t kDedicatedMemoryBytes =
                        telemetrySnapshot.dedicatedVideoMemoryBytes > 0
                        ? telemetrySnapshot.dedicatedVideoMemoryBytes
                        : static_cast<std::uint64_t>(adapterDesc.DedicatedVideoMemory);
                    const std::uint64_t kSharedMemoryBytes =
                        telemetrySnapshot.sharedSystemMemoryBytes > 0
                        ? telemetrySnapshot.sharedSystemMemoryBytes
                        : static_cast<std::uint64_t>(adapterDesc.SharedSystemMemory);
                    constexpr double kOneGiBInBytes = 1024.0 * 1024.0 * 1024.0;
                    adapterSnapshot.dedicatedMemoryGiB =
                        static_cast<double>(kDedicatedMemoryBytes) / kOneGiBInBytes;
                    adapterSnapshot.sharedMemoryGiB =
                        static_cast<double>(kSharedMemoryBytes) / kOneGiBInBytes;
                    adapterSnapshot.currentCoreClockMhz = telemetrySnapshot.currentCoreClockMhz;
                    adapterSnapshot.maxCoreClockMhz = telemetrySnapshot.maxCoreClockMhz;
                    adapterSnapshot.currentMemoryClockMhz = telemetrySnapshot.currentMemoryClockMhz;
                    adapterSnapshot.maxMemoryClockMhz = telemetrySnapshot.maxMemoryClockMhz;
                    snapshot.adapterList.push_back(adapterSnapshot);

                    // Prioritize the adapter with the largest dedicated memory in the main GPU summary to avoid the integrated GPU taking over on multi-GPU machines.
                    if (adapterSnapshot.dedicatedMemoryGiB > selectedDedicatedMemoryGiB)
                    {
                        selectedDedicatedMemoryGiB = adapterSnapshot.dedicatedMemoryGiB;
                        snapshot.adapterNameText = adapterSnapshot.adapterNameText;
                        snapshot.dedicatedMemoryGiB = adapterSnapshot.dedicatedMemoryGiB;
                    }
                }
                adapterPointer->Release();
            }
            factoryPointer->Release();
        }
        return snapshot;
    }

    // formatGpuHardwareSummaryText:
    // - Format DXGI/WDDM snapshots into the 'Graphics Card' information page within the UI thread.
    // - WMI only supplements driver and display mode information; it no longer handles VRAM capacity identification.
    QString formatGpuHardwareSummaryText(
        const GpuHardwareSummarySnapshot& snapshot,
        const QString& wmiText)
    {
        QStringList adapterBlockList;
        for (const GpuHardwareSummarySnapshot::AdapterSnapshot& adapter : snapshot.adapterList)
        {
            const QString kDedicatedMemoryText = adapter.dedicatedMemoryGiB > 0.0
                ? QString::number(adapter.dedicatedMemoryGiB, 'f', 2)
                : QStringLiteral("N/A");
            const QString kSharedMemoryText = adapter.sharedMemoryGiB > 0.0
                ? QString::number(adapter.sharedMemoryGiB, 'f', 2)
                : QStringLiteral("N/A");
            adapterBlockList.push_back(
                ks::i18n::contextText(
                    QStringLiteral("hardware.gpu.static.telemetry.adapter"),
                    QStringLiteral("[GPU %1 - DXGI/WDDM]\n名称: %2\n专用显存: %3 GiB\n共享 GPU 内存: %4 GiB\n核心频率: %5 MHz（最大 %6 MHz）\n显存频率: %7 MHz（最大 %8 MHz）"))
                .arg(adapter.adapterIndex)
                .arg(adapter.adapterNameText)
                .arg(kDedicatedMemoryText)
                .arg(kSharedMemoryText)
                .arg(formatGpuClockMhzText(adapter.currentCoreClockMhz))
                .arg(formatGpuClockMhzText(adapter.maxCoreClockMhz))
                .arg(formatGpuClockMhzText(adapter.currentMemoryClockMhz))
                .arg(formatGpuClockMhzText(adapter.maxMemoryClockMhz)));
        }

        if (adapterBlockList.isEmpty())
        {
            adapterBlockList.push_back(
                ks::i18n::contextText(
                    QStringLiteral("hardware.gpu.static.telemetry.unavailable"),
                    QStringLiteral("未从 DXGI/WDDM 读取到 GPU 显存与频率信息。")));
        }

        const QString kTelemetryHeading = ks::i18n::contextText(
            QStringLiteral("hardware.gpu.static.telemetry.heading"),
            QStringLiteral("[实时 GPU 硬件信息]"));
        const QString kWmiHeading = ks::i18n::contextText(
            QStringLiteral("hardware.gpu.static.wmi.heading"),
            QStringLiteral("[WMI 驱动与显示信息]"));
        return kTelemetryHeading
            + QStringLiteral("\n")
            + adapterBlockList.join(QStringLiteral("\n\n"))
            + QStringLiteral("\n\n")
            + kWmiHeading
            + QStringLiteral("\n")
            + wmiText.trimmed();
    }

    // createNoFrameChartView:
    // - Create a borderless ChartView to unify the visual style within the Dock.
    QChartView* createNoFrameChartView(QChart* chart, QWidget* parentWidget)
    {
        configureTransparentChart(chart);
        QChartView* chartView = new QChartView(chart, parentWidget);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setFrameShape(QFrame::NoFrame);
        // ChartView itself may generate QGraphicsView scrollbars; here they are uniformly disabled, allowing height to compress to 0.
        chartView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chartView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chartView->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
        configureCompressibleWidget(chartView, QSizePolicy::Expanding, QSizePolicy::Expanding);
        appendTransparentBackgroundStyle(chartView);
        return chartView;
    }

    // createPlotBackgroundChartView:
    // - Create a ChartView that preserves the plotArea style.
    // - Used for all utilization line charts to ensure the plot area box, grid, and area fill are not disabled by the generic transparency logic;
    // - Return value: A QChartView with borderless and transparent viewport settings applied.
    QChartView* createPlotBackgroundChartView(QChart* chart, QWidget* parentWidget)
    {
        configureTransparentChartViewOnly(chart);
        // QChart's SeriesAnimations morphs the entire old curve into the new one based on point indices.
        // When the sliding window deletes the head point and appends the tail point simultaneously, this triggers a full redraw of the chart
        // every second. Curve data updates in real-time, while only the visible X-axis range is smoothed by animateLiveValueAxisRange.
        chart->setAnimationOptions(QChart::kNoAnimation);
        QChartView* chartView = new QChartView(chart, parentWidget);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setFrameShape(QFrame::NoFrame);
        // ChartView itself still does not display scrollbars; dimensions are uniformly controlled by the outer layout.
        chartView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chartView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        chartView->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
        configureCompressibleWidget(chartView, QSizePolicy::Expanding, QSizePolicy::Expanding);
        appendTransparentBackgroundStyle(chartView);
        return chartView;
    }

    // animateLiveValueAxisRange:
    // - When appending new points to the line chart, only the X-axis window is smoothly moved; no point deformation is applied to the entire QLineSeries.
    // - When the same axis is shared by two lines in a single refresh, the later target replaces the previous animation target.
    // - 260 ms is significantly shorter than the 1 s sampling period, avoiding animation backlog.
    void animateLiveValueAxisRange(
        QValueAxis* axisPointer,
        const double targetMinValue,
        const double targetMaxValue)
    {
        if (axisPointer == nullptr || targetMaxValue <= targetMinValue)
        {
            return;
        }

        const double kStartMinValue = axisPointer->min();
        const double kStartMaxValue = axisPointer->max();
        if (qFuzzyCompare(kStartMinValue + 1.0, targetMinValue + 1.0)
            && qFuzzyCompare(kStartMaxValue + 1.0, targetMaxValue + 1.0))
        {
            axisPointer->setRange(targetMinValue, targetMaxValue);
            return;
        }

        const QList<QVariantAnimation*> kPreviousAnimations =
            axisPointer->findChildren<QVariantAnimation*>(
                QStringLiteral("kswordLiveAxisRangeAnimation"),
                Qt::FindDirectChildrenOnly);
        for (QVariantAnimation* previousAnimation : kPreviousAnimations)
        {
            previousAnimation->stop();
            delete previousAnimation;
        }

        QVariantAnimation* axisAnimation = new QVariantAnimation(axisPointer);
        axisAnimation->setObjectName(QStringLiteral("kswordLiveAxisRangeAnimation"));
        axisAnimation->setDuration(260);
        axisAnimation->setEasingCurve(QEasingCurve::OutCubic);
        axisAnimation->setStartValue(0.0);
        axisAnimation->setEndValue(1.0);

        const QPointer<QValueAxis> kSafeAxisPointer(axisPointer);
        QObject::connect(
            axisAnimation,
            &QVariantAnimation::valueChanged,
            axisPointer,
            [kSafeAxisPointer,
             kStartMinValue,
             kStartMaxValue,
             targetMinValue,
             targetMaxValue](const QVariant& progressValue)
            {
                if (kSafeAxisPointer == nullptr)
                {
                    return;
                }
                const double kProgress = progressValue.toDouble();
                kSafeAxisPointer->setRange(
                    kStartMinValue + (targetMinValue - kStartMinValue) * kProgress,
                    kStartMaxValue + (targetMaxValue - kStartMaxValue) * kProgress);
            });
        QObject::connect(
            axisAnimation,
            &QVariantAnimation::finished,
            axisPointer,
            [kSafeAxisPointer, targetMinValue, targetMaxValue]()
            {
                if (kSafeAxisPointer != nullptr)
                {
                    kSafeAxisPointer->setRange(targetMinValue, targetMaxValue);
                }
            });
        QObject::connect(
            axisAnimation,
            &QVariantAnimation::finished,
            axisAnimation,
            &QObject::deleteLater);
        axisAnimation->start();
    }

    // colorWithAlpha:
    // - Generate auxiliary colors with varying transparency based on the polyline's primary color.
    // - Ensures consistent hue for the drawing area background, grid, borders, and area fill.
    QColor colorWithAlpha(const QColor& sourceColor, const int alphaValue)
    {
        return QColor(
            sourceColor.red(),
            sourceColor.green(),
            sourceColor.blue(),
            std::clamp(alphaValue, 0, 255));
    }

    // initializeLineSeriesHistory:
    // - Pre-fill line points with fixed history length.
    // - Ensures the chart has a complete X-axis window on first display; subsequent sampling only appends via a sliding window.
    void initializeLineSeriesHistory(
        QLineSeries* lineSeries,
        const int historyLength,
        const double sampleValue = 0.0)
    {
        if (lineSeries == nullptr)
        {
            return;
        }

        for (int indexValue = 0; indexValue < historyLength; ++indexValue)
        {
            lineSeries->append(indexValue, sampleValue);
        }
    }

    // createBaselineSeries:
    // - Create a baseline line on the 0-axis with the same number of points as the line series.
    // - QAreaSeries depends on a closed area formed by upper and lower lines, so each utilization line holds its own baseline independently;
    QLineSeries* createBaselineSeries(
        QWidget* parentWidget,
        const int historyLength,
        const double baselineValue = 0.0)
    {
        QLineSeries* baselineSeries = new QLineSeries(parentWidget);
        initializeLineSeriesHistory(baselineSeries, historyLength, baselineValue);
        return baselineSeries;
    }

    // addFilledAreaSeries:
    // - Combine a line series and a baseline into an area series and add it to QChart;
    // - Returns the newly created QAreaSeries; returns nullptr on failure.
    QAreaSeries* addFilledAreaSeries(
        QChart* chartPointer,
        QLineSeries* lineSeries,
        QLineSeries* baselineSeries,
        const QColor& lineColor,
        const int fillAlpha = 46)
    {
        if (chartPointer == nullptr || lineSeries == nullptr || baselineSeries == nullptr)
        {
            return nullptr;
        }

        QAreaSeries* areaSeries = new QAreaSeries(lineSeries, baselineSeries);
        areaSeries->setName(lineSeries->name());
        areaSeries->setColor(colorWithAlpha(lineColor, fillAlpha));
        areaSeries->setBorderColor(lineColor);
        areaSeries->setPen(QPen(lineColor, 1.6));
        chartPointer->addSeries(areaSeries);
        return areaSeries;
    }

    // configureUtilizationPlotChart:
    // - Uniformly configure the appearance of the utilization plot chart.
    // - Retain the transparent outer background while adding a light background and a clear border to the plotArea.
    void configureUtilizationPlotChart(
        QChart* chartPointer,
        const QColor& accentColor,
        const QString& titleText = QString(),
        const bool legendVisible = false)
    {
        if (chartPointer == nullptr)
        {
            return;
        }

        chartPointer->legend()->setVisible(legendVisible);
        if (legendVisible)
        {
            chartPointer->legend()->setAlignment(Qt::AlignBottom);
        }
        chartPointer->setBackgroundVisible(false);
        chartPointer->setBackgroundRoundness(0);
        chartPointer->setMargins(QMargins(0, 0, 0, 0));
        chartPointer->setTitle(titleText);
        chartPointer->setTitleBrush(QBrush(ksword_theme::textPrimaryColor()));
        if (legendVisible)
        {
            chartPointer->legend()->setLabelColor(ksword_theme::textSecondaryColor());
        }
        chartPointer->setPlotAreaBackgroundVisible(true);
        chartPointer->setPlotAreaBackgroundBrush(QBrush(colorWithAlpha(accentColor, 18)));
        chartPointer->setPlotAreaBackgroundPen(QPen(colorWithAlpha(accentColor, 150), 1.0));
    }

    // configureUtilizationValueAxis:
    // - Uniformly hide axis labels while retaining the axis line and grid.
    // - The box and horizontal grid jointly reinforce the boundary of the utilization trend chart.
    void configureUtilizationValueAxis(
        QValueAxis* axisPointer,
        const QColor& accentColor,
        const double lowerValue,
        const double upperValue)
    {
        if (axisPointer == nullptr)
        {
            return;
        }

        axisPointer->setRange(lowerValue, upperValue);
        axisPointer->setLabelsVisible(false);
        axisPointer->setGridLineVisible(true);
        axisPointer->setMinorGridLineVisible(false);
        axisPointer->setLineVisible(true);
        axisPointer->setLinePen(QPen(colorWithAlpha(accentColor, 140), 1.0));
        axisPointer->setGridLinePen(QPen(colorWithAlpha(accentColor, 46), 1.0));
    }

    // queryPowerShellTextSync:
    // - Synchronously execute a PowerShell script in the current thread and return the text result.
    // - Call only in a background worker thread to avoid blocking the UI thread.
    // Parameter scriptText: The PowerShell command text to execute.
    // Parameter timeoutMs: Timeout duration (milliseconds).
    // Returns: standard output text; on failure, returns an error description.
    QString queryPowerShellTextSync(const QString& scriptText, const int timeoutMs)
    {
        QProcess process;
        process.setProgram(QStringLiteral("powershell.exe"));
        process.setArguments({
            QStringLiteral("-NoProfile"),
            QStringLiteral("-ExecutionPolicy"),
            QStringLiteral("Bypass"),
            QStringLiteral("-Command"),
            scriptText
            });
        process.start();

        // waitStartedOk purpose: Determine if the PowerShell process started successfully.
        const bool kWaitStartedOk = process.waitForStarted(1200);
        if (!kWaitStartedOk)
        {
            return QStringLiteral("PowerShell启动失败。");
        }

        // waitFinishedOk usage: Determines whether the command finished before the timeout.
        const bool kWaitFinishedOk = process.waitForFinished(timeoutMs);
        if (!kWaitFinishedOk)
        {
            process.kill();
            process.waitForFinished(800);
            return QStringLiteral("PowerShell执行超时（%1 ms）。").arg(timeoutMs);
        }

        // standardOutputText usage: Stores command standard output.
        // standardErrorText: Purpose: Stores the command's standard error output.
        const QString kStandardOutputText = QString::fromLocal8Bit(process.readAllStandardOutput()).trimmed();
        const QString kStandardErrorText = QString::fromLocal8Bit(process.readAllStandardError()).trimmed();
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        {
            return QStringLiteral("PowerShell执行失败。\nExitCode=%1\nError=%2")
                .arg(process.exitCode())
                .arg(kStandardErrorText.isEmpty() ? QStringLiteral("<空>") : kStandardErrorText);
        }

        if (kStandardOutputText.isEmpty())
        {
            return QStringLiteral("<无输出>");
        }
        return kStandardOutputText;
    }

    // buildOverviewStaticTextSnapshot:
    // - Build a static text snapshot for the 'Overview' page;
    // - Performs lightweight Win32/Qt system information reads without depending on UI objects.
    QString buildOverviewStaticTextSnapshot()
    {
        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);

        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        ::GlobalMemoryStatusEx(&memoryStatus);

        QString text;
        text += QStringLiteral("系统名称: %1\n").arg(QSysInfo::prettyProductName());
        text += QStringLiteral("CPU架构: %1\n").arg(QSysInfo::currentCpuArchitecture());
        text += QStringLiteral("内核类型: %1\n").arg(QSysInfo::kernelType());
        text += QStringLiteral("内核版本: %1\n").arg(QSysInfo::kernelVersion());
        text += QStringLiteral("逻辑处理器数量: %1\n").arg(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        text += QStringLiteral("处理器组掩码(十六进制): 0x%1\n")
            .arg(QString::number(static_cast<qulonglong>(systemInfo.dwActiveProcessorMask), 16).toUpper());
        text += QStringLiteral("页面大小: %1 字节\n").arg(systemInfo.dwPageSize);
        text += QStringLiteral("物理内存总量: %1\n").arg(bytesToGiBText(memoryStatus.ullTotalPhys));
        text += QStringLiteral("当前可用内存: %1\n").arg(bytesToGiBText(memoryStatus.ullAvailPhys));
        text += QStringLiteral("虚拟内存总量: %1\n").arg(bytesToGiBText(memoryStatus.ullTotalVirtual));
        text += QStringLiteral("当前可用虚拟内存: %1\n").arg(bytesToGiBText(memoryStatus.ullAvailVirtual));
        text += QStringLiteral("系统启动时间: %1\n")
            .arg(QDateTime::fromMSecsSinceEpoch(
                QDateTime::currentMSecsSinceEpoch() - static_cast<qint64>(::GetTickCount64()))
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
        return text;
    }

    // buildOverviewPeripheralTextSnapshot:
    // - Collect overview text for peripherals and hardware devices on the 'Overview' page.
    // - Override user-specified sound card, network card, and camera, and supplement motherboard, BIOS, and disk information.
    // Notes:
    // - This function executes a PowerShell + CIM query.
    // - Must be called on a background thread to avoid blocking the UI thread.
    QString buildOverviewPeripheralTextSnapshot()
    {
        const QString kScriptText = QStringLiteral(
            "$ErrorActionPreference='SilentlyContinue'; "
            "function Write-Section([string]$title,[object]$rows){ "
            "  if($null -eq $rows){return \"[$title]`n<未检测到>`n`n\"}; "
            "  $count = ($rows | Measure-Object).Count; "
            "  if($count -eq 0){return \"[$title]`n<未检测到>`n`n\"}; "
            "  $table = ($rows | Format-Table -AutoSize | Out-String); "
            "  return \"[$title]`n$table`n\"; "
            "}; "
            "$text = ''; "
            "$baseBoardRows = Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber; "
            "$biosRows = Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber; "
            "$cpuRows = Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed; "
            "$diskRows = Get-CimInstance Win32_DiskDrive | Select-Object Model,InterfaceType,MediaType,Size,SerialNumber; "
            "$gpuRows = Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion,VideoProcessor; "
            "$soundRows = Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,Status; "
            "$networkRows = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true } | "
            "  Select-Object Name,AdapterType,Speed,MACAddress,NetConnectionStatus,Manufacturer; "
            "$cameraRows = Get-CimInstance Win32_PnPEntity | "
            "  Where-Object { $_.PNPClass -eq 'Image' -or $_.Service -like '*usbvideo*' } | "
            "  Select-Object Name,Manufacturer,Status,Service,PNPDeviceID; "
            "$monitorRows = Get-CimInstance Win32_DesktopMonitor | Select-Object Name,MonitorType,ScreenWidth,ScreenHeight,Status; "
            "$printerRows = Get-CimInstance Win32_Printer | Select-Object Name,DriverName,PortName,WorkOffline,Default; "
            "$usbRows = Get-CimInstance Win32_USBControllerDevice | Select-Object Dependent -First 30; "
            "$text += Write-Section '主板' $baseBoardRows; "
            "$text += Write-Section 'BIOS' $biosRows; "
            "$text += Write-Section '处理器' $cpuRows; "
            "$text += Write-Section '磁盘设备' $diskRows; "
            "$text += Write-Section '显卡设备' $gpuRows; "
            "$text += Write-Section '声卡设备' $soundRows; "
            "$text += Write-Section '网卡设备(物理)' $networkRows; "
            "$text += Write-Section '摄像头设备' $cameraRows; "
            "$text += Write-Section '显示器设备' $monitorRows; "
            "$text += Write-Section '打印机设备' $printerRows; "
            "$text += Write-Section 'USB控制器映射(前30条)' $usbRows; "
            "$text");
        return queryPowerShellTextSync(kScriptText, 9000);
    }

    // buildGpuStaticTextSnapshot:
    // - Collects GPU information text via WMI;
    // - This function invokes PowerShell and must be executed on a background thread.
    QString buildGpuStaticTextSnapshot()
    {
        const QString kScriptText = QStringLiteral(
            "$list=Get-CimInstance Win32_VideoController | "
            "Select-Object Name,DriverVersion,VideoProcessor,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate,PNPDeviceID; "
            "if($null -eq $list){'未读取到显卡信息'} else {$list | Format-Table -AutoSize | Out-String}");
        return queryPowerShellTextSync(kScriptText, 5000);
    }

    // buildMemoryStaticTextSnapshot:
    // - Collect memory module and system memory information text via WMI.
    // - This function invokes PowerShell and must be executed on a background thread.
    QString buildMemoryStaticTextSnapshot()
    {
        const QString kScriptText = QStringLiteral(
            "$phy=Get-CimInstance Win32_PhysicalMemory | "
            "Select-Object BankLabel,Manufacturer,PartNumber,ConfiguredClockSpeed,Capacity,SMBIOSMemoryType; "
            "$os=Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory; "
            "'[物理内存条]';"
            "$phy | Format-Table -AutoSize | Out-String; "
            "'[操作系统内存]';"
            "$os | Format-List | Out-String");
        return queryPowerShellTextSync(kScriptText, 6000);
    }

    // SensorProbeResult:
    // - Saves the sensor value, source, and failure reason from a single sensor probe;
    // - Used by the asynchronous refresh logic to determine UI display and log output.
    struct SensorProbeResult
    {
        QString valueText = QStringLiteral("N/A"); // valueText: Text of the detected sensor value.
        QString sourceText; // sourceText: Source identifier upon successful read.
        QString reasonText; // reasonText: Summary of reasons for failure.
        QString rawOutputText; // rawOutputText: Raw script return text, for diagnostics.
        bool success = false; // success: Whether a valid value was read during this probe.
        bool expectedUnavailable = false; // expectedUnavailable: Sensor source is missing due to system capabilities; this is an expected unavailable state.
    };

#pragma pack(push, 4)
    // CoreTempSharedDataPrefix:
    // - Maps the original prefix of the Core Temp shared memory structure for long-term compatibility.
    // The new CoreTempMappingObjectEx appends fields after this prefix; temperature reading only requires the prefix.
    // - The structure member order is derived from the Core Temp developer documentation; 4-byte alignment must be strictly maintained.
    struct CoreTempSharedDataPrefix
    {
        unsigned int uiLoad[256];      // uiLoad: per-thread/core load; current temperature reading is not used.
        unsigned int uiTjMax[128];     // uiTjMax: TjMax per core, used for DeltaToTjMax conversion.
        unsigned int uiCoreCnt;        // uiCoreCnt: Number of CPU cores.
        unsigned int uiCPUCnt;         // uiCPUCnt: number of CPU packages.
        float fTemp[256];              // fTemp: per-core temperature or distance to TjMax.
        float fVID;                    // fVID: VID voltage reported by Core Temp.
        float fCPUSpeed;               // fCPUSpeed: Current CPU frequency.
        float fFSBSpeed;               // fFSBSpeed: Bus frequency.
        float fMultiplier;             // fMultiplier: Multiplier.
        char sCPUName[100];            // sCPUName: CPU name identified by Core Temp.
        unsigned char ucFahrenheit;    // ucFahrenheit: Whether the temperature is in Fahrenheit.
        unsigned char ucDeltaToTjMax;  // ucDeltaToTjMax: Whether the temperature field represents the distance to TjMax.
    };
#pragma pack(pop)

    // isReadableSensorValue:
    // - Check if the sensor text is a valid value for display.
    // - Unify handling empty strings and N/A.
    bool isReadableSensorValue(const QString& sensorValueText)
    {
        const QString kTrimmedValueText = sensorValueText.trimmed();
        return !kTrimmedValueText.isEmpty() && kTrimmedValueText != QStringLiteral("N/A");
    }

    // formatCelsiusSensorValue:
    // - Unifies validation and formatting of Celsius temperature values;
    // - Input valueCelsius: floating-point value in degrees Celsius;
    // - Returns an empty string if the value is out of bounds or NaN; otherwise returns display text with the °C suffix.
    QString formatCelsiusSensorValue(const double valueCelsius)
    {
        if (!std::isfinite(valueCelsius) || valueCelsius < -30.0 || valueCelsius > 130.0)
        {
            return QString();
        }
        return QStringLiteral("%1°C").arg(valueCelsius, 0, 'f', 1);
    }

    // parseSensorProbeOutput:
    // - Parses the PowerShell OK|... / ERR|... protocol text.
    // - Fallback to the legacy simple text format that returns only a single value.
    SensorProbeResult parseSensorProbeOutput(const QString& rawOutputText)
    {
        SensorProbeResult probeResult;
        probeResult.rawOutputText = rawOutputText.trimmed();

        const QString kFirstLineText = probeResult.rawOutputText
            .split('\n', Qt::SkipEmptyParts)
            .value(0)
            .trimmed();
        if (kFirstLineText.startsWith(QStringLiteral("OK|")))
        {
            const QStringList kResultPartList = kFirstLineText.split('|');
            probeResult.valueText =
                kResultPartList.size() >= 2 ? kResultPartList.at(1).trimmed() : QStringLiteral("N/A");
            probeResult.sourceText =
                kResultPartList.size() >= 3 ? kResultPartList.mid(2).join(QStringLiteral("|")).trimmed() : QString();
            probeResult.success = isReadableSensorValue(probeResult.valueText);
            if (!probeResult.success)
            {
                probeResult.reasonText = QStringLiteral("脚本返回成功标记，但值为空。");
            }
            return probeResult;
        }

        if (kFirstLineText.startsWith(QStringLiteral("ERR|")))
        {
            probeResult.reasonText = kFirstLineText.mid(4).trimmed();
            if (probeResult.reasonText.isEmpty())
            {
                probeResult.reasonText = QStringLiteral("脚本返回失败标记，但未提供原因。");
            }
            return probeResult;
        }

        if (kFirstLineText.isEmpty())
        {
            probeResult.reasonText = QStringLiteral("脚本无输出。");
            return probeResult;
        }

        if (kFirstLineText == QStringLiteral("<无输出>")
            || kFirstLineText.contains(QStringLiteral("PowerShell"))
            || kFirstLineText.contains(QStringLiteral("失败"))
            || kFirstLineText.contains(QStringLiteral("超时")))
        {
            probeResult.reasonText = kFirstLineText;
            return probeResult;
        }

        probeResult.valueText = kFirstLineText;
        probeResult.success = isReadableSensorValue(probeResult.valueText);
        if (!probeResult.success)
        {
            probeResult.reasonText = QStringLiteral("脚本仅返回了空值或 N/A。");
        }
        return probeResult;
    }

    // buildSensorProbeSignatureText:
    // - Generate a stable signature for log deduplication;
    // - Contains source and value on success; contains reason on failure.
    QString buildSensorProbeSignatureText(
        const QString& probeNameText,
        const SensorProbeResult& probeResult)
    {
        if (probeResult.success)
        {
            return QStringLiteral("%1:OK:%2:%3")
                .arg(probeNameText)
                .arg(probeResult.sourceText)
                .arg(probeResult.valueText);
        }

        return QStringLiteral("%1:ERR:%2")
            .arg(probeNameText)
            .arg(probeResult.reasonText);
    }

    // buildSensorProbeLogFragment:
    // - Generate log fragment for a single sensor item;
    // - On failure, prioritize returning the reason; on success, return the source and value.
    QString buildSensorProbeLogFragment(
        const QString& probeNameText,
        const SensorProbeResult& probeResult)
    {
        if (probeResult.success)
        {
            return QStringLiteral("%1=%2，来源=%3")
                .arg(probeNameText)
                .arg(probeResult.valueText)
                .arg(probeResult.sourceText.isEmpty() ? QStringLiteral("未标注") : probeResult.sourceText);
        }

        return QStringLiteral("%1失败，原因=%2")
            .arg(probeNameText)
            .arg(probeResult.reasonText.isEmpty() ? QStringLiteral("未提供原因。") : probeResult.reasonText);
    }

    // sensorReasonContainsAny:
    // - Search for any feature fragment in the probe diagnostic text;
    // - Parameter reasonText is the aggregated reason from PowerShell/CIM/Counter;
    // - Parameter markerTextList contains expected or hard-failure keywords to match.
    // - Returns true if at least one keyword matches; otherwise returns false.
    bool sensorReasonContainsAny(
        const QString& reasonText,
        const QStringList& markerTextList)
    {
        for (const QString& markerText : markerTextList)
        {
            if (!markerText.isEmpty() && reasonText.contains(markerText, Qt::CaseInsensitive))
            {
                return true;
            }
        }
        return false;
    }

    // sensorProbeHasExecutionFailure:
    // - Distinguish between 'script/permission/process execution failure' and 'hardware sensor source originally not existing'.
    // - Actual execution exceptions still require a WARN to avoid silently swallowing PowerShell timeouts or access denied errors.
    // - Returns true to indicate handling as an abnormal failure; returns false to indicate further evaluation for expected unavailability is required.
    bool sensorProbeHasExecutionFailure(const SensorProbeResult& probeResult)
    {
        const QString kDiagnosticText = probeResult.reasonText
            + QStringLiteral("\n")
            + probeResult.rawOutputText;
        static const QStringList kHardFailureMarkerList = {
            QStringLiteral("PowerShell启动失败"),
            QStringLiteral("PowerShell执行失败"),
            QStringLiteral("PowerShell执行超时"),
            QStringLiteral("脚本无输出"),
            QStringLiteral("脚本返回成功标记"),
            QStringLiteral("脚本仅返回"),
            QStringLiteral("拒绝访问"),
            QStringLiteral("Access denied"),
            QStringLiteral("RPC")
        };
        return sensorReasonContainsAny(kDiagnosticText, kHardFailureMarkerList);
    }

    // isExpectedCpuTemperatureUnavailable:
    // - Identify common Windows scenarios where CPU temperature cannot be exposed;
    // - Missing Libre/OpenHardwareMonitor namespaces, unsupported ACPI thermal zones, and thermal zone counters with no instances are all common.
    // - Returns true when the UI continues to display N/A, but the log should not be upgraded to WARN.
    bool isExpectedCpuTemperatureUnavailable(const SensorProbeResult& probeResult)
    {
        if (probeResult.success || probeResult.reasonText.isEmpty())
        {
            return false;
        }
        if (sensorProbeHasExecutionFailure(probeResult))
        {
            return false;
        }

        static const QStringList kExpectedTemperatureMarkerList = {
            QStringLiteral("Core Temp共享内存未打开"),
            QStringLiteral("无效命名空间"),
            QStringLiteral("Invalid namespace"),
            QStringLiteral("不支持"),
            QStringLiteral("Not supported"),
            QStringLiteral("指定的实例不存在"),
            QStringLiteral("does not exist"),
            QStringLiteral("未找到CPU温度传感器"),
            QStringLiteral("无热区数据"),
            QStringLiteral("读取值无效"),
            QStringLiteral("样本值无效"),
            QStringLiteral("无数据"),
            QStringLiteral("传感器存在但值无效"),
            QStringLiteral("热区值超出有效范围"),
            QStringLiteral("未找到可用温度来源")
        };
        return sensorReasonContainsAny(probeResult.reasonText, kExpectedTemperatureMarkerList);
    }

    // isExpectedCpuVoltageUnavailable:
    // - Identify common cases where Win32_Processor.CurrentVoltage is unavailable or unparseable.
    // - These values come from SMBIOS; many motherboards and virtualization environments do not provide actual core voltage.
    // - Returns true to display only N/A, avoiding misleading WARN output.
    bool isExpectedCpuVoltageUnavailable(const SensorProbeResult& probeResult)
    {
        if (probeResult.success || probeResult.reasonText.isEmpty())
        {
            return false;
        }
        if (sensorProbeHasExecutionFailure(probeResult))
        {
            return false;
        }

        static const QStringList kExpectedVoltageMarkerList = {
            QStringLiteral("CurrentVoltage"),
            QStringLiteral("无法解析"),
            QStringLiteral("未返回处理器对象"),
            QStringLiteral("WMIC path Win32_Processor: 无输出"),
            QStringLiteral("SMBIOS Type4"),
            QStringLiteral("SMBIOS RSMB")
        };
        return sensorReasonContainsAny(probeResult.reasonText, kExpectedVoltageMarkerList);
    }

    // queryCoreTempSharedMemoryProbeResult:
    // - Read the global shared memory CoreTempMappingObject exposed by Core Temp.
    // - CPU-Z and hardware monitoring tools typically rely on drivers or MSRs. When Windows WMI cannot read the data, such backends can be used.
    // Returns the maximum current core temperature on success; returns a structured reason on failure.
    SensorProbeResult queryCoreTempSharedMemoryProbeResult()
    {
        SensorProbeResult probeResult;
        HANDLE mappingHandle = ::OpenFileMappingW(
            FILE_MAP_READ,
            FALSE,
            L"Global\\CoreTempMappingObjectEx");
        if (mappingHandle == nullptr)
        {
            mappingHandle = ::OpenFileMappingW(
                FILE_MAP_READ,
                FALSE,
                L"CoreTempMappingObjectEx");
        }
        if (mappingHandle == nullptr)
        {
            mappingHandle = ::OpenFileMappingW(
                FILE_MAP_READ,
                FALSE,
                L"Global\\CoreTempMappingObject");
        }
        if (mappingHandle == nullptr)
        {
            mappingHandle = ::OpenFileMappingW(
                FILE_MAP_READ,
                FALSE,
                L"CoreTempMappingObject");
        }
        if (mappingHandle == nullptr)
        {
            probeResult.reasonText = QStringLiteral("Core Temp共享内存未打开。");
            return probeResult;
        }

        const void* mappedViewPointer = ::MapViewOfFile(
            mappingHandle,
            FILE_MAP_READ,
            0,
            0,
            sizeof(CoreTempSharedDataPrefix));
        if (mappedViewPointer == nullptr)
        {
            const DWORD kErrorCode = ::GetLastError();
            ::CloseHandle(mappingHandle);
            probeResult.reasonText = QStringLiteral("Core Temp共享内存映射失败，Win32错误=%1。")
                .arg(kErrorCode);
            return probeResult;
        }

        const CoreTempSharedDataPrefix* sharedDataPointer =
            static_cast<const CoreTempSharedDataPrefix*>(mappedViewPointer);
        const unsigned int kPackageCount = std::clamp(sharedDataPointer->uiCPUCnt, 1U, 128U);
        const unsigned int kCoreCount = std::clamp(sharedDataPointer->uiCoreCnt, 1U, 256U);
        const unsigned int kSampleCount = std::min(256U, std::max(kCoreCount, kPackageCount * kCoreCount));
        double maxTemperatureCelsius = -1000.0;
        for (unsigned int sampleIndex = 0; sampleIndex < kSampleCount; ++sampleIndex)
        {
            double valueCelsius = static_cast<double>(sharedDataPointer->fTemp[sampleIndex]);
            if (sharedDataPointer->ucFahrenheit != 0U)
            {
                valueCelsius = (valueCelsius - 32.0) * 5.0 / 9.0;
            }
            if (sharedDataPointer->ucDeltaToTjMax != 0U)
            {
                const unsigned int kTjMaxIndex = std::min(sampleIndex, 127U);
                const double kTjMaxValue = static_cast<double>(sharedDataPointer->uiTjMax[kTjMaxIndex]);
                if (kTjMaxValue > 0.0)
                {
                    valueCelsius = kTjMaxValue - valueCelsius;
                }
            }
            if (!std::isfinite(valueCelsius) || valueCelsius < -30.0 || valueCelsius > 130.0)
            {
                continue;
            }
            maxTemperatureCelsius = std::max(maxTemperatureCelsius, valueCelsius);
        }

        const QString kValueText = formatCelsiusSensorValue(maxTemperatureCelsius);
        if (isReadableSensorValue(kValueText))
        {
            probeResult.valueText = kValueText;
            probeResult.sourceText = QStringLiteral("Core Temp共享内存 / 核心最高温");
            probeResult.success = true;
        }
        else
        {
            probeResult.reasonText = QStringLiteral("Core Temp共享内存存在，但未得到有效核心温度样本。");
        }

        ::UnmapViewOfFile(mappedViewPointer);
        ::CloseHandle(mappingHandle);
        return probeResult;
    }

    // queryCpuTemperatureProbeResult:
    // - Queries the first available CPU temperature value (in °C).
    // - Fall back in the order: Libre/OpenHardwareMonitor -> CIM/WMI Thermal Zone -> Thermal Counter -> TemperatureProbe;
    // - Return structured reason text on failure.
    SensorProbeResult queryCpuTemperatureProbeResult()
    {
        SensorProbeResult coreTempProbeResult = queryCoreTempSharedMemoryProbeResult();
        if (coreTempProbeResult.success)
        {
            return coreTempProbeResult;
        }

        const QString kTemperatureScript = QStringLiteral(
            "$ErrorActionPreference='Stop'; "
            "function Add-Reason($list,[string]$reason){ if(-not [string]::IsNullOrWhiteSpace($reason)){ [void]$list.Add($reason) } }; "
            "function Format-Temp([double]$value){ "
            "  if([double]::IsNaN($value) -or [double]::IsInfinity($value)){ return $null }; "
            "  if($value -lt -30 -or $value -gt 130){ return $null }; "
            "  return ([math]::Round($value,1)).ToString() + '°C'; "
            "}; "
            "function Emit-Success([string]$value,[string]$source){ Write-Output ('OK|' + $value + '|' + $source); exit 0 }; "
            "function Test-CpuSensor($sensor){ "
            "  $name=[string]$sensor.Name; $identifier=[string]$sensor.Identifier; $hardwareName=[string]$sensor.HardwareName; "
            "  $text=($name + ' ' + $identifier + ' ' + $hardwareName); "
            "  if($text -match '(?i)cpu|processor|package|core|xeon|intel'){ return $true }; "
            "  if($identifier -match '(?i)/intelcpu|/cpu|/amdcpu'){ return $true }; "
            "  return $false; "
            "}; "
            "$reasons = New-Object 'System.Collections.Generic.List[string]'; "
            "foreach($serviceName in @('LibreHardwareMonitor','OpenHardwareMonitor','CoreTemp','HWiNFO64','HWiNFO32')){ "
            "  try { "
            "    $svc=Get-Service -Name $serviceName -ErrorAction SilentlyContinue; "
            "    if($null -ne $svc){ Add-Reason $reasons ('服务 ' + $serviceName + ': ' + [string]$svc.Status) } "
            "  } catch { } "
            "}; "
            "foreach($ns in @('root/LibreHardwareMonitor','root/OpenHardwareMonitor')){ "
            "  try { "
            "    $sensorRows=@(Get-CimInstance -Namespace $ns -ClassName Sensor -ErrorAction Stop); "
            "    $cpuTemps=@($sensorRows | Where-Object { "
            "      $_.SensorType -eq 'Temperature' -and "
            "      (Test-CpuSensor $_) "
            "    } | Sort-Object @{Expression={if($_.Name -match 'Package|CPU Package'){0}elseif($_.Name -match 'Core'){1}else{2}}}, Name); "
            "    if($cpuTemps.Count -le 0){ Add-Reason $reasons ('CIM ' + $ns + ': 未找到CPU温度传感器'); continue }; "
            "    foreach($sensor in $cpuTemps){ "
            "      $temp=Format-Temp ([double]$sensor.Value); "
            "      if($null -ne $temp){ Emit-Success $temp ('CIM ' + $ns + ' / ' + $sensor.Name) } "
            "    } "
            "    Add-Reason $reasons ('CIM ' + $ns + ': 传感器存在但值无效'); "
            "  } catch { Add-Reason $reasons ('CIM ' + $ns + ': ' + $_.Exception.Message) } "
            "}; "
            "foreach($ns in @('root/CIMV2','root/WMI')){ "
            "  foreach($className in @('Sensor','HardwareMonitor')){ "
            "    try { "
            "      $genericRows=@(Get-CimInstance -Namespace $ns -ClassName $className -ErrorAction Stop); "
            "      $genericTemps=@($genericRows | Where-Object { "
            "        (($_.SensorType -eq 'Temperature') -or ($_.Type -eq 'Temperature') -or ($_.Name -match '(?i)temperature|temp')) -and "
            "        (Test-CpuSensor $_) "
            "      }); "
            "      foreach($sensor in $genericTemps){ "
            "        $rawValue=$null; "
            "        if($null -ne $sensor.Value){ $rawValue=$sensor.Value } elseif($null -ne $sensor.CurrentValue){ $rawValue=$sensor.CurrentValue } elseif($null -ne $sensor.CurrentReading){ $rawValue=$sensor.CurrentReading }; "
            "        if($null -ne $rawValue){ "
            "          $temp=Format-Temp ([double]$rawValue); "
            "          if($null -ne $temp){ Emit-Success $temp ('CIM ' + $ns + ' / ' + $className + ' / ' + [string]$sensor.Name) } "
            "        } "
            "      } "
            "      if($genericRows.Count -gt 0){ Add-Reason $reasons ('CIM ' + $ns + '/' + $className + ': 未找到可用CPU温度值') } "
            "    } catch { } "
            "  } "
            "}; "
            "try { "
            "  $zoneRows=@(Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop); "
            "  if($zoneRows.Count -le 0){ Add-Reason $reasons 'CIM root/wmi: 无热区数据' }; "
            "  foreach($row in $zoneRows){ "
            "    $temp=Format-Temp ((([double]$row.CurrentTemperature)/10.0)-273.15); "
            "    if($null -ne $temp){ Emit-Success $temp 'CIM root/wmi / MSAcpi_ThermalZoneTemperature' } "
            "  } "
            "  Add-Reason $reasons 'CIM root/wmi: 热区值超出有效范围'; "
            "} catch { Add-Reason $reasons ('CIM root/wmi: ' + $_.Exception.Message) } "
            "try { "
            "  $zoneRows=@(Get-WmiObject -Namespace root\\wmi -Class MSAcpi_ThermalZoneTemperature -ErrorAction Stop); "
            "  if($zoneRows.Count -le 0){ Add-Reason $reasons 'WMI root\\\\wmi: 无热区数据' }; "
            "  foreach($row in $zoneRows){ "
            "    $temp=Format-Temp ((([double]$row.CurrentTemperature)/10.0)-273.15); "
            "    if($null -ne $temp){ Emit-Success $temp 'WMI root\\\\wmi / MSAcpi_ThermalZoneTemperature' } "
            "  } "
            "  Add-Reason $reasons 'WMI root\\\\wmi: 热区值超出有效范围'; "
            "} catch { Add-Reason $reasons ('WMI root\\\\wmi: ' + $_.Exception.Message) } "
            "foreach($counterPath in @('\\Thermal Zone Information(*)\\High Precision Temperature','\\Thermal Zone Information(*)\\Temperature')){ "
            "  try { "
            "    $samples=@((Get-Counter $counterPath -ErrorAction Stop).CounterSamples); "
            "    if($samples.Count -le 0){ Add-Reason $reasons ('Counter ' + $counterPath + ': 无实例'); continue }; "
            "    foreach($sample in $samples){ "
            "      $raw=[double]$sample.CookedValue; "
            "      if($raw -gt 200){ $raw=($raw/10.0)-273.15 }; "
            "      $temp=Format-Temp $raw; "
            "      if($null -ne $temp){ Emit-Success $temp ('Counter ' + $sample.Path) } "
            "    } "
            "    Add-Reason $reasons ('Counter ' + $counterPath + ': 样本值无效'); "
            "  } catch { Add-Reason $reasons ('Counter ' + $counterPath + ': ' + $_.Exception.Message) } "
            "}; "
            "try { "
            "  $probeRows=@(Get-CimInstance Win32_TemperatureProbe -ErrorAction Stop); "
            "  if($probeRows.Count -le 0){ Add-Reason $reasons 'CIM Win32_TemperatureProbe: 无数据' }; "
            "  foreach($probe in $probeRows){ "
            "    if($null -eq $probe.CurrentReading){ continue }; "
            "    $temp=Format-Temp ([double]$probe.CurrentReading); "
            "    if($null -ne $temp){ Emit-Success $temp 'CIM Win32_TemperatureProbe / CurrentReading' } "
            "  } "
            "  Add-Reason $reasons 'CIM Win32_TemperatureProbe: 读取值无效'; "
            "} catch { Add-Reason $reasons ('CIM Win32_TemperatureProbe: ' + $_.Exception.Message) } "
            "if($reasons.Count -le 0){ Add-Reason $reasons '未找到可用温度来源' }; "
            "Write-Output ('ERR|' + ($reasons -join ' || '));");
        SensorProbeResult probeResult = parseSensorProbeOutput(queryPowerShellTextSync(kTemperatureScript, 5200));
        if (!coreTempProbeResult.reasonText.isEmpty())
        {
            probeResult.reasonText = coreTempProbeResult.reasonText
                + QStringLiteral(" || ")
                + probeResult.reasonText;
        }
        if (isExpectedCpuTemperatureUnavailable(probeResult))
        {
            probeResult.expectedUnavailable = true;
            probeResult.reasonText = QStringLiteral(
                "当前系统未暴露CPU温度传感器；已保持N/A。"
                "CPU本身可能有DTS，但Windows WMI通常不直接暴露；"
                "请开启Core Temp共享内存、LibreHardwareMonitor或OpenHardwareMonitor的WMI后端。");
        }
        return probeResult;
    }

    // decodeSmbiosProcessorVoltageText:
    // - Decode the Voltage byte of Type 4 Processor Information according to the SMBIOS specification.
    // - When bit7 is set, the lower 7 bits represent 'current voltage × 10'; otherwise, the lower 3 bits represent the platform's nominal voltage capability bits.
    // - Returns an empty string to indicate that the byte does not carry usable voltage information.
    QString decodeSmbiosProcessorVoltageText(const unsigned char rawVoltage)
    {
        if (rawVoltage == 0U)
        {
            return QString();
        }
        if ((rawVoltage & 0x80U) != 0U)
        {
            // decodedVolts usage: Per SMBIOS specification, the lower 7 bits of this encoding represent the voltage value as a tenfold integer.
            const double kDecodedVolts = static_cast<double>(rawVoltage & 0x7FU) / 10.0;
            if (kDecodedVolts > 0.0)
            {
                return QString::number(kDecodedVolts, 'f', 2) + QStringLiteral("V");
            }
            return QString();
        }
        if ((rawVoltage & 0x01U) != 0U)
        {
            return QStringLiteral("5.0V");
        }
        if ((rawVoltage & 0x02U) != 0U)
        {
            return QStringLiteral("3.3V");
        }
        if ((rawVoltage & 0x04U) != 0U)
        {
            return QStringLiteral("2.9V");
        }
        return QString();
    }

    // SmbiosVoltageReadResult:
    // - Carries the conclusion of a direct SMBIOS read;
    // - tableReadable distinguishes between 'firmware table itself unreadable' and 'table readable but lacking usable voltage'; only the former requires fallback querying.
    struct SmbiosVoltageReadResult
    {
        SensorProbeResult probeResult;  // probeResult: A structured result consistent with other probes.
        bool tableReadable = false;     // tableReadable: Indicates whether the raw SMBIOS table was successfully retrieved.
    };

    // querySmbiosProcessorVoltageProbeResult:
    // - Directly read the SMBIOS raw table in this process and parse the Voltage field of the first central processor.
    // Win32_Processor.CurrentVoltage is already derived from this table; reading it directly avoids starting powershell.exe and the WMI/WMIC round-trip.
    // - This path takes microseconds, eliminating the possibility of PowerShell timeouts caused by periodic refresh triggers at the source.
    SmbiosVoltageReadResult querySmbiosProcessorVoltageProbeResult()
    {
        SmbiosVoltageReadResult readResult;

        // kRawSmbiosProvider usage: Big-endian integer representation of the firmware table provider signature 'RSMB'.
        constexpr DWORD kRawSmbiosProvider = 0x52534D42U;
        const UINT kRequiredSize = ::GetSystemFirmwareTable(kRawSmbiosProvider, 0, nullptr, 0);
        if (kRequiredSize == 0U)
        {
            readResult.probeResult.reasonText =
                QStringLiteral("SMBIOS RSMB: 固件表不可用，GetLastError=%1").arg(::GetLastError());
            return readResult;
        }

        std::vector<unsigned char> tableBuffer(static_cast<std::size_t>(kRequiredSize), 0U);
        const UINT kCopiedSize = ::GetSystemFirmwareTable(
            kRawSmbiosProvider,
            0,
            tableBuffer.data(),
            kRequiredSize);
        if (kCopiedSize == 0U || kCopiedSize > kRequiredSize)
        {
            readResult.probeResult.reasonText =
                QStringLiteral("SMBIOS RSMB: 表读取失败，GetLastError=%1").arg(::GetLastError());
            return readResult;
        }

        // Purpose of kRawSmbiosHeaderSize: the RawSMBIOSData header is fixed at 8 bytes (method/primary version/DMI revision + 4-byte length).
        constexpr std::size_t kRawSmbiosHeaderSize = 8U;
        if (static_cast<std::size_t>(kCopiedSize) <= kRawSmbiosHeaderSize)
        {
            readResult.probeResult.reasonText = QStringLiteral("SMBIOS RSMB: 表长度异常（%1 字节）。").arg(kCopiedSize);
            return readResult;
        }

        readResult.tableReadable = true;

        const unsigned char* tableBegin = tableBuffer.data() + kRawSmbiosHeaderSize;
        const std::size_t kTableSize = static_cast<std::size_t>(kCopiedSize) - kRawSmbiosHeaderSize;

        // rawVoltageFoundText: Preserve the raw value for diagnostics when the CPU structure exists but its bytes cannot be decoded.
        QString rawVoltageFoundText;
        std::size_t structureOffset = 0U;
        while (structureOffset + 4U <= kTableSize)
        {
            const unsigned char kStructureType = tableBegin[structureOffset];
            const unsigned char kFormattedLength = tableBegin[structureOffset + 1U];
            if (kFormattedLength < 4U || structureOffset + kFormattedLength > kTableSize)
            {
                break;
            }
            if (kStructureType == 127U)
            {
                // Type 127 = End-of-Table; subsequent content is invalid.
                break;
            }

            // Type 4 = Processor Information; offset 0x05 is processor type, 0x11 is Voltage.
            if (kStructureType == 4U && kFormattedLength > 0x11U && tableBegin[structureOffset + 0x05U] == 3U)
            {
                const unsigned char kRawVoltage = tableBegin[structureOffset + 0x11U];
                const QString kVoltageText = decodeSmbiosProcessorVoltageText(kRawVoltage);
                if (!kVoltageText.isEmpty())
                {
                    readResult.probeResult.valueText = kVoltageText;
                    readResult.probeResult.sourceText = QStringLiteral("SMBIOS Type4 / Processor Voltage");
                    readResult.probeResult.success = true;
                    return readResult;
                }
                if (rawVoltageFoundText.isEmpty())
                {
                    rawVoltageFoundText = QStringLiteral("0x%1")
                        .arg(QString::number(static_cast<unsigned int>(kRawVoltage), 16).toUpper());
                }
            }

            // The string area follows the formatted area and is terminated by two consecutive 0 bytes; an empty string area consists of exactly two zeros.
            std::size_t stringAreaCursor = structureOffset + kFormattedLength;
            while (stringAreaCursor + 1U < kTableSize
                && !(tableBegin[stringAreaCursor] == 0U && tableBegin[stringAreaCursor + 1U] == 0U))
            {
                ++stringAreaCursor;
            }
            structureOffset = stringAreaCursor + 2U;
        }

        if (!rawVoltageFoundText.isEmpty())
        {
            readResult.probeResult.reasonText =
                QStringLiteral("SMBIOS Type4: Voltage=%1 无法解析（固件未填写实际核心电压）。")
                .arg(rawVoltageFoundText);
            return readResult;
        }

        readResult.probeResult.reasonText = QStringLiteral("SMBIOS Type4: 未找到中央处理器结构。");
        return readResult;
    }

    // queryCpuVoltageProbeResultUncached:
    // - Query the first available CPU voltage value (unit: V);
    // - The primary path reads SMBIOS directly; it falls back to CIM queries only if the entire firmware table is unreadable.
    // - Support both SMBIOS bit flags and 10x voltage value encoding; return structured error text on failure.
    SensorProbeResult queryCpuVoltageProbeResultUncached()
    {
        const SmbiosVoltageReadResult kSmbiosReadResult = querySmbiosProcessorVoltageProbeResult();
        if (kSmbiosReadResult.probeResult.success)
        {
            return kSmbiosReadResult.probeResult;
        }
        if (kSmbiosReadResult.tableReadable)
        {
            // When the firmware table is read but no usable voltage is available, WMI/WMIC is merely a secondary translation of the
            // same byte; launching powershell.exe yields no new information and is the sole source of timeout alerts in local logs.
            SensorProbeResult probeResult = kSmbiosReadResult.probeResult;
            probeResult.expectedUnavailable = true;
            probeResult.reasonText = QStringLiteral(
                "当前系统未暴露CPU电压传感器；已保持N/A。"
                "SMBIOS Type4 Voltage 由固件填写，多数平台不提供实时核心电压。原始诊断：")
                + kSmbiosReadResult.probeResult.reasonText;
            return probeResult;
        }

        const QString kVoltageScript = QStringLiteral(
            "$ErrorActionPreference='Stop'; "
            "function Add-Reason($list,[string]$reason){ if(-not [string]::IsNullOrWhiteSpace($reason)){ [void]$list.Add($reason) } }; "
            // Win32_Processor.CurrentVoltage already strips the SMBIOS bit7 flag and directly provides the integer value
            // of "voltage × 10" (e.g., 0.8V corresponds to 8). Therefore, interpret it as a tenfold value first, and
            // only fall back to bit-based judgment for 5.0V/3.3V/2.9V when it falls within the nominal capability range.
            "function Format-Voltage([int]$raw){ "
            "  if($raw -le 0){ return $null }; "
            "  if(($raw -band 0x80) -ne 0){ "
            "    $decoded=(($raw -band 0x7F) / 10.0); "
            "    if($decoded -gt 0){ return ([math]::Round($decoded,2)).ToString('0.00') + 'V' } "
            "  }; "
            "  if($raw -ge 5 -and $raw -le 100){ "
            "    return ([math]::Round(($raw / 10.0),2)).ToString('0.00') + 'V'; "
            "  }; "
            "  if(($raw -band 0x1) -ne 0){ return '5.0V' }; "
            "  if(($raw -band 0x2) -ne 0){ return '3.3V' }; "
            "  if(($raw -band 0x4) -ne 0){ return '2.9V' }; "
            "  return $null; "
            "}; "
            "function Emit-Success([string]$value,[string]$source){ Write-Output ('OK|' + $value + '|' + $source); exit 0 }; "
            "$reasons = New-Object 'System.Collections.Generic.List[string]'; "
            "try { "
            "  $cpu=Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1; "
            "  if($null -eq $cpu){ Add-Reason $reasons 'CIM Win32_Processor: 未返回处理器对象' } "
            "  else { "
            "    $voltage=Format-Voltage ([uint16]$cpu.CurrentVoltage); "
            "    if($null -ne $voltage){ Emit-Success $voltage 'CIM Win32_Processor / CurrentVoltage' } "
            "    Add-Reason $reasons ('CIM Win32_Processor: CurrentVoltage=' + [string]$cpu.CurrentVoltage + ' 无法解析'); "
            "  } "
            "} catch { Add-Reason $reasons ('CIM Win32_Processor: ' + $_.Exception.Message) } "
            "if($reasons.Count -le 0){ Add-Reason $reasons '未找到可用电压来源' }; "
            "Write-Output ('ERR|' + ($reasons -join ' || '));");

        // Fallback path retains only the CIM branch:
        // - Get-WmiObject and wmic.exe read the same WMI data and cannot retrieve additional information.
        // - wmic.exe is an on-demand feature in newer Windows versions; its absence significantly increases overall execution time.
        // - After branch convergence, the single-process budget is relaxed to 9000 ms, allowing cold-start WMI queries to complete.
        SensorProbeResult probeResult = parseSensorProbeOutput(queryPowerShellTextSync(kVoltageScript, 9000));
        if (!kSmbiosReadResult.probeResult.reasonText.isEmpty())
        {
            probeResult.reasonText = kSmbiosReadResult.probeResult.reasonText
                + QStringLiteral(" || ")
                + probeResult.reasonText;
        }
        if (isExpectedCpuVoltageUnavailable(probeResult))
        {
            probeResult.expectedUnavailable = true;
            probeResult.reasonText = QStringLiteral(
                "当前系统未暴露CPU电压传感器；已保持N/A。"
                "Win32_Processor CurrentVoltage 常由SMBIOS决定，可能不是可读传感器。");
        }
        return probeResult;
    }

    // cpuVoltageProbeCacheMutex usage: Protects the voltage probe result cache; probing occurs on a background thread.
    // cpuVoltageProbeCacheValid: Marks whether a determined conclusion exists in the cache.
    // cpuVoltageProbeCacheResult: Stores the determined voltage probe conclusion.
    std::mutex cpuVoltageProbeCacheMutex;
    bool cpuVoltageProbeCacheValid = false;
    SensorProbeResult cpuVoltageProbeCacheResult;

    // queryCpuVoltageProbeResult:
    // - Provide cached CPU voltage probing externally.
    // - Voltage is read from the static SMBIOS table populated at firmware boot and does not change at runtime; refreshing every 5 seconds is unnecessary.
    // - Only cache definitive conclusions: 'read valid value' and 'platform confirmed not exposed'; execution failures are left for the next retry round.
    SensorProbeResult queryCpuVoltageProbeResult()
    {
        {
            const std::lock_guard<std::mutex> kCacheGuard(cpuVoltageProbeCacheMutex);
            if (cpuVoltageProbeCacheValid)
            {
                return cpuVoltageProbeCacheResult;
            }
        }

        const SensorProbeResult kProbeResult = queryCpuVoltageProbeResultUncached();
        if (kProbeResult.success || kProbeResult.expectedUnavailable)
        {
            const std::lock_guard<std::mutex> kCacheGuard(cpuVoltageProbeCacheMutex);
            cpuVoltageProbeCacheResult = kProbeResult;
            cpuVoltageProbeCacheValid = true;
        }
        return kProbeResult;
    }

    // HardwareDockCpuCounterBundle:
    // - Holds CPU-related PDH handles and failure status codes created by background threads.
    // - Stores only value types to facilitate easy re-injection to the UI thread for ownership, without involving any QWidget.
    struct HardwareDockCpuCounterBundle
    {
        void* cpuQueryHandle = nullptr;              // cpuQueryHandle: CPU query handle.
        std::vector<void*> coreCounterHandles;       // coreCounterHandles: Handles for the counter of each logical core.
        void* cpuPerformanceCounterHandle = nullptr; // cpuPerformanceCounterHandle: Handle for the processor performance percentage counter.
        void* cpuFrequencyCounterHandle = nullptr;   // cpuFrequencyCounterHandle: Handle to the processor base frequency counter.
        PDH_STATUS openQueryStatus = ERROR_SUCCESS;  // openQueryStatus: Return value from PdhOpenQueryW, used for failure logging.
    };

    // hardwareDockCpuCounterInitializing:
    // - Mark whether a background PDH initialization round is currently in progress.
    // - Prevent duplicate task dispatching during the per-second refresh while initialization is incomplete;
    std::atomic_bool hardwareDockCpuCounterInitializing{ false };

    // createHardwareDockCpuCounters:
    // - Input parameter coreCount: number of logical cores, determining how many \Processor(n) counters to register;
    // - Processing: Perform baseline collection after the calling thread completes PdhOpenQueryW/PdhAddEnglishCounterW.
    // - Return: Handle collection; failure fields remain nullptr for caller fallback on null handles.
    HardwareDockCpuCounterBundle createHardwareDockCpuCounters(const int coreCount)
    {
        HardwareDockCpuCounterBundle counterBundle;

        PDH_HQUERY queryHandle = nullptr;
        counterBundle.openQueryStatus = ::PdhOpenQueryW(nullptr, 0, &queryHandle);
        if (counterBundle.openQueryStatus != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return counterBundle;
        }

        const int kSafeCoreCount = std::max(0, coreCount);
        counterBundle.coreCounterHandles.reserve(static_cast<std::size_t>(kSafeCoreCount));
        for (int coreIndex = 0; coreIndex < kSafeCoreCount; ++coreIndex)
        {
            const QString kCounterPath = QStringLiteral("\\Processor(%1)\\% Processor Time").arg(coreIndex);
            PDH_HCOUNTER counterHandle = nullptr;
            const PDH_STATUS kAddStatus = ::PdhAddEnglishCounterW(
                queryHandle,
                reinterpret_cast<LPCWSTR>(kCounterPath.utf16()),
                0,
                &counterHandle);
            if (kAddStatus != ERROR_SUCCESS || counterHandle == nullptr)
            {
                // Placeholder nullptr when a core counter fails; subsequent sampling treats it as 0.
                counterBundle.coreCounterHandles.push_back(nullptr);
                continue;
            }
            counterBundle.coreCounterHandles.push_back(counterHandle);
        }

        // The 'speed' shown in Windows Task Manager cannot directly use ProcessorInformation.CurrentMhz:
        // On modern HWP/CPPC platforms, this is often fixed at the base frequency. Effective speed = Base frequency × Processor performance percentage.
        const auto kAddCpuTotalCounter =
            [queryHandle](const QString& counterPath, void** counterHandleOut)
            {
                if (counterHandleOut == nullptr)
                {
                    return;
                }
                PDH_HCOUNTER counterHandle = nullptr;
                const PDH_STATUS kAddStatus = ::PdhAddEnglishCounterW(
                    queryHandle,
                    reinterpret_cast<LPCWSTR>(counterPath.utf16()),
                    0,
                    &counterHandle);
                *counterHandleOut = kAddStatus == ERROR_SUCCESS ? counterHandle : nullptr;
            };
        kAddCpuTotalCounter(
            QStringLiteral("\\Processor Information(_Total)\\% Processor Performance"),
            &counterBundle.cpuPerformanceCounterHandle);
        kAddCpuTotalCounter(
            QStringLiteral("\\Processor Information(_Total)\\Processor Frequency"),
            &counterBundle.cpuFrequencyCounterHandle);

        ::PdhCollectQueryData(queryHandle);
        counterBundle.cpuQueryHandle = queryHandle;
        return counterBundle;
    }

    // closeHardwareDockCpuCounters:
    // - Input counterBundle: The collection of handles to be released.
    // - Processing: Close PDH queries; discard results if the control is destroyed or the handle was dropped in an earlier round.
    // - Returns: Nothing.
    void closeHardwareDockCpuCounters(const HardwareDockCpuCounterBundle& counterBundle)
    {
        if (counterBundle.cpuQueryHandle != nullptr)
        {
            ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(counterBundle.cpuQueryHandle));
        }
    }
}

HardwareDock::HardwareDock(QWidget* parent)
    : QWidget(parent)
{
    // Construction flow log: Helps locate the failure point during hardware page initialization.
    KLogEvent event;
    info << event << "[HardwareDock] 构造开始。" << eol;
    // The hardware page does not request a minimum size from the outer ADS layer; in narrow panels, internal charts actively compress.
    configureCompressibleWidget(this, QSizePolicy::Expanding, QSizePolicy::Expanding);

    initializeUi();
    initializeConnections();

    // Fill placeholder text during startup to prevent the window from freezing while waiting for the first frame of PowerShell execution.
    cachedOverviewStaticText_ = QStringLiteral("硬件概览加载中，请稍候...");
    cachedGpuStaticText_ = QStringLiteral("显卡信息加载中，请稍候...");
    cachedMemoryStaticText_ = QStringLiteral("内存信息加载中，请稍候...");
    cachedSensorText_ = QStringLiteral("N/A|N/A");
    if (cpuModelLabel_ != nullptr && !cpuModelText_.isEmpty())
    {
        cpuModelLabel_->setText(cpuModelText_);
    }

    refreshTimer_ = new QTimer(this);
    refreshTimer_->setInterval(1000);
    connect(refreshTimer_, &QTimer::timeout, this, [this]() {
        refreshAllViews();
    });

    info << event << "[HardwareDock] 构造完成。" << eol;
}

HardwareDock::~HardwareDock()
{
    if (refreshTimer_ != nullptr)
    {
        refreshTimer_->stop();
    }

    if (cpuPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(cpuPerfQueryHandle_));
        cpuPerfQueryHandle_ = nullptr;
        coreCounterHandles_.clear();
        cpuPerformanceCounterHandle_ = nullptr;
        cpuFrequencyCounterHandle_ = nullptr;
    }

    if (diskPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(diskPerfQueryHandle_));
        diskPerfQueryHandle_ = nullptr;
        diskReadCounterHandle_ = nullptr;
        diskWriteCounterHandle_ = nullptr;
    }

    if (gpuPerfQueryHandle_ != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(gpuPerfQueryHandle_));
        gpuPerfQueryHandle_ = nullptr;
        gpuCounterHandle_ = nullptr;
        gpuDedicatedMemoryCounterHandle_ = nullptr;
        gpuSharedMemoryCounterHandle_ = nullptr;
    }
}

void HardwareDock::resizeEvent(QResizeEvent* resizeEventPointer)
{
    QWidget::resizeEvent(resizeEventPointer);
    adjustUtilizationChartHeights();
}

bool HardwareDock::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    if (eventObject != nullptr
        && eventObject->type() == QEvent::MouseButtonRelease
        && utilizationBodySplitter_ != nullptr
        && watchedObject == utilizationBodySplitter_->handle(1))
    {
        // In non-opaque resize mode, release events arrive before the final child control layout; defer reading the
        // viewport width to the next event loop iteration to preserve the splitter size just submitted by the user.
        QTimer::singleShot(0, this, [this]()
        {
            adjustUtilizationChartHeights();
        });
    }

    return QWidget::eventFilter(watchedObject, eventObject);
}

void HardwareDock::showEvent(QShowEvent* showEventPointer)
{
    QWidget::showEvent(showEventPointer);

    // The R0 evidence page construction immediately triggers a driver query; the welcome page only reuses user-mode
    // performance sampling from this Dock, so this page must be delayed until the user actually opens the hardware Dock.
    if (r0EvidencePage_ == nullptr && sideTabWidget_ != nullptr)
    {
        initializeR0EvidenceTab();
    }

    startPerformanceSampling(true);

    // The splitter may not have its final width before the Dock is first displayed, so apply the 300px default
    // left column width in two rounds; once successful, do not overwrite subsequent user drag results.
    QTimer::singleShot(0, this, [this]()
    {
        applyInitialUtilizationSplitterSize();
    });
    QTimer::singleShot(80, this, [this]()
    {
        applyInitialUtilizationSplitterSize();
    });

    // During the initial display phase, perform staged re-layout to ensure the scroll area viewport height is stable.
    scheduleUtilizationLayoutRefresh();
}

void HardwareDock::startPerformanceSampling(const bool includeDriverHealth)
{
    driverHealthSamplingEnabled_ = includeDriverHealth;
    if (initialSamplingStarted_)
    {
        return;
    }

    initialSamplingStarted_ = true;
    startInitialSamplingAfterFirstPaint();
}

void HardwareDock::startInitialSamplingAfterFirstPaint()
{
    // safeThis usage: The Dock may be destroyed before the delayed task triggers; QPointer prevents dangling access.
    QPointer<HardwareDock> safeThis(this);

    // First sample delay: 80ms.
    // - Allows ADS Dock switching and placeholder UI to complete rendering first;
    // - Avoids blocking the click response chain with the initial latency of PDH/DXGI/Power API initialization.
    QTimer::singleShot(80, this, [safeThis]()
    {
        if (safeThis.isNull())
        {
            return;
        }

        HardwareDock* dockPointer = safeThis.data();
        if (dockPointer->coreChartEntries_.empty())
        {
            dockPointer->initializeCoreCharts();
        }
        dockPointer->initializePerformanceCounters();
        dockPointer->refreshCpuTopologyStaticInfo();
        dockPointer->refreshSystemVolumeInfo();
        dockPointer->refreshStaticHardwareTexts(false);
        dockPointer->refreshAllViews();
        dockPointer->requestAsyncStaticInfoRefresh();
        dockPointer->requestAsyncSensorRefresh();
        if (dockPointer->driverHealthSamplingEnabled_)
        {
            dockPointer->requestAsyncR0HardwareHealthRefresh();
        }

        if (dockPointer->refreshTimer_ != nullptr)
        {
            dockPointer->refreshTimer_->start();
        }
    });
}

void HardwareDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(6);

    // Top horizontal tabs:
    // - The outer layer is responsible only for hardware function classification and no longer occupies the left content width.
    // - Arrange tabs by content width; use scroll buttons when space is insufficient to avoid forcibly compressing text.
    // - User-visible names must use clear Chinese; internal protocol abbreviations should be placed in the page description.
    sideTabWidget_ = new QTabWidget(this);
    configureCompressibleWidget(sideTabWidget_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    sideTabWidget_->setTabPosition(QTabWidget::North);
    sideTabWidget_->setDocumentMode(true);
    sideTabWidget_->setUsesScrollButtons(true);
    sideTabWidget_->setElideMode(Qt::ElideNone);
    if (sideTabWidget_->tabBar() != nullptr)
    {
        sideTabWidget_->tabBar()->setExpanding(false);
        sideTabWidget_->tabBar()->setMovable(false);
    }
    rootLayout_->addWidget(sideTabWidget_, 1);

    // Tab order: Performance and Hardware Info -> Device Management -> Low-level Diagnostics.
    // First, register "performance monitoring" so that the Hardware Dock displays real-time data immediately upon its first opening.
    initializeUtilizationTab();
    initializeOverviewTab();
    initializeCpuTab();
    initializePowerTab();
    initializeGpuTab();
    initializeMemoryTab();
    initializeDiskMonitorTab();
    initializeDeviceManagerTab();
    initializeOtherDevicesTab();
    initializeHwidDispatchTab();
    initializeDeviceStackTab();
    initializeKeyboardMouseHidTab();
    initializeI8042AuditTab();
    initializeUsbTopologyTab();
    initializePnpAcpiPciTab();

    if (sideTabWidget_ != nullptr)
    {
        connect(
            sideTabWidget_,
            &QTabWidget::currentChanged,
            this,
            [this](const int tabIndexValue)
            {
                Q_UNUSED(tabIndexValue);
                if (sideTabWidget_ == nullptr || utilizationPage_ == nullptr)
                {
                    return;
                }

                QWidget* currentTabWidget = sideTabWidget_->currentWidget();
                if (currentTabWidget == diskMonitorHostPage_)
                {
                    // Disk monitoring will start ETW and process I/O scanning; it must be created only after the user actually enters this sub-page.
                    QTimer::singleShot(0, this, [this]()
                    {
                        ensureDiskMonitorTabInitialized();
                    });
                    return;
                }
                if (currentTabWidget == otherDevicesHostPage_)
                {
                    // The Other Devices tab enumerates PNP/Driver/Hardware lists; defer execution until the sub-page is first activated.
                    QTimer::singleShot(0, this, [this]()
                    {
                        ensureOtherDevicesTabInitialized();
                    });
                    return;
                }

                if (currentTabWidget == deviceStackPage_
                    || currentTabWidget == keyboardMouseHidPage_
                    || currentTabWidget == usbTopologyPage_
                    || currentTabWidget == pnpAcpiPciPage_)
                {
                    refreshStaticHardwareTexts(true);
                    return;
                }

                if (sideTabWidget_->currentWidget() != utilizationPage_)
                {
                    return;
                }
                // Refresh height when entering the 'Utilization' main page to fix the issue where the CPU sub-page was not properly expanded on first entry.
                scheduleUtilizationLayoutRefresh();
            });
    }
}

void HardwareDock::initializeOverviewTab()
{
    overviewPage_ = new QWidget(sideTabWidget_);
    overviewLayout_ = new QVBoxLayout(overviewPage_);
    overviewLayout_->setContentsMargins(4, 4, 4, 4);
    overviewLayout_->setSpacing(6);

    overviewSummaryLabel_ = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.overview.sampling"), QStringLiteral("采样中...")),
        overviewPage_);
    overviewSummaryLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    overviewLayout_->addWidget(overviewSummaryLabel_, 0);

    overviewEditor_ = new CodeEditorWidget(overviewPage_);
    overviewEditor_->setReadOnly(true);
    overviewLayout_->addWidget(overviewEditor_, 1);

    const int kTabIndex = sideTabWidget_->addTab(overviewPage_, QStringLiteral("硬件概览"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, overviewPage_, QStringLiteral("hardware.tab.overview"), QStringLiteral("硬件概览"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("查看处理器、内存、显卡和系统硬件摘要"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, overviewPage_, QStringLiteral("hardware.tooltip.overview"), QStringLiteral("查看处理器、内存、显卡和系统硬件摘要"));
}

void HardwareDock::initializeUtilizationTab()
{
    utilizationPage_ = new QWidget(sideTabWidget_);
    configureCompressibleWidget(utilizationPage_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(utilizationPage_);
    utilizationLayout_ = new QVBoxLayout(utilizationPage_);
    utilizationLayout_->setContentsMargins(4, 4, 4, 4);
    utilizationLayout_->setSpacing(6);

    // Task Manager style layout:
    // - Left side: performance navigation card list.
    // - The right side displays the detail page stack, switching with the left selection.
    utilizationBodySplitter_ = new QSplitter(Qt::Horizontal, utilizationPage_);
    utilizationBodySplitter_->setChildrenCollapsible(false);
    // Show only the rubber band during dragging without real-time reordering of the left cards; submit the new width all at once after release.
    utilizationBodySplitter_->setOpaqueResize(false);
    utilizationBodySplitter_->setHandleWidth(8);
    configureCompressibleWidget(
        utilizationBodySplitter_,
        QSizePolicy::Expanding,
        QSizePolicy::Expanding);
    utilizationLayout_->addWidget(utilizationBodySplitter_, 1);

    utilizationSidebarList_ = new QListWidget(utilizationPage_);
    utilizationSidebarList_->setFrameShape(QFrame::NoFrame);
    utilizationSidebarList_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // When the number of devices is large, do not continue compressing thumbnail cards to unreadable heights; instead, preserve card height and allow independent scrolling on the left.
    utilizationSidebarList_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    utilizationSidebarList_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    utilizationSidebarList_->setSelectionMode(QAbstractItemView::SingleSelection);
    utilizationSidebarList_->setSpacing(2);
    configureCompressibleWidget(utilizationSidebarList_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    utilizationSidebarList_->setMinimumWidth(140);
    utilizationSidebarList_->setStyleSheet(
        QStringLiteral(
            "QListWidget{border:none;background:transparent;}"
            "QListWidget::item{border:none;padding:0px;margin:0px;}"
            "QListWidget::item:selected{background:transparent;}"));
    appendTransparentBackgroundStyle(utilizationSidebarList_);
    utilizationBodySplitter_->addWidget(utilizationSidebarList_);

    utilizationDetailStack_ = new QStackedWidget(utilizationBodySplitter_);
    // The detail page content is shared by multiple sub-pages; the sizeHint of hidden sub-pages must not restrict the splitter in reverse.
    configureCompressibleWidget(utilizationDetailStack_, QSizePolicy::Ignored, QSizePolicy::Expanding);
    // Ensure the right-side details remain readable even if the left pane is dragged to a wider width; this defines
    // the splitter's maximum left-column boundary, rather than being indirectly determined by the card's sizeHint.
    utilizationDetailStack_->setMinimumWidth(360);
    appendTransparentBackgroundStyle(utilizationDetailStack_);
    utilizationBodySplitter_->addWidget(utilizationDetailStack_);
    if (QWidget* const kSplitterHandle = utilizationBodySplitter_->handle(1))
    {
        kSplitterHandle->installEventFilter(this);
    }
    utilizationBodySplitter_->setStretchFactor(0, 0);
    utilizationBodySplitter_->setStretchFactor(1, 1);
    // Provide available preset values first; after the first display, applyInitialUtilizationSplitterSize will calibrate
    // the left side to 300px based on the actual available splitter width, after which all user drag results are preserved.
    utilizationBodySplitter_->setSizes({ 300, 360 });

    initializeUtilizationCpuSubTab();
    initializeUtilizationMemorySubTab();
    initializeUtilizationDiskSubTab();
    initializeUtilizationNetworkSubTab();
    initializeUtilizationGpuSubTab();
    initializeUtilizationSidebarCards();

    connect(
        utilizationSidebarList_,
        &QListWidget::currentRowChanged,
        this,
        [this](const int rowIndex)
        {
            syncUtilizationSidebarSelection(rowIndex);
        });

    utilizationSidebarList_->setCurrentRow(0);
    syncUtilizationSidebarSelection(0);

    const int kTabIndex = sideTabWidget_->addTab(utilizationPage_, QStringLiteral("性能监控"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, utilizationPage_, QStringLiteral("hardware.tab.utilization"), QStringLiteral("性能监控"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("实时查看处理器、内存、磁盘、网络和显卡使用情况"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, utilizationPage_, QStringLiteral("hardware.tooltip.utilization"), QStringLiteral("实时查看处理器、内存、磁盘、网络和显卡使用情况"));
}

void HardwareDock::initializeUtilizationSidebarCards()
{
    if (utilizationSidebarList_ == nullptr)
    {
        return;
    }

    cpuNavCard_ = addUtilizationSidebarCard(
        utilizationCpuSubPage_,
        ks::i18n::contextText(QStringLiteral("hardware.utilization.card.cpu"), QStringLiteral("CPU")),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu),
        UtilizationDeviceKind::kCpu,
        -1);
    memoryNavCard_ = addUtilizationSidebarCard(
        utilizationMemorySubPage_,
        ks::i18n::contextText(QStringLiteral("hardware.utilization.card.memory"), QStringLiteral("内存")),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kMemory),
        UtilizationDeviceKind::kMemory,
        -1);
    // Disks, network adapters, and GPU devices no longer register fixed aggregate cards:
    // - Dynamically appended by ensure*UtilizationDevice after device discovery.
    // - This ensures that multiple disks, GPUs, and network cards each occupy a separate entry, similar to Task Manager.
    diskNavCard_ = nullptr;
    networkNavCard_ = nullptr;
    gpuNavCard_ = nullptr;

    if (memoryNavCard_ != nullptr)
    {
        memoryNavCard_->setSeriesColors(
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kMemory),
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kSharedMemory));
    }
}

PerformanceNavCard* HardwareDock::addUtilizationSidebarCard(
    QWidget* detailPage,
    const QString& titleText,
    const QColor& accentColor,
    const UtilizationDeviceKind kind,
    const int deviceIndex)
{
    if (utilizationSidebarList_ == nullptr)
    {
        return nullptr;
    }

    // itemPointer purpose: Holds the QListWidget row for the PerformanceNavCard.
    QListWidgetItem* itemPointer = new QListWidgetItem();
    // cardPointer usage: actually renders Task Manager-style thumbnail cards.
    PerformanceNavCard* cardPointer = new PerformanceNavCard(utilizationSidebarList_);
    cardPointer->setTitleText(titleText);
    cardPointer->setSubtitleText(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.card.sampling"),
            QStringLiteral("采样中...")));
    cardPointer->setAccentColor(accentColor);
    // Only the height is delegated to QListWidget management; the width is always determined by the viewport/splitter. Do not write the card's
    // recommended width into the item, or dragging the splitter will cause QListView to pull the splitter back in the opposite direction.
    itemPointer->setSizeHint(QSize(0, cardPointer->sizeHint().height()));
    utilizationSidebarList_->addItem(itemPointer);
    utilizationSidebarList_->setItemWidget(itemPointer, cardPointer);

    // navEntry purpose: Records the stable mapping between QListWidget row indices and QStackedWidget pages.
    UtilizationNavEntry navEntry;
    navEntry.navCard = cardPointer;
    navEntry.detailPage = detailPage;
    navEntry.kind = kind;
    navEntry.deviceIndex = deviceIndex;
    utilizationNavEntries_.push_back(navEntry);
    return cardPointer;
}

void HardwareDock::syncUtilizationSidebarSelection(const int selectedRowIndex)
{
    if (utilizationDetailStack_ == nullptr)
    {
        return;
    }

    const int kPageCount = utilizationDetailStack_->count();
    if (kPageCount <= 0)
    {
        return;
    }

    const int kEntryCount = static_cast<int>(utilizationNavEntries_.size());
    const int kBoundedRowIndex = kEntryCount > 0
        ? std::clamp(selectedRowIndex, 0, kEntryCount - 1)
        : std::clamp(selectedRowIndex, 0, kPageCount - 1);

    // targetPageIndex usage: Maps the left-side row number to the right-side stack's actual page index.
    int targetPageIndex = std::clamp(kBoundedRowIndex, 0, kPageCount - 1);
    if (kBoundedRowIndex >= 0 && kBoundedRowIndex < kEntryCount)
    {
        QWidget* targetPageWidget = utilizationNavEntries_[static_cast<std::size_t>(kBoundedRowIndex)].detailPage;
        if (targetPageWidget != nullptr)
        {
            const int kResolvedIndex = utilizationDetailStack_->indexOf(targetPageWidget);
            if (kResolvedIndex >= 0)
            {
                targetPageIndex = kResolvedIndex;
            }
        }
    }
    utilizationDetailStack_->setCurrentIndex(targetPageIndex);

    for (int entryIndex = 0; entryIndex < kEntryCount; ++entryIndex)
    {
        UtilizationNavEntry& entry = utilizationNavEntries_[static_cast<std::size_t>(entryIndex)];
        if (entry.navCard != nullptr)
        {
            entry.navCard->setSelectedState(entryIndex == kBoundedRowIndex);
        }
    }

    // Recalculate the large graph height immediately after option switching to avoid scrollbars appearing in the first frame.
    scheduleUtilizationLayoutRefresh();
}

void HardwareDock::applyInitialUtilizationSplitterSize()
{
    if (utilizationSplitterInitialSizeApplied_
        || utilizationBodySplitter_ == nullptr)
    {
        return;
    }

    const QList<int> kCurrentSizes = utilizationBodySplitter_->sizes();
    const int kAvailableWidth = kCurrentSizes.value(0) + kCurrentSizes.value(1);
    if (kAvailableWidth <= 0)
    {
        return;
    }

    const int kMaxLeftWidth = std::max(140, kAvailableWidth - 360);
    const int kLeftWidth = std::clamp(300, 140, kMaxLeftWidth);
    utilizationBodySplitter_->setSizes({ kLeftWidth, std::max(0, kAvailableWidth - kLeftWidth) });
    utilizationSplitterInitialSizeApplied_ = true;
    syncUtilizationSidebarCardWidths();
}

void HardwareDock::syncUtilizationSidebarCardWidths()
{
    if (utilizationSidebarList_ == nullptr)
    {
        return;
    }

    const int kCardWidth = utilizationSidebarList_->viewport()->width();
    if (kCardWidth <= 0)
    {
        return;
    }

    const QList<int> kSavedSplitterSizes = utilizationBodySplitter_ != nullptr
        ? utilizationBodySplitter_->sizes()
        : QList<int>();
    QList<int> boundedSplitterSizes = kSavedSplitterSizes;
    if (boundedSplitterSizes.size() == 2)
    {
        const int kAvailableWidth = boundedSplitterSizes.value(0) + boundedSplitterSizes.value(1);
        const int kMaxLeftWidth = std::max(140, kAvailableWidth - 360);
        const int kBoundedLeftWidth = std::clamp(
            boundedSplitterSizes.value(0),
            140,
            kMaxLeftWidth);
        boundedSplitterSizes = {
            kBoundedLeftWidth,
            std::max(0, kAvailableWidth - kBoundedLeftWidth) };
    }
    // QListWidget row width is always determined by the viewport; here we only fix the row height to avoid
    // writing the width obtained during the initial layout as an implicit minimum width for subsequent splitters.
    const QSize kNextSizeHint(0, 52);
    bool itemSizeChanged = false;

    for (int rowIndex = 0; rowIndex < utilizationSidebarList_->count(); ++rowIndex)
    {
        QListWidgetItem* const kItemPointer = utilizationSidebarList_->item(rowIndex);
        if (kItemPointer == nullptr || kItemPointer->sizeHint() == kNextSizeHint)
        {
            continue;
        }

        kItemPointer->setSizeHint(kNextSizeHint);
        itemSizeChanged = true;

        if (QWidget* const kCardWidget = utilizationSidebarList_->itemWidget(kItemPointer))
        {
            kCardWidget->setMinimumWidth(0);
            kCardWidget->setMaximumWidth(QWIDGETSIZE_MAX);
            kCardWidget->updateGeometry();
            kCardWidget->update();
        }
    }

    if (!itemSizeChanged
        || utilizationBodySplitter_ == nullptr
        || kSavedSplitterSizes.size() != 2)
    {
        return;
    }

    // QListWidget row width hints may trigger the parent splitter to reallocate; restore immediately and again
    // after layout events complete to ensure the user's actual dragged position is preserved upon release.
    utilizationBodySplitter_->setSizes(boundedSplitterSizes);
    QTimer::singleShot(0, this, [this, boundedSplitterSizes]()
    {
        if (utilizationBodySplitter_ != nullptr)
        {
            utilizationBodySplitter_->setSizes(boundedSplitterSizes);
        }
    });
}

void HardwareDock::adjustUtilizationChartHeights()
{
    // applyFixedHeightIfChanged:
    // - Writes the minimum/maximum height only if the target height changes, avoiding meaningless re-layouts that trigger recursive resize;
    // - widgetPointer: widget to set; heightValue: target fixed height (pixels);
    // - Return behavior: No return value; invalid heights are ignored.
    auto applyFixedHeightIfChanged =
        [](QWidget* widgetPointer, const int heightValue)
        {
            if (widgetPointer == nullptr || heightValue <= 0)
            {
                return;
            }
            if (widgetPointer->minimumHeight() == heightValue
                && widgetPointer->maximumHeight() == heightValue)
            {
                return;
            }
            widgetPointer->setMinimumHeight(heightValue);
            widgetPointer->setMaximumHeight(heightValue);
        };

    // applyMaxHeightIfChanged:
    // - Adjust only the maximum height; keep the minimum height at 0 to prevent the text area from expanding the parent layout in reverse.
    // - widgetPointer: target widget; maxHeightValue: target maximum height (in pixels);
    // - Return behavior: No return value; invalid heights are ignored.
    auto applyMaxHeightIfChanged =
        [](QWidget* widgetPointer, const int maxHeightValue)
        {
            if (widgetPointer == nullptr || maxHeightValue <= 0)
            {
                return;
            }
            if (widgetPointer->minimumHeight() == 0
                && widgetPointer->maximumHeight() == maxHeightValue)
            {
                return;
            }
            widgetPointer->setMinimumHeight(0);
            widgetPointer->setMaximumHeight(maxHeightValue);
        };

    // applyFixedWidthIfChanged:
    // - Write the minimum/maximum width only when the target width changes to prevent the CPU core grid factor control's sizeHint from re-stealing column width.
    // - widgetPointer: The control to be configured; widthValue: Target fixed width (pixels);
    // - Return behavior: no return value; invalid widths are ignored directly.
    auto applyFixedWidthIfChanged =
        [](QWidget* widgetPointer, const int widthValue)
        {
            if (widgetPointer == nullptr || widthValue <= 0)
            {
                return;
            }
            if (widgetPointer->minimumWidth() == widthValue
                && widgetPointer->maximumWidth() == widthValue)
            {
                return;
            }
            widgetPointer->setMinimumWidth(widthValue);
            widgetPointer->setMaximumWidth(widthValue);
        };

    // ===================== Left device list: shrink by width, scroll by height =====================
    if (utilizationPage_ != nullptr && utilizationSidebarList_ != nullptr)
    {
        // cardHeight usage: maintains the minimum readable height for thumbnails; list scrolling handles overflow in multi-disk/multi-NIC/GPU scenarios.
        if (utilizationSidebarList_->spacing() != 2)
        {
            utilizationSidebarList_->setSpacing(2);
        }
        syncUtilizationSidebarCardWidths();
    }

    // ===================== CPU Page: Dynamically compress width and height based on core grid =====================
    if (utilizationCpuSubPage_ != nullptr
        && coreChartHostWidget_ != nullptr
        && coreChartGridLayout_ != nullptr
        && !coreChartEntries_.empty())
    {
        // cpuReferenceHeight: Stabilizes the page height to prevent child controls' sizeHint from expanding the outer Dock.
        int cpuReferenceHeight = 0;
        if (utilizationDetailStack_ != nullptr)
        {
            cpuReferenceHeight = utilizationDetailStack_->contentsRect().height();
        }
        if (cpuReferenceHeight <= 0)
        {
            cpuReferenceHeight = utilizationCpuSubPage_->contentsRect().height();
        }
        if (cpuReferenceHeight <= 0)
        {
            cpuReferenceHeight = 240;
        }

        const int kTitleHeight = 72;
        const int kHeaderHeight = std::max(
            cpuModelLabel_ != nullptr ? cpuModelLabel_->height() : 0,
            kTitleHeight);
        const int kSummaryHeight = utilizationSummaryLabel_ != nullptr
            ? utilizationSummaryLabel_->sizeHint().height()
            : 16;
        const int kDetailHeight = std::max({
            cpuUtilPrimaryDetailLabel_ != nullptr ? cpuUtilPrimaryDetailLabel_->sizeHint().height() : 0,
            cpuUtilSecondaryDetailLabel_ != nullptr ? cpuUtilSecondaryDetailLabel_->sizeHint().height() : 0,
            cpuUtilTertiaryDetailLabel_ != nullptr ? cpuUtilTertiaryDetailLabel_->sizeHint().height() : 0
        });
        // Purpose of availableChartAreaHeight: usable height for the core chart; allows a very small height to ensure the page does not show scrollbars.
        const int kAvailableChartAreaHeight = std::max(
            1,
            cpuReferenceHeight - kHeaderHeight - kSummaryHeight - kDetailHeight - 42);
        const int kGridRows = std::max(1, cpuCoreGridRowCount_);
        const int kGridSpacing = std::max(0, coreChartGridLayout_->verticalSpacing());
        // cellHeight purpose: Height of each logical processor mini-card; compress further at low heights instead of letting the scrollbar take over.
        const int kCellHeight = std::max(
            1,
            (kAvailableChartAreaHeight - kGridSpacing * (kGridRows - 1)) / kGridRows);

        // cpuReferenceWidth usage:
        // - Use the current width of the scroll area viewport to prevent QGridLayout from expanding the first column based on QChartView/title sizeHint;
        // - The CPU core chart on the current page should not support horizontal scrolling; all columns are rearranged with the same width after the first frame and on resize.
        int cpuReferenceWidth = 0;
        if (coreChartScrollArea_ != nullptr && coreChartScrollArea_->viewport() != nullptr)
        {
            cpuReferenceWidth = coreChartScrollArea_->viewport()->contentsRect().width();
        }
        if (cpuReferenceWidth <= 0 && coreChartScrollArea_ != nullptr)
        {
            cpuReferenceWidth = coreChartScrollArea_->contentsRect().width();
        }
        if (cpuReferenceWidth <= 0)
        {
            cpuReferenceWidth = utilizationCpuSubPage_->contentsRect().width();
        }

        const int kGridColumns = std::max(1, cpuCoreGridColumnCount_);
        const int kHorizontalGridSpacing = std::max(0, coreChartGridLayout_->horizontalSpacing());
        const int kAvailableChartAreaWidth = std::max(1, cpuReferenceWidth);
        const int kCellWidth = std::max(
            1,
            (kAvailableChartAreaWidth - kHorizontalGridSpacing * (kGridColumns - 1)) / kGridColumns);
        const int kHostWidth = kGridColumns * kCellWidth + kHorizontalGridSpacing * (kGridColumns - 1);

        // Column width strategy description:
        // - QGridLayout defaults to referencing each child's sizeHint; QChartView may cause column 0 to widen rapidly after the first frame or data refresh.
        // - Sets column stretch, minimum column width, and fixed cell width simultaneously here to ensure even distribution across the viewport in 6-column scenarios.
        // - Reset surplus historical columns (residual after core count changes) to 0 to prevent old stretch values from participating in allocation.
        const int kLayoutColumnCount = std::max(kGridColumns, coreChartGridLayout_->columnCount());
        for (int columnIndex = 0; columnIndex < kLayoutColumnCount; ++columnIndex)
        {
            const bool kActiveColumn = columnIndex < kGridColumns;
            coreChartGridLayout_->setColumnStretch(columnIndex, kActiveColumn ? 1 : 0);
            coreChartGridLayout_->setColumnMinimumWidth(columnIndex, kActiveColumn ? kCellWidth : 0);
        }

        for (CoreChartEntry& chartEntry : coreChartEntries_)
        {
            if (chartEntry.containerWidget != nullptr)
            {
                applyFixedWidthIfChanged(chartEntry.containerWidget, kCellWidth);
                applyFixedHeightIfChanged(chartEntry.containerWidget, kCellHeight);
            }
            if (chartEntry.chartView != nullptr)
            {
                const int kTitleReserveHeight = chartEntry.titleLabel != nullptr
                    ? std::min(18, std::max(0, chartEntry.titleLabel->sizeHint().height()))
                    : 0;
                const int kChartHeight = std::max(1, kCellHeight - kTitleReserveHeight - kCpuCoreChartChromeReservePx);
                applyFixedHeightIfChanged(chartEntry.chartView, kChartHeight);
            }
        }

        const int kHostHeight = kGridRows * kCellHeight + kGridSpacing * (kGridRows - 1);
        applyFixedWidthIfChanged(coreChartHostWidget_, kHostWidth);
        applyFixedHeightIfChanged(coreChartHostWidget_, kHostHeight);
        if (coreChartScrollArea_ != nullptr)
        {
            // CPU core chart area fixed to available height; cells compressed when many cores exist, no scrollbars displayed.
            applyFixedHeightIfChanged(coreChartScrollArea_, kAvailableChartAreaHeight);
        }

        applyMaxHeightIfChanged(cpuUtilPrimaryDetailLabel_, std::max(1, cpuUtilPrimaryDetailLabel_ != nullptr ? cpuUtilPrimaryDetailLabel_->sizeHint().height() : 1));
        applyMaxHeightIfChanged(cpuUtilSecondaryDetailLabel_, std::max(1, cpuUtilSecondaryDetailLabel_ != nullptr ? cpuUtilSecondaryDetailLabel_->sizeHint().height() : 1));
        applyMaxHeightIfChanged(cpuUtilTertiaryDetailLabel_, std::max(1, cpuUtilTertiaryDetailLabel_ != nullptr ? cpuUtilTertiaryDetailLabel_->sizeHint().height() : 1));
    }

    // ===================== Other pages: compress main chart by page height ratio =====================
    auto adjustMainChartHeight =
        [](
            QWidget* pageWidget,
            QWidget* chartView,
            const double ratioValue,
            const int minHeightValue,
            const int reserveHeightValue)
        {
            if (pageWidget == nullptr || chartView == nullptr)
            {
                return;
            }
            const int kPageHeight = pageWidget->contentsRect().height();
            if (kPageHeight <= 0)
            {
                return;
            }
            const int kSafeMinHeight = std::max(1, minHeightValue);
            const int kMaxAllowedHeight = std::max(1, kPageHeight - reserveHeightValue);
            const int kExpectedHeight = static_cast<int>(std::round(static_cast<double>(kPageHeight) * ratioValue));
            const int kFinalHeight = std::clamp(kExpectedHeight, 1, kMaxAllowedHeight);
            const int kBoundedHeight = std::min(kFinalHeight, std::max(kSafeMinHeight, kMaxAllowedHeight));
            if (chartView->minimumHeight() != kBoundedHeight
                || chartView->maximumHeight() != kBoundedHeight)
            {
                chartView->setMinimumHeight(kBoundedHeight);
                chartView->setMaximumHeight(kBoundedHeight);
            }
        };

    adjustMainChartHeight(utilizationMemorySubPage_, memoryCompositionHistoryWidget_, 0.36, 24, 116);
    adjustMainChartHeight(utilizationDiskSubPage_, diskUtilChartView_, 0.40, 24, 120);
    adjustMainChartHeight(utilizationNetworkSubPage_, networkUtilChartView_, 0.40, 24, 120);

    applyMaxHeightIfChanged(memoryUtilPrimaryDetailLabel_, std::max(1, memoryUtilPrimaryDetailLabel_ != nullptr ? memoryUtilPrimaryDetailLabel_->sizeHint().height() : 1));
    applyMaxHeightIfChanged(memoryUtilSecondaryDetailLabel_, std::max(1, memoryUtilSecondaryDetailLabel_ != nullptr ? memoryUtilSecondaryDetailLabel_->sizeHint().height() : 1));
    applyMaxHeightIfChanged(diskUtilDetailLabel_, std::max(1, diskUtilDetailLabel_ != nullptr ? diskUtilDetailLabel_->sizeHint().height() : 1));
    applyMaxHeightIfChanged(networkUtilDetailLabel_, std::max(1, networkUtilDetailLabel_ != nullptr ? networkUtilDetailLabel_->sizeHint().height() : 1));
    for (DiskUtilizationDevice& device : diskUtilDevices_)
    {
        adjustMainChartHeight(device.pageWidget, device.chartView, 0.40, 24, 120);
        if (device.detailLabel != nullptr)
        {
            applyMaxHeightIfChanged(device.detailLabel, std::max(1, device.detailLabel->sizeHint().height()));
        }
    }
    for (NetworkUtilizationDevice& device : networkUtilDevices_)
    {
        adjustMainChartHeight(device.pageWidget, device.chartView, 0.40, 24, 120);
        if (device.detailLabel != nullptr)
        {
            applyMaxHeightIfChanged(device.detailLabel, std::max(1, device.detailLabel->sizeHint().height()));
        }
    }

    // GPU page: All four engine graphs and two VRAM curves are dynamically compressed.
    if (utilizationGpuSubPage_ != nullptr)
    {
        // gpuReferenceHeight usage: Reference height for GPU sub-page layout; prioritizes the visible stack area to prevent self-feedback height increase.
        int gpuReferenceHeight = 0;
        if (utilizationDetailStack_ != nullptr)
        {
            gpuReferenceHeight = utilizationDetailStack_->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = utilizationGpuSubPage_->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = 320;
        }

        const int kTitleHeight = std::max(
            gpuAdapterTitleLabel_ != nullptr ? gpuAdapterTitleLabel_->sizeHint().height() : 0,
            58);
        const int kSummaryHeight = gpuUtilSummaryLabel_ != nullptr
            ? gpuUtilSummaryLabel_->sizeHint().height()
            : 20;
        const int kDetailHeight = gpuUtilDetailLabel_ != nullptr
            ? gpuUtilDetailLabel_->sizeHint().height()
            : 22;
        // reservedHeight: Reserved height for the non-chart area of the GPU page (including layout spacing and top/bottom margins).
        const int kReservedHeight = kTitleHeight + kSummaryHeight + kDetailHeight + 38;
        const int kAvailableHeight = std::max(1, gpuReferenceHeight - kReservedHeight);

        // engineAreaHeight usage: Height allocated for the 2x2 engine diagram area.
        const int kEngineAreaHeight = std::max(
            1,
            static_cast<int>(std::round(static_cast<double>(kAvailableHeight) * 0.52)));
        const int kMemoryAreaEachHeight = std::max(1, (kAvailableHeight - kEngineAreaHeight - 8) / 2);
        if (gpuEngineHostWidget_ != nullptr && gpuEngineGridLayout_ != nullptr)
        {
            const int kRowSpacing = std::max(0, gpuEngineGridLayout_->verticalSpacing());
            const int kCellHeight = std::max(1, (kEngineAreaHeight - kRowSpacing) / 2);
            for (GpuEngineChartEntry& chartEntry : gpuEngineCharts_)
            {
                if (chartEntry.chartView != nullptr)
                {
                    applyMaxHeightIfChanged(chartEntry.chartView, std::max(1, kCellHeight - 10));
                }
                if (chartEntry.titleLabel != nullptr)
                {
                    chartEntry.titleLabel->setMinimumHeight(0);
                    chartEntry.titleLabel->setMaximumHeight(18);
                }
            }
            applyMaxHeightIfChanged(gpuEngineHostWidget_, kEngineAreaHeight);
        }

        if (gpuDedicatedMemoryChartView_ != nullptr)
        {
            applyMaxHeightIfChanged(gpuDedicatedMemoryChartView_, kMemoryAreaEachHeight);
        }
        if (gpuSharedMemoryChartView_ != nullptr)
        {
            applyMaxHeightIfChanged(gpuSharedMemoryChartView_, kMemoryAreaEachHeight);
        }
        if (gpuUtilDetailLabel_ != nullptr)
        {
            applyMaxHeightIfChanged(gpuUtilDetailLabel_, std::max(1, gpuUtilDetailLabel_->sizeHint().height()));
        }
    }
    for (GpuUtilizationDevice& device : gpuUtilDevices_)
    {
        if (device.pageWidget == nullptr)
        {
            continue;
        }

        // gpuReferenceHeight usage: the current stable height for multi-GPU sub-pages.
        int gpuReferenceHeight = 0;
        if (utilizationDetailStack_ != nullptr)
        {
            gpuReferenceHeight = utilizationDetailStack_->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            gpuReferenceHeight = device.pageWidget->contentsRect().height();
        }
        if (gpuReferenceHeight <= 0)
        {
            continue;
        }

        const int kLayoutSpacing = 6;
        const int kHeaderHeight = 58;
        const int kSummaryHeight = device.summaryLabel != nullptr
            ? device.summaryLabel->sizeHint().height()
            : 0;
        const int kDetailHeight = device.detailLabel != nullptr
            ? device.detailLabel->sizeHint().height()
            : 0;
        const int kReservedHeight = kHeaderHeight + kSummaryHeight + kDetailHeight + kLayoutSpacing * 7 + 12;
        const int kGraphAreaHeight = std::max(1, gpuReferenceHeight - kReservedHeight);
        const int kEngineAreaHeight = std::max(1, kGraphAreaHeight / 2);
        const int kMemoryAreaEachHeight = std::max(1, kGraphAreaHeight / 4);

        if (device.engineHostWidget != nullptr && device.engineGridLayout != nullptr)
        {
            const int kRowSpacing = std::max(0, device.engineGridLayout->verticalSpacing());
            const int kCellHeight = std::max(1, (kEngineAreaHeight - kRowSpacing) / 2);
            for (GpuEngineChartEntry& chartEntry : device.engineCharts)
            {
                if (chartEntry.chartView != nullptr)
                {
                    applyMaxHeightIfChanged(chartEntry.chartView, std::max(1, kCellHeight - 14));
                }
                if (chartEntry.titleLabel != nullptr)
                {
                    chartEntry.titleLabel->setMinimumHeight(0);
                    chartEntry.titleLabel->setMaximumHeight(18);
                }
            }
            applyMaxHeightIfChanged(device.engineHostWidget, kEngineAreaHeight);
        }
        applyMaxHeightIfChanged(device.dedicatedMemoryChartView, kMemoryAreaEachHeight);
        applyMaxHeightIfChanged(device.sharedMemoryChartView, kMemoryAreaEachHeight);
        if (device.detailLabel != nullptr)
        {
            applyMaxHeightIfChanged(device.detailLabel, std::max(1, device.detailLabel->sizeHint().height()));
        }
    }
}

void HardwareDock::initializeUtilizationCpuSubTab()
{
    utilizationCpuSubPage_ = new QWidget(utilizationDetailStack_);
    configureCompressibleWidget(utilizationCpuSubPage_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(utilizationCpuSubPage_);
    QVBoxLayout* cpuSubLayout = new QVBoxLayout(utilizationCpuSubPage_);
    cpuSubLayout->setContentsMargins(4, 4, 4, 4);
    cpuSubLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.cpu.title"), QStringLiteral("CPU")),
        utilizationCpuSubPage_);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    cpuModelLabel_ = new QLabel(QStringLiteral("检测中..."), utilizationCpuSubPage_);
    configurePersistentHeaderLabel(cpuModelLabel_);
    cpuModelLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    cpuModelLabel_->setStyleSheet(
        QStringLiteral("font-size:15px;font-weight:500;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(cpuModelLabel_, 6);
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(cpuModelLabel_, 0);
    cpuSubLayout->addLayout(headerLayout, 0);

    utilizationSummaryLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.summary.initial"),
            QStringLiteral("30 秒内的利用率 %")),
        utilizationCpuSubPage_);
    configureCompressibleLabel(utilizationSummaryLabel_);
    utilizationSummaryLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    cpuSubLayout->addWidget(utilizationSummaryLabel_, 0);

    coreChartScrollArea_ = new QScrollArea(utilizationCpuSubPage_);
    coreChartScrollArea_->setWidgetResizable(true);
    coreChartScrollArea_->setFrameShape(QFrame::NoFrame);
    // Compress the grid when there are many cores; do not display internal scrollbars.
    coreChartScrollArea_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    coreChartScrollArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    coreChartScrollArea_->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
    configureCompressibleWidget(coreChartScrollArea_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(coreChartScrollArea_);
    coreChartHostWidget_ = new QWidget(coreChartScrollArea_);
    configureCompressibleWidget(coreChartHostWidget_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(coreChartHostWidget_);
    coreChartGridLayout_ = new QGridLayout(coreChartHostWidget_);
    coreChartGridLayout_->setContentsMargins(0, 0, 0, 0);
    coreChartGridLayout_->setHorizontalSpacing(kCpuCoreChartGridSpacingPx);
    coreChartGridLayout_->setVerticalSpacing(kCpuCoreChartGridSpacingPx);
    // coreChartPlaceholderLabel usage: Temporarily replaces multiple QChartView instances before the first frame to avoid creating per-core charts all at once when constructing the hardware page.
    QLabel* coreChartPlaceholderLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.chart_placeholder"),
            QStringLiteral("CPU 核心图将在首帧后加载...")),
        coreChartHostWidget_);
    coreChartPlaceholderLabel->setAlignment(Qt::AlignCenter);
    coreChartPlaceholderLabel->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;")
        .arg(ksword_theme::textSecondaryHex()));
    coreChartGridLayout_->addWidget(coreChartPlaceholderLabel, 0, 0, 1, 1);
    coreChartScrollArea_->setWidget(coreChartHostWidget_);
    cpuSubLayout->addWidget(coreChartScrollArea_, 1);

    QHBoxLayout* detailLayout = new QHBoxLayout();
    detailLayout->setSpacing(16);
    cpuUtilPrimaryDetailLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.detail.primary_sampling"),
            QStringLiteral("CPU 详情采样中...")),
        utilizationCpuSubPage_);
    cpuUtilSecondaryDetailLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.detail.secondary_sampling"),
            QStringLiteral("硬件参数读取中...")),
        utilizationCpuSubPage_);
    cpuUtilTertiaryDetailLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.cpu.detail.tertiary_sampling"),
            QStringLiteral("缓存与 R0 状态读取中...")),
        utilizationCpuSubPage_);
    configureCompressibleLabel(cpuUtilPrimaryDetailLabel_);
    configureCompressibleLabel(cpuUtilSecondaryDetailLabel_);
    configureCompressibleLabel(cpuUtilTertiaryDetailLabel_);
    cpuUtilPrimaryDetailLabel_->setWordWrap(false);
    cpuUtilSecondaryDetailLabel_->setWordWrap(false);
    cpuUtilTertiaryDetailLabel_->setWordWrap(false);
    cpuUtilPrimaryDetailLabel_->setTextFormat(Qt::RichText);
    cpuUtilPrimaryDetailLabel_->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    cpuUtilSecondaryDetailLabel_->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    cpuUtilTertiaryDetailLabel_->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    cpuUtilPrimaryDetailLabel_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    cpuUtilSecondaryDetailLabel_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    cpuUtilTertiaryDetailLabel_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    detailLayout->addWidget(cpuUtilPrimaryDetailLabel_, 5);
    detailLayout->addWidget(cpuUtilSecondaryDetailLabel_, 3);
    detailLayout->addWidget(cpuUtilTertiaryDetailLabel_, 3);
    cpuSubLayout->addLayout(detailLayout, 0);

    utilizationDetailStack_->addWidget(utilizationCpuSubPage_);
}

void HardwareDock::initializeUtilizationMemorySubTab()
{
    utilizationMemorySubPage_ = new QWidget(utilizationDetailStack_);
    configureCompressibleWidget(utilizationMemorySubPage_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(utilizationMemorySubPage_);
    QVBoxLayout* memorySubLayout = new QVBoxLayout(utilizationMemorySubPage_);
    memorySubLayout->setContentsMargins(4, 4, 4, 4);
    memorySubLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.memory.title"), QStringLiteral("内存")),
        utilizationMemorySubPage_);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    memoryCapacityLabel_ = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.memory.capacity_sampling"), QStringLiteral("读取中...")),
        utilizationMemorySubPage_);
    configurePersistentHeaderLabel(memoryCapacityLabel_, QSizePolicy::Ignored);
    memoryCapacityLabel_->setStyleSheet(
        QStringLiteral("font-size:31px;font-weight:500;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(memoryCapacityLabel_, 8);
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(memoryCapacityLabel_, 0);
    memorySubLayout->addLayout(headerLayout, 0);

    memoryUtilSummaryLabel_ = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.memory.summary.initial"), QStringLiteral("内存使用量")),
        utilizationMemorySubPage_);
    configureCompressibleLabel(memoryUtilSummaryLabel_);
    memoryUtilSummaryLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    memorySubLayout->addWidget(memoryUtilSummaryLabel_, 0);

    memoryCompositionHistoryWidget_ = new MemoryCompositionHistoryWidget(utilizationMemorySubPage_);
    configureCompressibleWidget(memoryCompositionHistoryWidget_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    memorySubLayout->addWidget(memoryCompositionHistoryWidget_, 1);

    QHBoxLayout* detailLayout = new QHBoxLayout();
    detailLayout->setSpacing(16);
    memoryUtilPrimaryDetailLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.memory.detail.primary_sampling"),
            QStringLiteral("内存参数采样中...")),
        utilizationMemorySubPage_);
    memoryUtilSecondaryDetailLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.memory.detail.secondary_sampling"),
            QStringLiteral("硬件参数读取中...")),
        utilizationMemorySubPage_);
    configureCompressibleLabel(memoryUtilPrimaryDetailLabel_);
    configureCompressibleLabel(memoryUtilSecondaryDetailLabel_);
    memoryUtilPrimaryDetailLabel_->setWordWrap(false);
    memoryUtilSecondaryDetailLabel_->setWordWrap(false);
    memoryUtilPrimaryDetailLabel_->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    memoryUtilSecondaryDetailLabel_->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    detailLayout->addWidget(memoryUtilPrimaryDetailLabel_, 1);
    detailLayout->addWidget(memoryUtilSecondaryDetailLabel_, 1);
    memorySubLayout->addLayout(detailLayout, 0);

    utilizationDetailStack_->addWidget(utilizationMemorySubPage_);
}

void HardwareDock::initializeUtilizationDiskSubTab()
{
    utilizationDiskSubPage_ = new QWidget(utilizationDetailStack_);
    configureCompressibleWidget(utilizationDiskSubPage_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(utilizationDiskSubPage_);
    QVBoxLayout* diskSubLayout = new QVBoxLayout(utilizationDiskSubPage_);
    diskSubLayout->setContentsMargins(4, 4, 4, 4);
    diskSubLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.disk.title"), QStringLiteral("磁盘")),
        utilizationDiskSubPage_);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    diskSubLayout->addWidget(titleLabel, 0);

    diskUtilSummaryLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.disk.sampling"),
            QStringLiteral("磁盘采样初始化中...")),
        utilizationDiskSubPage_);
    configureCompressibleLabel(diskUtilSummaryLabel_);
    diskUtilSummaryLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    diskSubLayout->addWidget(diskUtilSummaryLabel_, 0);

    diskReadLineSeries_ = new QLineSeries(utilizationDiskSubPage_);
    diskReadLineSeries_->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.disk.read"), QStringLiteral("读取")));
    const QColor kDiskReadColor(80, 170, 255);
    const QColor kDiskWriteColor(255, 190, 105);
    diskReadLineSeries_->setColor(kDiskReadColor);
    diskReadBaselineSeries_ = createBaselineSeries(utilizationDiskSubPage_, historyLength_);
    diskWriteLineSeries_ = new QLineSeries(utilizationDiskSubPage_);
    diskWriteLineSeries_->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.disk.write"), QStringLiteral("写入")));
    diskWriteLineSeries_->setColor(kDiskWriteColor);
    diskWriteBaselineSeries_ = createBaselineSeries(utilizationDiskSubPage_, historyLength_);
    initializeLineSeriesHistory(diskReadLineSeries_, historyLength_);
    initializeLineSeriesHistory(diskWriteLineSeries_, historyLength_);

    QChart* diskChart = new QChart();
    diskReadAreaSeries_ = addFilledAreaSeries(
        diskChart,
        diskReadLineSeries_,
        diskReadBaselineSeries_,
        kDiskReadColor,
        42);
    diskWriteAreaSeries_ = addFilledAreaSeries(
        diskChart,
        diskWriteLineSeries_,
        diskWriteBaselineSeries_,
        kDiskWriteColor,
        34);
    configureUtilizationPlotChart(
        diskChart,
        kDiskReadColor,
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.disk.chart_title"),
            QStringLiteral("磁盘读写速率趋势")),
        true);

    diskUtilAxisX_ = new QValueAxis(diskChart);
    configureUtilizationValueAxis(diskUtilAxisX_, kDiskReadColor, 0.0, static_cast<double>(historyLength_));

    diskUtilAxisY_ = new QValueAxis(diskChart);
    configureUtilizationValueAxis(diskUtilAxisY_, kDiskReadColor, 0.0, 1.0);

    diskChart->addAxis(diskUtilAxisX_, Qt::AlignBottom);
    diskChart->addAxis(diskUtilAxisY_, Qt::AlignLeft);
    if (diskReadAreaSeries_ != nullptr)
    {
        diskReadAreaSeries_->attachAxis(diskUtilAxisX_);
        diskReadAreaSeries_->attachAxis(diskUtilAxisY_);
    }
    if (diskWriteAreaSeries_ != nullptr)
    {
        diskWriteAreaSeries_->attachAxis(diskUtilAxisX_);
        diskWriteAreaSeries_->attachAxis(diskUtilAxisY_);
    }

    diskUtilChartView_ = createPlotBackgroundChartView(diskChart, utilizationDiskSubPage_);
    diskSubLayout->addWidget(diskUtilChartView_, 1);

    diskUtilDetailLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.disk.detail_sampling"),
            QStringLiteral("磁盘参数采样中...")),
        utilizationDiskSubPage_);
    configureCompressibleLabel(diskUtilDetailLabel_);
    diskUtilDetailLabel_->setWordWrap(false);
    diskUtilDetailLabel_->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    diskSubLayout->addWidget(diskUtilDetailLabel_, 0);

    utilizationDetailStack_->addWidget(utilizationDiskSubPage_);
}

void HardwareDock::initializeUtilizationNetworkSubTab()
{
    utilizationNetworkSubPage_ = new QWidget(utilizationDetailStack_);
    configureCompressibleWidget(utilizationNetworkSubPage_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(utilizationNetworkSubPage_);
    QVBoxLayout* networkSubLayout = new QVBoxLayout(utilizationNetworkSubPage_);
    networkSubLayout->setContentsMargins(4, 4, 4, 4);
    networkSubLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.network.title"), QStringLiteral("以太网")),
        utilizationNetworkSubPage_);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    networkSubLayout->addWidget(titleLabel, 0);

    networkUtilSummaryLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.network.sampling"),
            QStringLiteral("网络采样初始化中...")),
        utilizationNetworkSubPage_);
    configureCompressibleLabel(networkUtilSummaryLabel_);
    networkUtilSummaryLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    networkSubLayout->addWidget(networkUtilSummaryLabel_, 0);

    networkRxLineSeries_ = new QLineSeries(utilizationNetworkSubPage_);
    networkRxLineSeries_->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.network.down"), QStringLiteral("下行")));
    const QColor kNetworkRxColor(92, 190, 255);
    const QColor kNetworkTxColor(153, 129, 255);
    networkRxLineSeries_->setColor(kNetworkRxColor);
    networkRxBaselineSeries_ = createBaselineSeries(utilizationNetworkSubPage_, historyLength_);
    networkTxLineSeries_ = new QLineSeries(utilizationNetworkSubPage_);
    networkTxLineSeries_->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.network.up"), QStringLiteral("上行")));
    networkTxLineSeries_->setColor(kNetworkTxColor);
    networkTxBaselineSeries_ = createBaselineSeries(utilizationNetworkSubPage_, historyLength_);
    initializeLineSeriesHistory(networkRxLineSeries_, historyLength_);
    initializeLineSeriesHistory(networkTxLineSeries_, historyLength_);

    QChart* networkChart = new QChart();
    networkRxAreaSeries_ = addFilledAreaSeries(
        networkChart,
        networkRxLineSeries_,
        networkRxBaselineSeries_,
        kNetworkRxColor,
        42);
    networkTxAreaSeries_ = addFilledAreaSeries(
        networkChart,
        networkTxLineSeries_,
        networkTxBaselineSeries_,
        kNetworkTxColor,
        34);
    configureUtilizationPlotChart(
        networkChart,
        kNetworkRxColor,
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.network.chart_title"),
            QStringLiteral("网络收发速率趋势")),
        true);

    networkUtilAxisX_ = new QValueAxis(networkChart);
    configureUtilizationValueAxis(networkUtilAxisX_, kNetworkRxColor, 0.0, static_cast<double>(historyLength_));

    networkUtilAxisY_ = new QValueAxis(networkChart);
    configureUtilizationValueAxis(networkUtilAxisY_, kNetworkRxColor, 0.0, 1.0);

    networkChart->addAxis(networkUtilAxisX_, Qt::AlignBottom);
    networkChart->addAxis(networkUtilAxisY_, Qt::AlignLeft);
    if (networkRxAreaSeries_ != nullptr)
    {
        networkRxAreaSeries_->attachAxis(networkUtilAxisX_);
        networkRxAreaSeries_->attachAxis(networkUtilAxisY_);
    }
    if (networkTxAreaSeries_ != nullptr)
    {
        networkTxAreaSeries_->attachAxis(networkUtilAxisX_);
        networkTxAreaSeries_->attachAxis(networkUtilAxisY_);
    }

    networkUtilChartView_ = createPlotBackgroundChartView(networkChart, utilizationNetworkSubPage_);
    networkSubLayout->addWidget(networkUtilChartView_, 1);

    networkUtilDetailLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.network.detail_sampling"),
            QStringLiteral("网络参数采样中...")),
        utilizationNetworkSubPage_);
    configureCompressibleLabel(networkUtilDetailLabel_);
    networkUtilDetailLabel_->setWordWrap(false);
    networkUtilDetailLabel_->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    networkSubLayout->addWidget(networkUtilDetailLabel_, 0);

    utilizationDetailStack_->addWidget(utilizationNetworkSubPage_);
}

void HardwareDock::initializeUtilizationGpuSubTab()
{
    utilizationGpuSubPage_ = new QWidget(utilizationDetailStack_);
    configureCompressibleWidget(utilizationGpuSubPage_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(utilizationGpuSubPage_);
    QVBoxLayout* gpuSubLayout = new QVBoxLayout(utilizationGpuSubPage_);
    gpuSubLayout->setContentsMargins(4, 4, 4, 4);
    gpuSubLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(
        ks::i18n::contextText(QStringLiteral("hardware.utilization.gpu.title"), QStringLiteral("GPU")),
        utilizationGpuSubPage_);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    gpuAdapterTitleLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.adapter_sampling"),
            QStringLiteral("适配器读取中...")),
        utilizationGpuSubPage_);
    configurePersistentHeaderLabel(gpuAdapterTitleLabel_, QSizePolicy::Ignored);
    gpuAdapterTitleLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    gpuAdapterTitleLabel_->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:500;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(gpuAdapterTitleLabel_, 6);
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(gpuAdapterTitleLabel_, 0);
    gpuSubLayout->addLayout(headerLayout, 0);

    gpuUtilSummaryLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.sampling"),
            QStringLiteral("GPU采样初始化中...")),
        utilizationGpuSubPage_);
    configureCompressibleLabel(gpuUtilSummaryLabel_);
    gpuUtilSummaryLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    gpuSubLayout->addWidget(gpuUtilSummaryLabel_, 0);

    // GPU engine 2x2 grid:
    // - Align with Task Manager's 3D / Copy / Video Encode / Video Decode;
    // - Each engine has an independent curve and title for easy bottleneck identification.
    gpuEngineHostWidget_ = new QWidget(utilizationGpuSubPage_);
    configureCompressibleWidget(gpuEngineHostWidget_, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(gpuEngineHostWidget_);
    gpuEngineGridLayout_ = new QGridLayout(gpuEngineHostWidget_);
    gpuEngineGridLayout_->setContentsMargins(0, 0, 0, 0);
    gpuEngineGridLayout_->setHorizontalSpacing(6);
    gpuEngineGridLayout_->setVerticalSpacing(6);
    gpuEngineCharts_.clear();

    auto addGpuEngineChart =
        [this](const QString& engineKeyText, const QString& displayNameText, const QColor& lineColor, const int rowIndex, const int columnIndex)
        {
            QWidget* cellWidget = new QWidget(gpuEngineHostWidget_);
            configureCompressibleWidget(cellWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
            appendTransparentBackgroundStyle(cellWidget);
            QVBoxLayout* cellLayout = new QVBoxLayout(cellWidget);
            cellLayout->setContentsMargins(0, 0, 0, 0);
            cellLayout->setSpacing(2);

            QLabel* cellTitle = new QLabel(displayNameText, cellWidget);
            configureCompressibleLabel(cellTitle);
            cellTitle->setStyleSheet(
                QStringLiteral("font-size:14px;font-weight:600;color:%1;")
                .arg(ksword_theme::textPrimaryHex()));
            cellLayout->addWidget(cellTitle, 0);

            QLineSeries* lineSeries = new QLineSeries(cellWidget);
            lineSeries->setColor(lineColor);
            QLineSeries* baselineSeries = createBaselineSeries(cellWidget, historyLength_);
            initializeLineSeriesHistory(lineSeries, historyLength_);

            QChart* chartPointer = new QChart();
            QAreaSeries* areaSeries = addFilledAreaSeries(
                chartPointer,
                lineSeries,
                baselineSeries,
                lineColor,
                44);
            configureUtilizationPlotChart(chartPointer, lineColor);

            QValueAxis* axisX = new QValueAxis(chartPointer);
            configureUtilizationValueAxis(axisX, lineColor, 0.0, static_cast<double>(historyLength_));

            QValueAxis* axisY = new QValueAxis(chartPointer);
            configureUtilizationValueAxis(axisY, lineColor, 0.0, 100.0);

            chartPointer->addAxis(axisX, Qt::AlignBottom);
            chartPointer->addAxis(axisY, Qt::AlignLeft);
            if (areaSeries != nullptr)
            {
                areaSeries->attachAxis(axisX);
                areaSeries->attachAxis(axisY);
            }

            QChartView* chartView = createPlotBackgroundChartView(chartPointer, cellWidget);
            cellLayout->addWidget(chartView, 1);
            gpuEngineGridLayout_->addWidget(cellWidget, rowIndex, columnIndex);

            GpuEngineChartEntry chartEntry;
            chartEntry.engineKeyText = engineKeyText;
            chartEntry.displayNameText = displayNameText;
            chartEntry.titleLabel = cellTitle;
            chartEntry.chartView = chartView;
            chartEntry.lineSeries = lineSeries;
            chartEntry.baselineSeries = baselineSeries;
            chartEntry.areaSeries = areaSeries;
            chartEntry.axisX = axisX;
            chartEntry.axisY = axisY;
            gpuEngineCharts_.push_back(chartEntry);
        };

    addGpuEngineChart(
        QStringLiteral("3d"), QStringLiteral("3D"),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kGpu), 0, 0);
    addGpuEngineChart(
        QStringLiteral("copy"), QStringLiteral("Copy"),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCopy), 0, 1);
    addGpuEngineChart(
        QStringLiteral("video_encode"), QStringLiteral("Video Encode"),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kVideoEncode), 1, 0);
    addGpuEngineChart(
        QStringLiteral("video_decode"), QStringLiteral("Video Decode"),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kVideoDecode), 1, 1);
    gpuSubLayout->addWidget(gpuEngineHostWidget_, 1);

    // VRAM curve: dedicated VRAM + shared VRAM.
    gpuDedicatedMemoryLineSeries_ = new QLineSeries(utilizationGpuSubPage_);
    const QColor kGpuDedicatedMemoryColor =
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kDedicatedMemory);
    const QColor kGpuSharedMemoryColor =
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kSharedMemory);
    gpuDedicatedMemoryLineSeries_->setColor(kGpuDedicatedMemoryColor);
    gpuDedicatedMemoryBaselineSeries_ = createBaselineSeries(utilizationGpuSubPage_, historyLength_);
    gpuSharedMemoryLineSeries_ = new QLineSeries(utilizationGpuSubPage_);
    gpuSharedMemoryLineSeries_->setColor(kGpuSharedMemoryColor);
    gpuSharedMemoryBaselineSeries_ = createBaselineSeries(utilizationGpuSubPage_, historyLength_);
    initializeLineSeriesHistory(gpuDedicatedMemoryLineSeries_, historyLength_);
    initializeLineSeriesHistory(gpuSharedMemoryLineSeries_, historyLength_);

    auto createGpuMemoryChart =
        [this](
            const QString& titleText,
            QLineSeries* lineSeries,
            QLineSeries* baselineSeries,
            QAreaSeries** areaSeriesOut,
            const QColor& lineColor,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut)
        {
            QChart* chartPointer = new QChart();
            QAreaSeries* areaSeries = addFilledAreaSeries(
                chartPointer,
                lineSeries,
                baselineSeries,
                lineColor,
                42);
            configureUtilizationPlotChart(chartPointer, lineColor, titleText);

            QValueAxis* axisX = new QValueAxis(chartPointer);
            configureUtilizationValueAxis(axisX, lineColor, 0.0, static_cast<double>(historyLength_));

            QValueAxis* axisY = new QValueAxis(chartPointer);
            configureUtilizationValueAxis(axisY, lineColor, 0.0, 1.0);

            chartPointer->addAxis(axisX, Qt::AlignBottom);
            chartPointer->addAxis(axisY, Qt::AlignLeft);
            if (areaSeries != nullptr)
            {
                areaSeries->attachAxis(axisX);
                areaSeries->attachAxis(axisY);
            }

            if (areaSeriesOut != nullptr)
            {
                *areaSeriesOut = areaSeries;
            }
            if (axisXOut != nullptr)
            {
                *axisXOut = axisX;
            }
            if (axisYOut != nullptr)
            {
                *axisYOut = axisY;
            }
            if (chartViewOut != nullptr)
            {
                *chartViewOut = createPlotBackgroundChartView(chartPointer, utilizationGpuSubPage_);
            }
        };

    createGpuMemoryChart(
        QStringLiteral("专用 GPU 内存利用率"),
        gpuDedicatedMemoryLineSeries_,
        gpuDedicatedMemoryBaselineSeries_,
        &gpuDedicatedMemoryAreaSeries_,
        kGpuDedicatedMemoryColor,
        &gpuDedicatedMemoryAxisX_,
        &gpuDedicatedMemoryAxisY_,
        &gpuDedicatedMemoryChartView_);
    createGpuMemoryChart(
        QStringLiteral("共享 GPU 内存利用率"),
        gpuSharedMemoryLineSeries_,
        gpuSharedMemoryBaselineSeries_,
        &gpuSharedMemoryAreaSeries_,
        kGpuSharedMemoryColor,
        &gpuSharedMemoryAxisX_,
        &gpuSharedMemoryAxisY_,
        &gpuSharedMemoryChartView_);

    gpuSubLayout->addWidget(gpuDedicatedMemoryChartView_, 0);
    gpuSubLayout->addWidget(gpuSharedMemoryChartView_, 0);

    gpuUtilDetailLabel_ = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.detail_sampling"),
            QStringLiteral("GPU参数采样中...")),
        utilizationGpuSubPage_);
    configureCompressibleLabel(gpuUtilDetailLabel_);
    gpuUtilDetailLabel_->setWordWrap(false);
    gpuUtilDetailLabel_->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    gpuSubLayout->addWidget(gpuUtilDetailLabel_, 0);

    utilizationDetailStack_->addWidget(utilizationGpuSubPage_);
}

void HardwareDock::initializeCpuTab()
{
    cpuPage_ = new QWidget(sideTabWidget_);
    cpuLayout_ = new QVBoxLayout(cpuPage_);
    cpuLayout_->setContentsMargins(4, 4, 4, 4);
    cpuLayout_->setSpacing(6);

    cpuDetailLabel_ = new QLabel(QStringLiteral("温度/电压读取中..."), cpuPage_);
    cpuDetailLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    cpuLayout_->addWidget(cpuDetailLabel_, 0);

    cpuDetailTable_ = new ks::ui::VisibleTableWidget(cpuPage_);
    cpuDetailTable_->setColumnCount(7);
    cpuDetailTable_->setHorizontalHeaderLabels({
        QStringLiteral("逻辑处理器"),
        QStringLiteral("利用率(%)"),
        QStringLiteral("当前频率(MHz)"),
        QStringLiteral("最大频率(MHz)"),
        QStringLiteral("限频(MHz)"),
        QStringLiteral("温度"),
        QStringLiteral("电压")
        });
    cpuDetailTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    cpuDetailTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    cpuDetailTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    cpuDetailTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    cpuDetailTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    cpuDetailTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    cpuDetailTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    cpuDetailTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    cpuDetailTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    cpuDetailTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    cpuDetailTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    installHardwareAuditCopyMenu(cpuDetailTable_);
    cpuLayout_->addWidget(cpuDetailTable_, 1);

    const int kTabIndex = sideTabWidget_->addTab(cpuPage_, QStringLiteral("处理器"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, cpuPage_, QStringLiteral("hardware.tab.cpu"), QStringLiteral("处理器"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("查看处理器型号、核心利用率、频率、温度和电压"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, cpuPage_, QStringLiteral("hardware.tooltip.cpu"), QStringLiteral("查看处理器型号、核心利用率、频率、温度和电压"));
}

void HardwareDock::initializePowerTab()
{
    // The power page maintains an independent Windows power scheme and controlled R0 CPU throttling logic.
    powerPage_ = new HardwarePowerPage(sideTabWidget_);
    const int kTabIndex = sideTabWidget_->addTab(
        powerPage_,
        QStringLiteral("电源"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        powerPage_,
        QStringLiteral("hardware.tab.power"),
        QStringLiteral("电源"));
    sideTabWidget_->setTabToolTip(
        kTabIndex,
        QStringLiteral("管理 Windows 电源方案与受控 CPU 功耗、Turbo 和 HWP 设置"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_,
        powerPage_,
        QStringLiteral("hardware.tooltip.power"),
        QStringLiteral("管理 Windows 电源方案与受控 CPU 功耗、Turbo 和 HWP 设置"));
}

void HardwareDock::initializeR0EvidenceTab()
{
    // Bottom-level hardware inspection page
    // - Input: none; relies on HardwareR0EvidencePage internally accessing the driver via ArkDriverClient.
    // - Processing: Present CPU/MSR/IDT/GDT read-only evidence as a separate top-level tab in the Hardware Dock.
    // - Return: None. The page is managed by the Qt parent-child tree.
    r0EvidencePage_ = new HardwareR0EvidencePage(sideTabWidget_);
    const int kTabIndex = sideTabWidget_->addTab(
        r0EvidencePage_,
        QStringLiteral("底层硬件检查"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, r0EvidencePage_, QStringLiteral("hardware.tab.r0_evidence"), QStringLiteral("底层硬件检查"));
    sideTabWidget_->setTabToolTip(
        kTabIndex,
        QStringLiteral("查看处理器寄存器与系统表的底层只读检查结果"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, r0EvidencePage_, QStringLiteral("hardware.tooltip.r0_evidence"), QStringLiteral("查看处理器寄存器与系统表的底层只读检查结果"));
}

void HardwareDock::initializeGpuTab()
{
    gpuPage_ = new QWidget(sideTabWidget_);
    gpuLayout_ = new QVBoxLayout(gpuPage_);
    gpuLayout_->setContentsMargins(4, 4, 4, 4);
    gpuLayout_->setSpacing(6);

    gpuEditor_ = new CodeEditorWidget(gpuPage_);
    gpuEditor_->setReadOnly(true);
    gpuLayout_->addWidget(gpuEditor_, 1);

    const int kTabIndex = sideTabWidget_->addTab(gpuPage_, QStringLiteral("显卡"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, gpuPage_, QStringLiteral("hardware.tab.gpu"), QStringLiteral("显卡"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("查看显卡型号、显存与驱动信息"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, gpuPage_, QStringLiteral("hardware.tooltip.gpu"), QStringLiteral("查看显卡型号、显存与驱动信息"));
}

void HardwareDock::initializeMemoryTab()
{
    memoryPage_ = new QWidget(sideTabWidget_);
    memoryLayout_ = new QVBoxLayout(memoryPage_);
    memoryLayout_->setContentsMargins(4, 4, 4, 4);
    memoryLayout_->setSpacing(6);

    memoryEditor_ = new CodeEditorWidget(memoryPage_);
    memoryEditor_->setReadOnly(true);
    memoryLayout_->addWidget(memoryEditor_, 1);

    const int kTabIndex = sideTabWidget_->addTab(memoryPage_, QStringLiteral("内存"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, memoryPage_, QStringLiteral("hardware.tab.memory"), QStringLiteral("内存"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("查看内存容量、模组与使用情况"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, memoryPage_, QStringLiteral("hardware.tooltip.memory"), QStringLiteral("查看内存容量、模组与使用情况"));
}

void HardwareDock::initializeDiskMonitorTab()
{
    // The disk monitoring page includes ETW sessions and full process IO enumeration; only a lightweight host is created when the Hardware Dock is first opened.
    diskMonitorHostPage_ = new QWidget(sideTabWidget_);
    QVBoxLayout* hostLayout = new QVBoxLayout(diskMonitorHostPage_);
    hostLayout->setContentsMargins(0, 0, 0, 0);
    hostLayout->setSpacing(0);
    hostLayout->addWidget(
        createHardwareDeferredPlaceholder(
            diskMonitorHostPage_,
            QStringLiteral("硬盘监控待加载"),
            QStringLiteral("切换到本页后再启动文件 ETW 与进程 IO 采样，避免拖慢硬件页首次打开。")),
        1);
    const int kTabIndex = sideTabWidget_->addTab(diskMonitorHostPage_, QStringLiteral("磁盘活动"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, diskMonitorHostPage_, QStringLiteral("hardware.tab.disk_activity"), QStringLiteral("磁盘活动"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("查看文件访问与进程磁盘读写活动"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, diskMonitorHostPage_, QStringLiteral("hardware.tooltip.disk_activity"), QStringLiteral("查看文件访问与进程磁盘读写活动"));
}

void HardwareDock::initializeDeviceManagerTab()
{
    // Device Management Page:
    // - Input: None; internally uses SetupAPI/CfgMgr for asynchronous PnP device enumeration.
    // - Handling: Create the page directly; the page itself controls background refresh and search.
    // - Return: None. Presented as an independent tab within the Hardware Dock.
    deviceManagerPage_ = new HardwareDeviceManagerPage(sideTabWidget_);
    const int kTabIndex = sideTabWidget_->addTab(deviceManagerPage_, QStringLiteral("设备管理"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, deviceManagerPage_, QStringLiteral("hardware.tab.device_manager"), QStringLiteral("设备管理"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("搜索、查看和管理 Windows 设备"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, deviceManagerPage_, QStringLiteral("hardware.tooltip.device_manager"), QStringLiteral("搜索、查看和管理 Windows 设备"));
}

void HardwareDock::initializeHwidDispatchTab()
{
    // initializeHwidDispatchTab：
    // - Input: None, depends on m_sideTabWidget;
    // - Processing: Add EASY-HWID-SPOOFER Dispatch-only integration page;
    // - Return: No return value; the page is released by the Qt parent-child tree.
    hwidDispatchPage_ = new HardwareHwidDispatchPage(sideTabWidget_);
    const int kTabIndex = sideTabWidget_->addTab(hwidDispatchPage_, QStringLiteral("硬件标识设置"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, hwidDispatchPage_, QStringLiteral("hardware.tab.hwid"), QStringLiteral("硬件标识设置"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("查看和调整支持的磁盘与网络硬件标识"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, hwidDispatchPage_, QStringLiteral("hardware.tooltip.hwid"), QStringLiteral("查看和调整支持的磁盘与网络硬件标识"));
}

void HardwareDock::initializeOtherDevicesTab()
{
    // The Other Devices page fetches hardware/PNP/driver lists; use a placeholder page to occupy the Tab when the Hardware Dock is opened for the first time.
    otherDevicesHostPage_ = new QWidget(sideTabWidget_);
    QVBoxLayout* hostLayout = new QVBoxLayout(otherDevicesHostPage_);
    hostLayout->setContentsMargins(0, 0, 0, 0);
    hostLayout->setSpacing(0);
    hostLayout->addWidget(
        createHardwareDeferredPlaceholder(
            otherDevicesHostPage_,
            QStringLiteral("其他设备待加载"),
            QStringLiteral("切换到本页后再异步枚举设备清单，减少硬件 Dock 初次点击耗时。")),
        1);
    const int kTabIndex = sideTabWidget_->addTab(otherDevicesHostPage_, QStringLiteral("其他设备"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, otherDevicesHostPage_, QStringLiteral("hardware.tab.other_devices"), QStringLiteral("其他设备"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("查看处理器、内存和显卡之外的硬件清单"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, otherDevicesHostPage_, QStringLiteral("hardware.tooltip.other_devices"), QStringLiteral("查看处理器、内存和显卡之外的硬件清单"));
}

void HardwareDock::initializeDeviceStackTab()
{
    deviceStackPage_ = createDeviceAuditPage(
        sideTabWidget_,
        QStringLiteral("设备节点与驱动链"),
        QStringLiteral("对比系统设备记录与内核设备栈，帮助发现异常关联；本页为只读。"),
        &deviceStackEditor_,
        &deviceStackTable_);
    const int kTabIndex = sideTabWidget_->addTab(deviceStackPage_, QStringLiteral("设备驱动链"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, deviceStackPage_, QStringLiteral("hardware.tab.device_stack"), QStringLiteral("设备驱动链"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("检查设备节点、驱动对象与附加驱动关系"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, deviceStackPage_, QStringLiteral("hardware.tooltip.device_stack"), QStringLiteral("检查设备节点、驱动对象与附加驱动关系"));
}

void HardwareDock::initializeKeyboardMouseHidTab()
{
    keyboardMouseHidPage_ = createDeviceAuditPage(
        sideTabWidget_,
        QStringLiteral("键盘、鼠标与其他输入设备"),
        QStringLiteral("只读审计：键盘、鼠标、HID 与输入设备状态，默认不做消息截获与输入抓取。"),
        &keyboardMouseHidEditor_,
        &keyboardMouseHidTable_);
    const int kTabIndex = sideTabWidget_->addTab(keyboardMouseHidPage_, QStringLiteral("键盘与鼠标"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, keyboardMouseHidPage_, QStringLiteral("hardware.tab.keyboard_mouse"), QStringLiteral("键盘与鼠标"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("检查键盘、鼠标与其他输入设备状态"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, keyboardMouseHidPage_, QStringLiteral("hardware.tooltip.keyboard_mouse"), QStringLiteral("检查键盘、鼠标与其他输入设备状态"));
}

void HardwareDock::initializeI8042AuditTab()
{
    i8042AuditPage_ = new HardwareI8042AuditPage(sideTabWidget_);
    const int kTabIndex = sideTabWidget_->addTab(
        i8042AuditPage_,
        QStringLiteral("i8042prt 审计"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        i8042AuditPage_,
        QStringLiteral("hardware.tab.i8042_audit"),
        QStringLiteral("i8042prt 审计"));
    sideTabWidget_->setTabToolTip(
        kTabIndex,
        QStringLiteral("精确验证 i8042prt 映像描述符、键鼠端点归属与设备栈关系"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_,
        i8042AuditPage_,
        QStringLiteral("hardware.tooltip.i8042_audit"),
        QStringLiteral("精确验证 i8042prt 映像描述符、键鼠端点归属与设备栈关系"));
}

void HardwareDock::initializeUsbTopologyTab()
{
    usbTopologyPage_ = createDeviceAuditPage(
        sideTabWidget_,
        QStringLiteral("USB 设备关系"),
        QStringLiteral("只读审计：USB 拓扑、控制器、Hub、端口与设备树关系。"),
        &usbTopologyEditor_,
        &usbTopologyTable_);
    const int kTabIndex = sideTabWidget_->addTab(usbTopologyPage_, QStringLiteral("USB 设备"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, usbTopologyPage_, QStringLiteral("hardware.tab.usb"), QStringLiteral("USB 设备"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("检查 USB 控制器、集线器、端口与设备关系"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, usbTopologyPage_, QStringLiteral("hardware.tooltip.usb"), QStringLiteral("检查 USB 控制器、集线器、端口与设备关系"));
}

void HardwareDock::initializePnpAcpiPciTab()
{
    pnpAcpiPciPage_ = createReadOnlyTextPage(
        sideTabWidget_,
        QStringLiteral("即插即用与系统总线"),
        QStringLiteral("只读审计：PnP、ACPI、PCI、DevNode 状态与 cross-view 风险标记。"),
        &pnpAcpiPciEditor_);
    const int kTabIndex = sideTabWidget_->addTab(pnpAcpiPciPage_, QStringLiteral("系统总线"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, pnpAcpiPciPage_, QStringLiteral("hardware.tab.system_bus"), QStringLiteral("系统总线"));
    sideTabWidget_->setTabToolTip(kTabIndex, QStringLiteral("查看即插即用、电源管理与 PCI 总线设备状态"));
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        sideTabWidget_, pnpAcpiPciPage_, QStringLiteral("hardware.tooltip.system_bus"), QStringLiteral("查看即插即用、电源管理与 PCI 总线设备状态"));
}

void HardwareDock::ensureDiskMonitorTabInitialized()
{
    if (diskMonitorPage_ != nullptr || diskMonitorHostPage_ == nullptr)
    {
        return;
    }

    QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(diskMonitorHostPage_->layout());
    if (hostLayout == nullptr)
    {
        hostLayout = new QVBoxLayout(diskMonitorHostPage_);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
    }

    // Clean up placeholder controls: The real page will take over the entire host area; old QWidget instances are released by the event loop.
    while (QLayoutItem* itemPointer = hostLayout->takeAt(0))
    {
        QWidget* itemWidget = itemPointer->widget();
        if (itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    diskMonitorPage_ = new DiskMonitorPage(diskMonitorHostPage_);
    hostLayout->addWidget(diskMonitorPage_, 1);
}

void HardwareDock::ensureOtherDevicesTabInitialized()
{
    if (otherDevicesPage_ != nullptr || otherDevicesHostPage_ == nullptr)
    {
        return;
    }

    QVBoxLayout* hostLayout = qobject_cast<QVBoxLayout*>(otherDevicesHostPage_->layout());
    if (hostLayout == nullptr)
    {
        hostLayout = new QVBoxLayout(otherDevicesHostPage_);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
    }

    // Clean up placeholder controls: the device manifest page handles asynchronous refresh internally; the host is only responsible for hosting the real page.
    while (QLayoutItem* itemPointer = hostLayout->takeAt(0))
    {
        QWidget* itemWidget = itemPointer->widget();
        if (itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    otherDevicesPage_ = new HardwareOtherDevicesPage(otherDevicesHostPage_);
    hostLayout->addWidget(otherDevicesPage_, 1);
}

void HardwareDock::initializeCoreCharts()
{
    if (coreChartGridLayout_ == nullptr || coreChartHostWidget_ == nullptr)
    {
        return;
    }

    // Clear the first-frame placeholder or old core chart: this function replaces the CPU core chart area with a real QChartView grid.
    while (QLayoutItem* itemPointer = coreChartGridLayout_->takeAt(0))
    {
        QWidget* itemWidget = itemPointer->widget();
        if (itemWidget != nullptr)
        {
            itemWidget->deleteLater();
        }
        delete itemPointer;
    }

    const DWORD kLogicalProcessorCount = std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    const int kCoreCount = static_cast<int>(kLogicalProcessorCount);
    const CpuCoreGridShape kGridShape = chooseCpuCoreGridShape(kCoreCount);
    cpuCoreGridColumnCount_ = kGridShape.columnCount;
    cpuCoreGridRowCount_ = kGridShape.rowCount;

    coreChartEntries_.clear();
    coreChartEntries_.reserve(kCoreCount);

    for (int coreIndex = 0; coreIndex < kCoreCount; ++coreIndex)
    {
        CoreChartEntry chartEntry;
        chartEntry.containerWidget = new QWidget(coreChartHostWidget_);
        configureCompressibleWidget(chartEntry.containerWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
        appendTransparentBackgroundStyle(chartEntry.containerWidget);
        QVBoxLayout* containerLayout = new QVBoxLayout(chartEntry.containerWidget);
        containerLayout->setContentsMargins(
            kCpuCoreChartCellMarginPx,
            kCpuCoreChartCellMarginPx,
            kCpuCoreChartCellMarginPx,
            kCpuCoreChartCellMarginPx);
        containerLayout->setSpacing(kCpuCoreChartInnerSpacingPx);

        chartEntry.titleLabel = new QLabel(
            QStringLiteral("CPU %1").arg(coreIndex),
            chartEntry.containerWidget);
        configureCompressibleLabel(chartEntry.titleLabel);
        chartEntry.titleLabel->setStyleSheet(
            QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
        chartEntry.titleLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        containerLayout->addWidget(chartEntry.titleLabel, 0);

        chartEntry.lineSeries = new QLineSeries(chartEntry.containerWidget);
        chartEntry.lineSeries->setColor(
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu));
        chartEntry.baselineSeries = new QLineSeries(chartEntry.containerWidget);
        for (int indexValue = 0; indexValue < historyLength_; ++indexValue)
        {
            chartEntry.lineSeries->append(indexValue, 0.0);
            chartEntry.baselineSeries->append(indexValue, 0.0);
        }

        QChart* chart = new QChart();
        chartEntry.areaSeries = new QAreaSeries(chartEntry.lineSeries, chartEntry.baselineSeries);
        const QColor kCpuChartColor =
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu);
        chartEntry.areaSeries->setColor(ksword_theme::withAlpha(kCpuChartColor, 46));
        chartEntry.areaSeries->setBorderColor(kCpuChartColor);
        chartEntry.areaSeries->setPen(QPen(kCpuChartColor, 1.6));
        chart->addSeries(chartEntry.areaSeries);
        chart->legend()->hide();
        chart->setBackgroundVisible(false);
        chart->setBackgroundRoundness(0);
        chart->setMargins(QMargins(0, 0, 0, 0));
        chart->setPlotAreaBackgroundVisible(true);
        chart->setPlotAreaBackgroundBrush(QBrush(ksword_theme::withAlpha(kCpuChartColor, 18)));
        chart->setPlotAreaBackgroundPen(QPen(ksword_theme::withAlpha(kCpuChartColor, 150), 1.0));

        chartEntry.axisX = new QValueAxis(chart);
        chartEntry.axisX->setRange(0, historyLength_ - 1);
        chartEntry.axisX->setLabelsVisible(false);
        chartEntry.axisX->setGridLineVisible(true);
        chartEntry.axisX->setMinorGridLineVisible(false);
        chartEntry.axisX->setLineVisible(true);
        chartEntry.axisX->setLinePen(QPen(ksword_theme::withAlpha(kCpuChartColor, 140), 1.0));
        chartEntry.axisX->setGridLinePen(QPen(ksword_theme::withAlpha(kCpuChartColor, 46), 1.0));

        chartEntry.axisY = new QValueAxis(chart);
        chartEntry.axisY->setRange(0.0, 100.0);
        chartEntry.axisY->setLabelsVisible(false);
        chartEntry.axisY->setGridLineVisible(true);
        chartEntry.axisY->setMinorGridLineVisible(false);
        chartEntry.axisY->setLineVisible(true);
        chartEntry.axisY->setLinePen(QPen(ksword_theme::withAlpha(kCpuChartColor, 140), 1.0));
        chartEntry.axisY->setGridLinePen(QPen(ksword_theme::withAlpha(kCpuChartColor, 46), 1.0));

        chart->addAxis(chartEntry.axisX, Qt::AlignBottom);
        chart->addAxis(chartEntry.axisY, Qt::AlignLeft);
        chartEntry.areaSeries->attachAxis(chartEntry.axisX);
        chartEntry.areaSeries->attachAxis(chartEntry.axisY);

        chartEntry.chartView = createPlotBackgroundChartView(chart, chartEntry.containerWidget);
        containerLayout->addWidget(chartEntry.chartView, 1);

        const int kRowIndex = coreIndex / kGridShape.columnCount;
        const int kColumnIndex = coreIndex % kGridShape.columnCount;
        coreChartGridLayout_->addWidget(chartEntry.containerWidget, kRowIndex, kColumnIndex);
        coreChartEntries_.push_back(chartEntry);
    }

    adjustUtilizationChartHeights();
}

void HardwareDock::initializeConnections()
{
    // No additional interactive buttons currently; reserved function for future expansion.
}

void HardwareDock::scheduleUtilizationLayoutRefresh()
{
    // The current event loop performs a re-layout first to ensure newly appended device cards immediately obtain stable dimensions.
    adjustUtilizationChartHeights();
    // 0ms delay is used to wait for the QListWidget to finish updating the viewport size after inserting rows.
    QTimer::singleShot(0, this, [this]()
    {
        adjustUtilizationChartHeights();
    });
    // 80ms delay to recalibrate after ADS Dock animation or first display chain completes.
    QTimer::singleShot(80, this, [this]()
    {
        adjustUtilizationChartHeights();
    });
}

int HardwareDock::findDiskUtilizationDeviceIndexByInstance(const QString& instanceNameText) const
{
    for (int indexValue = 0; indexValue < static_cast<int>(diskUtilDevices_.size()); ++indexValue)
    {
        const DiskUtilizationDevice& device = diskUtilDevices_[static_cast<std::size_t>(indexValue)];
        if (QString::compare(device.instanceNameText, instanceNameText, Qt::CaseInsensitive) == 0)
        {
            return indexValue;
        }
    }
    return -1;
}

int HardwareDock::ensureDiskUtilizationDevice(
    const DiskRateSample& sample,
    const int ordinalIndex)
{
    const int kExistingIndex = findDiskUtilizationDeviceIndexByInstance(sample.instanceNameText);
    if (kExistingIndex >= 0)
    {
        return kExistingIndex;
    }

    // device purpose: reserve UI controls and historical samples for newly discovered physical disk instances.
    DiskUtilizationDevice device;
    device.instanceNameText = sample.instanceNameText;
    const bool kUseDefaultDisplayName = sample.displayNameText.isEmpty();
    device.displayNameText = kUseDefaultDisplayName
        ? QStringLiteral("磁盘 %1").arg(ordinalIndex)
        : sample.displayNameText;
    if (kUseDefaultDisplayName)
    {
        device.displayNameText = ks::i18n::contextText(
            QStringLiteral("hardware.utilization.card.disk.prefix"),
            QStringLiteral("磁盘")) + device.displayNameText.mid(QStringLiteral("磁盘").size());
    }
    createDiskUtilizationDevicePage(&device);
    diskUtilDevices_.push_back(device);

    const int kDeviceIndex = static_cast<int>(diskUtilDevices_.size()) - 1;
    diskUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].navCard = addUtilizationSidebarCard(
        diskUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].pageWidget,
        diskUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].displayNameText,
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kDisk),
        UtilizationDeviceKind::kDisk,
        kDeviceIndex);
    if (diskUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].navCard != nullptr)
    {
        diskUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].navCard->setSeriesColors(
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kRead),
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kWrite));
    }
    scheduleUtilizationLayoutRefresh();
    return kDeviceIndex;
}

int HardwareDock::findNetworkUtilizationDeviceIndexByKey(const std::uint64_t interfaceKey) const
{
    for (int indexValue = 0; indexValue < static_cast<int>(networkUtilDevices_.size()); ++indexValue)
    {
        const NetworkUtilizationDevice& device = networkUtilDevices_[static_cast<std::size_t>(indexValue)];
        if (device.interfaceKey == interfaceKey)
        {
            return indexValue;
        }
    }
    return -1;
}

int HardwareDock::ensureNetworkUtilizationDevice(
    const NetworkRateSample& sample,
    const int ordinalIndex)
{
    const int kExistingIndex = findNetworkUtilizationDeviceIndexByKey(sample.interfaceKey);
    if (kExistingIndex >= 0)
    {
        return kExistingIndex;
    }

    // device purpose: reserve UI controls and incremental sampling baselines for newly discovered network interface instances.
    NetworkUtilizationDevice device;
    device.interfaceKey = sample.interfaceKey;
    const bool kUseDefaultDisplayName = sample.displayNameText.isEmpty();
    device.displayNameText = kUseDefaultDisplayName
        ? QStringLiteral("以太网 %1").arg(ordinalIndex)
        : sample.displayNameText;
    if (kUseDefaultDisplayName)
    {
        device.displayNameText = ks::i18n::contextText(
            QStringLiteral("hardware.utilization.card.network.prefix"),
            QStringLiteral("以太网")) + device.displayNameText.mid(QStringLiteral("以太网").size());
    }
    device.linkBitsPerSecond = sample.linkBitsPerSecond;
    device.lastRxBytes = sample.totalRxBytes;
    device.lastTxBytes = sample.totalTxBytes;
    device.lastSampleMs = QDateTime::currentMSecsSinceEpoch();
    device.hasPreviousSample = true;
    createNetworkUtilizationDevicePage(&device);
    networkUtilDevices_.push_back(device);

    const int kDeviceIndex = static_cast<int>(networkUtilDevices_.size()) - 1;
    networkUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].navCard = addUtilizationSidebarCard(
        networkUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].pageWidget,
        networkUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].displayNameText,
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kNetwork),
        UtilizationDeviceKind::kNetwork,
        kDeviceIndex);
    if (networkUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].navCard != nullptr)
    {
        networkUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].navCard->setSeriesColors(
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kRead),
            ksword_theme::performanceColor(ksword_theme::PerformanceRole::kWrite));
    }
    scheduleUtilizationLayoutRefresh();
    return kDeviceIndex;
}

int HardwareDock::findGpuUtilizationDeviceIndexByKey(const std::uint64_t adapterKey) const
{
    for (int indexValue = 0; indexValue < static_cast<int>(gpuUtilDevices_.size()); ++indexValue)
    {
        const GpuUtilizationDevice& device = gpuUtilDevices_[static_cast<std::size_t>(indexValue)];
        if (device.adapterKeyAssigned && device.adapterKey == adapterKey)
        {
            return indexValue;
        }
    }
    return -1;
}

int HardwareDock::ensureGpuUtilizationDevice(
    const GpuUsageSample& sample,
    const int ordinalIndex)
{
    const int kExistingIndex = findGpuUtilizationDeviceIndexByKey(sample.adapterKey);
    if (kExistingIndex >= 0)
    {
        return kExistingIndex;
    }

    // device usage: Reserves a Task Manager-style GPU details page for newly discovered DXGI adapters.
    GpuUtilizationDevice device;
    device.adapterKey = sample.adapterKey;
    device.adapterKeyAssigned = true;
    device.adapterIndex = sample.adapterIndex;
    device.displayNameText = ks::i18n::contextText(
        QStringLiteral("hardware.utilization.card.gpu.prefix"),
        QStringLiteral("GPU"))
        + QStringLiteral(" %1").arg(ordinalIndex);
    createGpuUtilizationDevicePage(&device);
    gpuUtilDevices_.push_back(device);

    const int kDeviceIndex = static_cast<int>(gpuUtilDevices_.size()) - 1;
    gpuUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].navCard = addUtilizationSidebarCard(
        gpuUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].pageWidget,
        gpuUtilDevices_[static_cast<std::size_t>(kDeviceIndex)].displayNameText,
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kGpu),
        UtilizationDeviceKind::kGpu,
        kDeviceIndex);
    scheduleUtilizationLayoutRefresh();
    return kDeviceIndex;
}

void HardwareDock::createDiskUtilizationDevicePage(DiskUtilizationDevice* devicePointer)
{
    if (devicePointer == nullptr || utilizationDetailStack_ == nullptr)
    {
        return;
    }

    devicePointer->pageWidget = new QWidget(utilizationDetailStack_);
    configureCompressibleWidget(devicePointer->pageWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(devicePointer->pageWidget);
    QVBoxLayout* pageLayout = new QVBoxLayout(devicePointer->pageWidget);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(devicePointer->displayNameText, devicePointer->pageWidget);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    pageLayout->addWidget(titleLabel, 0);

    devicePointer->summaryLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.device.disk.sampling"),
            QStringLiteral("磁盘采样初始化中...")),
        devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->summaryLabel);
    devicePointer->summaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    pageLayout->addWidget(devicePointer->summaryLabel, 0);

    devicePointer->readLineSeries = new QLineSeries(devicePointer->pageWidget);
    devicePointer->readLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.disk.read"), QStringLiteral("读取")));
    const QColor kReadColor(80, 170, 255);
    const QColor kWriteColor(255, 190, 105);
    devicePointer->readLineSeries->setColor(kReadColor);
    devicePointer->readBaselineSeries = createBaselineSeries(devicePointer->pageWidget, historyLength_);
    devicePointer->writeLineSeries = new QLineSeries(devicePointer->pageWidget);
    devicePointer->writeLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.disk.write"), QStringLiteral("写入")));
    devicePointer->writeLineSeries->setColor(kWriteColor);
    devicePointer->writeBaselineSeries = createBaselineSeries(devicePointer->pageWidget, historyLength_);
    initializeLineSeriesHistory(devicePointer->readLineSeries, historyLength_);
    initializeLineSeriesHistory(devicePointer->writeLineSeries, historyLength_);

    QChart* chart = new QChart();
    devicePointer->readAreaSeries = addFilledAreaSeries(
        chart,
        devicePointer->readLineSeries,
        devicePointer->readBaselineSeries,
        kReadColor,
        42);
    devicePointer->writeAreaSeries = addFilledAreaSeries(
        chart,
        devicePointer->writeLineSeries,
        devicePointer->writeBaselineSeries,
        kWriteColor,
        34);
    configureUtilizationPlotChart(
        chart,
        kReadColor,
        QStringLiteral("%1 %2")
            .arg(devicePointer->displayNameText)
            .arg(ks::i18n::contextText(
                QStringLiteral("hardware.utilization.disk.rate_suffix"),
                QStringLiteral("读写速率趋势"))),
        true);
    devicePointer->axisX = new QValueAxis(chart);
    configureUtilizationValueAxis(devicePointer->axisX, kReadColor, 0.0, static_cast<double>(historyLength_));
    devicePointer->axisY = new QValueAxis(chart);
    configureUtilizationValueAxis(devicePointer->axisY, kReadColor, 0.0, 1.0);
    chart->addAxis(devicePointer->axisX, Qt::AlignBottom);
    chart->addAxis(devicePointer->axisY, Qt::AlignLeft);
    if (devicePointer->readAreaSeries != nullptr)
    {
        devicePointer->readAreaSeries->attachAxis(devicePointer->axisX);
        devicePointer->readAreaSeries->attachAxis(devicePointer->axisY);
    }
    if (devicePointer->writeAreaSeries != nullptr)
    {
        devicePointer->writeAreaSeries->attachAxis(devicePointer->axisX);
        devicePointer->writeAreaSeries->attachAxis(devicePointer->axisY);
    }
    devicePointer->chartView = createPlotBackgroundChartView(chart, devicePointer->pageWidget);
    pageLayout->addWidget(devicePointer->chartView, 1);

    devicePointer->detailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.device.disk.detail_sampling"),
            QStringLiteral("磁盘参数采样中...")),
        devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->detailLabel);
    devicePointer->detailLabel->setWordWrap(false);
    devicePointer->detailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    pageLayout->addWidget(devicePointer->detailLabel, 0);

    utilizationDetailStack_->addWidget(devicePointer->pageWidget);
}

void HardwareDock::createNetworkUtilizationDevicePage(NetworkUtilizationDevice* devicePointer)
{
    if (devicePointer == nullptr || utilizationDetailStack_ == nullptr)
    {
        return;
    }

    devicePointer->pageWidget = new QWidget(utilizationDetailStack_);
    configureCompressibleWidget(devicePointer->pageWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(devicePointer->pageWidget);
    QVBoxLayout* pageLayout = new QVBoxLayout(devicePointer->pageWidget);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(devicePointer->displayNameText, devicePointer->pageWidget);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    pageLayout->addWidget(titleLabel, 0);

    devicePointer->summaryLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.device.network.sampling"),
            QStringLiteral("网络采样初始化中...")),
        devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->summaryLabel);
    devicePointer->summaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    pageLayout->addWidget(devicePointer->summaryLabel, 0);

    devicePointer->rxLineSeries = new QLineSeries(devicePointer->pageWidget);
    devicePointer->rxLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.network.down"), QStringLiteral("下行")));
    const QColor kRxColor(92, 190, 255);
    const QColor kTxColor(255, 190, 105);
    devicePointer->rxLineSeries->setColor(kRxColor);
    devicePointer->rxBaselineSeries = createBaselineSeries(devicePointer->pageWidget, historyLength_);
    devicePointer->txLineSeries = new QLineSeries(devicePointer->pageWidget);
    devicePointer->txLineSeries->setName(ks::i18n::contextText(
        QStringLiteral("hardware.utilization.network.up"), QStringLiteral("上行")));
    devicePointer->txLineSeries->setColor(kTxColor);
    devicePointer->txBaselineSeries = createBaselineSeries(devicePointer->pageWidget, historyLength_);
    initializeLineSeriesHistory(devicePointer->rxLineSeries, historyLength_);
    initializeLineSeriesHistory(devicePointer->txLineSeries, historyLength_);

    QChart* chart = new QChart();
    devicePointer->rxAreaSeries = addFilledAreaSeries(
        chart,
        devicePointer->rxLineSeries,
        devicePointer->rxBaselineSeries,
        kRxColor,
        42);
    devicePointer->txAreaSeries = addFilledAreaSeries(
        chart,
        devicePointer->txLineSeries,
        devicePointer->txBaselineSeries,
        kTxColor,
        34);
    configureUtilizationPlotChart(
        chart,
        kRxColor,
        QStringLiteral("%1 %2")
            .arg(devicePointer->displayNameText)
            .arg(ks::i18n::contextText(
                QStringLiteral("hardware.utilization.network.rate_suffix"),
                QStringLiteral("收发速率趋势"))),
        true);
    devicePointer->axisX = new QValueAxis(chart);
    configureUtilizationValueAxis(devicePointer->axisX, kRxColor, 0.0, static_cast<double>(historyLength_));
    devicePointer->axisY = new QValueAxis(chart);
    configureUtilizationValueAxis(devicePointer->axisY, kRxColor, 0.0, 1.0);
    chart->addAxis(devicePointer->axisX, Qt::AlignBottom);
    chart->addAxis(devicePointer->axisY, Qt::AlignLeft);
    if (devicePointer->rxAreaSeries != nullptr)
    {
        devicePointer->rxAreaSeries->attachAxis(devicePointer->axisX);
        devicePointer->rxAreaSeries->attachAxis(devicePointer->axisY);
    }
    if (devicePointer->txAreaSeries != nullptr)
    {
        devicePointer->txAreaSeries->attachAxis(devicePointer->axisX);
        devicePointer->txAreaSeries->attachAxis(devicePointer->axisY);
    }
    devicePointer->chartView = createPlotBackgroundChartView(chart, devicePointer->pageWidget);
    pageLayout->addWidget(devicePointer->chartView, 1);

    devicePointer->detailLabel = new QLabel(QStringLiteral("网络参数采样中..."), devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->detailLabel);
    devicePointer->detailLabel->setWordWrap(false);
    devicePointer->detailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    pageLayout->addWidget(devicePointer->detailLabel, 0);

    utilizationDetailStack_->addWidget(devicePointer->pageWidget);
}

void HardwareDock::createGpuUtilizationDevicePage(GpuUtilizationDevice* devicePointer)
{
    if (devicePointer == nullptr || utilizationDetailStack_ == nullptr)
    {
        return;
    }

    devicePointer->pageWidget = new QWidget(utilizationDetailStack_);
    configureCompressibleWidget(devicePointer->pageWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(devicePointer->pageWidget);
    QVBoxLayout* pageLayout = new QVBoxLayout(devicePointer->pageWidget);
    pageLayout->setContentsMargins(4, 4, 4, 4);
    pageLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* titleLabel = new QLabel(devicePointer->displayNameText, devicePointer->pageWidget);
    configurePersistentHeaderLabel(titleLabel);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:46px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(titleLabel, 14);
    devicePointer->adapterTitleLabel = new QLabel(QStringLiteral("适配器读取中..."), devicePointer->pageWidget);
    configurePersistentHeaderLabel(devicePointer->adapterTitleLabel, QSizePolicy::Ignored);
    devicePointer->adapterTitleLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    devicePointer->adapterTitleLabel->setStyleSheet(
        QStringLiteral("font-size:15px;font-weight:500;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    lockLabelHeightToFont(devicePointer->adapterTitleLabel, 6);
    headerLayout->addWidget(titleLabel, 0);
    headerLayout->addStretch(1);
    headerLayout->addWidget(devicePointer->adapterTitleLabel, 0);
    pageLayout->addLayout(headerLayout, 0);

    devicePointer->summaryLabel = new QLabel(QStringLiteral("GPU采样初始化中..."), devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->summaryLabel);
    devicePointer->summaryLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:14px;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    pageLayout->addWidget(devicePointer->summaryLabel, 0);

    devicePointer->engineHostWidget = new QWidget(devicePointer->pageWidget);
    configureCompressibleWidget(devicePointer->engineHostWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
    appendTransparentBackgroundStyle(devicePointer->engineHostWidget);
    devicePointer->engineGridLayout = new QGridLayout(devicePointer->engineHostWidget);
    devicePointer->engineGridLayout->setContentsMargins(0, 0, 0, 0);
    devicePointer->engineGridLayout->setHorizontalSpacing(6);
    devicePointer->engineGridLayout->setVerticalSpacing(6);
    devicePointer->engineCharts.clear();

    auto addEngineChart =
        [this, devicePointer](
            const QString& keyText,
            const QString& displayText,
            const QColor& lineColor,
            const int rowIndex,
            const int columnIndex)
        {
            QWidget* cellWidget = new QWidget(devicePointer->engineHostWidget);
            configureCompressibleWidget(cellWidget, QSizePolicy::Expanding, QSizePolicy::Expanding);
            appendTransparentBackgroundStyle(cellWidget);
            QVBoxLayout* cellLayout = new QVBoxLayout(cellWidget);
            cellLayout->setContentsMargins(3, 3, 3, 3);
            cellLayout->setSpacing(2);

            GpuEngineChartEntry chartEntry;
            chartEntry.engineKeyText = keyText;
            chartEntry.displayNameText = displayText;
            chartEntry.titleLabel = new QLabel(displayText, cellWidget);
            configureCompressibleLabel(chartEntry.titleLabel);
            chartEntry.titleLabel->setStyleSheet(
                QStringLiteral("font-size:12px;color:%1;").arg(ksword_theme::textPrimaryHex()));
            cellLayout->addWidget(chartEntry.titleLabel, 0);

            chartEntry.lineSeries = new QLineSeries(cellWidget);
            chartEntry.lineSeries->setColor(lineColor);
            chartEntry.baselineSeries = createBaselineSeries(cellWidget, historyLength_);
            initializeLineSeriesHistory(chartEntry.lineSeries, historyLength_);

            QChart* chart = new QChart();
            chartEntry.areaSeries = addFilledAreaSeries(
                chart,
                chartEntry.lineSeries,
                chartEntry.baselineSeries,
                lineColor,
                44);
            configureUtilizationPlotChart(chart, lineColor);
            chartEntry.axisX = new QValueAxis(chart);
            configureUtilizationValueAxis(chartEntry.axisX, lineColor, 0.0, static_cast<double>(historyLength_));
            chartEntry.axisY = new QValueAxis(chart);
            configureUtilizationValueAxis(chartEntry.axisY, lineColor, 0.0, 100.0);
            chart->addAxis(chartEntry.axisX, Qt::AlignBottom);
            chart->addAxis(chartEntry.axisY, Qt::AlignLeft);
            if (chartEntry.areaSeries != nullptr)
            {
                chartEntry.areaSeries->attachAxis(chartEntry.axisX);
                chartEntry.areaSeries->attachAxis(chartEntry.axisY);
            }
            chartEntry.chartView = createPlotBackgroundChartView(chart, cellWidget);
            cellLayout->addWidget(chartEntry.chartView, 1);

            devicePointer->engineGridLayout->addWidget(cellWidget, rowIndex, columnIndex);
            devicePointer->engineCharts.push_back(chartEntry);
        };

    addEngineChart(
        QStringLiteral("3d"), QStringLiteral("3D"),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kGpu), 0, 0);
    addEngineChart(
        QStringLiteral("copy"), QStringLiteral("Copy"),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCopy), 0, 1);
    addEngineChart(
        QStringLiteral("video_encode"), QStringLiteral("Video Encode"),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kVideoEncode), 1, 0);
    addEngineChart(
        QStringLiteral("video_decode"), QStringLiteral("Video Decode"),
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kVideoDecode), 1, 1);
    pageLayout->addWidget(devicePointer->engineHostWidget, 1);

    auto createMemoryChart =
        [this, devicePointer](
            const QString& titleText,
            QLineSeries** seriesOut,
            QLineSeries** baselineSeriesOut,
            QAreaSeries** areaSeriesOut,
            const QColor& lineColor,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut)
        {
            *seriesOut = new QLineSeries(devicePointer->pageWidget);
            (*seriesOut)->setColor(lineColor);
            *baselineSeriesOut = createBaselineSeries(devicePointer->pageWidget, historyLength_);
            initializeLineSeriesHistory(*seriesOut, historyLength_);

            QChart* chart = new QChart();
            *areaSeriesOut = addFilledAreaSeries(
                chart,
                *seriesOut,
                *baselineSeriesOut,
                lineColor,
                42);
            configureUtilizationPlotChart(chart, lineColor, titleText);
            *axisXOut = new QValueAxis(chart);
            configureUtilizationValueAxis(*axisXOut, lineColor, 0.0, static_cast<double>(historyLength_));
            *axisYOut = new QValueAxis(chart);
            configureUtilizationValueAxis(*axisYOut, lineColor, 0.0, 1.0);
            chart->addAxis(*axisXOut, Qt::AlignBottom);
            chart->addAxis(*axisYOut, Qt::AlignLeft);
            if (*areaSeriesOut != nullptr)
            {
                (*areaSeriesOut)->attachAxis(*axisXOut);
                (*areaSeriesOut)->attachAxis(*axisYOut);
            }
            *chartViewOut = createPlotBackgroundChartView(chart, devicePointer->pageWidget);
        };

    createMemoryChart(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.dedicated_memory_label"),
            QStringLiteral("专用 GPU 内存利用率")),
        &devicePointer->dedicatedMemoryLineSeries,
        &devicePointer->dedicatedMemoryBaselineSeries,
        &devicePointer->dedicatedMemoryAreaSeries,
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kDedicatedMemory),
        &devicePointer->dedicatedMemoryAxisX,
        &devicePointer->dedicatedMemoryAxisY,
        &devicePointer->dedicatedMemoryChartView);
    createMemoryChart(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.gpu.shared_memory_label"),
            QStringLiteral("共享 GPU 内存利用率")),
        &devicePointer->sharedMemoryLineSeries,
        &devicePointer->sharedMemoryBaselineSeries,
        &devicePointer->sharedMemoryAreaSeries,
        ksword_theme::performanceColor(ksword_theme::PerformanceRole::kSharedMemory),
        &devicePointer->sharedMemoryAxisX,
        &devicePointer->sharedMemoryAxisY,
        &devicePointer->sharedMemoryChartView);
    pageLayout->addWidget(devicePointer->dedicatedMemoryChartView, 0);
    pageLayout->addWidget(devicePointer->sharedMemoryChartView, 0);

    devicePointer->detailLabel = new QLabel(
        ks::i18n::contextText(
            QStringLiteral("hardware.utilization.device.gpu.detail_sampling"),
            QStringLiteral("GPU参数采样中...")),
        devicePointer->pageWidget);
    configureCompressibleLabel(devicePointer->detailLabel);
    devicePointer->detailLabel->setWordWrap(false);
    devicePointer->detailLabel->setStyleSheet(
        QStringLiteral("font-size:14px;color:%1;").arg(ksword_theme::textPrimaryHex()));
    pageLayout->addWidget(devicePointer->detailLabel, 0);

    utilizationDetailStack_->addWidget(devicePointer->pageWidget);
}

void HardwareDock::refreshCpuTopologyStaticInfo()
{
    if (cpuModelText_.isEmpty() || cpuModelText_ == QStringLiteral("N/A"))
    {
        cpuModelText_ = queryCpuBrandTextByCpuid();
    }
    if (cpuModelLabel_ != nullptr && !cpuModelText_.isEmpty())
    {
        cpuModelLabel_->setText(cpuModelText_);
    }

    DWORD requiredBytes = 0;
    ::GetLogicalProcessorInformationEx(RelationAll, nullptr, &requiredBytes);
    if (requiredBytes == 0)
    {
        cpuLogicalCoreCount_ = static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        return;
    }

    std::vector<unsigned char> buffer(requiredBytes);
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* infoPointer =
        reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data());
    if (::GetLogicalProcessorInformationEx(RelationAll, infoPointer, &requiredBytes) == FALSE)
    {
        cpuLogicalCoreCount_ = static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        return;
    }

    int packageCount = 0;
    int physicalCoreCount = 0;
    int logicalCoreCount = 0;
    std::uint64_t l1Bytes = 0;
    std::uint64_t l2Bytes = 0;
    std::uint64_t l3Bytes = 0;

    DWORD offsetBytes = 0;
    while (offsetBytes < requiredBytes)
    {
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* entryPointer =
            reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*>(buffer.data() + offsetBytes);
        if (entryPointer->Relationship == RelationProcessorPackage)
        {
            ++packageCount;
        }
        else if (entryPointer->Relationship == RelationProcessorCore)
        {
            ++physicalCoreCount;
            for (WORD groupIndex = 0; groupIndex < entryPointer->Processor.GroupCount; ++groupIndex)
            {
                logicalCoreCount += countBits(entryPointer->Processor.GroupMask[groupIndex].Mask);
            }
        }
        else if (entryPointer->Relationship == RelationCache)
        {
            if (entryPointer->Cache.Level == 1)
            {
                l1Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
            else if (entryPointer->Cache.Level == 2)
            {
                l2Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
            else if (entryPointer->Cache.Level == 3)
            {
                l3Bytes += static_cast<std::uint64_t>(entryPointer->Cache.CacheSize);
            }
        }

        if (entryPointer->Size == 0)
        {
            break;
        }
        offsetBytes += entryPointer->Size;
    }

    cpuPackageCount_ = std::max(1, packageCount);
    cpuPhysicalCoreCount_ = std::max(1, physicalCoreCount);
    cpuLogicalCoreCount_ = logicalCoreCount > 0
        ? logicalCoreCount
        : static_cast<int>(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    cpuL1CacheBytes_ = l1Bytes;
    cpuL2CacheBytes_ = l2Bytes;
    cpuL3CacheBytes_ = l3Bytes;
}

void HardwareDock::refreshSystemVolumeInfo()
{
    QString systemDrive = qEnvironmentVariable("SystemDrive");
    if (systemDrive.isEmpty())
    {
        systemDrive = QStringLiteral("C:");
    }

    QString rootPath = systemDrive;
    if (!rootPath.endsWith('\\'))
    {
        rootPath += QLatin1Char('\\');
    }

    ULARGE_INTEGER freeAvailableBytes{};
    ULARGE_INTEGER totalBytes{};
    ULARGE_INTEGER totalFreeBytes{};
    if (::GetDiskFreeSpaceExW(
        reinterpret_cast<LPCWSTR>(rootPath.utf16()),
        &freeAvailableBytes,
        &totalBytes,
        &totalFreeBytes) == TRUE)
    {
        systemVolumeTotalBytes_ = static_cast<std::uint64_t>(totalBytes.QuadPart);
        systemVolumeFreeBytes_ = static_cast<std::uint64_t>(totalFreeBytes.QuadPart);
    }

    wchar_t volumeNameBuffer[MAX_PATH] = {};
    if (::GetVolumeInformationW(
        reinterpret_cast<LPCWSTR>(rootPath.utf16()),
        volumeNameBuffer,
        MAX_PATH,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        0) == TRUE)
    {
        const QString kVolumeNameText = QString::fromWCharArray(volumeNameBuffer).trimmed();
        if (!kVolumeNameText.isEmpty())
        {
            systemVolumeText_ = QStringLiteral("%1 (%2)").arg(kVolumeNameText, systemDrive);
            return;
        }
    }

    systemVolumeText_ = rootPath;
}

void HardwareDock::initializePerformanceCounters()
{
    // Asynchronous initialization of counters:
    // PdhOpenQueryW + per-core PdhAddEnglishCounterW + \Processor Information takes over 100ms on the first call.
    // - Previously deferred to after the first frame but still on the UI thread; now offloaded to a thread pool, with handle takeover upon completion;
    // - samplePerCoreUsage returns false directly before the handle is ready, and the UI displays 0 as a placeholder.
    if (cpuPerfQueryHandle_ != nullptr)
    {
        return;
    }

    // expectedInitializingValue usage: CAS expected value (false = no initialization task is currently running).
    bool expectedInitializingValue = false;
    if (!hardwareDockCpuCounterInitializing.compare_exchange_strong(expectedInitializingValue, true))
    {
        return;
    }

    // coreCount must be read on the UI thread: m_coreChartEntries stores chart control data.
    const int kCoreCount = static_cast<int>(coreChartEntries_.size());

    // applicationContext shares the lifetime of the event loop; worker threads do not dereference Dock pointers.
    QObject* const kApplicationContext = QCoreApplication::instance();
    if (kApplicationContext == nullptr)
    {
        hardwareDockCpuCounterInitializing.store(false);
        return;
    }

    // safeThis purpose: Background tasks may outlive the Dock; lifecycle must be verified after re-entry.
    const QPointer<HardwareDock> kSafeThis(this);
    QThreadPool::globalInstance()->start(
        [kApplicationContext, kSafeThis, kCoreCount]()
        {
            // The background thread performs only pure data collection, producing handle values that can be safely transferred across threads.
            const HardwareDockCpuCounterBundle kCounterBundle = createHardwareDockCpuCounters(kCoreCount);

            const bool kInvokeOk = QMetaObject::invokeMethod(
                kApplicationContext,
                [kSafeThis, kCounterBundle]()
                {
                    if (kSafeThis.isNull())
                    {
                        closeHardwareDockCpuCounters(kCounterBundle);
                        hardwareDockCpuCounterInitializing.store(false);
                        return;
                    }

                    if (kCounterBundle.cpuQueryHandle == nullptr)
                    {
                        KLogEvent event;
                        warn << event
                            << "[HardwareDock] 初始化PDH失败：PdhOpenQueryW, status="
                            << kCounterBundle.openQueryStatus
                            << eol;
                        hardwareDockCpuCounterInitializing.store(false);
                        return;
                    }

                    if (kSafeThis->cpuPerfQueryHandle_ != nullptr)
                    {
                        // A previous initialization round already took over the handle; release the current result directly to avoid a leak.
                        closeHardwareDockCpuCounters(kCounterBundle);
                        hardwareDockCpuCounterInitializing.store(false);
                        return;
                    }

                    kSafeThis->cpuPerfQueryHandle_ = kCounterBundle.cpuQueryHandle;
                    kSafeThis->coreCounterHandles_ = kCounterBundle.coreCounterHandles;
                    kSafeThis->cpuPerformanceCounterHandle_ = kCounterBundle.cpuPerformanceCounterHandle;
                    kSafeThis->cpuFrequencyCounterHandle_ = kCounterBundle.cpuFrequencyCounterHandle;
                    hardwareDockCpuCounterInitializing.store(false);
                },
                Qt::QueuedConnection);

            if (!kInvokeOk)
            {
                closeHardwareDockCpuCounters(kCounterBundle);
                hardwareDockCpuCounterInitializing.store(false);
            }
        });
}

void HardwareDock::refreshAllViews()
{
    std::vector<double> coreUsageList;
    coreUsageList.reserve(coreChartEntries_.size());
    double totalCpuUsage = 0.0;
    if (!samplePerCoreUsage(&coreUsageList, &totalCpuUsage))
    {
        coreUsageList.assign(coreChartEntries_.size(), 0.0);
        totalCpuUsage = 0.0;
    }

    double memoryUsagePercent = 0.0;
    sampleMemoryUsage(&memoryUsagePercent);

    double diskReadBytesPerSec = 0.0;
    double diskWriteBytesPerSec = 0.0;
    double diskReadAverageBytesPerSec = 0.0;
    double diskWriteAverageBytesPerSec = 0.0;
    std::vector<DiskRateSample> diskSampleList;
    if (sampleDiskRates(&diskSampleList))
    {
        for (const DiskRateSample& sample : diskSampleList)
        {
            diskReadBytesPerSec += std::max(0.0, sample.readBytesPerSec);
            diskWriteBytesPerSec += std::max(0.0, sample.writeBytesPerSec);
        }
        if (!diskSampleList.empty())
        {
            const double kDiskCount = static_cast<double>(diskSampleList.size());
            diskReadAverageBytesPerSec = diskReadBytesPerSec / kDiskCount;
            diskWriteAverageBytesPerSec = diskWriteBytesPerSec / kDiskCount;
        }
    }
    else
    {
        diskReadBytesPerSec = 0.0;
        diskWriteBytesPerSec = 0.0;
    }

    double networkRxBytesPerSec = 0.0;
    double networkTxBytesPerSec = 0.0;
    double networkRxAverageBytesPerSec = 0.0;
    double networkTxAverageBytesPerSec = 0.0;
    std::vector<NetworkRateSample> networkSampleList;
    if (sampleNetworkRates(&networkSampleList))
    {
        for (const NetworkRateSample& sample : networkSampleList)
        {
            networkRxBytesPerSec += std::max(0.0, sample.rxBytesPerSec);
            networkTxBytesPerSec += std::max(0.0, sample.txBytesPerSec);
        }
        if (!networkSampleList.empty())
        {
            const double kNetworkCount = static_cast<double>(networkSampleList.size());
            networkRxAverageBytesPerSec = networkRxBytesPerSec / kNetworkCount;
            networkTxAverageBytesPerSec = networkTxBytesPerSec / kNetworkCount;
        }
    }
    else
    {
        networkRxBytesPerSec = 0.0;
        networkTxBytesPerSec = 0.0;
    }

    double gpuUsagePercent = 0.0;
    double gpuUsageAveragePercent = 0.0;
    std::vector<GpuUsageSample> gpuSampleList;
    if (sampleGpuUsages(&gpuSampleList))
    {
        double gpuUsageSum = 0.0;
        for (const GpuUsageSample& sample : gpuSampleList)
        {
            gpuUsagePercent = std::max(gpuUsagePercent, sample.overallUsagePercent);
            gpuUsageSum += std::clamp(sample.overallUsagePercent, 0.0, 100.0);
        }
        if (!gpuSampleList.empty())
        {
            gpuUsageAveragePercent = gpuUsageSum / static_cast<double>(gpuSampleList.size());
        }
    }
    else
    {
        gpuUsagePercent = 0.0;
    }

    std::vector<CpuPowerSnapshot> powerInfoList;
    sampleCpuPowerInfo(&powerInfoList);
    double sampledCpuSpeedGhz = 0.0;
    lastCpuSpeedGhz_ = sampleCpuEffectiveSpeed(&sampledCpuSpeedGhz)
        ? sampledCpuSpeedGhz
        : 0.0;

    ++sampleCounter_;
    pushBoundedHistorySample(&cpuUsageHistoryPercent_, totalCpuUsage);
    pushBoundedHistorySample(&memoryUsageHistoryPercent_, memoryUsagePercent);
    pushBoundedHistorySample(&gpuUsageHistoryPercent_, gpuUsagePercent);
    pushBoundedHistorySample(
        &diskAggregateHistoryBytesPerSec_,
        std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec));
    pushBoundedHistorySample(
        &networkAggregateHistoryBytesPerSec_,
        std::max(0.0, networkRxBytesPerSec) + std::max(0.0, networkTxBytesPerSec));
    if (driverHealthSamplingEnabled_)
    {
        requestAsyncR0HardwareHealthRefresh();
    }
    updateOverviewText(totalCpuUsage, memoryUsagePercent);
    updateUtilizationView(
        coreUsageList,
        memoryUsagePercent,
        diskReadBytesPerSec,
        diskWriteBytesPerSec,
        networkRxBytesPerSec,
        networkTxBytesPerSec,
        gpuUsagePercent);
    updateAdditionalDiskUtilizationDevices(diskSampleList);
    updateAdditionalNetworkUtilizationDevices(networkSampleList);
    updateAdditionalGpuUtilizationDevices(gpuSampleList);
    updateCpuDetailTable(coreUsageList, powerInfoList);
    updateTaskManagerDetailLabels(
        coreUsageList,
        powerInfoList,
        memoryUsagePercent,
        diskReadBytesPerSec,
        diskWriteBytesPerSec,
        networkRxBytesPerSec,
        networkTxBytesPerSec,
        gpuUsagePercent);
    emit performanceSnapshotChanged(
        totalCpuUsage,
        memoryUsagePercent,
        diskReadAverageBytesPerSec,
        diskWriteAverageBytesPerSec,
        networkRxAverageBytesPerSec,
        networkTxAverageBytesPerSec,
        gpuUsageAveragePercent);
    // Heavy reordering is only performed during resize/tab switching to avoid core container jitter caused by recalculating every second.

    // Periodic refresh strategy:
    // - Sensors are asynchronously refreshed every 5 seconds.
    // - Static text is asynchronously updated every 60 seconds (balancing information timeliness with system overhead).
    if ((sampleCounter_ % 5) == 1)
    {
        requestAsyncSensorRefresh();
    }
    if ((sampleCounter_ % 60) == 1)
    {
        requestAsyncStaticInfoRefresh();
    }
}

bool HardwareDock::samplePerCoreUsage(
    std::vector<double>* coreUsageOut,
    double* totalUsageOut)
{
    if (coreUsageOut == nullptr || totalUsageOut == nullptr)
    {
        return false;
    }
    if (cpuPerfQueryHandle_ == nullptr)
    {
        initializePerformanceCounters();
    }
    if (cpuPerfQueryHandle_ == nullptr)
    {
        return false;
    }

    const PDH_HQUERY kQueryHandle = reinterpret_cast<PDH_HQUERY>(cpuPerfQueryHandle_);
    const PDH_STATUS kCollectStatus = ::PdhCollectQueryData(kQueryHandle);
    if (kCollectStatus != ERROR_SUCCESS)
    {
        return false;
    }

    coreUsageOut->clear();
    coreUsageOut->reserve(coreCounterHandles_.size());
    double usageSum = 0.0;
    int validCount = 0;

    for (void* counterHandleVoid : coreCounterHandles_)
    {
        if (counterHandleVoid == nullptr)
        {
            coreUsageOut->push_back(0.0);
            continue;
        }

        PDH_FMT_COUNTERVALUE formattedValue{};
        const PDH_STATUS kReadStatus = ::PdhGetFormattedCounterValue(
            reinterpret_cast<PDH_HCOUNTER>(counterHandleVoid),
            PDH_FMT_DOUBLE,
            nullptr,
            &formattedValue);
        if (kReadStatus != ERROR_SUCCESS)
        {
            coreUsageOut->push_back(0.0);
            continue;
        }

        const double kUsageValue = std::clamp(formattedValue.doubleValue, 0.0, 100.0);
        coreUsageOut->push_back(kUsageValue);
        usageSum += kUsageValue;
        ++validCount;
    }

    *totalUsageOut = validCount > 0 ? (usageSum / static_cast<double>(validCount)) : 0.0;
    return true;
}

bool HardwareDock::sampleCpuEffectiveSpeed(double* speedGhzOut) const
{
    if (speedGhzOut == nullptr
        || cpuPerformanceCounterHandle_ == nullptr
        || cpuFrequencyCounterHandle_ == nullptr)
    {
        return false;
    }

    const auto kReadCounterValue =
        [](void* counterHandle, double* valueOut)
        {
            if (counterHandle == nullptr || valueOut == nullptr)
            {
                return false;
            }
            PDH_FMT_COUNTERVALUE formattedValue{};
            const PDH_STATUS kStatus = ::PdhGetFormattedCounterValue(
                reinterpret_cast<PDH_HCOUNTER>(counterHandle),
                PDH_FMT_DOUBLE,
                nullptr,
                &formattedValue);
            if (kStatus != ERROR_SUCCESS
                || (formattedValue.CStatus != PDH_CSTATUS_VALID_DATA
                    && formattedValue.CStatus != PDH_CSTATUS_NEW_DATA)
                || !std::isfinite(formattedValue.doubleValue))
            {
                return false;
            }
            *valueOut = formattedValue.doubleValue;
            return true;
        };

    double performancePercent = 0.0;
    double baseFrequencyMhz = 0.0;
    if (!kReadCounterValue(cpuPerformanceCounterHandle_, &performancePercent)
        || !kReadCounterValue(cpuFrequencyCounterHandle_, &baseFrequencyMhz))
    {
        return false;
    }

    const double kEffectiveFrequencyMhz = baseFrequencyMhz * performancePercent / 100.0;
    if (!std::isfinite(kEffectiveFrequencyMhz)
        || kEffectiveFrequencyMhz <= 0.0
        || kEffectiveFrequencyMhz > 20000.0)
    {
        return false;
    }

    *speedGhzOut = kEffectiveFrequencyMhz / 1000.0;
    return true;
}

bool HardwareDock::sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>* powerInfoOut)
{
    if (powerInfoOut == nullptr)
    {
        return false;
    }

    const ULONG kLogicalProcessorCount = std::max<ULONG>(
        1,
        static_cast<ULONG>(coreChartEntries_.size()));
    // KsProcessorPowerInformation Purpose:
    // - Maintain binary compatibility with the output structure of CallNtPowerInformation(ProcessorInformation).
    // Avoid compilation failures caused by missing PROCESSOR_POWER_INFORMATION definitions in different SDK versions.
    struct KsProcessorPowerInformation
    {
        ULONG number;            // Number: Logical processor ID.
        ULONG maxMhz;            // MaxMhz: Maximum frequency.
        ULONG currentMhz;        // CurrentMhz: Current frequency.
        ULONG mhzLimit;          // MhzLimit: Frequency limit upper bound.
        ULONG maxIdleState;      // MaxIdleState: Maximum idle state.
        ULONG currentIdleState;  // CurrentIdleState: Current idle state.
    };
    std::vector<KsProcessorPowerInformation> nativeInfoList(kLogicalProcessorCount);

    const NTSTATUS kNtStatus = ::CallNtPowerInformation(
        ProcessorInformation,
        nullptr,
        0,
        nativeInfoList.data(),
        static_cast<ULONG>(nativeInfoList.size() * sizeof(KsProcessorPowerInformation)));
    if (kNtStatus != 0)
    {
        return false;
    }

    powerInfoOut->clear();
    powerInfoOut->reserve(nativeInfoList.size());
    for (const KsProcessorPowerInformation& nativeInfo : nativeInfoList)
    {
        CpuPowerSnapshot snapshot;
        snapshot.coreIndex = nativeInfo.number;
        snapshot.currentMhz = nativeInfo.currentMhz;
        snapshot.maxMhz = nativeInfo.maxMhz;
        snapshot.limitMhz = nativeInfo.mhzLimit;
        powerInfoOut->push_back(snapshot);
    }
    return true;
}

bool HardwareDock::sampleMemoryUsage(double* memoryUsagePercentOut)
{
    if (memoryUsagePercentOut == nullptr)
    {
        return false;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus) == FALSE)
    {
        *memoryUsagePercentOut = 0.0;
        return false;
    }

    *memoryUsagePercentOut = static_cast<double>(memoryStatus.dwMemoryLoad);
    return true;
}

bool HardwareDock::sampleDiskRates(std::vector<DiskRateSample>* sampleListOut)
{
    if (sampleListOut == nullptr)
    {
        return false;
    }

    if (diskPerfQueryHandle_ == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER readCounterHandle = nullptr;
        PDH_HCOUNTER writeCounterHandle = nullptr;
        const PDH_STATUS kAddReadStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(*)\\Disk Read Bytes/sec",
            0,
            &readCounterHandle);
        const PDH_STATUS kAddWriteStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\PhysicalDisk(*)\\Disk Write Bytes/sec",
            0,
            &writeCounterHandle);
        if (kAddReadStatus != ERROR_SUCCESS || kAddWriteStatus != ERROR_SUCCESS)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        diskPerfQueryHandle_ = queryHandle;
        diskReadCounterHandle_ = readCounterHandle;
        diskWriteCounterHandle_ = writeCounterHandle;
        ::PdhCollectQueryData(queryHandle);
    }

    const PDH_HQUERY kQueryHandle = reinterpret_cast<PDH_HQUERY>(diskPerfQueryHandle_);
    if (::PdhCollectQueryData(kQueryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD readBufferSize = 0;
    DWORD readItemCount = 0;
    PDH_STATUS readQueryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(diskReadCounterHandle_),
        PDH_FMT_DOUBLE,
        &readBufferSize,
        &readItemCount,
        nullptr);
    if (readQueryStatus != PDH_MORE_DATA || readBufferSize == 0 || readItemCount == 0)
    {
        sampleListOut->clear();
        return true;
    }

    std::vector<unsigned char> readBuffer(readBufferSize);
    PDH_FMT_COUNTERVALUE_ITEM_W* readItemPointer =
        reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(readBuffer.data());
    readQueryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(diskReadCounterHandle_),
        PDH_FMT_DOUBLE,
        &readBufferSize,
        &readItemCount,
        readItemPointer);
    if (readQueryStatus != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD writeBufferSize = 0;
    DWORD writeItemCount = 0;
    PDH_STATUS writeQueryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(diskWriteCounterHandle_),
        PDH_FMT_DOUBLE,
        &writeBufferSize,
        &writeItemCount,
        nullptr);
    if (writeQueryStatus != PDH_MORE_DATA || writeBufferSize == 0 || writeItemCount == 0)
    {
        return false;
    }

    std::vector<unsigned char> writeBuffer(writeBufferSize);
    PDH_FMT_COUNTERVALUE_ITEM_W* writeItemPointer =
        reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(writeBuffer.data());
    writeQueryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(diskWriteCounterHandle_),
        PDH_FMT_DOUBLE,
        &writeBufferSize,
        &writeItemCount,
        writeItemPointer);
    if (writeQueryStatus != ERROR_SUCCESS)
    {
        return false;
    }

    sampleListOut->clear();
    sampleListOut->reserve(readItemCount);
    for (DWORD readIndex = 0; readIndex < readItemCount; ++readIndex)
    {
        const PDH_FMT_COUNTERVALUE_ITEM_W& readItem = readItemPointer[readIndex];
        const QString kInstanceNameText = QString::fromWCharArray(
            readItem.szName != nullptr ? readItem.szName : L"").trimmed();
        if (kInstanceNameText.isEmpty() || kInstanceNameText == QStringLiteral("_Total"))
        {
            continue;
        }
        if (readItem.FmtValue.CStatus != ERROR_SUCCESS)
        {
            continue;
        }

        DiskRateSample sample;
        sample.instanceNameText = kInstanceNameText;
        sample.displayNameText = simplifyDiskInstanceName(kInstanceNameText);
        sample.readBytesPerSec = std::max(0.0, readItem.FmtValue.doubleValue);
        for (DWORD writeIndex = 0; writeIndex < writeItemCount; ++writeIndex)
        {
            const PDH_FMT_COUNTERVALUE_ITEM_W& writeItem = writeItemPointer[writeIndex];
            const QString kWriteInstanceNameText = QString::fromWCharArray(
                writeItem.szName != nullptr ? writeItem.szName : L"").trimmed();
            if (QString::compare(kWriteInstanceNameText, kInstanceNameText, Qt::CaseInsensitive) == 0
                && writeItem.FmtValue.CStatus == ERROR_SUCCESS)
            {
                sample.writeBytesPerSec = std::max(0.0, writeItem.FmtValue.doubleValue);
                break;
            }
        }
        sampleListOut->push_back(sample);
    }
    return true;
}

bool HardwareDock::sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut)
{
    if (readBytesPerSecOut == nullptr || writeBytesPerSecOut == nullptr)
    {
        return false;
    }

    std::vector<DiskRateSample> sampleList;
    const bool kSampleOk = sampleDiskRates(&sampleList);
    if (!kSampleOk)
    {
        return false;
    }

    double totalReadBytesPerSec = 0.0;
    double totalWriteBytesPerSec = 0.0;
    for (const DiskRateSample& sample : sampleList)
    {
        totalReadBytesPerSec += std::max(0.0, sample.readBytesPerSec);
        totalWriteBytesPerSec += std::max(0.0, sample.writeBytesPerSec);
    }
    *readBytesPerSecOut = totalReadBytesPerSec;
    *writeBytesPerSecOut = totalWriteBytesPerSec;
    return true;
}

bool HardwareDock::sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut)
{
    if (rxBytesPerSecOut == nullptr || txBytesPerSecOut == nullptr)
    {
        return false;
    }

    MIB_IF_TABLE2* tablePointer = nullptr;
    if (::GetIfTable2(&tablePointer) != NO_ERROR || tablePointer == nullptr)
    {
        return false;
    }

    std::uint64_t totalRxBytes = 0;
    std::uint64_t totalTxBytes = 0;
    std::uint64_t primaryTrafficBytes = 0;
    QString primaryAdapterName;
    std::uint64_t primaryLinkBitsPerSecond = 0;
    for (ULONG rowIndex = 0; rowIndex < tablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = tablePointer->Table[rowIndex];
        if (rowValue.OperStatus != IfOperStatusUp)
        {
            continue;
        }
        if (rowValue.Type == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }

        totalRxBytes += static_cast<std::uint64_t>(rowValue.InOctets);
        totalTxBytes += static_cast<std::uint64_t>(rowValue.OutOctets);

        // Align with Task Manager display metric:
        // - Selects the active network interface with the highest 'cumulative traffic' as the primary display interface.
        // - Record the link speed for display on the details page.
        const std::uint64_t kRowTrafficBytes = static_cast<std::uint64_t>(rowValue.InOctets)
            + static_cast<std::uint64_t>(rowValue.OutOctets);
        if (kRowTrafficBytes >= primaryTrafficBytes)
        {
            primaryTrafficBytes = kRowTrafficBytes;
            primaryAdapterName = QString::fromWCharArray(rowValue.Alias);
            primaryLinkBitsPerSecond = std::max<std::uint64_t>(
                static_cast<std::uint64_t>(rowValue.ReceiveLinkSpeed),
                static_cast<std::uint64_t>(rowValue.TransmitLinkSpeed));
        }
    }
    ::FreeMibTable(tablePointer);

    primaryNetworkAdapterName_ = primaryAdapterName;
    primaryNetworkLinkBitsPerSecond_ = primaryLinkBitsPerSecond;

    const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
    if (lastNetworkSampleMs_ <= 0)
    {
        lastNetworkSampleMs_ = kNowMs;
        lastNetworkRxBytes_ = totalRxBytes;
        lastNetworkTxBytes_ = totalTxBytes;
        *rxBytesPerSecOut = 0.0;
        *txBytesPerSecOut = 0.0;
        return true;
    }

    const qint64 kElapsedMs = kNowMs - lastNetworkSampleMs_;
    if (kElapsedMs <= 0)
    {
        return false;
    }

    const std::uint64_t kDeltaRx = totalRxBytes >= lastNetworkRxBytes_
        ? (totalRxBytes - lastNetworkRxBytes_)
        : 0;
    const std::uint64_t kDeltaTx = totalTxBytes >= lastNetworkTxBytes_
        ? (totalTxBytes - lastNetworkTxBytes_)
        : 0;
    lastNetworkSampleMs_ = kNowMs;
    lastNetworkRxBytes_ = totalRxBytes;
    lastNetworkTxBytes_ = totalTxBytes;

    *rxBytesPerSecOut = static_cast<double>(kDeltaRx) * 1000.0 / static_cast<double>(kElapsedMs);
    *txBytesPerSecOut = static_cast<double>(kDeltaTx) * 1000.0 / static_cast<double>(kElapsedMs);
    return true;
}

bool HardwareDock::sampleNetworkRates(std::vector<NetworkRateSample>* sampleListOut)
{
    if (sampleListOut == nullptr)
    {
        return false;
    }

    MIB_IF_TABLE2* tablePointer = nullptr;
    if (::GetIfTable2(&tablePointer) != NO_ERROR || tablePointer == nullptr)
    {
        return false;
    }

    sampleListOut->clear();
    sampleListOut->reserve(tablePointer->NumEntries);
    const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
    std::uint64_t primaryTrafficBytes = 0;
    QString primaryAdapterName;
    std::uint64_t primaryLinkBitsPerSecond = 0;
    for (ULONG rowIndex = 0; rowIndex < tablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = tablePointer->Table[rowIndex];
        if (rowValue.OperStatus != IfOperStatusUp)
        {
            continue;
        }
        if (rowValue.Type == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }

        NetworkRateSample sample;
        sample.interfaceKey = interfaceLuidToKey(static_cast<std::uint64_t>(rowValue.InterfaceLuid.Value));
        sample.displayNameText = QString::fromWCharArray(rowValue.Alias).trimmed();
        if (sample.displayNameText.isEmpty())
        {
            sample.displayNameText = QString::fromWCharArray(rowValue.Description).trimmed();
        }
        sample.linkBitsPerSecond = std::max<std::uint64_t>(
            static_cast<std::uint64_t>(rowValue.ReceiveLinkSpeed),
            static_cast<std::uint64_t>(rowValue.TransmitLinkSpeed));
        sample.totalRxBytes = static_cast<std::uint64_t>(rowValue.InOctets);
        sample.totalTxBytes = static_cast<std::uint64_t>(rowValue.OutOctets);

        const int kDeviceIndex = ensureNetworkUtilizationDevice(
            sample,
            static_cast<int>(sampleListOut->size()));
        if (kDeviceIndex >= 0 && kDeviceIndex < static_cast<int>(networkUtilDevices_.size()))
        {
            NetworkUtilizationDevice& device = networkUtilDevices_[static_cast<std::size_t>(kDeviceIndex)];
            const qint64 kElapsedMs = kNowMs - device.lastSampleMs;
            if (device.hasPreviousSample && kElapsedMs > 0)
            {
                const std::uint64_t kDeltaRx = sample.totalRxBytes >= device.lastRxBytes
                    ? (sample.totalRxBytes - device.lastRxBytes)
                    : 0;
                const std::uint64_t kDeltaTx = sample.totalTxBytes >= device.lastTxBytes
                    ? (sample.totalTxBytes - device.lastTxBytes)
                    : 0;
                sample.rxBytesPerSec = static_cast<double>(kDeltaRx) * 1000.0 / static_cast<double>(kElapsedMs);
                sample.txBytesPerSec = static_cast<double>(kDeltaTx) * 1000.0 / static_cast<double>(kElapsedMs);
            }
            device.lastRxBytes = sample.totalRxBytes;
            device.lastTxBytes = sample.totalTxBytes;
            device.lastSampleMs = kNowMs;
            device.linkBitsPerSecond = sample.linkBitsPerSecond;
            device.hasPreviousSample = true;
        }
        const std::uint64_t kTrafficBytes = sample.totalRxBytes + sample.totalTxBytes;
        if (kTrafficBytes >= primaryTrafficBytes)
        {
            primaryTrafficBytes = kTrafficBytes;
            primaryAdapterName = sample.displayNameText;
            primaryLinkBitsPerSecond = sample.linkBitsPerSecond;
        }
        sampleListOut->push_back(sample);
    }
    ::FreeMibTable(tablePointer);
    primaryNetworkAdapterName_ = primaryAdapterName;
    primaryNetworkLinkBitsPerSecond_ = primaryLinkBitsPerSecond;
    return true;
}

bool HardwareDock::sampleGpuUsages(std::vector<GpuUsageSample>* sampleListOut)
{
    if (sampleListOut == nullptr)
    {
        return false;
    }

    // GpuSamplingSharedState:
    // - GPU sampling requires DXGI full adapter enumeration plus a fully instantiated array formatted with \GPU Engine(*) wildcards; the
    //   instance count equals 'process count × engine type'. Placing this in a per-second timer would continuously occupy the UI thread.
    // - Move the entire collection to a background task; the UI thread only reads the latest snapshot.
    // - Background tasks only read/write this shared state; they do not touch any QWidget.
    struct GpuSamplingSharedState
    {
        std::mutex stateMutex;                        // stateMutex: Protects the snapshot and PDH handle.
        std::vector<GpuUsageSample> cachedSampleList; // cachedSampleList: The most recent sampling snapshot.
        bool samplingInFlight = false;                // samplingInFlight: Whether a background sampling operation is already in progress.
        void* pdhQueryHandle = nullptr;               // pdhQueryHandle: GPU PDH query handle.
        void* engineCounterHandle = nullptr;          // engineCounterHandle: GPU engine utilization counter handle.
        void* dedicatedMemoryCounterHandle = nullptr; // dedicatedMemoryCounterHandle: handle for the dedicated video memory usage counter.
        void* sharedMemoryCounterHandle = nullptr;    // sharedMemoryCounterHandle: Handle for the shared video memory usage counter.
    };

    // Shared state is intentionally heap-allocated and never freed:
    // Background sampling may still be running during process exit; static object destruction could race with it.
    // - PDH query handles are also centrally reclaimed upon process exit to avoid closing queries that are currently in use.
    static GpuSamplingSharedState* const kGpuSamplingSharedState = new GpuSamplingSharedState();
    GpuSamplingSharedState* const kSamplingStatePointer = kGpuSamplingSharedState;

    // shouldStartBackgroundSampling usage: Determine whether to dispatch a new round of background sampling during this refresh.
    bool shouldStartBackgroundSampling = false;
    {
        const std::lock_guard<std::mutex> kStateLock(kSamplingStatePointer->stateMutex);
        *sampleListOut = kSamplingStatePointer->cachedSampleList;
        if (!kSamplingStatePointer->samplingInFlight)
        {
            kSamplingStatePointer->samplingInFlight = true;
            shouldStartBackgroundSampling = true;
        }
    }

    if (shouldStartBackgroundSampling)
    {
        QThreadPool::globalInstance()->start(
            [kSamplingStatePointer]()
            {
                // DXGI and PDH operations are completed entirely within this thread; COM interface pointers are not passed across threads.
                const HRESULT kComInitializeStatus = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

                // Retrieve handles within the lock and write them back at the end:
                // - Only one sampling task runs at a time, but the task may be executed on different threads.
                // - Establishes memory visibility via a mutex to prevent writes from the previous round from being invisible in the current round.
                void* gpuQueryHandle = nullptr;
                void* engineCounterHandle = nullptr;
                void* dedicatedMemoryCounterHandle = nullptr;
                void* sharedMemoryCounterHandle = nullptr;
                {
                    const std::lock_guard<std::mutex> kStateLock(kSamplingStatePointer->stateMutex);
                    gpuQueryHandle = kSamplingStatePointer->pdhQueryHandle;
                    engineCounterHandle = kSamplingStatePointer->engineCounterHandle;
                    dedicatedMemoryCounterHandle = kSamplingStatePointer->dedicatedMemoryCounterHandle;
                    sharedMemoryCounterHandle = kSamplingStatePointer->sharedMemoryCounterHandle;
                }

                // oneGiBInBytes usage: Convert DXGI byte fields to common GiB text used in Task Manager.
                constexpr double kOneGiBInBytes = 1024.0 * 1024.0 * 1024.0;
                // collectedSampleList usage: Results of this collection round; replaces the shared snapshot entirely upon success.
                std::vector<GpuUsageSample> collectedSampleList;
                // collectSucceeded: On DXGI enumeration failure, retains the previous snapshot and does not clear the UI data.
                bool collectSucceeded = false;

                IDXGIFactory6* factoryPointer = nullptr;
                const HRESULT kCreateFactoryStatus = ::CreateDXGIFactory1(IID_PPV_ARGS(&factoryPointer));
                if (SUCCEEDED(kCreateFactoryStatus) && factoryPointer != nullptr)
                {
                    collectSucceeded = true;
                    for (UINT adapterIndex = 0;; ++adapterIndex)
                    {
                        IDXGIAdapter1* adapterPointer = nullptr;
                        const HRESULT kEnumStatus = factoryPointer->EnumAdapters1(adapterIndex, &adapterPointer);
                        if (kEnumStatus == DXGI_ERROR_NOT_FOUND)
                        {
                            break;
                        }
                        if (FAILED(kEnumStatus) || adapterPointer == nullptr)
                        {
                            continue;
                        }

                        DXGI_ADAPTER_DESC1 adapterDesc{};
                        adapterPointer->GetDesc1(&adapterDesc);
                        if ((adapterDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0)
                        {
                            adapterPointer->Release();
                            continue;
                        }

                        GpuUsageSample sample;
                        sample.adapterKey = packLuidKey(adapterDesc.AdapterLuid);
                        sample.adapterIndex = static_cast<int>(adapterIndex);
                        sample.displayNameText = QString::fromWCharArray(adapterDesc.Description).trimmed();
                        sample.dedicatedMemoryGiB = static_cast<double>(adapterDesc.DedicatedVideoMemory) / kOneGiBInBytes;
                        sample.sharedMemoryGiB = static_cast<double>(adapterDesc.SharedSystemMemory) / kOneGiBInBytes;

                        GpuAdapterTelemetrySnapshot telemetrySnapshot;
                        if (queryGpuAdapterTelemetrySnapshot(adapterDesc.AdapterLuid, &telemetrySnapshot))
                        {
                            sample.currentCoreClockMhz = telemetrySnapshot.currentCoreClockMhz;
                            sample.maxCoreClockMhz = telemetrySnapshot.maxCoreClockMhz;
                            sample.currentMemoryClockMhz = telemetrySnapshot.currentMemoryClockMhz;
                            sample.maxMemoryClockMhz = telemetrySnapshot.maxMemoryClockMhz;
                            if (telemetrySnapshot.dedicatedVideoMemoryBytes > 0)
                            {
                                sample.dedicatedMemoryGiB =
                                    static_cast<double>(telemetrySnapshot.dedicatedVideoMemoryBytes) / kOneGiBInBytes;
                            }
                            if (telemetrySnapshot.sharedSystemMemoryBytes > 0)
                            {
                                sample.sharedMemoryGiB =
                                    static_cast<double>(telemetrySnapshot.sharedSystemMemoryBytes) / kOneGiBInBytes;
                            }
                        }

                        IDXGIAdapter3* adapter3Pointer = nullptr;
                        const HRESULT kQueryInterfaceStatus = adapterPointer->QueryInterface(
                            IID_PPV_ARGS(&adapter3Pointer));
                        if (SUCCEEDED(kQueryInterfaceStatus) && adapter3Pointer != nullptr)
                        {
                            DXGI_QUERY_VIDEO_MEMORY_INFO localMemoryInfo{};
                            DXGI_QUERY_VIDEO_MEMORY_INFO nonLocalMemoryInfo{};
                            const HRESULT kLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                                0,
                                DXGI_MEMORY_SEGMENT_GROUP_LOCAL,
                                &localMemoryInfo);
                            const HRESULT kNonLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                                0,
                                DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                                &nonLocalMemoryInfo);
                            if (SUCCEEDED(kLocalStatus))
                            {
                                // CurrentUsage only represents the current process's GPU memory commitment, not the total system GPU usage.
                                sample.dedicatedBudgetGiB =
                                    static_cast<double>(localMemoryInfo.Budget) / kOneGiBInBytes;
                            }
                            if (SUCCEEDED(kNonLocalStatus))
                            {
                                sample.sharedBudgetGiB =
                                    static_cast<double>(nonLocalMemoryInfo.Budget) / kOneGiBInBytes;
                            }
                            adapter3Pointer->Release();
                        }

                        if (sample.dedicatedMemoryGiB <= 0.0 && sample.dedicatedBudgetGiB > 0.0)
                        {
                            sample.dedicatedMemoryGiB = sample.dedicatedBudgetGiB;
                        }
                        if (sample.dedicatedBudgetGiB <= 0.0)
                        {
                            sample.dedicatedBudgetGiB = sample.dedicatedMemoryGiB;
                        }
                        if (sample.sharedMemoryGiB <= 0.0 && sample.sharedBudgetGiB > 0.0)
                        {
                            sample.sharedMemoryGiB = sample.sharedBudgetGiB;
                        }
                        if (sample.sharedMemoryGiB <= 0.0)
                        {
                            MEMORYSTATUSEX memoryStatus{};
                            memoryStatus.dwLength = sizeof(memoryStatus);
                            if (::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
                            {
                                const double kTotalMemoryGiB =
                                    static_cast<double>(memoryStatus.ullTotalPhys) / kOneGiBInBytes;
                                sample.sharedMemoryGiB = std::max(0.5, kTotalMemoryGiB * 0.5);
                            }
                        }
                        if (sample.sharedBudgetGiB <= 0.0)
                        {
                            sample.sharedBudgetGiB = sample.sharedMemoryGiB;
                        }

                        collectedSampleList.push_back(sample);
                        adapterPointer->Release();
                    }
                    factoryPointer->Release();
                }

                if (collectSucceeded && !collectedSampleList.empty())
                {
                    // memoryCounterReadable purpose: Only read the video memory array if a collect operation was actually completed in this round.
                    bool memoryCounterReadable = false;
                    if (gpuQueryHandle == nullptr)
                    {
                        // Registering the first \GPU Engine(*) wildcard instance incurs the highest overhead; it now runs entirely on a background thread.
                        PDH_HQUERY queryHandle = nullptr;
                        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) == ERROR_SUCCESS && queryHandle != nullptr)
                        {
                            PDH_HCOUNTER counterHandle = nullptr;
                            const PDH_STATUS kAddStatus = ::PdhAddEnglishCounterW(
                                queryHandle,
                                L"\\GPU Engine(*)\\Utilization Percentage",
                                0,
                                &counterHandle);
                            if (kAddStatus != ERROR_SUCCESS || counterHandle == nullptr)
                            {
                                ::PdhCloseQuery(queryHandle);
                            }
                            else
                            {
                                PDH_HCOUNTER newDedicatedMemoryCounterHandle = nullptr;
                                if (::PdhAddEnglishCounterW(
                                        queryHandle,
                                        L"\\GPU Adapter Memory(*)\\Dedicated Usage",
                                        0,
                                        &newDedicatedMemoryCounterHandle) != ERROR_SUCCESS)
                                {
                                    newDedicatedMemoryCounterHandle = nullptr;
                                }

                                PDH_HCOUNTER newSharedMemoryCounterHandle = nullptr;
                                if (::PdhAddEnglishCounterW(
                                        queryHandle,
                                        L"\\GPU Adapter Memory(*)\\Shared Usage",
                                        0,
                                        &newSharedMemoryCounterHandle) != ERROR_SUCCESS)
                                {
                                    newSharedMemoryCounterHandle = nullptr;
                                }

                                gpuQueryHandle = queryHandle;
                                engineCounterHandle = counterHandle;
                                dedicatedMemoryCounterHandle = newDedicatedMemoryCounterHandle;
                                sharedMemoryCounterHandle = newSharedMemoryCounterHandle;
                                ::PdhCollectQueryData(queryHandle);
                                ::Sleep(1);
                                ::PdhCollectQueryData(queryHandle);
                                memoryCounterReadable = true;
                            }
                        }
                    }
                    else if (::PdhCollectQueryData(reinterpret_cast<PDH_HQUERY>(gpuQueryHandle)) == ERROR_SUCCESS)
                    {
                        memoryCounterReadable = true;

                        DWORD bufferSize = 0;
                        DWORD itemCount = 0;
                        PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
                            reinterpret_cast<PDH_HCOUNTER>(engineCounterHandle),
                            PDH_FMT_DOUBLE,
                            &bufferSize,
                            &itemCount,
                            nullptr);
                        if (queryStatus == PDH_MORE_DATA && bufferSize > 0 && itemCount > 0)
                        {
                            std::vector<unsigned char> rawBuffer(bufferSize);
                            PDH_FMT_COUNTERVALUE_ITEM_W* itemPointer =
                                reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
                            queryStatus = ::PdhGetFormattedCounterArrayW(
                                reinterpret_cast<PDH_HCOUNTER>(engineCounterHandle),
                                PDH_FMT_DOUBLE,
                                &bufferSize,
                                &itemCount,
                                itemPointer);
                            if (queryStatus == ERROR_SUCCESS)
                            {
                                for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
                                {
                                    const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPointer[itemIndex];
                                    if (itemValue.FmtValue.CStatus != ERROR_SUCCESS)
                                    {
                                        continue;
                                    }

                                    const QString kEngineNameText = QString::fromWCharArray(
                                        itemValue.szName != nullptr ? itemValue.szName : L"");
                                    std::uint64_t adapterKey = 0;
                                    if (!parseGpuAdapterKeyFromCounterName(kEngineNameText, &adapterKey))
                                    {
                                        continue;
                                    }

                                    const QString kEngineKeyText = resolveGpuEngineKeyFromCounter(kEngineNameText);
                                    if (kEngineKeyText.isEmpty())
                                    {
                                        continue;
                                    }

                                    GpuUsageSample* samplePointer = nullptr;
                                    for (GpuUsageSample& sample : collectedSampleList)
                                    {
                                        if (sample.adapterKey == adapterKey)
                                        {
                                            samplePointer = &sample;
                                            break;
                                        }
                                    }
                                    if (samplePointer == nullptr)
                                    {
                                        continue;
                                    }

                                    const double kEngineUsagePercent =
                                        std::clamp(itemValue.FmtValue.doubleValue, 0.0, 100.0);
                                    if (kEngineKeyText == QStringLiteral("3d"))
                                    {
                                        samplePointer->usage3DPercent =
                                            std::max(samplePointer->usage3DPercent, kEngineUsagePercent);
                                    }
                                    else if (kEngineKeyText == QStringLiteral("copy"))
                                    {
                                        samplePointer->usageCopyPercent =
                                            std::max(samplePointer->usageCopyPercent, kEngineUsagePercent);
                                    }
                                    else if (kEngineKeyText == QStringLiteral("video_encode"))
                                    {
                                        samplePointer->usageVideoEncodePercent =
                                            std::max(samplePointer->usageVideoEncodePercent, kEngineUsagePercent);
                                    }
                                    else if (kEngineKeyText == QStringLiteral("video_decode"))
                                    {
                                        samplePointer->usageVideoDecodePercent =
                                            std::max(samplePointer->usageVideoDecodePercent, kEngineUsagePercent);
                                    }
                                    samplePointer->overallUsagePercent =
                                        std::max(samplePointer->overallUsagePercent, kEngineUsagePercent);
                                }
                            }
                        }
                    }

                    // GPU Adapter Memory is the WDDM system-level GPU memory usage; after aggregating by LUID in the instance name, it
                    // corresponds one-to-one with adapters enumerated by DXGI, avoiding treating KSword process's CurrentUsage as a global value.
                    const auto kApplyGpuMemoryCounter = [&collectedSampleList, kOneGiBInBytes](
                        void* counterHandleValue,
                        const bool dedicatedMemory)
                    {
                        if (counterHandleValue == nullptr)
                        {
                            return;
                        }

                        DWORD bufferSize = 0;
                        DWORD itemCount = 0;
                        PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
                            reinterpret_cast<PDH_HCOUNTER>(counterHandleValue),
                            PDH_FMT_DOUBLE,
                            &bufferSize,
                            &itemCount,
                            nullptr);
                        if (queryStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
                        {
                            return;
                        }

                        std::vector<unsigned char> rawBuffer(bufferSize);
                        PDH_FMT_COUNTERVALUE_ITEM_W* itemPointer =
                            reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
                        queryStatus = ::PdhGetFormattedCounterArrayW(
                            reinterpret_cast<PDH_HCOUNTER>(counterHandleValue),
                            PDH_FMT_DOUBLE,
                            &bufferSize,
                            &itemCount,
                            itemPointer);
                        if (queryStatus != ERROR_SUCCESS)
                        {
                            return;
                        }

                        for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
                        {
                            const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPointer[itemIndex];
                            const DWORD kValueStatus = itemValue.FmtValue.CStatus;
                            if (kValueStatus != PDH_CSTATUS_VALID_DATA
                                && kValueStatus != PDH_CSTATUS_NEW_DATA)
                            {
                                continue;
                            }

                            const QString kCounterNameText = QString::fromWCharArray(
                                itemValue.szName != nullptr ? itemValue.szName : L"");
                            std::uint64_t adapterKey = 0;
                            if (!parseGpuAdapterKeyFromCounterName(kCounterNameText, &adapterKey))
                            {
                                continue;
                            }

                            const auto kSampleIterator = std::find_if(
                                collectedSampleList.begin(),
                                collectedSampleList.end(),
                                [adapterKey](const GpuUsageSample& sample)
                                {
                                    return sample.adapterKey == adapterKey;
                                });
                            if (kSampleIterator == collectedSampleList.end())
                            {
                                continue;
                            }

                            const double kUsageGiB =
                                std::max(0.0, itemValue.FmtValue.doubleValue) / kOneGiBInBytes;
                            if (dedicatedMemory)
                            {
                                kSampleIterator->dedicatedUsedGiB += kUsageGiB;
                                kSampleIterator->dedicatedUsageAvailable = true;
                            }
                            else
                            {
                                kSampleIterator->sharedUsedGiB += kUsageGiB;
                                kSampleIterator->sharedUsageAvailable = true;
                            }
                        }
                    };

                    if (memoryCounterReadable)
                    {
                        kApplyGpuMemoryCounter(dedicatedMemoryCounterHandle, true);
                        kApplyGpuMemoryCounter(sharedMemoryCounterHandle, false);
                    }
                }

                {
                    const std::lock_guard<std::mutex> kStateLock(kSamplingStatePointer->stateMutex);
                    kSamplingStatePointer->pdhQueryHandle = gpuQueryHandle;
                    kSamplingStatePointer->engineCounterHandle = engineCounterHandle;
                    kSamplingStatePointer->dedicatedMemoryCounterHandle = dedicatedMemoryCounterHandle;
                    kSamplingStatePointer->sharedMemoryCounterHandle = sharedMemoryCounterHandle;
                    if (collectSucceeded)
                    {
                        kSamplingStatePointer->cachedSampleList = collectedSampleList;
                    }
                    kSamplingStatePointer->samplingInFlight = false;
                }

                if (SUCCEEDED(kComInitializeStatus))
                {
                    ::CoUninitialize();
                }
            });
    }

    if (sampleListOut->empty())
    {
        return true;
    }

    // The detail page creation and card registration must occur on the UI thread, so they are placed after the snapshot returns to this thread.
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleListOut->size()); ++sampleIndex)
    {
        ensureGpuUtilizationDevice(
            (*sampleListOut)[static_cast<std::size_t>(sampleIndex)],
            sampleIndex);
    }

    // Select the primary adapter with the largest dedicated VRAM from the old aggregated GPU page fix; do not reuse the frequency/VRAM of the 'first card' after merging utilization metrics.
    const auto kPrimarySampleIterator = std::max_element(
        sampleListOut->cbegin(),
        sampleListOut->cend(),
        [](const GpuUsageSample& leftSample, const GpuUsageSample& rightSample)
        {
            if (!qFuzzyCompare(
                    leftSample.dedicatedMemoryGiB + 1.0,
                    rightSample.dedicatedMemoryGiB + 1.0))
            {
                return leftSample.dedicatedMemoryGiB < rightSample.dedicatedMemoryGiB;
            }
            return leftSample.overallUsagePercent < rightSample.overallUsagePercent;
        });
    const GpuUsageSample& primarySample = *kPrimarySampleIterator;
    gpuAdapterNameText_ = primarySample.displayNameText;
    gpuCurrentCoreClockMhz_ = primarySample.currentCoreClockMhz;
    gpuMaxCoreClockMhz_ = primarySample.maxCoreClockMhz;
    gpuCurrentMemoryClockMhz_ = primarySample.currentMemoryClockMhz;
    gpuMaxMemoryClockMhz_ = primarySample.maxMemoryClockMhz;
    gpuDedicatedMemoryGiB_ = primarySample.dedicatedMemoryGiB;
    gpuSharedMemoryGiB_ = primarySample.sharedMemoryGiB;
    gpuDedicatedUsedGiB_ = primarySample.dedicatedUsedGiB;
    gpuDedicatedUsageAvailable_ = primarySample.dedicatedUsageAvailable;
    gpuDedicatedBudgetGiB_ = primarySample.dedicatedBudgetGiB;
    gpuSharedUsedGiB_ = primarySample.sharedUsedGiB;
    gpuSharedUsageAvailable_ = primarySample.sharedUsageAvailable;
    gpuSharedBudgetGiB_ = primarySample.sharedBudgetGiB;
    gpuUsage3DPercent_ = primarySample.usage3DPercent;
    gpuUsageCopyPercent_ = primarySample.usageCopyPercent;
    gpuUsageVideoEncodePercent_ = primarySample.usageVideoEncodePercent;
    gpuUsageVideoDecodePercent_ = primarySample.usageVideoDecodePercent;
    return true;
}

bool HardwareDock::sampleGpuUsage(double* gpuUsagePercentOut)
{
    if (gpuUsagePercentOut == nullptr)
    {
        return false;
    }

    if (gpuPerfQueryHandle_ == nullptr)
    {
        PDH_HQUERY queryHandle = nullptr;
        if (::PdhOpenQueryW(nullptr, 0, &queryHandle) != ERROR_SUCCESS || queryHandle == nullptr)
        {
            return false;
        }

        PDH_HCOUNTER counterHandle = nullptr;
        const PDH_STATUS kAddStatus = ::PdhAddEnglishCounterW(
            queryHandle,
            L"\\GPU Engine(*)\\Utilization Percentage",
            0,
            &counterHandle);
        if (kAddStatus != ERROR_SUCCESS || counterHandle == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            return false;
        }

        gpuPerfQueryHandle_ = queryHandle;
        gpuCounterHandle_ = counterHandle;
        ::PdhCollectQueryData(queryHandle);
        *gpuUsagePercentOut = 0.0;
        return true;
    }

    const PDH_HQUERY kQueryHandle = reinterpret_cast<PDH_HQUERY>(gpuPerfQueryHandle_);
    if (::PdhCollectQueryData(kQueryHandle) != ERROR_SUCCESS)
    {
        return false;
    }

    DWORD bufferSize = 0;
    DWORD itemCount = 0;
    PDH_STATUS queryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(gpuCounterHandle_),
        PDH_FMT_DOUBLE,
        &bufferSize,
        &itemCount,
        nullptr);
    if (queryStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
    {
        gpuUsage3DPercent_ = 0.0;
        gpuUsageCopyPercent_ = 0.0;
        gpuUsageVideoEncodePercent_ = 0.0;
        gpuUsageVideoDecodePercent_ = 0.0;
        *gpuUsagePercentOut = 0.0;
        sampleGpuMemoryInfoByDxgi();
        return true;
    }

    std::vector<unsigned char> rawBuffer(bufferSize);
    PDH_FMT_COUNTERVALUE_ITEM_W* itemPtr = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(rawBuffer.data());
    queryStatus = ::PdhGetFormattedCounterArrayW(
        reinterpret_cast<PDH_HCOUNTER>(gpuCounterHandle_),
        PDH_FMT_DOUBLE,
        &bufferSize,
        &itemCount,
        itemPtr);
    if (queryStatus != ERROR_SUCCESS)
    {
        gpuUsage3DPercent_ = 0.0;
        gpuUsageCopyPercent_ = 0.0;
        gpuUsageVideoEncodePercent_ = 0.0;
        gpuUsageVideoDecodePercent_ = 0.0;
        *gpuUsagePercentOut = 0.0;
        sampleGpuMemoryInfoByDxgi();
        return true;
    }

    // Task Manager 'Total GPU' approximation:
    // - Record peak usage first by engine category;
    // - Then take the maximum value among the four engine types as the overall utilization.
    double usage3DPercent = 0.0;
    double usageCopyPercent = 0.0;
    double usageVideoEncodePercent = 0.0;
    double usageVideoDecodePercent = 0.0;
    double peakUsage = 0.0;
    for (DWORD indexValue = 0; indexValue < itemCount; ++indexValue)
    {
        const PDH_FMT_COUNTERVALUE_ITEM_W& itemValue = itemPtr[indexValue];
        if (itemValue.FmtValue.CStatus != ERROR_SUCCESS)
        {
            continue;
        }

        // engineUsagePercent: Usage: Current counter sample value, clamped to 0~100.
        const double kEngineUsagePercent = std::clamp(itemValue.FmtValue.doubleValue, 0.0, 100.0);
        const QString kEngineNameText = QString::fromWCharArray(
            itemValue.szName != nullptr ? itemValue.szName : L"");
        const QString kEngineKeyText = resolveGpuEngineKeyFromCounter(kEngineNameText);
        if (kEngineKeyText == QStringLiteral("3d"))
        {
            usage3DPercent = std::max(usage3DPercent, kEngineUsagePercent);
        }
        else if (kEngineKeyText == QStringLiteral("copy"))
        {
            usageCopyPercent = std::max(usageCopyPercent, kEngineUsagePercent);
        }
        else if (kEngineKeyText == QStringLiteral("video_encode"))
        {
            usageVideoEncodePercent = std::max(usageVideoEncodePercent, kEngineUsagePercent);
        }
        else if (kEngineKeyText == QStringLiteral("video_decode"))
        {
            usageVideoDecodePercent = std::max(usageVideoDecodePercent, kEngineUsagePercent);
        }

        peakUsage = std::max(peakUsage, kEngineUsagePercent);
    }

    gpuUsage3DPercent_ = usage3DPercent;
    gpuUsageCopyPercent_ = usageCopyPercent;
    gpuUsageVideoEncodePercent_ = usageVideoEncodePercent;
    gpuUsageVideoDecodePercent_ = usageVideoDecodePercent;
    *gpuUsagePercentOut = std::clamp(peakUsage, 0.0, 100.0);
    sampleGpuMemoryInfoByDxgi();
    return true;
}

bool HardwareDock::sampleGpuMemoryInfoByDxgi()
{
    // oneGiBInBytes: Conversion factor for unified byte-to-GiB calculation.
    constexpr double kOneGiBInBytes = 1024.0 * 1024.0 * 1024.0;

    IDXGIFactory6* factoryPointer = nullptr;
    const HRESULT kCreateFactoryStatus = ::CreateDXGIFactory1(IID_PPV_ARGS(&factoryPointer));
    if (FAILED(kCreateFactoryStatus) || factoryPointer == nullptr)
    {
        return false;
    }

    bool querySuccess = false;
    for (UINT adapterIndex = 0;; ++adapterIndex)
    {
        IDXGIAdapter1* adapterPointer = nullptr;
        const HRESULT kEnumStatus = factoryPointer->EnumAdapters1(adapterIndex, &adapterPointer);
        if (kEnumStatus == DXGI_ERROR_NOT_FOUND)
        {
            break;
        }
        if (FAILED(kEnumStatus) || adapterPointer == nullptr)
        {
            continue;
        }

        DXGI_ADAPTER_DESC1 adapterDesc{};
        adapterPointer->GetDesc1(&adapterDesc);
        if ((adapterDesc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) != 0)
        {
            adapterPointer->Release();
            continue;
        }

        IDXGIAdapter3* adapter3Pointer = nullptr;
        const HRESULT kQueryInterfaceStatus = adapterPointer->QueryInterface(
            IID_PPV_ARGS(&adapter3Pointer));
        if (SUCCEEDED(kQueryInterfaceStatus) && adapter3Pointer != nullptr)
        {
            DXGI_QUERY_VIDEO_MEMORY_INFO localMemoryInfo{};
            DXGI_QUERY_VIDEO_MEMORY_INFO nonLocalMemoryInfo{};
            const HRESULT kLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                0,
                DXGI_MEMORY_SEGMENT_GROUP_LOCAL,
                &localMemoryInfo);
            const HRESULT kNonLocalStatus = adapter3Pointer->QueryVideoMemoryInfo(
                0,
                DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL,
                &nonLocalMemoryInfo);
            if (SUCCEEDED(kLocalStatus) && SUCCEEDED(kNonLocalStatus))
            {
                // DXGI CurrentUsage covers only the current process; the legacy compatibility path retains
                // only budget information and no longer disguises process-level data as system VRAM usage.
                gpuDedicatedUsedGiB_ = 0.0;
                gpuDedicatedUsageAvailable_ = false;
                gpuDedicatedBudgetGiB_ = static_cast<double>(localMemoryInfo.Budget) / kOneGiBInBytes;
                gpuSharedUsedGiB_ = 0.0;
                gpuSharedUsageAvailable_ = false;
                gpuSharedBudgetGiB_ = static_cast<double>(nonLocalMemoryInfo.Budget) / kOneGiBInBytes;

                // Some devices may return 0 for non-local budget; fall back to an approximation of half the physical memory.
                if (gpuSharedBudgetGiB_ <= 0.0)
                {
                    MEMORYSTATUSEX memoryStatus{};
                    memoryStatus.dwLength = sizeof(memoryStatus);
                    if (::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
                    {
                        const double kTotalMemoryGiB =
                            static_cast<double>(memoryStatus.ullTotalPhys) / kOneGiBInBytes;
                        gpuSharedBudgetGiB_ = std::max(0.5, kTotalMemoryGiB * 0.5);
                    }
                }

                const QString kAdapterNameText = QString::fromWCharArray(adapterDesc.Description).trimmed();
                if (!kAdapterNameText.isEmpty())
                {
                    gpuAdapterNameText_ = kAdapterNameText;
                }
                querySuccess = true;
            }
            adapter3Pointer->Release();
        }

        adapterPointer->Release();
        if (querySuccess)
        {
            break;
        }
    }

    factoryPointer->Release();
    return querySuccess;
}

bool HardwareDock::sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot* snapshotOut) const
{
    if (snapshotOut == nullptr)
    {
        return false;
    }

    PERFORMANCE_INFORMATION perfInfo{};
    perfInfo.cb = sizeof(perfInfo);
    if (::GetPerformanceInfo(&perfInfo, sizeof(perfInfo)) == FALSE)
    {
        return false;
    }

    // pageSizeBytes: Converts page count metrics to bytes.
    const std::uint64_t kPageSizeBytes = static_cast<std::uint64_t>(perfInfo.PageSize);
    snapshotOut->processCount = static_cast<std::uint32_t>(perfInfo.ProcessCount);
    snapshotOut->threadCount = static_cast<std::uint32_t>(perfInfo.ThreadCount);
    snapshotOut->handleCount = static_cast<std::uint32_t>(perfInfo.HandleCount);
    snapshotOut->commitTotalBytes = static_cast<std::uint64_t>(perfInfo.CommitTotal) * kPageSizeBytes;
    snapshotOut->commitLimitBytes = static_cast<std::uint64_t>(perfInfo.CommitLimit) * kPageSizeBytes;
    snapshotOut->cachedBytes = static_cast<std::uint64_t>(perfInfo.SystemCache) * kPageSizeBytes;
    snapshotOut->pagedPoolBytes = static_cast<std::uint64_t>(perfInfo.KernelPaged) * kPageSizeBytes;
    snapshotOut->nonPagedPoolBytes = static_cast<std::uint64_t>(perfInfo.KernelNonpaged) * kPageSizeBytes;
    return true;
}

void HardwareDock::updateOverviewText(const double cpuUsagePercent, const double memoryUsagePercent)
{
    if (overviewSummaryLabel_ == nullptr)
    {
        return;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    ::GlobalMemoryStatusEx(&memoryStatus);

    const QString kSummaryText = ks::i18n::contextText(
        QStringLiteral("hardware.overview.summary"),
        QStringLiteral("CPU总体利用率: %1%    内存利用率: %2%    可用内存: %3 / 总内存: %4    %5"))
        .arg(cpuUsagePercent, 0, 'f', 1)
        .arg(memoryUsagePercent, 0, 'f', 1)
        .arg(bytesToGiBText(memoryStatus.ullAvailPhys))
        .arg(bytesToGiBText(memoryStatus.ullTotalPhys))
        .arg(r0HardwareHealthSummaryText_);
    overviewSummaryLabel_->setText(kSummaryText);
}

void HardwareDock::updateUtilizationView(
    const std::vector<double>& coreUsageList,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    // averageCpuUsage usage: CPU average usage, displayed in the title and left navigation card.
    double averageCpuUsage = 0.0;
    if (!coreUsageList.empty())
    {
        for (const double kUsageValue : coreUsageList)
        {
            averageCpuUsage += kUsageValue;
        }
        averageCpuUsage /= static_cast<double>(coreUsageList.size());
    }

    if (utilizationSummaryLabel_ != nullptr)
    {
        const UtilizationStatisticSnapshot kCpuStats = buildStatisticSnapshot(cpuUsageHistoryPercent_);
        utilizationSummaryLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.cpu.summary"),
                QStringLiteral("30 秒内的利用率 %    总体：%1%    均值：%2%    峰值：%3%    趋势：%4    逻辑处理器：%5"))
            .arg(averageCpuUsage, 0, 'f', 1)
            .arg(kCpuStats.averageValue, 0, 'f', 1)
            .arg(kCpuStats.peakValue, 0, 'f', 1)
            .arg(buildTrendText(kCpuStats, true))
            .arg(coreUsageList.size()));
    }

    if (cpuModelLabel_ != nullptr && !cpuModelText_.isEmpty())
    {
        cpuModelLabel_->setText(cpuModelText_);
    }

    const int kChartCount = std::min(
        static_cast<int>(coreChartEntries_.size()),
        static_cast<int>(coreUsageList.size()));
    for (int indexValue = 0; indexValue < kChartCount; ++indexValue)
    {
        CoreChartEntry& chartEntry = coreChartEntries_[static_cast<std::size_t>(indexValue)];
        const double kUsageValue = coreUsageList[static_cast<std::size_t>(indexValue)];
        chartEntry.titleLabel->setText(
            QStringLiteral("CPU %1  %2%")
            .arg(indexValue, 2, 10, QLatin1Char('0'))
            .arg(kUsageValue, 5, 'f', 1, QLatin1Char(' ')));
        appendCoreSeriesPoint(chartEntry, kUsageValue);
    }

    // Memory sub-page: update summary and line trend.
    if (memoryUtilSummaryLabel_ != nullptr)
    {
        const UtilizationStatisticSnapshot kMemoryStats = buildStatisticSnapshot(memoryUsageHistoryPercent_);
        memoryUtilSummaryLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.memory.summary"),
                QStringLiteral("当前内存占用：%1%    均值：%2%    峰值：%3%    趋势：%4    %5"))
            .arg(memoryUsagePercent, 0, 'f', 1)
            .arg(kMemoryStats.averageValue, 0, 'f', 1)
            .arg(kMemoryStats.peakValue, 0, 'f', 1)
            .arg(buildTrendText(kMemoryStats, true))
            .arg(r0PhysicalMemorySummaryText_));
    }
    if (memoryCompositionHistoryWidget_ != nullptr)
    {
        MemoryCompositionHistoryWidget::CompositionSample memorySample;
        memorySample.usedPercent = memoryUsagePercent;

        SystemPerformanceSnapshot perfSnapshot;
        const bool kPerfOk = sampleSystemPerformanceSnapshot(&perfSnapshot);
        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        const bool kMemoryStatusOk = (::GlobalMemoryStatusEx(&memoryStatus) == TRUE);
        if (kPerfOk && kMemoryStatusOk && memoryStatus.ullTotalPhys > 0ULL)
        {
            const double kTotalPhysicalBytes = static_cast<double>(memoryStatus.ullTotalPhys);
            memorySample.cachedPercent = static_cast<double>(perfSnapshot.cachedBytes) / kTotalPhysicalBytes * 100.0;
            memorySample.pagedPoolPercent = static_cast<double>(perfSnapshot.pagedPoolBytes) / kTotalPhysicalBytes * 100.0;
            memorySample.nonPagedPoolPercent = static_cast<double>(perfSnapshot.nonPagedPoolBytes) / kTotalPhysicalBytes * 100.0;
        }
        memoryCompositionHistoryWidget_->appendSample(memorySample);
    }

    // Disk sub-page: Update read/write rate summary and line trend.
    if (diskUtilSummaryLabel_ != nullptr)
    {
        const UtilizationStatisticSnapshot kDiskStats = buildStatisticSnapshot(diskAggregateHistoryBytesPerSec_);
        diskUtilSummaryLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.disk.summary"),
                QStringLiteral("读取：%1    写入：%2    合计均值：%3    峰值：%4"))
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec))
            .arg(formatRateText(kDiskStats.averageValue))
            .arg(formatRateText(kDiskStats.peakValue)));
    }
    appendFilledSeriesPoint(
        diskReadLineSeries_,
        diskReadBaselineSeries_,
        diskUtilAxisX_,
        diskUtilAxisY_,
        diskReadBytesPerSec,
        0.0);
    appendFilledSeriesPoint(
        diskWriteLineSeries_,
        diskWriteBaselineSeries_,
        diskUtilAxisX_,
        diskUtilAxisY_,
        diskWriteBytesPerSec,
        0.0);
    updateSharedSeriesAxisRange(
        diskReadLineSeries_,
        diskWriteLineSeries_,
        diskUtilAxisX_,
        diskUtilAxisY_,
        0.0);

    // Network sub-page: update uplink/downlink rate summary and line trend.
    if (networkUtilSummaryLabel_ != nullptr)
    {
        const UtilizationStatisticSnapshot kNetworkStats = buildStatisticSnapshot(networkAggregateHistoryBytesPerSec_);
        networkUtilSummaryLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.network.summary"),
                QStringLiteral("接收：%1    发送：%2    合计均值：%3    峰值：%4"))
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(formatRateText(networkTxBytesPerSec))
            .arg(formatRateText(kNetworkStats.averageValue))
            .arg(formatRateText(kNetworkStats.peakValue)));
    }
    appendFilledSeriesPoint(
        networkRxLineSeries_,
        networkRxBaselineSeries_,
        networkUtilAxisX_,
        networkUtilAxisY_,
        networkRxBytesPerSec,
        0.0);
    appendFilledSeriesPoint(
        networkTxLineSeries_,
        networkTxBaselineSeries_,
        networkUtilAxisX_,
        networkUtilAxisY_,
        networkTxBytesPerSec,
        0.0);
    updateSharedSeriesAxisRange(
        networkRxLineSeries_,
        networkTxLineSeries_,
        networkUtilAxisX_,
        networkUtilAxisY_,
        0.0);

    // GPU sub-page: update utilization summary and line trend.
    if (gpuUtilSummaryLabel_ != nullptr)
    {
        const UtilizationStatisticSnapshot kGpuStats = buildStatisticSnapshot(gpuUsageHistoryPercent_);
        gpuUtilSummaryLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.summary"),
                QStringLiteral("GPU 当前：%1%    均值：%2%    峰值：%3%    3D：%4%    Copy：%5%"))
            .arg(gpuUsagePercent, 0, 'f', 1)
            .arg(kGpuStats.averageValue, 0, 'f', 1)
            .arg(kGpuStats.peakValue, 0, 'f', 1)
            .arg(gpuUsage3DPercent_, 0, 'f', 1)
            .arg(gpuUsageCopyPercent_, 0, 'f', 1));
    }

    for (GpuEngineChartEntry& chartEntry : gpuEngineCharts_)
    {
        double usagePercent = 0.0;
        if (chartEntry.engineKeyText == QStringLiteral("3d"))
        {
            usagePercent = gpuUsage3DPercent_;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("copy"))
        {
            usagePercent = gpuUsageCopyPercent_;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_encode"))
        {
            usagePercent = gpuUsageVideoEncodePercent_;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_decode"))
        {
            usagePercent = gpuUsageVideoDecodePercent_;
        }
        appendFilledSeriesPoint(
            chartEntry.lineSeries,
            chartEntry.baselineSeries,
            chartEntry.axisX,
            chartEntry.axisY,
            usagePercent,
            0.0);
        if (chartEntry.titleLabel != nullptr)
        {
            chartEntry.titleLabel->setText(
                QStringLiteral("%1  %2%")
                .arg(chartEntry.displayNameText)
                .arg(usagePercent, 0, 'f', 1));
        }
    }

    appendFilledSeriesPoint(
        gpuDedicatedMemoryLineSeries_,
        gpuDedicatedMemoryBaselineSeries_,
        gpuDedicatedMemoryAxisX_,
        gpuDedicatedMemoryAxisY_,
        gpuDedicatedUsedGiB_,
        0.0);
    appendFilledSeriesPoint(
        gpuSharedMemoryLineSeries_,
        gpuSharedMemoryBaselineSeries_,
        gpuSharedMemoryAxisX_,
        gpuSharedMemoryAxisY_,
        gpuSharedUsedGiB_,
        0.0);
    if (gpuDedicatedMemoryAxisY_ != nullptr)
    {
        const double kDedicatedUpperGiB = std::max(
            0.5,
            (gpuDedicatedMemoryGiB_ > 0.0 ? gpuDedicatedMemoryGiB_ : gpuDedicatedBudgetGiB_));
        gpuDedicatedMemoryAxisY_->setRange(0.0, kDedicatedUpperGiB);
    }
    if (gpuSharedMemoryAxisY_ != nullptr)
    {
        const double kSharedUpperGiB = std::max(
            0.5,
            (gpuSharedMemoryGiB_ > 0.0 ? gpuSharedMemoryGiB_ : gpuSharedBudgetGiB_));
        gpuSharedMemoryAxisY_->setRange(0.0, kSharedUpperGiB);
    }

    updateUtilizationSidebarCards(
        averageCpuUsage,
        memoryUsagePercent,
        diskReadBytesPerSec,
        diskWriteBytesPerSec,
        networkRxBytesPerSec,
        networkTxBytesPerSec,
        gpuUsagePercent);
}

void HardwareDock::updateUtilizationSidebarCards(
    const double cpuUsagePercent,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    if (cpuNavCard_ != nullptr)
    {
        cpuNavCard_->setSubtitleText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.cpu.summary"),
                QStringLiteral("%1%  %2 GHz"))
            .arg(cpuUsagePercent, 0, 'f', 0)
            .arg(lastCpuSpeedGhz_, 0, 'f', 2));
        cpuNavCard_->appendSample(cpuUsagePercent);
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (memoryNavCard_ != nullptr && ::GlobalMemoryStatusEx(&memoryStatus) == TRUE)
    {
        const double kTotalGiB = static_cast<double>(memoryStatus.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
        const double kUsedGiB =
            static_cast<double>(memoryStatus.ullTotalPhys - memoryStatus.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
        const double kCachedPercent = std::clamp(
            100.0 - memoryUsagePercent,
            0.0,
            100.0);
        const int kHistoryCapacity = std::max(1, memoryNavCard_->sampleCapacity());
        memoryNavUsedHistoryPercent_.push_back(memoryUsagePercent);
        memoryNavCachedHistoryPercent_.push_back(kCachedPercent);
        while (static_cast<int>(memoryNavUsedHistoryPercent_.size()) > kHistoryCapacity)
        {
            memoryNavUsedHistoryPercent_.erase(memoryNavUsedHistoryPercent_.begin());
        }
        while (static_cast<int>(memoryNavCachedHistoryPercent_.size()) > kHistoryCapacity)
        {
            memoryNavCachedHistoryPercent_.erase(memoryNavCachedHistoryPercent_.begin());
        }

        QVector<double> usedSampleList;
        QVector<double> cachedSampleList;
        usedSampleList.reserve(static_cast<int>(memoryNavUsedHistoryPercent_.size()));
        cachedSampleList.reserve(static_cast<int>(memoryNavCachedHistoryPercent_.size()));
        for (const double kUsedSampleValue : memoryNavUsedHistoryPercent_)
        {
            usedSampleList.push_back(std::clamp(kUsedSampleValue, 0.0, 100.0));
        }
        for (const double kCachedSampleValue : memoryNavCachedHistoryPercent_)
        {
            cachedSampleList.push_back(std::clamp(kCachedSampleValue, 0.0, 100.0));
        }

        memoryNavCard_->setSubtitleText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.memory.summary"),
                QStringLiteral("用 %1/%2 GB / 余 %3%"))
            .arg(kUsedGiB, 0, 'f', 1)
            .arg(kTotalGiB, 0, 'f', 1)
            .arg(kCachedPercent, 0, 'f', 0));
        memoryNavCard_->setSampleSeries(usedSampleList, cachedSampleList);
    }

    if (diskNavCard_ != nullptr)
    {
        rebuildDualRateNavCard(
            diskNavCard_,
            &diskNavReadHistoryBytesPerSec_,
            &diskNavWriteHistoryBytesPerSec_,
            diskReadBytesPerSec,
            diskWriteBytesPerSec,
            &diskNavAutoScaleBytesPerSec_,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.disk.summary"),
                QStringLiteral("读 %1 / 写 %2"))
            .arg(formatRateText(diskReadBytesPerSec))
            .arg(formatRateText(diskWriteBytesPerSec)));
    }

    if (networkNavCard_ != nullptr)
    {
        rebuildDualRateNavCard(
            networkNavCard_,
            &networkNavRxHistoryBytesPerSec_,
            &networkNavTxHistoryBytesPerSec_,
            networkRxBytesPerSec,
            networkTxBytesPerSec,
            &networkNavAutoScaleBytesPerSec_,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.network.summary"),
                QStringLiteral("下 %1 / 上 %2"))
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(formatRateText(networkTxBytesPerSec)));
    }

    if (gpuNavCard_ != nullptr)
    {
        gpuNavCard_->setSubtitleText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.gpu.summary"),
                QStringLiteral("%1%  %2/%3 GB"))
            .arg(gpuUsagePercent, 0, 'f', 0)
            .arg(formatGpuMemoryUsageGiBText(
                gpuDedicatedUsedGiB_,
                gpuDedicatedUsageAvailable_,
                1))
            .arg((gpuDedicatedMemoryGiB_ > 0.0 ? gpuDedicatedMemoryGiB_ : gpuDedicatedBudgetGiB_), 0, 'f', 1));
        gpuNavCard_->appendSample(gpuUsagePercent);
    }
}

void HardwareDock::updateAdditionalDiskUtilizationDevices(const std::vector<DiskRateSample>& sampleList)
{
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList.size()); ++sampleIndex)
    {
        const DiskRateSample& sample = sampleList[static_cast<std::size_t>(sampleIndex)];
        const int kDeviceIndex = ensureDiskUtilizationDevice(sample, sampleIndex);
        if (kDeviceIndex < 0 || kDeviceIndex >= static_cast<int>(diskUtilDevices_.size()))
        {
            continue;
        }
        updateDiskUtilizationDevice(diskUtilDevices_[static_cast<std::size_t>(kDeviceIndex)], sample);
    }
}

void HardwareDock::updateAdditionalNetworkUtilizationDevices(const std::vector<NetworkRateSample>& sampleList)
{
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList.size()); ++sampleIndex)
    {
        const NetworkRateSample& sample = sampleList[static_cast<std::size_t>(sampleIndex)];
        const int kDeviceIndex = ensureNetworkUtilizationDevice(sample, sampleIndex);
        if (kDeviceIndex < 0 || kDeviceIndex >= static_cast<int>(networkUtilDevices_.size()))
        {
            continue;
        }
        updateNetworkUtilizationDevice(networkUtilDevices_[static_cast<std::size_t>(kDeviceIndex)], sample);
    }
}

void HardwareDock::updateAdditionalGpuUtilizationDevices(const std::vector<GpuUsageSample>& sampleList)
{
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList.size()); ++sampleIndex)
    {
        const GpuUsageSample& sample = sampleList[static_cast<std::size_t>(sampleIndex)];
        const int kDeviceIndex = ensureGpuUtilizationDevice(sample, sampleIndex);
        if (kDeviceIndex < 0 || kDeviceIndex >= static_cast<int>(gpuUtilDevices_.size()))
        {
            continue;
        }
        updateGpuUtilizationDevice(gpuUtilDevices_[static_cast<std::size_t>(kDeviceIndex)], sample);
    }
}

void HardwareDock::updateDiskUtilizationDevice(
    DiskUtilizationDevice& device,
    const DiskRateSample& sample)
{
    if (device.summaryLabel != nullptr)
    {
        device.summaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.disk.summary"),
                QStringLiteral("读取：%1    写入：%2"))
            .arg(formatRateText(sample.readBytesPerSec))
            .arg(formatRateText(sample.writeBytesPerSec)));
    }

    appendFilledSeriesPoint(
        device.readLineSeries,
        device.readBaselineSeries,
        device.axisX,
        device.axisY,
        sample.readBytesPerSec,
        0.0);
    appendFilledSeriesPoint(
        device.writeLineSeries,
        device.writeBaselineSeries,
        device.axisX,
        device.axisY,
        sample.writeBytesPerSec,
        0.0);
    updateSharedSeriesAxisRange(
        device.readLineSeries,
        device.writeLineSeries,
        device.axisX,
        device.axisY,
        0.0);

    if (device.navCard != nullptr)
    {
        rebuildDualRateNavCard(
            device.navCard,
            &device.readHistoryBytesPerSec,
            &device.writeHistoryBytesPerSec,
            sample.readBytesPerSec,
            sample.writeBytesPerSec,
            &device.navAutoScaleBytesPerSec,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.disk.summary"),
                QStringLiteral("读 %1 / 写 %2"))
            .arg(formatRateText(sample.readBytesPerSec))
            .arg(formatRateText(sample.writeBytesPerSec)));
    }

    if (device.detailLabel != nullptr)
    {
        const double kTotalRate = std::max(0.0, sample.readBytesPerSec)
            + std::max(0.0, sample.writeBytesPerSec);
        const double kApproxPercent = std::clamp(
            kTotalRate / std::max(1.0, device.navAutoScaleBytesPerSec) * 100.0,
            0.0,
            100.0);
        device.detailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.disk.detail"),
                QStringLiteral(
                "活动时间(近似): %1%\n"
                "读取速度: %2\n"
                "写入速度: %3\n"
                "性能计数器实例: %4"))
            .arg(kApproxPercent, 0, 'f', 1)
            .arg(formatRateText(sample.readBytesPerSec))
            .arg(formatRateText(sample.writeBytesPerSec))
            .arg(sample.instanceNameText));
    }
}

void HardwareDock::updateNetworkUtilizationDevice(
    NetworkUtilizationDevice& device,
    const NetworkRateSample& sample)
{
    if (device.summaryLabel != nullptr)
    {
        device.summaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.network.summary"),
                QStringLiteral("接收：%1    发送：%2"))
            .arg(formatRateText(sample.rxBytesPerSec))
            .arg(formatRateText(sample.txBytesPerSec)));
    }

    appendFilledSeriesPoint(
        device.rxLineSeries,
        device.rxBaselineSeries,
        device.axisX,
        device.axisY,
        sample.rxBytesPerSec,
        0.0);
    appendFilledSeriesPoint(
        device.txLineSeries,
        device.txBaselineSeries,
        device.axisX,
        device.axisY,
        sample.txBytesPerSec,
        0.0);
    updateSharedSeriesAxisRange(
        device.rxLineSeries,
        device.txLineSeries,
        device.axisX,
        device.axisY,
        0.0);

    if (device.navCard != nullptr)
    {
        rebuildDualRateNavCard(
            device.navCard,
            &device.rxHistoryBytesPerSec,
            &device.txHistoryBytesPerSec,
            sample.rxBytesPerSec,
            sample.txBytesPerSec,
            &device.navAutoScaleBytesPerSec,
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.network.summary"),
                QStringLiteral("下 %1 / 上 %2"))
            .arg(formatRateText(sample.rxBytesPerSec))
            .arg(formatRateText(sample.txBytesPerSec)));
    }

    if (device.detailLabel != nullptr)
    {
        const double kLinkMbps = static_cast<double>(sample.linkBitsPerSecond) / (1000.0 * 1000.0);
        device.detailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.network.detail"),
                QStringLiteral(
                "适配器: %1\n"
                "发送: %2\n"
                "接收: %3\n"
                "链路速度: %4 Mbps"))
            .arg(sample.displayNameText.isEmpty() ? QStringLiteral("N/A") : sample.displayNameText)
            .arg(formatRateText(sample.txBytesPerSec))
            .arg(formatRateText(sample.rxBytesPerSec))
            .arg(kLinkMbps > 0.0 ? QString::number(kLinkMbps, 'f', 1) : QStringLiteral("N/A")));
    }
}

void HardwareDock::updateGpuUtilizationDevice(
    GpuUtilizationDevice& device,
    const GpuUsageSample& sample)
{
    const double kDedicatedCapacityGiB = sample.dedicatedMemoryGiB > 0.0
        ? sample.dedicatedMemoryGiB
        : sample.dedicatedBudgetGiB;
    const double kSharedCapacityGiB = sample.sharedMemoryGiB > 0.0
        ? sample.sharedMemoryGiB
        : sample.sharedBudgetGiB;
    const QString kCurrentCoreClockText = formatGpuClockMhzText(sample.currentCoreClockMhz);
    const QString kMaxCoreClockText = formatGpuClockMhzText(sample.maxCoreClockMhz);
    const QString kCurrentMemoryClockText = formatGpuClockMhzText(sample.currentMemoryClockMhz);
    const QString kMaxMemoryClockText = formatGpuClockMhzText(sample.maxMemoryClockMhz);

    if (device.adapterTitleLabel != nullptr)
    {
        device.adapterTitleLabel->setText(
            sample.displayNameText.isEmpty() ? QStringLiteral("N/A") : sample.displayNameText);
    }
    if (device.summaryLabel != nullptr)
    {
        device.summaryLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.gpu.summary"),
                QStringLiteral("GPU 当前利用率：%1%    3D：%2%    Copy：%3%    核心频率：%4 MHz"))
            .arg(sample.overallUsagePercent, 0, 'f', 1)
            .arg(sample.usage3DPercent, 0, 'f', 1)
            .arg(sample.usageCopyPercent, 0, 'f', 1)
            .arg(kCurrentCoreClockText));
    }

    for (GpuEngineChartEntry& chartEntry : device.engineCharts)
    {
        double usagePercent = 0.0;
        if (chartEntry.engineKeyText == QStringLiteral("3d"))
        {
            usagePercent = sample.usage3DPercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("copy"))
        {
            usagePercent = sample.usageCopyPercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_encode"))
        {
            usagePercent = sample.usageVideoEncodePercent;
        }
        else if (chartEntry.engineKeyText == QStringLiteral("video_decode"))
        {
            usagePercent = sample.usageVideoDecodePercent;
        }
        appendFilledSeriesPoint(
            chartEntry.lineSeries,
            chartEntry.baselineSeries,
            chartEntry.axisX,
            chartEntry.axisY,
            usagePercent,
            0.0);
        if (chartEntry.titleLabel != nullptr)
        {
            chartEntry.titleLabel->setText(
                QStringLiteral("%1  %2%")
                .arg(chartEntry.displayNameText)
                .arg(usagePercent, 0, 'f', 1));
        }
    }

    appendFilledSeriesPoint(
        device.dedicatedMemoryLineSeries,
        device.dedicatedMemoryBaselineSeries,
        device.dedicatedMemoryAxisX,
        device.dedicatedMemoryAxisY,
        sample.dedicatedUsedGiB,
        0.0);
    appendFilledSeriesPoint(
        device.sharedMemoryLineSeries,
        device.sharedMemoryBaselineSeries,
        device.sharedMemoryAxisX,
        device.sharedMemoryAxisY,
        sample.sharedUsedGiB,
        0.0);
    if (device.dedicatedMemoryAxisY != nullptr)
    {
        const double kDedicatedUpperGiB = std::max(
            0.5,
            kDedicatedCapacityGiB);
        device.dedicatedMemoryAxisY->setRange(0.0, kDedicatedUpperGiB);
    }
    if (device.sharedMemoryAxisY != nullptr)
    {
        device.sharedMemoryAxisY->setRange(0.0, std::max(0.5, kSharedCapacityGiB));
    }
    if (device.dedicatedMemoryChartView != nullptr
        && device.dedicatedMemoryChartView->chart() != nullptr)
    {
        device.dedicatedMemoryChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.dedicated_memory_title"),
                QStringLiteral("专用 GPU 内存利用率  %1 / %2 GiB"))
            .arg(formatGpuMemoryUsageGiBText(
                sample.dedicatedUsedGiB,
                sample.dedicatedUsageAvailable))
            .arg(kDedicatedCapacityGiB, 0, 'f', 2));
    }
    if (device.sharedMemoryChartView != nullptr
        && device.sharedMemoryChartView->chart() != nullptr)
    {
        device.sharedMemoryChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.shared_memory_title"),
                QStringLiteral("共享 GPU 内存利用率  %1 / %2 GiB"))
            .arg(formatGpuMemoryUsageGiBText(
                sample.sharedUsedGiB,
                sample.sharedUsageAvailable))
            .arg(kSharedCapacityGiB, 0, 'f', 2));
    }
    if (device.detailLabel != nullptr)
    {
        device.detailLabel->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.device.gpu.detail"),
                QStringLiteral(
                "利用率: %1%\n"
                "3D: %2%   Copy: %3%   Video Encode: %4%   Video Decode: %5%\n"
                "核心频率: %6 MHz（最大 %7 MHz）\n"
                "显存频率: %8 MHz（最大 %9 MHz）\n"
                "专用显存: %10 / %11 GiB\n"
                "共享显存: %12 / %13 GiB\n"
                "适配器索引: %14"))
            .arg(sample.overallUsagePercent, 0, 'f', 1)
            .arg(sample.usage3DPercent, 0, 'f', 1)
            .arg(sample.usageCopyPercent, 0, 'f', 1)
            .arg(sample.usageVideoEncodePercent, 0, 'f', 1)
            .arg(sample.usageVideoDecodePercent, 0, 'f', 1)
            .arg(kCurrentCoreClockText)
            .arg(kMaxCoreClockText)
            .arg(kCurrentMemoryClockText)
            .arg(kMaxMemoryClockText)
            .arg(formatGpuMemoryUsageGiBText(
                sample.dedicatedUsedGiB,
                sample.dedicatedUsageAvailable))
            .arg(kDedicatedCapacityGiB, 0, 'f', 2)
            .arg(formatGpuMemoryUsageGiBText(
                sample.sharedUsedGiB,
                sample.sharedUsageAvailable))
            .arg(kSharedCapacityGiB, 0, 'f', 2)
            .arg(sample.adapterIndex));
    }
    if (device.navCard != nullptr)
    {
        device.navCard->setSubtitleText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.card.gpu.summary"),
                QStringLiteral("%1%  %2/%3 GB"))
            .arg(sample.overallUsagePercent, 0, 'f', 0)
            .arg(formatGpuMemoryUsageGiBText(
                sample.dedicatedUsedGiB,
                sample.dedicatedUsageAvailable,
                1))
            .arg(kDedicatedCapacityGiB, 0, 'f', 1));
        device.navCard->appendSample(sample.overallUsagePercent);
    }
}

void HardwareDock::updateTaskManagerDetailLabels(
    const std::vector<double>& coreUsageList,
    const std::vector<CpuPowerSnapshot>& powerInfoList,
    const double memoryUsagePercent,
    const double diskReadBytesPerSec,
    const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec,
    const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    // Average CPU usage is used for core statistics on the CPU details page.
    double averageCpuUsage = 0.0;
    if (!coreUsageList.empty())
    {
        for (const double kUsageValue : coreUsageList)
        {
            averageCpuUsage += kUsageValue;
        }
        averageCpuUsage /= static_cast<double>(coreUsageList.size());
    }

    // CallNtPowerInformation typically returns only the base frequency on modern HWP/CPPC platforms.
    // "Speed" prioritizes the valid frequency from the current PDH cycle; the Power API serves only as a fallback when counters are unsupported.
    double currentMhzSum = 0.0;
    double maxMhzSum = 0.0;
    int cpuPowerCount = 0;
    for (const CpuPowerSnapshot& snapshot : powerInfoList)
    {
        if (snapshot.currentMhz > 0)
        {
            currentMhzSum += static_cast<double>(snapshot.currentMhz);
        }
        if (snapshot.maxMhz > 0)
        {
            maxMhzSum += static_cast<double>(snapshot.maxMhz);
        }
        ++cpuPowerCount;
    }
    const double kPowerApiCurrentCpuGhz = cpuPowerCount > 0
        ? (currentMhzSum / static_cast<double>(cpuPowerCount) / 1000.0)
        : 0.0;
    const double kCurrentCpuGhz = lastCpuSpeedGhz_ > 0.0
        ? lastCpuSpeedGhz_
        : kPowerApiCurrentCpuGhz;
    const double kBaseCpuGhz = cpuPowerCount > 0
        ? (maxMhzSum / static_cast<double>(cpuPowerCount) / 1000.0)
        : 0.0;
    lastCpuSpeedGhz_ = kCurrentCpuGhz;
    const UtilizationStatisticSnapshot kCpuStats = buildStatisticSnapshot(cpuUsageHistoryPercent_);

    // System performance snapshot is used for process/thread/handle and committed memory statistics.
    SystemPerformanceSnapshot perfSnapshot;
    const bool kPerfOk = sampleSystemPerformanceSnapshot(&perfSnapshot);

    // uptimeSeconds usage: System uptime in seconds, displayed as a Task Manager-style time string.
    const std::uint64_t kUptimeSeconds = static_cast<std::uint64_t>(::GetTickCount64() / 1000ULL);
    if (cpuUtilPrimaryDetailLabel_ != nullptr)
    {
        // buildMetricCellHtml usage: generates a table cell with a Task Manager-style 'gray label + large value'.
        // Inputs: localized label, formatted value, and font size; returns safe rich text ready for QLabel.
        const auto kBuildMetricCellHtml =
            [](const QString& labelText, const QString& valueText, const int valueFontSize)
            {
                return QStringLiteral(
                    "<td style=\"padding-right:18px;vertical-align:top;\">"
                    "<span style=\"color:%1;font-size:13px;\">%2</span><br/>"
                    "<span style=\"color:%3;font-size:%4px;font-weight:400;\">%5</span>"
                    "</td>")
                    // This is QLabel rich text, not QSS: QTextDocument's CSS parser does not recognize palette(...) (a
                    // QSS-specific extension); dynamic roles are ignored entirely, and colors revert to inherited values.
                    // Rich text must use *ColorHex() to resolve specific colors; this cell
                    // regenerates on every sample, so theme changes take effect on the next refresh.
                    .arg(ksword_theme::textSecondaryColorHex())
                    .arg(labelText.toHtmlEscaped())
                    .arg(ksword_theme::textPrimaryColorHex())
                    .arg(valueFontSize)
                    .arg(valueText.toHtmlEscaped());
            };

        // primaryHtml usage: Displays key metrics in three rows: utilization/speed, counts, and runtime, matching the screenshot.
        const QString kPrimaryHtml =
            QStringLiteral("<table cellspacing=\"0\" cellpadding=\"0\">"
                "<tr>%1%2</tr>"
                "<tr>%3%4%5</tr>"
                "<tr>%6</tr>"
                "</table>")
            .arg(kBuildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.utilization"),
                    QStringLiteral("利用率")),
                QStringLiteral("%1%").arg(averageCpuUsage, 0, 'f', 0),
                30))
            .arg(kBuildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.speed"),
                    QStringLiteral("速度")),
                QStringLiteral("%1 GHz").arg(kCurrentCpuGhz, 0, 'f', 2),
                30))
            .arg(kBuildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.processes"),
                    QStringLiteral("进程")),
                kPerfOk ? QString::number(perfSnapshot.processCount) : QStringLiteral("N/A"),
                25))
            .arg(kBuildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.threads"),
                    QStringLiteral("线程")),
                kPerfOk ? QString::number(perfSnapshot.threadCount) : QStringLiteral("N/A"),
                25))
            .arg(kBuildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.handles"),
                    QStringLiteral("句柄")),
                kPerfOk ? QString::number(perfSnapshot.handleCount) : QStringLiteral("N/A"),
                25))
            .arg(kBuildMetricCellHtml(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.cpu.metric.uptime"),
                    QStringLiteral("正常运行时间")),
                formatDurationText(kUptimeSeconds),
                25));
        cpuUtilPrimaryDetailLabel_->setText(kPrimaryHtml);
        cpuUtilPrimaryDetailLabel_->setToolTip(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.cpu.metric.statistics.tooltip"),
                QStringLiteral("均值：%1% | 峰值：%2% | 趋势：%3"))
            .arg(kCpuStats.averageValue, 0, 'f', 1)
            .arg(kCpuStats.peakValue, 0, 'f', 1)
            .arg(buildTrendText(kCpuStats, true)));
    }

    if (cpuUtilSecondaryDetailLabel_ != nullptr)
    {
        cpuUtilSecondaryDetailLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.cpu.detail.secondary"),
                QStringLiteral(
                "基准速度: %1 GHz\n"
                "插槽: %2\n"
                "内核: %3\n"
                "逻辑处理器: %4\n"
                "压力等级: %5"))
            .arg(kBaseCpuGhz, 0, 'f', 2)
            .arg(cpuPackageCount_ > 0 ? QString::number(cpuPackageCount_) : QStringLiteral("N/A"))
            .arg(cpuPhysicalCoreCount_ > 0 ? QString::number(cpuPhysicalCoreCount_) : QStringLiteral("N/A"))
            .arg(cpuLogicalCoreCount_ > 0 ? QString::number(cpuLogicalCoreCount_) : QStringLiteral("N/A"))
            .arg(buildPressureLevelText(averageCpuUsage)));
    }

    if (cpuUtilTertiaryDetailLabel_ != nullptr)
    {
        cpuUtilTertiaryDetailLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.cpu.detail.tertiary"),
                QStringLiteral(
                "L1缓存: %1\n"
                "L2缓存: %2\n"
                "L3缓存: %3\n"
                "%4\n"
                "%5"))
            .arg(cpuL1CacheBytes_ > 0 ? bytesToReadableText(static_cast<double>(cpuL1CacheBytes_)) : QStringLiteral("N/A"))
            .arg(cpuL2CacheBytes_ > 0 ? bytesToReadableText(static_cast<double>(cpuL2CacheBytes_)) : QStringLiteral("N/A"))
            .arg(cpuL3CacheBytes_ > 0 ? bytesToReadableText(static_cast<double>(cpuL3CacheBytes_)) : QStringLiteral("N/A"))
            .arg(r0HardwareHealthSummaryText_)
            .arg(r0CpuHardwareSummaryText_));

        // r0AuditToolTip: Preserves the complete audit text while preventing long lines from expanding the task-manager-style main view.
        const QString kR0AuditToolTip = r0HardwareHealthDetailText_
            + QStringLiteral("\n\n")
            + r0CpuHardwareDetailText_;
        cpuUtilSecondaryDetailLabel_->setToolTip(kR0AuditToolTip);
        cpuUtilTertiaryDetailLabel_->setToolTip(kR0AuditToolTip);
    }

    // The CPU details label displays a single line of 'Sampling...' text in the first frame, then replaces it with multi-line real-time data.
    // Recalculate the heights of the chart and detail areas here to ensure the chart actively shrinks rather than clipping bottom text.
    // Invocation: Called after both groups of detail texts are written; the function updates the layout only when dimensions change.
    // Return behavior: No return value; CPU pages are reflowed within the current event loop based on the latest text height.
    adjustUtilizationChartHeights();

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    const bool kMemoryStatusOk = (::GlobalMemoryStatusEx(&memoryStatus) == TRUE);
    if (kMemoryStatusOk)
    {
        const double kTotalGiB = static_cast<double>(memoryStatus.ullTotalPhys) / (1024.0 * 1024.0 * 1024.0);
        const double kAvailableGiB = static_cast<double>(memoryStatus.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
        const double kUsedGiB = kTotalGiB - kAvailableGiB;
        if (memoryCapacityLabel_ != nullptr)
        {
            memoryCapacityLabel_->setText(QStringLiteral("%1 GB").arg(kTotalGiB, 0, 'f', 1));
        }
        if (memoryUtilPrimaryDetailLabel_ != nullptr)
        {
            const UtilizationStatisticSnapshot kMemoryStats = buildStatisticSnapshot(memoryUsageHistoryPercent_);
            memoryUtilPrimaryDetailLabel_->setText(
                ks::i18n::contextText(
                    QStringLiteral("hardware.utilization.memory.detail.primary"),
                    QStringLiteral(
                    "使用中(含缓存): %1 GB\n"
                    "当前利用率: %2%\n"
                    "均值: %3%   峰值: %4%   趋势: %5\n"
                    "已提交: %6 / %7\n"
                    "已缓存: %8\n"
                    "分页池: %9\n"
                    "非分页池: %10"))
                .arg(kUsedGiB, 0, 'f', 1)
                .arg(memoryUsagePercent, 0, 'f', 1)
                .arg(kMemoryStats.averageValue, 0, 'f', 1)
                .arg(kMemoryStats.peakValue, 0, 'f', 1)
                .arg(buildTrendText(kMemoryStats, true))
                .arg(kPerfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.commitTotalBytes)) : QStringLiteral("N/A"))
                .arg(kPerfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.commitLimitBytes)) : QStringLiteral("N/A"))
                .arg(kPerfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.cachedBytes)) : QStringLiteral("N/A"))
                .arg(kPerfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.pagedPoolBytes)) : QStringLiteral("N/A"))
                .arg(kPerfOk ? bytesToReadableText(static_cast<double>(perfSnapshot.nonPagedPoolBytes)) : QStringLiteral("N/A")));
        }
    }

    if (memoryUtilSecondaryDetailLabel_ != nullptr)
    {
        ULONGLONG installedMemoryKb = 0;
        ::GetPhysicallyInstalledSystemMemory(&installedMemoryKb);
        const double kInstalledBytes = static_cast<double>(installedMemoryKb) * 1024.0;
        const double kReservedBytes = kMemoryStatusOk
            ? std::max(0.0, kInstalledBytes - static_cast<double>(memoryStatus.ullTotalPhys))
            : 0.0;
        memoryUtilSecondaryDetailLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.memory.detail.secondary"),
                QStringLiteral(
                "速度: %1 MHz\n"
                "已使用插槽: %2/%3\n"
                "外形规格: %4\n"
                "硬件保留内存: %5\n"
                "%6"))
            .arg(memorySpeedMhz_ > 0 ? QString::number(memorySpeedMhz_) : QStringLiteral("N/A"))
            .arg(memorySlotUsed_ > 0 ? QString::number(memorySlotUsed_) : QStringLiteral("N/A"))
            .arg(memorySlotTotal_ > 0 ? QString::number(memorySlotTotal_) : QStringLiteral("N/A"))
            .arg(memoryFormFactorText_.isEmpty() ? QStringLiteral("N/A") : memoryFormFactorText_)
            .arg(bytesToReadableText(kReservedBytes))
            .arg(r0PhysicalMemoryDetailText_));
    }

    if ((sampleCounter_ % 15) == 1)
    {
        refreshSystemVolumeInfo();
    }
    if (diskUtilDetailLabel_ != nullptr)
    {
        const double kDiskTotalRate = std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec);
        const double kDiskApproxPercent = std::clamp(
            kDiskTotalRate / std::max(1.0, diskNavAutoScaleBytesPerSec_) * 100.0,
            0.0,
            100.0);
        const UtilizationStatisticSnapshot kDiskStats = buildStatisticSnapshot(diskAggregateHistoryBytesPerSec_);
        diskUtilDetailLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.disk.detail"),
                QStringLiteral(
                "活动时间(近似): %1%\n"
                "当前合计: %2\n"
                "均值: %3\n"
                "峰值: %4\n"
                "趋势: %5\n"
                "系统卷: %6\n"
                "总容量: %7\n"
                "可用: %8"))
            .arg(kDiskApproxPercent, 0, 'f', 1)
            .arg(formatRateText(kDiskTotalRate))
            .arg(formatRateText(kDiskStats.averageValue))
            .arg(formatRateText(kDiskStats.peakValue))
            .arg(buildTrendText(kDiskStats, false))
            .arg(systemVolumeText_.isEmpty() ? QStringLiteral("N/A") : systemVolumeText_)
            .arg(systemVolumeTotalBytes_ > 0
                ? bytesToReadableText(static_cast<double>(systemVolumeTotalBytes_))
                : QStringLiteral("N/A"))
            .arg(systemVolumeFreeBytes_ > 0
                ? bytesToReadableText(static_cast<double>(systemVolumeFreeBytes_))
                : QStringLiteral("N/A")));
    }

    if (networkUtilDetailLabel_ != nullptr)
    {
        const QString kAdapterText = primaryNetworkAdapterName_.isEmpty()
            ? QStringLiteral("N/A")
            : primaryNetworkAdapterName_;
        const double kLinkMbps = static_cast<double>(primaryNetworkLinkBitsPerSecond_) / (1000.0 * 1000.0);
        const UtilizationStatisticSnapshot kNetworkStats = buildStatisticSnapshot(networkAggregateHistoryBytesPerSec_);
        networkUtilDetailLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.network.detail"),
                QStringLiteral(
                "适配器: %1\n"
                "发送: %2\n"
                "接收: %3\n"
                "合计: %4\n"
                "均值: %5\n"
                "峰值: %6\n"
                "趋势: %7\n"
                "链路速度: %8 Mbps"))
            .arg(kAdapterText)
            .arg(formatRateText(networkTxBytesPerSec))
            .arg(formatRateText(networkRxBytesPerSec))
            .arg(formatRateText(networkRxBytesPerSec + networkTxBytesPerSec))
            .arg(formatRateText(kNetworkStats.averageValue))
            .arg(formatRateText(kNetworkStats.peakValue))
            .arg(buildTrendText(kNetworkStats, false))
            .arg(kLinkMbps > 0.0 ? QString::number(kLinkMbps, 'f', 1) : QStringLiteral("N/A")));
    }

    const double kGpuDedicatedCapacityGiB = gpuDedicatedMemoryGiB_ > 0.0
        ? gpuDedicatedMemoryGiB_
        : gpuDedicatedBudgetGiB_;
    const double kGpuSharedCapacityGiB = gpuSharedMemoryGiB_ > 0.0
        ? gpuSharedMemoryGiB_
        : gpuSharedBudgetGiB_;
    const QString kGpuCurrentCoreClockText = formatGpuClockMhzText(gpuCurrentCoreClockMhz_);
    const QString kGpuMaxCoreClockText = formatGpuClockMhzText(gpuMaxCoreClockMhz_);
    const QString kGpuCurrentMemoryClockText = formatGpuClockMhzText(gpuCurrentMemoryClockMhz_);
    const QString kGpuMaxMemoryClockText = formatGpuClockMhzText(gpuMaxMemoryClockMhz_);

    if (gpuAdapterTitleLabel_ != nullptr)
    {
        gpuAdapterTitleLabel_->setText(
            gpuAdapterNameText_.isEmpty() ? QStringLiteral("N/A") : gpuAdapterNameText_);
    }
    if (gpuDedicatedMemoryChartView_ != nullptr
        && gpuDedicatedMemoryChartView_->chart() != nullptr)
    {
        gpuDedicatedMemoryChartView_->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.dedicated_memory_title"),
                QStringLiteral("专用 GPU 内存利用率  %1 / %2 GiB"))
            .arg(formatGpuMemoryUsageGiBText(
                gpuDedicatedUsedGiB_,
                gpuDedicatedUsageAvailable_))
            .arg(kGpuDedicatedCapacityGiB, 0, 'f', 2));
    }
    if (gpuSharedMemoryChartView_ != nullptr
        && gpuSharedMemoryChartView_->chart() != nullptr)
    {
        gpuSharedMemoryChartView_->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.shared_memory_title"),
                QStringLiteral("共享 GPU 内存利用率  %1 / %2 GiB"))
            .arg(formatGpuMemoryUsageGiBText(
                gpuSharedUsedGiB_,
                gpuSharedUsageAvailable_))
            .arg(kGpuSharedCapacityGiB, 0, 'f', 2));
    }

    if (gpuUtilDetailLabel_ != nullptr)
    {
        const UtilizationStatisticSnapshot kGpuStats = buildStatisticSnapshot(gpuUsageHistoryPercent_);
        gpuUtilDetailLabel_->setText(
            ks::i18n::contextText(
                QStringLiteral("hardware.utilization.gpu.detail"),
                QStringLiteral(
                "利用率: %1%\n"
                "均值: %2%   峰值: %3%   趋势: %4\n"
                "3D: %5%   Copy: %6%   Video Encode: %7%   Video Decode: %8%\n"
                "核心频率: %9 MHz（最大 %10 MHz）\n"
                "显存频率: %11 MHz（最大 %12 MHz）\n"
                "专用显存: %13 / %14 GiB\n"
                "共享显存: %15 / %16 GiB\n"
                "驱动版本: %17\n"
                "驱动日期: %18\n"
                "PNP: %19"))
            .arg(gpuUsagePercent, 0, 'f', 1)
            .arg(kGpuStats.averageValue, 0, 'f', 1)
            .arg(kGpuStats.peakValue, 0, 'f', 1)
            .arg(buildTrendText(kGpuStats, true))
            .arg(gpuUsage3DPercent_, 0, 'f', 1)
            .arg(gpuUsageCopyPercent_, 0, 'f', 1)
            .arg(gpuUsageVideoEncodePercent_, 0, 'f', 1)
            .arg(gpuUsageVideoDecodePercent_, 0, 'f', 1)
            .arg(kGpuCurrentCoreClockText)
            .arg(kGpuMaxCoreClockText)
            .arg(kGpuCurrentMemoryClockText)
            .arg(kGpuMaxMemoryClockText)
            .arg(formatGpuMemoryUsageGiBText(
                gpuDedicatedUsedGiB_,
                gpuDedicatedUsageAvailable_))
            .arg(kGpuDedicatedCapacityGiB, 0, 'f', 2)
            .arg(formatGpuMemoryUsageGiBText(
                gpuSharedUsedGiB_,
                gpuSharedUsageAvailable_))
            .arg(kGpuSharedCapacityGiB, 0, 'f', 2)
            .arg(gpuDriverVersionText_.isEmpty() ? QStringLiteral("N/A") : gpuDriverVersionText_)
            .arg(gpuDriverDateText_.isEmpty() ? QStringLiteral("N/A") : gpuDriverDateText_)
            .arg(gpuPnpDeviceIdText_.isEmpty() ? QStringLiteral("N/A") : gpuPnpDeviceIdText_));
    }
}

void HardwareDock::updateCpuDetailTable(
    const std::vector<double>& coreUsageList,
    const std::vector<CpuPowerSnapshot>& powerInfoList)
{
    if (cpuDetailTable_ == nullptr)
    {
        return;
    }

    const int kRowCount = std::max(
        static_cast<int>(coreUsageList.size()),
        static_cast<int>(powerInfoList.size()));
    cpuDetailTable_->setRowCount(kRowCount);

    const QString kSensorText = buildCpuSensorText(false);
    QString temperatureText = QStringLiteral("N/A");
    QString voltageText = QStringLiteral("N/A");
    const QStringList kSensorParts = kSensorText.split('|');
    if (kSensorParts.size() >= 2)
    {
        temperatureText = kSensorParts.at(0);
        voltageText = kSensorParts.at(1);
    }

    for (int rowIndex = 0; rowIndex < kRowCount; ++rowIndex)
    {
        const QString kCoreName = QStringLiteral("CPU %1").arg(rowIndex);
        const QString kUsageText = rowIndex < static_cast<int>(coreUsageList.size())
            ? QString::number(coreUsageList[static_cast<std::size_t>(rowIndex)], 'f', 1)
            : QStringLiteral("0.0");

        QString currentMhzText = QStringLiteral("N/A");
        QString maxMhzText = QStringLiteral("N/A");
        QString limitMhzText = QStringLiteral("N/A");
        if (rowIndex < static_cast<int>(powerInfoList.size()))
        {
            const CpuPowerSnapshot& snapshot = powerInfoList[static_cast<std::size_t>(rowIndex)];
            currentMhzText = QString::number(snapshot.currentMhz);
            maxMhzText = QString::number(snapshot.maxMhz);
            limitMhzText = QString::number(snapshot.limitMhz);
        }

        cpuDetailTable_->setItem(rowIndex, 0, new QTableWidgetItem(kCoreName));
        cpuDetailTable_->setItem(rowIndex, 1, new QTableWidgetItem(kUsageText));
        cpuDetailTable_->setItem(rowIndex, 2, new QTableWidgetItem(currentMhzText));
        cpuDetailTable_->setItem(rowIndex, 3, new QTableWidgetItem(maxMhzText));
        cpuDetailTable_->setItem(rowIndex, 4, new QTableWidgetItem(limitMhzText));
        cpuDetailTable_->setItem(rowIndex, 5, new QTableWidgetItem(temperatureText));
        cpuDetailTable_->setItem(rowIndex, 6, new QTableWidgetItem(voltageText));
    }

    if (cpuDetailLabel_ != nullptr)
    {
        cpuDetailLabel_->setText(
            QStringLiteral("CPU传感器：温度=%1，电压=%2（不可读时显示N/A）")
            .arg(temperatureText)
            .arg(voltageText));
    }
}

void HardwareDock::appendCoreSeriesPoint(CoreChartEntry& chartEntry, const double usagePercent)
{
    if (chartEntry.lineSeries == nullptr
        || chartEntry.baselineSeries == nullptr
        || chartEntry.axisX == nullptr
        || chartEntry.axisY == nullptr)
    {
        return;
    }

    chartEntry.lineSeries->append(sampleCounter_, usagePercent);
    chartEntry.baselineSeries->append(sampleCounter_, 0.0);
    while (chartEntry.lineSeries->count() > historyLength_)
    {
        chartEntry.lineSeries->remove(0);
    }
    while (chartEntry.baselineSeries->count() > historyLength_)
    {
        chartEntry.baselineSeries->remove(0);
    }

    const QList<QPointF> kPointList = chartEntry.lineSeries->points();
    if (!kPointList.isEmpty())
    {
        const double kFirstX = kPointList.first().x();
        const double kLastX = kPointList.last().x();
        if (qFuzzyCompare(kFirstX, kLastX))
        {
            animateLiveValueAxisRange(chartEntry.axisX, kFirstX - 1.0, kLastX + 1.0);
        }
        else
        {
            animateLiveValueAxisRange(chartEntry.axisX, kFirstX, kLastX);
        }
    }
    chartEntry.axisY->setRange(0.0, 100.0);
}

void HardwareDock::appendGeneralSeriesPoint(
    QLineSeries* lineSeries,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double sampleValue,
    const double minAxisYValue)
{
    if (lineSeries == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }

    lineSeries->append(sampleCounter_, sampleValue);
    while (lineSeries->count() > historyLength_)
    {
        lineSeries->remove(0);
    }

    const QList<QPointF> kPointList = lineSeries->points();
    if (kPointList.isEmpty())
    {
        return;
    }

    const double kFirstX = kPointList.first().x();
    const double kLastX = kPointList.last().x();
    if (qFuzzyCompare(kFirstX, kLastX))
    {
        animateLiveValueAxisRange(axisX, kFirstX - 1.0, kLastX + 1.0);
    }
    else
    {
        animateLiveValueAxisRange(axisX, kFirstX, kLastX);
    }
    double maxYValue = minAxisYValue + 1.0;
    for (const QPointF& pointValue : kPointList)
    {
        maxYValue = std::max(maxYValue, pointValue.y());
    }
    axisY->setRange(minAxisYValue, maxYValue * 1.15);
}

void HardwareDock::appendFilledSeriesPoint(
    QLineSeries* lineSeries,
    QLineSeries* baselineSeries,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double sampleValue,
    const double minAxisYValue)
{
    if (lineSeries == nullptr
        || baselineSeries == nullptr
        || axisX == nullptr
        || axisY == nullptr)
    {
        return;
    }

    // lineSeries usage: Stores the actual sampling curve; baselineSeries usage: Stores the lower boundary at the same X coordinate.
    lineSeries->append(sampleCounter_, sampleValue);
    baselineSeries->append(sampleCounter_, minAxisYValue);
    while (lineSeries->count() > historyLength_)
    {
        lineSeries->remove(0);
    }
    while (baselineSeries->count() > historyLength_)
    {
        baselineSeries->remove(0);
    }

    const QList<QPointF> kPointList = lineSeries->points();
    if (kPointList.isEmpty())
    {
        return;
    }

    const double kFirstX = kPointList.first().x();
    const double kLastX = kPointList.last().x();
    if (qFuzzyCompare(kFirstX, kLastX))
    {
        animateLiveValueAxisRange(axisX, kFirstX - 1.0, kLastX + 1.0);
    }
    else
    {
        animateLiveValueAxisRange(axisX, kFirstX, kLastX);
    }

    // maxYValue purpose: Sets the Y-axis upper limit based on the visible history of a single curve; the shared two-line axis will be unified later by updateSharedSeriesAxisRange.
    double maxYValue = minAxisYValue + 1.0;
    for (const QPointF& pointValue : kPointList)
    {
        maxYValue = std::max(maxYValue, pointValue.y());
    }
    axisY->setRange(minAxisYValue, maxYValue * 1.15);
}

void HardwareDock::updateSharedSeriesAxisRange(
    QLineSeries* primaryLineSeries,
    QLineSeries* secondaryLineSeries,
    QValueAxis* axisX,
    QValueAxis* axisY,
    const double minAxisYValue)
{
    if (axisX == nullptr || axisY == nullptr)
    {
        return;
    }

    const QList<QPointF> kPrimaryPointList =
        primaryLineSeries != nullptr ? primaryLineSeries->points() : QList<QPointF>();
    const QList<QPointF> kSecondaryPointList =
        secondaryLineSeries != nullptr ? secondaryLineSeries->points() : QList<QPointF>();
    if (kPrimaryPointList.isEmpty() && kSecondaryPointList.isEmpty())
    {
        return;
    }

    // firstXValue: The leftmost sampled X value in the visible region of both curves.
    double firstXValue = std::numeric_limits<double>::max();
    // lastXValue usage: The rightmost sampled X value in the visible area of both curves.
    double lastXValue = std::numeric_limits<double>::lowest();
    // maxYValue: The common maximum value in the currently visible history of both curves.
    double maxYValue = minAxisYValue + 1.0;

    const auto kAccumulatePointRange =
        [&firstXValue, &lastXValue, &maxYValue](const QList<QPointF>& pointList)
        {
            if (pointList.isEmpty())
            {
                return;
            }

            firstXValue = std::min(firstXValue, pointList.first().x());
            lastXValue = std::max(lastXValue, pointList.last().x());
            for (const QPointF& pointValue : pointList)
            {
                maxYValue = std::max(maxYValue, pointValue.y());
            }
        };

    kAccumulatePointRange(kPrimaryPointList);
    kAccumulatePointRange(kSecondaryPointList);

    if (qFuzzyCompare(firstXValue, lastXValue))
    {
        animateLiveValueAxisRange(axisX, firstXValue - 1.0, lastXValue + 1.0);
    }
    else
    {
        animateLiveValueAxisRange(axisX, firstXValue, lastXValue);
    }
    axisY->setRange(minAxisYValue, maxYValue * 1.15);
}

void HardwareDock::rebuildDualRateNavCard(
    PerformanceNavCard* navCard,
    std::vector<double>* primaryHistoryOut,
    std::vector<double>* secondaryHistoryOut,
    const double primaryBytesPerSecond,
    const double secondaryBytesPerSecond,
    double* upperBoundBytesPerSecondOut,
    const QString& subtitleText)
{
    if (navCard == nullptr
        || primaryHistoryOut == nullptr
        || secondaryHistoryOut == nullptr
        || upperBoundBytesPerSecondOut == nullptr)
    {
        return;
    }

    // safePrimaryBytesPerSecond usage: primary sequence safe rate value, filtering abnormal negative values.
    const double kSafePrimaryBytesPerSecond = std::max(0.0, primaryBytesPerSecond);
    // safeSecondaryBytesPerSecond: Secondary sequence safe rate value, filtering out abnormal negative values.
    const double kSafeSecondaryBytesPerSecond = std::max(0.0, secondaryBytesPerSecond);
    const int kHistoryCapacity = std::max(1, navCard->sampleCapacity());

    primaryHistoryOut->push_back(kSafePrimaryBytesPerSecond);
    secondaryHistoryOut->push_back(kSafeSecondaryBytesPerSecond);
    while (static_cast<int>(primaryHistoryOut->size()) > kHistoryCapacity)
    {
        primaryHistoryOut->erase(primaryHistoryOut->begin());
    }
    while (static_cast<int>(secondaryHistoryOut->size()) > kHistoryCapacity)
    {
        secondaryHistoryOut->erase(secondaryHistoryOut->begin());
    }

    // historyPeakBytesPerSecond usage: The actual peak value visible in the thumbnail history.
    double historyPeakBytesPerSecond = 0.0;
    for (const double kHistoryValue : *primaryHistoryOut)
    {
        historyPeakBytesPerSecond = std::max(historyPeakBytesPerSecond, kHistoryValue);
    }
    for (const double kHistoryValue : *secondaryHistoryOut)
    {
        historyPeakBytesPerSecond = std::max(historyPeakBytesPerSecond, kHistoryValue);
    }

    // Add some top padding to prevent peaks from touching the border directly.
    *upperBoundBytesPerSecondOut = std::max(1.0, historyPeakBytesPerSecond * 1.08);

    QVector<double> primaryPercentSampleList;
    QVector<double> secondaryPercentSampleList;
    primaryPercentSampleList.reserve(static_cast<int>(primaryHistoryOut->size()));
    secondaryPercentSampleList.reserve(static_cast<int>(secondaryHistoryOut->size()));
    for (const double kHistoryValue : *primaryHistoryOut)
    {
        primaryPercentSampleList.push_back(std::clamp(
            kHistoryValue / *upperBoundBytesPerSecondOut * 100.0,
            0.0,
            100.0));
    }
    for (const double kHistoryValue : *secondaryHistoryOut)
    {
        secondaryPercentSampleList.push_back(std::clamp(
            kHistoryValue / *upperBoundBytesPerSecondOut * 100.0,
            0.0,
            100.0));
    }

    navCard->setSubtitleText(subtitleText);
    navCard->setSampleSeries(primaryPercentSampleList, secondaryPercentSampleList);
}

QString HardwareDock::formatRateText(const double bytesPerSecondValue) const
{
    return bytesPerSecondToText(bytesPerSecondValue);
}

void HardwareDock::pushBoundedHistorySample(
    std::vector<double>* historyList,
    const double sampleValue) const
{
    if (historyList == nullptr)
    {
        return;
    }

    // historyCapacity purpose: reuse the main chart's history length to keep the statistical window consistent with the chart window.
    const int kHistoryCapacity = std::max(1, historyLength_);
    historyList->push_back(std::max(0.0, sampleValue));
    while (static_cast<int>(historyList->size()) > kHistoryCapacity)
    {
        historyList->erase(historyList->begin());
    }
}

HardwareDock::UtilizationStatisticSnapshot HardwareDock::buildStatisticSnapshot(
    const std::vector<double>& historyList) const
{
    UtilizationStatisticSnapshot snapshot;
    if (historyList.empty())
    {
        return snapshot;
    }

    // sampleCount/average/peak/min are based on the current visible history window, not cumulative process lifecycle values.
    snapshot.sampleCount = static_cast<int>(historyList.size());
    snapshot.currentValue = historyList.back();
    snapshot.minValue = std::numeric_limits<double>::max();
    for (const double kSampleValue : historyList)
    {
        const double kSafeSampleValue = std::max(0.0, kSampleValue);
        snapshot.averageValue += kSafeSampleValue;
        snapshot.peakValue = std::max(snapshot.peakValue, kSafeSampleValue);
        snapshot.minValue = std::min(snapshot.minValue, kSafeSampleValue);
    }
    snapshot.averageValue /= static_cast<double>(snapshot.sampleCount);
    snapshot.trendDelta = snapshot.currentValue - std::max(0.0, historyList.front());
    if (snapshot.minValue == std::numeric_limits<double>::max())
    {
        snapshot.minValue = 0.0;
    }
    return snapshot;
}

QString HardwareDock::buildTrendText(
    const UtilizationStatisticSnapshot& snapshot,
    const bool percentUnit) const
{
    // threshold: Ignores negligible fluctuations to prevent the page from flickering between 'rising' and 'falling' every second.
    const double kThreshold = percentUnit ? 1.0 : 1024.0;
    if (std::abs(snapshot.trendDelta) < kThreshold)
    {
        return QStringLiteral("平稳");
    }

    const QString kDirectionText = snapshot.trendDelta > 0.0
        ? QStringLiteral("上升")
        : QStringLiteral("下降");
    const double kAbsoluteDelta = std::abs(snapshot.trendDelta);
    if (percentUnit)
    {
        return QStringLiteral("%1 %2%")
            .arg(kDirectionText)
            .arg(kAbsoluteDelta, 0, 'f', 1);
    }
    return QStringLiteral("%1 %2")
        .arg(kDirectionText)
        .arg(formatRateText(kAbsoluteDelta));
}

QString HardwareDock::buildPressureLevelText(const double percentValue) const
{
    const double kSafePercentValue = std::clamp(percentValue, 0.0, 100.0);
    if (kSafePercentValue >= 90.0)
    {
        return QStringLiteral("极高");
    }
    if (kSafePercentValue >= 75.0)
    {
        return QStringLiteral("高");
    }
    if (kSafePercentValue >= 45.0)
    {
        return QStringLiteral("中");
    }
    if (kSafePercentValue >= 15.0)
    {
        return QStringLiteral("低");
    }
    return QStringLiteral("空闲");
}

QString HardwareDock::buildR0CpuFeatureBadgeText(const std::uint64_t featureMask) const
{
    // Input: KSWORD_ARK_CPU_FEATURE_* bitmap returned by R0 CPUID query.
    // Processing: Output short badges prioritized by performance/virtualization/security capabilities to avoid direct UI parsing of raw CPUID registers.
    // Return: Comma-separated capability text; 'N/A' if no capabilities are available to display.
    QStringList featureList;
    const auto kAppendFeatureIfPresent =
        [&featureList, featureMask](const std::uint64_t bitValue, const QString& featureName)
        {
            if ((featureMask & bitValue) != 0ULL)
            {
                featureList.append(featureName);
            }
        };

    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE, QStringLiteral("SSE"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE2, QStringLiteral("SSE2"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE3, QStringLiteral("SSE3"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSSE3, QStringLiteral("SSSE3"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE41, QStringLiteral("SSE4.1"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SSE42, QStringLiteral("SSE4.2"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_AES, QStringLiteral("AES"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_AVX, QStringLiteral("AVX"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_AVX2, QStringLiteral("AVX2"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_AVX512F, QStringLiteral("AVX512F"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_VMX, QStringLiteral("VMX"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_NX, QStringLiteral("NX"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SMEP, QStringLiteral("SMEP"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_SMAP, QStringLiteral("SMAP"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_RDTSCP, QStringLiteral("RDTSCP"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_INVARIANT_TSC, QStringLiteral("Invariant TSC"));
    kAppendFeatureIfPresent(KSWORD_ARK_CPU_FEATURE_HYPERVISOR, QStringLiteral("Hypervisor"));

    return featureList.isEmpty() ? QStringLiteral("N/A") : featureList.join(QStringLiteral(", "));
}

QString HardwareDock::buildPercentStatisticLine(
    const QString& labelText,
    const UtilizationStatisticSnapshot& snapshot) const
{
    return QStringLiteral("%1: 当前 %2% / 均值 %3% / 峰值 %4% / 趋势 %5 / 压力 %6 / 样本 %7")
        .arg(labelText)
        .arg(snapshot.currentValue, 0, 'f', 1)
        .arg(snapshot.averageValue, 0, 'f', 1)
        .arg(snapshot.peakValue, 0, 'f', 1)
        .arg(buildTrendText(snapshot, true))
        .arg(buildPressureLevelText(snapshot.currentValue))
        .arg(snapshot.sampleCount);
}

QString HardwareDock::buildRateStatisticLine(
    const QString& labelText,
    const UtilizationStatisticSnapshot& snapshot) const
{
    return QStringLiteral("%1: 当前 %2 / 均值 %3 / 峰值 %4 / 趋势 %5 / 样本 %6")
        .arg(labelText)
        .arg(formatRateText(snapshot.currentValue))
        .arg(formatRateText(snapshot.averageValue))
        .arg(formatRateText(snapshot.peakValue))
        .arg(buildTrendText(snapshot, false))
        .arg(snapshot.sampleCount);
}

void HardwareDock::requestAsyncR0HardwareHealthRefresh()
{
    // expectedFlag usage: Prevents concurrent sampling by multiple R0 threads.
    bool expectedFlag = false;
    if (!r0HardwareHealthRefreshing_.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    const qint64 kNowMs = QDateTime::currentMSecsSinceEpoch();
    if (lastR0HardwareHealthRefreshMs_ > 0 && kNowMs - lastR0HardwareHealthRefreshMs_ < 10'000)
    {
        r0HardwareHealthRefreshing_.store(false);
        return;
    }

    QPointer<HardwareDock> safeThis(this);
    std::thread([safeThis, kNowMs]() {
        // r0QueryLock usage: Health checks and on-demand device audits share a single serialized R0 request channel.
        const std::lock_guard<std::mutex> kR0QueryLock(hardwareR0QueryMutex);
        const ksword::ark::DriverClient kClient;
        const ksword::ark::DriverCapabilitiesQueryResult kCapabilityResult = kClient.queryDriverCapabilities();
        const ksword::ark::DynDataCapabilitiesResult kDynDataResult = kClient.queryDynDataCapabilities();
        const ksword::ark::DriverIntegrityResult kIntegrityResult = kClient.queryKernelCpuIntegrity();
        const ksword::ark::CpuHardwareSnapshotResult kCpuHardwareResult = kClient.queryCpuHardwareSnapshot();
        const ksword::ark::PhysicalMemoryLayoutResult kPhysicalMemoryResult = kClient.queryPhysicalMemoryLayout();

        if (safeThis.isNull())
        {
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kNowMs, kCapabilityResult, kDynDataResult, kIntegrityResult, kCpuHardwareResult, kPhysicalMemoryResult]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                const int kCpuEvidenceCount = static_cast<int>(kIntegrityResult.cpuCount);
                int idtEvidenceCount = 0;
                int msrEvidenceCount = 0;
                int highRiskCount = 0;
                int cpuProtectionRiskCount = 0;
                int unresolvedOwnerRiskCount = 0;
                for (const auto& entry : kIntegrityResult.entries)
                {
                    if (entry.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
                    {
                        ++idtEvidenceCount;
                    }
                    if (entry.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY)
                    {
                        ++msrEvidenceCount;
                    }
                    if (entry.riskFlags != KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE)
                    {
                        ++highRiskCount;
                    }
                    if ((entry.riskFlags
                        & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED)) != 0U)
                    {
                        ++cpuProtectionRiskCount;
                    }
                    if ((entry.riskFlags
                        & (KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER
                            | KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID)) != 0U)
                    {
                        ++unresolvedOwnerRiskCount;
                    }
                }

                int availableFeatureCount = 0;
                int degradedFeatureCount = 0;
                int deniedFeatureCount = 0;
                for (const auto& featureEntry : kCapabilityResult.entries)
                {
                    if (featureEntry.state == KSWORD_ARK_FEATURE_STATE_AVAILABLE)
                    {
                        ++availableFeatureCount;
                    }
                    else if (featureEntry.state == KSWORD_ARK_FEATURE_STATE_DEGRADED)
                    {
                        ++degradedFeatureCount;
                    }
                    else if (featureEntry.state == KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY)
                    {
                        ++deniedFeatureCount;
                    }
                }

                int healthScore = 100;
                if (!kCapabilityResult.io.ok)
                {
                    healthScore -= 25;
                }
                if (!kDynDataResult.io.ok || kDynDataResult.capabilityMask == 0ULL)
                {
                    healthScore -= 10;
                }
                if (!kIntegrityResult.io.ok)
                {
                    healthScore -= 35;
                }
                healthScore -= std::min(30, highRiskCount * 4);
                healthScore -= std::min(25, cpuProtectionRiskCount * 8);
                healthScore -= std::min(15, unresolvedOwnerRiskCount * 2);
                healthScore -= std::min(10, degradedFeatureCount * 2);
                healthScore -= std::min(10, deniedFeatureCount * 2);
                healthScore = std::clamp(healthScore, 0, 100);

                const QString kHealthLevelText = healthScore >= 90
                    ? QStringLiteral("优秀")
                    : (healthScore >= 75
                        ? QStringLiteral("良好")
                        : (healthScore >= 55
                            ? QStringLiteral("关注")
                            : QStringLiteral("高风险")));

                safeThis->r0HardwareHealthSummaryText_ = QStringLiteral(
                    "R0硬件健康: %1分/%2 | 风险=%3 保护风险=%4 | CPU=%5 IDT=%6 MSR=%7")
                    .arg(healthScore)
                    .arg(kHealthLevelText)
                    .arg(highRiskCount)
                    .arg(cpuProtectionRiskCount)
                    .arg(kCpuEvidenceCount)
                    .arg(idtEvidenceCount)
                    .arg(msrEvidenceCount);

                const QString kLastStatusText = QStringLiteral("0x%1")
                    .arg(static_cast<unsigned long>(kIntegrityResult.lastStatus), 8, 16, QChar('0'))
                    .toUpper();
                safeThis->r0HardwareHealthDetailText_ = QStringLiteral(
                    "R0健康: %1分/%2  CPU=%3  IDT=%4  MSR=%5  风险=%6  保护风险=%7\n"
                    "协议: avail=%8 degraded=%9 denied=%10  |  Last=%11")
                    .arg(healthScore)
                    .arg(kHealthLevelText)
                    .arg(kCpuEvidenceCount)
                    .arg(idtEvidenceCount)
                    .arg(msrEvidenceCount)
                    .arg(highRiskCount)
                    .arg(cpuProtectionRiskCount)
                    .arg(availableFeatureCount)
                    .arg(degradedFeatureCount)
                    .arg(deniedFeatureCount)
                    .arg(kIntegrityResult.io.ok ? kLastStatusText : QStringLiteral("N/A"));

                if (kCpuHardwareResult.io.ok)
                {
                    const QString kVendorText = QString::fromStdString(kCpuHardwareResult.vendor).trimmed();
                    const QString kBrandText = QString::fromStdString(kCpuHardwareResult.brand).trimmed();
                    const QString kFeatureBadgeText = safeThis->buildR0CpuFeatureBadgeText(kCpuHardwareResult.featureMask);
                    const QString kLeafText = QStringLiteral("basic=0x%1 ext=0x%2")
                        .arg(kCpuHardwareResult.maxBasicLeaf, 0, 16)
                        .arg(kCpuHardwareResult.maxExtendedLeaf, 0, 16)
                        .toUpper();
                    safeThis->r0CpuHardwareSummaryText_ = QStringLiteral(
                        "R0 CPU: %1 F%2/M%3/S%4 | 特性: %5")
                        .arg(kVendorText.isEmpty() ? QStringLiteral("N/A") : kVendorText)
                        .arg(kCpuHardwareResult.family)
                        .arg(kCpuHardwareResult.model)
                        .arg(kCpuHardwareResult.stepping)
                        .arg(kFeatureBadgeText);
                    safeThis->r0CpuHardwareDetailText_ = QStringLiteral(
                        "R0 CPUID: %1\n"
                        "Vendor: %2\n"
                        "Family/Model/Stepping: %3/%4/%5\n"
                        "Logical/Active: %6/%7\n"
                        "CLFLUSH line: %8 bytes\n"
                        "Leaves: %9\n"
                        "FeatureMask: 0x%10\n"
                        "Features: %11")
                        .arg(kBrandText.isEmpty() ? QStringLiteral("N/A") : kBrandText)
                        .arg(kVendorText.isEmpty() ? QStringLiteral("N/A") : kVendorText)
                        .arg(kCpuHardwareResult.family)
                        .arg(kCpuHardwareResult.model)
                        .arg(kCpuHardwareResult.stepping)
                        .arg(kCpuHardwareResult.logicalProcessorCount)
                        .arg(kCpuHardwareResult.activeProcessorCount)
                        .arg(kCpuHardwareResult.clflushLineSize)
                        .arg(kLeafText)
                        .arg(kCpuHardwareResult.featureMask, 16, 16, QChar('0'))
                        .arg(kFeatureBadgeText);
                    if (!kBrandText.isEmpty())
                    {
                        safeThis->cpuModelText_ = kBrandText;
                        if (safeThis->cpuModelLabel_ != nullptr)
                        {
                            safeThis->cpuModelLabel_->setText(kBrandText);
                        }
                    }
                }
                else
                {
                    const QString kReadableCpuIoMessage = friendlyHardwareIoMessage(
                        kCpuHardwareResult.io.message,
                        kCpuHardwareResult.unsupported);
                    safeThis->r0CpuHardwareSummaryText_ = kCpuHardwareResult.unsupported
                        ? QStringLiteral("R0 CPU硬件: 当前驱动不支持 CPUID 快照")
                        : QStringLiteral("R0 CPU硬件: 查询失败（Win32=%1）")
                            .arg(kCpuHardwareResult.io.win32Error);
                    safeThis->r0CpuHardwareDetailText_ = QStringLiteral(
                        "R0 CPUID 查询不可用\n"
                        "调用状态: %1\n"
                        "兼容性: %2\n"
                        "Win32错误: %3\n"
                        "NTSTATUS/LastStatus: 0x%4\n"
                        "说明: %5")
                        .arg(hardwareIoOkText(kCpuHardwareResult.io.ok))
                        .arg(kCpuHardwareResult.unsupported ? QStringLiteral("驱动不支持") : QStringLiteral("接口可用但查询失败"))
                        .arg(kCpuHardwareResult.io.win32Error)
                        .arg(QString::number(static_cast<std::uint32_t>(kCpuHardwareResult.lastStatus), 16).rightJustified(8, QChar('0')).toUpper())
                        .arg(kReadableCpuIoMessage);
                }

                if (kPhysicalMemoryResult.io.ok)
                {
                    const QString kTotalText = bytesToReadableText(static_cast<double>(kPhysicalMemoryResult.totalPhysicalBytes));
                    const QString kLargestText = bytesToReadableText(static_cast<double>(kPhysicalMemoryResult.largestRangeBytes));
                    const QString kGapText = bytesToReadableText(static_cast<double>(kPhysicalMemoryResult.estimatedAddressSpaceGapBytes));
                    safeThis->r0PhysicalMemorySummaryText_ = QStringLiteral(
                        "R0物理内存: %1 | ranges=%2 | 最大连续=%3")
                        .arg(kTotalText)
                        .arg(kPhysicalMemoryResult.rangeCount)
                        .arg(kLargestText);
                    safeThis->r0PhysicalMemoryDetailText_ = QStringLiteral(
                        "R0物理内存布局\n"
                        "总物理内存: %1\n"
                        "Range数量: %2  零长度: %3\n"
                        "最大连续Range: %4\n"
                        "最小Range: %5\n"
                        "最高物理地址: 0x%6\n"
                        "首Range基址: 0x%7\n"
                        "末Range结束: 0x%8\n"
                        "估算地址空洞: %9")
                        .arg(kTotalText)
                        .arg(kPhysicalMemoryResult.rangeCount)
                        .arg(kPhysicalMemoryResult.zeroLengthRangeCount)
                        .arg(kLargestText)
                        .arg(bytesToReadableText(static_cast<double>(kPhysicalMemoryResult.smallestRangeBytes)))
                        .arg(QString::number(kPhysicalMemoryResult.highestPhysicalAddress, 16).toUpper())
                        .arg(QString::number(kPhysicalMemoryResult.firstBaseAddress, 16).toUpper())
                        .arg(QString::number(kPhysicalMemoryResult.lastEndAddress, 16).toUpper())
                        .arg(kGapText);
                }
                else
                {
                    const QString kReadablePhysicalMemoryIoMessage = friendlyHardwareIoMessage(
                        kPhysicalMemoryResult.io.message,
                        kPhysicalMemoryResult.unsupported);
                    safeThis->r0PhysicalMemorySummaryText_ = kPhysicalMemoryResult.unsupported
                        ? QStringLiteral("R0物理内存: 当前驱动不支持布局快照")
                        : QStringLiteral("R0物理内存: 查询失败（Win32=%1）")
                            .arg(kPhysicalMemoryResult.io.win32Error);
                    safeThis->r0PhysicalMemoryDetailText_ = QStringLiteral(
                        "R0物理内存布局查询不可用\n"
                        "调用状态: %1\n"
                        "兼容性: %2\n"
                        "Win32错误: %3\n"
                        "NTSTATUS/LastStatus: 0x%4\n"
                        "说明: %5")
                        .arg(hardwareIoOkText(kPhysicalMemoryResult.io.ok))
                        .arg(kPhysicalMemoryResult.unsupported ? QStringLiteral("驱动不支持") : QStringLiteral("接口可用但查询失败"))
                        .arg(kPhysicalMemoryResult.io.win32Error)
                        .arg(QString::number(static_cast<std::uint32_t>(kPhysicalMemoryResult.lastStatus), 16).rightJustified(8, QChar('0')).toUpper())
                        .arg(kReadablePhysicalMemoryIoMessage);
                }

                safeThis->lastR0HardwareHealthRefreshMs_ = kNowMs;
                safeThis->r0HardwareHealthRefreshing_.store(false);
            },
            Qt::QueuedConnection);

        if (!kInvokeOk && !safeThis.isNull())
        {
            safeThis->r0HardwareHealthRefreshing_.store(false);
        }
    }).detach();
}

void HardwareDock::refreshStaticHardwareTexts(const bool forceRefresh)
{
    const QPointer<HardwareDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("hardware-device-audit-tables-refresh"),
        {
            deviceStackTable_,
            keyboardMouseHidTable_,
            usbTopologyTable_
        },
        [kSafeThis, forceRefresh]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->refreshStaticHardwareTexts(forceRefresh);
            }
        }))
    {
        return;
    }

    if (forceRefresh)
    {
        // The current diagnostic page requests only the data it needs; regular pages still update only lightweight static overviews.
        // This avoids continuously submitting three large R0 queries for Device/Input/USB every 60 seconds for automatic refresh.
        std::uint32_t deviceAuditRefreshMask = 0U;
        QWidget* const kCurrentPage = sideTabWidget_ != nullptr
            ? sideTabWidget_->currentWidget()
            : nullptr;
        if (kCurrentPage == deviceStackPage_)
        {
            deviceAuditRefreshMask = kDeviceStackAuditRefresh;
        }
        else if (kCurrentPage == keyboardMouseHidPage_)
        {
            deviceAuditRefreshMask = kInputStackAuditRefresh;
        }
        else if (kCurrentPage == usbTopologyPage_)
        {
            deviceAuditRefreshMask = kUsbTopologyAuditRefresh;
        }
        else if (kCurrentPage == pnpAcpiPciPage_)
        {
            deviceAuditRefreshMask = kPnpAcpiPciRefresh;
        }

        if (deviceAuditRefreshMask != 0U)
        {
            requestAsyncDeviceAuditRefresh(deviceAuditRefreshMask);
        }
        else
        {
            requestAsyncStaticInfoRefresh();
        }
    }

    if (overviewEditor_ != nullptr && !cachedOverviewStaticText_.isEmpty())
    {
        overviewEditor_->setText(cachedOverviewStaticText_);
    }
    if (gpuEditor_ != nullptr && !cachedGpuStaticText_.isEmpty())
    {
        gpuEditor_->setText(cachedGpuStaticText_);
    }
    if (memoryEditor_ != nullptr && !cachedMemoryStaticText_.isEmpty())
    {
        memoryEditor_->setText(cachedMemoryStaticText_);
    }
    if (deviceStackEditor_ != nullptr && !cachedDeviceStackStaticText_.isEmpty())
    {
        deviceStackEditor_->setText(cachedDeviceStackStaticText_);
    }
    populateDeviceAuditTable(deviceStackTable_, cachedDeviceStackRows_);
    if (keyboardMouseHidEditor_ != nullptr && !cachedKeyboardMouseHidStaticText_.isEmpty())
    {
        keyboardMouseHidEditor_->setText(cachedKeyboardMouseHidStaticText_);
    }
    populateDeviceAuditTable(keyboardMouseHidTable_, cachedKeyboardMouseHidRows_);
    if (usbTopologyEditor_ != nullptr && !cachedUsbTopologyStaticText_.isEmpty())
    {
        usbTopologyEditor_->setText(cachedUsbTopologyStaticText_);
    }
    populateDeviceAuditTable(usbTopologyTable_, cachedUsbTopologyRows_);
    if (pnpAcpiPciEditor_ != nullptr && !cachedPnpAcpiPciStaticText_.isEmpty())
    {
        pnpAcpiPciEditor_->setText(cachedPnpAcpiPciStaticText_);
    }
}

void HardwareDock::requestAsyncStaticInfoRefresh()
{
    // expectedFlag: CAS expected value for atomic refresh lock (false = no task currently).
    bool expectedFlag = false;
    if (!staticInfoRefreshing_.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    QPointer<HardwareDock> safeThis(this);
    std::thread([safeThis]() {
        if (safeThis.isNull())
        {
            return;
        }

        const QString kOverviewBaseText = buildOverviewStaticTextSnapshot();
        const QString kPeripheralOverviewText = buildOverviewPeripheralTextSnapshot();
        const QString kOverviewText = kOverviewBaseText
            + QStringLiteral("\n[硬件设备总览]\n")
            + kPeripheralOverviewText;
        const QString kGpuWmiText = buildGpuStaticTextSnapshot();
        const QString kMemoryText = buildMemoryStaticTextSnapshot();
        const MemoryHardwareSummarySnapshot kMemorySummary = queryMemoryHardwareSummarySnapshot();
        const GpuHardwareSummarySnapshot kGpuSummary = queryGpuHardwareSummarySnapshot();

        if (safeThis.isNull())
        {
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, kOverviewText, kGpuWmiText, kMemoryText, kMemorySummary, kGpuSummary]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->cachedOverviewStaticText_ = kOverviewText;
                safeThis->cachedGpuStaticText_ = formatGpuHardwareSummaryText(kGpuSummary, kGpuWmiText);
                safeThis->cachedMemoryStaticText_ = kMemoryText;
                safeThis->memorySpeedMhz_ = kMemorySummary.speedMhz;
                safeThis->memorySlotUsed_ = kMemorySummary.usedSlots;
                safeThis->memorySlotTotal_ = kMemorySummary.totalSlots;
                safeThis->memoryFormFactorText_ = kMemorySummary.formFactorText;
                if (safeThis->gpuAdapterNameText_.trimmed().isEmpty()
                    || safeThis->gpuAdapterNameText_ == QStringLiteral("N/A"))
                {
                    safeThis->gpuAdapterNameText_ = kGpuSummary.adapterNameText;
                }
                safeThis->gpuDriverVersionText_ = kGpuSummary.driverVersionText;
                safeThis->gpuDriverDateText_ = kGpuSummary.driverDateText;
                safeThis->gpuPnpDeviceIdText_ = kGpuSummary.pnpDeviceIdText;
                if (safeThis->gpuDedicatedMemoryGiB_ <= 0.0)
                {
                    safeThis->gpuDedicatedMemoryGiB_ = kGpuSummary.dedicatedMemoryGiB;
                }
                emit safeThis->staticOverviewChanged(safeThis->cachedOverviewStaticText_);
                safeThis->refreshStaticHardwareTexts(false);
                safeThis->staticInfoRefreshing_.store(false);
            },
            Qt::QueuedConnection);

        if (!kInvokeOk && !safeThis.isNull())
        {
            safeThis->staticInfoRefreshing_.store(false);
        }
        }).detach();
}

void HardwareDock::requestAsyncDeviceAuditRefresh(const std::uint32_t refreshMask)
{
    // normalizedMask purpose: Filters out unknown bits accidentally passed by the caller to avoid meaningless background tasks.
    const std::uint32_t kNormalizedMask = refreshMask &
        static_cast<std::uint32_t>(kAllDeviceAuditRefresh);
    if (kNormalizedMask == 0U)
    {
        return;
    }

    // The pending mask is merged first before acquiring execution rights; rapid page switching will not lose requests or concurrently start multiple threads.
    pendingDeviceAuditRefreshMask_.fetch_or(kNormalizedMask);
    bool expectedFlag = false;
    if (!deviceAuditRefreshing_.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    // requestedMask usage: obtain merged page bits once in this round; subsequent re-entries remain in pending for the next round.
    const std::uint32_t kRequestedMask =
        pendingDeviceAuditRefreshMask_.exchange(0U) &
        static_cast<std::uint32_t>(kAllDeviceAuditRefresh);
    QObject* const kApplicationContext = QCoreApplication::instance();
    if (kApplicationContext == nullptr)
    {
        deviceAuditRefreshing_.store(false);
        return;
    }

    QPointer<HardwareDock> safeThis(this);
    auto* deviceAuditTask = QRunnable::create(
        [kApplicationContext, safeThis, kRequestedMask]()
    {
        DeviceAuditViewSnapshot deviceStackSnapshot;
        DeviceAuditViewSnapshot inputStackSnapshot;
        DeviceAuditViewSnapshot usbTopologySnapshot;
        QString pnpAcpiPciText;

        // Three types of R0 audits share a serial lock and query only pages that are currently open.
        // PnP/ACPI/PCI are R3 text collection, do not consume driver channels.
        {
            const std::lock_guard<std::mutex> kR0QueryLock(hardwareR0QueryMutex);
            if ((kRequestedMask & kDeviceStackAuditRefresh) != 0U)
            {
                deviceStackSnapshot = HardwareDock::buildDeviceStackAuditViewSnapshot();
            }
            if ((kRequestedMask & kInputStackAuditRefresh) != 0U)
            {
                inputStackSnapshot = HardwareDock::buildKeyboardMouseHidAuditViewSnapshot();
            }
            if ((kRequestedMask & kUsbTopologyAuditRefresh) != 0U)
            {
                usbTopologySnapshot = HardwareDock::buildUsbTopologyAuditViewSnapshot();
            }
        }
        if ((kRequestedMask & kPnpAcpiPciRefresh) != 0U)
        {
            pnpAcpiPciText = HardwareDock::buildPnpAcpiPciStaticText();
        }

        // applicationContext has the same lifetime as the event loop; worker threads do not read page QPointers or dereference page members.
        QMetaObject::invokeMethod(
            kApplicationContext,
            [safeThis,
                kRequestedMask,
                deviceStackSnapshot = std::move(deviceStackSnapshot),
                inputStackSnapshot = std::move(inputStackSnapshot),
                usbTopologySnapshot = std::move(usbTopologySnapshot),
                pnpAcpiPciText = std::move(pnpAcpiPciText)]() mutable
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->applyDeviceAuditRefreshResult(
                    kRequestedMask,
                    std::move(deviceStackSnapshot),
                    std::move(inputStackSnapshot),
                    std::move(usbTopologySnapshot),
                    std::move(pnpAcpiPciText));
            },
            Qt::QueuedConnection);
    });
    deviceAuditTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(deviceAuditTask);
}

void HardwareDock::applyDeviceAuditRefreshResult(
    const std::uint32_t requestedMask,
    DeviceAuditViewSnapshot deviceStackSnapshot,
    DeviceAuditViewSnapshot inputStackSnapshot,
    DeviceAuditViewSnapshot usbTopologySnapshot,
    QString pnpAcpiPciText)
{
    const QList<QTableView*> kDeviceAuditTables = {
        deviceStackTable_,
        keyboardMouseHidTable_,
        usbTopologyTable_
    };
    if (ks::ui::isTableUiCommitBlockedByContextMenu(kDeviceAuditTables))
    {
        const QPointer<HardwareDock> kSafeThis(this);
        ks::ui::deferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("hardware-device-audit-snapshot-apply"),
            kDeviceAuditTables,
            [kSafeThis,
                requestedMask,
                deviceStackSnapshot = std::move(deviceStackSnapshot),
                inputStackSnapshot = std::move(inputStackSnapshot),
                usbTopologySnapshot = std::move(usbTopologySnapshot),
                pnpAcpiPciText = std::move(pnpAcpiPciText)]() mutable
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->applyDeviceAuditRefreshResult(
                        requestedMask,
                        std::move(deviceStackSnapshot),
                        std::move(inputStackSnapshot),
                        std::move(usbTopologySnapshot),
                        std::move(pnpAcpiPciText));
                }
            });
        return;
    }

    if ((requestedMask & kDeviceStackAuditRefresh) != 0U)
    {
        cachedDeviceStackStaticText_ = std::move(deviceStackSnapshot.summaryText);
        cachedDeviceStackRows_ = std::move(deviceStackSnapshot.rows);
    }
    if ((requestedMask & kInputStackAuditRefresh) != 0U)
    {
        cachedKeyboardMouseHidStaticText_ = std::move(inputStackSnapshot.summaryText);
        cachedKeyboardMouseHidRows_ = std::move(inputStackSnapshot.rows);
    }
    if ((requestedMask & kUsbTopologyAuditRefresh) != 0U)
    {
        cachedUsbTopologyStaticText_ = std::move(usbTopologySnapshot.summaryText);
        cachedUsbTopologyRows_ = std::move(usbTopologySnapshot.rows);
    }
    if ((requestedMask & kPnpAcpiPciRefresh) != 0U)
    {
        cachedPnpAcpiPciStaticText_ = std::move(pnpAcpiPciText);
    }

    refreshStaticHardwareTexts(false);
    deviceAuditRefreshing_.store(false);

    // pendingMask usage: Captures page-fault requests occurring during worker thread execution; serializes them for the next round.
    const std::uint32_t kPendingMask = pendingDeviceAuditRefreshMask_.load();
    if (kPendingMask != 0U)
    {
        requestAsyncDeviceAuditRefresh(kPendingMask);
    }
}

void HardwareDock::requestAsyncSensorRefresh()
{
    // expectedFlag: CAS expected value for atomic refresh lock (false = no task currently).
    bool expectedFlag = false;
    if (!sensorRefreshing_.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    // event usage: Links the current CPU sensor read with log output to facilitate tracking failure causes.
    KLogEvent event;
    QPointer<HardwareDock> safeThis(this);
    std::thread([safeThis, event]() {
        const SensorProbeResult kTemperatureProbeResult = queryCpuTemperatureProbeResult();
        const SensorProbeResult kVoltageProbeResult = queryCpuVoltageProbeResult();
        if (safeThis.isNull())
        {
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, event, kTemperatureProbeResult, kVoltageProbeResult]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                // previousSensorPartList: Split previous cache to retain the last valid values for temperature and voltage separately.
                const QStringList kPreviousSensorPartList = safeThis->cachedSensorText_.split('|');
                QString cachedTemperatureText =
                    kPreviousSensorPartList.size() >= 1 ? kPreviousSensorPartList.at(0) : QStringLiteral("N/A");
                QString cachedVoltageText =
                    kPreviousSensorPartList.size() >= 2 ? kPreviousSensorPartList.at(1) : QStringLiteral("N/A");

                if (isReadableSensorValue(kTemperatureProbeResult.valueText))
                {
                    cachedTemperatureText = kTemperatureProbeResult.valueText;
                }
                if (isReadableSensorValue(kVoltageProbeResult.valueText))
                {
                    cachedVoltageText = kVoltageProbeResult.valueText;
                }
                if (!isReadableSensorValue(cachedTemperatureText))
                {
                    cachedTemperatureText = QStringLiteral("N/A");
                }
                if (!isReadableSensorValue(cachedVoltageText))
                {
                    cachedVoltageText = QStringLiteral("N/A");
                }

                safeThis->cachedSensorText_ = QStringLiteral("%1|%2")
                    .arg(cachedTemperatureText)
                    .arg(cachedVoltageText);

                // previousLogSignatureText: Previous log signature, used to deduplicate failure/recovery logs.
                const QString kPreviousLogSignatureText = safeThis->lastSensorLogSignatureText_;
                const QString kLogSignatureText =
                    buildSensorProbeSignatureText(QStringLiteral("温度"), kTemperatureProbeResult)
                    + QStringLiteral("||")
                    + buildSensorProbeSignatureText(QStringLiteral("电压"), kVoltageProbeResult);
                if (kLogSignatureText != kPreviousLogSignatureText)
                {
                    safeThis->lastSensorLogSignatureText_ = kLogSignatureText;

                    // hasUnexpectedFailure purpose: Only promote truly exceptional failures like script failures, permission anomalies, or execution timeouts to WARN.
                    // Purpose of allProbeSucceeded: output recovery logs only when both temperature and voltage become readable again, to avoid false alarms for the normal N/A state.
                    const bool kHasUnexpectedFailure =
                        (!kTemperatureProbeResult.success && !kTemperatureProbeResult.expectedUnavailable)
                        || (!kVoltageProbeResult.success && !kVoltageProbeResult.expectedUnavailable);
                    const bool kAllProbeSucceeded = kTemperatureProbeResult.success && kVoltageProbeResult.success;
                    if (kHasUnexpectedFailure)
                    {
                        warn << event
                             << "[HardwareDock] CPU传感器读取失败："
                             << buildSensorProbeLogFragment(QStringLiteral("温度"), kTemperatureProbeResult)
                             << "；"
                             << buildSensorProbeLogFragment(QStringLiteral("电压"), kVoltageProbeResult)
                             << eol;
                    }
                    else if (kAllProbeSucceeded && !kPreviousLogSignatureText.isEmpty())
                    {
                        info << event
                             << "[HardwareDock] CPU传感器读取恢复："
                             << buildSensorProbeLogFragment(QStringLiteral("温度"), kTemperatureProbeResult)
                             << "；"
                             << buildSensorProbeLogFragment(QStringLiteral("电压"), kVoltageProbeResult)
                             << eol;
                    }
                }
                safeThis->sensorRefreshing_.store(false);
            },
            Qt::QueuedConnection);

        if (!kInvokeOk && !safeThis.isNull())
        {
            warn << event << "[HardwareDock] CPU传感器结果回投UI线程失败。" << eol;
            safeThis->sensorRefreshing_.store(false);
        }
        }).detach();
}

QString HardwareDock::buildOverviewStaticText() const
{
    return buildOverviewStaticTextSnapshot();
}

QString HardwareDock::buildGpuStaticText() const
{
    return buildGpuStaticTextSnapshot();
}

QString HardwareDock::buildMemoryStaticText() const
{
    return buildMemoryStaticTextSnapshot();
}

QString HardwareDock::buildCpuSensorText(const bool forceRefresh)
{
    // Changed the forced refresh scenario to 'asynchronous trigger' to ensure the caller does not block the UI thread.
    if (forceRefresh)
    {
        requestAsyncSensorRefresh();
    }

    if (!cachedSensorText_.isEmpty())
    {
        return cachedSensorText_;
    }
    return QStringLiteral("N/A|N/A");
}

QString HardwareDock::buildDeviceStackStaticText() const
{
    return buildDeviceStackAuditViewSnapshot().summaryText;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildDeviceStackAuditViewSnapshot()
{
    // scriptText purpose: Preserves the original Win32_PnPEntity / PnP cross-view output.
    // r0AuditResult: Appends R0 device stack audit summaries and structured rows via ArkDriverClient.
    const QString kScriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$rows=Get-CimInstance Win32_PnPEntity | Select-Object Name,PNPClass,Service,Status,PNPDeviceID,ConfigManagerErrorCode -First 120; "
        "$text='[DevNode / Device Stack]\\n'; "
        "$text += '说明：上方为 WMI/DevNode 视角；下方结构化表展示 R0 DeviceStack 行、attached/next 关系、风险标记和 PDB/DynData readiness。`n'; "
        "$text += ($rows | Format-Table -AutoSize | Out-String); "
        "$text += \"`n风险标记: 不执行卸载/删除/patch。\"; "
        "Write-Output $text");
    QString text = queryPowerShellTextSync(kScriptText, 8000);
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DeviceAuditResult kR0AuditResult = kClient.queryDeviceStackAudit();
    text += appendDeviceAuditSummaryText(
        QStringLiteral("R0 Device Stack Audit Summary"),
        kR0AuditResult,
        KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH);

    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryText = text;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("DeviceStack"), kR0AuditResult);
    return snapshot;
}

QString HardwareDock::buildKeyboardMouseHidStaticText() const
{
    return buildKeyboardMouseHidAuditViewSnapshot().summaryText;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildKeyboardMouseHidAuditViewSnapshot()
{
    // scriptText purpose: Preserve original WMI/PnP output for Keyboard/Mouse/HIDClass;
    // r0AuditResult purpose: Append R0 input device chain read-only audit summary and structured rows.
    const QString kScriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$rows=Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -in @('Keyboard','Mouse','HIDClass') -or $_.Service -match 'kbdhid|mouhid|hidusb' } | "
        "Select-Object Name,PNPClass,Service,Status,PNPDeviceID -First 160; "
        "$text='[Keyboard / Mouse / HID]\\n'; "
        "$text += '说明：默认不做消息截获、不做输入抓取。`n'; "
        "$text += ($rows | Format-Table -AutoSize | Out-String); "
        "Write-Output $text");
    QString text = queryPowerShellTextSync(kScriptText, 8000);
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DeviceAuditResult kR0AuditResult = kClient.queryInputStackAudit();
    text += appendDeviceAuditSummaryText(
        QStringLiteral("R0 Input Stack Audit Summary"),
        kR0AuditResult,
        KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH);

    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryText = text;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("InputStack"), kR0AuditResult);
    return snapshot;
}

QString HardwareDock::buildUsbTopologyStaticText() const
{
    return buildUsbTopologyAuditViewSnapshot().summaryText;
}

HardwareDock::DeviceAuditViewSnapshot HardwareDock::buildUsbTopologyAuditViewSnapshot()
{
    // scriptText usage: preserve WMI topology output for USB controllers/hubs/links.
    // r0AuditResult usage: Appends a read-only R0 USB topology audit summary and structured rows.
    const QString kScriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$controllers=Get-CimInstance Win32_USBController | Select-Object Name,Manufacturer,DeviceID,PNPDeviceID,Status; "
        "$hubs=Get-CimInstance Win32_USBHub | Select-Object Name,DeviceID,PNPDeviceID,Status; "
        "$links=Get-CimInstance Win32_USBControllerDevice | Select-Object Antecedent,Dependent -First 80; "
        "$text='[USB Topology]\\n'; "
        "$text += \"[USB控制器]\\n\" + ($controllers | Format-Table -AutoSize | Out-String); "
        "$text += \"`n[USB Hub]\\n\" + ($hubs | Format-Table -AutoSize | Out-String); "
        "$text += \"`n[USB连接]\\n\" + ($links | Format-Table -AutoSize | Out-String); "
        "Write-Output $text");
    QString text = queryPowerShellTextSync(kScriptText, 10000);
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DeviceAuditResult kR0AuditResult = kClient.queryUsbTopologyAudit();
    text += appendDeviceAuditSummaryText(
        QStringLiteral("R0 USB Topology Audit Summary"),
        kR0AuditResult,
        KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH);

    DeviceAuditViewSnapshot snapshot;
    snapshot.summaryText = text;
    snapshot.rows = buildDeviceAuditRows(QStringLiteral("UsbTopology"), kR0AuditResult);
    return snapshot;
}

QString HardwareDock::buildPnpAcpiPciStaticText()
{
    const QString kScriptText = QStringLiteral(
        "$ErrorActionPreference='SilentlyContinue'; "
        "$pnp=Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -like 'ACPI*' -or $_.PNPDeviceID -like 'PCI*' } | "
        "Select-Object Name,PNPClass,Service,Status,PNPDeviceID,ConfigManagerErrorCode -First 180; "
        "$board=Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version,SerialNumber; "
        "$bios=Get-CimInstance Win32_BIOS | Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber; "
        "$text='[PnP / ACPI / PCI]\\n'; "
        "$text += \"[主板/BIOS]\\n\" + ($board | Format-Table -AutoSize | Out-String) + \"`n\" + ($bios | Format-Table -AutoSize | Out-String); "
        "$text += \"`n[PnP节点]\\n\" + ($pnp | Format-Table -AutoSize | Out-String); "
        "$text += \"`n风险标记: 保持只读，不做 patch/remove/disable。\"; "
        "Write-Output $text");
    return queryPowerShellTextSync(kScriptText, 10000);
}
