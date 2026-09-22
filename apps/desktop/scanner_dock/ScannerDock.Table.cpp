#include "ScannerDock.h"

#include "internationalization/LanguageManager.h"
#include "../../../shared/platform/scanner/BinaryScanner.h"
#include "Theme.h"

#include <QAction>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <memory>
#include <vector>

namespace
{
    // fromBackendUtf8: Converts UTF-8 identifiers and fallback text from the scanning backend into a Qt string.
    QString fromBackendUtf8(const std::string& value)
    {
        return QString::fromUtf8(value.data(), static_cast<qsizetype>(value.size()));
    }
}

QString ScannerDock::localizedTableTitle(
    const std::string& tableId,
    const std::string& fallback) const
{
    const QString kId = fromBackendUtf8(tableId).toLower();
    if (kId == QStringLiteral("sections"))
    {
        return translated("scanner.table.sections", "节区");
    }
    if (kId == QStringLiteral("segments"))
    {
        return translated("scanner.table.segments", "段");
    }
    if (kId == QStringLiteral("imports"))
    {
        return translated("scanner.table.imports", "导入");
    }
    if (kId == QStringLiteral("exports"))
    {
        return translated("scanner.table.exports", "导出");
    }
    if (kId == QStringLiteral("symbols"))
    {
        return translated("scanner.table.symbols", "符号");
    }
    if (kId == QStringLiteral("load_commands"))
    {
        return translated("scanner.table.load_commands", "加载命令");
    }
    if (kId == QStringLiteral("fat_architectures") ||
        kId == QStringLiteral("architectures") ||
        kId == QStringLiteral("slices"))
    {
        return translated("scanner.table.architectures", "架构切片");
    }
    if (kId == QStringLiteral("dynamic_entries") ||
        kId == QStringLiteral("dynamic_dependencies"))
    {
        return translated("scanner.table.dynamic_entries", "动态链接条目");
    }
    if (kId == QStringLiteral("dynamic_libraries"))
    {
        return translated("scanner.table.dynamic_libraries", "动态库");
    }
    if (kId == QStringLiteral("program_headers"))
    {
        return translated("scanner.table.program_headers", "程序头");
    }
    if (kId == QStringLiteral("container_entries"))
    {
        return translated("scanner.table.container_entries", "容器成员");
    }
    return ks::i18n::sourceText(fromBackendUtf8(fallback));
}

QString ScannerDock::localizedColumnTitle(const std::string& fallback) const
{
    const QString kValue = fromBackendUtf8(fallback);
    const QString kNormalized = kValue.trimmed().toLower();
    if (kNormalized == QStringLiteral("name"))
    {
        return translated("scanner.column.name", "名称");
    }
    if (kNormalized == QStringLiteral("value"))
    {
        return translated("scanner.column.value", "值");
    }
    if (kNormalized == QStringLiteral("index"))
    {
        return translated("scanner.column.index", "索引");
    }
    if (kNormalized == QStringLiteral("type"))
    {
        return translated("scanner.column.type", "类型");
    }
    if (kNormalized == QStringLiteral("flags"))
    {
        return translated("scanner.column.flags", "标志");
    }
    if (kNormalized == QStringLiteral("offset") || kNormalized == QStringLiteral("file offset"))
    {
        return translated("scanner.column.offset", "偏移");
    }
    if (kNormalized == QStringLiteral("size") || kNormalized == QStringLiteral("file size"))
    {
        return translated("scanner.column.size", "大小");
    }
    if (kNormalized == QStringLiteral("address") ||
        kNormalized == QStringLiteral("virtual address"))
    {
        return translated("scanner.column.address", "地址");
    }
    if (kNormalized == QStringLiteral("format"))
    {
        return translated("scanner.column.format", "格式");
    }
    if (kNormalized == QStringLiteral("byte order"))
    {
        return translated("scanner.column.byte_order", "字节序");
    }
    if (kNormalized == QStringLiteral("module") || kNormalized == QStringLiteral("library"))
    {
        return translated("scanner.column.module", "模块");
    }
    if (kNormalized == QStringLiteral("ordinal"))
    {
        return translated("scanner.column.ordinal", "序号");
    }
    if (kNormalized == QStringLiteral("path"))
    {
        return translated("scanner.column.path", "路径");
    }
    if (kNormalized == QStringLiteral("extent"))
    {
        return translated("scanner.column.extent", "区段号");
    }
    if (kNormalized == QStringLiteral("volume id"))
    {
        return translated("scanner.column.volume_id", "卷标识");
    }
    if (kNormalized == QStringLiteral("filename encoding"))
    {
        return translated("scanner.column.filename_encoding", "文件名编码");
    }
    if (kNormalized == QStringLiteral("logical block size"))
    {
        return translated("scanner.column.logical_block_size", "逻辑块大小");
    }
    if (kNormalized == QStringLiteral("container entries"))
    {
        return translated("scanner.column.container_entries", "容器成员数");
    }
    if (kNormalized == QStringLiteral("volume descriptor offset"))
    {
        return translated("scanner.column.volume_descriptor_offset", "卷描述符偏移");
    }
    if (kNormalized == QStringLiteral("root directory extent"))
    {
        return translated("scanner.column.root_directory_extent", "根目录区段号");
    }
    if (kNormalized == QStringLiteral("root directory size"))
    {
        return translated("scanner.column.root_directory_size", "根目录大小");
    }
    return ks::i18n::sourceText(kValue);
}

QString ScannerDock::localizedTableValue(
    const std::string& tableId,
    const int column,
    const std::string& fallback) const
{
    const QString kId = fromBackendUtf8(tableId).toLower();
    const QString kValue = fromBackendUtf8(fallback);
    if (kId == QStringLiteral("container_entries") && column == 1)
    {
        if (kValue == QStringLiteral("Directory"))
        {
            return translated("scanner.container.type.directory", "目录");
        }
        if (kValue == QStringLiteral("File"))
        {
            return translated("scanner.container.type.file", "文件");
        }
        if (kValue == QStringLiteral("File (multi-extent)"))
        {
            return translated("scanner.container.type.multi_extent", "文件（多区段）");
        }
    }
    return ks::i18n::sourceText(kValue);
}

QString ScannerDock::localizedDiagnosticMessage(
    const std::string& code,
    const std::string& fallback) const
{
    const QString kId = fromBackendUtf8(code).toLower();
    if (kId == QStringLiteral("iso.volume_descriptor_invalid"))
    {
        return translated("scanner.diagnostic.iso.volume_invalid", "ISO9660 卷描述符或根目录无效。");
    }
    if (kId == QStringLiteral("iso.directory_record_invalid"))
    {
        return translated("scanner.diagnostic.iso.directory_invalid", "ISO9660 目录记录被截断或格式错误。");
    }
    if (kId == QStringLiteral("iso.identifier_invalid"))
    {
        return translated("scanner.diagnostic.iso.identifier_invalid", "ISO9660 文件标识超出目录记录范围。");
    }
    if (kId == QStringLiteral("iso.extent_mismatch"))
    {
        return translated("scanner.diagnostic.iso.extent_mismatch", "ISO9660 区段的小端与大端副本不一致。");
    }
    if (kId == QStringLiteral("iso.extent_out_of_bounds"))
    {
        return translated("scanner.diagnostic.iso.extent_out_of_bounds", "ISO9660 成员区段超出镜像快照。");
    }
    if (kId == QStringLiteral("iso.entry_limit_reached"))
    {
        return translated("scanner.diagnostic.iso.entry_limit", "ISO9660 遍历已在成员数量上限处停止。");
    }
    if (kId == QStringLiteral("iso.read_only_analysis"))
    {
        return translated("scanner.diagnostic.iso.read_only", "镜像仅从稳定字节快照解析；未挂载镜像，也未执行成员。");
    }
    return ks::i18n::sourceText(fromBackendUtf8(fallback));
}

QString ScannerDock::diagnosticSeverityText(const int severity) const
{
    switch (static_cast<ks::scanner::DiagnosticSeverity>(severity))
    {
    case ks::scanner::DiagnosticSeverity::kInformation:
        return translated("scanner.severity.information", "信息");
    case ks::scanner::DiagnosticSeverity::kWarning:
        return translated("scanner.severity.warning", "警告");
    case ks::scanner::DiagnosticSeverity::kError:
        return translated("scanner.severity.error", "错误");
    default:
        return translated("scanner.severity.unknown", "未知");
    }
}

QString ScannerDock::attackPathSeverityText(const int severity) const
{
    switch (static_cast<ks::scanner::AttackPathSeverity>(severity))
    {
    case ks::scanner::AttackPathSeverity::kInformation:
        return translated("scanner.attack.severity.information", "信息");
    case ks::scanner::AttackPathSeverity::kSuspicious:
        return translated("scanner.attack.severity.suspicious", "可疑");
    case ks::scanner::AttackPathSeverity::kHigh:
        return translated("scanner.attack.severity.high", "高危");
    case ks::scanner::AttackPathSeverity::kCritical:
        return translated("scanner.attack.severity.critical", "严重");
    default:
        return translated("scanner.severity.unknown", "未知");
    }
}

QString ScannerDock::attackPathStageText(const std::string& stage) const
{
    const QString kId = fromBackendUtf8(stage).toLower();
    if (kId == QStringLiteral("sideload"))
    {
        return translated("scanner.attack.stage.sideload", "DLL 侧载");
    }
    if (kId == QStringLiteral("elevation"))
    {
        return translated("scanner.attack.stage.elevation", "权限提升");
    }
    if (kId == QStringLiteral("masquerade"))
    {
        return translated("scanner.attack.stage.masquerade", "进程伪装");
    }
    if (kId == QStringLiteral("payload_decode"))
    {
        return translated("scanner.attack.stage.payload_decode", "载荷解码");
    }
    if (kId == QStringLiteral("persistence"))
    {
        return translated("scanner.attack.stage.persistence", "驱动服务");
    }
    if (kId == QStringLiteral("defense_evasion"))
    {
        return translated("scanner.attack.stage.defense_evasion", "防护破坏");
    }
    return ks::i18n::sourceText(fromBackendUtf8(stage));
}

QString ScannerDock::attackPathEvidenceText(const std::string& code) const
{
    const QString kId = fromBackendUtf8(code).toLower();
    if (kId == QStringLiteral("container.libcef_sideload_pair"))
    {
        return translated("scanner.attack.evidence.sideload_pair", "容器内 PE 的导入表指向同目录 libcef.dll。");
    }
    if (kId == QStringLiteral("proxy.cef_surface"))
    {
        return translated("scanner.attack.evidence.cef_surface", "DLL 提供 cef_execute_process、cef_initialize 等 CEF 代理导出。");
    }
    if (kId == QStringLiteral("proxy.cmstplua_uac"))
    {
        return translated("scanner.attack.evidence.cmstplua", "发现 CMSTPLUA 提权 moniker、CoGetObject 与管理员令牌检查组合。");
    }
    if (kId == QStringLiteral("proxy.peb_masquerade"))
    {
        return translated("scanner.attack.evidence.peb_masquerade", "发现把 PEB 进程参数改写为 C:\\Windows\\explorer.exe 的组合证据。");
    }
    if (kId == QStringLiteral("proxy.driver_service"))
    {
        return translated("scanner.attack.evidence.driver_service", "发现创建并启动 GhostSystemDriver 内核驱动服务的组合证据。");
    }
    if (kId == QStringLiteral("proxy.avp_evasion"))
    {
        return translated("scanner.attack.evidence.avp_evasion", "提权/驱动投递路径同时检查 avp.exe，符合安全软件规避。");
    }
    if (kId == QStringLiteral("embedded.double_base64_driver"))
    {
        return translated("scanner.attack.evidence.embedded_driver", "UTF-16 Base64 经两层 Base64 和十六进制解码后得到 PE 驱动。");
    }
    if (kId == QStringLiteral("driver.defender_registry"))
    {
        return translated("scanner.attack.evidence.defender_registry", "驱动同时修改 TamperProtection、实时防护和多个 Defender 服务键。");
    }
    if (kId == QStringLiteral("driver.security_process_kill"))
    {
        return translated("scanner.attack.evidence.process_kill", "驱动导入 ZwTerminateProcess 并包含多家安全产品进程目标。");
    }
    if (kId == QStringLiteral("driver.unload_360"))
    {
        return translated("scanner.attack.evidence.unload_360", "驱动调用 ZwUnloadDriver 并清理 360 注册表树。");
    }
    return fromBackendUtf8(code);
}

QWidget* ScannerDock::createAttackPathPage(
    const ks::scanner::BinaryScanResult& result) const
{
    auto* page = new QWidget(resultTabs_); // page: Container for the attack path conclusion and evidence table.
    auto* layout = new QVBoxLayout(page); // layout: Display the conclusion first, followed by individual evidence items.
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    auto* verdictLabel = new QLabel(page); // verdictLabel: Displays the final threshold verdict and rule version.
    verdictLabel->setWordWrap(true);
    verdictLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    verdictLabel->setText(
        result.attackPath.matched
            ? translated(
                "scanner.attack.verdict.detected",
                "检测到 EXIT / GhostSystemDriver 攻击路径：评分 %1/100，规则 %2。")
                .arg(result.attackPath.score)
                .arg(fromBackendUtf8(result.attackPath.ruleId))
            : translated(
                "scanner.attack.verdict.below_threshold",
                "发现相关静态证据，但未达到攻击路径阈值：评分 %1/100，规则 %2。")
                .arg(result.attackPath.score)
                .arg(fromBackendUtf8(result.attackPath.ruleId)));
    layout->addWidget(verdictLabel);

    auto* table = createReadOnlyTable(page); // table: Each row corresponds to a verifiable evidence item and its original offset.
    table->setColumnCount(7);
    table->setHorizontalHeaderLabels({
        translated("scanner.column.severity", "级别"),
        translated("scanner.attack.column.stage", "阶段"),
        translated("scanner.attack.column.evidence", "静态证据"),
        translated("scanner.attack.column.artifact", "对象"),
        QStringLiteral("MITRE ATT&CK"),
        translated("scanner.attack.column.score", "评分"),
        translated("scanner.column.offset", "偏移")
    });
    table->setRowCount(static_cast<int>(result.attackPath.evidence.size()));
    for (int row = 0; row < table->rowCount(); ++row)
    {
        const auto& evidence = result.attackPath.evidence[static_cast<std::size_t>(row)];
        table->setItem(row, 0, new QTableWidgetItem(
            attackPathSeverityText(static_cast<int>(evidence.severity))));
        table->setItem(row, 1, new QTableWidgetItem(attackPathStageText(evidence.stage)));
        table->setItem(row, 2, new QTableWidgetItem(attackPathEvidenceText(evidence.code)));
        table->setItem(row, 3, new QTableWidgetItem(fromBackendUtf8(evidence.artifact)));
        table->setItem(row, 4, new QTableWidgetItem(fromBackendUtf8(evidence.mitreTechnique)));
        table->setItem(row, 5, new QTableWidgetItem(QStringLiteral("+%1").arg(evidence.score)));
        table->setItem(
            row,
            6,
            new QTableWidgetItem(
                evidence.hasOffset
                    ? QStringLiteral("0x%1").arg(evidence.offset, 0, 16).toUpper()
                    : translated("scanner.attack.offset.decoded", "解码后对象")));
    }
    table->resizeColumnsToContents();
    layout->addWidget(table, 1);
    return page;
}

QWidget* ScannerDock::createStructuredTablePage(
    QTableWidget* table,
    const int columnCount) const
{
    // No grouping is needed for tables with five or fewer columns; returning the original table avoids adding meaningless control bars.
    if (table == nullptr || columnCount <= 5)
    {
        return table;
    }

    // page/pageLayout: Wide table page consists of tightly packed A/B/C controls and the original read-only table.
    auto* page = new QWidget(resultTabs_); // page: Outer page of this structure table.
    auto* pageLayout = new QVBoxLayout(page); // pageLayout: Arranges column group buttons and data tables vertically.
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(4);
    auto* buttonLayout = new QHBoxLayout(); // buttonLayout: Arrange A/B/C buttons with no spacing.
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(0);

    // groupCount: At most three groups; the first column serves as the identifier key and is retained in each group, while remaining columns are distributed evenly.
    const int kRemainingColumns = columnCount - 1; // remainingColumns: Number of fields excluding the identifier column.
    const int kGroupCount = std::clamp((kRemainingColumns + 3) / 4, 2, 3); // groupCount: actual number of column groups.
    const int kColumnsPerGroup = (kRemainingColumns + kGroupCount - 1) / kGroupCount; // columnsPerGroup: Maximum number of fields per group.
    auto groups = std::make_shared<std::vector<std::vector<int>>>(); // groups: Column indices displayed for each preset.
    auto buttons = std::make_shared<std::vector<QPointer<QPushButton>>>(); // buttons: Column group buttons that can be safely invalidated.

    // activeStyle/inactiveStyle: Currently use theme accent colors for presets; disable all coloring when customizing visibility.
    const QString kActiveStyle = QStringLiteral(
        "QPushButton { background:%1; color:%2; border:1px solid %1; padding:3px 10px; }")
        .arg(
            ksword_theme::accentHex(ksword_theme::AccentRole::kBlue),
            ksword_theme::onAccentDynamicHex()); // activeStyle: Activates the preset style.
    const QString kInactiveStyle = QStringLiteral(
        "QPushButton { background:%1; color:%2; border:1px solid %3; padding:3px 10px; }"
        "QPushButton:hover { background:%4; }")
        .arg(
            ksword_theme::surfaceHex(),
            ksword_theme::textPrimaryHex(),
            ksword_theme::borderHex(),
            ksword_theme::surfaceAltHex()); // inactiveStyle: Unselected or custom layout style.

    for (int groupIndex = 0; groupIndex < kGroupCount; ++groupIndex)
    {
        // columns: Each group retains column 0 and adds its complementary fields.
        std::vector<int> columns{ 0 }; // columns: Currently visible columns for the A/B/C preset.
        const int kFirstColumn = 1 + groupIndex * kColumnsPerGroup; // firstColumn: first column of the current group.
        const int kEndColumn = std::min(columnCount, kFirstColumn + kColumnsPerGroup); // endColumn: The column immediately after the current group's end.
        for (int column = kFirstColumn; column < kEndColumn; ++column)
        {
            columns.push_back(column);
        }
        groups->push_back(std::move(columns));

        // groupButton: A/B/C use tight layout with hover tooltips indicating current behavior.
        const char16_t kGroupLetter = static_cast<char16_t>(u'A' + groupIndex); // groupLetter: Letter identifier for the current group.
        auto* groupButton = new QPushButton(
            QString(QChar(kGroupLetter)),
            page); // groupButton: Switch to the current complementary field group.
        groupButton->setMinimumWidth(36);
        groupButton->setToolTip(
            translated(
                "scanner.column_view.tooltip",
                "列组 %1：显示一组互补字段；可在表头右键自定义列。")
                .arg(groupButton->text()));
        groupButton->setStyleSheet(groupIndex == 0 ? kActiveStyle : kInactiveStyle);
        buttons->push_back(groupButton);
        buttonLayout->addWidget(groupButton);
    }
    buttonLayout->addStretch(1);
    pageLayout->addLayout(buttonLayout);
    pageLayout->addWidget(table, 1);

    // applyGroup: Hides all columns first, then displays only the target group and updates the button theme when switching presets.
    const auto kApplyGroup =
        [table, groups, buttons, kActiveStyle, kInactiveStyle](const int groupIndex)
        {
            for (int column = 0; column < table->columnCount(); ++column)
            {
                table->setColumnHidden(column, true);
            }
            for (const int kColumn : groups->at(static_cast<std::size_t>(groupIndex)))
            {
                table->setColumnHidden(kColumn, false);
            }
            for (int buttonIndex = 0; buttonIndex < static_cast<int>(buttons->size()); ++buttonIndex)
            {
                if (buttons->at(static_cast<std::size_t>(buttonIndex)))
                {
                    buttons->at(static_cast<std::size_t>(buttonIndex))->setStyleSheet(
                        buttonIndex == groupIndex ? kActiveStyle : kInactiveStyle);
                }
            }
        };

    for (int groupIndex = 0; groupIndex < static_cast<int>(buttons->size()); ++groupIndex)
    {
        // groupButton: The current button is connected to its preset index; clicking it does not change the table data.
        QPushButton* groupButton = buttons->at(static_cast<std::size_t>(groupIndex)); // groupButton: Connect button.
        connect(
            groupButton,
            &QPushButton::clicked,
            page,
            [kApplyGroup, groupIndex]() { kApplyGroup(groupIndex); });
    }
    kApplyGroup(0);

    // Table header right-click menu allows per-column show/hide; each manual adjustment clears A/B/C activation colors to indicate a custom layout.
    QHeaderView* tableHeader = table->horizontalHeader(); // tableHeader: table header carrying the column menu.
    tableHeader->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(
        tableHeader,
        &QHeaderView::customContextMenuRequested,
        page,
        [this, table, tableHeader, buttons, kInactiveStyle](const QPoint& position)
        {
            QMenu menu(tableHeader); // menu: Column visibility toggle menu existing only during the current right-click operation.
            menu.setStyleSheet(QStringLiteral(
                "QMenu { background:%1; color:%2; border:1px solid %3; }"
                "QMenu::item { padding:5px 22px; }"
                "QMenu::item:selected { background:%4; color:%5; }"
                "QMenu::item:disabled { color:%6; }")
                .arg(
                    ksword_theme::surfaceHex(),
                    ksword_theme::textPrimaryHex(),
                    ksword_theme::borderHex(),
                    ksword_theme::accentHex(ksword_theme::AccentRole::kBlue),
                    ksword_theme::onAccentDynamicHex(),
                    ksword_theme::textDisabledColorHex()));

            // columnAction: Check state directly reflects current column visibility.
            for (int column = 0; column < table->columnCount(); ++column)
            {
                QAction* columnAction = menu.addAction( // columnAction: Menu item controlling the visibility of a single column.
                    table->horizontalHeaderItem(column) != nullptr
                        ? table->horizontalHeaderItem(column)->text()
                        : translated("scanner.column.unnamed", "未命名列"));
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(column));
                connect(
                    columnAction,
                    &QAction::toggled,
                    &menu,
                    [table, column, buttons, kInactiveStyle](const bool visible)
                    {
                        table->setColumnHidden(column, !visible);
                        for (const QPointer<QPushButton>& button : *buttons)
                        {
                            if (button)
                            {
                                button->setStyleSheet(kInactiveStyle);
                            }
                        }
                    });
            }
            menu.exec(tableHeader->mapToGlobal(position));
        });
    return page;
}
