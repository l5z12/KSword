#include "BootEditorTab.h"

#include "../../framework/PrivilegeElevationPrompt.h"
#include "../../ui/VisibleTableWidget.h"

#include "../../Theme.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QShowEvent>
#include <QSpinBox>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextCursor>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>

namespace
{
    // Column index constants:
    // - Unify the column order for entry tables.
    // - Avoids scattered magic numbers in the code.
    constexpr int kColumnIdentifier = 0;
    constexpr int kColumnDescription = 1;
    constexpr int kColumnType = 2;
    constexpr int kColumnDevice = 3;
    constexpr int kColumnPath = 4;
    constexpr int kColumnFlags = 5;

    // kDefaultCommandTimeoutMs：
    // - bcdedit execution timeout (milliseconds);
    // - Avoid UI blocking for an extended period caused by command hangs.
    constexpr int kDefaultCommandTimeoutMs = 30000;

    // buildBlueToolButtonStyle：
    // - Unify the style for toolbar icon buttons.
    // - Consistent with the project's blue theme.
    QString buildBlueToolButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // buildBlueInputStyle：
    // - Unify the border and focus feedback for input controls (edit boxes, combo boxes, numeric boxes).
    // - Improve visual consistency across the entire page.
    QString buildBlueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QSpinBox{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QSpinBox:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            + ksword_theme::themedComboBoxStyle();
    }

    // isCurrentProcessElevated：
    // - Check if the current process has administrator privileges.
    // - Used for the top hint: 'Is it possible to execute successfully?'
    bool isCurrentProcessElevated()
    {
        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        TOKEN_ELEVATION tokenElevation{};
        DWORD returnLength = 0;
        const BOOL kQueryOk = ::GetTokenInformation(
            tokenHandle,
            TokenElevation,
            &tokenElevation,
            sizeof(tokenElevation),
            &returnLength);
        ::CloseHandle(tokenHandle);
        return kQueryOk != FALSE && tokenElevation.TokenIsElevated != 0;
    }

    // buildSafeBootModeText：
    // - Convert safeboot text to displayable Chinese.
    // - Improve list reading efficiency.
    QString buildSafeBootModeText(const QString& safeBootValueText)
    {
        const QString kNormalizedText = safeBootValueText.trimmed().toLower();
        if (kNormalizedText == QStringLiteral("minimal"))
        {
            return QStringLiteral("安全模式-最小");
        }
        if (kNormalizedText == QStringLiteral("network"))
        {
            return QStringLiteral("安全模式-网络");
        }
        if (kNormalizedText.isEmpty())
        {
            return QStringLiteral("正常启动");
        }
        return QStringLiteral("安全模式-%1").arg(safeBootValueText);
    }
}

BootEditorTab::BootEditorTab(QWidget* parent)
    : QWidget(parent)
{
    // Build the UI during initialization:
    // - Move the initial BCD enumeration to showEvent to avoid triggering bcdedit as soon as the 'Misc' page is created.
    // - The status bar retains the 'not yet loaded' text written by initializeUi, ensuring semantic consistency with the actual state.
    initializeUi();
    initializeConnections();
}

// showEvent：
// - Purpose: Queue a single BCD enumeration when the page becomes truly visible for the first time; subsequent show/hide events will not trigger it again.
// - Parameter event: Qt show event, passed through to the base class.
// - Returns: Nothing.
void BootEditorTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (firstShowHandled_)
    {
        return;
    }

    firstShowHandled_ = true;

    // Defer to the next event loop iteration: ensure the page completes its first frame rendering before queuing the background enumeration.
    QTimer::singleShot(0, this, [this]()
        {
            refreshBcdEntries();
        });
}

void BootEditorTab::initializeUi()
{
    // Root layout:
    // - Top toolbar.
    // - Middle-top entry list and bottom three-column editor area;
    // - Bottom status summary.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    initializeToolbar();
    initializeCenterPane();

    statusLabel_ = new QLabel(QStringLiteral("状态：尚未加载 BCD 数据"), this);
    statusLabel_->setWordWrap(true);
    rootLayout_->addWidget(statusLabel_);
}

void BootEditorTab::initializeToolbar()
{
    // The top toolbar primarily hosts 'high-frequency global operations'.
    toolbarWidget_ = new QWidget(this);
    toolbarLayout_ = new QHBoxLayout(toolbarWidget_);
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);
    rootLayout_->addWidget(toolbarWidget_);

    // btnFactory：
    // - Unified construction of icon buttons with icons, tooltips, and a blue theme.
    // - Avoid duplicating button initialization logic.
    const auto kBtnFactory = [this](const QString& iconPath, const QString& tooltipText) -> QToolButton*
        {
            QToolButton* button = new QToolButton(toolbarWidget_);
            button->setIcon(QIcon(iconPath));
            button->setToolTip(tooltipText);
            button->setStyleSheet(buildBlueToolButtonStyle());
            button->setAutoRaise(false);
            button->setIconSize(QSize(16, 16));
            return button;
        };

    refreshButton_ = kBtnFactory(QStringLiteral(":/Icon/process_refresh.svg"), QStringLiteral("刷新 BCD 枚举"));
    exportButton_ = kBtnFactory(QStringLiteral(":/Icon/log_export.svg"), QStringLiteral("导出当前 BCD 存储"));
    importButton_ = kBtnFactory(QStringLiteral(":/Icon/codeeditor_open.svg"), QStringLiteral("导入 BCD 存储"));
    copyEntryButton_ = kBtnFactory(QStringLiteral(":/Icon/process_copy_row.svg"), QStringLiteral("复制当前引导项"));
    deleteEntryButton_ = kBtnFactory(QStringLiteral(":/Icon/process_terminate.svg"), QStringLiteral("删除当前引导项"));
    setDefaultButton_ = kBtnFactory(QStringLiteral(":/Icon/process_priority.svg"), QStringLiteral("设为默认启动项"));
    bootOnceButton_ = kBtnFactory(QStringLiteral(":/Icon/process_start.svg"), QStringLiteral("下一次启动使用该项"));
    copyRowButton_ = kBtnFactory(QStringLiteral(":/Icon/log_copy.svg"), QStringLiteral("复制当前行概要"));

    toolbarLayout_->addWidget(refreshButton_);
    toolbarLayout_->addWidget(exportButton_);
    toolbarLayout_->addWidget(importButton_);
    toolbarLayout_->addWidget(copyEntryButton_);
    toolbarLayout_->addWidget(deleteEntryButton_);
    toolbarLayout_->addWidget(setDefaultButton_);
    toolbarLayout_->addWidget(bootOnceButton_);
    toolbarLayout_->addWidget(copyRowButton_);

    filterEdit_ = new QLineEdit(toolbarWidget_);
    filterEdit_->setPlaceholderText(QStringLiteral("筛选：标识符/描述/路径/类型"));
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setToolTip(QStringLiteral("输入关键字实时过滤引导条目"));
    filterEdit_->setStyleSheet(buildBlueInputStyle());
    toolbarLayout_->addWidget(filterEdit_, 1);

    // m_adminHintLabel：
    // - Clearly indicates whether bcdedit has the prerequisites to execute.
    // - Reduces confusion from 'click then command failure'.
    adminHintLabel_ = new QLabel(toolbarWidget_);
    const bool kElevated = isCurrentProcessElevated();
    adminHintLabel_->setText(
        kElevated
        ? QStringLiteral("权限：管理员（可编辑）")
        : QStringLiteral("权限：非管理员（多数写操作会失败）"));
    // In admin mode, use palette(highlight) for dynamic color retrieval, automatically following theme changes.
    // Keep the semantic warning orange when not in admin mode; it must remain the same orange in both light and dark themes.
    adminHintLabel_->setStyleSheet(
        kElevated
        ? QStringLiteral("color:%1;font-weight:600;")
            .arg(ksword_theme::kPrimaryBlueHex)
        : QStringLiteral("color:%1;font-weight:600;")
            .arg(ksword_theme::warningColor().name(QColor::HexRgb)));
    toolbarLayout_->addWidget(adminHintLabel_);
}

void BootEditorTab::initializeCenterPane()
{
    // Main layout changed to vertical:
    // - The upper area contains only the entry table to avoid being squeezed by the edit area.
    // - Place the editor area in the lower section, subdivided into three columns: basic fields, advanced switches, and raw output.
    mainSplitter_ = new QSplitter(Qt::Vertical, this);
    mainSplitter_->setChildrenCollapsible(false);
    rootLayout_->addWidget(mainSplitter_, 1);

    // Upper table: displays the current BCD entry list.
    entryTable_ = new ks::ui::VisibleTableWidget(mainSplitter_);
    entryTable_->setColumnCount(6);
    entryTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("标识符"),
        QStringLiteral("描述"),
        QStringLiteral("类型"),
        QStringLiteral("设备"),
        QStringLiteral("路径"),
        QStringLiteral("状态")
        });
    entryTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    entryTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    entryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    entryTable_->setAlternatingRowColors(true);
    entryTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    entryTable_->verticalHeader()->setVisible(false);
    entryTable_->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);

    // Header width strategy:
    // - Description: the path column is stretchable;
    // - Other columns adapt to content.
    QHeaderView* entryHeader = entryTable_->horizontalHeader();
    entryHeader->setStretchLastSection(false);
    entryHeader->setSectionResizeMode(kColumnIdentifier, QHeaderView::ResizeToContents);
    entryHeader->setSectionResizeMode(kColumnDescription, QHeaderView::Stretch);
    entryHeader->setSectionResizeMode(kColumnType, QHeaderView::ResizeToContents);
    entryHeader->setSectionResizeMode(kColumnDevice, QHeaderView::ResizeToContents);
    entryHeader->setSectionResizeMode(kColumnPath, QHeaderView::Stretch);
    entryHeader->setSectionResizeMode(kColumnFlags, QHeaderView::ResizeToContents);

    // Editor pane below:
    // - The first column holds basic fields, traditional boot shortcuts, and application buttons.
    // - The second column hosts advanced switches and custom commands.
    // - The third pane independently holds raw output to prevent the log area from crowding configuration controls.
    editorPane_ = new QWidget(mainSplitter_);
    editorPaneLayout_ = new QVBoxLayout(editorPane_);
    editorPaneLayout_->setContentsMargins(0, 0, 0, 0);
    editorPaneLayout_->setSpacing(6);

    QSplitter* editorColumnsSplitter = new QSplitter(Qt::Horizontal, editorPane_);
    editorColumnsSplitter->setChildrenCollapsible(false);
    editorPaneLayout_->addWidget(editorColumnsSplitter, 1);

    QWidget* leftEditorColumn = new QWidget(editorColumnsSplitter);
    QVBoxLayout* leftEditorLayout = new QVBoxLayout(leftEditorColumn);
    leftEditorLayout->setContentsMargins(0, 0, 0, 0);
    leftEditorLayout->setSpacing(6);

    QWidget* middleEditorColumn = new QWidget(editorColumnsSplitter);
    QVBoxLayout* middleEditorLayout = new QVBoxLayout(middleEditorColumn);
    middleEditorLayout->setContentsMargins(0, 0, 0, 0);
    middleEditorLayout->setSpacing(6);

    QWidget* outputEditorColumn = new QWidget(editorColumnsSplitter);
    QVBoxLayout* outputEditorLayout = new QVBoxLayout(outputEditorColumn);
    outputEditorLayout->setContentsMargins(0, 0, 0, 0);
    outputEditorLayout->setSpacing(6);

    // Basic field edit group.
    QGroupBox* basicGroup = new QGroupBox(QStringLiteral("基础字段"), leftEditorColumn);
    QFormLayout* basicLayout = new QFormLayout(basicGroup);
    basicLayout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

    identifierValueLabel_ = new QLabel(QStringLiteral("-"), basicGroup);
    identifierValueLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    typeValueLabel_ = new QLabel(QStringLiteral("-"), basicGroup);
    typeValueLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    descriptionEdit_ = new QLineEdit(basicGroup);
    deviceEdit_ = new QLineEdit(basicGroup);
    osDeviceEdit_ = new QLineEdit(basicGroup);
    pathEdit_ = new QLineEdit(basicGroup);
    systemRootEdit_ = new QLineEdit(basicGroup);
    localeEdit_ = new QLineEdit(basicGroup);
    bootMenuPolicyCombo_ = new QComboBox(basicGroup);
    bootMenuPolicyCombo_->addItem(QStringLiteral("不修改"), QString());
    bootMenuPolicyCombo_->addItem(QStringLiteral("Standard"), QStringLiteral("Standard"));
    bootMenuPolicyCombo_->addItem(QStringLiteral("Legacy"), QStringLiteral("Legacy"));
    timeoutSpin_ = new QSpinBox(basicGroup);
    timeoutSpin_->setRange(0, 999);
    timeoutSpin_->setSuffix(QStringLiteral(" 秒"));

    descriptionEdit_->setStyleSheet(buildBlueInputStyle());
    deviceEdit_->setStyleSheet(buildBlueInputStyle());
    osDeviceEdit_->setStyleSheet(buildBlueInputStyle());
    pathEdit_->setStyleSheet(buildBlueInputStyle());
    systemRootEdit_->setStyleSheet(buildBlueInputStyle());
    localeEdit_->setStyleSheet(buildBlueInputStyle());
    bootMenuPolicyCombo_->setStyleSheet(buildBlueInputStyle());
    timeoutSpin_->setStyleSheet(buildBlueInputStyle());

    basicLayout->addRow(QStringLiteral("标识符"), identifierValueLabel_);
    basicLayout->addRow(QStringLiteral("对象类型"), typeValueLabel_);
    basicLayout->addRow(QStringLiteral("描述 description"), descriptionEdit_);
    basicLayout->addRow(QStringLiteral("设备 device"), deviceEdit_);
    basicLayout->addRow(QStringLiteral("OS 设备 osdevice"), osDeviceEdit_);
    basicLayout->addRow(QStringLiteral("加载路径 path"), pathEdit_);
    basicLayout->addRow(QStringLiteral("系统根 systemroot"), systemRootEdit_);
    basicLayout->addRow(QStringLiteral("区域 locale"), localeEdit_);
    basicLayout->addRow(QStringLiteral("启动菜单策略"), bootMenuPolicyCombo_);
    basicLayout->addRow(QStringLiteral("菜单等待超时"), timeoutSpin_);

    leftEditorLayout->addWidget(basicGroup);

    // Legacy boot shortcut group:
    // - Legacy boot = bootmenupolicy Legacy (F8 menu available);
    // - This is not equivalent to switching between BIOS/UEFI firmware modes (the latter requires operation in the motherboard firmware settings).
    QGroupBox* legacyGroup = new QGroupBox(QStringLiteral("传统引导（Legacy/F8）"), leftEditorColumn);
    QVBoxLayout* legacyLayout = new QVBoxLayout(legacyGroup);
    legacyLayout->setContentsMargins(8, 8, 8, 8);
    legacyLayout->setSpacing(6);

    legacyModeHintLabel_ = new QLabel(
        QStringLiteral("说明：这里的“传统引导”是 Windows 启动菜单策略（bootmenupolicy=Legacy），"
            "不是 BIOS/UEFI 模式切换。"),
        legacyGroup);
    legacyModeHintLabel_->setWordWrap(true);
    legacyLayout->addWidget(legacyModeHintLabel_);

    QWidget* legacyActionWidget = new QWidget(legacyGroup);
    QHBoxLayout* legacyActionLayout = new QHBoxLayout(legacyActionWidget);
    legacyActionLayout->setContentsMargins(0, 0, 0, 0);
    legacyActionLayout->setSpacing(6);

    setLegacyForSelectedButton_ = new QPushButton(QStringLiteral("当前项启用 Legacy"), legacyActionWidget);
    setLegacyForSelectedButton_->setToolTip(
        QStringLiteral("对当前选中引导项执行：bcdedit /set <id> bootmenupolicy Legacy"));
    setLegacyForSelectedButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));
    legacyActionLayout->addWidget(setLegacyForSelectedButton_);

    setLegacyForDefaultButton_ = new QPushButton(QStringLiteral("默认项启用 Legacy"), legacyActionWidget);
    setLegacyForDefaultButton_->setToolTip(
        QStringLiteral("对当前默认引导项执行：bcdedit /set <default> bootmenupolicy Legacy"));
    setLegacyForDefaultButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_priority.svg")));
    legacyActionLayout->addWidget(setLegacyForDefaultButton_);

    setStandardForSelectedButton_ = new QPushButton(QStringLiteral("当前项恢复 Standard"), legacyActionWidget);
    setStandardForSelectedButton_->setToolTip(
        QStringLiteral("对当前选中引导项执行：bcdedit /set <id> bootmenupolicy Standard"));
    setStandardForSelectedButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    legacyActionLayout->addWidget(setStandardForSelectedButton_);
    legacyActionLayout->addStretch(1);

    legacyLayout->addWidget(legacyActionWidget);
    leftEditorLayout->addWidget(legacyGroup);

    // Advanced switch group.
    QGroupBox* flagGroup = new QGroupBox(QStringLiteral("高级开关"), middleEditorColumn);
    QVBoxLayout* flagLayout = new QVBoxLayout(flagGroup);
    // Retain extra top spacing between the title and content to prevent the global QGroupBox title from overlapping the first checkbox.
    flagLayout->setContentsMargins(8, 14, 8, 8);
    flagLayout->setSpacing(4);

    testSigningCheck_ = new QCheckBox(QStringLiteral("开启测试签名 (testsigning)"), flagGroup);
    noIntegrityCheck_ = new QCheckBox(QStringLiteral("关闭完整性检查 (nointegritychecks)"), flagGroup);
    debugCheck_ = new QCheckBox(QStringLiteral("开启内核调试 (debug)"), flagGroup);
    bootLogCheck_ = new QCheckBox(QStringLiteral("开启启动日志 (bootlog)"), flagGroup);
    baseVideoCheck_ = new QCheckBox(QStringLiteral("使用基础视频驱动 (basevideo)"), flagGroup);
    recoveryEnabledCheck_ = new QCheckBox(QStringLiteral("启用恢复环境 (recoveryenabled)"), flagGroup);
    safeBootCombo_ = new QComboBox(flagGroup);
    safeBootCombo_->setToolTip(QStringLiteral("设置 safeboot 模式。关闭会删除 safeboot 字段。"));
    safeBootCombo_->addItem(QStringLiteral("关闭安全模式"), QStringLiteral("off"));
    safeBootCombo_->addItem(QStringLiteral("最小安全模式"), QStringLiteral("minimal"));
    safeBootCombo_->addItem(QStringLiteral("网络安全模式"), QStringLiteral("network"));
    safeBootCombo_->addItem(QStringLiteral("命令行安全模式"), QStringLiteral("alternateshell"));
    safeBootCombo_->setStyleSheet(buildBlueInputStyle());

    flagLayout->addWidget(testSigningCheck_);
    flagLayout->addWidget(noIntegrityCheck_);
    flagLayout->addWidget(debugCheck_);
    flagLayout->addWidget(bootLogCheck_);
    flagLayout->addWidget(baseVideoCheck_);
    flagLayout->addWidget(recoveryEnabledCheck_);
    flagLayout->addWidget(new QLabel(QStringLiteral("safeboot 模式"), flagGroup));
    flagLayout->addWidget(safeBootCombo_);
    middleEditorLayout->addWidget(flagGroup);

    // Action area: separate 'current entry modification' from 'bootmgr global parameters'.
    QWidget* actionWidget = new QWidget(leftEditorColumn);
    QHBoxLayout* actionLayout = new QHBoxLayout(actionWidget);
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(6);

    applyEntryButton_ = new QPushButton(QStringLiteral("应用当前条目"), actionWidget);
    applyEntryButton_->setToolTip(QStringLiteral("按基础字段与高级开关写回当前选中的 BCD 条目"));
    applyEntryButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));
    applyBootMgrButton_ = new QPushButton(QStringLiteral("应用 bootmgr 超时"), actionWidget);
    applyBootMgrButton_->setToolTip(QStringLiteral("仅写入 bcdedit /timeout 参数"));
    applyBootMgrButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_priority.svg")));
    reloadOneButton_ = new QPushButton(QStringLiteral("重读当前条目"), actionWidget);
    reloadOneButton_->setToolTip(QStringLiteral("按当前选中行重新加载编辑字段（不写入）"));
    reloadOneButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));

    actionLayout->addWidget(applyEntryButton_);
    actionLayout->addWidget(applyBootMgrButton_);
    actionLayout->addWidget(reloadOneButton_);
    actionLayout->addStretch(1);
    leftEditorLayout->addWidget(actionWidget);
    leftEditorLayout->addStretch(1);

    // Custom command group: supports entering arbitrary bcdedit parameters.
    QGroupBox* customGroup = new QGroupBox(QStringLiteral("自定义命令"), middleEditorColumn);
    QHBoxLayout* customLayout = new QHBoxLayout(customGroup);
    customLayout->setContentsMargins(8, 8, 8, 8);
    customLayout->setSpacing(6);

    customCommandEdit_ = new QLineEdit(customGroup);
    customCommandEdit_->setPlaceholderText(QStringLiteral("示例：/set {current} bootmenupolicy Legacy"));
    customCommandEdit_->setToolTip(QStringLiteral("只填写 bcdedit 后面的参数；也支持完整输入 bcdedit ..."));
    customCommandEdit_->setStyleSheet(buildBlueInputStyle());
    runCustomCommandButton_ = new QPushButton(QStringLiteral("执行"), customGroup);
    runCustomCommandButton_->setToolTip(QStringLiteral("执行自定义 bcdedit 命令并输出原始结果"));
    runCustomCommandButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));

    customLayout->addWidget(customCommandEdit_, 1);
    customLayout->addWidget(runCustomCommandButton_, 0);
    middleEditorLayout->addWidget(customGroup);
    middleEditorLayout->addStretch(1);

    // Raw output group:
    // - Placed independently in the third column to form a stable log observation area.
    // - Separated from the second column's advanced switches/custom commands to avoid mutual compression during horizontal expansion.
    QGroupBox* outputGroup = new QGroupBox(QStringLiteral("原始输出"), outputEditorColumn);
    QVBoxLayout* outputLayout = new QVBoxLayout(outputGroup);
    outputLayout->setContentsMargins(8, 8, 8, 8);
    outputLayout->setSpacing(4);

    rawOutputEdit_ = new QPlainTextEdit(outputGroup);
    rawOutputEdit_->setReadOnly(true);
    rawOutputEdit_->setPlaceholderText(QStringLiteral("这里显示 bcdedit 原始输出与命令执行日志。"));
    rawOutputEdit_->setMinimumHeight(180);
    outputLayout->addWidget(rawOutputEdit_);
    outputEditorLayout->addWidget(outputGroup, 1);

    // Split Ratio:
    // - Top table prioritizes readability;
    // - The lower edit area retains sufficient space for batch operations.
    mainSplitter_->setStretchFactor(0, 6);
    mainSplitter_->setStretchFactor(1, 5);
    mainSplitter_->setSizes(QList<int>{ 380, 320 });

    editorColumnsSplitter->setStretchFactor(0, 4);
    editorColumnsSplitter->setStretchFactor(1, 3);
    editorColumnsSplitter->setStretchFactor(2, 5);
    editorColumnsSplitter->setSizes(QList<int>{ 360, 320, 420 });
}

void BootEditorTab::initializeConnections()
{
    connect(refreshButton_, &QToolButton::clicked, this, [this]()
        {
            refreshBcdEntries();
        });
    connect(exportButton_, &QToolButton::clicked, this, [this]()
        {
            exportBcdStore();
        });
    connect(importButton_, &QToolButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("导入 BCD 存储"));
                return;
            }
            importBcdStore();
        });
    connect(copyEntryButton_, &QToolButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("复制 BCD 启动项"));
                return;
            }
            createCopyFromSelectedEntry();
        });
    connect(deleteEntryButton_, &QToolButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("删除 BCD 启动项"));
                return;
            }
            deleteSelectedEntry();
        });
    connect(setDefaultButton_, &QToolButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("设置默认 BCD 启动项"));
                return;
            }
            setSelectedAsDefaultEntry();
        });
    connect(bootOnceButton_, &QToolButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("设置一次性 BCD 启动项"));
                return;
            }
            addSelectedToBootSequence();
        });
    connect(copyRowButton_, &QToolButton::clicked, this, [this]()
        {
            copySelectedRowToClipboard();
        });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this](const QString&)
        {
            rebuildEntryTable();
        });
    connect(applyEntryButton_, &QPushButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("应用 BCD 启动项修改"));
                return;
            }
            applySelectedEntryChanges();
        });
    connect(applyBootMgrButton_, &QPushButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("应用 BCD 启动管理器修改"));
                return;
            }
            applyBootManagerChanges();
        });
    connect(setLegacyForSelectedButton_, &QPushButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("设置 Legacy 启动菜单策略"));
                return;
            }
            setLegacyBootForSelectedEntry();
        });
    connect(setLegacyForDefaultButton_, &QPushButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("设置默认项 Legacy 启动菜单策略"));
                return;
            }
            setLegacyBootForDefaultEntry();
        });
    connect(setStandardForSelectedButton_, &QPushButton::clicked, this, [this]()
        {
            if (!ks::ui::isCurrentProcessElevated())
            {
                (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("设置 Standard 启动菜单策略"));
                return;
            }
            setStandardBootForSelectedEntry();
        });
    connect(reloadOneButton_, &QPushButton::clicked, this, [this]()
        {
            syncEditorFromSelection();
        });
    connect(runCustomCommandButton_, &QPushButton::clicked, this, [this]()
        {
            executeCustomCommand();
        });
    connect(entryTable_, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            syncEditorFromSelection();
        });
    connect(entryTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPos)
        {
            QMenu menu(entryTable_);
            // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
            menu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制当前行"));
            QAction* selectedAction = menu.exec(entryTable_->viewport()->mapToGlobal(localPos));
            if (selectedAction == copyRowAction)
            {
                copySelectedRowToClipboard();
            }
        });
}

void BootEditorTab::refreshBcdEntries()
{
    const BcdCommandResult kEnumResult = runBcdEdit(
        QStringList{ QStringLiteral("/enum"), QStringLiteral("all"), QStringLiteral("/v") },
        kDefaultCommandTimeoutMs,
        QStringLiteral("枚举全部 BCD 条目"));
    appendCommandLog(QStringLiteral("bcdedit /enum all /v"), kEnumResult);

    if (!kEnumResult.startSucceeded || kEnumResult.timeout || kEnumResult.exitCode != 0)
    {
        // Clear cache when refresh fails:
        // - Prevent stale default item cache from causing subsequent "default item operations" to write to expired targets.
        // - Also clears the raw enumeration text to prevent the UI from displaying stale data.
        entryList_.clear();
        defaultIdentifierText_.clear();
        lastEnumRawText_.clear();
        rebuildEntryTable();
        clearEditorForNoSelection();

        const QString kTrimmedErrorText = kEnumResult.mergedOutputText.trimmed();
        if (kTrimmedErrorText.contains(QStringLiteral("Access is denied"), Qt::CaseInsensitive)
            || kTrimmedErrorText.contains(QStringLiteral("拒绝访问"), Qt::CaseInsensitive))
        {
            statusLabel_->setText(QStringLiteral("状态：读取 BCD 失败（访问被拒绝，请以管理员运行）。"));
        }
        else
        {
            statusLabel_->setText(QStringLiteral("状态：读取 BCD 失败，请查看原始输出。"));
        }
        return;
    }

    lastEnumRawText_ = kEnumResult.mergedOutputText;
    entryList_ = parseBcdEnumOutput(kEnumResult.mergedOutputText);

    // Read default boot entry: prioritize the 'default' field in {bootmgr}.
    defaultIdentifierText_.clear();
    for (const BcdEntry& entry : entryList_)
    {
        if (!entry.isBootManager)
        {
            continue;
        }
        defaultIdentifierText_ = readElementValue(entry, QStringList{
            QStringLiteral("default"),
            QStringLiteral("默认")
            });
        break;
    }

    const QString kDefaultIdLowerText = defaultIdentifierText_.trimmed().toLower();
    for (BcdEntry& entry : entryList_)
    {
        if (!kDefaultIdLowerText.isEmpty()
            && entry.identifierText.trimmed().compare(kDefaultIdLowerText, Qt::CaseInsensitive) == 0)
        {
            entry.isDefault = true;
        }
    }

    rebuildEntryTable();

    if (entryTable_->rowCount() > 0)
    {
        entryTable_->selectRow(0);
    }
    else
    {
        clearEditorForNoSelection();
    }
    updateStatusSummary();
}

void BootEditorTab::rebuildEntryTable()
{
    entryTable_->setRowCount(0);

    int visibleCount = 0;
    for (int index = 0; index < static_cast<int>(entryList_.size()); ++index)
    {
        const BcdEntry& entry = entryList_[static_cast<std::size_t>(index)];
        if (!entryMatchesFilter(entry))
        {
            continue;
        }

        const int kRowIndex = visibleCount++;
        entryTable_->insertRow(kRowIndex);

        const QString kDescriptionText = readElementValue(entry, QStringList{
            QStringLiteral("description"),
            QStringLiteral("描述")
            });
        const QString kDeviceText = readElementValue(entry, QStringList{
            QStringLiteral("device"),
            QStringLiteral("设备")
            });
        const QString kPathText = readElementValue(entry, QStringList{
            QStringLiteral("path"),
            QStringLiteral("路径")
            });
        const QString kSafeBootText = readElementValue(entry, QStringList{
            QStringLiteral("safeboot")
            });

        QStringList flagTextList;
        if (entry.isBootManager) { flagTextList.push_back(QStringLiteral("BOOTMGR")); }
        if (entry.isCurrent) { flagTextList.push_back(QStringLiteral("当前")); }
        if (entry.isDefault) { flagTextList.push_back(QStringLiteral("默认")); }
        if (!kSafeBootText.trimmed().isEmpty())
        {
            flagTextList.push_back(buildSafeBootModeText(kSafeBootText));
        }

        auto makeItem = [index](const QString& text) -> QTableWidgetItem*
            {
                QTableWidgetItem* item = new QTableWidgetItem(text);
                item->setData(Qt::UserRole, index);
                return item;
            };

        entryTable_->setItem(kRowIndex, kColumnIdentifier, makeItem(entry.identifierText));
        entryTable_->setItem(kRowIndex, kColumnDescription, makeItem(kDescriptionText));
        entryTable_->setItem(kRowIndex, kColumnType, makeItem(entry.objectTypeText));
        entryTable_->setItem(kRowIndex, kColumnDevice, makeItem(kDeviceText));
        entryTable_->setItem(kRowIndex, kColumnPath, makeItem(kPathText));
        entryTable_->setItem(kRowIndex, kColumnFlags, makeItem(flagTextList.join(QStringLiteral(" | "))));
    }

    updateStatusSummary();
}

void BootEditorTab::syncEditorFromSelection()
{
    const BcdEntry* selectedEntry = currentEntry();
    if (selectedEntry == nullptr)
    {
        clearEditorForNoSelection();
        return;
    }

    identifierValueLabel_->setText(selectedEntry->identifierText);
    typeValueLabel_->setText(selectedEntry->objectTypeText);
    descriptionEdit_->setText(readElementValue(*selectedEntry, QStringList{
        QStringLiteral("description"),
        QStringLiteral("描述")
        }));
    deviceEdit_->setText(readElementValue(*selectedEntry, QStringList{
        QStringLiteral("device"),
        QStringLiteral("设备")
        }));
    osDeviceEdit_->setText(readElementValue(*selectedEntry, QStringList{
        QStringLiteral("osdevice")
        }));
    pathEdit_->setText(readElementValue(*selectedEntry, QStringList{
        QStringLiteral("path"),
        QStringLiteral("路径")
        }));
    systemRootEdit_->setText(readElementValue(*selectedEntry, QStringList{
        QStringLiteral("systemroot")
        }));
    localeEdit_->setText(readElementValue(*selectedEntry, QStringList{
        QStringLiteral("locale")
        }));

    // bootmenupolicy: defaults to 'no modification' when no value is present.
    const QString kBootMenuPolicyText = readElementValue(*selectedEntry, QStringList{
        QStringLiteral("bootmenupolicy")
        }).trimmed();
    int policyIndex = bootMenuPolicyCombo_->findData(kBootMenuPolicyText);
    if (policyIndex < 0)
    {
        policyIndex = 0;
    }
    bootMenuPolicyCombo_->setCurrentIndex(policyIndex);

    // timeout: Read from bootmgr first; if the current entry lacks a value, retain the original.
    int timeoutValue = timeoutSpin_->value();
    for (const BcdEntry& entry : entryList_)
    {
        if (!entry.isBootManager)
        {
            continue;
        }
        const QString kTimeoutText = readElementValue(entry, QStringList{
            QStringLiteral("timeout"),
            QStringLiteral("超时")
            }).trimmed();
        bool convertOk = false;
        const int kConvertedValue = kTimeoutText.toInt(&convertOk);
        if (convertOk)
        {
            timeoutValue = kConvertedValue;
        }
        break;
    }
    timeoutSpin_->setValue(timeoutValue);

    // Boolean field: read uniformly compatible with yes/no, on/off.
    testSigningCheck_->setChecked(readElementBool(
        *selectedEntry,
        QStringList{ QStringLiteral("testsigning") },
        false));
    noIntegrityCheck_->setChecked(readElementBool(
        *selectedEntry,
        QStringList{ QStringLiteral("nointegritychecks") },
        false));
    debugCheck_->setChecked(readElementBool(
        *selectedEntry,
        QStringList{ QStringLiteral("debug") },
        false));
    bootLogCheck_->setChecked(readElementBool(
        *selectedEntry,
        QStringList{ QStringLiteral("bootlog") },
        false));
    baseVideoCheck_->setChecked(readElementBool(
        *selectedEntry,
        QStringList{ QStringLiteral("basevideo") },
        false));
    recoveryEnabledCheck_->setChecked(readElementBool(
        *selectedEntry,
        QStringList{ QStringLiteral("recoveryenabled") },
        true));

    // safeboot mode:
    // - alternateshell uses the combination of safeboot + safebootalternateshell for determination.
    const QString kSafeBootText = readElementValue(*selectedEntry, QStringList{
        QStringLiteral("safeboot")
        }).trimmed().toLower();
    const bool kAlternateShellEnabled = readElementBool(
        *selectedEntry,
        QStringList{ QStringLiteral("safebootalternateshell") },
        false);
    int safeBootIndex = 0;
    if (kSafeBootText == QStringLiteral("minimal") && kAlternateShellEnabled)
    {
        safeBootIndex = 3;
    }
    else if (kSafeBootText == QStringLiteral("minimal"))
    {
        safeBootIndex = 1;
    }
    else if (kSafeBootText == QStringLiteral("network"))
    {
        safeBootIndex = 2;
    }
    safeBootCombo_->setCurrentIndex(safeBootIndex);

    rawOutputEdit_->setPlainText(selectedEntry->rawBlockText);
}

void BootEditorTab::clearEditorForNoSelection()
{
    identifierValueLabel_->setText(QStringLiteral("-"));
    typeValueLabel_->setText(QStringLiteral("-"));
    descriptionEdit_->clear();
    deviceEdit_->clear();
    osDeviceEdit_->clear();
    pathEdit_->clear();
    systemRootEdit_->clear();
    localeEdit_->clear();
    bootMenuPolicyCombo_->setCurrentIndex(0);
    safeBootCombo_->setCurrentIndex(0);
    testSigningCheck_->setChecked(false);
    noIntegrityCheck_->setChecked(false);
    debugCheck_->setChecked(false);
    bootLogCheck_->setChecked(false);
    baseVideoCheck_->setChecked(false);
    recoveryEnabledCheck_->setChecked(true);
    rawOutputEdit_->clear();
}

void BootEditorTab::updateStatusSummary()
{
    const int kTotalCount = static_cast<int>(entryList_.size());
    const int kVisibleCount = entryTable_->rowCount();
    QString statusText = QStringLiteral("状态：总条目 %1，筛选后 %2")
        .arg(kTotalCount)
        .arg(kVisibleCount);

    if (!defaultIdentifierText_.trimmed().isEmpty())
    {
        statusText += QStringLiteral("，默认项 %1").arg(defaultIdentifierText_.trimmed());
    }
    statusLabel_->setText(statusText);
}
