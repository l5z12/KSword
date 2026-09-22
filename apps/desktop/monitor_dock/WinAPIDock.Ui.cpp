#include "WinAPIDock.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/ThemeStatusRole.h"
#include "../Theme.h"

// ============================================================
// WinAPIDock.Ui.cpp
// Purpose:
// 1) Centrally construct the control hierarchy and layout for the WinAPI Dock.
// 2) Keep headers concise to prevent UI code from bloating.
// 3) Uniformly set icons, tooltips, and blue theme styles for buttons.
// ============================================================

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QCompleter>
#include <QFormLayout>
#include <QFrame>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSize>
#include <QSplitter>
#include <QStyle>
#include <QTableWidget>
#include <QTimer>
#include <QToolButton>
#include <QStringList>
#include <QVBoxLayout>

namespace
{
    // configureIconButton：
    // - Purpose: Uniformly set the icon, tooltip, and size for 'icon-only' buttons;
    // - Call: All simple semantic buttons (refresh, browse, start, stop, export) route through here.
    // - Returns: No return value; skips directly if the control is null.
    void configureIconButton(
        QPushButton* buttonPointer,
        const QIcon& iconValue,
        const QString& toolTipText)
    {
        if (buttonPointer == nullptr)
        {
            return;
        }

        buttonPointer->setIcon(iconValue);
        buttonPointer->setText(QString());
        buttonPointer->setToolTip(toolTipText);
        buttonPointer->setFixedWidth(34);
        buttonPointer->setIconSize(QSize(18, 18));
    }

    // createPanelFrame：
    // - Purpose: Create a unified light-border panel to reduce visual fragmentation from bare controls in the top-level layout.
    // - Usage: Top process selection, left Agent, and right Fake Success configuration areas are reused.
    // - Return: QFrame with StyledPanel set; parent object passed by caller.
    QFrame* createPanelFrame(QWidget* parentWidget)
    {
        QFrame* const kFramePointer = new QFrame(parentWidget);
        kFramePointer->setFrameShape(QFrame::StyledPanel);
        kFramePointer->setFrameShadow(QFrame::Plain);
        return kFramePointer;
    }

    // createSectionTitle：
    // - Purpose: Generate configuration section title label.
    // - Called: at the top of the Agent session and Fake Success panels.
    // - Returns: A QLabel with a unified emphasis color style.
    QLabel* createSectionTitle(
        const QString& titleText,
        QWidget* parentWidget,
        const QString& styleSheetText)
    {
        QLabel* const kTitleLabel = new QLabel(titleText, parentWidget);
        kTitleLabel->setStyleSheet(styleSheetText);
        return kTitleLabel;
    }
}

void WinAPIDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(8, 8, 8, 8);
    rootLayout_->setSpacing(8);

    QFrame* const kSessionCollapseFrame = createPanelFrame(this);
    QVBoxLayout* const kSessionCollapseLayout = new QVBoxLayout(kSessionCollapseFrame);
    kSessionCollapseLayout->setContentsMargins(6, 6, 6, 6);
    kSessionCollapseLayout->setSpacing(8);

    sessionCollapseButton_ = new QToolButton(kSessionCollapseFrame);
    sessionCollapseButton_->setCheckable(true);
    sessionCollapseButton_->setChecked(true);
    sessionCollapseButton_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    sessionCollapseButton_->setArrowType(Qt::DownArrow);
    sessionCollapseButton_->setText(QStringLiteral("WinAPI Monitor 配置（目标进程 / Agent / Fake Success）"));
    sessionCollapseButton_->setToolTip(QStringLiteral("展开或折叠上方所有配置；结果表始终保留在最下方。"));
    kSessionCollapseLayout->addWidget(sessionCollapseButton_, 0);

    sessionCollapseContent_ = new QWidget(kSessionCollapseFrame);
    QVBoxLayout* const kSessionCollapseContentLayout = new QVBoxLayout(sessionCollapseContent_);
    kSessionCollapseContentLayout->setContentsMargins(0, 0, 0, 0);
    kSessionCollapseContentLayout->setSpacing(8);
    kSessionCollapseLayout->addWidget(sessionCollapseContent_, 0);
    rootLayout_->addWidget(kSessionCollapseFrame, 0);

    // Top process selection: user first enters a process name or PID, then selects the target from an icon-based dropdown list.
    processPanel_ = createPanelFrame(sessionCollapseContent_);
    QHBoxLayout* const kProcessPanelLayout = new QHBoxLayout(processPanel_);
    kProcessPanelLayout->setContentsMargins(8, 8, 8, 8);
    kProcessPanelLayout->setSpacing(8);

    QLabel* const kProcessTitleLabel = new QLabel(QStringLiteral("目标进程"), processPanel_);
    kProcessTitleLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::kPrimaryBlueHex));

    processIconLabel_ = new QLabel(processPanel_);
    processIconLabel_->setFixedSize(24, 24);
    processIconLabel_->setAlignment(Qt::AlignCenter);
    processIconLabel_->setPixmap(QIcon(QStringLiteral(":/Icon/process_main.svg")).pixmap(20, 20));
    processIconLabel_->setToolTip(QStringLiteral("当前匹配/选中进程图标。"));

    processCombo_ = new QComboBox(processPanel_);
    processCombo_->setEditable(true);
    processCombo_->setInsertPolicy(QComboBox::NoInsert);
    processCombo_->setMaxVisibleItems(24);
    processCombo_->setMinimumWidth(360);
    processCombo_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    processCombo_->setMinimumContentsLength(36);
    processCombo_->setStyleSheet(blueInputStyle());
    processCombo_->setToolTip(QStringLiteral("输入进程名、PID 或路径片段后选择目标。未选择候选时，也可直接输入数字 PID。"));
    if (processCombo_->lineEdit() != nullptr)
    {
        processCombo_->lineEdit()->setPlaceholderText(QStringLiteral("输入进程名 / PID / 路径，然后从下拉列表选择"));
        processCombo_->lineEdit()->setClearButtonEnabled(true);
    }
    if (processCombo_->completer() != nullptr)
    {
        processCombo_->completer()->setCaseSensitivity(Qt::CaseInsensitive);
        processCombo_->completer()->setFilterMode(Qt::MatchContains);
        processCombo_->completer()->setCompletionMode(QCompleter::PopupCompletion);
    }

    processRefreshButton_ = new QPushButton(processPanel_);
    configureIconButton(
        processRefreshButton_,
        style()->standardIcon(QStyle::SP_BrowserReload),
        QStringLiteral("刷新进程候选列表"));
    processRefreshButton_->setStyleSheet(blueButtonStyle());

    processStatusLabel_ = new QLabel(QStringLiteral("● 输入进程名或刷新候选列表"), processPanel_);
    ks::ui::applyStatusRole(processStatusLabel_, ks::ui::StatusRole::kIdle);

    kProcessPanelLayout->addWidget(kProcessTitleLabel, 0);
    kProcessPanelLayout->addWidget(processIconLabel_, 0);
    kProcessPanelLayout->addWidget(processCombo_, 1);
    kProcessPanelLayout->addWidget(processRefreshButton_, 0);
    kProcessPanelLayout->addWidget(processStatusLabel_, 0);
    kSessionCollapseContentLayout->addWidget(processPanel_, 0);

    // Bottom layout: left side is a standard WinAPI Agent session, right side is the Fake Success rule.
    topSplitter_ = new QSplitter(Qt::Horizontal, sessionCollapseContent_);
    topSplitter_->setChildrenCollapsible(false);
    kSessionCollapseContentLayout->addWidget(topSplitter_, 0);

    sessionPanel_ = createPanelFrame(nullptr);
    QVBoxLayout* const kSessionPanelLayout = new QVBoxLayout(sessionPanel_);
    kSessionPanelLayout->setContentsMargins(8, 8, 8, 8);
    kSessionPanelLayout->setSpacing(8);

    kSessionPanelLayout->addWidget(
        createSectionTitle(
            QStringLiteral("WinAPI Agent 会话"),
            sessionPanel_,
            QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::kPrimaryBlueHex)),
        0);

    QHBoxLayout* const kSessionConfigurationColumnsLayout = new QHBoxLayout();
    kSessionConfigurationColumnsLayout->setContentsMargins(0, 0, 0, 0);
    kSessionConfigurationColumnsLayout->setSpacing(8);

    QWidget* const kSessionConfigurationLeftColumn = new QWidget(sessionPanel_);
    QVBoxLayout* const kSessionConfigurationLeftLayout = new QVBoxLayout(kSessionConfigurationLeftColumn);
    kSessionConfigurationLeftLayout->setContentsMargins(0, 0, 0, 0);
    kSessionConfigurationLeftLayout->setSpacing(8);

    QFormLayout* const kSessionFormLayout = new QFormLayout();
    kSessionFormLayout->setContentsMargins(0, 0, 0, 0);
    kSessionFormLayout->setHorizontalSpacing(8);
    kSessionFormLayout->setVerticalSpacing(8);

    QWidget* const kDllPathRowWidget = new QWidget(kSessionConfigurationLeftColumn);
    QHBoxLayout* const kDllPathLayout = new QHBoxLayout(kDllPathRowWidget);
    kDllPathLayout->setContentsMargins(0, 0, 0, 0);
    kDllPathLayout->setSpacing(6);
    agentDllPathEdit_ = new QLineEdit(kDllPathRowWidget);
    agentDllPathEdit_->setText(defaultDllPathHint());
    agentDllPathEdit_->setToolTip(QStringLiteral("需要注入到目标进程中的 APIMonitor_x64.dll 路径。"));
    agentDllPathEdit_->setStyleSheet(blueInputStyle());

    browseAgentDllButton_ = new QPushButton(kDllPathRowWidget);
    configureIconButton(
        browseAgentDllButton_,
        style()->standardIcon(QStyle::SP_DirOpenIcon),
        QStringLiteral("浏览 Agent DLL 路径"));
    browseAgentDllButton_->setStyleSheet(blueButtonStyle());

    kDllPathLayout->addWidget(agentDllPathEdit_, 1);
    kDllPathLayout->addWidget(browseAgentDllButton_, 0);
    kSessionFormLayout->addRow(QStringLiteral("Agent DLL"), kDllPathRowWidget);

    manualPidEdit_ = new QLineEdit(kSessionConfigurationLeftColumn);
    manualPidEdit_->setPlaceholderText(QStringLiteral("可留空；填写后覆盖顶部进程选择"));
    manualPidEdit_->setToolTip(QStringLiteral("高级兜底：当下拉候选没有目标时，可直接输入 PID。填写后优先使用这里的 PID。"));
    manualPidEdit_->setStyleSheet(blueInputStyle());
    kSessionFormLayout->addRow(QStringLiteral("目标 PID（高级）"), manualPidEdit_);
    kSessionConfigurationLeftLayout->addLayout(kSessionFormLayout);

    QFrame* const kCategoryFrame = createPanelFrame(kSessionConfigurationLeftColumn);
    QVBoxLayout* const kCategoryLayout = new QVBoxLayout(kCategoryFrame);
    kCategoryLayout->setContentsMargins(8, 8, 8, 8);
    kCategoryLayout->setSpacing(6);

    QLabel* const kCategoryTitleLabel = new QLabel(QStringLiteral("Hook 分类"), kCategoryFrame);
    kCategoryLayout->addWidget(kCategoryTitleLabel, 0);

    hookFileCheck_ = new QCheckBox(QStringLiteral("文件 API"), kCategoryFrame);
    hookRegistryCheck_ = new QCheckBox(QStringLiteral("注册表 API"), kCategoryFrame);
    hookNetworkCheck_ = new QCheckBox(QStringLiteral("网络 API"), kCategoryFrame);
    hookProcessCheck_ = new QCheckBox(QStringLiteral("进程 API"), kCategoryFrame);
    hookLoaderCheck_ = new QCheckBox(QStringLiteral("加载器 API"), kCategoryFrame);
    autoInjectChildCheck_ = new QCheckBox(QStringLiteral("自动注入子进程"), kCategoryFrame);
    rawFallbackCheck_ = new QCheckBox(QStringLiteral("Raw 兜底 Hook（强类型优先）"), kCategoryFrame);
    rawDefaultDenyListCheck_ = new QCheckBox(QStringLiteral("启用默认高频/高风险黑名单"), kCategoryFrame);
    QFrame* const kRawConfigurationFrame = createPanelFrame(sessionPanel_);
    QVBoxLayout* const kRawConfigurationLayout = new QVBoxLayout(kRawConfigurationFrame);
    kRawConfigurationLayout->setContentsMargins(8, 8, 8, 8);
    kRawConfigurationLayout->setSpacing(6);

    QLabel* const kRawConfigurationTitleLabel = new QLabel(QStringLiteral("Raw 兜底配置"), kRawConfigurationFrame);
    kRawConfigurationLayout->addWidget(kRawConfigurationTitleLabel, 0);

    rawModuleListEdit_ = new QPlainTextEdit(kRawConfigurationFrame);
    rawDenyListEdit_ = new QPlainTextEdit(kRawConfigurationFrame);

    hookFileCheck_->setChecked(true);
    hookRegistryCheck_->setChecked(true);
    hookNetworkCheck_->setChecked(true);
    hookProcessCheck_->setChecked(true);
    hookLoaderCheck_->setChecked(false);
    autoInjectChildCheck_->setChecked(false);
    rawFallbackCheck_->setChecked(true);
    rawDefaultDenyListCheck_->setChecked(true);
    rawModuleListEdit_->setPlainText(defaultRawHookModulesText());
    rawDenyListEdit_->clear();
    rawModuleListEdit_->setStyleSheet(blueInputStyle());
    rawDenyListEdit_->setStyleSheet(blueInputStyle());
    rawModuleListEdit_->setFixedHeight(76);
    rawDenyListEdit_->setFixedHeight(76);
    rawModuleListEdit_->setPlaceholderText(QStringLiteral("ntdll.dll;KernelBase.dll;ws2_32.dll;wininet.dll;..."));
    rawDenyListEdit_->setPlaceholderText(QStringLiteral("额外规则，例如 MyHotApi;SomePrefix*；默认黑名单由上方复选框控制"));

    hookFileCheck_->setToolTip(QStringLiteral("CreateFileW / ReadFile / WriteFile 等文件访问相关 API。"));
    hookRegistryCheck_->setToolTip(QStringLiteral("RegOpenKeyExW / RegQueryValueExW / RegSetValueExW / RegDeleteValueW / RegEnum* 等注册表相关 API。"));
    hookNetworkCheck_->setToolTip(QStringLiteral("connect / WSAConnect / send / WSASend / sendto / recv / WSARecv / recvfrom 等网络相关 API。"));
    hookProcessCheck_->setToolTip(QStringLiteral("CreateProcessW 等进程控制相关 API。"));
    hookLoaderCheck_->setToolTip(QStringLiteral("LoadLibraryW / LoadLibraryExW 等模块加载相关 API。该类 Hook 对 GUI 进程稳定性风险更高，默认关闭。"));
    autoInjectChildCheck_->setToolTip(QStringLiteral("启用后，Agent 会在 CreateProcessW 成功时把同一个 APIMonitor_x64.dll 注入到新子进程；仅支持 x64 子进程。"));
    rawFallbackCheck_->setToolTip(QStringLiteral("对强类型表未覆盖的已加载模块导出安装 Raw ABI 入口 Hook。强类型 Hook 优先，Raw 只记录模块/函数/地址等兜底信息。"));
    rawDefaultDenyListCheck_->setToolTip(QStringLiteral("Raw 黑名单只影响兜底 Hook；强类型 Hook 不受影响。建议长期保持开启，避免字符串、堆、锁、时间等高频基础 API 刷爆日志。关闭后，下方额外黑名单仍然生效。"));
    rawModuleListEdit_->setToolTip(QStringLiteral("分号分隔模块名。Agent 只扫描已加载模块，后续 LoadLibrary 后会重试补装。"));
    rawDenyListEdit_->setToolTip(QStringLiteral("用户额外黑名单，分号分隔函数名，支持 prefix*。内置默认黑名单由上方复选框控制，不需要复制到这里。当前内置默认：%1").arg(defaultRawHookDenyListText()));

    kCategoryLayout->addWidget(hookFileCheck_, 0);
    kCategoryLayout->addWidget(hookRegistryCheck_, 0);
    kCategoryLayout->addWidget(hookNetworkCheck_, 0);
    kCategoryLayout->addWidget(hookProcessCheck_, 0);
    kCategoryLayout->addWidget(hookLoaderCheck_, 0);
    kCategoryLayout->addWidget(autoInjectChildCheck_, 0);
    kCategoryLayout->addWidget(rawFallbackCheck_, 0);
    kCategoryLayout->addWidget(rawDefaultDenyListCheck_, 0);
    kSessionConfigurationLeftLayout->addWidget(kCategoryFrame, 0);

    kRawConfigurationLayout->addWidget(new QLabel(QStringLiteral("Raw 模块目录（; 分隔）"), kRawConfigurationFrame), 0);
    kRawConfigurationLayout->addWidget(rawModuleListEdit_, 0);
    kRawConfigurationLayout->addWidget(new QLabel(QStringLiteral("Raw 额外黑名单（exact / prefix*）"), kRawConfigurationFrame), 0);
    kRawConfigurationLayout->addWidget(rawDenyListEdit_, 0);
    kRawConfigurationLayout->addStretch(1);

    kSessionConfigurationColumnsLayout->addWidget(kSessionConfigurationLeftColumn, 1);
    kSessionConfigurationColumnsLayout->addWidget(kRawConfigurationFrame, 1);
    kSessionPanelLayout->addLayout(kSessionConfigurationColumnsLayout);

    QHBoxLayout* const kSessionButtonLayout = new QHBoxLayout();
    kSessionButtonLayout->setSpacing(6);

    startButton_ = new QPushButton(sessionPanel_);
    configureIconButton(
        startButton_,
        style()->standardIcon(QStyle::SP_MediaPlay),
        QStringLiteral("启动 WinAPI 监控"));
    startButton_->setStyleSheet(blueButtonStyle());

    stopButton_ = new QPushButton(sessionPanel_);
    configureIconButton(
        stopButton_,
        style()->standardIcon(QStyle::SP_MediaStop),
        QStringLiteral("停止 WinAPI 监控"));
    stopButton_->setStyleSheet(blueButtonStyle());

    terminateHookButton_ = new QPushButton(sessionPanel_);
    configureIconButton(
        terminateHookButton_,
        style()->standardIcon(QStyle::SP_BrowserStop),
        QStringLiteral("手动终止目标进程中的 Hook"));
    terminateHookButton_->setStyleSheet(blueButtonStyle());

    exportButton_ = new QPushButton(sessionPanel_);
    configureIconButton(
        exportButton_,
        style()->standardIcon(QStyle::SP_DialogSaveButton),
        QStringLiteral("导出当前可见事件为 TSV"));
    exportButton_->setStyleSheet(blueButtonStyle());

    clearEventButton_ = new QPushButton(sessionPanel_);
    configureIconButton(
        clearEventButton_,
        style()->standardIcon(QStyle::SP_DialogResetButton),
        QStringLiteral("清空当前事件表"));
    clearEventButton_->setStyleSheet(blueButtonStyle());

    kSessionButtonLayout->addWidget(startButton_, 0);
    kSessionButtonLayout->addWidget(stopButton_, 0);
    kSessionButtonLayout->addWidget(terminateHookButton_, 0);
    kSessionButtonLayout->addWidget(exportButton_, 0);
    kSessionButtonLayout->addWidget(clearEventButton_, 0);
    kSessionButtonLayout->addStretch(1);
    kSessionPanelLayout->addLayout(kSessionButtonLayout);

    sessionStatusLabel_ = new QLabel(QStringLiteral("● 空闲"), sessionPanel_);
    ks::ui::applyStatusRole(sessionStatusLabel_, ks::ui::StatusRole::kIdle);
    kSessionPanelLayout->addWidget(sessionStatusLabel_, 0);
    kSessionPanelLayout->addStretch(1);

    QWidget* const kFakeSuccessPanel = createPanelFrame(nullptr);
    QVBoxLayout* const kFakeSuccessLayout = new QVBoxLayout(kFakeSuccessPanel);
    kFakeSuccessLayout->setContentsMargins(8, 8, 8, 8);
    kFakeSuccessLayout->setSpacing(6);

    kFakeSuccessLayout->addWidget(
        createSectionTitle(
            QStringLiteral("Fake Success（命中 API 直接伪返回）"),
            kFakeSuccessPanel,
            QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::kPrimaryBlueHex)),
        0);

    QFormLayout* const kFakeFormLayout = new QFormLayout();
    kFakeFormLayout->setContentsMargins(0, 0, 0, 0);
    kFakeFormLayout->setHorizontalSpacing(8);
    kFakeFormLayout->setVerticalSpacing(6);

    fakeModuleEdit_ = new QLineEdit(kFakeSuccessPanel);
    fakeApiEdit_ = new QLineEdit(kFakeSuccessPanel);
    fakeReturnValueEdit_ = new QLineEdit(kFakeSuccessPanel);
    fakeLastErrorValueEdit_ = new QLineEdit(kFakeSuccessPanel);
    fakeReturnTypeCombo_ = new QComboBox(kFakeSuccessPanel);
    fakeLastErrorKindCombo_ = new QComboBox(kFakeSuccessPanel);
    fakeRawFallbackCheck_ = new QCheckBox(QStringLiteral("启用 Fake Raw 兜底（未强类型导出仅伪造 RAX）"), kFakeSuccessPanel);

    fakeModuleEdit_->setPlaceholderText(QStringLiteral("KernelBase.dll"));
    fakeApiEdit_->setPlaceholderText(QStringLiteral("CreateFileW"));
    // Attach the exact match criteria to the corresponding input fields to avoid adding a persistent description at the top of the panel.
    fakeModuleEdit_->setToolTip(QStringLiteral("精确匹配模块名，需要带扩展名。"));
    fakeApiEdit_->setToolTip(QStringLiteral("精确匹配导出名，区分 A/W 后缀。"));
    fakeReturnValueEdit_->setPlaceholderText(QStringLiteral("0 / 1 / 0x0 / 0xFFFFFFFFFFFFFFFF"));
    fakeLastErrorValueEdit_->setPlaceholderText(QStringLiteral("0 表示 ERROR_SUCCESS"));
    fakeReturnValueEdit_->setText(QStringLiteral("0"));
    fakeLastErrorValueEdit_->setText(QStringLiteral("0"));
    fakeModuleEdit_->setStyleSheet(blueInputStyle());
    fakeApiEdit_->setStyleSheet(blueInputStyle());
    fakeReturnValueEdit_->setStyleSheet(blueInputStyle());
    fakeLastErrorValueEdit_->setStyleSheet(blueInputStyle());

    fakeReturnTypeCombo_->addItem(QStringLiteral("Scalar / RAX"), QStringLiteral("scalar"));
    fakeReturnTypeCombo_->addItem(QStringLiteral("BOOL"), QStringLiteral("bool"));
    fakeReturnTypeCombo_->addItem(QStringLiteral("HANDLE / PVOID"), QStringLiteral("handle"));
    fakeReturnTypeCombo_->addItem(QStringLiteral("DWORD / UINT / int"), QStringLiteral("dword"));
    fakeReturnTypeCombo_->addItem(QStringLiteral("NTSTATUS"), QStringLiteral("ntstatus"));
    fakeReturnTypeCombo_->addItem(QStringLiteral("HRESULT"), QStringLiteral("hresult"));
    fakeReturnTypeCombo_->addItem(QStringLiteral("LSTATUS"), QStringLiteral("lstatus"));
    fakeReturnTypeCombo_->addItem(QStringLiteral("SOCKET / int (WSA)"), QStringLiteral("socket"));
    fakeReturnTypeCombo_->setToolTip(QStringLiteral("模板只影响展示和结果码语义；v1 只伪造标量返回值，不写 out 参数。Fake 路径会先上报事件，再跳过原 API 并返回指定 RAX。"));
    fakeReturnTypeCombo_->setStyleSheet(blueInputStyle());

    fakeLastErrorKindCombo_->addItem(QStringLiteral("不修改 LastError"), QStringLiteral("none"));
    fakeLastErrorKindCombo_->addItem(QStringLiteral("SetLastError"), QStringLiteral("win32"));
    fakeLastErrorKindCombo_->addItem(QStringLiteral("WSASetLastError"), QStringLiteral("wsa"));
    fakeLastErrorKindCombo_->setToolTip(QStringLiteral("可选：Fake 返回前后设置 Win32 LastError 或 WSAError。"));
    fakeLastErrorKindCombo_->setStyleSheet(blueInputStyle());
    fakeRawFallbackCheck_->setChecked(false);
    fakeRawFallbackCheck_->setToolTip(QStringLiteral("关闭时，仅强类型表覆盖的 API 可 Fake Success；开启后，规则表里未强类型覆盖的 module!api 也会用通用 x64 RAX stub 直接返回。"));

    kFakeFormLayout->addRow(QStringLiteral("模块"), fakeModuleEdit_);
    kFakeFormLayout->addRow(QStringLiteral("API"), fakeApiEdit_);
    kFakeFormLayout->addRow(QStringLiteral("返回模板"), fakeReturnTypeCombo_);
    kFakeFormLayout->addRow(QStringLiteral("返回值"), fakeReturnValueEdit_);
    kFakeFormLayout->addRow(QStringLiteral("错误码类型"), fakeLastErrorKindCombo_);
    kFakeFormLayout->addRow(QStringLiteral("错误码值"), fakeLastErrorValueEdit_);
    kFakeSuccessLayout->addLayout(kFakeFormLayout);
    kFakeSuccessLayout->addWidget(fakeRawFallbackCheck_, 0);

    QHBoxLayout* const kFakeButtonLayout = new QHBoxLayout();
    kFakeButtonLayout->setContentsMargins(0, 0, 0, 0);
    kFakeButtonLayout->setSpacing(6);
    fakeAddRuleButton_ = new QPushButton(QStringLiteral("添加规则"), kFakeSuccessPanel);
    fakeRemoveRuleButton_ = new QPushButton(QStringLiteral("删除选中"), kFakeSuccessPanel);
    fakeApplyRuleButton_ = new QPushButton(QStringLiteral("应用规则并启动"), kFakeSuccessPanel);
    fakeStopRuleButton_ = new QPushButton(QStringLiteral("停止会话"), kFakeSuccessPanel);
    fakeAddRuleButton_->setToolTip(QStringLiteral("把上方输入加入规则表；启动 WinAPI 监控时写入 Agent 配置并生效。"));
    fakeRemoveRuleButton_->setToolTip(QStringLiteral("删除规则表当前选中的 Fake Success 规则。"));
    fakeApplyRuleButton_->setToolTip(QStringLiteral("用当前规则表写入配置并启动 WinAPI Agent。若会话已运行，请先停止再应用。"));
    fakeStopRuleButton_->setToolTip(QStringLiteral("停止当前 WinAPI Agent 会话；Fake Success 不支持运行中热更新。"));
    fakeAddRuleButton_->setStyleSheet(blueButtonStyle());
    fakeRemoveRuleButton_->setStyleSheet(blueButtonStyle());
    fakeApplyRuleButton_->setStyleSheet(blueButtonStyle());
    fakeStopRuleButton_->setStyleSheet(blueButtonStyle());
    kFakeButtonLayout->addWidget(fakeAddRuleButton_, 0);
    kFakeButtonLayout->addWidget(fakeRemoveRuleButton_, 0);
    kFakeButtonLayout->addWidget(fakeApplyRuleButton_, 0);
    kFakeButtonLayout->addWidget(fakeStopRuleButton_, 0);
    kFakeButtonLayout->addStretch(1);
    kFakeSuccessLayout->addLayout(kFakeButtonLayout);

    fakeRuleTable_ = new ks::ui::VisibleTableWidget(kFakeSuccessPanel);
    fakeRuleTable_->setColumnCount(kFakeRuleColumnCount);
    fakeRuleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    fakeRuleTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    fakeRuleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fakeRuleTable_->setAlternatingRowColors(true);
    fakeRuleTable_->setHorizontalHeaderLabels(
        QStringList{
            QStringLiteral("模块"),
            QStringLiteral("API"),
            QStringLiteral("返回模板"),
            QStringLiteral("返回值"),
            QStringLiteral("错误类型"),
            QStringLiteral("错误值")
        });
    fakeRuleTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    fakeRuleTable_->horizontalHeader()->setSectionResizeMode(kFakeRuleColumnModule, QHeaderView::ResizeToContents);
    fakeRuleTable_->horizontalHeader()->setSectionResizeMode(kFakeRuleColumnApi, QHeaderView::ResizeToContents);
    fakeRuleTable_->horizontalHeader()->setSectionResizeMode(kFakeRuleColumnReturnType, QHeaderView::ResizeToContents);
    fakeRuleTable_->horizontalHeader()->setSectionResizeMode(kFakeRuleColumnReturnValue, QHeaderView::ResizeToContents);
    fakeRuleTable_->horizontalHeader()->setSectionResizeMode(kFakeRuleColumnLastErrorKind, QHeaderView::ResizeToContents);
    fakeRuleTable_->horizontalHeader()->setSectionResizeMode(kFakeRuleColumnLastErrorValue, QHeaderView::Stretch);
    fakeRuleTable_->setStyleSheet(blueInputStyle());
    fakeRuleTable_->setMaximumHeight(170);
    kFakeSuccessLayout->addWidget(fakeRuleTable_, 0);

    fakeRuleStatusLabel_ = new QLabel(QStringLiteral("规则：0 条；启动会话时应用。"), kFakeSuccessPanel);
    ks::ui::applyStatusRole(fakeRuleStatusLabel_, ks::ui::StatusRole::kIdle);
    kFakeSuccessLayout->addWidget(fakeRuleStatusLabel_, 0);
    kFakeSuccessLayout->addStretch(1);

    topSplitter_->addWidget(sessionPanel_);
    topSplitter_->addWidget(kFakeSuccessPanel);
    topSplitter_->setStretchFactor(0, 1);
    topSplitter_->setStretchFactor(1, 1);

    filterPanel_ = new QWidget(this);
    QHBoxLayout* const kFilterLayout = new QHBoxLayout(filterPanel_);
    kFilterLayout->setContentsMargins(0, 0, 0, 0);
    kFilterLayout->setSpacing(6);

    eventFilterEdit_ = new QLineEdit(filterPanel_);
    eventFilterEdit_->setPlaceholderText(QStringLiteral("过滤 API / 分类 / 结果 / 详情"));
    eventFilterEdit_->setStyleSheet(blueInputStyle());

    eventFilterClearButton_ = new QPushButton(filterPanel_);
    configureIconButton(
        eventFilterClearButton_,
        style()->standardIcon(QStyle::SP_DialogResetButton),
        QStringLiteral("清空事件过滤条件"));
    eventFilterClearButton_->setStyleSheet(blueButtonStyle());

    eventKeepBottomCheck_ = new QCheckBox(QStringLiteral("保持贴底"), filterPanel_);
    eventKeepBottomCheck_->setChecked(true);
    eventKeepBottomCheck_->setToolTip(QStringLiteral("新事件到来时自动滚动到最底部。"));

    eventFilterStatusLabel_ = new QLabel(QStringLiteral("筛选结果：0 / 0"), filterPanel_);
    ks::ui::applyStatusRole(eventFilterStatusLabel_, ks::ui::StatusRole::kIdle);

    kFilterLayout->addWidget(eventFilterEdit_, 1);
    kFilterLayout->addWidget(eventFilterClearButton_, 0);
    kFilterLayout->addWidget(eventKeepBottomCheck_, 0);
    kFilterLayout->addWidget(eventFilterStatusLabel_, 0);
    rootLayout_->addWidget(filterPanel_, 0);

    eventTable_ = new ks::ui::VisibleTableWidget(this);
    eventTable_->setColumnCount(kEventColumnCount);
    eventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    eventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    eventTable_->setAlternatingRowColors(true);
    eventTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    eventTable_->setHorizontalHeaderLabels(
        QStringList{
            QStringLiteral("时间(100ns)"),
            QStringLiteral("分类"),
            QStringLiteral("API"),
            QStringLiteral("结果"),
            QStringLiteral("PID/TID"),
            QStringLiteral("详情")
        });
    eventTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    eventTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    eventTable_->setColumnWidth(kEventColumnTime100ns, 160);
    eventTable_->setColumnWidth(kEventColumnCategory, 72);
    eventTable_->setColumnWidth(kEventColumnApi, 190);
    eventTable_->setColumnWidth(kEventColumnResult, 100);
    eventTable_->setColumnWidth(kEventColumnPidTid, 112);
    eventTable_->setColumnWidth(kEventColumnDetail, 440);
    eventTable_->setStyleSheet(blueInputStyle());
    eventTable_->setAutoFillBackground(false);
    eventTable_->setAttribute(Qt::WA_StyledBackground, true);
    if (eventTable_->viewport() != nullptr)
    {
        eventTable_->viewport()->setAutoFillBackground(false);
        eventTable_->viewport()->setAttribute(Qt::WA_StyledBackground, true);
    }
    rootLayout_->addWidget(eventTable_, 1);

    uiFlushTimer_ = new QTimer(this);
    uiFlushTimer_->setInterval(120);

    connect(sessionCollapseButton_, &QToolButton::toggled, this, [this](const bool checked) {
        if (sessionCollapseContent_ != nullptr)
        {
            sessionCollapseContent_->setVisible(checked);
        }
        if (sessionCollapseButton_ != nullptr)
        {
            sessionCollapseButton_->setArrowType(checked ? Qt::DownArrow : Qt::RightArrow);
        }
    });
}
