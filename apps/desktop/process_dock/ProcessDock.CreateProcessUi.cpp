#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::initializeCreateProcessPage()
{
    createProcessPage_ = new QWidget(this);
    applyTransparentContainerStyle(createProcessPage_);
    createProcessPageLayout_ = new QVBoxLayout(createProcessPage_);
    createProcessPageLayout_->setContentsMargins(6, 6, 6, 6);
    createProcessPageLayout_->setSpacing(6);

    QScrollArea* scrollArea = new QScrollArea(createProcessPage_);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);
    applyTransparentContainerStyle(scrollArea);
    createProcessPageLayout_->addWidget(scrollArea, 1);

    QWidget* contentWidget = new QWidget(scrollArea);
    applyTransparentContainerStyle(contentWidget);
    QVBoxLayout* contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setContentsMargins(2, 2, 2, 2);
    contentLayout->setSpacing(8);
    scrollArea->setWidget(contentWidget);

    const QString kInputStyle = buildBlueLineEditStyle();
    const QString kComboStyle = buildBlueComboBoxStyle();
    const QString kButtonStyle = buildBlueButtonStyle(false);

    // Clear bit flag check caches before rebuilding the page to avoid dangling pointers caused by redundant initialization.
    creationFlagChecks_.clear();
    startupFlagChecks_.clear();
    startupFillAttributeChecks_.clear();
    tokenDesiredAccessChecks_.clear();

    // buildBitmaskCheckGroup:
    // - Automatically generate checkbox groups based on the 'Flag Definition List'.
    // - Each checkbox saves flagValue/flagName via Qt Property for subsequent unified combination calculations;
    const auto kBuildBitmaskCheckGroup =
        [](
            QWidget* parentWidget,
            const QString& groupTitle,
            const std::vector<BitmaskFlagDefinition>& definitionList,
            std::vector<QCheckBox*>* outputCheckBoxList) -> QGroupBox*
    {
        QGroupBox* groupBox = new QGroupBox(groupTitle, parentWidget);
        applyTransparentContainerStyle(groupBox);
        QGridLayout* groupLayout = new QGridLayout(groupBox);
        groupLayout->setContentsMargins(6, 6, 6, 6);
        groupLayout->setHorizontalSpacing(10);
        groupLayout->setVerticalSpacing(4);

        const int kColumnCount = 3;
        for (std::size_t index = 0; index < definitionList.size(); ++index)
        {
            const BitmaskFlagDefinition& definition = definitionList[index];
            QCheckBox* flagCheck = new QCheckBox(QString::fromUtf8(definition.nameText), groupBox);
            flagCheck->setProperty("flagValue", static_cast<qulonglong>(definition.value));
            flagCheck->setProperty("flagName", QString::fromUtf8(definition.nameText));
            flagCheck->setToolTip(
                QStringLiteral("%1\n值: 0x%2\n说明: %3")
                .arg(QString::fromUtf8(definition.nameText))
                .arg(QString::number(static_cast<qulonglong>(definition.value), 16).toUpper())
                .arg(QString::fromUtf8(definition.descriptionText)));

            const int kRow = static_cast<int>(index / static_cast<std::size_t>(kColumnCount));
            const int kCol = static_cast<int>(index % static_cast<std::size_t>(kColumnCount));
            groupLayout->addWidget(flagCheck, kRow, kCol);

            if (outputCheckBoxList != nullptr)
            {
                outputCheckBoxList->push_back(flagCheck);
            }
        }
        return groupBox;
    };

    // 1) Creation method + token source configuration.
    QGroupBox* methodGroup = new QGroupBox("创建方式 / 令牌来源", contentWidget);
    applyTransparentContainerStyle(methodGroup);
    QGridLayout* methodLayout = new QGridLayout(methodGroup);
    methodLayout->setHorizontalSpacing(8);
    methodLayout->setVerticalSpacing(6);
    createMethodCombo_ = new QComboBox(methodGroup);
    createMethodCombo_->addItem("CreateProcessW");
    createMethodCombo_->addItem("CreateProcessAsTokenW (内部使用 CreateProcessAsUserW + fallback)");
    createMethodCombo_->setStyleSheet(kComboStyle);
    createMethodCombo_->setCurrentIndex(0);
    createMethodCombo_->setToolTip("默认直接调用 CreateProcessW；切换到 Token 模式时会按 PID 打开并调整令牌。");

    tokenSourcePidEdit_ = new QLineEdit("0", methodGroup);
    tokenDesiredAccessEdit_ = new QLineEdit("0x00000FAB", methodGroup);
    tokenDuplicatePrimaryCheck_ = new QCheckBox("DuplicateTokenEx 成 PrimaryToken", methodGroup);
    tokenDuplicatePrimaryCheck_->setChecked(true);
    tokenSourcePidEdit_->setStyleSheet(kInputStyle);
    tokenDesiredAccessEdit_->setStyleSheet(kInputStyle);

    // Supplement the method selection area with Chinese semantics to avoid confusion when viewing only English API names.
    methodLayout->addWidget(new QLabel("API（创建方式）:", methodGroup), 0, 0);
    methodLayout->addWidget(createMethodCombo_, 0, 1, 1, 3);
    methodLayout->addWidget(new QLabel("源 PID（令牌来源进程）:", methodGroup), 1, 0);
    methodLayout->addWidget(tokenSourcePidEdit_, 1, 1);
    methodLayout->addWidget(new QLabel("令牌访问掩码（DesiredAccess）:", methodGroup), 1, 2);
    methodLayout->addWidget(tokenDesiredAccessEdit_, 1, 3);
    methodLayout->addWidget(tokenDuplicatePrimaryCheck_, 2, 0, 1, 4);

    // Token DesiredAccess bitmask selection area:
    // - Covers the most common TOKEN_* / standard permissions / GENERIC_* combinations.
    // - Users can select combinations to automatically construct the access mask.
    QGroupBox* tokenAccessGroup = kBuildBitmaskCheckGroup(
        methodGroup,
        "Token DesiredAccess 位标志组合",
        kTokenDesiredAccessDefinitions,
        &tokenDesiredAccessChecks_);
    methodLayout->addWidget(tokenAccessGroup, 3, 0, 1, 4);
    contentLayout->addWidget(methodGroup);

    // 2) CreateProcessW basic parameters.
    QGroupBox* basicGroup = new QGroupBox("CreateProcessW 参数（全部可选 Null）", contentWidget);
    applyTransparentContainerStyle(basicGroup);
    QGridLayout* basicLayout = new QGridLayout(basicGroup);
    basicLayout->setHorizontalSpacing(8);
    basicLayout->setVerticalSpacing(6);

    useApplicationNameCheck_ = new QCheckBox("启用 lpApplicationName（应用程序路径）", basicGroup);
    useCommandLineCheck_ = new QCheckBox("启用 lpCommandLine（命令行参数）", basicGroup);
    useCurrentDirectoryCheck_ = new QCheckBox("启用 lpCurrentDirectory（当前工作目录）", basicGroup);
    useEnvironmentCheck_ = new QCheckBox("启用 lpEnvironment（环境变量块）", basicGroup);
    environmentUnicodeCheck_ = new QCheckBox("环境块按 Unicode 传递（CREATE_UNICODE_ENVIRONMENT）", basicGroup);
    inheritHandleCheck_ = new QCheckBox("bInheritHandles（是否继承句柄）=TRUE", basicGroup);

    applicationNameEdit_ = new QLineEdit(basicGroup);
    applicationBrowseButton_ = new QPushButton("浏览…", basicGroup);
    commandLineEdit_ = new QLineEdit(basicGroup);
    currentDirectoryEdit_ = new QLineEdit(basicGroup);
    currentDirectoryBrowseButton_ = new QPushButton("浏览…", basicGroup);
    environmentEditor_ = new QPlainTextEdit(basicGroup);
    creationFlagsEdit_ = new QLineEdit("0x00000000", basicGroup);
    environmentEditor_->setPlaceholderText("每行一个 KEY=VALUE，留空则为 null。");
    environmentEditor_->setFixedHeight(72);

    applicationNameEdit_->setStyleSheet(kInputStyle);
    commandLineEdit_->setStyleSheet(kInputStyle);
    currentDirectoryEdit_->setStyleSheet(kInputStyle);
    environmentEditor_->setStyleSheet(kInputStyle);
    creationFlagsEdit_->setStyleSheet(kInputStyle);
    applicationBrowseButton_->setStyleSheet(kButtonStyle);
    currentDirectoryBrowseButton_->setStyleSheet(kButtonStyle);

    useApplicationNameCheck_->setChecked(false);
    useCommandLineCheck_->setChecked(false);
    useCurrentDirectoryCheck_->setChecked(false);
    useEnvironmentCheck_->setChecked(false);
    environmentUnicodeCheck_->setChecked(true);

    basicLayout->addWidget(useApplicationNameCheck_, 0, 0);
    basicLayout->addWidget(applicationNameEdit_, 0, 1, 1, 2);
    basicLayout->addWidget(applicationBrowseButton_, 0, 3);
    basicLayout->addWidget(useCommandLineCheck_, 1, 0);
    basicLayout->addWidget(commandLineEdit_, 1, 1, 1, 3);
    basicLayout->addWidget(useCurrentDirectoryCheck_, 2, 0);
    basicLayout->addWidget(currentDirectoryEdit_, 2, 1, 1, 2);
    basicLayout->addWidget(currentDirectoryBrowseButton_, 2, 3);
    basicLayout->addWidget(useEnvironmentCheck_, 3, 0);
    basicLayout->addWidget(environmentEditor_, 3, 1, 2, 3);
    basicLayout->addWidget(environmentUnicodeCheck_, 5, 1, 1, 3);
    basicLayout->addWidget(new QLabel("dwCreationFlags（创建标志）:", basicGroup), 6, 0);
    basicLayout->addWidget(creationFlagsEdit_, 6, 1);
    basicLayout->addWidget(inheritHandleCheck_, 6, 2, 1, 2);

    // dwCreationFlags bitmask selection area:
    // - List all common CreateProcess flags.
    // - When the user checks this, the flags are automatically combined into a bitmask and written back to the dwCreationFlags input box.
    QGroupBox* creationFlagsGroup = kBuildBitmaskCheckGroup(
        basicGroup,
        "dwCreationFlags 位标志组合",
        kCreateProcessFlagDefinitions,
        &creationFlagChecks_);
    basicLayout->addWidget(creationFlagsGroup, 7, 0, 1, 4);
    contentLayout->addWidget(basicGroup);

    // 3) PROCESS / THREAD SECURITY_ATTRIBUTES。
    QGroupBox* securityGroup = new QGroupBox("SECURITY_ATTRIBUTES（Process / Thread）", contentWidget);
    applyTransparentContainerStyle(securityGroup);
    QGridLayout* securityLayout = new QGridLayout(securityGroup);
    securityLayout->setHorizontalSpacing(8);
    securityLayout->setVerticalSpacing(6);

    useProcessSecurityCheck_ = new QCheckBox("启用 lpProcessAttributes（进程安全属性）", securityGroup);
    processSecurityLengthEdit_ = new QLineEdit("0", securityGroup);
    processSecurityDescriptorEdit_ = new QLineEdit("0", securityGroup);
    processSecurityInheritCheck_ = new QCheckBox("bInheritHandle（进程 SA）", securityGroup);

    useThreadSecurityCheck_ = new QCheckBox("启用 lpThreadAttributes（线程安全属性）", securityGroup);
    threadSecurityLengthEdit_ = new QLineEdit("0", securityGroup);
    threadSecurityDescriptorEdit_ = new QLineEdit("0", securityGroup);
    threadSecurityInheritCheck_ = new QCheckBox("bInheritHandle（线程 SA）", securityGroup);

    processSecurityLengthEdit_->setStyleSheet(kInputStyle);
    processSecurityDescriptorEdit_->setStyleSheet(kInputStyle);
    threadSecurityLengthEdit_->setStyleSheet(kInputStyle);
    threadSecurityDescriptorEdit_->setStyleSheet(kInputStyle);

    securityLayout->addWidget(useProcessSecurityCheck_, 0, 0);
    securityLayout->addWidget(new QLabel("nLength（结构体长度）", securityGroup), 0, 1);
    securityLayout->addWidget(processSecurityLengthEdit_, 0, 2);
    securityLayout->addWidget(new QLabel("lpSecurityDescriptor（安全描述符指针）", securityGroup), 0, 3);
    securityLayout->addWidget(processSecurityDescriptorEdit_, 0, 4);
    securityLayout->addWidget(processSecurityInheritCheck_, 0, 5);
    securityLayout->addWidget(useThreadSecurityCheck_, 1, 0);
    securityLayout->addWidget(new QLabel("nLength（结构体长度）", securityGroup), 1, 1);
    securityLayout->addWidget(threadSecurityLengthEdit_, 1, 2);
    securityLayout->addWidget(new QLabel("lpSecurityDescriptor（安全描述符指针）", securityGroup), 1, 3);
    securityLayout->addWidget(threadSecurityDescriptorEdit_, 1, 4);
    securityLayout->addWidget(threadSecurityInheritCheck_, 1, 5);
    contentLayout->addWidget(securityGroup);

    // 4) STARTUPINFOW with all fields.
    QGroupBox* startupGroup = new QGroupBox("STARTUPINFOW（全部字段）", contentWidget);
    applyTransparentContainerStyle(startupGroup);
    QGridLayout* startupLayout = new QGridLayout(startupGroup);
    startupLayout->setHorizontalSpacing(8);
    startupLayout->setVerticalSpacing(6);
    useStartupInfoCheck_ = new QCheckBox("启用 lpStartupInfo（启动信息结构体，取消则传 NULL）", startupGroup);
    useStartupInfoCheck_->setChecked(true);
    useStartupInfoCheck_->setToolTip("默认启用并传入有效 STARTUPINFOW；取消勾选只用于测试 NULL 参数失败路径。");

    siCbEdit_ = new QLineEdit("0", startupGroup);
    siReservedEdit_ = new QLineEdit(startupGroup);
    siDesktopEdit_ = new QLineEdit(startupGroup);
    siTitleEdit_ = new QLineEdit(startupGroup);
    siXEdit_ = new QLineEdit("0", startupGroup);
    siYEdit_ = new QLineEdit("0", startupGroup);
    siXSizeEdit_ = new QLineEdit("0", startupGroup);
    siYSizeEdit_ = new QLineEdit("0", startupGroup);
    siXCountCharsEdit_ = new QLineEdit("0", startupGroup);
    siYCountCharsEdit_ = new QLineEdit("0", startupGroup);
    siFillAttributeEdit_ = new QLineEdit("0x00000000", startupGroup);
    siFlagsEdit_ = new QLineEdit("0x00000000", startupGroup);
    siShowWindowEdit_ = new QLineEdit("0", startupGroup);
    siCbReserved2Edit_ = new QLineEdit("0", startupGroup);
    siReserved2PtrEdit_ = new QLineEdit("0", startupGroup);
    siStdInputEdit_ = new QLineEdit("0", startupGroup);
    siStdOutputEdit_ = new QLineEdit("0", startupGroup);
    siStdErrorEdit_ = new QLineEdit("0", startupGroup);

    const QList<QLineEdit*> kStartupEdits{
        siCbEdit_, siReservedEdit_, siDesktopEdit_, siTitleEdit_,
        siXEdit_, siYEdit_, siXSizeEdit_, siYSizeEdit_,
        siXCountCharsEdit_, siYCountCharsEdit_, siFillAttributeEdit_,
        siFlagsEdit_, siShowWindowEdit_, siCbReserved2Edit_,
        siReserved2PtrEdit_, siStdInputEdit_, siStdOutputEdit_, siStdErrorEdit_
    };
    for (QLineEdit* startupEdit : kStartupEdits)
    {
        startupEdit->setStyleSheet(kInputStyle);
    }

    int startupRow = 0;
    startupLayout->addWidget(useStartupInfoCheck_, startupRow++, 0, 1, 6);
    const auto kAddStartupField = [&startupLayout, &startupRow](const QString& labelText, QWidget* editorWidget, const int colOffset)
        {
            startupLayout->addWidget(new QLabel(labelText), startupRow, colOffset);
            startupLayout->addWidget(editorWidget, startupRow, colOffset + 1);
        };

    kAddStartupField("cb（结构体大小）", siCbEdit_, 0);
    kAddStartupField("lpReserved（保留字符串）", siReservedEdit_, 2);
    kAddStartupField("lpDesktop（目标桌面）", siDesktopEdit_, 4);
    ++startupRow;
    kAddStartupField("lpTitle（窗口标题）", siTitleEdit_, 0);
    kAddStartupField("dwX（窗口X坐标）", siXEdit_, 2);
    kAddStartupField("dwY（窗口Y坐标）", siYEdit_, 4);
    ++startupRow;
    kAddStartupField("dwXSize（窗口宽）", siXSizeEdit_, 0);
    kAddStartupField("dwYSize（窗口高）", siYSizeEdit_, 2);
    kAddStartupField("dwXCountChars（控制台宽）", siXCountCharsEdit_, 4);
    ++startupRow;
    kAddStartupField("dwYCountChars（控制台高）", siYCountCharsEdit_, 0);
    kAddStartupField("dwFillAttribute（控制台属性）", siFillAttributeEdit_, 2);
    kAddStartupField("dwFlags（启动标志）", siFlagsEdit_, 4);
    ++startupRow;
    kAddStartupField("wShowWindow（显示方式）", siShowWindowEdit_, 0);
    kAddStartupField("cbReserved2（保留2长度）", siCbReserved2Edit_, 2);
    kAddStartupField("lpReserved2（保留2指针）", siReserved2PtrEdit_, 4);
    ++startupRow;
    kAddStartupField("hStdInput（标准输入句柄）", siStdInputEdit_, 0);
    kAddStartupField("hStdOutput（标准输出句柄）", siStdOutputEdit_, 2);
    kAddStartupField("hStdError（标准错误句柄）", siStdErrorEdit_, 4);
    ++startupRow;

    // STARTUPINFO.dwFillAttribute bitmask selection area:
    // - Provides a visual combination of foreground/background colors and style bits.
    QGroupBox* startupFillAttrGroup = kBuildBitmaskCheckGroup(
        startupGroup,
        "STARTUPINFO.dwFillAttribute 位标志组合",
        kConsoleFillAttributeDefinitions,
        &startupFillAttributeChecks_);
    startupLayout->addWidget(startupFillAttrGroup, startupRow++, 0, 1, 6);

    // STARTUPINFO.dwFlags bit flag selection area:
    // - List STARTF_* flags.
    // - Combine directly via checkboxes and automatically populate the dwFlags input field.
    QGroupBox* startupFlagsGroup = kBuildBitmaskCheckGroup(
        startupGroup,
        "STARTUPINFO.dwFlags 位标志组合",
        kStartupInfoFlagDefinitions,
        &startupFlagChecks_);
    startupLayout->addWidget(startupFlagsGroup, startupRow++, 0, 1, 6);

    contentLayout->addWidget(startupGroup);

    // 5) All fields of PROCESS_INFORMATION.
    QGroupBox* processInfoGroup = new QGroupBox("PROCESS_INFORMATION（输出结构体，支持自定义初值）", contentWidget);
    applyTransparentContainerStyle(processInfoGroup);
    QGridLayout* processInfoLayout = new QGridLayout(processInfoGroup);
    processInfoLayout->setHorizontalSpacing(8);
    processInfoLayout->setVerticalSpacing(6);

    useProcessInfoCheck_ = new QCheckBox("启用 lpProcessInformation（进程信息输出结构，取消则传 NULL）", processInfoGroup);
    useProcessInfoCheck_->setChecked(true);
    useProcessInfoCheck_->setToolTip("默认启用并传入有效 PROCESS_INFORMATION；取消勾选只用于测试 NULL 参数失败路径。");
    piProcessHandleEdit_ = new QLineEdit("0", processInfoGroup);
    piThreadHandleEdit_ = new QLineEdit("0", processInfoGroup);
    piPidEdit_ = new QLineEdit("0", processInfoGroup);
    piTidEdit_ = new QLineEdit("0", processInfoGroup);
    piProcessHandleEdit_->setStyleSheet(kInputStyle);
    piThreadHandleEdit_->setStyleSheet(kInputStyle);
    piPidEdit_->setStyleSheet(kInputStyle);
    piTidEdit_->setStyleSheet(kInputStyle);

    processInfoLayout->addWidget(useProcessInfoCheck_, 0, 0, 1, 4);
    processInfoLayout->addWidget(new QLabel("hProcess（输出进程句柄）", processInfoGroup), 1, 0);
    processInfoLayout->addWidget(piProcessHandleEdit_, 1, 1);
    processInfoLayout->addWidget(new QLabel("hThread（输出线程句柄）", processInfoGroup), 1, 2);
    processInfoLayout->addWidget(piThreadHandleEdit_, 1, 3);
    processInfoLayout->addWidget(new QLabel("dwProcessId（输出PID）", processInfoGroup), 2, 0);
    processInfoLayout->addWidget(piPidEdit_, 2, 1);
    processInfoLayout->addWidget(new QLabel("dwThreadId（输出TID）", processInfoGroup), 2, 2);
    processInfoLayout->addWidget(piTidEdit_, 2, 3);
    contentLayout->addWidget(processInfoGroup);

    // 6) Token privilege editor.
    QGroupBox* tokenPrivilegeGroup = new QGroupBox("Token 特权调整（AdjustTokenPrivileges）", contentWidget);
    applyTransparentContainerStyle(tokenPrivilegeGroup);
    QVBoxLayout* tokenPrivilegeLayout = new QVBoxLayout(tokenPrivilegeGroup);
    const QStringList kPrivilegeNames = tokenPrivilegeNames();
    tokenPrivilegeTable_ = new ks::ui::VisibleTableWidget(kPrivilegeNames.size(), 2, tokenPrivilegeGroup);
    tokenPrivilegeTable_->setHorizontalHeaderLabels(QStringList{ "Privilege", "Action" });
    tokenPrivilegeTable_->horizontalHeader()->setStretchLastSection(true);
    tokenPrivilegeTable_->verticalHeader()->setVisible(false);
    tokenPrivilegeTable_->setSelectionMode(QAbstractItemView::NoSelection);
    tokenPrivilegeTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tokenPrivilegeTable_->setAlternatingRowColors(true);
    tokenPrivilegeTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(tokenPrivilegeTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            // Token privilege table copy menu:
            // - Input: privilege row selected via user right-click.
            // - Processing: Read the current text from the privilege cell and Action dropdown, then concatenate into TSV format.
            // - Return: Writes only to the clipboard; does not modify the token or call AdjustTokenPrivileges.
            if (tokenPrivilegeTable_ == nullptr)
            {
                return;
            }

            const int kRowIndex = tokenPrivilegeTable_->rowAt(localPosition.y());
            if (kRowIndex < 0 || kRowIndex >= tokenPrivilegeTable_->rowCount())
            {
                return;
            }

            tokenPrivilegeTable_->setCurrentCell(kRowIndex, 0);

            QMenu contextMenu(tokenPrivilegeTable_);
            contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
            QAction* copyRowAction = contextMenu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            if (contextMenu.exec(tokenPrivilegeTable_->viewport()->mapToGlobal(localPosition)) != copyRowAction)
            {
                return;
            }

            const QTableWidgetItem* privilegeItem = tokenPrivilegeTable_->item(kRowIndex, 0);
            const QComboBox* actionCombo = qobject_cast<QComboBox*>(tokenPrivilegeTable_->cellWidget(kRowIndex, 1));
            QStringList rowFields;
            rowFields.reserve(2);
            rowFields << (privilegeItem != nullptr ? privilegeItem->text() : QString());
            rowFields << (actionCombo != nullptr ? actionCombo->currentText() : QString());
            QApplication::clipboard()->setText(rowFields.join(QChar('\t')));
        });

    for (int row = 0; row < kPrivilegeNames.size(); ++row)
    {
        QTableWidgetItem* nameItem = new QTableWidgetItem(kPrivilegeNames.at(row));
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        tokenPrivilegeTable_->setItem(row, 0, nameItem);

        QComboBox* actionCombo = new QComboBox(tokenPrivilegeTable_);
        actionCombo->addItem("保持", static_cast<int>(ks::process::TokenPrivilegeAction::kKeep));
        actionCombo->addItem("启用", static_cast<int>(ks::process::TokenPrivilegeAction::kEnable));
        actionCombo->addItem("禁用", static_cast<int>(ks::process::TokenPrivilegeAction::kDisable));
        actionCombo->addItem("移除", static_cast<int>(ks::process::TokenPrivilegeAction::kRemove));
        actionCombo->setCurrentIndex(0);
        actionCombo->setStyleSheet(kComboStyle);
        tokenPrivilegeTable_->setCellWidget(row, 1, actionCombo);
    }

    QHBoxLayout* tokenActionLayout = new QHBoxLayout();
    applyTokenPrivilegeButton_ = new QPushButton("仅应用令牌调整（不创建）", tokenPrivilegeGroup);
    resetTokenPrivilegeButton_ = new QPushButton("重置全部特权动作为保持", tokenPrivilegeGroup);
    applyTokenPrivilegeButton_->setStyleSheet(kButtonStyle);
    resetTokenPrivilegeButton_->setStyleSheet(kButtonStyle);
    tokenActionLayout->addWidget(applyTokenPrivilegeButton_);
    tokenActionLayout->addWidget(resetTokenPrivilegeButton_);
    tokenActionLayout->addStretch(1);

    tokenPrivilegeLayout->addWidget(tokenPrivilegeTable_, 1);
    tokenPrivilegeLayout->addLayout(tokenActionLayout);
    contentLayout->addWidget(tokenPrivilegeGroup);

    // 7) Action buttons + output log.
    QGroupBox* actionGroup = new QGroupBox("执行与结果", contentWidget);
    applyTransparentContainerStyle(actionGroup);
    QVBoxLayout* actionLayout = new QVBoxLayout(actionGroup);
    QHBoxLayout* actionButtonLayout = new QHBoxLayout();
    launchProcessButton_ = new QPushButton("执行创建进程", actionGroup);
    resetCreateFormButton_ = new QPushButton("恢复默认配置", actionGroup);
    launchProcessButton_->setStyleSheet(kButtonStyle);
    resetCreateFormButton_->setStyleSheet(kButtonStyle);
    actionButtonLayout->addWidget(launchProcessButton_);
    actionButtonLayout->addWidget(resetCreateFormButton_);
    actionButtonLayout->addStretch(1);

    createResultOutput_ = new QTextEdit(actionGroup);
    createResultOutput_->setReadOnly(true);
    createResultOutput_->setMinimumHeight(140);
    createResultOutput_->setStyleSheet(kInputStyle);
    createResultOutput_->setPlaceholderText("这里显示请求参数摘要、API 返回结果和失败错误码。");

    actionLayout->addLayout(actionButtonLayout);
    actionLayout->addWidget(createResultOutput_, 1);
    contentLayout->addWidget(actionGroup, 1);

    // Default value supplement: the command line defaults to following applicationName.
    commandLineEdit_->setPlaceholderText("例如: \"C:\\Windows\\System32\\notepad.exe\" C:\\test.txt");
    applicationNameEdit_->setPlaceholderText("可执行文件路径（可为空并传 null）");
    currentDirectoryEdit_->setPlaceholderText("工作目录（可为空并传 null）");

    // Add Chinese explanatory tooltips for key CreateProcess parameters to help users understand the semantics of each field.
    applicationNameEdit_->setToolTip("lpApplicationName：应用程序路径。可为 null，由命令行首段决定可执行文件。");
    commandLineEdit_->setToolTip("lpCommandLine：完整命令行。可执行路径 + 参数，传入后可能被 API 就地修改。");
    currentDirectoryEdit_->setToolTip("lpCurrentDirectory：子进程初始工作目录。");
    environmentEditor_->setToolTip("lpEnvironment：环境变量块。每行 KEY=VALUE；禁用或启用但内容为空时传 null。取消 Unicode 时按系统 ANSI 代码页传递。");
    inheritHandleCheck_->setToolTip("bInheritHandles：是否继承父进程可继承句柄。");
    creationFlagsEdit_->setToolTip("dwCreationFlags：创建标志位掩码；可在下方复选框中逐位勾选组合。");
    useStartupInfoCheck_->setToolTip("lpStartupInfo：启动信息结构体，默认传入有效 STARTUPINFOW；取消勾选才传 null。");
    useProcessInfoCheck_->setToolTip("lpProcessInformation：默认传入有效输出结构接收 PID/TID；返回的句柄会在后端记录后立即关闭。");
    useProcessSecurityCheck_->setToolTip("lpProcessAttributes：进程对象安全属性。");
    useThreadSecurityCheck_->setToolTip("lpThreadAttributes：主线程对象安全属性。");
    siFlagsEdit_->setToolTip("STARTUPINFO.dwFlags：启动标志位掩码；可在下方 STARTF 复选框中组合。");
    siFillAttributeEdit_->setToolTip("STARTUPINFO.dwFillAttribute：控制台颜色/样式位；可在下方复选框组合。");
    tokenDesiredAccessEdit_->setToolTip("Token DesiredAccess：令牌访问掩码；可在下方复选框组合。");

    sideTabWidget_->addTab(createProcessPage_, blueTintedIcon(kIconStart), "创建进程");
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        createProcessPage_,
        QStringLiteral("process.tab.create"),
        QStringLiteral("创建进程"));
    refreshSideTabIconContrast();
    initializeCreateProcessConnections();
}

void ProcessDock::syncEditValueFromBitmaskChecks(
    QLineEdit* const valueEdit,
    const std::vector<QCheckBox*>* const checkBoxList)
{
    // Parameter validity check: return immediately if any parameter is null to avoid null pointer access.
    if (valueEdit == nullptr || checkBoxList == nullptr)
    {
        return;
    }

    // First calculate the 'all-known bitmask + checked bitmask' to preserve unknown bits
    // that the user manually entered but are not covered in the list when writing back.
    std::uint32_t knownMask = 0;
    std::uint32_t checkedMask = 0;
    for (QCheckBox* checkBox : *checkBoxList)
    {
        if (checkBox == nullptr)
        {
            continue;
        }
        bool convertOk = false;
        const std::uint32_t kFlagValue = static_cast<std::uint32_t>(
            checkBox->property("flagValue").toULongLong(&convertOk));
        if (!convertOk)
        {
            continue;
        }

        knownMask |= kFlagValue;
        if (checkBox->isChecked())
        {
            checkedMask |= kFlagValue;
        }
    }

    // Preserve unknown bits: avoid accidentally clearing manually entered bits when a known bit is checked.
    bool parseOk = false;
    const std::uint32_t kOriginalValue = parseUInt32WithDefault(valueEdit->text(), 0, &parseOk);
    const std::uint32_t kUnknownMask = parseOk ? (kOriginalValue & ~knownMask) : 0;
    const std::uint32_t kMergedValue = (checkedMask | kUnknownMask);

    const QString kMergedText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(kMergedValue), 8, 16, QChar('0'))
        .toUpper();
    if (valueEdit->text().compare(kMergedText, Qt::CaseInsensitive) == 0)
    {
        return;
    }

    // Block the textChanged signal to prevent recursive triggering from 'write-back text -> reverse sync'.
    const QSignalBlocker kBlocker(valueEdit);
    valueEdit->setText(kMergedText);
}

void ProcessDock::syncBitmaskChecksFromEditValue(
    QLineEdit* const valueEdit,
    const std::vector<QCheckBox*>* const checkBoxList,
    const QString& fieldDisplayName)
{
    // Parameter validity check: return immediately if any is null.
    if (valueEdit == nullptr || checkBoxList == nullptr)
    {
        return;
    }

    // On parse failure, only skip the sync checkbox; do not actively overwrite user input.
    bool parseOk = false;
    const std::uint32_t kEditValue = parseUInt32WithDefault(valueEdit->text(), 0, &parseOk);
    if (!parseOk)
    {
        Q_UNUSED(fieldDisplayName);
        return;
    }

    // Update check states item by item based on input values; use QSignalBlocker to prevent triggering toggled callbacks.
    for (QCheckBox* checkBox : *checkBoxList)
    {
        if (checkBox == nullptr)
        {
            continue;
        }

        bool convertOk = false;
        const std::uint32_t kFlagValue = static_cast<std::uint32_t>(
            checkBox->property("flagValue").toULongLong(&convertOk));
        if (!convertOk || kFlagValue == 0)
        {
            continue;
        }

        const bool kShouldChecked = ((kEditValue & kFlagValue) == kFlagValue);
        if (checkBox->isChecked() == kShouldChecked)
        {
            continue;
        }

        const QSignalBlocker kBlocker(checkBox);
        checkBox->setChecked(kShouldChecked);
    }
}

void ProcessDock::bindBitmaskEditor(
    QLineEdit* const valueEdit,
    std::vector<QCheckBox*>* const checkBoxList,
    const QString& fieldDisplayName)
{
    // Parameter validation: Do not bind if no input box or no checkbox list exists.
    if (valueEdit == nullptr || checkBoxList == nullptr)
    {
        return;
    }

    // Checkbox to text box: Recalculate the bit mask on every checkbox state change.
    for (QCheckBox* checkBox : *checkBoxList)
    {
        if (checkBox == nullptr)
        {
            continue;
        }

        connect(checkBox, &QCheckBox::toggled, this, [this, valueEdit, checkBoxList, fieldDisplayName](bool) {
            syncEditValueFromBitmaskChecks(valueEdit, checkBoxList);

            KLogEvent logEvent;
            dbg << logEvent
                << "[ProcessDock] 位标志勾选变更, field="
                << fieldDisplayName.toStdString()
                << ", value="
                << valueEdit->text().toStdString()
                << eol;
            });
    }

    // Text box to checkboxes: Support user input in decimal or 0x hexadecimal.
    connect(valueEdit, &QLineEdit::textChanged, this, [this, valueEdit, checkBoxList, fieldDisplayName](const QString&) {
        syncBitmaskChecksFromEditValue(valueEdit, checkBoxList, fieldDisplayName);
        });

    // Initial sync: Align default values and checkbox states when the page opens.
    syncBitmaskChecksFromEditValue(valueEdit, checkBoxList, fieldDisplayName);
}

bool ProcessDock::parseUnsignedText(const QString& text, std::uint64_t& valueOut)
{
    QString normalizedText = text.trimmed();
    if (normalizedText.isEmpty())
    {
        valueOut = 0;
        return true;
    }

    int numberBase = 10;
    if (normalizedText.startsWith("0x", Qt::CaseInsensitive))
    {
        normalizedText = normalizedText.mid(2);
        numberBase = 16;
    }
    else if (normalizedText.endsWith(QStringLiteral("h"), Qt::CaseInsensitive))
    {
        normalizedText.chop(1);
        numberBase = 16;
    }

    bool parseOk = false;
    const std::uint64_t kParsedValue = normalizedText.toULongLong(&parseOk, numberBase);
    if (!parseOk)
    {
        valueOut = 0;
        return false;
    }
    valueOut = kParsedValue;
    return true;
}

std::uint32_t ProcessDock::parseUInt32WithDefault(
    const QString& text,
    const std::uint32_t defaultValue,
    bool* const parseOkOut)
{
    std::uint64_t parsedValue = 0;
    if (!parseUnsignedText(text, parsedValue))
    {
        if (parseOkOut != nullptr)
        {
            *parseOkOut = false;
        }
        return defaultValue;
    }
    if (parsedValue > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
    {
        if (parseOkOut != nullptr)
        {
            *parseOkOut = false;
        }
        return defaultValue;
    }
    if (parseOkOut != nullptr)
    {
        *parseOkOut = true;
    }
    return static_cast<std::uint32_t>(parsedValue);
}

std::uint64_t ProcessDock::parseUInt64WithDefault(
    const QString& text,
    const std::uint64_t defaultValue,
    bool* const parseOkOut)
{
    std::uint64_t parsedValue = 0;
    if (!parseUnsignedText(text, parsedValue))
    {
        if (parseOkOut != nullptr)
        {
            *parseOkOut = false;
        }
        return defaultValue;
    }
    if (parseOkOut != nullptr)
    {
        *parseOkOut = true;
    }
    return parsedValue;
}
