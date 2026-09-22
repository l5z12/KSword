#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

void FileDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(6);

    // Top-level tabs changed to vertical layout: File Management + File Recovery.
    rootTabWidget_ = new QTabWidget(this);
    rootTabWidget_->setTabPosition(QTabWidget::West);
    rootTabWidget_->setDocumentMode(true);
    rootLayout_->addWidget(rootTabWidget_, 1);

    fileManagerPage_ = new QWidget(rootTabWidget_);
    QVBoxLayout* managerLayout = new QVBoxLayout(fileManagerPage_);
    managerLayout->setContentsMargins(0, 0, 0, 0);
    managerLayout->setSpacing(0);

    mainSplitter_ = new QSplitter(Qt::Horizontal, fileManagerPage_);
    // The divider between the two columns in file management must be determined by the user and the available viewport.
    // - Do not let long filenames or header width changes in one file list squeeze the other list out;
    // - Sub-panels are non-collapsible to prevent one side from being swallowed by its minimum content width in extremely narrow windows.
    mainSplitter_->setChildrenCollapsible(false);
    managerLayout->addWidget(mainSplitter_, 1);

    initializePanel(leftPanel_, QStringLiteral("左侧面板"));
    initializePanel(rightPanel_, QStringLiteral("右侧面板"));
    mainSplitter_->addWidget(leftPanel_.rootWidget);
    mainSplitter_->addWidget(rightPanel_.rootWidget);
    mainSplitter_->setStretchFactor(0, 1);
    mainSplitter_->setStretchFactor(1, 1);

    rootTabWidget_->addTab(fileManagerPage_, QStringLiteral("文件管理"));
    initializeRecoveryPage();
    if (fileRecoveryPage_ != nullptr)
    {
        rootTabWidget_->addTab(fileRecoveryPage_, QStringLiteral("文件恢复"));
    }
    initializeIrpBuilderPage();
    if (irpBuilderPage_ != nullptr)
    {
        rootTabWidget_->addTab(irpBuilderPage_, QStringLiteral("IRP 构造"));
    }
    ks::i18n::LanguageManager::instance().bindTab(
        rootTabWidget_, fileManagerPage_, QStringLiteral("file.tab.manager"), QStringLiteral("文件管理"));
    if (fileRecoveryPage_ != nullptr)
    {
        ks::i18n::LanguageManager::instance().bindTab(
            rootTabWidget_, fileRecoveryPage_, QStringLiteral("file.tab.recovery"), QStringLiteral("文件恢复"));
    }
    if (irpBuilderPage_ != nullptr)
    {
        ks::i18n::LanguageManager::instance().bindTab(
            rootTabWidget_, irpBuilderPage_, QStringLiteral("file.tab.irpbuilder"), QStringLiteral("IRP 构造"));
    }
}

void FileDock::initializePanel(FilePanelWidgets& panel, const QString& titleText)
{
    // Record the panel name; subsequent logs will uniformly include "left/right" labels for easier troubleshooting and localization.
    panel.panelNameText = titleText;

    {
        KLogEvent event;
        info << event
            << "[FileDock] 开始初始化面板, panel="
            << titleText.toStdString()
            << eol;
    }

    panel.rootWidget = new QWidget(mainSplitter_);
    // File panel root container is horizontally collapsible:
    // - Input: Current width allocated by QSplitter;
    // - Processing: Ignore the dynamic sizeHint of the internal file list to prevent the splitter from shifting when a file or directory is selected/loaded.
    // - Return: No return value; actual layout is still managed by rootLayout.
    panel.rootWidget->setMinimumWidth(0);
    panel.rootWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    panel.rootLayout = new QVBoxLayout(panel.rootWidget);
    panel.rootLayout->setContentsMargins(4, 4, 4, 4);
    panel.rootLayout->setSpacing(4);

    // Title bar: distinguish between left and right panels.
    QLabel* titleLabel = new QLabel(titleText, panel.rootWidget);
    titleLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(ksword_theme::kPrimaryBlueHex));
    panel.rootLayout->addWidget(titleLabel, 0);

    panel.navWidget = new QWidget(panel.rootWidget);
    panel.navLayout = new QHBoxLayout(panel.navWidget);
    panel.navLayout->setContentsMargins(0, 0, 0, 0);
    panel.navLayout->setSpacing(4);

    panel.backButton = new QPushButton(QIcon(":/Icon/file_nav_back.svg"), QString(), panel.navWidget);
    panel.backButton->setToolTip(QStringLiteral("后退"));
    panel.backButton->setStyleSheet(buildBlueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(panel.backButton);

    panel.forwardButton = new QPushButton(QIcon(":/Icon/file_nav_forward.svg"), QString(), panel.navWidget);
    panel.forwardButton->setToolTip(QStringLiteral("前进"));
    panel.forwardButton->setStyleSheet(buildBlueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(panel.forwardButton);

    panel.upButton = new QPushButton(QIcon(":/Icon/file_nav_up.svg"), QString(), panel.navWidget);
    panel.upButton->setToolTip(QStringLiteral("上级目录"));
    panel.upButton->setStyleSheet(buildBlueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(panel.upButton);

    panel.refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), panel.navWidget);
    panel.refreshButton->setToolTip(QStringLiteral("刷新当前目录"));
    panel.refreshButton->setStyleSheet(buildBlueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(panel.refreshButton);

    // Address area uses a 'stacked widget':
    // - Breadcrumb page: displayed by default;
    // - Edit page: switch after clicking the blank hot zone; press Enter to navigate.
    panel.pathStack = new QStackedWidget(panel.navWidget);
    panel.pathStack->setMinimumWidth(260);

    panel.breadcrumbWidget = new QWidget(panel.pathStack);
    panel.breadcrumbWidget->setObjectName(QStringLiteral("EmbeddedBreadcrumbWidget"));
    panel.breadcrumbWidget->setStyleSheet(QStringLiteral(
        "QWidget#EmbeddedBreadcrumbWidget{"
        "  border:1px solid %1;"
        "  border-radius:3px;"
        "  background:%2;"
        "}").arg(ksword_theme::borderHex(), ksword_theme::surfaceHex()));
    panel.breadcrumbLayout = new QHBoxLayout(panel.breadcrumbWidget);
    panel.breadcrumbLayout->setContentsMargins(6, 2, 6, 2);
    panel.breadcrumbLayout->setSpacing(2);

    panel.pathEdit = new QLineEdit(panel.pathStack);
    panel.pathEdit->setPlaceholderText(QStringLiteral("输入路径后按回车跳转"));
    panel.pathEdit->setStyleSheet(buildBlueInputStyle());

    // Drive dropdown:
    // - Fixed on the right side of the address bar to directly jump to the root directory of any drive.
    // Resolves the issue where the default path experience is biased toward the current system drive.
    panel.driveCombo = new QComboBox(panel.navWidget);
    panel.driveCombo->setStyleSheet(buildBlueInputStyle());
    panel.driveCombo->setMinimumWidth(92);
    panel.driveCombo->setMaximumWidth(140);
    panel.driveCombo->setToolTip(QStringLiteral("快速跳转到任意驱动器根目录"));

    panel.pathStack->addWidget(panel.breadcrumbWidget);
    panel.pathStack->addWidget(panel.pathEdit);

    panel.navLayout->addWidget(panel.backButton);
    panel.navLayout->addWidget(panel.forwardButton);
    panel.navLayout->addWidget(panel.upButton);
    panel.navLayout->addWidget(panel.refreshButton);
    panel.navLayout->addWidget(panel.pathStack, 1);
    panel.navLayout->addWidget(panel.driveCombo, 0);
    panel.rootLayout->addWidget(panel.navWidget, 0);

    panel.toolWidget = new QWidget(panel.rootWidget);
    panel.toolLayout = new QHBoxLayout(panel.toolWidget);
    panel.toolLayout->setContentsMargins(0, 0, 0, 0);
    panel.toolLayout->setSpacing(4);

    panel.viewModeCombo = new QComboBox(panel.toolWidget);
    panel.viewModeCombo->setStyleSheet(buildBlueInputStyle());
    panel.viewModeCombo->addItems(QStringList{ QStringLiteral("图标视图"), QStringLiteral("列表视图"), QStringLiteral("详情视图"), QStringLiteral("树形视图") });
    panel.viewModeCombo->setToolTip(QStringLiteral("切换文件显示模式，默认使用详情视图"));
    panel.viewModeCombo->setCurrentIndex(2);

    panel.showSystemCheck = new QCheckBox(QStringLiteral("系统"), panel.toolWidget);
    panel.showHiddenCheck = new QCheckBox(QStringLiteral("隐藏"), panel.toolWidget);
    panel.showSystemCheck->setChecked(true);
    panel.showHiddenCheck->setChecked(true);

    panel.sortModeCombo = new QComboBox(panel.toolWidget);
    panel.sortModeCombo->setStyleSheet(buildBlueInputStyle());
    panel.sortModeCombo->addItems(QStringList{ QStringLiteral("名称"), QStringLiteral("大小"), QStringLiteral("修改时间"), QStringLiteral("类型") });

    panel.readModeCombo = new QComboBox(panel.toolWidget);
    panel.readModeCombo->setStyleSheet(buildBlueInputStyle());
    panel.readModeCombo->addItems(QStringList{
        QStringLiteral("Windows API"),
        QStringLiteral("手动解析文件系统"),
        QStringLiteral("R0 驱动解析"),
        QStringLiteral("作为NTFS解析"),
        QStringLiteral("作为FAT32解析"),
        QStringLiteral("作为exFAT解析"),
        QStringLiteral("作为MFT解析"),
        QStringLiteral("R0 IRP 解析") });
    // Install an event filter to consume wheel events: see the explanation in eventFilter.
    panel.readModeCombo->installEventFilter(this);
    panel.readModeCombo->setFocusPolicy(Qt::StrongFocus);
    panel.readModeCombo->setToolTip(QStringLiteral(
        "切换目录读取方式：Windows API、R3 原始卷手动解析、"
        "R0 驱动目录解析，强制按 NTFS/FAT32/exFAT 解析，\n"
        "作为MFT解析（仅 NTFS：卷偏移直读 $MFT，禁用一切 WinAPI/FSCTL 回退），\n"
        "R0 IRP 解析（内核自建 IRP 把目录查询直发基础文件系统设备，绕过过滤层；\n"
        "打开阶段仍走正常路径，只在 CREATE 上做的拦截发现不了）。\n"
        "后两种会与常规视图对照，把只有绕过路径可见的条目标为疑似隐藏项。"));

    panel.filterEdit = new QLineEdit(panel.toolWidget);
    panel.filterEdit->setPlaceholderText(QStringLiteral("快速过滤"));
    panel.filterEdit->setStyleSheet(buildBlueInputStyle());

    panel.toolLayout->addWidget(panel.viewModeCombo, 0);
    panel.toolLayout->addWidget(panel.showSystemCheck, 0);
    panel.toolLayout->addWidget(panel.showHiddenCheck, 0);
    panel.toolLayout->addWidget(panel.sortModeCombo, 0);
    panel.toolLayout->addWidget(panel.readModeCombo, 0);
    panel.toolLayout->addWidget(panel.filterEdit, 1);
    panel.rootLayout->addWidget(panel.toolWidget, 0);

    panel.fsModel = new ReparseAwareFileSystemModel(panel.rootWidget);
    panel.fsModel->setReadOnly(false);
    panel.fsModel->setResolveSymlinks(true);
    panel.fsModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
    // Disable the 'gray but do not hide' behavior to ensure name filtering strictly shows only matching items.
    panel.fsModel->setNameFilterDisables(false);

    panel.proxyModel = new QSortFilterProxyModel(panel.rootWidget);
    panel.proxyModel->setSourceModel(panel.fsModel);
    panel.proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    panel.proxyModel->setFilterKeyColumn(0);

    panel.manualModel = new QStandardItemModel(panel.rootWidget);
    panel.manualModel->setColumnCount(static_cast<int>(ManualModelColumn::kCount));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::kName), Qt::Horizontal, QStringLiteral("名称"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::kSize), Qt::Horizontal, QStringLiteral("大小"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::kType), Qt::Horizontal, QStringLiteral("类型"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::kModifiedTime), Qt::Horizontal, QStringLiteral("修改时间"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::kFullPath), Qt::Horizontal, QStringLiteral("完整路径"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::kIsDirectory), Qt::Horizontal, QStringLiteral("目录标记"));

    panel.manualProxyModel = new QSortFilterProxyModel(panel.rootWidget);
    panel.manualProxyModel->setSourceModel(panel.manualModel);
    panel.manualProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    panel.manualProxyModel->setFilterKeyColumn(static_cast<int>(ManualModelColumn::kName));

    panel.fileViewStack = new QStackedWidget(panel.rootWidget);
    panel.fileViewStack->setMinimumWidth(0);
    panel.fileViewStack->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);

    panel.compactFileView = new QListView(panel.fileViewStack);
    panel.compactFileView->setMinimumWidth(0);
    panel.compactFileView->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    panel.compactFileView->setModel(panel.proxyModel);
    panel.compactFileView->setModelColumn(0);
    panel.compactFileView->setEditTriggers(QAbstractItemView::EditKeyPressed);
    panel.compactFileView->setContextMenuPolicy(Qt::CustomContextMenu);
    panel.compactFileView->viewport()->installEventFilter(this);
    panel.compactFileView->setDragEnabled(true);
    panel.compactFileView->setAcceptDrops(true);
    panel.compactFileView->setDropIndicatorShown(true);
    panel.compactFileView->setDragDropMode(QAbstractItemView::DragDrop);
    panel.compactFileView->setDefaultDropAction(Qt::MoveAction);
    panel.compactFileView->setDragDropOverwriteMode(false);

    panel.fileView = new QTreeView(panel.fileViewStack);
    // The file list manages column widths and scroll behavior internally within FileDock:
    // - Disable global TableColumnAutoFit to prevent QFileSystemModel from recalculating column widths for certain long names/type columns during selection or loading.
    // - Use Ignored for horizontal size policy to ensure QTreeView header/content width does not expand QSplitter child panels in reverse.
    panel.fileView->setMinimumWidth(0);
    panel.fileView->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    ks::ui::setTableColumnAutoFitEnabled(panel.fileView, false);
    panel.fileView->setModel(panel.proxyModel);
    panel.fileView->setEditTriggers(QAbstractItemView::EditKeyPressed);
    panel.fileView->setContextMenuPolicy(Qt::CustomContextMenu);
    panel.fileView->viewport()->installEventFilter(this);
    panel.fileView->setSortingEnabled(true);
    panel.fileView->setDragEnabled(true);
    panel.fileView->setAcceptDrops(true);
    panel.fileView->setDropIndicatorShown(true);
    panel.fileView->setDragDropMode(QAbstractItemView::DragDrop);
    panel.fileView->setDefaultDropAction(Qt::MoveAction);
    panel.fileView->setDragDropOverwriteMode(false);
    panel.fileView->header()->setStretchLastSection(false);
    panel.fileView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    panel.fileView->header()->setStyleSheet(QStringLiteral("QHeaderView::section{color:%1;}").arg(ksword_theme::kPrimaryBlueHex));
    // Both controls share the same selection model to maintain consistent multi-selection, current item, and right-click actions after switching views.
    QItemSelectionModel* compactSelectionModel = panel.compactFileView->selectionModel();
    panel.compactFileView->setSelectionModel(panel.fileView->selectionModel());
    if (compactSelectionModel != nullptr && compactSelectionModel != panel.fileView->selectionModel())
    {
        compactSelectionModel->deleteLater();
    }
    configureFileViewSelection(panel);
    panel.fileViewStack->addWidget(panel.compactFileView);
    panel.fileViewStack->addWidget(panel.fileView);
    panel.fileViewStack->setCurrentWidget(panel.fileView);
    panel.rootLayout->addWidget(panel.fileViewStack, 1);

    panel.statusBar = new QStatusBar(panel.rootWidget);
    panel.pathStatusLabel = new QLabel(QStringLiteral("路径: -"), panel.statusBar);
    panel.selectionStatusLabel = new QLabel(QStringLiteral("选中: 0"), panel.statusBar);
    panel.diskStatusLabel = new QLabel(QStringLiteral("磁盘: -"), panel.statusBar);
    panel.parserStatusLabel = new QLabel(QStringLiteral("解析器: Windows API"), panel.statusBar);
    panel.statusBar->addWidget(panel.pathStatusLabel, 1);
    panel.statusBar->addPermanentWidget(panel.parserStatusLabel, 0);
    panel.statusBar->addPermanentWidget(panel.selectionStatusLabel, 0);
    panel.statusBar->addPermanentWidget(panel.diskStatusLabel, 0);
    panel.rootLayout->addWidget(panel.statusBar, 0);

    // initialize read mode and synchronize the model.
    applyReadModeToPanel(panel);
    initializeConnections(panel);
    refreshDriveCombo(panel);

    // Default to the system root directory.
    const QString kDefaultPath = QDir::rootPath();
    navigateToPath(panel, kDefaultPath, true);

    {
        KLogEvent event;
        info << event
            << "[FileDock] 面板初始化完成, panel="
            << panel.panelNameText.toStdString()
            << ", defaultPath="
            << QDir::toNativeSeparators(kDefaultPath).toStdString()
            << eol;
    }
}

void FileDock::initializeConnections(FilePanelWidgets& panel)
{
    // Back button: Revert to the previous history path.
    connect(panel.backButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.historyIndex <= 0 || panel.history.empty())
        {
            return;
        }

        panel.historyIndex -= 1;
        const QString kTargetPath = panel.history.at(static_cast<std::size_t>(panel.historyIndex));
        {
            KLogEvent event;
            info << event
                << "[FileDock] 历史后退, panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(kTargetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, kTargetPath, false);
    });

    // Forward button: navigate to the next path in history.
    connect(panel.forwardButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.history.empty())
        {
            return;
        }
        const int kNextIndex = panel.historyIndex + 1;
        if (kNextIndex < 0 || kNextIndex >= static_cast<int>(panel.history.size()))
        {
            return;
        }

        panel.historyIndex = kNextIndex;
        const QString kTargetPath = panel.history.at(static_cast<std::size_t>(panel.historyIndex));
        {
            KLogEvent event;
            info << event
                << "[FileDock] 历史前进, panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(kTargetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, kTargetPath, false);
    });

    // Parent directory button: Switch from the current directory to the parent.
    connect(panel.upButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.currentPath.isEmpty())
        {
            return;
        }

        QDir currentDir(panel.currentPath);
        if (!currentDir.cdUp())
        {
            return;
        }

        {
            KLogEvent event;
            info << event
                << "[FileDock] 上级目录跳转, panel="
                << panel.panelNameText.toStdString()
                << ", from="
                << QDir::toNativeSeparators(panel.currentPath).toStdString()
                << ", to="
                << QDir::toNativeSeparators(currentDir.absolutePath()).toStdString()
                << eol;
        }
        navigateToPath(panel, currentDir.absolutePath(), true);
    });

    // Refresh button: reload the current directory.
    connect(panel.refreshButton, &QPushButton::clicked, this, [this, &panel]() {
        KLogEvent event;
        info << event
            << "[FileDock] 手动刷新目录, panel="
            << panel.panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
        refreshPanel(panel);
    });

    // Enter pressed in the address bar: navigate to the input path and automatically switch back to breadcrumb display mode.
    connect(panel.pathEdit, &QLineEdit::returnPressed, this, [this, &panel]() {
        const QString kTargetPath = panel.pathEdit->text().trimmed();
        {
            KLogEvent event;
            info << event
                << "[FileDock] 地址栏回车导航, panel="
                << panel.panelNameText.toStdString()
                << ", input="
                << QDir::toNativeSeparators(kTargetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, kTargetPath, true);
        setPathEditMode(panel, false);
    });

    // Drive combo box switch: directly jump to the root directory of the corresponding drive letter.
    connect(panel.driveCombo, &QComboBox::currentIndexChanged, this, [this, &panel](const int indexValue) {
        if (indexValue < 0)
        {
            return;
        }

        const QString kTargetRootPath = panel.driveCombo->itemData(indexValue).toString();
        if (kTargetRootPath.trimmed().isEmpty())
        {
            return;
        }

        if (panel.currentPath.compare(kTargetRootPath, Qt::CaseInsensitive) == 0)
        {
            return;
        }

        KLogEvent event;
        info << event
            << "[FileDock] 驱动器下拉框跳转, panel="
            << panel.panelNameText.toStdString()
            << ", targetRoot="
            << QDir::toNativeSeparators(kTargetRootPath).toStdString()
            << eol;
        navigateToPath(panel, kTargetRootPath, true);
    });

    // If editing finishes without pressing Enter: revert to the breadcrumb trail to avoid staying in text editing mode for too long.
    connect(panel.pathEdit, &QLineEdit::editingFinished, this, [this, &panel]() {
        if (!panel.pathEditMode)
        {
            return;
        }
        if (panel.pathEdit->hasFocus())
        {
            return;
        }
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        setPathEditMode(panel, false);
    });

    // ESC: cancel path editing and restore current path text.
    QShortcut* cancelPathEditShortcut = new QShortcut(QKeySequence(Qt::Key_Escape), panel.pathEdit);
    connect(cancelPathEditShortcut, &QShortcut::activated, this, [this, &panel]() {
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        setPathEditMode(panel, false);
        KLogEvent event;
        dbg << event
            << "[FileDock] 取消路径编辑, panel="
            << panel.panelNameText.toStdString()
            << eol;
    });

    // View switch: Adjust column display and icon size based on the current mode.
    connect(panel.viewModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        applyPanelFilterAndSort(panel);
    });

    // Toggle visibility of system files.
    connect(panel.showSystemCheck, &QCheckBox::toggled, this, [this, &panel](bool) {
        applyPanelFilterAndSort(panel);
    });

    // Toggle visibility of hidden files.
    connect(panel.showHiddenCheck, &QCheckBox::toggled, this, [this, &panel](bool) {
        applyPanelFilterAndSort(panel);
    });

    // Sort mode switch.
    connect(panel.sortModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        applyPanelFilterAndSort(panel);
    });

    // Switch read mode: real-time toggle between Windows API and manual parsing model.
    connect(panel.readModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        panel.manualLoadedPath.clear();
        panel.manualSourceDetail.clear();
        panel.manualResultPartial = false;
        if (panel.manualModel != nullptr)
        {
            panel.manualModel->setRowCount(0);
        }
        applyReadModeToPanel(panel);
        refreshPanel(panel);
    });

    // Fast filter input: update proxy model in real time.
    connect(panel.filterEdit, &QLineEdit::textChanged, this, [this, &panel](const QString&) {
        applyPanelFilterAndSort(panel);
    });

    // Double-click to open: directories enter, files open with the system default program.
    connect(panel.fileView, &QTreeView::doubleClicked, this, [this, &panel](const QModelIndex& proxyIndex) {
        if (!proxyIndex.isValid())
        {
            return;
        }

        const QString kPath = currentIndexPath(panel);
        if (kPath.isEmpty())
        {
            return;
        }

        QFileInfo info(kPath);
        if (info.isDir())
        {
            navigateToPath(panel, kPath, true);
            return;
        }

        QDesktopServices::openUrl(QUrl::fromLocalFile(kPath));
    });
    connect(panel.compactFileView, &QListView::doubleClicked, this, [this, &panel](const QModelIndex& proxyIndex) {
        if (!proxyIndex.isValid())
        {
            return;
        }

        const QString kPath = currentIndexPath(panel);
        if (kPath.isEmpty())
        {
            return;
        }

        QFileInfo info(kPath);
        if (info.isDir())
        {
            navigateToPath(panel, kPath, true);
            return;
        }

        QDesktopServices::openUrl(QUrl::fromLocalFile(kPath));
    });

    connect(panel.compactFileView, &QListView::customContextMenuRequested, this, [this, &panel](const QPoint& pos) {
        showPanelContextMenu(panel, pos);
    });


    // Right-click menu entry.
    connect(panel.fileView, &QTreeView::customContextMenuRequested, this, [this, &panel](const QPoint& pos) {
        showPanelContextMenu(panel, pos);
    });

    // Refresh the status bar when the selection changes.
    connect(panel.fileView->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this, &panel](const QItemSelection&, const QItemSelection&) {
        updatePanelStatus(panel);
    });

    // Update the status bar after the model directory loads, indicating that the current directory data is visible.
    connect(panel.fsModel, &QFileSystemModel::directoryLoaded, this, [this, &panel](const QString&) {
        updatePanelStatus(panel);
    });

    // Alt+D: quickly switch to path edit mode, behavior consistent with common file managers.
    QShortcut* editPathShortcut = new QShortcut(QKeySequence(Qt::ALT | Qt::Key_D), panel.rootWidget);
    connect(editPathShortcut, &QShortcut::activated, this, [this, &panel]() {
        setPathEditMode(panel, true);
    });

    // Enter shortcut: open selected item.
    QShortcut* openShortcut = new QShortcut(QKeySequence(Qt::Key_Return), panel.fileView);
    openShortcut->setContext(Qt::WidgetShortcut);
    connect(openShortcut, &QShortcut::activated, this, [this, &panel]() {
        openSelectedItems(panel);
    });
    QShortcut* openShortcutEnter = new QShortcut(QKeySequence(Qt::Key_Enter), panel.fileView);
    openShortcutEnter->setContext(Qt::WidgetShortcut);
    connect(openShortcutEnter, &QShortcut::activated, this, [this, &panel]() {
        openSelectedItems(panel);
    });

    // F2 rename shortcut.
    QShortcut* renameShortcut = new QShortcut(QKeySequence(Qt::Key_F2), panel.fileView);
    renameShortcut->setContext(Qt::WidgetShortcut);
    connect(renameShortcut, &QShortcut::activated, this, [this, &panel]() {
        renameSelectedItem(panel);
    });

    // Delete shortcut.
    QShortcut* deleteShortcut = new QShortcut(QKeySequence(Qt::Key_Delete), panel.fileView);
    deleteShortcut->setContext(Qt::WidgetShortcut);
    connect(deleteShortcut, &QShortcut::activated, this, [this, &panel]() {
        deleteSelectedItem(panel);
    });

    // Ctrl+C must remain "side-effect free": in File Explorer, it only places content into the clipboard; actual disk
    // writes occur only upon Ctrl+V. Previously, this was bound to "immediately copy to the opposite panel," writing to
    // the target directory without confirmation upon pressing the key, which completely contradicts user expectations.
    // Ctrl+X directly moved source files. Now changed to copy the selected path to the clipboard and unbind Ctrl+X.
    // Cross-panel transfers are still available via the right-click menu's 'Copy to opposite panel'
    // or 'Move to opposite panel' options, where the names clearly describe the action and target.
    QShortcut* copyShortcut = new QShortcut(QKeySequence::Copy, panel.fileView);
    copyShortcut->setContext(Qt::WidgetShortcut);
    connect(copyShortcut, &QShortcut::activated, this, [this, &panel]() {
        copySelectedItemPath(panel);
    });

    // QListView uses its own WidgetShortcut to prevent Enter/Delete keys from propagating to the address bar and filter input box.
    const auto kBindCompactShortcut =
        [this, &panel](const QKeySequence& keySequence, const auto& handler)
        {
            QShortcut* shortcut = new QShortcut(keySequence, panel.compactFileView);
            shortcut->setContext(Qt::WidgetShortcut);
            connect(shortcut, &QShortcut::activated, this, handler);
        };
    kBindCompactShortcut(QKeySequence(Qt::Key_Return), [this, &panel]() { openSelectedItems(panel); });
    kBindCompactShortcut(QKeySequence(Qt::Key_Enter), [this, &panel]() { openSelectedItems(panel); });
    kBindCompactShortcut(QKeySequence(Qt::Key_F2), [this, &panel]() { renameSelectedItem(panel); });
    kBindCompactShortcut(QKeySequence(Qt::Key_Delete), [this, &panel]() { deleteSelectedItem(panel); });
    kBindCompactShortcut(QKeySequence::Copy, [this, &panel]() { copySelectedItemPath(panel); });

}
