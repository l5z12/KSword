#include "StartupDock.Internal.h"

#include <QElapsedTimer>
#include "../ui/VisibleTableWidget.h"
#include "../internationalization/LanguageManager.h"

#include <QColor>
#include <QPair>

using namespace startup_dock_detail;

namespace startup_dock_detail
{
    QString startupText(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }

    QStringList startupTableHeaders()
    {
        return {
            startupText("startup.header.name", QStringLiteral("名称")),
            startupText("startup.header.publisher", QStringLiteral("发布者")),
            startupText("startup.header.image_path", QStringLiteral("映像路径")),
            startupText("startup.header.command", QStringLiteral("命令")),
            startupText("startup.header.location", QStringLiteral("来源位置")),
            startupText("startup.header.user", QStringLiteral("用户")),
            startupText("startup.header.status", QStringLiteral("状态")),
            startupText("startup.header.type", QStringLiteral("类型")),
            startupText("startup.header.detail", QStringLiteral("详情"))
        };
    }
}

namespace
{
    // kToolbarIconSize:
    // - Standardize the icon button size at the top of the startup items page.
    constexpr QSize kToolbarIconSize(16, 16);

    // kUntrustedRowHighlightColor:
    // - Define background color for the entire row of untrusted startup entries.
    // - Use semi-transparent red to ensure risk visibility without obscuring text;
    const QColor kUntrustedRowHighlightColor(255, 64, 64, 76);

    // isUntrustedStartupEntry:
    // - Check if a startup entry belongs to an untrusted target.
    // - Invocation: Pass the StartupEntry before row rendering.
    // - Input parameter entry: startup entry data currently being rendered;
    // - Returns true to highlight the item in red as a risk; false to keep the default style.
    bool isUntrustedStartupEntry(const StartupDock::StartupEntry& entry)
    {
        return entry.publisherText.contains(QStringLiteral("(Untrusted)"), Qt::CaseInsensitive)
            || (entry.category == StartupDock::StartupCategory::kImageHijack
                && entry.backendEntry.riskLevel == ks::startup::StartupRiskLevel::kCritical);
    }

    // createStartupTable:
    // - Create a startup items table with a unified column structure;
    // - Reused by six category pages.
    QTableWidget* createStartupTable(QWidget* parentWidget)
    {
        QTableWidget* tableWidget = new ks::ui::VisibleTableWidget(parentWidget);
        tableWidget->setColumnCount(StartupDock::toStartupColumn(StartupDock::StartupColumn::kCount));
        tableWidget->setHorizontalHeaderLabels(startupTableHeaders());
        tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        tableWidget->setWordWrap(false);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        tableWidget->horizontalHeader()->setSectionResizeMode(
            StartupDock::toStartupColumn(StartupDock::StartupColumn::kDetail),
            QHeaderView::Stretch);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kName), 180);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kPublisher), 170);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kImagePath), 260);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kCommand), 300);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kLocation), 260);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kUser), 120);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kEnabled), 70);
        tableWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kType), 110);
        return tableWidget;
    }

    // createSingleTablePage:
    // - Create a tab container that holds only a single table.
    QWidget* createSingleTablePage(QTableWidget** tableOut, QWidget* parentWidget)
    {
        QWidget* pageWidget = new QWidget(parentWidget);
        QVBoxLayout* pageLayout = new QVBoxLayout(pageWidget);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(4);
        QTableWidget* tableWidget = createStartupTable(pageWidget);
        pageLayout->addWidget(tableWidget, 1);
        if (tableOut != nullptr)
        {
            *tableOut = tableWidget;
        }
        return pageWidget;
    }

    // createStartupTree:
    // - Create a tree control dedicated to the advanced registry page;
    // - Level-1 nodes correspond to registry locations; level-2 nodes correspond to specific startup items.
    QTreeWidget* createStartupTree(QWidget* parentWidget)
    {
        QTreeWidget* treeWidget = new QTreeWidget(parentWidget);
        treeWidget->setColumnCount(StartupDock::toStartupColumn(StartupDock::StartupColumn::kCount));
        treeWidget->setHeaderLabels(startupTableHeaders());
        treeWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        treeWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        treeWidget->setWordWrap(false);
        treeWidget->setRootIsDecorated(true);
        treeWidget->setAlternatingRowColors(true);
        treeWidget->setUniformRowHeights(true);
        treeWidget->header()->setSectionResizeMode(QHeaderView::Interactive);
        treeWidget->header()->setSectionResizeMode(
            StartupDock::toStartupColumn(StartupDock::StartupColumn::kDetail),
            QHeaderView::Stretch);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kName), 260);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kPublisher), 170);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kImagePath), 260);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kCommand), 280);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kLocation), 280);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kUser), 120);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kEnabled), 70);
        treeWidget->setColumnWidth(StartupDock::toStartupColumn(StartupDock::StartupColumn::kType), 130);
        return treeWidget;
    }

    // createRegistryTreePage:
    // - Create the advanced registry page.
    // - The page's unique main control is a tree grouped by registry location.
    QWidget* createRegistryTreePage(QTreeWidget** treeOut, QWidget* parentWidget)
    {
        QWidget* pageWidget = new QWidget(parentWidget);
        QVBoxLayout* pageLayout = new QVBoxLayout(pageWidget);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(4);
        QTreeWidget* treeWidget = createStartupTree(pageWidget);
        pageLayout->addWidget(treeWidget, 1);
        if (treeOut != nullptr)
        {
            *treeOut = treeWidget;
        }
        return pageWidget;
    }
}

void StartupDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(6);

    initializeToolbar();
    initializeTabs();

    tableRebuildTimer_ = new QTimer(this);
    tableRebuildTimer_->setSingleShot(true);
    connect(
        tableRebuildTimer_,
        &QTimer::timeout,
        this,
        &StartupDock::continueIncrementalTableRebuild);

    rootLayout_->addWidget(toolbarWidget_, 0);
    rootLayout_->addWidget(sideTabWidget_, 1);
}

void StartupDock::initializeToolbar()
{
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    toolbarWidget_ = new QWidget(this);
    toolbarLayout_ = new QHBoxLayout(toolbarWidget_);
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    refreshButton_ = new QPushButton(toolbarWidget_);
    refreshButton_->setIcon(createBlueIcon(":/Icon/process_refresh.svg", kToolbarIconSize));
    languageManager.bindToolTip(
        refreshButton_,
        QStringLiteral("startup.toolbar.refresh.tooltip"),
        QStringLiteral("刷新当前启动项视图"));
    refreshButton_->setFixedSize(28, 28);

    exportButton_ = new QPushButton(toolbarWidget_);
    exportButton_->setIcon(createBlueIcon(":/Icon/log_export.svg", kToolbarIconSize));
    languageManager.bindToolTip(
        exportButton_,
        QStringLiteral("startup.toolbar.export.tooltip"),
        QStringLiteral("导出当前视图为制表符文本"));
    exportButton_->setFixedSize(28, 28);

    copyButton_ = new QPushButton(toolbarWidget_);
    copyButton_->setIcon(createBlueIcon(":/Icon/log_copy.svg", kToolbarIconSize));
    languageManager.bindToolTip(
        copyButton_,
        QStringLiteral("startup.toolbar.copy.tooltip"),
        QStringLiteral("复制当前选中启动项"));
    copyButton_->setFixedSize(28, 28);

    filterEdit_ = new QLineEdit(toolbarWidget_);
    languageManager.bindPlaceholder(
        filterEdit_,
        QStringLiteral("startup.toolbar.filter.placeholder"),
        QStringLiteral("过滤名称/发布者/路径/位置"));
    languageManager.bindToolTip(
        filterEdit_,
        QStringLiteral("startup.toolbar.filter.tooltip"),
        QStringLiteral("按名称、发布者、路径、位置和类型做模糊筛选。"));

    hideMicrosoftCheck_ = new QCheckBox(
        startupText("startup.toolbar.hide_microsoft", QStringLiteral("隐藏微软项")),
        toolbarWidget_);
    languageManager.bindText(
        hideMicrosoftCheck_,
        QStringLiteral("startup.toolbar.hide_microsoft"),
        QStringLiteral("隐藏微软项"));
    languageManager.bindToolTip(
        hideMicrosoftCheck_,
        QStringLiteral("startup.toolbar.hide_microsoft.tooltip"),
        QStringLiteral("隐藏发布者包含 Microsoft/Windows 的条目。"));

    hideEmptyPathCheck_ = new QCheckBox(
        startupText("startup.toolbar.hide_empty_path", QStringLiteral("隐藏空路径")),
        toolbarWidget_);
    languageManager.bindText(
        hideEmptyPathCheck_,
        QStringLiteral("startup.toolbar.hide_empty_path"),
        QStringLiteral("隐藏空路径"));
    languageManager.bindToolTip(
        hideEmptyPathCheck_,
        QStringLiteral("startup.toolbar.hide_empty_path.tooltip"),
        QStringLiteral("在高级注册表树中隐藏当前没有任何条目的注册表位置。"));

    statusLabel_ = new QLabel(
        startupText("startup.status.initial", QStringLiteral("状态：首次打开该页时加载启动项")),
        toolbarWidget_);
    statusLabel_->setWordWrap(true);
    statusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    toolbarLayout_->addWidget(refreshButton_);
    toolbarLayout_->addWidget(exportButton_);
    toolbarLayout_->addWidget(copyButton_);
    toolbarLayout_->addWidget(filterEdit_, 1);
    toolbarLayout_->addWidget(hideMicrosoftCheck_);
    toolbarLayout_->addWidget(hideEmptyPathCheck_);
    toolbarLayout_->addWidget(statusLabel_, 1);
}

void StartupDock::initializeTabs()
{
    sideTabWidget_ = new QTabWidget(this);
    sideTabWidget_->setTabPosition(QTabWidget::West);

    allPage_ = createSingleTablePage(&allTable_, sideTabWidget_);
    logonPage_ = createSingleTablePage(&logonTable_, sideTabWidget_);
    servicesPage_ = createSingleTablePage(&servicesTable_, sideTabWidget_);
    driversPage_ = createSingleTablePage(&driversTable_, sideTabWidget_);
    tasksPage_ = createSingleTablePage(&tasksTable_, sideTabWidget_);
    imageHijackPage_ = createSingleTablePage(&imageHijackTable_, sideTabWidget_);
    registryPage_ = createRegistryTreePage(&registryTree_, sideTabWidget_);
    wmiPage_ = createSingleTablePage(&wmiTable_, sideTabWidget_);
    hiddenPage_ = createSingleTablePage(&hiddenTable_, sideTabWidget_);

    sideTabWidget_->addTab(
        allPage_,
        QIcon(":/Icon/process_list.svg"),
        startupText("startup.tab.overview", QStringLiteral("总览")));
    sideTabWidget_->addTab(
        logonPage_,
        QIcon(":/Icon/process_main.svg"),
        startupText("startup.tab.logon", QStringLiteral("登录")));
    sideTabWidget_->addTab(
        servicesPage_,
        QIcon(":/Icon/process_start.svg"),
        startupText("startup.tab.services", QStringLiteral("服务")));
    sideTabWidget_->addTab(
        driversPage_,
        QIcon(":/Icon/process_details.svg"),
        startupText("startup.tab.drivers", QStringLiteral("驱动")));
    sideTabWidget_->addTab(
        tasksPage_,
        QIcon(":/Icon/process_refresh.svg"),
        startupText("startup.tab.tasks", QStringLiteral("计划任务")));
    sideTabWidget_->addTab(
        imageHijackPage_,
        QIcon(":/Icon/startup_image_hijack.svg"),
        startupText("startup.tab.image_hijack", QStringLiteral("映像劫持")));
    sideTabWidget_->addTab(
        registryPage_,
        QIcon(":/Icon/file_find.svg"),
        startupText("startup.tab.registry", QStringLiteral("高级注册表")));
    sideTabWidget_->addTab(
        wmiPage_,
        QIcon(":/Icon/process_tree.svg"),
        startupText("startup.tab.wmi", QStringLiteral("WMI")));
    sideTabWidget_->addTab(
        hiddenPage_,
        QIcon(":/Icon/startup_hidden.svg"),
        startupText("startup.tab.hidden", QStringLiteral("隐藏项")));
    const QList<QPair<QWidget*, QPair<QString, QString>>> kTabTranslations{
        {allPage_, {QStringLiteral("startup.tab.overview"), QStringLiteral("总览")}},
        {logonPage_, {QStringLiteral("startup.tab.logon"), QStringLiteral("登录")}},
        {servicesPage_, {QStringLiteral("startup.tab.services"), QStringLiteral("服务")}},
        {driversPage_, {QStringLiteral("startup.tab.drivers"), QStringLiteral("驱动")}},
        {tasksPage_, {QStringLiteral("startup.tab.tasks"), QStringLiteral("计划任务")}},
        {imageHijackPage_, {QStringLiteral("startup.tab.image_hijack"), QStringLiteral("映像劫持")}},
        {registryPage_, {QStringLiteral("startup.tab.registry"), QStringLiteral("高级注册表")}},
        {wmiPage_, {QStringLiteral("startup.tab.wmi"), QStringLiteral("WMI")}},
        {hiddenPage_, {QStringLiteral("startup.tab.hidden"), QStringLiteral("隐藏项")}}
    };
    for (const auto& tabTranslation : kTabTranslations)
    {
        ks::i18n::LanguageManager::instance().bindTab(
            sideTabWidget_,
            tabTranslation.first,
            tabTranslation.second.first,
            tabTranslation.second.second);
    }
}

void StartupDock::applyTranslatedHeaders()
{
    const QStringList kHeaderList = startup_dock_detail::startupTableHeaders();
    const QList<QTableWidget*> kTableList{
        allTable_,
        logonTable_,
        servicesTable_,
        driversTable_,
        tasksTable_,
        imageHijackTable_,
        wmiTable_,
        hiddenTable_
    };
    for (QTableWidget* tableWidget : kTableList)
    {
        if (tableWidget != nullptr)
        {
            tableWidget->setHorizontalHeaderLabels(kHeaderList);
        }
    }
    if (registryTree_ != nullptr)
    {
        registryTree_->setHeaderLabels(kHeaderList);
    }
}

void StartupDock::rebuildAllTables(const bool processesRefreshStage)
{
    if (tableRebuildTimer_ == nullptr || destroying_.load())
    {
        return;
    }

    // Result objects can only be created on the UI thread, but cannot monopolize the event loop with a long loop.
    // The work queue is rebuilt on every filter change, language switch, or new snapshot arrival; a zero-interval single-shot
    // timer allows the main window to continue handling painting, dragging, and Dock switching between two short time slices.
    tableRebuildTimer_->stop();
    tableRebuildProcessesRefreshStage_ =
        tableRebuildProcessesRefreshStage_ || processesRefreshStage;
    tableRebuildInProgress_ = true;
    tableRebuildTargets_.clear();
    registryRebuildTargets_.clear();
    tableRebuildTargetIndex_ = 0;
    registryRebuildTargetIndex_ = 0;
    tableRebuildCompletedUnits_ = 0;
    tableRebuildTotalUnits_ = 0;
    lastTableRebuildProgressPercent_ = -1;
    rebuildRegistryFirst_ = currentCategory() == StartupCategory::kRegistry;

    if (exportButton_ != nullptr)
    {
        exportButton_->setEnabled(false);
    }
    if (copyButton_ != nullptr)
    {
        copyButton_->setEnabled(false);
    }

    const std::array<std::pair<StartupCategory, QTableWidget*>, 8> kAllTableTargets{
        std::pair{ StartupCategory::kAll, allTable_ },
        std::pair{ StartupCategory::kLogon, logonTable_ },
        std::pair{ StartupCategory::kServices, servicesTable_ },
        std::pair{ StartupCategory::kDrivers, driversTable_ },
        std::pair{ StartupCategory::kTasks, tasksTable_ },
        std::pair{ StartupCategory::kImageHijack, imageHijackTable_ },
        std::pair{ StartupCategory::kWmi, wmiTable_ },
        std::pair{ StartupCategory::kHidden, hiddenTable_ }
    };
    const StartupCategory kVisibleCategory = currentCategory();
    const auto kAppendTableTarget = [this](
        const StartupCategory category,
        QTableWidget* const tableWidget)
    {
        if (tableWidget == nullptr)
        {
            return;
        }
        const auto kDuplicateIt = std::find_if(
            tableRebuildTargets_.cbegin(),
            tableRebuildTargets_.cend(),
            [tableWidget](const TableRebuildTarget& target)
            {
                return target.tableWidget == tableWidget;
            });
        if (kDuplicateIt != tableRebuildTargets_.cend())
        {
            return;
        }

        TableRebuildTarget target;
        target.category = category;
        target.tableWidget = tableWidget;
        target.visibleEntryIndexList.reserve(entryList_.size());
        for (int entryIndex = 0; entryIndex < static_cast<int>(entryList_.size()); ++entryIndex)
        {
            const StartupEntry& entry = entryList_[static_cast<std::size_t>(entryIndex)];
            if (category != StartupCategory::kAll && entry.category != category)
            {
                continue;
            }
            if (entryMatchesCurrentFilter(entry))
            {
                target.visibleEntryIndexList.push_back(entryIndex);
            }
        }

        tableWidget->setEnabled(false);
        tableWidget->setRowCount(0);
        tableWidget->setRowCount(static_cast<int>(target.visibleEntryIndexList.size()));
        tableRebuildTotalUnits_ += target.visibleEntryIndexList.size();
        tableRebuildTargets_.push_back(std::move(target));
    };

    // First populate the categories currently visible to the user; remaining categories are completed in subsequent time slices.
    for (const auto& [category, tableWidget] : kAllTableTargets)
    {
        if (category == kVisibleCategory)
        {
            kAppendTableTarget(category, tableWidget);
            break;
        }
    }
    for (const auto& [category, tableWidget] : kAllTableTargets)
    {
        kAppendTableTarget(category, tableWidget);
    }

    if (registryTree_ != nullptr)
    {
        registryTree_->setEnabled(false);
        registryTree_->clear();

        QStringList knownLocationList = buildKnownStartupRegistryLocationList();
        const bool kHideEmptyPath = (hideEmptyPathCheck_ != nullptr) && hideEmptyPathCheck_->isChecked();
        QHash<QString, std::vector<int>> totalEntryIndexMap;
        QHash<QString, std::vector<int>> visibleEntryIndexMap;
        for (int entryIndex = 0; entryIndex < static_cast<int>(entryList_.size()); ++entryIndex)
        {
            const StartupEntry& entry = entryList_[static_cast<std::size_t>(entryIndex)];
            if (!isRegistryBackedStartupEntry(entry))
            {
                continue;
            }
            const QString kGroupLocationText = entry.locationGroupText.trimmed().isEmpty()
                ? entry.locationText
                : entry.locationGroupText;
            totalEntryIndexMap[kGroupLocationText].push_back(entryIndex);
            if (!knownLocationList.contains(kGroupLocationText))
            {
                knownLocationList.push_back(kGroupLocationText);
            }
            if (entryMatchesCurrentFilter(entry))
            {
                visibleEntryIndexMap[kGroupLocationText].push_back(entryIndex);
            }
        }

        registryRebuildTargets_.reserve(static_cast<std::size_t>(knownLocationList.size()));
        for (const QString& groupLocationText : knownLocationList)
        {
            RegistryGroupRebuildTarget target;
            target.locationText = groupLocationText;
            target.totalEntryIndexList = totalEntryIndexMap.value(groupLocationText);
            target.visibleEntryIndexList = visibleEntryIndexMap.value(groupLocationText);
            if (kHideEmptyPath && target.totalEntryIndexList.empty())
            {
                continue;
            }
            tableRebuildTotalUnits_ += 1U + target.visibleEntryIndexList.size();
            registryRebuildTargets_.push_back(std::move(target));
        }
    }

    if (statusLabel_ != nullptr)
    {
        if (tableRebuildProcessesRefreshStage_)
        {
            statusLabel_->setText(
                startupText(
                    "startup.status.applying_stage_results",
                    QStringLiteral("状态：正在添加第 %1/%2 阶段结果，本阶段 %3 条..."))
                    .arg(activeRefreshStageIndex_ + 1U)
                    .arg(activeRefreshStageCount_)
                    .arg(activeRefreshStageEntryCount_));
        }
        else if (refreshInProgress_.load())
        {
            statusLabel_->setText(
                startupText(
                    "startup.status.refreshing",
                    QStringLiteral("状态：后台正在枚举启动项...")));
        }
        else
        {
            statusLabel_->setText(
                startupText(
                    "startup.status.rebuilding_view",
                    QStringLiteral("状态：正在分批更新当前启动项视图...")));
        }
    }

    if (tableRebuildTotalUnits_ == 0U)
    {
        finishIncrementalTableRebuild();
        return;
    }
    tableRebuildTimer_->start(0);
}

void StartupDock::continueIncrementalTableRebuild()
{
    if (!tableRebuildInProgress_ || destroying_.load())
    {
        return;
    }

    QElapsedTimer sliceTimer;
    sliceTimer.start();
    constexpr qint64 kSliceBudgetMilliseconds = 7;
    constexpr std::size_t kMaximumUnitsPerSlice = 24U;
    std::size_t sliceUnitCount = 0;

    const auto kProcessOneTableUnit = [this]() -> bool
    {
        while (tableRebuildTargetIndex_ < tableRebuildTargets_.size())
        {
            TableRebuildTarget& target = tableRebuildTargets_[tableRebuildTargetIndex_];
            if (target.nextRowIndex >= target.visibleEntryIndexList.size())
            {
                if (target.tableWidget != nullptr)
                {
                    target.tableWidget->setEnabled(true);
                }
                ++tableRebuildTargetIndex_;
                continue;
            }

            const int kEntryIndex = target.visibleEntryIndexList[target.nextRowIndex];
            if (target.tableWidget != nullptr
                && kEntryIndex >= 0
                && kEntryIndex < static_cast<int>(entryList_.size()))
            {
                appendEntryRow(
                    target.tableWidget,
                    static_cast<int>(target.nextRowIndex),
                    entryList_[static_cast<std::size_t>(kEntryIndex)],
                    kEntryIndex);
            }
            ++target.nextRowIndex;
            ++tableRebuildCompletedUnits_;
            if (target.nextRowIndex >= target.visibleEntryIndexList.size())
            {
                if (target.tableWidget != nullptr)
                {
                    target.tableWidget->setEnabled(true);
                }
                ++tableRebuildTargetIndex_;
            }
            return true;
        }
        return false;
    };

    const auto kProcessOneRegistryUnit = [this]() -> bool
    {
        while (registryRebuildTargetIndex_ < registryRebuildTargets_.size())
        {
            RegistryGroupRebuildTarget& target = registryRebuildTargets_[registryRebuildTargetIndex_];
            if (!target.initialized)
            {
                initializeRegistryTreeGroup(&target);
                ++tableRebuildCompletedUnits_;
                if (target.visibleEntryIndexList.empty())
                {
                    ++registryRebuildTargetIndex_;
                }
                return true;
            }
            if (target.nextEntryIndex >= target.visibleEntryIndexList.size())
            {
                ++registryRebuildTargetIndex_;
                continue;
            }

            const int kEntryIndex = target.visibleEntryIndexList[target.nextEntryIndex];
            if (target.groupItem != nullptr
                && kEntryIndex >= 0
                && kEntryIndex < static_cast<int>(entryList_.size()))
            {
                appendRegistryTreeLeaf(
                    target.groupItem,
                    entryList_[static_cast<std::size_t>(kEntryIndex)],
                    kEntryIndex);
            }
            ++target.nextEntryIndex;
            ++tableRebuildCompletedUnits_;
            if (target.nextEntryIndex >= target.visibleEntryIndexList.size())
            {
                ++registryRebuildTargetIndex_;
            }
            return true;
        }
        if (registryTree_ != nullptr)
        {
            registryTree_->setEnabled(true);
        }
        return false;
    };

    while (sliceUnitCount < kMaximumUnitsPerSlice
        && (sliceUnitCount == 0U || sliceTimer.elapsed() < kSliceBudgetMilliseconds))
    {
        bool processedUnit = false;
        if (rebuildRegistryFirst_)
        {
            processedUnit = kProcessOneRegistryUnit();
            if (!processedUnit)
            {
                rebuildRegistryFirst_ = false;
            }
        }
        if (!processedUnit)
        {
            processedUnit = kProcessOneTableUnit();
        }
        if (!processedUnit)
        {
            processedUnit = kProcessOneRegistryUnit();
        }
        if (!processedUnit)
        {
            break;
        }
        ++sliceUnitCount;
    }

    if (tableRebuildProcessesRefreshStage_
        && backendEnumerationCompleted_
        && progressPid_ != 0
        && activeRefreshStageCount_ != 0U)
    {
        const double kStageCompletedRatio = static_cast<double>(tableRebuildCompletedUnits_)
            / static_cast<double>(std::max<std::size_t>(1U, tableRebuildTotalUnits_));
        const double kAllStagesCompletedRatio =
            (static_cast<double>(activeRefreshStageIndex_) + kStageCompletedRatio)
            / static_cast<double>(activeRefreshStageCount_);
        const int kProgressPercent = std::clamp(
            94 + static_cast<int>(kAllStagesCompletedRatio * 5.0),
            94,
            99);
        if (kProgressPercent != lastTableRebuildProgressPercent_)
        {
            lastTableRebuildProgressPercent_ = kProgressPercent;
            kPro.set(
                progressPid_,
                startupText(
                    "startup.progress.apply_stage_results",
                    QStringLiteral("正在添加第 %1/%2 阶段结果（%3/%4）"))
                    .arg(activeRefreshStageIndex_ + 1U)
                    .arg(activeRefreshStageCount_)
                    .arg(tableRebuildCompletedUnits_)
                    .arg(tableRebuildTotalUnits_)
                    .toStdString(),
                0,
                static_cast<float>(kProgressPercent));
        }
    }

    const bool kTablesCompleted = tableRebuildTargetIndex_ >= tableRebuildTargets_.size();
    const bool kRegistryCompleted = registryRebuildTargetIndex_ >= registryRebuildTargets_.size();
    if (kTablesCompleted && kRegistryCompleted)
    {
        finishIncrementalTableRebuild();
        return;
    }
    tableRebuildTimer_->start(0);
}

void StartupDock::finishIncrementalTableRebuild()
{
    const bool kProcessesRefreshStage = tableRebuildProcessesRefreshStage_;
    tableRebuildInProgress_ = false;
    tableRebuildProcessesRefreshStage_ = false;
    rebuildRegistryFirst_ = false;
    tableRebuildTargets_.clear();
    registryRebuildTargets_.clear();

    const std::array<QTableWidget*, 8> kTableList{
        allTable_,
        logonTable_,
        servicesTable_,
        driversTable_,
        tasksTable_,
        imageHijackTable_,
        wmiTable_,
        hiddenTable_
    };
    for (QTableWidget* tableWidget : kTableList)
    {
        if (tableWidget != nullptr)
        {
            tableWidget->setEnabled(true);
        }
    }
    if (registryTree_ != nullptr)
    {
        registryTree_->setEnabled(true);
    }
    if (exportButton_ != nullptr)
    {
        exportButton_->setEnabled(true);
    }
    if (copyButton_ != nullptr)
    {
        copyButton_->setEnabled(true);
    }

    if (kProcessesRefreshStage)
    {
        appliedRefreshStageCount_ = std::max(
            appliedRefreshStageCount_,
            activeRefreshStageIndex_ + 1U);
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(
                startupText(
                    "startup.status.stage_results_applied",
                    QStringLiteral("状态：已添加 %1/%2 阶段，共 %3 条"))
                    .arg(appliedRefreshStageCount_)
                    .arg(activeRefreshStageCount_)
                    .arg(entryList_.size()));
        }
        QTimer::singleShot(0, this, [this]()
            {
                processNextRefreshStageResult();
            });
        return;
    }
    if (refreshInProgress_.load())
    {
        QTimer::singleShot(0, this, [this]()
            {
                processNextRefreshStageResult();
            });
        return;
    }
    if (!refreshInProgress_.load() && statusLabel_ != nullptr)
    {
        statusLabel_->setText(
            startupText("startup.status.summary", QStringLiteral("状态：共 %1 条，当前分类 %2"))
                .arg(entryList_.size())
                .arg(categoryToText(currentCategory())));
    }
}

void StartupDock::appendEntryRow(
    QTableWidget* tableWidget,
    const int rowIndex,
    const StartupEntry& entry,
    const int entryIndex)
{
    if (tableWidget == nullptr || rowIndex < 0)
    {
        return;
    }

    QTableWidgetItem* nameItem = createReadOnlyItem(entry.itemNameText);
    nameItem->setData(Qt::UserRole, entryIndex);
    nameItem->setIcon(resolveEntryIcon(entry));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::kName), nameItem);
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::kPublisher), createReadOnlyItem(entry.publisherText));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::kImagePath), createReadOnlyItem(entry.imagePathText));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::kCommand), createReadOnlyItem(entry.commandText));
    tableWidget->setItem(rowIndex, toStartupColumn(StartupColumn::kLocation), createReadOnlyItem(entry.locationText));
    tableWidget->setItem(
        rowIndex,
        toStartupColumn(StartupColumn::kUser),
        createReadOnlyItem(ks::i18n::sourceText(entry.userText)));
    tableWidget->setItem(
        rowIndex,
        toStartupColumn(StartupColumn::kEnabled),
        createReadOnlyItem(buildStatusText(entry.backendEntry)));
    tableWidget->setItem(
        rowIndex,
        toStartupColumn(StartupColumn::kType),
        createReadOnlyItem(ks::i18n::sourceText(entry.sourceTypeText)));
    tableWidget->setItem(
        rowIndex,
        toStartupColumn(StartupColumn::kDetail),
        createReadOnlyItem(startupLocalizedDetailText(entry.detailText)));

    // shouldHighlightUntrusted purpose: records whether the current entry matches the untrusted highlight condition.
    const bool kShouldHighlightUntrusted = isUntrustedStartupEntry(entry);
    if (kShouldHighlightUntrusted)
    {
        for (int columnIndex = 0; columnIndex < toStartupColumn(StartupColumn::kCount); ++columnIndex)
        {
            // currentItem usage: Locates each cell in the current row and uniformly applies a semi-transparent red background.
            QTableWidgetItem* currentItem = tableWidget->item(rowIndex, columnIndex);
            if (currentItem != nullptr)
            {
                currentItem->setBackground(kUntrustedRowHighlightColor);
            }
        }
    }
}

void StartupDock::appendRegistryTreeLeaf(
    QTreeWidgetItem* parentItem,
    const StartupEntry& entry,
    const int entryIndex)
{
    if (parentItem == nullptr)
    {
        return;
    }

    QTreeWidgetItem* entryItem = new QTreeWidgetItem(parentItem);
    entryItem->setData(0, kStartupEntryIndexRole, entryIndex);
    entryItem->setData(0, kStartupTreeNodeKindRole, static_cast<int>(StartupTreeNodeKind::kEntry));
    entryItem->setData(0, kStartupTreeLocationRole, entry.locationText);
    entryItem->setText(toStartupColumn(StartupColumn::kName), entry.itemNameText);
    entryItem->setText(toStartupColumn(StartupColumn::kPublisher), entry.publisherText);
    entryItem->setText(toStartupColumn(StartupColumn::kImagePath), entry.imagePathText);
    entryItem->setText(toStartupColumn(StartupColumn::kCommand), entry.commandText);
    entryItem->setText(toStartupColumn(StartupColumn::kLocation), entry.locationText);
    entryItem->setText(toStartupColumn(StartupColumn::kUser), ks::i18n::sourceText(entry.userText));
    entryItem->setText(
        toStartupColumn(StartupColumn::kEnabled),
        buildStatusText(entry.backendEntry));
    entryItem->setText(toStartupColumn(StartupColumn::kType), ks::i18n::sourceText(entry.sourceTypeText));
    entryItem->setText(toStartupColumn(StartupColumn::kDetail), startupLocalizedDetailText(entry.detailText));
    entryItem->setIcon(toStartupColumn(StartupColumn::kName), resolveEntryIcon(entry));

    // shouldHighlightUntrusted: In tree node mode, apply the same highlighting rules for untrusted entries as in table mode.
    const bool kShouldHighlightUntrusted = isUntrustedStartupEntry(entry);
    if (kShouldHighlightUntrusted)
    {
        for (int columnIndex = 0; columnIndex < toStartupColumn(StartupColumn::kCount); ++columnIndex)
        {
            entryItem->setBackground(columnIndex, kUntrustedRowHighlightColor);
        }
    }

    for (int columnIndex = 0; columnIndex < toStartupColumn(StartupColumn::kCount); ++columnIndex)
    {
        entryItem->setToolTip(columnIndex, entryItem->text(columnIndex));
    }
}

bool StartupDock::isRegistryBackedStartupEntry(const StartupEntry& entry) const
{
    return entry.canOpenRegistryLocation
        && !entry.locationText.trimmed().isEmpty()
        && (entry.category == StartupCategory::kLogon || entry.category == StartupCategory::kRegistry);
}

int StartupDock::findEntryIndexByRegistryTreeItem(const QTreeWidgetItem* treeItem) const
{
    if (treeItem == nullptr)
    {
        return -1;
    }

    const StartupTreeNodeKind kNodeKind = static_cast<StartupTreeNodeKind>(
        treeItem->data(0, kStartupTreeNodeKindRole).toInt());
    if (kNodeKind != StartupTreeNodeKind::kEntry)
    {
        return -1;
    }
    return treeItem->data(0, kStartupEntryIndexRole).toInt();
}

void StartupDock::initializeRegistryTreeGroup(RegistryGroupRebuildTarget* const target)
{
    if (target == nullptr || target->initialized || registryTree_ == nullptr)
    {
        return;
    }
    target->initialized = true;

    QTreeWidgetItem* groupItem = new QTreeWidgetItem(registryTree_);
    target->groupItem = groupItem;
    groupItem->setData(0, kStartupEntryIndexRole, -1);
    groupItem->setData(0, kStartupTreeNodeKindRole, static_cast<int>(StartupTreeNodeKind::kGroup));
    groupItem->setData(0, kStartupTreeLocationRole, target->locationText);
    groupItem->setFirstColumnSpanned(true);
    groupItem->setIcon(toStartupColumn(StartupColumn::kName), createBlueIcon(":/Icon/file_find.svg"));

    if (!target->visibleEntryIndexList.empty())
    {
        groupItem->setText(
            toStartupColumn(StartupColumn::kName),
            startupText("startup.registry.group.match_summary", QStringLiteral("%1    匹配 %2 项 / 总计 %3 项"))
                .arg(target->locationText)
                .arg(target->visibleEntryIndexList.size())
                .arg(target->totalEntryIndexList.size()));
    }
    else
    {
        groupItem->setText(
            toStartupColumn(StartupColumn::kName),
            target->totalEntryIndexList.empty()
                ? startupText("startup.registry.group.no_entries", QStringLiteral("%1    无条目"))
                    .arg(target->locationText)
                : startupText(
                    "startup.registry.group.no_filter_matches",
                    QStringLiteral("%1    当前过滤下无匹配项（总计 %2 项）"))
                    .arg(target->locationText)
                    .arg(target->totalEntryIndexList.size()));

        QTreeWidgetItem* placeholderItem = new QTreeWidgetItem(groupItem);
        placeholderItem->setData(0, kStartupEntryIndexRole, -1);
        placeholderItem->setData(0, kStartupTreeNodeKindRole, static_cast<int>(StartupTreeNodeKind::kPlaceholder));
        placeholderItem->setData(0, kStartupTreeLocationRole, target->locationText);
        placeholderItem->setText(
            toStartupColumn(StartupColumn::kName),
            target->totalEntryIndexList.empty()
                ? startupText("startup.registry.placeholder.no_entries", QStringLiteral("(无条目)"))
                : startupText("startup.registry.placeholder.no_matches", QStringLiteral("(无匹配项)")));
        placeholderItem->setText(
            toStartupColumn(StartupColumn::kDetail),
            target->totalEntryIndexList.empty()
                ? startupText(
                    "startup.registry.placeholder.not_found",
                    QStringLiteral("该位置当前未发现启动项"))
                : startupText(
                    "startup.registry.placeholder.filtered",
                    QStringLiteral("存在条目，但被当前过滤条件隐藏")));
    }

    groupItem->setExpanded(true);
}
