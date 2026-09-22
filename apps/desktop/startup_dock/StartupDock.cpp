#include "StartupDock.Internal.h"
#include "../ui/TableInteractionSupport.h"

using namespace startup_dock_detail;

StartupDock::StartupDock(QWidget* parent)
    : QWidget(parent)
{
    // Initialization order:
    // Create the UI first
    // - Reconnect interaction;
    // Switch full enumeration of startup items to lazy loading on first display to avoid slowing down main window startup.
    initializeUi();
    initializeConnections();

    KLogEvent initEvent;
    info << initEvent
        << startupText("startup.log.initialized", QStringLiteral("[StartupDock] 启动项页初始化完成。"))
               .toStdString()
        << eol;
}

StartupDock::~StartupDock()
{
    destroying_.store(true);
    if (tableRebuildTimer_ != nullptr)
    {
        tableRebuildTimer_->stop();
    }
    if (actionThread_ != nullptr && actionThread_->joinable())
    {
        actionThread_->join();
    }
    if (refreshThread_ != nullptr && refreshThread_->joinable())
    {
        refreshThread_->join();
    }
    if (refreshTimer_ != nullptr)
    {
        refreshTimer_->stop();
    }

    KLogEvent destroyEvent;
    info << destroyEvent
        << startupText("startup.log.destroyed", QStringLiteral("[StartupDock] 启动项页已析构。"))
               .toStdString()
        << eol;
}

void StartupDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange)
    {
        return;
    }

    applyTranslatedHeaders();
    rebuildAllTables();
    if (tableRebuildInProgress_)
    {
        return;
    }
    if (statusLabel_ == nullptr)
    {
        return;
    }
    if (refreshInProgress_.load())
    {
        statusLabel_->setText(
            refreshQueued_.load()
                ? startupText(
                    "startup.status.refresh_queued",
                    QStringLiteral("状态：后台刷新进行中，已记录新的刷新请求"))
                : startupText(
                    "startup.status.refreshing",
                    QStringLiteral("状态：后台正在枚举启动项...")));
    }
    else if (!initialRefreshDone_)
    {
        statusLabel_->setText(
            startupText(
                "startup.status.initial",
                QStringLiteral("状态：首次打开该页时加载启动项")));
    }
    else
    {
        statusLabel_->setText(
            startupText(
                "startup.status.summary",
                QStringLiteral("状态：共 %1 条，当前分类 %2"))
                .arg(entryList_.size())
                .arg(categoryToText(currentCategory())));
    }
}

int StartupDock::toStartupColumn(const StartupColumn column)
{
    return static_cast<int>(column);
}

QString StartupDock::categoryToText(const StartupCategory category)
{
    switch (category)
    {
    case StartupCategory::kAll:
        return startupText("startup.category.overview", QStringLiteral("总览"));
    case StartupCategory::kLogon:
        return startupText("startup.category.logon", QStringLiteral("登录"));
    case StartupCategory::kServices:
        return startupText("startup.category.services", QStringLiteral("服务"));
    case StartupCategory::kDrivers:
        return startupText("startup.category.drivers", QStringLiteral("驱动"));
    case StartupCategory::kTasks:
        return startupText("startup.category.tasks", QStringLiteral("计划任务"));
    case StartupCategory::kImageHijack:
        return startupText("startup.category.image_hijack", QStringLiteral("映像劫持"));
    case StartupCategory::kRegistry:
        return startupText("startup.category.registry", QStringLiteral("高级注册表"));
    case StartupCategory::kWmi:
        return startupText("startup.category.wmi", QStringLiteral("WMI"));
    case StartupCategory::kHidden:
        return startupText("startup.category.hidden", QStringLiteral("隐藏项"));
    default:
        return startupText("startup.category.unknown", QStringLiteral("未知"));
    }
}

void StartupDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (initialRefreshDone_)
    {
        return;
    }

    initialRefreshDone_ = true;
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(
            startupText("startup.status.first_load", QStringLiteral("状态：首次打开，正在加载启动项...")));
    }

    // Defer initial background enumeration to the end of the event loop:
    // - First, display the tab itself to avoid the user perceiving it as 'unresponsive to clicks'.
    // - Also move heavy tasks out of the main window construction phase to optimize startup speed.
    QTimer::singleShot(0, this, [this]()
        {
            requestAsyncRefresh(true);
        });
}

StartupDock::StartupCategory StartupDock::currentCategory() const
{
    if (sideTabWidget_ == nullptr)
    {
        return StartupCategory::kAll;
    }

    switch (sideTabWidget_->currentIndex())
    {
    case 0:
        return StartupCategory::kAll;
    case 1:
        return StartupCategory::kLogon;
    case 2:
        return StartupCategory::kServices;
    case 3:
        return StartupCategory::kDrivers;
    case 4:
        return StartupCategory::kTasks;
    case 5:
        return StartupCategory::kImageHijack;
    case 6:
        return StartupCategory::kRegistry;
    case 7:
        return StartupCategory::kWmi;
    case 8:
        return StartupCategory::kHidden;
    default:
        return StartupCategory::kAll;
    }
}

QTableWidget* StartupDock::currentCategoryTable() const
{
    switch (currentCategory())
    {
    case StartupCategory::kAll:
        return allTable_;
    case StartupCategory::kLogon:
        return logonTable_;
    case StartupCategory::kServices:
        return servicesTable_;
    case StartupCategory::kDrivers:
        return driversTable_;
    case StartupCategory::kTasks:
        return tasksTable_;
    case StartupCategory::kImageHijack:
        return imageHijackTable_;
    case StartupCategory::kRegistry:
        return nullptr;
    case StartupCategory::kWmi:
        return wmiTable_;
    case StartupCategory::kHidden:
        return hiddenTable_;
    default:
        return allTable_;
    }
}

QIcon StartupDock::resolveEntryIcon(const StartupEntry& entry)
{
    // Icon resolution remains on the UI thread:
    // - Avoid constructing QIcon / QFileIconProvider on background threads;
    // - Uses cache for the same path to reduce table reconstruction overhead.
    const QString kCacheKeyText =
        entry.imagePathText.trimmed().isEmpty()
        ? QStringLiteral("type:%1").arg(entry.sourceTypeText)
        : QStringLiteral("path:%1").arg(QDir::toNativeSeparators(entry.imagePathText));

    const auto kCacheIt = iconCache_.constFind(kCacheKeyText);
    if (kCacheIt != iconCache_.constEnd())
    {
        return kCacheIt.value();
    }

    QIcon resolvedIcon;
    if (!entry.imagePathText.trimmed().isEmpty())
    {
        const QFileInfo kFileInfo(entry.imagePathText);
        if (kFileInfo.exists())
        {
            static QFileIconProvider fileIconProvider;
            resolvedIcon = fileIconProvider.icon(kFileInfo);
        }
    }

    if (resolvedIcon.isNull())
    {
        if (entry.category == StartupCategory::kServices)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_start.svg");
        }
        else if (entry.category == StartupCategory::kDrivers)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_details.svg");
        }
        else if (entry.category == StartupCategory::kTasks)
        {
            resolvedIcon = createBlueIcon(":/Icon/process_refresh.svg");
        }
        else if (entry.category == StartupCategory::kImageHijack)
        {
            resolvedIcon = createBlueIcon(":/Icon/startup_image_hijack.svg");
        }
        else if (entry.category == StartupCategory::kRegistry)
        {
            resolvedIcon = createBlueIcon(":/Icon/file_find.svg");
        }
        else if (entry.category == StartupCategory::kHidden)
        {
            resolvedIcon = createBlueIcon(":/Icon/startup_hidden.svg");
        }
        else
        {
            resolvedIcon = createBlueIcon(":/Icon/process_main.svg");
        }
    }

    iconCache_.insert(kCacheKeyText, resolvedIcon);
    return resolvedIcon;
}

void StartupDock::requestAsyncRefresh(const bool forceRefresh)
{
    if (refreshInProgress_)
    {
        if (forceRefresh)
        {
            refreshQueued_ = true;
        }
        if (statusLabel_ != nullptr)
        {
            statusLabel_->setText(
                startupText(
                    "startup.status.refresh_queued",
                    QStringLiteral("状态：后台刷新进行中，已记录新的刷新请求")));
        }
        return;
    }

    if (refreshThread_ != nullptr && refreshThread_->joinable())
    {
        refreshThread_->join();
    }

    refreshInProgress_ = true;
    refreshQueued_ = false;
    pendingRefreshStageResults_.clear();
    backendEnumerationCompleted_ = false;
    refreshSnapshotStarted_ = false;
    activeRefreshStageIndex_ = 0;
    activeRefreshStageCount_ = 0;
    activeRefreshStageEntryCount_ = 0;
    appliedRefreshStageCount_ = 0;
    progressPid_ = kPro.add(
        this,
        startupText("startup.progress.title", QStringLiteral("启动项")).toStdString(),
        startupText("startup.progress.enumerate", QStringLiteral("枚举自启动项")).toStdString());
    kPro.set(
        progressPid_,
        startupText("startup.progress.prepare_logon", QStringLiteral("准备枚举登录项")).toStdString(),
        0,
        3.0f);
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(
            startupText("startup.status.refreshing", QStringLiteral("状态：后台正在枚举启动项...")));
    }

    const int kProgressPid = progressPid_;
    // The current language of LanguageManager is switched by the UI thread. Retrieve the progress text here first to
    // avoid concurrent access to the translation state between the background enumeration thread and the language switch.
    const std::array<std::string, 9> kEnumerationProgressTexts{
        startupText("startup.progress.enumerate_logon", QStringLiteral("正在枚举登录项")).toStdString(),
        startupText("startup.progress.enumerate_services", QStringLiteral("正在枚举服务启动项")).toStdString(),
        startupText("startup.progress.enumerate_drivers", QStringLiteral("正在枚举驱动启动项")).toStdString(),
        startupText("startup.progress.enumerate_tasks", QStringLiteral("正在枚举计划任务")).toStdString(),
        startupText("startup.progress.enumerate_image_hijacks", QStringLiteral("正在检查映像劫持项")).toStdString(),
        startupText("startup.progress.enumerate_registry", QStringLiteral("正在枚举高级注册表启动项")).toStdString(),
        startupText("startup.progress.enumerate_winsock", QStringLiteral("正在枚举 Winsock 启动项")).toStdString(),
        startupText("startup.progress.enumerate_wmi", QStringLiteral("正在枚举 WMI 持久化项")).toStdString(),
        startupText("startup.progress.enumerate_hidden", QStringLiteral("正在交叉检查隐藏启动项")).toStdString()
    };
    const std::string kBackendCompletedProgressText = startupText(
        "startup.progress.backend_completed",
        QStringLiteral("ks::startup 后端枚举完成")).toStdString();
    refreshThread_ = std::make_unique<std::thread>(
        [this,
         kProgressPid,
         kEnumerationProgressTexts,
         kBackendCompletedProgressText]()
        {
            if (destroying_.load())
            {
                return;
            }

            (void)ks::startup::enumerateAllStartupEntries(
                [kProgressPid, &kEnumerationProgressTexts](
                    const ks::startup::StartupEnumerationStage,
                    const std::size_t stageIndex,
                    const std::size_t stageCount)
                {
                    constexpr std::array<float, 9> kProgressValues{
                        5.0f,
                        13.0f,
                        21.0f,
                        29.0f,
                        44.0f,
                        52.0f,
                        63.0f,
                        70.0f,
                        80.0f
                    };
                    if (stageIndex >= stageCount
                        || stageIndex >= kEnumerationProgressTexts.size()
                        || stageIndex >= kProgressValues.size())
                    {
                        return;
                    }
                    kPro.set(
                        kProgressPid,
                        kEnumerationProgressTexts[stageIndex],
                        0,
                        kProgressValues[stageIndex]);
                },
                [this](
                    const ks::startup::StartupEnumerationStage,
                    const std::size_t stageIndex,
                    const std::size_t stageCount,
                    const std::vector<ks::startup::StartupEntry>& backendStageEntries)
                {
                    if (destroying_.load())
                    {
                        return;
                    }

                    std::vector<StartupEntry> stageEntryList;
                    stageEntryList.reserve(backendStageEntries.size());
                    appendBackendStartupEntries(&stageEntryList, backendStageEntries);
                    std::sort(
                        stageEntryList.begin(),
                        stageEntryList.end(),
                        [](const StartupEntry& left, const StartupEntry& right)
                        {
                            if (left.category != right.category)
                            {
                                return static_cast<int>(left.category) < static_cast<int>(right.category);
                            }
                            if (left.itemNameText.compare(right.itemNameText, Qt::CaseInsensitive) != 0)
                            {
                                return left.itemNameText.compare(right.itemNameText, Qt::CaseInsensitive) < 0;
                            }
                            return left.locationText.compare(right.locationText, Qt::CaseInsensitive) < 0;
                        });

                    QMetaObject::invokeMethod(
                        this,
                        [this,
                         stageIndex,
                         stageCount,
                         stageEntryList = std::move(stageEntryList)]() mutable
                        {
                            if (!destroying_.load())
                            {
                                enqueueRefreshStageResult(
                                    stageIndex,
                                    stageCount,
                                    std::move(stageEntryList));
                            }
                        },
                        Qt::QueuedConnection);
                });
            kPro.set(
                kProgressPid,
                kBackendCompletedProgressText,
                0,
                93.0f);

            if (destroying_.load())
            {
                return;
            }

            QMetaObject::invokeMethod(
                this,
                [this]()
                {
                    if (!destroying_.load())
                    {
                        markBackendEnumerationCompleted();
                    }
                },
                Qt::QueuedConnection);
        });
}

void StartupDock::enqueueRefreshStageResult(
    const std::size_t stageIndex,
    const std::size_t stageCount,
    std::vector<StartupEntry> entryList)
{
    if (destroying_.load()
        || !refreshInProgress_.load()
        || stageCount == 0U
        || stageIndex >= stageCount)
    {
        return;
    }

    RefreshStageResult stageResult;
    stageResult.stageIndex = stageIndex;
    stageResult.stageCount = stageCount;
    stageResult.entryList = std::move(entryList);
    pendingRefreshStageResults_.push_back(std::move(stageResult));
    processNextRefreshStageResult();
}

void StartupDock::processNextRefreshStageResult()
{
    if (destroying_.load()
        || !refreshInProgress_.load()
        || tableRebuildInProgress_)
    {
        return;
    }

    if (pendingRefreshStageResults_.empty())
    {
        if (backendEnumerationCompleted_)
        {
            completeRefreshAfterUiCommit();
        }
        return;
    }

    const QList<QAbstractItemView*> kStartupViews = {
        allTable_,
        logonTable_,
        servicesTable_,
        driversTable_,
        tasksTable_,
        imageHijackTable_,
        wmiTable_,
        hiddenTable_,
        registryTree_
    };
    if (ks::ui::isItemViewUiCommitBlockedByContextMenu(kStartupViews))
    {
        // The eight category tables and the registry tree share the same m_entryList index. The next batch can only be appended
        // after the menu closes to prevent row indices held by the current menu from becoming invalid during shared cache switching.
        const QPointer<StartupDock> kSafeThis(this);
        ks::ui::deferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("startup-tables-stage-result-apply"),
            kStartupViews,
            [kSafeThis]()
            {
                if (!kSafeThis.isNull())
                {
                    kSafeThis->processNextRefreshStageResult();
                }
            });
        return;
    }

    RefreshStageResult stageResult = std::move(pendingRefreshStageResults_.front());
    pendingRefreshStageResults_.pop_front();

    // Switch away from the old snapshot only when the first batch of results arrives; thereafter, each backend stage appends only to the cumulative results.
    // Do not process the next batch before the current batch is fully written to ensure the order seen by the user matches the backend enumeration order.
    if (!refreshSnapshotStarted_)
    {
        entryList_.clear();
        refreshSnapshotStarted_ = true;
    }
    const std::size_t kStageEntryCount = stageResult.entryList.size();
    entryList_.reserve(entryList_.size() + kStageEntryCount);
    for (StartupEntry& entry : stageResult.entryList)
    {
        entryList_.push_back(std::move(entry));
    }

    activeRefreshStageIndex_ = stageResult.stageIndex;
    activeRefreshStageCount_ = stageResult.stageCount;
    activeRefreshStageEntryCount_ = kStageEntryCount;
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(
            startupText(
                "startup.status.applying_stage_results",
                QStringLiteral("状态：正在添加第 %1/%2 阶段结果，本阶段 %3 条..."))
                .arg(activeRefreshStageIndex_ + 1U)
                .arg(activeRefreshStageCount_)
                .arg(kStageEntryCount));
    }
    rebuildAllTables(true);
}

void StartupDock::markBackendEnumerationCompleted()
{
    if (destroying_.load() || !refreshInProgress_.load())
    {
        return;
    }

    backendEnumerationCompleted_ = true;
    processNextRefreshStageResult();
}

void StartupDock::completeRefreshAfterUiCommit()
{
    if (destroying_.load()
        || !refreshInProgress_.load()
        || !backendEnumerationCompleted_
        || !pendingRefreshStageResults_.empty()
        || tableRebuildInProgress_)
    {
        return;
    }

    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(
            startupText("startup.status.summary", QStringLiteral("状态：共 %1 条，当前分类 %2"))
            .arg(entryList_.size())
            .arg(categoryToText(currentCategory())));
    }

    const int kCompletedProgressPid = progressPid_;
    progressPid_ = 0;
    if (kCompletedProgressPid != 0)
    {
        kPro.set(
            kCompletedProgressPid,
            startupText("startup.progress.completed", QStringLiteral("启动项刷新完成")).toStdString(),
            0,
            100.0f);
    }

    refreshInProgress_ = false;

    KLogEvent refreshEvent;
    info << refreshEvent
        << startupText("startup.log.refresh.completed", QStringLiteral("[StartupDock] 后台刷新完成, count="))
               .toStdString()
        << entryList_.size()
        << eol;

    if (refreshQueued_)
    {
        requestAsyncRefresh(false);
    }
}
