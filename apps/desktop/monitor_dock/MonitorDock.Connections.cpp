#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::initializeConnections()
{
    connect(sideTabWidget_, &QTabWidget::currentChanged, this, [this](const int index) {
        if (index < 0 || sideTabWidget_ == nullptr)
        {
            return;
        }

        QWidget* currentPage = sideTabWidget_->widget(index);
        if (currentPage == kernelCallbackHostPage_)
        {
            QTimer::singleShot(0, this, [this]()
            {
                ensureKernelCallbackTabInitialized();
            });
        }
        if (currentPage == directKernelCallHostPage_)
        {
            // The Direct Kernel Call page is created on-demand to avoid slowing down the initial opening of MonitorDock due to syscall mapping resolution.
            QTimer::singleShot(0, this, [this]()
            {
                ensureDirectKernelCallTabInitialized();
            });
        }
        if (currentPage == winApiPage_)
        {
            ensureWinApiTabInitialized();
        }

        triggerDeferredDiscoveryForCurrentTab();
    });
    if (etwTimelineWidget_ != nullptr)
    {
        etwTimelineWidget_->setSelectionChangedCallback(
            [this](const std::uint64_t start100ns, const std::uint64_t end100ns) {
                applyEtwTimelineSelection(start100ns, end100ns);
            });
    }

    // WMI basic interaction.
    connect(wmiProviderFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& text) {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] WMI Provider过滤词变更, keyword="
            << text.toStdString()
            << eol;
        applyWmiProviderFilter();
    });

    connect(wmiProviderRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击刷新WMI Provider与事件类。"
            << eol;
        refreshWmiProvidersAsync();
        refreshWmiEventClassesAsync();
    });

    connect(wmiSelectAllClassesButton_, &QPushButton::clicked, this, [this]() {
        for (int row = 0; row < wmiEventClassTable_->rowCount(); ++row)
        {
            QTableWidgetItem* item = wmiEventClassTable_->item(row, 0);
            if (item != nullptr)
            {
                item->setCheckState(Qt::Checked);
            }
        }
        KLogEvent event;
        info << event
            << "[MonitorDock] WMI事件类操作：全选。"
            << eol;
    });

    connect(wmiSelectNoneClassesButton_, &QPushButton::clicked, this, [this]() {
        for (int row = 0; row < wmiEventClassTable_->rowCount(); ++row)
        {
            QTableWidgetItem* item = wmiEventClassTable_->item(row, 0);
            if (item != nullptr)
            {
                item->setCheckState(Qt::Unchecked);
            }
        }
        KLogEvent event;
        info << event
            << "[MonitorDock] WMI事件类操作：全不选。"
            << eol;
    });

    connect(wmiSelectWin32ClassesButton_, &QPushButton::clicked, this, [this]() {
        int checkedCount = 0;
        for (int row = 0; row < wmiEventClassTable_->rowCount(); ++row)
        {
            QTableWidgetItem* checkItem = wmiEventClassTable_->item(row, 0);
            QTableWidgetItem* classItem = wmiEventClassTable_->item(row, 1);
            if (checkItem == nullptr || classItem == nullptr)
            {
                continue;
            }
            checkItem->setCheckState(classItem->text().startsWith(QStringLiteral("Win32_"), Qt::CaseInsensitive)
                ? Qt::Checked
                : Qt::Unchecked);
            if (checkItem->checkState() == Qt::Checked)
            {
                ++checkedCount;
            }
        }
        KLogEvent event;
        info << event
            << "[MonitorDock] WMI事件类操作：仅选Win32_*, selectedCount="
            << checkedCount
            << eol;
    });

    connect(wmiWhereTemplateCombo_, &QComboBox::currentIndexChanged, this, [this](int index) {
        if (index < 0)
        {
            return;
        }
        const QString kText = wmiWhereTemplateCombo_->itemData(index).toString().trimmed();
        if (kText.isEmpty())
        {
            return;
        }
        // Single-line WHERE input logic:
        // - Fill with template if content is empty.
        // - If not empty, append with AND on the same line to avoid appendPlainText generating a newline.
        const QString kExistingWhere = wmiWhereEditor_->toPlainText().trimmed();
        if (kExistingWhere.isEmpty())
        {
            wmiWhereEditor_->setPlainText(kText);
        }
        else
        {
            wmiWhereEditor_->setPlainText(kExistingWhere + QStringLiteral(" AND ") + kText);
        }

        KLogEvent event;
        info << event
            << "[MonitorDock] 追加WMI WHERE模板, template="
            << kText.toStdString()
            << eol;
    });

    connect(wmiStartSubscribeButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击开始WMI订阅。"
            << eol;
        startWmiSubscription();
    });

    connect(wmiStopSubscribeButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击停止WMI订阅。"
            << eol;
        stopWmiSubscription();
    });

    connect(wmiPauseSubscribeButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击切换WMI暂停状态。"
            << eol;
        setWmiSubscriptionPaused(!wmiSubscribePaused_.load());
    });

    connect(wmiExportButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击导出WMI事件。"
            << eol;
        exportWmiRowsToTsv();
    });

    connect(wmiEventTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        showWmiEventContextMenu(pos);
    });
    connect(wmiEventTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* itemPointer) {
        if (itemPointer == nullptr)
        {
            return;
        }
        openWmiEventDetailViewerForRow(itemPointer->row());
    });

    // WMI result filter interaction: Recalculate visible rows in real-time after any condition changes.
    const auto kBindWmiFilter = [this](QLineEdit* edit) {
        if (edit == nullptr)
        {
            return;
        }
        connect(edit, &QLineEdit::textChanged, this, [this]() {
            applyWmiEventFilter();
        });
    };
    kBindWmiFilter(wmiEventGlobalFilterEdit_);
    kBindWmiFilter(wmiEventProviderFilterEdit_);
    kBindWmiFilter(wmiEventClassFilterEdit_);
    kBindWmiFilter(wmiEventPidFilterEdit_);
    kBindWmiFilter(wmiEventDetailFilterEdit_);

    if (wmiEventRegexCheck_ != nullptr)
    {
        connect(wmiEventRegexCheck_, &QCheckBox::toggled, this, [this]() {
            applyWmiEventFilter();
        });
    }
    if (wmiEventCaseCheck_ != nullptr)
    {
        connect(wmiEventCaseCheck_, &QCheckBox::toggled, this, [this]() {
            applyWmiEventFilter();
        });
    }
    if (wmiEventInvertCheck_ != nullptr)
    {
        connect(wmiEventInvertCheck_, &QCheckBox::toggled, this, [this]() {
            applyWmiEventFilter();
        });
    }
    if (wmiEventFilterClearButton_ != nullptr)
    {
        connect(wmiEventFilterClearButton_, &QPushButton::clicked, this, [this]() {
            clearWmiEventFilter();
        });
    }

    // ETW basic interaction.
    if (etwPresetCategoryCombo_ != nullptr && etwPresetProviderList_ != nullptr)
    {
        const auto kApplyPresetCategoryFilter = [this](const QString& categoryText) {
            const QString kNormalizedCategory = categoryText.trimmed();
            int visibleCount = 0;
            for (int row = 0; row < etwPresetProviderList_->count(); ++row)
            {
                QListWidgetItem* item = etwPresetProviderList_->item(row);
                if (item == nullptr)
                {
                    continue;
                }
                const QString kItemCategory = item->data(Qt::UserRole + 1).toString();
                const bool kIsVisible = kNormalizedCategory.isEmpty()
                    || kNormalizedCategory == QStringLiteral("全部分类")
                    || kItemCategory.compare(kNormalizedCategory, Qt::CaseInsensitive) == 0;
                item->setHidden(!kIsVisible);
                if (kIsVisible)
                {
                    ++visibleCount;
                }
            }

            KLogEvent event;
            dbg << event
                << "[MonitorDock] ETW预置模板分类筛选, category="
                << kNormalizedCategory.toStdString()
                << ", visibleCount="
                << visibleCount
                << eol;
        };

        connect(etwPresetCategoryCombo_, &QComboBox::currentTextChanged, this, [kApplyPresetCategoryFilter](const QString& text) {
            kApplyPresetCategoryFilter(text);
        });
        kApplyPresetCategoryFilter(etwPresetCategoryCombo_->currentText());
    }

    if (etwPreFilterAddGroupButton_ != nullptr)
    {
        connect(etwPreFilterAddGroupButton_, &QPushButton::clicked, this, [this]() {
            addEtwFilterRuleGroup(EtwFilterStage::kPre);
            applyEtwFilterRules(EtwFilterStage::kPre);
        });
    }
    if (etwPreFilterApplyButton_ != nullptr)
    {
        connect(etwPreFilterApplyButton_, &QPushButton::clicked, this, [this]() {
            applyEtwFilterRules(EtwFilterStage::kPre);
        });
    }
    if (etwPreFilterClearButton_ != nullptr)
    {
        connect(etwPreFilterClearButton_, &QPushButton::clicked, this, [this]() {
            clearEtwFilterGroups(EtwFilterStage::kPre);
            applyEtwFilterRules(EtwFilterStage::kPre);
        });
    }
    if (etwPreFilterLoadDefaultButton_ != nullptr)
    {
        connect(etwPreFilterLoadDefaultButton_, &QPushButton::clicked, this, [this]() {
            loadEtwFilterConfigFromDefaultPath(true);
        });
    }
    if (etwPreFilterSaveDefaultButton_ != nullptr)
    {
        connect(etwPreFilterSaveDefaultButton_, &QPushButton::clicked, this, [this]() {
            saveEtwFilterConfigToDefaultPath(true);
        });
    }
    if (etwPreFilterImportButton_ != nullptr)
    {
        connect(etwPreFilterImportButton_, &QPushButton::clicked, this, [this]() {
            importEtwFilterConfigFromUserSelectedPath();
        });
    }
    if (etwPreFilterExportButton_ != nullptr)
    {
        connect(etwPreFilterExportButton_, &QPushButton::clicked, this, [this]() {
            exportEtwFilterConfigToUserSelectedPath();
        });
    }

    if (etwPostFilterAddGroupButton_ != nullptr)
    {
        connect(etwPostFilterAddGroupButton_, &QPushButton::clicked, this, [this]() {
            addEtwFilterRuleGroup(EtwFilterStage::kPost);
            applyEtwFilterRules(EtwFilterStage::kPost);
        });
    }
    if (etwPostFilterApplyButton_ != nullptr)
    {
        connect(etwPostFilterApplyButton_, &QPushButton::clicked, this, [this]() {
            applyEtwFilterRules(EtwFilterStage::kPost);
        });
    }
    if (etwPostFilterClearButton_ != nullptr)
    {
        connect(etwPostFilterClearButton_, &QPushButton::clicked, this, [this]() {
            clearEtwFilterGroups(EtwFilterStage::kPost, true);
            applyEtwFilterRules(EtwFilterStage::kPost);
        });
    }
    if (etwPostFilterLoadDefaultButton_ != nullptr)
    {
        connect(etwPostFilterLoadDefaultButton_, &QPushButton::clicked, this, [this]() {
            loadEtwFilterConfigFromDefaultPath(true);
        });
    }
    if (etwPostFilterSaveDefaultButton_ != nullptr)
    {
        connect(etwPostFilterSaveDefaultButton_, &QPushButton::clicked, this, [this]() {
            saveEtwFilterConfigToDefaultPath(true);
        });
    }
    if (etwPostFilterImportButton_ != nullptr)
    {
        connect(etwPostFilterImportButton_, &QPushButton::clicked, this, [this]() {
            importEtwFilterConfigFromUserSelectedPath();
        });
    }
    if (etwPostFilterExportButton_ != nullptr)
    {
        connect(etwPostFilterExportButton_, &QPushButton::clicked, this, [this]() {
            exportEtwFilterConfigToUserSelectedPath();
        });
    }

    connect(etwProviderRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击刷新ETW Provider。"
            << eol;
        refreshEtwProvidersAsync();
    });

    connect(etwSessionRefreshButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击刷新ETW会话。"
            << eol;
        refreshEtwSessionsAsync();
    });

    connect(etwSessionStopButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击结束选中ETW会话。"
            << eol;
        stopSelectedEtwSessions();
    });

    connect(etwSessionTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        if (etwSessionStopButton_ != nullptr && etwSessionTable_ != nullptr)
        {
            etwSessionStopButton_->setEnabled(!etwSessionTable_->selectedItems().isEmpty());
        }
    });

    connect(etwStartButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击开始ETW监听。"
            << eol;
        startEtwCapture();
    });

    connect(etwStopButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击停止ETW监听。"
            << eol;
        stopEtwCapture();
    });

    connect(etwPauseButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击切换ETW暂停状态。"
            << eol;
        if (!etwCapturePaused_.load())
        {
            setEtwCapturePaused(true);
        }
    });

    connect(etwExportButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent event;
        info << event
            << "[MonitorDock] 用户点击导出ETW事件。"
            << eol;
        exportEtwRowsToTsv();
    });

    connect(etwUiUpdateTimer_, &QTimer::timeout, this, [this]() {
        flushEtwPendingRows(!etwCaptureRunning_.load());
    });

    connect(etwEventTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        showEtwEventContextMenu(pos);
    });
    connect(etwEventTable_, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* itemPointer) {
        if (itemPointer == nullptr)
        {
            return;
        }
        openEtwEventDetailViewerForRow(itemPointer->row());
    });
}
