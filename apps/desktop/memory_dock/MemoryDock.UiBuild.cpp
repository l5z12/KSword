#include "MemoryDock.Internal.h"
#include "SystemMemoryAuditPage.h"
#include "DdmaPage.h"
#include "../ui/VisibleTableWidget.h"
#include "../internationalization/LanguageManager.h"

#include <QCompleter> // The inclusive completion for the process dropdown requires a complete type.

#include <functional>
#include <utility>

// Note: Migrated from the original aggregated implementation to a standalone .cpp file; member function implementations remain unchanged.
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.UiBuild.cpp
// Purpose: Encapsulate construction/destruction and UI structure initialization code.
// ============================================================

// ============================================================
// MemoryDock.UiBuild.cpp (split from
// the original UiLifecycle). Purpose:
// - Encapsulates lifecycle logic for MemoryDock construction/destruction, UI structure initialization, and signal-slot connections.
// - Focus on the 'UI and interaction binding' responsibility to avoid mixing with scanning algorithms or read/write utility functions.
// ============================================================

namespace
{
    // PopupLifecycleGuardedComboBox:
    // - Register the popup lifecycle before QComboBox::showPopup() to avoid windows where Qt's scroll
    //   animation temporarily hides the real popup, causing isVisible() to incorrectly report false.
    // - Unregister and re-queue the delayed submission in the next event loop iteration after hidePopup() completes.
    // - generation prevents old callbacks from incorrectly deregistering new popups when a popup is closed and immediately reopened.
    class PopupLifecycleGuardedComboBox final : public QComboBox
    {
    public:
        PopupLifecycleGuardedComboBox(
            QWidget* const parentWidget,
            std::function<void(bool)> popupStateChangedAction)
            : QComboBox(parentWidget),
              popupStateChangedAction_(std::move(popupStateChangedAction))
        {
        }

    protected:
        void showPopup() override
        {
            // An empty model does not trigger a popup, so there is no model/animation lifecycle to protect.
            if (count() <= 0)
            {
                QComboBox::showPopup();
                return;
            }

            ++popupGeneration_;
            if (popupStateChangedAction_)
            {
                popupStateChangedAction_(true);
            }
            QComboBox::showPopup();
        }

        void hidePopup() override
        {
            const quint64 kClosingGeneration = popupGeneration_;
            QComboBox::hidePopup();

            // The QComboBox's Hide cleanup is still within the current call stack; allow clearing/rebuilding the model in the next iteration.
            QTimer::singleShot(0, this, [this, kClosingGeneration]() {
                if (kClosingGeneration != popupGeneration_)
                {
                    return;
                }

                if (popupStateChangedAction_)
                {
                    popupStateChangedAction_(false);
                }
                });
        }

    private:
        std::function<void(bool)> popupStateChangedAction_;
        quint64 popupGeneration_ = 0ULL;
    };

    // copyMemoryUtilityCurrentRow:
    // - Copy the current row of the MemoryDock utility table.
    // - Input table: QTableWidget such as breakpoint table, bookmark table, etc.;
    // - Processing: Read visible text column by column and write to the clipboard in TSV format.
    // - Return: None; returns immediately if no row is selected or the clipboard is unavailable.
    void copyMemoryUtilityCurrentRow(QTableWidget* table)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
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
            const QTableWidgetItem* item = table->item(kRowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
    }

    // installMemoryUtilityCopyMenu:
    // - Install a read-only copy menu for auxiliary tables such as breakpoints and bookmarks;
    // - Input table: table requiring row copy capability;
    // - Processing: Synchronize the current row on click and display an explicit opaque QMenu.
    // - Returns: Nothing; does not change breakpoint or bookmark state.
    void installMemoryUtilityCopyMenu(QTableWidget* table)
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
                    copyMemoryUtilityCurrentRow(table);
                }
            });
    }
}

MemoryDock::MemoryDock(QWidget* parent)
    : QWidget(parent)
{
    // Log the construction start point to track the lifecycle of the memory page control.
    KLogEvent constructStartEvent;
    info << constructStartEvent
        << "[MemoryDock] 开始构造内存页面控件。"
        << eol;

    // Construction phase executes in a fixed order to ensure UI controls are created before signals are bound.
    initializeUi();
    initializeConnections();
    initializeBookmarkRefreshTimer();
    refreshProcessList(false);
    updateStatusBarText();

    // Log construction completion: confirm the initialization chain has finished executing.
    KLogEvent constructFinishEvent;
    info << constructFinishEvent
        << "[MemoryDock] 构造完成，已初始化 UI、连接、定时器与进程列表。"
        << eol;
}

MemoryDock::~MemoryDock()
{
    // Destruction start log: Helps locate background task status when the window is closed.
    KLogEvent destroyStartEvent;
    info << destroyStartEvent
        << "[MemoryDock] 开始析构，准备取消扫描并分离进程。"
        << eol;

    // Cancels the current scan before destruction to prevent background threads from using destroyed controls.
    cancelCurrentScan();
    detachProcess();

    // Destruction completion log: Mark the end of the control resource reclamation process.
    KLogEvent destroyFinishEvent;
    info << destroyFinishEvent
        << "[MemoryDock] 析构完成。"
        << eol;
}

void MemoryDock::initializeUi()
{
    // Log when initializing the root UI structure to help locate issues with UI component construction order.
    KLogEvent uiInitEvent;
    info << uiInitEvent
        << "[MemoryDock] initializeUi: 开始构建根布局。"
        << eol;

    // Root layout: title row, process toolbar, middle tab, and bottom status bar.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    // The header row follows the same three-segment layout as other docks: title on the left, status summary consuming the middle whitespace.
    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);
    dockTitleLabel_ = new QLabel(QStringLiteral("内存"), this);
    dockTitleLabel_->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
            .arg(ksword_theme::textPrimaryHex()));
    dockHeaderStatusLabel_ = new QLabel(QStringLiteral("未附加进程，请先选择目标并点击“附加”。"), this);
    dockHeaderStatusLabel_->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(ksword_theme::textSecondaryHex()));
    headerLayout->addWidget(dockTitleLabel_, 0);
    headerLayout->addWidget(dockHeaderStatusLabel_, 1);
    rootLayout_->addLayout(headerLayout);

    initializeToolbar();
    initializeTabs();
    initializeStatusBar();

    // After establishing the status bar, re-apply semantic colors to ensure bottom labels follow the same path.
    applyMemoryDockSemanticStyles();
}

void MemoryDock::applyMemoryDockSemanticStyles()
{
    // The high-risk write-back button uses an error semantic color border to distinguish it from standard buttons.
    if (driverMemoryApplyButton_ != nullptr)
    {
        driverMemoryApplyButton_->setStyleSheet(
            QStringLiteral(
                "QPushButton{border:1px solid %1;border-radius:3px;color:%1;padding:4px 10px;}"
                "QPushButton:disabled{border:1px solid %2;color:%2;}")
                .arg(ksword_theme::errorHex())
                .arg(ksword_theme::textSecondaryHex()));
    }

    // Bottom status bar: success color when attached, secondary color when not attached, warning color for read/write unavailable.
    const bool kAttached = (attachedPid_ != 0U);
    if (statusProcessLabel_ != nullptr)
    {
        statusProcessLabel_->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(kAttached ? ksword_theme::successHex() : ksword_theme::textSecondaryHex()));
    }
    if (statusPidLabel_ != nullptr)
    {
        statusPidLabel_->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(kAttached ? ksword_theme::textPrimaryHex() : ksword_theme::textSecondaryHex()));
    }
    if (statusMemoryIoLabel_ != nullptr)
    {
        // Attached but lacking read/write permissions is the most critical state to highlight, so use a warning color.
        QString memoryIoColor = ksword_theme::textSecondaryHex();
        if (kAttached)
        {
            memoryIoColor = canReadWriteMemory_
                ? ksword_theme::successHex()
                : ksword_theme::warningHex();
        }
        statusMemoryIoLabel_->setStyleSheet(QStringLiteral("color:%1;").arg(memoryIoColor));
    }
}

void MemoryDock::changeEvent(QEvent* eventObject)
{
    QWidget::changeEvent(eventObject);
    if (eventObject == nullptr)
    {
        return;
    }

    // Palette changes indicate a switch between light and dark themes; all semantic color snapshots must be re-evaluated.
    if (eventObject->type() == QEvent::ApplicationPaletteChange
        || eventObject->type() == QEvent::PaletteChange)
    {
        applyMemoryDockSemanticStyles();
    }
}

void MemoryDock::initializeToolbar()
{
    // Log toolbar initialization: explicitly record when top-level controls are created.
    KLogEvent toolbarInitEvent;
    info << toolbarInitEvent
        << "[MemoryDock] initializeToolbar: 创建进程工具栏控件。"
        << eol;

    // Place the top toolbar in a separate container to facilitate unified margin and spacing.
    QWidget* toolbarContainer = new QWidget(this);
    toolbarLayout_ = new QHBoxLayout(toolbarContainer);
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    processCombo_ = new PopupLifecycleGuardedComboBox(
        toolbarContainer,
        [this](const bool active) {
            processComboPopupLifecycleActive_ = active;
            if (!active)
            {
                flushProcessComboDeferredCommit();
            }
            });
    processCombo_->setMinimumWidth(280);
    processCombo_->setToolTip("选择目标进程。可直接输入过滤：进程名和 PID 都能匹配。");

    // Editable input with substring completion. Scrolling through hundreds of processes is impractical, and for programs with
    // many instances of the same name (e.g., QQ launching ten identical processes), distinguishing them requires the PID.
    // Therefore, completion must match PIDs within the entry text using MatchContains instead of the default prefix matching.
    processCombo_->setEditable(true);
    processCombo_->setInsertPolicy(QComboBox::NoInsert);
    if (QCompleter* const kProcessCompleter = processCombo_->completer())
    {
        kProcessCompleter->setCompletionMode(QCompleter::PopupCompletion);
        kProcessCompleter->setFilterMode(Qt::MatchContains);
        kProcessCompleter->setCaseSensitivity(Qt::CaseInsensitive);
        kProcessCompleter->setMaxVisibleItems(20);
    }
    if (QLineEdit* const kProcessEdit = processCombo_->lineEdit())
    {
        kProcessEdit->setPlaceholderText(QStringLiteral("输入进程名或 PID 过滤"));
        kProcessEdit->setClearButtonEnabled(true);
    }

    // Crosshair: Click and drag to the target window, then release to attach directly based on window ownership.
    // This path is safe because it cannot be misselected: users know "which window is the
    // one I want," not the PID; let them point to the window, and the tool resolves the PID.
    processPickerButton_ = new ks::ui::WindowPickerButton(toolbarContainer);
    processPickerButton_->setIcon(QIcon(QStringLiteral(":/Icon/window_picker_aim.svg")));
    processPickerButton_->setToolTip(
        QStringLiteral("按住不放，把光标拖到目标程序的窗口上再松手，即按该窗口所属进程附加。拖动时目标窗口会高亮，按 Esc 取消。"));

    // Real-time target hint during the pick process. Visible only during picking: occupying toolbar width otherwise is meaningless, and since
    // the mouse has already left the toolbar during picking, the user needs a place not requiring looking down to see the current target.
    processPickerHintLabel_ = new QLabel(toolbarContainer);
    processPickerHintLabel_->setVisible(false);
    processPickerHintLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;").arg(ksword_theme::controlAccentHex()));

    // Per project specification: action buttons must prioritize icons from the icon library, and every button must have a tooltip.
    attachButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_start.svg")), "附加", toolbarContainer);
    detachButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")), "分离", toolbarContainer);
    refreshButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")), "刷新", toolbarContainer);
    settingsButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_priority.svg")), "设置", toolbarContainer);
    attachButton_->setToolTip("附加到上面选中的进程，之后才能查看和搜索它的内存");
    detachButton_->setToolTip("从当前进程分离，释放已打开的进程句柄");
    refreshButton_->setToolTip("重新枚举系统进程列表，或刷新当前页的数据");
    settingsButton_->setToolTip("打开内存读写方式、扫描上限等选项");

    // The separator visually distinguishes the 'attach/detach' process actions from the 'refresh/settings' page actions.
    QFrame* toolbarSeparator = new QFrame(toolbarContainer);
    toolbarSeparator->setFrameShape(QFrame::VLine);
    toolbarSeparator->setFrameShadow(QFrame::Sunken);

    toolbarLayout_->addWidget(new QLabel("进程:", toolbarContainer));
    toolbarLayout_->addWidget(processCombo_, 1);
    toolbarLayout_->addWidget(processPickerButton_);
    toolbarLayout_->addWidget(processPickerHintLabel_);
    toolbarLayout_->addWidget(attachButton_);
    toolbarLayout_->addWidget(detachButton_);
    toolbarLayout_->addWidget(toolbarSeparator);
    toolbarLayout_->addWidget(refreshButton_);
    toolbarLayout_->addWidget(settingsButton_);

    rootLayout_->addWidget(toolbarContainer);
}

void MemoryDock::initializeTabs()
{
    // Log Tab initialization: facilitates troubleshooting when a specific page fails to create.
    KLogEvent tabInitEvent;
    info << tabInitEvent
        << "[MemoryDock] initializeTabs: 开始创建 11 个功能页。"
        << eol;

    // All child pages are uniformly hosted by QTabWidget.
    tabWidget_ = new QTabWidget(this);
    tabWidget_->setDocumentMode(true);
    rootLayout_->addWidget(tabWidget_, 1);

    initializeProcessModuleTab();
    initializeMemoryRegionTab();
    initializeMemorySearchTab();
    initializeMemoryViewerTab();
    initializeBreakpointBookmarkTab();
    initializeDriverMemoryRwTab();
    initializeKernelExecutableMemoryScanTab();
    initializeKernelMemoryEvidenceTab();
    initializeProcessPteTranslateTab();
    initializeProcessMemoryEvidenceTab();
    initializeSystemMemoryAuditTab();
    initializeTamperDetectionTab();
    initializeDdmaTab();

    // 12. Icon sets for the 12 tabs are configured here; scattering them across build functions risks omissions and hinders unified semantic adjustments.
    // Index order must strictly correspond to the construction order above.
    const char* const kTabIconAliases[] = {
        ":/Icon/process_list.svg",        // Processes and modules
        ":/Icon/disk_storage.svg",        // Memory region
        ":/Icon/codeeditor_find.svg",     // Memory search
        ":/Icon/process_details.svg",     // Memory Viewer
        ":/Icon/process_pause.svg",       // Breakpoints and bookmarks
        ":/Icon/disk_save.svg",           // Driver memory read/write
        ":/Icon/log_track.svg",           // Kernel executable pages
        ":/Icon/file_find.svg",           // Kernel memory evidence
        ":/Icon/process_tree.svg",        // PTE / VA translation
        ":/Icon/process_performance.svg", // Process memory evidence
        ":/Icon/disk_analyze.svg",        // System memory audit
        ":/Icon/disk_storage.svg"         // DDMA
    };
    const int kIconCount = static_cast<int>(sizeof(kTabIconAliases) / sizeof(kTabIconAliases[0]));
    for (int tabIndex = 0; tabIndex < tabWidget_->count() && tabIndex < kIconCount; ++tabIndex)
    {
        tabWidget_->setTabIcon(tabIndex, QIcon(QString::fromLatin1(kTabIconAliases[tabIndex])));
    }

    // The four evidence pages added later missed semantic key bindings; this completes them so they also follow language switching.
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    if (tabKernelExecutableMemory_ != nullptr)
    {
        languageManager.bindTab(
            tabWidget_, tabKernelExecutableMemory_,
            QStringLiteral("memory.tab.kernel_executable"), QStringLiteral("内核可执行页"));
    }
    if (tabKernelMemoryEvidence_ != nullptr)
    {
        languageManager.bindTab(
            tabWidget_, tabKernelMemoryEvidence_,
            QStringLiteral("memory.tab.kernel_memory_evidence"), QStringLiteral("内核内存证据"));
    }
    if (tabProcessPteTranslate_ != nullptr)
    {
        languageManager.bindTab(
            tabWidget_, tabProcessPteTranslate_,
            QStringLiteral("memory.tab.pte_translate"), QStringLiteral("PTE / VA 翻译"));
    }
    if (tabProcessMemoryEvidence_ != nullptr)
    {
        languageManager.bindTab(
            tabWidget_, tabProcessMemoryEvidence_,
            QStringLiteral("memory.tab.process_memory_evidence"), QStringLiteral("进程内存证据"));
    }
}

void MemoryDock::initializeSystemMemoryAuditTab()
{
    systemMemoryAuditPage_ = new SystemMemoryAuditPage(tabWidget_);
    tabWidget_->addTab(systemMemoryAuditPage_, QStringLiteral("系统内存审计"));
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_,
        systemMemoryAuditPage_,
        QStringLiteral("memory.tab.system_memory_audit"),
        QStringLiteral("系统内存审计"));
}

void MemoryDock::initializeTamperDetectionTab()
{
    // Mount this page **before** the DDMA page, but note that it depends on a session: the DDMA channel is the only read
    // path on this page that bypasses CPU page tables. Without it, this page can only detect standard patches. The page
    // itself will display this message on the UI when the channel is unavailable, rather than just graying out the checkbox.
    tamperDetectionPage_ = new ksword::memory_dock::TamperDetectionPage(tabWidget_);
    tabWidget_->addTab(tamperDetectionPage_, QStringLiteral("篡改检测"));
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_,
        tamperDetectionPage_,
        QStringLiteral("memory.tab.tamper_detection"),
        QStringLiteral("篡改检测"));
}

void MemoryDock::initializeDdmaTab()
{
    // Tab12: DDMA. The page handles channel configuration and self-checks itself; MemoryDock only mounts it and subscribes
    // to session changes, synchronizing "whether DDMA backend can be selected now" to dropdowns on other pages.
    ddmaPage_ = new DdmaPage(tabWidget_);
    ddmaPage_->setSessionChangedCallback([this]() { refreshBackendSelectors(); });

    tabWidget_->addTab(ddmaPage_, QStringLiteral("DDMA"));
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_,
        ddmaPage_,
        QStringLiteral("memory.tab.ddma"),
        QStringLiteral("DDMA"));

    // The system memory audit page must also be able to verify physical pages via DDMA; here, the session read entry is delegated to it.
    if (systemMemoryAuditPage_ != nullptr)
    {
        systemMemoryAuditPage_->setDdmaSessionProvider(
            [this]() -> const ksword::memory_backend::DdmaSession& {
                return currentDdmaSession();
            });
    }

    // The three dropdowns were already created in their respective Tab build functions; this performs the initial state synchronization.
    refreshBackendSelectors();
}

void MemoryDock::focusDdmaPage()
{
    if (tabWidget_ == nullptr || ddmaPage_ == nullptr)
    {
        return;
    }
    // In the embedded process details mode, this page is hidden; a hidden Tab cannot be switched to via
    // setCurrentWidget, so we first verify its visibility before switching to avoid the 'clicking does nothing' issue.
    const int kTabIndex = tabWidget_->indexOf(ddmaPage_);
    if (kTabIndex < 0 || !tabWidget_->isTabVisible(kTabIndex))
    {
        return;
    }
    tabWidget_->setCurrentWidget(ddmaPage_);
}

QWidget* MemoryDock::createBackendSelector(
    QWidget* const parent,
    QComboBox*& comboOut,
    QLabel*& hintOut)
{
    QWidget* container = new QWidget(parent);
    QHBoxLayout* layout = new QHBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(6);

    comboOut = new QComboBox(container);
    // The entry order must match the MemoryAccessBackend enumeration; the UI converts directly by index.
    comboOut->addItem(QStringLiteral("R3（ReadProcessMemory）"));
    comboOut->addItem(QStringLiteral("R0（驱动通道）"));
    comboOut->addItem(QStringLiteral("HVM（私有页表窗口）"));
    comboOut->addItem(QStringLiteral("DDMA（磁盘 DMA）"));
    comboOut->setToolTip(
        QStringLiteral("R3 走 ReadProcessMemory / WriteProcessMemory，不经驱动，受句柄权限与进程保护约束，也读不了内核地址和物理地址。\nR0 走驱动的 MmCopyVirtualMemory / MmMapIoSpaceEx，绕开句柄权限，能读内核地址与物理地址，但仍受 SLAT / EPT 约束。\nHVM 改写自有页表项指向目标帧，整条路径不调用任何文档化的内存管理器例程，别的驱动挂钩那些例程挂不到它头上；它同样受 SLAT / EPT 约束，与 R0 分歧说明的是内存管理器被挂了钩，而不是重定向。\nDDMA 走磁盘控制器的总线主控 DMA，不受 SLAT 约束，能读到被上层虚拟化重定向或隐藏的物理页；代价是必须借用磁盘扇区中转，而且明显更慢，需要先在“DDMA”子页配置通道。\n同一个地址几条读到的结果不一样本身就是判据，而分歧落在哪两条之间决定了它说明什么。"));

    hintOut = new QLabel(container);
    hintOut->setWordWrap(true);
    hintOut->setTextInteractionFlags(Qt::TextSelectableByMouse);

    layout->addWidget(new QLabel(QStringLiteral("访问后端"), container));
    layout->addWidget(comboOut);
    layout->addWidget(hintOut, 1);

    // When DDMA is selected but the channel is not yet ready, refreshBackendSelectors reverts the selection to the standard channel and
    // explains the missing step in the prompt. It uses QSignalBlocker to modify the index internally, preventing recursive triggers.
    connect(comboOut, &QComboBox::currentIndexChanged, this, [this](int) {
        refreshBackendSelectors();
        });

    return container;
}

void MemoryDock::refreshBackendSelectors()
{
    QString reason;
    const bool kDdmaUsable =
        ksword::memory_backend::isDdmaUsable(currentDdmaSession(), &reason);

    // The three dropdowns share the same criteria and text to avoid divergence from writing them separately.
    const auto kSyncOne = [this, kDdmaUsable, &reason](
                             QComboBox* const combo, QLabel* const hint) {
        if (combo == nullptr)
        {
            return;
        }
        const bool kDdmaSelected =
            (combo->currentIndex() ==
             static_cast<int>(ksword::memory_backend::MemoryAccessBackend::kDdma));

        // When DDMA becomes unusable, the dropdown currently selected on DDMA must revert
        // to the standard channel; otherwise, the next user read attempt will fail.
        if (kDdmaSelected && !kDdmaUsable)
        {
            const QSignalBlocker kBlocker(combo);
            combo->setCurrentIndex(
                static_cast<int>(ksword::memory_backend::MemoryAccessBackend::kStandardDriver));
        }

        if (hint == nullptr)
        {
            return;
        }
        if (kDdmaUsable)
        {
            hint->setText(QStringLiteral("DDMA 通道已就绪，可随时切换。"));
            hint->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
        }
        else
        {
            hint->setText(QStringLiteral("DDMA 暂不可用：%1").arg(reason));
            hint->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
        }
        };

    kSyncOne(searchBackendCombo_, searchBackendHintLabel_);
    kSyncOne(viewerBackendCombo_, viewerBackendHintLabel_);
    kSyncOne(driverMemoryBackendCombo_, driverMemoryBackendHintLabel_);

    // The system memory audit page has no backend pull-down; it only has a "DDMA Cross-Check" button, but it must still
    // follow the session availability switch; otherwise, it leaves a button that will inevitably fail when clicked.
    if (systemMemoryAuditPage_ != nullptr)
    {
        systemMemoryAuditPage_->refreshDdmaCrossCheckState();
    }

    // The tamper detection page must follow the session: DDMA is its only path bypassing the CPU page table. When
    // channel status changes, the types of conclusions it can draw also change, so the UI must reflect this truthfully.
    if (tamperDetectionPage_ != nullptr)
    {
        tamperDetectionPage_->refreshChannelAvailability();
    }
}

const ksword::memory_backend::DdmaSession& MemoryDock::currentDdmaSession() const
{
    // Read the process-level session instead of querying m_ddmaPage: DDMA pages may not be built yet (Dock layout
    // restoration order is not guaranteed), while the process-level session always has a deterministic value;
    // when unconfigured, it is 'unconfigured' and will not be misjudged as available due to a null pointer.
    return ksword::memory_backend::currentDdmaSession();
}

namespace
{
    // backendFromComboIndex：
    // - The dropdown item order corresponds one-to-one with the MemoryAccessBackend enum, so the index can be converted directly.
    // - All three dropdowns share this mapping to avoid modifying three separate locations when adding a new backend.
    //
    // Previously, all three cases were written as "treat as standard channel if not DDMA." With only two enum values, this obscured the
    // issue; adding R3 caused it to silently fold R3 into R0—user selects R3 but the driver path is taken. Since "different results for
    // the same address via different channels" is precisely why these three options exist, folding them away defeats their purpose.
    ksword::memory_backend::MemoryAccessBackend backendFromComboIndex(
        const QComboBox* const combo)
    {
        if (combo == nullptr)
        {
            return ksword::memory_backend::MemoryAccessBackend::kUserMode;
        }
        const int kSelectedIndex = combo->currentIndex();
        if (kSelectedIndex < 0
            || kSelectedIndex >
                static_cast<int>(ksword::memory_backend::MemoryAccessBackend::kDdma))
        {
            return ksword::memory_backend::MemoryAccessBackend::kUserMode;
        }
        return static_cast<ksword::memory_backend::MemoryAccessBackend>(kSelectedIndex);
    }
}

ksword::memory_backend::MemoryAccessBackend MemoryDock::currentSearchBackend() const
{
    return backendFromComboIndex(searchBackendCombo_);
}

ksword::memory_backend::MemoryAccessBackend MemoryDock::currentViewerBackend() const
{
    return backendFromComboIndex(viewerBackendCombo_);
}

ksword::memory_backend::MemoryAccessBackend MemoryDock::currentDriverMemoryBackend() const
{
    return backendFromComboIndex(driverMemoryBackendCombo_);
}

void MemoryDock::initializeProcessModuleTab()
{
    // Tab1 initialization log: records the construction of the 'Process and Module' page.
    KLogEvent tab1InitEvent;
    info << tab1InitEvent
        << "[MemoryDock] initializeProcessModuleTab: 构建进程与模块页面。"
        << eol;

    // Tab1: Processes and modules.
    tabProcessModule_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabProcessModule_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // Vertical split layout: process table on top, module table on bottom.
    QSplitter* splitter = new QSplitter(Qt::Vertical, tabProcessModule_);

    QWidget* processPanel = new QWidget(splitter);
    QVBoxLayout* processLayout = new QVBoxLayout(processPanel);
    processLayout->setContentsMargins(0, 0, 0, 0);
    processLayout->setSpacing(4);
    QHBoxLayout* processTopBarLayout = new QHBoxLayout();
    processTopBarLayout->setContentsMargins(0, 0, 0, 0);
    processTopBarLayout->setSpacing(8);
    processTopBarLayout->addWidget(new QLabel("进程列表（双击自动附加）", processPanel));

    // Align the filter box with the module table below: the module table is always present, while the process table is not, and the number of processes far exceeds the number of modules.
    processFilterEdit_ = new QLineEdit(processPanel);
    processFilterEdit_->setPlaceholderText("按进程名或 PID 过滤");
    processFilterEdit_->setClearButtonEnabled(true);
    processFilterEdit_->setStyleSheet(buildBlueInputStyle());
    processTopBarLayout->addWidget(processFilterEdit_, 1);

    processCountLabel_ = new QLabel(processPanel);
    processCountLabel_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
    processTopBarLayout->addWidget(processCountLabel_);

    processLayout->addLayout(processTopBarLayout);

    processTable_ = new ks::ui::VisibleTableWidget(processPanel);
    processTable_->setColumnCount(5);
    processTable_->setHorizontalHeaderLabels(QStringList{ "进程名", "PID", "会话ID", "CPU(可选)", "工作集" });
    processTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    processTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    processTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    processTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    processTable_->setSortingEnabled(true);
    processTable_->setAlternatingRowColors(true);
    processTable_->verticalHeader()->setVisible(false);
    processTable_->verticalHeader()->setDefaultSectionSize(20);
    // Uniformly scale process icons to 16x16 to ensure row height remains compact.
    processTable_->setIconSize(QSize(16, 16));
    // Session ID and working set are displayed. The working set is the only immediately visible difference between processes with the
    // same name: the memory usage of the main process and auxiliary processes typically differs by one or two orders of magnitude. Today,
    // this is exactly how we identified the target among ten QQ processes with the same name. The CPU column remains hidden: it has never
    // been populated and is always 0.00%. Displaying it would only add a column of useless data, which is worse than hiding it.
    processTable_->setColumnHidden(2, false);
    processTable_->setColumnHidden(3, true);
    processTable_->setColumnHidden(4, false);
    processTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    processTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    processTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    processTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    processTable_->setShowGrid(true);
    processLayout->addWidget(processTable_, 1);

    QWidget* modulePanel = new QWidget(splitter);
    QVBoxLayout* moduleLayout = new QVBoxLayout(modulePanel);
    moduleLayout->setContentsMargins(0, 0, 0, 0);
    moduleLayout->setSpacing(4);

    // Module area layout alignment for ProcessDetailWindow: Refresh button + Signature options + Status + Module table.
    QHBoxLayout* moduleTopBarLayout = new QHBoxLayout();
    moduleTopBarLayout->setContentsMargins(0, 0, 0, 0);
    moduleTopBarLayout->setSpacing(8);

    moduleRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新模块", modulePanel);
    moduleRefreshButton_->setStyleSheet(buildBlueButtonStyle());
    moduleSignatureCheck_ = new QCheckBox("刷新时校验签名", modulePanel);
    moduleSignatureCheck_->setChecked(true);
    moduleSignatureCheck_->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(ksword_theme::textPrimaryHex()));

    moduleTopBarLayout->addWidget(moduleRefreshButton_);
    moduleTopBarLayout->addWidget(moduleSignatureCheck_);

    moduleFilterEdit_ = new QLineEdit(modulePanel);
    moduleFilterEdit_->setPlaceholderText("按模块路径过滤关键字");
    moduleFilterEdit_->setStyleSheet(buildBlueInputStyle());
    moduleTopBarLayout->addWidget(moduleFilterEdit_, 1);

    moduleStatusLabel_ = new QLabel("● 待刷新", modulePanel);
    moduleStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
            .arg(ksword_theme::textSecondaryHex()));
    moduleTopBarLayout->addWidget(moduleStatusLabel_);
    moduleLayout->addLayout(moduleTopBarLayout);

    moduleTable_ = new QTreeWidget(modulePanel);
    moduleTable_->setColumnCount(static_cast<int>(ModuleTreeColumn::kCount));
    moduleTable_->setHeaderLabels(kModuleTreeHeaders);
    moduleTable_->setRootIsDecorated(false);
    moduleTable_->setItemsExpandable(false);
    moduleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    moduleTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    moduleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    moduleTable_->setAlternatingRowColors(true);
    moduleTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    moduleTable_->setSortingEnabled(true);
    moduleTable_->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::kPath), 460);
    moduleTable_->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::kSize), 110);
    moduleTable_->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::kSignature), 220);
    moduleTable_->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::kEntryOffset), 120);
    moduleTable_->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::kState), 100);
    moduleTable_->setColumnWidth(toModuleTreeColumnIndex(ModuleTreeColumn::kThreadId), 180);
    moduleLayout->addWidget(moduleTable_, 1);

    splitter->addWidget(processPanel);
    splitter->addWidget(modulePanel);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 5);

    tabLayout->addWidget(splitter, 1);
    tabWidget_->addTab(tabProcessModule_, "进程与模块");
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_, tabProcessModule_, QStringLiteral("memory.tab.process_module"), QStringLiteral("进程与模块"));
}

void MemoryDock::initializeMemoryRegionTab()
{
    // Tab2 initialization log: used to track the timing of memory region tab control initialization.
    KLogEvent tab2InitEvent;
    info << tab2InitEvent
        << "[MemoryDock] initializeMemoryRegionTab: 构建内存区域页面。"
        << eol;

    // Tab2: Memory regions.
    tabRegions_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabRegions_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // Action row: refresh button + keyword filter + result count, maintaining the same header structure as other pages.
    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(6);
    regionRefreshButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")), "刷新区域", tabRegions_);
    regionRefreshButton_->setToolTip("重新枚举当前附加进程的内存区域");
    regionFilterEdit_ = new QLineEdit(tabRegions_);
    regionFilterEdit_->setPlaceholderText("按基址、保护属性或映射文件路径过滤");
    regionFilterEdit_->setClearButtonEnabled(true);
    regionFilterEdit_->setToolTip("输入关键字后只显示匹配的区域行");
    regionStatusLabel_ = new QLabel("未附加进程。", tabRegions_);
    QFrame* regionActionSeparator = new QFrame(tabRegions_);
    regionActionSeparator->setFrameShape(QFrame::VLine);
    regionActionSeparator->setFrameShadow(QFrame::Sunken);
    actionLayout->addWidget(regionRefreshButton_);
    actionLayout->addWidget(regionActionSeparator);
    actionLayout->addWidget(regionFilterEdit_, 1);
    actionLayout->addWidget(regionStatusLabel_);
    tabLayout->addLayout(actionLayout);

    // The filter toggle is grouped to avoid crowding the action row.
    QGroupBox* filterGroup = new QGroupBox("过滤条件", tabRegions_);
    QHBoxLayout* filterLayout = new QHBoxLayout(filterGroup);
    filterLayout->setSpacing(10);
    regionCommittedOnlyCheck_ = new QCheckBox("仅已提交(MEM_COMMIT)", filterGroup);
    regionImageOnlyCheck_ = new QCheckBox("仅映像(IMAGE)", filterGroup);
    regionReadableOnlyCheck_ = new QCheckBox("仅可读", filterGroup);
    regionCommittedOnlyCheck_->setToolTip("只显示已实际分配物理内存的区域，隐藏仅保留未使用的区域");
    regionImageOnlyCheck_->setToolTip("只显示由 exe/dll 文件映射而来的内存区域");
    regionReadableOnlyCheck_->setToolTip("只显示当前可以读取的内存区域，隐藏不可访问的区域");
    regionCommittedOnlyCheck_->setChecked(true);
    regionReadableOnlyCheck_->setChecked(true);
    filterLayout->addWidget(regionCommittedOnlyCheck_);
    filterLayout->addWidget(regionImageOnlyCheck_);
    filterLayout->addWidget(regionReadableOnlyCheck_);
    filterLayout->addStretch(1);
    tabLayout->addWidget(filterGroup);

    regionTable_ = new ks::ui::VisibleTableWidget(tabRegions_);
    regionTable_->setColumnCount(6);
    regionTable_->setHorizontalHeaderLabels(QStringList{
        "基址", "大小", "保护属性", "状态", "类型", "映射文件"
        });
    regionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    regionTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    regionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    regionTable_->setAlternatingRowColors(true);
    regionTable_->setSortingEnabled(true);
    regionTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    regionTable_->verticalHeader()->setVisible(false);
    regionTable_->horizontalHeader()->setStretchLastSection(true);
    tabLayout->addWidget(regionTable_, 1);

    tabWidget_->addTab(tabRegions_, "内存区域");
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_, tabRegions_, QStringLiteral("memory.tab.regions"), QStringLiteral("内存区域"));
}

void MemoryDock::initializeMemorySearchTab()
{
    // Tab3 initialization log: used to locate the stage when memory search tab control anomalies occur.
    KLogEvent tab3InitEvent;
    info << tab3InitEvent
        << "[MemoryDock] initializeMemorySearchTab: 构建内存搜索页面。"
        << eol;

    // Tab3: Memory search.
    tabSearch_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabSearch_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    const QString kInputStyle = buildBlueInputStyle();
    const QString kComboStyle = buildBlueComboStyle();
    const QString kButtonStyle = buildBlueButtonStyle();

    // Search condition panel.
    QGroupBox* conditionGroup = new QGroupBox("搜索条件", tabSearch_);
    QGridLayout* conditionLayout = new QGridLayout(conditionGroup);
    conditionLayout->setHorizontalSpacing(8);
    conditionLayout->setVerticalSpacing(6);

    searchTypeCombo_ = new QComboBox(conditionGroup);
    searchTypeCombo_->addItem("字节", static_cast<int>(SearchValueType::kByte));
    searchTypeCombo_->addItem("2字节", static_cast<int>(SearchValueType::kInt16));
    searchTypeCombo_->addItem("4字节", static_cast<int>(SearchValueType::kInt32));
    searchTypeCombo_->addItem("8字节", static_cast<int>(SearchValueType::kInt64));
    searchTypeCombo_->addItem("浮点数", static_cast<int>(SearchValueType::kFloat32));
    searchTypeCombo_->addItem("双精度", static_cast<int>(SearchValueType::kFloat64));
    searchTypeCombo_->addItem("字节数组(支持??)", static_cast<int>(SearchValueType::kByteArray));
    searchTypeCombo_->addItem("ASCII字符串", static_cast<int>(SearchValueType::kStringAscii));
    searchTypeCombo_->addItem("Unicode字符串", static_cast<int>(SearchValueType::kStringUnicode));
    searchTypeCombo_->setStyleSheet(kComboStyle);

    searchValueEdit_ = new QLineEdit(conditionGroup);
    searchValueEdit_->setPlaceholderText("输入搜索值");
    searchValueEdit_->setStyleSheet(kInputStyle);

    searchRangeCombo_ = new QComboBox(conditionGroup);
    searchRangeCombo_->addItem("整个内存");
    searchRangeCombo_->addItem("自定义范围");
    searchRangeCombo_->setStyleSheet(kComboStyle);

    searchRangeStartEdit_ = new QLineEdit(conditionGroup);
    searchRangeEndEdit_ = new QLineEdit(conditionGroup);
    searchRangeStartEdit_->setPlaceholderText("起始地址");
    searchRangeEndEdit_->setPlaceholderText("结束地址");
    searchRangeStartEdit_->setStyleSheet(kInputStyle);
    searchRangeEndEdit_->setStyleSheet(kInputStyle);
    searchRangeStartEdit_->setEnabled(false);
    searchRangeEndEdit_->setEnabled(false);

    searchImageOnlyCheck_ = new QCheckBox("仅映像", conditionGroup);
    searchHeapOnlyCheck_ = new QCheckBox("仅堆(近似)", conditionGroup);
    searchStackOnlyCheck_ = new QCheckBox("仅栈(近似)", conditionGroup);
    searchTypeCombo_->setToolTip("选择要搜索的数据类型；类型必须和内存中实际存放的格式一致才能搜到");
    searchRangeCombo_->setToolTip("限定搜索的地址范围；选“自定义范围”后可填写右侧的起止地址");
    searchImageOnlyCheck_->setToolTip("只在 exe/dll 映射的内存中搜索");
    searchHeapOnlyCheck_->setToolTip("只在推测为堆（程序动态分配）的内存中搜索，判定为近似值");
    searchStackOnlyCheck_->setToolTip("只在推测为栈（函数局部变量）的内存中搜索，判定为近似值");

    firstScanButton_ = new QPushButton(QIcon(":/Icon/log_track.svg"), "首次扫描", conditionGroup);
    nextScanButton_ = new QPushButton(QIcon(":/Icon/codeeditor_find.svg"), "再次扫描", conditionGroup);
    resetScanButton_ = new QPushButton(QIcon(":/Icon/log_clear.svg"), "重置", conditionGroup);
    cancelScanButton_ = new QPushButton(QIcon(":/Icon/process_terminate.svg"), "取消扫描", conditionGroup);
    firstScanButton_->setToolTip("按上面的条件全新搜索一遍内存，得到初始结果集");
    nextScanButton_->setToolTip("在上次结果的基础上继续筛选，逐步缩小范围（需先完成首次扫描）");
    resetScanButton_->setToolTip("清空已有搜索结果，回到可重新首次扫描的状态");
    cancelScanButton_->setToolTip("中止正在进行的扫描");
    firstScanButton_->setStyleSheet(kButtonStyle);
    nextScanButton_->setStyleSheet(kButtonStyle);
    resetScanButton_->setStyleSheet(kButtonStyle);
    cancelScanButton_->setStyleSheet(kButtonStyle);
    nextScanButton_->setEnabled(false);
    cancelScanButton_->setEnabled(false);

    conditionLayout->addWidget(new QLabel("数据类型", conditionGroup), 0, 0);
    conditionLayout->addWidget(searchTypeCombo_, 0, 1);
    conditionLayout->addWidget(new QLabel("值", conditionGroup), 0, 2);
    conditionLayout->addWidget(searchValueEdit_, 0, 3, 1, 3);
    conditionLayout->addWidget(new QLabel("范围", conditionGroup), 1, 0);
    conditionLayout->addWidget(searchRangeCombo_, 1, 1);
    conditionLayout->addWidget(searchRangeStartEdit_, 1, 2);
    conditionLayout->addWidget(searchRangeEndEdit_, 1, 3);
    conditionLayout->addWidget(searchImageOnlyCheck_, 1, 4);
    conditionLayout->addWidget(searchHeapOnlyCheck_, 1, 5);
    conditionLayout->addWidget(searchStackOnlyCheck_, 1, 6);
    conditionLayout->addWidget(firstScanButton_, 2, 1);
    conditionLayout->addWidget(nextScanButton_, 2, 2);
    conditionLayout->addWidget(resetScanButton_, 2, 3);
    conditionLayout->addWidget(cancelScanButton_, 2, 4);

    tabLayout->addWidget(conditionGroup);

    QGroupBox* compareGroup = new QGroupBox("再次扫描过滤", tabSearch_);
    QHBoxLayout* compareLayout = new QHBoxLayout(compareGroup);
    compareLayout->setContentsMargins(8, 6, 8, 6);
    compareLayout->setSpacing(8);

    nextScanCompareCombo_ = new QComboBox(compareGroup);
    nextScanCompareCombo_->addItem("等于", static_cast<int>(SearchCompareMode::kEqual));
    nextScanCompareCombo_->addItem("大于", static_cast<int>(SearchCompareMode::kGreater));
    nextScanCompareCombo_->addItem("小于", static_cast<int>(SearchCompareMode::kLess));
    nextScanCompareCombo_->addItem("介于", static_cast<int>(SearchCompareMode::kBetween));
    nextScanCompareCombo_->addItem("变化", static_cast<int>(SearchCompareMode::kChanged));
    nextScanCompareCombo_->addItem("未变化", static_cast<int>(SearchCompareMode::kUnchanged));
    nextScanCompareCombo_->addItem("增加", static_cast<int>(SearchCompareMode::kIncreased));
    nextScanCompareCombo_->addItem("减少", static_cast<int>(SearchCompareMode::kDecreased));
    nextScanCompareCombo_->setStyleSheet(kComboStyle);
    nextScanCompareCombo_->setToolTip("再次扫描时的筛选方式：可按新值比较，也可按“变化/未变化/增加/减少”筛选");

    nextScanValueEdit_ = new QLineEdit(compareGroup);
    nextScanValueBEdit_ = new QLineEdit(compareGroup);
    nextScanValueEdit_->setPlaceholderText("值A");
    nextScanValueBEdit_->setPlaceholderText("值B");
    nextScanValueEdit_->setStyleSheet(kInputStyle);
    nextScanValueBEdit_->setStyleSheet(kInputStyle);
    nextScanValueBEdit_->setVisible(false);

    compareLayout->addWidget(new QLabel("条件", compareGroup));
    compareLayout->addWidget(nextScanCompareCombo_);
    compareLayout->addWidget(new QLabel("值", compareGroup));
    compareLayout->addWidget(nextScanValueEdit_, 1);
    compareLayout->addWidget(nextScanValueBEdit_, 1);
    tabLayout->addWidget(compareGroup);

    // Access backend selector: every region read on the scan page goes through the channel selected here.
    tabLayout->addWidget(
        createBackendSelector(tabSearch_, searchBackendCombo_, searchBackendHintLabel_));

    searchResultTable_ = new ks::ui::VisibleTableWidget(tabSearch_);
    searchResultTable_->setColumnCount(4);
    searchResultTable_->setHorizontalHeaderLabels(QStringList{ "地址", "当前值", "前次值", "备注" });
    searchResultTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    searchResultTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    searchResultTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    searchResultTable_->setAlternatingRowColors(true);
    searchResultTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    // The result table allows column sorting by default; during batch population, rebuildSearchResultTable temporarily disables and then restores it.
    searchResultTable_->setSortingEnabled(true);
    searchResultTable_->verticalHeader()->setVisible(false);
    searchResultTable_->horizontalHeader()->setStretchLastSection(true);
    tabLayout->addWidget(searchResultTable_, 1);

    QHBoxLayout* progressLayout = new QHBoxLayout();
    progressLayout->setContentsMargins(0, 0, 0, 0);
    progressLayout->setSpacing(8);
    scanProgressBar_ = new QProgressBar(tabSearch_);
    scanProgressBar_->setRange(0, 100);
    scanStatusLabel_ = new QLabel("就绪", tabSearch_);
    progressLayout->addWidget(scanProgressBar_, 1);
    progressLayout->addWidget(scanStatusLabel_);
    tabLayout->addLayout(progressLayout);

    tabWidget_->addTab(tabSearch_, "内存搜索");
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_, tabSearch_, QStringLiteral("memory.tab.search"), QStringLiteral("内存搜索"));
}

void MemoryDock::initializeMemoryViewerTab()
{
    // Tab4 initialization log: Marks the creation of the hex viewer control.
    KLogEvent tab4InitEvent;
    info << tab4InitEvent
        << "[MemoryDock] initializeMemoryViewerTab: 构建内存查看器页面。"
        << eol;

    // Tab4: Memory viewer.
    tabViewer_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabViewer_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    QHBoxLayout* navLayout = new QHBoxLayout();
    navLayout->setContentsMargins(0, 0, 0, 0);
    navLayout->setSpacing(8);
    navLayout->addWidget(new QLabel("地址:", tabViewer_));
    viewAddressEdit_ = new QLineEdit(tabViewer_);
    viewAddressEdit_->setPlaceholderText("输入地址后跳转，默认十六进制");
    viewAddressEdit_->setStyleSheet(buildBlueInputStyle());
    viewJumpButton_ = new QPushButton(QIcon(":/Icon/codeeditor_goto.svg"), "跳转", tabViewer_);
    viewJumpButton_->setStyleSheet(buildBlueButtonStyle());
    viewJumpButton_->setToolTip("跳转到左侧输入的内存地址并显示该处内容。地址无前缀时按十六进制解释。");
    viewProtectLabel_ = new QLabel("保护属性: -", tabViewer_);
    navLayout->addWidget(viewAddressEdit_, 1);
    navLayout->addWidget(viewJumpButton_);
    navLayout->addWidget(viewProtectLabel_);
    tabLayout->addLayout(navLayout);

    // Access backend selector: retrieves data from the selected channel when the viewer pages.
    tabLayout->addWidget(
        createBackendSelector(tabViewer_, viewerBackendCombo_, viewerBackendHintLabel_));

    // Unified hex editor component:
    // - Subsequent memory/file/network operations will all reuse this control.
    // - Tab4 is configured here to 16 bytes per row, read-only by default.
    hexEditorWidget_ = new HexEditorWidget(tabViewer_);
    hexEditorWidget_->setBytesPerRow(16);
    hexEditorWidget_->setEditable(false);
    tabLayout->addWidget(hexEditorWidget_, 1);

    viewerStatusLabel_ = new QLabel("未附加进程。", tabViewer_);
    tabLayout->addWidget(viewerStatusLabel_);

    tabWidget_->addTab(tabViewer_, "内存查看器");
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_, tabViewer_, QStringLiteral("memory.tab.viewer"), QStringLiteral("内存查看器"));
}

void MemoryDock::initializeBreakpointBookmarkTab()
{
    // Tab5 initialization log: Records the start of building the breakpoint and bookmark page.
    KLogEvent tab5InitEvent;
    info << tab5InitEvent
        << "[MemoryDock] initializeBreakpointBookmarkTab: 构建断点与书签页面。"
        << eol;

    // Tab5: Breakpoints and bookmarks.
    tabBpBookmark_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabBpBookmark_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    QSplitter* splitter = new QSplitter(Qt::Vertical, tabBpBookmark_);
    const QString kButtonStyle = buildBlueButtonStyle();

    QWidget* breakpointPanel = new QWidget(splitter);
    QVBoxLayout* breakpointLayout = new QVBoxLayout(breakpointPanel);
    breakpointLayout->setContentsMargins(0, 0, 0, 0);
    breakpointLayout->setSpacing(4);

    QHBoxLayout* bpButtonLayout = new QHBoxLayout();
    bpButtonLayout->setContentsMargins(0, 0, 0, 0);
    bpButtonLayout->setSpacing(6);
    addBreakpointButton_ = new QPushButton(QIcon(":/Icon/plus.svg"), "添加断点", breakpointPanel);
    removeBreakpointButton_ = new QPushButton(QIcon(":/Icon/log_clear.svg"), "删除断点", breakpointPanel);
    toggleBreakpointButton_ = new QPushButton(QIcon(":/Icon/process_pause.svg"), "启用/禁用", breakpointPanel);
    addBreakpointButton_->setToolTip("在指定地址下断点，目标进程执行到该处时会中断");
    removeBreakpointButton_->setToolTip("删除选中的断点并恢复该处的原始字节");
    toggleBreakpointButton_->setToolTip("临时启用或停用选中的断点，不删除该条记录");
    addBreakpointButton_->setStyleSheet(kButtonStyle);
    removeBreakpointButton_->setStyleSheet(kButtonStyle);
    toggleBreakpointButton_->setStyleSheet(kButtonStyle);
    bpButtonLayout->addWidget(addBreakpointButton_);
    bpButtonLayout->addWidget(removeBreakpointButton_);
    bpButtonLayout->addWidget(toggleBreakpointButton_);
    bpButtonLayout->addStretch(1);
    breakpointLayout->addLayout(bpButtonLayout);

    breakpointTable_ = new ks::ui::VisibleTableWidget(breakpointPanel);
    breakpointTable_->setColumnCount(5);
    breakpointTable_->setHorizontalHeaderLabels(QStringList{ "地址", "原字节", "状态", "命中次数", "描述" });
    breakpointTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    breakpointTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    breakpointTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    breakpointTable_->setAlternatingRowColors(true);
    breakpointTable_->verticalHeader()->setVisible(false);
    breakpointTable_->horizontalHeader()->setStretchLastSection(true);
    installMemoryUtilityCopyMenu(breakpointTable_);
    breakpointLayout->addWidget(breakpointTable_, 1);

    QWidget* bookmarkPanel = new QWidget(splitter);
    QVBoxLayout* bookmarkLayout = new QVBoxLayout(bookmarkPanel);
    bookmarkLayout->setContentsMargins(0, 0, 0, 0);
    bookmarkLayout->setSpacing(4);

    QHBoxLayout* bmButtonLayout = new QHBoxLayout();
    bmButtonLayout->setContentsMargins(0, 0, 0, 0);
    bmButtonLayout->setSpacing(6);
    addBookmarkButton_ = new QPushButton(QIcon(":/Icon/plus.svg"), "添加书签", bookmarkPanel);
    removeBookmarkButton_ = new QPushButton(QIcon(":/Icon/log_clear.svg"), "删除书签", bookmarkPanel);
    refreshBookmarkButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新值", bookmarkPanel);
    jumpBookmarkButton_ = new QPushButton(QIcon(":/Icon/codeeditor_goto.svg"), "跳转", bookmarkPanel);
    addBookmarkButton_->setToolTip("把当前地址收藏为书签，便于之后快速回到该位置");
    removeBookmarkButton_->setToolTip("删除选中的书签");
    refreshBookmarkButton_->setToolTip("重新读取所有书签地址处的当前值");
    jumpBookmarkButton_->setToolTip("在内存查看器中跳转到选中书签的地址");
    addBookmarkButton_->setStyleSheet(kButtonStyle);
    removeBookmarkButton_->setStyleSheet(kButtonStyle);
    refreshBookmarkButton_->setStyleSheet(kButtonStyle);
    jumpBookmarkButton_->setStyleSheet(kButtonStyle);
    bmButtonLayout->addWidget(addBookmarkButton_);
    bmButtonLayout->addWidget(removeBookmarkButton_);
    bmButtonLayout->addWidget(refreshBookmarkButton_);
    bmButtonLayout->addWidget(jumpBookmarkButton_);
    bmButtonLayout->addStretch(1);
    bookmarkLayout->addLayout(bmButtonLayout);

    bookmarkTable_ = new ks::ui::VisibleTableWidget(bookmarkPanel);
    bookmarkTable_->setColumnCount(4);
    bookmarkTable_->setHorizontalHeaderLabels(QStringList{ "地址", "当前值", "备注", "添加时间" });
    bookmarkTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    bookmarkTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    bookmarkTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    bookmarkTable_->setAlternatingRowColors(true);
    bookmarkTable_->verticalHeader()->setVisible(false);
    bookmarkTable_->horizontalHeader()->setStretchLastSection(true);
    installMemoryUtilityCopyMenu(bookmarkTable_);
    bookmarkLayout->addWidget(bookmarkTable_, 1);

    splitter->addWidget(breakpointPanel);
    splitter->addWidget(bookmarkPanel);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 5);
    tabLayout->addWidget(splitter, 1);

    tabWidget_->addTab(tabBpBookmark_, "断点与书签");
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_, tabBpBookmark_, QStringLiteral("memory.tab.breakpoints_bookmarks"), QStringLiteral("断点与书签"));
}

void MemoryDock::initializeDriverMemoryRwTab()
{
    // Tab6 initialization log: Records the start of building driver memory read/write pages.
    KLogEvent tab6InitEvent;
    info << tab6InitEvent
        << "[MemoryDock] initializeDriverMemoryRwTab: 构建驱动内存读写页面。"
        << eol;

    // Tab6: Driver memory read/write, separated from the original Win32 viewer to prevent editing from writing directly to real memory.
    tabDriverMemoryRw_ = new QWidget(tabWidget_);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabDriverMemoryRw_);
    tabLayout->setContentsMargins(6, 6, 6, 6);
    tabLayout->setSpacing(6);

    // ========================================================
    // Target group: source channel, target object, address, and read budget.
    // ========================================================

    QGroupBox* requestGroup = new QGroupBox("读取目标", tabDriverMemoryRw_);
    QGridLayout* requestLayout = new QGridLayout(requestGroup);
    requestLayout->setHorizontalSpacing(8);
    requestLayout->setVerticalSpacing(6);

    // The source dropdown determines which R0 channel to use; item order must match DriverMemorySourceMode.
    driverMemorySourceCombo_ = new QComboBox(requestGroup);
    driverMemorySourceCombo_->addItem("进程虚拟内存");
    driverMemorySourceCombo_->addItem("内核虚拟内存");
    driverMemorySourceCombo_->addItem("物理内存");
    driverMemorySourceCombo_->setToolTip(
        "选择读写通道：进程虚拟内存按 PID 定位；内核虚拟内存直接使用内核地址；"
        "物理内存绕过页表，单次读上限 64 KB、写上限 4 KB。");

    driverMemoryBaseCombo_ = new PopupLifecycleGuardedComboBox(
        requestGroup,
        [this](const bool active) {
            driverMemoryBaseComboPopupLifecycleActive_ = active;
            if (!active)
            {
                flushProcessComboDeferredCommit();
            }
            });
    driverMemoryBaseCombo_->setEditable(true);
    driverMemoryBaseCombo_->setMinimumWidth(260);
    driverMemoryBaseCombo_->setToolTip(
        "可输入 0、0x... 数值基址，或“模块名+十六进制偏移”（例如 client.dll+C125D9 或 CI.dll+1A2B）；"
        "其它非 0x 文本按进程名/PID 从下拉列表筛选目标进程。用户态模块取自当前附加进程，"
        "内核模块取自“刷新内核模块”得到的列表。中心地址为 0xFFFF... 高半区时自动按内核虚拟地址读取。");
    driverMemoryBaseCombo_->addItem("0", QVariant::fromValue(static_cast<uint>(0U)));
    driverMemoryBaseCombo_->setItemData(0, QString(), Qt::UserRole + 1);

    if (driverMemoryBaseCombo_->lineEdit() != nullptr)
    {
        driverMemoryBaseCombo_->lineEdit()->setPlaceholderText("0 / 0x基址 / 模块+偏移 / 进程名或PID");
    }

    // The kernel module list is loaded on demand: no cost is incurred to enumerate all kernel modules unless this button is clicked.
    driverMemoryKernelModuleRefreshButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")), "刷新内核模块", requestGroup);
    driverMemoryKernelModuleRefreshButton_->setToolTip(
        "枚举系统已加载的内核模块，之后即可用“CI.dll+偏移”这类表达式直接定位内核地址。");

    driverMemoryAddressEdit_ = new QLineEdit(requestGroup);
    driverMemoryAddressEdit_->setPlaceholderText("用户态有效地址/偏移，或 0xFFFF... 内核虚拟地址，或物理地址");
    driverMemoryAddressEdit_->setClearButtonEnabled(true);

    driverMemoryBeforeSpin_ = new QSpinBox(requestGroup);
    driverMemoryBeforeSpin_->setRange(0, static_cast<int>(KSWORD_ARK_MEMORY_READ_MAX_BYTES / 2UL));
    driverMemoryBeforeSpin_->setValue(1024);
    driverMemoryBeforeSpin_->setSuffix(" B");
    driverMemoryBeforeSpin_->setToolTip("从中心地址往前额外读取的字节数");

    driverMemoryAfterSpin_ = new QSpinBox(requestGroup);
    driverMemoryAfterSpin_->setRange(1, static_cast<int>(KSWORD_ARK_MEMORY_READ_MAX_BYTES / 2UL));
    driverMemoryAfterSpin_->setValue(1024);
    driverMemoryAfterSpin_->setSuffix(" B");
    driverMemoryAfterSpin_->setToolTip("从中心地址往后额外读取的字节数");

    driverMemoryReadButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_details.svg")), "R0 读取", requestGroup);
    driverMemoryReadButton_->setToolTip(
        "通过驱动以内核权限读取上述范围的内存，可读取普通方式无法访问的地址");

    requestLayout->addWidget(new QLabel("来源", requestGroup), 0, 0);
    requestLayout->addWidget(driverMemorySourceCombo_, 0, 1);
    requestLayout->addWidget(new QLabel("目标", requestGroup), 0, 2);
    requestLayout->addWidget(driverMemoryBaseCombo_, 0, 3, 1, 2);
    requestLayout->addWidget(driverMemoryKernelModuleRefreshButton_, 0, 5);
    requestLayout->addWidget(new QLabel("中心地址", requestGroup), 1, 0);
    requestLayout->addWidget(driverMemoryAddressEdit_, 1, 1, 1, 4);
    requestLayout->addWidget(driverMemoryReadButton_, 1, 5);
    requestLayout->addWidget(new QLabel("向前", requestGroup), 2, 0);
    requestLayout->addWidget(driverMemoryBeforeSpin_, 2, 1);
    requestLayout->addWidget(new QLabel("向后", requestGroup), 2, 2);
    requestLayout->addWidget(driverMemoryAfterSpin_, 2, 3);
    // Make the combo box and address field consume extra width, while keeping the button column at its intrinsic size.
    requestLayout->setColumnStretch(1, 1);
    requestLayout->setColumnStretch(3, 2);
    requestLayout->setColumnStretch(4, 1);
    tabLayout->addWidget(requestGroup);

    // Access backend selector: Both R0 reads and difference write-backs on this page go through the channel selected here.
    // It is an orthogonal dimension to the 'Source' dropdown above: 'Source' determines 'which address space to
    // read', while 'Backend' determines 'which path to use for reading'; do not merge them into a single dropdown.
    tabLayout->addWidget(createBackendSelector(
        tabDriverMemoryRw_, driverMemoryBackendCombo_, driverMemoryBackendHintLabel_));

    // ========================================================
    // Action button bar: Write-back, Clear, Dump, String write.
    // ========================================================

    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(6);

    driverMemoryApplyButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/disk_save.svg")), "应用差异到真实内存", tabDriverMemoryRw_);
    driverMemoryApplyButton_->setToolTip(
        "把下方编辑器中改动过的字节写回目标内存。这会真实修改进程或内核数据，"
        "内核路径带事务与失败回滚，用户态与物理内存路径没有回滚。");
    driverMemoryApplyButton_->setEnabled(false);

    driverMemoryResetButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")), "清空缓存", tabDriverMemoryRw_);
    driverMemoryResetButton_->setToolTip("丢弃已读取的缓存与未应用的改动");

    driverMemoryDumpButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_export.svg")), "转存到文件", tabDriverMemoryRw_);
    driverMemoryDumpButton_->setToolTip(
        "把当前快照写入磁盘。保存为 .txt 时输出带地址与 ASCII 的十六进制转储，其余扩展名写原始字节。");

    driverMemoryWriteStringButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/codeeditor_paste.svg")), "字符串写入", tabDriverMemoryRw_);
    driverMemoryWriteStringButton_->setToolTip(
        "按 ANSI 或 UTF-16LE 把一段字符串填入编辑缓存，确认后再用“应用差异到真实内存”写回。");

    actionLayout->addWidget(driverMemoryApplyButton_);
    actionLayout->addWidget(driverMemoryResetButton_);
    actionLayout->addWidget(driverMemoryDumpButton_);
    actionLayout->addWidget(driverMemoryWriteStringButton_);
    actionLayout->addStretch(1);
    tabLayout->addLayout(actionLayout);

    // ========================================================
    // View toolbar: three-view switching + text encoding + current range
    // ========================================================

    QHBoxLayout* viewBarLayout = new QHBoxLayout();
    viewBarLayout->setContentsMargins(0, 0, 0, 0);
    viewBarLayout->setSpacing(4);

    // The three segmented buttons are mutually exclusive, equivalent to the HexDump / Disassembly / TextView radio group in OpenArk.
    const auto kMakeViewButton = [this](const QString& iconAlias,
                                       const QString& labelText,
                                       const QString& tipText) {
        QToolButton* viewButton = new QToolButton(tabDriverMemoryRw_);
        viewButton->setIcon(QIcon(iconAlias));
        viewButton->setText(labelText);
        viewButton->setToolTip(tipText);
        viewButton->setCheckable(true);
        viewButton->setAutoExclusive(true);
        viewButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        return viewButton;
    };
    driverMemoryHexViewButton_ = kMakeViewButton(
        QStringLiteral(":/Icon/process_list.svg"), "十六进制",
        "以十六进制与 ASCII 对照展示，可直接编辑字节");
    driverMemoryDisasmViewButton_ = kMakeViewButton(
        QStringLiteral(":/Icon/log_track.svg"), "反汇编",
        "把当前缓存按目标位数解码成指令，只读展示");
    driverMemoryTextViewButton_ = kMakeViewButton(
        QStringLiteral(":/Icon/codeeditor_wrap.svg"), "文本",
        "按选定编码把缓存渲染成可打印文本，只读展示");
    driverMemoryHexViewButton_->setChecked(true);

    driverMemoryTextEncodingCombo_ = new QComboBox(tabDriverMemoryRw_);
    driverMemoryTextEncodingCombo_->addItem("单字节");
    driverMemoryTextEncodingCombo_->addItem("UTF-16LE");
    driverMemoryTextEncodingCombo_->setToolTip("文本视图使用的解码方式");

    // The vertical line separator visually separates the view switch from other controls.
    QFrame* viewBarSeparator = new QFrame(tabDriverMemoryRw_);
    viewBarSeparator->setFrameShape(QFrame::VLine);
    viewBarSeparator->setFrameShadow(QFrame::Sunken);

    driverMemoryRangeLabel_ = new QLabel("范围: 未读取", tabDriverMemoryRw_);
    driverMemoryRangeLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    viewBarLayout->addWidget(driverMemoryHexViewButton_);
    viewBarLayout->addWidget(driverMemoryDisasmViewButton_);
    viewBarLayout->addWidget(driverMemoryTextViewButton_);
    viewBarLayout->addWidget(viewBarSeparator);
    viewBarLayout->addWidget(new QLabel("文本编码", tabDriverMemoryRw_));
    viewBarLayout->addWidget(driverMemoryTextEncodingCombo_);
    viewBarLayout->addWidget(driverMemoryRangeLabel_, 1);
    tabLayout->addLayout(viewBarLayout);

    // ========================================================
    // View stack: push order must match DriverMemoryViewMode.
    // ========================================================

    driverMemoryViewStack_ = new QStackedWidget(tabDriverMemoryRw_);

    // The HexEditor allows editing on this page, but byteEdited only updates the R3 cache, not the target process directly.
    driverMemoryHexEditor_ = new HexEditorWidget(driverMemoryViewStack_);
    driverMemoryHexEditor_->setBytesPerRow(16);
    driverMemoryHexEditor_->setEditable(true);
    driverMemoryViewStack_->addWidget(driverMemoryHexEditor_);

    // Disassembly page: top row shows backend description, below is the instruction table.
    QWidget* disasmPage = new QWidget(driverMemoryViewStack_);
    QVBoxLayout* disasmLayout = new QVBoxLayout(disasmPage);
    disasmLayout->setContentsMargins(0, 0, 0, 0);
    disasmLayout->setSpacing(4);
    driverMemoryDisasmBackendLabel_ = new QLabel(
        "尚未读取内存，先在上方设置目标并点击“R0 读取”。", disasmPage);
    driverMemoryDisasmBackendLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    driverMemoryDisasmBackendLabel_->setWordWrap(true);
    disasmLayout->addWidget(driverMemoryDisasmBackendLabel_);

    // Use VisibleTableWidget instead of a raw QTableWidget to access the global action bar and frozen rows/columns.
    driverMemoryDisasmTable_ = new ks::ui::VisibleTableWidget(disasmPage);
    driverMemoryDisasmTable_->setColumnCount(5);
    driverMemoryDisasmTable_->setHorizontalHeaderLabels(
        QStringList{ "地址", "偏移", "原始字节", "助记符", "操作数" });
    driverMemoryDisasmTable_->setAlternatingRowColors(true);
    driverMemoryDisasmTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    driverMemoryDisasmTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    driverMemoryDisasmTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    driverMemoryDisasmTable_->setSortingEnabled(true);
    driverMemoryDisasmTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    driverMemoryDisasmTable_->verticalHeader()->setVisible(false);
    driverMemoryDisasmTable_->verticalHeader()->setDefaultSectionSize(22);
    disasmLayout->addWidget(driverMemoryDisasmTable_, 1);
    driverMemoryViewStack_->addWidget(disasmPage);

    // Text page: read-only code editor; content is always written via setRawText and is not included in localization.
    driverMemoryTextView_ = new CodeEditorWidget(driverMemoryViewStack_);
    driverMemoryTextView_->setReadOnly(true);
    driverMemoryTextView_->setRawText(
        QStringLiteral("尚未读取内存，先在上方设置目标并点击“R0 读取”。"));
    driverMemoryViewStack_->addWidget(driverMemoryTextView_);

    driverMemoryViewStack_->setCurrentIndex(static_cast<int>(DriverMemoryViewMode::kHex));
    tabLayout->addWidget(driverMemoryViewStack_, 1);

    driverMemoryStatusLabel_ = new QLabel("等待读取。", tabDriverMemoryRw_);
    driverMemoryStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    driverMemoryStatusLabel_->setWordWrap(true);
    tabLayout->addWidget(driverMemoryStatusLabel_);

    // Dangerous buttons and status labels use semantic colors; construction and theme switching follow the same dispatch path.
    applyMemoryDockSemanticStyles();

    tabWidget_->addTab(tabDriverMemoryRw_, "驱动内存读写");
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_, tabDriverMemoryRw_, QStringLiteral("memory.tab.driver_memory_rw"), QStringLiteral("驱动内存读写"));
}
