
#include "KernelDock.h"
#include "../ui/VisibleTableWidget.h"

// ============================================================
// KernelDock.cpp
// Purpose:
// 1) Implement the top-level UI tabs for the Kernel Dock (object namespace / atom table / SSDT / historical NtQuery / driver callbacks);
// 2) Implement asynchronous refresh, filtering, detail linkage, and right-click menus;
// 3) The specific low-level enumeration logic is placed in the Worker file; this file handles only UI and interaction orchestration.
// ============================================================

#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "KernelBaseNamedObjectsTab.h"
#include "KernelDockCidTab.h"
#include "KernelDescriptorTableTab.h"
#include "KernelSlatIommuAuditTab.h"
#include "KernelTextIntegrityTab.h"
#include "KernelVbsPostureTab.h"
#include "KernelDockIpcTab.h"
#include "KernelDeviceDriverObjectsTab.h"
#include "KernelIoTimerTab.h"
#include "KernelIoctlAuditTab.h"
#include "KernelIoctlDecoderTab.h"
#include "KernelKnowledgeTab.h"
#include "KernelObjectDirectoryDeepTab.h"
#include "KernelObjectTypeMatrixTab.h"
#include "KernelPlatformAuditTab.h"
#include "KernelSymbolicLinkTab.h"
#include "KernelThreadAuditTab.h"
#include "../settings_dock/AppearanceSettings.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QEventLoop>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QModelIndex>
#include <QPainter>
#include <QPixmap>
#include <QProgressBar>
#include <QPushButton>
#include <QSplitter>
#include <QShowEvent>
#include <QSvgRenderer>
#include <QTableWidget>
#include <QTabWidget>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // blueButtonStyle：
    // - Purpose: Unify icon button styles (including hover and pressed states).
    QString blueButtonStyle()
    {
        return ksword_theme::themedButtonStyle();
    }

    // blueInputStyle：
    // - Purpose: Unified filter input box style.
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // headerStyle：
    // - Purpose: Unify header styles to enhance column title readability.
    QString headerStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::borderHex());
    }

    // itemSelectionStyle：
    // - Purpose: Unifies selection highlighting for table/tree controls to the theme blue, avoiding system default color variations.
    QString itemSelectionStyle()
    {
        return QStringLiteral(
            "QTreeWidget::item:selected{background:%1;color:palette(highlighted-text);}")
            .arg(ksword_theme::kPrimaryBlueHex);
    }

    // tableRowAsTsv：
    // - Input tableWidget is a read-only table, and rowIndex is the current visible row;
    // - Processing: Extract cell text in column order, using <Empty> as a placeholder for null values, with fields separated by tabs.
    // - Returns: TSV suitable for pasting into a text editor or spreadsheet; returns an empty string if input is invalid.
    QString tableRowAsTsv(const QTableWidget* tableWidget, const int rowIndex)
    {
        if (tableWidget == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
        {
            return QString();
        }

        QStringList fieldList;
        fieldList.reserve(tableWidget->columnCount());
        for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* cellItem = tableWidget->item(rowIndex, columnIndex);
            fieldList.push_back(cellItem != nullptr && !cellItem->text().trimmed().isEmpty()
                ? cellItem->text()
                : kernelText("kernel.main.placeholder.empty", QStringLiteral("<空>")));
        }
        return fieldList.join('\t');
    }

    // showCopyRowContextMenu：
    // - Input tableWidget: Target table; localPosition: Right-click position; selectClickedRow: Controls whether to synchronize the current row.
    // - Processing: Display an explicitly themed context menu and copy the current/clicked row as TSV.
    // - Return: None; silently skips if the clipboard is unavailable or the row is invalid.
    void showCopyRowContextMenu(
        QTableWidget* tableWidget,
        const QPoint& localPosition,
        const bool selectClickedRow)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        const QModelIndex kClickedIndex = tableWidget->indexAt(localPosition);
        int rowIndex = kClickedIndex.isValid() ? kClickedIndex.row() : tableWidget->currentRow();
        if (selectClickedRow && kClickedIndex.isValid())
        {
            tableWidget->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
            rowIndex = kClickedIndex.row();
        }

        QMenu contextMenu(tableWidget);
        contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());

        QAction* copyRowAction = contextMenu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            kernelText("kernel.main.menu.copy_row", QStringLiteral("复制当前行")));
        copyRowAction->setEnabled(rowIndex >= 0);

        const QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
        if (selectedAction != copyRowAction || rowIndex < 0)
        {
            return;
        }

        QClipboard* clipboard = QApplication::clipboard();
        const QString kRowText = tableRowAsTsv(tableWidget, rowIndex);
        if (clipboard != nullptr && !kRowText.isEmpty())
        {
            clipboard->setText(kRowText);
        }
    }

    // statusLabelStyle：
    // - Purpose: Unify the color and font weight of status labels.
    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // ObjectNamespaceColumn: Object namespace tree column indices.
    enum class ObjectNamespaceColumn : int
    {
        kName = 0,
        kType,
        kPathOrScope,
        kStatus,
        kSymbolicTarget,
        kCount
    };

    // AtomColumn: Atom table column index.
    enum class AtomColumn : int
    {
        kValue = 0,
        kHex,
        kName,
        kSource,
        kStatus,
        kCount
    };

    // NtQueryColumn: Historical NtQuery table column index.
    enum class NtQueryColumn : int
    {
        kCategory = 0,
        kFunction,
        kQueryItem,
        kStatus,
        kSummary,
        kCount
    };

    // tintedSvgIcon：
    // - Purpose: Render resource SVGs into icons with a specified color for high-contrast display in the selected Tab state.
    // - Parameters: iconPath (resource path), tintColor (target color), iconSize (output size).
    QIcon tintedSvgIcon(const QString& iconPath, const QColor& tintColor, const QSize& iconSize = QSize(16, 16))
    {
        QSvgRenderer svgRenderer(iconPath);
        if (!svgRenderer.isValid())
        {
            return QIcon(iconPath);
        }

        QPixmap tintedPixmap(iconSize);
        tintedPixmap.fill(Qt::transparent);

        QPainter painter(&tintedPixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        svgRenderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(tintedPixmap.rect(), tintColor);
        painter.end();

        return QIcon(tintedPixmap);
    }

    // tabIcon：
    // - Purpose: Return a standard Tab icon, keeping the unselected state consistent with the project's icon resources.
    // - Variable iconPath: Icon resource path, placed uniformly at the call site for easier review.
    QIcon tabIcon(const QString& iconPath)
    {
        return tintedSvgIcon(iconPath, ksword_theme::primaryBlueColor);
    }

    // selectedTabIcon：
    // - Purpose: Return a white Tab icon to prevent blue-on-blue appearance when the selected tab has a blue background.
    QIcon selectedTabIcon(const QString& iconPath)
    {
        return tintedSvgIcon(iconPath, ksword_theme::onAccentColor());
    }

}

KernelDock::KernelDock(QWidget* parent)
    : QWidget(parent)
{
    KLogEvent initEvent;
    info << initEvent << "[KernelDock] 构造开始，准备初始化五页内核视图。" << eol;

    initializeUi();
    initializeConnections();

    // Initial screen tab must be initialized synchronously:
    // - KernelDock is often restored as the active dock by ADS; in this case, the show/currentChanged sequence may not trigger internal page initialization.
    // - Only initialize the current page, avoiding full construction of other heavy pages to completely prevent 'Kernel Dock black screen / no UI'.
    ensureTabInitialized(tabWidget_ != nullptr ? tabWidget_->currentIndex() : -1);

    // Add another 0ms fallback to cover cases where currentIndex changes later due to theme/ADS delayed restoration.
    QTimer::singleShot(0, this, [this]() {
        ensureTabInitialized(tabWidget_ != nullptr ? tabWidget_->currentIndex() : -1);
    });

    info << initEvent << "[KernelDock] 构造完成。" << eol;
}

QWidget* KernelDock::kswordSelfDriverPage() const
{
    // Return value: Non-owned pointer; page business state is still maintained by the current KernelDock instance.
    return selfDriverPage_;
}

bool KernelDock::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == selfDriverPage_ &&
        event != nullptr &&
        (event->type() == QEvent::Show ||
         event->type() == QEvent::ShowToParent))
    {
        ensureSelfDriverCurrentTabRefreshed();
    }
    return QWidget::eventFilter(watched, event);
}

void KernelDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    // Note: After ADS restores the layout, the internal QTabWidget of KernelDock may already be displayed, but the first tab has not yet been initialized.
    // Idempotent fallback in showEvent to ensure the current internal tab has actual UI content.
    ensureCurrentTabReadyForDisplay();
    QTimer::singleShot(0, this, [this]() {
        ensureCurrentTabReadyForDisplay();
    });
}

void KernelDock::ensureCurrentTabReadyForDisplay()
{
    if (tabWidget_ == nullptr)
    {
        return;
    }

    // ADS restoreState restores the outer Dock's activation state, but may not re-trigger the internal QTabWidget
    // currentChanged. This is actively called by mainWindow/showEvent to ensure the current page has real child controls.
    ensureTabInitialized(tabWidget_->currentIndex());
    tabWidget_->updateGeometry();
    tabWidget_->update();
    updateGeometry();
    update();
}

void KernelDock::focusProcessProtectTab()
{
    if (tabWidget_ == nullptr ||
        kernelAuditInnerTabWidget_ == nullptr ||
        kernelAuditTabIndex_ < 0 ||
        callbackTabIndex_ < 0)
    {
        return;
    }

    // First selects the secondary 'Driver Callback' tab, then switches to the top-level aggregated page. This ensures that when the top-level page is
    // initialized for the first time, ensureTabInitialized directly constructs the process protection page instead of falling back to the default Inline Hook.
    kernelAuditInnerTabWidget_->setCurrentIndex(callbackTabIndex_);
    tabWidget_->setCurrentIndex(kernelAuditTabIndex_);
    ensureTabInitialized(kernelAuditTabIndex_);
}

QString KernelDock::displayStateSummary() const
{
    if (tabWidget_ == nullptr)
    {
        return QStringLiteral("tabWidget=null");
    }

    QWidget* currentPage = tabWidget_->currentWidget();
    const QSize kTabSize = tabWidget_->size();
    const QSize kPageSize = currentPage != nullptr ? currentPage->size() : QSize();
    const int kPageChildCount = currentPage != nullptr
        ? currentPage->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly).size()
        : 0;
    const int kInnerTabCount = objectNamespaceInnerTabWidget_ != nullptr
        ? objectNamespaceInnerTabWidget_->count()
        : -1;

    // Return value kept on a single line to facilitate direct grep of KernelDockRepair in the log panel and file logs.
    return QStringLiteral(
        "tabCount=%1,current=%2,tabSize=%3x%4,page=%5,pageVisible=%6,pageSize=%7x%8,"
        "pageChildren=%9,objectNsReady=%10,innerTabs=%11")
        .arg(tabWidget_->count())
        .arg(tabWidget_->currentIndex())
        .arg(kTabSize.width())
        .arg(kTabSize.height())
        .arg(currentPage != nullptr ? currentPage->objectName() : QStringLiteral("<null>"))
        .arg(currentPage != nullptr && currentPage->isVisible() ? QStringLiteral("true") : QStringLiteral("false"))
        .arg(kPageSize.width())
        .arg(kPageSize.height())
        .arg(kPageChildCount)
        .arg(objectNamespaceTabInitialized_ ? QStringLiteral("true") : QStringLiteral("false"))
        .arg(kInnerTabCount);
}

void KernelDock::initializeUi()
{
    // objectName is the anchor for mainWindow's global QSS (ads--CDockWidget#ksDock_kernel
    // QWidget#KernelDockRoot ...), so it must be set first.
    setObjectName(QStringLiteral("KernelDockRoot"));

    // Deliberately omitting styleSheet, autoFillBackground, and WA_StyledBackground here:
    // Background transparency is determined by a single point in mainWindow (the criterion is 'background image is ready or window transparency is
    // enabled'), then propagated via global QSS and mount-time attribute settings. The entire layout is rebuilt when the theme or appearance changes.
    //
    // There used to be a built-in implementation with identical rules but a different selector prefix. Its criterion only checked if the background image file existed, and it resolved
    // paths relative to the exe directory. Consequently, the most common configuration—transparent window background without a background image—was incorrectly judged as opaque.
    // Since a control's own styleSheet has higher priority than its ancestors, this misjudgment would overwrite all correct global QSS rules,
    // causing the kernel page to appear opaque in most cases (issue #161). Retain the condition in only one place to prevent further deviation.

    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(4);

    // The initialization progress bar is hidden by default and only briefly shown when a lazy tab starts building.
    tabInitializingStatusLabel_ = new QLabel(kernelText("kernel.main.status.ready", QStringLiteral("页面就绪")), this);
    tabInitializingStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));
    tabInitializingStatusLabel_->setVisible(false);

    tabInitializingProgressBar_ = new QProgressBar(this);
    tabInitializingProgressBar_->setRange(0, 0);
    tabInitializingProgressBar_->setFixedHeight(4);
    tabInitializingProgressBar_->setTextVisible(false);
    tabInitializingProgressBar_->setVisible(false);
    tabInitializingProgressBar_->setStyleSheet(QStringLiteral(
        "QProgressBar{border:none;background:%1;border-radius:1px;}"
        "QProgressBar::chunk{background:%2;border-radius:1px;}")
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::kPrimaryBlueHex));
    rootLayout_->addWidget(tabInitializingStatusLabel_, 0);
    rootLayout_->addWidget(tabInitializingProgressBar_, 0);

    tabWidget_ = new QTabWidget(this);
    tabWidget_->setIconSize(QSize(16, 16));
    rootLayout_->addWidget(tabWidget_, 1);

    objectNamespacePage_ = new QWidget(tabWidget_);
    atomPage_ = new QWidget(tabWidget_);
    ioManagementPage_ = new QWidget(tabWidget_);
    ntQueryPage_ = new QWidget(tabWidget_);
    timerDpcPage_ = new QWidget(tabWidget_);
    crossViewPage_ = new QWidget(tabWidget_);
    ipcPage_ = new QWidget(tabWidget_);

    // Kernel audit and callback aggregation tab:
    // - Only adjust the UI hierarchy of the four existing business pages;
    // - Keep page objects and initialization/refresh functions unchanged to avoid business logic drift.
    kernelAuditPage_ = new QWidget(tabWidget_);
    kernelAuditLayout_ = new QVBoxLayout(kernelAuditPage_);
    kernelAuditLayout_->setContentsMargins(4, 4, 4, 4);
    kernelAuditInnerTabWidget_ = new QTabWidget(kernelAuditPage_);
    kernelAuditInnerTabWidget_->setIconSize(QSize(16, 16));
    kernelAuditLayout_->addWidget(kernelAuditInnerTabWidget_, 1);
    inlineHookPage_ = new QWidget(kernelAuditInnerTabWidget_);
    iatEatHookPage_ = new QWidget(kernelAuditInnerTabWidget_);
    callbackEnumPage_ = new QWidget(kernelAuditInnerTabWidget_);
    callbackInterceptPage_ = new QWidget(kernelAuditInnerTabWidget_);

    // The 'Ksword Self-Driver' container is not added to the KernelDock top-level.
    // mainWindow hands over the entire container to DriverDock; original business methods are still executed by KernelDock.
    selfDriverPage_ = new QWidget(this);
    // DriverDock is lazy-loaded. Keep this transfer-only container hidden until
    // it is reparented into DriverDock's tab widget, otherwise it appears at
    // KernelDock's top-left corner when KernelDock becomes visible first.
    selfDriverPage_->hide();
    selfDriverPage_->installEventFilter(this);
    selfDriverLayout_ = new QVBoxLayout(selfDriverPage_);
    selfDriverLayout_->setContentsMargins(4, 4, 4, 4);
    selfDriverInnerTabWidget_ = new QTabWidget(selfDriverPage_);
    selfDriverInnerTabWidget_->setIconSize(QSize(16, 16));
    selfDriverLayout_->addWidget(selfDriverInnerTabWidget_, 1);
    driverStatusPage_ = new QWidget(selfDriverInnerTabWidget_);

    objectNamespaceTabIndex_ = tabWidget_->addTab(
        objectNamespacePage_,
        tabIcon(QStringLiteral(":/Icon/process_tree.svg")),
        kernelText("kernel.main.tab.object_namespace.title", QStringLiteral("对象命名空间")));
    tabWidget_->setTabToolTip(objectNamespaceTabIndex_, kernelText("kernel.main.tab.object_namespace.tooltip", QStringLiteral("对象管理器命名空间遍历（默认页）")));

    atomTabIndex_ = tabWidget_->addTab(
        atomPage_,
        tabIcon(QStringLiteral(":/Icon/process_threads.svg")),
        kernelText("kernel.main.tab.atom.title", QStringLiteral("原子表遍历")));
    tabWidget_->setTabToolTip(atomTabIndex_, kernelText("kernel.main.tab.atom.tooltip", QStringLiteral("遍历全局原子范围并提供校验操作")));

    ntQueryTabIndex_ = tabWidget_->addTab(
        ntQueryPage_,
        tabIcon(QStringLiteral(":/Icon/process_details.svg")),
        kernelText("kernel.main.tab.nt_query.title", QStringLiteral("历史NtQuery")));
    tabWidget_->setTabToolTip(ntQueryTabIndex_, kernelText("kernel.main.tab.nt_query.tooltip", QStringLiteral("旧版内核 NtQuery 信息页")));

    // I/O management consolidates the original top-level SSDT, SSSDT, and IDT/GDT into horizontal sub-tabs and appends an IOCTLS decoder.
    ioManagementTabIndex_ = tabWidget_->addTab(
        ioManagementPage_,
        tabIcon(QStringLiteral(":/Icon/process_details.svg")),
        kernelText("kernel.main.tab.io_management.title", QStringLiteral("I/O管理")));
    tabWidget_->setTabToolTip(
        ioManagementTabIndex_,
        kernelText(
            "kernel.main.tab.io_management.tooltip",
            QStringLiteral("集中查看 SSDT、ShadowSSDT、IDT、GDT 并解析 IOCTL 控制码")));
    initializeIoManagementTab();

    inlineHookTabIndex_ = kernelAuditInnerTabWidget_->addTab(
        inlineHookPage_,
        tabIcon(QStringLiteral(":/Icon/process_critical.svg")),
        QStringLiteral("Inline Hook"));
    kernelAuditInnerTabWidget_->setTabToolTip(inlineHookTabIndex_, kernelText("kernel.main.tab.inline_hook.tooltip", QStringLiteral("扫描内核模块导出函数头部跳转补丁，并提供 force 后 NOP 摘除")));

    iatEatHookTabIndex_ = kernelAuditInnerTabWidget_->addTab(
        iatEatHookPage_,
        tabIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("IAT/EAT"));
    kernelAuditInnerTabWidget_->setTabToolTip(iatEatHookTabIndex_, kernelText("kernel.main.tab.iat_eat.tooltip", QStringLiteral("检测内核模块导入表和导出表可疑目标指针")));

    callbackEnumTabIndex_ = kernelAuditInnerTabWidget_->addTab(
        callbackEnumPage_,
        tabIcon(QStringLiteral(":/Icon/process_list.svg")),
        kernelText("kernel.main.tab.callback_enum.title", QStringLiteral("回调遍历")));
    kernelAuditInnerTabWidget_->setTabToolTip(
        callbackEnumTabIndex_,
        kernelText(
            "kernel.main.tab.callback_enum.tooltip",
            QStringLiteral("遍历 KswordARK 可见的系统回调、minifilter 和 System Informer DynData 诊断项")));

    callbackTabIndex_ = kernelAuditInnerTabWidget_->addTab(
        callbackInterceptPage_,
        tabIcon(QStringLiteral(":/Icon/process_critical.svg")),
        kernelText("kernel.main.tab.callback.title", QStringLiteral("驱动回调")));
    kernelAuditInnerTabWidget_->setTabToolTip(
        callbackTabIndex_,
        kernelText(
            "kernel.main.tab.callback.tooltip",
            QStringLiteral("驱动回调拦截规则管理与询问事件处理")));

    kernelAuditTabIndex_ = tabWidget_->addTab(
        kernelAuditPage_,
        tabIcon(QStringLiteral(":/Icon/process_critical.svg")),
        kernelText("kernel.main.tab.audit_callbacks.title", QStringLiteral("内核审计与回调")));
    tabWidget_->setTabToolTip(
        kernelAuditTabIndex_,
        kernelText(
            "kernel.main.tab.audit_callbacks.tooltip",
            QStringLiteral("集中查看 Inline Hook、IAT/EAT、回调遍历和驱动回调")));

    const int kHalAuditTabIndex = tabWidget_->addTab(
        new KernelPlatformAuditTab(KernelPlatformAuditTab::Mode::kHal, tabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_details.svg")),
        kernelText("kernel.main.tab.hal_audit.title", QStringLiteral("HAL")));
    tabWidget_->setTabToolTip(
        kHalAuditTabIndex,
        kernelText(
            "kernel.main.tab.hal_audit.tooltip",
            QStringLiteral("审计 HalDispatchTable、HalPrivateDispatchTable、HalAcpiDispatchTable 与 HalSubComponents，并受控编辑已验证函数槽")));

    const int kWdfAuditTabIndex = tabWidget_->addTab(
        new KernelPlatformAuditTab(KernelPlatformAuditTab::Mode::kWdf, tabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_list.svg")),
        kernelText("kernel.main.tab.wdf_audit.title", QStringLiteral("WDF")));
    tabWidget_->setTabToolTip(
        kWdfAuditTabIndex,
        kernelText(
            "kernel.main.tab.wdf_audit.tooltip",
            QStringLiteral("审计 KMDF 绑定函数地址、模块归属/执行节一致性与 WDF 回调，并受控编辑已验证的绑定表函数槽")));

    // VT-x/EPT pages moved to the top-level "Virtualization (KVM)" dock.
    // The reason for the move is not page ownership, but that it and the title bar's KVM right-click menu originally each held half the capabilities:
    // Resource preparation and release occur in the menu, while PREPARE/SELF_TEST/EPT rules reside on this page. There
    // are zero cross-references between the two sides, so a user cannot complete a full lifecycle from either side alone.

    slatIommuTabIndex_ = tabWidget_->addTab(
        new KernelSlatIommuAuditTab(tabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_priority.svg")),
        kernelText(
            "kernel.main.tab.slat_iommu.title",
            QStringLiteral("SLAT/IOMMU")));
    tabWidget_->setTabToolTip(
        slatIommuTabIndex_,
        kernelText(
            "kernel.main.tab.slat_iommu.tooltip",
            QStringLiteral("只读 EPT/NPT 虚拟-物理交叉视图、Hypervisor CPUID 与 DMAR/IVRS/IOMMU 运行时取证")));

    textIntegrityTabIndex_ = tabWidget_->addTab(
        new KernelTextIntegrityTab(tabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_details.svg")),
        kernelText(
            "kernel.main.tab.text_integrity.title",
            QStringLiteral("代码完整性")));
    tabWidget_->setTabToolTip(
        textIntegrityTabIndex_,
        kernelText(
            "kernel.main.tab.text_integrity.tooltip",
            QStringLiteral("把每个已加载模块的可执行节与重定位后的磁盘净映像全量逐字节比对，区分动态重定位位点与无法解释的代码改写")));

    vbsPostureTabIndex_ = tabWidget_->addTab(
        new KernelVbsPostureTab(tabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_priority.svg")),
        kernelText(
            "kernel.main.tab.vbs_posture.title",
            QStringLiteral("VBS/HVCI")));
    tabWidget_->setTabToolTip(
        vbsPostureTabIndex_,
        kernelText(
            "kernel.main.tab.vbs_posture.tooltip",
            QStringLiteral("区分 HVCI 策略位与运行时证据，识别「策略说开着但实际没跑」，并列出审计模式/测试签名/CI 调试等降级项")));

    timerDpcTabIndex_ = tabWidget_->addTab(
        timerDpcPage_,
        tabIcon(QStringLiteral(":/Icon/process_threads.svg")),
        kernelText("kernel.main.tab.timer_dpc.title", QStringLiteral("定时器/DPC")));
    tabWidget_->setTabToolTip(timerDpcTabIndex_, kernelText("kernel.main.tab.timer_dpc.tooltip", QStringLiteral("按 CPU 只读遍历 KTIMER 表并解析关联 KDPC 例程")));

    // The Work Queue Threads tab uses only system thread snapshots, WrQueue, and the trusted ActiveExWorker flag.
    // Do not read or guess the undocumented linked list structures of the Critical/Delayed/HyperCritical queues.
    workQueueThreadTabIndex_ = tabWidget_->addTab(
        new KernelThreadAuditTab(KernelThreadAuditTab::Mode::kWorkQueueThreads, tabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_threads.svg")),
        kernelText("kernel.main.tab.work_queue_threads.title", QStringLiteral("内核工作队列线程")));
    tabWidget_->setTabToolTip(
        workQueueThreadTabIndex_,
        kernelText(
            "kernel.main.tab.work_queue_threads.tooltip",
            QStringLiteral("基于安全线程证据审计工作队列候选、入口和模块归属")));

    crossViewTabIndex_ = tabWidget_->addTab(
        crossViewPage_,
        tabIcon(QStringLiteral(":/Icon/process_list.svg")),
        kernelText("kernel.main.tab.cid.title", QStringLiteral("CID表")));
    tabWidget_->setTabToolTip(crossViewTabIndex_, kernelText("kernel.main.tab.cid.tooltip", QStringLiteral("只读 CID / cross-view 证据聚合")));

    ipcTabIndex_ = tabWidget_->addTab(
        ipcPage_,
        tabIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("IPC"));
    tabWidget_->setTabToolTip(ipcTabIndex_, kernelText("kernel.main.tab.ipc.tooltip", QStringLiteral("只读 NamedPipe / ALPC / 通信对象")));

    // Knowledge Center uses read-only pages: both the directory and content are driven by language packs, and in-app buttons only switch to existing observation pages.
    knowledgeTab_ = new KernelKnowledgeTab(tabWidget_);
    knowledgeTab_->setRouteHandler([this](const QString& routeId) {
        openKnowledgeRoute(routeId);
    });
    knowledgeTabIndex_ = tabWidget_->addTab(
        knowledgeTab_,
        tabIcon(QStringLiteral(":/Icon/knowledge_book.svg")),
        ks::i18n::text(QStringLiteral("kernel.knowledge.tab.title")));
    tabWidget_->setTabToolTip(
        knowledgeTabIndex_,
        ks::i18n::text(QStringLiteral("kernel.knowledge.tab.tooltip")));
    ks::i18n::LanguageManager::instance().bindTab(
        tabWidget_,
        knowledgeTab_,
        QStringLiteral("kernel.knowledge.tab.title"),
        QString());
    ks::i18n::LanguageManager::instance().bindTabToolTip(
        tabWidget_,
        knowledgeTab_,
        QStringLiteral("kernel.knowledge.tab.tooltip"),
        QString());

    // DynData's overview and PDB Profile now become the second-level tabs under 'Ksword Self-Driver',
    // removing the empty 'Dynamic Offset' container that previously only held third-level tabs.
    initializeDynDataTab();
    dynDataTabInitialized_ = true;

    driverStatusTabIndex_ = selfDriverInnerTabWidget_->addTab(
        driverStatusPage_,
        tabIcon(QStringLiteral(":/Icon/process_details.svg")),
        kernelText("kernel.main.tab.driver_status.title", QStringLiteral("驱动状态")));
    selfDriverInnerTabWidget_->setTabToolTip(
        driverStatusTabIndex_,
        kernelText(
            "kernel.main.tab.driver_status.tooltip",
            QStringLiteral("KswordARK 驱动加载、协议、安全策略、DynData 和功能能力矩阵")));

    // The migration page must still construct real content before leaving the KernelDock top level.
    // Subsequent automatic/manual refreshes continue calling the original member functions without duplicating driver status business logic.
    initializeDriverStatusTab();
    driverStatusTabInitialized_ = true;

    tabWidget_->setCurrentIndex(objectNamespaceTabIndex_);
    updateTabIconContrast();
}

void KernelDock::showTabInitializingProgress(const int tabIndex, const QString& titleText)
{
    if (tabInitializingProgressBar_ == nullptr || tabInitializingStatusLabel_ == nullptr)
    {
        return;
    }

    // Only show progress on the tab currently being displayed to avoid distracting the user with background tab initialization.
    if (tabWidget_ != nullptr && tabWidget_->currentIndex() != tabIndex)
    {
        return;
    }

    tabInitializingStatusLabel_->setText(kernelText("kernel.main.status.initializing", QStringLiteral("正在初始化 %1 页面...")).arg(titleText));
    tabInitializingStatusLabel_->setVisible(true);
    tabInitializingProgressBar_->setVisible(true);
    QApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
}

void KernelDock::hideTabInitializingProgress()
{
    if (tabInitializingProgressBar_ != nullptr)
    {
        tabInitializingProgressBar_->setVisible(false);
    }
    if (tabInitializingStatusLabel_ != nullptr)
    {
        tabInitializingStatusLabel_->setVisible(false);
    }
}

void KernelDock::updateTabIconContrast()
{
    if (tabWidget_ == nullptr)
    {
        return;
    }

    // When a tab is selected with a blue background, use white resources to draw the icon; otherwise, keep the original icon color.
    const int kCurrentIndex = tabWidget_->currentIndex();
    tabWidget_->setTabIcon(objectNamespaceTabIndex_, tabIcon(QStringLiteral(":/Icon/process_tree.svg")));
    tabWidget_->setTabIcon(atomTabIndex_, tabIcon(QStringLiteral(":/Icon/process_threads.svg")));
    tabWidget_->setTabIcon(ntQueryTabIndex_, tabIcon(QStringLiteral(":/Icon/process_details.svg")));
    tabWidget_->setTabIcon(ioManagementTabIndex_, tabIcon(QStringLiteral(":/Icon/process_details.svg")));
    tabWidget_->setTabIcon(kernelAuditTabIndex_, tabIcon(QStringLiteral(":/Icon/process_critical.svg")));
    tabWidget_->setTabIcon(slatIommuTabIndex_, tabIcon(QStringLiteral(":/Icon/process_priority.svg")));
    tabWidget_->setTabIcon(textIntegrityTabIndex_, tabIcon(QStringLiteral(":/Icon/process_details.svg")));
    tabWidget_->setTabIcon(vbsPostureTabIndex_, tabIcon(QStringLiteral(":/Icon/process_priority.svg")));
    tabWidget_->setTabIcon(timerDpcTabIndex_, tabIcon(QStringLiteral(":/Icon/process_threads.svg")));
    tabWidget_->setTabIcon(workQueueThreadTabIndex_, tabIcon(QStringLiteral(":/Icon/process_threads.svg")));
    tabWidget_->setTabIcon(crossViewTabIndex_, tabIcon(QStringLiteral(":/Icon/process_list.svg")));
    tabWidget_->setTabIcon(ipcTabIndex_, tabIcon(QStringLiteral(":/Icon/process_details.svg")));
    tabWidget_->setTabIcon(knowledgeTabIndex_, tabIcon(QStringLiteral(":/Icon/knowledge_book.svg")));

    if (kCurrentIndex == objectNamespaceTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_tree.svg")));
    }
    else if (kCurrentIndex == atomTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_threads.svg")));
    }
    else if (kCurrentIndex == ntQueryTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_details.svg")));
    }
    else if (kCurrentIndex == ioManagementTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_details.svg")));
    }
    else if (kCurrentIndex == kernelAuditTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_critical.svg")));
    }
    else if (kCurrentIndex == slatIommuTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_priority.svg")));
    }
    else if (kCurrentIndex == textIntegrityTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_details.svg")));
    }
    else if (kCurrentIndex == vbsPostureTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_priority.svg")));
    }
    else if (kCurrentIndex == timerDpcTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_threads.svg")));
    }
    else if (kCurrentIndex == workQueueThreadTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_threads.svg")));
    }
    else if (kCurrentIndex == crossViewTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_list.svg")));
    }
    else if (kCurrentIndex == ipcTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/process_details.svg")));
    }
    else if (kCurrentIndex == knowledgeTabIndex_)
    {
        tabWidget_->setTabIcon(kCurrentIndex, selectedTabIcon(QStringLiteral(":/Icon/knowledge_book.svg")));
    }
}

void KernelDock::initializeIoManagementTab()
{
    if (ioManagementPage_ == nullptr || ioManagementLayout_ != nullptr)
    {
        return;
    }

    // m_ioManagementLayout only carries a top-level horizontal QTabWidget to prevent the old top-level page from being squeezed by extra margins.
    ioManagementLayout_ = new QVBoxLayout(ioManagementPage_);
    ioManagementLayout_->setContentsMargins(4, 4, 4, 4);
    ioManagementLayout_->setSpacing(0);

    ioManagementInnerTabWidget_ = new QTabWidget(ioManagementPage_);
    ioManagementInnerTabWidget_->setTabPosition(QTabWidget::North);
    ioManagementInnerTabWidget_->setDocumentMode(true);
    ioManagementLayout_->addWidget(ioManagementInnerTabWidget_, 1);

    // SSDT and ShadowSSDT continue to reuse the original pages and lazy refresh logic, adjusting only the container hierarchy.
    ssdtPage_ = new QWidget(ioManagementInnerTabWidget_);
    shadowSsdtPage_ = new QWidget(ioManagementInnerTabWidget_);
    ioSsdtTabIndex_ = ioManagementInnerTabWidget_->addTab(
        ssdtPage_,
        kernelText("kernel.main.inner_tab.ssdt", QStringLiteral("SSDT")));
    ioShadowSsdtTabIndex_ = ioManagementInnerTabWidget_->addTab(
        shadowSsdtPage_,
        kernelText("kernel.main.inner_tab.shadow_ssdt", QStringLiteral("ShadowSSDT")));

    // IDT and GDT are fixed to separate instances to satisfy the mental model of four kernel tables switching horizontally as shown in the screenshot.
    auto* idtTab = new KernelDescriptorTableTab(
        KernelDescriptorTableKind::kIdt,
        ioManagementInnerTabWidget_);
    auto* gdtTab = new KernelDescriptorTableTab(
        KernelDescriptorTableKind::kGdt,
        ioManagementInnerTabWidget_);
    ioIdtTabIndex_ = ioManagementInnerTabWidget_->addTab(
        idtTab,
        kernelText("kernel.main.inner_tab.idt", QStringLiteral("IDT")));
    ioGdtTabIndex_ = ioManagementInnerTabWidget_->addTab(
        gdtTab,
        kernelText("kernel.main.inner_tab.gdt", QStringLiteral("GDT")));

    // The IOCTLS sub-page is a pure R3 decoder that does not access the driver, so it can be created immediately alongside the rest of the kernel tables.
    auto* ioctlDecoderTab = new KernelIoctlDecoderTab(ioManagementInnerTabWidget_);
    ioIoctlTabIndex_ = ioManagementInnerTabWidget_->addTab(
        ioctlDecoderTab,
        kernelText("kernel.main.inner_tab.ioctls", QStringLiteral("IOCTLS")));

    ioManagementInnerTabWidget_->setTabToolTip(
        ioSsdtTabIndex_,
        kernelText("kernel.main.tab.ssdt.tooltip", QStringLiteral("驱动侧 SSDT 服务索引遍历结果")));
    ioManagementInnerTabWidget_->setTabToolTip(
        ioShadowSsdtTabIndex_,
        kernelText(
            "kernel.main.tab.shadow_ssdt.tooltip",
            QStringLiteral("参考 System Informer 的 win32k/win32u shadow syscall 解析")));
    ioManagementInnerTabWidget_->setTabToolTip(
        ioIdtTabIndex_,
        kernelText("kernel.main.inner_tab.idt.tooltip", QStringLiteral("按 CPU 读取 IDT 与 Handler 完整性证据")));
    ioManagementInnerTabWidget_->setTabToolTip(
        ioGdtTabIndex_,
        kernelText("kernel.main.inner_tab.gdt.tooltip", QStringLiteral("按 CPU 读取并解码 GDT 段描述符")));
    ioManagementInnerTabWidget_->setTabToolTip(
        ioIoctlTabIndex_,
        kernelText("kernel.main.inner_tab.ioctls.tooltip", QStringLiteral("解析 32 位 CTL_CODE 的 Device、Function、Access 与 Method")));
    ioManagementInnerTabWidget_->setCurrentIndex(ioSsdtTabIndex_);
}

void KernelDock::initializeObjectNamespaceTab()
{
    if (objectNamespacePage_ == nullptr || objectNamespaceLayout_ != nullptr)
    {
        return;
    }

    objectNamespaceLayout_ = new QVBoxLayout(objectNamespacePage_);
    objectNamespaceLayout_->setContentsMargins(4, 4, 4, 4);
    objectNamespaceLayout_->setSpacing(6);

    objectNamespaceInnerTabWidget_ = new QTabWidget(objectNamespacePage_);
    objectNamespaceInnerTabWidget_->setIconSize(QSize(16, 16));
    objectNamespaceLayout_->addWidget(objectNamespaceInnerTabWidget_, 1);

    objectNamespaceOverviewPage_ = new QWidget(objectNamespaceInnerTabWidget_);
    objectNamespaceOverviewLayout_ = new QVBoxLayout(objectNamespaceOverviewPage_);
    objectNamespaceOverviewLayout_->setContentsMargins(4, 4, 4, 4);
    objectNamespaceOverviewLayout_->setSpacing(6);

    objectNamespaceInnerTabWidget_->addTab(
        objectNamespaceOverviewPage_,
        tabIcon(QStringLiteral(":/Icon/process_tree.svg")),
        kernelText("kernel.main.inner_tab.overview", QStringLiteral("总览")));
    objectNamespaceInnerTabWidget_->addTab(
        new KernelObjectDirectoryDeepTab(objectNamespaceInnerTabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_tree.svg")),
        kernelText("kernel.main.inner_tab.directory_recursion", QStringLiteral("目录递归")));
    objectNamespaceInnerTabWidget_->addTab(
        new KernelBaseNamedObjectsTab(objectNamespaceInnerTabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_threads.svg")),
        QStringLiteral("BaseNamedObjects"));
    objectNamespaceInnerTabWidget_->addTab(
        new KernelSymbolicLinkTab(objectNamespaceInnerTabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        kernelText("kernel.main.inner_tab.symbolic_link", QStringLiteral("符号链接")));
    objectNamespaceInnerTabWidget_->addTab(
        new KernelDeviceDriverObjectsTab(objectNamespaceInnerTabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_details.svg")),
        kernelText("kernel.main.inner_tab.device_driver", QStringLiteral("设备与驱动")));
    auto* ioTimerTab = new KernelIoTimerTab(objectNamespaceInnerTabWidget_);
    const int kIoTimerInnerTabIndex = objectNamespaceInnerTabWidget_->addTab(
        ioTimerTab,
        tabIcon(QStringLiteral(":/Icon/process_threads.svg")),
        kernelText("kernel.main.inner_tab.io_timer", QStringLiteral("IoTimer")));
    objectNamespaceInnerTabWidget_->setTabToolTip(
        kIoTimerInnerTabIndex,
        kernelText(
            "kernel.main.inner_tab.io_timer.tooltip",
            QStringLiteral("枚举 DEVICE_OBJECT.Timer，并提供经三重身份校验的公开 WDM 启动/停止操作")));
    auto* ioctlAuditTab = new KernelIoctlAuditTab(objectNamespaceInnerTabWidget_);
    objectNamespaceInnerTabWidget_->addTab(
        ioctlAuditTab,
        tabIcon(QStringLiteral(":/Icon/process_list.svg")),
        kernelText("kernel.main.inner_tab.ioctl_audit", QStringLiteral("IOCTL 派遣表")));
    objectNamespaceInnerTabWidget_->addTab(
        new KernelObjectTypeMatrixTab(objectNamespaceInnerTabWidget_),
        tabIcon(QStringLiteral(":/Icon/process_list.svg")),
        kernelText("kernel.main.inner_tab.object_type", QStringLiteral("对象类型")));

    // IOCTL audit and IoTimer both issue R0 queries for every DriverObject. KernelDock may be created for layout restoration
    // even when not the active main Dock, so initial collection can only begin after the user actually switches to the sub-page.
    connect(objectNamespaceInnerTabWidget_, &QTabWidget::currentChanged, this,
        [this, ioctlAuditTab, ioTimerTab](const int tabIndex) {
            if (objectNamespaceInnerTabWidget_->widget(tabIndex) == ioctlAuditTab)
            {
                ioctlAuditTab->requestInitialRefresh();
            }
            else if (objectNamespaceInnerTabWidget_->widget(tabIndex) == ioTimerTab)
            {
                ioTimerTab->requestInitialRefresh();
            }
        });

    objectNamespaceToolLayout_ = new QHBoxLayout();
    objectNamespaceToolLayout_->setContentsMargins(0, 0, 0, 0);
    objectNamespaceToolLayout_->setSpacing(6);

    refreshObjectNamespaceButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), objectNamespaceOverviewPage_);
    refreshObjectNamespaceButton_->setToolTip(kernelText("kernel.main.object_namespace.refresh.tooltip", QStringLiteral("刷新对象命名空间枚举结果")));
    refreshObjectNamespaceButton_->setStyleSheet(blueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshObjectNamespaceButton_);

    objectNamespaceFilterEdit_ = new QLineEdit(objectNamespaceOverviewPage_);
    objectNamespaceFilterEdit_->setPlaceholderText(kernelText("kernel.main.object_namespace.filter.placeholder", QStringLiteral("按根目录/目录路径/对象名/对象类型/状态筛选")));
    objectNamespaceFilterEdit_->setToolTip(kernelText("kernel.main.object_namespace.filter.tooltip", QStringLiteral("输入关键字后实时过滤对象命名空间树")));
    objectNamespaceFilterEdit_->setClearButtonEnabled(true);
    objectNamespaceFilterEdit_->setStyleSheet(blueInputStyle());

    objectNamespaceStatusLabel_ = new QLabel(kernelText("kernel.main.object_namespace.status.waiting", QStringLiteral("状态：等待刷新")), objectNamespaceOverviewPage_);
    objectNamespaceStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    objectNamespaceToolLayout_->addWidget(refreshObjectNamespaceButton_, 0);
    objectNamespaceToolLayout_->addWidget(objectNamespaceFilterEdit_, 1);
    objectNamespaceToolLayout_->addWidget(objectNamespaceStatusLabel_, 0);
    objectNamespaceOverviewLayout_->addLayout(objectNamespaceToolLayout_);

    QSplitter* verticalSplitter = new QSplitter(Qt::Vertical, objectNamespaceOverviewPage_);
    objectNamespaceOverviewLayout_->addWidget(verticalSplitter, 1);

    QSplitter* horizontalSplitter = new QSplitter(Qt::Horizontal, verticalSplitter);

    objectNamespaceTree_ = new QTreeWidget(horizontalSplitter);
    objectNamespaceTree_->setColumnCount(static_cast<int>(ObjectNamespaceColumn::kCount));
    objectNamespaceTree_->setHeaderLabels(QStringList{
        kernelText("kernel.main.object_namespace.header.name", QStringLiteral("名称")),
        kernelText("kernel.main.object_namespace.header.type", QStringLiteral("类型")),
        kernelText("kernel.main.object_namespace.header.path_scope", QStringLiteral("路径/说明")),
        kernelText("kernel.main.object_namespace.header.status", QStringLiteral("状态")),
        kernelText("kernel.main.object_namespace.header.symbolic_target", QStringLiteral("符号链接目标"))
        });
    objectNamespaceTree_->setSelectionMode(QAbstractItemView::SingleSelection);
    objectNamespaceTree_->setAlternatingRowColors(true);
    objectNamespaceTree_->setContextMenuPolicy(Qt::CustomContextMenu);
    objectNamespaceTree_->setStyleSheet(itemSelectionStyle());
    objectNamespaceTree_->setUniformRowHeights(true);
    objectNamespaceTree_->setRootIsDecorated(true);
    objectNamespaceTree_->header()->setStyleSheet(headerStyle());
    // Column width strategy:
    // - Initial layout still relies on global TableColumnAutoFit to push visible width.
    // - Does not force hide the horizontal scrollbar; allows Qt to show it as needed after the user drags columns wider.
    objectNamespaceTree_->header()->setSectionResizeMode(QHeaderView::Stretch);
    objectNamespaceTree_->setToolTip(kernelText("kernel.main.object_namespace.tree.tooltip", QStringLiteral("文件管理器式对象命名空间树，支持逐级展开与右键操作")));

    objectNamespacePropertyTable_ = new ks::ui::VisibleTableWidget(horizontalSplitter);
    objectNamespacePropertyTable_->setColumnCount(2);
    objectNamespacePropertyTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.main.object_namespace.property.header", QStringLiteral("属性项")),
        kernelText("kernel.main.object_namespace.property.value", QStringLiteral("值"))
        });
    objectNamespacePropertyTable_->setSelectionMode(QAbstractItemView::NoSelection);
    objectNamespacePropertyTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    objectNamespacePropertyTable_->setAlternatingRowColors(true);
    objectNamespacePropertyTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    objectNamespacePropertyTable_->setCornerButtonEnabled(false);
    objectNamespacePropertyTable_->verticalHeader()->setVisible(false);
    objectNamespacePropertyTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    objectNamespacePropertyTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    objectNamespacePropertyTable_->setColumnWidth(0, 220);
    objectNamespacePropertyTable_->setToolTip(kernelText("kernel.main.object_namespace.property.tooltip", QStringLiteral("当前选中节点的字段详情（字段名 + 字段值）")));

    objectNamespaceDetailEditor_ = new CodeEditorWidget(verticalSplitter);
    objectNamespaceDetailEditor_->setObjectName(QStringLiteral("ks_object_namespace_detail_editor"));
    objectNamespaceDetailEditor_->setReadOnly(true);
    objectNamespaceDetailEditor_->setText(kernelText("kernel.main.object_namespace.detail.initial", QStringLiteral("请选择对象命名空间节点查看详情。")));

    horizontalSplitter->setStretchFactor(0, 3);
    horizontalSplitter->setStretchFactor(1, 2);
    verticalSplitter->setStretchFactor(0, 4);
    verticalSplitter->setStretchFactor(1, 2);

    // Object namespace page connections: refresh, filter, detail linkage, and context menu.
    connect(refreshObjectNamespaceButton_, &QPushButton::clicked, this, [this]() {
        refreshObjectNamespaceAsync();
    });
    connect(objectNamespaceFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildObjectNamespaceTable(filterText.trimmed());
    });
    connect(objectNamespaceTree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem*, QTreeWidgetItem*) {
        showObjectNamespaceDetailByCurrentRow();
    });
    connect(objectNamespaceTree_, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showObjectNamespaceContextMenu(localPosition);
    });
    connect(objectNamespacePropertyTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showCopyRowContextMenu(objectNamespacePropertyTable_, localPosition, false);
    });
}

void KernelDock::initializeAtomTableTab()
{
    if (atomPage_ == nullptr || atomLayout_ != nullptr)
    {
        return;
    }

    atomLayout_ = new QVBoxLayout(atomPage_);
    atomLayout_->setContentsMargins(4, 4, 4, 4);
    atomLayout_->setSpacing(6);

    atomToolLayout_ = new QHBoxLayout();
    atomToolLayout_->setContentsMargins(0, 0, 0, 0);
    atomToolLayout_->setSpacing(6);

    refreshAtomButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), atomPage_);
    refreshAtomButton_->setToolTip(kernelText("kernel.main.atom.refresh.tooltip", QStringLiteral("刷新原子表遍历结果")));
    refreshAtomButton_->setStyleSheet(blueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshAtomButton_);

    atomFilterEdit_ = new QLineEdit(atomPage_);
    atomFilterEdit_->setPlaceholderText(kernelText("kernel.main.atom.filter.placeholder", QStringLiteral("按 Atom 值/十六进制/名称/来源筛选")));
    atomFilterEdit_->setToolTip(kernelText("kernel.main.atom.filter.tooltip", QStringLiteral("输入关键字后实时过滤原子表")));
    atomFilterEdit_->setClearButtonEnabled(true);
    atomFilterEdit_->setStyleSheet(blueInputStyle());

    atomStatusLabel_ = new QLabel(kernelText("kernel.main.atom.status.waiting", QStringLiteral("状态：等待刷新")), atomPage_);
    atomStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    atomToolLayout_->addWidget(refreshAtomButton_, 0);
    atomToolLayout_->addWidget(atomFilterEdit_, 1);
    atomToolLayout_->addWidget(atomStatusLabel_, 0);
    atomLayout_->addLayout(atomToolLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, atomPage_);
    atomLayout_->addWidget(splitter, 1);

    atomTable_ = new ks::ui::VisibleTableWidget(splitter);
    atomTable_->setColumnCount(static_cast<int>(AtomColumn::kCount));
    atomTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.main.atom.header.value", QStringLiteral("Atom值")),
        kernelText("kernel.main.atom.header.hex", QStringLiteral("十六进制")),
        kernelText("kernel.main.atom.header.name", QStringLiteral("名称")),
        kernelText("kernel.main.atom.header.source", QStringLiteral("来源")),
        kernelText("kernel.main.atom.header.status", QStringLiteral("状态"))
        });
    atomTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    atomTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    atomTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    atomTable_->setAlternatingRowColors(true);
    atomTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    atomTable_->setStyleSheet(itemSelectionStyle());
    atomTable_->setCornerButtonEnabled(false);
    atomTable_->verticalHeader()->setVisible(false);
    atomTable_->horizontalHeader()->setStyleSheet(headerStyle());
    atomTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    atomTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(AtomColumn::kName), QHeaderView::Stretch);
    atomTable_->setColumnWidth(static_cast<int>(AtomColumn::kValue), 110);
    atomTable_->setColumnWidth(static_cast<int>(AtomColumn::kHex), 110);
    atomTable_->setColumnWidth(static_cast<int>(AtomColumn::kSource), 220);
    atomTable_->setColumnWidth(static_cast<int>(AtomColumn::kStatus), 160);

    atomDetailEditor_ = new CodeEditorWidget(splitter);
    atomDetailEditor_->setReadOnly(true);
    atomDetailEditor_->setText(kernelText("kernel.main.atom.detail.initial", QStringLiteral("请选择一条原子记录查看详情。")));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        atomTable_, atomDetailEditor_, atomPage_);

    // Atom table page connection: refresh, filter, details linkage, and right-click menu.
    connect(refreshAtomButton_, &QPushButton::clicked, this, [this]() {
        refreshAtomTableAsync();
    });
    connect(atomFilterEdit_, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildAtomTable(filterText.trimmed());
    });
    connect(atomTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showAtomDetailByCurrentRow();
    });
    connect(atomTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showAtomContextMenu(localPosition);
    });
}

void KernelDock::initializeNtQueryTab()
{
    if (ntQueryPage_ == nullptr || ntQueryLayout_ != nullptr)
    {
        return;
    }

    ntQueryLayout_ = new QVBoxLayout(ntQueryPage_);
    ntQueryLayout_->setContentsMargins(4, 4, 4, 4);
    ntQueryLayout_->setSpacing(6);

    ntQueryToolLayout_ = new QHBoxLayout();
    ntQueryToolLayout_->setContentsMargins(0, 0, 0, 0);
    ntQueryToolLayout_->setSpacing(6);

    refreshNtQueryButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), ntQueryPage_);
    refreshNtQueryButton_->setToolTip(kernelText("kernel.main.nt_query.refresh.tooltip", QStringLiteral("刷新历史 NtQuery 信息")));
    refreshNtQueryButton_->setStyleSheet(blueButtonStyle());
    ksword_theme::applyCompactIconButtonMetrics(refreshNtQueryButton_);

    ntQueryStatusLabel_ = new QLabel(kernelText("kernel.main.nt_query.status.waiting", QStringLiteral("状态：等待刷新")), ntQueryPage_);
    ntQueryStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::textSecondaryHex()));

    ntQueryToolLayout_->addWidget(refreshNtQueryButton_, 0);
    ntQueryToolLayout_->addWidget(ntQueryStatusLabel_, 1);
    ntQueryLayout_->addLayout(ntQueryToolLayout_);

    QSplitter* splitter = new QSplitter(Qt::Vertical, ntQueryPage_);
    ntQueryLayout_->addWidget(splitter, 1);

    ntQueryTable_ = new ks::ui::VisibleTableWidget(splitter);
    ntQueryTable_->setColumnCount(static_cast<int>(NtQueryColumn::kCount));
    ntQueryTable_->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.main.nt_query.header.category", QStringLiteral("类别")),
        kernelText("kernel.main.nt_query.header.function", QStringLiteral("函数")),
        kernelText("kernel.main.nt_query.header.item", QStringLiteral("查询项")),
        kernelText("kernel.main.nt_query.header.status", QStringLiteral("状态")),
        kernelText("kernel.main.nt_query.header.summary", QStringLiteral("摘要"))
        });
    ntQueryTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    ntQueryTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    ntQueryTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ntQueryTable_->setAlternatingRowColors(true);
    ntQueryTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    ntQueryTable_->setStyleSheet(itemSelectionStyle());
    ntQueryTable_->setCornerButtonEnabled(false);
    ntQueryTable_->verticalHeader()->setVisible(false);
    ntQueryTable_->horizontalHeader()->setStyleSheet(headerStyle());
    ntQueryTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ntQueryTable_->horizontalHeader()->setSectionResizeMode(static_cast<int>(NtQueryColumn::kSummary), QHeaderView::Stretch);

    ntQueryDetailEditor_ = new CodeEditorWidget(splitter);
    ntQueryDetailEditor_->setReadOnly(true);
    ntQueryDetailEditor_->setText(kernelText("kernel.main.nt_query.detail.initial", QStringLiteral("请选择一条 NtQuery 结果查看详情。")));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    ks::ui::DetailLayoutRegistry::registerHost(
        ntQueryTable_, ntQueryDetailEditor_, ntQueryPage_);

    // History NtQuery page connection: refresh and details linkage.
    connect(refreshNtQueryButton_, &QPushButton::clicked, this, [this]() {
        refreshNtQueryAsync();
    });
    connect(ntQueryTable_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showNtQueryDetailByCurrentRow();
    });
    connect(ntQueryTable_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showCopyRowContextMenu(ntQueryTable_, localPosition, true);
    });
}

void KernelDock::initializeConnections()
{
    // Top-level tab switch: initialize the corresponding page on demand and trigger the initial data load.
    connect(tabWidget_, &QTabWidget::currentChanged, this, [this](const int tabIndex) {
        updateTabIconContrast();
        ensureTabInitialized(tabIndex);
    });

    // I/O management internal tab initializes only the current SSDT/ShadowSSDT; IDT/GDT are first-rendered by their respective showEvent handlers.
    if (ioManagementInnerTabWidget_ != nullptr)
    {
        connect(
            ioManagementInnerTabWidget_,
            &QTabWidget::currentChanged,
            this,
            [this](const int innerTabIndex)
            {
                if (tabWidget_ != nullptr &&
                    tabWidget_->currentIndex() == ioManagementTabIndex_)
                {
                    ensureIoManagementTabInitialized(innerTabIndex);
                }
            });
    }

    // Kernel audit and callback internal switching continues to reuse the original lazy initialization entry point.
    // The top level recognizes only aggregated pages; specific business logic is determined by the current secondary tab.
    if (kernelAuditInnerTabWidget_ != nullptr)
    {
        connect(
            kernelAuditInnerTabWidget_,
            &QTabWidget::currentChanged,
            this,
            [this](const int)
            {
                if (tabWidget_ != nullptr &&
                    tabWidget_->currentIndex() == kernelAuditTabIndex_)
                {
                    ensureTabInitialized(kernelAuditTabIndex_);
                }
            });
    }

    if (selfDriverInnerTabWidget_ != nullptr)
    {
        connect(
            selfDriverInnerTabWidget_,
            &QTabWidget::currentChanged,
            this,
            [this](const int)
            {
                ensureSelfDriverCurrentTabRefreshed();
            });
    }
}

void KernelDock::ensureSelfDriverCurrentTabRefreshed()
{
    if (selfDriverRefreshCheckPending_ ||
        selfDriverPage_ == nullptr ||
        selfDriverInnerTabWidget_ == nullptr)
    {
        return;
    }
    selfDriverRefreshCheckPending_ = true;
    QTimer::singleShot(0, this, [this]()
    {
        selfDriverRefreshCheckPending_ = false;
        if (selfDriverPage_ == nullptr ||
            selfDriverInnerTabWidget_ == nullptr ||
            !selfDriverPage_->isVisible())
        {
            return;
        }

        const int kCurrentIndex =
            selfDriverInnerTabWidget_->currentIndex();
        if ((kCurrentIndex == dynDataTabIndex_ ||
                kCurrentIndex == dynDataProfileTabIndex_) &&
            !dynDataFirstRefreshTriggered_)
        {
            dynDataFirstRefreshTriggered_ = true;
            refreshDynDataAsync();
        }
        else if (kCurrentIndex == driverStatusTabIndex_ &&
                 !driverStatusFirstRefreshTriggered_)
        {
            driverStatusFirstRefreshTriggered_ = true;
            refreshDriverStatusAsync();
        }
    });
}

void KernelDock::initializeCrossViewTab()
{
    if (crossViewPage_ == nullptr)
    {
        return;
    }

    // Read-only CID / cross-view pages directly reuse independent components to avoid duplicating a full collection logic set within the main container.
    auto* layout = new QVBoxLayout(crossViewPage_);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(0);

    auto* tab = new KernelDockCidTab(crossViewPage_);
    layout->addWidget(tab, 1);
}

void KernelDock::initializeIpcTab()
{
    if (ipcPage_ == nullptr)
    {
        return;
    }

    // The read-only IPC page directly reuses independent components to aggregate NamedPipe, ALPC, and communication endpoints.
    auto* layout = new QVBoxLayout(ipcPage_);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(0);

    auto* tab = new KernelDockIpcTab(ipcPage_);
    layout->addWidget(tab, 1);
}

void KernelDock::openKnowledgeRoute(const QString& routeId)
{
    if (tabWidget_ == nullptr)
    {
        return;
    }

    // The routing table lists only pages that already exist within the KernelDock where the Knowledge Center resides.
    // Tab switching does not automatically trigger clicks on Refresh, Repair, Detach, or other buttons that may alter system state.
    int targetTabIndex = -1;
    if (routeId == QStringLiteral("object_namespace"))
    {
        targetTabIndex = objectNamespaceTabIndex_;
    }
    else if (routeId == QStringLiteral("io_management"))
    {
        targetTabIndex = ioManagementTabIndex_;
    }
    else if (routeId == QStringLiteral("kernel_audit"))
    {
        targetTabIndex = kernelAuditTabIndex_;
    }
    else if (routeId == QStringLiteral("slat_iommu"))
    {
        targetTabIndex = slatIommuTabIndex_;
    }
    else if (routeId == QStringLiteral("text_integrity"))
    {
        targetTabIndex = textIntegrityTabIndex_;
    }
    else if (routeId == QStringLiteral("vbs"))
    {
        targetTabIndex = vbsPostureTabIndex_;
    }
    else if (routeId == QStringLiteral("timer_dpc"))
    {
        targetTabIndex = timerDpcTabIndex_;
    }
    else if (routeId == QStringLiteral("work_queue_threads"))
    {
        targetTabIndex = workQueueThreadTabIndex_;
    }
    else if (routeId == QStringLiteral("cid"))
    {
        targetTabIndex = crossViewTabIndex_;
    }
    else if (routeId == QStringLiteral("ipc"))
    {
        targetTabIndex = ipcTabIndex_;
    }

    if (targetTabIndex >= 0)
    {
        tabWidget_->setCurrentIndex(targetTabIndex);
        ensureTabInitialized(targetTabIndex);
    }
}

void KernelDock::ensureTabInitialized(const int tabIndex)
{
    if (tabIndex == objectNamespaceTabIndex_ && !objectNamespaceTabInitialized_)
    {
        showTabInitializingProgress(tabIndex, kernelText("kernel.main.tab.object_namespace.title", QStringLiteral("对象命名空间")));
        initializeObjectNamespaceTab();
        objectNamespaceTabInitialized_ = true;
        hideTabInitializingProgress();
        refreshObjectNamespaceAsync();
        return;
    }

    if (tabIndex == atomTabIndex_ && !atomTabInitialized_)
    {
        showTabInitializingProgress(tabIndex, kernelText("kernel.main.progress.global_atom", QStringLiteral("全局原子表")));
        initializeAtomTableTab();
        atomTabInitialized_ = true;
        hideTabInitializingProgress();
        refreshAtomTableAsync();
        return;
    }

    if (tabIndex == ntQueryTabIndex_ && !ntQueryTabInitialized_)
    {
        showTabInitializingProgress(tabIndex, kernelText("kernel.main.tab.nt_query.progress", QStringLiteral("历史 NtQuery")));
        initializeNtQueryTab();
        ntQueryTabInitialized_ = true;
        hideTabInitializingProgress();
        refreshNtQueryAsync();
        return;
    }

    if (tabIndex == ioManagementTabIndex_)
    {
        const int kInnerTabIndex = ioManagementInnerTabWidget_ != nullptr
            ? ioManagementInnerTabWidget_->currentIndex()
            : -1;
        ensureIoManagementTabInitialized(kInnerTabIndex);
        return;
    }

    if (tabIndex == kernelAuditTabIndex_)
    {
        const int kInnerTabIndex = kernelAuditInnerTabWidget_ != nullptr
            ? kernelAuditInnerTabWidget_->currentIndex()
            : -1;
        if (kInnerTabIndex == inlineHookTabIndex_ && !inlineHookTabInitialized_)
        {
            showTabInitializingProgress(tabIndex, QStringLiteral("Inline Hook"));
            initializeInlineHookTab();
            inlineHookTabInitialized_ = true;
            hideTabInitializingProgress();
            refreshInlineHooksAsync();
        }
        else if (kInnerTabIndex == iatEatHookTabIndex_ && !iatEatHookTabInitialized_)
        {
            showTabInitializingProgress(tabIndex, QStringLiteral("IAT/EAT"));
            initializeIatEatHookTab();
            iatEatHookTabInitialized_ = true;
            hideTabInitializingProgress();
            refreshIatEatHooksAsync();
        }
        else if (kInnerTabIndex == callbackEnumTabIndex_ && !callbackEnumTabInitialized_)
        {
            showTabInitializingProgress(
                tabIndex,
                kernelText("kernel.main.tab.callback_enum.title", QStringLiteral("回调遍历")));
            initializeCallbackEnumTab();
            callbackEnumTabInitialized_ = true;
            hideTabInitializingProgress();
            refreshCallbackEnumAsync();
        }
        else if (kInnerTabIndex == callbackTabIndex_ && !callbackTabInitialized_)
        {
            showTabInitializingProgress(
                tabIndex,
                kernelText("kernel.main.tab.callback.title", QStringLiteral("驱动回调")));
            initializeCallbackInterceptTab();
            callbackTabInitialized_ = true;
            hideTabInitializingProgress();
        }
        return;
    }

    if (tabIndex == timerDpcTabIndex_ && !timerDpcTabInitialized_)
    {
        showTabInitializingProgress(tabIndex, kernelText("kernel.main.tab.timer_dpc.title", QStringLiteral("定时器/DPC")));
        initializeTimerDpcTab();
        timerDpcTabInitialized_ = true;
        hideTabInitializingProgress();
        refreshTimerDpcAfterDynDataAsync();
        return;
    }

    if (tabIndex == crossViewTabIndex_ && !crossViewTabInitialized_)
    {
        showTabInitializingProgress(tabIndex, kernelText("kernel.main.tab.cid.title", QStringLiteral("CID表")));
        initializeCrossViewTab();
        crossViewTabInitialized_ = true;
        hideTabInitializingProgress();
        return;
    }

    if (tabIndex == ipcTabIndex_ && !ipcTabInitialized_)
    {
        showTabInitializingProgress(tabIndex, QStringLiteral("IPC"));
        initializeIpcTab();
        ipcTabInitialized_ = true;
        hideTabInitializingProgress();
        return;
    }

}

void KernelDock::ensureIoManagementTabInitialized(const int innerTabIndex)
{
    if (innerTabIndex == ioSsdtTabIndex_ && !ssdtTabInitialized_)
    {
        showTabInitializingProgress(ioManagementTabIndex_, QStringLiteral("SSDT"));
        initializeSsdtTab();
        ssdtTabInitialized_ = true;
        hideTabInitializingProgress();
        refreshSsdtAsync();
        return;
    }

    if (innerTabIndex == ioShadowSsdtTabIndex_ && !shadowSsdtTabInitialized_)
    {
        showTabInitializingProgress(ioManagementTabIndex_, QStringLiteral("ShadowSSDT"));
        initializeShadowSsdtTab();
        shadowSsdtTabInitialized_ = true;
        hideTabInitializingProgress();
        refreshShadowSsdtAsync();
    }
}
