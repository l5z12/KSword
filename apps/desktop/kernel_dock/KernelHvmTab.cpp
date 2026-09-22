#include "KernelHvmTab.h"
#include "../MainWindow.h"

#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../settings_dock/AppearanceSettings.h"
#include "../ui/FlowLayout.h"
// isNestedAllowed: The authoritative source for the nested switch. This page previously calculated its own value, which was narrower.
#include "../ui/KvmControl.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QVariant>

#include <algorithm>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum HvmCpuColumn : int
    {
        kCpuColumnProcessor = 0,
        kCpuColumnResource,
        kCpuColumnSelfTest,
        kCpuColumnGuestExit,
        kCpuColumnVmxResult,
        kCpuColumnNtStatus,
        kCpuColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // Button availability already clarifies the lifecycle order; what is missing is the 'why it is gray':
    // updateButtons can derive the disabled conditions, but the user only sees a single gray button, requiring them
    // to reverse-engineer which one to click first. Here, the reason is appended after the static description.
    //
    // Static descriptions are stored in dynamic properties and retrieved because this function runs every refresh cycle:
    // Directly appending to the toolTip would stack reasons into a long string one by one.
    void setGateTooltip(QPushButton* const button, const QString& gateReason)
    {
        if (button == nullptr)
        {
            return;
        }
        const QVariant kStoredBaseTooltip = button->property("ks_base_tooltip");
        const QString kBaseTooltip = kStoredBaseTooltip.isValid()
            ? kStoredBaseTooltip.toString()
            : button->toolTip();
        if (!kStoredBaseTooltip.isValid())
        {
            button->setProperty("ks_base_tooltip", kBaseTooltip);
        }
        if (gateReason.isEmpty())
        {
            button->setToolTip(kBaseTooltip);
            return;
        }
        button->setToolTip(kBaseTooltip.isEmpty()
            ? gateReason
            : kBaseTooltip + QLatin1Char('\n') + gateReason);
    }
}

KernelHvmTab::KernelHvmTab(QWidget* parent)
    : KernelHvmTab(FeatureArea::kKept, parent)
{
}

KernelHvmTab::KernelHvmTab(
    const FeatureArea featureArea,
    QWidget* parent)
    : QWidget(parent)
    , featureArea_(featureArea)
{
    initializeUi();
}

void KernelHvmTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(
            this,
            [this]() { refreshAsync(); },
            Qt::QueuedConnection);
    }
}

void KernelHvmTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    // Hazard warnings are concise to save space: they follow the button that triggers actual hardware operations, with the full version in the confirmation dialog after clicking.
    const QString kHazardTip = kernelText(
        "kernel.hvm.hazard.tooltip",
        QStringLiteral("虚拟化进入、页表缓存类型或退出恢复错误可能导致系统不稳定或蓝屏。"));

    // Use a line-break layout instead of QHBoxLayout: This row contains eight buttons with labels that are complete
    // sentences of 4–6 characters (e.g., 'Start One-Time Guest'). At 1024px width, QHBoxLayout compresses each button
    // below its sizeHint, truncating 'Refresh Capability' to 'efresh Capabilitie'—the buttons remain clickable, but their
    // labels become unreadable. The line-break layout enables wrapping while maintaining a single row in wider windows.
    auto* toolbar = new ks::ui::FlowLayout(nullptr, 0, 6, 4);
    refreshButton_ = new QPushButton(
        kernelText("kernel.hvm.refresh", QStringLiteral("刷新能力")),
        this);
    prepareButton_ = new QPushButton(
        kernelText("kernel.hvm.prepare", QStringLiteral("准备虚拟化后端")),
        this);
    selfTestButton_ = new QPushButton(
        kernelText("kernel.hvm.self_test", QStringLiteral("逐 CPU 自检")),
        this);
    launchButton_ = new QPushButton(
        kernelText("kernel.hvm.launch", QStringLiteral("启动一次性来宾")),
        this);
    teardownButton_ = new QPushButton(
        kernelText("kernel.hvm.teardown", QStringLiteral("释放后端")),
        this);
    startResidentButton_ = new QPushButton(
        kernelText(
            "kernel.hvm.resident.start",
            QStringLiteral("启动驻留 VMM")),
        this);
    stopResidentButton_ = new QPushButton(
        kernelText(
            "kernel.hvm.resident.stop",
            QStringLiteral("停止驻留 VMM")),
        this);
    refreshButton_->setToolTip(
        kernelText(
            "kernel.hvm.refresh.tooltip",
            QStringLiteral("重新检测当前 CPU 支持哪些硬件虚拟化能力")));
    prepareButton_->setToolTip(
        kernelText(
            "kernel.hvm.prepare.tooltip",
            QStringLiteral("为硬件虚拟化分配所需内存与页表结构，是启动来宾前的准备步骤"))
        + QLatin1Char('\n') + kHazardTip);
    selfTestButton_->setToolTip(
        kernelText(
            "kernel.hvm.self_test.tooltip",
            QStringLiteral("逐个 CPU 核心测试虚拟化功能是否可以正常开启"))
        + QLatin1Char('\n') + kHazardTip);
    launchButton_->setToolTip(
        kernelText(
            "kernel.hvm.launch.tooltip",
            QStringLiteral("启动一个一次性的虚拟机来宾用于验证，运行后立即退出"))
        + QLatin1Char('\n') + kHazardTip);
    teardownButton_->setToolTip(
        kernelText(
            "kernel.hvm.teardown.tooltip",
            QStringLiteral("释放虚拟化后端占用的内存与资源")));
    startResidentButton_->setToolTip(
        kernelText(
            "kernel.hvm.resident.start.tooltip",
            QStringLiteral("启动常驻的虚拟机监控器，持续运行以便监控（会影响系统运行状态，请谨慎使用）"))
        + QLatin1Char('\n')
        + kernelText(
            "kernel.hvm.resident.start.gate_tooltip",
            QStringLiteral("Intel 使用 VMX/EPT，AMD 使用实验性 SVM/NPT。必须通过全 CPU 自检与生命周期保护；AMD 仅接受明确允许的 VMware 外层。")));
    stopResidentButton_->setToolTip(
        kernelText(
            "kernel.hvm.resident.stop.tooltip",
            QStringLiteral("停止常驻的虚拟机监控器并恢复系统原状")));
    featureActionButton_ = new QPushButton(this);
    if (featureArea_ == FeatureArea::kKept)
    {
        featureActionButton_->setText(
            kernelText(
                "kernel.hvm.ept.actions",
                QStringLiteral("EPT 规则与事件")));
        featureActionButton_->setToolTip(
            kernelText(
                "kernel.hvm.ept.actions.tooltip",
                QStringLiteral("EPT 严格规则只是取证 tripwire：命中后记录并去虚拟化，不注入异常，原访问仍可能在同一 RIP 原生重试并成功。")));
        auto* eptMenu = new QMenu(featureActionButton_);
        QAction* addRule = eptMenu->addAction(
            kernelText(
                "kernel.hvm.ept.add",
                QStringLiteral("添加物理页规则...")));
        QAction* queryRule = eptMenu->addAction(
            kernelText(
                "kernel.hvm.ept.query",
                QStringLiteral("查询规则...")));
        QAction* removeRule = eptMenu->addAction(
            kernelText(
                "kernel.hvm.ept.remove",
                QStringLiteral("移除规则...")));
        QAction* clearRules = eptMenu->addAction(
            kernelText(
                "kernel.hvm.ept.clear",
                QStringLiteral("清空全部规则...")));
        eptMenu->addSeparator();
        QAction* readEvents = eptMenu->addAction(
            kernelText(
                "kernel.hvm.events.read",
                QStringLiteral("读取 VM-exit / EPT 事件")));
        QAction* clearEventRing = eptMenu->addAction(
            kernelText(
                "kernel.hvm.events.clear",
                QStringLiteral("清空已停止的事件环...")));
        featureActionButton_->setMenu(eptMenu);
        connect(addRule, &QAction::triggered, this, [this]() {
            addEptRule();
        });
        connect(queryRule, &QAction::triggered, this, [this]() {
            queryEptRule();
        });
        connect(removeRule, &QAction::triggered, this, [this]() {
            removeEptRule();
        });
        connect(clearRules, &QAction::triggered, this, [this]() {
            clearEptRules();
        });
        connect(readEvents, &QAction::triggered, this, [this]() {
            queryEvents();
        });
        connect(clearEventRing, &QAction::triggered, this, [this]() {
            clearEvents();
        });
    }
    else if (featureArea_ == FeatureArea::kNestedVmx)
    {
        /*
         * The key used for the label is the same as the confirmation box title in validateNested(); the fallback text in both
         * places must be character-for-character identical. If they differ, the same key may display two different names depending
         * on which location is accessed first, and this discrepancy only manifests when the translation term is missing.
         */
        featureActionButton_->setText(
            kernelText(
                "kernel.hvm.nested.validate",
                QStringLiteral("验证 Nested VMX 分派能力")));
        featureActionButton_->setToolTip(
            kernelText(
                "kernel.hvm.nested.validate.tooltip",
                QStringLiteral("探测并报告嵌套 VMX 分派能力。分派本身已完整：vmcs12/vmcs02 合并、L2 退出反射与影子 EPT 都已实现并在硬件上验证过。这个按钮只做探测，不会让常驻带上嵌套派发——那一位在虚拟化菜单的「允许来宾嵌套（我们作为宿主）」。")));
        connect(
            featureActionButton_,
            &QPushButton::clicked,
            this,
            [this]() { validateNested(); });
    }
    else
    {
        featureActionButton_->setText(
            kernelText(
                "kernel.hvm.evmcs.validate",
                QStringLiteral("验证 Hyper-V eVMCS（partial）")));
        featureActionButton_->setToolTip(
            kernelText(
                "kernel.hvm.evmcs.validate.tooltip",
                QStringLiteral("仅做 TLFS 能力、根/来宾分区与 VP-assist 所有权检查；不接管 VP-assist 页面和 clean fields，不会标为 active。")));
        connect(
            featureActionButton_,
            &QPushButton::clicked,
            this,
            [this]() { validateEvmcs(); });
    }
    for (QPushButton* button :
         { refreshButton_,
           prepareButton_,
           selfTestButton_,
           launchButton_,
           teardownButton_,
           startResidentButton_,
           stopResidentButton_,
           featureActionButton_ })
    {
        button->setStyleSheet(ksword_theme::themedButtonStyle());
    }
    statusLabel_ = new QLabel(
        kernelText("kernel.hvm.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(ksword_theme::textSecondaryHex()));
    toolbar->addWidget(refreshButton_);
    toolbar->addWidget(prepareButton_);
    toolbar->addWidget(selfTestButton_);
    toolbar->addWidget(launchButton_);
    toolbar->addWidget(startResidentButton_);
    toolbar->addWidget(stopResidentButton_);
    toolbar->addWidget(teardownButton_);
    toolbar->addWidget(featureActionButton_);
    rootLayout->addLayout(toolbar);
    // Move the status label out of the button row: the wrap layout has no stretch, so placing it after the last button causes it to be treated as
    // a ninth button and participate in wrapping, making its position jump erratically with window width. Occupying its own line is more stable.
    rootLayout->addWidget(statusLabel_);

    summaryLabel_ = new QLabel(this);
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    summaryLabel_->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;color:%1;}")
            .arg(ksword_theme::textPrimaryHex()));
    rootLayout->addWidget(summaryLabel_);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    cpuTable_ = new ks::ui::VisibleTableWidget(splitter);
    cpuTable_->setColumnCount(kCpuColumnCount);
    cpuTable_->setHorizontalHeaderLabels({
        kernelText("kernel.hvm.cpu.processor", QStringLiteral("处理器")),
        kernelText("kernel.hvm.cpu.resource", QStringLiteral("控制结构")),
        kernelText("kernel.hvm.cpu.self_test", QStringLiteral("自检")),
        kernelText("kernel.hvm.cpu.guest_exit", QStringLiteral("来宾 / VM-exit")),
        kernelText("kernel.hvm.cpu.vmx_result", QStringLiteral("执行状态")),
        kernelText("kernel.hvm.cpu.ntstatus", QStringLiteral("NTSTATUS"))
    });
    cpuTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    cpuTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    cpuTable_->setAlternatingRowColors(true);
    cpuTable_->verticalHeader()->setVisible(false);
    cpuTable_->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    cpuTable_->horizontalHeader()->setStretchLastSection(true);

    detailEdit_ = new QTextEdit(splitter);
    detailEdit_->setReadOnly(true);
    detailEdit_->setPlaceholderText(
        kernelText(
            "kernel.hvm.detail.placeholder",
            QStringLiteral("刷新后显示 VMX MSR、EPT 映射与生命周期证据")));
    splitter->addWidget(cpuTable_);
    splitter->addWidget(detailEdit_);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    rootLayout->addWidget(splitter, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });
    connect(prepareButton_, &QPushButton::clicked, this, [this]() {
        prepareBackend();
    });
    connect(selfTestButton_, &QPushButton::clicked, this, [this]() {
        selfTestBackend();
    });
    connect(launchButton_, &QPushButton::clicked, this, [this]() {
        launchControlledGuest();
    });
    connect(teardownButton_, &QPushButton::clicked, this, [this]() {
        teardownBackend();
    });
    connect(startResidentButton_, &QPushButton::clicked, this, [this]() {
        startResident();
    });
    connect(stopResidentButton_, &QPushButton::clicked, this, [this]() {
        stopResident();
    });
    if (featureArea_ == FeatureArea::kEvmcs)
    {
        prepareButton_->setVisible(false);
        selfTestButton_->setVisible(false);
        launchButton_->setVisible(false);
        startResidentButton_->setVisible(false);
        stopResidentButton_->setVisible(false);
        teardownButton_->setVisible(false);
    }
    updateButtons();
}

void KernelHvmTab::refreshAsync()
{
    if (operationRunning_)
    {
        return;
    }
    operationRunning_ = true;
    statusLabel_->setText(
        kernelText(
            "kernel.hvm.status.refreshing",
            QStringLiteral("正在读取 CPUID、VMX MSR 与后端状态...")));
    updateButtons();
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([safeThis]() {
        ksword::ark::DriverClient client;
        auto result = client.queryHvmStatus();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result = std::move(result)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyStatus(std::move(result));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyStatus(ksword::ark::HvmStatusResult result)
{
    operationRunning_ = false;
    supported_ = result.io.ok && !result.unsupported;
    if (!supported_)
    {
        snapshot_ = {};
        cpuTable_->setRowCount(0);
        summaryLabel_->setText(
            result.unsupported
                ? kernelText(
                      "kernel.hvm.status.unsupported",
                      QStringLiteral("当前驱动不支持 HVM 协议，请更新并重新加载驱动。"))
                : kernelText(
                      "kernel.hvm.status.failed",
                      QStringLiteral("HVM 状态读取失败：%1"))
                      .arg(QString::fromStdString(result.io.message)));
        detailEdit_->clear();
        statusLabel_->setText(
            kernelText("kernel.hvm.status.failed_short", QStringLiteral("状态：读取失败")));
        updateButtons();
        return;
    }

    snapshot_ = result.response;
    const QString kCpuVendor = fixedAscii(
        snapshot_.cpuVendor,
        KSWORD_ARK_HVM_VENDOR_CHARS);
    const QString kHypervisorVendor = fixedAscii(
        snapshot_.hypervisorVendor,
        KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS);
    summaryLabel_->setText(
        kernelText(
            "kernel.hvm.summary",
            QStringLiteral("CPU：%1　Hypervisor：%2　状态：%3　准备 CPU：%4/%5　自检通过：%6/%5　EPT 页表页：%7　RAM 映射：%8 GiB　VM-exit：%9　最近退出：%10"))
            .arg(kCpuVendor.isEmpty() ? QStringLiteral("-") : kCpuVendor)
            .arg(kHypervisorVendor.isEmpty()
                     ? kernelText("kernel.hvm.none", QStringLiteral("未检测到"))
                     : kHypervisorVendor)
            .arg(stateText(snapshot_.stateFlags))
            .arg(snapshot_.preparedProcessorCount)
            .arg(snapshot_.processorCount)
            .arg(snapshot_.selfTestPassedProcessorCount)
            .arg(snapshot_.eptPageCount)
            .arg(
                static_cast<double>(snapshot_.mappedRamBytes) /
                    (1024.0 * 1024.0 * 1024.0),
                0,
                'f',
                2)
            .arg(snapshot_.vmExitCount)
            .arg(
                snapshot_.lastExitReason ==
                        KSWORD_ARK_HVM_EXIT_REASON_NONE
                    ? QStringLiteral("-")
                    : QString::number(snapshot_.lastExitReason)));
    summaryLabel_->setText(
        summaryLabel_->text() +
        kernelText(
            "kernel.hvm.summary.implementation",
            QStringLiteral(
                "\n实现成熟度（Resident / EPT / Nested / eVMCS）：%1 / %2 / %3 / %4；驻留 CPU：%5；规则：%6；事件：%7（丢失 %8 / 环回 %9 / 累计 %10）"))
            .arg(implementationText(
                snapshot_.residentImplementation))
            .arg(implementationText(
                snapshot_.eptImplementation))
            .arg(implementationText(
                snapshot_.nestedImplementation))
            .arg(implementationText(
                snapshot_.evmcsImplementation))
            .arg(snapshot_.residentProcessorCount)
            .arg(snapshot_.eptRuleCount)
            .arg(snapshot_.eventCount)
            .arg(snapshot_.droppedEventCount)
            .arg(snapshot_.overwrittenEventCount)
            .arg(snapshot_.publishedEventCount));
    /*
     * The physical mapping window occupies a separate line and is placed alongside the processor count.
     *
     * Its preparation-phase self-check is **completely invisible** elsewhere: if it fails, nested L2 entry and shadow
     * EPT synthesis simply reject silently without changing status bits, maturity, or processor count. Thus, what is
     * needed here is not "whether it exists" but "whether there is enough"—fewer processors than required means certain
     * cores will reject the function, and the rejection reason will point to the function itself, not the window.
     *
     * The denominator cannot be m_snapshot.processorCount. That represents the driver's 'prepared processor count',
     * which is 0 before resources are prepared, while the window is created during driver initialization. Using it as a
     * denominator would result in '2 / 0 — insufficient' immediately after loading the driver: the numerator is correct,
     * the denominator is wrong, and the conclusion is exactly reversed, falsely reporting a healthy machine as broken.
     */
    const unsigned long kLogicalProcessorCount =
        static_cast<unsigned long>(
            ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    summaryLabel_->setText(
        summaryLabel_->text() +
        ((kLogicalProcessorCount != 0UL &&
          snapshot_.physWindowReadyCount >= kLogicalProcessorCount)
            ? kernelText(
                  "kernel.hvm.summary.phys_window_ok",
                  QStringLiteral("\n退出安全物理窗口：%1 / %2 个处理器已就绪"))
                  .arg(snapshot_.physWindowReadyCount)
                  .arg(kLogicalProcessorCount)
            : kernelText(
                  "kernel.hvm.summary.phys_window_short",
                  QStringLiteral("\n退出安全物理窗口：%1 / %2 个处理器已就绪 —— **不足**。缺窗口的处理器上，嵌套 L2 进入与影子 EPT 合成会被拒绝，而报出来的理由会指向那些功能，不会指向窗口。"))
                  .arg(snapshot_.physWindowReadyCount)
                  .arg(kLogicalProcessorCount)));
    /*
     * Nested items must each occupy a separate line, and **both values must be reported together**.
     *
     * nestedState is transient: L2_ACTIVE holds only for the instant L2 is actually running; the
     * guest reverts to DISPATCH_READY immediately upon VMXOFF. Polling every two seconds will almost
     * never capture this instant, leading to the incorrect conclusion that 'L2 never started'.
     *
     * The rejection count is monotonic; the complement fills exactly this gap: if it
     * is non-zero, it means another hypervisor (VMware / VirtualBox / WSL2 / Docker)
     * on this machine attempted to launch a VM beneath us and was blocked. The user's
     * symptom is "My VM won't start," and prior to this, no reading pointed to us.
     */
    summaryLabel_->setText(
        summaryLabel_->text() +
        kernelText(
            "kernel.hvm.summary.nested",
            QStringLiteral("\n嵌套：%1（瞬时读数）　L2 进入被拒累计：%2"))
            .arg(nestedStateText(snapshot_.nestedState))
            .arg(snapshot_.nestedL2LaunchRefusedCount));

    // Use AMD-specific summary to avoid presenting Intel EPT and nested counts as evidence for AMD.
    //
    // The summary is a banner, not details: originally, the entire block contained seven lines of buildDetail
    // output, while m_detailEdit below displayed the same buildDetail—duplicate content on one page, with the
    // banner stretched to seven lines. Here, keep only one line and point to the details pane.
    if (snapshot_.backend == KSWORD_ARK_HVM_BACKEND_SVM)
    {
        summaryLabel_->setText(kernelText(
            "kernel.hvm.summary.amd",
            QStringLiteral("AMD SVM / VMCB / NPT（实验性）　准备 / 自检 / 常驻：%1 / %2 / %3　NPT 就绪：%4\n完整读数见下方详情；内层 SVM 与 EPT 扩展未实现。"))
            .arg(snapshot_.preparedProcessorCount)
            .arg(snapshot_.selfTestPassedProcessorCount)
            .arg(snapshot_.residentProcessorCount)
            .arg(snapshot_.slatReady
                ? kernelText("kernel.hvm.yes_plain", QStringLiteral("是"))
                : kernelText("kernel.hvm.no_plain", QStringLiteral("否"))));
    }

    const int kRowCount = static_cast<int>(std::min<unsigned long>(
        snapshot_.processorCount,
        KSWORD_ARK_HVM_MAX_PROCESSORS));
    cpuTable_->setRowCount(kRowCount);
    for (int rowIndex = 0; rowIndex < kRowCount; ++rowIndex)
    {
        const auto& cpu = snapshot_.processors[rowIndex];
        const bool kResourceReady =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY) != 0U;
        const bool kTested =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED) != 0U;
        const bool kPassed =
            (cpu.backend == KSWORD_ARK_HVM_BACKEND_SVM) ? kTested :
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED) != 0U;
        const bool kVmcsLoaded =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED) != 0U;
        const bool kGuestLaunched =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED) != 0U;
        const bool kVmExitHandled =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED) != 0U;
        cpuTable_->setItem(
            rowIndex,
            kCpuColumnProcessor,
            readOnlyItem(
                QStringLiteral("%1:%2")
                    .arg(cpu.processorGroup)
                    .arg(cpu.processorNumber)));
        cpuTable_->setItem(
            rowIndex,
            kCpuColumnResource,
            readOnlyItem(
                kResourceReady
                    ? kernelText("kernel.hvm.yes", QStringLiteral("已准备"))
                    : kernelText("kernel.hvm.no", QStringLiteral("未准备"))));
        cpuTable_->setItem(
            rowIndex,
            kCpuColumnSelfTest,
            readOnlyItem(
                !kTested
                    ? kernelText("kernel.hvm.not_tested", QStringLiteral("未执行"))
                    : (kPassed
                           ? kernelText("kernel.hvm.passed", QStringLiteral("通过"))
                           : kernelText("kernel.hvm.failed", QStringLiteral("失败")))));
        QString guestExitText = QStringLiteral("-");
        if (kVmExitHandled)
        {
            guestExitText = kernelText(
                "kernel.hvm.cpu.exit_handled",
                QStringLiteral("已退出（原因 %1）"))
                .arg(cpu.lastExitReason);
        }
        else if (kGuestLaunched)
        {
            guestExitText = kernelText(
                "kernel.hvm.cpu.launched",
                QStringLiteral("来宾已启动"));
        }
        else if (kVmcsLoaded)
        {
            guestExitText = kernelText(
                "kernel.hvm.cpu.vmcs_loaded",
                QStringLiteral("VMCS 已加载"));
        }
        cpuTable_->setItem(
            rowIndex,
            kCpuColumnGuestExit,
            // On AMD, this column shows the VMCB exit code, which is only meaningful after an actual exit occurs:
            // When VMRUN has not been executed, the field is zero. However, zero is a valid exit code (#DE). Previously, unconditionally
            // displaying it as 0x0000000000000000 made it appear as a hardware reading for a value that was never collected.
            readOnlyItem(cpu.backend == KSWORD_ARK_HVM_BACKEND_SVM
                ? (cpu.vmExitCount == 0ULL
                       ? QStringLiteral("-")
                       : QStringLiteral("0x%1")
                             .arg(cpu.svmExitCode, 16, 16, QLatin1Char('0')))
                : guestExitText));
        cpuTable_->setItem(
            rowIndex,
            kCpuColumnVmxResult,
            // This column's header is "Execution Status". Intel displays VM-instruction errors, while AMD displays the
            // execution stage—both indicate "where we are or where we failed" in this step, so they share the same column.
            // However, the stage must be translated to a name: a raw 3 in this table yields no readable information.
            readOnlyItem(
                cpu.backend == KSWORD_ARK_HVM_BACKEND_SVM
                    ? executionStageText(cpu.executionStage)
                    : cpu.vmxInstructionResult == 0xFFU
                        ? QStringLiteral("-")
                        : QString::number(cpu.vmxInstructionResult)));
        cpuTable_->setItem(
            rowIndex,
            kCpuColumnNtStatus,
            readOnlyItem(ntStatusText(cpu.lastStatus)));
    }
    detailEdit_->setPlainText(buildDetail(snapshot_));
    statusLabel_->setText(
        kernelText("kernel.hvm.status.ready", QStringLiteral("状态：已刷新")));
    updateButtons();
}

void KernelHvmTab::runControlAsync(
    const unsigned long command,
    const bool force,
    const bool enableEptEvents,
    const bool enableNestedVmx,
    const bool enableEvmcs)
{
    if (operationRunning_)
    {
        return;
    }
    operationRunning_ = true;
    statusLabel_->setText(
        kernelText(
            "kernel.hvm.status.operating",
            QStringLiteral("正在执行 HVM 生命周期操作...")));
    updateButtons();
    const unsigned long kGeneration = snapshot_.generation;
    /*
     * ALLOW_NESTED is derived from the user's nested switch setting, no longer determined by 'which feature page is currently active'.
     *
     * The original rule bound this bit to `m_featureArea == NestedVmx` and **structurally excluded
     * START_RESIDENT**. Consequently, on any machine with nested virtualization or VBS enabled, the page's
     * 'Start Resident VMM' always fails: the driver detects an outer hypervisor and the request lacks this
     * bit, returning STATUS_HV_FEATURE_UNAVAILABLE, causing the UI to report HYPERVISOR_CONFLICT.
     *
     * Harder to debug is that it only fails at the **last step**: PREPARE and SELF_TEST pass with this bit set
     * in nested paging, so the first two steps succeed, and the user hits a wall only at the end with an error
     * saying "hypervisor conflict"—which sounds like an environment issue, not a missing bit in the request.
     *
     * There is only one authoritative source: ksword::kvm::isNestedAllowed(), which corresponds to
     * the toggle in the virtualization menu. The KvmControl layer uses this directly. Following it
     * ensures there are no two entry points providing different flags for the same command.
     *
     * VALIDATE_NESTED retains its own additional conditions: its purpose is to probe nested capabilities;
     * if an item is selected for probing, this bit must be set even if the global switch is off.
     *
     * Only commands containing ALLOW_NESTED in the whitelist receive: TEARDOWN / STOP_RESIDENT / RESET_FAULT
     * are not accepted for them; providing an extra bit causes the entire request to be judged INVALID_REQUEST.
     */
    const bool kCommandAcceptsNested =
        command == KSWORD_ARK_HVM_CONTROL_PREPARE ||
        command == KSWORD_ARK_HVM_CONTROL_SELF_TEST ||
        command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST ||
        command == KSWORD_ARK_HVM_CONTROL_START_RESIDENT ||
        command == KSWORD_ARK_HVM_CONTROL_SOAK ||
        command == KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED;
    const bool kAllowNested = kCommandAcceptsNested &&
        (ksword::kvm::isNestedAllowed() ||
         (command == KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED &&
          (enableNestedVmx || enableEvmcs)));
    /*
     * Backend selection must follow the same authoritative source and can only be provided on PREPARE.
     *
     * These two flags are only read during PREPARE. The driver finalizes the backend when
     * preparing resources, and START_RESIDENT checks that already-fixed value. Since
     * neither flag was initially set (controlHvm's subsequent parameters default to
     * false), the resources prepared from this page always default to the MTF backend.
     *
     * The consequences manifest only on machines without MTF support — i.e., **every nested machine or one with VBS enabled**:
     * The separated view only works with the EPTP-switching backend; preparing here will never
     * succeed, yet the UI provides no indication. The same switch works via the virtualization
     * menu path, causing the two paths to yield different results for the same setting.
     *
     * The whitelist is strict: providing an extra bit causes the entire request to be rejected as INVALID_REQUEST instead of ignoring that bit.
     */
    const bool kPrepareBackendFlags =
        (command == KSWORD_ARK_HVM_CONTROL_PREPARE);
    /*
     * This private EPT bit must be sent twice: once for PREPARE and again for START_RESIDENT.
     *
     * This is not redundant. PREPARE sets LocalEptArmed (indicating whether the hierarchy is ready),
     * while the driver's actual criterion for deciding whether to use a private hierarchy for resident
     * mode is `(Flags & ENABLE_LOCAL_EPT) && Runtime->LocalEptArmed`—both conditions must be met.
     * If only PREPARE is issued, the first half is always false, so resident always runs at the shared hierarchy.
     *
     * Symptoms mirror the PREPARE section above: on multi-core machines, the EPT view fails to load,
     * yet the UI provides no indication of the cause—the switch is checked, and preparation succeeds.
     * The whitelist confirms that START_RESIDENT accepts this flag (see allowedFlags in hvm_runtime.c).
     *
     * The backend deliberately does not follow EPTP switching: ENABLE_EPTP_SWITCH is **not** in the
     * START_RESIDENT whitelist. Sending an extra bit causes the entire request to be judged INVALID_REQUEST.
     * The backend selects this at preparation; the resident startup check uses that pre-determined value.
     */
    const bool kResidentFeatureFlags =
        (command == KSWORD_ARK_HVM_CONTROL_START_RESIDENT);
    const bool kEnableLocalEpt =
        (kPrepareBackendFlags || kResidentFeatureFlags) &&
        ksword::kvm::isLocalEptEnabled();
    const bool kEnableEptpSwitch =
        kPrepareBackendFlags && ksword::kvm::isEptpSwitchEnabled();
    const bool kEnableVe = kResidentFeatureFlags && ksword::kvm::isVeEnabled();
    const bool kEnableVmFunc = kResidentFeatureFlags && ksword::kvm::isVmFuncEnabled();
    const bool kHideHypervisor = kResidentFeatureFlags && ksword::kvm::isHypervisorHidden();
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([
        safeThis,
        command,
        kGeneration,
        force,
        kAllowNested,
        enableEptEvents,
        enableNestedVmx,
        enableEvmcs,
        kEnableLocalEpt,
        kEnableEptpSwitch, kEnableVe, kEnableVmFunc, kHideHypervisor]() {
        ksword::ark::DriverClient client;
        auto control = client.controlHvm(
            command,
            kGeneration,
            force,
            kAllowNested,
            true,
            enableEptEvents,
            enableNestedVmx,
            enableEvmcs,
            kEnableVe,
            kEnableVmFunc,
            kEnableLocalEpt,
            kEnableEptpSwitch, 0UL, kHideHypervisor);
        auto status = client.queryHvmStatus();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis,
             command,
             control = std::move(control),
             status = std::move(status)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyControl(
                        command,
                        std::move(control),
                        std::move(status));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyControl(
    const unsigned long command,
    ksword::ark::HvmControlResult control,
    ksword::ark::HvmStatusResult status)
{
    operationRunning_ = false;
    const bool kPartial =
        control.io.ok &&
        control.response.status ==
            KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION;
    if (kPartial)
    {
        QMessageBox::warning(
            this,
            kernelText(
                "kernel.hvm.operation.title",
                QStringLiteral("HVM 操作")),
            kernelText(
                "kernel.hvm.operation.partial",
                QStringLiteral(
                    "能力检查已完成，但实现成熟度为 partial，未进入 active。"
                    "\nResident / EPT / Nested / eVMCS：%1 / %2 / %3 / %4"
                    "\nNTSTATUS：%5"
                    "\nNested 不会运行 L2；eVMCS 未接管 VP-assist/clean fields。"))
                .arg(control.response.residentImplementation)
                .arg(control.response.eptImplementation)
                .arg(control.response.nestedImplementation)
                .arg(control.response.evmcsImplementation)
                .arg(ntStatusText(control.response.lastStatus)));
    }
    else if (!control.io.ok ||
             control.response.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            kernelText("kernel.hvm.operation.title", QStringLiteral("HVM 操作")),
            kernelText(
                "kernel.hvm.operation.failed",
                QStringLiteral("操作未完成。\n协议状态：%1\nNTSTATUS：%2\n%3"))
                .arg(control.response.status)
                .arg(ntStatusText(control.response.lastStatus))
                .arg(QString::fromStdString(control.io.message)));
    }
    else
    {
        QString action;
        if (command == KSWORD_ARK_HVM_CONTROL_PREPARE)
        {
            action = kernelText(
                "kernel.hvm.action.prepared",
                QStringLiteral("VMX/EPT 后端已准备"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_SELF_TEST)
        {
            action = kernelText(
                "kernel.hvm.action.tested",
                QStringLiteral("逐 CPU VMX 自检已完成"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST)
        {
            action = kernelText(
                "kernel.hvm.action.launched",
                QStringLiteral("一次性来宾已 VMLAUNCH，并通过 VMCALL 完成 VM-exit"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_START_RESIDENT)
        {
            action = kernelText(
                "kernel.hvm.action.resident_started",
                QStringLiteral(
                    "所有目标 CPU 已进入驻留 VMX non-root；"
                    "只有完整 rendezvous 成功后才标记为 active"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT)
        {
            action = kernelText(
                "kernel.hvm.action.resident_stopped",
                QStringLiteral(
                    "驻留 VMM 已停止；所有完成处理器均已 VMXOFF 并恢复原始 CR4"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_RESET_FAULT)
        {
            action = kernelText(
                "kernel.hvm.action.fault_reset",
                QStringLiteral("已清除停止状态下的可恢复故障标记"));
        }
        else
        {
            action = kernelText(
                "kernel.hvm.action.torn_down",
                QStringLiteral("HVM 后端资源已释放"));
        }
        QMessageBox::information(
            this,
            kernelText("kernel.hvm.operation.title", QStringLiteral("HVM 操作")),
            action);
    }
    applyStatus(std::move(status));
}

void KernelHvmTab::prepareBackend()
{
    const QString kWarning = kernelText(
        "kernel.hvm.prepare.warning",
        QStringLiteral(
            "按当前后端为每个 CPU 分配控制结构、保存区及页表。AMD 使用 VMCB/HSAVE 和完整 NPT 身份映射，Intel 使用 VMXON/VMCS/EPT。准备会占用不可分页内存，但不会进入常驻；只有全部 CPU 停止后才能释放。"));
    if (confirmTyped(kWarning, kernelText("kernel.hvm.prepare", QStringLiteral("准备虚拟化后端"))))
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_PREPARE, false);
    }
}

void KernelHvmTab::selfTestBackend()
{
    const QString kWarning = kernelText(
        "kernel.hvm.self_test.warning",
        QStringLiteral(
            "驱动将绑定每个 CPU 执行硬件自检。AMD 必须完成一次带已知退出标记的 VMRUN 往返并恢复原生状态；Intel 执行 VMX 自检。请在调试虚拟机中保存工作并连接调试器，硬件或恢复错误可能导致蓝屏。"));
    if (confirmTyped(kWarning, kernelText("kernel.hvm.self_test", QStringLiteral("逐 CPU 自检"))))
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_SELF_TEST, true);
    }
}

void KernelHvmTab::launchControlledGuest()
{
    const QString kWarning = kernelText(
        "kernel.hvm.launch.warning",
        QStringLiteral(
            "这是实际的高风险 VM-entry：驱动会在一个已自检 CPU 上进入 VMX root，装载完整 VMCS，真实执行 VMLAUNCH。"
            "一次性来宾只执行 VMCALL；VM-exit 入口会采集退出原因、qualification、RIP/RSP 和 VM-instruction error，随后 VMCLEAR、VMXOFF 并恢复 CR4。"
            "任何 VMCS、EPT、固件、Hyper-V/VBS、嵌套虚拟化或处理器实现异常都可能导致系统不稳定、蓝屏或必须重启。"
            "请先保存全部工作；外层已有 Hypervisor 时，请求必须带上嵌套允许位，也就是虚拟化菜单里的「允许嵌套运行（作为 L1）」，并且外层确实把 VMX 暴露进来。"));
    if (confirmTyped(kWarning, kernelText("kernel.hvm.launch", QStringLiteral("启动一次性来宾"))))
    {
        runControlAsync(
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST,
            true);
    }
}

void KernelHvmTab::teardownBackend()
{
    const bool kConfirmationSuppressed =
        ks::settings::dangerousActionConfirmationsSuppressed();
    if (kConfirmationSuppressed ||
        QMessageBox::question(
                this,
                kernelText("kernel.hvm.teardown.title", QStringLiteral("释放 HVM 后端")),
                kernelText(
                    "kernel.hvm.teardown.warning",
                    QStringLiteral(
                        "全部 CPU 停止后释放当前后端资源，并清除准备和自检证据。请先导出诊断记录。继续吗？")),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) == QMessageBox::Yes)
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_TEARDOWN, false);
    }
}

bool KernelHvmTab::confirmTyped(
    const QString& warning,
    const QString& phrase)
{
    if (ks::settings::dangerousActionConfirmationsSuppressed())
    {
        return true;
    }
    const auto kAnswer = QMessageBox::warning(
        this,
        kernelText("kernel.hvm.confirm.title", QStringLiteral("内核虚拟化风险确认")),
        warning,
        QMessageBox::Ok | QMessageBox::Cancel,
        QMessageBox::Cancel);
    if (kAnswer != QMessageBox::Ok)
    {
        return false;
    }

    // Changed secondary confirmation to direct click: no longer requires manual entry of the confirmation phrase.
    // phrase is still displayed as an action identifier to let the user clearly identify which operation is being confirmed.
    const auto kFinalAnswer = QMessageBox::warning(
        this,
        kernelText("kernel.hvm.confirm.final.title", QStringLiteral("最终确认")),
        kernelText(
            "kernel.hvm.confirm.final.prompt",
            QStringLiteral("确认执行“%1”？此操作可能导致系统不稳定。"))
            .arg(phrase),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    return kFinalAnswer == QMessageBox::Yes;
}

void KernelHvmTab::updateButtons()
{
    const bool kAmd = snapshot_.backend == KSWORD_ARK_HVM_BACKEND_SVM;
    const bool kResourcesReady =
        (snapshot_.stateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0U;
    const bool kGuestReady =
        (snapshot_.stateFlags &
            KSWORD_ARK_HVM_STATE_GUEST_READY) != 0U;
    const bool kGuestRunning =
        (snapshot_.stateFlags &
            KSWORD_ARK_HVM_STATE_GUEST_RUNNING) != 0U;
    const bool kResidentActive =
        (snapshot_.stateFlags &
            KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) != 0U;
    const bool kSelfTestPassed =
        (snapshot_.stateFlags &
            KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) != 0U;
    const bool kResidentAvailable =
        (snapshot_.featureFlags &
            (KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
             KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED)) ==
            (KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
             KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED) &&
        snapshot_.residentImplementation !=
            KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED &&
        (snapshot_.stateFlags &
            (KSWORD_ARK_HVM_STATE_EPT_TRUNCATED |
             KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING |
             KSWORD_ARK_HVM_STATE_FAULTED |
             KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED |
             KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED)) == 0U;
    refreshButton_->setEnabled(!operationRunning_);

    // Each button below counts as one 'first door blocking it'. The order corresponds to the
    // conditions in setEnabled; changing one side requires changing the other simultaneously.
    const QString kBusyReason = kernelText(
        "kernel.hvm.gate.busy",
        QStringLiteral("灰掉的原因：另一项虚拟化操作正在执行。"));
    const QString kUnsupportedReason = kernelText(
        "kernel.hvm.gate.unsupported",
        QStringLiteral("灰掉的原因：当前 CPU 或驱动不提供硬件虚拟化后端。"));
    const QString kNeedResourcesReason = kernelText(
        "kernel.hvm.gate.needs_resources",
        QStringLiteral("灰掉的原因：需要先准备虚拟化后端。"));
    const QString kResidentActiveReason = kernelText(
        "kernel.hvm.gate.resident_active",
        QStringLiteral("灰掉的原因：驻留 VMM 正在运行；先点“停止驻留 VMM”。"));
    // commonReason: A gate applied uniformly to all buttons, returning based on their actual evaluation order.
    const auto kCommonReason = [&]() -> QString {
        if (operationRunning_) { return kBusyReason; }
        if (!supported_) { return kUnsupportedReason; }
        return QString();
    };

    prepareButton_->setEnabled(
        !operationRunning_ && supported_ && !kResourcesReady);
    setGateTooltip(prepareButton_, [&]() -> QString {
        const QString kCommon = kCommonReason();
        if (!kCommon.isEmpty()) { return kCommon; }
        if (kResourcesReady)
        {
            return kernelText(
                "kernel.hvm.gate.already_prepared",
                QStringLiteral("灰掉的原因：资源已经准备过了；要重新准备先点“释放后端”。"));
        }
        return QString();
    }());

    selfTestButton_->setEnabled(
        !operationRunning_ &&
        supported_ &&
        kResourcesReady &&
        !kResidentActive);
    setGateTooltip(selfTestButton_, [&]() -> QString {
        const QString kCommon = kCommonReason();
        if (!kCommon.isEmpty()) { return kCommon; }
        if (!kResourcesReady) { return kNeedResourcesReason; }
        if (kResidentActive) { return kResidentActiveReason; }
        return QString();
    }());

    launchButton_->setEnabled(
        !operationRunning_ &&
        supported_ &&
        kGuestReady &&
        !kGuestRunning &&
        !kResidentActive);
    setGateTooltip(launchButton_, [&]() -> QString {
        const QString kCommon = kCommonReason();
        if (!kCommon.isEmpty()) { return kCommon; }
        if (!kGuestReady)
        {
            return kernelText(
                "kernel.hvm.gate.guest_not_ready",
                QStringLiteral("灰掉的原因：一次性来宾尚未就绪，需要先准备资源并通过逐 CPU 自检。"));
        }
        if (kGuestRunning)
        {
            return kernelText(
                "kernel.hvm.gate.guest_running",
                QStringLiteral("灰掉的原因：一次性来宾正在运行。"));
        }
        if (kResidentActive) { return kResidentActiveReason; }
        return QString();
    }());

    teardownButton_->setEnabled(
        !operationRunning_ &&
        supported_ &&
        kResourcesReady &&
        !kGuestRunning &&
        !kResidentActive);
    setGateTooltip(teardownButton_, [&]() -> QString {
        const QString kCommon = kCommonReason();
        if (!kCommon.isEmpty()) { return kCommon; }
        if (!kResourcesReady)
        {
            return kernelText(
                "kernel.hvm.gate.nothing_to_release",
                QStringLiteral("灰掉的原因：当前没有已准备的资源可释放。"));
        }
        if (kGuestRunning)
        {
            return kernelText(
                "kernel.hvm.gate.guest_running",
                QStringLiteral("灰掉的原因：一次性来宾正在运行。"));
        }
        if (kResidentActive) { return kResidentActiveReason; }
        return QString();
    }());

    startResidentButton_->setEnabled(
        !operationRunning_ &&
        supported_ &&
        kResidentAvailable &&
        kSelfTestPassed &&
        !kResidentActive &&
        featureArea_ != FeatureArea::kEvmcs);
    setGateTooltip(startResidentButton_, [&]() -> QString {
        const QString kCommon = kCommonReason();
        if (!kCommon.isEmpty()) { return kCommon; }
        if (featureArea_ == FeatureArea::kEvmcs)
        {
            return kernelText(
                "kernel.hvm.gate.evmcs_no_resident",
                QStringLiteral("灰掉的原因：eVMCS 视图不提供常驻启动入口。"));
        }
        if (!kResidentAvailable)
        {
            /*
             * Identify the specific actual blocker bit-by-bit, rather than listing a string of possible causes.
             *
             * Originally a static string, this reason no longer matches the calculation of
             * `residentAvailable` above: it claims "outer Hypervisor present" blocks, but the code never
             * checks that bit. Moreover, the statement is outdated; running under an outer hypervisor is now
             * possible (with `ALLOW_NESTED`). Conversely, it omits the actual check performed by the code.
             * UNLOAD_GUARD_ARMED。
             *
             * Deriving from the same set of flags ensures both sides cannot speak at cross-purposes.
             */
            const auto kBlockedBy = [&](const unsigned long long flag) {
                return (snapshot_.stateFlags & flag) != 0ULL;
            };
            if (snapshot_.residentImplementation ==
                    KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED ||
                (snapshot_.featureFlags &
                    (KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
                     KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED)) !=
                    (KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
                     KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED))
            {
                return kernelText(
                    "kernel.hvm.gate.resident_unsupported",
                    QStringLiteral("灰掉的原因：驱动没有报告可用的常驻 VMM 后端（能力位或实现成熟度不足）。"));
            }
            if (kBlockedBy(KSWORD_ARK_HVM_STATE_EPT_TRUNCATED))
            {
                return kernelText(
                    "kernel.hvm.gate.resident_ept_truncated",
                    QStringLiteral("灰掉的原因：EPT 恒等映射被截断，常驻启动会看不到部分物理内存。"));
            }
            if (kBlockedBy(KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING))
            {
                return kernelText(
                    "kernel.hvm.gate.resident_power_pending",
                    QStringLiteral("灰掉的原因：有一次电源状态转换正在进行，此时启动常驻会在挂起路径上失去处理器。"));
            }
            if (kBlockedBy(KSWORD_ARK_HVM_STATE_FAULTED))
            {
                return kernelText(
                    "kernel.hvm.gate.resident_faulted",
                    QStringLiteral("灰掉的原因：运行时处于 FAULTED。先“清除故障”，而它要求常驻已经停下。"));
            }
            if (kBlockedBy(KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED))
            {
                return kernelText(
                    "kernel.hvm.gate.resident_rollback",
                    QStringLiteral("灰掉的原因：上一次操作留下了待回滚的状态，必须先“释放后端”。"));
            }
            if (kBlockedBy(KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED))
            {
                return kernelText(
                    "kernel.hvm.gate.resident_unload_guard",
                    QStringLiteral("灰掉的原因：驱动卸载保护已武装 —— 有一次卸载正在等待常驻退出。"));
            }
            return kernelText(
                "kernel.hvm.gate.resident_unavailable",
                QStringLiteral("灰掉的原因：驱动侧常驻硬件门未通过，但没有单独一条状态位能解释它。请把“刷新”后的状态位报出来。"));
        }
        if (!kSelfTestPassed)
        {
            return kernelText(
                "kernel.hvm.gate.self_test_required",
                QStringLiteral("灰掉的原因：需要先通过“逐 CPU 自检”。"));
        }
        if (kResidentActive)
        {
            return kernelText(
                "kernel.hvm.gate.already_resident",
                QStringLiteral("灰掉的原因：驻留 VMM 已经在运行。"));
        }
        return QString();
    }());

    stopResidentButton_->setEnabled(
        !operationRunning_ &&
        supported_ &&
        kResidentActive);
    setGateTooltip(stopResidentButton_, [&]() -> QString {
        const QString kCommon = kCommonReason();
        if (!kCommon.isEmpty()) { return kCommon; }
        if (!kResidentActive)
        {
            return kernelText(
                "kernel.hvm.gate.resident_inactive",
                QStringLiteral("灰掉的原因：当前没有驻留 VMM 在运行。"));
        }
        return QString();
    }());

    featureActionButton_->setEnabled(
        !operationRunning_ &&
        supported_ &&
        (featureArea_ != FeatureArea::kKept || kResourcesReady));
    setGateTooltip(featureActionButton_, [&]() -> QString {
        const QString kCommon = kCommonReason();
        if (!kCommon.isEmpty()) { return kCommon; }
        if (featureArea_ == FeatureArea::kKept && !kResourcesReady)
        {
            return kNeedResourcesReason;
        }
        return QString();
    }());
    if (kAmd)
    {
        // Do not wrap the button text. Previously, "Prepare Resources" was rewritten as "SVM / VMCB /
        // NPT", replacing an action name with an architecture name: the button no longer describes what
        // it does, while the backend details are already shown in the status at the top of the page.
        launchButton_->setEnabled(false);
        featureActionButton_->setEnabled(false);
        const QString kAmdFeatureReason = kernelText(
            "kernel.hvm.gate.amd_intel_only",
            QStringLiteral("灰掉的原因：这一项建立在 Intel VMX 的 VMCS 字段或 EPT 分离视图上，当前的 AMD SVM/NPT 后端还没有对应实现。"));
        setGateTooltip(launchButton_, kAmdFeatureReason);
        setGateTooltip(featureActionButton_, kAmdFeatureReason);

        // Intel-exclusive switches are not silently applied to AMD.
        //
        // Gray out the two buttons and explicitly list which switches are involved: all these switches are persisted or
        // retained across sessions. The user may have opened this on a different Intel machine; here they only see two gray
        // buttons with no indication of where to disable them. Previously, there was no explanation here, creating a dead end.
        QStringList blockingOptions;
        if (ksword::kvm::isLocalEptEnabled())
        {
            blockingOptions << kernelText("kernel.hvm.option.local_ept",
                QStringLiteral("每处理器私有 EPT"));
        }
        if (ksword::kvm::isEptpSwitchEnabled())
        {
            blockingOptions << kernelText("kernel.hvm.option.eptp_switch",
                QStringLiteral("EPTP 切换后端"));
        }
        if (ksword::kvm::isNestedDispatchEnabled())
        {
            blockingOptions << kernelText("kernel.hvm.option.nested_dispatch",
                QStringLiteral("嵌套 VMX 派发"));
        }
        if (ksword::kvm::isVeEnabled())
        {
            blockingOptions << kernelText("kernel.hvm.option.ve",
                QStringLiteral("#VE 反射"));
        }
        if (ksword::kvm::isVmFuncEnabled())
        {
            blockingOptions << kernelText("kernel.hvm.option.vmfunc",
                QStringLiteral("VMFUNC"));
        }
        if (ksword::kvm::isHypervisorHidden())
        {
            blockingOptions << kernelText("kernel.hvm.option.hide_hypervisor",
                QStringLiteral("隐藏 Hypervisor 身份"));
        }
        if (!blockingOptions.isEmpty())
        {
            const QString kOptionReason = kernelText(
                "kernel.hvm.gate.amd_intel_options",
                QStringLiteral("灰掉的原因：以下 Intel 专属选项当前是打开的，AMD 后端不接受它们：%1。请在标题栏 KVM 按钮的右键菜单里关掉后重试。"))
                .arg(blockingOptions.join(
                    kernelText("kernel.hvm.option.separator", QStringLiteral("、"))));
            prepareButton_->setEnabled(false);
            startResidentButton_->setEnabled(false);
            setGateTooltip(prepareButton_, kOptionReason);
            setGateTooltip(startResidentButton_, kOptionReason);
        }
    }
}
