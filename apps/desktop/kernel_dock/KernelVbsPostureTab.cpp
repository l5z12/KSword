#include "KernelVbsPostureTab.h"

#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QList>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QVBoxLayout>

#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum PostureColumn : int
    {
        kPostureColumnItem = 0,
        kPostureColumnObserved,
        kPostureColumnVerdict,
        kPostureColumnSource,
        kPostureColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString hex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')).toUpper().replace(
            QStringLiteral("0X"), QStringLiteral("0x"));
    }

    // A module is considered truly loaded only if its state is PRESENT; UNKNOWN/UNAVAILABLE merely indicates missing evidence.
    bool modulePresent(const std::uint32_t state)
    {
        return state == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT;
    }
}

KernelVbsPostureTab::KernelVbsPostureTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelVbsPostureTab::showEvent(QShowEvent* event)
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

void KernelVbsPostureTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        kernelText("kernel.vbs_posture.refresh", QStringLiteral("刷新姿态")),
        this);
    // Assessment criteria do not occupy layout space: attached to the trigger collection button; hover to view.
    refreshButton_->setToolTip(
        kernelText(
            "kernel.vbs_posture.refresh.tooltip",
            QStringLiteral("策略位只说明「配置想开」，HVCI 真正生效还需要 hypervisor 在位且 securekernel.exe / skci.dll 已加载。")));
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    statusLabel_ = new QLabel(
        kernelText("kernel.vbs_posture.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    toolbar->addWidget(refreshButton_);
    toolbar->addStretch(1);
    toolbar->addWidget(statusLabel_);
    rootLayout->addLayout(toolbar);

    verdictLabel_ = new QLabel(this);
    verdictLabel_->setWordWrap(true);
    verdictLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    verdictLabel_->setStyleSheet(
        QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
            .arg(ksword_theme::textPrimaryHex()));
    rootLayout->addWidget(verdictLabel_);

    downgradeLabel_ = new QLabel(this);
    downgradeLabel_->setWordWrap(true);
    downgradeLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    downgradeLabel_->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;color:%1;}").arg(ksword_theme::textPrimaryHex()));
    rootLayout->addWidget(downgradeLabel_);

    auto* splitter = new QSplitter(Qt::Vertical, this);

    table_ = new ks::ui::VisibleTableWidget(splitter);
    table_->setColumnCount(kPostureColumnCount);
    table_->setHorizontalHeaderLabels({
        kernelText("kernel.vbs_posture.column.item", QStringLiteral("检查项")),
        kernelText("kernel.vbs_posture.column.observed", QStringLiteral("观测值")),
        kernelText("kernel.vbs_posture.column.verdict", QStringLiteral("判定")),
        kernelText("kernel.vbs_posture.column.source", QStringLiteral("证据来源"))
    });
    // If evidence from both sides is inconsistent, treat it as disabled.
    QTableWidgetItem* verdictHeader = table_->horizontalHeaderItem(kPostureColumnVerdict);
    if (verdictHeader != nullptr)
    {
        verdictHeader->setToolTip(
            kernelText(
                "kernel.vbs_posture.column.verdict.tooltip",
                QStringLiteral("策略位与运行证据不一致时一律按未启用处理，不会因为策略位为 1 就判定为已启用。")));
    }
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setStretchLastSection(true);

    detailEdit_ = new QTextEdit(splitter);
    detailEdit_->setReadOnly(true);
    detailEdit_->setPlaceholderText(
        kernelText(
            "kernel.vbs_posture.detail.placeholder",
            QStringLiteral("刷新后显示 CodeIntegrity 选项掩码、Hyper-V 模块状态与原始 NTSTATUS")));

    splitter->addWidget(table_);
    splitter->addWidget(detailEdit_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
}

void KernelVbsPostureTab::refreshAsync()
{
    if (queryRunning_)
    {
        return;
    }
    queryRunning_ = true;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(
        kernelText(
            "kernel.vbs_posture.status.refreshing",
            QStringLiteral("状态：正在采集只读安全姿态...")));

    QPointer<KernelVbsPostureTab> safeThis(this);
    std::thread([safeThis]() {
        ksword::ark::DriverClient client;
        Snapshot snapshot;
        snapshot.security = client.querySecurityStatus();
        snapshot.hyperV = client.queryHyperVSummary();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, snapshot = std::move(snapshot)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applySnapshot(std::move(snapshot));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelVbsPostureTab::applySnapshot(Snapshot snapshot)
{
    queryRunning_ = false;
    refreshButton_->setEnabled(true);

    if (!snapshot.security.io.ok)
    {
        table_->setRowCount(0);
        detailEdit_->clear();
        downgradeLabel_->clear();
        const QString kFailureText = snapshot.security.unsupported
            ? kernelText(
                "kernel.vbs_posture.status.unsupported",
                QStringLiteral("状态：当前驱动不支持安全姿态审计协议"))
            : kernelText(
                "kernel.vbs_posture.status.failed",
                QStringLiteral("状态：读取失败（%1）"))
                .arg(QString::fromStdString(snapshot.security.io.message));
        statusLabel_->setText(kFailureText);
        verdictLabel_->setText(kFailureText);
        verdictLabel_->setStyleSheet(
            QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
                .arg(ksword_theme::errorHex()));
        return;
    }

    const QList<PostureRow> kRows = buildRows(snapshot);
    populateTable(kRows);
    applyVerdictBanner(snapshot, kRows);
    detailEdit_->setPlainText(buildDetail(snapshot));
    statusLabel_->setText(
        snapshot.security.response.queryStatus < 0
            ? kernelText(
                "kernel.vbs_posture.status.partial",
                QStringLiteral("状态：部分证据不可用（%1）"))
                .arg(ntStatusText(snapshot.security.response.queryStatus))
            : kernelText("kernel.vbs_posture.status.ready", QStringLiteral("状态：已刷新")));
}

QList<KernelVbsPostureTab::PostureRow> KernelVbsPostureTab::buildRows(const Snapshot& snapshot)
{
    const auto& security = snapshot.security.response;
    const bool kHyperVOk = snapshot.hyperV.io.ok;
    const auto& hyperV = snapshot.hyperV.response;

    const QString kSourceCi = QStringLiteral("SystemCodeIntegrityInformation");
    const QString kSourceModule = kernelText(
        "kernel.vbs_posture.source.module", QStringLiteral("已加载模块快照"));
    const QString kSourceCpuid = QStringLiteral("CPUID");

    QList<PostureRow> rows;

    // First group: Policy intent.
    rows.append({
        kernelText("kernel.vbs_posture.item.kmci_policy", QStringLiteral("HVCI/KMCI 策略位")),
        boolText(security.hvciKmciEnabled),
        security.hvciKmciEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.policy_on", QStringLiteral("策略要求启用"))
            : kernelText("kernel.vbs_posture.verdict.policy_off", QStringLiteral("策略未启用")),
        kSourceCi,
        security.hvciKmciEnabled != 0U ? Severity::kGood : Severity::kBad,
        false
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.kmci_audit", QStringLiteral("HVCI/KMCI 审计模式")),
        boolText(security.hvciAuditMode),
        security.hvciAuditMode != 0U
            ? kernelText("kernel.vbs_posture.verdict.audit_only", QStringLiteral("只记录不阻断，等同未强制"))
            : kernelText("kernel.vbs_posture.verdict.enforcing", QStringLiteral("非审计模式")),
        kSourceCi,
        security.hvciAuditMode != 0U ? Severity::kBad : Severity::kGood,
        security.hvciAuditMode != 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.kmci_strict", QStringLiteral("HVCI/KMCI 严格模式")),
        boolText(security.hvciStrictMode),
        security.hvciStrictMode != 0U
            ? kernelText("kernel.vbs_posture.verdict.strict_on", QStringLiteral("严格模式已开"))
            : kernelText("kernel.vbs_posture.verdict.strict_off", QStringLiteral("未开启严格模式")),
        kSourceCi,
        security.hvciStrictMode != 0U ? Severity::kGood : Severity::kNeutral,
        false
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.ium", QStringLiteral("IUM（隔离用户模式）签名")),
        boolText(security.hvciIumEnabled),
        security.hvciIumEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.ium_on", QStringLiteral("已启用"))
            : kernelText("kernel.vbs_posture.verdict.ium_off", QStringLiteral("未启用")),
        kSourceCi,
        security.hvciIumEnabled != 0U ? Severity::kGood : Severity::kNeutral,
        false
    });

    // Second group: runtime evidence. If the policy bit is true but this group is missing, it means 'thought to be on but actually off'.
    rows.append({
        kernelText("kernel.vbs_posture.item.hypervisor", QStringLiteral("Hypervisor 在位")),
        kHyperVOk
            ? QStringLiteral("%1 %2")
                .arg(moduleStateText(hyperV.hypervisorPresent))
                .arg(fixedWide(hyperV.hypervisorVendor, sizeof(hyperV.hypervisorVendor) / sizeof(wchar_t)))
                .trimmed()
            : moduleStateText(KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE),
        (kHyperVOk && modulePresent(hyperV.hypervisorPresent))
            ? kernelText("kernel.vbs_posture.verdict.hv_present", QStringLiteral("CPUID 报告 hypervisor 存在"))
            : kernelText("kernel.vbs_posture.verdict.hv_absent", QStringLiteral("未观测到 hypervisor")),
        kSourceCpuid,
        (kHyperVOk && modulePresent(hyperV.hypervisorPresent)) ? Severity::kGood : Severity::kBad,
        false
    });
    rows.append({
        QStringLiteral("securekernel.exe"),
        moduleStateText(security.secureKernelModuleLoaded),
        modulePresent(security.secureKernelModuleLoaded)
            ? kernelText("kernel.vbs_posture.verdict.sk_loaded", QStringLiteral("安全内核已加载"))
            : kernelText("kernel.vbs_posture.verdict.sk_missing", QStringLiteral("未观测到安全内核")),
        kSourceModule,
        modulePresent(security.secureKernelModuleLoaded) ? Severity::kGood : Severity::kBad,
        false
    });
    rows.append({
        QStringLiteral("skci.dll"),
        moduleStateText(security.skciModuleLoaded),
        modulePresent(security.skciModuleLoaded)
            ? kernelText("kernel.vbs_posture.verdict.skci_loaded", QStringLiteral("VTL1 代码完整性模块已加载"))
            : kernelText("kernel.vbs_posture.verdict.skci_missing", QStringLiteral("未观测到 skci")),
        kSourceModule,
        modulePresent(security.skciModuleLoaded) ? Severity::kGood : Severity::kBad,
        false
    });
    rows.append({
        QStringLiteral("ci.dll"),
        moduleStateText(security.ciModuleLoaded),
        modulePresent(security.ciModuleLoaded)
            ? kernelText("kernel.vbs_posture.verdict.ci_loaded", QStringLiteral("VTL0 代码完整性模块已加载"))
            : kernelText("kernel.vbs_posture.verdict.ci_missing", QStringLiteral("未观测到 ci")),
        kSourceModule,
        modulePresent(security.ciModuleLoaded) ? Severity::kGood : Severity::kWarning,
        false
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.vbs_derived", QStringLiteral("VBS 存在（派生值）")),
        boolText(security.vbsPresent),
        kernelText(
            "kernel.vbs_posture.verdict.vbs_derived",
            QStringLiteral("由策略位与模块状态推导，不作为独立运行证据")),
        kSourceModule,
        Severity::kNeutral,
        false
    });

    // Third group: Downgrade items that weaken kernel code integrity.
    rows.append({
        kernelText("kernel.vbs_posture.item.ci_enabled", QStringLiteral("内核 CI 启用")),
        boolText(security.ciEnabled),
        security.ciEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.ci_on", QStringLiteral("已启用"))
            : kernelText("kernel.vbs_posture.verdict.ci_off", QStringLiteral("未启用")),
        kSourceCi,
        security.ciEnabled != 0U ? Severity::kGood : Severity::kBad,
        security.ciEnabled == 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.testsigning", QStringLiteral("测试签名模式")),
        boolText(security.testSigningEnabled),
        security.testSigningEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.testsign_on", QStringLiteral("允许加载测试签名驱动"))
            : kernelText("kernel.vbs_posture.verdict.testsign_off", QStringLiteral("未开启")),
        kSourceCi,
        security.testSigningEnabled != 0U ? Severity::kBad : Severity::kGood,
        security.testSigningEnabled != 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.ci_debug", QStringLiteral("CI 调试模式")),
        boolText(security.ciDebugModeEnabled),
        security.ciDebugModeEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.ci_debug_on", QStringLiteral("代码完整性策略被放宽"))
            : kernelText("kernel.vbs_posture.verdict.ci_debug_off", QStringLiteral("未开启")),
        kSourceCi,
        security.ciDebugModeEnabled != 0U ? Severity::kBad : Severity::kGood,
        security.ciDebugModeEnabled != 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.kd", QStringLiteral("内核调试器")),
        boolText(security.kernelDebuggerEnabled),
        security.kernelDebuggerEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.kd_on", QStringLiteral("已连接或已启用"))
            : kernelText("kernel.vbs_posture.verdict.kd_off", QStringLiteral("未启用")),
        kernelText("kernel.vbs_posture.source.kd", QStringLiteral("KdDebuggerEnabled")),
        security.kernelDebuggerEnabled != 0U ? Severity::kWarning : Severity::kGood,
        security.kernelDebuggerEnabled != 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.secure_boot", QStringLiteral("Secure Boot")),
        QStringLiteral("%1 / %2")
            .arg(boolText(security.secureBootEnabled))
            .arg(boolText(security.secureBootCapable)),
        security.secureBootEnabled != 0U
            ? kernelText("kernel.vbs_posture.verdict.sb_on", QStringLiteral("已启用"))
            : kernelText("kernel.vbs_posture.verdict.sb_off", QStringLiteral("未启用（VBS 的信任根被削弱）")),
        kernelText("kernel.vbs_posture.source.secure_boot", QStringLiteral("SystemSecureBootInformation")),
        security.secureBootEnabled != 0U ? Severity::kGood : Severity::kWarning,
        security.secureBootEnabled == 0U
    });
    rows.append({
        kernelText("kernel.vbs_posture.item.build_flags", QStringLiteral("测试/预览版构建")),
        QStringLiteral("test=%1 flight=%2 flighting=%3")
            .arg(boolText(security.testBuild))
            .arg(boolText(security.flightBuild))
            .arg(boolText(security.flightingEnabled)),
        (security.testBuild != 0U || security.flightBuild != 0U)
            ? kernelText("kernel.vbs_posture.verdict.build_relaxed", QStringLiteral("非零售构建，签名策略可能不同"))
            : kernelText("kernel.vbs_posture.verdict.build_retail", QStringLiteral("零售构建")),
        kSourceCi,
        (security.testBuild != 0U || security.flightBuild != 0U) ? Severity::kWarning : Severity::kGood,
        false
    });

    return rows;
}

void KernelVbsPostureTab::populateTable(const QList<PostureRow>& rows)
{
    table_->setRowCount(0);
    for (const PostureRow& row : rows)
    {
        const int kTableRow = table_->rowCount();
        table_->insertRow(kTableRow);
        table_->setItem(kTableRow, kPostureColumnItem, readOnlyItem(row.item));
        table_->setItem(kTableRow, kPostureColumnObserved, readOnlyItem(row.observed));

        auto* verdictItem = readOnlyItem(row.verdict);
        switch (row.severity)
        {
        case Severity::kGood:
            verdictItem->setForeground(ksword_theme::successColor());
            break;
        case Severity::kWarning:
            verdictItem->setForeground(ksword_theme::warningColor());
            break;
        case Severity::kBad:
            verdictItem->setForeground(ksword_theme::errorColor());
            break;
        case Severity::kNeutral:
        default:
            break;
        }
        table_->setItem(kTableRow, kPostureColumnVerdict, verdictItem);
        table_->setItem(kTableRow, kPostureColumnSource, readOnlyItem(row.source));
    }
    table_->resizeColumnsToContents();
}

void KernelVbsPostureTab::applyVerdictBanner(
    const Snapshot& snapshot,
    const QList<PostureRow>& rows)
{
    const auto& security = snapshot.security.response;
    const bool kPolicyEnabled = security.hvciKmciEnabled != 0U;
    const bool kAuditMode = security.hvciAuditMode != 0U;

    // Running evidence must come from observations independent of policy bits: hypervisor present + VTL1 module loaded.
    const bool kHypervisorPresent = snapshot.hyperV.io.ok
        && modulePresent(snapshot.hyperV.response.hypervisorPresent);
    const bool kVtl1Present = modulePresent(security.secureKernelModuleLoaded)
        || modulePresent(security.skciModuleLoaded);
    const bool kModuleEvidenceUsable = security.moduleQueryStatus >= 0;
    const bool kRunning = kHypervisorPresent && kVtl1Present;

    QString verdict;
    QString color;
    if (!kModuleEvidenceUsable)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.no_evidence",
            QStringLiteral("证据不足：模块快照查询失败（%1），无法判定 HVCI 是否真正运行"))
            .arg(ntStatusText(security.moduleQueryStatus));
        color = ksword_theme::warningHex();
    }
    else if (kPolicyEnabled && kRunning && kAuditMode)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.running_audit",
            QStringLiteral("HVCI 运行中，但处于审计模式：违规只被记录，不会被阻断"));
        color = ksword_theme::warningHex();
    }
    else if (kPolicyEnabled && kRunning)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.running",
            QStringLiteral("HVCI 正在强制执行：策略位与运行时证据一致"));
        color = ksword_theme::successHex();
    }
    else if (kPolicyEnabled && !kRunning)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.policy_only",
            QStringLiteral("策略声称已启用，但缺少运行证据（hypervisor 或 securekernel/skci 未观测到）——按未启用处理"));
        color = ksword_theme::errorHex();
    }
    else if (!kPolicyEnabled && kRunning)
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.vbs_only",
            QStringLiteral("VBS 在运行，但 KMCI 策略位未启用：内核代码完整性未受 VTL1 强制"));
        color = ksword_theme::errorHex();
    }
    else
    {
        verdict = kernelText(
            "kernel.vbs_posture.verdict.disabled",
            QStringLiteral("HVCI 未启用：内核代码页不受 VTL1 强制保护"));
        color = ksword_theme::errorHex();
    }

    verdictLabel_->setText(verdict);
    verdictLabel_->setStyleSheet(
        QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
            .arg(color));

    QStringList downgrades;
    for (const PostureRow& row : rows)
    {
        if (row.downgrade)
        {
            downgrades.push_back(row.item);
        }
    }
    downgradeLabel_->setText(
        downgrades.isEmpty()
            ? kernelText(
                "kernel.vbs_posture.downgrade.none",
                QStringLiteral("降级项：未发现"))
            : kernelText(
                "kernel.vbs_posture.downgrade.list",
                QStringLiteral("降级项（%1）：%2"))
                .arg(downgrades.size())
                .arg(downgrades.join(QStringLiteral("、"))));
}

QString KernelVbsPostureTab::buildDetail(const Snapshot& snapshot)
{
    const auto& security = snapshot.security.response;
    QStringList lines;

    lines << QStringLiteral("=== SystemCodeIntegrityInformation ===");
    lines << QStringLiteral("codeIntegrityOptions = %1").arg(hex32(security.codeIntegrityOptions));
    lines << QStringLiteral("  %1").arg(codeIntegrityOptionText(security.codeIntegrityOptions));
    lines << QStringLiteral("fieldFlags = %1  sourceMask = %2")
        .arg(hex32(security.fieldFlags))
        .arg(hex32(security.sourceMask));
    lines << QStringLiteral("queryStatus = %1  codeIntegrityStatus = %2")
        .arg(ntStatusText(security.queryStatus))
        .arg(ntStatusText(security.codeIntegrityStatus));
    lines << QStringLiteral("secureBootStatus = %1  moduleQueryStatus = %2  debuggerStatus = %3")
        .arg(ntStatusText(security.secureBootStatus))
        .arg(ntStatusText(security.moduleQueryStatus))
        .arg(ntStatusText(security.debuggerStatus));
    lines << QStringLiteral("kernelDebuggerEnabled = %1  kernelDebuggerNotPresent = %2")
        .arg(security.kernelDebuggerEnabled)
        .arg(security.kernelDebuggerNotPresent);
    lines << QString();

    lines << QStringLiteral("=== Hyper-V summary ===");
    if (!snapshot.hyperV.io.ok)
    {
        lines << (snapshot.hyperV.unsupported
            ? QStringLiteral("unsupported by current driver")
            : QStringLiteral("query failed: %1")
                .arg(QString::fromStdString(snapshot.hyperV.io.message)));
    }
    else
    {
        const auto& hyperV = snapshot.hyperV.response;
        lines << QStringLiteral("hypervisorPresent = %1  vendor = %2")
            .arg(moduleStateText(hyperV.hypervisorPresent))
            .arg(fixedWide(hyperV.hypervisorVendor, sizeof(hyperV.hypervisorVendor) / sizeof(wchar_t)));
        lines << QStringLiteral("winhv.sys = %1  winhvr.sys = %2  hvloader.sys = %3")
            .arg(moduleStateText(hyperV.winHvStatus))
            .arg(moduleStateText(hyperV.winHvRuntimeStatus))
            .arg(moduleStateText(hyperV.hvLoaderStatus));
        lines << QStringLiteral("vmbus = %1  vmswitch = %2  vpci = %3  hvsocket = %4")
            .arg(moduleStateText(hyperV.vmbusStatus))
            .arg(moduleStateText(hyperV.vSwitchStatus))
            .arg(moduleStateText(hyperV.vPciStatus))
            .arg(moduleStateText(hyperV.hvSocketStatus));
        lines << QStringLiteral("rootPartitionStatus = %1  moduleQueryStatus = %2")
            .arg(moduleStateText(hyperV.rootPartitionStatus))
            .arg(ntStatusText(hyperV.moduleQueryStatus));
    }

    return lines.join(QLatin1Char('\n'));
}

QString KernelVbsPostureTab::codeIntegrityOptionText(const std::uint32_t options)
{
    if (options == 0U)
    {
        return QStringLiteral("(none)");
    }
    QStringList parts;
    const struct
    {
        std::uint32_t bit;
        const char* name;
    } kTable[] = {
        { KSWORD_ARK_CODEINTEGRITY_OPTION_ENABLED, "ENABLED" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_TESTSIGN, "TESTSIGN" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_UMCI_ENABLED, "UMCI_ENABLED" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED, "UMCI_AUDITMODE" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_TEST_BUILD, "TEST_BUILD" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED, "DEBUGMODE" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_FLIGHT_BUILD, "FLIGHT_BUILD" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_FLIGHTING_ENABLED, "FLIGHTING" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED, "HVCI_KMCI_ENABLED" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE, "HVCI_KMCI_AUDITMODE" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE, "HVCI_KMCI_STRICTMODE" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED, "HVCI_IUM_ENABLED" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_WHQL_ENFORCEMENT, "WHQL_ENFORCEMENT" },
        { KSWORD_ARK_CODEINTEGRITY_OPTION_WHQL_AUDITMODE, "WHQL_AUDITMODE" }
    };
    std::uint32_t known = 0U;
    for (const auto& entry : kTable)
    {
        if ((options & entry.bit) != 0U)
        {
            parts.push_back(QString::fromLatin1(entry.name));
            known |= entry.bit;
        }
    }
    const std::uint32_t kLeftover = options & ~known;
    if (kLeftover != 0U)
    {
        parts.push_back(hex32(kLeftover));
    }
    return parts.join(QStringLiteral(" | "));
}

QString KernelVbsPostureTab::moduleStateText(const std::uint32_t state)
{
    switch (state)
    {
    case KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT:
        return kernelText("kernel.vbs_posture.state.present", QStringLiteral("已加载"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_ABSENT:
        return kernelText("kernel.vbs_posture.state.absent", QStringLiteral("未加载"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_ENABLED:
        return kernelText("kernel.vbs_posture.state.enabled", QStringLiteral("已启用"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_DISABLED:
        return kernelText("kernel.vbs_posture.state.disabled", QStringLiteral("已禁用"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_DEGRADED:
        return kernelText("kernel.vbs_posture.state.degraded", QStringLiteral("降级"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_UNAVAILABLE:
        return kernelText("kernel.vbs_posture.state.unavailable", QStringLiteral("不可用"));
    case KSWORD_ARK_SECURITY_AUDIT_STATE_UNKNOWN:
    default:
        return kernelText("kernel.vbs_posture.state.unknown", QStringLiteral("未知"));
    }
}

QString KernelVbsPostureTab::boolText(const std::uint32_t value)
{
    return value != 0U
        ? kernelText("kernel.vbs_posture.bool.yes", QStringLiteral("是"))
        : kernelText("kernel.vbs_posture.bool.no", QStringLiteral("否"));
}

QString KernelVbsPostureTab::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<unsigned long>(status), 8, 16, QLatin1Char('0'));
}

QString KernelVbsPostureTab::fixedWide(const wchar_t* text, const std::size_t capacity)
{
    if (text == nullptr || capacity == 0U)
    {
        return QString();
    }
    std::size_t length = 0U;
    while (length < capacity && text[length] != L'\0')
    {
        ++length;
    }
    return QString::fromWCharArray(text, static_cast<int>(length));
}
