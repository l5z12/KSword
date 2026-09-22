// KvmHookWizard.Verify.cpp: Step 3 (pre-check) and Step 5 (post-installation verification).
//
// These two steps are opposite ends of the same process: before installation, list every reason the driver would reject;
// after installation, break down the question "did it actually take effect?" into several independently falsifiable readings.
// They share a four-column table (criteria / current reading / conclusion / fix), so column semantics remain consistent:
// Column 2 must only contain what was read (with numbers and status bits); Column 3 is the conclusion.
//
// Why is each criterion three-state:
//   The fact that 'the target function was not executed within the observation window' is neither pass nor fail; 'flipCount remains constantly
//   0 under the EPTP switch backend' is also not a failure. With only two states, these readings would be forcibly painted red or green, and
//   both paint jobs would be lies. Therefore, NoReading takes a neutral color and must explicitly explain why there are no readings.
//
// This file does not write m_plan. Each segment of the plan has a
// unique writer (see KvmHookPlan.h sections); this file only reads.

#include "KvmHookWizard.h"

#include "KvmControl.h"
#include "KvmEptLeafProbe.h"
#include "KvmViewDialog.h"
#include "KvmWriteAccessGate.h"
#include "ThemeStatusRole.h"
#include "../internationalization/LanguageManager.h"

#include <QAbstractItemView>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <thread>

namespace
{
    // Upper bound of physical addresses accepted by the driver: KSW_HVM_MAX_MAPPED_PHYSICAL
    // = 512 GiB * 16 PML4 entries = 8 TiB (hvm_internal.h:54-56), validated against page
    // alignment during installation (hvm_ept_view.c:288-295).
    // The client echoes it to move the rejection to the pre-check phase, rather than waiting for the driver to return INVALID_REQUEST.
    constexpr quint64 kMaxMappedPhysical = 0x80000000000ULL;

    // Polling interval for resident observation. 1 second is fast enough to keep up with manual
    // triggers of the target function, yet avoids saturating the driver-side state lock.
    constexpr int kResidentPollIntervalMs = 1000;

    // hex64: Addresses are always echoed in hexadecimal format with a 0x prefix. This is a numeric format, not a translation, and should not be added to the glossary.
    QString hex64(const quint64 value)
    {
        return QStringLiteral("0x%1").arg(value, 0, 16);
    }

    // flagText: echoes the status bit as true/false according to its name in the protocol.
    // Deliberately not translating to "Yes/No": the column readout must match the driver-side field names verbatim.
    QString flagText(const bool value)
    {
        return value ? QStringLiteral("true") : QStringLiteral("false");
    }

    // makeRow: Constructs a row with four columns. Parameter order matches column order to prevent column mismatches at call sites.
    ks::ui::KvmCheckRow makeRow(
        const int criterionId,
        const QString& criterion,
        const QString& reading,
        const ks::ui::KvmCheckVerdict verdict,
        const QString& conclusion,
        const ks::ui::KvmCheckRemedy remedy,
        const QString& remedyLabel,
        const bool blocking)
    {
        ks::ui::KvmCheckRow row;
        row.criterionId = criterionId;
        row.criterion = criterion;
        row.reading = reading;
        row.verdict = verdict;
        row.conclusion = conclusion;
        row.remedy = remedy;
        row.remedyLabel = remedyLabel;
        row.blocking = blocking;
        return row;
    }

    // findInstalledView: Locates the view entry matching the given viewId within a single LIST result.
    // Return nullptr if not found — call sites must distinguish between
    // 'not in table' (Fail) and 'table read failure' (NoReading).
    const ksword::kvm::KvmViewEntry* findInstalledView(
        const ksword::kvm::KvmViewResult& views,
        const unsigned long viewId)
    {
        if (viewId == 0UL)
        {
            return nullptr;
        }
        for (const ksword::kvm::KvmViewEntry& entry : views.views)
        {
            if (entry.viewId == viewId)
            {
                return &entry;
            }
        }
        return nullptr;
    }

    // firstDifferenceOffset: Returns the index of the first byte difference between the two pages; returns -1 if they are identical.
    // Different lengths count as a difference; return the length of the shorter one.
    qsizetype firstDifferenceOffset(
        const QByteArray& left,
        const QByteArray& right)
    {
        const qsizetype kShared = qMin(left.size(), right.size());
        for (qsizetype index = 0; index < kShared; ++index)
        {
            if (left.at(index) != right.at(index))
            {
                return index;
            }
        }
        return left.size() == right.size() ? -1 : kShared;
    }
}

namespace ks::ui
{
    QString describeCheckVerdict(const KvmCheckVerdict verdict)
    {
        switch (verdict)
        {
        case KvmCheckVerdict::kPass:
            return ks::i18n::sourceText(QStringLiteral("通过"));
        case KvmCheckVerdict::kFail:
            return ks::i18n::sourceText(QStringLiteral("未通过"));
        case KvmCheckVerdict::kNoReading:
            break;
        }
        // 「No Reading」must be lexically distinct from「Failed」: it is
        // an independent conclusion, not a euphemism for failure.
        return ks::i18n::sourceText(QStringLiteral("无读数"));
    }

    StatusRole checkVerdictStatusRole(const KvmCheckVerdict verdict)
    {
        switch (verdict)
        {
        case KvmCheckVerdict::kPass:
            return StatusRole::kSuccess;
        case KvmCheckVerdict::kFail:
            return StatusRole::kError;
        case KvmCheckVerdict::kNoReading:
            break;
        }
        // Neutral colors are a hard convention: coloring red makes a 'no reading' look
        // like a failure, coloring green makes it look like a pass, but it is neither.
        return StatusRole::kIdle;
    }

    // =====================================================================
    // Step 3: Pre-check
    // =====================================================================

    QWidget* KvmHookWizard::buildPreflightPage()
    {
        QWidget* const kPage = new QWidget(this);
        QVBoxLayout* const kLayout = new QVBoxLayout(kPage);

        QLabel* const kHintLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("这一页把驱动安装视图时逐条检查的前置条件读回来。第 2 列是实测读数，第 3 列才是结论；带修复按钮的那几条能就地处理，没有按钮的那几条只能解释，本向导不提供任何绕过驱动前置检查的路径。")),
            kPage);
        kHintLabel->setWordWrap(true);
        kLayout->addWidget(kHintLabel);

        preflightTable_ = new QTableWidget(0, 4, kPage);
        preflightTable_->setHorizontalHeaderLabels(QStringList()
            << ks::i18n::sourceText(QStringLiteral("判据"))
            << ks::i18n::sourceText(QStringLiteral("当前读数"))
            << ks::i18n::sourceText(QStringLiteral("结论"))
            << ks::i18n::sourceText(QStringLiteral("修复")));
        preflightTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        preflightTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        preflightTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        preflightTable_->verticalHeader()->setVisible(false);
        preflightTable_->horizontalHeader()->setSectionResizeMode(
            1,
            QHeaderView::Stretch);
        kLayout->addWidget(preflightTable_, 1);

        QHBoxLayout* const kButtonLayout = new QHBoxLayout();
        preflightRefreshButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("重新预检")),
            kPage);
        kButtonLayout->addWidget(preflightRefreshButton_);
        kButtonLayout->addStretch(1);
        kLayout->addLayout(kButtonLayout);

        preflightStatusLabel_ = new QLabel(QString(), kPage);
        preflightStatusLabel_->setWordWrap(true);
        kLayout->addWidget(preflightStatusLabel_);

        connect(preflightRefreshButton_, &QPushButton::clicked, this, [this]() {
            startPreflightRefresh();
        });
        // The debounce timer is owned by the skeleton. It may not yet be constructed (construction order is determined
        // by [W]), so we only wire it up if it exists; schedulePreflightRefresh has a separate fallback branch.
        if (preflightDebounce_ != nullptr)
        {
            preflightDebounce_->setSingleShot(true);
            connect(preflightDebounce_, &QTimer::timeout, this, [this]() {
                startPreflightRefresh();
            });
        }
        return kPage;
    }

    void KvmHookWizard::schedulePreflightRefresh()
    {
        if (preflightDebounce_ == nullptr)
        {
            // If no timer is available, refresh immediately. An extra
            // IOCTL is preferable to a button that does not respond.
            startPreflightRefresh();
            return;
        }
        preflightDebounce_->setSingleShot(true);
        preflightDebounce_->start(kInputDebounceMilliseconds);
    }

    void KvmHookWizard::startPreflightRefresh()
    {
        if (preflightInFlight_)
        {
            return;
        }
        preflightInFlight_ = true;
        // Sequence number must be captured at initiation: return order is not guaranteed to match send order.
        const quint64 kSequence = ++preflightSequence_;
        setBusy(true);
        if (preflightStatusLabel_ != nullptr)
        {
            preflightStatusLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("正在读取驱动状态与已装视图……")));
            applyStatusRole(preflightStatusLabel_, StatusRole::kInfo);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, kSequence]() {
            // QUERY + LIST are both blocking IOCTL calls and must complete on this background thread.
            const PreflightSnapshot kSnapshot = collectPreflightSnapshot();
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, kSequence, kSnapshot]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyPreflightResult(kSequence, kSnapshot);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyPreflightResult(
        const quint64 sequence,
        const PreflightSnapshot& snapshot)
    {
        // Clear the single-flight flag regardless of sequence expiration; otherwise, a discarded reading will permanently block the entry.
        preflightInFlight_ = false;
        setBusy(false);
        if (sequence != preflightSequence_)
        {
            // Stale readings invalidated by a subsequent refresh: committing them would cause the table to mismatch the current plan.
            return;
        }

        preflightRows_ = buildPreflightRows(snapshot, plan_);
        fillCheckTable(preflightTable_, preflightRows_);

        int failCount = 0;
        int noReadingCount = 0;
        for (const KvmCheckRow& row : preflightRows_)
        {
            if (row.verdict == KvmCheckVerdict::kFail)
            {
                ++failCount;
            }
            else if (row.verdict == KvmCheckVerdict::kNoReading)
            {
                ++noReadingCount;
            }
        }
        if (preflightStatusLabel_ != nullptr)
        {
            const bool kBlocked = hasBlockingPreflightFailure();
            preflightStatusLabel_->setText(
                ks::i18n::sourceText(QStringLiteral("共 %1 条判据：未通过 %2 条，无读数 %3 条。%4"))
                    .arg(preflightRows_.size())
                    .arg(failCount)
                    .arg(noReadingCount)
                    .arg(kBlocked
                        ? ks::i18n::sourceText(QStringLiteral("仍有阻塞项没有通过，现在不能进入安装步骤。"))
                        : ks::i18n::sourceText(QStringLiteral("阻塞项都已通过，可以进入安装步骤。"))));
            applyStatusRole(
                preflightStatusLabel_,
                kBlocked ? StatusRole::kWarning : StatusRole::kSuccess);
        }
        // When the blocked state changes, the Next button must update accordingly.
        updateNavigationState();
    }

    KvmHookWizard::PreflightSnapshot KvmHookWizard::collectPreflightSnapshot()
    {
        PreflightSnapshot snapshot;
        // Both readings must be taken at the same instant; taking them separately can cause a contradiction
        // where the state says 'not resident' while the view table shows an old value from the resident period.
        snapshot.state = ksword::kvm::queryState();
        // queryState always returns a struct; when the driver is not running, availability carries this
        // state. Thus, stateValid records that 'this call returned', not that 'the driver is available'.
        snapshot.stateValid = true;

        const ksword::kvm::KvmViewResult kViews = ksword::kvm::listViews();
        snapshot.viewsOk = kViews.ok;
        snapshot.viewCount = kViews.ok ? kViews.viewCount : 0UL;
        snapshot.viewsMessage = kViews.message;
        return snapshot;
    }

    QVector<KvmCheckRow> KvmHookWizard::buildPreflightRows(
        const PreflightSnapshot& snapshot,
        const KvmHookPlan& plan)
    {
        QVector<KvmCheckRow> rows;
        rows.reserve(static_cast<int>(KvmHookPreflightCriterion::kCount));

        const ksword::kvm::KvmState& state = snapshot.state;

        // ---- 0. R-1 Write Access Gate ----
        const bool kWriteAllowed = ksword::kvm::isWriteAccessEnabled();
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kWriteAccessGate),
            ks::i18n::sourceText(QStringLiteral("R-1 写权限门已开启")),
            ks::i18n::sourceText(QStringLiteral("写权限门（客户端侧）= %1"))
                .arg(flagText(kWriteAllowed)),
            kWriteAllowed ? KvmCheckVerdict::kPass : KvmCheckVerdict::kFail,
            kWriteAllowed
                ? ks::i18n::sourceText(QStringLiteral("客户端侧这道门是开的。驱动侧另外还要确认令牌与 FILE_WRITE_ACCESS，那两道不在这里判。"))
                : ks::i18n::sourceText(QStringLiteral("关闭时安装视图的请求在客户端就被拒，根本不会发出 IOCTL。")),
            kWriteAllowed ? KvmCheckRemedy::kNone : KvmCheckRemedy::kEnableWriteAccess,
            ks::i18n::sourceText(QStringLiteral("开启写权限")),
            true));

        // ---- 1. Resources Ready ----: Whether the driver is running is indicated
        // by 'availability' and placed on the same row as 'resourcesReady':
        // Splitting into two rows causes the user to see two duplicate red messages when the driver is not running.
        const bool kDriverRunning =
            state.availability != ksword::kvm::KvmAvailability::kDriverNotRunning;
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kResourcesPrepared),
            ks::i18n::sourceText(QStringLiteral("驱动在跑且资源已准备（PREPARE 已执行、未 TEARDOWN）")),
            ks::i18n::sourceText(QStringLiteral("availability=%1；resourcesReady=%2；generation=%3；faulted=%4"))
                .arg(ksword::kvm::describeAvailability(state.availability))
                .arg(flagText(state.resourcesReady))
                .arg(state.generation)
                .arg(flagText(state.faulted)),
            state.resourcesReady ? KvmCheckVerdict::kPass : KvmCheckVerdict::kFail,
            state.resourcesReady
                ? ks::i18n::sourceText(QStringLiteral("资源在位。现在正是安装分离视图的窗口期——启动常驻之后视图表就不可变了。"))
                : (kDriverRunning
                    ? ks::i18n::sourceText(QStringLiteral("资源未准备，驱动会直接拒绝安装。准备资源要在标题栏 KVM 菜单里做，本向导不自己发 PREPARE。"))
                    : ks::i18n::sourceText(QStringLiteral("KswordARK 驱动未运行，先点 R0 启动驱动服务，其余判据在此之前都读不到真值。"))),
            state.resourcesReady ? KvmCheckRemedy::kNone : KvmCheckRemedy::kPrepareResources,
            ks::i18n::sourceText(QStringLiteral("去 KVM 菜单准备资源")),
            true));

        // ---- 2. Not resident ----
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kNotResident),
            ks::i18n::sourceText(QStringLiteral("未常驻：常驻期间驱动拒绝改动视图表")),
            ks::i18n::sourceText(QStringLiteral("residentActive=%1；residentProcessorCount=%2 / 逻辑处理器 %3；nestedResident=%4"))
                .arg(flagText(state.residentActive))
                .arg(state.residentProcessorCount)
                .arg(state.processorCount)
                .arg(flagText(state.nestedResident)),
            state.residentActive ? KvmCheckVerdict::kFail : KvmCheckVerdict::kPass,
            state.residentActive
                ? ks::i18n::sourceText(QStringLiteral("常驻中的 VM exit 不取 PASSIVE_LEVEL 锁就读视图表，所以驱动在还有处理器处于 non-root 时把整张表连同每张叶和每页影子都锁成不可变（hvm_ept_view.c:948-966）。停止常驻要在标题栏 KVM 菜单或内核 Dock 的 HVM 页里做。"))
                : ks::i18n::sourceText(QStringLiteral("没有处理器处于 non-root，视图表此刻可改。")),
            state.residentActive ? KvmCheckRemedy::kStopResident : KvmCheckRemedy::kNone,
            ks::i18n::sourceText(QStringLiteral("去 KVM 菜单停止常驻")),
            true));

        // ---- 3. EPT hierarchy established ----
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kEptReady),
            ks::i18n::sourceText(QStringLiteral("EPT 层次已建好（安装视图的第一道硬门）")),
            ks::i18n::sourceText(QStringLiteral("eptReady=%1；eptPointer=%2；eptRulesReady=%3；eptRuleCount=%4"))
                .arg(flagText(state.eptReady))
                .arg(hex64(state.eptPointer))
                .arg(flagText(state.eptRulesReady))
                .arg(state.eptRuleCount),
            state.eptReady ? KvmCheckVerdict::kPass : KvmCheckVerdict::kFail,
            state.eptReady
                ? ks::i18n::sourceText(QStringLiteral("层次在位，驱动这一道检查会过（hvm_ept_view.c:614-622）。"))
                : ks::i18n::sourceText(QStringLiteral("缺 STATE_EPT_READY 时驱动回 NOT_PREPARED / STATUS_DEVICE_NOT_READY（hvm_ept_view.c:614-622）。层次由 PREPARE 建，去 KVM 菜单准备资源。")),
            state.eptReady ? KvmCheckRemedy::kNone : KvmCheckRemedy::kPrepareResources,
            ks::i18n::sourceText(QStringLiteral("去 KVM 菜单准备资源")),
            true));

        // ---- 4. Topology: Single-core or private EPT armed ----
        //
        // This case has no solution on multi-core machines, so the associated button only explains the issue without offering a fix.
        const bool kLocalEptRequested = ksword::kvm::isLocalEptEnabled();
        const bool kTopologyOk = state.processorCount == 1UL || state.localEptArmed;
        QString topologyConclusion;
        if (kTopologyOk)
        {
            topologyConclusion = state.localEptArmed
                ? ks::i18n::sourceText(QStringLiteral("私有 EPT 已武装：翻转只落在取到 exit 的那个处理器上，多核也能安装。"))
                : ks::i18n::sourceText(QStringLiteral("单处理器拓扑：翻转窗口不会被别的处理器看到，驱动这一条会过（hvm_ept_view.c:687-695）。"));
            if (kLocalEptRequested && !state.localEptArmed)
            {
                // Single-core systems are also affected by this chain: startResident passes
                // isLocalEptEnabled() directly to START_RESIDENT (KvmControl.cpp:523), and since LocalEptArmed
                // is always false, the driver rejects the startup with 'Processor not supported'.
                topologyConclusion += QStringLiteral(" ");
                topologyConclusion += ks::i18n::sourceText(QStringLiteral("注意：私有 EPT 持久化开关是打开的但没有武装，而启动常驻会把这个请求原样发给驱动（KvmControl.cpp:523），于是常驻会以「处理器不支持」被拒——在单核机上也一样。第 5 步 B 段要观察翻转的话，先在 KVM 菜单里把这个开关关掉。"));
            }
        }
        else
        {
            topologyConclusion = ks::i18n::sourceText(QStringLiteral("多核且私有 EPT 未武装：驱动回 MULTIPROCESSOR_UNSAFE / STATUS_NOT_SUPPORTED（hvm_ept_view.c:687-695）。而武装它需要 PREPARE 带 ENABLE_LOCAL_EPT——那个标志确实会被 PREPARE 读取并置位（hvm_runtime.c:1573-1582），却不在 PREPARE 的 allowedFlags 白名单里（hvm_runtime.c:2682-2685），驱动自己的注释把这件事称为 standing defect（hvm_runtime.c:2674-2681）。所以这一条在多核机上通过协议不可达，本向导不提供任何假装是出路的按钮。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kTopology),
            ks::i18n::sourceText(QStringLiteral("拓扑：单处理器，或每处理器私有 EPT 已武装")),
            ks::i18n::sourceText(QStringLiteral("逻辑处理器 %1；localEptArmed=%2；私有 EPT 持久化开关=%3；eptpSwitchArmed=%4"))
                .arg(state.processorCount)
                .arg(flagText(state.localEptArmed))
                .arg(flagText(kLocalEptRequested))
                .arg(flagText(state.eptpSwitchArmed)),
            kTopologyOk ? KvmCheckVerdict::kPass : KvmCheckVerdict::kFail,
            topologyConclusion,
            kTopologyOk
                ? KvmCheckRemedy::kNone
                : KvmCheckRemedy::kExplainLocalEptUnreachable,
            ks::i18n::sourceText(QStringLiteral("为什么多核上没有出路")),
            true));

        // ---- 5. Single-context INVEPT ----
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kInveptSingle),
            ks::i18n::sourceText(QStringLiteral("处理器支持单上下文 INVEPT（两套后端都要）")),
            ks::i18n::sourceText(QStringLiteral("inveptSingleReady=%1"))
                .arg(flagText(state.inveptSingleReady)),
            state.inveptSingleReady ? KvmCheckVerdict::kPass : KvmCheckVerdict::kFail,
            state.inveptSingleReady
                ? ks::i18n::sourceText(QStringLiteral("无论写回叶项还是切 EPTP，都得把按旧值建出来的翻译丢掉，这条能力在位。"))
                : ks::i18n::sourceText(QStringLiteral("这是处理器能力，客户端修不了：这台机器装不了分离视图。")),
            KvmCheckRemedy::kNone,
            QString(),
            true));

        // ---- 6. Backend Capabilities ----
        //
        // Must check eptpSwitchArmed first to decide which bit to inspect: checking monitorTrapFlagReady alone
        // would misclassify nested Hyper-V guests as unsolvable, which is precisely why switching backends exists.
        KvmCheckVerdict backendVerdict = KvmCheckVerdict::kPass;
        QString backendConclusion;
        KvmCheckRemedy backendRemedy = KvmCheckRemedy::kNone;
        if (state.eptpSwitchArmed)
        {
            backendConclusion = ks::i18n::sourceText(QStringLiteral("已武装 EPTP 切换后端：它不需要 Monitor Trap Flag，只需要 execute-only EPT 叶。而 execute-only 这一位由驱动在安装时判定，客户端没有对应的状态位可读——所以本行只证明后端选择这一关过了，不代表安装一定成功。"));
        }
        else if (state.monitorTrapFlagReady)
        {
            backendConclusion = ks::i18n::sourceText(QStringLiteral("默认后端（写叶 + Monitor Trap Flag 单步一条指令 + 写回），MTF 在位。"));
        }
        else
        {
            backendVerdict = KvmCheckVerdict::kFail;
            if (state.eptpSwitchingAvailable)
            {
                backendConclusion = ks::i18n::sourceText(QStringLiteral("默认后端要 Monitor Trap Flag，这台机器没有（嵌套 Hyper-V 客户机就拿不到它）。处理器提供 VM function 0，所以改用 EPTP 切换后端是可行的：这一位只随 PREPARE 发出，要先在 KVM 菜单里打开开关，再释放资源并重新准备才会生效。"));
                backendRemedy = KvmCheckRemedy::kSwitchToEptpBackend;
            }
            else
            {
                backendConclusion = ks::i18n::sourceText(QStringLiteral("默认后端要 Monitor Trap Flag，这台机器没有；而处理器也不提供 VM function 0，所以换成 EPTP 切换后端同样走不通。这是硬件能力，客户端修不了。"));
            }
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kBackend),
            ks::i18n::sourceText(QStringLiteral("后端能力：默认后端看 Monitor Trap Flag，EPTP 切换后端看 execute-only")),
            ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=%1；monitorTrapFlagReady=%2；eptpSwitchingAvailable=%3"))
                .arg(flagText(state.eptpSwitchArmed))
                .arg(flagText(state.monitorTrapFlagReady))
                .arg(flagText(state.eptpSwitchingAvailable)),
            backendVerdict,
            backendConclusion,
            backendRemedy,
            ks::i18n::sourceText(QStringLiteral("改用 EPTP 切换后端")),
            true));

        // ---- 7. View table capacity ----
        //
        // [Partially pre-checkable only] This step can only count entries: the snapshot for this step does not include
        // an entry list, so it is impossible to determine at this layer whether the target page is already occupied by
        // an installed view. Such conflicts, similar to 'the target page is covered by an EPT rule interval' (KvmControl
        // also lacks an interface to list rules), will only be exposed as LEAF_CONFLICT during installation.
        KvmCheckVerdict capacityVerdict = KvmCheckVerdict::kPass;
        QString capacityConclusion;
        KvmCheckRemedy capacityRemedy = KvmCheckRemedy::kNone;
        if (!snapshot.viewsOk)
        {
            capacityVerdict = KvmCheckVerdict::kNoReading;
            capacityConclusion = ks::i18n::sourceText(QStringLiteral("读不到视图表，因此不知道还有没有位置。「不知道」不是「可以装」，所以这一条同样挡住下一步。"));
        }
        else if (snapshot.viewCount >= KSWORD_ARK_HVM_MAX_VIEWS)
        {
            capacityVerdict = KvmCheckVerdict::kFail;
            capacityConclusion = ks::i18n::sourceText(QStringLiteral("视图表已满，必须先移除一条才能再装。"));
            capacityRemedy = KvmCheckRemedy::kOpenViewPanel;
        }
        else
        {
            capacityConclusion = ks::i18n::sourceText(QStringLiteral("表里还有位置。注意这一条只数了条数：目标页是否已被某条已装视图占用、或被某条 EPT 规则区间覆盖，本预检都看不到——那两种冲突会在安装时以 LEAF_CONFLICT 暴露。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kViewTableCapacity),
            ks::i18n::sourceText(QStringLiteral("视图表还有位置（上限 32 条）")),
            ks::i18n::sourceText(QStringLiteral("已装视图 %1 条 / 上限 %2；LIST 结果=%3%4"))
                .arg(snapshot.viewCount)
                .arg(static_cast<unsigned long>(KSWORD_ARK_HVM_MAX_VIEWS))
                .arg(flagText(snapshot.viewsOk))
                .arg(snapshot.viewsMessage.isEmpty()
                    ? QString()
                    : QStringLiteral("；%1").arg(snapshot.viewsMessage)),
            capacityVerdict,
            capacityConclusion,
            capacityRemedy,
            ks::i18n::sourceText(QStringLiteral("打开视图面板")),
            true));

        // ---- 8. Target page geometry ----
        KvmCheckVerdict geometryVerdict = KvmCheckVerdict::kPass;
        QString geometryConclusion;
        if (!plan.resolved)
        {
            geometryVerdict = KvmCheckVerdict::kNoReading;
            geometryConclusion = ks::i18n::sourceText(QStringLiteral("目标还没有解析成功，pageBasePhysical 不可信。回第 1 步把目标定下来。"));
        }
        else if (!plan.pageIsAligned())
        {
            geometryVerdict = KvmCheckVerdict::kFail;
            geometryConclusion = ks::i18n::sourceText(QStringLiteral("目标物理页没有页对齐，驱动会回 INVALID_REQUEST（hvm_ept_view.c:288-295）。"));
        }
        else if (plan.pageBasePhysical >= kMaxMappedPhysical)
        {
            geometryVerdict = KvmCheckVerdict::kFail;
            geometryConclusion = ks::i18n::sourceText(QStringLiteral("目标物理页超出 EPT 后端接受的 8 TiB 窗口，驱动会回 INVALID_REQUEST（hvm_ept_view.c:288-295）。"));
        }
        else
        {
            geometryConclusion = ks::i18n::sourceText(QStringLiteral("页对齐且在 8 TiB 窗口内。请注意驱动**只**查这两条：它不查目标页是不是 RAM，也不查这一页归谁——地址算错的后果是给一页无关内存挂上 HOOK，而且全程不会有人报错。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kTargetPageGeometry),
            ks::i18n::sourceText(QStringLiteral("目标页几何：页对齐且小于 8 TiB")),
            ks::i18n::sourceText(QStringLiteral("resolved=%1；virtualAddress=%2；fullPhysicalAddress=%3；pageBasePhysical=%4；pageOffset=%5"))
                .arg(flagText(plan.resolved))
                .arg(hex64(plan.virtualAddress))
                .arg(hex64(plan.fullPhysicalAddress))
                .arg(hex64(plan.pageBasePhysical))
                .arg(hex64(plan.pageOffset)),
            geometryVerdict,
            geometryConclusion,
            geometryVerdict == KvmCheckVerdict::kPass
                ? KvmCheckRemedy::kNone
                : KvmCheckRemedy::kReturnToTargetStep,
            ks::i18n::sourceText(QStringLiteral("回第 1 步改目标")),
            true));

        // ---- 9. Patch Geometry ----
        const ksword::evidence::CrossPageClassification kClassification =
            plan.classifyPatchGeometry();
        const bool kCrossesPage =
            kClassification == ksword::evidence::CrossPageClassification::kCrossesPage;
        KvmCheckVerdict patchVerdict = KvmCheckVerdict::kPass;
        QString patchConclusion;
        if (plan.patchIsEmpty())
        {
            patchVerdict = KvmCheckVerdict::kFail;
            patchConclusion = ks::i18n::sourceText(QStringLiteral("补丁是空的。空补丁拼出来的影子页与原页逐位相同，装上去什么都不改变，却会让人以为补丁生效了。"));
        }
        else if (kCrossesPage)
        {
            patchVerdict = KvmCheckVerdict::kFail;
            patchConclusion = ks::i18n::sourceText(QStringLiteral("补丁越过了页尾。一条视图恰好覆盖一页，协议里没有 PageCount；把跨页补丁拆成两条视图会让两页的翻转彼此独立，中间任何一次退出都可能让 guest 执行到半条指令。所以两种后端下这都是 fail-closed，直接拒绝，不拆。"));
        }
        else
        {
            patchConclusion = ks::i18n::sourceText(QStringLiteral("补丁完整落在这一页内。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kPatchGeometry),
            ks::i18n::sourceText(QStringLiteral("补丁几何：非空且完整落在这一页内")),
            ks::i18n::sourceText(QStringLiteral("页内起点=%1；长度=%2 字节；终点=%3；跨页判定=%4"))
                .arg(hex64(plan.pageOffset))
                .arg(plan.patchLength())
                .arg(hex64(plan.patchEndOffset()))
                .arg(kCrossesPage
                    ? ks::i18n::sourceText(QStringLiteral("跨页"))
                    : ks::i18n::sourceText(QStringLiteral("页内"))),
            patchVerdict,
            patchConclusion,
            patchVerdict == KvmCheckVerdict::kPass
                ? KvmCheckRemedy::kNone
                : KvmCheckRemedy::kReturnToPatchStep,
            ks::i18n::sourceText(QStringLiteral("回第 2 步改补丁")),
            true));

        // ---- 10. Baseline page complete ----
        const bool kBaselineOk = plan.baselineIsComplete();
        rows.append(makeRow(
            static_cast<int>(KvmHookPreflightCriterion::kBaselineComplete),
            ks::i18n::sourceText(QStringLiteral("基线页完整：恰好 4096 字节")),
            ks::i18n::sourceText(QStringLiteral("基线页 %1 字节 / %2"))
                .arg(plan.baselinePage.size())
                .arg(static_cast<int>(ksword::evidence::kPatchPageBytes)),
            kBaselineOk ? KvmCheckVerdict::kPass : KvmCheckVerdict::kFail,
            kBaselineOk
                ? ks::i18n::sourceText(QStringLiteral("整页都在。影子页的底稿与第 4 步的 TOCTOU 比对用的都是它。"))
                : ks::i18n::sourceText(QStringLiteral("基线不是完整一页。分片读少一片，拼出来的影子页里就会有一段零字节——而影子页正是被执行的那一份。")),
            kBaselineOk ? KvmCheckRemedy::kNone : KvmCheckRemedy::kRecaptureBaseline,
            ks::i18n::sourceText(QStringLiteral("重新抓基线")),
            true));

        return rows;
    }

    void KvmHookWizard::runPreflightRemedy(const KvmCheckRemedy remedy)
    {
        switch (remedy)
        {
        case KvmCheckRemedy::kNone:
            return;

        case KvmCheckRemedy::kEnableWriteAccess:
            // Unified entry point: Ensure the confirmation text and suppressionKey exist only in KvmWriteAccessGate.
            (void)ks::ui::requestKvmWriteAccess(this);
            schedulePreflightRefresh();
            return;

        case KvmCheckRemedy::kPrepareResources:
            // Deliberately avoid calling ensurePrepared directly here: the main window serializes all KVM control
            // commands using its own mutex. If the dialog bypasses this, the dock and dialog could simultaneously
            // issue commands against the driver state lock. This function only routes the call to that entry point.
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("准备 KVM 资源")),
                ks::i18n::sourceText(QStringLiteral("请在标题栏 KVM 按钮的右键菜单里执行「准备资源」。本向导不自己发 PREPARE：主窗口用一把操作互斥串行化全部 KVM 控制命令，对话框绕过它会让两处同时对驱动状态锁发命令。准备完回到这一页点「重新预检」。")));
            schedulePreflightRefresh();
            return;

        case KvmCheckRemedy::kStopResident:
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("停止 KVM 常驻")),
                ks::i18n::sourceText(QStringLiteral("请在标题栏 KVM 按钮或内核 Dock 的 HVM 页里停止常驻。理由与准备资源相同：控制命令统一走主窗口的操作互斥。停止之后回到这一页点「重新预检」。")));
            schedulePreflightRefresh();
            return;

        case KvmCheckRemedy::kSwitchToEptpBackend:
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("改用 EPTP 切换后端")),
                ks::i18n::sourceText(QStringLiteral("后端只在 PREPARE 时选定，所以要三步：先在标题栏 KVM 菜单里打开「EPTP 切换后端」，再执行「释放资源」，最后重新执行「准备资源」。只改开关而不重新准备资源不会生效，状态里的 eptpSwitchArmed 会一直是 false。")));
            schedulePreflightRefresh();
            return;

        case KvmCheckRemedy::kOpenViewPanel:
        {
            // The view panel is the ready-made entry point for removing installed views; do not recreate one in the wizard.
            KvmViewDialog* const kDialog = new KvmViewDialog(this);
            kDialog->setAttribute(Qt::WA_DeleteOnClose);
            kDialog->show();
            return;
        }

        case KvmCheckRemedy::kReturnToTargetStep:
            goToStep(Step::kTarget);
            return;

        case KvmCheckRemedy::kReturnToPatchStep:
            goToStep(Step::kPatch);
            return;

        case KvmCheckRemedy::kRecaptureBaseline:
            goToStep(Step::kPatch);
            // Explicitly capture again: the automatic capture in step 2 is conditional, but the user clicking
            // this button wants an 'unconditional retry'. The capture itself is independent and does not stack.
            startBaselineCapture();
            return;

        case KvmCheckRemedy::kExplainLocalEptUnreachable:
            // Explain only, do not fix. Leaving a useless 'Enable Private EPT' button is worse than not having one.
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("多核上为什么装不了分离视图")),
                ks::i18n::sourceText(QStringLiteral("驱动要求 ProcessorCount == 1 或 LocalEptArmed（hvm_ept_view.c:687-695），因为在共享层次上翻转一张叶的窗口对每个处理器都可见。而 LocalEptArmed 通过协议不可达：ENABLE_LOCAL_EPT 确实会被 PREPARE 读取并置位（hvm_runtime.c:1573-1582），但它不在 PREPARE 的 allowedFlags 白名单里（hvm_runtime.c:2682-2685），带上它的请求在进入那段代码之前就被判成非法；驱动自己在 hvm_runtime.c:2674-2681 的注释里把这件事称为 standing defect。所以这台机器上没有出路，本向导不给你一个假装能修好它的按钮。要走完流程可以改用排练目标，并在单处理器拓扑下验证。")));
            return;

        case KvmCheckRemedy::kExplainNotMeasured:
            QMessageBox::information(
                this,
                ks::i18n::sourceText(QStringLiteral("这一条为什么恒为「无读数」")),
                ks::i18n::sourceText(QStringLiteral("路线图原文：只验了 CLOAK（读被重定向）。HOOK 方向（执行被重定向到影子）未实测。而且当时未对已知函数下 hook，用的是探针自己分配的一页匿名内存。所以「执行真的落到影子页上」这件事本项目没有实测过，这一行只能是无读数——把它标成通过就是在说一句没有证据的话。另外提醒一句：CLOAK/HOOK 不是安全边界，失败即放行（InstructionLength = 0 时处理器会重执行并读到真页）。")));
            return;
        }
    }

    bool KvmHookWizard::hasBlockingPreflightFailure() const
    {
        if (preflightRows_.isEmpty())
        {
            // No preflight run yet = no readings = unknown. 'Unknown' does not mean 'installable'.
            return true;
        }
        for (const KvmCheckRow& row : preflightRows_)
        {
            // NoReading also blocks: When the blocking criterion has no read data, we cannot determine
            // if the driver will reject it; this uncertainty is the reason we cannot proceed.
            if (row.blocking && row.verdict != KvmCheckVerdict::kPass)
            {
                return true;
            }
        }
        return false;
    }

    // =====================================================================
    // Step 5: Post-installation verification
    // =====================================================================

    QWidget* KvmHookWizard::buildVerifyPage()
    {
        QWidget* const kPage = new QWidget(this);
        QVBoxLayout* const kLayout = new QVBoxLayout(kPage);

        QLabel* const kHintLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("A 段这四条读数在未常驻时就能拿到。其中只有基座叶回读那一条能在 EPT 层面把「没生效」证伪，其余三条是记账性读数——它们证明驱动接受并记住了这条视图，不证明处理器看到的翻译变了。")),
            kPage);
        kHintLabel->setWordWrap(true);
        kLayout->addWidget(kHintLabel);

        verifyStaticTable_ = new QTableWidget(0, 4, kPage);
        verifyStaticTable_->setHorizontalHeaderLabels(QStringList()
            << ks::i18n::sourceText(QStringLiteral("判据"))
            << ks::i18n::sourceText(QStringLiteral("当前读数"))
            << ks::i18n::sourceText(QStringLiteral("结论"))
            << ks::i18n::sourceText(QStringLiteral("修复")));
        verifyStaticTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        verifyStaticTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        verifyStaticTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        verifyStaticTable_->verticalHeader()->setVisible(false);
        verifyStaticTable_->horizontalHeader()->setSectionResizeMode(
            1,
            QHeaderView::Stretch);
        kLayout->addWidget(verifyStaticTable_, 1);

        QHBoxLayout* const kStaticButtonLayout = new QHBoxLayout();
        verifyRefreshButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("重新校验 A 段")),
            kPage);
        kStaticButtonLayout->addWidget(verifyRefreshButton_);
        kStaticButtonLayout->addStretch(1);
        kLayout->addLayout(kStaticButtonLayout);

        // ---- B section: collapsed by default ----
        verifyResidentGroup_ = new QGroupBox(
            ks::i18n::sourceText(QStringLiteral("B 段：启动常驻并观察（可选，勾选展开）")),
            kPage);
        verifyResidentGroup_->setCheckable(true);
        verifyResidentGroup_->setChecked(false);
        QVBoxLayout* const kGroupLayout = new QVBoxLayout(verifyResidentGroup_);

        // Collapse by hiding this container: the checkbox only disables child controls. The B section being expanded by
        // default causes anxiety — two of the three lines will inevitably have no readings in common configurations.
        QWidget* const kResidentBody = new QWidget(verifyResidentGroup_);
        QVBoxLayout* const kBodyLayout = new QVBoxLayout(kResidentBody);
        kBodyLayout->setContentsMargins(0, 0, 0, 0);

        QLabel* const kResidentWarningLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("常驻期间请不要在别的面板里读这一页。内核基线比对、反汇编、内存 Dock 去读它都会落进翻转窗口，并可能触发 fail-closed 退虚拟化，本向导管不住那些面板。")),
            kResidentBody);
        kResidentWarningLabel->setWordWrap(true);
        applyStatusRole(kResidentWarningLabel, StatusRole::kWarning);
        kBodyLayout->addWidget(kResidentWarningLabel);

        QLabel* const kResidentHintLabel = new QLabel(
            ks::i18n::sourceText(QStringLiteral("常驻请在标题栏 KVM 按钮里自己启动，然后由你自己去触发目标函数，本页每秒读一次计数与事件环。本向导刻意不提供「自动触发目标函数」的动作：从用户态触发已知会带着 ring 3 的 RSP/RIP 在 ring 0 返回并蓝屏。")),
            kResidentBody);
        kResidentHintLabel->setWordWrap(true);
        kBodyLayout->addWidget(kResidentHintLabel);

        verifyResidentTable_ = new QTableWidget(0, 4, kResidentBody);
        verifyResidentTable_->setHorizontalHeaderLabels(QStringList()
            << ks::i18n::sourceText(QStringLiteral("判据"))
            << ks::i18n::sourceText(QStringLiteral("当前读数"))
            << ks::i18n::sourceText(QStringLiteral("结论"))
            << ks::i18n::sourceText(QStringLiteral("修复")));
        verifyResidentTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
        verifyResidentTable_->setSelectionMode(QAbstractItemView::SingleSelection);
        verifyResidentTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        verifyResidentTable_->verticalHeader()->setVisible(false);
        verifyResidentTable_->horizontalHeader()->setSectionResizeMode(
            1,
            QHeaderView::Stretch);
        kBodyLayout->addWidget(verifyResidentTable_, 1);

        verifyResidentButton_ = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("开始每秒观察")),
            kResidentBody);
        verifyResidentButton_->setCheckable(true);
        kBodyLayout->addWidget(verifyResidentButton_);

        kGroupLayout->addWidget(kResidentBody);
        kResidentBody->setVisible(false);
        kLayout->addWidget(verifyResidentGroup_);

        verifyStatusLabel_ = new QLabel(QString(), kPage);
        verifyStatusLabel_->setWordWrap(true);
        kLayout->addWidget(verifyStatusLabel_);

        // Poll timer not in header: its start/stop points are all in these three lambdas,
        // and as a child object of this page, it is destroyed along with the dialog.
        QTimer* const kPollTimer = new QTimer(this);
        kPollTimer->setInterval(kResidentPollIntervalMs);
        connect(kPollTimer, &QTimer::timeout, this, [this]() {
            startVerifyResident();
        });

        connect(verifyRefreshButton_, &QPushButton::clicked, this, [this]() {
            startVerifyStatic();
        });
        connect(
            verifyResidentButton_,
            &QPushButton::toggled,
            this,
            [this, kPollTimer](const bool observing) {
                if (observing)
                {
                    verifyResidentButton_->setText(ks::i18n::sourceText(
                        QStringLiteral("停止观察")));
                    kPollTimer->start();
                    // Fetch immediately to avoid making the user wait a full second for an empty table to populate.
                    startVerifyResident();
                    return;
                }
                verifyResidentButton_->setText(ks::i18n::sourceText(
                    QStringLiteral("开始每秒观察")));
                kPollTimer->stop();
            });
        connect(
            verifyResidentGroup_,
            &QGroupBox::toggled,
            this,
            [this, kResidentBody, kPollTimer](const bool expanded) {
                kResidentBody->setVisible(expanded);
                if (!expanded)
                {
                    // Must stop when collapsed: folded groups performing IOCTLs in the background
                    // are the hardest to trace as a class of 'how did the machine move itself'.
                    kPollTimer->stop();
                    if (verifyResidentButton_ != nullptr)
                    {
                        verifyResidentButton_->setChecked(false);
                    }
                }
            });
        return kPage;
    }

    void KvmHookWizard::startVerifyStatic()
    {
        if (verifyStaticInFlight_)
        {
            return;
        }
        if (!plan_.installed)
        {
            if (verifyStatusLabel_ != nullptr)
            {
                verifyStatusLabel_->setText(ks::i18n::sourceText(
                    QStringLiteral("还没有装上视图，A 段没有可读的对象。")));
                applyStatusRole(verifyStatusLabel_, StatusRole::kIdle);
            }
            return;
        }
        verifyStaticInFlight_ = true;
        const quint64 kSequence = ++verifyStaticSequence_;
        const quint64 kPageBase = plan_.pageBasePhysical;
        setBusy(true);
        if (verifyStatusLabel_ != nullptr)
        {
            verifyStatusLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("正在读取状态、视图表、目标页与基座 EPT 叶……")));
            applyStatusRole(verifyStatusLabel_, StatusRole::kInfo);
        }

        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, kSequence, kPageBase]() {
            const VerifyStaticSnapshot kSnapshot =
                collectVerifyStaticSnapshot(kPageBase);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, kSequence, kSnapshot]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyVerifyStatic(kSequence, kSnapshot);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyVerifyStatic(
        const quint64 sequence,
        const VerifyStaticSnapshot& snapshot)
    {
        verifyStaticInFlight_ = false;
        setBusy(false);
        if (sequence != verifyStaticSequence_)
        {
            return;
        }

        verifyStaticRows_ = buildVerifyStaticRows(snapshot, plan_);
        fillCheckTable(verifyStaticTable_, verifyStaticRows_);

        int failCount = 0;
        int noReadingCount = 0;
        for (const KvmCheckRow& row : verifyStaticRows_)
        {
            if (row.verdict == KvmCheckVerdict::kFail)
            {
                ++failCount;
            }
            else if (row.verdict == KvmCheckVerdict::kNoReading)
            {
                ++noReadingCount;
            }
        }
        if (verifyStatusLabel_ != nullptr)
        {
            verifyStatusLabel_->setText(
                ks::i18n::sourceText(QStringLiteral("A 段 %1 条：未通过 %2 条，无读数 %3 条。这四条都不能证明「执行真的被重定向到影子页」——那件事本项目未实测。"))
                    .arg(verifyStaticRows_.size())
                    .arg(failCount)
                    .arg(noReadingCount));
            applyStatusRole(
                verifyStatusLabel_,
                failCount > 0 ? StatusRole::kError : StatusRole::kInfo);
        }
    }

    KvmHookWizard::VerifyStaticSnapshot KvmHookWizard::collectVerifyStaticSnapshot(
        const quint64 pageBasePhysical)
    {
        VerifyStaticSnapshot snapshot;
        snapshot.state = ksword::kvm::queryState();
        snapshot.stateValid = true;
        snapshot.views = ksword::kvm::listViews();
        // The actual page re-read uses the same function as capturing the baseline, so both sides avoid having two separate sharding logics.
        QString failure;
        snapshot.rereadPage = readTargetPage(pageBasePhysical, &failure);
        snapshot.rereadFailure = failure;
        // Leaf re-read is done last: it will fetch the eptPointer via QUERY again, which is later
        // than the previous fetch; the blind spot annotation uses the two bits it brings back.
        snapshot.leaf = readBaseEptLeaf(pageBasePhysical);
        return snapshot;
    }

    QVector<KvmCheckRow> KvmHookWizard::buildVerifyStaticRows(
        const VerifyStaticSnapshot& snapshot,
        const KvmHookPlan& plan)
    {
        QVector<KvmCheckRow> rows;
        rows.reserve(static_cast<int>(KvmHookVerifyCriterion::kCount));

        const ksword::kvm::KvmViewEntry* const kEntry =
            findInstalledView(snapshot.views, plan.installedViewId);

        // ---- 0. View in table ----
        KvmCheckVerdict presentVerdict = KvmCheckVerdict::kPass;
        QString presentConclusion;
        if (!snapshot.views.ok)
        {
            presentVerdict = KvmCheckVerdict::kNoReading;
            presentConclusion = ks::i18n::sourceText(QStringLiteral("视图表读不回来，所以不知道这条视图还在不在。"));
        }
        else if (kEntry == nullptr)
        {
            presentVerdict = KvmCheckVerdict::kFail;
            presentConclusion = ks::i18n::sourceText(QStringLiteral("表里没有这个编号：视图已经不在了（可能被别的面板移除，或资源被释放过）。"));
        }
        else if (kEntry->kind != KSWORD_ARK_HVM_VIEW_KIND_HOOK
            || kEntry->physicalAddress != plan.pageBasePhysical)
        {
            presentVerdict = KvmCheckVerdict::kFail;
            presentConclusion = ks::i18n::sourceText(QStringLiteral("编号对上了，但类型或目标物理页与本次安装的不一致——这个编号现在指的不是我们装的那条视图。"));
        }
        else
        {
            presentConclusion = ks::i18n::sourceText(QStringLiteral("驱动接受了这条视图并把它记在表里。请注意这**只**证明记账：它不证明 EPT 层面生效，那要靠下面的叶回读。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookVerifyCriterion::kViewPresent),
            ks::i18n::sourceText(QStringLiteral("视图在表里，且类型与目标物理页一致")),
            ks::i18n::sourceText(QStringLiteral("期望 viewId=%1，kind=%2（HOOK），physicalAddress=%3；表里读到 %4；LIST 结果=%5"))
                .arg(plan.installedViewId)
                .arg(static_cast<unsigned long>(KSWORD_ARK_HVM_VIEW_KIND_HOOK))
                .arg(hex64(plan.pageBasePhysical))
                .arg(kEntry == nullptr
                    ? ks::i18n::sourceText(QStringLiteral("（没有这个编号）"))
                    : ks::i18n::sourceText(QStringLiteral("kind=%1，physicalAddress=%2，shadowPhysicalAddress=%3，flipCount=%4"))
                        .arg(kEntry->kind)
                        .arg(hex64(kEntry->physicalAddress))
                        .arg(hex64(kEntry->shadowPhysicalAddress))
                        .arg(kEntry->flipCount))
                .arg(flagText(snapshot.views.ok)),
            presentVerdict,
            presentConclusion,
            KvmCheckRemedy::kNone,
            QString(),
            false));

        // ---- 1. Shadow pages and real pages are two distinct frames ----
        const quint64 kShadowPhysical = kEntry != nullptr
            ? kEntry->shadowPhysicalAddress
            : plan.shadowPhysicalAddress;
        KvmCheckVerdict shadowVerdict = KvmCheckVerdict::kPass;
        QString shadowConclusion;
        if (!snapshot.views.ok || kEntry == nullptr)
        {
            shadowVerdict = KvmCheckVerdict::kNoReading;
            shadowConclusion = ks::i18n::sourceText(QStringLiteral("表里没有这条视图，影子页地址无从核对。"));
        }
        else if (kShadowPhysical == 0ULL || kShadowPhysical == plan.pageBasePhysical)
        {
            shadowVerdict = KvmCheckVerdict::kFail;
            shadowConclusion = ks::i18n::sourceText(QStringLiteral("影子页地址为零或与真页相同：那样翻转过去执行的还是原来那一页，补丁不可能生效。"));
        }
        else
        {
            shadowConclusion = ks::i18n::sourceText(QStringLiteral("驱动为这条视图分配了一个独立的帧。注意本行只比地址：影子页里的 4096 字节是不是我们提交的那一份，这一段快照没有带回来，所以那件事在这里**没有被验证**。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookVerifyCriterion::kShadowDistinct),
            ks::i18n::sourceText(QStringLiteral("影子页地址非零且不等于真页")),
            ks::i18n::sourceText(QStringLiteral("shadowPhysicalAddress=%1；真页 pageBasePhysical=%2；安装时记下的影子地址=%3"))
                .arg(hex64(kShadowPhysical))
                .arg(hex64(plan.pageBasePhysical))
                .arg(hex64(plan.shadowPhysicalAddress)),
            shadowVerdict,
            shadowConclusion,
            KvmCheckRemedy::kNone,
            QString(),
            false));

        // ---- 2. Real page unchanged ----
        KvmCheckVerdict realVerdict = KvmCheckVerdict::kPass;
        QString realReadingDetail;
        QString realConclusion;
        if (snapshot.rereadPage.isEmpty())
        {
            realVerdict = KvmCheckVerdict::kNoReading;
            realReadingDetail = snapshot.rereadFailure.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("（重读没有返回任何字节）"))
                : snapshot.rereadFailure;
            realConclusion = ks::i18n::sourceText(QStringLiteral("目标页这次读不回来，所以不知道它有没有被改过。"));
        }
        else if (!plan.baselineIsComplete())
        {
            realVerdict = KvmCheckVerdict::kNoReading;
            realReadingDetail = ks::i18n::sourceText(QStringLiteral("（基线页不完整，没有可比对的基准）"));
            realConclusion = ks::i18n::sourceText(QStringLiteral("基线不是完整一页，比对没有基准。"));
        }
        else
        {
            const qsizetype kDifference =
                firstDifferenceOffset(snapshot.rereadPage, plan.baselinePage);
            if (kDifference < 0)
            {
                realReadingDetail = ks::i18n::sourceText(QStringLiteral("与基线逐字节相同"));
                realConclusion = ks::i18n::sourceText(QStringLiteral("真页没有被改动。这是一条**记账性读数，不是 EPT 事实**：addView 全程只写影子（hvm_ept_view.c:360-418），本来就不该碰真页。它的价值在于给「移除视图之后真页能复原」留下前半段证据。"));
            }
            else
            {
                realVerdict = KvmCheckVerdict::kFail;
                realReadingDetail = ks::i18n::sourceText(QStringLiteral("第一处不同在页内偏移 %1"))
                    .arg(hex64(static_cast<quint64>(kDifference)));
                realConclusion = ks::i18n::sourceText(QStringLiteral("真页与基线不同。HOOK 不改真页，所以是**别的东西**动过它——在弄清是什么之前不要继续，我们拼进影子页的原字节可能已经过期。"));
            }
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookVerifyCriterion::kRealPageUnchanged),
            ks::i18n::sourceText(QStringLiteral("真页与基线逐字节相同")),
            ks::i18n::sourceText(QStringLiteral("重读 %1 字节；基线 %2 字节；比对结果=%3"))
                .arg(snapshot.rereadPage.size())
                .arg(plan.baselinePage.size())
                .arg(realReadingDetail),
            realVerdict,
            realConclusion,
            realVerdict == KvmCheckVerdict::kFail
                ? KvmCheckRemedy::kRecaptureBaseline
                : KvmCheckRemedy::kNone,
            ks::i18n::sourceText(QStringLiteral("重新抓基线")),
            false));

        // ---- 3. Base EPT leaf re-read ----
        //
        // Steady-state primary leaf = valid page | READ | WRITE, **no EXECUTE** (hvm_ept_view.c:178-180).
        //
        // The criteria are compared together: reachedLeaf, R=1, W=1, X=0, plus **frame address == target page base address**.
        // Checking against X alone is insufficient — primary is a complete constant value; it requires one bit to match while allowing the others to be arbitrary.
        // However, when all three permission bits are correct but the frame points elsewhere, those three bits represent a valid reading of an error object.
        // If polarity flips on a backend (primary switches to shadow side), both the expected
        // **frame** and **three bits** must be updated together; do not change only the X flag.
        const EptLeafProbeResult& leaf = snapshot.leaf;
        const QString kLeafReading =
            ks::i18n::sourceText(QStringLiteral("eptPointer=%1；走到第 %2 级（%3）；叶项=%4；R=%5 W=%6 X=%7；帧=%8；largePage=%9；suppressVe=%10；localEptArmed=%11；eptpSwitchArmed=%12"))
                .arg(hex64(leaf.eptPointer))
                .arg(leaf.walkedLevels)
                .arg(leaf.leafLevel >= 0
                    ? eptLeafLevelName(leaf.leafLevel)
                    : ks::i18n::sourceText(QStringLiteral("未走到叶")))
                .arg(hex64(leaf.leafEntry))
                .arg(leaf.readable ? 1 : 0)
                .arg(leaf.writable ? 1 : 0)
                .arg(leaf.executable ? 1 : 0)
                .arg(hex64(leaf.leafFrameAddress))
                .arg(flagText(leaf.largePage))
                .arg(flagText(leaf.suppressVe))
                .arg(flagText(leaf.localEptArmed))
                .arg(flagText(leaf.eptpSwitchArmed));

        KvmCheckVerdict leafVerdict = KvmCheckVerdict::kPass;
        QString leafConclusion;
        // Only **private EPT** invalidates the base reading; EPTP switching does not.
        //
        // This rule previously blocked both backends together, which was a real defect: the only usable backend on the target machine is EPTP
        // switching, so the only criterion among the four that could disprove 'the leaf write was correct but ineffective' was disabled.
        // Testing on the target on 2026-09-07 disproved that assumption: after installing a CLOAK,
        // the base leaf read back `0x80000000F1353034  R=0 W=0 X=1`, exactly the CLOAK primary value.
        //
        // As hardcoded in the design doc: EPTP switch index 0 = base; each leaf takes the primary value, i.e., today's
        // steady state; index k relaxes only leaf k-1 (see the hierarchy numbering section in KswordArkHvmEptSwitch.h).
        // Thus, the base leaf is exactly the steady-state primary value, making it a valid criterion.
        // The one it cannot read is the 'relaxed leaf at index k', which belongs to the flipped state and is not covered by this criterion.
        //
        // Private EPT is different: each processor has its own tree branching from a base that
        // is not the currently loaded one, so that scenario still results in no-read verdict.
        // Bitwise OR of the two status bits: the bit from the probe itself and the bit from this snapshot come from two separate QUERY operations.
        if (leaf.localEptArmed || snapshot.state.localEptArmed)
        {
            // Blind spots must be presented alongside readings; otherwise, this criterion becomes another false positive.
            leafVerdict = KvmCheckVerdict::kNoReading;
            leafConclusion = ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT 已武装：每个处理器各有一棵从基座分叉出去的树，正在装载的不是基座，而本探针只读得到基座。所以这里既不能算通过也不能算失败。"));
        }
        else if (!leaf.ok)
        {
            leafVerdict = KvmCheckVerdict::kNoReading;
            leafConclusion = leaf.message.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("走表没有完成，拿不到叶项。"))
                : leaf.message;
        }
        else if (leaf.unmapped || !leaf.reachedLeaf)
        {
            leafVerdict = KvmCheckVerdict::kFail;
            leafConclusion = ks::i18n::sourceText(QStringLiteral("基座里这一页没有映射到叶。装了 HOOK 的页必须有一张能被翻转的叶项，走表被截断说明这一页不是我们以为的那一页。"));
        }
        else if (leaf.executable || !leaf.readable || !leaf.writable)
        {
            // Check all three bits together, not just X.
            //
            // The criterion name specifies 'R=1 W=1 X=0', but the earlier implementation only asserted X. A leaf
            // with R=0 W=0 X=0 (e.g., disabled by another mechanism) would incorrectly receive a green check here.
            // The three bits form a single unit: the primary value is the constant TruePage|READ|WRITE.
            // If any bit mismatches, it proves the leaf does not hold this constant.
            leafVerdict = KvmCheckVerdict::kFail;
            leafConclusion = ks::i18n::sourceText(QStringLiteral("叶项的权限三位与 HOOK 稳态的 primary 值对不上。primary 是真页 | READ | WRITE 且不给 X（hvm_ept_view.c:178-180），期望 R=1 W=1 X=0；上面「当前读数」里的实际三位就是证据。"));
        }
        else if (leaf.leafFrameAddress != plan.pageBasePhysical)
        {
            // Matching permissions do not guarantee a matching target.
            //
            // The frame in HOOK's primary value is the **true page**, and addView never modifies the true page
            // (hvm_ept_view.c:360-418 touches only shadows). Thus, the frame address must still equal the target page base address.
            // If not equal, this leaf has been remapped elsewhere, or we traversed the table to a different
            // page — either case causes the upper three bits to correctly indicate an error object.
            leafVerdict = KvmCheckVerdict::kFail;
            leafConclusion = ks::i18n::sourceText(QStringLiteral("叶项的权限三位对得上，但它指向的物理帧不是目标页。HOOK 的 primary 值指向真页本身，安装过程从不改写真页，所以帧地址应当仍等于目标页基址；对不上意味着这张叶描述的不是我们以为的那一页。"));
        }
        else
        {
            leafConclusion = ks::i18n::sourceText(QStringLiteral("叶项是真页 | R | W 且不可执行，帧地址也仍是目标页基址，与 HOOK 稳态的 primary 值一致（hvm_ept_view.c:178-180）。这是四条里唯一一条能被 EPT 层面的错误证伪的读数。它仍然不证明执行会落到影子页上——那件事本项目未实测。"));
        }
        // Under the EPTP switching backend, add a boundary note: this predicate reads the base, which by design holds the primary value for each
        // leaf, making it a valid predicate for steady state. It does not describe the leaf with relaxed constraints at index k (flipped state).
        if (leafVerdict != KvmCheckVerdict::kNoReading
            && (leaf.eptpSwitchArmed || snapshot.state.eptpSwitchArmed))
        {
            leafConclusion += QStringLiteral(" ");
            leafConclusion += ks::i18n::sourceText(QStringLiteral("后端是 EPTP 切换：本读数取自基座层次，而基座按设计让每一叶都取主值，所以它正是稳态的有效判据。它不描述翻转时切过去的那套层次（索引 k 只放宽第 k-1 号叶），那属于翻转态。"));
        }
        if (leaf.largePage && leafVerdict != KvmCheckVerdict::kNoReading)
        {
            leafConclusion += QStringLiteral(" ");
            leafConclusion += ks::i18n::sourceText(QStringLiteral("另外这张叶是大页，它管的不止目标这一页，改它会影响整段范围。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookVerifyCriterion::kBaseEptLeafNotExecutable),
            ks::i18n::sourceText(QStringLiteral("基座 EPT 叶回读：R=1 W=1 X=0")),
            kLeafReading,
            leafVerdict,
            leafConclusion,
            KvmCheckRemedy::kNone,
            QString(),
            false));

        return rows;
    }

    void KvmHookWizard::startVerifyResident()
    {
        if (verifyResidentInFlight_ || busy_)
        {
            return;
        }
        if (!plan_.installed)
        {
            return;
        }
        verifyResidentInFlight_ = true;
        const quint64 kSequence = ++verifyResidentSequence_;
        const unsigned long long kCursor = eventCursor_;

        // This path runs once per second and deliberately avoids busy states: disabling the
        // navigation buttons every second would make the entire dialog unusable during observation.
        QPointer<KvmHookWizard> safeThis(this);
        std::thread([safeThis, kSequence, kCursor]() {
            const VerifyResidentSnapshot kSnapshot =
                collectVerifyResidentSnapshot(kCursor);
            if (safeThis == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, kSequence, kSnapshot]() {
                    if (safeThis == nullptr)
                    {
                        return;
                    }
                    safeThis->applyVerifyResident(kSequence, kSnapshot);
                },
                Qt::QueuedConnection);
        }).detach();
    }

    void KvmHookWizard::applyVerifyResident(
        const quint64 sequence,
        const VerifyResidentSnapshot& snapshot)
    {
        verifyResidentInFlight_ = false;
        if (sequence != verifyResidentSequence_)
        {
            return;
        }

        // Events are consumable reads: once the cursor advances, the records read in the previous round cannot be retrieved again.
        if (snapshot.events.ok && snapshot.events.newestSequence > eventCursor_)
        {
            eventCursor_ = snapshot.events.newestSequence;
        }

        QVector<KvmCheckRow> rows = buildVerifyResidentRows(snapshot, plan_);
        const int kEventIndex =
            static_cast<int>(KvmHookResidentCriterion::kFlipEventObserved);
        if (kEventIndex < rows.size()
            && kEventIndex < verifyResidentRows_.size()
            && verifyResidentRows_.at(kEventIndex).verdict == KvmCheckVerdict::kPass
            && rows.at(kEventIndex).verdict != KvmCheckVerdict::kPass)
        {
            // This view flip event was already seen in the previous round. Since the cursor has advanced,
            // not reading it this round does not mean it didn't occur—retain the previous round's
            // conclusion; otherwise, a valid reading would be erased by itself in the next second.
            KvmCheckRow sticky = verifyResidentRows_.at(kEventIndex);
            sticky.conclusion = sticky.conclusion + QStringLiteral(" ")
                + ks::i18n::sourceText(QStringLiteral("（本行来自本次观察中较早的一次轮询：事件环是消费型的，游标推进之后旧事件读不回来。）"));
            rows[kEventIndex] = sticky;
        }
        verifyResidentRows_ = rows;
        fillCheckTable(verifyResidentTable_, verifyResidentRows_);

        if (verifyStatusLabel_ != nullptr)
        {
            const ksword::kvm::KvmState& state = snapshot.state;
            QString text =
                ks::i18n::sourceText(QStringLiteral("常驻存活：residentActive=%1；residentProcessorCount=%2 / 逻辑处理器 %3；vmExitCount=%4"))
                    .arg(flagText(state.residentActive))
                    .arg(state.residentProcessorCount)
                    .arg(state.processorCount)
                    .arg(state.vmExitCount);
            StatusRole role = state.residentActive
                ? StatusRole::kInfo
                : StatusRole::kIdle;
            if (!state.residentActive || state.residentProcessorCount == 0UL)
            {
                role = StatusRole::kWarning;
                text += QStringLiteral(" ");
                text += ks::i18n::sourceText(QStringLiteral("如果刚才还在常驻，那么发生过 fail-closed 退虚拟化。按代码最可能的三种成因：上一次翻转还没恢复就又来一次（hvm_ept_view.c:832-838）、取到的访问方向与视图不符（:843-858）、或者这条视图在切换后端里不可表示（hvm_ept_switch.c:519-526）。本向导不会自动重装——重装会把现场盖掉。"));
            }
            verifyStatusLabel_->setText(text);
            applyStatusRole(verifyStatusLabel_, role);
        }
    }

    KvmHookWizard::VerifyResidentSnapshot KvmHookWizard::collectVerifyResidentSnapshot(
        const unsigned long long afterSequence)
    {
        VerifyResidentSnapshot snapshot;
        snapshot.state = ksword::kvm::queryState();
        snapshot.stateValid = true;
        snapshot.views = ksword::kvm::listViews();
        // clear passed as false: Clearing the ring would also erase events currently being consumed by other panels.
        snapshot.events = ksword::kvm::readEvents(afterSequence, false);
        return snapshot;
    }

    QVector<KvmCheckRow> KvmHookWizard::buildVerifyResidentRows(
        const VerifyResidentSnapshot& snapshot,
        const KvmHookPlan& plan)
    {
        QVector<KvmCheckRow> rows;
        rows.reserve(static_cast<int>(KvmHookResidentCriterion::kCount));

        const ksword::kvm::KvmViewEntry* const kEntry =
            findInstalledView(snapshot.views, plan.installedViewId);
        const unsigned long long kFlipCount =
            kEntry != nullptr ? kEntry->flipCount : 0ULL;

        // ---- 0. Flip count
        //
        // Must check the backend first: the only increment point is at hvm_ept_view.c:903, while
        // the EPTP switch backend returns early at :821, so that code path is never reached.
        KvmCheckVerdict flipVerdict = KvmCheckVerdict::kNoReading;
        QString flipReading;
        QString flipConclusion;
        if (snapshot.state.eptpSwitchArmed)
        {
            flipReading =
                ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=true（EPTP 切换后端）；flipCount=%1（本后端不产生此计数）"))
                    .arg(kFlipCount);
            flipConclusion = ks::i18n::sourceText(QStringLiteral("本后端不产生这个计数：唯一的递增点在 hvm_ept_view.c:903，而切换后端在 :821 就提前返回了。所以这里恒为 0，**既不是失败也不代表没生效**——这一条在本后端下换成下面的事件环来看。"));
        }
        else if (kEntry == nullptr)
        {
            flipReading = ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=false（默认后端）；表里没有 viewId=%1"))
                .arg(plan.installedViewId);
            flipConclusion = ks::i18n::sourceText(QStringLiteral("视图表里读不到这条视图，拿不到它的计数。"));
        }
        else if (kFlipCount > 0ULL)
        {
            flipVerdict = KvmCheckVerdict::kPass;
            flipReading = ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=false（默认后端）；flipCount=%1"))
                .arg(kFlipCount);
            flipConclusion = ks::i18n::sourceText(QStringLiteral("这一页至少被翻转过一次：处理器为它取过 EPT 违例，驱动装上了影子叶并单步了一条指令。它证明翻转机制在跑，仍然不证明执行落到了影子页上。"));
        }
        else
        {
            flipReading = ks::i18n::sourceText(QStringLiteral("eptpSwitchArmed=false（默认后端）；flipCount=0"));
            flipConclusion = ks::i18n::sourceText(QStringLiteral("观察窗口内这一页没有被碰过。这是**无读数**，不是失败：目标函数还没被执行，或者常驻还没起来。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookResidentCriterion::kFlipCount),
            ks::i18n::sourceText(QStringLiteral("翻转计数从 0 变正（仅默认后端产生）")),
            flipReading,
            flipVerdict,
            flipConclusion,
            KvmCheckRemedy::kNone,
            QString(),
            false));

        // ---- 1. This view flip has appeared in the event ring
        int matchedEvents = 0;
        for (const ksword::kvm::KvmEventEntry& event : snapshot.events.events)
        {
            // ruleId for view flip carries the viewId: both share this column.
            if (event.type == KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION
                && event.ruleId == plan.installedViewId
                && plan.installedViewId != 0UL)
            {
                ++matchedEvents;
            }
        }
        KvmCheckVerdict eventVerdict = KvmCheckVerdict::kNoReading;
        QString eventConclusion;
        if (!snapshot.events.ok)
        {
            eventConclusion = snapshot.events.message.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("事件环读不回来。"))
                : snapshot.events.message;
        }
        else if (matchedEvents > 0)
        {
            eventVerdict = KvmCheckVerdict::kPass;
            eventConclusion = ks::i18n::sourceText(QStringLiteral("事件环里有这条视图的 EPT 违例：这一页在观察窗口内确实被访问并触发了翻转。它是 EPTP 切换后端下唯一的翻转证据。"));
        }
        else
        {
            eventConclusion = ks::i18n::sourceText(QStringLiteral("事件环里没有这条视图的翻转事件。这是**无读数**：目标函数在观察窗口内没有被执行过，既不是成功也不是失败。"));
        }
        rows.append(makeRow(
            static_cast<int>(KvmHookResidentCriterion::kFlipEventObserved),
            ks::i18n::sourceText(QStringLiteral("事件环里出现过 ruleId 等于本视图编号的 EPT 违例")),
            ks::i18n::sourceText(QStringLiteral("本次读回 %1 条事件（其中匹配 viewId=%2 的 EPT 违例 %3 条）；droppedRows=%4；availableRows=%5；newestSequence=%6；读取结果=%7"))
                .arg(snapshot.events.events.size())
                .arg(plan.installedViewId)
                .arg(matchedEvents)
                .arg(snapshot.events.droppedRows)
                .arg(snapshot.events.availableRows)
                .arg(snapshot.events.newestSequence)
                .arg(flagText(snapshot.events.ok)),
            eventVerdict,
            eventConclusion,
            KvmCheckRemedy::kNone,
            QString(),
            false));

        // ---- 2. Verify if execution was truly redirected ----
        //
        // Always has no readings. The original roadmap text states this; do not change it to 'Verified'.
        rows.append(makeRow(
            static_cast<int>(KvmHookResidentCriterion::kExecutionRedirected),
            ks::i18n::sourceText(QStringLiteral("执行被重定向到影子页")),
            ks::i18n::sourceText(QStringLiteral("本项目未实测：没有任何一条读数能回答这个问题")),
            KvmCheckVerdict::kNoReading,
            ks::i18n::sourceText(QStringLiteral("路线图原文：只验了 CLOAK（读被重定向）。HOOK 方向（执行被重定向到影子）未实测。上面两条只能说明这一页被访问过并触发了翻转，说不出被重定向过去执行的是哪一份字节。")),
            KvmCheckRemedy::kExplainNotMeasured,
            ks::i18n::sourceText(QStringLiteral("为什么没有读数")),
            false));

        return rows;
    }

    void KvmHookWizard::fillCheckTable(
        QTableWidget* const table,
        const QVector<KvmCheckRow>& rows)
    {
        if (table == nullptr)
        {
            return;
        }
        // Clear first, then rebuild: directly changing the row count will attach cell controls left over from the previous
        // batch (buttons in column 4) to the new rows, causing the buttons to execute the previous batch's repair actions.
        table->setRowCount(0);
        table->setRowCount(rows.size());

        // The button in the 4th column must callback to the dialog instance. Since fillCheckTable is static, we retrieve the
        // instance from the window containing the table itself, at which point the control tree is already fully constructed.
        KvmHookWizard* const kWizard =
            qobject_cast<KvmHookWizard*>(table->window());

        for (int row = 0; row < rows.size(); ++row)
        {
            const KvmCheckRow& data = rows.at(row);

            QTableWidgetItem* const kCriterionItem =
                new QTableWidgetItem(data.criterion);
            kCriterionItem->setToolTip(data.criterion);
            table->setItem(row, 0, kCriterionItem);

            // Column 2 records only what was read; Column 3 holds the conclusion. All three tables share this column semantics.
            QTableWidgetItem* const kReadingItem =
                new QTableWidgetItem(data.reading);
            kReadingItem->setToolTip(data.reading);
            table->setItem(row, 1, kReadingItem);

            // The verdict column uses a QLabel to inherit semantic status colors from the global style block:
            // QTableWidgetItem is not a control; applyStatusRole has no effect on it.
            QLabel* const kVerdictLabel = new QLabel(
                describeCheckVerdict(data.verdict),
                table);
            kVerdictLabel->setToolTip(data.conclusion);
            kVerdictLabel->setWordWrap(true);
            kVerdictLabel->setMargin(4);
            applyStatusRole(kVerdictLabel, checkVerdictStatusRole(data.verdict));
            table->setCellWidget(row, 2, kVerdictLabel);

            if (data.remedy != KvmCheckRemedy::kNone && kWizard != nullptr)
            {
                QPushButton* const kRemedyButton = new QPushButton(
                    data.remedyLabel,
                    table);
                kRemedyButton->setToolTip(data.conclusion);
                const KvmCheckRemedy kRemedy = data.remedy;
                connect(
                    kRemedyButton,
                    &QPushButton::clicked,
                    kWizard,
                    [kWizard, kRemedy]() {
                        kWizard->runPreflightRemedy(kRemedy);
                    });
                table->setCellWidget(row, 3, kRemedyButton);
            }
        }
        table->resizeRowsToContents();
    }
}
