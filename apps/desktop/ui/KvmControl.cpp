#include "KvmControl.h"

#include "../internationalization/LanguageManager.h"

#include <QSettings>
#include <QStringList>

#include <atomic>
// __cpuid: When the EPT window is insufficient, the host's physical address width must be read in user mode.
#include <intrin.h>

namespace ksword::kvm
{
    namespace
    {
        // A PML4 entry covers guest physical space.
        constexpr quint64 kBytesPerPml4Entry = 512ULL * 1024ULL * 1024ULL * 1024ULL;

        // Physical address width reported by host CPUID.80000008H:EAX[7:0]; returns 0 if unavailable.
        //
        // Read in user mode: MAXPHYADDR is provided by a CPUID instruction executable at CPL3, requiring no
        // driver assistance. This is precisely why this message can be accurate—it is needed only **after
        // the driver refuses**, at which point the driver's ability to cooperate is no longer guaranteed.
        unsigned long hostPhysicalAddressBits()
        {
            int leaves[4] = { 0, 0, 0, 0 };
            __cpuid(leaves, static_cast<int>(0x80000000));
            if (static_cast<unsigned int>(leaves[0]) < 0x80000008U)
            {
                return 0UL;
            }
            __cpuid(leaves, static_cast<int>(0x80000008));
            const unsigned long kBits =
                static_cast<unsigned long>(leaves[0]) & 0xFFUL;
            // Widths below 32 bits or above 52 bits are not architecturally meaningful; treat as unanswerable.
            return (kBits >= 32UL && kBits <= 52UL) ? kBits : 0UL;
        }

        // Persistent key for the write-access switch. Placed under Safety/ to align with other safety gates.
        const QString kWriteAccessSettingKey =
            QStringLiteral("Safety/Kvm/WriteAccessEnabled");

        // Persistent key for the nested mode switch.
        const QString kNestedAllowedSettingKey =
            QStringLiteral("Safety/Kvm/NestedAllowed");
        // Private EPT differs from #VE/VMFUNC: it does not expose capabilities, but ensures safety of
        // existing capabilities across multiple cores. Thus, it is persistent, just like nested mode.
        const QString kLocalEptSettingKey =
            QStringLiteral("Safety/Kvm/LocalEptEnabled");
        std::atomic<int> gLocalEptCache{ -1 };
        // The backend selection does not expose capabilities; it merely switches to a different machine view, so it is also persisted.
        const QString kEptpSwitchSettingKey =
            QStringLiteral("Safety/Kvm/EptpSwitchEnabled");
        std::atomic<int> gEptpSwitchCache{ -1 };
        // #VE is scoped to the current process only, with no corresponding registry key, ensuring it cannot persist across sessions.
        std::atomic<bool> gVeEnabled{ false };
        // VMFUNC also avoids setting keys: a guest-visible interface should not persist across sessions.
        std::atomic<bool> gVmFuncEnabled{ false };
        // Nested dispatch is not persisted in the settings key. Enabling it allows any ring 0 code to launch a
        // VM beneath us. If it persists across sessions, no one will remember it was enabled on the next boot.
        std::atomic<bool> gNestedDispatchEnabled{ false };
        std::atomic<bool> gHideHypervisor{ false };

        // In-process cache: button refresh is a high-frequency path and cannot read the registry every time.
        // -1 indicates that the value has not yet been read from QSettings.
        std::atomic_int gWriteAccessCache{ -1 };
        std::atomic_int gNestedAllowedCache{ -1 };

        // buildDetail: Compresses a single snapshot into a multi-line tooltip description.
        QString buildDetail(const KvmState& state)
        {
            QStringList lines;
            lines << ks::i18n::sourceText(QStringLiteral("KSwordVM（R-1 层）"));
            if (state.availability != KvmAvailability::kAvailable &&
                !state.residentActive)
            {
                lines << describeAvailability(state.availability);
                return lines.join(QStringLiteral("\n"));
            }
            if (state.residentActive)
            {
                lines << ks::i18n::sourceText(
                    QStringLiteral("常驻中：%1/%2 个逻辑处理器在 VMX non-root"))
                    .arg(state.residentProcessorCount)
                    .arg(state.processorCount);
                lines << ks::i18n::sourceText(QStringLiteral("累计 VM-exit：%1"))
                    .arg(state.vmExitCount);
            }
            else
            {
                lines << ks::i18n::sourceText(
                    QStringLiteral("就绪：%1 个逻辑处理器已准备，未进入 non-root"))
                    .arg(state.processorCount);
            }
            // Whether resident operation survives depends on the MSR bitmap and exit coverage; display both explicitly.
            lines << (state.msrBitmapReady
                ? ks::i18n::sourceText(QStringLiteral("MSR bitmap：可用"))
                : ks::i18n::sourceText(QStringLiteral("MSR bitmap：不可用（常驻会立即退出）")));
            lines << (state.sustainedProven
                ? ks::i18n::sourceText(QStringLiteral("常驻保持自检：已通过"))
                : ks::i18n::sourceText(QStringLiteral("常驻保持自检：未执行")));
            if (state.eptRuleCount > 0)
            {
                lines << ks::i18n::sourceText(QStringLiteral("EPT 规则：%1 条"))
                    .arg(state.eptRuleCount);
            }
            // There are two backends for the split view, and they must be selected based on the [armed state] rather than the request.
            // When requested but not armed due to insufficient capability, the driver keeps the default backend and does not
            // error. In this case, displaying "enabled" is worse than an error: the caller would reason about cross-processor
            // visibility based on a false premise. Therefore, the three cases are described separately and not merged.
            if (state.eptpSwitchArmed)
            {
                lines << ks::i18n::sourceText(QStringLiteral("分离视图后端：EPTP 切换（已武装，不需要 Monitor Trap Flag）"));
            }
            else if (isEptpSwitchEnabled())
            {
                lines << ks::i18n::sourceText(QStringLiteral("分离视图后端：写叶 + Monitor Trap Flag。已请求 EPTP 切换但未武装——驱动没有确认它需要的能力（INVEPT single 与 execute-only EPT 叶），或者资源是在打开这个开关之前准备的"));
            }
            else
            {
                lines << ks::i18n::sourceText(QStringLiteral("分离视图后端：写叶 + Monitor Trap Flag（默认）"));
            }
            // Per-processor private EPT follows the same mode as the backend selection above: a checkmark in the menu indicates
            // **Request**: Only the armed bit is factual. Installing views across multiple cores relies on this. If a request is made but the bit isn't
            // armed, starting the resident component returns only a raw status code 21, leaving the user unable to determine the specific failure.
            if (state.localEptArmed)
            {
                lines << ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT：已武装（多核上可以安装分离视图）"));
            }
            else if (isLocalEptEnabled())
            {
                lines << ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT：**已请求但未武装** —— 驱动没有确认它需要的能力（INVEPT single 与 Monitor Trap Flag），或者资源是在打开这个开关之前准备的。多核上安装分离视图会被拒"));
            }
            else if (state.processorCount > 1UL)
            {
                lines << ks::i18n::sourceText(QStringLiteral("每处理器私有 EPT：未请求。这台机器是多核，分离视图在共享层次上不安全，会被拒绝安装"));
            }
            // Both dangerous switches must be visible in the state, not just in the menu checkbox.
            // Armed but invisible is equivalent to not being armed at all.
            if (state.veArmed)
            {
                lines << ks::i18n::sourceText(QStringLiteral("#VE：控制位已武装。仍有两道保险挡着实际投递（全叶项 suppress-#VE、信息区锁 busy）"));
            }
            if (state.vmFuncArmed)
            {
                lines << ks::i18n::sourceText(QStringLiteral("VMFUNC：已武装。guest 中任意 ring 3 线程都能切换 EPT 视图，且不产生 VM-exit"));
            }
            if (state.nestedResident)
            {
                lines << ks::i18n::sourceText(
                    QStringLiteral("嵌套运行：作为 L1 跑在外层 hypervisor 之下，性能与可用能力均降级"));
            }
            else if (state.hypervisorPresent)
            {
                lines << (isNestedAllowed()
                    ? ks::i18n::sourceText(QStringLiteral("嵌套模式：已开启"))
                    : ks::i18n::sourceText(QStringLiteral("嵌套模式：已关闭（外层有 hypervisor，常驻会被拒绝）")));
            }
            // Outbound direction: who wants to run beneath us.
            //
            // This line appears only when non-zero, as it is normally always zero. When non-zero, it describes an event where
            // the user cannot see the causal link: another hypervisor on the machine failed to start a VM because we blocked it.
            // The transient status bit on the driver side is cleared on VMXOFF, so the value read here is a monotonically non-decreasing counter.
            if (state.nestedL2LaunchRefusedCount > 0UL)
            {
                lines << ks::i18n::sourceText(QStringLiteral("已拒绝 %1 次「在我们之下启动虚拟机」的请求：本机另一个 hypervisor（VMware / VirtualBox / WSL2 / Docker 等）尝试过 VMLAUNCH 并被拒。我们不提供嵌套 VMX，所以它的虚拟机在我们常驻期间起不来 —— 用户那边看到的现象是「虚拟机突然起不来了」，而线索不会指向这里。"))
                    .arg(state.nestedL2LaunchRefusedCount);
            }
            lines << (isWriteAccessEnabled()
                ? ks::i18n::sourceText(QStringLiteral("写权限：已开启（允许 R-1 改写）"))
                : ks::i18n::sourceText(QStringLiteral("写权限：已关闭（只读观测）")));
            if (state.faulted)
            {
                lines << ks::i18n::sourceText(
                    QStringLiteral("存在故障或待回滚，需要先重置"));
            }
            return lines.join(QStringLiteral("\n"));
        }

        // classify: Translate the query status returned by the driver and status bits into an availability conclusion.
        KvmAvailability classify(
            const ksword::ark::HvmStatusResult& result)
        {
            if (!result.io.ok || result.unsupported)
            {
                return KvmAvailability::kDriverNotRunning;
            }
            switch (result.response.queryStatus)
            {
            case KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED:
                return KvmAvailability::kFirmwareDisabled;
            case KSWORD_ARK_HVM_QUERY_STATUS_HYPERVISOR_CONFLICT:
                return KvmAvailability::kHypervisorConflict;
            case KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU:
                return KvmAvailability::kUnsupportedCpu;
            case KSWORD_ARK_HVM_QUERY_STATUS_BACKEND_NOT_IMPLEMENTED:
                return KvmAvailability::kBackendNotImplemented;
            default:
                break;
            }
            if ((result.response.stateFlags &
                    (KSWORD_ARK_HVM_STATE_FAULTED |
                     KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED)) != 0UL)
            {
                return KvmAvailability::kFaulted;
            }
            // Outer hypervisor present but nested mode disabled: the driver refuses to stay resident, but this is a user
            // toggleable setting. Reporting it as "unsupported" misleads users into thinking hardware replacement is needed.
            if ((result.response.featureFlags &
                    KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
                !isNestedAllowed())
            {
                return KvmAvailability::kNestedNotAllowed;
            }
            // Check VMX and SVM capability gates separately; EPT/MSR bitmap are not AMD capability bits.
            const unsigned long long kRequiredFeatures =
                result.response.backend == KSWORD_ARK_HVM_BACKEND_SVM ?
                (KSWORD_ARK_HVM_FEATURE_AMD |
                 KSWORD_ARK_HVM_FEATURE_SVM |
                 KSWORD_ARK_HVM_FEATURE_NPT |
                 KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED) :
                (
                KSWORD_ARK_HVM_FEATURE_INTEL |
                KSWORD_ARK_HVM_FEATURE_VMX |
                KSWORD_ARK_HVM_FEATURE_EPT |
                KSWORD_ARK_HVM_FEATURE_MSR_BITMAP |
                KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED);
            if ((result.response.featureFlags & kRequiredFeatures) !=
                kRequiredFeatures)
            {
                return KvmAvailability::kUnsupportedCpu;
            }
            if ((result.response.stateFlags &
                    KSWORD_ARK_HVM_STATE_RESOURCES_READY) == 0UL)
            {
                return KvmAvailability::kNotPrepared;
            }
            return KvmAvailability::kAvailable;
        }

        // toCommandResult: Translate driver control results into conclusions directly displayable in the UI.
        KvmCommandResult toCommandResult(
            const ksword::ark::HvmControlResult& result,
            const QString& actionName)
        {
            KvmCommandResult command;
            command.protocolStatus = result.response.status;
            command.ntStatus = result.response.lastStatus;
            command.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK;
            if (command.ok)
            {
                command.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return command;
            }
            if (!result.io.ok && result.unsupported)
            {
                command.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return command;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU:
                reason = ks::i18n::sourceText(QStringLiteral("处理器不支持"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED:
                reason = ks::i18n::sourceText(QStringLiteral("固件已关闭虚拟化"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT:
                reason = ks::i18n::sourceText(
                    QStringLiteral("已有 Hypervisor（Hyper-V/VBS）占用 VMX root"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_BUSY:
                reason = ks::i18n::sourceText(QStringLiteral("另一个 HVM 操作正在执行"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("全核集合失败"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_ROLLBACK_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要先重置故障状态"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED:
                reason = ks::i18n::sourceText(QStringLiteral("系统正在电源转换，已拒绝"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备。先在 KVM 菜单里执行「准备资源」"));
                break;
            // ---- Previously, this entire batch fell into the default case, exposing users with only a raw number ----
            //
            // The most frequent collisions involve the seven LOCAL_EPT entries (21-27): they are the mandatory path for the
            // 'per-processor private EPT' switch, which in turn is the only way to install separated views on multi-core systems.
            // The user only sees 'Protocol Status 21', without
            // knowing what 21 means or what to do next.
            case KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST:
                reason = ks::i18n::sourceText(QStringLiteral("请求本身不合法：多半是同时请求了互斥的能力，或带了这条命令不接受的标志"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("缺少显式确认位。这与安全策略无关，是协议要求调用方明确表态"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源已经准备过了。重复准备会把状态打成 FAULTED，所以驱动直接拒绝；要换配置请先「释放资源」"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("分配每处理器资源失败（多半是非分页内存不足）"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("一次性受控来宾没能启动：VMCS 构造或 VMLAUNCH 被拒"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT:
                reason = ks::i18n::sourceText(QStringLiteral("来宾产生了未预期的 VM 退出，已按 fail-closed 处理"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION:
                reason = ks::i18n::sourceText(QStringLiteral("这条路径只有部分实现，驱动拒绝在半成品上继续"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED:
                reason = ks::i18n::sourceText(QStringLiteral("外层 hypervisor 没有向本机暴露嵌套 VMX"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_EVMCS_UNSUPPORTED:
                reason = ks::i18n::sourceText(QStringLiteral("外层 hypervisor 不提供 eVMCS"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("生命周期守卫拒绝：常驻已在跑，或电源/拓扑/卸载守卫没有全部就位"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_NOT_ARMED:
                reason = ks::i18n::sourceText(QStringLiteral("请求了每处理器私有 EPT，但它没有被武装。武装发生在**准备资源**那一步，所以打开开关之后必须先「释放资源」再重新准备"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_LEAF_SET_TOO_LARGE:
                reason = ks::i18n::sourceText(QStringLiteral("要镜像的可翻转叶太多，超出每处理器私有层次的上限。先移除一些视图或规则"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_PAGE_BUDGET_EXHAUSTED:
                reason = ks::i18n::sourceText(QStringLiteral("私有 EPT 层次的页预算不够。处理器越多每叶越贵，减少视图/规则数量或减少核数"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_SPLIT_MISSING:
                reason = ks::i18n::sourceText(QStringLiteral("某一页缺少 4KiB 分裂，私有层次无法镜像它。这通常意味着规则或视图表在准备之后被改过"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_VERIFY_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("私有 EPT 层次建好之后没有通过自校验，已拒绝使用（宁可不启动，也不在没验过的页表上跑）"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_VMFUNC:
                reason = ks::i18n::sourceText(QStringLiteral("私有 EPT 与 VMFUNC 互斥：VMFUNC 发布一份全处理器共用的 EPTP 列表，而私有层次让同一个索引在每个处理器上指向不同的东西"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_NESTED:
                reason = ks::i18n::sourceText(QStringLiteral("私有 EPT 与嵌套 VMX 互斥。请关掉其中一个"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_EPT_WINDOW_TOO_SMALL:
            {
                /*
                 * This statement must be phrased inversely: **it is not that the processor is unsupported**.
                 *
                 * Before this code existed, the same scenario took the UNSUPPORTED_CPU path,
                 * causing an Intel Core Ultra with all capabilities to be told "processor not
                 * supported," forcing users to check the CPU and BIOS, neither of which had issues.
                 *
                 * All three values are indispensable: the local requirement (CPUID, read by user-mode), the
                 * available amount in this version (driver-reported eptPml4EntryBudget, **do not** use
                 * compile-time constants from the UI—these are incorrect when versions mismatch), and the
                 * converted address space size; otherwise, the first two values are meaningless to ordinary users.
                 */
                const unsigned long kBits = hostPhysicalAddressBits();
                const unsigned long kBudget =
                    result.response.eptPml4EntryBudget;
                const QString kBudgetText = kBudget != 0UL
                    ? ks::i18n::sourceText(QStringLiteral("%1 项（%2 TiB）"))
                        .arg(kBudget)
                        .arg((static_cast<quint64>(kBudget) * kBytesPerPml4Entry)
                                 / (1024ULL * 1024ULL * 1024ULL * 1024ULL))
                    : ks::i18n::sourceText(QStringLiteral("未知（这个驱动版本没有回报窗口大小）"));
                if (kBits != 0UL)
                {
                    const quint64 kNeedBytes = 1ULL << kBits;
                    const unsigned long kNeedEntries = static_cast<unsigned long>(
                        (kNeedBytes + kBytesPerPml4Entry - 1ULL) / kBytesPerPml4Entry);
                    reason = ks::i18n::sourceText(QStringLiteral(
                        "本机的客户物理地址空间比这一版驱动能建的 EPT 恒等映射窗口大：CPUID 报告 %1 位物理地址（%2 TiB），需要 %3 个 512 GiB 的 PML4 项，而这个驱动的窗口是 %4。**这不是处理器不支持** —— 它每一项能力都齐备，换一个窗口更大的驱动版本即可。"))
                        .arg(kBits)
                        .arg(kNeedBytes / (1024ULL * 1024ULL * 1024ULL * 1024ULL))
                        .arg(kNeedEntries)
                        .arg(kBudgetText);
                }
                else
                {
                    reason = ks::i18n::sourceText(QStringLiteral(
                        "本机的客户物理地址空间比这一版驱动能建的 EPT 恒等映射窗口大（这个驱动的窗口是 %1；本机需要多少问不出来，CPUID 没有提供物理地址宽度叶）。**这不是处理器不支持。**"))
                        .arg(kBudgetText);
                }
                break;
            }
            case KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("自检未通过"));
                break;
            case KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("状态代次已变化，请重新读取后再试"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            command.message = ks::i18n::sourceText(QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return command;
        }
    }

    QString describeAvailability(const KvmAvailability availability)
    {
        switch (availability)
        {
        case KvmAvailability::kAvailable:
            return ks::i18n::sourceText(QStringLiteral("可启动常驻"));
        case KvmAvailability::kDriverNotRunning:
            return ks::i18n::sourceText(
                QStringLiteral("KswordARK 驱动未运行，请先启用 R0"));
        case KvmAvailability::kUnsupportedCpu:
            return ks::i18n::sourceText(
                QStringLiteral("处理器不满足常驻硬件门（Intel VMX + EPT + MSR bitmap）"));
        case KvmAvailability::kFirmwareDisabled:
            return ks::i18n::sourceText(
                QStringLiteral("固件中已关闭虚拟化，请在 BIOS/UEFI 中开启"));
        case KvmAvailability::kHypervisorConflict:
            return ks::i18n::sourceText(
                QStringLiteral("Hyper-V/VBS 已占用 VMX root，需先关闭后重启"));
        case KvmAvailability::kNotPrepared:
            return ks::i18n::sourceText(QStringLiteral("尚未准备资源，点击后自动准备"));
        case KvmAvailability::kFaulted:
            return ks::i18n::sourceText(QStringLiteral("存在故障或待回滚，需要先重置"));
        case KvmAvailability::kBackendNotImplemented:
            return ks::i18n::sourceText(
                QStringLiteral("处理器支持 AMD SVM，但本版本尚未实现 SVM 后端"));
        case KvmAvailability::kNestedNotAllowed:
            return ks::i18n::sourceText(
                QStringLiteral("检测到外层 hypervisor（虚拟机或 VBS/HVCI）。在右键菜单中开启嵌套模式后可以作为 L1 运行"));
        }
        return QString();
    }

    KvmState queryState()
    {
        KvmState state;
        ksword::ark::DriverClient client;
        const auto kResult = client.queryHvmStatus();
        state.availability = classify(kResult);
        if (!kResult.io.ok || kResult.unsupported)
        {
            state.shortStatus = describeAvailability(state.availability);
            state.detail = buildDetail(state);
            return state;
        }

        const auto& response = kResult.response;
        state.backend = response.backend;
        state.generation = response.generation;
        state.processorCount = response.processorCount;
        state.residentProcessorCount = response.residentProcessorCount;
        state.eptRuleCount = response.eptRuleCount;
        state.vmExitCount = response.vmExitCount;
        state.eptPointer = response.eptPointer;
        state.residentActive = response.residentProcessorCount > 0UL ||
            (response.stateFlags &
                KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) != 0UL;
        state.residentComplete = response.processorCount > 0UL &&
            response.residentProcessorCount == response.processorCount;
        state.faulted = (response.stateFlags &
            (KSWORD_ARK_HVM_STATE_FAULTED |
             KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED)) != 0UL;
        state.msrBitmapReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_MSR_BITMAP) != 0ULL;
        state.exitEmulationReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION) != 0ULL;
        state.sustainedProven = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED) != 0ULL;
        state.eptRulesReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_EPT_RULES) != 0ULL;
        state.hypervisorPresent = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL;
        state.nestedResident = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_RESIDENT_NESTED) != 0UL;
        state.nestedL2LaunchRefusedCount =
            response.nestedL2LaunchRefusedCount;
        state.veArmed = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_VE_ACTIVE) != 0UL;
        state.veSuppressedByDefault = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_VE_SUPPRESSED_BY_DEFAULT) != 0ULL;
        state.vmFuncArmed = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE) != 0UL;
        state.eptpSwitchingAvailable = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING) != 0ULL;
        // Read the armed bit rather than the local request switch: the driver sets this bit only when capabilities are complete;
        // if capabilities are missing, it defaults to the backend without error, and the request bit is identical in both cases.
        state.eptpSwitchArmed = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;
        // Same reason, same pitfall: Private EPT was previously only visible in the menu checkbox, which represents a
        // request. When driver capabilities are insufficient, maintain the shared hierarchy without raising an error.
        state.localEptArmed = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) != 0ULL;
        // Pre-installation view setup: the driver checks items one by one, so the UI must also report them one by one. Previously, without these four flags,
        // 'installation failure' could only be displayed as a protocol status code, leaving users unable to identify which specific item was missing.
        state.resourcesReady = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0UL;
        state.eptReady = (response.stateFlags &
            KSWORD_ARK_HVM_STATE_EPT_READY) != 0UL;
        state.inveptSingleReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL;
        state.monitorTrapFlagReady = (response.featureFlags &
            KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL;

        if (state.residentActive)
        {
            state.shortStatus = state.residentComplete
                ? ks::i18n::sourceText(QStringLiteral("KVM 常驻中（全核）"))
                : ks::i18n::sourceText(QStringLiteral("KVM 常驻中（部分核心）"));
        }
        else
        {
            state.shortStatus = describeAvailability(state.availability);
        }
        state.detail = buildDetail(state);
        return state;
    }

    KvmCommandResult ensurePrepared()
    {
        ksword::ark::DriverClient client;
        auto status = client.queryHvmStatus();
        if (!status.io.ok || status.unsupported)
        {
            KvmCommandResult failure;
            failure.message = describeAvailability(
                KvmAvailability::kDriverNotRunning);
            return failure;
        }

        // Do not ignore selected Intel extensions: the AMD first version has no corresponding implementation.
        if (status.response.backend == KSWORD_ARK_HVM_BACKEND_SVM &&
            (isLocalEptEnabled() || isEptpSwitchEnabled() ||
             isNestedDispatchEnabled() || isVeEnabled() ||
             isVmFuncEnabled() || isHypervisorHidden()))
        {
            KvmCommandResult failure;
            failure.message = ks::i18n::sourceText(QStringLiteral("AMD 常驻不支持所选的 Intel 扩展。请关闭 EPT、嵌套派发、VE、VMFUNC 和身份隐藏选项后重试。"));
            return failure;
        }
        unsigned long generation = status.response.generation;
        // Do not re-allocate when resources are ready: PREPARE returns ALREADY_PREPARED for the ready state.
        if ((status.response.stateFlags &
                KSWORD_ARK_HVM_STATE_RESOURCES_READY) == 0UL)
        {
            // Backend selection is only read by PREPARE: the driver decides on armament during resource
            // preparation, and the START_RESIDENT whitelist will treat this bit as INVALID_REQUEST.
            const auto kPrepared = client.controlHvm(
                KSWORD_ARK_HVM_CONTROL_PREPARE,
                generation,
                false,
                isNestedAllowed(),
                true,
                false,
                false,
                false,
                false,
                false,
                /*
                 * enableLocalEpt must be issued here, not only at START_RESIDENT.
                 *
                 * LocalEptArmed is only set by PREPARE — the resident driver checks that
                 * already-determined value. If this bit is only present in START_RESIDENT, it passes
                 * the whitelist check, but LocalEptArmed remains permanently false, causing the driver
                 * to reject with STATUS_NOT_SUPPORTED and the UI to display 'CPU not supported' —
                 * while the real cause is that this bit never reached the path capable of setting it.
                 */
                isLocalEptEnabled(),
                isEptpSwitchEnabled());
            auto result = toCommandResult(
                kPrepared,
                ks::i18n::sourceText(QStringLiteral("准备 KVM 资源")));
            if (!result.ok)
            {
                return result;
            }
            generation = kPrepared.response.newGeneration;
        }
        // PREPARE may select a different backend from the requested one. Read back
        // the actual armed bits before reporting readiness or entering residency.
        status = client.queryHvmStatus();
        if (!status.io.ok || status.unsupported || status.response.queryStatus != 0)
        {
            KvmCommandResult failure;
            failure.message = ks::i18n::sourceText(QStringLiteral("准备后状态查询失败，未继续自检或启动。"));
            return failure;
        }
        generation = status.response.generation;
        if ((isEptpSwitchEnabled() && !(status.response.featureFlags & KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED)) ||
            (isLocalEptEnabled() && !(status.response.featureFlags & KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED)))
        {
            KvmCommandResult failure;
            failure.message = ks::i18n::sourceText(QStringLiteral("请求的 EPT 后端未实际武装。请停止常驻、释放资源后重新准备，并检查硬件能力。"));
            return failure;
        }
        // Self-test confirms that each logical processor completes a backend hardware round-trip, which is a prerequisite for resident startup.
        if ((status.response.stateFlags &
                KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) == 0UL)
        {
            const auto kTested = client.controlHvm(
                KSWORD_ARK_HVM_CONTROL_SELF_TEST,
                generation,
                true,
                isNestedAllowed(),
                true);
            return toCommandResult(
                kTested,
                ks::i18n::sourceText(QStringLiteral("KVM 自检")));
        }

        KvmCommandResult success;
        success.ok = true;
        success.message = ks::i18n::sourceText(QStringLiteral("KVM 资源已就绪。"));
        return success;
    }

    KvmCommandResult startResident(const unsigned long expectedGeneration)
    {
        /*
         * Mutually exclusive combinations are blocked before dispatch, rather than letting the driver reject them.
         *
         * The driver indeed rejects this (kswordArkHvmResidentStart returns STATUS_INVALID_PARAMETER
         * for ENABLE_LOCAL_EPT + ENABLE_NESTED_VMX), but that response is "invalid request" without
         * specifying **which bit** caused it. Both switches appear in the menu, can be checked, and
         * clicking Start yields an uninformative error. This is exactly the same failure mode as
         * when force=true turned "release resources" into a constant failure: symptoms alone cannot
         * reveal the root cause; one must cross-reference the whitelist item by item.
         *
         * The root cause is structural: nesting must synthesize an EPT pointer from the guest's level
         * and our level, but per-processor private roots make this synthesis processor-specific.
         * Thus, it is necessary to clearly state which two switches conflict and why.
         */
        if (isHypervisorHidden() && !isNestedDispatchEnabled())
        {
            KvmCommandResult failure;
            failure.message = ks::i18n::sourceText(QStringLiteral("隐藏 Hypervisor 身份要求同时开启嵌套派发。"));
            return failure;
        }
        if (isLocalEptEnabled() && isNestedDispatchEnabled())
        {
            KvmCommandResult conflict;
            conflict.ok = false;
            conflict.message = ks::i18n::sourceText(QStringLiteral("「每处理器私有 EPT」与「嵌套派发」不能同时开启。嵌套要把来宾的 EPT 层次和我们的合成成一个指针，而私有根会让这个合成变成处理器相关的。请先关掉其中一个。"));
            return conflict;
        }
        // Before the resident component starts, it must be prepared and self-checked; otherwise, the driver will reject it directly.
        const auto kPrepared = ensurePrepared();
        if (!kPrepared.ok)
        {
            return kPrepared;
        }
        ksword::ark::DriverClient client;
        // Both preparation and self-check advance the generation, so re-read instead of using the caller-provided value.
        const auto kRefreshed = client.queryHvmStatus();
        if (!kRefreshed.io.ok || kRefreshed.unsupported || kRefreshed.response.queryStatus != 0)
        {
            KvmCommandResult failure;
            failure.message = ks::i18n::sourceText(QStringLiteral("操作前状态查询失败，未使用旧代次继续执行。"));
            return failure;
        }
        (void)expectedGeneration;
        const unsigned long kGeneration = kRefreshed.response.generation;
        const auto kStarted = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
            kGeneration,
            true,
            isNestedAllowed(),
            true,
            kRefreshed.response.backend != KSWORD_ARK_HVM_BACKEND_SVM,
            /*
             * enableNestedVmx was originally hardcoded to false, so this path can never enable
             * nested dispatch. The entire nested feature is only accessible via the KernelDock
             * page, which hard-binds it to 'which feature page is currently active' with no
             * toggle. This end-to-end verified capability does not exist on the main UI.
             */
            isNestedDispatchEnabled(),
            false,
            isVeEnabled(),
            isVmFuncEnabled(),
            isLocalEptEnabled(),
            false, 0UL, isHypervisorHidden());
        // enableEptpSwitch is intentionally left at the default false: the backend is
        // already determined by PREPARE in ensurePrepared; if this flag appears on
        // START_RESIDENT, the driver's whitelist will classify it as INVALID_REQUEST.
        return toCommandResult(
            kStarted,
            ks::i18n::sourceText(QStringLiteral("启动 KVM 常驻")));
    }

    KvmCommandResult stopResident(const unsigned long expectedGeneration)
    {
        ksword::ark::DriverClient client;
        const auto kStopped = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
            expectedGeneration,
            false,
            false,
            true);
        return toCommandResult(
            kStopped,
            ks::i18n::sourceText(QStringLiteral("停止 KVM 常驻")));
    }

    KvmCommandResult runSoak(
        const unsigned long expectedGeneration,
        const unsigned long milliseconds)
    {
        const auto kPrepared = ensurePrepared();
        if (!kPrepared.ok)
        {
            return kPrepared;
        }
        ksword::ark::DriverClient client;
        const auto kRefreshed = client.queryHvmStatus();
        if (!kRefreshed.io.ok || kRefreshed.unsupported || kRefreshed.response.queryStatus != 0)
        {
            KvmCommandResult failure;
            failure.message = ks::i18n::sourceText(QStringLiteral("操作前状态查询失败，未使用旧代次继续执行。"));
            return failure;
        }
        (void)expectedGeneration;
        const unsigned long kGeneration = kRefreshed.response.generation;
        const auto kSoaked = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_SOAK,
            kGeneration,
            true,
            isNestedAllowed(),
            true,
            true,
            false,
            false,
            // enableVe: The hold self-test never enables #VE; it is intended to prove that resident operation can survive.
            false,
            // enableVmFunc: Similarly, keep self-checks from exposing any guest-visible switch interfaces.
            false,
            // enableLocalEpt: The self-check aims to prove that the resident component survives, not
            // that a private layer can be built; creating an extra layer would only mix failure causes.
            false,
            // enableEptpSwitch: This bit is only recognized during PREPARE; including it during SOAK will cause rejection.
            // The backend determines how views are installed; it does not determine whether resident operation can survive.
            false,
            milliseconds);
        auto result = toCommandResult(
            kSoaked,
            ks::i18n::sourceText(QStringLiteral("KVM 常驻保持自检")));
        if (result.ok)
        {
            result.message = ks::i18n::sourceText(
                QStringLiteral("常驻保持自检通过：保持 %1 毫秒，无处理器掉出 non-root。"))
                .arg(kSoaked.response.soakElapsedMilliseconds);
        }
        else if (kSoaked.response.soakUnexpectedDevirtualizations > 0UL)
        {
            // Core drops are the most valuable failure evidence and must be presented verbatim rather than merged into generic failure messages.
            result.message = ks::i18n::sourceText(
                QStringLiteral("常驻保持自检失败：保持 %1 毫秒后有 %2 个处理器掉出 non-root。"))
                .arg(kSoaked.response.soakElapsedMilliseconds)
                .arg(kSoaked.response.soakUnexpectedDevirtualizations);
        }
        return result;
    }

    KvmCommandResult resetFault(const unsigned long expectedGeneration)
    {
        ksword::ark::DriverClient client;
        const auto kReset = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_RESET_FAULT,
            expectedGeneration,
            true,
            false,
            true);
        return toCommandResult(
            kReset,
            ks::i18n::sourceText(QStringLiteral("重置 KVM 故障状态")));
    }

    KvmCommandResult releaseResources(const unsigned long expectedGeneration)
    {
        ksword::ark::DriverClient client;
        /*
         * The TEARDOWN permission bits include **only** UI_CONFIRMED; FORCE is not accepted.
         *
         * Originally, force=true was passed, causing `(flags & ~allowedFlags)
         * != 0` to always hold true; this command **never succeeded**.
         * Pressing 'Release Resources' in the menu immediately returns INVALID_REQUEST. Providing an extra digit that isn't
         * ignored, with a rejection reason stating only 'Invalid Request' without specifying which digit is wrong, yields no
         * symptoms pointing to the root cause; the only solution is to verify against the command whitelist item by item.
         *
         * Match the allowedFlags switch in hvm_runtime.c:
         *   STOP_RESIDENT / TEARDOWN: only when UI_CONFIRMED.
         *   PREPARE                    UI_CONFIRMED | ALLOW_NESTED | ENABLE_EPTP_SWITCH
         *   SELF_TEST / START_RESIDENT UI_CONFIRMED | FORCE | ALLOW_NESTED | …
         */
        const auto kReleased = client.controlHvm(
            KSWORD_ARK_HVM_CONTROL_TEARDOWN,
            expectedGeneration,
            false,
            false,
            true);
        return toCommandResult(
            kReleased,
            ks::i18n::sourceText(QStringLiteral("释放 KVM 资源")));
    }

    bool isNestedAllowed()
    {
        const int kCached = gNestedAllowedCache.load(std::memory_order_relaxed);
        if (kCached >= 0)
        {
            return kCached != 0;
        }
        QSettings settings;
        const bool kAllowed =
            settings.value(kNestedAllowedSettingKey, false).toBool();
        gNestedAllowedCache.store(kAllowed ? 1 : 0, std::memory_order_relaxed);
        return kAllowed;
    }

    void setNestedAllowed(const bool allowed)
    {
        QSettings settings;
        settings.setValue(kNestedAllowedSettingKey, allowed);
        gNestedAllowedCache.store(allowed ? 1 : 0, std::memory_order_relaxed);
    }

    bool isHypervisorHidden() { return gHideHypervisor.load(std::memory_order_relaxed); }
    void setHypervisorHidden(bool enabled) { gHideHypervisor.store(enabled, std::memory_order_relaxed); }

    bool isNestedDispatchEnabled()
    {
        // In-process state, deliberately not persisted to QSettings: restarting the client resets it to disabled.
        // It enables a capability (others can run VMs beneath us), not
        // a description of the environment (we run beneath others).
        // Thus, it belongs with #VE/VMFUNC, not with isNestedAllowed.
        return gNestedDispatchEnabled.load(std::memory_order_relaxed);
    }

    void setNestedDispatchEnabled(const bool enabled)
    {
        gNestedDispatchEnabled.store(enabled, std::memory_order_relaxed);
        if (!enabled) { gHideHypervisor.store(false, std::memory_order_relaxed); }
    }

    bool isVeEnabled()
    {
        // In-process state, deliberately not persisted to QSettings: restarting the client resets it to disabled.
        return gVeEnabled.load(std::memory_order_relaxed);
    }

    void setVeEnabled(const bool enabled)
    {
        gVeEnabled.store(enabled, std::memory_order_relaxed);
    }

    bool isLocalEptEnabled()
    {
        const int kCached = gLocalEptCache.load(std::memory_order_relaxed);
        if (kCached >= 0)
        {
            return kCached != 0;
        }
        QSettings settings;
        const bool kEnabled =
            settings.value(kLocalEptSettingKey, false).toBool();
        gLocalEptCache.store(kEnabled ? 1 : 0, std::memory_order_relaxed);
        return kEnabled;
    }

    void setLocalEptEnabled(const bool enabled)
    {
        QSettings settings;
        settings.setValue(kLocalEptSettingKey, enabled);
        gLocalEptCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
    }

    bool isEptpSwitchEnabled()
    {
        const int kCached = gEptpSwitchCache.load(std::memory_order_relaxed);
        if (kCached >= 0)
        {
            return kCached != 0;
        }
        QSettings settings;
        const bool kEnabled =
            settings.value(kEptpSwitchSettingKey, false).toBool();
        gEptpSwitchCache.store(kEnabled ? 1 : 0, std::memory_order_relaxed);
        return kEnabled;
    }

    void setEptpSwitchEnabled(const bool enabled)
    {
        QSettings settings;
        settings.setValue(kEptpSwitchSettingKey, enabled);
        gEptpSwitchCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
    }

    bool isVmFuncEnabled()
    {
        // Like #VE, it lives only in this process: restarting the client resets it to disabled.
        return gVmFuncEnabled.load(std::memory_order_relaxed);
    }

    void setVmFuncEnabled(const bool enabled)
    {
        gVmFuncEnabled.store(enabled, std::memory_order_relaxed);
    }

    bool isWriteAccessEnabled()
    {
        const int kCached = gWriteAccessCache.load(std::memory_order_relaxed);
        if (kCached >= 0)
        {
            return kCached != 0;
        }
        QSettings settings;
        const bool kEnabled =
            settings.value(kWriteAccessSettingKey, false).toBool();
        gWriteAccessCache.store(kEnabled ? 1 : 0, std::memory_order_relaxed);
        return kEnabled;
    }

    void setWriteAccessEnabled(const bool enabled)
    {
        QSettings settings;
        settings.setValue(kWriteAccessSettingKey, enabled);
        gWriteAccessCache.store(enabled ? 1 : 0, std::memory_order_relaxed);
    }

    namespace
    {
        // toMemoryResult: Translate driver responses into conclusions ready for direct UI display.
        KvmMemoryResult toMemoryResult(
            const ksword::ark::HvmMemoryResult& result,
            const QString& actionName,
            const bool expectPayload)
        {
            KvmMemoryResult memory;
            memory.usedDirectWindow = result.response.usedDirectWindow != 0;
            memory.windowReady = result.response.windowReady != 0;
            memory.physicalAddress = result.response.physicalAddress;
            memory.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_MEMORY_STATUS_OK;
            if (memory.ok)
            {
                if (expectPayload)
                {
                    memory.data = QByteArray(
                        reinterpret_cast<const char*>(result.response.data),
                        static_cast<int>(result.response.bytesTransferred));
                }
                memory.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return memory;
            }
            if (!result.io.ok && result.unsupported)
            {
                memory.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return memory;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_WINDOW_UNAVAILABLE:
                reason = ks::i18n::sourceText(
                    QStringLiteral("私有页表窗口不可用"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_ADDRESS_INVALID:
                reason = ks::i18n::sourceText(QStringLiteral("地址或长度非法"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_TRANSLATION_FAILED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("该地址在目标页表中未映射"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_ACCESS_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("访问该物理页失败"));
                break;
            case KSWORD_ARK_HVM_MEMORY_STATUS_PARTIAL:
                reason = ks::i18n::sourceText(
                    QStringLiteral("只完成了 %1 字节"))
                    .arg(result.response.bytesTransferred);
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            memory.message = ks::i18n::sourceText(QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return memory;
        }

        // denyWithoutWriteAccess: Unconditionally denies access when write permissions are disabled and initiates no IOCTL.
        KvmMemoryResult denyWithoutWriteAccess(const QString& actionName)
        {
            KvmMemoryResult memory;
            memory.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return memory;
        }
    }

    KvmMemoryResult queryMemoryWindow()
    {
        ksword::ark::DriverClient client;
        // Window queries do not touch memory, so no gates beyond token confirmation are needed.
        const auto kResult = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW,
            0,
            0,
            0,
            nullptr,
            false,
            true);
        return toMemoryResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("查询 R-1 内存窗口")),
            false);
    }

    KvmMemoryResult readPhysical(
        const unsigned long long physicalAddress,
        const unsigned long length)
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL,
            physicalAddress,
            0,
            length,
            nullptr,
            false,
            true);
        return toMemoryResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("R-1 读取物理内存")),
            true);
    }

    KvmMemoryResult writePhysical(
        const unsigned long long physicalAddress,
        const QByteArray& payload)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("R-1 写入物理内存"));
        // Write permission is the second gate within the process: when closed, no IOCTL is sent.
        if (!isWriteAccessEnabled())
        {
            return denyWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL,
            physicalAddress,
            0,
            static_cast<unsigned long>(payload.size()),
            reinterpret_cast<const unsigned char*>(payload.constData()),
            // Writes must go through a private window. MmCopyMemory has no physical write path;
            // rather than letting the driver fail on the rollback path, directly require a window.
            true,
            true);
        return toMemoryResult(kResult, kActionName, false);
    }

    KvmMemoryResult readVirtual(
        const unsigned long long directoryBase,
        const unsigned long long virtualAddress,
        const unsigned long length)
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL,
            virtualAddress,
            directoryBase,
            length,
            nullptr,
            false,
            true);
        return toMemoryResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("R-1 读取虚拟内存")),
            true);
    }

    KvmMemoryResult writeVirtual(
        const unsigned long long directoryBase,
        const unsigned long long virtualAddress,
        const QByteArray& payload)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("R-1 写入虚拟内存"));
        if (!isWriteAccessEnabled())
        {
            return denyWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL,
            virtualAddress,
            directoryBase,
            static_cast<unsigned long>(payload.size()),
            reinterpret_cast<const unsigned char*>(payload.constData()),
            true,
            true);
        return toMemoryResult(kResult, kActionName, false);
    }

    KvmMemoryResult translate(
        const unsigned long long directoryBase,
        const unsigned long long virtualAddress)
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.hvmMemory(
            KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE,
            virtualAddress,
            directoryBase,
            0,
            nullptr,
            false,
            true);
        return toMemoryResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("R-1 地址翻译")),
            false);
    }

    namespace
    {
        // Two NTSTATUS values returned for the view path. Provide the numeric values here rather than importing them into ntstatus.h:
        // This layer only needs to separate the two branches; the entire status code table is not required.
        // Source of the value: Windows SDK shared/ntstatus.h:
        // STATUS_DEVICE_BUSY = 0x80000011，STATUS_NOT_SUPPORTED = 0xC00000BB。
        constexpr long kViewStatusDeviceBusy =
            static_cast<long>(0x80000011UL);
        constexpr long kViewStatusNotSupported =
            static_cast<long>(0xC00000BBUL);

        // toViewResult: Translate driver view responses into conclusions ready for direct UI display.
        KvmViewResult toViewResult(
            const ksword::ark::HvmViewResult& result,
            const QString& actionName)
        {
            KvmViewResult view;
            view.viewId = result.response.viewId;
            view.viewCount = result.response.viewCount;
            // Both levels of failure codes must be propagated on every return path: the caller relies on them
            // to pinpoint the failure step, whereas a message string discards this information once formed.
            view.protocolStatus = result.response.status;
            view.lastStatus = result.response.lastStatus;
            view.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_VIEW_STATUS_OK;
            if (view.ok)
            {
                const unsigned long kRows =
                    result.response.returnedRows <= KSWORD_ARK_HVM_MAX_VIEWS
                        ? result.response.returnedRows
                        : KSWORD_ARK_HVM_MAX_VIEWS;
                for (unsigned long index = 0; index < kRows; ++index)
                {
                    const auto& row = result.response.rows[index];
                    KvmViewEntry entry;
                    entry.viewId = row.viewId;
                    entry.kind = row.kind;
                    entry.flags = row.flags;
                    entry.physicalAddress = row.physicalAddress;
                    entry.shadowPhysicalAddress = row.shadowPhysicalAddress;
                    entry.flipCount = row.flipCount;
                    view.views.append(entry);
                }
                view.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return view;
            }
            if (!result.io.ok && result.unsupported)
            {
                view.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return view;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST:
                // Previously, this case fell into the default branch, displaying as the meaningless 'Protocol Status 1'.
                // The driver maps all four validation failures to this single code, so the message must list all four
                // scenarios; otherwise, users can only guess whether the address is wrong or the version mismatch.
                reason = ks::i18n::sourceText(
                    QStringLiteral("请求被判为无效：目标物理地址未按四 KiB 页对齐、或超出驱动映射上界八 TiB、或协议版本与结构大小与驱动不符、或指定的代次与当前代次不一致"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND:
                reason = ks::i18n::sourceText(QStringLiteral("没有这条视图"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL:
                reason = ks::i18n::sourceText(QStringLiteral("视图表已满"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("无法把该页拆成四 KiB 粒度"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT:
                reason = ks::i18n::sourceText(
                    QStringLiteral("该页已被另一条视图或 EPT 规则占用"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("处理器不支持仅执行的 EPT 叶项，无法隐藏"));
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE:
                // The same protocol code is generated by two completely different branches; only lastStatus can distinguish them:
                // An already-running resident hypervisor is an operation-ordering issue we can resolve ourselves; insufficient topology or capabilities are not.
                // The latter is not phrased as 'go change the CPU core count'—the private EPT request bits required for multi-core
                // cannot be sent to the PREPARE whitelist in the current driver, so that path is blocked and should not mislead users.
                if (result.response.lastStatus == kViewStatusDeviceBusy)
                {
                    reason = ks::i18n::sourceText(
                        QStringLiteral("正在常驻：常驻期间视图表、EPT 叶项与影子页都被锁为不可变，请先停止常驻再安装"));
                }
                else if (result.response.lastStatus == kViewStatusNotSupported)
                {
                    reason = ks::i18n::sourceText(
                        QStringLiteral("拓扑或能力不满足：多处理器上安装视图需要每处理器私有 EPT 层次，而该请求位当前无法通过协议送达驱动；此外处理器必须支持单上下文 INVEPT，使用默认后端时还必须支持 Monitor Trap Flag"));
                }
                else
                {
                    reason = ks::i18n::sourceText(
                        QStringLiteral("视图翻转共享叶项，只能在单处理器且未常驻时安装"));
                }
                break;
            case KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("影子页分配或捕获失败"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            view.message = ks::i18n::sourceText(QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return view;
        }

        // denyViewWithoutWriteAccess: uniformly deny access when write permissions are disabled without issuing an IOCTL.
        KvmViewResult denyViewWithoutWriteAccess(const QString& actionName)
        {
            KvmViewResult view;
            view.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return view;
        }

        // toDomainResult: Translate driver domain execution responses into conclusions directly displayable in the UI.
        KvmDomainResult toDomainResult(
            const ksword::ark::HvmDomainResult& result,
            const QString& actionName)
        {
            KvmDomainResult domain;
            domain.domainIndex = result.response.domainIndex;
            domain.domainCount = result.response.domainCount;
            domain.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_DOMAIN_STATUS_OK;
            if (domain.ok)
            {
                const unsigned long kRows =
                    result.response.returnedRows <=
                        KSWORD_ARK_HVM_MAX_DOMAIN_ROWS
                        ? result.response.returnedRows
                        : KSWORD_ARK_HVM_MAX_DOMAIN_ROWS;
                for (unsigned long index = 0; index < kRows; ++index)
                {
                    const auto& row = result.response.rows[index];
                    KvmDomainEntry entry;
                    entry.domainIndex = row.domainIndex;
                    entry.active = row.active != 0;
                    entry.privateTableCount = row.privateTableCount;
                    entry.eptPointer = row.eptPointer;
                    domain.domains.append(entry);
                }
                domain.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return domain;
            }
            if (!result.io.ok && result.unsupported)
            {
                domain.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return domain;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_DOMAIN_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_FOUND:
                reason = ks::i18n::sourceText(
                    QStringLiteral("没有这个域，或者范围不在恒等映射窗口里"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_TABLE_FULL:
                reason = ks::i18n::sourceText(
                    QStringLiteral("域已用尽，或该域分叉的页表已达上限"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_EXECUTE_ONLY_UNSUPPORTED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("处理器不支持仅执行的 EPT 叶项，拿不掉读权限"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_UNSUPPORTED:
                reason = ks::i18n::sourceText(
                    QStringLiteral("处理器不提供 EPTP 切换，域建了也切不过去"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_RESIDENT_ACTIVE:
                reason = ks::i18n::sourceText(
                    QStringLiteral("常驻期间不能改域：可能有 VCPU 正在这些表里执行"));
                break;
            case KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("页表分叉失败"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            domain.message = ks::i18n::sourceText(QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return domain;
        }

        // denyDomainWithoutWriteAccess: Unconditionally deny when write access is disabled; do not issue an IOCTL.
        KvmDomainResult denyDomainWithoutWriteAccess(const QString& actionName)
        {
            KvmDomainResult domain;
            domain.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return domain;
        }
    }

    KvmViewResult listViews()
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmView(
            KSWORD_ARK_HVM_VIEW_OP_QUERY,
            0, 0, 0, 0, nullptr, false, false, false, false);
        return toViewResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("读取 EPT 视图")));
    }

    KvmViewResult addView(
        const unsigned long kind,
        const unsigned long long physicalAddress,
        const KvmViewShadowSeed seed,
        const QByteArray& shadow)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("安装 EPT 视图"));
        if (!isWriteAccessEnabled())
        {
            return denyViewWithoutWriteAccess(kActionName);
        }
        // Explicit shadow content must be exactly one page: the driver copies in whole pages; a shorter copy would read uninitialized data.
        QByteArray page;
        if (seed == KvmViewShadowSeed::kExplicit)
        {
            if (shadow.size() != static_cast<int>(KSWORD_ARK_HVM_VIEW_PAGE_BYTES))
            {
                KvmViewResult view;
                view.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：影子内容必须正好是 %2 字节。"))
                    .arg(kActionName)
                    .arg(static_cast<int>(KSWORD_ARK_HVM_VIEW_PAGE_BYTES));
                return view;
            }
            page = shadow;
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmView(
            KSWORD_ARK_HVM_VIEW_OP_ADD,
            kind,
            0,
            0,
            physicalAddress,
            page.isEmpty()
                ? nullptr
                : reinterpret_cast<const unsigned char*>(page.constData()),
            seed == KvmViewShadowSeed::kFromTarget,
            seed == KvmViewShadowSeed::kZero,
            true,
            true);
        return toViewResult(kResult, kActionName);
    }

    KvmViewResult removeView(const unsigned long viewId)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("移除 EPT 视图"));
        if (!isWriteAccessEnabled())
        {
            return denyViewWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmView(
            KSWORD_ARK_HVM_VIEW_OP_REMOVE,
            0, viewId, 0, 0, nullptr, false, false, false, true);
        return toViewResult(kResult, kActionName);
    }

    KvmViewResult clearViews()
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("清空 EPT 视图"));
        if (!isWriteAccessEnabled())
        {
            return denyViewWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmView(
            KSWORD_ARK_HVM_VIEW_OP_CLEAR,
            0, 0, 0, 0, nullptr, false, false, false, true);
        return toViewResult(kResult, kActionName);
    }

    KvmDomainResult listDomains()
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmDomain(
            KSWORD_ARK_HVM_DOMAIN_OP_QUERY,
            0, 0, 0, 0, 0, false);
        return toDomainResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("读取 EPT 执行域")));
    }

    KvmDomainResult createDomain()
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("创建 EPT 执行域"));
        if (!isWriteAccessEnabled())
        {
            return denyDomainWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmDomain(
            KSWORD_ARK_HVM_DOMAIN_OP_CREATE,
            0, 0, 0, 0, 0, true);
        return toDomainResult(kResult, kActionName);
    }

    KvmDomainResult restrictDomain(
        const unsigned long domainIndex,
        const unsigned long long physicalAddress,
        const unsigned long long byteCount,
        const unsigned long deniedAccess)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("收紧 EPT 执行域权限"));
        if (!isWriteAccessEnabled())
        {
            return denyDomainWithoutWriteAccess(kActionName);
        }
        // Domain 0 is the default view; tightening it tightens all domains, and the driver will
        // reject it. Block this here to prevent users from thinking they are modifying a copy.
        if (domainIndex == 0)
        {
            KvmDomainResult domain;
            domain.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：0 号是默认视图，收紧它会影响所有域。"))
                .arg(kActionName);
            return domain;
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmDomain(
            KSWORD_ARK_HVM_DOMAIN_OP_RESTRICT,
            domainIndex,
            0,
            physicalAddress,
            byteCount,
            deniedAccess,
            true);
        return toDomainResult(kResult, kActionName);
    }

    KvmDomainResult resetDomains()
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("清空 EPT 执行域"));
        if (!isWriteAccessEnabled())
        {
            return denyDomainWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmDomain(
            KSWORD_ARK_HVM_DOMAIN_OP_RESET,
            0, 0, 0, 0, 0, true);
        return toDomainResult(kResult, kActionName);
    }

    namespace
    {
        // toMsrPolicyResult: Translate driver policy responses into conclusions ready for UI display.
        KvmMsrPolicyResult toMsrPolicyResult(
            const ksword::ark::HvmMsrPolicyResult& result,
            const QString& actionName)
        {
            KvmMsrPolicyResult policy;
            policy.policyId = result.response.policyId;
            policy.policyCount = result.response.policyCount;
            policy.ok = result.io.ok &&
                result.response.status ==
                    KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
            if (policy.ok)
            {
                const unsigned long kRows =
                    result.response.returnedRows <=
                        KSWORD_ARK_HVM_MAX_MSR_POLICIES
                        ? result.response.returnedRows
                        : KSWORD_ARK_HVM_MAX_MSR_POLICIES;
                for (unsigned long index = 0; index < kRows; ++index)
                {
                    const auto& row = result.response.rows[index];
                    KvmMsrPolicyEntry entry;
                    entry.policyId = row.policyId;
                    entry.msrIndex = row.msrIndex;
                    entry.access = row.access;
                    entry.action = row.action;
                    entry.fakeValue = row.fakeValue;
                    entry.hitCount = row.hitCount;
                    policy.policies.append(entry);
                }
                policy.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return policy;
            }
            if (!result.io.ok && result.unsupported)
            {
                policy.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return policy;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_FOUND:
                reason = ks::i18n::sourceText(QStringLiteral("没有这条策略"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_TABLE_FULL:
                reason = ks::i18n::sourceText(QStringLiteral("策略表已满"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_INDEX_UNCOVERED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "该 MSR 索引不在位图覆盖的两段范围内"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_WRITE_LOG_UNSAFE:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "写方向不支持“记录后放行”：在 VMX root 里重放 WRMSR 没有退路"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_RESIDENT_BUSY:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "常驻期间不能改动策略，请先停止常驻"));
                break;
            case KSWORD_ARK_HVM_MSR_POLICY_STATUS_DUPLICATE:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "该索引与方向上已有一条策略"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return policy;
        }

        // denyMsrPolicyWithoutWriteAccess: Unconditionally denies the policy when write access is disabled; no IOCTL is sent.
        KvmMsrPolicyResult denyMsrPolicyWithoutWriteAccess(
            const QString& actionName)
        {
            KvmMsrPolicyResult policy;
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return policy;
        }
    }

    KvmMsrPolicyResult listMsrPolicies()
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmMsrPolicy(
            KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY,
            0, 0, 0, 0, 0, false);
        return toMsrPolicyResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("读取 MSR 策略")));
    }

    KvmMsrPolicyResult addMsrPolicy(
        const unsigned long msrIndex,
        const unsigned long access,
        const unsigned long action,
        const unsigned long long fakeValue)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("安装 MSR 策略"));
        if (!isWriteAccessEnabled())
        {
            return denyMsrPolicyWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmMsrPolicy(
            KSWORD_ARK_HVM_MSR_POLICY_OP_ADD,
            0,
            msrIndex,
            access,
            action,
            fakeValue,
            true);
        return toMsrPolicyResult(kResult, kActionName);
    }

    KvmMsrPolicyResult removeMsrPolicy(const unsigned long policyId)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("移除 MSR 策略"));
        if (!isWriteAccessEnabled())
        {
            return denyMsrPolicyWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmMsrPolicy(
            KSWORD_ARK_HVM_MSR_POLICY_OP_REMOVE,
            policyId, 0, 0, 0, 0, true);
        return toMsrPolicyResult(kResult, kActionName);
    }

    KvmMsrPolicyResult clearMsrPolicies()
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("清空 MSR 策略"));
        if (!isWriteAccessEnabled())
        {
            return denyMsrPolicyWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmMsrPolicy(
            KSWORD_ARK_HVM_MSR_POLICY_OP_CLEAR,
            0, 0, 0, 0, 0, true);
        return toMsrPolicyResult(kResult, kActionName);
    }

    KvmEventResult readEvents(
        const unsigned long long afterSequence,
        const bool clear)
    {
        KvmEventResult events;
        ksword::ark::DriverClient client;
        const auto kResult = client.queryHvmEvents(
            afterSequence,
            KSWORD_ARK_HVM_MAX_EVENT_ROWS,
            clear);
        events.ok = kResult.io.ok;
        if (!events.ok)
        {
            events.message = kResult.unsupported
                ? ks::i18n::sourceText(
                    QStringLiteral("读取 HVM 事件失败：当前驱动不提供该能力。"))
                : ks::i18n::sourceText(
                    QStringLiteral("读取 HVM 事件失败。"));
            return events;
        }
        events.droppedRows = kResult.response.droppedRows;
        events.availableRows = kResult.response.availableRows;
        events.newestSequence = kResult.response.newestSequence;
        const unsigned long kRows =
            kResult.response.returnedRows <= KSWORD_ARK_HVM_MAX_EVENT_ROWS
                ? kResult.response.returnedRows
                : KSWORD_ARK_HVM_MAX_EVENT_ROWS;
        for (unsigned long index = 0; index < kRows; ++index)
        {
            const auto& row = kResult.response.rows[index];
            KvmEventEntry entry;
            entry.sequence = row.sequence;
            entry.timestamp = row.timestamp;
            entry.guestPhysicalAddress = row.guestPhysicalAddress;
            entry.guestLinearAddress = row.guestLinearAddress;
            entry.guestRip = row.guestRip;
            entry.qualification = row.qualification;
            entry.processorGroup = row.processorGroup;
            entry.processorNumber = row.processorNumber;
            entry.type = row.type;
            entry.exitReason = row.exitReason;
            entry.access = row.access;
            entry.ruleId = row.ruleId;
            entry.status = row.status;
            /* The two registers that can only be captured at the moment of VM-exit in the match context are promoted as-is. */
            entry.guestRsp = row.guestRsp;
            entry.guestCr3 = row.guestCr3;
            entry.watchState = row.watchState;
            entry.eventFlags = row.eventFlags;
            events.events.append(entry);
        }
        return events;
    }

    namespace
    {
        // toCrPolicyResult: Translates the driver response into a conclusion ready for direct UI display.
        KvmCrPolicyResult toCrPolicyResult(
            const ksword::ark::HvmCrPolicyResult& result,
            const QString& actionName)
        {
            KvmCrPolicyResult policy;
            policy.cr0PinnedMask = result.response.cr0PinnedMask;
            policy.cr4PinnedMask = result.response.cr4PinnedMask;
            policy.cr0PinnedValue = result.response.cr0PinnedValue;
            policy.cr4PinnedValue = result.response.cr4PinnedValue;
            policy.refusedWriteCount = result.response.refusedWriteCount;
            policy.cr3SwitchCount = result.response.cr3SwitchCount;
            policy.debugAccessCount = result.response.debugAccessCount;
            policy.trackCr3 = (result.response.flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) != 0;
            policy.interceptDr = (result.response.flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_INTERCEPT_DR) != 0;
            policy.log = (result.response.flags &
                KSWORD_ARK_HVM_CR_POLICY_FLAG_LOG) != 0;
            policy.ok = result.io.ok &&
                result.response.status ==
                    KSWORD_ARK_HVM_CR_POLICY_STATUS_OK;
            if (policy.ok)
            {
                policy.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return policy;
            }
            if (!result.io.ok && result.unsupported)
            {
                policy.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return policy;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_CR_POLICY_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_CR_POLICY_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_CR_POLICY_STATUS_RESIDENT_BUSY:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "掩码在建 VMCS 时消费，常驻期间改动不会生效，已拒绝"));
                break;
            case KSWORD_ARK_HVM_CR_POLICY_STATUS_BIT_NOT_PINNABLE:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "该位被固定位 MSR 强制，钉住它会让每次 VM entry 失败"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return policy;
        }
    }

    KvmCrPolicyResult readCrPolicy()
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmCrPolicy(
            KSWORD_ARK_HVM_CR_POLICY_OP_QUERY,
            0, 0, false, false, false, false);
        return toCrPolicyResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("读取控制寄存器策略")));
    }

    KvmCrPolicyResult applyCrPolicy(
        const unsigned long long cr0PinnedMask,
        const unsigned long long cr4PinnedMask,
        const bool trackCr3,
        const bool interceptDr,
        const bool log)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("配置控制寄存器策略"));
        if (!isWriteAccessEnabled())
        {
            KvmCrPolicyResult policy;
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(kActionName);
            return policy;
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmCrPolicy(
            KSWORD_ARK_HVM_CR_POLICY_OP_SET,
            cr0PinnedMask,
            cr4PinnedMask,
            trackCr3,
            interceptDr,
            log,
            true);
        return toCrPolicyResult(kResult, kActionName);
    }

    KvmCrPolicyResult clearCrPolicy()
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("清除控制寄存器策略"));
        if (!isWriteAccessEnabled())
        {
            KvmCrPolicyResult policy;
            policy.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(kActionName);
            return policy;
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmCrPolicy(
            KSWORD_ARK_HVM_CR_POLICY_OP_CLEAR,
            0, 0, false, false, false, true);
        return toCrPolicyResult(kResult, kActionName);
    }

    namespace
    {
        // toProcessResult: Translate driver process handling responses into conclusions directly displayable in the UI.
        KvmProcessResult toProcessResult(
            const ksword::ark::HvmProcessResult& result,
            const QString& actionName)
        {
            KvmProcessResult disposition;
            disposition.protocolStatus = result.response.status;
            disposition.lastStatus = result.response.lastStatus;
            disposition.rowCount = result.response.rowCount;
            disposition.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_PROCESS_STATUS_OK;
            // The table is refilled on both success and failure: even on failure, the caller must see the current contents;
            // otherwise, a 'table full' rejection would only show a number, making it impossible to determine which entry to remove.
            const unsigned long kRows =
                result.response.returnedRows <=
                    KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS
                    ? result.response.returnedRows
                    : KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS;
            for (unsigned long index = 0; index < kRows; ++index)
            {
                const auto& row = result.response.rows[index];
                KvmProcessDispositionEntry entry;
                entry.processId = row.processId;
                entry.disposition = row.disposition;
                entry.hierarchyIndex = row.hierarchyIndex;
                entry.directoryBase = row.directoryBase;
                entry.guestPhysicalAddress = row.guestPhysicalAddress;
                entry.guestLinearAddress = row.guestLinearAddress;
                entry.interceptCount = row.interceptCount;
                disposition.dispositions.append(entry);
            }
            if (disposition.ok)
            {
                disposition.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return disposition;
            }
            if (!result.io.ok && result.unsupported)
            {
                disposition.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return disposition;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST:
                reason = ks::i18n::sourceText(QStringLiteral("请求不合法"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_CONFIRMATION_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral("需要显式确认"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "安装处置要求常驻停着，请先停止常驻"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "找不到该 PID 对应的进程"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_TABLE_FULL:
                reason = ks::i18n::sourceText(QStringLiteral("处置表已满"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND:
                reason = ks::i18n::sourceText(QStringLiteral("没有这条处置"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_ALREADY_ARMED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "该进程已经装着一条处置"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "要求先开启 CR3 追踪：处置靠地址空间认目标，没有它认不出来"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "要求 EPTP 切换后端：受限层次靠切指针生效"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "目标线性地址翻译失败，那一页此刻不在内存里"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "目标受保护，驱动拒绝对它下处置"));
                break;
            case KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            disposition.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return disposition;
        }

        // denyProcessWithoutWriteAccess: Unconditionally deny when write access is disabled; do not issue an IOCTL.
        KvmProcessResult denyProcessWithoutWriteAccess(const QString& actionName)
        {
            KvmProcessResult disposition;
            disposition.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return disposition;
        }

        // toInjectResult: Translates the driver injection response into a conclusion ready for direct UI display.
        KvmInjectResult toInjectResult(
            const ksword::ark::HvmInjectResult& result,
            const QString& actionName)
        {
            KvmInjectResult injection;
            injection.protocolStatus = result.response.status;
            injection.lastStatus = result.response.lastStatus;
            injection.rowCount = result.response.rowCount;
            injection.ok = result.io.ok &&
                result.response.status == KSWORD_ARK_HVM_INJECT_STATUS_OK;
            const unsigned long kRows =
                result.response.returnedRows <= KSWORD_ARK_HVM_MAX_INJECTIONS
                    ? result.response.returnedRows
                    : KSWORD_ARK_HVM_MAX_INJECTIONS;
            for (unsigned long index = 0; index < kRows; ++index)
            {
                const auto& row = result.response.rows[index];
                KvmInjectionEntry entry;
                entry.processId = row.processId;
                entry.payloadBytes = row.payloadBytes;
                entry.directoryBase = row.directoryBase;
                entry.guestLinearAddress = row.guestLinearAddress;
                entry.guestPhysicalAddress = row.guestPhysicalAddress;
                entry.caveOffset = row.caveOffset;
                entry.caveBytes = row.caveBytes;
                entry.executionCount = row.executionCount;
                entry.viewId = row.viewId;
                entry.caveFiller = row.caveFiller;
                injection.injections.append(entry);
            }
            if (injection.ok)
            {
                injection.message = ks::i18n::sourceText(
                    QStringLiteral("%1 成功。")).arg(actionName);
                return injection;
            }
            if (!result.io.ok && result.unsupported)
            {
                injection.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：当前驱动不提供该能力。"))
                    .arg(actionName);
                return injection;
            }
            QString reason;
            switch (result.response.status)
            {
            case KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST:
                reason = ks::i18n::sourceText(QStringLiteral("请求不合法"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_NOT_PREPARED:
                reason = ks::i18n::sourceText(QStringLiteral("资源尚未准备"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "安装注入要求常驻停着，请先停止常驻"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_PROCESS_LOOKUP_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "找不到该 PID 对应的进程"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "目标线性地址翻译失败，那一页此刻不在内存里"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_TABLE_FULL:
                reason = ks::i18n::sourceText(QStringLiteral("注入表已满"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_NOT_FOUND:
                reason = ks::i18n::sourceText(QStringLiteral("没有这条注入"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_ALREADY_ARMED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "该进程已经装着一条注入"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_PROTECTED_TARGET:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "目标受保护，驱动拒绝对它注入"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_CR3_TRACKING_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "要求先开启 CR3 追踪：注入靠地址空间认目标，没有它认不出来"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_EPTP_SWITCH_REQUIRED:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "要求 EPTP 切换后端：执行视图靠切指针生效"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "这一页里找不到足够大的空隙放外壳，换一页再试"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED:
                reason = ks::i18n::sourceText(QStringLiteral("执行视图安装失败"));
                break;
            case KSWORD_ARK_HVM_INJECT_STATUS_PAGE_NOT_EXECUTABLE:
                reason = ks::i18n::sourceText(QStringLiteral(
                    "这一页在目标里不可执行，劫持它不会被触发"));
                break;
            default:
                reason = ks::i18n::sourceText(QStringLiteral("协议状态 %1"))
                    .arg(result.response.status);
                break;
            }
            injection.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：%2。"))
                .arg(actionName)
                .arg(reason);
            return injection;
        }

        // denyInjectWithoutWriteAccess: uniformly deny injection when write access is disabled, without sending IOCTL.
        KvmInjectResult denyInjectWithoutWriteAccess(const QString& actionName)
        {
            KvmInjectResult injection;
            injection.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：R-1 写权限未开启。"))
                .arg(actionName);
            return injection;
        }
    }

    KvmProcessResult listProcessDispositions()
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmProcess(
            KSWORD_ARK_HVM_PROCESS_OP_QUERY, 0, 0, false);
        return toProcessResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("读取 R-1 进程处置")));
    }

    KvmProcessResult freezeProcess(
        const unsigned long processId,
        const unsigned long long guestLinearAddress)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("冻结进程"));
        if (!isWriteAccessEnabled())
        {
            return denyProcessWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmProcess(
            KSWORD_ARK_HVM_PROCESS_OP_FREEZE,
            processId,
            guestLinearAddress,
            true);
        return toProcessResult(kResult, kActionName);
    }

    KvmProcessResult terminateProcess(
        const unsigned long processId,
        const unsigned long long guestLinearAddress)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("结束进程"));
        if (!isWriteAccessEnabled())
        {
            return denyProcessWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmProcess(
            KSWORD_ARK_HVM_PROCESS_OP_TERMINATE,
            processId,
            guestLinearAddress,
            true);
        return toProcessResult(kResult, kActionName);
    }

    KvmProcessResult releaseProcessDisposition(const unsigned long processId)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("撤销进程处置"));
        if (!isWriteAccessEnabled())
        {
            return denyProcessWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmProcess(
            KSWORD_ARK_HVM_PROCESS_OP_RELEASE, processId, 0, true);
        return toProcessResult(kResult, kActionName);
    }

    KvmProcessResult releaseAllProcessDispositions()
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("撤销全部进程处置"));
        if (!isWriteAccessEnabled())
        {
            return denyProcessWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmProcess(
            KSWORD_ARK_HVM_PROCESS_OP_RELEASE_ALL, 0, 0, true);
        return toProcessResult(kResult, kActionName);
    }

    KvmInjectResult listInjections()
    {
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmInject(
            KSWORD_ARK_HVM_INJECT_OP_QUERY, 0, 0, 0, 0, nullptr, 0, false);
        return toInjectResult(
            kResult,
            ks::i18n::sourceText(QStringLiteral("读取 R-1 注入")));
    }

    KvmInjectResult injectDll(
        const unsigned long processId,
        const unsigned long long guestLinearAddress,
        const unsigned long long loadLibraryAddress,
        const QString& dllPath)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("注入 DLL"));
        if (!isWriteAccessEnabled())
        {
            return denyInjectWithoutWriteAccess(kActionName);
        }
        // The payload is a UTF-16 path without a trailing null: the driver pads with zeros, and the padded zero serves as the terminator.
        // QString is already UTF-16; no transcoding is performed here, so there is no path for transcoding failure.
        const int kPathBytes = dllPath.size() * static_cast<int>(sizeof(char16_t));
        if (dllPath.isEmpty() ||
            kPathBytes > static_cast<int>(
                KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES - sizeof(char16_t)))
        {
            KvmInjectResult injection;
            injection.message = ks::i18n::sourceText(
                QStringLiteral("%1 失败：DLL 路径为空或超出载荷上限。"))
                .arg(kActionName);
            return injection;
        }
        // Resolve LoadLibraryW to 0 locally: kernel32 ASLR is re-randomized per process start, not per process,
        // so the resolved address for this process holds for the target. If resolution fails, state it
        // explicitly; passing 0 to the driver only returns 'invalid request', failing to point to this step.
        unsigned long long resolvedLoadLibrary = loadLibraryAddress;
        if (resolvedLoadLibrary == 0ULL)
        {
            const HMODULE kKernel32 = GetModuleHandleW(L"kernel32.dll");
            const FARPROC kResolved = kKernel32 != nullptr
                ? GetProcAddress(kKernel32, "LoadLibraryW")
                : nullptr;
            if (kResolved == nullptr)
            {
                KvmInjectResult injection;
                injection.message = ks::i18n::sourceText(
                    QStringLiteral("%1 失败：无法就地解析 LoadLibraryW。"))
                    .arg(kActionName);
                return injection;
            }
            resolvedLoadLibrary =
                static_cast<unsigned long long>(
                    reinterpret_cast<ULONG_PTR>(kResolved));
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmInject(
            KSWORD_ARK_HVM_INJECT_OP_ARM,
            processId,
            KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH,
            guestLinearAddress,
            resolvedLoadLibrary,
            reinterpret_cast<const unsigned char*>(dllPath.utf16()),
            static_cast<unsigned long>(kPathBytes),
            true);
        return toInjectResult(kResult, kActionName);
    }

    KvmInjectResult releaseInjection(const unsigned long processId)
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("撤销进程注入"));
        if (!isWriteAccessEnabled())
        {
            return denyInjectWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmInject(
            KSWORD_ARK_HVM_INJECT_OP_RELEASE,
            processId, 0, 0, 0, nullptr, 0, true);
        return toInjectResult(kResult, kActionName);
    }

    KvmInjectResult releaseAllInjections()
    {
        const QString kActionName =
            ks::i18n::sourceText(QStringLiteral("撤销全部 R-1 注入"));
        if (!isWriteAccessEnabled())
        {
            return denyInjectWithoutWriteAccess(kActionName);
        }
        ksword::ark::DriverClient client;
        const auto kResult = client.controlHvmInject(
            KSWORD_ARK_HVM_INJECT_OP_RELEASE_ALL,
            0, 0, 0, 0, nullptr, 0, true);
        return toInjectResult(kResult, kActionName);
    }
}
