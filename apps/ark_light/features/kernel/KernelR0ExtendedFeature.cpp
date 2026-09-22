#include "KernelR0ExtendedFeature.h"

namespace ksword::features::kernel {
namespace {

// descriptor creates one ArkDriverClient read-only feature descriptor. Inputs
// are the feature id, title, category, and summary; output is catalog metadata
// only, with no driver calls or UI ownership.
KernelFeatureDescriptor descriptor(
    const KernelFeatureId id,
    const std::wstring& title,
    const std::wstring& category,
    const std::wstring& summary) {
    KernelFeatureDescriptor descriptor;
    descriptor.id = id;
    descriptor.title = title;
    descriptor.category = category;
    descriptor.summary = summary;
    descriptor.backend = KernelFeatureBackend::kArkDriverClient;
    descriptor.requiresAdministrator = true;
    descriptor.mayModifyKernelState = false;
    return descriptor;
}

} // namespace

std::vector<KernelFeatureDescriptor> createR0ExtendedDescriptors() {
    // These entries expose existing ArkDriverClient read-only protocol paths in
    // KernelDock instead of leaving them reachable only from other legacy docks.
    return {
        descriptor(
            KernelFeatureId::kKernelExecutableMemory,
            L"内核可执行内存",
            L"内核信息",
            L"通过 ArkDriverClient 扫描 R0 可执行内核页、页权限和模块归属。"),
        descriptor(
            KernelFeatureId::kKernelMemoryEvidence,
            L"内核内存证据",
            L"内核信息",
            L"通过 ArkDriverClient 聚合内核内存风险证据、BigPool、模块和样本摘要。"),
        descriptor(
            KernelFeatureId::kProcessCrossView,
            L"进程 CrossView",
            L"内核信息",
            L"通过 ArkDriverClient 比对 EPROCESS ActiveProcessLinks/CID 等来源。"),
        descriptor(
            KernelFeatureId::kThreadCrossView,
            L"线程 CrossView",
            L"内核信息",
            L"通过 ArkDriverClient 比对 ETHREAD/KTHREAD/CID 等来源。"),
        descriptor(
            KernelFeatureId::kDriverIntegrity,
            L"驱动完整性",
            L"驱动诊断",
            L"通过 ArkDriverClient 聚合 DriverObject/LDR/FastIo/MajorFunction 完整性证据。"),
        descriptor(
            KernelFeatureId::kKernelCpuIntegrity,
            L"CPU/IDT 完整性",
            L"驱动诊断",
            L"通过 ArkDriverClient 查询 CPU、IDT、描述符表和相关完整性证据。"),
        descriptor(
            KernelFeatureId::kCpuHardwareSnapshot,
            L"CPU 硬件快照",
            L"硬件",
            L"通过 ArkDriverClient 读取 R0 CPUID/处理器数量与特征位摘要。"),
        descriptor(
            KernelFeatureId::kPhysicalMemoryLayout,
            L"物理内存布局",
            L"硬件",
            L"通过 ArkDriverClient 读取 MmGetPhysicalMemoryRanges 聚合物理内存范围。"),
        descriptor(
            KernelFeatureId::kMutationAudit,
            L"内核修改审计",
            L"驱动诊断",
            L"通过 ArkDriverClient 只读展示 mutation transaction 审计环。"),
        descriptor(
            KernelFeatureId::kKeyboardHotkeys,
            L"键盘热键枚举",
            L"内核信息",
            L"通过 ArkDriverClient 枚举 win32k RegisterHotKey 内部表。"),
        descriptor(
            KernelFeatureId::kKeyboardHooks,
            L"键盘钩子枚举",
            L"内核信息",
            L"通过 ArkDriverClient 枚举 win32k WH_KEYBOARD/WH_KEYBOARD_LL 钩子链。"),
        descriptor(
            KernelFeatureId::kDynDataCapabilities,
            L"DynData 能力",
            L"驱动诊断",
            L"通过 ArkDriverClient 查询轻量 DynData capability mask 与状态。"),
        descriptor(
            KernelFeatureId::kPdbProfileStatus,
            L"PDB Profile 状态",
            L"驱动诊断",
            L"只读汇总 DynData v3/v4 profile、模块命中、capability group 和缺字段降级状态。"),
        descriptor(
            KernelFeatureId::kCidTableSummary,
            L"CID 表摘要",
            L"内核信息",
            L"只读枚举 PspCidTable 采样行，并与进程/线程 CrossView 的 source/anomaly 证据对齐。"),
        descriptor(
            KernelFeatureId::kIpcSummary,
            L"IPC 汇总",
            L"内核信息",
            L"只读汇总 ALPC、NamedPipe、Mailslot、SMB 相关 IPC 审计入口和当前 R0 降级状态。"),
        descriptor(
            KernelFeatureId::kHookAuditSummary,
            L"Hook 审计摘要",
            L"驱动诊断",
            L"只读汇总 callback、SSDT/ShadowSSDT、Inline Hook、IAT/EAT 的审计入口与 capability 状态。"),
        descriptor(
            KernelFeatureId::kMinifilterBypassPids,
            L"Minifilter 放行 PID",
            L"回调",
            L"通过 ArkDriverClient 查询 R0 minifilter bypass PID 白名单。"),
        descriptor(
            KernelFeatureId::kKernelTimerDpc,
            L"KTIMER/DPC",
            L"内核信息",
            L"通过 ArkDriverClient 只读枚举每 CPU TimerTable 中的 KTIMER/KDPC 快照与完整性诊断。"),
        descriptor(
            KernelFeatureId::kIoctlRegistry,
            L"IOCTL 派遣表",
            L"驱动诊断",
            L"通过 ArkDriverClient 查询 KswordARK 统一 IOCTL 派遣注册表及 capability 门槛。"),
        descriptor(
            KernelFeatureId::kWorkQueueThreads,
            L"内核工作队列",
            L"内核信息",
            L"通过 ArkDriverClient 只读枚举 ExWorkerQueue 工作项、例程地址与承载线程。"),
        descriptor(
            KernelFeatureId::kSlatIommuAudit,
            L"SLAT / IOMMU 审计",
            L"内核信息",
            L"通过 ArkDriverClient 读取 EPT/NPT 跨视图探针与 DMAR/IVRS 固件证据。"),
        descriptor(
            KernelFeatureId::kHvmStatus,
            L"VT-x / EPT 状态",
            L"内核信息",
            L"通过 ArkDriverClient 只读查询虚拟化能力、接管状态与 EPT 运行时代次。"),
        descriptor(
            KernelFeatureId::kHvmEvents,
            L"VM-exit 事件",
            L"内核信息",
            L"通过 ArkDriverClient 拉取 R0 采集的 VM-exit 事件环，不改变接管状态。"),
        descriptor(
            KernelFeatureId::kDriverDispatchTable,
            L"驱动派遣表",
            L"驱动诊断",
            L"通过 ArkDriverClient 只读查询任意 DriverObject 的 MajorFunction 当前值与基线。"),
        descriptor(
            KernelFeatureId::kDriverImageFields,
            L"驱动镜像字段",
            L"驱动诊断",
            L"通过 ArkDriverClient 只读查询 LDR 镜像条目的名称、路径、基址与标志。"),
        descriptor(
            KernelFeatureId::kDriverCommunication,
            L"驱动通信端点",
            L"驱动诊断",
            L"通过 ArkDriverClient 只读查询目标驱动的设备/符号链接通信面与当前管控状态。"),
        descriptor(
            KernelFeatureId::kPlatformAudit,
            L"平台审计",
            L"驱动诊断",
            L"通过 ArkDriverClient 只读读取平台安全审计条目与其证据来源。"),
        descriptor(
            KernelFeatureId::kSystemTimeState,
            L"系统计时状态",
            L"硬件",
            L"通过 ArkDriverClient 只读查询性能计数器后端、倍率接管状态与计时槽地址。"),
        descriptor(
            KernelFeatureId::kI8042Audit,
            L"键鼠端点审计",
            L"硬件",
            L"通过 ArkDriverClient 只读枚举 i8042 键鼠过滤回调、承载模块与判定结果。"),
        descriptor(
            KernelFeatureId::kPiDdbCache,
            L"PiDDB 缓存",
            L"驱动诊断",
            L"通过 ArkDriverClient 只读枚举 PiDDBCacheTable 中的驱动加载记录。"),
        descriptor(
            KernelFeatureId::kRawDiskSectors,
            L"物理磁盘扇区",
            L"硬件",
            L"通过 ArkDriverClient 按扇区对齐读取物理磁盘原始字节，用过滤框填盘号、起点填偏移。"),
        descriptor(
            KernelFeatureId::kNetworkTrafficPackets,
            L"网络逐包捕获",
            L"内核信息",
            L"通过 ArkDriverClient 读取 R0 WFP 逐包环，无需 Npcap；抓包开关在下一版接入。")
    };
}

} // namespace Ksword::Features::Kernel
