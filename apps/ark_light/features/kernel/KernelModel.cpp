#include "KernelModel.h"

namespace ksword::features::kernel {

std::wstring toDisplayName(const KernelFeatureId id) {
    // The switch is deliberately exhaustive for current retained KernelDock
    // entries. Unknown future values fall through to a safe generic label.
    switch (id) {
    case KernelFeatureId::kObjectNamespaceOverview: return L"对象命名空间";
    case KernelFeatureId::kObjectDirectoryRecursive: return L"目录递归";
    case KernelFeatureId::kNamedPipe: return L"命名管道";
    case KernelFeatureId::kBaseNamedObjects: return L"BaseNamedObjects";
    case KernelFeatureId::kSymbolicLink: return L"符号链接";
    case KernelFeatureId::kDeviceDriverObjects: return L"设备与驱动对象";
    case KernelFeatureId::kObjectTypeMatrix: return L"对象类型矩阵";
    case KernelFeatureId::kCommunicationEndpoint: return L"通信端点";
    case KernelFeatureId::kAtomTable: return L"原子表遍历";
    case KernelFeatureId::kNtQueryLegacy: return L"历史 NtQuery";
    case KernelFeatureId::kSsdt: return L"SSDT 遍历";
    case KernelFeatureId::kShadowSsdt: return L"SSSDT 解析";
    case KernelFeatureId::kInlineHook: return L"Inline Hook 检测 & 摘除";
    case KernelFeatureId::kIatEatHook: return L"IAT/EAT 钩子检测";
    case KernelFeatureId::kDynData: return L"动态偏移";
    case KernelFeatureId::kDriverStatus: return L"驱动状态";
    case KernelFeatureId::kCallbackIntercept: return L"驱动回调";
    case KernelFeatureId::kCallbackEnumeration: return L"回调遍历";
    case KernelFeatureId::kKernelExecutableMemory: return L"内核可执行内存";
    case KernelFeatureId::kKernelMemoryEvidence: return L"内核内存证据";
    case KernelFeatureId::kProcessCrossView: return L"进程 CrossView";
    case KernelFeatureId::kThreadCrossView: return L"线程 CrossView";
    case KernelFeatureId::kDriverIntegrity: return L"驱动完整性";
    case KernelFeatureId::kKernelCpuIntegrity: return L"CPU/IDT 完整性";
    case KernelFeatureId::kCpuHardwareSnapshot: return L"CPU 硬件快照";
    case KernelFeatureId::kPhysicalMemoryLayout: return L"物理内存布局";
    case KernelFeatureId::kMutationAudit: return L"内核修改审计";
    case KernelFeatureId::kKeyboardHotkeys: return L"键盘热键枚举";
    case KernelFeatureId::kKeyboardHooks: return L"键盘钩子枚举";
    case KernelFeatureId::kDynDataCapabilities: return L"DynData 能力";
    case KernelFeatureId::kMinifilterBypassPids: return L"Minifilter 放行 PID";
    case KernelFeatureId::kKernelTimerDpc: return L"KTIMER/DPC";
    case KernelFeatureId::kIoctlRegistry: return L"IOCTL 派遣表";
    case KernelFeatureId::kPdbProfileStatus: return L"PDB Profile 状态";
    case KernelFeatureId::kCidTableSummary: return L"CID 表摘要";
    case KernelFeatureId::kIpcSummary: return L"IPC 汇总";
    case KernelFeatureId::kHookAuditSummary: return L"Hook 审计摘要";
    default: return L"未知内核功能";
    }
}

std::wstring backendToDisplayName(const KernelFeatureBackend backend) {
    // Keep labels short because this text is shown in the feature list and in
    // the detail panel. The enum remains the source of truth for routing.
    switch (backend) {
    case KernelFeatureBackend::kUserModeNative: return L"R3 Native";
    case KernelFeatureBackend::kArkDriverClient: return L"ArkDriverClient";
    case KernelFeatureBackend::kHybrid: return L"R3 + ArkDriverClient";
    default: return L"Unknown";
    }
}

} // namespace Ksword::Features::Kernel
