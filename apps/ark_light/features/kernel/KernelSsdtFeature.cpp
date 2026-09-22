#include "KernelSsdtFeature.h"

namespace ksword::features::kernel {

KernelFeatureDescriptor createSsdtDescriptor() {
    // The descriptor is intentionally pure data. Driver calls and UI controls
    // are kept out of this feature file so parallel sessions can wire them
    // through KernelFacade and KernelPage without changing this ownership.
    KernelFeatureDescriptor descriptor;
    descriptor.id = KernelFeatureId::kSsdt;
    descriptor.title = L"SSDT 遍历";
    descriptor.category = L"系统调用";
    descriptor.summary = L"保留 SSDT 遍历入口：通过 ArkDriverClient 查询 R0 SSDT/ntoskrnl 服务索引快照。";
    descriptor.backend = KernelFeatureBackend::kArkDriverClient;
    descriptor.requiresAdministrator = true;
    descriptor.mayModifyKernelState = false;
    return descriptor;
}

} // namespace Ksword::Features::Kernel
