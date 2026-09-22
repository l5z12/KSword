#include "KernelDynDataFeature.h"

namespace ksword::features::kernel {

KernelFeatureDescriptor createDynDataDescriptor() {
    // The descriptor is intentionally pure data. Driver calls and UI controls
    // are kept out of this feature file so parallel sessions can wire them
    // through KernelFacade and KernelPage without changing this ownership.
    KernelFeatureDescriptor descriptor;
    descriptor.id = KernelFeatureId::kDynData;
    descriptor.title = L"动态偏移";
    descriptor.category = L"驱动诊断";
    descriptor.summary = L"保留 DynData 状态、字段、capability 和本地 PDB profile 应用入口。";
    descriptor.backend = KernelFeatureBackend::kArkDriverClient;
    descriptor.requiresAdministrator = true;
    descriptor.mayModifyKernelState = false;
    return descriptor;
}

} // namespace Ksword::Features::Kernel
