#include "KernelObjectTypeMatrixFeature.h"

namespace ksword::features::kernel {

KernelFeatureDescriptor createObjectTypeMatrixDescriptor() {
    // The descriptor is intentionally pure data. Driver calls and UI controls
    // are kept out of this feature file so parallel sessions can wire them
    // through KernelFacade and KernelPage without changing this ownership.
    KernelFeatureDescriptor descriptor;
    descriptor.id = KernelFeatureId::kObjectTypeMatrix;
    descriptor.title = L"对象类型矩阵";
    descriptor.category = L"对象命名空间";
    descriptor.summary = L"保留对象类型矩阵入口：NtQueryObject ObjectTypesInformation 只读类型统计。";
    descriptor.backend = KernelFeatureBackend::kUserModeNative;
    descriptor.requiresAdministrator = false;
    descriptor.mayModifyKernelState = false;
    return descriptor;
}

} // namespace Ksword::Features::Kernel
