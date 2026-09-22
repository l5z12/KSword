#include "KernelNamedPipeFeature.h"

namespace ksword::features::kernel {

KernelFeatureDescriptor createNamedPipeDescriptor() {
    // The descriptor is intentionally pure data. Driver calls and UI controls
    // are kept out of this feature file so parallel sessions can wire them
    // through KernelFacade and KernelPage without changing this ownership.
    KernelFeatureDescriptor descriptor;
    descriptor.id = KernelFeatureId::kNamedPipe;
    descriptor.title = L"命名管道";
    descriptor.category = L"对象命名空间";
    descriptor.summary = L"保留命名管道页入口：枚举 NT 对象命名空间中的 NamedPipe 相关对象。";
    descriptor.backend = KernelFeatureBackend::kUserModeNative;
    descriptor.requiresAdministrator = false;
    descriptor.mayModifyKernelState = false;
    return descriptor;
}

} // namespace Ksword::Features::Kernel
