#include "KernelCallbackEnumerationFeature.h"

namespace ksword::features::kernel {

KernelFeatureDescriptor createCallbackEnumerationDescriptor() {
    // The descriptor is intentionally pure data. Driver calls and UI controls
    // are kept out of this feature file so parallel sessions can wire them
    // through KernelFacade and KernelPage without changing this ownership.
    KernelFeatureDescriptor descriptor;
    descriptor.id = KernelFeatureId::kCallbackEnumeration;
    descriptor.title = L"回调遍历";
    descriptor.category = L"回调";
    descriptor.summary = L"保留回调遍历和外部回调移除入口；移除动作必须经 facade 和 UI 双重确认。";
    descriptor.backend = KernelFeatureBackend::kArkDriverClient;
    descriptor.requiresAdministrator = true;
    descriptor.mayModifyKernelState = true;
    return descriptor;
}

} // namespace Ksword::Features::Kernel
