#include "KernelCommunicationEndpointFeature.h"

namespace ksword::features::kernel {

KernelFeatureDescriptor createCommunicationEndpointDescriptor() {
    // The descriptor is intentionally pure data. Driver calls and UI controls
    // are kept out of this feature file so parallel sessions can wire them
    // through KernelFacade and KernelPage without changing this ownership.
    KernelFeatureDescriptor descriptor;
    descriptor.id = KernelFeatureId::kCommunicationEndpoint;
    descriptor.title = L"通信端点";
    descriptor.category = L"对象命名空间";
    descriptor.summary = L"保留通信端点入口：ALPC/Port/Section/Event 等端点型对象聚合视图。";
    descriptor.backend = KernelFeatureBackend::kHybrid;
    descriptor.requiresAdministrator = false;
    descriptor.mayModifyKernelState = false;
    return descriptor;
}

} // namespace Ksword::Features::Kernel
