#include "KernelCatalog.h"

#include "KernelAtomTableFeature.h"
#include "KernelBaseNamedObjectsFeature.h"
#include "KernelCallbackEnumerationFeature.h"
#include "KernelCallbackInterceptFeature.h"
#include "KernelCommunicationEndpointFeature.h"
#include "KernelDeviceDriverObjectsFeature.h"
#include "KernelDriverStatusFeature.h"
#include "KernelDynDataFeature.h"
#include "KernelIatEatHookFeature.h"
#include "KernelInlineHookFeature.h"
#include "KernelNamedPipeFeature.h"
#include "KernelNtQueryLegacyFeature.h"
#include "KernelObjectDirectoryRecursiveFeature.h"
#include "KernelObjectNamespaceFeature.h"
#include "KernelObjectTypeMatrixFeature.h"
#include "KernelR0ExtendedFeature.h"
#include "KernelShadowSsdtFeature.h"
#include "KernelSsdtFeature.h"
#include "KernelSymbolicLinkFeature.h"

namespace ksword::features::kernel {

std::vector<KernelFeatureDescriptor> getKernelFeatureDescriptors() {
    // The order mirrors the original KernelDock tab order and nested object
    // namespace pages. Each entry comes from its own file so future sessions can
    // replace one feature implementation without touching the catalog shape.
    std::vector<KernelFeatureDescriptor> descriptors = {
        createObjectNamespaceDescriptor(),
        createObjectDirectoryRecursiveDescriptor(),
        createNamedPipeDescriptor(),
        createBaseNamedObjectsDescriptor(),
        createSymbolicLinkDescriptor(),
        createDeviceDriverObjectsDescriptor(),
        createObjectTypeMatrixDescriptor(),
        createCommunicationEndpointDescriptor(),
        createAtomTableDescriptor(),
        createNtQueryLegacyDescriptor(),
        createSsdtDescriptor(),
        createShadowSsdtDescriptor(),
        createInlineHookDescriptor(),
        createIatEatHookDescriptor(),
        createDynDataDescriptor(),
        createDriverStatusDescriptor(),
        createCallbackInterceptDescriptor(),
        createCallbackEnumerationDescriptor()
    };

    // Append the R0 extended read-only pages after the classic KernelDock
    // entries. Input is the static metadata from KernelR0ExtendedFeature;
    // processing keeps the catalog ordering stable; return value is the full
    // feature list consumed by KernelPage tab population and query dispatch.
    std::vector<KernelFeatureDescriptor> extended = createR0ExtendedDescriptors();
    descriptors.insert(descriptors.end(), extended.begin(), extended.end());
    return descriptors;
}

} // namespace Ksword::Features::Kernel
