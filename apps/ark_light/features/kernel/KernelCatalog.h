#pragma once

#include "KernelModel.h"

#include <vector>

namespace ksword::features::kernel {

// getKernelFeatureDescriptors returns every retained kernel feature entry from
// the original KernelDock. There is no input; processing concatenates the
// per-feature descriptor files in UI order; output is consumed by KernelPage and
// by any future module registry integration.
std::vector<KernelFeatureDescriptor> getKernelFeatureDescriptors();

} // namespace Ksword::Features::Kernel
