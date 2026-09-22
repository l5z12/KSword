#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createCallbackInterceptDescriptor returns metadata for the retained "driver callback" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createCallbackInterceptDescriptor();

} // namespace Ksword::Features::Kernel
