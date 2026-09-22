#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createDynDataDescriptor returns metadata for the retained "dynamic offset" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createDynDataDescriptor();

} // namespace Ksword::Features::Kernel
