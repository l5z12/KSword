#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createSsdtDescriptor returns metadata for the retained "SSDT traversal" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createSsdtDescriptor();

} // namespace Ksword::Features::Kernel
