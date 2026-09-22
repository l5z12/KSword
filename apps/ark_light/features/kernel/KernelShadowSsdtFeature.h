#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createShadowSsdtDescriptor returns metadata for the retained "SSSDT parsing" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createShadowSsdtDescriptor();

} // namespace Ksword::Features::Kernel
