#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createAtomTableDescriptor returns metadata for the retained "atom table traversal" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createAtomTableDescriptor();

} // namespace Ksword::Features::Kernel
