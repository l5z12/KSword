#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createDriverStatusDescriptor returns metadata for the retained "Driver Status" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createDriverStatusDescriptor();

} // namespace Ksword::Features::Kernel
