#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createSymbolicLinkDescriptor returns metadata for the retained "symbolic link" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createSymbolicLinkDescriptor();

} // namespace Ksword::Features::Kernel
