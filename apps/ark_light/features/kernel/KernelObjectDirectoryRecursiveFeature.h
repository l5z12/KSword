#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createObjectDirectoryRecursiveDescriptor returns metadata for the retained 'directory recursion' entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createObjectDirectoryRecursiveDescriptor();

} // namespace Ksword::Features::Kernel
