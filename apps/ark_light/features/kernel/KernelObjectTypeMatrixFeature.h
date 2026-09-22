#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createObjectTypeMatrixDescriptor returns metadata for the retained "object type matrix" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createObjectTypeMatrixDescriptor();

} // namespace Ksword::Features::Kernel
