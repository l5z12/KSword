#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createNamedPipeDescriptor returns metadata for the retained "Named Pipe" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createNamedPipeDescriptor();

} // namespace Ksword::Features::Kernel
