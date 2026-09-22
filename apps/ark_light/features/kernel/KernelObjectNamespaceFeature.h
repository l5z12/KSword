#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createObjectNamespaceDescriptor returns metadata for the retained "object namespace" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createObjectNamespaceDescriptor();

} // namespace Ksword::Features::Kernel
