#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createCallbackEnumerationDescriptor returns metadata for the retained "callback traversal" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createCallbackEnumerationDescriptor();

} // namespace Ksword::Features::Kernel
