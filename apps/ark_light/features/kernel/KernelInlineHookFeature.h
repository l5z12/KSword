#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createInlineHookDescriptor returns metadata for the retained "Inline Hook Detection & Removal" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createInlineHookDescriptor();

} // namespace Ksword::Features::Kernel
