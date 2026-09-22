#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createIatEatHookDescriptor returns metadata for the retained "IAT/EAT hook detection" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createIatEatHookDescriptor();

} // namespace Ksword::Features::Kernel
