#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createDeviceDriverObjectsDescriptor returns metadata for the retained "Device and Driver Objects" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createDeviceDriverObjectsDescriptor();

} // namespace Ksword::Features::Kernel
