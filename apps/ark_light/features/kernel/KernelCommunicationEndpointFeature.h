#pragma once

#include "KernelModel.h"

namespace ksword::features::kernel {

// createCommunicationEndpointDescriptor returns metadata for the retained "Communication Endpoint" entry.
// There is no input; processing fills a descriptor matching the original
// KernelDock entry; output is consumed by the lightweight Win32 catalog.
KernelFeatureDescriptor createCommunicationEndpointDescriptor();

} // namespace Ksword::Features::Kernel
