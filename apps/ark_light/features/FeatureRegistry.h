#pragma once

#include "../ui/ModuleDescriptor.h"

#include <vector>

namespace ksword::features {

// getModuleDescriptors returns every first-stage module exposed by the Win32
// shell. There is no input; processing returns static descriptors for docked
// module pages; output is copied by the main window.
std::vector<ksword::ui::ModuleDescriptor> getModuleDescriptors();

} // namespace Ksword::Features
