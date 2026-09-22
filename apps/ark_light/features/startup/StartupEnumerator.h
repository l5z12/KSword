#pragma once

#include "StartupModel.h"

namespace ksword::features::startup {

// enumerateStartupEntries returns every startup surface owned by this module.
// There is no input; processing queries registry Run/RunOnce, Startup folders,
// services, and the scheduled-task facade; output is a complete snapshot.
StartupEnumerationResult enumerateStartupEntries();

} // namespace Ksword::Features::Startup
