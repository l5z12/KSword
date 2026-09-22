#include "StartupFeature.h"

#include "StartupView.h"

namespace ksword::features::startup {

HWND createStartupFeaturePage(HWND parent, const RECT& bounds) {
    return createStartupFeatureView(parent, bounds);
}

} // namespace Ksword::Features::Startup
