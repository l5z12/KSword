#include "ServiceFeature.h"

#include "ServiceView.h"

namespace ksword::features::service {

HWND createServiceFeaturePage(HWND parent, const RECT& bounds) {
    return createServiceView(parent, bounds);
}

} // namespace Ksword::Features::Service
