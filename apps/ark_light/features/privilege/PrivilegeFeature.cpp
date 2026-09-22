#include "PrivilegeFeature.h"

#include "PrivilegeView.h"

namespace ksword::features::privilege {

HWND createPrivilegeFeaturePage(HWND parent, const RECT& bounds) {
    return createPrivilegeView(parent, bounds);
}

} // namespace Ksword::Features::privilege
