#include "ProcessDetailFeature.h"

#include "ProcessDetailPage.h"

namespace ksword::features::process_detail {

HWND createProcessDetailPage(
    HWND parent,
    DWORD processId,
    ULONGLONG expectedCreationTime100ns,
    const RECT& bounds) {
    return ProcessDetailPage::create(parent, processId, expectedCreationTime100ns, bounds);
}

} // namespace Ksword::Features::process_detail
