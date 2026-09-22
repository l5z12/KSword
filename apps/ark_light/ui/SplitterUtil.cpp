#include "SplitterUtil.h"

#include <algorithm>

namespace ksword::ui {

int clampSplitterPosition(int totalLength, int desiredPosition, int minimumPaneSize) {
    // Inputs use logical pixels. The minimum is clamped to zero so callers may
    // explicitly allow a pane to collapse without extra validation.
    const int kSafeTotal = std::max(0, totalLength);
    const int kSafeMinimum = std::max(0, minimumPaneSize);
    if (kSafeTotal <= kSafeMinimum * 2) {
        return kSafeTotal / 2;
    }
    return std::clamp(desiredPosition, kSafeMinimum, kSafeTotal - kSafeMinimum);
}

SplitterLayout calculateSplitterRects(
    const RECT& clientRect,
    SplitterOrientation orientation,
    int splitterPosition,
    int splitterSize) {
    // The helper performs geometry math only. It does not create windows,
    // subclass controls, or change DockManager behavior.
    SplitterLayout layout{};
    const int kSafeSplitterSize = std::max(1, splitterSize);

    if (orientation == SplitterOrientation::kVertical) {
        const int kTotalWidth = std::max(0, static_cast<int>(clientRect.right - clientRect.left));
        const int kSplit = clientRect.left + std::clamp(splitterPosition, 0, kTotalWidth);
        const int kHalf = kSafeSplitterSize / 2;
        layout.firstPane = RECT{ clientRect.left, clientRect.top, kSplit - kHalf, clientRect.bottom };
        layout.splitterBar = RECT{ kSplit - kHalf, clientRect.top, kSplit - kHalf + kSafeSplitterSize, clientRect.bottom };
        layout.secondPane = RECT{ kSplit - kHalf + kSafeSplitterSize, clientRect.top, clientRect.right, clientRect.bottom };
    } else {
        const int kTotalHeight = std::max(0, static_cast<int>(clientRect.bottom - clientRect.top));
        const int kSplit = clientRect.top + std::clamp(splitterPosition, 0, kTotalHeight);
        const int kHalf = kSafeSplitterSize / 2;
        layout.firstPane = RECT{ clientRect.left, clientRect.top, clientRect.right, kSplit - kHalf };
        layout.splitterBar = RECT{ clientRect.left, kSplit - kHalf, clientRect.right, kSplit - kHalf + kSafeSplitterSize };
        layout.secondPane = RECT{ clientRect.left, kSplit - kHalf + kSafeSplitterSize, clientRect.right, clientRect.bottom };
    }

    return layout;
}

bool hitTestSplitter(const SplitterLayout& layout, POINT point) {
    // PtInRect follows Win32 semantics: left/top inclusive, right/bottom
    // exclusive. The caller supplies client coordinates.
    return ::PtInRect(&layout.splitterBar, point) != FALSE;
}

} // namespace Ksword::Ui
