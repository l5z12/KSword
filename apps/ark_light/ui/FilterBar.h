#pragma once

#include "../core/Win32Lean.h"

#include <string>

namespace ksword::ui {

// createFilterBar creates a self-contained label/edit/clear toolbar. The
// parent receives WM_COMMAND with EN_CHANGE after 200 ms of quiet input, using
// the supplied id. It owns its child controls and needs no explicit destroy.
HWND createFilterBar(HWND parent, int id, const std::wstring& cueText, int x, int y, int width, int height);

// getFilterBarText returns the current filter query without leading/trailing
// whitespace. It is safe to call from the parent command handler.
std::wstring getFilterBarText(HWND filterBar);

// getFilterBarRegexEnabled reports whether the ".*" toggle is pressed. Input is
// the filter bar HWND; output is false for a null or plain bar. Callers pass the
// result to VirtualListView::filterRowIndexes and must include it when they
// compare a completed filter result against the current query: switching mode
// without retyping leaves the text identical, and a text-only comparison would
// throw the new result away.
bool getFilterBarRegexEnabled(HWND filterBar);

// setFilterBarText replaces the text. notifyParent controls whether a debounced
// EN_CHANGE notification is generated.
void setFilterBarText(HWND filterBar, const std::wstring& text, bool notifyParent = true);

// focusFilterBar moves keyboard focus to its edit box.
void focusFilterBar(HWND filterBar);

} // namespace Ksword::Ui
