#pragma once

#include "../core/Win32Lean.h"

#include <string>

namespace ksword::ui {

// registerControlClasses registers all custom lightweight controls. Input is the
// module instance; processing registers idempotent WNDCLASS records; output is
// true when all required classes are available.
bool registerControlClasses(HINSTANCE instance);

// systemUiFont returns the current Windows UI message font. There is no input;
// processing queries NONCLIENTMETRICS and creates a matching HFONT; output is a
// process-owned font handle that callers must not delete.
HFONT systemUiFont();

// refreshSystemUiFont drops the cached Windows UI message font. There is no
// input; processing recreates it on next use; no value is returned.
void refreshSystemUiFont();

// createText creates a child STATIC using the Windows UI message font. Inputs
// are parent, id, text and geometry; processing creates the HWND; output is HWND.
HWND createText(HWND parent, int id, const std::wstring& text, int x, int y, int w, int h);

// createButton creates a compact child push button using the Windows UI message
// font. Inputs are parent, id, text and geometry; output is the HWND.
HWND createButton(HWND parent, int id, const std::wstring& text, int x, int y, int w, int h);

// setWindowFontRecursive applies the Windows UI message font to a window
// subtree. Input is a root HWND; processing sends WM_SETFONT; no return.
void setWindowFontRecursive(HWND root);

// paintPanel fills a themed panel rectangle. Inputs are paint DC and geometry;
// processing draws background and border; no value is returned.
void paintPanel(HDC dc, const RECT& rect);

// drawTextLine draws one clipped text line. Inputs are a DC, text, rect, color,
// font and alignment flags; processing selects the font temporarily; no return.
void drawTextLine(HDC dc, const std::wstring& text, RECT rect, COLORREF color, HFONT font, UINT format);

} // namespace Ksword::Ui
