#pragma once

// ============================================================
// ThemeColorRemap.h
// Purpose:
// 1) Fix theme non-following issues caused by static theme tokens being baked into fixed #RRGGBB during widget construction;
// 2) Collect all static token values once before and once after the theme seed changes to obtain the "old value -> new value" mapping;
// 3) Use this mapping to replace outdated colors in every existing widget styleSheet without editing thousands of call sites.
//
// Background: theme.h contains two types of tokens. Dynamic tokens in the palette(...) form are parsed by Qt during each render, naturally following the
// theme. In contrast, static tokens like *ColorHex(), accentHex(), and semantic colors are fixed to #RRGGBB at the moment of invocation. Consequently,
// styleSheet values written during page construction permanently remain stuck at the theme colors present at construction time. Since control-specific
// styleSheet values have higher priority than ancestor global QSS, rebuilding the global style block cannot recover the correct colors.
// ============================================================

#include <QList>
#include <QString>

namespace ks::ui
{
    // ThemeColorSnapshot purpose: a static token value snapshot taken before a theme switch.
    // colorTexts corresponds one-to-one with the internal token table by index; it contains no semantic information and is used solely for establishing old-to-new mappings.
    struct ThemeColorSnapshot
    {
        QList<QString> colorTexts;
    };

    // captureThemeColorSnapshot: Evaluates all static tokens based on the current theme seed.
    // Invocation: Must be called before updating the seed in setDarkModeEnabled / setPrimaryAccentColor /
    // setMainBackgroundColor; otherwise, the captured value will be the new one, resulting in an empty mapping.
    ThemeColorSnapshot captureThemeColorSnapshot();

    // ThemeColorRemapResult reports the coverage of a single remapping operation for logging in the theme refresh pipeline.
    struct ThemeColorRemapResult
    {
        // mappedColorCount: Count of color entries that actually changed and are included in the rewrite.
        int mappedColorCount = 0;
        // ambiguousColorCount: count of conflicting entries where old and new values differ; these colors are skipped entirely.
        int ambiguousColorCount = 0;
        // inspectedWidgetCount: Number of scanned widgets whose styleSheet is non-empty.
        int inspectedWidgetCount = 0;
        // rewrittenWidgetCount: The number of controls whose styleSheet was actually rewritten.
        int rewrittenWidgetCount = 0;
        // rewrittenPaletteWidgetCount: The number of controls whose local QPalette was actually rewritten.
        int rewrittenPaletteWidgetCount = 0;
    };

    // remapStaleThemeColors: Replace old token colors in existing widget styleSheet values with the new colors.
    // Input: Snapshot collected before the theme seed update.
    // Processing: re-evaluate the same token set to get new values, construct an old->new mapping, and rewrite
    //       #RRGGBB, #AARRGGBB, and rgb()/rgba() formats in a single pass; alpha in rgba is preserved as-is.
    //       Also rewrite the QPalette set by the controls themselves: an explicit setPalette call freezes the resolve markers, preventing subsequent
    //       QApplication::setPalette calls from affecting these roles. Consequently, the table's background color, text color, and selection color
    //       remain fixed at the theme values from construction. Only modify the group/role that was explicitly set, keeping alpha unchanged.
    // Returns: Statistics of the remapping performed in this session.
    // Invocation: mainWindow::applyAppearanceSettings is called after both the QApplication palette
    //           and the global style block are updated, ensuring that rebuilt style sheets are not rolled back.
    ThemeColorRemapResult remapStaleThemeColors(const ThemeColorSnapshot& previousSnapshot);

    // remapStaleThemeColorsInText function: Applies a consistent color remapping to a single segment of style text.
    // Reused by callers that cached style text during construction but are outside QApplication::allWidgets().
    QString remapStaleThemeColorsInText(
        const ThemeColorSnapshot& previousSnapshot,
        const QString& styleText);
}
