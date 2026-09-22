#pragma once

// ============================================================
// ThemeStatusRole.h
// Purpose:
// 1) Extract the five semantic state colors (Idle/Info/Success/Warning/Error) from the styleSheet constructed during page initialization.
// 2) Controls only record their own state; colors are uniformly distributed by global style blocks, and theme switching automatically follows.
// 3) Replace the three duplicate monitor*ColorHex() + buildStatusStyle() implementations in the MonitorDock family.
//
// Background: Semantic status colors are a class of colors that QPalette roles cannot express — the palette lacks an 'error red',
// so they cannot be dynamically swapped via `palette(...)` like surface or border colors. However, they also must not be baked
// into fixed #RRGGBB values during widget construction via `*Color().name()`: successColor/errorColor values differ between light
// and dark themes; once baked, status text would remain stuck on the old theme's red/green/orange. Furthermore, a widget's own
// `styleSheet` has higher priority than ancestor global QSS, so rebuilding the global style block cannot recover the issue.
//
// Solution: The control writes only the state, not the color. Colors are centralized in the global stylesheet block
// QLabel[ksword_status_role="..."] rules, which are rebuilt entirely upon theme refresh. The control itself no longer
// holds a styleSheet, so it is no longer subject to being overwritten by the legacy style sheet scan in ThemeColorRemap.
// ============================================================

#include <QString>

class QWidget;

namespace ks::ui
{
    // StatusRole: Semantic status enumeration, corresponding one-to-one with property values in global style blocks.
    enum class StatusRole
    {
        // None: Clear status flag; control reverts to inherited color.
        kNone,
        // Idle: Neutral states such as not started, not subscribed, or not selected; use secondary text color.
        kIdle,
        // Info: Neutral prompts such as in progress, submitted, or awaiting acknowledgment.
        kInfo,
        // Success: Active, connected, or validation passed.
        kSuccess,
        // Warning: downgrade available, partial failure, incomplete result.
        kWarning,
        // Error: Failed, unavailable, or denied.
        kError
    };

    // kStatusRoleProperty: Dynamic property name carrying the status; global style blocks use it for property selection.
    inline constexpr const char* kStatusRoleProperty = "ksword_status_role";

    // applyStatusRole: Applies semantic status to the widget and triggers immediate style re-matching.
    // Input: Target widget (returns immediately if null) and semantic status.
    // Processing: Return immediately if the property value has not changed to avoid unnecessary unpolish/polish operations. If changed, update the property and
    //       re-polish. Qt's property selectors only participate in matching during the polish phase; changing a property without polishing will not update the color.
    // Usage: replaces the original `label->setStyleSheet(buildStatusStyle(monitor*ColorHex()))`.
    void applyStatusRole(QWidget* widget, StatusRole role);

    // buildStatusRoleStyleRules: Generates global QSS rule fragments for semantic status colors.
    // Returns: Rule text directly appendable to base control style blocks, using semantic colors from the current theme.
    // Usage: Built by concatenating within buildGlobalBaseControlStyleBlock, rebuilt entirely upon theme refresh.
    QString buildStatusRoleStyleRules();
}
