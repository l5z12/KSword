#pragma once

// Support for ADS tab bar overflow scrolling, left/right navigation, and layout reset.

#include <QObject>
#include <QString>

namespace ads
{
    class CDockManager;
}

namespace ks::ui
{
    // Install mouse/trackpad horizontal scrolling and left/right arrows that appear only on overflow.
    //
    // Must attach to the manager rather than scanning once at startup: tab bars appear **later** —
    // floating containers, after restoreState, and creating new docks all generate new tab bars.
    // This function handles both existing and subsequently created docks (via dockAreaCreated subscription).
    //
    // Idempotent: repeated calls will not install a second filter.
    void installDockTabWheelScrolling(ads::CDockManager* dockManager);

    // Delete the saved dock layout file so the next launch returns to the default arrangement.
    //
    // Returns true to indicate that the old layout will definitely not be read again afterward—including the case where the file does not exist.
    // The deletion is exposed separately because the caller must also prevent the old layout
    // from being saved again on this exit; only mainWindow knows how to handle that step.
    bool discardSavedDockLayout(const QString& layoutConfigPath);
}
