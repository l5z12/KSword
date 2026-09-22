#pragma once

// Implementation details shared by mainWindow's responsibility-specific units.
// Public window API remains in mainWindow.h.
#include <QColor>
#include <QString>
#include <QWidget>
#include <functional>
#include <string>

namespace ads { class CDockWidget; }

namespace ksword::ui::main_window
{
    // kDockLayoutConfigFileVersion:
    // - Version number for ADS saveState/restoreState operations.
    // - Increment this when the dock set or default layout undergoes an incompatible change to automatically discard old layouts.
    // 7: Added a top-level "Virtualization (KVM)" Dock. Since the old layout lacks ksDock_kvm, after ADS restoration,
    // this page will not appear in any Dock area, leaving the user unaware of the new page with no notification.
    inline constexpr int kDockLayoutConfigFileVersion = 7;

    // kDockLayoutConfigFileName:
    // - Define the ADS layout configuration file name after user drag-and-drop.
    // - The file resides in the config directory at the same level as the exe, facilitating independent configuration packaging.
    inline constexpr const char* kDockLayoutConfigFileName = "ksword_ads_layout.bin";

    // kLazyDockPlaceholderProgressBarObjectName / kLazyDockPlaceholderStageLabelObjectName: Purpose:
    // - Stable objectName for the progress bar and stage label in the lazy-loaded placeholder page.
    // - The placeholder page is handed over to ADS immediately after being created by createDockPlaceholderWidget; initialization
    //   at each stage can only rely on findChild to reverse-lookup these two controls, so their names must remain fixed.
    inline constexpr const char* kLazyDockPlaceholderProgressBarObjectName = "ksLazyDockProgressBar";

    inline constexpr const char* kLazyDockPlaceholderStageLabelObjectName = "ksLazyDockStageLabel";

    QColor dockTabTextColor(const bool activeTab);

    void withTemporaryNonTopMostForDockSwitch(const std::function<void()>& switchOperation);

    void configureAdsDockTabVisualIdentity(ads::CDockWidget* dockWidget);

    void refreshAdsDockTabVisualIdentities(QWidget* rootWidget);

    void updateLazyDockPlaceholderProgress(
        ads::CDockWidget* dockWidget,
        const QString& stageText,
        const int progressPercent);

    bool isDockWidgetActiveForLazyInitialization(
        ads::CDockWidget* dockWidget,
        ads::CDockWidget* focusedDockWidget);

    void ensureKswordAdsDockComponentsFactoryInstalled();
}
