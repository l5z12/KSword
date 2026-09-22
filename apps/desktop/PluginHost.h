#pragma once

// ============================================================
// PluginHost.h
// Purpose:
// - Provides the sole bridge from the Ksword GUI to standalone plugin CLI entry points.
// - The GUI reads the plugin manifest but never loads third-party plugin code or DLLs.
// - File, process, and network entries share the same target context and menu construction logic.
// ============================================================

#include <QString>

#include <QtGlobal>

class QMenu;
class QTabWidget;
class QWidget;

namespace ks::plugin_host
{
    enum class TargetKind
    {
        kFile,
        kProcess,
        kNetwork,
    };

    struct InvocationContext
    {
        TargetKind targetKind = TargetKind::kFile;
        QString filePath;
        quint32 processId = 0;
        QString processName;
    };

    // populateTargetMenu：
    // - Discover installed plugins from plugin\<id>\plugin.json;
    // - Only display plugins that declare support for the current target type; menu hierarchy is always 'Plugins → <Plugin Name>'.
    // - After selecting an action, Ksword directly launches the standalone entry point using QProcess.
    void populateTargetMenu(QMenu* menu, QWidget* owner, const InvocationContext& context);

    // populateTabPlugins：
    // - Discovers external process plugins with plugin_type=tab or hybrid;
    // - Establish native child window containers within the host QTabWidget without loading plugin DLLs/code into KSword;
    // - The plugin window handle must belong to the plugin process just started and must be attached directly to the HWND provided by the host.
    // - Returns the number of tabs successfully added to the host.
    int populateTabPlugins(QTabWidget* tabWidget, QWidget* owner);

    // createTabPluginContainer：
    // - Create the content container for the top 'Plugins' Dock and inject the KSword base theme styles;
    // - All Tab-type plugins enter only this container and are not mixed into the 'Misc/Utilities' page.
    // - Display an empty state page allowing direct access to the plugin manager when no installed Tab plugins exist.
    QWidget* createTabPluginContainer(QWidget* parent);

    // showPluginManager：
    // - Opens a non-modal plugin manager window;
    // - Manages local plugins and performs license confirmation, validation, and one-click installation from the marketplace.
    void showPluginManager(QWidget* owner);
}
