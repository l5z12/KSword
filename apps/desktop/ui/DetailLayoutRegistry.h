#pragma once

// ============================================================
// DetailLayoutRegistry.h
// Purpose:
// - Save global detail display scheme;
// - Immediately broadcast schemes for created pages.
// - Allow subsequent lazy-loaded pages to register using the latest scheme directly.
// ============================================================

#include "../settings_dock/AppearanceSettings.h"

class CodeEditorWidget;
class QAbstractItemView;
class QWidget;

namespace ks::ui
{
    class DetailLayoutHost;

    class DetailLayoutRegistry final
    {
    public:
        // registerHost: Register a strictly matched page and return its controller; reuse the existing controller if the same editor is registered again.
        static DetailLayoutHost* registerHost(
            QAbstractItemView* tableView,
            CodeEditorWidget* detailEditor,
            QWidget* ownerWidget);

        // applyGlobalScheme: Updates the global scheme and immediately re-layouts all still-active pages.
        static void applyGlobalScheme(ks::settings::DetailDisplayScheme scheme);

        // globalScheme: Returns the current global scheme for use by lazy-loaded page registration.
        static ks::settings::DetailDisplayScheme globalScheme();

        // hostFor / prepareDataRebuild: Locate the page controller based on the original detail editor and clean up synthesized rows before business data rebuild.
        static DetailLayoutHost* hostFor(CodeEditorWidget* detailEditor);
        static void prepareDataRebuild(CodeEditorWidget* detailEditor);

    private:
        DetailLayoutRegistry() = delete;
    };
}
