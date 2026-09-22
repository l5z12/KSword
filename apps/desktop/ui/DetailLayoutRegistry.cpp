#include "DetailLayoutRegistry.h"

#include "DetailLayoutHost.h"

#include <QList>
#include <QPointer>

namespace
{
    // detailHosts: stores only weak references; QPointer automatically becomes null after page destruction, triggering cleanup on the next call.
    QList<QPointer<ks::ui::DetailLayoutHost>>& detailHosts()
    {
        static QList<QPointer<ks::ui::DetailLayoutHost>> hosts;
        return hosts;
    }

    // currentDetailScheme: Process-local unique global scheme, defaulting to match AppearanceSettings.
    ks::settings::DetailDisplayScheme& currentDetailScheme()
    {
        static ks::settings::DetailDisplayScheme scheme =
            ks::settings::DetailDisplayScheme::kBottomCollapsed;
        return scheme;
    }

    // pruneDestroyedHosts: Remove weak references to controllers destroyed along with lazy-loaded pages.
    void pruneDestroyedHosts()
    {
        QList<QPointer<ks::ui::DetailLayoutHost>>& hosts = detailHosts();
        for (int index = hosts.size() - 1; index >= 0; --index)
        {
            if (hosts.at(index).isNull())
            {
                hosts.removeAt(index);
            }
        }
    }
}

ks::ui::DetailLayoutHost* ks::ui::DetailLayoutRegistry::registerHost(
    QAbstractItemView* tableView,
    CodeEditorWidget* detailEditor,
    QWidget* ownerWidget)
{
    if (tableView == nullptr || detailEditor == nullptr || ownerWidget == nullptr)
    {
        return nullptr;
    }

    pruneDestroyedHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : detailHosts())
    {
        if (!hostPointer.isNull() && hostPointer->detailEditor() == detailEditor)
        {
            hostPointer->setTableView(tableView);
            hostPointer->applyScheme(currentDetailScheme());
            return hostPointer.data();
        }
    }

    // New controllers use the page as the QObject parent, ensuring no floating windows or callbacks remain when the page is unloaded.
    DetailLayoutHost* host = new DetailLayoutHost(tableView, detailEditor, ownerWidget);
    detailHosts().append(QPointer<DetailLayoutHost>(host));
    host->applyScheme(currentDetailScheme());
    return host;
}

void ks::ui::DetailLayoutRegistry::applyGlobalScheme(
    const ks::settings::DetailDisplayScheme scheme)
{
    currentDetailScheme() = scheme;
    pruneDestroyedHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : detailHosts())
    {
        if (!hostPointer.isNull())
        {
            hostPointer->applyScheme(scheme);
        }
    }
}

ks::settings::DetailDisplayScheme ks::ui::DetailLayoutRegistry::globalScheme()
{
    return currentDetailScheme();
}

ks::ui::DetailLayoutHost* ks::ui::DetailLayoutRegistry::hostFor(
    CodeEditorWidget* detailEditor)
{
    if (detailEditor == nullptr)
    {
        return nullptr;
    }

    pruneDestroyedHosts();
    for (const QPointer<DetailLayoutHost>& hostPointer : detailHosts())
    {
        if (!hostPointer.isNull() && hostPointer->detailEditor() == detailEditor)
        {
            return hostPointer.data();
        }
    }
    return nullptr;
}

void ks::ui::DetailLayoutRegistry::prepareDataRebuild(CodeEditorWidget* detailEditor)
{
    DetailLayoutHost* host = hostFor(detailEditor);
    if (host != nullptr)
    {
        host->prepareDataRebuild();
    }
}
