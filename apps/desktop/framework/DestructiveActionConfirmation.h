#pragma once

#include <QString>

class QWidget;

namespace ks::ui
{
    // Display a unified confirmation dialog for irreversible actions. Persist the 'do not show again' setting only if the user confirms and checks the box.
    bool confirmDestructiveAction(
        QWidget* parent,
        const QString& suppressionKey,
        const QString& actionTitle,
        const QString& targetDescription,
        const QString& riskDescription = QString());
}
