#include "ThemeStatusRole.h"

#include "../Theme.h"

#include <QLatin1String>
#include <QStyle>
#include <QVariant>
#include <QWidget>

namespace ks::ui
{
    namespace
    {
        // statusRoleName: Maps the enum to property value text.
        // The spelling here shares the same set of literals with the selector in buildStatusRoleStyleRules; both locations must be updated simultaneously.
        QLatin1String statusRoleName(const StatusRole role)
        {
            switch (role)
            {
            case StatusRole::kIdle:
                return QLatin1String("idle");
            case StatusRole::kInfo:
                return QLatin1String("info");
            case StatusRole::kSuccess:
                return QLatin1String("success");
            case StatusRole::kWarning:
                return QLatin1String("warning");
            case StatusRole::kError:
                return QLatin1String("error");
            case StatusRole::kNone:
                break;
            }
            return QLatin1String("");
        }
    }

    void applyStatusRole(QWidget* const widget, const StatusRole role)
    {
        if (widget == nullptr)
        {
            return;
        }
        const QString kRoleText(statusRoleName(role));
        // Return immediately if the status has not changed: the collection callback resets the status label to the same state in every refresh cycle,
        // while unpolish/polish must recalculate the entire style rule chain; under high-frequency events, this would significantly slow down refreshes.
        if (widget->property(kStatusRoleProperty).toString() == kRoleText)
        {
            return;
        }
        widget->setProperty(kStatusRoleProperty, kRoleText);
        // Attribute selectors only participate in matching during the polish phase; changing attributes without re-polishing will not change the color.
        QStyle* const kWidgetStyle = widget->style();
        if (kWidgetStyle != nullptr)
        {
            kWidgetStyle->unpolish(widget);
            kWidgetStyle->polish(widget);
        }
        widget->update();
    }

    QString buildStatusRoleStyleRules()
    {
        // The selector group and the '{' are written within the same string fragment so that i18n audits can recognize it as QSS rather than UI text.
        // Idle state uses a dynamic palette role directly: it already follows the theme and does not need re-evaluation on every rebuild.
        // The remaining four colors are semantic colors that cannot be expressed by the palette; they are retrieved from the current theme upon rebuilding this style block.
        return QStringLiteral(
            "QLabel[ksword_status_role=\"idle\"]{"
            "  color:palette(placeholder-text);"
            "  font-weight:600;"
            "}"
            "QLabel[ksword_status_role=\"info\"]{"
            "  color:%1;"
            "  font-weight:600;"
            "}"
            "QLabel[ksword_status_role=\"success\"]{"
            "  color:%2;"
            "  font-weight:600;"
            "}"
            "QLabel[ksword_status_role=\"warning\"]{"
            "  color:%3;"
            "  font-weight:600;"
            "}"
            "QLabel[ksword_status_role=\"error\"]{"
            "  color:%4;"
            "  font-weight:600;"
            "}")
            .arg(ksword_theme::infoHex())
            .arg(ksword_theme::successHex())
            .arg(ksword_theme::warningHex())
            .arg(ksword_theme::errorHex());
    }
}
