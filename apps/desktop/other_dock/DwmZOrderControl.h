#pragma once
#include <cstdint>
class QWidget;
class QString;
namespace ks::dwm_order
{
    struct Reply;
    struct WindowIdentity;
    QWidget* createControl(const WindowIdentity& identity, QWidget* parent);
    QString errorDescription(const Reply& reply);
}
