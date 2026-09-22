#pragma once
#include "WindowInputClient.h"
class QWidget;
namespace ks::window_input
{
    QWidget* createControl(const dwm_order::WindowIdentity& identity, QWidget* parent);
    QWidget* createInjectionPage(QWidget* parent);
}
