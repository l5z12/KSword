#include "GlobalRefreshShortcut.h"

#include <QAbstractButton>
#include <QApplication>
#include <QEvent>
#include <QKeyEvent>
#include <QPointer>
#include <QString>
#include <QWidget>

namespace
{
    // looksLikeRefreshButton:
    // - Determine if a button is a 'Refresh' button.
    // - Refresh buttons in the project are mostly icon-only; reliable cues are
    //   objectName, button text, and tooltip in order. Any one match is sufficient.
    bool looksLikeRefreshButton(const QAbstractButton* button)
    {
        if (button == nullptr)
        {
            return false;
        }
        if (button->objectName().contains(QStringLiteral("refresh"), Qt::CaseInsensitive))
        {
            return true;
        }
        // Match only the prefix to avoid mistaking options like "Verify signature during refresh" or descriptive text for a refresh button.
        if (button->text().trimmed().startsWith(QStringLiteral("刷新")))
        {
            return true;
        }
        return button->toolTip().trimmed().startsWith(QStringLiteral("刷新"));
    }

    // findRefreshButtonNear:
    // - Starting from the focused control, traverse upward to find the refresh button in the nearest ancestor.
    // - Search nearby to ensure that when multiple pages coexist, the trigger affects only the current page.
    // Returns: A clickable refresh button; returns nullptr if not found.
    QAbstractButton* findRefreshButtonNear(QWidget* startWidget)
    {
        for (QWidget* scope = startWidget; scope != nullptr; scope = scope->parentWidget())
        {
            const QList<QAbstractButton*> kButtonList = scope->findChildren<QAbstractButton*>();
            for (QAbstractButton* button : kButtonList)
            {
                if (button != nullptr
                    && button->isVisible()
                    && button->isEnabled()
                    && looksLikeRefreshButton(button))
                {
                    return button;
                }
            }
            if (scope->isWindow())
            {
                break;
            }
        }
        return nullptr;
    }

    // GlobalRefreshShortcutFilter:
    // - QApplication-level event filter;
    // - Capture F5 without modifier keys and forward to the refresh button of the current page.
    class GlobalRefreshShortcutFilter final : public QObject
    {
    public:
        explicit GlobalRefreshShortcutFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr || eventObject->type() != QEvent::KeyPress)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
            // Handle bare F5 only; combinations with Ctrl/Shift/Alt are reserved for individual pages.
            if (keyEvent->key() != Qt::Key_F5
                || (keyEvent->modifiers() & ~Qt::KeypadModifier) != Qt::NoModifier)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWidget* startWidget = QApplication::focusWidget();
            if (startWidget == nullptr)
            {
                startWidget = QApplication::activeWindow();
            }
            QAbstractButton* refreshButton = findRefreshButtonNear(startWidget);
            if (refreshButton == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            refreshButton->click();
            return true;
        }
    };

    // globalRefreshShortcutFilterInstance:
    // - Returns the singleton filter instance; the parent is bound to QApplication, so manual deletion is not required.
    GlobalRefreshShortcutFilter* globalRefreshShortcutFilterInstance()
    {
        static QPointer<GlobalRefreshShortcutFilter> filterInstance;
        if (filterInstance == nullptr && qApp != nullptr)
        {
            filterInstance = new GlobalRefreshShortcutFilter(qApp);
        }
        return filterInstance.data();
    }
}

namespace ks::ui
{
    void installGlobalRefreshShortcut(QApplication* appInstance)
    {
        if (appInstance == nullptr)
        {
            return;
        }
        GlobalRefreshShortcutFilter* filterInstance = globalRefreshShortcutFilterInstance();
        if (filterInstance == nullptr)
        {
            return;
        }
        appInstance->installEventFilter(filterInstance);
    }
}
