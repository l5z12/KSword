#pragma once

#include <functional>

#include <QObject>
#include <QSize>
#include <QTabWidget>
#include <QWidget>

// createBasicPlaceholder:
// - Inputs: tipText is the text displayed in the placeholder body.
// - Processing: the implementation builds a simple QWidget with centered text.
// - Return: a newly allocated QWidget owned by the caller/Qt parent chain.
QWidget* createBasicPlaceholder(const QString& tipText = "Placeholder panel");

namespace ks::ui
{
    // applyResponsiveWindowGeometry:
    // - Clamps initial and minimum dimensions based on the available area of the screen where the parent window resides.
    // - Prevents windows from being pushed out of the work area due to hardcoded minimumSize in high DPI, small screen, and remote desktop environments.
    // - Constrains only the initial/minimum size, not the user's ability to maximize the window later.
    void applyResponsiveWindowGeometry(
        QWidget* window,
        QWidget* candidateParent,
        const QSize& preferredSize,
        const QSize& minimumSize,
        double maxAvailableRatio = 0.9);

    // scheduleDeferredTabActivation:
    // - Defer construction of heavy Tab pages from the currentChanged synchronous call point to the next UI event loop iteration;
    // - If either context or placeholder is destroyed, the callback will no longer access invalid controls.
    using DeferredTabActivationCallback = std::function<void()>;

    void scheduleDeferredTabActivation(
        QObject* context,
        QTabWidget* tabWidget,
        int tabIndex,
        QWidget* placeholderPage,
        DeferredTabActivationCallback callback);
}
