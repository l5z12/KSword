#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    // resolveVisibleDialogParent:
    // - Select a visible parent window for the file unlocker;
    // - Shell right-click uses a hidden FileDock host; popups cannot be attached directly to hidden controls.
    QWidget* resolveVisibleDialogParent(QWidget* const preferredParent)
    {
        QWidget* candidate = preferredParent;
        if (candidate != nullptr)
        {
            QWidget* const kTopLevel = candidate->window();
            if (kTopLevel != nullptr)
            {
                candidate = kTopLevel;
            }
        }
        if (candidate != nullptr && candidate->isVisible())
        {
            return candidate;
        }
        if (QWidget* const kActiveWindow = QApplication::activeWindow(); kActiveWindow != nullptr)
        {
            return kActiveWindow;
        }
        const QWidgetList kTopLevelWidgetList = QApplication::topLevelWidgets();
        for (QWidget* const kWidget : kTopLevelWidgetList)
        {
            if (kWidget != nullptr && kWidget->isVisible())
            {
                return kWidget;
            }
        }
        return preferredParent;
    }

    int calculateFileStandaloneWindowMaxWidth(
        QWidget* candidateParent,
        QWidget* fallbackWindow,
        const double ratio,
        const int fallbackWidth)
    {
        // Inputs:
        // - candidateParent: The client area control to prioritize.
        // - fallbackWindow: current standalone window used for screen fallback;
        // - ratio: client area width ratio
        // - fallbackWidth: fallback width.
        // Processing:
        // - Prefer the parent control's contentsRect width;
        // - Use the active window's client area if the parent control is unavailable;
        // - Fall back to the screen's available width.
        // Returns: Maximum calculated width based on proportion; falls back to a default width only when no judgment is possible.
        int clientWidth = 0;
        if (candidateParent != nullptr && candidateParent->contentsRect().width() > 0)
        {
            clientWidth = candidateParent->contentsRect().width();
        }

        if (clientWidth <= 0)
        {
            QWidget* activeWindow = QApplication::activeWindow();
            if (activeWindow != nullptr &&
                activeWindow != fallbackWindow &&
                activeWindow->contentsRect().width() > 0)
            {
                clientWidth = activeWindow->contentsRect().width();
            }
        }

        QScreen* targetScreen = nullptr;
        if (candidateParent != nullptr && candidateParent->windowHandle() != nullptr)
        {
            targetScreen = candidateParent->windowHandle()->screen();
        }
        if (targetScreen == nullptr && fallbackWindow != nullptr && fallbackWindow->windowHandle() != nullptr)
        {
            targetScreen = fallbackWindow->windowHandle()->screen();
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QApplication::primaryScreen();
        }
        if (clientWidth <= 0 && targetScreen != nullptr)
        {
            clientWidth = targetScreen->availableGeometry().width();
        }

        const int kBoundedFallbackWidth = std::max(1, fallbackWidth);
        if (clientWidth <= 0 || ratio <= 0.0)
        {
            return kBoundedFallbackWidth;
        }
        return std::max(1, static_cast<int>(std::floor(static_cast<double>(clientWidth) * ratio)));
    }

    void applyFileStandaloneWindowWidthLimit(
        QWidget* window,
        QWidget* candidateParent,
        const QSize& preferredSize,
        const double ratio)
    {
        // Inputs:
        // - window: the file attribute window to be constrained.
        // - candidateParent: Source of the client area width.
        // - preferredSize: original design size;
        // - ratio: maximum width ratio.
        // Processing: Set maximumWidth and clip the initial resize width.
        // Returns: Nothing.
        if (window == nullptr)
        {
            return;
        }

        const int kMaxWidth = calculateFileStandaloneWindowMaxWidth(
            candidateParent,
            window,
            ratio,
            preferredSize.width());
        window->setMaximumWidth(kMaxWidth);
        window->resize(std::min(preferredSize.width(), kMaxWidth), preferredSize.height());
    }

    QString unlockOperationModeToText(const UnlockOperationMode mode)
    {
        if (mode == UnlockOperationMode::kCloseHandleR3)
        {
            return QStringLiteral("R3 关闭句柄");
        }
        return mode == UnlockOperationMode::kTerminateProcessR0
            ? QStringLiteral("R0 结束进程")
            : QStringLiteral("R3 结束进程");
    }

    QString formatHandleValueText(const std::uint64_t handleValue)
    {
        if (handleValue == 0U)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(handleValue), 0, 16)
            .toUpper();
    }

    void appendUniqueText(QStringList& list, const QString& text)
    {
        const QString kNormalizedText = text.trimmed();
        if (!kNormalizedText.isEmpty() && !list.contains(kNormalizedText))
        {
            list.push_back(kNormalizedText);
        }
    }
}
