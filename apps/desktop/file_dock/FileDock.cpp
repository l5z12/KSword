#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

FileDock::FileDock(QWidget* parent)
    : QWidget(parent)
{
    // Construction log: records the start of the file module.
    KLogEvent event;
    info << event << "[FileDock] 构造开始，初始化双栏资源管理器。" << eol;

    initializeUi();
}

FileDock::~FileDock()
{
    // Destruction phase first releases held Oplocks, then stops the unlocker background thread.
    releaseAllActiveOplocks(false);
    unlockerWorkerStopRequested_.store(true);
    std::thread workerThread;
    {
        std::lock_guard<std::mutex> lock(unlockerWorkerMutex_);
        if (unlockerWorkerThread_.joinable())
        {
            workerThread = std::move(unlockerWorkerThread_);
        }
    }
    if (workerThread.joinable())
    {
        workerThread.join();
    }
}

void FileDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange)
    {
        return;
    }

    const auto kRefreshPanelView = [](FilePanelWidgets& panel)
        {
            if (panel.fileView != nullptr && panel.fileView->viewport() != nullptr)
            {
                // ReparseAwareFileSystemModel::data() generates size and type on the fly in the current language;
                // Proactively refresh the viewport to avoid waiting for directory changes or a restart before re-fetching data.
                panel.fileView->viewport()->update();
            }
            if (panel.compactFileView != nullptr && panel.compactFileView->viewport() != nullptr)
            {
                panel.compactFileView->viewport()->update();
            }
        };
    kRefreshPanelView(leftPanel_);
    kRefreshPanelView(rightPanel_);
}

bool FileDock::eventFilter(QObject* watched, QEvent* event)
{
    // The read mode combo box consumes wheel events: each switch triggers a directory reparse, and Pure MFT /
    // R0 IRP modes trigger full-volume reparse operations. If the mouse scrolls from the list to the toolbar,
    // a single scroll action can switch multiple modes, effectively queuing multiple full-volume scans.
    // The switch must be an explicit user selection made by opening the dropdown.
    if (event != nullptr && event->type() == QEvent::Wheel &&
        ((leftPanel_.readModeCombo != nullptr && watched == leftPanel_.readModeCombo) ||
         (rightPanel_.readModeCombo != nullptr && watched == rightPanel_.readModeCombo)))
    {
        return true;
    }

    // QFileSystemModel/QTreeView updates the current row based on default mouse selection rules during the right-click press phase.
    // Pre-processes the right-click on the file list viewport: if a selected row is hit, preserve the current multi-selection set.
    // When clicking an unselected row, switch to that single row to ensure subsequent custom menu reads of selectedPaths() remain consistent.
    if (event != nullptr && event->type() == QEvent::MouseButtonPress)
    {
        QMouseEvent* const kMouseEvent = static_cast<QMouseEvent*>(event);
        if (kMouseEvent != nullptr && kMouseEvent->button() == Qt::RightButton)
        {
            FilePanelWidgets* targetPanel = nullptr;
            QAbstractItemView* targetView = nullptr;
            if (leftPanel_.fileView != nullptr && watched == leftPanel_.fileView->viewport())
            {
                targetPanel = &leftPanel_;
                targetView = leftPanel_.fileView;
            }
            else if (rightPanel_.fileView != nullptr && watched == rightPanel_.fileView->viewport())
            {
                targetPanel = &rightPanel_;
                targetView = rightPanel_.fileView;
            }
            else if (leftPanel_.compactFileView != nullptr && watched == leftPanel_.compactFileView->viewport())
            {
                targetPanel = &leftPanel_;
                targetView = leftPanel_.compactFileView;
            }
            else if (rightPanel_.compactFileView != nullptr && watched == rightPanel_.compactFileView->viewport())
            {
                targetPanel = &rightPanel_;
                targetView = rightPanel_.compactFileView;
            }

            if (targetPanel != nullptr && targetView != nullptr)
            {
                const QModelIndex kHitIndex = targetView->indexAt(kMouseEvent->pos());
                QItemSelectionModel* const kSelectionModel = targetView->selectionModel();
                if (kHitIndex.isValid() && kSelectionModel != nullptr)
                {
                    const QModelIndex kHitRowIndex = kHitIndex.siblingAtColumn(0);
                    const bool kHitAlreadySelected =
                        kSelectionModel->isRowSelected(kHitIndex.row(), kHitIndex.parent()) ||
                        (kHitRowIndex.isValid() && kSelectionModel->isSelected(kHitRowIndex));
                    if (!kHitAlreadySelected)
                    {
                        kSelectionModel->select(kHitIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                    }
                    // Update only the current index without calling QTreeView::setCurrentIndex() to prevent Qt from clearing the multi-selection set according to standard click rules.
                    kSelectionModel->setCurrentIndex(kHitIndex, QItemSelectionModel::NoUpdate);
                    return true;
                }
            }
        }
    }

    return QWidget::eventFilter(watched, event);
}
