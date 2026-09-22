#include "../Framework.h"
#include "NotificationCardManager.h"

#include <algorithm>  // std::find_if
#include <cmath>      // std::isfinite
#include <utility>    // std::move

#include <QApplication> // QApplication::instance
#include <QCoreApplication> // QCoreApplication::instance
#include <QEventLoop> // Keep UI event processing active while waiting for results in a non-modal option window.
#include <QGuiApplication>
#include <QMessageBox>  // Blocking button selection dialog
#include <QMetaObject>  // invokeMethod
#include <QObject>      // qobject_cast
#include <QPushButton>  // Return type of QMessageBox::addButton.
#include <QThread>      // Check if the current thread is the UI thread.
#include <QScreen>
#include <QWindow>

#include <atomic>

namespace
{
    std::atomic_uint gNonModalOptionDialogSequence{ 0 };
    constexpr std::size_t kMaximumTerminalTaskHistory = 256U;

    // findTaskByPidMutable:
    // - Find the task iterator by PID in the writable task container.
    // Parameter tasks: Task container (writable).
    // Parameter pid: The target PID.
    // Return value: Returns the corresponding iterator if found; otherwise returns end().
    std::vector<KProgressTask>::iterator findTaskByPidMutable(
        std::vector<KProgressTask>& tasks,
        const int pid)
    {
        return std::find_if(
            tasks.begin(),
            tasks.end(),
            [pid](const KProgressTask& taskItem) { return taskItem.pid == pid; });
    }

    // showOptionsDialogOnUiThread:
    // - Create and execute a blocking options dialog on the UI thread;
    // - Returns the index of the clicked button (1-based).
    // Parameter prompt: Prompt text.
    // Parameter options: Array of button texts.
    // Return value:
    // - 1..N indicates user selection;
    // - 0 indicates the dialog was closed or no selection was made.
    int showOptionsDialogNonModalOnUiThread(
        const std::string& prompt,
        const std::vector<std::string>& options)
    {
        QMessageBox optionDialog(ks::ui::notificationCardHostWindow());
        optionDialog.setWindowTitle(QStringLiteral("任务操作"));
        optionDialog.setIcon(QMessageBox::Question);
        optionDialog.setText(QString::fromUtf8(prompt.c_str()));
        optionDialog.setWindowModality(Qt::NonModal);
        optionDialog.setModal(false);

        std::vector<QAbstractButton*> buttonHandles;
        buttonHandles.reserve(options.size());
        for (const std::string& optionText : options)
        {
            QAbstractButton* optionButton = optionDialog.addButton(
                QString::fromUtf8(optionText.c_str()),
                QMessageBox::ActionRole);
            buttonHandles.push_back(optionButton);
        }

        int selectedIndex = 0;
        QEventLoop resultLoop;
        QObject::connect(&optionDialog, &QMessageBox::finished, &resultLoop, [&]() {
            QAbstractButton* clickedButton = optionDialog.clickedButton();
            for (std::size_t index = 0; index < buttonHandles.size(); ++index)
            {
                if (buttonHandles[index] == clickedButton)
                {
                    selectedIndex = static_cast<int>(index + 1);
                    break;
                }
            }
            resultLoop.quit();
        });

        optionDialog.show();
        QScreen* targetScreen = nullptr;
        QWidget* hostWindow = ks::ui::notificationCardHostWindow();
        if (hostWindow != nullptr)
        {
            targetScreen = QGuiApplication::screenAt(hostWindow->frameGeometry().center());
            if (targetScreen == nullptr && hostWindow->windowHandle() != nullptr)
            {
                targetScreen = hostWindow->windowHandle()->screen();
            }
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QGuiApplication::primaryScreen();
        }
        if (targetScreen != nullptr)
        {
            const QRect kAvailableRect = targetScreen->availableGeometry();
            const unsigned int kSequence = gNonModalOptionDialogSequence.fetch_add(1);
            const int kOffset = static_cast<int>(kSequence % 8U) * 26;
            optionDialog.move(
                kAvailableRect.center() - QPoint(optionDialog.width() / 2, optionDialog.height() / 2)
                + QPoint(kOffset, kOffset));
        }
        optionDialog.raise();
        resultLoop.exec();
        return selectedIndex;
    }

    int showOptionsDialogOnUiThread(
        const int pid,
        const std::string& prompt,
        const std::vector<std::string>& options)
    {
        // Return 0 immediately if no options are provided to avoid showing an empty dialog.
        if (options.empty())
        {
            return 0;
        }

        if (ks::ui::isProgressTaskNotificationOverflowed(pid))
        {
            // Overflow tasks use a non-modal window: the caller still receives the original synchronous return value, while the main UI continues processing events.
            return showOptionsDialogNonModalOnUiThread(prompt, options);
        }

        QMessageBox optionDialog;
        optionDialog.setWindowTitle(QStringLiteral("任务操作"));
        optionDialog.setIcon(QMessageBox::Question);
        optionDialog.setText(QString::fromUtf8(prompt.c_str()));

        // Append options as buttons in order and record the mapping.
        std::vector<QAbstractButton*> buttonHandles;
        buttonHandles.reserve(options.size());
        for (const std::string& optionText : options)
        {
            QAbstractButton* optionButton = optionDialog.addButton(
                QString::fromUtf8(optionText.c_str()),
                QMessageBox::ActionRole);
            buttonHandles.push_back(optionButton);
        }

        // Blocks execution until the user clicks a button or closes the window.
        optionDialog.exec();
        QAbstractButton* clickedButton = optionDialog.clickedButton();
        if (clickedButton == nullptr)
        {
            return 0;
        }

        // Map the button pointer back to its 1-based index.
        for (std::size_t index = 0; index < buttonHandles.size(); ++index)
        {
            if (buttonHandles[index] == clickedButton)
            {
                return static_cast<int>(index + 1);
            }
        }
        return 0;
    }
} // namespace

// Global progress manager definition (extern declaration located in Framework.h).
KProgress kPro;

KProgress::KProgress() = default;

int KProgress::add(const std::string& taskName, const std::string& stepName)
{
    return addInternal(nullptr, taskName, stepName, false);
}

int KProgress::add(
    QObject* const owner,
    const std::string& taskName,
    const std::string& stepName)
{
    return addInternal(owner, taskName, stepName, false);
}

int KProgress::addReusable(
    QObject* const owner,
    const std::string& taskName,
    const std::string& stepName)
{
    return addInternal(owner, taskName, stepName, true);
}

int KProgress::addInternal(
    QObject* const owner,
    const std::string& taskName,
    const std::string& stepName,
    const bool retainedForReuse)
{
    int newPid = 0;
    bool shouldBindOwner = false;

    {
        std::lock_guard<std::mutex> lockGuard(mutex_);

        // Allocate a PID and create the initial task object.
        newPid = nextPid_++;
        KProgressTask newTask;
        newTask.pid = newPid;
        newTask.taskName = taskName;
        newTask.stepName = stepName;
        newTask.stepCode = 0;
        newTask.progress = 0.0f;
        newTask.hiddenInList = false;
        newTask.hideProgressBarTemporarily = false;
        newTask.retainedForReuse = retainedForReuse;

        // Append to container and increment revision number to trigger UI refresh.
        tasks_.push_back(std::move(newTask));
        if (owner != nullptr)
        {
            taskOwners_.emplace(newPid, owner);
            shouldBindOwner = boundOwners_.insert(owner).second;
        }
        ++revision_;
    }

    if (shouldBindOwner)
    {
        // Connect to the same owner only once; the callback batch-deletes all tasks created by this page.
        const QMetaObject::Connection kOwnerDestroyedConnection = QObject::connect(
            owner,
            &QObject::destroyed,
            [owner](QObject*)
            {
                kPro.removeTasksOwnedBy(owner);
            });
        if (!kOwnerDestroyedConnection)
        {
            // When owner can no longer establish a lifecycle binding, do not retain tasks that cannot be automatically reclaimed.
            removeTasksOwnedBy(owner);
        }
    }

    return newPid;
}

void KProgress::set(const int pid, const std::string& stepName, const int stepCode, const float progressValue)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);

    // Find the target task; if not found, return silently to avoid interrupting the business flow.
    const auto kTaskIterator = findTaskByPidMutable(tasks_, pid);
    if (kTaskIterator == tasks_.end())
    {
        return;
    }

    // Update step text, business status code, and progress value.
    kTaskIterator->stepName = stepName;
    kTaskIterator->stepCode = stepCode;
    kTaskIterator->progress = normalizeProgress(progressValue);

    // Hide the card when progress reaches 1.0 (satisfies the 'hide after completion' requirement).
    kTaskIterator->hiddenInList = (kTaskIterator->progress >= 1.0f);

    // No longer need temporary hide logic in completed state; reset uniformly.
    if (kTaskIterator->hiddenInList)
    {
        kTaskIterator->hideProgressBarTemporarily = false;
    }

    // Increment the revision number after data changes and notify the UI to repaint.
    ++revision_;

    if (kTaskIterator->hiddenInList)
    {
        pruneTerminalHistoryLocked();
    }
}

int KProgress::ui(const int pid, const std::string& prompt, const std::vector<std::string>& options)
{
    // Temporarily hide the progress bar for the target task before showing the dialog.
    setProgressBarHiddenForUi(pid, true);

    // Obtain the UI thread context via the Qt application object.
    QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr)
    {
        // Cannot pop up a dialog without QApplication; restore the progress bar and return 0.
        setProgressBarHiddenForUi(pid, false);
        return 0;
    }

    int selectedIndex = 0;

    // If already on the UI thread, show the dialog directly; otherwise, block and dispatch the call to the UI thread.
    if (QThread::currentThread() == appInstance->thread())
    {
        selectedIndex = showOptionsDialogOnUiThread(pid, prompt, options);
    }
    else
    {
        QMetaObject::invokeMethod(
            appInstance,
            [&selectedIndex, &prompt, &options, pid]()
            {
                selectedIndex = showOptionsDialogOnUiThread(pid, prompt, options);
            },
            Qt::BlockingQueuedConnection);
    }

    // Restore progress bar visibility after the dialog closes.
    setProgressBarHiddenForUi(pid, false);
    return selectedIndex;
}

std::vector<KProgressTask> KProgress::snapshot() const
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return tasks_;
}

std::size_t KProgress::revision() const
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    return revision_;
}

float KProgress::normalizeProgress(const float rawProgress)
{
    // Treat non-finite values as 0 to prevent NaN/Inf from polluting the UI.
    if (!std::isfinite(rawProgress))
    {
        return 0.0f;
    }

    // Compatible with two input formats:
    // 1) 0~1: Proportional format.
    // 2) 0~100: Percentage format (e.g., 70.0f).
    float normalizedValue = rawProgress;
    if (normalizedValue > 1.0f)
    {
        normalizedValue /= 100.0f;
    }

    // Clamp progress to the [0, 1] range to ensure safe progress bar display.
    if (normalizedValue < 0.0f)
    {
        normalizedValue = 0.0f;
    }
    if (normalizedValue > 1.0f)
    {
        normalizedValue = 1.0f;
    }
    return normalizedValue;
}

void KProgress::pruneTerminalHistoryLocked()
{
    const std::size_t kTerminalTaskCount = static_cast<std::size_t>(std::count_if(
        tasks_.cbegin(),
        tasks_.cend(),
        [](const KProgressTask& taskItem)
        {
            return taskItem.hiddenInList && !taskItem.retainedForReuse;
        }));
    if (kTerminalTaskCount <= kMaximumTerminalTaskHistory)
    {
        return;
    }

    std::size_t tasksToRemove = kTerminalTaskCount - kMaximumTerminalTaskHistory;
    tasks_.erase(
        std::remove_if(
            tasks_.begin(),
            tasks_.end(),
            [this, &tasksToRemove](const KProgressTask& taskItem)
            {
                if (tasksToRemove == 0U ||
                    !taskItem.hiddenInList ||
                    taskItem.retainedForReuse)
                {
                    return false;
                }
                --tasksToRemove;
                taskOwners_.erase(taskItem.pid);
                return true;
            }),
        tasks_.end());
}

void KProgress::removeTasksOwnedBy(QObject* const owner)
{
    if (owner == nullptr)
    {
        return;
    }

    std::lock_guard<std::mutex> lockGuard(mutex_);
    const std::size_t kPreviousTaskCount = tasks_.size();
    tasks_.erase(
        std::remove_if(
            tasks_.begin(),
            tasks_.end(),
            [this, owner](const KProgressTask& taskItem)
            {
                const auto kOwnerIterator = taskOwners_.find(taskItem.pid);
                if (kOwnerIterator == taskOwners_.end() || kOwnerIterator->second != owner)
                {
                    return false;
                }
                taskOwners_.erase(kOwnerIterator);
                return true;
            }),
        tasks_.end());
    boundOwners_.erase(owner);

    if (tasks_.size() != kPreviousTaskCount)
    {
        ++revision_;
    }
}

void KProgress::setProgressBarHiddenForUi(const int pid, const bool hidden)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);

    // Find the task corresponding to the PID; if it does not exist, return immediately.
    const auto kTaskIterator = findTaskByPidMutable(tasks_, pid);
    if (kTaskIterator == tasks_.end())
    {
        return;
    }

    // When a card is hidden due to completion, there is no need to process the 'progress bar temporary hide' state.
    if (kTaskIterator->hiddenInList)
    {
        return;
    }

    // Increment the revision number only when the state actually changes to avoid meaningless refreshes.
    if (kTaskIterator->hideProgressBarTemporarily != hidden)
    {
        kTaskIterator->hideProgressBarTemporarily = hidden;
        ++revision_;
    }
}
