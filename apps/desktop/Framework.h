#pragma once

// ==============================
// Framework.h
// This header file is the sole public entry point for the Framework module:
// 1) Exposes log levels, event structures, and the log manager.
// 2) Expose five global streaming log objects (dbg/info/warn/err/fatal);
// 3) Expose the EOL macro to carry file/line/function information and trigger a single log submission;
// 4) Exposes the KProgress task progress manager (kPro).
// ==============================

#include <cstddef>    // std::size_t: Used for revision numbers and container indices.
#include <ctime>      // std::time_t: Used to record log timestamps.
#include <mutex>      // std::mutex: Ensures thread safety for the log container.
#include <sstream>    // std::ostringstream: Used for streaming log text concatenation.
#include <string>     // std::string: Used to store log content, file names, and function names.
#include <unordered_map> // std::unordered_map: used to associate task PID with owner.
#include <unordered_set> // std::unordered_set: Ensures each owner registers its cleanup callback only once.
#include <vector>     // std::vector: Internal storage for the log manager.
#include <QString>    // QString: Used for Qt string log output overloading.

// On Windows, use GUIDs as unique event identifiers.
#include <guiddef.h>

// Ksword.h: Unifies inclusion of Win32 tool wrappers (process, string, etc.) under the ksword/ directory.
// Specification requirement: Framework.h serves as the global entry point and must cascade-include Ksword.h.
#include "Ksword.h"
#include "framework/StartupSplash.h"

class QObject;

// Logging core now lives in ksword/log/log.h and is re-exported by Ksword.h.
// Legacy names such as KLogEvent, KEventEntry, dbg/info/warn/err/fatal,
// guidToString, logLevelToString, formatTimeToString and eol remain
// available through that reusable ksword module.

// KProgressTask: Visual snapshot data for a single progress task.
// This structure is used to render the 'current operation' card list in the UI.
struct KProgressTask
{
    int pid = 0;                             // Unique task ID (returned by add).
    std::string taskName;                    // Task title (e.g., "Task 1").
    std::string stepName;                    // Current step (e.g., "Step 2").
    int stepCode = 0;                        // Step status code (reserved field for business custom use).
    float progress = 0.0f;                   // normalize progress value to the range [0.0, 1.0].
    bool hiddenInList = false;               // true indicates the task card should be hidden from the list (e.g., completed).
    bool hideProgressBarTemporarily = false; // true indicates temporarily hiding the progress bar (during UI option popups).
    bool retainedForReuse = false;           // true indicates retention after the terminal state for reuse by periodic tasks of the same owner.
};

// KProgress: progress bar manager.
// External capabilities:
// 1) add: Add a task card and return the PID.
// 2) set: Update step and progress;
// 3) UI: Blockingly pop up an option dialog and return the user's selected index (1-based).
class KProgress
{
public:
    // Constructor purpose:
    // - initialize PID auto-increment counter and container.
    KProgress();

    // add:
    // - Add a task record and display it in the task card list.
    // - Returns the PID of the new task, used by subsequent set/UI operations to locate the task.
    // Parameter taskName: Task name (card title).
    // Parameter stepName: initial step text.
    // Return value: PID of the new task (greater than 0).
    int add(const std::string& taskName, const std::string& stepName);

    // add (owner binding version) purpose:
    // - Create a one-time task that is automatically removed when the owner is destroyed.
    // - Suitable for asynchronous UI operations to prevent zombie tasks from lingering after the page is closed.
    int add(QObject* owner, const std::string& taskName, const std::string& stepName);

    // addReusable:
    // - Create a periodic task that can be set again after completion;
    // - Automatically removed when owner is destroyed to avoid cross-page lifecycle leaks.
    int addReusable(QObject* owner, const std::string& taskName, const std::string& stepName);

    // set:
    // - Update the step text and progress for the specified PID.
    // - Automatically hides the task card when progressValue is normalized to 1.0.
    // Parameter pid: Target process PID.
    // Parameter stepName: new step text.
    // Parameter stepCode: Step status code (business reserved field).
    // Parameter progressValue:
    // - Supports [0,1] ratio values (e.g., 0.7);
    // - Also supports [0,100] percentage values (e.g., 70.0f, which is automatically converted to 0.7).
    void set(int pid, const std::string& stepName, int stepCode, float progressValue);

    // UI (vector version) purpose:
    // - Blocks to display the options dialog;
    // - Temporarily hide the progress bar for this PID during dialog display; restore it after selection ends.
    // Parameter pid: Target process PID.
    // Parameter prompt: Dialog prompt text.
    // Parameter options: Button option array (mapped to return index in order).
    // Return value:
    // - 1..N: The user selected the Nth option;
    // - 0: User cancelled or no options available.
    int ui(int pid, const std::string& prompt, const std::vector<std::string>& options);

    // UI (variadic version) purpose:
    // - Syntax sugar overload supporting UI(pid, "prompt", "Option A", "Option B", ...).
    // Parameters pid/prompt: same meaning as above.
    // Parameter options: Variadic option list, must be constructible from std::string.
    // Return value: Same as the vector version.
    template <typename... TOptions>
    int ui(int pid, const std::string& prompt, const TOptions&... options)
    {
        // Unify variadic arguments into a vector to reuse the main implementation.
        const std::vector<std::string> kOptionList{ std::string(options)... };
        return ui(pid, prompt, kOptionList);
    }

    // Snapshot:
    // - Returns a snapshot copy of all current tasks (including hidden markers).
    // Return value: Copy of the task array.
    std::vector<KProgressTask> snapshot() const;

    // Revision:
    // - Increments with every add/set/UI state transition;
    // - UI can use this value to determine if a refresh is needed.
    // Return value: current revision number.
    std::size_t revision() const;

private:
    // normalizeProgress:
    // - normalize the progress value to [0, 1].
    // - Automatically support percentage notation like '70.0f'.
    // Parameter rawProgress: Raw progress value.
    // Return value: normalized progress.
    static float normalizeProgress(float rawProgress);

    // addInternal purpose: Centralized task creation with optional owner lifecycle binding.
    int addInternal(
        QObject* owner,
        const std::string& taskName,
        const std::string& stepName,
        bool retainedForReuse);

    // pruneTerminalHistoryLocked purpose: Retain only bounded, one-time terminal history states within the lock.
    void pruneTerminalHistoryLocked();

    // removeTasksOwnedBy: Batch-delete all tasks and binding records when the owner is destructed.
    void removeTasksOwnedBy(QObject* owner);

    // setProgressBarHiddenForUi:
    // - Toggle the "temporarily hide progress bar" state before and after UI popups.
    // Parameter pid: Target process PID.
    // Parameter hidden: true hides, false restores.
    void setProgressBarHiddenForUi(int pid, bool hidden);

private:
    mutable std::mutex mutex_;             // Thread lock protecting the task container and revision number.
    std::vector<KProgressTask> tasks_;     // Progress task container.
    std::unordered_map<int, QObject*> taskOwners_; // Record owner bindings and synchronize cleanup when tasks are deleted.
    std::unordered_set<QObject*> boundOwners_;     // Each active owner retains at most one destroyed callback.
    int nextPid_ = 1;                      // Next assignable PID (incrementing).
    std::size_t revision_ = 0;             // Task data revision number.
};

// Global progress manager for UI and business code.
// Logging globals are declared by ksword/log/log.h via Ksword.h.
extern KProgress kPro;
