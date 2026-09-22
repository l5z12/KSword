#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    const std::vector<TerminateMethodEntry>& terminateMethodTable()
    {
        static const std::vector<TerminateMethodEntry> kTable =
        {
            // Directly request the kernel to terminate the process. This is the most common approach but is most easily blocked by kernel callbacks.
            { "TerminateProcess(Kernel32)", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByWin32(pid, d); } },
            { "NtTerminateProcess/ZwTerminateProcess", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByNtNative(pid, d); } },

            // Please let the session/terminal service terminate it. It uses a separate service process, so
            // it does not consume the caller's handle permissions, but the target must belong to a session.
            { "WTSTerminateProcess(WTS API)", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByWtsApi(pid, d); } },
            { "WinStationTerminateProcess(winsta)", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByWinStationApi(pid, d); } },

            // Tie the job object to the process. If the target is not in any Job, this group
            // fails together; knowing this avoids retrying the other entry in the group.
            { "TerminateJobObject(Job)", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByJobObject(pid, d); } },
            { "NtTerminateJobObject/ZwTerminateJobObject", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByNtJobObject(pid, d); } },

            // Let the Restart Manager handle it. It will first attempt a graceful exit for the target; the force option is for forced termination.
            { "RmShutdown(Restart Manager)", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByRestartManager(pid, false, d); } },
            { "RmShutdown(Restart Manager, force)", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByRestartManager(pid, true, d); } },

            // Bypass failures like 'unable to obtain a valid handle'.
            { "DuplicateHandle(-1)+TerminateProcess", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByDuplicateHandlePseudo(pid, d); } },

            // Do not terminate the process itself; instead, kill its threads one by one. The process object remains
            // until the last thread exits, so the target may still appear in the list for a short time after "success".
            { "TerminateThread(全部线程)", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateAllThreadsByPid(pid, d); } },
            { "NtTerminateThread/ZwTerminateThread(全部线程)", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateAllThreadsByPidNtNative(pid, d); } },

            // Uses debugger identity. After successful attachment, detaching and killing is often effective for targets that
            // refuse normal termination, but the entire group fails if the target is already attached to another debugger.
            { "DebugActiveProcess 调试附加", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByDebugAttach(pid, d); } },
            { "ntsd -c q -p <pid>", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByNtsdCommand(pid, d); } },

            // This method differs from all others above: it **does not ask anyone to terminate
            // the process**; instead, it removes the target's required mappings to force a crash.
            // Thus, there is no 'graceful exit', and the target may simply become unstable. It is
            // grouped separately to make this distinction visible before selection.
            { "NtUnmapViewOfSection 卸载 ntdll.dll", [](std::uint32_t pid, std::string* d)
                { return ks::process::terminateProcessByNtUnmapNtdll(pid, d); } }
        };
        return kTable;
    }

    // isProcessPresentBySnapshot:
    // - Check if target PID still exists via Toolhelp process snapshot;
    // - Used for real-time liveness verification after each step of the 'Terminate Process' batch action.
    // Call pattern: called internally in a loop by ProcessDock::executeTerminateProcessAction.
    // Parameter targetPid: Target process PID.
    // Parameter queryOkOut: snapshot query success status (nullable).
    // Return value: true = process still exists (or conservatively treated as existing on query failure); false = process does not exist.
    bool isProcessPresentBySnapshot(const std::uint32_t targetPid, bool* const queryOkOut)
    {
        if (queryOkOut != nullptr)
        {
            *queryOkOut = false;
        }

        // snapshotHandle: Receives the system process snapshot handle for subsequent PID enumeration.
        const HANDLE kSnapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (kSnapshotHandle == INVALID_HANDLE_VALUE)
        {
            return true;
        }

        // processEntry usage: read process snapshot records one by one and compare PIDs.
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(kSnapshotHandle, &processEntry) == FALSE)
        {
            ::CloseHandle(kSnapshotHandle);
            return true;
        }

        // processPresent usage: Records whether the target PID was hit in the current snapshot.
        bool processPresent = false;
        do
        {
            if (processEntry.th32ProcessID == targetPid)
            {
                processPresent = true;
                break;
            }
        } while (::Process32NextW(kSnapshotHandle, &processEntry) != FALSE);

        ::CloseHandle(kSnapshotHandle);
        if (queryOkOut != nullptr)
        {
            *queryOkOut = true;
        }
        return processPresent;
    }

    // waitForProcessExitAfterSuccessfulTerminate：
    // - After the termination API receives the request, wait for a fixed 200ms on the target process handle.
    // - Stop the combination chain only when the handle is triggered; if a timeout occurs, proceed to the next termination method.
    // - If the sync handle cannot be opened, conservatively continue the chain to avoid misjudging 'unable to observe' as 'already exited'.
    bool waitForProcessExitAfterSuccessfulTerminate(
        const std::uint32_t targetPid,
        std::string* const detailTextOut)
    {
        constexpr DWORD kSuccessfulTerminateWaitMilliseconds = 200U;
        const HANDLE kProcessHandle = ::OpenProcess(SYNCHRONIZE, FALSE, targetPid);
        if (kProcessHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatProcessWin32Error(
                    "OpenProcess(SYNCHRONIZE)",
                    ::GetLastError());
            }
            return false;
        }

        const DWORD kWaitResult = ::WaitForSingleObject(
            kProcessHandle,
            kSuccessfulTerminateWaitMilliseconds);
        const DWORD kWaitError = kWaitResult == WAIT_FAILED ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(kProcessHandle);
        if (kWaitResult == WAIT_OBJECT_0)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process handle signaled within 200ms";
            }
            return true;
        }
        if (detailTextOut != nullptr)
        {
            *detailTextOut = kWaitResult == WAIT_TIMEOUT
                ? "process handle remained unsignaled after 200ms"
                : formatProcessWin32Error("WaitForSingleObject", kWaitError);
        }
        return false;
    }
}
