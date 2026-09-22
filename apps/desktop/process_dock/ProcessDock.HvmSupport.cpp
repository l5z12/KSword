#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    /*
     * Address pre-filled in the R-1 process handling dialog: Entry point of the target main module.
     *
     * This is merely a **default value**, not the correct answer. The entry point is valid only for newly started
     * processes; for processes already in a message loop, it may never be executed again. A non-executed entry point is
     * equivalent to no action. Therefore, the UI places it in a user-editable input box rather than fixing it for the user.
     *
     * If retrieval fails, return 0; display a prominent 0x0 in the input box to force the caller to fill it manually.
     */
    std::uint64_t hvmProcessEntryPointAddress(const std::uint32_t processId)
    {
        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            processId);
        if (kProcessHandle == nullptr)
        {
            return 0ULL;
        }
        std::uint64_t entryPoint = 0ULL;
        HMODULE mainModule = nullptr;
        DWORD neededBytes = 0UL;
        // The first module is the main image; only retrieve it, do not enumerate the entire table.
        if (::EnumProcessModules(
                kProcessHandle,
                &mainModule,
                sizeof(mainModule),
                &neededBytes) != FALSE)
        {
            MODULEINFO moduleInfo{};
            if (::GetModuleInformation(
                    kProcessHandle,
                    mainModule,
                    &moduleInfo,
                    sizeof(moduleInfo)) != FALSE)
            {
                entryPoint =
                    reinterpret_cast<std::uint64_t>(moduleInfo.EntryPoint);
            }
        }
        ::CloseHandle(kProcessHandle);
        return entryPoint;
    }

    /*
     * Get the address of a thread in the target process **currently executing**.
     *
     * One-click operations require this: the entry point executes only once at startup. Pinning a
     * process already in a message loop to the entry page is equivalent to doing nothing—yet 'doing
     * nothing' looks identical to success from the outside. This is the most expensive failure mode
     * for such mechanisms. The thread's current RIP, by definition, is the page that will be executed.
     *
     * Suspension is mandatory: without it, the RIP obtained from GetThreadContext is meaningless (the thread is running, so the
     * read value may be an arbitrary intermediate state). The suspension window lasts only as long as a single context fetch.
     *
     * Return 0 if not found; the caller falls back to the entry point and allows manual modification.
     */
    std::uint64_t hvmProcessRunningThreadRip(const std::uint32_t processId)
    {
        const HANDLE kSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0UL);
        if (kSnapshot == INVALID_HANDLE_VALUE)
        {
            return 0ULL;
        }
        std::uint64_t rip = 0ULL;
        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(kSnapshot, &threadEntry) != FALSE)
        {
            do
            {
                if (threadEntry.th32OwnerProcessID != processId)
                {
                    continue;
                }
                const HANDLE kThreadHandle = ::OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE,
                    threadEntry.th32ThreadID);
                if (kThreadHandle == nullptr)
                {
                    continue;
                }
                if (::SuspendThread(kThreadHandle) != static_cast<DWORD>(-1))
                {
                    CONTEXT threadContext{};
                    threadContext.ContextFlags = CONTEXT_CONTROL;
                    if (::GetThreadContext(kThreadHandle, &threadContext) != FALSE)
                    {
                        rip = static_cast<std::uint64_t>(threadContext.Rip);
                    }
                    ::ResumeThread(kThreadHandle);
                }
                ::CloseHandle(kThreadHandle);
                // One is sufficient: any executing thread must be on a page that will be executed.
                if (rip != 0ULL)
                {
                    break;
                }
            } while (::Thread32Next(kSnapshot, &threadEntry) != FALSE);
        }
        ::CloseHandle(kSnapshot);
        return rip;
    }

    // enumHvmInjectWakeProc:
    // - Input: Win32 top-level window enumeration callback parameter;
    // - Processing: Send a WM_NULL message to windows belonging to the target process; skip others.
    // - Return: Always TRUE—the entire process, not a single window, is to be woken.
    BOOL CALLBACK enumHvmInjectWakeProc(HWND windowHandle, LPARAM parameter)
    {
        auto* const kContext = reinterpret_cast<HvmInjectWakeContext*>(parameter);
        if (kContext == nullptr || windowHandle == nullptr)
        {
            return TRUE;
        }
        DWORD owningProcessId = 0UL;
        (void)::GetWindowThreadProcessId(windowHandle, &owningProcessId);
        if (owningProcessId != kContext->processId)
        {
            return TRUE;
        }
        if (::PostMessageW(windowHandle, WM_NULL, 0U, 0L) != FALSE)
        {
            kContext->postedCount += 1U;
        }
        return TRUE;
    }

    /*
     * hvmProcessWakeMessageLoops:
     * - Input parameter processId: Target process PID.
     * - Handling: Send a WM_NULL message to each of its top-level windows.
     * - Returns: the number of successfully dispatched windows; 0 indicates the target has no top-level windows.
     *
     * This is not part of the injection itself, but provides an opportunity for the injection to occur. R-1 injection is a **trap**, not a push:
     * This triggers only when the target itself executes to the hijacked page. Idle process threads remain stuck in
     * waiting; that page may never be executed—yet this is indistinguishable from a failure occurring externally.
     *
     * WM_NULL is the lowest-cost wake: it writes no target memory, creates no threads, and changes no state; it
     * simply returns a thread blocked in GetMessage to user mode to resume execution on its original page.
     * However, it remains a user-mode interaction visible to message hooks, so it is used only when the execution
     * count is still zero, and the result must explicitly state this step was taken, not done silently.
     */
    std::size_t hvmProcessWakeMessageLoops(const unsigned long processId)
    {
        HvmInjectWakeContext context;
        context.processId = processId;
        (void)::EnumWindows(
            &enumHvmInjectWakeProc,
            reinterpret_cast<LPARAM>(&context));
        return context.postedCount;
    }

    /*
     * hvmInjectExecutionCount:
     * - Input parameter processId: The PID used for the injection command;
     * - Processing: Read back the execution count for the entry in the R-1 injection table that has already been executed.
     * - Returns: the execution count; 0 if the entry is missing or unreadable.
     *
     * The return code alone cannot distinguish between 'installed' and 'executed': a successful installation with a payload that never
     * runs looks identical to a successful execution. The execution count is the only metric that separates these two scenarios.
     */
    unsigned long long hvmInjectExecutionCount(const unsigned long processId)
    {
        ksword::ark::DriverClient client;
        const ksword::ark::HvmInjectResult kResult = client.controlHvmInject(
            KSWORD_ARK_HVM_INJECT_OP_QUERY,
            processId,
            0UL,
            0ULL,
            0ULL,
            nullptr,
            0UL,
            true);
        if (!kResult.io.ok ||
            kResult.response.status != KSWORD_ARK_HVM_INJECT_STATUS_OK)
        {
            return 0ULL;
        }
        const unsigned long kRowCount = std::min<unsigned long>(
            kResult.response.returnedRows,
            KSWORD_ARK_HVM_MAX_INJECTIONS);
        for (unsigned long index = 0UL; index < kRowCount; ++index)
        {
            if (kResult.response.rows[index].processId == processId)
            {
                return kResult.response.rows[index].executionCount;
            }
        }
        return 0ULL;
    }

    /*
     * hvmInjectWaitForExecution:
     * - Parameter processId: Target PID; timeoutMilliseconds: Maximum wait duration.
     * - Processing: Poll execution count; return immediately if non-zero.
     * - Returns: Observed execution count.
     *
     * Deliberately avoid extracting the event loop here: the resident component was just stopped and restarted, so the UI is
     * already blocked longer; allowing user actions during the two-second wait for injection results would only cause reentrancy.
     */
    unsigned long long hvmInjectWaitForExecution(
        const unsigned long processId,
        const unsigned long long timeoutMilliseconds)
    {
        const unsigned long long kDeadline =
            ::GetTickCount64() + timeoutMilliseconds;
        for (;;)
        {
            const unsigned long long kExecuted =
                hvmInjectExecutionCount(processId);
            if (kExecuted != 0ULL || ::GetTickCount64() >= kDeadline)
            {
                return kExecuted;
            }
            ::Sleep(50UL);
        }
    }
}
