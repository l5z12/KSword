#pragma once

// Cross-process x64 stack unwinding for injection checks.
//
// This layer performs only collection, **without reliability checks**: it delegates the facts of 'how far
// the unwind reached' and 'whether this PC lies within an image containing unwind data' to admitStackFrames
// in shared/evidence. The criteria are placed there because offline testing exists there but not here.
//
// Why not implement x64 unwinding manually? Application .pdata/.xdata unwind code must correctly handle non-volatile
// registers, UWOP_SET_FPREG, chained unwind info, and epilogues. A buggy unwinder can **mislabel incorrect frames as
// reliable**. Since "reliable frames entering payload memory" is one of the three gates leading to
// DifferenceObserved, an error here is worse than having no stack walk at all. Therefore, we rely on the system's own
// StackWalk64 for unwinding, providing only three callbacks: memory read, module base address, and RUNTIME_FUNCTION.
//
// Why not suspend the target: The hard constraint of this feature is read-only and non-intrusive. Instead, it **only
// recognizes threads in a waiting state**. Microsoft's statement that "running threads cannot obtain a valid context"
// refers to threads executing on other cores; the context of threads blocked in a wait is inherently stable. The most
// critical shellcode pattern (a beacon that sleeps then wakes) happens to reside exactly in this waiting state.

#include "../../evidence/InjectionSurvey.h"

#include <Windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ks::process
{
    struct StackWalkOptions final
    {
        std::size_t maxThreads = 64U;
        // Maximum frames to unwind for a single thread. Normal call stacks resolve within dozens of frames; the upper limit prevents infinite
        // loops in malformed stacks. If the limit is hit, it is recorded in terminationReason and not mistaken for "reached stack bottom".
        std::size_t maxFrames = 64U;
    };

    struct StackWalkResult final
    {
        std::vector<ksword::evidence::ThreadStackInput> stacks;

        std::uint32_t threadsConsidered = 0U;   // Number of threads in this process enumerated.
        std::uint32_t threadsWaiting = 0U;      // Both the previous and current checks are waiting.
        std::uint32_t threadsWalked = 0U;       // Actual unwound count.
        bool attempted = false;                 // false indicates the entire section was skipped (e.g., architecture not supported).
        std::string diagnostic;                 // Non-empty only if the entire section failed.

        bool completed() const noexcept { return attempted && !stacks.empty(); }
    };

    // process requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ.
    // Native x64 targets only: WOW64 and other architectures directly return attempted=false with diagnostics,
    // avoiding the fallback of "forcing x86 stacks with an x64 unwinder" which would produce garbage frames.
    StackWalkResult walkProcessStacks(HANDLE process,
                                      std::uint32_t pid,
                                      const ksword::evidence::ProcessInstanceId& owner,
                                      ksword::evidence::ProcessArchitecture architecture,
                                      const StackWalkOptions& options);
}
