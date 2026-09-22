#pragma once

// Process-level serialization lock for DbgHelp.
//
// Microsoft explicitly states "All DbgHelp functions, such as this one, are single threaded." — this is a
// constraint on the **entire DLL**, not per session. There are currently two usages of DbgHelp in this process:
//
//   * shared/ark_client/ArkRuntimeDynData.cpp — PDB parsing for kernel structure offsets.
//   * ksword/process/injection_stack_walk.cpp —— Cross-process stack unwind for injection checks
//
// Each location holds its own file-local mutex, which is equivalent to no locking: both can enter DbgHelp
// simultaneously. Therefore, the lock must be placed here for shared use by both sides. The lock scope must
// cover SymInitialize, SymCleanup, option settings, and all intermediate calls, not just 'that single query'.
//
// Place only one function-local static: avoids global construction order issues; header-only, no .cpp needed.

#include <mutex>

namespace ks::dbghelp
{
    inline std::mutex& serializationMutex()
    {
        static std::mutex mutex;
        return mutex;
    }
}
