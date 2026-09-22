#include "InjectionStackWalk.h"

#include "../DbgHelpSerialization.h"

#include <DbgHelp.h>
#include <TlHelp32.h>

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>

namespace ev = ksword::evidence;

namespace ks::process
{
    namespace
    {
        // --- NtQuerySystemInformation: Thread State ---------------------------------
        // Determines if a thread is in a waiting state. Toolhelp cannot provide this, and
        // GetThreadContext does not guarantee the snapshot is stable or not changing.

        using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

        constexpr ULONG kSystemProcessInformation = 5UL;
        // KTHREAD_STATE::Waiting. Retrieving context requires the thread to be **stopped**; only this value is valid:
        // Ready/Running/Standby all indicate that the thread may resume execution on another core at any time.
        constexpr ULONG kThreadStateWaiting = 5UL;

        struct SystemThreadInformation final
        {
            LARGE_INTEGER kernelTime;
            LARGE_INTEGER userTime;
            LARGE_INTEGER createTime;
            ULONG waitTime;
            PVOID startAddress;
            struct
            {
                HANDLE uniqueProcess;
                HANDLE uniqueThread;
            } clientId;
            LONG priority;
            LONG basePriority;
            ULONG contextSwitches;
            ULONG threadState;
            ULONG waitReason;
        };

        // UNICODE_STRING is declared in winternl.h/ntdef.h; this file only includes Windows.h.
        // Only its **layout** is needed here (we do not read the process name), so we implement it manually based on public documentation.
        struct UnicodeStringField final
        {
            USHORT length;
            USHORT maximumLength;
            PWSTR buffer;
        };

        struct SystemProcessInformationHeader final
        {
            ULONG nextEntryOffset;
            ULONG numberOfThreads;
            LARGE_INTEGER workingSetPrivateSize;
            ULONG hardFaultCount;
            ULONG numberOfThreadsHighWatermark;
            ULONGLONG cycleTime;
            LARGE_INTEGER createTime;
            LARGE_INTEGER userTime;
            LARGE_INTEGER kernelTime;
            UnicodeStringField imageName;
            LONG basePriority;
            HANDLE uniqueProcessId;
            HANDLE inheritedFromUniqueProcessId;
            ULONG handleCount;
            ULONG sessionId;
            ULONG_PTR uniqueProcessKey;
            SIZE_T peakVirtualSize;
            SIZE_T virtualSize;
            ULONG pageFaultCount;
            SIZE_T peakWorkingSetSize;
            SIZE_T workingSetSize;
            SIZE_T quotaPeakPagedPoolUsage;
            SIZE_T quotaPagedPoolUsage;
            SIZE_T quotaPeakNonPagedPoolUsage;
            SIZE_T quotaNonPagedPoolUsage;
            SIZE_T pagefileUsage;
            SIZE_T peakPagefileUsage;
            SIZE_T privatePageCount;
            LARGE_INTEGER readOperationCount;
            LARGE_INTEGER writeOperationCount;
            LARGE_INTEGER otherOperationCount;
            LARGE_INTEGER readTransferCount;
            LARGE_INTEGER writeTransferCount;
            LARGE_INTEGER otherTransferCount;
        };

        NtQuerySystemInformationFn resolveNtQuerySystemInformation()
        {
            static const NtQuerySystemInformationFn kFn = []() -> NtQuerySystemInformationFn {
                const HMODULE kNtdll = ::GetModuleHandleW(L"ntdll.dll");
                if (kNtdll == nullptr)
                {
                    return nullptr;
                }
                return reinterpret_cast<NtQuerySystemInformationFn>(
                    reinterpret_cast<void*>(
                        ::GetProcAddress(kNtdll, "NtQuerySystemInformation")));
            }();
            return kFn;
        }

        // tid -> threadState. If not found, return an empty map rather than treating all as waiting.
        std::map<std::uint32_t, ULONG> queryThreadStates(const std::uint32_t pid)
        {
            std::map<std::uint32_t, ULONG> states;
            const NtQuerySystemInformationFn kQuery = resolveNtQuerySystemInformation();
            if (kQuery == nullptr)
            {
                return states;
            }

            // The process table may grow between calls, so retry several rounds based on the returned required size.
            ULONG needed = 512U * 1024U;
            std::vector<std::uint8_t> buffer;
            LONG status = 0;
            for (int attempt = 0; attempt < 6; ++attempt)
            {
                buffer.assign(needed, 0U);
                ULONG produced = 0U;
                status = kQuery(kSystemProcessInformation, buffer.data(),
                               static_cast<ULONG>(buffer.size()), &produced);
                if (status >= 0)
                {
                    break;
                }
                // STATUS_INFO_LENGTH_MISMATCH: Retry with the kernel-reported size plus an additional margin.
                needed = (produced > needed ? produced : needed * 2U) + 64U * 1024U;
            }
            if (status < 0)
            {
                return states;
            }

            std::size_t offset = 0U;
            while (offset + sizeof(SystemProcessInformationHeader) <= buffer.size())
            {
                const auto* const kHeader =
                    reinterpret_cast<const SystemProcessInformationHeader*>(buffer.data() + offset);
                if (reinterpret_cast<ULONG_PTR>(kHeader->uniqueProcessId) ==
                    static_cast<ULONG_PTR>(pid))
                {
                    const std::size_t kThreadsOffset =
                        offset + sizeof(SystemProcessInformationHeader);
                    for (ULONG index = 0U; index < kHeader->numberOfThreads; ++index)
                    {
                        const std::size_t kAt =
                            kThreadsOffset + index * sizeof(SystemThreadInformation);
                        if (kAt + sizeof(SystemThreadInformation) > buffer.size())
                        {
                            break;
                        }
                        const auto* const kThread =
                            reinterpret_cast<const SystemThreadInformation*>(buffer.data() + kAt);
                        states[static_cast<std::uint32_t>(
                            reinterpret_cast<ULONG_PTR>(kThread->clientId.uniqueThread))] =
                            kThread->threadState;
                    }
                    break;
                }
                if (kHeader->nextEntryOffset == 0U)
                {
                    break;
                }
                offset += kHeader->nextEntryOffset;
            }
            return states;
        }

        // --- .pdata for Each Module ---------------------------------------------------

        struct ModuleUnwindTable final
        {
            std::uint64_t imageBase = 0U;
            std::uint64_t imageSize = 0U;
            // The RUNTIME_FUNCTION table read back from the target is sorted in ascending order by BeginAddress (as required by the PE spec;
            // no additional sorting is performed). A disordered table indicates an untrusted image, so the lookup is intentionally skipped.
            std::vector<RUNTIME_FUNCTION> functions;
            // Whether the image has a non-empty exception directory. This bit is the basis for determining "whether the next frame relies on unwind data":
            // In such images, functions either have table entries or are leaf functions (ABI guarantees
            // [RSP] is the return address). In both cases, the frame is computed, not guessed.
            bool hasExceptionDirectory = false;
        };

        // Traverse all states during a single unwind. DbgHelp's callback signature lacks a user context pointer,
        // so we must pass the current walker via thread_local — this is the standard usage for this API set.
        class StackWalkContext final
        {
        public:
            explicit StackWalkContext(HANDLE process) : process_(process) {}

            bool readMemory(const DWORD64 address, void* const buffer, const DWORD size,
                            LPDWORD readOut)
            {
                SIZE_T read = 0U;
                const BOOL kOk = ::ReadProcessMemory(
                    process_, reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(address)),
                    buffer, size, &read);
                if (readOut != nullptr)
                {
                    *readOut = static_cast<DWORD>(read);
                }
                return kOk != FALSE && read == size;
            }

            // Returns the base address of the image containing the PC; returns 0 if not in an image (private memory or mapped non-image).
            std::uint64_t moduleBase(const DWORD64 address)
            {
                const ModuleUnwindTable* const kTable = tableFor(address);
                return kTable == nullptr ? 0U : kTable->imageBase;
            }

            // StackWalk64 requires a RUNTIME_FUNCTION pointer valid within the **current process address space**,
            // so it returns the address from the cache, which remains valid until the entire unwind completes.
            PRUNTIME_FUNCTION functionEntry(const DWORD64 address)
            {
                const ModuleUnwindTable* const kTable = tableFor(address);
                if (kTable == nullptr || kTable->functions.empty())
                {
                    return nullptr;
                }
                const auto kRva = static_cast<std::uint32_t>(address - kTable->imageBase);
                // Find the last entry where BeginAddress <= rva, then verify rva actually falls within it.
                const auto kHit = std::upper_bound(
                    kTable->functions.begin(), kTable->functions.end(), kRva,
                    [](const std::uint32_t value, const RUNTIME_FUNCTION& entry) {
                        return value < entry.BeginAddress;
                    });
                if (kHit == kTable->functions.begin())
                {
                    return nullptr;
                }
                const RUNTIME_FUNCTION& entry = *(kHit - 1);
                if (kRva >= entry.EndAddress)
                {
                    // Falls between two functions: this is a leaf function or code not in the table, not a table entry.
                    return nullptr;
                }
                return const_cast<PRUNTIME_FUNCTION>(&entry);
            }

            // Check whether the image containing this PC has an exception directory. See the comments in ModuleUnwindTable.
            bool pcCoveredByUnwindData(const std::uint64_t address)
            {
                const ModuleUnwindTable* const kTable = tableFor(address);
                return kTable != nullptr && kTable->hasExceptionDirectory;
            }

        private:
            const ModuleUnwindTable* tableFor(const DWORD64 address)
            {
                MEMORY_BASIC_INFORMATION info{};
                if (::VirtualQueryEx(process_,
                                     reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(address)),
                                     &info, sizeof(info)) != sizeof(info))
                {
                    return nullptr;
                }
                if (info.Type != MEM_IMAGE || info.AllocationBase == nullptr)
                {
                    // Private memory / non-image mapping — this is where the shellcode resides. No unwind data available.
                    return nullptr;
                }
                const auto kBase =
                    static_cast<std::uint64_t>(reinterpret_cast<ULONG_PTR>(info.AllocationBase));
                const auto kCached = tables_.find(kBase);
                if (kCached != tables_.end())
                {
                    return kCached->second ? &*kCached->second : nullptr;
                }
                std::unique_ptr<ModuleUnwindTable> table = loadTable(kBase);
                const ModuleUnwindTable* const kResult = table ? table.get() : nullptr;
                tables_.emplace(kBase, std::move(table));
                return kResult;
            }

            std::unique_ptr<ModuleUnwindTable> loadTable(const std::uint64_t base)
            {
                // Headers: DOS -> NT. Only read the necessary fields; full PE parsing is
                // handled by PeImageMap. No relocation or section mapping is performed here.
                std::uint8_t headers[0x1000] = {};
                SIZE_T read = 0U;
                if (::ReadProcessMemory(process_,
                                        reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(base)),
                                        headers, sizeof(headers), &read) == FALSE ||
                    read < sizeof(IMAGE_DOS_HEADER))
                {
                    return nullptr;
                }
                const auto* const kDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
                if (kDos->e_magic != IMAGE_DOS_SIGNATURE || kDos->e_lfanew < 0)
                {
                    return nullptr;
                }
                const auto kNtOffset = static_cast<std::size_t>(kDos->e_lfanew);
                if (kNtOffset + sizeof(IMAGE_NT_HEADERS64) > read)
                {
                    return nullptr;
                }
                const auto* const kNt =
                    reinterpret_cast<const IMAGE_NT_HEADERS64*>(headers + kNtOffset);
                if (kNt->Signature != IMAGE_NT_SIGNATURE ||
                    kNt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
                    kNt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    return nullptr;
                }

                auto table = std::make_unique<ModuleUnwindTable>();
                table->imageBase = base;
                table->imageSize = kNt->OptionalHeader.SizeOfImage;

                if (kNt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                {
                    return table;  // No exception directory: valid, but the next frame must rely on guessing.
                }
                const IMAGE_DATA_DIRECTORY& directory =
                    kNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (directory.VirtualAddress == 0U || directory.Size < sizeof(RUNTIME_FUNCTION))
                {
                    return table;
                }
                // The directory must fit entirely within the image. Otherwise, the header cannot be trusted; discard the entire block.
                if (static_cast<std::uint64_t>(directory.VirtualAddress) + directory.Size >
                    table->imageSize)
                {
                    return table;
                }

                const std::size_t kCount = directory.Size / sizeof(RUNTIME_FUNCTION);
                if (kCount == 0U || kCount > kMaxRuntimeFunctions)
                {
                    return table;
                }
                std::vector<RUNTIME_FUNCTION> functions(kCount);
                SIZE_T tableRead = 0U;
                if (::ReadProcessMemory(
                        process_,
                        reinterpret_cast<LPCVOID>(
                            static_cast<ULONG_PTR>(base + directory.VirtualAddress)),
                        functions.data(), kCount * sizeof(RUNTIME_FUNCTION), &tableRead) == FALSE ||
                    tableRead != kCount * sizeof(RUNTIME_FUNCTION))
                {
                    return table;
                }
                table->functions = std::move(functions);
                table->hasExceptionDirectory = true;
                return table;
            }

            // ntdll's .pdata section has about 20,000 entries; allocate three times that as a buffer. Anything larger indicates a modified header.
            static constexpr std::size_t kMaxRuntimeFunctions = 65536U;

            HANDLE process_ = nullptr;
            // A null value indicates "this base address has been checked and no table is available", avoiding repeated reads.
            std::map<std::uint64_t, std::unique_ptr<ModuleUnwindTable>> tables_;
        };

        thread_local StackWalkContext* tContext = nullptr;

        BOOL __stdcall readMemoryCallback(HANDLE, const DWORD64 address, PVOID buffer,
                                          const DWORD size, LPDWORD readOut)
        {
            if (tContext == nullptr)
            {
                return FALSE;
            }
            return tContext->readMemory(address, buffer, size, readOut) ? TRUE : FALSE;
        }

        PVOID __stdcall functionTableAccessCallback(HANDLE, const DWORD64 address)
        {
            if (tContext == nullptr)
            {
                return nullptr;
            }
            return tContext->functionEntry(address);
        }

        DWORD64 __stdcall getModuleBaseCallback(HANDLE, const DWORD64 address)
        {
            if (tContext == nullptr)
            {
                return 0U;
            }
            return tContext->moduleBase(address);
        }

        struct ScopedThreadHandle final
        {
            HANDLE handle = nullptr;
            ~ScopedThreadHandle()
            {
                if (handle != nullptr)
                {
                    ::CloseHandle(handle);
                }
            }
        };
    }

    StackWalkResult walkProcessStacks(HANDLE process,
                                      const std::uint32_t pid,
                                      const ev::ProcessInstanceId& owner,
                                      const ev::ProcessArchitecture architecture,
                                      const StackWalkOptions& options)
    {
        StackWalkResult result;

        // Only support native x64. Using the x64 unwinder to walk a WOW64 32-bit stack produces garbage frames that look like valid frames; once
        // such garbage frames enter the reliable prefix, they artificially inflate the conclusion. It is better to skip the entire section.
        if (architecture != ev::ProcessArchitecture::kX64)
        {
            result.diagnostic = "stack walk skipped: target is not native x64";
            return result;
        }
        if (process == nullptr)
        {
            result.diagnostic = "stack walk skipped: no process handle";
            return result;
        }

        const std::map<std::uint32_t, ULONG> kStatesBefore = queryThreadStates(pid);
        if (kStatesBefore.empty())
        {
            // If thread states cannot be found, the context's trustworthiness cannot be determined; do not proceed rather than assuming all threads are waiting.
            result.diagnostic = "stack walk skipped: thread states unavailable";
            return result;
        }
        result.attempted = true;

        const ScopedThreadHandle kSnapshot{ ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0U) };
        if (kSnapshot.handle == INVALID_HANDLE_VALUE || kSnapshot.handle == nullptr)
        {
            result.diagnostic = "stack walk skipped: thread snapshot failed";
            result.attempted = false;
            return result;
        }

        std::vector<std::uint32_t> candidates;
        std::uint32_t matchedStates = 0U;
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (::Thread32First(kSnapshot.handle, &entry) != FALSE)
        {
            do
            {
                if (entry.th32OwnerProcessID != pid)
                {
                    continue;
                }
                ++result.threadsConsidered;
                const auto kState = kStatesBefore.find(entry.th32ThreadID);
                if (kState == kStatesBefore.end())
                {
                    continue;
                }
                ++matchedStates;
                if (kState->second != kThreadStateWaiting)
                {
                    continue;
                }
                ++result.threadsWaiting;
                if (candidates.size() < options.maxThreads)
                {
                    candidates.push_back(entry.th32ThreadID);
                }
            } while (::Thread32Next(kSnapshot.handle, &entry) != FALSE);
        }

        // The layouts of SYSTEM_PROCESS_INFORMATION and SYSTEM_THREAD_INFORMATION are hand-coded based on public documentation.
        // If written incorrectly, the result is "parsing out a bunch of garbage TIDs"—which silently degrades to "no waiting
        // threads," looking identical to "the process is indeed running." Therefore, a check is established here: the number of
        // threads counted by Toolhelp must have a significant portion found in the state table. If none match, it indicates a
        // layout error and is explicitly reported, rather than pretending to have checked and found nothing.
        if (result.threadsConsidered != 0U && matchedStates * 2U < result.threadsConsidered)
        {
            result.attempted = false;
            result.threadsWaiting = 0U;
            result.diagnostic = "stack walk skipped: thread state layout mismatch";
            return result;
        }

        if (candidates.empty())
        {
            return result;  // When attempted=true and stacks is empty, the predicate layer records a gap.
        }

        StackWalkContext context(process);
        // DbgHelp is a single-threaded DLL; the lock must cover all StackWalk64 calls.
        std::lock_guard<std::mutex> dbgHelpLock(ks::dbghelp::serializationMutex());
        tContext = &context;
        struct ContextReset final
        {
            ~ContextReset() { tContext = nullptr; }
        } contextReset;

        for (const std::uint32_t kTid : candidates)
        {
            ev::ThreadStackInput stack;
            stack.thread.process = owner;
            stack.thread.tid = ev::OptionalU64::of(static_cast<std::uint64_t>(kTid));

            const ScopedThreadHandle kThread{
                ::OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, kTid)
            };
            if (kThread.handle == nullptr)
            {
                const DWORD kError = ::GetLastError();
                stack.outcome = ev::CollectionOutcome::failure(
                    ev::CollectionStatus::kAccessDenied, "Win32",
                    static_cast<std::uint64_t>(kError), std::string());
                result.stacks.push_back(std::move(stack));
                continue;
            }

            // CONTEXT requires 16-byte alignment; the type has DECLSPEC_ALIGN(16), and stack-local variables satisfy this.
            CONTEXT threadContext{};
            threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (::GetThreadContext(kThread.handle, &threadContext) == FALSE)
            {
                const DWORD kError = ::GetLastError();
                stack.outcome = ev::CollectionOutcome::failure(
                    ev::CollectionStatus::kError, "Win32",
                    static_cast<std::uint64_t>(kError), std::string());
                result.stacks.push_back(std::move(stack));
                continue;
            }

            // Fetch again and verify that RIP, RSP, and RBP match exactly. This is more direct and cheaper than re-checking
            // the thread state: the property we need is that "this set of values did not change during our read," not that
            // "the kernel currently classifies it as waiting." A running thread will almost never yield the exact same
            // three values on two reads, whereas a thread in a waiting state guarantees they remain identical.
            //
            // The window cannot be completely sealed. However, even if a leak occurs, the first return address unwound
            // from the torn context is almost impossible to land in an image with unwind data; the reliable prefix will
            // truncate it immediately. The failure direction is "not claiming reliability," which is the correct path.
            CONTEXT verifyContext{};
            verifyContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            const bool kVerified =
                ::GetThreadContext(kThread.handle, &verifyContext) != FALSE &&
                verifyContext.Rip == threadContext.Rip &&
                verifyContext.Rsp == threadContext.Rsp &&
                verifyContext.Rbp == threadContext.Rbp;
            stack.trust = ev::classifyThreadContextTrust(
                /*captured=*/true, /*suspendedOrSnapshot=*/false,
                /*waitingBeforeAndAfter=*/kVerified);

            STACKFRAME64 frame{};
            frame.AddrPC.Offset = threadContext.Rip;
            frame.AddrPC.Mode = AddrModeFlat;
            frame.AddrFrame.Offset = threadContext.Rbp;
            frame.AddrFrame.Mode = AddrModeFlat;
            frame.AddrStack.Offset = threadContext.Rsp;
            frame.AddrStack.Mode = AddrModeFlat;

            // StackWalk64 modifies the passed-in CONTEXT, so provide a copy.
            CONTEXT walkContext = threadContext;
            bool reachedBottom = false;
            // Whether the previous frame's PC is in an image with unwind data determines whether **this frame** is computed or
            // guessed. The stack-top frame comes directly from thread context with no 'previous frame', so it is always computed.
            bool previousPcCovered = true;
            for (std::size_t depth = 0U; depth < options.maxFrames; ++depth)
            {
                if (::StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, kThread.handle, &frame,
                                  &walkContext, readMemoryCallback,
                                  functionTableAccessCallback, getModuleBaseCallback,
                                  nullptr) == FALSE)
                {
                    reachedBottom = true;
                    break;
                }
                if (frame.AddrPC.Offset == 0U)
                {
                    reachedBottom = true;
                    break;
                }

                ev::RawStackFrame raw;
                raw.instructionPointer = ev::OptionalU64::of(frame.AddrPC.Offset);
                raw.stackPointer = ev::OptionalU64::of(frame.AddrStack.Offset);
                raw.derivedFromUnwindData = previousPcCovered;
                raw.unwindDataAvailableAtPc = context.pcCoveredByUnwindData(frame.AddrPC.Offset);
                previousPcCovered = raw.unwindDataAvailableAtPc;
                stack.frames.push_back(raw);
            }
            if (!reachedBottom && stack.frames.size() >= options.maxFrames)
            {
                // Hitting the limit does not mean 'walked to the end'. Write this explicitly to prevent it from being misread as a complete stack.
                stack.terminationReason = "frame limit reached";
            }

            ++result.threadsWalked;
            result.stacks.push_back(std::move(stack));
        }

        return result;
    }
}
