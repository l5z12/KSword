#include "pch.h"
#include "HookEngine.h"

#include <TlHelp32.h>

namespace apimon
{
    namespace
    {
        constexpr std::size_t kAbsoluteJumpSize = 14; // kAbsoluteJumpSize: FF 25 [rip+0] + 8-byte target address, does not modify general-purpose registers.
        thread_local std::uint32_t gInlineHookInternalBypassDepth = 0; // g_inlineHookInternalBypassDepth: Reentrancy bypass depth for internal HookEngine operations.

        class ScopedOtherThreadsSuspender
        {
        public:
            ScopedOtherThreadsSuspender()
            {
                const DWORD kCurrentProcessId = ::GetCurrentProcessId();
                const DWORD kCurrentThreadId = ::GetCurrentThreadId();

                HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (snapshotHandle == INVALID_HANDLE_VALUE)
                {
                    return;
                }

                THREADENTRY32 threadEntry{};
                threadEntry.dwSize = sizeof(threadEntry);
                if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
                {
                    ::CloseHandle(snapshotHandle);
                    return;
                }

                do
                {
                    if (threadEntry.th32OwnerProcessID != kCurrentProcessId
                        || threadEntry.th32ThreadID == kCurrentThreadId)
                    {
                        continue;
                    }

                    HANDLE threadHandle = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
                    if (threadHandle == nullptr)
                    {
                        continue;
                    }

                    if (::SuspendThread(threadHandle) != static_cast<DWORD>(-1))
                    {
                        suspendedThreadHandles_.push_back(threadHandle);
                    }
                    else
                    {
                        ::CloseHandle(threadHandle);
                    }
                } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

                ::CloseHandle(snapshotHandle);
            }

            ~ScopedOtherThreadsSuspender()
            {
                for (auto it = suspendedThreadHandles_.rbegin(); it != suspendedThreadHandles_.rend(); ++it)
                {
                    ::ResumeThread(*it);
                    ::CloseHandle(*it);
                }
            }

        private:
            ScopedInlineHookInternalBypass hookBypass_; // m_hookBypass: Suppresses self-triggered hooks (e.g., OpenThread, SuspendThread) during thread suspension/resumption.
            std::vector<HANDLE> suspendedThreadHandles_;
        };

        std::size_t modRmLength(
            const unsigned char* codePointer,
            const std::size_t maxLength,
            bool* usesRipRelativeOut)
        {
            if (codePointer == nullptr || maxLength < 1)
            {
                return 0;
            }
            if (usesRipRelativeOut != nullptr)
            {
                *usesRipRelativeOut = false;
            }

            std::size_t totalLength = 1;
            const unsigned char kModrmValue = codePointer[0];
            const unsigned char kModValue = static_cast<unsigned char>((kModrmValue >> 6) & 0x3);
            const unsigned char kRmValue = static_cast<unsigned char>(kModrmValue & 0x7);

            if (kModValue != 3 && kRmValue == 4)
            {
                if (maxLength < totalLength + 1)
                {
                    return 0;
                }
                const unsigned char kSibValue = codePointer[totalLength++];
                const unsigned char kBaseValue = static_cast<unsigned char>(kSibValue & 0x7);
                if (kModValue == 0 && kBaseValue == 5)
                {
                    totalLength += 4;
                }
            }

            if (kModValue == 0 && kRmValue == 5)
            {
                if (usesRipRelativeOut != nullptr)
                {
                    *usesRipRelativeOut = true;
                }
                totalLength += 4;
            }
            else if (kModValue == 1)
            {
                totalLength += 1;
            }
            else if (kModValue == 2)
            {
                totalLength += 4;
            }

            return totalLength <= maxLength ? totalLength : 0;
        }

        std::size_t decodeInstructionLength(const unsigned char* codePointer, const std::size_t maxLength)
        {
            if (codePointer == nullptr || maxLength == 0)
            {
                return 0;
            }

            std::size_t offsetValue = 0;
            bool operandOverride = false;
            bool rexW = false;

            while (offsetValue < maxLength)
            {
                const unsigned char kPrefixValue = codePointer[offsetValue];
                if (kPrefixValue == 0x66)
                {
                    operandOverride = true;
                    ++offsetValue;
                    continue;
                }
                if ((kPrefixValue >= 0x40 && kPrefixValue <= 0x4F))
                {
                    rexW = (kPrefixValue & 0x08) != 0;
                    ++offsetValue;
                    continue;
                }
                if (kPrefixValue == 0xF0 || kPrefixValue == 0xF2 || kPrefixValue == 0xF3
                    || kPrefixValue == 0x2E || kPrefixValue == 0x36 || kPrefixValue == 0x3E
                    || kPrefixValue == 0x26 || kPrefixValue == 0x64 || kPrefixValue == 0x65
                    || kPrefixValue == 0x67)
                {
                    ++offsetValue;
                    continue;
                }
                break;
            }

            if (offsetValue >= maxLength)
            {
                return 0;
            }

            const unsigned char kOpcodeValue = codePointer[offsetValue++];
            if ((kOpcodeValue >= 0x50 && kOpcodeValue <= 0x5F)
                || kOpcodeValue == 0x90
                || kOpcodeValue == 0xC3
                || kOpcodeValue == 0xCC)
            {
                return offsetValue;
            }
            if (kOpcodeValue == 0x6A)
            {
                return offsetValue + 1 <= maxLength ? offsetValue + 1 : 0;
            }
            if (kOpcodeValue == 0x68)
            {
                return offsetValue + 4 <= maxLength ? offsetValue + 4 : 0;
            }
            if (kOpcodeValue == 0xE8 || kOpcodeValue == 0xE9 || kOpcodeValue == 0xEB)
            {
                // Copying relative control flow to the trampoline changes its semantics; reject it as unsafe to Hook here.
                return 0;
            }
            if (kOpcodeValue >= 0xB8 && kOpcodeValue <= 0xBF)
            {
                const std::size_t kImmLength = rexW ? 8 : (operandOverride ? 2 : 4);
                return offsetValue + kImmLength <= maxLength ? offsetValue + kImmLength : 0;
            }
            if (kOpcodeValue == 0x0F)
            {
                if (offsetValue >= maxLength)
                {
                    return 0;
                }

                const unsigned char kSecondOpcode = codePointer[offsetValue++];
                if (kSecondOpcode >= 0x80 && kSecondOpcode <= 0x8F)
                {
                    return 0;
                }
                if (kSecondOpcode == 0x1F)
                {
                    bool usesRipRelative = false;
                    const std::size_t kModrmLength = modRmLength(
                        codePointer + offsetValue,
                        maxLength - offsetValue,
                        &usesRipRelative);
                    if (usesRipRelative)
                    {
                        return 0;
                    }
                    return kModrmLength == 0 ? 0 : offsetValue + kModrmLength;
                }
                return 0;
            }

            const auto kAppendModRmInstruction = [&](const std::size_t immediateLength) -> std::size_t {
                bool usesRipRelative = false;
                const std::size_t kModrmLength = modRmLength(
                    codePointer + offsetValue,
                    maxLength - offsetValue,
                    &usesRipRelative);
                if (kModrmLength == 0)
                {
                    return 0;
                }
                if (usesRipRelative)
                {
                    return 0;
                }
                const std::size_t kTotalLength = offsetValue + kModrmLength + immediateLength;
                return kTotalLength <= maxLength ? kTotalLength : 0;
            };

            switch (kOpcodeValue)
            {
            case 0x01:
            case 0x03:
            case 0x09:
            case 0x0B:
            case 0x21:
            case 0x23:
            case 0x29:
            case 0x2B:
            case 0x31:
            case 0x33:
            case 0x39:
            case 0x3B:
            case 0x63:
            case 0x80:
            case 0x84:
            case 0x85:
            case 0x88:
            case 0x89:
            case 0x8A:
            case 0x8B:
            case 0x8D:
                return kAppendModRmInstruction(0);
            case 0x81:
            case 0xC7:
                return kAppendModRmInstruction(4);
            case 0x83:
            case 0xC6:
                return kAppendModRmInstruction(1);
            case 0xFF:
                // 0xFF simultaneously covers multiple semantics such as call/jmp/push; here we uniformly and conservatively reject it.
                return 0;
            case 0xF6:
            case 0xF7:
            {
                // Nt* syscall stubs in modern x64 ntdll commonly take the following form:
                //   F6 04 25 08 03 FE 7F 01    test byte ptr [KUSER_SHARED_DATA+0x308], 1
                // The old decoder does not recognize F6, preventing the installation of inline hooks on Nt* export stubs.
                // Here, only F6/F7 ModRM instructions that copy without altering relative control flow are copied; TEST /0,/1 with an immediate operand, while other unary operations have no immediate operand.
                if (offsetValue >= maxLength)
                {
                    return 0;
                }

                const unsigned char kModrmValue = codePointer[offsetValue];
                const unsigned char kRegValue = static_cast<unsigned char>((kModrmValue >> 3) & 0x7);
                const std::size_t kImmediateLength = (kRegValue == 0 || kRegValue == 1)
                    ? (kOpcodeValue == 0xF6 ? 1 : (operandOverride ? 2 : 4))
                    : 0;
                return kAppendModRmInstruction(kImmediateLength);
            }
            default:
                break;
            }

            return 0;
        }

        // buildAbsoluteJump:
        // - Input: targetBuffer points to at least kAbsoluteJumpSize bytes of writable memory; destinationAddress is the jump target;
        // - Processing: Write an x64 RIP indirect absolute jump stub to avoid breaking the trampoline's restored RAX with mov rax/jmp rax.
        // - Return: No return value; the caller is responsible for flushing the instruction cache afterward.
        void buildAbsoluteJump(unsigned char* targetBuffer, const void* destinationAddress)
        {
            targetBuffer[0] = 0xFF;
            targetBuffer[1] = 0x25;
            targetBuffer[2] = 0x00;
            targetBuffer[3] = 0x00;
            targetBuffer[4] = 0x00;
            targetBuffer[5] = 0x00;
            std::memcpy(targetBuffer + 6, &destinationAddress, sizeof(destinationAddress));
        }

        void* resolveJumpStub(void* addressValue)
        {
            unsigned char* currentPointer = static_cast<unsigned char*>(addressValue);
            for (int depth = 0; depth < 8 && currentPointer != nullptr; ++depth)
            {
                if (currentPointer[0] == 0xE9)
                {
                    const std::int32_t kRelativeOffset = *reinterpret_cast<std::int32_t*>(currentPointer + 1);
                    currentPointer = currentPointer + 5 + kRelativeOffset;
                    continue;
                }
                if (currentPointer[0] == 0xEB)
                {
                    const std::int8_t kRelativeOffset = *reinterpret_cast<std::int8_t*>(currentPointer + 1);
                    currentPointer = currentPointer + 2 + kRelativeOffset;
                    continue;
                }
                if (currentPointer[0] == 0xFF && currentPointer[1] == 0x25)
                {
                    const std::int32_t kRelativeOffset = *reinterpret_cast<std::int32_t*>(currentPointer + 2);
                    void** indirectPointer = reinterpret_cast<void**>(currentPointer + 6 + kRelativeOffset);
                    currentPointer = static_cast<unsigned char*>(*indirectPointer);
                    continue;
                }
                if (currentPointer[0] == 0x48 && currentPointer[1] == 0xFF && currentPointer[2] == 0x25)
                {
                    const std::int32_t kRelativeOffset = *reinterpret_cast<std::int32_t*>(currentPointer + 3);
                    void** indirectPointer = reinterpret_cast<void**>(currentPointer + 7 + kRelativeOffset);
                    currentPointer = static_cast<unsigned char*>(*indirectPointer);
                    continue;
                }
                break;
            }
            return currentPointer;
        }

        std::size_t calculatePatchSize(const unsigned char* codePointer)
        {
            std::size_t patchSize = 0;
            while (patchSize < kAbsoluteJumpSize && patchSize < 24)
            {
                const std::size_t kInstructionLength = decodeInstructionLength(codePointer + patchSize, 24 - patchSize);
                if (kInstructionLength == 0)
                {
                    return 0;
                }
                patchSize += kInstructionLength;
            }
            return patchSize >= kAbsoluteJumpSize ? patchSize : 0;
        }
    }

    bool isInlineHookInternalBypassActive()
    {
        // isInlineHookInternalBypassActive:
        // - Inputs: None;
        // - Processing: Read the current thread's HookEngine internal operation depth.
        // - Returns: true if depth is greater than 0.
        return gInlineHookInternalBypassDepth != 0;
    }

    ScopedInlineHookInternalBypass::ScopedInlineHookInternalBypass()
    {
        // Constructor:
        // - Inputs: None;
        // - Processing: Current thread enters the HookEngine internal scope; HookedXXX wrappers will bypass directly.
        // - Returns: Nothing.
        ++gInlineHookInternalBypassDepth;
        entered_ = true;
    }

    ScopedInlineHookInternalBypass::~ScopedInlineHookInternalBypass()
    {
        // Destructor:
        // - Inputs: None;
        // - Processing: Exit the HookEngine internal scope for the current thread to prevent bypassing user calls after installation/uninstallation completes.
        // - Returns: Nothing.
        if (entered_ && gInlineHookInternalBypassDepth != 0)
        {
            --gInlineHookInternalBypassDepth;
        }
    }

    InlineHookInstallResult installInlineHook(
        const wchar_t* moduleName,
        const char* procName,
        void* detourAddress,
        InlineHookRecord* hookOut,
        void** originalOut,
        std::wstring* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        ScopedInlineHookInternalBypass hookBypassScope;
        if (moduleName == nullptr || procName == nullptr || detourAddress == nullptr || hookOut == nullptr || originalOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"InstallInlineHook received invalid argument.";
            }
            return InlineHookInstallResult::kPermanentFailure;
        }
        if (hookOut->permanentlyDisabled)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"Hook has been permanently disabled after a previous unsafe install attempt.";
            }
            return InlineHookInstallResult::kPermanentFailure;
        }

        HMODULE moduleHandle = ::GetModuleHandleW(moduleName);
        if (moduleHandle == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = std::wstring(L"Module not loaded: ") + moduleName;
            }
            return InlineHookInstallResult::kRetryableFailure;
        }

        void* exportAddress = reinterpret_cast<void*>(::GetProcAddress(moduleHandle, procName));
        if (exportAddress == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"GetProcAddress failed.";
            }
            hookOut->permanentlyDisabled = true;
            return InlineHookInstallResult::kPermanentFailure;
        }

        unsigned char* targetPointer = static_cast<unsigned char*>(resolveJumpStub(exportAddress));
        const std::size_t kPatchSize = calculatePatchSize(targetPointer);
        if (kPatchSize == 0 || kPatchSize > hookOut->originalBytes.size())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"Unsupported or relocation-unsafe prologue for inline hook.";
            }
            hookOut->permanentlyDisabled = true;
            return InlineHookInstallResult::kPermanentFailure;
        }

        unsigned char* trampolinePointer = static_cast<unsigned char*>(::VirtualAlloc(
            nullptr,
            kPatchSize + kAbsoluteJumpSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));
        if (trampolinePointer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"VirtualAlloc for trampoline failed.";
            }
            hookOut->permanentlyDisabled = true;
            return InlineHookInstallResult::kPermanentFailure;
        }

        std::memcpy(trampolinePointer, targetPointer, kPatchSize);
        buildAbsoluteJump(trampolinePointer + kPatchSize, targetPointer + kPatchSize);

        DWORD oldProtect = 0;
        if (::VirtualProtect(targetPointer, kPatchSize, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE)
        {
            ::VirtualFree(trampolinePointer, 0, MEM_RELEASE);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"VirtualProtect for target patch failed.";
            }
            hookOut->permanentlyDisabled = true;
            return InlineHookInstallResult::kPermanentFailure;
        }

        ScopedOtherThreadsSuspender suspendOtherThreadsScope;
        hookOut->targetAddress = targetPointer;
        hookOut->detourAddress = detourAddress;
        hookOut->trampolineAddress = trampolinePointer;
        hookOut->patchSize = kPatchSize;
        hookOut->permanentlyDisabled = false;
        *originalOut = trampolinePointer;
        std::memcpy(hookOut->originalBytes.data(), targetPointer, kPatchSize);

        unsigned char patchBuffer[32] = {};
        buildAbsoluteJump(patchBuffer, detourAddress);
        std::memset(patchBuffer + kAbsoluteJumpSize, 0x90, kPatchSize - kAbsoluteJumpSize);
        std::memcpy(targetPointer, patchBuffer, kPatchSize);
        ::FlushInstructionCache(::GetCurrentProcess(), targetPointer, kPatchSize);

        DWORD unusedProtect = 0;
        ::VirtualProtect(targetPointer, kPatchSize, oldProtect, &unusedProtect);
        hookOut->installed = true;
        return InlineHookInstallResult::kInstalled;
    }

    void uninstallInlineHook(InlineHookRecord* hookValue)
    {
        ScopedInlineHookInternalBypass hookBypassScope;
        if (hookValue == nullptr || !hookValue->installed || hookValue->targetAddress == nullptr)
        {
            return;
        }

        DWORD oldProtect = 0;
        if (::VirtualProtect(hookValue->targetAddress, hookValue->patchSize, PAGE_EXECUTE_READWRITE, &oldProtect) != FALSE)
        {
            ScopedOtherThreadsSuspender suspendOtherThreadsScope;
            std::memcpy(hookValue->targetAddress, hookValue->originalBytes.data(), hookValue->patchSize);
            ::FlushInstructionCache(::GetCurrentProcess(), hookValue->targetAddress, hookValue->patchSize);
            DWORD unusedProtect = 0;
            ::VirtualProtect(hookValue->targetAddress, hookValue->patchSize, oldProtect, &unusedProtect);
        }

        if (hookValue->trampolineAddress != nullptr)
        {
            ::VirtualFree(hookValue->trampolineAddress, 0, MEM_RELEASE);
        }

        hookValue->installed = false;
        hookValue->targetAddress = nullptr;
        hookValue->detourAddress = nullptr;
        hookValue->trampolineAddress = nullptr;
        hookValue->patchSize = 0;
        hookValue->originalBytes.fill(0);
    }
}
