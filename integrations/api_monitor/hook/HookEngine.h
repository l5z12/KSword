#pragma once

// ============================================================
// hook/HookEngine.h
// Purpose:
// 1) Provide basic installation and unloading capabilities for x64 Inline Hooks.
// 2) Responsible for constructing a trampoline for the target function and saving the original bytes.
// 3) Reused by the HookTargets layer when batch installing WinAPI detours.
// ============================================================

#include "pch.h"

namespace apimon
{
    // isInlineHookInternalBypassActive:
    // - Inputs: None;
    // - Processing: Check if the current thread is within the internal interval of HookEngine's own inline hook installation/uninstallation.
    // - Return: true indicates that the HookedXXX wrapper should directly call the original trampoline to avoid self-triggered recursion during the installation phase.
    bool isInlineHookInternalBypassActive();

    class ScopedInlineHookInternalBypass final
    {
    public:
        // ScopedInlineHookInternalBypass constructor:
        // - Inputs: None;
        // - Processing: Increment the current thread's HookEngine internal bypass depth.
        // - Returns: Nothing.
        ScopedInlineHookInternalBypass();

        // ScopedInlineHookInternalBypass destructor:
        // - Inputs: None;
        // - Processing: Decrement the current thread's HookEngine internal bypass depth;
        // - Returns: Nothing.
        ~ScopedInlineHookInternalBypass();

        ScopedInlineHookInternalBypass(const ScopedInlineHookInternalBypass&) = delete;
        ScopedInlineHookInternalBypass& operator=(const ScopedInlineHookInternalBypass&) = delete;

    private:
        bool entered_ = false; // m_entered: Records whether construction successfully entered bypass to prevent incorrect decrement under abnormal paths.
    };

    enum class InlineHookInstallResult
    {
        kInstalled,
        kRetryableFailure,
        kPermanentFailure
    };

    struct InlineHookRecord
    {
        void* targetAddress = nullptr;                       // targetAddress: The final target address to be patched.
        void* detourAddress = nullptr;                       // detourAddress: Address of the Detour function.
        void* trampolineAddress = nullptr;                   // trampolineAddress: Address of the original instruction trampoline.
        std::array<unsigned char, 32> originalBytes = {};   // originalBytes: The original bytes before being overwritten.
        std::size_t patchSize = 0;                          // patchSize: Number of leading bytes currently overwritten.
        bool installed = false;                             // installed: Indicates whether the current Hook is active.
        bool permanentlyDisabled = false;                   // permanentlyDisabled: Whether permanently disabled due to unsafe installation.
    };

    InlineHookInstallResult installInlineHook(
        const wchar_t* moduleName,
        const char* procName,
        void* detourAddress,
        InlineHookRecord* hookOut,
        void** originalOut,
        std::wstring* errorTextOut);

    void uninstallInlineHook(InlineHookRecord* hookValue);
}
