#include "WindowCaptureProtection.h"

// ============================================================
// WindowCaptureProtection.cpp
// Purpose:
// 1) Encapsulate SetWindowDisplayAffinity calls for both the current process and cross-process scenarios;
// 2) Cross-process paths only support same-architecture x64 GUI processes;
// 3) Preserve system error codes on failure as much as possible to enable actionable diagnostics in the UI.
// ============================================================

#include <array>
#include <cstddef>
#include <cwchar>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

namespace
{
    // RemoteAffinityParameter layout:
    // - The offset must match the read offset in the x64 shellcode.
    // - Use only integer types to avoid remote process ABI and struct padding differences.
    constexpr std::size_t kRemoteParamSize = 0x28;
    constexpr std::size_t kOffsetSetWindowDisplayAffinity = 0x00;
    constexpr std::size_t kOffsetGetLastError = 0x08;
    constexpr std::size_t kOffsetTargetHwnd = 0x10;
    constexpr std::size_t kOffsetAffinity = 0x18;
    constexpr std::size_t kOffsetCallResult = 0x1C;
    constexpr std::size_t kOffsetLastError = 0x20;

    // HandleGuard:
    // - Close Win32 HANDLE using RAII;
    // - Call: Process, snapshot, and remote thread handles are all managed via this class.
    class HandleGuard
    {
    public:
        explicit HandleGuard(const HANDLE handleValue = nullptr)
            : handle_(handleValue)
        {
        }

        ~HandleGuard()
        {
            reset(nullptr);
        }

        HandleGuard(const HandleGuard&) = delete;
        HandleGuard& operator=(const HandleGuard&) = delete;

        HANDLE get() const
        {
            return handle_;
        }

        void reset(const HANDLE newHandle)
        {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle_);
            }
            handle_ = newHandle;
        }

    private:
        HANDLE handle_ = nullptr; // m_handle: Currently managed Win32 handle.
    };

    // appendDetail:
    // - Concatenate diagnostic text;
    // - Input partText: a single diagnostic segment.
    // - Output detailText: cumulative diagnostics separated by semicolons;
    void appendDetail(std::string& detailText, const std::string& partText)
    {
        if (partText.empty())
        {
            return;
        }

        if (!detailText.empty())
        {
            detailText += "; ";
        }
        detailText += partText;
    }

    // formatWin32Error:
    // - Formats Win32 error codes into stable log text;
    // - Output only digits to avoid log comparison issues across different system languages.
    std::string formatWin32Error(const char* const operationName, const DWORD errorCode)
    {
        std::string operationText = operationName != nullptr ? operationName : "Win32";
        operationText += " failed, error=";
        operationText += std::to_string(static_cast<unsigned long>(errorCode));
        return operationText;
    }

    // hwndFromValue:
    // - Restore the integer HWND saved by the UI to a Win32 HWND;
    // - Pass hwndValue: window handle in quint64/std::uint64_t format.
    HWND hwndFromValue(const std::uint64_t hwndValue)
    {
        return reinterpret_cast<HWND>(static_cast<UINT_PTR>(hwndValue));
    }

    // hwndToValue:
    // - Convert Win32 HWND to a stable integer;
    // - Call: The result structure does not expose Windows.h types.
    std::uint64_t hwndToValue(const HWND windowHandle)
    {
        return static_cast<std::uint64_t>(reinterpret_cast<UINT_PTR>(windowHandle));
    }

    // writeUInt64:
    // - Write remote parameter block in little-endian order;
    // - Input offsetValue: Parameter block offset;
    // - Passes integerValue: the 64-bit value to write.
    void writeUInt64(
        std::array<std::uint8_t, kRemoteParamSize>& parameterBytes,
        const std::size_t offsetValue,
        const std::uint64_t integerValue)
    {
        for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index)
        {
            parameterBytes[offsetValue + index] =
                static_cast<std::uint8_t>((integerValue >> (index * 8)) & 0xFF);
        }
    }

    // writeUInt32:
    // - Write remote parameter block in little-endian order;
    // - Input offsetValue: Parameter block offset;
    // - Passes integerValue: the 32-bit value to write.
    void writeUInt32(
        std::array<std::uint8_t, kRemoteParamSize>& parameterBytes,
        const std::size_t offsetValue,
        const std::uint32_t integerValue)
    {
        for (std::size_t index = 0; index < sizeof(std::uint32_t); ++index)
        {
            parameterBytes[offsetValue + index] =
                static_cast<std::uint8_t>((integerValue >> (index * 8)) & 0xFF);
        }
    }

    // readUInt32:
    // - Read a 32-bit value from the remote parameter block in little-endian format;
    // - Call: Read callResult/lastError after the remote thread finishes.
    std::uint32_t readUInt32(
        const std::array<std::uint8_t, kRemoteParamSize>& parameterBytes,
        const std::size_t offsetValue)
    {
        std::uint32_t integerValue = 0;
        for (std::size_t index = 0; index < sizeof(std::uint32_t); ++index)
        {
            integerValue |= static_cast<std::uint32_t>(parameterBytes[offsetValue + index]) << (index * 8);
        }
        return integerValue;
    }

    // queryRootWindow:
    // - SetWindowDisplayAffinity accepts only top-level windows;
    // - Child window input is merged to GA_ROOT, ensuring that selecting any control also protects its parent top-level window.
    HWND queryRootWindow(const HWND requestedWindowHandle, bool& usedRootWindow)
    {
        usedRootWindow = false;
        HWND rootWindowHandle = ::GetAncestor(requestedWindowHandle, GA_ROOT);
        if (rootWindowHandle == nullptr)
        {
            return requestedWindowHandle;
        }

        if (rootWindowHandle != requestedWindowHandle)
        {
            usedRootWindow = true;
        }
        return rootWindowHandle;
    }

    // queryRemoteModuleBase:
    // - Locate the base address of a specified DLL in the target process module snapshot;
    // - Input PID: Target process PID;
    // - Returns 0 if snapshot failed or module does not exist.
    std::uint64_t queryRemoteModuleBase(
        const DWORD pid,
        const wchar_t* const moduleName,
        std::string& detailText)
    {
        HandleGuard snapshotHandle(::CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid));
        if (snapshotHandle.get() == INVALID_HANDLE_VALUE)
        {
            appendDetail(detailText, formatWin32Error("CreateToolhelp32Snapshot(module)", ::GetLastError()));
            return 0;
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        if (::Module32FirstW(snapshotHandle.get(), &moduleEntry) == FALSE)
        {
            appendDetail(detailText, formatWin32Error("Module32FirstW", ::GetLastError()));
            return 0;
        }

        do
        {
            if (_wcsicmp(moduleEntry.szModule, moduleName) == 0)
            {
                return reinterpret_cast<std::uint64_t>(moduleEntry.modBaseAddr);
            }
        } while (::Module32NextW(snapshotHandle.get(), &moduleEntry) != FALSE);

        appendDetail(detailText, "target module not found");
        return 0;
    }

    // resolveRemoteProcedure:
    // - Calculates the remote function address using 'Local Function RVA + Target Module Base Address';
    // - This policy is stable when the target and current processes use the same system DLL version.
    // - Validate the target process architecture before calling.
    std::uint64_t resolveRemoteProcedure(
        const DWORD pid,
        const wchar_t* const moduleName,
        const char* const procedureName,
        std::string& detailText)
    {
        HMODULE localModuleHandle = ::GetModuleHandleW(moduleName);
        if (localModuleHandle == nullptr)
        {
            localModuleHandle = ::LoadLibraryW(moduleName);
        }
        if (localModuleHandle == nullptr)
        {
            appendDetail(detailText, formatWin32Error("LoadLibraryW(local module)", ::GetLastError()));
            return 0;
        }

        FARPROC localProcedureAddress = ::GetProcAddress(localModuleHandle, procedureName);
        if (localProcedureAddress == nullptr)
        {
            appendDetail(detailText, "GetProcAddress(local procedure) failed");
            return 0;
        }

        const std::uint64_t kRemoteModuleBase = queryRemoteModuleBase(pid, moduleName, detailText);
        if (kRemoteModuleBase == 0)
        {
            return 0;
        }

        const auto kLocalBaseValue = reinterpret_cast<std::uint64_t>(localModuleHandle);
        const auto kLocalProcedureValue = reinterpret_cast<std::uint64_t>(localProcedureAddress);
        return kRemoteModuleBase + (kLocalProcedureValue - kLocalBaseValue);
    }

    // queryProcessMachine:
    // - Prefer calling IsWow64Process2 to determine the process architecture.
    // - Returns true if a comparable machine type has been obtained.
    bool queryProcessMachine(
        const HANDLE processHandle,
        USHORT& processMachine,
        USHORT& nativeMachine)
    {
        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        const HMODULE kKernel32Handle = ::GetModuleHandleW(L"kernel32.dll");
        const auto kIsWow64Process2 = kKernel32Handle != nullptr
            ? reinterpret_cast<IsWow64Process2Fn>(::GetProcAddress(kKernel32Handle, "IsWow64Process2"))
            : nullptr;
        if (kIsWow64Process2 != nullptr)
        {
            return kIsWow64Process2(processHandle, &processMachine, &nativeMachine) != FALSE;
        }

        BOOL isWow64 = FALSE;
        if (::IsWow64Process(processHandle, &isWow64) == FALSE)
        {
            return false;
        }

        nativeMachine = sizeof(void*) == 8 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        processMachine = isWow64 != FALSE ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_UNKNOWN;
        return true;
    }

    // isTargetCompatibleArchitecture:
    // - The currently implemented remote thread stub uses x64 instructions.
    // - If the target is a WOW64/32-bit process, return false and let the UI display the restriction reason.
    bool isTargetCompatibleArchitecture(
        const HANDLE targetProcessHandle,
        std::string& detailText)
    {
        USHORT currentProcessMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT currentNativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT targetProcessMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT targetNativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

        if (!queryProcessMachine(::GetCurrentProcess(), currentProcessMachine, currentNativeMachine) ||
            !queryProcessMachine(targetProcessHandle, targetProcessMachine, targetNativeMachine))
        {
            appendDetail(detailText, "query process architecture failed");
            return false;
        }

        const bool kCurrentIsWow64 = currentProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN;
        const bool kTargetIsWow64 = targetProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN;
        if (kCurrentIsWow64 || kTargetIsWow64)
        {
            appendDetail(detailText, "remote capture protection only supports same-architecture x64 targets");
            return false;
        }

        if (currentNativeMachine != targetNativeMachine)
        {
            appendDetail(detailText, "native machine mismatch");
            return false;
        }
        return true;
    }

    // RemoteAffinityCallResult：
    // - Purpose: Distinguish between "remote thread infrastructure failure" and "remote API returning FALSE".
    // - Call: When protection is enabled, only continue attempting the WDA_MONITOR fallback if the API returns FALSE.
    struct RemoteAffinityCallResult
    {
        bool infrastructureOk = false;      // infrastructureOk: Whether remote allocation, write, thread, and read operations are complete.
        bool apiOk = false;                 // apiOk: return value of SetWindowDisplayAffinity.
        DWORD apiLastError = 0;             // apiLastError: result of GetLastError within the target process.
        std::string detail;                 // detail: Diagnostic text when infrastructure fails.
    };

    // remoteAffinityShellcode:
    // - x64 remote thread entry point; parameter RCX points to RemoteAffinityParameter;
    // - Calls user32!SetWindowDisplayAffinity in the target process;
    // On failure, call ntdll!RtlGetLastWin32Error within the target process and write the result back to the parameter block.
    const std::vector<std::uint8_t>& remoteAffinityShellcode()
    {
        static const std::vector<std::uint8_t> kShellcode = {
            0x53,
            0x48, 0x83, 0xEC, 0x20,
            0x48, 0x89, 0xCB,
            0x48, 0x8B, 0x03,
            0x48, 0x8B, 0x4B, 0x10,
            0x8B, 0x53, 0x18,
            0xFF, 0xD0,
            0x89, 0x43, 0x1C,
            0x85, 0xC0,
            0x75, 0x0B,
            0x48, 0x8B, 0x43, 0x08,
            0xFF, 0xD0,
            0x89, 0x43, 0x20,
            0xEB, 0x07,
            0xC7, 0x43, 0x20, 0x00, 0x00, 0x00, 0x00,
            0x8B, 0x43, 0x1C,
            0x48, 0x83, 0xC4, 0x20,
            0x5B,
            0xC3
        };
        return kShellcode;
    }

    // executeRemoteSetAffinity:
    // - Execute SetWindowDisplayAffinity(hwnd, affinity) within the target process.
    // - processHandle: a handle to a process with remote thread and VM privileges;
    // - Returns RemoteAffinityCallResult, preserving remote API and infrastructure state.
    RemoteAffinityCallResult executeRemoteSetAffinity(
        const HANDLE processHandle,
        const DWORD pid,
        const HWND windowHandle,
        const DWORD affinityValue)
    {
        RemoteAffinityCallResult callResult;
        std::string resolveDetail;
        const std::uint64_t kRemoteSetAffinityAddress = resolveRemoteProcedure(
            pid,
            L"user32.dll",
            "SetWindowDisplayAffinity",
            resolveDetail);
        const std::uint64_t kRemoteGetLastErrorAddress = resolveRemoteProcedure(
            pid,
            L"ntdll.dll",
            "RtlGetLastWin32Error",
            resolveDetail);
        if (kRemoteSetAffinityAddress == 0 || kRemoteGetLastErrorAddress == 0)
        {
            callResult.detail = resolveDetail.empty() ? "remote procedure resolve failed" : resolveDetail;
            return callResult;
        }

        std::array<std::uint8_t, kRemoteParamSize> parameterBytes{};
        writeUInt64(parameterBytes, kOffsetSetWindowDisplayAffinity, kRemoteSetAffinityAddress);
        writeUInt64(parameterBytes, kOffsetGetLastError, kRemoteGetLastErrorAddress);
        writeUInt64(parameterBytes, kOffsetTargetHwnd, hwndToValue(windowHandle));
        writeUInt32(parameterBytes, kOffsetAffinity, static_cast<std::uint32_t>(affinityValue));

        const std::vector<std::uint8_t>& shellcode = remoteAffinityShellcode();
        const SIZE_T kShellcodeSize = static_cast<SIZE_T>(shellcode.size());
        const SIZE_T kParameterSize = static_cast<SIZE_T>(parameterBytes.size());
        void* remoteBlock = ::VirtualAllocEx(
            processHandle,
            nullptr,
            kShellcodeSize + kParameterSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (remoteBlock == nullptr)
        {
            callResult.detail = formatWin32Error("VirtualAllocEx(remote affinity block)", ::GetLastError());
            return callResult;
        }

        auto cleanupRemoteBlock = [&processHandle, &remoteBlock]() {
            if (remoteBlock != nullptr)
            {
                ::VirtualFreeEx(processHandle, remoteBlock, 0, MEM_RELEASE);
                remoteBlock = nullptr;
            }
        };

        SIZE_T bytesWritten = 0;
        if (::WriteProcessMemory(processHandle, remoteBlock, shellcode.data(), kShellcodeSize, &bytesWritten) == FALSE ||
            bytesWritten != kShellcodeSize)
        {
            callResult.detail = formatWin32Error("WriteProcessMemory(remote shellcode)", ::GetLastError());
            cleanupRemoteBlock();
            return callResult;
        }

        auto* const kRemoteParameter = static_cast<std::uint8_t*>(remoteBlock) + kShellcodeSize;
        bytesWritten = 0;
        if (::WriteProcessMemory(processHandle, kRemoteParameter, parameterBytes.data(), kParameterSize, &bytesWritten) == FALSE ||
            bytesWritten != kParameterSize)
        {
            callResult.detail = formatWin32Error("WriteProcessMemory(remote parameter)", ::GetLastError());
            cleanupRemoteBlock();
            return callResult;
        }

        HandleGuard remoteThread(::CreateRemoteThread(
            processHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteBlock),
            kRemoteParameter,
            0,
            nullptr));
        if (remoteThread.get() == nullptr)
        {
            callResult.detail = formatWin32Error("CreateRemoteThread(remote affinity)", ::GetLastError());
            cleanupRemoteBlock();
            return callResult;
        }

        const DWORD kWaitResult = ::WaitForSingleObject(remoteThread.get(), 3000);
        if (kWaitResult != WAIT_OBJECT_0)
        {
            callResult.detail = kWaitResult == WAIT_TIMEOUT
                ? "remote affinity thread timed out"
                : formatWin32Error("WaitForSingleObject(remote affinity)", ::GetLastError());
            return callResult;
        }

        SIZE_T bytesRead = 0;
        if (::ReadProcessMemory(processHandle, kRemoteParameter, parameterBytes.data(), kParameterSize, &bytesRead) == FALSE ||
            bytesRead != kParameterSize)
        {
            callResult.detail = formatWin32Error("ReadProcessMemory(remote parameter)", ::GetLastError());
            cleanupRemoteBlock();
            return callResult;
        }

        cleanupRemoteBlock();
        callResult.infrastructureOk = true;
        callResult.apiOk = readUInt32(parameterBytes, kOffsetCallResult) != 0;
        callResult.apiLastError = readUInt32(parameterBytes, kOffsetLastError);
        return callResult;
    }

    // applyAffinityDirect:
    // - Directly call SetWindowDisplayAffinity within the current process;
    // - When enabling protection, first try EXCLUDEFROMCAPTURE, then fall back to MONITOR.
    bool applyAffinityDirect(
        const HWND windowHandle,
        const bool enableProtection,
        DWORD& appliedAffinity,
        DWORD& win32Error)
    {
        win32Error = 0;
        appliedAffinity = ks::window::kDisplayAffinityAllowCapture;
        if (!enableProtection)
        {
            if (::SetWindowDisplayAffinity(windowHandle, appliedAffinity) != FALSE)
            {
                return true;
            }
            win32Error = ::GetLastError();
            return false;
        }

        appliedAffinity = ks::window::kDisplayAffinityExcludeFromCapture;
        if (::SetWindowDisplayAffinity(windowHandle, appliedAffinity) != FALSE)
        {
            return true;
        }

        appliedAffinity = ks::window::kDisplayAffinityMonitorOnly;
        if (::SetWindowDisplayAffinity(windowHandle, appliedAffinity) != FALSE)
        {
            return true;
        }

        win32Error = ::GetLastError();
        return false;
    }

    // applyAffinityRemote:
    // - Perform DisplayAffinity writes in an external process;
    // - Inputs pid, windowHandle, and enableProtection;
    // - On failure, return detailed diagnostics; on success, write the actual affinity.
    bool applyAffinityRemote(
        const DWORD pid,
        const HWND windowHandle,
        const bool enableProtection,
        DWORD& appliedAffinity,
        DWORD& win32Error,
        std::string& detailText)
    {
        HandleGuard processHandle(::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            pid));
        if (processHandle.get() == nullptr)
        {
            win32Error = ::GetLastError();
            appendDetail(detailText, formatWin32Error("OpenProcess(remote affinity)", win32Error));
            return false;
        }

        if (!isTargetCompatibleArchitecture(processHandle.get(), detailText))
        {
            win32Error = ERROR_NOT_SUPPORTED;
            return false;
        }

        appliedAffinity = enableProtection
            ? ks::window::kDisplayAffinityExcludeFromCapture
            : ks::window::kDisplayAffinityAllowCapture;
        RemoteAffinityCallResult remoteCall = executeRemoteSetAffinity(
            processHandle.get(),
            pid,
            windowHandle,
            appliedAffinity);
        if (!remoteCall.infrastructureOk)
        {
            appendDetail(detailText, remoteCall.detail);
            win32Error = ERROR_GEN_FAILURE;
            return false;
        }
        if (remoteCall.apiOk)
        {
            win32Error = 0;
            return true;
        }

        if (!enableProtection)
        {
            win32Error = remoteCall.apiLastError;
            appendDetail(detailText, formatWin32Error("remote SetWindowDisplayAffinity(WDA_NONE)", win32Error));
            return false;
        }

        appliedAffinity = ks::window::kDisplayAffinityMonitorOnly;
        remoteCall = executeRemoteSetAffinity(
            processHandle.get(),
            pid,
            windowHandle,
            appliedAffinity);
        if (!remoteCall.infrastructureOk)
        {
            appendDetail(detailText, remoteCall.detail);
            win32Error = ERROR_GEN_FAILURE;
            return false;
        }
        if (remoteCall.apiOk)
        {
            win32Error = 0;
            return true;
        }

        win32Error = remoteCall.apiLastError;
        appendDetail(detailText, formatWin32Error("remote SetWindowDisplayAffinity(fallback WDA_MONITOR)", win32Error));
        return false;
    }
}

namespace ks::window
{
    CaptureProtectionResult setWindowCaptureProtection(
        const std::uint64_t hwndValue,
        const bool enableProtection)
    {
        CaptureProtectionResult result;
        result.requestedProtection = enableProtection;
        result.requestedHwnd = hwndValue;
        result.appliedHwnd = hwndValue;
        result.appliedAffinity = enableProtection
            ? kDisplayAffinityExcludeFromCapture
            : kDisplayAffinityAllowCapture;

        HWND requestedWindowHandle = hwndFromValue(hwndValue);
        if (requestedWindowHandle == nullptr || ::IsWindow(requestedWindowHandle) == FALSE)
        {
            result.win32Error = ERROR_INVALID_WINDOW_HANDLE;
            result.detail = "invalid HWND";
            return result;
        }

        bool usedRootWindow = false;
        HWND targetWindowHandle = queryRootWindow(requestedWindowHandle, usedRootWindow);
        if (targetWindowHandle == nullptr || ::IsWindow(targetWindowHandle) == FALSE)
        {
            result.win32Error = ERROR_INVALID_WINDOW_HANDLE;
            result.detail = "root HWND invalid";
            return result;
        }

        DWORD processId = 0;
        ::GetWindowThreadProcessId(targetWindowHandle, &processId);
        result.processId = static_cast<std::uint32_t>(processId);
        result.appliedHwnd = hwndToValue(targetWindowHandle);
        result.usedRootWindow = usedRootWindow;

        DWORD appliedAffinity = result.appliedAffinity;
        DWORD win32Error = 0;
        if (processId == ::GetCurrentProcessId())
        {
            result.success = applyAffinityDirect(
                targetWindowHandle,
                enableProtection,
                appliedAffinity,
                win32Error);
        }
        else
        {
            result.usedRemoteThread = true;
            result.success = applyAffinityRemote(
                processId,
                targetWindowHandle,
                enableProtection,
                appliedAffinity,
                win32Error,
                result.detail);
        }

        result.appliedAffinity = appliedAffinity;
        result.win32Error = win32Error;
        if (result.success)
        {
            result.detail = enableProtection
                ? "capture protection applied"
                : "capture protection removed";
        }
        else if (result.detail.empty())
        {
            result.detail = formatWin32Error("SetWindowDisplayAffinity", result.win32Error);
        }
        return result;
    }

    bool queryWindowDisplayAffinity(
        const std::uint64_t hwndValue,
        std::uint32_t& affinityOut,
        std::uint32_t* const win32ErrorOut)
    {
        affinityOut = kDisplayAffinityAllowCapture;
        if (win32ErrorOut != nullptr)
        {
            *win32ErrorOut = 0;
        }

        HWND windowHandle = hwndFromValue(hwndValue);
        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            if (win32ErrorOut != nullptr)
            {
                *win32ErrorOut = ERROR_INVALID_WINDOW_HANDLE;
            }
            return false;
        }

        DWORD affinityValue = 0;
        if (::GetWindowDisplayAffinity(windowHandle, &affinityValue) == FALSE)
        {
            if (win32ErrorOut != nullptr)
            {
                *win32ErrorOut = ::GetLastError();
            }
            return false;
        }

        affinityOut = static_cast<std::uint32_t>(affinityValue);
        return true;
    }

    std::string displayAffinityName(const std::uint32_t affinityValue)
    {
        switch (affinityValue)
        {
        case kDisplayAffinityAllowCapture:
            return "WDA_NONE / 允许截图";
        case kDisplayAffinityMonitorOnly:
            return "WDA_MONITOR / 截图黑屏";
        case kDisplayAffinityExcludeFromCapture:
            return "WDA_EXCLUDEFROMCAPTURE / 从截图中隐藏";
        default:
            return "未知 DisplayAffinity";
        }
    }
}
