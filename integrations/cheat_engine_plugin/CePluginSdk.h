#pragma once

#include <Windows.h>

#include <cstddef>

// Note: This file only describes the Cheat Engine SDK v6 ABI prefixes actually used by the KSword bridge plugin.
// Field order follows Cheat Engine's official cepluginsdk.h; do not copy Lua or UI extension definitions.
namespace ksword::ce
{
    constexpr unsigned int kCeSdkVersion = 6U;

    struct PluginVersion
    {
        unsigned int version; // version: Minimum CE SDK version required by the plugin.
        char* pluginName;      // pluginName: NUL-terminated name valid for the DLL's lifetime.
    };

    enum class PluginType : int
    {
        kAddressList = 0,
        kMemoryView = 1,
        kOnDebugEvent = 2,
        kProcessWatcherEvent = 3,
        kFunctionPointerChange = 4,
        kMainMenu = 5,
        kDisassemblerContext = 6,
        kDisassemblerRenderLine = 7,
        kAutoAssembler = 8
    };

    using ShowMessageFunction = void(__stdcall*)(char* message);
    using RegisterFunction = int(__stdcall*)(
        int pluginId,
        PluginType functionType,
        void* initialization);
    using UnregisterFunction = BOOL(__stdcall*)(int pluginId, int functionId);
    using GetMainWindowHandleFunction = HANDLE(__stdcall*)();

    // Note: The following placeholder function types are used only to maintain ABI field width; the plugin will not call them.
    using GenericFunction = void(__stdcall*)();
    using ReadProcessMemoryFunction = BOOL(WINAPI*)(
        HANDLE processHandle,
        LPCVOID baseAddress,
        LPVOID buffer,
        SIZE_T bytesToRead,
        SIZE_T* bytesRead);
    using WriteProcessMemoryFunction = BOOL(WINAPI*)(
        HANDLE processHandle,
        LPVOID baseAddress,
        LPCVOID buffer,
        SIZE_T bytesToWrite,
        SIZE_T* bytesWritten);
    using OpenProcessFunction = HANDLE(WINAPI*)(
        DWORD desiredAccess,
        BOOL inheritHandle,
        DWORD processId);
    using VirtualQueryExFunction = SIZE_T(WINAPI*)(
        HANDLE processHandle,
        LPCVOID address,
        PMEMORY_BASIC_INFORMATION information,
        SIZE_T informationLength);

    using FunctionPointerChangeCallback = void(__stdcall*)(int reserved);

    struct FunctionPointerChangeInitialization
    {
        FunctionPointerChangeCallback callbackRoutine; // callbackRoutine: Notification after CE rebuilds the function table.
    };

    // Note: The structure must maintain the same order from the first field to VirtualQueryEx as the official ExportedFunctions.
    // sizeofExportedFunctions: Used solely to verify that CE provides at least the fields this plugin needs to access.
    struct ExportedFunctions
    {
        int sizeofExportedFunctions;
        ShowMessageFunction showMessage;
        RegisterFunction registerFunction;
        UnregisterFunction unregisterFunction;
        ULONG* openedProcessId;
        HANDLE* openedProcessHandle;
        GetMainWindowHandleFunction getMainWindowHandle;
        GenericFunction autoAssemble;
        GenericFunction assembler;
        GenericFunction disassembler;
        GenericFunction changeRegistersAtAddress;
        GenericFunction injectDll;
        GenericFunction freezeMemory;
        GenericFunction unfreezeMemory;
        GenericFunction fixMemory;
        GenericFunction processList;
        GenericFunction reloadSettings;
        GenericFunction getAddressFromPointer;
        ReadProcessMemoryFunction* readProcessMemory;
        void* writeProcessMemory;
        void* getThreadContext;
        void* setThreadContext;
        void* suspendThread;
        void* resumeThread;
        void* openProcess;
        void* waitForDebugEvent;
        void* continueDebugEvent;
        void* debugActiveProcess;
        void* stopDebugging;
        void* stopRegisterChange;
        void* virtualProtect;
        void* virtualProtectEx;
        void* virtualQueryEx;
    };

    constexpr std::size_t kRequiredExportedFunctionsSize =
        offsetof(ExportedFunctions, virtualQueryEx) + sizeof(void*);
}
