#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkKeyboardIoctl.h"
#include "../driver/KswordArkWin32kIoctl.h"
#include "../driver/KswordArkWindowBandIoctl.h"

namespace ksword::ark
{
    struct WindowBandResult
    {
        IoResult io;
        KSWORD_ARK_WINDOW_BAND_RESPONSE response{};
    };

    // KeyboardHotkeyEntry is an R3 model row corresponding to the internal table of R0 win32k RegisterHotKey.
    struct KeyboardHotkeyEntry
    {
        std::uint32_t source = 0;
        std::uint32_t status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
        std::uint32_t flags = 0;
        std::uint32_t bucketIndex = 0;
        std::uint32_t depth = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t modifierFlags2 = 0;
        std::uint32_t virtualKey = 0;
        std::uint32_t hotkeyId = 0;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        long lastStatus = 0;
        std::uint64_t hotkeyObject = 0;
        std::uint64_t nextHotkeyObject = 0;
        std::uint64_t sessionGlobals = 0;
        std::uint64_t threadInfo = 0;
        std::uint64_t threadObject = 0;
        std::uint64_t windowObject = 0;
        std::uint64_t windowHandle = 0;
        std::uint64_t destinationHandle = 0;
        std::uint64_t callbackAddress = 0;
        std::uint64_t childListFlink = 0;
        std::uint64_t childListBlink = 0;
        std::uint64_t snapshotHash = 0;
        std::uint32_t objectSize = 0;
        std::uint32_t entryFlags = 0;
        std::wstring detail;
    };

    // KeyboardHotkeyEnumResult: Carries the R0 keyboard hotkey enumeration response.
    struct KeyboardHotkeyEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t win32kBase = 0;
        std::uint64_t sessionGlobals = 0;
        std::uint32_t tableOffset = 0;
        std::uint32_t hotkeyNextOffset = 0;
        std::uint32_t hotkeyModifiersOffset = 0;
        std::uint32_t hotkeyVkOffset = 0;
        std::uint32_t hotkeyIdOffset = 0;
        std::vector<KeyboardHotkeyEntry> entries;
    };

    // KeyboardHotkeyMutationResult carries the response for R0 hotkey edit or deletion during a snapshot protection operation.
    struct KeyboardHotkeyMutationResult
    {
        IoResult io;
        KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_RESPONSE response{};
    };

    // KeyboardHookEntry is an R3 model row corresponding to the R0 win32k WH_KEYBOARD/WH_KEYBOARD_LL chain.
    struct KeyboardHookEntry
    {
        std::uint32_t source = 0;
        std::uint32_t status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
        std::uint32_t flags = 0;
        std::uint32_t hookType = 0;
        std::uint32_t hookScope = KSWORD_ARK_KEYBOARD_HOOK_SCOPE_UNKNOWN;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint32_t moduleId = 0;
        long lastStatus = 0;
        std::uint64_t hookObject = 0;
        std::uint64_t chainHead = 0;
        std::uint64_t nextHookObject = 0;
        std::uint64_t threadInfo = 0;
        std::uint64_t targetThreadInfo = 0;
        std::uint64_t desktopInfo = 0;
        std::uint64_t procedureAddress = 0;
        std::uint64_t procedureOffset = 0;
        std::uint64_t moduleBase = 0;
        std::wstring detail;
    };

    // KeyboardHookEnumResult carries the R0 keyboard hook enumeration response.
    struct KeyboardHookEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t win32kBase = 0;
        std::uint32_t threadHookArrayOffset = 0;
        std::uint32_t desktopInfoOffset = 0;
        std::uint32_t desktopHookArrayOffset = 0;
        std::uint32_t hookNextOffset = 0;
        std::uint32_t hookTypeOffset = 0;
        std::uint32_t hookProcedureOffset = 0;
        std::uint32_t hookFlagsOffset = 0;
        std::uint32_t hookModuleIdOffset = 0;
        std::uint32_t hookTargetThreadInfoOffset = 0;
        std::vector<KeyboardHookEntry> entries;
    };

    // Win32kProfileStatusResult carries the win32k/win32kbase/win32kfull profile and session summary.
    // Input: queryWin32kProfileStatus return.
    // Handling: sessions store per-session readiness; fieldOffsets store PDB offset status.
    // Return behavior: read-only status, no window hooks installed.
    struct Win32kProfileStatusResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        std::uint64_t userGetSiloGlobals = 0;
        KSWORD_ARK_WIN32K_MODULE_STATE win32k{};
        KSWORD_ARK_WIN32K_MODULE_STATE win32kbase{};
        KSWORD_ARK_WIN32K_MODULE_STATE win32kfull{};
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        std::vector<KSWORD_ARK_WIN32K_SESSION_ENTRY> entries;
    };

    // Win32kWindowsResult carries HWND/tagWND cross-view rows.
    // Input: Return value of queryWin32kWindows.
    // Note: entries store HWND, PID/TID, desktop, rect, and title/class states.
    // Return behavior: does not read message payload, does not alter window state.
    struct Win32kWindowsResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        std::vector<KSWORD_ARK_WIN32K_WINDOW_ENTRY> entries;
    };

    // Win32kGuiThreadsResult carries snapshots of GUI threads, tagQ, focus, capture, and caret.
    // Input: returned by queryWin32kGuiThreads.
    // Processing: entries store queue objects and active HWND diagnostic addresses.
    // Return behavior: no hooking, no blocking, no replaying of window messages.
    struct Win32kGuiThreadsResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        std::vector<KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY> entries;
    };

    // Win32kHotkeysPdbResult carries a PDB-backed hotkey snapshot.
    // Input: returned by queryWin32kHotkeysPdb.
    // Note: entries store hotkey objects, VK/modifiers, and associated HWND/threadInfo.
    // Returns: Behavior: Do not delete hotkeys; do not modify the linked list.
    struct Win32kHotkeysPdbResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        std::vector<KSWORD_ARK_WIN32K_HOTKEY_ENTRY> entries;
    };

    // Win32kHooksPdbResult carries a snapshot of the PDB-backed hook chain.
    // Input: return value of queryWin32kHooksPdb.
    // Handling: entries store hook objects, procedures, moduleBase, and target threadInfo.
    // Return behavior: Do not remove/unlink the hook chain.
    struct Win32kHooksPdbResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT layout{};
        std::uint32_t discoveredChainCount = 0;
        std::uint32_t visitedNodeCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t corruptLinkCount = 0;
        std::uint32_t duplicateCount = 0;
        std::uint32_t win32kbaseTimeDateStamp = 0;
        std::uint32_t win32kbaseImageSize = 0;
        std::uint32_t win32kfullTimeDateStamp = 0;
        std::uint32_t win32kfullImageSize = 0;
        std::wstring detail;
        std::vector<KSWORD_ARK_WIN32K_HOOK_ENTRY> entries;
    };

    // Win32kTimersResult holds a read-only snapshot of gTimerHashTable/tagTIMER.
    // Input: queryWin32kTimers return.
    // Note: Preserve PE identity, actual layout, traversal integrity count, and Timer rows.
    // Return behavior: no deletion, no modification, no rescheduling of window timers.
    struct Win32kTimersResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        std::uint64_t timerHashTable = 0;
        std::uint32_t visitedNodeCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t corruptBucketCount = 0;
        std::uint32_t duplicateCount = 0;
        std::uint32_t win32kbaseTimeDateStamp = 0;
        std::uint32_t win32kbaseImageSize = 0;
        std::uint32_t win32kfullTimeDateStamp = 0;
        std::uint32_t win32kfullImageSize = 0;
        KSWORD_ARK_WIN32K_TIMER_LAYOUT layout{};
        std::wstring detail;
        std::vector<KSWORD_ARK_WIN32K_TIMER_ENTRY> entries;
    };

    // Win32kEventHooksResult holds a read-only snapshot of gpWinEventHooks/tagEVENTHOOK.
    // Input: returned by queryWin32kEventHooks.
    // Note: Preserving PE identity, actual layout, chain integrity count, and WinEvent Hook rows.
    // Return behavior: UnhookWinEvent is not called, and the global Hook chain is not modified.
    struct Win32kEventHooksResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        std::uint64_t hookListPointer = 0;
        std::uint64_t hookListHead = 0;
        std::uint32_t visitedNodeCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t corruptLinkCount = 0;
        std::uint32_t duplicateCount = 0;
        std::uint32_t win32kbaseTimeDateStamp = 0;
        std::uint32_t win32kbaseImageSize = 0;
        std::uint32_t win32kfullTimeDateStamp = 0;
        std::uint32_t win32kfullImageSize = 0;
        KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT layout{};
        std::wstring detail;
        std::vector<KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY> entries;
    };

    // Win32kWindowRuntimeDetailResult carries win32k readiness/detail for a single HWND.
    // Input: Return value of queryWin32kWindowDetail.
    // Handles: response saves module/profile/capability/offset status; explains reasons even when tagWND reader is disabled.
    // Return behavior: Read-only display; no window hooks installed, no message payload read.
    struct Win32kWindowRuntimeDetailResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE response{};
    };
}
