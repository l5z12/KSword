#pragma once

#include "ProcessModel.h"

#include <string>
#include <vector>

namespace ksword::features::process {

enum class ProcessActionId {
    kCopyCell,
    kCopyRow,
    kCopyVisibleResults,
    kExportVisibleResults,
    kOpenDetails,
    kOpenImageInFileModule,
    kOpenNetworkForProcess,
    kOpenHandlesForProcess,
    kOpenEtwForProcess,
    kOpenWindowsForProcess,
    kTerminateProcessMultiMethod,
    kTerminateProcess,
    kTerminateProcessTree,
    kR0TerminateProcess,
    kR0TerminateProcessTree,
    kR0SuspendProcess,
    kR0HideUnlinkOnly,
    kR0HidePatchPidOnly,
    kR0HideLegacyBoth,
    kR0UnhideProcess,
    kR0ClearHiddenMarks,
    kR0EnableBreakOnTermination,
    kR0DisableBreakOnTermination,
    kR0DisableApcInsertion,
    kR0DkomRemoveFromCidTable,
    kR0SetIntegrityUntrusted,
    kR0SetIntegrityLow,
    kR0SetIntegrityMedium,
    kR0SetIntegrityMediumPlus,
    kR0SetIntegrityHigh,
    kR0SetIntegritySystem,
    kR0InjectDll,
    kR0InjectShellcode,
    kRefreshPplProtectionLevel,
    kSuspendProcess,
    kResumeProcess,
    kEnableEfficiencyMode,
    kDisableEfficiencyMode,
    kSetCriticalProcess,
    kClearCriticalProcess,
    kOpenFolder,
    kOpenMemoryOperation,
    kScanHotkeys,
    kSetPriorityIdle,
    kSetPriorityBelowNormal,
    kSetPriorityNormal,
    kSetPriorityAboveNormal,
    kSetPriorityHigh,
    kSetPriorityRealtime,
    kR0SetPplNone,
    kR0SetPplAuthenticode,
    kR0SetPplCodeGen,
    kR0SetPplAntimalware,
    kR0SetPplLsa,
    kR0SetPplWindows,
    kR0SetPplWinTcb,
    // Full PP (PsProtectedTypeProtected). Shares the same IOCTL as PPL above,
    // except the type bit in the PS_PROTECTION byte changes from 1 to 2.
    kR0SetPpAuthenticode,
    kR0SetPpCodeGen,
    kR0SetPpAntimalware,
    kR0SetPpLsa,
    kR0SetPpWindows,
    kR0SetPpWinTcb
};

struct ProcessActionMenuItem {
    ProcessActionId id = ProcessActionId::kOpenDetails;
    std::wstring text;
};

struct ProcessActionResult {
    bool success = false;
    std::wstring title;
    std::wstring detail;
};

// executeProcessAction runs the Win32 layer for one context-menu command. Inputs
// are action id, selected PIDs, and current model snapshot for path lookup.
// Processing performs local Win32 actions and retained ArkDriverClient R0
// operations. Output is a result
// message that callers must surface to the user/status area.
ProcessActionResult executeProcessAction(
    ProcessActionId actionId,
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows);

// priorityClassForAction maps menu priority actions to Win32 priority classes.
// Input is a ProcessActionId; output is zero when the id is not a priority item.
DWORD priorityClassForAction(ProcessActionId actionId);

// executeR0ProcessDllInjection / executeR0ProcessShellcodeInjection mirror the
// full Ksword5.1 ArkDriverClient process injection calls. Inputs are selected
// PIDs, their captured snapshot rows, and a user-picked payload path; processing
// holds each verified process instance through the R0 IOCTL; output is a
// display-ready operation result.
ProcessActionResult executeR0ProcessDllInjection(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows,
    const std::wstring& dllPath);

ProcessActionResult executeR0ProcessShellcodeInjection(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows,
    const std::wstring& shellcodePath);

} // namespace Ksword::Features::Process
