#pragma once

// ============================================================
// FileHandleUsageScanner.h
// Purpose:
// - Provides the capability to scan for file/folder handle usage.
// - Input: target path list; Output: list of matched handles.
// - Reused by the FileDock right-click 'Scan Handle Usage' window.
// ============================================================

#include "../Framework.h"

#include <QString>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace filedock::handleusage
{
    // HandleUsageProgressCallback purpose: safely pass background scan stages and percentages to the UI layer for display.
    using HandleUsageProgressCallback = std::function<void(const QString& stageText, float progressValue)>;

    // HandleUsageEntry:
    // - Represents a matched handle usage record.
    // - Simultaneously carries handle information, owning process information, and matched path information.
    struct HandleUsageEntry
    {
        std::uint32_t processId = 0;        // processId: Owning process PID.
        std::uint64_t processCreationTime = 0; // processCreationTime: Process creation time, used to verify PID identity before destructive operations.
        QString processName;                // processName: Name of the owning process.
        QString processImagePath;           // processImagePath: The image path of the owning process.
        std::uint64_t handleValue = 0;      // handleValue: Handle value.
        std::uint16_t typeIndex = 0;        // typeIndex: Object type index.
        QString typeName;                   // typeName: Object type name.
        QString objectName;                 // objectName: Object name (typically an NT path).
        std::uint32_t grantedAccess = 0;    // grantedAccess: access mask.
        std::uint32_t attributes = 0;       // attributes: Handle attribute bits.
        QString matchedTargetPath;          // matchedTargetPath: Matched target path (user perspective).
        bool matchedByDirectoryRule = false; // matchedByDirectoryRule: true = directory prefix match; false = exact match.
        QString matchRuleText;              // matchRuleText: Source description of the match (file handle/process image/module image, etc.).
        QString enumerationSource;          // enumerationSource: Enumeration source (KernelHandleTable/R3DuplicateHandle/Synthetic source).
    };

    // HandleUsageScanResult:
    // - Aggregate the complete results of a single scan.
    // - Include statistical counts and diagnostic information for direct display in the UI status bar.
    struct HandleUsageScanResult
    {
        std::vector<HandleUsageEntry> entries; // entries: List of matched handles.
        std::size_t totalHandleCount = 0;      // totalHandleCount: Total number of system handles.
        std::size_t fileLikeHandleCount = 0;   // fileLikeHandleCount: Number of File-type handles.
        std::size_t matchedHandleCount = 0;    // matchedHandleCount: Count of handles matching the target path.
        std::size_t processImageMatchCount = 0; // processImageMatchCount: Count of hits for 'Process Image Usage'.
        std::size_t loadedModuleMatchCount = 0; // loadedModuleMatchCount: Count of matches for 'module load occupancy'.
        std::size_t kernelHandleMatchCount = 0; // kernelHandleMatchCount: number of file handle hits in the R0 HandleTable.
        bool kernelHandleTableAttempted = false; // kernelHandleTableAttempted: Indicates whether the R0 HandleTable scan was called first.
        bool kernelHandleTableUsed = false;      // kernelHandleTableUsed: Whether the file handle result originates from R0.
        bool r3HandleFallbackUsed = false;       // r3HandleFallbackUsed: Whether it fell back to R3 after R0 became unavailable.
        std::uint64_t elapsedMs = 0;           // elapsedMs: Scan duration in milliseconds.
        QString diagnosticText;                // diagnosticText: Diagnostic text (failure count/degradation info).
    };

    // scanHandleUsageByPaths:
    // - Scan system handles and filter those occupying the target paths.
    // - Supports both file and directory matching rules (exact file match, directory prefix match).
    // Invocation: Called by the background thread on the 'File Usage and Unlock' page of the file properties dialog.
    // Input absolutePaths: target absolute path collection (multiple selection supported).
    // Accepts progressPid: the progress bar ID; 0 indicates no progress forwarding.
    // Passing tryKernelHandleTable: true indicates priority attempt on R0 HandleTable; false indicates R3-only or synthetic usage scanning.
    // Note: Pass cancellationCallback: if it returns true, terminate the scan as soon as possible; if omitted, execute the original full scan.
    // Output: HandleUsageScanResult (returned by value).
    HandleUsageScanResult scanHandleUsageByPaths(
        const std::vector<QString>& absolutePaths,
        int progressPid = 0,
        bool tryKernelHandleTable = true,
        const std::function<bool()>& cancellationCallback = {},
        const HandleUsageProgressCallback& progressCallback = {});
}
