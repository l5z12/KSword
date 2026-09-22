#pragma once

// ============================================================
// KernelDockObjectNamespaceWorker.h
// Purpose:
// 1) Provide a background task for enumerating the object manager namespace.
// 2) Provide symlink target resolution capability;
// 3) Provide the capability to map NT device paths to DOS paths.
// ============================================================

#include "KernelDock.h"

#include <vector> // std::vector: Holds output list.

// runObjectNamespaceSnapshotTask：
// - Purpose: enumerate key Object Manager directories and generate table rows.
// - Invocation: Recommended to call in a background thread.
// - Parameter rowsOut: Output enumeration results (cleared internally before use).
// - Input errorTextOut: Fatal error text output (cleared on success).
// - Return: true if task is available; false if fatal error (e.g., Nt API load failure).
bool runObjectNamespaceSnapshotTask(std::vector<KernelObjectNamespaceEntry>& rowsOut, QString& errorTextOut);

// queryObjectNamespaceSymbolicLinkTarget：
// - Purpose: Resolve the symbolic link target by object path.
// - Usage: Reused by the right-click menu action 'Resolve Symbolic Link Target'.
// - Input symbolicLinkPathText: Full path of the target symbolic link (paths like \??\C: must start with \);
// - Output targetTextOut: the resolved target path.
// - Out: statusTextOut: status text (including failure reason).
// - Returns: true on success; false on failure.
bool queryObjectNamespaceSymbolicLinkTarget(
    const QString& symbolicLinkPathText,
    QString& targetTextOut,
    QString& statusTextOut);

// queryDosPathCandidatesByNtPath：
// - Purpose: Map NT device paths (e.g., \Device\HarddiskVolume3\Windows) to DOS path candidates.
// - Call: Reused for object table right-click menu action 'Try map DOS path'.
// - Input ntPathText: NT path.
// - Returns: List of DOS path candidates (may be empty).
std::vector<QString> queryDosPathCandidatesByNtPath(const QString& ntPathText);
