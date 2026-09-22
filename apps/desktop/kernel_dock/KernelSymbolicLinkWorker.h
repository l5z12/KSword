#pragma once

// ============================================================
// KernelSymbolicLinkWorker.h
// Purpose:
// 1) Provide dedicated SymbolicLink enumeration in common Object Manager directories;
// 2) Parse the target using NtOpenSymbolicLinkObject + NtQuerySymbolicLinkObject;
// 3) Provide mappings from NT device paths to DOS path candidates without relying on R0/driver IOCTLs.
// ============================================================

#include <QString>

#include <vector>

struct KernelSymbolicLinkEntry
{
    QString sourceDirectory; // sourceDirectory: Object directory from which this record originates.
    QString linkName;        // linkName: Object name within the directory; used as a failure placeholder if the directory cannot be opened.
    QString fullPath;        // fullPath: Full object path of the symbolic link.
    QString targetPath;      // targetPath: The target path returned by NtQuerySymbolicLinkObject.
    QString dosCandidate;    // dosCandidate: DOS path candidate mapped via QueryDosDeviceW.
    QString statusText;      // statusText: Enumeration/open/parse status; retains failure reason on error lines.
};

// runKernelSymbolicLinkSnapshotTask：
// - Input rowsOut: Output container, cleared at function start.
// - Input errorTextOut: Fatal error text; cleared on success or partial success.
// - Processing: enumerate common object directories, select SymbolicLink objects, and resolve each link's target and DOS candidates.
// - Return value: true indicates task completion; false indicates fatal failure such as Nt API load failure.
bool runKernelSymbolicLinkSnapshotTask(
    std::vector<KernelSymbolicLinkEntry>& rowsOut,
    QString& errorTextOut);

// queryKernelSymbolicLinkTarget：
// - Input: symbolicLinkPathText is the full path of the symbolic link object, e.g., \GLOBAL??\C:.
// - Output targetTextOut: returns the target path upon successful parsing.
// - Output statusTextOut: description of NtOpen/NtQuery status.
// - Handling logic: Open the SymbolicLink object and resolve its target only, without recursive enumeration of the target.
// - Return value: true indicates successful parsing; false indicates failure to open or query.
bool queryKernelSymbolicLinkTarget(
    const QString& symbolicLinkPathText,
    QString& targetTextOut,
    QString& statusTextOut);

// queryKernelSymbolicLinkDosPathCandidates：
// - Input: ntPathText is an NT device path, e.g., \Device\HarddiskVolume3\Windows.
// - Processing logic: Iterate through QueryDosDeviceW mappings from A: to Z: to generate possible DOS paths.
// - Returns the result: a list of candidate DOS paths; returns an empty list if no mapping is found.
std::vector<QString> queryKernelSymbolicLinkDosPathCandidates(const QString& ntPathText);
