#pragma once

// ============================================================
// KernelDeviceDriverObjectsWorker.h
// Purpose:
// 1) Provides a read-only background enumeration task for a dedicated 'Device and Driver' view;
// 2) Use only R3 object manager APIs to enumerate directories
//    such as \Device, \Driver, \FileSystem, and \FileSystem\Filters;
// 3) Only resolves symbolic link targets; performs no policy writes or kernel interactions.
// ============================================================

#include "../Framework.h"

#include <vector> // std::vector: Holds enumeration results.

// ============================================================
// KernelDeviceDriverObjectEntry
// Purpose:
// - Represents a single read-only result row in the 'Devices and Drivers' specialized view;
// - This structure is dedicated to UI display and TSV export, containing no writable fields.
// ============================================================
struct KernelDeviceDriverObjectEntry
{
    QString directoryPathText;   // directoryPathText: The current enumeration source directory, e.g., \Device.
    QString objectNameText;      // objectNameText: Object name.
    QString objectTypeText;      // objectTypeText: Object type, such as Device, Driver, Directory, or SymbolicLink.
    QString fullPathText;        // fullPathText: Full path of the object.
    QString targetPathText;      // targetPathText: Symbolic link target; non-linked objects remain empty.
    QString statusText;          // statusText: Status text used to describe enumeration or parsing results.
    QString capabilityHintText;  // capabilityHintText: Chinese capability hint, explaining what can be done next.
    QString detailText;          // detailText: Supplementary description text for subsequent integration with the details panel.
    long statusCode = 0;         // statusCode: Original NTSTATUS for subsequent diagnostics.
    bool querySucceeded = false; // querySucceeded: Whether object information was successfully retrieved on this line.
    bool isDirectory = false;    // isDirectory: Whether the object is a directory.
    bool isSymbolicLink = false; // isSymbolicLink: Whether the object is a symbolic link.
    bool isScopeEntry = false;   // isScopeEntry: Whether this is a directory-scope entry (not an actual child object).
};

// runKernelDeviceDriverObjectsSnapshotTask：
// - Input: rowsOut to receive all enumeration results; errorTextOut to return fatal error text;
// - Processing: Load object manager APIs from ntdll, enumerate four target directories sequentially, and resolve symbolic links.
// - Return: true indicates the task executed successfully to completion; false indicates a fatal error such as API loading failure.
bool runKernelDeviceDriverObjectsSnapshotTask(
    std::vector<KernelDeviceDriverObjectEntry>& rowsOut,
    QString& errorTextOut);
