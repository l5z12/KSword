#pragma once

// ============================================================
// KernelBaseNamedObjectsWorker.h
// Purpose:
// 1) Defines the R3 collection result model for the BaseNamedObjects specialized view;
// 2) Expose the read-only snapshot collection entry point;
// 3) Does not depend on the KswordARK driver, adds no new IOCTLs, and performs no handle enumeration.
// ============================================================

#include "../Framework.h"

#include <vector>

// KernelBaseNamedObjectEntry:
// - Input source: object directory entries enumerated by NtOpenDirectoryObject + NtQueryDirectoryObject;
// - Processing logic: The worker supplements display fields based on scope, session, type, and category.
// - Return behavior: pure data structure consumed by the UI table.
struct KernelBaseNamedObjectEntry
{
    QString scopeText;          // scopeText：Global / Current Session / Session N。
    QString directoryPathText;  // directoryPathText: The object directory being enumerated.
    QString objectNameText;     // objectNameText: Directory entry name.
    QString objectTypeText;     // objectTypeText: Original NT object type name.
    QString typeCategoryText;   // typeCategoryText：Event/Mutant/Semaphore/Section/Timer/Job/Directory/SymbolicLink/Other。
    QString fullPathText;       // fullPathText：directoryPath + objectName。
    QString symbolicTargetText; // symbolicTargetText: SymbolicLink target; empty if not a symbolic link.
    QString statusText;         // statusText: Status for directory enumeration/symbolic link resolution.
    unsigned long sessionId = 0; // sessionId: Session ID; Global uses ULONG_MAX to represent the non-session directory.
    bool hasSessionId = false;  // hasSessionId: Whether sessionId is valid.
    bool canEnumerate = false;  // canEnumerate: Whether the Directory type can be further enumerated.
};

// runBaseNamedObjectsSnapshotTask：
// - Input rowsOut: Output list, cleared at function start;
// - Input errorTextOut: Fatal error text; cleared on success.
// - Processing logic: enumerate \BaseNamedObjects, the current Session, and discoverable numeric Sessions under \Sessions;
// - Returns: true indicates the collection process is available; false indicates a fatal error such as Nt API loading failure.
bool runBaseNamedObjectsSnapshotTask(
    std::vector<KernelBaseNamedObjectEntry>& rowsOut,
    QString& errorTextOut);
