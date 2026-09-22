#pragma once

// ============================================================
// HandleObjectTypeWorker.h
// Purpose:
// - Provides background collection capabilities for 'object type snapshots';
// - Shared between the "Object Type" page of the Handle Dock and the handle list type mapping.
// - Centralize kernel object type resolution logic in the handle module to prevent UI file bloat;
// ============================================================

#include "../Framework.h"

#include <QString>

#include <cstdint>
#include <unordered_map>
#include <vector>

// ============================================================
// HandleObjectTypeEntry
// Purpose:
// - Represents a snapshot record of an object type.
// - Used for "object type page table display + handle type index mapping".
// ============================================================
struct HandleObjectTypeEntry
{
    std::uint32_t typeIndex = 0;              // typeIndex: Object type index.
    QString typeNameText;                     // typeNameText: Object type name (File/Process/Key, etc.).
    std::uint64_t totalObjectCount = 0;       // totalObjectCount: Total number of objects.
    std::uint64_t totalHandleCount = 0;       // totalHandleCount: Total number of handles.
    std::uint32_t validAccessMask = 0;        // validAccessMask: Valid access mask.
    bool securityRequired = false;            // securityRequired: Whether security checks are required.
    bool maintainHandleCount = false;         // maintainHandleCount: Whether to maintain the handle count.
    std::uint32_t poolType = 0;               // poolType: Pool type value.
    std::uint32_t defaultPagedPoolCharge = 0; // defaultPagedPoolCharge: default paged pool quota.
    std::uint32_t defaultNonPagedPoolCharge = 0; // defaultNonPagedPoolCharge: Default quota for non-paged pool.
};

// runHandleObjectTypeSnapshotTask：
// - Purpose: Collect a system object type snapshot in a background thread.
// - Usage: Called when the Handle Dock initiates an object type refresh.
// - Input rowsOut: Output object type list (cleared and then written within the function);
// - Pass errorTextOut: failure description text (cleared on success).
// - Returns: true = success; false = failure.
bool runHandleObjectTypeSnapshotTask(
    std::vector<HandleObjectTypeEntry>& rowsOut,
    QString& errorTextOut);

// buildTypeNameMapFromObjectTypeRows：
// - Purpose: Convert a list of object type rows into a typeIndex -> typeName mapping.
// - Call: Before enumerating the handle list, directly reuse this mapping to avoid displaying Type#50.
// - Input: rows, list of object type rows.
// - Returns: Type index mapping table (UTF-8 strings).
std::unordered_map<std::uint16_t, std::string> buildTypeNameMapFromObjectTypeRows(
    const std::vector<HandleObjectTypeEntry>& rows);
