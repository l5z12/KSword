#pragma once

// ============================================================
// KernelDockAtomWorker.h
// Purpose:
// 1) Provides a background task for enumerating the atom table.
// 2) Provide utility functions to verify atom existence by name.
// ============================================================

#include "KernelDock.h"

#include <cstdint> // std::uint16_t: Atom value type.
#include <vector>  // std::vector: Result container.

// runAtomTableSnapshotTask：
// - Purpose: Iterate through the global atom range and output visible atom entries.
// - Invocation: Recommended to execute in a background thread.
// - Input rowsOut: Output atom row results (cleared internally before use).
// - Input parameter errorTextOut: output error text (cleared on success).
// - Returns: true = task completed (empty results allowed); false = fatal error occurred.
bool runAtomTableSnapshotTask(std::vector<KernelAtomEntry>& rowsOut, QString& errorTextOut);

// verifyGlobalAtomByName：
// - Purpose: Call GlobalFindAtomW to verify if the specified name exists in the global atom table.
// - Input parameter atomNameText: The atom name to verify;
// - Output atomValueOut: return the Atom value on match.
// - Output detailTextOut: detail text (for the detail panel).
// - Returns: true = hit; false = miss or invalid parameters.
bool verifyGlobalAtomByName(
    const QString& atomNameText,
    std::uint16_t& atomValueOut,
    QString& detailTextOut);
