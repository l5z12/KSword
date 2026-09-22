#pragma once

// ============================================================
// KernelDockQueryWorker.h
// Purpose:
// 1) Provide data collection functions reusable by KernelDock background threads;
// 2) Decouple time-consuming NtQuery* calls and raw data parsing from the UI file.
// 3) Keep KernelDock.cpp under 1000 lines for easier maintenance and auditing.
// ============================================================

#include "KernelDock.h"

#include <vector> // std::vector: Holds result list.

// runKernelTypeSnapshotTask：
// - Purpose: Collects object type IDs, names, and statistics required for the 'Kernel Object Types' page.
// - Call: Invoked on background thread; prohibit long-running execution directly on UI thread.
// - Parameter rowsOut: Output list of object type rows (cleared and then written within the function).
// - Input errorTextOut: Failure reason text (cleared on success).
// - Return: true indicates success; false indicates failure.
bool runKernelTypeSnapshotTask(std::vector<KernelObjectTypeEntry>& rowsOut, QString& errorTextOut);

// runNtQuerySnapshotTask：
// - Purpose: Collect common NtQuery*Information call results required for the 'NtQuery Information' page.
// - Call: Invoked on background thread; prohibit long-running execution directly on UI thread.
// - Parameter rowsOut: output list of NtQuery result rows (cleared and then written within the function).
// - Input errorTextOut: Failure reason text (cleared on success).
// - Return: true indicates success; false indicates failure.
bool runNtQuerySnapshotTask(std::vector<KernelNtQueryResultEntry>& rowsOut, QString& errorTextOut);
