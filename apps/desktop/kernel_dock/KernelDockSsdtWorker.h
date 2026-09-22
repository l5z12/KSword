#pragma once

#include "KernelDock.h"

#include <vector>

// runSsdtSnapshotTask：
// - Purpose: Obtain an SSDT traversal snapshot via driver IOCTL.
// - Call: Invoked on background thread; prohibit long-running execution directly on UI thread.
// - Input rowsOut: Output list of SSDT rows (cleared and then written within the function).
// - Input errorTextOut: Failure reason text (cleared on success).
// - Return: true indicates success; false indicates failure.
bool runSsdtSnapshotTask(std::vector<KernelSsdtEntry>& rowsOut, QString& errorTextOut);
