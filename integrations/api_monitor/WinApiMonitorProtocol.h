#pragma once

// ============================================================
// APIMonitor_x64/WinApiMonitorProtocol.h
// Purpose:
// 1) Provide a stable local include entry for the DLL project;
// 2) Forward actual protocol definitions uniformly to the shared directory at the repository root;
// 3) Avoid writing overly long cross-directory relative paths directly in the core/hook layer.
// ============================================================

#include "../../shared/WinApiMonitorProtocol.h"
