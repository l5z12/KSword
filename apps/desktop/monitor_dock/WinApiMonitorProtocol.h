#pragma once

// ============================================================
// WinApiMonitorProtocol.h
// Purpose:
// 1) Retain the existing include path on the WinAPIDock side to prevent breakage when other main program code continues to reference it;
// 2) Actual protocol definitions are centralized in the repository root shared directory to ensure UI and Agent use the same protocol;
// 3) This file performs only lightweight forwarding and no longer maintains an independent protocol copy.
// ============================================================

#include "../../../shared/WinApiMonitorProtocol.h"
