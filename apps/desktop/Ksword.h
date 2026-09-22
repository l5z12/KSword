#pragma once

// ============================================================
// Ksword.h
// Purpose:
// 1) Serves as the Win32 tool entry header file at the root directory level;
// 2) Uniformly expose all capabilities under the ks namespace externally.
// 3) Meet the encapsulation goal of being reusable even when detached from KswordARK.
// ============================================================

// Notes:
// - The concrete implementation code is placed in the ksword/ recursive folder under the root directory.
// - The business layer only needs to include "Ksword.h".
#include "../../shared/platform/Ksword.h"
