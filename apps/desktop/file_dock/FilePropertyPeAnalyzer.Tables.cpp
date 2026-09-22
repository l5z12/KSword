#include "FilePropertyPeAnalyzer.Internal.h"

// ============================================================
// FilePropertyPeAnalyzer.Tables.cpp
// Purpose:
// - Compatibility compilation unit for legacy PE table entry parsing fragments;
// - The reusable PE basic analysis backend has been migrated to ks::file::analyzePeFile;
// - The UI layer now calls ks::file via FilePropertyPeAnalyzer.cpp and no longer maintains parsing logic in this file.
// Input: No runtime input.
// Processing: This file no longer registers or executes any PE parsing functions.
// Returns: Nothing.
// ============================================================
