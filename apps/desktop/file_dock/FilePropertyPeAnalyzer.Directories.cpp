#include "FilePropertyPeAnalyzer.Internal.h"

// ============================================================
// FilePropertyPeAnalyzer.Directories.cpp
// Purpose:
// - Compatibility compilation unit for legacy PE data directory parsing fragments.
// - Resource, relocation, debug, TLS, CLR, certificate, and other directory summaries have been migrated to ksword/file/pe_analyzer.cpp;
// - Retain this empty compilation unit solely to stabilize existing .vcxproj entries; it no longer carries backend logic.
// Input: No runtime input.
// Processing: This file no longer depends on Qt containers or Win32 PE structure parsing implementations.
// Returns: Nothing.
// ============================================================
