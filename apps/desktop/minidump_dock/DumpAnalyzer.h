#pragma once

// ============================================================
// DumpAnalyzer.h
// Purpose:
// - Aggregate parsed raw facts (stop code/exception code, parameters, crash address, call
//   stack, modules, and unloaded modules) into a single, directly readable diagnostic conclusion:
//   One-sentence conclusion + fault classification + evidence chain + candidate culprit module + troubleshooting suggestions;
// - Attribution uses weighted voting: if the same module is hit by multiple pieces of evidence, their
//   weights are accumulated. System core modules (ntoskrnl/hal/ntdll, etc.) are heavily down-weighted because
//   they almost always appear on the stack but are typically 'reporters' rather than 'culprits'—consistent
//   with the WinDbg !analyze approach of skipping system modules first to find third-party modules.
// Limitation:
// - Without symbols, attribution granularity is limited to modules; call stacks are derived from stack scanning and may contain
//   false positives. Therefore, all conclusions include a confidence level (High/Medium/Low) and avoid absolute assertions.
// Call method:
// - The kernel and user-mode parsing paths each call buildAnalysis once during cleanup.
//   Read-only fields already filled in the result are used to write directly into result.analysis.
// ============================================================

#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

namespace ks::minidump
{
    // buildAnalysis: Generate a comprehensive diagnostic conclusion and write it to result.analysis.
    // Pass modules (pre-built module index) and result (parse result, modified in-place);
    // Requires that result.kind, result.bugCheckCode, result.exceptionCode, result.faultingAddress,
    // result.stackFrames, result.modules, and result.unloadedModules be populated before calling.
    void buildAnalysis(const ModuleIndex& modules, DumpParseResult& result);

    // isSystemModule purpose: Determine if the module name belongs to a core module built into the operating system.
    // Input: moduleName is the module name, optionally including a path. Return whether it is a core system module.
    // During attribution, weight for such modules is reduced to avoid conclusions always pointing to ntoskrnl.exe.
    bool isSystemModule(const QString& moduleName);

    // analysisConfidenceText purpose: convert the confidence enum to Chinese text.
    // Input confidence; returns "No conclusion" if None.
    QString analysisConfidenceText(AnalysisConfidence confidence);
}
