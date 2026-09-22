#pragma once

// ============================================================
// DumpBugCheckText.h
// Purpose:
// - Full interpretation capability for kernel BugCheck (blue screen stop codes) is centralized in this module:
//   Stop code names and meanings, fault categorization, itemized interpretation of the four parameters with
//   values, parameter sub-type tables specific to each stop code, and user-facing troubleshooting suggestions.
// - Division of labor with MinidumpCodeText.h: the latter contains user-mode exception codes and general interpretations for memory/streams,
//   while this file contains only tables related to kernel blue screens to prevent the single file from becoming unmanageably large.
// - "Interpreting each item with its value" is the reason this module exists: merely providing static
//   parameter descriptions (parameter 1 is an address, parameter 2 is IRQL, etc.) is worthless. Actual
//   values must be translated—mapping addresses to drivers, determining IRQL levels, identifying access
//   types (read/write), and specifying the exact NTSTATUS exception—to directly point to the root cause.
// Call method:
// After KernelDumpParser parses the bug check code and four parameters, it
//   passes them along with the ModuleIndex to describeBugCheckParameters.
// - DumpAnalyzer generates conclusions using bugCheckCategoryOf/bugCheckSuggestions.
// ============================================================

#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

namespace ks::minidump
{
    // BugCheckCategory: Fault classification for the stop code, determining which category of troubleshooting advice to provide.
    enum class BugCheckCategory
    {
        kUnknown,     // Unknown: Unclassified.
        kDriver,      // Driver: Driver defects (out-of-bounds access, use-after-free, IRQL violations, etc.).
        kMemory,      // Memory: Memory manager or pool consistency errors, which may be caused by driver corruption or physical memory faults.
        kHardware,    // Hardware: Errors reported by hardware (WHEA, Machine Check, Bus Errors).
        kFileSystem,  // FileSystem: File system or storage stack error.
        kPower,       // Power: related to power state transitions.
        kGraphics,    // Graphics: display driver / TDR.
        kWatchdog,    // Watchdog: Watchdog timeout (DPC, clock, PDC).
        kSecurity,    // Security: Kernel security checks / PatchGuard.
        kSoftware,    // Software: Abnormal exit of a critical system process or component.
        kBoot,        // Boot: Initialization failure during boot phase.
        kUserInitiated, // UserInitiated: Manually triggered crash dump.
    };

    // BugCheckParameterInfo: a complete interpretation of a specific BugCheck parameter.
    struct BugCheckParameterInfo
    {
        QString label;  // label: Chinese parameter name (e.g., "accessed memory address"); empty if unknown.
        QString value;  // value: Hexadecimal text of the parameter.
        QString detail; // detail: Interpretation based on values (module ownership, IRQL name, exception code name, etc.).
    };

    // bugCheckCodeNameEx: Returns the official name of the stop code.
    // Input: stop code; returns empty string if not recorded.
    QString bugCheckCodeNameEx(std::uint32_t code);

    // bugCheckMeaning purpose: return the Chinese meaning description of the stop code.
    // Input: stop code; returns empty string if not recorded.
    QString bugCheckMeaning(std::uint32_t code);

    // bugCheckCategoryOf: Returns the fault category of the stop code.
    // Accepts the stop code; returns 'Unknown' if not recorded.
    BugCheckCategory bugCheckCategoryOf(std::uint32_t code);

    // bugCheckCategoryText purpose: Converts fault categories into Chinese text.
    // Input: category; returns 'Uncategorized' when Unknown.
    QString bugCheckCategoryText(BugCheckCategory category);

    // describeBugCheckParameters: Translates the four parameters item-by-item into human-readable interpretations.
    // Input: code is the stop code; parameters contains four arguments; modules is the module index for address ownership;
    // pointerSize is the pointer width. Return exactly 4 interpretations, leaving label empty where semantics are unknown.
    std::vector<BugCheckParameterInfo> describeBugCheckParameters(
        std::uint32_t code,
        const std::uint64_t parameters[4],
        const ModuleIndex& modules,
        std::uint32_t pointerSize);

    // bugCheckSuggestions purpose: provides troubleshooting suggestions corresponding to the given stop code.
    // Accepts a bug check code; returns a list of Chinese suggestions, or generic category-level suggestions if not found.
    QStringList bugCheckSuggestions(std::uint32_t code);

    // faultingAddressFromBugCheck purpose: Extract the 'faulting instruction address' from the parameters.
    // Different stop codes place the instruction address in different parameter bits (0xD1 in parameter 4, 0x50 in
    // parameter 3, 0x7E in parameter 2, etc.). Attribution analysis relies on this to identify the offending module.
    // Takes code and four parameters; returns 0 for stop codes without this semantics.
    std::uint64_t faultingAddressFromBugCheck(
        std::uint32_t code,
        const std::uint64_t parameters[4]);

    // nestedStatusFromBugCheck purpose: extract the 'nested NTSTATUS exception code' from the parameters.
    // - Stop codes like 0x1E/0x7E/0x3B/0x8E are merely 'unhandled'; the actual cause is the NTSTATUS
    // in the parameters. Pass the code and four parameters; return 0 if this semantics do not apply.
    std::uint32_t nestedStatusFromBugCheck(
        std::uint32_t code,
        const std::uint64_t parameters[4]);

    // IrqlText purpose: convert IRQL value to level name.
    // Accepts an IRQL value; returns a string like '2 (DISPATCH_LEVEL)'.
    QString irqlText(std::uint64_t irql);

    // memoryAccessTypeText: converts 'read/write/execute' type codes to Chinese.
    // Accepts accessType (0: read, 1: write, 8 or 10: execute); returns a Chinese description.
    QString memoryAccessTypeText(std::uint64_t accessType);

    // ===== Subtype tables specific to each stop code below =====

    // memoryManagementSubcodeText purpose: Subcode for parameter 1 of 0x1A MEMORY_MANAGEMENT.
    QString memoryManagementSubcodeText(std::uint64_t subcode);

    // badPoolCallerText: 0xC2 BAD_POOL_CALLER, parameter 1 is the pool violation type.
    QString badPoolCallerText(std::uint64_t violationType);

    // driverVerifierViolationText: Subtype 0xC4 for Driver Verifier violation.
    QString driverVerifierViolationText(std::uint64_t subtype);

    // kernelSecurityCheckText purpose: 0x139 kernel security check failure subtype.
    QString kernelSecurityCheckText(std::uint64_t subtype);

    // kernelTrapText: returns text for parameter 1 (trap number) of 0x7F UNEXPECTED_KERNEL_MODE_TRAP.
    QString kernelTrapText(std::uint64_t trapNumber);

    // wheaErrorSourceText: 0x124 WHEA Parameter 1 error source type.
    QString wheaErrorSourceText(std::uint64_t sourceType);

    // dpcWatchdogText: Subtype for parameter 1 of 0x133 DPC_WATCHDOG_VIOLATION.
    QString dpcWatchdogText(std::uint64_t subtype);

    // powerStateFailureText purpose: 0x9F DRIVER_POWER_STATE_FAILURE parameter 1 subtype.
    QString powerStateFailureText(std::uint64_t subtype);

    // patchGuardRegionText purpose: Region number for parameter 4 of 0x109 CRITICAL_STRUCTURE_CORRUPTION.
    QString patchGuardRegionText(std::uint64_t region);

    // pnpFatalErrorText purpose: 0xCA PNP_DETECTED_FATAL_ERROR parameter 1 subcode.
    QString pnpFatalErrorText(std::uint64_t subcode);
}
