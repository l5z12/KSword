#pragma once

// ============================================================
// DumpPoolTag.h
// Purpose:
// - Identify the pool tag (4 printable characters) from the stop code parameter and crash point
//   registers, and answer the most critical question: who allocated this problematic memory.
// - Ownership is determined by two explicit methods, not by guessing:
//   1) Read the triage\pooltag.txt file bundled with the WDK debugger (if present);
//   2) Search for these 4 bytes in the disk image of loaded modules: when the driver calls
//      ExAllocatePoolWithTag, the tag is an immediate value and must appear in its own image.
//
// Why this deserves separate handling (lessons from practice):
// A 0x13A KERNEL_MODE_HEAP_CORRUPTION crash stack once showed only ndis/NETIO; the next time it
//   showed conhost. Neither was the actual culprit—the pool corruption 'discoverer' was merely
//   the next entity to allocate memory. The true driver responsible is identified by the pool tag
//   of the corrupted block itself. Without this step, the names on the stack only mislead.
// - The same logic applies to 0x50: when crashing at ExFreePoolWithTag, the tag is in
//   the parameter registers, directly indicating "whose memory is being freed this time".
// Limitation:
// - Native Minidumps generated from local BSODs typically do not include the memory pages containing pool blocks,
//   so pool tags from pool headers cannot be retrieved; tags must instead be extracted from parameters and registers.
// - Image search can only prove that 'these 4 bytes appeared in the code of a certain module'; it is a strong clue
//   rather than definitive proof. When multiple modules match, all are listed without making a selection for the user.
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // Note: looksLikePoolTag purpose: Determine if a 32-bit value resembles a pool tag.
    // Input: value. Returns whether all 4 bytes fall within the common pool tag character set.
    // Strict criteria: Pool tags are conventionally printable ASCII, typically alphanumeric, with a trailing space allowed.
    bool looksLikePoolTag(std::uint32_t value);

    // poolTagText: Restores a 32-bit value to a 4-character text string in little-endian order.
    // Takes a value; returns a string like "KsFi". No validity check is performed; ensure looksLikePoolTag passes before calling.
    QString poolTagText(std::uint32_t value);

    // applyPoolTagAttribution purpose: Identify pool tag candidates and write them in-place to result.poolTags.
    // Note: Pass result (the parse result, modified in place); if a match is found, append a conclusion to analysis.findings.
    // Only emit if pool tag values actually appear in the bugcheck code or registers; do not generate noise.
    void applyPoolTagAttribution(DumpParseResult& result);
}
