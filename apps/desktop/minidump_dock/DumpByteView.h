#pragma once

// ============================================================
// DumpByteView.h
// Purpose:
// - Format verified contiguous raw bytes from the dump file into fixed-width hexadecimal text.
// - Output: Contains target machine addresses, hexadecimal bytes,
//   and ASCII preview for the TRIAGE data block raw view page;
// - Only processes data already validated by the caller within file ranges; does not perform file I/O.
// Call method:
// - KernelDumpParser reads restricted previews and fills the DumpByteBlock.
// - Calls formatDumpBytes to generate read-only text when MinidumpDock renders the tab.
// ============================================================

#include <QString>

#include <cstdint>

namespace ks::minidump
{
    // formatDumpBytes: Renders raw bytes into a hexadecimal view with 16 bytes per line.
    // Parameter baseAddress: The virtual address or file offset of the first byte on the target machine, as specified by the caller's metadata.
    // Parameters bytes/byteCount: validated raw byte range.
    // Parameter omittedBytes: The count of remaining bytes not included in the preview, used for a trailing hint.
    // Returns: Raw text suitable for direct insertion into a read-only text control.
    QString formatDumpBytes(
        std::uint64_t baseAddress,
        const unsigned char* bytes,
        std::uint64_t byteCount,
        std::uint64_t omittedBytes = 0);
}
