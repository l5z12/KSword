#pragma once

#include "MemorySnapshot.h"

#include <cstddef>
#include <string>

namespace ksword::features::memory {

// renderMemorySnapshotHexAscii formats one immutable snapshot as an offset,
// hexadecimal-byte and printable-ASCII investigation view. It only consumes
// local snapshot bytes and never reads the target process again.
std::wstring renderMemorySnapshotHexAscii(
    const MemoryReadSnapshot& snapshot,
    std::size_t bytesPerLine = 16U);

// extractMemorySnapshotText reports bounded printable ASCII and UTF-16LE runs
// from a local snapshot. The helper is intentionally conservative: it emits
// evidence rather than pretending every byte sequence is a decoded string.
std::wstring extractMemorySnapshotText(
    const MemoryReadSnapshot& snapshot,
    std::size_t minimumRunLength = 4U);

// buildMemorySnapshotTextReport combines identity, transport status, hex/ASCII
// evidence and discovered text into one UTF-16 report suitable for copy/export.
std::wstring buildMemorySnapshotTextReport(const MemoryReadSnapshot& snapshot);

} // namespace Ksword::Features::Memory
