#include "MemoryInspection.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace ksword::features::memory {
namespace {

bool isPrintableAscii(const std::uint8_t value) noexcept {
    return value >= 0x20U && value <= 0x7EU;
}

wchar_t printableAsciiOrDot(const std::uint8_t value) noexcept {
    return isPrintableAscii(value) ? static_cast<wchar_t>(value) : L'.';
}

std::wstring formatAddress(const std::uint64_t value) {
    std::wostringstream output;
    output << L"0x" << std::uppercase << std::hex << std::setfill(L'0') << std::setw(16) << value;
    return output.str();
}

void appendTextRun(std::wstring& output,
    const wchar_t* encoding,
    const std::uint64_t address,
    const std::wstring& value) {
    output += encoding;
    output += L" ";
    output += formatAddress(address);
    output += L": ";
    output += value;
    output += L"\r\n";
}

} // namespace

std::wstring renderMemorySnapshotHexAscii(
    const MemoryReadSnapshot& snapshot,
    std::size_t bytesPerLine) {
    if (bytesPerLine == 0U) {
        bytesPerLine = 16U;
    }

    std::wostringstream output;
    output << L"Address             Hex";
    const std::size_t kPadding = bytesPerLine > 1U ? bytesPerLine * 3U - 3U : 2U;
    output << std::wstring(kPadding > 3U ? kPadding - 3U : 1U, L' ') << L" ASCII\r\n";
    for (std::size_t offset = 0U; offset < snapshot.bytes.size(); offset += bytesPerLine) {
        const std::size_t kLineSize = (std::min)(bytesPerLine, snapshot.bytes.size() - offset);
        output << formatAddress(snapshot.address + offset) << L"  ";
        for (std::size_t index = 0U; index < bytesPerLine; ++index) {
            if (index < kLineSize) {
                output << std::uppercase << std::hex << std::setfill(L'0') << std::setw(2)
                    << static_cast<unsigned>(snapshot.bytes[offset + index]) << L" ";
            } else {
                output << L"   ";
            }
        }
        output << std::dec << L" ";
        for (std::size_t index = 0U; index < kLineSize; ++index) {
            output << printableAsciiOrDot(snapshot.bytes[offset + index]);
        }
        output << L"\r\n";
    }
    return output.str();
}

std::wstring extractMemorySnapshotText(
    const MemoryReadSnapshot& snapshot,
    std::size_t minimumRunLength) {
    minimumRunLength = (std::max)(std::size_t{ 1U }, minimumRunLength);
    std::wstring output;

    for (std::size_t offset = 0U; offset < snapshot.bytes.size();) {
        if (!isPrintableAscii(snapshot.bytes[offset])) {
            ++offset;
            continue;
        }
        const std::size_t kStart = offset;
        std::wstring text;
        while (offset < snapshot.bytes.size() && isPrintableAscii(snapshot.bytes[offset])) {
            text.push_back(static_cast<wchar_t>(snapshot.bytes[offset]));
            ++offset;
        }
        if (text.size() >= minimumRunLength) {
            appendTextRun(output, L"ASCII", snapshot.address + kStart, text);
        }
    }

    for (std::size_t offset = 0U; offset + 1U < snapshot.bytes.size();) {
        if (!isPrintableAscii(snapshot.bytes[offset]) || snapshot.bytes[offset + 1U] != 0U) {
            ++offset;
            continue;
        }
        const std::size_t kStart = offset;
        std::wstring text;
        while (offset + 1U < snapshot.bytes.size() && isPrintableAscii(snapshot.bytes[offset]) &&
            snapshot.bytes[offset + 1U] == 0U) {
            text.push_back(static_cast<wchar_t>(snapshot.bytes[offset]));
            offset += 2U;
        }
        if (text.size() >= minimumRunLength) {
            appendTextRun(output, L"UTF-16LE", snapshot.address + kStart, text);
        }
    }

    return output.empty() ? L"未发现长度足够的 ASCII 或 UTF-16LE 文本。\r\n" : output;
}

std::wstring buildMemorySnapshotTextReport(const MemoryReadSnapshot& snapshot) {
    std::wostringstream output;
    output << L"[Memory Snapshot]\r\n"
           << L"Sequence: " << snapshot.sequence << L"\r\n"
           << L"PID: " << snapshot.processId << L"\r\n"
           << L"BaseAddress: " << formatAddress(snapshot.address) << L"\r\n"
           << L"RequestedBytes: " << snapshot.requestedBytes << L"\r\n"
           << L"ReturnedBytes: " << snapshot.bytes.size() << L"\r\n"
           << L"Status: " << snapshot.statusText << L"\r\n\r\n"
           << L"[Hex ASCII]\r\n" << renderMemorySnapshotHexAscii(snapshot) << L"\r\n"
           << L"[Text Runs]\r\n" << extractMemorySnapshotText(snapshot);
    return output.str();
}

} // namespace Ksword::Features::Memory
