#include "CliSupport.h"

namespace ksword::cli
{
    // printWin32Error renders a failed Win32 operation in a compact form.
    // Inputs: operation describes the API/IOCTL; error is GetLastError output.
    // Processing: prints decimal and hexadecimal forms for quick triage.
    // Returns: no value; output goes to stderr.
    void printWin32Error(const wchar_t* operation, DWORD error)
    {
        std::wcerr << L"error: " << operation << L" failed, win32=" << error
                   << L" (0x" << std::hex << error << std::dec << L")\n";
    }

    // fixedAnsi copies a fixed char array into std::string safely.
    // Inputs: text points at protocol storage; maxBytes is the field capacity.
    // Processing: scans until NUL or capacity, whichever comes first.
    // Returns: a possibly empty string without embedded protocol padding.
    std::string fixedAnsi(const char* text, std::size_t maxBytes)
    {
        if (text == nullptr || maxBytes == 0U)
        {
            return {};
        }

        std::size_t length = 0U;
        while (length < maxBytes && text[length] != '\0')
        {
            ++length;
        }
        return std::string(text, text + length);
    }

    // fixedWide copies a fixed wchar_t array into std::wstring safely.
    // Inputs: text points at protocol storage; maxChars is the field capacity.
    // Processing: scans until NUL or capacity, whichever comes first.
    // Returns: a possibly empty wide string without trailing padding.
    std::wstring fixedWide(const wchar_t* text, std::size_t maxChars)
    {
        if (text == nullptr || maxChars == 0U)
        {
            return {};
        }

        std::size_t length = 0U;
        while (length < maxChars && text[length] != L'\0')
        {
            ++length;
        }
        return std::wstring(text, text + length);
    }

    // ipcSummaryStatusName renders KSWORD_ARK_IPC_SUMMARY_STATUS_* values.
    // Inputs: status is a shared protocol enum returned by query IPC summary.
    // Processing: keeps legacy STUB distinguishable from current unavailable
    // states so acceptance does not confuse old-driver fallback with R0 evidence.
    // Returns: a stable human-readable status label for CLI output.
    const wchar_t* ipcSummaryStatusName(std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_IPC_SUMMARY_STATUS_OK:
            return L"OK";
        case KSWORD_ARK_IPC_SUMMARY_STATUS_PARTIAL:
            return L"Partial";
        case KSWORD_ARK_IPC_SUMMARY_STATUS_STUB:
            return L"LegacyStub";
        case KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED:
            return L"Failed";
        case KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE:
        default:
            return L"Unavailable";
        }
    }

    // fixedUtf16 copies unsigned-short UTF-16 protocol fields into std::wstring.
    // Inputs: text points at UTF-16 code units; maxChars bounds the scan.
    // Processing: casts code units to wchar_t, matching Windows UTF-16 wchar_t.
    // Returns: a std::wstring suitable for console output on Windows.
    std::wstring fixedUtf16(const unsigned short* text, std::size_t maxChars)
    {
        if (text == nullptr || maxChars == 0U)
        {
            return {};
        }

        std::wstring value;
        for (std::size_t index = 0U; index < maxChars && text[index] != 0U; ++index)
        {
            value.push_back(static_cast<wchar_t>(text[index]));
        }
        return value;
    }

    // hex64 formats a 64-bit integer as a fixed-width hexadecimal value.
    // Inputs: value is the integer to render.
    // Processing: uses an isolated stringstream to avoid mutating global cout state.
    // Returns: wide string in 0xNNNN form.
    std::wstring hex64(std::uint64_t value)
    {
        std::wostringstream stream;
        stream << L"0x" << std::hex << std::uppercase << value;
        return stream.str();
    }

    // hexdump prints raw bytes in a stable offset+ASCII layout.
    // Inputs: source bytes and an optional row width.
    // Processing: emits to stdout only; suitable for debugging variable payloads.
    // Returns: no value.
    void hexdump(const std::uint8_t* data, std::size_t size, std::size_t width )
    {
        if (data == nullptr || size == 0U)
        {
            std::wcout << L"(empty)\n";
            return;
        }

        for (std::size_t offset = 0U; offset < size; offset += width)
        {
            const std::size_t kLineBytes = std::min(width, size - offset);
            std::wcout << std::hex << std::setw(8) << std::setfill(L'0') << offset << L": ";
            for (std::size_t index = 0U; index < width; ++index)
            {
                if (index < kLineBytes)
                {
                    std::wcout << std::setw(2) << static_cast<unsigned int>(data[offset + index]) << L' ';
                }
                else
                {
                    std::wcout << L"   ";
                }
            }
            std::wcout << L"|";
            for (std::size_t index = 0U; index < kLineBytes; ++index)
            {
                const unsigned char kCh = data[offset + index];
                std::wcout << (kCh >= 32U && kCh < 127U ? static_cast<wchar_t>(kCh) : L'.');
            }
            std::wcout << L"|\n" << std::dec << std::setfill(L' ');
        }
    }

    // dumpWideText prints a fixed wide string only when it is non-empty.
    // Inputs: label and the decoded wide string.
    // Processing: emits one line in a consistent key/value format.
    // Returns: no value.
    void dumpWideText(const wchar_t* label, const std::wstring& value)
    {
        if (!value.empty())
        {
            std::wcout << L"  " << label << L"='" << value << L"'\n";
        }
    }

    // reportFixedResponse prints the common fixed-response banner.
    // Inputs: protocol version, status value, last status and bytesReturned.
    // Processing: standardizes the fields required by the plan.
    // Returns: no value.
    void reportFixedResponse(std::uint32_t version, std::uint32_t status, long lastStatus, DWORD bytesReturned)
    {
        std::wcout << L"version=" << version
                   << L" status=" << status
                   << L" lastStatus=0x" << std::hex << static_cast<unsigned long>(lastStatus)
                   << L" bytesReturned=" << std::dec << bytesReturned << L"\n";
    }

    // printResponseBanner keeps the older command implementations readable.
    // Inputs: the common version/status/last-status/byte-count tuple.
    // Processing: delegates to the normalized fixed-response printer.
    // Returns: no value; output goes to stdout.
    void printResponseBanner(std::uint32_t version, std::uint32_t status, long lastStatus, DWORD bytesReturned)
    {
        reportFixedResponse(version, status, lastStatus, bytesReturned);
    }

    // reportFixedStatus prints protocol/status fields for read-only fixed responses.
    // Inputs: protocol version, status and lastStatus fields.
    // Processing: leaves bytesReturned handling to the caller when it differs.
    // Returns: no value.
    void reportFixedStatus(std::uint32_t version, std::uint32_t status, long lastStatus)
    {
        std::wcout << L"version=" << version
                   << L" status=" << status
                   << L" lastStatus=0x" << std::hex << static_cast<unsigned long>(lastStatus)
                   << std::dec << L"\n";
    }

    // formatGuid128 renders the callback GUID packet in the same shape as UI code.
    // Inputs: fixed 16-byte GUID packet.
    // Processing: prints uppercase hexadecimal with 8-4-4-4-12 grouping.
    // Returns: formatted GUID text.
    std::wstring formatGuid128(const KSWORD_ARK_GUID128& guid)
    {
        std::wostringstream stream;
        const unsigned char* bytes = guid.bytes;
        stream << std::hex << std::uppercase << std::setfill(L'0')
               << std::setw(2) << static_cast<unsigned int>(bytes[0])
               << std::setw(2) << static_cast<unsigned int>(bytes[1])
               << std::setw(2) << static_cast<unsigned int>(bytes[2])
               << std::setw(2) << static_cast<unsigned int>(bytes[3]) << L"-"
               << std::setw(2) << static_cast<unsigned int>(bytes[4])
               << std::setw(2) << static_cast<unsigned int>(bytes[5]) << L"-"
               << std::setw(2) << static_cast<unsigned int>(bytes[6])
               << std::setw(2) << static_cast<unsigned int>(bytes[7]) << L"-"
               << std::setw(2) << static_cast<unsigned int>(bytes[8])
               << std::setw(2) << static_cast<unsigned int>(bytes[9]) << L"-"
               << std::setw(2) << static_cast<unsigned int>(bytes[10])
               << std::setw(2) << static_cast<unsigned int>(bytes[11])
               << std::setw(2) << static_cast<unsigned int>(bytes[12])
               << std::setw(2) << static_cast<unsigned int>(bytes[13])
               << std::setw(2) << static_cast<unsigned int>(bytes[14])
               << std::setw(2) << static_cast<unsigned int>(bytes[15]);
        return stream.str();
    }

    // printSimpleProcessEntry renders one process row with the most useful stable fields.
    // Inputs: shared process entry from a variable response.
    // Processing: prints IDs, field flags, object pointers and decoded names.
    // Returns: no value.
    void printSimpleProcessEntry(const KSWORD_ARK_PROCESS_ENTRY& entry)
    {
        std::wcout << L"  pid=" << entry.processId
                   << L" ppid=" << entry.parentProcessId
                   << L" flags=0x" << std::hex << entry.flags
                   << L" fieldFlags=0x" << entry.fieldFlags
                   << L" r0Status=" << std::dec << entry.r0Status
                   << L" image='" << fixedAnsi(entry.imageName, sizeof(entry.imageName)).c_str() << L"'\n";
        const std::wstring kImagePath = fixedUtf16(entry.imagePath, KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS);
        dumpWideText(L"imagePath", kImagePath);
    }

    // printSimpleThreadEntry renders one thread row with cross-view relevant fields.
    // Inputs: shared thread entry.
    // Processing: prints ID, flags, stack info availability and counter sources.
    // Returns: no value.
    void printSimpleThreadEntry(const KSWORD_ARK_THREAD_ENTRY& entry)
    {
        std::wcout << L"  tid=" << entry.threadId
                   << L" pid=" << entry.processId
                   << L" flags=0x" << std::hex << entry.flags
                   << L" fieldFlags=0x" << entry.fieldFlags
                   << L" r0Status=" << std::dec << entry.r0Status
                   << L" stackBase=" << hex64(entry.stackBase)
                   << L" kernelStack=" << hex64(entry.kernelStack) << L"\n";
    }

    // printCountHeader renders the common variable-response metadata.
    // Inputs: protocol version, total row count, returned row count, row byte size,
    // and DeviceIoControl bytesReturned.
    // Processing: prints the normalized acceptance fields first
    // (version/returned/total/entrySize/rowSize/bytesReturned/truncated), then keeps
    // legacy totalCount/returnedCount aliases so older scripts remain compatible.
    // Returns: no value.
    void printCountHeader(std::uint32_t version, std::uint32_t total, std::uint32_t returned, std::uint32_t entrySize, DWORD bytesReturned)
    {
        std::wcout << L"version=" << version
                   << L" returned=" << returned
                   << L" total=" << total
                   << L" entrySize=" << entrySize
                   << L" rowSize=" << entrySize
                   << L" bytesReturned=" << bytesReturned
                   << L" truncated=" << ((returned < total) ? 1U : 0U)
                   << L" totalCount=" << total
                   << L" returnedCount=" << returned << L"\n";
    }
}
