#include "CliSupport.h"

namespace ksword::cli
{
    DriverHandle openDriver(DWORD desiredAccess)
    {
        return ksword::ark::DriverClient{}.openSilently(desiredAccess);
    }

    IoctlResult sendIoctl(DriverHandle& handle, DWORD code, void* input,
        DWORD inputBytes, void* output, DWORD outputBytes)
    {
        if (!handle.isValid())
        {
            IoctlResult result;
            result.win32Error = ERROR_INVALID_HANDLE;
            return result;
        }
        return ksword::ark::DriverClient{}.deviceIoControl(
            code, input, inputBytes, output, outputBytes, &handle);
    }

    // readFileBytes loads a whole file into memory for blob-style IOCTL inputs.
    // Inputs: path and an upper size bound to reject oversized protocol blobs.
    // Processing: opens the file in binary mode and validates the actual length.
    // Returns: byte vector on success; throws on IO or size violations.
    std::vector<std::uint8_t> readFileBytes(const std::wstring& path, std::size_t maxBytes)
    {
        if (path.empty())
        {
            throw std::invalid_argument("file path");
        }

        HANDLE file = ::CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            throw std::runtime_error("open file");
        }

        LARGE_INTEGER size{};
        if (::GetFileSizeEx(file, &size) == FALSE)
        {
            ::CloseHandle(file);
            throw std::runtime_error("file size");
        }
        if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > maxBytes)
        {
            ::CloseHandle(file);
            throw std::out_of_range("file too large");
        }

        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
        DWORD readBytes = 0;
        if (!bytes.empty())
        {
            if (::ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &readBytes, nullptr) == FALSE)
            {
                ::CloseHandle(file);
                throw std::runtime_error("file read");
            }
            bytes.resize(readBytes);
        }
        ::CloseHandle(file);
        return bytes;
    }

    // copyWideToFixed writes a command-line string into a protocol wchar_t field.
    // Inputs: destination/capacity are the protocol field; source is user text.
    // Processing: truncates to leave room for NUL and clears the destination first.
    // Returns: no value; destination is always NUL terminated when capacity > 0.
    void copyWideToFixed(wchar_t* destination, std::size_t capacity, const std::wstring& source)
    {
        if (destination == nullptr || capacity == 0U)
        {
            return;
        }

        std::fill(destination, destination + capacity, L'\0');
        const std::size_t kChars = std::min<std::size_t>(source.size(), capacity - 1U);
        if (kChars != 0U)
        {
            std::copy(source.data(), source.data() + kChars, destination);
        }
    }

    // responseCountLimit bounds user-visible row printing.
    // Inputs: reported count, available count and CLI limit.
    // Processing: chooses the smallest count to keep parsing within buffer.
    // Returns: bounded count.
    std::size_t responseCountLimit(std::size_t reported, std::size_t available, std::size_t limit)
    {
        return std::min({ reported, available, limit });
    }

    // currentUtc100ns returns the current UTC FILETIME tick count.
    // Inputs: none.
    // Processing: converts GetSystemTimePreciseAsFileTime into a 64-bit scalar.
    // Returns: UTC time in 100ns units.
    std::uint64_t currentUtc100ns()
    {
        FILETIME fileTime{};
        ::GetSystemTimePreciseAsFileTime(&fileTime);
        ULARGE_INTEGER value{};
        value.HighPart = fileTime.dwHighDateTime;
        value.LowPart = fileTime.dwLowDateTime;
        return static_cast<std::uint64_t>(value.QuadPart);
    }

    // parseGuid128 decodes a 32-hex-digit callback GUID string.
    // Inputs: GUID text with or without dashes.
    // Processing: strips separators and decodes byte pairs in order.
    // Returns: GUID packet or throws on malformed text.
    KSWORD_ARK_GUID128 parseGuid128(const std::wstring& text)
    {
        const std::vector<std::uint8_t> kBytes = parseHexBytes(text);
        if (kBytes.size() != 16U)
        {
            throw std::invalid_argument("guid");
        }

        KSWORD_ARK_GUID128 guid{};
        std::memcpy(guid.bytes, kBytes.data(), 16U);
        return guid;
    }

    // loadBytesFromHexOrFile loads write payload bytes from --hex or --data-file.
    // Inputs: parsed args and the option names to consult.
    // Processing: enforces maxBytes and optional mandatory payload presence.
    // Returns: decoded bytes or throws on invalid/missing combinations.
    std::vector<std::uint8_t> loadBytesFromHexOrFile(
        const NamedArgs& args,
        const wchar_t* hexKey,
        const wchar_t* fileKey,
        std::size_t maxBytes,
        bool required)
    {
        const std::wstring* hexText = getOptionText(args, hexKey);
        const std::wstring* fileText = getOptionText(args, fileKey);
        if (hexText != nullptr && fileText != nullptr)
        {
            throw std::invalid_argument("mutually exclusive payload");
        }
        if (hexText == nullptr && fileText == nullptr)
        {
            if (required)
            {
                throw std::invalid_argument("payload");
            }
            return {};
        }

        std::vector<std::uint8_t> bytes =
            (hexText != nullptr) ? parseHexBytes(*hexText) : readFileBytes(*fileText, maxBytes);
        if (bytes.size() > maxBytes)
        {
            throw std::out_of_range("payload too large");
        }
        return bytes;
    }

    // openDriverOrReport opens the shared control device and emits a uniform error.
    // Inputs: desired access for the pending IOCTL.
    // Processing: caller receives a possibly-invalid handle and may stop on failure.
    // Returns: DriverHandle RAII wrapper.
    DriverHandle openDriverOrReport(DWORD desiredAccess )
    {
        DriverHandle handle = openDriver(desiredAccess);
        if (!handle.isValid())
        {
            printWin32Error(L"CreateFileW(" KSWORD_ARK_LOG_WIN32_PATH L")", ::GetLastError());
        }
        return handle;
    }

    // runNoOutputIoctl issues a control code whose success is mostly transport-level.
    // Inputs: control code and optional request buffer.
    // Processing: prints bytesReturned and Win32 completion information.
    // Returns: CLI exit code.
    int runNoOutputIoctl(
        const wchar_t* label,
        DWORD code,
        void* input,
        DWORD inputBytes,
        DWORD desiredAccess )
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.isValid())
        {
            return 2;
        }

        IoctlResult io = sendIoctl(handle, code, input, inputBytes, nullptr, 0U);
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return 3;
        }

        std::wcout << L"bytesReturned=" << io.bytesReturned
                   << L" win32Error=" << io.win32Error << L"\n";
        return 0;
    }

    // copyBytesToFixed copies a byte vector into a fixed protocol array.
    // Inputs: destination array, destination capacity, and source bytes.
    // Processing: zero-fills destination and copies at most capacity bytes.
    // Returns: no value; destination remains deterministic for METHOD_BUFFERED.
    void copyBytesToFixed(unsigned char* destination, std::size_t capacity, const std::vector<std::uint8_t>& source)
    {
        if (destination == nullptr || capacity == 0U)
        {
            return;
        }
        std::fill(destination, destination + capacity, 0U);
        const std::size_t kCopyBytes = std::min<std::size_t>(capacity, source.size());
        if (kCopyBytes != 0U)
        {
            std::copy(source.begin(), source.begin() + static_cast<std::ptrdiff_t>(kCopyBytes), destination);
        }
    }

    // checkedDwordSize converts vector sizes into Win32 DWORD byte counts.
    // Inputs: byte count in size_t.
    // Processing: rejects values that DeviceIoControl cannot represent.
    // Returns: DWORD byte count.
    DWORD checkedDwordSize(std::size_t bytes)
    {
        if (bytes > std::numeric_limits<DWORD>::max())
        {
            throw std::out_of_range("buffer too large");
        }
        return static_cast<DWORD>(bytes);
    }

    // boundedPathLength validates a fixed WCHAR path protocol field.
    // Inputs: command line path and target field capacity including terminator.
    // Processing: rejects empty or over-capacity paths before copying.
    // Returns: character length excluding NUL.
    unsigned short boundedPathLength(const std::wstring& pathText, std::size_t capacity)
    {
        if (pathText.empty() || pathText.size() >= capacity)
        {
            throw std::out_of_range("path length");
        }
        return static_cast<unsigned short>(pathText.size());
    }

    // sendRawIoctl opens the driver and performs one synchronous IOCTL call.
    // Inputs: label/code, optional input buffer, output buffer vector and access.
    // Processing: handles CreateFile/DeviceIoControl transport errors uniformly.
    // Returns: CLI-style exit code; io/output receive raw completion data.
    int sendRawIoctl(
        const wchar_t* label,
        DWORD code,
        void* input,
        DWORD inputBytes,
        std::vector<std::uint8_t>& output,
        IoctlResult& io,
        DWORD desiredAccess )
    {
        DriverHandle handle = openDriverOrReport(desiredAccess);
        if (!handle.isValid())
        {
            // When failing to open the device, retain the actual error code in io: callers typically
            // print io.win32Error in the failure branch; if not set, it prints 0, misreporting "Device
            // not found (2)" as "No error". The sibling function sendFixedRequestResponse does this.
            io.win32Error = ::GetLastError();
            io.ok = false;
            return 2;
        }
        io = sendIoctl(
            handle,
            code,
            input,
            inputBytes,
            output.empty() ? nullptr : output.data(),
            checkedDwordSize(output.size()));
        if (!io.ok)
        {
            printWin32Error(label, io.win32Error);
            return 3;
        }
        return 0;
    }

    // validateVariable validates header + variable entries before parsing rows.
    // Inputs: returned bytes, header size, entry size and minimum row size.
    // Processing: checks short buffers and invalid row sizes.
    // Returns: available row count in the returned buffer.
    std::size_t validateVariable(DWORD bytesReturned, std::size_t headerSize, std::uint32_t entrySize, std::size_t minEntrySize, const wchar_t* label)
    {
        if (bytesReturned < headerSize)
        {
            std::wcerr << L"error: " << label << L" response too small: " << bytesReturned << L" bytes\n";
            throw std::runtime_error("small response");
        }
        if (entrySize < minEntrySize)
        {
            std::wcerr << L"error: " << label << L" invalid entrySize=" << entrySize << L"\n";
            throw std::runtime_error("entry size");
        }
        return (static_cast<std::size_t>(bytesReturned) - headerSize) / static_cast<std::size_t>(entrySize);
    }

    // isUnsupportedTransportError recognizes old-driver or missing-IOCTL results.
    // Inputs: Win32 error returned by DeviceIoControl.
    // Processing: maps common unsupported/unimplemented transport statuses.
    // Returns: true when the caller should print "unsupported / unavailable".
    bool isUnsupportedTransportError(DWORD error)
    {
        return error == ERROR_INVALID_FUNCTION ||
               error == ERROR_NOT_SUPPORTED ||
               error == ERROR_CALL_NOT_IMPLEMENTED ||
               error == ERROR_PROC_NOT_FOUND;
    }

    // normalizeIoctlRc keeps new audit commands graceful on older drivers.
    // Inputs: feature label, IoctlResult and the raw helper return code.
    // Processing: rewrites missing IOCTL failures into a clear audit message.
    // Returns: CLI exit code; 5 means supported by CLI but unavailable in driver.
    int normalizeIoctlRc(const wchar_t* feature, const IoctlResult& io, int rc)
    {
        if (rc == 3 && isUnsupportedTransportError(io.win32Error))
        {
            std::wcout << L"unsupported / unavailable: " << feature
                       << L" (driver does not expose this read-only IOCTL)\n";
            return 5;
        }
        return rc;
    }

    // commandUnsupported reports a known command whose protocol is not present.
    // Inputs: feature and reason strings.
    // Processing: prints a stable phrase required by acceptance checks.
    // Returns: non-zero CLI status to let scripts detect degraded support.
    int commandUnsupported(const wchar_t* feature, const wchar_t* reason)
    {
        std::wcout << L"unsupported / unavailable: " << feature
                   << L" (" << reason << L")\n";
        return 5;
    }
}
