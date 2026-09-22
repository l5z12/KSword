#include "CliSupport.h"

namespace ksword::cli
{
    // commandLogFamily reads the non-IOCTL log ReadFile channel.
    // Inputs: argc/argv from wmain.
    // Processing: reads bounded frames until END_OF_LOG or --max-frames.
    // Returns: process exit code.
    int commandLogFamily(int argc, wchar_t* argv[])
    {
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 2);
        const std::uint32_t kMaxFrames = getOptionU32(kArgs, L"--max-frames", 64U);
        DriverHandle handle = openDriver(GENERIC_READ);
        if (!handle.isValid())
        {
            printWin32Error(L"CreateFileW(" KSWORD_ARK_LOG_WIN32_PATH L")", ::GetLastError());
            return 2;
        }
        std::vector<char> buffer(4096U, '\0');
        for (std::uint32_t frame = 0; frame < kMaxFrames; ++frame)
        {
            DWORD bytesRead = 0;
            if (::ReadFile(handle.native(), buffer.data(), static_cast<DWORD>(buffer.size() - 1U), &bytesRead, nullptr) == FALSE)
            {
                printWin32Error(L"ReadFile(log)", ::GetLastError());
                return 3;
            }
            if (bytesRead == 0U) break;
            std::string text(buffer.data(), buffer.data() + bytesRead);
            const std::size_t kMarker = text.find(KSWORD_ARK_LOG_END_MARKER);
            if (kMarker != std::string::npos)
            {
                text.resize(kMarker);
                std::cout << text;
                break;
            }
            std::cout << text;
        }
        return 0;
    }
}
