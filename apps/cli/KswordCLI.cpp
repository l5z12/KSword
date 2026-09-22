#include "CliSupport.h"

namespace ksword::cli
{
    // configureConsole prepares stdout/stderr for Unicode-friendly diagnostics.
    // Inputs: none.
    // Processing: uses UTF-8 wide-text mode so console and redirected output do
    //             not contain UTF-16 NUL separators.
    // Returns: no value.
    void configureConsole()
    {
        (void)_setmode(_fileno(stdout), _O_U8TEXT);
        (void)_setmode(_fileno(stderr), _O_U8TEXT);
    }
}

using namespace ksword::cli;

int wmain(int argc, wchar_t* argv[])
{
    configureConsole();
    try
    {
        return dispatchCommand(argc, argv);
    }
    catch (const std::exception& ex)
    {
        const std::string kMessage = ex.what();
        std::wcerr << L"error: " << std::wstring(kMessage.begin(), kMessage.end()) << L"\n";
        return 1;
    }
}
