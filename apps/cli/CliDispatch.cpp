#include "CliSupport.h"

namespace ksword::cli
{
    // Inputs: argc/argv from wmain; argv[1] is the command family.
    // Processing: keeps family routing centralized and leaves subcommand parsing
    //             to the family handlers.
    // Returns: process exit code from the selected handler.
    int dispatchCommand(int argc, wchar_t* argv[])
    {
        if (argc < 2 || argv[1] == nullptr)
        {
            printUsage();
            return 1;
        }

        const std::wstring kFamily = argv[1];
        if (isHelpToken(argv[1]))
        {
            return printHelpForTarget(argc, argv, 2);
        }
        if (argc >= 3 && isHelpToken(argv[2]))
        {
            return printHelpForTarget(argc, argv, 1);
        }
        if (argc >= 4 && hasTrailingHelpToken(argc, argv, 3))
        {
            return printSpecificCommandHelp(kFamily, argv[2]) ? 0 : 1;
        }
        if (const FamilyHelp* registration = findFamilyHelp(kFamily))
        {
            return registration->run(argc, argv);
        }

        std::wcerr << L"error: unknown family '" << kFamily << L"'\n";
        printUsage();
        return 1;
    }
}
