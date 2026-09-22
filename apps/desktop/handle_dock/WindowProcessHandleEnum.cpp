// ============================================================
// WindowProcessHandleEnum.cpp
// Purpose:
// - Retain the old console example for enumerating handles by path;
// - No longer maintains independent native handle query code;
// - Reuses the FileDock backend via ks::file::scanHandleUsageByPaths.
// Note: This file is not included in Ksword5.1.vcxproj and is retained solely as a manual diagnostic sample.
// ============================================================

#include "../../../shared/platform/file/FileHandleTools.h"

#include <Windows.h>

#include <iostream>
#include <string>
#include <vector>

int wmain(int argc, wchar_t* argv[])
{
    // Input arguments are one or more file/directory paths; directories are matched by prefix rules.
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);
    if (argc <= 1)
    {
        std::wcout << L"Usage: WindowProcessHandleEnum.exe <file-or-directory> [more paths...]\n";
        return 1;
    }

    // Path passed verbatim to ks::file; the backend generates DOS/NT dual-view matching rules.
    std::vector<std::wstring> pathList;
    for (int index = 1; index < argc; ++index)
    {
        if (argv[index] != nullptr && argv[index][0] != L'\0')
        {
            pathList.emplace_back(argv[index]);
        }
    }

    // The progress callback only outputs stage text; the real UI progress bar is handled by the FileDock adapter layer.
    ks::file::HandleUsageScanOptions options{};
    options.tryKernelHandleTable = true;
    options.progressCallback = [](const std::string& stepText, const float progressValue)
    {
        std::cout << "[" << progressValue << "%] " << stepText << std::endl;
    };

    const ks::file::HandleUsageScanResult kResult = ks::file::scanHandleUsageByPaths(pathList, options);
    std::wcout << L"matched=" << kResult.entries.size()
        << L" totalHandles=" << kResult.totalHandleCount
        << L" elapsedMs=" << kResult.elapsedMs << L"\n";
    if (!kResult.diagnosticText.empty())
    {
        std::wcout << L"diagnostic=" << kResult.diagnosticText << L"\n";
    }

    // Output hit source, including file handle, process image, and module load three backend result types.
    for (const ks::file::HandleUsageEntry& entry : kResult.entries)
    {
        std::wcout << L"PID=" << entry.processId
            << L" Process=" << entry.processName
            << L" Handle=0x" << std::hex << entry.handleValue << std::dec
            << L" Source=" << entry.enumerationSource
            << L" Rule=" << entry.matchRuleText
            << L" Object=" << entry.objectName << L"\n";
    }
    return 0;
}
