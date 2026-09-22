// ============================================================
// EnumProcessHandle.cpp
// Purpose:
// - Preserve the old handle enumeration console example file;
// - No longer maintains independent native handle query code;
// - Reuse the main process handle Dock backend via ks::file::buildHandleSnapshot.
// Note: This file is not included in Ksword5.1.vcxproj and is retained solely as a manual diagnostic sample.
// ============================================================

#include "../../../shared/platform/file/FileHandleTools.h"

#include <Windows.h>

#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t* argv[])
{
    // Use UTF-8 code page for console output to facilitate displaying Chinese paths in object names.
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);

    // Optional argument argv[1] is the PID; if not provided, enumerate the global handle snapshot.
    ks::file::HandleSnapshotOptions options{};
    options.enumMode = ks::file::HandleEnumMode::kDuplicateHandle;
    options.resolveObjectName = true;
    options.nameResolveBudget = 128;
    if (argc > 1 && argv[1] != nullptr && argv[1][0] != L'\0')
    {
        options.hasPidFilter = true;
        options.pidFilter = static_cast<std::uint32_t>(std::wcstoul(argv[1], nullptr, 10));
    }

    // The backend is responsible for dynamic Nt API loading, handle duplication, object name resolution, and filling R0/R3 difference fields.
    const ks::file::HandleSnapshotResult kResult = ks::file::buildHandleSnapshot(options);
    std::wcout << L"total=" << kResult.totalHandleCount
        << L" visible=" << kResult.visibleHandleCount
        << L" elapsedMs=" << kResult.elapsedMs << L"\n";
    if (!kResult.diagnosticText.empty())
    {
        std::wcout << L"diagnostic=" << kResult.diagnosticText << L"\n";
    }

    // The example prints only the first 200 rows to prevent the console from being flooded by a large system handle table.
    std::size_t printedCount = 0;
    for (const ks::file::HandleSnapshotRow& row : kResult.rows)
    {
        if (printedCount++ >= 200U)
        {
            std::wcout << L"<truncated>\n";
            break;
        }
        std::wcout << L"PID=" << row.processId
            << L" Process=" << row.processName
            << L" Handle=0x" << std::hex << row.handleValue << std::dec
            << L" Type=" << row.typeName
            << L" Name=" << row.objectName << L"\n";
    }
    return 0;
}
