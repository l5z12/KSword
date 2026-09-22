#include "ProcessDetailWindow.InternalCommon.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../internationalization/LanguageManager.h"

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.AdvancedInfo.cpp
// Purpose:
// - Asynchronously refresh thread details.
// - Token details refreshed asynchronously.
// - Token switch read and apply (NtSetInformationToken);
// - PEB/memory summary async refresh.
// ============================================================

namespace
{
    // NtQueryInformationThread function signature:
    // - The second parameter uses ULONG directly to avoid SDK enumeration differences.
    using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    // NtQueryInformationProcess function signature:
    // - Uniformly use ULONG information classes here to avoid compilation issues caused by SDK version differences.
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    // NtSetInformationToken function signature:
    // - The Windows Native API entry point is named NtSetInformationToken.
    // - This file treats it as the 'NtSetTokenInformation' semantics to drive token switch writes.
    using NtSetInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG);

    // PROCESSINFOCLASS key constants:
    // - These values are used to complete the depth information reading for token pages and PEB pages.
    // - If the target system does not support the corresponding info class, the query fails and automatically degrades.
    constexpr ULONG kProcessInfoClassDebugPort = 7;
    constexpr ULONG kProcessInfoClassBreakOnTermination = 29;
    constexpr ULONG kProcessInfoClassExecuteFlags = 34;
    constexpr ULONG kProcessInfoClassCommandLine = 60;
    constexpr ULONG kProcessInfoClassProtection = 61;
    constexpr ULONG kProcessInfoClassSubsystem = 75;

    // MandatoryPolicy bit constants:
    // - Some SDK versions may not export this macro.
    // - Provides a local constexpr fallback here to ensure the project compiles.
#ifndef TOKEN_MANDATORY_POLICY_NO_WRITE_UP
    constexpr DWORD kTokenMandatoryPolicyNoWriteUp = 0x1;
#else
    constexpr DWORD kTokenMandatoryPolicyNoWriteUp = TOKEN_MANDATORY_POLICY_NO_WRITE_UP;
#endif
#ifndef TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN
    constexpr DWORD kTokenMandatoryPolicyNewProcessMin = 0x2;
#else
    constexpr DWORD kTokenMandatoryPolicyNewProcessMin = TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN;
#endif

    // TOKEN_ADJUST_SESSIONID fallback constant:
    // - Some older SDKs may not define this access flag.
    // - Provides a unified numeric fallback here to avoid compilation differences.
#ifndef TOKEN_ADJUST_SESSIONID
    constexpr DWORD kTokenAdjustSessionIdAccess = 0x0100;
#else
    constexpr DWORD kTokenAdjustSessionIdAccess = TOKEN_ADJUST_SESSIONID;
#endif

    // Boolean semantics for TokenInformationClass constants:
    // - Uses numeric constants to avoid enumeration visibility differences across SDK headers.
    // - Corresponds one-to-one with the newly added checkboxes on the Token Switch page.
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassHasRestrictions =
        static_cast<TOKEN_INFORMATION_CLASS>(21);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsAppContainer =
        static_cast<TOKEN_INFORMATION_CLASS>(29);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsRestricted =
        static_cast<TOKEN_INFORMATION_CLASS>(40);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsLessPrivilegedAppContainer =
        static_cast<TOKEN_INFORMATION_CLASS>(46);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsSandboxed =
        static_cast<TOKEN_INFORMATION_CLASS>(47);
    constexpr TOKEN_INFORMATION_CLASS kTokenInfoClassIsAppSilo =
        static_cast<TOKEN_INFORMATION_CLASS>(51);

    // Structure required for GetProcessInformation(ProcessPowerThrottling):
    // - Use locally defined types to avoid dependency on type declarations only visible in newer SDK versions.
    struct ProcessPowerThrottlingStateNative
    {
        ULONG version = 0;      // Structure version number.
        ULONG controlMask = 0;  // Controllable bit mask.
        ULONG stateMask = 0;    // Current state bitmask
    };

    // GetProcessInformation dynamic function signature:
    // - The second parameter uses ULONG to represent the information class, ensuring compatibility across different header file environments.
    using GetProcessInformationFn = BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD);

    // ProcessWow64Information：
    // - NtQueryInformationProcess information class 26.
    // - When a 64-bit controller reads a 32-bit target, it must first retrieve the Wow64 PEB, then parse using 32-bit structures.
    constexpr ULONG kProcessInfoClassWow64Information = 26;

    // PEB text read limit:
    // - UNICODE_STRING length comes from a remote process and must be bounded first;
    // - Prevent UI background threads from allocating excessive memory due to corrupted or forged ProcessParameters.
    constexpr std::size_t kMaxRemoteUnicodeBytes = 256 * 1024;

    // Maximum limit for environment block preview:
    // - There is no stable, cross-version dependent field for environment block length within the PEB;
    // - Use chunked reading and stop at double NUL or when the limit is reached.
    constexpr std::size_t kMaxEnvironmentPreviewBytes = 128 * 1024;
    constexpr std::size_t kEnvironmentReadChunkBytes = 4096;
    constexpr std::size_t kMaxEnvironmentPreviewLines = 20;
    constexpr std::size_t kMaxEnvironmentLineChars = 4096;

    // RemoteUnicodeString32：
    // - Layout of UNICODE_STRING within a 32-bit target process;
    // - The buffer is a remote 32-bit address and cannot be used directly as the current process's UNICODE_STRING.
    struct RemoteUnicodeString32 final
    {
        USHORT length = 0;        // Byte length, excluding the terminating NUL.
        USHORT maximumLength = 0; // Byte capacity, which may be greater than length.
        std::uint32_t buffer = 0; // Remote 32-bit PWSTR address.
    };

    // Curdir32/Curdir64：
    // - Corresponds to RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.
    // - Retain only DosPath and Handle to satisfy the display of the current directory in the details page.
    struct Curdir32 final
    {
        RemoteUnicodeString32 dosPath{};
        std::uint32_t handle = 0;
    };

    struct Curdir64 final
    {
        UNICODE_STRING dosPath{};
        PVOID handle = nullptr;
    };

    // Peb32Lite/Peb64Lite：
    // - Overwrite only the PEB starting fields up to ProcessParameters.
    // - Avoid reading the full SDK PEB structure to reduce failure probability due to field changes across versions.
    struct Peb32Lite final
    {
        BYTE reserved1[2]{};
        BYTE beingDebugged = 0;
        BYTE reserved2[1]{};
        std::uint32_t mutant = 0;
        std::uint32_t imageBaseAddress = 0;
        std::uint32_t ldr = 0;
        std::uint32_t processParameters = 0;
    };

    struct Peb64Lite final
    {
        BYTE reserved1[2]{};
        BYTE beingDebugged = 0;
        BYTE reserved2[1]{};
        PVOID mutant = nullptr;
        PVOID imageBaseAddress = nullptr;
        PVOID ldr = nullptr;
        PVOID processParameters = nullptr;
    };

    // RtlUserProcessParameters32Lite/RtlUserProcessParameters64Lite：
    // - Overwrite CurrentDirectory/ImagePathName/CommandLine/Environment according to public stable offsets.
    // - Pointers and UNICODE_STRING sizes differ between 32-bit and 64-bit; they must be defined separately.
    struct RtlUserProcessParameters32Lite final
    {
        BYTE reservedBeforeCurrentDirectory[0x24]{};
        Curdir32 currentDirectory{};
        RemoteUnicodeString32 dllPath{};
        RemoteUnicodeString32 imagePathName{};
        RemoteUnicodeString32 commandLine{};
        std::uint32_t environment = 0;
    };

    struct RtlUserProcessParameters64Lite final
    {
        BYTE reservedBeforeCurrentDirectory[0x38]{};
        Curdir64 currentDirectory{};
        UNICODE_STRING dllPath{};
        UNICODE_STRING imagePathName{};
        UNICODE_STRING commandLine{};
        PVOID environment = nullptr;
    };

    // RemotePebProcessParametersRead：
    // - Carries the result of a single PEB->ProcessParameters parsing;
    // - readOk indicates the parameter block structure was read successfully; an empty string does not necessarily imply a read failure.
    struct RemotePebProcessParametersRead final
    {
        QString labelText;                         // Native PEB / Wow64 PEB。
        bool readOk = false;                       // Whether ProcessParameters was successfully read.
        std::uint64_t pebAddress = 0;              // PEB address.
        std::uint64_t imageBaseAddress = 0;         // PEB.ImageBaseAddress。
        std::uint64_t processParametersAddress = 0;// Address of ProcessParameters.
        std::uint64_t environmentAddress = 0;      // Environment address.
        QString commandLineText;                   // Command line within PEB.
        QString imagePathText;                     // Image path within PEB.
        QString currentDirectoryText;              // Current directory within PEB.
        QString diagnosticText;                    // Failure or downgrade reason.
    };

    // queryNtProcessInfoFixed：
    // - Read the 'fixed-size' NtQueryInformationProcess output structure;
    // - Return true on success; return false on failure.
    template<typename T>
    bool queryNtProcessInfoFixed(
        const NtQueryInformationProcessFn queryFunction,
        HANDLE processHandle,
        const ULONG infoClass,
        T& outValue)
    {
        if (queryFunction == nullptr || processHandle == nullptr)
        {
            return false;
        }

        std::memset(&outValue, 0, sizeof(T));
        const NTSTATUS kStatus = queryFunction(
            processHandle,
            infoClass,
            &outValue,
            static_cast<ULONG>(sizeof(T)),
            nullptr);
        return NT_SUCCESS(kStatus);
    }

    // queryNtProcessInfoBuffer：
    // - Read the variable-length buffer output of NtQueryInformationProcess;
    // - For example, scenarios like ProcessCommandLineInformation.
    bool queryNtProcessInfoBuffer(
        const NtQueryInformationProcessFn queryFunction,
        HANDLE processHandle,
        const ULONG infoClass,
        std::vector<std::uint8_t>& bufferOut)
    {
        bufferOut.clear();
        if (queryFunction == nullptr || processHandle == nullptr)
        {
            return false;
        }

        ULONG requiredLength = 0;
        NTSTATUS firstStatus = queryFunction(
            processHandle,
            infoClass,
            nullptr,
            0,
            &requiredLength);

        if (!NT_SUCCESS(firstStatus) && requiredLength == 0)
        {
            return false;
        }

        if (requiredLength < sizeof(UNICODE_STRING))
        {
            requiredLength = static_cast<ULONG>(sizeof(UNICODE_STRING) + 512);
        }

        bufferOut.resize(requiredLength + sizeof(wchar_t), 0);
        NTSTATUS secondStatus = queryFunction(
            processHandle,
            infoClass,
            bufferOut.data(),
            static_cast<ULONG>(bufferOut.size()),
            &requiredLength);
        if (!NT_SUCCESS(secondStatus))
        {
            bufferOut.clear();
            return false;
        }
        return true;
    }

    // queryCommandLineTextByNt：
    // - Read the command line via ProcessCommandLineInformation;
    // - Supports both implementations: returning an embedded string and returning a remote pointer.
    QString queryCommandLineTextByNt(
        const NtQueryInformationProcessFn queryFunction,
        HANDLE processHandle)
    {
        std::vector<std::uint8_t> commandBuffer;
        if (!queryNtProcessInfoBuffer(
            queryFunction,
            processHandle,
            kProcessInfoClassCommandLine,
            commandBuffer))
        {
            return QString();
        }

        const auto* commandUnicode = reinterpret_cast<const UNICODE_STRING*>(commandBuffer.data());
        if (commandUnicode == nullptr || commandUnicode->Length == 0 || commandUnicode->Buffer == nullptr)
        {
            return QString();
        }

        const std::uintptr_t kBufferBegin = reinterpret_cast<std::uintptr_t>(commandBuffer.data());
        const std::uintptr_t kBufferSize = commandBuffer.size();
        const std::uintptr_t kStringPtr = reinterpret_cast<std::uintptr_t>(commandUnicode->Buffer);
        const std::size_t kStringLengthBytes = static_cast<std::size_t>(commandUnicode->Length);
        if ((kStringLengthBytes % sizeof(wchar_t)) != 0 || kStringLengthBytes > kMaxRemoteUnicodeBytes)
        {
            return QString();
        }

        // Case A: The string is located directly within the returned buffer.
        if (kStringPtr >= kBufferBegin &&
            kStringPtr - kBufferBegin <= kBufferSize &&
            kStringLengthBytes <= kBufferSize - (kStringPtr - kBufferBegin))
        {
            return QString::fromWCharArray(
                reinterpret_cast<const wchar_t*>(kStringPtr),
                static_cast<int>(commandUnicode->Length / sizeof(wchar_t)));
        }

        // Case B: The return value is a remote pointer, requiring a second ReadProcessMemory call.
        std::vector<wchar_t> remoteChars(
            static_cast<std::size_t>(commandUnicode->Length / sizeof(wchar_t)) + 1,
            L'\0');
        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ReadProcessMemory(
            processHandle,
            commandUnicode->Buffer,
            remoteChars.data(),
            commandUnicode->Length,
            &bytesRead);
        if (kReadOk == FALSE || bytesRead == 0)
        {
            return QString();
        }
        return QString::fromWCharArray(remoteChars.data());
    }

    // appendPebDiagnostic：
    // - Appends non-fatal errors from PEB parsing to diagnostic text;
    // - Input parameter target is the mutable diagnostic text, and message is the content to append.
    // - Return: None. The caller continues to the subsequent fallback path.
    void appendPebDiagnostic(QString& target, const QString& message)
    {
        if (message.trimmed().isEmpty())
        {
            return;
        }

        if (!target.trimmed().isEmpty())
        {
            target += QStringLiteral(" | ");
        }
        target += message;
    }

    // readRemoteMemoryExact：
    // - Read a fixed length of memory from a remote process.
    // - Input: processHandle is the target process handle; remoteAddress is the target address.
    // - The input parameters localBuffer and localSize represent the local receive buffer.
    // - Returns true if localSize bytes were read completely; false if the address is invalid or only partial data was read.
    bool readRemoteMemoryExact(
        HANDLE processHandle,
        const std::uint64_t remoteAddress,
        void* localBuffer,
        const SIZE_T localSize)
    {
        if (processHandle == nullptr || remoteAddress == 0 || localBuffer == nullptr || localSize == 0)
        {
            return false;
        }

        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localBuffer,
            localSize,
            &bytesRead);
        return kReadOk != FALSE && bytesRead == localSize;
    }

    // readRemoteStructure：
    // - Read a remote structure based on template type;
    // - Clear the output before reading to avoid leftover old data on failure;
    // - Returns true if the structure is fully read; returns false if the remote page is unreadable or the length is insufficient.
    template<typename T>
    bool readRemoteStructure(
        HANDLE processHandle,
        const std::uint64_t remoteAddress,
        T& valueOut)
    {
        std::memset(&valueOut, 0, sizeof(T));
        return readRemoteMemoryExact(
            processHandle,
            remoteAddress,
            &valueOut,
            static_cast<SIZE_T>(sizeof(T)));
    }

    // readRemoteUnicodeStringByAddress：
    // - Read UTF-16 strings by 'remote address + byte length';
    // - Handle: Perform even-length validation and upper limit checks to prevent excessive allocation triggered by a corrupted PEB.
    // - Returns the read QString; returns an empty QString on failure or if the string is empty.
    QString readRemoteUnicodeStringByAddress(
        HANDLE processHandle,
        const std::uint64_t bufferAddress,
        const USHORT lengthBytes)
    {
        if (processHandle == nullptr || bufferAddress == 0 || lengthBytes == 0)
        {
            return QString();
        }

        if ((lengthBytes % sizeof(wchar_t)) != 0 ||
            static_cast<std::size_t>(lengthBytes) > kMaxRemoteUnicodeBytes)
        {
            return QString();
        }

        std::vector<wchar_t> stringBuffer(
            static_cast<std::size_t>(lengthBytes / sizeof(wchar_t)) + 1,
            L'\0');
        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(bufferAddress)),
            stringBuffer.data(),
            static_cast<SIZE_T>(lengthBytes),
            &bytesRead);
        if (kReadOk == FALSE || bytesRead < sizeof(wchar_t))
        {
            return QString();
        }

        if (bytesRead > lengthBytes)
        {
            bytesRead = lengthBytes;
        }

        const int kCharCount = static_cast<int>(bytesRead / sizeof(wchar_t));
        if (kCharCount <= 0)
        {
            return QString();
        }
        stringBuffer[static_cast<std::size_t>(kCharCount)] = L'\0';
        return QString::fromWCharArray(stringBuffer.data(), kCharCount);
    }

    // readRemoteUnicodeString64：
    // - Read UNICODE_STRING from a 64-bit target structure;
    // - Input: UNICODE_STRING snapshot of the current process bit-width;
    // - Returns the string text; returns empty on failure.
    QString readRemoteUnicodeString64(
        HANDLE processHandle,
        const UNICODE_STRING& remoteUnicode)
    {
        return readRemoteUnicodeStringByAddress(
            processHandle,
            reinterpret_cast<std::uint64_t>(remoteUnicode.Buffer),
            remoteUnicode.Length);
    }

    // readRemoteUnicodeString32：
    // - Read the UNICODE_STRING from the 32-bit target structure;
    // - Input: manually defined 32-bit layout; Buffer is promoted to 64-bit address before reading;
    // - Returns the string text; returns empty on failure.
    QString readRemoteUnicodeString32(
        HANDLE processHandle,
        const RemoteUnicodeString32& remoteUnicode)
    {
        return readRemoteUnicodeStringByAddress(
            processHandle,
            static_cast<std::uint64_t>(remoteUnicode.buffer),
            remoteUnicode.length);
    }

    // readRemoteEnvironmentPreviewLines：
    // - Read the remote environment variable block in chunks until a double NUL is encountered, a read failure occurs, or the limit is reached.
    // - Return only the first kMaxEnvironmentPreviewLines lines to avoid excessive UI text.
    // - diagnosticTextOut: Optional output for truncation/failure hints.
    // - Returns a list of environment variable preview lines; returns an empty list if reading fails.
    QStringList readRemoteEnvironmentPreviewLines(
        HANDLE processHandle,
        const std::uint64_t environmentAddress,
        QString* diagnosticTextOut)
    {
        if (diagnosticTextOut != nullptr)
        {
            diagnosticTextOut->clear();
        }
        if (processHandle == nullptr || environmentAddress == 0)
        {
            return {};
        }

        std::vector<wchar_t> environmentChars;
        environmentChars.reserve(kEnvironmentReadChunkBytes / sizeof(wchar_t));

        bool foundDoubleNull = false;
        bool readStoppedByError = false;
        std::size_t offsetBytes = 0;
        while (offsetBytes < kMaxEnvironmentPreviewBytes)
        {
            const std::size_t kBytesRemaining = kMaxEnvironmentPreviewBytes - offsetBytes;
            const std::size_t kRequestBytes = std::min<std::size_t>(
                kEnvironmentReadChunkBytes,
                kBytesRemaining);
            std::vector<std::uint8_t> chunkBuffer(kRequestBytes, 0);

            SIZE_T bytesRead = 0;
            const BOOL kReadOk = ReadProcessMemory(
                processHandle,
                reinterpret_cast<LPCVOID>(
                    static_cast<std::uintptr_t>(environmentAddress + offsetBytes)),
                chunkBuffer.data(),
                static_cast<SIZE_T>(chunkBuffer.size()),
                &bytesRead);
            if (kReadOk == FALSE || bytesRead < sizeof(wchar_t))
            {
                readStoppedByError = true;
                break;
            }

            const std::size_t kCharCount = static_cast<std::size_t>(bytesRead / sizeof(wchar_t));
            const std::size_t kScanStartIndex = environmentChars.empty()
                ? 1
                : environmentChars.size();
            const auto* chunkChars = reinterpret_cast<const wchar_t*>(chunkBuffer.data());
            environmentChars.insert(environmentChars.end(), chunkChars, chunkChars + kCharCount);

            for (std::size_t index = kScanStartIndex; index < environmentChars.size(); ++index)
            {
                if (environmentChars[index - 1] == L'\0' && environmentChars[index] == L'\0')
                {
                    environmentChars.resize(index);
                    foundDoubleNull = true;
                    break;
                }
            }
            if (foundDoubleNull)
            {
                break;
            }

            const std::size_t kConsumedBytes = kCharCount * sizeof(wchar_t);
            if (kConsumedBytes == 0 || kConsumedBytes < kRequestBytes)
            {
                readStoppedByError = true;
                break;
            }
            offsetBytes += kConsumedBytes;
        }

        QStringList lines;
        std::size_t cursorIndex = 0;
        while (cursorIndex < environmentChars.size() &&
            lines.size() < static_cast<int>(kMaxEnvironmentPreviewLines))
        {
            const wchar_t* currentLine = environmentChars.data() + cursorIndex;
            std::size_t currentLength = 0;
            while (cursorIndex + currentLength < environmentChars.size() &&
                environmentChars[cursorIndex + currentLength] != L'\0')
            {
                ++currentLength;
            }
            if (currentLength == 0)
            {
                break;
            }

            const int kVisibleLength = static_cast<int>(
                std::min<std::size_t>(currentLength, kMaxEnvironmentLineChars));
            QString lineText = QString::fromWCharArray(currentLine, kVisibleLength);
            if (currentLength > kMaxEnvironmentLineChars)
            {
                lineText += QStringLiteral(" ...<truncated>");
            }
            lines.push_back(lineText);
            cursorIndex += currentLength + 1;
        }

        if (diagnosticTextOut != nullptr)
        {
            if (!foundDoubleNull && offsetBytes >= kMaxEnvironmentPreviewBytes)
            {
                *diagnosticTextOut = QStringLiteral("环境变量块预览达到128KB上限，已截断。");
            }
            else if (readStoppedByError && lines.empty())
            {
                *diagnosticTextOut = QStringLiteral("环境变量块地址不可完整读取。");
            }
        }

        return lines;
    }

    // readPebProcessParameters64：
    // - Parse PEB->RTL_USER_PROCESS_PARAMETERS according to the 64-bit layout.
    // - Outputs command line, image path, current directory, and environment block address;
    // - Returns a structure carrying `readOk` and diagnostic text; does not throw exceptions directly.
    RemotePebProcessParametersRead readPebProcessParameters64(
        HANDLE processHandle,
        const std::uint64_t pebAddress,
        const QString& labelText)
    {
        RemotePebProcessParametersRead result{};
        result.labelText = labelText;
        result.pebAddress = pebAddress;

        Peb64Lite pebSnapshot{};
        if (!readRemoteStructure(processHandle, pebAddress, pebSnapshot))
        {
            result.diagnosticText = QStringLiteral("读取64位PEB头失败。");
            return result;
        }

        result.processParametersAddress = reinterpret_cast<std::uint64_t>(
            pebSnapshot.processParameters);
        result.imageBaseAddress = reinterpret_cast<std::uint64_t>(
            pebSnapshot.imageBaseAddress);
        if (result.processParametersAddress == 0)
        {
            result.diagnosticText = QStringLiteral("64位PEB.ProcessParameters为空。");
            return result;
        }

        RtlUserProcessParameters64Lite processParameters{};
        if (!readRemoteStructure(
            processHandle,
            result.processParametersAddress,
            processParameters))
        {
            result.diagnosticText = QStringLiteral("读取64位RTL_USER_PROCESS_PARAMETERS失败。");
            return result;
        }

        result.readOk = true;
        result.environmentAddress = reinterpret_cast<std::uint64_t>(
            processParameters.environment);
        result.commandLineText = readRemoteUnicodeString64(
            processHandle,
            processParameters.commandLine);
        result.imagePathText = readRemoteUnicodeString64(
            processHandle,
            processParameters.imagePathName);
        result.currentDirectoryText = readRemoteUnicodeString64(
            processHandle,
            processParameters.currentDirectory.dosPath);
        return result;
    }

    // readPebProcessParameters32：
    // - Parse PEB->RTL_USER_PROCESS_PARAMETERS according to the Wow64 32-bit layout;
    // - Resolves parsing failures when reading 32-bit targets with 64-bit structure offsets in 64-bit processes.
    // - Returns a structure carrying `readOk` and diagnostic text; does not throw exceptions directly.
    RemotePebProcessParametersRead readPebProcessParameters32(
        HANDLE processHandle,
        const std::uint64_t pebAddress,
        const QString& labelText)
    {
        RemotePebProcessParametersRead result{};
        result.labelText = labelText;
        result.pebAddress = pebAddress;

        Peb32Lite pebSnapshot{};
        if (!readRemoteStructure(processHandle, pebAddress, pebSnapshot))
        {
            result.diagnosticText = QStringLiteral("读取32位PEB头失败。");
            return result;
        }

        result.processParametersAddress = static_cast<std::uint64_t>(
            pebSnapshot.processParameters);
        result.imageBaseAddress = static_cast<std::uint64_t>(
            pebSnapshot.imageBaseAddress);
        if (result.processParametersAddress == 0)
        {
            result.diagnosticText = QStringLiteral("32位PEB.ProcessParameters为空。");
            return result;
        }

        RtlUserProcessParameters32Lite processParameters{};
        if (!readRemoteStructure(
            processHandle,
            result.processParametersAddress,
            processParameters))
        {
            result.diagnosticText = QStringLiteral("读取32位RTL_USER_PROCESS_PARAMETERS失败。");
            return result;
        }

        result.readOk = true;
        result.environmentAddress = static_cast<std::uint64_t>(
            processParameters.environment);
        result.commandLineText = readRemoteUnicodeString32(
            processHandle,
            processParameters.commandLine);
        result.imagePathText = readRemoteUnicodeString32(
            processHandle,
            processParameters.imagePathName);
        result.currentDirectoryText = readRemoteUnicodeString32(
            processHandle,
            processParameters.currentDirectory.dosPath);
        return result;
    }

    // PebEditTargetSnapshot：
    // Represents the target context for a 'prepare to write PEB' operation.
    // - When isWow64Target=true, write according to the 32-bit PEB/ProcessParameters layout;
    // - Returned for use by the UI write flow; does not directly hold handle lifetimes.
    struct PebEditTargetSnapshot final
    {
        bool valid = false;                         // Whether the target PEB was successfully parsed.
        bool isWow64Target = false;                 // true = Wow64PEB/32-bit layout; false = NativePEB/64-bit layout.
        std::uint64_t pebAddress = 0;               // Remote PEB address.
        std::uint64_t processParametersAddress = 0; // Address of the remote RTL_USER_PROCESS_PARAMETERS.
        std::uint64_t imageBaseAddress = 0;         // Current PEB.ImageBaseAddress.
        std::uint64_t environmentAddress = 0;       // Current Environment pointer.
        RtlUserProcessParameters64Lite params64{};  // 64-bit parameter block snapshot.
        RtlUserProcessParameters32Lite params32{};  // 32-bit parameter block snapshot.
        QString errorText;                          // Failure reason.
    };

    // parseUnsignedIntegerText：
    // - Parse hexadecimal/decimal unsigned integers from UI input;
    // - Supports 0x prefix (case-insensitive) and pure decimal.
    // - Writes to valueOut and returns true on success; returns false on failure.
    bool parseUnsignedIntegerText(const QString& inputText, std::uint64_t& valueOut)
    {
        QString text = inputText.trimmed();
        if (text.isEmpty())
        {
            return false;
        }

        bool ok = false;
        int base = 10;
        if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            text = text.mid(2);
            base = 16;
        }
        valueOut = text.toULongLong(&ok, base);
        return ok;
    }

    // writeRemoteBytesWithProtect：
    // - Write a segment of remote memory to the target process;
    // - First attempt WriteProcessMemory directly; if it fails, temporarily change to PAGE_READWRITE and retry;
    // - Returns true for a complete write; false if the address is unwritable or permissions are insufficient.
    bool writeRemoteBytesWithProtect(
        HANDLE processHandle,
        const std::uint64_t remoteAddress,
        const void* localBuffer,
        const SIZE_T localSize,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (processHandle == nullptr || remoteAddress == 0 || localBuffer == nullptr || localSize == 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("写入参数为空。");
            }
            return false;
        }

        SIZE_T bytesWritten = 0;
        BOOL writeOk = WriteProcessMemory(
            processHandle,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localBuffer,
            localSize,
            &bytesWritten);
        if (writeOk != FALSE && bytesWritten == localSize)
        {
            return true;
        }

        const DWORD kFirstError = GetLastError();
        DWORD oldProtect = 0;
        if (VirtualProtectEx(
            processHandle,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localSize,
            PAGE_READWRITE,
            &oldProtect) == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("WriteProcessMemory失败(%1)，VirtualProtectEx失败(%2)。")
                    .arg(kFirstError)
                    .arg(GetLastError());
            }
            return false;
        }

        bytesWritten = 0;
        writeOk = WriteProcessMemory(
            processHandle,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localBuffer,
            localSize,
            &bytesWritten);
        const DWORD kSecondError = GetLastError();

        DWORD ignoredProtect = 0;
        VirtualProtectEx(
            processHandle,
            reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localSize,
            oldProtect,
            &ignoredProtect);

        if (writeOk != FALSE && bytesWritten == localSize)
        {
            return true;
        }
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("WriteProcessMemory失败(%1)，重试失败(%2)，written=%3/%4。")
                .arg(kFirstError)
                .arg(kSecondError)
                .arg(static_cast<qulonglong>(bytesWritten))
                .arg(static_cast<qulonglong>(localSize));
        }
        return false;
    }

    // buildRemoteUtf16Buffer：
    // - Convert QString to a UTF-16LE buffer usable by remote UNICODE_STRING.
    // - Output includes trailing NUL; Length field is still used by caller as byte count excluding NUL.
    std::vector<wchar_t> buildRemoteUtf16Buffer(const QString& text)
    {
        std::vector<wchar_t> buffer(static_cast<std::size_t>(text.size()) + 1, L'\0');
        if (!text.isEmpty())
        {
            std::memcpy(
                buffer.data(),
                text.utf16(),
                static_cast<std::size_t>(text.size()) * sizeof(wchar_t));
        }
        return buffer;
    }

    // allocateRemoteUnicodeBuffer：
    // - Allocate a UTF-16 string buffer in the target process and write content to it.
    // - When wow64Required=true, the return address must fit in a 32-bit pointer.
    // - On success, output the remote address; on failure, return false.
    bool allocateRemoteUnicodeBuffer(
        HANDLE processHandle,
        const QString& text,
        const bool wow64Required,
        std::uint64_t& remoteBufferOut,
        QString* errorTextOut)
    {
        remoteBufferOut = 0;
        const std::vector<wchar_t> kBuffer = buildRemoteUtf16Buffer(text);
        const SIZE_T kByteSize = static_cast<SIZE_T>(kBuffer.size() * sizeof(wchar_t));
        LPVOID remoteBuffer = VirtualAllocEx(
            processHandle,
            nullptr,
            kByteSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (remoteBuffer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("VirtualAllocEx字符串缓冲失败(%1)。").arg(GetLastError());
            }
            return false;
        }

        remoteBufferOut = reinterpret_cast<std::uint64_t>(remoteBuffer);
        if (wow64Required && remoteBufferOut > 0xFFFFFFFFULL)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Wow64字符串新缓冲区地址超过32位范围：%1。")
                    .arg(uint64ToHex(remoteBufferOut));
            }
            return false;
        }

        if (!writeRemoteBytesWithProtect(
            processHandle,
            remoteBufferOut,
            kBuffer.data(),
            kByteSize,
            errorTextOut))
        {
            return false;
        }
        return true;
    }

    // updateRemoteUnicodeString64：
    // - Update the UNICODE_STRING field within the 64-bit RTL_USER_PROCESS_PARAMETERS.
    // - Overwrite in place if the new string fits the original buffer; otherwise, remotely allocate a new buffer and update the descriptor.
    // - Returns true if the descriptor has been written to the string.
    bool updateRemoteUnicodeString64(
        HANDLE processHandle,
        const std::uint64_t descriptorAddress,
        const UNICODE_STRING& currentDescriptor,
        const QString& newText,
        QString* errorTextOut)
    {
        if (newText.size() > (std::numeric_limits<USHORT>::max() / static_cast<int>(sizeof(wchar_t)) - 1))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("字符串超过UNICODE_STRING长度上限。");
            }
            return false;
        }
        const std::vector<wchar_t> kNewBuffer = buildRemoteUtf16Buffer(newText);
        const USHORT kNewLengthBytes = static_cast<USHORT>(newText.size() * sizeof(wchar_t));
        const USHORT kNewMaximumBytes = static_cast<USHORT>(kNewBuffer.size() * sizeof(wchar_t));

        UNICODE_STRING updatedDescriptor = currentDescriptor;
        const std::uint64_t kCurrentBufferAddress = reinterpret_cast<std::uint64_t>(currentDescriptor.Buffer);
        if (kCurrentBufferAddress != 0 && currentDescriptor.MaximumLength >= kNewMaximumBytes)
        {
            if (!writeRemoteBytesWithProtect(
                processHandle,
                kCurrentBufferAddress,
                kNewBuffer.data(),
                static_cast<SIZE_T>(kNewMaximumBytes),
                errorTextOut))
            {
                return false;
            }
            updatedDescriptor.Length = kNewLengthBytes;
        }
        else
        {
            std::uint64_t allocatedAddress = 0;
            if (!allocateRemoteUnicodeBuffer(
                processHandle,
                newText,
                false,
                allocatedAddress,
                errorTextOut))
            {
                return false;
            }
            updatedDescriptor.Length = kNewLengthBytes;
            updatedDescriptor.MaximumLength = kNewMaximumBytes;
            updatedDescriptor.Buffer = reinterpret_cast<PWSTR>(static_cast<std::uintptr_t>(allocatedAddress));
        }

        return writeRemoteBytesWithProtect(
            processHandle,
            descriptorAddress,
            &updatedDescriptor,
            static_cast<SIZE_T>(sizeof(updatedDescriptor)),
            errorTextOut);
    }

    // updateRemoteUnicodeString32：
    // - Updates UNICODE_STRING fields within the Wow64/32-bit RTL_USER_PROCESS_PARAMETERS.
    // - Buffer/Length/MaximumLength are written back in 32-bit layout;
    // - Returns true if the descriptor has been written to the string.
    bool updateRemoteUnicodeString32(
        HANDLE processHandle,
        const std::uint64_t descriptorAddress,
        const RemoteUnicodeString32& currentDescriptor,
        const QString& newText,
        QString* errorTextOut)
    {
        if (newText.size() > (std::numeric_limits<USHORT>::max() / static_cast<int>(sizeof(wchar_t)) - 1))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("字符串超过UNICODE_STRING长度上限。");
            }
            return false;
        }
        const std::vector<wchar_t> kNewBuffer = buildRemoteUtf16Buffer(newText);
        const USHORT kNewLengthBytes = static_cast<USHORT>(newText.size() * sizeof(wchar_t));
        const USHORT kNewMaximumBytes = static_cast<USHORT>(kNewBuffer.size() * sizeof(wchar_t));

        RemoteUnicodeString32 updatedDescriptor = currentDescriptor;
        if (currentDescriptor.buffer != 0 && currentDescriptor.maximumLength >= kNewMaximumBytes)
        {
            if (!writeRemoteBytesWithProtect(
                processHandle,
                static_cast<std::uint64_t>(currentDescriptor.buffer),
                kNewBuffer.data(),
                static_cast<SIZE_T>(kNewMaximumBytes),
                errorTextOut))
            {
                return false;
            }
            updatedDescriptor.length = kNewLengthBytes;
        }
        else
        {
            std::uint64_t allocatedAddress = 0;
            if (!allocateRemoteUnicodeBuffer(
                processHandle,
                newText,
                true,
                allocatedAddress,
                errorTextOut))
            {
                return false;
            }
            updatedDescriptor.length = kNewLengthBytes;
            updatedDescriptor.maximumLength = kNewMaximumBytes;
            updatedDescriptor.buffer = static_cast<std::uint32_t>(allocatedAddress);
        }

        return writeRemoteBytesWithProtect(
            processHandle,
            descriptorAddress,
            &updatedDescriptor,
            static_cast<SIZE_T>(sizeof(updatedDescriptor)),
            errorTextOut);
    }

    // readRemoteEnvironmentBlock：
    // - Read the remote environment block completely until double NUL or the safety limit is reached;
    // - Returns a QStringList where each item is the original "NAME=value" text;
    // - On failure, errorTextOut provides the specific reason.
    bool readRemoteEnvironmentBlock(
        HANDLE processHandle,
        const std::uint64_t environmentAddress,
        QStringList& environmentLinesOut,
        QString* errorTextOut)
    {
        environmentLinesOut.clear();
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (processHandle == nullptr || environmentAddress == 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Environment指针为空。");
            }
            return false;
        }

        std::vector<wchar_t> environmentChars;
        bool foundDoubleNull = false;
        std::size_t offsetBytes = 0;
        while (offsetBytes < kMaxEnvironmentPreviewBytes)
        {
            const std::size_t kRequestBytes = std::min<std::size_t>(
                kEnvironmentReadChunkBytes,
                kMaxEnvironmentPreviewBytes - offsetBytes);
            std::vector<std::uint8_t> chunkBuffer(kRequestBytes, 0);
            SIZE_T bytesRead = 0;
            const BOOL kReadOk = ReadProcessMemory(
                processHandle,
                reinterpret_cast<LPCVOID>(
                    static_cast<std::uintptr_t>(environmentAddress + offsetBytes)),
                chunkBuffer.data(),
                static_cast<SIZE_T>(chunkBuffer.size()),
                &bytesRead);
            if (kReadOk == FALSE || bytesRead < sizeof(wchar_t))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("读取Environment块失败(%1)，offset=%2。")
                        .arg(GetLastError())
                        .arg(static_cast<qulonglong>(offsetBytes));
                }
                return false;
            }

            const std::size_t kCharCount = static_cast<std::size_t>(bytesRead / sizeof(wchar_t));
            const std::size_t kScanStart = environmentChars.empty() ? 1 : environmentChars.size();
            const auto* chunkChars = reinterpret_cast<const wchar_t*>(chunkBuffer.data());
            environmentChars.insert(environmentChars.end(), chunkChars, chunkChars + kCharCount);
            for (std::size_t index = kScanStart; index < environmentChars.size(); ++index)
            {
                if (environmentChars[index - 1] == L'\0' && environmentChars[index] == L'\0')
                {
                    environmentChars.resize(index + 1);
                    foundDoubleNull = true;
                    break;
                }
            }
            if (foundDoubleNull)
            {
                break;
            }

            const std::size_t kConsumedBytes = kCharCount * sizeof(wchar_t);
            if (kConsumedBytes == 0)
            {
                break;
            }
            offsetBytes += kConsumedBytes;
        }

        if (!foundDoubleNull)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Environment块超过128KB或缺少双NUL终止。");
            }
            return false;
        }

        std::size_t cursorIndex = 0;
        while (cursorIndex < environmentChars.size())
        {
            const wchar_t* lineBegin = environmentChars.data() + cursorIndex;
            std::size_t lineLength = 0;
            while (cursorIndex + lineLength < environmentChars.size() &&
                environmentChars[cursorIndex + lineLength] != L'\0')
            {
                ++lineLength;
            }
            if (lineLength == 0)
            {
                break;
            }
            environmentLinesOut << QString::fromWCharArray(lineBegin, static_cast<int>(lineLength));
            cursorIndex += lineLength + 1;
        }
        return true;
    }

    // updateRemoteEnvironmentVariable：
    // - Add or replace a single NAME=value pair in the remote environment variable block.
    // - Completed by allocating a new environment block and updating the ProcessParameters.Environment pointer;
    // - Does not release the old environment block to avoid corrupting the target process's own allocator metadata.
    bool updateRemoteEnvironmentVariable(
        HANDLE processHandle,
        const PebEditTargetSnapshot& targetSnapshot,
        const QString& variableName,
        const QString& variableValue,
        QString* errorTextOut)
    {
        const QString kNormalizedName = variableName.trimmed();
        if (kNormalizedName.isEmpty() || kNormalizedName.contains('='))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("环境变量名为空或包含等号。");
            }
            return false;
        }

        QStringList environmentLines;
        if (!readRemoteEnvironmentBlock(
            processHandle,
            targetSnapshot.environmentAddress,
            environmentLines,
            errorTextOut))
        {
            return false;
        }

        const QString kReplacementLine = kNormalizedName + QLatin1Char('=') + variableValue;
        bool replaced = false;
        for (QString& lineText : environmentLines)
        {
            const int kEqualIndex = lineText.indexOf('=');
            if (kEqualIndex <= 0)
            {
                continue;
            }
            const QString kExistingName = lineText.left(kEqualIndex);
            if (kExistingName.compare(kNormalizedName, Qt::CaseInsensitive) == 0)
            {
                lineText = kReplacementLine;
                replaced = true;
                break;
            }
        }
        if (!replaced)
        {
            environmentLines << kReplacementLine;
        }

        std::vector<wchar_t> environmentBuffer;
        for (const QString& lineText : environmentLines)
        {
            const int kOldSize = static_cast<int>(environmentBuffer.size());
            environmentBuffer.resize(environmentBuffer.size() + static_cast<std::size_t>(lineText.size()) + 1, L'\0');
            if (!lineText.isEmpty())
            {
                std::memcpy(
                    environmentBuffer.data() + kOldSize,
                    lineText.utf16(),
                    static_cast<std::size_t>(lineText.size()) * sizeof(wchar_t));
            }
        }
        environmentBuffer.push_back(L'\0');

        const SIZE_T kByteSize = static_cast<SIZE_T>(environmentBuffer.size() * sizeof(wchar_t));
        LPVOID remoteBuffer = VirtualAllocEx(
            processHandle,
            nullptr,
            kByteSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        if (remoteBuffer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("VirtualAllocEx环境块失败(%1)。").arg(GetLastError());
            }
            return false;
        }

        const std::uint64_t kRemoteAddress = reinterpret_cast<std::uint64_t>(remoteBuffer);
        if (targetSnapshot.isWow64Target && kRemoteAddress > 0xFFFFFFFFULL)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("Wow64环境块新地址超过32位范围：%1。")
                    .arg(uint64ToHex(kRemoteAddress));
            }
            return false;
        }

        if (!writeRemoteBytesWithProtect(
            processHandle,
            kRemoteAddress,
            environmentBuffer.data(),
            kByteSize,
            errorTextOut))
        {
            return false;
        }

        if (targetSnapshot.isWow64Target)
        {
            const std::uint32_t kRemoteAddress32 = static_cast<std::uint32_t>(kRemoteAddress);
            const std::uint64_t kFieldAddress =
                targetSnapshot.processParametersAddress + offsetof(RtlUserProcessParameters32Lite, environment);
            return writeRemoteBytesWithProtect(
                processHandle,
                kFieldAddress,
                &kRemoteAddress32,
                static_cast<SIZE_T>(sizeof(kRemoteAddress32)),
                errorTextOut);
        }

        const std::uint64_t kFieldAddress =
            targetSnapshot.processParametersAddress + offsetof(RtlUserProcessParameters64Lite, environment);
        const PVOID kRemotePointer = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(kRemoteAddress));
        return writeRemoteBytesWithProtect(
            processHandle,
            kFieldAddress,
            &kRemotePointer,
            static_cast<SIZE_T>(sizeof(kRemotePointer)),
            errorTextOut);
    }

    // queryPebEditTargetSnapshot：
    // - Resolves NativePEB or Wow64PEB based on the UI target selection;
    // - Read the ProcessParameters snapshot simultaneously for subsequent field offset calculations.
    // - Returns valid=false if the target is unavailable.
    PebEditTargetSnapshot queryPebEditTargetSnapshot(
        HANDLE processHandle,
        const QString& targetName)
    {
        PebEditTargetSnapshot snapshot{};
        if (processHandle == nullptr)
        {
            snapshot.errorText = QStringLiteral("进程句柄为空。");
            return snapshot;
        }

        HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
        const NtQueryInformationProcessFn kNtQueryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtQueryInformationProcess") : nullptr);
        if (kNtQueryProcess == nullptr)
        {
            snapshot.errorText = QStringLiteral("无法定位NtQueryInformationProcess。");
            return snapshot;
        }

        PROCESS_BASIC_INFORMATION basicInfo{};
        const NTSTATUS kBasicStatus = kNtQueryProcess(
            processHandle,
            static_cast<ULONG>(ProcessBasicInformation),
            &basicInfo,
            static_cast<ULONG>(sizeof(basicInfo)),
            nullptr);
        if (!NT_SUCCESS(kBasicStatus))
        {
            snapshot.errorText = QStringLiteral("NtQueryInformationProcess(ProcessBasicInformation)失败：%1。")
                .arg(QStringLiteral("0x%1")
                    .arg(static_cast<unsigned long>(kBasicStatus), 8, 16, QChar('0'))
                    .toUpper());
            return snapshot;
        }

        const bool kWantWow64 = targetName.compare(QStringLiteral("Wow64PEB"), Qt::CaseInsensitive) == 0;
        if (kWantWow64)
        {
            ULONG_PTR wow64PebAddress = 0;
            if (!queryNtProcessInfoFixed(
                kNtQueryProcess,
                processHandle,
                kProcessInfoClassWow64Information,
                wow64PebAddress) ||
                wow64PebAddress == 0)
            {
                snapshot.errorText = QStringLiteral("目标没有可用Wow64PEB。");
                return snapshot;
            }

            Peb32Lite peb32{};
            if (!readRemoteStructure(processHandle, static_cast<std::uint64_t>(wow64PebAddress), peb32))
            {
                snapshot.errorText = QStringLiteral("读取Wow64PEB头失败。");
                return snapshot;
            }
            if (peb32.processParameters == 0)
            {
                snapshot.errorText = QStringLiteral("Wow64PEB.ProcessParameters为空。");
                return snapshot;
            }
            if (!readRemoteStructure(
                processHandle,
                static_cast<std::uint64_t>(peb32.processParameters),
                snapshot.params32))
            {
                snapshot.errorText = QStringLiteral("读取32位ProcessParameters失败。");
                return snapshot;
            }

            snapshot.valid = true;
            snapshot.isWow64Target = true;
            snapshot.pebAddress = static_cast<std::uint64_t>(wow64PebAddress);
            snapshot.processParametersAddress = static_cast<std::uint64_t>(peb32.processParameters);
            snapshot.imageBaseAddress = static_cast<std::uint64_t>(peb32.imageBaseAddress);
            snapshot.environmentAddress = static_cast<std::uint64_t>(snapshot.params32.environment);
            return snapshot;
        }

        if (basicInfo.PebBaseAddress == nullptr)
        {
            snapshot.errorText = QStringLiteral("NativePEB地址为空。");
            return snapshot;
        }

        Peb64Lite peb64{};
        snapshot.pebAddress = reinterpret_cast<std::uint64_t>(basicInfo.PebBaseAddress);
        if (!readRemoteStructure(processHandle, snapshot.pebAddress, peb64))
        {
            snapshot.errorText = QStringLiteral("读取NativePEB头失败。");
            return snapshot;
        }
        if (peb64.processParameters == nullptr)
        {
            snapshot.errorText = QStringLiteral("NativePEB.ProcessParameters为空。");
            return snapshot;
        }
        snapshot.processParametersAddress = reinterpret_cast<std::uint64_t>(peb64.processParameters);
        if (!readRemoteStructure(processHandle, snapshot.processParametersAddress, snapshot.params64))
        {
            snapshot.errorText = QStringLiteral("读取64位ProcessParameters失败。");
            return snapshot;
        }

        snapshot.valid = true;
        snapshot.isWow64Target = false;
        snapshot.imageBaseAddress = reinterpret_cast<std::uint64_t>(peb64.imageBaseAddress);
        snapshot.environmentAddress = reinterpret_cast<std::uint64_t>(snapshot.params64.environment);
        return snapshot;
    }

    // updatePebImageBaseAddress：
    // - Only modifies the PEB.ImageBaseAddress field;
    // - Does not remap images or repair the LDR list; this is an advanced deception/testing capability.
    bool updatePebImageBaseAddress(
        HANDLE processHandle,
        const PebEditTargetSnapshot& targetSnapshot,
        const std::uint64_t newImageBaseAddress,
        QString* errorTextOut)
    {
        if (targetSnapshot.isWow64Target)
        {
            if (newImageBaseAddress > 0xFFFFFFFFULL)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("Wow64PEB.ImageBaseAddress不能超过32位。");
                }
                return false;
            }
            const std::uint32_t kImageBase32 = static_cast<std::uint32_t>(newImageBaseAddress);
            const std::uint64_t kFieldAddress = targetSnapshot.pebAddress + offsetof(Peb32Lite, imageBaseAddress);
            return writeRemoteBytesWithProtect(
                processHandle,
                kFieldAddress,
                &kImageBase32,
                static_cast<SIZE_T>(sizeof(kImageBase32)),
                errorTextOut);
        }

        const PVOID kImageBasePointer = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(newImageBaseAddress));
        const std::uint64_t kFieldAddress = targetSnapshot.pebAddress + offsetof(Peb64Lite, imageBaseAddress);
        return writeRemoteBytesWithProtect(
            processHandle,
            kFieldAddress,
            &kImageBasePointer,
            static_cast<SIZE_T>(sizeof(kImageBasePointer)),
            errorTextOut);
    }

    // memoryStateToText：
    // - Textualize the Memory Region State field.
    QString memoryStateToText(const DWORD stateValue)
    {
        switch (stateValue)
        {
        case MEM_COMMIT: return QStringLiteral("Commit");
        case MEM_RESERVE: return QStringLiteral("Reserve");
        case MEM_FREE: return QStringLiteral("Free");
        default: return QString("State(0x%1)").arg(stateValue, 0, 16).toUpper();
        }
    }

    // memoryTypeToText：
    // - Textual representation of the memory region Type field.
    QString memoryTypeToText(const DWORD typeValue)
    {
        switch (typeValue)
        {
        case MEM_IMAGE: return QStringLiteral("Image");
        case MEM_MAPPED: return QStringLiteral("Mapped");
        case MEM_PRIVATE: return QStringLiteral("Private");
        default: return QString("Type(0x%1)").arg(typeValue, 0, 16).toUpper();
        }
    }

    // memoryProtectToText：
    // - Convert memory region protection attributes to text for easier list auditing.
    QString memoryProtectToText(const DWORD protectValue)
    {
        if (protectValue == 0)
        {
            return QStringLiteral("-");
        }

        QStringList flags;
        const DWORD kBaseProtect = protectValue & 0xFF;
        switch (kBaseProtect)
        {
        case PAGE_NOACCESS: flags << QStringLiteral("NOACCESS"); break;
        case PAGE_READONLY: flags << QStringLiteral("R"); break;
        case PAGE_READWRITE: flags << QStringLiteral("RW"); break;
        case PAGE_WRITECOPY: flags << QStringLiteral("WC"); break;
        case PAGE_EXECUTE: flags << QStringLiteral("X"); break;
        case PAGE_EXECUTE_READ: flags << QStringLiteral("XR"); break;
        case PAGE_EXECUTE_READWRITE: flags << QStringLiteral("XRW"); break;
        case PAGE_EXECUTE_WRITECOPY: flags << QStringLiteral("XWC"); break;
        default: flags << QString("0x%1").arg(kBaseProtect, 0, 16).toUpper(); break;
        }

        if ((protectValue & PAGE_GUARD) != 0) flags << QStringLiteral("GUARD");
        if ((protectValue & PAGE_NOCACHE) != 0) flags << QStringLiteral("NOCACHE");
        if ((protectValue & PAGE_WRITECOMBINE) != 0) flags << QStringLiteral("WRITECOMBINE");
        return flags.join('|');
    }

    // Order of KERNEL_CALLBACK_TABLE fields in currently public Windows symbols:
    // - PEB stores only the table pointer, not the table length;
    // - Field order provides readable names for indices; older systems automatically truncate results via consecutive unavailable trailing items.
    // - The maximum read count is always bounded by the length of this array to prevent unbounded scanning of remote memory.
    constexpr const char* kKernelCallbackNames[] =
    {
        "__fnCOPYDATA",
        "__fnCOPYGLOBALDATA",
        "__fnEMPTY1",
        "__fnNCDESTROY",
        "__fnDWORDOPTINLPMSG",
        "__fnINOUTDRAG",
        "__fnGETTEXTLENGTHS1",
        "__fnINCNTOUTSTRING",
        "__fnINCNTOUTSTRINGNULL",
        "__fnINLPCOMPAREITEMSTRUCT",
        "__fnINLPCREATESTRUCT",
        "__fnINLPDELETEITEMSTRUCT",
        "__fnINLPDRAWITEMSTRUCT",
        "__fnPOPTINLPUINT1",
        "__fnPOPTINLPUINT2",
        "__fnINLPMDICREATESTRUCT",
        "__fnINOUTLPMEASUREITEMSTRUCT",
        "__fnINLPWINDOWPOS",
        "__fnINOUTLPPOINT51",
        "__fnINOUTLPSCROLLINFO",
        "__fnINOUTLPRECT",
        "__fnINOUTNCCALCSIZE",
        "__fnINOUTLPPOINT52",
        "__fnINPAINTCLIPBRD",
        "__fnINSIZECLIPBRD",
        "__fnINDESTROYCLIPBRD",
        "__fnINSTRINGNULL1",
        "__fnINSTRINGNULL2",
        "__fnINDEVICECHANGE",
        "__fnPOWERBROADCAST",
        "__fnINLPUAHDRAWMENU1",
        "__fnOPTOUTLPDWORDOPTOUTLPDWORD1",
        "__fnOPTOUTLPDWORDOPTOUTLPDWORD2",
        "__fnOUTDWORDINDWORD",
        "__fnOUTLPRECT",
        "__fnOUTSTRING",
        "__fnPOPTINLPUINT3",
        "__fnPOUTLPINT",
        "__fnSENTDDEMSG",
        "__fnINOUTSTYLECHANGE1",
        "__fnHkINDWORD",
        "__fnHkINLPCBTACTIVATESTRUCT",
        "__fnHkINLPCBTCREATESTRUCT",
        "__fnHkINLPDEBUGHOOKSTRUCT",
        "__fnHkINLPMOUSEHOOKSTRUCTEX1",
        "__fnHkINLPKBDLLHOOKSTRUCT",
        "__fnHkINLPMSLLHOOKSTRUCT",
        "__fnHkINLPMSG",
        "__fnHkINLPRECT",
        "__fnHkOPTINLPEVENTMSG",
        "__xxxClientCallDelegateThread",
        "__ClientCallDummyCallback1",
        "__ClientCallDummyCallback2",
        "__fnSHELLWINDOWMANAGEMENTCALLOUT",
        "__fnSHELLWINDOWMANAGEMENTNOTIFY",
        "__ClientCallDummyCallback3",
        "__xxxClientCallDitThread",
        "__xxxClientEnableMMCSS",
        "__xxxClientUpdateDpi",
        "__xxxClientExpandStringW",
        "__ClientCopyDDEIn1",
        "__ClientCopyDDEIn2",
        "__ClientCopyDDEOut1",
        "__ClientCopyDDEOut2",
        "__ClientCopyImage",
        "__ClientEventCallback",
        "__ClientFindMnemChar",
        "__ClientFreeDDEHandle",
        "__ClientFreeLibrary",
        "__ClientGetCharsetInfo",
        "__ClientGetDDEFlags",
        "__ClientGetDDEHookData",
        "__ClientGetListboxString",
        "__ClientGetMessageMPH",
        "__ClientLoadImage",
        "__ClientLoadLibrary",
        "__ClientLoadMenu",
        "__ClientLoadLocalT1Fonts",
        "__ClientPSMTextOut",
        "__ClientLpkDrawTextEx",
        "__ClientExtTextOutW",
        "__ClientGetTextExtentPointW",
        "__ClientCharToWchar",
        "__ClientAddFontResourceW",
        "__ClientThreadSetup",
        "__ClientDeliverUserApc",
        "__ClientNoMemoryPopup",
        "__ClientMonitorEnumProc",
        "__ClientCallWinEventProc",
        "__ClientWaitMessageExMPH",
        "__ClientCallDummyCallback4",
        "__ClientCallDummyCallback5",
        "__ClientImmLoadLayout",
        "__ClientImmProcessKey",
        "__fnIMECONTROL",
        "__fnINWPARAMDBCSCHAR",
        "__fnGETTEXTLENGTHS2",
        "__ClientCallDummyCallback6",
        "__ClientLoadStringW",
        "__ClientLoadOLE",
        "__ClientRegisterDragDrop",
        "__ClientRevokeDragDrop",
        "__fnINOUTMENUGETOBJECT",
        "__ClientPrinterThunk",
        "__fnOUTLPCOMBOBOXINFO",
        "__fnOUTLPSCROLLBARINFO",
        "__fnINLPUAHDRAWMENU2",
        "__fnINLPUAHDRAWMENUITEM",
        "__fnINLPUAHDRAWMENU3",
        "__fnINOUTLPUAHMEASUREMENUITEM",
        "__fnINLPUAHDRAWMENU4",
        "__fnOUTLPTITLEBARINFOEX",
        "__fnTOUCH",
        "__fnGESTURE",
        "__fnPOPTINLPUINT4",
        "__fnPOPTINLPUINT5",
        "__xxxClientCallDefaultInputHandler",
        "__fnEMPTY2",
        "__ClientRimDevCallback",
        "__xxxClientCallMinTouchHitTestingCallback",
        "__ClientCallLocalMouseHooks",
        "__xxxClientBroadcastThemeChange",
        "__xxxClientCallDevCallbackSimple",
        "__xxxClientAllocWindowClassExtraBytes",
        "__xxxClientFreeWindowClassExtraBytes",
        "__fnGETWINDOWDATA",
        "__fnINOUTSTYLECHANGE2",
        "__fnHkINLPMOUSEHOOKSTRUCTEX2",
        "__xxxClientCallDefWindowProc",
        "__fnSHELLSYNCDISPLAYCHANGED",
        "__fnHkINLPCHARHOOKSTRUCT",
        "__fnINTERCEPTEDWINDOWACTION",
        "__xxxTooltipCallback",
        "__xxxClientInitPSBInfo",
        "__xxxClientDoScrollMenu",
        "__xxxClientEndScroll",
        "__xxxClientDrawSize",
        "__xxxClientDrawScrollBar",
        "__xxxClientHitTestScrollBar",
        "__xxxClientTrackInit"
    };

    constexpr std::size_t kKernelCallbackMinimumProbeCount = 64;
    constexpr std::size_t kKernelCallbackBoundaryRunLength = 8;

    // isExecutableMemoryProtection: Checks if the page base protection bits allow execution.
    bool isExecutableMemoryProtection(const DWORD protectionValue)
    {
        switch (protectionValue & 0xFFU)
        {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    // protectionLevelToText：
    // - Textual representation of the single-byte level of ProcessProtectionInformation.
    QString protectionLevelToText(const std::uint8_t protectionLevel)
    {
        if (protectionLevel == 0)
        {
            return QStringLiteral("None");
        }

        const std::uint8_t kSigner = protectionLevel >> 4;
        const std::uint8_t kType = protectionLevel & 0x07;
        return QStringLiteral("Level=0x%1 (Signer=%2, Type=%3)")
            .arg(protectionLevel, 2, 16, QChar('0'))
            .arg(kSigner)
            .arg(kType);
    }

    // countTopLevelWindowsByPid：
    // - Enumerates all top-level windows and counts how many are held by the target PID.
    std::uint32_t countTopLevelWindowsByPid(const std::uint32_t pid)
    {
        struct EnumContext final
        {
            std::uint32_t targetPid = 0;   // Target process PID.
            std::uint32_t windowCount = 0; // Statistics result.
        };

        EnumContext context{};
        context.targetPid = pid;

        EnumWindows(
            [](HWND hwnd, LPARAM param) -> BOOL
            {
                auto* ctx = reinterpret_cast<EnumContext*>(param);
                if (ctx == nullptr)
                {
                    return FALSE;
                }

                DWORD ownerPid = 0;
                GetWindowThreadProcessId(hwnd, &ownerPid);
                if (ownerPid == ctx->targetPid)
                {
                    ++ctx->windowCount;
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&context));

        return context.windowCount;
    }

    // queryDesktopNameByProcessThreads：
    // - Retrieve the desktop object name of the target process via its thread ID (when available).
    QString queryDesktopNameByProcessThreads(const std::uint32_t pid)
    {
        HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return QString();
        }

        QString desktopName;
        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        BOOL hasThread = Thread32First(snapshotHandle, &threadEntry);
        while (hasThread != FALSE)
        {
            if (threadEntry.th32OwnerProcessID == pid)
            {
                HDESK desktopHandle = GetThreadDesktop(threadEntry.th32ThreadID);
                if (desktopHandle != nullptr)
                {
                    wchar_t desktopBuffer[256] = {};
                    DWORD bytesNeeded = 0;
                    const BOOL kQueryOk = GetUserObjectInformationW(
                        desktopHandle,
                        UOI_NAME,
                        desktopBuffer,
                        static_cast<DWORD>(sizeof(desktopBuffer)),
                        &bytesNeeded);
                    if (kQueryOk != FALSE)
                    {
                        desktopName = QString::fromWCharArray(desktopBuffer);
                    }
                }
                break;
            }
            hasThread = Thread32Next(snapshotHandle, &threadEntry);
        }

        CloseHandle(snapshotHandle);
        return desktopName;
    }

    // ThreadBasicInformationNative：
    // - Corresponds to the thread basic information structure;
    // - Retain only the fields required for rendering the current page.
    struct ThreadBasicInformationNative
    {
        NTSTATUS exitStatus = 0;           // Thread exit status.
        PVOID tebBaseAddress = nullptr;    // TEB address.
        CLIENT_ID clientId{};              // Client ID.
        ULONG_PTR affinityMask = 0;        // Affinity mask.
        LONG priority = 0;                 // Current priority.
        LONG basePriority = 0;             // Base priority.
    };

    // threadInspectR0StatusText：
    // - Converts R0 thread extended status to short text for the detail view.
    // - Maintains the same semantics as the ProcessDock thread overview page.
    QString threadInspectR0StatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_THREAD_R0_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_THREAD_R0_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData missing");
        case KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED:
            return QStringLiteral("Read failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // runtimeDetailStatusText：
    // - Input detail IOCTL return value: KSWORD_ARK_DETAIL_STATUS_*.
    // - Processing: Convert to a stable, readable Chinese/English mixed status.
    // - Return: Short text for displaying Process/Thread runtime details.
    QString runtimeDetailStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_DETAIL_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_DETAIL_STATUS_PARTIAL:
            return QStringLiteral("Partial（部分字段可用）");
        case KSWORD_ARK_DETAIL_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported（驱动未启用该详情协议）");
        case KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED:
            return QStringLiteral("Lookup failed（目标对象不存在或不可引用）");
        case KSWORD_ARK_DETAIL_STATUS_CAPABILITY_MISSING:
            return QStringLiteral("Capability missing（动态偏移能力不足）");
        case KSWORD_ARK_DETAIL_STATUS_READ_FAILED:
            return QStringLiteral("Read failed（字段读取失败）");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // fixedRuntimeWideText：
    // - Input shared/driver fixed wchar_t buffer;
    // - Processing: Truncate at NUL to prevent displaying padding areas in the detail view.
    // - Returns: Empty text is uniformly described as 'No additional explanation'.
    QString fixedRuntimeWideText(const wchar_t* const bufferPointer, const std::size_t maxChars)
    {
        if (bufferPointer == nullptr || maxChars == 0U)
        {
            return QStringLiteral("无额外说明");
        }

        std::size_t length = 0U;
        while (length < maxChars && bufferPointer[length] != L'\0')
        {
            ++length;
        }
        if (length == 0U)
        {
            return QStringLiteral("无额外说明");
        }
        return QString::fromWCharArray(bufferPointer, static_cast<int>(length));
    }

    // fixedRuntimeImageName：
    // - Input: fixed char[16] process name from shared/driver
    // - Processing: Truncate at NUL and display as local 8-bit text;
    // - Return: Display <empty> for null values to distinguish between unread data and UI blanks.
    QString fixedRuntimeImageName(const char* const bufferPointer, const std::size_t maxChars)
    {
        if (bufferPointer == nullptr || maxChars == 0U)
        {
            return QStringLiteral("<empty>");
        }

        std::size_t length = 0U;
        while (length < maxChars && bufferPointer[length] != '\0')
        {
            ++length;
        }
        if (length == 0U)
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromLocal8Bit(bufferPointer, static_cast<int>(length));
    }

    // runtimeCapabilityMaskText：
    // - Input mask: DynData capability or missing capability bitmap.
    // - Processing: Translate each capability bit into a user-understandable field group name.
    // - Return: Short text for the last column/tooltip, preserving hexadecimal format for easy log comparison.
    QString runtimeCapabilityMaskText(const std::uint64_t mask, const bool missingMode)
    {
        QStringList names;
        const auto kAppendName =
            [&names, mask](const std::uint64_t bit, const QString& nameText)
            {
                if ((mask & bit) != 0ULL)
                {
                    names.push_back(nameText);
                }
            };

        kAppendName(KSW_CAP_DYN_NTOS_ACTIVE, QStringLiteral("ntoskrnl profile"));
        kAppendName(KSW_CAP_DYN_LXCORE_ACTIVE, QStringLiteral("lxcore profile"));
        kAppendName(KSW_CAP_OBJECT_TYPE_FIELDS, QStringLiteral("对象类型字段"));
        kAppendName(KSW_CAP_HANDLE_TABLE_DECODE, QStringLiteral("句柄表解码"));
        kAppendName(KSW_CAP_PROCESS_OBJECT_TABLE, QStringLiteral("进程 ObjectTable"));
        kAppendName(KSW_CAP_THREAD_STACK_FIELDS, QStringLiteral("线程栈边界"));
        kAppendName(KSW_CAP_THREAD_IO_COUNTERS, QStringLiteral("线程 I/O 计数"));
        kAppendName(KSW_CAP_ALPC_FIELDS, QStringLiteral("ALPC 字段"));
        kAppendName(KSW_CAP_SECTION_CONTROL_AREA, QStringLiteral("Section/ControlArea"));
        kAppendName(KSW_CAP_PROCESS_PROTECTION_PATCH, QStringLiteral("进程保护字段"));
        kAppendName(KSW_CAP_WSL_LXCORE_FIELDS, QStringLiteral("WSL/lxcore 字段"));
        kAppendName(KSW_CAP_ETW_GUID_FIELDS, QStringLiteral("ETW 字段"));
        kAppendName(KSW_CAP_CALLBACK_NOTIFY_GLOBALS, QStringLiteral("进程/线程/镜像回调全局"));
        kAppendName(KSW_CAP_CALLBACK_REGISTRY_GLOBALS, QStringLiteral("注册表回调全局"));
        kAppendName(KSW_CAP_CALLBACK_OBJECT_FIELDS, QStringLiteral("对象回调字段"));
        kAppendName(KSW_CAP_PROCESS_LIST_FIELDS, QStringLiteral("进程链表字段"));
        kAppendName(KSW_CAP_THREAD_LIST_FIELDS, QStringLiteral("线程链表字段"));
        kAppendName(KSW_CAP_CID_TABLE_WALK, QStringLiteral("CID 表遍历"));
        kAppendName(KSW_CAP_KERNEL_MODULE_LIST_FIELDS, QStringLiteral("内核模块链表字段"));
        kAppendName(KSW_CAP_DRIVER_OBJECT_FIELDS, QStringLiteral("驱动对象字段"));
        kAppendName(KSW_CAP_KERNEL_GLOBALS, QStringLiteral("内核全局 RVA"));

        if (names.isEmpty())
        {
            return missingMode
                ? QStringLiteral("无缺失能力（0x0）")
                : QStringLiteral("无已知能力（0x0）");
        }

        return QStringLiteral("%1（0x%2）")
            .arg(names.join(QStringLiteral("、")))
            .arg(static_cast<qulonglong>(mask), 0, 16)
            .toUpper();
    }

    // processRuntimeFieldListText：
    // - Input fieldFlags: field coverage bitmap returned by process detail IOCTL;
    // Processing: Expand to _EPROCESS/object field names to avoid displaying only 0x bitmaps in the UI.
    // - Returns: List of readable fields.
    QString processRuntimeFieldListText(const std::uint32_t fieldFlags)
    {
        QStringList fields;
        const auto kAppendField =
            [&fields, fieldFlags](const std::uint32_t bit, const QString& fieldText)
            {
                if ((fieldFlags & bit) != 0U)
                {
                    fields.push_back(fieldText);
                }
            };

        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_PUBLIC_IDENTITY, QStringLiteral("PID/镜像名"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_ADDRESS, QStringLiteral("EPROCESS 地址"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_UNIQUE_PROCESS_ID, QStringLiteral("_EPROCESS.UniqueProcessId"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_ACTIVE_PROCESS_LINKS, QStringLiteral("_EPROCESS.ActiveProcessLinks"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_THREAD_LIST_HEAD, QStringLiteral("_EPROCESS.ThreadListHead"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_IMAGE_FILE_NAME, QStringLiteral("_EPROCESS.ImageFileName"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_TOKEN_FASTREF, QStringLiteral("_EPROCESS.Token"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_TABLE, QStringLiteral("_EPROCESS.ObjectTable"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_OBJECT, QStringLiteral("_EPROCESS.SectionObject"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_PROTECTION, QStringLiteral("_EPROCESS.Protection"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_SIGNATURE_LEVEL, QStringLiteral("_EPROCESS.SignatureLevel"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_SIGNATURE, QStringLiteral("_EPROCESS.SectionSignatureLevel"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_OFFSET_SOURCES, QStringLiteral("偏移来源"));
        kAppendField(KSWORD_ARK_PROCESS_DETAIL_FIELD_KERNEL_GLOBALS, QStringLiteral("ntoskrnl 全局 RVA"));

        return fields.isEmpty()
            ? QStringLiteral("未采集到进程运行时字段")
            : fields.join(QStringLiteral("、"));
    }

    // threadRuntimeFieldListText：
    // - Input fieldFlags: field coverage bitmap returned by thread detail IOCTL;
    // - Processing: Expand to ETHREAD/KTHREAD field names.
    // - Returns: List of readable fields.
    QString threadRuntimeFieldListText(const std::uint32_t fieldFlags)
    {
        QStringList fields;
        const auto kAppendField =
            [&fields, fieldFlags](const std::uint32_t bit, const QString& fieldText)
            {
                if ((fieldFlags & bit) != 0U)
                {
                    fields.push_back(fieldText);
                }
            };

        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_PUBLIC_IDENTITY, QStringLiteral("TID/PID"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_OBJECT_ADDRESS, QStringLiteral("ETHREAD 地址"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_ETHREAD_CID, QStringLiteral("_ETHREAD.Cid"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_THREAD_LIST_ENTRY, QStringLiteral("_ETHREAD.ThreadListEntry"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS, QStringLiteral("_ETHREAD.StartAddress"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS, QStringLiteral("_ETHREAD.Win32StartAddress"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_KTHREAD_PROCESS, QStringLiteral("_KTHREAD.Process"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_STACK_LIMITS, QStringLiteral("_KTHREAD 栈边界"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_IO_COUNTERS, QStringLiteral("_KTHREAD I/O 计数"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_OFFSET_SOURCES, QStringLiteral("偏移来源"));
        kAppendField(KSWORD_ARK_THREAD_DETAIL_FIELD_KERNEL_GLOBALS, QStringLiteral("ntoskrnl 全局 RVA"));

        return fields.isEmpty()
            ? QStringLiteral("未采集到线程运行时字段")
            : fields.join(QStringLiteral("、"));
    }

    // runtimeFieldSourceText：
    // - Input source: Source value from KSW_DYN_FIELD_SOURCE_*;
    // - Processing: Convert to Chinese source names to avoid displaying raw numbers in the UI.
    // - Returns: human-readable text such as PDB profile, System Informer, or runtime pattern.
    QString runtimeFieldSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            return QStringLiteral("System Informer DynData");
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("运行时模式识别");
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            return QStringLiteral("Ksword 扩展表");
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        case KSW_DYN_FIELD_SOURCE_UNAVAILABLE:
        default:
            return QStringLiteral("不可用");
        }
    }

    // runtimeOffsetPresent：
    // - Input offset: offset/RVA in the shared protocol;
    // - Processing: Filter unavailable/0xffff sentinel values;
    // - Return: TRUE indicates the offset is valid and can be displayed.
    bool runtimeOffsetPresent(const unsigned long offset)
    {
        return offset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE && offset != 0x0000FFFFUL;
    }

    // runtimeOffsetText：
    // - Input offset: offset/RVA in the shared protocol;
    // - Processing: Convert to hexadecimal when available; otherwise, explicitly mark as unavailable.
    // - Returns: A stable display value for detailed text.
    QString runtimeOffsetText(const unsigned long offset)
    {
        if (!runtimeOffsetPresent(offset))
        {
            return QStringLiteral("<不可用>");
        }
        return uint64ToHex(static_cast<std::uint64_t>(offset));
    }

    // runtimeOffsetSourceItemText：
    // - Input name/offset/source: Single field name, offset, and source;
    // - Processing: Combine into human-readable evidence fragments.
    // - Return: e.g., "_EPROCESS.Token=0x4B8(PDB profile)".
    QString runtimeOffsetSourceItemText(
        const QString& name,
        const unsigned long offset,
        const unsigned long source)
    {
        return QStringLiteral("%1=%2(%3)")
            .arg(name)
            .arg(runtimeOffsetText(offset))
            .arg(runtimeFieldSourceText(source));
    }

    // processRuntimeOffsetSourceText：
    // - Input response: process runtime detail response;
    // - Processing: Expand process-related offsets and sources.
    // - Returns: One-line readable source list.
    QString processRuntimeOffsetSourceText(const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& response)
    {
        QStringList parts;
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.UniqueProcessId"),
            response.offsets.epUniqueProcessId,
            response.sources.epUniqueProcessId));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.ActiveProcessLinks"),
            response.offsets.epActiveProcessLinks,
            response.sources.epActiveProcessLinks));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.ThreadListHead"),
            response.offsets.epThreadListHead,
            response.sources.epThreadListHead));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.ImageFileName"),
            response.offsets.epImageFileName,
            response.sources.epImageFileName));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.Token"),
            response.offsets.epToken,
            response.sources.epToken));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.ObjectTable"),
            response.offsets.epObjectTable,
            response.sources.epObjectTable));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.SectionObject"),
            response.offsets.epSectionObject,
            response.sources.epSectionObject));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.Protection"),
            response.offsets.epProtection,
            response.sources.epProtection));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.SignatureLevel"),
            response.offsets.epSignatureLevel,
            response.sources.epSignatureLevel));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_EPROCESS.SectionSignatureLevel"),
            response.offsets.epSectionSignatureLevel,
            response.sources.epSectionSignatureLevel));
        return parts.join(QStringLiteral("；"));
    }

    // threadRuntimeOffsetSourceText：
    // - Input response: thread runtime detail response;
    // - Processing: Expand thread-related offsets and sources.
    // - Returns: One-line readable source list.
    QString threadRuntimeOffsetSourceText(const KSWORD_ARK_THREAD_DETAIL_RESPONSE& response)
    {
        QStringList parts;
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_ETHREAD.Cid"),
            response.offsets.etCid,
            response.sources.etCid));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_ETHREAD.ThreadListEntry"),
            response.offsets.etThreadListEntry,
            response.sources.etThreadListEntry));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_ETHREAD.StartAddress"),
            response.offsets.etStartAddress,
            response.sources.etStartAddress));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_ETHREAD.Win32StartAddress"),
            response.offsets.etWin32StartAddress,
            response.sources.etWin32StartAddress));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.Process"),
            response.offsets.ktProcess,
            response.sources.ktProcess));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.InitialStack"),
            response.offsets.ktInitialStack,
            response.sources.ktInitialStack));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.StackLimit"),
            response.offsets.ktStackLimit,
            response.sources.ktStackLimit));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.StackBase"),
            response.offsets.ktStackBase,
            response.sources.ktStackBase));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.KernelStack"),
            response.offsets.ktKernelStack,
            response.sources.ktKernelStack));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.ReadOperationCount"),
            response.offsets.ktReadOperationCount,
            response.sources.ktReadOperationCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.WriteOperationCount"),
            response.offsets.ktWriteOperationCount,
            response.sources.ktWriteOperationCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.OtherOperationCount"),
            response.offsets.ktOtherOperationCount,
            response.sources.ktOtherOperationCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.ReadTransferCount"),
            response.offsets.ktReadTransferCount,
            response.sources.ktReadTransferCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.WriteTransferCount"),
            response.offsets.ktWriteTransferCount,
            response.sources.ktWriteTransferCount));
        parts.push_back(runtimeOffsetSourceItemText(
            QStringLiteral("_KTHREAD.OtherTransferCount"),
            response.offsets.ktOtherTransferCount,
            response.sources.ktOtherTransferCount));
        return parts.join(QStringLiteral("；"));
    }

    // runtimeKernelGlobalItemText：
    // - Input name/rva/source/address: global symbol name, RVA, source, and current VA.
    // - Processing: Convert global symbols from the PDB profile into human-readable evidence;
    // - Returns: a human-readable snippet of a single global symbol.
    QString runtimeKernelGlobalItemText(
        const QString& name,
        const unsigned long rva,
        const unsigned long source,
        const std::uint64_t address)
    {
        return QStringLiteral("%1: RVA=%2, VA=%3, 来源=%4")
            .arg(name)
            .arg(runtimeOffsetText(rva))
            .arg(address == 0ULL ? QStringLiteral("<不可用>") : uint64ToHex(address))
            .arg(runtimeFieldSourceText(source));
    }

    // runtimeKernelGlobalsText：
    // - Input globals: ntoskrnl global RVA package within the detail response;
    // - Processing: List key global symbols such as CID, module list, driver unloading, PiDDB, and SSDT shadow;
    // - Returns: Multi-line text ready for the detail page or tooltip.
    QString runtimeKernelGlobalsText(const KSWORD_ARK_RUNTIME_KERNEL_GLOBALS& globals)
    {
        QStringList parts;
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("PspCidTable"),
            globals.pspCidTableRva,
            globals.pspCidTableSource,
            globals.pspCidTableAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("PsLoadedModuleList"),
            globals.psLoadedModuleListRva,
            globals.psLoadedModuleListSource,
            globals.psLoadedModuleListAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("MmUnloadedDrivers"),
            globals.mmUnloadedDriversRva,
            globals.mmUnloadedDriversSource,
            globals.mmUnloadedDriversAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("PiDDBCacheTable"),
            globals.piDdbCacheTableRva,
            globals.piDdbCacheTableSource,
            globals.piDdbCacheTableAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("KeServiceDescriptorTableShadow"),
            globals.keServiceDescriptorTableShadowRva,
            globals.keServiceDescriptorTableShadowSource,
            globals.keServiceDescriptorTableShadowAddress));
        parts.push_back(runtimeKernelGlobalItemText(
            QStringLiteral("MmLastUnloadedDriver"),
            globals.mmLastUnloadedDriverRva,
            globals.mmLastUnloadedDriverSource,
            globals.mmLastUnloadedDriverAddress));
        return parts.join(QStringLiteral("；"));
    }

    // runtimeSamplingSummaryText：
    // - Input rawDetailText: fixed detail text from the driver;
    // - Processing: Collapse common English sampling logs into Chinese descriptions; retain summaries only for unknown text.
    // - Return: User-facing sampling description to avoid directly inserting IOCTL logs into the last column of the table.
    QString runtimeSamplingSummaryText(const QString& rawDetailText, const QString& subjectText)
    {
        const QString kTrimmedText = rawDetailText.trimmed();
        if (kTrimmedText.isEmpty() || kTrimmedText == QStringLiteral("无额外说明"))
        {
            return QStringLiteral("%1运行时详情无额外驱动说明。").arg(subjectText);
        }
        if (kTrimmedText.contains(QStringLiteral("sampled by"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1运行时字段已由驱动只读采样；字段覆盖、缺失能力和失败状态已在本行展开。")
                .arg(subjectText);
        }
        if (kTrimmedText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1详情协议版本不匹配，请同步 R3/R0/shared 协议。").arg(subjectText);
        }
        if (kTrimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1详情受 DynData capability 限制，缺失能力已在本行列出。").arg(subjectText);
        }
        return kTrimmedText;
    }

    // readableRuntimeIoMessage：
    // - Input rawMessage: ArkDriverClient::IoResult::message; subjectText: page/capability name.
    // - Processing: Convert common DeviceIoControl/unsupported/capability/version/buffer text into Chinese descriptions;
    // - Returns: Readable text suitable for the detail page, status bar, or the last column of a table.
    QString readableRuntimeIoMessage(
        const QString& rawMessage,
        const QString& subjectText,
        const QString& fallbackText,
        const bool unsupported = false)
    {
        if (unsupported)
        {
            return QStringLiteral("%1当前驱动未提供对应只读详情入口。").arg(subjectText);
        }

        const QString kTrimmedText = rawMessage.trimmed();
        if (kTrimmedText.isEmpty())
        {
            return fallbackText;
        }
        if (kTrimmedText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1当前驱动/协议暂不支持该只读详情入口。").arg(subjectText);
        }
        if (kTrimmedText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            kTrimmedText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1动态偏移能力未满足，请查看内核 DynData/Capability 状态。").arg(subjectText);
        }
        if (kTrimmedText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1详情协议版本不匹配，请同步 R3/R0/shared 协议。").arg(subjectText);
        }
        if (kTrimmedText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1驱动调用失败。原始错误：%2").arg(subjectText, kTrimmedText);
        }
        if (kTrimmedText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive) &&
            kTrimmedText.contains(QStringLiteral("trunc"), Qt::CaseInsensitive))
        {
            return QStringLiteral("%1返回结果过多，当前只展示截断后的可用证据。").arg(subjectText);
        }
        return kTrimmedText;
    }

    // ntStatusHexText：
    // - Input: NTSTATUS/Win32 status value;
    // - Processing: Uniformly pad with zeros for uppercase hexadecimal display.
    // - Returns: stable text suitable for copying into a debugger or log.
    QString ntStatusHexText(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(statusValue), 8, 16, QChar('0'))
            .toUpper();
    }

    // runtimeFieldSampleStatusText：
    // - Input sampler response-level status;
    // - Processing: Convert to mixed Chinese/English short status to avoid displaying raw numbers in the UI.
    // - Returns: Status text suitable for a header row.
    QString runtimeFieldSampleStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_PARTIAL:
            return QStringLiteral("Partial（部分字段读取失败）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_LOOKUP_FAILED:
            return QStringLiteral("LookupFailed（对象查找失败）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_INVALID_REQUEST:
            return QStringLiteral("InvalidRequest（请求无效）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_TRUNCATED:
            return QStringLiteral("Truncated（结果被截断）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN:
        default:
            return QStringLiteral("Unknown(%1)").arg(statusValue);
        }
    }

    // runtimeFieldSampleRowStatusText：
    // - Input sampler: Row-level status.
    // - Processing: Indicate whether a single-field read succeeded, was denied, or failed.
    // - Returns: Text suitable for displaying evidence rows field by field.
    QString runtimeFieldSampleRowStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK:
            return QStringLiteral("OK（已读取）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OFFSET_REJECTED:
            return QStringLiteral("OffsetRejected（偏移超过安全范围）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_SIZE_REJECTED:
            return QStringLiteral("SizeRejected（字段长度不适合采样）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_READ_FAILED:
            return QStringLiteral("ReadFailed（对象字段读取失败）");
        case KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_UNKNOWN:
        default:
            return QStringLiteral("Unknown(%1)").arg(statusValue);
        }
    }

    // runtimeFieldSampleBytesText：
    // - Input is the raw bytes of a small field;
    // - Processing: Concatenate in compact hexadecimal to avoid polluting the detail view with non-printable characters;
    // - Returns: e.g., "40 04 00 00"; returns <empty> for null values.
    QString runtimeFieldSampleBytesText(const std::vector<std::uint8_t>& bytes)
    {
        if (bytes.empty())
        {
            return QStringLiteral("<empty>");
        }
        QStringList parts;
        parts.reserve(static_cast<int>(bytes.size()));
        for (const std::uint8_t kByteValue : bytes)
        {
            parts.push_back(QStringLiteral("%1")
                .arg(static_cast<unsigned int>(kByteValue), 2, 16, QChar('0'))
                .toUpper());
        }
        return parts.join(QChar(' '));
    }

    // runtimeFieldSampleReadLeValue：
    // - Input bytes/offset/byteCount: raw bytes of the small field returned by the sampler;
    // - Processing: Interpret as an unsigned value of up to 8 bytes in Windows x64 little-endian order.
    // - Returns: On success, writes the integer to valueOut; returns false on failure.
    bool runtimeFieldSampleReadLeValue(
        const std::vector<std::uint8_t>& bytes,
        const std::size_t offset,
        const std::size_t byteCount,
        std::uint64_t& valueOut)
    {
        valueOut = 0ULL;
        if (byteCount == 0U || byteCount > sizeof(std::uint64_t))
        {
            return false;
        }
        if (offset > bytes.size() || bytes.size() - offset < byteCount)
        {
            return false;
        }

        for (std::size_t byteIndex = 0; byteIndex < byteCount; ++byteIndex)
        {
            valueOut |= static_cast<std::uint64_t>(bytes[offset + byteIndex]) << (byteIndex * 8U);
        }
        return true;
    }

    // runtimeFieldSampleDecimalHexText：
    // - Input value: already interpreted integer or handle value;
    // - Processing: Output both decimal and hexadecimal values simultaneously to facilitate bidirectional verification between PID/TID and addresses.
    // - Return: For example, "1234 (0x00000000000004D2)".
    QString runtimeFieldSampleDecimalHexText(const std::uint64_t value)
    {
        return QStringLiteral("%1 (%2)")
            .arg(QString::number(static_cast<qulonglong>(value)))
            .arg(uint64ToHex(value));
    }

    // runtimeFieldSampleAsciiText：
    // - Input bytes: char[] bytes returned by PDB sampler;
    // - Processing: Truncate to NUL; replace non-printable characters with '.'.
    // - Returns: Suitable for displaying short ASCII fields like _EPROCESS.ImageFileName.
    QString runtimeFieldSampleAsciiText(const std::vector<std::uint8_t>& bytes)
    {
        QString text;
        for (const std::uint8_t kByteValue : bytes)
        {
            if (kByteValue == 0U)
            {
                break;
            }
            if (kByteValue >= 0x20U && kByteValue <= 0x7EU)
            {
                text.append(QChar(static_cast<ushort>(kByteValue)));
            }
            else
            {
                text.append(QChar('.'));
            }
        }

        if (text.isEmpty())
        {
            return QStringLiteral("<空字符串或不可打印>");
        }
        return QStringLiteral("\"%1\"").arg(text);
    }

    // runtimeFieldSampleTypeOrUnknown：
    // - Input entry: R3 sampler line;
    // - Processing: Convert PDB field types to QString and insert placeholders for empty types.
    // - Return: Type text used for field headers and interpreter judgment.
    QString runtimeFieldSampleTypeOrUnknown(const ksword::ark::RuntimeFieldSampleEntry& entry)
    {
        const QString kTypeText = QString::fromStdString(entry.type).trimmed();
        if (kTypeText.isEmpty())
        {
            return QStringLiteral("<unknown>");
        }
        return kTypeText;
    }

    // runtimeFieldSampleNameOrId：
    // - Input entry: R0 sampler row and R3 request metadata;
    // - Processing: Prefer PDB qualifiedName; fall back to runtimeItemId if missing;
    // - Returns: human-readable field name.
    QString runtimeFieldSampleNameOrId(const ksword::ark::RuntimeFieldSampleEntry& entry)
    {
        const QString kNameText = QString::fromStdString(entry.name).trimmed();
        if (!kNameText.isEmpty())
        {
            return kNameText;
        }
        return QStringLiteral("runtimeItemId=%1").arg(uint64ToHex(entry.runtimeItemId));
    }

    // runtimeFieldSampleUnicodeStringText：
    // - Input bytes: Sample of _UNICODE_STRING header; on x64, the Buffer is at offset 8.
    // - Processing: Interpret only the structure header; do not follow to read remote strings, avoiding triggering additional kernel reads in the UI.
    // - Returns: Length/MaximumLength/Buffer triple.
    QString runtimeFieldSampleUnicodeStringText(const std::vector<std::uint8_t>& bytes)
    {
        std::uint64_t lengthValue = 0ULL;
        std::uint64_t maximumLengthValue = 0ULL;
        std::uint64_t bufferValue = 0ULL;
        const bool kLengthOk = runtimeFieldSampleReadLeValue(bytes, 0U, sizeof(std::uint16_t), lengthValue);
        const bool kMaximumOk = runtimeFieldSampleReadLeValue(bytes, 2U, sizeof(std::uint16_t), maximumLengthValue);
        const bool kBufferOk = runtimeFieldSampleReadLeValue(bytes, 8U, sizeof(std::uint64_t), bufferValue);
        if (!kLengthOk || !kMaximumOk || !kBufferOk)
        {
            return QStringLiteral("UNICODE_STRING 头部字节不足，无法解释。");
        }

        return QStringLiteral("UNICODE_STRING Length=%1, MaximumLength=%2, Buffer=%3")
            .arg(static_cast<unsigned long long>(lengthValue))
            .arg(static_cast<unsigned long long>(maximumLengthValue))
            .arg(uint64ToHex(bufferValue));
    }

    // runtimeFieldSamplePairPointersText：
    // - Input bytes/nameA/nameB: Two consecutive x64 pointer or handle fields.
    // - Processing: Explain small 16-byte structures like CLIENT_ID and LIST_ENTRY;
    // - Returns: Two-value summary with field names.
    QString runtimeFieldSamplePairPointersText(
        const std::vector<std::uint8_t>& bytes,
        const QString& nameA,
        const QString& nameB,
        const bool decimalHint)
    {
        std::uint64_t firstValue = 0ULL;
        std::uint64_t secondValue = 0ULL;
        const bool kFirstOk = runtimeFieldSampleReadLeValue(bytes, 0U, sizeof(std::uint64_t), firstValue);
        const bool kSecondOk = runtimeFieldSampleReadLeValue(bytes, 8U, sizeof(std::uint64_t), secondValue);
        if (!kFirstOk || !kSecondOk)
        {
            return QStringLiteral("%1/%2 字节不足，无法解释。").arg(nameA).arg(nameB);
        }

        const QString kFirstText = decimalHint
            ? runtimeFieldSampleDecimalHexText(firstValue)
            : uint64ToHex(firstValue);
        const QString kSecondText = decimalHint
            ? runtimeFieldSampleDecimalHexText(secondValue)
            : uint64ToHex(secondValue);
        return QStringLiteral("%1=%2, %3=%4")
            .arg(nameA)
            .arg(kFirstText)
            .arg(nameB)
            .arg(kSecondText);
    }

    // runtimeFieldSampleFastRefText：
    // - Input rawValue: _EX_FAST_REF original 64-bit value;
    // - Processing: Split the low 4 bits fast-ref count and the aligned object address.
    // - Returns: Human-readable explanation for fast reference fields such as Token/ObjectTable.
    QString runtimeFieldSampleFastRefText(const std::uint64_t rawValue)
    {
        const std::uint64_t kObjectAddress = rawValue & ~0xFULL;
        const std::uint64_t kRefCount = rawValue & 0xFULL;
        return QStringLiteral("EX_FAST_REF raw=%1, object=%2, refBits=%3")
            .arg(uint64ToHex(rawValue))
            .arg(uint64ToHex(kObjectAddress))
            .arg(static_cast<unsigned long long>(kRefCount));
    }

    // runtimeFieldSampleProtectionText：
    // - Input rawValue: _PS_PROTECTION/UCHAR raw protection bits;
    // - Processing: Decompose by Type/Audit/Signer bitfields for direct viewing of PPL/protection level;
    // - Returns: Human-readable explanation of the process protection field.
    QString runtimeFieldSampleProtectionText(const std::uint64_t rawValue)
    {
        const std::uint64_t kTypeValue = rawValue & 0x7ULL;
        const std::uint64_t kAuditValue = (rawValue >> 3U) & 0x1ULL;
        const std::uint64_t kSignerValue = (rawValue >> 4U) & 0xFULL;
        return QStringLiteral("PS_PROTECTION raw=%1, Type=%2, Audit=%3, Signer=%4")
            .arg(uint64ToHex(rawValue & 0xFFULL))
            .arg(static_cast<unsigned long long>(kTypeValue))
            .arg(static_cast<unsigned long long>(kAuditValue))
            .arg(static_cast<unsigned long long>(kSignerValue));
    }

    // runtimeFieldSamplePointerLike：
    // - Input name/type: PDB field name and field type;
    // - Processing: Determine whether the current field is better displayed as an address/handle or as a standard integer;
    // - Returns: true indicates the preferred uint64ToHex address style.
    bool runtimeFieldSamplePointerLike(const QString& nameText, const QString& typeText)
    {
        const QString kCombinedText = QStringLiteral("%1 %2")
            .arg(nameText)
            .arg(typeText)
            .toLower();
        return kCombinedText.contains(QChar('*')) ||
            kCombinedText.contains(QStringLiteral("ptr")) ||
            kCombinedText.contains(QStringLiteral("pvoid")) ||
            kCombinedText.contains(QStringLiteral("handle")) ||
            kCombinedText.contains(QStringLiteral("address")) ||
            kCombinedText.contains(QStringLiteral("objecttable")) ||
            kCombinedText.contains(QStringLiteral("sectionobject")) ||
            kCombinedText.contains(QStringLiteral("startaddress")) ||
            kCombinedText.contains(QStringLiteral("kernelstack")) ||
            kCombinedText.contains(QStringLiteral("initialstack")) ||
            kCombinedText.contains(QStringLiteral("stackbase")) ||
            kCombinedText.contains(QStringLiteral("stacklimit")) ||
            kCombinedText.contains(QStringLiteral(".process"));
    }

    // runtimeFieldSampleInterpretedValue：
    // - Input entry/name/type: sampler single-line and PDB metadata;
    // - Processing: Interpret short bytes using common kernel structure fields to avoid displaying only valueU64/hex bytes;
    // - Returns: Human-readable interpretation; returns the integer or raw byte summary if unrecognized.
    QString runtimeFieldSampleInterpretedValue(
        const ksword::ark::RuntimeFieldSampleEntry& entry,
        const QString& nameText,
        const QString& typeText)
    {
        const QString kLowerName = nameText.toLower();
        const QString kLowerType = typeText.toLower();
        const std::vector<std::uint8_t>& bytes = entry.sampleBytes;
        if (entry.status != KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK)
        {
            return QStringLiteral("未解释：字段未成功读取。");
        }
        if (bytes.empty() || entry.bytesRead == 0U)
        {
            return QStringLiteral("未解释：R0 未返回字段字节。");
        }

        if (kLowerName.contains(QStringLiteral("imagefilename")) ||
            kLowerType.contains(QStringLiteral("char[")))
        {
            return QStringLiteral("ASCII=%1").arg(runtimeFieldSampleAsciiText(bytes));
        }
        if (kLowerType.contains(QStringLiteral("_client_id")) ||
            kLowerName.endsWith(QStringLiteral(".cid")))
        {
            return runtimeFieldSamplePairPointersText(
                bytes,
                QStringLiteral("UniqueProcess"),
                QStringLiteral("UniqueThread"),
                true);
        }
        if (kLowerType.contains(QStringLiteral("_list_entry")) ||
            kLowerName.contains(QStringLiteral("activeprocesslinks")) ||
            kLowerName.contains(QStringLiteral("threadlistentry")) ||
            kLowerName.contains(QStringLiteral("threadlisthead")) ||
            kLowerName.contains(QStringLiteral("inloadorderlinks")))
        {
            return runtimeFieldSamplePairPointersText(
                bytes,
                QStringLiteral("Flink"),
                QStringLiteral("Blink"),
                false);
        }
        if (kLowerType.contains(QStringLiteral("_unicode_string")))
        {
            return runtimeFieldSampleUnicodeStringText(bytes);
        }

        std::uint64_t rawValue = 0ULL;
        const std::size_t kReadableSize = std::min<std::size_t>(
            bytes.size(),
            std::min<std::size_t>(entry.size, sizeof(std::uint64_t)));
        const bool kRawOk = runtimeFieldSampleReadLeValue(bytes, 0U, kReadableSize, rawValue);
        if (!kRawOk)
        {
            return QStringLiteral("原始字节=%1").arg(runtimeFieldSampleBytesText(bytes));
        }
        if (kLowerType.contains(QStringLiteral("_ex_fast_ref")) ||
            kLowerName.endsWith(QStringLiteral(".token")))
        {
            return runtimeFieldSampleFastRefText(rawValue);
        }
        if (kLowerType.contains(QStringLiteral("_ps_protection")) ||
            kLowerName.contains(QStringLiteral("protection")))
        {
            return runtimeFieldSampleProtectionText(rawValue);
        }
        if (kLowerName.contains(QStringLiteral("uniqueprocessid")))
        {
            return QStringLiteral("PID=%1").arg(runtimeFieldSampleDecimalHexText(rawValue));
        }
        if (runtimeFieldSamplePointerLike(nameText, typeText))
        {
            return QStringLiteral("Pointer=%1").arg(uint64ToHex(rawValue));
        }
        return QStringLiteral("Integer=%1").arg(runtimeFieldSampleDecimalHexText(rawValue));
    }

    // runtimeFieldSampleResultText：
    // - Input: ArkDriverClient sampler result and title.
    // - Processing: Expand response headers and the offset/value/status for each field.
    // - Returns: Human-readable text directly writable to CodeEditorWidget.
    QString runtimeFieldSampleResultText(
        const ksword::ark::RuntimeFieldSampleResult& result,
        const QString& titleText)
    {
        QStringList lines;
        lines << QStringLiteral("[%1]").arg(titleText);
        if (!result.io.ok)
        {
            lines << readableRuntimeIoMessage(
                QString::fromStdString(result.io.message),
                titleText,
                QStringLiteral("PDB deep runtime sampler 暂不可用。"),
                result.unsupported);
            return lines.join(QChar('\n'));
        }

        lines << QStringLiteral("Status: %1").arg(runtimeFieldSampleStatusText(result.status));
        lines << QStringLiteral("Object: %1").arg(uint64ToHex(result.objectAddress));
        lines << QStringLiteral("Returned/Total: %1/%2").arg(result.returnedCount).arg(result.totalCount);
        lines << QStringLiteral("DynDataCapability: %1").arg(uint64ToHex(result.dynDataCapabilityMask));
        lines << QStringLiteral("LastStatus: %1").arg(ntStatusHexText(result.lastStatus));
        if (result.entries.empty())
        {
            lines << QStringLiteral("  <没有返回字段行>");
            return lines.join(QChar('\n'));
        }

        for (const ksword::ark::RuntimeFieldSampleEntry& entry : result.entries)
        {
            const QString kNameText = runtimeFieldSampleNameOrId(entry);
            const QString kTypeText = runtimeFieldSampleTypeOrUnknown(entry);
            lines << QStringLiteral("  - %1").arg(kNameText);
            lines << QStringLiteral("      Type: %1").arg(kTypeText);
            lines << QStringLiteral("      Offset/Size: %1 / %2 bytes, BytesRead=%3")
                .arg(uint64ToHex(entry.offset))
                .arg(entry.size)
                .arg(entry.bytesRead);
            lines << QStringLiteral("      Status: %1, LastStatus=%2")
                .arg(runtimeFieldSampleRowStatusText(entry.status))
                .arg(ntStatusHexText(entry.lastStatus));
            lines << QStringLiteral("      Value: %1")
                .arg(runtimeFieldSampleInterpretedValue(entry, kNameText, kTypeText));
            lines << QStringLiteral("      Raw: valueU64=%1, bytes=[%2], runtimeItemId=%3, flags=%4")
                .arg(uint64ToHex(entry.valueU64))
                .arg(runtimeFieldSampleBytesText(entry.sampleBytes))
                .arg(uint64ToHex(entry.runtimeItemId))
                .arg(uint64ToHex(entry.flags));
        }
        return lines.join(QChar('\n'));
    }

    // readThreadUserStackFromTeb：
    // - Reads the user stack boundary from the NT_TIB starting field of the target process's TEB.
    // - Failure only affects the boundary hint in the call stack window, not the display of the thread line itself.
    bool readThreadUserStackFromTeb(
        HANDLE processHandle,
        const std::uint64_t tebAddress,
        std::uint64_t& stackBaseOut,
        std::uint64_t& stackLimitOut)
    {
        stackBaseOut = 0;
        stackLimitOut = 0;
        if (processHandle == nullptr || tebAddress == 0)
        {
            return false;
        }

        NT_TIB tibSnapshot{};
        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(tebAddress)),
            &tibSnapshot,
            sizeof(tibSnapshot),
            &bytesRead);
        if (kReadOk == FALSE || bytesRead < sizeof(PVOID) * 2)
        {
            return false;
        }

        stackBaseOut = reinterpret_cast<std::uint64_t>(tibSnapshot.StackBase);
        stackLimitOut = reinterpret_cast<std::uint64_t>(tibSnapshot.StackLimit);
        return true;
    }

    // queryTokenInfoBuffer：
    // - Unified token information retrieval.
    // - On success, write the byte content to bufferOut.
    bool queryTokenInfoBuffer(
        HANDLE tokenHandle,
        TOKEN_INFORMATION_CLASS infoClass,
        std::vector<std::uint8_t>& bufferOut)
    {
        bufferOut.clear();
        DWORD requiredLength = 0;
        GetTokenInformation(tokenHandle, infoClass, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            return false;
        }

        bufferOut.resize(requiredLength);
        const BOOL kQueryOk = GetTokenInformation(
            tokenHandle,
            infoClass,
            bufferOut.data(),
            requiredLength,
            &requiredLength);
        return kQueryOk != FALSE;
    }

    // formatNtStatusHex：
    // - Convert NTSTATUS to a 0xXXXXXXXX hexadecimal string.
    // - Intended for appending auditable error details when token switch application fails.
    QString formatNtStatusHex(const NTSTATUS statusCode)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(statusCode), 8, 16, QChar('0'))
            .toUpper();
    }

    // queryTokenBoolFlag：
    // - Read the 'ULONG boolean bit' type token field;
    // - Outputs a bool value on success; returns false on failure.
    bool queryTokenBoolFlag(
        HANDLE tokenHandle,
        const TOKEN_INFORMATION_CLASS infoClass,
        bool& valueOut)
    {
        ULONG rawValue = 0;
        DWORD returnLength = 0;
        const BOOL kQueryOk = GetTokenInformation(
            tokenHandle,
            infoClass,
            &rawValue,
            static_cast<DWORD>(sizeof(rawValue)),
            &returnLength);
        if (kQueryOk == FALSE || returnLength < sizeof(rawValue))
        {
            return false;
        }
        valueOut = (rawValue != 0);
        return true;
    }

    // queryTokenMandatoryPolicyBits：
    // - Read TokenMandatoryPolicy and split into two checkbox bits.
    // - Outputs two boolean values: NoWriteUp and NewProcessMin.
    bool queryTokenMandatoryPolicyBits(
        HANDLE tokenHandle,
        bool& noWriteUpOut,
        bool& newProcessMinOut)
    {
        TOKEN_MANDATORY_POLICY mandatoryPolicy{};
        DWORD returnLength = 0;
        const BOOL kQueryOk = GetTokenInformation(
            tokenHandle,
            TokenMandatoryPolicy,
            &mandatoryPolicy,
            static_cast<DWORD>(sizeof(mandatoryPolicy)),
            &returnLength);
        if (kQueryOk == FALSE || returnLength < sizeof(mandatoryPolicy))
        {
            return false;
        }
        noWriteUpOut = (mandatoryPolicy.Policy & kTokenMandatoryPolicyNoWriteUp) != 0;
        newProcessMinOut = (mandatoryPolicy.Policy & kTokenMandatoryPolicyNewProcessMin) != 0;
        return true;
    }

    // applyTokenBoolFlag：
    // - Write ULONG boolean flags using NtSetInformationToken;
    // - Returns NTSTATUS to allow the caller to record the cause of individual failures.
    NTSTATUS applyTokenBoolFlag(
        const NtSetInformationTokenFn setInformationToken,
        HANDLE tokenHandle,
        const TOKEN_INFORMATION_CLASS infoClass,
        const bool enabled)
    {
        if (setInformationToken == nullptr || tokenHandle == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000000DL);
        }
        ULONG rawValue = enabled ? 1UL : 0UL;
        return setInformationToken(
            tokenHandle,
            infoClass,
            &rawValue,
            static_cast<ULONG>(sizeof(rawValue)));
    }

    // applyTokenMandatoryPolicyBits：
    // - Combine two policy checkboxes into TOKEN_MANDATORY_POLICY;
    // - Uses NtSetInformationToken to write policy bits in a single operation.
    NTSTATUS applyTokenMandatoryPolicyBits(
        const NtSetInformationTokenFn setInformationToken,
        HANDLE tokenHandle,
        const bool noWriteUpEnabled,
        const bool newProcessMinEnabled)
    {
        if (setInformationToken == nullptr || tokenHandle == nullptr)
        {
            return static_cast<NTSTATUS>(0xC000000DL);
        }

        TOKEN_MANDATORY_POLICY mandatoryPolicy{};
        mandatoryPolicy.Policy = 0;
        if (noWriteUpEnabled)
        {
            mandatoryPolicy.Policy |= kTokenMandatoryPolicyNoWriteUp;
        }
        if (newProcessMinEnabled)
        {
            mandatoryPolicy.Policy |= kTokenMandatoryPolicyNewProcessMin;
        }
        return setInformationToken(
            tokenHandle,
            TokenMandatoryPolicy,
            &mandatoryPolicy,
            static_cast<ULONG>(sizeof(mandatoryPolicy)));
    }

    // describeIntegrityLevel：
    // - Convert integrity RID to text.
    QString describeIntegrityLevel(const DWORD integrityRid)
    {
        switch (integrityRid)
        {
        case SECURITY_MANDATORY_UNTRUSTED_RID: return QStringLiteral("Untrusted");
        case SECURITY_MANDATORY_LOW_RID: return QStringLiteral("Low");
        case SECURITY_MANDATORY_MEDIUM_RID: return QStringLiteral("Medium");
        case SECURITY_MANDATORY_HIGH_RID: return QStringLiteral("High");
        case SECURITY_MANDATORY_SYSTEM_RID: return QStringLiteral("System");
        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: return QStringLiteral("ProtectedProcess");
        default: return QString("RID=%1").arg(integrityRid);
        }
    }

    // describePriorityClass：
    // - Converts priority class constants to text.
    QString describePriorityClass(const DWORD priorityClass)
    {
        switch (priorityClass)
        {
        case IDLE_PRIORITY_CLASS: return QStringLiteral("IDLE");
        case BELOW_NORMAL_PRIORITY_CLASS: return QStringLiteral("BELOW_NORMAL");
        case NORMAL_PRIORITY_CLASS: return QStringLiteral("NORMAL");
        case ABOVE_NORMAL_PRIORITY_CLASS: return QStringLiteral("ABOVE_NORMAL");
        case HIGH_PRIORITY_CLASS: return QStringLiteral("HIGH");
        case REALTIME_PRIORITY_CLASS: return QStringLiteral("REALTIME");
        default: return QString("UNKNOWN(%1)").arg(priorityClass);
        }
    }

    // tokenInfoClassNameById：
    // - Map TokenInformationClass values to their corresponding names.
    // - Displays unknown IDs as TokenClassN to avoid information loss.
    QString tokenInfoClassNameById(const ULONG classId)
    {
        switch (classId)
        {
        case 1: return QStringLiteral("TokenUser");
        case 2: return QStringLiteral("TokenGroups");
        case 3: return QStringLiteral("TokenPrivileges");
        case 4: return QStringLiteral("TokenOwner");
        case 5: return QStringLiteral("TokenPrimaryGroup");
        case 6: return QStringLiteral("TokenDefaultDacl");
        case 7: return QStringLiteral("TokenSource");
        case 8: return QStringLiteral("TokenType");
        case 9: return QStringLiteral("TokenImpersonationLevel");
        case 10: return QStringLiteral("TokenStatistics");
        case 11: return QStringLiteral("TokenRestrictedSids");
        case 12: return QStringLiteral("TokenSessionId");
        case 13: return QStringLiteral("TokenGroupsAndPrivileges");
        case 14: return QStringLiteral("TokenSessionReference");
        case 15: return QStringLiteral("TokenSandBoxInert");
        case 16: return QStringLiteral("TokenAuditPolicy");
        case 17: return QStringLiteral("TokenOrigin");
        case 18: return QStringLiteral("TokenElevationType");
        case 19: return QStringLiteral("TokenLinkedToken");
        case 20: return QStringLiteral("TokenElevation");
        case 21: return QStringLiteral("TokenHasRestrictions");
        case 22: return QStringLiteral("TokenAccessInformation");
        case 23: return QStringLiteral("TokenVirtualizationAllowed");
        case 24: return QStringLiteral("TokenVirtualizationEnabled");
        case 25: return QStringLiteral("TokenIntegrityLevel");
        case 26: return QStringLiteral("TokenUIAccess");
        case 27: return QStringLiteral("TokenMandatoryPolicy");
        case 28: return QStringLiteral("TokenLogonSid");
        case 29: return QStringLiteral("TokenIsAppContainer");
        case 30: return QStringLiteral("TokenCapabilities");
        case 31: return QStringLiteral("TokenAppContainerSid");
        case 32: return QStringLiteral("TokenAppContainerNumber");
        case 33: return QStringLiteral("TokenUserClaimAttributes");
        case 34: return QStringLiteral("TokenDeviceClaimAttributes");
        case 35: return QStringLiteral("TokenRestrictedUserClaimAttributes");
        case 36: return QStringLiteral("TokenRestrictedDeviceClaimAttributes");
        case 37: return QStringLiteral("TokenDeviceGroups");
        case 38: return QStringLiteral("TokenRestrictedDeviceGroups");
        case 39: return QStringLiteral("TokenSecurityAttributes");
        case 40: return QStringLiteral("TokenIsRestricted");
        case 41: return QStringLiteral("TokenProcessTrustLevel");
        case 42: return QStringLiteral("TokenPrivateNameSpace");
        case 43: return QStringLiteral("TokenSingletonAttributes");
        case 44: return QStringLiteral("TokenBnoIsolation");
        case 45: return QStringLiteral("TokenChildProcessFlags");
        case 46: return QStringLiteral("TokenIsLessPrivilegedAppContainer");
        case 47: return QStringLiteral("TokenIsSandboxed");
        case 48: return QStringLiteral("TokenOriginatingProcessTrustLevel");
        case 49: return QStringLiteral("TokenLoggingInformation");
        case 50: return QStringLiteral("TokenLearningMode");
        case 51: return QStringLiteral("TokenIsAppSilo");
        default: return QStringLiteral("TokenClass%1").arg(classId);
        }
    }

    // formatTokenRawPreview：
    // Format the first N bytes of the raw buffer as a hexadecimal preview.
    // - Output: Formatted as "01 00 FF ..." for quick comparison of current values.
    QString formatTokenRawPreview(const std::vector<std::uint8_t>& rawBuffer, const std::size_t maxBytes)
    {
        if (rawBuffer.empty() || maxBytes == 0)
        {
            return QStringLiteral("-");
        }

        QStringList byteTextList;
        const std::size_t kPreviewCount = std::min<std::size_t>(rawBuffer.size(), maxBytes);
        byteTextList.reserve(static_cast<int>(kPreviewCount) + 1);
        for (std::size_t index = 0; index < kPreviewCount; ++index)
        {
            byteTextList << QStringLiteral("%1")
                .arg(static_cast<unsigned int>(rawBuffer[index]), 2, 16, QChar('0'))
                .toUpper();
        }
        if (rawBuffer.size() > kPreviewCount)
        {
            byteTextList << QStringLiteral("...");
        }
        return byteTextList.join(QStringLiteral(" "));
    }
}

void ProcessDetailWindow::updateThreadInspectStatusLabel(const QString& statusText, const bool refreshing)
{
    // Status label refresh:
    // - refreshing=true displays blue 'in progress'.
    // - false displays gray completion state.
    if (threadInspectStatusLabel_ == nullptr)
    {
        return;
    }

    threadInspectStatusLabel_->setText(statusText);
    threadInspectStatusLabel_->setStyleSheet(
        refreshing
        ? buildStateLabelStyle(ksword_theme::primaryBlueColor, 700)
        : buildStateLabelStyle(statusSecondaryColor(), 600));
}

void ProcessDetailWindow::requestAsyncThreadInspectRefresh()
{
    // Prevent re-entrancy and protect against invalid PID.
    if (threadInspectRefreshing_ || baseRecord_.pid == 0)
    {
        return;
    }

    // Once thread detail refresh is truly queued, the thread page is considered to have completed its initial scheduling.
    // User-initiated refresh and automatic lazy loading share this flag to avoid duplicate queuing.
    threadInspectInitialRefreshStarted_ = true;

    threadInspectRefreshing_ = true;
    const std::uint64_t kTicketValue = ++threadInspectRefreshTicket_;
    updateThreadInspectStatusLabel(QStringLiteral("● 正在刷新线程细节..."), true);
    if (refreshThreadInspectButton_ != nullptr)
    {
        refreshThreadInspectButton_->setEnabled(false);
    }

    if (threadInspectRefreshProgressPid_ == 0)
    {
        threadInspectRefreshProgressPid_ = kPro.addReusable(this, "进程详情", "刷新线程细节");
    }
    kPro.set(threadInspectRefreshProgressPid_, "扫描线程信息", 0, 20.0f);

    const std::uint32_t kPidValue = baseRecord_.pid;
    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kPidValue, kTicketValue]()
        {
            ThreadInspectRefreshResult refreshResult{};
            const auto kBeginTime = std::chrono::steady_clock::now();
            std::unordered_map<std::uint32_t, const ksword::ark::ThreadEntry*> r0ThreadByTid;
            const ksword::ark::DriverClient kDriverClient;

            // R0 thread extension is an optional enhancement: if the driver is unloaded or DynData is insufficient, R3 thread enumeration continues to display results.
            const ksword::ark::ThreadEnumResult kR0ThreadResult =
                kDriverClient.enumerateThreads(
                    KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL,
                    kPidValue);
            if (kR0ThreadResult.io.ok)
            {
                r0ThreadByTid.reserve(kR0ThreadResult.entries.size());
                for (const ksword::ark::ThreadEntry& r0Entry : kR0ThreadResult.entries)
                {
                    if (r0Entry.threadId != 0U)
                    {
                        r0ThreadByTid.insert_or_assign(r0Entry.threadId, &r0Entry);
                    }
                }
            }
            else
            {
                const QString kRawThreadIoMessage =
                    QString::fromStdString(kR0ThreadResult.io.message).trimmed();
                const QString kReadableThreadIoMessage = readableRuntimeIoMessage(
                    kRawThreadIoMessage,
                    QStringLiteral("R0线程扩展"),
                    QStringLiteral("无额外驱动消息。"),
                    false);
                refreshResult.diagnosticText = QStringLiteral("R0线程扩展不可用: %1")
                    .arg(kReadableThreadIoMessage);
            }

            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                kPidValue);
            if (processHandle == nullptr)
            {
                if (!refreshResult.diagnosticText.trimmed().isEmpty())
                {
                    refreshResult.diagnosticText += QStringLiteral(" | ");
                }
                refreshResult.diagnosticText += QStringLiteral("OpenProcess读取TEB失败(%1)").arg(GetLastError());
            }

            HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshotHandle == INVALID_HANDLE_VALUE)
            {
                if (!refreshResult.diagnosticText.trimmed().isEmpty())
                {
                    refreshResult.diagnosticText += QStringLiteral(" | ");
                }
                refreshResult.diagnosticText += QString("CreateToolhelp32Snapshot失败(%1)").arg(GetLastError());
            }
            else
            {
                HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
                NtQueryInformationThreadFn ntQueryThread = nullptr;
                if (ntdllModule != nullptr)
                {
                    ntQueryThread = reinterpret_cast<NtQueryInformationThreadFn>(
                        GetProcAddress(ntdllModule, "NtQueryInformationThread"));
                }

                THREADENTRY32 threadEntry{};
                threadEntry.dwSize = sizeof(threadEntry);
                BOOL hasThread = Thread32First(snapshotHandle, &threadEntry);
                while (hasThread != FALSE)
                {
                    if (threadEntry.th32OwnerProcessID == kPidValue)
                    {
                        ThreadInspectItem rowItem{};
                        rowItem.threadId = threadEntry.th32ThreadID;
                        rowItem.processId = kPidValue;
                        rowItem.stateText = QStringLiteral("Unknown");
                        rowItem.priorityValue = 0;
                        rowItem.switchCount = 0;
                        rowItem.startAddressText = QStringLiteral("-");
                        rowItem.tebAddressText = QStringLiteral("-");
                        rowItem.affinityText = QStringLiteral("-");
                        rowItem.registerSummaryText = QStringLiteral("-");

                        HANDLE threadHandle = OpenThread(
                            THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                            FALSE,
                            threadEntry.th32ThreadID);
                        if (threadHandle != nullptr)
                        {
                            FILETIME createTime{};
                            FILETIME exitTime{};
                            FILETIME kernelTime{};
                            FILETIME userTime{};
                            if (GetThreadTimes(
                                threadHandle,
                                &createTime,
                                &exitTime,
                                &kernelTime,
                                &userTime) != FALSE)
                            {
                                rowItem.createTime100ns =
                                    (static_cast<std::uint64_t>(createTime.dwHighDateTime) << 32U) |
                                    static_cast<std::uint64_t>(createTime.dwLowDateTime);
                            }
                            rowItem.priorityValue = GetThreadPriority(threadHandle);
                            if (ntQueryThread != nullptr)
                            {
                                ThreadBasicInformationNative basicInfo{};
                                NTSTATUS basicStatus = ntQueryThread(
                                    threadHandle,
                                    0,
                                    &basicInfo,
                                    static_cast<ULONG>(sizeof(basicInfo)),
                                    nullptr);
                                if (NT_SUCCESS(basicStatus))
                                {
                                    rowItem.tebAddress =
                                        reinterpret_cast<std::uint64_t>(basicInfo.tebBaseAddress);
                                    rowItem.tebAddressText = uint64ToHex(
                                        rowItem.tebAddress);
                                    rowItem.affinityText = uint64ToHex(basicInfo.affinityMask);
                                    rowItem.stateText = (basicInfo.exitStatus == STATUS_PENDING)
                                        ? QStringLiteral("Running")
                                        : QStringLiteral("Exited");
                                    std::uint64_t userStackBase = 0;
                                    std::uint64_t userStackLimit = 0;
                                    if (readThreadUserStackFromTeb(
                                        processHandle,
                                        rowItem.tebAddress,
                                        userStackBase,
                                        userStackLimit))
                                    {
                                        rowItem.userStackBase = userStackBase;
                                        rowItem.userStackLimit = userStackLimit;
                                    }
                                }

                                PVOID startAddress = nullptr;
                                NTSTATUS startStatus = ntQueryThread(
                                    threadHandle,
                                    9,
                                    &startAddress,
                                    static_cast<ULONG>(sizeof(startAddress)),
                                    nullptr);
                                if (NT_SUCCESS(startStatus))
                                {
                                    rowItem.startAddress =
                                        reinterpret_cast<std::uint64_t>(startAddress);
                                    rowItem.win32StartAddress = rowItem.startAddress;
                                    rowItem.startAddressText = uint64ToHex(
                                        rowItem.startAddress);
                                }
                            }

                            CONTEXT threadContext{};
                            threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                            const DWORD kSuspendCount = SuspendThread(threadHandle);
                            if (kSuspendCount != static_cast<DWORD>(-1))
                            {
                                const BOOL kContextOk = GetThreadContext(threadHandle, &threadContext);
                                ResumeThread(threadHandle);
                                if (kContextOk != FALSE)
                                {
#if defined(_M_X64)
                                    rowItem.registerSummaryText = QString("RIP=%1 RSP=%2")
                                        .arg(uint64ToHex(threadContext.Rip))
                                        .arg(uint64ToHex(threadContext.Rsp));
#elif defined(_M_IX86)
                                    rowItem.registerSummaryText = QString("EIP=%1 ESP=%2")
                                        .arg(uint64ToHex(threadContext.Eip))
                                        .arg(uint64ToHex(threadContext.Esp));
#else
                                    rowItem.registerSummaryText = QStringLiteral("当前架构未实现");
#endif
                                }
                            }
                            CloseHandle(threadHandle);
                        }
                        else
                        {
                            rowItem.stateText = QStringLiteral("AccessDenied");
                        }

                        const auto kR0It = r0ThreadByTid.find(rowItem.threadId);
                        if (kR0It != r0ThreadByTid.end() && kR0It->second != nullptr)
                        {
                            // Merge R0 KTHREAD extensions:
                            // - These fields are for boundary diagnostics only;
                            // - Do not use kernel addresses as input credentials for subsequent IOCTLs.
                            rowItem.r0ThreadStatus = kR0It->second->r0Status;
                            rowItem.r0CapabilityMask = kR0It->second->dynDataCapabilityMask;
                            rowItem.r0KernelStack = kR0It->second->kernelStack;
                            rowItem.r0StackBase = kR0It->second->stackBase;
                            rowItem.r0StackLimit = kR0It->second->stackLimit;
                            rowItem.r0InitialStack = kR0It->second->initialStack;
                        }

                        // Fixed thread detail IOCTL:
                        // - Input: TID/PID only; driver re-references ETHREAD.
                        // - Output used to complete Cid, linked list, start address, stack boundaries, and I/O count;
                        // - This page renders only the results and does not treat returned kernel addresses as credentials for subsequent operations.
                        const ksword::ark::ThreadRuntimeDetailResult kDetailResult =
                            kDriverClient.queryThreadRuntimeDetail(rowItem.threadId, kPidValue);
                        if (kDetailResult.io.ok)
                        {
                            const KSWORD_ARK_THREAD_DETAIL_RESPONSE& detailResponse =
                                kDetailResult.response;
                            rowItem.r0DetailStatus = detailResponse.status;
                            rowItem.r0DetailFieldFlags = detailResponse.fieldFlags;
                            rowItem.r0MissingCapabilityMask = detailResponse.missingCapabilityMask;
                            rowItem.r0DetailLastStatus = detailResponse.lastStatus;
                            rowItem.r0CapabilityMask = detailResponse.dynDataCapabilityMask != 0U
                                ? detailResponse.dynDataCapabilityMask
                                : rowItem.r0CapabilityMask;

                            if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS) != 0U)
                            {
                                rowItem.startAddress = detailResponse.startAddress;
                                rowItem.startAddressText = uint64ToHex(detailResponse.startAddress);
                            }
                            if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS) != 0U)
                            {
                                rowItem.win32StartAddress = detailResponse.win32StartAddress;
                            }
                            if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_STACK_LIMITS) != 0U)
                            {
                                rowItem.r0InitialStack = detailResponse.initialStack;
                                rowItem.r0StackLimit = detailResponse.stackLimit;
                                rowItem.r0StackBase = detailResponse.stackBase;
                                rowItem.r0KernelStack = detailResponse.kernelStack;
                                rowItem.r0ThreadStatus = KSWORD_ARK_THREAD_R0_STATUS_OK;
                            }
                            if ((detailResponse.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_IO_COUNTERS) != 0U)
                            {
                                rowItem.r0ReadOperationCount = detailResponse.readOperationCount;
                                rowItem.r0WriteOperationCount = detailResponse.writeOperationCount;
                                rowItem.r0OtherOperationCount = detailResponse.otherOperationCount;
                                rowItem.r0ReadTransferCount = detailResponse.readTransferCount;
                                rowItem.r0WriteTransferCount = detailResponse.writeTransferCount;
                                rowItem.r0OtherTransferCount = detailResponse.otherTransferCount;
                            }

                            rowItem.r0RuntimeDetailText = QStringLiteral(
                                "线程详情=%1；已采集=%2；缺失能力=%3；LastStatus=%4；"
                                "CID=%5/%6；Start=%7；Win32Start=%8；I/O=%9/%10/%11 ops, %12/%13/%14 bytes；"
                                "偏移来源=%15；内核全局=%16；采样说明=%17")
                                .arg(runtimeDetailStatusText(detailResponse.status))
                                .arg(threadRuntimeFieldListText(detailResponse.fieldFlags))
                                .arg(runtimeCapabilityMaskText(detailResponse.missingCapabilityMask, true))
                                .arg(ntStatusHexText(detailResponse.lastStatus))
                                .arg(static_cast<qulonglong>(detailResponse.cidUniqueProcess))
                                .arg(static_cast<qulonglong>(detailResponse.cidUniqueThread))
                                .arg(uint64ToHex(detailResponse.startAddress))
                                .arg(uint64ToHex(detailResponse.win32StartAddress))
                                .arg(static_cast<qulonglong>(detailResponse.readOperationCount))
                                .arg(static_cast<qulonglong>(detailResponse.writeOperationCount))
                                .arg(static_cast<qulonglong>(detailResponse.otherOperationCount))
                                .arg(static_cast<qulonglong>(detailResponse.readTransferCount))
                                .arg(static_cast<qulonglong>(detailResponse.writeTransferCount))
                                .arg(static_cast<qulonglong>(detailResponse.otherTransferCount))
                                .arg(threadRuntimeOffsetSourceText(detailResponse))
                                .arg(runtimeKernelGlobalsText(detailResponse.kernelGlobals))
                                .arg(runtimeSamplingSummaryText(
                                    fixedRuntimeWideText(
                                        detailResponse.detail,
                                        KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS),
                                    QStringLiteral("线程")));
                        }
                        else
                        {
                            const QString kRawMessage =
                                QString::fromStdString(kDetailResult.io.message).trimmed();
                            const QString kReadableMessage = readableRuntimeIoMessage(
                                kRawMessage,
                                QStringLiteral("线程详情"),
                                QStringLiteral("线程详情暂不可用。"),
                                kDetailResult.unsupported);
                            rowItem.r0RuntimeDetailText = kReadableMessage;
                        }

                        refreshResult.rows.push_back(std::move(rowItem));
                    }

                    hasThread = Thread32Next(snapshotHandle, &threadEntry);
                }
                CloseHandle(snapshotHandle);
            }
            if (processHandle != nullptr)
            {
                CloseHandle(processHandle);
            }

            std::sort(
                refreshResult.rows.begin(),
                refreshResult.rows.end(),
                [](const ThreadInspectItem& left, const ThreadInspectItem& right)
                {
                    return left.threadId < right.threadId;
                });

            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, refreshResult, kTicketValue]()
                {
                    if (guardThis == nullptr || guardThis->threadInspectRefreshTicket_ != kTicketValue)
                    {
                        return;
                    }
                    guardThis->applyThreadInspectResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyThreadInspectResult(const ThreadInspectRefreshResult& refreshResult)
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(threadRuntimeSampleOutput_);
    threadInspectRefreshing_ = false;
    if (refreshThreadInspectButton_ != nullptr)
    {
        refreshThreadInspectButton_->setEnabled(true);
    }

    threadInspectRows_ = refreshResult.rows;

    if (threadInspectTable_ != nullptr)
    {
        // Generate stack boundary column text:
        // - Access ThreadInspectItem within the member function to keep the type as a window-private implementation detail.
        // - Displays both R3 user stack and R0 KTHREAD boundaries in text.
        const auto kStackBoundaryText = [](const ThreadInspectItem& rowItem) -> QString
        {
            const QString kUserText =
                (rowItem.userStackBase != 0 || rowItem.userStackLimit != 0)
                ? QStringLiteral("U:%1-%2")
                    .arg(uint64ToHex(rowItem.userStackLimit))
                    .arg(uint64ToHex(rowItem.userStackBase))
                : QStringLiteral("U:Unavailable");
            const QString kKernelText =
                (rowItem.r0KernelStack != 0 ||
                    rowItem.r0StackBase != 0 ||
                    rowItem.r0StackLimit != 0 ||
                    rowItem.r0InitialStack != 0)
                ? QStringLiteral("K:%1/%2-%3 I=%4")
                    .arg(uint64ToHex(rowItem.r0KernelStack))
                    .arg(uint64ToHex(rowItem.r0StackLimit))
                    .arg(uint64ToHex(rowItem.r0StackBase))
                    .arg(uint64ToHex(rowItem.r0InitialStack))
                : QStringLiteral("K:Unavailable");
            return QStringLiteral("%1 | %2 | %3")
                .arg(kUserText)
                .arg(kKernelText)
                .arg(threadInspectR0StatusText(rowItem.r0ThreadStatus));
        };

        threadInspectTable_->setSortingEnabled(false);
        threadInspectTable_->setRowCount(0);
        for (std::size_t cacheIndex = 0; cacheIndex < threadInspectRows_.size(); ++cacheIndex)
        {
            const ThreadInspectItem& rowItem = threadInspectRows_[cacheIndex];
            const int kRow = threadInspectTable_->rowCount();
            threadInspectTable_->insertRow(kRow);
            auto* threadIdItem = new QTableWidgetItem(QString::number(rowItem.threadId));
            threadIdItem->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(static_cast<qulonglong>(cacheIndex)));
            threadIdItem->setData(Qt::UserRole + 1, QVariant::fromValue<qulonglong>(rowItem.threadId));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kThreadId), threadIdItem);
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kState), new QTableWidgetItem(rowItem.stateText));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kPriority), new QTableWidgetItem(QString::number(rowItem.priorityValue)));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kSwitchCount), new QTableWidgetItem(QString::number(rowItem.switchCount)));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kStartAddress), new QTableWidgetItem(rowItem.startAddressText));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kTebAddress), new QTableWidgetItem(rowItem.tebAddressText));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kAffinity), new QTableWidgetItem(rowItem.affinityText));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kRegisterSummary), new QTableWidgetItem(rowItem.registerSummaryText));
            auto* stackBoundaryItem = new QTableWidgetItem(kStackBoundaryText(rowItem));
            stackBoundaryItem->setToolTip(QStringLiteral("UserStackBase=%1\nUserStackLimit=%2\nR0KernelStack=%3\nR0StackBase=%4\nR0StackLimit=%5\nR0InitialStack=%6\nR0Status=%7\nCapability=0x%8")
                .arg(uint64ToHex(rowItem.userStackBase))
                .arg(uint64ToHex(rowItem.userStackLimit))
                .arg(uint64ToHex(rowItem.r0KernelStack))
                .arg(uint64ToHex(rowItem.r0StackBase))
                .arg(uint64ToHex(rowItem.r0StackLimit))
                .arg(uint64ToHex(rowItem.r0InitialStack))
                .arg(threadInspectR0StatusText(rowItem.r0ThreadStatus))
                .arg(static_cast<qulonglong>(rowItem.r0CapabilityMask), 0, 16));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kStackBoundary), stackBoundaryItem);

            auto* runtimeDetailItem = new QTableWidgetItem(
                rowItem.r0RuntimeDetailText.trimmed().isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("线程 runtime detail 暂不可用。"))
                : rowItem.r0RuntimeDetailText);
            runtimeDetailItem->setToolTip(QStringLiteral(
                "DetailStatus=%1\n"
                "已采集字段=%2\n"
                "缺失能力=%3\n"
                "LastStatus=%4\n"
                "Read/Write/Other Ops=%5/%6/%7\n"
                "Read/Write/Other Bytes=%8/%9/%10\n\n"
                "%11")
                .arg(runtimeDetailStatusText(rowItem.r0DetailStatus))
                .arg(threadRuntimeFieldListText(rowItem.r0DetailFieldFlags))
                .arg(runtimeCapabilityMaskText(rowItem.r0MissingCapabilityMask, true))
                .arg(ntStatusHexText(rowItem.r0DetailLastStatus))
                .arg(static_cast<qulonglong>(rowItem.r0ReadOperationCount))
                .arg(static_cast<qulonglong>(rowItem.r0WriteOperationCount))
                .arg(static_cast<qulonglong>(rowItem.r0OtherOperationCount))
                .arg(static_cast<qulonglong>(rowItem.r0ReadTransferCount))
                .arg(static_cast<qulonglong>(rowItem.r0WriteTransferCount))
                .arg(static_cast<qulonglong>(rowItem.r0OtherTransferCount))
                .arg(runtimeDetailItem->text()));
            threadInspectTable_->setItem(kRow, toThreadColumnIndex(ThreadRowColumn::kRuntimeDetail), runtimeDetailItem);
        }
        threadInspectTable_->setSortingEnabled(true);
    }

    QString statusText = QString("● 刷新完成 %1 ms | 线程数 %2")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.rows.size());
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
        KLogEvent diagnosticEvent;
        warn << diagnosticEvent
            << "[ProcessDetailWindow] thread inspection completed with diagnostics, rowCount="
            << refreshResult.rows.size()
            << ", diagnostic="
            << refreshResult.diagnosticText.toStdString()
            << eol;
    }
    updateThreadInspectStatusLabel(statusText, false);
    kPro.set(threadInspectRefreshProgressPid_, "线程细节刷新完成", 0, 100.0f);
}

void ProcessDetailWindow::requestAsyncSelectedThreadRuntimeSample()
{
    // Current thread PDB deep runtime sampling:
    // - Input: TID currently selected in the thread table and the window's PID;
    // - Background only passes TID/PID/runtimeItemId/offset/size, not the ETHREAD address.
    // - Returns text to be written to CodeEditorWidget for auditors to copy and compare fields.
    if (threadRuntimeSampleRefreshing_)
    {
        if (threadInspectStatusLabel_ != nullptr)
        {
            threadInspectStatusLabel_->setText(QStringLiteral("● 当前线程 PDB 字段采样仍在进行..."));
        }
        return;
    }
    if (threadInspectTable_ == nullptr || threadRuntimeSampleOutput_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = threadInspectTable_->currentRow();
    if (kCurrentRow < 0)
    {
        threadRuntimeSampleOutput_->setText(QStringLiteral("请先在线程表中选择一条线程记录。"));
        return;
    }

    const QTableWidgetItem* threadIdItem =
        threadInspectTable_->item(kCurrentRow, toThreadColumnIndex(ThreadRowColumn::kThreadId));
    const std::uint32_t kThreadId = threadIdItem != nullptr
        ? static_cast<std::uint32_t>(threadIdItem->data(Qt::UserRole + 1).toULongLong())
        : 0U;
    const std::size_t kCacheIndex = threadIdItem != nullptr
        ? static_cast<std::size_t>(threadIdItem->data(Qt::UserRole).toULongLong())
        : static_cast<std::size_t>(threadInspectRows_.size());
    if (kThreadId == 0U || kCacheIndex >= threadInspectRows_.size())
    {
        threadRuntimeSampleOutput_->setText(QStringLiteral("当前线程行缺少 TID 或缓存索引，请先刷新线程页。"));
        return;
    }

    const ThreadInspectItem kSelectedRow = threadInspectRows_[kCacheIndex];
    const std::uint32_t kProcessId = kSelectedRow.processId != 0U
        ? kSelectedRow.processId
        : baseRecord_.pid;
    if (kProcessId == 0U)
    {
        threadRuntimeSampleOutput_->setText(QStringLiteral("当前进程 PID 不可用，无法执行线程 PDB 字段采样。"));
        return;
    }

    threadRuntimeSampleRefreshing_ = true;
    const std::uint64_t kTicketValue = ++threadRuntimeSampleTicket_;
    if (sampleThreadRuntimeButton_ != nullptr)
    {
        sampleThreadRuntimeButton_->setEnabled(false);
    }
    if (threadInspectStatusLabel_ != nullptr)
    {
        threadInspectStatusLabel_->setText(QStringLiteral("● 正在采样 TID=%1 的 PDB deep 字段...").arg(kThreadId));
        threadInspectStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }
    threadRuntimeSampleOutput_->setText(QStringLiteral(
        "正在后台执行 thread_detail PDB deep runtime 字段采样...\n"
        "请求只包含 TID/PID/offset/size，不提交 ETHREAD 地址。"));

    QPointer<ProcessDetailWindow> guardThis(this);
    auto* sampleTask = QRunnable::create(
        [guardThis, kTicketValue, kProcessId, kThreadId, kSelectedRow]()
        {
            const auto kBeginTime = std::chrono::steady_clock::now();
            QStringList lines;
            lines << QStringLiteral("[Selected Thread Runtime Context]");
            lines << QStringLiteral("TID/PID: %1/%2").arg(kThreadId).arg(kProcessId);
            lines << QStringLiteral("Start/Win32Start: %1 / %2")
                .arg(uint64ToHex(kSelectedRow.startAddress))
                .arg(uint64ToHex(kSelectedRow.win32StartAddress));
            lines << QStringLiteral("TEB: %1").arg(uint64ToHex(kSelectedRow.tebAddress));
            lines << QStringLiteral("R0 fixed detail: %1")
                .arg(kSelectedRow.r0RuntimeDetailText.trimmed().isEmpty()
                    ? QStringLiteral("线程 runtime detail 暂不可用。")
                    : kSelectedRow.r0RuntimeDetailText);
            lines << QString();

            const ksword::ark::DriverClient kDriverClient;
            const ksword::ark::DynDataStatusResult kDynDataStatusResult =
                kDriverClient.queryDynDataStatus();
            QString deepIdentityGuardText;
            bool deepIdentityMatched = false;
            if (kDynDataStatusResult.io.ok)
            {
                deepIdentityMatched = pdbRuntimeCatalogMatchesKernelIdentity(
                    kDynDataStatusResult.ntoskrnl.timeDateStamp,
                    kDynDataStatusResult.ntoskrnl.sizeOfImage,
                    &deepIdentityGuardText);
            }
            else
            {
                const QString kReadableDynDataMessage = readableRuntimeIoMessage(
                    QString::fromStdString(kDynDataStatusResult.io.message),
                    QStringLiteral("DynData状态"),
                    QStringLiteral("DynData status 查询没有返回额外说明。"),
                    false);
                deepIdentityGuardText = QStringLiteral(
                    "[PDB Deep Runtime Identity Guard]\n"
                    "结论: 不匹配，跳过只读采样\n"
                    "原因: DynData status 查询不可用，无法校验 deep offset 与当前内核 identity。%1")
                    .arg(kReadableDynDataMessage);
            }

            lines << deepIdentityGuardText;
            lines << QString();
            const std::vector<ksword::ark::RuntimeFieldSampleRequestItem> kSampleItems =
                deepIdentityMatched
                ? buildPdbRuntimeSampleItems(QStringLiteral("thread_detail"), 64)
                : std::vector<ksword::ark::RuntimeFieldSampleRequestItem>{};
            if (!deepIdentityMatched)
            {
                lines << QStringLiteral("[PDB Deep Runtime Sample - thread_detail]");
                lines << QStringLiteral("deep catalog identity 未与当前 ntoskrnl 匹配，已跳过 R0 字段采样，避免错误偏移。");
            }
            else if (kSampleItems.empty())
            {
                lines << QStringLiteral("[PDB Deep Runtime Sample - thread_detail]");
                lines << QStringLiteral("profiles/pdb_deep_offsets 中没有找到可安全采样的 thread_detail 小字段。");
            }
            else
            {
                const ksword::ark::RuntimeFieldSampleResult kSampleResult =
                    kDriverClient.queryThreadRuntimeFieldSamples(kThreadId, kProcessId, kSampleItems);
                lines << runtimeFieldSampleResultText(
                    kSampleResult,
                    QStringLiteral("线程 PDB deep 字段采样"));
            }

            lines << QString();
            lines << QStringLiteral("[PDB Deep Runtime Catalog - thread_detail preview]");
            lines << buildPdbRuntimeCatalogPreview(QStringLiteral("thread_detail"), 16, 64);

            const std::uint64_t kElapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());
            lines << QString();
            lines << QStringLiteral("ElapsedMs: %1").arg(kElapsedMs);
            const QString kOutputText = lines.join(QChar('\n'));

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, kTicketValue, kThreadId, kOutputText, kElapsedMs]()
                {
                    if (guardThis == nullptr || guardThis->threadRuntimeSampleTicket_ != kTicketValue)
                    {
                        return;
                    }

                    guardThis->threadRuntimeSampleRefreshing_ = false;
                    if (guardThis->sampleThreadRuntimeButton_ != nullptr)
                    {
                        guardThis->sampleThreadRuntimeButton_->setEnabled(true);
                    }
                    if (guardThis->threadRuntimeSampleOutput_ != nullptr)
                    {
                        guardThis->threadRuntimeSampleOutput_->setText(kOutputText);
                    }
                    if (guardThis->threadInspectStatusLabel_ != nullptr)
                    {
                        guardThis->threadInspectStatusLabel_->setText(
                            QStringLiteral("● TID=%1 PDB 字段采样完成 %2 ms")
                            .arg(kThreadId)
                            .arg(kElapsedMs));
                        guardThis->threadInspectStatusLabel_->setStyleSheet(
                            buildStateLabelStyle(statusIdleColor(), 600));
                    }
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(sampleTask);
}

void ProcessDetailWindow::requestAsyncTokenRefresh()
{
    // Token page async refresh:
    // - Parse user SID, integrity level, groups, and privileges;
    // - The entire process executes in a background thread to avoid blocking window interactions.
    if (tokenRefreshing_ || baseRecord_.pid == 0)
    {
        return;
    }

    // Token text page refresh is expensive; the initial refresh flag prevents duplicate automatic refreshes after page switching.
    tokenInitialRefreshStarted_ = true;

    tokenRefreshing_ = true;
    const std::uint64_t kTicketValue = ++tokenRefreshTicket_;
    if (refreshTokenButton_ != nullptr)
    {
        refreshTokenButton_->setEnabled(false);
    }
    if (tokenStatusLabel_ != nullptr)
    {
        tokenStatusLabel_->setText(QStringLiteral("● 正在刷新令牌..."));
        tokenStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }

    if (tokenRefreshProgressPid_ == 0)
    {
        tokenRefreshProgressPid_ = kPro.addReusable(this, "进程详情", "刷新令牌信息");
    }
    kPro.set(tokenRefreshProgressPid_, "读取令牌字段", 0, 20.0f);

    const std::uint32_t kPidValue = baseRecord_.pid;
    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kPidValue, kTicketValue]()
        {
            TextRefreshResult refreshResult{};
            const auto kBeginTime = std::chrono::steady_clock::now();
            std::wostringstream textBuilder;
            textBuilder << L"[Token / Security Information]\n";
            textBuilder << L"PID: " << kPidValue << L"\n";

            // Open process handle:
            // - Token information requires PROCESS_QUERY_LIMITED_INFORMATION.
            // - Handle: The security extension fields and virtual memory summary require PROCESS_QUERY_INFORMATION / VM_READ.
            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                kPidValue);
            if (processHandle == nullptr)
            {
                processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, kPidValue);
            }
            if (processHandle == nullptr)
            {
                refreshResult.diagnosticText = QString("OpenProcess失败(%1)").arg(GetLastError());
            }
            else
            {
                // Dynamically load NtQueryInformationProcess:
                // - Used to read native fields such as DebugPort, protection level, DEP, and critical process flags.
                HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
                NtQueryInformationProcessFn ntQueryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
                    ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtQueryInformationProcess") : nullptr);

                HANDLE tokenHandle = nullptr;
                if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE)
                {
                    refreshResult.diagnosticText = QString("OpenProcessToken失败(%1)").arg(GetLastError());
                }
                else
                {
                    std::vector<std::uint8_t> tokenBuffer;

                    // TokenUser: outputs user SID and account name.
                    if (queryTokenInfoBuffer(tokenHandle, TokenUser, tokenBuffer))
                    {
                        const auto* tokenUserInfo = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.data());
                        textBuilder << L"User: " << convertSidToText(tokenUserInfo->User.Sid).toStdWString() << L"\n";
                    }

                    // TokenIntegrityLevel: Outputs the integrity level.
                    if (queryTokenInfoBuffer(tokenHandle, TokenIntegrityLevel, tokenBuffer))
                    {
                        const auto* mandatoryLabel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(tokenBuffer.data());
                        DWORD integrityRid = 0;
                        if (mandatoryLabel->Label.Sid != nullptr &&
                            *GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) > 0)
                        {
                            integrityRid = *GetSidSubAuthority(
                                mandatoryLabel->Label.Sid,
                                *GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) - 1);
                        }
                        textBuilder << L"Integrity: " << describeIntegrityLevel(integrityRid).toStdWString() << L"\n";
                    }

                    // TokenElevationType: Output elevation type (Default/Full/Limited).
                    TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
                    if (queryTokenInfoBuffer(tokenHandle, TokenElevationType, tokenBuffer) &&
                        tokenBuffer.size() >= sizeof(TOKEN_ELEVATION_TYPE))
                    {
                        elevationType = *reinterpret_cast<const TOKEN_ELEVATION_TYPE*>(tokenBuffer.data());
                    }
                    const wchar_t* elevationTypeText = L"Default";
                    if (elevationType == TokenElevationTypeFull)
                    {
                        elevationTypeText = L"Full";
                    }
                    else if (elevationType == TokenElevationTypeLimited)
                    {
                        elevationTypeText = L"Limited";
                    }
                    textBuilder << L"ElevationType: " << elevationTypeText << L"\n";

                    // TokenElevation: Output whether elevation is granted.
                    if (queryTokenInfoBuffer(tokenHandle, TokenElevation, tokenBuffer) &&
                        tokenBuffer.size() >= sizeof(TOKEN_ELEVATION))
                    {
                        const auto* elevation = reinterpret_cast<const TOKEN_ELEVATION*>(tokenBuffer.data());
                        textBuilder << L"IsElevated: " << (elevation->TokenIsElevated != 0 ? L"true" : L"false") << L"\n";
                    }

                    // TokenLinkedToken: Indicates whether a linked token exists (in administrator split token scenarios).
                    if (queryTokenInfoBuffer(tokenHandle, TokenLinkedToken, tokenBuffer) &&
                        tokenBuffer.size() >= sizeof(TOKEN_LINKED_TOKEN))
                    {
                        const auto* linkedTokenInfo = reinterpret_cast<const TOKEN_LINKED_TOKEN*>(tokenBuffer.data());
                        const bool kHasLinkedToken =
                            linkedTokenInfo->LinkedToken != nullptr &&
                            linkedTokenInfo->LinkedToken != INVALID_HANDLE_VALUE;
                        textBuilder << L"LinkedToken: " << (kHasLinkedToken ? L"Present" : L"None") << L"\n";
                        if (kHasLinkedToken)
                        {
                            CloseHandle(linkedTokenInfo->LinkedToken);
                        }
                    }
                    else
                    {
                        textBuilder << L"LinkedToken: Unavailable\n";
                    }

                    // TokenRestrictedSids: Output restricted SID count.
                    if (queryTokenInfoBuffer(tokenHandle, TokenRestrictedSids, tokenBuffer))
                    {
                        const auto* restrictedSids = reinterpret_cast<const TOKEN_GROUPS*>(tokenBuffer.data());
                        textBuilder << L"RestrictedSidCount: " << restrictedSids->GroupCount << L"\n";
                    }
                    else
                    {
                        textBuilder << L"RestrictedSidCount: 0\n";
                    }

                    // TokenGroups: Output group count and preview.
                    if (queryTokenInfoBuffer(tokenHandle, TokenGroups, tokenBuffer))
                    {
                        const auto* groupsInfo = reinterpret_cast<const TOKEN_GROUPS*>(tokenBuffer.data());
                        textBuilder << L"GroupCount: " << groupsInfo->GroupCount << L"\n";
                        const DWORD kPreviewCount = std::min<DWORD>(groupsInfo->GroupCount, 16);
                        for (DWORD index = 0; index < kPreviewCount; ++index)
                        {
                            textBuilder << L"  - "
                                << convertSidToText(groupsInfo->Groups[index].Sid).toStdWString()
                                << L"\n";
                        }
                    }

                    // TokenPrivileges: Outputs the privilege count and enabled status.
                    if (queryTokenInfoBuffer(tokenHandle, TokenPrivileges, tokenBuffer))
                    {
                        const auto* privilegesInfo =
                            reinterpret_cast<const TOKEN_PRIVILEGES*>(tokenBuffer.data());
                        textBuilder << L"PrivilegeCount: " << privilegesInfo->PrivilegeCount << L"\n";
                        const DWORD kPreviewCount = std::min<DWORD>(privilegesInfo->PrivilegeCount, 24);
                        for (DWORD index = 0; index < kPreviewCount; ++index)
                        {
                            const LUID_AND_ATTRIBUTES& privilegeEntry = privilegesInfo->Privileges[index];
                            WCHAR privilegeName[256] = {};
                            DWORD nameLength = static_cast<DWORD>(std::size(privilegeName));
                            const BOOL kNameOk = LookupPrivilegeNameW(
                                nullptr,
                                const_cast<LUID*>(&privilegeEntry.Luid),
                                privilegeName,
                                &nameLength);
                            textBuilder << L"  - "
                                << (kNameOk != FALSE ? std::wstring(privilegeName) : L"<Unknown>")
                                << ((privilegeEntry.Attributes & SE_PRIVILEGE_ENABLED) != 0 ? L" [Enabled]" : L" [Disabled]")
                                << L"\n";
                        }
                    }

                    // All token information class snapshot:
                    // - Enumerates TokenInformationClass 1..80;
                    // - Output readability, byte length, and raw preview for each class to avoid missing key fields.
                    textBuilder << L"\n[All TokenInformationClass Snapshot]\n";
                    for (ULONG classId = 1; classId <= 80; ++classId)
                    {
                        std::vector<std::uint8_t> classRawBuffer;
                        const TOKEN_INFORMATION_CLASS kInfoClass = static_cast<TOKEN_INFORMATION_CLASS>(classId);
                        const bool kQueryOk = queryTokenInfoBuffer(tokenHandle, kInfoClass, classRawBuffer);
                        if (kQueryOk)
                        {
                            textBuilder << L"  ["
                                << classId
                                << L"] "
                                << tokenInfoClassNameById(classId).toStdWString()
                                << L": size="
                                << classRawBuffer.size()
                                << L", raw="
                                << formatTokenRawPreview(classRawBuffer, 24).toStdWString()
                                << L"\n";
                        }
                        else
                        {
                            const DWORD kQueryError = GetLastError();
                            textBuilder << L"  ["
                                << classId
                                << L"] "
                                << tokenInfoClassNameById(classId).toStdWString()
                                << L": queryFailed("
                                << kQueryError
                                << L")\n";
                        }
                    }

                    CloseHandle(tokenHandle);
                }

                // Native process security fields:
                // - DebugPort / DEP / Critical / Protection / Subsystem。
                if (ntQueryProcess != nullptr)
                {
                    ULONG_PTR debugPort = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassDebugPort, debugPort))
                    {
                        textBuilder << L"DebugPort: " << uint64ToHex(debugPort).toStdWString() << L"\n";
                    }

                    ULONG executeFlags = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassExecuteFlags, executeFlags))
                    {
                        textBuilder << L"DEPFlags: 0x"
                            << QString::number(executeFlags, 16).toUpper().toStdWString()
                            << L"\n";
                    }

                    ULONG breakOnTermination = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassBreakOnTermination, breakOnTermination))
                    {
                        textBuilder << L"ProcessCriticalFlag(BreakOnTermination): "
                            << (breakOnTermination != 0 ? L"true" : L"false")
                            << L"\n";
                    }

                    std::uint8_t protectionLevel = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassProtection, protectionLevel))
                    {
                        textBuilder << L"Protection: "
                            << protectionLevelToText(protectionLevel).toStdWString()
                            << L"\n";
                    }

                    ULONG subsystemType = 0;
                    if (queryNtProcessInfoFixed(ntQueryProcess, processHandle, kProcessInfoClassSubsystem, subsystemType))
                    {
                        textBuilder << L"SubsystemType: " << subsystemType << L"\n";
                    }
                }

                // GUI resource statistics: GDI / USER object counts.
                const DWORD kGdiObjectCount = GetGuiResources(processHandle, GR_GDIOBJECTS);
                const DWORD kUserObjectCount = GetGuiResources(processHandle, GR_USEROBJECTS);
                textBuilder << L"GDIObjectCount: " << kGdiObjectCount << L"\n";
                textBuilder << L"USERObjectCount: " << kUserObjectCount << L"\n";

                // IO counters: read/write operation counts and byte counts.
                IO_COUNTERS ioCounters{};
                if (GetProcessIoCounters(processHandle, &ioCounters) != FALSE)
                {
                    textBuilder << L"IoReadOps: " << ioCounters.ReadOperationCount << L"\n";
                    textBuilder << L"IoWriteOps: " << ioCounters.WriteOperationCount << L"\n";
                    textBuilder << L"IoReadBytes: " << ioCounters.ReadTransferCount << L"\n";
                    textBuilder << L"IoWriteBytes: " << ioCounters.WriteTransferCount << L"\n";
                }

                // Job association info: whether the process is in a Job object.
                BOOL inJobObject = FALSE;
                if (IsProcessInJob(processHandle, nullptr, &inJobObject) != FALSE)
                {
                    textBuilder << L"InJobObject: " << (inJobObject != FALSE ? L"true" : L"false") << L"\n";
                }

                // Power-saving state: dynamically query GetProcessInformation(ProcessPowerThrottling=4).
                HMODULE kernel32Module = GetModuleHandleW(L"kernel32.dll");
                GetProcessInformationFn getProcessInformation = reinterpret_cast<GetProcessInformationFn>(
                    kernel32Module != nullptr ? GetProcAddress(kernel32Module, "GetProcessInformation") : nullptr);
                if (getProcessInformation != nullptr)
                {
                    ProcessPowerThrottlingStateNative powerState{};
                    powerState.version = 1;
                    const BOOL kPowerOk = getProcessInformation(
                        processHandle,
                        4,
                        &powerState,
                        static_cast<DWORD>(sizeof(powerState)));
                    if (kPowerOk != FALSE)
                    {
                        textBuilder << L"PowerThrottlingControlMask: 0x"
                            << QString::number(powerState.controlMask, 16).toUpper().toStdWString()
                            << L"\n";
                        textBuilder << L"PowerThrottlingStateMask: 0x"
                            << QString::number(powerState.stateMask, 16).toUpper().toStdWString()
                            << L"\n";
                    }
                }

                // Window-related information: window count + thread desktop name + current window station name.
                const std::uint32_t kWindowCount = countTopLevelWindowsByPid(kPidValue);
                textBuilder << L"TopLevelWindowCount: " << kWindowCount << L"\n";

                const QString kDesktopName = queryDesktopNameByProcessThreads(kPidValue);
                if (!kDesktopName.trimmed().isEmpty())
                {
                    textBuilder << L"ThreadDesktop: " << kDesktopName.toStdWString() << L"\n";
                }

                HWINSTA processWindowStation = GetProcessWindowStation();
                if (processWindowStation != nullptr)
                {
                    wchar_t stationNameBuffer[256] = {};
                    DWORD stationNameBytes = 0;
                    const BOOL kStationOk = GetUserObjectInformationW(
                        processWindowStation,
                        UOI_NAME,
                        stationNameBuffer,
                        static_cast<DWORD>(sizeof(stationNameBuffer)),
                        &stationNameBytes);
                    if (kStationOk != FALSE)
                    {
                        textBuilder << L"ProcessWindowStation: " << stationNameBuffer << L"\n";
                    }
                }

                // Supplement output for session ID and handle count.
                DWORD sessionId = 0;
                if (ProcessIdToSessionId(kPidValue, &sessionId) != FALSE)
                {
                    textBuilder << L"SessionId: " << sessionId << L"\n";
                }
                DWORD handleCount = 0;
                if (GetProcessHandleCount(processHandle, &handleCount) != FALSE)
                {
                    textBuilder << L"HandleCount: " << handleCount << L"\n";
                }

                CloseHandle(processHandle);
            }

            refreshResult.detailText = QString::fromStdWString(textBuilder.str());
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, refreshResult, kTicketValue]()
                {
                    if (guardThis == nullptr || guardThis->tokenRefreshTicket_ != kTicketValue)
                    {
                        return;
                    }
                    guardThis->applyTokenRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::refreshTokenSwitchStates()
{
    // Token switch state re-read log:
    // - The current read-back chain reuses the same KLogEvent;
    // - Facilitates chaining 'open handle -> read field -> update UI' into a single traceable link.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] refreshTokenSwitchStates: pid="
        << baseRecord_.pid
        << eol;

    // Switch page re-read belongs to the initial refresh action of this page; manual refresh also reuses this flag.
    tokenSwitchInitialRefreshStarted_ = true;

    // setStatusLabel:
    // - Unify writing status text and color;
    // - Avoid repeating setText/setStyleSheet across multiple branches.
    const auto kSetStatusLabel =
        [this](const QString& statusText, const QColor& textColor, const int fontWeight)
    {
        if (tokenSwitchStatusLabel_ == nullptr)
        {
            return;
        }
        tokenSwitchStatusLabel_->setText(statusText);
        tokenSwitchStatusLabel_->setStyleSheet(buildStateLabelStyle(textColor, fontWeight));
    };

    if (baseRecord_.pid == 0)
    {
        kSetStatusLabel(QStringLiteral("● 刷新失败：PID 无效"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: PID 无效。"
            << eol;
        return;
    }

    if (refreshTokenSwitchButton_ != nullptr)
    {
        refreshTokenSwitchButton_->setEnabled(false);
    }
    kSetStatusLabel(QStringLiteral("● 正在读取令牌开关..."), ksword_theme::primaryBlueColor, 700);

    // Open process and token handles:
    // - Reading the switch only requires TOKEN_QUERY;
    // - Use QUERY_LIMITED for the process handle first to minimize privilege requirements.
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, baseRecord_.pid);
    if (processHandle == nullptr)
    {
        const DWORD kOpenProcessError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("修改目标进程令牌"), kOpenProcessError);
        kSetStatusLabel(
            QStringLiteral("● 刷新失败：OpenProcess(%1)").arg(kOpenProcessError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: OpenProcess 失败, error="
            << kOpenProcessError
            << eol;
        if (refreshTokenSwitchButton_ != nullptr)
        {
            refreshTokenSwitchButton_->setEnabled(true);
        }
        return;
    }

    HANDLE tokenHandle = nullptr;
    if (OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE || tokenHandle == nullptr)
    {
        const DWORD kOpenTokenError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("读取目标进程令牌"), kOpenTokenError);
        CloseHandle(processHandle);
        processHandle = nullptr;
        kSetStatusLabel(
            QStringLiteral("● 刷新失败：OpenProcessToken(%1)").arg(kOpenTokenError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: OpenProcessToken 失败, error="
            << kOpenTokenError
            << eol;
        if (refreshTokenSwitchButton_ != nullptr)
        {
            refreshTokenSwitchButton_->setEnabled(true);
        }
        return;
    }

    // queryBoolToCheckBox:
    // - Read a ULONG boolean bit from the token and write it to the corresponding checkbox;
    // - Handle: Write failed items to failItemList for final status bar aggregation.
    int successCount = 0;
    QStringList failItemList;
    const auto kQueryBoolToCheckBox =
        [tokenHandle, &successCount, &failItemList](
            QCheckBox* checkBox,
            const TOKEN_INFORMATION_CLASS infoClass,
            const QString& itemName)
    {
        if (checkBox == nullptr)
        {
            failItemList << QStringLiteral("%1(控件为空)").arg(itemName);
            return;
        }

        bool flagValue = false;
        if (!queryTokenBoolFlag(tokenHandle, infoClass, flagValue))
        {
            const DWORD kQueryError = GetLastError();
            failItemList << QStringLiteral("%1(%2)").arg(itemName).arg(kQueryError);
            return;
        }
        checkBox->setChecked(flagValue);
        ++successCount;
    };

    kQueryBoolToCheckBox(tokenSandboxInertCheck_, TokenSandBoxInert, QStringLiteral("SandboxInert"));
    kQueryBoolToCheckBox(tokenVirtualizationAllowedCheck_, TokenVirtualizationAllowed, QStringLiteral("VirtualizationAllowed"));
    kQueryBoolToCheckBox(tokenVirtualizationEnabledCheck_, TokenVirtualizationEnabled, QStringLiteral("VirtualizationEnabled"));
    kQueryBoolToCheckBox(tokenUiAccessCheck_, TokenUIAccess, QStringLiteral("UIAccess"));
    kQueryBoolToCheckBox(
        tokenHasRestrictionsCheck_,
        kTokenInfoClassHasRestrictions,
        QStringLiteral("HasRestrictions"));
    kQueryBoolToCheckBox(
        tokenIsAppContainerCheck_,
        kTokenInfoClassIsAppContainer,
        QStringLiteral("IsAppContainer"));
    kQueryBoolToCheckBox(
        tokenIsRestrictedCheck_,
        kTokenInfoClassIsRestricted,
        QStringLiteral("IsRestricted"));
    kQueryBoolToCheckBox(
        tokenIsLessPrivilegedAppContainerCheck_,
        kTokenInfoClassIsLessPrivilegedAppContainer,
        QStringLiteral("IsLessPrivilegedAppContainer"));
    kQueryBoolToCheckBox(
        tokenIsSandboxedCheck_,
        kTokenInfoClassIsSandboxed,
        QStringLiteral("IsSandboxed"));
    kQueryBoolToCheckBox(
        tokenIsAppSiloCheck_,
        kTokenInfoClassIsAppSilo,
        QStringLiteral("IsAppSilo"));

    // MandatoryPolicy Read:
    // - Read two bits at once and synchronize them to the two policy checkboxes respectively;
    // - Record failures to failItemList as well.
    if (tokenMandatoryNoWriteUpCheck_ == nullptr || tokenMandatoryNewProcessMinCheck_ == nullptr)
    {
        failItemList << QStringLiteral("MandatoryPolicy(控件为空)");
    }
    else
    {
        bool noWriteUpEnabled = false;
        bool newProcessMinEnabled = false;
        if (queryTokenMandatoryPolicyBits(tokenHandle, noWriteUpEnabled, newProcessMinEnabled))
        {
            tokenMandatoryNoWriteUpCheck_->setChecked(noWriteUpEnabled);
            tokenMandatoryNewProcessMinCheck_->setChecked(newProcessMinEnabled);
            ++successCount;
        }
        else
        {
            const DWORD kQueryError = GetLastError();
            failItemList << QStringLiteral("MandatoryPolicy(%1)").arg(kQueryError);
        }
    }

    CloseHandle(tokenHandle);
    tokenHandle = nullptr;
    CloseHandle(processHandle);
    processHandle = nullptr;

    if (refreshTokenSwitchButton_ != nullptr)
    {
        refreshTokenSwitchButton_->setEnabled(true);
    }

    // Final status bar:
    // - Display green for all success.
    // - Displays an orange summary for failed items; the complete list of failures is written only to the log.
    if (failItemList.isEmpty())
    {
        kSetStatusLabel(
            QStringLiteral("● 刷新完成：%1 项开关已同步").arg(successCount),
            statusIdleColor(),
            600);
        info << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: 完成, successCount="
            << successCount
            << eol;
    }
    else
    {
        kSetStatusLabel(
            QStringLiteral("● 刷新完成：成功%1，失败%2；详情已写入日志。")
            .arg(successCount)
            .arg(failItemList.size()),
            statusWarningColor(),
            700);
        warn << actionEvent
            << "[ProcessDetailWindow] refreshTokenSwitchStates: 部分失败, successCount="
            << successCount
            << ", failItems="
            << failItemList.join(QStringLiteral(" | ")).toStdString()
            << eol;
    }
}

void ProcessDetailWindow::applyTokenSwitchStates()
{
    // Token switch state apply log:
    // - Use the same KLogEvent throughout the entire application flow.
    // - Each field logs its result separately to facilitate pinpointing which permission is insufficient.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] applyTokenSwitchStates: pid="
        << baseRecord_.pid
        << eol;

    // setStatusLabel:
    // - Unify writing status text and color;
    // - Maintain a feedback style consistent with refreshTokenSwitchStates.
    const auto kSetStatusLabel =
        [this](const QString& statusText, const QColor& textColor, const int fontWeight)
    {
        if (tokenSwitchStatusLabel_ == nullptr)
        {
            return;
        }
        tokenSwitchStatusLabel_->setText(statusText);
        tokenSwitchStatusLabel_->setStyleSheet(buildStateLabelStyle(textColor, fontWeight));
    };

    if (baseRecord_.pid == 0)
    {
        kSetStatusLabel(QStringLiteral("● 应用失败：PID 无效"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: PID 无效。"
            << eol;
        return;
    }

    if (applyTokenSwitchButton_ != nullptr)
    {
        applyTokenSwitchButton_->setEnabled(false);
    }
    kSetStatusLabel(QStringLiteral("● 正在应用令牌开关..."), ksword_theme::primaryBlueColor, 700);

    // Dynamically resolve NtSetInformationToken:
    // - The user requirement mentions NtSetTokenInformation; this corresponds to NtSetInformationToken exported by ntdll.
    // - If the export is unavailable, terminate immediately and provide an error message.
    HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
    if (ntdllModule == nullptr)
    {
        ntdllModule = LoadLibraryW(L"ntdll.dll");
    }
    const auto kSetInformationToken = reinterpret_cast<NtSetInformationTokenFn>(
        ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtSetInformationToken") : nullptr);
    if (kSetInformationToken == nullptr)
    {
        kSetStatusLabel(QStringLiteral("● 应用失败：NtSetInformationToken 不可用"), statusWarningColor(), 700);
        err << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: NtSetInformationToken 不可用。"
            << eol;
        if (applyTokenSwitchButton_ != nullptr)
        {
            applyTokenSwitchButton_->setEnabled(true);
        }
        return;
    }

    // Open target token:
    // - The write switch requires TOKEN_ADJUST_DEFAULT.
    // - Also retains TOKEN_QUERY for subsequent re-reading and diagnostics.
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, baseRecord_.pid);
    if (processHandle == nullptr)
    {
        const DWORD kOpenProcessError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("修改目标进程令牌"), kOpenProcessError);
        kSetStatusLabel(
            QStringLiteral("● 应用失败：OpenProcess(%1)").arg(kOpenProcessError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: OpenProcess 失败, error="
            << kOpenProcessError
            << eol;
        if (applyTokenSwitchButton_ != nullptr)
        {
            applyTokenSwitchButton_->setEnabled(true);
        }
        return;
    }

    HANDLE tokenHandle = nullptr;
    if (OpenProcessToken(processHandle, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &tokenHandle) == FALSE || tokenHandle == nullptr)
    {
        const DWORD kOpenTokenError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("修改目标进程令牌"), kOpenTokenError);
        CloseHandle(processHandle);
        processHandle = nullptr;
        kSetStatusLabel(
            QStringLiteral("● 应用失败：OpenProcessToken(%1)").arg(kOpenTokenError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: OpenProcessToken 失败, error="
            << kOpenTokenError
            << eol;
        if (applyTokenSwitchButton_ != nullptr)
        {
            applyTokenSwitchButton_->setEnabled(true);
        }
        return;
    }

    // applyBoolFromCheckBox:
    // - Reads the checkbox state and calls NtSetInformationToken.
    // - Each failure records an NTSTATUS, which is ultimately aggregated into the status bar.
    int successCount = 0;
    long privilegeDeniedStatus = 0;
    QStringList failItemList;
    const auto kApplyBoolFromCheckBox =
        [kSetInformationToken, tokenHandle, &successCount, &failItemList, &privilegeDeniedStatus](
            QCheckBox* checkBox,
            const TOKEN_INFORMATION_CLASS infoClass,
            const QString& itemName)
    {
        if (checkBox == nullptr)
        {
            failItemList << QStringLiteral("%1(控件为空)").arg(itemName);
            return;
        }

        const NTSTATUS kSetStatus = applyTokenBoolFlag(
            kSetInformationToken,
            tokenHandle,
            infoClass,
            checkBox->isChecked());
        if (!NT_SUCCESS(kSetStatus))
        {
            if (static_cast<unsigned long>(kSetStatus) == 0xC0000022UL)
            {
                privilegeDeniedStatus = static_cast<long>(kSetStatus);
            }
            failItemList << QStringLiteral("%1(%2)").arg(itemName).arg(formatNtStatusHex(kSetStatus));
            return;
        }
        ++successCount;
    };

    kApplyBoolFromCheckBox(tokenSandboxInertCheck_, TokenSandBoxInert, QStringLiteral("SandboxInert"));
    kApplyBoolFromCheckBox(tokenVirtualizationAllowedCheck_, TokenVirtualizationAllowed, QStringLiteral("VirtualizationAllowed"));
    kApplyBoolFromCheckBox(tokenVirtualizationEnabledCheck_, TokenVirtualizationEnabled, QStringLiteral("VirtualizationEnabled"));
    kApplyBoolFromCheckBox(tokenUiAccessCheck_, TokenUIAccess, QStringLiteral("UIAccess"));
    kApplyBoolFromCheckBox(
        tokenHasRestrictionsCheck_,
        kTokenInfoClassHasRestrictions,
        QStringLiteral("HasRestrictions"));
    kApplyBoolFromCheckBox(
        tokenIsAppContainerCheck_,
        kTokenInfoClassIsAppContainer,
        QStringLiteral("IsAppContainer"));
    kApplyBoolFromCheckBox(
        tokenIsRestrictedCheck_,
        kTokenInfoClassIsRestricted,
        QStringLiteral("IsRestricted"));
    kApplyBoolFromCheckBox(
        tokenIsLessPrivilegedAppContainerCheck_,
        kTokenInfoClassIsLessPrivilegedAppContainer,
        QStringLiteral("IsLessPrivilegedAppContainer"));
    kApplyBoolFromCheckBox(
        tokenIsSandboxedCheck_,
        kTokenInfoClassIsSandboxed,
        QStringLiteral("IsSandboxed"));
    kApplyBoolFromCheckBox(
        tokenIsAppSiloCheck_,
        kTokenInfoClassIsAppSilo,
        QStringLiteral("IsAppSilo"));

    // MandatoryPolicy Write:
    // - Combines two policy checkboxes into a single POLICY bitmask.
    // - Submit using NtSetInformationToken(TokenMandatoryPolicy) in a single call.
    if (tokenMandatoryNoWriteUpCheck_ == nullptr || tokenMandatoryNewProcessMinCheck_ == nullptr)
    {
        failItemList << QStringLiteral("MandatoryPolicy(控件为空)");
    }
    else
    {
        const NTSTATUS kPolicyStatus = applyTokenMandatoryPolicyBits(
            kSetInformationToken,
            tokenHandle,
            tokenMandatoryNoWriteUpCheck_->isChecked(),
            tokenMandatoryNewProcessMinCheck_->isChecked());
        if (NT_SUCCESS(kPolicyStatus))
        {
            ++successCount;
        }
        else
        {
            if (static_cast<unsigned long>(kPolicyStatus) == 0xC0000022UL)
            {
                privilegeDeniedStatus = static_cast<long>(kPolicyStatus);
            }
            failItemList << QStringLiteral("MandatoryPolicy(%1)").arg(formatNtStatusHex(kPolicyStatus));
        }
    }

    CloseHandle(tokenHandle);
    tokenHandle = nullptr;
    CloseHandle(processHandle);
    processHandle = nullptr;

    if (applyTokenSwitchButton_ != nullptr)
    {
        applyTokenSwitchButton_->setEnabled(true);
    }

    if (privilegeDeniedStatus != 0)
    {
        (void)ks::ui::promptForPrivilegeNtStatus(
            this,
            QStringLiteral("修改目标进程令牌"),
            privilegeDeniedStatus);
    }

    // Apply result feedback:
    // - Refreshes the text token page and switch page when all operations succeed;
    // - Refresh the switch page even if some items fail, to ensure the UI state remains as consistent as possible with the actual state.
    if (failItemList.isEmpty())
    {
        kSetStatusLabel(
            QStringLiteral("● 应用完成：成功%1项").arg(successCount),
            statusIdleColor(),
            600);
        info << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: 全部成功, successCount="
            << successCount
            << eol;
    }
    else
    {
        kSetStatusLabel(
            QStringLiteral("● 应用完成：成功%1，失败%2；详情已写入日志。")
            .arg(successCount)
            .arg(failItemList.size()),
            statusWarningColor(),
            700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyTokenSwitchStates: 部分失败, successCount="
            << successCount
            << ", failItems="
            << failItemList.join(QStringLiteral(" | ")).toStdString()
            << eol;
    }

    requestAsyncTokenRefresh();
    refreshTokenSwitchStates();
}

void ProcessDetailWindow::applyRawTokenInformation()
{
    // Raw settings application log:
    // - A single KLogEvent spans 'parse input -> open token -> NtSetInformationToken'.
    // - Ensure failure points can be accurately located in logs.
    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDetailWindow] applyRawTokenInformation: pid="
        << baseRecord_.pid
        << eol;

    // setStatusLabel:
    // - Uniformly set the status text and color for the token settings page;
    // - Reduce repetitive setText/setStyleSheet code across multiple branches.
    const auto kSetStatusLabel =
        [this](const QString& statusText, const QColor& textColor, const int fontWeight)
    {
        if (tokenSwitchStatusLabel_ == nullptr)
        {
            return;
        }
        tokenSwitchStatusLabel_->setText(statusText);
        tokenSwitchStatusLabel_->setStyleSheet(buildStateLabelStyle(textColor, fontWeight));
    };

    if (baseRecord_.pid == 0)
    {
        kSetStatusLabel(QStringLiteral("● 原始设置失败：PID 无效"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: PID 无效。"
            << eol;
        return;
    }
    if (tokenRawInfoClassCombo_ == nullptr || tokenRawInputModeCombo_ == nullptr || tokenRawPayloadEdit_ == nullptr)
    {
        kSetStatusLabel(QStringLiteral("● 原始设置失败：控件未初始化"), statusWarningColor(), 700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: 原始设置控件为空。"
            << eol;
        return;
    }

    const int kClassId = tokenRawInfoClassCombo_->currentData().toInt();
    const QString kModeKey = tokenRawInputModeCombo_->currentData().toString().trimmed().toLower();
    const QString kPayloadText = tokenRawPayloadEdit_->text().trimmed();
    if (kClassId <= 0)
    {
        kSetStatusLabel(QStringLiteral("● 原始设置失败：信息类无效"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: classId 无效="
            << kClassId
            << eol;
        return;
    }
    if (kPayloadText.isEmpty())
    {
        kSetStatusLabel(QStringLiteral("● 原始设置失败：负载为空"), statusWarningColor(), 700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: payload 为空。"
            << eol;
        return;
    }

    // Input parsing:
    // - UInt32/UInt64 use Qt's automatic base parsing (supports 0x prefix);
    // - HexBytes: byte sequence separated by spaces or commas.
    std::vector<std::uint8_t> payloadBuffer;
    QString parseErrorText;
    if (kModeKey == QStringLiteral("u32"))
    {
        bool parseOk = false;
        const qulonglong kParsedValue = kPayloadText.toULongLong(&parseOk, 0);
        if (!parseOk || kParsedValue > 0xFFFFFFFFULL)
        {
            parseErrorText = QStringLiteral("UInt32 解析失败");
        }
        else
        {
            const std::uint32_t kValue32 = static_cast<std::uint32_t>(kParsedValue);
            payloadBuffer.resize(sizeof(kValue32));
            std::memcpy(payloadBuffer.data(), &kValue32, sizeof(kValue32));
        }
    }
    else if (kModeKey == QStringLiteral("u64"))
    {
        bool parseOk = false;
        const qulonglong kParsedValue = kPayloadText.toULongLong(&parseOk, 0);
        if (!parseOk)
        {
            parseErrorText = QStringLiteral("UInt64 解析失败");
        }
        else
        {
            const std::uint64_t kValue64 = static_cast<std::uint64_t>(kParsedValue);
            payloadBuffer.resize(sizeof(kValue64));
            std::memcpy(payloadBuffer.data(), &kValue64, sizeof(kValue64));
        }
    }
    else if (kModeKey == QStringLiteral("hex"))
    {
        QString normalizedText = kPayloadText;
        normalizedText.replace(',', ' ');
        const QStringList kTokenList = normalizedText.split(' ', Qt::SkipEmptyParts);
        if (kTokenList.isEmpty())
        {
            parseErrorText = QStringLiteral("HexBytes 解析失败：没有字节");
        }
        else
        {
            payloadBuffer.reserve(static_cast<std::size_t>(kTokenList.size()));
            for (const QString& tokenText : kTokenList)
            {
                QString oneByteText = tokenText.trimmed();
                if (oneByteText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
                {
                    oneByteText = oneByteText.mid(2);
                }
                bool oneByteOk = false;
                const uint kOneByteValue = oneByteText.toUInt(&oneByteOk, 16);
                if (!oneByteOk || kOneByteValue > 0xFFU)
                {
                    parseErrorText = QStringLiteral("HexBytes 解析失败：非法字节 '%1'").arg(tokenText);
                    payloadBuffer.clear();
                    break;
                }
                payloadBuffer.push_back(static_cast<std::uint8_t>(kOneByteValue));
            }
        }
    }
    else
    {
        parseErrorText = QStringLiteral("未知输入模式");
    }

    if (!parseErrorText.isEmpty() || payloadBuffer.empty())
    {
        kSetStatusLabel(
            QStringLiteral("● 原始设置失败：%1").arg(parseErrorText.isEmpty() ? QStringLiteral("负载为空") : parseErrorText),
            statusWarningColor(),
            700);
        warn << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: 负载解析失败, mode="
            << kModeKey.toStdString()
            << ", payload="
            << kPayloadText.toStdString()
            << ", error="
            << parseErrorText.toStdString()
            << eol;
        return;
    }

    if (tokenRawApplyButton_ != nullptr)
    {
        tokenRawApplyButton_->setEnabled(false);
    }
    kSetStatusLabel(QStringLiteral("● 正在应用原始令牌设置..."), ksword_theme::primaryBlueColor, 700);

    // Dynamically resolve NtSetInformationToken:
    // - User-selected info classes and values are passed directly to native APIs.
    // - This path covers all configurable options beyond the quick toggle.
    HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
    if (ntdllModule == nullptr)
    {
        ntdllModule = LoadLibraryW(L"ntdll.dll");
    }
    const auto kSetInformationToken = reinterpret_cast<NtSetInformationTokenFn>(
        ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtSetInformationToken") : nullptr);
    if (kSetInformationToken == nullptr)
    {
        kSetStatusLabel(QStringLiteral("● 原始设置失败：NtSetInformationToken 不可用"), statusWarningColor(), 700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: NtSetInformationToken 不可用。"
            << eol;
        if (tokenRawApplyButton_ != nullptr)
        {
            tokenRawApplyButton_->setEnabled(true);
        }
        return;
    }

    // Open target token:
    // - TOKEN_ADJUST_DEFAULT overrides most settings.
    // - TOKEN_ADJUST_SESSIONID is used for special cases like TokenSessionId and similar information classes.
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, baseRecord_.pid);
    if (processHandle == nullptr)
    {
        const DWORD kOpenProcessError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("应用原始进程令牌设置"), kOpenProcessError);
        kSetStatusLabel(
            QStringLiteral("● 原始设置失败：OpenProcess(%1)").arg(kOpenProcessError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: OpenProcess 失败, error="
            << kOpenProcessError
            << eol;
        if (tokenRawApplyButton_ != nullptr)
        {
            tokenRawApplyButton_->setEnabled(true);
        }
        return;
    }

    HANDLE tokenHandle = nullptr;
    if (OpenProcessToken(
        processHandle,
        TOKEN_ADJUST_DEFAULT | kTokenAdjustSessionIdAccess | TOKEN_QUERY,
        &tokenHandle) == FALSE || tokenHandle == nullptr)
    {
        const DWORD kOpenTokenError = GetLastError();
        (void)ks::ui::promptForPrivilegeFailure(this, QStringLiteral("应用原始进程令牌设置"), kOpenTokenError);
        CloseHandle(processHandle);
        processHandle = nullptr;
        kSetStatusLabel(
            QStringLiteral("● 原始设置失败：OpenProcessToken(%1)").arg(kOpenTokenError),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: OpenProcessToken 失败, error="
            << kOpenTokenError
            << eol;
        if (tokenRawApplyButton_ != nullptr)
        {
            tokenRawApplyButton_->setEnabled(true);
        }
        return;
    }

    const TOKEN_INFORMATION_CLASS kInfoClass = static_cast<TOKEN_INFORMATION_CLASS>(kClassId);
    const NTSTATUS kSetStatus = kSetInformationToken(
        tokenHandle,
        kInfoClass,
        payloadBuffer.data(),
        static_cast<ULONG>(payloadBuffer.size()));

    CloseHandle(tokenHandle);
    tokenHandle = nullptr;
    CloseHandle(processHandle);
    processHandle = nullptr;

    if (tokenRawApplyButton_ != nullptr)
    {
        tokenRawApplyButton_->setEnabled(true);
    }

    if (NT_SUCCESS(kSetStatus))
    {
        kSetStatusLabel(
            QStringLiteral("● 原始设置成功：[%1] %2, size=%3")
            .arg(kClassId)
            .arg(tokenInfoClassNameById(static_cast<ULONG>(kClassId)))
            .arg(payloadBuffer.size()),
            statusIdleColor(),
            600);
        info << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: 成功, classId="
            << kClassId
            << ", className="
            << tokenInfoClassNameById(static_cast<ULONG>(kClassId)).toStdString()
            << ", payloadSize="
            << payloadBuffer.size()
            << ", payloadPreview="
            << formatTokenRawPreview(payloadBuffer, 24).toStdString()
            << eol;
    }
    else
    {
        (void)ks::ui::promptForPrivilegeNtStatus(this, QStringLiteral("应用原始进程令牌设置"), static_cast<long>(kSetStatus));
        kSetStatusLabel(
            QStringLiteral("● 原始设置失败：[%1] %2, status=%3")
            .arg(kClassId)
            .arg(tokenInfoClassNameById(static_cast<ULONG>(kClassId)))
            .arg(formatNtStatusHex(kSetStatus)),
            statusWarningColor(),
            700);
        err << actionEvent
            << "[ProcessDetailWindow] applyRawTokenInformation: 失败, classId="
            << kClassId
            << ", className="
            << tokenInfoClassNameById(static_cast<ULONG>(kClassId)).toStdString()
            << ", status="
            << formatNtStatusHex(kSetStatus).toStdString()
            << ", payloadSize="
            << payloadBuffer.size()
            << ", payloadPreview="
            << formatTokenRawPreview(payloadBuffer, 24).toStdString()
            << eol;
    }

    // Unified refresh after submission:
    // - The token detail page will re-fetch the complete information snapshot.
    // - The shortcut switch page will re-read the visible checkbox states.
    requestAsyncTokenRefresh();
    refreshTokenSwitchStates();
}

void ProcessDetailWindow::requestAsyncKernelCallbackRefresh()
{
    // Callback tab refreshes independently of the PEB summary tab:
    // - Only read the PEB pointer, callback table, and module snapshot.
    // - Do not scan the entire virtual address space to avoid the full page overhead of the PEB when the user only views the callback table.
    if (kernelCallbackRefreshing_ || baseRecord_.pid == 0U)
    {
        return;
    }

    kernelCallbackInitialRefreshStarted_ = true;
    kernelCallbackRefreshing_ = true;
    const std::uint64_t kTicketValue = ++kernelCallbackRefreshTicket_;
    const std::uint32_t kPidValue = baseRecord_.pid;

    if (refreshKernelCallbackButton_ != nullptr)
    {
        refreshKernelCallbackButton_->setEnabled(false);
    }
    if (kernelCallbackStatusLabel_ != nullptr)
    {
        kernelCallbackStatusLabel_->setText(QStringLiteral("● 正在读取内核回调表..."));
        kernelCallbackStatusLabel_->setStyleSheet(
            buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }
    if (kernelCallbackRefreshProgressPid_ == 0)
    {
        kernelCallbackRefreshProgressPid_ = kPro.addReusable(this, "进程详情", "读取内核回调表");
    }
    kPro.set(kernelCallbackRefreshProgressPid_, "打开目标进程", 0, 15.0f);

    QPointer<ProcessDetailWindow> guardThis(this);
    QRunnable* refreshTask = QRunnable::create([guardThis, kPidValue, kTicketValue]()
        {
            KernelCallbackRefreshResult refreshResult{};
            const auto kBeginTime = std::chrono::steady_clock::now();
            const auto kDeliverResult = [&refreshResult, kBeginTime, guardThis, kTicketValue]()
                {
                    refreshResult.elapsedMs = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - kBeginTime).count());
                    QMetaObject::invokeMethod(
                        guardThis,
                        [guardThis, kTicketValue, refreshResult]()
                        {
                            if (guardThis == nullptr ||
                                guardThis->kernelCallbackRefreshTicket_ != kTicketValue)
                            {
                                return;
                            }
                            guardThis->applyKernelCallbackRefreshResult(refreshResult);
                        },
                        Qt::QueuedConnection);
                };

            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION |
                PROCESS_QUERY_LIMITED_INFORMATION |
                PROCESS_VM_READ,
                FALSE,
                kPidValue);
            if (processHandle == nullptr)
            {
                refreshResult.diagnosticText = QStringLiteral("OpenProcess失败(%1)。")
                    .arg(GetLastError());
                kDeliverResult();
                return;
            }

            HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
            const NtQueryInformationProcessFn kNtQueryProcess =
                reinterpret_cast<NtQueryInformationProcessFn>(
                    ntdllModule != nullptr
                        ? GetProcAddress(ntdllModule, "NtQueryInformationProcess")
                        : nullptr);
            if (kNtQueryProcess == nullptr)
            {
                refreshResult.diagnosticText = QStringLiteral("无法定位NtQueryInformationProcess。");
                CloseHandle(processHandle);
                kDeliverResult();
                return;
            }

            PROCESS_BASIC_INFORMATION basicInformation{};
            const NTSTATUS kBasicStatus = kNtQueryProcess(
                processHandle,
                0,
                &basicInformation,
                static_cast<ULONG>(sizeof(basicInformation)),
                nullptr);

            ULONG_PTR wow64PebAddress = 0;
            const NTSTATUS kWow64Status = kNtQueryProcess(
                processHandle,
                kProcessInfoClassWow64Information,
                &wow64PebAddress,
                static_cast<ULONG>(sizeof(wow64PebAddress)),
                nullptr);
            const bool kUseWow64Peb = NT_SUCCESS(kWow64Status) && wow64PebAddress != 0U;

            std::uint64_t pebAddress = 0;
            std::uint64_t callbackTableAddress = 0;
            std::size_t pointerSize = sizeof(std::uint64_t);
            if (kUseWow64Peb)
            {
                refreshResult.pebKindText = QStringLiteral("Wow64PEB");
                pebAddress = static_cast<std::uint64_t>(wow64PebAddress);
                pointerSize = sizeof(std::uint32_t);

                std::uint32_t callbackTableAddress32 = 0;
                if (!readRemoteStructure(
                    processHandle,
                    pebAddress + 0x2CU,
                    callbackTableAddress32))
                {
                    refreshResult.diagnosticText = QStringLiteral(
                        "读取Wow64PEB.KernelCallbackTable失败。");
                    CloseHandle(processHandle);
                    kDeliverResult();
                    return;
                }
                callbackTableAddress = static_cast<std::uint64_t>(callbackTableAddress32);
            }
            else
            {
                if (!NT_SUCCESS(kBasicStatus) || basicInformation.PebBaseAddress == nullptr)
                {
                    refreshResult.diagnosticText = QStringLiteral(
                        "NtQueryInformationProcess(ProcessBasicInformation)失败：%1。")
                        .arg(formatNtStatusHex(kBasicStatus));
                    CloseHandle(processHandle);
                    kDeliverResult();
                    return;
                }

                refreshResult.pebKindText = QStringLiteral("NativePEB");
                pebAddress = reinterpret_cast<std::uint64_t>(basicInformation.PebBaseAddress);
                std::uint64_t callbackTableAddress64 = 0;
                if (!readRemoteStructure(
                    processHandle,
                    pebAddress + 0x58U,
                    callbackTableAddress64))
                {
                    refreshResult.diagnosticText = QStringLiteral(
                        "读取NativePEB.KernelCallbackTable失败。");
                    CloseHandle(processHandle);
                    kDeliverResult();
                    return;
                }
                callbackTableAddress = callbackTableAddress64;
            }

            refreshResult.pebAddressText = uint64ToHex(pebAddress);
            refreshResult.tableAddressText = uint64ToHex(callbackTableAddress);
            if (callbackTableAddress == 0U)
            {
                refreshResult.diagnosticText = QStringLiteral(
                    "KernelCallbackTable为空；目标进程可能尚未加载User32。");
                CloseHandle(processHandle);
                kDeliverResult();
                return;
            }
            if ((callbackTableAddress % pointerSize) != 0U)
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QStringLiteral("KernelCallbackTable地址未按指针宽度对齐。"));
            }

            MEMORY_BASIC_INFORMATION tableMemoryInfo{};
            const SIZE_T kTableQuerySize = VirtualQueryEx(
                processHandle,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(callbackTableAddress)),
                &tableMemoryInfo,
                sizeof(tableMemoryInfo));
            if (kTableQuerySize != sizeof(tableMemoryInfo) ||
                tableMemoryInfo.State != MEM_COMMIT ||
                (tableMemoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0U)
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QStringLiteral("KernelCallbackTable所在内存区域不可安全读取。"));
                CloseHandle(processHandle);
                kDeliverResult();
                return;
            }

            const ks::process::ProcessModuleSnapshot kModuleSnapshot =
                ks::process::enumerateProcessModulesAndThreads(kPidValue, false);
            if (!kModuleSnapshot.diagnosticText.empty())
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QString::fromStdString(kModuleSnapshot.diagnosticText));
            }

            std::size_t trailingUnusableCount = 0;
            bool oldTableBoundaryDetected = false;
            for (std::size_t index = 0; index < std::size(kKernelCallbackNames); ++index)
            {
                KernelCallbackInspectItem row{};
                row.index = static_cast<std::uint32_t>(index);
                row.callbackName = QString::fromLatin1(kKernelCallbackNames[index]);
                row.moduleText = QStringLiteral("-");
                row.moduleOffsetText = QStringLiteral("-");
                row.protectionText = QStringLiteral("-");

                const std::uint64_t kEntryAddress =
                    callbackTableAddress + static_cast<std::uint64_t>(index * pointerSize);
                std::uint64_t callbackAddress = 0;
                bool entryReadOk = false;
                if (pointerSize == sizeof(std::uint32_t))
                {
                    std::uint32_t callbackAddress32 = 0;
                    entryReadOk = readRemoteStructure(processHandle, kEntryAddress, callbackAddress32);
                    callbackAddress = static_cast<std::uint64_t>(callbackAddress32);
                }
                else
                {
                    entryReadOk = readRemoteStructure(processHandle, kEntryAddress, callbackAddress);
                }

                bool plausibleCallback = false;
                if (!entryReadOk)
                {
                    row.addressText = QStringLiteral("-");
                    row.statusText = QStringLiteral("读取失败");
                    row.suspicious = true;
                }
                else if (callbackAddress == 0U)
                {
                    row.addressText = uint64ToHex(0);
                    row.statusText = QStringLiteral("空");
                    row.suspicious = true;
                }
                else
                {
                    row.addressText = uint64ToHex(callbackAddress);
                    MEMORY_BASIC_INFORMATION callbackMemoryInfo{};
                    const SIZE_T kCallbackQuerySize = VirtualQueryEx(
                        processHandle,
                        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(callbackAddress)),
                        &callbackMemoryInfo,
                        sizeof(callbackMemoryInfo));
                    if (kCallbackQuerySize != sizeof(callbackMemoryInfo))
                    {
                        row.statusText = QStringLiteral("地址不可查询");
                        row.suspicious = true;
                    }
                    else
                    {
                        row.protectionText = memoryProtectToText(callbackMemoryInfo.Protect);
                        const bool kCommitted = callbackMemoryInfo.State == MEM_COMMIT;
                        const bool kGuarded =
                            (callbackMemoryInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0U;
                        const bool kExecutable =
                            kCommitted && !kGuarded &&
                            isExecutableMemoryProtection(callbackMemoryInfo.Protect);

                        bool moduleMatched = false;
                        for (const ks::process::ProcessModuleRecord& moduleRecord : kModuleSnapshot.modules)
                        {
                            if (moduleRecord.moduleBaseAddress == 0U ||
                                moduleRecord.moduleSizeBytes == 0U ||
                                callbackAddress < moduleRecord.moduleBaseAddress)
                            {
                                continue;
                            }
                            const std::uint64_t kModuleOffset =
                                callbackAddress - moduleRecord.moduleBaseAddress;
                            if (kModuleOffset >= static_cast<std::uint64_t>(moduleRecord.moduleSizeBytes))
                            {
                                continue;
                            }

                            row.modulePath = QString::fromStdString(moduleRecord.modulePath);
                            row.moduleText = QString::fromStdString(moduleRecord.moduleName).trimmed();
                            if (row.moduleText.isEmpty())
                            {
                                row.moduleText = QFileInfo(row.modulePath).fileName();
                            }
                            row.moduleOffsetText = uint64ToHex(kModuleOffset);
                            moduleMatched = true;
                            break;
                        }

                        plausibleCallback = kExecutable;
                        if (!kCommitted)
                        {
                            row.statusText = QStringLiteral("未提交");
                            row.suspicious = true;
                        }
                        else if (!kExecutable && moduleMatched)
                        {
                            row.statusText = QStringLiteral("模块内非可执行地址");
                            row.suspicious = true;
                        }
                        else if (!kExecutable)
                        {
                            row.statusText = QStringLiteral("非模块且不可执行");
                            row.suspicious = true;
                        }
                        else if (!moduleMatched)
                        {
                            row.statusText = QStringLiteral("非模块可执行内存");
                            row.suspicious = true;
                        }
                        else
                        {
                            row.statusText = QStringLiteral("正常");
                        }
                    }
                }

                refreshResult.rows.push_back(std::move(row));
                if (plausibleCallback)
                {
                    trailingUnusableCount = 0;
                }
                else
                {
                    ++trailingUnusableCount;
                }

                if ((index + 1U) >= kKernelCallbackMinimumProbeCount &&
                    trailingUnusableCount >= kKernelCallbackBoundaryRunLength)
                {
                    refreshResult.rows.resize(
                        refreshResult.rows.size() - trailingUnusableCount);
                    oldTableBoundaryDetected = true;
                    break;
                }
            }

            if (oldTableBoundaryDetected)
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QStringLiteral("检测到连续不可用尾项，已按目标系统实际表长截断。"));
            }
            if (refreshResult.rows.empty())
            {
                appendPebDiagnostic(
                    refreshResult.diagnosticText,
                    QStringLiteral("未识别到可用的内核回调表条目。"));
            }

            CloseHandle(processHandle);
            kDeliverResult();
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyKernelCallbackRefreshResult(
    const KernelCallbackRefreshResult& refreshResult)
{
    kernelCallbackRefreshing_ = false;
    if (refreshKernelCallbackButton_ != nullptr)
    {
        refreshKernelCallbackButton_->setEnabled(true);
    }

    kernelCallbackRows_ = refreshResult.rows;
    rebuildKernelCallbackTable();

    const std::size_t kSuspiciousCount = static_cast<std::size_t>(std::count_if(
        kernelCallbackRows_.cbegin(),
        kernelCallbackRows_.cend(),
        [](const KernelCallbackInspectItem& row)
        {
            return row.suspicious;
        }));

    if (kernelCallbackStatusLabel_ != nullptr)
    {
        QString statusText = QStringLiteral("● 刷新完成 %1 ms | %2 | PEB:%3 | 表:%4 | 条目:%5 | 异常:%6")
            .arg(refreshResult.elapsedMs)
            .arg(refreshResult.pebKindText.isEmpty() ? QStringLiteral("未知PEB") : refreshResult.pebKindText)
            .arg(refreshResult.pebAddressText.isEmpty() ? QStringLiteral("-") : refreshResult.pebAddressText)
            .arg(refreshResult.tableAddressText.isEmpty() ? QStringLiteral("-") : refreshResult.tableAddressText)
            .arg(kernelCallbackRows_.size())
            .arg(kSuspiciousCount);
        QColor statusColor = kSuspiciousCount > 0U ? statusWarningColor() : statusIdleColor();
        if (!refreshResult.diagnosticText.trimmed().isEmpty())
        {
            statusText += QStringLiteral(
                " | 存在诊断；详情已写入日志。");
            statusColor = kernelCallbackRows_.empty() ? statusErrorColor() : statusWarningColor();
        }
        kernelCallbackStatusLabel_->setText(statusText);
        kernelCallbackStatusLabel_->setStyleSheet(buildStateLabelStyle(statusColor, 700));
    }

    kPro.set(kernelCallbackRefreshProgressPid_, "内核回调表读取完成", 0, 100.0f);

    KLogEvent event;
    info << event
        << "[ProcessDetailWindow] applyKernelCallbackRefreshResult: pid="
        << baseRecord_.pid
        << ", rows="
        << kernelCallbackRows_.size()
        << ", suspicious="
        << kSuspiciousCount
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::rebuildKernelCallbackTable()
{
    if (kernelCallbackTable_ == nullptr)
    {
        return;
    }

    const bool kSortingEnabled = kernelCallbackTable_->isSortingEnabled();
    kernelCallbackTable_->setSortingEnabled(false);
    kernelCallbackTable_->clearContents();
    kernelCallbackTable_->setRowCount(static_cast<int>(kernelCallbackRows_.size()));

    for (int rowIndex = 0; rowIndex < static_cast<int>(kernelCallbackRows_.size()); ++rowIndex)
    {
        const KernelCallbackInspectItem& row = kernelCallbackRows_[static_cast<std::size_t>(rowIndex)];
        auto* indexItem = new QTableWidgetItem();
        indexItem->setData(Qt::DisplayRole, row.index);
        auto* nameItem = new QTableWidgetItem(row.callbackName);
        auto* addressItem = new QTableWidgetItem(row.addressText);
        auto* moduleItem = new QTableWidgetItem(row.moduleText);
        auto* moduleOffsetItem = new QTableWidgetItem(row.moduleOffsetText);
        auto* protectionItem = new QTableWidgetItem(row.protectionText);
        auto* statusItem = new QTableWidgetItem(row.statusText);
        if (!row.modulePath.isEmpty())
        {
            moduleItem->setToolTip(row.modulePath);
        }

        QTableWidgetItem* items[] =
        {
            indexItem,
            nameItem,
            addressItem,
            moduleItem,
            moduleOffsetItem,
            protectionItem,
            statusItem
        };
        for (int columnIndex = 0; columnIndex < static_cast<int>(std::size(items)); ++columnIndex)
        {
            if (row.suspicious)
            {
                items[columnIndex]->setForeground(statusWarningColor());
            }
            kernelCallbackTable_->setItem(rowIndex, columnIndex, items[columnIndex]);
        }
    }

    kernelCallbackTable_->setSortingEnabled(kSortingEnabled);
}

void ProcessDetailWindow::requestAsyncPebRefresh()
{
    // PEB page async refresh:
    // - Display PEB address, priority, affinity, memory, and I/O counts.
    // - Additionally output a summary of virtual address space statistics.
    if (pebRefreshing_ || baseRecord_.pid == 0)
    {
        return;
    }

    // PEB/address space scanning is performed only when the user enters the page or manually refreshes.
    pebInitialRefreshStarted_ = true;

    {
        KLogEvent event;
        info << event
            << "[ProcessDetailWindow] requestAsyncPebRefresh: 开始异步刷新, pid="
            << baseRecord_.pid
            << eol;
    }

    pebRefreshing_ = true;
    const std::uint64_t kTicketValue = ++pebRefreshTicket_;
    if (refreshPebButton_ != nullptr)
    {
        refreshPebButton_->setEnabled(false);
    }
    if (pebStatusLabel_ != nullptr)
    {
        pebStatusLabel_->setText(QStringLiteral("● 正在刷新PEB..."));
        pebStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }

    if (pebRefreshProgressPid_ == 0)
    {
        pebRefreshProgressPid_ = kPro.addReusable(this, "进程详情", "刷新PEB信息");
    }
    kPro.set(pebRefreshProgressPid_, "读取PEB与地址空间", 0, 20.0f);

    const std::uint32_t kPidValue = baseRecord_.pid;
    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, kPidValue, kTicketValue]()
        {
            TextRefreshResult refreshResult{};
            const auto kBeginTime = std::chrono::steady_clock::now();
            const auto kProgressDispatcher = [guardThis, kTicketValue](const QString& stepText, const float progressValue)
                {
                    QMetaObject::invokeMethod(
                        guardThis,
                        [guardThis, kTicketValue, stepText, progressValue]()
                        {
                            if (guardThis == nullptr || guardThis->pebRefreshTicket_ != kTicketValue)
                            {
                                return;
                            }
                            if (guardThis->pebRefreshProgressPid_ != 0)
                            {
                                kPro.set(
                                    guardThis->pebRefreshProgressPid_,
                                    stepText.toStdString(),
                                    0,
                                    progressValue);
                            }
                        },
                        Qt::QueuedConnection);
                };

            kProgressDispatcher(QStringLiteral("打开目标进程"), 28.0f);
            std::wostringstream textBuilder;
            textBuilder << L"[PEB / Process Summary]\n";
            textBuilder << L"PID: " << kPidValue << L"\n";

            HANDLE processHandle = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE,
                kPidValue);
            if (processHandle == nullptr)
            {
                processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, kPidValue);
            }
            if (processHandle == nullptr)
            {
                refreshResult.diagnosticText = QString("OpenProcess失败(%1)").arg(GetLastError());
                textBuilder << L"OpenProcess: <failed>\n";
                kProgressDispatcher(QStringLiteral("打开进程失败"), 100.0f);
            }
            else
            {
                kProgressDispatcher(QStringLiteral("读取PEB与基础信息"), 40.0f);
                PROCESS_BASIC_INFORMATION basicInfo{};
                HMODULE ntdllModule = GetModuleHandleW(L"ntdll.dll");
                NtQueryInformationProcessFn ntQueryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
                    ntdllModule != nullptr ? GetProcAddress(ntdllModule, "NtQueryInformationProcess") : nullptr);
                if (ntQueryProcess != nullptr)
                {
                    NTSTATUS basicStatus = ntQueryProcess(
                        processHandle,
                        static_cast<ULONG>(ProcessBasicInformation),
                        &basicInfo,
                        static_cast<ULONG>(sizeof(basicInfo)),
                        nullptr);
                    if (NT_SUCCESS(basicStatus))
                    {
                        textBuilder << L"PEB Address: "
                            << uint64ToHex(reinterpret_cast<std::uint64_t>(basicInfo.PebBaseAddress)).toStdWString()
                            << L"\n";
                    }
                }

                // Command-line read:
                // Prefer ProcessCommandLineInformation;
                // - Fallback to cached m_baseRecord.commandLine on failure.
                const QString kCommandLineText = queryCommandLineTextByNt(ntQueryProcess, processHandle);
                textBuilder << L"CommandLine: "
                    << (kCommandLineText.trimmed().isEmpty()
                        ? L"-"
                        : kCommandLineText.toStdWString())
                    << L"\n";

                // Current directory:
                // - The current directory at the Nt layer is unstable across different system structure layouts.
                // - Here, the 'image directory' is provided first as a stable and readily available approximation.
                QString imagePathText = QString::fromStdString(ks::process::queryProcessPathByPid(kPidValue));
                QString currentDirectoryText;
                if (!imagePathText.trimmed().isEmpty())
                {
                    currentDirectoryText = QFileInfo(imagePathText).absolutePath();
                }
                textBuilder << L"CurrentDirectory(approx): "
                    << (currentDirectoryText.trimmed().isEmpty()
                        ? L"-"
                        : currentDirectoryText.toStdWString())
                    << L"\n";

                ULONG_PTR processAffinityMask = 0;
                ULONG_PTR systemAffinityMask = 0;
                if (GetProcessAffinityMask(processHandle, &processAffinityMask, &systemAffinityMask) != FALSE)
                {
                    textBuilder << L"ProcessAffinity: " << uint64ToHex(processAffinityMask).toStdWString() << L"\n";
                    std::wostringstream coreTextBuilder;
                    bool firstCore = true;
                    for (int bitIndex = 0; bitIndex < static_cast<int>(sizeof(ULONG_PTR) * 8); ++bitIndex)
                    {
                        const ULONG_PTR kMask = static_cast<ULONG_PTR>(1ULL) << bitIndex;
                        if ((processAffinityMask & kMask) == 0)
                        {
                            continue;
                        }
                        if (!firstCore)
                        {
                            coreTextBuilder << L",";
                        }
                        coreTextBuilder << bitIndex;
                        firstCore = false;
                    }
                    textBuilder << L"CpuCoreAffinity: " << coreTextBuilder.str() << L"\n";
                }

                const DWORD kPriorityClass = GetPriorityClass(processHandle);
                textBuilder << L"PriorityClass: " << describePriorityClass(kPriorityClass).toStdWString() << L"\n";

                // Wow64 status:
                // - Output the current process machine architecture and the Wow64 guest architecture.
                USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                if (IsWow64Process2(processHandle, &processMachine, &nativeMachine) != FALSE)
                {
                    textBuilder << L"Wow64ProcessMachine: 0x"
                        << QString::number(processMachine, 16).toUpper().toStdWString()
                        << L"\n";
                    textBuilder << L"Wow64NativeMachine: 0x"
                        << QString::number(nativeMachine, 16).toUpper().toStdWString()
                        << L"\n";
                }

                // Start time and CPU time (kernel + user).
                FILETIME creationTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};
                if (GetProcessTimes(
                    processHandle,
                    &creationTime,
                    &exitTime,
                    &kernelTime,
                    &userTime) != FALSE)
                {
                    ULARGE_INTEGER kernelValue{};
                    kernelValue.LowPart = kernelTime.dwLowDateTime;
                    kernelValue.HighPart = kernelTime.dwHighDateTime;
                    ULARGE_INTEGER userValue{};
                    userValue.LowPart = userTime.dwLowDateTime;
                    userValue.HighPart = userTime.dwHighDateTime;
                    const double kKernelMs = static_cast<double>(kernelValue.QuadPart) / 10000.0;
                    const double kUserMs = static_cast<double>(userValue.QuadPart) / 10000.0;
                    textBuilder << L"KernelCpuMs: " << kKernelMs << L"\n";
                    textBuilder << L"UserCpuMs: " << kUserMs << L"\n";
                }

                PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
                if (GetProcessMemoryInfo(
                    processHandle,
                    reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&memoryCounters),
                    sizeof(memoryCounters)) != FALSE)
                {
                    textBuilder << L"WorkingSet: " << memoryCounters.WorkingSetSize << L" bytes\n";
                    textBuilder << L"PrivateUsage: " << memoryCounters.PrivateUsage << L" bytes\n";
                    textBuilder << L"PeakWorkingSet: " << memoryCounters.PeakWorkingSetSize << L" bytes\n";
                    textBuilder << L"QuotaPagedPool: " << memoryCounters.QuotaPagedPoolUsage << L" bytes\n";
                    textBuilder << L"QuotaNonPagedPool: " << memoryCounters.QuotaNonPagedPoolUsage << L" bytes\n";
                    textBuilder << L"PageFaultCount: " << memoryCounters.PageFaultCount << L"\n";
                }

                IO_COUNTERS ioCounters{};
                if (GetProcessIoCounters(processHandle, &ioCounters) != FALSE)
                {
                    textBuilder << L"ReadOps: " << ioCounters.ReadOperationCount << L"\n";
                    textBuilder << L"WriteOps: " << ioCounters.WriteOperationCount << L"\n";
                    textBuilder << L"ReadBytes: " << ioCounters.ReadTransferCount << L"\n";
                    textBuilder << L"WriteBytes: " << ioCounters.WriteTransferCount << L"\n";
                }

                kProgressDispatcher(QStringLiteral("解析PEB参数块"), 55.0f);

                // Subsystem information: ProcessSubsystemInformation (when available).
                if (ntQueryProcess != nullptr)
                {
                    ULONG subsystemInfo = 0;
                    if (queryNtProcessInfoFixed(
                        ntQueryProcess,
                        processHandle,
                        kProcessInfoClassSubsystem,
                        subsystemInfo))
                    {
                        textBuilder << L"SubsystemInformation: " << subsystemInfo << L"\n";
                    }
                }

                // PEB parameter block parsing:
                // - Read Native PEB in 64-bit layout;
                // - Reads the Wow64 PEB using 32-bit layout to prevent offset misalignment for 32-bit processes in 64-bit tools.
                QString pebDiagnosticText;
                std::vector<RemotePebProcessParametersRead> pebReadList;
                if (basicInfo.PebBaseAddress != nullptr)
                {
                    pebReadList.push_back(readPebProcessParameters64(
                        processHandle,
                        reinterpret_cast<std::uint64_t>(basicInfo.PebBaseAddress),
                        QStringLiteral("NativePEB")));
                }
                else
                {
                    appendPebDiagnostic(pebDiagnosticText, QStringLiteral("ProcessBasicInformation 未返回 PEB 地址。"));
                }

                ULONG_PTR wow64PebAddress = 0;
                if (ntQueryProcess != nullptr &&
                    queryNtProcessInfoFixed(
                        ntQueryProcess,
                        processHandle,
                        kProcessInfoClassWow64Information,
                        wow64PebAddress) &&
                    wow64PebAddress != 0 &&
                    wow64PebAddress != reinterpret_cast<ULONG_PTR>(basicInfo.PebBaseAddress))
                {
                    pebReadList.push_back(readPebProcessParameters32(
                        processHandle,
                        static_cast<std::uint64_t>(wow64PebAddress),
                        QStringLiteral("Wow64PEB")));
                }

                std::uint64_t imageBaseAddress = 0;
                for (const RemotePebProcessParametersRead& pebRead : pebReadList)
                {
                    if (!pebRead.readOk)
                    {
                        appendPebDiagnostic(
                            pebDiagnosticText,
                            QStringLiteral("%1: %2")
                            .arg(pebRead.labelText)
                            .arg(pebRead.diagnosticText));
                        continue;
                    }

                    textBuilder << L"["
                        << pebRead.labelText.toStdWString()
                        << L"]\n";
                    textBuilder << L"  PebAddress: "
                        << uint64ToHex(pebRead.pebAddress).toStdWString()
                        << L"\n";
                    textBuilder << L"  ProcessParameters: "
                        << uint64ToHex(pebRead.processParametersAddress).toStdWString()
                        << L"\n";
                    textBuilder << L"  ImageBaseAddress: "
                        << uint64ToHex(pebRead.imageBaseAddress).toStdWString()
                        << L"\n";
                    textBuilder << L"  Environment: "
                        << uint64ToHex(pebRead.environmentAddress).toStdWString()
                        << L"\n";

                    if (!pebRead.commandLineText.trimmed().isEmpty())
                    {
                        textBuilder << L"CommandLine("
                            << pebRead.labelText.toStdWString()
                            << L"): "
                            << pebRead.commandLineText.toStdWString()
                            << L"\n";
                    }
                    if (!pebRead.imagePathText.trimmed().isEmpty())
                    {
                        imagePathText = pebRead.imagePathText;
                        textBuilder << L"ImagePath("
                            << pebRead.labelText.toStdWString()
                            << L"): "
                            << pebRead.imagePathText.toStdWString()
                            << L"\n";
                    }
                    if (!pebRead.currentDirectoryText.trimmed().isEmpty())
                    {
                        currentDirectoryText = pebRead.currentDirectoryText;
                        textBuilder << L"CurrentDirectory("
                            << pebRead.labelText.toStdWString()
                            << L"): "
                            << pebRead.currentDirectoryText.toStdWString()
                            << L"\n";
                    }
                    if (imageBaseAddress == 0 && pebRead.imageBaseAddress != 0)
                    {
                        imageBaseAddress = pebRead.imageBaseAddress;
                    }
                }

                if (!pebDiagnosticText.trimmed().isEmpty())
                {
                    appendPebDiagnostic(refreshResult.diagnosticText, pebDiagnosticText);
                }

                // Image entry point:
                // - Prefer PEB.ImageBaseAddress to avoid ToolHelp module snapshots blocking on certain processes.
                // - Only reads the PE header; does not enumerate the module list.
                kProgressDispatcher(QStringLiteral("解析映像入口点"), 60.0f);
                if (imageBaseAddress != 0)
                {
                    textBuilder << L"ImageBaseAddress: "
                        << uint64ToHex(imageBaseAddress).toStdWString()
                        << L"\n";
                    IMAGE_DOS_HEADER dosHeader{};
                    SIZE_T bytesRead = 0;
                    if (ReadProcessMemory(
                        processHandle,
                        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(imageBaseAddress)),
                        &dosHeader,
                        sizeof(dosHeader),
                        &bytesRead) != FALSE &&
                        bytesRead == sizeof(dosHeader) &&
                        dosHeader.e_magic == IMAGE_DOS_SIGNATURE &&
                        dosHeader.e_lfanew > 0 &&
                        dosHeader.e_lfanew < 0x100000)
                    {
                        IMAGE_NT_HEADERS64 ntHeader64{};
                        if (ReadProcessMemory(
                            processHandle,
                            reinterpret_cast<LPCVOID>(
                                static_cast<std::uintptr_t>(
                                    imageBaseAddress + static_cast<std::uint64_t>(dosHeader.e_lfanew))),
                            &ntHeader64,
                            sizeof(ntHeader64),
                            &bytesRead) != FALSE &&
                            bytesRead >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + sizeof(WORD) &&
                            ntHeader64.Signature == IMAGE_NT_SIGNATURE)
                        {
                            const WORD kOptionalMagic = ntHeader64.OptionalHeader.Magic;
                            if (kOptionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
                                kOptionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                            {
                                const std::uint32_t kEntryRva = ntHeader64.OptionalHeader.AddressOfEntryPoint;
                                textBuilder << L"EntryPointRva: 0x"
                                    << QString::number(kEntryRva, 16).toUpper().toStdWString()
                                    << L"\n";
                                textBuilder << L"EntryPointAddress: "
                                    << uint64ToHex(imageBaseAddress + kEntryRva).toStdWString()
                                    << L"\n";
                            }
                        }
                    }
                }
                else
                {
                    appendPebDiagnostic(refreshResult.diagnosticText, QStringLiteral("PEB 未提供可用映像基址。"));
                }

                // Environment variable block preview:
                // - Select the first environment address from the successfully parsed PEB parameter block;
                // - Read in chunks with a 128KB limit to prevent background tasks from hanging when the environment block is corrupted.
                kProgressDispatcher(QStringLiteral("读取环境变量预览"), 64.0f);
                bool environmentPreviewOk = false;
                for (const RemotePebProcessParametersRead& pebRead : pebReadList)
                {
                    if (!pebRead.readOk || pebRead.environmentAddress == 0)
                    {
                        continue;
                    }

                    QString environmentDiagnosticText;
                    const QStringList kEnvironmentLines = readRemoteEnvironmentPreviewLines(
                        processHandle,
                        pebRead.environmentAddress,
                        &environmentDiagnosticText);
                    if (!environmentDiagnosticText.trimmed().isEmpty())
                    {
                        appendPebDiagnostic(refreshResult.diagnosticText, environmentDiagnosticText);
                    }
                    if (kEnvironmentLines.isEmpty())
                    {
                        continue;
                    }

                    environmentPreviewOk = true;
                    textBuilder << L"[EnvironmentPreview:"
                        << pebRead.labelText.toStdWString()
                        << L"]\n";
                    for (const QString& lineText : kEnvironmentLines)
                    {
                        textBuilder << L"  " << lineText.toStdWString() << L"\n";
                    }
                    break;
                }
                if (!environmentPreviewOk)
                {
                    textBuilder << L"[EnvironmentPreview]\n";
                    textBuilder << L"  <unavailable>\n";
                }

                SYSTEM_INFO systemInfo{};
                GetSystemInfo(&systemInfo);
                MEMORY_BASIC_INFORMATION memoryInfo{};
                std::uint64_t commitBytes = 0;
                std::uint64_t mappedBytes = 0;
                std::uint64_t imageBytes = 0;
                std::uint64_t privateBytes = 0;
                std::uint64_t regionCount = 0;
                std::uint64_t previewRegionCount = 0;
                constexpr std::uint64_t kMaxRegionScanCount = 60000;
                const std::uintptr_t kMinAddress =
                    reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
                const std::uintptr_t kMaxAddress =
                    reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
                std::uintptr_t cursorAddress = kMinAddress;
                bool regionScanTruncated = false;
                bool regionScanTimeout = false;
                const auto kRegionScanDeadline = kBeginTime + std::chrono::seconds(8);

                kProgressDispatcher(QStringLiteral("扫描虚拟地址空间"), 68.0f);
                textBuilder << L"[VirtualAddressRegionPreview]\n";
                while (cursorAddress < kMaxAddress)
                {
                    if (std::chrono::steady_clock::now() > kRegionScanDeadline)
                    {
                        regionScanTimeout = true;
                        break;
                    }

                    const SIZE_T kQuerySize = VirtualQueryEx(
                        processHandle,
                        reinterpret_cast<LPCVOID>(cursorAddress),
                        &memoryInfo,
                        sizeof(memoryInfo));
                    if (kQuerySize == 0)
                    {
                        break;
                    }
                    if (memoryInfo.RegionSize == 0)
                    {
                        appendPebDiagnostic(
                            refreshResult.diagnosticText,
                            QStringLiteral("虚拟内存枚举遇到零长度区域，已提前终止。"));
                        break;
                    }

                    ++regionCount;
                    if (regionCount >= kMaxRegionScanCount)
                    {
                        regionScanTruncated = true;
                        break;
                    }

                    if ((regionCount % 2000) == 0)
                    {
                        const float kProgressValue = std::min(
                            90.0f,
                            60.0f + static_cast<float>(regionCount) * 0.0005f);
                        kProgressDispatcher(QStringLiteral("扫描虚拟地址空间"), kProgressValue);
                    }

                    if (memoryInfo.State == MEM_COMMIT)
                    {
                        commitBytes += static_cast<std::uint64_t>(memoryInfo.RegionSize);
                    }
                    if (memoryInfo.Type == MEM_MAPPED)
                    {
                        mappedBytes += static_cast<std::uint64_t>(memoryInfo.RegionSize);
                    }
                    if (memoryInfo.Type == MEM_IMAGE)
                    {
                        imageBytes += static_cast<std::uint64_t>(memoryInfo.RegionSize);
                    }
                    if (memoryInfo.Type == MEM_PRIVATE)
                    {
                        privateBytes += static_cast<std::uint64_t>(memoryInfo.RegionSize);
                    }

                    // Preview output: lists up to 40 committed regions, including their state, protection, type, and mapped file.
                    if (memoryInfo.State == MEM_COMMIT && previewRegionCount < 40)
                    {
                        QString mappedPathText;
                        wchar_t mappedPathBuffer[1024] = {};
                        if ((memoryInfo.Type == MEM_MAPPED || memoryInfo.Type == MEM_IMAGE) &&
                            GetMappedFileNameW(
                                processHandle,
                                memoryInfo.BaseAddress,
                                mappedPathBuffer,
                                static_cast<DWORD>(std::size(mappedPathBuffer))) > 0)
                        {
                            mappedPathText = QString::fromWCharArray(mappedPathBuffer);
                        }

                        const std::uint64_t kBaseAddress = reinterpret_cast<std::uint64_t>(memoryInfo.BaseAddress);
                        const std::uint64_t kEndAddress = kBaseAddress + static_cast<std::uint64_t>(memoryInfo.RegionSize);
                        textBuilder << L"  "
                            << uint64ToHex(kBaseAddress).toStdWString()
                            << L"-"
                            << uint64ToHex(kEndAddress).toStdWString()
                            << L" | "
                            << memoryStateToText(memoryInfo.State).toStdWString()
                            << L" | "
                            << memoryProtectToText(memoryInfo.Protect).toStdWString()
                            << L" | "
                            << memoryTypeToText(memoryInfo.Type).toStdWString();
                        if (!mappedPathText.trimmed().isEmpty())
                        {
                            textBuilder << L" | " << mappedPathText.toStdWString();
                        }
                        textBuilder << L"\n";
                        ++previewRegionCount;
                    }

                    const std::uintptr_t kNextAddress =
                        cursorAddress + static_cast<std::uintptr_t>(memoryInfo.RegionSize);
                    if (kNextAddress <= cursorAddress)
                    {
                        appendPebDiagnostic(
                            refreshResult.diagnosticText,
                            QStringLiteral("虚拟内存枚举地址发生回绕，已提前终止。"));
                        break;
                    }
                    cursorAddress = kNextAddress;
                }
                if (regionScanTruncated)
                {
                    appendPebDiagnostic(
                        refreshResult.diagnosticText,
                        QString("虚拟内存枚举达到上限(%1)，结果为部分数据。")
                        .arg(kMaxRegionScanCount));
                }
                if (regionScanTimeout)
                {
                    appendPebDiagnostic(
                        refreshResult.diagnosticText,
                        QStringLiteral("虚拟内存枚举超过8秒，已返回部分结果。"));
                }
                textBuilder << L"RegionCount: " << regionCount << L"\n";
                textBuilder << L"CommitBytes: " << commitBytes << L"\n";
                textBuilder << L"MappedBytes: " << mappedBytes << L"\n";
                textBuilder << L"ImageBytes: " << imageBytes << L"\n";
                textBuilder << L"PrivateBytes: " << privateBytes << L"\n";

                // Heap info: Only count HeapList quantity.
                // - The legacy implementation continues to call Heap32First/Heap32Next to iterate through all heap blocks.
                // - These APIs may block internally for a long time in large processes, protected processes, or heap corruption scenarios;
                // - The primary goal of the PEB page is to parse ProcessParameters and the environment block, so we actively skip the full enumeration of heap blocks here.
                kProgressDispatcher(QStringLiteral("跳过堆块枚举"), 90.0f);
                textBuilder << L"HeapCount: <skipped>\n";
                textBuilder << L"HeapBlockCount: <skipped>\n";
                textBuilder << L"HeapBlockEnumeration: <skipped to keep PEB refresh bounded>\n";

                kProgressDispatcher(QStringLiteral("汇总PEB结果"), 95.0f);

                CloseHandle(processHandle);
            }

            if (!refreshResult.diagnosticText.trimmed().isEmpty())
            {
                textBuilder << L"[Diagnostic]\n";
                textBuilder << L"  " << refreshResult.diagnosticText.toStdWString() << L"\n";
            }

            refreshResult.detailText = QString::fromStdWString(textBuilder.str());
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, refreshResult, kTicketValue]()
                {
                    if (guardThis == nullptr || guardThis->pebRefreshTicket_ != kTicketValue)
                    {
                        return;
                    }
                    guardThis->applyPebRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyTokenRefreshResult(const TextRefreshResult& refreshResult)
{
    tokenRefreshing_ = false;
    if (refreshTokenButton_ != nullptr)
    {
        refreshTokenButton_->setEnabled(true);
    }
    if (tokenDetailOutput_ != nullptr)
    {
        tokenDetailOutput_->setText(refreshResult.detailText);
    }
    if (tokenStatusLabel_ != nullptr)
    {
        tokenStatusLabel_->setText(QString("● 刷新完成 %1 ms").arg(refreshResult.elapsedMs));
        tokenStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
    }
    kPro.set(tokenRefreshProgressPid_, "令牌信息刷新完成", 0, 100.0f);
}

void ProcessDetailWindow::applyPebRefreshResult(const TextRefreshResult& refreshResult)
{
    pebRefreshing_ = false;
    if (refreshPebButton_ != nullptr)
    {
        refreshPebButton_->setEnabled(true);
    }
    if (pebDetailOutput_ != nullptr)
    {
        pebDetailOutput_->setText(refreshResult.detailText);
    }
    populatePebEditableFieldsFromText(refreshResult.detailText);
    if (pebStatusLabel_ != nullptr)
    {
        QString statusText = QString("● 刷新完成 %1 ms").arg(refreshResult.elapsedMs);
        QString statusStyle = buildStateLabelStyle(statusIdleColor(), 600);
        if (!refreshResult.diagnosticText.trimmed().isEmpty())
        {
            statusText += QStringLiteral(
                " | 存在诊断；详情已写入日志。");
            statusStyle = buildStateLabelStyle(statusWarningColor(), 700);
        }
        pebStatusLabel_->setText(statusText);
        pebStatusLabel_->setStyleSheet(statusStyle);
    }
    kPro.set(pebRefreshProgressPid_, "PEB信息刷新完成", 0, 100.0f);

    KLogEvent event;
    info << event
        << "[ProcessDetailWindow] applyPebRefreshResult: 完成, pid="
        << baseRecord_.pid
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::applyPebEditableFields()
{
    // PEB editable field application:
    // - Write to the UNICODE_STRING field within RTL_USER_PROCESS_PARAMETERS.
    // - Environment variables are completed by replacing the Environment pointer to point to a new environment block.
    // - Affinity and priority use Win32 APIs, representing real process attributes rather than PEB fields.
    if (baseRecord_.pid == 0)
    {
        QMessageBox::warning(this, QStringLiteral("PEB 修改"), QStringLiteral("PID 为 0，不能修改。"));
        return;
    }

    const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
        this,
        QStringLiteral("确认修改远程 PEB"),
        QStringLiteral(
            "即将写入目标进程的 PEB/ProcessParameters 或修改进程运行属性。\n\n"
            "错误的 CommandLine/ImagePath/CurrentDirectory/ImageBaseAddress 可能导致目标进程自身逻辑或第三方工具误判。\n"
            "建议只对测试进程执行。是否继续？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmButton != QMessageBox::Yes)
    {
        return;
    }

    const QString kTargetName = (pebTargetCombo_ != nullptr)
        ? pebTargetCombo_->currentData().toString()
        : QStringLiteral("NativePEB");
    QStringList resultLines;
    int successCount = 0;
    int failCount = 0;
    int skipCount = 0;

    HANDLE processHandle = OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_SET_INFORMATION,
        FALSE,
        baseRecord_.pid);
    if (processHandle == nullptr)
    {
        const DWORD kErrorCode = GetLastError();
        // privilegePromptHandled: Records whether the privilege recovery entry point has fully handled the OpenProcess failure.
        const bool kPrivilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("修改远程进程 PEB"), kErrorCode);
        if (!kPrivilegePromptHandled)
        {
            QMessageBox::critical(
                this,
                QStringLiteral("PEB 修改失败"),
                QStringLiteral("OpenProcess失败：%1").arg(kErrorCode));
        }
        return;
    }

    PebEditTargetSnapshot targetSnapshot = queryPebEditTargetSnapshot(processHandle, kTargetName);
    if (!targetSnapshot.valid)
    {
        CloseHandle(processHandle);
        QMessageBox::critical(
            this,
            QStringLiteral("PEB 修改失败"),
            QStringLiteral("%1不可用：%2").arg(kTargetName, targetSnapshot.errorText));
        return;
    }

    const auto kAppendApplyResult = [&resultLines, &successCount, &failCount, &skipCount](
        const QString& fieldName,
        const bool attempted,
        const bool success,
        const QString& detailText)
        {
            if (!attempted)
            {
                ++skipCount;
                resultLines << QStringLiteral("[跳过] %1：%2").arg(fieldName, detailText);
                return;
            }
            if (success)
            {
                ++successCount;
                resultLines << QStringLiteral("[成功] %1：%2").arg(fieldName, detailText);
            }
            else
            {
                ++failCount;
                resultLines << QStringLiteral("[失败] %1：%2").arg(fieldName, detailText);
            }
        };

    const auto kApplyStringField = [&](const QString& fieldName, const QString& inputText) {
        if (inputText.isEmpty())
        {
            kAppendApplyResult(fieldName, false, false, QStringLiteral("输入为空。"));
            return;
        }

        QString currentText;
        std::uint64_t descriptorAddress = 0;
        QString errorText;
        bool writeOk = false;
        if (targetSnapshot.isWow64Target)
        {
            RemoteUnicodeString32 descriptor{};
            if (fieldName == QStringLiteral("CommandLine"))
            {
                descriptor = targetSnapshot.params32.commandLine;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters32Lite, commandLine);
            }
            else if (fieldName == QStringLiteral("ImagePathName"))
            {
                descriptor = targetSnapshot.params32.imagePathName;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters32Lite, imagePathName);
            }
            else
            {
                descriptor = targetSnapshot.params32.currentDirectory.dosPath;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters32Lite, currentDirectory) +
                    offsetof(Curdir32, dosPath);
            }
            currentText = readRemoteUnicodeString32(processHandle, descriptor);
            if (currentText == inputText)
            {
                kAppendApplyResult(fieldName, false, false, QStringLiteral("未变化。"));
                return;
            }
            writeOk = updateRemoteUnicodeString32(
                processHandle,
                descriptorAddress,
                descriptor,
                inputText,
                &errorText);
        }
        else
        {
            UNICODE_STRING descriptor{};
            if (fieldName == QStringLiteral("CommandLine"))
            {
                descriptor = targetSnapshot.params64.commandLine;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters64Lite, commandLine);
            }
            else if (fieldName == QStringLiteral("ImagePathName"))
            {
                descriptor = targetSnapshot.params64.imagePathName;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters64Lite, imagePathName);
            }
            else
            {
                descriptor = targetSnapshot.params64.currentDirectory.dosPath;
                descriptorAddress = targetSnapshot.processParametersAddress +
                    offsetof(RtlUserProcessParameters64Lite, currentDirectory) +
                    offsetof(Curdir64, dosPath);
            }
            currentText = readRemoteUnicodeString64(processHandle, descriptor);
            if (currentText == inputText)
            {
                kAppendApplyResult(fieldName, false, false, QStringLiteral("未变化。"));
                return;
            }
            writeOk = updateRemoteUnicodeString64(
                processHandle,
                descriptorAddress,
                descriptor,
                inputText,
                &errorText);
        }

        kAppendApplyResult(
            fieldName,
            true,
            writeOk,
            writeOk
                ? QStringLiteral("已写入 %1 字符。").arg(inputText.size())
                : errorText);
    };

    if (pebCommandLineEdit_ != nullptr)
    {
        kApplyStringField(QStringLiteral("CommandLine"), pebCommandLineEdit_->text());
    }
    if (pebImagePathEdit_ != nullptr)
    {
        kApplyStringField(QStringLiteral("ImagePathName"), pebImagePathEdit_->text());
    }
    if (pebCurrentDirectoryEdit_ != nullptr)
    {
        kApplyStringField(QStringLiteral("CurrentDirectory"), pebCurrentDirectoryEdit_->text());
    }

    if (pebEnvironmentNameEdit_ != nullptr && !pebEnvironmentNameEdit_->text().trimmed().isEmpty())
    {
        QString errorText;
        const bool kEnvOk = updateRemoteEnvironmentVariable(
            processHandle,
            targetSnapshot,
            pebEnvironmentNameEdit_->text(),
            (pebEnvironmentValueEdit_ != nullptr) ? pebEnvironmentValueEdit_->text() : QString(),
            &errorText);
        kAppendApplyResult(
            QStringLiteral("Environment"),
            true,
            kEnvOk,
            kEnvOk
                ? QStringLiteral("已新增/替换 %1。").arg(pebEnvironmentNameEdit_->text().trimmed())
                : errorText);
    }
    else
    {
        kAppendApplyResult(QStringLiteral("Environment"), false, false, QStringLiteral("未填写变量名。"));
    }

    if (pebImageBaseEdit_ != nullptr && !pebImageBaseEdit_->text().trimmed().isEmpty())
    {
        std::uint64_t imageBaseValue = 0;
        if (!parseUnsignedIntegerText(pebImageBaseEdit_->text(), imageBaseValue))
        {
            kAppendApplyResult(QStringLiteral("ImageBaseAddress"), true, false, QStringLiteral("数值格式无效。"));
        }
        else if (imageBaseValue == targetSnapshot.imageBaseAddress)
        {
            kAppendApplyResult(QStringLiteral("ImageBaseAddress"), false, false, QStringLiteral("未变化。"));
        }
        else
        {
            QString errorText;
            const bool kImageBaseOk = updatePebImageBaseAddress(
                processHandle,
                targetSnapshot,
                imageBaseValue,
                &errorText);
            kAppendApplyResult(
                QStringLiteral("ImageBaseAddress"),
                true,
                kImageBaseOk,
                kImageBaseOk ? QStringLiteral("已写入 %1。").arg(uint64ToHex(imageBaseValue)) : errorText);
        }
    }
    else
    {
        kAppendApplyResult(QStringLiteral("ImageBaseAddress"), false, false, QStringLiteral("输入为空。"));
    }

    if (pebAffinityMaskEdit_ != nullptr && !pebAffinityMaskEdit_->text().trimmed().isEmpty())
    {
        std::uint64_t affinityValue = 0;
        if (!parseUnsignedIntegerText(pebAffinityMaskEdit_->text(), affinityValue) || affinityValue == 0)
        {
            kAppendApplyResult(QStringLiteral("AffinityMask"), true, false, QStringLiteral("亲和性掩码格式无效或为0。"));
        }
        else
        {
            ULONG_PTR processAffinity = 0;
            ULONG_PTR systemAffinity = 0;
            const bool kQueryAffinityOk = GetProcessAffinityMask(processHandle, &processAffinity, &systemAffinity) != FALSE;
            if (kQueryAffinityOk && static_cast<std::uint64_t>(processAffinity) == affinityValue)
            {
                kAppendApplyResult(QStringLiteral("AffinityMask"), false, false, QStringLiteral("未变化。"));
            }
            else if (affinityValue > static_cast<std::uint64_t>(std::numeric_limits<ULONG_PTR>::max()))
            {
                kAppendApplyResult(QStringLiteral("AffinityMask"), true, false, QStringLiteral("掩码超过当前进程位宽。"));
            }
            else if (SetProcessAffinityMask(processHandle, static_cast<ULONG_PTR>(affinityValue)) == FALSE)
            {
                kAppendApplyResult(
                    QStringLiteral("AffinityMask"),
                    true,
                    false,
                    QStringLiteral("SetProcessAffinityMask失败(%1)。").arg(GetLastError()));
            }
            else
            {
                kAppendApplyResult(
                    QStringLiteral("AffinityMask"),
                    true,
                    true,
                    QStringLiteral("已设置为 %1。").arg(uint64ToHex(affinityValue)));
            }
        }
    }
    else
    {
        kAppendApplyResult(QStringLiteral("AffinityMask"), false, false, QStringLiteral("输入为空。"));
    }

    if (pebPriorityClassCombo_ != nullptr)
    {
        const DWORD kPriorityClass = static_cast<DWORD>(pebPriorityClassCombo_->currentData().toUInt());
        if (kPriorityClass == 0)
        {
            kAppendApplyResult(QStringLiteral("PriorityClass"), false, false, QStringLiteral("选择为不修改。"));
        }
        else
        {
            const DWORD kCurrentPriority = GetPriorityClass(processHandle);
            if (kCurrentPriority == kPriorityClass)
            {
                kAppendApplyResult(QStringLiteral("PriorityClass"), false, false, QStringLiteral("未变化。"));
            }
            else if (SetPriorityClass(processHandle, kPriorityClass) == FALSE)
            {
                kAppendApplyResult(
                    QStringLiteral("PriorityClass"),
                    true,
                    false,
                    QStringLiteral("SetPriorityClass失败(%1)。").arg(GetLastError()));
            }
            else
            {
                kAppendApplyResult(
                    QStringLiteral("PriorityClass"),
                    true,
                    true,
                    QStringLiteral("已设置为 %1。").arg(describePriorityClass(kPriorityClass)));
            }
        }
    }

    CloseHandle(processHandle);

    const QString kSummaryText = QStringLiteral("成功 %1，失败 %2，跳过 %3")
        .arg(successCount)
        .arg(failCount)
        .arg(skipCount);
    if (pebStatusLabel_ != nullptr)
    {
        pebStatusLabel_->setText(QStringLiteral("● PEB修改完成：%1").arg(kSummaryText));
        pebStatusLabel_->setStyleSheet(buildStateLabelStyle(
            failCount == 0 ? statusIdleColor() : statusWarningColor(),
            700));
    }

    QMessageBox::information(
        this,
        QStringLiteral("PEB 修改结果"),
        kSummaryText + QStringLiteral("\n\n") + resultLines.join('\n'));
    requestAsyncPebRefresh();
}

void ProcessDetailWindow::populatePebEditableFieldsFromText(const QString& detailText)
{
    // PEB edit area auto-fill:
    // - Extract string fields of the currently selected PEB from the refresh text;
    // - For numeric fields, prefer global ProcessAffinity/PriorityClass/ImageBaseAddress;
    // - Only update the editor content without triggering any remote writes.
    if (detailText.trimmed().isEmpty())
    {
        return;
    }

    const QString kTargetName = (pebTargetCombo_ != nullptr)
        ? pebTargetCombo_->currentData().toString()
        : QStringLiteral("NativePEB");
    const QString kEscapedTarget = QRegularExpression::escape(kTargetName);

    const auto kCaptureSingleLine = [&detailText](const QString& patternText) -> QString
        {
            const QRegularExpression kPattern(
                patternText,
                QRegularExpression::MultilineOption);
            const QRegularExpressionMatch kMatch = kPattern.match(detailText);
            if (!kMatch.hasMatch())
            {
                return QString();
            }
            return kMatch.captured(1).trimmed();
        };

    const QString kCommandLineText = kCaptureSingleLine(
        QStringLiteral("^CommandLine\\(%1\\):\\s*(.*)$").arg(kEscapedTarget));
    const QString kImagePathText = kCaptureSingleLine(
        QStringLiteral("^ImagePath\\(%1\\):\\s*(.*)$").arg(kEscapedTarget));
    const QString kCurrentDirectoryText = kCaptureSingleLine(
        QStringLiteral("^CurrentDirectory\\(%1\\):\\s*(.*)$").arg(kEscapedTarget));
    const QString kImageBaseText = kCaptureSingleLine(
        QStringLiteral("^\\s*ImageBaseAddress:\\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\\s*$"));
    const QString kAffinityText = kCaptureSingleLine(
        QStringLiteral("^ProcessAffinity:\\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\\s*$"));
    const QString kPriorityText = kCaptureSingleLine(QStringLiteral("^PriorityClass:\\s*([^\\r\\n]+)\\s*$"));

    if (pebCommandLineEdit_ != nullptr)
    {
        pebCommandLineEdit_->setText(kCommandLineText);
    }
    if (pebImagePathEdit_ != nullptr)
    {
        pebImagePathEdit_->setText(kImagePathText);
    }
    if (pebCurrentDirectoryEdit_ != nullptr)
    {
        pebCurrentDirectoryEdit_->setText(kCurrentDirectoryText);
    }
    if (pebImageBaseEdit_ != nullptr && !kImageBaseText.isEmpty())
    {
        pebImageBaseEdit_->setText(kImageBaseText);
    }
    if (pebAffinityMaskEdit_ != nullptr && !kAffinityText.isEmpty())
    {
        pebAffinityMaskEdit_->setText(kAffinityText);
    }
    if (pebPriorityClassCombo_ != nullptr && !kPriorityText.isEmpty())
    {
        const QString kNormalizedPriority = kPriorityText.section('(', 0, 0).trimmed();
        for (int index = 0; index < pebPriorityClassCombo_->count(); ++index)
        {
            if (pebPriorityClassCombo_->itemText(index).compare(kNormalizedPriority, Qt::CaseInsensitive) == 0)
            {
                pebPriorityClassCombo_->setCurrentIndex(index);
                break;
            }
        }
    }
}

void ProcessDetailWindow::requestAsyncSectionRefresh()
{
    // Section/ControlArea query entry:
    // - Do not pass m_baseRecord.r0SectionObjectAddress to the driver;
    // - Driver-side re-queries EPROCESS.SectionObject based on PID to prevent diagnostic addresses from becoming credentials.
    if (sectionInfoRefreshing_)
    {
        return;
    }
    if (baseRecord_.pid == 0)
    {
        return;
    }

    // Section/ControlArea queries depend on driver IOCTLs; use the initial refresh flag to avoid triggering duplicates on page switches.
    sectionInfoInitialRefreshStarted_ = true;

    sectionInfoRefreshing_ = true;
    ++sectionInfoRefreshTicket_;
    const std::uint64_t kTicketValue = sectionInfoRefreshTicket_;
    const std::uint32_t kProcessId = baseRecord_.pid;
    QPointer<ProcessDetailWindow> guardThis(this);
    if (refreshSectionInfoButton_ != nullptr)
    {
        refreshSectionInfoButton_->setEnabled(false);
    }
    if (sectionInfoStatusLabel_ != nullptr)
    {
        sectionInfoStatusLabel_->setText(QStringLiteral("● 正在查询 Section/ControlArea..."));
        sectionInfoStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }

    // KProgress currently exposes only the add/set two-phase interface:
    // - add creates a task card and returns the task ID;
    // - set the refresh step text and progress; the 100% completion triggers automatic hiding.
    if (sectionInfoRefreshProgressPid_ == 0)
    {
        sectionInfoRefreshProgressPid_ = kPro.addReusable(this, "进程详情", "查询 Section/ControlArea");
    }
    kPro.set(sectionInfoRefreshProgressPid_, QStringLiteral("查询 PID=%1 的 Section/ControlArea").arg(kProcessId).toStdString(), 0, 5.0f);

    auto* refreshTask = QRunnable::create(
        [guardThis, kTicketValue, kProcessId]()
        {
            const auto kBeginTime = std::chrono::steady_clock::now();
            SectionRefreshResult refreshResult{};
            std::wstringstream textBuilder;
            const ksword::ark::DriverClient kDriverClient;

            const ksword::ark::ProcessRuntimeDetailResult kProcessDetailResult =
                kDriverClient.queryProcessRuntimeDetail(kProcessId);
            const ksword::ark::DynDataStatusResult kDynDataStatusResult =
                kDriverClient.queryDynDataStatus();
            QString deepIdentityGuardText;
            bool deepIdentityMatched = false;
            if (kDynDataStatusResult.io.ok)
            {
                deepIdentityMatched = pdbRuntimeCatalogMatchesKernelIdentity(
                    kDynDataStatusResult.ntoskrnl.timeDateStamp,
                    kDynDataStatusResult.ntoskrnl.sizeOfImage,
                    &deepIdentityGuardText);
            }
            else
            {
                const QString kReadableDynDataMessage = readableRuntimeIoMessage(
                    QString::fromStdString(kDynDataStatusResult.io.message),
                    QStringLiteral("DynData状态"),
                    QStringLiteral("DynData status 查询没有返回额外说明。"),
                    false);
                deepIdentityGuardText = QStringLiteral(
                    "[PDB Deep Runtime Identity Guard]\n"
                    "结论: 不匹配，跳过只读采样\n"
                    "原因: DynData status 查询不可用，无法校验 deep offset 与当前内核 identity。%1")
                    .arg(kReadableDynDataMessage);
            }
            const std::vector<ksword::ark::RuntimeFieldSampleRequestItem> kProcessSampleItems =
                deepIdentityMatched
                ? buildPdbRuntimeSampleItems(QStringLiteral("process_detail"), 64)
                : std::vector<ksword::ark::RuntimeFieldSampleRequestItem>{};
            const ksword::ark::RuntimeFieldSampleResult kProcessSampleResult = (!deepIdentityMatched || kProcessSampleItems.empty())
                ? ksword::ark::RuntimeFieldSampleResult{}
                : kDriverClient.queryProcessRuntimeFieldSamples(kProcessId, kProcessSampleItems);
            const auto kSectionResult = kDriverClient.queryProcessSection(
                kProcessId,
                KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL,
                KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);

            const auto kStatusHex = [](const long status) -> QString
                {
                    return QStringLiteral("0x%1")
                        .arg(static_cast<quint32>(status), 8, 16, QChar('0'))
                        .toUpper();
                };
            const auto kSectionStatusText = [](const std::uint32_t statusValue) -> QString
                {
                    switch (statusValue)
                    {
                    case KSWORD_ARK_SECTION_QUERY_STATUS_OK:
                        return QStringLiteral("OK");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_PARTIAL:
                        return QStringLiteral("Partial");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_DYNDATA_MISSING:
                        return QStringLiteral("DynData Missing");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_PROCESS_LOOKUP_FAILED:
                        return QStringLiteral("Process Lookup Failed");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_SECTION_OBJECT_MISSING:
                        return QStringLiteral("SectionObject Missing");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_CONTROL_AREA_MISSING:
                        return QStringLiteral("ControlArea Missing");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_REMOTE_UNSUPPORTED:
                        return QStringLiteral("Remote Mapping Unsupported");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED:
                        return QStringLiteral("Mapping Query Failed");
                    case KSWORD_ARK_SECTION_QUERY_STATUS_BUFFER_TOO_SMALL:
                        return QStringLiteral("Buffer Too Small");
                    default:
                        return QStringLiteral("Unavailable");
                    }
                };
            const auto kMappingTypeText = [](const std::uint32_t typeValue) -> QString
                {
                    switch (typeValue)
                    {
                    case KSWORD_ARK_SECTION_MAP_TYPE_PROCESS:
                        return QStringLiteral("Process");
                    case KSWORD_ARK_SECTION_MAP_TYPE_SESSION:
                        return QStringLiteral("Session");
                    case KSWORD_ARK_SECTION_MAP_TYPE_SYSTEM_CACHE:
                        return QStringLiteral("SystemCache");
                    default:
                        return QStringLiteral("Unknown");
                    }
                };

            textBuilder << L"[R0 Process Runtime Detail]\n";
            if (kProcessDetailResult.io.ok)
            {
                const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& processDetail =
                    kProcessDetailResult.response;
                textBuilder << L"Status: "
                    << runtimeDetailStatusText(processDetail.status).toStdWString()
                    << L"\n";
                textBuilder << L"PID/Image: "
                    << processDetail.processId
                    << L" / "
                    << fixedRuntimeImageName(
                        processDetail.imageName,
                        KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS).toStdWString()
                    << L"\n";
                textBuilder << L"Object/UniqueProcessId: "
                    << uint64ToHex(processDetail.processObjectAddress).toStdWString()
                    << L" / "
                    << uint64ToHex(processDetail.uniqueProcessIdValue).toStdWString()
                    << L"\n";
                textBuilder << L"ActiveProcessLinks: Flink="
                    << uint64ToHex(processDetail.activeProcessLinksFlink).toStdWString()
                    << L", Blink="
                    << uint64ToHex(processDetail.activeProcessLinksBlink).toStdWString()
                    << L"\n";
                textBuilder << L"ThreadListHead: Flink="
                    << uint64ToHex(processDetail.threadListHeadFlink).toStdWString()
                    << L", Blink="
                    << uint64ToHex(processDetail.threadListHeadBlink).toStdWString()
                    << L"\n";
                textBuilder << L"ObjectTable/SectionObject: "
                    << uint64ToHex(processDetail.objectTableAddress).toStdWString()
                    << L" / "
                    << uint64ToHex(processDetail.sectionObjectAddress).toStdWString()
                    << L"\n";
                textBuilder << L"TokenFastRef/TokenObject: "
                    << uint64ToHex(processDetail.tokenFastRef).toStdWString()
                    << L" / "
                    << uint64ToHex(processDetail.tokenObjectAddress).toStdWString()
                    << L"\n";
                textBuilder << L"Protection/Signature/SectionSignature: 0x"
                    << QStringLiteral("%1")
                        .arg(static_cast<unsigned int>(processDetail.protection), 2, 16, QChar('0'))
                        .toUpper().toStdWString()
                    << L" / 0x"
                    << QStringLiteral("%1")
                        .arg(static_cast<unsigned int>(processDetail.signatureLevel), 2, 16, QChar('0'))
                        .toUpper().toStdWString()
                    << L" / 0x"
                    << QStringLiteral("%1")
                        .arg(static_cast<unsigned int>(processDetail.sectionSignatureLevel), 2, 16, QChar('0'))
                        .toUpper().toStdWString()
                    << L"\n";
                textBuilder << L"已采集字段: "
                    << processRuntimeFieldListText(processDetail.fieldFlags).toStdWString()
                    << L"\n";
                textBuilder << L"Offsets: UniquePid="
                    << uint64ToHex(processDetail.offsets.epUniqueProcessId).toStdWString()
                    << L", ActiveLinks="
                    << uint64ToHex(processDetail.offsets.epActiveProcessLinks).toStdWString()
                    << L", ThreadList="
                    << uint64ToHex(processDetail.offsets.epThreadListHead).toStdWString()
                    << L", ImageFileName="
                    << uint64ToHex(processDetail.offsets.epImageFileName).toStdWString()
                    << L", Token="
                    << uint64ToHex(processDetail.offsets.epToken).toStdWString()
                    << L", ObjectTable="
                    << uint64ToHex(processDetail.offsets.epObjectTable).toStdWString()
                    << L", SectionObject="
                    << uint64ToHex(processDetail.offsets.epSectionObject).toStdWString()
                    << L"\n";
                textBuilder << L"OffsetSources: "
                    << processRuntimeOffsetSourceText(processDetail).toStdWString()
                    << L"\n";
                textBuilder << L"KernelGlobals: "
                    << runtimeKernelGlobalsText(processDetail.kernelGlobals).toStdWString()
                    << L"\n";
                textBuilder << L"DynData已具备能力: "
                    << runtimeCapabilityMaskText(processDetail.dynDataCapabilityMask, false).toStdWString()
                    << L"\n";
                textBuilder << L"DynData缺失能力: "
                    << runtimeCapabilityMaskText(processDetail.missingCapabilityMask, true).toStdWString()
                    << L"\n";
                textBuilder << L"LastStatus: "
                    << ntStatusHexText(processDetail.lastStatus).toStdWString()
                    << L"\n";
                textBuilder << L"说明: "
                    << runtimeSamplingSummaryText(
                        fixedRuntimeWideText(
                            processDetail.detail,
                            KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS),
                        QStringLiteral("进程")).toStdWString()
                    << L"\n\n";
            }
            else
            {
                const QString kRawMessage =
                    QString::fromStdString(kProcessDetailResult.io.message).trimmed();
                const QString kReadableMessage = readableRuntimeIoMessage(
                    kRawMessage,
                    QStringLiteral("进程详情"),
                    QStringLiteral("进程 runtime detail 暂不可用。"),
                    kProcessDetailResult.unsupported);
                textBuilder << L"Status: unavailable\n";
                textBuilder << L"说明: " << kReadableMessage.toStdWString() << L"\n\n";
            }

            textBuilder << L"[PDB Deep Runtime Sample - process_detail]\n";
            textBuilder << deepIdentityGuardText.toStdWString() << L"\n";
            if (!deepIdentityMatched)
            {
                textBuilder << L"deep catalog identity 未与当前 ntoskrnl 匹配，已跳过 R0 字段采样，避免错误偏移。\n\n";
            }
            else if (kProcessSampleItems.empty())
            {
                textBuilder << L"PDB deep offset JSON 未提供可安全采样的小字段，或 profiles\\pdb_deep_offsets 未找到。\n\n";
            }
            else
            {
                textBuilder << runtimeFieldSampleResultText(
                    kProcessSampleResult,
                    QStringLiteral("进程 PDB deep 字段采样")).toStdWString()
                    << L"\n\n";
            }

            textBuilder << L"[PDB Deep Runtime Catalog - process_detail]\n"
                << buildPdbRuntimeCatalogPreview(QStringLiteral("process_detail"), 64, 1024).toStdWString()
                << L"\n\n";
            textBuilder << L"[PDB Deep Runtime Catalog - thread_detail]\n"
                << buildPdbRuntimeCatalogPreview(QStringLiteral("thread_detail"), 64, 1024).toStdWString()
                << L"\n\n";

            // Append a broader PDB deep offset domain:
            // - Input: handle/module/memory/ipc/callback/common domains pre-generated in bulk within the ntkrnlmp deep JSON.
            // Processing: Display only the directory preview without issuing additional R0 calls or expanding the current query's privilege scope.
            // - Returns: Writes to the CodeEditorWidget text so the process detail page can directly see the backup offset library, not just a summary.
            const auto kAppendDeepCatalogPreviewDomain =
                [&textBuilder](const QString& domainName, const QString& titleText)
            {
                textBuilder << L"[PDB Deep Runtime Catalog - "
                    << titleText.toStdWString()
                    << L"]\n"
                    << buildPdbRuntimeCatalogPreview(domainName, 32, 256).toStdWString()
                    << L"\n\n";
            };
            kAppendDeepCatalogPreviewDomain(QStringLiteral("handle_object_detail"), QStringLiteral("handle_object_detail"));
            kAppendDeepCatalogPreviewDomain(QStringLiteral("memory_section_detail"), QStringLiteral("memory_section_detail"));
            kAppendDeepCatalogPreviewDomain(QStringLiteral("module_driver_detail"), QStringLiteral("module_driver_detail"));
            kAppendDeepCatalogPreviewDomain(QStringLiteral("ipc_alpc_detail"), QStringLiteral("ipc_alpc_detail"));
            kAppendDeepCatalogPreviewDomain(QStringLiteral("callback_registry_security"), QStringLiteral("callback_registry_security"));
            kAppendDeepCatalogPreviewDomain(QStringLiteral("common_kernel_primitives"), QStringLiteral("common_kernel_primitives"));
            kAppendDeepCatalogPreviewDomain(QStringLiteral("kernel_global_detail"), QStringLiteral("kernel_global_detail"));

            const QString kRawSectionIoMessage =
                QString::fromStdString(kSectionResult.io.message).trimmed();
            const QString kReadableSectionIoMessage = readableRuntimeIoMessage(
                kRawSectionIoMessage,
                QStringLiteral("Section/ControlArea"),
                QStringLiteral("无额外驱动消息。"),
                false);

            textBuilder << L"[R0 Section Query]\n";
            textBuilder << L"IO说明: " << kReadableSectionIoMessage.toStdWString() << L"\n";
            if (!kSectionResult.io.ok)
            {
                refreshResult.diagnosticText = kReadableSectionIoMessage;
            }
            else
            {
                textBuilder << L"Status: " << kSectionStatusText(kSectionResult.queryStatus).toStdWString() << L"\n";
                textBuilder << L"LastStatus: " << kStatusHex(kSectionResult.lastStatus).toStdWString() << L"\n";
                textBuilder << L"FieldFlags: " << uint64ToHex(kSectionResult.fieldFlags).toStdWString() << L"\n";
                textBuilder << L"DynDataCapability: " << uint64ToHex(kSectionResult.dynDataCapabilityMask).toStdWString() << L"\n";
                textBuilder << L"SectionObject: " << uint64ToHex(kSectionResult.sectionObjectAddress).toStdWString() << L"\n";
                textBuilder << L"ControlArea: " << uint64ToHex(kSectionResult.controlAreaAddress).toStdWString() << L"\n";
                textBuilder << L"EpSectionObjectOffset: " << uint64ToHex(kSectionResult.epSectionObjectOffset).toStdWString() << L"\n";
                textBuilder << L"MmSectionControlAreaOffset: " << uint64ToHex(kSectionResult.mmSectionControlAreaOffset).toStdWString() << L"\n";
                textBuilder << L"MmControlAreaListHeadOffset: " << uint64ToHex(kSectionResult.mmControlAreaListHeadOffset).toStdWString() << L"\n";
                textBuilder << L"MmControlAreaLockOffset: " << uint64ToHex(kSectionResult.mmControlAreaLockOffset).toStdWString() << L"\n";
                textBuilder << L"Mappings: total=" << kSectionResult.totalCount
                    << L", returned=" << kSectionResult.returnedCount
                    << L", parsed=" << kSectionResult.mappings.size() << L"\n";

                if ((kSectionResult.fieldFlags & KSWORD_ARK_SECTION_FIELD_REMOTE_MAPPING_UNSUPPORTED) != 0U)
                {
                    textBuilder << L"RemoteMapping: unsupported by current ControlArea marker\n";
                }
                if ((kSectionResult.fieldFlags & KSWORD_ARK_SECTION_FIELD_MAPPING_TRUNCATED) != 0U)
                {
                    textBuilder << L"MappingList: truncated\n";
                }

                textBuilder << L"[Mappings]\n";
                if (kSectionResult.mappings.empty())
                {
                    textBuilder << L"  <empty or unavailable>\n";
                }
                else
                {
                    for (const auto& mappingEntry : kSectionResult.mappings)
                    {
                        textBuilder << L"  "
                            << kMappingTypeText(mappingEntry.viewMapType).toStdWString()
                            << L" | PID=" << mappingEntry.processId
                            << L" | "
                            << uint64ToHex(mappingEntry.startVa).toStdWString()
                            << L"-"
                            << uint64ToHex(mappingEntry.endVa).toStdWString()
                            << L"\n";
                    }
                }
            }

            refreshResult.detailText = QString::fromStdWString(textBuilder.str());
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - kBeginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, refreshResult, kTicketValue]()
                {
                    if (guardThis == nullptr || guardThis->sectionInfoRefreshTicket_ != kTicketValue)
                    {
                        return;
                    }
                    guardThis->applySectionRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applySectionRefreshResult(const SectionRefreshResult& refreshResult)
{
    sectionInfoRefreshing_ = false;
    if (refreshSectionInfoButton_ != nullptr)
    {
        refreshSectionInfoButton_->setEnabled(true);
    }
    if (sectionInfoOutput_ != nullptr)
    {
        sectionInfoOutput_->setText(refreshResult.detailText);
    }
    if (sectionInfoStatusLabel_ != nullptr)
    {
        QString statusText = QStringLiteral("● 刷新完成 %1 ms").arg(refreshResult.elapsedMs);
        QString statusStyle = buildStateLabelStyle(statusIdleColor(), 600);
        if (!refreshResult.diagnosticText.trimmed().isEmpty())
        {
            statusText += QStringLiteral(
                " | 存在诊断；详情已写入日志。");
            statusStyle = buildStateLabelStyle(statusWarningColor(), 700);
            KLogEvent diagnosticEvent;
            warn << diagnosticEvent
                << "[ProcessDetailWindow] section refresh completed with diagnostics, pid="
                << baseRecord_.pid
                << ", diagnostic="
                << refreshResult.diagnosticText.toStdString()
                << eol;
        }
        sectionInfoStatusLabel_->setText(statusText);
        sectionInfoStatusLabel_->setStyleSheet(statusStyle);
    }
    kPro.set(sectionInfoRefreshProgressPid_, "Section/ControlArea 查询完成", 0, 100.0f);
}
