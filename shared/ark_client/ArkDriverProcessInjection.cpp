#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <utility>
#include <vector>

namespace ksword::ark
{
    using detail::isUnsupportedIoctlError;
    namespace
    {
        std::size_t processInjectRequestHeaderSize()
        {
            return sizeof(KSWORD_ARK_INJECT_PROCESS_REQUEST) - sizeof(unsigned char);
        }

        ProcessInjectResult makeProcessInjectInputFailure(
            const std::uint32_t processId,
            const std::uint32_t injectType,
            const unsigned long win32Error,
            const std::string& message)
        {
            ProcessInjectResult result{};
            result.processId = processId;
            result.injectType = injectType;
            result.io.ok = false;
            result.io.win32Error = win32Error;
            result.io.message = message;
            return result;
        }

        void copyProcessInjectResponse(
            ProcessInjectResult& result,
            const KSWORD_ARK_INJECT_PROCESS_RESPONSE& response)
        {
            result.version = static_cast<std::uint32_t>(response.version);
            result.processId = static_cast<std::uint32_t>(response.processId);
            result.injectType = static_cast<std::uint32_t>(response.injectType);
            result.status = static_cast<std::uint32_t>(response.status);
            result.flags = static_cast<std::uint32_t>(response.flags);
            result.bytesWritten = static_cast<std::uint32_t>(response.bytesWritten);
            result.lastStatus = static_cast<long>(response.lastStatus);
            result.waitStatus = static_cast<long>(response.waitStatus);
            result.entryPointAddress = static_cast<std::uint64_t>(response.entryPointAddress);
            result.parameterAddress = static_cast<std::uint64_t>(response.parameterAddress);
            result.remoteBaseAddress = static_cast<std::uint64_t>(response.remoteBaseAddress);
            result.remoteRegionSize = static_cast<std::uint64_t>(response.remoteRegionSize);
            result.io.ntStatus = result.lastStatus;
        }

        std::string buildProcessInjectMessage(const ProcessInjectResult& result)
        {
            std::ostringstream stream;
            stream << "pid=" << result.processId
                << ", type=" << result.injectType
                << ", status=" << result.status
                << ", flags=0x" << std::hex << std::uppercase << result.flags
                << ", written=" << std::dec << result.bytesWritten
                << ", remote=0x" << std::hex << result.remoteBaseAddress
                << ", region=0x" << result.remoteRegionSize
                << ", entry=0x" << result.entryPointAddress
                << ", param=0x" << result.parameterAddress
                << ", lastStatus=0x" << static_cast<unsigned long>(result.lastStatus)
                << ", waitStatus=0x" << static_cast<unsigned long>(result.waitStatus);
            return stream.str();
        }
    }

    ProcessInjectResult DriverClient::injectProcessDll(
        const std::uint32_t processId,
        const std::wstring& dllPath,
        const unsigned long flags) const
    {
        if (dllPath.empty())
        {
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                ERROR_INVALID_PARAMETER,
                "DLL path is empty");
        }
        if (dllPath.size() + 1U >
            KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES / sizeof(wchar_t))
        {
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                ERROR_BAD_LENGTH,
                "DLL path is larger than R0 inject payload limit");
        }

        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        if (kernel32Module == nullptr)
        {
            const unsigned long kLastError = ::GetLastError();
            const unsigned long kWin32Error = kLastError != ERROR_SUCCESS
                ? kLastError
                : ERROR_MOD_NOT_FOUND;
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                kWin32Error,
                "GetModuleHandleW(kernel32.dll) failed, error=" + std::to_string(kWin32Error));
        }

        FARPROC loadLibraryAddress = ::GetProcAddress(kernel32Module, "LoadLibraryW");
        if (loadLibraryAddress == nullptr)
        {
            const unsigned long kLastError = ::GetLastError();
            const unsigned long kWin32Error = kLastError != ERROR_SUCCESS
                ? kLastError
                : ERROR_PROC_NOT_FOUND;
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                kWin32Error,
                "GetProcAddress(LoadLibraryW) failed, error=" + std::to_string(kWin32Error));
        }

        const std::size_t kPayloadBytes = (dllPath.size() + 1U) * sizeof(wchar_t);
        const std::size_t kHeaderSize = processInjectRequestHeaderSize();
        std::vector<std::uint8_t> requestBuffer(kHeaderSize + kPayloadBytes, 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_INJECT_PROCESS_REQUEST*>(requestBuffer.data());
        request->version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION;
        request->processId = processId;
        request->injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH;
        request->flags = flags;
        request->payloadBytes = static_cast<unsigned long>(kPayloadBytes);
        request->entryPointAddress =
            static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(loadLibraryAddress));
        request->parameterAddress = 0ULL;
        std::memcpy(request->payload, dllPath.c_str(), kPayloadBytes);

        ProcessInjectResult injectResult{};
        KSWORD_ARK_INJECT_PROCESS_RESPONSE response{};
        injectResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_INJECT_PROCESS,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!injectResult.io.ok)
        {
            injectResult.processId = processId;
            injectResult.injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH;
            injectResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_INJECT_PROCESS/DLL) failed, error=" +
                std::to_string(injectResult.io.win32Error);
            return injectResult;
        }
        if (injectResult.io.bytesReturned < sizeof(response))
        {
            injectResult.io.ok = false;
            injectResult.io.message =
                "process inject DLL response too small, bytesReturned=" +
                std::to_string(injectResult.io.bytesReturned);
            return injectResult;
        }

        copyProcessInjectResponse(injectResult, response);
        injectResult.io.message = buildProcessInjectMessage(injectResult);
        return injectResult;
    }

    ProcessInjectResult DriverClient::injectProcessShellcode(
        const std::uint32_t processId,
        const std::vector<std::uint8_t>& shellcode,
        const unsigned long flags) const
    {
        if (shellcode.empty())
        {
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE,
                ERROR_INVALID_PARAMETER,
                "shellcode payload is empty");
        }
        if (shellcode.size() > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES)
        {
            return makeProcessInjectInputFailure(
                processId,
                KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE,
                ERROR_BAD_LENGTH,
                "shellcode payload is larger than R0 inject payload limit");
        }

        const std::size_t kHeaderSize = processInjectRequestHeaderSize();
        std::vector<std::uint8_t> requestBuffer(kHeaderSize + shellcode.size(), 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_INJECT_PROCESS_REQUEST*>(requestBuffer.data());
        request->version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION;
        request->processId = processId;
        request->injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE;
        request->flags = flags;
        request->payloadBytes = static_cast<unsigned long>(shellcode.size());
        request->entryPointAddress = 0ULL;
        request->parameterAddress = 0ULL;
        std::memcpy(request->payload, shellcode.data(), shellcode.size());

        ProcessInjectResult injectResult{};
        KSWORD_ARK_INJECT_PROCESS_RESPONSE response{};
        injectResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_INJECT_PROCESS,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!injectResult.io.ok)
        {
            injectResult.processId = processId;
            injectResult.injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE;
            injectResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_INJECT_PROCESS/SHELLCODE) failed, error=" +
                std::to_string(injectResult.io.win32Error);
            return injectResult;
        }
        if (injectResult.io.bytesReturned < sizeof(response))
        {
            injectResult.io.ok = false;
            injectResult.io.message =
                "process inject shellcode response too small, bytesReturned=" +
                std::to_string(injectResult.io.bytesReturned);
            return injectResult;
        }

        copyProcessInjectResponse(injectResult, response);
        injectResult.io.message = buildProcessInjectMessage(injectResult);
        return injectResult;
    }
}
