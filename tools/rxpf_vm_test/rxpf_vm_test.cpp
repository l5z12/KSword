// RXPF test-signing VM harness. Do not run on a production host.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>
#include <string>

#include "../../shared/driver/KswordArkRxPfIoctl.h"

namespace
{
    constexpr wchar_t kDevicePath[] = L"\\\\.\\KswordARKLog";
    constexpr unsigned char kSelfTestCode[] = {
        0x48U, 0xC7U, 0xC0U, 0x78U, 0x56U, 0x34U, 0x12U,
        0x48U, 0x83U, 0xC0U, 0x01U,
        0xC3U
    };

    KSWORD_ARK_RXPF_REQUEST_HEADER makeHeader(
        const unsigned long size,
        const unsigned long extraFlags = 0UL)
    {
        KSWORD_ARK_RXPF_REQUEST_HEADER header{};
        header.version = KSWORD_ARK_RXPF_PROTOCOL_VERSION;
        header.size = size;
        header.flags = KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED | extraFlags;
        header.confirmationToken = KSWORD_ARK_RXPF_CONFIRMATION_TOKEN;
        return header;
    }

    template <typename Request, typename Response>
    bool sendIoctl(
        const HANDLE device,
        const DWORD code,
        const Request& request,
        Response& response,
        const std::string_view operation)
    {
        DWORD returned = 0UL;
        std::memset(&response, 0, sizeof(response));
        const BOOL kOk = ::DeviceIoControl(
            device,
            code,
            const_cast<Request*>(&request),
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)),
            &returned,
            nullptr);
        if (kOk == FALSE)
        {
            std::cerr << "[FAIL] " << operation
                      << ": Win32=" << ::GetLastError() << '\n';
            return false;
        }
        if (returned != sizeof(response))
        {
            std::cerr << "[FAIL] " << operation
                      << ": returned=" << returned
                      << ", expected=" << sizeof(response) << '\n';
            return false;
        }
        std::cout << "[PASS] " << operation << '\n';
        return true;
    }

    bool querySupport(
        const HANDLE device,
        KSWORD_ARK_RXPF_QUERY_SUPPORT_RESPONSE& response)
    {
        const auto kRequest = makeHeader(
            static_cast<unsigned long>(sizeof(KSWORD_ARK_RXPF_REQUEST_HEADER)));
        if (!sendIoctl(
                device,
                IOCTL_KSWORD_ARK_RXPF_QUERY_SUPPORT,
                kRequest,
                response,
                "query support"))
        {
            return false;
        }
        std::cout << "  build=" << response.ntBuildNumber
                  << " timestamp=0x" << std::hex
                  << response.imageTimeDateStamp
                  << " imageSize=0x" << response.imageSize
                  << " checksum=0x" << response.imageCheckSum
                  << " functionRva=0x" << response.functionRva
                  << " flags=0x" << response.supportFlags
                  << std::dec << '\n';
        return true;
    }

    bool unregisterPage(
        const HANDLE device,
        const unsigned long long recordId)
    {
        KSWORD_ARK_RXPF_RECORD_REQUEST request{};
        KSWORD_ARK_RXPF_PAGE_RESPONSE response{};
        request.header = makeHeader(static_cast<unsigned long>(sizeof(request)));
        request.recordId = recordId;
        return sendIoctl(
            device,
            IOCTL_KSWORD_ARK_RXPF_UNREGISTER_PAGE,
            request,
            response,
            "unregister page");
    }

    bool triggerChainedUserFault()
    {
        void* faultPage = ::VirtualAlloc(
            nullptr,
            4096U,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
        DWORD oldProtection = 0UL;
        bool caught = false;

        if (faultPage == nullptr)
        {
            return false;
        }
        if (::VirtualProtect(
                faultPage,
                4096U,
                PAGE_NOACCESS,
                &oldProtection) == FALSE)
        {
            (void)::VirtualFree(faultPage, 0U, MEM_RELEASE);
            return false;
        }
        __try
        {
            const volatile unsigned char kValue =
                *static_cast<volatile unsigned char*>(faultPage);
            (void)kValue;
        }
        __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
            ? EXCEPTION_EXECUTE_HANDLER
            : EXCEPTION_CONTINUE_SEARCH)
        {
            caught = true;
        }
        (void)::VirtualFree(faultPage, 0U, MEM_RELEASE);
        return caught;
    }

    bool exercisePage(
        const HANDLE device,
        const unsigned long targetKind,
        const std::string_view label)
    {
        KSWORD_ARK_RXPF_REGISTER_PAGE_REQUEST registerRequest{};
        KSWORD_ARK_RXPF_PAGE_RESPONSE page{};
        unsigned long long recordId = 0ULL;
        bool passed = true;

        registerRequest.header = makeHeader(
            static_cast<unsigned long>(sizeof(registerRequest)),
            KSWORD_ARK_RXPF_FLAG_CAPTURE_BACKUP);
        registerRequest.targetKind = targetKind;
        registerRequest.targetAddress = 0ULL;
        if (!sendIoctl(
                device,
                IOCTL_KSWORD_ARK_RXPF_REGISTER_PAGE,
                registerRequest,
                page,
                std::string("register ") + std::string(label)))
        {
            return false;
        }
        recordId = page.recordId;

        KSWORD_ARK_RXPF_RECORD_REQUEST recordRequest{};
        recordRequest.header = makeHeader(
            static_cast<unsigned long>(sizeof(recordRequest)));
        recordRequest.recordId = recordId;
        if (!sendIoctl(
                device,
                IOCTL_KSWORD_ARK_RXPF_CHANGE_PAGE,
                recordRequest,
                page,
                "change page to writable/NX"))
        {
            passed = false;
        }
        if (passed &&
            (page.state != KSWORD_ARK_RXPF_PAGE_STATE_RW_NX ||
             page.writableAlias == 0ULL))
        {
            std::cerr << "[FAIL] page did not reach RW/NX with an alias\n";
            passed = false;
        }

        if (passed)
        {
            KSWORD_ARK_RXPF_WRITE_PAGE_REQUEST writeRequest{};
            writeRequest.header = makeHeader(
                static_cast<unsigned long>(sizeof(writeRequest)));
            writeRequest.recordId = recordId;
            writeRequest.offset = 0UL;
            writeRequest.length = static_cast<unsigned long>(sizeof(kSelfTestCode));
            std::memcpy(
                writeRequest.bytes,
                kSelfTestCode,
                sizeof(kSelfTestCode));
            passed = sendIoctl(
                device,
                IOCTL_KSWORD_ARK_RXPF_WRITE_PAGE,
                writeRequest,
                page,
                "write test instructions");
        }

        if (passed)
        {
            KSWORD_ARK_RXPF_SET_EMULATION_REQUEST setRequest{};
            setRequest.header = makeHeader(
                static_cast<unsigned long>(sizeof(setRequest)));
            setRequest.recordId = recordId;
            setRequest.enable = 1UL;
            passed = sendIoctl(
                device,
                IOCTL_KSWORD_ARK_RXPF_SET_EMULATION,
                setRequest,
                page,
                "install shadow IDTs");
            if (passed)
            {
                const bool kEnableStatePassed =
                    page.emulationEnabled == 1UL;
                const bool kChainPassed = triggerChainedUserFault();
                if (!kEnableStatePassed)
                {
                    std::cerr << "[FAIL] emulation enable was not published\n";
                }
                if (!kChainPassed)
                {
                    std::cerr << "[FAIL] user #PF did not chain to Windows SEH\n";
                }
                setRequest.enable = 0UL;
                bool restorePassed = sendIoctl(
                    device,
                    IOCTL_KSWORD_ARK_RXPF_SET_EMULATION,
                    setRequest,
                    page,
                    "restore original IDTs");
                if (restorePassed && page.emulationEnabled != 0UL)
                {
                    std::cerr << "[FAIL] emulation disable was not published\n";
                    restorePassed = false;
                }
                passed = kEnableStatePassed && kChainPassed &&
                    restorePassed;
            }
        }

        if (passed)
        {
            KSWORD_ARK_RXPF_SELF_TEST_RESPONSE selfTest{};
            passed = sendIoctl(
                device,
                IOCTL_KSWORD_ARK_RXPF_RUN_SELF_TEST,
                recordRequest,
                selfTest,
                "run three-instruction #PF self-test");
            if (passed &&
                (selfTest.returnedValue != selfTest.expectedValue ||
                 selfTest.instructionCount == 0UL ||
                 selfTest.faultsObserved != selfTest.instructionCount))
            {
                std::cerr << "[FAIL] self-test values: returned=0x"
                          << std::hex << selfTest.returnedValue
                          << " expected=0x" << selfTest.expectedValue
                          << std::dec << " faults="
                          << selfTest.faultsObserved << '\n';
                passed = false;
            }
        }

        const bool kCleanupPassed = unregisterPage(device, recordId);
        return passed && kCleanupPassed;
    }

    bool queryDiagnostics(const HANDLE device)
    {
        const auto kStatsRequest = makeHeader(
            static_cast<unsigned long>(sizeof(KSWORD_ARK_RXPF_REQUEST_HEADER)));
        KSWORD_ARK_RXPF_STATS_RESPONSE stats{};
        if (!sendIoctl(
                device,
                IOCTL_KSWORD_ARK_RXPF_QUERY_STATS,
                kStatsRequest,
                stats,
                "query statistics"))
        {
            return false;
        }
        std::cout << "  total=" << stats.totalFaults
                  << " managed=" << stats.managedFaults
                  << " emulated=" << stats.emulatedInstructions
                  << " chained=" << stats.chainedFaults
                  << " recursive=" << stats.recursiveFaults
                  << " unsupported=" << stats.unsupportedInstructions
                  << " active=" << stats.activeHandlers << '\n';

        KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST eventRequest{};
        KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE events{};
        eventRequest.header = makeHeader(
            static_cast<unsigned long>(sizeof(eventRequest)));
        eventRequest.afterSequence = 0ULL;
        eventRequest.maxRows = KSWORD_ARK_RXPF_MAX_EVENT_ROWS;
        if (!sendIoctl(
                device,
                IOCTL_KSWORD_ARK_RXPF_DRAIN_EVENTS,
                eventRequest,
                events,
                "drain diagnostic events"))
        {
            return false;
        }
        std::cout << "  eventRows=" << events.returnedRows
                  << " newest=" << events.newestSequence
                  << " dropped=" << events.droppedRows << '\n';
        return true;
    }
}

int wmain(const int argc, wchar_t** argv)
{
    const bool kRunImageTest =
        argc == 2 && std::wstring_view(argv[1]) == L"--self-image";
    const HANDLE kDevice = ::CreateFileW(
        kDevicePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (kDevice == INVALID_HANDLE_VALUE)
    {
        std::cerr << "CreateFileW failed: " << ::GetLastError() << '\n';
        return 2;
    }

    KSWORD_ARK_RXPF_QUERY_SUPPORT_RESPONSE support{};
    bool passed = querySupport(kDevice, support);
    if (passed)
    {
        passed = exercisePage(
            kDevice,
            KSWORD_ARK_RXPF_TARGET_ALLOCATED_TEST,
            "allocated test page");
    }
    if (passed)
    {
        passed = querySupport(kDevice, support) &&
            (support.supportFlags &
                KSWORD_ARK_RXPF_SUPPORT_ALLOCATED_TEST_PASSED) != 0UL;
        if (!passed)
        {
            std::cerr << "[FAIL] allocated-page gate was not published\n";
        }
    }
    if (passed && kRunImageTest)
    {
        const unsigned long kRequired =
            KSWORD_ARK_RXPF_SUPPORT_BUILD_MATCH |
            KSWORD_ARK_RXPF_SUPPORT_ABI_VERIFIED |
            KSWORD_ARK_RXPF_SUPPORT_SELF_IMAGE_TEST_PAGE;
        if ((support.supportFlags & kRequired) != kRequired)
        {
            std::cerr << "[FAIL] exact self-image build profile is unavailable\n";
            passed = false;
        }
        else
        {
            passed = exercisePage(
                kDevice,
                KSWORD_ARK_RXPF_TARGET_SELF_IMAGE_TEST,
                "dedicated self-image page");
        }
    }
    if (passed)
    {
        passed = queryDiagnostics(kDevice);
    }

    ::CloseHandle(kDevice);
    std::cout << (passed ? "RXPF VM test passed\n" : "RXPF VM test failed\n");
    return passed ? 0 : 1;
}
