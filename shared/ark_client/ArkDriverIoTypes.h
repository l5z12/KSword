#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>


namespace ksword::ark
{
    // IoResult is the common outcome for every KswordARK driver operation.
    // ok mirrors the Win32 DeviceIoControl success bit, win32Error preserves
    // GetLastError(), ntStatus is filled only when a response packet carries it.
    struct IoResult
    {
        bool ok = false;
        unsigned long win32Error = ERROR_SUCCESS;
        long ntStatus = 0;
        std::string message;
        unsigned long bytesReturned = 0;
    };

    // DriverHandle owns one KswordARK control-device handle. It is move-only so
    // UI code can cache handles without duplicating close responsibility.
    class DriverHandle
    {
    public:
        DriverHandle() noexcept = default;
        explicit DriverHandle(HANDLE handleValue) noexcept;
        ~DriverHandle();

        DriverHandle(const DriverHandle&) = delete;
        DriverHandle& operator=(const DriverHandle&) = delete;
        DriverHandle(DriverHandle&& other) noexcept;
        DriverHandle& operator=(DriverHandle&& other) noexcept;

        bool isValid() const noexcept;
        HANDLE native() const noexcept;
        HANDLE release() noexcept;
        void reset(HANDLE newHandle = INVALID_HANDLE_VALUE) noexcept;

    private:
        HANDLE handle_ = INVALID_HANDLE_VALUE;
    };

    // VariableAuditResultBase: Stores the IO status shared by all newly added read-only audit wrappers.
    // Input: Populated by ArkDriverAudit.cpp when parsing METHOD_BUFFERED responses.
    // Handling: unsupported distinguishes between unregistered IOCTLs in older drivers and protocol parsing failures.
    // Return behavior: The struct itself has no function return; the caller reads fields to display the R0 audit status.
    struct VariableAuditResultBase
    {
        IoResult io;                         // io: Result of the underlying DeviceIoControl and protocol parsing.
        bool unsupported = false;            // unsupported: True if the old driver lacks this IOCTL or explicitly returns unsupported.
        std::uint32_t version = 0;           // version: Shared protocol version.
        std::uint32_t status = 0;            // status: Overall status defined by the protocol.
        std::uint32_t flags = 0;             // flags: Response-level flags or query flags.
        std::uint32_t totalCount = 0;        // totalCount: Total rows observed at R0.
        std::uint32_t returnedCount = 0;     // returnedCount: Number of rows written to the output buffer by R0.
        std::uint32_t entrySize = 0;         // entrySize: Size of a single protocol structure row.
        long lastStatus = 0;                 // lastStatus: The most recent NTSTATUS from R0.
    };

    // AsyncIoResult reports an overlapped DeviceIoControl issue attempt. A false
    // issued value with win32Error==ERROR_IO_PENDING means the request is queued.
    struct AsyncIoResult
    {
        bool issued = false;
        unsigned long win32Error = ERROR_SUCCESS;
        unsigned long bytesReturned = 0;
    };
}
