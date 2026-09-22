#pragma once

#include <cstdint>
#include <type_traits>

namespace ks::dwm_order
{
    inline constexpr std::uint32_t kProtocolVersion = 3;
    inline constexpr std::uint32_t kMagic = 0x4f5a5744;
    enum class Action : std::uint32_t { kQuery, kApply, kRestore, kStop, kConnect };
    enum class Position : std::uint32_t { kFront, kBack, kBefore, kAfter };
    enum class Status : std::uint32_t
    {
        kOk, kInvalidRequest, kInvalidWindow, kDifferentDesktop, kUnsupportedRuntime,
        kHookConflict, kWindowNotComposed, kNativeFailure, kVerificationFailed,
        kNotRunning, kAgentMismatch, kTransportFailure, kTimeout, kInternalException
    };
    enum ResultFlags : std::uint32_t
    {
        kVerified = 1, kMaintaining = 2, kHooksInstalled = 4, kRestored = 8
    };

    struct WindowIdentity
    {
        std::uint64_t hwnd = 0;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint64_t processCreated = 0;
    };
    struct Request
    {
        Action action = Action::kQuery;
        Position position = Position::kFront;
        std::uint32_t maintain = 1;
        std::uint32_t reserved = 0;
        WindowIdentity target;
        WindowIdentity reference;
    };
    struct Response
    {
        Status status = Status::kInvalidRequest;
        std::uint32_t win32Error = 0;
        std::int32_t nativeResult = 0;
        std::uint32_t flags = 0;
        std::uint32_t dwmProcessId = 0;
        std::uint32_t band = 0;
        std::uint32_t index = 0; // Zero is visually frontmost, opposite to native Flink order.
        std::uint32_t windowCount = 0;
        std::uint64_t previous = 0; // Window immediately above this one.
        std::uint64_t next = 0; // Window immediately below this one.
        std::uint64_t maintainedWindow = 0;
        Status maintenanceStatus = Status::kOk;
        std::uint32_t reserved = 0;
    };
    struct alignas(8) Packet
    {
        std::uint32_t magic = kMagic;
        std::uint32_t version = kProtocolVersion;
        std::uint32_t bytes = sizeof(Packet);
        std::uint32_t reserved = 0;
        Request request;
        Response response;
        // Query-only process handles duplicated into DWM, owned by the client.
        // Valid until the request thread ends; never retained by maintenance hooks.
        std::uint64_t targetProcess = 0;
        std::uint64_t referenceProcess = 0;
    };
    static_assert(sizeof(WindowIdentity) == 24);
    static_assert(sizeof(Request) == 64);
    static_assert(sizeof(Response) == 64);
    static_assert(sizeof(Packet) == 160);
    static_assert(std::is_trivially_copyable_v<Packet>);
}
