#pragma once

// ============================================================
// ksword/network/network_request_tools.h
// Namespace:
// ks::network Purpose:
// 1) Define parameters/results structures required for 'manually constructed network requests';
// 2) Supports configurable TCP/UDP Winsock request execution;
// 3) Supports both text and hexadecimal payload input formats.
//
// Design notes:
// - Inline implementation in the header file to avoid adding a new .cpp file and modifying project files.
// - Primarily targets parameterized execution scenarios in the NetworkDock 'Request Construction' tab.
// ============================================================

#include <algorithm> // std::clamp: Constrains length and timeout ranges.
#include <cctype>    // std::isxdigit: Validates hexadecimal characters.
#include <cstdint>   // Fixed-width integers: ports, lengths, timeouts, etc.
#include <cstring>   // std::memset: zeroing the sockaddr structure.
#include <exception> // std::exception: protection against hexadecimal parsing exceptions.
#include <string>    // std::string: Parameter and result text.
#include <utility>   // std::move: Result object move assignment.
#include <vector>    // std::vector: Request/response byte container.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Ws2def.h>
#include <Mstcpip.h>

// Ws2_32: Basic network APIs such as WSAStartup, socket, connect, send, and recv.
#pragma comment(lib, "Ws2_32.lib")

namespace ks::network
{
    // ManualNetworkApiKind: the API method provided by the request construction page.
    enum class ManualNetworkApiKind : std::uint8_t
    {
        kWinSockTcp = 0, // TCP: Typical connect + send + recv.
        kWinSockUdp = 1  // UDP: Supports connect or sendto/recvfrom.
    };

    // ManualPayloadFormat: Payload input format.
    enum class ManualPayloadFormat : std::uint8_t
    {
        kAsciiText = 0, // Send as UTF-8 text bytes.
        kHexBytes = 1   // Send as a hexadecimal byte string (e.g., "48 65 6C 6C 6F").
    };

    // ManualNetworkRequest: A complete parameter object for a single manual request.
    struct ManualNetworkRequest
    {
        // API mode:
        // - Defaults to TCP;
        // - UI can switch to UDP.
        ManualNetworkApiKind apiKind = ManualNetworkApiKind::kWinSockTcp;

        // Socket parameters:
        // - When overrideSocketParameters is false, automatically apply default TCP/UDP values based on apiKind;
        // - When true, directly uses addressFamily, socketType, protocol, and socketFlags.
        bool overrideSocketParameters = false;
        int addressFamily = AF_INET;         // Address family (default AF_INET).
        int socketType = SOCK_STREAM;        // Socket type (SOCK_STREAM / SOCK_DGRAM).
        int protocol = IPPROTO_TCP;          // Protocol (IPPROTO_TCP / IPPROTO_UDP).
        DWORD socketFlags = WSA_FLAG_OVERLAPPED; // WSASocket flags。

        // Local/remote endpoints:
        bool enableLocalBind = false;        // When true, bind to (localAddress:localPort) first.
        std::string localAddress = "0.0.0.0";// bind address.
        std::uint16_t localPort = 0;         // bind port (0 = system-assigned).
        std::string remoteAddress = "127.0.0.1"; // Target address.
        std::uint16_t remotePort = 80;       // Target port.

        // Request execution behavior:
        bool connectBeforeSend = true;       // Whether to connect before sending (can be disabled for UDP).
        bool enableReuseAddress = false;     // SO_REUSEADDR。
        bool enableNoDelay = false;          // TCP_NODELAY (valid under TCP).
        std::uint32_t sendTimeoutMs = 3000;  // SO_SNDTIMEO。
        std::uint32_t receiveTimeoutMs = 3000;// SO_RCVTIMEO。
        int sendFlags = 0;                   // send/sendto flags。
        int receiveFlags = 0;                // recv/recvfrom flags。
        bool receiveAfterSend = true;        // Whether to read the response after sending.
        std::size_t receiveMaxBytes = 4096;  // Maximum number of bytes to read in the response.
        bool shutdownSendAfterWrite = false; // Whether to send shutdown(SD_SEND) after write under TCP.

        // Request payload:
        ManualPayloadFormat payloadFormat = ManualPayloadFormat::kAsciiText;
        std::string payloadText;             // Text or hexadecimal string (determined by payloadFormat).
    };

    // ManualNetworkResult: The result of a single manual request execution.
    struct ManualNetworkResult
    {
        bool succeeded = false;              // Overall success flag.
        int wsaErrorCode = 0;                // WSA error code on failure (0 indicates none).
        std::string detailText;              // Detailed description (can be displayed directly in the UI).
        std::size_t bytesSent = 0;           // Actual number of bytes sent.
        std::size_t bytesReceived = 0;       // Actual number of bytes received.
        std::vector<std::uint8_t> responseBytes; // Receive the raw response bytes.
    };

    // ManualNetworkRequestValidation：
    // - Purpose: Provides pure parameter validation for the UI before dispatching to the background thread.
    // - payloadByteCount represents the actual number of bytes to be sent after constructing the payload according to payloadFormat.
    struct ManualNetworkRequestValidation
    {
        bool valid = false;                  // true indicates parameters are ready for the executor.
        std::string errorText;               // Reason for validation failure; empty string indicates no error.
        std::size_t payloadByteCount = 0;    // Byte count of the parsed payload.
    };

    namespace request_detail
    {
        // makeWsaErrorText: Assembles the WSA error code into human-readable text.
        inline std::string makeWsaErrorText(const int wsaErrorCode)
        {
            return "WSAError=" + std::to_string(wsaErrorCode);
        }

        // WsaSessionGuard：
        // - Responsible for the WSAStartup/WSACleanup lifecycle within the current call scope;
        // - Prevent resource leaks caused by callers forgetting to clean up.
        class WsaSessionGuard
        {
        public:
            WsaSessionGuard()
            {
                std::memset(&wsaData_, 0, sizeof(wsaData_));
                startupResult_ = ::WSAStartup(MAKEWORD(2, 2), &wsaData_);
                started_ = (startupResult_ == 0);
            }

            ~WsaSessionGuard()
            {
                if (started_)
                {
                    ::WSACleanup();
                }
            }

            bool started() const
            {
                return started_;
            }

            int startupResult() const
            {
                return startupResult_;
            }

        private:
            WSADATA wsaData_{};
            int startupResult_ = 0;
            bool started_ = false;
        };

        // SocketGuard：
        // - Simple RAII socket wrapper;
        // - Ensure that exception/early-exit paths also call closesocket.
        class SocketGuard
        {
        public:
            SocketGuard() = default;
            ~SocketGuard()
            {
                close();
            }

            void reset(const SOCKET socketValue)
            {
                close();
                socket_ = socketValue;
            }

            SOCKET get() const
            {
                return socket_;
            }

            bool valid() const
            {
                return socket_ != INVALID_SOCKET;
            }

            void close()
            {
                if (socket_ != INVALID_SOCKET)
                {
                    ::closesocket(socket_);
                    socket_ = INVALID_SOCKET;
                }
            }

        private:
            SOCKET socket_ = INVALID_SOCKET;
        };

        // resolveIpv4Endpoint：
        // - Parses address:port into a sockaddr_in structure.
        // - Supports IPv4 only; returns false on failure.
        inline bool resolveIpv4Endpoint(
            const std::string& addressText,
            const std::uint16_t portValue,
            sockaddr_in& endpointOut)
        {
            std::memset(&endpointOut, 0, sizeof(endpointOut));
            endpointOut.sin_family = AF_INET;
            endpointOut.sin_port = htons(portValue);
            const int kParseResult = ::inet_pton(AF_INET, addressText.c_str(), &endpointOut.sin_addr);
            return kParseResult == 1;
        }

        // parseHexPayloadText：
        // - Parse hex byte strings, supporting space/newline/comma separators;
        // - Example: "48 65 6C 6C 6F" -> {'H','e','l','l','o'}.
        inline bool parseHexPayloadText(
            const std::string& hexPayloadText,
            std::vector<std::uint8_t>& payloadBytesOut,
            std::string* errorTextOut = nullptr)
        {
            payloadBytesOut.clear();
            if (errorTextOut != nullptr)
            {
                errorTextOut->clear();
            }

            // Sanitize input: remove common delimiters and retain only hexadecimal characters.
            std::string normalizedHexText;
            normalizedHexText.reserve(hexPayloadText.size());
            for (char currentChar : hexPayloadText)
            {
                if (currentChar == ' ' || currentChar == '\t' || currentChar == '\r' ||
                    currentChar == '\n' || currentChar == ',' || currentChar == ';')
                {
                    continue;
                }
                if (!std::isxdigit(static_cast<unsigned char>(currentChar)))
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = "hex payload contains non-hex character.";
                    }
                    return false;
                }
                normalizedHexText.push_back(currentChar);
            }

            // Hexadecimal characters must appear in pairs; an odd length is considered a format error.
            if ((normalizedHexText.size() % 2) != 0)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = "hex payload length must be even.";
                }
                return false;
            }

            // Parse every two characters into 1 byte.
            payloadBytesOut.reserve(normalizedHexText.size() / 2);
            for (std::size_t index = 0; index < normalizedHexText.size(); index += 2)
            {
                const std::string kByteHexText = normalizedHexText.substr(index, 2);
                try
                {
                    const unsigned long kByteValue = std::stoul(kByteHexText, nullptr, 16);
                    payloadBytesOut.push_back(static_cast<std::uint8_t>(kByteValue & 0xFFUL));
                }
                catch (const std::exception&)
                {
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = "hex payload parse exception occurred.";
                    }
                    payloadBytesOut.clear();
                    return false;
                }
            }

            return true;
        }
    } // namespace request_detail

    // manualNetworkApiKindToString: Convert API enum to text.
    inline std::string manualNetworkApiKindToString(const ManualNetworkApiKind apiKind)
    {
        switch (apiKind)
        {
        case ManualNetworkApiKind::kWinSockTcp: return "WinSockTcp";
        case ManualNetworkApiKind::kWinSockUdp: return "WinSockUdp";
        default:                               return "UnknownApi";
        }
    }

    // manualPayloadFormatToString: Converts the payload format enum to text.
    inline std::string manualPayloadFormatToString(const ManualPayloadFormat payloadFormat)
    {
        switch (payloadFormat)
        {
        case ManualPayloadFormat::kAsciiText: return "AsciiText";
        case ManualPayloadFormat::kHexBytes:  return "HexBytes";
        default:                             return "UnknownFormat";
        }
    }

    // buildManualRequestPayloadBytes：
    // - Construct send bytes according to ManualPayloadFormat;
    // - In ASCII mode, directly copy the payloadText bytes;
    // - HEX mode reuses request_detail::parseHexPayloadText.
    inline bool buildManualRequestPayloadBytes(
        const ManualNetworkRequest& request,
        std::vector<std::uint8_t>& payloadBytesOut,
        std::string* errorTextOut = nullptr)
    {
        payloadBytesOut.clear();
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        if (request.payloadFormat == ManualPayloadFormat::kAsciiText)
        {
            payloadBytesOut.assign(request.payloadText.begin(), request.payloadText.end());
            return true;
        }

        if (request.payloadFormat == ManualPayloadFormat::kHexBytes)
        {
            return request_detail::parseHexPayloadText(request.payloadText, payloadBytesOut, errorTextOut);
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = "unknown payload format.";
        }
        return false;
    }

    // validateManualNetworkRequest：
    // - Validate the IPv4/TCP/UDP parameter combinations supported by the executor;
    // - does not create sockets or send network requests; performs only reusable parameter validation;
    // - When returning false, resultOut->errorText can be directly displayed to the UI.
    inline bool validateManualNetworkRequest(
        const ManualNetworkRequest& request,
        ManualNetworkRequestValidation* const resultOut)
    {
        ManualNetworkRequestValidation validationResult{};

        if (request.apiKind != ManualNetworkApiKind::kWinSockTcp &&
            request.apiKind != ManualNetworkApiKind::kWinSockUdp)
        {
            validationResult.errorText = "unknown manual request API kind.";
            if (resultOut != nullptr)
            {
                *resultOut = validationResult;
            }
            return false;
        }

        int effectiveAddressFamily = request.addressFamily;
        if (!request.overrideSocketParameters)
        {
            effectiveAddressFamily = AF_INET;
        }
        if (effectiveAddressFamily != AF_INET)
        {
            validationResult.errorText = "Only AF_INET is supported in current manual request tool.";
            if (resultOut != nullptr)
            {
                *resultOut = validationResult;
            }
            return false;
        }

        if (request.remoteAddress.empty() || request.remotePort == 0)
        {
            validationResult.errorText = "remote endpoint is empty or port is zero.";
            if (resultOut != nullptr)
            {
                *resultOut = validationResult;
            }
            return false;
        }

        sockaddr_in remoteEndpoint{};
        if (!request_detail::resolveIpv4Endpoint(request.remoteAddress, request.remotePort, remoteEndpoint))
        {
            validationResult.errorText = "remote endpoint parse failed (IPv4 only).";
            if (resultOut != nullptr)
            {
                *resultOut = validationResult;
            }
            return false;
        }

        if (request.enableLocalBind)
        {
            if (request.localAddress.empty())
            {
                validationResult.errorText = "local bind address is empty.";
                if (resultOut != nullptr)
                {
                    *resultOut = validationResult;
                }
                return false;
            }

            sockaddr_in localEndpoint{};
            if (!request_detail::resolveIpv4Endpoint(request.localAddress, request.localPort, localEndpoint))
            {
                validationResult.errorText = "local bind endpoint parse failed (IPv4 only).";
                if (resultOut != nullptr)
                {
                    *resultOut = validationResult;
                }
                return false;
            }
        }

        std::vector<std::uint8_t> payloadBytes;
        std::string payloadErrorText;
        if (!buildManualRequestPayloadBytes(request, payloadBytes, &payloadErrorText))
        {
            validationResult.errorText = "payload parse failed: " + payloadErrorText;
            if (resultOut != nullptr)
            {
                *resultOut = validationResult;
            }
            return false;
        }

        validationResult.valid = true;
        validationResult.payloadByteCount = payloadBytes.size();
        if (resultOut != nullptr)
        {
            *resultOut = validationResult;
        }
        return true;
    }

    // executeManualNetworkRequest：
    // - Execute a network request based on request parameters.
    // - Supports TCP/UDP, optional bind/connect, and optional response reception.
    // - Returns true if the request process succeeds, false if execution fails.
    inline bool executeManualNetworkRequest(
        const ManualNetworkRequest& request,
        ManualNetworkResult* const resultOut)
    {
        if (resultOut == nullptr)
        {
            return false;
        }

        ManualNetworkResult localResult{};
        localResult.detailText.clear();

        // Start the WSA session; return immediately on failure.
        request_detail::WsaSessionGuard wsaGuard;
        if (!wsaGuard.started())
        {
            localResult.succeeded = false;
            localResult.wsaErrorCode = wsaGuard.startupResult();
            localResult.detailText = "WSAStartup failed: " + request_detail::makeWsaErrorText(localResult.wsaErrorCode);
            *resultOut = std::move(localResult);
            return false;
        }

        // Determine default socket parameters based on the API mode.
        // Use UI to explicitly override values when overrideSocketParameters=true.
        int effectiveAddressFamily = request.addressFamily;
        int effectiveSocketType = request.socketType;
        int effectiveProtocol = request.protocol;
        if (!request.overrideSocketParameters)
        {
            if (request.apiKind == ManualNetworkApiKind::kWinSockTcp)
            {
                effectiveAddressFamily = AF_INET;
                effectiveSocketType = SOCK_STREAM;
                effectiveProtocol = IPPROTO_TCP;
            }
            else
            {
                effectiveAddressFamily = AF_INET;
                effectiveSocketType = SOCK_DGRAM;
                effectiveProtocol = IPPROTO_UDP;
            }
        }

        // The current implementation supports only IPv4: if the user manually changes the family, an error is returned immediately.
        if (effectiveAddressFamily != AF_INET)
        {
            localResult.succeeded = false;
            localResult.detailText = "Only AF_INET is supported in current manual request tool.";
            *resultOut = std::move(localResult);
            return false;
        }

        // Create socket.
        request_detail::SocketGuard socketGuard;
        const SOCKET kSocketValue = ::WSASocketW(
            effectiveAddressFamily,
            effectiveSocketType,
            effectiveProtocol,
            nullptr,
            0,
            request.socketFlags);
        if (kSocketValue == INVALID_SOCKET)
        {
            localResult.succeeded = false;
            localResult.wsaErrorCode = ::WSAGetLastError();
            localResult.detailText = "WSASocket failed: " + request_detail::makeWsaErrorText(localResult.wsaErrorCode);
            *resultOut = std::move(localResult);
            return false;
        }
        socketGuard.reset(kSocketValue);

        // Socket options: SO_REUSEADDR, timeouts, and TCP_NODELAY.
        if (request.enableReuseAddress)
        {
            const BOOL kReuseAddress = TRUE;
            (void)::setsockopt(
                socketGuard.get(),
                SOL_SOCKET,
                SO_REUSEADDR,
                reinterpret_cast<const char*>(&kReuseAddress),
                static_cast<int>(sizeof(kReuseAddress)));
        }

        const int kSendTimeoutMs = static_cast<int>(std::clamp<std::uint32_t>(request.sendTimeoutMs, 0U, 3600000U));
        const int kReceiveTimeoutMs = static_cast<int>(std::clamp<std::uint32_t>(request.receiveTimeoutMs, 0U, 3600000U));
        (void)::setsockopt(
            socketGuard.get(),
            SOL_SOCKET,
            SO_SNDTIMEO,
            reinterpret_cast<const char*>(&kSendTimeoutMs),
            static_cast<int>(sizeof(kSendTimeoutMs)));
        (void)::setsockopt(
            socketGuard.get(),
            SOL_SOCKET,
            SO_RCVTIMEO,
            reinterpret_cast<const char*>(&kReceiveTimeoutMs),
            static_cast<int>(sizeof(kReceiveTimeoutMs)));

        if (request.enableNoDelay && effectiveProtocol == IPPROTO_TCP)
        {
            const BOOL kNoDelay = TRUE;
            (void)::setsockopt(
                socketGuard.get(),
                IPPROTO_TCP,
                TCP_NODELAY,
                reinterpret_cast<const char*>(&kNoDelay),
                static_cast<int>(sizeof(kNoDelay)));
        }

        // Resolve remote endpoint; return immediately on failure.
        sockaddr_in remoteEndpoint{};
        if (!request_detail::resolveIpv4Endpoint(request.remoteAddress, request.remotePort, remoteEndpoint))
        {
            localResult.succeeded = false;
            localResult.detailText = "remote endpoint parse failed (IPv4 only).";
            *resultOut = std::move(localResult);
            return false;
        }

        // Optional local endpoint binding.
        if (request.enableLocalBind)
        {
            sockaddr_in localEndpoint{};
            if (!request_detail::resolveIpv4Endpoint(request.localAddress, request.localPort, localEndpoint))
            {
                localResult.succeeded = false;
                localResult.detailText = "local bind endpoint parse failed (IPv4 only).";
                *resultOut = std::move(localResult);
                return false;
            }

            const int kBindResult = ::bind(
                socketGuard.get(),
                reinterpret_cast<const sockaddr*>(&localEndpoint),
                static_cast<int>(sizeof(localEndpoint)));
            if (kBindResult == SOCKET_ERROR)
            {
                localResult.succeeded = false;
                localResult.wsaErrorCode = ::WSAGetLastError();
                localResult.detailText = "bind failed: " + request_detail::makeWsaErrorText(localResult.wsaErrorCode);
                *resultOut = std::move(localResult);
                return false;
            }
        }

        // When connectBeforeSend is true, connect to the remote endpoint first.
        if (request.connectBeforeSend)
        {
            const int kConnectResult = ::connect(
                socketGuard.get(),
                reinterpret_cast<const sockaddr*>(&remoteEndpoint),
                static_cast<int>(sizeof(remoteEndpoint)));
            if (kConnectResult == SOCKET_ERROR)
            {
                localResult.succeeded = false;
                localResult.wsaErrorCode = ::WSAGetLastError();
                localResult.detailText = "connect failed: " + request_detail::makeWsaErrorText(localResult.wsaErrorCode);
                *resultOut = std::move(localResult);
                return false;
            }
        }

        // Construct the payload bytes to send:
        // - Shares buildManualRequestPayloadBytes with UI pre-submission validation;
        // - Keep HEX parsing rules consistent between validation and execution.
        std::vector<std::uint8_t> payloadBytes;
        std::string parseHexErrorText;
        if (!buildManualRequestPayloadBytes(request, payloadBytes, &parseHexErrorText))
        {
            localResult.succeeded = false;
            localResult.detailText = "payload parse failed: " + parseHexErrorText;
            *resultOut = std::move(localResult);
            return false;
        }

        // Execute send:
        // - Use send in the connected scenario.
        // - Uses sendto for UDP scenarios without a prior connect.
        int sendResult = 0;
        if (request.connectBeforeSend)
        {
            sendResult = ::send(
                socketGuard.get(),
                reinterpret_cast<const char*>(payloadBytes.data()),
                static_cast<int>(payloadBytes.size()),
                request.sendFlags);
        }
        else
        {
            sendResult = ::sendto(
                socketGuard.get(),
                reinterpret_cast<const char*>(payloadBytes.data()),
                static_cast<int>(payloadBytes.size()),
                request.sendFlags,
                reinterpret_cast<const sockaddr*>(&remoteEndpoint),
                static_cast<int>(sizeof(remoteEndpoint)));
        }
        if (sendResult == SOCKET_ERROR)
        {
            localResult.succeeded = false;
            localResult.wsaErrorCode = ::WSAGetLastError();
            localResult.detailText = "send/sendto failed: " + request_detail::makeWsaErrorText(localResult.wsaErrorCode);
            *resultOut = std::move(localResult);
            return false;
        }
        localResult.bytesSent = static_cast<std::size_t>(sendResult);

        // In TCP mode, optionally execute shutdown(SD_SEND) to test half-close semantics.
        if (request.shutdownSendAfterWrite && effectiveProtocol == IPPROTO_TCP)
        {
            const int kShutdownResult = ::shutdown(socketGuard.get(), SD_SEND);
            if (kShutdownResult == SOCKET_ERROR)
            {
                // Log a warning here without immediately marking the operation as failed to avoid disrupting the subsequent recv debugging flow.
                localResult.detailText +=
                    (" | shutdown(SD_SEND) failed: " + request_detail::makeWsaErrorText(::WSAGetLastError()));
            }
        }

        // Optional response reception: supports both connected recv and unconnected recvfrom.
        if (request.receiveAfterSend)
        {
            const std::size_t kReceiveLimitBytes = std::clamp<std::size_t>(request.receiveMaxBytes, 1ULL, 1024ULL * 1024ULL);
            localResult.responseBytes.resize(kReceiveLimitBytes);

            int receiveResult = 0;
            if (request.connectBeforeSend)
            {
                receiveResult = ::recv(
                    socketGuard.get(),
                    reinterpret_cast<char*>(localResult.responseBytes.data()),
                    static_cast<int>(localResult.responseBytes.size()),
                    request.receiveFlags);
            }
            else
            {
                sockaddr_in sourceEndpoint{};
                int sourceEndpointLength = static_cast<int>(sizeof(sourceEndpoint));
                receiveResult = ::recvfrom(
                    socketGuard.get(),
                    reinterpret_cast<char*>(localResult.responseBytes.data()),
                    static_cast<int>(localResult.responseBytes.size()),
                    request.receiveFlags,
                    reinterpret_cast<sockaddr*>(&sourceEndpoint),
                    &sourceEndpointLength);
            }

            if (receiveResult == SOCKET_ERROR)
            {
                const int kReceiveWsaError = ::WSAGetLastError();
                if (kReceiveWsaError == WSAETIMEDOUT || kReceiveWsaError == WSAEWOULDBLOCK)
                {
                    // Timeout is not a hard failure: the request was sent, but no data was received within the timeout window.
                    localResult.bytesReceived = 0;
                    localResult.responseBytes.clear();
                    localResult.succeeded = true;
                    localResult.wsaErrorCode = kReceiveWsaError;
                    localResult.detailText = "request sent, receive timeout: " + request_detail::makeWsaErrorText(kReceiveWsaError);
                    *resultOut = std::move(localResult);
                    return true;
                }

                localResult.succeeded = false;
                localResult.wsaErrorCode = kReceiveWsaError;
                localResult.detailText = "recv/recvfrom failed: " + request_detail::makeWsaErrorText(kReceiveWsaError);
                *resultOut = std::move(localResult);
                return false;
            }

            localResult.bytesReceived = static_cast<std::size_t>(receiveResult);
            localResult.responseBytes.resize(localResult.bytesReceived);
        }
        else
        {
            localResult.responseBytes.clear();
            localResult.bytesReceived = 0;
        }

        // Execution flow succeeded.
        localResult.succeeded = true;
        if (localResult.detailText.empty())
        {
            localResult.detailText = "manual network request succeeded.";
        }
        *resultOut = std::move(localResult);
        return true;
    }
} // namespace ks::network
