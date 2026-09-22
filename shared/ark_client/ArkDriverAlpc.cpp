#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <cstdint>
#include <sstream>
#include <string>

namespace ksword::ark
{
    namespace
    {

        AlpcPortInfo parseAlpcPortInfo(const KSWORD_ARK_ALPC_PORT_INFO& responsePort)
        {
            // Purpose: Convert shared protocol port nodes to the UI-side model.
            // Processing: Copy fields one by one and convert fixed-length WCHAR names to std::wstring.
            // Returns: An AlpcPortInfo value object.
            AlpcPortInfo parsedPort{};
            parsedPort.relation = static_cast<std::uint32_t>(responsePort.relation);
            parsedPort.fieldFlags = static_cast<std::uint32_t>(responsePort.fieldFlags);
            parsedPort.ownerProcessId = static_cast<std::uint32_t>(responsePort.ownerProcessId);
            parsedPort.flags = static_cast<std::uint32_t>(responsePort.flags);
            parsedPort.state = static_cast<std::uint32_t>(responsePort.state);
            parsedPort.sequenceNo = static_cast<std::uint32_t>(responsePort.sequenceNo);
            parsedPort.basicStatus = static_cast<long>(responsePort.basicStatus);
            parsedPort.nameStatus = static_cast<long>(responsePort.nameStatus);
            parsedPort.objectAddress = static_cast<std::uint64_t>(responsePort.objectAddress);
            parsedPort.portContext = static_cast<std::uint64_t>(responsePort.portContext);
            parsedPort.portName = detail::readFixedString(responsePort.portName, KSWORD_ARK_ALPC_PORT_NAME_CHARS);
            return parsedPort;
        }
    }

    AlpcPortQueryResult DriverClient::queryAlpcPort(
        const std::uint32_t processId,
        const std::uint64_t handleValue,
        const unsigned long flags) const
    {
        // Purpose: Invoke the R0 ALPC query IOCTL.
        // Handling: Pass only PID + HandleValue, not object address; parse fixed response packet.
        // Return: An AlpcPortQueryResult containing the IO result, status, and port relationship.
        AlpcPortQueryResult queryResult{};
        KSWORD_ARK_QUERY_ALPC_PORT_REQUEST request{};
        KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE response{};
        request.flags = flags;
        request.processId = processId;
        request.handleValue = handleValue;

        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_ALPC_PORT,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!queryResult.io.ok)
        {
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_ALPC_PORT) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }
        if (queryResult.io.bytesReturned < sizeof(KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-alpc-port response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        queryResult.version = static_cast<std::uint32_t>(response.version);
        queryResult.processId = static_cast<std::uint32_t>(response.processId);
        queryResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        queryResult.handleValue = static_cast<std::uint64_t>(response.handleValue);
        queryResult.queryStatus = static_cast<std::uint32_t>(response.queryStatus);
        queryResult.objectReferenceStatus = static_cast<long>(response.objectReferenceStatus);
        queryResult.typeStatus = static_cast<long>(response.typeStatus);
        queryResult.basicStatus = static_cast<long>(response.basicStatus);
        queryResult.communicationStatus = static_cast<long>(response.communicationStatus);
        queryResult.nameStatus = static_cast<long>(response.nameStatus);
        queryResult.dynDataCapabilityMask = static_cast<std::uint64_t>(response.dynDataCapabilityMask);
        queryResult.alpcCommunicationInfoOffset = static_cast<std::uint32_t>(response.alpcCommunicationInfoOffset);
        queryResult.alpcOwnerProcessOffset = static_cast<std::uint32_t>(response.alpcOwnerProcessOffset);
        queryResult.alpcConnectionPortOffset = static_cast<std::uint32_t>(response.alpcConnectionPortOffset);
        queryResult.alpcServerCommunicationPortOffset = static_cast<std::uint32_t>(response.alpcServerCommunicationPortOffset);
        queryResult.alpcClientCommunicationPortOffset = static_cast<std::uint32_t>(response.alpcClientCommunicationPortOffset);
        queryResult.alpcHandleTableOffset = static_cast<std::uint32_t>(response.alpcHandleTableOffset);
        queryResult.alpcHandleTableLockOffset = static_cast<std::uint32_t>(response.alpcHandleTableLockOffset);
        queryResult.alpcAttributesOffset = static_cast<std::uint32_t>(response.alpcAttributesOffset);
        queryResult.alpcAttributesFlagsOffset = static_cast<std::uint32_t>(response.alpcAttributesFlagsOffset);
        queryResult.alpcPortContextOffset = static_cast<std::uint32_t>(response.alpcPortContextOffset);
        queryResult.alpcPortObjectLockOffset = static_cast<std::uint32_t>(response.alpcPortObjectLockOffset);
        queryResult.alpcSequenceNoOffset = static_cast<std::uint32_t>(response.alpcSequenceNoOffset);
        queryResult.alpcStateOffset = static_cast<std::uint32_t>(response.alpcStateOffset);
        queryResult.typeName = detail::readFixedString(response.typeName, KSWORD_ARK_ALPC_TYPE_NAME_CHARS);
        queryResult.queryPort = parseAlpcPortInfo(response.queryPort);
        queryResult.connectionPort = parseAlpcPortInfo(response.connectionPort);
        queryResult.serverPort = parseAlpcPortInfo(response.serverPort);
        queryResult.clientPort = parseAlpcPortInfo(response.clientPort);

        std::ostringstream stream;
        stream << "version=" << queryResult.version
            << ", pid=" << queryResult.processId
            << ", handle=0x" << std::hex << std::uppercase << queryResult.handleValue
            << ", queryStatus=" << std::dec << queryResult.queryStatus
            << ", fieldFlags=0x" << std::hex << std::uppercase << queryResult.fieldFlags
            << std::dec << ", bytesReturned=" << queryResult.io.bytesReturned;
        queryResult.io.message = stream.str();
        return queryResult;
    }
}
