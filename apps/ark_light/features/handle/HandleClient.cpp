#include "HandleClient.h"

#include "../../../../shared/driver/KswordArkHandleIoctl.h"

#include <algorithm>
#include <cwctype>
#include <sstream>

namespace ksword::features::handle {
namespace {

constexpr long kNtStatusInvalidParameter = -1073741811L;

// makeInvalidPidResult creates a local validation failure without touching R0.
// Input is the rejected PID; processing mirrors ArkDriverClient status style;
// output is a HandleEnumView with io.ok=false.
HandleEnumView makeInvalidPidResult(const std::uint32_t processId) {
    HandleEnumView result;
    result.processId = processId;
    result.overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
    result.lastStatus = kNtStatusInvalidParameter;
    result.io.ok = false;
    result.io.win32Error = ERROR_INVALID_PARAMETER;
    result.io.ntStatus = kNtStatusInvalidParameter;
    result.io.message = "handle audit requires a non-zero target pid";
    return result;
}

// copyEntry maps the strong ArkDriverClient result into the page-local view.
// New protocol-only diagnostics remain zero/default until they are exposed by
// ArkDriverClient; this keeps the Light UI on the supported public contract.
HandleEntryView copyEntry(const ksword::ark::HandleEntry& entry) {
    HandleEntryView out;
    out.processId = static_cast<std::uint32_t>(entry.processId);
    out.handleValue = static_cast<std::uint32_t>(entry.handleValue);
    out.fieldFlags = static_cast<std::uint32_t>(entry.fieldFlags);
    out.decodeStatus = static_cast<std::uint32_t>(entry.decodeStatus);
    out.grantedAccess = static_cast<std::uint32_t>(entry.grantedAccess);
    out.attributes = static_cast<std::uint32_t>(entry.attributes);
    out.objectTypeIndex = static_cast<std::uint32_t>(entry.objectTypeIndex);
    out.objectAddress = static_cast<std::uint64_t>(entry.objectAddress);
    out.dynDataCapabilityMask = static_cast<std::uint64_t>(entry.dynDataCapabilityMask);
    out.epObjectTableOffset = static_cast<std::uint32_t>(entry.epObjectTableOffset);
    out.htHandleContentionEventOffset = static_cast<std::uint32_t>(entry.htHandleContentionEventOffset);
    out.obDecodeShift = static_cast<std::uint32_t>(entry.obDecodeShift);
    out.obAttributesShift = static_cast<std::uint32_t>(entry.obAttributesShift);
    out.otNameOffset = static_cast<std::uint32_t>(entry.otNameOffset);
    out.otIndexOffset = static_cast<std::uint32_t>(entry.otIndexOffset);
    return out;
}

// isAlpcPortType decides whether the selected object can use the dedicated
// ALPC parser. The input is ObjectType text produced by the typed object query;
// output is false for every non-port object, avoiding unrelated extra IOCTLs.
bool isAlpcPortType(const std::wstring& typeName) {
    std::wstring normalized;
    normalized.reserve(typeName.size());
    for (const wchar_t kCharacter : typeName) {
        normalized.push_back(static_cast<wchar_t>(std::towupper(kCharacter)));
    }
    return normalized.find(L"ALPC") != std::wstring::npos &&
        normalized.find(L"PORT") != std::wstring::npos;
}

} // namespace

HandleEnumView HandleAuditClient::enumerateProcessHandles(const std::uint32_t processId) const {
    // Input is one target process id. Processing uses the typed ArkDriverClient
    // handle API. Output keeps partial/transport failures visible to the page.
    if (processId == 0U) {
        return makeInvalidPidResult(processId);
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::HandleEnumResult kTyped = kClient.enumerateProcessHandles(
        processId,
        KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL);
    HandleEnumView result;
    result.io = kTyped.io;
    result.version = kTyped.version;
    result.totalCount = kTyped.totalCount;
    result.returnedCount = kTyped.returnedCount;
    result.processId = kTyped.processId;
    result.overallStatus = kTyped.overallStatus;
    result.lastStatus = kTyped.lastStatus;
    result.entries.reserve(kTyped.entries.size());
    for (const ksword::ark::HandleEntry& entry : kTyped.entries) {
        result.entries.push_back(copyEntry(entry));
    }

    std::ostringstream stream;
    stream << "version=" << result.version
           << ", pid=" << result.processId
           << ", total=" << result.totalCount
           << ", returned=" << result.returnedCount
           << ", parsed=" << result.entries.size()
           << ", overallStatus=" << result.overallStatus
           << ", bytesReturned=" << result.io.bytesReturned;
    result.io.message = stream.str();
    return result;
}

HandleObjectDetailView HandleAuditClient::queryHandleObject(
    const std::uint32_t processId,
    const std::uint64_t handleValue) const {
    // Inputs identify one process handle. Processing asks R0 for the metadata
    // currently exposed by the strong client: type name, object name and access
    // diagnostics. It intentionally does not request a proxy handle.
    HandleObjectDetailView result;
    const ksword::ark::DriverClient kClient;
    const ksword::ark::HandleObjectQueryResult kTyped = kClient.queryHandleObject(
        processId,
        handleValue,
        KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL,
        0U);
    result.io = kTyped.io;
    result.version = kTyped.version;
    result.processId = kTyped.processId;
    result.fieldFlags = kTyped.fieldFlags;
    result.handleValue = kTyped.handleValue;
    result.objectAddress = kTyped.objectAddress;
    result.objectTypeIndex = kTyped.objectTypeIndex;
    result.queryStatus = kTyped.queryStatus;
    result.objectReferenceStatus = kTyped.objectReferenceStatus;
    result.typeStatus = kTyped.typeStatus;
    result.nameStatus = kTyped.nameStatus;
    result.proxyStatus = kTyped.proxyStatus;
    result.proxyNtStatus = kTyped.proxyNtStatus;
    result.proxyPolicyFlags = kTyped.proxyPolicyFlags;
    result.requestedAccess = kTyped.requestedAccess;
    result.actualGrantedAccess = kTyped.actualGrantedAccess;
    result.proxyHandle = kTyped.proxyHandle;
    result.dynDataCapabilityMask = kTyped.dynDataCapabilityMask;
    result.otNameOffset = kTyped.otNameOffset;
    result.otIndexOffset = kTyped.otIndexOffset;
    result.typeName = kTyped.typeName;
    result.objectName = kTyped.objectName;
    if (kTyped.io.ok && isAlpcPortType(result.typeName)) {
        result.alpcQueried = true;
        result.alpc = kClient.queryAlpcPort(processId, handleValue);
    }

    std::ostringstream stream;
    stream << "version=" << result.version
           << ", pid=" << result.processId
           << ", handle=0x" << std::hex << std::uppercase << result.handleValue
           << ", queryStatus=" << std::dec << result.queryStatus
           << ", bytesReturned=" << result.io.bytesReturned;
    result.io.message = stream.str();
    return result;
}

} // namespace Ksword::Features::Handle
