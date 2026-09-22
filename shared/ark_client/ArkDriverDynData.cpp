#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <utility>

namespace ksword::ark
{
    namespace
    {


        // convertModuleIdentity:
        // - Converts module identity packet from shared protocol to R3-friendly structure;
        // - Input parameter source: Module identity structure returned by the driver.
        // - Return: ArkDynModuleIdentity value object.
        ArkDynModuleIdentity convertModuleIdentity(const KSW_DYN_MODULE_IDENTITY_PACKET& source)
        {
            ArkDynModuleIdentity result{};
            result.present = source.present != 0UL;
            result.classId = static_cast<std::uint32_t>(source.classId);
            result.machine = static_cast<std::uint32_t>(source.machine);
            result.timeDateStamp = static_cast<std::uint32_t>(source.timeDateStamp);
            result.sizeOfImage = static_cast<std::uint32_t>(source.sizeOfImage);
            result.imageBase = static_cast<std::uint64_t>(source.imageBase);
            result.moduleName = detail::readFixedString(source.moduleName, KSW_DYN_MODULE_NAME_CHARS);
            return result;
        }

        // copyDynAnsi:
        // - Safely copies std::string into the shared protocol's fixed char array;
        // - Parameters: destination (target buffer), destinationBytes (capacity), source (source text);
        // - Return: None; always ensures the destination is NUL-terminated.
        void copyDynAnsi(char* const destination, const std::size_t destinationBytes, const std::string& source)
        {
            if (destination == nullptr || destinationBytes == 0U)
            {
                return;
            }

            std::memset(destination, 0, destinationBytes);
            const std::size_t kBytesToCopy = std::min<std::size_t>(source.size(), destinationBytes - 1U);
            if (kBytesToCopy > 0U)
            {
                std::memcpy(destination, source.data(), kBytesToCopy);
            }
        }

        // buildIdentityPacket:
        // - Converts R3 module identity to a shared protocol packet;
        // - Input source: ArkDynModuleIdentity.
        // - Returns: KSW_DYN_MODULE_IDENTITY_PACKET value object.
        KSW_DYN_MODULE_IDENTITY_PACKET buildIdentityPacket(const ArkDynModuleIdentity& source)
        {
            KSW_DYN_MODULE_IDENTITY_PACKET packet{};
            packet.present = source.present ? 1UL : 0UL;
            packet.classId = static_cast<unsigned long>(source.classId);
            packet.machine = static_cast<unsigned long>(source.machine);
            packet.timeDateStamp = static_cast<unsigned long>(source.timeDateStamp);
            packet.sizeOfImage = static_cast<unsigned long>(source.sizeOfImage);
            packet.imageBase = static_cast<unsigned long long>(source.imageBase);
            const std::size_t kCharsToCopy = std::min<std::size_t>(
                source.moduleName.size(),
                static_cast<std::size_t>(KSW_DYN_MODULE_NAME_CHARS - 1U));
            for (std::size_t index = 0U; index < kCharsToCopy; ++index)
            {
                packet.moduleName[index] = source.moduleName[index];
            }
            packet.moduleName[KSW_DYN_MODULE_NAME_CHARS - 1U] = L'\0';
            return packet;
        }
    }

    // queryDynDataStatus:
    // - Request R0's current DynData match status.
    // - No input parameters;
    // - Returns: IO result, module identity, capability, and the reason for any unavailability.
    DynDataStatusResult DriverClient::queryDynDataStatus() const
    {
        DynDataStatusResult result{};
        KSW_QUERY_DYN_STATUS_RESPONSE response{};

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_DYN_STATUS,
            nullptr,
            0UL,
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_DYN_STATUS) failed, error=" + std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response) || response.version != KSWORD_ARK_DYNDATA_PROTOCOL_VERSION)
        {
            result.io.ok = false;
            result.io.message = "DynData status response invalid, bytesReturned=" + std::to_string(result.io.bytesReturned);
            return result;
        }

        result.statusFlags = static_cast<std::uint32_t>(response.statusFlags);
        result.systemInformerDataVersion = static_cast<std::uint32_t>(response.systemInformerDataVersion);
        result.systemInformerDataLength = static_cast<std::uint32_t>(response.systemInformerDataLength);
        result.lastStatus = static_cast<long>(response.lastStatus);
        result.matchedProfileClass = static_cast<std::uint32_t>(response.matchedProfileClass);
        result.matchedProfileOffset = static_cast<std::uint32_t>(response.matchedProfileOffset);
        result.matchedFieldsId = static_cast<std::uint32_t>(response.matchedFieldsId);
        result.fieldCount = static_cast<std::uint32_t>(response.fieldCount);
        result.capabilityMask = static_cast<std::uint64_t>(response.capabilityMask);
        result.ntoskrnl = convertModuleIdentity(response.ntoskrnl);
        result.lxcore = convertModuleIdentity(response.lxcore);
        result.unavailableReason = detail::readFixedString(response.unavailableReason, KSW_DYN_REASON_CHARS);

        std::ostringstream stream;
        stream << "DynData status flags=0x" << std::hex << result.statusFlags
            << ", caps=0x" << result.capabilityMask
            << std::dec << ", fields=" << result.fieldCount
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }

    // queryDynDataCapabilities:
    // - Request the current R0 DynData capability bitmap.
    // - No input parameters;
    // - Returns: A lightweight capability query result.
    DynDataCapabilitiesResult DriverClient::queryDynDataCapabilities() const
    {
        DynDataCapabilitiesResult result{};
        KSW_QUERY_CAPABILITIES_RESPONSE response{};

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_CAPABILITIES,
            nullptr,
            0UL,
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_CAPABILITIES) failed, error=" + std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response) || response.version != KSWORD_ARK_DYNDATA_PROTOCOL_VERSION)
        {
            result.io.ok = false;
            result.io.message = "DynData capabilities response invalid, bytesReturned=" + std::to_string(result.io.bytesReturned);
            return result;
        }

        result.statusFlags = static_cast<std::uint32_t>(response.statusFlags);
        result.capabilityMask = static_cast<std::uint64_t>(response.capabilityMask);
        result.io.message = "DynData capability query ok, mask=" + std::to_string(result.capabilityMask);
        return result;
    }

    // queryDynDataFields:
    // - Request R0's current DynData field list.
    // - No input parameters;
    // - Returns: The parsed field rows and the total response count.
    DynDataFieldsResult DriverClient::queryDynDataFields() const
    {
        DynDataFieldsResult result{};
        std::vector<std::uint8_t> responseBuffer(64U * 1024U, 0U);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS,
            nullptr,
            0UL,
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS) failed, error=" + std::to_string(result.io.win32Error);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSW_QUERY_DYN_FIELDS_RESPONSE) - sizeof(KSW_DYN_FIELD_ENTRY);
        if (result.io.bytesReturned < kHeaderSize)
        {
            result.io.ok = false;
            result.io.message = "DynData fields response too small, bytesReturned=" + std::to_string(result.io.bytesReturned);
            return result;
        }

        const auto* responseHeader = reinterpret_cast<const KSW_QUERY_DYN_FIELDS_RESPONSE*>(responseBuffer.data());
        if (responseHeader->version != KSWORD_ARK_DYNDATA_PROTOCOL_VERSION || responseHeader->entrySize < sizeof(KSW_DYN_FIELD_ENTRY))
        {
            result.io.ok = false;
            result.io.message = "DynData fields response header invalid.";
            return result;
        }

        result.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        result.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        const std::size_t kAvailableCount = (result.io.bytesReturned - kHeaderSize) / static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(static_cast<std::size_t>(responseHeader->returnedCount), kAvailableCount);
        result.entries.reserve(kParsedCount);

        for (std::size_t index = 0U; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset = kHeaderSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (kEntryOffset + sizeof(KSW_DYN_FIELD_ENTRY) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceEntry = reinterpret_cast<const KSW_DYN_FIELD_ENTRY*>(responseBuffer.data() + kEntryOffset);
            DynDataFieldEntry row{};
            row.fieldId = static_cast<std::uint32_t>(sourceEntry->fieldId);
            row.flags = static_cast<std::uint32_t>(sourceEntry->flags);
            row.source = static_cast<std::uint32_t>(sourceEntry->source);
            row.offset = static_cast<std::uint32_t>(sourceEntry->offset);
            row.capabilityMask = static_cast<std::uint64_t>(sourceEntry->capabilityMask);
            row.fieldName = detail::readFixedString(sourceEntry->fieldName, sizeof(sourceEntry->fieldName));
            row.sourceName = detail::readFixedString(sourceEntry->sourceName, sizeof(sourceEntry->sourceName));
            row.featureName = detail::readFixedString(sourceEntry->featureName, sizeof(sourceEntry->featureName));
            result.entries.push_back(std::move(row));
        }

        result.io.message = "DynData fields parsed=" + std::to_string(result.entries.size())
            + ", total=" + std::to_string(result.totalCount);
        return result;
    }

    // applyDynDataProfile:
    // - Pack the R3-parsed JSON profile into an IOCTL request and send it to R0.
    // - Input profile: profile metadata, ntoskrnl identity, and field array;
    // - Return: R0 apply response; io.ok indicates transport/protocol availability, status indicates semantic application result.
    DynDataProfileApplyResult DriverClient::applyDynDataProfile(const DynDataProfileApplyInput& profile) const
    {
        DynDataProfileApplyResult result{};
        if (profile.fields.empty() || profile.fields.size() > KSW_DYN_PROFILE_MAX_FIELDS)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "DynData profile field count invalid.";
            return result;
        }

        const std::size_t kRequestBytes =
            KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE +
            (profile.fields.size() * sizeof(KSW_DYN_PROFILE_FIELD_PACKET));
        if (kRequestBytes > static_cast<std::size_t>(std::numeric_limits<unsigned long>::max()))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "DynData profile request too large.";
            return result;
        }

        std::vector<std::uint8_t> requestBuffer(kRequestBytes, 0U);
        auto* request = reinterpret_cast<KSW_APPLY_DYN_PROFILE_REQUEST*>(requestBuffer.data());
        request->size = static_cast<unsigned long>(kRequestBytes);
        request->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
        request->flags = KSW_DYN_PROFILE_FLAG_TRANSPORT_IOCTL;
        request->fieldCount = static_cast<unsigned long>(profile.fields.size());
        request->ntoskrnl = buildIdentityPacket(profile.ntoskrnl);
        copyDynAnsi(request->profileName, sizeof(request->profileName), profile.profileName);
        copyDynAnsi(request->pdbName, sizeof(request->pdbName), profile.pdbName);
        copyDynAnsi(request->pdbGuid, sizeof(request->pdbGuid), profile.pdbGuid);
        request->pdbAge = static_cast<unsigned long>(profile.pdbAge);

        for (std::size_t index = 0U; index < profile.fields.size(); ++index)
        {
            request->fields[index].fieldId = static_cast<unsigned long>(profile.fields[index].fieldId);
            request->fields[index].offset = static_cast<unsigned long>(profile.fields[index].offset);
        }

        KSW_APPLY_DYN_PROFILE_RESPONSE response{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE) failed, error=" + std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response) || response.version != KSWORD_ARK_DYNDATA_PROTOCOL_VERSION)
        {
            result.io.ok = false;
            result.io.message = "DynData profile apply response invalid, bytesReturned=" + std::to_string(result.io.bytesReturned);
            return result;
        }

        result.status = static_cast<long>(response.status);
        result.appliedFieldCount = static_cast<std::uint32_t>(response.appliedFieldCount);
        result.rejectedFieldCount = static_cast<std::uint32_t>(response.rejectedFieldCount);
        result.unknownFieldCount = static_cast<std::uint32_t>(response.unknownFieldCount);
        result.statusFlags = static_cast<std::uint32_t>(response.statusFlags);
        result.capabilityMask = static_cast<std::uint64_t>(response.capabilityMask);
        result.message = detail::readFixedString(response.message, KSW_DYN_REASON_CHARS);
        result.io.ntStatus = result.status;

        std::ostringstream stream;
        stream << "DynData PDB profile apply status=0x" << std::hex << static_cast<unsigned long>(result.status)
            << std::dec << ", applied=" << result.appliedFieldCount
            << ", rejected=" << result.rejectedFieldCount
            << ", unknown=" << result.unknownFieldCount;
        result.io.message = stream.str();
        return result;
    }

    // applyDynDataProfileEx:
    // - Pack typed items from the R3 v2 profile into an EX IOCTL request and send it to R0.
    // - Input profile: profile metadata, ntoskrnl identity, and GlobalRva/StructOffset items;
    // - Returns: R0 EX apply response; io.ok indicates transport/protocol availability, status indicates semantic application result.
    DynDataProfileApplyExResult DriverClient::applyDynDataProfileEx(const DynDataProfileApplyExInput& profile) const
    {
        DynDataProfileApplyExResult result{};
        if (profile.items.empty() || profile.items.size() > KSW_DYN_PROFILE_EX_MAX_ITEMS)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "DynData profile EX item count invalid.";
            return result;
        }

        const std::size_t kRequestBytes =
            KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE +
            (profile.items.size() * sizeof(KSW_DYN_PROFILE_EX_ITEM_PACKET));
        if (kRequestBytes > static_cast<std::size_t>(std::numeric_limits<unsigned long>::max()))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "DynData profile EX request too large.";
            return result;
        }

        std::vector<std::uint8_t> requestBuffer(kRequestBytes, 0U);
        auto* request = reinterpret_cast<KSW_APPLY_DYN_PROFILE_EX_REQUEST*>(requestBuffer.data());
        request->size = static_cast<unsigned long>(kRequestBytes);
        request->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
        request->flags = KSW_DYN_PROFILE_FLAG_TRANSPORT_IOCTL;
        request->itemCount = static_cast<unsigned long>(profile.items.size());
        request->ntoskrnl = buildIdentityPacket(profile.ntoskrnl);
        copyDynAnsi(request->profileName, sizeof(request->profileName), profile.profileName);
        copyDynAnsi(request->pdbName, sizeof(request->pdbName), profile.pdbName);
        copyDynAnsi(request->pdbGuid, sizeof(request->pdbGuid), profile.pdbGuid);
        request->pdbAge = static_cast<unsigned long>(profile.pdbAge);

        for (std::size_t index = 0U; index < profile.items.size(); ++index)
        {
            request->items[index].itemId = static_cast<unsigned long>(profile.items[index].itemId);
            request->items[index].itemKind = static_cast<unsigned long>(profile.items[index].itemKind);
            request->items[index].value = static_cast<unsigned long>(profile.items[index].value);
            request->items[index].flags = static_cast<unsigned long>(profile.items[index].flags);
        }

        KSW_APPLY_DYN_PROFILE_EX_RESPONSE response{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!result.io.ok)
        {
            result.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX) failed, error=" + std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < sizeof(response) || response.version != KSWORD_ARK_DYNDATA_PROTOCOL_VERSION)
        {
            result.io.ok = false;
            result.io.message = "DynData profile EX apply response invalid, bytesReturned=" + std::to_string(result.io.bytesReturned);
            return result;
        }

        result.status = static_cast<long>(response.status);
        result.appliedItemCount = static_cast<std::uint32_t>(response.appliedItemCount);
        result.rejectedItemCount = static_cast<std::uint32_t>(response.rejectedItemCount);
        result.unknownItemCount = static_cast<std::uint32_t>(response.unknownItemCount);
        result.statusFlags = static_cast<std::uint32_t>(response.statusFlags);
        result.capabilityMask = static_cast<std::uint64_t>(response.capabilityMask);
        result.message = detail::readFixedString(response.message, KSW_DYN_REASON_CHARS);
        result.io.ntStatus = result.status;

        std::ostringstream stream;
        stream << "DynData PDB profile EX apply status=0x" << std::hex << static_cast<unsigned long>(result.status)
            << std::dec << ", applied=" << result.appliedItemCount
            << ", rejected=" << result.rejectedItemCount
            << ", unknown=" << result.unknownItemCount;
        result.io.message = stream.str();
        return result;
    }
}
