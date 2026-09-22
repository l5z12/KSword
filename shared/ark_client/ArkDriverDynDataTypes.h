#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "ArkDriverIoTypes.h"
#include "../driver/KswordArkDynDataIoctl.h"

namespace ksword::ark
{
    // ArkDynModuleIdentity is the module identity display structure on the R3 side.
    struct ArkDynModuleIdentity
    {
        bool present = false;
        std::uint32_t classId = 0;
        std::uint32_t machine = 0;
        std::uint32_t timeDateStamp = 0;
        std::uint32_t sizeOfImage = 0;
        std::uint64_t imageBase = 0;
        std::wstring moduleName;
    };

    // DynDataStatusResult: Carries R0 DynData status and matching diagnostics.
    struct DynDataStatusResult
    {
        IoResult io;
        std::uint32_t statusFlags = 0;
        std::uint32_t systemInformerDataVersion = 0;
        std::uint32_t systemInformerDataLength = 0;
        long lastStatus = 0;
        std::uint32_t matchedProfileClass = 0;
        std::uint32_t matchedProfileOffset = 0;
        std::uint32_t matchedFieldsId = 0;
        std::uint32_t fieldCount = 0;
        std::uint64_t capabilityMask = 0;
        ArkDynModuleIdentity ntoskrnl;
        ArkDynModuleIdentity lxcore;
        std::wstring unavailableReason;
    };

    // DynDataFieldEntry is the R3-side field row model.
    struct DynDataFieldEntry
    {
        std::uint32_t fieldId = 0;
        std::uint32_t flags = 0;
        std::uint32_t source = 0;
        std::uint32_t offset = 0;
        std::uint64_t capabilityMask = 0;
        std::string fieldName;
        std::string sourceName;
        std::string featureName;
    };

    // DynDataFieldsResult carries the field list response.
    struct DynDataFieldsResult
    {
        IoResult io;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::vector<DynDataFieldEntry> entries;
    };

    // DynDataCapabilitiesResult carries the response for a lightweight capability query.
    struct DynDataCapabilitiesResult
    {
        IoResult io;
        std::uint32_t statusFlags = 0;
        std::uint64_t capabilityMask = 0;
    };

    // DynDataProfileField is a single field packet after parsing the R3 JSON profile.
    // Input: fieldId/offset comes from profiles/ark_dyndata JSON.
    // Note: ArkDriverClient packs this array into KSW_APPLY_DYN_PROFILE_REQUEST.
    // Return behavior: The structure itself has no return value; it serves solely as input for applyDynDataProfile.
    struct DynDataProfileField
    {
        std::uint32_t fieldId = 0;
        std::uint32_t offset = 0;
    };

    // DynDataProfileExItem is a typed item after expanding the v2 profile pack.
    // Input: itemId, itemKind, value, and flags come from the R3 JSON pack validation result.
    // Note: ArkDriverClient performs only packed IOCTL transmission; semantic validation is handled by the R3/R0 dual layers.
    // Return behavior: The structure itself has no return value; it serves only as an input element for applyDynDataProfileEx.
    struct DynDataProfileExItem
    {
        std::uint32_t itemId = 0;
        std::uint32_t itemKind = 0;
        std::uint32_t value = 0;
        std::uint32_t flags = 0;
    };

    // DynDataProfileApplyInput is the R3 input model for the driver's apply IOCTL.
    // Input: profile metadata, current ntoskrnl identity, and field list.
    // Handling: The client is responsible only for protocol packaging, not JSON semantic parsing.
    // Return behavior: Invoke applyDynDataProfile to obtain DynDataProfileApplyResult.
    struct DynDataProfileApplyInput
    {
        std::string profileName;
        std::string pdbName;
        std::string pdbGuid;
        std::uint32_t pdbAge = 0;
        ArkDynModuleIdentity ntoskrnl;
        std::vector<DynDataProfileField> fields;
    };

    // DynDataProfileApplyResult carries the fixed response after merging R0 with the PDB profile.
    // Input: none, returned by DriverClient::applyDynDataProfile.
    // Note: Stores R0 validation result, applied field count, status bits, and message.
    // Return behavior: io.ok indicates IOCTL call and protocol response are available; status indicates R0 semantic result.
    struct DynDataProfileApplyResult
    {
        IoResult io;
        long status = 0;
        std::uint32_t appliedFieldCount = 0;
        std::uint32_t rejectedFieldCount = 0;
        std::uint32_t unknownFieldCount = 0;
        std::uint32_t statusFlags = 0;
        std::uint64_t capabilityMask = 0;
        std::wstring message;
    };

    // DynDataProfileApplyExInput is the R3 input model for v2 typed item apply.
    // Input: profile metadata, current ntoskrnl identity, and v2 items.
    // Processing: Client packages data into KSW_APPLY_DYN_PROFILE_EX_REQUEST.
    // Return behavior: Returns DynDataProfileApplyExResult after calling applyDynDataProfileEx.
    struct DynDataProfileApplyExInput
    {
        std::string profileName;
        std::string pdbName;
        std::string pdbGuid;
        std::uint32_t pdbAge = 0;
        ArkDynModuleIdentity ntoskrnl;
        std::vector<DynDataProfileExItem> items;
    };

    // DynDataProfileApplyExResult carries the response after R0 merges v2 typed items.
    // Input: None; returned by DriverClient::applyDynDataProfileEx.
    // Processing: Save item-level apply/reject/unknown counts, status bits, and capabilities.
    // Return behavior: io.ok indicates IOCTL call and protocol response are available; status indicates R0 semantic result.
    struct DynDataProfileApplyExResult
    {
        IoResult io;
        long status = 0;
        std::uint32_t appliedItemCount = 0;
        std::uint32_t rejectedItemCount = 0;
        std::uint32_t unknownItemCount = 0;
        std::uint32_t statusFlags = 0;
        std::uint64_t capabilityMask = 0;
        std::wstring message;
    };

    // DriverFeatureCapabilityEntry is a row in the unified capability matrix (R3 model).
    struct DriverFeatureCapabilityEntry
    {
        std::uint32_t featureId = 0;
        std::uint32_t state = 0;
        std::uint32_t flags = 0;
        std::uint32_t requiredPolicyFlags = 0;
        std::uint32_t deniedPolicyFlags = 0;
        std::uint64_t requiredDynDataMask = 0;
        std::uint64_t presentDynDataMask = 0;
        std::string featureName;
        std::string stateName;
        std::string dependencyText;
        std::string reasonText;
    };

    // DriverCapabilitiesQueryResult carries the Phase 1 unified capabilities query response.
    struct DriverCapabilitiesQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t driverProtocolVersion = 0;
        std::uint32_t statusFlags = 0;
        std::uint32_t securityPolicyFlags = 0;
        std::uint32_t dynDataStatusFlags = 0;
        long lastErrorStatus = 0;
        std::uint32_t totalFeatureCount = 0;
        std::uint32_t returnedFeatureCount = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::string lastErrorSource;
        std::string lastErrorSummary;
        std::vector<DriverFeatureCapabilityEntry> entries;
    };

    // DynDataV4ApplyInput is the R3 packed input for a v4 PDB profile.
    // Input: module/capabilityGroups/items come from a validated profile generated by the PDB extractor.
    // Note: ArkDriverClient is responsible only for length validation and protocol transmission.
    // Return behavior: After calling applyDynDataProfileV4, obtain DynDataV4ApplyResult.
    struct DynDataV4ApplyInput
    {
        KSW_DYN_V4_MODULE_IDENTITY_PACKET module{};
        std::vector<KSW_DYN_V4_CAPABILITY_GROUP_PACKET> capabilityGroups;
        std::vector<KSW_DYN_V4_ITEM_PACKET> items;
        std::uint32_t flags = 0;
    };

    // DynDataV4ApplyResult carries the fixed response received by R0 after applying a v4 module profile.
    // Input: None, returned by applyDynDataProfileV4.
    // Handling: response preserves module identity, statusFlags, capabilityMask, and messages.
    // Return behavior: io.ok indicates transport/protocol success; unsupported indicates the old driver lacks a v4 entry.
    struct DynDataV4ApplyResult
    {
        IoResult io;
        bool unsupported = false;
        KSW_APPLY_DYN_PROFILE_V4_RESPONSE response{};
    };

    // DynDataV4ModulesResult carries the status of loaded v4 module profiles.
    // Input: Return value of queryDynDataV4Modules.
    // Note: entries store the status of each module's class, profile, status, and capability.
    // Return behavior: Read-only query of the current R0 v4 profile cache.
    struct DynDataV4ModulesResult : VariableAuditResultBase
    {
        std::vector<KSW_DYN_V4_MODULE_STATUS_ENTRY> entries;
    };

    // DynDataV4CapabilityGroupsResult carries the integrity status of v4 capability groups.
    // Input: Return value of queryDynDataV4CapabilityGroups.
    // Note: entries store counts for required, optional present, and missing items.
    // Return behavior: read-only display of profile gaps.
    struct DynDataV4CapabilityGroupsResult : VariableAuditResultBase
    {
        std::vector<KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY> entries;
    };

    // DynDataV4MissingItemsResult carries the summary of v4 required/optional missing items.
    // Input: Return value of queryDynDataV4MissingItems.
    // Handling: entries store itemName/reason for UI to display missing profile items.
    // Return behavior: read-only query; does not modify DynData state.
    struct DynDataV4MissingItemsResult : VariableAuditResultBase
    {
        std::vector<KSW_DYN_V4_MISSING_ITEM_ENTRY> entries;
    };

    // DynDataV4ItemsResult: Carries a read-only list of accepted v4 items.
    // Input: return value of queryDynDataV4Items.
    // Processing: entries store moduleClassId, itemIndex, and the complete KSW_DYN_V4_ITEM_PACKET.
    // Return behavior: read-only query; does not reapply the profile, nor does it attach the item to the business path.
    struct DynDataV4ItemsResult : VariableAuditResultBase
    {
        std::vector<KSW_DYN_V4_ITEM_STATUS_ENTRY> entries;
    };
}
