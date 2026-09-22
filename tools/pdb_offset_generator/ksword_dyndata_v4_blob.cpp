// Package a v4 profile manifest into the raw blob consumed by KswordCLI `dyn apply-profile-v4 --blob`.
//
// Why it's needed: JSON parsing for packing is currently only available in the GUI (using Qt's JSON); the CLI cannot use it.
// Thus, on a target machine with only the driver and CLI, **there is no way to load the PDB profile into the
// driver** — the practical consequence is that `_EPROCESS.VadRoot` remains Unavailable. The VAD view appears to say
// "this build lacks an offset table," but the reality is "the offset table is in the package, just not applied."
//
// The split is intentional: **binary layout appears only here**. Populate directly from the product header's structs; do not
// manually copy byte-by-byte elsewhere (the manual copy will inevitably drift from the header, and drift goes undetected).
// The JSON portion is handled by Python; it only outputs a plain text manifest.
//
// Manifest format (one entry per line, lines starting with # are comments):
//   profile      <profileName>
//   pdbName      <name>
//   pdbGuid      <32 hex>
//   pdbAge       <n>
//   moduleName   <name>
//   machine      <n>
//   timeDateStamp <n>
//   sizeOfImage  <n>
//   imageBase <n> (0 indicates no declaration)
//   classId      <n>
//   flags        <n>
//   group <groupId> <flags> <requiredItemCount> <optionalItemCount> <groupName>
//   item  <itemId> <itemKind> <flags> <capabilityGroupId> <valueLow> <valueHigh> <aux0..aux3>
//   field <fieldId> <offset> (for legacy/v1)
//
// Two package types: `--v4` (default) sets APPLY_DYN_PROFILE_V4, while `--v1` sets APPLY_DYN_PROFILE.
// **Both must be sent**: v4 entries go into an independent v4 store (the message is 'accepted for safe storage'); they do
// not write to `State->Kernel.*`. The injection_vad.c module reads exactly the latter, which is only populated by v1 apply.
// If only v4 is sent, apply reports success for both 113/113, yet `_EPROCESS.VadRoot` remains Unavailable.

#include <Windows.h>

#include "../../shared/driver/KswordArkDynDataIoctl.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    void copyNarrow(char* const destination, const std::size_t capacity, const std::string& text)
    {
        std::memset(destination, 0, capacity);
        const std::size_t kCount = text.size() < (capacity - 1U) ? text.size() : (capacity - 1U);
        std::memcpy(destination, text.c_str(), kCount);
    }

    void copyWide(wchar_t* const destination, const std::size_t capacity, const std::string& text)
    {
        std::memset(destination, 0, capacity * sizeof(wchar_t));
        const int kWritten = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, destination,
                                                  static_cast<int>(capacity));
        if (kWritten <= 0)
        {
            destination[0] = L'\0';
        }
        destination[capacity - 1U] = L'\0';
    }
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::printf("usage: %s <manifest> <output-blob> [--v1|--v4]\n", argv[0]);
        std::printf("layout: v4-header=%zu item=%zu group=%zu module=%zu v1-header=%zu field=%zu\n",
                    static_cast<std::size_t>(KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE),
                    sizeof(KSW_DYN_V4_ITEM_PACKET),
                    sizeof(KSW_DYN_V4_CAPABILITY_GROUP_PACKET),
                    sizeof(KSW_DYN_V4_MODULE_IDENTITY_PACKET),
                    static_cast<std::size_t>(KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE),
                    sizeof(KSW_DYN_PROFILE_FIELD_PACKET));
        return 2;
    }
    const bool kLegacyMode = (argc > 3) && (std::strcmp(argv[3], "--v1") == 0);

    std::ifstream manifest(argv[1]);
    if (!manifest.is_open())
    {
        std::printf("cannot open manifest: %s\n", argv[1]);
        return 3;
    }

    std::string profileName, pdbName, pdbGuid, moduleName;
    unsigned long pdbAge = 0U, machine = 0U, timeDateStamp = 0U, sizeOfImage = 0U;
    unsigned long classId = 0U, requestFlags = 0U;
    unsigned long long imageBase = 0ULL;
    std::vector<KSW_DYN_V4_CAPABILITY_GROUP_PACKET> groups;
    std::vector<KSW_DYN_V4_ITEM_PACKET> items;
    std::vector<KSW_DYN_PROFILE_FIELD_PACKET> legacyFields;

    std::string line;
    while (std::getline(manifest, line))
    {
        if (line.empty() || line[0] == '#')
        {
            continue;
        }
        std::istringstream stream(line);
        std::string key;
        stream >> key;
        if (key == "profile") { std::getline(stream >> std::ws, profileName); }
        else if (key == "pdbName") { stream >> pdbName; }
        else if (key == "pdbGuid") { stream >> pdbGuid; }
        else if (key == "pdbAge") { stream >> pdbAge; }
        else if (key == "moduleName") { stream >> moduleName; }
        else if (key == "machine") { stream >> machine; }
        else if (key == "timeDateStamp") { stream >> timeDateStamp; }
        else if (key == "sizeOfImage") { stream >> sizeOfImage; }
        else if (key == "imageBase") { stream >> imageBase; }
        else if (key == "classId") { stream >> classId; }
        else if (key == "flags") { stream >> requestFlags; }
        else if (key == "group")
        {
            KSW_DYN_V4_CAPABILITY_GROUP_PACKET group{};
            std::string name;
            stream >> group.groupId >> group.flags >> group.requiredItemCount >>
                group.optionalItemCount;
            std::getline(stream >> std::ws, name);
            copyNarrow(group.groupName, KSW_DYN_V4_CAPABILITY_NAME_CHARS, name);
            groups.push_back(group);
        }
        else if (key == "item")
        {
            KSW_DYN_V4_ITEM_PACKET item{};
            stream >> item.itemId >> item.itemKind >> item.flags >> item.capabilityGroupId >>
                item.valueLow >> item.valueHigh >> item.aux0 >> item.aux1 >> item.aux2 >>
                item.aux3;
            items.push_back(item);
        }
        else if (key == "field")
        {
            KSW_DYN_PROFILE_FIELD_PACKET field{};
            stream >> field.fieldId >> field.offset;
            legacyFields.push_back(field);
        }
        else
        {
            std::printf("unknown manifest key: %s\n", key.c_str());
            return 4;
        }
    }

    if (kLegacyMode)
    {
        if (legacyFields.empty() || legacyFields.size() > KSW_DYN_PROFILE_MAX_FIELDS)
        {
            std::printf("legacy field count invalid: %zu\n", legacyFields.size());
            return 5;
        }
        const std::size_t kLegacyBytes = KSW_APPLY_DYN_PROFILE_REQUEST_HEADER_SIZE +
                                        legacyFields.size() * sizeof(KSW_DYN_PROFILE_FIELD_PACKET);
        std::vector<unsigned char> legacyBuffer(kLegacyBytes, 0U);
        auto* const kLegacy =
            reinterpret_cast<KSW_APPLY_DYN_PROFILE_REQUEST*>(legacyBuffer.data());
        kLegacy->size = static_cast<unsigned long>(kLegacyBytes);
        kLegacy->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
        kLegacy->flags = requestFlags;
        kLegacy->fieldCount = static_cast<unsigned long>(legacyFields.size());
        kLegacy->ntoskrnl.present = 1UL;
        kLegacy->ntoskrnl.classId = classId;
        kLegacy->ntoskrnl.machine = machine;
        kLegacy->ntoskrnl.timeDateStamp = timeDateStamp;
        kLegacy->ntoskrnl.sizeOfImage = sizeOfImage;
        kLegacy->ntoskrnl.imageBase = imageBase;
        copyWide(kLegacy->ntoskrnl.moduleName, KSW_DYN_MODULE_NAME_CHARS, moduleName);
        copyNarrow(kLegacy->profileName, KSW_DYN_PROFILE_NAME_CHARS, profileName);
        copyNarrow(kLegacy->pdbName, KSW_DYN_PDB_NAME_CHARS, pdbName);
        copyNarrow(kLegacy->pdbGuid, KSW_DYN_PDB_GUID_CHARS, pdbGuid);
        kLegacy->pdbAge = pdbAge;
        for (std::size_t index = 0U; index < legacyFields.size(); ++index)
        {
            kLegacy->fields[index] = legacyFields[index];
        }
        std::ofstream legacyOutput(argv[2], std::ios::binary | std::ios::trunc);
        if (!legacyOutput.is_open())
        {
            std::printf("cannot write blob: %s\n", argv[2]);
            return 6;
        }
        legacyOutput.write(reinterpret_cast<const char*>(legacyBuffer.data()),
                           static_cast<std::streamsize>(legacyBuffer.size()));
        std::printf("wrote %zu bytes (v1): fields=%zu profile='%s'\n", kLegacyBytes,
                    legacyFields.size(), profileName.c_str());
        return 0;
    }

    if (items.empty() || items.size() > KSW_DYN_V4_MAX_ITEMS_PER_MODULE ||
        groups.size() > KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE)
    {
        std::printf("item/group count invalid: items=%zu groups=%zu\n", items.size(),
                    groups.size());
        return 5;
    }

    const std::size_t kBytes =
        KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE + items.size() * sizeof(KSW_DYN_V4_ITEM_PACKET);
    std::vector<unsigned char> buffer(kBytes, 0U);
    auto* const kRequest = reinterpret_cast<KSW_APPLY_DYN_PROFILE_V4_REQUEST*>(buffer.data());
    kRequest->size = static_cast<unsigned long>(kBytes);
    kRequest->version = KSW_DYN_V4_PROTOCOL_VERSION;
    kRequest->flags = requestFlags;
    kRequest->itemCount = static_cast<unsigned long>(items.size());
    kRequest->capabilityGroupCount = static_cast<unsigned long>(groups.size());

    kRequest->module.image.present = 1UL;
    kRequest->module.image.classId = classId;
    kRequest->module.image.machine = machine;
    kRequest->module.image.timeDateStamp = timeDateStamp;
    kRequest->module.image.sizeOfImage = sizeOfImage;
    kRequest->module.image.imageBase = imageBase;
    copyWide(kRequest->module.image.moduleName, KSW_DYN_MODULE_NAME_CHARS, moduleName);
    copyNarrow(kRequest->module.pdb.pdbName, KSW_DYN_PDB_NAME_CHARS, pdbName);
    copyNarrow(kRequest->module.pdb.pdbGuid, KSW_DYN_PDB_GUID_CHARS, pdbGuid);
    kRequest->module.pdb.pdbAge = pdbAge;
    copyNarrow(kRequest->module.profileName, KSW_DYN_V4_PROFILE_NAME_CHARS, profileName);

    for (std::size_t index = 0U; index < groups.size(); ++index)
    {
        kRequest->capabilityGroups[index] = groups[index];
    }
    for (std::size_t index = 0U; index < items.size(); ++index)
    {
        kRequest->items[index] = items[index];
    }

    std::ofstream output(argv[2], std::ios::binary | std::ios::trunc);
    if (!output.is_open())
    {
        std::printf("cannot write blob: %s\n", argv[2]);
        return 6;
    }
    output.write(reinterpret_cast<const char*>(buffer.data()),
                 static_cast<std::streamsize>(buffer.size()));
    output.close();

    std::printf("wrote %zu bytes: items=%zu groups=%zu profile='%s'\n", kBytes, items.size(),
                groups.size(), profileName.c_str());
    return 0;
}
