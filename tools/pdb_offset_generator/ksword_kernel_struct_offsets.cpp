// Offline kernel structure offset extractor (development tool, not distributed with the product).
//
// Why it's needed: VAD view injection checks, image section object comparisons, and VAD unlinking judgments all require
// structure offsets verified against the target build. The backend for `ksword_pdb_profile_generator.py` is llvm-pdbutil,
// which is not available on this machine. DbgHelp is present, and ArkRuntimeDynData.cpp in the repository has already used
// it to read PDB types for a long time. Here, we reuse the same TI_FINDCHILDREN recipe, just running on the offline side.
//
// **Read local symbol library only, never connect to the network**: The symbol path is hardcoded to the specified directory without
// the `srv*` prefix, so DbgHelp searches only within the standard layout of the local symbol library: <pdb>\<GUID><Age>\<pdb>.
// The product-side policy prohibiting PDB downloads on target machines remains unaffected — this tool is not included in the product.
//
// Usage:
//   ksword_kernel_struct_offsets.exe <pe-path> <symbol-store> [<type>!<member> ...]
//   When type!member is not provided, output the list of fields required for built-in injection checks.
//
// Output is JSON for downstream consumption; fields that fail to parse are explicitly listed in "missing".
// **Do not guess or use values from similar builds**.

#include <Windows.h>
#include <DbgHelp.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#pragma comment(lib, "DbgHelp.lib")

namespace
{
    // All kernel structure fields required for the injection check line.
    // VAD tree traversal requires only EPROCESS.VadRoot; chain-break detection requires the tree pointer in MmvadShort.
    // Image section object comparison requires traversing the chain from VAD to ControlArea/Segment.
    const char* const kWantedFields[] = {
        "_EPROCESS!VadRoot",
        "_EPROCESS!VadHint",
        "_EPROCESS!VadCount",
        "_EPROCESS!UniqueProcessId",
        "_MMVAD_SHORT!VadNode",
        "_MMVAD_SHORT!StartingVpn",
        "_MMVAD_SHORT!EndingVpn",
        "_MMVAD_SHORT!StartingVpnHigh",
        "_MMVAD_SHORT!EndingVpnHigh",
        "_MMVAD_SHORT!u",
        "_MMVAD_SHORT!VadFlags",
        "_MMVAD!Subsection",
        "_MMVAD!FirstPrototypePte",
        "_MMVAD!LastContiguousPte",
        "_RTL_BALANCED_NODE!Left",
        "_RTL_BALANCED_NODE!Right",
        "_RTL_BALANCED_NODE!ParentValue",
        "_RTL_AVL_TREE!Root",
        "_SUBSECTION!ControlArea",
        "_SUBSECTION!SubsectionBase",
        "_SUBSECTION!PtesInSubsection",
        "_SUBSECTION!NextSubsection",
        "_SUBSECTION!StartingSector",
        "_CONTROL_AREA!Segment",
        "_CONTROL_AREA!FilePointer",
        "_CONTROL_AREA!NumberOfSectionReferences",
        "_SEGMENT!ControlArea",
        "_SEGMENT!TotalNumberOfPtes",
        "_SEGMENT!SegmentFlags",
        "_SEGMENT!PrototypePte",
    };

    struct Session final
    {
        HANDLE key = nullptr;
        DWORD64 base = 0U;
        ~Session()
        {
            if (key != nullptr)
            {
                ::SymCleanup(key);
            }
        }
    };

    std::string jsonEscape(const std::string& text)
    {
        std::string out;
        for (const char kCharacter : text)
        {
            switch (kCharacter)
            {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            default: out.push_back(kCharacter); break;
            }
        }
        return out;
    }

    std::string narrow(const wchar_t* const wide)
    {
        if (wide == nullptr)
        {
            return std::string();
        }
        const int kNeeded =
            ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
        if (kNeeded <= 1)
        {
            return std::string();
        }
        std::string out(static_cast<std::size_t>(kNeeded - 1), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), kNeeded, nullptr, nullptr);
        return out;
    }

    struct MemberInfo final
    {
        DWORD offset = 0U;
        DWORD bitPosition = 0U;
        ULONG64 bitLength = 0U;
        bool isBitfield = false;
    };

    // All members of a type: name -> offset.
    bool loadTypeMembers(const Session& session, const std::string& typeName,
                         std::map<std::string, MemberInfo>& membersOut,
                         ULONG64& sizeOut)
    {
        std::vector<std::uint8_t> storage(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char), 0U);
        auto* const kSymbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
        kSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        kSymbol->MaxNameLen = MAX_SYM_NAME;
        if (::SymGetTypeFromName(session.key, session.base, typeName.c_str(), kSymbol) == FALSE)
        {
            return false;
        }
        sizeOut = kSymbol->Size;
        const ULONG kTypeIndex = kSymbol->TypeIndex;

        DWORD childCount = 0U;
        if (::SymGetTypeInfo(session.key, session.base, kTypeIndex, TI_GET_CHILDRENCOUNT,
                             &childCount) == FALSE)
        {
            return false;
        }
        if (childCount == 0U)
        {
            return true;
        }

        const std::size_t kBytes = sizeof(TI_FINDCHILDREN_PARAMS) +
                                  (static_cast<std::size_t>(childCount) - 1U) * sizeof(ULONG);
        std::vector<std::uint8_t> childStorage(kBytes, 0U);
        auto* const kChildren = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(childStorage.data());
        kChildren->Count = childCount;
        kChildren->Start = 0U;
        if (::SymGetTypeInfo(session.key, session.base, kTypeIndex, TI_FINDCHILDREN,
                             kChildren) == FALSE)
        {
            return false;
        }

        for (ULONG index = 0U; index < childCount; ++index)
        {
            const ULONG kChildId = kChildren->ChildId[index];
            wchar_t* rawName = nullptr;
            if (::SymGetTypeInfo(session.key, session.base, kChildId, TI_GET_SYMNAME,
                                 &rawName) == FALSE ||
                rawName == nullptr)
            {
                continue;
            }
            const std::unique_ptr<wchar_t, decltype(&::LocalFree)> kName(rawName, &::LocalFree);

            DWORD offset = 0U;
            if (::SymGetTypeInfo(session.key, session.base, kChildId, TI_GET_OFFSET,
                                 &offset) == FALSE)
            {
                continue;
            }
            MemberInfo info;
            info.offset = offset;
            DWORD bitPosition = 0U;
            if (::SymGetTypeInfo(session.key, session.base, kChildId, TI_GET_BITPOSITION,
                                 &bitPosition) != FALSE)
            {
                ULONG64 bitLength = 0U;
                if (::SymGetTypeInfo(session.key, session.base, kChildId, TI_GET_LENGTH,
                                     &bitLength) != FALSE)
                {
                    info.isBitfield = true;
                    info.bitPosition = bitPosition;
                    info.bitLength = bitLength;
                }
            }
            membersOut.emplace(narrow(kName.get()), info);
        }
        return true;
    }
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        std::printf("usage: %s <pe-path> <symbol-store> [<type>!<member> ...]\n", argv[0]);
        return 2;
    }
    const std::string kPePath = argv[1];
    const std::string kSymbolStore = argv[2];

    std::vector<std::string> wanted;
    for (int index = 3; index < argc; ++index)
    {
        wanted.emplace_back(argv[index]);
    }
    if (wanted.empty())
    {
        for (const char* const kField : kWantedFields)
        {
            wanted.emplace_back(kField);
        }
    }

    // SYMOPT_EXACT_SYMBOLS: fails if GUID/Age mismatch, never accepts adjacent PDB versions.
    // Do not set SYMOPT_DEBUG and do not use srv* prefixes—the search path is limited to the specified local libraries.
    ::SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS |
                    SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_INCLUDE_32BIT_MODULES);

    Session session;
    session.key = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0x4B53574FU));
    if (::SymInitialize(session.key, kSymbolStore.c_str(), FALSE) == FALSE)
    {
        std::printf("{\"error\":\"SymInitialize failed\",\"win32\":%lu}\n", ::GetLastError());
        session.key = nullptr;
        return 3;
    }

    session.base = ::SymLoadModuleEx(session.key, nullptr, kPePath.c_str(), nullptr,
                                     0x10000000ULL, 0U, nullptr, 0U);
    if (session.base == 0U)
    {
        std::printf("{\"error\":\"SymLoadModuleEx failed\",\"win32\":%lu}\n", ::GetLastError());
        return 4;
    }

    IMAGEHLP_MODULEW64 moduleInfo{};
    moduleInfo.SizeOfStruct = sizeof(moduleInfo);
    if (::SymGetModuleInfoW64(session.key, session.base, &moduleInfo) == FALSE)
    {
        std::printf("{\"error\":\"SymGetModuleInfoW64 failed\",\"win32\":%lu}\n", ::GetLastError());
        return 5;
    }
    // SymNone / SymDeferred indicates that symbols failed to load entirely; in this case, any 'offset' is invalid.
    if (moduleInfo.SymType != SymPdb)
    {
        std::printf("{\"error\":\"no PDB loaded\",\"symType\":%d}\n",
                    static_cast<int>(moduleInfo.SymType));
        return 6;
    }

    std::printf("{\n");
    std::printf("  \"pe\": \"%s\",\n", jsonEscape(kPePath).c_str());
    std::printf("  \"pdb\": \"%s\",\n", jsonEscape(narrow(moduleInfo.LoadedPdbName)).c_str());
    std::printf("  \"pdbGuid\": \"%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X\",\n",
                moduleInfo.PdbSig70.Data1, moduleInfo.PdbSig70.Data2, moduleInfo.PdbSig70.Data3,
                moduleInfo.PdbSig70.Data4[0], moduleInfo.PdbSig70.Data4[1],
                moduleInfo.PdbSig70.Data4[2], moduleInfo.PdbSig70.Data4[3],
                moduleInfo.PdbSig70.Data4[4], moduleInfo.PdbSig70.Data4[5],
                moduleInfo.PdbSig70.Data4[6], moduleInfo.PdbSig70.Data4[7]);
    std::printf("  \"pdbAge\": %lu,\n", moduleInfo.PdbAge);
    std::printf("  \"timeDateStamp\": \"0x%08lX\",\n", moduleInfo.TimeDateStamp);
    std::printf("  \"sizeOfImage\": \"0x%08lX\",\n", moduleInfo.ImageSize);

    std::map<std::string, std::map<std::string, MemberInfo>> cache;
    std::map<std::string, ULONG64> typeSizes;
    std::vector<std::string> missing;

    std::printf("  \"fields\": {\n");
    bool first = true;
    for (const std::string& entry : wanted)
    {
        const std::size_t kBang = entry.find('!');
        if (kBang == std::string::npos)
        {
            missing.push_back(entry);
            continue;
        }
        const std::string kTypeName = entry.substr(0U, kBang);
        const std::string kMemberName = entry.substr(kBang + 1U);

        if (cache.find(kTypeName) == cache.end())
        {
            std::map<std::string, MemberInfo> members;
            ULONG64 size = 0U;
            if (!loadTypeMembers(session, kTypeName, members, size))
            {
                cache.emplace(kTypeName, std::map<std::string, MemberInfo>{});
                typeSizes.emplace(kTypeName, 0U);
            }
            else
            {
                cache.emplace(kTypeName, std::move(members));
                typeSizes.emplace(kTypeName, size);
            }
        }
        const auto& members = cache[kTypeName];
        const auto kHit = members.find(kMemberName);
        if (kHit == members.end())
        {
            missing.push_back(entry);
            continue;
        }
        if (!first)
        {
            std::printf(",\n");
        }
        first = false;
        std::printf("    \"%s\": { \"offset\": %lu, \"offsetHex\": \"0x%lX\"",
                    jsonEscape(entry).c_str(), kHit->second.offset, kHit->second.offset);
        if (kHit->second.isBitfield)
        {
            std::printf(", \"bitPosition\": %lu, \"bitLength\": %llu",
                        kHit->second.bitPosition,
                        static_cast<unsigned long long>(kHit->second.bitLength));
        }
        std::printf(" }");
    }
    std::printf("\n  },\n");

    std::printf("  \"typeSizes\": {\n");
    first = true;
    for (const auto& [typeName, size] : typeSizes)
    {
        if (!first)
        {
            std::printf(",\n");
        }
        first = false;
        std::printf("    \"%s\": %llu", jsonEscape(typeName).c_str(),
                    static_cast<unsigned long long>(size));
    }
    std::printf("\n  },\n");

    std::printf("  \"missing\": [");
    for (std::size_t index = 0U; index < missing.size(); ++index)
    {
        std::printf("%s\"%s\"", index == 0U ? "" : ", ", jsonEscape(missing[index]).c_str());
    }
    std::printf("]\n}\n");
    return 0;
}
