#pragma once

#include "ArkDriverTypes.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ksword::ark
{
    // RuntimeDynDataResolveResult is an optional precise PDB resolution result for development builds.
    // Input: Current module PE identity returned by R0, plus symbol names additionally required by the caller.
    // Processing: Validate the local PE identity, load the exact PDB for that PE via a serial DbgHelp session,
    //       and then generate v1/EX/v4 apply inputs using the same field directory as the offline generator.
    // Return behavior: Caller may issue apply inputs only if valid=true; on failure, only diagnostics are provided, with no guessing of cross-version offsets.
    struct RuntimeDynDataResolveResult
    {
        bool attempted = false;
        bool imageIdentityMatched = false;
        bool pdbIdentityAvailable = false;
        bool valid = false;
        std::wstring imagePath;
        std::wstring pdbPath;
        std::wstring diagnostics;
        std::uint32_t resolvedFieldCount = 0;
        std::uint32_t resolvedTypedItemCount = 0;
        std::uint32_t resolvedV4ItemCount = 0;
        DynDataProfileApplyInput profile;
        DynDataProfileApplyExInput profileEx;
        DynDataV4ApplyInput profileV4;
        std::unordered_map<std::string, std::uint32_t> symbolRvas;
    };

    // resolveRuntimeDynDataProfile currently returns an empty result according to offline product policy; when the pack is not
    // hit, only the bundled matrix or local feature codes can be used. No build is allowed to download PDBs on the target machine.
    RuntimeDynDataResolveResult resolveRuntimeDynDataProfile(
        const ArkDynModuleIdentity& identity,
        const std::vector<std::string>& extraSymbolNames = {});
}
