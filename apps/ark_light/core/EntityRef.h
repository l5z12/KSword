#pragma once

#include <cstdint>
#include <string>

namespace ksword::core {

enum class EntityKind {
    kNone,
    kModule,
    kProcess,
    kThread,
    kFile,
    kRegistryKey,
    kWindow,
    kDriver,
    kNetworkEndpoint
};

enum class NavigationTarget {
    kDefault,
    kProcessDetails,
    kMemoryOperations,
    kFileBrowser,
    kRegistryBrowser,
    kNetworkConnections,
    kHandleTable,
    kWindowManager,
    kEtwMonitor
};

// EntityRef identifies the same system entity across pages. Process and thread
// identities may include a creation time; text carries a path, module title or
// endpoint tuple without weakening the numeric identity fields.
struct EntityRef final {
    EntityKind kind = EntityKind::kNone;
    std::uint64_t id = 0;
    std::uint64_t parentId = 0;
    std::uint64_t creationTime100ns = 0;
    std::wstring text;
};

struct NavigationRequest final {
    NavigationTarget target = NavigationTarget::kDefault;
    EntityRef entity;
};

enum class CommandInputKind {
    kInvalid,
    kNavigation,
    kShell
};

struct CommandInputResult final {
    CommandInputKind kind = CommandInputKind::kInvalid;
    NavigationRequest navigation;
    std::wstring shellCommand;
    std::wstring error;
};

// parseCommandInput implements the Lite command palette grammar. A leading !
// is the only shell escape; all other recognized prefixes produce a typed
// navigation request so arbitrary text is never silently executed.
CommandInputResult parseCommandInput(const std::wstring& input);

} // namespace Ksword::Core
