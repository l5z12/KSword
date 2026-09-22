#pragma once

// ============================================================
// ksword/startup/startup.h
// Namespace: ks::startup
// Purpose:
// - Provide a non-UI startup persistence enumeration backend.
// - Keep records in UTF-8 std::string fields so Qt and non-Qt callers can adapt them.
// - Avoid UI framework dependencies in this layer.
// ============================================================

#include <cstddef>    // std::size_t: enumeration stage coordinates.
#include <cstdint>    // std::uint32_t: Win32 result and status placeholders.
#include <functional> // std::function: optional enumeration progress callback.
#include <string>     // std::string: UTF-8 text fields exposed across layers.
#include <vector>     // std::vector: startup record and catalog containers.

namespace ks::startup
{
    // StartupCategory describes the logical startup source family.
    enum class StartupCategory : int
    {
        kAll = 0,
        kLogon,
        kServices,
        kDrivers,
        kTasks,
        kImageHijack,
        kRegistry,
        kWmi,
        kHidden // Cross-view findings: objects one Windows view exposes and another one hides.
    };

    // StartupEnumerationStage identifies the active source family during a full enumeration pass.
    // It is intentionally UI-neutral; callers map the stable stage to their own localized text.
    enum class StartupEnumerationStage : int
    {
        kLogon = 0,
        kServices,
        kDrivers,
        kTasks,
        kImageHijack,
        kAdvancedRegistry,
        kWinsock,
        kWmi,
        kHidden
    };

    // StartupEnumerationProgressCallback runs immediately before each source family is enumerated.
    // stageIndex is zero-based and stageCount is the total number of source families in the pass.
    using StartupEnumerationProgressCallback = std::function<void(
        StartupEnumerationStage stage,
        std::size_t stageIndex,
        std::size_t stageCount)>;

    // StartupActionKind identifies a backend operation without parsing display text.
    enum class StartupActionKind : int
    {
        kNone = 0,
        kRegistryRunValue,
        kRegistryTree,
        kStartupFolderFile,
        kScheduledTask,
        kScmStartType,
        kWmiEntryRemoval
    };

    // StartupRegistryRoot identifies the registry hives accepted by warning-gated value actions.
    enum class StartupRegistryRoot : int
    {
        kNone = 0,
        kCurrentUser,
        kLocalMachine
    };

    // StartupScmStartMode preserves the native SCM mode instead of collapsing Manual into Disabled.
    enum class StartupScmStartMode : int
    {
        kNone = 0,
        kBoot,
        kSystem,
        kAutomatic,
        kManual,
        kDisabled
    };

    // StartupRiskLevel lets UI layers select warning treatment without parsing diagnostics.
    enum class StartupRiskLevel : int
    {
        kNormal = 0,
        kElevated,
        kCritical
    };

    // StartupActionLocator contains machine-readable action coordinates.
    // Only fields relevant to actionKind are populated.
    struct StartupActionLocator
    {
        StartupRegistryRoot registryRoot = StartupRegistryRoot::kNone;
        std::string registrySubKeyText;
        std::string registryValueNameText;
        bool registryValueSnapshotValid = false;
        std::uint32_t registryValueType = 0;
        std::vector<std::uint8_t> registryRawData;
        bool registryTreeSnapshotValid = false;
        std::uint32_t registryTreeSubKeyCount = 0;
        std::uint32_t registryTreeValueCount = 0;
        std::uint64_t registryTreeLastWriteTime = 0;
        std::string originalFilePathText;
        std::string parkedFilePathText;
        bool fileIdentitySnapshotValid = false;
        std::uint64_t fileVolumeSerial = 0;
        std::uint64_t fileIndex = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t fileLastWriteTime = 0;
        std::string taskPathText;
        std::string taskNameText;
        std::string taskDefinitionSha256Text;
        std::string serviceNameText;
        bool serviceIsDriver = false;
        StartupScmStartMode serviceStartMode = StartupScmStartMode::kNone;
        std::uint32_t serviceType = 0;
        std::uint32_t serviceStartType = 0;
        std::string serviceBinaryPathText;
        std::string wmiClassNameText;
        std::string wmiNameText;
        std::string wmiFilterText;
        std::string wmiConsumerText;
        std::string backupIdText;
    };

    // StartupEntry is the unified backend record used by every enumerator.
    // All text is UTF-8. UI layers may convert it to their own view model.
    struct StartupEntry
    {
        std::string uniqueIdText;          // Stable identity for cache, deletion, or diagnostics.
        StartupCategory category = StartupCategory::kAll; // Logical category of this entry.
        std::string categoryText;          // Display-ready category text.
        std::string itemNameText;          // Entry display name.
        std::string publisherText;         // Signature/company placeholder or resolved publisher.
        std::string imagePathText;         // Normalized image path when one can be inferred.
        std::string commandText;           // Raw command, registry data, or action text.
        std::string locationText;          // Source location: registry key, SCM name, task path, etc.
        std::string locationGroupText;     // Registry tree group location when applicable.
        std::string registryValueNameText; // Real registry value name for deletion.
        std::string userText;              // User/context text.
        std::string detailText;            // Additional diagnostics or source details.
        std::string sourceTypeText;        // Source subtype such as Run, ScheduledTask, WMI-EventFilter.
        StartupActionKind actionKind = StartupActionKind::kNone; // Structured backend operation.
        StartupActionLocator actionLocator; // Structured coordinates consumed by action APIs.
        bool enabled = true;               // Whether the source is enabled; for SCM, whether it is not Disabled.
        bool canEnable = false;             // Whether setStartupEntryEnabled(entry, true) is supported.
        bool canDisable = false;            // Whether setStartupEntryEnabled(entry, false) is supported.
        StartupRiskLevel riskLevel = StartupRiskLevel::kElevated; // Structured warning severity.
        // Stable i18n codes: registry_user, registry_machine, startup_folder,
        // scheduled_task, backup_record, service, driver, critical_registry,
        // policy, winsock, wmi, unsupported_source.
        std::string riskReasonCode;
        std::string riskReasonText;         // Stable backend warning or unavailability reason.
        bool canOpenFileLocation = false;  // Whether imagePathText can be opened in Explorer.
        bool canOpenRegistryLocation = false; // Whether locationText points to a registry location.
        bool canDelete = false;            // Whether the caller can delete this source entry.
        bool deleteRegistryTree = false;   // True when deletion should remove the whole subkey.
        bool imagePathExists = false;      // Existence placeholder for UI filtering/future checks.
        bool signatureTrusted = false;     // Signature trust placeholder; publisherText is display text.
        std::uint32_t lastErrorCode = 0;   // Optional Win32 error for synthetic/error records.
    };

    // StartupEnumerationStageResultCallback runs after one source family completes and before its
    // records are moved into the aggregate result. The referenced batch is valid only for the
    // duration of the callback; callers that dispatch asynchronously must copy or convert it.
    using StartupEnumerationStageResultCallback = std::function<void(
        StartupEnumerationStage stage,
        std::size_t stageIndex,
        std::size_t stageCount,
        const std::vector<StartupEntry>& stageEntries)>;

    // StartupActionStatus is a caller-facing classification for startup actions.
    enum class StartupActionStatus : int
    {
        kSuccess = 0,
        kNoChange,
        kInvalidEntry,
        kNotSupported,
        kConflict,
        kNotFound,
        kAccessDenied,
        kWriteFailed,
        kVerificationFailed,
        kRollbackFailed,
        kProcessFailed
    };

    // ActionResult reports the primary outcome and whether a failed mutation was rolled back.
    struct ActionResult
    {
        StartupActionStatus status = StartupActionStatus::kInvalidEntry;
        bool success = false;
        bool changed = false;
        bool rollbackAttempted = false;
        bool rollbackSucceeded = false;
        std::uint32_t errorCode = 0;
        std::string messageText;
    };

    // categoryToText returns a stable Chinese display label for a category.
    std::string categoryToText(StartupCategory category);

    // normalizeFilePathText extracts an executable/library/driver path from a command line.
    std::string normalizeFilePathText(const std::string& commandText);

    // queryPublisherTextByPath returns a publisher/signature display string, or empty on failure.
    std::string queryPublisherTextByPath(const std::string& filePathText);

    // normalizeRegistryLocationLine fixes one raw Autoruns-style registry catalog line.
    std::string normalizeRegistryLocationLine(const std::string& rawLineText);

    // buildKnownStartupRegistryLocationList normalizes and de-duplicates raw catalog lines.
    std::vector<std::string> buildKnownStartupRegistryLocationList(
        const std::vector<std::string>& rawLineList);

    // enumerateLogonEntries returns Run/RunOnce/RunOnceEx and Startup Folder records.
    std::vector<StartupEntry> enumerateLogonEntries();

    // enumerateServiceEntries returns Win32 service records with mutable SCM start types.
    std::vector<StartupEntry> enumerateServiceEntries();

    // enumerateDriverEntries returns driver service records with mutable SCM start types.
    std::vector<StartupEntry> enumerateDriverEntries();

    // enumerateTaskEntries returns Scheduled Task records collected through PowerShell.
    std::vector<StartupEntry> enumerateTaskEntries();

    // enumerateImageHijackEntries returns executable redirection and image-load findings from
    // IFEO, filtered IFEO subkeys, Application Verifier DLL settings, and SilentProcessExit.
    std::vector<StartupEntry> enumerateImageHijackEntries();

    // enumerateAdvancedRegistryEntries returns Explorer/Winlogon/LSA/COM style registry persistence.
    std::vector<StartupEntry> enumerateAdvancedRegistryEntries();

    // enumerateWinsockEntries returns Winsock provider/catalog registry records.
    std::vector<StartupEntry> enumerateWinsockEntries();

    // enumerateWmiEntries returns WMI permanent event persistence records.
    std::vector<StartupEntry> enumerateWmiEntries();

    // enumerateHiddenEntries returns persistence that ordinary Win32/COM enumeration cannot see.
    // Findings come from comparing two views of the same object: the native NT registry view against
    // the Win32 view, the registry service database against the SCM, the Task Scheduler registry
    // cache against the Task Scheduler API, the configured Startup folder against the shell default,
    // and per-user class registrations against machine-wide ones.
    // Records are report-only: hidden objects are not addressable through the normal action locators.
    std::vector<StartupEntry> enumerateHiddenEntries();

    // enumerateAllStartupEntries runs every backend enumerator in the standard StartupDock order.
    std::vector<StartupEntry> enumerateAllStartupEntries();

    // Callback overload keeps the backend UI-neutral while allowing a caller to expose each source
    // family as a distinct progress step. The no-argument overload preserves existing callers.
    std::vector<StartupEntry> enumerateAllStartupEntries(
        const StartupEnumerationProgressCallback& progressCallback);

    // Two-callback overload additionally publishes each completed source family as an ordered batch.
    std::vector<StartupEntry> enumerateAllStartupEntries(
        const StartupEnumerationProgressCallback& progressCallback,
        const StartupEnumerationStageResultCallback& stageResultCallback);

    // setStartupEntryEnabled performs a warning-gated operation using actionKind/actionLocator only.
    ActionResult setStartupEntryEnabled(const StartupEntry& entry, bool enabled);

    // deleteStartupEntry permanently removes an entry after revalidating its structured locator.
    ActionResult deleteStartupEntry(const StartupEntry& entry);
}
