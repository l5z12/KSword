#include "../../../apps/ark_light/core/DriverLeasePolicy.h"
#include "../../../apps/ark_light/core/EntityRef.h"
#include "../../../apps/ark_light/core/WorkspaceConfig.h"
#include "../../../apps/ark_light/features/file/PathNavigator.h"
#include "../../../apps/ark_light/features/monitor/EtwEventModel.h"
#include "../../../apps/ark_light/features/registry/RegistrySearchModel.h"
#include "../../../apps/ark_light/features/sys_tools/IoctlDecoder.h"
#include "../../../apps/ark_light/features/window/Win32kTimerEvidenceModel.h"
#include "../../../apps/ark_light/features/memory/MemorySnapshot.h"
#include "../../../apps/ark_light/features/memory/MemoryInspection.h"
#include "../../../apps/ark_light/features/memory/MemoryWritePlan.h"
#include "../../../apps/ark_light/ui/EvidenceSession.h"
#include "../../../shared/ark_client/ArkDriverTypes.h"
#include "TestSupport.h"

#include <array>
#include <clocale>
#include <iostream>
#include <cwchar>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(const bool condition, const wchar_t* label) {
    if (!condition) {
        ++failures;
        std::wcerr << L"FAIL: " << label << L'\n';
    }
}

} // namespace

// Suite entry point for the HOOK patch page construction layer (shared/evidence/HookPatchCompose.h).
// Declarations for the remaining suites are in the manifest of TestSupport.h; this one is left here per division of labor. The main
// session will merge it over. Different locations do not affect the criteria; without it, the entire suite would be silently absent.
int runHookPatchComposeTests();

int wmain() {
    // The default "C" locale for wide-character streams cannot convert non-ASCII wide characters: MSVC sets the badbit on
    // wcout/wcerr at that point and **swallows all subsequent output** — including failure tags from later test suites and
    // the final summary. This has been reproduced on modules with Chinese suite names (output stops after half a line).
    // Switch to UTF-8 locale to enable conversion; on failure, fall back to classic to ensure at least ASCII tags are preserved.
    if (std::setlocale(LC_ALL, ".UTF-8") == nullptr) {
        std::setlocale(LC_ALL, "C");
    }

    using ksword::core::CommandInputKind;
    using ksword::core::DriverLeasePolicy;
    using ksword::core::EntityKind;
    using ksword::core::NavigationTarget;
    using ksword::core::parseCommandInput;
    using ksword::core::WorkspaceCommandId;
    using ksword::core::WorkspaceConfig;
    using ksword::core::WorkspaceConfigDecodeStatus;
    using ksword::features::memory::MemorySnapshotHistory;
    using ksword::features::memory::MemoryReadSnapshot;

    expect(DriverLeasePolicy::ownsStartTransition(false, true), L"new driver start is owned");
    expect(!DriverLeasePolicy::ownsStartTransition(true, true), L"pre-existing driver is not owned");
    expect(DriverLeasePolicy::shouldStopOnLastRelease(true, 0), L"owned driver stops on last lease");
    expect(!DriverLeasePolicy::shouldStopOnLastRelease(true, 1), L"owned driver stays for peer lease");
    expect(!DriverLeasePolicy::shouldStopOnLastRelease(false, 0), L"pre-existing driver stays running");

    WorkspaceConfig workspaceConfig{};
    workspaceConfig.hasNormalRect = true;
    workspaceConfig.normalRect = { -1920, 40, 1200, 1080 };
    workspaceConfig.maximized = true;
    workspaceConfig.activeCommandId = 40010;
    const auto kWorkspaceBinary = ksword::core::serializeWorkspaceConfig(workspaceConfig);
    const auto kWorkspaceRoundTrip = ksword::core::deserializeWorkspaceConfig(kWorkspaceBinary);
    expect(kWorkspaceBinary.size() == ksword::core::kWorkspaceConfigBinarySize &&
            kWorkspaceBinary[0U] == static_cast<std::uint8_t>('K') &&
            kWorkspaceBinary[1U] == static_cast<std::uint8_t>('S') &&
            kWorkspaceBinary[2U] == static_cast<std::uint8_t>('L') &&
            kWorkspaceBinary[3U] == static_cast<std::uint8_t>('W') &&
            kWorkspaceBinary[4U] == 1U && kWorkspaceBinary[5U] == 0U &&
            kWorkspaceBinary[6U] == 36U && kWorkspaceBinary[7U] == 0U &&
            kWorkspaceBinary[8U] == 3U && kWorkspaceBinary[9U] == 0U &&
            kWorkspaceBinary[12U] == 0x80U && kWorkspaceBinary[13U] == 0xF8U &&
            kWorkspaceBinary[14U] == 0xFFU && kWorkspaceBinary[15U] == 0xFFU,
        L"workspace config emits a fixed explicit little-endian binary layout");
    expect(kWorkspaceRoundTrip.valid() && !kWorkspaceRoundTrip.discardedNormalRect &&
            kWorkspaceRoundTrip.config.hasNormalRect &&
            kWorkspaceRoundTrip.config.normalRect.left == -1920 &&
            kWorkspaceRoundTrip.config.normalRect.top == 40 &&
            kWorkspaceRoundTrip.config.normalRect.right == 1200 &&
            kWorkspaceRoundTrip.config.normalRect.bottom == 1080 &&
            kWorkspaceRoundTrip.config.maximized && kWorkspaceRoundTrip.config.activeCommandId == 40010,
        L"workspace config round-trips rectangle maximized and command state");

    auto badMagicWorkspace = kWorkspaceBinary;
    badMagicWorkspace[0U] = static_cast<std::uint8_t>('X');
    auto badVersionWorkspace = kWorkspaceBinary;
    badVersionWorkspace[4U] = 2U;
    auto badDeclaredSizeWorkspace = kWorkspaceBinary;
    badDeclaredSizeWorkspace[6U] = 35U;
    auto badFlagsWorkspace = kWorkspaceBinary;
    badFlagsWorkspace[8U] |= 0x04U;
    auto badReservedWorkspace = kWorkspaceBinary;
    badReservedWorkspace[32U] = 1U;
    const auto kShortWorkspace = ksword::core::deserializeWorkspaceConfig(
        std::span<const std::uint8_t>(kWorkspaceBinary.data(), kWorkspaceBinary.size() - 1U));
    expect(!kShortWorkspace.valid() && kShortWorkspace.status == WorkspaceConfigDecodeStatus::kInvalidLength &&
            ksword::core::deserializeWorkspaceConfig(badMagicWorkspace).status == WorkspaceConfigDecodeStatus::kInvalidMagic &&
            ksword::core::deserializeWorkspaceConfig(badVersionWorkspace).status == WorkspaceConfigDecodeStatus::kUnsupportedVersion &&
            ksword::core::deserializeWorkspaceConfig(badDeclaredSizeWorkspace).status == WorkspaceConfigDecodeStatus::kInvalidDeclaredSize &&
            ksword::core::deserializeWorkspaceConfig(badFlagsWorkspace).status == WorkspaceConfigDecodeStatus::kInvalidFlags &&
            ksword::core::deserializeWorkspaceConfig(badReservedWorkspace).status == WorkspaceConfigDecodeStatus::kInvalidReserved,
        L"workspace config rejects corrupt header flags and reserved bytes");

    auto invalidRectWorkspace = kWorkspaceBinary;
    invalidRectWorkspace[20U] = invalidRectWorkspace[12U];
    invalidRectWorkspace[21U] = invalidRectWorkspace[13U];
    invalidRectWorkspace[22U] = invalidRectWorkspace[14U];
    invalidRectWorkspace[23U] = invalidRectWorkspace[15U];
    const auto kInvalidRectRestore = ksword::core::deserializeWorkspaceConfig(invalidRectWorkspace);
    const std::array<WorkspaceCommandId, 2U> kFallbackModules = { 40001, 40002 };
    expect(kInvalidRectRestore.valid() && kInvalidRectRestore.discardedNormalRect &&
            !kInvalidRectRestore.config.hasNormalRect && kInvalidRectRestore.config.maximized &&
            kInvalidRectRestore.config.activeCommandId == 40010 &&
            ksword::core::resolveWorkspaceCommandId(
                kInvalidRectRestore.config.activeCommandId, kFallbackModules, 40002) == 40002,
        L"workspace restore drops only an invalid rectangle and independently falls back the command");

    const std::array<WorkspaceCommandId, 4U> kOriginalModuleOrder = { 40001, 40010, 40011, 40018 };
    const std::array<WorkspaceCommandId, 4U> kReorderedModules = { 40018, 40011, 40001, 40010 };
    expect(ksword::core::resolveWorkspaceCommandId(40011, kOriginalModuleOrder, 40001) == 40011 &&
            ksword::core::resolveWorkspaceCommandId(40011, kReorderedModules, 40001) == 40011 &&
            ksword::core::resolveWorkspaceCommandId(49999, kOriginalModuleOrder) == 40001 &&
            ksword::core::resolveWorkspaceCommandId(49999, kReorderedModules) == 40001,
        L"workspace command restore uses stable ids rather than module indexes or order");

    const auto kProcess = parseCommandInput(L" pid 1234 ");
    expect(kProcess.kind == CommandInputKind::kNavigation, L"pid command navigates");
    expect(kProcess.navigation.target == NavigationTarget::kProcessDetails, L"pid target");
    expect(kProcess.navigation.entity.kind == EntityKind::kProcess && kProcess.navigation.entity.id == 1234,
        L"pid entity identity");

    const auto kMemory = parseCommandInput(L"mem 4321");
    expect(kMemory.kind == CommandInputKind::kNavigation &&
            kMemory.navigation.target == NavigationTarget::kMemoryOperations &&
            kMemory.navigation.entity.kind == EntityKind::kProcess && kMemory.navigation.entity.id == 4321U,
        L"memory command targets explicit process operations");
    const auto kMemoryModule = parseCommandInput(L"内存");
    expect(kMemoryModule.kind == CommandInputKind::kNavigation && kMemoryModule.navigation.target == NavigationTarget::kDefault &&
            kMemoryModule.navigation.entity.kind == EntityKind::kModule,
        L"plain memory title still opens the module without a target");

    const auto kWindow = parseCommandInput(L"hwnd 0xABC");
    expect(kWindow.navigation.target == NavigationTarget::kWindowManager && kWindow.navigation.entity.id == 0xABCU,
        L"hex HWND command");

    const auto kFile = parseCommandInput(L"file C:\\Windows\\System32\\ntdll.dll");
    expect(kFile.navigation.target == NavigationTarget::kFileBrowser &&
        kFile.navigation.entity.text == L"C:\\Windows\\System32\\ntdll.dll", L"file command");

    const auto kModule = parseCommandInput(L"网络");
    expect(kModule.navigation.entity.kind == EntityKind::kModule && kModule.navigation.entity.text == L"网络",
        L"plain module title");
    const auto kEnglishModule = parseCommandInput(L"process");
    expect(kEnglishModule.kind == CommandInputKind::kNavigation &&
            kEnglishModule.navigation.entity.kind == EntityKind::kModule &&
            kEnglishModule.navigation.entity.text == L"进程",
        L"bare English module alias resolves to a registry title");
    const auto kFileModule = parseCommandInput(L"file");
    expect(kFileModule.kind == CommandInputKind::kNavigation &&
            kFileModule.navigation.entity.kind == EntityKind::kModule &&
            kFileModule.navigation.entity.text == L"文件",
        L"bare file alias opens its module instead of requiring a path");

    const auto kShell = parseCommandInput(L"! whoami /all");
    expect(kShell.kind == CommandInputKind::kShell && kShell.shellCommand == L"whoami /all", L"explicit shell escape");
    expect(parseCommandInput(L"pid zero").kind == CommandInputKind::kInvalid, L"invalid pid rejected");
    expect(parseCommandInput(L"pid 4294967296").kind == CommandInputKind::kInvalid &&
            parseCommandInput(L"tid 0x100000000").kind == CommandInputKind::kInvalid &&
            parseCommandInput(L"net 4294967296").kind == CommandInputKind::kInvalid,
        L"32-bit entity commands reject values that would truncate during routing");
    const auto kLargeHwnd = parseCommandInput(L"hwnd 0x100000000");
    expect(kLargeHwnd.kind == CommandInputKind::kNavigation &&
            kLargeHwnd.navigation.entity.kind == EntityKind::kWindow &&
            kLargeHwnd.navigation.entity.id == 0x100000000ULL,
        L"HWND command preserves a 64-bit native handle value");

    using ksword::features::file::PathNavigator;
    expect(PathNavigator::normalizeKnownDirectoryPath(L" C:/Program Files/KSword/ ") == L"C:\\Program Files\\KSword",
        L"known DOS directory normalizes without probing");
    expect(PathNavigator::normalizeKnownDirectoryPath(L"\\\\server\\share\\folder\\") == L"\\\\server\\share\\folder",
        L"known UNC directory normalizes without probing");
    expect(PathNavigator::normalizeKnownDirectoryPath(L"\\Device\\HarddiskVolume3\\Windows").empty() &&
            PathNavigator::normalizeKnownDirectoryPath(L"\\\\?\\C:\\Windows").empty() &&
            PathNavigator::normalizeKnownDirectoryPath(L"C:relative").empty(),
        L"known directory rejects device extended and relative syntax");
    expect(PathNavigator::parentDirectoryForKnownFilePath(L"C:\\Windows\\System32\\notepad.exe") == L"C:\\Windows\\System32" &&
            PathNavigator::parentDirectoryForKnownFilePath(L"\\\\server\\share\\folder\\report.txt") == L"\\\\server\\share\\folder" &&
            PathNavigator::parentDirectoryForKnownFilePath(L"C:\\pagefile.sys") == L"C:\\",
        L"known file parent stays within explicit DOS and UNC routes");
    expect(PathNavigator::parentDirectoryForKnownFilePath(L"svchost.exe -k netsvcs").empty() &&
            PathNavigator::parentDirectoryForKnownFilePath(L"\\\\?\\C:\\Windows\\notepad.exe").empty(),
        L"known file parent rejects command and extended syntax");

    ksword::features::monitor::EtwEvent firstEtwEvent{};
    firstEtwEvent.timeText = L"2026-08-27 10:00:00.000";
    firstEtwEvent.providerText = L"Provider One";
    firstEtwEvent.eventId = 10U;
    firstEtwEvent.level = 4U;
    firstEtwEvent.processId = 100U;
    firstEtwEvent.threadId = 101U;
    firstEtwEvent.summary = L"first summary";
    ksword::features::monitor::EtwEvent secondEtwEvent{};
    secondEtwEvent.timeText = L"2026-08-27 10:00:01.000";
    secondEtwEvent.providerText = L"Provider\tTwo";
    secondEtwEvent.eventId = 20U;
    secondEtwEvent.level = 5U;
    secondEtwEvent.processId = 200U;
    secondEtwEvent.threadId = 201U;
    secondEtwEvent.summary = L"second\r\nsummary";
    const std::wstring kEtwTsv = ksword::features::monitor::buildVisibleEtwEventsTsv(
        { firstEtwEvent, secondEtwEvent }, { 1U, 0U });
    expect(kEtwTsv.find(L"PID\t时间\tProvider\tTID\tEventId\tLevel\t摘要\r\n200\t2026-08-27 10:00:01.000\tProvider Two\t201\t20\t5\tsecond  summary\r\n100") == 0U,
        L"ETW TSV follows visible order and sanitizes cell delimiters");
    expect(ksword::features::monitor::buildVisibleEtwEventsTsv({ firstEtwEvent }, {}).empty() &&
            ksword::features::monitor::buildVisibleEtwEventsTsv({ firstEtwEvent }, { 3U }).empty(),
        L"ETW TSV rejects empty and invalid visible snapshots");

    ksword::features::registry::RegistrySearchRequest registrySearchRequest{};
    registrySearchRequest.startPath = L"  HKLM\\Software\\KSword  ";
    registrySearchRequest.query = L"  Needle  ";
    registrySearchRequest.maxKeys = 999999U;
    registrySearchRequest.maxValues = 999999U;
    registrySearchRequest.maxResults = 999999U;
    registrySearchRequest.maxDepth = 999999U;
    registrySearchRequest.maxValuePreviewBytes = 999999U;
    const auto kRegistrySearchValidation = ksword::features::registry::validateRegistrySearchRequest(registrySearchRequest);
    expect(kRegistrySearchValidation.valid && kRegistrySearchValidation.request.startPath == L"HKLM\\Software\\KSword" &&
            kRegistrySearchValidation.normalizedQuery == L"Needle" &&
            kRegistrySearchValidation.request.maxKeys == ksword::features::registry::kRegistrySearchMaxKeys &&
            kRegistrySearchValidation.request.maxValues == ksword::features::registry::kRegistrySearchMaxValues &&
            kRegistrySearchValidation.request.maxResults == ksword::features::registry::kRegistrySearchMaxResults &&
            kRegistrySearchValidation.request.maxDepth == ksword::features::registry::kRegistrySearchMaxDepth &&
            kRegistrySearchValidation.request.maxValuePreviewBytes == ksword::features::registry::kRegistrySearchMaxValuePreviewBytes,
        L"registry search request trims text and clamps hard budgets");
    expect(!ksword::features::registry::validateRegistrySearchRequest({ L"HKLM", L"" }).valid &&
            !ksword::features::registry::validateRegistrySearchRequest({ L"", L"needle" }).valid,
        L"registry search rejects empty path and keyword");
    ksword::features::registry::RegistrySearchRequest zeroBudgetSearchRequest{};
    zeroBudgetSearchRequest.startPath = L"HKLM";
    zeroBudgetSearchRequest.query = L"needle";
    zeroBudgetSearchRequest.maxKeys = 0U;
    zeroBudgetSearchRequest.maxValues = 0U;
    zeroBudgetSearchRequest.maxResults = 0U;
    zeroBudgetSearchRequest.maxDepth = 0U;
    zeroBudgetSearchRequest.maxValuePreviewBytes = 0U;
    const auto kZeroBudgetSearchValidation = ksword::features::registry::validateRegistrySearchRequest(zeroBudgetSearchRequest);
    expect(kZeroBudgetSearchValidation.valid &&
            kZeroBudgetSearchValidation.request.maxKeys == ksword::features::registry::kRegistrySearchMaxKeys &&
            kZeroBudgetSearchValidation.request.maxValues == ksword::features::registry::kRegistrySearchMaxValues &&
            kZeroBudgetSearchValidation.request.maxResults == ksword::features::registry::kRegistrySearchMaxResults &&
            kZeroBudgetSearchValidation.request.maxDepth == ksword::features::registry::kRegistrySearchMaxDepth &&
            kZeroBudgetSearchValidation.request.maxValuePreviewBytes == ksword::features::registry::kRegistrySearchMaxValuePreviewBytes,
        L"registry search normalizes omitted zero budgets to fixed bounds");

    ksword::features::registry::RegistrySearchCandidate registryCandidate{};
    registryCandidate.kind = ksword::features::registry::RegistrySearchEntryKind::kValue;
    registryCandidate.keyPath = L" HKLM\\Software\\Needle\\Branch ";
    registryCandidate.valueName = L"Name\tNeedle";
    registryCandidate.valueTypeText = L"REG_SZ";
    registryCandidate.dataPreview = L"line1\r\nneedle payload";
    registryCandidate.dataByteCount = 80U;
    registryCandidate.depth = 3U;
    const auto kRegistryHit = ksword::features::registry::projectRegistrySearchHit(registryCandidate, 24U);
    expect(kRegistryHit.valid && kRegistryHit.keyPath == L"HKLM\\Software\\Needle\\Branch" &&
            kRegistryHit.valueName == L"Name Needle" && kRegistryHit.dataPreviewTruncated &&
            ksword::features::registry::registrySearchHitMatches(kRegistryHit, L"NEEDLE") &&
            ksword::features::registry::registrySearchHitMatches(kRegistryHit, L"reg_sz") &&
            !ksword::features::registry::registrySearchHitMatches(kRegistryHit, L"missing"),
        L"registry search projects safe candidates and matches fields case insensitively");
    ksword::features::registry::RegistrySearchSnapshot registrySearchSnapshot{};
    registrySearchSnapshot.request = kRegistrySearchValidation.request;
    registrySearchSnapshot.stopReason = ksword::features::registry::RegistrySearchStopReason::kDepthLimitReached;
    registrySearchSnapshot.counters.visitedKeyCount = 12U;
    registrySearchSnapshot.counters.visitedValueCount = 4U;
    registrySearchSnapshot.counters.skippedDepthCount = 2U;
    registrySearchSnapshot.hits = { kRegistryHit };
    expect(ksword::features::registry::buildRegistrySearchStatusText(registrySearchSnapshot).find(L"深度") != std::wstring::npos,
        L"registry search status names explicit traversal stop reasons");
    registrySearchSnapshot.stopReason = ksword::features::registry::RegistrySearchStopReason::kValueLimitReached;
    expect(ksword::features::registry::buildRegistrySearchStatusText(registrySearchSnapshot).find(L"个值的上限") != std::wstring::npos,
        L"registry search status names the value work bound");
    registrySearchSnapshot.stopReason = ksword::features::registry::RegistrySearchStopReason::kSubKeyEnumerationLimitReached;
    registrySearchSnapshot.counters.inspectedSubKeyCount = 12U;
    expect(ksword::features::registry::buildRegistrySearchStatusText(registrySearchSnapshot).find(L"子键枚举工作上限") != std::wstring::npos,
        L"registry search status distinguishes child-enumeration work bounds");
    const std::wstring kRegistrySearchTsv = ksword::features::registry::buildVisibleRegistrySearchTsv(
        { kRegistryHit, {} }, { 0U, 1U, 9U });
    expect(kRegistrySearchTsv.find(L"类型\t键路径\t值名称") == 0U &&
            kRegistrySearchTsv.find(L"Name Needle") != std::wstring::npos &&
            kRegistrySearchTsv.find(L'\t') != std::wstring::npos &&
            kRegistrySearchTsv.find(L"\r\nneedle") == std::wstring::npos,
        L"registry search TSV preserves valid visible order and sanitizes fields");

    const auto kIoctl = ksword::features::sys_tools::decodeIoctlCode(L" 0x222004 ");
    expect(kIoctl.state == ksword::features::sys_tools::IoctlDecodeState::kValid &&
            kIoctl.code == 0x00222004U && kIoctl.deviceType == 0x0022U && kIoctl.function == 0x0801U &&
            kIoctl.access == 0U && kIoctl.method == 0U && !kIoctl.common && kIoctl.custom,
        L"IOCTL decoder extracts standard CTL_CODE fields");
    const auto kIoctlBoundary = ksword::features::sys_tools::decodeIoctlCode(L"FFFFFFFF");
    expect(kIoctlBoundary.state == ksword::features::sys_tools::IoctlDecodeState::kValid &&
            kIoctlBoundary.deviceType == 0xFFFFU && kIoctlBoundary.function == 0x0FFFU &&
            kIoctlBoundary.access == 3U && kIoctlBoundary.method == 3U && kIoctlBoundary.common && kIoctlBoundary.custom,
        L"IOCTL decoder preserves common custom and field boundaries");
    expect(ksword::features::sys_tools::decodeIoctlCode(L"").state == ksword::features::sys_tools::IoctlDecodeState::kEmpty &&
            ksword::features::sys_tools::decodeIoctlCode(L"0x").state == ksword::features::sys_tools::IoctlDecodeState::kInvalid &&
            ksword::features::sys_tools::decodeIoctlCode(L"123456789").state == ksword::features::sys_tools::IoctlDecodeState::kInvalid &&
            ksword::features::sys_tools::decodeIoctlCode(L"0x22G004").state == ksword::features::sys_tools::IoctlDecodeState::kInvalid,
        L"IOCTL decoder rejects malformed and overflow input");
    expect(ksword::features::sys_tools::buildIoctlDecodedReport(kIoctl).find(L"FILE_ANY_ACCESS") != std::wstring::npos &&
            ksword::features::sys_tools::buildIoctlDecodedReport(kIoctlBoundary).find(L"METHOD_NEITHER") != std::wstring::npos,
        L"IOCTL decoder report includes standard access and method names");

    ksword::ark::Win32kTimersResult timerEvidence{};
    timerEvidence.io.ok = true;
    timerEvidence.io.message = "timer snapshot ok";
    timerEvidence.version = 2U;
    timerEvidence.status = KSWORD_ARK_WIN32K_STATUS_OK;
    timerEvidence.totalCount = 3U;
    timerEvidence.returnedCount = 1U;
    timerEvidence.entrySize = sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY);
    timerEvidence.flags = 0x17U;
    timerEvidence.lastStatus = -1073741823L;
    timerEvidence.capabilityMask = 0x1122334455667788ULL;
    timerEvidence.missingCapabilityMask = 0x10ULL;
    timerEvidence.timerHashTable = 0xFFFFF80012340000ULL;
    timerEvidence.visitedNodeCount = 8U;
    timerEvidence.readFailureCount = 1U;
    timerEvidence.corruptBucketCount = 2U;
    timerEvidence.duplicateCount = 3U;
    timerEvidence.win32kbaseTimeDateStamp = 0x11223344U;
    timerEvidence.win32kbaseImageSize = 0x55667788U;
    timerEvidence.win32kfullTimeDateStamp = 0x99AABBCCU;
    timerEvidence.win32kfullImageSize = 0xDDEEFF00U;
    timerEvidence.layout.source = KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY;
    timerEvidence.layout.objectSize = 0x88U;
    timerEvidence.layout.bucketCount = 64U;
    timerEvidence.layout.bucketStride = 16U;
    KSWORD_ARK_WIN32K_TIMER_ENTRY timerEntry{};
    timerEntry.fieldFlags = KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT |
        KSWORD_ARK_WIN32K_TIMER_FIELD_THREAD |
        KSWORD_ARK_WIN32K_TIMER_FIELD_CALLBACK |
        KSWORD_ARK_WIN32K_TIMER_FIELD_INTERVAL |
        KSWORD_ARK_WIN32K_TIMER_FIELD_FLAGS |
        KSWORD_ARK_WIN32K_TIMER_FIELD_WINDOW |
        KSWORD_ARK_WIN32K_TIMER_FIELD_ID |
        KSWORD_ARK_WIN32K_TIMER_FIELD_ALTERNATE_THREAD |
        KSWORD_ARK_WIN32K_TIMER_FIELD_HASH_LINK;
    timerEntry.status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    timerEntry.processId = 321U;
    timerEntry.threadId = 654U;
    timerEntry.sessionId = 2U;
    timerEntry.flags = 0xA5U;
    timerEntry.intervalMs = 1000U;
    timerEntry.countdownMs = 500U;
    timerEntry.toleranceMs = 25U;
    timerEntry.lastStatus = -1073741823L;
    timerEntry.timerObject = 0xFFFFF80000001000ULL;
    timerEntry.callbackAddress = 0xFFFFF80000002000ULL;
    timerEntry.primaryThreadInfo = 0xFFFFF80000003000ULL;
    timerEntry.alternateThreadInfo = 0xFFFFF80000004000ULL;
    timerEntry.windowObject = 0xFFFFF80000005000ULL;
    timerEntry.timerId = 0x1234ULL;
    timerEntry.hashLink = 0xFFFFF80000006000ULL;
    std::wmemcpy(timerEntry.detail, L"timer\tpartial", 13U);
    timerEvidence.entries.push_back(timerEntry);
    const auto kTimerRows = ksword::features::window::buildWin32kTimerEvidenceRows(timerEvidence);
    expect(kTimerRows.size() == 3U && kTimerRows[0].status == L"OK" && kTimerRows[1].status == L"Exact" &&
            kTimerRows[2].status == L"Partial" && kTimerRows[2].relatedProcessId == 321U,
        L"Win32k timer evidence projects snapshot layout and owner identity");
    expect(kTimerRows[0].detail.find(L"gTimerHashTable=0xFFFFF80012340000") != std::wstring::npos &&
            kTimerRows[1].detail.find(L"source=ValidatedDisassembly") != std::wstring::npos &&
            kTimerRows[2].detail.find(L"timerObject=0xFFFFF80000001000") != std::wstring::npos &&
            kTimerRows[2].detail.find(L"lastStatus=0xC0000001") != std::wstring::npos &&
            kTimerRows[2].detail.find(L"timer partial") != std::wstring::npos,
        L"Win32k timer evidence preserves raw addresses status and sanitized detail");

    ksword::ark::Win32kTimersResult incompleteTimerEvidence{};
    incompleteTimerEvidence.io.ok = true;
    incompleteTimerEvidence.status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
    incompleteTimerEvidence.layout.source = KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_NEAREST_PREVIOUS;
    KSWORD_ARK_WIN32K_TIMER_ENTRY incompleteTimerEntry{};
    incompleteTimerEntry.fieldFlags = KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT;
    incompleteTimerEntry.status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    incompleteTimerEntry.processId = 999U;
    incompleteTimerEntry.threadId = 888U;
    incompleteTimerEntry.timerObject = 0x12345678ULL;
    incompleteTimerEvidence.entries.push_back(incompleteTimerEntry);
    const auto kIncompleteTimerRows = ksword::features::window::buildWin32kTimerEvidenceRows(incompleteTimerEvidence);
    expect(kIncompleteTimerRows.size() == 3U && kIncompleteTimerRows[1].status == L"NearestPrevious" &&
            kIncompleteTimerRows[2].relatedProcessId == 0U &&
            kIncompleteTimerRows[2].detail.find(L"processId=<absent; raw=999>") != std::wstring::npos &&
            kIncompleteTimerRows[2].detail.find(L"callbackAddress=<absent; raw=0x0000000000000000>") != std::wstring::npos,
        L"Win32k timer evidence keeps missing driver fields explicit and non-navigable");

    ksword::ark::Win32kTimersResult unsupportedTimerEvidence{};
    unsupportedTimerEvidence.io.ok = false;
    unsupportedTimerEvidence.unsupported = true;
    unsupportedTimerEvidence.io.message = "legacy driver";
    const auto kUnsupportedTimerRows = ksword::features::window::buildWin32kTimerEvidenceRows(unsupportedTimerEvidence);
    expect(kUnsupportedTimerRows.size() == 1U && kUnsupportedTimerRows.front().status == L"Unsupported" &&
            kUnsupportedTimerRows.front().detail.find(L"legacy driver") != std::wstring::npos,
        L"Win32k timer evidence degrades old drivers to one explicit summary row");
    expect(ksword::features::window::win32kTimerEvidenceStatusText(KSWORD_ARK_WIN32K_STATUS_READ_FAILED) == L"ReadFailed" &&
            ksword::features::window::win32kTimerEvidenceStatusText(0xA5A5A5A5U).find(L"0xA5A5A5A5") != std::wstring::npos,
        L"Win32k timer evidence preserves known and unknown protocol status codes");

    MemorySnapshotHistory snapshots(2U);
    expect(!snapshots.record(0U, 0x1000U, 4U, { 1U }, L"bad"), L"snapshot rejects missing pid");
    expect(snapshots.record(42U, 0x1000U, 4U, { 1U, 2U, 3U, 4U }, L"first"), L"first snapshot recorded");
    expect(snapshots.record(42U, 0x2000U, 2U, { 5U, 6U }, L"second"), L"second snapshot recorded");
    expect(snapshots.canMovePrevious() && !snapshots.canMoveNext(), L"snapshot back navigation available");
    expect(snapshots.movePrevious() && snapshots.current() && snapshots.current()->address == 0x1000U,
        L"snapshot previous selects first bytes");
    expect(snapshots.record(42U, 0x3000U, 1U, { 7U }, L"branch"), L"snapshot branch recorded");
    expect(snapshots.size() == 2U && !snapshots.canMoveNext() && snapshots.current() && snapshots.current()->address == 0x3000U,
        L"snapshot branch truncates forward history");

    MemoryReadSnapshot inspect{};
    inspect.sequence = 7U;
    inspect.processId = 42U;
    inspect.address = 0x1000U;
    inspect.requestedBytes = 13U;
    inspect.bytes = { 'T', 'e', 's', 't', 0U, 'W', 0U, 'i', 0U, 'd', 0U, 'e', 0U };
    inspect.statusText = L"partial read";
    const std::wstring kHexAscii = ksword::features::memory::renderMemorySnapshotHexAscii(inspect);
    const std::wstring kTextRuns = ksword::features::memory::extractMemorySnapshotText(inspect);
    expect(kHexAscii.find(L"0x0000000000001000") != std::wstring::npos && kHexAscii.find(L"Test") != std::wstring::npos,
        L"memory hex ascii view includes address and printable bytes");
    expect(kTextRuns.find(L"ASCII") != std::wstring::npos && kTextRuns.find(L"UTF-16LE") != std::wstring::npos,
        L"memory inspection extracts ascii and utf16 text runs");
    expect(ksword::features::memory::buildMemorySnapshotTextReport(inspect).find(L"ReturnedBytes") != std::wstring::npos,
        L"memory inspection report includes snapshot metadata");

    MemoryReadSnapshot writableSnapshot{};
    writableSnapshot.sequence = 8U;
    writableSnapshot.processId = 88U;
    writableSnapshot.address = 0x2000U;
    writableSnapshot.requestedBytes = 10U;
    writableSnapshot.bytes = { 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U };
    ksword::features::memory::MemoryWritePlan writePlan{};
    std::wstring planError;
    const std::vector<std::uint8_t> kEditedBytes = { 0U, 9U, 8U, 3U, 4U, 7U, 8U, 9U, 8U, 9U };
    expect(ksword::features::memory::buildMemoryWritePlan(writableSnapshot, kEditedBytes, 2U, writePlan, planError),
        L"memory write plan accepts same-length edited snapshot");
    expect(writePlan.changedByteCount == 5U && writePlan.blocks.size() == 3U,
        L"memory write plan merges and splits contiguous differences");
    expect(writePlan.blocks[0].address == 0x2001U && writePlan.blocks[0].desiredAfter == std::vector<std::uint8_t>{ 9U, 8U } &&
            writePlan.blocks[1].address == 0x2005U && writePlan.blocks[1].desiredAfter == std::vector<std::uint8_t>{ 7U, 8U } &&
            writePlan.blocks[2].address == 0x2007U && writePlan.blocks[2].desiredAfter == std::vector<std::uint8_t>{ 9U },
        L"memory write plan preserves exact chunk addresses and payloads");
    expect(ksword::features::memory::validateMemoryWritePlan(writePlan, planError),
        L"memory write plan validates generated blocks");

    ksword::features::memory::MemoryWritePlan noChangePlan{};
    expect(ksword::features::memory::buildMemoryWritePlan(writableSnapshot, writableSnapshot.bytes, 2U, noChangePlan, planError) &&
            noChangePlan.changedByteCount == 0U && noChangePlan.blocks.empty(),
        L"memory write plan does not create no-op writes");
    expect(!ksword::features::memory::buildMemoryWritePlan(writableSnapshot, { 1U }, 2U, noChangePlan, planError),
        L"memory write plan rejects length drift");
    MemoryReadSnapshot overflowSnapshot = writableSnapshot;
    overflowSnapshot.address = (std::numeric_limits<std::uint64_t>::max)();
    expect(!ksword::features::memory::buildMemoryWritePlan(overflowSnapshot, kEditedBytes, 2U, noChangePlan, planError),
        L"memory write plan rejects address wraparound");
    ksword::features::memory::MemoryWritePlan malformedPlan = writePlan;
    malformedPlan.blocks[0].desiredAfter[0] = 0U;
    expect(!ksword::features::memory::validateMemoryWritePlan(malformedPlan, planError),
        L"memory write plan rejects desired-byte drift");

    const std::wstring kRedacted = ksword::ui::redactEvidenceText(
        L"C:\\Users\\Felix\\Desktop\\sample.txt", ksword::ui::EvidenceRedaction::kPrivacy);
    expect(kRedacted == L"C:\\Users\\<redacted>\\Desktop\\sample.txt", L"privacy path redaction");

    const ksword::ui::EvidenceDiff kDiff = ksword::ui::buildEvidenceDiff(L"one\r\ntwo\r\n", L"two\r\nthree\r\n");
    expect(kDiff.added.size() == 1U && kDiff.added.front() == L"three", L"evidence added line");
    expect(kDiff.removed.size() == 1U && kDiff.removed.front() == L"one", L"evidence removed line");
    expect(kDiff.unchanged.size() == 1U && kDiff.unchanged.front() == L"two", L"evidence unchanged line");

    ksword::ui::EvidenceSession session;
    expect(session.record(L"process", L"tsv", L"pid\tname") == 1U, L"first evidence sequence");
    session.record(L"process", L"tsv", L"pid\tname\r\n4\tSystem");
    expect(session.size() == 2U, L"evidence session size");
    expect(session.exportJson(ksword::ui::EvidenceRedaction::kPrivacy).find(L"ksword-arklight-evidence-v1") !=
        std::wstring::npos, L"evidence JSON schema");
    expect(ksword::ui::renderEvidenceDiff(session.latestDiff()).find(L"+ 4\tSystem") != std::wstring::npos,
        L"latest evidence diff");
    expect(session.erase(1U) && session.size() == 1U && !session.erase(1U),
        L"evidence session erases one immutable item by sequence");

    // Offline automated tests for the next phase acceptance (docs/next/KSword_Next_Roadmap_Acceptance.md).
    // Each suite calls the production implementation in shared/evidence and returns its own failure count.
    failures += runEvidenceContractTests();
    failures += runCrossViewTests();
    failures += runEntityGraphTests();
    failures += runDumpFactsTests();
    failures += runSnapshotCompareTests();
    failures += runSecurityStateTests();
    failures += runWfpTests();
    failures += runTimelineTests();
    failures += runImageIntegrityTests();
    failures += runMemoryEvidenceTests();
    failures += runInjectionSurveyTests();
    failures += runHvmEptSwitchTests();
    failures += runHvmWatchTests();
    failures += runDdmaPlanTests();
    failures += runNumericTextParseTests();
    failures += runMemoryTamperCrossViewTests();
    failures += runDmaProcessOpPlanTests();
    failures += runHookPatchComposeTests();

    if (failures == 0) {
        std::wcout << L"KswordARKLightTests: PASS\n";
    }
    return failures == 0 ? 0 : 1;
}
