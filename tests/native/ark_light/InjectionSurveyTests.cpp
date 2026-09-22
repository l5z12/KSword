// Offline automated tests for the J module (process memory injection and integrity check).
//
// Covers the five items and their hard rules from Phase 1 of issue #196:
//   J-01: Address space index and protection value classification (including missed detection of `protect & PAGE_EXECUTE` flagged in issues).
//   J-02 Module cross-view L/I/P (eligibility for missing-item inference, incomplete WOW64 list, path resolution failure are gaps).
//   J-03 Working set filtering (Valid/Shared semantics; ShareCount must not substitute for Shared; shared pages not allowed).
//   J-04: Thread start/end points (start page is now non-executable, cannot ignore clues; mismatch in collection ≠ mismatch in ownership).
//   J-05: Normalized profile modes must match; unconfirmed references cannot be upgraded to 'modified and confirmed'. At the conclusion
// layer: incomplete coverage can never result in 'no differences found', and private RX alone does not constitute 'injected'.
//
// All fixtures are constructed via code in this file; expected values are written as manually calculated constants. Do
// not call the code under test to compute expectations—otherwise, the test merely stamps approval on the implementation.

#include "TestSupport.h"

#include "../../../shared/evidence/InjectionSurvey.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace ksword::evidence;

// ---------------------------------------------------------------------------
// Fixture construction
// ---------------------------------------------------------------------------

RegionRecord makeRegion(const std::uint64_t base,
                        const std::uint64_t size,
                        const RegionState state,
                        const RegionType type,
                        const std::uint32_t protect,
                        const std::uint64_t allocationBase = 0,
                        const std::string& mappedPath = std::string()) {
    RegionRecord record;
    record.base = OptionalU64::of(base);
    record.size = OptionalU64::of(size);
    record.state = state;
    record.type = type;
    record.protection = toRegionProtection(
        classifyWin32Protection(OptionalU64::of(protect)));
    record.allocationBase = OptionalU64::of(allocationBase == 0U ? base : allocationBase);
    record.mappedPath = mappedPath;
    record.source = RegionEvidenceSource::kR3VirtualQuery;
    return record;
}

CollectionOutcome accessDeniedOutcome() {
    return CollectionOutcome::failure(CollectionStatus::kAccessDenied, "WIN32", 5U,
                                      "ERROR_ACCESS_DENIED");
}

ProcessInstanceId makeProcess(const std::uint64_t pid,
                              const std::uint64_t createTime,
                              const bool withBootId = true) {
    ProcessInstanceId id;
    id.pid = OptionalU64::of(pid);
    if (createTime != 0U) {
        id.createTime100ns = OptionalU64::of(createTime);
    }
    if (withBootId) {
        id.bootId = "boot-1";
    }
    id.imageName = "target.exe";
    return id;
}

ThreadInstanceId makeThread(const ProcessInstanceId& process, const std::uint64_t tid) {
    ThreadInstanceId thread;
    thread.process = process;
    thread.tid = OptionalU64::of(tid);
    return thread;
}

DriverInstanceId makeModule(const std::string& path,
                            const std::uint64_t base,
                            const std::uint64_t size) {
    DriverInstanceId module;
    module.imagePath = path;
    module.imageBase = OptionalU64::of(base);
    module.imageSize = OptionalU64::of(size);
    return module;
}

ImageCodeExtent makeImage(const std::string& path,
                          const std::uint64_t base,
                          const std::uint64_t size,
                          const std::uint64_t codeBegin,
                          const std::uint64_t codeEnd,
                          const bool codeKnown = true) {
    ImageCodeExtent image;
    image.path = path;
    image.base = base;
    image.size = size;
    image.codeBeginRva = codeBegin;
    image.codeEndRva = codeEnd;
    image.codeExtentKnown = codeKnown;
    return image;
}

bool hasGap(const std::vector<std::string>& gaps, const char* key) {
    return std::find(gaps.begin(), gaps.end(), std::string(key)) != gaps.end();
}

bool hasRule(const std::vector<InjectionFinding>& findings, const char* ruleId) {
    return std::any_of(findings.begin(), findings.end(),
                       [ruleId](const InjectionFinding& finding) {
                           return finding.ruleId == ruleId;
                       });
}

const InjectionFinding* findRule(const std::vector<InjectionFinding>& findings,
                                 const char* const ruleId) {
    const auto kHit = std::find_if(findings.begin(), findings.end(),
                                  [ruleId](const InjectionFinding& finding) {
                                      return finding.ruleId == ruleId;
                                  });
    return kHit == findings.end() ? nullptr : &*kHit;
}

std::size_t countIssue(const ModuleCrossViewReport& report, const ModuleCrossIssue issue) {
    return static_cast<std::size_t>(
        std::count_if(report.findings.begin(), report.findings.end(),
                      [issue](const ModuleCrossFinding& finding) {
                          return finding.issue == issue;
                      }));
}

// ---------------------------------------------------------------------------
// J-01: Protection value classification
// ---------------------------------------------------------------------------
void testProtectionClassification(ksword_tests::Suite& suite) {
    // Missed detection pointed out by the issue: PAGE_EXECUTE_READ (0x20) & PAGE_EXECUTE
    // (0x10) == 0, so `protect & PAGE_EXECUTE` incorrectly marks R-X pages as non-executable.
    suite.expect((0x20U & 0x10U) == 0U, L"J-01 PAGE_EXECUTE_READ 与 PAGE_EXECUTE 无公共位");
    suite.expect((0x40U & 0x10U) == 0U, L"J-01 PAGE_EXECUTE_READWRITE 与 PAGE_EXECUTE 无公共位");
    suite.expect((0x80U & 0x10U) == 0U, L"J-01 PAGE_EXECUTE_WRITECOPY 与 PAGE_EXECUTE 无公共位");

    const ProtectionFacts kExecute =
        classifyWin32Protection(OptionalU64::of(kWin32PageExecute));
    suite.expect(kExecute.execute == ExecuteProtection::kExecute, L"J-01 PAGE_EXECUTE 分类");
    suite.expect(executeProtectionIsExecutable(kExecute.execute), L"J-01 PAGE_EXECUTE 可执行");
    suite.expect(!kExecute.readable, L"J-01 PAGE_EXECUTE 不可读");

    const ProtectionFacts kExecuteRead =
        classifyWin32Protection(OptionalU64::of(kWin32PageExecuteRead));
    suite.expect(kExecuteRead.execute == ExecuteProtection::kExecuteRead, L"J-01 R-X 分类");
    suite.expect(executeProtectionIsExecutable(kExecuteRead.execute), L"J-01 R-X 可执行");
    suite.expect(kExecuteRead.readable && !kExecuteRead.writable, L"J-01 R-X 读写位");

    const ProtectionFacts kRwx =
        classifyWin32Protection(OptionalU64::of(kWin32PageExecuteReadWrite));
    suite.expect(kRwx.execute == ExecuteProtection::kExecuteReadWrite, L"J-01 RWX 分类");
    suite.expect(kRwx.writable && kRwx.readable, L"J-01 RWX 读写位");
    suite.expect(!kRwx.copyOnWrite, L"J-01 RWX 非写时复制");

    const ProtectionFacts kWcx =
        classifyWin32Protection(OptionalU64::of(kWin32PageExecuteWriteCopy));
    suite.expect(kWcx.execute == ExecuteProtection::kExecuteWriteCopy, L"J-01 RXC 分类");
    suite.expect(kWcx.copyOnWrite, L"J-01 RXC 写时复制位");
    suite.expect(executeProtectionIsExecutable(kWcx.execute), L"J-01 RXC 可执行");

    const ProtectionFacts kRw = classifyWin32Protection(OptionalU64::of(kWin32PageReadWrite));
    suite.expect(kRw.execute == ExecuteProtection::kNotExecutable, L"J-01 RW 不可执行");
    suite.expect(kRw.readable && kRw.writable, L"J-01 RW 读写位");

    const ProtectionFacts kNoAccess =
        classifyWin32Protection(OptionalU64::of(kWin32PageNoAccess));
    suite.expect(kNoAccess.noAccess, L"J-01 NOACCESS 标记");
    suite.expect(!kNoAccess.readable, L"J-01 NOACCESS 不可读");

    const ProtectionFacts kWriteCopy =
        classifyWin32Protection(OptionalU64::of(kWin32PageWriteCopy));
    suite.expect(kWriteCopy.copyOnWrite && !executeProtectionIsExecutable(kWriteCopy.execute),
                 L"J-01 WRITECOPY 写时复制且不可执行");

    // PAGE_GUARD is a modifier flag and does not change the base protection value.
    const ProtectionFacts kGuarded = classifyWin32Protection(
        OptionalU64::of(kWin32PageExecuteRead | kWin32PageGuard));
    suite.expect(kGuarded.guard, L"J-01 PAGE_GUARD 单独成位");
    suite.expect(kGuarded.execute == ExecuteProtection::kExecuteRead,
                 L"J-01 PAGE_GUARD 不改变基本保护值");

    // Other high-bit modifiers similarly must not affect the basic value determination.
    const ProtectionFacts kNoCache = classifyWin32Protection(
        OptionalU64::of(kWin32PageExecuteReadWrite | kWin32PageNoCache |
                        kWin32PageWriteCombine | kWin32PageTargetsNoUpdate));
    suite.expect(kNoCache.execute == ExecuteProtection::kExecuteReadWrite,
                 L"J-01 高位修饰不影响基本保护值");

    // Unrecognized base value: neither executable nor non-executable.
    const ProtectionFacts kWeird = classifyWin32Protection(OptionalU64::of(0x07U));
    suite.expect(kWeird.unrecognizedBase, L"J-01 未知基本值置位");
    suite.expect(kWeird.execute == ExecuteProtection::kUnknown, L"J-01 未知基本值不下判断");

    // No original value provided = unknown; definitely not 'non-executable'.
    const ProtectionFacts kUnset = classifyWin32Protection(OptionalU64::unset());
    suite.expect(kUnset.execute == ExecuteProtection::kUnknown, L"J-01 缺原始值即未知");
    suite.expect(!executeProtectionIsExecutable(kUnset.execute), L"J-01 未知不算可执行");
    suite.expect(!kUnset.rawValue.present, L"J-01 缺原始值不补 0");

    // toRegionProtection projects back.
    const RegionProtection kProjected = toRegionProtection(kRwx);
    suite.expect(kProjected.executable && kProjected.writable && kProjected.readable,
                 L"J-01 RWX 投影到 RegionProtection");
    suite.expect(kProjected.rawValue.present &&
                     kProjected.rawValue.value == kWin32PageExecuteReadWrite,
                 L"J-01 原始值无损保留");

    // effectiveProtection: Use the original value if available to correct executable flags miscalculated by the caller.
    RegionRecord wrongFlags =
        makeRegion(0x10000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                   kWin32PageExecuteRead);
    wrongFlags.protection.executable = false;  // Simulate the caller using incorrect bits with the computed result.
    const ProtectionFacts kCorrected = effectiveProtection(wrongFlags);
    suite.expect(kCorrected.execute == ExecuteProtection::kExecuteRead,
                 L"J-01 原始值纠正错误的 executable 位");

    RegionRecord noRaw;
    noRaw.base = OptionalU64::of(0x20000U);
    noRaw.size = OptionalU64::of(0x1000U);
    noRaw.state = RegionState::kCommit;
    noRaw.type = RegionType::kPrivate;
    const ProtectionFacts kEmpty = effectiveProtection(noRaw);
    suite.expect(kEmpty.execute == ExecuteProtection::kUnknown,
                 L"J-01 保护字段全默认视为未知");

    noRaw.protection.readable = true;
    noRaw.protection.executable = true;
    const ProtectionFacts kFallback = effectiveProtection(noRaw);
    suite.expect(kFallback.execute == ExecuteProtection::kExecuteRead,
                 L"J-01 无原始值时退回布尔字段");
}

// ---------------------------------------------------------------------------
// J-01: Region code classification.
// ---------------------------------------------------------------------------
void testRegionCodeClass(ksword_tests::Suite& suite) {
    const RegionRecord kImageExec = makeRegion(0x140001000ULL, 0x1000U, RegionState::kCommit,
                                              RegionType::kImage, kWin32PageExecuteRead);
    suite.expect(classifyRegionCode(kImageExec) == RegionCodeClass::kImageExecutable,
                 L"J-01 映像可执行页分类");
    suite.expect(!isDynamicCodeCandidate(RegionCodeClass::kImageExecutable),
                 L"J-01 映像可执行页不是动态代码候选");

    const RegionRecord kPrivateExec = makeRegion(0x200000U, 0x1000U, RegionState::kCommit,
                                                RegionType::kPrivate, kWin32PageExecuteRead);
    suite.expect(classifyRegionCode(kPrivateExec) == RegionCodeClass::kPrivateExecutable,
                 L"J-01 私有可执行页分类");
    suite.expect(isDynamicCodeCandidate(RegionCodeClass::kPrivateExecutable),
                 L"J-01 私有可执行页是候选");

    // Cannot scan only private memory, or mapped non-image code will be missed.
    const RegionRecord kMappedExec = makeRegion(0x300000U, 0x1000U, RegionState::kCommit,
                                               RegionType::kMapped, kWin32PageExecuteReadWrite);
    suite.expect(classifyRegionCode(kMappedExec) == RegionCodeClass::kMappedExecutable,
                 L"J-01 映射可执行页分类");
    suite.expect(isDynamicCodeCandidate(RegionCodeClass::kMappedExecutable),
                 L"J-01 映射可执行页是候选");

    const RegionRecord kImageData = makeRegion(0x140010000ULL, 0x1000U, RegionState::kCommit,
                                              RegionType::kImage, kWin32PageReadWrite);
    suite.expect(classifyRegionCode(kImageData) == RegionCodeClass::kNonExecutable,
                 L"J-01 映像数据页不可执行");

    const RegionRecord kReserved = makeRegion(0x400000U, 0x1000U, RegionState::kReserved,
                                             RegionType::kPrivate, kWin32PageNoAccess);
    suite.expect(classifyRegionCode(kReserved) == RegionCodeClass::kNotCommitted,
                 L"J-01 未提交区域不参与代码分类");

    const RegionRecord kFreeRegion = makeRegion(0x500000U, 0x1000U, RegionState::kFree,
                                               RegionType::kUnknown, kWin32PageNoAccess);
    suite.expect(classifyRegionCode(kFreeRegion) == RegionCodeClass::kNotCommitted,
                 L"J-01 空闲区域不参与代码分类");

    // Executable but type unknown: cannot be forced into any category.
    const RegionRecord kUnknownType = makeRegion(0x600000U, 0x1000U, RegionState::kCommit,
                                                RegionType::kUnknown, kWin32PageExecuteRead);
    suite.expect(classifyRegionCode(kUnknownType) == RegionCodeClass::kUnknown,
                 L"J-01 类型未知不硬判");
    suite.expect(!isDynamicCodeCandidate(RegionCodeClass::kUnknown),
                 L"J-01 未知不是候选");
}

// ---------------------------------------------------------------------------
// J-01: Address space index.
// ---------------------------------------------------------------------------
void testAddressSpaceIndex(ksword_tests::Suite& suite) {
    // A private allocation starting at 0x100000 with three sub-regions: RW / RX / RW.
    // After aggregation, the middle page must still be visible as RX — this ensures 'no loss of permissions for each sub-region'.
    std::vector<RegionRecord> records;
    records.push_back(makeRegion(0x102000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageReadWrite, 0x100000U));
    records.push_back(makeRegion(0x100000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageReadWrite, 0x100000U));
    records.push_back(makeRegion(0x101000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageExecuteRead, 0x100000U));
    records.push_back(makeRegion(0x140000000ULL, 0x2000U, RegionState::kCommit,
                                 RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                 "C:\\app\\target.exe"));

    const AddressSpaceIndex kIndex = buildAddressSpaceIndex(records, CollectionOutcome::success());
    suite.expect(kIndex.entries.size() == 4U, L"J-01 索引保留全部子区域");
    suite.expect(kIndex.searchableCount == 4U, L"J-01 全部记录可参与查找");
    suite.expect(kIndex.entries[0].base.value == 0x100000U, L"J-01 索引按 base 升序");
    suite.expect(kIndex.entries[3].base.value == 0x140000000ULL, L"J-01 索引末项是映像");
    suite.expect(kIndex.groups.size() == 2U, L"J-01 按 AllocationBase 聚合成两组");
    suite.expect(kIndex.dynamicCodeCandidateCount == 1U, L"J-01 动态代码候选计数");
    suite.expect(kIndex.committedBytes == 0x5000U, L"J-01 已提交字节合计");
    suite.expect(kIndex.executableBytes == 0x3000U, L"J-01 可执行字节合计");

    const std::size_t kRxEntry = kIndex.findEntry(0x101800U);
    suite.expect(kRxEntry != AddressSpaceIndex::kNoEntry, L"J-01 命中 RX 子区域");
    suite.expect(kIndex.codeClasses[kRxEntry] == RegionCodeClass::kPrivateExecutable,
                 L"J-01 聚合后子区域权限未被吞掉");

    const AllocationGroup* group = kIndex.groupForEntry(kRxEntry);
    suite.expect(group != nullptr, L"J-01 子区域可回到分配组");
    if (group != nullptr) {
        suite.expect(group->allocationBase.present && group->allocationBase.value == 0x100000U,
                     L"J-01 分配组基址");
        suite.expect(group->entryIndices.size() == 3U, L"J-01 分配组含三个子区域");
        suite.expect(group->anyExecutable, L"J-01 分配组标记含可执行子区域");
        suite.expect(!group->anyWritableExecutable, L"J-01 R-X 不是可写可执行");
        suite.expect(group->executableBytes == 0x1000U, L"J-01 分配组可执行字节");
        suite.expect(group->committedBytes == 0x3000U, L"J-01 分配组已提交字节");
        suite.expect(!group->typeMixed, L"J-01 同类型不标混合");
    }

    // Boundary: Right end of interval is open.
    suite.expect(kIndex.findEntry(0x100000U) != AddressSpaceIndex::kNoEntry, L"J-01 左端命中");
    suite.expect(kIndex.findEntry(0x102FFFU) != AddressSpaceIndex::kNoEntry, L"J-01 右端内命中");
    suite.expect(kIndex.findEntry(0x103000U) == AddressSpaceIndex::kNoEntry,
                 L"J-01 右端开区间不命中");
    suite.expect(kIndex.findEntry(0x0FFFFFU) == AddressSpaceIndex::kNoEntry, L"J-01 左侧空洞");
    suite.expect(kIndex.findEntry(0x7FFFFFFFFFFFULL) == AddressSpaceIndex::kNoEntry,
                 L"J-01 索引外地址不编造归属");

    suite.expect(kIndex.coverage.succeeded == 4U, L"J-01 账目成功数");
    suite.expect(kIndex.coverage.failed == 0U, L"J-01 账目失败数");
    suite.expect(kIndex.usableForAbsenceInference(), L"J-01 成功且完整才可做缺项推断");

    // Broken record: reserved but excluded from lookup, and counted as failed.
    RegionRecord broken;
    broken.base = OptionalU64::of(0x900000U);
    broken.state = RegionState::kCommit;
    broken.type = RegionType::kPrivate;
    std::vector<RegionRecord> withBroken = records;
    withBroken.push_back(broken);
    const AddressSpaceIndex kBrokenIndex =
        buildAddressSpaceIndex(withBroken, CollectionOutcome::success());
    suite.expect(kBrokenIndex.entries.size() == 5U, L"J-01 残缺记录不被丢弃");
    suite.expect(kBrokenIndex.searchableCount == 4U, L"J-01 残缺记录不参与查找");
    suite.expect(kBrokenIndex.coverage.failed == 1U, L"J-01 残缺记录计入失败");
    suite.expect(!kBrokenIndex.coverage.fullyCovered(), L"J-01 有失败即非完整覆盖");
    suite.expect(!kBrokenIndex.usableForAbsenceInference(), L"J-01 不完整不得做缺项推断");
    suite.expect(kBrokenIndex.findEntry(0x900000U) == AddressSpaceIndex::kNoEntry,
                 L"J-01 残缺记录不产生假命中");

    // Collection failed: even if the list happens to be complete, there is no qualification for absence inference.
    const AddressSpaceIndex kDeniedIndex = buildAddressSpaceIndex(records, accessDeniedOutcome());
    suite.expect(!kDeniedIndex.usableForAbsenceInference(), L"J-01 拒绝访问不得做缺项推断");
    suite.expect(kDeniedIndex.outcome.nativeCode.present && kDeniedIndex.outcome.nativeCode.value == 5U,
                 L"J-01 失败保留原始错误码");

    // Regions without AllocationBase form their own group and must not be merged into others.
    RegionRecord orphan = makeRegion(0x800000U, 0x1000U, RegionState::kCommit,
                                     RegionType::kPrivate, kWin32PageReadWrite);
    orphan.allocationBase = OptionalU64::unset();
    std::vector<RegionRecord> withOrphan = records;
    withOrphan.push_back(orphan);
    const AddressSpaceIndex kOrphanIndex =
        buildAddressSpaceIndex(withOrphan, CollectionOutcome::success());
    suite.expect(kOrphanIndex.groups.size() == 3U, L"J-01 无 AllocationBase 自成一组");

    // Empty input + failure status: does not mean "address space is empty".
    const AddressSpaceIndex kEmptyDenied = buildAddressSpaceIndex({}, accessDeniedOutcome());
    suite.expect(kEmptyDenied.entries.empty(), L"J-01 空输入无条目");
    suite.expect(!kEmptyDenied.usableForAbsenceInference(), L"J-01 空+失败不等于确认为空");
}

// ---------------------------------------------------------------------------
// J-01b: Cheap summary filter for the process list
// ---------------------------------------------------------------------------
void testSurfaceScreen(ksword_tests::Suite& suite) {
    suite.expect(surfaceScreenCountsAreMeaningful(SurfaceScreenState::kScreened),
                 L"筛选 只有已筛选的计数有意义");
    suite.expect(!surfaceScreenCountsAreMeaningful(SurfaceScreenState::kAccessDenied),
                 L"筛选 访问受限的 0 不是没有");
    suite.expect(!surfaceScreenCountsAreMeaningful(SurfaceScreenState::kNotScreened),
                 L"筛选 未筛选的 0 不是没有");
    suite.expect(!surfaceScreenCountsAreMeaningful(SurfaceScreenState::kFailed),
                 L"筛选 失败的 0 不是没有");

    std::vector<RegionRecord> records;
    records.push_back(makeRegion(0x140000000ULL, 0x10000U, RegionState::kCommit,
                                 RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                 "C:\\app\\target.exe"));
    records.push_back(makeRegion(0x200000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageExecuteReadWrite));   // Private RWX
    records.push_back(makeRegion(0x300000U, 0x2000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageExecuteRead));        // Private R-X (non-writable)
    records.push_back(makeRegion(0x400000U, 0x4000U, RegionState::kCommit, RegionType::kMapped,
                                 kWin32PageExecuteRead));        // Map R-X
    records.push_back(makeRegion(0x500000U, 0x8000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageReadWrite));          // Ordinary RW; not counted

    const AddressSpaceIndex kIndex = buildAddressSpaceIndex(records, CollectionOutcome::success());
    const ProcessSurfaceScreen kScreen =
        summarizeSurfaceScreen(kIndex, OptionalU64::of(0x1D100000000ULL));
    suite.expect(kScreen.state == SurfaceScreenState::kScreened, L"筛选 成功态");
    suite.expect(kScreen.regionCount == 5U, L"筛选 区域总数");
    suite.expect(kScreen.dynamicCodeRegions == 3U, L"筛选 动态代码区域数（私有+映射）");
    suite.expect(kScreen.writableExecutableRegions == 1U, L"筛选 可写可执行区域数");
    suite.expect(kScreen.dynamicCodeBytes == 0x7000U, L"筛选 动态代码字节数");
    suite.expect(kScreen.screenedUtc100ns.present &&
                     kScreen.screenedUtc100ns.value == 0x1D100000000ULL,
                 L"筛选 记录首次观测时间");

    // Access restricted: count remains 0, but the status indicates this 0 means 'unknown'.
    const AddressSpaceIndex kDenied = buildAddressSpaceIndex(records, accessDeniedOutcome());
    const ProcessSurfaceScreen kDeniedScreen =
        summarizeSurfaceScreen(kDenied, OptionalU64::unset());
    suite.expect(kDeniedScreen.state == SurfaceScreenState::kAccessDenied,
                 L"筛选 拒绝访问态");
    suite.expect(kDeniedScreen.dynamicCodeRegions == 0U, L"筛选 拒绝访问不给计数");
    suite.expect(!surfaceScreenCountsAreMeaningful(kDeniedScreen.state),
                 L"筛选 拒绝访问的计数不可用");

    CollectionOutcome notCollected;
    const AddressSpaceIndex kEmpty = buildAddressSpaceIndex({}, notCollected);
    suite.expect(summarizeSurfaceScreen(kEmpty, OptionalU64::unset()).state ==
                     SurfaceScreenState::kNotScreened,
                 L"筛选 未采集态");

    CollectionOutcome unsupported;
    unsupported.status = CollectionStatus::kUnsupported;
    const AddressSpaceIndex kUnsup = buildAddressSpaceIndex(records, unsupported);
    suite.expect(summarizeSurfaceScreen(kUnsup, OptionalU64::unset()).state ==
                     SurfaceScreenState::kFailed,
                 L"筛选 不支持归入失败态");

    // Partial success still counts (execution happened), but the caller can detect incompleteness from the status.
    CollectionOutcome partial;
    partial.status = CollectionStatus::kPartial;
    const AddressSpaceIndex kPartialIndex = buildAddressSpaceIndex(records, partial);
    const ProcessSurfaceScreen kPartialScreen =
        summarizeSurfaceScreen(kPartialIndex, OptionalU64::unset());
    suite.expect(kPartialScreen.state == SurfaceScreenState::kScreened,
                 L"筛选 部分成功仍给计数");
    suite.expect(kPartialScreen.dynamicCodeRegions == 3U, L"筛选 部分成功计数一致");
}

// ---------------------------------------------------------------------------
// J-02: Module cross-view.
// ---------------------------------------------------------------------------
void testModuleCrossView(ksword_tests::Suite& suite) {
    ModuleCrossViewInput input;
    input.loaderOutcome = CollectionOutcome::success();
    input.imageOutcome = CollectionOutcome::success();
    input.payloadOutcome = CollectionOutcome::success();
    input.loaderTrust = ModuleEnumerationTrust::kTrusted;
    input.mainImagePathFromLoader = "C:\\app\\target.exe";
    input.mainImagePathFromKernel = "C:\\app\\target.exe";
    input.mainImagePathFromMapping = "\\Device\\HarddiskVolume3\\app\\target.exe";
    input.mainImageBaseFromLoader = OptionalU64::of(0x140000000ULL);
    input.mainImageBaseFromMapping = OptionalU64::of(0x140000000ULL);

    LoaderModuleEntry main;
    main.module = makeModule("C:\\app\\target.exe", 0x140000000ULL, 0x10000U);
    main.listedName = "target.exe";
    main.isMainImage = true;
    LoaderModuleEntry ntdll;
    ntdll.module = makeModule("C:\\Windows\\System32\\ntdll.dll", 0x7FF800000000ULL, 0x20000U);
    ntdll.listedName = "ntdll.dll";
    input.loaderView = { main, ntdll };

    ImageMappingEntry mainMap;
    mainMap.allocationBase = OptionalU64::of(0x140000000ULL);
    mainMap.mappedSize = OptionalU64::of(0x10000U);
    mainMap.mappedPath = "\\Device\\HarddiskVolume3\\app\\target.exe";
    mainMap.pathOutcome = CollectionOutcome::success();
    ImageMappingEntry ntdllMap;
    ntdllMap.allocationBase = OptionalU64::of(0x7FF800000000ULL);
    ntdllMap.mappedSize = OptionalU64::of(0x20000U);
    ntdllMap.mappedPath = "\\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll";
    ntdllMap.pathOutcome = CollectionOutcome::success();
    input.imageView = { mainMap, ntdllMap };

    const ModuleCrossViewReport kClean = evaluateModuleCrossView(input);
    suite.expect(kClean.matchedModules == 2U, L"J-02 两个模块都对上");
    suite.expect(kClean.findings.empty(), L"J-02 设备路径与 DOS 路径不产生假不一致");
    suite.expect(kClean.absenceInferenceAllowed, L"J-02 两侧成功才允许缺项推断");
    suite.expect(kClean.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"J-02 干净场景结论");
    suite.expect(kClean.coverageGapKeys.empty(), L"J-02 干净场景无缺口");

    // Manual mapping: has image mapping, but not in loader list.
    ModuleCrossViewInput manual = input;
    ImageMappingEntry ghost;
    ghost.allocationBase = OptionalU64::of(0x7FF900000000ULL);
    ghost.mappedSize = OptionalU64::of(0x8000U);
    ghost.mappedPath = "\\Device\\HarddiskVolume3\\temp\\payload.dll";
    ghost.pathOutcome = CollectionOutcome::success();
    manual.imageView.push_back(ghost);
    const ModuleCrossViewReport kManualReport = evaluateModuleCrossView(manual);
    suite.expect(kManualReport.mappingOnly == 1U, L"J-02 映像无加载器项计数");
    suite.expect(countIssue(kManualReport, ModuleCrossIssue::kImageMappingWithoutLoaderEntry) == 1U,
                 L"J-02 映像无加载器项产出");
    suite.expect(kManualReport.conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"J-02 交叉矛盾结论");

    // Loader has an entry but it is not mapped.
    ModuleCrossViewInput phantom = input;
    LoaderModuleEntry unmapped;
    unmapped.module = makeModule("C:\\temp\\phantom.dll", 0x7FFA00000000ULL, 0x4000U);
    unmapped.listedName = "phantom.dll";
    phantom.loaderView.push_back(unmapped);
    const ModuleCrossViewReport kPhantomReport = evaluateModuleCrossView(phantom);
    suite.expect(kPhantomReport.loaderOnly == 1U, L"J-02 加载器项无映射计数");
    suite.expect(countIssue(kPhantomReport, ModuleCrossIssue::kLoaderEntryWithoutImageMapping) == 1U,
                 L"J-02 加载器项无映射产出");

    // Loader view failure: missing items are not inferred; only gaps are left.
    ModuleCrossViewInput denied = manual;
    denied.loaderOutcome = accessDeniedOutcome();
    const ModuleCrossViewReport kDeniedReport = evaluateModuleCrossView(denied);
    suite.expect(!kDeniedReport.absenceInferenceAllowed, L"J-02 视图失败即无缺项资格");
    suite.expect(countIssue(kDeniedReport, ModuleCrossIssue::kImageMappingWithoutLoaderEntry) == 0U,
                 L"J-02 视图失败不产出缺项");
    suite.expect(hasGap(kDeniedReport.coverageGapKeys, kGapLoaderViewUnavailable),
                 L"J-02 视图失败留缺口键");
    suite.expect(kDeniedReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"J-02 视图失败不得表述为未发现差异");

    // Partial success also lacks eligibility for missing items: Partial is not Success.
    ModuleCrossViewInput partial = manual;
    partial.imageOutcome.status = CollectionStatus::kPartial;
    const ModuleCrossViewReport kPartialReport = evaluateModuleCrossView(partial);
    suite.expect(!kPartialReport.absenceInferenceAllowed, L"J-02 部分成功无缺项资格");
    suite.expect(hasGap(kPartialReport.coverageGapKeys, kGapImageViewUnavailable),
                 L"J-02 部分成功留缺口键");

    // WOW64 collector: Module filter parameters are ignored, resulting in a naturally incomplete list.
    ModuleCrossViewInput wow = manual;
    wow.loaderTrust = ModuleEnumerationTrust::kFilterIgnoredUnderWow64;
    const ModuleCrossViewReport kWowReport = evaluateModuleCrossView(wow);
    suite.expect(!kWowReport.absenceInferenceAllowed, L"J-02 WOW64 列表无缺项资格");
    suite.expect(hasGap(kWowReport.coverageGapKeys, kGapModuleEnumerationWow64),
                 L"J-02 WOW64 留缺口键");

    // Path not found: this is a gap, not 'file implantation' nor 'observed discrepancy'.
    ModuleCrossViewInput noPath = input;
    noPath.imageView[1].mappedPath.clear();
    noPath.imageView[1].pathOutcome = accessDeniedOutcome();
    const ModuleCrossViewReport kNoPathReport = evaluateModuleCrossView(noPath);
    suite.expect(countIssue(kNoPathReport, ModuleCrossIssue::kMappedPathUnavailable) == 1U,
                 L"J-02 路径失败留证据");
    suite.expect(hasGap(kNoPathReport.coverageGapKeys, kGapMappedPathUnavailable),
                 L"J-02 路径失败留缺口键");
    suite.expect(kNoPathReport.conclusion != AnalysisConclusion::kDifferenceObserved,
                 L"J-02 路径失败本身不是差异");
    suite.expect(kNoPathReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"J-02 路径失败不得表述为未发现差异");

    // Path mismatch.
    ModuleCrossViewInput mismatch = input;
    mismatch.imageView[1].mappedPath = "\\Device\\HarddiskVolume3\\temp\\fake.dll";
    const ModuleCrossViewReport kMismatchReport = evaluateModuleCrossView(mismatch);
    suite.expect(countIssue(kMismatchReport, ModuleCrossIssue::kLoaderPathMismatch) == 1U,
                 L"J-02 路径不一致产出");

    // Size mismatch: report only if exceeding tolerance.
    ModuleCrossViewInput sizeClose = input;
    sizeClose.imageView[1].mappedSize = OptionalU64::of(0x20000U + 0x1000U);
    const ModuleCrossViewReport kSizeCloseReport = evaluateModuleCrossView(sizeClose);
    suite.expect(countIssue(kSizeCloseReport, ModuleCrossIssue::kLoaderSizeMismatch) == 0U,
                 L"J-02 容差内不报大小不一致");

    ModuleCrossViewInput sizeFar = input;
    sizeFar.imageView[1].mappedSize = OptionalU64::of(0x200000U);
    const ModuleCrossViewReport kSizeFarReport = evaluateModuleCrossView(sizeFar);
    suite.expect(countIssue(kSizeFarReport, ModuleCrossIssue::kLoaderSizeMismatch) == 1U,
                 L"J-02 超容差报大小不一致");

    // Main image is contradictory.
    ModuleCrossViewInput conflict = input;
    conflict.mainImagePathFromKernel = "C:\\Windows\\System32\\svchost.exe";
    const ModuleCrossViewReport kConflictReport = evaluateModuleCrossView(conflict);
    suite.expect(countIssue(kConflictReport, ModuleCrossIssue::kMainImageIdentityConflict) == 1U,
                 L"J-02 主映像身份矛盾产出");

    ModuleCrossViewInput baseConflict = input;
    baseConflict.mainImageBaseFromMapping = OptionalU64::of(0x150000000ULL);
    const ModuleCrossViewReport kBaseConflictReport = evaluateModuleCrossView(baseConflict);
    suite.expect(countIssue(kBaseConflictReport, ModuleCrossIssue::kMainImageIdentityConflict) == 1U,
                 L"J-02 主映像基址矛盾产出");

    // Insufficient sources for the main image: a gap.
    ModuleCrossViewInput oneSource = input;
    oneSource.mainImagePathFromKernel.clear();
    oneSource.mainImagePathFromMapping.clear();
    const ModuleCrossViewReport kOneSourceReport = evaluateModuleCrossView(oneSource);
    suite.expect(hasGap(kOneSourceReport.coverageGapKeys, kGapMainImageSourceMissing),
                 L"J-02 主映像来源不足留缺口");

    // No observations on either side: NoEvidence, not "no difference found".
    ModuleCrossViewInput nothing;
    nothing.loaderOutcome = accessDeniedOutcome();
    nothing.imageOutcome = accessDeniedOutcome();
    nothing.payloadOutcome = accessDeniedOutcome();
    const ModuleCrossViewReport kNothingReport = evaluateModuleCrossView(nothing);
    suite.expect(kNothingReport.conclusion == AnalysisConclusion::kNoEvidence,
                 L"J-02 无观测即无证据");

    // Pass through payload candidate count.
    ModuleCrossViewInput payload = input;
    PayloadCandidateEntry candidate;
    candidate.base = OptionalU64::of(0x300000U);
    candidate.size = OptionalU64::of(0x2000U);
    candidate.type = RegionType::kPrivate;
    candidate.structure = PayloadStructure::kHeaderErasedPe;
    candidate.outcome = CollectionOutcome::success();
    payload.payloadView.push_back(candidate);
    const ModuleCrossViewReport kPayloadReport = evaluateModuleCrossView(payload);
    suite.expect(kPayloadReport.payloadCandidates == 1U, L"J-02 载荷候选计数");
}

// ---------------------------------------------------------------------------
// J-03: Working set filtering
// ---------------------------------------------------------------------------
void testWorkingSetScreen(ksword_tests::Suite& suite) {
    WorkingSetPageFact notQueried;
    notQueried.va = 0x140001000ULL;
    suite.expect(screenWorkingSetPage(notQueried) == PageScreenVerdict::kNotQueried,
                 L"J-03 没查过就是没查过");

    WorkingSetPageFact invalid;
    invalid.va = 0x140001000ULL;
    invalid.queried = true;
    invalid.valid = false;
    invalid.shared = true;  // Do not trust this field when Valid==0.
    suite.expect(screenWorkingSetPage(invalid) == PageScreenVerdict::kInvalidNeedsRecheck,
                 L"J-03 无效页保守标待补查");

    WorkingSetPageFact invalidNotShared = invalid;
    invalidNotShared.shared = false;
    suite.expect(screenWorkingSetPage(invalidNotShared) == PageScreenVerdict::kInvalidNeedsRecheck,
                 L"J-03 无效页不因 Shared 取值而改判");

    WorkingSetPageFact privatized;
    privatized.va = 0x140002000ULL;
    privatized.queried = true;
    privatized.valid = true;
    privatized.shared = false;
    suite.expect(screenWorkingSetPage(privatized) == PageScreenVerdict::kPrivatizedCandidate,
                 L"J-03 有效且不可共享是私有化候选");

    // ShareCount == 1 does not imply Shared: this page remains 'shareable'.
    WorkingSetPageFact sharedOne;
    sharedOne.va = 0x140003000ULL;
    sharedOne.queried = true;
    sharedOne.valid = true;
    sharedOne.shared = true;
    sharedOne.shareCount = OptionalU64::of(1U);
    suite.expect(screenWorkingSetPage(sharedOne) == PageScreenVerdict::kSharedNotCleared,
                 L"J-03 ShareCount==1 不代替 Shared");

    WorkingSetPageFact sharedMany = sharedOne;
    sharedMany.shareCount = OptionalU64::of(7U);
    suite.expect(screenWorkingSetPage(sharedMany) == PageScreenVerdict::kSharedNotCleared,
                 L"J-03 多进程共享同样不放行");

    // Fast mode selects only privatized pages; deep mode does not exclude any image pages based on shared state.
    suite.expect(pageSelectedForComparison(PageScreenVerdict::kPrivatizedCandidate, SurveyMode::kFast),
                 L"J-03 快扫比较私有化页");
    suite.expect(!pageSelectedForComparison(PageScreenVerdict::kSharedNotCleared, SurveyMode::kFast),
                 L"J-03 快扫优先不比较共享页");
    suite.expect(pageSelectedForComparison(PageScreenVerdict::kSharedNotCleared, SurveyMode::kDeep),
                 L"J-03 深扫不排除共享页");
    suite.expect(pageSelectedForComparison(PageScreenVerdict::kInvalidNeedsRecheck, SurveyMode::kDeep),
                 L"J-03 深扫补查无效页");
    suite.expect(!pageSelectedForComparison(PageScreenVerdict::kNotQueried, SurveyMode::kDeep),
                 L"J-03 没查过的页不能当成已比较");
    suite.expect(!pageSelectedForComparison(PageScreenVerdict::kNotQueried, SurveyMode::kFast),
                 L"J-03 快扫同样不把未查页当已比较");
}

// ---------------------------------------------------------------------------
// J-04: Thread start point
// ---------------------------------------------------------------------------
void testThreadStarts(ksword_tests::Suite& suite) {
    std::vector<RegionRecord> records;
    // Main image 0x140000000, code RVA [0x1000, 0x5000).
    records.push_back(makeRegion(0x140000000ULL, 0x10000U, RegionState::kCommit,
                                 RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                 "C:\\app\\target.exe"));
    // Private executable block.
    records.push_back(makeRegion(0x300000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageExecuteReadWrite));
    // Private but currently non-executable (payload suspended).
    records.push_back(makeRegion(0x310000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageReadWrite));
    // Map non-image.
    records.push_back(makeRegion(0x320000U, 0x1000U, RegionState::kCommit, RegionType::kMapped,
                                 kWin32PageExecuteRead, 0x320000U, "C:\\temp\\blob.bin"));
    // Reserved but not committed.
    records.push_back(makeRegion(0x330000U, 0x1000U, RegionState::kReserved, RegionType::kPrivate,
                                 kWin32PageNoAccess));

    const AddressSpaceIndex kIndex = buildAddressSpaceIndex(records, CollectionOutcome::success());
    const std::vector<ImageCodeExtent> kImages = {
        makeImage("C:\\app\\target.exe", 0x140000000ULL, 0x10000U, 0x1000U, 0x5000U),
    };

    const ProcessInstanceId kProcess = makeProcess(4321U, 0x1D000000000ULL);

    std::vector<ThreadStartInput> threads;
    ThreadStartInput inCode;
    inCode.thread = makeThread(kProcess, 1001U);
    inCode.startAddress = OptionalU64::of(0x140002000ULL);
    inCode.startAddressOutcome = CollectionOutcome::success();
    threads.push_back(inCode);

    ThreadStartInput outsideCode;
    outsideCode.thread = makeThread(kProcess, 1002U);
    outsideCode.startAddress = OptionalU64::of(0x140008000ULL);
    outsideCode.startAddressOutcome = CollectionOutcome::success();
    threads.push_back(outsideCode);

    ThreadStartInput privateStart;
    privateStart.thread = makeThread(kProcess, 1003U);
    privateStart.startAddress = OptionalU64::of(0x300100U);
    privateStart.startAddressOutcome = CollectionOutcome::success();
    threads.push_back(privateStart);

    ThreadStartInput dormant;
    dormant.thread = makeThread(kProcess, 1004U);
    dormant.startAddress = OptionalU64::of(0x310100U);
    dormant.startAddressOutcome = CollectionOutcome::success();
    threads.push_back(dormant);

    ThreadStartInput mappedStart;
    mappedStart.thread = makeThread(kProcess, 1005U);
    mappedStart.startAddress = OptionalU64::of(0x320100U);
    mappedStart.startAddressOutcome = CollectionOutcome::success();
    threads.push_back(mappedStart);

    ThreadStartInput reservedStart;
    reservedStart.thread = makeThread(kProcess, 1006U);
    reservedStart.startAddress = OptionalU64::of(0x330100U);
    reservedStart.startAddressOutcome = CollectionOutcome::success();
    threads.push_back(reservedStart);

    ThreadStartInput unmapped;
    unmapped.thread = makeThread(kProcess, 1007U);
    unmapped.startAddress = OptionalU64::of(0x900000U);
    unmapped.startAddressOutcome = CollectionOutcome::success();
    threads.push_back(unmapped);

    ThreadStartInput missing;
    missing.thread = makeThread(kProcess, 1008U);
    missing.startAddressOutcome = accessDeniedOutcome();
    threads.push_back(missing);

    // The entry point lies within a valid module, but the first jump exits that module (trampoline).
    ThreadStartInput trampoline;
    trampoline.thread = makeThread(kProcess, 1009U);
    trampoline.startAddress = OptionalU64::of(0x140003000ULL);
    trampoline.startAddressOutcome = CollectionOutcome::success();
    trampoline.entryInspected = true;
    trampoline.entryReadable = true;
    trampoline.immediateBranchTarget = OptionalU64::of(0x300200U);
    threads.push_back(trampoline);

    const std::vector<ThreadStartFinding> kFindings =
        evaluateThreadStarts(threads, kIndex, kImages);
    suite.expect(kFindings.size() == 9U, L"J-04 每个线程一条结果");

    suite.expect(kFindings[0].landing == ThreadStartLanding::kImageCodeRange,
                 L"J-04 起点落在映像代码范围");
    suite.expect(kFindings[0].owningPath == "C:\\app\\target.exe", L"J-04 归属模块路径");

    suite.expect(kFindings[1].landing == ThreadStartLanding::kImageOutsideCode,
                 L"J-04 起点在映像内但不符合代码布局");

    suite.expect(kFindings[2].landing == ThreadStartLanding::kNonImagePrivate,
                 L"J-04 起点落在私有区域");
    suite.expect(kFindings[2].startPageExecutableKnown && kFindings[2].startPageExecutable,
                 L"J-04 私有起点页可执行事实");

    // The start page is now non-executable, but this cannot be used to ignore this lead: landing remains NonImagePrivate.
    suite.expect(kFindings[3].landing == ThreadStartLanding::kNonImagePrivate,
                 L"J-04 起点页不可执行不改变落点判定");
    suite.expect(kFindings[3].startPageExecutableKnown && !kFindings[3].startPageExecutable,
                 L"J-04 起点页不可执行作为并列事实记录");

    suite.expect(kFindings[4].landing == ThreadStartLanding::kNonImageMapped,
                 L"J-04 起点落在映射非映像区域");
    suite.expect(kFindings[4].owningPath == "C:\\temp\\blob.bin", L"J-04 映射来源路径");

    suite.expect(kFindings[5].landing == ThreadStartLanding::kFreeOrReserved,
                 L"J-04 起点落在未提交区域");

    suite.expect(kFindings[6].landing == ThreadStartLanding::kOutsideIndex,
                 L"J-04 索引未覆盖即缺口");

    // Start address not collected means no observation, not "ownership mismatch".
    suite.expect(kFindings[7].landing == ThreadStartLanding::kNotCollected,
                 L"J-04 起点未采集单独成态");
    suite.expect(!kFindings[7].startAddress.present, L"J-04 起点未采集不补 0");
    suite.expect(kFindings[7].outcome.status == CollectionStatus::kAccessDenied,
                 L"J-04 起点未采集保留原因");

    suite.expect(kFindings[8].landing == ThreadStartLanding::kImageCodeRange,
                 L"J-04 trampoline 起点本身正常");
    suite.expect(kFindings[8].branchTargetLanding == ThreadStartLanding::kNonImagePrivate,
                 L"J-04 trampoline 第一跳落点");
    suite.expect(kFindings[8].branchLeavesOwningModule, L"J-04 trampoline 跨模块");

    // When code layout is unknown, do not subdivide or pretend it is normal.
    const std::vector<ImageCodeExtent> kNoLayout = {
        makeImage("C:\\app\\target.exe", 0x140000000ULL, 0x10000U, 0U, 0U, false),
    };
    const std::vector<ThreadStartFinding> kNoLayoutFindings =
        evaluateThreadStarts({ outsideCode }, kIndex, kNoLayout);
    suite.expect(kNoLayoutFindings.size() == 1U, L"J-04 布局未知仍产出结果");
    suite.expect(kNoLayoutFindings[0].landing == ThreadStartLanding::kImageLayoutUnknown,
                 L"J-04 代码布局未知单独成态");

    // Thread context trust level.
    suite.expect(classifyThreadContextTrust(false, false, false) == ThreadContextTrust::kNotCaptured,
                 L"J-04 未取上下文");
    suite.expect(classifyThreadContextTrust(true, false, false) ==
                     ThreadContextTrust::kRunningThreadUntrusted,
                 L"J-04 运行中线程上下文不可信");
    suite.expect(classifyThreadContextTrust(true, true, false) ==
                     ThreadContextTrust::kSuspendedOrSnapshot,
                 L"J-04 挂起/快照上下文可用");
    // No suspension and no snapshot, but both checks occur while waiting — this is the actual state this feature consumes.
    suite.expect(classifyThreadContextTrust(true, false, true) ==
                     ThreadContextTrust::kWaitingThreadStable,
                 L"J-04 等待中线程上下文稳定");
    // Suspended takes precedence over 'both in waiting': it does not rely on the premise that the state remained unchanged during collection.
    suite.expect(classifyThreadContextTrust(true, true, true) ==
                     ThreadContextTrust::kSuspendedOrSnapshot,
                 L"J-04 挂起优先于等待态");
    // If the context is not retrieved, it does not matter whether the thread is waiting or not.
    suite.expect(classifyThreadContextTrust(false, true, true) == ThreadContextTrust::kNotCaptured,
                 L"J-04 没取到就是没取到");
    suite.expect(!contextUsableAsExecutionEvidence(ThreadContextTrust::kRunningThreadUntrusted),
                 L"J-04 运行中上下文不得当执行证据");
    suite.expect(!contextUsableAsExecutionEvidence(ThreadContextTrust::kNotCaptured),
                 L"J-04 未取上下文不得当执行证据");
    suite.expect(contextUsableAsExecutionEvidence(ThreadContextTrust::kSuspendedOrSnapshot),
                 L"J-04 快照上下文可当执行证据");
    suite.expect(contextUsableAsExecutionEvidence(ThreadContextTrust::kWaitingThreadStable),
                 L"J-04 等待中上下文可当执行证据");

    // Stack evidence is separated into three tiers.
    suite.expect(stackEvidenceCountsAsExecution(StackEvidenceKind::kReliableUnwoundFrame),
                 L"J-04 可靠帧算执行证据");
    suite.expect(!stackEvidenceCountsAsExecution(
                     StackEvidenceKind::kHeuristicReturnAddressCandidate),
                 L"J-04 启发式候选返回地址不算执行证据");
    suite.expect(!stackEvidenceCountsAsExecution(StackEvidenceKind::kPlainPointerReference),
                 L"J-04 栈上像地址的数值不算调用帧");
}

// ---------------------------------------------------------------------------
// J-05: Compare plan with reference trustworthiness
// ---------------------------------------------------------------------------
void testComparisonPlan(ksword_tests::Suite& suite) {
    // Hard constraint: The normalization profiles for both modes must be identical.
    suite.expect(std::string(normalizationProfileId(SurveyMode::kFast)) ==
                     std::string(normalizationProfileId(SurveyMode::kDeep)),
                 L"J-05 快扫深扫归一化 profile 相同");
    suite.expect(normalizationProfileVersion(SurveyMode::kFast) ==
                     normalizationProfileVersion(SurveyMode::kDeep),
                 L"J-05 快扫深扫归一化版本相同");

    ComparisonPlanInput input;
    input.mode = SurveyMode::kFast;
    input.images = {
        makeImage("C:\\app\\target.exe", 0x140000000ULL, 0x10000U, 0x1000U, 0x5000U),
        makeImage("C:\\Windows\\System32\\ntdll.dll", 0x7FF800000000ULL, 0x20000U, 0x1000U,
                  0x12000U),
    };
    input.mainImagePath = "C:\\app\\target.exe";
    input.mainImageEntryRva = OptionalU64::of(0x1500U);
    input.entryWindowBytes = 64U;
    input.threadEntrySites.push_back({ "C:\\Windows\\System32\\ntdll.dll", 0x2000U });
    input.screenedPages.push_back({ "C:\\app\\target.exe", 0x3000U });

    const ComparisonPlan kFast = buildComparisonPlan(input);
    suite.expect(kFast.normalizationProfileId == std::string(kNormalizationProfileId),
                 L"J-05 计划记录归一化 profile");
    suite.expect(kFast.targets.size() == 3U, L"J-05 快扫计划三个定向目标");
    suite.expect(kFast.targets[0].reason == ComparisonReason::kMainImageEntry,
                 L"J-05 主映像入口优先");
    suite.expect(kFast.targets[0].range.rva == 0x1500U && kFast.targets[0].range.length == 64U,
                 L"J-05 主映像入口窗口");
    suite.expect(kFast.targets[1].reason == ComparisonReason::kSuspiciousThreadEntry,
                 L"J-05 可疑线程入口进入计划");
    suite.expect(kFast.targets[2].reason == ComparisonReason::kWorkingSetScreenedPage,
                 L"J-05 工作集筛出页进入计划");
    suite.expect(kFast.targets[2].range.length == 4096U, L"J-05 筛出页按页比较");
    suite.expect(kFast.coverageGapKeys.empty(), L"J-05 快扫计划无缺口");

    ComparisonPlanInput deepInput = input;
    deepInput.mode = SurveyMode::kDeep;
    const ComparisonPlan kDeep = buildComparisonPlan(deepInput);
    suite.expect(kDeep.normalizationProfileId == kFast.normalizationProfileId,
                 L"J-05 深扫沿用同一 profile");
    suite.expect(kDeep.targets.size() == 5U, L"J-05 深扫追加全量可执行范围");
    suite.expect(kDeep.targets[0].reason == ComparisonReason::kFullExecutableCoverage,
                 L"J-05 深扫先覆盖全部可执行映像范围");
    suite.expect(kDeep.targets[0].range.rva == 0x1000U && kDeep.targets[0].range.length == 0x4000U,
                 L"J-05 深扫覆盖代码区间");

    // Main image entry unavailable: a gap, not 'no entry'.
    ComparisonPlanInput noEntry = input;
    noEntry.mainImageEntryRva = OptionalU64::unset();
    const ComparisonPlan kNoEntryPlan = buildComparisonPlan(noEntry);
    suite.expect(hasGap(kNoEntryPlan.coverageGapKeys, kGapMainImageSourceMissing),
                 L"J-05 主映像入口缺失留缺口");

    ComparisonPlanInput noMain = input;
    noMain.mainImagePath.clear();
    const ComparisonPlan kNoMainPlan = buildComparisonPlan(noMain);
    suite.expect(hasGap(kNoMainPlan.coverageGapKeys, kGapMainImageSourceMissing),
                 L"J-05 主映像路径缺失留缺口");

    // Thread entry points to an unknown module: gap.
    ComparisonPlanInput unknownModule = input;
    unknownModule.threadEntrySites.push_back({ "C:\\temp\\unknown.dll", 0x1000U });
    const ComparisonPlan kUnknownPlan = buildComparisonPlan(unknownModule);
    suite.expect(hasGap(kUnknownPlan.coverageGapKeys, kGapThreadStartUnavailable),
                 L"J-05 入口模块未知留缺口");

    // Range is clipped to image boundaries to prevent out-of-bounds access.
    ComparisonPlanInput nearEnd = input;
    nearEnd.mainImageEntryRva = OptionalU64::of(0xFFE0U);
    const ComparisonPlan kNearEndPlan = buildComparisonPlan(nearEnd);
    suite.expect(!kNearEndPlan.targets.empty(), L"J-05 边界附近仍产出目标");
    if (!kNearEndPlan.targets.empty()) {
        suite.expect(kNearEndPlan.targets[0].range.rva == 0xFFE0U &&
                         kNearEndPlan.targets[0].range.length == 0x20U,
                     L"J-05 范围裁到映像边界");
    }

    // Images with unknown code layout cover the entire block in deep scan, leaving gaps.
    ComparisonPlanInput unknownLayout;
    unknownLayout.mode = SurveyMode::kDeep;
    unknownLayout.images = {
        makeImage("C:\\app\\opaque.dll", 0x180000000ULL, 0x4000U, 0U, 0U, false),
    };
    unknownLayout.mainImagePath = "C:\\app\\opaque.dll";
    unknownLayout.mainImageEntryRva = OptionalU64::of(0x100U);
    const ComparisonPlan kUnknownLayoutPlan = buildComparisonPlan(unknownLayout);
    suite.expect(hasGap(kUnknownLayoutPlan.coverageGapKeys, kGapReferenceUncertain),
                 L"J-05 代码布局未知留缺口");
    suite.expect(!kUnknownLayoutPlan.targets.empty() &&
                     kUnknownLayoutPlan.targets[0].range.length == 0x4000U,
                 L"J-05 代码布局未知覆盖整块");

    // Reference confidence: Only 'Verified' allows stating 'Modification Confirmed'.
    suite.expect(referenceSupportsDifferenceClaim(ReferenceConfidence::kReferenceVerified),
                 L"J-05 已核对参考支持差异结论");
    suite.expect(!referenceSupportsDifferenceClaim(ReferenceConfidence::kReferenceUncertain),
                 L"J-05 参考不确定不得断言修改已证实");
    suite.expect(!referenceSupportsDifferenceClaim(ReferenceConfidence::kNoReference),
                 L"J-05 无参考不得断言修改已证实");
}

// ---------------------------------------------------------------------------
// J-06: Cross-view of R0 scanning backend
// ---------------------------------------------------------------------------
SurveyInput makeCleanInput();  // Defined in the "Main Entry" section below.

// Create a stack with a "trusted context + all calculated from unwind data". frameIps are ordered from stack top to bottom.
// lastFrameHasUnwindData determines whether the last frame's PC itself has unwind data—it only affects
// Whether the next frame is reliable has no impact on the given set of frames.
ThreadStackInput makeTrustedStack(const std::uint64_t tid,
                                  const std::vector<std::uint64_t>& frameIps,
                                  const bool lastFrameHasUnwindData = true) {
    ThreadStackInput stack;
    stack.thread.tid = OptionalU64::of(tid);
    stack.trust = ThreadContextTrust::kWaitingThreadStable;
    for (std::size_t index = 0U; index < frameIps.size(); ++index) {
        RawStackFrame frame;
        frame.instructionPointer = OptionalU64::of(frameIps[index]);
        frame.stackPointer = OptionalU64::of(0x9000000ULL + index * 0x100ULL);
        frame.derivedFromUnwindData = true;
        frame.unwindDataAvailableAtPc =
            (index + 1U == frameIps.size()) ? lastFrameHasUnwindData : true;
        stack.frames.push_back(frame);
    }
    return stack;
}

void testKernelCrossView(ksword_tests::Suite& suite) {
    // Eligibility criteria are fixed first.
    suite.expect(kernelBackendSupportsAbsenceInference(KernelBackendState::kAvailable),
                 L"内核 完整可用才有缺项资格");
    suite.expect(!kernelBackendSupportsAbsenceInference(KernelBackendState::kPartial),
                 L"内核 部分完成无缺项资格");
    suite.expect(!kernelBackendSupportsAbsenceInference(KernelBackendState::kProfileUnverified),
                 L"内核 profile 未验证无缺项资格");
    suite.expect(!kernelBackendSupportsAbsenceInference(KernelBackendState::kDriverUnavailable),
                 L"内核 驱动不可用无缺项资格");
    suite.expect(!kernelBackendSupportsAbsenceInference(KernelBackendState::kNotRequested),
                 L"内核 未请求无缺项资格");

    // R3 index: one committed private region plus one image region.
    std::vector<RegionRecord> records;
    records.push_back(makeRegion(0x140000000ULL, 0x10000U, RegionState::kCommit,
                                 RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                 "C:\\app\\target.exe"));
    records.push_back(makeRegion(0x200000U, 0x2000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageReadWrite));
    const AddressSpaceIndex kIndex = buildAddressSpaceIndex(records, CollectionOutcome::success());
    suite.expect(kIndex.usableForAbsenceInference(), L"内核 R3 索引可做缺项推断");

    auto makeVadRegion = [](std::uint64_t begin, std::uint64_t end, bool priv) {
        KernelVadRegion region;
        region.startVa = OptionalU64::of(begin);
        region.endVaExclusive = OptionalU64::of(end);
        region.privateMemory = priv;
        region.vadNodeAddress = OptionalU64::of(0xFFFFA00000000000ULL + begin);
        return region;
    };

    // --- No kernel backend request: Silently skip the entire section, leaving no gaps
    {
        KernelCrossViewInput input;
        input.r3Index = &kIndex;
        const KernelCrossViewReport kReport = evaluateKernelCrossView(input);
        suite.expect(kReport.findings.empty(), L"内核 未请求无结果");
        suite.expect(kReport.coverageGapKeys.empty(), L"内核 未请求不留缺口");
        suite.expect(kReport.capabilityLimitKeys.empty(), L"内核 未请求不留能力限制");
        suite.expect(kReport.conclusion == AnalysisConclusion::kNoEvidence,
                     L"内核 未请求即无证据");
    }

    // --- Consistent on both sides: no findings, always blocking the 'kernel trusted' restriction ---
    {
        KernelCrossViewInput input;
        input.r3Index = &kIndex;
        input.vadView.state = KernelBackendState::kAvailable;
        input.vadView.outcome = CollectionOutcome::success();
        input.vadView.regions = {
            makeVadRegion(0x140000000ULL, 0x140010000ULL, false),
            makeVadRegion(0x200000ULL, 0x202000ULL, true),
        };
        const KernelCrossViewReport kReport = evaluateKernelCrossView(input);
        suite.expect(kReport.findings.empty(), L"内核 两侧一致无结果");
        suite.expect(kReport.absenceInferenceAllowed, L"内核 两侧完整才允许缺项推断");
        suite.expect(std::find(kReport.capabilityLimitKeys.begin(),
                               kReport.capabilityLimitKeys.end(),
                               std::string(kLimitKernelTrustAssumption)) !=
                         kReport.capabilityLimitKeys.end(),
                     L"内核 恒挂内核可信限制");
        suite.expect(std::find(kReport.capabilityLimitKeys.begin(),
                               kReport.capabilityLimitKeys.end(),
                               std::string(kLimitKernelVadFlagsUnverified)) !=
                         kReport.capabilityLimitKeys.end(),
                     L"内核 恒挂 VAD 位布局未验证限制");
        suite.expect(std::find(kReport.capabilityLimitKeys.begin(),
                               kReport.capabilityLimitKeys.end(),
                               std::string(kLimitKernelSectionCompare)) !=
                         kReport.capabilityLimitKeys.end(),
                     L"内核 恒挂第三层未做限制");
        suite.expect(kReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                     L"内核 两侧一致结论");
    }

    // --- VAD present, R3 absent: the most valuable finding (R3 view hides something) ---
    {
        KernelCrossViewInput input;
        input.r3Index = &kIndex;
        input.vadView.state = KernelBackendState::kAvailable;
        input.vadView.outcome = CollectionOutcome::success();
        input.vadView.regions = {
            makeVadRegion(0x140000000ULL, 0x140010000ULL, false),
            makeVadRegion(0x200000ULL, 0x202000ULL, true),
            makeVadRegion(0x900000ULL, 0x901000ULL, true),   // Not in R3 index
        };
        const KernelCrossViewReport kReport = evaluateKernelCrossView(input);
        suite.expect(kReport.vadOnlyCount == 1U, L"内核 VAD 独有区域计数");
        suite.expect(!kReport.findings.empty() &&
                         kReport.findings[0].issue == KernelRegionCrossIssue::kVadOnlyRange,
                     L"内核 VAD 独有区域产出");
        // The valid cause directory hasn't been created yet, so the analysis only reaches 'Indeterminate'.
        suite.expect(kReport.conclusion == AnalysisConclusion::kIndeterminate,
                     L"内核 差异只到待解释");
        suite.expect(std::find(kReport.capabilityLimitKeys.begin(),
                               kReport.capabilityLimitKeys.end(),
                               std::string(kLimitKernelBenignBaseline)) !=
                         kReport.capabilityLimitKeys.end(),
                     L"内核 有差异即声明合法成因目录未建立");
    }

    // --- Profile not verified: yields no findings, only leaves a gap ---
    {
        KernelCrossViewInput input;
        input.r3Index = &kIndex;
        input.vadView.state = KernelBackendState::kProfileUnverified;
        input.vadView.outcome = CollectionOutcome{};
        input.vadView.regions = { makeVadRegion(0x900000ULL, 0x901000ULL, true) };
        const KernelCrossViewReport kReport = evaluateKernelCrossView(input);
        suite.expect(kReport.findings.empty(), L"内核 profile 未验证不产结果");
        suite.expect(kReport.vadOnlyCount == 0U, L"内核 profile 未验证不计数");
        suite.expect(std::find(kReport.coverageGapKeys.begin(), kReport.coverageGapKeys.end(),
                               std::string(kGapKernelProfileUnverified)) !=
                         kReport.coverageGapKeys.end(),
                     L"内核 profile 未验证留缺口");
        suite.expect(kReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                     L"内核 profile 未验证不得表述为一致");
    }

    // --- Partial completion: also lacks gap eligibility.
    {
        KernelCrossViewInput input;
        input.r3Index = &kIndex;
        input.vadView.state = KernelBackendState::kPartial;
        input.vadView.outcome = CollectionOutcome{ };
        input.vadView.unreadableNodeCount = 3U;
        input.vadView.regions = { makeVadRegion(0x900000ULL, 0x901000ULL, true) };
        const KernelCrossViewReport kReport = evaluateKernelCrossView(input);
        suite.expect(!kReport.absenceInferenceAllowed, L"内核 部分完成无缺项资格");
        suite.expect(kReport.findings.empty(), L"内核 部分完成不产缺项结果");
        suite.expect(std::find(kReport.coverageGapKeys.begin(), kReport.coverageGapKeys.end(),
                               std::string(kGapKernelBackendUnavailable)) !=
                         kReport.coverageGapKeys.end(),
                     L"内核 部分完成留缺口");
    }

    // --- Page table says executable, R3 says not executable: Direct observation, no need for page fault qualification ---
    {
        KernelCrossViewInput input;
        input.r3Index = &kIndex;
        input.pteView.state = KernelBackendState::kAvailable;
        input.pteView.outcome = CollectionOutcome::success();
        KernelExecutableExtent extent;
        extent.startVa = OptionalU64::of(0x200000ULL);   // R3 states this region is RW and non-executable.
        extent.byteLength = OptionalU64::of(0x1000ULL);
        extent.pageSize = 4096U;
        extent.executable = true;
        extent.writable = true;
        extent.userAccessible = true;
        extent.firstEntryValue = OptionalU64::of(0x8000000012345067ULL);
        input.pteView.extents = { extent };
        const KernelCrossViewReport kReport = evaluateKernelCrossView(input);
        suite.expect(kReport.executableBeyondViewCount == 1U, L"内核 页表越过 R3 视图计数");
        suite.expect(!kReport.findings.empty() &&
                         kReport.findings[0].issue ==
                             KernelRegionCrossIssue::kExecutableBeyondR3View,
                     L"内核 页表越过 R3 视图产出");
        suite.expect(!kReport.absenceInferenceAllowed,
                     L"内核 页表正面观测不依赖缺项资格");
        suite.expect(kReport.conclusion == AnalysisConclusion::kIndeterminate,
                     L"内核 页表差异只到待解释");
    }

    // --- Page tables match R3: no result produced ---
    {
        KernelCrossViewInput input;
        input.r3Index = &kIndex;
        input.pteView.state = KernelBackendState::kAvailable;
        input.pteView.outcome = CollectionOutcome::success();
        KernelExecutableExtent extent;
        extent.startVa = OptionalU64::of(0x140001000ULL);  // Image RX segment
        extent.byteLength = OptionalU64::of(0x1000ULL);
        extent.pageSize = 4096U;
        extent.executable = true;
        extent.userAccessible = true;
        input.pteView.extents = { extent };
        const KernelCrossViewReport kReport = evaluateKernelCrossView(input);
        suite.expect(kReport.executableBeyondViewCount == 0U,
                     L"内核 页表与 R3 一致不产结果");
    }

    // --- Missing R3 index: do not guess ---
    {
        KernelCrossViewInput input;
        input.vadView.state = KernelBackendState::kAvailable;
        input.vadView.outcome = CollectionOutcome::success();
        const KernelCrossViewReport kReport = evaluateKernelCrossView(input);
        suite.expect(kReport.findings.empty(), L"内核 缺 R3 索引不产结果");
        suite.expect(kReport.conclusion == AnalysisConclusion::kNoEvidence,
                     L"内核 缺 R3 索引即无证据");
    }

    // --- Total entry passthrough ---
    {
        SurveyInput survey = makeCleanInput();
        survey.kernelVadState = KernelBackendState::kAvailable;
        KernelCrossViewInput crossInput;
        crossInput.r3Index = &survey.addressSpace;
        crossInput.vadView.state = KernelBackendState::kAvailable;
        crossInput.vadView.outcome = CollectionOutcome::success();
        // The VAD must cover both R3 regions in makeCleanInput simultaneously; otherwise,
        // it will produce extra R3OnlyCommittedRange entries, and the count will not be 1.
        crossInput.vadView.regions = {
            makeVadRegion(0x140000000ULL, 0x140010000ULL, false),
            makeVadRegion(0x100000ULL, 0x101000ULL, true),
            makeVadRegion(0x900000ULL, 0x901000ULL, true),
        };
        survey.kernelCrossView = evaluateKernelCrossView(crossInput);
        const SurveyReport kReport = runInjectionSurvey(survey);
        suite.expect(kReport.kernelCrossIssueCount == 1U, L"内核 总入口交叉计数");
        suite.expect(hasRule(kReport.findings, kRuleIdKernelRegionHiddenFromR3),
                     L"内核 总入口产出隐藏区域规则");
        suite.expect(kReport.hasLimit(kLimitKernelTrustAssumption),
                     L"内核 总入口透传内核可信限制");
        suite.expect(kReport.conclusion == AnalysisConclusion::kIndeterminate,
                     L"内核 总入口结论只到待解释");
        suite.expect(std::find(kReport.completedCheckKeys.begin(),
                               kReport.completedCheckKeys.end(),
                               std::string(kCheckKernelVadCrossView)) !=
                         kReport.completedCheckKeys.end(),
                     L"内核 总入口登记已完成检查");
    }

    // --- Native machine has no device: capability limitation, not a coverage gap ---
    {
        SurveyInput survey = makeCleanInput();
        survey.extraCapabilityLimitKeys.push_back(kLimitKernelBackendAbsent);
        const SurveyReport kReport = runInjectionSurvey(survey);
        suite.expect(kReport.hasLimit(kLimitKernelBackendAbsent),
                     L"内核 无设备记为能力限制");
        suite.expect(!kReport.hasGap(kLimitKernelBackendAbsent),
                     L"内核 无设备不记为覆盖缺口");
        suite.expect(kReport.scopeIntact, L"内核 无设备不破坏声明范围");
        suite.expect(kReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                     L"内核 无设备不压制结论");
    }

    // --- Device present but call failed: that is a real gap ---
    {
        SurveyInput survey = makeCleanInput();
        survey.kernelVadState = KernelBackendState::kDriverUnavailable;
        KernelCrossViewInput crossInput;
        crossInput.r3Index = &survey.addressSpace;
        crossInput.vadView.state = KernelBackendState::kDriverUnavailable;
        crossInput.vadView.outcome = accessDeniedOutcome();
        survey.kernelCrossView = evaluateKernelCrossView(crossInput);
        const SurveyReport kReport = runInjectionSurvey(survey);
        suite.expect(kReport.hasGap(kGapKernelBackendUnavailable),
                     L"内核 调用失败记为覆盖缺口");
        suite.expect(!kReport.scopeIntact, L"内核 调用失败破坏声明范围");
        suite.expect(kReport.conclusion == AnalysisConclusion::kIndeterminate,
                     L"内核 调用失败压制结论");
    }

    // --- No fake gaps when driver is missing ---
    {
        const SurveyReport kReport = runInjectionSurvey(makeCleanInput());
        suite.expect(!kReport.hasGap(kGapKernelBackendUnavailable),
                     L"内核 未请求不产生假缺口");
        suite.expect(std::find(kReport.notPerformedCheckKeys.begin(),
                               kReport.notPerformedCheckKeys.end(),
                               std::string(kCheckKernelVadCrossView)) !=
                         kReport.notPerformedCheckKeys.end(),
                     L"内核 未请求登记为未执行");
        suite.expect(kReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                     L"内核 未请求不压制结论");
    }
}

// ---------------------------------------------------------------------------
// Exception (whitelist)
// ---------------------------------------------------------------------------
ExceptionRelation makeException() {
    ExceptionRelation rule;
    rule.ruleId = "vendor.hook.amsi";
    rule.ruleVersion = 3U;
    rule.category = ExceptionCategory::kSecurityInstrumentation;
    rule.targetImageIdentity = "app:target.exe:1.2.3";
    rule.modifiedModuleIdentity = "mod:amsi.dll:10.0.26100";
    rule.modifiedRange = RvaRange{ 0x2000U, 0x10U };
    rule.evidenceText = "vendor advisory 2026-07";
    return rule;
}

void testExceptionRelations(ksword_tests::Suite& suite) {
    const ExceptionRelation kGood = makeException();
    suite.expect(admitExceptionRelation(kGood) == ExceptionAdmission::kAccepted,
                 L"例外 完整规则准入");

    // Module identity key: uses a cross-session master key when a strong identity is available (to distinguish same-name different versions); otherwise degrades to a normalized path.
    DriverInstanceId weakModule = makeModule("C:\\Windows\\System32\\NTDLL.DLL", 0x1000U, 0x2000U);
    suite.expect(moduleIdentityKeyFor(weakModule) == "c:\\windows\\system32\\ntdll.dll",
                 L"例外 弱身份退化为归一化路径");
    DriverInstanceId strongModule = weakModule;
    strongModule.pdbSignature = "RSDS-0011-2233-4455-1";
    const std::string kStrongKey = moduleIdentityKeyFor(strongModule);
    suite.expect(kStrongKey != moduleIdentityKeyFor(weakModule),
                 L"例外 强身份与弱身份不共键");
    suite.expect(kStrongKey.find("RSDS-0011-2233-4455-1") != std::string::npos,
                 L"例外 强身份键含 PDB 签名");

    ExceptionRelation noId = kGood;
    noId.ruleId.clear();
    suite.expect(admitExceptionRelation(noId) == ExceptionAdmission::kMissingRuleId,
                 L"例外 缺 ruleId 被拒");

    ExceptionRelation noCategory = kGood;
    noCategory.category = ExceptionCategory::kUnspecified;
    suite.expect(admitExceptionRelation(noCategory) == ExceptionAdmission::kMissingCategory,
                 L"例外 缺类别被拒");

    ExceptionRelation noTarget = kGood;
    noTarget.targetImageIdentity.clear();
    suite.expect(admitExceptionRelation(noTarget) ==
                     ExceptionAdmission::kMissingTargetImageIdentity,
                 L"例外 缺目标程序身份被拒");

    ExceptionRelation noModule = kGood;
    noModule.modifiedModuleIdentity.clear();
    suite.expect(admitExceptionRelation(noModule) == ExceptionAdmission::kMissingModuleIdentity,
                 L"例外 缺被修改模块身份被拒");

    ExceptionRelation emptyRange = kGood;
    emptyRange.modifiedRange = RvaRange{ 0x2000U, 0U };
    suite.expect(admitExceptionRelation(emptyRange) == ExceptionAdmission::kEmptyRange,
                 L"例外 空范围被拒");

    // A 'waiver' covering the entire module equals permanent allowance — must reject.
    ExceptionRelation wide = kGood;
    wide.modifiedRange = RvaRange{ 0U, 0xFFFFFFFFU };
    suite.expect(admitExceptionRelation(wide) == ExceptionAdmission::kRangeTooWide,
                 L"例外 超宽范围被拒");

    ExceptionRelation atLimit = kGood;
    atLimit.modifiedRange = RvaRange{ 0x2000U, kExplanationRuleMaxSpanBytes };
    suite.expect(admitExceptionRelation(atLimit) == ExceptionAdmission::kAccepted,
                 L"例外 上限内准入");
    ExceptionRelation overLimit = kGood;
    overLimit.modifiedRange = RvaRange{ 0x2000U, kExplanationRuleMaxSpanBytes + 1U };
    suite.expect(admitExceptionRelation(overLimit) == ExceptionAdmission::kRangeTooWide,
                 L"例外 超出上限一字节即拒");

    // Match.
    ExceptionQuery query;
    query.targetImageIdentity = "app:target.exe:1.2.3";
    query.modifiedModuleIdentity = "mod:amsi.dll:10.0.26100";
    query.range = RvaRange{ 0x2004U, 0x8U };
    const ExceptionMatchResult kMatched = matchExceptionRelation({ kGood }, query);
    suite.expect(kMatched.match == ExceptionMatch::kMatched, L"例外 范围被完全包含时命中");
    suite.expect(kMatched.ruleId == "vendor.hook.amsi" && kMatched.ruleVersion == 3U,
                 L"例外 命中记录规则身份");
    suite.expect(kMatched.category == ExceptionCategory::kSecurityInstrumentation,
                 L"例外 命中记录类别");

    suite.expect(matchExceptionRelation({}, query).match == ExceptionMatch::kNoRule,
                 L"例外 无规则");

    ExceptionQuery otherApp = query;
    otherApp.targetImageIdentity = "app:other.exe:1.0";
    suite.expect(matchExceptionRelation({ kGood }, otherApp).match ==
                     ExceptionMatch::kTargetImageMismatch,
                 L"例外 目标程序不同不命中");

    ExceptionQuery otherModule = query;
    otherModule.modifiedModuleIdentity = "mod:ntdll.dll:10.0.26100";
    suite.expect(matchExceptionRelation({ kGood }, otherModule).match ==
                     ExceptionMatch::kModuleMismatch,
                 L"例外 模块不同不命中");

    // Partial coverage does not count as a match.
    ExceptionQuery spill = query;
    spill.range = RvaRange{ 0x200CU, 0x10U };
    suite.expect(matchExceptionRelation({ kGood }, spill).match == ExceptionMatch::kRangeNotCovered,
                 L"例外 部分覆盖不算命中");

    // Jump target requirements.
    ExceptionRelation withBranch = kGood;
    withBranch.allowedBranchTargetModuleIdentity = "mod:vendor.dll:2.1";
    ExceptionQuery wrongBranch = query;
    wrongBranch.actualBranchTargetModuleIdentity = "mod:evil.dll:0.1";
    suite.expect(matchExceptionRelation({ withBranch }, wrongBranch).match ==
                     ExceptionMatch::kBranchTargetMismatch,
                 L"例外 跳转目标不符不命中");
    ExceptionQuery rightBranch = query;
    rightBranch.actualBranchTargetModuleIdentity = "mod:vendor.dll:2.1";
    suite.expect(matchExceptionRelation({ withBranch }, rightBranch).match ==
                     ExceptionMatch::kMatched,
                 L"例外 跳转目标相符命中");
    // Also not allowed when no jump fact exists.
    suite.expect(matchExceptionRelation({ withBranch }, query).match ==
                     ExceptionMatch::kBranchTargetMismatch,
                 L"例外 缺跳转事实不放行");

    // Byte check: failing to read a byte results in a miss (fail-closed).
    ExceptionRelation withBytes = kGood;
    withBytes.expectedBytes = { 0xE9U, 0x00U, 0x00U, 0x00U };
    suite.expect(matchExceptionRelation({ withBytes }, query).match ==
                     ExceptionMatch::kBytesUnavailable,
                 L"例外 要求字节但读不到不命中");

    ExceptionQuery wrongBytes = query;
    wrongBytes.bytesAvailable = true;
    wrongBytes.actualBytes = { 0xCCU, 0x00U, 0x00U, 0x00U };
    suite.expect(matchExceptionRelation({ withBytes }, wrongBytes).match ==
                     ExceptionMatch::kBytesMismatch,
                 L"例外 字节不符不命中");

    ExceptionQuery rightBytes = query;
    rightBytes.bytesAvailable = true;
    rightBytes.actualBytes = { 0xE9U, 0x00U, 0x00U, 0x00U };
    suite.expect(matchExceptionRelation({ withBytes }, rightBytes).match ==
                     ExceptionMatch::kMatched,
                 L"例外 字节相符命中");

    // Rejected rules do not participate in matching, and the discard must be visible.
    const ExceptionMatchResult kRejected = matchExceptionRelation({ wide, noCategory }, query);
    suite.expect(kRejected.match == ExceptionMatch::kAllRulesRejected, L"例外 全被拒");
    suite.expect(kRejected.rejectedRuleCount == 2U, L"例外 被拒条数可见");

    const ExceptionMatchResult kMixed = matchExceptionRelation({ wide, kGood }, query);
    suite.expect(kMixed.match == ExceptionMatch::kMatched, L"例外 合法规则仍生效");
    suite.expect(kMixed.rejectedRuleCount == 1U, L"例外 混合场景记录被拒条数");
}

// ---------------------------------------------------------------------------
// Observation semantics table and identity verification.
// ---------------------------------------------------------------------------
void testSemanticsAndIdentity(ksword_tests::Suite& suite) {
    const ObservationClass kAll[] = {
        ObservationClass::kPrivateOrMappedExecutablePresent,
        ObservationClass::kNormalizedImageDiffers,
        ObservationClass::kPayloadStructureWithReliableFrame,
        ObservationClass::kMappedModuleOutsideBaseline,
        ObservationClass::kScanCompleteNoStrongEvidence,
        ObservationClass::kKeyInputUnavailable,
    };
    for (const ObservationClass kObservation : kAll) {
        const ObservationSemantics kSemantics = semanticsFor(kObservation);
        suite.expect(kSemantics.observation == kObservation, L"语义表 观测回填");
        suite.expect(kSemantics.allowedConclusionKey != nullptr &&
                         kSemantics.allowedConclusionKey[0] != '\0',
                     L"语义表 允许结论键非空");
        suite.expect(kSemantics.forbiddenConclusionKey != nullptr &&
                         kSemantics.forbiddenConclusionKey[0] != '\0',
                     L"语义表 禁止结论键非空");
        suite.expect(std::string(kSemantics.allowedConclusionKey) !=
                         std::string(kSemantics.forbiddenConclusionKey),
                     L"语义表 两个键不同");
    }

    // Private RX only reaches 'Pending Explanation', not 'Injected'.
    suite.expect(semanticsFor(ObservationClass::kPrivateOrMappedExecutablePresent).contribution ==
                     AnalysisConclusion::kIndeterminate,
                 L"语义表 私有可执行只到待解释");
    // Key input unavailability must be reported as 'incomplete conclusion', not 'target clean'.
    suite.expect(semanticsFor(ObservationClass::kKeyInputUnavailable).contribution ==
                     AnalysisConclusion::kIndeterminate,
                 L"语义表 关键输入缺失不得表述为干净");
    suite.expect(semanticsFor(ObservationClass::kNormalizedImageDiffers).contribution ==
                     AnalysisConclusion::kDifferenceObserved,
                 L"语义表 归一化差异是观测到差异");
    suite.expect(semanticsFor(ObservationClass::kScanCompleteNoStrongEvidence).contribution ==
                     AnalysisConclusion::kNoDifferenceObserved,
                 L"语义表 扫完无强证据只是已覆盖范围内未发现");

    // Identity recheck.
    const ProcessInstanceId kBefore = makeProcess(1234U, 0x1D000000000ULL);
    suite.expect(recheckProcessIdentity(kBefore, kBefore) == IdentityRecheckVerdict::kSame,
                 L"身份 同实例");
    const ProcessInstanceId kReused = makeProcess(1234U, 0x1D000000999ULL);
    suite.expect(recheckProcessIdentity(kBefore, kReused) == IdentityRecheckVerdict::kChanged,
                 L"身份 PID 复用判变更");
    const ProcessInstanceId kWeak = makeProcess(1234U, 0U, false);
    suite.expect(recheckProcessIdentity(kWeak, kWeak) == IdentityRecheckVerdict::kUnverifiable,
                 L"身份 只有 PID 不足以确认");
    const ProcessInstanceId kOtherPid = makeProcess(5678U, 0x1D000000000ULL);
    suite.expect(recheckProcessIdentity(kBefore, kOtherPid) == IdentityRecheckVerdict::kChanged,
                 L"身份 PID 不同判变更");

    // WOW64 collector trust level.
    suite.expect(evaluateModuleEnumerationTrust(CollectorArchitecture::kWow64,
                                                ProcessArchitecture::kWow64) ==
                     ModuleEnumerationTrust::kFilterIgnoredUnderWow64,
                 L"身份 WOW64 采集器过滤被忽略");
    suite.expect(evaluateModuleEnumerationTrust(CollectorArchitecture::kNative64,
                                                ProcessArchitecture::kWow64) ==
                     ModuleEnumerationTrust::kTrusted,
                 L"身份 原生 64 位采集器可信");
    suite.expect(evaluateModuleEnumerationTrust(CollectorArchitecture::kUnknown,
                                                ProcessArchitecture::kX64) ==
                     ModuleEnumerationTrust::kUnknown,
                 L"身份 采集器架构未知不假设可信");
    suite.expect(evaluateModuleEnumerationTrust(CollectorArchitecture::kNative64,
                                                ProcessArchitecture::kUnknown) ==
                     ModuleEnumerationTrust::kUnknown,
                 L"身份 目标架构未知不假设可信");
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

// Construct an input where everything succeeds and is clean; each test case modifies one aspect of it.
SurveyInput makeCleanInput() {
    SurveyInput input;
    input.mode = SurveyMode::kFast;
    input.detectorVersion = "j-module/1.0.0";
    input.processBefore = makeProcess(4321U, 0x1D000000000ULL);
    input.processAfter = input.processBefore;
    input.collectedUtc100ns = OptionalU64::of(0x1D100000000ULL);
    input.targetArchitecture = ProcessArchitecture::kX64;
    input.collectorArchitecture = CollectorArchitecture::kNative64;
    input.targetImageIdentity = "app:target.exe:1.2.3";

    std::vector<RegionRecord> records;
    records.push_back(makeRegion(0x140000000ULL, 0x10000U, RegionState::kCommit,
                                 RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                 "C:\\app\\target.exe"));
    records.push_back(makeRegion(0x100000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                                 kWin32PageReadWrite));
    input.addressSpace = buildAddressSpaceIndex(records, CollectionOutcome::success());

    ModuleCrossViewInput crossInput;
    crossInput.loaderOutcome = CollectionOutcome::success();
    crossInput.imageOutcome = CollectionOutcome::success();
    crossInput.payloadOutcome = CollectionOutcome::success();
    crossInput.loaderTrust = ModuleEnumerationTrust::kTrusted;
    crossInput.mainImagePathFromLoader = "C:\\app\\target.exe";
    crossInput.mainImagePathFromKernel = "C:\\app\\target.exe";
    crossInput.mainImagePathFromMapping = "C:\\app\\target.exe";
    crossInput.mainImageBaseFromLoader = OptionalU64::of(0x140000000ULL);
    crossInput.mainImageBaseFromMapping = OptionalU64::of(0x140000000ULL);
    LoaderModuleEntry main;
    main.module = makeModule("C:\\app\\target.exe", 0x140000000ULL, 0x10000U);
    main.listedName = "target.exe";
    main.isMainImage = true;
    crossInput.loaderView = { main };
    ImageMappingEntry mainMap;
    mainMap.allocationBase = OptionalU64::of(0x140000000ULL);
    mainMap.mappedSize = OptionalU64::of(0x10000U);
    mainMap.mappedPath = "C:\\app\\target.exe";
    mainMap.pathOutcome = CollectionOutcome::success();
    crossInput.imageView = { mainMap };
    input.moduleCrossView = evaluateModuleCrossView(crossInput);

    input.workingSetQueried = true;
    input.workingSetOutcome = CollectionOutcome::success();
    input.workingSetPagesScreened = 16U;

    input.threadEnumerationOutcome = CollectionOutcome::success();
    ThreadStartInput mainThread;
    mainThread.thread = makeThread(input.processBefore, 1001U);
    mainThread.startAddress = OptionalU64::of(0x140002000ULL);
    mainThread.startAddressOutcome = CollectionOutcome::success();
    const std::vector<ImageCodeExtent> kImages = {
        makeImage("C:\\app\\target.exe", 0x140000000ULL, 0x10000U, 0x1000U, 0x5000U),
    };
    input.threadStarts = evaluateThreadStarts({ mainThread }, input.addressSpace, kImages);

    ImageComparisonOutcome comparison;
    comparison.module = makeModule("C:\\app\\target.exe", 0x140000000ULL, 0x10000U);
    comparison.referenceConfidence = ReferenceConfidence::kReferenceVerified;
    comparison.report.outcome = CollectionOutcome::success();
    comparison.report.conclusion = AnalysisConclusion::kNoDifferenceObserved;
    input.imageComparisons = { comparison };

    return input;
}

ImageDiffEntry makeDiffEntry(const std::uint32_t rva,
                             const std::uint32_t length,
                             const DiffExplanation explanation = DiffExplanation::kUnexplained) {
    ImageDiffEntry entry;
    entry.kind = DiffKind::kByteDifference;
    entry.rva = rva;
    entry.va = 0x140000000ULL + rva;
    entry.length = length;
    entry.sectionName = ".text";
    entry.explanation = explanation;
    entry.readStatus = ByteReadStatus::kRead;
    entry.referenceBytes.assign(length, 0x90U);
    entry.liveBytes.assign(length, 0xE9U);
    return entry;
}

void testSurveyPipeline(ksword_tests::Suite& suite) {
    // --- Clean path ---
    const SurveyReport kClean = runInjectionSurvey(makeCleanInput());
    suite.expect(kClean.identity == IdentityRecheckVerdict::kSame, L"总入口 身份一致");
    suite.expect(kClean.findings.empty(), L"总入口 干净路径无结果");
    suite.expect(kClean.scopeIntact, L"总入口 干净路径声明范围完好");
    // Fast mode always carries two capability limitations: 'non-executable memory not scanned' and 'no reliable stack
    // backtrace'. Therefore, coverageComplete being false is **correct**; it should simply not suppress the conclusion.
    suite.expect(!kClean.coverageComplete, L"总入口 快扫覆盖不完整（能力限制）");
    suite.expect(kClean.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 干净路径结论");
    suite.expect(kClean.hasObservation(ObservationClass::kScanCompleteNoStrongEvidence),
                 L"总入口 干净路径记录观测类别");
    suite.expect(kClean.firstObservedUtc100ns.present &&
                     kClean.firstObservedUtc100ns.value == 0x1D100000000ULL,
                 L"总入口 首次观测时间");
    suite.expect(kClean.detectorVersion == "j-module/1.0.0", L"总入口 检测器版本");
    suite.expect(kClean.ruleSetVersion == kInjectionSurveyRuleSetVersion, L"总入口 规则集版本");
    // The termination condition for fast mode is 'which checks were completed', not a choice between Injected or Clean.
    suite.expect(!kClean.completedCheckKeys.empty(), L"总入口 列出已完成检查");
    suite.expect(!kClean.notPerformedCheckKeys.empty(), L"总入口 列出未执行检查");
    suite.expect(std::find(kClean.completedCheckKeys.begin(), kClean.completedCheckKeys.end(),
                           std::string(kCheckAddressSpaceIndex)) != kClean.completedCheckKeys.end(),
                 L"总入口 地址空间索引已完成");
    suite.expect(std::find(kClean.notPerformedCheckKeys.begin(),
                           kClean.notPerformedCheckKeys.end(),
                           std::string(kCheckNonExecutableScan)) !=
                     kClean.notPerformedCheckKeys.end(),
                 L"总入口 快扫不声称扫了非可执行内存");

    // --- Private RX is merely 'pending interpretation', not 'already injected' ---
    SurveyInput dynamicCode = makeCleanInput();
    std::vector<RegionRecord> withRx;
    withRx.push_back(makeRegion(0x140000000ULL, 0x10000U, RegionState::kCommit,
                                RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                "C:\\app\\target.exe"));
    withRx.push_back(makeRegion(0x200000U, 0x1000U, RegionState::kCommit, RegionType::kPrivate,
                                kWin32PageExecuteReadWrite));
    dynamicCode.addressSpace = buildAddressSpaceIndex(withRx, CollectionOutcome::success());
    const SurveyReport kDynamicReport = runInjectionSurvey(dynamicCode);
    suite.expect(kDynamicReport.dynamicCodeRegionCount == 1U, L"总入口 动态代码区域计数");
    suite.expect(hasRule(kDynamicReport.findings, kRuleIdDynamicCodeRegion),
                 L"总入口 动态代码产出结果");
    suite.expect(kDynamicReport.conclusion == AnalysisConclusion::kIndeterminate,
                 L"总入口 私有 RX 只到待解释");
    suite.expect(kDynamicReport.conclusion != AnalysisConclusion::kDifferenceObserved,
                 L"总入口 私有 RX 不等于观测到差异");
    suite.expect(kDynamicReport.hasObservation(
                     ObservationClass::kPrivateOrMappedExecutablePresent),
                 L"总入口 动态代码观测类别");
    // If there is no evidence for the injecting process, the source is unknown, and no elevation entry is provided.
    suite.expect(!kDynamicReport.findings.empty() &&
                     kDynamicReport.findings[0].injectorAttribution == OwnerAttribution::kUnknown,
                 L"总入口 注入源默认未知");
    suite.expect(!kDynamicReport.findings.empty() &&
                     kDynamicReport.findings[0].injectorCandidates.empty(),
                 L"总入口 无证据不列注入源候选");
    suite.expect(!kDynamicReport.findings.empty() &&
                     kDynamicReport.findings[0].firstObservedUtc100ns.present,
                 L"总入口 结果带首次观测时间");

    // Mapped executable memory is also a candidate (do not scan only private memory).
    SurveyInput mappedCode = makeCleanInput();
    std::vector<RegionRecord> withMapped;
    withMapped.push_back(makeRegion(0x140000000ULL, 0x10000U, RegionState::kCommit,
                                    RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                    "C:\\app\\target.exe"));
    withMapped.push_back(makeRegion(0x400000U, 0x2000U, RegionState::kCommit, RegionType::kMapped,
                                    kWin32PageExecuteRead));
    mappedCode.addressSpace = buildAddressSpaceIndex(withMapped, CollectionOutcome::success());
    const SurveyReport kMappedReport = runInjectionSurvey(mappedCode);
    suite.expect(kMappedReport.dynamicCodeRegionCount == 1U, L"总入口 映射可执行计入候选");
    suite.expect(!kMappedReport.findings.empty() &&
                     kMappedReport.findings[0].regionType == RegionType::kMapped,
                 L"总入口 映射候选保留类型");

    // --- Normalized difference (reference verified) ---
    SurveyInput diffInput = makeCleanInput();
    diffInput.imageComparisons[0].report.entries.push_back(makeDiffEntry(0x1200U, 5U));
    const SurveyReport kDiffReport = runInjectionSurvey(diffInput);
    suite.expect(kDiffReport.unexplainedImageDiffCount == 1U, L"总入口 未解释差异计数");
    suite.expect(hasRule(kDiffReport.findings, kRuleIdImageBytesUnexplained),
                 L"总入口 未解释差异产出结果");
    suite.expect(kDiffReport.conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"总入口 归一化差异升到观测到差异");
    suite.expect(kDiffReport.hasObservation(ObservationClass::kNormalizedImageDiffers),
                 L"总入口 归一化差异观测类别");
    suite.expect(!kDiffReport.findings.empty() &&
                     kDiffReport.findings[0].rva.present &&
                     kDiffReport.findings[0].rva.value == 0x1200U,
                 L"总入口 差异带 RVA");
    suite.expect(!kDiffReport.findings.empty() &&
                     kDiffReport.findings[0].sectionName == ".text",
                 L"总入口 差异带节名");

    // ImageDiff self-explained differences are no longer counted as unexplained.
    SurveyInput explained = makeCleanInput();
    explained.imageComparisons[0].report.entries.push_back(
        makeDiffEntry(0x1200U, 5U, DiffExplanation::kExplained));
    const SurveyReport kExplainedReport = runInjectionSurvey(explained);
    suite.expect(kExplainedReport.unexplainedImageDiffCount == 0U,
                 L"总入口 已解释差异不计入未解释");
    suite.expect(kExplainedReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 已解释差异不改变结论");

    // Reference uncertain: must not be promoted to 'modified verified'.
    SurveyInput uncertain = makeCleanInput();
    uncertain.imageComparisons[0].referenceConfidence = ReferenceConfidence::kReferenceUncertain;
    uncertain.imageComparisons[0].report.entries.push_back(makeDiffEntry(0x1200U, 5U));
    const SurveyReport kUncertainReport = runInjectionSurvey(uncertain);
    suite.expect(kUncertainReport.unexplainedImageDiffCount == 0U,
                 L"总入口 参考不确定不计入已证实差异");
    suite.expect(hasRule(kUncertainReport.findings, kRuleIdImageReferenceUncertain),
                 L"总入口 参考不确定单独成规则");
    suite.expect(kUncertainReport.hasGap(kGapReferenceUncertain), L"总入口 参考不确定留缺口");
    suite.expect(kUncertainReport.conclusion == AnalysisConclusion::kIndeterminate,
                 L"总入口 参考不确定不得断言差异");

    // Bytes that cannot be read on-site are holes, not "identical" nor "different".
    SurveyInput missingBytes = makeCleanInput();
    ImageDiffEntry hole = makeDiffEntry(0x1300U, 8U);
    hole.kind = DiffKind::kMissingLiveBytes;
    hole.readStatus = ByteReadStatus::kUnreadable;
    hole.liveBytes.clear();
    missingBytes.imageComparisons[0].report.entries.push_back(hole);
    const SurveyReport kMissingReport = runInjectionSurvey(missingBytes);
    suite.expect(kMissingReport.unexplainedImageDiffCount == 0U, L"总入口 缺字节不算差异");
    suite.expect(kMissingReport.hasGap(kGapAddressSpaceIncomplete), L"总入口 缺字节留缺口");
    suite.expect(kMissingReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 缺字节不得表述为未发现差异");

    // Exception-hit: retain results but exclude from unexplained counts and do not elevate the conclusion.
    SurveyInput whitelisted = makeCleanInput();
    whitelisted.imageComparisons[0].report.entries.push_back(makeDiffEntry(0x2004U, 4U));
    ExceptionRelation rule = makeException();
    // Rule identity must be generated using the same function: matching is a strict equality comparison; a manually written path
    // with different casing will never match. This assertion also fixes in the test how the rule writer obtains the identity string.
    rule.modifiedModuleIdentity =
        moduleIdentityKeyFor(makeModule("C:\\app\\target.exe", 0x140000000ULL, 0x10000U));
    suite.expect(rule.modifiedModuleIdentity == "c:\\app\\target.exe",
                 L"总入口 身份不足时模块键退化为归一化路径");
    whitelisted.exceptions = { rule };
    const SurveyReport kWhitelistedReport = runInjectionSurvey(whitelisted);
    suite.expect(kWhitelistedReport.exceptionExplainedCount == 1U, L"总入口 例外命中计数");
    suite.expect(kWhitelistedReport.unexplainedImageDiffCount == 0U,
                 L"总入口 例外命中不计入未解释");
    suite.expect(!kWhitelistedReport.findings.empty() &&
                     kWhitelistedReport.findings[0].explainedByException(),
                 L"总入口 例外命中仍保留结果");
    suite.expect(kWhitelistedReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 例外命中不抬结论");

    // --- Suppress all coverage gaps to force 'No Difference Found' ---
    SurveyInput noWorkingSet = makeCleanInput();
    noWorkingSet.workingSetQueried = false;
    noWorkingSet.workingSetOutcome = accessDeniedOutcome();
    const SurveyReport kNoWorkingSetReport = runInjectionSurvey(noWorkingSet);
    suite.expect(kNoWorkingSetReport.hasGap(kGapWorkingSetUnavailable), L"总入口 工作集缺口");
    suite.expect(!kNoWorkingSetReport.coverageComplete, L"总入口 有缺口即覆盖不完整");
    suite.expect(kNoWorkingSetReport.conclusion == AnalysisConclusion::kIndeterminate,
                 L"总入口 有缺口不得表述为未发现差异");
    suite.expect(kNoWorkingSetReport.hasObservation(ObservationClass::kKeyInputUnavailable),
                 L"总入口 缺口记录为关键输入不可获得");

    SurveyInput noThreads = makeCleanInput();
    noThreads.threadStarts.clear();
    noThreads.threadEnumerationOutcome = accessDeniedOutcome();
    const SurveyReport kNoThreadsReport = runInjectionSurvey(noThreads);
    suite.expect(kNoThreadsReport.hasGap(kGapThreadStartUnavailable), L"总入口 线程缺口");
    suite.expect(kNoThreadsReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 线程缺口压制干净结论");

    SurveyInput denied = makeCleanInput();
    denied.addressSpace.outcome = accessDeniedOutcome();
    const SurveyReport kDeniedReport = runInjectionSurvey(denied);
    suite.expect(kDeniedReport.hasGap(kGapAddressSpaceIncomplete), L"总入口 地址空间缺口");
    suite.expect(kDeniedReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 拒绝访问不得输出未发现注入");

    // Budget truncation: must be displayed; never return "clean".
    SurveyInput truncated = makeCleanInput();
    truncated.budgetStop = BudgetStop::kTimeExhausted;
    const SurveyReport kTruncatedReport = runInjectionSurvey(truncated);
    suite.expect(kTruncatedReport.hasGap(kGapBudgetTruncated), L"总入口 截断留缺口");
    suite.expect(kTruncatedReport.coverage.limitHit, L"总入口 截断记入账目");
    suite.expect(!kTruncatedReport.coverage.cancelled, L"总入口 命中上限不是取消");
    suite.expect(kTruncatedReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 截断不得表述为干净");

    SurveyInput cancelled = makeCleanInput();
    cancelled.budgetStop = BudgetStop::kCancelled;
    const SurveyReport kCancelledReport = runInjectionSurvey(cancelled);
    suite.expect(kCancelledReport.coverage.cancelled, L"总入口 取消与命中上限分开记录");
    suite.expect(!kCancelledReport.coverage.limitHit, L"总入口 取消不伪装成命中上限");

    SurveyInput notRun = makeCleanInput();
    notRun.plannedComparisonsNotRun = 3U;
    const SurveyReport kNotRunReport = runInjectionSurvey(notRun);
    suite.expect(kNotRunReport.hasGap(kGapBudgetTruncated), L"总入口 计划未跑完留缺口");

    // The collector's self-reported coverage gaps also suppress 'no differences found'.
    SurveyInput collectorGap = makeCleanInput();
    collectorGap.extraCoverageGapKeys.push_back(kGapMappedPathUnavailable);
    const SurveyReport kCollectorGapReport = runInjectionSurvey(collectorGap);
    suite.expect(kCollectorGapReport.hasGap(kGapMappedPathUnavailable),
                 L"总入口 采集器缺口透传");
    suite.expect(kCollectorGapReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 采集器缺口压制干净结论");
    suite.expect(!kCollectorGapReport.coverageComplete, L"总入口 采集器缺口即覆盖不完整");

    // Collector-reported capability limits are listed but do not suppress conclusions.
    SurveyInput collectorLimit = makeCleanInput();
    collectorLimit.extraCapabilityLimitKeys.push_back(kLimitPayloadHeaderErased);
    collectorLimit.extraCapabilityLimitKeys.push_back(kLimitRuntimeAttribution);
    const SurveyReport kCollectorLimitReport = runInjectionSurvey(collectorLimit);
    suite.expect(kCollectorLimitReport.hasLimit(kLimitPayloadHeaderErased),
                 L"总入口 采集器能力限制透传");
    suite.expect(kCollectorLimitReport.hasLimit(kLimitRuntimeAttribution),
                 L"总入口 运行时归因限制透传");
    suite.expect(!kCollectorLimitReport.hasGap(kLimitPayloadHeaderErased),
                 L"总入口 能力限制不混进缺口");
    suite.expect(kCollectorLimitReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 能力限制不压制结论");

    // --- Identity change: Entire evidence invalidated ---
    SurveyInput reused = makeCleanInput();
    reused.processAfter = makeProcess(4321U, 0x1D000000999ULL);
    const SurveyReport kReusedReport = runInjectionSurvey(reused);
    suite.expect(kReusedReport.identity == IdentityRecheckVerdict::kChanged, L"总入口 身份变更");
    suite.expect(kReusedReport.findings.empty(), L"总入口 身份变更丢弃全部结果");
    suite.expect(kReusedReport.conclusion == AnalysisConclusion::kNoEvidence,
                 L"总入口 身份变更即无证据");
    suite.expect(kReusedReport.hasGap(kGapIdentityChanged), L"总入口 身份变更留缺口");
    suite.expect(!kReusedReport.coverageComplete, L"总入口 身份变更覆盖不完整");

    SurveyInput weakIdentity = makeCleanInput();
    weakIdentity.processBefore = makeProcess(4321U, 0U, false);
    weakIdentity.processAfter = weakIdentity.processBefore;
    const SurveyReport kWeakReport = runInjectionSurvey(weakIdentity);
    suite.expect(kWeakReport.identity == IdentityRecheckVerdict::kUnverifiable,
                 L"总入口 弱身份无法确认");
    suite.expect(kWeakReport.hasGap(kGapIdentityUnverifiable), L"总入口 弱身份留缺口");
    suite.expect(kWeakReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 弱身份压制干净结论");

    // --- Thread start exception ---
    SurveyInput badThread = makeCleanInput();
    std::vector<RegionRecord> withPrivate;
    withPrivate.push_back(makeRegion(0x140000000ULL, 0x10000U, RegionState::kCommit,
                                     RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                     "C:\\app\\target.exe"));
    withPrivate.push_back(makeRegion(0x500000U, 0x1000U, RegionState::kCommit,
                                     RegionType::kPrivate, kWin32PageExecuteReadWrite));
    badThread.addressSpace = buildAddressSpaceIndex(withPrivate, CollectionOutcome::success());
    ThreadStartInput strayThread;
    strayThread.thread = makeThread(badThread.processBefore, 2002U);
    strayThread.startAddress = OptionalU64::of(0x500100U);
    strayThread.startAddressOutcome = CollectionOutcome::success();
    badThread.threadStarts = evaluateThreadStarts(
        { strayThread }, badThread.addressSpace,
        { makeImage("C:\\app\\target.exe", 0x140000000ULL, 0x10000U, 0x1000U, 0x5000U) });
    const SurveyReport kBadThreadReport = runInjectionSurvey(badThread);
    suite.expect(kBadThreadReport.threadStartAnomalyCount == 1U, L"总入口 线程起点异常计数");
    suite.expect(hasRule(kBadThreadReport.findings, kRuleIdThreadStartOutsideImage),
                 L"总入口 线程起点异常产出结果");
    suite.expect(!kBadThreadReport.findings.empty() &&
                     !kBadThreadReport.findings.back().relatedThreads.empty(),
                 L"总入口 线程结果关联线程身份");
    suite.expect(kBadThreadReport.conclusion == AnalysisConclusion::kIndeterminate,
                 L"总入口 线程起点异常只到待解释");

    // Start point not captured: Use a different ruleId and do not increment the 'exception' count.
    SurveyInput unknownThread = makeCleanInput();
    ThreadStartInput missingStart;
    missingStart.thread = makeThread(unknownThread.processBefore, 2003U);
    missingStart.startAddressOutcome = accessDeniedOutcome();
    unknownThread.threadStarts = evaluateThreadStarts(
        { missingStart }, unknownThread.addressSpace,
        { makeImage("C:\\app\\target.exe", 0x140000000ULL, 0x10000U, 0x1000U, 0x5000U) });
    const SurveyReport kUnknownThreadReport = runInjectionSurvey(unknownThread);
    suite.expect(kUnknownThreadReport.threadStartAnomalyCount == 0U,
                 L"总入口 起点未采集不计入异常");
    suite.expect(hasRule(kUnknownThreadReport.findings, kRuleIdThreadStartUnknown),
                 L"总入口 起点未采集单独规则");
    suite.expect(!hasRule(kUnknownThreadReport.findings, kRuleIdThreadStartOutsideImage),
                 L"总入口 起点未采集不混用归属不一致规则");
    suite.expect(kUnknownThreadReport.hasGap(kGapThreadStartUnavailable),
                 L"总入口 起点未采集留缺口");

    // --- Module cross contradiction ---
    SurveyInput crossIssue = makeCleanInput();
    ModuleCrossFinding ghost;
    ghost.issue = ModuleCrossIssue::kImageMappingWithoutLoaderEntry;
    ghost.base = OptionalU64::of(0x7FF900000000ULL);
    ghost.mappedPath = "C:\\temp\\payload.dll";
    ghost.mappedSize = OptionalU64::of(0x8000U);
    ghost.inputOutcome = CollectionOutcome::success();
    crossIssue.moduleCrossView.findings.push_back(ghost);
    crossIssue.moduleCrossView.conclusion = AnalysisConclusion::kDifferenceObserved;
    const SurveyReport kCrossReport = runInjectionSurvey(crossIssue);
    suite.expect(kCrossReport.moduleCrossIssueCount == 1U, L"总入口 交叉视图问题计数");
    suite.expect(hasRule(kCrossReport.findings, kRuleIdImageWithoutLoaderEntry),
                 L"总入口 交叉视图问题产出结果");
    // "Image present, loader absent" has many valid causes (resource mapping, metadata image, .NET). In practice,
    // explorer.exe consistently shows over a dozen such cases, so this is only marked as 'to be explained'.
    suite.expect(kCrossReport.moduleCrossConflictCount == 0U,
                 L"总入口 缺项不是矛盾");
    suite.expect(kCrossReport.conclusion == AnalysisConclusion::kIndeterminate,
                 L"总入口 缺项只到待解释");
    suite.expect(!kCrossReport.findings.empty() &&
                     kCrossReport.findings[0].moduleName == "payload.dll",
                 L"总入口 交叉视图问题带模块名");

    // Only true conflicts (contradictory views of the same object) are escalated to observed discrepancies.
    SurveyInput crossConflict = makeCleanInput();
    ModuleCrossFinding renamed;
    renamed.issue = ModuleCrossIssue::kLoaderPathMismatch;
    renamed.base = OptionalU64::of(0x7FF800000000ULL);
    renamed.loaderPath = "C:\\Windows\\System32\\ntdll.dll";
    renamed.mappedPath = "C:\\temp\\evil.dll";
    renamed.inputOutcome = CollectionOutcome::success();
    crossConflict.moduleCrossView.findings.push_back(renamed);
    crossConflict.moduleCrossView.conclusion = AnalysisConclusion::kDifferenceObserved;
    const SurveyReport kCrossConflictReport = runInjectionSurvey(crossConflict);
    suite.expect(kCrossConflictReport.moduleCrossConflictCount == 1U, L"总入口 路径冲突是矛盾");
    suite.expect(kCrossConflictReport.conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"总入口 矛盾升到观测到差异");

    SurveyInput mainConflict = makeCleanInput();
    ModuleCrossFinding mainMismatch;
    mainMismatch.issue = ModuleCrossIssue::kMainImageIdentityConflict;
    mainMismatch.inputOutcome = CollectionOutcome::success();
    mainConflict.moduleCrossView.findings.push_back(mainMismatch);
    mainConflict.moduleCrossView.conclusion = AnalysisConclusion::kDifferenceObserved;
    const SurveyReport kMainConflictReport = runInjectionSurvey(mainConflict);
    suite.expect(kMainConflictReport.moduleCrossConflictCount == 1U, L"总入口 主映像矛盾计入");
    suite.expect(kMainConflictReport.conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"总入口 主映像矛盾升到观测到差异");

    // The binning function itself.
    suite.expect(moduleCrossIssueIsContradiction(ModuleCrossIssue::kLoaderPathMismatch),
                 L"分档 路径不一致是矛盾");
    suite.expect(moduleCrossIssueIsContradiction(ModuleCrossIssue::kLoaderSizeMismatch),
                 L"分档 大小不一致是矛盾");
    suite.expect(moduleCrossIssueIsContradiction(ModuleCrossIssue::kMainImageIdentityConflict),
                 L"分档 主映像自相矛盾是矛盾");
    suite.expect(!moduleCrossIssueIsContradiction(
                     ModuleCrossIssue::kImageMappingWithoutLoaderEntry),
                 L"分档 映像无加载器项不是矛盾");
    suite.expect(!moduleCrossIssueIsContradiction(
                     ModuleCrossIssue::kLoaderEntryWithoutImageMapping),
                 L"分档 加载器项无映射不是矛盾");
    suite.expect(!moduleCrossIssueIsContradiction(ModuleCrossIssue::kMappedPathUnavailable),
                 L"分档 路径查不到不是矛盾");

    // If the path cannot be retrieved, do not generate a finding; only record the gap.
    SurveyInput pathGap = makeCleanInput();
    ModuleCrossFinding noPath;
    noPath.issue = ModuleCrossIssue::kMappedPathUnavailable;
    noPath.base = OptionalU64::of(0x7FF900000000ULL);
    noPath.inputOutcome = accessDeniedOutcome();
    pathGap.moduleCrossView.findings.push_back(noPath);
    pathGap.moduleCrossView.coverageGapKeys.push_back(kGapMappedPathUnavailable);
    const SurveyReport kPathGapReport = runInjectionSurvey(pathGap);
    suite.expect(kPathGapReport.moduleCrossIssueCount == 0U, L"总入口 路径缺失不计入矛盾");
    suite.expect(kPathGapReport.hasGap(kGapMappedPathUnavailable), L"总入口 路径缺失留缺口");

    // --- Capability limitations and coverage gaps are two distinct categories ---
    SurveyInput deep = makeCleanInput();
    deep.mode = SurveyMode::kDeep;
    const SurveyReport kDeepReport = runInjectionSurvey(deep);
    suite.expect(kDeepReport.hasLimit(kLimitStackUnwindUnavailable),
                 L"能力 无可靠栈回溯记为能力限制");
    suite.expect(kDeepReport.hasLimit(kLimitNonExecutableNotScanned),
                 L"能力 未扫非可执行内存记为能力限制");
    suite.expect(!kDeepReport.hasGap(kLimitStackUnwindUnavailable),
                 L"能力 限制不混进覆盖缺口");
    // Critical boundary: Capability restrictions must not suppress conclusions (otherwise the four states would always degrade to three), but coverage completeness is false.
    suite.expect(kDeepReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"能力 限制不压制已覆盖范围内的结论");
    suite.expect(kDeepReport.scopeIntact, L"能力 限制不破坏声明范围");
    suite.expect(!kDeepReport.coverageComplete, L"能力 有限制即覆盖不完整");

    SurveyInput deepFull = makeCleanInput();
    deepFull.mode = SurveyMode::kDeep;
    deepFull.threadStacks = { makeTrustedStack(100U, { 0x7FF800001000ULL }) };
    deepFull.nonExecutableMemoryScanned = true;
    const SurveyReport kDeepFullReport = runInjectionSurvey(deepFull);
    suite.expect(!kDeepFullReport.hasLimit(kLimitStackUnwindUnavailable),
                 L"能力 栈回溯可用即无限制");
    suite.expect(!kDeepFullReport.hasLimit(kLimitNonExecutableNotScanned),
                 L"能力 已扫非可执行内存即无限制");
    suite.expect(kDeepFullReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"能力 全覆盖结论");
    suite.expect(kDeepFullReport.coverageComplete, L"能力 全覆盖标记");
    suite.expect(kDeepFullReport.scopeIntact, L"能力 全覆盖范围完整");

    // Fast mode includes these two capability limits by default, but does not suppress the conclusion.
    const SurveyReport kFastLimits = runInjectionSurvey(makeCleanInput());
    suite.expect(kFastLimits.hasLimit(kLimitNonExecutableNotScanned),
                 L"能力 快扫记录非可执行内存限制");
    suite.expect(kFastLimits.hasLimit(kLimitStackUnwindUnavailable),
                 L"能力 快扫记录栈回溯限制");
    suite.expect(kFastLimits.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"能力 快扫限制不压制结论");

    // Conversely, real coverage gaps must be suppressed.
    SurveyInput scopeBroken = makeCleanInput();
    scopeBroken.extraCoverageGapKeys.push_back(kGapWorkingSetUnavailable);
    const SurveyReport kScopeBrokenReport = runInjectionSurvey(scopeBroken);
    suite.expect(!kScopeBrokenReport.scopeIntact, L"能力 覆盖缺口破坏声明范围");
    suite.expect(kScopeBrokenReport.conclusion == AnalysisConclusion::kIndeterminate,
                 L"能力 覆盖缺口压制结论");

    // ImageDiff's limitationKeys must also be routed according to this line.
    // "No disk reference comparable" (DVRT/zero-padding/relocation normalization impossible) defines the scope; do not suppress conclusions.
    SurveyInput noReferenceBytes = makeCleanInput();
    noReferenceBytes.imageComparisons[0].report.limitationKeys = {
        "integrity.limitation.excludedNotComparable",
        "integrity.limitation.relocationDirectoryMissing",
    };
    const SurveyReport kNoReferenceReport = runInjectionSurvey(noReferenceBytes);
    suite.expect(kNoReferenceReport.hasLimit("integrity.limitation.excludedNotComparable"),
                 L"能力 不可比范围记为能力限制");
    suite.expect(kNoReferenceReport.hasLimit("integrity.limitation.relocationDirectoryMissing"),
                 L"能力 重定位无法归一化记为能力限制");
    suite.expect(kNoReferenceReport.scopeIntact, L"能力 不可比范围不破坏声明范围");
    suite.expect(kNoReferenceReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"能力 不可比范围不压制结论");

    // 'Intended to compare but failed' (unreadable / hit limit / module expired) must be suppressed.
    SurveyInput readFailed = makeCleanInput();
    readFailed.imageComparisons[0].report.limitationKeys = {
        "integrity.limitation.unreadableBytes",
    };
    const SurveyReport kReadFailedReport = runInjectionSurvey(readFailed);
    suite.expect(kReadFailedReport.hasGap("integrity.limitation.unreadableBytes"),
                 L"能力 读不到字节记为覆盖缺口");
    suite.expect(!kReadFailedReport.scopeIntact, L"能力 读不到字节破坏声明范围");
    suite.expect(kReadFailedReport.conclusion == AnalysisConclusion::kIndeterminate,
                 L"能力 读不到字节压制结论");

    SurveyInput staleModule = makeCleanInput();
    staleModule.imageComparisons[0].report.limitationKeys = {
        "integrity.limitation.moduleStale",
    };
    const SurveyReport kStaleModuleReport = runInjectionSurvey(staleModule);
    suite.expect(kStaleModuleReport.hasGap("integrity.limitation.moduleStale"),
                 L"能力 模块过期记为覆盖缺口");
    suite.expect(!kStaleModuleReport.scopeIntact, L"能力 模块过期破坏声明范围");

    // --- Non-Image Payload Structure ---
    SurveyInput payload = makeCleanInput();
    PayloadCandidateEntry erased;
    erased.base = OptionalU64::of(0x600000U);
    erased.size = OptionalU64::of(0x3000U);
    erased.type = RegionType::kPrivate;
    erased.structure = PayloadStructure::kHeaderErasedPe;
    erased.outcome = CollectionOutcome::success();
    erased.structureFacts.push_back("payload.unwind=present");
    payload.payloadCandidates = { erased };
    const SurveyReport kPayloadReport = runInjectionSurvey(payload);
    suite.expect(hasRule(kPayloadReport.findings, kRuleIdPayloadStructure),
                 L"总入口 载荷结构产出结果");
    suite.expect(!kPayloadReport.hasObservation(
                     ObservationClass::kPayloadStructureWithReliableFrame),
                 L"总入口 无可靠栈帧时载荷结构不升格");

    // Same memory region cannot appear in two places: evidence of the payload structure must be in the dynamic code region.
    SurveyInput sameRegion = makeCleanInput();
    std::vector<RegionRecord> rxRegion;
    rxRegion.push_back(makeRegion(0x140000000ULL, 0x10000U, RegionState::kCommit,
                                  RegionType::kImage, kWin32PageExecuteRead, 0x140000000ULL,
                                  "C:\\app\\target.exe"));
    rxRegion.push_back(makeRegion(0x600000U, 0x3000U, RegionState::kCommit, RegionType::kPrivate,
                                  kWin32PageExecuteReadWrite));
    sameRegion.addressSpace = buildAddressSpaceIndex(rxRegion, CollectionOutcome::success());
    sameRegion.payloadCandidates = { erased };  // erased.base is exactly 0x600000
    const SurveyReport kSameRegionReport = runInjectionSurvey(sameRegion);
    suite.expect(kSameRegionReport.dynamicCodeRegionCount == 1U, L"总入口 同一区域只计一次");
    suite.expect(!hasRule(kSameRegionReport.findings, kRuleIdPayloadStructure),
                 L"总入口 同一区域不再单独出载荷结构行");
    suite.expect(kSameRegionReport.findings.size() == 1U, L"总入口 同一块内存只出一行");
    suite.expect(!kSameRegionReport.findings.empty() &&
                     std::any_of(kSameRegionReport.findings[0].facts.begin(),
                                 kSameRegionReport.findings[0].facts.end(),
                                 [](const std::string& fact) {
                                     return fact == "payload.structure=HeaderErasedPe";
                                 }),
                 L"总入口 载荷结构并进区域证据");

    // Having "stack backtrace capability available" is not enough: the memory must **actually be reliably entered via frames**.
    // This stack is trusted and frames are reliable, but all landing points lie outside the 0x600000 region.
    SurveyInput payloadWalkOnly = payload;
    payloadWalkOnly.threadStacks = {
        makeTrustedStack(201U, { 0x7FF800001000ULL, 0x7FF800002000ULL })
    };
    const SurveyReport kPayloadWalkOnlyReport = runInjectionSurvey(payloadWalkOnly);
    suite.expect(!kPayloadWalkOnlyReport.hasObservation(
                     ObservationClass::kPayloadStructureWithReliableFrame),
                 L"总入口 栈回溯可用本身不构成执行关联");
    suite.expect(kPayloadWalkOnlyReport.payloadWithExecutionCount == 0U,
                 L"总入口 无帧进入不计执行关联");
    suite.expect(kPayloadWalkOnlyReport.conclusion != AnalysisConclusion::kDifferenceObserved,
                 L"总入口 无帧进入不升到观测到差异");

    // A sleeping beacon has this shape: the top two stack frames are in ntdll/kernelbase, and the third frame falls into the non-image
    // memory region at 0x600000. The third frame is **calculated from the caller with unwind data**, so it enters the reliable prefix.
    SurveyInput payloadWithFrame = payload;
    payloadWithFrame.threadStacks = {
        makeTrustedStack(202U,
                         { 0x7FF800001000ULL, 0x7FF800002000ULL, 0x600100ULL },
                         /*lastFrameHasUnwindData=*/false)
    };
    const SurveyReport kPayloadFrameReport = runInjectionSurvey(payloadWithFrame);
    suite.expect(kPayloadFrameReport.hasObservation(
                     ObservationClass::kPayloadStructureWithReliableFrame),
                 L"总入口 结构 + 可靠栈帧才升格");
    suite.expect(kPayloadFrameReport.payloadWithExecutionCount == 1U,
                 L"总入口 执行关联计数");
    suite.expect(kPayloadFrameReport.conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"总入口 载荷与执行关联升到观测到差异");

    // Frame entered, but structure is only "PE file in data" — still not upgraded.
    SurveyInput dataPeWithFrame = makeCleanInput();
    PayloadCandidateEntry dataOnlyFramed = erased;
    dataOnlyFramed.structure = PayloadStructure::kDataOnlyPeFile;
    dataPeWithFrame.payloadCandidates = { dataOnlyFramed };
    dataPeWithFrame.threadStacks = {
        makeTrustedStack(203U, { 0x7FF800001000ULL, 0x600100ULL },
                         /*lastFrameHasUnwindData=*/false)
    };
    const SurveyReport kDataPeFramedReport = runInjectionSurvey(dataPeWithFrame);
    suite.expect(kDataPeFramedReport.payloadWithExecutionCount == 0U,
                 L"总入口 数据中的 PE 即使有帧也不升格");

    // A PE in the data does not equal a loaded and executed PE.
    SurveyInput dataPe = makeCleanInput();
    PayloadCandidateEntry dataOnly = erased;
    dataOnly.structure = PayloadStructure::kDataOnlyPeFile;
    dataPe.payloadCandidates = { dataOnly };
    dataPe.threadStacks = { makeTrustedStack(204U, { 0x7FF800001000ULL }) };
    const SurveyReport kDataPeReport = runInjectionSurvey(dataPe);
    suite.expect(!kDataPeReport.hasObservation(
                     ObservationClass::kPayloadStructureWithReliableFrame),
                 L"总入口 数据中的 PE 不升格为已执行载荷");

    // Unchecked candidates produce no conclusions and are placed in the "unexecuted checks" category.
    SurveyInput notExamined = makeCleanInput();
    PayloadCandidateEntry unchecked = erased;
    unchecked.structure = PayloadStructure::kNotExamined;
    notExamined.payloadCandidates = { unchecked };
    const SurveyReport kNotExaminedReport = runInjectionSurvey(notExamined);
    suite.expect(!hasRule(kNotExaminedReport.findings, kRuleIdPayloadStructure),
                 L"总入口 未检查候选不产出结果");
    suite.expect(std::find(kNotExaminedReport.notPerformedCheckKeys.begin(),
                           kNotExaminedReport.notPerformedCheckKeys.end(),
                           std::string(kCheckPayloadStructure)) !=
                     kNotExaminedReport.notPerformedCheckKeys.end(),
                 L"总入口 未检查候选登记为未执行");

    // --- Stack backtrace: Reliable prefix. Test admitStackFrames
    // independently, then test its effect through the main entry.
    {
        // Untrusted context: invalidate the entire chain, not 'downgrade to heuristic'.
        ThreadStackInput running = makeTrustedStack(300U, { 0x7FF800001000ULL, 0x600100ULL });
        running.trust = ThreadContextTrust::kRunningThreadUntrusted;
        suite.expect(admitStackFrames(running) == 0U, L"栈 运行中线程的上下文整条作废");

        ThreadStackInput notCaptured = makeTrustedStack(301U, { 0x7FF800001000ULL });
        notCaptured.trust = ThreadContextTrust::kNotCaptured;
        suite.expect(admitStackFrames(notCaptured) == 0U, L"栈 没取到上下文不产生可靠帧");

        // Suspended/snapshot and "both waiting twice" are both considered trusted.
        ThreadStackInput suspended = makeTrustedStack(302U, { 0x7FF800001000ULL });
        suspended.trust = ThreadContextTrust::kSuspendedOrSnapshot;
        suite.expect(admitStackFrames(suspended) == 1U, L"栈 挂起/快照可信");
        suite.expect(admitStackFrames(makeTrustedStack(303U, { 0x7FF800001000ULL })) == 1U,
                     L"栈 等待中线程可信");

        // Trusted prefix truncates after accepting this frame at the point where "unwind data unavailable at this frame's PC".
        // This is precisely the location of the shellcode frame: it is calculated by the caller, so it counts; what lies below it does not.
        ThreadStackInput beacon = makeTrustedStack(
            304U, { 0x7FF800001000ULL, 0x7FF800002000ULL, 0x600100ULL });
        beacon.frames[2].unwindDataAvailableAtPc = false;
        beacon.frames.push_back(RawStackFrame{ OptionalU64::of(0x7FF800009000ULL),
                                               OptionalU64::of(0x9000400ULL), false, true });
        suite.expect(admitStackFrames(beacon) == 3U, L"栈 载荷帧进可靠前缀而其后的不进");

        // Frames missing a PC are truncated directly: frames without a landing point cannot participate in any judgment.
        ThreadStackInput missingPc = makeTrustedStack(305U, { 0x7FF800001000ULL, 0x600100ULL });
        missingPc.frames[1].instructionPointer = OptionalU64{};
        suite.expect(admitStackFrames(missingPc) == 1U, L"栈 无落点的帧截断可靠前缀");

        // Guessed frames do not enter the reliable prefix, even if they have unwind data.
        ThreadStackInput guessed = makeTrustedStack(306U, { 0x7FF800001000ULL, 0x600100ULL });
        guessed.frames[1].derivedFromUnwindData = false;
        suite.expect(admitStackFrames(guessed) == 1U, L"栈 扫栈猜出的帧不进可靠前缀");
    }

    // Stack unwound but no trusted context obtained — this is a gap, not a capability limit. Conflating
    // the two would let "failed this time" be mischaracterized as "not supported in this version."
    SurveyInput allRunning = makeCleanInput();
    allRunning.mode = SurveyMode::kDeep;
    allRunning.nonExecutableMemoryScanned = true;
    ThreadStackInput runningStack = makeTrustedStack(310U, { 0x7FF800001000ULL });
    runningStack.trust = ThreadContextTrust::kRunningThreadUntrusted;
    allRunning.threadStacks = { runningStack };
    const SurveyReport kAllRunningReport = runInjectionSurvey(allRunning);
    suite.expect(kAllRunningReport.hasGap(kGapStackWalkUntrusted),
                 L"栈 全在跑记成缺口");
    suite.expect(!kAllRunningReport.hasLimit(kLimitStackUnwindUnavailable),
                 L"栈 做过就不再记能力限制");
    suite.expect(kAllRunningReport.stackThreadsWalked == 1U, L"栈 走过的线程计数");
    suite.expect(kAllRunningReport.stackThreadsTrusted == 0U, L"栈 可信线程计数为零");
    suite.expect(kAllRunningReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"栈 缺口压制干净结论");

    // A crash not caused by a clumsy hand is guaranteed by three layers.
    SurveyInput noStacks = makeCleanInput();
    noStacks.mode = SurveyMode::kDeep;
    noStacks.nonExecutableMemoryScanned = true;
    const SurveyReport kNoStacksReport = runInjectionSurvey(noStacks);
    suite.expect(kNoStacksReport.hasLimit(kLimitStackUnwindUnavailable),
                 L"栈 没做记能力限制");
    suite.expect(!kNoStacksReport.hasGap(kGapStackWalkUntrusted), L"栈 没做不记缺口");
    suite.expect(kNoStacksReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"栈 能力限制不压制干净结论");

    // Account: reliable frame count and thread back-source.
    SurveyInput beaconSurvey = makeCleanInput();
    PayloadCandidateEntry beaconPayload;
    beaconPayload.base = OptionalU64::of(0x600000U);
    beaconPayload.size = OptionalU64::of(0x3000U);
    beaconPayload.type = RegionType::kPrivate;
    beaconPayload.structure = PayloadStructure::kHeaderErasedPe;
    beaconPayload.outcome = CollectionOutcome::success();
    beaconSurvey.payloadCandidates = { beaconPayload };
    beaconSurvey.threadStacks = {
        makeTrustedStack(311U, { 0x7FF800001000ULL, 0x7FF800002000ULL, 0x600100ULL },
                         /*lastFrameHasUnwindData=*/false)
    };
    const SurveyReport kBeaconReport = runInjectionSurvey(beaconSurvey);
    suite.expect(kBeaconReport.stackThreadsTrusted == 1U, L"栈 可信线程计数");
    suite.expect(kBeaconReport.stackReliableFrameCount == 3U, L"栈 可靠帧计数");
    suite.expect(kBeaconReport.payloadWithExecutionCount == 1U, L"栈 落点自动判出执行关联");
    suite.expect(kBeaconReport.conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"栈 落点升到观测到差异");
    {
        const InjectionFinding* const kHit =
            findRule(kBeaconReport.findings, kRuleIdPayloadStructure);
        suite.expect(kHit != nullptr, L"栈 载荷条目存在");
        if (kHit != nullptr) {
            suite.expect(kHit->confidence == EvidenceConfidence::kCorroboratedIndependent,
                         L"栈 结构与执行两个来源互证");
            suite.expect(!kHit->relatedThreads.empty() &&
                             kHit->relatedThreads.front().tid.valueOr(0U) == 311ULL,
                         L"栈 落点回源到具体线程");
            suite.expect(std::any_of(kHit->facts.begin(), kHit->facts.end(),
                                     [](const std::string& fact) {
                                         return fact == "stack.frame.depth=2";
                                     }),
                         L"栈 落点记录栈深度");
        }
    }

    // Sleeping payloads: non-executable candidates collected during acquisition are listed but do not trigger a conclusion.
    // Measured baseline noise is approximately 0.3 non-executable regions per process that "look like a proper PE" on their first
    // page. Including these in the conclusion-elevation path causes clean machines to routinely report "observed differences".
    suite.expect(payloadCandidateCanRaiseConclusion(beaconPayload),
                 L"栈 可执行候选可参与升结论");
    {
        PayloadCandidateEntry dormant = beaconPayload;
        dormant.executableAtScanTime = false;
        suite.expect(!payloadCandidateCanRaiseConclusion(dormant),
                     L"休眠 不可执行候选不参与升结论");

        SurveyInput dormantSurvey = makeCleanInput();
        dormantSurvey.payloadCandidates = { dormant };
        // Provide a reliable frame that truly lands in this memory region — even this shouldn't be promoted.
        dormantSurvey.threadStacks = {
            makeTrustedStack(320U, { 0x7FF800001000ULL, 0x600100ULL },
                             /*lastFrameHasUnwindData=*/false)
        };
        const SurveyReport kDormantReport = runInjectionSurvey(dormantSurvey);
        suite.expect(kDormantReport.payloadWithExecutionCount == 0U,
                     L"休眠 不可执行候选即便有帧进入也不升格");
        suite.expect(kDormantReport.conclusion != AnalysisConclusion::kDifferenceObserved,
                     L"休眠 不可执行候选不升到观测到差异");
        // But it must **still appear in the list** — not escalating the conclusion does not mean hiding it from the user.
        suite.expect(hasRule(kDormantReport.findings, kRuleIdPayloadStructure),
                     L"休眠 不可执行候选仍然列出条目");
        const InjectionFinding* const kDormantHit =
            findRule(kDormantReport.findings, kRuleIdPayloadStructure);
        suite.expect(kDormantHit != nullptr &&
                         std::any_of(kDormantHit->facts.begin(), kDormantHit->facts.end(),
                                     [](const std::string& fact) {
                                         return fact == "payload.executable-at-scan=false";
                                     }),
                     L"休眠 条目记录采集时不可执行");
    }

    // If non-executable memory has been scanned, that capability restriction should no longer be recorded.
    {
        SurveyInput scanned = makeCleanInput();
        scanned.mode = SurveyMode::kDeep;
        scanned.nonExecutableMemoryScanned = true;
        scanned.threadStacks = { makeTrustedStack(321U, { 0x7FF800001000ULL }) };
        const SurveyReport kScannedReport = runInjectionSurvey(scanned);
        suite.expect(!kScannedReport.hasLimit(kLimitNonExecutableNotScanned),
                     L"休眠 扫过即无该能力限制");
        suite.expect(kScannedReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                     L"休眠 扫过后仍可给出干净结论");
    }

    // The hit point is one byte outside the payload range: not considered an entry.
    SurveyInput justOutside = beaconSurvey;
    justOutside.threadStacks = {
        makeTrustedStack(312U, { 0x7FF800001000ULL, 0x603000ULL },
                         /*lastFrameHasUnwindData=*/false)
    };
    const SurveyReport kJustOutsideReport = runInjectionSurvey(justOutside);
    suite.expect(kJustOutsideReport.payloadWithExecutionCount == 0U,
                 L"栈 范围外一字节不算进入");

    // A hit point appears in the unreliable segment: it doesn't count. Marking the
    // shellcode frame as guessed means it should no longer support execution correlation.
    SurveyInput guessedHit = beaconSurvey;
    ThreadStackInput guessedStack =
        makeTrustedStack(313U, { 0x7FF800001000ULL, 0x600100ULL });
    guessedStack.frames[1].derivedFromUnwindData = false;
    guessedHit.threadStacks = { guessedStack };
    const SurveyReport kGuessedHitReport = runInjectionSurvey(guessedHit);
    suite.expect(kGuessedHitReport.payloadWithExecutionCount == 0U,
                 L"栈 猜出来的落点不撑执行关联");
    suite.expect(kGuessedHitReport.conclusion != AnalysisConclusion::kDifferenceObserved,
                 L"栈 猜出来的落点不升结论");

    // --- VAD chain break --- Three-state criteria. The most
    // critical rule: NotChecked must not be folded into Consistent.
    // Interpreting 'incomplete' as 'the tree is valid' is the only fatal error in this dimension.
    {
        const auto kMakeView = []() {
            KernelVadView view;
            view.state = KernelBackendState::kAvailable;
            view.outcome = CollectionOutcome::success();
            view.integrityValid = true;
            view.vadCountKnown = true;
            view.vadHintKnown = true;
            view.visitedCount = 586U;
            view.vadCount = 586U;
            view.vadHintAddress = OptionalU64::of(0xFFFFCA827CAA1E00ULL);
            view.vadHintVisited = true;
            return view;
        };

        suite.expect(evaluateVadLinkIntegrity(kMakeView()) == VadLinkIntegrity::kConsistent,
                     L"断链 全对得上即一致");

        // Incomplete traversal: always treat as NotChecked, even if the three readings appear 'fine'.
        KernelVadView partial = kMakeView();
        partial.integrityValid = false;
        suite.expect(evaluateVadLinkIntegrity(partial) == VadLinkIntegrity::kNotChecked,
                     L"断链 遍历不完整即未检查");
        KernelVadView notAvailable = kMakeView();
        notAvailable.state = KernelBackendState::kPartial;
        suite.expect(evaluateVadLinkIntegrity(notAvailable) == VadLinkIntegrity::kNotChecked,
                     L"断链 后端非完整即未检查");

        // Parent pointer does not point back.
        KernelVadView orphan = kMakeView();
        orphan.parentMismatchNodes = 1U;
        suite.expect(evaluateVadLinkIntegrity(orphan) == VadLinkIntegrity::kInconsistent,
                     L"断链 父指针回指不上即不一致");

        // The VadHint points to a node not found in the tree.
        KernelVadView hintLost = kMakeView();
        hintLost.vadHintVisited = false;
        suite.expect(evaluateVadLinkIntegrity(hintLost) == VadLinkIntegrity::kInconsistent,
                     L"断链 VadHint 不可达即不一致");
        // However, a null VadHint is valid (for a newly created process that hasn't been used yet) and should not be considered inconsistent.
        KernelVadView hintNull = kMakeView();
        hintNull.vadHintVisited = false;
        hintNull.vadHintAddress = OptionalU64{};
        suite.expect(evaluateVadLinkIntegrity(hintNull) == VadLinkIntegrity::kConsistent,
                     L"断链 VadHint 为空不算不一致");
        // Do not use it for null checks when the offset is unavailable.
        KernelVadView hintUnknown = kMakeView();
        hintUnknown.vadHintKnown = false;
        hintUnknown.vadHintVisited = false;
        suite.expect(evaluateVadLinkIntegrity(hintUnknown) == VadLinkIntegrity::kConsistent,
                     L"断链 VadHint 偏移不可用时不参与判定");

        // Count is greater than the number of nodes traversed = there are nodes not on the tree.
        KernelVadView fewer = kMakeView();
        fewer.visitedCount = 585U;
        suite.expect(evaluateVadLinkIntegrity(fewer) == VadLinkIntegrity::kInconsistent,
                     L"断链 走出来比计数少即不一致");
        // **Reverse counting is excluded**: During concurrent VAD creation, the count not yet being incremented is normal; including it would cause false positives on busy processes.
        KernelVadView more = kMakeView();
        more.visitedCount = 587U;
        suite.expect(evaluateVadLinkIntegrity(more) == VadLinkIntegrity::kConsistent,
                     L"断链 走出来比计数多不算不一致");
        KernelVadView countUnknown = kMakeView();
        countUnknown.vadCountKnown = false;
        countUnknown.visitedCount = 100U;
        suite.expect(evaluateVadLinkIntegrity(countUnknown) == VadLinkIntegrity::kConsistent,
                     L"断链 计数偏移不可用时不参与判定");
    }

    // On entering the main entry point: Inconsistencies only reach 'Pending Explanation', not escalated to 'Observed Difference'.
    {
        SurveyInput linkBroken = makeCleanInput();
        linkBroken.kernelVadState = KernelBackendState::kAvailable;
        linkBroken.kernelPteState = KernelBackendState::kAvailable;
        linkBroken.kernelCrossView.linkIntegrity = VadLinkIntegrity::kInconsistent;
        linkBroken.kernelCrossView.linkVisitedCount = 585U;
        linkBroken.kernelCrossView.linkVadCount = 586U;
        linkBroken.kernelCrossView.linkVadCountKnown = true;
        linkBroken.kernelCrossView.linkParentMismatchNodes = 2U;
        const SurveyReport kBrokenReport = runInjectionSurvey(linkBroken);
        suite.expect(kBrokenReport.vadLinkIssueCount == 1U, L"断链 总入口计数");
        suite.expect(hasRule(kBrokenReport.findings, kRuleIdKernelVadLinkBroken),
                     L"断链 总入口产出条目");
        suite.expect(kBrokenReport.hasObservation(
                         ObservationClass::kVadTreeLinkageInconsistent),
                     L"断链 总入口记观测类");
        suite.expect(kBrokenReport.conclusion == AnalysisConclusion::kIndeterminate,
                     L"断链 只到待解释");
        suite.expect(kBrokenReport.conclusion != AnalysisConclusion::kDifferenceObserved,
                     L"断链 不升到观测到差异（误报率尚未实测）");
        const InjectionFinding* const kBrokenHit =
            findRule(kBrokenReport.findings, kRuleIdKernelVadLinkBroken);
        suite.expect(kBrokenHit != nullptr &&
                         std::any_of(kBrokenHit->facts.begin(), kBrokenHit->facts.end(),
                                     [](const std::string& fact) {
                                         return fact == "vad.count-from-eprocess=586";
                                     }),
                     L"断链 条目带内核计数可回源");

        // Completed and consistent: record as a finished check with no gaps.
        SurveyInput linkOk = makeCleanInput();
        linkOk.kernelVadState = KernelBackendState::kAvailable;
        linkOk.kernelPteState = KernelBackendState::kAvailable;
        linkOk.kernelCrossView.linkIntegrity = VadLinkIntegrity::kConsistent;
        const SurveyReport kOkReport = runInjectionSurvey(linkOk);
        suite.expect(kOkReport.vadLinkIssueCount == 0U, L"断链 一致时无条目");
        suite.expect(!kOkReport.hasGap(kGapVadLinkUncheckable), L"断链 一致时不留缺口");

        // Backend succeeded but tree traversal incomplete: **gap**, not "consistent".
        SurveyInput linkUnchecked = makeCleanInput();
        linkUnchecked.kernelVadState = KernelBackendState::kAvailable;
        linkUnchecked.kernelPteState = KernelBackendState::kAvailable;
        linkUnchecked.kernelCrossView.linkIntegrity = VadLinkIntegrity::kNotChecked;
        const SurveyReport kUncheckedReport = runInjectionSurvey(linkUnchecked);
        suite.expect(kUncheckedReport.hasGap(kGapVadLinkUncheckable),
                     L"断链 没走完记成缺口");
        suite.expect(kUncheckedReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                     L"断链 缺口压制干净结论");
    }

    // --- Image Section Object Reference Page --- Section objects are the second
    // source of "what this image should look like" (the disk file is the first).
    // Its coverage accounting must be gated separately: prototype PTEs that are not in a valid page state cannot
    // yield a reference. This means **no match was found**, not that a comparison was made with no differences.
    {
        ImageComparisonOutcome diskRef;
        diskRef.referenceSource = ImageReferenceSource::kDiskFile;
        suite.expect(sectionReferenceCoverageComplete(diskRef),
                     L"节参考 磁盘来源不受节覆盖账约束");

        ImageComparisonOutcome full;
        full.referenceSource = ImageReferenceSource::kSectionObject;
        full.sectionPagesRequested = 16U;
        full.sectionPagesAvailable = 16U;
        suite.expect(sectionReferenceCoverageComplete(full), L"节参考 全覆盖");

        ImageComparisonOutcome partial = full;
        partial.sectionPagesAvailable = 15U;
        suite.expect(!sectionReferenceCoverageComplete(partial), L"节参考 少一页即不完整");

        // If no pages were requested, it cannot be considered "fully covered" — that is not a comparison, but a lack of comparison.
        ImageComparisonOutcome none;
        none.referenceSource = ImageReferenceSource::kSectionObject;
        suite.expect(!sectionReferenceCoverageComplete(none), L"节参考 零请求不算完整");

        suite.expect(std::string(imageReferenceSourceName(ImageReferenceSource::kSectionObject)) ==
                         "SectionObject",
                     L"节参考 来源名可回源");
    }

    // On reaching the total entry: suppress clean conclusions when section references are incomplete.
    {
        SurveyInput sectionPartial = makeCleanInput();
        ImageComparisonOutcome outcome;
        outcome.referenceConfidence = ReferenceConfidence::kReferenceVerified;
        outcome.referenceSource = ImageReferenceSource::kSectionObject;
        outcome.sectionPagesRequested = 32U;
        outcome.sectionPagesAvailable = 20U;
        outcome.report.outcome = CollectionOutcome::success();
        sectionPartial.imageComparisons = { outcome };
        const SurveyReport kPartialReport = runInjectionSurvey(sectionPartial);
        suite.expect(kPartialReport.sectionReferenceComparisons == 1U, L"节参考 计数");
        suite.expect(kPartialReport.hasGap(kGapSectionReferenceIncomplete),
                     L"节参考 覆盖不全记成缺口");
        suite.expect(kPartialReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                     L"节参考 缺口压制干净结论");

        SurveyInput sectionFull = makeCleanInput();
        ImageComparisonOutcome complete = outcome;
        complete.sectionPagesAvailable = 32U;
        sectionFull.imageComparisons = { complete };
        const SurveyReport kFullReport = runInjectionSurvey(sectionFull);
        suite.expect(!kFullReport.hasGap(kGapSectionReferenceIncomplete),
                     L"节参考 全覆盖不留缺口");
        suite.expect(kFullReport.conclusion == AnalysisConclusion::kNoDifferenceObserved,
                     L"节参考 全覆盖可给出干净结论");
    }

    // --- WOW64 collector gap pass-through.
    SurveyInput wow = makeCleanInput();
    wow.collectorArchitecture = CollectorArchitecture::kWow64;
    const SurveyReport kWowReport = runInjectionSurvey(wow);
    suite.expect(kWowReport.hasGap(kGapModuleEnumerationWow64), L"总入口 WOW64 缺口透传");
    suite.expect(kWowReport.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"总入口 WOW64 列表不完整压制干净结论");

    // --- No observations at all ---
    SurveyInput nothing;
    nothing.processBefore = makeProcess(4321U, 0x1D000000000ULL);
    nothing.processAfter = nothing.processBefore;
    nothing.addressSpace.outcome = accessDeniedOutcome();
    nothing.moduleCrossView.conclusion = AnalysisConclusion::kNoEvidence;
    nothing.threadEnumerationOutcome = accessDeniedOutcome();
    const SurveyReport kNothingReport = runInjectionSurvey(nothing);
    suite.expect(kNothingReport.conclusion == AnalysisConclusion::kNoEvidence,
                 L"总入口 无观测即无证据");
    suite.expect(!kNothingReport.coverageComplete, L"总入口 无观测覆盖不完整");
}

} // namespace

int runInjectionSurveyTests() {
    ksword_tests::Suite suite(L"J injection survey");
    testProtectionClassification(suite);
    testRegionCodeClass(suite);
    testAddressSpaceIndex(suite);
    testSurfaceScreen(suite);
    testModuleCrossView(suite);
    testWorkingSetScreen(suite);
    testThreadStarts(suite);
    testComparisonPlan(suite);
    testKernelCrossView(suite);
    testExceptionRelations(suite);
    testSemanticsAndIdentity(suite);
    testSurveyPipeline(suite);
    suite.report();
    return suite.failures();
}
