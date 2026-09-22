// Offline automated tests for the F module (existing capability reuse and evidence foundation).
//
// All assertions directly call the production implementation in shared/evidence; the implementation is not duplicated in the tests.
//
// Coverage scope (report accurately, no exaggeration):
//   * Full coverage: F-03, F-04, F-05, F-06, F-08, F-11, and the JSON untrusted input boundary for Q-12.
//   * Covers only the pure policy section: F-09, F-10, F-12. The final pass conditions for these three rules depend on UI/session
//     behavior, whereas the assertion functions in this file (decideNavigation / resolveProcessNavigation /) determine the verdict.
//     decideRefresh / LatestRequestGate / validateRange / evaluateBudget /
//     buildTrustStatement / Match* / fullyCovered / describeRemaining) currently have **no callers** on the
//     production side—the only production entry point is toCollectionOutcome in DriverDock.cpp. Before the
//     access layer is implemented, a green light here only indicates that the criteria themselves are correct.

#include "TestSupport.h"

#include "../../../shared/evidence/EvidenceEnvelope.h"
#include "../../../shared/evidence/EvidenceJson.h"
#include "../../../shared/evidence/LiveNavigation.h"
#include "../../../shared/evidence/LosslessValue.h"
#include "../../../shared/evidence/ObjectIdentity.h"
#include "../../../shared/evidence/ScanBudget.h"

// F-05 production implementation (driver client shared by Qt main app / Light / CLI).
#include "../../../shared/ark_client/ArkDriverEvidence.h"

#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace {

using namespace ksword::evidence;

// IoResult::ntStatus is long; test NTSTATUS constants are written as 32-bit unsigned, with conversion centralized here.
long asNtStatus(std::uint32_t status) noexcept {
    return static_cast<long>(status);
}

// ---------------------------------------------------------------------------
// F-08: Lossless 64-bit data
// ---------------------------------------------------------------------------
void testLosslessValues(ksword_tests::Suite& s) {
    constexpr std::uint64_t kAbove2p53 = 9007199254740993ULL;  // 2^53 + 1, which cannot be represented by double
    constexpr std::uint64_t kMaxU64 = (std::numeric_limits<std::uint64_t>::max)();
    constexpr std::uint64_t kMaxCanonicalKernel = 0xFFFFFFFFFFFFFFFFULL;

    s.expect(formatU64(kAbove2p53, U64Format::kDecimal) == "9007199254740993",
             L"F-08 2^53+1 decimal is exact");

    std::uint64_t parsed = 0U;
    s.expect(parseU64("9007199254740993", parsed) && parsed == kAbove2p53,
             L"F-08 2^53+1 round-trips through decimal text");

    s.expect(formatU64(kMaxU64, U64Format::kDecimal) == "18446744073709551615",
             L"F-08 max u64 decimal is exact");
    s.expect(parseU64("18446744073709551615", parsed) && parsed == kMaxU64,
             L"F-08 max u64 parses back exactly");
    s.expect(!parseU64("18446744073709551616", parsed),
             L"F-08 u64 overflow is rejected, not truncated");

    s.expect(formatU64(0x00007FFE12340000ULL, U64Format::kHexAddress) == "0x00007FFE12340000",
             L"F-08 address keeps a fixed 16-digit hex form");
    s.expect(parseU64("0x00007FFE12340000", parsed) && parsed == 0x00007FFE12340000ULL,
             L"F-08 hex address round-trips");
    s.expect(formatU64(kMaxCanonicalKernel, U64Format::kHexAddress) == "0xFFFFFFFFFFFFFFFF",
             L"F-08 highest address formats without loss");

    // Null is not 0
    OptionalU64 empty;
    s.expect(!empty.present && formatOptionalU64(empty, U64Format::kDecimal).empty(),
             L"F-08 unset optional formats to empty, not 0");
    OptionalU64 roundTripped = OptionalU64::of(7U);
    s.expect(parseOptionalU64("", roundTripped) && !roundTripped.present,
             L"F-08 empty text parses back to unset, not 0");
    s.expect(parseOptionalU64("0", roundTripped) && roundTripped.present && roundTripped.value == 0U,
             L"F-08 zero stays a present zero");
    s.expect(OptionalU64::of(0U) != OptionalU64::unset(),
             L"F-08 present-zero and unset are distinct values");

    std::int64_t signedValue = 0;
    s.expect(formatI64((std::numeric_limits<std::int64_t>::min)()) == "-9223372036854775808" &&
                 parseI64("-9223372036854775808", signedValue) &&
                 signedValue == (std::numeric_limits<std::int64_t>::min)(),
             L"F-08 int64 min round-trips without UB");
}

// ---------------------------------------------------------------------------
// F-08: JSON round-trip; the parser never accepts floating-point.
// ---------------------------------------------------------------------------
void testJsonRoundTrip(ksword_tests::Suite& s) {
    constexpr std::uint64_t kBig = 9007199254740993ULL;

    JsonObject members;
    members.emplace_back("address", JsonValue::makeU64Text(0xFFFFF80312345678ULL, U64Format::kHexAddress));
    members.emplace_back("count", JsonValue::makeU64Text(kBig, U64Format::kDecimal));
    members.emplace_back("missing", JsonValue::makeOptionalU64Text(OptionalU64::unset(), U64Format::kDecimal));
    members.emplace_back("zero", JsonValue::makeOptionalU64Text(OptionalU64::of(0U), U64Format::kDecimal));
    members.emplace_back("label", JsonValue::makeString("C:\\a\"b\\\nc"));
    const JsonValue kDocument = JsonValue::makeObject(std::move(members));

    const std::string kText = writeJson(kDocument);
    const JsonParseResult kReparsed = parseJson(kText);
    s.expect(kReparsed.ok(), L"F-08 evidence JSON reparses");

    std::uint64_t address = 0U;
    std::uint64_t count = 0U;
    OptionalU64 missing = OptionalU64::of(123U);
    OptionalU64 zero;
    std::string label;
    const JsonValue* addressNode = kReparsed.value.find("address");
    const JsonValue* countNode = kReparsed.value.find("count");
    const JsonValue* missingNode = kReparsed.value.find("missing");
    const JsonValue* zeroNode = kReparsed.value.find("zero");
    const JsonValue* labelNode = kReparsed.value.find("label");
    s.expect(addressNode != nullptr && addressNode->tryGetU64(address) && address == 0xFFFFF80312345678ULL,
             L"F-08 kernel address survives JSON round-trip bit-for-bit");
    s.expect(countNode != nullptr && countNode->tryGetU64(count) && count == kBig,
             L"F-08 2^53+1 survives JSON round-trip");
    s.expect(missingNode != nullptr && missingNode->isNull() &&
                 missingNode->tryGetOptionalU64(missing) && !missing.present,
             L"F-08 null stays unset after import and never becomes 0");
    s.expect(zeroNode != nullptr && zeroNode->tryGetOptionalU64(zero) && zero.present && zero.value == 0U,
             L"F-08 explicit zero stays zero after import");
    s.expect(labelNode != nullptr && labelNode->tryGetString(label) && label == "C:\\a\"b\\\nc",
             L"F-08 escaped text round-trips exactly");

    // Floating-point values must be explicitly rejected, not silently truncated.
    s.expect(parseJson("{\"v\":9007199254740993.0}").status == JsonParseStatus::kFloatingPointRejected,
             L"F-08 floating point numbers are rejected");
    s.expect(parseJson("{\"v\":1e3}").status == JsonParseStatus::kFloatingPointRejected,
             L"F-08 exponent form is rejected");

    // Q-12: Boundary of untrusted input.
    s.expect(parseJson("{\"a\":1,\"a\":2}").status == JsonParseStatus::kDuplicateKey,
             L"Q-12 duplicate object keys are rejected, not silently overwritten");
    s.expect(parseJson("{} trailing").status == JsonParseStatus::kTrailingData,
             L"Q-12 trailing data is rejected");
    s.expect(parseJson("").status == JsonParseStatus::kEmpty, L"Q-12 empty input is reported as empty");
    {
        JsonLimits shallow;
        shallow.maxDepth = 4;
        std::string deep;
        for (int i = 0; i < 40; ++i) {
            deep += "[";
        }
        for (int i = 0; i < 40; ++i) {
            deep += "]";
        }
        s.expect(parseJson(deep, shallow).status == JsonParseStatus::kDepthLimit,
                 L"Q-12 deep nesting hits the depth limit instead of recursing away");
    }
    s.expect(parseJson("{\"v\":\"\x01\"}").status != JsonParseStatus::kOk,
             L"Q-12 raw control characters in strings are rejected");

    // F-08: Round-trip of arrays and scalar types (makeArray / asArray / tryGetI64 / tryGetBool)
    JsonArray items;
    items.push_back(JsonValue::makeInt(-9007199254740993LL));  // -(2^53+1)
    items.push_back(JsonValue::makeBool(true));
    items.push_back(JsonValue::makeBool(false));
    items.push_back(JsonValue::makeNull());
    items.push_back(JsonValue::makeUInt(kBig));
    const std::string kArrayText = writeJson(JsonValue::makeArray(std::move(items)));
    const JsonParseResult kArrayBack = parseJson(kArrayText);
    const JsonArray* reparsedArray = kArrayBack.ok() ? kArrayBack.value.asArray() : nullptr;
    s.expect(reparsedArray != nullptr && reparsedArray->size() == 5U,
             L"F-08 a JSON array round-trips with its element count intact");
    if (reparsedArray != nullptr && reparsedArray->size() == 5U) {
        std::int64_t negative = 0;
        bool flagTrue = false;
        bool flagFalse = true;
        std::uint64_t big = 0U;
        s.expect((*reparsedArray)[0].tryGetI64(negative) && negative == -9007199254740993LL,
                 L"F-08 a negative value past 2^53 survives the array round-trip");
        s.expect((*reparsedArray)[1].tryGetBool(flagTrue) && flagTrue &&
                     (*reparsedArray)[2].tryGetBool(flagFalse) && !flagFalse,
                 L"F-08 booleans round-trip as booleans, not as 0/1");
        s.expect((*reparsedArray)[3].isNull() && !(*reparsedArray)[3].tryGetBool(flagTrue),
                 L"F-08 null in an array stays null and is not readable as a bool");
        s.expect((*reparsedArray)[4].tryGetU64(big) && big == kBig,
                 L"F-08 an unsigned value past 2^53 survives the array round-trip");
    }

    // F-07 / Q-12: Capping nodes by 'count' alone cannot control memory usage — add a secondary cap based on estimated byte count.
    {
        std::string manyNodes("[");
        for (int i = 0; i < 6; ++i) {
            manyNodes += (i == 0) ? "1" : ",1";
        }
        manyNodes += "]";  // 1 array node + 6 element nodes

        JsonLimits tinyNodeBytes;
        tinyNodeBytes.maxEstimatedNodeBytes = 1U;  // Cannot even fit a single JsonValue.
        s.expect(parseJson(manyNodes, tinyNodeBytes).status == JsonParseStatus::kSizeLimit,
                 L"F-07 a node-memory budget smaller than one node reports SizeLimit, not Ok");

        JsonLimits roomyNodeBytes;
        roomyNodeBytes.maxEstimatedNodeBytes = 16U * 1024U * 1024U;
        s.expect(parseJson(manyNodes, roomyNodeBytes).ok(),
                 L"F-07 the same input parses once the node-memory budget is raised");
    }

    // Q-12: Maximum total input bytes.
    {
        JsonLimits tinyInput;
        tinyInput.maxTotalBytes = 4U;
        s.expect(parseJson("[1,2]", tinyInput).status == JsonParseStatus::kSizeLimit,
                 L"Q-12 input larger than maxTotalBytes is refused before parsing");
        s.expect(parseJson("[1]", tinyInput).ok(),
                 L"Q-12 input inside maxTotalBytes still parses");
    }

    // Q-12: The default node limit applies to extremely large flat arrays (to prevent several MB of input from expanding into hundreds of MB of resident memory).
    {
        std::string wide("[0");
        wide.reserve(1300000U);
        for (int i = 0; i < 600000; ++i) {
            wide += ",0";
        }
        wide += "]";
        s.expect(parseJson(wide).status == JsonParseStatus::kNodeLimit,
                 L"F-07 600k array elements exceed the default node budget instead of being accepted");
    }

    // Q-12: Duplicate key detection must be amortized O(1). The old implementation scanned linearly by member count; 128,000 members were measured.
    // 15.3 seconds, extrapolating to about 17 minutes based on the default member limit — a DoS channel on the import side.
    // Pin with 200,000 valid members here: an O(n²) implementation cannot complete within this time limit.
    {
        std::string wideObject("{");
        wideObject.reserve(4000000U);
        for (int i = 0; i < 200000; ++i) {
            if (i != 0) {
                wideObject += ',';
            }
            wideObject += "\"k";
            wideObject += std::to_string(i);
            wideObject += "\":1";
        }
        wideObject += '}';

        const auto kStarted = std::chrono::steady_clock::now();
        const JsonParseResult kWideResult = parseJson(wideObject);
        const auto kElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now() - kStarted)
                                   .count();
        s.expect(kWideResult.ok(), L"Q-12 a 200k-member object is accepted, not rejected outright");
        s.expect(kElapsedMs < 2000,
                 L"Q-12 duplicate-key detection stays near-linear on a 200k-member object");

        // Duplicate keys must still be caught under the same scale.
        std::string duplicated = wideObject;
        duplicated.pop_back();
        duplicated += ",\"k0\":2}";
        s.expect(parseJson(duplicated).status == JsonParseStatus::kDuplicateKey,
                 L"Q-12 the fast duplicate-key index still rejects a late duplicate");
    }
}

// ---------------------------------------------------------------------------
// F-03: Stable object identity
// ---------------------------------------------------------------------------
void testObjectIdentity(ksword_tests::Suite& s) {
    ProcessInstanceId first;
    first.bootId = "boot-A";
    first.pid = OptionalU64::of(4321U);
    first.createTime100ns = OptionalU64::of(133000000000000000ULL);
    first.eprocessAddress = OptionalU64::of(0xFFFFA00112340000ULL);
    first.imageName = "target.exe";

    ProcessInstanceId sameAgain = first;
    ProcessInstanceId pidReused = first;
    pidReused.createTime100ns = OptionalU64::of(133000000099999999ULL);
    pidReused.eprocessAddress = OptionalU64::of(0xFFFFA00112340000ULL);  // Address reuse

    ProcessInstanceId otherBoot = first;
    otherBoot.bootId = "boot-B";

    ProcessInstanceId noCreateTime = first;
    noCreateTime.createTime100ns = OptionalU64::unset();

    s.expect(matchProcessInstance(first, sameAgain) == MatchResult::kConfirmed,
             L"F-03 identical process instance confirms");
    s.expect(matchProcessInstance(first, pidReused) == MatchResult::kNoMatch,
             L"F-03 same PID + different creation time is a different instance");
    s.expect(matchProcessInstance(first, otherBoot) == MatchResult::kNoMatch,
             L"F-03 same PID across boots is a different instance");
    s.expect(matchProcessInstance(first, noCreateTime) == MatchResult::kCandidate,
             L"F-03 missing creation time stays a candidate and is never auto-merged");
    s.expect(noCreateTime.strength() == IdentityStrength::kWeak && noCreateTime.crossSessionKey().empty(),
             L"F-03 weak process identity yields no cross-session key");
    s.expect(first.crossSessionKey() != pidReused.crossSessionKey(),
             L"F-03 PID reuse produces distinct cross-session keys");

    // Same address but different objects.
    ProcessInstanceId addressTwin;
    addressTwin.bootId = "boot-A";
    addressTwin.pid = OptionalU64::of(9999U);
    addressTwin.createTime100ns = OptionalU64::of(133000000000000000ULL);
    addressTwin.eprocessAddress = first.eprocessAddress;
    s.expect(matchProcessInstance(first, addressTwin) == MatchResult::kNoMatch,
             L"F-03 same address different PID is not the same object");

    // Thread bound to process instance
    ThreadInstanceId thread;
    thread.process = first;
    thread.tid = OptionalU64::of(777U);
    thread.createTime100ns = OptionalU64::of(133000000000500000ULL);

    ThreadInstanceId threadOnReusedPid = thread;
    threadOnReusedPid.process = pidReused;
    s.expect(matchThreadInstance(thread, threadOnReusedPid) == MatchResult::kNoMatch,
             L"F-03 thread does not attach to a new process on a reused PID");

    ThreadInstanceId tidReuse = thread;
    tidReuse.createTime100ns = OptionalU64::of(133000000900000000ULL);
    s.expect(matchThreadInstance(thread, tidReuse) == MatchResult::kNoMatch,
             L"F-03 TID reuse is a different thread instance");

    ThreadInstanceId threadNoCreate = thread;
    threadNoCreate.createTime100ns = OptionalU64::unset();
    s.expect(matchThreadInstance(thread, threadNoCreate) == MatchResult::kCandidate &&
                 threadNoCreate.crossSessionKey().empty(),
             L"F-03 thread without creation stamp stays a candidate");

    // Same path, different files
    FileIdentity fileA;
    fileA.path = "C:\\Windows\\System32\\drivers\\test.sys";
    fileA.volumeSerial = OptionalU64::of(0x1234ABCDULL);
    fileA.fileId = "0x0000000000000000000200000000AAAA";
    FileIdentity fileB = fileA;
    fileB.fileId = "0x0000000000000000000200000000BBBB";
    s.expect(matchFileIdentity(fileA, fileB) == MatchResult::kNoMatch,
             L"F-03 same path different file id is a different file");
    FileIdentity pathOnly;
    pathOnly.path = fileA.path;
    s.expect(matchFileIdentity(fileA, pathOnly) == MatchResult::kCandidate &&
                 pathOnly.crossSessionKey().empty(),
             L"F-03 path alone is not a cross-session file key");

    // F-03: Same hash but different path means "same bytes", not "same file object".
    // Genuine driver under System32 vs. an identical byte-for-byte copy deployed to the user directory.
    FileIdentity systemCopy;
    systemCopy.path = "C:\\Windows\\System32\\drivers\\good.sys";
    systemCopy.contentHash = "sha256:AA";
    FileIdentity droppedCopy;
    droppedCopy.path = "C:\\Users\\Public\\dropped_copy.sys";
    droppedCopy.contentHash = "sha256:AA";
    s.expect(matchFileIdentity(systemCopy, droppedCopy) == MatchResult::kCandidate,
             L"F-03 the same content at two different paths is a candidate, never one file");
    s.expect(!systemCopy.crossSessionKey().empty() && !droppedCopy.crossSessionKey().empty() &&
                 systemCopy.crossSessionKey() != droppedCopy.crossSessionKey(),
             L"F-03 two paths holding identical bytes get two different cross-session keys");
    FileIdentity caseVariant = systemCopy;
    caseVariant.path = "c:/windows/system32/drivers/good.sys";
    s.expect(caseVariant.crossSessionKey() == systemCopy.crossSessionKey(),
             L"F-03 the content key normalises case and separators so one file keeps one key");

    // Hard link: Two paths sharing (volumeSerial, fileId) represent the same file object.
    FileIdentity linkedA;
    linkedA.path = "C:\\Windows\\System32\\drivers\\linked.sys";
    linkedA.volumeSerial = OptionalU64::of(0x1234ABCDULL);
    linkedA.fileId = "0x0000000000000000000200000000CCCC";
    FileIdentity linkedB = linkedA;
    linkedB.path = "C:\\Windows\\System32\\drivers\\other-name.sys";
    s.expect(matchFileIdentity(linkedA, linkedB) == MatchResult::kConfirmed &&
                 linkedA.crossSessionKey() == linkedB.crossSessionKey(),
             L"F-03 a shared volume+fileId still confirms one object across two paths");

    // Same five-tuple, different time periods.
    ConnectionIdentity connEarly;
    connEarly.bootId = "boot-A";
    connEarly.protocol = 6U;
    connEarly.localAddress = "127.0.0.1";
    connEarly.localPort = 50001U;
    connEarly.remoteAddress = "127.0.0.1";
    connEarly.remotePort = 9;
    connEarly.observedFirstUtc100ns = OptionalU64::of(1000U);
    connEarly.observedLastUtc100ns = OptionalU64::of(2000U);
    ConnectionIdentity connLate = connEarly;
    connLate.observedFirstUtc100ns = OptionalU64::of(5000U);
    connLate.observedLastUtc100ns = OptionalU64::of(6000U);
    s.expect(connEarly.fiveTupleKey() == connLate.fiveTupleKey(),
             L"F-03 the two connections share a five-tuple");
    s.expect(matchConnectionIdentity(connEarly, connLate) == MatchResult::kNoMatch,
             L"F-03 same five-tuple in disjoint windows is a different connection");
    ConnectionIdentity connNoWindow = connEarly;
    connNoWindow.observedFirstUtc100ns = OptionalU64::unset();
    connNoWindow.observedLastUtc100ns = OptionalU64::unset();
    s.expect(matchConnectionIdentity(connEarly, connNoWindow) == MatchResult::kCandidate,
             L"F-03 connection without an observation window stays a candidate");

    // F-03: Cross-boot protection must not be bypassed when bootId is missing. Both sides being empty means "missing", not "identical".
    ConnectionIdentity noBootA = connEarly;
    noBootA.bootId.clear();
    noBootA.observedFirstUtc100ns = OptionalU64::of(1000U);
    noBootA.observedLastUtc100ns = OptionalU64::of(2000U);
    ConnectionIdentity noBootB = noBootA;
    noBootB.observedFirstUtc100ns = OptionalU64::of(1500U);
    noBootB.observedLastUtc100ns = OptionalU64::of(2500U);
    s.expect(matchConnectionIdentity(noBootA, noBootB) == MatchResult::kCandidate,
             L"F-03 overlapping windows without any boot id cannot confirm one connection");
    s.expect(noBootA.crossSessionKey().empty(),
             L"F-03 a connection without a boot id gets no cross-session key");

    // Has bootId and interval overlap, but the owning process is completely unknown: the port will be rebound by the next process.
    ConnectionIdentity overlapA = connEarly;
    overlapA.observedFirstUtc100ns = OptionalU64::of(1000U);
    overlapA.observedLastUtc100ns = OptionalU64::of(2000U);
    ConnectionIdentity overlapB = overlapA;
    overlapB.observedFirstUtc100ns = OptionalU64::of(1500U);
    overlapB.observedLastUtc100ns = OptionalU64::of(2500U);
    s.expect(matchConnectionIdentity(overlapA, overlapB) == MatchResult::kCandidate,
             L"F-03 an unknown owning process holds an overlapping connection at candidate");

    ConnectionIdentity ownedA = overlapA;
    ownedA.owner = first;
    ConnectionIdentity ownedB = overlapB;
    ownedB.owner = first;
    s.expect(matchConnectionIdentity(ownedA, ownedB) == MatchResult::kConfirmed,
             L"F-03 same boot + overlapping window + confirmed owner does confirm one connection");

    // Driver: Same name but different versions must not be conflated.
    DriverInstanceId loaded;
    loaded.bootId = "boot-A";
    loaded.imagePath = "C:\\Windows\\System32\\drivers\\ksword.sys";
    loaded.timeDateStamp = OptionalU64::of(0x65000000ULL);
    loaded.imageSize = OptionalU64::of(0x30000ULL);
    loaded.pdbSignature = "GUID-1/1";
    DriverInstanceId otherVersion = loaded;
    otherVersion.pdbSignature = "GUID-2/1";
    s.expect(matchDriverInstance(loaded, otherVersion) == MatchResult::kNoMatch,
             L"I-01 same driver path with a different PDB identity is a different image");

    // F-03: Insufficient identity (R0 enumeration cannot retrieve the image path: unbacked, unloaded, or path
    // wiped) means the remaining stamp+size is insufficient for confirmation. Since
    // strength()/crossSessionKey() indicates 'no primary key', the matcher cannot assert 'definitely the same'.
    DriverInstanceId stampOnly;
    stampOnly.timeDateStamp = OptionalU64::of(0x65000000ULL);
    stampOnly.imageSize = OptionalU64::of(0x30000ULL);
    const DriverInstanceId kStampOnlyTwin = stampOnly;
    s.expect(stampOnly.strength() == IdentityStrength::kUnusable &&
                 stampOnly.crossSessionKey().empty(),
             L"F-03 timestamp+size without a path or PDB is an unusable driver identity");
    s.expect(matchDriverInstance(stampOnly, kStampOnlyTwin) == MatchResult::kCandidate,
             L"F-03 an unusable driver identity can never confirm, only stay a candidate");

    // Monotonicity: Adding information must not make the conclusion stronger or weaker. Same path -> Confirmed;
    // Different paths but identical image identity -> Candidate; both are more explicit than 'nothing'.
    DriverInstanceId pathedA = stampOnly;
    pathedA.imagePath = "C:\\Windows\\System32\\drivers\\a.sys";
    DriverInstanceId pathedSame = pathedA;
    DriverInstanceId pathedB = stampOnly;
    pathedB.imagePath = "C:\\Users\\Public\\a.sys";
    s.expect(matchDriverInstance(pathedA, pathedSame) == MatchResult::kConfirmed,
             L"F-03 timestamp+size confirm once both sides carry the same image path");
    s.expect(matchDriverInstance(pathedA, pathedB) == MatchResult::kCandidate,
             L"F-03 the same image identity at two paths is a candidate copy, not a mismatch");

    // General invariant: if identity on either side is unavailable, none of the six Match* functions may return Confirmed.
    const ProcessInstanceId kNoPid{};               // pid missing -> Unusable
    const ThreadInstanceId kNoTid{};                // missing tid -> Unusable
    const FileIdentity kNothingKnown{};             // All three fields empty -> Unusable.
    const HandleIdentity kNoHandle{};               // Missing handleValue -> Unusable
    const ConnectionIdentity kNoProtocol{};         // Missing address/protocol -> Unusable
    s.expect(kNoPid.strength() == IdentityStrength::kUnusable &&
                 kNoTid.strength() == IdentityStrength::kUnusable &&
                 kNothingKnown.strength() == IdentityStrength::kUnusable &&
                 kNoHandle.strength() == IdentityStrength::kUnusable &&
                 kNoProtocol.strength() == IdentityStrength::kUnusable,
             L"F-03 the five empty identities all report as unusable");
    s.expect(matchProcessInstance(kNoPid, kNoPid) != MatchResult::kConfirmed &&
                 matchThreadInstance(kNoTid, kNoTid) != MatchResult::kConfirmed &&
                 matchDriverInstance(stampOnly, kStampOnlyTwin) != MatchResult::kConfirmed &&
                 matchFileIdentity(kNothingKnown, kNothingKnown) != MatchResult::kConfirmed &&
                 matchHandleIdentity(kNoHandle, kNoHandle) != MatchResult::kConfirmed &&
                 matchConnectionIdentity(kNoProtocol, kNoProtocol) != MatchResult::kConfirmed,
             L"F-03 no matcher confirms when either side's identity is unusable");

    // handle
    HandleIdentity handle;
    handle.owner = first;
    handle.handleValue = OptionalU64::of(0x1F0ULL);
    handle.objectAddress = OptionalU64::of(0xFFFFA00155550000ULL);
    handle.typeName = "File";
    HandleIdentity recycled = handle;
    recycled.objectAddress = OptionalU64::of(0xFFFFA00166660000ULL);
    s.expect(matchHandleIdentity(handle, recycled) == MatchResult::kCandidate,
             L"F-03 recycled handle value on a different object is not confirmed");
    HandleIdentity foreign = handle;
    foreign.owner = pidReused;
    s.expect(matchHandleIdentity(handle, foreign) == MatchResult::kNoMatch,
             L"F-03 handle value is scoped to its owning process instance");
}

// ---------------------------------------------------------------------------
// F-04: Source and time
// ---------------------------------------------------------------------------
void testSourceAndTime(ksword_tests::Suite& s) {
    CaptureWindow bootA;
    bootA.machineId = "machine-1";
    bootA.bootId = "boot-A";
    bootA.monotonicFrequency = OptionalU64::of(10000000ULL);  // 10 MHz QPC
    CaptureWindow bootB = bootA;
    bootB.bootId = "boot-B";

    s.expect(monotonicComparable(bootA, bootA), L"F-04 same boot monotonic values compare");
    s.expect(!monotonicComparable(bootA, bootB),
             L"F-04 monotonic values from two boot cycles are not comparable");

    std::int64_t nanos = 0;
    s.expect(monotonicDeltaNanos(bootA, 1000ULL, 1000ULL + 10000000ULL, nanos) && nanos == 1000000000LL,
             L"F-04 monotonic delta converts to nanoseconds without floating point");
    CaptureWindow noFrequency = bootA;
    noFrequency.monotonicFrequency = OptionalU64::unset();
    s.expect(!monotonicDeltaNanos(noFrequency, 0ULL, 1ULL, nanos),
             L"F-04 missing QPC frequency refuses to produce a duration");
    CaptureWindow noBoot = bootA;
    noBoot.bootId.clear();
    s.expect(!monotonicDeltaNanos(noBoot, 0ULL, 1ULL, nanos),
             L"F-04 raw QPC without a boot identity cannot be subtracted");
}

// ---------------------------------------------------------------------------
// F-05 / F-06: Separation of availability and conclusion; incomplete collection of accounts.
// ---------------------------------------------------------------------------
void testStatusAndCoverage(ksword_tests::Suite& s) {
    // Successful empty set: the ledger must explicitly write 'total 0, success 0' to represent a truly complete enumeration.
    EvidenceEnvelope emptyButSuccessful;
    emptyButSuccessful.outcome = CollectionOutcome::success();
    emptyButSuccessful.coverage.totalKnown = OptionalU64::of(0U);
    emptyButSuccessful.coverage.succeeded = 0U;
    s.expect(emptyButSuccessful.coverage.fullyCovered() &&
                 emptyButSuccessful.deriveConclusion(false) == AnalysisConclusion::kNoDifferenceObserved,
             L"F-05 a correct empty result with a declared total of 0 is an observation, not a failure");

    // F-06 / BLOCKER: A blank account is not fully covered. Forgetting to fill in the
    // account's collector must not grant a free '100% complete scan + no differences found'.
    const CoverageAccount kBlank{};
    s.expect(!kBlank.fullyCovered(),
             L"F-06 a blank coverage account is unknown coverage, never full coverage");
    s.expect(kBlank.describeRemaining() == "remaining:unknown",
             L"F-06 a blank coverage account reports its remainder as unknown");
    EvidenceEnvelope successNoAccount;
    successNoAccount.outcome = CollectionOutcome::success();
    s.expect(successNoAccount.deriveConclusion(false) == AnalysisConclusion::kIndeterminate,
             L"F-05 success without any coverage account cannot claim no-difference");

    // F-06: Range scope — Requesting [0x1000, 0x9000) only processes up to 0x2000.
    EvidenceEnvelope shortRange;
    shortRange.outcome = CollectionOutcome::success();
    shortRange.coverage.requestedBegin = OptionalU64::of(0x1000ULL);
    shortRange.coverage.requestedEnd = OptionalU64::of(0x9000ULL);
    shortRange.coverage.processedBegin = OptionalU64::of(0x1000ULL);
    shortRange.coverage.processedEnd = OptionalU64::of(0x2000ULL);
    s.expect(!shortRange.coverage.fullyCovered(),
             L"F-06 a request range wider than the processed range is not fully covered");
    s.expect(shortRange.deriveConclusion(false) == AnalysisConclusion::kIndeterminate,
             L"F-05 a Success status with a short-processed range still cannot say no-difference");
    s.expect(shortRange.coverage.describeRemaining() == "remaining-range:28672",
             L"F-06 the unprocessed tail is reported as an exact remainder");

    // Incomplete endpoint: When only 'begin' exists without 'end', the end boundary cannot be validated -> incomplete.
    CoverageAccount halfEndpoints;
    halfEndpoints.requestedBegin = OptionalU64::of(0x1000ULL);
    halfEndpoints.processedBegin = OptionalU64::of(0x1000ULL);
    s.expect(!halfEndpoints.fullyCovered(),
             L"F-06 a range with only begin endpoints cannot claim full coverage");

    // All four endpoints are present and the processing range covers the requested range: this constitutes full coverage under the range specification.
    CoverageAccount wholeRange;
    wholeRange.requestedBegin = OptionalU64::of(0x1000ULL);
    wholeRange.requestedEnd = OptionalU64::of(0x2000ULL);
    wholeRange.processedBegin = OptionalU64::of(0x1000ULL);
    wholeRange.processedEnd = OptionalU64::of(0x2000ULL);
    s.expect(wholeRange.fullyCovered() && wholeRange.describeRemaining() == "remaining-range:0",
             L"F-06 a fully processed range is complete and reports a zero remainder");

    // F-06: A truncated or skipped run alone is sufficient to negate full coverage and must force the conclusion back to Indeterminate.
    EvidenceEnvelope truncatedRun;
    truncatedRun.outcome = CollectionOutcome::success();
    truncatedRun.coverage.totalKnown = OptionalU64::of(10U);
    truncatedRun.coverage.succeeded = 10U;
    truncatedRun.coverage.truncated = 3U;
    s.expect(!truncatedRun.coverage.fullyCovered(),
             L"F-06 truncated items block the fully-covered claim");
    s.expect(truncatedRun.deriveConclusion(false) == AnalysisConclusion::kIndeterminate,
             L"F-05 a truncated success cannot be upgraded to no-difference");
    s.expect(truncatedRun.coverage.describeRemaining() == "truncated:3",
             L"F-06 truncation is named as the reason instead of reporting remaining:0");

    EvidenceEnvelope skippedRun;
    skippedRun.outcome = CollectionOutcome::success();
    skippedRun.coverage.totalKnown = OptionalU64::of(10U);
    skippedRun.coverage.succeeded = 9U;
    skippedRun.coverage.skipped = 1U;
    s.expect(!skippedRun.coverage.fullyCovered(),
             L"F-06 a skipped item blocks the fully-covered claim");
    s.expect(skippedRun.deriveConclusion(false) == AnalysisConclusion::kIndeterminate,
             L"F-05 a success with a skipped item cannot be upgraded to no-difference");
    s.expect(skippedRun.coverage.describeRemaining() == "incomplete:failed=0,skipped=1",
             L"F-06 a count that adds up but hides a skip is reported as incomplete");

    EvidenceEnvelope interfaceFailure;
    interfaceFailure.outcome = CollectionOutcome::failure(CollectionStatus::kError, "NTSTATUS",
                                                          0xC0000001ULL, "STATUS_UNSUCCESSFUL");
    s.expect(interfaceFailure.deriveConclusion(false) == AnalysisConclusion::kNoEvidence,
             L"F-05 a failed collector never yields a normal conclusion");
    s.expect(interfaceFailure.outcome.nativeCode.present &&
                 interfaceFailure.outcome.nativeCode.value == 0xC0000001ULL &&
                 interfaceFailure.outcome.nativeCodeDomain == "NTSTATUS" &&
                 !interfaceFailure.outcome.message.empty(),
             L"F-05 the raw error code and message are preserved");

    EvidenceEnvelope halfReturned;
    halfReturned.outcome.status = CollectionStatus::kPartial;
    halfReturned.coverage.succeeded = 50U;
    halfReturned.coverage.totalKnown = OptionalU64::of(100U);
    s.expect(halfReturned.deriveConclusion(false) == AnalysisConclusion::kIndeterminate,
             L"F-05 a half-covered scan cannot conclude no-difference");
    s.expect(halfReturned.deriveConclusion(true) == AnalysisConclusion::kDifferenceObserved,
             L"F-05 a partial scan can still report a difference it did observe");
    s.expect(halfReturned.coverage.describeRemaining() == "remaining:50",
             L"F-06 remaining count is derived from the declared total");

    EvidenceEnvelope notStarted;
    s.expect(notStarted.outcome.status == CollectionStatus::kNotCollected &&
                 notStarted.deriveConclusion(false) == AnalysisConclusion::kNoEvidence,
             L"F-05 a collector that never ran is not a normal result");

    EvidenceEnvelope denied;
    denied.outcome = CollectionOutcome::failure(CollectionStatus::kAccessDenied, "WIN32", 5ULL,
                                                "ERROR_ACCESS_DENIED");
    s.expect(denied.deriveConclusion(false) == AnalysisConclusion::kNoEvidence &&
                 !statusCarriesObservation(denied.outcome.status),
             L"F-05 access denied is distinguishable from an empty success");

    EvidenceEnvelope unsupported;
    unsupported.outcome.status = CollectionStatus::kUnsupported;
    s.expect(std::string(collectionStatusName(unsupported.outcome.status)) == "Unsupported" &&
                 std::string(collectionStatusName(denied.outcome.status)) == "AccessDenied" &&
                 std::string(collectionStatusName(emptyButSuccessful.outcome.status)) == "Success" &&
                 std::string(collectionStatusName(halfReturned.outcome.status)) == "Partial" &&
                 std::string(collectionStatusName(notStarted.outcome.status)) == "NotCollected",
             L"F-05 all five availability states export as distinct names");

    // F-06: Unknown total must not be misrepresented by the returned count.
    CoverageAccount unknownTotal;
    unknownTotal.succeeded = 128U;
    s.expect(!unknownTotal.totalKnown.present &&
                 unknownTotal.describeRemaining() == "remaining:unknown",
             L"F-06 an unknown total is reported as unknown, not as the returned count");

    CoverageAccount limited;
    limited.limitHit = true;
    limited.limit = OptionalU64::of(4096U);
    limited.succeeded = 4096U;
    s.expect(!limited.fullyCovered() && limited.describeRemaining() == "limit-hit:4096",
             L"F-06 hitting the cap never reports a 100% complete scan");

    // F-06: When a count source is unknown, a 0 in failed/skipped means "not counted" rather than "did not occur".
    // Previous T-module review testing revealed that when only total counts are reported, unknown items are summed as 0, making
    // the ledger appear precise while actually representing a lower bound. countsIncomplete converts this into an explicit state.
    CoverageAccount unknownCounts;
    unknownCounts.totalKnown = OptionalU64::of(10U);
    unknownCounts.succeeded = 10U;
    s.expect(unknownCounts.fullyCovered(),
             L"F-06 a fully reconciled count basis is complete when every counter is known");
    unknownCounts.countsIncomplete = true;
    s.expect(!unknownCounts.fullyCovered(),
             L"F-06 an unknown counter source blocks the fully-covered claim even when the numbers add up");
    s.expect(unknownCounts.describeRemaining() == "counts-incomplete",
             L"F-06 an unknown counter source is reported as such, not as a precise remaining count");

    CoverageAccount withFailures;
    withFailures.succeeded = 10U;
    withFailures.failed = 1U;
    withFailures.totalKnown = OptionalU64::of(11U);
    s.expect(!withFailures.fullyCovered(),
             L"F-06 a single item failure blocks the fully-covered claim");
    s.expect(withFailures.describeRemaining() == "incomplete:failed=1,skipped=0",
             L"F-06 a failed item is named rather than folded into remaining:0");

    // Invariant F-06: When fullyCovered() is true, describeRemaining() must not report 'unknown'.
    // Both methods must provide a consistent account — the earlier 'empty account =
    // full coverage + remaining unknown' simultaneously stated two contradictory facts.
    CoverageAccount countComplete;
    countComplete.totalKnown = OptionalU64::of(3U);
    countComplete.succeeded = 3U;
    const CoverageAccount kSamples[] = {kBlank,          halfEndpoints, wholeRange,
                                       countComplete,  withFailures,  limited,
                                       unknownTotal,   truncatedRun.coverage,
                                       skippedRun.coverage, shortRange.coverage,
                                       emptyButSuccessful.coverage};
    bool invariantHolds = true;
    for (const CoverageAccount& account : kSamples) {
        if (account.fullyCovered() && account.describeRemaining() == "remaining:unknown") {
            invariantHolds = false;
        }
    }
    s.expect(invariantHolds,
             L"F-06 fully-covered and remaining:unknown can never be reported together");
    s.expect(countComplete.fullyCovered() && countComplete.describeRemaining() == "remaining:0",
             L"F-06 a declared total that was fully processed is complete with a zero remainder");
}

// ---------------------------------------------------------------------------
// F-11: Source trust boundary
// ---------------------------------------------------------------------------
void testTrustBoundary(ksword_tests::Suite& s) {
    EvidenceEnvelope wrapperOne;
    wrapperOne.source.collectorId = "ui.processTable";
    wrapperOne.source.sourceGroup = "r0.process.enum";
    wrapperOne.source.origin = SourceOrigin::kLiveKernel;
    wrapperOne.outcome.status = CollectionStatus::kPartial;  // Same incomplete data

    EvidenceEnvelope wrapperTwo = wrapperOne;
    wrapperTwo.source.collectorId = "api.processList";  // Second-level wrapper for the same underlying collector.

    EvidenceEnvelope thirdWrapper = wrapperOne;
    thirdWrapper.source.collectorId = "cli.processDump";

    const TrustStatement kStatement = buildTrustStatement({wrapperOne, wrapperTwo, thirdWrapper});
    s.expect(kStatement.viewCount == 3U && kStatement.independentSourceGroupCount == 1U,
             L"X-01 three wrappers over one collector count as one independent source group");
    s.expect(kStatement.allFromSameLiveKernel && kStatement.anyIncompleteCoverage,
             L"F-11 the trust statement records same-kernel origin and incomplete coverage");

    bool hasAbsenceLimit = false;
    bool hasSingleGroupLimit = false;
    for (const std::string& key : kStatement.limitationKeys) {
        if (key == "trust.limitation.noAbsenceProof") {
            hasAbsenceLimit = true;
        }
        if (key == "trust.limitation.singleSourceGroup") {
            hasSingleGroupLimit = true;
        }
    }
    s.expect(hasAbsenceLimit && hasSingleGroupLimit,
             L"F-11 agreement across same-source views is reported as a limitation, never as safety");

    EvidenceEnvelope independent = wrapperOne;
    independent.source.collectorId = "r3.toolhelp";
    independent.source.sourceGroup = "r3.toolhelp.snapshot";
    independent.source.origin = SourceOrigin::kLiveUserMode;
    const TrustStatement kMixed = buildTrustStatement({wrapperOne, independent});
    s.expect(kMixed.independentSourceGroupCount == 2U && !kMixed.allFromSameLiveKernel,
             L"X-01 a genuinely different source raises the independent group count");

    // F-11: All three source types must remain visible. When allFromSameLiveKernel is false, the remaining
    // half (whether external files or offline samples) must not disappear entirely from the structure.
    EvidenceEnvelope liveKernel;
    liveKernel.source.collectorId = "r0.module.enum";
    liveKernel.source.sourceGroup = "r0.module.enum";
    liveKernel.source.origin = SourceOrigin::kLiveKernel;
    liveKernel.outcome = CollectionOutcome::success();
    liveKernel.coverage.totalKnown = OptionalU64::of(0U);

    EvidenceEnvelope offline = liveKernel;
    offline.source.collectorId = "session.replay";
    offline.source.sourceGroup = "session.replay";
    offline.source.origin = SourceOrigin::kOfflineSample;

    EvidenceEnvelope external = liveKernel;
    external.source.collectorId = "disk.image";
    external.source.sourceGroup = "disk.image";
    external.source.origin = SourceOrigin::kExternalFile;

    const TrustStatement kOfflineMix = buildTrustStatement({offline, liveKernel});
    s.expect(kOfflineMix.offlineSampleViewCount == 1U && kOfflineMix.liveKernelViewCount == 1U &&
                 kOfflineMix.distinctOriginCount == 2U && !kOfflineMix.allFromSameLiveKernel,
             L"F-11 a half-offline conclusion counts both origins instead of hiding one");
    s.expect(kOfflineMix.originViewCount(SourceOrigin::kOfflineSample) == 1U &&
                 kOfflineMix.originViewCount(SourceOrigin::kExternalFile) == 0U,
             L"F-11 per-origin counts are readable by kind");

    bool hasOfflineLimit = false;
    for (const std::string& key : kOfflineMix.limitationKeys) {
        if (key == "trust.limitation.offlineSample") {
            hasOfflineLimit = true;
        }
    }
    s.expect(hasOfflineLimit,
             L"F-11 mixing an offline sample into a conclusion is stated as a limitation");

    const TrustStatement kExternalMix = buildTrustStatement({external, liveKernel});
    bool hasExternalLimit = false;
    for (const std::string& key : kExternalMix.limitationKeys) {
        if (key == "trust.limitation.externalFile") {
            hasExternalLimit = true;
        }
    }
    s.expect(hasExternalLimit && kExternalMix.externalFileViewCount == 1U,
             L"F-11 an external file view is stated as a limitation of its own");

    const TrustStatement kKernelOnly = buildTrustStatement({liveKernel});
    bool kernelOnlyClaimsOffline = false;
    for (const std::string& key : kKernelOnly.limitationKeys) {
        if (key == "trust.limitation.offlineSample" || key == "trust.limitation.externalFile") {
            kernelOnlyClaimsOffline = true;
        }
    }
    s.expect(!kernelOnlyClaimsOffline && kKernelOnly.liveKernelViewCount == 1U &&
                 kKernelOnly.distinctOriginCount == 1U,
             L"F-11 a purely live-kernel statement does not invent offline limitations");

    // F-04: Source category and collection method are exported as independent names.
    s.expect(std::string(sourceOriginName(SourceOrigin::kExternalFile)) == "ExternalFile" &&
                 std::string(sourceOriginName(SourceOrigin::kOfflineSample)) == "OfflineSample" &&
                 std::string(sourceOriginName(SourceOrigin::kLiveKernel)) == "LiveKernel" &&
                 std::string(sourceOriginName(SourceOrigin::kLiveUserMode)) == "LiveUserMode" &&
                 std::string(sourceOriginName(SourceOrigin::kUnknown)) == "Unknown",
             L"F-11 all five source origins export as distinct names");
    s.expect(std::string(captureModeName(CaptureMode::kUnknown)) == "Unknown" &&
                 std::string(captureModeName(CaptureMode::kSnapshot)) == "Snapshot" &&
                 std::string(captureModeName(CaptureMode::kStreaming)) == "Streaming" &&
                 std::string(captureModeName(CaptureMode::kReplay)) == "Replay",
             L"F-04 all four capture modes export as distinct names");
}

// ---------------------------------------------------------------------------
// F-10 / M-10: Cancellation, concurrency, and scan budget
// ---------------------------------------------------------------------------
void testTaskAndBudget(ksword_tests::Suite& s) {
    LatestRequestGate gate;
    const std::uint64_t kRequestA = gate.begin();
    const std::uint64_t kRequestB = gate.begin();
    s.expect(!gate.accepts(kRequestA) && gate.accepts(kRequestB),
             L"F-10 a late result from request A cannot overwrite request B");
    gate.cancelCurrent();
    s.expect(!gate.accepts(kRequestB), L"F-10 cancelling invalidates the in-flight request immediately");

    s.expect(!taskStateIsTerminal(TaskState::kCancelling) && taskStateIsTerminal(TaskState::kCancelled),
             L"F-10 cancelling is distinct from cancelled so the UI cannot fake a finished cleanup");
    s.expect(!taskStateIsTerminal(TaskState::kPending) && !taskStateIsTerminal(TaskState::kRunning) &&
                 taskStateIsTerminal(TaskState::kCompleted) && taskStateIsTerminal(TaskState::kFailed),
             L"F-10 only cancelled/completed/failed are terminal states");
    s.expect(std::string(taskStateName(TaskState::kPending)) == "Pending" &&
                 std::string(taskStateName(TaskState::kRunning)) == "Running" &&
                 std::string(taskStateName(TaskState::kCancelling)) == "Cancelling" &&
                 std::string(taskStateName(TaskState::kCancelled)) == "Cancelled" &&
                 std::string(taskStateName(TaskState::kCompleted)) == "Completed" &&
                 std::string(taskStateName(TaskState::kFailed)) == "Failed",
             L"F-10 all six task states export as distinct names");

    const AddressRange kApproved{0x10000ULL, 0x10000ULL};
    s.expect(validateRange({0x10000ULL, 0x1000ULL}, kApproved) == RangeValidation::kOk,
             L"M-10 an in-range request is accepted");
    s.expect(validateRange({0x10000ULL, 0U}, kApproved) == RangeValidation::kEmptyRange,
             L"M-10 an empty range is rejected");
    s.expect(validateRange({0xFFFFFFFFFFFFFFFFULL, 0x10ULL}, kApproved) == RangeValidation::kOverflow,
             L"M-10 a wrapping range is rejected");
    s.expect(validateRange({0x8000ULL, 0x1000ULL}, kApproved) == RangeValidation::kExceedsApproved,
             L"M-10 a request below the approved window is rejected");
    s.expect(validateRange({0x1FFF0ULL, 0x1000ULL}, kApproved) == RangeValidation::kExceedsApproved,
             L"M-10 a request past the approved window is rejected");

    // M-10: Reversed range. Under the (begin, length) expression, the caller calculating the
    // length would wrap a reversed range; endpoint entry must pass the 'swapped' state as-is.
    s.expect(validateRange(AddressRange::fromBeginEnd(0x20000ULL, 0x10000ULL), kApproved) ==
                 RangeValidation::kReversed,
             L"M-10 an end below begin is reported as reversed, not as an empty or wrapping range");
    s.expect(AddressRange::fromBeginEnd(0x10000ULL, 0x11000ULL).length == 0x1000ULL &&
                 validateRange(AddressRange::fromBeginEnd(0x10000ULL, 0x11000ULL), kApproved) ==
                     RangeValidation::kOk,
             L"M-10 a well-ordered endpoint pair becomes the matching length and validates");
    s.expect(validateRange(AddressRange::fromBeginEnd(0x10000ULL, 0x10000ULL), kApproved) ==
                 RangeValidation::kEmptyRange,
             L"M-10 equal endpoints are an empty range, not a reversed one");
    s.expect(std::string(rangeValidationName(RangeValidation::kReversed)) == "Reversed",
             L"M-10 the reversed verdict has its own exported name");

    // M-10: Unbounded approved range != allowing scan of the full 64-bit address space.
    const AddressRange kUnbounded{};
    s.expect(validateRange({0ULL, (std::numeric_limits<std::uint64_t>::max)()}, kUnbounded) ==
                 RangeValidation::kExceedsApproved,
             L"M-10 scanning the whole 64-bit space is refused even without an approved window");
    s.expect(validateRange({0x10000ULL, 0x1000ULL}, kUnbounded) == RangeValidation::kOk,
             L"M-10 an ordinary request without an approved window is still accepted");

    ScanBudget budget;
    budget.maxBytes = OptionalU64::of(4096U);
    budget.maxDurationNanos = OptionalU64::of(1000000ULL);
    s.expect(budget.bounded(), L"M-10 a production scan budget is bounded");

    ScanProgress progress;
    progress.bytesDone = 2048U;
    s.expect(evaluateBudget(budget, progress) == BudgetStop::kContinue,
             L"M-10 a scan under budget keeps going");
    progress.bytesDone = 4096U;
    const BudgetStop kStop = evaluateBudget(budget, progress);
    s.expect(kStop == BudgetStop::kBytesExhausted, L"M-10 the byte cap stops the scan");

    CoverageAccount coverage;
    coverage.succeeded = 4096U;
    applyStopToCoverage(kStop, budget, coverage);
    const CollectionOutcome kOutcome = outcomeForStop(kStop);
    s.expect(kOutcome.status == CollectionStatus::kPartial && coverage.limitHit && !coverage.fullyCovered(),
             L"M-10 a capped scan reports partial results and keeps what it finished");

    ScanProgress cancelled;
    cancelled.bytesDone = 1U;
    cancelled.cancelRequested = true;
    s.expect(evaluateBudget(budget, cancelled) == BudgetStop::kCancelled,
             L"M-10 cancel takes priority over the remaining budget");

    // F-06: Cancellation is not 'limit hit'. Recording it as limitHit with limit=unset causes the account output
    // to show 'limit-hit:unknown'—a user-initiated cancellation is misreported as hitting an unknown limit.
    CoverageAccount cancelCoverage;
    cancelCoverage.succeeded = 1U;
    applyStopToCoverage(BudgetStop::kCancelled, budget, cancelCoverage);
    s.expect(cancelCoverage.cancelled && !cancelCoverage.limitHit,
             L"F-06 a user cancellation is recorded as cancelled, not as a limit hit");
    s.expect(cancelCoverage.describeRemaining() == "cancelled",
             L"F-06 the account names cancellation as the stop reason");
    s.expect(cancelCoverage.describeRemaining().rfind("limit-hit:", 0U) != 0U,
             L"F-06 a cancellation never reports itself as limit-hit:unknown");
    s.expect(!cancelCoverage.fullyCovered(),
             L"F-06 a cancelled scan is never fully covered");
    s.expect(outcomeForStop(BudgetStop::kCancelled).status == CollectionStatus::kPartial &&
                 outcomeForStop(BudgetStop::kCancelled).message == "cancelled",
             L"F-06 a cancelled scan keeps its partial results and says why");

    // M-10: The three limits (pages, entries, time) apply independently.
    ScanBudget pageBudget;
    pageBudget.maxPages = OptionalU64::of(2U);
    ScanProgress pagesDone;
    pagesDone.pagesDone = 2U;
    ScanBudget itemBudget;
    itemBudget.maxItems = OptionalU64::of(5U);
    ScanProgress itemsDone;
    itemsDone.itemsDone = 5U;
    ScanBudget timeBudget;
    timeBudget.maxDurationNanos = OptionalU64::of(1000U);
    ScanProgress timeDone;
    timeDone.elapsedNanos = 1000U;
    s.expect(evaluateBudget(pageBudget, pagesDone) == BudgetStop::kPagesExhausted &&
                 evaluateBudget(itemBudget, itemsDone) == BudgetStop::kItemsExhausted &&
                 evaluateBudget(timeBudget, timeDone) == BudgetStop::kTimeExhausted,
             L"M-10 the page, item and time caps each stop the scan on their own");
    s.expect(outcomeForStop(BudgetStop::kPagesExhausted).message == "budget:pages" &&
                 outcomeForStop(BudgetStop::kItemsExhausted).message == "budget:items" &&
                 outcomeForStop(BudgetStop::kTimeExhausted).message == "budget:time",
             L"M-10 each cap records which budget stopped the scan");
    s.expect(std::string(budgetStopName(BudgetStop::kPagesExhausted)) == "PagesExhausted" &&
                 std::string(budgetStopName(BudgetStop::kItemsExhausted)) == "ItemsExhausted" &&
                 std::string(budgetStopName(BudgetStop::kTimeExhausted)) == "TimeExhausted" &&
                 std::string(budgetStopName(BudgetStop::kContinue)) == "Continue",
             L"M-10 every budget stop reason exports as a distinct name");

    CoverageAccount pageCoverage;
    applyStopToCoverage(BudgetStop::kPagesExhausted, pageBudget, pageCoverage);
    s.expect(pageCoverage.limitHit && !pageCoverage.cancelled &&
                 pageCoverage.describeRemaining() == "limit-hit:2",
             L"M-10 a page-cap stop records the cap that fired");

    ScanBudget unbounded2;
    s.expect(!unbounded2.bounded(),
             L"M-10 a budget with no cap at all reports itself as unbounded");
}

// ---------------------------------------------------------------------------
// F-09 / F-12: Sessions and sites are separated; page linkage applies.
// ---------------------------------------------------------------------------
void testSessionAndNavigation(ksword_tests::Suite& s) {
    s.expect(decideRefresh(DataOrigin::kSession, 5U, 9U, true) ==
                 RefreshDecision::kRejectSessionIsImmutable,
             L"F-09 a saved session is never overwritten by a background refresh");
    s.expect(decideRefresh(DataOrigin::kLive, 5U, 9U, true) == RefreshDecision::kApply,
             L"F-09 a live view accepts a newer snapshot");
    s.expect(decideRefresh(DataOrigin::kLive, 9U, 5U, true) == RefreshDecision::kRejectStaleSnapshot,
             L"F-09 a stale snapshot cannot replace a newer one");
    s.expect(decideRefresh(DataOrigin::kLive, 5U, 9U, false) == RefreshDecision::kRejectNotLatestRequest,
             L"F-10 a result from a superseded request is dropped");

    ProcessInstanceId saved;
    saved.bootId = "boot-A";
    saved.pid = OptionalU64::of(4321U);
    saved.createTime100ns = OptionalU64::of(133000000000000000ULL);
    saved.imageName = "target.exe";

    LiveResolution gone;
    gone.found = false;
    s.expect(resolveProcessNavigation(saved, gone) == LiveNavigationDecision::kRejectObjectExited,
             L"F-09 an exited object reports as exited");

    LiveResolution reused;
    reused.found = true;
    reused.liveProcess = saved;
    reused.liveProcess.createTime100ns = OptionalU64::of(133000000999999999ULL);
    s.expect(resolveProcessNavigation(saved, reused) == LiveNavigationDecision::kRejectIdentityMismatch,
             L"F-09 a reused PID is refused instead of handing the action to a new process");

    LiveResolution unverifiable;
    unverifiable.found = true;
    unverifiable.liveProcess = saved;
    unverifiable.liveProcess.createTime100ns = OptionalU64::unset();
    s.expect(resolveProcessNavigation(saved, unverifiable) ==
                 LiveNavigationDecision::kRejectIdentityUnverifiable,
             L"F-09 an unverifiable identity is neither allowed nor called a mismatch");

    LiveResolution same;
    same.found = true;
    same.liveProcess = saved;
    s.expect(resolveProcessNavigation(saved, same) == LiveNavigationDecision::kAllow,
             L"F-09 a confirmed identity still navigates");

    NavigationRequest request;
    request.page = NavigationPage::kMemory;
    request.object = makeProcessRef(saved, "ev-001");
    request.evidenceId = "ev-001";
    request.anchor = "0x00007FFE12340000";
    s.expect(request.object.navigable() && !request.object.key.empty(),
             L"F-12 a strong identity produces a navigable reference");
    s.expect(decideNavigation(request, true, true, true) == NavigationOutcome::kDelivered,
             L"F-12 an available page with the object present receives the request");
    s.expect(decideNavigation(request, false, true, true) == NavigationOutcome::kTargetPageMissing,
             L"F-12 a closed target page is reported, not silently retargeted");
    s.expect(decideNavigation(request, true, false, true) == NavigationOutcome::kObjectNotPresent,
             L"F-12 a missing object is explained instead of jumping to the first row");
    s.expect(decideNavigation(request, true, true, false) == NavigationOutcome::kEvidenceNotSaved,
             L"M-08 evidence absent from an offline session is reported as not saved");

    NavigationRequest weak = request;
    ProcessInstanceId weakIdentity = saved;
    weakIdentity.createTime100ns = OptionalU64::unset();
    weak.object = makeProcessRef(weakIdentity, "ev-002");
    s.expect(decideNavigation(weak, true, true, true) == NavigationOutcome::kIdentityUnusable,
             L"F-12 an identity too weak to be sure refuses to navigate");

    // F-12: Identity threshold is unrelated to requireExactMatch. requireExactMatch specifies anchor precision, not
    // whether to validate identity. Treating it as a switch allows weak identities to bypass validation when set to false.
    NavigationRequest weakInexact = weak;
    weakInexact.requireExactMatch = false;
    s.expect(!weakInexact.object.navigable(),
             L"F-12 the weak reference really is non-navigable");
    s.expect(decideNavigation(weakInexact, true, true, true) == NavigationOutcome::kIdentityUnusable,
             L"F-12 relaxing the anchor requirement does not relax the identity gate");

    // F-12: Navigation without an evidence ID cannot return to the original evidence; it must not be counted as delivered.
    NavigationRequest noEvidenceId = request;
    noEvidenceId.evidenceId.clear();
    s.expect(decideNavigation(noEvidenceId, true, true, true) == NavigationOutcome::kEvidenceIdMissing,
             L"F-12 a navigation request without an evidence id is refused, not delivered");
    s.expect(decideNavigation(noEvidenceId, true, true, false) == NavigationOutcome::kEvidenceIdMissing,
             L"F-12 a missing evidence id is reported even when the session has nothing saved");
    s.expect(std::string(navigationOutcomeName(NavigationOutcome::kEvidenceIdMissing)) ==
                 "EvidenceIdMissing",
             L"F-12 the missing-evidence-id verdict has its own exported name");
}

// ---------------------------------------------------------------------------
// F-05: Driver call result -> normalization layer for collection state (production implementation in ArkDriverEvidence.h)
// ---------------------------------------------------------------------------
void testDriverOutcomeNormalisation(ksword_tests::Suite& s) {
    using ksword::ark::DriverCallShape;
    using ksword::ark::IoResult;
    using ksword::ark::toCollectionOutcome;

    IoResult ok;
    ok.ok = true;
    ok.bytesReturned = 0U;  // Success with zero bytes: correct empty set.
    const CollectionOutcome kEmptySuccess = toCollectionOutcome(ok);
    s.expect(kEmptySuccess.status == CollectionStatus::kSuccess,
             L"F-05 a successful call returning nothing is a correct empty set");

    DriverCallShape truncatedShape;
    truncatedShape.partial = true;
    s.expect(toCollectionOutcome(ok, truncatedShape).status == CollectionStatus::kPartial,
             L"F-05 a protocol PARTIAL/TRUNCATED flag downgrades success to partial");

    IoResult denied;
    denied.ok = false;
    denied.win32Error = ERROR_ACCESS_DENIED;
    denied.message = "DeviceIoControl failed";
    const CollectionOutcome kDeniedOutcome = toCollectionOutcome(denied);
    s.expect(kDeniedOutcome.status == CollectionStatus::kAccessDenied &&
                 kDeniedOutcome.nativeCodeDomain == "WIN32" &&
                 kDeniedOutcome.nativeCode.present &&
                 kDeniedOutcome.nativeCode.value == ERROR_ACCESS_DENIED &&
                 kDeniedOutcome.message == "DeviceIoControl failed",
             L"F-05 access denied keeps its raw Win32 code and message");

    IoResult timedOut;
    timedOut.ok = false;
    timedOut.win32Error = WAIT_TIMEOUT;
    s.expect(toCollectionOutcome(timedOut).status == CollectionStatus::kTimeout,
             L"F-05 a timeout is its own state, not a generic error");

    // Old drivers return ERROR_INVALID_FUNCTION for unknown IOCTLs: this indicates unsupported, not an error.
    IoResult unknownIoctl;
    unknownIoctl.ok = false;
    unknownIoctl.win32Error = ERROR_INVALID_FUNCTION;
    s.expect(toCollectionOutcome(unknownIoctl).status == CollectionStatus::kUnsupported,
             L"Q-04 an old driver rejecting a new IOCTL degrades to unsupported, not error");

    DriverCallShape unsupportedShape;
    unsupportedShape.unsupported = true;
    IoResult okButUnsupported;
    okButUnsupported.ok = true;
    s.expect(toCollectionOutcome(okButUnsupported, unsupportedShape).status ==
                 CollectionStatus::kUnsupported,
             L"F-05 a protocol UNSUPPORTED flag wins over a successful DeviceIoControl");

    IoResult ntFailure;
    ntFailure.ok = false;
    ntFailure.ntStatus = static_cast<long>(0xC0000022L);  // STATUS_ACCESS_DENIED
    ntFailure.win32Error = ERROR_ACCESS_DENIED;
    const CollectionOutcome kNtOutcome = toCollectionOutcome(ntFailure);
    s.expect(kNtOutcome.nativeCodeDomain == "NTSTATUS" &&
                 kNtOutcome.nativeCode.present &&
                 kNtOutcome.nativeCode.value == 0xC0000022ULL,
             L"F-05 an NTSTATUS from R0 is preserved without sign loss");

    // ------------------------------------------------------------------
    // F-05: IOCTL round-trip succeeds but the R0-side operation fails — the most common failure mode in the full stack.
    // ok=true and win32Error=ERROR_SUCCESS; failures are recorded only in the response packet's NTSTATUS.
    // Previously, only io.ok was checked, causing this path to always be treated as Success; after
    // wrapping in an envelope, deriveConclusion(false) directly returns 'No differences found'.
    // ------------------------------------------------------------------
    IoResult r0Denied;
    r0Denied.ok = true;
    r0Denied.win32Error = ERROR_SUCCESS;
    r0Denied.ntStatus = asNtStatus(0xC0000022U);  // STATUS_ACCESS_DENIED
    const CollectionOutcome kR0DeniedOutcome = toCollectionOutcome(r0Denied);
    s.expect(kR0DeniedOutcome.status == CollectionStatus::kAccessDenied,
             L"F-05 a successful IOCTL carrying STATUS_ACCESS_DENIED is an R0 failure, not a success");
    s.expect(kR0DeniedOutcome.nativeCodeDomain == "NTSTATUS" &&
                 kR0DeniedOutcome.nativeCode.present &&
                 kR0DeniedOutcome.nativeCode.value == 0xC0000022ULL,
             L"F-05 the R0 NTSTATUS stays the raw code of record");
    EvidenceEnvelope r0DeniedEnvelope;
    r0DeniedEnvelope.outcome = kR0DeniedOutcome;
    s.expect(r0DeniedEnvelope.deriveConclusion(false) == AnalysisConclusion::kNoEvidence,
             L"F-05 an R0 access denial yields no evidence, never no-difference-observed");

    IoResult r0Missing;
    r0Missing.ok = true;
    r0Missing.ntStatus = asNtStatus(0xC0000034U);  // STATUS_OBJECT_NAME_NOT_FOUND
    s.expect(toCollectionOutcome(r0Missing).status == CollectionStatus::kUnsupported,
             L"F-05 STATUS_OBJECT_NAME_NOT_FOUND from R0 degrades to unsupported, not success");

    IoResult r0NotSupported;
    r0NotSupported.ok = true;
    r0NotSupported.ntStatus = asNtStatus(0xC00000BBU);  // STATUS_NOT_SUPPORTED
    s.expect(toCollectionOutcome(r0NotSupported).status == CollectionStatus::kUnsupported,
             L"F-05 STATUS_NOT_SUPPORTED from R0 is unsupported, not a generic error");

    IoResult r0Timeout;
    r0Timeout.ok = true;
    r0Timeout.ntStatus = asNtStatus(0x00000102U);  // STATUS_TIMEOUT
    s.expect(toCollectionOutcome(r0Timeout).status == CollectionStatus::kTimeout,
             L"F-05 STATUS_TIMEOUT is a timeout even though its severity bits say success");

    IoResult r0Generic;
    r0Generic.ok = true;
    r0Generic.ntStatus = asNtStatus(0xC0000001U);  // STATUS_UNSUCCESSFUL
    s.expect(toCollectionOutcome(r0Generic).status == CollectionStatus::kError,
             L"F-05 any other NT_ERROR from R0 lands in Error rather than Success");

    // NT_WARNING (0x8xxxxxxx) means 'data was retrieved but not fully'. It is not a failure. Writing
    // `ntStatus < 0` would treat it as an error, causing the partially retrieved observation to be lost.
    IoResult r0Overflow;
    r0Overflow.ok = true;
    r0Overflow.ntStatus = asNtStatus(0x80000005U);  // STATUS_BUFFER_OVERFLOW
    const CollectionOutcome kOverflowOutcome = toCollectionOutcome(r0Overflow);
    s.expect(kOverflowOutcome.status == CollectionStatus::kPartial,
             L"F-05 STATUS_BUFFER_OVERFLOW is partial data, neither success nor error");
    s.expect(statusCarriesObservation(kOverflowOutcome.status),
             L"F-05 the partial data from a warning status still counts as an observation");

    // NT_SUCCESS / NT_INFORMATION does not alter the judgment.
    IoResult r0Informational;
    r0Informational.ok = true;
    r0Informational.ntStatus = asNtStatus(0x40000000U);  // NT_INFORMATION segment
    s.expect(toCollectionOutcome(r0Informational).status == CollectionStatus::kSuccess,
             L"F-05 an informational NTSTATUS leaves a successful collection successful");

    IoResult r0Zero;
    r0Zero.ok = true;
    r0Zero.ntStatus = 0;
    s.expect(toCollectionOutcome(r0Zero).status == CollectionStatus::kSuccess &&
                 !toCollectionOutcome(r0Zero).nativeCode.present,
             L"F-05 STATUS_SUCCESS stays a success and writes no native code");

    // Some protocols treat lastStatus as a purely informational flag; such protocols must explicitly allow exiting this determination.
    DriverCallShape informationalStatus;
    informationalStatus.ntStatusIsAuthoritative = false;
    s.expect(toCollectionOutcome(r0Denied, informationalStatus).status == CollectionStatus::kSuccess,
             L"F-05 a protocol may opt out of NTSTATUS triage explicitly, never by default");

    // The unsupported flag still takes precedence over the NTSTATUS triage.
    s.expect(toCollectionOutcome(r0Denied, unsupportedShape).status == CollectionStatus::kUnsupported,
             L"F-05 a protocol UNSUPPORTED flag still wins over the NTSTATUS triage");

    const CollectionOutcome kAbsent = ksword::ark::driverNotCollected("driver not loaded");
    s.expect(kAbsent.status == CollectionStatus::kNotCollected &&
                 kAbsent.message == "driver not loaded",
             L"F-05 never-started collection is distinct from an empty success");

    EvidenceEnvelope envelope;
    envelope.outcome = kAbsent;
    s.expect(envelope.deriveConclusion(false) == AnalysisConclusion::kNoEvidence,
             L"F-05 an unloaded driver produces no evidence, never a normal verdict");

    // X-01: sourceGroup must be filled according to the underlying source; two layers of wrapping share one group.
    const auto kWrapperSource = ksword::ark::makeDriverSource(
        "ui.driverTable", 1U, "r0.module.enum", "IOCTL_KSWORD_ARK_QUERY_MODULES");
    const auto kCoreSource = ksword::ark::makeDriverSource(
        "r0.module.enum", 1U, "r0.module.enum", "IOCTL_KSWORD_ARK_QUERY_MODULES");
    EvidenceEnvelope wrapper;
    wrapper.source = kWrapperSource;
    wrapper.outcome = CollectionOutcome::success();
    EvidenceEnvelope core;
    core.source = kCoreSource;
    core.outcome = CollectionOutcome::success();
    s.expect(buildTrustStatement({wrapper, core}).independentSourceGroupCount == 1U,
             L"X-01 the driver source helper keeps two wrappers in one source group");
}

} // namespace

int runEvidenceContractTests() {
    ksword_tests::Suite suite(L"F evidence contract");
    testLosslessValues(suite);
    testJsonRoundTrip(suite);
    testObjectIdentity(suite);
    testSourceAndTime(suite);
    testStatusAndCoverage(suite);
    testTrustBoundary(suite);
    testTaskAndBudget(suite);
    testSessionAndNavigation(suite);
    testDriverOutcomeNormalisation(suite);
    suite.report();
    return suite.failures();
}
