// Offline automated tests for the T module (unified timeline and investigation session).
//
// Covered test IDs: T-01 T-02 T-03 T-04 T-05 T-06 T-08 T-09 T-10 T-12.
// Not covered: T-07 (independent cursor/lease, requires real environment testing), T-11 (controlled load
// helper, requires real process/file/registry/loopback operations which this layer cannot generate).
//
// Assertion principles (Q-01 / Q-02):
//   * Expectation values must be manually written. When verifying "sorting correctness", provide manually written expected
//     recordId sequences; do not compare the sorting function's output against itself. When verifying "time difference correctness",
//     hard-code manually calculated values like -50 or 10000; do not call the tested difference function to generate expectations.
//   * Input for bad-file cases is modified byte-by-byte by the test itself (truncation, payload replacement,
//     trailer count alteration); the production parsing path has no branches that read the test's ground truth.
//   * Each "must-reject" criterion has a corresponding counter-example assertion: default accounts are incomplete, bare PIDs do
//     not create SameProcess edges, unknown versions do not use the legacy parser, and weak identities do not receive confirmation.

#include "TestSupport.h"

#include "../../../shared/evidence/TimelineCore.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace ksword::evidence;

constexpr const char* kBoot1 = "boot-T-1";
constexpr const char* kBoot2 = "boot-T-2";

// Manually written time baseline: FILETIME magnitude around 2022-08-01, all calculated in decimal by hand.
constexpr std::uint64_t kT0 = 133000000000000000ULL;

BoundsPolicy makeBounds(std::uint64_t maxEvents, RetentionPolicy policy) {
    BoundsPolicy bounds;
    bounds.maxEventsInMemory = OptionalU64::of(maxEvents);
    bounds.policy = policy;
    bounds.declaredBeforeCollection = true;  // T-08: Declared before collection
    return bounds;
}

// T-08: A session must have an upper bound that can be truly converted into a count to allow collection to start, so the
// pattern 'declared but completely unbounded' no longer exists. Here, a memory upper bound far higher than any use case count
// (10000) is provided; the bound therefore never triggers, while satisfying the precondition that 'memory has an upper bound'.
BoundsPolicy makeRoomyDeclaredBounds() {
    BoundsPolicy bounds;
    bounds.maxEventsInMemory = OptionalU64::of(10000ULL);
    bounds.policy = RetentionPolicy::kStopOnLimit;
    bounds.declaredBeforeCollection = true;
    return bounds;
}

SessionManifest makeManifest() {
    SessionManifest manifest;
    manifest.sessionId = "session-T-1";
    manifest.machineId = "machine-T";
    manifest.bootId = kBoot1;
    manifest.displayName = "T timeline";
    manifest.window.machineId = "machine-T";
    manifest.window.bootId = kBoot1;
    manifest.window.sessionId = "session-T-1";
    manifest.window.mode = CaptureMode::kStreaming;
    manifest.window.startUtc100ns = OptionalU64::of(kT0);
    manifest.window.endUtc100ns = OptionalU64::of(kT0 + 1000000ULL);
    manifest.queryRangeBegin100ns = OptionalU64::of(kT0);
    manifest.queryRangeEnd100ns = OptionalU64::of(kT0 + 1000000ULL);
    return manifest;
}

// T-06: "Session equals full system activity" requires positive evidence: at least one collector capability must
// be declared, and every declared collector must have actually succeeded. A bare manifest declaring no
// capabilities is never considered a complete collection; this is why the following two manifests are separated.
CollectorCapability makeHealthyCapability() {
    CollectorCapability capability;
    capability.collectorId = "etw.kernel";
    capability.collectorVersion = 3U;
    capability.sourceGroup = "etw.kernel";
    capability.origin = SourceOrigin::kLiveKernel;
    capability.declaredCategories.push_back(TimelineEventCategory::kProcess);
    capability.declaredCategories.push_back(TimelineEventCategory::kFile);
    capability.availability = CollectionOutcome::success();
    return capability;
}

SessionManifest makeManifestWithHealthyCollector() {
    SessionManifest manifest = makeManifest();
    manifest.capabilities.push_back(makeHealthyCapability());
    return manifest;
}

EventTimeStamp makeTime(const char* bootId,
                        std::uint64_t sourceTime,
                        std::uint64_t receiveTime,
                        TimeResolution resolution) {
    EventTimeStamp time;
    time.bootId = bootId;
    time.sourceTime100ns = OptionalU64::of(sourceTime);
    time.receiveTime100ns = OptionalU64::of(receiveTime);
    time.sourceResolution = resolution;
    return time;
}

TimelineEvent makeEvent(const char* recordId,
                        const char* providerId,
                        TimelineEventCategory category,
                        std::uint64_t pid,
                        const EventTimeStamp& time) {
    TimelineEvent event;
    event.recordId = recordId;
    event.providerId = providerId;
    event.sourceGroup = "etw.kernel";
    event.eventId = 1U;
    event.eventVersion = 1U;
    event.category = category;
    event.pid = OptionalU64::of(pid);
    event.time = time;
    event.parseOutcome = EventParseOutcome::kParsed;
    event.parserId = "test.parser";
    event.parserVersion = 1U;
    event.rawFields.emplace_back("Field", std::string(recordId) + "-value");
    event.rawPayloadHex = "00112233";
    return event;
}

// All six categories declare named sources; local counting starts from 0 so that totalLost() can safely return a definitive value.
void declareAllLossSources(LossLedger& ledger) {
    ledger.declareSource(LossCategory::kSourceDrop, "etw.EventsLost", true, false);
    ledger.declareSource(LossCategory::kRingOverwrite, "ring.OverwriteCount", true, false);
    ledger.declareSource(LossCategory::kQueueDiscard, "local.r3queue", false, false);
    ledger.declareSource(LossCategory::kParseFailure, "local.parser", false, false);
    ledger.declareSource(LossCategory::kFilteredOut, "local.collectionFilter", false, false);
    ledger.declareSource(LossCategory::kRetentionEvicted, "local.retention", false, false);
    ledger.setAbsolute(LossCategory::kSourceDrop, 0ULL);
    ledger.setAbsolute(LossCategory::kRingOverwrite, 0ULL);
}

std::vector<std::string> splitTextLines(const std::string& text) {
    std::vector<std::string> lines;
    std::size_t begin = 0;
    while (begin < text.size()) {
        const std::size_t kPos = text.find('\n', begin);
        if (kPos == std::string::npos) {
            lines.push_back(text.substr(begin));
            break;
        }
        lines.push_back(text.substr(begin, kPos - begin + 1U));  // Preserve newline characters.
        begin = kPos + 1U;
    }
    return lines;
}

// Out-of-bounds reads will crash the entire test suite, preventing any failure from being reported. Assertions must always use this element accessor.
// Returns a default object on out-of-bounds index, so failures manifest as 'wrong value' rather than process crashes.
template <typename Container>
const typename Container::value_type& elementOrDefault(const Container& items, std::size_t index) {
    static const typename Container::value_type kFallback{};
    return index < items.size() ? items[index] : kFallback;
}

bool containsKey(const std::vector<std::string>& keys, const char* needle) {
    return std::find(keys.begin(), keys.end(), std::string(needle)) != keys.end();
}

bool hasEdge(const std::vector<TimelineEdge>& edges, TimelineEdgeKind kind, const char* from, const char* to) {
    for (const TimelineEdge& edge : edges) {
        if (edge.kind == kind && edge.fromRecordId == from && edge.toRecordId == to) {
            return true;
        }
    }
    return false;
}

std::size_t countEdges(const std::vector<TimelineEdge>& edges, TimelineEdgeKind kind) {
    std::size_t count = 0;
    for (const TimelineEdge& edge : edges) {
        if (edge.kind == kind) {
            ++count;
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// T-01: Session lifecycle
// ---------------------------------------------------------------------------
void testSessionLifecycle(ksword_tests::Suite& s) {
    // Core separation: background recording continues when display is paused; only "stop collection" halts the background.
    s.expect(sessionAcceptsNewEvents(SessionState::kCollecting),
             L"T-01 Collecting records events");
    s.expect(sessionAcceptsNewEvents(SessionState::kDisplayPaused),
             L"T-01 DisplayPaused still records in background");
    s.expect(!sessionUpdatesDisplay(SessionState::kDisplayPaused),
             L"T-01 DisplayPaused freezes the display only");
    s.expect(!sessionAcceptsNewEvents(SessionState::kStopped),
             L"T-01 Stopped records nothing");
    s.expect(!sessionAcceptsNewEvents(SessionState::kSaved),
             L"T-01 Saved records nothing");
    s.expect(!sessionAcceptsNewEvents(SessionState::kNew),
             L"T-01 New records nothing before Start");

    const SessionTransition kStart = evaluateSessionTransition(SessionState::kNew, SessionAction::kStart);
    s.expect(kStart.allowed && kStart.nextState == SessionState::kCollecting,
             L"T-01 New + Start -> Collecting");
    s.expect(kStart.backgroundRecording && kStart.displayUpdating,
             L"T-01 Collecting records and displays");

    const SessionTransition kPause =
        evaluateSessionTransition(SessionState::kCollecting, SessionAction::kPauseDisplay);
    s.expect(kPause.allowed && kPause.nextState == SessionState::kDisplayPaused,
             L"T-01 Collecting + PauseDisplay -> DisplayPaused");
    s.expect(kPause.backgroundRecording,
             L"T-01 pausing the display does NOT stop background recording");
    s.expect(!kPause.displayUpdating, L"T-01 paused display stops updating");
    s.expect(kPause.bufferingNoticeKey == "timeline.session.buffering.recording-display-frozen",
             L"T-01 paused state exposes its buffering policy key");

    const SessionTransition kStopFromPause =
        evaluateSessionTransition(SessionState::kDisplayPaused, SessionAction::kStopCollection);
    s.expect(kStopFromPause.allowed && kStopFromPause.nextState == SessionState::kStopped,
             L"T-01 StopCollection is reachable from DisplayPaused");
    s.expect(!kStopFromPause.backgroundRecording,
             L"T-01 StopCollection is the only action that stops recording");

    const SessionTransition kBadResume =
        evaluateSessionTransition(SessionState::kCollecting, SessionAction::kResumeDisplay);
    s.expect(!kBadResume.allowed && kBadResume.nextState == SessionState::kCollecting,
             L"T-01 ResumeDisplay while collecting is rejected without changing state");
    s.expect(kBadResume.rejectionKey == "timeline.session.display-not-paused",
             L"T-01 rejected resume names its reason");
    s.expect(kBadResume.backgroundRecording,
             L"T-01 a rejected action still reports the true current recording state");

    const SessionTransition kRestart =
        evaluateSessionTransition(SessionState::kStopped, SessionAction::kStart);
    s.expect(!kRestart.allowed &&
                 kRestart.rejectionKey == "timeline.session.restart-requires-new-session",
             L"T-01 a stopped session cannot be restarted in place");
    const SessionTransition kSaveWhileCollecting =
        evaluateSessionTransition(SessionState::kCollecting, SessionAction::kSave);
    s.expect(!kSaveWhileCollecting.allowed &&
                 kSaveWhileCollecting.rejectionKey == "timeline.session.stop-before-save",
             L"T-01 saving requires a determined end boundary");
    s.expect(evaluateSessionTransition(SessionState::kStopped, SessionAction::kSave).allowed,
             L"T-01 Stopped + Save -> Saved");
    s.expect(evaluateSessionTransition(SessionState::kSaved, SessionAction::kReset).allowed,
             L"T-01 Saved + Reset -> New");
    s.expect(!evaluateSessionTransition(SessionState::kNew, SessionAction::kSave).allowed,
             L"T-01 New has nothing to save");

    // T-08 Precondition: If the upper limit was not declared prior to collection, the process must not start.
    SessionManifest manifest = makeManifest();
    BoundsPolicy undeclared;
    undeclared.maxEventsInMemory = OptionalU64::of(10ULL);
    undeclared.declaredBeforeCollection = false;
    TimelineSession undeclaredSession(manifest, undeclared);
    const SessionTransition kBlocked = undeclaredSession.apply(SessionAction::kStart);
    s.expect(!kBlocked.allowed && kBlocked.rejectionKey == "timeline.session.bounds-not-declared",
             L"T-08 collection cannot start before the bounds are declared");
    s.expect(undeclaredSession.state() == SessionState::kNew,
             L"T-08 a blocked Start leaves the session in New");

    // Real timeline: start -> record 1 entry -> pause display -> record another entry (must enter session) -> stop -> record again (must reject).
    TimelineSession session(manifest, makeRoomyDeclaredBounds());
    s.expect(session.apply(SessionAction::kStart).allowed, L"T-01 session starts");
    const IngestResult kFirst = session.ingest(
        makeEvent("e1", "P", TimelineEventCategory::kProcess, 100U,
                  makeTime(kBoot1, kT0 + 10ULL, kT0 + 20ULL, TimeResolution::kMicrosecond)));
    s.expect(kFirst.accepted && kFirst.assignedSequence == 1U,
             L"T-01 first event is accepted with sequence 1");
    s.expect(session.apply(SessionAction::kPauseDisplay).allowed, L"T-01 display pauses");
    const IngestResult kDuringPause = session.ingest(
        makeEvent("e2", "P", TimelineEventCategory::kFile, 100U,
                  makeTime(kBoot1, kT0 + 30ULL, kT0 + 40ULL, TimeResolution::kMicrosecond)));
    s.expect(kDuringPause.accepted,
             L"T-01 events collected while the display is paused still enter the session");
    s.expect(session.events().size() == 2U, L"T-01 two events retained after the pause");
    s.expect(session.apply(SessionAction::kStopCollection).allowed, L"T-01 collection stops");
    const IngestResult kAfterStop = session.ingest(
        makeEvent("e3", "P", TimelineEventCategory::kFile, 100U,
                  makeTime(kBoot1, kT0 + 50ULL, kT0 + 60ULL, TimeResolution::kMicrosecond)));
    s.expect(!kAfterStop.accepted &&
                 kAfterStop.reasonKey == "timeline.ingest.session-not-collecting",
             L"T-01 no new event is recorded after StopCollection");
    s.expect(session.events().size() == 2U,
             L"T-01 the stopped session still holds exactly the two collected events");
    s.expect(!kAfterStop.countedAsLoss,
             L"T-01 a post-stop event is not counted as a capture loss");
}

// ---------------------------------------------------------------------------
// T-02: Event envelope and parsing
// ---------------------------------------------------------------------------
EventSchemaRegistry makeRegistry() {
    EventSchemaRegistry registry;
    const struct {
        const char* provider;
        std::uint32_t eventId;
        const char* parserId;
        std::uint32_t parserVersion;
        TimelineEventCategory category;
        const char* requiredField;
    } kSpecs[] = {
        { "Kernel-Process",  1U, "parser.process",  11U, TimelineEventCategory::kProcess,  "ProcessId" },
        { "Kernel-Thread",   2U, "parser.thread",   12U, TimelineEventCategory::kThread,   "ThreadId" },
        { "Kernel-Image",    3U, "parser.image",    13U, TimelineEventCategory::kImage,    "ImageBase" },
        { "Kernel-File",     4U, "parser.file",     14U, TimelineEventCategory::kFile,     "FileName" },
        { "Kernel-Registry", 5U, "parser.registry", 15U, TimelineEventCategory::kRegistry, "KeyName" },
        { "Kernel-Network",  6U, "parser.network",  16U, TimelineEventCategory::kNetwork,  "RemotePort" },
    };
    for (const auto& spec : kSpecs) {
        EventSchema schema;
        schema.providerId = spec.provider;
        schema.eventId = spec.eventId;
        schema.version = 1U;
        schema.parserId = spec.parserId;
        schema.parserVersion = spec.parserVersion;
        schema.category = spec.category;
        schema.requiredFields.push_back(spec.requiredField);
        registry.add(schema);
    }
    // The 3rd version of the same event is also known: used to prove that requesting version 2 neither falls back to 1 nor jumps to 3.
    EventSchema v3;
    v3.providerId = "Kernel-File";
    v3.eventId = 4U;
    v3.version = 3U;
    v3.parserId = "parser.file.v3";
    v3.parserVersion = 34U;
    v3.category = TimelineEventCategory::kFile;
    v3.requiredFields.push_back("FileName");
    registry.add(v3);
    return registry;
}

void testEventEnvelope(ksword_tests::Suite& s) {
    const EventSchemaRegistry kRegistry = makeRegistry();
    s.expect(kRegistry.size() == 7U, L"T-02 registry holds the seven declared schemas");

    // One fixed sample per category; the expected parserVersion and category are hardcoded independently in the test.
    const struct {
        const char* provider;
        std::uint32_t eventId;
        const char* field;
        std::uint32_t expectedParserVersion;
        TimelineEventCategory expectedCategory;
    } kSamples[] = {
        { "Kernel-Process",  1U, "ProcessId",  11U, TimelineEventCategory::kProcess },
        { "Kernel-Thread",   2U, "ThreadId",   12U, TimelineEventCategory::kThread },
        { "Kernel-Image",    3U, "ImageBase",  13U, TimelineEventCategory::kImage },
        { "Kernel-File",     4U, "FileName",   14U, TimelineEventCategory::kFile },
        { "Kernel-Registry", 5U, "KeyName",    15U, TimelineEventCategory::kRegistry },
        { "Kernel-Network",  6U, "RemotePort", 16U, TimelineEventCategory::kNetwork },
    };
    std::size_t parsedCount = 0;
    for (const auto& sample : kSamples) {
        EventParseRequest request;
        request.providerId = sample.provider;
        request.eventId = sample.eventId;
        request.version = 1U;
        request.rawFields.emplace_back(sample.field, "sample");
        request.rawPayloadHex = "AABB";
        const EventParseReport kReport = parseEventPayload(kRegistry, request);
        if (kReport.outcome == EventParseOutcome::kParsed &&
            kReport.parserVersion == sample.expectedParserVersion &&
            kReport.category == sample.expectedCategory &&
            kReport.reasonKey == "timeline.parse.ok") {
            ++parsedCount;
        }
    }
    s.expect(parsedCount == 6U, L"T-02 all six declared categories parse with their own parser");

    // Unknown version: does not apply to either v1 or v3.
    EventParseRequest unknown;
    unknown.providerId = "Kernel-File";
    unknown.eventId = 4U;
    unknown.version = 2U;
    unknown.rawFields.emplace_back("FileName", "C:\\t\\a.txt");
    unknown.rawFields.emplace_back("NewFieldInV2", "42");
    unknown.rawPayloadHex = "DEADBEEF";
    const EventParseReport kUnknownReport = parseEventPayload(kRegistry, unknown);
    s.expect(kUnknownReport.outcome == EventParseOutcome::kUnparsedUnknownSchema,
             L"T-02 an unknown event version is kept as an unparsed record");
    s.expect(kUnknownReport.parserVersion == 0U,
             L"T-02 an unknown version never borrows another version's parser version");
    s.expect(kUnknownReport.parserId.empty(),
             L"T-02 an unknown version names no parser");
    s.expect(kUnknownReport.reasonKey == "timeline.parse.unknown-event-version",
             L"T-02 unknown version and unknown provider are distinguishable");

    EventParseRequest unknownProvider = unknown;
    unknownProvider.providerId = "Some-Third-Party";
    const EventParseReport kUnknownProviderReport = parseEventPayload(kRegistry, unknownProvider);
    s.expect(kUnknownProviderReport.reasonKey == "timeline.parse.unknown-provider-event",
             L"T-02 an unknown provider gets its own reason key");
    s.expect(kUnknownProviderReport.outcome == EventParseOutcome::kUnparsedUnknownSchema,
             L"T-02 an unknown provider is also an unparsed record, not a malformed one");

    // Missing required fields -> Malformed, and the parser identity is recorded (indicating 'this parser failed').
    EventParseRequest missing;
    missing.providerId = "Kernel-File";
    missing.eventId = 4U;
    missing.version = 1U;
    missing.rawFields.emplace_back("SomethingElse", "x");
    const EventParseReport kMissingReport = parseEventPayload(kRegistry, missing);
    s.expect(kMissingReport.outcome == EventParseOutcome::kMalformed,
             L"T-02 a missing required field is Malformed, not Parsed");
    s.expect(kMissingReport.missingRequiredFields.size() == 1U &&
                 kMissingReport.missingRequiredFields[0] == "FileName",
             L"T-02 the missing field is named");
    s.expect(kMissingReport.parserVersion == 14U,
             L"T-02 a malformed payload still records which parser tried");

    // Known payload truncated on the collection side -> Malformed, and no parser is selected.
    EventParseRequest truncated;
    truncated.providerId = "Kernel-File";
    truncated.eventId = 4U;
    truncated.version = 1U;
    truncated.payloadTruncated = true;
    const EventParseReport kTruncatedReport = parseEventPayload(kRegistry, truncated);
    s.expect(kTruncatedReport.outcome == EventParseOutcome::kMalformed &&
                 kTruncatedReport.reasonKey == "timeline.parse.payload-truncated",
             L"T-02 a truncated payload is Malformed with its own reason");
    s.expect(kTruncatedReport.parserId.empty(),
             L"T-02 a truncated payload selects no parser at all");

    // Unresolved records must fully preserve original fields and payloads, and their categories must not be inferred.
    TimelineEvent event;
    event.recordId = "u1";
    event.providerId = "Kernel-File";
    event.eventId = 4U;
    event.eventVersion = 2U;
    event.category = TimelineEventCategory::kOther;
    event.rawFields = unknown.rawFields;
    event.rawPayloadHex = unknown.rawPayloadHex;
    applyParseReport(event, kUnknownReport);
    s.expect(event.parseOutcome == EventParseOutcome::kUnparsedUnknownSchema,
             L"T-02 the unparsed outcome lands on the event");
    s.expect(event.rawFields.size() == 2U && event.rawFields[0].first == "FileName" &&
                 event.rawFields[0].second == "C:\\t\\a.txt" &&
                 event.rawFields[1].first == "NewFieldInV2" && event.rawFields[1].second == "42",
             L"T-02 raw fields survive an unparsed record byte for byte");
    s.expect(event.rawPayloadHex == "DEADBEEF",
             L"T-02 the raw payload survives an unparsed record");
    s.expect(event.category == TimelineEventCategory::kOther,
             L"T-02 an unparsed record does not get a guessed category");
    s.expect(event.eventVersion == 2U,
             L"T-02 the original event version is preserved on the record");

    TimelineEvent parsedEvent;
    parsedEvent.category = TimelineEventCategory::kOther;
    EventParseRequest fileRequest;
    fileRequest.providerId = "Kernel-File";
    fileRequest.eventId = 4U;
    fileRequest.version = 1U;
    fileRequest.rawFields.emplace_back("FileName", "C:\\t\\b.txt");
    applyParseReport(parsedEvent, parseEventPayload(kRegistry, fileRequest));
    s.expect(parsedEvent.category == TimelineEventCategory::kFile &&
                 parsedEvent.parserVersion == 14U,
             L"T-02 a parsed record takes the schema's category and parser version");

    TimelineEvent defaultEvent;
    s.expect(defaultEvent.parseOutcome == EventParseOutcome::kUnparsedUnknownSchema &&
                 defaultEvent.parserVersion == 0U,
             L"T-02 a default-constructed event is unparsed, not silently Parsed");
}

// ---------------------------------------------------------------------------
// T-04: Time semantics
// ---------------------------------------------------------------------------
void testTimeSemantics(ksword_tests::Suite& s) {
    s.expect(resolutionSpan100ns(TimeResolution::kMillisecond) == 10000ULL,
             L"T-04 one millisecond is 10000 units of 100ns");
    s.expect(resolutionSpan100ns(TimeResolution::kSecond) == 10000000ULL,
             L"T-04 one second is 10000000 units of 100ns");
    s.expect(resolutionSpan100ns(TimeResolution::kUnknown) == 0ULL,
             L"T-04 an unknown resolution declares no span");

    // Calibration is a derived value: source time remains unchanged; only the effective time has the offset added.
    EventTimeStamp calibrated = makeTime(kBoot1, 1000ULL, 1100ULL, TimeResolution::kMicrosecond);
    calibrated.calibrationAvailable = true;
    calibrated.calibrationOffset100ns = -250;
    calibrated.calibrationId = "cal-A";
    s.expect(calibrated.sourceTime100ns.present && calibrated.sourceTime100ns.value == 1000ULL,
             L"T-04 calibration never rewrites the source time");
    s.expect(calibrated.effectiveTime100ns().present &&
                 calibrated.effectiveTime100ns().value == 750ULL,
             L"T-04 the effective time applies the calibration offset");

    EventTimeStamp underflow = makeTime(kBoot1, 100ULL, 100ULL, TimeResolution::kMicrosecond);
    underflow.calibrationAvailable = true;
    underflow.calibrationOffset100ns = -500;
    s.expect(underflow.effectiveTime100ns().value == 0ULL,
             L"T-04 a negative calibration saturates at zero instead of wrapping");

    EventTimeStamp receiveOnly;
    receiveOnly.bootId = kBoot1;
    receiveOnly.receiveTime100ns = OptionalU64::of(4242ULL);
    receiveOnly.sourceResolution = TimeResolution::kMillisecond;
    s.expect(receiveOnly.effectiveFromReceiveTime() &&
                 receiveOnly.effectiveTime100ns().value == 4242ULL,
             L"T-04 a missing source time falls back to the receive time and says so");

    EventTimeStamp noTime;
    noTime.bootId = kBoot1;
    s.expect(!noTime.effectiveTime100ns().present,
             L"T-04 an event with no time at all stays unknown, not zero");

    // Sequential comparison. Expected deltas are all manually calculated.
    const EventTimeStamp kA = makeTime(kBoot1, 100000ULL, 100000ULL, TimeResolution::kMicrosecond);
    const EventTimeStamp kB = makeTime(kBoot1, 110000ULL, 110000ULL, TimeResolution::kMicrosecond);
    const TimeComparisonResult kForward = compareEventTimes(kA, kB);
    s.expect(kForward.kind == TimeComparison::kComparable && kForward.delta100ns == 10000,
             L"T-04 a forward pair is comparable with a positive delta");
    s.expect(!kForward.regression, L"T-04 a forward pair reports no regression");

    const TimeComparisonResult kBackward = compareEventTimes(kB, kA);
    s.expect(kBackward.delta100ns == -10000 && kBackward.regression,
             L"T-04 a reversed pair reports a negative delta and a regression");

    // Clock rollback wraparound trap: unsigned subtraction reports -50 as 1.8e19.
    const EventTimeStamp kLate = makeTime(kBoot1, 100ULL, 100ULL, TimeResolution::kHundredNanosecond);
    const EventTimeStamp kRolledBack = makeTime(kBoot1, 50ULL, 120ULL, TimeResolution::kHundredNanosecond);
    const TimeComparisonResult kRegression = compareEventTimes(kLate, kRolledBack);
    s.expect(kRegression.delta100ns == -50,
             L"T-04 a 50-unit clock rollback reports exactly -50, never a wrapped value");
    s.expect(kRegression.regression && kRegression.kind == TimeComparison::kComparable,
             L"T-04 the rollback is flagged as a regression");

    const EventTimeStamp kSame = makeTime(kBoot1, 100000ULL, 100001ULL, TimeResolution::kMicrosecond);
    const TimeComparisonResult kDuplicate = compareEventTimes(kA, kSame);
    s.expect(kDuplicate.kind == TimeComparison::kComparableButUncertain && kDuplicate.delta100ns == 0,
             L"T-04 identical timestamps are comparable but order-uncertain");

    const EventTimeStamp kClose = makeTime(kBoot1, 100003ULL, 100003ULL, TimeResolution::kMicrosecond);
    s.expect(compareEventTimes(kA, kClose).kind == TimeComparison::kComparableButUncertain,
             L"T-04 a gap smaller than the resolution is order-uncertain");

    const EventTimeStamp kCoarse = makeTime(kBoot1, 200000ULL, 200000ULL, TimeResolution::kUnknown);
    s.expect(compareEventTimes(kA, kCoarse).kind == TimeComparison::kComparableButUncertain,
             L"T-04 an unknown resolution never claims a strict order");

    const EventTimeStamp kOtherBoot = makeTime(kBoot2, 110000ULL, 110000ULL, TimeResolution::kMicrosecond);
    const TimeComparisonResult kCrossBoot = compareEventTimes(kA, kOtherBoot);
    s.expect(kCrossBoot.kind == TimeComparison::kIncomparableCrossBoot && kCrossBoot.delta100ns == 0,
             L"T-04 timestamps from two boot cycles are never subtracted");

    EventTimeStamp noBoot = makeTime("", 110000ULL, 110000ULL, TimeResolution::kMicrosecond);
    s.expect(compareEventTimes(kA, noBoot).kind == TimeComparison::kIncomparableCrossBoot,
             L"T-04 a missing boot id also blocks subtraction");

    s.expect(compareEventTimes(kA, noTime).kind == TimeComparison::kIncomparableUnknownTime,
             L"T-04 a missing time is incomparable, not zero");

    const EventTimeStamp kLow = makeTime(kBoot1, 0ULL, 0ULL, TimeResolution::kHundredNanosecond);
    const EventTimeStamp kHigh =
        makeTime(kBoot1, 18000000000000000000ULL, 0ULL, TimeResolution::kHundredNanosecond);
    const TimeComparisonResult kHuge = compareEventTimes(kLow, kHigh);
    s.expect(kHuge.kind == TimeComparison::kIncomparableMagnitude && kHuge.delta100ns == 0,
             L"T-04 a difference beyond int64 is reported incomparable rather than wrapped");

    EventTimeStamp calA = makeTime(kBoot1, 100000ULL, 100000ULL, TimeResolution::kMicrosecond);
    calA.calibrationId = "cal-1";
    EventTimeStamp calB = makeTime(kBoot1, 200000ULL, 200000ULL, TimeResolution::kMicrosecond);
    calB.calibrationId = "cal-2";
    const TimeComparisonResult kCalibrationChange = compareEventTimes(calA, calB);
    s.expect(kCalibrationChange.calibrationChanged &&
                 kCalibrationChange.kind == TimeComparison::kComparableButUncertain,
             L"T-04 a calibration change downgrades the order to uncertain");

    // Sort key: manually specified expected order.
    TimelineSortKey k1;
    k1.bootEpochRank = 0U;
    k1.timeKnown = true;
    k1.effectiveTime100ns = 200ULL;
    k1.arrivalSequence = 5U;
    k1.recordId = "b";
    TimelineSortKey k2 = k1;
    k2.effectiveTime100ns = 100ULL;
    k2.arrivalSequence = 9U;
    k2.recordId = "a";
    s.expect(sortKeyLess(k2, k1) && !sortKeyLess(k1, k2),
             L"T-04 an earlier effective time sorts first regardless of arrival order");
    TimelineSortKey unknownKey = k1;
    unknownKey.timeKnown = false;
    unknownKey.effectiveTime100ns = 0ULL;
    s.expect(sortKeyLess(k1, unknownKey) && !sortKeyLess(unknownKey, k1),
             L"T-04 unknown-time keys sort after known ones, not to the front");
    TimelineSortKey epochKey = k2;
    epochKey.bootEpochRank = 1U;
    s.expect(sortKeyLess(k1, epochKey),
             L"T-04 a later boot epoch sorts after the first epoch even with a smaller timestamp");
    TimelineSortKey tieA = k1;
    TimelineSortKey tieB = k1;
    tieB.arrivalSequence = 6U;
    s.expect(sortKeyLess(tieA, tieB), L"T-04 equal timestamps are tie-broken by arrival sequence");
    TimelineSortKey groupA = k1;
    TimelineSortKey groupB = k1;
    groupA.sourceGroup = "etw";
    groupB.sourceGroup = "ring";
    s.expect(sortKeyLess(groupA, groupB), L"T-04 the source group is a stable final tie-break");

    // Within session: out-of-order insertion, two start cycles, duplicate timestamps.
    TimelineSession session(makeManifest(), makeRoomyDeclaredBounds());
    session.apply(SessionAction::kStart);
    session.ingest(makeEvent("t1", "P", TimelineEventCategory::kProcess, 100U,
                             makeTime(kBoot1, kT0 + 30000ULL, kT0, TimeResolution::kMicrosecond)));
    session.ingest(makeEvent("t2", "P", TimelineEventCategory::kProcess, 100U,
                             makeTime(kBoot1, kT0 + 10000ULL, kT0 + 1ULL, TimeResolution::kMicrosecond)));
    session.ingest(makeEvent("t3", "P", TimelineEventCategory::kProcess, 100U,
                             makeTime(kBoot1, kT0 + 50000ULL, kT0 + 2ULL, TimeResolution::kMicrosecond)));
    session.ingest(makeEvent("t4", "P", TimelineEventCategory::kProcess, 100U,
                             makeTime(kBoot2, kT0 + 5000ULL, kT0 + 3ULL, TimeResolution::kMicrosecond)));
    s.expect(session.events().size() == 4U, L"T-04 four events retained");
    s.expect(elementOrDefault(session.events(), 1).time.lateArrival,
             L"T-04 an out-of-order event is admitted and flagged as late");
    s.expect(!elementOrDefault(session.events(), 0).time.lateArrival && !elementOrDefault(session.events(), 2).time.lateArrival,
             L"T-04 in-order events are not flagged as late");
    s.expect(!elementOrDefault(session.events(), 3).time.lateArrival,
             L"T-04 a smaller timestamp in a NEW boot cycle is not a late arrival");
    s.expect(elementOrDefault(session.events(), 1).time.sourceTime100ns.value == kT0 + 10000ULL,
             L"T-04 the late event keeps its original source time");

    const std::vector<TimelineSortKey> kOrder = session.sortedOrder();
    s.expect(kOrder.size() == 4U, L"T-04 the sort produces one key per event");
    // Hand-written expectation: within boot-1, order by time t2 < t1 < t3; boot-2 is placed entirely after.
    const bool kOrderMatches = kOrder.size() == 4U && kOrder[0].recordId == "t2" &&
                              kOrder[1].recordId == "t1" && kOrder[2].recordId == "t3" &&
                              kOrder[3].recordId == "t4";
    s.expect(kOrderMatches, L"T-04 the cross-source order is t2,t1,t3,t4 as computed by hand");
    s.expect(kOrder.size() == 4U && kOrder[3].bootEpochRank == 1U &&
                 kOrder[3].explanationKey == "timeline.order.cross-boot-grouped-by-epoch",
             L"T-04 the second boot cycle is grouped by epoch and says so");
    s.expect(kOrder.size() == 4U && kOrder[0].explanationKey == "timeline.order.by-source-time",
             L"T-04 an ordinary key explains that it sorted by source time");

    TimelineSession duplicates(makeManifest(), makeRoomyDeclaredBounds());
    duplicates.apply(SessionAction::kStart);
    duplicates.ingest(makeEvent("d1", "P", TimelineEventCategory::kFile, 100U,
                                makeTime(kBoot1, kT0 + 700ULL, kT0, TimeResolution::kMicrosecond)));
    duplicates.ingest(makeEvent("d2", "P", TimelineEventCategory::kFile, 100U,
                                makeTime(kBoot1, kT0 + 700ULL, kT0 + 1ULL, TimeResolution::kMicrosecond)));
    s.expect(elementOrDefault(duplicates.events(), 0).time.orderUncertain && elementOrDefault(duplicates.events(), 1).time.orderUncertain,
             L"T-04 two identical timestamps mark both events order-uncertain");
    const std::vector<TimelineSortKey> kDuplicateOrder = duplicates.sortedOrder();
    s.expect(kDuplicateOrder.size() == 2U &&
                 kDuplicateOrder[0].explanationKey == "timeline.order.uncertain-within-resolution",
             L"T-04 the sort explains that these two neighbours are indistinguishable");
}

// ---------------------------------------------------------------------------
// T-05 Process reuse and ownership
// ---------------------------------------------------------------------------
ProcessInstanceId makeProcessId(std::uint64_t pid, std::uint64_t createTime, const char* image) {
    ProcessInstanceId id;
    id.bootId = kBoot1;
    id.pid = OptionalU64::of(pid);
    id.createTime100ns = OptionalU64::of(createTime);
    id.imageName = image;
    return id;
}

void testAttribution(ksword_tests::Suite& s) {
    ProcessInstanceLedger ledger;
    // Two lifecycles for the same PID 1000: A[100,200], B[300,400].
    s.expect(ledger.observeStart(makeProcessId(1000U, 100U, "a.exe"), 100U),
             L"T-05 instance A start is recorded");
    s.expect(ledger.observeExit(makeProcessId(1000U, 100U, "a.exe"), 200U),
             L"T-05 instance A exit is recorded");
    s.expect(ledger.observeStart(makeProcessId(1000U, 300U, "b.exe"), 300U),
             L"T-05 instance B start is recorded");
    s.expect(ledger.observeExit(makeProcessId(1000U, 300U, "b.exe"), 400U),
             L"T-05 instance B exit is recorded");
    s.expect(ledger.instanceCount() == 2U, L"T-05 the two lifetimes are separate instances");

    const OptionalU64 kPid1000 = OptionalU64::of(1000ULL);
    const AttributionDecision kInA =
        ledger.attribute(kBoot1, kPid1000, makeTime(kBoot1, 150U, 150U, TimeResolution::kHundredNanosecond));
    s.expect(kInA.kind == AttributionKind::kBoundToInstance &&
                 kInA.instance.createTime100ns.value == 100ULL,
             L"T-05 an event inside A's window binds to A");
    s.expect(kInA.identityMatch == MatchResult::kConfirmed &&
                 kInA.identityStrength == IdentityStrength::kStrong,
             L"T-05 a complete instance identity yields a Confirmed match");

    const AttributionDecision kInB =
        ledger.attribute(kBoot1, kPid1000, makeTime(kBoot1, 350U, 350U, TimeResolution::kHundredNanosecond));
    s.expect(kInB.kind == AttributionKind::kBoundToInstance &&
                 kInB.instance.createTime100ns.value == 300ULL,
             L"T-05 after PID reuse an event inside B's window binds to B, not to A");

    const AttributionDecision kBetween =
        ledger.attribute(kBoot1, kPid1000, makeTime(kBoot1, 250U, 250U, TimeResolution::kHundredNanosecond));
    s.expect(kBetween.kind == AttributionKind::kAfterInstanceExit,
             L"T-05 an event in the gap between two lifetimes is not attributed to either");
    s.expect(!kBetween.provisionalId.empty() && kBetween.instance.pid.present == false,
             L"T-05 the gap event becomes a provisional entity rather than a silent guess");
    s.expect(kBetween.reasonKey == "timeline.attribution.after-known-exit",
             L"T-05 the gap event names the reason");

    const AttributionDecision kAfterAll =
        ledger.attribute(kBoot1, kPid1000, makeTime(kBoot1, 900U, 900U, TimeResolution::kHundredNanosecond));
    s.expect(kAfterAll.kind == AttributionKind::kAfterInstanceExit,
             L"T-05 a late event arriving after the target ended is not re-hung on a live PID");

    const AttributionDecision kBeforeAll =
        ledger.attribute(kBoot1, kPid1000, makeTime(kBoot1, 50U, 50U, TimeResolution::kHundredNanosecond));
    s.expect(kBeforeAll.kind == AttributionKind::kProvisional &&
                 kBeforeAll.reasonKey == "timeline.attribution.missing-start-event",
             L"T-05 an event before every known start is provisional");

    // No PID with a start event at all.
    const AttributionDecision kOrphan =
        ledger.attribute(kBoot1, OptionalU64::of(2000ULL),
                         makeTime(kBoot1, 150U, 150U, TimeResolution::kHundredNanosecond));
    s.expect(kOrphan.kind == AttributionKind::kProvisional && !kOrphan.provisionalId.empty(),
             L"T-05 a PID with no start event gets an incomplete-identity provisional entity");
    const ProvisionalProcessEntity* entity = ledger.findProvisional(kOrphan.provisionalId);
    s.expect(entity != nullptr && !entity->identityComplete,
             L"T-05 the provisional entity is explicitly identity-incomplete");
    s.expect(entity != nullptr && entity->pid.present && entity->pid.value == 2000ULL,
             L"T-05 the provisional entity keeps the observed PID");

    // Weak evidence must not mark temporary entities as complete.
    ProcessInstanceId weak;
    weak.bootId = kBoot1;
    weak.pid = OptionalU64::of(2000ULL);  // No createTime -> crossSessionKey is empty.
    s.expect(!ledger.confirmProvisional(kOrphan.provisionalId, weak, "note"),
             L"T-05 weak evidence cannot confirm a provisional entity");
    const ProvisionalProcessEntity* stillWeak = ledger.findProvisional(kOrphan.provisionalId);
    s.expect(stillWeak != nullptr && !stillWeak->identityComplete &&
                 stillWeak->resolutionNoteKey ==
                     "timeline.provisional.resolve-rejected-weak-identity",
             L"T-05 the rejected resolution is recorded instead of silently succeeding");

    s.expect(ledger.confirmProvisional(kOrphan.provisionalId, makeProcessId(2000U, 140U, "c.exe"),
                                       "timeline.provisional.resolved-by-later-start-event"),
             L"T-05 a complete identity confirms the provisional entity");
    const ProvisionalProcessEntity* resolved = ledger.findProvisional(kOrphan.provisionalId);
    s.expect(resolved != nullptr && resolved->identityComplete &&
                 !resolved->resolvedInstanceKey.empty() &&
                 resolved->resolutionNoteKey ==
                     "timeline.provisional.resolved-by-later-start-event",
             L"T-05 the resolution keeps a traceable note and the resolved instance key");

    // An instance with incomplete identity: even if the window matches, it can only be marked as Candidate.
    ProcessInstanceLedger weakLedger;
    ProcessInstanceId weakInstance;
    weakInstance.bootId = kBoot1;
    weakInstance.pid = OptionalU64::of(3000ULL);
    s.expect(weakLedger.observeStart(weakInstance, 100U),
             L"T-05 an instance without a create time can still be registered");
    const AttributionDecision kWeakBind =
        weakLedger.attribute(kBoot1, OptionalU64::of(3000ULL),
                             makeTime(kBoot1, 150U, 150U, TimeResolution::kHundredNanosecond));
    s.expect(kWeakBind.kind == AttributionKind::kBoundToInstance &&
                 kWeakBind.identityStrength == IdentityStrength::kWeak &&
                 kWeakBind.identityMatch == MatchResult::kCandidate,
             L"T-05 a weak instance identity caps the match at Candidate");

    // Three fallback paths: missing PID, missing bootId, and missing timestamp.
    const AttributionDecision kNoPid =
        ledger.attribute(kBoot1, OptionalU64::unset(),
                         makeTime(kBoot1, 150U, 150U, TimeResolution::kHundredNanosecond));
    s.expect(kNoPid.kind == AttributionKind::kUnknownProcess &&
                 kNoPid.reasonKey == "timeline.attribution.no-pid",
             L"T-05 an event without a PID is UnknownProcess");
    const AttributionDecision kNoBoot =
        ledger.attribute("", kPid1000, makeTime("", 150U, 150U, TimeResolution::kHundredNanosecond));
    s.expect(kNoBoot.kind == AttributionKind::kProvisional &&
                 kNoBoot.reasonKey == "timeline.attribution.no-boot-id",
             L"T-05 without a boot id the PID is never resolved to a live instance");
    EventTimeStamp timeless;
    timeless.bootId = kBoot1;
    const AttributionDecision kNoTime = ledger.attribute(kBoot1, kPid1000, timeless);
    s.expect(kNoTime.kind == AttributionKind::kProvisional &&
                 kNoTime.reasonKey == "timeline.attribution.no-time",
             L"T-05 an event without a usable time is not placed into any window");

    s.expect(!ledger.observeStart(ProcessInstanceId{}, 10U),
             L"T-05 an instance with neither boot id nor PID is refused");
    s.expect(!ledger.observeExit(makeProcessId(4321U, 1U, "x.exe"), 10U),
             L"T-05 an exit for an unknown instance does not fabricate one");

    // Session path must not be silently attributed.
    TimelineSession session(makeManifest(), makeRoomyDeclaredBounds());
    session.apply(SessionAction::kStart);
    session.processes().observeStart(makeProcessId(5000U, kT0 + 100ULL, "live.exe"), kT0 + 100ULL);
    session.ingest(makeEvent("p1", "Kernel-File", TimelineEventCategory::kFile, 5000U,
                             makeTime(kBoot1, kT0 + 200ULL, kT0 + 200ULL, TimeResolution::kMicrosecond)));
    session.ingest(makeEvent("p2", "Kernel-File", TimelineEventCategory::kFile, 6000U,
                             makeTime(kBoot1, kT0 + 300ULL, kT0 + 300ULL, TimeResolution::kMicrosecond)));
    s.expect(elementOrDefault(session.events(), 0).attribution == AttributionKind::kBoundToInstance &&
                 !elementOrDefault(session.events(), 0).processInstanceKey.empty(),
             L"T-05 a known instance produces a cross-session instance key on the event");
    s.expect(elementOrDefault(session.events(), 1).attribution == AttributionKind::kProvisional &&
                 elementOrDefault(session.events(), 1).processInstanceKey.empty() &&
                 !elementOrDefault(session.events(), 1).provisionalProcessId.empty(),
             L"T-05 an unknown PID gets a provisional id and NO instance key");

    // -----------------------------------------------------------------------
    // T-05 PID reuse + late termination event. Hand-written timeline:
    //   A: createTime=100, start=100, end event delayed, reported at 350
    //   B: createTime=300, start=300, not yet seen end. Only select candidates by (bootId,
    // pid, latest start time among those not ended); A's exit will be attributed to B.
    // -----------------------------------------------------------------------
    ProcessInstanceLedger reuse;
    s.expect(reuse.observeStart(makeProcessId(1000U, 100U, "a.exe"), 100U),
             L"T-05 reuse fixture: instance A starts at 100");
    s.expect(reuse.observeStart(makeProcessId(1000U, 300U, "b.exe"), 300U),
             L"T-05 reuse fixture: instance B starts at 300 on the same PID");
    s.expect(reuse.observeExit(makeProcessId(1000U, 100U, "a.exe"), 350U),
             L"T-05 a late exit is matched to A by createTime, not to the newest same-PID instance");
    const AttributionDecision kReuseAt400 =
        reuse.attribute(kBoot1, kPid1000, makeTime(kBoot1, 400U, 400U, TimeResolution::kHundredNanosecond));
    s.expect(kReuseAt400.kind == AttributionKind::kBoundToInstance &&
                 kReuseAt400.instance.createTime100ns.present &&
                 kReuseAt400.instance.createTime100ns.value == 300ULL,
             L"T-05 after that late exit an event at t=400 binds to B (createTime 300), not to the dead A (createTime 100)");
    const AttributionDecision kReuseAt320 =
        reuse.attribute(kBoot1, kPid1000, makeTime(kBoot1, 320U, 320U, TimeResolution::kHundredNanosecond));
    s.expect(kReuseAt320.kind == AttributionKind::kAmbiguous,
             L"T-05 t=320 sits inside both windows and is reported Ambiguous instead of being picked");

    // Exit events include createTime, but the registered instance does not; unable to verify, so reject rather than forcibly attach.
    ProcessInstanceLedger weakStart;
    ProcessInstanceId noCreateTime;
    noCreateTime.bootId = kBoot1;
    noCreateTime.pid = OptionalU64::of(1500ULL);
    s.expect(weakStart.observeStart(noCreateTime, 100U),
             L"T-05 an instance with no create time can be registered");
    s.expect(!weakStart.observeExit(makeProcessId(1500U, 100U, "x.exe"), 200U),
             L"T-05 an exit carrying a createTime is refused when the registered instance has none to compare");
    s.expect(weakStart.weakExitMatchCount() == 0U,
             L"T-05 a refused exit is not booked as a weak match");
    s.expect(weakStart.observeExit(noCreateTime, 200U),
             L"T-05 an exit with no createTime falls back to the start-time heuristic");
    s.expect(weakStart.weakExitMatchCount() == 1U,
             L"T-05 the start-time fallback is counted as a weak exit match instead of passing as certain");

    // Same PID and start time, but different createTime values: these are two instances. A later registration must not overwrite them as one.
    ProcessInstanceLedger sameStart;
    sameStart.observeStart(makeProcessId(1600U, 10U, "p.exe"), 50U);
    sameStart.observeStart(makeProcessId(1600U, 20U, "q.exe"), 50U);
    s.expect(sameStart.instanceCount() == 2U,
             L"T-05 two different createTimes at the same start time are two instances, not one overwritten record");

    // -----------------------------------------------------------------------
    // T-05 Ambiguous: Two instances with the same PID have overlapping windows (both lack end events).
    // -----------------------------------------------------------------------
    ProcessInstanceLedger overlap;
    overlap.observeStart(makeProcessId(50U, 100U, "o1.exe"), 100U);
    overlap.observeStart(makeProcessId(50U, 150U, "o2.exe"), 150U);
    const AttributionDecision kAmbiguous =
        overlap.attribute(kBoot1, OptionalU64::of(50ULL),
                          makeTime(kBoot1, 200U, 200U, TimeResolution::kHundredNanosecond));
    s.expect(kAmbiguous.kind == AttributionKind::kAmbiguous,
             L"T-05 two overlapping same-PID windows are reported Ambiguous, never silently picked");
    s.expect(kAmbiguous.reasonKey == "timeline.attribution.overlapping-instances",
             L"T-05 the ambiguous attribution names its reason");
    s.expect(!kAmbiguous.provisionalId.empty(),
             L"T-05 the ambiguous event still gets a stable provisional entity id");
    s.expect(kAmbiguous.identityStrength == IdentityStrength::kUnusable &&
                 kAmbiguous.identityMatch == MatchResult::kCandidate,
             L"T-05 an ambiguous attribution never claims a Confirmed identity match");
    s.expect(!kAmbiguous.instance.pid.present,
             L"T-05 an ambiguous attribution carries no bound instance at all");

    TimelineSession ambiguousSession(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    ambiguousSession.apply(SessionAction::kStart);
    ambiguousSession.processes().observeStart(makeProcessId(50U, kT0 + 100ULL, "o1.exe"), kT0 + 100ULL);
    ambiguousSession.processes().observeStart(makeProcessId(50U, kT0 + 150ULL, "o2.exe"), kT0 + 150ULL);
    ambiguousSession.ingest(makeEvent("amb1", "P", TimelineEventCategory::kProcess, 50U,
                                      makeTime(kBoot1, kT0 + 200ULL, kT0 + 200ULL,
                                               TimeResolution::kMicrosecond)));
    const TimelineEvent& ambiguousEvent = elementOrDefault(ambiguousSession.events(), 0);
    s.expect(ambiguousEvent.attribution == AttributionKind::kAmbiguous,
             L"T-05 the session marks the overlapping-instance event Ambiguous");
    s.expect(ambiguousEvent.processInstanceKey.empty(),
             L"T-05 an ambiguous event carries NO cross-session instance key");
    s.expect(!ambiguousEvent.provisionalProcessId.empty(),
             L"T-05 an ambiguous event carries a provisional id instead");

    // -----------------------------------------------------------------------
    // T-05: Provisional entity IDs cannot be formed by simple concatenation; an empty bootId and the literal 'boot-unknown' previously collided into a single entity.
    // -----------------------------------------------------------------------
    s.expect(makeProvisionalEntityId(std::string(), OptionalU64::of(7ULL),
                                     AttributionKind::kProvisional) !=
                 makeProvisionalEntityId(std::string("boot-unknown"), OptionalU64::of(7ULL),
                                         AttributionKind::kProvisional),
             L"T-05 an absent boot id and a boot cycle literally named boot-unknown encode to different ids");
    ProcessInstanceLedger collide;
    EventTimeStamp missingBoot;
    missingBoot.sourceTime100ns = OptionalU64::of(100ULL);
    missingBoot.sourceResolution = TimeResolution::kHundredNanosecond;
    const AttributionDecision kAbsentBoot =
        collide.attribute(std::string(), OptionalU64::of(7ULL), missingBoot);
    const AttributionDecision kNamedBoot =
        collide.attribute(std::string("boot-unknown"), OptionalU64::of(7ULL),
                          makeTime("boot-unknown", 900U, 900U, TimeResolution::kHundredNanosecond));
    s.expect(kAbsentBoot.provisionalId != kNamedBoot.provisionalId,
             L"T-05 the two events do not share one provisional id");
    s.expect(collide.provisionals().size() == 2U,
             L"T-05 they stay two provisional entities instead of merging into one (hand-count: 2)");
    const ProvisionalProcessEntity* absentEntity = collide.findProvisional(kAbsentBoot.provisionalId);
    const ProvisionalProcessEntity* namedEntity = collide.findProvisional(kNamedBoot.provisionalId);
    s.expect(absentEntity != nullptr && absentEntity->eventCount == 1U && absentEntity->bootId.empty(),
             L"T-05 the boot-less entity keeps exactly its own one event and an empty boot id");
    s.expect(namedEntity != nullptr && namedEntity->eventCount == 1U &&
                 namedEntity->bootId == "boot-unknown",
             L"T-05 the named boot cycle is not folded into an entity whose recorded boot id is empty");
    s.expect(absentEntity != nullptr && absentEntity->firstSeenTime100ns.present &&
                 absentEntity->firstSeenTime100ns.value == 100ULL &&
                 absentEntity->lastSeenTime100ns.value == 100ULL,
             L"T-05 the boot-less entity first/last seen stay at 100, not stretched to 900 by the other event");
}

// ---------------------------------------------------------------------------
// T-06: Loss ledger
// ---------------------------------------------------------------------------
void testLossAccounting(ksword_tests::Suite& s) {
    LossLedger fresh;
    s.expect(fresh.anyUnknown(),
             L"T-06 an untouched ledger is unknown, not a clean zero");
    s.expect(!fresh.totalLost().present,
             L"T-06 an untouched ledger refuses to report a total");
    s.expect(!fresh.counter(LossCategory::kSourceDrop).count.present,
             L"T-06 an untouched category has no count at all");

    LossLedger ledger;
    s.expect(!ledger.declareSource(LossCategory::kSourceDrop, "", true, false),
             L"T-06 an empty statistic source is refused");
    s.expect(ledger.declareSource(LossCategory::kSourceDrop, "etw.EventsLost", true, false),
             L"T-06 an authoritative source can be declared");
    s.expect(!ledger.counter(LossCategory::kSourceDrop).count.present,
             L"T-06 an authoritative category stays unknown until the source reports");
    s.expect(!ledger.declareSource(LossCategory::kSourceDrop, "other.counter", true, false),
             L"T-06 a category cannot switch to a second statistic source");
    s.expect(ledger.counter(LossCategory::kSourceDrop).statisticSource == "etw.EventsLost",
             L"T-06 the rejected re-declaration leaves the original source intact");

    s.expect(!ledger.addObserved(LossCategory::kSourceDrop, 1ULL),
             L"T-06 local increments on an authoritative category would double count");
    s.expect(ledger.setAbsolute(LossCategory::kSourceDrop, 5ULL),
             L"T-06 the authoritative source sets an absolute count");
    s.expect(ledger.counter(LossCategory::kSourceDrop).count.present &&
                 ledger.counter(LossCategory::kSourceDrop).count.value == 5ULL,
             L"T-06 the absolute count is stored losslessly");

    s.expect(ledger.declareSource(LossCategory::kQueueDiscard, "local.r3queue", false, false),
             L"T-06 a locally counted category can be declared");
    s.expect(ledger.counter(LossCategory::kQueueDiscard).count.present &&
                 ledger.counter(LossCategory::kQueueDiscard).count.value == 0ULL,
             L"T-06 a local category starts at an explained zero");
    s.expect(!ledger.setAbsolute(LossCategory::kQueueDiscard, 9ULL),
             L"T-06 a local category refuses an absolute overwrite");
    s.expect(ledger.addObserved(LossCategory::kQueueDiscard, 3ULL) &&
                 ledger.counter(LossCategory::kQueueDiscard).count.value == 3ULL,
             L"T-06 local increments accumulate");

    s.expect(!ledger.setInterval(LossCategory::kSourceDrop, 10ULL, 20ULL),
             L"T-06 a total-only source cannot be given a fabricated loss interval");
    s.expect(!ledger.counter(LossCategory::kSourceDrop).intervalBegin100ns.present,
             L"T-06 the refused interval leaves no residue");
    s.expect(ledger.declareSource(LossCategory::kRingOverwrite, "ring.OverwriteCount", true, true),
             L"T-06 a source that does provide intervals declares it");
    s.expect(ledger.setInterval(LossCategory::kRingOverwrite, 10ULL, 20ULL),
             L"T-06 an interval-capable source may record the interval");
    s.expect(!ledger.setInterval(LossCategory::kRingOverwrite, 30ULL, 20ULL),
             L"T-06 a reversed interval is refused");

    s.expect(ledger.anyUnknown(),
             L"T-06 the ledger is still unknown while RingOverwrite has no count");
    s.expect(!ledger.totalLost().present,
             L"T-06 an unknown category poisons the total instead of counting as zero");
    ledger.setAbsolute(LossCategory::kRingOverwrite, 7ULL);
    ledger.declareSource(LossCategory::kParseFailure, "local.parser", false, false);
    ledger.declareSource(LossCategory::kFilteredOut, "local.collectionFilter", false, false);
    ledger.declareSource(LossCategory::kRetentionEvicted, "local.retention", false, false);
    s.expect(!ledger.anyUnknown(), L"T-06 all six categories now have named sources and counts");
    const OptionalU64 kTotal = ledger.totalLost();
    // Manual calculation: 5 (SourceDrop) + 7 (RingOverwrite) + 3 (QueueDiscard) + 0 + 0 + 0 = 15
    s.expect(kTotal.present && kTotal.value == 15ULL, L"T-06 the total is 5+7+3 = 15");
    const std::vector<std::string> kKeys = ledger.limitationKeys();
    s.expect(containsKey(kKeys, "timeline.loss.total-only.SourceDrop"),
             L"T-06 a total-only positive count is reported as total-only");
    s.expect(!containsKey(kKeys, "timeline.loss.total-only.RingOverwrite"),
             L"T-06 an interval-capable source is not marked total-only");

    LossLedger clean;
    declareAllLossSources(clean);
    s.expect(!clean.anyUnknown() && clean.totalLost().present && clean.totalLost().value == 0ULL,
             L"T-06 a fully sourced ledger can report a real zero");
    s.expect(containsKey(clean.limitationKeys(), "timeline.loss.none-all-categories-sourced"),
             L"T-06 the zero case is a positive statement, not an empty default");
    LossLedger partial;
    partial.declareSource(LossCategory::kSourceDrop, "etw.EventsLost", true, false);
    s.expect(containsKey(partial.limitationKeys(), "timeline.loss.no-source.QueueDiscard"),
             L"T-06 a category with no source is named explicitly");
    s.expect(containsKey(partial.limitationKeys(), "timeline.loss.unknown-count.SourceDrop"),
             L"T-06 a declared but unreported category is named explicitly");

    // Force queue overflow: limit 3 + StopOnLimit.
    TimelineSession stopping(makeManifest(), makeBounds(3ULL, RetentionPolicy::kStopOnLimit));
    declareAllLossSources(stopping.loss());
    stopping.apply(SessionAction::kStart);
    std::size_t accepted = 0;
    std::size_t rejected = 0;
    for (int i = 0; i < 5; ++i) {
        const std::string kId = "q" + std::to_string(i);
        const IngestResult kResult = stopping.ingest(
            makeEvent(kId.c_str(), "P", TimelineEventCategory::kProcess, 100U,
                      makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                               kT0, TimeResolution::kMicrosecond)));
        if (kResult.accepted) {
            ++accepted;
        } else {
            ++rejected;
        }
    }
    s.expect(accepted == 3U && rejected == 2U, L"T-08 StopOnLimit accepts 3 and refuses 2");
    s.expect(stopping.events().size() == 3U, L"T-08 the memory bound really is 3 events");
    s.expect(stopping.boundsState() == BoundsState::kMemoryLimitReached,
             L"T-08 reaching the memory limit is marked, not silent");
    s.expect(stopping.loss().counter(LossCategory::kQueueDiscard).count.value == 2ULL,
             L"T-06 the two refused events are counted as queue discards");
    s.expect(stopping.loss().counter(LossCategory::kRetentionEvicted).count.value == 0ULL,
             L"T-06 StopOnLimit does not also count them as retention evictions");

    // Force ring overwrite eviction: limit 3 + EvictOldest.
    TimelineSession evicting(makeManifest(), makeBounds(3ULL, RetentionPolicy::kEvictOldest));
    declareAllLossSources(evicting.loss());
    evicting.apply(SessionAction::kStart);
    for (int i = 0; i < 5; ++i) {
        const std::string kId = "r" + std::to_string(i);
        evicting.ingest(makeEvent(kId.c_str(), "P", TimelineEventCategory::kProcess, 100U,
                                  makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                           kT0, TimeResolution::kMicrosecond)));
    }
    s.expect(evicting.events().size() == 3U, L"T-08 EvictOldest keeps the window at 3 events");
    s.expect(elementOrDefault(evicting.events(), 0).recordId == "r2",
             L"T-08 the two oldest records are the ones evicted");
    s.expect(evicting.loss().counter(LossCategory::kRetentionEvicted).count.value == 2ULL,
             L"T-06 the evictions are counted under the retention category");
    s.expect(evicting.loss().counter(LossCategory::kQueueDiscard).count.value == 0ULL,
             L"T-06 evictions are not double counted as queue discards");

    // Disk limit conversion: 100 bytes / 40 bytes per event = 2 events.
    BoundsPolicy diskBounds;
    diskBounds.maxArchiveBytes = OptionalU64::of(100ULL);
    diskBounds.approximateBytesPerEvent = OptionalU64::of(40ULL);
    diskBounds.policy = RetentionPolicy::kStopOnLimit;
    diskBounds.declaredBeforeCollection = true;
    TimelineSession disk(makeManifest(), diskBounds);
    declareAllLossSources(disk.loss());
    disk.apply(SessionAction::kStart);
    for (int i = 0; i < 4; ++i) {
        const std::string kId = "d" + std::to_string(i);
        disk.ingest(makeEvent(kId.c_str(), "P", TimelineEventCategory::kProcess, 100U,
                              makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                       kT0, TimeResolution::kMicrosecond)));
    }
    s.expect(disk.events().size() == 2U, L"T-08 100 bytes at 40 bytes per event bounds at 2");
    s.expect(disk.boundsState() == BoundsState::kArchiveLimitReached,
             L"T-08 the archive limit is reported separately from the memory limit");

    BoundsPolicy zeroBounds = makeBounds(0ULL, RetentionPolicy::kEvictOldest);
    TimelineSession zero(makeManifest(), zeroBounds);
    declareAllLossSources(zero.loss());
    zero.apply(SessionAction::kStart);
    const IngestResult kZeroResult =
        zero.ingest(makeEvent("z0", "P", TimelineEventCategory::kProcess, 100U,
                              makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond)));
    s.expect(!kZeroResult.accepted && kZeroResult.reasonKey == "timeline.ingest.capacity-zero",
             L"T-08 a zero capacity refuses everything instead of looping");
    s.expect(zero.events().empty(), L"T-08 nothing is retained under a zero capacity");

    // Parsing failures are recorded as ParseFailure; unknown schemas are ignored (original records are preserved intact).
    TimelineSession parsing(makeManifest(), makeRoomyDeclaredBounds());
    declareAllLossSources(parsing.loss());
    parsing.apply(SessionAction::kStart);
    TimelineEvent malformed = makeEvent("m1", "P", TimelineEventCategory::kOther, 100U,
                                        makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond));
    malformed.parseOutcome = EventParseOutcome::kMalformed;
    parsing.ingest(malformed);
    TimelineEvent unparsed = makeEvent("m2", "P", TimelineEventCategory::kOther, 100U,
                                       makeTime(kBoot1, kT0 + 10000ULL, kT0, TimeResolution::kMicrosecond));
    unparsed.parseOutcome = EventParseOutcome::kUnparsedUnknownSchema;
    parsing.ingest(unparsed);
    s.expect(parsing.loss().counter(LossCategory::kParseFailure).count.value == 1ULL,
             L"T-06 only the malformed record counts as a parse failure");
    s.expect(parsing.events().size() == 2U,
             L"T-06 both records are still retained for later re-parsing");
}

// ---------------------------------------------------------------------------
// T-03: Collection filtering and display filtering are separated.
// ---------------------------------------------------------------------------
void testFilterSeparation(ksword_tests::Suite& s) {
    TimelineSession session(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    declareAllLossSources(session.loss());
    session.apply(SessionAction::kStart);
    const std::uint64_t kPids[] = { 4100ULL, 4200ULL, 4100ULL, 4200ULL };
    for (int i = 0; i < 4; ++i) {
        const std::string kId = "f" + std::to_string(i);
        session.ingest(makeEvent(kId.c_str(), "Kernel-File", TimelineEventCategory::kFile,
                                 kPids[i],
                                 makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                          kT0, TimeResolution::kMicrosecond)));
    }
    s.expect(session.events().size() == 4U, L"T-03 all four events entered the session");

    EventFilter display;
    display.active = true;
    display.ruleId = "ui.only-4100";
    display.allowedPids.push_back(4100ULL);
    session.setDisplayFilter(display);
    s.expect(session.visibleEvents().size() == 2U, L"T-03 the display filter shows two events");
    s.expect(session.events().size() == 4U,
             L"T-03 the display filter does not remove anything from the session");

    const ExportPlan kVisible = session.buildExportPlan(ExportScope::kVisibleOnly);
    s.expect(kVisible.exportedEventCount == 2U && kVisible.retainedEventCount == 4U,
             L"T-03 the visible export carries 2 of 4 retained events");
    s.expect(kVisible.hiddenByDisplayFilter == 2U,
             L"T-03 the visible export states how many events it hid");
    s.expect(!kVisible.representsRetainedSession,
             L"T-03 the visible export does not claim to be the whole session");
    s.expect(containsKey(kVisible.noticeKeys, "timeline.export.hidden-events-still-in-session"),
             L"T-03 the visible export says the hidden events still exist");

    const ExportPlan kFull = session.buildExportPlan(ExportScope::kFullSession);
    s.expect(kFull.exportedEventCount == 4U && kFull.representsRetainedSession,
             L"T-03 the full export carries every retained event");
    s.expect(kFull.hiddenByDisplayFilter == 2U,
             L"T-03 the full export still reports what the UI is hiding");
    s.expect(containsKey(kFull.noticeKeys, "timeline.export.display-filter-not-applied"),
             L"T-03 the full export states that the display filter was not applied");
    s.expect(kFull.excludedByCollectionFilter == 0U,
             L"T-03 nothing was excluded at collection time in this run");
    // New criterion: in addition to 'no filter / no loss / no bound hit', it requires at least one declared
    // collector capability that is Success for every instance. This manifest declares a Success etw.kernel.
    s.expect(kFull.retainedSessionIsCompleteCapture,
             L"T-03 no filter + no loss + no bound hit + one declared collector that succeeded = complete capture");
    s.expect(kFull.unavailableCollectorCount == 0U,
             L"T-03 the complete-capture session has zero unavailable declared collectors");

    // Counterexample: with the same data, if a collector's capabilities are not declared in the manifest, it is unknown what data should have been collected.
    TimelineSession undeclaredCollectors(makeManifest(), makeRoomyDeclaredBounds());
    declareAllLossSources(undeclaredCollectors.loss());
    undeclaredCollectors.apply(SessionAction::kStart);
    undeclaredCollectors.ingest(makeEvent("nc1", "Kernel-File", TimelineEventCategory::kFile, 4100U,
                                          makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond)));
    const ExportPlan kUndeclaredPlan =
        undeclaredCollectors.buildExportPlan(ExportScope::kFullSession);
    s.expect(!kUndeclaredPlan.retainedSessionIsCompleteCapture,
             L"T-06 a session that declared no collector capability at all is never a complete capture");
    s.expect(containsKey(kUndeclaredPlan.noticeKeys,
                         "timeline.export.no-collector-capability-declared"),
             L"T-06 the export says why: nothing declared what was supposed to be collected");

    // Collection filtering: matched events never entered the session; this is distinct from display filtering.
    TimelineSession collecting(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    declareAllLossSources(collecting.loss());
    EventFilter collection;
    collection.active = true;
    collection.ruleId = "capture.only-4100";
    collection.allowedPids.push_back(4100ULL);
    collecting.setCollectionFilter(collection);
    collecting.apply(SessionAction::kStart);
    std::size_t admitted = 0;
    for (int i = 0; i < 4; ++i) {
        const std::string kId = "c" + std::to_string(i);
        const IngestResult kResult = collecting.ingest(
            makeEvent(kId.c_str(), "Kernel-File", TimelineEventCategory::kFile, kPids[i],
                      makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                               kT0, TimeResolution::kMicrosecond)));
        if (kResult.accepted) {
            ++admitted;
        } else {
            s.expect(kResult.reasonKey == "timeline.ingest.excluded-by-collection-filter" &&
                         kResult.lossCategory == LossCategory::kFilteredOut,
                     L"T-03 a collection-filtered event is accounted as FilteredOut");
        }
    }
    s.expect(admitted == 2U, L"T-03 the collection filter admitted exactly two events");
    s.expect(collecting.events().size() == 2U,
             L"T-03 collection-filtered events never entered the session");
    s.expect(collecting.loss().counter(LossCategory::kFilteredOut).count.value == 2ULL,
             L"T-06 collection-filtered events are counted in their own category");
    const ExportPlan kCollectedFull = collecting.buildExportPlan(ExportScope::kFullSession);
    s.expect(kCollectedFull.excludedByCollectionFilter == 2U,
             L"T-03 the full export reports what the collection filter removed");
    s.expect(!kCollectedFull.retainedSessionIsCompleteCapture,
             L"T-03 a collection-filtered session is never called a complete capture");
    s.expect(containsKey(kCollectedFull.noticeKeys, "timeline.export.collection-filter-applied"),
             L"T-03 the full export names the collection filter");

    // Filter semantics itself.
    TimelineEvent probe = makeEvent("probe", "Kernel-File", TimelineEventCategory::kFile, 4100U,
                                    makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond));
    EventFilter inactive;
    s.expect(filterAdmits(inactive, probe), L"T-03 an inactive filter admits everything");
    EventFilter byCategory;
    byCategory.active = true;
    byCategory.allowedCategories.push_back(TimelineEventCategory::kRegistry);
    s.expect(!filterAdmits(byCategory, probe), L"T-03 a category filter rejects other categories");
    EventFilter byProvider;
    byProvider.active = true;
    byProvider.allowedProviderIds.push_back("Kernel-File");
    s.expect(filterAdmits(byProvider, probe), L"T-03 a provider filter admits its provider");
    TimelineEvent noPid = probe;
    noPid.pid = OptionalU64::unset();
    EventFilter byPid;
    byPid.active = true;
    byPid.allowedPids.push_back(4100ULL);
    s.expect(!filterAdmits(byPid, noPid),
             L"T-03 an event with an unknown PID is not silently admitted by a PID filter");
}

// ---------------------------------------------------------------------------
// T-09 / T-10 Save and restore
// ---------------------------------------------------------------------------
TimelineSession buildPersistenceSession() {
    SessionManifest manifest = makeManifest();
    CollectorCapability etw;
    etw.collectorId = "etw.kernel";
    etw.collectorVersion = 3U;
    etw.sourceGroup = "etw.kernel";
    etw.origin = SourceOrigin::kLiveKernel;
    etw.declaredCategories.push_back(TimelineEventCategory::kProcess);
    etw.declaredCategories.push_back(TimelineEventCategory::kFile);
    etw.availability = CollectionOutcome::success();
    manifest.capabilities.push_back(etw);
    CollectorCapability ring;
    ring.collectorId = "r0.callback.ring";
    ring.collectorVersion = 2U;
    ring.sourceGroup = "r0.callback.ring";
    ring.origin = SourceOrigin::kLiveKernel;
    ring.declaredCategories.push_back(TimelineEventCategory::kRegistry);
    ring.availability = CollectionOutcome::failure(CollectionStatus::kAccessDenied, "NTSTATUS",
                                                   0xC0000022ULL, "STATUS_ACCESS_DENIED");
    manifest.capabilities.push_back(ring);

    TimelineSession session(manifest, makeRoomyDeclaredBounds());
    declareAllLossSources(session.loss());
    session.loss().setAbsolute(LossCategory::kRingOverwrite, 7ULL);
    session.loss().setAbsolute(LossCategory::kSourceDrop, 2ULL);
    session.processes().observeStart(makeProcessId(7000U, kT0 + 5ULL, "target.exe"), kT0 + 5ULL);
    session.apply(SessionAction::kStart);

    const TimelineEventCategory kCategories[] = {
        TimelineEventCategory::kProcess, TimelineEventCategory::kThread,
        TimelineEventCategory::kImage,   TimelineEventCategory::kFile,
        TimelineEventCategory::kRegistry, TimelineEventCategory::kNetwork,
    };
    for (int i = 0; i < 6; ++i) {
        const std::string kId = "s" + std::to_string(i);
        TimelineEvent event = makeEvent(kId.c_str(), "Kernel-Sample", kCategories[i], 7000U,
                                        makeTime(kBoot1,
                                                 kT0 + 100ULL + static_cast<std::uint64_t>(i) * 10000ULL,
                                                 kT0 + 200ULL, TimeResolution::kMicrosecond));
        event.rawFields.clear();
        event.rawFields.emplace_back("Payload", "payload-" + std::to_string(i));
        event.eventId = static_cast<std::uint32_t>(i + 1);
        if (i == 0) {
            event.sourceLinkId = "activity-A";
            event.sourceLinkField = "ActivityId";
        }
        session.ingest(event);
    }
    TimelineEvent unknownSchema =
        makeEvent("s6", "Third-Party", TimelineEventCategory::kOther, 7000U,
                  makeTime(kBoot1, kT0 + 100ULL + 60000ULL, kT0 + 200ULL, TimeResolution::kMicrosecond));
    unknownSchema.rawFields.clear();
    unknownSchema.rawFields.emplace_back("Payload", "payload-6");
    unknownSchema.eventVersion = 9U;
    unknownSchema.parseOutcome = EventParseOutcome::kUnparsedUnknownSchema;
    unknownSchema.parserId.clear();
    unknownSchema.parserVersion = 0U;
    unknownSchema.rawPayloadHex = "CAFEBABE";
    session.ingest(unknownSchema);
    session.apply(SessionAction::kStopCollection);
    return session;
}

void testPersistence(ksword_tests::Suite& s) {
    const TimelineSession kOriginal = buildPersistenceSession();
    s.expect(kOriginal.events().size() == 7U, L"T-09 the sample session holds seven events");

    const std::string kText = serializeSession(kOriginal, 2U);
    const std::vector<std::string> kLines = splitTextLines(kText);
    // Manual calculation: 1 header line + ceil(7/2)=4 batches + 1 trailer line = 6 lines.
    s.expect(kLines.size() == 6U, L"T-09 the file is header + 4 batches + trailer");

    const SessionLoadResult kLoaded = loadSession(kText);
    s.expect(kLoaded.status == SessionLoadStatus::kOk, L"T-09 a complete file loads cleanly");
    s.expect(kLoaded.recoveredEventCount == 7U && kLoaded.committedBatchCount == 4U,
             L"T-09 all seven events across four committed batches are recovered");
    s.expect(kLoaded.uncommittedEventCount == 0U, L"T-09 nothing is left uncommitted");
    s.expect(kLoaded.fileFormatVersion == 1U, L"T-09 the file declares format version 1");

    // Statistics consistency: expected values are the manually written 7 / 2 / "ring.OverwriteCount" in the test.
    s.expect(kLoaded.session.loss().counter(LossCategory::kRingOverwrite).count.present &&
                 kLoaded.session.loss().counter(LossCategory::kRingOverwrite).count.value == 7ULL,
             L"T-09 the ring overwrite count survives the round trip");
    s.expect(kLoaded.session.loss().counter(LossCategory::kRingOverwrite).statisticSource ==
                 "ring.OverwriteCount",
             L"T-09 the statistic source name survives the round trip");
    s.expect(kLoaded.session.loss().counter(LossCategory::kSourceDrop).count.value == 2ULL,
             L"T-09 the source drop count survives the round trip");
    s.expect(kLoaded.session.loss().totalLost().present &&
                 kLoaded.session.loss().totalLost().value == 9ULL,
             L"T-09 the restored total is 7+2 = 9");

    // Sampling consistency: the 4th item (index 3) is a File class with payload-3.
    s.expect(kLoaded.session.events().size() == 7U, L"T-09 seven events are in the reopened session");
    const TimelineEvent& sample = elementOrDefault(kLoaded.session.events(), 3);
    s.expect(sample.recordId == "s3" && sample.category == TimelineEventCategory::kFile,
             L"T-09 the sampled event keeps its id and category");
    s.expect(sample.rawFields.size() == 1U && sample.rawFields[0].first == "Payload" &&
                 sample.rawFields[0].second == "payload-3",
             L"T-09 the sampled event keeps its raw field");
    s.expect(sample.time.sourceTime100ns.present &&
                 sample.time.sourceTime100ns.value == kT0 + 100ULL + 30000ULL,
             L"T-09 the sampled source time is byte-identical after reopening");
    s.expect(sample.arrivalSequence == 4U, L"T-09 the arrival sequence survives");
    const TimelineEvent& unparsed = elementOrDefault(kLoaded.session.events(), 6);
    s.expect(unparsed.parseOutcome == EventParseOutcome::kUnparsedUnknownSchema &&
                 unparsed.parserVersion == 0U && unparsed.eventVersion == 9U,
             L"T-09 the unparsed record reopens as an unparsed record with its own version");
    s.expect(unparsed.rawPayloadHex == "CAFEBABE",
             L"T-09 the unparsed record keeps its raw payload");
    s.expect(kLoaded.session.manifest().capabilities.size() == 2U,
             L"T-09 the collector capabilities are stored with the session");
    s.expect(elementOrDefault(kLoaded.session.manifest().capabilities, 1).availability.status ==
                 CollectionStatus::kAccessDenied,
             L"T-09 an unavailable collector keeps its failure status");
    s.expect(elementOrDefault(kLoaded.session.manifest().capabilities, 1).availability.nativeCode.present &&
                 elementOrDefault(kLoaded.session.manifest().capabilities, 1).availability.nativeCode.value ==
                     0xC0000022ULL,
             L"T-09 the native error code is preserved, not flattened");
    s.expect(kLoaded.session.manifest().queryRangeBegin100ns.present &&
                 kLoaded.session.manifest().queryRangeBegin100ns.value == kT0,
             L"T-09 the query range is stored with the session");
    s.expect(kLoaded.session.state() == SessionState::kSaved,
             L"T-09 a reopened session is read-only, never Collecting");
    s.expect(!sessionAcceptsNewEvents(kLoaded.session.state()),
             L"T-09 reopening offline cannot start recording anything");

    // Truncate tail: only commit submitted batches. Manual calc: keep header + batch0 + batch1 = 4 events.
    std::string truncated = elementOrDefault(kLines, 0) + elementOrDefault(kLines, 1) + elementOrDefault(kLines, 2) + elementOrDefault(kLines, 3).substr(0, 25U);
    const SessionLoadResult kTruncatedResult = loadSession(truncated);
    s.expect(kTruncatedResult.status == SessionLoadStatus::kIncompleteTail,
             L"T-10 a truncated tail is IncompleteTail, not Corrupt");
    s.expect(kTruncatedResult.recoveredEventCount == 4U,
             L"T-10 the two complete batches before the cut are still recovered");
    s.expect(kTruncatedResult.committedBatchCount == 2U,
             L"T-10 exactly two committed batches are reported");
    s.expect(kTruncatedResult.diagnosticKey == "timeline.load.unterminated-final-line",
             L"T-10 the truncation diagnostic is specific");
    s.expect(truncated.size() == elementOrDefault(kLines, 0).size() + elementOrDefault(kLines, 1).size() + elementOrDefault(kLines, 2).size() + 25U,
             L"T-10 loading does not modify the source text");

    // Missing trailer: the batch is complete, but the session did not end normally.
    const std::string kNoTrailer = elementOrDefault(kLines, 0) + elementOrDefault(kLines, 1) + elementOrDefault(kLines, 2) + elementOrDefault(kLines, 3) + elementOrDefault(kLines, 4);
    const SessionLoadResult kNoTrailerResult = loadSession(kNoTrailer);
    s.expect(kNoTrailerResult.status == SessionLoadStatus::kIncompleteTail &&
                 kNoTrailerResult.diagnosticKey == "timeline.load.missing-trailer",
             L"T-10 a missing trailer is reported as an incomplete tail");
    s.expect(kNoTrailerResult.recoveredEventCount == 7U,
             L"T-10 every committed batch is still recovered without a trailer");

    // Corrupted first batch: checksum mismatch; no recoverable batches exist prior.
    std::string corruptFirst = kText;
    const std::size_t kFirstPayload = corruptFirst.find("payload-0");
    s.expect(kFirstPayload != std::string::npos, L"T-10 the corruption target exists");
    if (kFirstPayload != std::string::npos) {
        corruptFirst.replace(kFirstPayload, 9U, "payload-Z");
    }
    const SessionLoadResult kCorruptFirstResult = loadSession(corruptFirst);
    s.expect(kCorruptFirstResult.status == SessionLoadStatus::kCorrupt &&
                 kCorruptFirstResult.diagnosticKey == "timeline.load.batch-checksum-mismatch",
             L"T-10 a silently altered batch is detected as corrupt");
    s.expect(kCorruptFirstResult.recoveredEventCount == 0U,
             L"T-10 nothing is recovered when the first batch is the corrupt one");

    // Corrupt the second batch: the first batch remains recoverable.
    std::string corruptSecond = kText;
    const std::size_t kSecondPayload = corruptSecond.find("payload-2");
    if (kSecondPayload != std::string::npos) {
        corruptSecond.replace(kSecondPayload, 9U, "payload-Y");
    }
    const SessionLoadResult kCorruptSecondResult = loadSession(corruptSecond);
    s.expect(kCorruptSecondResult.status == SessionLoadStatus::kCorrupt,
             L"T-10 corruption in a later batch is still corrupt");
    s.expect(kCorruptSecondResult.recoveredEventCount == 2U &&
                 kCorruptSecondResult.committedBatchCount == 1U,
             L"T-10 the committed batch before the corruption is preserved");
    s.expect(kCorruptSecondResult.failedLineIndex == 2U,
             L"T-10 the failing line is identified");

    // Version too new: independent status; do not guess-read or modify the file.
    std::string tooNew = kText;
    const std::size_t kVersionPos = tooNew.find("\"formatVersion\":1");
    s.expect(kVersionPos != std::string::npos, L"T-10 the format version field is present");
    if (kVersionPos != std::string::npos) {
        tooNew.replace(kVersionPos, 17U, "\"formatVersion\":9");
    }
    const std::string kTooNewCopy = tooNew;
    const SessionLoadResult kTooNewResult = loadSession(tooNew);
    s.expect(kTooNewResult.status == SessionLoadStatus::kVersionTooNew,
             L"T-10 a newer format version has its own status");
    s.expect(kTooNewResult.fileFormatVersion == 9U,
             L"T-10 the newer version number is reported back");
    s.expect(kTooNewResult.recoveredEventCount == 0U,
             L"T-10 nothing is guessed out of a newer format");
    s.expect(tooNew == kTooNewCopy, L"T-10 the source text is untouched by the failed load");

    // Invalid header and empty input.
    const SessionLoadResult kGarbage = loadSession("this is not json\n");
    s.expect(kGarbage.status == SessionLoadStatus::kMissingHeader,
             L"T-10 a garbage first line is a missing header");
    s.expect(loadSession("").status == SessionLoadStatus::kEmpty,
             L"T-10 an empty file is Empty, not Corrupt");
    const SessionLoadResult kWrongKind = loadSession("{\"kind\":\"something.else\"}\n");
    s.expect(kWrongKind.status == SessionLoadStatus::kMissingHeader &&
                 kWrongKind.diagnosticKey == "timeline.load.header-kind-mismatch",
             L"T-10 a foreign JSON document is rejected by kind");

    // Trailer count mismatch.
    std::string mismatched = kText;
    const std::size_t kCountPos = mismatched.find("\"eventCount\":\"7\"");
    s.expect(kCountPos != std::string::npos, L"T-10 the trailer event count is present");
    if (kCountPos != std::string::npos) {
        mismatched.replace(kCountPos, 16U, "\"eventCount\":\"9\"");
    }
    const SessionLoadResult kMismatchResult = loadSession(mismatched);
    s.expect(kMismatchResult.status == SessionLoadStatus::kTrailerMismatch,
             L"T-10 a trailer that disagrees with the data is its own status");
    s.expect(kMismatchResult.recoveredEventCount == 7U,
             L"T-10 the recovered events are still reported on a trailer mismatch");

    // Uncommitted tail batch: do not restore, but report the count.
    TimelineSession mini(makeManifest(), makeRoomyDeclaredBounds());
    declareAllLossSources(mini.loss());
    mini.apply(SessionAction::kStart);
    mini.ingest(makeEvent("u0", "P", TimelineEventCategory::kProcess, 100U,
                          makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond)));
    mini.ingest(makeEvent("u1", "P", TimelineEventCategory::kProcess, 100U,
                          makeTime(kBoot1, kT0 + 10000ULL, kT0, TimeResolution::kMicrosecond)));
    mini.apply(SessionAction::kStopCollection);
    SessionBatch committedBatch;
    committedBatch.batchIndex = 0U;
    committedBatch.committed = true;
    committedBatch.events.assign(mini.events().begin(), mini.events().end());
    SessionBatch pendingBatch;
    pendingBatch.batchIndex = 1U;
    pendingBatch.committed = false;
    pendingBatch.events.push_back(makeEvent("u2", "P", TimelineEventCategory::kProcess, 100U,
                                            makeTime(kBoot1, kT0 + 20000ULL, kT0,
                                                     TimeResolution::kMicrosecond)));
    pendingBatch.events.push_back(makeEvent("u3", "P", TimelineEventCategory::kProcess, 100U,
                                            makeTime(kBoot1, kT0 + 30000ULL, kT0,
                                                     TimeResolution::kMicrosecond)));
    const std::string kPendingText = serializeSessionHeaderLine(mini) +
                                    serializeBatchLine(committedBatch) +
                                    serializeBatchLine(pendingBatch) + serializeTrailerLine(mini, 1U);
    const SessionLoadResult kPendingResult = loadSession(kPendingText);
    s.expect(kPendingResult.status == SessionLoadStatus::kIncompleteTail &&
                 kPendingResult.diagnosticKey == "timeline.load.uncommitted-batch-present",
             L"T-10 an uncommitted batch keeps the load from claiming a clean file");
    s.expect(kPendingResult.recoveredEventCount == 2U,
             L"T-10 only the committed batch is recovered");
    s.expect(kPendingResult.uncommittedEventCount == 2U,
             L"T-10 the uncommitted events are reported as missing, not as recovered");
}

// ---------------------------------------------------------------------------
// T-12 Relations do not impersonate causality
// ---------------------------------------------------------------------------
void testRelationEdges(ksword_tests::Suite& s) {
    s.expect(edgeKindAllowsCausalWording(TimelineEdgeKind::kSourceProvidedLink),
             L"T-12 only a source-provided link may carry causal wording");
    s.expect(!edgeKindAllowsCausalWording(TimelineEdgeKind::kTemporalNeighbor),
             L"T-12 temporal adjacency is never causal");
    s.expect(!edgeKindAllowsCausalWording(TimelineEdgeKind::kSameProcess),
             L"T-12 same-process is never causal");
    s.expect(!edgeKindAllowsCausalWording(TimelineEdgeKind::kParentChild),
             L"T-12 parent-child is never causal");

    // Two events that are close in time but completely unrelated: different process instances with no source correlation.
    TimelineEvent left = makeEvent("x1", "Kernel-Process", TimelineEventCategory::kProcess, 9100U,
                                   makeTime(kBoot1, kT0 + 1000ULL, kT0, TimeResolution::kMicrosecond));
    left.processInstanceKey = "proc-instance-9100";
    left.arrivalSequence = 1U;
    TimelineEvent right = makeEvent("x2", "Kernel-File", TimelineEventCategory::kFile, 9200U,
                                    makeTime(kBoot1, kT0 + 1200ULL, kT0, TimeResolution::kMicrosecond));
    right.processInstanceKey = "proc-instance-9200";
    right.arrivalSequence = 2U;
    const std::vector<TimelineEvent> kUnrelated = { left, right };

    EdgeBuildOptions options;
    options.temporalNeighborWindow100ns = OptionalU64::of(5000ULL);
    const std::vector<TimelineEdge> kEdges = buildEdges(kUnrelated, {}, options);
    s.expect(kEdges.size() == 1U, L"T-12 two unrelated neighbours produce exactly one edge");
    s.expect(countEdges(kEdges, TimelineEdgeKind::kTemporalNeighbor) == 1U,
             L"T-12 that edge is a temporal neighbour");
    s.expect(countEdges(kEdges, TimelineEdgeKind::kSameProcess) == 0U &&
                 countEdges(kEdges, TimelineEdgeKind::kParentChild) == 0U &&
                 countEdges(kEdges, TimelineEdgeKind::kSourceProvidedLink) == 0U,
             L"T-12 no causal-capable edge is invented between unrelated events");
    s.expect(!kEdges.empty() && kEdges[0].basisKey == "timeline.edge.basis.adjacent-in-time-only",
             L"T-12 the basis of the edge says it is adjacency only");
    // Hand-computed: 1200 - 1000 = 200
    s.expect(!kEdges.empty() && kEdges[0].temporalGap100ns.present &&
                 kEdges[0].temporalGap100ns.value == 200ULL,
             L"T-12 the temporal gap is the hand-computed 200");
    s.expect(!kEdges.empty() && !edgeKindAllowsCausalWording(kEdges[0].kind),
             L"T-12 the produced edge refuses causal wording");

    // Without a window, no 'neighbor' edges are generated.
    EdgeBuildOptions noWindow;
    const std::vector<TimelineEdge> kNoNeighbour = buildEdges(kUnrelated, {}, noWindow);
    s.expect(countEdges(kNoNeighbour, TimelineEdgeKind::kTemporalNeighbor) == 0U,
             L"T-12 adjacency edges only exist when a window is requested");

    // Not considered adjacent if outside the window.
    EdgeBuildOptions tinyWindow;
    tinyWindow.temporalNeighborWindow100ns = OptionalU64::of(100ULL);
    s.expect(countEdges(buildEdges(kUnrelated, {}, tinyWindow), TimelineEdgeKind::kTemporalNeighbor) == 0U,
             L"T-12 a gap larger than the window produces no adjacency edge");

    // Same instance: Create a SameProcess edge.
    TimelineEvent sameA = left;
    TimelineEvent sameB = right;
    sameB.processInstanceKey = "proc-instance-9100";
    const std::vector<TimelineEvent> kSameProcess = { sameA, sameB };
    const std::vector<TimelineEdge> kSameEdges = buildEdges(kSameProcess, {}, noWindow);
    s.expect(hasEdge(kSameEdges, TimelineEdgeKind::kSameProcess, "x1", "x2"),
             L"T-12 two events of the same confirmed instance are linked as SameProcess");
    s.expect(!kSameEdges.empty() && kSameEdges[0].basisDetail == "proc-instance-9100",
             L"T-12 the SameProcess basis names the instance key it used");

    // Counterexample: same PID but incomplete identity (no instance key) — never create an edge.
    TimelineEvent provisionalA = left;
    provisionalA.processInstanceKey.clear();
    provisionalA.provisionalProcessId = "prov:boot-T-1:pid=9100:Provisional";
    TimelineEvent provisionalB = right;
    provisionalB.pid = OptionalU64::of(9100ULL);
    provisionalB.processInstanceKey.clear();
    provisionalB.provisionalProcessId = "prov:boot-T-1:pid=9100:Provisional";
    const std::vector<TimelineEvent> kProvisionalPair = { provisionalA, provisionalB };
    s.expect(countEdges(buildEdges(kProvisionalPair, {}, noWindow), TimelineEdgeKind::kSameProcess) == 0U,
             L"T-12 a bare PID never produces a SameProcess edge");

    // Association directly provided by the source.
    TimelineEvent linkedA = left;
    linkedA.sourceLinkId = "activity-7";
    linkedA.sourceLinkField = "ActivityId";
    TimelineEvent linkedB = right;
    linkedB.sourceLinkId = "activity-7";
    linkedB.sourceLinkField = "ActivityId";
    const std::vector<TimelineEvent> kLinked = { linkedA, linkedB };
    const std::vector<TimelineEdge> kLinkedEdges = buildEdges(kLinked, {}, noWindow);
    s.expect(hasEdge(kLinkedEdges, TimelineEdgeKind::kSourceProvidedLink, "x1", "x2"),
             L"T-12 a shared source-provided link id builds a SourceProvidedLink edge");
    bool linkBasisOk = false;
    for (const TimelineEdge& edge : kLinkedEdges) {
        if (edge.kind == TimelineEdgeKind::kSourceProvidedLink && edge.basisDetail == "ActivityId=activity-7") {
            linkBasisOk = true;
        }
    }
    s.expect(linkBasisOk, L"T-12 the source link edge names the field and value it came from");

    // Parent-child: the creation fact provided by the source, and the parent instance must have a clickable event in the session.
    TimelineEvent parentEvent = makeEvent("pa", "Kernel-Process", TimelineEventCategory::kProcess,
                                          9000U,
                                          makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond));
    parentEvent.processInstanceKey = "proc-parent";
    TimelineEvent childEvent = makeEvent("ch", "Kernel-Process", TimelineEventCategory::kProcess,
                                         9100U,
                                         makeTime(kBoot1, kT0 + 500ULL, kT0,
                                                  TimeResolution::kMicrosecond));
    childEvent.processInstanceKey = "proc-child";
    ParentChildFact fact;
    fact.recordId = "ch";
    fact.childInstanceKey = "proc-child";
    fact.parentInstanceKey = "proc-parent";
    const std::vector<TimelineEvent> kFamily = { parentEvent, childEvent };
    const std::vector<TimelineEdge> kFamilyEdges = buildEdges(kFamily, { fact }, noWindow);
    s.expect(hasEdge(kFamilyEdges, TimelineEdgeKind::kParentChild, "pa", "ch"),
             L"T-12 a source-provided creation fact builds a ParentChild edge");

    ParentChildFact orphanFact = fact;
    orphanFact.parentInstanceKey = "proc-missing";
    s.expect(countEdges(buildEdges(kFamily, { orphanFact }, noWindow), TimelineEdgeKind::kParentChild) == 0U,
             L"T-12 a parent with no event in the session yields no unprovable edge");
}

// ---------------------------------------------------------------------------
// Session envelope (reuses F-layer criteria).
// ---------------------------------------------------------------------------
void testSessionEnvelope(ksword_tests::Suite& s) {
    TimelineSession fresh(makeManifest(), makeRoomyDeclaredBounds());
    const EvidenceEnvelope kFreshEnvelope = buildSessionEnvelope(fresh);
    s.expect(kFreshEnvelope.outcome.status == CollectionStatus::kNotCollected,
             L"T-06 a session that never ran is NotCollected, not an empty Success");
    s.expect(kFreshEnvelope.deriveConclusion(false) == AnalysisConclusion::kNoEvidence,
             L"T-06 a session that never ran yields NoEvidence, not NoDifferenceObserved");

    TimelineSession unaccounted(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    unaccounted.apply(SessionAction::kStart);
    unaccounted.ingest(makeEvent("a1", "P", TimelineEventCategory::kProcess, 100U,
                                 makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond)));
    const EvidenceEnvelope kUnaccountedEnvelope = buildSessionEnvelope(unaccounted);
    s.expect(kUnaccountedEnvelope.outcome.status == CollectionStatus::kPartial,
             L"T-06 a session with an unfilled loss ledger is Partial, never Success");
    s.expect(kUnaccountedEnvelope.outcome.message == "loss accounting incomplete",
             L"T-06 the Partial names the loss ledger as the reason, not the collectors");
    s.expect(!kUnaccountedEnvelope.coverage.processedBegin.present,
             L"T-06 an unfilled ledger withholds the processed-range positive evidence");
    s.expect(!kUnaccountedEnvelope.coverage.fullyCovered(),
             L"T-06 an unfilled ledger is never full coverage");

    TimelineSession accounted(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    declareAllLossSources(accounted.loss());
    accounted.apply(SessionAction::kStart);
    accounted.ingest(makeEvent("b1", "P", TimelineEventCategory::kProcess, 100U,
                               makeTime(kBoot1, kT0 + 10ULL, kT0, TimeResolution::kMicrosecond)));
    accounted.ingest(makeEvent("b2", "P", TimelineEventCategory::kProcess, 100U,
                               makeTime(kBoot1, kT0 + 20000ULL, kT0, TimeResolution::kMicrosecond)));
    const EvidenceEnvelope kAccountedEnvelope = buildSessionEnvelope(accounted);
    // New criterion: requires that every declared collector in the manifest is Success.
    s.expect(kAccountedEnvelope.outcome.status == CollectionStatus::kSuccess,
             L"T-06 fully accounted + unfiltered + within bounds + every declared collector Success = Success");
    s.expect(kAccountedEnvelope.coverage.processedBegin.present &&
                 kAccountedEnvelope.coverage.processedBegin.value == kT0 + 10ULL &&
                 kAccountedEnvelope.coverage.processedEnd.value == kT0 + 20000ULL,
             L"T-06 the processed range is the observed min and max effective time");
    s.expect(!kAccountedEnvelope.coverage.totalKnown.present,
             L"T-06 a timeline never claims to know how many events the system produced");
    s.expect(kAccountedEnvelope.coverage.succeeded == 2U,
             L"T-06 the coverage account carries the retained event count");
    s.expect(kAccountedEnvelope.source.origin == SourceOrigin::kLiveUserMode,
             L"T-06 a live session is not labelled as an offline sample");
}


// ---------------------------------------------------------------------------
// T-06 Collector capability must be read, not just written without inspection.
// ---------------------------------------------------------------------------
void testCollectorAvailability(ksword_tests::Suite& s) {
    // Declare two collectors: one Error (intended for File) and one Unsupported (intended for Registry).
    // Neither event type is collected: this does not mean "no events occurred in the system";
    // exporting a full collection would incorrectly present a collection failure as normal behavior.
    SessionManifest manifest = makeManifest();
    CollectorCapability fileCollector;
    fileCollector.collectorId = "etw.file";
    fileCollector.collectorVersion = 1U;
    fileCollector.sourceGroup = "etw.file";
    fileCollector.origin = SourceOrigin::kLiveKernel;
    fileCollector.declaredCategories.push_back(TimelineEventCategory::kFile);
    fileCollector.availability = CollectionOutcome::failure(CollectionStatus::kError, "WIN32", 5ULL,
                                                            "StartTrace failed");
    manifest.capabilities.push_back(fileCollector);
    CollectorCapability registryCollector;
    registryCollector.collectorId = "r0.registry";
    registryCollector.collectorVersion = 2U;
    registryCollector.sourceGroup = "r0.registry";
    registryCollector.origin = SourceOrigin::kLiveKernel;
    registryCollector.declaredCategories.push_back(TimelineEventCategory::kRegistry);
    registryCollector.availability.status = CollectionStatus::kUnsupported;
    manifest.capabilities.push_back(registryCollector);

    TimelineSession broken(manifest, makeRoomyDeclaredBounds());
    declareAllLossSources(broken.loss());
    broken.apply(SessionAction::kStart);
    broken.ingest(makeEvent("cap1", "P", TimelineEventCategory::kProcess, 100U,
                            makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond)));
    s.expect(broken.events().size() == 1U && broken.loss().totalLost().present &&
                 broken.loss().totalLost().value == 0ULL,
             L"T-06 fixture: one event, zero accounted loss - only the collectors are broken");

    const ExportPlan kBrokenPlan = broken.buildExportPlan(ExportScope::kFullSession);
    s.expect(!kBrokenPlan.retainedSessionIsCompleteCapture,
             L"T-06 a session whose declared File and Registry collectors never ran is NOT a complete capture");
    s.expect(kBrokenPlan.unavailableCollectorCount == 2U,
             L"T-06 both unavailable collectors are counted (hand-count: 2 of 2 declared)");
    s.expect(containsKey(kBrokenPlan.noticeKeys,
                         "timeline.export.collector-unavailable:etw.file:Error:File"),
             L"T-06 the notice names the collector, its status and the category it owed");
    s.expect(containsKey(kBrokenPlan.noticeKeys,
                         "timeline.export.collector-unavailable:r0.registry:Unsupported:Registry"),
             L"T-06 an unsupported collector gets its own notice with its own category");

    const EvidenceEnvelope kBrokenEnvelope = buildSessionEnvelope(broken);
    s.expect(kBrokenEnvelope.outcome.status == CollectionStatus::kPartial,
             L"T-06 an unavailable declared collector downgrades the envelope to Partial, never Success");
    s.expect(kBrokenEnvelope.outcome.nativeCodeDomain == "WIN32" &&
                 kBrokenEnvelope.outcome.nativeCode.present &&
                 kBrokenEnvelope.outcome.nativeCode.value == 5ULL,
             L"T-06 the failing collector native error domain and code reach the envelope outcome");
    s.expect(kBrokenEnvelope.outcome.message.find("StartTrace failed") != std::string::npos,
             L"T-06 the collector own failure message is carried, not replaced by a generic one");
    s.expect(kBrokenEnvelope.deriveConclusion(false) != AnalysisConclusion::kNoDifferenceObserved ||
                 statusCarriesObservation(kBrokenEnvelope.outcome.status),
             L"T-06 a Partial envelope still carries observation, so the conclusion path stays consistent");

    // Only if all are Success can the collection be considered complete — proving the new criterion is not 'always false'.
    TimelineSession healthy(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    declareAllLossSources(healthy.loss());
    healthy.apply(SessionAction::kStart);
    healthy.ingest(makeEvent("cap2", "P", TimelineEventCategory::kProcess, 100U,
                             makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond)));
    s.expect(healthy.buildExportPlan(ExportScope::kFullSession).retainedSessionIsCompleteCapture,
             L"T-06 a session whose only declared collector succeeded can still be a complete capture");
    s.expect(buildSessionEnvelope(healthy).outcome.status == CollectionStatus::kSuccess,
             L"T-06 an all-Success capability set does not block Success");

    // T-06 Overwrite accounting: The count of entries excluded by collection filtering cannot be written as 0.
    // Hand-written data: 12 events total; 5 from PID 4100 admitted, 7 from PID 4200 excluded by collection filter.
    TimelineSession filtered(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    declareAllLossSources(filtered.loss());
    EventFilter onlyOne;
    onlyOne.active = true;
    onlyOne.ruleId = "capture.only-4100";
    onlyOne.allowedPids.push_back(4100ULL);
    filtered.setCollectionFilter(onlyOne);
    filtered.apply(SessionAction::kStart);
    for (int i = 0; i < 12; ++i) {
        const std::string kId = "cv" + std::to_string(i);
        filtered.ingest(makeEvent(kId.c_str(), "Kernel-File", TimelineEventCategory::kFile,
                                  i < 5 ? 4100ULL : 4200ULL,
                                  makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                           kT0, TimeResolution::kMicrosecond)));
    }
    s.expect(filtered.events().size() == 5U && filtered.collectionFilteredOutCount() == 7U,
             L"T-03 fixture: 5 admitted, 7 excluded by the collection filter (hand-count)");
    const EvidenceEnvelope kFilteredEnvelope = buildSessionEnvelope(filtered);
    s.expect(kFilteredEnvelope.coverage.skipped == 7U,
             L"T-06 coverage.skipped carries the 7 collection-filtered events, not a flattened 0");
    s.expect(kFilteredEnvelope.coverage.succeeded == 5U,
             L"T-06 coverage.succeeded carries the 5 retained events");
    s.expect(kFilteredEnvelope.outcome.status == CollectionStatus::kPartial,
             L"T-06 a collection-filtered session is Partial");
}

// ---------------------------------------------------------------------------
// T-06: The session declares its own four types of loss sources.
// ---------------------------------------------------------------------------
void testSelfDeclaredLossSources(ksword_tests::Suite& s) {
    // We intentionally do not call declareAllLossSources here: previously, the count of evicted events on this path did not
    // exist (count was unset, statisticSource was an empty string), so there was no way to track the number of dropped entries.
    TimelineSession session(makeManifestWithHealthyCollector(),
                            makeBounds(3ULL, RetentionPolicy::kEvictOldest));
    session.apply(SessionAction::kStart);
    for (int i = 0; i < 10; ++i) {
        const std::string kId = "sd" + std::to_string(i);
        session.ingest(makeEvent(kId.c_str(), "P", TimelineEventCategory::kProcess, 100U,
                                 makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                          kT0, TimeResolution::kMicrosecond)));
    }
    s.expect(session.events().size() == 3U, L"T-08 the eviction window holds 3 events (hand-count)");
    const LossCounter& evicted = session.loss().counter(LossCategory::kRetentionEvicted);
    s.expect(evicted.count.present && evicted.count.value == 7ULL,
             L"T-06 10 ingested minus 3 retained = 7 evictions are counted with no caller-side declareSource");
    s.expect(evicted.statisticSource == "local.retention" && !evicted.sourceIsAuthoritative,
             L"T-06 the session names the statistic source of its own retention losses");
    s.expect(session.loss().counter(LossCategory::kQueueDiscard).count.present &&
                 session.loss().counter(LossCategory::kParseFailure).count.present &&
                 session.loss().counter(LossCategory::kFilteredOut).count.present,
             L"T-06 all four locally generated categories start at an explained zero");
    s.expect(!session.loss().counter(LossCategory::kSourceDrop).count.present &&
                 session.loss().counter(LossCategory::kSourceDrop).statisticSource.empty(),
             L"T-06 the session does not fake a source for the two counters only the collector can report");

    // After reset, the four local categories must still have named sources; they cannot be cleared wholesale by LossLedger().
    session.apply(SessionAction::kStopCollection);
    session.apply(SessionAction::kReset);
    const LossCounter& afterReset = session.loss().counter(LossCategory::kRetentionEvicted);
    s.expect(afterReset.statisticSource == "local.retention" && afterReset.count.present &&
                 afterReset.count.value == 0ULL,
             L"T-06 Reset restores the explained zero instead of wiping the local sources");

    // Not recording in the ledger is a hard error: the class is marked as unknown, the total is unset accordingly, and this entry is never silently dropped.
    TimelineSession unbookable(makeManifestWithHealthyCollector(),
                               makeBounds(1ULL, RetentionPolicy::kEvictOldest));
    declareAllLossSources(unbookable.loss());
    // Force local accounting into source-authoritative mode so addObserved is rejected, simulating an external change to the accounting mode.
    unbookable.loss().mutableCounter(LossCategory::kRetentionEvicted).sourceIsAuthoritative = true;
    unbookable.apply(SessionAction::kStart);
    for (int i = 0; i < 3; ++i) {
        const std::string kId = "ub" + std::to_string(i);
        unbookable.ingest(makeEvent(kId.c_str(), "P", TimelineEventCategory::kProcess, 100U,
                                    makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                             kT0, TimeResolution::kMicrosecond)));
    }
    s.expect(unbookable.lossAccountingFailed(),
             L"T-06 a loss that cannot be booked is a hard error, not a dropped count");
    s.expect(!unbookable.loss().counter(LossCategory::kRetentionEvicted).count.present,
             L"T-06 the unbookable category is marked unknown instead of staying at a stale number");
    s.expect(!unbookable.loss().totalLost().present,
             L"T-06 the unbookable category poisons the total instead of silently reading 0");
    s.expect(!unbookable.buildExportPlan(ExportScope::kFullSession).retainedSessionIsCompleteCapture,
             L"T-06 a session whose accounting failed is never a complete capture");
}

// ---------------------------------------------------------------------------
// T-08 declared upper bound must be truly enforceable.
// ---------------------------------------------------------------------------
void testBoundsEnforceability(ksword_tests::Suite& s) {
    // Declared a 4096-byte disk limit but omitted the estimated byte count per entry: that limit will never take effect.
    BoundsPolicy unenforceable;
    unenforceable.maxArchiveBytes = OptionalU64::of(4096ULL);
    unenforceable.policy = RetentionPolicy::kStopOnLimit;
    unenforceable.declaredBeforeCollection = true;
    TimelineSession noPerEvent(makeManifest(), unenforceable);
    const SessionTransition kRejectedA = noPerEvent.apply(SessionAction::kStart);
    s.expect(!kRejectedA.allowed &&
                 kRejectedA.rejectionKey == "timeline.session.archive-limit-unenforceable",
             L"T-08 an archive limit with no bytes-per-event estimate is refused before collection starts");
    s.expect(noPerEvent.state() == SessionState::kNew,
             L"T-08 the refused Start leaves the session in New");

    BoundsPolicy zeroPerEvent = unenforceable;
    zeroPerEvent.approximateBytesPerEvent = OptionalU64::of(0ULL);
    TimelineSession zeroBytes(makeManifest(), zeroPerEvent);
    s.expect(zeroBytes.apply(SessionAction::kStart).rejectionKey ==
                 "timeline.session.archive-limit-unenforceable",
             L"T-08 a zero bytes-per-event estimate is just as unenforceable");

    // No upper limit convertible to a count -> the 'memory has an upper limit' criterion is empty.
    BoundsPolicy noLimit;
    noLimit.policy = RetentionPolicy::kStopOnLimit;
    noLimit.declaredBeforeCollection = true;
    TimelineSession unbounded(makeManifest(), noLimit);
    const SessionTransition kRejectedB = unbounded.apply(SessionAction::kStart);
    s.expect(!kRejectedB.allowed && kRejectedB.rejectionKey == "timeline.session.no-memory-bound",
             L"T-08 a bounds policy that declares no limit at all cannot start collecting");

    // Setting the estimated bytes per event allows the session to start, and the upper limit is enforced: manual calculation 4096 / 512 = 8 events.
    BoundsPolicy enforceable = unenforceable;
    enforceable.approximateBytesPerEvent = OptionalU64::of(512ULL);
    TimelineSession bounded(makeManifest(), enforceable);
    declareAllLossSources(bounded.loss());
    s.expect(bounded.apply(SessionAction::kStart).allowed,
             L"T-08 an enforceable archive limit is allowed to start");
    for (int i = 0; i < 20; ++i) {
        const std::string kId = "ae" + std::to_string(i);
        bounded.ingest(makeEvent(kId.c_str(), "P", TimelineEventCategory::kProcess, 100U,
                                 makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                          kT0, TimeResolution::kMicrosecond)));
    }
    s.expect(bounded.events().size() == 8U,
             L"T-08 4096 bytes at 512 bytes per event really bounds the session at 8 events");
    s.expect(bounded.boundsState() == BoundsState::kArchiveLimitReached,
             L"T-08 hitting the archive bound is reported as the archive bound");
    s.expect(bounded.loss().counter(LossCategory::kQueueDiscard).count.value == 12ULL,
             L"T-08 the 12 refused events are accounted, not silently dropped (hand-count: 20 - 8)");
}

// ---------------------------------------------------------------------------
// T-04 / T-12 recordId must be unique: it serves as the tiebreaker for sorting, the join key for edges, and the primary key for exports.
// ---------------------------------------------------------------------------
void testRecordIdDiscipline(ksword_tests::Suite& s) {
    TimelineSession session(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    session.apply(SessionAction::kStart);
    const IngestResult kFirst =
        session.ingest(makeEvent("dup", "P", TimelineEventCategory::kProcess, 100U,
                                 makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond)));
    s.expect(kFirst.accepted, L"T-04 the first event with a given record id is accepted");
    const IngestResult kRepeat =
        session.ingest(makeEvent("dup", "P", TimelineEventCategory::kProcess, 100U,
                                 makeTime(kBoot1, kT0 + 10000ULL, kT0, TimeResolution::kMicrosecond)));
    s.expect(!kRepeat.accepted && kRepeat.reasonKey == "timeline.ingest.duplicate-record-id",
             L"T-04 a duplicate record id is refused instead of producing two records that share a sort tiebreak");
    s.expect(kRepeat.countedAsLoss && kRepeat.lossCategory == LossCategory::kQueueDiscard,
             L"T-04 the refused duplicate is accounted as an R3-side discard, not silently swallowed");

    TimelineEvent nameless = makeEvent("x", "P", TimelineEventCategory::kProcess, 100U,
                                       makeTime(kBoot1, kT0 + 20000ULL, kT0,
                                                TimeResolution::kMicrosecond));
    nameless.recordId.clear();
    const IngestResult kEmpty = session.ingest(nameless);
    s.expect(!kEmpty.accepted && kEmpty.reasonKey == "timeline.ingest.missing-record-id",
             L"T-04 an event with no record id is refused: it has no final sort tiebreak and no export key");
    s.expect(session.events().size() == 1U,
             L"T-04 only the one well-formed event is retained (hand-count: 1)");
    s.expect(session.loss().counter(LossCategory::kQueueDiscard).count.value == 2ULL,
             L"T-04 both refusals are counted (hand-count: 1 duplicate + 1 nameless)");

    // After eviction, this ID becomes reusable again—the deduplication table follows the retention window and does not grow indefinitely.
    TimelineSession ring(makeManifestWithHealthyCollector(),
                         makeBounds(2ULL, RetentionPolicy::kEvictOldest));
    ring.apply(SessionAction::kStart);
    ring.ingest(makeEvent("g0", "P", TimelineEventCategory::kProcess, 100U,
                          makeTime(kBoot1, kT0, kT0, TimeResolution::kMicrosecond)));
    ring.ingest(makeEvent("g1", "P", TimelineEventCategory::kProcess, 100U,
                          makeTime(kBoot1, kT0 + 10000ULL, kT0, TimeResolution::kMicrosecond)));
    ring.ingest(makeEvent("g2", "P", TimelineEventCategory::kProcess, 100U,
                          makeTime(kBoot1, kT0 + 20000ULL, kT0, TimeResolution::kMicrosecond)));
    const IngestResult kReused =
        ring.ingest(makeEvent("g0", "P", TimelineEventCategory::kProcess, 100U,
                              makeTime(kBoot1, kT0 + 30000ULL, kT0, TimeResolution::kMicrosecond)));
    s.expect(kReused.accepted,
             L"T-08 a record id whose event was evicted can be used again by a later event");
}

// ---------------------------------------------------------------------------
// T-10: The loaded conclusion must be attached to the session; the trailer must be the last line; an invalid enumeration name implies a corrupted file.
// ---------------------------------------------------------------------------
void testLoadIntegrityPropagation(ksword_tests::Suite& s) {
    TimelineSession source(makeManifestWithHealthyCollector(), makeRoomyDeclaredBounds());
    declareAllLossSources(source.loss());
    source.loss().setAbsolute(LossCategory::kSourceDrop, 0ULL);
    source.loss().setAbsolute(LossCategory::kRingOverwrite, 0ULL);
    source.apply(SessionAction::kStart);
    for (int i = 0; i < 6; ++i) {
        const std::string kId = "L" + std::to_string(i);
        source.ingest(makeEvent(kId.c_str(), "P", TimelineEventCategory::kProcess, 100U,
                                makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                         kT0, TimeResolution::kMicrosecond)));
    }
    source.apply(SessionAction::kStopCollection);
    const std::string kText = serializeSession(source, 3U);
    const std::vector<std::string> kLines = splitTextLines(kText);
    // Manual calculation: 1 header line + ceil(6/3)=2 batches + 1 trailer line = 4 lines.
    s.expect(kLines.size() == 4U, L"T-09 six events at batch size three write header + 2 batches + trailer");

    // Baseline: A session recovered from a structurally complete file is still considered fully collected.
    const SessionLoadResult kClean = loadSession(kText);
    s.expect(kClean.status == SessionLoadStatus::kOk && kClean.recoveredEventCount == 6U,
             L"T-10 the complete file loads cleanly with all six events");
    s.expect(kClean.session.loadIntegrity().restoredFromFile &&
                 kClean.session.loadIntegrity().representsCompleteFile(),
             L"T-10 the loaded session itself knows it came from a structurally complete file");
    s.expect(kClean.unrecoverableEventCount == 0U &&
                 kClean.session.unrecoverableFileEventCount() == 0U,
             L"T-10 a complete file leaves nothing unrecoverable");
    s.expect(kClean.session.buildExportPlan(ExportScope::kFullSession).retainedSessionIsCompleteCapture,
             L"T-10 a session restored from a complete file may still export as a complete capture");
    s.expect(buildSessionEnvelope(kClean.session).outcome.status == CollectionStatus::kSuccess,
             L"T-10 a session restored from a complete file may still envelope as Success");

    // Missing trailer: the same 6 data entries, but the file does not end normally.
    const std::string kNoTrailer =
        elementOrDefault(kLines, 0) + elementOrDefault(kLines, 1) + elementOrDefault(kLines, 2);
    const SessionLoadResult kTail = loadSession(kNoTrailer);
    s.expect(kTail.status == SessionLoadStatus::kIncompleteTail && kTail.recoveredEventCount == 6U,
             L"T-10 a trailer-less file still recovers its six committed events");
    s.expect(kTail.session.loadIntegrity().restoredFromFile &&
                 kTail.session.loadIntegrity().status == SessionLoadStatus::kIncompleteTail,
             L"T-10 the loaded session carries the IncompleteTail verdict, not a clean slate");
    const ExportPlan kTailPlan = kTail.session.buildExportPlan(ExportScope::kFullSession);
    s.expect(!kTailPlan.retainedSessionIsCompleteCapture,
             L"T-10 the SAME six events restored from a trailer-less file are no longer a complete capture");
    s.expect(containsKey(kTailPlan.noticeKeys,
                         "timeline.export.restored-from-incomplete-file.IncompleteTail"),
             L"T-10 the export notice names the load status that made the session incomplete");
    const EvidenceEnvelope kTailEnvelope = buildSessionEnvelope(kTail.session);
    s.expect(kTailEnvelope.outcome.status == CollectionStatus::kPartial,
             L"T-10 a session restored from a trailer-less file envelopes as Partial, never Success");
    s.expect(kTailEnvelope.outcome.message.find("timeline.load.missing-trailer") != std::string::npos,
             L"T-10 the envelope message carries the load diagnostic key");

    // Trailer declares 9 entries, but only 6 were recovered: manual calculation shows 3 cannot be recovered.
    std::string mismatched = kText;
    const std::string kCountNeedle = "\"eventCount\":\"6\"";
    const std::size_t kCountPos = mismatched.find(kCountNeedle);
    s.expect(kCountPos != std::string::npos, L"T-10 the trailer event count field is present");
    if (kCountPos != std::string::npos) {
        mismatched.replace(kCountPos, kCountNeedle.size(), "\"eventCount\":\"9\"");
    }
    const SessionLoadResult kMismatch = loadSession(mismatched);
    s.expect(kMismatch.status == SessionLoadStatus::kTrailerMismatch,
             L"T-10 a trailer that disagrees with the data keeps its own status");
    s.expect(kMismatch.declaredEventCount == 9U && kMismatch.recoveredEventCount == 6U,
             L"T-10 both the declared and the recovered counts are reported");
    s.expect(kMismatch.unrecoverableEventCount == 3U &&
                 kMismatch.session.unrecoverableFileEventCount() == 3U,
             L"T-10 the 3 events the trailer claims but the file cannot produce are accounted (hand-count: 9 - 6)");
    s.expect(!kMismatch.session.buildExportPlan(ExportScope::kFullSession)
                  .retainedSessionIsCompleteCapture,
             L"T-10 a trailer-mismatched session is never exported as a complete capture");
    s.expect(buildSessionEnvelope(kMismatch.session).outcome.status == CollectionStatus::kPartial,
             L"T-10 a trailer-mismatched session envelopes as Partial");
    s.expect(buildSessionEnvelope(kMismatch.session).coverage.truncated == 3U,
             L"T-10 the unrecoverable events show up in the coverage account as truncated");

    // Content after the trailer: interrupted rewrite, appended batches, or a second trailer.
    const std::string kAfterTrailerBatch = kText + elementOrDefault(kLines, 1);
    const SessionLoadResult kAfterBatch = loadSession(kAfterTrailerBatch);
    s.expect(kAfterBatch.status == SessionLoadStatus::kCorrupt &&
                 kAfterBatch.diagnosticKey == "timeline.load.content-after-trailer",
             L"T-10 a batch line after the trailer is Corrupt, not a clean complete session");
    s.expect(!kAfterBatch.representsCompleteFile(),
             L"T-10 a file with content after its trailer never claims to be complete");
    const std::string kTwoTrailers = kText + elementOrDefault(kLines, 3);
    const SessionLoadResult kSecond = loadSession(kTwoTrailers);
    s.expect(kSecond.status == SessionLoadStatus::kCorrupt &&
                 kSecond.diagnosticKey == "timeline.load.content-after-trailer",
             L"T-10 a second trailer line is rejected the same way");

    // Written twice in the same batch: recordId is duplicated, corrupting the structure.
    const std::string kDuplicated = elementOrDefault(kLines, 0) + elementOrDefault(kLines, 1) +
                                   elementOrDefault(kLines, 1) + elementOrDefault(kLines, 3);
    const SessionLoadResult kDup = loadSession(kDuplicated);
    s.expect(kDup.status == SessionLoadStatus::kCorrupt &&
                 kDup.diagnosticKey == "timeline.load.duplicate-record-id",
             L"T-10 a repeated batch is detected through its duplicate record ids");
    s.expect(kDup.recoveredEventCount == 3U,
             L"T-10 the first copy of the batch is still recovered (hand-count: 3)");

    // Unrecognized enum names indicate bad files; do not silently fall back to a benign default.
    std::string badStatus = kText;
    const std::string kStatusNeedle = "\"availabilityStatus\":\"Success\"";
    const std::size_t kStatusPos = badStatus.find(kStatusNeedle);
    s.expect(kStatusPos != std::string::npos, L"T-10 the capability availability status field is present");
    if (kStatusPos != std::string::npos) {
        badStatus.replace(kStatusPos, kStatusNeedle.size(), "\"availabilityStatus\":\"HypervisorDenied\"");
    }
    const SessionLoadResult kBadStatusResult = loadSession(badStatus);
    s.expect(kBadStatusResult.status == SessionLoadStatus::kMissingHeader &&
                 kBadStatusResult.diagnosticKey == "timeline.load.header-fields-invalid",
             L"T-10 an unrecognised availabilityStatus fails the header instead of decoding to NotCollected");
    s.expect(kBadStatusResult.session.manifest().capabilities.empty(),
             L"T-10 nothing is half-restored out of a header carrying an unknown enum name");

    std::string badOrigin = kText;
    const std::string kOriginNeedle = "\"origin\":\"LiveKernel\"";
    const std::size_t kOriginPos = badOrigin.find(kOriginNeedle);
    s.expect(kOriginPos != std::string::npos, L"T-10 the capability origin field is present");
    if (kOriginPos != std::string::npos) {
        badOrigin.replace(kOriginPos, kOriginNeedle.size(), "\"origin\":\"LiveHypervisor\"");
    }
    s.expect(loadSession(badOrigin).status == SessionLoadStatus::kMissingHeader,
             L"T-10 an unrecognised source origin fails the header instead of decoding to Unknown");
    s.expect(badOrigin.find("LiveHypervisor") != std::string::npos,
             L"T-10 the failed load leaves the source text untouched");
}

// ---------------------------------------------------------------------------
// T-08 Streaming persistence: one line per write, do not concatenate the entire file into a single string.
// ---------------------------------------------------------------------------
void testStreamingSerialization(ksword_tests::Suite& s) {
    const TimelineSession kOriginal = buildPersistenceSession();
    const std::string kOneShot = serializeSession(kOriginal, 2U);

    std::vector<std::string> chunks;
    serializeSessionTo(kOriginal, 2U,
                       [&chunks](std::string_view line) { chunks.emplace_back(line); });
    // Manual calculation: 1 header line + ceil(7/2)=4 batches + 1 trailer line = 6 chunks.
    s.expect(chunks.size() == 6U, L"T-08 the streaming writer yields exactly 6 chunks for 7 events at batch size 2");
    std::string joined;
    for (const std::string& chunk : chunks) {
        joined += chunk;
    }
    s.expect(joined == kOneShot,
             L"T-08 the streamed bytes are identical to the one-shot serialization");
    bool everyChunkIsOneLine = true;
    for (const std::string& chunk : chunks) {
        if (chunk.empty() || chunk.back() != '\n' || chunk.find('\n') != chunk.size() - 1U) {
            everyChunkIsOneLine = false;
        }
    }
    s.expect(everyChunkIsOneLine,
             L"T-08 every streamed chunk is exactly one terminated line, so a sink can write it and forget it");
    s.expect(loadSession(joined).status == SessionLoadStatus::kOk,
             L"T-08 the streamed file loads back cleanly");

    std::size_t counted = 0;
    serializeSessionTo(kOriginal, 0U, [&counted](std::string_view) { ++counted; });
    // batchSize=0 is treated as one batch: header + 1 batch + trailer = 3 blocks (manual calculation).
    s.expect(counted == 3U, L"T-08 batch size zero streams header + one batch + trailer");
}

// ---------------------------------------------------------------------------
// Scale: the criterion is that when n doubles, the execution time must not approach quadrupling.
//
// The three hotspots were originally O(n^2): sortedOrder's uncertainty re-checking via linear table lookup by recordId,
// EvictOldest moving the entire retention window with vector::erase(begin()), and buildEdges' inner scan traversing to the
// array end when keys are distinct. Absolute execution time fluctuates with machine load, so we compare **ratios** here:
// O(n log n) / O(n) is approximately 2.1x, O(n^2) is 4x; threshold set to 3.0x with 20 ms jitter margin.
// Take the minimum of three measurements per run — the standard robust estimate for micro-benchmarks.
// ---------------------------------------------------------------------------
template <typename Fn>
double bestMillisOfThree(Fn&& fn) {
    double best = 0.0;
    for (int attempt = 0; attempt < 3; ++attempt) {
        const std::chrono::steady_clock::time_point kBegin = std::chrono::steady_clock::now();
        fn();
        const std::chrono::steady_clock::time_point kEnd = std::chrono::steady_clock::now();
        const double kElapsed = std::chrono::duration<double, std::milli>(kEnd - kBegin).count();
        if (attempt == 0 || kElapsed < best) {
            best = kElapsed;
        }
    }
    return best;
}

BoundsPolicy makeLargeBounds(std::uint64_t maxEvents, RetentionPolicy policy) {
    BoundsPolicy bounds;
    bounds.maxEventsInMemory = OptionalU64::of(maxEvents);
    bounds.policy = policy;
    bounds.declaredBeforeCollection = true;
    return bounds;
}

std::vector<TimelineEvent> makeSyntheticEvents(std::size_t count, bool uniqueLinkKeys) {
    std::vector<TimelineEvent> events;
    events.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::string kId = "n" + std::to_string(i);
        TimelineEvent event = makeEvent(kId.c_str(), "P", TimelineEventCategory::kProcess, 100U,
                                        makeTime(kBoot1, kT0 + static_cast<std::uint64_t>(i) * 10000ULL,
                                                 kT0, TimeResolution::kMicrosecond));
        event.arrivalSequence = static_cast<std::uint64_t>(i) + 1U;
        if (uniqueLinkKeys) {
            // Typical on a busy machine: instance keys and ActivityId values differ, so no edges can be constructed.
            event.processInstanceKey = "inst-" + std::to_string(i);
            event.sourceLinkId = "act-" + std::to_string(i);
            event.sourceLinkField = "ActivityId";
        }
        events.push_back(std::move(event));
    }
    return events;
}

void testScalability(ksword_tests::Suite& s) {
    // ---- sortedOrder ----
    const std::vector<TimelineEvent> kSortSmall = makeSyntheticEvents(6000U, false);
    const std::vector<TimelineEvent> kSortLarge = makeSyntheticEvents(12000U, false);
    TimelineSession sortSmallSession(makeManifest(), makeLargeBounds(200000ULL, RetentionPolicy::kStopOnLimit));
    TimelineSession sortLargeSession(makeManifest(), makeLargeBounds(200000ULL, RetentionPolicy::kStopOnLimit));
    sortSmallSession.apply(SessionAction::kStart);
    sortLargeSession.apply(SessionAction::kStart);
    for (const TimelineEvent& event : kSortSmall) {
        sortSmallSession.ingest(event);
    }
    for (const TimelineEvent& event : kSortLarge) {
        sortLargeSession.ingest(event);
    }
    s.expect(sortSmallSession.events().size() == 6000U && sortLargeSession.events().size() == 12000U,
             L"T-04 scale fixture: 6000 and 12000 events are retained");
    std::size_t sortSink = 0;
    const double kSortSmallMs = bestMillisOfThree([&sortSmallSession, &sortSink]() {
        sortSink += sortSmallSession.sortedOrder().size();
    });
    const double kSortLargeMs = bestMillisOfThree([&sortLargeSession, &sortSink]() {
        sortSink += sortLargeSession.sortedOrder().size();
    });
    s.expect(sortSink == 3U * (6000U + 12000U),
             L"T-04 scale fixture: every sortedOrder call returned one key per event");
    s.expect(kSortLargeMs <= 3.0 * kSortSmallMs + 20.0,
             L"T-04 doubling the event count must not quadruple sortedOrder: quadratic order-uncertainty lookup is refused");
    const std::vector<TimelineSortKey> kOrder = sortLargeSession.sortedOrder();
    s.expect(kOrder.size() == 12000U && elementOrDefault(kOrder, 0).recordId == "n0" &&
                 elementOrDefault(kOrder, 11999U).recordId == "n11999",
             L"T-04 the hand-written expected order still holds at scale: n0 first, n11999 last");

    // ---- EvictOldest ----
    // Both cases evict exactly 5000 entries, differing only in the retention window size (500 vs. 4000).
    // The O(1) eviction time scales with the number of queued items (5500 -> 9000, approximately 1.6x):
    // The implementation for moving the entire window scales with window size (500 -> 4000, approx. 8x).
    const std::vector<TimelineEvent> kEvictSmall = makeSyntheticEvents(5500U, false);
    const std::vector<TimelineEvent> kEvictLarge = makeSyntheticEvents(9000U, false);
    std::size_t evictSink = 0;
    const double kEvictSmallMs = bestMillisOfThree([&kEvictSmall, &evictSink]() {
        TimelineSession session(makeManifest(), makeLargeBounds(500ULL, RetentionPolicy::kEvictOldest));
        session.apply(SessionAction::kStart);
        for (const TimelineEvent& event : kEvictSmall) {
            session.ingest(event);
        }
        evictSink += session.events().size();
    });
    const double kEvictLargeMs = bestMillisOfThree([&kEvictLarge, &evictSink]() {
        TimelineSession session(makeManifest(), makeLargeBounds(4000ULL, RetentionPolicy::kEvictOldest));
        session.apply(SessionAction::kStart);
        for (const TimelineEvent& event : kEvictLarge) {
            session.ingest(event);
        }
        evictSink += session.events().size();
    });
    s.expect(evictSink == 3U * (500U + 4000U),
             L"T-08 scale fixture: each run retained exactly its configured window");
    s.expect(kEvictLargeMs <= 3.0 * kEvictSmallMs + 20.0,
             L"T-08 the same number of evictions must not cost 8x more just because the window is 8x larger");

    // ---- buildEdges ----
    const std::vector<TimelineEvent> kEdgeSmall = makeSyntheticEvents(16000U, true);
    const std::vector<TimelineEvent> kEdgeLarge = makeSyntheticEvents(32000U, true);
    EdgeBuildOptions noWindow;
    std::size_t edgeSink = 0;
    const double kEdgeSmallMs = bestMillisOfThree([&kEdgeSmall, &noWindow, &edgeSink]() {
        edgeSink += buildEdges(kEdgeSmall, {}, noWindow).size();
    });
    const double kEdgeLargeMs = bestMillisOfThree([&kEdgeLarge, &noWindow, &edgeSink]() {
        edgeSink += buildEdges(kEdgeLarge, {}, noWindow).size();
    });
    s.expect(edgeSink == 0U,
             L"T-12 scale fixture: all keys are distinct, so no edge is produced at either size");
    s.expect(kEdgeLargeMs <= 3.0 * kEdgeSmallMs + 20.0,
             L"T-12 doubling the event count must not quadruple BuildEdges: the no-match full scan is refused");

    // After grouping, the edge value semantics remain unchanged: it only connects to the next event with the same key and is clickable.
    std::vector<TimelineEvent> paired = makeSyntheticEvents(5000U, true);
    paired[0].processInstanceKey = "shared-instance";
    paired[4999].processInstanceKey = "shared-instance";
    paired[1].sourceLinkId = "shared-activity";
    paired[2].sourceLinkId = "shared-activity";
    paired[3].sourceLinkId = "shared-activity";
    const std::vector<TimelineEdge> kPairedEdges = buildEdges(paired, {}, noWindow);
    s.expect(countEdges(kPairedEdges, TimelineEdgeKind::kSameProcess) == 1U &&
                 hasEdge(kPairedEdges, TimelineEdgeKind::kSameProcess, "n0", "n4999"),
             L"T-12 one shared instance key across 5000 events builds exactly one SameProcess edge, n0 -> n4999");
    s.expect(countEdges(kPairedEdges, TimelineEdgeKind::kSourceProvidedLink) == 2U &&
                 hasEdge(kPairedEdges, TimelineEdgeKind::kSourceProvidedLink, "n1", "n2") &&
                 hasEdge(kPairedEdges, TimelineEdgeKind::kSourceProvidedLink, "n2", "n3"),
             L"T-12 three events sharing one activity id chain into 2 edges, each to the next one only");
}

} // namespace

int runTimelineTests() {
    ksword_tests::Suite suite(L"T timeline");
    testSessionLifecycle(suite);
    testEventEnvelope(suite);
    testTimeSemantics(suite);
    testAttribution(suite);
    testLossAccounting(suite);
    testFilterSeparation(suite);
    testPersistence(suite);
    testRelationEdges(suite);
    testSessionEnvelope(suite);
    testCollectorAvailability(suite);
    testSelfDeclaredLossSources(suite);
    testBoundsEnforceability(suite);
    testRecordIdDiscipline(suite);
    testLoadIntegrityPropagation(suite);
    testStreamingSerialization(suite);
    testScalability(suite);
    suite.report();
    return suite.failures();
}
