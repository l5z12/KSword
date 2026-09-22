#include "TimelineCore.h"

#include <algorithm>
#include <limits>
#include <unordered_map>
#include <utility>

namespace ksword::evidence {
namespace {

// FNV-1a 64. Used only for batch self-verification (to detect batches modified after being written to disk), not for cryptographic verification.
std::uint64_t fnv1a64(std::string_view text) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char kRaw : text) {
        hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(kRaw));
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::uint64_t saturatingAddU64(std::uint64_t a, std::uint64_t b) noexcept {
    const std::uint64_t kLimit = std::numeric_limits<std::uint64_t>::max();
    return (a > kLimit - b) ? kLimit : a + b;
}

// Do not use -v to take the absolute value of int64; negating INT64_MIN is UB (undefined behavior).
std::uint64_t absToU64(std::int64_t value) noexcept {
    if (value >= 0) {
        return static_cast<std::uint64_t>(value);
    }
    return static_cast<std::uint64_t>(-(value + 1)) + 1ULL;
}

bool containsPid(const std::vector<std::uint64_t>& list, std::uint64_t pid) noexcept {
    return std::find(list.begin(), list.end(), pid) != list.end();
}

const char* bufferingNoticeFor(SessionState state) noexcept {
    switch (state) {
    case SessionState::kNew:           return "timeline.session.buffering.none";
    case SessionState::kCollecting:    return "timeline.session.buffering.recording-and-displaying";
    // T-01: This is the core message for this module — background recording and disk flushing continue while display is paused.
    case SessionState::kDisplayPaused: return "timeline.session.buffering.recording-display-frozen";
    case SessionState::kStopped:       return "timeline.session.buffering.no-new-events-retained";
    case SessionState::kSaved:         return "timeline.session.buffering.read-only";
    }
    return "timeline.session.buffering.none";
}

SessionTransition makeAllowed(SessionState next) {
    SessionTransition t;
    t.allowed = true;
    t.nextState = next;
    t.backgroundRecording = sessionAcceptsNewEvents(next);
    t.displayUpdating = sessionUpdatesDisplay(next);
    t.bufferingNoticeKey = bufferingNoticeFor(next);
    return t;
}

SessionTransition makeRejected(SessionState current, const char* reasonKey) {
    SessionTransition t;
    t.allowed = false;
    t.nextState = current;
    t.backgroundRecording = sessionAcceptsNewEvents(current);
    t.displayUpdating = sessionUpdatesDisplay(current);
    t.bufferingNoticeKey = bufferingNoticeFor(current);
    t.rejectionKey = reasonKey;
    return t;
}

// ---------------------------------------------------------------------------
// JSON helper
// ---------------------------------------------------------------------------

void put(JsonObject& object, const char* name, JsonValue value) {
    object.emplace_back(std::string(name), std::move(value));
}

void putText(JsonObject& object, const char* name, const std::string& value) {
    put(object, name, JsonValue::makeString(value));
}

void putU32(JsonObject& object, const char* name, std::uint32_t value) {
    put(object, name, JsonValue::makeUInt(static_cast<std::uint64_t>(value)));
}

void putU64Text(JsonObject& object, const char* name, std::uint64_t value) {
    put(object, name, JsonValue::makeU64Text(value, U64Format::kDecimal));
}

void putOptionalU64(JsonObject& object, const char* name, const OptionalU64& value) {
    put(object, name, JsonValue::makeOptionalU64Text(value, U64Format::kDecimal));
}

bool readText(const JsonValue& object, const char* name, std::string& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    return field->tryGetString(out);
}

bool readU32(const JsonValue& object, const char* name, std::uint32_t& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    std::uint64_t raw = 0;
    if (!field->tryGetU64(raw)) {
        return false;
    }
    if (raw > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        return false;
    }
    out = static_cast<std::uint32_t>(raw);
    return true;
}

bool readU64(const JsonValue& object, const char* name, std::uint64_t& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    return field->tryGetU64(out);
}

bool readOptionalU64(const JsonValue& object, const char* name, OptionalU64& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    return field->tryGetOptionalU64(out);
}

bool readBool(const JsonValue& object, const char* name, bool& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    return field->tryGetBool(out);
}

bool readI64(const JsonValue& object, const char* name, std::int64_t& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    std::string text;
    if (!field->tryGetString(text)) {
        return field->tryGetI64(out);
    }
    return parseI64(text, out);
}

// Enum name <-> value. The parser only looks up by name; if not found, it treats the file as corrupt and never "guesses the closest one".
template <typename Enum, std::size_t N>
bool lookupEnum(const std::pair<const char*, Enum> (&table)[N],
                const std::string& name,
                Enum& out) {
    for (std::size_t i = 0; i < N; ++i) {
        if (name == table[i].first) {
            out = table[i].second;
            return true;
        }
    }
    return false;
}

const std::pair<const char*, TimelineEventCategory> kCategoryTable[] = {
    { "Process", TimelineEventCategory::kProcess },
    { "Thread", TimelineEventCategory::kThread },
    { "Image", TimelineEventCategory::kImage },
    { "File", TimelineEventCategory::kFile },
    { "Registry", TimelineEventCategory::kRegistry },
    { "Network", TimelineEventCategory::kNetwork },
    { "Other", TimelineEventCategory::kOther },
};

const std::pair<const char*, EventParseOutcome> kParseOutcomeTable[] = {
    { "Parsed", EventParseOutcome::kParsed },
    { "UnparsedUnknownSchema", EventParseOutcome::kUnparsedUnknownSchema },
    { "Malformed", EventParseOutcome::kMalformed },
};

const std::pair<const char*, TimeResolution> kResolutionTable[] = {
    { "Unknown", TimeResolution::kUnknown },
    { "Second", TimeResolution::kSecond },
    { "Millisecond", TimeResolution::kMillisecond },
    { "Microsecond", TimeResolution::kMicrosecond },
    { "HundredNanosecond", TimeResolution::kHundredNanosecond },
};

const std::pair<const char*, AttributionKind> kAttributionTable[] = {
    { "BoundToInstance", AttributionKind::kBoundToInstance },
    { "Provisional", AttributionKind::kProvisional },
    { "AfterInstanceExit", AttributionKind::kAfterInstanceExit },
    { "Ambiguous", AttributionKind::kAmbiguous },
    { "UnknownProcess", AttributionKind::kUnknownProcess },
};

const std::pair<const char*, SessionState> kSessionStateTable[] = {
    { "New", SessionState::kNew },
    { "Collecting", SessionState::kCollecting },
    { "DisplayPaused", SessionState::kDisplayPaused },
    { "Stopped", SessionState::kStopped },
    { "Saved", SessionState::kSaved },
};

const std::pair<const char*, RetentionPolicy> kRetentionTable[] = {
    { "StopOnLimit", RetentionPolicy::kStopOnLimit },
    { "EvictOldest", RetentionPolicy::kEvictOldest },
};

const std::pair<const char*, BoundsState> kBoundsStateTable[] = {
    { "WithinLimits", BoundsState::kWithinLimits },
    { "MemoryLimitReached", BoundsState::kMemoryLimitReached },
    { "ArchiveLimitReached", BoundsState::kArchiveLimitReached },
};

// T-10: availabilityStatus / origin previously used 'linear name lookup, leaving a benign default value if not found'.
// That path would silently misclassify *failure* as *never run* (AccessDenied misspelled -> NotCollected, while nativeCode
// still holds STATUS_ACCESS_DENIED, creating a contradiction between the two fields), and it contradicts the approach in
// the same header where unknown enums are treated as bad files. Now, always use the hard failure from lookupEnum.
const std::pair<const char*, CollectionStatus> kCollectionStatusTable[] = {
    { "NotCollected", CollectionStatus::kNotCollected },
    { "Success", CollectionStatus::kSuccess },
    { "Partial", CollectionStatus::kPartial },
    { "Unsupported", CollectionStatus::kUnsupported },
    { "AccessDenied", CollectionStatus::kAccessDenied },
    { "Timeout", CollectionStatus::kTimeout },
    { "Error", CollectionStatus::kError },
};

const std::pair<const char*, SourceOrigin> kSourceOriginTable[] = {
    { "Unknown", SourceOrigin::kUnknown },
    { "LiveKernel", SourceOrigin::kLiveKernel },
    { "LiveUserMode", SourceOrigin::kLiveUserMode },
    { "ExternalFile", SourceOrigin::kExternalFile },
    { "OfflineSample", SourceOrigin::kOfflineSample },
};

const std::pair<const char*, LossCategory> kLossCategoryTable[] = {
    { "SourceDrop", LossCategory::kSourceDrop },
    { "RingOverwrite", LossCategory::kRingOverwrite },
    { "QueueDiscard", LossCategory::kQueueDiscard },
    { "ParseFailure", LossCategory::kParseFailure },
    { "FilteredOut", LossCategory::kFilteredOut },
    { "RetentionEvicted", LossCategory::kRetentionEvicted },
};

JsonValue encodeEvent(const TimelineEvent& event) {
    JsonObject object;
    putText(object, "recordId", event.recordId);
    putText(object, "providerId", event.providerId);
    putText(object, "sourceGroup", event.sourceGroup);
    putU32(object, "eventId", event.eventId);
    putU32(object, "eventVersion", event.eventVersion);
    putU32(object, "opcode", event.opcode);
    putU32(object, "task", event.task);
    putText(object, "category", timelineEventCategoryName(event.category));
    putText(object, "parseOutcome", eventParseOutcomeName(event.parseOutcome));
    putText(object, "parserId", event.parserId);
    putU32(object, "parserVersion", event.parserVersion);
    putText(object, "parseReasonKey", event.parseReasonKey);

    JsonArray fields;
    fields.reserve(event.rawFields.size());
    for (const auto& pair : event.rawFields) {
        JsonObject one;
        putText(one, "n", pair.first);
        putText(one, "v", pair.second);
        fields.push_back(JsonValue::makeObject(std::move(one)));
    }
    put(object, "rawFields", JsonValue::makeArray(std::move(fields)));
    putText(object, "rawPayloadHex", event.rawPayloadHex);

    JsonObject time;
    putOptionalU64(time, "sourceTime100ns", event.time.sourceTime100ns);
    putOptionalU64(time, "receiveTime100ns", event.time.receiveTime100ns);
    putText(time, "sourceResolution", timeResolutionName(event.time.sourceResolution));
    put(time, "calibrationAvailable", JsonValue::makeBool(event.time.calibrationAvailable));
    putText(time, "calibrationOffset100ns", formatI64(event.time.calibrationOffset100ns));
    putText(time, "calibrationId", event.time.calibrationId);
    putText(time, "bootId", event.time.bootId);
    putOptionalU64(time, "sourceMonotonic", event.time.sourceMonotonic);
    put(time, "lateArrival", JsonValue::makeBool(event.time.lateArrival));
    put(time, "orderUncertain", JsonValue::makeBool(event.time.orderUncertain));
    put(object, "time", JsonValue::makeObject(std::move(time)));

    putText(object, "attribution", attributionKindName(event.attribution));
    putText(object, "processInstanceKey", event.processInstanceKey);
    putText(object, "provisionalProcessId", event.provisionalProcessId);
    putOptionalU64(object, "pid", event.pid);
    putOptionalU64(object, "tid", event.tid);
    putU64Text(object, "arrivalSequence", event.arrivalSequence);
    putText(object, "sourceLinkId", event.sourceLinkId);
    putText(object, "sourceLinkField", event.sourceLinkField);
    return JsonValue::makeObject(std::move(object));
}

bool decodeEvent(const JsonValue& value, TimelineEvent& out) {
    if (value.asObject() == nullptr) {
        return false;
    }
    TimelineEvent event;
    std::string text;
    if (!readText(value, "recordId", event.recordId)) { return false; }
    if (!readText(value, "providerId", event.providerId)) { return false; }
    if (!readText(value, "sourceGroup", event.sourceGroup)) { return false; }
    if (!readU32(value, "eventId", event.eventId)) { return false; }
    if (!readU32(value, "eventVersion", event.eventVersion)) { return false; }
    if (!readU32(value, "opcode", event.opcode)) { return false; }
    if (!readU32(value, "task", event.task)) { return false; }
    if (!readText(value, "category", text) || !lookupEnum(kCategoryTable, text, event.category)) {
        return false;
    }
    if (!readText(value, "parseOutcome", text) ||
        !lookupEnum(kParseOutcomeTable, text, event.parseOutcome)) {
        return false;
    }
    if (!readText(value, "parserId", event.parserId)) { return false; }
    if (!readU32(value, "parserVersion", event.parserVersion)) { return false; }
    if (!readText(value, "parseReasonKey", event.parseReasonKey)) { return false; }

    const JsonValue* fields = value.find("rawFields");
    if (fields == nullptr) { return false; }
    const JsonArray* fieldArray = fields->asArray();
    if (fieldArray == nullptr) { return false; }
    for (const JsonValue& item : *fieldArray) {
        std::string name;
        std::string raw;
        if (!readText(item, "n", name) || !readText(item, "v", raw)) {
            return false;
        }
        event.rawFields.emplace_back(std::move(name), std::move(raw));
    }
    if (!readText(value, "rawPayloadHex", event.rawPayloadHex)) { return false; }

    const JsonValue* time = value.find("time");
    if (time == nullptr || time->asObject() == nullptr) { return false; }
    if (!readOptionalU64(*time, "sourceTime100ns", event.time.sourceTime100ns)) { return false; }
    if (!readOptionalU64(*time, "receiveTime100ns", event.time.receiveTime100ns)) { return false; }
    if (!readText(*time, "sourceResolution", text) ||
        !lookupEnum(kResolutionTable, text, event.time.sourceResolution)) {
        return false;
    }
    if (!readBool(*time, "calibrationAvailable", event.time.calibrationAvailable)) { return false; }
    if (!readI64(*time, "calibrationOffset100ns", event.time.calibrationOffset100ns)) { return false; }
    if (!readText(*time, "calibrationId", event.time.calibrationId)) { return false; }
    if (!readText(*time, "bootId", event.time.bootId)) { return false; }
    if (!readOptionalU64(*time, "sourceMonotonic", event.time.sourceMonotonic)) { return false; }
    if (!readBool(*time, "lateArrival", event.time.lateArrival)) { return false; }
    if (!readBool(*time, "orderUncertain", event.time.orderUncertain)) { return false; }

    if (!readText(value, "attribution", text) ||
        !lookupEnum(kAttributionTable, text, event.attribution)) {
        return false;
    }
    if (!readText(value, "processInstanceKey", event.processInstanceKey)) { return false; }
    if (!readText(value, "provisionalProcessId", event.provisionalProcessId)) { return false; }
    if (!readOptionalU64(value, "pid", event.pid)) { return false; }
    if (!readOptionalU64(value, "tid", event.tid)) { return false; }
    if (!readU64(value, "arrivalSequence", event.arrivalSequence)) { return false; }
    if (!readText(value, "sourceLinkId", event.sourceLinkId)) { return false; }
    if (!readText(value, "sourceLinkField", event.sourceLinkField)) { return false; }

    out = std::move(event);
    return true;
}

JsonValue encodeEventArray(const std::vector<TimelineEvent>& events) {
    JsonArray array;
    array.reserve(events.size());
    for (const TimelineEvent& event : events) {
        array.push_back(encodeEvent(event));
    }
    return JsonValue::makeArray(std::move(array));
}

std::uint64_t batchChecksum(const std::vector<TimelineEvent>& events) {
    return fnv1a64(writeJson(encodeEventArray(events), 0U));
}

// Each line contains one JSON document; the line must end with '\n'. A final line missing '\n' indicates it was 'interrupted mid-write'.
std::vector<std::string_view> splitLines(std::string_view text, bool& lastLineTerminated) {
    std::vector<std::string_view> lines;
    lastLineTerminated = true;
    std::size_t begin = 0;
    while (begin < text.size()) {
        const std::size_t kPos = text.find('\n', begin);
        if (kPos == std::string_view::npos) {
            lines.push_back(text.substr(begin));
            lastLineTerminated = false;
            break;
        }
        std::string_view line = text.substr(begin, kPos - begin);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        lines.push_back(line);
        begin = kPos + 1;
    }
    return lines;
}

} // namespace

// ===========================================================================
// Name table
// ===========================================================================

const char* sessionStateName(SessionState state) noexcept {
    switch (state) {
    case SessionState::kNew:           return "New";
    case SessionState::kCollecting:    return "Collecting";
    case SessionState::kDisplayPaused: return "DisplayPaused";
    case SessionState::kStopped:       return "Stopped";
    case SessionState::kSaved:         return "Saved";
    }
    return "New";
}

bool sessionAcceptsNewEvents(SessionState state) noexcept {
    switch (state) {
    case SessionState::kCollecting:
    // T-01: The display is paused, not the collection. Background recording continues.
    // Returning events here would mean 'stopping collection and silently dropping events'.
    case SessionState::kDisplayPaused:
        return true;
    case SessionState::kNew:
    case SessionState::kStopped:
    case SessionState::kSaved:
        return false;
    }
    return false;
}

bool sessionUpdatesDisplay(SessionState state) noexcept {
    switch (state) {
    case SessionState::kCollecting:
        return true;
    case SessionState::kNew:
    case SessionState::kDisplayPaused:
    case SessionState::kStopped:
    case SessionState::kSaved:
        return false;
    }
    return false;
}

const char* sessionActionName(SessionAction action) noexcept {
    switch (action) {
    case SessionAction::kStart:          return "Start";
    case SessionAction::kPauseDisplay:   return "PauseDisplay";
    case SessionAction::kResumeDisplay:  return "ResumeDisplay";
    case SessionAction::kStopCollection: return "StopCollection";
    case SessionAction::kSave:           return "Save";
    case SessionAction::kReset:          return "Reset";
    }
    return "Start";
}

const char* timelineEventCategoryName(TimelineEventCategory category) noexcept {
    switch (category) {
    case TimelineEventCategory::kProcess:  return "Process";
    case TimelineEventCategory::kThread:   return "Thread";
    case TimelineEventCategory::kImage:    return "Image";
    case TimelineEventCategory::kFile:     return "File";
    case TimelineEventCategory::kRegistry: return "Registry";
    case TimelineEventCategory::kNetwork:  return "Network";
    case TimelineEventCategory::kOther:    return "Other";
    }
    return "Other";
}

const char* eventParseOutcomeName(EventParseOutcome outcome) noexcept {
    switch (outcome) {
    case EventParseOutcome::kParsed:                return "Parsed";
    case EventParseOutcome::kUnparsedUnknownSchema: return "UnparsedUnknownSchema";
    case EventParseOutcome::kMalformed:             return "Malformed";
    }
    return "UnparsedUnknownSchema";
}

const char* timeResolutionName(TimeResolution resolution) noexcept {
    switch (resolution) {
    case TimeResolution::kUnknown:           return "Unknown";
    case TimeResolution::kSecond:            return "Second";
    case TimeResolution::kMillisecond:       return "Millisecond";
    case TimeResolution::kMicrosecond:       return "Microsecond";
    case TimeResolution::kHundredNanosecond: return "HundredNanosecond";
    }
    return "Unknown";
}

std::uint64_t resolutionSpan100ns(TimeResolution resolution) noexcept {
    switch (resolution) {
    case TimeResolution::kUnknown:           return 0ULL;
    case TimeResolution::kSecond:            return 10000000ULL;
    case TimeResolution::kMillisecond:       return 10000ULL;
    case TimeResolution::kMicrosecond:       return 10ULL;
    case TimeResolution::kHundredNanosecond: return 1ULL;
    }
    return 0ULL;
}

const char* timeComparisonName(TimeComparison comparison) noexcept {
    switch (comparison) {
    case TimeComparison::kComparable:              return "Comparable";
    case TimeComparison::kComparableButUncertain:  return "ComparableButUncertain";
    case TimeComparison::kIncomparableCrossBoot:   return "IncomparableCrossBoot";
    case TimeComparison::kIncomparableUnknownTime: return "IncomparableUnknownTime";
    case TimeComparison::kIncomparableMagnitude:   return "IncomparableMagnitude";
    }
    return "IncomparableUnknownTime";
}

const char* attributionKindName(AttributionKind kind) noexcept {
    switch (kind) {
    case AttributionKind::kBoundToInstance:   return "BoundToInstance";
    case AttributionKind::kProvisional:       return "Provisional";
    case AttributionKind::kAfterInstanceExit: return "AfterInstanceExit";
    case AttributionKind::kAmbiguous:         return "Ambiguous";
    case AttributionKind::kUnknownProcess:    return "UnknownProcess";
    }
    return "UnknownProcess";
}

const char* lossCategoryName(LossCategory category) noexcept {
    switch (category) {
    case LossCategory::kSourceDrop:       return "SourceDrop";
    case LossCategory::kRingOverwrite:    return "RingOverwrite";
    case LossCategory::kQueueDiscard:     return "QueueDiscard";
    case LossCategory::kParseFailure:     return "ParseFailure";
    case LossCategory::kFilteredOut:      return "FilteredOut";
    case LossCategory::kRetentionEvicted: return "RetentionEvicted";
    }
    return "SourceDrop";
}

LossCategory lossCategoryAt(std::size_t index) noexcept {
    switch (index) {
    case 0: return LossCategory::kSourceDrop;
    case 1: return LossCategory::kRingOverwrite;
    case 2: return LossCategory::kQueueDiscard;
    case 3: return LossCategory::kParseFailure;
    case 4: return LossCategory::kFilteredOut;
    default: return LossCategory::kRetentionEvicted;
    }
}

const char* filterStageName(FilterStage stage) noexcept {
    switch (stage) {
    case FilterStage::kCollection: return "Collection";
    case FilterStage::kDisplay:    return "Display";
    }
    return "Collection";
}

const char* exportScopeName(ExportScope scope) noexcept {
    switch (scope) {
    case ExportScope::kVisibleOnly: return "VisibleOnly";
    case ExportScope::kFullSession: return "FullSession";
    }
    return "VisibleOnly";
}

const char* retentionPolicyName(RetentionPolicy policy) noexcept {
    switch (policy) {
    case RetentionPolicy::kStopOnLimit: return "StopOnLimit";
    case RetentionPolicy::kEvictOldest: return "EvictOldest";
    }
    return "StopOnLimit";
}

const char* boundsStateName(BoundsState state) noexcept {
    switch (state) {
    case BoundsState::kWithinLimits:        return "WithinLimits";
    case BoundsState::kMemoryLimitReached:  return "MemoryLimitReached";
    case BoundsState::kArchiveLimitReached: return "ArchiveLimitReached";
    }
    return "WithinLimits";
}

const char* timelineEdgeKindName(TimelineEdgeKind kind) noexcept {
    switch (kind) {
    case TimelineEdgeKind::kSameProcess:        return "SameProcess";
    case TimelineEdgeKind::kParentChild:        return "ParentChild";
    case TimelineEdgeKind::kTemporalNeighbor:   return "TemporalNeighbor";
    case TimelineEdgeKind::kSourceProvidedLink: return "SourceProvidedLink";
    }
    return "TemporalNeighbor";
}

bool edgeKindAllowsCausalWording(TimelineEdgeKind kind) noexcept {
    switch (kind) {
    // T-12: Only associations provided by the source itself permit causal phrasing.
    case TimelineEdgeKind::kSourceProvidedLink:
        return true;
    // Same process indicates 'same execution entity', parent-child indicates 'creation relationship', and temporal neighbor indicates 'occurred consecutively'.
    // None of the three can infer that "A caused B".
    case TimelineEdgeKind::kSameProcess:
    case TimelineEdgeKind::kParentChild:
    case TimelineEdgeKind::kTemporalNeighbor:
        return false;
    }
    return false;
}

const char* sessionLoadStatusName(SessionLoadStatus status) noexcept {
    switch (status) {
    case SessionLoadStatus::kOk:              return "Ok";
    case SessionLoadStatus::kEmpty:           return "Empty";
    case SessionLoadStatus::kMissingHeader:   return "MissingHeader";
    case SessionLoadStatus::kVersionTooNew:   return "VersionTooNew";
    case SessionLoadStatus::kIncompleteTail:  return "IncompleteTail";
    case SessionLoadStatus::kCorrupt:         return "Corrupt";
    case SessionLoadStatus::kTrailerMismatch: return "TrailerMismatch";
    }
    return "Empty";
}

// ===========================================================================
// T-01 transition table
// ===========================================================================

SessionTransition evaluateSessionTransition(SessionState current, SessionAction action) {
    switch (current) {
    case SessionState::kNew:
        switch (action) {
        case SessionAction::kStart:          return makeAllowed(SessionState::kCollecting);
        case SessionAction::kReset:          return makeAllowed(SessionState::kNew);
        case SessionAction::kPauseDisplay:
        case SessionAction::kResumeDisplay:
        case SessionAction::kStopCollection: return makeRejected(current, "timeline.session.not-collecting");
        case SessionAction::kSave:           return makeRejected(current, "timeline.session.nothing-to-save");
        }
        break;
    case SessionState::kCollecting:
        switch (action) {
        // T-01: Pausing display does not change whether 'recording is active in the background'.
        case SessionAction::kPauseDisplay:   return makeAllowed(SessionState::kDisplayPaused);
        // T-01: Stopping collection is a **separate** action and the only one that stops background recording.
        case SessionAction::kStopCollection: return makeAllowed(SessionState::kStopped);
        case SessionAction::kStart:          return makeRejected(current, "timeline.session.already-collecting");
        case SessionAction::kResumeDisplay:  return makeRejected(current, "timeline.session.display-not-paused");
        // Boundary must be determined before saving: saving during collection writes a session with an undefined cutoff point.
        case SessionAction::kSave:           return makeRejected(current, "timeline.session.stop-before-save");
        case SessionAction::kReset:          return makeRejected(current, "timeline.session.stop-before-reset");
        }
        break;
    case SessionState::kDisplayPaused:
        switch (action) {
        case SessionAction::kResumeDisplay:  return makeAllowed(SessionState::kCollecting);
        // Stopping collection directly while paused is valid — this is the meaning of 'two buttons'.
        case SessionAction::kStopCollection: return makeAllowed(SessionState::kStopped);
        case SessionAction::kStart:          return makeRejected(current, "timeline.session.already-collecting");
        case SessionAction::kPauseDisplay:   return makeRejected(current, "timeline.session.already-paused");
        case SessionAction::kSave:           return makeRejected(current, "timeline.session.stop-before-save");
        case SessionAction::kReset:          return makeRejected(current, "timeline.session.stop-before-reset");
        }
        break;
    case SessionState::kStopped:
        switch (action) {
        case SessionAction::kSave:           return makeAllowed(SessionState::kSaved);
        case SessionAction::kReset:          return makeAllowed(SessionState::kNew);
        // Resumption is forbidden after stop: resuming would create two records with unclear boundaries within the same session.
        case SessionAction::kStart:          return makeRejected(current, "timeline.session.restart-requires-new-session");
        case SessionAction::kPauseDisplay:
        case SessionAction::kResumeDisplay:
        case SessionAction::kStopCollection: return makeRejected(current, "timeline.session.already-stopped");
        }
        break;
    case SessionState::kSaved:
        switch (action) {
        case SessionAction::kSave:           return makeAllowed(SessionState::kSaved);
        case SessionAction::kReset:          return makeAllowed(SessionState::kNew);
        case SessionAction::kStart:          return makeRejected(current, "timeline.session.restart-requires-new-session");
        case SessionAction::kPauseDisplay:
        case SessionAction::kResumeDisplay:
        case SessionAction::kStopCollection: return makeRejected(current, "timeline.session.already-stopped");
        }
        break;
    }
    return makeRejected(current, "timeline.session.unsupported-action");
}

// ===========================================================================
// T-04 timestamp
// ===========================================================================

OptionalU64 EventTimeStamp::effectiveTime100ns() const noexcept {
    if (!sourceTime100ns.present) {
        // Fall back to receive time only when source time is missing. Calibration applies to the source clock, so do not add it on this path.
        return receiveTime100ns;
    }
    if (!calibrationAvailable || calibrationOffset100ns == 0) {
        return sourceTime100ns;
    }
    const std::uint64_t kBase = sourceTime100ns.value;
    const std::uint64_t kDelta = absToU64(calibrationOffset100ns);
    if (calibrationOffset100ns > 0) {
        const std::uint64_t kLimit = std::numeric_limits<std::uint64_t>::max();
        return OptionalU64::of(kBase > kLimit - kDelta ? kLimit : kBase + kDelta);
    }
    return OptionalU64::of(kBase < kDelta ? 0ULL : kBase - kDelta);
}

bool EventTimeStamp::effectiveFromReceiveTime() const noexcept {
    return !sourceTime100ns.present && receiveTime100ns.present;
}

TimeComparisonResult compareEventTimes(const EventTimeStamp& earlier,
                                       const EventTimeStamp& later) noexcept {
    TimeComparisonResult result;
    result.calibrationChanged = earlier.calibrationId != later.calibrationId;

    const OptionalU64 kA = earlier.effectiveTime100ns();
    const OptionalU64 kB = later.effectiveTime100ns();
    if (!kA.present || !kB.present) {
        result.kind = TimeComparison::kIncomparableUnknownTime;
        return result;
    }
    // Unknown boot cycles are also incomparable: without a bootId, it is impossible to prove that two timestamps belong to the same clock epoch.
    if (earlier.bootId.empty() || later.bootId.empty() || earlier.bootId != later.bootId) {
        result.kind = TimeComparison::kIncomparableCrossBoot;
        return result;
    }

    // Signed path. Unsigned subtraction can wrap around, turning a 1ms callback into an astronomical number (verified in X module).
    const bool kReversed = kB.value < kA.value;
    const std::uint64_t kMagnitude = kReversed ? (kA.value - kB.value) : (kB.value - kA.value);
    result.regression = kReversed;
    if (kMagnitude > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        result.kind = TimeComparison::kIncomparableMagnitude;
        result.delta100ns = 0;
        return result;
    }
    const std::int64_t kSignedMagnitude = static_cast<std::int64_t>(kMagnitude);
    result.delta100ns = kReversed ? -kSignedMagnitude : kSignedMagnitude;

    // When precision is unknown, we cannot assert order resolvability; strict total ordering across sources does not exist.
    if (earlier.sourceResolution == TimeResolution::kUnknown ||
        later.sourceResolution == TimeResolution::kUnknown) {
        result.kind = TimeComparison::kComparableButUncertain;
        return result;
    }
    const std::uint64_t kSpan = std::max(resolutionSpan100ns(earlier.sourceResolution),
                                        resolutionSpan100ns(later.sourceResolution));
    if (kMagnitude == 0ULL || kMagnitude < kSpan) {
        result.kind = TimeComparison::kComparableButUncertain;
        return result;
    }
    // If calibration has changed once, there is insufficient evidence that the two timestamps fall in the same coordinate system; the order is only "uncertain".
    if (result.calibrationChanged) {
        result.kind = TimeComparison::kComparableButUncertain;
        return result;
    }
    result.kind = TimeComparison::kComparable;
    return result;
}

bool sortKeyLess(const TimelineSortKey& a, const TimelineSortKey& b) noexcept {
    if (a.bootEpochRank != b.bootEpochRank) {
        return a.bootEpochRank < b.bootEpochRank;
    }
    if (a.timeKnown != b.timeKnown) {
        // Unknown timestamps are placed after known ones, rather than being treated as 0 and pushed to the front.
        return a.timeKnown;
    }
    if (a.timeKnown && a.effectiveTime100ns != b.effectiveTime100ns) {
        return a.effectiveTime100ns < b.effectiveTime100ns;
    }
    if (a.arrivalSequence != b.arrivalSequence) {
        return a.arrivalSequence < b.arrivalSequence;
    }
    if (a.sourceGroup != b.sourceGroup) {
        return a.sourceGroup < b.sourceGroup;
    }
    return a.recordId < b.recordId;
}

// ===========================================================================
// T-05 process ownership
// ===========================================================================

bool ProcessInstanceLedger::observeStart(const ProcessInstanceId& identity,
                                         std::uint64_t startTime100ns) {
    if (identity.bootId.empty() || !identity.pid.present) {
        return false;  // Without a boot cycle and PID, registration cannot be used for attribution.
    }
    for (InstanceRecord& record : instances_) {
        if (record.identity.bootId != identity.bootId || record.identity.pid != identity.pid ||
            record.startTime100ns != startTime100ns) {
            continue;
        }
        // Same bootId/pid/start time but different createTime — these are two separate instances and cannot be merged.
        if (identity.createTime100ns.present && record.identity.createTime100ns.present &&
            identity.createTime100ns.value != record.identity.createTime100ns.value) {
            continue;
        }
        record.identity = identity;  // Fill in information such as createTime and imageName.
        return true;
    }
    InstanceRecord record;
    record.identity = identity;
    record.startTime100ns = startTime100ns;
    instances_.push_back(std::move(record));
    return true;
}

bool ProcessInstanceLedger::observeExit(const ProcessInstanceId& identity,
                                        std::uint64_t exitTime100ns) {
    if (identity.bootId.empty() || !identity.pid.present) {
        return false;
    }
    // T-05: If createTime is present, it must match precisely. Selecting candidates solely by (bootId, pid, "latest start
    // time") causes A's late exit event to be attributed to B: A ends up with no end time (window extends infinitely), and
    // B is marked as already exited. Subsequently, events with timestamp t falling within B's window become Ambiguous due
    // to overlapping windows, and events after t are incorrectly treated as "B has exited," causing errors on both sides.
    const bool kHaveCreateTime = identity.createTime100ns.present;
    InstanceRecord* best = nullptr;
    for (InstanceRecord& record : instances_) {
        if (record.identity.bootId != identity.bootId || record.identity.pid != identity.pid) {
            continue;
        }
        if (record.exitKnown || record.startTime100ns > exitTime100ns) {
            continue;
        }
        if (kHaveCreateTime) {
            if (!record.identity.createTime100ns.present ||
                record.identity.createTime100ns.value != identity.createTime100ns.value) {
                continue;  // If the identity does not match, it is not this instance; better to drop this exit than to hang.
            }
            best = &record;
            break;
        }
        if (best == nullptr || record.startTime100ns > best->startTime100ns) {
            best = &record;
        }
    }
    if (best == nullptr) {
        return false;  // Do not fabricate an 'already ended' instance; the caller records a mismatched exit based on this.
    }
    best->exitKnown = true;
    best->exitTime100ns = exitTime100ns;
    if (!kHaveCreateTime) {
        // No createTime; this match was guessed from the start time. Count it separately without pretending it's certain.
        ++weakExitMatchCount_;
    }
    return true;
}

std::string makeProvisionalEntityId(const std::string& bootId,
                                    const OptionalU64& pid,
                                    AttributionKind originKind) {
    // The length prefix ensures injective encoding: an empty bootId and the literal "boot-unknown" no longer collapse
    // into the same entity, and a bootId containing ":pid=" won't cause two different boot cycles to collide.
    std::string id("prov:b");
    id.append(formatU64(static_cast<std::uint64_t>(bootId.size()), U64Format::kDecimal));
    id.push_back(':');
    id.append(bootId);
    id.append(":pid=");
    id.append(pid.present ? formatU64(pid.value, U64Format::kDecimal) : std::string("unknown"));
    id.push_back(':');
    id.append(attributionKindName(originKind));
    return id;
}

ProvisionalProcessEntity& ProcessInstanceLedger::touchProvisional(const std::string& bootId,
                                                                  const OptionalU64& pid,
                                                                  const OptionalU64& time,
                                                                  AttributionKind originKind) {
    const std::string kId = makeProvisionalEntityId(bootId, pid, originKind);

    const auto kFound = provisionalIndex_.find(kId);
    if (kFound != provisionalIndex_.end() && kFound->second < provisionals_.size()) {
        ProvisionalProcessEntity& entity = provisionals_[kFound->second];
        ++entity.eventCount;
        if (time.present) {
            if (!entity.firstSeenTime100ns.present || time.value < entity.firstSeenTime100ns.value) {
                entity.firstSeenTime100ns = time;
            }
            if (!entity.lastSeenTime100ns.present || time.value > entity.lastSeenTime100ns.value) {
                entity.lastSeenTime100ns = time;
            }
        }
        return entity;
    }
    ProvisionalProcessEntity entity;
    entity.provisionalId = kId;
    entity.bootId = bootId;
    entity.pid = pid;
    entity.firstSeenTime100ns = time;
    entity.lastSeenTime100ns = time;
    entity.eventCount = 1U;
    entity.originKind = originKind;
    entity.identityComplete = false;  // T-05: Temporary entities are always 'identity incomplete'.
    provisionalIndex_.emplace(kId, provisionals_.size());
    provisionals_.push_back(std::move(entity));
    return provisionals_.back();
}

AttributionDecision ProcessInstanceLedger::attribute(const std::string& bootId,
                                                     const OptionalU64& pid,
                                                     const EventTimeStamp& time) {
    AttributionDecision decision;
    if (!pid.present) {
        decision.kind = AttributionKind::kUnknownProcess;
        decision.reasonKey = "timeline.attribution.no-pid";
        return decision;
    }

    const OptionalU64 kEffective = time.effectiveTime100ns();
    if (bootId.empty()) {
        // Cannot map a PID to a specific boot cycle without a boot ID; never guess 'the current one'.
        decision.kind = AttributionKind::kProvisional;
        decision.reasonKey = "timeline.attribution.no-boot-id";
        decision.provisionalId =
            touchProvisional(bootId, pid, kEffective, AttributionKind::kProvisional).provisionalId;
        return decision;
    }
    if (!kEffective.present) {
        decision.kind = AttributionKind::kProvisional;
        decision.reasonKey = "timeline.attribution.no-time";
        decision.provisionalId =
            touchProvisional(bootId, pid, kEffective, AttributionKind::kProvisional).provisionalId;
        return decision;
    }

    const std::uint64_t kT = kEffective.value;
    const InstanceRecord* covering = nullptr;
    std::size_t coveringCount = 0;
    bool sawEndedBefore = false;
    for (const InstanceRecord& record : instances_) {
        if (record.identity.bootId != bootId || record.identity.pid != pid) {
            continue;
        }
        if (record.startTime100ns <= kT && (!record.exitKnown || kT <= record.exitTime100ns)) {
            covering = &record;
            ++coveringCount;
            continue;
        }
        if (record.exitKnown && record.exitTime100ns < kT) {
            sawEndedBefore = true;
        }
    }

    if (coveringCount == 1U && covering != nullptr) {
        decision.kind = AttributionKind::kBoundToInstance;
        decision.instance = covering->identity;
        decision.identityStrength = covering->identity.strength();
        // F-03 Unified threshold: if identity strength is insufficient, only Candidate is assigned; do not upgrade based on 'window match'.
        decision.identityMatch = decision.identityStrength == IdentityStrength::kStrong
                                     ? MatchResult::kConfirmed
                                     : MatchResult::kCandidate;
        decision.reasonKey = "timeline.attribution.instance-window-match";
        return decision;
    }
    if (coveringCount > 1U) {
        decision.kind = AttributionKind::kAmbiguous;
        decision.reasonKey = "timeline.attribution.overlapping-instances";
        decision.provisionalId =
            touchProvisional(bootId, pid, kEffective, AttributionKind::kAmbiguous).provisionalId;
        return decision;
    }
    if (sawEndedBefore) {
        // T-05: Late events occurring after the target has exited. Never reassign to the next instance of the same PID.
        decision.kind = AttributionKind::kAfterInstanceExit;
        decision.reasonKey = "timeline.attribution.after-known-exit";
        decision.provisionalId =
            touchProvisional(bootId, pid, kEffective, AttributionKind::kAfterInstanceExit).provisionalId;
        return decision;
    }
    // T-05: Missing process start event — create a provisional entity with incomplete identity instead of attributing it to the current process with the same PID.
    decision.kind = AttributionKind::kProvisional;
    decision.reasonKey = "timeline.attribution.missing-start-event";
    decision.provisionalId =
        touchProvisional(bootId, pid, kEffective, AttributionKind::kProvisional).provisionalId;
    return decision;
}

bool ProcessInstanceLedger::confirmProvisional(const std::string& provisionalId,
                                               const ProcessInstanceId& identity,
                                               std::string noteKey) {
    for (ProvisionalProcessEntity& entity : provisionals_) {
        if (entity.provisionalId != provisionalId) {
            continue;
        }
        const std::string kKey = identity.crossSessionKey();
        if (kKey.empty()) {
            // The supplementary evidence itself lacks sufficient identity (missing createTime/bootId). Record this attempt,
            // but never mark the provisional entity as "completed" — that would be passing off weak evidence as confirmed.
            entity.resolutionNoteKey = "timeline.provisional.resolve-rejected-weak-identity";
            return false;
        }
        entity.identityComplete = true;
        entity.resolvedInstanceKey = kKey;
        entity.resolutionNoteKey = std::move(noteKey);
        return true;
    }
    return false;
}

const ProvisionalProcessEntity* ProcessInstanceLedger::findProvisional(
    const std::string& provisionalId) const noexcept {
    for (const ProvisionalProcessEntity& entity : provisionals_) {
        if (entity.provisionalId == provisionalId) {
            return &entity;
        }
    }
    return nullptr;
}

// ===========================================================================
// T-06: Loss ledger
// ===========================================================================

bool LossLedger::declareSource(LossCategory category,
                               std::string statisticSource,
                               bool sourceIsAuthoritative,
                               bool intervalSupported) {
    if (statisticSource.empty()) {
        return false;  // T-06: '0 also has an explainable statistical source'; the source must not be an empty string.
    }
    LossCounter& counter = counters_[static_cast<std::size_t>(category)];
    if (!counter.statisticSource.empty()) {
        // Changing the source equates to changing the measurement standard; old counters cannot be directly reused—reject to avoid combining two different standards.
        return counter.statisticSource == statisticSource &&
               counter.sourceIsAuthoritative == sourceIsAuthoritative &&
               counter.intervalSupported == intervalSupported;
    }
    counter.statisticSource = std::move(statisticSource);
    counter.sourceIsAuthoritative = sourceIsAuthoritative;
    counter.intervalSupported = intervalSupported;
    if (!sourceIsAuthoritative) {
        // Local counting starts from 0, and this 0 has a source.
        counter.count = OptionalU64::of(0ULL);
    }
    // Authoritative categories remain 'unknown' until the source actually reports a count; do not default to 0.
    return true;
}

bool LossLedger::setAbsolute(LossCategory category, std::uint64_t count) {
    LossCounter& counter = counters_[static_cast<std::size_t>(category)];
    if (counter.statisticSource.empty() || !counter.sourceIsAuthoritative) {
        return false;  // Local scope must not be overwritten by absolute values, or local increments will be lost or duplicated.
    }
    counter.count = OptionalU64::of(count);
    return true;
}

bool LossLedger::addObserved(LossCategory category, std::uint64_t delta) {
    LossCounter& counter = counters_[static_cast<std::size_t>(category)];
    if (counter.statisticSource.empty() || counter.sourceIsAuthoritative) {
        // The source provides an absolute value; incrementing locally again would count the same lost items twice.
        return false;
    }
    counter.count = OptionalU64::of(saturatingAddU64(counter.count.valueOr(0ULL), delta));
    return true;
}

bool LossLedger::setInterval(LossCategory category, std::uint64_t begin100ns, std::uint64_t end100ns) {
    LossCounter& counter = counters_[static_cast<std::size_t>(category)];
    if (counter.statisticSource.empty() || !counter.intervalSupported) {
        // T-06: Sources report only total timing; do not fabricate precise lost intervals.
        return false;
    }
    if (begin100ns > end100ns) {
        return false;
    }
    counter.intervalBegin100ns = OptionalU64::of(begin100ns);
    counter.intervalEnd100ns = OptionalU64::of(end100ns);
    return true;
}

const LossCounter& LossLedger::counter(LossCategory category) const noexcept {
    return counters_[static_cast<std::size_t>(category)];
}

LossCounter& LossLedger::mutableCounter(LossCategory category) noexcept {
    return counters_[static_cast<std::size_t>(category)];
}

bool LossLedger::anyUnknown() const noexcept {
    for (std::size_t i = 0; i < kLossCategoryCount; ++i) {
        if (counters_[i].statisticSource.empty() || !counters_[i].count.present) {
            return true;
        }
    }
    return false;
}

OptionalU64 LossLedger::totalLost() const noexcept {
    std::uint64_t total = 0;
    for (std::size_t i = 0; i < kLossCategoryCount; ++i) {
        if (!counters_[i].count.present) {
            // Treating unknown values as 0 when summing can incorrectly mark partial traces as complete.
            return OptionalU64::unset();
        }
        total = saturatingAddU64(total, counters_[i].count.value);
    }
    return OptionalU64::of(total);
}

std::vector<std::string> LossLedger::limitationKeys() const {
    std::vector<std::string> keys;
    bool anyPositive = false;
    for (std::size_t i = 0; i < kLossCategoryCount; ++i) {
        const LossCategory kCategory = lossCategoryAt(i);
        const LossCounter& counter = counters_[i];
        if (counter.statisticSource.empty()) {
            keys.push_back(std::string("timeline.loss.no-source.") + lossCategoryName(kCategory));
            continue;
        }
        if (!counter.count.present) {
            keys.push_back(std::string("timeline.loss.unknown-count.") + lossCategoryName(kCategory));
            continue;
        }
        if (counter.count.value != 0ULL) {
            anyPositive = true;
            if (!counter.intervalSupported) {
                keys.push_back(std::string("timeline.loss.total-only.") + lossCategoryName(kCategory));
            }
        }
    }
    if (keys.empty() && !anyPositive) {
        // All six categories have named sources and are all 0 — this is a positive assertion, not a 'default safe' assumption.
        keys.push_back("timeline.loss.none-all-categories-sourced");
    }
    return keys;
}

// ===========================================================================
// T-03 filtering
// ===========================================================================

bool filterAdmits(const EventFilter& filter, const TimelineEvent& event) noexcept {
    if (!filter.active) {
        return true;
    }
    if (!filter.allowedPids.empty()) {
        if (!event.pid.present || !containsPid(filter.allowedPids, event.pid.value)) {
            return false;
        }
    }
    if (!filter.allowedCategories.empty()) {
        if (std::find(filter.allowedCategories.begin(), filter.allowedCategories.end(),
                      event.category) == filter.allowedCategories.end()) {
            return false;
        }
    }
    if (!filter.allowedProviderIds.empty()) {
        if (std::find(filter.allowedProviderIds.begin(), filter.allowedProviderIds.end(),
                      event.providerId) == filter.allowedProviderIds.end()) {
            return false;
        }
    }
    return true;
}

// ===========================================================================
// T-02 parsing
// ===========================================================================

void EventSchemaRegistry::add(EventSchema schema) {
    for (EventSchema& existing : schemas_) {
        if (existing.providerId == schema.providerId && existing.eventId == schema.eventId &&
            existing.version == schema.version) {
            existing = std::move(schema);
            return;
        }
    }
    schemas_.push_back(std::move(schema));
}

const EventSchema* EventSchemaRegistry::findExact(const std::string& providerId,
                                                  std::uint32_t eventId,
                                                  std::uint32_t version) const noexcept {
    for (const EventSchema& schema : schemas_) {
        if (schema.providerId == providerId && schema.eventId == eventId &&
            schema.version == version) {
            return &schema;
        }
    }
    // T-02: There is no branch for "rolling back to the latest lower version." An unknown version is simply unknown.
    return nullptr;
}

bool EventSchemaRegistry::knowsProviderEvent(const std::string& providerId,
                                             std::uint32_t eventId) const noexcept {
    for (const EventSchema& schema : schemas_) {
        if (schema.providerId == providerId && schema.eventId == eventId) {
            return true;
        }
    }
    return false;
}

EventParseReport parseEventPayload(const EventSchemaRegistry& registry,
                                   const EventParseRequest& request) {
    EventParseReport report;
    if (request.payloadTruncated) {
        report.outcome = EventParseOutcome::kMalformed;
        report.reasonKey = "timeline.parse.payload-truncated";
        return report;
    }

    const EventSchema* schema = registry.findExact(request.providerId, request.eventId, request.version);
    if (schema == nullptr) {
        report.outcome = EventParseOutcome::kUnparsedUnknownSchema;
        report.reasonKey = registry.knowsProviderEvent(request.providerId, request.eventId)
                               ? "timeline.parse.unknown-event-version"
                               : "timeline.parse.unknown-provider-event";
        // Unparsed record: parser ID remains empty/0; never fill in an approximate version number.
        report.parserId.clear();
        report.parserVersion = 0U;
        report.category = TimelineEventCategory::kOther;
        return report;
    }

    report.parserId = schema->parserId;
    report.parserVersion = schema->parserVersion;
    report.category = schema->category;
    for (const std::string& required : schema->requiredFields) {
        bool found = false;
        for (const auto& field : request.rawFields) {
            if (field.first == required) {
                found = true;
                break;
            }
        }
        if (!found) {
            report.missingRequiredFields.push_back(required);
        }
    }
    if (!report.missingRequiredFields.empty()) {
        report.outcome = EventParseOutcome::kMalformed;
        report.reasonKey = "timeline.parse.missing-required-field";
        return report;
    }
    report.outcome = EventParseOutcome::kParsed;
    report.reasonKey = "timeline.parse.ok";
    return report;
}

void applyParseReport(TimelineEvent& event, const EventParseReport& report) {
    event.parseOutcome = report.outcome;
    event.parserId = report.parserId;
    event.parserVersion = report.parserVersion;
    event.parseReasonKey = report.reasonKey;
    // Only allow rewriting the category if a parser was actually selected; unknown schemas must not infer the category.
    if (!report.parserId.empty()) {
        event.category = report.category;
    }
    // rawFields / rawPayloadHex are always preserved: the value of unprocessed records lies in the raw data.
}

// ===========================================================================
// T-12 relationship edge
// ===========================================================================

namespace {

TimelineEdge makeEdge(TimelineEdgeKind kind,
                      const TimelineEvent& from,
                      const TimelineEvent& to,
                      const char* basisKey,
                      std::string basisDetail) {
    TimelineEdge edge;
    edge.kind = kind;
    edge.fromRecordId = from.recordId;
    edge.toRecordId = to.recordId;
    edge.basisKey = basisKey;
    edge.basisDetail = std::move(basisDetail);
    return edge;
}

inline constexpr std::size_t kNoIndex = static_cast<std::size_t>(-1);

// Compute the index of the next event with the same key for each event. A single O(n) hash scan replaces the original inner linear search:
// When keys are distinct (common on busy machines), the original implementation scans to the end of the array for every event: with n=16000,
// this takes 400 ms and yields zero edges—pure wasted scanning. Scanning backwards achieves the same edge generation order as the original.
std::vector<std::size_t> nextWithSameKey(const std::vector<TimelineEvent>& events,
                                         std::string TimelineEvent::*member) {
    std::vector<std::size_t> next(events.size(), kNoIndex);
    std::unordered_map<std::string, std::size_t> seen;
    seen.reserve(events.size() * 2U);
    for (std::size_t i = events.size(); i-- > 0;) {
        const std::string& key = events[i].*member;
        if (key.empty()) {
            continue;
        }
        const auto kFound = seen.find(key);
        if (kFound != seen.end()) {
            next[i] = kFound->second;
        }
        seen[key] = i;
    }
    return next;
}

// Table of first occurrence indices. The original ParentChild implementation scanned the entire table for every fact (and did not exit even after finding both ends), resulting
// in O(facts × events) complexity. This replaces it with a single table build. The semantics of 'first occurrence' remain consistent with the original implementation.
std::unordered_map<std::string, std::size_t> firstIndexByKey(
    const std::vector<TimelineEvent>& events,
    std::string TimelineEvent::*member) {
    std::unordered_map<std::string, std::size_t> index;
    index.reserve(events.size() * 2U);
    for (std::size_t i = 0; i < events.size(); ++i) {
        const std::string& key = events[i].*member;
        if (key.empty()) {
            continue;
        }
        index.emplace(key, i);  // emplace does not overwrite existing items -> retain the first occurrence.
    }
    return index;
}

} // namespace

std::vector<TimelineEdge> buildEdges(const std::vector<TimelineEvent>& events,
                                     const std::vector<ParentChildFact>& parentFacts,
                                     const EdgeBuildOptions& options) {
    std::vector<TimelineEdge> edges;

    // ---- SameProcess: Only recognize confirmed instance primary keys. Do not build edges based solely on raw PIDs (PIDs are reused).----
    if (options.includeSameProcess) {
        const std::vector<std::size_t> kNext =
            nextWithSameKey(events, &TimelineEvent::processInstanceKey);
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (kNext[i] == kNoIndex) {
                continue;  // Link only to the next event in the same instance to avoid O(n^2) edge explosion.
            }
            edges.push_back(makeEdge(TimelineEdgeKind::kSameProcess, events[i], events[kNext[i]],
                                     "timeline.edge.basis.same-process-instance",
                                     events[i].processInstanceKey));
        }
    }

    // ---- ParentChild: Requires the parent instance to actually have events in the session to ensure it can be expanded ----
    if (options.includeParentChild) {
        const std::unordered_map<std::string, std::size_t> kByInstance =
            firstIndexByKey(events, &TimelineEvent::processInstanceKey);
        const std::unordered_map<std::string, std::size_t> kByRecordId =
            firstIndexByKey(events, &TimelineEvent::recordId);
        for (const ParentChildFact& fact : parentFacts) {
            if (fact.recordId.empty() || fact.parentInstanceKey.empty() ||
                fact.childInstanceKey.empty()) {
                continue;
            }
            const auto kParentIt = kByInstance.find(fact.parentInstanceKey);
            const auto kChildIt = kByRecordId.find(fact.recordId);
            if (kParentIt == kByInstance.end() || kChildIt == kByRecordId.end()) {
                continue;  // Do not create edge if no traceable evidence exists.
            }
            edges.push_back(makeEdge(TimelineEdgeKind::kParentChild, events[kParentIt->second],
                                     events[kChildIt->second],
                                     "timeline.edge.basis.parent-child-from-create-event",
                                     fact.parentInstanceKey));
        }
    }

    // ---- SourceProvidedLink: the only edge permitted for causal phrasing ----
    if (options.includeSourceProvidedLink) {
        const std::vector<std::size_t> kNext = nextWithSameKey(events, &TimelineEvent::sourceLinkId);
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (kNext[i] == kNoIndex) {
                continue;
            }
            std::string detail = events[i].sourceLinkField.empty()
                                     ? events[i].sourceLinkId
                                     : events[i].sourceLinkField + "=" + events[i].sourceLinkId;
            edges.push_back(makeEdge(TimelineEdgeKind::kSourceProvidedLink, events[i], events[kNext[i]],
                                     "timeline.edge.basis.source-provided-link",
                                     std::move(detail)));
        }
    }

    // ---- TemporalNeighbor: Only generated if the caller explicitly provides a window ----
    if (options.temporalNeighborWindow100ns.present) {
        std::vector<std::size_t> order;
        order.reserve(events.size());
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (events[i].time.effectiveTime100ns().present) {
                order.push_back(i);
            }
        }
        std::sort(order.begin(), order.end(), [&events](std::size_t a, std::size_t b) {
            const std::uint64_t kTa = events[a].time.effectiveTime100ns().value;
            const std::uint64_t kTb = events[b].time.effectiveTime100ns().value;
            if (kTa != kTb) {
                return kTa < kTb;
            }
            if (events[a].arrivalSequence != events[b].arrivalSequence) {
                return events[a].arrivalSequence < events[b].arrivalSequence;
            }
            return events[a].recordId < events[b].recordId;
        });
        const std::uint64_t kWindow = options.temporalNeighborWindow100ns.value;
        for (std::size_t k = 1; k < order.size(); ++k) {
            const TimelineEvent& previous = events[order[k - 1]];
            const TimelineEvent& current = events[order[k]];
            const TimeComparisonResult kComparison = compareEventTimes(previous.time, current.time);
            if (!kComparison.comparable()) {
                continue;  // Cross-startup cycle or unknown time: Do not discuss "adjacent".
            }
            const std::uint64_t kGap = absToU64(kComparison.delta100ns);
            if (kGap > kWindow) {
                continue;
            }
            TimelineEdge edge = makeEdge(TimelineEdgeKind::kTemporalNeighbor, previous, current,
                                         // Wording intentionally fixed: "occurring merely adjacent" rather than "causing".
                                         "timeline.edge.basis.adjacent-in-time-only",
                                         std::string());
            edge.temporalGap100ns = OptionalU64::of(kGap);
            edge.orderUncertain = kComparison.kind == TimeComparison::kComparableButUncertain;
            edges.push_back(std::move(edge));
        }
    }

    return edges;
}

// ===========================================================================
// Session
// ===========================================================================

namespace {

// A description key for an unavailable collector: who, what status, and which event types it should have supplied.
// The category is written into the key so the UI can state 'This category (e.g., Registry) was not collected at all, not that it doesn't exist in the system'.
std::string describeUnavailableCollector(const CollectorCapability& capability) {
    std::string key("timeline.export.collector-unavailable:");
    key.append(capability.collectorId.empty() ? std::string("unnamed-collector")
                                              : capability.collectorId);
    key.push_back(':');
    key.append(collectionStatusName(capability.availability.status));
    key.push_back(':');
    if (capability.declaredCategories.empty()) {
        key.append("no-declared-category");
        return key;
    }
    for (std::size_t i = 0; i < capability.declaredCategories.size(); ++i) {
        if (i != 0U) {
            key.push_back('+');
        }
        key.append(timelineEventCategoryName(capability.declaredCategories[i]));
    }
    return key;
}

} // namespace

TimelineSession::TimelineSession() {
    declareLocalLossSources();
}

TimelineSession::TimelineSession(SessionManifest manifest, BoundsPolicy bounds)
    : manifest_(std::move(manifest)), bounds_(std::move(bounds)) {
    declareLocalLossSources();
}

void TimelineSession::declareLocalLossSources() {
    // T-06: "0 must also have a named statistical source." These four loss categories are generated by the session itself, so their source
    // must be this layer, and thus the session declares them during construction. Previously, the caller had to run declareSource() first;
    // if forgotten, every addObserved() call in ingest() would return false, and the count of filtered/dropped/discarded entries would
    // have no destination—the criterion "0 also has a source" was merely a verbal agreement by the caller.
    loss_.declareSource(LossCategory::kFilteredOut, "local.collectionFilter", false, false);
    loss_.declareSource(LossCategory::kQueueDiscard, "local.r3queue", false, false);
    loss_.declareSource(LossCategory::kParseFailure, "local.parser", false, false);
    loss_.declareSource(LossCategory::kRetentionEvicted, "local.retention", false, false);
    // SourceDrop and RingOverwrite are counted by the collector source; the session has no authority to declare them.
}

bool TimelineSession::recordLocalLoss(LossCategory category, std::uint64_t delta) {
    if (loss_.addObserved(category, delta)) {
        return true;
    }
    // If the record cannot be written, it is a hard error: mark this category as 'Unknown' and unset totalLost(). Better
    // to fail to determine the total count than to silently drop this entry while falsely claiming '0 items lost'.
    loss_.mutableCounter(category).count = OptionalU64::unset();
    lossAccountingFailed_ = true;
    return false;
}

std::uint32_t TimelineSession::registerBoot(const std::string& bootId) {
    for (std::size_t i = 0; i < bootEpochs_.size(); ++i) {
        if (bootEpochs_[i].bootId == bootId) {
            return static_cast<std::uint32_t>(i);
        }
    }
    BootEpoch epoch;
    epoch.bootId = bootId;
    bootEpochs_.push_back(std::move(epoch));
    return static_cast<std::uint32_t>(bootEpochs_.size() - 1U);
}

std::uint32_t TimelineSession::bootRankOf(const std::string& bootId) const noexcept {
    for (std::size_t i = 0; i < bootEpochs_.size(); ++i) {
        if (bootEpochs_[i].bootId == bootId) {
            return static_cast<std::uint32_t>(i);
        }
    }
    return static_cast<std::uint32_t>(bootEpochs_.size());
}

SessionTransition TimelineSession::apply(SessionAction action) {
    SessionTransition transition = evaluateSessionTransition(state_, action);
    if (transition.allowed && action == SessionAction::kStart) {
        // T-08: Upper bound and expiration behavior must be declared before collection; otherwise, start is prohibited.
        if (!bounds_.declaredBeforeCollection) {
            return makeRejected(state_, "timeline.session.bounds-not-declared");
        }
        // If a disk limit is declared but the number of events cannot be calculated (missing approximateBytesPerEvent
        // or it is 0), that limit will never take effect—users see a false guarantee. In practice: declaring 4096
        // bytes without a per-event estimate left all 50000 events, with boundsState remaining WithinLimits,
        // resulting in 36 MB written (8932× the declared limit). This must be rejected before collection begins.
        if (bounds_.maxArchiveBytes.present &&
            (!bounds_.approximateBytesPerEvent.present ||
             bounds_.approximateBytesPerEvent.value == 0ULL)) {
            return makeRejected(state_, "timeline.session.archive-limit-unenforceable");
        }
        // T-08 'Memory has an upper limit': If there is no upper limit that can be truly converted into a count, it is not bounded collection.
        if (!bounds_.maxEventsInMemory.present && !bounds_.maxArchiveBytes.present) {
            return makeRejected(state_, "timeline.session.no-memory-bound");
        }
    }
    if (!transition.allowed) {
        return transition;
    }
    if (action == SessionAction::kReset) {
        events_.clear();
        recordIds_.clear();
        bootEpochs_.clear();
        loss_ = LossLedger();
        declareLocalLossSources();  // After reset, the four local categories must still have named sources.
        processes_ = ProcessInstanceLedger();
        loadIntegrity_ = SessionLoadIntegrity();
        boundsState_ = BoundsState::kWithinLimits;
        nextSequence_ = 1U;
        filteredOutCount_ = 0U;
        lossAccountingFailed_ = false;
    }
    state_ = transition.nextState;
    return transition;
}

IngestResult TimelineSession::ingest(TimelineEvent event) {
    IngestResult result;
    result.bounds = boundsState_;

    // T-01: No new events may be recorded after stopping or saving.
    if (!sessionAcceptsNewEvents(state_)) {
        result.accepted = false;
        result.reasonKey = "timeline.ingest.session-not-collecting";
        return result;
    }

    // recordId serves as the final tiebreaker for sorting, the join key for relationship edges, and the primary key for export and restoration. A null
    // or duplicate value causes these three operations to reference different records (uncertainty in sortedOrder leads to incorrect time comparisons).
    // Reject and discard on the R3 side — rejection is acceptable, but silently swallowing is not.
    if (event.recordId.empty()) {
        result.accepted = false;
        result.lossCategory = LossCategory::kQueueDiscard;
        result.reasonKey = "timeline.ingest.missing-record-id";
        result.countedAsLoss = recordLocalLoss(LossCategory::kQueueDiscard, 1ULL);
        return result;
    }
    if (recordIds_.find(event.recordId) != recordIds_.end()) {
        result.accepted = false;
        result.lossCategory = LossCategory::kQueueDiscard;
        result.reasonKey = "timeline.ingest.duplicate-record-id";
        result.countedAsLoss = recordLocalLoss(LossCategory::kQueueDiscard, 1ULL);
        return result;
    }

    // T-03: Collection filtering takes effect here; display filtering **does not participate** in any judgment.
    if (!filterAdmits(collectionFilter_, event)) {
        ++filteredOutCount_;
        result.accepted = false;
        result.lossCategory = LossCategory::kFilteredOut;
        result.reasonKey = "timeline.ingest.excluded-by-collection-filter";
        result.countedAsLoss = recordLocalLoss(LossCategory::kFilteredOut, 1ULL);
        return result;
    }

    // T-08: Bounded. Convert the upper limit to a count; the disk limit can only be converted if a per-event byte estimate is provided.
    std::uint64_t capacity = std::numeric_limits<std::uint64_t>::max();
    bool archiveBound = false;
    if (bounds_.maxEventsInMemory.present) {
        capacity = bounds_.maxEventsInMemory.value;
    }
    if (bounds_.maxArchiveBytes.present && bounds_.approximateBytesPerEvent.present &&
        bounds_.approximateBytesPerEvent.value != 0ULL) {
        const std::uint64_t kDiskCapacity =
            bounds_.maxArchiveBytes.value / bounds_.approximateBytesPerEvent.value;
        if (kDiskCapacity <= capacity) {
            capacity = kDiskCapacity;
            archiveBound = true;
        }
    }

    if (capacity != std::numeric_limits<std::uint64_t>::max()) {
        const std::uint64_t kRetained = static_cast<std::uint64_t>(events_.size());
        if (capacity == 0ULL) {
            boundsState_ = archiveBound ? BoundsState::kArchiveLimitReached
                                        : BoundsState::kMemoryLimitReached;
            result.bounds = boundsState_;
            result.accepted = false;
            result.lossCategory = LossCategory::kQueueDiscard;
            result.reasonKey = "timeline.ingest.capacity-zero";
            result.countedAsLoss = recordLocalLoss(LossCategory::kQueueDiscard, 1ULL);
            return result;
        }
        if (kRetained >= capacity) {
            boundsState_ = archiveBound ? BoundsState::kArchiveLimitReached
                                        : BoundsState::kMemoryLimitReached;
            result.bounds = boundsState_;
            switch (bounds_.policy) {
            case RetentionPolicy::kStopOnLimit:
                result.accepted = false;
                result.lossCategory = LossCategory::kQueueDiscard;
                result.reasonKey = "timeline.ingest.limit-reached-stopped";
                result.countedAsLoss = recordLocalLoss(LossCategory::kQueueDiscard, 1ULL);
                return result;
            case RetentionPolicy::kEvictOldest:
                while (static_cast<std::uint64_t>(events_.size()) >= capacity && !events_.empty()) {
                    // O(1) eviction. Originally vector::erase(begin()), evicting one item required moving the entire
                    // retention window (sizeof(TimelineEvent)=560B); with a 100k limit, throughput was only ~186 ops/sec.
                    recordIds_.erase(events_.front().recordId);
                    events_.pop_front();
                    result.evictedOldest = true;
                    // Evictions are recorded as RetentionEvicted, distinct from queue drops; never merge counts.
                    result.countedAsLoss =
                        recordLocalLoss(LossCategory::kRetentionEvicted, 1ULL) || result.countedAsLoss;
                }
                result.lossCategory = LossCategory::kRetentionEvicted;
                result.reasonKey = "timeline.ingest.limit-reached-evicted-oldest";
                break;
            }
        }
    }

    // T-04: Time annotation. The source time is modified in no way; only a marker is added.
    const std::uint32_t kRank = registerBoot(event.time.bootId);
    BootEpoch& epoch = bootEpochs_[kRank];
    const OptionalU64 kEffective = event.time.effectiveTime100ns();
    if (kEffective.present) {
        if (epoch.maxTimeKnown && kEffective.value < epoch.maxEffectiveTime100ns) {
            event.time.lateArrival = true;  // Received out of temporal order — can be inserted but must be flagged.
        }
        if (!epoch.maxTimeKnown || kEffective.value > epoch.maxEffectiveTime100ns) {
            epoch.maxEffectiveTime100ns = kEffective.value;
            epoch.maxTimeKnown = true;
        }
    }
    if (!events_.empty()) {
        // If the current event cannot be distinguished from the previous arrival within timestamp precision, mark both as "order uncertain".
        // Authoritative adjacency checks are performed in sortedOrder(); this is only for streaming UI.
        const TimeComparisonResult kComparison = compareEventTimes(events_.back().time, event.time);
        if (kComparison.kind == TimeComparison::kComparableButUncertain) {
            events_.back().time.orderUncertain = true;
            event.time.orderUncertain = true;
        }
    }

    // T-05: Attribution. If the start event is missing, a temporary entity is obtained; it never falls back to the current process with the same PID.
    const AttributionDecision kDecision = processes_.attribute(event.time.bootId, event.pid, event.time);
    event.attribution = kDecision.kind;
    event.processInstanceKey =
        kDecision.kind == AttributionKind::kBoundToInstance ? kDecision.instance.crossSessionKey()
                                                          : std::string();
    event.provisionalProcessId = kDecision.provisionalId;

    // T-06: Only events with incomplete raw fields classified as Malformed count as 'parse failure with lost information'.
    // UnparsedUnknownSchema records are fully preserved and not counted as lost to avoid double-counting.
    if (event.parseOutcome == EventParseOutcome::kMalformed) {
        // Consistent with existing semantics: a parse failure does not change the event's countedAsLoss status (it was accepted).
        recordLocalLoss(LossCategory::kParseFailure, 1ULL);
    }

    event.arrivalSequence = nextSequence_++;
    result.assignedSequence = event.arrivalSequence;
    result.accepted = true;
    if (result.reasonKey.empty()) {
        result.reasonKey = "timeline.ingest.accepted";
    }
    result.bounds = boundsState_;
    recordIds_.insert(event.recordId);
    events_.push_back(std::move(event));
    return result;
}

bool TimelineSession::appendRestoredEvent(TimelineEvent event) {
    if (event.recordId.empty() || recordIds_.find(event.recordId) != recordIds_.end()) {
        return false;  // Empty or duplicate recordId found in file: structure is corrupted, cannot treat as normal recovery.
    }
    registerBoot(event.time.bootId);
    if (event.arrivalSequence >= nextSequence_) {
        nextSequence_ = event.arrivalSequence + 1U;
    }
    recordIds_.insert(event.recordId);
    events_.push_back(std::move(event));
    return true;
}

void TimelineSession::setStatsForRestore(std::uint64_t filteredOutCount, BoundsState bounds) noexcept {
    filteredOutCount_ = filteredOutCount;
    boundsState_ = bounds;
}

std::vector<const TimelineEvent*> TimelineSession::visibleEvents() const {
    std::vector<const TimelineEvent*> visible;
    visible.reserve(events_.size());
    for (const TimelineEvent& event : events_) {
        if (filterAdmits(displayFilter_, event)) {
            visible.push_back(&event);
        }
    }
    return visible;
}

std::vector<TimelineSortKey> TimelineSession::sortedOrder() const {
    // Sort keys are moved in pairs with their source events. The original approach was to sort, then perform a linear table lookup by recordId
    // for each pair—requiring a full table scan for every adjacent pair. At n=32000, this took 5.2 seconds; extrapolating to the spec's 1
    // million records at the same slope would take 84 minutes. Furthermore, that lookup retained the **last** recordId with a matching name;
    // duplicate IDs would cause the wrong record to be compared by time (duplicate IDs are now rejected at the ingest entry point).
    struct Entry final {
        TimelineSortKey key;
        const TimelineEvent* event = nullptr;
    };
    std::vector<Entry> entries;
    entries.reserve(events_.size());
    for (const TimelineEvent& event : events_) {
        TimelineSortKey key;
        key.bootEpochRank = bootRankOf(event.time.bootId);
        const OptionalU64 kEffective = event.time.effectiveTime100ns();
        key.timeKnown = kEffective.present;
        key.effectiveTime100ns = kEffective.valueOr(0ULL);
        key.arrivalSequence = event.arrivalSequence;
        key.sourceGroup = event.sourceGroup;
        key.recordId = event.recordId;
        if (!key.timeKnown) {
            key.explanationKey = "timeline.order.time-unknown-ordered-by-arrival";
        } else if (key.bootEpochRank != 0U) {
            // Do not compare time values across boot cycles; group only by the order of first appearance per boot cycle.
            key.explanationKey = "timeline.order.cross-boot-grouped-by-epoch";
        } else if (event.time.effectiveFromReceiveTime()) {
            key.explanationKey = "timeline.order.by-receive-time-source-time-missing";
        } else {
            key.explanationKey = "timeline.order.by-source-time";
        }
        Entry entry;
        entry.key = std::move(key);
        entry.event = &event;
        entries.push_back(std::move(entry));
    }
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        return sortKeyLess(a.key, b.key);
    });

    // Note: When adjacent entries are indistinguishable within precision, the rewrite clarifies that the **order** is determined, not the actual chronological sequence.
    for (std::size_t i = 1; i < entries.size(); ++i) {
        if (entries[i - 1].key.bootEpochRank != entries[i].key.bootEpochRank) {
            continue;
        }
        if (!entries[i - 1].key.timeKnown || !entries[i].key.timeKnown) {
            continue;
        }
        const TimeComparisonResult kComparison =
            compareEventTimes(entries[i - 1].event->time, entries[i].event->time);
        if (kComparison.kind == TimeComparison::kComparableButUncertain) {
            entries[i - 1].key.explanationKey = "timeline.order.uncertain-within-resolution";
            entries[i].key.explanationKey = "timeline.order.uncertain-within-resolution";
        }
    }

    std::vector<TimelineSortKey> keys;
    keys.reserve(entries.size());
    for (Entry& entry : entries) {
        keys.push_back(std::move(entry.key));
    }
    return keys;
}

ExportPlan TimelineSession::buildExportPlan(ExportScope scope) const {
    ExportPlan plan;
    plan.scope = scope;
    plan.retainedEventCount = static_cast<std::uint64_t>(events_.size());
    plan.excludedByCollectionFilter = filteredOutCount_;
    const std::uint64_t kVisible = static_cast<std::uint64_t>(visibleEvents().size());
    plan.hiddenByDisplayFilter = plan.retainedEventCount - kVisible;

    switch (scope) {
    case ExportScope::kVisibleOnly:
        plan.exportedEventCount = kVisible;
        plan.representsRetainedSession = plan.hiddenByDisplayFilter == 0ULL && !displayFilter_.active;
        plan.noticeKeys.push_back("timeline.export.visible-only");
        if (plan.hiddenByDisplayFilter != 0ULL) {
            // T-03: Display filtering must not make the export appear as if 'these events do not exist'.
            plan.noticeKeys.push_back("timeline.export.hidden-events-still-in-session");
        } else if (displayFilter_.active) {
            plan.noticeKeys.push_back("timeline.export.display-filter-active-nothing-hidden");
        }
        break;
    case ExportScope::kFullSession:
        plan.exportedEventCount = plan.retainedEventCount;
        plan.representsRetainedSession = true;
        plan.noticeKeys.push_back("timeline.export.full-session");
        if (displayFilter_.active) {
            plan.noticeKeys.push_back("timeline.export.display-filter-not-applied");
        }
        break;
    }

    // T-06: Collector capabilities are not write-only decorations. If File / Registry collectors are declared but none run (Error /
    // Unsupported / AccessDenied), the session naturally contains no File / Registry events. This does not mean "nothing happened
    // in the system"; exporting this as a complete collection would falsely present collection failures as normal operation.
    std::uint64_t unavailable = 0;
    for (const CollectorCapability& capability : manifest_.capabilities) {
        if (capability.availability.status == CollectionStatus::kSuccess) {
            continue;
        }
        ++unavailable;
        plan.noticeKeys.push_back(describeUnavailableCollector(capability));
    }
    plan.unavailableCollectorCount = unavailable;
    const bool kCapabilitiesDeclared = !manifest_.capabilities.empty();
    if (!kCapabilitiesDeclared) {
        // Declaring no collector capabilities means we don't know what should have been collected. "Completeness" requires positive evidence.
        plan.noticeKeys.push_back("timeline.export.no-collector-capability-declared");
    }

    plan.unrecoverableFileEventCount = loadIntegrity_.unrecoverableEventCount;
    const bool kLoadedFileIsComplete =
        !loadIntegrity_.restoredFromFile || loadIntegrity_.representsCompleteFile();
    if (!kLoadedFileIsComplete) {
        plan.noticeKeys.push_back(std::string("timeline.export.restored-from-incomplete-file.") +
                                  sessionLoadStatusName(loadIntegrity_.status));
    }
    if (plan.unrecoverableFileEventCount != 0ULL) {
        plan.noticeKeys.push_back("timeline.export.unrecoverable-file-events");
    }
    if (lossAccountingFailed_) {
        plan.noticeKeys.push_back("timeline.export.loss-accounting-failed");
    }

    const OptionalU64 kTotal = loss_.totalLost();
    plan.retainedSessionIsCompleteCapture =
        !collectionFilter_.active && kTotal.present && kTotal.value == 0ULL &&
        boundsState_ == BoundsState::kWithinLimits && kCapabilitiesDeclared && unavailable == 0ULL &&
        !lossAccountingFailed_ && plan.unrecoverableFileEventCount == 0ULL && kLoadedFileIsComplete;
    if (!plan.retainedSessionIsCompleteCapture) {
        plan.noticeKeys.push_back("timeline.export.session-not-complete-capture");
    }
    if (collectionFilter_.active) {
        plan.noticeKeys.push_back("timeline.export.collection-filter-applied");
    }
    if (boundsState_ != BoundsState::kWithinLimits) {
        plan.noticeKeys.push_back("timeline.export.bounds-reached");
    }
    return plan;
}

// ===========================================================================
// T-09 / T-10 persistence
// ===========================================================================

std::string serializeSessionHeaderLine(const TimelineSession& session) {
    const SessionManifest& manifest = session.manifest();
    JsonObject header;
    putText(header, "kind", kTimelineFormatKind);
    putU32(header, "formatVersion", kTimelineFormatVersion);
    putText(header, "sessionId", manifest.sessionId);
    putText(header, "machineId", manifest.machineId);
    putText(header, "bootId", manifest.bootId);
    putText(header, "displayName", manifest.displayName);
    putText(header, "state", sessionStateName(session.state()));
    putOptionalU64(header, "queryRangeBegin100ns", manifest.queryRangeBegin100ns);
    putOptionalU64(header, "queryRangeEnd100ns", manifest.queryRangeEnd100ns);

    JsonObject window;
    putOptionalU64(window, "startUtc100ns", manifest.window.startUtc100ns);
    putOptionalU64(window, "endUtc100ns", manifest.window.endUtc100ns);
    putOptionalU64(window, "startMonotonic", manifest.window.startMonotonic);
    putOptionalU64(window, "endMonotonic", manifest.window.endMonotonic);
    putOptionalU64(window, "monotonicFrequency", manifest.window.monotonicFrequency);
    putText(window, "machineId", manifest.window.machineId);
    putText(window, "bootId", manifest.window.bootId);
    putText(window, "sessionId", manifest.window.sessionId);
    putText(window, "mode", captureModeName(manifest.window.mode));
    put(header, "window", JsonValue::makeObject(std::move(window)));

    const BoundsPolicy& bounds = session.bounds();
    JsonObject boundsObject;
    putOptionalU64(boundsObject, "maxEventsInMemory", bounds.maxEventsInMemory);
    putOptionalU64(boundsObject, "maxArchiveBytes", bounds.maxArchiveBytes);
    putOptionalU64(boundsObject, "approximateBytesPerEvent", bounds.approximateBytesPerEvent);
    putText(boundsObject, "policy", retentionPolicyName(bounds.policy));
    put(boundsObject, "declaredBeforeCollection", JsonValue::makeBool(bounds.declaredBeforeCollection));
    put(header, "bounds", JsonValue::makeObject(std::move(boundsObject)));

    JsonArray capabilities;
    for (const CollectorCapability& capability : manifest.capabilities) {
        JsonObject one;
        putText(one, "collectorId", capability.collectorId);
        putU32(one, "collectorVersion", capability.collectorVersion);
        putText(one, "sourceGroup", capability.sourceGroup);
        putText(one, "origin", sourceOriginName(capability.origin));
        JsonArray categories;
        for (const TimelineEventCategory kCategory : capability.declaredCategories) {
            categories.push_back(JsonValue::makeString(timelineEventCategoryName(kCategory)));
        }
        put(one, "declaredCategories", JsonValue::makeArray(std::move(categories)));
        putText(one, "availabilityStatus", collectionStatusName(capability.availability.status));
        putText(one, "availabilityDomain", capability.availability.nativeCodeDomain);
        putOptionalU64(one, "availabilityCode", capability.availability.nativeCode);
        putText(one, "availabilityMessage", capability.availability.message);
        capabilities.push_back(JsonValue::makeObject(std::move(one)));
    }
    put(header, "capabilities", JsonValue::makeArray(std::move(capabilities)));

    const EventFilter& filter = session.collectionFilter();
    JsonObject filterObject;
    put(filterObject, "active", JsonValue::makeBool(filter.active));
    putText(filterObject, "ruleId", filter.ruleId);
    JsonArray pids;
    for (const std::uint64_t kPid : filter.allowedPids) {
        pids.push_back(JsonValue::makeU64Text(kPid, U64Format::kDecimal));
    }
    put(filterObject, "allowedPids", JsonValue::makeArray(std::move(pids)));
    JsonArray categories;
    for (const TimelineEventCategory kCategory : filter.allowedCategories) {
        categories.push_back(JsonValue::makeString(timelineEventCategoryName(kCategory)));
    }
    put(filterObject, "allowedCategories", JsonValue::makeArray(std::move(categories)));
    JsonArray providers;
    for (const std::string& provider : filter.allowedProviderIds) {
        providers.push_back(JsonValue::makeString(provider));
    }
    put(filterObject, "allowedProviderIds", JsonValue::makeArray(std::move(providers)));
    put(header, "collectionFilter", JsonValue::makeObject(std::move(filterObject)));

    std::string line = writeJson(JsonValue::makeObject(std::move(header)), 0U);
    line.push_back('\n');
    return line;
}

std::string serializeBatchLine(const SessionBatch& batch) {
    // Encode the event array only once: the checksum and the row content share the same JsonValue. Previously,
    // encodeEventArray ran twice (once for the checksum, once for output), doubling the work for large batches.
    JsonValue eventsValue = encodeEventArray(batch.events);
    const std::uint64_t kChecksum = fnv1a64(writeJson(eventsValue, 0U));
    JsonObject object;
    putText(object, "kind", "batch");
    putU64Text(object, "batchIndex", batch.batchIndex);
    put(object, "committed", JsonValue::makeBool(batch.committed));
    putText(object, "checksum", formatU64(kChecksum, U64Format::kHexAddress));
    put(object, "events", std::move(eventsValue));
    std::string line = writeJson(JsonValue::makeObject(std::move(object)), 0U);
    line.push_back('\n');
    return line;
}

std::string serializeTrailerLine(const TimelineSession& session, std::uint64_t committedBatchCount) {
    JsonObject object;
    putText(object, "kind", "trailer");
    putU64Text(object, "batchCount", committedBatchCount);
    putU64Text(object, "eventCount", static_cast<std::uint64_t>(session.events().size()));
    putU64Text(object, "collectionFilteredOut", session.collectionFilteredOutCount());
    putText(object, "boundsState", boundsStateName(session.boundsState()));

    JsonArray loss;
    for (std::size_t i = 0; i < kLossCategoryCount; ++i) {
        const LossCategory kCategory = lossCategoryAt(i);
        const LossCounter& counter = session.loss().counter(kCategory);
        JsonObject one;
        putText(one, "category", lossCategoryName(kCategory));
        putOptionalU64(one, "count", counter.count);
        putText(one, "statisticSource", counter.statisticSource);
        put(one, "sourceIsAuthoritative", JsonValue::makeBool(counter.sourceIsAuthoritative));
        put(one, "intervalSupported", JsonValue::makeBool(counter.intervalSupported));
        putOptionalU64(one, "intervalBegin100ns", counter.intervalBegin100ns);
        putOptionalU64(one, "intervalEnd100ns", counter.intervalEnd100ns);
        loss.push_back(JsonValue::makeObject(std::move(one)));
    }
    put(object, "loss", JsonValue::makeArray(std::move(loss)));

    std::string line = writeJson(JsonValue::makeObject(std::move(object)), 0U);
    line.push_back('\n');
    return line;
}

void serializeSessionTo(const TimelineSession& session,
                        std::size_t batchSize,
                        const std::function<void(std::string_view)>& sink) {
    if (!sink) {
        return;
    }
    const std::size_t kEffectiveBatchSize = batchSize == 0U ? session.events().size() + 1U : batchSize;
    sink(serializeSessionHeaderLine(session));

    std::uint64_t batchIndex = 0;
    std::size_t offset = 0;
    // Load only one batch into memory at a time. Previously, this code kept appending to a single std::string; a session with 200k events
    // of 512B payloads would accumulate a 360 MiB single string, causing peak memory usage equal to the session plus the entire file.
    while (offset < session.events().size()) {
        SessionBatch batch;
        batch.batchIndex = batchIndex;
        batch.committed = true;
        const std::size_t kEnd = std::min(session.events().size(), offset + kEffectiveBatchSize);
        batch.events.assign(session.events().begin() + static_cast<std::ptrdiff_t>(offset),
                            session.events().begin() + static_cast<std::ptrdiff_t>(kEnd));
        sink(serializeBatchLine(batch));
        offset = kEnd;
        ++batchIndex;
    }
    sink(serializeTrailerLine(session, batchIndex));
}

std::string serializeSession(const TimelineSession& session, std::size_t batchSize) {
    std::string text;
    serializeSessionTo(session, batchSize, [&text](std::string_view line) { text.append(line); });
    return text;
}

namespace {

bool restoreLossFromTrailer(const JsonValue& trailer, LossLedger& ledger) {
    const JsonValue* loss = trailer.find("loss");
    if (loss == nullptr) {
        return false;
    }
    const JsonArray* array = loss->asArray();
    if (array == nullptr) {
        return false;
    }
    for (const JsonValue& item : *array) {
        std::string name;
        if (!readText(item, "category", name)) {
            return false;
        }
        LossCategory category = LossCategory::kSourceDrop;
        if (!lookupEnum(kLossCategoryTable, name, category)) {
            return false;
        }
        LossCounter& counter = ledger.mutableCounter(category);
        if (!readOptionalU64(item, "count", counter.count)) { return false; }
        if (!readText(item, "statisticSource", counter.statisticSource)) { return false; }
        if (!readBool(item, "sourceIsAuthoritative", counter.sourceIsAuthoritative)) { return false; }
        if (!readBool(item, "intervalSupported", counter.intervalSupported)) { return false; }
        if (!readOptionalU64(item, "intervalBegin100ns", counter.intervalBegin100ns)) { return false; }
        if (!readOptionalU64(item, "intervalEnd100ns", counter.intervalEnd100ns)) { return false; }
    }
    return true;
}

bool restoreHeader(const JsonValue& header, SessionManifest& manifest, BoundsPolicy& bounds,
                   EventFilter& filter, SessionState& state) {
    if (!readText(header, "sessionId", manifest.sessionId)) { return false; }
    if (!readText(header, "machineId", manifest.machineId)) { return false; }
    if (!readText(header, "bootId", manifest.bootId)) { return false; }
    if (!readText(header, "displayName", manifest.displayName)) { return false; }
    std::string text;
    if (!readText(header, "state", text) || !lookupEnum(kSessionStateTable, text, state)) {
        return false;
    }
    if (!readOptionalU64(header, "queryRangeBegin100ns", manifest.queryRangeBegin100ns)) { return false; }
    if (!readOptionalU64(header, "queryRangeEnd100ns", manifest.queryRangeEnd100ns)) { return false; }

    const JsonValue* window = header.find("window");
    if (window == nullptr || window->asObject() == nullptr) { return false; }
    if (!readOptionalU64(*window, "startUtc100ns", manifest.window.startUtc100ns)) { return false; }
    if (!readOptionalU64(*window, "endUtc100ns", manifest.window.endUtc100ns)) { return false; }
    if (!readOptionalU64(*window, "startMonotonic", manifest.window.startMonotonic)) { return false; }
    if (!readOptionalU64(*window, "endMonotonic", manifest.window.endMonotonic)) { return false; }
    if (!readOptionalU64(*window, "monotonicFrequency", manifest.window.monotonicFrequency)) { return false; }
    if (!readText(*window, "machineId", manifest.window.machineId)) { return false; }
    if (!readText(*window, "bootId", manifest.window.bootId)) { return false; }
    if (!readText(*window, "sessionId", manifest.window.sessionId)) { return false; }
    if (!readText(*window, "mode", text)) { return false; }
    // Collection mode: all retrieved sessions are replays; here we only verify the field exists and has a known value.
    if (text != "Unknown" && text != "Snapshot" && text != "Streaming" && text != "Replay") {
        return false;
    }
    manifest.window.mode = CaptureMode::kReplay;

    const JsonValue* boundsObject = header.find("bounds");
    if (boundsObject == nullptr || boundsObject->asObject() == nullptr) { return false; }
    if (!readOptionalU64(*boundsObject, "maxEventsInMemory", bounds.maxEventsInMemory)) { return false; }
    if (!readOptionalU64(*boundsObject, "maxArchiveBytes", bounds.maxArchiveBytes)) { return false; }
    if (!readOptionalU64(*boundsObject, "approximateBytesPerEvent", bounds.approximateBytesPerEvent)) {
        return false;
    }
    if (!readText(*boundsObject, "policy", text) || !lookupEnum(kRetentionTable, text, bounds.policy)) {
        return false;
    }
    if (!readBool(*boundsObject, "declaredBeforeCollection", bounds.declaredBeforeCollection)) {
        return false;
    }

    const JsonValue* capabilities = header.find("capabilities");
    if (capabilities == nullptr) { return false; }
    const JsonArray* capabilityArray = capabilities->asArray();
    if (capabilityArray == nullptr) { return false; }
    for (const JsonValue& item : *capabilityArray) {
        CollectorCapability capability;
        if (!readText(item, "collectorId", capability.collectorId)) { return false; }
        if (!readU32(item, "collectorVersion", capability.collectorVersion)) { return false; }
        if (!readText(item, "sourceGroup", capability.sourceGroup)) { return false; }
        // Unrecognized origins no longer silently default to Unknown: within the same header, declaredCategories,
        // policy, and state all treat 'unrecognized' as 'bad file'; there is no reason to be more lenient here.
        if (!readText(item, "origin", text) ||
            !lookupEnum(kSourceOriginTable, text, capability.origin)) {
            return false;
        }
        const JsonValue* categories = item.find("declaredCategories");
        if (categories == nullptr) { return false; }
        const JsonArray* categoryArray = categories->asArray();
        if (categoryArray == nullptr) { return false; }
        for (const JsonValue& category : *categoryArray) {
            std::string categoryName;
            if (!category.tryGetString(categoryName)) { return false; }
            TimelineEventCategory decoded = TimelineEventCategory::kOther;
            if (!lookupEnum(kCategoryTable, categoryName, decoded)) { return false; }
            capability.declaredCategories.push_back(decoded);
        }
        // Unrecognized availabilityStatus used to silently fall back to NotCollected — this was a one-time
        // **Failure** should be reclassified as **Never Run**, yet nativeCode still retains
        // STATUS_ACCESS_DENIED. The two fields contradict each other. Bad names lead to bad files.
        if (!readText(item, "availabilityStatus", text) ||
            !lookupEnum(kCollectionStatusTable, text, capability.availability.status)) {
            return false;
        }
        if (!readText(item, "availabilityDomain", capability.availability.nativeCodeDomain)) { return false; }
        if (!readOptionalU64(item, "availabilityCode", capability.availability.nativeCode)) { return false; }
        if (!readText(item, "availabilityMessage", capability.availability.message)) { return false; }
        manifest.capabilities.push_back(std::move(capability));
    }

    const JsonValue* filterObject = header.find("collectionFilter");
    if (filterObject == nullptr || filterObject->asObject() == nullptr) { return false; }
    if (!readBool(*filterObject, "active", filter.active)) { return false; }
    if (!readText(*filterObject, "ruleId", filter.ruleId)) { return false; }
    const JsonValue* pids = filterObject->find("allowedPids");
    if (pids == nullptr || pids->asArray() == nullptr) { return false; }
    for (const JsonValue& pid : *pids->asArray()) {
        std::uint64_t value = 0;
        if (!pid.tryGetU64(value)) { return false; }
        filter.allowedPids.push_back(value);
    }
    const JsonValue* filterCategories = filterObject->find("allowedCategories");
    if (filterCategories == nullptr || filterCategories->asArray() == nullptr) { return false; }
    for (const JsonValue& category : *filterCategories->asArray()) {
        std::string categoryName;
        if (!category.tryGetString(categoryName)) { return false; }
        TimelineEventCategory decoded = TimelineEventCategory::kOther;
        if (!lookupEnum(kCategoryTable, categoryName, decoded)) { return false; }
        filter.allowedCategories.push_back(decoded);
    }
    const JsonValue* filterProviders = filterObject->find("allowedProviderIds");
    if (filterProviders == nullptr || filterProviders->asArray() == nullptr) { return false; }
    for (const JsonValue& provider : *filterProviders->asArray()) {
        std::string providerName;
        if (!provider.tryGetString(providerName)) { return false; }
        filter.allowedProviderIds.push_back(providerName);
    }
    return true;
}

} // namespace

SessionLoadResult loadSession(std::string_view text) {
    SessionLoadResult result;
    if (text.empty()) {
        result.status = SessionLoadStatus::kEmpty;
        result.diagnosticKey = "timeline.load.empty";
        return result;
    }

    bool lastLineTerminated = true;
    const std::vector<std::string_view> kLines = splitLines(text, lastLineTerminated);
    if (kLines.empty()) {
        result.status = SessionLoadStatus::kEmpty;
        result.diagnosticKey = "timeline.load.empty";
        return result;
    }

    // ---- header ----
    const JsonParseResult kHeaderParse = parseJson(kLines[0]);
    result.jsonStatus = kHeaderParse.status;
    if (!kHeaderParse.ok() || kHeaderParse.value.asObject() == nullptr) {
        result.status = SessionLoadStatus::kMissingHeader;
        result.diagnosticKey = "timeline.load.header-unparsable";
        result.failedLineIndex = 0;
        return result;
    }
    std::string kind;
    if (!readText(kHeaderParse.value, "kind", kind) || kind != kTimelineFormatKind) {
        result.status = SessionLoadStatus::kMissingHeader;
        result.diagnosticKey = "timeline.load.header-kind-mismatch";
        return result;
    }
    if (!readU32(kHeaderParse.value, "formatVersion", result.fileFormatVersion)) {
        result.status = SessionLoadStatus::kMissingHeader;
        result.diagnosticKey = "timeline.load.header-version-missing";
        return result;
    }
    if (result.fileFormatVersion > kTimelineFormatVersion) {
        // T-10: VersionTooNew is a distinct status. Do not treat it as 'invalid format' and never attempt to guess-read.
        result.status = SessionLoadStatus::kVersionTooNew;
        result.diagnosticKey = "timeline.load.format-version-too-new";
        return result;
    }

    SessionManifest manifest;
    BoundsPolicy bounds;
    EventFilter collectionFilter;
    SessionState state = SessionState::kSaved;
    if (!restoreHeader(kHeaderParse.value, manifest, bounds, collectionFilter, state)) {
        result.status = SessionLoadStatus::kMissingHeader;
        result.diagnosticKey = "timeline.load.header-fields-invalid";
        return result;
    }

    TimelineSession session(std::move(manifest), bounds);
    session.setCollectionFilter(std::move(collectionFilter));

    bool sawTrailer = false;
    bool sawUncommitted = false;
    std::uint64_t trailerEventCount = 0;
    std::uint64_t trailerBatchCount = 0;
    std::uint64_t trailerFilteredOut = 0;
    BoundsState trailerBounds = BoundsState::kWithinLimits;
    SessionLoadStatus status = SessionLoadStatus::kOk;
    std::string diagnostic = "timeline.load.ok";

    for (std::size_t index = 1; index < kLines.size(); ++index) {
        const bool kIsLastLine = (index + 1U == kLines.size());
        if (kLines[index].empty()) {
            continue;
        }
        if (sawTrailer) {
            // T-10: The trailer must be the last line. Any content after it—such as a second trailer, an old trailer left in the
            // middle due to an interrupted rewrite, or batches appended afterward—indicates that the file structure is corrupted.
            // Previously, this was just a continue, so reading "header+batch+trailer+batch"
            // resulted in status=Ok / representsCompleteFile()=true for a "clean complete session".
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.content-after-trailer";
            break;
        }
        if (kIsLastLine && !lastLineTerminated) {
            // Interrupted mid-write: this line is incomplete; previously committed batches remain intact.
            status = SessionLoadStatus::kIncompleteTail;
            diagnostic = "timeline.load.unterminated-final-line";
            result.failedLineIndex = index;
            break;
        }
        const JsonParseResult kLineParse = parseJson(kLines[index]);
        if (!kLineParse.ok() || kLineParse.value.asObject() == nullptr) {
            result.jsonStatus = kLineParse.status;
            result.failedLineIndex = index;
            status = kIsLastLine ? SessionLoadStatus::kIncompleteTail : SessionLoadStatus::kCorrupt;
            diagnostic = kIsLastLine ? "timeline.load.tail-line-unparsable"
                                    : "timeline.load.line-unparsable";
            break;
        }
        std::string lineKind;
        if (!readText(kLineParse.value, "kind", lineKind)) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.line-kind-missing";
            break;
        }
        if (lineKind == "trailer") {
            if (!readU64(kLineParse.value, "batchCount", trailerBatchCount) ||
                !readU64(kLineParse.value, "eventCount", trailerEventCount) ||
                !readU64(kLineParse.value, "collectionFilteredOut", trailerFilteredOut)) {
                result.failedLineIndex = index;
                status = SessionLoadStatus::kCorrupt;
                diagnostic = "timeline.load.trailer-fields-invalid";
                break;
            }
            std::string boundsName;
            if (!readText(kLineParse.value, "boundsState", boundsName) ||
                !lookupEnum(kBoundsStateTable, boundsName, trailerBounds)) {
                result.failedLineIndex = index;
                status = SessionLoadStatus::kCorrupt;
                diagnostic = "timeline.load.trailer-fields-invalid";
                break;
            }
            if (!restoreLossFromTrailer(kLineParse.value, session.loss())) {
                result.failedLineIndex = index;
                status = SessionLoadStatus::kCorrupt;
                diagnostic = "timeline.load.trailer-loss-invalid";
                break;
            }
            sawTrailer = true;
            continue;
        }
        if (lineKind != "batch") {
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.unknown-line-kind";
            break;
        }

        bool committed = false;
        std::uint64_t batchIndex = 0;
        std::string checksumText;
        if (!readBool(kLineParse.value, "committed", committed) ||
            !readU64(kLineParse.value, "batchIndex", batchIndex) ||
            !readText(kLineParse.value, "checksum", checksumText)) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.batch-fields-invalid";
            break;
        }
        const JsonValue* eventsValue = kLineParse.value.find("events");
        if (eventsValue == nullptr || eventsValue->asArray() == nullptr) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.batch-events-invalid";
            break;
        }
        std::vector<TimelineEvent> decoded;
        bool decodeOk = true;
        for (const JsonValue& item : *eventsValue->asArray()) {
            TimelineEvent event;
            if (!decodeEvent(item, event)) {
                decodeOk = false;
                break;
            }
            decoded.push_back(std::move(event));
        }
        if (!decodeOk) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.event-decode-failed";
            break;
        }
        if (!committed) {
            // T-10: Only committed batches are acknowledged. Uncommitted counts are reported separately and marked as missing.
            sawUncommitted = true;
            result.uncommittedEventCount =
                saturatingAddU64(result.uncommittedEventCount,
                                 static_cast<std::uint64_t>(decoded.size()));
            continue;
        }
        std::uint64_t storedChecksum = 0;
        if (!parseU64(checksumText, storedChecksum)) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.batch-checksum-invalid";
            break;
        }
        if (batchChecksum(decoded) != storedChecksum) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.batch-checksum-mismatch";
            break;
        }
        bool appendOk = true;
        for (TimelineEvent& event : decoded) {
            if (!session.appendRestoredEvent(std::move(event))) {
                appendOk = false;
                break;
            }
        }
        if (!appendOk) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::kCorrupt;
            diagnostic = "timeline.load.duplicate-record-id";
            break;
        }
        ++result.committedBatchCount;
    }

    result.recoveredEventCount = static_cast<std::uint64_t>(session.events().size());
    result.trailerPresent = sawTrailer;
    if (sawTrailer) {
        session.setStatsForRestore(trailerFilteredOut, trailerBounds);
        result.declaredEventCount = trailerEventCount;
    }
    if (status == SessionLoadStatus::kOk) {
        if (!sawTrailer) {
            status = SessionLoadStatus::kIncompleteTail;
            diagnostic = "timeline.load.missing-trailer";
        } else if (sawUncommitted) {
            status = SessionLoadStatus::kIncompleteTail;
            diagnostic = "timeline.load.uncommitted-batch-present";
        } else if (trailerEventCount != result.recoveredEventCount ||
                   trailerBatchCount != result.committedBatchCount) {
            status = SessionLoadStatus::kTrailerMismatch;
            diagnostic = "timeline.load.trailer-count-mismatch";
        }
    }

    // T-10: 'Mark uncommitted portion as missing'. Two sources: the count in the uncommitted batch, and the portion where
    // the trailer claims more than was actually recovered. This is not T-06's six types of collection loss (which refer to
    // the collection phase), so it is recorded separately with its own statistics source and never merged into totalLost().
    std::uint64_t unrecoverable = result.uncommittedEventCount;
    if (sawTrailer && trailerEventCount > result.recoveredEventCount) {
        const std::uint64_t kMissing = trailerEventCount - result.recoveredEventCount;
        if (kMissing > unrecoverable) {
            // Those not submitted were already included in the trailer declaration; take the larger value to avoid double counting.
            unrecoverable = kMissing;
        }
    }
    result.unrecoverableEventCount = unrecoverable;

    // T-10: The conclusion must be attached to the session. Previously it was only written to 'result'; once
    // the session was handed off, 'trailer mismatch' due to truncated files would vanish entirely. In
    // practice, sessions from truncated files yield retainedSessionIsCompleteCapture=1 and envelope Success.
    SessionLoadIntegrity integrity;
    integrity.restoredFromFile = true;
    integrity.status = status;
    integrity.diagnosticKey = diagnostic;
    integrity.unrecoverableEventCount = unrecoverable;
    integrity.unrecoverableStatisticSource = "local.session-file.uncommitted";
    session.setLoadIntegrityForRestore(std::move(integrity));

    // Sessions reopened offline are read-only only; restored states must not be 'collecting'.
    session.setStateForRestore(state == SessionState::kNew ? SessionState::kNew : SessionState::kSaved);
    result.status = status;
    result.diagnosticKey = std::move(diagnostic);
    result.session = std::move(session);
    return result;
}

// ===========================================================================
// Session envelope
// ===========================================================================

EvidenceEnvelope buildSessionEnvelope(const TimelineSession& session) {
    EvidenceEnvelope envelope;
    envelope.source.collectorId = "timeline.session";
    envelope.source.sourceGroup = "timeline.session";
    envelope.source.collectorVersion = kTimelineFormatVersion;
    envelope.source.dependsOn = "ETW / CallbackMonitor / FileMonitor";
    envelope.source.origin = session.state() == SessionState::kSaved ? SourceOrigin::kOfflineSample
                                                                   : SourceOrigin::kLiveUserMode;
    envelope.window = session.manifest().window;
    envelope.evidenceId = session.manifest().sessionId;

    const LossLedger& loss = session.loss();
    const OptionalU64 kTotal = loss.totalLost();
    const SessionManifest& manifest = session.manifest();
    const SessionLoadIntegrity& integrity = session.loadIntegrity();

    const CollectorCapability* unavailable = nullptr;
    for (const CollectorCapability& capability : manifest.capabilities) {
        if (capability.availability.status != CollectionStatus::kSuccess) {
            unavailable = &capability;
            break;
        }
    }

    if (session.state() == SessionState::kNew) {
        envelope.outcome.status = CollectionStatus::kNotCollected;
    } else if (manifest.capabilities.empty()) {
        // No collector capability declared: Without knowing what should have been collected, it has no right to claim 'collection complete'.
        envelope.outcome.status = CollectionStatus::kPartial;
        envelope.outcome.message = "no collector capability declared";
    } else if (unavailable != nullptr) {
        // F-05: On failure, preserve the original error code and description; do not pad with default 0, empty string, or "success".
        envelope.outcome.status = CollectionStatus::kPartial;
        envelope.outcome.nativeCodeDomain = unavailable->availability.nativeCodeDomain;
        envelope.outcome.nativeCode = unavailable->availability.nativeCode;
        envelope.outcome.message = unavailable->collectorId + ": " +
                                   collectionStatusName(unavailable->availability.status) +
                                   (unavailable->availability.message.empty()
                                        ? std::string()
                                        : (": " + unavailable->availability.message));
    } else if (integrity.restoredFromFile && !integrity.representsCompleteFile()) {
        envelope.outcome.status = CollectionStatus::kPartial;
        envelope.outcome.message = std::string("session file ") +
                                   sessionLoadStatusName(integrity.status) + ": " +
                                   integrity.diagnosticKey;
    } else if (integrity.unrecoverableEventCount != 0ULL) {
        envelope.outcome.status = CollectionStatus::kPartial;
        envelope.outcome.message = "session file has unrecoverable events";
    } else if (session.lossAccountingFailed()) {
        envelope.outcome.status = CollectionStatus::kPartial;
        envelope.outcome.message = "loss accounting failed";
    } else if (!kTotal.present) {
        envelope.outcome.status = CollectionStatus::kPartial;
        envelope.outcome.message = "loss accounting incomplete";
    } else if (kTotal.value != 0ULL || session.boundsState() != BoundsState::kWithinLimits ||
               session.collectionFilteredOutCount() != 0ULL) {
        envelope.outcome.status = CollectionStatus::kPartial;
    } else {
        envelope.outcome.status = CollectionStatus::kSuccess;
    }

    CoverageAccount& coverage = envelope.coverage;
    coverage.requestedBegin = manifest.queryRangeBegin100ns;
    coverage.requestedEnd = manifest.queryRangeEnd100ns;
    coverage.succeeded = static_cast<std::uint64_t>(session.events().size());
    // The count of filtered-out entries is authoritatively recorded by the session; the FilteredOut value in the ledger is merely its copy.
    // Previously, `loss.counter(FilteredOut).count.valueOr(0)` was used here; when a source was missing, "7
    // items excluded" was incorrectly recorded as 0—exactly the substitution this module forbids at line 1041.
    coverage.skipped = session.collectionFilteredOutCount();
    // These three counters in CoverageAccount are std::uint64_t at the F layer with no 'unknown' state available.
    // Therefore, only **known** counters are summed, and any unknown category marks the outcome as Partial with the
    // reason specified above. Unknown values are never treated as 0 to falsely imply the accounts are balanced.
    const LossCategory kFailedCategories[] = { LossCategory::kSourceDrop,
                                               LossCategory::kRingOverwrite,
                                               LossCategory::kQueueDiscard,
                                               LossCategory::kParseFailure };
    std::uint64_t failed = 0;
    bool anyUnknownCount = false;
    for (const LossCategory kCategory : kFailedCategories) {
        const LossCounter& counter = loss.counter(kCategory);
        if (!counter.count.present) {
            // T-06: The source provides no count for this category. Skipping it is correct (unknowns cannot be summed as 0
            // into the total), but the skip itself must be logged—otherwise, the number in coverage.failed appears precise
            // but is actually a lower bound, causing the UI to misinterpret 'unknown missing count' as 'nothing missing'.
            anyUnknownCount = true;
            continue;
        }
        failed = saturatingAddU64(failed, counter.count.value);
    }
    coverage.failed = failed;
    coverage.countsIncomplete = anyUnknownCount;
    // Truncated coverage includes retention-evicted entries plus entries unrecoverable from session files; both indicate "this trace segment was truncated".
    coverage.truncated =
        saturatingAddU64(loss.counter(LossCategory::kRetentionEvicted).count.valueOr(0ULL),
                         integrity.unrecoverableEventCount);
    coverage.limitHit = session.boundsState() != BoundsState::kWithinLimits;
    coverage.limit = session.bounds().maxEventsInMemory;

    // F-06 / T-06: The timeline **never knows** the total number of events that occurred in the system, so totalKnown is never
    // set. Only when all six categories of accounts have named sources can we provide the positive evidence of "processing scope";
    // If any category is unknown, leave the endpoints empty; fullyCovered() then reports incomplete coverage — exactly as intended.
    if (!loss.anyUnknown()) {
        std::uint64_t begin = 0;
        std::uint64_t end = 0;
        bool any = false;
        for (const TimelineEvent& event : session.events()) {
            const OptionalU64 kEffective = event.time.effectiveTime100ns();
            if (!kEffective.present) {
                continue;
            }
            if (!any || kEffective.value < begin) {
                begin = kEffective.value;
            }
            if (!any || kEffective.value > end) {
                end = kEffective.value;
            }
            any = true;
        }
        if (any) {
            coverage.processedBegin = OptionalU64::of(begin);
            coverage.processedEnd = OptionalU64::of(end);
        }
    }
    return envelope;
}

} // namespace ksword::evidence
